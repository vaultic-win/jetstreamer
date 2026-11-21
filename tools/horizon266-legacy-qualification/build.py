"""Render a direct rustc recipe. Execution requires the booked, isolated build unit."""
import argparse
import hashlib
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

BASE = Path('/home/ubuntu/.jetstreamer-private/current-reader-check-20261118-v1/target/release')
RUSTC = Path('/home/ubuntu/.rustup/toolchains/1.98.0-x86_64-unknown-linux-gnu/bin/rustc')
RUSTC_SHA = '3690cc576ede140504698405d5d8fa3826aaadbe71699c6c4ed0a565d6f493e2'
STAGE = Path('/run/horizon266-legacy-build-v2')
OUT = Path('/var/lib/jetstreamer/horizon266-legacy-source-build-v2/result')
UNIT = 'horizon266-legacy-source-build-v2.service'
CAP = 2 << 30
WORK = Path('/tmp/horizon266-legacy-rustc-v2')
TMPFS_BYTES = 512 << 20
PARENTS = {
    'jetstreamer-firehose-4aa6d7a7eed843c9/lib-jetstreamer_firehose':
        'ahash cid dashmap futures_util log once_cell reqwest serde_cbor thiserror tokio xxhash_rust url',
    'jetstreamer-node-4d8b8213fc4e6e60/bin-jetstreamer-node':
        'ripget tempfile solana_clock sha2 serde_json libc',
}

def require(ok, msg):
    if not ok:
        raise ValueError(msg)

def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def recipe(source):
    lock = tomllib.loads((source/'Cargo.lock.original').read_text())
    locked = {(p['name'],p['version']):p for p in lock['package']}
    deps = BASE/'deps'
    fingerprints = BASE/'.fingerprint'
    argv = [str(RUSTC),'--edition=2024','--crate-name','horizon266_legacy_source',
            str(STAGE/'main.rs'),'--out-dir',str(WORK),'-C','opt-level=1','-C','debuginfo=0','-C','codegen-units=1',
            '-C','strip=debuginfo','-C','linker=/usr/bin/cc','--emit',
            'link='+str(OUT/'legacy-source')+',dep-info='+str(OUT/'inputs.d'),
            '-C','link-arg=-Wl,-Map='+str(OUT/'link.map'),'-L','dependency='+str(deps)]
    records = []
    for parent, names in PARENTS.items():
        parent_fp = fingerprints/(parent+'.json')
        metadata = json.loads(parent_fp.read_bytes())
        require('s3-backend' not in metadata['features'],'unexpected S3 feature')
        for name in names.split():
            hits = [d for d in metadata['deps'] if d[1]==name]
            require(len(hits)==1, name+' parent fingerprint')
            fp = hits[0][3].to_bytes(8,'little').hex()
            candidates = [p for p in fingerprints.glob('*/lib-'+name) if p.read_text().strip()==fp]
            require(len(candidates)==1, name+' ambiguous cached library')
            p = candidates[0]
            suffix = p.parent.name.rsplit('-',1)[1]
            artifact = deps/f'lib{name}-{suffix}.rlib'
            depinfo = deps/f'{name}-{suffix}.d'
            entries = depinfo.read_text().splitlines()[0].split(': ',1)[1].split()
            versions = {(m.group(1),m.group(2)) for e in entries
                        if (m:=re.search(r'/registry/src/[^/]+/([^/]+?)-(\d+\.\d+\.\d+(?:[+.-][\w.+-]+)?)/',e))}
            require(len(versions)==1 and artifact.is_file(),name+' package source/version')
            package, version = next(iter(versions))
            registry = locked[(package,version)]
            require(len(registry['checksum'])==64,name+' original lock source')
            records.append(dict(name=name,artifact=str(artifact),fingerprint=str(p),fingerprint_value=fp,
                                parent=str(parent_fp),parent_sha256=digest(parent_fp),depinfo=str(depinfo),
                                package=package,version=version,registry_checksum=registry['checksum'],
                                features=json.loads((p.parent/(p.name+'.json')).read_bytes())['features']))
            argv.extend(['--extern',name+'='+str(artifact)])
    native=[]
    for group in ('aws-lc-sys','ring','openssl-sys','zstd-sys'):
        for output in sorted((BASE/'build').glob(group+'-*/output')):
            for line in output.read_text().splitlines():
                if line.startswith('cargo:rustc-link-search=native='):
                    path = Path(line.split('=',2)[2])
                    require(path.is_relative_to(BASE/'build') and path.is_dir(),'unbound native search path')
                    argv.extend(['-L','native='+str(path)])
                    native.append(dict(output=str(output),sha256=digest(output),path=str(path)))
    return dict(argv=argv,cwd=str(WORK),dependencies=records,native=native,rustc_sha256=RUSTC_SHA)

def build():
    group = Path('/sys/fs/cgroup/system.slice')/UNIT
    require(Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+UNIT and
            os.getuid()==1000 and os.environ.get('INVOCATION_ID'),'wrong build unit')
    for key,value in [('memory.max',CAP),('memory.swap.max',0),('pids.max',96)]:
        require((group/key).read_text().strip()==str(value),'wrong '+key)
    require(sorted(l.split(':')[0].strip() for l in Path('/proc/self/net/dev').read_text().splitlines()[2:])==['lo'],'private network')
    tmp_rows = [line.split(' - ', 1)[1].split()[0] for line in Path('/proc/self/mountinfo').read_text().splitlines()
                if line.split()[4] == '/tmp']
    tmp = os.statvfs('/tmp')
    require(Path.cwd() == Path('/tmp') and tmp_rows == ['tmpfs'] and
            tmp.f_blocks * tmp.f_frsize == TMPFS_BYTES, 'wrong private compiler tmpfs')
    require(not list(OUT.iterdir()) and not os.access(STAGE,os.W_OK) and
            all(p.is_file() and not os.access(p,os.W_OK) for p in STAGE.iterdir()),
            'source must be read-only and result directory empty')
    provenance=json.loads((STAGE/'provenance.json').read_bytes())
    def compiler_inputs():
        for row in provenance['files']:
            require(digest(STAGE/row['name'])==(row.get('fragment_sha256') or row['sha256']),row['name'])
        require(digest(RUSTC)==RUSTC_SHA,'compiler image')
    compiler_inputs()
    plan = recipe(STAGE)
    accepted=json.loads((STAGE/'plan.json').read_bytes())
    require(plan==accepted,'staged plan drift')
    measured = {r['artifact']:digest(Path(r['artifact'])) for r in plan['dependencies']}
    WORK.mkdir(mode=0o700)
    env=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',TMPDIR=str(WORK),LANG='C',CARGO_PKG_VERSION='0.8.1')
    compiled=subprocess.run(plan['argv'],env=env,check=True,cwd=plan['cwd'])
    compiler_inputs()
    require(measured=={p:digest(Path(p)) for p in measured},'library changed during build')
    actual=(OUT/'inputs.d').read_text().splitlines()[0].split(': ',1)[1].split()
    need={'main.rs','native.inc','epochs.rs','network.rs','index.rs','archive.rs'}
    require({(WORK/s).resolve() for s in actual}=={STAGE/s for s in need},'compiler input closure')
    result=dict(invocation=os.environ['INVOCATION_ID'],compiler_argv=compiled.args,compiler_cwd=plan['cwd'],
                compiler_tmpdir=env['TMPDIR'],compiler_tmpfs_bytes=tmp.f_blocks*tmp.f_frsize,
                plan_sha256=digest(STAGE/'plan.json'),
                provenance_sha256=digest(STAGE/'provenance.json'),extern_sha256=measured,
                output_sha256={n:digest(OUT/n) for n in ('legacy-source','inputs.d','link.map')})
    with (OUT/'build.json').open('x') as f:
        json.dump(result,f,indent=2)
        f.flush()
        os.fsync(f.fileno())

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan',type=Path,metavar='MATERIALIZED_SOURCE')
    mode.add_argument('--build',action='store_true')
    args=parser.parse_args()
    if args.build:
        build()
    else:
        print(json.dumps(recipe(args.plan),indent=2))
