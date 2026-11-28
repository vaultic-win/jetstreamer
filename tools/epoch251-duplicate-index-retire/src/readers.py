"""Inspect executable and configuration edges to a single original 251 download."""
import argparse, hashlib, json, os, re, subprocess
from collections import defaultdict
from pathlib import Path

PRIVATE=Path('/home/ubuntu/.jetstreamer-private')
def scan(own=''):
    prefix='qualification-251-index-20261118-v1'
    selected_root=PRIVATE/prefix
    target=selected_root/'cid251.partial'
    roots={'horizon251-index-transfer-20261118-v1.service','horizon251-index-cache-seal-20261118-v1.service'}
    component=re.compile(rb'(?:/home/ubuntu/\.jetstreamer-private/)?'+re.escape(os.fsencode(prefix))+rb'(?![A-Za-z0-9_.-])(?:/[A-Za-z0-9_./+@=-]*)?')
    def relevant(blob):
        for match in component.finditer(blob):
            literal=Path(os.fsdecode(match[0]))
            candidate=literal if literal.is_absolute() else PRIVATE/literal
            if candidate==target or (candidate==selected_root or selected_root in candidate.parents) and candidate in target.parents:
                return True
        return (b'/horizon251-index-cache-20261118-v1/seal-plan.json' in blob
                or re.search(rb'(?<![A-Za-z0-9_.-])cid251[.]partial(?![A-Za-z0-9_.-])',blob) is not None)
    def activation(line):
        start=line.lstrip()
        names=re.findall(rb'(?<![A-Za-z0-9_.@-])[A-Za-z0-9_.@-]+\.(?:service|timer|path)(?![A-Za-z0-9_.@-])',line)
        if not any(os.fsdecode(name) in roots for name in names):return False
        return (start.startswith((b'Wants=',b'Requires=',b'BindsTo=',b'Unit=',b'Activates=',b'OnFailure=',b'OnSuccess=',b'PropagatesReloadTo='))
                or re.search(rb'\bsystemctl\b[^\n]*(?:\bstart\b|\brestart\b|\btry-restart\b|\benable\b)',line) is not None)
    configuration=[Path(p) for p in ('/etc/systemd/system','/usr/lib/systemd/system','/usr/local/lib/systemd/system','/run/systemd/system','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/etc/systemd/user','/usr/lib/systemd/user','/etc/cron.d','/etc/crontab','/var/spool/cron/crontabs','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly')]
    configuration.append(PRIVATE/'systemd-staging')
    for h in [Path('/root'),*Path('/home').iterdir()]:
        configuration.extend((h/'.config/systemd',h/'.local/share/systemd'))
    for user in Path('/run/user').glob('*'):
        configuration.extend(user/'systemd'/s for s in ('user','transient','generator','generator.early','generator.late'))
    recipe=re.compile(rb'/(?:var/lib/jetstreamer|usr/local/(?:bin|lib/jetstreamer)|home/ubuntu/(?:\.jetstreamer-private|\.codex/diagnostics|workspace/jetstreamer/(?:scripts|tools))|run/horizon|tmp/horizon)[A-Za-z0-9_/+.@=,:-]+')
    budget=0;cached={};visited=set();hits=[];aliases=defaultdict(set);unresolved=[]
    def read(p):
        nonlocal budget
        if p in cached:return cached[p]
        n=p.stat().st_size
        if n>8<<20:raise ValueError('config exceeds metadata bound '+str(p))
        with p.open('rb') as f:
            head=f.read(128)
            if head.startswith(b'\x7fELF') or b'\0' in head:return b''
            f.seek(0);data=f.read((8<<20)+1)
        budget+=len(data)
        if len(data)!=n or budget>512<<20:raise ValueError('changed or oversized metadata graph')
        cached[p]=data
        return data
    def visit(p,ancestors):
        if p.is_symlink() and not p.exists():
            if (relevant(os.fsencode(p)) or relevant(os.fsencode(os.readlink(p)))):unresolved.append(str(p))
            return
        real=p.resolve(strict=True)
        if real==Path('/dev/null') or real in ancestors:return
        if real.is_dir():
            for child in p.iterdir():visit(child,ancestors|{real})
        elif real.is_file():aliases[real].add(str(p))
    for root in configuration:
        if root.exists():visit(root,set())
    def edges(data):
        return set(recipe.findall(data))
    def captured(data,trail):
        if relevant(data) or any(activation(line) for line in data.splitlines()):
            hits.append({'origin':trail[0],'chain':trail[1:],'sha256':hashlib.sha256(data).hexdigest()})
    def follow(p,trail):
        if len(trail)>16:raise ValueError('unresolved command depth')
        try:real=p.resolve(strict=True)
        except (FileNotFoundError,NotADirectoryError):return
        key=(trail[0],real)
        if key in visited or not real.is_file():return
        visited.add(key)
        if real.suffix.lower() in ('.env','.jet','.zst','.gz','.index','.so','.rlib','.bin','.lock','.ext4','.tar') or any(k in real.name.lower() for k in ('credential','secret')):return
        # Inspect the magic first so a large executable is never read as configuration.
        with real.open('rb') as fp:magic=fp.read(128)
        if magic.startswith(b'\x7fELF') or b'\0' in magic:return
        if not (real.suffix in ('.json','.py','.sh','.bash','.toml','.conf','.service','.timer','.path') or magic.startswith(b'#!')):return
        data=read(real);chain=[*trail,str(real)];captured(data,chain)
        # Enumerate executable/configuration edges. Receipt and archive references inside a JSON
        # are evidence; recurse through explicit configuration and command fields only.
        if real.suffix=='.json':
            try:obj=json.loads(data)
            except (json.JSONDecodeError,UnicodeDecodeError):
                # Some historical control paths carry JSON lines or a zero-byte marker.
                # Retain their direct hits and follow every literal recipe path.
                for item in edges(data):follow(Path(os.fsdecode(item)),chain)
                return
            def commands(v):
                if isinstance(v,dict):
                    for k,x in v.items():
                        if k.lower() in ('plan','configuration','settings','script','executable','command','argv','args','exec','config','launcher','wrapper','manifest','source_plan'):yield json.dumps(x).encode()
                        elif isinstance(x,(list,dict)):yield from commands(x)
                elif isinstance(v,list):
                    for x in v:yield from commands(x)
            literals=set().union(*(edges(x) for x in commands(obj)))
        else:literals=edges(data)
        for item in literals:follow(Path(os.fsdecode(item)),chain)
    for dest,names in aliases.items():
        if own and names=={own} and str(dest)==own:
            continue
        data=read(dest)
        for name in sorted(names):
            service_data=b'\n'.join(line for line in data.splitlines() if not line.lstrip().startswith((b'#',b';',b'Description=',b'Documentation=',b'After=',b'Before=')))
            captured(service_data,[name])
            for line in data.splitlines():
                directive=line.lstrip()
                if directive.startswith((b'ExecStart',b'ExecStop',b'ExecReload',b'ExecCondition',b'EnvironmentFile=',b'WorkingDirectory=')) or '/cron' in name:
                    for item in edges(line):follow(Path(os.fsdecode(item)),[name])
    return dict(selection='cid',original_journal=original_journal(),files=len(aliases),inspected_command_sources=len(visited),remaining=hits,unresolved=unresolved)

def original_journal():
    units=['horizon251-index-transfer-20261118-v1.service','horizon251-index-cache-seal-20261118-v1.service']
    args=['/usr/bin/journalctl','--since','2026-11-18 18:55 UTC','--until','2026-11-18 19:02 UTC','--no-pager','-o','json']
    for unit in units:
        args.extend(['-u',unit])
    rows=[]
    for line in subprocess.check_output(args,timeout=15).splitlines():
        r=json.loads(line)
        if r.get('MESSAGE_ID') in ('39f53479d3a045ac8e11786248231fbf','7ad2d189f7e94e70a38c781354912448') or r.get('_COMM')=='curl':
            rows.append({k:r[k] for k in ['__CURSOR', '_BOOT_ID', '_UID', '_PID', 'UNIT', '_SYSTEMD_UNIT', 'INVOCATION_ID', '_SYSTEMD_INVOCATION_ID', 'MESSAGE_ID', 'MESSAGE'] if k in r})
    signature=hashlib.sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if len(rows)!=6 or signature!='ab24159b001358e95cddb9c59f532c4c1173b714ad10c264ced7248a17db0827':
        raise ValueError('Original transfer, response, PID1 success, or sealer changed')
    return dict(projection_sha256=signature,events=len(rows),transfer_iid='8fd0271eb06b4307aba4e116c12f00d8',seal_iid='ae5f2adc7b964ea5a8d37fc2620dfae8')

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('selection', choices=['cid'])
    parser.add_argument('--own',default='')
    args=parser.parse_args()
    if args.own and not re.fullmatch(r'/run/systemd/transient/horizon251-index-cid-(check|retire)-a[1-9][0-9]{0,2}[.]service',args.own):
        raise ValueError('foreign unit')
    print(json.dumps(scan(args.own),indent=2))
