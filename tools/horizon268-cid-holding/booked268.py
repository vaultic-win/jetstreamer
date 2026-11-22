"""Fixed epoch 267 and 268 booked payloads and pure fit calculation. Main owns admission and completion."""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

EPOCH = 268
M = 1 << 20
SIZE = 12_161_495_866
SHA = 'c4555600164ccd37313ae7f02c3fd36fd47a8117c91a92b812c1052ab2b2ce68'
DEV, INO = 66305, 18336466
STAMP = (DEV, INO, SIZE, 1795317228600534172, 1795317228862535056)
SRC = Path('/var/lib/jetstreamer/horizon268-cid-input-v175-a1/index.body')
DEST = Path('/var/lib/jetstreamer/horizon268-cid-holding-restore-v1')
TMP = Path('/run/horizon268-cid-holding-work')
CG = Path('/sys/fs/cgroup')
LOCK = Path('/run/horizon-v164-main-build-booking.lock')
MAIN = '01a1f8f4-293b-7a91-a36e-2e7658bba721'
BOOT = '3b17d0055c3a4a0e8841da097e0957b5'
HARD = 1211435323392
PAID = '480ec34cb8286d8ec29d8950f606984decdb43fdf43c4e7194bf78efd7c387b5'
BASE_LEDGER = '7beddd086fb5c8a5d602ab0cb51b1dd3dad2db87e2c0ef96c7e6c933e152e26d'
OWNERS = {
    'horizon-singleton-211-capped-4aeca563-v1.service',
    'horizon-upload-247-staged-fadfe2d4-v1.service',
    'horizon-qualify-265-replacement-20261119-v3.service',
}
PINS = {
    Path('/usr/bin/sha256sum'): '27a7d8f6a005702618e92c88f20b829d38247ad3369e0c35b1ff219d15194bd1',
    Path('/usr/bin/curl'): 'd90fe31761b6ac228a75507b62186b3ed00ccf1f0fc5c7ce704bbe3936e31343',
}
ORIGINAL_267 = Path('/var/lib/jetstreamer/horizon267-cid-input-v173-a1/index.body')
SEAL267 = {'path': '/home/ubuntu/.codex/diagnostics/horizon267-rooted-input-seal-v175-a1/completion.json',
           'sha256': 'd8e880e77656163a5c0108aa88a4b920b3cee46b695a008b9a42c7e1d6b7a1a2'}
# service MiB, controller MiB, new tmpfs MiB, extra data bytes, wall seconds
PHASES = {
    'build': (384, 64, 40, 0, 600),
    'park': (320, 64, 40, 0, 7200),
    'verify': (256, 64, 0, 0, 3600),
    'restore': (320, 64, 0, SIZE + 4*M, 3600),
    'retire': (128, 64, 0, 0, 900),
}

def select_epoch267():
    """Select the separately compiled 267 image for this single-operation process."""
    global EPOCH, SRC, SIZE, SHA, INO, STAMP, TMP, DEST
    EPOCH = 267
    SRC = ORIGINAL_267
    SIZE = 10_392_794_246
    SHA = '03ee92c1cd55485275d21633e4fd2a759eb6fb21484b580a0c6e98901795a9fc'
    INO = 18336175
    STAMP = (DEV, INO, SIZE, 1795315093251462982, 1795315093465463670)
    DEST = Path('/var/lib/jetstreamer/horizon267-cid-holding-restore-v1')
    TMP = Path('/run/horizon267-cid-holding-work')
    PHASES['restore'] = (320, 64, 0, SIZE + 4*M, 3600)


def need(ok, message):
    if not ok:
        raise ValueError(message)

def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

def binding(ref):
    path = Path(ref['path'])
    st = path.lstat()
    need(path.resolve() == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
         and st.st_nlink == 1 and not st.st_mode & 0o022 and st.st_size <= 4*M, 'unsafe receipt')
    b = path.read_bytes()
    after = path.lstat()
    need((after.st_dev, after.st_ino, after.st_ctime_ns) == (st.st_dev, st.st_ino, st.st_ctime_ns)
         and hashlib.sha256(b).hexdigest() == ref['sha256'], 'receipt changed')
    return json.loads(b)

def stamp(p):
    m = p.lstat()
    need(p.resolve() == p and stat.S_ISREG(m.st_mode) and
         (m.st_uid,m.st_gid,m.st_nlink,stat.S_IMODE(m.st_mode)) == (0,0,1,0o400), 'unsafe input')
    return (m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_ctime_ns)

def census(dev, ino):
    """The privileged host controller must run this in the initial PID namespace."""
    need(os.readlink('/proc/self/ns/pid') == os.readlink('/proc/1/ns/pid')
         and Path('/proc/1/comm').read_text().strip() == 'systemd', 'full host PID view required')
    hits = []
    seen_mounts = set()
    dev_field=f'{os.major(dev)}:{os.minor(dev)}'.encode()
    roots={os.fsencode(SRC),os.fsencode(SRC.with_name(f'.horizon{EPOCH}-quarantine-{SHA[:8]}.body')),
           os.fsencode(f'/var/lib/jetstreamer/horizon{EPOCH}-cid-holding-custody-v1/quarantine-{SHA[:8]}.body')}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():
            continue
        try:
            ns=os.readlink(p/'ns/mnt')
            if ns not in seen_mounts:
                with (p/'mountinfo').open('rb') as mounts:
                    for row in mounts:
                        fields=row.split()
                        if len(fields)>5 and fields[2]==dev_field and fields[3] in roots:
                            hits.append((p.name,'file-bind-mount'))
                seen_mounts.add(ns)
            for fd in (p/'fd').iterdir():
                try:
                    m = fd.stat()
                except FileNotFoundError:
                    continue
                if (m.st_dev,m.st_ino) == (dev,ino):
                    hits.append((p.name,fd.name))
            with (p/'maps').open('rb') as maps:
                for line in maps:
                    cells = line.split(None,5)
                    if len(cells) < 5 or int(cells[4]) != ino:
                        continue
                    a,b = cells[3].split(b':')
                    if os.makedev(int(a,16),int(b,16)) == dev:
                        hits.append((p.name,'mmap'))
        except (FileNotFoundError, ProcessLookupError):
            continue
    return sorted(set(hits))

def price(cap, phase, retained, serial, metadata):
    """retained includes existing external tmpfs. New private stage is charged separately."""
    svc,ctl,stage,disk,wall = PHASES[phase]
    context = cap['complete_fit']
    m = cap['finite_memory']
    need(set(context['owners']) == OWNERS and
         context['stopped228']['memory_retained'] == 120_000_000_000 and
         context['stopped266']['memory_retained'] == 176_000_000_000 and
         all(context[k]['released_memory'] == context[k]['released_disk'] == 0 for k in ('stopped228','stopped266')) and
         m['baseline_hard'] == HARD and cap['registered_ledger']['sha256'] == BASE_LEDGER and
         cap['minimum_free_bytes'] == cap['floor']['minimum_free'] >= cap['floor']['registered_independent_floor'] >= 4213923166208,
         'different complete funding basis')
    # A dedicated park mount is destroyed with its service. Main can issue its
    # entire lifetime from the same exclusive finite allocation as the worker.
    serial_amounts = {0, (svc + ctl) * M}
    if phase == 'park':
        serial_amounts.add((svc + ctl + stage) * M)
    need(type(retained) is int and retained >= 0 and type(metadata) is int and metadata>=0 and
         type(serial) is int and serial in serial_amounts, 'invalid external obligations')
    floor = cap['minimum_free_bytes']
    free = min(context['free'],*(v['free'] for v in cap['allocated_backing'].values()))
    increment = (svc+ctl+stage)*M + retained - serial
    hard = context['mem']['MemTotal'] - HARD - increment
    growth = context['mem']['MemAvailable'] - (HARD+increment-sum(context['charged_memory'].values()))
    charge = disk + metadata
    return dict(phase=phase, service=svc*M, controller=ctl*M, new_tmpfs=stage*M, retained=retained,
                serial=serial, hard_margin=hard, growth_margin=growth, physical_free=free,
                protected_floor=floor, physical_peak=charge, disk_margin=free-floor-charge,
                zero_data_path=(charge==0 and phase!='retire'),
                requires_prepaid_control_space=(charge==0 and phase=='retire'), seconds=wall, capacity_credit=0,
                fits=min(hard,growth)>=0 and (charge==0 or free>=floor+charge),
                serial_requires_independent_Main_assignment=bool(serial))

def bind_fit(booking):
    base = binding(booking['complete_basis'])
    op = booking['operation']
    price_row = price(base,op,booking['retained'],booking['serial'],booking['metadata'])
    need(price_row == booking['price'] and price_row['fits'] and
         0<=time.time()-base['recorded_unix_seconds']<=120 and time.time()<base['expires_unix_seconds'],
         'expired or changed booked fit')
    held=binding(booking['retained_review'])
    need(held['controller']==MAIN and held['complete_basis']==booking['complete_basis'] and
         sum(x['cap_bytes'] for x in held['obligations'])==booking['retained'] and
         all(type(x['cap_bytes']) is int and x['cap_bytes']>=0 for x in held['obligations']) and
         len({x['id'] for x in held['obligations']})==len(held['obligations']),
         'external retained inventory mismatch')
    if booking['serial']:
        paid = binding(booking['serial_basis'])
        grant = binding(booking['serial_assignment'])
        need(booking['serial_basis']['sha256']==PAID and paid['fits'] and
             binding(paid['source_review'])['Main_accepted'] and
             paid['requested_memory']==6368*M and paid['source_basis']['e434_ledger']==base['registered_ledger'] and
             grant['Main_accepted'] and grant['phase']==op and grant['bytes']==booking['serial'] and
             grant['source']==booking['serial_basis'] and grant['complete_basis']==booking['complete_basis'] and
             grant['exclusive']==True,'new phase-specific exclusive serial grant required')
    return price_row

def booked_kernel(b):
    op = b['operation']
    need(op in PHASES and b['schema']==f'horizon{EPOCH}-cid-holding-booking-v1'
         and b['controller']==MAIN and b['boot']==BOOT==Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-','')
         and os.geteuid()==0 and os.uname().nodename=='horizon-vaultic','wrong executing identity')
    fit = bind_fit(b)
    self_cgroup = Path('/proc/self/cgroup').read_text().strip().split('::',1)[1]
    need(self_cgroup==b['cgroup'] and self_cgroup.startswith('/') and self_cgroup!='/','wrong paid cgroup')
    cg = CG / self_cgroup.lstrip('/')
    quota,period=map(int,(cg/'cpu.max').read_text().split())
    need(int((cg/'memory.max').read_text())==fit['service'] and
         (cg/'memory.swap.max').read_text().strip()=='0' and int((cg/'pids.max').read_text()) in range(4,65) and
         0<quota<=period and os.sched_getaffinity(0)=={56} and (cg/'cpuset.cpus.effective').read_text().strip()=='56',
         'kernel effective phase envelope')
    # The controller holds this common lock for the entire operation and is in the original PID view.
    locks=Path('/proc/locks').read_text().splitlines()
    st=LOCK.stat(); code=f'{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}'
    need(any(len(row)>5 and row[1:4]==['FLOCK','ADVISORY','WRITE'] and row[4]==str(b['controller_pid'])
             and row[5]==code for row in (x.split() for x in locks)), 'booking owner lost common lock')
    owner=Path('/proc')/str(b['controller_pid'])
    need((owner/'stat').read_text().rsplit(')',1)[1].split()[19]==str(b['controller_start_ticks']), 'controller PID reused')
    return fit

def native_conditions(b):
    op=b['operation']
    need(op in ('park','verify','restore'), 'expected network phase')
    fit=booked_kernel(b)
    image=Path(b['image']['path']);m=image.lstat()
    need(image.resolve()==image and stat.S_ISREG(m.st_mode) and m.st_uid==0 and not m.st_mode&0o222
         and m.st_nlink==1 and m.st_size<32*M and digest(image)==b['image']['sha256'],'different sealed worker')
    for tool,sha in PINS.items():
        need(digest(tool)==sha, 'different native transport or hash executable')
    if op=='park':
        need(stamp(SRC)==STAMP and not census(DEV,INO),'original CID index is open or changed')
        need(b['closed_source_review']['sha256'] and binding(b['closed_source_review'])['source_sha256']==SHA,'source closure missing')
        closed=binding(b['closed_source_review'])
        need(closed['controller']==MAIN and closed['source_identity']==list(STAMP) and
             closed['closed'] and closed['release_authorized']==False and closed['pending_writers']==[] and
             0<=time.time()-closed['recorded_unix_seconds']<=120,'closed source review not current')
        v=os.statvfs(TMP)
        need(subprocess.check_output(['/usr/bin/findmnt','-nr','-T',str(TMP),'-o','TARGET,FSTYPE'],text=True).split()==[str(TMP),'tmpfs']
             and v.f_blocks*v.f_frsize<=fit['new_tmpfs'] and v.f_bavail*v.f_frsize>=32*M+65536,
             'funded private part stage missing')
    elif op=='restore':
        need(DEST.parent==Path('/var/lib/jetstreamer') and DEST.stat().st_dev==SRC.parent.parent.stat().st_dev
             and fit['physical_peak']>=SIZE+4*M,'full restore overlap not funded')
    env_digest=hashlib.sha256(os.environ['HORIZON_S3_ENDPOINT'].encode()).hexdigest()
    need(env_digest==b['authenticated_endpoint_sha256'],'changed approved endpoint')
    if fit['zero_data_path']:
        # Check every mount alias of the production data device in this actor view.
        # tmpfs and pipes supply every writable stage and receipt. Native tools never start services.
        dev=f'{os.major(DEV)}:{os.minor(DEV)}'
        info=[r.split() for r in Path('/proc/self/mountinfo').read_text().splitlines()]
        data=[r for r in info if r[2]==dev]
        need(data and all('ro' in r[5].split(',') for r in data)
             and all(not (stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_dev==DEV) for fd in (1,2)),
             'zero data phase has a writable data-device alias or output')
    return image

def actor(ref):
    b=binding(ref)
    image=native_conditions(b)
    op=b['operation']
    # Main supervises the complete cgroup for the booked duration, including curl/hash descendants.
    env={k:os.environ[k] for k in ('HORIZON_S3_ENDPOINT','HORIZON_ACCESS_KEY_ID','HORIZON_SECRET_ACCESS_KEY')}
    r=subprocess.run([str(image),op],env=env,capture_output=True,timeout=PHASES[op][4])
    if r.returncode:
        message=r.stderr.decode(errors='replace')
        for value in env.values():
            if value:
                message=message.replace(value,'[redacted]')
        raise RuntimeError(f'native {op} exited {r.returncode}: {message[-1000:]}')
    doc=json.loads(r.stdout)
    need(doc['operation']==op and doc['sha256']==SHA and doc['bytes']==SIZE and doc['epoch']==EPOCH and doc['parts']==(SIZE+32*M-1)//(32*M) and
         re.fullmatch('[0-9a-f]{64}',doc['manifest_sha256']) and doc['capacity_credit']==0 and not doc['canonical_publication'],
         'native result mismatch')
    if op=='restore':
        m=stamp(DEST/'index.body')
        need(m[2]==SIZE and m[:2]!=(DEV,INO),'restore identity')
        doc['restored_identity']=m
    if op=='park':
        need(stamp(SRC)==STAMP,'source incarnation after park')
    return dict(schema=f'horizon{EPOCH}-cid-holding-actor-v1',booking=ref,worker=b['image'],result=doc)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--epoch',type=int,choices=(267,268),default=268)
    sub=p.add_subparsers(dest='action',required=True)
    f=sub.add_parser('fit')
    f.add_argument('basis',type=Path);f.add_argument('phase',choices=PHASES)
    for name in ('retained','serial','metadata'):
        f.add_argument(name,type=int)
    a=sub.add_parser('actor');a.add_argument('booking',type=Path);a.add_argument('sha256')
    args=p.parse_args()
    if args.epoch==267:
        select_epoch267()
    if args.action=='fit':
        base=json.loads(args.basis.read_bytes())
        if 'fit' in base:
            base=base['fit']['complete_basis']
        output=price(base,args.phase,args.retained,args.serial,args.metadata)
    else:
        output=actor(dict(path=str(args.booking),sha256=args.sha256))
    print(json.dumps(output,sort_keys=True),flush=True)
if __name__=='__main__':
    main()
