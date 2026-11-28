"""Read-only epoch 141 owner fence. stdout is one JSON receipt; nonzero rejects."""
import collections
import ctypes
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-replay-20261120-v1')
SOURCE = Path('/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1/retained')
CAPTURE = Path('/var/lib/jetstreamer/horizon_runtime_data/held141-collection-retirement-20261120-v1/state/captured-rocksdb')
STAGE = CAPTURE.with_name('captured-members')
MEMBERS = BASE / 'held141-local-census-v2/ALL_MEMBERS.json'
KNOWN = BASE / 'HELD141_KNOWN_CONSUMERS.json'
REVIEW = BASE / 'HELD141_SCHEDULED_CONSUMER_REVIEW_1637.json'
READER = BASE / 'held141-restored-native-v1/READER_QUALIFICATION.json'
DERIVATIVE = Path('/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1')
LOCK = Path('/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock')
DEV = 64512
DIR_ID = 105578544
SEALED = Path('/usr/local/lib/jetstreamer')
LIBC = ctypes.CDLL(None, use_errno=True)
PATHS = re.compile(rb"/(?:usr/local/lib/jetstreamer|home/sol/(?:\.jetstreamer-private|workspace)|var/lib/jetstreamer)[A-Za-z0-9_/@+:.%=-]*")
UNIT = re.compile(r'^[A-Za-z0-9_.@:\\-]+\.(?:service|timer|path|socket|target|mount|automount|scope)$')
ARCHIVE_PACKAGES = re.compile(r'(?:141.*(?:ledger|retention|native|acquisition)|(?:native|retention|ledger).*141)',re.I)


def require(value, reason):
    if not value:
        raise ValueError(reason)


def ident(st):
    return (st.st_dev, st.st_ino)


def bound(path, expected):
    data=path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == expected, 'historical receipt changed: ' + str(path))
    return json.loads(data)


def markers(after, out, reasons):
    table=bound(MEMBERS,'0a623fd77b45bc4ce501aed595e4a95fb68b34362de364a6a0bca2b293854477')
    ids={(v[0],v[1]) for _,v,_ in table}
    require(len(ids)==6094 and all(d==DEV for d,_ in ids),'invalid complete member identity table')
    ids.add((DEV,DIR_ID))
    path=CAPTURE if after else SOURCE
    require(ident(path.lstat())==(DEV,DIR_ID) and path.is_dir(),'wrong retained or captured directory identity')
    if after:
        require(not os.path.lexists(SOURCE),'original path reappeared after capture')
        if os.path.lexists(STAGE):
            member_dir=STAGE.lstat()
            require(stat.S_ISDIR(member_dir.st_mode) and member_dir.st_dev==DEV and member_dir.st_uid==0 and member_dir.st_gid==0 and not member_dir.st_mode&0o022,'untrusted captured-members directory')
            ids.add(ident(member_dir))
    known=bound(KNOWN,'53f1e1f54dc6f41e2be9b0a2140349942688c3b455f6e855c9e1196f1b106661')
    prior=bound(REVIEW,'dcdcf501b5bc73069a3ef29cb0762a2aaccbc0222578559b0591b8d5e1f8b60b')
    future=bound(READER,'fe59b3f3e91fd901cffdb060027f922631230ea0df90ead1ad369758d66e9c5d')
    require(all(future[k] is True for k in ('known_full_target_derivative_reopened_in_current_rust_reader','real_ledger_readonly_reopened_at_separate_database_path','new_inode_synthetic_tar_restored_and_read_by_same_native_binary')), 'future reader proofs missing')
    for record in future['verified_inputs']:
        p=Path(record['path'])
        require(hashlib.sha256(p.read_bytes()).hexdigest()==record['sha256'], 'changed future-reader evidence: '+str(p))
    n=known['source_native_acquisition']
    native=bound(Path(n['path']),n['sha256'])
    require(native.get('full_target_raw_acquisition_complete') is True and native.get('complete_retained_census_revalidated_after_close') is True and native.get('raw_acquired_target_count')==18283, 'native acquisition incomplete')
    derivative={}
    for name,inode,size,ctime in [('original-entries.data',100539636,15067873514,1795118103963465226),('index.json',100539635,7576887,1795118070495307606)]:
        p=DERIVATIVE/name;s=p.lstat()
        require(ident(s)==(DEV,inode) and s.st_size==size and s.st_ctime_ns==ctime and s.st_mode==0o100444 and s.st_uid==s.st_gid==0 and s.st_nlink==1,'retained derivative identity changed: '+str(p))
        derivative[name]=[s.st_dev,s.st_ino,s.st_size,s.st_ctime_ns]
    out['retained_derivative']=derivative
    require(ident(LOCK.lstat())==(DEV,101135013),'campaign lock inode changed')
    ancestors=set()
    pid=os.getppid()
    while pid>0 and pid not in ancestors:
        ancestors.add(pid);pid=int(Path('/proc',str(pid),'status').read_text().split('PPid:')[1].split()[0])
    lockid=(os.major(DEV),os.minor(DEV),101135013)
    holders=[]
    for line in Path('/proc/locks').read_text().splitlines():
        a=line.split()
        if len(a)<6 or a[1:4]!=['FLOCK','ADVISORY','WRITE']: continue
        major,minor,ino=a[5].split(':')
        if (int(major,16),int(minor,16),int(ino))==lockid:holders.append(int(a[4]))
    out['lock_owner_pids']=holders
    if len(holders)!=1 or holders[0] not in ancestors:reasons.append('the exact campaign mutation lock must be held by an ancestor during this scan')
    return ids,{r['unit'] for r in prior['rows']}


def systemctl(*args):
    p=subprocess.run(['systemctl','--system','--no-pager',*args],capture_output=True,text=True,timeout=30)
    if p.returncode not in (0,4):raise ValueError(f'systemd query failed ({p.returncode})')
    return p.stdout


def scheduler(out,reasons,ids):
    """Reverse references in operator launch plans and scheduler fragments plus known native owners."""
    direct={str(SOURCE),str(SOURCE.parent)}
    base=SEALED
    packages={e.name for e in os.scandir(base) if e.is_dir(follow_symlinks=False)}
    allfiles=set()
    # Scan executable scripts and declared launch/config plans independently of the package name.
    # Named epoch141 native packages additionally include compiled executable and source evidence.
    native=[]
    for name in packages:
        d=base/name
        for f in os.scandir(d):
            if not f.is_file(follow_symlinks=False):continue
            p=Path(f.path); n=f.name.lower()
            if p.suffix in ('.py','.sh','.service','.timer','.path') or (p.suffix=='.json' and ('plan' in n or 'config' in n)) or (
                  ARCHIVE_PACKAGES.search(name) and p.suffix in ('.rs','.json') and n not in ('deployment-seal-receipt.json','sha256sums')):
                allfiles.add(p)
            if ARCHIVE_PACKAGES.search(name) and f.stat().st_mode&0o111 and p.suffix not in ('.sh','.py'):native.append(p)
    roots=['/etc/systemd/system','/run/systemd/system','/run/systemd/transient','/usr/lib/systemd/system','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/etc/systemd/user','/usr/lib/systemd/user','/home/sol/.config/systemd/user','/run/user/1001/systemd','/etc/cron.d','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly','/var/spool/cron/crontabs']
    configs={}
    for root in map(Path,roots):
        if not root.exists():continue
        def err(exc):raise exc
        for folder,_,files in os.walk(root,onerror=err):
            for name in files:
                p=Path(folder)/name
                if p.is_symlink():
                    if not p.exists() or not p.resolve().is_file():continue
                if not p.is_file():continue
                if 'cron' in str(root): kind='cron'
                elif UNIT.match(name):kind='unit'
                elif p.suffix=='.conf' and p.parent.name.endswith('.d'):kind='dropin'
                else:continue
                configs[p]=kind
    crontab=Path('/etc/crontab')
    if crontab.is_file():configs[crontab]='cron'
    # Unit commands can dispatch through an unsealed Python/shell entry point or pass a
    # plan as argv. Follow these controls forward before inverting the dependency graph.
    # Never follow ledger/archive payloads or export the contents of a launch plan.
    forward=set()
    seen_controls=set()
    def discover(body):
        for b in PATHS.findall(body):
            p=Path(os.fsdecode(b.rstrip(b'.')))
            if p in seen_controls or p in allfiles:continue
            suffix=p.suffix.lower()
            if suffix not in ('.py','.sh','.json',''):continue
            if suffix=='.json' and not re.search(r'plan|config|observer|control-request',p.name,re.I):continue
            if p.is_relative_to(SOURCE) or p.is_relative_to(CAPTURE) or p.is_relative_to(STAGE):continue
            seen_controls.add(p)
            try:s=p.stat()
            except (FileNotFoundError,NotADirectoryError):continue
            require(ident(s) not in ids,'control artifact aliases a retained inode: '+str(p))
            if not stat.S_ISREG(s.st_mode):continue
            if not suffix:
                if not s.st_mode&0o111:continue
                with p.open('rb') as file:
                    if file.read(2)!=b'#!':continue
            require(s.st_size<=128<<20,'oversize control reference needs independent review: '+str(p))
            allfiles.add(p);forward.add(p)
            require(len(forward)<=16384,'operator-control dependency limit reached')
    for p,kind in configs.items():
        require(p.stat().st_size<=16<<20,'oversize scheduler file: '+str(p))
        body=p.read_bytes()
        enabled_lines=body if kind=='cron' else b'\n'.join(line for line in body.splitlines() if line.lstrip().startswith(b'Exec'))
        discover(enabled_lines)
    done=set()
    while allfiles-done:
        batch=allfiles-done;done.update(batch)
        for p in batch:
            require(p.stat().st_size<=128<<20,'oversize launch/source file: '+str(p))
            discover(p.read_bytes())
    active=set();edges=collections.defaultdict(set); compiled=[];exact={str(p) for p in allfiles}|{str(p) for p in native}
    dirs={str(p.parent) for p in allfiles}|{str(p.parent) for p in native}
    def scan(p,body,staged=False):
        name=str(p)
        if any(os.fsencode(k) in body for k in direct):active.add(name)
        for b in PATHS.findall(body):
            k=os.fsdecode(b.rstrip(b'.'))
            if k in exact and k!=name:edges[k].add(name)
            elif k in dirs and k!=str(p.parent):edges[k].add(name)
    for p in sorted(allfiles):
        s=p.stat()
        # Large archive bodies, snapshots and database members are never read.
        require(s.st_size<=128<<20, 'oversize launch/source file needs independent review: '+str(p))
        scan(p,p.read_bytes())
    import mmap
    marker=os.fsencode(SOURCE.parent)
    for p in native:
        with p.open('rb') as f:
            if f.read(4)!=b'\x7fELF':continue
            with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as m:
                if m.find(marker)>=0:
                    active.add(str(p)); compiled.append(str(p))
    for p in configs:
        require(p.stat().st_size<=16<<20,'oversize scheduler file: '+str(p))
        scan(p,p.read_bytes())
    # Package directory references can select an executable by shell expansion.
    pending=list(active); examined=set()
    while pending:
        node=pending.pop()
        if node in examined:continue
        examined.add(node)
        for owner in edges[node]|edges[str(Path(node).parent)]:
            if owner not in active:active.add(owner);pending.append(owner)
    owners=set()
    for p,kind in configs.items():
        if str(p) not in active:continue
        if kind=='cron' or 'systemd/user' in str(p) or str(p).startswith('/run/user/'):
            reasons.append('review matched cron/user activation: '+str(p));continue
        owners.add(p.name if kind=='unit' else p.parent.name.removesuffix('.d'))
    out['scheduler_inventory']={'metadata_files':len(allfiles),'forward_control_files':len(forward),'native_images_examined':len(native),'scheduler_files':len(configs),'compiled_literal_matches':sorted(compiled),'reachable_metadata_or_fragments':sorted(active),'direct_or_transitive_units':sorted(owners)}
    return owners


def exhausted_timer(name,r):
    if not (name.endswith('.timer') and r.get('ActiveState')=='active' and r.get('SubState') in ('running','elapsed')
            and r.get('UnitFileState')=='transient' and r.get('Triggers')
            and r.get('NextElapseUSecRealtime') in ('','n/a','infinity') and r.get('NextElapseUSecMonotonic')=='infinity'
            and r.get('OnClockChange')=='no' and r.get('OnTimezoneChange')=='no'
            and not any(r.get(k) for k in ('RequiredBy','WantedBy','BoundBy','UpheldBy','TriggeredBy'))):
        return False
    try:
        last=datetime.datetime.strptime(r['LastTriggerUSec'],'%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=datetime.timezone.utc)
    except (KeyError,ValueError):
        return False
    if last>datetime.datetime.now(datetime.timezone.utc):
        return False
    mono=r.get('TimersMonotonic',''); calendar=r.get('TimersCalendar','')
    if mono and not calendar:
        return r.get('Persistent')=='no' and bool(re.fullmatch(r'\{ On(?:Active|Boot)USec=[^;{}]+ ; next_elapse=0 \}',mono))
    m=re.fullmatch(r'\{ OnCalendar=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) UTC ; next_elapse=\(null\) \}',calendar)
    if mono or not m:
        return False
    only_deadline=datetime.datetime.fromisoformat(m[1]).replace(tzinfo=datetime.timezone.utc)
    if only_deadline>last:
        return False
    if r.get('Persistent')=='no':
        return True
    if r.get('Persistent')=='yes':
        stamp=Path('/var/lib/systemd/timers','stamp-'+name).lstat()
        return stat.S_ISREG(stamp.st_mode) and stamp.st_uid==0 and not stamp.st_mode&0o022 and stamp.st_mtime_ns>=int(only_deadline.timestamp())*10**9
    return False


def native_states(names, out, reasons):
    fields='Id,MainPID,ControlPID,Restart,Job,LoadState,ActiveState,SubState,UnitFileState,Triggers,TriggeredBy,UpheldBy,OnFailureOf,OnSuccessOf,WantedBy,RequiredBy,BoundBy,TimersMonotonic,TimersCalendar,NextElapseUSecMonotonic,NextElapseUSecRealtime,LastTriggerUSec,OnClockChange,OnTimezoneChange,Persistent,FragmentPath'
    rows={}; todo=set(names)
    while todo:
        batch=sorted(todo)[:64]; todo.difference_update(batch)
        block=systemctl('show','-p',fields,'--',*batch)
        new={}
        for linegroup in block.strip().split('\n\n'):
            r=dict(l.split('=',1) for l in linegroup.splitlines() if '=' in l)
            if 'Id' in r:new[r['Id']]=r
        require(set(batch)<=new.keys(),'incomplete systemd response: '+str(sorted(set(batch)-new.keys())[:8]))
        for name,r in new.items():
            rows[name]=r
            units=set()
            for key in ('TriggeredBy','UpheldBy','OnFailureOf','OnSuccessOf','WantedBy','RequiredBy','BoundBy'):
                units.update(r.get(key,'').split())
            if name.endswith(('.timer','.path','.socket')):units.update(r.get('Triggers','').split())
            todo.update(units-rows.keys())
            pending=bool(r.get('Job','').strip())
            enabled=r.get('UnitFileState','') in ('enabled','enabled-runtime')
            if r.get('UnitFileState','') in ('linked','linked-runtime'):
                enabled=any(r.get(k) for k in ('WantedBy','RequiredBy','BoundBy'))
            quiet=r.get('ActiveState') in ('failed','inactive') or (r.get('ActiveState')=='active' and r.get('SubState')=='exited')
            if exhausted_timer(name,r):quiet=True
            if not quiet or pending or enabled or r.get('MainPID','0')!='0' or r.get('ControlPID','0')!='0' or r.get('Restart','no') not in ('','no'):
                reasons.append('pending or activatable owner: '+name+' '+r.get('ActiveState','')+'/'+r.get('SubState',''))
    out['native_owners']=rows


def mountpath(s):
    return Path(re.sub(r'\\([0-7]{3})',lambda m:chr(int(m.group(1),8)),s))


def namespace_info(proc, ids, reasons):
    aliases=set(); entries=[]
    for row in (proc/'mountinfo').read_text().splitlines():
        parts=row.split()
        dev=tuple(map(int,parts[2].split(':')))
        if dev!=(os.major(DEV),os.minor(DEV)):continue
        root,where=mountpath(parts[3]),mountpath(parts[4]);entries.append((root,where))
    def fsroots(path):
        covered=[(root,where) for root,where in entries if path.is_relative_to(where)]
        if not covered:return set()
        root,where=max(covered,key=lambda x:len(x[1].parts))
        return {root/path.relative_to(where)}
    objects={Path('/')/SOURCE.relative_to('/home/sol')}
    # Include HOME-backed runtime even inside namespaces hiding the host /var path.
    for target in (CAPTURE,STAGE):
        objects.update(fsroots(target))
        objects.add(Path('/.jetstreamer-private/horizon-root-runtime-data')/target.relative_to('/var/lib/jetstreamer/horizon_runtime_data'))
    for root,where in entries:
        for obj in objects:
            if root.is_relative_to(obj):
                reasons.append('explicit mount of retained collection/member: '+str(proc)+' '+str(where))
            elif obj.is_relative_to(root):aliases.add(where/obj.relative_to(root))
        try:
            st=(proc/'root'/str(where).lstrip('/')).stat()
            if ident(st) in ids:reasons.append('mount exposes retained inode: '+str(proc)+' '+str(where))
        except FileNotFoundError:
            # A mount may be shadowed by a later mount, its root field was checked above.
            pass
    return aliases


def process_scan(ids,out,reasons):
    require(platform.machine()=='x86_64','unqualified kcmp ABI')
    me=os.getpid()
    count=threads=maps_count=fdsets=fssets=0; namespaces={};fdrefs=0; vanished=0; zombies=0
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal() or int(p.name)==me:continue
        pid=int(p.name)
        try:
            cmd=(p/'cmdline').read_bytes().split(b'\0')
            allthreads=list((p/'task').iterdir());count+=1
            for t in allthreads:
                try:
                    tid=int(t.name);threads+=1
                    status=(t/'stat').read_bytes().rsplit(b') ',1)[1].split()
                    if status[0] in (b'Z', b'X'):
                        # Exiting tasks leave a pid while holding none of the user resources.
                        require(not any((t/'fd').iterdir()) and not (t/'maps').read_bytes(),'terminal task still has user resources')
                        zombies+=1;continue
                    ns=os.readlink(t/'ns/mnt')
                    if ns not in namespaces:namespaces[ns]=namespace_info(t,ids,reasons)
                    aliases=namespaces[ns]|{SOURCE,CAPTURE,STAGE}
                    if tid==pid:
                        cwd=None
                        try:cwd=Path(os.readlink(t/'cwd'))
                        except FileNotFoundError:pass
                        for arg in cmd:
                            if any(os.fsencode(a) in arg for a in aliases):
                                reasons.append(f'command references target: pid {pid}');break
                            if cwd and arg and not arg.startswith((b'/',b'-')) and b'/' in arg:
                                candidate=Path(os.path.normpath(str(cwd/os.fsdecode(arg))))
                                if any(candidate.is_relative_to(a) for a in aliases):
                                    reasons.append(f'relative target argument: pid {pid}');break
                    def separate(k):
                        if tid==pid:return True
                        res=LIBC.syscall(312,pid,tid,k,0,0)
                        if res<0:
                            code=ctypes.get_errno()
                            if code==errno.ESRCH:raise ProcessLookupError
                            # Restricted capabilities may prevent kcmp. Inspect this thread separately.
                            if code in (errno.EPERM,errno.ENOSYS):return True
                            raise OSError(code,os.strerror(code))
                        return res!=0
                    links=[]
                    if separate(2):
                        fdsets+=1;links.extend((t/'fd').iterdir())
                    if separate(3):
                        fssets+=1;links.extend((t/'cwd',t/'root'))
                    if separate(1):
                        maps_count+=1;links.append(t/'exe')
                        with (t/'maps').open('rb') as maps:
                            for line in maps:
                                cols=line.split(None,5)
                                if len(cols)<5:raise ValueError('incomplete process map record')
                                maj,minor=cols[3].split(b':');pair=(os.makedev(int(maj,16),int(minor,16)),int(cols[4]))
                                if pair in ids:reasons.append(f'mapped target: pid {pid} tid {tid} inode {pair[1]}')
                    for link in links:
                        try:
                            st=link.stat(); fdrefs+=1
                            if ident(st) in ids:reasons.append(f'live target descriptor: {pid}/{tid}/{link.name} inode {st.st_ino}')
                        except (FileNotFoundError,ProcessLookupError):
                            # Atomic FD retirement or a kernel thread without a user executable.
                            continue
                except (FileNotFoundError,ProcessLookupError):
                    if t.exists():raise
                    vanished+=1
        except (FileNotFoundError,ProcessLookupError):
            if p.exists():raise
            vanished+=1
    out['live_census']={'processes':count,'threads':threads,'file_tables':fdsets,'fs_tables':fssets,'memory_spaces':maps_count,'descriptors_checked':fdrefs,'vanished_tasks':vanished,'terminal_no_resource_tasks':zombies,'mount_namespaces':{k:sorted(map(str,v)) for k,v in namespaces.items()}}


def run():
    require(sys.argv[1:] in ([],['--after-capture']),'expected no argument or --after-capture')
    require(os.geteuid()==0,'root process visibility required')
    out={'schema':'horizon-held141-consumer-gate-v1','at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'after_capture':bool(sys.argv[1:])}
    reasons=[]
    try:
        ids,prior=markers(out['after_capture'],out,reasons)
        names=scheduler(out,reasons,ids)|prior
        native_states(names,out,reasons)
        process_scan(ids,out,reasons)
    except Exception as exc:
        reasons.append(f'{type(exc).__name__}: {exc}')
    out.update(clear=not reasons,reasons=sorted(set(reasons)))
    print(json.dumps(out,sort_keys=True,separators=(',',':')),flush=True)
    return 0 if out['clear'] else 1


if __name__=='__main__':
    try:raise SystemExit(run())
    except Exception as exc:
        print(json.dumps({'clear':False,'reasons':[str(exc)]}));raise SystemExit(1)
