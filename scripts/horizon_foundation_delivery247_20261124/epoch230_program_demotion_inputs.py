
from pathlib import Path
import fcntl,hashlib,json,os,re,shlex,subprocess,sys,time

BASE=Path('/var/lib/jetstreamer/horizon230-program-demotion-ram-v328')
CONTROL=Path('/var/lib/jetstreamer/horizon-seven-publication-controller-v222')
PREP_SHA='686b890839f3066071f4baecdb697f74d1e568a0b4edce3e14571fdc4274889c'

def ref(p):
    with p.open('rb') as f:return dict(path=str(p),sha256=hashlib.file_digest(f,'sha256').hexdigest())

def image(binding):
    path = Path(binding['path'])
    stamp = path.stat()
    assert path.is_absolute() and path.resolve() == path and path.is_file()
    assert stamp.st_uid == 0 and not stamp.st_mode & 0o222 and os.access(path, os.X_OK)
    assert ref(path)['sha256'] == binding['sha256']
    return dict(path=str(path), sha256=binding['sha256'], device=stamp.st_dev,
                inode=stamp.st_ino, bytes=stamp.st_size)

def bound(p,sha):
    assert p.is_absolute() and p.resolve()==p and p.is_file() and p.stat().st_uid==0 and not p.stat().st_mode&0o222
    assert ref(p)['sha256']==sha
    return json.loads(p.read_bytes())
def put(p,contents):
    with p.open('xb') as f:
        os.fchmod(f.fileno(),0o400)
        f.write(contents)
        f.flush()
        os.fsync(f.fileno())
    directory = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return ref(p)
def record(p,doc):return put(p,(json.dumps(doc,sort_keys=True,indent=2)+'\n').encode())

def render(p, worker, node):
    template=Path(p['producer_template']['path'])
    assert ref(template)==p['producer_template']
    rendered=template.read_text()
    replacements=(
        ('__QUALIFIED_EPOCH230_WORKER__', worker['path'], 3),
        (p['node']['path'], node['path'], 1),
        (str(Path(p['node']['path']).parent)+'\n',node['path']+'\n',1),
        ('BindReadOnlyPaths=', 'BindReadOnlyPaths='+node['path']+' ', 1),
        ('JETSTREAMER_HISTORICAL_WORKER_V1_6_20=', 'JETSTREAMER_HISTORICAL_WORKER_EPOCH230_DEMOTION=', 1),
    )
    for before,after,count in replacements:
        assert rendered.count(before)==count,before
        rendered=rendered.replace(before,after)
    argv,=[shlex.split(row.removeprefix('ExecStart=')) for row in rendered.splitlines() if row.startswith('ExecStart=')]
    assert argv[0]==node['path'] and argv[1]=='230' and '--qualification-end-slot=99375855' in argv
    return rendered, argv

def prepare(qualification,qualification_sha):
    assert re.fullmatch(r'[0-9a-f]{64}',qualification_sha)
    accepted=bound(qualification,qualification_sha)
    worker=image(accepted['worker'])
    node=image(accepted['node'])
    assert accepted['epoch']==230 and accepted['diagnostic_only'] is True
    assert not (BASE/'profile.json').exists()
    p=bound(BASE/'preparation.json',PREP_SHA)
    assert not p['replay_admitted'] and p['static_validation']['validated'] and p['epoch']==230
    assert ref(Path(p['guard']['path']))==p['guard'] and image(p['node'])==p['node']
    rendered, argv = render(p, worker, node)
    props=[]
    contexts=('ReadWritePaths=','ReadOnlyPaths=','BindReadOnlyPaths=','ProtectHome=','ProtectSystem=')
    for row in rendered.splitlines():
        if row.startswith(contexts):
            props.append('--property='+row)
        if row.startswith('Environment='):
            prop,=shlex.split(row.removeprefix('Environment='))
            props.append('--setenv='+prop)
    program="""
import hashlib,json,os,subprocess,sys
from pathlib import Path
d=json.loads(sys.argv[1])
assert os.getuid()==1000
for dest,row in d['mounts'].items():
    path=Path(dest); stamp=path.stat()
    assert (stamp.st_dev,stamp.st_ino,stamp.st_size)==(row['device'],row['inode'],row['size'])
    assert os.statvfs(path).f_flag&os.ST_RDONLY,dest
for item in (d['worker'],d['node']):
    path=Path(item['path'])
    stamp=path.stat()
    assert (stamp.st_dev,stamp.st_ino,stamp.st_size)==(item['device'],item['inode'],item['bytes'])
    assert os.statvfs(path).f_flag&os.ST_RDONLY and os.access(path,os.X_OK)
    with path.open('rb') as f:
        assert hashlib.file_digest(f,'sha256').hexdigest()==item['sha256']
assert os.environ['JETSTREAMER_HISTORICAL_WORKER_EPOCH230_DEMOTION']==d['worker']['path']
assert os.environ['JETSTREAMER_HISTORICAL_TRACE']=='1'
assert os.environ['JETSTREAMER_EPOCH230_BANK_TRACE_DIR']==d['root']+'/bank-trace'
assert os.access(d['root']+'/bank-trace',os.W_OK)
snapshot=Path(d['snapshot']['path']); stamp=snapshot.stat()
assert os.statvfs(snapshot).f_flag&os.ST_RDONLY and (stamp.st_dev,stamp.st_ino,stamp.st_size)==(d['snapshot']['device'],d['snapshot']['inode'],d['snapshot']['bytes'])
capability=subprocess.run([d['node']['path'],'--epoch230-demotion-capability'],capture_output=True,text=True,timeout=10)
assert capability.returncode==0,capability.stderr
report=json.loads(capability.stdout)
assert report['schema']=='jetstreamer-private-epoch230-demotion-parent-capability-v1'
assert report['epoch']==230 and report['worker_executable']==d['worker']['path']
assert report['worker_sha256']==d['worker']['sha256'] and report['run_root']==d['root']
assert (report['bootstrap_slot'],report['bank_hash_slot'],report['terminal_slot'])==(99359376,99368201,99375855)
assert d['argv'][-1]=='--horizon-output='+d['root']+'/output/'+report['output_leaf']
print(json.dumps(dict(namespace_verified=True,started_replay=False,bound_read_only_inputs=len(d['mounts']),capability=report)))
"""
    command=['systemd-run','--quiet','--wait','--pipe','--collect','--unit=foundation-230-demotion-namespace-v328',
      '--property=Type=exec','--property=User=ubuntu','--property=PrivateNetwork=yes','--property=MemoryMax=1G',
      '--property=MemorySwapMax=0','--property=CPUQuota=100%','--property=RuntimeMaxSec=25',
      *props,'--','/usr/bin/python3','-I','-B','-c',program,
      json.dumps(dict(mounts=p['membership'],worker=worker,node=node,snapshot=p['snapshot'],root=p['run_root'],argv=argv))]
    verdict=subprocess.run(command,capture_output=True,text=True,timeout=35)
    execution=record(BASE/f'namespace-execution-{time.time_ns()}.json',dict(exit=verdict.returncode,stdout=verdict.stdout,stderr=verdict.stderr))
    assert verdict.returncode==0,verdict
    producer=put(BASE/'producer.service',rendered.encode())
    namespace=record(BASE/'namespace.json',dict(result=json.loads(verdict.stdout),execution=execution,preparation=ref(BASE/'preparation.json')))
    assert p['target_slot']==99368202 and p['terminal_slot']==99375855
    focused=record(BASE/'focused.json',dict(bootstrap_slot=p['bootstrap_slot'],first_divergent_slot=99368201,
         following_vote_slot=p['target_slot'],
         checkpoint_slot=p['terminal_slot'],checkpoint_generation=p['terminal_generation'],protected_source=ref(BASE/'preparation.json')))
    ready=record(BASE/'profile.json',dict(epoch=230,unit=p['unit'],guard_unit='horizon-230-program-demotion-protective-v328.service',
        run_root=p['run_root'],argv=argv,producer=producer,guard=p['guard'],guard_plan=p['static_guard'],
        token=p['token'],namespace=namespace,focused=focused,node=node,worker=worker,worker_qualification=ref(qualification),
        cpu=list(range(72,80)),memory_max_bytes=225000000000,filesystem=p['filesystem'],ram_scratch_cap_bytes=150000000000,
        canonical_epoch_publication_authorized=False))
    print(json.dumps(ready))

if __name__ == '__main__':
    assert len(sys.argv)==3 and os.geteuid()==0 and __debug__
    with (CONTROL/'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        prepare(Path(sys.argv[1]),sys.argv[2])
