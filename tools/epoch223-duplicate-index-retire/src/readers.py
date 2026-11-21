"""Inspect staged configuration, selected historical recipes, and original manager custody; no state changes."""
import argparse,hashlib,json,os,re,stat,subprocess
from pathlib import Path
from collections import defaultdict
P=Path('/home/ubuntu/.jetstreamer-private')
V=Path('/var/lib/jetstreamer')
HISTORICAL=[{'unit': 'horizon-import-239-namespace-probe-20261117-v3.service', 'fragment': '/etc/systemd/system/horizon-import-239-namespace-probe-20261117-v3.service', 'sha256': '49d1504c6028e3d8f2c0725a754a35b78ba2d9baaf1436cadfd7f68aeca8bfc4'}, {'unit': 'horizon-import-244-namespace-probe-20261117-v1.service', 'fragment': '/etc/systemd/system/horizon-import-244-namespace-probe-20261117-v1.service', 'sha256': '3fd3817e8a7e52fee10842c6153f87c68f7697ff5572bd33b6421b91d342c9c6'}, {'unit': 'horizon-import-239-current-20261117-v3.service', 'fragment': '/etc/systemd/system/horizon-import-239-current-20261117-v3.service', 'sha256': 'eb95b43a389fc94ca6b8ed10761b7672cb963aadb9957d7dc16b56b899d63a64'}, {'unit': 'horizon-import-233-committed-v2.service', 'fragment': '/etc/systemd/system/horizon-import-233-committed-v2.service', 'sha256': '88ed8283376bf7ead6c715f73c6021237d424fec6b57987fb8b93d03243a0c5b'}, {'unit': 'horizon-import-233-common-mount-probe-v2.service', 'fragment': '/etc/systemd/system/horizon-import-233-common-mount-probe-v2.service', 'sha256': '62f974bd1f72808bd20064be096955121a751e717260f2dbbb6132421e06b1eb'}, {'unit': 'horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service', 'fragment': '/etc/systemd/system/horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service', 'sha256': '5abdc106f69d2bc8b86c9d5a7033d24691a69d9c7a09c5ae84f50205524c2972'}, {'unit': 'horizon-import-239-current-20261117-v2.service', 'fragment': '/etc/systemd/system/horizon-import-239-current-20261117-v2.service', 'sha256': '1a1aaa25b8ab2ff39a1241e391cd4cf0ebb12169d3dceb1e95c589980a75d7b1'}, {'unit': 'horizon-import-244-current-20261117-v1.service', 'fragment': '/etc/systemd/system/horizon-import-244-current-20261117-v1.service', 'sha256': '4cb7866d90e6cccd209364de9efba47a95fcf57431058e56a4d0f5291bb8a76a'}, {'unit': 'horizon-import-239-namespace-probe-20261117-v2.service', 'fragment': '/run/systemd/system/horizon-import-239-namespace-probe-20261117-v2.service', 'sha256': 'd0a48880e9cbd49c722fc36e8f27a5b175ec2d69c55ac0db22206dfe82fa6424'}]
names=['qualification-223-v1625-tail-1743245a-v3','singleton-223-postcount-ad1d65a-v1','qualification-223-v1620-prefix-warmup-d15ee08b-v1']
known=['archive-223-tail-reread-1743245a-v3.service','horizon-qualify-223-v1625-tail-1743245a-v3.service','horizon-qualify-223-singleton-postcount-ad1d65a-v1.service','horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service','horizon223-index-duplicate-survey-20261120-v1.service']
def bind(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def read(p):return json.loads(p.read_bytes())
def scan(own=None):
 roots=[Path(x) for x in ('/etc/systemd/system','/run/systemd/system','/run/systemd/transient','/run/systemd/generator','/run/systemd/generator.early','/run/systemd/generator.late','/usr/lib/systemd/system','/usr/local/lib/systemd/system','/etc/systemd/user','/usr/lib/systemd/user','/root/.config/systemd','/root/.local/share/systemd')]
 roots.extend([P/'systemd-staging'])
 for h in Path('/home').iterdir():roots.extend((h/'.config/systemd',h/'.local/share/systemd'))
 for r in Path('/run/user').glob('*'):roots.extend(r/'systemd'/s for s in ('user','transient','generator','generator.early','generator.late'))
 selected=[str(P/n) for n in names]+known+['1743245a-v3','singleton-postcount-ad1d65a-v1','singleton-guard-ad1d65a-v1','d15ee08b-v1']
 raw={}; aliases=defaultdict(list); missing=[]
 def visit(p,seen):
  if p.is_symlink() and not p.exists():
   missing.append(str(p));return
  dest=p.resolve(strict=True)
  if dest==Path('/dev/null') or (own is not None and p==dest==own):return
  if dest.is_dir():
   if dest in seen:return
   for entry in p.iterdir():visit(entry,seen|{dest})
  elif dest.is_file():
   aliases[dest].append(str(p))
   if dest not in raw:
    assert dest.stat().st_size<8<<20
    raw[dest]=dest.read_bytes()
 for root in roots:
  if root.is_dir():visit(root,set())
 direct=[]
 for dest,data in raw.items():
  hits=[n for n in selected if n.encode() in data]
  if hits:direct.append(dict(source=bind(dest),aliases=sorted(aliases[dest]),references=hits))
 # Review small executable scripts and JSON control plans reached from configured
 # service commands. Skip ELF programs and inputs such as archives, and keep
 # the proof local to paths used by Jetstreamer. Never emit scripts or env values.
 candidates={}
 visited_edges=set()
 dependencies=[]
 pattern=re.compile(rb"/(?:var/lib/jetstreamer|home/ubuntu/\.jetstreamer-private|run/horizon|tmp/horizon)[A-Za-z0-9_./+@:=,-]+")
 def audit(p,trail,active):
  try:real=p.resolve(strict=True)
  except (FileNotFoundError,NotADirectoryError,RuntimeError):return
  if real in active or (trail[0],real) in visited_edges or not real.is_file() or real.stat().st_size>8<<20:return
  visited_edges.add((trail[0],real))
  if 'credential' in real.name.lower() or real.name.endswith('.env') or 'secret' in real.name.lower():return
  if real not in candidates:
   with real.open('rb') as f:head=f.read(80)
   candidates[real]=real.read_bytes() if real.suffix in ('.json','.py','.sh','.bash','.toml','.conf','.service','.timer','.path') or head.startswith(b'#!') else None
  data=candidates[real]
  if data is None:return
  if len(trail)>12:raise ValueError('indirect command depth '+str(real))
  hits=[n for n in selected if n.encode() in data]
  if hits:
   record=dict(unit=trail[0],chain=trail[1:]+[str(real)],source=bind(real),references=hits,metadata_only=False)
   if re.fullmatch(r'/run/systemd/transient/horizon-resume-fleet-20261117-v[12]\.service',trail[0]):
    expected={'v1':'01a50c15e8401cdcc792a6bd784b40b9131aa342aee7af580118f263ff776b21','v2':'fb1a128de4b98f6cf52d9680c2bd72a5951316365d496e8c86d12f7200d7604f'}
    tag=Path(trail[0]).stem.rsplit('-',1)[-1]
    plan=read(real);track=plan.pop('tracked_units')
    command=Path(trail[0]).read_text()
    matched=[u for u in track if any(n in u for n in selected)]
    record['metadata_only']=(real==V/('horizon-resume-fleet-20261117-'+tag)/'plan.json' and record['source']['sha256']==expected[tag] and
       '"'+'fleet-reconcile'+'" "'+str(real)+'" "--plan-sha256" "'+expected[tag]+'"' in command and
       not any(n in json.dumps(plan) for n in selected) and set(matched)=={'horizon-223-tail-guard-1743245a-v3.service',known[2],known[3]})
   dependencies.append(record)
  if real.suffix=='.json':return
  for f in set(pattern.findall(data)):
   audit(Path(os.fsdecode(f)),trail+[str(real)],active|{real})
 for p,data in raw.items():
  if p.suffix not in ('.service','.conf','.timer','.path') and not any(Path(f).suffix=='.service' for f in aliases[p]):continue
  # Restrict transitive parsing to activation commands and their named configuration inputs.
  for line in data.splitlines():
   if not line.lstrip().startswith((b'ExecStart',b'ExecStop',b'ExecReload',b'ExecCondition')):continue
   for f in set(pattern.findall(line)):
    audit(Path(os.fsdecode(f)),[str(p)],set())
 old=HISTORICAL; archived=V/'horizon-duplicate-index223-before-disarm-20261120-v2'
 already=[]
 for row in old:
  f=Path(row['fragment']);saved=archived/f.name
  assert f.is_symlink() and f.readlink()==Path('/dev/null') and bind(saved)['sha256']==row['sha256']
  already.append(dict(unit=row['unit'],saved=bind(saved),mask=str(f)))
 additional={k for r in direct for f in r['aliases'] for k in [Path(f).name] if k.endswith(('.service','.timer','.path')) and not k.startswith(('@','dbus-'))}
 units=sorted(set(known)|set(r['unit'] for r in old)|additional)
 states={}
 for name in units:
  proc=subprocess.run(['systemctl','show','--all',name,'--property=Id,ActiveState,SubState,MainPID,ControlPID,LoadState,Job,InvocationID,FragmentPath,DropInPaths,ExecStart,TriggeredBy,Triggers,RequiredBy,WantedBy,Restart,NRestarts'],capture_output=True,text=True)
  assert proc.returncode in (0,4)
  state=dict(x.split('=',1) for x in proc.stdout.splitlines())
  state['has_cgroup']=(Path('/sys/fs/cgroup/system.slice')/name).exists()
  states[name]=state
 return dict(roots=[str(r) for r in roots],files=len(raw),bytes=sum(map(len,raw.values())),dangling_links=missing,direct=direct,already_masked=already,manager=states,indirect=dependencies,small_recipe_sources=len(candidates))
def verify_closed(own):
 assert own.name.startswith('horizon223-duplicate-index-') and own.parent==Path('/run/systemd/transient') and own.is_file()
 assert Path('/proc/self/cgroup').read_text().strip()=='0::/system.slice/'+own.name
 result=scan(own)
 assert not result['direct'] and all(r['metadata_only'] for r in result['indirect']), 'staged direct or indirect reader remains'
 for name,u in result['manager'].items():
  if name==known[4]:
   assert u['LoadState']=='not-found'
   continue
  assert u['LoadState']=='masked' and u['ActiveState']=='inactive' and u['SubState']=='dead' and not u.get('ExecStart') and not u['has_cgroup']
  assert (u['MainPID'],u['ControlPID'],u['Job'],u['InvocationID'],u['TriggeredBy'])==('0','0','','','')
 return dict(staged_files=result['files'],bounded_bytes=result['bytes'],sources=result['small_recipe_sources'],
             protected_metadata_only=[r['source'] for r in result['indirect']],all_readers_closed=True)
if __name__=='__main__':
 args=argparse.ArgumentParser();args.add_argument('--verify-closed',type=Path);arg=args.parse_args()
 print(json.dumps(verify_closed(arg.verify_closed) if arg.verify_closed else scan(),indent=2))
