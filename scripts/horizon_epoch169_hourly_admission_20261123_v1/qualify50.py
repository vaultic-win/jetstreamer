"""Exercise the existing captured observation with read-only remote input and local overlay writes."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

SOURCE=Path(__file__).resolve().parent
sys.path.insert(0,str(SOURCE))
import derive50 as generator

BASE=Path('/var/lib/jetstreamer/horizon_runtime_data')
W=BASE/'survivor172-cadence-20261122-v1'
B=BASE/'epoch143-first-hourly-20261127-v1'
O=BASE/'root234808-live166167170-20261127-v1'
R=Path('/home/sol/.jetstreamer-private/r2-status-receipts')
SEALER=Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
TOOL_SHA='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert sha(SEALER)==TOOL_SHA
if len(sys.argv)==2 and sys.argv[1] not in ('--isolate','--stage-only'):
    d=Path(tempfile.mkdtemp(dir=Path(sys.argv[1]),prefix='v50-rehearsal-'))
    print(d,flush=True)
    raise SystemExit(subprocess.run(['unshare','--mount','--propagation','private',sys.executable,'-IB',__file__,'--isolate',d]).returncode)
if len(sys.argv)!=3 or sys.argv[1] not in ('--isolate','--stage-only'):
    raise SystemExit('use qualify50.py WORK_DIRECTORY or --stage-only EXISTING_PLAN_DIRECTORY')
dest=Path(sys.argv[2]);os.umask(0o077)
stage=sys.argv[1]=='--stage-only'
def overlay(p,n):
    u=dest/(n+'-upper');m=dest/(n+'-work');u.mkdir();m.mkdir()
    subprocess.run(['mount','-t','overlay','overlay','-o',f'lowerdir={p},upperdir={u},workdir={m}',p],check=True)
if not stage:
    if Path('/proc/self/ns/mnt').samefile('/proc/1/ns/mnt'):
        raise ValueError('rehearsal requires its private mount namespace')
    propagation=subprocess.check_output(['findmnt','-n','-o','PROPAGATION','-T','/'],text=True).strip()
    if propagation!='private':
        raise ValueError('rehearsal mount tree may propagate')
    for p,n in ((W,'writer'),(B,'booker')):overlay(p,n)
    # These destinations are validated by backing device. Bind an independent
    # same-filesystem copy; all other status/fleet inputs remain read-only.
    target=R/'cycle234808-live166167170-19-20261127-v1'
    for p,n in ((target,'receipts-copy'),(O,'out-copy')):
        copy=dest/n
        subprocess.run(['cp','-a','--',p,copy],check=True)
        subprocess.run(['mount','--bind',copy,p],check=True)
def prepare(tag,old):
    plan=generator.stage(old,dest/(tag+'-input'))
    p=dest/(tag+'-plan.json');p.write_text(json.dumps(plan,sort_keys=True,indent=2)+'\n');p.chmod(0o400)
    if stage:return (str(p),sha(p))
    q=subprocess.run([SEALER,p,'--plan-sha256',sha(p),'--self-sha256',TOOL_SHA],capture_output=True,text=True)
    if q.returncode:raise RuntimeError(q.stderr+q.stdout)
    s=Path(plan['destination'])/'deployment-seal-receipt.json'
    return dict(path=str(s),sha256=sha(s))
book=prepare('booker',B/'booking-price-v49');writer=prepare('writer',W/generator.OLD)
if stage:
    print(json.dumps(dict(book=book,writer=writer)));raise SystemExit
w=W/generator.NEW
def call(name,args):
    q=subprocess.run(list(map(str,args)),capture_output=True,text=True)
    (dest/(name+'.stderr')).write_text(q.stderr);(dest/(name+'.stdout')).write_text(q.stdout)
    if q.returncode:raise RuntimeError(name+': '+q.stderr[-3200:])
    return json.loads(q.stdout)
latest=max(BASE.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),key=lambda p:p.stat().st_mtime_ns)
entry=call('entry',['/usr/bin/python3','-IB',w/'status_cycle.py','--check-entry'])
handoff=call('handoff',['/usr/bin/python3','-IB',w/'status_cycle.py','--check-v50-handoff',latest,sha(latest)])
assert entry==writer and handoff['old_owner']['sha256']==generator.ACTIVE and handoff['split_wire_receiver']['sha256']==sha(w/'split_wire.py')
assert sha(w/'initial162.py')==generator.INITIAL
listen=call('listener',['/usr/bin/python3','-IB',w/'watch143_versions.py','--check-failed-predecessor'])
assert listen['writer']==handoff['old_owner']
record=call('recover',['/usr/bin/python3','-IB',w/'recover50.py','--package-sha256',writer['sha256'],'--check'])
print('complete source-native entry, pre-bind and recovery preflight',flush=True)
sys.path.insert(0,str(w));import status_cycle as cycle
head=cycle.bound(latest);fleet=cycle.checked(head);cfg=cycle.sealed(fleet['sole_next_observer'])
sample=cycle.bound(Path(cfg['output']))
ctx=cycle.make_context(head,fleet,sample,cfg,O)
bridge=cycle.handoff();observation=cycle.census(ctx,bridge)
class Storage:
    def __init__(self):
        source=cycle.status.Storage()
        self.signed_get=source.get
        self.inventory=source.inventory
        self.cached={}
        self.writes={}
    def get(self,e):
        if e in self.writes:return self.writes[e]
        if e not in self.cached:self.cached[e]=self.signed_get(e)
        return self.cached[e]
    def put(self,e,etag,data):
        assert e not in self.writes and self.get(e)[0]==etag
        self.writes[e]=('"'+hashlib.md5(data).hexdigest()+'"',data)
        return self.writes[e][0]
store=Storage()
legacy,allref=cycle.publish_all(ctx,bridge,store,observation)
for ref in record['preserved_receipts'].values():assert sha(Path(ref['path']))==ref['sha256']
a=cycle.checked(legacy);allbody=cycle.checked(allref)
partial={int(name.split('-')[1].split('.')[0]) for name in record['preserved_receipts']}
assert not partial.intersection(store.writes) and len(partial)==11
sr=cycle.checked(allbody['receipts']['169']);payload=sr['after_status']
assert sr['previous_receipt']==record['event'] and sr['producer_invocation_id']=='b01da82c3091478f920ddcc71f4d9191'
assert payload['phase']=='replay' and payload['elapsed_execution_millis']>0 and payload['jet_size_bytes']>0
assert not sr['measured_canonical_progress'] and not sr['archive_publication_authorized']
assert sum(sr['planning_milliseconds'].values())==payload['estimated_remaining_millis']
assert a['canonical_producer_count']==2 and a['active_private_diagnostic_count']==3 and a['active_producer_count']==5
due=cycle.stamp(cycle.utc(ctx.stamp)+dt.timedelta(minutes=30))
future=cycle.project(ctx.next_cfg,due,sample)
acfg=cycle.config(O,future)
actors=[r['range'] for r in future['diagnostic_replays']]
assert actors.count('169')==1
projected=cycle.fleet_successor(ctx,bridge,observation,legacy,allref,acfg,cycle.names(due)['timer'])
rows=projected['actual_executing_replays']+projected['actual_active_private_diagnostics']
assert len(rows)==5 and {r['epoch'] for r in rows}=={146,167,169,170,172}
summary=dict(writer=writer,booker=book,entry=entry,handoff=handoff,listener=listen,
             capture=sample,statuses=allbody['status_epochs'],recovered_receipts=record['preserved_receipts'],
             simulated_conditional_puts=sorted(store.writes),authenticated_original_reads=sorted(store.cached),
             issued_162_receiver=generator.INITIAL,
             epoch169=sr,successor_producers={r['epoch']:r['unit']['InvocationID'] for r in rows},
             next_config=acfg,report_transport='read-only authenticated GET and inventory with in-memory conditional PUT')
(dest/'QUALIFICATION.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
print('passed full native fleet successor',dest,'status',allbody['status_epochs'],'writes',sorted(store.writes),flush=True)
