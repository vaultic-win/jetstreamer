"""Run the real 19-key publisher against private lifecycle fixtures for the normal 168."""
import copy
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

package, old, current, scratch = map(Path,sys.argv[1:])
sys.path.insert(0,str(package))
import cadence168, reconcile, status, status168, status168_controls
from cycle import Cycle, observed_lane
from evidence import bound, checked, durable

def put_file(p,v):
    durable(p,v)
    return bound(p)

class Store:
    def __init__(self,records):
        self.items = {e:(r['before_etag'],status.body(r['before_status'])) for e,r in records.items()}
        self.writes = []
    def get(self,e):
        return self.items[e]
    def put(self,e,tag,data):
        assert self.get(e)[0] == tag
        tag = '"fixture-'+status.digest(data)+'"'
        self.items[e] = tag,data
        self.writes.append(e)
        return tag

scratch.mkdir(mode=0o700)
ref=bound(old)
fleet=checked(bound(current))
before=Cycle(str(old),ref['sha256'],fleet['observer']['sha256'])
assert not before.metered168 and not before.metered168_row and before.retired168 and status168.inspect() is None
assert status168_controls.run(status168)['rejected'] == 7
audit=checked(fleet['authenticated_status_audit'])
records={int(e):checked(r) for e,r in audit['receipts'].items()}
assert len(records)==19
stages=[]
sha='a'*32
actor=dict(producer_unit=status168.U,producer_invocation_id=sha,producer_pid=os.getpid(),start_ticks=1234)
intent=dict(prior_trace_terminal=status168.ref(status168.TRACE,status168.CLOSED),
            prepared=status168.ref(status168.D/'PREPARED.json',status168.PREPARED),token='f'*32,
            producer_unit=status168.U,timer_unit=status168.T)
intentref=put_file(scratch/'intent.json',intent)
ad=dict(epoch=168,**actor,prior_trace_terminal=intent['prior_trace_terminal'],bootstrap_only=True,
        transaction_replay_claimed=False, first_guard=intentref,post_guard_capacity=intentref)
adref=put_file(scratch/'admission.json',ad)
row=dict(range='168',producer_unit=status168.U,controller_unit=status168.U,
         expected_producer_invocation_id=sha,expected_controller_invocation_id=sha,
         scratch_path=str(scratch),worker_executable_basename='historical-worker',
         append_log=dict(path=str(scratch/'log'),device=1,inode=2))
worker=dict(**actor,admission=adref,worker_sha256=status168.WORKER,worker_pid=os.getppid(),worker_start_ticks=100,
            observer_row=row)
first=put_file(scratch/'first-worker.json',worker)
samples=[('intent',None,None,None,False),('gated',actor,None,None,False),
         ('protected-bootstrap',actor,ad,None,False),('protected-worker',actor,ad,worker,False),
         ('advancing-worker',actor,ad,worker,True)]
for label,a,d,w,measured in samples:
    capture=status168.classify(intent,a,d,w)
    assert capture['stage']==('protected-worker' if measured else label)
    capture.update(intent=intentref,prior_trace_terminal=intent['prior_trace_terminal'])
    if d:
        capture.update(admission=adref,first_worker=first if w else None,current_guard={'receipt':adref,'timer':{'Id':status168.T}})
    c=copy.deepcopy(before)
    directory=scratch/label
    directory.mkdir(mode=0o700)
    c.paths['out']=directory
    put_file(directory/'FULL172_OBSERVATION.json',checked(bound(before.paths['out']/'FULL172_OBSERVATION.json')))
    with patch.object(status168,'inspect',return_value=capture):
        c.metered168=cadence168.freeze(c)
    if measured:
        native=copy.deepcopy(next(s for s in c.sample['replays'] if s['range']=='166'))
        native.update(range='168',scratch_path=row['scratch_path'])
        for edge in ('before','after'):
            native['producer_'+edge].update(unit=status168.U,invocation_id=sha,main_pid=actor['producer_pid'])
            native['worker_'+edge]['pid']=worker['worker_pid']
        progress=native['useful_work']
        progress['journal_invocation_id']=sha
        progress['append_log_evidence'].update(**row['append_log'],producer_main_pid=actor['producer_pid'])
        for key in ('first','last'):
            progress[key].update(slot=cadence168.FIRST+(100 if key=='first' else 180),terminal_slot=cadence168.LAST)
        progress.update(slot_delta=80,counter_resets=0,elapsed_seconds=120,transaction_delta=1000,sufficient_for_rates=True)
        c.cfg['replays'].append(row)
        c.sample['replays'].append(native)
    cadence168.interpret(c,observed_lane)
    assert bool(c.metered168_row)==bool(d)
    assert [r for r in c.next_cfg['replays'] if r['range']=='168']==([row] if w else [])
    local=Store(records); reports=directory/'status'; reports.mkdir(mode=0o700)
    arch=lambda c,e: {'size':256} if e==168 and w else records[e].get('archive_sample')
    with patch.object(c,'public_fresh'),patch.object(c,'unchanged'),patch.object(status,'observed_archive',side_effect=arch):
        result=status._publish(c,local,reports,audit['ready_epochs'])
        assert status._publish(c,local,reports,audit['ready_epochs'])==result
    sr=checked(result)
    assert len(sr['receipts'])==len(set(local.writes))==len(local.writes)==19
    for e,proof in sr['receipts'].items():
        value=checked(proof);assert value['after_sha256']==status.digest(local.get(int(e))[1])
    cap=checked(fleet['current_home_cycle_capacity'])
    cap[cadence168.FIELD]=c.metered168['reference']
    capref=put_file(directory/'capacity.json',cap)
    next_cfg=put_file(directory/'next.json',c.next_cfg)
    f=reconcile.assemble(c,result,fleet['continuing_audit_obligation']['current_observation'],capref,next_cfg)
    assert f['active_producer_count']==fleet['active_producer_count']+bool(d)
    assert f['canonical_producer_count']==fleet['canonical_producer_count']+bool(d)
    assert f['bootstrap_count']==fleet['bootstrap_count']+(label=='protected-bootstrap')
    assert f['useful_replay_count']==fleet['useful_replay_count']+measured
    assert f['terminal168_trace_mismatch']==fleet['terminal168_trace_mismatch']
    assert f['actual_active_private_diagnostics']==fleet['actual_active_private_diagnostics']
    v=checked(sr['receipts']['168']);assert v['after_status']['phase']==('replay' if measured else 'verification')
    assert v.get('producer_invocation_id')==(sha if d else None) and bool(v['measured_canonical_progress'])==measured
    assert bool(cadence168.previous(f))==bool(d)
    if d:
        fake=copy.deepcopy(f)
        r=next(r for key in ('actual_active_bootstraps','actual_executing_replays') for r in fake[key] if r['epoch']==168)
        r['unit']['InvocationID']='0'*32
        try:cadence168.previous(fake)
        except ValueError:pass
        else:raise AssertionError('foreign normal 168 accepted')
    for k in ('complete_DATA_bytes','complete_projected_memory_bytes','all_reservation_ending_bytes'):
        assert f[k]==fleet[k]
    stages.append(dict(stage=label,readbacks=19,admitted=bool(d),measured=measured,public_phase=v['after_status']['phase']))
print(json.dumps(dict(stages=stages,current_original_168_closed=True,production_writes=0)))
