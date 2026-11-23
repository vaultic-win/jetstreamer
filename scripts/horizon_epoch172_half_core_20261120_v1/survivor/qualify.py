"""Replay saved native 172 measures and exercise every current If-Match write in memory."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import status_cycle as c

class Mirror:
    def __init__(self,refs):
        self.objects={}
        self.writes=[]
        for e,r in refs.items():
            proof=c.checked(r)
            self.objects[int(e)]=(proof['after_etag'],c.status.body(proof['after_status']))
    def get(self,e):
        return self.objects[e]
    def put(self,e,tag,raw):
        assert tag==self.objects[e][0]
        result='"'+hashlib.md5(raw).hexdigest()+'"'
        self.objects[e]=(result,raw)
        self.writes.append(e)
        return result

def fail(call):
    try: call()
    except (ValueError,AssertionError):return
    raise AssertionError('accepted mismatched input')

def resume_after_external_event(m, parent, baseline, event_record):
    # The fixture first writes and independently authenticates an event between cadence samples.
    epoch=168
    event_dir=parent/'event-168-resume-test'; c.ensure_dir(event_dir)
    c.durable(event_dir/'RECEIPT.json',c.checked(event_record))
    event=c.bound(event_dir/'RECEIPT.json')
    advanced=copy.copy(m)
    advanced.now+=c.dt.timedelta(seconds=1); advanced.stamp=c.stamp(advanced.now)
    cycle_dir=parent/'resume-cycle'; c.ensure_dir(cycle_dir)
    mirror=Mirror({'168':event})
    state={'168':event}
    c.publish(advanced,mirror,state,cycle_dir,epoch)
    successor=state['168']
    with patch('evidence.STATUS_ROOT',parent):
        # A crash can leave only the intent, on either side of the remote conditional PUT.
        for saved_remote, num_writes in ((event,1),(successor,0)):
            retry_store=Mirror({'168':saved_remote})
            proof=cycle_dir/'epoch-168.receipt.json'
            proof.unlink()
            selected={'168':baseline}
            c.read_statuses(retry_store,selected,cycle_dir)
            assert selected['168']==event
            c.publish(advanced,retry_store,selected,cycle_dir,epoch)
            assert len(retry_store.writes)==num_writes and selected['168']==successor
            c.authenticated(retry_store,epoch,successor)
        # An unrelated epoch or fork may never acquire the stored If-Match.
        fail(lambda:c.read_statuses(mirror,{'168':event_record | {'sha256':'0'*64}},cycle_dir))
        fork=parent/'event-168-fork';c.ensure_dir(fork)
        c.durable(fork/'RECEIPT.json',c.checked(event))
        fail(lambda:c.read_statuses(mirror,{'168':baseline},cycle_dir))

def main():
    c.validate_package()
    handoff=c.handoff();head=handoff['fleet'];fleet=c.checked(head)
    stops,diag=c.stopped_populations(handoff,fleet)
    assert set(stops)=={'166','167','168','170'} and diag['disposition']=='interrupted-or-unclassified'
    parent=c.checked(fleet['previous_Root_operational_review'])
    target=c.sealed(parent['sole_next_observer'])
    sample=c.checked(fleet['observer']);tmp=copy.deepcopy(sample)
    projected=c.project(target,target['not_before_utc'],parent['observer'])
    # The same five epoch numbers can belong to replacement processes.
    # A mixed generation must never collapse to the historical 172-only view.
    mixed=copy.deepcopy(target)
    row=next(r for r in mixed['replays'] if r['range']=='168')
    row['expected_producer_invocation_id']='0'*32
    fail(lambda:c.project(mixed,target['not_before_utc'],parent['observer']))
    tmp['replays']=[r for r in tmp['replays'] if r['range']=='172']
    tmp['diagnostic_replays']=[r for r in tmp['diagnostic_replays'] if r['range']!='169']
    assert c.check_sample(parent,tmp,projected)==fleet['sampled_at_utc']
    fail(lambda:c.check_sample(parent,dict(tmp,replays=[]),projected))
    bad=copy.deepcopy(tmp);bad['cadence']['previous_sample_sha256']='0'*64
    fail(lambda:c.check_sample(parent,bad,projected))
    future=c.stamp(c.now());stamp=c.utc(future)
    m=SimpleNamespace(fleet=fleet,fleet_ref=head,now=stamp,stamp=future,prior=c.checked(fleet['authenticated_status_audit']),
        full172=c.read_ref(Path(head['path']).parent/'FULL172_OBSERVATION.json'),sample_ref=fleet['observer'],
        sample=tmp,lanes={},advancing={},cfg=projected,next_cfg=copy.deepcopy(projected))
    c.full172.reconcile_sample(m,c.cycle.observed_lane)
    # Prior and saved observation refer to the same completed measurement. Use the actual predecessor for the rate.
    m.fleet=parent
    c.full172.reconcile_sample(m,c.cycle.observed_lane)
    assert m.advancing[172]
    wrong=copy.deepcopy(tmp['replays'][0]);wrong['producer_after']['main_pid']+=1
    row=projected['replays'][0]
    fail(lambda: c.cycle.observed_lane(wrong,row,row['expected_producer_invocation_id'],int(m.full172_row['unit']['MainPID'])))
    refs=c.baselines(head,fleet,handoff)
    orig=dict(refs);store=Mirror(refs)
    qa=Path(sys.argv[1]);c.ensure_dir(qa)
    temporary=Path(tempfile.mkdtemp(dir=qa));os.chmod(temporary,0o700)
    c.read_statuses(store,refs,temporary)
    for e in sorted(map(int,refs)):
        if e==172:
            archive=c.checked(refs['172'])['archive_sample']
        else:
            archive=None
        c.publish(m,store,refs,temporary,e,archive)
    assert len(store.writes)==20
    for e,ref in refs.items():
        p=c.authenticated(store,int(e),ref);a=p['after_status'];b=p['before_status']
        assert p['previous_receipt']==orig[e] and a['sampled_at_utc']==future and p['conditional_header']=='If-Match'
        if e!='172':
            assert a['phase']=='verification' and a['estimated_remaining_millis']+a['elapsed_execution_millis']==b['estimated_remaining_millis']+b['elapsed_execution_millis']
    committed=refs.pop('168');refs['168']=orig['168']
    (temporary/'epoch-168.receipt.json').unlink()
    c.publish(m,store,refs,temporary,168)
    assert refs['168']==committed and len(store.writes)==20
    fail(lambda:c.authenticated(store,168,orig['168']))
    resume_after_external_event(m,temporary,orig['168'],committed)
    assert diag['resource_credit_bytes']==0 and diag['retained_root_cap_bytes']==96<<30
    print(json.dumps(dict(signed_head=head,incident=c.bound(c.BASE/'four-homefloor-20261122-v1/HANDOFF.json'),
         positive_window=fleet['observer'],bytes_written_to_R2=0,conditional_epochs=store.writes,
         interrupted_after_put_recovered=True,external_event_restart_before_and_after_put=True,wrong_predecessor_rejected=True,wrong_producer_rejected=True,
         guard_closures=list(stops),diagnostic169=diag,qualified_utc=future)))

if __name__=='__main__':
    main()
