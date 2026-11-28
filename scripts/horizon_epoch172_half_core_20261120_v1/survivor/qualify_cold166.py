"""Verify retry11 guard enrollment, real three-lane sampling, and durable If-Match transitions."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import status_cycle as c
from qualify import Mirror,fail

def main():
    hist=c.read_ref(c.HEAD);head=hist['previous_Root_operational_review'];prior=c.checked(head)
    signed=c.bound(c.HEAD.parent/'RECOVERED_WORKERS.json');obs=c.checked(signed);keys={'166','167'}
    obs={**obs,**{field:{k:v for k,v in obs[field].items() if k in keys} for field in ('owners','measured')}}
    sample=c.checked(hist['observer']);cfg=c.sealed(prior['sole_next_observer'])
    cfg['replays']=[r for r in cfg['replays'] if r['range'] in keys|{'172'}]
    sample['replays']=[r for r in sample['replays'] if r['range'] in keys|{'172'}]
    assert c.check_sample(prior,sample,cfg)==hist['sampled_at_utc']
    fail(lambda:c.check_sample(prior,dict(sample,replays=sample['replays'][1:]),cfg))
    route=c.cold166_status.reader();prepared,_,guard,proof=c.cold166_status.generation()
    cap,digest,reg=route.guard_budget(166,c.cold166_status.ROOT,dict(maximum_root_physical_bytes=288<<30,
        data_fulfillment=proof['contract']),dict(source=prepared))
    assert cap==288 and digest==proof['guard']['sha256'] and reg==proof
    fail(lambda:route.guard_budget(166,c.cold166_status.ROOT,dict(maximum_root_physical_bytes=512<<30,
                     data_fulfillment=proof['contract']),dict(source=prepared)))
    def observe(include,bad=False):
        scfg=copy.deepcopy(cfg);snap=copy.deepcopy(sample)
        if not include:
            scfg['replays']=scfg['replays'][1:];snap['replays']=snap['replays'][1:]
        if bad:snap['replays'][0]['worker_after']['pid']+=1
        previous=prior if include else dict(prior,actual_executing_replays=[r for r in prior['actual_executing_replays'] if r['epoch']!=166],
                                            actual_active_bootstraps=[r for r in prior['actual_active_bootstraps'] if r['epoch']!=166])
        ctx=SimpleNamespace(fleet=previous,fleet_ref=head,cfg=scfg,sample=snap,sample_ref=hist['observer'],
            next_cfg=copy.deepcopy(scfg),stamp=hist['sampled_at_utc'],now=c.utc(hist['sampled_at_utc']),
            lanes={},advancing={172:True},commits={},histories={},prior=c.checked(prior['authenticated_status_audit']))
        ctx.next_cfg['replays']=[v for v in scfg['replays'] if v['range']=='172']
        with patch.object(route,'freeze',return_value=(signed,obs)):
            route.sample_rows(ctx,c.cycle.observed_lane)
        return ctx
    live=observe(True);boot=observe(False);fail(lambda:observe(True,True))
    assert c.cold167_status.counts(live)==dict(canonical_producer_count=3,current_replay_lanes=3,active_bootstraps=0)
    assert c.cold167_status.counts(boot)==dict(canonical_producer_count=3,current_replay_lanes=2,active_bootstraps=1)
    assert boot.new_rows[166]['phase']=='verification' and boot.advancing[167]
    historic=next(r for r in hist['actual_executing_replays'] if r['epoch']==166)
    assert live.new_rows[166]['progress']==historic['progress']
    result=c.checked(hist['complete_active_status_receipts']['166'])
    refs={'166':result['previous_receipt']};store=Mirror(refs);fixture=Path(sys.argv[1]);c.ensure_dir(fixture)
    with tempfile.TemporaryDirectory(dir=fixture) as tmp:
        destination=Path(tmp)
        for i,ctx in enumerate((boot,live)):
            out=destination/str(i);c.ensure_dir(out)
            ctx.now=c.now()+c.dt.timedelta(seconds=i);ctx.stamp=c.stamp(ctx.now)
            with patch.object(c.status,'observed_archive',return_value=result['archive_sample']):
                before=refs['166'];c.publish(ctx,store,refs,out,166)
                refs['166']=before;c.publish(ctx,store,refs,out,166)
            committed=c.authenticated(store,166,refs['166'])
            assert committed['previous_receipt']==before and committed['producer_invocation_id']==historic['unit']['InvocationID']
    assert store.writes==[166,166] and committed['measured_canonical_progress']
    return dict(original_capture=signed,counted_native_workers=3,wrong_166_worker_rejected=True,
                retry11_wrong_cap_rejected=True,guard=guard,prepared=prepared,conditional_writes=len(store.writes),
                measured_166=live.new_rows[166]['progress']['transactions_per_second'],remote_writes=0)

if __name__=='__main__':print(json.dumps(main()))
