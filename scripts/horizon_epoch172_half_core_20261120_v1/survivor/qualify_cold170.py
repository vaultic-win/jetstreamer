"""Exercise both third-lane orders and their four-lane successor with recorded native captures."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import status_cycle as c
import cold170_status as cold
from qualify import Mirror, fail


def main():
    hist = c.read_ref(c.HEAD)
    head = hist['previous_Root_operational_review']
    prior = c.checked(head)
    signed = c.bound(c.HEAD.parent/'RECOVERED_WORKERS.json')
    evidence = c.checked(signed)
    route = cold.reader()
    _, _, proof = cold.generation()
    plan = dict(maximum_root_physical_bytes=384 << 30, data_fulfillment=proof['contract'])
    booking = dict(source=dict(path=str(cold.ROOT/'PREPARED.json')))
    assert route.guard_budget(170, cold.ROOT, plan, booking) == (384, proof['guard']['sha256'], proof)
    fail(lambda: route.guard_budget(170, cold.ROOT, dict(plan, maximum_root_physical_bytes=288<<30), booking))
    fail(lambda: route.guard_budget(170, cold.ROOT, dict(plan, data_fulfillment={}), booking))
    fail(lambda: route.guard_budget(170, cold.ROOT, plan, dict(source={})))

    def observe(population, scheduled, wrong=False):
        keys = {str(e) for e in population}
        cfg = c.sealed(prior['sole_next_observer'])
        sample = c.checked(hist['observer'])
        for b in (cfg, sample):
            b['replays'] = [v for v in b['replays'] if int(v['range']) in scheduled | {172}]
        assert c.check_sample(prior, sample, cfg) == hist['sampled_at_utc']
        if wrong:
            target = next(v for v in sample['replays'] if v['range'] == '170')
            target['worker_after']['pid'] += 1
        original = {k:[v for v in prior[k] if v['epoch'] in scheduled | {172}]
                    for k in ('actual_executing_replays','actual_active_bootstraps')}
        context = SimpleNamespace(fleet=dict(prior, **original),fleet_ref=head,cfg=cfg,sample=sample,
                sample_ref=hist['observer'],next_cfg=copy.deepcopy(cfg),stamp=hist['sampled_at_utc'],
                now=c.utc(hist['sampled_at_utc']),lanes={},advancing={172:True},commits={},histories={},
                prior=c.checked(prior['authenticated_status_audit']))
        context.next_cfg['replays'] = [v for v in cfg['replays'] if v['range']=='172']
        filtered = dict(evidence)
        for key in ('owners','measured'):
            filtered[key]={k:v for k,v in evidence[key].items() if k in keys}
        with patch.object(route, 'freeze', return_value=(signed,filtered)):
            route.sample_rows(context,c.cycle.observed_lane)
        assert {int(v['range']) for v in context.next_cfg['replays']} == population | {172}
        counts = cold.cold167.counts(context)
        assert counts == dict(canonical_producer_count=len(population)+1,
                              active_bootstraps=len(population-scheduled),current_replay_lanes=len(scheduled)+1)
        return context

    third = observe({167,170}, {167})
    measured = observe({167,170}, {167,170})
    observe({166,167,170}, {166,167})
    observe({166,167,170}, {167,170})
    fourth = observe({166,167,170}, {166,167,170})
    fail(lambda: observe({166,167,170}, {166,167,170}, True))
    original = next(v for v in hist['actual_executing_replays'] if v['epoch']==170)
    assert original['progress'] == fourth.new_rows[170]['progress']
    result=c.checked(hist['complete_active_status_receipts']['170'])
    refs={'170':result['previous_receipt']}
    store=Mirror(refs)
    parent=Path(sys.argv[1]);c.ensure_dir(parent)
    with tempfile.TemporaryDirectory(dir=parent) as work:
        for i,context in enumerate((third,measured,third)):
            dest=Path(work)/str(i);c.ensure_dir(dest)
            context.now=c.now()+c.dt.timedelta(seconds=i);context.stamp=c.stamp(context.now)
            with patch.object(c.status,'observed_archive',return_value=result['archive_sample']):
                before=refs['170'];c.publish(context,store,refs,dest,170)
                refs['170']=before;c.publish(context,store,refs,dest,170)
            accepted=c.authenticated(store,170,refs['170'])
            assert accepted['previous_receipt']==before and accepted['producer_invocation_id']==original['unit']['InvocationID']
            if i==1:
                assert accepted['measured_canonical_progress'] and accepted['after_status']['phase']=='replay'
            if i==2:
                assert not accepted['measured_canonical_progress'] and accepted['after_status']['phase']=='replay'
                assert accepted['carried_replay_status']==before
                foreign=dict(c.checked(before),current_guarded_admission={'path':'foreign','sha256':'0'*64})
                mismatch=Path(work)/'wrong-admission.json'; c.durable(mismatch,foreign)
                bad={'170':c.bound(mismatch)}
                wrong_dir=Path(work)/'rejected';c.ensure_dir(wrong_dir)
                with patch.object(c.status,'observed_archive',return_value=result['archive_sample']):
                    fail(lambda:c.publish(context,Mirror(bad),bad,wrong_dir,170))
    assert store.writes==[170,170,170]
    return dict(original_capture=signed, launch_orders=[[167,170,166],[166,167,170]],
                measured_lanes=4, measured_170_tps=original['progress']['transactions_per_second'],
                changed_native_identity_rejected=True, authenticated_fixture_writes=3, carried_authenticated_replay_writes=1, remote_writes=0)


if __name__=='__main__':
    print(json.dumps(main()))
