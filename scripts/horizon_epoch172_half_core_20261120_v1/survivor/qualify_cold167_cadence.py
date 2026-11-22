"""Exercise the scheduled 167/172 consumer using immutable historical observations."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import status_cycle as c
from qualify import Mirror, fail

FLEET = {'path':str(c.HEAD),'sha256':'6eeb24940a8316f95a6921a55d8781f9a1a41067ac766894b127aab61afec639'}
NEW = {'path':str(c.BASE/'root191757-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),
       'sha256':'d10c4336594352464bce6c59a2b24e966a2dcfa8c95fed18771dbf4b7f1cbcf8'}

def main():
    c.validate_package()
    old=c.checked(FLEET);live=c.checked(NEW)
    proof=c.bound(Path(FLEET['path']).parent/'RECOVERED_WORKERS.json')
    capture=c.checked(proof);capture['owners']={'167':capture['owners']['167']}
    capture['measured']={'167':capture['measured']['167']}
    historic=c.checked(capture['fleet'])
    native=c.checked(capture['sample']);native['replays']=[r for r in native['replays'] if r['range'] in ('167','172')]
    cfg=c.sealed(historic['sole_next_observer'])
    cfg['replays']=[r for r in cfg['replays'] if r['range'] in ('167','172')]
    assert c.check_sample(historic,native,cfg)==old['sampled_at_utc']
    fail(lambda:c.check_sample(historic,dict(native,replays=native['replays'][1:]),cfg))
    fail(lambda:c.check_sample(historic,native,dict(cfg,replays=list(reversed(cfg['replays'])))))
    route=c.cold167_status.reader()
    def observe(include_worker, mismatched=False):
        m=SimpleNamespace(fleet=historic if include_worker else live,stamp=old['sampled_at_utc'],now=c.utc(old['sampled_at_utc']),
            fleet_ref=capture['fleet'],cfg=copy.deepcopy(cfg),sample=copy.deepcopy(native),sample_ref=capture['sample'],
            next_cfg=copy.deepcopy(cfg),lanes={},advancing={172:True},commits={},histories={})
        m.next_cfg['replays']=[r for r in m.next_cfg['replays'] if r['range']=='172']
        if not include_worker:
            m.cfg['replays']=m.cfg['replays'][1:];m.sample['replays']=m.sample['replays'][1:]
        if mismatched: m.sample['replays'][0]['worker_after']['pid']+=1
        with patch.object(route,'freeze',return_value=(proof,capture)):
            route.sample_rows(m,c.cycle.observed_lane)
        return m
    boot=observe(False)
    assert boot.new_rows[167]['phase']=='verification' and not boot.advancing[167]
    assert c.cold167_status.counts(boot)==dict(canonical_producer_count=2,active_bootstraps=1,current_replay_lanes=1)
    replay=observe(True)
    assert replay.advancing[167] and c.cold167_status.counts(replay)==dict(canonical_producer_count=2,active_bootstraps=0,current_replay_lanes=2)
    assert replay.new_rows[167]['progress']==next(r['progress'] for r in old['actual_executing_replays'] if r['epoch']==167)
    fail(lambda:observe(True,True))
    # Bootstrap and measured transitions must both use the authenticated If-Match entry point.
    refs=c.baselines(NEW,live,c.handoff());store=Mirror(refs)
    qa=Path(sys.argv[1]);c.ensure_dir(qa)
    temporary=Path(tempfile.mkdtemp(dir=qa));os.chmod(temporary,0o700)
    for i,ctx in enumerate((boot,replay)):
        dst=temporary/str(i);c.ensure_dir(dst)
        ctx.now=c.now()+c.dt.timedelta(seconds=i)
        ctx.stamp=c.stamp(ctx.now);ctx.prior=c.checked(live['authenticated_status_audit'])
        previous=refs['167']
        archive=c.checked(old['complete_active_status_receipts']['167'])['archive_sample'] if 'complete_active_status_receipts' in old else None
        if archive is None:
            archive=c.checked(c.checked(old['authenticated_status_audit'])['receipts']['167'])['archive_sample']
        with patch.object(c.status,'observed_archive',return_value=archive), patch.object(c.cold167_status,'reader',return_value=route):
            c.publish(ctx,store,refs,dst,167)
        receipt=c.authenticated(store,167,refs['167'])
        assert receipt['previous_receipt']==previous and receipt['producer_invocation_id']==capture['owners']['167']['actor']['producer_invocation_id']
        assert receipt['after_status']['phase']==('replay' if i else 'verification') and receipt['measured_canonical_progress']==bool(i)
        assert receipt['current_guarded_admission']==capture['owners']['167']['admission']
        fail(lambda:c.authenticated(store,167,previous))
    # Exercise the real prelaunch observation. No service is started, and writes go to the in-memory store.
    current=SimpleNamespace(fleet=live,cfg=c.sealed(live['sole_next_observer']))
    if route.native(167) is None:
        c.cold167_status.reconcile(current,c.cycle.observed_lane)
        assert current.recovered_owners=={} and current.recovered_ref is None
    print(json.dumps(dict(original_sample=capture['sample'],original_capture=proof,current_anchor=NEW,
        two_guarded_owners=True,measured_167_TPS=replay.new_rows[167]['progress']['transactions_per_second'],
        bootstrap_count=1,process_only_replay_claimed=False,measured_replay_count=2,wrong_worker_rejected=True,
        missing_row_rejected=True,wrong_order_rejected=True,conditional_writes=len(store.writes),remote_mutations=0)))

if __name__=='__main__':main()
