"""Exercise successor admission, cold bootstrap, worker, progress and failure using private fixtures."""
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
import json
import sys

import recovered
from cycle import observed_lane
from evidence import bound, checked, need, utc
from guard_stops import PREVIOUS
from qualify import reject


def qualify():
    fleet=checked(PREVIOUS)
    config=checked(fleet['sole_next_observer'])
    sample=checked(fleet['observer'])
    original={r['epoch']:r for r in fleet['actual_executing_replays']}
    cfgrows={int(r['range']):r for r in config['replays']}
    captures={}
    references={}
    for epoch in recovered.ROUTES:
        old=original[epoch]
        r=cfgrows[epoch]
        obs=next(row for row in sample['replays'] if row['range']==str(epoch))
        unit=old['unit'];pid=int(unit['MainPID'])
        ar={'path':f'fixture/admission-{epoch}','sha256':'a'*64}
        fr={'path':f'fixture/first-worker-{epoch}','sha256':'f'*64}
        actor=dict(producer_unit=unit['Id'],producer_pid=pid,producer_invocation_id=unit['InvocationID'],start_ticks=1)
        captures[str(epoch)]=dict(actor=actor,unit=unit,admission=ar,first_worker=fr)
        references[ar['path']]=dict(first_guard=old['guard_protection'],post_guard_capacity=old['admission'])
        references[fr['path']]=dict(worker_pid=obs['worker_before']['pid'],admission=ar)
    def lookup(ref):return references[ref['path']]
    def run(step,bad=False):
        owners=deepcopy(captures)
        for v in owners.values():
            if step=='intent':v['admission']=None
            if step in ('intent','bootstrap'):v['first_worker']=None
        registered=step=='sampled'
        section=dict(owners=owners,measured={
            k:dict(config=cfgrows[int(k)] if step in ('worker','sampled') else None,
                   protection=dict(timer={},receipt=original[int(k)]['guard_protection'])) for k,v in owners.items() if v['admission']})
        selected=[r for r in config['replays'] if int(r['range']) in recovered.ROUTES and registered]
        seen=[deepcopy(r) for r in sample['replays'] if int(r['range']) in recovered.ROUTES and registered]
        if bad:seen[0]['worker_after']['pid']+=1
        c=SimpleNamespace(fleet=dict(actual_executing_replays=[],actual_active_bootstraps=[]),
            cfg=dict(replays=selected),sample=dict(replays=seen),sample_ref=fleet['observer'],lanes={},advancing={},next_cfg=dict(replays=[]))
        with patch.object(recovered,'freeze',return_value=({},section)),patch.object(recovered,'checked',side_effect=lookup):
            recovered.sample_rows(c,observed_lane)
        assert set(c.new_rows)==(set() if step=='intent' else set(recovered.ROUTES))
        assert len(c.next_cfg['replays'])==(3 if step in ('worker','sampled') else 0)
        result=dict(actual_executing_replays=[],actual_active_bootstraps=[],epochs=[dict(epoch=n) for n in recovered.ROUTES],
                    canonical_producer_count=1,active_producer_count=2,bootstrap_count=0,guarded_bootstrap_owner_count=0,live_replay_count=1)
        recovered.install(result,c)
        assert result['canonical_producer_count']==1+len(c.new_rows)
        assert result['live_replay_count']==1+sum(c.advancing.values())
        assert result['bootstrap_count']==len(c.new_rows)-sum(c.advancing.values())
        return dict(stage=step,registered=len(c.next_cfg['replays']),canonical=len(c.new_rows),measured=sum(c.advancing.values()))
    stages=[run(s) for s in ('intent','bootstrap','worker','sampled')]
    reject(run,'sampled',True)
    return dict(native_historical_input=fleet['observer'],stages=stages,wrong_worker_rejected=True,production_writes=0)


if __name__=='__main__':print(json.dumps(qualify(),sort_keys=True))
