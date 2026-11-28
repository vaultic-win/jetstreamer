"""Exercise a committed retry13 with the other measured workers and an in-memory status store."""
import copy
import datetime
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
import status_cycle as cycle
import cold170_commit as terminal
import cold170_status as cold
from qualify import Mirror

def main():
    path=cycle.BASE/'root231757-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
    fref=cycle.bound(path)
    assert fref['sha256']=='72f9ffb04009946f22229595f225a78fb4e49c10278a3570ebd2395fb3498c7d'
    fleet=cycle.checked(fref)
    env=terminal.DELIVERY/'held-publication-qa-e524d80eb6fa4ffdad057fec8dc0dc04/test-receiver/authority/TERMINAL_SUCCESS.json'
    tf=cycle.bound(env);fixture=cycle.checked(tf)
    tr=dict(tf,path=str(terminal.DELIVERY/'TERMINAL_SUCCESS.json'))
    proof=dict(terminal=tr, live=terminal.LIVE,admission=terminal.AD,first_worker=terminal.FIRST,
               producer_invocation_id=terminal.IID,resource_credit_bytes=0)
    terminal.bind(fleet,proof,adopting=True)
    previous=cycle.checked(fleet['observer']);cfg=cycle.sealed(fleet['sole_next_observer'])
    ownerdata=fleet[terminal.OWNERS]
    kept={'167':ownerdata['167']}
    row=next(v for v in fleet['actual_executing_replays'] if v['epoch']==167)
    recorded=cycle.checked(fleet['current_homefloor_cold166_167_170_observation'])
    now=cycle.utc(fleet['sampled_at_utc'])+datetime.timedelta(minutes=30)
    out=Path(sys.argv[1])
    # Real saved capture, frozen before a local commit was seen in the same sample.
    with tempfile.TemporaryDirectory(dir=out) as temp:
        dest=Path(temp)
        c=SimpleNamespace(fleet=copy.deepcopy(fleet),fleet_ref=fref,stamp=cycle.stamp(now),now=now,
                          cfg=cfg,sample=previous,sample_ref=fleet['observer'],
                          next_cfg=copy.deepcopy(cfg),paths={'out':dest},new_rows={},lanes={},advancing={172:True},
                          prior=cycle.checked(fleet['authenticated_status_audit']))
        saved=dict(fleet=fref,sample=c.sample_ref,owners=ownerdata,measured=recorded['measured'])
        cycle.durable(dest/'RECOVERED_WORKERS.json',saved)
        mod=cold.reader()
        def sample(ctx, _):
            ref,capture=mod.freeze(ctx)
            assert ref['path']!=str(dest/'RECOVERED_WORKERS.json') and capture['owners']==kept
            assert capture['prior_same_sample_capture']==cycle.bound(dest/'RECOVERED_WORKERS.json')
            ctx.recovered_ref=ref;ctx.recovered_owners=capture['owners'];ctx.new_rows={167:row};ctx.advancing[167]=True
            ctx.next_cfg['replays'].append(row['observer_config'])
        with patch.object(cold,'reader',return_value=mod),patch.object(cold,'terminal_route',return_value=proof), \
             patch.object(cold,'roster',return_value={167}),patch.object(mod,'ownership',return_value=kept), \
             patch.object(mod,'sample_rows',side_effect=sample),patch.object(cold,'projection'):
            cold.reconcile(c,cycle.cycle.observed_lane)
        assert c.commits=={170:proof} and c.recovered_owners==kept and set(c.new_rows)=={167}
        assert {int(v['range']) for v in c.next_cfg['replays']}=={167,172}
        ready=copy.deepcopy(fleet)
        for group in terminal.GROUPS:ready[group]=[v for v in ready[group] if v['epoch'] not in (167,170)]
        cold.install(c,ready)
        terminal.bind(ready,proof,adopting=True)
        assert ready[terminal.OWNERS]==kept and ready[terminal.FIELD]==tr and terminal.DRAIN not in ready
        ref=fleet['complete_active_status_receipts']['170']
        refs={'170':ref};store=Mirror(refs)
        real=cycle.checked
        with patch.object(cycle,'checked',side_effect=lambda r,*args,**kw: fixture if r==tr else real(r,*args,**kw)):
            cycle.publish(c,store,refs,dest,170)
            result=cycle.checked(refs['170']);assert result['cold170_local_commit']==tr
            assert result['after_status']['phase']=='verification' and result['after_status']['jet_size_bytes']==fixture['local_archive']['size']
            assert result['authenticated_readback'] and result['producer_invocation_id'] is None and not result['archive_publication_authorized']
            second=dest/'later';cycle.ensure_dir(second)
            c.now+=datetime.timedelta(minutes=30);c.stamp=cycle.stamp(c.now)
            cycle.publish(c,store,refs,second,170)
            following=cycle.checked(refs['170'])
            assert following['after_status']['estimated_remaining_millis']==result['after_status']['estimated_remaining_millis']-1800000
            assert store.writes==[170,170]
    return dict(fleet=fref,synthetic_manager_envelope=tf,surviving_epochs=[167,172],conditional_fixture_writes=2,
                physical_writes=0,fixture_replay_row_removed=True,local_commit_still_pending_guard=True)

if __name__=='__main__':print(json.dumps(main(),sort_keys=True))
