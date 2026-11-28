"""Qualify the prepared retry on the host and exercise process promotion and scheduling offline."""
import copy
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import status_cycle as cycle
import cold168_status as retry
from qualify import Mirror, fail


def promotion(parent, profile):
    root, proc = parent/'receipts', parent/'proc'
    for d in (root, proc, root/'tools', root/'barrier', proc/'fd'):
        d.mkdir()
    alias = proc/'root'/retry.ALIAS.relative_to('/')
    alias.mkdir(parents=True)
    gate = root/'tools/gate.py'
    gate.touch()
    payload = root/'COLD_PAYLOAD.json'
    payload.touch()
    for name, source in [('gate.py',gate),('payload.json',payload),('jetstreamer-node',retry.NODE)]:
        (alias/name).symlink_to(source)
    (proc/'fd/1').symlink_to(retry.RUN/'producer.log')
    iid = '1' * 32
    actor = dict(producer_invocation_id=iid, producer_unit=retry.UNIT, producer_pid=1001, start_ticks=90210)
    group = ['1001']
    args = profile['payload']['regular_node_argv']
    image = proc/'exe'
    image.symlink_to('/usr/bin/python3')
    cmd = proc/'cmdline'
    def write_argv(argv):
        cmd.write_bytes(b'\0'.join(v.encode() for v in argv) + b'\0')
    def inspect():
        retry.verify_process(proc, group, actor, profile)
    with patch.object(retry, 'ROOT', root):
        write_argv(profile['producer_argv'][-11:])
        inspect()
        group.append('2002')
        fail(inspect)
        group.pop()
        st = image.stat()
        held = dict(actor, stage='held', exe_device=st.st_dev, exe_inode=st.st_ino)
        cycle.durable(root/'ACTUAL_PRODUCER_NATIVE.json', held)
        inspect()
        write_argv([*profile['producer_argv'][-11:-1], 'different-snapshot'])
        fail(inspect)
        write_argv(args)
        image.unlink()
        image.symlink_to(retry.NODE)
        for n in ['FIRST_GUARD','ACTUAL_GUARD_PLAN','POST_GUARD_CAPACITY']:
            cycle.durable(root/(n+'.json'),dict(fits=True))
        auth = {k:actor[k] for k in ('producer_invocation_id','producer_pid','start_ticks')}
        for k,n in [('first_guard','FIRST_GUARD'),('actual_guard_plan','ACTUAL_GUARD_PLAN'),
                    ('post_guard_capacity','POST_GUARD_CAPACITY')]:
            auth[k] = cycle.bound(root/(n+'.json'))
        cycle.durable(root/'AUTHORIZED_GATED_PAYLOAD.json',auth)
        permit = root/'barrier/allow'
        permit.write_text('2'*32)
        permit.chmod(0o444)
        fail(inspect)
        permit.write_text(iid)
        inspect()
        st = image.stat()
        node = dict(actor, stage='node', exe_device=st.st_dev, exe_inode=st.st_ino,
                    authorization=cycle.bound(root/'AUTHORIZED_GATED_PAYLOAD.json'))
        cycle.durable(root/'NODE_AFTER_PERMIT.json',node)
        inspect()
        with patch.dict(actor, start_ticks=actor['start_ticks']+1):
            fail(inspect)
        write_argv(['unregistered-node', *args[1:]])
        fail(inspect)


def measured_population(hist, previous, frozen, captured, scheduled):
    # The pre-stop sample contains genuine replay windows for all five epoch numbers.
    config = cycle.sealed(previous['sole_next_observer'])
    sample = cycle.checked(hist['observer'])
    for dataset in (config,sample):
        dataset['replays'] = [r for r in dataset['replays'] if int(r['range']) in scheduled | {172}]
    assert cycle.check_sample(previous, sample, config) == hist['sampled_at_utc']
    saved = copy.deepcopy(frozen)
    if 168 in captured:
        row = next(r for r in hist['actual_executing_replays'] if r['epoch']==168)
        ad = cycle.checked(row['admission'])
        actor = {k:ad[k] for k in ('producer_unit','producer_invocation_id','producer_pid','start_ticks')}
        saved['owners']['168'] = dict(actor=actor, unit=row['unit'], admission=row['admission'],first_worker=row['first_worker'])
        saved['measured']['168'] = dict(config=row['observer_config'],protection=dict(timer=row['guard_timer'],receipt=row['guard_protection']))
    for key in ('owners','measured'):
        saved[key] = {k:v for k,v in saved[key].items() if int(k) in captured}
    groups = {key:[r for r in previous[key] if r['epoch'] in scheduled | {172}]
              for key in ('actual_executing_replays','actual_active_bootstraps')}
    ctx = SimpleNamespace(fleet=dict(previous, **groups),cfg=config,sample=sample,sample_ref=hist['observer'],lanes={},advancing={172:True},
                          next_cfg=dict(config, replays=[r for r in config['replays'] if r['range']=='172']))
    mod = cycle.cold_workers.reader()
    with patch.object(mod,'freeze',return_value=(cycle.bound(cycle.HEAD.parent/'RECOVERED_WORKERS.json'),saved)):
        mod.sample_rows(ctx,cycle.cycle.observed_lane)
    assert set(ctx.new_rows)==captured
    assert {int(r['range']) for r in ctx.next_cfg['replays']} == captured | {172}
    assert cycle.cold167_status.counts(ctx)==dict(canonical_producer_count=len(captured)+1,
                   current_replay_lanes=len(scheduled)+1,active_bootstraps=len(captured-scheduled))
    if 168 in scheduled:
        assert ctx.new_rows[168]['progress']['transaction_delta']>0
    return ctx


def main():
    prepared, baseline, proof = retry.generation()
    mod = cycle.cold_workers.reader()
    assert mod.FIELD == retry.FIELD and mod.ROUTES[168][4] == 288
    plan = dict(maximum_root_physical_bytes=288<<30,data_fulfillment=proof['contract'])
    admission = dict(source=prepared)
    assert mod.guard_budget(168,retry.ROOT,plan,admission) == (288,proof['guard']['sha256'],proof)
    fail(lambda: mod.guard_budget(168,retry.ROOT,dict(plan,maximum_root_physical_bytes=384<<30),admission))
    fail(lambda: mod.guard_budget(168,retry.ROOT,plan,dict(source=retry.ANCHOR)))
    with tempfile.TemporaryDirectory(dir=sys.argv[1]) as td:
        promotion(Path(td), baseline['profile'])
    hist = cycle.read_ref(cycle.HEAD)
    previous = cycle.checked(hist['previous_Root_operational_review'])
    frozen = cycle.read_ref(cycle.HEAD.parent/'RECOVERED_WORKERS.json')
    populations = []
    for captured, scheduled in [({167,170,168},{167,170}), ({166,167,170,168},{166,167,170}),
                              ({166,167,170,168},{167,168,170}), ({166,167,170,168},{166,167,168,170}),
                              ({166,167,168},{166,167,168}), ({167,168},{167,168})]:
        ctx = measured_population(hist, previous, frozen, captured, scheduled)
        populations.append(sorted(e for e,advanced in ctx.advancing.items() if advanced))
    # Exercise the 168-specific archive selection used by the shared status code.
    # Replay the historical window in the real writer with an in-memory R2.
    row = ctx.new_rows[168]
    ctx.metered168_row = row
    ctx.prior = cycle.checked(previous['authenticated_status_audit'])
    ctx.now = cycle.utc(hist['sampled_at_utc'])
    ctx.stamp = hist['sampled_at_utc']
    ctx.fleet_ref = hist['previous_Root_operational_review']
    prior = cycle.checked(hist['complete_active_status_receipts']['168'])
    refs = {'168': prior['previous_receipt']}
    store = Mirror(refs)
    first = cycle.checked(row['admission'])
    assert first['producer_invocation_id'] == row['unit']['InvocationID']
    elapsed = prior['after_status']['elapsed_execution_millis']
    started = ctx.now - cycle.dt.timedelta(milliseconds=elapsed)
    row['unit'] = dict(row['unit'], ExecMainStartTimestamp=started.strftime('%a %Y-%m-%d %H:%M:%S UTC'))
    with tempfile.TemporaryDirectory(dir=sys.argv[1]) as td:
        dest = Path(td)
        with patch.object(cycle.status, 'observed_archive', return_value=prior['archive_sample']):
            cycle.publish(ctx,store,refs,dest,168)
            result=cycle.authenticated(store,168,refs['168'])
            assert result['current_guarded_admission']==row['admission'] and result['measured_canonical_progress']
            assert result['after_status']['phase']=='replay' and result['archive_sample']==prior['archive_sample']
        assert store.writes==[168]
    return dict(prepared=prepared,guard=retry.QUAL,successor_root=retry.ANCHOR,log=cycle.bound(retry.ROOT/'OBSERVER_LOG_PREPARED.json'),
                measured_populations=populations, held_and_promoted_identity_checked=True, conditional_fixture_writes=1, remote_writes=0)


if __name__ == '__main__':
    print(json.dumps(main(),sort_keys=True))
