"""Exercise the cold 167 status path using the signed November 22 pre-stop sample."""
import copy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch


def check(package, fixture_root):
    sys.path.insert(0, str(package))
    import status_cycle as cycle
    import cold167_status as cold
    from qualify import Mirror, fail
    import delivery_eta
    import status

    assert Path(cycle.__file__).parent == Path(cold.__file__).parent == package
    cycle.validate_package()
    signed = cycle.checked(cycle.handoff()['fleet'])
    prior = cycle.checked(signed['previous_Root_operational_review'])
    ref = signed['observer']
    sample = cycle.checked(ref)
    recovery_ref = next(row['recovery_observation'] for row in signed['actual_executing_replays'] if row['epoch'] == 167)
    recovery = cycle.checked(recovery_ref)
    actual = {key: { '167': copy.deepcopy(recovery[key]['167']) } for key in ('owners', 'measured')}
    actor = actual['owners']['167']['actor']
    row = actual['measured']['167']['config']
    first = cycle.checked(actual['owners']['167']['first_worker'])
    assert first['observer_row'] == row and actor['producer_invocation_id'] == first['producer_invocation_id']
    rate_ref = signed['complete_active_status_receipts']['167']
    rate = cycle.checked(rate_ref)
    assert rate['producer_invocation_id'] == first['producer_invocation_id'] and rate['authenticated_readback']
    sampled = next(r for r in sample['replays'] if r['range'] == '167')
    original = cycle.checked(rate['previous_receipt'])

    def context(cfg, observation):
        return SimpleNamespace(cfg={'replays': [cfg]}, sample={'replays': [observation]}, next_cfg={'replays': []},
                fleet=prior, fleet_ref=rate['fleet_predecessor'], sample_ref=ref, stamp=sample['recorded_at_utc'],
                now=cycle.utc(sample['recorded_at_utc']), advancing={172: True}, lanes={}, delivery_forecasts={})

    reader = cold.reader()
    binding, prepared, guard = cold.generation()
    assert reader.QUAL == binding['guard_qualification'] and reader.GUARD_SHA == guard['guard']['sha256']
    assert reader.ROUTES[167] == (cold.NAME, cold.ROOT.name, cold.RUN, prepared['baseline']['root']['inode'], 512)
    forged = copy.deepcopy(binding)
    forged['guard_qualification']['sha256'] = '0' * 64
    cycle.ensure_dir(fixture_root)
    with tempfile.TemporaryDirectory(dir=fixture_root) as temp:
        selected = Path(temp) / 'generation.json'
        cycle.durable(selected, forged)
        with patch.object(cold, 'BINDING', selected):
            fail(cold.reader)
    def bind(c):
        with patch.object(reader, 'freeze', return_value=(recovery_ref, actual)):
            reader.sample_rows(c, cycle.cycle.observed_lane)

    c = context(row, sampled)
    bind(c)
    work = c.new_rows[167]['progress']
    assert c.advancing[167] and c.new_rows[167]['phase'] == 'replay'
    assert work == rate['epoch_useful_work'] and work['transaction_delta'] > 0 and work['slot_delta'] > 0
    # Project from the historical first-worker receipt with only the generation selectors rebound.
    with patch.object(cold, 'ROOT', Path(first['admission']['path']).parent), patch.object(cold, 'UNIT', actor['producer_unit']):
        cold.projection(row)
        fail(lambda: cold.projection(dict(row, expected_controller_invocation_id='0' * 32)))
    forged = copy.deepcopy(sampled)
    forged['producer_after']['main_pid'] = actor['producer_pid'] + 1
    fail(lambda: bind(context(row, forged)))
    forged = copy.deepcopy(sampled)
    forged['worker_after']['pid'] = first['worker_pid'] + 1
    fail(lambda: bind(context(row, forged)))
    fail(lambda: bind(context(dict(row, scratch_path='/home/sol'), sampled)))
    assert cold.counts(c) == dict(canonical_producer_count=2, active_bootstraps=0, current_replay_lanes=2)

    def quote(ctx, epoch, size):
        assert epoch == 167 and size == rate['archive_sample']['size']
        ctx.delivery_forecasts[epoch] = rate['delivery_forecast']
        return ctx.delivery_forecasts[epoch]

    history = {'167': rate['previous_receipt']}
    objects = Mirror(history)
    cycle.ensure_dir(fixture_root)
    dest = Path(tempfile.mkdtemp(dir=fixture_root))
    with patch.object(status, 'observed_archive', return_value=rate['archive_sample']), patch.object(delivery_eta, 'prepare', quote):
        cycle.publish(c, objects, history, dest, 167)
        history['167'] = rate['previous_receipt']
        cycle.publish(c, objects, history, dest, 167)
    accepted = cycle.authenticated(objects, 167, history['167'])
    assert objects.writes == [167] and accepted['previous_receipt'] == rate['previous_receipt']
    assert accepted['current_guarded_admission'] == first['admission'] and accepted['measured_canonical_progress']
    assert accepted['after_status']['phase'] == 'replay' and accepted['after_status']['jet_size_bytes'] == rate['archive_sample']['size']
    assert accepted['before_status'] == original['after_status'] and accepted['after_status']['estimated_remaining_millis'] > 0
    return dict(fixture=ref, first_worker=actual['owners']['167']['first_worker'], progress_receipt=rate_ref,
                slots_advanced=work['slot_delta'], transactions=work['transaction_delta'],
                tps=work['transactions_per_second'], next_status=history['167'], simulated_conditional_writes=1,
                guard_qualification=binding['guard_qualification'],wrong_guard_qualification_rejected=True,
                wrong_main_pid_rejected=True, wrong_worker_pid_rejected=True, wrong_config_rejected=True,
                r2_mutations=False)


if __name__ == '__main__':
    print(json.dumps(check(Path(__file__).resolve().parent, Path(sys.argv[1])), sort_keys=True))
