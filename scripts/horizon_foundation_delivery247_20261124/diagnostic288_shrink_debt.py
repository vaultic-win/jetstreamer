"""Associate the private epoch 288 comparison with the Foundation cadence."""

from pathlib import Path
import re

from ordinary249.delivery248 import V, bound, props, ref


UNIT = 'horizon-perf-epoch288-shrink-debt@v327.service'
PACKAGE = V / 'horizon288-shrink-debt-comparison-v327'
RUN_ROOT = Path('/home/ubuntu/.jetstreamer-private/qualification-288-shrink-debt-compare-v327')
REGISTRATION = PACKAGE / 'cadence-registration.json'
FIELDS = ['Id', 'ActiveState', 'SubState', 'InvocationID', 'MainPID', 'NRestarts', 'ControlGroup']


def registration():
    if not REGISTRATION.is_file():
        return None
    source = ref(REGISTRATION)
    record = bound(source)
    assert record['schema'] == 'jetstreamer-historical-performance-launch-receipt-v1'
    assert record['epoch'] == 288 and record['unit'] == UNIT and record['run_root'] == str(RUN_ROOT)
    assert record['kind'] == 'epoch288-bounded-shrink-debt-storage-comparison'
    assert record['launched'] and record['entry_replay_requested'] and not record['canonical_epoch_publication_authorized']
    assert (record['bootstrap_slot'], record['target_slot'], record['terminal_slot']) == (124415782, 124429562, 124435861)
    assert re.fullmatch(r'[0-9a-f]{32}', record['invocation_id']) and record['main_pid'] > 0
    admission = bound(record['admission'])
    assert admission['epoch'] == 288 and admission['admitted'] and not admission['publication_authorized']
    sample = bound(record['active_guard'])
    assert sample['producer_invocation_id'] == record['invocation_id'] and sample['producer']['pid'] == record['main_pid']
    assert sample['plan_sha256'] == record['guard_plan']['sha256'] and not sample['trip_reason']
    return source, record


def configuration():
    value = registration()
    if value is None:
        return []
    _, record = value
    live = props(UNIT, FIELDS)
    if live['ActiveState'] in ('inactive', 'failed'):
        assert live['MainPID'] == '0' and not live['ControlGroup']
        return []
    assert (live['Id'], live['ActiveState'], live['SubState']) == (UNIT, 'active', 'running')
    assert live['InvocationID'] == record['invocation_id'] and int(live['MainPID']) == record['main_pid']
    assert live['ControlGroup'] == '/system.slice/' + UNIT and live['NRestarts'] == '0'
    assert (Path('/proc') / live['MainPID'] / 'exe').samefile(record['node_path'])
    return [dict(range='288-288', controller_unit=UNIT, expected_controller_invocation_id=record['invocation_id'],
                 producer_unit=UNIT, expected_producer_invocation_id=record['invocation_id'],
                 scratch_path=str(RUN_ROOT), worker_executable_basename='historical-worker')]


def gate(plan):
    value = registration()
    if value is None:
        return
    source, record = value
    if UNIT not in plan['tracked_units']:
        plan['tracked_units'].append(UNIT)
    diagnostic = dict(epoch=288, unit=UNIT, invocation_id=record['invocation_id'],
                      scratch_path=str(RUN_ROOT), launch_receipt=source)
    diagnostics = plan.setdefault('diagnostics', [])
    previous = [row for row in diagnostics if row['unit'] == UNIT]
    assert not previous or previous == [diagnostic]
    epoch = plan['gates']['288']
    if source not in epoch['evidence']:
        epoch['evidence'].append(source)
    replacement = 'horizon-qualify-288-root-shrink-debt-v1.service' in plan['tracked_units']
    terminal = PACKAGE / 'terminal.json'
    if terminal.is_file():
        terminal_ref = ref(terminal)
        result = bound(terminal_ref)
        assert result['registration'] == source and not result['publication_authorized']
        if terminal_ref not in epoch['evidence']:
            epoch['evidence'].append(terminal_ref)
        if replacement:
            assert result['candidate_terminal_checkpoint_passed']
            assert result['manager']['INVOCATION_ID'] == record['invocation_id']
            live = props(UNIT, FIELDS)
            assert live['ActiveState'] == 'inactive' and live['MainPID'] == '0' and not live['ControlGroup']
            diagnostics[:] = [row for row in diagnostics if row['unit'] != UNIT]
            return
        epoch['next_action'] = result['next_action']
    else:
        assert not replacement
        epoch['next_action'] = 'Measure storage across slot 124429562 and verify the canonical checkpoint at slot 124435861.'
    if not previous:
        diagnostics.append(diagnostic)


def owns(row):
    producer = row.get('producer', {})
    if producer.get('Id') != UNIT:
        return False
    _, record = registration()
    assert row['epoch'] == 288 and row['phase'] == 'diagnostic-qualification'
    assert producer['InvocationID'] == record['invocation_id'] and row['scratch_path'] == str(RUN_ROOT)
    assert not row['ordinary_replay_claim'] and not row['current_sidecar_eta_valid']
    return True
