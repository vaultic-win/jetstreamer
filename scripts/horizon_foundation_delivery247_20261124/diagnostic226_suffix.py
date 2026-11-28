"""Enroll the private epoch 226 suffix in the existing fleet cadence."""

import re
from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref

UNIT = 'horizon-qualify-226-checkpoint-continuation-suffix-v1.service'
PACKAGE = V / 'horizon226-suffix-v1'
REGISTRATION = PACKAGE / 'cadence-registration.json'
RUN_ROOT = Path('/home/ubuntu/.jetstreamer-private/checkpoint-continuation-226-suffix-v1')
WORKER_SHA = '7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a'
FLEET_IMAGE = {
    'path': '/var/lib/jetstreamer/horizon292-fleet-cutoff-recovery-v339/jetstreamer-r2',
    'sha256': '3df74e8e3b78f8d940bf60718c533a1e34f45e455d41fe13feac6b931d2891ec',
}
FIELDS = ['Id', 'ActiveState', 'SubState', 'InvocationID', 'MainPID', 'NRestarts', 'ControlGroup']


def receipt():
    if not REGISTRATION.is_file():
        return None
    mode = REGISTRATION.lstat()
    assert REGISTRATION.resolve() == REGISTRATION and mode.st_uid == 0 and mode.st_nlink == 1
    assert not mode.st_mode & 0o222
    source = ref(REGISTRATION)
    row = bound(source)
    assert row['schema'] == 'jetstreamer-historical-performance-launch-receipt-v1'
    assert (row['kind'], row['epoch'], row['unit'], row['run_root']) == (
        'epoch226-checkpoint-suffix', 226, UNIT, str(RUN_ROOT))
    assert (row['bootstrap_slot'], row['first_slot'], row['last_slot']) == (98063464, 98063465, 98063999)
    assert row['launched'] and row['entry_replay_requested'] and row['source_prefix_retained']
    assert row['canonical_epoch_publication_authorized'] is False and row['worker_sha256'] == WORKER_SHA
    assert re.fullmatch('[0-9a-f]{32}', row['invocation_id']) and row['main_pid'] > 0
    admission = bound(row['admission'])
    assert admission['schema'] == 'jetstreamer-epoch226-scoped-repair-admission-v1'
    assert admission['admitted'] and admission['epoch'] == 226 and admission['operation'] == 'replay'
    assert (admission['producer_unit'], admission['run_root']) == (UNIT, str(RUN_ROOT))
    stage = bound(row['plan'])
    assert stage['admission'] == row['admission'] and stage['stage']['operation'] == 'replay'
    assert stage['stage']['worker']['sha256'] == WORKER_SHA
    active_guard = bound(row['active_guard'])
    assert active_guard['producer_invocation_id'] == row['invocation_id']
    assert active_guard['producer']['pid'] == row['main_pid'] and active_guard['trip_reason'] is None
    assert active_guard['plan_sha256'] == row['guard_plan']['sha256']
    return source, row


def configuration():
    registered = receipt()
    if registered is None:
        return []
    _, row = registered
    live = props(UNIT, FIELDS)
    if live['ActiveState'] in ('inactive', 'failed'):
        assert live['MainPID'] == '0' and not live['ControlGroup']
        return []
    assert (live['Id'], live['ActiveState'], live['SubState']) == (UNIT, 'active', 'running')
    assert live['InvocationID'] == row['invocation_id'] and int(live['MainPID']) == row['main_pid']
    assert live['ControlGroup'] == '/system.slice/' + UNIT and live['NRestarts'] == '0'
    assert (Path('/proc') / live['MainPID'] / 'exe').samefile(row['node_path'])
    return [dict(range='226-226', controller_unit=UNIT, expected_controller_invocation_id=row['invocation_id'],
                 producer_unit=UNIT, expected_producer_invocation_id=row['invocation_id'],
                 scratch_path=str(RUN_ROOT), worker_executable_basename='historical-worker')]


def register(plan):
    registered = receipt()
    if registered is None:
        return None
    source, row = registered
    if UNIT not in plan['tracked_units']:
        plan['tracked_units'].append(UNIT)
    owners = plan.setdefault('diagnostics', [])
    claim = dict(epoch=226, unit=UNIT, invocation_id=row['invocation_id'],
                 scratch_path=str(RUN_ROOT), launch_receipt=source)
    previous = [owner for owner in owners if owner['unit'] == UNIT]
    assert not previous or previous == [claim]
    if not previous:
        owners.append(claim)
    gate = plan['gates']['226']
    if source not in gate['evidence']:
        gate['evidence'].append(source)
    gate['next_action'] = 'Accept the private 535-slot replay and exact terminal receipt before assembly.'
    return FLEET_IMAGE


def owns(row):
    producer = row.get('producer', {})
    if producer.get('Id') != UNIT:
        return False
    _, registration = receipt()
    assert row['epoch'] == 226 and row['phase'] == 'diagnostic-qualification'
    assert producer['InvocationID'] == registration['invocation_id']
    assert row['ordinary_replay_claim'] is False and row['current_sidecar_eta_valid'] is False
    assert row['scratch_path'] == str(RUN_ROOT)
    return True
