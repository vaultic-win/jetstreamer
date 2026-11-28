"""Carry the accepted epoch 262 bootstrap claim through the existing cadence."""

from pathlib import Path

from ordinary249.delivery248 import V, bound, props, ref

UNIT = 'horizon-262-native-input-20261126-v1.service'
PHASE = 'private-cold-snapshot-verification'
ROOT = '/run/horizon262-native-cold-v1'
RUN_SCHEMA = 'jetstreamer-private-epoch262-native-input-running-v1'
TERMINAL_SCHEMA = 'jetstreamer-private-epoch262-native-terminal-proof-v1'


def owns(row):
    return (row['epoch'] == 262 and row['phase'] == PHASE
            and row['unit']['Id'] == UNIT)


def predecessor(current):
    """Adopt accepted events in order, keeping the routine observation identity."""
    fleet = bound(current)
    directory = Path(current['path']).parent
    for leaf, schema in (('running', RUN_SCHEMA), ('terminal', TERMINAL_SCHEMA)):
        path = directory / f'native262-{leaf}' / 'fleet.json'
        if not path.is_file():
            continue
        identity = path.stat()
        assert path.resolve() == path and identity.st_uid == 0 and not identity.st_mode & 0o022
        candidate = ref(path)
        accepted = bound(candidate)
        assert accepted['schema'] == fleet['schema'] == 'jetstreamer-horizon-campaign-fleet-v1'
        assert (accepted['first_epoch'], accepted['last_epoch']) == (201, 300)
        assert accepted['previous_fleet'] == current
        for key in ('sampled_at_utc', 'observer_receipt', 'observer_sha256'):
            assert accepted[key] == fleet[key]
        event = bound(accepted['metadata_event'])
        assert (event['schema'], event['epoch'], event['unit']) == (schema, 262, UNIT)
        assert event['fleet'] == current
        assert event['observer'] == {'path': fleet['observer_receipt'], 'sha256': fleet['observer_sha256']}
        current, fleet = candidate, accepted
    return current


def registered(fleet_ref):
    fleet = bound(fleet_ref)
    plan = bound({'path': fleet['plan'], 'sha256': fleet['plan_sha256']})
    matches = [claim for claim in plan['pipeline_claims'] if claim['unit'] == UNIT]
    if not matches:
        return None
    claim, = matches
    origin_ref, = claim['evidence']
    origin = bound(origin_ref)
    assert (origin['schema'], origin['epoch'], origin['unit']) == (RUN_SCHEMA, 262, UNIT)
    assert (claim['epoch'], claim['phase'], claim['invocation_id']) == (262, PHASE, origin['invocation_id'])
    return origin


def configure(config, origin):
    runtime = props(UNIT, ['ActiveState', 'SubState', 'InvocationID', 'MainPID'])
    if (runtime['ActiveState'], runtime['SubState']) != ('active', 'running'):
        return
    assert runtime['InvocationID'] == origin['invocation_id']
    assert int(runtime['MainPID']) == origin['main_pid']
    handoff = bound(origin['startup_handoff'])
    config.setdefault('native_input_diagnostics', []).append({
        'epoch': 262,
        'unit': UNIT,
        'expected_invocation_id': origin['invocation_id'],
        'main_pid': origin['main_pid'],
        'scratch_path': ROOT,
        'executable': handoff['harness']['path'],
        'executable_sha256': handoff['harness']['sha256'],
    })


def images(origin, check_image):
    admission = bound(origin['admission'])
    source = bound(admission['source_publication'])
    selected = {}
    for role in ('observer', 'fleet'):
        artifact, = (row['artifact'] for row in source['artifacts'] if row['role'] == role)
        assert Path(artifact['path']).is_relative_to(V)
        selected[role] = Path(check_image(artifact))
    return selected
