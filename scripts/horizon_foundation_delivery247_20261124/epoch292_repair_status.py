"""Verify the stopped 292 bootstrap duplicate and correct its live repair status."""

import datetime as dt
import fcntl
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, '/var/lib/jetstreamer/horizon249-delivery-v214-tools')
from ordinary249.delivery248 import D, V, aws, bound, funds, props, ref

CONTROL = V / 'horizon-seven-publication-controller-v222'
PACKAGE = V / 'horizon292-full-v322'
GUARDS = V / 'horizon292-full-guard-receipts-v322'
STATE = PACKAGE / 'repair-status-v335'
WORKER_PROOF = V / 'horizon288-worker-shrink-debt-v327'
ROOT = Path('/home/ubuntu/.jetstreamer-private/qualification-292-root-v322')
UNIT = 'horizon-qualify-292-root-singleton-v322.service'
OWNER = 'foundation-292-bootstrap-repair-v335.service'
INVOCATION = 'ed9666c18ff34ef3bb1cca59131a323b'
KEY = 'epoch-292.epoch-status.json'


def identity(path):
    stamp = path.lstat()
    assert path.resolve() == path and stat.S_ISREG(stamp.st_mode) and stamp.st_nlink == 1
    return dict(device=stamp.st_dev, inode=stamp.st_ino, bytes=stamp.st_size,
                allocated_bytes=stamp.st_blocks * 512, modified_ns=stamp.st_mtime_ns,
                changed_ns=stamp.st_ctime_ns, uid=stamp.st_uid, mode=stamp.st_mode)


def image_proof(path, sha):
    before = identity(path)
    with path.open('rb') as stream:
        assert os.fstat(stream.fileno()).st_ino == before['inode']
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    assert digest == sha and identity(path) == before
    return dict(path=str(path), sha256=digest, **before)


def terminal_proof():
    manager = props(UNIT, ['ActiveState', 'InvocationID', 'MainPID', 'ControlPID', 'ControlGroup', 'Job'])
    assert manager == dict(ActiveState='inactive', InvocationID='', MainPID='0', ControlPID='0',
                           ControlGroup='', Job='')
    cut = ref(GUARDS / 'stop-intent.json')
    done = ref(GUARDS / 'stop-completion.json')
    intent, stop = bound(cut), bound(done)
    assert intent['producer_invocation_id'] == stop['producer_invocation_id'] == INVOCATION
    assert intent['reason'] == 'root-physical-budget' and stop['scratch_deleted'] is False
    assert stop['terminal']['active'] == 'inactive' and not stop['terminal']['pid']
    assert intent['sample']['root_physical_observation']['exceeds_budget']
    return dict(intent=cut, stop=done, producer=manager)


def snapshot_repair():
    profile = bound(ref(PACKAGE / 'profile.json'))
    old_build = bound(ref(WORKER_PROOF / 'worker-build-and-wire.json'))
    candidate = bound(ref(WORKER_PROOF / 'completion.json'))
    assert profile['epoch'] == 292 and profile['run_root'] == str(ROOT)
    assert old_build['byte_identical_protocol'] and old_build['default_features_only']
    assert profile['worker']['sha256'] == old_build['old']['sha256']
    for worker in (profile['worker'], candidate['sealed_worker']):
        image_proof(Path(worker['path']), worker['sha256'])
    snapshot = profile['snapshot']
    source = Path(snapshot['path'])
    duplicate, = ROOT.glob('state/*/work/root-cohort-292-292/run-*/scratch/.historical-runtime/*/bound-bootstrap/' + source.name)
    sealed = image_proof(source, snapshot['sha256'])
    copy = image_proof(duplicate, snapshot['sha256'])
    assert sealed['uid'] == 0 and not sealed['mode'] & 0o222 and sealed['inode'] != copy['inode']
    assert sealed['bytes'] == copy['bytes'] == snapshot['bytes']
    return funds.put(STATE / 'bootstrap-comparison.json', dict(epoch=292, original=sealed, duplicate=copy,
        sealed_candidate=ref(WORKER_PROOF / 'completion.json'), previous_worker=profile['worker'],
        replacement_wire_compatible=True, live_storage_comparison_passed=False,
        local_retirement_authorized=False, publication_authorized=False, remote_mutations=False))


def put_repair_status(owner, terminal, comparison):
    previous = ref(D / 'horizon-foundation-seven-lane-v291/292/completion.json')
    old = bound(previous)
    native, old_payload = bound(old['native']), bound(old['readback'])
    assert old['authenticated_exact_byte_readback'] and old['key'] == KEY
    assert native['producer_invocation_id'] == native['controller_invocation_id'] == INVOCATION
    assert old_payload == native['status'] and old_payload['phase'] == 'replay' and old_payload['epoch'] == 292
    objects = aws('list-objects-v2', '--prefix', 'epoch-292.')
    assert not objects.get('IsTruncated') and {row['Key'] for row in objects.get('Contents', [])} == {KEY}
    current = STATE / 'before.json'
    response = aws('get-object', '--key', KEY, '--if-match', old['etag'], str(current))
    assert response['ETag'] == old['etag'] and current.read_bytes() == Path(old['readback']['path']).read_bytes()
    os.chmod(current, 0o400)
    with current.open('rb') as stream:
        os.fsync(stream.fileno())
    timing = ref(D / 'horizon-foundation-seven-lane-v227/211/timing.json')
    costs = bound(timing)
    tail = round(sum(costs[key] for key in ('local', 'public', 'upload', 'readback')))
    replay_seconds = round((432000 + 1853) / 1.61)
    queue_and_qualification = 36 * 3600
    now = dt.datetime.now(dt.UTC).replace(microsecond=0)
    start = dt.datetime.strptime(owner['ExecMainStartTimestamp'], '%a %Y-%m-%d %H:%M:%S UTC').replace(tzinfo=dt.UTC)
    elapsed = max(1000, round((now - start).total_seconds() * 1000))
    archive, = ROOT.glob('state/*/work/root-cohort-292-292/run-*/archives/epoch-292.jet')
    archive_identity = identity(archive)
    payload = dict(epoch=292, jet_size_bytes=archive_identity['bytes'], elapsed_execution_millis=elapsed,
        estimated_remaining_millis=1000 * (queue_and_qualification + replay_seconds + tail),
        sampled_at_utc=now.strftime('%Y-%m-%dT%H:%M:%SZ'), phase='verification')
    body = funds.put(STATE / 'payload.json', payload)
    intent = funds.put(STATE / 'intent.json', dict(schema='foundation-epoch292-status-repair-intent-v335',
        epoch=292, previous=previous, previous_readback=ref(current), previous_etag=old['etag'], key=KEY,
        terminal=terminal, bootstrap_comparison=comparison, owner=owner, retained_archive=archive_identity,
        estimate=dict(full_restart_assumed=True, replay_rate=1.61, replay_seconds=replay_seconds,
            queue_and_qualification_seconds=queue_and_qualification, capacity_allowance_is_a_forecast=True,
            delivery_seconds=tail, comparable_pipeline=timing), payload=body))
    assert terminal_proof() == terminal and props(OWNER, list(owner)) == owner
    result = aws('put-object', '--key', KEY, '--if-match', old['etag'], '--content-type', 'application/json',
                 '--body', body['path'])
    etag = result['ETag']
    assert etag and etag != old['etag']
    readback = STATE / 'readback.json'
    response = aws('get-object', '--key', KEY, '--if-match', etag, str(readback))
    assert response['ETag'] == etag and readback.read_bytes() == Path(body['path']).read_bytes()
    os.chmod(readback, 0o400)
    with readback.open('rb') as stream:
        os.fsync(stream.fileno())
    return funds.put(STATE / 'completion.json', dict(key=KEY, etag=etag, intent=intent,
        readback=ref(readback), authenticated_exact_byte_readback=True, archive_publication_authorized=False))


if __name__ == '__main__':
    assert __debug__ and os.geteuid() == 0 and os.environ['CODEX_THREAD_ID'] == '01a1f8f4-293b-7a91-a36e-2e7658bba721'
    os.umask(0o077)
    owner = props(OWNER, ['ActiveState', 'SubState', 'MainPID', 'InvocationID', 'ExecMainStartTimestamp'])
    assert owner['MainPID'] == str(os.getpid()) and owner['ActiveState'] == 'active' and owner['SubState'] == 'running'
    terminal = terminal_proof()
    STATE.mkdir(mode=0o700)
    comparison = snapshot_repair()
    with (CONTROL / 'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(put_repair_status(owner, terminal, comparison)))
