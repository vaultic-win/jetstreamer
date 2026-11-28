"""Carry authenticated status writes across the interrupted epoch 296 sample."""

import fcntl
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, '/var/lib/jetstreamer/horizon249-delivery-v214-tools')
from ordinary249.delivery248 import D, V, aws, bound, funds, props, ref


CONTROL = V / 'horizon-seven-publication-controller-v222'
PACKAGE = V / 'horizon296-guarded-singleton-v1'
FAILED = D / 'horizon-foundation-seven-lane-v331'
PREDECESSOR = D / 'horizon-foundation-seven-lane-v330/completion.json'
OBSERVER = D / 'horizon-resume-observer-20261120-v331.json'
MARKER = FAILED / 'interrupted-epoch296-cutoff.json'
UNIT = 'horizon-qualify-296-rooted-singleton-v1.service'
INVOCATION = '5d84409726e04264976c77a4f3874e02'
SCHEMA = 'foundation-epoch296-ended-during-fleet-reconciliation-v1'


def interrupted_cutoff():
    if not MARKER.is_file():
        return None
    saved = bound(ref(MARKER))
    assert saved['schema'] == SCHEMA and saved['observer'] == ref(OBSERVER)
    assert saved['accepted_predecessor'] == ref(PREDECESSOR)
    assert saved['terminal'] == ref(PACKAGE / 'terminal.json')
    assert saved['producer_invocation_id'] == INVOCATION and saved['status_keys_authentication_passed']
    assert saved['archive_publication_authorized'] is False
    return saved


def seal_cutoff():
    assert not (FAILED / 'status-audit.json').exists() and not (FAILED / 'completion.json').exists()
    assert not (D / 'horizon-resume-observer-20261120-v332.json').exists()
    observer_ref = ref(OBSERVER)
    observer = bound(observer_ref)
    assert observer['cadence']['routine_minimum_interval_enforced'] is True
    predecessor = ref(PREDECESSOR)
    previous = bound(predecessor)
    assert observer['cadence']['previous_sample_sha256'] == previous['observer']['sha256']
    replay, = [r for r in observer['replays'] if r['range'] == '296-296']
    assert replay['invocation_binding_stable'] and replay['producer_after']['invocation_id'] == INVOCATION
    terminal = ref(PACKAGE / 'terminal.json')
    failure = bound(terminal)
    assert failure['epoch'] == 296 and failure['invocation_id'] == INVOCATION and failure['guard_drained']
    assert not failure['archive_publication_authorized']
    names = ['ActiveState', 'MainPID', 'ControlGroup', 'Job', 'InvocationID', 'ExecMainStatus']
    assert props(UNIT, names) == dict(ActiveState='failed', MainPID='0', ControlGroup='', Job='',
                                      InvocationID=INVOCATION, ExecMainStatus='1')
    statuses = {}
    for epoch, earlier in previous['statuses'].items():
        candidate = ref(FAILED / epoch / 'completion.json')
        current = bound(candidate)
        key = f'epoch-{epoch}.epoch-status.json'
        assert current['key'] == key and current['authenticated_exact_byte_readback']
        assert bound(current['readback'])['epoch'] == int(epoch)
        if current != bound(earlier):
            assert bound(current['intent'])['previous'] == earlier
        metadata = aws('head-object', '--key', key, '--if-match', current['etag'])
        assert metadata['ETag'] == current['etag']
        assert metadata['ContentLength'] == Path(current['readback']['path']).stat().st_size
        statuses[epoch] = candidate
    return funds.put(MARKER, dict(schema=SCHEMA, observer=observer_ref, accepted_predecessor=predecessor,
        previous_fleet=previous['fleet'], producer_invocation_id=INVOCATION, terminal=terminal,
        statuses=statuses, status_keys_authentication_passed=True, archive_publication_authorized=False))


if __name__ == '__main__':
    assert __debug__ and os.geteuid() == 0
    assert os.environ['CODEX_THREAD_ID'] == '01a1f8f4-293b-7a91-a36e-2e7658bba721'
    os.umask(0o077)
    with (CONTROL / 'cycle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(seal_cutoff()))
