"""Preserve the interrupted v291 observation and adopt its applied status writes."""

import fcntl
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, '/var/lib/jetstreamer/horizon249-delivery-v214-tools')
from ordinary249.delivery248 import D, V, aws, bound, funds, props, ref

CONTROL = V / 'horizon-seven-publication-controller-v222'
PACKAGE = V / 'horizon292-full-v322'
UNIT = 'horizon-qualify-292-root-singleton-v322.service'
INVOCATION = 'ed9666c18ff34ef3bb1cca59131a323b'


def root(version):
    return D / f'horizon-foundation-seven-lane-v{version}'


def sample(version):
    return D / f'horizon-resume-observer-20261120-v{version}.json'


def interrupted_cutoff():
    marker = root(291) / 'interrupted-cutoff.json'
    if not marker.is_file():
        return None
    doc = bound(ref(marker))
    assert doc['schema'] == 'foundation-epoch292-stopped-during-fleet-reconciliation-v1'
    assert doc['observer'] == ref(sample(291)) and doc['accepted_predecessor'] == ref(root(290) / 'completion.json')
    assert doc['producer_invocation_id'] == INVOCATION and doc['new_resource_samples'] == 0
    assert doc['status_keys_authentication_passed'] and not doc['archive_publication_authorized']
    assert doc['terminal'] == ref(PACKAGE / 'terminal.json')
    return doc


def seal_cutoff():
    assert not (root(291) / 'status-audit.json').exists() and not (root(291) / 'completion.json').exists()
    assert not sample(292).exists()
    old_sample, observed = ref(sample(290)), ref(sample(291))
    observer = bound(observed)
    assert observer['cadence']['routine_minimum_interval_enforced'] is True
    assert observer['cadence']['previous_sample_sha256'] == old_sample['sha256']
    replay, = [row for row in observer['replays'] if row['range'] == '292-292']
    assert replay['invocation_binding_stable'] and replay['producer_after']['invocation_id'] == INVOCATION
    terminal, repair = ref(PACKAGE / 'terminal.json'), ref(PACKAGE / 'repair-backlog.json')
    stopped, backlog = bound(terminal), bound(repair)
    assert stopped['epoch'] == backlog['epoch'] == 292 and backlog['terminal'] == terminal and backlog['open']
    assert bound(stopped['registration'])['invocation_id'] == INVOCATION
    assert stopped['timer_drained'] == dict(ActiveState='inactive', Job='')
    manager = props(UNIT, ['ActiveState', 'MainPID', 'ControlPID', 'ControlGroup', 'Job'])
    assert manager == dict(ActiveState='inactive', MainPID='0', ControlPID='0', ControlGroup='', Job='')
    predecessor = ref(root(290) / 'completion.json')
    previous = bound(predecessor)
    assert previous['observer'] == old_sample
    corrections = {}
    for epoch in previous['statuses']:
        path = PACKAGE / 'repair-status-v335/completion.json' if epoch == '292' else root(291) / epoch / 'completion.json'
        source = ref(path)
        current = bound(source)
        key = f'epoch-{epoch}.epoch-status.json'
        assert current['key'] == key and current['authenticated_exact_byte_readback']
        status = bound(current['readback'])
        assert status['epoch'] == int(epoch)
        if epoch == '292':
            assert status['phase'] == 'verification' and not current['archive_publication_authorized']
            assert bound(current['intent'])['previous'] == ref(root(291) / epoch / 'completion.json')
        metadata = aws('head-object', '--key', key, '--if-match', current['etag'])
        assert metadata['ETag'] == current['etag']
        assert metadata['ContentLength'] == Path(current['readback']['path']).stat().st_size
        corrections[epoch] = source
    return funds.put(root(291) / 'interrupted-cutoff.json', dict(
        schema='foundation-epoch292-stopped-during-fleet-reconciliation-v1', observer=observed,
        accepted_predecessor=predecessor, previous_fleet=previous['fleet'], producer_invocation_id=INVOCATION,
        terminal=terminal, repair_backlog=repair, statuses=corrections, status_keys_authentication_passed=True,
        new_resource_samples=0, archive_publication_authorized=False))


if __name__ == '__main__':
    assert __debug__ and os.geteuid() == 0 and os.environ['CODEX_THREAD_ID'] == '01a1f8f4-293b-7a91-a36e-2e7658bba721'
    os.umask(0o077)
    with (CONTROL / 'cycle.lock').open('a+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(seal_cutoff()))
