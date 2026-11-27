"""Adopt the first conditional epoch 162 status into the existing fleet receipt chain."""
from pathlib import Path
import stat

from evidence import bound, checked, need

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2')
INITIAL = BASE / 'split-v1/INITIAL_STATUS.json'


def baseline(c, previous):
    row = c.split162
    if not INITIAL.exists():
        need(previous is None and (not row or row['phase'] in ('held','bootstrap','worker','terminal')),
             'split 162 first status or its receiver disappeared')
        # Initial creation belongs to the separately authenticated event. The
        # inventory path rejects an object with no accepted create receipt.
        return None
    meta = INITIAL.lstat()
    need(INITIAL.resolve(strict=True) == INITIAL and stat.S_ISREG(meta.st_mode)
         and meta.st_uid == 0 and not meta.st_mode & 0o022 and meta.st_nlink == 1,
         'untrusted 162 initial receipt')
    first_ref = bound(INITIAL)
    first = checked(first_ref)
    need(row is not None and first['epoch'] == 162 and first['key'] == 'epoch-162.epoch-status.json'
         and first['previous_receipt'] is None and first['conditional_header'] == 'If-None-Match'
         and first['authenticated_readback'] is True and first['private162_split_held'] == row['held_owner']
         and first['producer_invocation_id'] == row['producer_invocation_id']
         and first['after_status']['epoch'] == 162 and first['after_status']['phase'] in ('verification','replay')
         and first.get('split162_enrollment') and first.get('split162_grant'),
         'foreign split 162 initial status event')
    enrollment = checked(first['split162_enrollment'])
    grant = checked(first['split162_grant'])
    need(grant['held'] == row['held_owner'] and enrollment['operator'] == dict(path=str(BASE/'issued-split-v1/deployment-seal-receipt.json'),
              sha256='ca5ac887bdb0ca18b607966df05e890dbbc0ba3f73fb1112c4717ab97dc9415e'),
         'foreign split 162 grant')
    if previous is not None:
        current = checked(previous)
        need(current['epoch']==162 and current['authenticated_readback'] is True
             and current['private162_split_held']==row['held_owner']
             and current['split162_enrollment']==first['split162_enrollment']
             and current['producer_invocation_id'] in (row['producer_invocation_id'],None),
             'overlapping split 162 status owners')
    return previous or first_ref
