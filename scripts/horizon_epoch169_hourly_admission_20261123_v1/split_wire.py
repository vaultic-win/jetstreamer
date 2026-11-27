"""Project admitted private interval work onto the ordinary six-field status report."""
import math
import os
from pathlib import Path
import stat

from evidence import checked, need, utc

PRIVATE = Path('/home/sol/.jetstreamer-private')
PATHS = {
    169: PRIVATE / 'epoch169-hourly-source-20261123-v1/v158/epoch-169-through-73245218.jet',
    162: PRIVATE / 'epoch162-first-hourly-completion-20261127-v2/ledger/epoch-162.diagnostic.jet',
}
BOUNDS = {169: (73238441, 73245218), 162: (69983761, 69991076)}
IDENTITIES = {169: 'hourly169_start_intent', 162: 'private162_split_held'}
REVIEW = 12 * 3600 * 1000


def actor(row):
    if row['epoch'] == 169:
        return row['hourly169_start_intent'], row.get('invocation_id') or row['unit']['InvocationID']
    return row['held_owner'], row['producer_invocation_id']


def archive(row):
    pid = row['actor']['producer_pid']
    proc = Path('/proc') / str(pid)
    name = PATHS[row['epoch']]
    view = proc / 'root' / name.relative_to('/')
    try:
        seen = view.lstat()
    except FileNotFoundError:
        need((proc / 'stat').is_file(), 'producer exited during archive observation')
        return None
    need(stat.S_ISREG(seen.st_mode) and seen.st_uid == 1001 and seen.st_nlink == 1, 'unrecognized private interval output')
    matches = []
    for fd in (proc / 'fd').iterdir():
        try:
            if fd.readlink() == name and os.path.samestat(seen, fd.stat()):
                matches.append(fd.name)
        except FileNotFoundError:
            continue
    need(matches, 'private interval archive detached from the guarded producer')
    return dict(path=str(name), producer_pid=pid, device=seen.st_dev, inode=seen.st_ino,
                size=seen.st_size, bound_producer_fds=matches)


def elapsed(c, row, previous, old, same):
    if same:
        age = round((c.now - utc(previous['sampled_at_utc'])).total_seconds() * 1000)
        return previous['elapsed_execution_millis'] + age
    # A first sample cannot reuse another actor's elapsed time. Both native
    # adapters preserve the original Linux start ticks in the actor receipt.
    identity, iid = actor(row)
    admitted = checked(identity)
    need(admitted['producer_invocation_id'] == iid, 'incorrect private status start')
    boot_time = next(int(line.split()[1]) for line in Path('/proc/stat').read_text().splitlines() if line.startswith('btime '))
    ms = round((c.now.timestamp() - boot_time - admitted['start_ticks'] / os.sysconf('SC_CLK_TCK')) * 1000)
    need(ms >= 0, 'private actor started after this observer')
    return ms


def forecast(c, row, previous, old, original, delivery):
    epoch = row['epoch']
    first, end = BOUNDS[epoch]
    key = IDENTITIES[epoch]
    identity, iid = actor(row)
    age = round((c.now-utc(previous['sampled_at_utc'])).total_seconds() * 1000)
    same = old.get(key) == identity and old.get('producer_invocation_id') == iid
    closed = row['phase'] == 'terminal'
    # read_statuses() has authenticated the predecessor, including newer
    # conditional events. A replay phase can be carried only by the same owner.
    need(age >= 0 and previous['epoch'] == epoch and previous['phase'] in ('replay', 'verification')
         and (previous['phase'] != 'replay' or same), 'private replay predecessor belongs to another actor')
    need(not row['canonical_replay_claimed'] and not row['archive_publication_authorized'],
         'private interval unexpectedly gained canonical authority')
    measured = row.get('transaction_replay_claimed', False)
    observed = row.get('native_diagnostic') or {}
    progress = observed.get('observation', {}).get('useful_work') if measured else None
    active_worker = row['phase'] == 'worker'
    part = archive(row) if active_worker else None
    if part is not None:
        size = part['size']
    elif closed and epoch == 169:
        final = checked(row['terminal'])
        size = (final.get('archive') or {}).get('size', previous['jet_size_bytes'] if same else 0)
    else:
        size = previous['jet_size_bytes'] if closed and same else 0
    if active_worker and same:
        need(size >= previous['jet_size_bytes'], 'private archive length regressed for this actor')
    need(not measured or (part is not None and progress and active_worker), 'measured work lacks an open private archive')
    quote = delivery(c, epoch, size)
    prior_rate = old.get('measured_slots_per_second') if same else None
    rate = None
    if measured:
        last = progress['last']['slot']
        need(progress['journal_invocation_id'] == iid and first <= last <= end
             and progress['transaction_delta'] > 0 and progress['slot_delta'] > 0 and progress['elapsed_seconds'] > 0,
             'unbound or out-of-interval progress rate')
        rate = progress['slot_delta'] / progress['elapsed_seconds']
        interval = math.ceil((end-last) * 1000 / rate)
    else:
        # The accepted first event may precede the first scheduled worker
        # observation. Retain the measured rate and its absolute interval ETA.
        rate = prior_rate
        prior_stages = old.get('planning_milliseconds') or {}
        interval = max(0, prior_stages.get('interval_remaining', 0) - age)
    if rate is not None:
        need(math.isfinite(rate) and rate > 0, 'invalid private replay rate')
        stages = dict(interval_remaining=0 if closed else interval, route_review_and_qualification=REVIEW,
                      full_epoch_replay=math.ceil(432000000 / rate), delivery=quote['total_millis'])
        remaining = sum(stages.values())
    else:
        # Bootstrap has no usable local rate yet. Its registered owner/event
        # carries the reviewed planning forecast through the canonical sidecar.
        remaining = max(previous['estimated_remaining_millis'] - age, quote['total_millis'] + REVIEW)
        stages = dict(interval_remaining=0, delivery=quote['total_millis'], route_review_and_qualification=REVIEW,
                      unmeasured_replay_and_queue=remaining - quote['total_millis'] - REVIEW)
    carried = active_worker and not measured and same and previous['phase'] == 'replay'
    phase = 'replay' if measured or carried else 'verification'
    # A terminal transfers the open repair back to the campaign. Once this
    # transfer is recorded, the generic repair branch can age its forecast.
    after = dict(epoch=epoch, phase=phase, sampled_at_utc=c.stamp, estimated_remaining_millis=remaining,
                 jet_size_bytes=size, elapsed_execution_millis=elapsed(c,row,previous,old,same))
    extra = {key:identity, 'producer_invocation_id':None if closed else iid, 'current_repair_owner':'/root',
             'measured_canonical_progress':False, 'private_transaction_progress':bool(measured),
             'delivery_forecast':quote, 'planning_milliseconds':stages, 'measured_slots_per_second':rate,
             'archive_sample':part, 'private_status_event_predecessor':original,
             'estimate_model':'Private interval, route review, full canonical replay and complete verified delivery.'}
    if epoch == 162:
        extra['split162_enrollment'] = old['split162_enrollment']
        if 'split162_grant' in old:
            extra['split162_grant'] = old['split162_grant']
    if carried:
        extra['carried_private_replay_status'] = original
    return after, extra
