"""Bind the half-core source and its retained allocation to its accepted predecessor."""
from pathlib import Path

from evidence import checked, need
import full172

FIELD = 'full172_local_commit'
FIRST = dict(path=str(full172.ROOT/'FIRST_PROTECTED_HISTORICAL_WORKER_20261121.json'),
             sha256='165d1600fb91aebef3903532ed997db46658f8901d765c49e3550fb548c39148')
ADMISSION = dict(path=str(full172.ADMISSION),
                 sha256='c1dc591288eca1a2f6e2ab37888c57f108d2d25e6639d292d612def83ff2f2df')


def preceding(fleet):
    row = full172.owned(fleet)
    if row is None:
        return None
    first = checked(FIRST)
    admission = checked(ADMISSION)
    protected = first['worker_guard']
    actor = dict(producer_unit=row['unit']['Id'], producer_invocation_id=row['unit']['InvocationID'])
    need(row['admission'] == fleet['current_full172_admission'] == ADMISSION and
         first['observer_row'] == row['observer_config'] and
         row['post_guard_capacity'] == fleet['current_full172_post_guard_fit'] == admission['post_guard_capacity'] and
         actor == {k:admission[k] for k in actor} and row['start_ticks'] == admission['start_ticks'] and
         protected['producer']['InvocationID'] == actor['producer_invocation_id'] and
         int(protected['producer']['MainPID']) == admission['producer_pid'] and
         protected['timer']['InvocationID'] == row['guard_timer']['InvocationID'],
         'foreign 172 first worker, guard or original admission')
    return dict(admission=ADMISSION, first_worker=FIRST, actor=actor)


def retained_cap(proof):
    need(proof['first_worker'] == FIRST and proof['admission'] == ADMISSION,
         'different full 172 booking')
    admission = checked(ADMISSION)
    guard = checked(admission['actual_guard_plan'])
    fit = checked(admission['post_guard_capacity'])
    need(fit['candidate_cap_bytes'] == guard['maximum_root_physical_bytes'] == full172.CAP and
         guard['invocation_id'] == admission['producer_invocation_id'] and
         guard['unit'] == full172.UNIT and
         Path(guard['worker_root']) == full172.LOG.parents[1] and
         fit['resource_credit_bytes'] == fit['resource_promise_ending_bytes'] == 0,
         '172 retained worker root or reservation differs')
    return full172.CAP


def frozen(c, proof):
    path = c.paths['out']/'FULL172_OBSERVATION.json'
    if not path.exists():
        return None
    from evidence import bound
    ref = bound(path)
    record = checked(ref)
    first = checked(FIRST)
    need(proof['admission'] == record['identity']['admission'] == ADMISSION and
         proof['first_worker'] == FIRST and record['observer'] == c.sample_ref and
         record['fleet'] == c.fleet_ref and record['guard']['observer_config'] == first['observer_row'] and
         record['guard']['worker_pid'] == first['worker_pid'] and
         record['guard']['worker_start_ticks'] == first['worker_start_ticks'],
         'different 172 owner in frozen observation')
    return ref
