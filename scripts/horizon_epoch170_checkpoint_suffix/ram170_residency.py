"""Measure the funded 170 producer on both sides of the host availability samples."""
import os
from pathlib import Path

LIMIT = 56 << 30
SCRATCH_LIMIT = 40 << 30
PROC = Path('/proc')


def memory(group):
    counters = dict(line.split() for line in (group / 'memory.stat').read_text().splitlines())
    return dict(anon=int(counters['anon']), shmem=int(counters['shmem']),
                current=int((group / 'memory.current').read_text()),
                maximum=int((group / 'memory.max').read_text()),
                swap_max=int((group / 'memory.swap.max').read_text()),
                swap_current=int((group / 'memory.swap.current').read_text()))


def lower(first, last, pss_anon, scratch_used):
    for counters in (first, last):
        if counters['maximum'] != LIMIT or counters['swap_max'] or counters['swap_current']:
            raise ValueError('unexpected 170 cgroup limit or swap')
        if min(counters['anon'], counters['shmem'], counters['current']) < 0:
            raise ValueError('negative 170 cgroup usage')
    if pss_anon < 0 or not 0 <= scratch_used <= SCRATCH_LIMIT:
        raise ValueError('invalid 170 process or tmpfs usage')
    anon = min(first['anon'], last['anon'], pss_anon)
    shmem = min(first['shmem'], last['shmem'], scratch_used)
    return min(LIMIT, first['current'], last['current'], anon + shmem)


def sample(core, live, owner):
    if not owner or owner['phase'] != 'worker':
        return None
    # owner() set 'worker' only after the sealed observer authenticated the node,
    # worker executable and a guard sample naming that worker. Re-bind this
    # specific actor and recheck its kernel identity around the memory reads.
    callback = live['receiver'](core)
    gap = callback.gap
    scope = callback.interface()
    actor_ref, actor = gap.read_actor()
    grant, release = core.read(gap.RELEASE)
    parent = actor['producer_pid']
    processes = owner['processes']
    expected = {row[0] for row in processes}
    core.need(actor_ref == owner['actor'] == grant['actor'] and release == owner['release']
              and actor['unit'] == owner['unit'] == scope['expected_producer_unit'] == gap.UNIT
              and actor['interface'] == grant['interface'] == gap.INTERFACE
              and actor['producer_invocation_id'] == owner['invocation'] == grant['producer_invocation_id']
              and grant['guard_plan'] == owner['guard_plan'] and owner['pid'] == parent
              and scope['profile']['producer_memory_bytes'] == LIMIT
              and scope['profile']['scratch_noswap_tmpfs_bytes'] == SCRATCH_LIMIT
              and len(expected) == len(processes) == 2
              and any(row[0] == parent and row[1] == actor['start_ticks'] for row in processes),
              'different protected 170 owner, scope, release or processes')
    child, = expected - {parent}
    worker_row, = (row for row in processes if row[0] == child)
    scratch = Path(scope['run']) / 'scratch'
    mapping = gap.workspace.mount(parent, scratch)
    core.need(worker_row[2] == mapping['device'] and mapping['bytes'] == SCRATCH_LIMIT,
              '170 worker executable is outside its private mount')
    guard, sighted = gap.guard(scope, actor, {'pid': child}, grant)
    core.need(sighted and guard['plan'] == owner['guard_plan']
              and guard['timer_invocation_id'] == grant['guard_timer_invocation_id'],
              '170 guard did not observe this worker')
    group = gap.CGROUP
    projected = PROC / str(parent) / 'root' / scratch.relative_to('/')

    def match():
        core.need(not os.path.lexists(Path(scope['guard_receipts']) / 'stop-intent.json')
                  and set(map(int, (group / 'cgroup.procs').read_text().split())) == expected
                  and all(gap.process(row[0]) == row for row in processes)
                  and (PROC / str(parent) / 'ns/mnt').samefile(PROC / str(child) / 'ns/mnt')
                  and gap.workspace.mount(parent, scratch) == mapping,
                  '170 cgroup, processes, mount or guard changed')

    def occupied():
        fs = os.statvfs(projected)
        core.need(fs.f_frsize * fs.f_blocks == SCRATCH_LIMIT, 'different 170 tmpfs capacity')
        return (fs.f_blocks - fs.f_bfree) * fs.f_frsize

    match()
    before = memory(group)
    earlier = occupied()
    pss_anon = []
    for pid, *_ in processes:
        lines = (PROC / str(pid) / 'smaps_rollup').read_text().splitlines()
        field, = (line.split() for line in lines if line.startswith('Pss_Anon:'))
        core.need(len(field) == 3 and field[2] == 'kB' and field[1].isdecimal(),
                  'invalid 170 anonymous proportional set size')
        pss_anon.append(int(field[1]) * 1024)
    later = occupied()
    after = memory(group)
    match()
    paid = lower(before, after, sum(pss_anon), min(earlier, later))
    return dict(actor=actor_ref, scope=gap.INTERFACE, release=release, guard=guard, invocation=owner['invocation'],
                processes=processes, mount=mapping, pss_anon=pss_anon, workspace_usage=[earlier, later],
                cgroup_before=before, cgroup_after=after, realized_bytes=paid)


def apply(core, native, first, last):
    price = native['ram_retry_cost']
    core.need('ram170_residency' not in native and price['producer_memory_max'] == LIMIT
              and price['scratch_tmpfs'] == SCRATCH_LIMIT and price['original_guard_still_budgeted']
              and price['resident_ram_credit'] == native['realized_170_anon'] == 0
              and native['raw']['priced_170_invocation'] is None and not native['resource_credit_bytes'],
              'missing or previously realized 170 reservation')
    owner = native['ram_gap170']
    paid = 0
    if owner and owner['phase'] == 'worker':
        core.need(first and last and all(first[k] == last[k] for k in
                  ('actor', 'scope', 'release', 'invocation', 'processes', 'mount'))
                  and all(first[k] == owner[k] for k in ('actor', 'release', 'invocation', 'processes'))
                  and first['guard']['plan'] == last['guard']['plan'] == owner['guard_plan']
                  and first['guard']['timer_invocation_id'] == last['guard']['timer_invocation_id'],
                  '170 owner changed across host availability samples')
        core.need(all(0 <= x['realized_bytes'] <= LIMIT for x in (first, last)), 'invalid resident RAM')
        paid = min(first['realized_bytes'], last['realized_bytes'])
    else:
        core.need(first is last is None, 'residency without a protected 170 worker')
    core.need(native['required_ram'] >= LIMIT, '170 reservation missing from roster')
    native['required_ram'] -= paid
    native['ram_margin'] = native['available_ram'] - native['required_ram']
    price.update(resident_ram_credit=paid, unrealized_producer_ram=LIMIT - paid)
    native['ram170_residency'] = dict(before=first, after=last, realized_bytes=paid,
                                     nonresident_commitment=LIMIT-paid, source_limit=LIMIT, resource_credit_bytes=0)
