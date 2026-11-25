"""Bind the one held full-epoch 170 actor to the native fleet capacity capture."""

import os
from pathlib import Path
import re
import time

ACTOR = ('Id', 'MainPID', 'InvocationID', 'ControlGroup', 'ActiveState', 'SubState', 'Job',
         'NRestarts', 'MemoryMax', 'CPUQuotaPerSecUSec', 'MemorySwapMax', 'ExecMainStartTimestamp')
TIMER = ('Id', 'InvocationID', 'ActiveState', 'SubState', 'Triggers', 'Job')
MAX_AGE = 120
MIN_FLOOR = 8_297_502_499_408
MEMORY_WITH_RESERVE = 810_658_050_048
CPU_MICROS = 64_000_000


def epoch145_members(s, fit):
    members = fit.members(fit.A145)
    if len(members) <= 2:
        return members
    # V5w's periodic read-only quote shares the already budgeted verifier
    # cgroup. Recognize only its pinned provider and its actual descendant
    # tree. A third verifier worker or unrelated process still fails pricing.
    manager = s.show(fit.A145)
    parent = int(manager['MainPID'])
    group = '0::/system.slice/' + fit.A145
    authority = Path('/var/lib/jetstreamer/horizon_runtime_data')
    package = authority / 'incident-replay-fit-20261121-v1/tools-homefloor-145-v5v-custody-recovery-v1'
    script = package / 'post-stop-fit'
    seal, _ = s.read(package / 'deployment-seal-receipt.json',
                     'd09996b143470c616b817301e3565a49a4c57c91cf1f8e09d16f63fb00243042')
    member, = (row for row in seal['members'] if row['name'] == script.name)
    fit.binary(script, member['sha256'])
    parents = {}
    for pid in members:
        try:
            ppid, _, actual_group = s.process(pid)
        except (FileNotFoundError, ProcessLookupError):
            s.need(pid not in fit.members(fit.A145), 'unstable epoch 145 census')
            continue
        s.need(actual_group == group, 'foreign epoch 145 census group')
        parents[pid] = ppid
    probes = []
    for pid, ppid in parents.items():
        if ppid != parent:
            continue
        proc = Path('/proc') / str(pid)
        try:
            argv = [os.fsdecode(item) for item in (proc / 'cmdline').read_bytes().split(b'\0') if item]
            if len(argv) == 6 and argv[2:4] == [str(script), '145']:
                fleet = Path(argv[4])
                python = Path('/usr/bin/python3')
                s.need((proc / 'exe').samefile(python) and Path(argv[0]).resolve() == python.resolve()
                       and argv[1] in ('-IB', '-BI') and fleet.parent.parent == authority
                       and fleet.name == 'ROOT_COMPLETE_OPERATIONAL_FLEET.json'
                       and re.fullmatch(r'[0-9a-f]{64}', argv[5]),
                       'foreign epoch 145 probe arguments')
                probes.append(pid)
        except (FileNotFoundError, ProcessLookupError):
            s.need(pid not in fit.members(fit.A145), 'unstable epoch 145 direct child')
    s.need(len(probes) <= 1, 'overlapping epoch 145 pricing probes')
    eligible = set(probes)
    while eligible:
        added = {pid for pid, ppid in parents.items() if pid not in eligible and ppid in eligible}
        if not added:
            break
        eligible |= added
    canonical = tuple(pid for pid in members if pid in parents and pid not in eligible)
    latest = set(fit.members(fit.A145))
    s.need(len(canonical) == 2 and parent in canonical
           and set(canonical) <= latest <= set(parents), 'foreign or changing epoch 145 process population')
    return canonical


def idle(s, fit, hourly, unit):
    fields = ('Id', 'LoadState', 'ActiveState', 'Job')
    if unit.endswith('.service'):
        fields += ('MainPID', 'ControlPID')
    state = hourly['properties'](unit, *fields)
    s.need(state['Id'] == unit and state['LoadState'] == 'not-found'
           and state['ActiveState'] == 'inactive' and not state['Job']
           and state.get('MainPID', '0') == state.get('ControlPID', '0') == '0' and not fit.members(unit),
           'occupied full epoch 170 startup unit')


def never_released(s, route, proc=None):
    root = route['ROOT']
    forbidden = [route['PERMIT'], root / 'AUTHORIZED_GATED_PAYLOAD.json',
                 root / 'ACTUAL_ADMISSION_AND_PROTECTION.json', root / 'FIRST_PROTECTED_WORKER.json']
    if proc is not None:
        forbidden.append(proc / 'root/run/horizon-epoch170-full-metered/barrier/allow')
    s.need(not any(path.exists() or path.is_symlink() for path in forbidden),
           'full epoch 170 already obtained a release or admission')


def prestart(s, fit, route, hourly):
    for unit in (route['UNIT'], route['TIMER'], route['TIMER'].removesuffix('.timer') + '.service'):
        idle(s, fit, hourly, unit)
    never_released(s, route)
    route['generation']()
    route['hold_image']()


def held(s, fit, route, ref, status):
    route['hold_image']()
    current = route['native'](ACTOR)
    s.need(current is not None, 'full epoch 170 is not held')
    unit, actor = current
    pid = actor['producer_pid']
    proc = Path('/proc') / str(pid)
    iid = actor['producer_invocation_id']
    s.need(unit['Id'] == route['UNIT'] and (proc / 'exe').samefile(route['HOLD'])
           and fit.members(route['UNIT']) == (pid,)
           and s.process(pid)[1:] == (actor['start_ticks'], '0::' + route['GROUP']),
           'full epoch 170 left its exact one-process hold')
    never_released(s, route, proc)
    intent, _, _ = route['intent']()
    review = route['checked'](intent['prepared'])
    price = route['checked'](review['price'])
    enroll = route['checked'](review['observer'])
    s.need(intent['fleet'] == ref and price['fleet'] == ref and enroll['fleet'] == ref
           and price['status_registration']['invocation_id'] == enroll['incumbent']['invocation_id']
           and status['invocation_id'] == enroll['incumbent']['invocation_id'],
           'full epoch 170 prestart and native capture use different fleet or cadence')
    exe = (proc / 'exe').stat()
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    intent_ref = route['bound'](route['ROOT'] / 'START_INTENT.json')
    return dict(actor, unit=route['UNIT'], processes=[[pid, actor['start_ticks'], exe.st_dev, exe.st_ino]],
                invocation_id=iid, boot_id=boot, start_intent=intent_ref, prestart=review['price'],
                observer_enrollment=review['observer'], armed_floor=intent['armed_floor'],
                prestart_physical_bytes=price['bookings']['170']['physical_bytes'])


def first_guard(s, route, hourly, actor):
    root = route['ROOT']
    guard_ref = route['bound'](root / 'FIRST_GUARD.json')
    proof = route['checked'](guard_ref)
    plan_ref = route['bound'](root / 'ACTUAL_GUARD_PLAN.json')
    plan = route['checked'](plan_ref)
    qual = route['generation']()[2]
    timer = route['TIMER']
    service = timer.removesuffix('.timer') + '.service'
    current = hourly['properties'](timer, *TIMER)
    s.need(current['Id'] == proof['timer']['Id'] == timer
           and current['ActiveState'] == proof['timer']['ActiveState'] == 'active'
           and current['InvocationID'] == proof['timer']['InvocationID']
           and current['SubState'] == 'waiting' and not current['Job'] and current['Triggers'] == service,
           'full epoch 170 first guard timer changed')
    s.need(plan['unit'] == route['UNIT'] and plan['invocation_id'] == actor['invocation_id']
           and plan['filesystem'] == '/home/sol' and plan['worker_root'] == str(route['LANE'])
           and plan['receipt_directory'] == str(root / 'guard-receipts')
           and plan['maximum_root_physical_bytes'] == route['CAP'] and plan['maximum_worker_vmas'] == 3_500_000
           and plan['minimum_free_bytes'] == actor['armed_floor']
           and plan['data_fulfillment'] == qual['contract'], 'different full epoch 170 guard plan')
    sample = route['actual_guard'](actor, proof, plan_ref)
    observed = sample['root_physical_observation']
    walks = [observed[side]['physical_bytes'] for side in ('first', 'second')]
    age = time.time() - sample['recorded_unix_seconds']
    s.need(sample['schema'] == 'jetstreamer-horizon-standalone-guard-sample-v1'
           and sample['plan'] == plan_ref['path']
           and sample['producer']['cgroup'] == route['GROUP']
           and sample['producer']['invocation_id'] == actor['invocation_id']
           and sample['minimum_free_bytes'] == plan['minimum_free_bytes']
           and sample['maximum_root_physical_bytes'] == observed['maximum_physical_bytes'] == route['CAP']
           and sample['maximum_worker_vmas'] == plan['maximum_worker_vmas']
           and all(0 < size <= route['CAP'] for size in walks)
           and observed['conservative_physical_bytes'] == max(walks)
           and 0 <= age <= MAX_AGE and not sample['workers']
           and not sample['r2_mutations'] and not sample['remote_mutations'] and not sample['scratch_deleted']
           and not sample['bounded_measurement'] and sample['bounded_canary'] is None,
           'stale, foreign, or released full epoch 170 first guard')
    exits = hourly['pid1'](service, proof['guard_invocation'], actor['boot_id'],
                           (hourly['SUCCESS'], hourly['FAILURE'], hourly['EXIT']))
    s.need(len(exits) == 1 and exits[0]['MESSAGE_ID'] == hourly['SUCCESS']
           and exits[0]['INVOCATION_ID'] == proof['guard_invocation']
           and exits[0]['UNIT'] == service and exits[0]['_PID'] == '1'
           and exits[0]['_BOOT_ID'] == actor['boot_id'].replace('-', '')
           and int(exits[0]['__REALTIME_TIMESTAMP']) // 1_000_000 >= sample['recorded_unix_seconds'],
           'full epoch 170 first guard lacks its exact PID 1 success')
    physical = min(walks) if all(observed[side]['vanished_entries'] == 0 for side in ('first', 'second')) else None
    return dict(first_guard=guard_ref, actual_guard_plan=plan_ref, receipt=proof['receipt'],
                timer_invocation_id=current['InvocationID'], guard_invocation_id=proof['guard_invocation'],
                physical_bytes=physical, available_bytes=sample['available_bytes'],
                recorded_unix_seconds=sample['recorded_unix_seconds'])


def ownership(s, fit, route, hourly, mode, ref, status):
    if mode == 'prestart':
        prestart(s, fit, route, hourly)
        return None, None
    actor = held(s, fit, route, ref, status)
    if mode == 'held':
        idle(s, fit, hourly, route['TIMER'])
        idle(s, fit, hourly, route['TIMER'].removesuffix('.timer') + '.service')
        return actor, None
    s.need(mode == 'post-guard', 'unknown full epoch 170 capacity stage')
    return actor, first_guard(s, route, hourly, actor)


def price(s, route, native, mode, actor, guard, fleet_available):
    book = native['bookings']['170']
    s.need(native['epoch'] == 145 and native['candidate'] is None
           and native['complete_cpu_quota_micros'] == CPU_MICROS
           and native['complete_memory_plus_reserve_bytes'] == MEMORY_WITH_RESERVE
           and native['resource_credit_bytes'] == 0 and native['replay_launch_authorized'] is False
           and native['bounded_qualification'] is None and '170' not in native['replacements']
           and native['failed_cold170']['terminal']['sha256'] == route['RETRY13_TERMINAL']
           and native['failed_cold170']['reservation_ending_bytes'] == 0
           and book['root'] == str(route['LANE'])
           and book['physical_bytes'] + book['remaining_bytes'] == book['cap_bytes'] == route['CAP'],
           'different full epoch 170 whole-fleet resource equation')
    if mode == 'prestart':
        return native
    # The existing capture already charges the 384 GiB tree once. Do not
    # reduce its remaining allowance for extra apparent growth in the hold.
    physical = min(book['physical_bytes'], actor['prestart_physical_bytes'])
    if guard and guard['physical_bytes'] is not None:
        physical = min(physical, guard['physical_bytes'])
    remaining = route['CAP'] - physical
    absolute = max(MIN_FLOOR, native['active168_guard_floor'],
                   native['candidate136'].get('guard_floor', 0),
                   *(peer['guard']['floor'] for peer in native['survivors'].values()),
                   *(peer['floor'] for peer in native['replacements'].values()))
    # Add back any lower physical estimate before removing this candidate's
    # share. Retain the armed guard floor even if the recomputation is lower.
    native_required = native['complete_required_HOME_bytes'] + (book['physical_bytes'] - physical)
    repriced = max(absolute, native_required - remaining)
    armed = actor['armed_floor']
    available = min(native['available_HOME_bytes'], guard['available_bytes']) if guard else native['available_HOME_bytes']
    required = max(native_required, armed + remaining)
    donor_required = native['epoch159_donor_cover']['native_home_required'] + (
        required - native['complete_required_HOME_bytes'])
    s.need(remaining > 0 and MIN_FLOOR <= repriced <= armed,
           'full epoch 170 post-start price exceeds the armed guard floor')
    result = dict(native, epoch=170, candidate=actor, available_HOME_bytes=available,
                  complete_required_HOME_bytes=required, protected_raw_floor_bytes=armed, fits=(
                      native['fits'] and available >= required and min(available, fleet_available) >= donor_required
                      and native['available_memory_bytes'] >= native['required_available_memory_bytes']))
    result['bookings'] = dict(native['bookings'], **{'170': dict(
        book, run=str(route['RUN']), physical_bytes=physical, remaining_bytes=remaining,
        measurement='retained prestart baseline and native whole-tree samples')})
    result['epoch170_metered_full'] = dict(
        stage=mode, producer_unit=actor['producer_unit'], producer_invocation_id=actor['invocation_id'],
        producer_pid=actor['producer_pid'], start_ticks=actor['start_ticks'], boot_id=actor['boot_id'],
        start_intent=actor['start_intent'], prestart=actor['prestart'],
        observer_enrollment=actor['observer_enrollment'], worker_sha256=route['WORKER_SHA'],
        first_guard=guard, resource_credit_bytes=0, candidate_repriced_floor_bytes=repriced,
        donor_required_HOME_bytes=donor_required,
        original_complete_required_home_bytes=native['complete_required_HOME_bytes'])
    return result
