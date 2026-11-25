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


def admission_basis(s, route):
    intent, _, _ = route['intent']()
    review = route['checked'](intent['prepared'])
    price = route['checked'](review['price'])
    book = price['bookings']['170']
    donor = price['epoch159_donor_cover']
    floor = price['protected_raw_floor_bytes']
    context = price['epoch170_metered_full']
    protected_basis = max(donor['native_home_required'],
                          context['zero_remaining_donor_floor_bytes'] + book['remaining_bytes'])
    extra = price['complete_required_HOME_bytes'] - protected_basis
    s.need(price['complete_required_HOME_bytes'] == floor + book['remaining_bytes']
           and book['physical_bytes'] + book['remaining_bytes'] == route['CAP']
           and 0 <= extra <= donor['remaining_home_bytes']
           and context.get('additional_reservation_bytes') == extra
           and context.get('donor_required_HOME_bytes') == protected_basis,
           'full epoch 170 prestart omitted the protected donor floor')
    return intent, review, price


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
    intent, review, price = admission_basis(s, route)
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


def current_guard(s, route, hourly, actor, record, first):
    root = route['ROOT']
    plan_ref = route['bound'](root / 'ACTUAL_GUARD_PLAN.json')
    plan = route['checked'](plan_ref)
    timer = route['TIMER']
    service = timer.removesuffix('.timer') + '.service'
    current = hourly['properties'](timer, *TIMER)
    expected = actor['post_guard']['epoch170_metered_full']['first_guard']
    s.need(current['Id'] == timer and current['ActiveState'] == 'active'
           and current['SubState'] == 'waiting' and not current['Job'] and current['Triggers'] == service
           and current['InvocationID'] == expected['timer_invocation_id']
           and expected['actual_guard_plan'] == plan_ref
           and (record['admission'] is None or route['checked'](record['admission'])['timer_invocation_id']
                == current['InvocationID']), 'changed active epoch 170 guard timer or plan')
    directory = root / 'guard-receipts'
    paths = sorted(directory.glob('sample-*.json'), key=lambda path: path.stat().st_mtime_ns, reverse=True)
    for path in paths[:4]:
        receipt = route['bound'](path)
        iid = path.name.removeprefix('sample-').removesuffix('.json')
        s.need(re.fullmatch(r'[a-f0-9]{32}', iid), 'foreign active epoch 170 sample name')
        guard = {'receipt': receipt, 'guard_invocation': iid, 'timer': current}
        sample = route['actual_guard'](actor, guard, plan_ref)
        expected_workers = [p[0] for p in actor['processes'][1:]]
        seen_workers = sample['workers']
        if [w[0] for w in seen_workers] != expected_workers:
            continue
        s.need(all(0 < w[1] <= plan['maximum_worker_vmas'] for w in seen_workers),
               'active epoch 170 worker exceeds its native VMA ceiling')
        observed = sample['root_physical_observation']
        walks = [observed[side]['physical_bytes'] for side in ('first', 'second')]
        capture = sample['recorded_unix_seconds']
        s.need(sample['schema'] == 'jetstreamer-horizon-standalone-guard-sample-v1'
               and sample['plan'] == plan_ref['path'] and sample['producer']['cgroup'] == route['GROUP']
               and sample['producer']['invocation_id'] == actor['invocation_id']
               and sample['minimum_free_bytes'] == plan['minimum_free_bytes'] == actor['armed_floor']
               and sample['maximum_root_physical_bytes'] == observed['maximum_physical_bytes'] == route['CAP']
               and sample['maximum_worker_vmas'] == plan['maximum_worker_vmas']
               and observed['conservative_physical_bytes'] == max(walks)
               and all(0 < size <= route['CAP'] for size in walks)
               and 0 <= time.time() - capture <= MAX_AGE
               and not sample['r2_mutations'] and not sample['remote_mutations'] and not sample['scratch_deleted']
               and not sample['bounded_measurement'] and sample['bounded_canary'] is None,
               'stale, tripped or foreign active epoch 170 guard')
        events = hourly['pid1'](service, iid, actor['boot_id'], (hourly['SUCCESS'], hourly['FAILURE'], hourly['EXIT']))
        if not events:
            continue
        event, = events
        s.need(event['MESSAGE_ID'] == hourly['SUCCESS'] and event['INVOCATION_ID'] == iid
               and event['UNIT'] == service and event['_PID'] == '1'
               and event['_BOOT_ID'] == actor['boot_id'].replace('-', '')
               and int(event['__REALTIME_TIMESTAMP']) // 1_000_000 >= capture,
               'active epoch 170 lacks exact PID 1 guard success')
        if first:
            original = route['actual_guard'](actor, first['worker_guard'], plan_ref)
            s.need(original['workers'][0][0] == first['worker_pid'] and capture >= original['recorded_unix_seconds']
                   and first['worker_guard']['timer']['InvocationID'] == current['InvocationID'],
                   'active epoch 170 guard lacks the first protected worker')
        if any(observed[side]['vanished_entries'] for side in ('first', 'second')):
            continue
        return dict(actual_guard_plan=plan_ref, receipt=receipt, timer_invocation_id=current['InvocationID'],
                    guard_invocation_id=iid, physical_bytes=min(walks), available_bytes=sample['available_bytes'],
                    recorded_unix_seconds=capture)
    raise ValueError('no completed active epoch 170 guard for the current worker')


def active(s, fit, route, hourly, ref, status, fleet):
    require_v6(s, status)
    intent, review, price = admission_basis(s, route)
    route['check_lineage'](ref, fleet)
    state = route['native'](ACTOR)
    s.need(state is not None, 'missing active full epoch 170 producer')
    unit, actor = state
    s.need(not route['held']({'actor': actor}), 'active epoch 170 still holds the startup payload')
    record = route['ownership'](fleet, state)
    root = route['ROOT']
    post_ref = route['bound'](root / 'POST_GUARD_CAPACITY.json')
    post = route['checked'](post_ref)
    launch = post['epoch170_metered_full']
    iid = actor['producer_invocation_id']
    pid = actor['producer_pid']
    s.need(launch['stage'] == 'post-guard' and launch['start_intent'] == route['bound'](root / 'START_INTENT.json')
           and post['protected_raw_floor_bytes'] == intent['armed_floor']
           and post['complete_required_HOME_bytes'] == intent['armed_floor'] + post['bookings']['170']['remaining_bytes']
           and launch['prestart'] == review['price'] and launch['producer_invocation_id'] == iid
           and launch['producer_pid'] == pid and launch['start_ticks'] == actor['start_ticks'],
           'active epoch 170 release lacks the protected launch quote')
    members = fit.members(route['UNIT'])
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    s.need(launch['boot_id'] == boot and len(members) in (1, 2) and pid in members,
           'foreign active epoch 170 process population')
    executable = (Path('/proc') / str(pid) / 'exe').stat()
    processes = [[pid, actor['start_ticks'], executable.st_dev, executable.st_ino]]
    first = route['checked'](record['first_worker']) if record['first_worker'] else None
    if len(members) == 2:
        s.need(first is not None, 'active epoch 170 worker awaits first protected receipt')
        worker = next(child for child in members if child != pid)
        pp, ticks, group = s.process(worker)
        worker_exe = Path('/proc') / str(worker) / 'exe'
        m = worker_exe.stat()
        with worker_exe.open('rb') as image:
            import hashlib
            digest = hashlib.file_digest(image, 'sha256').hexdigest()
            s.need(os.path.samestat(m, os.fstat(image.fileno())), 'active epoch 170 worker image changed')
        s.need((pp, ticks, group) == (pid, first['worker_start_ticks'], '0::' + route['GROUP'])
               and worker == first['worker_pid']
               and (m.st_dev, m.st_ino) == (first['worker_exe_device'], first['worker_exe_inode'])
               and digest == route['WORKER_SHA']
               and worker_exe.readlink().is_relative_to(Path(first['observer_row']['scratch_path'])),
               'foreign active epoch 170 worker identity')
        processes.append([worker, ticks, m.st_dev, m.st_ino])
    else:
        s.need(first is None, 'active epoch 170 lost its protected worker')
    rows = [row for key in ('actual_executing_replays', 'actual_active_bootstraps',
                            'actual_active_private_diagnostics') for row in fleet[key] if row['epoch'] == 170]
    entry = rows[0] if len(rows) == 1 else None
    s.need((not rows and ref == intent['fleet']) or
           (entry is not None and record['admission'] is not None and entry['admission'] == record['admission']
            and entry['unit']['Id'] == route['UNIT'] and entry['unit']['InvocationID'] == iid
            and int(entry['unit']['MainPID']) == pid and entry['start_ticks'] == actor['start_ticks']),
           'active epoch 170 belongs to another fleet generation')
    s.need(fit.members(route['UNIT']) == members and route['native'](ACTOR) == (unit, actor),
           'active epoch 170 actor changed during collection')
    full = dict(actor, unit=route['UNIT'], processes=processes, invocation_id=iid, boot_id=boot,
                start_intent=launch['start_intent'], prestart=review['price'],
                observer_enrollment=review['observer'], armed_floor=intent['armed_floor'],
                prestart_physical_bytes=price['bookings']['170']['physical_bytes'],
                post_guard=post, post_guard_capacity=post_ref, admission=record['admission'])
    return full, current_guard(s, route, hourly, full, record, first)


def drained145(s, fit, root):
    fields = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'MainPID', 'ControlPID',
              'InvocationID', 'ControlGroup', 'Job')
    manager = s.show(fit.A145)
    prior = '97bd2045ebe449e3ae77330c7e4ec7b4'
    family = root / 'epoch145-semantic-continuity-20261121-v1'
    alternatives = [generation for generation in ('v5x', 'v5z')
                    if (family / f'{generation}-name-handoff/SEMANTIC_COMPLETION.json').is_file()]
    s.need(len(alternatives) <= 1, 'multiple epoch 145 successor completion claims')
    generation = alternatives[0] if alternatives else 'v5w'
    successor_generation = bool(alternatives)
    cgroup = Path('/sys/fs/cgroup/system.slice') / fit.A145
    s.need(manager['Id'] == fit.A145 and manager['ActiveState'] == 'inactive'
           and manager['SubState'] == 'dead' and manager['LoadState'] in ('loaded', 'not-found')
           and manager.get('Result', 'success') == 'success'
           and manager['MainPID'] == manager['ControlPID'] == '0'
           and (successor_generation or manager['InvocationID'] in ('', prior)) and not manager['ControlGroup']
           and not manager['Job'] and not fit.members(fit.A145) and not cgroup.exists(),
           'epoch 145 semantic owner has not drained')
    if generation == 'v5z':
        # The sealed build provider already runs the exact V5z completion
        # reader. Epoch 170 does not consume the later archive delivery binary.
        package = root / 'incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5z-build-v1'
    else:
        package = family / {'v5w': 'tools-v13o', 'v5x': 'tools-v13p'}[generation]
    checker = package / 'incident-post-phase.py'
    seal, seal_ref = s.read(package / 'deployment-seal-receipt.json',
                            None if successor_generation else '5e297cce79ec8adb123ae4eb43f5f98a582cb469397db92de399fef262508ee3')
    entry, = (m for m in seal['members'] if m['name'] == checker.name and m['mode'] == '0444')
    s.need(seal['destination'] == str(package) and (
           successor_generation or entry['sha256'] == 'c5cce42fce69856c5f0be82d4bc0a622889ab18c48e587e724430024bfa74a9a'),
           'foreign epoch 145 semantic completion checker')
    if successor_generation:
        s.need(seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1'
               and seal['sealer_sha256'] == 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'
               and seal['remote_mutations'] is seal['r2_mutations'] is False,
               f'foreign {generation} semantic checker seal')
    fit.binary(checker, entry['sha256'])
    import runpy
    readers = runpy.run_path(str(checker))
    if generation == 'v5z':
        s.need(readers['V5Z_POST'], 'the sealed adapter does not read V5z completion')
    complete, _ = readers['v5x_completion' if successor_generation else 'v5w_completion'](s)
    if successor_generation:
        successor = Path(complete['path']).parent.name
        s.need(s.iid(successor) and successor != prior and manager['InvocationID'] in ('', successor)
               and Path(complete['path']) == root / 'epoch145-guarded-export-20261121-v1/state' / successor / 'complete.json',
               f'different successful {generation} manager')
        prior = successor
    observed = s.show(fit.A145)
    s.need(all(manager.get(key) == observed.get(key) for key in fields)
           and not fit.members(fit.A145) and not cgroup.exists(),
           'epoch 145 changed during the semantic handoff')
    return dict(Id=fit.A145, MainPID='0', stage=f'{generation}-semantic-complete-drained',
                completed_invocation_id=prior, completion=complete, checker_seal=seal_ref)


def require_v6(s, status):
    provider = '/var/lib/jetstreamer/horizon_runtime_data/survivor172-cadence-20261122-v1'
    package = 'tools-cold168-retry4-failed166-v6-entry146'
    holding = f'{provider}/tools-cold168-retry4-failed166-v7-entry146/deployment-seal-receipt.json'
    s.need(status['consumer_seal']['path'] == f'{provider}/{package}/deployment-seal-receipt.json'
           or status['consumer_seal'] == dict(path=holding, sha256='c1b777be3164beca0db8afc9777a02bbbd8f7babc09acf063acb00297cd51504'),
           'full epoch 170 requires the registered v6 receiver or its qualified holding successor')


def ownership(s, fit, route, hourly, mode, ref, status, fleet):
    if mode == 'prestart':
        prestart(s, fit, route, hourly)
        return None, None
    if mode == 'active':
        return active(s, fit, route, hourly, ref, status, fleet)
    require_v6(s, status)
    actor = held(s, fit, route, ref, status)
    if mode == 'held':
        idle(s, fit, hourly, route['TIMER'])
        idle(s, fit, hourly, route['TIMER'].removesuffix('.timer') + '.service')
        return actor, None
    s.need(mode == 'post-guard', 'unknown full epoch 170 capacity stage')
    return actor, first_guard(s, route, hourly, actor)


def unchanged(s, mode, earlier, later):
    actor, guard = earlier
    current, newest = later
    if mode != 'active':
        s.need(earlier == later, 'full epoch 170 hold or first guard changed during price')
        return
    s.need(actor == current and all(guard[k] == newest[k] for k in ('actual_guard_plan', 'timer_invocation_id'))
           and newest['recorded_unix_seconds'] >= guard['recorded_unix_seconds']
           and 0 <= time.time() - guard['recorded_unix_seconds'] <= MAX_AGE,
           'active full epoch 170 process or guard generation changed during price')


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
    # The native active capture has already debited protected growth from
    # this prepaid booking. Startup uses the lower prestart and observed basis.
    physical = book['physical_bytes']
    if mode != 'active':
        physical = min(physical, actor['prestart_physical_bytes'])
        if guard and guard['physical_bytes'] is not None:
            physical = min(physical, guard['physical_bytes'])
    remaining = route['CAP'] - physical
    absolute = max(MIN_FLOOR, native['active168_guard_floor'],
                   native['candidate136'].get('guard_floor', 0),
                   *(peer['guard']['floor'] for peer in native['survivors'].values()),
                   *(peer['floor'] for peer in native['replacements'].values()))
    # The donor result includes the native complete requirement. The two
    # floors are alternatives protecting the same prepaid capacity.
    donor = native['epoch159_donor_cover']
    base_required = native['complete_required_HOME_bytes']
    zero_native = native['full170_zero_remaining_native_HOME_bytes']
    s.need(0 < zero_native <= base_required <= donor['native_home_required'], 'invalid native or donor floor')
    overhead = donor['native_home_required'] - base_required
    zero_donor = zero_native + overhead
    donor_required = max(donor['native_home_required'] + (book['physical_bytes'] - physical),
                         zero_donor + remaining)
    repriced = max(absolute, donor_required - remaining)
    armed = actor['armed_floor']
    available = min(native['available_HOME_bytes'], donor['native_home_available'], fleet_available)
    if guard:
        available = min(available, guard['available_bytes'])
    required = armed + remaining
    extra = required - donor_required
    s.need((remaining > 0 or mode == 'active' and remaining == 0) and MIN_FLOOR <= repriced <= armed,
           'full epoch 170 post-start price exceeds the armed guard floor')
    result = dict(native, epoch=170, candidate=actor, available_HOME_bytes=available,
                  complete_required_HOME_bytes=required, protected_raw_floor_bytes=armed, fits=(
                      native['fits'] and available >= required and 0 <= extra <= donor['remaining_home_bytes']
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
        donor_required_HOME_bytes=donor_required, zero_remaining_donor_floor_bytes=zero_donor,
        additional_reservation_bytes=extra,
        post_guard_capacity=actor.get('post_guard_capacity'),
        original_complete_required_home_bytes=native['complete_required_HOME_bytes'])
    return result
