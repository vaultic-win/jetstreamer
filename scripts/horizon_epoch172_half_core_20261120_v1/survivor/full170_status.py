"""Project the corrected epoch 170 into the existing guarded replay observer."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from evidence import BASE, bound, checked, need

PACKAGE = 'tools-cold168-retry4-failed166-v6-entry146'
if Path(__file__).resolve().parent.name in ('tools-cold168-retry4-failed166-v7-entry146',
                                           'tools-cold168-retry5-failed166-v13-entry146'):
    PACKAGE = Path(__file__).resolve().parent.name
ROOT = BASE / 'epoch170-full-metered-rebook-20261124-v1'
QUAL = BASE / 'epoch170-full-metered-guard-20261124-v1/GUARD_QUALIFIED.json'
LANE = Path('/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1')
NAME = '170-full-metered-20261124-v1'
RUN = LANE / 'replacement-local3retry7-20261110-v1/replacement-local3retry10-20261121-v1/full-metered-20261124-v1'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
GROUP = '/system.slice/' + UNIT
APPEND = RUN / 'producer.log'
HOLD = ROOT / 'tools-preflight-879447ca/preflight'
HOLD_ALIAS = Path('/run/horizon-epoch170-full-metered/preflight')
PAYLOAD_ALIAS = Path('/run/horizon-epoch170-full-metered/payload.json')
PERMIT = ROOT / 'barrier/allow'
NODE = Path('/usr/local/lib/jetstreamer/horizon-independent170-singleton-package-20261109-v1/jetstreamer-node')
WORKER_SHA = 'b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541'
NODE_SHA = 'a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65'
HOLD_SHA = 'f3a8557fd3b3f3681c1669fcd7dc714e09a7266348200e5784ccf7f06e684b24'
HOLD_SEAL = '2a4ab5d56a9f5b8328050b6d0bb218bdc04eacc125c1e63d0b1ff76e73850842'
QUAL_SHA = 'f19c5936d20b1d0942deac0305b64bd1f56aa9d6cb4d840f556ecb68f2a52d5a'
ROOT_SHA = 'a1659d7a938785e30dbf792663ea0a3db9e14bdcfffa9bfdd90a4d423fc2224b'
RETRY13_TERMINAL = '16664fda43d296d115858ff67a173d6d0cccb5f2ac90d446aa797da34a2f6c9d'
DIAGNOSTIC = 'horizon-qualify-170-metered-hourly-20261124-v1.service'
FIELD = 'current_cold170_full_metered_held'
CAP = 384 << 30


def ref(path, digest):
    return dict(path=str(path), sha256=digest)


def pinned(path, digest):
    return checked(ref(path, digest))


def identity(path):
    m = path.lstat()
    return dict(path=str(path), device=m.st_dev, inode=m.st_ino), m


def generation():
    anchor = ref(ROOT / 'SUCCESSOR_ROOT.json', ROOT_SHA)
    root = checked(anchor)
    run, m = identity(RUN)
    need(root['schema'] == 'horizon-epoch170-metered-successor-root-v1'
         and root['root'] == str(RUN) and root['device'] == run['device'] and root['inode'] == run['inode']
         and root['retained_retry13_terminal_sha256'] == RETRY13_TERMINAL
         and RUN.resolve(strict=True) == RUN
         and (m.st_uid, m.st_gid, m.st_mode) == (1001, 1003, stat.S_IFDIR | 0o700),
         'changed metered epoch 170 run root')
    qualification = pinned(QUAL, QUAL_SHA)
    need(qualification['schema'] == 'horizon-170-full-metered-native-guard-qualified-v1'
         and qualification['physical_launch'] is False, 'changed metered 170 guard qualification')
    return anchor, run, qualification


def hold_image():
    seal = pinned(HOLD.with_name('deployment-seal-receipt.json'), HOLD_SEAL)
    entry, = (row for row in seal['members'] if row['name'] == HOLD.name)
    need(seal['destination'] == str(HOLD.parent) and entry['mode'] == '0555'
         and entry['sha256'] == HOLD_SHA and bound(HOLD) == ref(HOLD, HOLD_SHA),
         'changed metered 170 hold image')


def intent():
    anchor, run, _ = generation()
    start = checked(bound(ROOT / 'START_INTENT.json'))
    review = checked(start['prepared'])
    pre = checked(review['price'])
    profile = review['profile']
    enroll_ref = review['observer']
    enroll = checked(enroll_ref)
    candidate = enroll['candidate']
    active_fleet = start['fleet']
    fleet_sha = active_fleet['sha256']
    price = pre['epoch170_metered_full']
    book = pre['bookings']['170']
    need(start['epoch'] == 170 and start['producer_unit'] == UNIT and start['timer_unit'] == TIMER
         and start['stable_root'] in (anchor, run) and start['resource_credit_bytes'] == 0
         and start['predecessor_stop']['sha256'] == 'd670ce226f7ee5e24660dbd99b2d8174d72cd38f39487d10b17bcc4c0a85d50a'
         and review['schema'] == 'horizon-epoch170-metered-preflight-review-v1'
         and review['replay_launch_authorized'] is False and review['archive_publication_authorized'] is False
         and review['guard']['root'] == anchor and review['guard']['qualification'] == ref(QUAL, QUAL_SHA)
         and profile['actor']['run'] == str(RUN) and profile['actor']['unit'] == UNIT
         and profile['source']['node']['reference'] == ref(NODE, NODE_SHA)
         and profile['source']['worker']['reference']['sha256'] == WORKER_SHA
         and profile['previous']['terminal']['sha256'] == RETRY13_TERMINAL,
         'unbound metered 170 start or source')
    need(enroll_ref['path'] == str(ROOT / f'OBSERVER_ENROLLMENT-{fleet_sha}.json')
         and enroll['schema'] == 'horizon-epoch170-metered-observer-enrollment-v1'
         and enroll['fleet'] == active_fleet and enroll['prospective_only'] is True and enroll['activation_granted'] is False
         and enroll['candidate_root'] == anchor and enroll['guard_qualification'] == review['guard']['qualification']
         and candidate['producer_unit'] == UNIT and candidate['guard_timer'] == TIMER
         and candidate['append_log'] == str(APPEND) and candidate['worker_sha256'] == WORKER_SHA,
         'foreign metered 170 enrollment')
    need(pre['epoch'] == 170 and pre['fleet'] == active_fleet and pre['fits'] is True
         and pre['resource_credit_bytes'] == 0 and pre['replay_launch_authorized'] is False
         and start['prestart'] in (pre, review['price'])
         and start['armed_floor'] == pre['protected_raw_floor_bytes']
         and book['root'] == str(LANE) and book['run'] == str(RUN) and book['cap_bytes'] == CAP
         and price['stage'] == 'prestart' and price['observer_enrollment'] == enroll_ref
         and price['candidate_root'] == anchor and price['worker_sha256'] == WORKER_SHA
         and price['retained_retry13_terminal'] == profile['previous']['terminal']
         and price['reassigned_prepaid_bookings'] == 1,
         'foreign metered 170 prestart quote')
    return start, profile, candidate


def append_identity(candidate, proc=None):
    log, m = identity(APPEND)
    need((m.st_uid, m.st_gid, m.st_mode, m.st_nlink) == (0, 0, stat.S_IFREG | 0o600, 1)
         and (log['device'], log['inode']) == (candidate['log_device'], candidate['log_inode']),
         'different metered 170 append log')
    if proc is not None:
        for fd in ('1', '2'):
            information = dict(line.split(':', 1) for line in (proc / 'fdinfo' / fd).read_text().splitlines())
            need((proc / 'fd' / fd).samefile(APPEND) and int(information['flags'], 8) & os.O_APPEND,
                 'metered 170 producer does not hold the enrolled append log')
    return log


def actual_guard(actor, guard, plan_ref):
    sample_ref = guard['receipt']
    sample = checked(sample_ref)
    need(sample_ref['path'] == str(ROOT / 'guard-receipts' / f"sample-{guard['guard_invocation']}.json")
         and sample['guard_invocation_id'] == guard['guard_invocation']
         and sample['guard_sha256'] == pinned(QUAL, QUAL_SHA)['guard']['sha256']
         and sample['plan_sha256'] == plan_ref['sha256']
         and sample['producer_invocation_id'] == actor['producer_invocation_id']
         and sample['producer']['pid'] == actor['producer_pid']
         and sample['producer']['active'] == 'active'
         and sample['producer_stop_enabled'] is True and sample['trip_reason'] is None
         and sample['DATA_fulfillment'] and sample['DATA_fulfillment_observation_error'] is None
         and sample['worker_observation_error'] is None
         and sample['root_physical_observation_error'] is None
         and sample['root_physical_observation']['exceeds_budget'] is False,
         'foreign or tripped metered 170 guard evidence')
    return sample


def authorized(actor, start, proc):
    authorization = checked(bound(ROOT / 'AUTHORIZED_GATED_PAYLOAD.json'))
    plan_ref = bound(ROOT / 'ACTUAL_GUARD_PLAN.json')
    first_ref = bound(ROOT / 'FIRST_GUARD.json')
    post_ref = bound(ROOT / 'POST_GUARD_CAPACITY.json')
    plan, first, post = (checked(reference) for reference in (plan_ref, first_ref, post_ref))
    book, current = post['bookings']['170'], post['candidate']
    actor_id = actor['producer_invocation_id']
    need(all(authorization[key] == value for key, value in actor.items())
         and authorization['intent'] == bound(ROOT / 'START_INTENT.json')
         and authorization['actual_guard_plan'] == plan_ref
         and authorization['first_guard'] == first_ref and authorization['post_guard_capacity'] == post_ref
         and plan['invocation_id'] == actor_id and plan['unit'] == UNIT
         and plan['minimum_free_bytes'] == start['armed_floor']
         and plan['receipt_directory'] == str(ROOT / 'guard-receipts') and plan['worker_root'] == str(LANE)
         and plan['maximum_root_physical_bytes'] == CAP
         and plan['data_fulfillment'] == pinned(QUAL, QUAL_SHA)['contract']
         and first['timer']['Id'] == TIMER and first['timer']['ActiveState'] == 'active'
         and post['epoch'] == 170 and post['fits'] is True and post['fleet'] == start['fleet']
         and post['resource_credit_bytes'] == 0 and post['replay_launch_authorized'] is False
         and current['producer_invocation_id'] == actor_id and current['producer_pid'] == actor['producer_pid']
         and book['cap_bytes'] == CAP and book['run'] == str(RUN) and book['root'] == str(LANE),
         'missing metered 170 invocation-bound guard release or capacity')
    actual_guard(actor, first, plan_ref)
    _, m = identity(PERMIT)
    projected = proc / 'root' / PAYLOAD_ALIAS.parent.relative_to('/') / 'barrier/allow'
    need((m.st_uid, m.st_gid, m.st_mode, m.st_nlink) == (0, 0, stat.S_IFREG | 0o444, 1)
         and projected.samefile(PERMIT) and PERMIT.read_bytes() == actor_id.encode(),
         'different metered 170 release inode or invocation')
    return first


def projected_payload(path, expected):
    with path.open('rb') as fd:
        m = os.fstat(fd.fileno())
        raw = fd.read(1 << 20)
        need((m.st_uid, m.st_gid, m.st_mode, m.st_nlink) == (0, 0, stat.S_IFREG | 0o444, 1)
             and m.st_size == len(raw) and hashlib.sha256(raw).hexdigest() == expected,
             'changed metered 170 projected payload')
    return json.loads(raw)


def native(properties):
    from owners import show, ticks

    row = show(UNIT, properties)
    if row['ActiveState'] == 'inactive' and row['MainPID'] == '0' and not row['Job']:
        return None
    iid = row['InvocationID']
    need(row['Id'] == UNIT and row['ActiveState'] == 'active' and row['SubState'] == 'running'
         and row['NRestarts'] == '0' and not row['Job'] and row['ControlGroup'] == GROUP
         and row['MemoryMax'] == str(68 << 30) and row['CPUQuotaPerSecUSec'] == '9s'
         and row['MemorySwapMax'] == '0' and re.fullmatch(r'[0-9a-f]{32}', iid) and int(iid, 16),
         'unknown metered 170 service state')
    pid = int(row['MainPID'])
    proc = Path('/proc') / str(pid)
    actor = dict(producer_unit=UNIT, producer_invocation_id=iid, producer_pid=pid, start_ticks=ticks(pid))
    start, profile, candidate = intent()
    append_identity(candidate, proc)
    hold_image()
    image = proc / 'exe'
    argv = [os.fsdecode(entry) for entry in (proc / 'cmdline').read_bytes().split(b'\0') if entry]
    need((proc / 'cgroup').read_text().strip() == '0::' + GROUP, 'foreign metered 170 cgroup')
    if image.samefile(HOLD):
        payload = proc / 'root' / PAYLOAD_ALIAS.relative_to('/')
        need(len(argv) == 3 and argv[0] in (str(HOLD), str(HOLD_ALIAS))
             and argv[1] == 'hold' and re.fullmatch(r'[0-9a-f]{64}', argv[2])
             and projected_payload(payload, argv[2]) == profile
             and (Path('/sys/fs/cgroup') / GROUP.lstrip('/') / 'cgroup.procs').read_text().split() == [str(pid)]
             and not (ROOT / 'ACTUAL_ADMISSION_AND_PROTECTION.json').exists()
             and not (ROOT / 'FIRST_PROTECTED_WORKER.json').exists(),
             'foreign metered 170 hold, payload or process population')
        return row, actor
    args = profile['actor']['producer_argv_after_protection']
    source = profile['source']['node']
    with (proc / 'exe').open('rb') as node:
        m = os.fstat(node.fileno())
        need(image.samefile(NODE) and argv == args[args.index(str(NODE)):]
             and (m.st_dev, m.st_ino, m.st_size) == (source['device'], source['inode'], source['bytes'])
             and (m.st_uid, m.st_gid, m.st_mode, m.st_nlink) == (0, 0, stat.S_IFREG | 0o555, 1)
             and hashlib.file_digest(node, 'sha256').hexdigest() == NODE_SHA, 'foreign metered 170 node')
    authorized(actor, start, proc)
    return row, actor


def held(entry):
    return entry is not None and (Path('/proc') / str(entry['actor']['producer_pid']) / 'exe').samefile(HOLD)


def projection(row, actor=None):
    first = checked(bound(ROOT / 'FIRST_PROTECTED_WORKER.json'))
    _, _, candidate = intent()
    iid = first['producer_invocation_id']
    need(row == first['observer_row'] and first['admission'] == bound(ROOT / 'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and first['epoch'] == 170 and first['producer_unit'] == UNIT and first['worker_sha256'] == WORKER_SHA
         and (actor is None or all(first[key] == value for key, value in actor.items()))
         and row is not None and row['range'] == '170' and row['producer_unit'] == row['controller_unit'] == UNIT
         and row['expected_producer_invocation_id'] == row['expected_controller_invocation_id'] == iid
         and row['append_log'] == append_identity(candidate)
         and Path(row['scratch_path']).is_relative_to(RUN / 'private')
         and row['worker_executable_basename'] == 'historical-worker', 'different metered 170 worker projection')


def check_lineage(fleet_ref, fleet):
    start, _, _ = intent()
    target = start['fleet']
    oldest = checked(target)['sampled_at_utc']
    while fleet_ref != target:
        fleet_ref = fleet['previous_Root_operational_review']
        prior = checked(fleet_ref)
        need(oldest <= prior['sampled_at_utc'] < fleet['sampled_at_utc'],
             'metered 170 admission belongs to a different fleet')
        fleet = prior


def ownership(fleet, state):
    prior = fleet.get('current_homefloor_cold166_167_170_owners', {}).get('170')
    admission_path = ROOT / 'ACTUAL_ADMISSION_AND_PROTECTION.json'
    first_path = ROOT / 'FIRST_PROTECTED_WORKER.json'
    if state is None:
        need(not prior and not admission_path.exists() and not first_path.exists(),
             'metered 170 producer requires terminal reconciliation')
        return None
    unit, actor = state
    record = dict(unit=unit, actor=actor, admission=None, first_worker=None)
    if admission_path.exists():
        admission_ref = bound(admission_path)
        a = checked(admission_ref)
        start, _, _ = intent()
        need(a['epoch'] == 170 and all(a[key] == value for key, value in actor.items())
             and a['intent'] == bound(ROOT / 'START_INTENT.json') and a['fleet'] == start['fleet']
             and a['stable_root'] == start['stable_root'] and a['predecessor_stop'] == start['predecessor_stop']
             and a['source'] == start['prepared'] and a['resource_credit_bytes'] == 0
             and a['timer_unit'] == TIMER and a['bootstrap_only'] is True and a['transaction_replay_claimed'] is False
             and a['first_guard'] == bound(ROOT / 'FIRST_GUARD.json')
             and a['post_guard_capacity'] == bound(ROOT / 'POST_GUARD_CAPACITY.json')
             and a['actual_guard_plan'] == bound(ROOT / 'ACTUAL_GUARD_PLAN.json')
             and checked(a['first_guard'])['timer']['InvocationID'] == a['timer_invocation_id'],
             'foreign metered 170 admission')
        record['admission'] = admission_ref
        if first_path.exists():
            record['first_worker'] = bound(first_path)
            first = checked(record['first_worker'])
            need(first['worker_pid'] > 1 and first['worker_start_ticks'] > actor['start_ticks']
                 and first['worker_exe_device'] > 0 and first['worker_exe_inode'] > 0,
                 'invalid metered 170 protected worker identity')
            projection(first['observer_row'], actor)
    else:
        need(not first_path.exists(), 'metered 170 first worker lacks admission')
    if prior:
        need(prior['actor'] == actor and all(not prior[key] or prior[key] == record[key]
             for key in ('admission', 'first_worker')), 'metered 170 owner or admission changed')
    return record


def register(module):
    _, run, qualification = generation()
    module.ROUTES[170] = (NAME, ROOT.name, RUN, run['inode'], 384)
    original = module.native, module.guard_budget, module.observe_worker, module.ownership

    def actor(epoch):
        return native(module.ACTOR) if epoch == 170 else original[0](epoch)

    def guard_budget(epoch, root, plan, admission):
        if epoch != 170:
            return original[1](epoch, root, plan, admission)
        need(root == ROOT and plan['maximum_root_physical_bytes'] == CAP
             and plan['worker_root'] == str(LANE)
             and plan['data_fulfillment'] == qualification['contract'],
             'different metered 170 guard plan')
        return 384, qualification['guard']['sha256'], qualification

    def worker(epoch, owner, first, sample):
        if epoch != 170:
            return original[2](epoch, owner, first, sample)
        config = original[2](epoch, owner, first, sample)
        projection(config, owner)
        ad = checked(first['admission'])
        initial = actual_guard(owner, first['worker_guard'], ad['actual_guard_plan'])
        proc = Path('/proc') / str(first['worker_pid'])
        with (proc / 'exe').open('rb') as image:
            m = os.fstat(image.fileno())
            need((m.st_dev, m.st_ino) == (first['worker_exe_device'], first['worker_exe_inode'])
                 and hashlib.file_digest(image, 'sha256').hexdigest() == WORKER_SHA
                 and len(initial['workers']) == 1 and initial['workers'][0][0] == first['worker_pid']
                 and first['worker_guard']['timer']['InvocationID'] == ad['timer_invocation_id'],
                 'different first-protected metered 170 executable or guard')
        return config

    def owners(fleet):
        # The inherited route owns the retry13 publication and must never
        # interpret corrected receipts as belonging to that invocation.
        route = module.ROUTES.pop(170)
        try:
            records = original[3](fleet)
        finally:
            module.ROUTES[170] = route
        selected = ownership(fleet, actor(170))
        if selected is not None:
            records['170'] = selected
        return records

    module.native, module.guard_budget, module.observe_worker, module.ownership = actor, guard_budget, worker, owners


def historical_diagnostic(fleet):
    from owners import show

    row = next(item for item in fleet['epochs'] if item['epoch'] == 170)
    terminal = checked(row['private170_observation'])['observed']['terminal']
    before = terminal['manager']
    need(not any(item['epoch'] == 170 for item in fleet['actual_active_private_diagnostics'])
         and terminal['successful_exit'] is True and terminal['reservation_ending_bytes'] == 0
         and terminal['archive_publication_authorized'] is False
         and show(DIAGNOSTIC, tuple(before)) == before, 'metered 170 overlaps the diagnostic')
