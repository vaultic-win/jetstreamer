"""Follow the sealed epoch 168 retry from its held process through guarded replay."""
import os
from pathlib import Path
import re

from evidence import BASE, bound, checked, need
from owners import show, ticks

ROOT = BASE/'epoch168-retry2-rebook-20261122-v1'
GUARD = BASE/'epoch168-cold-guard-20261122-v2'
RUN = Path('/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/cold-retry2-20261122')
ALIAS = Path('/run/horizon-full168-cold-v2')
NAME = '168-full-metered-cold-v2-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
FIELD = 'current_homefloor_cold166_167_168_170_owners'
BINDING = Path(__file__).with_name('retry2-168-generation.json')
ANCHOR = dict(path=str(ROOT/'SUCCESSOR_ROOT.json'), sha256='ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc')
QUAL = dict(path=str(GUARD/'GUARD_QUALIFIED.json'), sha256='bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b')
STOP = '1fba7a686be4387737b8c7776a5ed92a59bff82c15ced77496e9214c94710f62'
WORKER_SHA = 'b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541'
NODE = '/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1/jetstreamer-node'
NODE_SHA = 'a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65'


RETRY3 = Path(__file__).with_name('retry3-168-generation.json').is_file()
PACKAGE = 'tools-cold168-retry3-v1' if RETRY3 else 'tools-cold168-retry2-v1'
ROOT_INODE, LOG_INODE = 103481350, 103481356
if RETRY3:
    ROOT = BASE/'epoch168-retry3-rebook-20261123-v1'
    GUARD = BASE/'epoch168-cold-guard-20261123-v3'
    RUN = RUN.with_name('cold-retry3-20261123')
    ALIAS = Path('/run/horizon-full168-cold-v3')
    NAME = '168-full-metered-cold-v3-20261123'
    UNIT = 'horizon-qualify-'+NAME+'.service'
    TIMER = 'horizon-guard-'+NAME+'.timer'
    ROOT_INODE, LOG_INODE = 103481378, 103481382
    BINDING = Path(__file__).with_name('retry3-168-generation.json')
    ANCHOR = dict(path=str(ROOT/'SUCCESSOR_ROOT.json'),sha256='a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4')
    FAILURE = dict(path=str(BASE/'epoch168-retry2-rebook-20261122-v1/RELEASED_NODE_STARTUP_FAILURE_20261123.json'),
                   sha256='a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643')
    QUAL = checked(bound(BINDING))['guard_qualification']
    need(QUAL['path']==str(GUARD/'GUARD_QUALIFIED.json'), 'different retry3 guard path')


def generation():
    binding = checked(bound(BINDING))
    prepared = bound(ROOT/'PREPARED.json')
    expected = dict(prepared=prepared, successor_root=ANCHOR, guard_qualification=QUAL)
    anchor, proof, reg = checked(ANCHOR), checked(QUAL), checked(prepared)
    if RETRY3:
        expected['failed_retry2'] = FAILURE
        failed = checked(FAILURE)
        need(anchor['previous_start_failure']==FAILURE and failed['permit_consumed']
             and failed['no_admission_record'] and failed['worker_receipt_absent'] and not failed['replay_claimed'],
             'different consumed retry2 generation')
    else:
        need(prepared['sha256']=='dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a',
             'different retry2 preparation')
    need(binding==expected,'foreign 168 generation')
    baseline, profile = reg['baseline'], reg['profile']
    need(reg['epoch'] == 168 and reg['schema'] == 'horizon-168-replay-recovery-preparation-v1'
         and reg['worker_sha256'] == WORKER_SHA and reg['node_sha256'] == NODE_SHA
         and reg['original_run_retained'] and not reg['replay_launch_authorized']
         and baseline['stable_roots'] == ANCHOR and baseline['predecessor_stop'] == anchor['prior_stop']
         and anchor['prior_stop']['sha256'] == STOP, 'different 168 preparation')
    root = RUN.lstat()
    need(RUN.resolve(strict=True) == RUN and (root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode)
         == (64512, ROOT_INODE, 1001, 1003, 0o40700) and anchor['root'] == str(RUN)
         and baseline['root'] == dict(path=str(RUN), device=root.st_dev, inode=root.st_ino),
         'different 168 run directory')
    log = (RUN/'producer.log').lstat()
    logreg = checked(bound(ROOT/'OBSERVER_LOG_PREPARED.json'))
    need(logreg['prepared'] == prepared and logreg['path'] == anchor['log']['path'] == str(RUN/'producer.log')
         and (logreg['device'], logreg['inode']) == (log.st_dev, log.st_ino) == (64512, LOG_INODE)
         and (log.st_uid, log.st_gid, log.st_mode, log.st_nlink) == (0, 0, 0o100600, 1), 'different 168 observer log')
    need(baseline['profile'] == profile and profile['producer_unit'] == UNIT and profile['guard_timer'] == TIMER
         and reg['payload'] == bound(ROOT/'COLD_PAYLOAD.json') and checked(reg['payload']) == profile['payload']
         and profile['payload']['members']['jetstreamer-node'] == [NODE, NODE_SHA]
         and proof['schema'] == ('horizon-168-cold-v3-native-guard-qualified-v1' if RETRY3 else 'horizon-168-cold-v2-native-guard-qualified-v1')
         and proof['guard'] == bound(GUARD/'tools/guard') and proof['guard']['sha256'] == profile['guard_binary_sha256']
         and proof['seal'] == bound(GUARD/'tools/deployment-seal-receipt.json'), 'different 168 inputs or guard')
    return prepared, baseline, proof


def same_actor(record, actor):
    return all(record.get(k) == v for k, v in actor.items())


def verify_process(proc, cgroup, actor, profile):
    args = profile['payload']['regular_node_argv']
    launch = profile['producer_argv']
    gate = ['/usr/bin/python3', '-IB', str(ALIAS/'gate.py')]
    actual = [os.fsdecode(v) for v in (proc/'cmdline').read_bytes().split(b'\0') if v]
    need(len(args) == 8 and args[0] == str(ALIAS/'jetstreamer-node') and launch[-11:] == gate + args
         and (proc/'fd/1').samefile(RUN/'producer.log'), 'different 168 command or append log')
    image = proc/'exe'
    held_path = ROOT/'ACTUAL_PRODUCER_NATIVE.json'
    node_path = ROOT/'NODE_AFTER_PERMIT.json'
    account = ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json'
    if image.samefile('/usr/bin/python3'):
        need(actual == gate + args and cgroup == [str(actor['producer_pid'])]
             and (proc/'root'/ALIAS.relative_to('/')/'gate.py').samefile(ROOT/'tools/gate.py')
             and (proc/'root'/ALIAS.relative_to('/')/'payload.json').samefile(ROOT/'COLD_PAYLOAD.json')
             and not node_path.exists() and not account.exists(), 'foreign held 168 process')
        if held_path.exists():
            held = checked(bound(held_path))
            st = image.stat()
            need(same_actor(held, actor) and held['stage'] == 'held'
                 and (held['exe_device'], held['exe_inode']) == (st.st_dev, st.st_ino), 'different held 168 actor')
        return
    held = checked(bound(held_path))
    authref = bound(ROOT/'AUTHORIZED_GATED_PAYLOAD.json')
    auth = checked(authref)
    gate_image = Path('/usr/bin/python3').stat()
    permit = ROOT/'barrier/allow'
    mode = permit.lstat()
    need(image.samefile(NODE) and actual == args and str(actor['producer_pid']) in cgroup
         and (proc/'root'/ALIAS.relative_to('/')/'jetstreamer-node').samefile(NODE)
         and held['stage'] == 'held' and same_actor(held, actor)
         and (held['exe_device'], held['exe_inode']) == (gate_image.st_dev, gate_image.st_ino)
         and all(auth[k] == actor[k] for k in ('producer_pid','producer_invocation_id','start_ticks'))
         and auth['first_guard'] == bound(ROOT/'FIRST_GUARD.json')
         and auth['actual_guard_plan'] == bound(ROOT/'ACTUAL_GUARD_PLAN.json')
         and auth['post_guard_capacity'] == bound(ROOT/'POST_GUARD_CAPACITY.json')
         and checked(auth['post_guard_capacity'])['fits'] is True
         and (mode.st_uid, mode.st_gid, mode.st_mode, mode.st_nlink) == (0, 0, 0o100444, 1)
         and permit.read_bytes() == actor['producer_invocation_id'].encode(), 'unfunded 168 node promotion')
    if node_path.exists() or account.exists():
        node = checked(bound(node_path))
        st = image.stat()
        need(node['authorization'] == authref and node['stage'] == 'node' and same_actor(node, actor)
             and (node['exe_device'], node['exe_inode']) == (st.st_dev, st.st_ino), 'different promoted 168 actor')


def native(properties):
    row = show(UNIT, properties)
    if row['ActiveState'] in ('inactive','failed') and row['MainPID'] == '0' and not row['Job']:
        return None
    need(row['Id'] == UNIT and row['ActiveState'] == 'active' and row['SubState'] == 'running' and not row['Job']
         and row['ControlGroup'] == '/system.slice/'+UNIT and row['NRestarts'] == '0' and row['MemorySwapMax'] == '0'
         and row['MemoryMax'] == str(68<<30) and row['CPUQuotaPerSecUSec'] == '9s'
         and re.fullmatch('[0-9a-f]{32}', row['InvocationID']), 'wrong 168 unit or booking')
    pid = int(row['MainPID'])
    proc = Path('/proc')/str(pid)
    actor = dict(producer_unit=UNIT, producer_invocation_id=row['InvocationID'], producer_pid=pid, start_ticks=ticks(pid))
    prepared, baseline, _ = generation()
    intent = checked(bound(ROOT/'START_INTENT.json'))
    need(intent['epoch'] == 168 and intent['producer_unit'] == UNIT and intent['timer_unit'] == TIMER
         and intent['prepared'] == prepared and intent['stable_root'] == baseline['root']
         and intent['predecessor_stop'] == baseline['predecessor_stop']
         and (proc/'cgroup').read_text().strip() == '0::'+row['ControlGroup'], 'unregistered 168 launch')
    group = Path('/sys/fs/cgroup')/row['ControlGroup'].lstrip('/')/'cgroup.procs'
    verify_process(proc, group.read_text().split(), actor, baseline['profile'])
    return row, actor


def check_generation(fleet_ref, fleet, state, event):
    _, actor = state
    prepared, baseline, _ = generation()
    intentref = bound(ROOT/'START_INTENT.json')
    intent = checked(intentref)
    stop = checked(checked(event)['reports']['168'])['guard_stop_completion']
    need(fleet['current_four_homefloor_stops'] == event and intent['prepared'] == prepared
         and intent['stable_root'] == baseline['root'] and intent['predecessor_stop'] == baseline['predecessor_stop'] == stop,
         'foreign 168 intent or stop')
    if (ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists():
        admitted = checked(bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json'))
        post = checked(bound(ROOT/'POST_GUARD_CAPACITY.json'))
        need(same_actor(admitted, actor) and admitted['stage'] == 'node' and admitted['source'] == prepared
             and admitted['intent'] == intentref and admitted['fleet'] == intent['fleet']
             and admitted['post_guard_capacity'] == bound(ROOT/'POST_GUARD_CAPACITY.json')
             and post['epoch'] == 168 and post['fits'] and post['bookings']['168']['cap_bytes'] == 288<<30
             and same_actor(post['candidate'], actor), 'unfunded or different 168 admission')
    target = intent['fleet']
    oldest = checked(target)['sampled_at_utc']
    while fleet_ref != target:
        fleet_ref = fleet['previous_Root_operational_review']
        prior = checked(fleet_ref)
        need(oldest <= prior['sampled_at_utc'] < fleet['sampled_at_utc'], '168 start from another fleet')
        fleet = prior


def projection(row):
    first = checked(bound(ROOT/'FIRST_PROTECTED_WORKER.json'))
    need(first['epoch'] == 168 and first['admission'] == bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and first['worker_sha256'] == WORKER_SHA and row == first['observer_row'] and row['range'] == '168'
         and row['producer_unit'] == row['controller_unit'] == UNIT and row['worker_executable_basename'] == 'historical-worker'
         and row['expected_producer_invocation_id'] == row['expected_controller_invocation_id'] == first['producer_invocation_id'],
         'foreign 168 worker row')


def census(owners, full, recovered):
    # The shared process census counts native nodes. The pre-admission Python
    # gate has its own single-process and executable checks.
    native_owners = recovered
    row = recovered.get('168')
    held = False
    if row and not row['admission']:
        proc = Path('/proc')/str(row['actor']['producer_pid'])
        held = (proc/'exe').samefile('/usr/bin/python3')
        if held:
            native_owners = {k:v for k,v in recovered.items() if k != '168'}
    owners.replay_census([], None, full=full, closed168_owner=True, metered_commit=True, restored=native_owners)
    if held:
        from cold167_status import reader
        current = native(reader().ACTOR)
        need(current and current[1] == row['actor'] and (proc/'exe').samefile('/usr/bin/python3'),
             '168 gate changed during fleet census')


def register(module):
    previous_native, previous_budget = module.native, module.guard_budget
    module.ROUTES[168] = (NAME, ROOT.name, RUN, ROOT_INODE, 288)
    module.FIELD = FIELD

    def actor(epoch):
        return native(module.ACTOR) if epoch == 168 else previous_native(epoch)

    def budget(epoch, root, plan, admission):
        if epoch != 168:
            return previous_budget(epoch, root, plan, admission)
        prepared, _, proof = generation()
        need(root == ROOT and admission['source'] == prepared and plan['maximum_root_physical_bytes'] == 288<<30
             and plan['data_fulfillment'] == proof['contract'], 'different 168 guard plan')
        return 288, proof['guard']['sha256'], proof

    module.native, module.guard_budget = actor, budget
