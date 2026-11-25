"""Follow the sealed epoch 168 retry from its held process through guarded replay."""
import os
from pathlib import Path
import re
import time

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


GENERATIONS = [n for n in (2, 3, 4, 5) if Path(__file__).with_name(f'retry{n}-168-generation.json').is_file()]
need(len(GENERATIONS)==1, 'missing or ambiguous 168 generation')
ATTEMPT, = GENERATIONS
PACKAGE = f'tools-cold168-retry{ATTEMPT}-v1'
ROOT_INODE, LOG_INODE = 103481350, 103481356
CAP_GIB = 512 if ATTEMPT == 5 else 288
RETRY4_IID = '913443d7f9f44d7e9d3e0eec420acfab'
RETRY4_STOP = {
    'path': str(BASE/'epoch168-retry4-rebook-20261123-v1/guard-receipts/stop-completion.json'),
    'sha256': 'b0538a4dee05df924a8d04f8562866df701c03996498963552a932059826cdab',
}
RETRY5_SOURCE = {
    'path': str(BASE/'incident-replay-fit-20261121-v1/STOPPED168_RETRY5_RETAINED_SOURCE_CONTROL_20261125.json'),
    'sha256': '488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2',
}
if ATTEMPT in (3, 4):
    ROOT = BASE/f'epoch168-retry{ATTEMPT}-rebook-20261123-v1'
    GUARD = BASE/f'epoch168-cold-guard-20261123-v{ATTEMPT}'
    RUN = RUN.with_name(f'cold-retry{ATTEMPT}-20261123')
    ALIAS = Path(f'/run/horizon-full168-cold-v{ATTEMPT}')
    NAME = f'168-full-metered-cold-v{ATTEMPT}-20261123'
    UNIT = 'horizon-qualify-'+NAME+'.service'
    TIMER = 'horizon-guard-'+NAME+'.timer'
    BINDING = Path(__file__).with_name(f'retry{ATTEMPT}-168-generation.json')
    if ATTEMPT == 3:
        ROOT_INODE, LOG_INODE = 103481378, 103481382
        anchor_sha='a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4'
        prior='epoch168-retry2-rebook-20261122-v1'
        failure_sha='a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643'
    else:
        ROOT_INODE, LOG_INODE = 103481722, 103481750
        anchor_sha='713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4'
        prior='epoch168-retry3-rebook-20261123-v1'
        failure_sha='cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21'
    ANCHOR = dict(path=str(ROOT/'SUCCESSOR_ROOT.json'),sha256=anchor_sha)
    FAILURE = dict(path=str(BASE/prior/'RELEASED_NODE_STARTUP_FAILURE_20261123.json'), sha256=failure_sha)
    QUAL = checked(bound(BINDING))['guard_qualification']
    need(QUAL['path']==str(GUARD/'GUARD_QUALIFIED.json'), 'different 168 guard path')
if ATTEMPT == 5:
    ROOT = BASE/'epoch168-retry5-rebook-20261125-v1'
    GUARD = BASE/'epoch168-cold-guard-20261125-v5'
    RUN = RUN.with_name('cold-retry5-20261125')
    ALIAS = Path('/run/horizon-full168-cold-v5')
    NAME = '168-full-metered-cold-v5-20261125'
    UNIT = 'horizon-qualify-'+NAME+'.service'
    TIMER = 'horizon-guard-'+NAME+'.timer'
    BINDING = Path(__file__).with_name('retry5-168-generation.json')
    ANCHOR = dict(path=str(ROOT/'SUCCESSOR_ROOT.json'),
                  sha256='4cd544fddda40cd81c94358b8c455feac24247b14f56e8fdb8ede2727c54af25')
    QUAL = dict(path=str(GUARD/'GUARD_QUALIFIED.json'),
                sha256='e237ca579a8921adaae0081ef71a82b35377e4ff80acaf8539c03cd68e3aa696')
    ROOT_INODE, LOG_INODE = 109396827, 109396830



def await_recovery(unit, pid):
    # A cold handoff after the clock fired must register the new lock owner
    # before the normal reader can resume the pending sample or publish a row.
    if ATTEMPT != 4:
        return
    receipts=BASE/'survivor172-cadence-20261122-v1'
    name='COLD168_RETRY4_V1_STATUS_'
    intent=receipts/(name+'INTENT.json')
    if not intent.exists():
        return
    issued=checked(bound(intent))
    if 'failed_incumbent' not in issued:
        return
    active=receipts/(name+'ACTIVE.json')
    end=time.monotonic()+90
    while not active.exists():
        need(time.monotonic()<end,'cold receiver lease was not registered')
        time.sleep(0.10)
    registered=checked(bound(active))
    actor=registered['new']
    need(registered['intent']==bound(intent) and registered['failed_incumbent']==issued['failed_incumbent']
         and actor['invocation_id']==unit['InvocationID'] and actor['pid']==pid and actor['start_ticks']==ticks(pid)
         and actor['program']==str(Path(__file__).with_name('status_cycle.py'))
         and actor['unit']==unit['Id'] and issued['schedule']==registered['schedule'],
         'unregistered recovery writer invocation')


def generation():
    binding = checked(bound(BINDING))
    prepared = bound(ROOT/'PREPARED.json')
    expected = dict(prepared=prepared, successor_root=ANCHOR, guard_qualification=QUAL)
    anchor, proof, reg = checked(ANCHOR), checked(QUAL), checked(prepared)
    if ATTEMPT in (3, 4):
        expected[f'failed_retry{ATTEMPT-1}'] = FAILURE
        failed = checked(FAILURE)
        need(anchor['previous_start_failure']==FAILURE and failed['permit_consumed']
             and failed['no_admission_record'] is (ATTEMPT==3) and failed['worker_receipt_absent'] and not failed['replay_claimed'],
             'different consumed 168 generation')
        if ATTEMPT == 4:
            admission=failed['receipts']['ACTUAL_ADMISSION_AND_PROTECTION.json']
            data=checked(admission)
            need(anchor['parent_immutable'] and not anchor['children_immutable']
                 and anchor['common_mount_fixture']['sha256']=='51b01c0110965a74db73e539dea68b0520f9e9b5ed02cb581f6a7f54be310704'
                 and failed['bootstrap_admission'] and not failed['worker_in_observed_guard_samples']
                 and admission['sha256']=='8dd692fda6b1098a22a2162792e7165005692385795e6cae72b6df472c7e83c0'
                 and data['producer_invocation_id']=='032cb7da1929485994cf18b384c93459' and data['producer_pid']==889002
                 and data['bootstrap_only'] and not data['transaction_replay_claimed'], 'different admitted 168 predecessor')
    elif ATTEMPT == 5:
        expected['retained_source'] = RETRY5_SOURCE
        source = checked(RETRY5_SOURCE)
        stop = checked(RETRY4_STOP)
        need(source['stop']['terminal'] == RETRY4_STOP and stop['producer_invocation_id'] == RETRY4_IID
             and source['resource_credit_bytes'] == source['stop']['reservation_ending_bytes'] == 0
             and anchor['schema'] == 'horizon-epoch168-retry5-successor-root-v1'
             and anchor['source_control_sha256'] == RETRY5_SOURCE['sha256']
             and anchor['root_immutable'] is True and anchor['worker_launched'] is False
             and anchor['whole_tree_cap_bytes'] == CAP_GIB << 30
             and proof['physical_launch'] is False, 'different retry5 root, retained stop or guard')
        for ref in proof['contract'].values():
            checked(ref)
    else:
        need(prepared['sha256']=='dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a',
             'different retry2 preparation')
    need(binding==expected,'foreign 168 generation')
    baseline, profile = reg['baseline'], reg['profile']
    predecessor_stop = baseline['predecessor_stop']
    need(reg['epoch'] == 168 and reg['schema'] == 'horizon-168-replay-recovery-preparation-v1'
         and reg['worker_sha256'] == WORKER_SHA and reg['node_sha256'] == NODE_SHA
         and reg['original_run_retained'] and not reg['replay_launch_authorized']
         and baseline['stable_roots'] == ANCHOR
         and predecessor_stop['sha256'] == STOP
         and (ATTEMPT == 5 or predecessor_stop == anchor['prior_stop']), 'different 168 preparation')
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
         and proof['schema'] == f'horizon-168-cold-v{ATTEMPT}-native-guard-qualified-v1'
         and proof['guard'] == bound(GUARD/'tools/guard') and proof['guard']['sha256'] == profile['guard_binary_sha256']
         and proof['seal'] == bound(GUARD/'tools/deployment-seal-receipt.json'), 'different 168 inputs or guard')
    if ATTEMPT == 5:
        proposal = checked(anchor['candidate'])
        expected_profile = dict(proposal['profile'], guard_binary_sha256=proof['guard']['sha256'])
        need(profile == expected_profile and profile['payload_sha256'] == reg['payload']['sha256']
             and bound(ROOT/'tools/gate.py')['sha256'] == proposal['gated_producer_source']['sha256'],
             'different sealed retry5 proposal or gate')
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
         and re.fullmatch('[0-9a-f]{32}', row['InvocationID'])
         and (ATTEMPT != 5 or row['InvocationID'] not in ('0'*32, RETRY4_IID)), 'wrong 168 unit or booking')
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
             and post['epoch'] == 168 and post['fits'] and post['bookings']['168']['cap_bytes'] == CAP_GIB << 30
             and same_actor(post['candidate'], actor), 'unfunded or different 168 admission')
    target = intent['fleet']
    oldest = checked(target)['sampled_at_utc']
    if ATTEMPT == 5:
        proof = checked(RETRY5_SOURCE)['stop']
        need(fleet.get('cold168_retry4_root_physical_stop') == proof
             and checked(target).get('cold168_retry4_root_physical_stop') == proof,
             'retry5 launch dropped the retained retry4 stop')
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


def verify_retained_population(stopped, owner, live, scheduled):
    need(ATTEMPT == 5 and stopped == checked(RETRY5_SOURCE)['stop'],
         'retry5 lost its independent retained stop')
    if owner is None:
        need(not live and not scheduled, 'retry5 rows have no registered owner')
        return
    actor = owner['actor']
    iid = actor['producer_invocation_id']
    manager = owner['unit']
    need(actor['producer_unit'] == manager['Id'] == UNIT and iid == manager['InvocationID']
         and re.fullmatch('[0-9a-f]{32}', iid) and iid not in ('0'*32, RETRY4_IID)
         and actor['producer_pid'] == int(manager['MainPID']) > 1
         and actor['start_ticks'] > 0, 'different retained retry5 owner')
    if not owner['admission']:
        need(not owner['first_worker'] and not live and not scheduled, 'held retry5 claimed protected replay')
        return
    admission = owner['admission']
    need(admission == bound(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json')
         and same_actor(checked(admission), actor) and len(live) == 1
         and live[0]['admission'] == admission and live[0]['unit']['Id'] == UNIT
         and live[0]['unit']['InvocationID'] == iid and live[0]['start_ticks'] == actor['start_ticks'],
         'retry5 owner differs from its admitted fleet row')
    row = live[0]['observer_config']
    if owner['first_worker']:
        need(owner['first_worker'] == bound(ROOT/'FIRST_PROTECTED_WORKER.json')
             and row is not None and scheduled == [row], 'retry5 first worker differs from the sole clock')
        projection(row)
    else:
        need(row is None and not scheduled, 'retry5 was scheduled before first-worker protection')


def census(owners, full, recovered, entry_lease=None):
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
    entry = {"entry_lease": entry_lease} if entry_lease is not None else {}
    owners.replay_census([], None, full=full, closed168_owner=True, metered_commit=True,
                         restored=native_owners, **entry)
    if held:
        from cold167_status import reader
        current = native(reader().ACTOR)
        need(current and current[1] == row['actor'] and (proc/'exe').samefile('/usr/bin/python3'),
             '168 gate changed during fleet census')


def register(module):
    previous_native, previous_budget = module.native, module.guard_budget
    module.ROUTES[168] = (NAME, ROOT.name, RUN, ROOT_INODE, CAP_GIB)
    module.FIELD = FIELD

    def actor(epoch):
        return native(module.ACTOR) if epoch == 168 else previous_native(epoch)

    def budget(epoch, root, plan, admission):
        if epoch != 168:
            return previous_budget(epoch, root, plan, admission)
        prepared, _, proof = generation()
        need(root == ROOT and admission['source'] == prepared and plan['maximum_root_physical_bytes'] == CAP_GIB << 30
             and plan['data_fulfillment'] == proof['contract'], 'different 168 guard plan')
        return CAP_GIB, proof['guard']['sha256'], proof

    module.native, module.guard_budget = actor, budget
