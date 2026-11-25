"""Price the metered epoch 168 successor in its original paid tree."""
from copy import deepcopy
import hashlib
import json
import os
import re
import runpy
import stat
from pathlib import Path

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
RETRY5 = globals().get('RETRY5', False)
RETRY4 = globals().get('RETRY4',False) or RETRY5
RETRY3 = globals().get('RETRY3',False) or RETRY4
RETRY2_DIRECTORY = 'epoch168-retry2-rebook-20261122-v1'
DIRECTORY = RETRY2_DIRECTORY
NAME = '168-full-metered-cold-v2-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
GUARD = R / 'epoch168-cold-guard-20261122-v2'
OLD = R / 'epoch168-full-metered-20261121-v1'
LANE = Path('/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1')
RUN = LANE / 'full-metered-20261121-v1/cold-retry2-20261122'
ROOT_SHA = 'ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc'
PAYLOAD_SHA = '6c56c0cad87c9d22ca72ad8e2cf97cb0cc0c5e1b4d1d01e4f051dfc01875b240'
WORKER_SHA = 'b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541'
PRIOR_IID = '9cebb1d022124fb08588e93e055d5446'
ORIGINAL_ARGV_SHA = '39d2e97f8f6962984f1ec9672a4701fe0772e3a63a72465b8d945d59eab7b4fa'
PREPARED_SHA = 'dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a'
LOG_SHA = 'bdaff851db2edbac62c7b925156ba2cdb827001268324ee851e74d0790f8a84f'
GATE_SHA = 'bdddd295d33c195dcef49fa28f69da8b85ec152a496ddd98a04be76914b45d2a'
GUARD_QUAL_SHA = 'bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b'
ROOT_INODE,LOG_INODE = 103481350,103481356
ALIAS = Path('/run/horizon-full168-cold-v2')
FAILED_IID = 'd929652cba0e459cafc75edd05356c83'
FAILURE_SHA = 'a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643'

if RETRY3:
    DIRECTORY = 'epoch168-retry3-rebook-20261123-v1'
    NAME = '168-full-metered-cold-v3-20261123'
    UNIT = 'horizon-qualify-'+NAME+'.service'
    GUARD = R/'epoch168-cold-guard-20261123-v3'
    RUN = LANE/'full-metered-20261121-v1/cold-retry3-20261123'
    ALIAS = Path('/run/horizon-full168-cold-v3')
    ROOT_SHA = 'a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4'
    ROOT_INODE,LOG_INODE = 103481378,103481382
    generation = json.loads(Path(__file__).with_name('retry3-168-fit-generation.json').read_bytes())
    expected = dict(prepared=R/DIRECTORY/'PREPARED.json',log=R/DIRECTORY/'OBSERVER_LOG_PREPARED.json',
                    guard=GUARD/'GUARD_QUALIFIED.json',gate=R/DIRECTORY/'tools/gate.py')
    if set(generation)!=set(expected) or any(set(generation[k])!={'path','sha256'} or generation[k]['path']!=str(p) or
           not re.fullmatch('[0-9a-f]{64}',generation[k]['sha256']) for k,p in expected.items()):
        raise ValueError('foreign qualified epoch 168 retry3 generation')
    PREPARED_SHA,LOG_SHA,GUARD_QUAL_SHA,GATE_SHA = (generation[k]['sha256'] for k in ('prepared','log','guard','gate'))


if RETRY4:
    PREVIOUS_PREPARED_SHA,PREVIOUS_GUARD_SHA=PREPARED_SHA,GUARD_QUAL_SHA
    DIRECTORY='epoch168-retry4-rebook-20261123-v1'
    NAME='168-full-metered-cold-v4-20261123'
    UNIT='horizon-qualify-'+NAME+'.service'
    GUARD=R/'epoch168-cold-guard-20261123-v4'
    RUN=LANE/'full-metered-20261121-v1/cold-retry4-20261123'
    ALIAS=Path('/run/horizon-full168-cold-v4')
    generation=json.loads(Path(__file__).with_name('retry4-168-fit-generation.json').read_bytes())
    expected=dict(prepared=R/DIRECTORY/'PREPARED.json',log=R/DIRECTORY/'OBSERVER_LOG_PREPARED.json',
                  guard=GUARD/'GUARD_QUALIFIED.json',gate=R/DIRECTORY/'tools/gate.py',root=R/DIRECTORY/'SUCCESSOR_ROOT.json')
    if set(generation)!=set(expected) or any(set(generation[k])!={'path','sha256'} or generation[k]['path']!=str(path)
            or not re.fullmatch('[0-9a-f]{64}',generation[k]['sha256']) for k,path in expected.items()):
        raise ValueError('foreign epoch 168 retry4 generation')
    PREPARED_SHA,LOG_SHA,GUARD_QUAL_SHA,GATE_SHA,ROOT_SHA=(generation[k]['sha256'] for k in ('prepared','log','guard','gate','root'))
    RETRY4_PREPARED_SHA, RETRY4_GUARD_SHA = PREPARED_SHA, GUARD_QUAL_SHA
    common_mount=runpy.run_path(str(Path(__file__).with_name('cold168_common_mount.py')))
    spent=runpy.run_path(str(Path(__file__).with_name('closed_retry3.py')))
    if ROOT_SHA != '713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4':
        raise ValueError('unbound new epoch168 root')
    ROOT_INODE, LOG_INODE = 103481722, 103481750


if RETRY5:
    DIRECTORY = 'epoch168-retry5-rebook-20261125-v1'
    NAME = '168-full-metered-cold-v5-20261125'
    UNIT = 'horizon-qualify-' + NAME + '.service'
    GUARD = R / 'epoch168-cold-guard-20261125-v5'
    RUN = RUN.with_name('cold-retry5-20261125')
    ALIAS = Path('/run/horizon-full168-cold-v5')
    ROOT_SHA = '4cd544fddda40cd81c94358b8c455feac24247b14f56e8fdb8ede2727c54af25'
    PREPARED_SHA = '2320e810781b070887acb47874bb2eeb24670a43f7fb71684728169b00af0241'
    LOG_SHA = '116d48dde43a51ef04a0e0c7e6e9fa5ac6f175f5795d8648010c1dc94d6ad988'
    GATE_SHA = '6bd4746b5d205ccfd857c88d7fdaa56e9e9826bf987ad408f3d1f8f0c4304f21'
    GUARD_QUAL_SHA = 'e237ca579a8921adaae0081ef71a82b35377e4ff80acaf8539c03cd68e3aa696'
    ROOT_INODE, LOG_INODE = 109396827, 109396830
    RETAINED_RETRY4 = R / 'incident-replay-fit-20261121-v1/STOPPED168_RETRY5_RETAINED_SOURCE_CONTROL_20261125.json'
    RETAINED_RETRY4_SHA = '488dbd9e630511b97a0ad0704241a0a1fdec71a614caf17c6cd1d3a63b3dc0b2'
    HOME_STOP_SHA = '1fba7a686be4387737b8c7776a5ed92a59bff82c15ced77496e9214c94710f62'
    CAP = 512 << 30
    OUTSIDE_CAP_STOP_ALLOWANCE = 8 << 30


def retry5_stop(s, fit):
    retained, ref = s.read(RETAINED_RETRY4, RETAINED_RETRY4_SHA)
    stop = retained['stop']
    retry4 = R / 'epoch168-retry4-rebook-20261123-v1'
    terminal = s.bound(stop['terminal'], retry4 / 'guard-receipts/stop-completion.json')
    intent = s.bound(stop['stop_intent'], retry4 / 'guard-receipts/stop-intent.json')
    admission = s.bound(stop['admission'], retry4 / 'ACTUAL_ADMISSION_AND_PROTECTION.json')
    sample = intent['sample']['root_physical_observation']
    s.need(retained['epoch'] == 168 and stop['producer_invocation_id'] ==
           terminal['producer_invocation_id'] == intent['producer_invocation_id'] ==
           admission['producer_invocation_id'] == '913443d7f9f44d7e9d3e0eec420acfab' and
           intent['reason'] == 'root-physical-budget' and terminal['terminal']['pid'] == 0 and
           terminal['terminal']['active'] == 'inactive' and terminal['scratch_deleted'] is False and
           stop['resource_credit_bytes'] == stop['reservation_ending_bytes'] == 0 and
           stop['retained_cap_bytes'] == sample['maximum_physical_bytes'] == 288 << 30 and
           stop['measured_physical_bytes'] == sample['conservative_physical_bytes'] > stop['retained_cap_bytes'],
           'foreign retained retry4 guard stop')
    timer = stop['retired_guard_timer']
    for unit in (admission['producer_unit'], timer, timer.removesuffix('.timer') + '.service'):
        manager = s.show(unit)
        s.need(manager['ActiveState'] == 'inactive' and not manager['InvocationID'] and
               not manager['Job'] and not fit.members(unit), 'stopped retry4 owner returned')
    return stop, ref


def retry5_preparation(s, root, prepared):
    stop = OLD / 'guard-receipts/stop-completion.json'
    terminal, stop_ref = s.read(stop, HOME_STOP_SHA)
    control, control_ref = s.read(RETAINED_RETRY4, RETAINED_RETRY4_SHA)
    baseline = prepared['baseline']
    s.need(root['schema'] == 'horizon-epoch168-retry5-successor-root-v1' and
           root['root_immutable'] is True and common_mount['immutable'](RUN) and
           all(not common_mount['immutable'](RUN / k) for k in ('private', 'output')) and
           baseline['retained_source_control'] == control_ref and
           root['source_control_sha256'] == control_ref['sha256'] and
           root['whole_tree_cap_bytes'] == prepared['profile']['payload']['whole_root_cap'] == CAP and
           baseline['predecessor_stop'] == stop_ref and
           baseline['retry4_root_physical_stop'] == control['stop'] and
           terminal['producer_invocation_id'] == PRIOR_IID and terminal['terminal']['pid'] == 0,
           'different retry5 namespace or stopped custody')
    return stop_ref, control['stop']


def failed_retry2(s,root):
    previous=R/RETRY2_DIRECTORY
    path=previous/'RELEASED_NODE_STARTUP_FAILURE_20261123.json'
    failure,ref=s.read(path,FAILURE_SHA)
    retained=s.bound(root['previous_root'],previous/'SUCCESSOR_ROOT.json')
    s.need(root['previous_root']['sha256']=='ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc' and
           all(retained[k]==root[k] for k in ('prior_stop','initial_cleanup')),'different retry2 root or cleanup')
    old=failure['producer']
    s.need(root['previous_start_failure']==ref and failure['epoch']==168 and failure['no_admission_record'] and
           failure['private_directory_empty'] and failure['permit_consumed'] and failure['worker_receipt_absent'] and
           not failure['replay_claimed'] and not failure['worker_in_observed_guard_samples'] and
           old['Id']=='horizon-qualify-168-full-metered-cold-v2-20261122.service' and
           (old['InvocationID'],old['MainPID'],old['ActiveState'],old['ExecMainStatus'])==(FAILED_IID,'0','failed','1'),
           'different failed retry2 settlement')
    for name in ('START_INTENT.json','ACTUAL_PRODUCER_NATIVE.json','FIRST_GUARD.json','POST_GUARD_CAPACITY.json',
                 'AUTHORIZED_GATED_PAYLOAD.json'):
        obj=s.bound(failure['receipts'][name],previous/name)
        if name in ('ACTUAL_PRODUCER_NATIVE.json','AUTHORIZED_GATED_PAYLOAD.json'):
            s.need(obj['producer_invocation_id']==FAILED_IID,'foreign spent producer')
    permit=previous/'barrier/allow'
    st=permit.lstat()
    s.need((st.st_uid,st.st_gid,st.st_nlink,st.st_mode)==(0,0,1,0o100444) and permit.read_bytes()==FAILED_IID.encode() and
           not any((previous/name).exists() for name in ('ACTUAL_ADMISSION_AND_PROTECTION.json','FIRST_PROTECTED_WORKER.json')),
           'failed retry2 acquired a different permit or admission')


def stable(s):
    root, ref = s.read(R / DIRECTORY / 'SUCCESSOR_ROOT.json', ROOT_SHA)
    candidate = dict(root, path=root['root'])
    for item, p in ((candidate,RUN),(root['private'],RUN/'private'),(root['output'],RUN/'output')):
        m = p.lstat()
        s.need(p.resolve(strict=True) == p and str(p) == item['path'] and
               [m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode] ==
               [item[k] for k in ('device','inode','uid','gid','mode')], 'different cold 168 namespace')
    log = RUN/'producer.log'
    observed = log.lstat()
    old = root['log']
    d = R/DIRECTORY
    log_record = d/'OBSERVER_LOG_PREPARED.json'
    s.need(log.resolve(strict=True)==log and old['path']==str(log) and observed.st_nlink==1 and
           (observed.st_dev,observed.st_ino,observed.st_mode)==(old['device'],old['inode'],old['mode']) and
           stat.S_ISREG(observed.st_mode) and stat.S_IMODE(observed.st_mode)==0o600, 'different cold 168 append log')
    if log_record.exists():
        prepared,pr=s.read(d/'PREPARED.json',PREPARED_SHA)
        log_prep,_=s.read(log_record,LOG_SHA)
        s.need(prepared['epoch']==168 and log_prep['prepared']==pr and log_prep['path']==str(log) and
               (log_prep['device'],log_prep['inode'],log_prep['mode'],log_prep['size'],log_prep['nlink'])==
               (observed.st_dev,observed.st_ino,0o600,0,1) and
               (observed.st_uid,observed.st_gid)==(log_prep['uid'],log_prep['gid'])==(0,0),
               'unbound root-owned cold 168 append log')
    else:
        s.need((observed.st_uid,observed.st_gid)==(old['uid'],old['gid'])==(1001,1003) and
               observed.st_size==0, 'cold 168 append log changed before observer registration')
    s.need(candidate['inode']==ROOT_INODE and root['log']['inode']==LOG_INODE and root['worker_launched'] is False,
           'wrong cold 168 generation')
    if RETRY5:
        s.need(log_record.exists(), 'retry5 requires the prepared append log')
        retry5_preparation(s, root, prepared)
        return ref
    if RETRY4:
        previous=R/'epoch168-retry3-rebook-20261123-v1'
        fixture = previous/'COMMON_MOUNT_REGRESSION/RESULT.json'
        fixture_sha = '51b01c0110965a74db73e539dea68b0520f9e9b5ed02cb581f6a7f54be310704'
        _, fixture_ref = s.read(fixture, fixture_sha)
        s.need(root['common_mount_fixture'] == fixture_ref and root['parent_immutable'] is True and
               root['children_immutable'] is False and root['private']['inode'] == 103481729 and
               root['output']['inode'] == 103481728 and
               all(not common_mount['immutable'](RUN / k) for k in ('private', 'output')),
               'different common mount witness or sealed replay children')
        before=s.bound(root['previous_root'],previous/'SUCCESSOR_ROOT.json')
        s.need(root['previous_root']['sha256']=='a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4' and
               root['previous_start_failure']==s.ref(previous/'RELEASED_NODE_STARTUP_FAILURE_20261123.json',spent['FAILURE']) and
               all(root[k]==before[k] for k in ('initial_cleanup','prior_stop')) and common_mount['immutable'](RUN),
               'different retry4 predecessor or unprotected fresh attempt')
        failed_retry2(s,before)
    elif RETRY3:
        failed_retry2(s,root)
    closed = s.bound(root['prior_stop'],OLD/'guard-receipts/stop-completion.json')
    cleanup = s.bound(root['initial_cleanup'],R/'epoch168-closed-accounts-20261122-v1/state/full-metered/COMPLETE.json')
    s.need(closed['producer_invocation_id'] == closed['terminal']['invocation_id'] ==
           cleanup['original_iid'] == PRIOR_IID and closed['terminal']['pid'] == 0 and
           cleanup['scope_empty'] and cleanup['archive_or_snapshot_removed'] is False and
           not any(Path(cleanup['scope']).iterdir()), 'wrong stopped 168 settlement')
    return ref


def observe(s,fit,native_actor,own):
    rootref = stable(s)
    root = s.bound(rootref,R / DIRECTORY / 'SUCCESSOR_ROOT.json')
    if RETRY5:
        prepared, _ = s.read(R / DIRECTORY / 'PREPARED.json', PREPARED_SHA)
        home_stop, retry4 = retry5_preparation(s, root, prepared)
        s.need(retry5_stop(s, fit)[0] == retry4, 'different retry5 predecessor')
        predecessor = dict(original=dict(producer_invocation_id=PRIOR_IID), stop_completion=home_stop)
        actor = native_actor(168, own, LANE, RUN, predecessor, generation=(DIRECTORY, NAME))
        s.need(actor is None or actor['producer_invocation_id'] != retry4['producer_invocation_id'],
               'spent retry4 invocation cannot admit retry5')
        return actor
    stopped=set(root['stopped_units'])
    if RETRY3:
        # The creation receipt includes the successor before admission. native_actor checks it below.
        stopped -= {UNIT,'horizon-guard-'+NAME+'.timer','horizon-guard-'+NAME+'.service'}
        stopped.update(('horizon-qualify-168-full-metered-20261121-v1.service',
                        'horizon-guard-168-full-metered-20261121-v1.timer','horizon-guard-168-full-metered-20261121-v1.service'))
    if RETRY4:
        settled=spent['settled'](s,fit)
        s.need(settled['failure']==root['previous_start_failure'] and not settled['executing'],'different spent retry3 owner')
        stopped.discard(spent['UNIT'])
    for unit in stopped:
        m=s.show(unit)
        old_failed=RETRY3 and unit=='horizon-qualify-168-full-metered-cold-v2-20261122.service' and (
            m['ActiveState'],m['InvocationID'],m['ExecMainStatus'])==('failed',FAILED_IID,'1')
        s.need((m['ActiveState']=='inactive' or old_failed) and not m['Job'] and not fit.members(unit), 'stopped 168 owner returned')
    predecessor = dict(original=dict(producer_invocation_id=PRIOR_IID), stop_completion=root['prior_stop'])
    actor=native_actor(168,own,LANE,RUN,predecessor,generation=(DIRECTORY,NAME))
    if RETRY3 and actor is not None:
        s.need(actor['producer_invocation_id'] not in ((FAILED_IID,spent['IID']) if RETRY4 else (FAILED_IID,)),'spent retry2 invocation cannot admit retry3')
    return actor


def registered_inputs(s, payload):
    # The three index destinations follow the new output root. The snapshot argument keeps
    # its original generation-bound path. None of these multi-GB files need a second copy.
    original_output = RUN.parent / 'ledger'
    snapshot = payload['bootstrap_file']
    pairs = {Path(snapshot['path']): Path(snapshot['path']),
             RUN / 'output/genesis.tar.bz2': Path(payload['genesis']['path'])}
    for row in payload['indexes']:
        target = RUN / 'output' / Path(row['target']).relative_to(original_output)
        pairs[target] = Path(row['source']['path'])
    s.need(len(pairs) == 5, 'missing or duplicate original 168 input')
    for row in [snapshot, payload['genesis'], *(i['source'] for i in payload['indexes'])]:
        path = Path(row['path'])
        st = path.lstat()
        s.need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and
               [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns] == row['identity'],
               'changed retained cold 168 input: ' + str(path))
    for name, (source, digest) in payload['members'].items():
        path = Path(source)
        with path.open('rb') as f:
            s.need(hashlib.file_digest(f,'sha256').hexdigest() == digest, 'foreign cold 168 member: ' + name)
        pairs[ALIAS / name] = path
    return pairs


def normal_argv(s, payload):
    original = payload['regular_node_argv']
    s.need(len(original) == 8 and original[1:5] == ['168', str(RUN.parent/'ledger'), '--verify',
           '--root-checkpoint-cohort'] and original[-1] == '--snapshot-archive='+payload['bootstrap_file']['path'],
           'unrecognized original metered node argv')
    return [str(ALIAS/'jetstreamer-node'), '168', str(RUN/'output'), *original[3:5],
            '--cohort-manifest='+str(ALIAS/'preflight-168-v4.json'), *original[6:]]


def projected_argv(s, argv):
    bindings = {}
    for arg in argv:
        if not arg.startswith('--property=BindReadOnlyPaths='):
            continue
        for token in arg.removeprefix('--property=BindReadOnlyPaths=').split():
            parts = token.split(':')
            source, dest = Path(parts[0]), Path(parts[-1])
            s.need(len(parts) in (1,2) and source.is_absolute() and dest.is_absolute() and
                   dest not in bindings, 'ambiguous cold 168 read-only projection')
            bindings[dest] = source
    return bindings


def check_profile(s, d, profile, original, translated):
    """Recreate only the paths moved by the new generation; preserve all bank and replay parameters."""
    expected = normal_argv(s, original)
    intended = deepcopy(original)
    intended['producer_unit'] = UNIT
    intended['guard_unit'] = 'horizon-guard-'+NAME
    intended['regular_node_argv'] = expected
    if RETRY5:
        intended['whole_root_cap'] = CAP
    intended['environment']['JETSTREAMER_PRIVATE_RUN_ROOT'] = str(RUN/'private')
    intended['environment']['JETSTREAMER_HISTORICAL_WORKER_V1_5_6'] = str(ALIAS/'jetstreamer-historical-worker-v1-5-6')
    for row in intended['indexes']:
        relative = Path(row['target']).relative_to(RUN.parent/'ledger/compact-indexes')
        row['target'] = str(RUN/'output/compact-indexes'/relative)
    s.need(translated == profile['payload'] == intended and profile['indexes'] == intended['indexes'] and
           profile['source_argv'] == s.ref(OLD/'SESSION_PRODUCER_ARGV.json', ORIGINAL_ARGV_SHA),
           'foreign cold 168 payload or original arguments')
    pairs = registered_inputs(s, original)
    pairs.update({ALIAS/'payload.json': d/'COLD_PAYLOAD.json', ALIAS/'barrier': d/'barrier',
                  ALIAS/'gate.py': d/'tools/gate.py'})
    entries = profile['readonly_projections']
    argv = profile['producer_argv']
    s.need(len(entries) == len(pairs) and {Path(dst):Path(src) for src,dst in entries} == pairs and
           projected_argv(s, argv) == pairs, 'foreign registered cold 168 input projections')
    return expected, pairs


def home_namespace(s,proc,profile,pairs):
    """Check the held process's effective mount table before its gate can release the node."""
    home=Path('/home/sol')
    config=Path(profile['payload']['environment']['XDG_CONFIG_HOME'])
    s.need(config==LANE/'config','foreign 168 config directory')
    writable={RUN/'output',RUN/'private'}
    readonly={RUN/'producer.log',config}
    if RETRY4:
        writable={RUN}
    elif RETRY3:
        readonly.add(RUN)
    expected={home,*readonly,*writable,*(p for p in pairs if p.is_relative_to(home))}
    inaccessible,=(v.removeprefix('--property=InaccessiblePaths=').split() for v in profile['producer_argv']
                   if v.startswith('--property=InaccessiblePaths='))
    masks={Path(p.removeprefix('-')) for p in inaccessible}
    mounted={}
    for line in (proc/'mountinfo').read_text().splitlines():
        fields=line.split()
        target=Path(fields[4])
        if not target.is_relative_to(home):
            continue
        opts=set(fields[5].split(','))
        if target in masks:
            # A systemd inaccessible path may be absent beneath the empty HOME tmpfs.
            exposed=proc/'root'/target.relative_to('/')
            s.need('ro' in opts and exposed.stat().st_mode & 0o777==0,'unmasked 168 private path '+str(target))
            continue
        s.need(target in expected and target not in mounted,'unexpected 168 HOME mount '+str(target))
        mounted[target]=opts
        if target==home:
            s.need(fields[3]=='/' and fields[fields.index('-')+1]=='tmpfs' and
                   {'ro','noexec','nosuid','nodev'} <= opts,'168 HOME must be a read-only noexec tmpfs')
    s.need(mounted.keys()==expected,'incomplete 168 HOME namespace')
    for target in writable|readonly:
        s.need(('rw' if target in writable else 'ro') in mounted[target] and
               s.same_file(proc/'root'/target.relative_to('/'),target),'foreign 168 HOME bind '+str(target))
    if RETRY4:
        common_mount['verify'](s,proc,RUN,mounted)
    elif RETRY3:
        for target in [RUN,*writable]:
            node_view=(proc/'root'/target.relative_to('/')).stat()
            s.need((node_view.st_uid,node_view.st_gid,node_view.st_mode)==(1001,1003,0o40700),
                   'untrusted 168 private run parent or child '+str(target))
        s.need('noexec' not in mounted[RUN/'private'],'168 historical worker scratch forbids execution')
    s.need(not (proc/'root/home/sol/workspace/jetstreamer/Cargo.toml').exists(),'168 workspace exposed')


def verify_start(s,d,proc,unit,timer,tree,run,intent,identity,held,readonly_mounts):
    prepared, ref = s.read(d/'PREPARED.json',PREPARED_SHA)
    profile = prepared['profile']
    s.need(intent['prepared']==ref and profile['producer_unit']==unit==UNIT and
           profile['fresh_attempt']==str(run)==str(RUN) and profile['guard_timer']==timer and
           profile['guard_worker_root']==str(tree)==str(LANE) and
           intent['stable_root']==dict(path=str(RUN),device=64512,inode=ROOT_INODE),
           'foreign cold 168 prepared owner')
    payload,_=s.read(OLD/'inputs-v1/payload.json',PAYLOAD_SHA)
    s.read(OLD/'SESSION_PRODUCER_ARGV.json',ORIGINAL_ARGV_SHA)
    translated, payload_ref=s.read(d/'COLD_PAYLOAD.json',profile['payload_sha256'])
    base=prepared['baseline']
    s.need(base['profile']==profile and prepared['payload']==payload_ref and base['root']==intent['stable_root'] and
           base['stable_roots']==s.ref(d/'SUCCESSOR_ROOT.json',ROOT_SHA) and
           base['predecessor_stop']==intent['predecessor_stop'] and prepared['epoch']==168 and
           prepared['node_sha256']==payload['members']['jetstreamer-node'][1] and prepared['worker_sha256']==WORKER_SHA,
           'wrong cold 168 preparation or predecessor')
    expected,pairs=check_profile(s,d,profile,payload,translated)
    gate=ALIAS/'gate.py'
    python=Path('/usr/bin/python3')
    full=[str(python),'-IB',str(gate),*expected]
    s.need(profile['producer_argv'][-len(full):]==full and hashlib.sha256(pairs[gate].read_bytes()).hexdigest()==GATE_SHA,
           'wrong cold 168 held gate or launch arguments')
    readonly_mounts(s,proc,pairs)
    home_namespace(s,proc,profile,pairs)
    env=(proc/'environ').read_bytes().split(b'\0')
    enrolled={**translated['environment'],'HORIZON_FULL168_PAYLOAD_SHA256':payload_ref['sha256'],
              'INVOCATION_ID':identity['producer_invocation_id']}
    for key,val in enrolled.items():
        match=[v for v in env if v.startswith(os.fsencode(key+'='))]
        s.need(match==[os.fsencode(key+'='+val)], 'different cold 168 process environment: '+key)
    node=Path(payload['members']['jetstreamer-node'][0])
    s.need(s.same_file(proc/'exe',python if held else node) and
           (proc/'cmdline').read_bytes().split(b'\0')==[os.fsencode(a) for a in (full if held else expected)]+[b''],
           'changed cold 168 executable or arguments')
    status = {k:v.split() for k,v in (l.split(':',1) for l in (proc/'status').read_text().splitlines() if ':' in l)}
    s.need(status['Uid']==['1001']*4 and status['Gid']==['1003']*4,'changed cold 168 process credentials')
    permit=d/'barrier/allow'
    if held:
        s.need(not permit.exists() and not (d/'NODE_AFTER_PERMIT.json').exists(), 'premature cold 168 permit')
    else:
        m=permit.lstat()
        s.need(stat.S_ISREG(m.st_mode) and (m.st_uid,m.st_gid,m.st_nlink,stat.S_IMODE(m.st_mode))==(0,0,1,0o444)
               and permit.read_bytes()==identity['producer_invocation_id'].encode(), 'foreign cold 168 permit')
        observed,_=s.read(d/'NODE_AFTER_PERMIT.json')
        node_stat=node.stat()
        s.identity(observed,dict(identity,stage='node',exe_device=node_stat.st_dev,exe_inode=node_stat.st_ino))
        auth=s.bound(observed['authorization'],d/'AUTHORIZED_GATED_PAYLOAD.json')
        admission,_=s.read(d/'ACTUAL_ADMISSION_AND_PROTECTION.json')
        s.identity(admission,dict(identity,stage='node',exe_device=node_stat.st_dev,exe_inode=node_stat.st_ino))
        s.need(auth['producer_pid']==identity['producer_pid'] and auth['start_ticks']==identity['start_ticks'] and
               auth['producer_invocation_id']==identity['producer_invocation_id'] and auth['transaction_replay_claimed'] is False and
               all(auth[k]==admission[k] for k in ('post_guard_capacity','actual_guard_plan','first_guard')),
               'unbound cold 168 permit release')
    return guard(s,profile)


def guard(s,profile):
    qualified, _ = s.read(GUARD/'GUARD_QUALIFIED.json',GUARD_QUAL_SHA)
    image=GUARD/'tools/guard';digest=profile['guard_binary_sha256']
    seal=s.bound(qualified['seal'],image.parent/'deployment-seal-receipt.json')
    contract=qualified['contract']
    terms=s.bound(contract['contract'],GUARD/'contract/contract.json')
    s.bound(contract['deployment_seal'],GUARD/'contract/deployment-seal-receipt.json')
    witness=s.bound(terms['qualified_native_witness'],GUARD/'NATIVE_WITNESS.json')
    schema='horizon-168-cold-v3-native-guard-qualified-v1' if RETRY3 else 'horizon-168-cold-v2-native-guard-qualified-v1'
    if RETRY4: schema='horizon-168-cold-v4-native-guard-qualified-v1'
    if RETRY5: schema='horizon-168-cold-v5-native-guard-qualified-v1'
    s.need(qualified['schema']==schema and qualified['guard']==dict(path=str(image),sha256=digest) and
           seal['destination']==str(image.parent) and any(x['name']=='guard' and x['sha256']==digest for x in seal['members']) and
           witness['native_identity']['executable']==str(image) and witness['native_identity']['executable_sha256']==digest and
           hashlib.sha256(image.read_bytes()).hexdigest()==digest,'different qualified cold 168 guard')
    return digest,contract


def registered_writer(s, prior):
    """Follow the same-service handoff; the active writer can be enrolled before 168 starts."""
    old_pkg, old_seal, old_iid, old_actor = prior
    status = R/'survivor172-cadence-20261122-v1'
    prefix = 'COLD168_RETRY2_V1_STATUS_'
    active_path = status/(prefix+'ACTIVE.json')
    rollback_path = status/(prefix+'ROLLBACK.json')
    if not (active_path.exists() or rollback_path.exists()):
        return prior
    q, qr = s.read(status/(prefix+'QUALIFIED.json'))
    intent, ir = s.read(status/(prefix+'INTENT.json'))
    current, _ = s.read(status/'COLD170_RETRY13_V2_STATUS_ACTIVE.json')
    s.need(old_actor==current['new']==intent['old'] and old_iid==old_actor['invocation_id']
           and old_pkg==status/'tools-cold170-retry13-v2' and old_seal==s.ref(old_pkg/'deployment-seal-receipt.json',
               'f1b4781788205dbc065f5b116577c2e263e523f65e19cd658c31a9ae7e86fdb4')
           and intent['qualified']==qr, 'foreign 168 writer predecessor or handoff')
    _, prep = s.read(R/RETRY2_DIRECTORY/'PREPARED.json','dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a')
    _, root = s.read(R/RETRY2_DIRECTORY/'SUCCESSOR_ROOT.json','ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc')
    _, guardref = s.read(R/'epoch168-cold-guard-20261122-v2/GUARD_QUALIFIED.json','bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b')
    package = Path(q['package']['path']).parent
    seal = s.bound(q['package'],package/'deployment-seal-receipt.json')
    entry, = (v for v in seal['members'] if v['name']=='status_cycle.py')
    s.need(package.parent==status and package!=old_pkg and seal['destination']==str(package)
           and q['schema']=='horizon-168-retry2-v1-status-qualified-v1' and q['epoch']==168
           and q['entry']==s.ref(package/'status_cycle.py',entry['sha256']) and q['guard']==guardref and
           q['successor_root']==root and q['prepared']==prep and re.fullmatch('[0-9a-f]{40}',q['source_commit']) and
           isinstance(q['suites'],dict) and q['suites'], 'foreign qualified cold 168 status package or enrollment')
    if active_path.exists():
        active, _ = s.read(active_path)
        s.need(active['intent']==ir and active['qualified']==qr and active['old']==old_actor and
               q['generation'] is not None and active['generation']==q['generation'] and
               active['schedule']==intent['schedule'], 'different cold 168 active status handoff')
        actor, selected = active['new'], q['package']
    else:
        rollback, first = s.read(rollback_path)
        iid = s.show(old_actor['unit'])['InvocationID']
        if rollback['restored']['invocation_id']!=iid:
            s.need(s.iid(iid),'invalid cold 168 rollback owner')
            rollback,_=s.read(status/(prefix+'ROLLBACK_'+iid+'.json'))
            s.need(rollback['original_rollback']==first,'unbound cold 168 rollback')
        s.need(rollback['intent']==ir and rollback['schedule']==intent['schedule'],'different cold 168 rollback schedule')
        actor, selected, package = rollback['restored'], old_seal, old_pkg
    s.need(actor['unit']==old_actor['unit'] and actor['program']==str(package/'status_cycle.py') and
           s.iid(actor['invocation_id']) and actor['invocation_id']!=old_iid and
           all(actor['lock'][k]==old_actor['lock'][k] for k in ('path','device','inode')),
           'different cold 168 status service or exclusive lock')
    return package, selected, actor['invocation_id'], actor


def holding(s, fit, fleet, prior):
    """Observe 168 only when it occupies the serial holding slot after the 166 copy."""
    park = R/'epoch168-full-metered-holding-20261122-v1'
    unit = 'horizon-closed168-full-metered-park-20261122-v1.service'
    manager = s.show(unit)
    members = fit.members(unit)
    if not (park/'PARK_START.json').exists():
        s.need(not members and manager['ActiveState']=='inactive' and not manager['Job'],
               'unregistered cold 168 holding owner')
        return None
    prepared, inputs = s.read(park/'PREPARED.json','2fa44417d9b239b8e35820c1bed5b6e47d184517e9850cbc7992c7f8b5663c58')
    admission, ar = s.read(park/'PARK_ADMISSION.json')
    start, sr = s.read(park/'PARK_START.json')
    quote = s.bound(admission['fit'],park/'PARK_FIT.json')
    plan = s.bound(prepared['plan'],park/'package/plan.json')
    proof = start['native']
    image = prepared['holding_image']
    promise = fleet['retry9_auxiliary_commitments']
    s.need(prior['stage']=='completed-copy' and prior['unit']==prepared['predecessor_166_job'] and
           quote['fits'] and admission['owner']=='primary' and admission['unit']==unit and
           admission['inputs']==inputs and admission['plan']==prepared['plan'] and start['admission']==ar and
           promise['holding_serial'] and promise['holding_and_build_may_overlap'] and
           promise['holding_cpu_quota_micros']==admission['cpu']==2000000 and
           promise['holding_memory_bytes']==admission['memory']==2<<30 and admission['tasks']==256 and
           promise['holding_staging_bytes']==admission['archive_staging_bytes']==admission['resource_credit_bytes']==0 and
           start['resource_credit_bytes']==0 and promise['holding_restore_overlap_bytes']>=plan['length']==
           admission['restore_overlap_bytes']==prepared['private_restore_bytes']==51889766680 and
           plan['sha256']==prepared['source_sha256'] and plan['source']==prepared['source_path'],
           'foreign cold 168 holding admission or unfunded serial transfer')
    s.need(proof['Id']==unit and s.iid(proof['InvocationID']) and manager['InvocationID']==proof['InvocationID'] and
           manager['MemoryMax']==str(admission['memory']) and manager['CPUQuotaPerSecUSec']=='2s' and
           manager['NRestarts']==manager['MemorySwapMax']=='0' and proof['TasksMax']=='256' and
           fit.command('/usr/bin/systemctl','show','--property=TasksMax','--value',unit).strip()=='256',
           'foreign cold 168 holding limits or process generation')
    if members:
        pid=int(proof['MainPID']); proc=Path('/proc')/str(pid); _,ticks,group=s.process(pid)
        s.need(manager['ActiveState'] in ('active','activating') and manager['MainPID']==str(pid) and
               members==(pid,) and ticks==int(start['start_ticks']) and group=='0::/system.slice/'+unit and
               s.same_file(proc/'exe',Path(image['path'])) and (proc/'cmdline').read_bytes().split(b'\0')==
               [os.fsencode(arg) for arg in prepared['argv']]+[b''], 'foreign cold 168 holding worker')
        stage='copy-only'
    else:
        s.need(manager['MainPID']=='0' and manager['ActiveState']=='active' and manager['SubState']=='exited'
               and manager['ExecMainStatus']=='0' and manager['Result']=='success' and not manager['Job'],
               'cold 168 holding actor not successfully drained')
        stage='completed-copy'
    return dict(stage=stage,unit=unit,invocation_id=proof['InvocationID'],admission=ar,start=sr,
                restore_overlap_bytes=plan['length'],additional_reservation_bytes=0,resource_credit_bytes=0)


def prestart(s,fit,epoch,ref,prestart136,capture,tree_size,host_floor,budget,registered_floor,fund,sources):
    # Inactive 166 remains fully charged by the original stopped-tree booking.
    # Count retained siblings of an active 166 only when its own generation is present.
    retained={}
    for peer, source in sources.items():
        if peer==epoch:
            continue
        unit='horizon-qualify-'+source['NAME']+'.service'
        if not fit.members(unit):
            continue
        lane, run = source['LANE'],source['RUN']
        cap={166:288,167:512,168:288,170:384}[peer]<<30
        size=tree_size(lane,cap,run)
        s.need(tree_size(lane,cap,run)==size,'retained peer siblings changed')
        retained[peer]=size
    price=capture(epoch,ref,prestart136)
    s.need(price['candidate'] is None and set(map(str,retained))==set(price['replacements']),
           'prestart does not match the observed owner census')
    for peer in retained:
        source=sources[peer];book=price['bookings'][str(peer)]
        s.need(book['root']==str(source['LANE']) and book['run']==str(source['RUN']),
               'wrong active peer run')
    raw=None
    if 168 in retained:
        f=s.bound(ref,Path(ref['path']));ledger=s.bound(fit.BOOK, Path(fit.BOOK['path']))
        def rebase(physical):
            val,_=host_floor(f,ledger,dict(physical_bytes=physical),price['survivors'],
                             price['bookings'].get('172'),price['bookings'].get('169'))
            extension=price['epoch170_extension']
            return val+(extension['extra_bytes'] if extension else 0)
        s.need(rebase(price['bookings']['168']['physical_bytes'])==price['original_aggregate_HOME_bytes'],
               'original 168 occupied host floor no longer reproduces')
        raw=rebase(retained[168])
    fund(s,price,retained,budget,registered_floor,cold168_profile=True,raw_with_retained168=raw)
    return price
