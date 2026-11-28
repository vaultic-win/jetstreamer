"""Bind epoch 166 retry11 and the closed prefix being parked on its original booking."""
import hashlib
import os
from pathlib import Path
import stat
import subprocess

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
LANE = Path('/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1')
PREVIOUS_RUN = LANE/'replacement-local3retry10-20261121-v1'
RUN = PREVIOUS_RUN/'cold-retry11-20261122'
NAME = '166-independent-retry11-20261122'
UNIT = 'horizon-qualify-' + NAME + '.service'
TIMER = 'horizon-guard-' + NAME + '.timer'
DIRECTORY = 'epoch166-retry11-rebook-20261122-v1'
PREVIOUS_UNIT = 'horizon-qualify-166-independent-recovery-20261121-v1.service'
PREVIOUS_IID = '3c220efd0d0740f59572a96447e83762'
STOP_PATH = R/'epoch166-independent-cold-recovery-20261121-v1/guard-receipts/stop-completion.json'
STOP_SHA = 'a72e48f26f716ac397b974d73040fec59c68957ce21be60634627039b3e7cab6'
CLEAN = R/'epoch166-independent-closed-accounts-20261122-v1'
ROOT_SHA = '02ca91b396f6bc9327b626eb80583af4ce004d63fb6854c7a5e2c50f38c12329'
PARK = R/'epoch166-retry10-holding-20261122-v1'
ADMISSION_SHA = 'e9fd206ceb587186f439c8afa4b6e6d2eb4f3b64a024a09f7a286b9c4fef2d08'
START_SHA = '8439ad40268f89f9bcc94b511d21c6c7daf39139f284477bdd1a67099271dff9'
BASIS_SHA = 'd5071abe6d840e4cb0dd402ce75ee69e720543fb83005cc944dd939061aca7e5'
GUARD_ROOT = R/'epoch166-retry11-guard-20261122-v1'


def failed(s, fit, fleet, rows):
    failure = fleet['cold166_retry11_write_version_failure']
    root = R/DIRECTORY
    terminal = s.bound(failure['terminal'], root/'WRITE_VERSION_TERMINAL_20261124.json')
    admission = s.bound(failure['admission'], root/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    worker = s.bound(failure['first_worker'], root/'FIRST_PROTECTED_WORKER.json')
    plan = s.bound(admission['actual_guard_plan'], root/'ACTUAL_GUARD_PLAN.json')
    iid = failure['producer_invocation_id']
    exit_event = terminal['pid1_exit']
    s.need(166 not in rows and
           terminal['schema'] == 'horizon-epoch166-retry11-write-version-terminal-v1'
           and terminal['epoch'] == admission['epoch'] == 166 and worker['admission'] == failure['admission']
           and terminal['producer_invocation'] == admission['producer_invocation_id'] == worker['producer_invocation_id'] == iid
           and exit_event['_PID'] == '1' and exit_event['UNIT'] == admission['producer_unit'] == UNIT
           and exit_event['INVOCATION_ID'] == iid and exit_event['EXIT_CODE'] == 'exited'
           and exit_event['EXIT_STATUS'] == '1'
           and terminal['guard_timer_before']['InvocationID'] == admission['timer_invocation_id']
           and admission['timer_unit'] == TIMER and plan['worker_root'] == str(LANE)
           and plan['maximum_root_physical_bytes'] == 288 << 30
           and plan['unit'] == UNIT and plan['invocation_id'] == iid
           and failure['reservation_ending_bytes'] == terminal['resource_credit_bytes'] == 0,
           'failed epoch 166 terminal or retained booking differs')
    for unit in (UNIT, TIMER.removesuffix('.timer') + '.service'):
        meta = s.show(unit)
        s.need(meta['ActiveState'] in ('failed', 'inactive') and not meta['Job']
               and meta['MainPID'] == meta['ControlPID'] == '0' and not fit.members(unit),
               'failed epoch 166 producer or guard is still live')
    timer = s.show(TIMER)
    s.need(timer['ActiveState'] == 'inactive' and not timer['Job'], 'failed epoch 166 timer is still live')
    stable(s)
    return failure


def stable(s):
    source, ref = s.read(CLEAN/'SUCCESSOR_ROOT.json', ROOT_SHA)
    info = RUN.lstat()
    s.need(source['root'] == str(RUN) and source['parent'] == str(PREVIOUS_RUN)
           and source['worker_launched'] is False and RUN.resolve(strict=True) == RUN
           and (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode) ==
               tuple(source[k] for k in ('device','inode','uid','gid','mode'))
           and (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)) == (1001,1003,0o700),
           'wrong retry11 run root')
    return ref


def holding(s, fit, fleet):
    admission, ar = s.read(PARK/'PARK_ADMISSION.json', ADMISSION_SHA)
    start, sr = s.read(PARK/'PARK_START.json', START_SHA)
    basis, br = s.read(PARK/'HOLDING_PRICE_BASIS.json', BASIS_SHA)
    populated = s.bound(admission['inputs'], PARK/'PREPARED.json')
    plan = s.bound(admission['plan'], PARK/'package/plan.json')
    old = s.bound(admission['fit'], PARK/'PARK_FIT.json')
    clean = [s.bound(r,CLEAN/'state'/label/'COMPLETE.json') for r,label in zip(admission['cleanup'],('local3retry9','local3retry10'),strict=True)]
    s.need(all(v['scope_empty'] and not v['archive_or_snapshot_removed'] and v['resource_credit_bytes']==0 for v in clean)
           and sum(v['retired_tree_before_bytes']-v['scope_root_remaining_bytes'] for v in clean)==admission['actual_retired_allocated_bytes']
           and old['fits'] and start['admission']==ar and admission['plan']==populated['park_spec']
           and plan['sha256']=='dfddb43b910008e87d319638dcd6dce950b8d5fc298ff412e3a3ac82afad6128'
           and plan['length']==admission['restore_overlap_bytes']==basis['private_restore_bytes']==64922604512
           and admission['cap']==288<<30 and admission['archive_staging_bytes']==admission['resource_credit_bytes']==0,
           'foreign retry11 cleanup or holding admission')
    promise = fleet['retry9_auxiliary_commitments']
    s.need(promise['holding_serial'] and promise['holding_and_build_may_overlap'] and
           promise['holding_cpu_quota_micros']==admission['cpu']==2000000 and
           promise['holding_memory_bytes']==admission['memory']==2<<30 and
           promise['holding_staging_bytes']==0 and promise['holding_restore_overlap_bytes']>=plan['length'],
           'holding exceeds the original fleet booking')
    unit=admission['unit']; ticket=start['native']; m=s.show(unit)
    s.need(unit=='horizon-closed166-retry10-park-20261122-v1.service' and m['InvocationID']==ticket['InvocationID']
           and m['CPUQuotaPerSecUSec']=='2s' and m['MemoryMax']==str(2<<30) and m['MemorySwapMax']=='0' and m['NRestarts']=='0',
           'different paid holding unit or limits')
    members=fit.members(unit)
    if members:
        pid=int(ticket['MainPID']); proc=Path('/proc')/str(pid); _,ticks,group=s.process(pid)
        s.need(m['ActiveState'] in ('active','activating') and m['MainPID']==str(pid) and members==(pid,)
               and ticks==int(start['start_ticks']) and group=='0::/system.slice/'+unit
               and proc.joinpath('cmdline').read_bytes().split(b'\0')==[os.fsencode(x) for x in basis['park_argv']]+[b'']
               and s.same_file(proc/'exe',Path(populated['registered_image']['path'])), 'foreign holding process')
        stage='copy-only'
    else:
        s.need(m['MainPID']=='0' and m['ActiveState']=='active' and m['SubState']=='exited' and m['ExecMainStatus']=='0'
               and m['Result']=='success' and not m['Job'], 'holding unit not successfully drained')
        stage='completed-copy'
    return dict(admission=ar,start=sr,basis=br,stage=stage,unit=unit,invocation_id=m['InvocationID'],
                actual_scratch_retirement=admission['cleanup'],stage_bytes=0,restore_overlap_bytes=plan['length'],
                additional_reservation_bytes=0,resource_credit_bytes=0)


def guard(s, prepared):
    qualified, qr = s.read(GUARD_ROOT/'GUARD_QUALIFIED.json', 'd43d47340cc01d97cea8a37bdff9ac2d27762761c4cbb74f0d8740dda9e5ea22')
    image=GUARD_ROOT/'tools/guard'; digest=prepared['profile']['guard_binary_sha256']
    seal=s.bound(qualified['seal'],image.parent/'deployment-seal-receipt.json')
    contract=qualified['contract']; terms=s.bound(contract['contract'],GUARD_ROOT/'contract/contract.json')
    s.bound(contract['deployment_seal'],GUARD_ROOT/'contract/deployment-seal-receipt.json')
    witness=s.bound(terms['qualified_native_witness'],GUARD_ROOT/'NATIVE_WITNESS.json')
    s.need(qualified['schema']=='horizon-166-retry11-native-guard-qualified-v1' and
           qualified['guard']==dict(path=str(image),sha256=digest) and seal['destination']==str(image.parent)
           and any(x['name']=='guard' and x['sha256']==digest for x in seal['members'])
           and witness['native_identity']['executable']==str(image) and witness['native_identity']['executable_sha256']==digest
           and hashlib.sha256(image.read_bytes()).hexdigest()==digest, 'wrong retry11 qualified guard')
    return digest,contract


def readonly_mounts(s, proc, pairs):
    """Verify each producer-namespace bind resolves to the enrolled source inode and is read-only."""
    mounts = {}
    for line in (proc / 'mountinfo').read_text().splitlines():
        parts = line.split()
        target = Path(parts[4])
        if target in pairs:
            s.need(target not in mounts, 'ambiguous input mount')
            mounts[target] = parts[5].split(',')
    for target, source in pairs.items():
        actual = proc / 'root' / target.relative_to('/')
        s.need(source.resolve(strict=True) == source and s.same_file(actual, source)
               and 'ro' in mounts.get(target, ()), 'changed or writable retry11 input: ' + str(target))


def mounted_inputs(s, prepared, intent, proc):
    """Bind the current namespace to the five inputs verified by the native cold session."""
    b = prepared['baseline']
    profile = prepared['profile']
    s.need(b['profile'] == profile and prepared['indexes'] == profile['indexes']
           and b['stable_roots'] == s.ref(CLEAN / 'SUCCESSOR_ROOT.json', ROOT_SHA)
           and intent['stable_root'] == b['root'] == {
               'path': str(RUN), 'device': RUN.stat().st_dev, 'inode': RUN.stat().st_ino},
           'different retry11 prepared source or root')
    prior, _ = s.read(STOP_PATH.parents[1] / 'PREPARED.json',
                      '3da08c1ba5947e439877c984f60f297178733ee06e230cc96564b11a11d754d5')
    prior_indexes = prior['indexes']
    pairs = {}
    s.need(len(prior_indexes) == len(prepared['indexes']) == 3, 'missing retry11 indexes')
    for previous, current in zip(prior_indexes, prepared['indexes'], strict=True):
        target = RUN / Path(previous['target']).relative_to(PREVIOUS_RUN)
        s.need(current == {**previous, 'target': str(target)}, 'different retry11 index registration')
        source = Path(current['path'])
        st = source.lstat()
        s.need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and (st.st_uid, st.st_gid) == (1001, 1003)
               and [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns] == current['identity'],
               'changed retained compact index')
        pairs[target] = source
    old = prior['baseline']['snapshot']
    view = Path(old['path'])
    snap = b['snapshot']
    src = Path(snap['path'])
    st = src.lstat()
    s.need(src.is_relative_to(PREVIOUS_RUN / 'private') and src.name == view.name
           and stat.S_ISREG(st.st_mode) and (st.st_uid, st.st_gid, st.st_nlink) == (1001, 1003, 1)
           and (snap['device'], snap['inode'], snap['length']) == (st.st_dev, st.st_ino, st.st_size)
           == (64512, 93782058, old['length']) and snap['ctime'] == list(divmod(st.st_ctime_ns, 10**9))
           and snap['sha256'] == old['sha256'] and snap['generation'] == old['generation'],
           'foreign retry11 HOME snapshot')
    pairs[view] = src
    pairs[RUN / 'output/genesis.tar.bz2'] = view.parent / 'genesis.tar.bz2'
    s.need(len(pairs) == 5, 'overlapping cold input mount targets')
    readonly_mounts(s, proc, pairs)


def observe(s, fit, native_actor, own):
    stable(s)
    stopped, stop=s.read(STOP_PATH,STOP_SHA)
    s.need(stopped['producer_invocation_id']==PREVIOUS_IID and stopped['terminal']['active']=='inactive'
           and not fit.members(PREVIOUS_UNIT) and s.show(PREVIOUS_UNIT)['ActiveState']=='inactive',
           'retry10 still running')
    predecessor={'original':{'producer_invocation_id':PREVIOUS_IID}, 'stop_completion':stop}
    return native_actor(166,own,LANE,RUN,predecessor,generation=(DIRECTORY,NAME))
