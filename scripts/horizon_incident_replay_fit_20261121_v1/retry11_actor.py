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
    qualified, qr = s.read(GUARD_ROOT/'GUARD_QUALIFIED.json')
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


def observe(s, fit, native_actor, own):
    stable(s)
    stopped, stop=s.read(STOP_PATH,STOP_SHA)
    s.need(stopped['producer_invocation_id']==PREVIOUS_IID and stopped['terminal']['active']=='inactive'
           and not fit.members(PREVIOUS_UNIT) and s.show(PREVIOUS_UNIT)['ActiveState']=='inactive',
           'retry10 still running')
    predecessor={'original':{'producer_invocation_id':PREVIOUS_IID}, 'stop_completion':stop}
    return native_actor(166,own,LANE,RUN,predecessor,generation=(DIRECTORY,NAME))
