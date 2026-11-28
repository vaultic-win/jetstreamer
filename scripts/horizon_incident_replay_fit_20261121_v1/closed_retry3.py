"""Validate the specific admitted epoch 168 bootstrap that exited at its atomic publication probe."""
from pathlib import Path

ROOT=Path('/var/lib/jetstreamer/horizon_runtime_data/epoch168-retry3-rebook-20261123-v1')
FAILURE='cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21'
ADMISSION='8dd692fda6b1098a22a2162792e7165005692385795e6cae72b6df472c7e83c0'
IID='032cb7da1929485994cf18b384c93459'
UNIT='horizon-qualify-168-full-metered-cold-v3-20261123.service'
TIMER='horizon-guard-168-full-metered-cold-v3-20261123.timer'


def settled(s,fit):
    failed,fr=s.read(ROOT/'RELEASED_NODE_STARTUP_FAILURE_20261123.json',FAILURE)
    data=failed['receipts']
    admission,ar=s.read(ROOT/'ACTUAL_ADMISSION_AND_PROTECTION.json',ADMISSION)
    s.need(failed['schema']=='horizon-168-released-node-publication-probe-failure-v1'
           and failed['epoch']==168 and failed['bootstrap_admission'] and not failed['no_admission_record']
           and failed['permit_consumed'] and failed['worker_receipt_absent'] and not failed['worker_in_observed_guard_samples']
           and not failed['replay_claimed'] and not failed['r2_mutations']
           and 'Invalid cross-device link (os error 18)' in failed['node_error'] and len(failed['guard_samples'])==4
           and ar==data['ACTUAL_ADMISSION_AND_PROTECTION.json']
           and admission['producer_invocation_id']==IID and admission['producer_pid']==889002 and admission['producer_unit']==UNIT
           and admission['stage']=='node' and admission['bootstrap_only'] and not admission['transaction_replay_claimed']
           and admission['source']==data['PREPARED.json'] and admission['intent']==data['START_INTENT.json']
           and admission['first_guard']==data['FIRST_GUARD.json'] and admission['post_guard_capacity']==data['POST_GUARD_CAPACITY.json'],
           'unbound failed retry3 bootstrap')
    node=s.bound(data['NODE_AFTER_PERMIT.json'],ROOT/'NODE_AFTER_PERMIT.json')
    permit=s.bound(data['AUTHORIZED_GATED_PAYLOAD.json'],ROOT/'AUTHORIZED_GATED_PAYLOAD.json')
    s.need(node['authorization']==data['AUTHORIZED_GATED_PAYLOAD.json'] and all(
        record['producer_invocation_id']==IID and record['producer_pid']==admission['producer_pid']
        and record['start_ticks']==admission['start_ticks'] for record in (node,permit))
        and permit['post_guard_capacity']==admission['post_guard_capacity'], 'different retry3 promotion')
    path=ROOT/'barrier/allow'
    m=path.lstat()
    s.need((m.st_uid,m.st_gid,m.st_mode,m.st_nlink)==(0,0,0o100444,1) and
           path.read_bytes()==IID.encode() and not (ROOT/'FIRST_PROTECTED_WORKER.json').exists(),
           'different retry3 permit or recorded historical worker')
    producer=s.show(UNIT);timer=s.show(TIMER);guard=s.show(TIMER.removesuffix('.timer')+'.service')
    s.need(producer['Id']==UNIT and producer['InvocationID']==IID and producer['ActiveState']==producer['SubState']=='failed' and
           producer['Result']=='exit-code' and producer['ExecMainStatus']=='1' and producer['NRestarts']=='0'
           and producer['MainPID']==producer['ControlPID']=='0' and not producer['Job'] and not fit.members(UNIT)
           and timer['Id']==TIMER and guard['Id']==TIMER.removesuffix('.timer')+'.service' and
           all(m['ActiveState']=='inactive' and m['SubState']=='dead' and not m['Job'] for m in (timer,guard)) and
           guard['MainPID']=='0' and not fit.members(guard['Id']), 'retry3 generation is not drained')
    return dict(failure=fr,admission=ar,unit=UNIT,invocation_id=IID,producer_pid=0,executing=False,
                bootstrap_admission=True,worker_receipt_absent=True,resource_credit_bytes=0)
