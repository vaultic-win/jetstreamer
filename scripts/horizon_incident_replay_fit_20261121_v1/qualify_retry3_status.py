"""Test the registered retry3 status selector using the installed reader and private simulated handoffs."""
import copy
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
R=Path('/var/lib/jetstreamer/horizon_runtime_data')
sys.path.insert(0,str(R/'epoch168-full-metered-20261121-v1/session-v4-registered136'))
import status168 as real


def exercise(scratch, retry4=False):
    attempt = 4 if retry4 else 3
    previous_attempt = attempt - 1
    failure_key = f'failed_retry{previous_attempt}'
    library=runpy.run_path(str(HERE/f'retry{attempt}_status.py'))
    select=library['registered_writer']
    values=select.__globals__
    real_status=values['STATUS']
    previous, pref=real.read(real_status/f'COLD168_RETRY{previous_attempt}_V1_STATUS_ACTIVE.json',values['PREDECESSOR'])
    original=previous['new']
    qual, qr=real.read(real_status/(values['PREFIX']+'QUALIFIED.json'))
    qref=qual['generation']
    enrolled=real.bound(qref,Path(qref['path']))
    prepared, guard=enrolled['prepared']['sha256'],enrolled['guard_qualification']['sha256']
    oldpkg=real_status/f'tools-cold168-retry{previous_attempt}-v1'
    oldseal=real.ref(oldpkg/'deployment-seal-receipt.json',values['PRIOR_SEAL'])
    original_tuple=(oldpkg,oldseal,original['invocation_id'],original)
    if not (real_status/(values['PREFIX']+'ACTIVE.json')).exists() and not (real_status/(values['PREFIX']+'ROLLBACK.json')).exists():
        assert select(real,original_tuple,prepared,guard)==original_tuple
    temp=Path(scratch)
    priorpkg=temp/oldpkg.name
    priorseal=dict(oldseal,path=str(priorpkg/'deployment-seal-receipt.json'))
    old=dict(original,program=str(priorpkg/'status_cycle.py'))
    previous=dict(previous,new=old)
    prior=(priorpkg,priorseal,old['invocation_id'],old)
    pkg=temp/f'tools-cold168-retry{attempt}-v1'
    translated=lambda ref: dict(ref,path=str(pkg/Path(ref['path']).name))
    q=copy.deepcopy(qual)
    for field in ('package','generation','entry'):
        q[field]=translated(qual[field])
    sref=real.read(Path(qual['package']['path']))[0]
    seal=dict(sref,destination=str(pkg))
    actor=dict(old,program=str(pkg/'status_cycle.py'),pid=1234,start_ticks=12345,invocation_id='a'*32)
    schedule={'fleet':{'path':'fixture','sha256':'b'*64}}
    binding=dict(old=old,qualified=qr,admission=q['prepared'],prepared=q['prepared'],generation=q['generation'],
                 previous_active=pref,**{failure_key:q[failure_key]})
    intent=dict(**binding,schedule=schedule)
    intentref={'path':str(temp/(values['PREFIX']+'INTENT.json')),'sha256':'1'*64}
    active=dict(**binding,new=actor,schedule=schedule,schema=f'horizon-168-retry{attempt}-v1-status-active-v1',intent=intentref)
    previous_path=temp/f'COLD168_RETRY{previous_attempt}_V1_STATUS_ACTIVE.json'
    paths={kind:temp/(values['PREFIX']+kind+'.json') for kind in ('QUALIFIED','INTENT','ACTIVE','ROLLBACK')}
    first_rollback={'path':str(paths['ROLLBACK']),'sha256':'e'*64}
    rollback_actor=dict(old,invocation_id='d'*32,pid=12346,start_ticks=12347)
    rollback=dict(restored=rollback_actor,intent=intentref,schedule=schedule)
    records={previous_path:(previous,pref),paths['QUALIFIED']:(q,qr),paths['INTENT']:(intent,intentref),
             paths['ACTIVE']:(active,{}),paths['ROLLBACK']:(rollback,first_rollback)}
    def read(path,digest=None):
        if path not in records:
            return real.read(path,digest)
        data, ref=records[path]
        if digest:
            assert ref['sha256']==digest
        return data,ref
    extra={q['package']['path']:seal,q['generation']['path']:enrolled}
    def bound(ref,path):
        assert ref['path']==str(path)
        return extra[str(path)] if str(path) in extra else real.bound(ref,path)
    s=SimpleNamespace(read=read,need=real.need,bound=bound,iid=real.iid,ref=real.ref,
                      show=lambda unit:{'InvocationID':rollback_actor['invocation_id']})
    denied=[]
    bootstrap_controls=[]
    if retry4:
        failed_path=values['PRIOR']/'RELEASED_NODE_STARTUP_FAILURE_20261123.json'
        failed,failed_ref=real.read(failed_path,values['FAILURE'])
        admission_ref=failed['receipts']['ACTUAL_ADMISSION_AND_PROTECTION.json']
        admitted_path=Path(admission_ref['path'])
        admitted=real.bound(admission_ref,admitted_path)
        records[failed_path]=(failed,failed_ref)
        records[admitted_path]=(admitted,admission_ref)
        bootstrap_controls=[(failed,'no_admission_record',True),(failed,'bootstrap_admission',False),
                            (failed,'worker_in_observed_guard_samples',True),(failed,'worker_receipt_absent',False),
                            (admitted,'producer_pid',0),(admitted,'producer_invocation_id','e'*32),
                            (admitted,'bootstrap_only',False),(admitted,'transaction_replay_claimed',True)]
    with patch.dict(values,STATUS=temp):
        assert select(s,prior,prepared,guard)==prior
        paths['ACTIVE'].touch()
        assert select(s,prior,prepared,guard)==(pkg,q['package'],actor['invocation_id'],actor)
        for record,key,value in [(previous,'new',{}),(q,failure_key,{}),(q,'generation',dict(q['generation'],sha256='a'*64)),
                                 (q,'guard',{}),(q,'entry',{}),(intent,'previous_active',{}),(intent,'old',{}),
                                 (active,'schema','different'),(active,'schedule',{}),(active,'intent',{}),
                                 (actor,'program','foreign'),(actor,'lock',dict(actor['lock'],inode=1))]:
            with patch.dict(record,{key:value}):
                try:select(s,prior,prepared,guard)
                except (ValueError,AssertionError):denied.append(key)
                else:raise AssertionError('accepted changed '+key)
        for rec,key,value in bootstrap_controls:
            with patch.dict(rec,{key:value}):
                try:select(s,prior,prepared,guard)
                except (ValueError,AssertionError):pass
                else:raise AssertionError('accepted changed bootstrap '+key)
        paths['ACTIVE'].unlink()
        paths['ROLLBACK'].touch()
        assert select(s,prior,prepared,guard)==(priorpkg,priorseal,rollback_actor['invocation_id'],rollback_actor)
        second=dict(rollback_actor,invocation_id='f'*32)
        second_path=temp/(values['PREFIX']+'ROLLBACK_'+second['invocation_id']+'.json')
        records[second_path]=(dict(restored=second,intent=intentref,schedule=schedule,original_rollback=first_rollback),{})
        s.show=lambda unit: {'InvocationID':second['invocation_id']}
        assert select(s,prior,prepared,guard)==(priorpkg,priorseal,second['invocation_id'],second)
        with patch.dict(records[second_path][0],original_rollback={}):
            try:select(s,prior,prepared,guard)
            except ValueError:denied.append('original_rollback')
            else:raise AssertionError('accepted changed rollback')
    return dict(previous=pref,qualification=qr,actual_prepared=enrolled['prepared'],actual_guard=enrolled['guard_qualification'],
                controls=denied,bootstrap_controls=[key for _,key,_ in bootstrap_controls],simulated_handoffs=['success','rollback','repeated rollback'],physical_service_changes=0,r2_writes=0)


if __name__=='__main__':
    assert len(sys.argv) in (2,3) and sys.argv[2:] in ([],['--retry4'])
    parent=Path(sys.argv[1]).resolve(strict=True)
    assert parent.is_relative_to('/home/sol')
    with tempfile.TemporaryDirectory(dir=parent) as directory:
        print(json.dumps(exercise(directory, sys.argv[2:]==['--retry4']),sort_keys=True))
