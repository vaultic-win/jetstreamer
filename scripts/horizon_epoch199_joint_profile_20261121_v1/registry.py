"""Register each exclusive, authenticated original reservation with the existing fleet writer."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

B=Path('/var/lib/jetstreamer/horizon_runtime_data/epoch199-delivery-recovery-20261121-v1')
P=B/'phase-transition-v1'
REG=B/'phase-handoffs'
KEY='epoch199200_exclusive_phase_transfers'
ROOTS={166:'epoch166-independent-cold-20261120-v1',167:'epoch167-standard-lane-20261109-v1',168:'epoch168-standard-lane-20261109-v1',170:'epoch170-standard-lane-20261109-v1',172:'epoch172-standard-lane-20261110-v1'}

def service():
    seal=(P/'deployment-seal-receipt.json').read_bytes()
    if hashlib.sha256(seal).hexdigest()!='10d37c49a49f7144433955251127d4daebd2729d2e92cfaaeae8696fa01ca5b4':
        raise ValueError('unqualified 199/200 recipient')
    for row in json.loads(seal)['members']:
        path=P/row['name']
        if path.resolve(strict=True)!=path or path.stat().st_uid!=0 or path.stat().st_mode&0o222 or hashlib.sha256(path.read_bytes()).hexdigest()!=row['sha256']:
            raise ValueError('changed 199/200 enrollment package')
    return runpy.run_path(str(P/'transition_fit.py'))

def book(f,epoch):
    return dict(root=str(Path('/home/sol/.jetstreamer-private')/ROOTS[epoch]),cap_bytes=f['T']['ALL_CAP'][epoch])

def terminal_path(f,epoch):
    if epoch==166:
        return B.parent/'epoch166-retry10-terminal-20261121-v1/TERMINAL_SUCCESS.json'
    return f['delivery'](epoch)/'TERMINAL_SUCCESS.json'

def apply(fleet):
    """Called by the single normal fleet writer on its pending, complete in-memory result."""
    if os.geteuid()!=0 or not sys.flags.isolated or not __debug__:
        raise ValueError('isolated controlling fleet required')
    existing=fleet.get(KEY,{})
    present={str(e):REG/f'{e}.json' for e in ROOTS if (REG/f'{e}.json').exists()}
    if not present and not existing:
        return fleet
    f=service();need=f['need'];_,event=f['helpers']()
    need(fleet['owner']=='/root' and fleet['schema']=='horizon-Root-complete-fleet-operational-review-v1' and fleet['all_active_status_reports_authenticated_readback'] is True and fleet['all_reservation_ending_bytes']==0 and isinstance(existing,dict),'different fleet writer')
    result={}
    for k,p in present.items():
        e=int(k);record,ref=event['document'](p,0o400)
        term,tr=event['document'](terminal_path(f,e),0o400)
        need(term['epoch']==e and term['producer_invocation_id']==f['T']['GENERATIONS'][e] and fleet.get(f['FIELD'][e])==tr and tr==record['terminal'],'grant predates the accepted original terminal')
        f['transfer'](event,e,ref,dict(terminal=tr),book(f,e),fleet)
        result[k]=ref
    need(all(result.get(k)==v for k,v in existing.items()),'prior exclusive transfer missing or changed')
    fleet[KEY]=result
    return fleet

def prepare(epoch,commit=False):
    """Use a root-approved repair assessment and completed original sync to calculate one grant."""
    f=service();need=f['need'];pub,event=f['helpers']()
    need(os.geteuid()==0 and sys.flags.isolated and __debug__ and epoch in ROOTS,'isolated root required')
    destination=REG/f'{epoch}.json';assessment=REG/f'{epoch}-repair.json'
    # A missing prerequisite never starts a physical capacity capture.
    if not terminal_path(f,epoch).exists() or not assessment.exists():
        return dict(outcome='awaiting-original-terminal-and-repair-assessment',epoch=epoch,resource_credit_bytes=0)
    term,tr=event['document'](terminal_path(f,epoch),0o400)
    repair,rr=event['document'](assessment,0o400)
    fleet,fr=f['head'](event)
    need(fleet.get(f['FIELD'][epoch])==tr and term['producer_invocation_id']==f['T']['GENERATIONS'][epoch],'original terminal not accepted')
    syncs=sorted(f['delivery'](epoch).glob(f'run-*/receipts/epoch-{epoch}.r2.json'))
    if not syncs:
        return dict(outcome='awaiting-original-verified-publication',epoch=epoch,terminal=tr,resource_credit_bytes=0)
    if destination.exists():
        prior,pr=event['document'](destination,0o400)
        f['transfer'](event,epoch,pr,dict(terminal=tr),book(f,epoch),fleet)
        return dict(outcome='existing-exclusive-transfer',epoch=epoch,receipt=pr,transfer=prior)
    with (REG/f'.{epoch}-issuance.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        # Both native captures must independently determine the stopped original footprint.
        cap=f['capture'](fr)
        values=[row['native']['bookings'][str(epoch)] for row in cap['records']]
        need(all(x['measurement']=='two complete stopped-tree walks' and x['root']==book(f,epoch)['root'] and x['cap_bytes']==book(f,epoch)['cap_bytes'] for x in values),'foreign or live booked tree')
        need(repair['owner']=='/root' and repair['epoch']==epoch and repair['terminal']==tr and repair['booked_root']==book(f,epoch)['root'] and type(repair['assessed_additional_growth_bytes']) is int and repair['assessed_additional_growth_bytes']>=0,'unaccepted repair-growth assessment')
        retained=f['T']['BOOK']+repair['assessed_additional_growth_bytes']
        amount=max(0,min(x['remaining_bytes'] for x in values)-retained)
        candidates=[]
        for p in syncs:
            sync,sr=event['document'](p,0o600)
            if sync['archive_sha256']==term['local_archive']['sha256']:
                candidates.append(sr)
        need(len(candidates)==1,'no unique sync of the exact original terminal')
        record=dict(schema='horizon-root-exclusive-phase-transfer-v1',owner='/root',origin_epoch=epoch,origin_generation=term['producer_invocation_id'],recipient='epoch199200-measured-through-import',terminal=tr,booked_root=values[-1]['root'],original_cap_bytes=values[-1]['cap_bytes'],exclusive_until_joint_import_reconciliation=True,replay_restart_claim_ended=True,retained_memory_bytes=2*f['T']['G'],retained_cpu_quota_micros=500000 if epoch==172 else 1000000,published_archive_retained_local=True,separate_historical_repair_promises_retained=True,repair_assessment=rr,retained_growth_bytes=retained,sync_receipt=candidates[0],maximum_transfer_bytes=amount,measured_native_captures=[v['sha256'] for v in cap['records']],issuance_fleet=fr)
        # Validate the proposed body through the same reader before publishing it
        # at its fixed, no-overwrite location. All referenced inputs use real FDs.
        proposed=(json.dumps(record,sort_keys=True)+'\n').encode()
        expected=dict(path=str(destination),sha256=hashlib.sha256(proposed).hexdigest())
        def pending_document(p,mode):
            if p==destination and mode==0o400:
                return record,expected
            return event['document'](p,mode)
        f['transfer'](dict(document=pending_document),epoch,expected,dict(terminal=tr),values[-1],fleet)
        need(f['head'](event)[1]==fr and event['document'](assessment,0o400)[1]==rr,'authority changed before grant')
        if not commit:
            return dict(outcome='priced-proposal',epoch=epoch,transfer=record,resource_credit_bytes=0)
        if destination.exists():
            need(event['document'](destination,0o400)[1]==expected,'conflicting concurrent grant')
        else:
            event['once'](destination,record)
        _,actual=event['document'](destination,0o400)
        need(actual==expected,'published grant differs')
        f['transfer'](event,epoch,actual,dict(terminal=tr),values[-1],fleet)
        return dict(outcome='awaiting-registration-in-normal-fleet',epoch=epoch,receipt=actual,resource_credit_bytes=0)

if __name__=='__main__':
    options=argparse.ArgumentParser()
    options.add_argument('command',choices=['prepare','issue'])
    options.add_argument('epoch',type=int,choices=ROOTS)
    args=options.parse_args()
    print(json.dumps(prepare(args.epoch,args.command=='issue'),sort_keys=True))
