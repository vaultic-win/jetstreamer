"""Hand the measured 20:47 dependency forecast to the existing 21:17 conditional status writer."""
import argparse
import ctypes
import datetime as dt
import errno
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = R/'survivor172-cadence-20261122-v1'
TOOLS = ROOT/'tools-cold167-v3'
SOURCE = Path('/home/sol/.jetstreamer-private/forecast-rebook167-20261122/actual-204757.json')
PLAN_SHA = '0c0f4a3a02ed353f7ecc946eb74258083d4b821460e3d0e4cd408d5f3011829e'
HEAD = {'path':str(R/'root204757-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),
        'sha256':'c1adb1440eb03a18e7932da7b1222fede46a7ff4b938f0c3ccedde93dbaba3a5'}
ACTIVE = {'path':str(ROOT/'COLD167_V3_STATUS_ACTIVE.json'),
          'sha256':'a0ab18c5bd28557884a837d0ad125f5535267c68eca73bd286682e9f43961a3f'}
OUT = ROOT/'dual-204757-dependent-forecast'
CHANGED = {137,140,141,159,161,163,173,185,186,199,200}
DUE = '2026-11-22T21:17:57Z'
SENT = 'SENT_TO_SOLE_WRITER.json'

def need(test,message):
    if not test:
        raise ValueError(message)

def hashed(path,digest):
    data=path.read_bytes()
    need(hashlib.sha256(data).hexdigest()==digest, 'changed source '+str(path))
    return data

def context():
    program=TOOLS/'status_cycle.py'
    hashed(program,'1eb66200c76f8da4399ccffd3b00af1322436b7e14ee2c076b03fb9cdf4687c0')
    c=runpy.run_path(str(program))
    handoff=ROOT/'handoff-68909c82/handoff_cold167.py'
    hashed(handoff,'71f6f047c3ce872264613d8d72cd3d4881e6b0c221021dd4a8661398cf5f7802')
    control=runpy.run_path(str(handoff));owner=c['checked'](ACTIVE)['new']
    need(control['publisher'](c,program)==owner,'status writer changed')
    fleet=c['checked'](HEAD);cfg=c['sealed'](fleet['sole_next_observer'])
    need(cfg['not_before_utc']==DUE and fleet['sole_next_observer']['sha256']=='ba991bbdaccd4b8bf3111962635c81230ac2bd6d425a5bbfbdc0c70b2e9dcc67','wrong next observer')
    paths=c['names'](DUE)
    model=json.loads(hashed(SOURCE,PLAN_SHA))
    need(model['actual_grants']==model['additional_credit_from_130']==0 and model['all_estimates_are_conditional']
         and model['latest_fleet']==HEAD and model['measured_167_basis']=='published dual observation'
         and model['selection']['sha256']=='fa98480f23467a67617cede1678f285a63a39b28262c6106caa75e5e3f19a079'
         and model['native_capacity']['sha256']=='453ec9d3dcc4bc7b0049374944ab5c121f3b471a28f32268e9ab5d613f8edecd',
         'incorrect dependency forecast basis')
    c['checked'](model['native_capacity'])
    refs=fleet['complete_active_status_receipts'];full=c['checked'](fleet['complete_active_status_audit'])
    need(refs==full['receipts'] and len(refs)==20 and set(refs)==set(model['comparison']),'incomplete prior statuses')
    need({int(k) for k,v in model['comparison'].items() if v['delta_ms']}==CHANGED,'foreign correction population')
    for key,result in model['comparison'].items():
        prior=c['checked'](refs[key]);body=prior['after_status']
        old=round(c['utc'](body['sampled_at_utc']).timestamp()*1000)+body['estimated_remaining_millis']
        need(result['previous']==refs[key] and result['projected_ms']==old+result['delta_ms'] and
             (int(key) not in CHANGED or (prior['current_repair_owner']=='/root' and body['phase']=='verification')),
             'forecast predecessor changed for '+key)
    return c,control,owner,fleet,cfg,paths,model

def preflight(c,control,owner,fleet,cfg,paths,model):
    control['timer_evidence'](c,HEAD)
    storage=c['status'].Storage()
    statuses,sidecars,archives=storage.inventory()
    need(statuses==set(map(int,model['comparison'])) and CHANGED.isdisjoint(sidecars|set(archives)),
         'archive identities or status population moved')
    readback={}
    for key,ref in fleet['complete_active_status_receipts'].items():
        prior=c['authenticated'](storage,int(key),ref)
        readback[key]=dict(receipt=ref,etag=prior['after_etag'],sha256=prior['after_sha256'])
    c['durable'](OUT/'PREPARED.json',dict(controller=ACTIVE,head=HEAD,config=fleet['sole_next_observer'],
        statuses=readback,changed=sorted(CHANGED),selected_plan=c['bound'](OUT/'PLAN.json'),remote_mutations=0))

def inputs(c,fleet,cfg,model,sample,observed_ref):
    recorded=c['check_sample'](fleet,sample,cfg)
    live={str(r['epoch']):r for r in fleet['actual_executing_replays']}
    need(live.keys()=={'167','172'},'different replay population')
    for row,actual in zip(cfg['replays'],sample['replays'],strict=True):
        key=row['range'];unit=live[key]['unit']
        need(c['cycle'].observed_lane(actual,row,unit['InvocationID'],int(unit['MainPID'])) and
             actual['useful_work']['counter_resets']==0 and row==live[key]['observer_config'],'changed native replay sample')
    models=c['bound'](OUT/'PLAN.json');when=round(c['utc'](recorded).timestamp()*1000)
    intents={}
    for epoch in sorted(CHANGED):
        key=str(epoch);result=model['comparison'][key];ref=fleet['complete_active_status_receipts'][key];prior=c['checked'](ref)
        old=prior['after_status'];age=when-round(c['utc'](old['sampled_at_utc']).timestamp()*1000)
        revised=dict(old,sampled_at_utc=recorded,elapsed_execution_millis=old['elapsed_execution_millis']+age,
                     estimated_remaining_millis=result['projected_ms']-when)
        need(age>=1800000 and revised['estimated_remaining_millis']>0 and set(revised)==c['status'].FIELDS and
             prior['producer_invocation_id'] is None and prior['measured_canonical_progress'] is False,'unexpected repair owner')
        intents[epoch]=dict(epoch=epoch,key=c['status'].key(epoch),previous_receipt=ref,conditional_header='If-Match',
            before_etag=prior['after_etag'],before_sha256=prior['after_sha256'],before_status=old,
            after_sha256=hashlib.sha256(c['status'].body(revised)).hexdigest(),after_status=revised,
            observer=observed_ref,fleet_predecessor=HEAD,sampled_at_utc=recorded,canonical_producer_count=2,
            active_bootstraps=0,current_replay_lanes=2,current_four_homefloor_stop=None,archive_publication_authorized=False,
            replay_launch_authorized=False,producer_invocation_id=None,measured_canonical_progress=False,
            current_repair_owner='/root',estimate_model='Conditional earliest joint start, from the measured 167/172 cycle.',
            model=models,preflight=c['bound'](OUT/'PREPARED.json'),prepared_by='stage_dual_forecasts.py',
            resource_credit_bytes=0,actual_grants=0)
    return intents

def stage_dir(c,target,intents):
    # Expose all eleven together before the existing writer opens the cycle status directory.
    # If the incumbent got here first, leave its entire cycle alone.
    tmp=Path(tempfile.mkdtemp(dir=target.parent,prefix='.prepared-dual-forecast-'))
    files=[]
    try:
        for epoch,plan in intents.items():
            p=tmp/f'epoch-{epoch}.intent.json';c['durable'](p,plan);files.append(p)
        rename=ctypes.CDLL(None,use_errno=True).renameat2
        rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
        if rename(-100,os.fsencode(tmp),-100,os.fsencode(target),1):
            n=ctypes.get_errno()
            if n==errno.EEXIST:
                need(all((target/p.name).is_file() and c['read_ref'](target/p.name)==plan
                         for p,plan in zip(files,intents.values(),strict=True)),'incumbent has already opened this cycle')
            else:raise OSError(n,os.strerror(n),target)
        else:
            fd=os.open(target.parent,os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(fd)
            finally:os.close(fd)
    finally:
        if tmp.exists():
            for p in files:p.unlink(missing_ok=True)
            tmp.rmdir()
    return {str(e):c['bound'](target/f'epoch-{e}.intent.json') for e in intents}

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=('preflight','stage','verify'))
    args=ap.parse_args()
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,'expected isolated root runner')
    c,control,owner,fleet,cfg,paths,model=context()
    c['ensure_dir'](OUT);c['durable'](OUT/'PLAN.json',model)
    if args.action=='preflight':
        preflight(c,control,owner,fleet,cfg,paths,model)
        return c['bound'](OUT/'PREPARED.json')
    prepared=c['read_ref'](OUT/'PREPARED.json')
    need(prepared['selected_plan']==c['bound'](OUT/'PLAN.json') and prepared['config']==fleet['sole_next_observer'],'different prepared forecast')
    if args.action=='stage':
        need(not (paths['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists(),'cycle already completed')
        while not paths['sample'].exists():
            need(c['now']()<c['utc'](DUE)+dt.timedelta(minutes=3),'native sample overdue')
            time.sleep(min(2,max(.1,(c['utc'](DUE)-c['now']()).total_seconds())))
        ref=c['bound'](paths['sample'])
        intents=inputs(c,fleet,cfg,model,c['checked'](ref),ref)
        need(control['publisher'](c,TOOLS/'status_cycle.py')==owner,'registered writer changed during sample')
        handed=stage_dir(c,paths['statuses'],intents)
        c['durable'](OUT/SENT,dict(sample=ref,inputs=handed,owner=owner,remote_writes=0))
        return c['bound'](OUT/SENT)
    latest=c['bound'](paths['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json')
    successor=c['checked'](latest);handoff=c['read_ref'](OUT/SENT);actual=successor['complete_active_status_receipts']
    need(successor['previous_Root_operational_review']==HEAD and successor['observer']==handoff['sample'] and
         len(actual)==20 and set(map(int,handoff['inputs']))==CHANGED,'incomplete handoff')
    storage=c['status'].Storage();readback={}
    for key,ref in actual.items():
        row=c['authenticated'](storage,int(key),ref)
        if int(key) in CHANGED:
            intent=c['checked'](handoff['inputs'][key])
            need(all(row[k]==v for k,v in intent.items()) and row['after_etag']!=row['before_etag'],
                 'publisher receipt differs from source intent')
        readback[key]=dict(receipt=ref,etag=row['after_etag'],sha256=row['after_sha256'])
    c['durable'](OUT/'FINAL_READBACK.json',dict(fleet=latest,handoff=c['bound'](OUT/SENT),statuses=readback,
        corrections=sorted(CHANGED),remote_writes_by_handoff=0))
    return c['bound'](OUT/'FINAL_READBACK.json')

if __name__=='__main__':
    print(json.dumps(main()))
