"""Refresh the exact event-created private verifier status alongside the legacy nineteen."""
import datetime as dt
import json
from pathlib import Path
import time

from evidence import BASE,EPOCHS,bound,checked,digest,durable,need,utc

ROOT=BASE/'prefix140-status-cadence-20261122-v1'
KEY='epoch-140.epoch-status.json'
FIELDS={'epoch','jet_size_bytes','elapsed_execution_millis','estimated_remaining_millis','sampled_at_utc','phase'}

def initial():
    gate=ROOT/'INITIAL.json'
    if not gate.exists():return None
    ref=checked(bound(gate))['receipt']
    row=checked(ref)
    need(row['epoch']==140 and row['key']==KEY and row['authenticated_readback'] is True
         and row['conditional_header'] in ('If-None-Match','If-Match')
         and row['after_status']['epoch']==140 and set(row['after_status'])==FIELDS,
         'foreign private 140 initial event')
    return ref

def listed(c,statuses):
    old=set(EPOCHS)
    need(statuses==old or statuses==old|{140},'unregistered public status inventory change')
    if statuses==old:
        need(initial() is None and not c.fleet.get('current_private140_status_receipt'),'registered private 140 disappeared from inventory')
        c.private140_listed=False
        return
    c.private140_listed=True
    until=time.monotonic()+120
    while initial() is None and time.monotonic()<until:time.sleep(1)
    need(initial() is not None,'no authenticated event registration for listed private epoch 140')

def body(v):
    return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()

def authenticate(row,etag,raw):
    need(row['authenticated_readback'] and row['epoch']==140 and row['key']==KEY
         and row['after_etag']==etag and row['after_sha256']==digest(raw) and row['after_status']==json.loads(raw),
         'foreign or changed private 140 status')

def refresh(c,store,out,original):
    if not c.private140_listed:return original
    primary=checked(original);need(set(map(int,primary['receipts']))==set(EPOCHS) and 140 not in primary['ready_epochs'],'split private status inventory')
    parent=c.fleet.get('current_private140_status_receipt') or initial()
    prior=checked(parent)
    dest=out/'epoch-140.receipt.json';pending=out/'epoch-140.intent.json'
    etag,raw=store.get(140)
    if dest.exists():
        rec=checked(bound(dest));authenticate(rec,etag,raw)
        need(rec['previous_receipt']==parent and rec['observer']==c.sample_ref and rec['fleet_predecessor']==c.fleet_ref,'foreign completed private status')
    else:
        if pending.exists():
            plan=checked(bound(pending))
            need(plan['previous_receipt']==parent and plan['observer']==c.sample_ref and plan['fleet_predecessor']==c.fleet_ref,'foreign pending private status')
        else:
            authenticate(prior,etag,raw)
            old=prior['after_status'];ms=round((utc(c.stamp)-utc(old['sampled_at_utc'])).total_seconds()*1000)
            if ms<=0:
                need(bytes(raw)==body(old) and initial()==parent,'newer private status is not the authenticated initial event')
                plan=None
            else:
                after=dict(old,sampled_at_utc=c.stamp,elapsed_execution_millis=old['elapsed_execution_millis']+ms,
                           estimated_remaining_millis=max(0,old['estimated_remaining_millis']-ms))
                plan=dict(schema='private-epoch140-scheduled-status-refresh-v1',epoch=140,key=KEY,conditional_header='If-Match',
                          observer=c.sample_ref,fleet_predecessor=c.fleet_ref,previous_receipt=parent,sampled_at_utc=c.stamp,
                          before_etag=etag,before_sha256=digest(raw),before_status=old,after_status=after,
                          after_sha256=digest(body(after)),forecast='Carry the authenticated absolute delivery estimate and advance elapsed wall time.')
                durable(pending,plan)
        if plan is not None:
            if etag==plan['before_etag'] and digest(raw)==plan['before_sha256']:
                put_etag=store.put(140,etag,body(plan['after_status']))
                etag,raw=store.get(140)
                need(put_etag==etag,'private 140 conditional ETag readback changed')
            need(raw==body(plan['after_status']) and digest(raw)==plan['after_sha256'],'private 140 conditional readback mismatch')
            durable(dest,dict(plan,after_etag=etag,authenticated_readback=True))
    ref=bound(dest) if dest.exists() else parent
    authenticate(checked(ref),etag,raw)
    all_rows=dict(primary['receipts']);all_rows['140']=ref
    whole=out/'COMPLETE_ACTIVE_STATUSES.json'
    durable(whole,dict(schema='horizon-all-current-authenticated-statuses-v1',observer=c.sample_ref,fleet_predecessor=c.fleet_ref,
                       sampled_at_utc=c.stamp,authenticated_readback=True,authenticated_status_count=len(all_rows),
                       status_epochs=sorted(map(int,all_rows)),receipts=all_rows,original_nineteen=original,private140=ref,initial_event=initial()))
    return original

def reconcile(c,f,statusref):
    path=c.paths['statuses']/'COMPLETE_ACTIVE_STATUSES.json'
    if not path.exists():
        need(not c.fleet.get('current_private140_status_receipt'),'incomplete private 140 cadence')
        return
    complete=bound(path);all_rows=checked(complete);prior=checked(statusref)
    need(all_rows['original_nineteen']==statusref and all_rows['observer']==c.sample_ref and all_rows['fleet_predecessor']==c.fleet_ref
         and all_rows['receipts']==dict(prior['receipts'],**{'140':all_rows['private140']}) and len(all_rows['receipts'])==20,
         'split public and private 140 status generation')
    f['current_private140_status_receipt']=all_rows['private140']
    f['complete_active_status_audit']=complete
    f['complete_active_status_count']=20
    f['complete_active_status_receipts']=all_rows['receipts']
    f['authenticated_status_audit_scope']='Original nineteen, retained to reproduce existing native price and admission contracts; complete active set is complete_active_status_audit.'
