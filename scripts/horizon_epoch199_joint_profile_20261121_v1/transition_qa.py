"""Exercise exact HOME nesting, transfer cardinality, funding thresholds and source bindings."""
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys

HERE=Path(__file__).resolve().parent
F=runpy.run_path(str(HERE/'transition_fit.py'))
T=F['T']
B=F['B']
def receipts(epoch,mutate=None):
    # An in-memory provider exercises the exact production validator. No fake
    # object is written to a canonical destination or passed to a native guard.
    book=dict(root=f'/private/booked-{epoch}',cap_bytes=T['ALL_CAP'][epoch])
    records={}
    def add(path,data,mode):
        ref=dict(path=str(path),sha256=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest())
        records[str(path)]=(data,ref,mode)
        return ref
    def doc(path,mode):
        data,ref,want=records[str(path)]
        assert mode==want
        return data,ref
    iid='f'*32
    run=F['delivery'](epoch)/('run-'+iid)
    key=f'epoch-{epoch}.jet'
    assert F['FIELD'][epoch]
    term=add(F['delivery'](epoch)/'TERMINAL_SUCCESS.json',dict(epoch=epoch,transaction_id='t',local_archive=dict(sha256='a'*64,size=123,device=64512,inode=284)),0o400)
    adm=dict(publication_authorized=True,terminal_sha256=term['sha256'],transaction_id='t',operation='current-reader-sync-retain-local',invocation_id=iid,unit=F['UNITS'][epoch],archive_inode=284,archive_device=64512)
    obj=dict(bucket='solana-archive-with-accounts-data',key=key,length=123,sha256='a'*64,etag='123')
    play=dict(schema='horizon-r2-current-reader-playback-acceptance-v1',epoch=epoch,remote_playback=dict(object=obj,public_origin='https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev'))
    repair=dict(owner='/root',epoch=epoch,booked_root=book['root'],terminal=term,local_archive_retained=True,historical_provenance_retained=True,no_active_restore_or_repair_claim=True,assessed_additional_growth_bytes=4096)
    if mutate=='source-inode':adm['archive_inode']+=1
    if mutate=='missing-readback': play['remote_playback']['object']['sha256']='c'*64
    if mutate=='repair-pending': repair['no_active_restore_or_repair_claim']=False
    add(run/'admission.json',adm,0o400)
    playback=add(run/'scratch'/'epoch-test'/'remote-playback-acceptance.json',play,0o400)
    pub=dict(schema='jetstreamer-horizon-r2-receipt-v1',bucket='solana-archive-with-accounts-data',epoch=epoch,archive_key=key,checksum_key=key+'.sha256',archive_length=123,archive_sha256='a'*64,remote_sha256_readback=True,archive_etag='123',current_reader_playback=playback)
    if mutate=='wrong-sidecar':pub['checksum_key']=key+'.wrong'
    if mutate=='wrong-bucket':pub['bucket']='unrelated'
    sync=add(run/'receipts'/f'epoch-{epoch}.r2.json',pub,0o600)
    rr=add(F['REG']/f'{epoch}-repair.json',repair,0o400)
    transfer=dict(schema='horizon-root-exclusive-phase-transfer-v1',owner='/root',origin_epoch=epoch,origin_generation=T['GENERATIONS'][epoch],recipient='epoch199200-measured-through-import',terminal=term,booked_root=book['root'],original_cap_bytes=book['cap_bytes'],exclusive_until_joint_import_reconciliation=True,replay_restart_claim_ended=True,retained_memory_bytes=2*T['G'],retained_cpu_quota_micros=500000 if epoch==172 else 1000000,published_archive_retained_local=True,separate_historical_repair_promises_retained=True,repair_assessment=rr,retained_growth_bytes=T['BOOK']+4096,sync_receipt=sync,maximum_transfer_bytes=T['G'])
    if mutate=='wrong-owner':transfer['origin_generation']='0'*32
    if mutate=='other-recipient':transfer['recipient']='another replay'
    if mutate=='short-restore':transfer['retained_growth_bytes']-=1
    ref=add(F['REG']/f'{epoch}.json',transfer,0o400)
    result=F['transfer'](dict(document=doc),epoch,ref,dict(terminal=term),book,{})
    assert result==dict(retained_growth_bytes=T['BOOK']+4096,maximum_transfer_bytes=T['G'])

def main():
    pub,event=F['helpers']()
    fit=F['bound'](event,dict(path=str(B/'old166-census-6c327d0174a1466c833c84a00dd45164/FIT.json'),sha256='b0765f7b9c0f16b4708fef996c4c555f53a7f7521a677b910bbe618f750c5233'),0o400)
    ledger=F['bound'](event,fit['registered_host_equation']['source'],0o444)
    fleet=F['bound'](event,fit['fleet'],0o600)
    ram=int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])*1024
    prior=8499707994704
    def project(f,handoffs,closed):
        return T['calculate'](f,ledger,fleet,prior,handoffs,closed,ram,64)
    rows=T['scenarios'](fit,ledger,fleet,prior,ram,64,set())
    assert len(rows)==32 and all(r['gaps']['disk']>0 for r in rows)
    assert rows[0]['gaps']==dict(disk=421771903568,committed_memory=164037705728,available_memory=0,cpu_quota_micros=8000000)
    assert next(r for r in rows if r['transferred']==[166,168,170])['gaps']==next(r for r in rows if r['transferred']==[166,167,168,170])['gaps']==dict(disk=318692688464,committed_memory=0,available_memory=0,cpu_quota_micros=0)
    assert rows[-1]['gaps']==dict(disk=62926500432,committed_memory=0,available_memory=0,cpu_quota_micros=0)
    assert all(r['gaps']['committed_memory']>0 for r in rows if len(r['transferred'])<3)
    # A synthetic closed booking can exercise the arithmetic only. No such row,
    # physical byte, grant, or synthetic provider is exposed to production.
    all_closed={166,167,168,170}
    fake=dict(fit,replacements={},active168_guard_floor=0,joined_resident_lower_bounds={},required_available_memory_bytes=fit['required_available_memory_bytes']+sum(fit['joined_resident_lower_bounds'].values()))
    grants={e:dict(retained_growth_bytes=T['BOOK'],maximum_transfer_bytes=T['CAP'][e]) for e in all_closed}
    need=T['need']
    before=project(fake,grants,all_closed)[1]
    price=before['complete_protected_HOME_bytes']+448*T['G']
    for delta in (-1,0,1):
        case=dict(fake,available_HOME_bytes=price+delta)
        row=project(case,grants,all_closed)[1]
        assert row['gaps']['disk']==max(0,-delta) and sum(row['gaps'].values())==row['gaps']['disk']
    invalid=[]
    for label,original,allow,closed in [
        ('live-grant',fit,grants,set()),('different-native-required',dict(fake,complete_required_HOME_bytes=fit['complete_required_HOME_bytes']-1),grants,all_closed),
        ('lost-live-guard',dict(fit,active168_guard_floor=fit['available_HOME_bytes']+1),{},set()),
        ('different-cpu',dict(fake,complete_cpu_quota_micros=56000000),grants,all_closed),
        ('different-memory',dict(fake,complete_memory_plus_reserve_bytes=T['MEM']-1),grants,all_closed),
        ('unknown-epoch',fake,{136:dict(retained_growth_bytes=0,maximum_transfer_bytes=2)},all_closed),
        ('unpaid-publication-storage',fake,{166:dict(retained_growth_bytes=0,maximum_transfer_bytes=T['G'])},all_closed),
        ('negative-capacity',fake,{166:dict(retained_growth_bytes=T['BOOK'],maximum_transfer_bytes=-1)},all_closed),
        ('inconsistent-resident-set',fit,{},all_closed)]:
        try:project(original,allow,closed)
        except (ValueError,KeyError):invalid.append(label)
        else:raise AssertionError(label)
    assert project(fake,{},all_closed)[1]['gaps']['committed_memory']==rows[0]['gaps']['committed_memory']
    cases=('source-inode','missing-readback','repair-pending','wrong-sidecar','wrong-bucket','wrong-owner','other-recipient','short-restore')
    for epoch in T['ALL_CAP']:
        receipts(epoch)
        for change in cases:
            try:receipts(epoch,change)
            except ValueError:invalid.append(str(epoch)+'-'+change)
            else:raise AssertionError(change)
    U=runpy.run_path(str(HERE/'transition_units.py'))
    units=U['units']()
    assert sum('PathExistsGlob=' in c for c in units.values())==5 and sum('RemainAfterExit=yes' in c for c in units.values())==5 and all('OnCalendar' not in c and 'OnUnitActiveSec' not in c for c in units.values())
    assert 'PathChanged=' in units[U['PATH']] and all(U['CHECK'] in units[f'horizon-199200-after-publication-{e}.service'] for e in T['CAP'])
    live,fr=F['head'](event)
    assert fr==F['head'](event)[1] and live['owner']=='/root'
    qualification='82672869ba90c9e63cf327929bb28172b8866b8c329849d184295155cc3f1e0d'
    five=json.loads(F['pin'](F['NATIVE']/'qualification.json',qualification).read_bytes())
    full=F['bound'](event,five['native'],0o400)
    mat=F['bound'](event,five['qualified_matrix'],0o400)['matrix']
    assert five['counts']==mat['counts']==dict(populations=64,publisher_prices=160,transfer_combinations=486,adverse=160)
    assert 'PathChanged='+str(F['R']/'epoch169-focused-terminal-20261121-v1/TERMINAL_GUARD_DRAINED.json') in units[U['PATH']]
    five_fleet=F['bound'](event,full['fleet'],0o600)
    assert five['source_commit']=='c777aed01c50c69725adb60d0341a278c495e593' and full['fits'] and full['closed_full172'] is None
    current=T['scenarios'](full,ledger,five_fleet,prior,ram,64,set())
    assert len(current)==32 and current[0]['complete_protected_HOME_bytes']==full['complete_required_HOME_bytes'] and current[0]['gaps']['disk']>0
    return dict(schema='horizon-199-phase-transition-qa-v2',focused169_matrix=five['qualified_matrix'],focused169_cases=mat['counts'],qualified_five_source_native=qualification,current_scenarios=current,latest_native_recorded=full['recorded_unix_seconds'],source_native_fit=fit['fleet'],observed_native_fit_sha256='b0765f7b9c0f16b4708fef996c4c555f53a7f7521a677b910bbe618f750c5233',accepted_head_at_test=fr,original_169_172_nested_floor_reproduces=True,scenarios=rows,negative_controls=invalid,synthetic_one_byte_thresholds=[-1,0,1],test_grants_installed=False,publications_or_replays_started=0)
if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True))
