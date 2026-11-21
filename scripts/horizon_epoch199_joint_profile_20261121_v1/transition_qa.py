"""Exercise exact HOME nesting, transfer cardinality, funding thresholds and source bindings."""
import ast
import copy
import inspect
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
    ram=F['bound'](event,fleet['observer'],0o644)['host_memory']['total_kib']*1024
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
    five=json.loads(F['pin'](F['NATIVE'].parent/'tools-v13/qualification.json',qualification).read_bytes())
    full=F['bound'](event,five['native'],0o400)
    mat=F['bound'](event,five['qualified_matrix'],0o400)['matrix']
    assert five['counts']==mat['counts']==dict(populations=64,publisher_prices=160,transfer_combinations=486,adverse=160)
    assert 'PathChanged='+str(F['R']/'epoch169-focused-terminal-20261121-v1/TERMINAL_GUARD_DRAINED.json') in units[U['PATH']]
    five_fleet=F['bound'](event,full['fleet'],0o600)
    assert five['source_commit']=='c777aed01c50c69725adb60d0341a278c495e593' and full['fits'] and full['closed_full172'] is None
    five_source_scenarios=T['scenarios'](full,ledger,five_fleet,prior,ram,64,set())
    assert len(five_source_scenarios)==32 and five_source_scenarios[0]['complete_protected_HOME_bytes']==full['complete_required_HOME_bytes'] and five_source_scenarios[0]['gaps']['disk']>0
    bridge=F['NATIVE'].parent/'tools-v14'
    bridge_sha='4cf6d3ba5f3891bd950fdf9feda3915c2a3c199d813402b8aef50fbf2adb6435'
    bridge_seal=dict(path=str(bridge/'deployment-seal-receipt.json'),sha256='86fdbaec0d37065e568f1aec19474f116162d94c161982479f1a96401b700500')
    eight=json.loads(F['pin'](bridge/'qualification.json',bridge_sha).read_bytes())
    predecessor=F['bound'](event,eight['predecessor'],0o444,bridge.parent/'tools-v13/deployment-seal-receipt.json')
    assert eight['predecessor']['sha256']=='ad9409085ca6e2d73f532b81a889cc0ffadbcbdede649f1d02de663ca4c44bd2'
    assert eight['source_commit']=='fd3180c7867ef17a0c4249d38bb5e7fb47efe14f'
    assert {row['sha256'] for row in predecessor['members'] if row['name']=='publication-fit'}=={eight['members']['publication-fit']}
    assert len(eight['registrations'])==8 and eight['refused_crossed_modes']==9 and eight['resource_credit_bytes']==0
    for mode in ('semantic','post'):
        registration=eight['registrations']['focused-'+mode]
        assert registration['seal']==eight['phase_seals'][mode]
        F['bound'](event,registration['seal'],0o444)
        F['bound'](event,registration['build'],0o444)
    actual_ref=dict(path=str(F['R']/'epoch145-guarded-export-20261121-v1/state/e6551a0bb8a14b989902e15c9ecc0751/recovery-started.json'),sha256='55d2a0504271e8a1eea2ca8c105a288be9497f1a2b80177279481692d06e041f')
    actual=F['bound'](event,actual_ref,0o600)
    assert actual['image']==eight['registrations']['focused-semantic']['image'] and actual['fresh_fit']['phase145']['window']['continuity_seal']==eight['phase_seals']['semantic']
    assert actual['fresh_fit']['provider_seal']==bridge_seal and actual['iid']==actual['fresh_fit']['phase145']['invocation_id']
    assert eight['fit']['phase145']['failure']['sha256']=='6533e594be11534e7fb58ac0f1fd752ead37cfd114e36899a956970b8318bb29'
    routes=runpy.run_path(str(HERE/'forecast_routes.py'))
    def price_capture(native):
        roster=F['bound'](event,native['fleet'],0o600)
        assert native['fits'] and native['resource_credit_bytes']==0 and not native['replay_launch_authorized']
        assert F['bound'](event,native['registered_host_equation']['source'],0o444)==ledger
        prices=routes['price_rows'](native,roster,ledger,prior,ram,T)
        assert len(prices)==486 and prices[0]['complete_protected_HOME_bytes']==native['complete_required_HOME_bytes']
        assert all(set(row['transferred'])<=set(row['closed']) for row in prices)
        exact=T['scenarios'](native,ledger,roster,prior,ram,64,set())
        comparable=[{k:v for k,v in row.items() if k!='private169_closed'} for row in prices
                    if not row['private169_closed'] and row['transferred']==row['closed']]
        order=lambda row:(len(row['closed']),row['closed'])
        assert len(exact)==32 and sorted(exact,key=order)==sorted(comparable,key=order)
        return dict(fleet=native['fleet'],phase=native['phase145'],populations=64,transfers=len(prices),checkpoint_scenarios=len(exact))
    captures=dict(stopped=price_capture(eight['fit']),resumed=price_capture(actual['fresh_fit']))
    nine_sha='45a6b4627bba3fc9b242d9c7030fc9c817f49466932a9fb067f24ed1bf5a800e'
    nine=json.loads(F['pin'](F['NATIVE'].parent/'tools-v15/qualification.json',nine_sha).read_bytes())
    assert nine['schema']=='horizon-145-nine-phase-native-qualification-v1' and nine['predecessor']==bridge_seal
    assert nine['members']['post-stop-fit']=='ef38a9640e35d60d2257d59d0cee5641f3a35df4d76365d336a741cf480490ea' and nine['members']['publication-fit']==F['PUB']
    assert nine['refused_crossed_modes']==13 and nine['resource_credit_bytes']==0
    assert set(nine['registrations'])==set(eight['registrations'])|{'retry-post'}
    for name,previous in eight['registrations'].items():
        current_phase=nine['registrations'][name]
        assert {k:v for k,v in current_phase.items() if k!='profile'}=={k:v for k,v in previous.items() if k!='profile'}
        assert current_phase['profile']['sha256']==previous['profile']['sha256']
    post=nine['registrations']['retry-post']
    assert nine['phase_seals']['retry-post']==post['seal']
    F['bound'](event,post['seal'],0o444,F['R']/'epoch145-semantic-continuity-20261121-v1/tools-v10/deployment-seal-receipt.json')
    F['bound'](event,post['build'],0o444)
    assert nine['fit']['phase145']['invocation_id']==actual['iid'] and nine['fit']['phase145']['stage']=='leased-worker'
    captures['current_leased_worker']=price_capture(nine['fit'])
    previous_pub=runpy.run_path(str(F['pin'](bridge/'publication-fit',eight['members']['publication-fit'])))
    for name in ('identity','closing','validate'):
        assert ast.dump(ast.parse(inspect.getsource(pub[name])))==ast.dump(ast.parse(inspect.getsource(previous_pub[name])))
    # Bind the original checkpoint modes through timer recovery and its real post verifier.
    timer_qualifications = {}
    previous_dir = F['NATIVE'].parent / 'tools-v15'
    previous = nine
    for generation, digest, added, phase in (
        ('tools-v16', '32537b525247db295fa5c7d523fdb45a840d0c69377d7659ea0647f15c9f439c', 'timer-semantic', 'tools-v5e'),
        ('tools-v17', '8ef798bc5e5574ee6ac43a05dc60243da7697d426f71e6c2417a599b565c4614', 'timer-post', 'tools-v11'),
    ):
        base = F['NATIVE'].parent / generation
        current = json.loads(F['pin'](base / 'qualification.json', digest).read_bytes())
        F['bound'](event, current['predecessor'], 0o444, previous_dir / 'deployment-seal-receipt.json')
        assert set(current['registrations']) == set(previous['registrations']) | {added}
        for name, old in previous['registrations'].items():
            new = current['registrations'][name]
            assert all(old[k] == new[k] for k in ('seal', 'image', 'build', 'adapter'))
        registration = current['registrations'][added]
        assert current['phase_seals'][added] == registration['seal']
        expected = F['R'] / 'epoch145-semantic-continuity-20261121-v1' / phase
        F['bound'](event, registration['seal'], 0o444, expected / 'deployment-seal-receipt.json')
        F['bound'](event, registration['build'], 0o444)
        assert current['refused_crossed_modes'] > previous['refused_crossed_modes']
        assert current['members']['publication-fit'] == F['PUB'] and current['resource_credit_bytes'] == 0
        captures[added] = price_capture(current['fit'])
        timer_qualifications[added] = dict(qualification=digest, seal=registration['seal'])
        previous, previous_dir = current, base
    assert current['members']['post-stop-fit'] == F['PROVIDER']
    observed = current['fit']['phase145']
    assert observed['stage'] == 'leased-worker' and observed['invocation_id'] == 'a99ed8b51e8a482b805b8a36a11b2700'
    assert observed['window']['continuity_seal'] == current['registrations']['timer-semantic']['seal']
    return dict(schema='horizon-199-phase-transition-qa-v4',timer_qualifications=timer_qualifications,current_registered_modes=sorted(current['registrations']),current_crossed_modes=current['refused_crossed_modes'],nine_phase_qualification=nine_sha,
                retry_post_seal=post['seal'],nine_registered_modes=sorted(nine['registrations']),refused_crossed_modes=nine['refused_crossed_modes'],eight_phase_qualification=bridge_sha,v14_retry_start=actual_ref,provider_captures=captures,focused169_matrix=five['qualified_matrix'],focused169_cases=mat['counts'],qualified_five_source_native=qualification,current_scenarios=five_source_scenarios,latest_native_recorded=full['recorded_unix_seconds'],source_native_fit=fit['fleet'],observed_native_fit_sha256='b0765f7b9c0f16b4708fef996c4c555f53a7f7521a677b910bbe618f750c5233',accepted_head_at_test=fr,original_169_172_nested_floor_reproduces=True,scenarios=rows,negative_controls=invalid,synthetic_one_byte_thresholds=[-1,0,1],test_grants_installed=False,publications_or_replays_started=0)
if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True))
