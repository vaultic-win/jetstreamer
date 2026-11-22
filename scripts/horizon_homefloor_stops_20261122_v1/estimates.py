"""Update the dated dependency model after four guard closures and the private 169 terminal."""
from contextlib import ExitStack
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil
import os
from pathlib import Path
import runpy
import sys

import closures as cl


def calculate(fleet, closure, floor):
    original = cl.BASE/'failed-retry1-091010-forecast-20261122-v1'
    lastref = bound(original/'MODEL.json')
    assert lastref['sha256']=='8a6c91b204918d0c8fe22bdf6c36ebcee2de6b17a7a39b9c3c5815cb4178fc61'
    prev = checked(lastref)
    src=checked(prev['base_stage_budgets'])['models']
    provider=prev['calculation'];assert provider==bound(original/'plan.py')
    v=runpy.run_path(provider['path'])
    assert v['verify_live']() is None and len(v['rows'])==486
    before=dict(fleet['complete_active_status_receipts']);before.update(closure['reports'])
    old={int(n):checked(ref) for n,ref in before.items()}
    def absolute(n):
        s=old[n]['after_status'];return round(utc(s['sampled_at_utc']).timestamp()*1000)+s['estimated_remaining_millis']
    models={}
    def stage(e, start, phases, reason):
        assert all(x>=0 for x in phases.values())
        models[e]=dict(start_ms=start,phase_milliseconds=phases,absolute_ready_ms=start+sum(phases.values()),basis=reason,
                       canonical_progress_credited=False,resource_credit_bytes=0)
        return models[e]['absolute_ready_ms']
    def copy(e):return dict(prev['models'][str(e)]['phase_milliseconds'])
    repair=max(row['model']['recorded_stop_ms']+row['model']['repair_and_requalification_ms'] for row in old.values() if row.get('schema')=='horizon-status-homefloor-repair-v1')
    assert cl.drained('horizon-holding-export145-20261121-v1.service')['ActiveState']=='failed'
    stage(145,repair,copy(145),'The 145 contender remains stopped. Use the shared six-hour incident repair window, followed by source reauthentication and both independent complete semantic passes. No cancelled 136 handoff is credited.')
    phase145=models[145]['phase_milliseconds']
    post=repair+sum(phase145[k] for k in ('source_reauthentication','expected_source_semantic_digest','independent_decoded_output_semantic_reread',
                           'first_full_hash_fsync_and_promotion','guarded_post_full_poh_and_adjacent_boundaries','guarded_post_local_plugin','post_source_hashes_and_handoff'))
    stage(136,post,copy(136),'136 follows guarded 145 post verification, admission and its full canonical replay.')
    stage(171,models[136]['absolute_ready_ms'],copy(171),'171 follows 136 publication and its own repair and complete replay.')
    diag=bound(cl.BASE/'epoch169-focused-terminal-20261121-v1/TERMINAL.json');d=checked(diag)
    assert d['epoch']==169 and d['disposition']=='interrupted-or-unclassified' and not d['private_segment'] and d['resource_credit_bytes']==0
    intent=checked(d['guard_stop']['intent'])
    assert intent['reason']=='root-physical-budget' and intent['producer_invocation_id']==d['producer_invocation_id']
    prior169=bound(cl.STATUS/'event-169-canonical-stages-after064959-20261121-v1/MODEL.json')
    old169=checked(prior169);phases=dict(old169['phase_milliseconds'])
    observation=bound(Path(closure['fleet']['path']).parent/'FOCUSED169_OBSERVATION.json')
    progress=checked(observation)['observed_progress'];first,last=progress['first'],progress['last']
    assert progress['advancing'] and progress['ordered'] and last['terminal_slot']==first['terminal_slot']
    inp=checked(d['input_proof'])
    assert inp['terminal_slot']==last['terminal_slot'] and inp['start_slot']<first['slot']<last['slot']<last['terminal_slot']
    rate=(last['slot']-first['slot'])*1e6/(last['realtime_microseconds']-first['realtime_microseconds'])
    phases.pop('private_diagnostic_remaining_to_its_own_target_with_25pct')
    private_ms=ceil((inp['terminal_slot']-inp['start_slot']+1)/rate*1250)
    phases['full_private_diagnostic_from_retained_bootstrap_with_25pct']=private_ms
    end169=stage(169,repair,phases,'Private diagnostic stopped on its physical workspace ceiling without a reusable completed segment. Price full private reproduction, trace repair/retest and the independent full canonical replay and publication.')
    diag_release=repair+private_ms+phases['post_trace_mismatch_correction_retest_and_guarded_readmission']
    assert diag_release<end169
    grants={n:absolute(n) for n in (166,167,168,170,172)}
    delivery={e:old[e]['model']['delivery_tail_ms'] for e in cl.STOPPED}
    delivery[172]=old[172]['delivery_forecast']['total_millis']
    replay_end={e:t-delivery[e] for e,t in grants.items()}
    close={e:t+7200000 for e,t in replay_end.items()}
    assert all(close[n]<grants[n] for n in close)
    rows=deepcopy(v['rows'])
    for row in rows:row['gaps']['disk']=max(0,row['complete_protected_HOME_bytes']+row['candidate_HOME_bytes']-floor['conservative_home_bytes'])
    ready=models[145]['absolute_ready_ms']
    alts=[dict(a,ready_ms=ready+a['ready_ms']-prev['models']['145']['absolute_forecast_ms']) for a in v['alternatives']]
    select=v['routes']['select_routes'];best,cases=select(rows,close,grants,diag_release,ready,alts)
    used=best['row']['transferred'];when=best['start_ms']
    assert best['case']['dated'] and set(used)<=set(grants)
    why='Conditional transfers require actual successor reconstruction, native stop, publication, fresh fit and distinct physical retirement. The four current stops release no workspace. No grants recorded.'
    for e in (199,200):stage(e,when,copy(e),why)
    joint=copy(199);returned=when+joint['full_two_epoch_replay_and_checkpoints']+joint['recovery_contingency']+7200000
    def available(e,earliest):return max(returned,earliest) if e in used else earliest
    early=v['early141'];min141=early['observed_at_ms']+early['phase_milliseconds']['concurrent_engineering_and_capacity_queue']
    stage(141,max(ready,available(167,replay_end[167]),min141),copy(141),'Old 167 stopped. Project reconstruction before successor use, then account for any joint handback.')
    stage(173,max(ready,available(166,grants[166])),copy(173),'Old 166 stopped. Project reconstructed delivery and the actual grant handback before 173.')
    stage(185,models[173]['absolute_ready_ms'],copy(185),'185 follows the reassessed 173 route.')
    def through(e,names):
        m=models[e];return m['start_ms']+sum(m['phase_milliseconds'][k] for k in names)
    windows={166:through(185,['fresh_full_reader_memory_DATA_and_replay_admission','full_boundary_runtime_native_Frame_successor_qualification','bank_restore_and_warmup','full_canonical_epoch_replay_with_prior_25_percent_contingency']),
             167:through(141,['complete_source_qualification_and_suffix_inputs','bootstrap_restore_and_init','cold_replay_to_root','in_epoch_Bank_checkpoint_qualification_allowance','suffix_replay']),
             170:available(170,replay_end[170]),172:available(172,replay_end[172])}
    order=v['order'];table=v['table']
    for n in sorted(order,key=lambda e:(order[e][0],e)):
        lane=min(windows,key=lambda e:(windows[e],e));anchor=max(windows[lane],order[n][1])
        stage(n,anchor,copy(n),'Next nonoverlapping modeled lane after the changed owner and delivery sequence.')
        seq=table['standby_sequence'][str(n)];windows[lane]=anchor+seq['estimated_replay_finish_ms']-seq['estimated_start_ms']
        models[n].update(proposed_lane=lane,estimated_replay_finish_ms=windows[lane])
    assert len(models)==14
    return dict(schema='horizon-four-homefloor-dependency-forecast-v1',models=models,calculation=bound(Path(__file__).resolve()),previous_schedule=lastref,
        closed_status_event=bound(cl.OUT/'R2_STOP_CORRECTIONS.json'),fleet=closure['fleet'],budget_provider=provider,
        historical_native=prev['historical_native_price'],historical_mirrors=prev['historical_mirror_price'],release_states_priced=len(rows),
        actual_169_terminal=diag,private_169_observation=observation,previous_169_model=prior169,conditional_169_handback_ms=diag_release,
        projected_joint=best,all_physical_scenarios=cases,conditional_grants=used,conditional_joint_return_ms=returned,closed_successor_drain_ms=close,
        donor_ready_ms=grants,availability_snapshot=floor,comparison_scope='Historical paid case repriced with current conservative HOME and guarded full-replay recovery. Current 145, four producer and private-169 reservations persist pending verified handbacks.',actual_grants=0,resource_credit_bytes=0)


def run(mode):
    cl.drained(cl.OWNER)
    event=bound(cl.OUT/'R2_STOP_CORRECTIONS.json');closure=checked(event)
    assert event['sha256']=='9719cca38d4d9f8fddb65529436c408139d884c1a7838b4ea323e39a8499a214'
    fleet=checked(closure['fleet']);prior=dict(fleet['complete_active_status_receipts']);prior.update(closure['reports'])
    freeze=cl.OUT/'FORECAST_INPUT.json';model_path=cl.OUT/'FORECAST_MODEL.json'
    with ExitStack() as locks:
        for p in (cl.BASE/'stable-cadence-controller-20261120-v1/consumer.lock',Path(fleet['complete_active_status_audit']['path']).parent/'cycle.lock'):
            locks.callback(os.close,lock(p))
        if freeze.exists():floor=checked(bound(freeze))
        else:
            stat=os.statvfs('/home/sol');actual=stat.f_frsize*stat.f_bavail
            floor=dict(captured_at_utc=cl.stamp(),actual_free_home=actual,conservative_home_bytes=min(actual,fleet['complete_cycle_conservative_available_DATA_bytes']),last_complete_fleet_available=fleet['complete_cycle_conservative_available_DATA_bytes'])
            if mode=='publish':durable(freeze,floor)
        model=calculate(fleet,closure,floor)
        if mode=='publish':durable(model_path,model)
        st=Storage();statuses,ready,archives=st.inventory()
        assert statuses==set(map(int,prior))
        changes={}
        for n,m in model['models'].items():
            keystr=str(n);prev=checked(prior[keystr]);old=prev['after_status'];old_absolute=round(utc(old['sampled_at_utc']).timestamp()*1000)+old['estimated_remaining_millis']
            if m['absolute_ready_ms']==old_absolute:continue
            assert n not in ready|set(archives) and old['phase']=='verification' and prev['current_repair_owner']=='/root'
            ev=cl.STATUS/f'event-{n}-homefloor-dependencies-after171010-20261122-v1';intent=ev/'INTENT.json';receipt=ev/'RECEIPT.json'
            if mode=='publish':ensure_dir(ev);locks.callback(os.close,lock(ev/'writer.lock'))
            et,raw=st.get(n)
            if intent.exists():
                i=checked(bound(intent));assert i['previous_receipt']==prior[keystr] and i['model']==bound(model_path)
                assert (et==prev['after_etag'] and raw==body(old)) or (et!=prev['after_etag'] and raw==body(i['after_status']))
            else:
                assert et==prev['after_etag'] and raw==body(old) and digest(raw)==prev['after_sha256']
                now=cl.stamp();nowms=round(utc(now).timestamp()*1000);oldms=round(utc(old['sampled_at_utc']).timestamp()*1000)
                after=dict(old,sampled_at_utc=now,elapsed_execution_millis=old['elapsed_execution_millis']+nowms-oldms,estimated_remaining_millis=m['absolute_ready_ms']-nowms)
                assert after['estimated_remaining_millis']>0
                if mode=='publish':
                    durable(intent,dict(schema='horizon-root-homefloor-bounded-forecast-event-v1',epoch=n,key=key(n),owner='/root',
                           primary_thread=fleet['primary_thread'],current_repair_owner='/root',producer_invocation_id=None,previous_receipt=prior[keystr],
                           sampled_at_utc=now,before_status=old,before_etag=et,before_sha256=digest(raw),after_status=after,after_sha256=digest(body(after)),
                           conditional_header='If-Match',model=bound(model_path),absolute_forecast_ms=m['absolute_ready_ms'],archive_or_sidecar_mutations=False))
            if mode=='publish':
                i=checked(bound(intent))
                if raw!=body(i['after_status']):
                    et=st.put(n,et,body(i['after_status']));durable(ev/'CONDITIONAL_RESPONSE.json',dict(intent=bound(intent),if_match=i['before_etag'],returned_etag=et))
                tag,raw=st.get(n);assert tag==et and raw==body(i['after_status'])
                if not receipt.exists():durable(receipt,dict(i,after_etag=tag,authenticated_readback=True,verified_at_utc=cl.stamp()))
                rc=checked(bound(receipt));assert rc['after_sha256']==digest(raw) and rc['previous_receipt']==prior[keystr];changes[keystr]=bound(receipt)
            print(n,datetime.fromtimestamp(m['absolute_ready_ms']/1000,timezone.utc).isoformat(),flush=True)
        if mode=='publish':
            assert st.inventory()==(statuses,ready,archives)
            readbacks={}
            for n,prev in prior.items():
                ref=changes.get(n,prev);rc=checked(ref);tag,raw=st.get(int(n));assert tag==rc['after_etag'] and raw==body(rc['after_status'])
                readbacks[n]=dict(receipt=ref,etag=tag,sha256=digest(raw))
            done=cl.OUT/'FINAL_READBACK.json'
            durable(done,dict(statuses=readbacks,ready_epochs=sorted(ready),native_fleet=closure['fleet'],forecast_model=bound(model_path),closed_status_event=event))
            durable(cl.OUT/'HANDOFF.json',dict(fleet=closure['fleet'],final_readback=bound(done),closures={k:checked(x)['guard_stop_completion'] for k,x in closure['reports'].items()},
                   corrected_stop_events=event,dependent_forecast=bound(model_path),original_observer=fleet['observer'],terminal169=model['actual_169_terminal'],expected_remaining_canonical=[172],
                   remote_changes=sorted(map(int,changes)),no_double_counted_resource_credit=True))
            print('HANDOFF',bound(cl.OUT/'HANDOFF.json'))
if __name__=='__main__':
    assert os.geteuid()==0 and __debug__ and sys.argv[1:] in (['preflight'],['publish'])
    b=cl.PACKAGE/'deployment-seal-receipt.json'
    assert cl.hashlib.sha256(b.read_bytes()).hexdigest()=='7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e'
    sys.path.insert(0,str(cl.PACKAGE))
    from status import Storage,body,key
    from evidence import bound,checked,digest,durable,lock,ensure_dir,utc
    run(sys.argv[1])
