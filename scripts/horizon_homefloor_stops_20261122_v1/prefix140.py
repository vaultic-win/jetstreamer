"""Carry epoch 140's qualified private recorder estimate onto the newly projected 141 resource window."""
from contextlib import ExitStack
import hashlib
from pathlib import Path
import sys

import closures as cl


def run(mode):
    predecessor=bound(cl.OUT/'HANDOFF.json')
    assert predecessor['sha256']=='6ec8ef5b423a960162964723a86a4be8b3d87b4b09eb909c902b240fdde15d8a'
    hand=checked(predecessor);read=checked(hand['final_readback']);f=checked(hand['fleet'])
    original=bound(cl.BASE/'prefix140-status-cadence-20261122-v1/INITIAL_EVENT_RECEIPT.json')
    initial=checked(original)['model'];old141=checked(initial['reference_141_latest'])['after_status']
    wait141=round(utc(old141['sampled_at_utc']).timestamp()*1000)+old141['estimated_remaining_millis']-initial['comparable_resource_window_ms']
    dep=checked(hand['dependent_forecast'])['models']['141']
    assert wait141 == sum(dep['phase_milliseconds'].values()) == 691569019
    assert dep['start_ms']+wait141==dep['absolute_ready_ms']
    audit=f['current_private_prefix140_obligation']['complete_result'];q=checked(audit)
    assert q['status']=='passed' and q['selected_prefix_mapping_proven'] and not q['publication_authorized']
    audit_ms=Path(audit['path']).stat().st_mtime_ns//1000000
    start=max(dep['start_ms'],audit_ms)
    target=start+sum(initial['phase_milliseconds'].values())
    model=dict(original_private_status=original,window_referenced_141=hand['dependent_forecast'],prefix_audit_completed=audit,
               actual_prefix_completion_ms=audit_ms,estimated_141_resource_window_ms=dep['start_ms'],phase_milliseconds=initial['phase_milliseconds'],
               absolute_ready_ms=target,resource_credit_bytes=0,real_canonical_replay_started=False)
    prior=read['statuses']['140']['receipt'];before=checked(prior);before_body=before['after_status']
    ev=cl.STATUS/'event-140-homefloor-dependencies-after171010-20261122-v1'
    with ExitStack() as locks:
        for path in (cl.BASE/'stable-cadence-controller-20261120-v1/consumer.lock',Path(f['complete_active_status_audit']['path']).parent/'cycle.lock'):
            locks.callback(cl.os.close,lock(path))
        cl.drained(cl.OWNER);st=Storage()
        statuses,side,archives=st.inventory();assert len(statuses)==20 and 140 not in side|set(archives)
        tag,raw=st.get(140);ip=ev/'INTENT.json';rp=ev/'RECEIPT.json';mp=ev/'MODEL.json'
        if mode=='publish':ensure_dir(ev);locks.callback(cl.os.close,lock(ev/'writer.lock'));durable(mp,model)
        if ip.exists():
            i=checked(bound(ip));assert i['previous_receipt']==prior and i['model']==bound(mp)
            assert (tag==before['after_etag'] and raw==body(before_body)) or (tag!=before['after_etag'] and raw==body(i['after_status']))
        else:
            assert raw==body(before_body) and tag==before['after_etag'] and digest(raw)==before['after_sha256']
            now=cl.stamp();nowms=round(utc(now).timestamp()*1000);oldms=round(utc(before_body['sampled_at_utc']).timestamp()*1000)
            after=dict(before_body,sampled_at_utc=now,elapsed_execution_millis=before_body['elapsed_execution_millis']+nowms-oldms,estimated_remaining_millis=target-nowms)
            assert before_body['phase']=='verification' and after['estimated_remaining_millis']>0 and before_body['jet_size_bytes']==0
            if mode=='publish':
                durable(ip,dict(epoch=140,key=key(140),schema='horizon-root-private140-capacity-window-correction-v1',owner='/root',current_repair_owner='/root',primary_thread=f['primary_thread'],previous_receipt=prior,model=bound(mp),before_etag=tag,before_status=before_body,before_sha256=digest(raw),after_status=after,after_sha256=digest(body(after)),conditional_header='If-Match',archive_or_sidecar_mutations=False))
        if mode=='preflight':print(target,model['estimated_141_resource_window_ms']);return
        i=checked(bound(ip))
        if raw!=body(i['after_status']):
            tag=st.put(140,tag,body(i['after_status']));durable(ev/'CONDITIONAL_RESPONSE.json',dict(intent=bound(ip),if_match=i['before_etag'],returned_etag=tag))
        t,raw=st.get(140);assert t==tag and raw==body(i['after_status'])
        if not rp.exists():durable(rp,dict(i,after_etag=tag,authenticated_readback=True,verified_at_utc=cl.stamp()))
        report=dict(read['statuses'])
        report['140']=dict(receipt=bound(rp),etag=tag,sha256=digest(raw))
        assert st.inventory()==(statuses,side,archives)
        for n,row in report.items():
            rc=checked(row['receipt']);t,b=st.get(int(n));assert b==body(rc['after_status']) and t==row['etag']==rc['after_etag']
        final=cl.OUT/'FINAL_READBACK_V2.json'
        durable(final,dict(read,statuses=report,predecessor=hand['final_readback'],private140_event=bound(rp)))
        target_path=cl.OUT/'HANDOFF_V2.json';durable(target_path,dict(hand,final_readback=bound(final),previous_handoff=predecessor,private140_model=bound(mp),remote_changes=sorted(hand['remote_changes']+[140])))
        print(bound(target_path))

if __name__=='__main__':
    assert cl.os.geteuid()==0 and __debug__ and sys.argv[1:] in (['preflight'],['publish'])
    assert hashlib.sha256((cl.PACKAGE/'deployment-seal-receipt.json').read_bytes()).hexdigest()=='7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e'
    sys.path.insert(0,str(cl.PACKAGE))
    from evidence import bound,checked,digest,durable,ensure_dir,lock,utc
    from status import Storage,body,key
    run(sys.argv[1])
