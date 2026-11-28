"""Close four November 22 replay owners through the incumbent authenticated status publisher."""
from contextlib import ExitStack
from datetime import datetime, timezone
from math import ceil
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data')
OUT = BASE / 'four-homefloor-20261122-v1'
STATUS = Path('/home/sol/.jetstreamer-private/r2-status-receipts')
PACKAGE = BASE / 'prefix140-status-cadence-20261122-v1/cadence-tools'
FLEET = BASE / 'root171010-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
STOPPED = {166:71711708, 167:72143703, 168:72575704, 170:73439777}
OWNER = 'horizon-archive-status-cadence-after172-20261120-v1.service'


def manager(unit):
    keys = 'Id,InvocationID,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Job'
    output = subprocess.check_output(['systemctl','show',unit,'-p',keys],text=True)
    return dict(line.split('=',1) for line in output.splitlines())


def drained(unit):
    m = manager(unit)
    assert m['Id'] == unit and m['ActiveState'] in ('inactive','failed')
    assert m['MainPID'] == m['ControlPID'] == '0' and not m['Job'] and not m['ControlGroup']
    group = Path('/sys/fs/cgroup/system.slice') / unit
    assert not group.exists() or not (group/'cgroup.procs').read_text().strip()
    return m


def stamp():
    return datetime.now(timezone.utc).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')


def bind_stop(e, row, predecessor):
    unit = row['unit']['Id']
    iid = row['unit']['InvocationID']
    old = checked(predecessor)
    assert old['producer_invocation_id'] == iid and old['after_status']['phase'] == 'replay'
    before = checked(row['guard_protection'])
    root = Path(row['guard_protection']['path']).parent
    intent = bound(root/'stop-intent.json')
    end = bound(root/'stop-completion.json')
    stop, completion = checked(intent), checked(end)
    sample = stop['sample']
    sample_ref = bound(root/f"sample-{sample['guard_invocation_id']}.json")
    assert checked(sample_ref) == sample
    assert iid == before['producer_invocation_id'] == stop['producer_invocation_id'] == completion['producer_invocation_id']
    assert stop['reason'] == sample['trip_reason'] == 'filesystem-floor'
    assert sample['producer_stop_enabled'] and sample['available_bytes'] < sample['minimum_free_bytes']
    assert sample['root_physical_observation']['conservative_physical_bytes'] <= sample['maximum_root_physical_bytes']
    assert not sample['root_physical_observation_error'] and not sample['worker_observation_error']
    assert completion['intent'] == intent['path'] and completion['terminal']['invocation_id'] == iid
    assert completion['terminal']['pid'] == 0 and not completion['scratch_deleted'] and not completion['r2_mutations']
    assert before['plan_sha256'] == sample['plan_sha256'] == completion['plan_sha256']
    terminal = drained(unit)
    old_archive = old['archive_sample']
    archive = Path(old_archive['path'])
    meta = archive.lstat()
    assert archive.resolve(strict=True) == archive and stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
    assert (meta.st_dev,meta.st_ino)==(old_archive['device'],old_archive['inode']) and meta.st_size>=old_archive['size']
    cohort = archive.parent.parent
    assert cohort == Path(row['scratch_path']).parent and archive.name == f'epoch-{e}.jet'
    state_file = cohort/'cohort-state.json'
    with state_file.open('rb') as state_source:
        sm = os.fstat(state_source.fileno())
        sb = state_source.read(16385)
        assert sm.st_uid in (0,1001) and stat.S_ISREG(sm.st_mode) and sm.st_nlink==1
        assert sm.st_size==len(sb)<=16384 and state_file.resolve()==state_file and os.path.samestat(sm,state_file.lstat())
    sv=json.loads(sb);assert sv['status']=='running-private' and sv['start_epoch']==sv['end_epoch']==e
    state=dict(path=str(state_file),sha256=hashlib.sha256(sb).hexdigest(),device=sm.st_dev,inode=sm.st_ino,uid=sm.st_uid)
    progress = row['progress']
    assert progress['sufficient_for_rates'] and progress['slot_delta']>0 and progress['counter_resets']==0
    log = Path(progress['append_log_evidence']['path'])
    with log.open('rb') as source:
        prefix = source.read(2<<20)
    match = re.search(rb'bound predecessor snapshot [^\n]+ generation (\d+) at slot (\d+)',prefix)
    assert match and int(match[2]) == STOPPED[e] and (log.stat().st_dev,log.stat().st_ino)==(progress['append_log_evidence']['device'],progress['append_log_evidence']['inode'])
    finish = progress['last']['terminal_slot']
    assert finish == (e+1)*432000-1 and progress['last']['slot'] < finish
    replay_ms = ceil((finish-STOPPED[e])*1100/progress['slots_per_second'])
    delivery_ms = old['delivery_forecast']['total_millis']
    # Previous requalifications on this host used a six-hour repair allowance.
    prior = checked(bound(BASE/'epoch168-witness-incident-20261121-v1/R2_STOP_CORRECTIONS.json'))
    prior_budget = checked(prior['reports']['166'])['model']['repair_and_requalification_ms']
    assert prior_budget == 21600000
    anchor=sample['recorded_unix_seconds']*1000
    return dict(guard=sample_ref,guard_stop_intent=intent,guard_stop_completion=end,
                terminal_native=terminal,terminal_producer_invocation_id=iid,
                model=dict(recorded_stop_ms=anchor,retained_partial=str(archive),retained_partial_bytes=meta.st_size,
                           retained_device=meta.st_dev,retained_inode=meta.st_ino,retained_state=state,
                           replay_start_planning_slot=STOPPED[e],bootstrap_generation=int(match[1]),
                           last_measured_slot=progress['last']['slot'],final_slot=finish,
                           rate_source=row['observer'],last_slots_per_second=progress['slots_per_second'],
                           repair_allowance_source=prior['reports']['166'],repair_and_requalification_ms=prior_budget,
                           full_replay_with_10pct_ms=replay_ms,delivery_tail_ms=delivery_ms,
                           absolute_ready_ms=anchor+prior_budget+replay_ms+delivery_ms,
                           planning_assumption='Requalify physical HOME funding and restore the original input. Full replay is priced until a usable continuation is proven.',
                           archive_or_bank_resume_claimed=False))


def publish(mode):
    assert hashlib.sha256(FLEET.read_bytes()).hexdigest()=='6eeb24940a8316f95a6921a55d8781f9a1a41067ac766894b127aab61afec639'
    fref=bound(FLEET);fleet=checked(fref);refs=fleet['complete_active_status_receipts']
    assert len(refs)==20 and checked(fleet['complete_active_status_audit'])['receipts']==refs
    registry={row['epoch']:row for row in fleet['actual_executing_replays']}
    assert set(registry)==set(STOPPED)|{172}
    st=Storage()
    with ExitStack() as locks:
        # A new observer must wait for the durable four-epoch event before claiming this lock.
        for p in (BASE/'stable-cadence-controller-20261120-v1/consumer.lock',
                  Path(fleet['complete_active_status_audit']['path']).parent/'cycle.lock'):
            locks.callback(os.close,lock(p))
        drained(OWNER)
        statuses,ready,archives=st.inventory()
        assert statuses==set(map(int,refs)) and set(STOPPED).isdisjoint(ready|set(archives))
        result={}
        for e in STOPPED:
            ref=refs[str(e)];prior=checked(ref);old=prior['after_status'];evidence=bind_stop(e,registry[e],ref)
            ev=STATUS/f'event-{e}-homefloor-stop-after171010-20261122-v1'
            if mode=='publish':ensure_dir(ev);locks.callback(os.close,lock(ev/'writer.lock'))
            et,raw=st.get(e);ip=ev/'INTENT.json'
            if ip.exists():
                intent=checked(bound(ip))
                assert intent['previous_receipt']==ref and all(intent[k]==v for k,v in evidence.items())
                assert (et==prior['after_etag'] and raw==body(old)) or (raw==body(intent['after_status']) and et!=prior['after_etag'])
            else:
                assert et==prior['after_etag'] and raw==body(old) and digest(raw)==prior['after_sha256']
                now=stamp();nowms=round(utc(now).timestamp()*1000);oldms=round(utc(old['sampled_at_utc']).timestamp()*1000)
                model=evidence['model'];after=dict(old,phase='verification',sampled_at_utc=now,
                    jet_size_bytes=model['retained_partial_bytes'],estimated_remaining_millis=model['absolute_ready_ms']-nowms,
                    elapsed_execution_millis=old['elapsed_execution_millis']+nowms-oldms)
                assert after['estimated_remaining_millis']>0 and set(after)==set(old)
                intent=dict(schema='horizon-status-homefloor-repair-v1',epoch=e,key=key(e),owner='/root',current_repair_owner='/root',
                    primary_thread=fleet['primary_thread'],producer_invocation_id=None,measured_canonical_progress=False,
                    sampled_at_utc=now,previous_receipt=ref,before_status=old,before_etag=et,before_sha256=digest(raw),
                    after_status=after,after_sha256=digest(body(after)),fleet=fref,conditional_header='If-Match',
                    archive_publication_authorized=False,replay_launch_authorized=False,**evidence)
            if mode=='preflight':
                print(e,evidence['model']['retained_partial_bytes'],evidence['model']['absolute_ready_ms']);continue
            durable(ip,intent)
            if raw!=body(intent['after_status']):
                assert bind_stop(e,registry[e],ref)==evidence
                et=st.put(e,et,body(intent['after_status']))
                durable(ev/'CONDITIONAL_RESPONSE.json',dict(intent=bound(ip),if_match=intent['before_etag'],returned_etag=et))
            tag,raw=st.get(e);assert tag==et and raw==body(intent['after_status'])
            rp=ev/'RECEIPT.json'
            if not rp.exists():durable(rp,dict(intent,after_etag=tag,authenticated_readback=True,verified_at_utc=stamp()))
            rc=checked(bound(rp));assert rc['after_etag']==tag and rc['after_sha256']==digest(raw) and rc['previous_receipt']==ref
            result[str(e)]=bound(rp)
        if mode=='publish':
            assert st.inventory()==(statuses,ready,archives)
            for e in refs:
                rc=checked(result.get(e,refs[e]));tag,raw=st.get(int(e))
                assert tag==rc['after_etag'] and raw==body(rc['after_status'])
            durable(OUT/'R2_STOP_CORRECTIONS.json',dict(fleet=fref,reports=result,authenticated_status_count=20,archives_or_sidecars_changed=False,canonical_producer_epochs=[172]))

if __name__ == '__main__':
    assert os.geteuid()==0 and __debug__ and sys.argv[1:] in (['preflight'],['publish'])
    seal=PACKAGE/'deployment-seal-receipt.json'
    assert hashlib.sha256(seal.read_bytes()).hexdigest()=='7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e'
    for member in json.loads(seal.read_bytes())['members']:
        assert hashlib.sha256((PACKAGE/member['name']).read_bytes()).hexdigest()==member['sha256']
    sys.path.insert(0,str(PACKAGE))
    from status import Storage,body,key
    from evidence import bound,checked,digest,durable,lock,ensure_dir,utc
    publish(sys.argv[1])
