"""Continue the existing fleet status protocol after the four November 22 HOME guard stops."""
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data')
PACKAGE = BASE/'prefix140-status-cadence-20261122-v1/cadence-tools'
PARENT_SEAL = '7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e'
HEAD = BASE/'root171010-live166167170-20261122-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'
ROOT = BASE/'survivor172-cadence-20261122-v1'
CONTROLLER = 'horizon-archive-status-cadence-after172-20261120-v1.service'
CLOSED = (166, 167, 168, 170)
GUARD169 = BASE/'epoch169-focused-terminal-20261121-v1'
ENTRY146_FIELD = 'epoch146_bounded_entry_lease'
CURRENT = Path(__file__).resolve()
PRIVATE136 = CURRENT.parent == ROOT / 'tools-cold168-retry4-136-v1'
RESUMING = CURRENT.parent == ROOT / 'tools-cold168-retry4-resume-v1'
FAILED166 = CURRENT.parent == ROOT / 'tools-cold168-retry4-failed166-v1'
HOURLY170 = FAILED166 or CURRENT.parent == ROOT / 'tools-cold168-retry4-failed170-hourly170-v1'
FAILED170 = HOURLY170 or CURRENT.parent == ROOT / 'tools-cold168-retry4-failed170-v1'
assert hashlib.sha256((PACKAGE/'deployment-seal-receipt.json').read_bytes()).hexdigest() == PARENT_SEAL
sys.path.insert(0,str(PACKAGE))
from evidence import bound, checked, content, durable, ensure_dir, lock, names, need, sealed, utc
import cycle
import delivery_eta
import focused169_completion
import full172
import owners
import prefix140_storage
import race166
import ready_audit_growth
import resident_clock
import retired_public_audit
import status
sys.path.insert(0,str(CURRENT.parent))
import cold167_status
import cold166_status

if HOURLY170:
    import hourly170_cadence

if PRIVATE136:
    private136 = cycle.private136
    need(Path(private136.__file__) == PACKAGE / 'private136.py', 'different inherited epoch 136 observer')

cold_workers = cold166_status
if any(CURRENT.with_name(f'{name}-170-generation.json').is_file() for name in ('retry11','retry12','retry13')):
    import cold170_status as cold_workers

# The original five-lane receipt predates all four HOME guard stops.
SURVIVOR_CONFIGS = (('172',), ('167','172'), ('166','167','172'), ('167','170','172'), ('166','167','170','172'))
ORIGINAL_CONFIG = {
    'path': str(HEAD.parent/'sealed-next/observer.json'),
    'sha256': '44fa45e339652456767ac1167c6a73c1ad39b3b151968398d1697c9541efe7bc',
}

if getattr(cold_workers, 'cold168', None):
    SURVIVOR_CONFIGS += (('167','168','172'), ('166','167','168','172'),
                         ('167','168','170','172'), ('166','167','168','170','172'))


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)

def stamp(value):
    return value.strftime('%Y-%m-%dT%H:%M:%SZ')

def read_ref(path):
    return checked(bound(path))

def run(*args):
    return subprocess.check_output(list(map(str,args)),text=True,timeout=120)

def validate_package():
    from evidence import raw
    for row in checked(dict(path=str(PACKAGE/'deployment-seal-receipt.json'),sha256=PARENT_SEAL))['members']:
        path=PACKAGE/row['name']
        need(hashlib.sha256(raw(path)).hexdigest()==row['sha256'],'changed cadence dependency '+str(path))
    with race166.NATIVE.open('rb') as source:
        need(hashlib.file_digest(source,'sha256').hexdigest()==race166.NATIVE_SHA,'changed native observer')

def project(original, due, predecessor):
    need(original['observation_reason']=='routine' and original['minimum_interval_seconds']==1800,
         'unexpected cadence or user observation')
    owners_by_epoch={r['range']:r for r in original['replays']}
    keys=tuple(owners_by_epoch)
    historical=(keys==('166','167','168','170','172')
                and original['replays']==sealed(ORIGINAL_CONFIG)['replays'])
    need(len(owners_by_epoch)==len(original['replays']) and (historical or keys in SURVIVOR_CONFIGS),
         'unrecognized prior producer population')
    need(owners_by_epoch['172']['producer_unit']==full172.UNIT,'changed survivor')
    if '168' in owners_by_epoch and not historical:
        route = getattr(cold_workers, 'cold168', None)
        need(route and owners_by_epoch['168']['producer_unit'] == route.UNIT, 'unregistered 168 observer')
    rows=[owners_by_epoch['172']] if historical else list(owners_by_epoch.values())
    if FAILED170 and '170' in owners_by_epoch and cold_workers.failed_route():
        rows=[row for row in rows if row['range']!='170']
    if FAILED166 and '166' in owners_by_epoch:
        cold166_status.failed_route()
        cold166_status.projection(owners_by_epoch['166'])
        rows=[row for row in rows if row['range']!='166']
    for row in rows:
        if row['range']!='172':
            cold_workers.projection(row)
    return dict(original,replays=rows,
                diagnostic_replays=[r for r in original['diagnostic_replays'] if r['range']!='169'],
                previous_sample=predecessor['path'],output=str(names(due)['sample']),not_before_utc=due)

def check_sample(fleet, sample, cfg):
    parent=checked(fleet['observer'])
    scheduled=sample['cadence']
    need(sample['schema']==parent['schema'] and utc(sample['recorded_at_utc'])>=utc(cfg['not_before_utc']),
         'sample predates configured clock')
    need(scheduled['configured_not_before_utc']==cfg['not_before_utc'] and scheduled['observation_reason']=='routine'
         and scheduled['routine_minimum_interval_enforced'] and scheduled['previous_sample']==fleet['observer']['path']
         and scheduled['previous_sample_sha256']==fleet['observer']['sha256']
         and scheduled['observed_interval_seconds']>=1800
         and [r['range'] for r in sample['replays']]==[r['range'] for r in cfg['replays']]
         and tuple(r['range'] for r in cfg['replays']) in SURVIVOR_CONFIGS,
         'wrong sample predecessor or cadence')
    need([r['range'] for r in sample['diagnostic_replays']]==[r['range'] for r in cfg['diagnostic_replays']],
         'native diagnostic population changed')
    need(not resident_clock.incomplete(sample),'native host census incomplete')
    return sample['recorded_at_utc']

def native_closed(row,ref):
    data=checked(ref)
    plan_dir=Path(row['guard_protection']['path']).parent
    need(ref['path']==str(plan_dir/'stop-completion.json') and data['producer_invocation_id']==row['unit']['InvocationID']
         and data['terminal']['pid']==0,'guard completion does not bind original producer')
    intent=read_ref(plan_dir/'stop-intent.json')
    need(intent['reason']=='filesystem-floor' and intent['producer_invocation_id']==data['producer_invocation_id']
         and data['intent']==str(plan_dir/'stop-intent.json'),
         'different stop reason or producer')
    n=owners.show(row['unit']['Id'],('Id','ActiveState','MainPID','ControlPID','Job','ControlGroup'))
    need(n['MainPID']==n['ControlPID']=='0' and not n['Job'] and n['ActiveState'] in ('inactive','failed'),
         'closed producer reacquired a process')
    return dict(completion=ref,intent=bound(plan_dir/'stop-intent.json'),unit=n,
                guard=owners.show(row['guard_timer']['Id'],('Id','ActiveState','SubState','Job','InvocationID')))

def stopped_populations(handoff, fleet):
    initial=checked(handoff['fleet'])
    original={r['epoch']:r for r in initial['actual_executing_replays']}
    need(set(original)=={*CLOSED,172} and set(map(int,handoff['closures']))==set(CLOSED),'unexpected closure population')
    deaths={str(e):native_closed(original[e],handoff['closures'][str(e)]) for e in CLOSED}
    term=bound(GUARD169/'TERMINAL.json'); data=checked(term)
    need(data['producer_invocation_id']==focused169_completion.IID and data['disposition'] in focused169_completion.DISPOSITIONS,
         'different focused diagnostic')
    keeper=next(r for r in initial['actual_active_private_diagnostics'] if r['epoch']==169)
    checked(keeper['admission'])
    need(data['admission']==keeper['admission'] and not data['canonical_replay_claimed']
         and not data['archive_publication_authorized'] and not data['reservation_ending_bytes'],
         'unknown diagnostic disposition')
    n=owners.show(keeper['unit']['Id'],('Id','ActiveState','MainPID','ControlPID','Job'))
    need(n['MainPID']==n['ControlPID']=='0' and n['ActiveState'] in ('inactive','failed') and not n['Job'],
         'diagnostic producer did not drain')
    timer=owners.show(keeper['guard_timer']['Id'],('Id','ActiveState','SubState','InvocationID','Job'))
    drained=GUARD169/'TERMINAL_GUARD_DRAINED.json'
    return deaths,dict(terminal=term,unit=n,timer=timer,guard_retirement=bound(drained) if drained.exists() else None,
        disposition=data['disposition'],fallback_guard_stop=data.get('guard_stop'),retained_root_cap_bytes=focused169_completion.CAP,
        actual_guard_plan=data['actual_guard_plan'],reservation_ending_bytes=0,resource_credit_bytes=0)

def closure_members(head,handoff):
    need(handoff['fleet']['path']==str(HEAD),'wrong incident head')
    need(checked(handoff['fleet'])['sampled_at_utc']=='2026-11-22T17:10:10Z','wrong incident sample')
    if head!=handoff['fleet']:
        need(checked(head)['survivor172_incident']==bound(ROOT/'HANDOFF.json'),'different incident lineage')

def authenticated(store,key,ref):
    etag,raw=store.get(key)
    row=checked(ref)
    need(row['epoch']==key and row['authenticated_readback'] and row['after_etag']==etag
         and row['after_sha256']==hashlib.sha256(raw).hexdigest() and status.body(row['after_status'])==raw,
         'status changed outside authenticated handoff for '+str(key))
    return row

def read_statuses(store, receipts, destination):
    original=dict(receipts)
    for key,ref in original.items():
        intent=destination/f'epoch-{key}.intent.json'
        if intent.exists():
            plan=read_ref(intent)
            previous=plan['previous_receipt']
            before=checked(previous)
            need(plan['epoch']==int(key) and before['epoch']==int(key) and before['authenticated_readback']
                 and before['after_etag']==plan['before_etag'] and before['after_sha256']==plan['before_sha256']
                 and before['after_status']==plan['before_status'], 'intent changed its authenticated predecessor')
            if previous!=ref:
                # The current remote body may already be the result of the interrupted PUT.
                # Prove the event chain to its saved predecessor; publish checks the remote body.
                prior,_=external_event(int(key),ref,plan['before_etag'],status.body(plan['before_status']))
                need(prior==previous,'intent predecessor is outside the registered event chain')
                receipts[key]=prior
            continue
        if int(key)!=172:
            etag,raw=store.get(int(key))
            row=checked(ref)
            if row['after_etag']!=etag or row['after_sha256']!=hashlib.sha256(raw).hexdigest():
                ref,row=external_event(int(key),ref,etag,raw)
                receipts[key]=ref
        authenticated(store,int(key),ref)

def external_event(epoch,prior,etag,raw):
    from evidence import STATUS_ROOT, digest
    # Concurrent changes must be a recorded chain of exact If-Match events for this epoch.
    candidates=[]
    previous=checked(prior)
    for path in STATUS_ROOT.glob(f'event-{epoch}-*/RECEIPT.json'):
        if path.stat().st_mtime_ns< Path(prior['path']).stat().st_mtime_ns: continue
        row=read_ref(path)
        if row.get('epoch')==epoch and row.get('authenticated_readback') and row.get('conditional_header')=='If-Match':
            candidates.append((path,row))
    seen=set()
    while prior['sha256'] not in seen:
        seen.add(prior['sha256'])
        matches=[(p,r) for p,r in candidates if r.get('previous_receipt')==prior and r.get('before_etag')==previous['after_etag']
                 and r.get('before_sha256')==previous['after_sha256'] and r.get('before_status')==previous['after_status']]
        need(len(matches)==1,'unresolved or forked external status event for '+str(epoch))
        p,previous=matches[0];prior=bound(p)
        if previous['after_etag']==etag and previous['after_sha256']==digest(raw) and status.body(previous['after_status'])==raw:
            return prior,previous
    raise ValueError('cyclic successor event')

def publish(c,store,refs,out,epoch,archive=None):
    key=str(epoch)
    original=refs[key];old=checked(original);intent=out/f'epoch-{epoch}.intent.json';dest=out/f'epoch-{epoch}.receipt.json'
    if not intent.exists():
        authenticated(store,epoch,original)
        if utc(old['after_status']['sampled_at_utc'])>=c.now:
            return
        prior=old['after_status'];extra={}
        if epoch==172:
            quote=delivery_eta.estimate(c,172,archive['size'] if archive else 0)
            previous_remaining=delivery_eta.adjusted_remaining(prior,old,quote)
            after=full172.forecast(c,prior,archive,previous_remaining,quote['total_millis'])
            extra.update(delivery_forecast=quote,producer_invocation_id=c.full172_row['unit']['InvocationID'],
                         measured_canonical_progress=c.advancing[172],current_repair_owner=None,archive_sample=archive)
        elif epoch == 170 and epoch in getattr(c,'commits',{}):
            proof=c.commits[epoch]
            term=checked(proof['terminal'])
            committed=term['local_archive']
            size=committed['size']
            age=round((c.now-utc(prior['sampled_at_utc'])).total_seconds()*1000)
            need(size>0 and age>=0 and prior['phase'] in ('replay','verification'), 'foreign committed 170 status')
            quote=delivery_eta.estimate(c,epoch,size,committed=True)
            first=old.get('cold170_local_commit') != proof['terminal']
            remaining=quote['total_millis'] if first else prior['estimated_remaining_millis']-age
            need(remaining>0,'committed epoch 170 needs a fresh delivery forecast')
            after=dict(prior, sampled_at_utc=c.stamp, elapsed_execution_millis=prior['elapsed_execution_millis']+age,
                       estimated_remaining_millis=remaining, phase='verification', jet_size_bytes=size)
            extra.update(cold170_local_commit=proof['terminal'], archive_sample=committed,
                         delivery_forecast=quote, producer_invocation_id=None, measured_canonical_progress=False,
                         current_repair_owner='/root')
        elif epoch in getattr(c,'new_rows',{}):
            after,archive=cold_workers.reader().forecast(c,epoch,prior,old)
            actor=c.new_rows[epoch]
            if (after['phase']=='verification' and prior['phase']=='replay' and old.get('current_guarded_admission')
                    and old.get('producer_invocation_id')==actor['unit']['InvocationID']):
                # A guarded worker may begin replay after the current native sampler was armed.
                # Its authenticated event remains valid for this admission until a new sample measures it.
                need(old['current_guarded_admission']==actor['admission'],'prior replay belongs to another admission')
                need(not c.advancing[epoch],'advancing worker reported bootstrap')
                after['phase']='replay'
                extra['carried_replay_status']=original
            extra.update(delivery_forecast=c.delivery_forecasts[epoch],producer_invocation_id=actor['unit']['InvocationID'],
                         measured_canonical_progress=c.advancing[epoch],current_repair_owner=None,archive_sample=archive,
                         current_guarded_admission=actor['admission'],current_guard=actor['guard_protection'])
        else:
            need(prior['phase']=='verification','new replay owner requires adoption before publication')
            age=round((c.now-utc(prior['sampled_at_utc'])).total_seconds()*1000)
            need(age>=0 and prior['estimated_remaining_millis']>age,'external forecast expired or follows observation')
            after=dict(prior,sampled_at_utc=c.stamp,elapsed_execution_millis=prior['elapsed_execution_millis']+age,
                       estimated_remaining_millis=prior['estimated_remaining_millis']-age)
            extra.update(producer_invocation_id=None,measured_canonical_progress=False,current_repair_owner='/root',
                         estimate_model='Retain the absolute publication forecast of the authenticated predecessor.')
        if PRIVATE136:
            extra.update(private136.status_fields(c,epoch))
        if HOURLY170 and epoch == 170 and c.hourly170:
            private = c.hourly170.get('row')
            extra.update(private170_observation=c.hourly170['receipt'],
                         private_transaction_progress=bool(private and private['transaction_replay_claimed']))
            if private:
                extra['producer_invocation_id'] = private['unit']['InvocationID']
        durable(intent,dict(epoch=epoch,key=status.key(epoch),previous_receipt=original,conditional_header='If-Match',
                before_etag=old['after_etag'],before_sha256=old['after_sha256'],before_status=prior,
                after_sha256=hashlib.sha256(status.body(after)).hexdigest(),after_status=after,
                observer=c.sample_ref,fleet_predecessor=c.fleet_ref,sampled_at_utc=c.stamp,
                **cold167_status.counts(c),
                current_four_homefloor_stop=c.fleet.get('current_four_homefloor_stops')
                    if epoch in CLOSED and epoch not in getattr(c,'new_rows',{}) and epoch not in getattr(c,'commits',{}) else None,
                archive_publication_authorized=False,replay_launch_authorized=False,**extra))
    plan=read_ref(intent)
    need(plan['previous_receipt']==original and plan['observer']==c.sample_ref and plan['fleet_predecessor']==c.fleet_ref,
         'different uncompleted status intent')
    etag,raw=store.get(epoch)
    if etag==plan['before_etag'] and raw==status.body(plan['before_status']):
        need(not dest.exists(),'old status replayed after commit')
        written=store.put(epoch,etag,status.body(plan['after_status']))
        etag,raw=store.get(epoch);need(written==etag,'updated status ETag lost')
    need(raw==status.body(plan['after_status']) and etag!=plan['before_etag'],'conditional update was superseded')
    durable(dest,dict(plan,after_etag=etag,authenticated_readback=True))
    refs[key]=bound(dest)

def handoff():
    stopref=bound(BASE/'four-homefloor-20261122-v1/R2_STOP_CORRECTIONS.json')
    need(stopref['sha256']=='9719cca38d4d9f8fddb65529436c408139d884c1a7838b4ea323e39a8499a214',
         'foreign incident aggregate')
    stop=checked(stopref)
    finalref=bound(BASE/'four-homefloor-20261122-v1/FINAL_READBACK.json')
    final=checked(finalref)
    need(stop['fleet']==final['native_fleet']==bound(HEAD) and len(final['statuses'])==20 and not stop['archives_or_sidecars_changed'],
         'unbound final 20-status handoff')
    path=BASE/'four-homefloor-20261122-v1/HANDOFF.json'
    result=checked(dict(path=str(path),sha256='6ec8ef5b423a960162964723a86a4be8b3d87b4b09eb909c902b240fdde15d8a'))
    need(result['corrected_stop_events']==stopref and result['fleet']==stop['fleet'] and result['final_readback']==finalref
         and result['closures']=={e:checked(ref)['guard_stop_completion'] for e,ref in stop['reports'].items()},
         'different incident handoff or native closures')
    for e,entry in final['statuses'].items():
        receipt=checked(entry['receipt'])
        need(receipt['after_etag']==entry['etag'] and receipt['after_sha256']==entry['sha256']
             and receipt['epoch']==int(e) and receipt['authenticated_readback'],'foreign incident readback')
    return result

def config(directory,cfg):
    ensure_dir(directory)
    source=directory/'observer.json';durable(source,cfg)
    target=directory/'sealed-next';plan=directory/'next-seal-plan.json'
    durable(plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(target),
        members=[dict(source=str(source),name='observer.json',mode=0o444,sha256=bound(source)['sha256'])]))
    if not (target/'deployment-seal-receipt.json').exists():
        from evidence import SEALER
        run('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment',
            plan,'--plan-sha256',bound(plan)['sha256'],'--self-sha256',SEALER)
    ref=bound(target/'observer.json')
    need(sealed(ref)==cfg,'different sealed config')
    return ref

def timer_names():
    return [r.split()[0] for r in run('systemctl','list-units','--type=timer','--state=waiting','--no-legend',
                  '--plain','horizon-observer-*.timer').splitlines() if r.strip()]

def schedule(ref):
    cfg=sealed(ref);due=cfg['not_before_utc'];timer=names(due)['timer'];unit=timer.removesuffix('.timer')
    waiting=timer_names()
    if not waiting:
        need(utc(due)>now(),'requested timer deadline elapsed')
        run('systemd-run','--quiet','--unit='+unit,'--on-calendar='+utc(due).strftime('%F %T UTC'),
            '--timer-property=AccuracySec=1s','--timer-property=RemainAfterElapse=no',race166.NATIVE,ref['path'])
    need(timer_names()==[timer],'multiple or foreign observer clocks')
    n=owners.show(timer,('ActiveState','SubState','Triggers','TimersCalendar'))
    command=owners.show(unit+'.service',('ExecStart',))['ExecStart']
    need(n['ActiveState']=='active' and n['SubState']=='waiting' and n['Triggers']==unit+'.service'
         and str(race166.NATIVE)+' '+ref['path']+' ' in command
         and utc(due).strftime('%F %T UTC') in n['TimersCalendar'],'scheduled observer command differs')
    return timer

def epoch146_entry(c):
    prior = c.fleet.get(ENTRY146_FIELD)
    offer_path = c.paths['out'] / 'ENTRY146_LEASE_OFFER.json'
    if prior is None and not offer_path.exists():
        return None
    import bounded142
    reader = owners.cadence168.status168
    if prior is not None:
        need(not offer_path.exists(), 'overlapping epoch 146 lease offer')
        return dict(lease=prior, claim=bounded142.reservation146(reader, prior), new=False)
    offer = read_ref(offer_path)
    need(offer == dict(schema='horizon-epoch146-cadence-offer-v1', lease=offer['lease'],
                      fleet_predecessor=c.fleet_ref, observer=c.sample_ref),
         'foreign epoch 146 cadence offer')
    lease = offer['lease']
    claim = bounded142.reservation146(reader, lease)
    if bounded142.terminal146(claim):
        return None
    need(bounded142.held146(reader, lease) == claim, 'epoch 146 hold differs from its reservation')
    return dict(lease=lease, claim=claim, new=True)


def install_epoch146_entry(c, fleet):
    entry = c.entry146
    if entry is None:
        return
    import bounded142
    if bounded142.terminal146(entry['claim']):
        fleet.pop(ENTRY146_FIELD, None)
        return
    if entry['new']:
        need(bounded142.held146(owners.cadence168.status168, entry['lease']) == entry['claim'],
             'epoch 146 hold changed before fleet publication')
    fleet[ENTRY146_FIELD] = entry['lease']


def make_context(head,fleet,sample_ref,cfg,out):
    sample=checked(sample_ref);when=check_sample(fleet,sample,cfg)
    c=SimpleNamespace(fleet_ref=head,fleet=fleet,stamp=when,now=utc(when),cfg=cfg,sample=sample,sample_ref=sample_ref,
           paths={'out':out,'sample':Path(sample_ref['path'])},lanes={},advancing={},next_cfg=copy.deepcopy(cfg),
           prior=checked(fleet['authenticated_status_audit']),new_rows={},rows={},metered168_row=None)
    if PRIVATE136:
        private136.previous(fleet)
        c.private136 = private136.freeze(c)
        private136.interpret(c,cycle.observed_lane)
    old=full172.owned(fleet);need(old is not None,'172 missing prior ownership')
    ident=full172.identity(fleet)
    oref=out/'FULL172_OBSERVATION.json'
    if not oref.exists():
        guard=full172.guard_view(ident['admission'])
        durable(oref,dict(fleet=head,observer=sample_ref,identity=ident,guard=guard))
    c.full172=read_ref(oref)
    need(c.full172['observer']==sample_ref and c.full172['fleet']==head and c.full172['identity']==ident,'foreign guard evidence')
    full172.reconcile_sample(c,cycle.observed_lane)
    cold_workers.reconcile(c,cycle.observed_lane)
    c.entry146 = epoch146_entry(c)
    entry = {'entry_lease': c.entry146['lease']} if c.entry146 is not None else {}
    native_owners = c.recovered_owners
    if HOURLY170:
        c.hourly170 = hourly170_cadence.observe(c)
        hourly170_cadence.interpret(c,c.hourly170,cycle.observed_lane)
        private = c.hourly170.get('row') if c.hourly170 else None
        if private:
            need('170' not in native_owners and 170 not in c.new_rows, 'epoch 170 has two native owners')
            native_owners = dict(native_owners, **{'170': dict(
                unit=private['unit'], actor=dict(producer_pid=int(private['unit']['MainPID'])))})
    if getattr(cold_workers, 'cold168', None):
        cold_workers.cold168.census(owners, ident, native_owners, **entry)
    else:
        owners.replay_census([],None,full=ident,closed168_owner=True,metered_commit=True,
                             restored=native_owners,**entry)
    return c

def baselines(head,fleet,bridge):
    if head==bridge['fleet']:
        observed=checked(bridge['final_readback'])['statuses']
        return {e:row['receipt'] for e,row in observed.items()}
    return dict(checked(fleet['complete_active_status_audit'])['receipts'])

def census(c,bridge):
    out=c.paths['out'];path=out/'CYCLE_OBSERVATION.json'
    if path.exists():
        stored=read_ref(path)
        need(stored['observer']==c.sample_ref and stored['fleet_predecessor']==c.fleet_ref,'foreign local observation')
        return stored
    deaths,diag=stopped_populations(bridge,c.fleet)
    prefix=prefix140_storage.storage()
    audit,storage,owner=retired_public_audit.observe_public(Path('/home/sol').stat().st_dev,c.fleet['continuing_audit_obligation'])
    old=checked(c.fleet['current_home_cycle_capacity'])
    # Whole-root promises for closed and waiting actors continue on this branch.
    cap=dict(old,home_filesystem=c.sample['filesystem'],audit_storage=storage,audit_owner_witness=owner,
        private_epoch140_verifier=prefix,surviving_epoch172_protection=c.full172,closed_producer_observations=deaths,
        retained_private_diagnostic_169=diag,retained_prior_capacity=c.fleet['current_home_cycle_capacity'],
        fresh_admission=False,resource_credit_bytes=0,all_reservation_ending_bytes=0)
    cap['historical_prior_owner_observations']={k:cap.pop(k) for k in ('private136_observation','private136_capacity',
        'active_live_diagnostics','current_normal_168','optional_existing_serial_build_136') if k in cap}
    # Retain each older obligation once by the immutable prior capacity reference.
    cap.pop('historical_prior_owner_observations',None)
    if PRIVATE136 and c.private136:
        cap.update(private136_observation=c.private136['receipt'], private136_capacity=c.private136.get('capacity'),
                   active_live_diagnostics=private136.active(c.private136))
    if HOURLY170 and c.hourly170:
        cap['private170_observation'] = c.hourly170['receipt']
    if 'current_metered168_observation' in cap:
        cap['historical_pre_homefloor_metered168_observation']=cap.pop('current_metered168_observation')
    arc=status.observed_archive(c,172) if c.full172_row['scratch_path'] else None
    witness=dict(observer=c.sample_ref,fleet_predecessor=c.fleet_ref,audit=audit,capacity=cap,
            survivors=sorted([172,*c.new_rows]),closures=deaths,focused169=diag,archive172=arc,
            cold166_and_167=c.recovered_ref if 166 in c.new_rows else None,
            guarded_cold_observation=c.recovered_ref)
    if c.recovered_ref:
        cap['current_cold167_protection']=c.recovered_ref
        if 166 in c.new_rows:
            cap['current_cold166_retry11_protection']=c.recovered_ref
        if 168 in c.new_rows:
            name = f'current_cold168_retry{cold_workers.cold168.ATTEMPT}_protection'
            cap[name]=c.recovered_ref
        if 170 in c.new_rows:
            cap[f'current_cold170_{cold_workers.ATTEMPT}_protection']=c.recovered_ref
    if FAILED166:
        cap['retained_cold166_retry11_reservation'] = c.failed166
    durable(path,witness)
    return witness

def publish_all(c,bridge,store,vs):
    target=names(c.cfg['not_before_utc'])['statuses'];ensure_dir(target)
    refs=baselines(c.fleet_ref,c.fleet,bridge)
    initial=set(int(k) for k in refs)
    need(initial==set(status.EPOCHS)|{140},'different status population')
    ready=status.inventory(c,store)
    read_statuses(store,refs,target)
    for e in sorted(initial):
        publish(c,store,refs,target,e,vs['archive172'] if e==172 else None)
    for e,r in refs.items(): authenticated(store,int(e),r)
    need(ready==status.inventory(c,store),'archive inventory changed during status refresh')
    counts=cold167_status.counts(c)
    diagnostic_count=private136.active(c.private136) if PRIVATE136 else 0
    diagnostic_count+=int(bool(HOURLY170 and c.hourly170 and c.hourly170.get('row')))
    original=dict(c.prior)
    original.update(receipts={k:v for k,v in refs.items() if k!='140'},observer=c.sample_ref,
                    active_producer_count=counts['canonical_producer_count']+diagnostic_count,active_private_diagnostic_count=diagnostic_count,
                    canonical_producer_count=counts['canonical_producer_count'],replay_lanes=counts['current_replay_lanes'],
                    active_bootstraps=counts['active_bootstraps'],fleet_predecessor=c.fleet_ref,
                    effective_status_predecessor=c.fleet['authenticated_status_audit'],sampled_at_utc=c.stamp,
                    owner=CONTROLLER,coordinated_private_diagnostic_169=vs['focused169'],
                    newer_events_read_back_without_overwrite={})
    p=target/'COMPLETED.json';durable(p,original)
    complete=target/'COMPLETE_ACTIVE_STATUSES.json'
    durable(complete,dict(schema='horizon-all-current-authenticated-statuses-v1',observer=c.sample_ref,
         fleet_predecessor=c.fleet_ref,sampled_at_utc=c.stamp,authenticated_readback=True,
         authenticated_status_count=len(refs),status_epochs=sorted(initial),receipts=refs,original_nineteen=bound(p),
         private140=refs['140'],archives_or_sidecars_changed=False))
    return bound(p),bound(complete)

def fleet_successor(c,bridge,observed,statusref,allref,nref,timer):
    fleet=copy.deepcopy(c.fleet)
    lookup={r['epoch']:r for r in fleet['epochs']}
    a=checked(allref);base=c.paths['out']
    for name in ('AUDIT','HOME_CAPACITY'):
        durable(base/(name+'.json'),observed['audit' if name=='AUDIT' else 'capacity'])
    ar=bound(base/'AUDIT.json');hr=bound(base/'HOME_CAPACITY.json');disk=c.sample['filesystem']['conservative_available_bytes']
    for e,ref in a['receipts'].items():
        new=checked(ref)['after_status'];entry=lookup[int(e)]
        entry.update(status=new,current_status=new,status_publication=ref,current_authenticated_status_receipt=ref,
                     current_coordinated_observer=c.sample_ref)
    for e in CLOSED:
        entry=lookup[e];entry.pop('current_replay',None);entry.pop('current_bootstrap',None)
        entry.update(no_live_producer_claimed=True,current_repair_owner='/root',repair_open=True,state='verification',
             current_home_floor_stop=observed['closures'][str(e)],current_status_scope='HOME floor guard stopped the producer.')
    entry=lookup[169];entry.pop('current_private_diagnostic',None)
    entry.update(no_live_producer_claimed=True,current_repair_owner='/root',repair_open=True,state='verification',
           current_status_scope='Private diagnostic stopped; canonical repair remains open.',focused169_terminal=observed['focused169']['terminal'])
    lookup[172].update(current_replay=c.full172_row,current_repair_owner=None,no_live_producer_claimed=False,state='executing')
    initial=checked(bridge['fleet'])
    diag=next(r for r in initial['actual_active_private_diagnostics'] if r['epoch']==169)
    fleet.update(survivor172_incident=bound(ROOT/'HANDOFF.json'),previous_Root_operational_review=c.fleet_ref,
          sampled_at_utc=c.stamp,recorded_unix_seconds=observed['audit']['observed_at'],observer=c.sample_ref,
          sole_next_timer=timer,sole_next_observer=nref,actual_executing_replays=[c.full172_row],actual_active_bootstraps=[],
          bootstrap_count=0,guarded_bootstrap_owner_count=0,actual_active_private_diagnostics=[],active_private_diagnostic_count=0,
          useful_replay_count=int(c.advancing[172]),live_replay_count=1,active_producer_count=1,canonical_producer_count=1,
          authenticated_status_audit=statusref,effective_status_receipts=checked(statusref)['receipts'],
          complete_active_status_audit=allref,complete_active_status_count=20,complete_active_status_receipts=a['receipts'],
          current_private140_status_receipt=a['receipts']['140'],current_home_cycle_capacity=hr,current_four_homefloor_stops=bridge['corrected_stop_events'],
          historical_focused169_worker=diag,focused169_terminal=observed['focused169']['terminal'],
          current_private_169_observer_result=observed['focused169'],current_audit_progress=dict(observation=ar,field='progress'),
          current_audit_child=dict(observation=ar,field='child'),last_accepted_audit_summary=dict(observation=ar,field='summary'),
          audit_progress_at_recovery_overlay=observed['audit']['progress'],audit_summary_at_recovery_overlay=observed['audit']['summary'],
          audit_progress_capture_unix_at_recovery_overlay=observed['audit']['observed_at'],
          same_sample_conservative_free_DATA_bytes=disk,complete_cycle_conservative_available_DATA_bytes=disk,
          all_reservation_ending_bytes=0,resource_credit_bytes=0,
          cycle_reconciliation_scope='Single surviving canonical replay 172. Four HOME guard closures and terminal 169. All twenty status keys are authenticated.')
    fleet['current_replay_lane_recovery']='Recover interrupted 166/167/168/170 from retained inputs under fresh funding.'
    fleet['next_lane_recovery']=fleet['current_replay_lane_recovery']
    if observed['focused169']['guard_retirement']:
        fleet['focused169_guard_retirement']=observed['focused169']['guard_retirement']
    for key in ('current_metered168_observation','original_disk_guard_recovery_workers','recovered_workers_observation'):
        if key in fleet: fleet['historical_pre_homefloor_'+key]=fleet.pop(key)
    cap=observed['capacity'];fleet['complete_DATA_authority']['current_audit_growth']=hr
    fleet['complete_DATA_with_remaining_audit_growth_bytes']=fleet['complete_DATA_bytes']+cap['audit_storage']['remaining_DATA_growth_bytes']
    ready_audit_growth.reconcile(fleet,observed['audit'],cap,ar)
    prefix140_storage.reconcile(fleet,cap)
    cold_workers.install(c,fleet)
    if PRIVATE136:
        private136.install(c,fleet)
    if HOURLY170:
        hourly170_cadence.install(fleet,c.hourly170)
    install_epoch146_entry(c, fleet)
    if c.new_rows:
        active=', '.join(map(str,sorted([172,*c.new_rows])))
        pending=', '.join(map(str,sorted(set(CLOSED)-set(c.new_rows)-set(c.commits))))
        fleet['cycle_reconciliation_scope']=f'Guarded epochs {active}. Four original HOME closures and twenty authenticated status keys.'
        fleet['current_replay_lane_recovery']=f'Maintain epochs {active} and reprice {pending}.'
        fleet['next_lane_recovery']=fleet['current_replay_lane_recovery']
    return fleet

def track_timer(ref):
    cfg=sealed(ref);due=utc(cfg['not_before_utc']);sample=Path(cfg['output'])
    timer=names(cfg['not_before_utc'])['timer'];unit=timer.replace('.timer','.service')
    if not sample.exists() and now()<due:
        schedule(ref)
        time.sleep(max(0,(due-now()).total_seconds()+2))
    if not sample.exists() and now()>=due:
        state=owners.show(unit,('ActiveState','SubState','Result','Job','LoadState'))
        # A delayed controller can recover its already armed timer or start a new clock.
        if state['LoadState']=='not-found' and timer not in timer_names():
            return None,'elapsed before arming'
    while True:
        state=owners.show(unit,('ActiveState','SubState','Result','Job','LoadState'))
        if sample.exists() and state['ActiveState'] not in ('activating','active'):
            need(state['Result']=='success','native sampler failed after creating evidence')
            return bound(sample),None
        if state['ActiveState']=='failed':
            return None,'native sampler failed'
        if not sample.exists() and state['ActiveState']=='inactive' and now()>due+dt.timedelta(seconds=120):
            return None,'native output absent after timer expiration'
        need(now()<due+dt.timedelta(seconds=2100),'native observer exceeded original time bound')
        time.sleep(3)

def registered(cycle_dir,fleet):
    marker=cycle_dir/'REGISTERED.json'
    if marker.exists():
        receipt=read_ref(marker)
        need(receipt['predecessor']==bound(Path(fleet['observer']['path'])),'foreign recovery clock')
        return receipt['config']
    prior=sealed(fleet['sole_next_observer'])
    due=max(now()+dt.timedelta(seconds=20), utc(checked(fleet['observer'])['recorded_at_utc'])+dt.timedelta(seconds=1800))
    ref=config(cycle_dir,project(prior,stamp(due),fleet['observer']))
    durable(marker,dict(predecessor=fleet['observer'],config=ref))
    return ref

def advance_sample(head,fleet,ref):
    while True:
        cfg=sealed(ref);state=names(cfg['not_before_utc']);existing=state['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json'
        if existing.exists():
            new=read_ref(existing)
            need(new['previous_Root_operational_review']==head and new['survivor172_incident']==bound(ROOT/'HANDOFF.json'),
                 'different owner of completed cycle')
            return None,None,bound(existing)
        replacement=ROOT/('recover-'+ref['sha256'][:20])
        if (replacement/'REGISTERED.json').exists():
            ref=read_ref(replacement/'REGISTERED.json')['config'];continue
        sample_ref,error=track_timer(ref)
        if sample_ref:
            sample=checked(sample_ref)
            if not resident_clock.incomplete(sample):
                check_sample(fleet,sample,cfg)
                return ref,sample_ref,None
            error='native HOST RSS unavailable'
        ensure_dir(replacement)
        log=replacement/'TERMINAL.json'
        if not log.exists():
            durable(log,dict(fleet=head,prior_config=ref,failed_sample=sample_ref,error=error))
        record=read_ref(log)
        need(record['prior_config']==ref and record['fleet']==head,'different retired clock')
        last=utc(checked(sample_ref)['recorded_at_utc']) if sample_ref else utc(cfg['not_before_utc'])
        due=max(now()+dt.timedelta(seconds=20),last+dt.timedelta(seconds=1800))
        replacement_ref=config(replacement,project(cfg,stamp(due),fleet['observer']))
        durable(replacement/'REGISTERED.json',dict(config=replacement_ref,terminal=bound(log)))
        ref=replacement_ref

def one_cycle(head,ref,bridge,completed_sample=None):
    fleet=checked(head);closure_members(head,bridge)
    if completed_sample is None:
        config_ref,sample,already=advance_sample(head,fleet,ref)
        if already:return already
    else:
        config_ref,sample=ref,completed_sample
        need(ref==fleet['sole_next_observer'] and sealed(ref)['output']==sample['path'],
             'different resumed observer registration')
    cfg=sealed(config_ref);out=names(cfg['not_before_utc'])['out'];ensure_dir(out)
    c=make_context(head,fleet,sample,cfg,out)
    observed=census(c,bridge)
    store=status.Storage()
    legacy,whole=publish_all(c,bridge,store,observed)
    marker=out/'NEXT_DUE.json'
    if not marker.exists():
        due=max(now()+dt.timedelta(seconds=20),utc(c.stamp)+dt.timedelta(seconds=1800))
        durable(marker,dict(due=stamp(due),observer=sample))
    when=read_ref(marker);need(when['observer']==sample,'different recorded next phase')
    nextref=config(out,project(c.next_cfg,when['due'],sample))
    # Commit the next active schedule before exposing the fleet as the new head.
    if utc(when['due'])>now():
        timer=schedule(nextref)
    else:
        # A publishing retry can occur after its intended time. Arm a later sole timer
        # that still uses the original sample as cadence predecessor.
        alt=out/'recovery-clock';ensure_dir(alt)
        altref=alt/'REGISTERED.json'
        if not altref.exists():
            r=config(alt,project(c.next_cfg,stamp(now()+dt.timedelta(seconds=20)),sample))
            durable(altref,dict(config=r))
        nextref=read_ref(altref)['config'];timer=schedule(nextref)
    result=fleet_successor(c,bridge,observed,legacy,whole,nextref,timer)
    target=out/'ROOT_COMPLETE_OPERATIONAL_FLEET.json';durable(target,result)
    print(json.dumps(dict(fleet=bound(target),timer=timer,status_count=20,**cold167_status.counts(c))),
          flush=True)
    return bound(target)

def entry():
    package='tools-cold166-retry11'
    if cold_workers is not cold166_status:
        package=f'tools-cold170-{cold_workers.ATTEMPT}-v2'
        if cold_workers.ATTEMPT == 'retry13' and CURRENT.with_name('cold170_commit.py').is_file():
            package='tools-cold170-retry13-terminal-v1'
        if cold_workers.cold168:
            package=cold_workers.cold168.PACKAGE
    if PRIVATE136:
        need(package == 'tools-cold168-retry4-v1', '136 cadence requires the qualified retry4 parent')
        package = 'tools-cold168-retry4-136-v1'
    if RESUMING:
        need(package == 'tools-cold168-retry4-v1', 'cadence resumption requires the qualified retry4 parent')
        package = 'tools-cold168-retry4-resume-v1'
    if FAILED170:
        need(package == 'tools-cold168-retry4-v1', '170 terminal cadence requires the qualified retry4 parent')
        package = 'tools-cold168-retry4-failed170-hourly170-v1' if HOURLY170 else 'tools-cold168-retry4-failed170-v1'
    if FAILED166:
        package = 'tools-cold168-retry4-failed166-v1'
    need(os.geteuid()==0 and __debug__ and CURRENT==ROOT/package/'status_cycle.py','expected deployed sole controller')
    receipt=bound(CURRENT.parent/'deployment-seal-receipt.json')
    seal=checked(receipt)
    member,=(v for v in seal['members'] if v['name']=='status_cycle.py')
    need(seal['destination']==str(CURRENT.parent) and member['sha256']==bound(CURRENT)['sha256'],
         'unsealed cadence entry')
    if HOURLY170:
        member, = (item for item in seal['members'] if item['name']=='hourly170_cadence.py')
        need(Path(hourly170_cadence.__file__) == CURRENT.with_name(member['name'])
             and bound(CURRENT.with_name(member['name']))['sha256']==member['sha256'],
             'unsealed epoch 170 private cadence observer')
    return receipt


def await_private136_owner(state, receipt):
    intent_path=ROOT/'EPOCH136_V5N_STATUS_INTENT.json'
    active_path=ROOT/'EPOCH136_V5N_STATUS_ACTIVE.json'
    intent=read_ref(intent_path)
    qualification=checked(intent['qualification'])
    old=checked(intent['previous_active'])
    need(intent['schema']=='horizon-136-v5n-status-intent-v1' and intent['old']==old['new']
         and qualification['package']==receipt and qualification['entry']==bound(CURRENT),
         'different qualified private 136 status transition')
    due=time.monotonic()+90
    while not active_path.exists():
        need(time.monotonic()<due,'private 136 cadence owner was not registered')
        time.sleep(0.1)
    active=read_ref(active_path);new=active['new'];pid=os.getpid()
    need(active['schema']=='horizon-136-v5n-status-active-v1' and active['intent']==bound(intent_path)
         and active['schedule']==intent['schedule'] and active['old']==intent['old']
         and new['program']==str(CURRENT) and new['unit']==state['Id'] and new['pid']==pid
         and new['start_ticks']==owners.ticks(pid) and new['invocation_id']==state['InvocationID'],
         'different live private 136 status owner')


def failed170_resume(state, receipt, fd):
    """Adopt the one sealed clock for the four surviving producers."""
    ready = read_ref(ROOT/'FAILED170_CADENCE_READY.json')
    need(ready['schema']=='horizon-epoch170-failed-cadence-ready-v1' and ready['package']==receipt,
         'different failed epoch 170 cadence deployment')
    fleet_ref = ready['fleet']
    fleet = checked(fleet_ref)
    failure = cold_workers.failed_route(fleet)
    need(failure and ready['terminal']==failure['terminal'] and ready['guard_drain']==failure['guard_drain'],
         'different failed epoch 170 terminal evidence')
    old_owner = ready['old_owner']
    need(old_owner==bound(ROOT/'COLD168_RETRY4_V1_STATUS_RESUME_ACTIVE.json'), 'different incumbent cadence owner')
    old = checked(old_owner)['new']
    lock_stat = os.fstat(fd)
    need(state['Id']==old['unit']==CONTROLLER and state['ActiveState']=='active' and not state['Job']
         and state['ControlGroup']=='/system.slice/'+CONTROLLER and state['MainPID']==str(os.getpid())
         and state['InvocationID'] and state['InvocationID']!=old['invocation_id']
         and (lock_stat.st_dev,lock_stat.st_ino)==(old['lock']['device'],old['lock']['inode']),
         'successor does not hold the incumbent cadence lock')
    old_pid = old['pid']
    need(not Path(f'/proc/{old_pid}').exists() or owners.ticks(old_pid)!=old['start_ticks'],
         'incumbent cadence process still present')
    old_timer = ready['old_timer']
    need(old_timer['Id']==fleet['sole_next_timer'] and old_timer['InvocationID'],
         'different incumbent observer timer')
    correction = checked(ready['correction'])
    need(correction['previous_receipt']==fleet['complete_active_status_receipts']['170']
         and correction['fleet_predecessor']==fleet_ref and correction['terminal']==ready['terminal']
         and correction['guard_drain']==ready['guard_drain'] and correction['epoch']==170
         and correction['conditional_header']=='If-Match' and correction['authenticated_readback']
         and correction['after_status']['phase']=='verification' and correction['current_repair_owner']=='/root',
         'different authenticated epoch 170 repair estimate')
    config_ref = ready['config']
    prior_config = sealed(fleet['sole_next_observer'])
    cfg = sealed(config_ref)
    due = cfg['not_before_utc']
    need(cfg==project(prior_config,due,fleet['observer'])
         and [row['range'] for row in cfg['replays']]==['166','167','168','172']
         and utc(due)>=utc(checked(fleet['observer'])['recorded_at_utc'])+dt.timedelta(seconds=1800),
         'wrong failed epoch 170 observer clock or population')
    waiting = timer_names()
    new_timer = names(due)['timer']
    need(not waiting or waiting==[new_timer], 'another observer timer is still armed')
    if waiting:
        active = owners.show(new_timer,('InvocationID',))
        need(active['InvocationID']!=old_timer['InvocationID'], 'incumbent observer timer is still armed')
    return ready


def hourly170_resume(state, receipt, fd):
    """Adopt the incumbent's existing observer clock after an exclusive handoff."""
    ready_path = ROOT/'HOURLY170_CADENCE_READY.json'
    ready_ref = bound(ready_path)
    ready = checked(ready_ref)
    incumbent = ROOT/'failed170-retry13-cadence-20261124-v1/ACTIVE.json'
    need(ready['schema']=='horizon-epoch170-hourly-cadence-ready-v1'
         and ready['package']==receipt and ready['old_owner']==bound(incumbent),
         'different hourly epoch 170 cadence deployment')
    old = checked(ready['old_owner'])['new']
    previous_lock = old['lock']
    held = os.fstat(fd)
    need(state['Id']==old['unit']==CONTROLLER and state['ActiveState']=='active' and not state['Job']
         and state['InvocationID'] and state['InvocationID']!=old['invocation_id']
         and (held.st_dev,held.st_ino)==(previous_lock['device'],previous_lock['inode']),
         'hourly epoch 170 does not hold the incumbent consumer lock')
    try:
        still_running = owners.ticks(old['pid'])==old['start_ticks']
    except FileNotFoundError:
        still_running = False
    need(not still_running, 'incumbent epoch 170 writer is still present')
    fleet = checked(ready['fleet'])
    need(ready['config']==fleet['sole_next_observer'] and ready['timer']==fleet['sole_next_timer']
         and ready['fleet']['path']==str(max(BASE.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),
                                             key=lambda path:path.stat().st_mtime_ns)),
         'handoff does not bind the latest fleet and observer clock')
    cfg = sealed(ready['config'])
    waiting = timer_names()
    need(waiting==[ready['timer']] or (not waiting and Path(cfg['output']).is_file()),
         'incumbent observer timer or completed sample is missing')
    pid = os.getpid()
    actor = dict(unit=CONTROLLER, program=str(CURRENT), invocation_id=state['InvocationID'],
                 pid=pid, start_ticks=owners.ticks(pid), lock=dict(previous_lock,fd=fd))
    durable(ROOT/'HOURLY170_CADENCE_ACTIVE.json',
            dict(schema='horizon-epoch170-hourly-cadence-active-v1', ready=ready_ref,
                 old=old, new=actor, producer_mutations=False))
    return ready


def check_failed166_ready(ready, receipt):
    need(ready['schema'] == 'horizon-epoch166-failed-cadence-ready-v1'
         and ready['package'] == receipt and ready['old_owner'] ==
         bound(ROOT/'failed170-retry13-cadence-20261124-v1/ACTIVE.json'),
         'different failed epoch 166 cadence deployment')
    fleet_ref = ready['fleet']
    fleet = checked(fleet_ref)
    failure = cold166_status.failed_route(fleet)
    correction = checked(ready['correction'])
    need(correction['previous_receipt'] == fleet['complete_active_status_receipts']['166']
         and correction['fleet_predecessor'] == fleet_ref and correction['terminal'] == failure['terminal']
         and correction['epoch'] == 166 and correction['conditional_header'] == 'If-Match'
         and correction['authenticated_readback'] and correction['after_status']['phase'] == 'verification'
         and correction['current_repair_owner'] == '/root', 'different authenticated epoch 166 repair estimate')
    recovery = checked(ready['old_registration'])
    retired = checked(recovery['terminal'])
    need(retired['fleet'] == fleet_ref and retired['prior_config'] == fleet['sole_next_observer']
         and retired['error'] == 'native sampler failed' and retired['failed_sample'] is None
         and ready['old_timer'] == names(sealed(recovery['config'])['not_before_utc'])['timer'],
         'different failed observer clock')
    cfg = sealed(ready['config'])
    due = cfg['not_before_utc']
    need(cfg == project(sealed(recovery['config']), due, fleet['observer'])
         and [row['range'] for row in cfg['replays']] == ['167', '168', '172']
         and utc(due) >= utc(sealed(recovery['config'])['not_before_utc'])
         and utc(due) >= utc(checked(fleet['observer'])['recorded_at_utc']) + dt.timedelta(seconds=1800),
         'different epoch 166 successor population or schedule')
    return cfg


def failed166_resume(state, receipt, fd):
    ready_ref = bound(ROOT/'FAILED166_CADENCE_READY.json')
    ready = checked(ready_ref)
    cfg = check_failed166_ready(ready, receipt)
    old = checked(ready['old_owner'])['new']
    m = os.fstat(fd)
    need(state['Id'] == old['unit'] == CONTROLLER and state['ActiveState'] == 'active' and not state['Job']
         and state['InvocationID'] and state['InvocationID'] != old['invocation_id']
         and (m.st_dev, m.st_ino) == (old['lock']['device'], old['lock']['inode']),
         'epoch 166 successor does not hold the incumbent consumer lock')
    try:
        still_running = owners.ticks(old['pid']) == old['start_ticks']
    except FileNotFoundError:
        still_running = False
    need(not still_running, 'incumbent writer is still running')
    new_timer = names(cfg['not_before_utc'])['timer']
    need(timer_names() in ([], [new_timer]), 'foreign observer timer is still armed')
    pid = os.getpid()
    actor = dict(unit=CONTROLLER, program=str(CURRENT), invocation_id=state['InvocationID'],
                 pid=pid, start_ticks=owners.ticks(pid), lock=dict(old['lock'], fd=fd))
    durable(ROOT/'FAILED166_CADENCE_ACTIVE.json',
            dict(schema='horizon-epoch166-failed-cadence-active-v1', ready=ready_ref,
                 old=old, new=actor, producer_mutations=False))
    return ready


def main():
    receipt=entry()
    if sys.argv[1:]==['--check-entry']:
        print(json.dumps(receipt))
        return
    if FAILED166 and sys.argv[1:] == ['--check-failed166']:
        print(json.dumps(check_failed166_ready(read_ref(ROOT/'FAILED166_CADENCE_READY.json'), receipt)))
        return
    if RESUMING:
        member, = (row for row in checked(receipt)['members'] if row['name']=='status_resume.py')
        need(member['mode']=='0444' and bound(CURRENT.with_name(member['name']))['sha256']==member['sha256'],
             'unsealed cadence recovery bootstrap')
        import status_resume
        if sys.argv[1:] in (['--resume-prepare'], ['--resume-register']):
            os.umask(0o077)
            fd=lock(ROOT/'cold167-status-handoff.lock')
            try:
                action = status_resume.mark_intent if sys.argv[1]=='--resume-prepare' else status_resume.mark_active
                print(json.dumps(action(globals(),receipt)))
                return
            finally:
                os.close(fd)
    need(len(sys.argv)==1,'unexpected cadence argument')
    os.umask(0o077)
    fd=lock(BASE/'stable-cadence-controller-20261120-v1/consumer.lock')
    try:
        state=owners.show(CONTROLLER,('Id','InvocationID','MainPID','ControlGroup','Job','ActiveState'))
        need(state['MainPID']==str(os.getpid()) and Path('/proc/self/cgroup').read_text().strip()=='0::'+state['ControlGroup'],
             'outside original status service')
        resume=None
        if PRIVATE136:
            await_private136_owner(state,receipt)
        elif RESUMING:
            resume=status_resume.await_owner(globals(),receipt,state,fd)
        elif FAILED166:
            resume=failed166_resume(state,receipt,fd)
        elif HOURLY170:
            resume=hourly170_resume(state,receipt,fd)
        elif FAILED170:
            resume=failed170_resume(state,receipt,fd)
        elif getattr(cold_workers, 'cold168', None):
            cold_workers.cold168.await_recovery(state,os.getpid())
        validate_package()
        proof=handoff()
        durable(ROOT/'HANDOFF.json',proof)
        if resume is None:
            initial=ROOT/'first-clock';ensure_dir(initial)
            head=proof['fleet'];ref=registered(initial,checked(head))
        elif FAILED170:
            head=resume['fleet'];ref=resume['config']
        else:
            head=one_cycle(resume['fleet'],resume['config'],proof,resume['completed_sample'])
            ref=checked(head)['sole_next_observer']
        while True:
            head=one_cycle(head,ref,proof);ref=checked(head)['sole_next_observer']
    finally:
        os.close(fd)

if __name__=='__main__':
    main()
