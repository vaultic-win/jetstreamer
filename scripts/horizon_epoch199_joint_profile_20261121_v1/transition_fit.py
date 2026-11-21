"""Consume the ordinary closed fleet and scoped one-time 199/200 transfers."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import time

HERE=Path(__file__).resolve().parent
T=runpy.run_path(str(HERE/'transition_budget.py'))
need=T['need']
R=Path('/var/lib/jetstreamer/horizon_runtime_data')
B=R/'epoch199-delivery-recovery-20261121-v1'
REG=B/'phase-handoffs'
V11=R/'incident-replay-fit-20261121-v1/tools-v11'
SEAL='50a46e9010b448f2e038300c7aa5ffcdf38bf36ff4caf9bd783fe76ae513f4dc'
PUB='7c7cd5c883f768b0f374f63952eefa1efb5f0e08fe74269d939f8d1e98eca1b4'
PROVIDER='f6583caf06127010d2a3209f1a173df78264766f70bc869067bed10adf3b0349'
EVENT=R/'epoch166-retry10-delivery-20261121-v1/event-tools-current/terminal_event.py'
EVENT_SHA='2f04ec0a5825d98d39add39ad961d2dc71ea8aa94df8261adb6a3782bd737e43'
PATTERN=re.compile(r'root(\d{6})-live166167170-(\d{8})-v1')
FLEET='ROOT_COMPLETE_OPERATIONAL_FLEET.json'
FIELD={166:'recovered166_local_commit',167:'indexed167_local_commit',168:'metered168_local_commit',170:'recovered170_local_commit'}
UNITS={166:'horizon-publish-166-retry10-committed.service',167:'horizon-publish-167-source-index-committed.service',168:'horizon-publish-168-metered-committed.service',170:'horizon-publish-170-retry10-committed.service'}

def pin(path,digest):
    meta=path.lstat()
    need(path.resolve(strict=True)==path and stat.S_ISREG(meta.st_mode) and meta.st_uid==meta.st_gid==0 and meta.st_nlink==1 and meta.st_mode&0o222==0 and hashlib.sha256(path.read_bytes()).hexdigest()==digest,'changed root deployment '+str(path))
    return path

def helpers():
    seal=json.loads(pin(V11/'deployment-seal-receipt.json',SEAL).read_bytes())
    members={r['name']:r['sha256'] for r in seal['members']}
    need(seal['destination']==str(V11) and members['post-stop-fit']==PROVIDER and members['publication-fit']==PUB,'different complete provider')
    pin(V11/'post-stop-fit',PROVIDER)
    return runpy.run_path(str(pin(V11/'publication-fit',PUB))),runpy.run_path(str(pin(EVENT,EVENT_SHA)))

def bound(event,ref,mode,where=None):
    p=Path(ref['path'])
    need(where is None or p==where,'foreign evidence '+str(p))
    obj,actual=event['document'](p,mode)
    need(actual==ref,'changed evidence '+str(p))
    return obj

def head(event):
    now=time.time(); candidates=[]
    for d in R.glob('root??????-live166167170-????????-v1'):
        match=PATTERN.fullmatch(d.name)
        if match:
            tag,day=match.groups()
            sampled=datetime.datetime.strptime(day+tag,'%Y%m%d%H%M%S').replace(tzinfo=datetime.timezone.utc)
            if 0<=now-sampled.timestamp()<=2400 and (d/FLEET).exists():
                candidates.append((sampled,d))
    need(candidates,'no current accepted cadence')
    sample,d=max(candidates)
    f,fr=event['document'](d/FLEET,0o600)
    observer=bound(event,f['observer'],0o644,R/('sample-'+d.name+'.json'))
    clock=observer['cadence']
    scheduled=sample.strftime('%Y-%m-%dT%H:%M:%SZ')
    need(observer['schema']=='jetstreamer-horizon-live-resource-sample-v2' and clock['configured_not_before_utc']==scheduled and clock['observation_reason']=='routine' and clock['routine_minimum_interval_enforced'] is True and clock['observed_interval_seconds']>=clock['minimum_interval_seconds']==1800 and scheduled<=observer['recorded_at_utc']<=observer['completed_at_utc'],'unbound scheduled and actual observer times')
    need(f['owner']=='/root' and f['schema']=='horizon-Root-complete-fleet-operational-review-v1' and f['sampled_at_utc']==observer['recorded_at_utc'] and 0<=now-f['recorded_unix_seconds']<=2400 and f['all_active_status_reports_authenticated_readback'] is True,'unaccepted fleet or observer')
    report=bound(event,f['authenticated_status_audit'],0o600)
    need(report['owner']=='/root' and report['schema']=='horizon-status-full-range-audit-v1' and report['authenticated_readback'] is True and report['observer']==f['observer'] and report['sampled_at_utc']==f['sampled_at_utc'] and report['archive_or_sidecar_mutations'] is False and report['authenticated_status_count']==f['authenticated_status_count'],'unaccepted authenticated report')
    return f,fr

def delivery(epoch):
    return R/('epoch166-retry10-delivery-20261121-v1' if epoch==166 else f'epoch{epoch}-current-delivery-20261121-v1')

def transfer(event,epoch,ref,closure,book,fleet):
    # A closure is not a resource release. Only this unique per-generation
    # reservation assigned to our recipient by the controlling fleet can be spent.
    record=bound(event,ref,0o400,REG/f'{epoch}.json')
    gen=T['GENERATIONS'][epoch]
    need(record['schema']=='horizon-root-exclusive-phase-transfer-v1' and record['owner']=='/root' and record['origin_epoch']==epoch and record['origin_generation']==gen and record['recipient']=='epoch199200-measured-through-import' and record['terminal']==closure['terminal'] and record['booked_root']==book['root'] and record['original_cap_bytes']==book['cap_bytes']==T['CAP'][epoch] and record['exclusive_until_joint_import_reconciliation'] is True and record['replay_restart_claim_ended'] is True,'unassigned or non-exclusive old producer budget')
    need(record['retained_memory_bytes']==2*T['G'] and record['retained_cpu_quota_micros']==1000000 and record['published_archive_retained_local'] is True and record['separate_historical_repair_promises_retained'] is True,'uncounted delivery or repair custody')
    # The fleet owner registers the exact terminal, budget, and restoration
    # assessment. A public sync receipt does not retire a local archive.
    rr=record['repair_assessment']
    repair=bound(event,rr,0o400,REG/f'{epoch}-repair.json')
    need(repair['terminal']==closure['terminal'] and repair['owner']=='/root' and repair['epoch']==epoch and repair['booked_root']==book['root'] and repair['local_archive_retained'] is True and repair['historical_provenance_retained'] is True and repair['no_active_restore_or_repair_claim'] is True and repair['assessed_additional_growth_bytes']>=0 and record['retained_growth_bytes']>=T['BOOK']+repair['assessed_additional_growth_bytes'],'unfunded repair or future restore')
    terminal=bound(event,closure['terminal'],0o400)
    archive=terminal['local_archive']
    sync=record['sync_receipt']; path=Path(sync['path'])
    run=path.parent.parent
    need(run.parent==delivery(epoch) and re.fullmatch(r'run-[0-9a-f]{32}',run.name) and path==run/'receipts'/f'epoch-{epoch}.r2.json','foreign sync receipt')
    receipt=bound(event,sync,0o600)
    adm,_=event['document'](run/'admission.json',0o400)
    need(adm['publication_authorized'] is True and adm['terminal_sha256']==closure['terminal']['sha256'] and adm['transaction_id']==terminal['transaction_id'] and adm['operation']=='current-reader-sync-retain-local' and adm['invocation_id']==run.name[4:] and adm['unit']==UNITS[epoch] and adm['archive_inode']==archive['inode'] and adm['archive_device']==archive['device'],'different publisher or local source')
    need(receipt['schema']=='jetstreamer-horizon-r2-receipt-v1' and receipt['epoch']==epoch and receipt['archive_key']==f'epoch-{epoch}.jet' and receipt['checksum_key']==f'epoch-{epoch}.jet.sha256' and receipt['archive_length']==archive['size'] and receipt['archive_sha256']==archive['sha256'] and receipt['remote_sha256_readback'] is True and receipt['archive_etag'],'incomplete published pair')
    playback=receipt['current_reader_playback']
    p=Path(playback['path'])
    need(p.name=='remote-playback-acceptance.json' and p.parent.parent==run/'scratch','foreign playback path')
    play=bound(event,playback,0o400)
    obj=play['remote_playback']['object']
    need(play['schema']=='horizon-r2-current-reader-playback-acceptance-v1' and play['epoch']==epoch and obj==dict(bucket=receipt['bucket'],key=receipt['archive_key'],length=archive['size'],sha256=archive['sha256'],etag=receipt['archive_etag']) and play['remote_playback']['public_origin']=='https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev','foreign remote playback')
    return {k:record[k] for k in ('maximum_transfer_bytes','retained_growth_bytes')}

def capture(required_head=None):
    pub,event=helpers()
    fleet,fr=head(event)
    need(required_head is None or fr==required_head,'fleet changed before capture')
    ledger=bound(event,dict(path=str(R/'epoch172-full-half-core-20261120-v1/POST_GUARD_CAPACITY.json'),sha256='e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb'),0o444)
    prior=bound(event,dict(path=str(R/'epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json'),sha256='803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc'),0o400)['protected_raw_floor_bytes']
    registered=fleet.get('epoch199200_exclusive_phase_transfers',{})
    need(isinstance(registered,dict) and set(registered)<={str(e) for e in FIELD},'foreign transfer registry')
    ram=int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1])*1024
    cpus=os.sysconf('SC_NPROCESSORS_ONLN')
    records=[]
    for _ in range(2):
        raw=pub['capture_provider'](V11/'post-stop-fit',fr['path'],fr['sha256'])
        fit=json.loads(raw)
        need(fit['fits'] and fit['fleet']==fr and 0<=time.time()-fit['recorded_unix_seconds']<120,'unfunded native fleet')
        closed=pub['closing'](fit,fleet)
        for e,c in closed.items():
            pub['validate'](fit,fleet,fr,c['terminal'],e)
            term=bound(event,c['terminal'],0o400)
            need(term['producer_invocation_id']==T['GENERATIONS'][e] and term['producer_unit'] and term['epoch']==e and term['reservation_ending_bytes']==0,'wrong original generation')
        grants={int(k):transfer(event,int(k),v,closed[int(k)],fit['bookings'][k],fleet) for k,v in registered.items()}
        effective,summary=T['calculate'](fit,ledger,fleet,prior,grants,closed,ram,cpus)
        records.append(dict(native=fit,sha256=hashlib.sha256(raw).hexdigest(),projection=effective,summary=summary))
    a,b=records
    need(head(event)[1]==fr and pub['identity'](a['native'])==pub['identity'](b['native']) and a['native']['phase145']==b['native']['phase145'] and a['native']['candidate136']==b['native']['candidate136'] and a['native']['status_registration']==b['native']['status_registration'] and pub['closing'](a['native'],fleet)==pub['closing'](b['native'],fleet),'fleet or actor changed between captures')
    gaps={k:max(a['summary']['gaps'][k],b['summary']['gaps'][k]) for k in b['summary']['gaps']}
    return dict(schema='horizon-199200-exclusive-capacity-v1',fleet=fr,ordinary_provider_seal=SEAL,registered_transfers=registered,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),records=records,gaps=gaps,fits=not any(gaps.values()) and bool(registered),observed_unix_seconds=int(time.time()))
