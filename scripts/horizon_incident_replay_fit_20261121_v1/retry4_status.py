"""Follow the qualified retry-4 writer after the original retry-3 writer has been resolved."""
from pathlib import Path
import re

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
STATUS = R/'survivor172-cadence-20261122-v1'
ROOT = R/'epoch168-retry4-rebook-20261123-v1'
GUARD = R/'epoch168-cold-guard-20261123-v4'
PRIOR = R/'epoch168-retry3-rebook-20261123-v1'
PREFIX = 'COLD168_RETRY4_V1_STATUS_'
ANCHOR = '713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4'
FAILURE = 'cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21'
PREDECESSOR = 'b63b2e1b0f681e458a141a857db6b4b66137596f5387f9efb4edac31ab8d1bb7'
PRIOR_SEAL = '2b36ded26d4e244c166c1f3623d8f125f558b94fb1a17555b96c361d5cb3cfd2'
RESUME = STATUS/'tools-cold168-retry4-resume-v1'
RESUME_PRIOR_SHA = '16cd7406abfd04bee0ae5ad8120e095507eeb7928f3ce670a8bb83328fc414ff'
RESUME_WRITER = 'e83c7741fbb843029b110f1369e973a4'
FAILED_RESUME = 'd3c726dc3143441b80687e0c9504221b'
RESUME_FLEET = '7e45aafe0709ddd977f622a8a3ad1041678852bce5755d7268245cf07c90c037'
RESUME_SAMPLE = '8ea7d08de19c26038d88f69a4f7df04e90df4b6cc45c3a7a4b65ebba8e05094c'
EXIT = '98e322203f7a4ed290d09fe03c09fe15'


def registered_writer(s, prior, prepared_sha, guard_sha):
    oldpkg, old_seal, old_iid, old=prior
    previous, previous_ref=s.read(STATUS/'COLD168_RETRY3_V1_STATUS_ACTIVE.json',PREDECESSOR)
    s.need(oldpkg==STATUS/'tools-cold168-retry3-v1' and old_seal==s.ref(oldpkg/'deployment-seal-receipt.json',PRIOR_SEAL)
           and previous['new']==old and old_iid==old['invocation_id'],'different retry4 predecessor')
    active=STATUS/(PREFIX+'ACTIVE.json')
    rollback=STATUS/(PREFIX+'ROLLBACK.json')
    if not (active.exists() or rollback.exists()):
        return prior
    qual, qr=s.read(STATUS/(PREFIX+'QUALIFIED.json'))
    intent, ir=s.read(STATUS/(PREFIX+'INTENT.json'))
    prep, pr=s.read(ROOT/'PREPARED.json',prepared_sha)
    anchor, ar=s.read(ROOT/'SUCCESSOR_ROOT.json',ANCHOR)
    _, gr=s.read(GUARD/'GUARD_QUALIFIED.json',guard_sha)
    failure, fr=s.read(PRIOR/'RELEASED_NODE_STARTUP_FAILURE_20261123.json',FAILURE)
    admission, adm=s.read(PRIOR/'ACTUAL_ADMISSION_AND_PROTECTION.json',
                         '8dd692fda6b1098a22a2162792e7165005692385795e6cae72b6df472c7e83c0')
    s.need(failure['receipts']['ACTUAL_ADMISSION_AND_PROTECTION.json']==adm
           and failure['bootstrap_admission'] and failure['no_admission_record'] is False
           and admission['bootstrap_only'] and admission['transaction_replay_claimed'] is False
           and admission['producer_pid']==889002
           and admission['producer_invocation_id']==failure['producer']['InvocationID']=='032cb7da1929485994cf18b384c93459'
           and not failure['worker_in_observed_guard_samples'], 'different retry3 bootstrap admission')
    newpkg=STATUS/'tools-cold168-retry4-v1'
    pack=qual['package'];seal=s.bound(pack,newpkg/'deployment-seal-receipt.json')
    entry,=(v for v in seal['members'] if v['name']=='status_cycle.py')
    gen,=(v for v in seal['members'] if v['name']=='retry4-168-generation.json')
    selected=s.bound(qual['generation'],newpkg/gen['name'])
    s.need(qual['schema']=='horizon-168-retry4-v1-status-qualified-v1' and qual['epoch']==prep['epoch']==168
           and qual['prepared']==pr and qual['successor_root']==ar and qual['guard']==gr
           and qual['failed_retry3']==fr==anchor['previous_start_failure'] and failure['permit_consumed']
           and failure['worker_receipt_absent'] and not failure['replay_claimed']
           and seal['destination']==str(newpkg) and qual['entry']==s.ref(newpkg/'status_cycle.py',entry['sha256'])
           and qual['generation']==s.ref(newpkg/gen['name'],gen['sha256']) and
           selected==dict(prepared=pr,successor_root=ar,guard_qualification=gr,failed_retry3=fr)
           and re.fullmatch('[a-f0-9]{40}',qual['source_commit']) and qual['suites'],
           'unbound retry4 writer qualification')
    binding=dict(qualified=qr,old=old,admission=pr,prepared=pr,generation=qual['generation'],
                 previous_active=previous_ref,failed_retry3=fr)
    s.need(all(intent.get(k)==v for k,v in binding.items()),'foreign retry4 writer intent')
    if active.exists():
        rec,_=s.read(active)
        s.need(rec['schema']=='horizon-168-retry4-v1-status-active-v1'
               and all(rec.get(k)==v for k,v in binding.items())
               and rec['intent']==ir and rec['schedule']==intent['schedule'],'different retry4 active writer')
        actor,pkg,seal_ref=rec['new'],newpkg,pack
    else:
        rec, original=s.read(rollback)
        iid=s.show(old['unit'])['InvocationID']
        if rec['restored']['invocation_id']!=iid:
            s.need(s.iid(iid),'foreign retry4 rollback invocation')
            rec,_=s.read(STATUS/(PREFIX+'ROLLBACK_'+iid+'.json'))
            s.need(rec['original_rollback']==original,'different original retry4 rollback')
        s.need(rec['intent']==ir and rec['schedule']==intent['schedule'],'different retry4 rollback')
        actor,pkg,seal_ref=rec['restored'],oldpkg,old_seal
    s.need(actor['unit']==old['unit'] and actor['program']==str(pkg/'status_cycle.py')
           and s.iid(actor['invocation_id']) and actor['invocation_id']!=old_iid
           and all(actor['lock'][k]==old['lock'][k] for k in ('path','inode','device')),
           'foreign retry4 service, generation or exclusive lock')
    return registered_resume_writer(s, (pkg,seal_ref,actor['invocation_id'],actor))


def registered_resume_writer(s, prior):
    active = STATUS/(PREFIX+'RESUME_ACTIVE.json')
    if not active.exists():
        return prior
    old_package, _, old_iid, old = prior
    s.need(old_package==STATUS/'tools-cold168-retry4-v1' and old_iid==RESUME_WRITER,
           'different cadence resumption predecessor')
    original, original_ref = s.read(STATUS/(PREFIX+'ACTIVE.json'), RESUME_PRIOR_SHA)
    intent, intent_ref = s.read(STATUS/(PREFIX+'RESUME_INTENT.json'))
    resumed, _ = s.read(active)
    package = intent['package']
    seal = s.bound(package, RESUME/'deployment-seal-receipt.json')
    entry, = [m for m in seal['members'] if m['name']=='status_cycle.py' and m['mode']=='0444']
    actor = resumed['new']
    terminal = intent['terminal']
    schedule = intent['schedule']
    fleet, fleet_ref = s.read(R/'root231757-live166167170-20261123-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json', RESUME_FLEET)
    sample, sample_ref = s.read(R/'sample-root234757-live166167170-20261123-v1.json', RESUME_SAMPLE)
    s.need(original['new']==intent['old']==old and intent['prior_active']==original_ref
           and intent['schema']=='horizon-retry4-status-resume-intent-v1'
           and [(item['UNIT'],item['INVOCATION_ID'],item['MESSAGE_ID'],item['__CURSOR'].split(';')[1])
                for item in terminal] == [(old['unit'],RESUME_WRITER,EXIT,'i=394009d'),(old['unit'],FAILED_RESUME,EXIT,'i=3940106')]
           and int(terminal[0]['__REALTIME_TIMESTAMP']) < int(terminal[1]['__REALTIME_TIMESTAMP'])
           and schedule['fleet']==fleet_ref and schedule['config']==fleet['sole_next_observer']
           and schedule['completed_sample']==sample_ref and sample['recorded_at_utc']=='2026-11-23T23:47:57Z'
           and resumed['schema']=='horizon-retry4-status-resume-active-v1' and resumed['intent']==intent_ref
           and seal['schema']=='jetstreamer-sealed-deployment-receipt-v1'
           and seal['destination']==str(RESUME) and seal['remote_mutations'] is False
           and actor['unit']==old['unit'] and actor['program']==str(RESUME/entry['name'])
           and actor['pid']>1 and actor['start_ticks']>old['start_ticks']
           and s.iid(actor['invocation_id']) and actor['invocation_id'] not in (old_iid,FAILED_RESUME)
           and all(actor['lock'][key]==old['lock'][key] for key in ('path','inode','device')),
           'foreign or unregistered resumed cadence writer')
    return RESUME,package,actor['invocation_id'],actor


def registered_failed170_writer(s, prior):
    """Bind the terminal-aware writer without giving up the old producer booking."""
    old_package, old_seal, old_iid, old = prior
    evidence = STATUS / 'failed170-retry13-cadence-20261124-v1'
    package = STATUS / 'tools-cold168-retry4-failed170-v1'
    active, _ = s.read(evidence / 'ACTIVE.json')
    switch = s.bound(active['intent'], evidence / 'SWITCH_INTENT.json')
    ready = s.bound(active['ready'], STATUS / 'FAILED170_CADENCE_READY.json')
    drained = s.bound(switch['drained'], evidence / 'DRAINED.json')
    transition = s.bound(drained['intent'], evidence / 'DRAIN_INTENT.json')
    seal = s.bound(ready['package'], package / 'deployment-seal-receipt.json')
    prior_owner = s.bound(ready['old_owner'], STATUS / (PREFIX + 'RESUME_ACTIVE.json'))
    actor = active['new']
    s.need(old_package == RESUME and old_seal['path'] == str(RESUME / 'deployment-seal-receipt.json')
           and prior_owner['new'] == transition['old_actor'] == active['dropped_owner'] == old
           and old_iid == transition['old_owner']['InvocationID'] == old['invocation_id']
           and active['ready'] == switch['ready'] and ready['fleet'] == transition['fleet']
           and ready['old_timer'] == transition['old_timer'] and ready['terminal'] == transition['terminal']
           and ready['guard_drain'] == transition['guard_drain'] and ready['correction'] == transition['status']
           and drained['sole_lock_released'] and drained['reservation_ending_bytes'] == 0
           and seal['destination'] == str(package) and seal['remote_mutations'] is False,
           'foreign epoch 170 failure or status writer handoff')
    s.need(active['producer_mutations'] is False and switch['producer_mutations'] is False
           and actor['program'] == str(package / 'status_cycle.py') and actor['unit'] == old['unit']
           and s.iid(actor['invocation_id']) and actor['invocation_id'] != old_iid
           and actor['pid'] > 1 and actor['start_ticks'] > old['start_ticks']
           and all(actor['lock'][key] == old['lock'][key] for key in ('path', 'inode', 'device')),
           'different terminal-aware cadence owner or lock')
    return package, ready['package'], actor['invocation_id'], actor


def registered_hourly170_writer(s, prior, *, failed166=False):
    """Bind the diagnostic-aware consumer to the existing fleet lock."""
    old_package, old_seal, old_iid, old = prior
    prefix = 'FAILED166' if failed166 else 'HOURLY170'
    ready_path = STATUS / (prefix + '_CADENCE_READY.json')
    active, _ = s.read(STATUS / (prefix + '_CADENCE_ACTIVE.json'))
    ready = s.bound(active['ready'], ready_path)
    previous = s.bound(ready['old_owner'], STATUS / 'failed170-retry13-cadence-20261124-v1/ACTIVE.json')
    package = STATUS / ('tools-cold168-retry4-failed166-v1' if failed166 else
                        'tools-cold168-retry4-failed170-hourly170-v1')
    seal = s.bound(ready['package'], package / 'deployment-seal-receipt.json')
    fleet = s.bound(ready['fleet'], Path(ready['fleet']['path']))
    actor = active['new']
    schema = 'horizon-epoch166-failed-cadence' if failed166 else 'horizon-epoch170-hourly-cadence'
    s.need(old_package == STATUS / 'tools-cold168-retry4-failed170-v1'
           and old_seal['path'] == str(old_package / 'deployment-seal-receipt.json')
           and ready['schema'] == schema + '-ready-v1'
           and active['schema'] == schema + '-active-v1'
           and active['producer_mutations'] is False
           and previous['new'] == active['old'] == old
           and seal['destination'] == str(package) and seal['remote_mutations'] is False,
           'foreign hourly epoch 170 cadence transition')
    if failed166:
        recovery = s.bound(ready['old_registration'], Path(ready['old_registration']['path']))
        terminal = s.bound(recovery['terminal'], Path(recovery['terminal']['path']))
        config = s.bound(ready['config'], Path(ready['config']['path']))
        s.need(terminal['fleet'] == ready['fleet'] and terminal['prior_config'] == fleet['sole_next_observer']
               and config['previous_sample'] == fleet['observer']['path']
               and [row['range'] for row in config['replays']] == ['167', '168', '172'],
               'foreign failed epoch 166 census')
    else:
        s.need(ready['config'] == fleet['sole_next_observer'] and ready['timer'] == fleet['sole_next_timer'],
               'different hourly epoch 170 observer clock')
    s.need(actor['program'] == str(package / 'status_cycle.py') and actor['unit'] == old['unit']
           and s.iid(actor['invocation_id']) and actor['invocation_id'] != old_iid
           and actor['pid'] > 1 and actor['start_ticks'] > old['start_ticks']
           and all(actor['lock'][key] == old['lock'][key] for key in ('path', 'inode', 'device')),
           'changed hourly epoch 170 writer identity or lock')
    return package, ready['package'], actor['invocation_id'], actor


def registered_failed166_rejoin(s, prior, version=2):
    old_package, old_seal, old_iid, old = prior
    s.need(version in (2, 3, 4, 5, 6, 7, 8, 11), 'unknown epoch 166 cadence rejoin')
    def package_for(generation):
        name = f'tools-cold168-retry4-failed166-v{generation}'
        return STATUS / (name + '-entry146' if generation >= 4 else name)

    name = f'FAILED166_CADENCE_V{version}'
    predecessor = {8: 5, 11: 8}.get(version, version - 1)
    if version == 7 and old_package == package_for(5):
        predecessor = 5
    previous_name = 'FAILED166_CADENCE' if version == 2 else f'FAILED166_CADENCE_V{predecessor}'
    active, _ = s.read(STATUS / f'{name}_ACTIVE.json')
    ready = s.bound(active['ready'], STATUS / f'{name}_READY.json')
    previous = s.bound(ready['old_owner'], STATUS / f'{previous_name}_ACTIVE.json')
    fleet = s.bound(ready['fleet'], Path(ready['fleet']['path']))
    package = package_for(version)
    seal = s.bound(ready['package'], package / 'deployment-seal-receipt.json')
    actor = active['new']
    if version == 7:
        allowed = {5: '3f36fd3f6f51da689953d091aeafd620a6296d480ff0c0ee8111414d98a3b286',
                   6: 'dd6011e39810a319f7025ee7887b58aaa000a70209c14ca7ddced49769a15352'}
        s.need(old_seal['sha256'] == allowed[predecessor]
               and ready['package']['sha256'] == 'c1b777be3164beca0db8afc9777a02bbbd8f7babc09acf063acb00297cd51504',
               'different epoch 185 holding cadence deployment')
    if version == 8:
        s.need(old_seal['sha256'] == '3f36fd3f6f51da689953d091aeafd620a6296d480ff0c0ee8111414d98a3b286'
               and ready['package']['sha256'] == '3ae90b99cc09e7b58d1f88bc5ed72e8150d0383c906c0a169e401f262dab370a',
               'different missed-sample cadence deployment')
        recovery_dir = STATUS / ('recover-' + ready['config']['sha256'][:20])
        registration = s.bound(ready['recovery_registration'], recovery_dir / 'REGISTERED.json')
        failure = s.bound(registration['terminal'], recovery_dir / 'TERMINAL.json')
        config = s.bound(registration['config'], recovery_dir / 'sealed-next' / 'observer.json')
        sample = s.bound(ready['recovery_sample'], Path(config['output']))
        s.need(failure['fleet'] == ready['fleet'] and failure['prior_config'] == ready['config']
               and failure['error'] == 'native HOST RSS unavailable'
               and sample['cadence']['previous_sample_sha256'] == fleet['observer']['sha256']
               and sample['cadence']['configured_not_before_utc'] == config['not_before_utc'],
               'missed-sample rejoin does not bind the completed replacement')
    if version == 11:
        s.need(old_seal['sha256'] == '3ae90b99cc09e7b58d1f88bc5ed72e8150d0383c906c0a169e401f262dab370a'
               and ready['package']['sha256'] == 'cfcb2a66ab626bb5a0066377f22c65ca424e9e42f4a87f866f6d53be56583a5c',
               'different epoch 168 guard-stop cadence deployment')
        failure = s.bound(ready['failed_writer'], Path(ready['failed_writer']['path']))
        preflight = s.bound(ready['native_preflight'], Path(ready['native_preflight']['path']))
        config = s.bound(ready['config'], Path(ready['config']['path']))
        sample = s.bound(ready['completed_sample'], Path(config['output']))
        s.need(failure['schema'] == 'horizon-status-writer-epoch168-stop-terminal-v1'
               and failure['unit'] == old['unit'] and failure['invocation_id'] == old_iid
               and failure['exit_status'] == 1 and failure['failure'] == 'missing admitted cold worker 168'
               and failure['sample'] == preflight['sample'] == ready['completed_sample']
               and sample['cadence']['previous_sample_sha256'] == fleet['observer']['sha256']
               and sample['cadence']['configured_not_before_utc'] == config['not_before_utc']
               and preflight['fleet'] == ready['fleet'] and preflight['current_sample_accepted'] is False
               and preflight['r2_mutations'] is False and preflight['replay_launch_authorized'] is False
               and preflight['stopped_168']['resource_credit_bytes'] == 0
               and preflight['stopped_168']['reservation_ending_bytes'] == 0,
               'guard-stop cadence does not bind the failed writer and accepted sample')
    s.need(old_package == package_for(predecessor)
           and old_seal['path'] == str(old_package / 'deployment-seal-receipt.json')
           and active['schema'] == 'horizon-epoch166-cadence-rejoin-active-v1'
           and ready['schema'] == 'horizon-epoch166-cadence-rejoin-ready-v1'
           and active['producer_mutations'] is False and previous['new'] == active['old'] == old
           and ready['config'] == fleet['sole_next_observer'] and ready['timer'] == fleet['sole_next_timer']
           and seal['destination'] == str(package) and seal['remote_mutations'] is False
           and actor['program'] == str(package / 'status_cycle.py') and actor['unit'] == old['unit']
           and s.iid(actor['invocation_id']) and actor['invocation_id'] != old_iid
           and actor['pid'] > 1 and actor['start_ticks'] > old['start_ticks']
           and all(actor['lock'][key] == old['lock'][key] for key in ('path', 'inode', 'device')),
           'different epoch 166 cadence rejoin identity or clock')
    return package, ready['package'], actor['invocation_id'], actor


def registered_136_writer(s, prior):
    oldpkg, old_seal, _, old = prior
    s.need(oldpkg in (STATUS / 'tools-cold168-retry4-v1', RESUME) and old is not None,
           'different 136 cadence predecessor')
    root = STATUS / 'tools-cold168-retry4-136-v1'
    intent, intent_ref = s.read(STATUS / 'EPOCH136_V5N_STATUS_INTENT.json')
    qual = s.bound(intent['qualification'], STATUS / 'EPOCH136_V5N_STATUS_QUALIFIED.json')
    end, _ = s.read(STATUS / 'EPOCH136_V5N_STATUS_ACTIVE.json')
    previous_name = 'RESUME_ACTIVE.json' if oldpkg==RESUME else 'ACTIVE.json'
    old_active = s.bound(intent['previous_active'], STATUS / (PREFIX + previous_name))
    new = end['new']
    seal = s.bound(qual['package'], root / 'deployment-seal-receipt.json')
    entry, = [m for m in seal['members'] if m['name'] == 'status_cycle.py' and m['mode'] == '0444']
    s.need(intent['schema'] == 'horizon-136-v5n-status-intent-v1'
           and end['schema'] == 'horizon-136-v5n-status-active-v1' and end['intent'] == intent_ref
           and end['schedule'] == intent['schedule'] and old_active['new'] == intent['old'] == end['old'] == old
           and qual['schema'] == 'horizon-136-v5n-status-qualified-v1' and qual['prior_seal'] == old_seal
           and qual['suites'] and re.fullmatch('[a-f0-9]{40}', qual['source_commit'])
           and seal['schema'] == 'jetstreamer-sealed-deployment-receipt-v1' and seal['destination'] == str(root)
           and seal['remote_mutations'] is False and qual['entry'] == s.ref(root / entry['name'], entry['sha256'])
           and new['program'] == qual['entry']['path'] and new['unit'] == old['unit']
           and s.iid(new['invocation_id']) and new['invocation_id'] != old['invocation_id']
           and all(new['lock'][key] == old['lock'][key] for key in ('path','inode','device')),
           'different qualified 136 cadence owner or lock')
    return root, qual['package'], new['invocation_id'], new
