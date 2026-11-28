"""Transfer the existing cadence service to the qualified epoch 168 receiver before replay starts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys

BASE = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = BASE/'survivor172-cadence-20261122-v1'
SESSION = BASE/'epoch168-retry2-rebook-20261122-v1'
OLD = ROOT/'tools-cold170-retry13-v2/status_cycle.py'
TARGET = ROOT/'tools-cold168-retry2-v1'
TAG = 'COLD168_RETRY2_V1_STATUS_'
QUALIFIED = ROOT/(TAG+'QUALIFIED.json')
ACTIVE = ROOT/(TAG+'ACTIVE.json')
PREPARED = {'path':str(SESSION/'PREPARED.json'),'sha256':'dd1b2296e8cd987eccf90053b999d647cd28c09a43279493fd625c719ed0388a'}
ANCHOR = {'path':str(SESSION/'SUCCESSOR_ROOT.json'),'sha256':'ec909d6701ce7dcbee72da319bf0179ba375e1cf6e284aa29686e1dd0a3cbecc'}
GUARD = {'path':str(BASE/'epoch168-cold-guard-20261122-v2/GUARD_QUALIFIED.json'),'sha256':'bab2140873334dfbab487be91cf044a31a000cbdec525075fe1ea4a086198e2b'}
PREVIOUS = {'path':str(ROOT/'COLD170_RETRY13_V2_STATUS_ACTIVE.json'),'sha256':'6b180fd6e5fab24a547e4951b290b50404d8d39fae5e0a9374db0bb27800f486'}
COMMON = ROOT/'retry13-170-switch-v2/handoff_cold167.py'
COMMON_SHA = '7f189ae92d13bca515099267852c1551fa43f159387eee7af5ec48839933260d'
OLD_SHA = 'c33a5af976a225d3fe5957e698ec70fc41df19d4932727122c44dc48a93162b1'
FORECAST = ROOT/'third170-234757-dependency-forecast'
FORECAST_PREP = {'path':str(FORECAST/'PREPARED.json'),'sha256':'6f7bb045e38425ffd644a8bed03a120b51877569a53743a15f8459e71161d958'}
CHANGED = {136,137,140,141,145,159,161,163,171,173,185,186,199,200}
DUE = '2026-11-23T00:17:57Z'
SEALER_SHA = 'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3'


def need(condition, why):
    if not condition:
        raise ValueError(why)


ATTEMPT = 2
FAILURE = dict(path=str(BASE/'epoch168-retry2-rebook-20261122-v1/RELEASED_NODE_STARTUP_FAILURE_20261123.json'),
               sha256='a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643')
FIRST_RETRY2_CYCLE = dict(path=str(BASE/'root004757-live166167170-20261123-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),
                          sha256='39db14ce7cbc96d1ca300e1120db6e67e4b5048582f8968f9886fd4317a107cc')


def configure_successor(attempt):
    global ATTEMPT,SESSION,OLD,TARGET,TAG,QUALIFIED,ACTIVE,PREPARED,ANCHOR,GUARD,PREVIOUS,OLD_SHA,FAILURE
    global FORECAST,FORECAST_PREP,DUE
    need(attempt in (3,4), 'unknown successor')
    ATTEMPT=attempt
    SESSION=BASE/f'epoch168-retry{attempt}-rebook-20261123-v1'
    OLD=ROOT/f'tools-cold168-retry{attempt-1}-v1/status_cycle.py'
    if attempt==3:
        OLD_SHA='dc0f98d1b468c2568abc63c723167e47529ec5f8f03b683421c77468184db690'
        anchor_sha='a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4'
        previous_sha='c144e7d6badc06ea10f4aef853ce84dd33a2e906a045d1f094bce04b8693a8e5'
    else:
        OLD_SHA='d8823404a5dcf35965fb5b519569dd8fc5ede733cea215a582aa5669d8b9eb98'
        anchor_sha='713e94750dd3d430c2f54c1ccb2af7ed708dec802af5cbf210ee4963a992d0f4'
        previous_sha='b63b2e1b0f681e458a141a857db6b4b66137596f5387f9efb4edac31ab8d1bb7'
        FAILURE=dict(path=str(BASE/'epoch168-retry3-rebook-20261123-v1/RELEASED_NODE_STARTUP_FAILURE_20261123.json'),
                     sha256='cf8ef71b5b000cc4138f726d019c59a107b9b3d45f741b0b4802a6f4f31f1d21')
        FORECAST=ROOT/'three-004757-dependency-forecasts'
        FORECAST_PREP=dict(path=str(FORECAST/'PREPARED.json'),sha256='88627ed83dc9d40ab4179ab4ed286f0c3a7c82c9f21bcf5d40af902b727ca6eb')
        DUE='2026-11-23T01:17:57Z'
    TARGET=ROOT/f'tools-cold168-retry{attempt}-v1'
    TAG=f'COLD168_RETRY{attempt}_V1_STATUS_'
    QUALIFIED=ROOT/(TAG+'QUALIFIED.json')
    ACTIVE=ROOT/(TAG+'ACTIVE.json')
    q=json.loads(QUALIFIED.read_bytes())
    PREPARED=q['prepared']
    GUARD=q['guard']
    need(PREPARED['path']==str(SESSION/'PREPARED.json') and
         GUARD['path']==str(BASE/f'epoch168-cold-guard-20261123-v{attempt}/GUARD_QUALIFIED.json'), 'foreign 168 enrollment paths')
    ANCHOR=dict(path=str(SESSION/'SUCCESSOR_ROOT.json'),sha256=anchor_sha)
    PREVIOUS=dict(path=str(ROOT/f'COLD168_RETRY{attempt-1}_V1_STATUS_ACTIVE.json'),sha256=previous_sha)


def generation_record():
    data=dict(prepared=PREPARED,successor_root=ANCHOR,guard_qualification=GUARD)
    if ATTEMPT>2:
        data[f'failed_retry{ATTEMPT-1}']=FAILURE
    return data


def checked_member(c, path):
    seal = c['bound'](path.parent/'deployment-seal-receipt.json')
    manifest = c['checked'](seal)
    member, = (row for row in manifest['members'] if row['name']==path.name)
    need(manifest['schema']=='jetstreamer-sealed-deployment-receipt-v1' and
         manifest['sealer_sha256']==SEALER_SHA and manifest['remote_mutations'] is False and
         path.resolve(strict=True)==path and manifest['destination']==str(path.parent) and
         member['mode']=='0444' and path.stat().st_mode & 0o777==0o444 and
         c['bound'](path)['sha256']==member['sha256'], 'different sealed program '+str(path))
    return seal


def enrollment(c):
    ref=c['bound'](QUALIFIED)
    q=c['checked'](ref)
    need(q['schema']==f'horizon-168-retry{ATTEMPT}-v1-status-qualified-v1' and q['epoch']==168 and
         q['guard']==GUARD and q['successor_root']==ANCHOR and q['prepared']==PREPARED and
         q['generation'] is not None and re.fullmatch('[0-9a-f]{40}',q['source_commit']) and
         isinstance(q['suites'],dict) and q['suites'], 'different status qualification')
    for enrolled in (PREPARED,ANCHOR,GUARD):
        c['checked'](enrolled)
    program=TARGET/'status_cycle.py'
    need(checked_member(c,program)==q['package'] and c['bound'](program)==q['entry'],
         'different qualified epoch 168 program or package')
    if ATTEMPT>2:
        need(q[f'failed_retry{ATTEMPT-1}']==c['checked'](ANCHOR)['previous_start_failure']==FAILURE
             and c['checked'](FAILURE)['no_admission_record'] is (ATTEMPT==3), 'foreign previous 168 admission')
    generation=TARGET/f'retry{ATTEMPT}-168-generation.json'
    need(checked_member(c,generation)==q['package'] and c['bound'](generation)==q['generation'] and
         c['checked'](q['generation'])==generation_record(),
         'different qualified epoch 168 generation')
    return ref,q


def finished_forecast(c):
    """Bind the original issuer and fourteen conditional intents to all twenty authenticated readbacks."""
    if ATTEMPT==3:
        accepted=c['checked'](PREVIOUS)
        fleet=c['checked'](FIRST_RETRY2_CYCLE)
        final=fleet['complete_active_status_audit']
        audit=c['checked'](final)
        rows=fleet['complete_active_status_receipts']
        need(accepted['new']['program']==str(OLD) and accepted['new']['invocation_id']=='040a0247801f47968d9e33d77eab2e5e'
             and audit['authenticated_readback'] and not audit['archives_or_sidecars_changed']
             and audit['receipts']==rows and len(rows)==audit['authenticated_status_count']==20,
             'incomplete first retry2 readback')
        for epoch, item in rows.items():
            row=c['checked'](item)
            need(row['authenticated_readback'] and row['epoch']==int(epoch) and
                 re.fullmatch('[0-9a-f]{64}',row['after_sha256']) and row['after_etag'], 'foreign first retry2 status')
        return final,FIRST_RETRY2_CYCLE
    subscriber=c['checked'](PREVIOUS)
    issuer=PREVIOUS
    if ATTEMPT==4:
        issuer=subscriber['previous_active']
        need(issuer['sha256']=='c144e7d6badc06ea10f4aef853ce84dd33a2e906a045d1f094bce04b8693a8e5'
             and c['checked'](issuer)['new']==subscriber['old'] and subscriber['new']['program']==str(OLD)
             and subscriber['new']['invocation_id']=='c66cbea9e6d847b6aadd08b320fe6602',
             'wrong retry3 forecast successor')
    prior=c['checked'](issuer)
    prep=c['checked'](FORECAST_PREP)
    final_ref=c['bound'](FORECAST/'FINAL_READBACK.json')
    final=c['checked'](final_ref)
    hand=c['checked'](final['handoff'])
    expected=c['names'](DUE)
    fleet=c['checked'](final['fleet'])
    whole=c['checked'](fleet['complete_active_status_audit'])
    actual=fleet['complete_active_status_receipts']
    need(final['handoff']==c['bound'](FORECAST/'SENT_TO_SOLE_WRITER.json') and sorted(CHANGED)==final['corrections']
         and prep['controller']==issuer and hand['owner']==prior['new'] and
         hand['remote_writes']==final['remote_writes_by_handoff']==0 and set(map(int,hand['inputs']))==CHANGED and
         final['fleet']==c['bound'](expected['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json') and
         fleet['previous_Root_operational_review']==prep['head'] and fleet['observer']==hand['sample']==whole['observer']
         and whole['fleet_predecessor']==prep['head'] and whole['archives_or_sidecars_changed'] is False and
         whole['authenticated_readback'] is True and whole['authenticated_status_count']==len(actual)==20
         and actual==whole['receipts'] and set(prep['statuses'])==set(final['statuses'])==set(actual),
         'wrong issuer, forecast handoff, fleet or authenticated status population')
    for key,receipt in actual.items():
        row=c['checked'](receipt)
        need(row['authenticated_readback'] is True and final['statuses'][key]=={
             'receipt':receipt,'etag':row['after_etag'],'sha256':row['after_sha256']}, 'unbound R2 readback for '+key)
        if int(key) in CHANGED:
            intent=c['checked'](hand['inputs'][key])
            need(row['before_etag']!=row['after_etag'] and intent['conditional_header']=='If-Match' and
                 intent['previous_receipt']==prep['statuses'][key]['receipt'] and intent['active_status_writer']==issuer and
                 all(row[k]==v for k,v in intent.items()),'different original forecast intent '+key)
    return final_ref,final['fleet']


def current_cycle(c,head,first):
    current=head;seen=set()
    before=c['checked'](FORECAST_PREP)['head']
    while current!=first:
        path=Path(current['path'])
        need(path.parent.parent==BASE and path.name=='ROOT_COMPLETE_OPERATIONAL_FLEET.json' and
             current!=before and current['sha256'] not in seen,'fleet is outside the completed 00:17 forecast chain')
        seen.add(current['sha256'])
        previous=c['checked'](current)['previous_Root_operational_review']
        need(isinstance(previous,dict) and previous.get('path'), '00:17 cutover predecessor missing')
        current=previous
    fleet=c['checked'](head)
    statuses=c['checked'](fleet['complete_active_status_audit'])
    need(fleet['complete_active_status_count']==statuses['authenticated_status_count']==20 and
         statuses['authenticated_readback'] and statuses['receipts']==fleet['complete_active_status_receipts'],
         'incomplete status cycle')
    config=c['sealed'](fleet['sole_next_observer'])
    future=c['names'](config['not_before_utc'])['statuses']
    need(not future.exists() or (future.is_dir() and not any(future.iterdir())),'next status cycle has pending work')
    return future


def check_owner(owner,original,program):
    need(owner['unit']==original['unit'] and owner['program']==str(program) and
         re.fullmatch('[a-f0-9]{32}',owner['invocation_id']) and owner['invocation_id']!=original['invocation_id'] and
         all(owner['lock'][key]==original['lock'][key] for key in ('path','device','inode')),
         'different replacement service, lock or invocation')


def restored_owner(c,owner,original):
    check_owner(owner,original,OLD)
    intent_path=ROOT/(TAG+'INTENT.json')
    intent=c['read_ref'](intent_path)
    ref=c['bound'](ROOT/(TAG+'ROLLBACK.json'))
    rollback=c['checked'](ref)
    if rollback['restored']['invocation_id']!=owner['invocation_id']:
        rollback=c['read_ref'](ROOT/(TAG+'ROLLBACK_'+owner['invocation_id']+'.json'))
        need(rollback['original_rollback']==ref,'different original rollback')
    need(intent['old']==original and rollback['restored']==owner and
         rollback['intent']==c['bound'](intent_path) and rollback['schedule']==intent['schedule'],
         'unregistered restored writer')


def registration(c):
    incumbent=c['checked'](PREVIOUS)['new']
    qualification,q=enrollment(c)
    final,first=finished_forecast(c)
    binding=dict(prepared=PREPARED,generation=q['generation'],completed_forecast=final)
    if ATTEMPT>2:
        binding.update(previous_active=PREVIOUS,**{f'failed_retry{ATTEMPT-1}':FAILURE})
    intent_path=ROOT/(TAG+'INTENT.json')
    if intent_path.exists():
        intent=c['read_ref'](intent_path)
        need(intent['old']==incumbent and intent['qualified']==qualification and intent['admission']==PREPARED and
             all(intent.get(k)==v for k,v in binding.items()),'different epoch 168 handoff intent')
    if ACTIVE.exists():
        adopted=c['read_ref'](ACTIVE)
        need(adopted['old']==incumbent and adopted['intent']==c['bound'](intent_path) and
             adopted['schedule']==intent['schedule'] and adopted['admission']==PREPARED and
             adopted['qualified']==qualification and all(adopted.get(k)==v for k,v in binding.items()),
             'different completed 168 receiver handoff')
        check_owner(adopted['new'],incumbent,TARGET/'status_cycle.py')
    return incumbent,qualification,binding,first


def switch(c,common,head):
    incumbent,qualification,binding,first=registration(c)
    intent_path=ROOT/(TAG+'INTENT.json')
    def enrollment_proof(_):
        # An accepted handoff remains identifiable once the epoch starts or the next clock fires.
        if not ACTIVE.exists():
            current_cycle(c,head,first)
            need(not any((SESSION/n).exists() for n in ('START_INTENT.json','ACTUAL_PRODUCER_NATIVE.json',
                     'ACTUAL_ADMISSION_AND_PROTECTION.json','FIRST_PROTECTED_WORKER.json')) and
                 not (SESSION/'barrier/allow').exists(),'epoch 168 changed before receiver activation')
        need(enrollment(c)[0]==qualification,'receiver qualification changed')
        return PREPARED
    def write(path,record):
        if path==intent_path:
            need(record['old']==incumbent,'different original publisher')
        if path in (ACTIVE,intent_path):
            record=dict(record,**binding)
        if path==ACTIVE:
            if ATTEMPT>2:
                record=dict(record,schema=f'horizon-168-retry{ATTEMPT}-v1-status-active-v1')
            check_owner(record['new'],incumbent,TARGET/'status_cycle.py')
        if 'restored' in record:
            check_owner(record['restored'],incumbent,OLD)
        c['durable'](path,record)
    drop=common['DROP'].with_name('z'*(15+ATTEMPT)+f'-cold168-retry{ATTEMPT}-v1.conf')
    return common['switch'](dict(c,durable=write),head,target=TARGET,incumbent=OLD,
             incumbent_iid=incumbent['invocation_id'],tag=TAG,drop=drop,admission=enrollment_proof)


def main(args):
    if args.attempt>2:
        configure_successor(args.attempt)
    need(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__,
         'run with isolated root Python and disabled bytecode')
    need(hashlib.sha256(COMMON.read_bytes()).hexdigest()==COMMON_SHA and
         hashlib.sha256(OLD.read_bytes()).hexdigest()==OLD_SHA,'original handoff or status code changed')
    common=runpy.run_path(str(COMMON));c=runpy.run_path(str(OLD))
    p=Path(args.fleet)
    need(p.name=='ROOT_COMPLETE_OPERATIONAL_FLEET.json' and p.parent.parent==BASE,'foreign fleet path')
    head=c['bound'](p)
    if args.mode=='observe':
        old=c['checked'](PREVIOUS)['new']
        accepted=ACTIVE.exists()
        owner=common['publisher'](c,TARGET/'status_cycle.py' if accepted else OLD)
        if accepted:
            registration(c)
            need(c['read_ref'](ACTIVE)['new']==owner,'different accepted writer')
        elif (ROOT/(TAG+'ROLLBACK.json')).exists():
            restored_owner(c,owner,old)
        else:
            need(owner==old,'different incumbent writer')
        observation=dict(owner=owner,head=head,accepted=accepted,forecast_complete=False)
        if (FORECAST/'FINAL_READBACK.json').exists():
            final,first=finished_forecast(c)
            future=current_cycle(c,head,first)
            observation.update(forecast_complete=True,readback=final,next_status_directory=str(future))
        observation['schedule']=common['timer_evidence'](c,head,0)
        return observation
    checked_member(c,Path(__file__).resolve())
    fd=c['lock'](ROOT/'cold167-status-handoff.lock')
    try:
        return switch(c,common,head)
    finally:
        os.close(fd)


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=('observe','activate'))
    parser.add_argument('fleet')
    flags=parser.add_mutually_exclusive_group()
    flags.add_argument('--retry3',dest='attempt',action='store_const',const=3)
    flags.add_argument('--retry4',dest='attempt',action='store_const',const=4)
    parser.set_defaults(attempt=2)
    print(json.dumps(main(parser.parse_args()),sort_keys=True))
