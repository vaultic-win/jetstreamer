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
    return pkg,seal_ref,actor['invocation_id'],actor


def registered_136_writer(s, prior):
    oldpkg, old_seal, _, old = prior
    s.need(oldpkg == STATUS / 'tools-cold168-retry4-v1' and old is not None, 'different 136 cadence predecessor')
    root = STATUS / 'tools-cold168-retry4-136-v1'
    intent, intent_ref = s.read(STATUS / 'EPOCH136_V5N_STATUS_INTENT.json')
    qual = s.bound(intent['qualification'], STATUS / 'EPOCH136_V5N_STATUS_QUALIFIED.json')
    end, _ = s.read(STATUS / 'EPOCH136_V5N_STATUS_ACTIVE.json')
    old_active = s.bound(intent['previous_active'], STATUS / (PREFIX + 'ACTIVE.json'))
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
