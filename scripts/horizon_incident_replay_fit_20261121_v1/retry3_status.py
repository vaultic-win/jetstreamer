"""Follow the qualified retry-3 writer after the original retry-2 writer has been resolved."""
from pathlib import Path
import re

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
STATUS = R/'survivor172-cadence-20261122-v1'
ROOT = R/'epoch168-retry3-rebook-20261123-v1'
GUARD = R/'epoch168-cold-guard-20261123-v3'
PRIOR = R/'epoch168-retry2-rebook-20261122-v1'
PREFIX = 'COLD168_RETRY3_V1_STATUS_'
ANCHOR = 'a3042cdfc0bbe51408f032a1ee33e2f33d635060f77e4db260f10c18224c86d4'
FAILURE = 'a3353dfdbcf5de9320f22229134c9bdcaa70abb40aca0e85dd1ad315c4740643'
PREDECESSOR = 'c144e7d6badc06ea10f4aef853ce84dd33a2e906a045d1f094bce04b8693a8e5'
PRIOR_SEAL = '8c06411819ee01049d5e799756b078e62fa0f6109a8afebf4deb34790d1dee5d'


def registered_writer(s, prior, prepared_sha, guard_sha):
    oldpkg, old_seal, old_iid, old=prior
    previous, previous_ref=s.read(STATUS/'COLD168_RETRY2_V1_STATUS_ACTIVE.json',PREDECESSOR)
    s.need(oldpkg==STATUS/'tools-cold168-retry2-v1' and old_seal==s.ref(oldpkg/'deployment-seal-receipt.json',PRIOR_SEAL)
           and previous['new']==old and old_iid==old['invocation_id'],'different retry3 predecessor')
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
    newpkg=STATUS/'tools-cold168-retry3-v1'
    pack=qual['package'];seal=s.bound(pack,newpkg/'deployment-seal-receipt.json')
    entry,=(v for v in seal['members'] if v['name']=='status_cycle.py')
    gen,=(v for v in seal['members'] if v['name']=='retry3-168-generation.json')
    selected=s.bound(qual['generation'],newpkg/gen['name'])
    s.need(qual['schema']=='horizon-168-retry3-v1-status-qualified-v1' and qual['epoch']==prep['epoch']==168
           and qual['prepared']==pr and qual['successor_root']==ar and qual['guard']==gr
           and qual['failed_retry2']==fr==anchor['previous_start_failure'] and failure['permit_consumed']
           and failure['no_admission_record'] and failure['worker_receipt_absent'] and not failure['replay_claimed']
           and seal['destination']==str(newpkg) and qual['entry']==s.ref(newpkg/'status_cycle.py',entry['sha256'])
           and qual['generation']==s.ref(newpkg/gen['name'],gen['sha256']) and
           selected==dict(prepared=pr,successor_root=ar,guard_qualification=gr,failed_retry2=fr)
           and re.fullmatch('[a-f0-9]{40}',qual['source_commit']) and qual['suites'],
           'unbound retry3 writer qualification')
    binding=dict(qualified=qr,old=old,admission=pr,prepared=pr,generation=qual['generation'],
                 previous_active=previous_ref,failed_retry2=fr)
    s.need(all(intent.get(k)==v for k,v in binding.items()),'foreign retry3 writer intent')
    if active.exists():
        rec,_=s.read(active)
        s.need(rec['schema']=='horizon-168-retry3-v1-status-active-v1'
               and all(rec.get(k)==v for k,v in binding.items())
               and rec['intent']==ir and rec['schedule']==intent['schedule'],'different retry3 active writer')
        actor,pkg,seal_ref=rec['new'],newpkg,pack
    else:
        rec, original=s.read(rollback)
        iid=s.show(old['unit'])['InvocationID']
        if rec['restored']['invocation_id']!=iid:
            s.need(s.iid(iid),'foreign retry3 rollback invocation')
            rec,_=s.read(STATUS/(PREFIX+'ROLLBACK_'+iid+'.json'))
            s.need(rec['original_rollback']==original,'different original retry3 rollback')
        s.need(rec['intent']==ir and rec['schedule']==intent['schedule'],'different retry3 rollback')
        actor,pkg,seal_ref=rec['restored'],oldpkg,old_seal
    s.need(actor['unit']==old['unit'] and actor['program']==str(pkg/'status_cycle.py')
           and s.iid(actor['invocation_id']) and actor['invocation_id']!=old_iid
           and all(actor['lock'][k]==old['lock'][k] for k in ('path','inode','device')),
           'foreign retry3 service, generation or exclusive lock')
    return pkg,seal_ref,actor['invocation_id'],actor
