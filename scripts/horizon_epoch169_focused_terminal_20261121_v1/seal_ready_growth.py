"""Qualify the current HOME charge and preserve the legacy native pricing input."""
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
OLD=R/'ready-audit-cadence-20261121-v1/cadence-tools'
ROOT=R/'ready-audit-growth-20261121-v1'
sys.path.insert(0,str(OLD))
from evidence import bound,checked,durable,ensure_dir,need

def replace(data,needle,text):
    need(data.count(needle)==1,'unexpected predecessor source')
    return data.replace(needle,text)

def rewritten(stage,name,needle,text):
    p=stage/name
    p.write_text(replace((OLD/name).read_text(),needle,text)); os.chmod(p,0o400)
    return p

def main(source,policy_ref,head,registration):
    assert os.geteuid()==0 and sys.flags.isolated and __debug__
    policy=checked(policy_ref); operator=checked(policy['operator_budget'])
    need(operator and len(policy['groups'])>0,'missing operator cap or charge groups')
    if registration:
        need(Path(policy['operator_budget']['path'])==R/'ready-range-audit-20261121-v1/OUTPUT_BUDGET.json',
             'unregistered operator output budget')
    else:
        need(policy['standby_fixture'] is True,'qualification requires explicit fixture')
    scope=checked(bound(OLD/'CHRONOLOGICAL_RETIREMENT.json'))['scope']
    f=checked(head);previous=checked(f['current_home_cycle_capacity']);ar=f['current_audit_progress']['observation']
    audit=checked(ar);assert audit['inventory']==scope and 'chronological_retirement' in audit
    stage=ROOT/'staging';ensure_dir(stage)
    output=stage/'ready_audit_growth.py';output.write_bytes((source/output.name).read_bytes());os.chmod(output,0o400)
    jobs=stage/'ready_audit_jobs.py';jobs.write_bytes((source/jobs.name).read_bytes());os.chmod(jobs,0o400)
    # Keep the frozen predecessor's public status behavior and only replace its disk charge.
    witness=rewritten(stage,'retired_public_audit.py','    return audit,storage,witness',
                      "    from ready_audit_growth import accounting\n    from ready_audit_jobs import native_jobs\n    audit['active_ready_workers']=native_jobs(scope_ref)\n    return audit,accounting(current['epoch']) or storage,witness")
    rec=rewritten(stage,'reconcile.py','    # The 07:49 historical diagnostic',
                  '    from ready_audit_growth import reconcile as ready_growth\n    ready_growth(f, audit, capacity, ar)\n    # The 07:49 historical diagnostic')
    oldseal=bound(OLD/'deployment-seal-receipt.json')
    need(oldseal==checked(bound(OLD.parent/'QUALIFIED.json'))['package_seal'],'unregistered ready package')
    members=[]
    for entry in checked(oldseal)['members']:
        name=entry['name'];old=OLD/name;need(bound(old)['sha256']==entry['sha256'],'changed prior member')
        p={witness.name:witness,rec.name:rec}.get(name,old)
        members.append((name,p,int(entry['mode'],8)))
    members.extend([(output.name,output,0o444),(jobs.name,jobs,0o444)])
    pkg=ROOT/'cadence-tools';seal=runpy.run_path(str(R/'resident-observer-20261121-v1/source/seal_resident_cadence.py'))['seal'](ROOT,pkg,members)
    sys.path.insert(0,str(pkg))
    from ready_audit_growth import accounting,forecast,reconcile
    from ready_audit_jobs import native_jobs
    native_snapshot=native_jobs(scope)
    storage=accounting(audit['progress']['epoch'],policy_ref); specimen=dict(f);specimen['continuing_audit_obligation']=dict(f['continuing_audit_obligation'])
    reconcile(specimen,audit,dict(audit_storage=storage),ar)
    frozen=specimen['continuing_audit_obligation']['current_storage'];active=specimen['active_ready_range_audit_obligation']['current_storage']
    assert frozen['remaining_DATA_growth_bytes']==18<<30 and not frozen['included_in_current_aggregate']
    assert active['remaining_DATA_growth_bytes']<=256<<20 and active['remaining_cargo_growth_allowance_bytes']==0
    assert active['historical_deleted_bytes_added_to_freespace']==0
    historical=bound(R/'epoch145-semantic-continuity-20261121-v1/incident-build-72c2b7ce7b6d488183ca1b02623f0523/before.json')
    need(historical['sha256']=='968ba48e53cc30bc087ecd6498525d9a4c0ffe427fb4d697058965cdb948c8db','unexpected native paid snapshot')
    data=checked(historical);equations={}
    for version in ('v14','v15'):
        provider=R/('incident-replay-fit-20261121-v1/tools-'+version)/'post-stop-fit'
        reg=runpy.run_path(str(provider));fit=reg['fit'];ledger=reg['bound'](fit.BOOK)
        def native_projection(fleet):
            return reg['host_floor'](fleet,ledger,data['bookings']['168'],data['survivors'],
                                     data['bookings'].get('172'),data['bookings'].get('169'))[0] + data['epoch170_extension']['extra_bytes']
        expected=data['original_aggregate_HOME_bytes']
        assert native_projection(f)==native_projection(specimen)==expected
        crossed=dict(specimen);crossed['continuing_audit_obligation']=dict(specimen['continuing_audit_obligation'],current_storage=active)
        try:native_projection(crossed)
        except ValueError as exc:assert str(exc)=='changed complete host, holding, temporary or audit commitments'
        else:raise ValueError('unregistered native basis unexpectedly admitted')
        equations[version]=dict(provider=bound(provider),recorded=historical,exact_reproduced_floor=expected,
                                crossed_pricing_basis_refused=True)
    with tempfile.TemporaryDirectory(dir=ROOT) as temp:
        p=Path(temp);artifact=p/'log';artifact.write_bytes(b'x'*4096);os.link(artifact,p/'same-inode')
        group=dict(name='fixture',host_paths=[str(p)],maximum_host_allocation_bytes=1<<20)
        row=forecast([group])[0];assert row['allocated_bytes_lower_observation']==(p.stat().st_blocks+artifact.stat().st_blocks)*512
        try:forecast([group,group])
        except ValueError:pass
        else:raise ValueError('double-charged path admitted')
    retired=Path('/home/sol/.jetstreamer-private/fast-range-residency-20261121/retirement')
    reclaimed=[bound(retired/name) for name in ('controller-6993f6c464784548b08c895457d51474.json',
        'reader-eebe1e84a15d4583b0cb59f1032a3ce0.json','source-2b262175ba7e43adbbc11bcc88bd25b2.json')]
    removed=sum(checked(ref)['retirable_allocated_bytes'] for ref in reclaimed)
    assert removed==8_180_154_368
    projection=dict(schema='ready-audit-active-home-growth-pricing-v1',fleet=head,fleet_native_sample=f['observer'],original_capacity=f['current_home_cycle_capacity'],
                    raw_home_free_bytes=f['same_sample_conservative_free_DATA_bytes'],current_active_audit_growth=storage,legacy_native_pricing_basis=frozen,
                    previous_complete_DATA_with_audit=f['complete_DATA_with_remaining_audit_growth_bytes'],
                    corrected_complete_DATA_with_audit=f['complete_DATA_bytes']+active['remaining_DATA_growth_bytes'],
                    historical_cleanup=dict(receipts=reclaimed,physical_reclamation_already_in_raw_freespace_bytes=removed),
                    prior_checked_legacy_deletions_added_again=0,source_observation=ar)
    ledger=ROOT/('CURRENT_LEDGER.json' if registration else 'FIXTURE_LEDGER.json')
    projection['effective_for_live_queue']=registration
    durable(ledger,projection)
    result=dict(schema='ready-audit-growth-cadence-qualification-v1',package_seal=seal,head=head,operator_basis=policy_ref,
        unchanged_shared_quota_micros=f['continuing_audit_obligation']['additional_cpu_quota_micros'],
        ledger=bound(ledger),qualified_native_jobs=native_snapshot,overlap_refusal=True,hardlink_counted_once=True,
        legacy_pricing_compatible=True,exact_native_pricing_reproductions=equations,
        effective_for_live_queue=registration,new_host_samples=0,remote_mutations=False)
    if registration:
        first=checked(bound(ROOT/'QUALIFIED.json'))
        need(first['package_seal']==seal and not first['effective_for_live_queue'],'wrong standby package')
    receipt=ROOT/('REGISTERED.json' if registration else 'QUALIFIED.json')
    durable(receipt,result)
    print(json.dumps(bound(receipt)))

if __name__=='__main__':
    mode,source,policy,policy_sha,head,head_sha=sys.argv[1:]
    need(mode in ('prepare','register'),'choose prepare or register')
    main(Path(source),dict(path=policy,sha256=policy_sha),dict(path=head,sha256=head_sha),mode=='register')
