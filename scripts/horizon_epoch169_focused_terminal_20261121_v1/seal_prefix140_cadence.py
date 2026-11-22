"""Bind the independent 140 verifier's physical HOME price to future native fleet samples."""
import json
import os
from pathlib import Path
import runpy
import sys

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
PREVIOUS=R/'ready-idle-cpu-20261121-v1'
ROOT=R/'prefix140-cadence-20261122-v1'
OLD=PREVIOUS/'cadence-tools'
sys.path.insert(0,str(OLD))
from evidence import bound,checked,durable,need

def main():
    need(os.geteuid()==0 and sys.flags.isolated and __debug__,'root isolated Python required')
    old=bound(OLD/'deployment-seal-receipt.json')
    need(old==checked(bound(PREVIOUS/'QUALIFIED.json'))['package_seal'],'unexpected prior cadence')
    source=ROOT/'source'
    edits={
        'capacity.py':('    return dict(observer=c.sample_ref,fleet_predecessor=c.fleet_ref,audit=audit,capacity=cap)',
                       '    from prefix140_storage import storage as prefix140_storage\n    cap["private_epoch140_verifier"]=prefix140_storage()\n'),
        'reconcile.py':('    # The 07:49 historical diagnostic',
                        '    from prefix140_storage import reconcile as prefix140_reconcile\n    prefix140_reconcile(f, capacity)\n'),
    }
    entries=[]
    for m in checked(old)['members']:
        name=m['name'];p=OLD/name
        need(bound(p)['sha256']==m['sha256'],'foreign predecessor member')
        if name in edits:
            needle, addition=edits[name];data=p.read_text()
            need(data.count(needle)==1,'unrecognized cadence source')
            p=source/name;p.write_text(data.replace(needle,addition+needle));p.chmod(0o400)
        entries.append((name,p,int(m['mode'],8)))
    entries.append(('prefix140_storage.py',source/'prefix140_storage.py',0o444))
    pkg=ROOT/'cadence-tools'
    seal=runpy.run_path(str(R/'resident-observer-20261121-v1/source/seal_resident_cadence.py'))['seal'](ROOT,pkg,entries)
    mod=runpy.run_path(str(pkg/'prefix140_storage.py'))
    current=mod['storage']()
    head_ref=checked(bound(PREVIOUS/'FIRST_COMPLETE_IDLE_CADENCE.json'))['head']
    head=checked(head_ref)
    old_charge=head['complete_DATA_with_remaining_audit_growth_bytes']
    legacy=head['continuing_audit_obligation']['current_storage']
    mod['reconcile'](head,dict(private_epoch140_verifier=current))
    amount=current['host_allocation']
    assert head['complete_DATA_with_remaining_audit_growth_bytes']==old_charge+current['remaining_DATA_growth_bytes']
    assert current['remaining_DATA_growth_bytes'] in (0, (16<<20)-amount['allocated_bytes_lower_observation'])
    assert head['continuing_audit_obligation']['current_storage']==legacy and legacy['remaining_DATA_growth_bytes']==18<<30
    duplicate=dict(head);duplicate['complete_DATA_with_remaining_audit_growth_bytes']=old_charge+1
    try:mod['reconcile'](duplicate,dict(private_epoch140_verifier=current))
    except ValueError:pass
    else:raise ValueError('duplicate 140 charge accepted')
    q=ROOT/'QUALIFIED.json';durable(q,dict(schema='horizon-prefix140-native-cadence-qualification-v1',package_seal=seal,prior_package=old,head=head_ref,
           existing_ready_only_floor=old_charge,projected_complete_fleet_with_prefix=head['complete_DATA_with_remaining_audit_growth_bytes'],
           actual_native_storage=current,qualified_duplicate_refusal=True,additional_observations=0))
    print(json.dumps(bound(q)))
if __name__=='__main__': main()
