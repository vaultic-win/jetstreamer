"""Seal the named legacy retirement and replace only the operational audit observation."""
import copy
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from types import SimpleNamespace

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
OLD=R/'resident-observer-20261121-v1/cadence-tools'
ROOT=R/'ready-audit-cadence-20261121-v1'
READY=R/'ready-range-audit-20261121-v1'
sys.path.insert(0,str(OLD))
from evidence import bound, checked, durable, ensure_dir, need
from owners import show

def main(source):
    assert os.geteuid()==0 and sys.flags.isolated and __debug__
    head=bound(R/'root221010-live166167170-20261121-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json')
    need(head['sha256']=='cc3ed077e951c11a3a563f1c45a6ef2f1ae4aeb4b2a1f4dc4012fe77d3e56855','unexpected handoff head')
    fleet=checked(head); previous=checked(fleet['current_home_cycle_capacity'])['audit_owner_witness']
    oldseal=bound(OLD/'deployment-seal-receipt.json')
    need(oldseal['sha256']=='8cfe270dc4d29793df46f669944320ec25f850e3a2478ce1a28b8837ae421c62','unexpected previous package')
    stop=bound(Path('/home/sol/.jetstreamer-private/fast-range-residency-20261121/retirement/chronological-stopped.json'))
    closed=checked(stop); legacy=closed['legacy']
    need(legacy['Id']==previous['native']['Id'] and legacy['InvocationID']==previous['native']['InvocationID'] and
         legacy['MainPID']=='0' and legacy['ActiveState']=='inactive' and legacy['UnitFileState']=='disabled' and
         int(previous['native']['MainPID']) in closed['old_pids_gone'] and closed['scope']==[101,300] and closed['preserved_receipts']==82,
         'retirement does not identify the prior public owner')
    scope=bound(READY/'scope.json'); need(scope['sha256']=='5be8c088182bcff1fc1e39a09000060e88da4c825537c9d9d934283719545d43','foreign scope')
    stage=ROOT/'staging';ensure_dir(stage)
    unit='horizon-r2-ready-ranges-101-300-20261121-v1.service'
    retirement=dict(schema='horizon-chronological-retirement-to-ready-range-v1',head=head,prior_capacity=fleet['current_home_cycle_capacity'],
        commissioning=stop,legacy_unit=legacy['Id'],legacy=legacy,prior_authority=previous['launch'],original_download_stop=previous['predecessor_stop'],
        successor_unit=unit,initial_successor=show(unit,('Id','InvocationID','MainPID','ActiveState','ControlGroup')),scope=scope,
        predecessor_seal=oldseal,resource_credit_bytes=0)
    durable(stage/'CHRONOLOGICAL_RETIREMENT.json',retirement)
    data=(OLD/'capacity.py').read_text(); needle='from public_witness import observe_public'; assert data.count(needle)==1
    out=stage/'capacity.py'; out.write_text(data.replace(needle,'from retired_public_audit import observe_public'));os.chmod(out,0o400)
    module=stage/'retired_public_audit.py';module.write_bytes((source/module.name).read_bytes());os.chmod(module,0o400)
    members=[]
    for m in checked(oldseal)['members']:
        name=m['name'];p=OLD/name;assert bound(p)['sha256']==m['sha256']
        members.append((name,out if name==out.name else p,int(m['mode'],8)))
    members += [(module.name,module,0o444),('CHRONOLOGICAL_RETIREMENT.json',stage/'CHRONOLOGICAL_RETIREMENT.json',0o444)]
    pkg=ROOT/'cadence-tools'
    seal=runpy.run_path(str(OLD.parent/'source/seal_resident_cadence.py'))['seal'](ROOT,pkg,members)
    sys.path.insert(0,str(pkg));from retired_public_audit import observe_public,regions,retired
    audit,storage,witness=observe_public(ROOT.stat().st_dev,fleet['continuing_audit_obligation'])
    assert audit['summary']['archives']==sum(b-a+1 for a,b in regions(checked(scope))) and len(regions(checked(scope)))==12 and storage['remaining_DATA_growth_bytes']==18<<30
    assert witness['native']['ActiveState']=='active' and witness['shared_slice']['CPUQuotaPerSecUSec']=='4s'
    neg=[]
    for change in ('bounds','duplicate_range','missing_range'):
        altered=copy.deepcopy(checked(scope))
        if change=='bounds':altered['scope']=[0,300]
        elif change=='duplicate_range':altered['eligible_ranges'].append(altered['eligible_ranges'][-1])
        else:altered['eligible_ranges'].pop()
        try:regions(altered)
        except ValueError:neg.append(change)
        else:raise RuntimeError(change)
    try:retired(dict(MainPID='1',ActiveState='active',Job=''),ROOT)
    except ValueError:neg.append('restarted_legacy')
    else:raise RuntimeError('revived legacy accepted')
    durable(ROOT/'QUALIFIED.json',dict(schema='ready-only-audit-cadence-qualification-v1',package_seal=seal,head=head,
        retirement=bound(pkg/'CHRONOLOGICAL_RETIREMENT.json'),native_successor=witness,private_read_only_observation=audit,
        storage=storage,refusals=neg,new_host_samples=0,remote_mutations=False))
    print(json.dumps(bound(ROOT/'QUALIFIED.json')))

if __name__=='__main__': main(Path(sys.argv[1]))
