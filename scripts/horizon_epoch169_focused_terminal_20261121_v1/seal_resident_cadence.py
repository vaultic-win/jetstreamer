"""Qualify and seal the production observer and its normal status consumer."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

R=Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT=R/'resident-observer-20261121-v1'
OLD=R/'host-census-clock-recovery-20261121-v1/cadence-tools'
sys.path.insert(0,str(OLD))
from evidence import bound,checked,durable,ensure_dir,need,SEALER


def seal(directory,destination,members):
    plan=directory/('seal-'+destination.name+'.json')
    durable(plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(destination),
                      members=[dict(name=n,source=str(p),sha256=bound(p)['sha256'],mode=m) for n,p,m in members]))
    if not destination.exists():
        sealer=Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
        need(bound(sealer)['sha256']==SEALER,'unexpected sealer')
        subprocess.run([sealer,plan,'--plan-sha256',bound(plan)['sha256'],'--self-sha256',SEALER],stdout=subprocess.DEVNULL,check=True)
    subprocess.run(['sha256sum','--check','--status','SHA256SUMS'],cwd=destination,check=True)
    ref=bound(destination/'deployment-seal-receipt.json')
    need(checked(ref)['plan_sha256']==bound(plan)['sha256'],'wrong existing seal')
    return ref


def main():
    assert os.geteuid()==0 and sys.flags.isolated and __debug__
    source,run,head=map(Path,sys.argv[1:])
    assert source==ROOT/'source' and run.parent==ROOT and len(run.name)==32
    subprocess.run(['sha256sum','--check','--status',run/'passed'],cwd=run,check=True)
    assert not (run/'work.ext4').exists() and '81 passed; 0 failed' in (run/'tests.log').read_text()
    assert '3 passed; 0 failed' in (run/'root-tests.log').read_text()
    assert bound(source/'build_resident_observer.sh')['sha256']==bound(ROOT/'build.sh')['sha256']
    prefix='/home/sol/.jetstreamer-private/observer-exit-census-20261107-v1'
    fit=checked(bound(run/'fit.json'))
    assert fit['fits'] and fit['fleet']==bound(head)
    proof=dict(source_archive=prefix+'/source-freeze.tar.gz',source_archive_sha256='4fe9c556a1dc272f04bf1f856ecb9bbf1c7e128909dddf56e487951b614e343b',
               base_manifest=bound(Path('/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/source-manifest.json')),
               patch=bound(ROOT/'pf-exiting.patch'),rss_sha256=(run/'rss.sha256').read_text().split()[0],fit=bound(run/'fit.json'),
               release=bound(run/'jetstreamer-horizon-observe'),build=bound(ROOT/'build.sh'),production_tests=bound(run/'tests.log'),
               root_tests=bound(run/'root-tests.log'),before=bound(run/'before-check.json'),after=bound(run/'after-check.json'),
               bounded_complete_attempts=5,observations=0)
    durable(run/'OBSERVER_BUILD.json',proof)
    image=ROOT/'observer/jetstreamer-horizon-observe'
    imgseal=seal(run,image.parent,[(image.name,run/image.name,0o555),('proof.json',run/'OBSERVER_BUILD.json',0o444)])
    stage=run/'package';ensure_dir(stage)
    subprocess.run([sys.executable,'-IB',source/'derive_resident_cadence.py',OLD,image,proof['release']['sha256'],stage],check=True)
    old=checked(bound(OLD/'deployment-seal-receipt.json'))
    members=[]
    for member in old['members']:
        name=member['name'];p=stage/name
        if not p.exists():
            p=OLD/name
            assert bound(p)['sha256']==member['sha256']
        members.append((name,p,int(member['mode'],8)))
    members.extend((name,source/name,0o444) for name in ['resident_clock.py','qualify_resident_clock.py'])
    pkg=ROOT/'cadence-tools'
    pkgseal=seal(run,pkg,members)
    fixture=run/'clock-fixture';ensure_dir(fixture)
    qual=json.loads(subprocess.check_output([sys.executable,'-IB',source/'qualify_resident_clock.py',pkg,fixture,head]))
    assert qual['repeated_recovery'] and len(qual['refusals'])==6 and qual['unchanged_config'] and qual['native']==bound(image)
    durable(run/'QUALIFIED.json',dict(schema='production-observer-resident-census-and-clock-qualification-v1',
           observer_seal=imgseal,package_seal=pkgseal,build=bound(run/'OBSERVER_BUILD.json'),clock_fixture=qual,
           source={p.name:bound(p) for p in source.iterdir() if p.is_file()}))
    print(json.dumps(bound(run/'QUALIFIED.json')))

if __name__=='__main__':
    main()
