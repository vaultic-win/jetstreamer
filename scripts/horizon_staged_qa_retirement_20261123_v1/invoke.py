"""Plan or submit one owner-selected staged-test inspection or execution."""
import argparse
import fcntl
import hashlib
import os
import re
import runpy
import subprocess
import sys
import time
from pathlib import Path

RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
ALLOWED = {RUNTIME / name / 'tools' for name in
           ('stage22-sealed-qa-retirement-20261123-v1', 'stage30-sealed-qa-retirement-20261123-v1',
            'stage41-sealed-qa-retirement-20261123-v1', 'stage88-sealed-qa-retirement-20261123-v1',
            'stage128-sealed-qa-retirement-20261123-v1', 'stage88-sealed-qa-retirement-20261123-v2',
            'stage88-sealed-qa-retirement-20261123-v3')}
TOOLS = Path(__file__).absolute().parent
CARGO = RUNTIME/'epoch166-exact-cargo-retirement-20261123-v1/tools'
PROVIDER_HASH = '47fdd08d729005893e183ece467a756bcba25b5adccfe3060c1c24829e0c4ece'

def require(ok,msg):
    if not ok:
        raise RuntimeError(str(msg))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['plan','submit'])
    parser.add_argument('action',choices=['inspect','execute'])
    parser.add_argument('seal')
    parser.add_argument('--inspection-sha256')
    cfg=parser.parse_args()
    require(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__,'root python3 -IB required')
    require(TOOLS in ALLOWED and Path(__file__).absolute()==TOOLS/'invoke.py','use sealed operator')
    require(hashlib.sha256((CARGO/'host.py').read_bytes()).hexdigest()==PROVIDER_HASH,'changed fit provider')
    host=runpy.run_path(str(CARGO/'host.py'))
    host['sealed'](TOOLS,cfg.seal)
    engine=runpy.run_path(str(TOOLS/'retirement.py'))
    deployed=runpy.run_path(str(TOOLS/'host.py'))
    manifest=host['bound'](deployed['MANIFEST'],deployed['SCOPE'])
    deployed['checked_selection'](manifest, TOOLS, host['bound'])
    state=deployed['STATE']
    engine['secure_state'](state)
    require((cfg.action=='execute')==bool(cfg.inspection_sha256),'bind inspection only at execution')
    epoch=str(time.time_ns())
    unit='horizon-fit-'+deployed['PROFILE']+'-'+cfg.action+'-'+epoch
    # Retain the terminal unit, so a concurrent physical reader can finish a
    # stable census. All source names and quarantine share one writable mount.
    args=['systemd-run','--no-block','--service-type=oneshot','--unit='+unit]
    props=['CPUQuota=50%','MemoryMax=768M','MemorySwapMax=0','TasksMax=64',
           'PrivateNetwork=yes','NoNewPrivileges=yes','ProtectSystem=full','RemainAfterExit=yes',
           'TimeoutStartSec=1500','UMask=0077','Nice=10','IOSchedulingClass=best-effort','IOSchedulingPriority=7']
    for item in props:
        args+=['-p',item]
    args+=['/usr/bin/python3','-IB',str(TOOLS/'host.py'),cfg.action,cfg.seal]
    if cfg.inspection_sha256:
        require(re.fullmatch('[0-9a-f]{64}',cfg.inspection_sha256),'invalid inspection SHA')
        entries=[p for p in state.glob('inspection-*.json') if engine['fingerprint'](p)==cfg.inspection_sha256]
        require(len(entries)==1 and engine['read'](entries[0])['scope']=={'selection':deployed['SCOPE'],'seal':cfg.seal},
                'no matching inspection for this published executable')
        args+=['--inspection-sha256',cfg.inspection_sha256]
    if cfg.mode=='plan':
        print('validated',len(manifest['proposed_files']),manifest['physical_allocated_bytes'],args)
        return
    fit=deployed['price'](host)
    cg=host['read'](Path(fit['fleet']['path']))['retry9_auxiliary_commitments']
    require(cg['build_and_native_qualification_serial'] and cg['holding_and_build_may_overlap']
            and cg['build_cpu_quota_micros'] >= 500000
            and cg['build_memory_bytes'] >= (768 << 20), 'missing maintenance booking')
    for mutex in (deployed['SERIAL'],deployed['MUTEX']):
        with mutex.open('rb') as fd:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    launch=state/('launch-'+epoch)
    launch.mkdir(mode=0o700)
    engine['publish'](launch/'price.json',fit)
    engine['publish'](launch/'intent.json',dict(cmd=args,unit=unit,price_sha256=engine['fingerprint'](launch/'price.json'),
                                              seal=cfg.seal,selected=deployed['SCOPE'],credited_bytes=0))
    req=subprocess.run(args,capture_output=True,text=True,timeout=30)
    engine['publish'](launch/'submission.json',dict(unit=unit,code=req.returncode,log=req.stdout+req.stderr))
    req.check_returncode()
    print('submitted',unit,launch,flush=True)

if __name__=='__main__':
    main()
