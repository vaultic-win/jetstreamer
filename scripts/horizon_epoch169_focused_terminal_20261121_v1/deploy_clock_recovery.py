"""Derive the exact late-window consumer from the previously qualified production package."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
OLD = R / 'epoch169-focused-terminal-20261121-v1/cadence-tools'
ROOT = R / 'host-census-clock-recovery-20261121-v1'
BASE_SHA = '96f3180ef0ed6a35765f28afd698330db267f3092dcf4c9b648b819e69ef4810'
sys.path.insert(0, str(OLD))
from evidence import bound, checked, durable, ensure_dir, need, sealed, SEALER
from cycle import load_fleet

def seal(dest, members):
    p = ROOT / ('plan-' + dest.name + '.json')
    durable(p, dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=str(dest),
                    members=[dict(name=name, source=str(path), mode=mode, sha256=bound(path)['sha256'])
                             for name,path,mode in members]))
    tool = Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
    need(bound(tool)['sha256'] == SEALER, 'foreign sealer')
    if not dest.exists():
        subprocess.run([tool,p,'--plan-sha256',bound(p)['sha256'],'--self-sha256',SEALER],check=True,stdout=subprocess.DEVNULL)
    subprocess.run(['sha256sum','--check','--status','SHA256SUMS'],cwd=dest,check=True)
    return bound(dest/'deployment-seal-receipt.json')

def main():
    assert os.geteuid()==0 and sys.flags.isolated and __debug__ and len(sys.argv)==3
    repo, commit = Path(sys.argv[1]),sys.argv[2]
    def git(*args):
        return subprocess.check_output(['runuser','-u','sol','--','git','-C',repo,*args])
    git('merge-base','--is-ancestor',commit,'refs/remotes/origin/account-updates')
    prefix='scripts/horizon_epoch169_focused_terminal_20261121_v1/'
    def source(name):
        return git('show',commit+':'+prefix+name)
    assert source('deploy_clock_recovery.py') == Path(__file__).read_bytes()
    base=bound(OLD/'deployment-seal-receipt.json')
    assert base['sha256']==BASE_SHA
    orig = checked(base)
    subprocess.run(['sha256sum','--check','--status','SHA256SUMS'],cwd=OLD,check=True)
    ensure_dir(ROOT)
    stage=ROOT/'stage'
    ensure_dir(stage)
    def write(name,data):
        path=stage/name
        if path.exists():
            assert path.read_bytes()==data
        else:
            with path.open('xb') as f:
                os.fchmod(f.fileno(),0o400);f.write(data);f.flush();os.fsync(f.fileno())
        return path
    path=write('clock_recovery.py',source('clock_recovery.py'))
    sys.path.insert(0,str(stage))
    import clock_recovery as bridge
    fleet,cfg,_=load_fleet(bridge.HEAD)
    obs=stage/'observer.json';durable(obs,bridge.replacement(cfg))
    config_seal=seal(ROOT/'sealed-next',[('observer.json',obs,0o444)])
    view,new=bridge.view(bridge.HEAD,fleet,cfg)
    assert new==sealed(view['sole_next_observer'])
    edits={
        'cycle.py':('    return f,cfg,prevs','    from clock_recovery import view\n    f,cfg=view(ref,f,cfg)\n    return f,cfg,prevs'),
        'guard_stops.py':('    fleet=checked(fleet_ref)\n    effective,effective_path',
                          '    from clock_recovery import view\n    fleet,cfg=view(fleet_ref,checked(fleet_ref),cfg)\n    effective,effective_path'),
        'race166.py':('    p=Path(path);directory=p.parent.parent',
                      '    import clock_recovery\n    if Path(path)==clock_recovery.CONFIG:\n        return clock_recovery.scheduled(Path(path))\n    p=Path(path);directory=p.parent.parent')}
    members=[('clock_recovery.py',path,0o444)]
    for item in orig['members']:
        name=item['name'];p=OLD/name;assert bound(p)['sha256']==item['sha256']
        if name in edits:
            a,b=edits[name];code=p.read_text();assert code.count(a)==1
            code=code.replace(a,b);compile(code,name,'exec');p=write(name,code.encode())
        members.append((name,p,int(item['mode'],8)))
    pkg=ROOT/'cadence-tools'
    package=seal(pkg,members)
    meta=json.loads(subprocess.check_output([sys.executable,'-B',pkg/'describe.py',
                                             bridge.HEAD['path'],bridge.HEAD['sha256']]))
    assert meta['due']==bridge.TARGET and meta['sample']==new['output'] and meta['required_reports']==19
    # Use previous verifier unchanged on the first successor once its complete fleet exists.
    durable(ROOT/'BRIDGE.json',dict(predecessor=bridge.HEAD,incomplete=bridge.CLOSED,
                                    config=config_seal,package=package,source_commit=commit,meta=meta))
    print(json.dumps(meta))

if __name__=='__main__':
    main()
