"""Handle original terminal or capacity transfers; enforce guard-first PID1 launch."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
F=runpy.run_path(str(HERE/'transition_fit.py'))
W=runpy.run_path(str(HERE/'watch.py'))
C=W['C']
B=C['B']
HOLD=C['HOLD']
CTRL=C['CTRL']
need=C['need']
STATE=B/'transition-state'
CAP=HERE/'transition_event.py'
UNIT='horizon-199200-phase-checkpoint.service'
FOCUSED=B.parent/'epoch169-focused-terminal-20261121-v1/TERMINAL_GUARD_DRAINED.json'

def sh(*args):
    return subprocess.check_output(['/usr/bin/systemctl',*args],text=True,timeout=25)

def evidence():
    meta=(HERE/'deployment-seal-receipt.json').lstat()
    need(HERE==B/'phase-transition-v4' and meta.st_uid==0 and meta.st_nlink==1 and meta.st_mode&0o222==0,'unsealed transition install')
    seal=json.loads((HERE/'deployment-seal-receipt.json').read_bytes())
    need(seal['destination']==str(HERE) and all(hashlib.sha256((HERE/m['name']).read_bytes()).hexdigest()==m['sha256'] for m in seal['members']),'changed transition provider')
    _,event=F['helpers']()
    proof,_=event['document'](STATE/'BRANCH_V4.json',0o400)
    need(proof['origin']=='origin/account-updates' and proof['package_seal']==hashlib.sha256((HERE/'deployment-seal-receipt.json').read_bytes()).hexdigest() and proof['merged_source_files']=={m['name']:m['sha256'] for m in seal['members']} and re.fullmatch('[a-f0-9]{40}',proof['contained_commit']),'production source lacks branch binding')
    # On this host a current head can move without disturbing immutable deployed sources.
    repo='/home/sol/workspace/jetstreamer'
    subprocess.run(['/usr/sbin/runuser','-u','sol','--','/usr/bin/git','-C',repo,'merge-base','--is-ancestor',proof['contained_commit'],'refs/remotes/origin/account-updates'],check=True,timeout=10)
    return event

def effective(a):
    need(a['fits'] and not any(a['gaps'].values()),'unfunded 199/200 candidate')
    rows=[r['projection'] for r in a['records']]
    v=dict(rows[-1])
    for k in ('complete_required_HOME_bytes','complete_memory_plus_reserve_bytes','required_available_memory_bytes','complete_cpu_quota_micros'):
        v[k]=max(r[k] for r in rows)
    return v

def check_install():
    all_units=runpy.run_path(str(HERE/'transition_units.py'))['units']()
    for name,body in all_units.items():
        path=Path('/etc/systemd/system')/name
        need(path.resolve(strict=True)==path and path.read_text()==body and path.stat().st_uid==0 and path.stat().st_mode&0o022==0,'changed PID1 dependency or budget '+name)

def guard():
    evidence();check_install()
    # This service exclusively owns the whole 199/200 reservation throughout import.
    with (STATE/'reservation.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        a=F['capture']()
        W['protect'](effective(a),a)

def controller():
    event=evidence(); check_install()
    info=W['props'](HOLD);iid=info['InvocationID']
    need(info['ActiveState']=='active' and info['SubState']=='running' and re.fullmatch('[0-9a-f]{32}',iid),'missing original guard owner')
    d=B/('guard-'+iid)
    # PID1 After= orders service startup. The first protecting observation is the admission barrier.
    own=W['props'](CTRL)
    need(own['InvocationID']==os.environ['INVOCATION_ID'] and int(own['MainPID'])==os.getpid() and own['Slice']=='horizon199200-aux.slice','foreign controller')
    deadline=time.monotonic()+420
    while not (d/'FIRST_PROTECTING_GUARD.json').exists():
        need(time.monotonic()<deadline and W['props'](HOLD)['InvocationID']==iid,'guard failed before the first protecting sample')
        time.sleep(.5)
    a,_=event['document'](d/'EXCLUSIVE_TRANSITION.json',0o400)
    need(time.time()-a['observed_unix_seconds']<180 and F['head'](event)[1]==a['fleet'],'funded fleet changed before controller')
    plan,plan_ref=event['document'](d/'PLAN.json',0o400)
    first,_=event['document'](d/'FIRST_PROTECTING_GUARD.json',0o400)
    sample=F['bound'](event,first['sample'],0o600)
    C['gate'](sample,plan,plan_ref['sha256'],int(info['MainPID']),time.time(),info['ControlGroup'])
    argv=C['controller_options'](effective(a))
    need('--execute' not in argv,'unexpected execution argument')
    os.execv(argv[0],[*argv,'--execute'])

def registered_head(event):
    # An allocation can reach its immutable registry before the existing cadence
    # has accepted it. Subscribe before inspecting, then wake only on that event.
    changes=event['Changes']()
    try:
        changes.watch(F['R'])
        while True:
            for d in F['R'].glob('root??????-live166167170-????????-v1'):
                if d.is_dir() and time.time()-d.stat().st_mtime<2700:
                    changes.watch(d)
            f,fr=F['head'](event)
            actual={str(e):event['document'](F['REG']/f'{e}.json',0o400)[1] for e in F['FIELD'] if (F['REG']/f'{e}.json').exists()}
            declared=f.get('epoch199200_exclusive_phase_transfers',{})
            need(all(actual.get(k)==v for k,v in declared.items()),'unregistered or conflicting grant in the accepted root fleet')
            diagnostic=event['document'](FOCUSED,0o400)[1] if FOCUSED.exists() else None
            published=f.get('focused169_guard_retirement')
            need(published is None or published==diagnostic,'conflicting focused guard retirement')
            if actual==declared and diagnostic==published:
                return fr
            changes.wait()
    finally:
        changes.close()

def checkpoint():
    event=evidence(); check_install()
    iid=os.environ['INVOCATION_ID']
    need(re.fullmatch('[0-9a-f]{32}',iid) and W['props'](UNIT)['InvocationID']==iid,'foreign checkpoint owner')
    with (STATE/'checkpoint.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        path=STATE/('event-'+iid+'.json')
        reasons=['original focused 169 guard retired'] if FOCUSED.exists() else []
        for e in F['FIELD']:
            d=F['delivery'](e)
            if (d/'event-state/INTENT.json').is_file():reasons.append(f'accepted publisher {e}')
            if list(d.glob(f'run-*/receipts/epoch-{e}.r2.json')):reasons.append(f'published {e}')
        for item in F['REG'].glob('*.json'):
            reasons.append('root transfer '+item.name)
        if not reasons:
            event['once'](path,dict(outcome='awaiting-original-transition',real_transition_evidence=[],replay_started=False))
            return
        for unit in (HOLD,CTRL):
            state=W['props'](unit)
            if state['ActiveState'] in ('active','activating','deactivating'):
                event['once'](path,dict(outcome='existing-199200-manager',unit=unit,state=state,replay_started=False))
                return
        try:
            result=F['capture'](registered_head(event))
            record=dict(reasons=reasons,capacity=result,outcome='funded' if result['fits'] else 'not-funded',replay_started=False)
        except Exception as exc:
            event['once'](path,dict(reasons=reasons,outcome='provider-refused',detail=str(exc),replay_started=False))
            raise
        event['once'](path,record)
        if result['fits']:
            # Queue only the existing fixed owners. The guard repeats the full two-capture
            # grant review; the controller rechecks that guard's current original sample.
            sh('start','--no-block',HOLD,CTRL)

if __name__=='__main__':
    need(os.geteuid()==0 and sys.flags.isolated and __debug__ and len(sys.argv)==2,'root entry point required')
    {'checkpoint':checkpoint,'guard':guard,'controller':controller}[sys.argv[1]]()
