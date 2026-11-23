"""Close the two exact timers that continued firing after their original producers drained."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).parent))
from funding import CG, D, V, bound, partition, ref
from owners import props
import funds

ROOT = D/'horizon-terminal-guard-closures-v215'
WINDOW = Path('/tmp/horizon-v162-takeover/guard-window.py')
PREVIOUS = '15f4114d378b24b09098e478975010c9c93ccabd6f602b4014261dae34f7c757'
CONFIG = {
    265: ('horizon-265-replacement-20261119-protective-v3','horizon265-replacement-20261119-guard-v3',
          'ebd9d801abd65d504dd4b63e8e6106fa771cae4d1b320a5ae3ce358df983501a',
          'horizon-singleton-delivery265-20261120-v1/terminal-drain.json','8ce7206e139b9dcd3fc1312619f9125147404925ebe275027581a0dced5624ca',
          '182de64d33674f95b7758d410eb1812b','50f90e4b68884d40ab45f9025ca8dd2e',
          '049b5ddcba4a7ee373ee563b7768ca3850f507702763cebd92bb38f2577cf32d','2590387503c0e1a8d61838aaef782777d91f5e3d5cc275451cda86e0becc903f'),
    266: ('horizon-native266-protective-v1','horizon-native266-guard-binding-cold-5e05c518-v160-a',
          'c0590b034179ad0b770a182772afdd97c82a6441da978a6aa5864b653c2ade03',
          'horizon-native266-terminal-proof-v161-cold-a1/proof.json','7affafddf177c057661d73b339a1e7453a9e6330b7722cf26a789088661c1658',
          'de754f74bbac40b9877d3b912af14886','eb29f6ed14ee48bda0aabde4d779569c',
          '1d62497de6c26db6a6ba85a0fc60802b6b945605a33b961bc050a66175b66cfb','fa3852339834b02fd8267c2a1c7f005ecd06b90e2ed126a5165b5a72a8dad836')
}


def pin(p, expected):
    r = ref(p)
    assert r['sha256'] == expected, p
    return r


def observe(epoch):
    base, folder, digest, name, proof_sha, iid, timer_iid, service_sha, timer_sha = CONFIG[epoch]
    original = pin(V/name,proof_sha)
    q = bound(original)
    plan = pin(V/folder/'guard-plan.json',digest)
    g = bound(plan)
    assert g['invocation_id'] == iid
    producer = g['unit']
    if epoch == 265:
        assert q['producer_cgroup_drained'] and all(e['UNIT']==producer and e['INVOCATION_ID']==iid for e in q['producer']['events'])
        assert bound(q['plan'])['producer_invocation_id']==iid and q['producer']['events']
    else:
        assert q['unit']==producer and q['invocation_id']==iid and q['native_input_qualified']
        assert q['terminal_manager']['ActiveState']=='inactive' and q['terminal_manager']['MainPID']=='0'
    state = props(producer,['ActiveState','MainPID','Job','ControlGroup','InvocationID'])
    assert state == dict(ActiveState='inactive',MainPID='0',Job='',ControlGroup='',InvocationID=iid) and not (CG/producer).exists()
    unit = base+'.service'
    timer = base+'.timer'
    system = props(unit,['ExecStart','FragmentPath','DropInPaths','TriggeredBy'])
    assert plan['path'] in system['ExecStart'] and not system['DropInPaths']
    fragment = pin(Path(system['FragmentPath']).resolve(),service_sha)
    env = Path(plan['path']).with_name('guard.env')
    assert env.read_text().split('=',1)[1].strip()==digest and env.stat().st_uid==0 and not env.stat().st_mode & 0o022
    t = props(timer,['Id','ActiveState','InvocationID','Unit','FragmentPath','Triggers','TriggeredBy','PartOf','WantedBy','RequiredBy','DropInPaths','Job'])
    assert t['Id']==timer and t['Unit']==t['Triggers']==unit and not any(t[k] for k in ('PartOf','WantedBy','RequiredBy','DropInPaths','Job','TriggeredBy'))
    timer_file = pin(Path(t['FragmentPath']).resolve(),timer_sha)
    if t['ActiveState']=='active':
        assert t['InvocationID']==timer_iid and system['TriggeredBy']==timer
    else:
        assert t['ActiveState']=='inactive' and t['InvocationID'] in ('',timer_iid) and system['TriggeredBy'] in ('',timer)
    return dict(terminal=original,plan=plan,env=ref(env),producer=producer,producer_state=state,
                producer_iid=iid,timer=t,timer_fragment=timer_file,guard_fragment=fragment)


def retired(epoch):
    done = ROOT/f'{epoch}-closed.json'
    if not done.exists():
        return False
    now = observe(epoch)
    record = bound(ref(done))
    assert now==record['after'] and now['timer']['ActiveState']=='inactive'
    assert not (CG/(CONFIG[epoch][0]+'.service')).exists()
    return True


def install_window():
    original = WINDOW.read_text()
    code = f"""import sys
sys.path.insert(0,{str(Path(__file__).resolve().parent)!r})
from guard_closure import CONFIG, retired
units=[CONFIG[epoch][0] for epoch in CONFIG if not retired(epoch)]
"""
    old = "units=['horizon-native266-protective-v1','horizon-265-replacement-20261119-protective-v3']"
    if code in original:
        assert hashlib.sha256(original.replace(code,old).encode()).hexdigest()==PREVIOUS
        return
    assert hashlib.sha256(original.encode()).hexdigest()==PREVIOUS and original.count(old)==1
    updated = original.replace(old,code)
    compile(updated,str(WINDOW),'exec')
    tmp = WINDOW.with_suffix('.terminal-aware')
    with tmp.open('x') as f:
        f.write(updated); f.flush(); os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
    os.replace(tmp,WINDOW)
    fd=os.open(WINDOW.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def close():
    with partition.take():
        ROOT.mkdir(mode=0o700,exist_ok=True)
        for epoch in CONFIG:
            observe(epoch)
        install_window()
        for epoch in CONFIG:
            if retired(epoch):
                continue
            before = observe(epoch)
            intent = ROOT/f'{epoch}-intent.json'
            if not intent.exists():
                assert before['timer']['ActiveState']=='active'
                funds.put(intent,dict(before=before,window=ref(WINDOW)))
            previously = bound(ref(intent))['before']
            assert previously['timer']['InvocationID']==CONFIG[epoch][6] and previously['terminal']==before['terminal']
            timer=before['timer']['Id']
            if before['timer']['ActiveState']=='active':
                subprocess.run(['systemctl','stop',timer],check=True)
            unit=before['timer']['Unit']
            timeout=time.monotonic()+75
            while (CG/unit).exists() and time.monotonic()<timeout:
                time.sleep(0.5)
            assert not (CG/unit).exists() and props(unit,['MainPID','Job','ActiveState'])==dict(MainPID='0',Job='',ActiveState='inactive')
            after=observe(epoch)
            assert after['timer']['ActiveState']=='inactive'
            rows=[json.loads(l) for l in subprocess.check_output(['journalctl','-b','-o','json','--no-pager','_PID=1','_UID=0','UNIT='+timer,'INVOCATION_ID='+CONFIG[epoch][6]]).splitlines()]
            assert any(r.get('MESSAGE_ID')=='9d1aaa27d60140bd96365438aad20286' and r.get('JOB_RESULT')=='done' for r in rows)
            print(funds.put(ROOT/f'{epoch}-closed.json',dict(intent=ref(intent),after=after,pid1=funds.put(ROOT/f'{epoch}-manager.json',rows),resource_credit=0)),flush=True)
        assert all(retired(epoch) for epoch in CONFIG)
        subprocess.run(['/usr/bin/python3','-B',str(WINDOW)],check=True,timeout=20)


if __name__ == '__main__':
    close()
