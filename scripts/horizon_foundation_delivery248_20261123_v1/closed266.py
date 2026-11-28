"""Reconcile the original 266 target stop across its already completed, unavailable observer row."""
import datetime
import hashlib
import os
from pathlib import Path
import sys
from . import delivery249 as lane

T=Path('/run/horizon266-bounded-tools-v208')
EVENT=Path('/run/horizon266-terminal-event-v211-a1')
TERMINAL=lane.D/'horizon266-bounded-terminal-event-v211-a1/completion.json'

def crossover(o,done,row):
    term=lane.bound(lane.shared.pin(TERMINAL,'94958f52d3f1265519325c5b5bbccacf68b119cf441a8939ea678eb8946f5667'))
    assert row['status']=='unavailable' and row['observation'] is None and row['ordinary_replay_claim'] is False
    assert row['error']=='systemd control group is not absolute: prefix not found'
    assert done['instruction266_registration']==term['first_entries'] and done['observer_exit_code']==0
    assert term['bounded_target_met'] and term['producer_drained'] and not term['resources_released']
    assert term['unit']==row['producer_unit'] and term['iid']==row['expected_producer_invocation_id']
    assert not (lane.CG/term['unit']).exists() and lane.shared.props(term['unit'],['MainPID','ActiveState','Job'])==dict(MainPID='0',ActiveState='inactive',Job='')
    ended,=[e for e in term['manager_events'] if e.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448']
    assert int(ended['__REALTIME_TIMESTAMP']) <= datetime.datetime.fromisoformat(o['recorded_at_utc']).timestamp()*1e6
    return False

def install():
    target=T/'register_retry.py'
    old=" assert row['status']=='observed' and row['error'] is None and not row['ordinary_replay_claim']"
    s=target.read_text()
    assert hashlib.sha256(s.encode()).hexdigest()=='b6e8bdc9f726cfa0e83d5b1f9e99e9c7f996fa3dcd65baece4f5bb5d8ffe6505' and s.count(old)==1
    source=s.replace(old," if row['status']=='unavailable':\n  import sys\n  sys.path.insert(0,'/var/lib/jetstreamer/horizon249-delivery-v214-tools')\n  from ordinary249.closed266 import crossover\n  return crossover(o,done,row)\n"+old)
    compile(source,str(target),'exec')
    temp=target.with_suffix('.closed266')
    with temp.open('x') as f:
        f.write(source);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
    os.replace(temp,target)

def consume(version=214):
    import fcntl
    # Use the exact same continuation functions and one owner lock after the live-row consumer exited.
    path=EVENT/'continue_closed.py'
    source=path.read_text()
    assert hashlib.sha256(source.encode()).hexdigest()=='ac75cd9adf349b5bac808515060b9192f1fa23a1d18ad1bf04d7c8aa6af03cf1'
    ns={'__file__':str(path)}
    exec(compile(source[:source.index("result=D/'horizon266-bounded-retry-terminal-status")],str(path),'exec'),ns)
    assert lane.bound(lane.ref(TERMINAL))['producer_drained']
    assert version >= 214 and ns['fleet'](version - 1).is_file()
    with (ns['launch']/'closed-consumer.lock').open('rb') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        while True:
            dest=Path(f'/tmp/horizon-main-v{version}')
            if ns['fleet'](version).is_file():
                version+=1;ns['prepare'](version);continue
            if version==214:
                assert lane.bound(lane.ref(ns['cut'](214)))['observer_exit_code']==0
            else:
                mark=lane.D/f'horizon-terminal-aware-cycle-v{version}-bounded-retry266-closed-v1/completion.json'
                ns['wait'](mark)
                done=lane.bound(lane.ref(mark));assert done['observer_exit_code']==0 and not done.get('instruction266_registration')
            timer=lane.D/f'horizon-schedule-v{version+1}-bounded-retry266-closed-v1/timer.json'
            if not timer.is_file():ns['run'](EVENT/'cadence.py',version+1,'closed','roll')
            n=lane.bound(lane.ref(timer));assert n['previous']==lane.ref(lane.D/f'horizon-resume-observer-20261120-v{version}.json')
            assert lane.shared.props(n['timer']['Id'],['InvocationID','ActiveState'])==dict(InvocationID=n['timer']['InvocationID'],ActiveState='active')
            ns['run'](dest/'status.py')
            status261=lane.D/f'horizon261-replay-preparation-status-v{version}-a1/completion.json'
            if status261.exists():
                done=lane.bound(lane.ref(status261))
                intent=lane.bound(done['intent'])
                assert done['authenticated_exact_byte_readback'] and intent['payload']==lane.bound(done['readback'])
                assert done['key']=='epoch-261.epoch-status.json' and n['previous'] in intent['evidence']
            else:
                ns['run'](dest/'status261.py',version)
            ns['run'](dest/'fleet.py')
            version+=1;ns['prepare'](version)

if __name__=='__main__':
    action,=sys.argv[1:]
    {'install':install,'consume':consume}[action]()
