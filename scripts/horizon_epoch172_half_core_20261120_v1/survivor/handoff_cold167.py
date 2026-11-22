"""Qualify and hand the original cadence service to its funded cold 167 generation."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
ROOT = R / 'survivor172-cadence-20261122-v1'
TOOL = ROOT / 'tools-cold167-v3'
OLD = ROOT / 'tools/status_cycle.py'
OLD_IID = '1baf803f31384ddaacb3a291ad9383bc'
NEW = TOOL / 'status_cycle.py'
QUAL = ROOT / 'COLD167_V3_STATUS_QUALIFIED.json'
ACTIVE = ROOT / 'COLD167_V3_STATUS_ACTIVE.json'
CANDIDATE = R / 'epoch167-source-index-rebook-20261122-v3'
UNIT = 'horizon-archive-status-cadence-after172-20261120-v1.service'
DROP = Path('/run/systemd/system') / (UNIT + '.d') / 'zzzzzzzzzzzzzz-cold167-v3.conf'
LOCK = R / 'stable-cadence-controller-20261120-v1/consumer.lock'
REPO = Path('/home/sol/workspace/jetstreamer')
SRC = 'scripts/horizon_epoch172_half_core_20261120_v1/survivor'
SEALER = Path('/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment')
MEMBERS = ('status_cycle.py', 'cold167_status.py', 'qualify.py', 'qualify_cold167.py', 'qualify_cold167_cadence.py')
FIELDS = ('Id','MainPID','ControlPID','ActiveState','SubState','Job','InvocationID','ControlGroup','NRestarts')
OLD_SHA = 'b6b51d8dd4a8ac68473fc2da03c3c86e853828cbaf65932ac0d3cf557f5a3eba'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def output(*argv, timeout=30):
    return subprocess.check_output(list(map(str, argv)), timeout=timeout)


def write_new(path, data):
    if not path.exists():
        with path.open('xb') as out:
            os.fchmod(out.fileno(), 0o400)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        syncdir(path.parent)
    require(path.read_bytes() == data and not path.lstat().st_mode & 0o022, 'different staged file ' + str(path))


def syncdir(directory):
    fd = os.open(directory, os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prepare(c, commit, prepared_sha, guard_sha):
    require(re.fullmatch('[0-9a-f]{40}', commit), 'full source revision required')
    def git(*args):
        return output('/usr/sbin/runuser','-u','sol','--','/usr/bin/git','-C',REPO,*args)
    git('merge-base','--is-ancestor',commit,'origin/account-updates')
    stage = ROOT / 'cold167-v3-status-source'
    c['ensure_dir'](stage)
    for name in MEMBERS:
        write_new(stage / name, git('show', f'{commit}:{SRC}/{name}'))
    guard_root = R/'epoch167-cold-guard-20261122-v3'
    prepared = c['bound'](CANDIDATE/'PREPARED.json')
    guard = c['bound'](guard_root/'GUARD_QUALIFIED.json')
    require(prepared['sha256']==prepared_sha and guard['sha256']==guard_sha, 'different launch or guard qualification')
    c['durable'](stage/'generation.json', dict(prepared=prepared,guard_qualification=guard))
    members = (*MEMBERS,'generation.json')
    require(set(p.name for p in stage.iterdir()) == set(members), 'unexpected staged member')
    plan = ROOT / 'cold167-v3-status-seal-plan.json'
    c['durable'](plan, dict(schema='jetstreamer-sealed-deployment-plan-v1', destination=str(TOOL),
        members=[dict(name=n, mode=0o444, source=str(stage/n), sha256=c['bound'](stage/n)['sha256']) for n in members]))
    if not TOOL.exists():
        output(SEALER, plan, '--plan-sha256', c['bound'](plan)['sha256'], '--self-sha256',
               'e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3')
    seal = c['bound'](TOOL/'deployment-seal-receipt.json')
    actual = c['checked'](seal)
    require(actual['plan_sha256'] == c['bound'](plan)['sha256'] and actual['destination']==str(TOOL)
            and all(c['bound'](stage/n)['sha256']==c['bound'](TOOL/n)['sha256'] for n in members), 'package differs')
    if QUAL.exists():
        receipt = c['read_ref'](QUAL)
        require(receipt['package']==seal and receipt['source_commit']==commit, 'conflicting cadence qualification')
        return c['bound'](QUAL)
    qa = ROOT/'cold167-v3-status-qa'
    c['ensure_dir'](qa)
    old = json.loads(output('/usr/bin/python3','-IB',TOOL/'qualify.py',qa))
    recent = json.loads(output('/usr/bin/python3','-IB',TOOL/'qualify_cold167.py',qa))
    dual = json.loads(output('/usr/bin/python3','-IB',TOOL/'qualify_cold167_cadence.py',qa))
    require(dual['two_guarded_owners'] and len(set(old['conditional_epochs'])) == 20 and old['bytes_written_to_R2']==0
            and recent['wrong_main_pid_rejected'] and recent['wrong_worker_pid_rejected'] and recent['wrong_config_rejected']
            and recent['guard_qualification']==guard and recent['wrong_guard_qualification_rejected']
            and recent['simulated_conditional_writes']==1 and not recent['r2_mutations'], 'status qualification failed')
    c['durable'](QUAL,dict(source_commit=commit,package=seal,normal=old,cold167=recent,dual=dual))
    return c['bound'](QUAL)


def timer_evidence(c, ref, minimum_seconds=110):
    data = c['checked'](ref)
    cfg = c['sealed'](data['sole_next_observer'])
    due = c['utc'](cfg['not_before_utc'])
    timer = c['names'](cfg['not_before_utc'])['timer']
    require(data['sole_next_timer']==timer and c['timer_names']()==[timer] and data['complete_active_status_count']==20
            and due>c['now']()+datetime.timedelta(seconds=minimum_seconds) and not Path(cfg['output']).exists(),
            'handoff needs a completed cycle and time for the service switch')
    manager = c['owners'].show(timer,('Id','ActiveState','SubState','Triggers','InvocationID','TimersCalendar','Job'))
    require(manager['ActiveState']=='active' and manager['SubState']=='waiting' and
            manager['Triggers']==timer.removesuffix('.timer')+'.service' and not manager['Job'], 'observer no longer armed')
    argv = c['owners'].show(manager['Triggers'],('ExecStart',))['ExecStart']
    require(str(c['race166'].NATIVE)+' '+data['sole_next_observer']['path']+' ' in argv and
            due.strftime('%F %T UTC') in manager['TimersCalendar'], 'different armed observer')
    return dict(fleet=ref, config=data['sole_next_observer'], timer=manager)


def publisher(c, program, require_sleep=False):
    before = c['owners'].show(UNIT,FIELDS)
    require(before['MainPID']!='0' and before['ActiveState']=='active' and before['SubState']=='running'
            and before['NRestarts']==before['ControlPID']=='0' and not before['Job'], 'cadence service not running')
    pid = int(before['MainPID'])
    proc = Path('/proc')/str(pid)
    group = '/system.slice/'+UNIT
    require(before['ControlGroup']==group and (proc/'cgroup').read_text().strip()=='0::'+group
            and (proc/'exe').samefile('/usr/bin/python3') and (proc/'cmdline').read_bytes().split(b'\0') ==
            [b'/usr/bin/python3',b'-IB',os.fsencode(program),b''], 'unexpected publisher executable or arguments')
    require(not require_sleep or ((proc/'wchan').read_text().strip()=='hrtimer_nanosleep' and
            (proc/'task'/str(pid)/'children').read_text().strip()==''), 'publisher not at its quiescent wait')
    lockstat = LOCK.lstat()
    key = f'{os.major(lockstat.st_dev):02x}:{os.minor(lockstat.st_dev):02x}:{lockstat.st_ino}'
    match = ['FLOCK','ADVISORY','WRITE',str(pid),key,'0','EOF']
    fds = []
    for fd in (proc/'fd').iterdir():
        try:
            if fd.samefile(LOCK) and any(row.startswith('lock:') and row.split()[2:] == match for row in
                                         (proc/'fdinfo'/fd.name).read_text().splitlines()):
                fds.append(int(fd.name))
        except FileNotFoundError:
            continue
    require(len(fds)==1 and before==c['owners'].show(UNIT,FIELDS), 'different sole lock holder')
    ticks = int((proc/'stat').read_text().rsplit(')',1)[1].split()[19])
    return dict(unit=UNIT,pid=pid,start_ticks=ticks,invocation_id=before['InvocationID'],
                program=str(program),lock=dict(path=str(LOCK),device=lockstat.st_dev,inode=lockstat.st_ino,fd=fds[0]))


def admitted(c):
    m=runpy.run_path(str(TOOL/'cold167_status.py'))
    reader=m['reader']()
    state=reader.native(167)
    require(state and (CANDIDATE/'ACTUAL_ADMISSION_AND_PROTECTION.json').exists(), 'cold 167 has no admitted owner')
    ref=c['bound'](CANDIDATE/'ACTUAL_ADMISSION_AND_PROTECTION.json')
    a=c['checked'](ref)
    m['check_generation'](a['fleet'],c['checked'](a['fleet']),state)
    first=c['checked'](c['bound'](CANDIDATE/'FIRST_PROTECTED_WORKER.json'))
    proof,sample=reader.guard(167,a,state[1])
    row=reader.observe_worker(167,state[1],first,sample)
    m['projection'](row)
    require(first['admission']==ref and a['producer_invocation_id']==state[1]['producer_invocation_id'],
            'new worker differs from actual admission')
    return ref


def start_and_wait(c, program):
    output('systemctl','start',UNIT)
    end=time.monotonic()+15
    while True:
        try:
            return publisher(c,program,True)
        except (ValueError,FileNotFoundError,ProcessLookupError):
            if time.monotonic()>=end:
                raise
            time.sleep(0.2)


def switch(c, head, *, target, incumbent, incumbent_iid, tag, drop, admission):
    program=target/'status_cycle.py'
    qualified_ref=ROOT/(tag+'QUALIFIED.json')
    accepted=ROOT/(tag+'ACTIVE.json')
    qualified=c['read_ref'](qualified_ref)
    require(qualified['package']==c['bound'](target/'deployment-seal-receipt.json'), 'qualified package changed')
    new_admission=admission(c)
    manifest='[Service]\nExecStart=\nEnvironmentFile=/etc/jetstreamer/horizon-r2.env\nExecStart=/usr/bin/python3 -IB '+str(program)+'\n'
    intent=ROOT/(tag+'INTENT.json')
    if accepted.exists():
        receipt=c['read_ref'](accepted)
        require(receipt['new']==publisher(c,program) and receipt['admission']==new_admission
                and receipt['qualified']==c['bound'](qualified_ref), 'different adopted writer')
        return c['bound'](accepted)
    schedule=timer_evidence(c,head)
    if intent.exists():
        initial=c['read_ref'](intent)
        require(initial['schedule']==schedule and initial['admission']==new_admission and initial['qualified']==c['bound'](qualified_ref),
                'handoff intent is for a different cycle or owner')
    else:
        old=publisher(c,incumbent,True)
        require(old['invocation_id']==incumbent_iid and not drop.exists(), 'different original status owner')
        c['durable'](intent,dict(old=old,schedule=schedule,qualified=c['bound'](qualified_ref),admission=new_admission))
    initial=c['read_ref'](intent)
    rollback=ROOT/(tag+'ROLLBACK.json')
    state=c['owners'].show(UNIT,FIELDS)
    previous=initial['old']
    if rollback.exists() and state['MainPID']!='0' and not drop.exists():
        saved=c['read_ref'](rollback)
        if saved['restored']['invocation_id'] != state['InvocationID']:
            require(re.fullmatch('[0-9a-f]{32}',state['InvocationID']), 'invalid restored writer ID')
            saved=c['read_ref'](ROOT/(tag+'ROLLBACK_'+state['InvocationID']+'.json'))
            require(saved['original_rollback']==c['bound'](rollback), 'unbound subsequent rollback')
        require(saved['intent']==c['bound'](intent) and saved['schedule']==schedule, 'foreign restored writer')
        previous=saved['restored']
    if state['MainPID']!='0' and state['InvocationID']==previous['invocation_id']:
        require(previous==publisher(c,incumbent,True) and timer_evidence(c,head)==schedule, 'publisher moved before handoff')
        output('systemctl','stop',UNIT,timeout=95)
    state=c['owners'].show(UNIT,FIELDS)
    if state['MainPID']=='0':
        require(state['ActiveState'] in ('inactive','failed') and not state['Job'], 'original service has not drained')
        try:
            lease=c['lock'](LOCK)
            try:
                require(timer_evidence(c,head,15)==schedule, 'armed observer changed during switch')
                write_new(drop,manifest.encode())
                output('systemctl','daemon-reload')
                argv=c['owners'].show(UNIT,('ExecStart','MainPID','Job'))
                require(argv['MainPID']=='0' and not argv['Job'] and str(program)+' ' in argv['ExecStart'],
                        'manager has not loaded qualified replacement')
            finally:
                os.close(lease)
            new=start_and_wait(c,program)
        except Exception:
            # Restore the existing service if the new generation has not yet written a sample.
            current=c['owners'].show(UNIT,FIELDS)
            if current['MainPID']!='0':
                require(timer_evidence(c,head,0)==schedule, 'new publisher may be processing the sample')
                require((Path('/proc')/current['MainPID']/'cmdline').read_bytes().split(b'\0')==
                        [b'/usr/bin/python3',b'-IB',os.fsencode(program),b''], 'different running publisher')
                output('systemctl','stop',UNIT,timeout=95)
            if drop.exists():
                require(drop.read_bytes()==manifest.encode(), 'drop-in replaced')
                drop.unlink();syncdir(drop.parent)
            output('systemctl','daemon-reload')
            restored=start_and_wait(c,incumbent)
            record=dict(intent=c['bound'](intent),restored=restored,schedule=schedule)
            rollback_record=rollback
            if rollback.exists():
                record['original_rollback']=c['bound'](rollback)
                rollback_record=ROOT/(tag+'ROLLBACK_'+restored['invocation_id']+'.json')
            c['durable'](rollback_record,record)
            raise
    else:
        require(drop.read_bytes()==manifest.encode(), 'different live service during recovery')
        new=publisher(c,program)
    require(timer_evidence(c,head,0)==schedule and new_admission==admission(c) and new['invocation_id']!=initial['old']['invocation_id'],
            'custody changed across the switch')
    c['durable'](accepted,dict(new=new,old=initial['old'],intent=c['bound'](intent),schedule=schedule,
                            qualified=c['bound'](qualified_ref),admission=new_admission,dropin=c['bound'](drop)))
    return c['bound'](accepted)


def activate(c, head):
    return switch(c,head,target=TOOL,incumbent=OLD,incumbent_iid=OLD_IID,tag='COLD167_V3_STATUS_',
                  drop=DROP,admission=admitted)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('mode',choices=('prepare','observe','activate'))
    parser.add_argument('reference',help='merged source commit for prepare, complete fleet pathname otherwise')
    parser.add_argument('--prepared-sha256')
    parser.add_argument('--guard-qualification-sha256')
    args=parser.parse_args()
    require(os.geteuid()==0 and sys.flags.isolated and __debug__ and hashlib.sha256(OLD.read_bytes()).hexdigest()==OLD_SHA,
            'expected original installed cadence')
    c=runpy.run_path(str(OLD))
    if args.mode=='prepare':
        return prepare(c,args.reference,args.prepared_sha256,args.guard_qualification_sha256)
    ref=c['bound'](Path(args.reference))
    require(Path(ref['path']).name=='ROOT_COMPLETE_OPERATIONAL_FLEET.json' and Path(ref['path']).parent.parent==R,
            'foreign fleet path')
    if args.mode=='observe':
        return dict(schedule=timer_evidence(c,ref),owner=publisher(c,OLD,True))
    fd=c['lock'](ROOT/'cold167-status-handoff.lock')
    try:
        return activate(c,ref)
    finally:
        os.close(fd)


if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True))
