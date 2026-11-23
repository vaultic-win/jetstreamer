"""Resume the completed 01:47:57 observation after the admitted retry3 bootstrap and its writer exited."""
import argparse
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import time

R = Path('/var/lib/jetstreamer/horizon_runtime_data')
BASE = R/'survivor172-cadence-20261122-v1'
EXIT = BASE/'RETRY3_STATUS_EXIT_014757_REMOTE_READBACK.json'
EXIT_SHA = '799563bf01e179ae33d4e85188f87813c82736563b0d056f5fa6bd82d0e95a25'
Q = BASE/'COLD168_RETRY4_V1_BEFORE_SWITCH_QUALIFICATION.json'
READY = BASE/'COLD168_RETRY4_V1_STATUS_HANDOFF_READY.json'
RESULT = BASE/'COLD168_RETRY4_V1_PENDING_SAMPLE_COMPLETE.json'
HANDOFF = BASE/'cold168-retry4-status-switch-v1/handoff_cold168.py'
RECOVERY = BASE/'cold168-retry4-failed-writer-v1'
DUE = '2026-11-23T01:47:57Z'
TAG = 'COLD168_RETRY4_V1_STATUS_'
ACTIVE = BASE/(TAG+'ACTIVE.json')
INTENT = BASE/(TAG+'INTENT.json')
NEW = BASE/'tools-cold168-retry4-v1/status_cycle.py'


def need(condition, why):
    if not condition:
        raise ValueError(why)


def initial():
    need(os.geteuid()==0 and sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'use isolated privileged Python')
    h=runpy.run_path(str(HANDOFF))
    h['configure_successor'](4)
    h=h['switch'].__globals__
    c=runpy.run_path(str(h['OLD']))
    h['checked_member'](c,HANDOFF)
    h['checked_member'](c,Path(__file__).resolve())
    need(Path(__file__).resolve().parent==RECOVERY and c['bound'](EXIT)['sha256']==EXIT_SHA, 'unsealed recovery operator or release')
    return h,c,runpy.run_path(str(h['COMMON']))


def bindings(h,c):
    failed=c['read_ref'](EXIT)
    head=failed['last_complete']
    prior=c['checked'](head)
    sample=failed['native_sample']
    paths=c['names'](DUE)
    envelope=c['checked'](sample)
    old,qualified,bindings,_=h['registration'](c)
    need(failed['old_registration']==h['PREVIOUS'] and failed['failure168']==bindings['failed_retry3']
         and sample==c['bound'](paths['sample']) and failed['full172']==c['bound'](paths['out']/'FULL172_OBSERVATION.json')
         and c['checked'](failed['full172'])['observer']==sample and c['checked'](failed['full172'])['fleet']==head
         and prior['sole_next_timer']==paths['timer'] and envelope['recorded_at_utc']==DUE
         and envelope['cadence']['previous_sample_sha256']==prior['observer']['sha256']
         and envelope['cadence']['observed_interval_seconds']==1800 and envelope['cadence']['routine_minimum_interval_enforced']
         and sorted(row['range'] for row in envelope['replays'])==['167','170','172']
         and all(row['invocation_binding_stable'] and row['useful_work']['transaction_delta']>0 for row in envelope['replays']),
         'different completed single observation or predecessor')
    config=prior['sole_next_observer']
    cfg=c['sealed'](config)
    need(cfg['not_before_utc']==DUE and cfg['output']==sample['path'], 'different due config')
    rows=failed['authenticated_unchanged_rows']
    need(len(rows)==20 and rows.keys()==prior['complete_active_status_receipts'].keys(), 'incomplete pre-recovery inventory')
    for key,data in rows.items():
        item=c['checked'](data['receipt'])
        need(data['receipt']==prior['complete_active_status_receipts'][key] and data['etag']==item['after_etag']
             and data['sha256']==item['after_sha256'] and item['authenticated_readback'], 'different original status '+key)
    schedule=dict(fleet=head,config=config,timer=paths['timer'],completed_sample=sample,full172=failed['full172'])
    return dict(**bindings,qualified=qualified,old=old,admission=h['PREPARED'],schedule=schedule,failed_incumbent=c['bound'](EXIT))


def pending(c,common,bind):
    paths=c['names'](DUE)
    need(all(x.name=='FULL172_OBSERVATION.json' for x in paths['out'].iterdir()) and not paths['statuses'].exists()
         and not c['timer_names'](), 'partial or already consumed observation')
    for unit in (paths['timer'],paths['timer'].removesuffix('.timer')+'.service'):
        state=c['owners'].show(unit,('Id','ActiveState','Job'))
        need(state['Id']==unit and state['ActiveState']=='inactive' and not state['Job'], 'observer still active')
    old=bind['old']
    fields=('Id','ActiveState','SubState','MainPID','ControlPID','ExecMainPID','InvocationID','Job','ControlGroup','NRestarts','Result','ExecMainStatus')
    state=c['owners'].show(common['UNIT'],fields)
    need(state['Id']==old['unit'] and state['ExecMainPID']==str(old['pid']) and state['InvocationID']==old['invocation_id']
         and state['ActiveState']==state['SubState']=='failed' and state['Result']=='exit-code' and state['ExecMainStatus']=='1'
         and state['ControlPID']==state['MainPID']==state['NRestarts']=='0' and not state['ControlGroup'] and not state['Job'],
         'different or live incumbent writer')
    stat=common['LOCK'].lstat()
    need((stat.st_dev,stat.st_ino)==(old['lock']['device'],old['lock']['inode']) and str(common['LOCK'])==old['lock']['path'],
         'original cadence lock changed')
    root=R/'epoch168-retry4-rebook-20261123-v1'
    need(not any((root/n).exists() for n in ('START_INTENT.json','ACTUAL_ADMISSION_AND_PROTECTION.json','barrier/allow')),
         'new 168 already launched')


def qualify(h,c,common,b):
    pending(c,common,b)
    need(c['read_ref'](Q)['qualified']==b['qualified'],'different offline handoff controls')
    # The real successor code may create small capture receipts only under the private rehearsal root.
    # The predecessor imports modules with the same basenames. Load the isolated receiver in a fresh process.
    with tempfile.TemporaryDirectory(dir=BASE) as tmp:
        output=common['output']('/usr/bin/python3','-IB',Path(__file__),'sample-rehearsal',tmp,timeout=150)
        test=json.loads(output)
    need(test['workers']==[167,170,172] and test['sample']==b['schedule']['completed_sample'] and test['remote_writes']==0,
         'actual receiver did not consume all three original rows')
    fd=c['lock'](common['LOCK'])
    try:
        pending(c,common,b)
    finally:
        os.close(fd)
    if not READY.exists():
        c['durable'](READY,dict(schema='horizon-168-retry4-cold-writer-ready-v1',qualified=b['qualified'],binding=b,
                                 controls=c['bound'](Q),sample_rehearsal=test,previous_writer_drained=True,writer_switch=False))
    record=c['read_ref'](READY)
    need(record['binding']==b and record['controls']==c['bound'](Q), 'different cold qualification')
    return c['bound'](READY)


def rehearsal(directory):
    need(directory.parent==BASE and directory.is_dir() and not any(directory.iterdir()),'invalid empty fixture root')
    c=runpy.run_path(str(NEW))
    failed=c['read_ref'](EXIT)
    sample=failed['native_sample']
    head=failed['last_complete']
    fleet=c['checked'](head)
    c['durable'](directory/'FULL172_OBSERVATION.json',c['checked'](failed['full172']))
    ctx=c['make_context'](head,fleet,sample,c['sealed'](fleet['sole_next_observer']),directory)
    workers=sorted(e for e,advanced in ctx.advancing.items() if advanced)
    return dict(workers=workers,sample=sample,active_bootstraps=c['cold167_status'].counts(ctx)['active_bootstraps'],remote_writes=0)


def activate(h,c,common,b):
    if ACTIVE.exists():
        record=c['read_ref'](ACTIVE)
        need(all(record.get(k)==v for k,v in b.items()) and record['new']==common['publisher'](c,NEW),
             'different active cold receiver')
        return c['bound'](ACTIVE)
    need(c['read_ref'](READY)['binding']==b,'missing cold handoff qualification')
    unit=common['UNIT']
    drop=common['DROP'].with_name('z'*19+'-cold168-retry4-v1.conf')
    manifest=('[Service]\nExecStart=\nEnvironmentFile=/etc/jetstreamer/horizon-r2.env\nExecStart=/usr/bin/python3 -IB '+str(NEW)+'\n').encode()
    current=c['owners'].show(unit,('ActiveState','MainPID','InvocationID'))
    if current['MainPID']=='0':
        fd=c['lock'](common['LOCK'])
        try:
            pending(c,common,b)
            c['durable'](INTENT,b)
            common['write_new'](drop,manifest)
            common['output']('systemctl','daemon-reload')
            state=c['owners'].show(unit,('ExecStart','MainPID','Job'))
            need(state['MainPID']=='0' and not state['Job'] and str(NEW)+' ' in state['ExecStart'], 'incorrect recovery ExecStart')
        finally:
            os.close(fd)
        common['output']('systemctl','start',unit)
    need(c['read_ref'](INTENT)==b and drop.read_bytes()==manifest, 'different issued recovery')
    # The child holds the original lock and waits for this ACTIVE before it can publish.
    deadline=time.monotonic()+25
    while True:
        try:
            actor=common['publisher'](c,NEW,True)
            break
        except (ValueError, FileNotFoundError, ProcessLookupError):
            if time.monotonic()>deadline:
                raise
            time.sleep(0.1)
    h['check_owner'](actor,b['old'],NEW)
    need(c['read_ref'](INTENT)==b and not c['names'](DUE)['statuses'].exists(), 'sample consumed before adoption')
    c['durable'](ACTIVE,dict(b,new=actor,intent=c['bound'](INTENT),dropin=c['bound'](drop),schema='horizon-168-retry4-v1-status-active-v1'))
    return c['bound'](ACTIVE)


def complete(c,common):
    adopted=c['read_ref'](ACTIVE)
    need(common['publisher'](c,NEW)==adopted['new'],'different completing status writer')
    f=c['bound'](c['names'](DUE)['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json')
    fleet=c['checked'](f)
    audit=c['checked'](fleet['complete_active_status_audit'])
    need(fleet['previous_Root_operational_review']==adopted['schedule']['fleet']
         and fleet['observer']==adopted['schedule']['completed_sample']==audit['observer']
         and audit['authenticated_readback'] and not audit['archives_or_sidecars_changed']
         and audit['authenticated_status_count']==len(audit['receipts'])==20
         and audit['receipts']==fleet['complete_active_status_receipts'], 'incomplete original status publication')
    for key,row in audit['receipts'].items():
        item=c['checked'](row)
        need(item['epoch']==int(key) and item['authenticated_readback'] and item['after_etag'] and item['after_sha256'],
             'missing authenticated status '+key)
    next_schedule=common['timer_evidence'](c,f,0)
    c['durable'](RESULT,dict(cold_recovery=c['bound'](ACTIVE),fleet=f,authenticated_audit=fleet['complete_active_status_audit'],
                             count=20,original_sample=fleet['observer'],next_schedule=next_schedule))
    return c['bound'](RESULT)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('qualify','activate','complete','sample-rehearsal'))
    parser.add_argument('scratch',nargs='?',type=Path)
    args=parser.parse_args()
    if args.mode=='sample-rehearsal':
        return rehearsal(args.scratch)
    h,c,common=initial()
    fd=c['lock'](BASE/'cold167-status-handoff.lock')
    try:
        if args.mode=='complete':
            return complete(c,common)
        b=bindings(h,c)
        return qualify(h,c,common,b) if args.mode=='qualify' else activate(h,c,common,b)
    finally:
        os.close(fd)


if __name__=='__main__':
    print(json.dumps(main(),sort_keys=True))
