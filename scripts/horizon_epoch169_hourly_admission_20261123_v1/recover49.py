"""Transfer the already captured sample from a failed V48 writer to V49."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
WRITER = RUNTIME / 'survivor172-cadence-20261122-v1'
NEW = WRITER / 'tools-cold168-retry5-failed166-v49-entry146'
PKG = '4dd7b81551d7c2e556a3a7bafa6d2d2b6603db9abdbcf360a7cf4f22ea416307'
LOCK = Path('/run/horizon-epoch171-to136-g1.operation.lock')
EVIDENCE = RUNTIME / 'epoch169-hourly-admission-20261123-v1/v49-deployment'
EVENT = Path('/home/sol/.jetstreamer-private/r2-status-receipts/event-169-hourly-replay-b01da82c-20261127-v1/RECEIPT.json')
EVENT_SHA = 'c8307a85afbcc6a15b3381cd18197a9224b0ee5c23d06d32ec598e1ec2a9b2c6'


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def load():
    seal = NEW / 'deployment-seal-receipt.json'
    require(hashlib.sha256(seal.read_bytes()).hexdigest() == PKG, 'unrecognized V49 package')
    package = json.loads(seal.read_bytes())
    require(package['destination'] == str(NEW), 'V49 image moved')
    for member in package['members']:
        p = NEW / member['name']
        require(p.parent == NEW and p.resolve() == p and p.stat().st_uid == 0 and not p.stat().st_mode & 0o222
                and hashlib.sha256(p.read_bytes()).hexdigest() == member['sha256'], 'changed V49 '+p.name)
    sys.path.insert(0,str(NEW))
    import status_cycle as cycle
    import cutover49 as handoff
    return cycle, handoff


def failed_owner(h, actor):
    st = h.state(h.WRITER,'Id','ActiveState','SubState','Result','MainPID','ControlPID','Job','ExecMainStatus')
    require(st['Id'] == h.WRITER and st['ActiveState']=='failed' and st['SubState']=='failed'
            and st['Result']=='exit-code' and st['ExecMainStatus']=='1' and st['MainPID']==st['ControlPID']=='0'
            and not st['Job'], 'original cadence has not exited on its error')
    pid = Path('/proc') /str(actor['pid'])
    require(not pid.exists() or int((pid/'stat').read_text().rsplit(') ',1)[1].split()[19]) != actor['start_ticks'],
            'original writer still runs')
    def journal(*filters):
        rows=h.command('/usr/bin/journalctl','-b','-q','--no-pager','-o','json',*filters)
        return [json.loads(line) for line in rows.splitlines()]
    ends=journal('_PID=1','_UID=0','UNIT='+h.WRITER,'INVOCATION_ID='+actor['invocation_id'])
    failed = [r for r in ends if r.get('MESSAGE_ID')=='98e322203f7a4ed290d09fe03c09fe15' and r.get('COMMAND')=='ExecStart'
              and r.get('EXIT_CODE')=='exited' and r.get('EXIT_STATUS')=='1']
    require(len(failed)==1,'missing or ambiguous exact V48 PID1 failure')
    records=journal('_SYSTEMD_UNIT='+h.WRITER,'_SYSTEMD_INVOCATION_ID='+actor['invocation_id'],
                    '_PID='+str(actor['pid']))
    trace = [r for r in records if r.get('MESSAGE')=='ValueError: new replay owner requires adoption before publication']
    require(len(trace)==1,'V48 exited for a different reason')
    return dict(pid1=failed[0]['__CURSOR'],trace=trace[0]['__CURSOR'],actor=actor)


def check(c, h, proof=True):
    require(os.geteuid()==0 and not h.ACTIVE.exists(),'a V49 owner already exists')
    old=h.doc(h.OLD_ACTIVE,h.OLD_OWNER)['new']
    death=failed_owner(h,old)
    latest=max(RUNTIME.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),key=lambda p:p.stat().st_mtime_ns)
    head=h.ref(latest)
    fleet=c.checked(head)
    ready=c.transition_v49.ready(vars(c),head,c.entry())
    sample=ready['completed_sample']
    require(sample and not c.timer_names() and c.sealed(ready['config'])['output']==sample['path'],
            'missing original completed sample')
    out=c.names(c.sealed(ready['config'])['not_before_utc'])
    require(not (out['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists(), 'observation already accepted')
    held=c.checked(dict(path=str(EVENT),sha256=EVENT_SHA))
    require(held['previous_receipt']==fleet['complete_active_status_receipts']['169'] and
            held['authenticated_readback'] and held['after_status']['phase']=='replay','foreign event')
    fids=sorted(p.name for p in out['statuses'].glob('epoch-*.intent.json'))
    receipts=sorted(p.name for p in out['statuses'].glob('epoch-*.receipt.json'))
    for p in out['statuses'].glob('epoch-*.intent.json'):
        row=c.read_ref(p)
        require(row['fleet_predecessor']==head and row['observer']==sample and row['conditional_header']=='If-Match'
               and row['key']==c.status.key(row['epoch']), 'partial status has a foreign observer')
    require(not (out['statuses']/'epoch-169.intent.json').exists() and not (out['statuses']/'epoch-169.receipt.json').exists(),
            'V48 committed a different 169 intent')
    if proof:
        owner_ref=dict(path=str(EVENT),sha256=EVENT_SHA)
        require(c.authenticated(c.status.Storage(),169,owner_ref)==held,'169 remote event no longer agrees')
    return ready,dict(predecessor=death,sample=sample,fleet=head,event=dict(path=str(EVENT),sha256=EVENT_SHA),
                      preserved_intents=fids,preserved_receipts=receipts,listener=h.preserve143(),endpoints=h.endpoints(fleet))


def run(apply):
    cycle,h=load()
    if h.ACTIVE.exists():
        data=h.doc(h.ACTIVE);h.owner(data['new'],NEW)
        return dict(active=h.ref(h.ACTIVE))
    with LOCK.open('rb') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX)
        ready,record=check(cycle,h)
        if not apply:
            return record
        body=(json.dumps(ready,sort_keys=True)+'\n').encode()
        d = h.SYSTEMD_DIRECTORY / (h.WRITER+'.d')
        source=max((p for p in d.glob('*.conf') if '-v48-' in p.name),key=lambda p:p.name)
        old=source.read_bytes()
        require(old.count(os.fsencode(h.OLD))==1 and h.sha(h.OLD/'deployment-seal-receipt.json')==h.ORIGINAL_SEAL,
                'incumbent writer definition changed')
        new=old.replace(os.fsencode(h.OLD),os.fsencode(NEW))
        dest=d/('z'+source.name.replace('-v48-','-v49-'))
        if dest.exists():
            require(dest.read_bytes()==new,'foreign staged writer definition')
        else:
            h.private_write(dest,new,0o644)
        if h.READY.exists():
            saved=h.doc(h.READY)
            require(saved==ready or saved==dict(ready,completed_sample=None),'foreign staged V49 handoff')
        else:
            h.private_write(h.READY,body,0o400)
        intent=EVIDENCE/'SAME_SAMPLE_RECOVERY.json'
        if not intent.exists():
            h.private_write(intent,(json.dumps(record,sort_keys=True)+'\n').encode(),0o400)
        require(h.doc(intent)['sample']==record['sample'],'another sample recovery was recorded')
        h.systemctl('daemon-reload')
        before=failed_owner(h,record['predecessor']['actor'])
        require(before==record['predecessor'] and str(NEW/'status_cycle.py') in h.state(h.WRITER,'ExecStart')['ExecStart']
                and not cycle.timer_names(),'wrong writer or observer for start')
        # The original complete sample remains on disk. Only the existing
        # status controller starts; its normal entry authenticates every intent.
        h.systemctl('start', h.WRITER)
        return dict(recovery=h.ref(intent),ready=h.ref(h.READY),sample=record['sample'],writer_started=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(__doc__)
    parser.add_argument('--apply',action='store_true')
    print(json.dumps(run(parser.parse_args().apply),sort_keys=True))
