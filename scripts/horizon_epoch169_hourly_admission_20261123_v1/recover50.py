"""Adopt the eleven conditional receipts of the failed V49 23:48 observation."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

RUNTIME = Path('/var/lib/jetstreamer/horizon_runtime_data')
WRITER = RUNTIME / 'survivor172-cadence-20261122-v1'
NEW = WRITER / 'tools-cold168-retry5-failed166-v50-entry146'
EVIDENCE = RUNTIME / 'epoch169-hourly-admission-20261123-v1/v50-deployment'
STATUS = Path('/home/sol/.jetstreamer-private/r2-status-receipts')
EVENT = STATUS / 'event-169-hourly-replay-b01da82c-20261127-v1/RECEIPT.json'
EVENT_SHA = 'c8307a85afbcc6a15b3381cd18197a9224b0ee5c23d06d32ec598e1ec2a9b2c6'
FLEET_SHA = '94dd74f69ac71beef375fe67238d38a7f0204b3f3832d04f3ebf1882e9b43ec9'
SAMPLE_SHA = '8bf7db505862f00ac9a87f527f4ab46c7dba25ebf87aa85c9b94d17b06cc2bbc'
RECEIPT146_SHA = '7dd70c8b8303952535b66723d5a86242624864108f30b1696e025df61d40d58f'
PREVIOUS146_SHA = 'd2569e83b26e9547e0df21518a50e2f034724b6cf9b8f8fdd3c3381399e5a891'
REBOUND_SHA = '94641b9b2dc501c0a6bcf3f8d117e94a6ef873087fd565bae6677c6432d19c96'
PARTIAL = (136,137,140,141,146,159,161,163,166,167,168)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def immutable(path):
    st = path.lstat()
    return (path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_uid == 0
            and st.st_nlink == 1 and not st.st_mode & 0o222)


def load(package_sha):
    seal = NEW/'deployment-seal-receipt.json'
    require(Path(__file__).resolve() == NEW/'recover50.py' and immutable(seal) and sha(seal) == package_sha,
            'unexpected V50 recovery package')
    package = json.loads(seal.read_bytes())
    require(package['destination'] == str(NEW), 'V50 package moved')
    for member in package['members']:
        p = NEW/member['name']
        require(p.parent == NEW and immutable(p) and p.stat().st_size == member['bytes']
                and stat.S_IMODE(p.stat().st_mode) == int(member['mode'], 8) and sha(p) == member['sha256'],
                'changed V50 package member '+p.name)
    sys.path.insert(0,str(NEW))
    import status_cycle
    import cutover50
    return status_cycle, cutover50


def failed_owner(h, actor):
    before = h.doc(h.OLD_ACTIVE,h.OLD_OWNER)['new']
    require(actor == before and actor['invocation_id'] == '0f4399ebc3764a809f6bac019f45a0ed'
            and actor['program'] == str(h.OLD/'status_cycle.py'), 'unexpected V49 predecessor')
    st = h.state(h.WRITER,'Id','ActiveState','SubState','Result','MainPID','ControlPID','Job','ExecMainStatus')
    require(st['Id'] == h.WRITER and st['ActiveState'] == st['SubState'] == 'failed'
            and st['Result']=='exit-code' and st['ExecMainStatus']=='1' and st['MainPID']==st['ControlPID']=='0'
            and not st['Job'], 'V49 writer is no longer failed and drained')
    pid = Path('/proc') / str(actor['pid'])
    require(not pid.exists() or int((pid/'stat').read_text().rsplit(') ',1)[1].split()[19]) != actor['start_ticks'],
            'original writer still runs')
    def journal(*filters):
        data = h.command('/usr/bin/journalctl','-b','-q','--no-pager','-o','json',*filters)
        return [json.loads(line) for line in data.splitlines()]
    ends = journal('_PID=1','_UID=0','UNIT='+h.WRITER,'INVOCATION_ID='+actor['invocation_id'])
    failed = [r for r in ends if r.get('MESSAGE_ID')=='98e322203f7a4ed290d09fe03c09fe15'
              and r.get('COMMAND')=='ExecStart' and r.get('EXIT_CODE')=='exited' and r.get('EXIT_STATUS')=='1']
    records = journal('_SYSTEMD_UNIT='+h.WRITER,'_SYSTEMD_INVOCATION_ID='+actor['invocation_id'],
                      '_PID='+str(actor['pid']))
    trace = [r for r in records if r.get('MESSAGE')=='ValueError: unresolved or forked external status event for 146']
    require(len(failed)==len(trace)==1, 'unexpected V49 terminal record')
    return dict(pid1=failed[0]['__CURSOR'],trace=trace[0]['__CURSOR'],actor=actor)


def retained_listener(h):
    if h.LISTENER_RECEIPT.exists() or h.released143():
        return h.preserve143()
    prior = h.TARGET/'REENTRY_V49_REBOUND.json'
    receipt = h.doc(prior,REBOUND_SHA)
    listener = h.listener_state(h.ORIGINAL_LISTENER)
    require((listener['InvocationID'],listener['MainPID']) ==
            (receipt['new']['InvocationID'],receipt['new']['MainPID'])
            and receipt['writer_package'] == h.member(h.OLD,h.ORIGINAL_LISTENER.name),
            'different 143 listener before rebind')
    return dict(listener=listener,handoff=h.ref(prior))


def check(c,h):
    require(os.geteuid()==0 and not h.ACTIVE.exists(), 'a V50 owner already exists')
    death = failed_owner(h,h.doc(h.OLD_ACTIVE,h.OLD_OWNER)['new'])
    latest = max(RUNTIME.glob('root*/ROOT_COMPLETE_OPERATIONAL_FLEET.json'),key=lambda p:p.stat().st_mtime_ns)
    head = h.ref(latest)
    require(head['sha256'] == FLEET_SHA,'different fleet head')
    fleet = c.checked(head)
    ready = c.transition_v50.ready(vars(c),head,c.entry())
    sample = ready['completed_sample']
    require(sample and sample['sha256'] == SAMPLE_SHA and not c.timer_names()
            and c.sealed(ready['config'])['output']==sample['path'], 'original sample or clock changed')
    out = c.names(c.sealed(ready['config'])['not_before_utc'])
    require(not (out['out']/'ROOT_COMPLETE_OPERATIONAL_FLEET.json').exists(), 'observation already accepted')
    owner_ref = dict(path=str(EVENT),sha256=EVENT_SHA)
    store = c.status.Storage()
    held = c.authenticated(store,169,owner_ref)
    require(held['previous_receipt']==fleet['complete_active_status_receipts']['169']
            and held['after_status']['phase']=='replay', 'foreign 169 event')
    target = out['statuses']
    intents = {p.name:h.ref(p) for p in target.glob('epoch-*.intent.json')}
    receipts = {p.name:h.ref(p) for p in target.glob('epoch-*.receipt.json')}
    require(set(intents)=={f'epoch-{e}.intent.json' for e in PARTIAL}
            and set(receipts)=={f'epoch-{e}.receipt.json' for e in PARTIAL},'different interrupted batch')
    for e in PARTIAL:
        intent = c.checked(intents[f'epoch-{e}.intent.json'])
        receipt_ref = receipts[f'epoch-{e}.receipt.json']
        row = c.authenticated(store,e,receipt_ref)
        require(intent['fleet_predecessor']==head and intent['observer']==sample and intent['conditional_header']=='If-Match'
                and intent['key']==c.status.key(e) and dict(intent,after_etag=row['after_etag'],authenticated_readback=True)==row,
                'wrong partial status for epoch '+str(e))
        if e==146:
            require(receipt_ref['sha256']==RECEIPT146_SHA and
                    row['previous_receipt']['sha256']==PREVIOUS146_SHA,'different existing 146 receipt')
    listener = retained_listener(h)
    actors = h.endpoints(fleet,listener)
    require(len(actors['producers'])==5,'different five-producer roster')
    return ready,dict(predecessor=death,sample=sample,fleet=head,event=owner_ref,
                      preserved_intents=intents,preserved_receipts=receipts,listener=listener,endpoints=actors)


def run(package_sha,apply):
    c,h = load(package_sha)
    with h.BOOKING_LOCK.open('rb') as fd:
        fcntl.flock(fd,fcntl.LOCK_EX)
        if h.ACTIVE.exists():
            active=h.doc(h.ACTIVE)
            h.owner(active['new'],NEW)
            require(active['ready']==h.ref(h.READY),'unexpected V50 activation')
            return dict(active=h.ref(h.ACTIVE),listener=h.preserve143())
        ready,record = check(c,h)
        if not apply:
            return record
        replacement = h.rebind_listener()
        require(h.endpoints(c.checked(record['fleet']),replacement) == dict(record['endpoints'],hourly143=replacement),
                'protected roster changed during listener rebind')
        record['listener_after'] = replacement
        body = (json.dumps(ready,sort_keys=True)+'\n').encode()
        d = h.SYSTEMD_DIRECTORY / (h.WRITER+'.d')
        source = max((p for p in d.glob('*.conf') if '-v49-' in p.name),key=lambda p:p.name)
        old = source.read_bytes()
        require(old.count(os.fsencode(h.OLD))==1 and h.sha(h.OLD/'deployment-seal-receipt.json')==h.ORIGINAL_SEAL,
                'previous writer definition changed')
        new = old.replace(os.fsencode(h.OLD),os.fsencode(NEW))
        dest = d/('z'+source.name.replace('-v49-','-v50-'))
        if dest.exists():
            require(dest.read_bytes()==new,'foreign staged writer definition')
        else:
            h.private_write(dest,new,0o644)
        if h.READY.exists():
            require(h.doc(h.READY)==ready,'foreign staged V50 handoff')
        else:
            h.private_write(h.READY,body,0o400)
        intent = EVIDENCE/'SAME_SAMPLE_RECOVERY.json'
        if not intent.exists():
            h.private_write(intent,(json.dumps(record,sort_keys=True)+'\n').encode(),0o400)
        saved = h.doc(intent)
        for k in ('predecessor','sample','fleet','event','preserved_intents','preserved_receipts','listener_after'):
            require(saved[k]==record[k],'changed V50 recovery intent '+k)
        h.systemctl('daemon-reload')
        require(failed_owner(h,record['predecessor']['actor'])==record['predecessor']
                and str(NEW/'status_cycle.py') in h.state(h.WRITER,'ExecStart')['ExecStart']
                and not c.timer_names(),'wrong writer or observer for startup')
        h.systemctl('start', h.WRITER)
        return dict(recovery=h.ref(intent),ready=h.ref(h.READY),sample=record['sample'],writer_started=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-sha256',required=True)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check',action='store_true')
    mode.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    print(json.dumps(run(args.package_sha256,args.apply),sort_keys=True))
