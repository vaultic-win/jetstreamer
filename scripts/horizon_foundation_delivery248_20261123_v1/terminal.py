"""Record the original uploader exit, retained reservation, and authenticated archive state."""
if __package__:
    from . import delivery248
else:
    import delivery248
import fcntl
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
CG, UNIT = delivery248.CG, delivery248.UNIT
aws, bound, funds, props, ref = delivery248.aws, delivery248.bound, delivery248.funds, delivery248.props, delivery248.ref

def pid1(iid,unit=UNIT):
    raw = subprocess.check_output(['journalctl','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+unit,'INVOCATION_ID='+iid])
    events = [json.loads(line) for line in raw.splitlines()]
    assert all(e['UNIT'] == unit and e['INVOCATION_ID'] == iid for e in events)
    return events

def capture(owner=delivery248):
    archive_key = f"epoch-{owner.EPOCH}.jet"
    completion = owner.ROOT/"terminal.json"
    claim_ref,claim,book,launch = owner.registered()
    iid = claim['invocation_id']
    pid = int(launch['unit']['MainPID'])
    assert os.geteuid() == 0 and os.environ['CODEX_THREAD_ID'] == book['controller']
    with (owner.ROOT/'terminal.lock').open('ab') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if completion.exists():
            assert bound(ref(completion))['claim'] == claim_ref
            return
        if Path(f'/proc/{pid}').exists():
            descriptor = os.pidfd_open(pid)
            if (CG/owner.UNIT).exists():
                assert owner.live_binding()['pid'] == pid
                watch = owner.ROOT/'terminal-watch.json'
                if not watch.exists():funds.put(watch,dict(claim=claim_ref,iid=iid,pid=pid,boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
                waiter = select.poll()
                waiter.register(descriptor,select.POLLIN)
                waiter.poll()
            os.close(descriptor)
        limit = time.monotonic()+30
        while True:
            manager = props(owner.UNIT,['ActiveState','MainPID','Job','InvocationID','NRestarts'])
            events = pid1(iid,owner.UNIT)
            if (not (CG/owner.UNIT).exists() and manager['MainPID']=='0' and not manager['Job'] and manager['ActiveState'] in ('inactive','failed')
                    and any(e.get('UNIT_RESULT') or e.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' for e in events)):
                break
            assert time.monotonic()<limit
            time.sleep(0.5)
        assert manager['InvocationID'] in ('',iid) and manager['NRestarts']=='0'
        assert any(e.get('MESSAGE_ID')=='39f53479d3a045ac8e11786248231fbf' for e in events)
        remote = owner.prefix()
        evidence = None
        if (archive_key+'.sha256') in remote:
            r = ref(owner.PRIVATE/f'receipts/epoch-{owner.EPOCH}.r2.json')
            receipt=bound(r)
            assert receipt['bucket']=='solana-archive-with-accounts-data' and receipt['epoch']==owner.EPOCH and receipt['archive_key']==archive_key
            assert receipt['checksum_key']==(archive_key+'.sha256') and receipt['archive_length']==remote[archive_key]['Size']==owner.LENGTH
            assert receipt['archive_sha256']==owner.SHA and receipt['archive_etag']==remote[archive_key]['ETag'].strip('"')
            assert receipt['remote_sha256_readback']
            replay=bound(receipt['current_reader_playback'])
            assert replay['reader_plan']==book['plan'] and replay['local_playback']['process_exit_code']==0 and replay['remote_playback']['playback']['process_exit_code']==0
            assert replay['local_playback']['report']['report']==replay['remote_playback']['playback']['report']['report']
            side=owner.ROOT/'terminal-sidecar.txt'
            got=aws('get-object','--key',(archive_key+'.sha256'),'--if-match',remote[(archive_key+'.sha256')]['ETag'],str(side))
            assert got['ETag']==remote[(archive_key+'.sha256')]['ETag'] and side.read_text()==owner.SHA+f'  {archive_key}\n'
            assert owner.prefix()==remote
            evidence=dict(native=r,playback=receipt['current_reader_playback'],authenticated_sidecar=ref(side))
        funds.put(completion,dict(claim=claim_ref,issuer=launch['booking'],manager=manager,events=events,remote=remote,ready=evidence is not None,
                            proof=evidence,reservation_released=False,source_retired=False,status_deletion_performed=False))

if __name__=='__main__':
    capture()
