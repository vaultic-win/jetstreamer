"""Record the original uploader exit, retained reservation, and authenticated archive state."""
import fcntl
import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from delivery248 import CG, CLAIM, KEY, LENGTH, PRIVATE, ROOT, SHA, UNIT, aws, bound, funds, live_binding, prefix, props, ref, registered

DONE = ROOT/'terminal.json'

def pid1(iid):
    raw = subprocess.check_output(['journalctl','--no-pager','-o','json','_PID=1','_UID=0','UNIT='+UNIT,'INVOCATION_ID='+iid])
    events = [json.loads(line) for line in raw.splitlines()]
    assert all(e['UNIT'] == UNIT and e['INVOCATION_ID'] == iid for e in events)
    return events

def capture():
    claim_ref,claim,book,launch = registered()
    iid = claim['invocation_id']
    pid = int(launch['unit']['MainPID'])
    assert os.geteuid() == 0 and os.environ['CODEX_THREAD_ID'] == book['controller']
    with (ROOT/'terminal.lock').open('ab') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if DONE.exists():
            assert bound(ref(DONE))['claim'] == claim_ref
            return
        if Path(f'/proc/{pid}').exists():
            descriptor = os.pidfd_open(pid)
            if (CG/UNIT).exists():
                assert live_binding()['pid'] == pid
                watch = ROOT/'terminal-watch.json'
                if not watch.exists():funds.put(watch,dict(claim=claim_ref,iid=iid,pid=pid,boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()))
                waiter = select.poll()
                waiter.register(descriptor,select.POLLIN)
                waiter.poll()
            os.close(descriptor)
        limit = time.monotonic()+30
        while True:
            manager = props(UNIT,['ActiveState','MainPID','Job','InvocationID','NRestarts'])
            events = pid1(iid)
            if (not (CG/UNIT).exists() and manager['MainPID']=='0' and not manager['Job'] and manager['ActiveState'] in ('inactive','failed')
                    and any(e.get('UNIT_RESULT') or e.get('MESSAGE_ID')=='7ad2d189f7e94e70a38c781354912448' for e in events)):
                break
            assert time.monotonic()<limit
            time.sleep(0.5)
        assert manager['InvocationID'] in ('',iid) and manager['NRestarts']=='0'
        assert any(e.get('MESSAGE_ID')=='39f53479d3a045ac8e11786248231fbf' for e in events)
        remote = prefix()
        evidence = None
        if 'epoch-248.jet.sha256' in remote:
            r = ref(PRIVATE/'receipts/epoch-248.r2.json')
            receipt=bound(r)
            assert receipt['bucket']=='solana-archive-with-accounts-data' and receipt['epoch']==248 and receipt['archive_key']=='epoch-248.jet'
            assert receipt['checksum_key']=='epoch-248.jet.sha256' and receipt['archive_length']==remote['epoch-248.jet']['Size']==LENGTH
            assert receipt['archive_sha256']==SHA and receipt['archive_etag']==remote['epoch-248.jet']['ETag'].strip('"')
            assert receipt['remote_sha256_readback']
            replay=bound(receipt['current_reader_playback'])
            assert replay['reader_plan']==book['plan'] and replay['local_playback']['process_exit_code']==0 and replay['remote_playback']['playback']['process_exit_code']==0
            assert replay['local_playback']['report']['report']==replay['remote_playback']['playback']['report']['report']
            side=ROOT/'terminal-sidecar.txt'
            got=aws('get-object','--key','epoch-248.jet.sha256','--if-match',remote['epoch-248.jet.sha256']['ETag'],str(side))
            assert got['ETag']==remote['epoch-248.jet.sha256']['ETag'] and side.read_text()==SHA+'  epoch-248.jet\n'
            assert prefix()==remote
            evidence=dict(native=r,playback=receipt['current_reader_playback'],authenticated_sidecar=ref(side))
        funds.put(DONE,dict(claim=claim_ref,issuer=launch['booking'],manager=manager,events=events,remote=remote,ready=evidence is not None,
                            proof=evidence,reservation_released=False,source_retired=False,status_deletion_performed=False))

if __name__=='__main__':
    capture()
