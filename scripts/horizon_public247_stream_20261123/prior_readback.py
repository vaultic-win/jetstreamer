"""Capture the already-finished authenticated hash pass on the exact staged 247 object."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time

sys.path.insert(0,'/var/lib/jetstreamer/horizon-public247-stream-v214')
import verify

D, bound, ref = verify.D, verify.bound, verify.ref
ROOT = D/'horizon-upload-247-staged-fadfe2d4-v1'
# Seal through the newline of the verified event. Native playback can append later.
PREFIX_BYTES = 1012764
PREFIX_SHA = '10294da9c370992cb956bb53d08358198136d069c394a92ab033df24cafcd7ac'

def capture():
    claim_ref=verify.prior.pin(ROOT/'pipeline-claim.json','aae2e3816b4550e105d2eeca727f84ec63e51f711ca48dc4c0535b7605f2da1b')
    claim=bound(claim_ref)
    launch=ref(ROOT/'launch.json');original=bound(launch);book=bound(original['booking'])
    assert original['unit']['InvocationID']==claim['invocation_id']=='e434de7095a5407f80353b8f1df5eea8'
    assert original['unit']['ExecStart']==claim['expected_exec_start'] and book['argv'][-1]=='--recover-staged-247'
    pin=verify.remote()
    assert book['remote']==dict(key=pin['key'],etag=pin['etag'].strip('"'),length=pin['bytes'],sha256=verify.SHA,sidecar_absent=True)
    log=ROOT/'operation.log'
    with log.open('rb') as file:
        meta=os.fstat(file.fileno())
        assert (meta.st_dev,meta.st_ino,meta.st_uid,stat.S_IMODE(meta.st_mode))==(66305,9538750,0,0o600)
        data=file.read(PREFIX_BYTES)
        assert len(data)==PREFIX_BYTES and hashlib.sha256(data).hexdigest()==PREFIX_SHA and os.path.samestat(meta,log.stat())
    rows=[json.loads(line) for line in data.splitlines() if line.startswith(b'{"') and b'"event":"r2-readback-' in line]
    first,last=rows[0],rows[-1]
    assert first['event']=='r2-readback-start' and last['event']=='r2-readback-verified'
    assert all(x['event']=='r2-readback-progress' for x in rows[1:-1])
    assert all(r['total_bytes']==verify.SIZE and r['key']==pin['key'] for r in rows)
    assert all(a['hashed_bytes']<=b['hashed_bytes'] and a['elapsed_millis']<=b['elapsed_millis'] for a,b in zip(rows,rows[1:]))
    assert first['hashed_bytes']==0 and first['expected_etag']==book['remote']['etag'] and first['expected_sha256']==verify.SHA
    assert last['hashed_bytes']==verify.SIZE and last['whole_file_sha256_verified'] and not first['whole_file_sha256_verified']
    current=bound(ref(verify.PLAN));old=bound(book['approved_plan'])
    local=ref(verify.OLD/'local-acceptance.json');accepted=bound(local)
    assert accepted['reader_plan']==book['approved_plan'] and accepted['full_verifier']==old['full_verifier']
    assert old['full_verifier']['sha256']==current['full_verifier']['sha256'] and old['threads']==current['threads']
    for plan in (old,current):
        image=Path(plan['full_verifier']['path'])
        assert image.resolve()==image and image.stat().st_uid==0 and not image.stat().st_mode & 0o222
        with image.open('rb') as stream:
            assert hashlib.file_digest(stream,'sha256').hexdigest()==plan['full_verifier']['sha256']
    assert old['epoch_expectations']==current['epoch_expectations']
    old_plugin=accepted['local_playback']
    assert old_plugin['process_exit_code']==accepted['full_exit_code']==0
    assert bound(old_plugin['report_binding'])==old_plugin['report'] and old_plugin['pipeline']==old['pipeline']
    source=bound(book['source_hand_off'])['source']['archive']
    identity=source['identity']; st=Path(source['path']).lstat()
    assert (st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(
        identity['device'],identity['inode'],identity['length'],identity['modified_seconds']*10**9+identity['modified_nanoseconds'],
        identity['changed_seconds']*10**9+identity['changed_nanoseconds'])
    assert source['path']==accepted['full_invocation'][0] and source['sha256']==verify.SHA
    assert old['pipeline']['sha256']!=current['pipeline']['sha256']
    folder=D/'horizon247-prior-authenticated-readback-v214'
    folder.mkdir(mode=0o700,exist_ok=True)
    proof=dict(observed_at=time.time(),claim=claim_ref,launch=launch,booking=original['booking'],local_acceptance=local,
        log_prefix=dict(path=str(log),bytes=PREFIX_BYTES,sha256=PREFIX_SHA,device=meta.st_dev,inode=meta.st_ino),
        authenticated_object=pin,authenticated_sha256=verify.SHA,first_event=first,last_event=last,
        full_verifier_unchanged=True,boundary_evidence=current['epoch_expectations'],current_plan=ref(verify.PLAN),
        current_local_plugin_pending=True,public_plugin=ref(verify.LAUNCH),publication_performed=False)
    print(verify.put(folder/'proof.json',proof),flush=True)

if __name__=='__main__':capture()
