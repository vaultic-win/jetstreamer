"""Bind an already-published coordinated ETA to its live uploader with the Rust publisher."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from . import delivery248, delivery249

D=delivery248.D
ref,bound=delivery248.ref,delivery248.bound
put=delivery248.funds.put
FIELDS=('epoch','jet_size_bytes','elapsed_execution_millis','estimated_remaining_millis','sampled_at_utc','phase')

def payload(path,status):
    """Produce the exact serde_json::to_vec_pretty bytes used for receipt recovery."""
    assert set(status)==set(FIELDS)
    data=(json.dumps({k:status[k] for k in FIELDS},indent=2)+'\n').encode()
    if path.exists():
        assert path.read_bytes()==data
        return
    with path.open('xb') as output:
        output.write(data);output.flush();os.fsync(output.fileno())
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def install():
    target=Path('/tmp/horizon-main-v214/status.py')
    old=" planned=read(intent);assert planned['key']==key;write(payload,planned['payload'])"
    new=""" planned=read(intent);assert planned['key']==key
 if lane and lane.CLAIM.exists():
  from ordinary249.native_status import payload as native_payload
  native_payload(payload,planned['payload'])
 else:write(payload,planned['payload'])"""
    with delivery248.partition.take():
        assert not (D/'horizon-resume-observer-20261120-v214.json').exists()
        source=target.read_text()
        if new in source:return
        assert target.stat().st_uid==0 and source.count(old)==1
        source=source.replace(old,new);compile(source,str(target),'exec')
        tmp=target.with_suffix('.nativebytes')
        with tmp.open('x') as f:
            f.write(source);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
        os.replace(tmp,target)

def capture(version,lane):
    fleet=ref(D/f'horizon-fleet-takeover-v{version}-20261120-v1/fleet-v1.json')
    f=bound(fleet)
    observer=dict(path=f['observer_receipt'],sha256=f['observer_sha256'])
    claim_ref,claim,book,launch=lane.registered()
    assert lane.live_binding()['invocation_id']==claim['invocation_id']
    epoch=lane.EPOCH
    assert any(row['epoch']==epoch for row in f['active'])
    folder=lane.ROOT/f'native-status-v{version}'
    folder.mkdir(mode=0o700,exist_ok=True)
    complete=folder/'completion.json'
    if complete.exists():
        assert bound(ref(complete))['fleet']==fleet
        return
    status=D/f'horizon-resumed-campaign-status-v{version}-a1'/str(epoch)
    intent=ref(status/'intent.json');data=bound(intent);p=data['payload']
    assert p['sampled_at_utc']==f['sampled_at_utc'] and observer in data['evidence']
    expected=bound(ref(status/'completion.json'))
    assert expected['authenticated_exact_byte_readback'] and bound(expected['readback'])==p
    archive=bound(book['handoff'])['source']['archive']
    origin=ref(Path(f'/home/ubuntu/.jetstreamer-private/r2-status-receipts/epoch-{epoch}.status-20261117045633.json'))
    assert bound(origin)['producer_invocation_id']==lane.ORIGIN_IID
    model=folder/'model.json'
    binding=dict(claim_phase=claim['phase'],expected_exec_start=claim['expected_exec_start'],unit=lane.UNIT,
        invocation_id=claim['invocation_id'],origin_invocation_id=lane.ORIGIN_IID,
        origin_unit=bound(book['handoff'])['producer']['unit']['Id'],model_path=str(model),model_sha256='',
        fleet_path=fleet['path'],fleet_sha256=fleet['sha256'])
    spec=dict(schema='jetstreamer-horizon-pipeline-status-plan-v1',epoch=epoch,phase=p['phase'],binding=binding,
        receipt_directory=str(Path(origin['path']).parent),observer=observer,fleet=fleet,origin_launch=origin,
        estimated_remaining_millis=p['estimated_remaining_millis'],expected_jet_size_bytes=lane.LENGTH,jet_path=archive['path'],
        estimate_basis=data['basis'],estimate_evidence=[intent,ref(status/f'timing{epoch}.json'),claim_ref],
        peer_units=[f'horizon-upload-{epoch}-singleton-20261119-v1.service'])
    if model.exists():assert bound(ref(model))==spec
    else:put(model,spec)
    binary=bound(ref(D/'horizon266-bounded-consumers-v210-a2/deployment.json'))['binaries']['jetstreamer-r2']
    image=Path(binary['path'])
    assert image.resolve()==image and image.stat().st_uid==0 and not image.stat().st_mode & 0o222
    with image.open('rb') as stream:
        assert hashlib.file_digest(stream,'sha256').hexdigest()==binary['sha256']
    cmd=[binary['path'],'status-publish-pipeline',str(model),'--plan-sha256',ref(model)['sha256']]
    result=subprocess.run([*cmd,'--check-only'],capture_output=True,text=True)
    put(folder/'check.json',dict(model=ref(model),binary=binary,code=result.returncode,stderr=result.stderr,stdout=result.stdout))
    result.check_returncode()
    result=subprocess.run(cmd,capture_output=True,text=True)
    if result.returncode:raise RuntimeError(result.stderr)
    native=ref(Path(result.stdout.strip()))
    receipt=bound(native)
    assert receipt['authenticated_readback'] and receipt['status']==p and receipt['pipeline_binding']['model_sha256']==ref(model)['sha256']
    assert receipt['object_etag'].strip('"')==expected['etag'].strip('"')
    print(put(complete,dict(fleet=fleet,claim=claim_ref,receipt=native,status=ref(status/'completion.json'))),flush=True)

if __name__=='__main__':
    if sys.argv[1:]==['install']:install()
    else:
        version,epoch=map(int,sys.argv[1:])
        capture(version,{248:delivery248,249:delivery249}[epoch])
