"""Publish the independently running epoch's ETA with its original conditional status lineage."""
import datetime as dt
if __package__:
    from . import delivery248
else:
    import delivery248
import hashlib
import json
import math
import os
import time
from pathlib import Path
D, ROOT = delivery248.D, delivery248.ROOT
aws, bound, funds, ref = delivery248.aws, delivery248.bound, delivery248.funds, delivery248.ref

FIRST = ROOT/'start-status'
START = ROOT/'origin-clock-status'
OLD = D/'horizon247-delivery-admission-20261119-v1/operation.log'

def events(path):
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        assert size < 64 << 20
        data = stream.read(size)
        assert len(data) == size
    rows = [json.loads(line) for line in data.splitlines() if line.startswith(b'{"') and line.endswith(b'}') and b'"event":"r2-' in line]
    return rows,dict(path=str(path),prefix_bytes=size,prefix_sha256=hashlib.sha256(data).hexdigest())

def timing(now, items, owner=delivery248):
    archive_key = f"epoch-{owner.EPOCH}.jet"
    claim_ref,claim,book,launch = owner.registered()
    owner.live_binding()
    assert owner.KEY in items and archive_key+'.sha256' not in items
    original = Path(book['fit']['fleet']['path'])
    v = original.parent.name.split('-v')[1].split('-')[0]
    benchmark = D/f'horizon-resumed-campaign-status-v{v}-a1/247/readback-timing.json'
    old = bound(ref(benchmark))
    history, history_ref = events(OLD)
    upload, = [row for row in history if row['event'] == 'r2-upload-committed']
    assert upload['acknowledged_bytes'] == upload['total_bytes'] == old['total_bytes'] and upload['key'] == 'epoch-247.jet'
    ratio = owner.LENGTH / old['total_bytes']
    local = ratio*old['repeat_local_seconds']
    send = ratio*upload['elapsed_millis']/1000
    read = ratio*old['repeat_whole_read_seconds']
    public = ratio*old['repeat_public_seconds']
    rows, log = events(owner.ROOT/'operation.log')
    assert all(r['key'] == archive_key and r['total_bytes'] == owner.LENGTH for r in rows)
    phase = 'verification'
    elapsed = max(0,now-launch['time'])
    remaining = max(1800,local-elapsed)+send+read+public
    for row in rows:
        kind = row['event']
        if kind.startswith('r2-upload-'):
            assert 0 <= row['acknowledged_bytes'] <= owner.LENGTH
            phase = 'upload'
            transferred = row['acknowledged_bytes']
            rate = transferred / (row['elapsed_millis']/1000) if transferred and row['elapsed_millis'] else owner.LENGTH/send
            remaining = (owner.LENGTH-transferred)/rate+read+public
        elif kind.startswith('r2-readback-'):
            amount = row['hashed_bytes']
            assert 0 <= amount <= owner.LENGTH
            phase = 'readback'
            rate = amount/(row['elapsed_millis']/1000) if amount and row['elapsed_millis'] else owner.LENGTH/read
            remaining = (owner.LENGTH-amount)/rate+public
            if kind == 'r2-readback-verified':
                assert amount == owner.LENGTH and row['whole_file_sha256_verified']
                phase = 'verification'
                remaining = max(1800, public-max(0,now-(owner.ROOT/'operation.log').stat().st_mtime))
    if archive_key in items:
        assert items[archive_key]['Size'] == owner.LENGTH
        meta = aws('head-object','--key',archive_key)
        assert meta['ContentLength'] == owner.LENGTH and meta['ETag'] == items[archive_key]['ETag']
        assert owner.SHA in meta['Metadata'].values()
    origin = bound(book['handoff'])['producer']
    event, = [e for e in origin['events'] if e['MESSAGE_ID'] == '39f53479d3a045ac8e11786248231fbf']
    assert event['_PID'] == '1' and event['_UID'] == '0' and event['UNIT'] == origin['unit']['Id']
    assert event['INVOCATION_ID'] == origin['unit']['InvocationID'] == owner.ORIGIN_IID
    elapsed_ms = int(now*1000)-int(event['__REALTIME_TIMESTAMP'])//1000
    assert elapsed_ms >= elapsed*1000
    return dict(phase=phase,seconds=math.ceil(remaining+1800),elapsed=elapsed_ms,owner=launch['unit']['InvocationID'],
                claim=claim_ref,benchmark=ref(benchmark),original_upload=history_ref,log=log,at=now)

def start(owner=delivery248, previous_receipt=None):
    directory = owner.ROOT/'origin-clock-status'
    claim_ref,claim,book,launch = owner.registered()
    fleet = Path(book['fit']['fleet']['path'])
    v = fleet.parent.name.split('-v')[1].split('-')[0]
    prev = previous_receipt or ref(D/f'horizon-resumed-campaign-status-v{v}-a1/{owner.EPOCH}/completion.json')
    if owner.EPOCH == 248:
        first = ref(FIRST/'completion.json')
        assert bound(bound(first)['intent'])['previous'] == prev
        prev = first
    previous = bound(prev)
    old = bound(previous['readback'])
    assert old['epoch'] == owner.EPOCH and previous['authenticated_exact_byte_readback'] and previous['key'] == owner.KEY
    directory.mkdir(mode=0o700,exist_ok=True)
    marker = directory/'completion.json'
    if marker.exists():
        assert bound(bound(ref(marker))['intent'])['previous'] == prev
        return
    items = owner.prefix()
    intent = directory/'intent.json'
    if not intent.exists():
        got = aws('get-object','--key',owner.KEY,str(directory/'before.json'))
        assert got['ETag'] == items[owner.KEY]['ETag'] == previous['etag'] and ref(directory/'before.json')['sha256'] == previous['readback']['sha256']
        t = timing(time.time(),items,owner)
        now = dt.datetime.fromtimestamp(t['at'],dt.timezone.utc)
        payload = dict(epoch=owner.EPOCH,phase=t['phase'],jet_size_bytes=owner.LENGTH,elapsed_execution_millis=t['elapsed'],
                       estimated_remaining_millis=t['seconds']*1000,sampled_at_utc=now.strftime('%Y-%m-%dT%H:%M:%SZ'))
        funds.put(intent,dict(key=owner.KEY,previous=prev,payload=payload,evidence=[claim_ref,book['fixture'],ref(directory/'timing.json') if (directory/'timing.json').exists() else funds.put(directory/'timing.json',t)],
                              basis=f'Independent two-thread delivery. Timings scale measured epoch 247 local verification, multipart upload, readback and public playback to the epoch {owner.EPOCH} archive.'))
    value = bound(ref(intent))
    blob = directory/'payload.json'
    if not blob.exists(): funds.put(blob,value['payload'])
    assert bound(ref(blob)) == value['payload']
    if items[owner.KEY]['ETag'] == previous['etag']:
        aws('put-object','--key',owner.KEY,'--if-match',previous['etag'],'--body',str(blob),'--content-type','application/json')
    got = aws('get-object','--key',owner.KEY,str(directory/'readback.json'))
    assert (directory/'readback.json').read_bytes() == blob.read_bytes()
    funds.put(marker,dict(key=owner.KEY,etag=got['ETag'],intent=ref(intent),readback=ref(directory/'readback.json'),authenticated_exact_byte_readback=True))

if __name__ == '__main__':
    start()
