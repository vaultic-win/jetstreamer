"""Publish the independently running epoch's ETA with its original conditional status lineage."""
import datetime as dt
import hashlib
import json
import math
import os
import time
from pathlib import Path
from delivery248 import CLAIM, D, KEY, LENGTH, PRIVATE, ROOT, SHA, aws, bound, funds, live_binding, prefix, ref, registered

START = ROOT/'start-status'
OLD = D/'horizon247-delivery-admission-20261119-v1/operation.log'

def events(path):
    with path.open('rb') as stream:
        size = os.fstat(stream.fileno()).st_size
        assert size < 64 << 20
        data = stream.read(size)
        assert len(data) == size
    rows = [json.loads(line) for line in data.splitlines() if line.startswith(b'{"') and line.endswith(b'}') and b'"event":"r2-' in line]
    return rows,dict(path=str(path),prefix_bytes=size,prefix_sha256=hashlib.sha256(data).hexdigest())

def timing(now, items):
    claim_ref,claim,book,launch = registered()
    live_binding()
    assert KEY in items and 'epoch-248.jet.sha256' not in items
    original = Path(book['fit']['fleet']['path'])
    v = original.parent.name.split('-v')[1].split('-')[0]
    benchmark = D/f'horizon-resumed-campaign-status-v{v}-a1/247/readback-timing.json'
    old = bound(ref(benchmark))
    history, history_ref = events(OLD)
    upload, = [row for row in history if row['event'] == 'r2-upload-committed']
    assert upload['acknowledged_bytes'] == upload['total_bytes'] == old['total_bytes'] and upload['key'] == 'epoch-247.jet'
    ratio = LENGTH / old['total_bytes']
    local = ratio*old['repeat_local_seconds']
    send = ratio*upload['elapsed_millis']/1000
    read = ratio*old['repeat_whole_read_seconds']
    public = ratio*old['repeat_public_seconds']
    rows, log = events(ROOT/'operation.log')
    assert all(r['key'] == 'epoch-248.jet' and r['total_bytes'] == LENGTH for r in rows)
    phase = 'verification'
    elapsed = max(0,now-launch['time'])
    remaining = max(1800,local-elapsed)+send+read+public
    for row in rows:
        kind = row['event']
        if kind.startswith('r2-upload-'):
            assert 0 <= row['acknowledged_bytes'] <= LENGTH
            phase = 'upload'
            transferred = row['acknowledged_bytes']
            rate = transferred / (row['elapsed_millis']/1000) if transferred and row['elapsed_millis'] else LENGTH/send
            remaining = (LENGTH-transferred)/rate+read+public
        elif kind.startswith('r2-readback-'):
            amount = row['hashed_bytes']
            assert 0 <= amount <= LENGTH
            phase = 'readback'
            rate = amount/(row['elapsed_millis']/1000) if amount and row['elapsed_millis'] else LENGTH/read
            remaining = (LENGTH-amount)/rate+public
            if kind == 'r2-readback-verified':
                assert amount == LENGTH and row['whole_file_sha256_verified']
                phase = 'verification'
                remaining = max(1800, public-max(0,now-(ROOT/'operation.log').stat().st_mtime))
    if 'epoch-248.jet' in items:
        assert items['epoch-248.jet']['Size'] == LENGTH
        meta = aws('head-object','--key','epoch-248.jet')
        assert meta['ContentLength'] == LENGTH and meta['ETag'] == items['epoch-248.jet']['ETag']
        assert SHA in meta['Metadata'].values()
    return dict(phase=phase,seconds=math.ceil(remaining+1800),elapsed=round(elapsed*1000),owner=launch['unit']['InvocationID'],
                claim=claim_ref,benchmark=ref(benchmark),original_upload=history_ref,log=log,at=now)

def start():
    claim_ref,claim,book,launch = registered()
    fleet = Path(book['fit']['fleet']['path'])
    v = fleet.parent.name.split('-v')[1].split('-')[0]
    prev = ref(D/f'horizon-resumed-campaign-status-v{v}-a1/248/completion.json')
    previous = bound(prev)
    old = bound(previous['readback'])
    assert old['epoch'] == 248 and previous['authenticated_exact_byte_readback'] and previous['key'] == KEY
    START.mkdir(mode=0o700,exist_ok=True)
    marker = START/'completion.json'
    if marker.exists():
        assert bound(bound(ref(marker))['intent'])['previous'] == prev
        return
    items = prefix()
    intent = START/'intent.json'
    if not intent.exists():
        got = aws('get-object','--key',KEY,str(START/'before.json'))
        assert got['ETag'] == items[KEY]['ETag'] == previous['etag'] and ref(START/'before.json')['sha256'] == previous['readback']['sha256']
        t = timing(time.time(),items)
        now = dt.datetime.fromtimestamp(t['at'],dt.timezone.utc)
        payload = dict(epoch=248,phase=t['phase'],jet_size_bytes=LENGTH,elapsed_execution_millis=t['elapsed'],
                       estimated_remaining_millis=t['seconds']*1000,sampled_at_utc=now.strftime('%Y-%m-%dT%H:%M:%SZ'))
        funds.put(intent,dict(key=KEY,previous=prev,payload=payload,evidence=[claim_ref,book['fixture'],ref(START/'timing.json') if (START/'timing.json').exists() else funds.put(START/'timing.json',t)],
                              basis='Independent two-thread delivery. Timings scale measured epoch 247 local verification, multipart upload, readback and public playback to the epoch 248 archive.'))
    value = bound(ref(intent))
    blob = START/'payload.json'
    if not blob.exists(): funds.put(blob,value['payload'])
    assert bound(ref(blob)) == value['payload']
    if items[KEY]['ETag'] == previous['etag']:
        aws('put-object','--key',KEY,'--if-match',previous['etag'],'--body',str(blob),'--content-type','application/json')
    got = aws('get-object','--key',KEY,str(START/'readback.json'))
    assert (START/'readback.json').read_bytes() == blob.read_bytes()
    funds.put(marker,dict(key=KEY,etag=got['ETag'],intent=ref(intent),readback=ref(START/'readback.json'),authenticated_exact_byte_readback=True))

if __name__ == '__main__':
    start()
