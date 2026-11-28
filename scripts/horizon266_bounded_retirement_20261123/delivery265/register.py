"""Register the independent epoch 265 uploader with the existing cadence and resource issuers."""
import hashlib
import os
from pathlib import Path
import sys

import lane265 as lane

ROOT=Path('/var/lib/jetstreamer/horizon265-delivery-v215-tools')
IMPORT="sys.path.insert(0,'/var/lib/jetstreamer/horizon265-delivery-v215-tools')\nimport lane265\n"
T=Path('/run/horizon266-bounded-tools-v208')


def replace(s, a, b):
    assert s.count(a)==1,a
    return s.replace(a,b)


def cadence(s):
    s=replace(s,'from ordinary249 import delivery249 as lane249\n','from ordinary249 import delivery249 as lane249\n'+IMPORT)
    s=replace(s,' build=lane249.DEPLOY',''' build=lane249.DEPLOY
binding265=None
if lane265.CLAIM.exists():
 binding265=lane265.select_schedule(cad,version,state,'replace265' in sys.argv)
 build=lane265.DEPLOY''')
    s=replace(s,"  cfg.pop('delivery249_claim',None)", """  cfg.pop('delivery249_claim',None)
 if binding265:
  assert cfg.get('delivery265_claim') in (None,binding265)
  cfg['delivery265_claim']=binding265
 elif (lane265.ROOT/'terminal.json').exists():
  cfg.pop('delivery265_claim',None)""")
    return replace(s,"result.get('delivery249_claim')==binding249","result.get('delivery249_claim')==binding249 and result.get('delivery265_claim')==binding265")


def price(s):
    s=replace(s,' from ordinary249 import delivery249 as lane249\n',' from ordinary249 import delivery249 as lane249\n '+IMPORT.strip().replace('\n','\n ')+'\n')
    s=replace(s,'({249} if lane249.CLAIM.exists() else set())','({249} if lane249.CLAIM.exists() else set()) | ({265} if lane265.CLAIM.exists() else set())')
    s=replace(s,'  fixed.update(lane249.finite_owner())','  fixed.update(lane249.finite_owner())\n  fixed.update(lane265.finite_owner())')
    s=replace(s,' assert len(anon_samples)>=3',""" if lane265.BOOK.exists():
  b265=bound(ref(lane265.BOOK));release=bound(b265['donor'])
  assert b265['donor']['sha256']=='c2112c2cf4d97797dbf9d1d2c347c2e00c954c14eedba5572b621aa22e7588af'
  assert release['terminal']==ref(D/'horizon266-bounded-terminal-event-v211-a1/completion.json') and release['original']==br
  assert release['current']['identity']==p['identity'] and Path('/sys/block/loop18/ro').read_text().strip()=='1'
  assert p['first']['blocks']==p['second']['blocks']==release['retained_backing_bytes']
  assert b265['gross']==delivery.GROSS and b265['disk']==delivery.DISK and not b265['automatic_release']
  # The old 266 floor already reserves this disk. Commit only its sealed freed space.
  assert b265['disk']<=p['remaining']
  growth+=b265['gross']
 assert len(anon_samples)>=3""")
    return replace(s,'return dict(assessment_only=','return dict(closed265_delivery=ref(lane265.BOOK) if lane265.BOOK.exists() else None,assessment_only=')


def status(s):
    s=replace(s,"  if n==265:\n   elapsed=", "  if n==265 and not lane.CLAIM.exists():\n   elapsed=")
    s=replace(s,'from ordinary249 import delivery249 as lane249\n','from ordinary249 import delivery249 as lane249\n'+IMPORT)
    s=replace(s,'249:lane249}.get(n)','249:lane249,265:lane265}.get(n)')
    s=replace(s,' if n in range(247,252):',' if n in range(247,252) or (n==265 and lane.CLAIM.exists()):')
    return replace(s,"hand=V/f'horizon-singleton-delivery{n}-20261119-v1/terminal-handoff.json';archive=", "hand=V/(f'horizon-singleton-delivery{n}-20261119-v1' if n!=265 else 'horizon-singleton-delivery265-20261120-v1')/'terminal-handoff.json';archive=")


def fleet(s):
    s=replace(s,'from ordinary249 import delivery249 as lane249\n','from ordinary249 import delivery249 as lane249\n'+IMPORT)
    s=replace(s,'if n in (248,249) and incident.exists():','if n in (248,249,265) and incident.exists():')
    s=replace(s,'added249=lane249.CLAIM.exists()',"""closure=b.checked(lane265.ref(lane265.D/'horizon257-after-closed266-v215-a1/assessment.json'))
for e in (257,266):
 b.include(p['gates'][str(e)],lane265.D/'horizon257-after-closed266-v215-a1/assessment.json',lane265.V/'horizon266-v210-closed-growth-v215/release.json')
p['gates']['257']['next_action']='Native bootstrap inputs match. Use the sealed 266 capacity to fund the guarded 257 cold restore and charge concurrent delivery.'
p['gates']['266']['next_action']='The partial archive is retained on the sealed loop. Full replay requires qualified holding retirement and a serial restore budget for 250 and 251.'
added265=lane265.CLAIM.exists() and lane265.census(p,o,done)
added249=lane249.CLAIM.exists()""")
    return replace(s,'|({249} if added249 else set()))','|({249} if added249 else set())|({265} if added265 else set()))')


def install():
    assert __debug__ and os.geteuid()==0 and Path(__file__).parent==ROOT
    base=Path('/tmp/horizon-main-v216')
    tables=[
        (T/'retry_fit.py','75b2ff13ee9f07ea8afb7a4a46f9a93fa845e21c8719a269b0cedbd84a3cd153',price),
        (T/'retry_entry_cadence.py','ba06d6aa1b0293a50dd86f2a65010eb3aa7d304c8412fb050def57ff5d6e75e1',cadence),
        (Path('/run/horizon266-terminal-event-v211-a1/cadence.py'),'4fc25cef0e1e1e90813abb29b40361019b2e4da836f8da87a781f9f43ebf0b75',cadence),
        (base/'status.py','6552866bdfac8c49beb1743914a1c1f5ba22cfac44a1fbb870e8b4e17baf8263',status),
        (base/'fleet.py','0672d60ef3d9227a6ef0e7d6ce93dc7541d340a385935bde6ea51f019c7f55fe',fleet)]
    records=[]
    with lane.shared.partition.take():
        assert not (lane.D/'horizon-resume-observer-20261120-v216.json').exists()
        for path,digest,render in tables:
            backup=ROOT/(path.parent.name+'-'+path.name+'.original')
            start=backup.read_bytes() if backup.exists() else path.read_bytes()
            assert hashlib.sha256(start).hexdigest()==digest and path.stat().st_uid==0
            code=render(start.decode());compile(code,str(path),'exec')
            records.append((path,backup,start,code.encode()))
        for path,backup,start,new in records:
            assert path.read_bytes() in (start,new)
            if not backup.exists():
                with backup.open('xb') as f:
                    f.write(start);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
            if path.read_bytes()!=new:
                tmp=path.with_suffix('.with265')
                with tmp.open('xb') as f:
                    f.write(new);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
                os.replace(tmp,path)
        print('Registered 265 funding, cadence, status and fleet consumers',flush=True)


if __name__=='__main__':install()
