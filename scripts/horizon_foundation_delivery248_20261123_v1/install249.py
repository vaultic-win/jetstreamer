"""Register both delivery lanes on the existing 30-minute cadence and resource ledger."""
import hashlib
import os
import sys
from pathlib import Path
from . import delivery249 as lane

TOOLS = lane.V/'horizon249-delivery-v214-tools'
IMPORT = f"sys.path.insert(0,{str(TOOLS)!r})\nfrom ordinary249 import delivery249 as lane249\n"
T = Path('/run/horizon266-bounded-tools-v208')
BASE = Path('/tmp/horizon-main-v214')

def once(s,old,new):
    assert s.count(old)==1,old
    return s.replace(old,new)

def price(s):
    s=once(s,' import verify as audit247',' import verify as audit247\n '+IMPORT.strip().replace('\n','\n '))
    s=once(s,'if delivery.CLAIM.exists() else {247,266})','if delivery.CLAIM.exists() else {247,266}) | ({249} if lane249.CLAIM.exists() else set())')
    s=once(s,' def witness():',' anon_samples=[]\n def witness():')
    s=once(s,'  fixed.update(audit247.witness())','  fixed.update(audit247.witness())\n  fixed.update(lane249.finite_owner())')
    # MemAvailable already excludes these resident anonymous pages. Keep the complete
    # unconsumed limit and control reserve, and credit no file cache or shared memory.
    s=once(s,'  return samples','''  anonymous={}
  for unit in (delivery.UNIT,audit247.UNIT):
   if unit in fixed:
    stat=dict(line.split() for line in (CG/unit/'memory.stat').read_text().splitlines())
    anonymous[unit]=min(samples[unit],int(stat['anon']))
    assert anonymous[unit]>=0 and int((CG/unit/'memory.swap.current').read_text())==0
  anon_samples.append(anonymous)
  return samples''')
    s=once(s," assert q['hard']<=total",""" if lane249.BOOK.exists():
  book=bound(ref(lane249.BOOK));assert book['gross']==delivery.GROSS and book['disk']==delivery.DISK and not book['automatic_release']
  growth+=book['gross'];floor+=book['disk']
 assert len(anon_samples)>=3
 credit={unit:min(sample.get(unit,0) for sample in anon_samples) for unit in (delivery.UNIT,audit247.UNIT)}
 assert credit[delivery.UNIT]<=delivery.LIMIT and credit[audit247.UNIT]<=audit_growth
 growth-=sum(credit.values())
 assert q['hard']<=total""")
    return once(s,'return dict(public247_charge=',"return dict(reserved_211_delivery249=ref(lane249.BOOK) if lane249.BOOK.exists() else None,resident_anonymous_credit=credit,public247_charge=")

def cadence(s):
    s=once(s,'version=int(sys.argv[1]);',IMPORT+'version=int(sys.argv[1]);')
    s=once(s,' build=delivery.DEPLOY',''' build=delivery.DEPLOY
binding249=None
if lane249.CLAIM.exists():
 binding249=lane249.select_schedule(cad,version,state,'replace249' in sys.argv)
 build=lane249.DEPLOY''')
    s=once(s,' w.update(config=dict(',''' if binding249:
  assert cfg.get('delivery249_claim') in (None,binding249)
  cfg['delivery249_claim']=binding249
 elif (lane249.ROOT/'terminal.json').exists():
  cfg.pop('delivery249_claim',None)
 w.update(config=dict(''')
    return once(s," assert result.get('delivery248_claim')==binding"," assert result.get('delivery248_claim')==binding and result.get('delivery249_claim')==binding249")

def status(s):
    s=once(s,'import status248\n',IMPORT+'from ordinary249 import status248, delivery248 as lane248\n')
    s=once(s,' if n==248 and delivery.CLAIM.exists():\n  if', ''' lane={248:lane248,249:lane249}.get(n)
 if lane and lane.CLAIM.exists():
  if''')
    s=s.replace("'epoch-248.jet.sha256' in items", "f'epoch-{n}.jet.sha256' in items").replace("{key,'epoch-248.jet'}","{key,f'epoch-{n}.jet'}")
    s=s.replace("delivery.ROOT/'terminal.json'","lane.ROOT/'terminal.json'")
    s=once(s," if n==248:\n  for directory in (status248.FIRST,status248.START):"," if lane:\n  for directory in ((status248.FIRST,status248.START) if n==248 else (lane.ROOT/'origin-clock-status',)):")
    s=s.replace('n==248 and delivery.CLAIM.exists()', 'lane and lane.CLAIM.exists()')
    s=once(s,'status248.timing(sample.timestamp(),items)','status248.timing(sample.timestamp(),items,lane)')
    s=s.replace('bind(delivery.CLAIM)','bind(lane.CLAIM)').replace('delivery.live_binding()', 'lane.live_binding()')
    s=once(s,"wd/'timing248.json'","wd/f'timing{n}.json'")
    return once(s,"basis='Independent epoch 248 delivery.","basis=f'Independent epoch {n} delivery.")

def fleet(s):
    s=once(s,'import delivery248 as delivery','import delivery248 as delivery\n'+IMPORT)
    s=once(s,'if n==248 and incident.exists():','if n in (248,249) and incident.exists():')
    s=once(s,"b.include(p['gates']['248'],incident)","b.include(p['gates'][str(n)],incident)")
    s=once(s,'added=delivery.CLAIM.exists()',"""audit=d/'horizon-r2-public247-current-reader-v214'
for record in ('launch.json','verified.json'):
 if (audit/record).is_file(): b.include(p['gates']['247'],audit/record)
added249=lane249.CLAIM.exists() and lane249.census(p,o,done)
added=delivery.CLAIM.exists()""")
    return once(s,'==({247,266,248} if added else {247,266})','==({247,266}|({248} if added else set())|({249} if added249 else set()))')

def main():
    assert __debug__ and os.geteuid()==0 and Path(__file__).parent==TOOLS/'ordinary249'
    files=[
        (T/'retry_fit.py','313351892682d785daa36a4924e7a3da2f83b028ed7d84ad1f228409e55a1574',price),
        (T/'retry_entry_cadence.py','294231b3b6e876c33b99cf6c732fffef9acc47a1198de4e9daf1837097958ba0',cadence),
        (Path('/run/horizon266-terminal-event-v211-a1/cadence.py'),'cbcd0fbb774ce42eb832dc3812125b106c6467ca07234533ed1c549e231d1add',cadence),
        (BASE/'status.py','3ba007eb8407ae0d475beabc1a09ab1427248f104e94b41725b35cfdd378b9b0',status),
        (BASE/'fleet.py','7f81d6fc720b8d895677e0f1c7cf4d0b9b49bb3166540d60a86132268f47c369',fleet)]
    with lane.shared.partition.take():
        assert not lane.BOOK.exists() and not (lane.D/'horizon-resume-observer-20261120-v214.json').exists()
        changes=[]
        for path,sha,render in files:
            backup=TOOLS/(path.parent.name+'-'+path.name+'.original')
            original=backup.read_bytes() if backup.exists() else path.read_bytes()
            assert path.stat().st_uid==0 and hashlib.sha256(original).hexdigest()==sha,path
            result=render(original.decode()).encode()
            compile(result,str(path),'exec')
            assert path.read_bytes() in (original,result)
            changes.append((path,backup,original,result))
        if sys.argv[1:] == ['check']:
            print('Validated five existing worker and cadence consumers')
            return
        assert sys.argv[1:]==['install']
        for path,backup,original,result in changes:
            if not backup.exists():
                with backup.open('xb') as f:
                    f.write(original); f.flush(); os.fchmod(f.fileno(),0o400); os.fsync(f.fileno())
            if path.read_bytes()==result:
                continue
            tmp=path.with_suffix('.delivery249')
            with tmp.open('xb') as f:
                f.write(result);f.flush();os.fchmod(f.fileno(),0o400);os.fsync(f.fileno())
            os.replace(tmp,path)

if __name__=='__main__':
    main()
