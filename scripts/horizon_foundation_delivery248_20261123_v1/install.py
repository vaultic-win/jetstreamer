"""Extend the existing finite issuer and cadence in place at the pending timer boundary."""
import hashlib
import os
import sys
from pathlib import Path
from delivery248 import BOOK, D, V, partition

TOOLS = V/'horizon248-delivery-v213-tools'
IMPORT = f"import sys\nsys.path.insert(0,{str(TOOLS)!r})\nimport delivery248 as delivery\n"
T = Path('/run/horizon266-bounded-tools-v208')
BASE = Path('/tmp/horizon-main-v213')

def replace(source,old,new):
    assert source.count(old) == 1,old
    return source.replace(old,new)

def price(s):
    s = replace(s,'def price(serial,retained,disk):','def price(serial,retained,disk):\n '+IMPORT.replace('\n','\n ').rstrip())
    s = replace(s,"<= {247,266}", "<= ({247,266,248} if delivery.CLAIM.exists() else {247,266})")
    s = replace(s,"  assert os.path.samefile('/proc/3483521", "  fixed.update(delivery.finite_owner())\n  assert os.path.samefile('/proc/3483521")
    s = replace(s," assert q['hard']<=total", """ if delivery.BOOK.exists():
  book=bound(ref(delivery.BOOK));assert book['gross']==delivery.GROSS and book['disk']==delivery.DISK and not book['automatic_release']
  growth+=book['gross'];floor+=book['disk']
 assert q['hard']<=total""")
    return replace(s,'return dict(closed_guest=rel','return dict(reserved_211_delivery=ref(delivery.BOOK) if delivery.BOOK.exists() else None,closed_guest=rel')

def cadence(s):
    s=replace(s,'version=int(sys.argv[1]);',IMPORT+'version=int(sys.argv[1]);')
    s=replace(s,"launch=c.ref(cad.D/", """binding=None
if delivery.CLAIM.exists():
 binding=delivery.select_schedule(cad,version,state,'replace248' in sys.argv)
 build=delivery.DEPLOY
launch=c.ref(cad.D/""")
    s=replace(s,' w.update(config=dict(',''' if binding:
  assert cfg.get('delivery248_claim') in (None,binding)
  cfg['delivery248_claim']=binding
 elif (delivery.ROOT/'terminal.json').exists():
  cfg.pop('delivery248_claim',None)
 w.update(config=dict(''')
    return replace(s," assert result['ordinary_replay_count']", " assert result.get('delivery248_claim')==binding\n assert result['ordinary_replay_count']")

def status(s):
    s=replace(s,'os.umask(0o077)',IMPORT+'import status248\nos.umask(0o077)')
    original=" assert key in items and f'epoch-{n}.jet.sha256' not in items and (f'epoch-{n}.jet' in items)==(n==247)"
    s=replace(s,original,''' if n==248 and delivery.CLAIM.exists():
  if 'epoch-248.jet.sha256' in items:
   terminal=delivery.ROOT/'terminal.json'
   if terminal.exists() and delivery.bound(delivery.ref(terminal))['ready']:
    write(wd/'terminal-outcome.json',dict(terminal=bind(terminal),observer=bind(obs),ready=True,status_cleanup_pending=(key in items)));continue
   write(wd/'terminal-outcome.json',dict(observer=bind(obs),ready=False,awaiting_native_receipt=True,status_cleanup_pending=True));continue
  if (delivery.ROOT/'terminal.json').exists():
   write(wd/'terminal-outcome.json',dict(terminal=bind(delivery.ROOT/'terminal.json'),observer=bind(obs),ready=False,repair_required=True));continue
  assert key in items and set(items)<= {key,'epoch-248.jet'}
 else:
 '''+original)
    s=replace(s,' marker_data=read(prior_marker);',""" if n==248:
  for directory in (status248.FIRST,status248.START):
   event=directory/'completion.json'
   if event.exists() and read(Path(read(event)['intent']['path']))['previous']==bind(prior_marker):prior_marker=event
 marker_data=read(prior_marker);""")
    s=replace(s,'  else:\n   queue+=20*3600;',"""  elif n==248 and delivery.CLAIM.exists():
   t=status248.timing(sample.timestamp(),items)
   evidence+=[bind(delivery.CLAIM),t['benchmark']]
   model_file=wd/'timing248.json'
   if not model_file.exists():write(model_file,t)
   t=read(model_file);assert t['owner']==delivery.live_binding()['invocation_id']
   phase=t['phase'];queue=t['seconds'];evidence.append(bind(model_file))
   basis='Independent epoch 248 delivery. Local verification, multipart upload, authenticated readback and public playback allowances use measured 247 rates and the current uploader progress.'
  else:
   queue+=20*3600;""")
    return replace(s,'  write(intent,dict(payload=v,previous=bind(before)',"""  if n==248 and delivery.CLAIM.exists():
   v.update(sampled_at_utc=o['recorded_at_utc'],elapsed_execution_millis=t['elapsed'],estimated_remaining_millis=t['seconds']*1000)
  write(intent,dict(payload=v,previous=bind(before)""")

def fleet(s):
    s=replace(s,'import sys,importlib.util',IMPORT+'import sys,importlib.util')
    s=replace(s," v=b.raw(marker);ip=b.checked(v['intent']);",''' incident=marker.parent/'terminal-outcome.json'
 if n==248 and incident.exists():
  assert b.raw(incident)['observer']==b.ref(obs)
  b.include(p['gates']['248'],incident)
  continue
 v=b.raw(marker);ip=b.checked(v['intent']);''')
    s=replace(s,'q=b.raw(built);',"""added=delivery.CLAIM.exists() and delivery.census(p,o,done)
for target in range(292,296):
 b.include(p['gates'][str(target)],d/'horizon292-bootstrap-layout-v211-a1/completion.json')
q=b.raw(built);""")
    return replace(s,"=={247,266}","==({247,266,248} if added else {247,266})")

def main():
    assert Path(__file__).parent == TOOLS
    changes = [
        (T/'retry_fit.py','3a057a380b987a677f401fa6d739b046035f15f8a4db3c4aa75076788c5a269b',price),
        (T/'retry_entry_cadence.py','a3b4295cecb04a6b316e45fdd783c9e6d3bb3aafe17ec76fbeee66ec60cd683d',cadence),
        (Path('/run/horizon266-terminal-event-v211-a1/cadence.py'),'be53e07fe15c12706e571ffd041b252de89f5bf0ee00eeb121143c5af9c6fbdd',cadence),
        (BASE/'fleet.py','7a654f4ec5bb708c053db38b54b5bb025d1583ebbd3d9a012ae96fa54a62d156',fleet),
        (BASE/'status.py','bed74a3e053a5cb39c0fbd57c49732283964efa22abe7694d0a3a1af08a4847d',status)]
    with partition.take():
        assert not BOOK.exists() and not (D/'horizon-resume-observer-20261120-v213.json').exists()
        staged = []
        for path,digest,render in changes:
            data = path.read_bytes()
            assert path.stat().st_uid == 0 and hashlib.sha256(data).hexdigest() == digest,path
            source = render(data.decode())
            compile(source,str(path),'exec')
            staged.append((path,source,data))
        for path,source,data in staged:
            backup = TOOLS/(path.parent.name+'-'+path.name+'.original')
            if not backup.exists(): backup.write_bytes(data);backup.chmod(0o400)
            assert backup.read_bytes() == data
            tmp = path.with_suffix('.with248')
            with tmp.open('x') as file:
                file.write(source);file.flush();os.fchmod(file.fileno(),0o400);os.fsync(file.fileno())
            os.replace(tmp,path)

if __name__=='__main__':
    main()
