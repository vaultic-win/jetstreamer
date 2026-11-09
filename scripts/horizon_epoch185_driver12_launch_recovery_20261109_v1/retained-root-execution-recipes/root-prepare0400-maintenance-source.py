from pathlib import Path
import json,hashlib,ast,os
old=Path('/tmp/continuations0330-status-only-driver12-source-20261109-v1/maintenance');p=Path('/tmp/continuations0400-status-only-final5-failure-source-20261109-v1/maintenance');p.mkdir(parents=True,mode=0o700)
sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def upd(s):return s.replace('033022','040022').replace('current0330','current0400').replace('CURRENT0330','CURRENT0400').replace('2026-11-09T03:30:22Z','2026-11-09T04:00:22Z').replace('1794195022','1794196822')
for f in old.iterdir():
 if f.is_file():
  dest=p/upd(f.name)
  with dest.open('x')as h:h.write(upd(f.read_text()))
  os.chmod(dest,0o600)
mp=json.loads((old/'CURRENT0330_EXACT_LITERAL_MAP.json').read_text());mp={v:upd(v)for v in mp.values()if isinstance(v,str)and upd(v)!=v};(p/'CURRENT0400_EXACT_LITERAL_MAP.json').write_text(json.dumps(mp,indent=2)+'\n')
f=p/'maintain-first-lane0330.py';s=f.read_text();s=s.replace("old = base / 'actual030022-visible-root-acceptance-20261109-v1'", "old = base / 'actual033022-visible-root-acceptance-20261109-v1'")
s=s.replace('status-estimate-review030022.json','status-estimate-review033022.json').replace('status-audit030022-execution.json','status-audit033022-execution.json').replace('inventory030022-argv.json','inventory033022-argv.json').replace('status-audit030022-argv.json','status-audit033022-argv.json')
s=s.replace('sample-20261109T030022Z-postcompletion154-v1.json','sample-20261109T033022Z-postcompletion154-v1.json').replace('03a38c4dce0fd1f8d8fa8838b9b7d41d9ce225e71a5276fa354de6c357ed39ad','5c8457f3d3f32eeecab7e5e89c793362a363350ab74c2ca86295925cd42d2c94')
start=s.index("review['current_cycle_reassessment'] = ");end=s.index('\n',start)
status='Nov9 04:00 recovery. Actual replay0 target5. Driver12 resource-census repair and Helper35 ACTUALLYqualified and normally sealed. H35 four compiler stages2938ordinary126ignored all retainedH34controls and genuine0230Frame complete outer adapter passed; freshQA5closed, normal6GiBextraQA0. Final5 four compilers37ordinary9ignored and native0-7 passed; native8 prestart-only fixed deadline control FAILED at Instant::now>=deadline. Final5 NOT qualified, production not sealed. Likely poll floor submillisecond early timeout; Final6 narrow successor source diagnosis delegated, all original22/30/600 clocks and original failure preserved. Planner6 and Operation38 independent source tasks; no launch until actual qualification/current guard/fresh admission. Canonical retainedDATA5174779130516 includes Final5DATA512MiB once; no P6/O38/guard0400 charges. ActualReview7 deadline04:43:21 retains same19:25:15control/original17:30:22+24hqualification/full413404206/bootstrap1h/verification6h/delivery4h. Original0230Main failed02:47:53 own resourceguardENOENT with zeroOOM counters; actual qualified terminal retained, completed reader not yet retired. Last genuineFrame/resources0230; 0300/0330/0400 are observer/status-only until full current chain qualified. Sole active controller Root; otherhost200-300three lanes and original199FDs protected. Prepare next executable launch dependencies directly; source/build not replay.'
s=s[:start]+"review['current_cycle_reassessment'] = "+repr(status)+s[end:];s=s.replace('CurrentNov9 03:30:22','CurrentNov9 04:00:22');f.unlink();(p/'maintain-first-lane0400.py').write_text(s)
book=Path('/home/sol/.jetstreamer-private/epoch185-final5-postmain-driver12-qa-20261109-v1/ROOT_NORMAL6_FINAL5_DATA512_BOOKING.json');(p/'ROOT_ACTUAL_CURRENT0400_DATA_BINDING.json').write_text(json.dumps(b(book),indent=2)+'\n')
for f in p.glob('*.py'):ast.parse(f.read_text())
ast.parse((p/'status_audit040022.py.PREVIEW').read_text())
(p/'HANDOFF.md').write_text('Existing status-only continuation adapted to actual sole0400observer, all historical clocks retained. D12/H35qualified; Final5lastnativefailed. CanonicalDATA5174779130516 normal6extraQA0. No newresourcecredits. No observer rearm.\n')
print(p)
