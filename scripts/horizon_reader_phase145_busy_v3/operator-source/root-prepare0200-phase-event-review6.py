from pathlib import Path
import json,os,hashlib,datetime,re,subprocess
base=Path('/home/sol/.jetstreamer-private');mp=base/'epoch185-explicit-control-review6-model-20261109-next-v1';mp.mkdir(mode=0o700)
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
b=lambda p:dict(path=str(p),sha256=sha(p))
def save(p,v):
 raw=(json.dumps(v,indent=2)+'\n').encode() if not isinstance(v,str) else v.encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
previous=base/'epoch185-explicit-control-review5-model-20261109-next-v1/FIXED185_ETA_MODEL_EXPLICIT_CONTROL_REVIEW5.json'
v=json.loads(previous.read_text());now=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
parse=lambda x:datetime.datetime.strptime(x,'%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc)
reason='Actual02 finitechain passed strict qualified37/Final4 metadata authority and realfleet; realFrame capability passed. O26 capture-phase failed while the unchanged145 periodicguard was activating with pendingJob41040174. Its query rejects Job before its intended active-guard wait branch. No02Frame/reader/actor/Main ran; no retry after original02:15:22 cutoff. Root will repair this finite readonly phase wait to classify exact busy guard states as waiting, retain strict settled guard/timer identity and all2-4s/25s gates, qualify native negatives, and integrate phase successor. Remaining planning allocation: timing source and ordinary/native qualification15min, next02:30 guard/current metadata preparation10min, fresh finite Frame/reader/admission/originalMain25min, contingency10min. Final4/Operation37/guard0200 actual qualification and exact0100retirement remain completed and not repeated. Fullboundary/publicationstillunqualified. Original24h qualification and full unexecuted replay costs unchanged; no native lease change.'
v['control_review_history'].append(dict(previous_model=b(previous),previous_total_control_allocation_millis=v['control_integration_allocation_millis'],reviewed_at_utc=now.strftime('%Y-%m-%dT%H:%M:%SZ'),original_control_anchor_preserved=v['control_model_issued_at_utc'],explicit_new_remaining_control_allowance_millis=3600000,reason=reason,inside_original24h_qualification_budget=True,no_original_native_clock_reset=True))
v['control_integration_allocation_millis']=int((now-parse(v['control_model_issued_at_utc'])).total_seconds())*1000+3600000
assert v['control_integration_allocation_millis']<int((parse(v['qualification_anchor_utc'])+datetime.timedelta(milliseconds=v['qualification_original_total_millis'])-parse(v['control_model_issued_at_utc'])).total_seconds())*1000
v['assumption']=reason
model=mp/'FIXED185_ETA_MODEL_EXPLICIT_CONTROL_REVIEW6.json';save(model,v);save(mp/'MODEL_BINDING.json',b(model))
s=Path('/tmp/status185-current0100-explicit-review5-event-r1.py').read_text()
s=s.replace('current0100-explicit-control-review5-status-event-20261109-v1','current0200-phase-failure-explicit-control-review6-status-event-20261109-v1')
s=s.replace(str(previous),str(model)).replace(sha(previous),sha(model))
point='receipt=dict(schema='
assert s.count(point)==1
insert="""phase_failure=Path('/home/sol/.jetstreamer-private/first-lane-full-reader-witness-qualification-20261107-v1/current0200-20261109-v1/FRAME5-R4-capture-PHASE-EXECUTION.json')
phase_value=json.loads(phase_failure.read_bytes());assert phase_value['code']==1 and 'phase native identity/job/restart' in phase_value['stderr']
phase_outcome=Path('/home/sol/.jetstreamer-private/epoch185-positive-upstream-current0200-frame-capture-r4-20261109-v24/19-reader-start-phase-native-original-outcome.json')
pv=json.loads(phase_outcome.read_bytes());pn=dict(x.split('=',1) for x in bytes(pv['stdout_bytes']).decode().splitlines());assert pn['Id']=='horizon-guard145-prefix-shared72h-20261107-v8g1.service' and pn['ActiveState']=='activating' and pn['Job']=='41040174' and pn['NRestarts']=='0'
assert not Path('/var/lib/jetstreamer/horizon-recovered-resource-frames-20261029-v1/frame20261109T020022-witness-terminal145-chain128-v5.json').exists()
owner.update(current_task=m['assumption'],actual0200_capture_phase_failure=bound(phase_failure),actual0200_original_pending_guard_sample=bound(phase_outcome),complete_current_DATA_bytes=5164578583188,actual_review6_model=bound(modelpath),no_full_epoch_replay_started=True)
"""
s=s.replace(point,insert+point)
s=s.replace("assumption='Event reassessment: explicit reviewed90minute control replacement from SAME19:25:15 anchor inside unchanged original24h budget; qualified three successors but guard fixture/source-authority/freshnative gates outstanding. Full unexecuted replay/bootstrap/verification/delivery retained. No nativelease reset or resourcecredit.'", "assumption=m['assumption']")
source=mp/'status185-event0200-review6.py';save(source,s)
dest='/usr/local/lib/jetstreamer/horizon-status185-phase-event0200-review6-tools-20261109-v1'
plan=mp/'STATUS-SEAL-PLAN.json';save(plan,dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(source),name=source.name,sha256=sha(source),mode=0o444)]))
sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h=re.search("h='([a-f0-9]{64})'",Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1);assert sha(sealer)==h
os.umask(0o022);z=subprocess.run([sealer,str(plan),'--plan-sha256',sha(plan),'--self-sha256',h],capture_output=True,text=True);save(mp/'STATUS-SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));assert z.returncode==0,z.stderr
print(dest+'/'+source.name)
