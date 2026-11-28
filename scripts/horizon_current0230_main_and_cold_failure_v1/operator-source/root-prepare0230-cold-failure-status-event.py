from pathlib import Path
import json,os,hashlib,re,subprocess
base=Path('/home/sol/.jetstreamer-private');p=base/'epoch185-current0230-cold-failure-status-source-20261109-v1';p.mkdir(mode=0o700);sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 raw=(json.dumps(v,indent=2)+'\n').encode() if not isinstance(v,str)else v.encode();fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb')as h:h.write(raw);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
s=Path('/usr/local/lib/jetstreamer/horizon-status185-phase-event0200-review6-tools-20261109-v1/status185-event0200-review6.py').read_text().replace('current0200-phase-failure-explicit-control-review6-status-event-20261109-v1','current0230-cold-failure-status-event-20261109-v1')
point='receipt=dict(schema=';assert s.count(point)==1
insert="""failed_unit='horizon-qualify-185-capped-cold-positive-positive-0230-20261109-next.service'
failed_args=['systemctl','show',failed_unit,'-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,ExecMainPID,NRestarts,ExecMainStartTimestamp,ExecMainExitTimestamp,ExecMainStatus,Result,ControlGroup,MemoryPeak']
failed_native=dict(x.split('=',1) for x in subprocess.check_output(failed_args,text=True).splitlines())
assert failed_native['InvocationID']=='da9b57fed9f04c9fa1b0c5dba1932488' and failed_native['MainPID']==failed_native['ControlPID']==failed_native['NRestarts']=='0' and failed_native['ActiveState']=='failed' and failed_native['SubState']=='failed' and failed_native['Result']=='exit-code' and failed_native['ExecMainStatus']=='1' and failed_native['ControlGroup']==''
assert failed_native['ExecMainStartTimestamp']=='Mon 2026-11-09 02:39:53 UTC' and failed_native['ExecMainExitTimestamp']=='Mon 2026-11-09 02:47:53 UTC'
log=Path('/home/sol/.jetstreamer-private/epoch185-cold-control-positive-positive-0230-20261109-next/private-stdout-stderr.log');logtext=log.read_text();assert 'No such file or directory (os error 2)' in logtext and '"event":"failure"' in logtext and '"phase":"cold initialization"' in logtext
new['elapsed_execution_millis']=int((now-parse('2026-11-09T02:39:53Z')).total_seconds())*1000
body=(json.dumps(new,sort_keys=True,separators=(',',':'))+'\\n').encode()
for stale_key in ['actual_current_producer_invocation_id','actual_current_producer_unit','actual_current_producer_native','bounded_native_initialization_active']:
 owner.pop(stale_key,None)
current_task='Actual0230 Main ran02:39:53..02:47:53 in coldinitialization and then exited1 with No such file or directory(os error2) after480814ms; no canonical/transaction progress observed. Nativeunitfailed andallMain/ControlPIDs0/cgroupempty, originalIIDda9b57fed9f04c9fa1b0c5dba1932488 retained. ReportednativeMemoryPeak48GiB is an observation, not an OOM diagnosis. Root active diagnosis must inspect exactworkerresult/driverfilesystempath and kernel/native evidence before changing runtime/memory. Bothfirstguard andsubsequentMainguards succeeded; lifecycle captured through qualifiedH34withoutactorrestart. No retry/restart/reset/clockextension; rawfailedworker/scratch/logs/promises preserved. Useful0target5. Root attempted fullparentbuild booking but its liveactorprerequisite rejected; no booking or compiler started. CanonicalDATA5165652325012normal6extraQA0. OriginalReview6/fullunexecutedreplay/bootstrap/verification/delivery remain; failedboundedwarmup grantsno fullreplay credit.'
owner.update(current_task=current_task,current_operator='/root',current_phase='verification',actual0230_failed_after_Main_native=failed_native,actual0230_closed_cold_initialization_failure_log=bound(log),complete_current_DATA_bytes=5165652325012,no_full_epoch_replay_started=True,resource_credit_bytes=0,elapsed_time_basis='Original0230Main02:39:53 with continuing Root recovery; failed producer is not represented as live')
m['assumption']=current_task
"""
s=s.replace(point,insert+point).replace("c.put_object(Bucket=bucket", "assert dict(x.split('=',1) for x in subprocess.check_output(failed_args,text=True).splitlines())==failed_native\nc.put_object(Bucket=bucket")
compile(s,'cold-failure-status','exec');save('status185-cold-failure.py',s)
dest='/usr/local/lib/jetstreamer/horizon-status185-current0230-cold-failure-tools-20261109-v1';save('SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(p/'status185-cold-failure.py'),name='status.py',sha256=sha(p/'status185-cold-failure.py'),mode=0o444)]));sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h=re.search("h='([a-f0-9]{64})'",Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1);assert sha(sealer)==h;os.umask(0o022);plan=p/'SEAL-PLAN.json';z=subprocess.run([sealer,str(plan),'--plan-sha256',sha(plan),'--self-sha256',h],capture_output=True,text=True);save('SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));assert z.returncode==0,z.stderr
