from pathlib import Path
import json,os,hashlib,re,subprocess
base=Path('/home/sol/.jetstreamer-private');p=base/'epoch185-current0500-cold-failure-lifecycle-status-source-20261109-v1';p.mkdir(mode=0o700);sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest()
def save(n,v):
 raw=(json.dumps(v,indent=2)+'\n').encode() if not isinstance(v,str)else v.encode();fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb')as h:h.write(raw);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
s=Path('/usr/local/lib/jetstreamer/horizon-status185-review8-tools-20261109-v1/status.py').read_text().replace('current0430-explicit-control-review8-status-event-20261109-v1','current0500-cold-failure-lifecycle-status-event-20261109-v1')
point='receipt=dict(schema=';assert s.count(point)==1
insert="""live_unit='horizon-qualify-185-capped-cold-positive-positive-0500-20261109-next.service'
live_args=['systemctl','show',live_unit,'-pId,InvocationID,ActiveState,SubState,MainPID,ControlPID,ExecMainPID,NRestarts,ExecMainStartTimestamp,ControlGroup']
live_native=dict(x.split('=',1) for x in subprocess.check_output(live_args,text=True).splitlines())
assert live_native['InvocationID']=='722adc397ae24bb4b96d452783599f57' and live_native['MainPID']=='0' and live_native['ExecMainPID']=='3961564' and live_native['ControlPID']==live_native['NRestarts']=='0' and live_native['ActiveState']=='failed' and live_native['SubState']=='failed'
assert live_native['ExecMainStartTimestamp']=='Mon 2026-11-09 05:15:23 UTC'
lifecycle=Path('/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/722adc397ae24bb4b96d452783599f57/lifecycle.json');life=json.loads(lifecycle.read_bytes())
assert life['schema']=='horizon-epoch185-native-retained-lifecycle-v2' and life['actor_invocation_id']==live_native['InvocationID'] and life['released_actor']['pid']==3961564
assert life['publication_authorized'] is False and life['fresh_admission_authorized'] is False and life['resource_credit_bytes']==0
recovery=Path('/home/sol/.jetstreamer-private/epoch185-positive-final-control-722adc397ae24bb4b96d452783599f57/ROOT_MAIN_LIFECYCLE_CAPTURED_WITHOUT_ACTOR_RESTART.json');rc=json.loads(recovery.read_bytes());assert rc['no_signal_reset_replay_restart_or_clock_change'] and rc['lifecycle']==bound(lifecycle)
new['elapsed_execution_millis']=int((now-parse('2026-11-09T05:15:23Z')).total_seconds())*1000
assert new['elapsed_execution_millis']>=0
body=(json.dumps(new,sort_keys=True,separators=(',',':'))+'\\n').encode()
current_task='Actual0500 bounded185 Main started05:15:23 and exited1 at05:23:23 UTC in cold initialization. Final log: allocation census retry limit; no usage accepted: descendant disappeared during allocation census, under live unpacked/accounts. Exact IID722adc397ae24bb4b96d452783599f57/PID3961564 retained, zero restarts, MainPID and ControlPID now0. No canonical transaction progress observed; useful lanes0,target5. Root actively diagnoses Driver12 allocation census and prepares independent163 replacement. Helper35 lifecycle captured before failure; no restart, signal, deadline renewal or replay credit. Final6 wrapper had independently timed out05:15:45 after successful firstguard/token/Main and left worker running. Current0500 Frame/resources/Planner6/O38/H35 accepted; full185 parent route and publication still unqualified. MemoryPeak48GiB alone is not OOM evidence. All original Review8 model anchors, full unexecuted413404206ms/bootstrap1h/verification6h/delivery4h retained. DATA5177463485076 normal6GiB extraQA0. Other host epochs200-300 and protected199 unchanged.'
owner.update(current_task=current_task,actual_current_producer_invocation_id=live_native['InvocationID'],actual_current_producer_unit=live_unit,actual_current_producer_native=live_native,actual_lifecycle=bound(lifecycle),actual_same_original_main_recovery=bound(recovery),complete_current_DATA_bytes=5177463485076,phase='verification',bounded_native_initialization_active=False,actual0500_terminal_native=live_native,actual0500_failure_log=bound(Path('/home/sol/.jetstreamer-private/epoch185-cold-control-positive-positive-0500-20261109-next/private-stdout-stderr.log')),no_full_epoch_replay_started=True,elapsed_time_basis='Original current producer Main ExecMainStartTimestamp05:15:23, replacing prior Root-repair elapsed basis through authenticated handoff')
m['assumption']=current_task
"""
s=s.replace(point,insert+point)
s=s.replace("c.put_object(Bucket=bucket", "assert dict(x.split('=',1) for x in subprocess.check_output(live_args,text=True).splitlines())==live_native\nc.put_object(Bucket=bucket")
compile(s,'running-status','exec');save('status185-current0500-cold-failure.py',s)
dest='/usr/local/lib/jetstreamer/horizon-status185-current0500-cold-failure-tools-20261109-v1';save('SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=dest,members=[dict(source=str(p/'status185-current0500-cold-failure.py'),name='status.py',sha256=sha(p/'status185-current0500-cold-failure.py'),mode=0o444)]));sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';h=re.search("h='([a-f0-9]{64})'",Path('/tmp/arm-first-lane-observer1900.py').read_text()).group(1);assert sha(sealer)==h;os.umask(0o022);plan=p/'SEAL-PLAN.json';z=subprocess.run([sealer,str(plan),'--plan-sha256',sha(plan),'--self-sha256',h],capture_output=True,text=True);save('SEAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));assert z.returncode==0,z.stderr
print(dest+'/status.py')
