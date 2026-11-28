import pathlib,json,hashlib,os,subprocess,re,time,stat
BASE=pathlib.Path('/home/sol/.jetstreamer-private')
STATE=BASE/'epoch145-prefix-extract-shared72h-20261107-v8g1-state'
RUNTIME=BASE/'delivery145-next-source-20261107-v1/native-v8-source/root-runtime'
PLAN=pathlib.Path('/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json')
def bound(p):return {'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def native(unit):
 fields='Id,InvocationID,MainPID,ControlPID,ActiveState,SubState,Result,NRestarts,ExecMainStatus,Job'
 if unit.endswith('.timer'):fields+=',LoadState,Triggers,DropInPaths,TimersMonotonic'
 out={}
 for line in subprocess.check_output(['systemctl','show',unit,'--property='+fields],text=True).splitlines():
  k,v=line.split('=',1)
  if k=='TimersMonotonic':out[k]=out.get(k,'')+v+'\n'
  else:assert k not in out;out[k]=v
 return out

def armed_timer(v):
 assert v['InvocationID']=='f6f2308db2dc47be8f470030fb587b90' and v['LoadState']=='loaded' and v['ActiveState']=='active' and v['SubState'] in ['waiting','running'] and v['Job']==''
 assert v['Triggers']=='horizon-guard145-prefix-shared72h-20261107-v8g1.service' and v['DropInPaths']==''
 rows=v['TimersMonotonic'].splitlines()
 assert len(rows)==2 and sum(x.startswith('{ OnActiveUSec=1s ; next_elapse=') and x.endswith(' }') for x in rows)==1 and sum(x.startswith('{ OnUnitActiveUSec=30s ; next_elapse=') and x.endswith(' }') for x in rows)==1
 return v

def timer_same_as(first):
 armed_timer(first);last=armed_timer(native(first['Id']))
 assert {k:v for k,v in first.items() if k not in ['SubState','TimersMonotonic']}=={k:v for k,v in last.items() if k not in ['SubState','TimersMonotonic']},'Armed timer identity or definition changed'
 return True

def inspect_previous_running(now):
 plan=json.loads(PLAN.read_text());launch=json.loads((RUNTIME/'ROOT_ACTUAL_GUARD_BEFORE_SOURCE_AND_RUNNING_EXPORTER.json').read_text());ready=json.loads((STATE/'ready.json').read_text());admission=json.loads((STATE/'admission.json').read_text());before=json.loads((STATE/'guard-before-source-read.json').read_text())
 assert launch['plan']==ready['plan']==before['plan']==bound(PLAN)
 assert ready['admission']['sha256']==bound(STATE/'admission.json')['sha256'] and before['admission']==ready['admission']
 assert plan['program']['sha256']=='b416b7c932ef781c8d0f863b63b803379dd58cb1affe99dced6a61830a95ad76' and plan['minimum_available_memory_bytes']==642177138688 and plan['minimum_free_bytes']==5074152197938
 assert admission['required_initial_memory_bytes']<=plan['minimum_available_memory_bytes'] and admission['required_initial_data_bytes']<=plan['minimum_free_bytes']
 actor=native(plan['actor_unit']);timer=native(plan['timer_unit'])
 assert actor['InvocationID']==ready['actor_iid']=='f37b155136614e0183ba2e9adb8714ef' and actor['MainPID']==str(ready['actor_pid']) and actor['ControlPID']=='0' and actor['ActiveState']=='active' and actor['SubState']=='running' and actor['Result']=='success' and actor['NRestarts']=='0' and actor['Job']==''
 armed_timer(timer)
 m=STATE.lstat();assert STATE.resolve()==STATE and stat.S_ISDIR(m.st_mode) and m.st_uid==m.st_gid==0 and stat.S_IMODE(m.st_mode)==0o700 and {'device':m.st_dev,'inode':m.st_ino}==plan['state_directory_identity']
 logpath=RUNTIME/'actor.log';size=logpath.stat().st_size;assert size<=2<<20
 with logpath.open('rb') as f:raw=f.read(size)
 rows=[(int(a),int(z)) for a,z in re.findall(rb'heartbeat elapsed_seconds=(\d+)[^\n]*phase=2 charged_output_bytes=(\d+)',raw)]
 original_rate_evidence=None
 latest_status=max((q for q in (BASE/'r2-status-receipts').glob('epoch-145.status-correction-*.json') if re.fullmatch(r'epoch-145\.status-correction-\d{14}\.json',q.name)),key=lambda q:q.name)
 status=json.loads(latest_status.read_text());assert status['authenticated_readback'] and status['owner_evidence']['current_operator']=='/root'
 parts=dict(status['estimate_parts_millis'])
 validation_done=b'source validation completed; canonical432000-slot export and independent reread start' in raw
 if validation_done:parts['source_validation_millis']=0
 if len(rows)>=4:
  window=rows[-7:];dt=window[-1][0]-window[0][0];growth=window[-1][1]-window[0][1]
  assert dt>0 and growth>=0
  if dt>=180 and growth>0:
   remaining=max(0,plan['output_maximum_bytes']-window[-1][1]);millis=(remaining*dt*1500+growth-1)//growth
   key='private_canonical_export_from_original_measured_partial_rate_with25percent_contingency_millis'
   parts[key]=millis
   original_rate_evidence={'existing_same_invocation_heartbeat_window':window,'elapsed_window_seconds':dt,'charged_growth_bytes':growth,'output_budget_bytes':plan['output_maximum_bytes'],'remaining_budget_bytes':remaining,'allowance_percent':150,'not_a_resource_observation':True,'full_output_size_not_measured':True}
 canonical=pathlib.Path(plan['output_root'])/'epoch-145.jet';bytes_now=0
 if canonical.exists():
  cm=canonical.lstat();assert stat.S_ISREG(cm.st_mode) and cm.st_uid==0 and cm.st_nlink==1;bytes_now=cm.st_size
 owner={'current_operator':'/root','current_repair_owner':'/root','current_task':'The admitted v8 epoch145 exporter is actively processing the verified original source under genuine periodic guard. Preserve old source/failed partial and all resource floors; finish private export/reread then independent full/plugin/boundary/upload/readback gates.','current_internal_stage':'private-canonical-export-and-independent-reread' if validation_done else 'source-validation','current_phase':'verification','actual_active_exporter':actor,'actual_guard_timer':timer,'actual_exporter_start':{'ready_at_unix_seconds':ready['at_unix_seconds']},'repair_started_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(ready['at_unix_seconds'])),'actual_exporter_plan':bound(PLAN),'actual_admission':bound(STATE/'admission.json'),'actual_genuine_guard_before_source':bound(STATE/'guard-before-source-read.json'),'new_live_exporter_memory_cap_bytes':plan['actor_memory_bytes'],'new_live_exporter_guard_memory_cap_bytes':plan['guard_memory_bytes'],'new_live_exporter_memory_floor_bytes':plan['minimum_available_memory_bytes'],'new_live_exporter_DATA_floor_bytes':plan['minimum_free_bytes'],'original_source_and_failed_partial_preserved':True,'no_replay_lane_claimed':True}
 result={'owner':owner,'parts':parts,'elapsed_execution_millis':max(0,now-ready['at_unix_seconds'])*1000,'jet_size_bytes':bytes_now,'actor':actor,'timer':timer,'original_launch':bound(RUNTIME/'ROOT_ACTUAL_GUARD_BEFORE_SOURCE_AND_RUNNING_EXPORTER.json'),'plan':bound(PLAN),'rate_evidence':original_rate_evidence,'phase2_source_log_prefix':{'path':str(logpath),'captured_prefix_bytes':size,'captured_prefix_sha256':hashlib.sha256(raw).hexdigest()},'no_new_replay_or_resource_observation':True}
 assert native(plan['actor_unit'])==actor and timer_same_as(timer)
 return result

# Event-only terminal repair owner. Does not release any original reservation.
def inspect(now):
 event=pathlib.Path('/home/sol/.jetstreamer-private/actual043022-visible-root-acceptance-20261109-v1/ROOT_ORIGINAL145_TERMINAL_FAILURE_AND_NO_RELEASE.json')
 v=json.loads(event.read_bytes());actor=native(v['native']['Id']);assert all(value==v['native'][key] for key,value in actor.items())
 assert actor['MainPID']==actor['ControlPID']==actor['NRestarts']=='0' and actor['Result']=='exit-code' and actor['ExecMainStatus']=='74'
 review=json.loads(pathlib.Path('/home/sol/.jetstreamer-private/actual043022-visible-root-acceptance-20261109-v1/status-estimate-review043022.json').read_bytes())
 parts=dict(review['parts_by_epoch']['145'])
 prior=json.loads(pathlib.Path(review['latest_authenticated_status_by_epoch']['145']['path']).read_bytes())
 assert prior['authenticated_readback'] and prior['owner_evidence']['current_operator']=='/root'
 prior_at=int(time.mktime(time.strptime(prior['after_status']['sampled_at_utc'],'%Y-%m-%dT%H:%M:%SZ')))
 elapsed=max(0,(now-prior_at)*1000)
 assert all(type(x) is int and x>=0 for x in parts.values())
 original_total=sum(parts.values())
 assert original_total>elapsed, 'Prior planning arrival passed; explicit reassessment required'
 left=elapsed
 for key in ['uncertainty_contingency']+[k for k in parts if k!='uncertainty_contingency']:
  if key not in parts:continue
  consumed=min(parts[key],left);parts[key]-=consumed;left-=consumed
 assert left==0 and sum(parts.values())==original_total-elapsed and sum(parts.values())>0

 owner=review['owner_updates_by_epoch']['145'].copy()
 owner.update(current_operator='/root',current_repair_owner='/root',original_terminal_exporter=actor,no_live_exporter_claimed=True,no_replay_lane_claimed=True,original_failure_event=bound(event),memory_credit_bytes=0,DATA_credit_bytes=0)
 start=1794037462
 return dict(actor=actor,timer=armed_timer(native('horizon-guard145-prefix-shared72h-20261107-v8g1.timer')),owner=owner,parts=parts,jet_size_bytes=0,elapsed_execution_millis=max(0,(now-start)*1000),rate_evidence={'failed_original_exporter_not_a_live_rate':True},phase2_source_log_prefix={'terminal_failure':bound(event)})
