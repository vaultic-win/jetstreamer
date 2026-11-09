from pathlib import Path
import json,hashlib,os,subprocess,re,datetime
base=Path('/home/sol/.jetstreamer-private');Q=base/'first-lane-full-reader-witness-qualification-20261107-v1';p=Q/'current0430-20261109-v1';C=Q/'combined-runtime';sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def read(x):
 f=Path(x['path']);assert f.is_absolute()and f.resolve()==f and b(f)==x;return json.loads(f.read_text())
def save(root,name,v):
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(root,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
priorfile=p/'ROOT_ACTUAL_VALIDATED_HISTORICAL0230_AUTHORITY.json';prior=json.loads(priorfile.read_text());verification=json.loads((p/'ROOT_VALIDATE_HISTORICAL0230_AUTHORITY_EXECUTION.json').read_text());assert verification['code']==0 and json.loads(verification['stdout'])==prior
paths=dict(driver12=base/'epoch185-concurrent-storage-census-driver12-qa-20261109-v1/ROOT_ACTUAL_NORMALLY_SEALED_DRIVER12_BINDINGS.json',helper35=base/'epoch185-driver12-consumer-helper-qa-20261109-v35/ROOT_ACTUAL_QUALIFIED_HELPER35_BINDINGS.json',final6=base/'epoch185-final6-postmain-fixed-deadline-qa-20261109-v1/ROOT_ACTUAL_QUALIFIED_FINAL6_BINDINGS.json',planner6=base/'epoch185-helper35-current-witness-planner-qa-20261109-v6/ROOT_ACTUAL_QUALIFIED_PLANNER6_BINDINGS.json',operation38=base/'epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_QUALIFIED_OPERATION38_BINDINGS.json',guard0430=C/'current0430-window-20261109-v1/ROOT_ACTUAL_QUALIFIED_GUARD0430_BINDINGS.json')
roles={};proofs={};units={};executions={}
def add_execution(binding):
 e=read(binding);executions[binding['path']]=binding
 argv=e.get('argv',[])
 for a in argv:
  if isinstance(a,str)and a.startswith('--unit='):units.setdefault(a.split('=',1)[1].removesuffix('.service')+'.service',None)
 for stream in ['stdout','stderr']:
  for name in re.findall(r'Running as unit: ([A-Za-z0-9_.@-]+\.service)',e.get(stream,'')):units.setdefault(name,None)
 return e
for name,f in paths.items():
 r=json.loads(f.read_text());roles[name]=r;q=read(r['qualification']);proofs[name]=q;seal=read(r['normal_seal']);assert seal['schema']=='jetstreamer-sealed-deployment-receipt-v1'and seal['destination']==str(Path(r['program']['path']).parent)
 assert seal['replay_launch_authorized']is False and seal['publication_authorized']is False and seal['r2_mutations']is False
 assert len([x for x in seal['members']if x['name']==Path(r['program']['path']).name and x['sha256']==r['program']['sha256']and x['mode']=='0555'])==1
 assert len([x for x in seal['members']if x['name']=='artifact-proof.json'and x['sha256']==r['qualification']['sha256']and x['mode']=='0444'])==1
 image=q.get('production_artifact',q.get('production',q.get('artifact')));assert image['sha256']==r['program']['sha256'];assert q['all_required_tests_passed']and q['prod_clippy_passed']and q['test_clippy_passed']
 for row in q.get('originals',[]):
  if 'execution'in row:add_execution(row['execution'])
  native=row.get('original_native',row.get('actual_original_native',{}))
  if native.get('Id'):units[native['Id']]=native.get('InvocationID')or None
 for x in q.get('ordinary_and_native_originals',[]):assert add_execution(x)['code']==0
 for x in q.get('actual_metadata_controls',[]):add_execution(x)
 for row in q.get('actual_terminal_states',[]):units.setdefault(row['unit'],None)
 graphkey='actual_source_and_exact_recipes'if 'actual_source_and_exact_recipes'in q else 'exact_source_and_compiler_graph'if 'exact_source_and_compiler_graph'in q else None
 if graphkey:
  graph=read(q[graphkey])
  for a in graph['recipes'].values():
   for x in a:
    if x.startswith('--unit='):units.setdefault(x.split('=',1)[1]+'.service',None)
assert proofs['driver12']['ordinary_tests_passed']==37 and proofs['driver12']['finite_retry_attempts']==8
assert proofs['helper35']['ordinary_count']==2938 and proofs['helper35']['ignored_count']==126 and proofs['helper35']['actual_features']==['native210-small','native227-small']
assert proofs['final6']['ordinary_tests_passed']==38 and proofs['final6']['ignored_tests']==10 and proofs['final6']['all_ten_ignored_native_controls_passed']
assert proofs['planner6']['ordinary_tests_passed']==32 and proofs['planner6']['prelaunch13_role_distinct']
assert proofs['operation38']['ordinary_count']==71 and proofs['operation38']['ignored_native_count']==5 and proofs['operation38']['exact_successful0230_reader_retirement_qualified']
assert proofs['guard0430']['ordinary_tests_passed']==65 and proofs['guard0430']['sample_unix']==1794198622
books=[base/'epoch185-concurrent-storage-census-driver12-qa-20261109-v1/ROOT_NORMAL6_SERIAL2_DRIVER12_DATA4_BOOKING.json',base/'epoch185-driver12-consumer-helper-qa-20261109-v35/ROOT_FRESH_EXTRA_QA5_COMPILER8_DATA4_BOOKING.json',base/'epoch185-final5-postmain-driver12-qa-20261109-v1/ROOT_NORMAL6_FINAL5_DATA512_BOOKING.json',base/'epoch185-final6-postmain-fixed-deadline-qa-20261109-v1/ROOT_NORMAL6_FINAL6_DATA512_BOOKING.json',base/'epoch185-helper35-current-witness-planner-qa-20261109-v6/ROOT_NORMAL6_PLANNER6_DATA512_BOOKING.json',base/'epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_NORMAL6_OPERATION38_DATA512_BOOKING.json',base/'current0430-guard-window-booking-20261109-v1/ROOT_NORMAL6_CURRENT0430_GUARD_DATA512_BOOKING.json']
additions=list(prior['successor_additive_DATA_bookings']);total=prior['current_complete_DATA_lower_bound_bytes'];assert total==5165652325012
for f in books:
 d=json.loads(f.read_text());old=d.get('previous_retained_DATA_lower_bound_bytes',d.get('previous_complete_DATA_lower_bound_bytes'));assert old==total,(f,old,total);delta=d.get('new_retained_DATA_bytes',d.get('new_additive_retained_DATA_bytes',d.get('additional_retained_DATA_bytes')));assert delta in[512<<20,4<<30];total+=delta;assert d.get('complete_DATA_bytes',d.get('complete_DATA_lower_bound_bytes'))==total;assert str(f)not in{x['path']for x in additions};additions.append(b(f))
assert total==5176926614164
amount=lambda d:d.get('new_additive_retained_DATA_bytes',d.get('additional_retained_DATA_bytes',d.get('new_retained_DATA_bytes',0)))
assert 5133440070292+sum(amount(read(x))for x in additions)==total
retirementfile=base/'epoch185-operation38-driver12-helper35-qa-20261109-v1/ROOT_ACTUAL_EXACT0230_SUCCESSFUL_READER_RETIRED.json';retirement=json.loads(retirementfile.read_text());assert retirement['memory_credit_bytes']==retirement['DATA_credit_bytes']==0;assert add_execution(retirement['execution'])['code']==0;completed=read(retirement['result']['actual_successful_reader_retirement']);assert completed['resource_credit_bytes']==0 and completed['program']['sha256']==roles['operation38']['program']['sha256']
closure35=read(roles['helper35']['closure']);assert closure35['fresh_extra_QA5_bytes_after']==0 and closure35['normal_pool_bytes']==6<<30
acceptfile=p/'ROOT_GENUINE_CURRENT_CLI_V5_CAPTURE_ACCEPTED.json';accept=json.loads(acceptfile.read_text());assert accept['original_final_drains_pending']is False;frame=read(accept['frame']);assert frame['self_sha256']=='70b82a16f8c5d71257305a0873440deccf8746f78b09fc33ee23f5c691e29fe4'
outer=C/'REGRESSION_CURRENT0430_R2_genuine-current-outer_ORIGINAL_EXECUTION_V27.json';e=json.loads(outer.read_text());assert e['code']==0 and '1 passed; 0 failed;'in e['stdout'];add_execution(b(outer))
states=[]
for unit,expected_iid in sorted(units.items()):
 n=dict(x.split('=',1)for x in subprocess.check_output(['systemctl','show',unit,'-pId,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,ActiveState,SubState,Result,ExecMainStatus,Job'],text=True).splitlines());assert n['Id']==unit and n['MainPID']==n['ControlPID']==n['NRestarts']=='0'and n['ControlGroup']==n['Job']=='';assert n['ActiveState']not in['activating','deactivating']
 if expected_iid and n['InvocationID']:assert n['InvocationID']==expected_iid,(unit,'owner changed')
 cg=Path('/sys/fs/cgroup/system.slice')/unit;assert not cg.exists()or all(not x.read_text().strip()for x in cg.rglob('cgroup.procs'));states.append(n)
histclosure=C/'ROOT_HELPER27_CURRENT0430_HISTORICAL_BASE_NORMAL_POOL_REVALIDATED_CLOSURE.json';hc=json.loads(histclosure.read_text());assert hc['complete_DATA_bytes']==5165652325012 and hc['new_QA_memory_released_bytes']==0 and hc['all_original_QA_actors_terminal_and_drained']
new=dict(prior);new.update(schema='horizon-current0430-next-qualified-bindings-v1',predecessor_authority=b(priorfile),strict_historical_authority_execution=b(p/'ROOT_VALIDATE_HISTORICAL0230_AUTHORITY_EXECUTION.json'),operation=roles['operation38']['program'],qualification=roles['operation38']['qualification'],normal_seal=roles['operation38']['normal_seal'],planner=roles['planner6']['program'],planner_qualification=roles['planner6']['qualification'],planner_normal_seal=roles['planner6']['normal_seal'],postreader30=roles['helper35']['program'],postreader30_qualification=roles['helper35']['qualification'],postreader30_normal_seal=roles['helper35']['normal_seal'],final_executor=roles['final6']['program'],final_executor_qualification=roles['final6']['qualification'],final_executor_normal_seal=roles['final6']['normal_seal'],accepted_actor_driver=roles['driver12']['program'],qualified_route=roles['operation38']['qualified_route'],reader_lifecycle_control=roles['operation38']['reader_lifecycle_control'],successful_reader_retirement_control=roles['operation38']['successful_reader_retirement_control'],successor_additive_DATA_bookings=additions,current_complete_DATA_lower_bound_bytes=total,current_qualified_artifact_bindings={k:b(f)for k,f in paths.items()},actual_successful0230_reader_retirement=b(retirementfile),actual_guard0430_booking=b(books[-1]),actual_current0430_Frame_acceptance=b(acceptfile),actual_current0430_complete_outer=b(outer),helper35_QA_closure=roles['helper35']['closure'],new_memory_or_DATA_credit_bytes=0,replay_launch_authorized=False,full_boundary_route_qualified=False)
save(p,'ROOT_CURRENT0430_COMPLETE_QUALIFIED_SUCCESSOR_AUTHORITY.json',new)
closure=dict(hc);closure.update(schema='native163-full-reader-extra-QA6-closure-v1',historical_base_closure=b(histclosure),actual_current_successor_authority=b(p/'ROOT_CURRENT0430_COMPLETE_QUALIFIED_SUCCESSOR_AUTHORITY.json'),complete_DATA_bytes=total,new_QA_memory_released_bytes=0,required_final_qualifications=hc['required_final_qualifications']+[r['qualification']for r in roles.values()],actual_current_qualified_roles={k:b(f)for k,f in paths.items()},actual_current_additional_terminal_unit_census=states,actual_current_original_execution_records=list(executions.values()),actual_current0430_Frame_acceptance=b(acceptfile),actual_current0430_complete_outer=b(outer),actual_original0230_reader_retirement=b(retirementfile),actual_guard0430_qualification=roles['guard0430']['qualification'],actual_helper35_QA5_closure=roles['helper35']['closure'],current_metadata_qualification_only=True,no_replay_or_native_launch_authority=True)
save(C,'ROOT_HELPER27_CURRENT0430_NORMAL_POOL_REVALIDATED_CLOSURE.json',closure)
print('CURRENT0430_AUTHORITY_AND_NORMAL6_CLOSURE',len(states),'additional closed units; historical',len(hc['actual_terminal_unit_census']),'units retained; DATA',total,'no new resource credit',flush=True)
