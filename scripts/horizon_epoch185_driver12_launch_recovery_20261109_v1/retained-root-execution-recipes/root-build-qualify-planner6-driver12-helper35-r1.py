from pathlib import Path
import json,os,hashlib,subprocess,shutil,re,datetime
base=Path('/home/sol/.jetstreamer-private');p=base/'epoch185-helper35-current-witness-planner-qa-20261109-v6';packet=Path('/tmp/planner6-driver12-helper35-source-20261109-v1');old=base/'epoch185-helper34-current-witness-planner-qa-20261108-v5';p.mkdir(mode=0o700)
sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 f=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(f,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 f=os.open(p,os.O_DIRECTORY);os.fsync(f);os.close(f)
previous=base/'epoch185-final6-postmain-fixed-deadline-qa-20261109-v1/ROOT_NORMAL6_FINAL6_DATA512_BOOKING.json';assert json.loads(previous.read_text())['complete_DATA_bytes']==5175316001428
save('ROOT_NORMAL6_PLANNER6_DATA512_BOOKING.json',dict(schema='horizon-normal6-planner6-helper35-booking-v1',owner='/root',previous=b(previous),previous_retained_DATA_lower_bound_bytes=5175316001428,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5175852872340,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=2<<30,ordinary_observer_bytes=2<<30,Root_and_status_bytes=2<<30,all_previous_source_and_DATA_promises_retained=True,no_replay_or_resource_credit=True))
shutil.copytree(packet/'source',p/'source');(p/'qa/tmp').mkdir(mode=0o700,parents=True);(p/'requests').mkdir(mode=0o700)
graph=json.loads((packet/'SOURCE_AND_EXACT4_RECIPES.NOT_EXECUTED.json').read_text());recipes=graph['recipes'];assert graph['proposed_QA_directory_not_created']==str(p)
for a in recipes.values():assert sum(x=='--extern'for x in a)==5 and str(p/'source/main.rs')in a
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',dict(schema='horizon-planner6-current-source-and-exact4-v1',source=[b(f)for f in sorted((p/'source').rglob('*'))if f.is_file()],recipes=recipes,extern_bindings=graph['extern_bindings'],actual_Driver12=graph['actual_Driver12'],actual_Helper35=graph['actual_Helper35'],source_handoff=b(packet/'HANDOFF.md'),source_candidate_graph=b(packet/'SOURCE_AND_EXACT4_RECIPES.NOT_EXECUTED.json'),booking=b(p/'ROOT_NORMAL6_PLANNER6_DATA512_BOOKING.json')))
executions=[];units=[]
def run(label,a,success=True):
 save(label+'-ORIGINAL-ARGV.json',a);print(datetime.datetime.now(datetime.timezone.utc).isoformat(),'BEGIN',label,flush=True);z=subprocess.run(a,capture_output=True,text=True,timeout=710);save(label+'-ORIGINAL-EXECUTION.json',dict(argv=a,code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-800:],z.stderr[-2200:],flush=True)
 if success:assert z.returncode==0,label
 else:assert z.returncode!=0 and any(s in z.stderr for s in ['role crossed','role/image/artifact mismatch','current full reader','reader role','helper normal seal','reader helper image']),label
 executions.append(b(p/(label+'-ORIGINAL-EXECUTION.json')))
 for x in a:
  if x.startswith('--unit='):units.append(x.split('=',1)[1]+'.service')
 return z
for label,a in recipes.items():run(label,a)
sealer='/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment';hs='e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3';assert sha(sealer)==hs;os.umask(0o022)
def seal(label,dest,files):
 save(label+'-SEAL-PLAN.json',dict(schema='jetstreamer-sealed-deployment-plan-v1',destination=str(dest),members=[dict(source=str(f),name=n,sha256=sha(f),mode=m)for f,n,m in files]));run(label+'-SEAL',[sealer,str(p/(label+'-SEAL-PLAN.json')),'--plan-sha256',sha(p/(label+'-SEAL-PLAN.json')),'--self-sha256',hs])
candidate=Path('/usr/local/lib/jetstreamer/horizon-positive185-planner6-metadata-control-candidate-20261109-v1');seal('CANDIDATE',candidate,[(p/'qa/planner','planner',0o555),(p/'qa/planner-tests','tests',0o555)])
a=json.loads((old/'ORDINARY-ORIGINAL-ARGV.json').read_text());a=[x.replace(str(old),str(p)).replace('horizon-positive185-planner5','horizon-positive185-planner6')for x in a];a=[str(candidate/'tests')if x==str(p/'qa/planner-tests')else x for x in a]
ordinary=run('ORDINARY',a);match=re.search(r'test result: ok\. (\d+) passed; 0 failed; (\d+) ignored;',ordinary.stdout);assert match and int(match[1])==32 and int(match[2])==0
h35=json.loads((base/'epoch185-driver12-consumer-helper-qa-20261109-v35/ROOT_ACTUAL_QUALIFIED_HELPER35_BINDINGS.json').read_text());role35=dict(image=h35['program'],artifact=h35['qualification'],normal_seal=h35['normal_seal']);template=json.loads((old/'requests/accepted-current-helper34.json').read_text());role34=template['native185_capture_role'];reader=template['full_reader_role'];positive=None
cases=['accepted-current-helper35','reject-historical-helper34','reject-current-path-old-sha','reject-old-path-current-sha','reject-prelaunch-as-native','reject-helper35-as-prelaunch','reject-old-artifact-current-image','reject-old-seal-current-image']
for case in cases:
 v=json.loads(json.dumps(template));v['generation']='planner6-2300-'+case;v['native185_capture_role']=json.loads(json.dumps(role35))
 if case=='reject-historical-helper34':v['native185_capture_role']=role34
 if case=='reject-current-path-old-sha':v['native185_capture_role']['image']['sha256']=role34['image']['sha256']
 if case=='reject-old-path-current-sha':v['native185_capture_role']['image']['path']=role34['image']['path']
 if case=='reject-prelaunch-as-native':v['native185_capture_role']=reader
 if case=='reject-helper35-as-prelaunch':v['full_reader_role']=role35
 if case=='reject-old-artifact-current-image':v['native185_capture_role']['artifact']=role34['artifact']
 if case=='reject-old-seal-current-image':v['native185_capture_role']['normal_seal']=role34['normal_seal']
 save('requests/'+case+'.json',v);f=p/'requests'/ (case+'.json');a=json.loads((old/'ACTUAL2300-ACCEPTED-CURRENT-HELPER34-ORIGINAL-ARGV.json').read_text());a=[x.replace(str(old),str(p)).replace('horizon-planner5-actual2300-accepted-current-helper34-control-20261108-v1','horizon-planner6-2300-'+case+'-20261109-v1').replace('/usr/local/lib/jetstreamer/horizon-positive185-planner5-metadata-control-candidate-20261108-v1/planner',str(candidate/'planner'))for x in a];a[a.index('plan-positive185')+1]=str(f);a[a.index('--request-sha256')+1]=sha(f);a[a.index('--self-sha256')+1]=sha(candidate/'planner');z=run('ACTUAL2300-'+case.upper(),a,success=case.startswith('accepted'))
 if case.startswith('accepted'):positive=json.loads(z.stdout)
assert positive and positive['admission_issued']is False and positive['full_epoch_route_qualified']is False
m=json.loads(Path(positive['metadata_plan']['path']).read_text());assert sha(positive['metadata_plan']['path'])==positive['metadata_plan']['sha256'];outputs={Path(x['path']).name:x for x in m['outputs']}
for x in m['outputs']:assert sha(x['path'])==x['sha256']
seq=json.loads(Path(outputs['FINITE_SEQUENCE_SOURCE_CONTRACT.json']['path']).read_text());assert seq['prelaunch_reader']==reader['image']and seq['native_capture']==seq['post_enrollment_reader']==h35['program'];assert not seq['executor_implemented']and seq['native_calls_performed']==0
for stage in seq['stages']:
 if 'operation'in stage:assert stage['operation']['program']==h35['program']
# Inspect all generated metadata as retained source material, never as admission.
root=Path(positive['metadata_plan']['path']).parent
selected=[]
for f in root.iterdir():
 if f.is_file():
  s=f.read_text();
  if 'horizon-epoch185-guarded-adapter-v12'in s:selected.append(f.name)
assert selected,'Driver12 absent from all positive outputs'
terminals=[]
for unit in units:
 n=dict(x.split('=',1)for x in subprocess.check_output(['systemctl','show',unit,'-pMainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job'],text=True).splitlines());assert n['MainPID']==n['ControlPID']==n['NRestarts']=='0'and n['Job']==n['ControlGroup']=='';terminals.append(dict(unit=unit,native=n))
proof=dict(schema='horizon-positive185-planner6-driver12-helper35-qualified-v1',production_artifact=b(p/'qa/planner'),actual_source_and_exact_recipes=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),ordinary_tests_passed=32,ignored_tests=0,all_four_compiler_stages_passed=True,prod_clippy_passed=True,test_clippy_passed=True,all_required_tests_passed=True,actual_Helper35=graph['actual_Helper35'],actual_Driver12=graph['actual_Driver12'],actual2300_positive=b(p/'ACTUAL2300-ACCEPTED-CURRENT-HELPER35-ORIGINAL-EXECUTION.json'),actual_metadata_controls=executions,actual_terminal_states=terminals,all_original_actors_terminal_and_drained=True,metadata_controls_are_not_fresh_admission=True,historical_driver11_constructor_retained=True,current_driver12_templates_selected=True,current_helper35_sequence_selected=True,prelaunch13_role_distinct=True,original_clocks_memory_DATA_and_prefix_scope_preserved=True,replay_launch_authorized=False,publication_authorized=False)
save('PRODUCTION-ORIGINAL-QUALIFICATION.json',proof);dest=Path('/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261109-v6');seal('PRODUCTION-NORMAL',dest,[(p/'qa/planner','planner',0o555),(p/'PRODUCTION-ORIGINAL-QUALIFICATION.json','artifact-proof.json',0o444),(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json','source-and-recipes.json',0o444)])
bind=dict(schema='horizon-actual-qualified-planner6-helper35-bindings-v1',program=b(dest/'planner'),qualification=b(dest/'artifact-proof.json'),normal_seal=b(dest/'deployment-seal-receipt.json'),source_and_recipes=b(dest/'source-and-recipes.json'),booking=b(p/'ROOT_NORMAL6_PLANNER6_DATA512_BOOKING.json'),actual_Helper35=graph['actual_Helper35'],actual_Driver12=graph['actual_Driver12'],actual2300_positive=b(p/'ACTUAL2300-ACCEPTED-CURRENT-HELPER35-ORIGINAL-EXECUTION.json'),all_eight_actual2300_metadata_controls_passed=True,complete_DATA_bytes=5175852872340,fresh_resource_and_admission_still_required=True);save('ROOT_ACTUAL_QUALIFIED_PLANNER6_BINDINGS.json',bind);print('PLANNER6_QUALIFIED',json.dumps(bind),flush=True)
