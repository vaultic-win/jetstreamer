from pathlib import Path
import os,json,hashlib,shutil,subprocess,datetime
base=Path('/home/sol/.jetstreamer-private');p=base/'epoch185-final6-postmain-fixed-deadline-qa-20261109-v1';p.mkdir(mode=0o700);packet=Path('/tmp/final6-postmain-fixed-deadline-source-20261109-v1');sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as h:json.dump(v,h,indent=2);h.flush();os.fsync(h.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
previous=base/'epoch185-final5-postmain-driver12-qa-20261109-v1/ROOT_NORMAL6_FINAL5_DATA512_BOOKING.json';assert json.loads(previous.read_text())['complete_DATA_bytes']==5174779130516
closure=base/'epoch185-driver12-consumer-helper-qa-20261109-v35/ROOT_FRESH_EXTRA_QA5_CLOSED_NORMAL6_DATA_RETAINED.json';assert json.loads(closure.read_text())['fresh_extra_QA5_bytes_after']==0
save('ROOT_NORMAL6_FINAL6_DATA512_BOOKING.json',dict(schema='horizon-normal6-final6-fixed-deadline-booking-v1',owner='/root',previous=b(previous),previous_retained_DATA_lower_bound_bytes=5174779130516,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5175316001428,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=512<<20,all_previous_source_and_DATA_promises_retained=True,actual_helper35_QA5_closure=b(closure),no_replay_or_resource_credit=True))
shutil.copytree(packet/'source',p/'source');(p/'work/tmp').mkdir(mode=0o700,parents=True)
recipes=json.loads((packet/'EXACT_FOUR_RECIPES.UNSTARTED.json').read_text())
for label,a in recipes.items():
 recipes[label]=[x.replace('20261109-v5-postmain','20261109-v6-fixed-deadline')if x.startswith('--unit=')else x for x in a];assert sum(x=='--extern'for x in recipes[label])==5;assert str(p/'source/main.rs')in recipes[label]
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',dict(schema='horizon-final6-fixed-deadline-source-and-four-v1',source=[b(f)for f in sorted((p/'source').rglob('*'))if f.is_file()],recipes=recipes,source_candidate=b(packet/'SOURCE_ONLY_MANIFEST.json'),booking=b(p/'ROOT_NORMAL6_FINAL6_DATA512_BOOKING.json'),actual_Driver12=b(base/'epoch185-concurrent-storage-census-driver12-qa-20261109-v1/ROOT_ACTUAL_NORMALLY_SEALED_DRIVER12_BINDINGS.json'),retained_final5_failure=b(packet/'RETAINED_FAILED_FINAL5_QUALIFICATION_BINDINGS.json'),material_22s_budget_vs_30s_guard_fit_limitation_preserved=True))
for label,a in recipes.items():
 save(label+'-ORIGINAL-ARGV.json',a);print(datetime.datetime.now(datetime.timezone.utc).isoformat(),'BEGIN',label,flush=True);z=subprocess.run(a,capture_output=True,text=True,timeout=330);save(label+'-ORIGINAL-EXECUTION.json',dict(code=z.returncode,stdout=z.stdout,stderr=z.stderr));print(label,z.returncode,z.stdout[-600:],z.stderr[-4500:],flush=True);assert z.returncode==0,label
save('ROOT_ALL_FOUR_COMPILERS_PASSED.json',dict(all_four_compilers_passed=True,source_and_exact_recipes=b(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),no_replay_or_publication_authority=True))
