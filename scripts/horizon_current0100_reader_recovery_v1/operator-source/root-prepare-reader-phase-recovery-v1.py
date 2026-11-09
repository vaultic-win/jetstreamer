from pathlib import Path
import os,json,hashlib,shutil,datetime
base=Path('/home/sol/.jetstreamer-private');p=base/'current-reader-phase199-recovery-qa-20261109-v1';p.mkdir(mode=0o700);(p/'source').mkdir(mode=0o700);(p/'qa').mkdir(mode=0o700);(p/'qa/tmp').mkdir(mode=0o700)
old=base/'epoch185-positive-current-operation36-planner5-qa-20261108-v1';sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(n,v):
 fd=os.open(p/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump(v,f,indent=2);f.flush();os.fsync(f.fileno())
 fd=os.open(p,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
previous=base/'current0100-guard-window-booking-20261109-v1/ROOT_NORMAL6_CURRENT0100_GUARD_DATA512_BOOKING.json';assert json.loads(previous.read_text())['complete_DATA_bytes']==5162431099540
save('ROOT_NORMAL6_PHASE199_DATA512_BOOKING.json',dict(schema='horizon-normal6-advisory-phase199-recovery-booking-v1',owner='/root',previous=b(previous),previous_retained_DATA_lower_bound_bytes=5162431099540,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5162967970452,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=512<<20,all_prior_DATA_retained=True,no_replay_or_publication_authority=True))
for f in (old/'source').iterdir():
 if f.is_file():shutil.copyfile(f,p/'source'/f.name)
main=p/'source/main.rs';s=main.read_text();needle='    let own = Bound {\n        path: fs::read_link("/proc/self/exe")?,\n';assert s.count(needle)==1
s=s.replace(needle,'    ensure!(["qualify-current-reader-start-phase", "read-current-original-between-guard-fires"].contains(&a[1].as_str()), "this image has advisory reader-phase scope only");\n'+needle);main.write_text(s)
f=p/'source/reader_phase.rs';s=f.read_text();assert s.count('(12000000..=14000000)')==1;s=s.replace('(12000000..=14000000)','(2000000..=4000000)').replace('v >= 15000000','v >= 25000000')
s=s.replace('assert!(phase(13000000, 0, 30000000));','assert!(phase(3000000, 0, 30000000));').replace('assert!(!phase(13000000, 0, 27000000));','assert!(!phase(3000000, 0, 27000000));')
needle='fn wait_phase(r: &mut process::Runner<\'_>) -> Result<Value> {';assert needle in s
extra='''fn retained199_phase(r: &mut process::Runner<'_>) -> Result<Value> {
    let gu="jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service";
    let ti="jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.timer";
    let g=query(r,gu)?;let t=query(r,ti)?;
    ensure!(g["ActiveState"]=="inactive"&&g["SubState"]=="dead"&&g["Result"]=="success"&&g["ExecMainStatus"]=="0"&&g["ExecMainCode"]=="1"&&g["MainPID"]=="0"&&g["ControlPID"]=="0"&&g["ControlGroup"]=="", "retained199 guard must be genuinely terminal successful");
    ensure!(t["InvocationID"]=="97aeff8897434ed5ad89dd56c3fb17d1"&&t["ActiveState"]=="active"&&t["SubState"]=="waiting"&&t["Unit"]==gu,"retained199 armed timer identity");
    let exit=text(&g,"ExecMainExitTimestampMonotonic")?.parse::<u64>()?;let next=span(text(&t,"NextElapseUSecMonotonic")?)?;
    ensure!(phase(mono()?,exit,next),"retained199 advisory quiet phase differs");
    let gg=query(r,gu)?;let tt=query(r,ti)?;ensure!(g==gg&&t==tt&&phase(mono()?,exit,next),"retained199 phase identity changed");
    Ok(json!({"guard":g,"timer":t,"exact_native_pair_preserved":true,"no_guard_or_timer_mutation":true,"quiet_phase_is_not_rollover_or_replay_authority":true}))
}
'''
s=s.replace(needle,extra+needle)
needle='                let evidence = json!({"schema"';assert needle in s
s=s.replace(needle,'                let retained199 = retained199_phase(r)?;\n'+needle)
s=s.replace('"guard":g,"timer":t,"actual_monotonic_usec":final_now','"guard":g,"timer":t,"retained199_advisory_phase":retained199,"actual_monotonic_usec":final_now')
needle='    let mut c = Command::new(&av[0]);';assert needle in s
s=s.replace(needle,'    ensure!(retained199_phase(r)? == evidence["retained199_advisory_phase"], "retained199 advisory phase changed before original reader");\n'+needle)
f.write_text(s)
graph=json.loads((old/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text());recipes={}
for label,a in graph['recipes'].items():
 a=[x.replace(str(old),str(p)).replace('horizon-positive185-current-operation-'+label+'-20261108-v36-helper34-planner5-r1','horizon-reader-phase199-'+label+'-20261109-v1') for x in a]
 recipes[label]=a
source=[b(x) for x in sorted((p/'source').iterdir()) if x.is_file()]
save('SOURCE_AND_EXACT4_FROZEN_RECIPES.json',dict(graph,source=source,recipes=recipes,predecessor=b(old/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json'),scope='ADVISORY prelaunch full-reader only; all assembly/admission/worker routes rejected at CLI. Reader13/Helper34/Planner5/Operation36 remain unchanged.',change_basis='0030comparison failed near retained199refire. Exact values not saved. Use early2-4s completed145 AND199 advisory phase,>=25s before nextfire, retaining original exactfullreader, oldfreshness and all equality/safety checks. No whole-reader fit or no-refire guarantee.',complete_DATA_bytes=5162967970452))
print(p)
