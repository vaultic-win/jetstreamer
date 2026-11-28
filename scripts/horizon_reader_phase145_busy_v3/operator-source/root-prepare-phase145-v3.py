from pathlib import Path
import os,json,hashlib,shutil
base=Path('/home/sol/.jetstreamer-private');old=base/'current-reader-phase199-recovery-qa-20261109-v2';p=base/'current-reader-phase145-busy-recovery-qa-20261109-v3';p.mkdir(mode=0o700)
sha=lambda f:hashlib.sha256(Path(f).read_bytes()).hexdigest();b=lambda f:dict(path=str(f),sha256=sha(f))
def save(f,v):
 raw=(json.dumps(v,indent=2)+'\n').encode() if not isinstance(v,str) else v.encode()
 fd=os.open(f,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'wb') as s:s.write(raw);s.flush();os.fsync(s.fileno())
 fd=os.open(f.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
prev=base/'current0200-guard-window-booking-20261109-v1/ROOT_NORMAL6_CURRENT0200_GUARD_DATA512_BOOKING.json';assert json.loads(prev.read_text())['complete_DATA_bytes']==5164578583188
book=dict(schema='horizon-normal6-advisory-phase145-busy-recovery-booking-v1',owner='/root',previous=b(prev),previous_retained_DATA_lower_bound_bytes=5164578583188,new_retained_DATA_bytes=536870912,complete_DATA_bytes=5165115454100,normal_pool_bytes=6<<30,extra_QA_bytes=0,one_serial_compiler_bytes=512<<20,all_prior_DATA_retained=True,no_replay_or_publication_authority=True)
save(p/'ROOT_NORMAL6_PHASE145_BUSY_DATA512_BOOKING.json',book)
shutil.copytree(old/'source',p/'source');(p/'qa/tmp').mkdir(parents=True,mode=0o700)
f=p/'source/reader_phase.rs';s=f.read_text();needle='fn query(r: &mut process::Runner'
i=s.index(needle)
helper='''fn known_primary_busy_guard(v: &Value, unit: &str) -> bool {
    unit == GUARD && v["Id"] == GUARD
        && matches!(v["ActiveState"].as_str(), Some("active" | "activating" | "deactivating"))
        && v["Job"].as_str().is_some_and(|x| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit()))
}
fn validate_query(v: &Value, unit: &str) -> Result<()> {
    ensure!(v["Id"] == unit && v["LoadState"] == "loaded"
        && v["NRestarts"].as_str().is_none_or(|x| x == "0")
        && (v["Job"] == "" || known_primary_busy_guard(v, unit)),
        "phase native identity/job/restart");
    Ok(())
}
'''
s=s[:i]+helper+s[i:]
a=s.index('    ensure!(\n        v["Id"] == unit',s.index(needle));z=s.index('    Ok(v)',a)
s=s[:a]+'    validate_query(&v, unit)?;\n'+s[z:]
s=s.replace('g["ActiveState"] == "failed"\n            && g["SubState"]', 'g["ActiveState"] == "failed"\n            && g["Job"] == ""\n            && g["SubState"]')
s+='''
#[cfg(test)] mod pending_primary_tests {
use super::*;
fn original() -> Value { serde_json::from_str(include_str!("original0200-pending145-sample.json")).unwrap() }
#[test] fn genuine0200_pending_primary_is_wait_only() { let v=original();assert!(validate_query(&v,GUARD).is_ok());assert!(terminal_guard(&v).unwrap().is_none()); }
#[test] fn pending_foreign_identity_restart_and_bad_jobs_reject() { for (k,x) in [("Id","foreign.service"),("LoadState","not-found"),("NRestarts","1"),("Job","bogus")] { let mut v=original();v[k]=json!(x);assert!(validate_query(&v,GUARD).is_err(),"{k}"); } let v=original();assert!(validate_query(&v,"jetstreamer-adaptive-reserve-epoch199-backfill-20261102-v1.service").is_err()); }
#[test] fn settled_pending_job_rejects_and_is_never_a_terminal_phase() { let mut v=original();v["ActiveState"]=json!("failed");v["SubState"]=json!("failed");assert!(validate_query(&v,GUARD).is_err());assert!(terminal_guard(&v).is_err()); }
#[test] fn settled_guard_still_requires_exact_clocks_and_empty_job() { let mut v=original();v["Job"]=json!("");v["ActiveState"]=json!("failed");v["SubState"]=json!("failed");v["Result"]=json!("exit-code");v["ExecMainCode"]=json!("1");v["ExecMainStatus"]=json!("1");v["MainPID"]=json!("0");v["ControlPID"]=json!("0");v["ControlGroup"]=json!("");v["ExecMainExitTimestampMonotonic"]=json!("100");assert!(validate_query(&v,GUARD).is_ok());assert_eq!(terminal_guard(&v).unwrap(),Some(100));assert!(!phase(100,100,30000100));assert!(phase(2000100,100,30000100));assert!(!phase(4000101,100,30000100));assert!(!phase(2000100,100,27000099)); }
}
'''
f.write_text(s)
raw=base/'epoch185-positive-upstream-current0200-frame-capture-r4-20261109-v24/19-reader-start-phase-native-original-outcome.json';r=json.loads(raw.read_text());g=dict(x.split('=',1) for x in bytes(r['stdout_bytes']).decode().splitlines());save(p/'source/original0200-pending145-sample.json',g)
v=json.loads((old/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json').read_text());v['recipes']={k:[x.replace(str(old),str(p)).replace('horizon-reader-phase199-','horizon-reader-phase145-busy-').replace('20261109-v2','20261109-v3') for x in a]for k,a in v['recipes'].items()};v['source']=[b(f)for f in sorted((p/'source').rglob('*'))if f.is_file()];v.update(actual_predecessor=b(old/'ROOT_ACTUAL_QUALIFIED_ADVISORY_PHASE199_BINDINGS.json'),actual_pending_sample=b(raw),booking=b(p/'ROOT_NORMAL6_PHASE145_BUSY_DATA512_BOOKING.json'),complete_DATA_bytes=5165115454100,primary_busy_wait_only=True,no_final_snapshot_or_original_clock_relaxation=True);save(p/'SOURCE_AND_EXACT4_FROZEN_RECIPES.json',v)
build=Path('/tmp/root-build-reader-phase199-exact-four-r2.py').read_text().replace(str(old),str(p));save(Path('/tmp/root-build-reader-phase145-exact-four-v3.py'),build)
print(p)
