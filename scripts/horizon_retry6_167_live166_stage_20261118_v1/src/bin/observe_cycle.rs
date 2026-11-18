//! Bind an accepted observation/status cycle and arm its one successor timer.
//! No replay, archive, admission or reservation-ending authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs::{self, File, OpenOptions}, io::Write, os::unix::fs::{OpenOptionsExt, PermissionsExt}, path::Path, process::Command};
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn sha(b: &[u8]) -> String { format!("{:x}", Sha256::digest(b)) }
fn bind(p: &str) -> Result<Value> { Ok(json!({"path":p,"sha256":sha(&fs::read(p)?)})) }
fn run(c: &mut Command) -> Result<String> { let o=c.output()?; ensure!(o.status.success(),"command {c:?}: {}",String::from_utf8_lossy(&o.stderr)); Ok(String::from_utf8(o.stdout)?) }
fn read(p: &str) -> Result<Value> { Ok(serde_json::from_slice(&fs::read(p)?)?) }
fn write(p: &str, v: &Value) -> Result<Value> {
    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o400).custom_flags(libc::O_NOFOLLOW).open(p)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;f.sync_all()?;File::open(Path::new(p).parent().context("parent")?)?.sync_all()?;bind(p)
}
fn clock_labels(stamp: &str) -> Result<(String,String)> {
    ensure!(stamp.len()==20 && stamp.is_ascii(),"canonical UTC clock required");
    for (i,b) in stamp.bytes().enumerate() {
        let separator=match i {4|7=>Some(b'-'),10=>Some(b'T'),13|16=>Some(b':'),19=>Some(b'Z'),_=>None};
        ensure!(separator.map_or_else(||b.is_ascii_digit(),|s|b==s),"invalid UTC clock");
    }
    ensure!((1..=12).contains(&stamp[5..7].parse::<u32>()?) && (1..=31).contains(&stamp[8..10].parse::<u32>()?)
        && stamp[11..13].parse::<u32>()?<24 && stamp[14..16].parse::<u32>()?<60 && stamp[17..19].parse::<u32>()?<60,"invalid clock fields");
    Ok((format!("{}{}{}",&stamp[..4],&stamp[5..7],&stamp[8..10]),format!("{}{}",&stamp[11..13],&stamp[14..16])))
}
fn main() -> Result<()> {
    ensure!(unsafe{libc::geteuid()}==0,"Root required");
    let a:Vec<_>=std::env::args().collect();
    ensure!(a.len()==5,"observe_cycle SAMPLE STATUS PREVIOUS_CONFIG PREVIOUS_FLEET");
    let sample=read(&a[1])?;let status=read(&a[2])?;
    ensure!(sample["schema"]=="jetstreamer-horizon-live-resource-sample-v2"
        && sample["cadence"]["routine_minimum_interval_enforced"]==true
        && sample["cadence"]["observed_interval_seconds"].as_u64().is_some_and(|v|v>=1800)
        && status["observer"]==bind(&a[1])? && status["authenticated_readback"]==true
        && status["authenticated_status_count"]==19,"accepted cycle required");
    let rows=sample["replays"].as_array().context("replays")?;
    ensure!(rows.len()==1 && rows[0]["range"]=="166" && rows[0]["invocation_binding_stable"]==true
        && rows[0]["producer_after"]["invocation_id"]=="03fa3ce80d8c4769a1e9dec548cdbeca"
        && rows[0]["producer_after"]["active_state"]=="active" && rows[0]["producer_after"]["restarts"]==0,"exact healthy166 required");
    let stamp=sample["recorded_at_utc"].as_str().context("stamp")?;
    let next=sample["cadence"]["next_routine_observation_not_before_utc"].as_str().context("next")?;
    let (date,tag)=clock_labels(stamp)?;
    let (next_date,next_tag)=clock_labels(next)?;
    ensure!(next>stamp,"successor clock must advance");
    let root=format!("/var/lib/jetstreamer/root{tag}-live166-observation-{date}-v1");
    fs::create_dir(&root)?;fs::set_permissions(&root,fs::Permissions::from_mode(0o700))?;
    let mut config=read(&a[3])?;
    ensure!(config["output"]==a[1] && config["minimum_interval_seconds"]==1800,"predecessor observer mismatch");
    config["previous_sample"]=json!(a[1]);config["not_before_utc"]=json!(next);
    config["output"]=json!(format!("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root{next_tag}-live166-{next_date}-v1.json"));
    let cpath=format!("{root}/next-observer.json");let cb=write(&cpath,&config)?;
    let destination=format!("/usr/local/lib/jetstreamer/horizon-live166-observer-config-{tag}-{date}-v1");
    let ppath=format!("{root}/seal-plan.json");
    let p=write(&ppath,&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":cpath,"name":"next-observer.json","sha256":cb["sha256"],"mode":292}]}))?;
    ensure!(sha(&fs::read(SEALER)?)==SEALER_SHA,"sealer changed");
    run(Command::new(SEALER).args([&ppath,"--plan-sha256",p["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
    let sealed=format!("{destination}/next-observer.json");
    let unit=format!("horizon-observer-root{next_tag}-live166-{next_date}-v1");
    let calendar=format!("{} {} UTC",&next[..10],&next[11..19]);
    run(Command::new("/usr/bin/systemd-run").args(["--unit",&unit,"--on-calendar",&calendar,"--timer-property=AccuracySec=1s",
        "--property=Type=oneshot","--property=CPUQuota=200%","--property=MemoryMax=2G","--property=TasksMax=128",
        "/usr/local/lib/jetstreamer/horizon-observer-exit-census-20261107-v1/jetstreamer-horizon-observe",&sealed]))?;
    let timer=run(Command::new("/usr/bin/systemctl").args(["show",&format!("{unit}.timer"),"-p","ActiveState","-p","SubState","-p","NextElapseUSecRealtime"]))?;
    ensure!(timer.lines().any(|l|l=="ActiveState=active") && timer.lines().any(|l|l=="SubState=waiting"),"successor timer not waiting");
    let mut fleet=read(&a[4])?;
    ensure!(fleet["owner"]=="/root" && fleet["live_replay_count"]==1,"predecessor fleet differs");
    fleet["previous_Root_operational_review"]=bind(&a[4])?;fleet["observer"]=bind(&a[1])?;
    fleet["authenticated_status_audit"]=bind(&a[2])?;fleet["sampled_at_utc"]=json!(stamp);
    fleet["sole_next_observer"]=bind(&sealed)?;fleet["same_sample_conservative_free_DATA_bytes"]=sample["filesystem"]["conservative_available_bytes"].clone();
    fleet["actual_executing_replays"][0]["observer"]=bind(&a[1])?;
    fleet["actual_executing_replays"][0]["progress"]=rows[0]["useful_work"].clone();
    for row in fleet["epochs"].as_array_mut().context("fleet epochs")? { row["current_coordinated_observer"]=bind(&a[1])?; }
    fleet["new_resource_observations"]=json!(false);fleet["replay_launch_authorized"]=json!(false);
    fleet["cycle_reconciliation_scope"]=json!("Same accepted observer and authenticated statuses; prior census/history retained explicitly; not fresh admission authority.");
    let audit_allocation="/var/lib/jetstreamer/r2-audit-additive-budget-20261118-v1/allocation.json";
    let audit_binding=bind(audit_allocation)?;
    ensure!(audit_binding["sha256"]=="f99e0d79b062a86f13d808eafed4cb4d53c7325c154934b0c2b59f4f78fa8a46","audit allocation changed");
    fleet["continuing_audit_obligation"]=json!({"allocation":audit_binding,
        "additional_memory_bytes":25769803776u64,"additional_cpu_quota_micros":4000000u64,
        "root_filesystem_archive_cap_bytes":17179869184u64,"DATA_reservation_bytes":0,
        "original_promises_ended":false,"fresh_native_observation_claimed":false,
        "admission_requirement":"The epoch167 launcher must revalidate the current audit image, invocation and cgroup limits, and add this full allocation to the preserved campaign commitments."});
    fleet["completed_snapshot183_retirement"]=bind("/var/lib/jetstreamer/snapshot183-private-retire-20261118-v1/target-0-completion.json")?;
    let mut completed_cleanup=Vec::new();
    for path in ["/var/lib/jetstreamer/snapshot152-private-retire-20261118-v1/target-0-completion.json",
        "/var/lib/jetstreamer/snapshot152-private-retire-20261118-v1/target-1-completion.json",
        "/var/lib/jetstreamer/horizon-dev-cache-check-sol-debug-retire-20261118-v2/completion.json",
        "/var/lib/jetstreamer/horizon-dev-cache-check-sol-release-deps-retire-20261118-v2/completion.json"] {
        let receipt=read(path)?;
        ensure!(receipt["r2_mutations"]==false && (receipt["cache_absent"]==true || (receipt["source_absent"]==true && receipt["quarantine_absent"]==true)),"cleanup completion missing");
        completed_cleanup.push(bind(path)?);
    }
    fleet["completed_cleanup_after_2249"]=json!(completed_cleanup);
    let custody141="/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-435e917094c39e05a8df2ac97cbba71e8470261112dcc2be30fdf56a013c0688.json";
    let custody=read(custody141)?;
    ensure!(custody["source"]=="/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2"
        && custody["sha256"]=="7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b"
        && custody["length"]==189943475031u64,"foreign epoch141 custody");
    fleet["completed_holding141_custody"]=bind(custody141)?;
    let retirement141="/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch141-completion.json";
    let retired=Path::new(retirement141).try_exists()?;
    if retired {
        let completion=read(retirement141)?;
        ensure!(completion["schema"]=="jetstreamer-holding-retire141-completion-v1"
            && completion["source_absent"]==true && completion["quarantine_absent"]==true
            && completion["authenticated_custody_revalidated"]==true
            && completion["retired_censused_physical_bytes"]==189943668736u64
            && completion["actual_free_delta_claimed"]==false && completion["r2_mutations"]==false,
            "epoch141 retirement incomplete");
        fleet["completed_holding141_retirement"]=bind(retirement141)?;
    }
    fleet["next_lane_recovery"]=json!({"epoch":167,"last_attempt_unit":"horizon-167-live166retry7-prepare-operation-2058-20261118-v1.service",
        "last_result":"complete166/167/169/170 growth does not fit","required_available_bytes":7493617796914u64,
        "holding_unit":"horizon-closed141-input-park-20261118-v1.service","credited_reclamation_bytes":0,
        "cache_check_result":"Both workspace caches and the two obsolete epoch152 snapshots have been retired with durable receipts. Admission must use actual measured free space, not summed cache-entry blocks.",
        "holding_custody_complete":true,"holding_local_retirement_complete":retired,
        "next_action":if retired {"Refresh epoch167 physical measurement and run fresh preparation and guarded launch including the audit allocation; use actual available bytes."}
            else {"Finish the qualified exact epoch141 local retirement after completed holding custody, then refresh epoch167 measurement and admission including the audit allocation."}});
    println!("{}",write(&format!("{root}/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),&fleet)?);
    println!("next_observer={sealed}; timer={unit}.timer; at={next}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::clock_labels;
    #[test]
    fn midnight_successor_uses_its_own_date() {
        assert_eq!(clock_labels("2026-11-18T23:49:25Z").unwrap(),("20261118".into(),"2349".into()));
        assert_eq!(clock_labels("2026-11-19T00:19:25Z").unwrap(),("20261119".into(),"0019".into()));
        for bad in ["2026/11/19T00:19:25Z","2026-11-19T24:19:25Z","2026-11-19T00:19:25+00:00",""] {
            assert!(clock_labels(bad).is_err());
        }
    }
}
