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
    ensure!(stamp.len()==20 && next.len()==20 && stamp.starts_with("2026-11-18T") && next.starts_with("2026-11-18T"),"Nov18 cycle only");
    let tag=format!("{}{}",&stamp[11..13],&stamp[14..16]);
    let next_tag=format!("{}{}",&next[11..13],&next[14..16]);
    ensure!(tag.bytes().chain(next_tag.bytes()).all(|b|b.is_ascii_digit()),"bad time label");
    let root=format!("/var/lib/jetstreamer/root{tag}-live166-observation-20261118-v1");
    fs::create_dir(&root)?;fs::set_permissions(&root,fs::Permissions::from_mode(0o700))?;
    let mut config=read(&a[3])?;
    ensure!(config["output"]==a[1] && config["minimum_interval_seconds"]==1800,"predecessor observer mismatch");
    config["previous_sample"]=json!(a[1]);config["not_before_utc"]=json!(next);
    config["output"]=json!(format!("/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-root{next_tag}-live166-20261118-v1.json"));
    let cpath=format!("{root}/next-observer.json");let cb=write(&cpath,&config)?;
    let destination=format!("/usr/local/lib/jetstreamer/horizon-live166-observer-config-{tag}-20261118-v1");
    let ppath=format!("{root}/seal-plan.json");
    let p=write(&ppath,&json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":cpath,"name":"next-observer.json","sha256":cb["sha256"],"mode":292}]}))?;
    ensure!(sha(&fs::read(SEALER)?)==SEALER_SHA,"sealer changed");
    run(Command::new(SEALER).args([&ppath,"--plan-sha256",p["sha256"].as_str().unwrap(),"--self-sha256",SEALER_SHA]))?;
    let sealed=format!("{destination}/next-observer.json");
    let unit=format!("horizon-observer-root{next_tag}-live166-20261118-v1");
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
    fleet["next_lane_recovery"]=json!({"epoch":167,"last_attempt_unit":"horizon-167-live166retry7-prepare-operation-2058-20261118-v1.service",
        "last_result":"complete166/167/169/170 growth does not fit","required_available_bytes":7493617796914u64,
        "holding_unit":"horizon-closed141-input-park-20261118-v1.service","credited_reclamation_bytes":0,
        "next_action":"Complete authenticated holding then exact local retirement and duplicate-cache cleanup before a fresh admission."});
    println!("{}",write(&format!("{root}/ROOT_COMPLETE_OPERATIONAL_FLEET.json"),&fleet)?);
    println!("next_observer={sealed}; timer={unit}.timer; at={next}");
    Ok(())
}
