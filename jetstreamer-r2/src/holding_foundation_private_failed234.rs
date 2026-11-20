//! Exact closed v5 epoch234 partial: preserve bytes without canonical/resume authority.
use super::*;
use std::collections::BTreeMap;

pub(super) const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-234-general-shrink-debt-budget506-e3f15eb2-v5";
pub(super) const RELATIVE_SOURCE: &str = "state/destination-2f534eff3635f52231b3a1a967176ba8ba026469fbf6dbcfc7904a70d9c3985e/work/root-cohort-234-234/run-3988871-1793884339127858642/archives/epoch-234.jet";
pub(super) const PRODUCER: &str = "horizon-qualify-234-general-shrink-debt-budget506-e3f15eb2-v5.service";
const IID: &str = "42cd9e2dba644e3093f5479da3a3c917";
pub(super) const SHA: &str = "7fced40e968d470828abbe474096df017d60750e811aa6258dfe447d1165a931";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon234-failure909-status-event-v1/native-terminal.json";
const TERMINAL_SHA: &str = "08f113fb5f54494c50a1fa89cf89328be7ec18ed74b86c85011fbf3e78e970ea";
const RELEASE: &str = "/var/lib/jetstreamer/horizon234-terminal909-growth-release.json";
const RELEASE_SHA: &str = "9f0d3b5449ce16fe76ffdb1491da3ed13d9b0d5698b218c95cb3a97bc434ff5f";
const HASH: &str = "/var/lib/jetstreamer/horizon976-failed234-cleanup-candidate-Main-v1/hash/full-hash-success.json";
const HASH_SHA: &str = "e3a364d55ad860b89b303e3cd895e682c400354c49d8076c0256ea34d99dceb0";
const STATE_SHA: &str = "69fbe6fd5187b975f55778cf8ff0819b3b212e787c4bb25aac1f8a3f48aaa865";
const FINGERPRINT: &str = "sha256:3f0e03105ba1e6b166091d3519e1aea1f432d81e51044c3a35f49fb3e8991970";
const CLOSED_PEERS: [&str; 7] = [
    "horizon-234-general-shrink-debt-budget506-protective-v5.service",
    "horizon-234-general-shrink-debt-budget506-protective-v5.timer",
    "horizon-prepare-237-delivery-metadata895-v1.service",
    "horizon-publish-237-committed-v2.service",
    "horizon-publish-237-common-mount-probe-v2.service",
    "horizon-qualify-237-metadata-profile-control895-v1.service",
    "horizon-qualify-237-metadata-profile-control895-v2.service",
];

fn fixed(path: &str, sha: &str) -> Bound {
    Bound { path: path.into(), sha256: sha.into() }
}
fn bindings() -> [Bound; 3] {
    [fixed(TERMINAL, TERMINAL_SHA), fixed(RELEASE, RELEASE_SHA), fixed(HASH, HASH_SHA)]
}
pub(super) fn lineage_bindings() -> Value {
    json!({"original_failed_producer":fixed(TERMINAL,TERMINAL_SHA),
        "future_growth_reclassification_only":fixed(RELEASE,RELEASE_SHA),
        "closed_whole_file_hash":fixed(HASH,HASH_SHA)})
}
fn state_path() -> PathBuf {
    Artifact::FailedV5234.source().parent().unwrap().parent().unwrap().join("cohort-state.json")
}
fn state_stamp() -> Stamp {
    Stamp { device:66305, inode:15061978, length:222, uid:1000, gid:1000,
        mode:0o600, links:1, mtime_ns:1793884339126673695, ctime_ns:1793884339126673695 }
}
pub(super) fn closure_requirements(units: &BTreeMap<String,String>, original: &[Bound]) -> Result<()> {
    ensure!(units.get(PRODUCER).map(String::as_str)==Some(IID), "failed234 original producer IID differs");
    for unit in CLOSED_PEERS {
        ensure!(units.contains_key(unit), "failed234 exact guard or staged consumer omitted: {unit}");
    }
    for b in bindings() {
        ensure!(original.iter().filter(|x|x.path==b.path && x.sha256==b.sha256).count()==1,
            "failed234 exact failure/hash lineage missing or duplicated");
    }
    Ok(())
}
fn failed_terminal(v: &Value) -> bool {
    v["Id"]==PRODUCER && v["InvocationID"]==IID && v["ActiveState"]=="failed"
        && v["SubState"]=="failed" && v["Result"]=="exit-code" && v["ExecMainStatus"]=="1"
        && v["MainPID"]=="0" && v["ControlPID"]=="0" && v["NRestarts"]=="0"
        && v["Restart"]=="no" && v["Job"]=="" && v["ControlGroup"]==""
}
fn lineage_shape(terminal: &Value, release: &Value, hash: &Value) -> Result<()> {
    let a=Artifact::FailedV5234; let e=a.expected(); let file=&hash["file"];
    ensure!(failed_terminal(terminal) && failed_terminal(&release["terminal"])
        && release["schema"]=="horizon234-terminal-future-growth-release-v1"
        && release["Main_accepted_future_obligation_reclassification_only"]==true
        && release["failed_partial_archive_and_inputs_retained"]==true
        && release["original_PID_and_cgroup_closed"]==true
        && release["physical_storage_credit_bytes"]==0,
        "failed234 original terminal/future-only preservation lineage differs");
    ensure!(hash["schema"]=="horizon976-failed234-closed-partial-whole-hash-success-v1"
        && hash["sha256"]==SHA && hash["file_identity_unchanged"]==true
        && hash["hash_owner_stopped_and_cgroup_drained"]==true
        && hash["no_R2_mutation_or_local_retirement"]==true
        && hash["reservation_or_memory_credit_bytes"]==0
        && hash["actual_unit"]=="horizon-cleanup976-failed234-hash-v1.service"
        && hash["actual_invocation_id"]=="775e76268a894be89a02d56bc2b79156"
        && hash["actual_pid"]==674832 && hash["actual_terminal"]=="success0"
        && file["path"].as_str()==a.source().to_str()
        && file["device"]==e.device && file["inode"]==e.inode && file["logical_bytes"]==e.length
        && file["uid"]==e.uid && file["nlink"]==1 && hash["mode"]==e.mode && hash["gid"]==e.gid
        && file["mtime_ns"].as_i64().map(i128::from)==Some(e.mtime_ns)
        && file["ctime_ns"].as_i64().map(i128::from)==Some(e.ctime_ns)
        && hash["original_cohort_state"]["path"].as_str()==state_path().to_str()
        && hash["original_cohort_state"]["sha256"]==STATE_SHA,
        "failed234 whole hash is not the exact closed original partial");
    Ok(())
}
pub(super) fn preservation() -> Result<()> {
    let b=bindings();
    lineage_shape(&saved(&b[0])?, &saved(&b[1])?, &saved(&b[2])?)?;
    original_state()?;
    Ok(())
}
fn metadata_value(raw: &[u8]) -> Value {
    json!([{"name":"cohort-state.json","source_path":state_path(),"sha256":STATE_SHA,
        "length":raw.len(),"source_identity":state_stamp(),"uid":1000,"gid":1000,"mode":0o600,
        "raw_base64":BASE64_STANDARD.encode(raw)}])
}
pub(super) fn validate_metadata(v: &Value) -> Result<()> {
    let rows=v.as_array().context("failed234 raw cohort metadata array absent")?;
    ensure!(rows.len()==1, "failed234 requires exactly its original cohort metadata");
    let r=&rows[0];
    let raw=BASE64_STANDARD.decode(r["raw_base64"].as_str().context("failed234 raw cohort bytes absent")?)?;
    ensure!(r["name"]=="cohort-state.json" && r["source_path"].as_str()==state_path().to_str()
        && r["sha256"]==STATE_SHA && r["length"]==222 && raw.len()==222
        && hex_lower(&Sha256::digest(&raw))==STATE_SHA
        && r["source_identity"]==serde_json::to_value(state_stamp())?
        && r["uid"]==1000 && r["gid"]==1000 && r["mode"]==0o600,
        "failed234 raw cohort metadata normalized, substituted or given a source sidecar role");
    let value: Value=serde_json::from_slice(&raw)?;
    ensure!(value["schema"]=="jetstreamer-root-cohort-run-v1"
        && value["start_epoch"]==234 && value["end_epoch"]==234
        && value["manifest_fingerprint"]==FINGERPRINT && value["status"]=="running-private",
        "failed234 original stale run state must remain raw; it is not a resumable/complete checkpoint");
    Ok(())
}
fn original_state() -> Result<Value> {
    let p=state_path(); let m=fs::symlink_metadata(&p)?;
    ensure!(p.canonicalize()?==p && m.is_file() && Stamp::of(&m)==state_stamp(),
        "failed234 retained original cohort metadata identity changed");
    let before=regular_identity(&p)?;
    let raw=read_stable_bounded(&p,4096,"failed234 raw original cohort state")?;
    ensure!(regular_identity(&p)?==before && Stamp::of(&fs::symlink_metadata(&p)?)==state_stamp(),
        "failed234 cohort state changed during read");
    let value=metadata_value(&raw); validate_metadata(&value)?; Ok(value)
}
pub(super) fn metadata() -> Result<Value> {
    preservation()?;
    for suffix in [".sha256", ".segment.json"] {
        ensure!(retirement::absent(&PathBuf::from(format!("{}{suffix}",Artifact::FailedV5234.source().display())))?,
            "failed234 partial unexpectedly gained a source sidecar/segment");
    }
    original_state()
}
pub(super) fn manifest(v: &Value) -> Result<()> {
    ensure!(v["failed_v5_234_lineage"]==lineage_bindings(), "failed234 manifest changed original failed/hash lineage");
    preservation()?;
    validate_metadata(&v["raw_metadata"])
}

#[cfg(test)]
#[path = "holding_foundation_private_failed234_tests.rs"]
mod tests;
