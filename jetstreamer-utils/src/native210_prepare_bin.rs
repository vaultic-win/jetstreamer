//! Exact native210 preparation. Does not admit, launch, restore or contact R2.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod common;
use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
const TEST: &str = "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test";
const TEST_SHA: &str = "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon-210-native-main-guard-v1/jetstreamer-horizon-standalone-guard";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1";
const SNAPSHOT: &str = "snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst";
const SNAPSHOT_SHA: &str = "3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1";
const UNIT: &str = "archive-210-v1616-native-input-actual-v1.service";
const SELECTOR: &str =
    "runtime::native210_input::native_epoch210_cold_input_matches_canonical_accounts_commitment";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    harness: Bound,
    guard: Bound,
    singleton_preflight: Bound,
    output_directory: PathBuf,
}
fn validate_preflight(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-v1616-singleton-preflight-v1"
            && v["epoch"] == 210
            && v["bootstrap_slot"] == 90719638u64
            && v["output_slot_start"] == 90720000u64
            && v["output_slot_end_exclusive"] == 91152000u64
            && v["canonical_root_slots"] == json!([91151575u64])
            && v["post_root_slot_count"] == 424
            && v["manifest_fingerprint"]
                == "sha256:723578e0e7eef4daa09b68bb2a45263f61bcb19ce49daef094d3174ee1f65b6b"
            && v["snapshot_bindings_sha256"]
                == "877aeb63674523f1d4cc6937f993a57204bc39999e8e378ea84a6ac1ae5409a8"
            && v["retained_package"] == PACKAGE
            && v["runtime"] == "solana-v1.6.16"
            && v["snapshot_restored"] == false
            && v["worker_started"] == false
            && v["replay_entries"] == 0
            && v["candidate_only"] == true
            && v["full_epoch_replay_qualified"] == false
            && v["publication_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "210 preflight scope, roots or authority differs"
    );
    Ok(())
}
fn immutable_metadata(path: &Path, bytes: u64) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == bytes,
        "210 cached immutable input identity differs"
    );
    Ok(
        json!({"path":path,"bytes":bytes,"device":m.dev(),"inode":m.ino(),"mode":m.mode(),
        "mtime_seconds":m.mtime(),"mtime_nanoseconds":m.mtime_nsec()}),
    )
}
fn plan(harness: &Bound, guard: &Bound) -> Value {
    json!({"schema":"jetstreamer-private-epoch210-dormant-native-cold-plan-v1","epoch":210,"unit":UNIT,"run_root":ROOT,
        "native_main":{"executable":harness.path,"sha256":harness.sha256,"actual_main_pid_binding_required_before_guard_seal":true},
        "guard":{"executable":guard.path,"sha256":guard.sha256},
        "arguments":[SELECTOR,"--exact","--ignored","--test-threads=1","--nocapture"],
        "scratch":format!("{ROOT}/scratch"),"scratch_environment":"JETSTREAMER_EPOCH210_V1616_TEST_SCRATCH",
        "snapshot":{"path":Path::new(PACKAGE).join(SNAPSHOT),"bytes":8579041139u64,"sha256":SNAPSHOT_SHA,"slot":90719638u64,"expected_accounts_hash":"3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ"},
        "genesis":{"path":Path::new(PACKAGE).join("genesis.tar.bz2"),"bytes":20144,"sha256":GENESIS_SHA},
        "envelope":{"memory_high_bytes":112u64<<30,"memory_max_bytes":128u64<<30,"swap_max_bytes":0,"maximum_root_physical_bytes":300000000000u64,"maximum_worker_vmas":3500000,"cpu_quota_cores":8,"cpu_affinity":"0-7","tasks_max":512,"runtime_max_seconds":2700,"restart":"no","uid":1000,"gid":1000,"network":"AF_UNIX only"},
        "persistent_unit_file_required":true,"transient_systemd_run_is_not_the_deployment":true,
        "fresh_complete_fleet_admission_required":true,"preserve_all_guard_minimum_free_baselines":true,
        "registered_exact_invocation_and_mainpid_required":true,"guard_first_actual_sandboxed_fire_required":true,
        "approved_native_origin_and_central_fleet_claim_required":true,"status_phase":"verification","routine_minimum_interval_seconds":1800,
        "replay_entries":0,"entry_replay":false,"native_input_qualified":false,"host_job_launch_authorized":false,
        "replay_launch_authorized":false,"runtime_promotion_authorized":false,"full_epoch_qualified":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6 && a[2] == "--spec-sha256" && a[4] == "--self-sha256",
        "usage: PREPARER SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "210 preparation requires root"
    );
    common::bound_file(&env::current_exe()?, &a[5], 128 << 20, true)?;
    let s: Spec =
        serde_json::from_slice(&common::bound_file(Path::new(&a[1]), &a[3], 65536, true)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch210-native-preparation-spec-v1"
            && s.harness.path == Path::new(TEST)
            && s.harness.sha256 == TEST_SHA
            && s.guard.path == Path::new(GUARD)
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native210-preparation-")),
        "210 preparation spec scope differs"
    );
    common::bound_file(&s.harness.path, &s.harness.sha256, 128 << 20, true)?;
    common::bound_file(&s.guard.path, &s.guard.sha256, 128 << 20, true)?;
    let cli: Value = serde_json::from_slice(&common::bound_file(
        &s.singleton_preflight.path,
        &s.singleton_preflight.sha256,
        65536,
        true,
    )?)?;
    validate_preflight(&cli)?;
    let snapshot = immutable_metadata(&Path::new(PACKAGE).join(SNAPSHOT), 8579041139)?;
    common::bound_file(
        &Path::new(PACKAGE).join("genesis.tar.bz2"),
        GENESIS_SHA,
        20144,
        true,
    )?;
    let cold = plan(&s.harness, &s.guard);
    let cold_path = s.output_directory.join("native-cold-plan.json");
    common::write_receipt(&cold_path, &cold)?;
    let bytes = fs::read(&cold_path)?;
    let report = json!({"schema":"jetstreamer-private-epoch210-native-preparation-v1","epoch":210,
        "cold_plan":{"path":cold_path,"sha256":common::sha(&bytes)},"harness_sha256":s.harness.sha256,"guard_sha256":s.guard.sha256,
        "singleton_preflight":{"path":s.singleton_preflight.path,"sha256":s.singleton_preflight.sha256},"snapshot_metadata":snapshot,
        "snapshot_expected_sha256":SNAPSHOT_SHA,"snapshot_body_reread":false,"snapshot_body_rehash_required_by_native_test":true,
        "bootstrap_slot":90719638u64,"canonical_final_root":91151575u64,"output_slot_start":90720000u64,"output_slot_count":432000,"post_root_slot_count":424,
        "self_sha256":a[5],"spec_sha256":a[3],"resource_samples_taken":0,"services_changed":false,"worker_started":false,"snapshot_restored":false,
        "native_input_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    common::write_receipt(&s.output_directory.join("preparation.json"), &report)?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real210_preflight_cannot_borrow209_root_or_grant_native_authority() {
        let good: Value = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/native210/singleton-preflight.json"
        ))
        .unwrap();
        validate_preflight(&good).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut bad = good.clone();
            bad[key] = Value::Null;
            assert!(validate_preflight(&bad).is_err(), "{key}");
        }
        let mut bad = good;
        bad["epoch"] = json!(209);
        assert!(validate_preflight(&bad).is_err());
    }
}
