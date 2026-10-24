//! Prepare exact227 v1.6.25 native metadata. No Bank, service, observation or R2 work.
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
const TEST: &str =
    "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner";
const TEST_SHA: &str = "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef";
const WORKER: &str = "/var/lib/jetstreamer/horizon-227-v1625-qualification-7a831420-v1/jetstreamer-historical-worker-v1-6-25";
const WORKER_SHA: &str = "7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a";
const GUARD: &str = if cfg!(feature = "epoch227-v1625-native-small") {
    "/var/lib/jetstreamer/horizon-227-v1625-native-small-main-guard-v2/jetstreamer-horizon-standalone-guard"
} else {
    "/var/lib/jetstreamer/horizon-227-v1625-native-main-guard-v1/jetstreamer-horizon-standalone-guard"
};
const INPUT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
const PREFLIGHT_SHA: &str = "6a7f2ec35ded81d3577a062db0b4ddddf64b8a812856173c7600fb75ce7dcf53";
const SNAPSHOT: &str = "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
const SNAPSHOT_SHA: &str = "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const ROOT: &str = if cfg!(feature = "epoch227-v1625-native-small") {
    "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-small-v2"
} else {
    "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-v1"
};
const UNIT: &str = if cfg!(feature = "epoch227-v1625-native-small") {
    "horizon-native-input-227-v1625-small-v2.service"
} else {
    "horizon-native-input-227-v1625-7a831420-v1.service"
};
const SCRATCH_BYTES: u64 = if cfg!(feature = "epoch227-v1625-native-small") {
    96_000_000_000
} else {
    300_000_000_000
};
const CENSUS: &str = "/var/lib/jetstreamer/horizon-native227-snapshot-census-actual-v1/census.json";
const CENSUS_SHA: &str = "6f5ec8b8f384bfb3531689fb0654b076c1febc1aad35058abf9398153bcd1a1f";
const CENSUS_BOUND: u64 = 77_949_771_776;
const SELECTOR: &str =
    "runtime::tests::native_epoch227_v1625_cold_input_matches_canonical_accounts_commitment";
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
    worker: Bound,
    preflight: Bound,
    output_directory: PathBuf,
}
fn spec_scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-private-epoch227-v1625-native-preparation-spec-v1"
            && s.harness.path == Path::new(TEST)
            && s.harness.sha256 == TEST_SHA
            && s.worker.path == Path::new(WORKER)
            && s.worker.sha256 == WORKER_SHA
            && s.guard.path == Path::new(GUARD)
            && common::is_sha(&s.guard.sha256)
            && s.preflight.path == Path::new(INPUT).join("preflight227-singleton.json")
            && s.preflight.sha256 == PREFLIGHT_SHA
            && s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native227-v1625-preparation-")),
        "227 v1625 native preparation fingerprint or output differs"
    );
    Ok(())
}
fn cold(guard: &Bound) -> Value {
    let mut value = json!({"schema":"jetstreamer-private-epoch227-v1625-dormant-native-cold-plan-v1","epoch":227,
        "unit":UNIT,"run_root":ROOT,"runtime":"solana-v1.6.25",
        "runtime_revision":"7de8a55b54d3e11058b82f9483bb405d143b455c",
        "native_main":{"executable":TEST,"sha256":TEST_SHA,"actual_main_pid_binding_required_before_guard_seal":true},
        "full_worker":{"executable":WORKER,"sha256":WORKER_SHA,"worker_started":false},
        "guard":{"executable":guard.path,"sha256":guard.sha256},
        "arguments":[SELECTOR,"--exact","--ignored","--test-threads=1","--nocapture"],
        "scratch":format!("{ROOT}/scratch"),"scratch_environment":"JETSTREAMER_EPOCH227_V1625_TEST_SCRATCH",
        "snapshot":{"path":Path::new(INPUT).join(SNAPSHOT),"bytes":10261480487u64,"sha256":SNAPSHOT_SHA,
            "slot":98063464u64,"expected_accounts_hash":"4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR"},
        "genesis":{"path":Path::new(INPUT).join("genesis.tar.bz2"),"bytes":20144,"sha256":GENESIS_SHA},
        "envelope":{"memory_high_bytes":112u64<<30,"memory_max_bytes":128u64<<30,"swap_max_bytes":0,
            "maximum_root_physical_bytes":SCRATCH_BYTES,"maximum_worker_vmas":3500000,
            "cpu_quota_cores":8,"cpu_affinity":"0-7","tasks_max":512,"runtime_max_seconds":2700,
            "restart":"no","uid":1000,"gid":1000,"network":"AF_UNIX only"},
        "persistent_unit_file_required":true,"transient_systemd_run_is_not_the_deployment":true,
        "fresh_complete_fleet_admission_required":true,"preserve_all_guard_minimum_free_baselines":true,
        "preserve_original_failed227_history":true,"original_v1620_proof_not_reused":true,
        "registered_exact_invocation_and_mainpid_required":true,"guard_first_actual_sandboxed_fire_required":true,
        "approved_native_origin_and_central_fleet_claim_required":true,"status_phase":"verification",
        "routine_minimum_interval_seconds":1800,"replay_entries":0,"entry_replay":false,
        "native_input_qualified":false,"host_job_launch_authorized":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"full_epoch_qualified":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    if cfg!(feature = "epoch227-v1625-native-small") {
        value["snapshot_census"] = json!({"path":CENSUS,"sha256":CENSUS_SHA});
        value["disk_envelope_model"] = json!({"formula":"2*dense_4096_rounded_file_bytes+metadata_allowance_bytes+1073741824",
            "modeled_bytes":CENSUS_BOUND,"maximum_root_physical_bytes":SCRATCH_BYTES,
            "bounded_experiment_only":true,"original_300gb_generation_preserved":true});
    }
    value
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6 && a[2] == "--spec-sha256" && a[4] == "--self-sha256",
        "usage: PREPARER SPEC --spec-sha256 SHA --self-sha256 SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "preparation requires root");
    common::bound_file(&env::current_exe()?, &a[5], 128 << 20, true)?;
    let s: Spec =
        serde_json::from_slice(&common::bound_file(Path::new(&a[1]), &a[3], 65536, true)?)?;
    spec_scope(&s)?;
    if cfg!(feature = "epoch227-v1625-native-small") {
        let census: Value = serde_json::from_slice(&common::bound_file(
            Path::new(CENSUS),
            CENSUS_SHA,
            16384,
            true,
        )?)?;
        ensure!(
            census["schema"] == "jetstreamer-native-readonly-snapshot-census-v1"
                && census["epoch"] == 227
                && census["snapshot_sha256"] == SNAPSHOT_SHA
                && census["census"]["twice_dense_plus_metadata_plus_one_gib_bytes"] == CENSUS_BOUND
                && census["snapshot_extracted"] == false
                && census["bank_constructed"] == false
                && census["native_execution_authorized"] == false
                && CENSUS_BOUND < SCRATCH_BYTES,
            "227 smaller generation lacks its exact snapshot envelope census"
        );
    }
    for b in [&s.harness, &s.guard, &s.worker, &s.preflight] {
        common::bound_file(&b.path, &b.sha256, 128 << 20, true)?;
    }
    let snapshot_path = Path::new(INPUT).join(SNAPSHOT);
    let m = fs::symlink_metadata(&snapshot_path)?;
    ensure!(
        snapshot_path.canonicalize()? == snapshot_path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == 10261480487,
        "retained227 snapshot metadata differs"
    );
    common::bound_file(
        &Path::new(INPUT).join("genesis.tar.bz2"),
        GENESIS_SHA,
        20144,
        true,
    )?;
    let plan_path = s.output_directory.join("native-cold-plan.json");
    common::write_receipt(&plan_path, &cold(&s.guard))?;
    let report = json!({"schema":"jetstreamer-private-epoch227-v1625-native-preparation-v1","epoch":227,
        "cold_plan":{"path":plan_path,"sha256":common::sha(&fs::read(&plan_path)?)},
        "harness_sha256":TEST_SHA,"full_worker_sha256":WORKER_SHA,"guard_sha256":s.guard.sha256,
        "preflight":{"path":s.preflight.path,"sha256":s.preflight.sha256},
        "snapshot_metadata":{"path":snapshot_path,"bytes":m.len(),"device":m.dev(),"inode":m.ino(),"mode":m.mode()},
        "snapshot_expected_sha256":SNAPSHOT_SHA,"snapshot_body_reread":false,
        "snapshot_body_rehash_required_by_native_test":true,"bootstrap_slot":98063464u64,
        "self_sha256":a[5],"spec_sha256":a[3],"resource_samples_taken":0,"services_changed":false,
        "worker_started":false,"snapshot_restored":false,"native_input_qualified":false,
        "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
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
    fn exact227_full_profile_and_zero_replay_authority_are_separate_from_diagnostic() {
        let mut s = Spec {
            schema: "jetstreamer-private-epoch227-v1625-native-preparation-spec-v1".into(),
            harness: Bound {
                path: TEST.into(),
                sha256: TEST_SHA.into(),
            },
            guard: Bound {
                path: GUARD.into(),
                sha256: "a".repeat(64),
            },
            worker: Bound {
                path: WORKER.into(),
                sha256: WORKER_SHA.into(),
            },
            preflight: Bound {
                path: Path::new(INPUT).join("preflight227-singleton.json"),
                sha256: PREFLIGHT_SHA.into(),
            },
            output_directory: "/var/lib/jetstreamer/horizon-native227-v1625-preparation-test"
                .into(),
        };
        spec_scope(&s).unwrap();
        let p = cold(&s.guard);
        assert_eq!(p["native_main"]["sha256"], TEST_SHA);
        assert_eq!(p["full_worker"]["sha256"], WORKER_SHA);
        assert_eq!(p["replay_entries"], 0);
        assert_eq!(p["envelope"]["memory_max_bytes"], 128u64 << 30);
        assert_eq!(p["envelope"]["maximum_root_physical_bytes"], SCRATCH_BYTES);
        if cfg!(feature = "epoch227-v1625-native-small") {
            assert_eq!(p["snapshot_census"]["sha256"], CENSUS_SHA);
            assert_eq!(p["disk_envelope_model"]["modeled_bytes"], CENSUS_BOUND);
            assert!(CENSUS_BOUND < SCRATCH_BYTES);
        } else {
            assert!(p.get("snapshot_census").is_none());
        }
        for flag in [
            "entry_replay",
            "native_input_qualified",
            "host_job_launch_authorized",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(p[flag], false, "{flag}");
        }
        s.harness.sha256 =
            "f9ca164d16ec78429293effeba083da122c1ae36c4de45ffc2ddba537b652400".into();
        assert!(spec_scope(&s).is_err());
        s.harness.sha256 = TEST_SHA.into();
        s.worker.sha256 = "d01adb1980ee52a59a7aff7a3a0496746ca325e5fc655817d9a7743a1913ef62".into();
        assert!(spec_scope(&s).is_err());
        s.worker.sha256 = WORKER_SHA.into();
        s.preflight.sha256 = "b".repeat(64);
        assert!(spec_scope(&s).is_err());
    }
}
