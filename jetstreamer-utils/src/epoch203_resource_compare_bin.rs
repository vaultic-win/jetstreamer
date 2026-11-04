//! Evidence-only comparison of the exact epoch 203 t16 and t1 bounded attempts.
//! This never selects a production route, changes resource claims or launches work.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

const BASELINE_SHA: &str = "55b04dfb7e32f7b3a902aaa1ee00d73d05524640cccafcf826ff53885cd99b90";
const WORKER_SHA: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const SNAPSHOT_SHA: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
const NODE_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
const CANDIDATE_RUNNER: &str = "c041979fa0be26f6a35cb7063e962a666e71ddde74b1f680c53c210a0f7b1722";
const CANDIDATE_PLAN: &str = "028f5eae11caa21cc7a9261b60fd253ea0cc512e1b7ee5c7c70751ebca85974e";
const BASELINE_INVOCATION: &str = "efbb040eaba2492f8cfd8976c00b37d5";
const CANDIDATE_INVOCATION: &str = "10a5df6a121f45f4be1874e9c696a603";
const TARGET: u64 = 87_720_000;
const CANDIDATE_PATH: &str =
    "/var/lib/jetstreamer/horizon-203-r1-bounded-outcome-20261020-v1/resource.json";
const STOP_PATH: &str =
    "/var/lib/jetstreamer/horizon-203-r1-bounded-outcome-20261020-v1/target-stop.json";
const CAPTURE_PATH: &str =
    "/var/lib/jetstreamer/horizon-203-r1-bounded-outcome-20261020-v1/target-capture.json";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    baseline_path: PathBuf,
    baseline_sha256: String,
    candidate_path: PathBuf,
    target_stop_sha256: String,
    target_capture_sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_sha(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_bound(path: &Path, sha: &str) -> Result<Vec<u8>> {
    ensure!(valid_sha(sha), "invalid SHA-256");
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 32 * 1024 * 1024,
        "unsafe or oversized evidence"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
        )
    };
    ensure!(
        identity(&before) == identity(&after)
            && identity(&after) == identity(&named)
            && digest(&bytes) == sha,
        "evidence identity or digest changed"
    );
    Ok(bytes)
}

fn number(v: &Value, name: &str) -> Result<u64> {
    v.as_u64()
        .with_context(|| format!("missing integer {name}"))
}

fn counter(text: &str, key: &str) -> Result<u64> {
    let mut found = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some(key) {
            ensure!(found.is_none(), "duplicate counter {key}");
            found = Some(words.next().context("counter value missing")?.parse()?);
            ensure!(words.next().is_none(), "malformed counter {key}");
        }
    }
    found.with_context(|| format!("counter {key} missing"))
}

#[derive(Debug, Serialize)]
struct Metrics {
    elapsed_millis: u64,
    observed_slot: u64,
    last_progress_slot: u64,
    first_progress_slot: u64,
    time_to_first_progress_millis: u64,
    progress_window_millis: u64,
    transactions: u64,
    account_updates: u64,
    physical_scratch_bytes: u64,
    scratch_files: u64,
    memory_peak_bytes: u64,
    memory_high_events: u64,
    progress_window_slots_per_second: f64,
    progress_window_transactions_per_second: f64,
    progress_window_account_updates_per_second: f64,
}

fn metrics(v: &Value, candidate: bool) -> Result<Metrics> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch203-bounded-resource-v1"
            && v["epoch"] == 203
            && v["target_slot"] == TARGET
            && v["success"] == true
            && v["target_reached"] == true
            && v["external_signal"] == 0
            && v.get("error") == Some(&Value::Null)
            && matches!(v["child_return_code"].as_i64(), Some(0 | 1)),
        "not a successful bounded controlled stop"
    );
    ensure!(
        v["worker_sha256"] == WORKER_SHA
            && v["snapshot_sha256"] == SNAPSHOT_SHA
            && v["node_sha256"] == NODE_SHA,
        "workload identity differs"
    );
    for key in [
        "ordinary_replay_authorized",
        "full_cold_epoch_peak_qualified",
        "publication_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v["authority"][key] == false, "unexpected authority {key}");
    }
    if candidate {
        ensure!(
            v["invocation_id"] == CANDIDATE_INVOCATION
                && v["runner_sha256"] == CANDIDATE_RUNNER
                && v["plan"]["sha256"] == CANDIDATE_PLAN
                && v["unit"] == "horizon-qualify-203-bounded-resource-r1-d10f455-v1.service"
                && v["solana_rayon_threads"] == 1,
            "not the exact single-thread attempt"
        );
    } else {
        // The exact legacy baseline digest pins its t16 build; that older
        // receipt predates the explicit thread-count field. No generic default.
        ensure!(
            v["invocation_id"] == BASELINE_INVOCATION
                && v["runner_sha256"]
                    == "bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12"
                && v["plan"]["sha256"]
                    == "afef9054bcd2da773e70c100a6941d2020c75db47c2c2fe1282ebfe01bd87a2f"
                && v["unit"] == "horizon-qualify-203-bounded-resource-store8-a72fd72-v1.service"
                && (v.get("solana_rayon_threads").is_none() || v["solana_rayon_threads"] == 16),
            "not the pinned t16 baseline"
        );
    }
    let observed = number(&v["observed_slot"], "observed slot")?;
    ensure!(
        (TARGET..=TARGET + 1000).contains(&observed),
        "target overshoot differs"
    );
    let first = &v["first_progress"];
    let last = &v["last_progress"];
    let first_slot = number(&first["slot"], "first slot")?;
    let last_slot = number(&last["slot"], "last slot")?;
    ensure!(
        (87_695_516..=87_697_000).contains(&first_slot)
            && (TARGET - 1000..=observed).contains(&last_slot),
        "progress coverage differs"
    );
    let delta = |key: &str| -> Result<u64> {
        let d = number(&last[key], key)?
            .checked_sub(number(&first[key], key)?)
            .context("progress reset")?;
        ensure!(d > 0, "empty progress delta");
        Ok(d)
    };
    let elapsed = number(&v["elapsed_millis"], "elapsed millis")?;
    let window = delta("elapsed_millis")?;
    ensure!(
        elapsed >= number(&last["elapsed_millis"], "last elapsed")? && elapsed <= 21_600_000,
        "invalid elapsed bound"
    );
    let cg = &v["capture"]["cgroup"];
    let events = cg["memory.events"]
        .as_str()
        .context("memory events missing")?;
    for key in ["max", "oom", "oom_kill", "oom_group_kill"] {
        ensure!(counter(events, key)? == 0, "memory safety event {key}");
    }
    let memory_peak: u64 = cg["memory.peak"]
        .as_str()
        .context("memory peak missing")?
        .trim()
        .parse()?;
    ensure!(
        memory_peak > 0 && memory_peak <= 96 << 30,
        "memory bound exceeded"
    );
    let physical = number(&v["capture"]["scratch"]["physical_bytes"], "scratch bytes")?;
    let files = number(&v["capture"]["scratch"]["regular_files"], "scratch files")?;
    ensure!(
        physical > 0 && physical <= 256 << 30 && files > 0,
        "scratch bound differs"
    );
    let rate = |key: &str| -> Result<f64> { Ok(delta(key)? as f64 * 1000.0 / window as f64) };
    Ok(Metrics {
        elapsed_millis: elapsed,
        observed_slot: observed,
        last_progress_slot: last_slot,
        first_progress_slot: first_slot,
        time_to_first_progress_millis: number(&first["elapsed_millis"], "first elapsed")?,
        progress_window_millis: window,
        transactions: number(&last["transactions"], "transactions")?,
        account_updates: number(&last["account_updates"], "account updates")?,
        physical_scratch_bytes: physical,
        scratch_files: files,
        memory_peak_bytes: memory_peak,
        memory_high_events: counter(events, "high")?,
        progress_window_slots_per_second: rate("slot")?,
        progress_window_transactions_per_second: rate("transactions")?,
        progress_window_account_updates_per_second: rate("account_updates")?,
    })
}

fn compare(b: &Metrics, c: &Metrics) -> Value {
    // Report observations, not a production selection or a full-prefix fit.
    json!({"schema":"jetstreamer-private-epoch203-resource-comparison-v1",
        "baseline":b,"candidate":c,
        "candidate_relative_to_baseline":{
            "elapsed":c.elapsed_millis as f64/b.elapsed_millis as f64,
            "physical_scratch":c.physical_scratch_bytes as f64/b.physical_scratch_bytes as f64,
            "scratch_files":c.scratch_files as f64/b.scratch_files as f64,
            "memory_peak":c.memory_peak_bytes as f64/b.memory_peak_bytes as f64,
            "progress_window_slots_per_second":c.progress_window_slots_per_second/b.progress_window_slots_per_second,
            "progress_window_transactions_per_second":c.progress_window_transactions_per_second/b.progress_window_transactions_per_second,
            "progress_window_account_updates_per_second":c.progress_window_account_updates_per_second/b.progress_window_account_updates_per_second},
        "limitations":["Same target permits at most 1000 slots overshoot; raw work totals and window boundaries are reported for interpretation.",
            "Progress-window rates start at the first progress marker, not a proven settling boundary, and are not equal-work windows; compare terminal capture and observed overshoot.",
            "No complete-prefix nonlinear peak, canonical checkpoint, plugin or restart qualification follows from a bounded comparison."],
        "authority":{"production_configuration_selected":false,"replay_launch_authorized":false,
            "full_cold_epoch_peak_qualified":false,"runtime_promotion_authorized":false,
            "publication_authorized":false,"canonical_sidecar_authorized":false,
            "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}})
}

fn validate_capture(result: &Value, stop: &Value, capture: &Value) -> Result<()> {
    ensure!(
        stop["schema"] == "jetstreamer-private-epoch203-canary-target-stop-v1"
            && stop["invocation_id"] == CANDIDATE_INVOCATION
            && stop["target_slot"] == TARGET
            && stop["observed_slot"] == result["observed_slot"]
            && stop["child_pid"] == result["child_pid"]
            && stop["child_pid"].as_u64().is_some_and(|pid| pid > 1)
            && stop["written_unix_seconds"].as_u64().is_some_and(|t| t > 0)
            && stop["scratch_snapshot_captured"] == true
            && stop["external_signal"] == 0
            && stop["capture_path"]
                == "/home/ubuntu/.jetstreamer-private/bounded-resource-203-r1-d10f455-v1/receipts/target-capture.json"
            && stop["capture_canonical_json_sha256"] == digest(&serde_json::to_vec(capture)?)
            && result["capture"] == *capture,
        "target-stop/capture/result binding differs"
    );
    Ok(())
}

fn run() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    ensure!(
        a.len() == 8
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && a[6] == "--candidate-sha256",
        "usage: jetstreamer-epoch203-resource-compare PLAN --plan-sha256 HEX --self-sha256 HEX --candidate-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "comparison requires root");
    ensure!(
        valid_sha(&a[5]) && digest(&fs::read("/proc/self/exe")?) == a[5],
        "self digest mismatch"
    );
    let p: Plan = serde_json::from_slice(&read_bound(Path::new(&a[1]), &a[3])?)?;
    ensure!(
        p.schema == "jetstreamer-private-epoch203-resource-comparison-plan-v2"
            && p.baseline_sha256 == BASELINE_SHA
            && p.candidate_path == Path::new(CANDIDATE_PATH),
        "plan differs from exact comparison"
    );
    let b = metrics(
        &serde_json::from_slice(
            &read_bound(&p.baseline_path, &p.baseline_sha256).context("baseline result binding")?,
        )?,
        false,
    )
    .context("baseline metrics")?;
    let candidate: Value = serde_json::from_slice(
        &read_bound(&p.candidate_path, &a[7]).context("candidate result binding")?,
    )?;
    let stop: Value =
        serde_json::from_slice(&read_bound(Path::new(STOP_PATH), &p.target_stop_sha256)?)?;
    let capture: Value = serde_json::from_slice(&read_bound(
        Path::new(CAPTURE_PATH),
        &p.target_capture_sha256,
    )?)?;
    validate_capture(&candidate, &stop, &capture)?;
    let c = metrics(&candidate, true).context("candidate metrics")?;
    let mut result = compare(&b, &c);
    result["evidence"] = json!({"plan":a[1],"plan_sha256":a[3],"comparator_sha256":a[5],
        "baseline_path":p.baseline_path,"baseline_sha256":p.baseline_sha256,
        "candidate_path":p.candidate_path,"candidate_sha256":a[7],
        "target_stop_path":STOP_PATH,"target_stop_sha256":p.target_stop_sha256,
        "target_capture_path":CAPTURE_PATH,"target_capture_sha256":p.target_capture_sha256});
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(candidate: bool) -> Value {
        json!({"schema":"jetstreamer-private-epoch203-bounded-resource-v1","epoch":203,"target_slot":TARGET,
            "success":true,"target_reached":true,"external_signal":0,"error":null,"child_return_code":1,
            "worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"node_sha256":NODE_SHA,
            "invocation_id":if candidate {CANDIDATE_INVOCATION}else{BASELINE_INVOCATION},
            "runner_sha256":if candidate {CANDIDATE_RUNNER}else{"bc9a75b420210a93b6ab65d28bd82d1fe2748c95541394bfae2e0f0f5153bf12"},
            "plan":{"sha256":if candidate {CANDIDATE_PLAN}else{"afef9054bcd2da773e70c100a6941d2020c75db47c2c2fe1282ebfe01bd87a2f"}},
            "unit":if candidate {"horizon-qualify-203-bounded-resource-r1-d10f455-v1.service"}else{"horizon-qualify-203-bounded-resource-store8-a72fd72-v1.service"},
            "solana_rayon_threads":if candidate {1}else{16},"observed_slot":TARGET,"elapsed_millis":7000000,
            "first_progress":{"slot":87696021,"transactions":250159,"account_updates":733740,"elapsed_millis":516807},
            "last_progress":{"slot":TARGET,"transactions":12123260,"account_updates":36897389,"elapsed_millis":6900000},
            "capture":{"scratch":{"physical_bytes":100000000000u64,"regular_files":500000},
                "cgroup":{"memory.peak":"85000000000","memory.events":"high 10\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"}},
            "authority":{"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"publication_authorized":false,
                "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"remote_mutations":false,"r2_mutations":false}})
    }
    #[test]
    fn exact_receipts_compare_without_selection_authority() {
        let b = metrics(&fixture(false), false).unwrap();
        let c = metrics(&fixture(true), true).unwrap();
        let r = compare(&b, &c);
        assert_eq!(r["candidate_relative_to_baseline"]["elapsed"], 1.0);
        assert!(
            r["authority"]
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == false)
        );
    }
    #[test]
    fn legacy_thread_default_is_only_for_exact_control() {
        let mut b = fixture(false);
        b.as_object_mut().unwrap().remove("solana_rayon_threads");
        metrics(&b, false).unwrap();
        let mut c = fixture(true);
        c.as_object_mut().unwrap().remove("solana_rayon_threads");
        assert!(metrics(&c, true).is_err());
    }
    #[test]
    fn changed_workload_or_owner_or_stop_is_rejected() {
        for (key, value) in [
            ("epoch", json!(225)),
            ("target_slot", json!(TARGET + 1)),
            ("worker_sha256", json!("a".repeat(64))),
            ("snapshot_sha256", json!("b".repeat(64))),
            ("node_sha256", json!("c".repeat(64))),
            ("invocation_id", json!("replacement")),
            ("solana_rayon_threads", json!(16)),
            ("success", json!(false)),
            ("target_reached", json!(false)),
            ("child_return_code", json!(2)),
            ("external_signal", json!(15)),
            ("error", json!("failed")),
            ("observed_slot", json!(TARGET + 1001)),
        ] {
            let mut c = fixture(true);
            c[key] = value;
            assert!(metrics(&c, true).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn unsafe_or_missing_memory_counters_are_rejected() {
        for events in [
            "max 1\noom 0\noom_kill 0\noom_group_kill 0\nhigh 0",
            "max 0\noom 1\noom_kill 0\noom_group_kill 0\nhigh 0",
            "max 0\noom 0\noom_kill 0\nhigh 0",
        ] {
            let mut c = fixture(true);
            c["capture"]["cgroup"]["memory.events"] = json!(events);
            assert!(metrics(&c, true).is_err());
        }
        assert!(counter("oom 0\noom 0", "oom").is_err());
    }
    #[test]
    fn progress_reset_and_zero_duration_are_rejected() {
        for key in ["slot", "transactions", "account_updates", "elapsed_millis"] {
            let mut c = fixture(true);
            c["last_progress"][key] = c["first_progress"][key].clone();
            assert!(metrics(&c, true).is_err());
        }
    }
    #[test]
    fn unexpected_authority_and_hard_bounds_are_rejected() {
        let mut c = fixture(true);
        c["authority"]["publication_authorized"] = json!(true);
        assert!(metrics(&c, true).is_err());
        let mut c = fixture(true);
        c["capture"]["scratch"]["physical_bytes"] = json!((256u64 << 30) + 1);
        assert!(metrics(&c, true).is_err());
        let mut c = fixture(true);
        c["capture"]["cgroup"]["memory.peak"] = json!(((96u64 << 30) + 1).to_string());
        assert!(metrics(&c, true).is_err());
    }
    #[test]
    fn lower_case_exact_digests_only() {
        assert!(valid_sha(BASELINE_SHA));
        assert!(!valid_sha(&BASELINE_SHA.to_uppercase()));
        assert!(!valid_sha("0"));
    }

    #[test]
    fn target_detection_and_progress_counters_are_separately_reported() {
        let mut c = fixture(true);
        c["last_progress"]["slot"] = json!(TARGET - 5);
        let m = metrics(&c, true).unwrap();
        assert_eq!(m.observed_slot, TARGET);
        assert_eq!(m.last_progress_slot, TARGET - 5);
        c["last_progress"]["slot"] = json!(TARGET - 1001);
        assert!(metrics(&c, true).is_err());
    }

    #[test]
    fn missing_error_or_noninteger_progress_is_not_success_evidence() {
        let mut c = fixture(true);
        c.as_object_mut().unwrap().remove("error");
        assert!(metrics(&c, true).is_err());
        for invalid in [json!(-1), json!("100"), json!(1.5), Value::Null] {
            let mut c = fixture(true);
            c["last_progress"]["transactions"] = invalid;
            assert!(metrics(&c, true).is_err());
        }
    }

    #[test]
    fn evidence_reader_rejects_relative_symlink_and_wrong_hash() {
        assert!(read_bound(Path::new("relative"), BASELINE_SHA).is_err());
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("input.json");
        fs::write(&path, b"{}").unwrap();
        let link = tmp.path().join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_bound(&link, &digest(b"{}")).is_err());
        assert!(read_bound(&path, BASELINE_SHA).is_err());
    }

    fn capture_fixture() -> (Value, Value, Value) {
        let mut r = fixture(true);
        r["child_pid"] = json!(123);
        let capture = r["capture"].clone();
        let stop = json!({"schema":"jetstreamer-private-epoch203-canary-target-stop-v1",
            "invocation_id":CANDIDATE_INVOCATION,"target_slot":TARGET,"observed_slot":TARGET,
            "child_pid":123,"written_unix_seconds":1792484241u64,
            "scratch_snapshot_captured":true,"external_signal":0,
            "capture_path":"/home/ubuntu/.jetstreamer-private/bounded-resource-203-r1-d10f455-v1/receipts/target-capture.json",
            "capture_canonical_json_sha256":digest(&serde_json::to_vec(&capture).unwrap())});
        (r, stop, capture)
    }

    #[test]
    fn sealed_copies_preserve_the_actual_pre_stop_capture_binding() {
        let (r, stop, capture) = capture_fixture();
        validate_capture(&r, &stop, &capture).unwrap();
    }

    #[test]
    fn changed_target_owner_child_or_capture_hash_is_rejected() {
        let (r, stop, capture) = capture_fixture();
        for (key, v) in [
            ("invocation_id", json!("replacement")),
            ("child_pid", json!(124)),
            ("observed_slot", json!(TARGET + 1)),
            ("target_slot", json!(TARGET + 1)),
            ("written_unix_seconds", json!(0)),
            ("scratch_snapshot_captured", json!(false)),
            ("external_signal", json!(15)),
            ("capture_path", json!("/other/capture.json")),
            ("capture_canonical_json_sha256", json!("a".repeat(64))),
        ] {
            let mut bad = stop.clone();
            bad[key] = v;
            assert!(
                validate_capture(&r, &bad, &capture).is_err(),
                "accepted {key}"
            );
        }
    }

    #[test]
    fn rehashed_but_different_capture_is_not_the_result_capture() {
        let (r, mut stop, mut capture) = capture_fixture();
        capture["scratch"]["physical_bytes"] = json!(1);
        stop["capture_canonical_json_sha256"] =
            json!(digest(&serde_json::to_vec(&capture).unwrap()));
        assert!(validate_capture(&r, &stop, &capture).is_err());
    }
}
