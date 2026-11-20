//! Exact gated bootstrap-only epoch265 owner. No replay/publication authority.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch265-native-input-running-v1";
pub(super) const UNIT: &str = "horizon-265-native-input-20261119-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native265-protective-v1.service";
pub(super) const RETENTION: &str = "horizon-native265-terminal-retention.target";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/native-input265-selected-20261119-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input";
pub(super) const TEST_SHA: &str =
    "0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon265-native-guard-page-00bdb61a-20261119-v1/horizon265-native-guard";
pub(super) const GUARD_SHA: &str =
    "75d4703d13ae7a72a359299da01002798e37ebdd4085dcb4291cdaaf29df7842";
pub(super) const SNAPSHOT_SHA: &str =
    "04eb59e2dbbc2b0d4f1535741fa9d56794c32ad18e14c98df4fa76a5ae397641";
pub(super) const ACCOUNTS_HASH: &str = "Jo2p1i6wNNn71fwwkyoA6shEtYtovbqzVc6p2W16FzW";
pub(super) struct WorkerProfile {
    pub(super) path: &'static str,
    pub(super) sha256: &'static str,
    pub(super) backend: &'static str,
    pub(super) solana_commit: &'static str,
}
pub(super) const WORKER_PROFILE: WorkerProfile = WorkerProfile {
    path: WORKER,
    sha256: WORKER_SHA,
    backend: "solana-v1.7.15",
    solana_commit: "4892eb4e1ad278d5249b6cda8983f88effb3e98b",
};
pub(super) const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
pub(super) const WORKER_SHA: &str =
    "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
pub(super) const MEMORY: u64 = 128_000_000_000;
pub(super) const SCRATCH: u64 = 506_191_984_640;
pub(super) fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("265 number {k}"))
}
pub(super) fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("265 string {k}"))
}
pub(super) fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn binding(v: &Value) -> Result<BoundFile> {
    Ok(serde_json::from_value(v.clone())?)
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-cold-snapshot-verification" && unit == UNIT
}
pub(super) fn command() -> String {
    format!("{{ path={TEST} ; argv[]={TEST}")
}
pub(super) fn no_authority(v: &Value) -> Result<()> {
    native210::no_authority(v)
}
pub(super) fn deny(v: &mut Value) {
    for k in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[k] = json!(false);
    }
}
pub(super) fn namespace(path: &Path, prefix: &str, leaf: &str) -> Result<()> {
    ensure!(
        path.file_name().and_then(|s| s.to_str()) == Some(leaf)
            && path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(prefix)),
        "265 namespace differs"
    );
    Ok(())
}
pub(super) fn sealed(b: &BoundFile) -> Result<Value> {
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer") && b.path.canonicalize()? == b.path,
        "265 sealed namespace"
    );
    for p in b.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "265 evidence ancestor changed"
        );
    }
    native210::immutable_json(b)
}
/// Production uses only FsEvidence. Tests supply the same digest-bound graph without
/// requiring privileged writes into the deployment namespace.
pub(super) trait EvidenceReader {
    fn json(&self, b: &BoundFile, immutable: bool) -> Result<Value>;
    fn bytes(&self, b: &BoundFile, maximum: u64) -> Result<Vec<u8>>;
    fn canonical(&self, p: &Path) -> Result<PathBuf>;
}
pub(super) struct FsEvidence;
impl EvidenceReader for FsEvidence {
    fn json(&self, b: &BoundFile, immutable: bool) -> Result<Value> {
        if immutable { sealed(b) } else { bound_json(b) }
    }
    fn canonical(&self, p: &Path) -> Result<PathBuf> {
        Ok(p.canonicalize()?)
    }
    fn bytes(&self, b: &BoundFile, maximum: u64) -> Result<Vec<u8>> {
        ensure!(
            b.path.starts_with("/var/lib/jetstreamer") && b.path.canonicalize()? == b.path,
            "265 byte evidence namespace"
        );
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
            "265 byte evidence custody"
        );
        for p in b.path.ancestors().skip(1) {
            let m = fs::symlink_metadata(p)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "265 byte evidence parent"
            );
        }
        let bytes = read_stable_bounded(&b.path, maximum, "265 immutable byte evidence")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == b.sha256,
            "265 byte evidence digest"
        );
        Ok(bytes)
    }
}
pub(super) fn prestart_values(q: &Value, review: &Value, source: &Value) -> Result<()> {
    ensure!(
        review["schema"] == "horizon-native265-current-fleet-review-v1"
            && review["epoch"] == 265
            && review["Main_accepted"] == true,
        "265 startup review scope differs"
    );
    no_authority(review)?;
    no_authority(q)?;
    let launchers = source["artifacts"]
        .as_array()
        .context("265 published artifacts")?
        .iter()
        .filter(|r| r["role"] == "launcher")
        .collect::<Vec<_>>();
    ensure!(
        launchers.len() == 1,
        "265 exact launcher provenance missing/ambiguous"
    );
    let artifact = binding(&launchers[0]["artifact"])?;
    ensure!(
        artifact.path.starts_with("/var/lib/jetstreamer"),
        "265 launcher artifact namespace"
    );
    let sha = artifact.sha256.as_str();
    ensure!(hex(sha, 64), "265 launcher artifact digest");
    ensure!(
        q["schema"] == "horizon-native265-prestart-qualification-v1"
            && q["harness"] == json!({"path":TEST,"sha256":TEST_SHA})
            && q["guard"] == json!({"path":GUARD,"sha256":GUARD_SHA})
            && q["guard"] == review["guard"]
            && q["source_publication"] == review["source_publication"]
            && q["observer_complete_tuple_accepted"] == true
            && q["fleet_running_and_terminal_accepted"] == true
            && q["inactive_status_exact_owner_accepted"] == true
            && q["terminal_retention_accepted"] == true
            && q["pre_restore_gate_tests_accepted"] == true
            && q["actual_first_guard_required_before_snapshot"] == true
            && q["actual_native_startup_qualified"] == false
            && q["launcher_artifact_sha256"] == sha,
        "265 prestart qualification differs from published launcher"
    );
    Ok(())
}
fn checked(c: &PipelineClaim, r: &Value) -> Result<()> {
    ensure!(
        c.epoch == 265
            && scope(&c.phase, &c.unit)
            && hex(&c.invocation_id, 32)
            && c.expected_exec_start.split(" ; ignore_errors=").next() == Some(command().as_str())
            && r["schema"] == SCHEMA
            && r["epoch"] == 265
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["private_run_root"] == ROOT
            && r["test_sha256"] == TEST_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["bootstrap_slot"] == 114_479_281u64
            && r["accounts_hash"] == ACCOUNTS_HASH
            && r["maximum_memory_bytes"] == MEMORY
            && r["maximum_scratch_bytes"] == SCRATCH
            && r["resource_samples_taken"] == 0
            && r["replay_entries"] == 0
            && r["native_input_qualified"] == false
            && r["ordinary_replay_claim"] == false
            && r["public_sidecar_countdown_authorized"] == true
            && num(r, "main_pid")? > 1
            && num(r, "main_pid")? <= i32::MAX as u64
            && num(r, "recorded_unix_seconds")? == utc_seconds(text(r, "sampled_at_utc")?)?,
        "265 closed running origin differs"
    );
    no_authority(r)
}
/// Validate immutable launch evidence historically, without restarting the clock.
pub(super) fn startup(hb: &BoundFile) -> Result<(Value, Value)> {
    startup_read(hb, &FsEvidence)
}
pub(super) fn startup_read(hb: &BoundFile, reader: &impl EvidenceReader) -> Result<(Value, Value)> {
    namespace(
        &hb.path,
        "horizon-native265-execution-",
        "guarded-startup-handoff.json",
    )?;
    let h = reader.json(hb, true)?;
    no_authority(&h)?;
    let iid = text(&h, "invocation_id")?;
    let pid: u32 = num(&h, "main_pid")?.try_into()?;
    ensure!(
        h["schema"] == "horizon-native265-guarded-startup-v1"
            && h["unit"] == UNIT
            && hex(iid, 32)
            && pid > 1
            && h["native_input_qualified"] == false,
        "265 handoff differs"
    );
    let pb = binding(&h["startup_plan"])?;
    namespace(&pb.path, "horizon-native265-startup-plan-", "plan.json")?;
    let p = reader.json(&pb, true)?;
    let a = reader.json(&binding(&h["admission"])?, true)?;
    no_authority(&a)?;
    ensure!(
        p["schema"] == "horizon-native265-startup-plan-v1"
            && p["epoch"] == 265
            && p["unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["worker_root"] == ROOT
            && p["bootstrap_slot"] == 114_479_281u64
            && p["snapshot_sha256"] == SNAPSHOT_SHA
            && p["maximum_memory_bytes"] == MEMORY
            && p["maximum_root_physical_bytes"] == SCRATCH
            && p["harness"] == json!({"path":TEST,"sha256":TEST_SHA})
            && p["guard"] == json!({"path":GUARD,"sha256":GUARD_SHA})
            && p["token_root"] == "/var/lib/jetstreamer/horizon-native265-startup-tokens"
            && p["admission"] == h["admission"]
            && a["schema"] == "horizon-native265-current-fleet-admission-v1"
            && a["epoch"] == 265
            && a["mode"] == "native-cold"
            && a["unit"] == UNIT
            && a["private_run_root"] == ROOT
            && a["maximum_memory_bytes"] == MEMORY
            && a["candidate_incremental_peak_bytes"] == SCRATCH
            && a["protected_existing_floor_bytes"] == p["minimum_free_bytes"]
            && num(&p, "minimum_free_bytes")? > 0
            && a["harness"] == p["harness"]
            && a["guard"] == p["guard"]
            && a["boot_id"] == p["boot_id"]
            && a["admitted"] == true,
        "265 startup/admission pins differ"
    );
    for key in [
        "source_publication",
        "observer",
        "fleet",
        "review",
        "reservation_ledger",
    ] {
        binding(&a[key])?;
    }
    let source = reader.json(&binding(&a["source_publication"])?, true)?;
    ensure!(
        source["schema"] == "horizon-native265-source-publication-v1"
            && source["remote_ref"] == "refs/heads/account-updates"
            && hex(text(&source, "remote_head")?, 40)
            && source["all_required_dependencies_in_remote"] == true
            && source["exact_deployed_source_provenance_reviewed"] == true
            && source["no_untracked_required_source"] == true,
        "265 source publication absent"
    );
    let review = reader.json(&binding(&a["review"])?, true)?;
    ensure!(
        review["source_publication"] == a["source_publication"],
        "265 admission review/source mismatch"
    );
    let q = reader.json(&binding(&review["prestart_qualification"])?, true)?;
    prestart_values(&q, &review, &source)?;
    reader.json(&binding(&q["qualification_evidence"])?, false)?;
    let stop = reader.json(&binding(&q["protective_stop_qualification"])?, true)?;
    ensure!(
        stop["schema"] == "horizon-native265-protective-stop-qualification-v1"
            && stop["Main_accepted"] == true
            && stop["harness"] == p["harness"]
            && stop["guard"] == p["guard"]
            && stop["actual_pid1_stop_ordering_verified"] == true
            && stop["sandbox_permissions_verified"] == true
            && stop["original_attempt_retired_with_evidence"] == true,
        "265 protective stop acceptance absent"
    );
    no_authority(&stop)?;
    let capture = reader.json(&binding(&stop["capture"])?, true)?;
    ensure!(
        capture["schema"] == "horizon-native265-protective-stop-capture-v1"
            && capture["harness"] == p["harness"]
            && capture["guard"] == p["guard"]
            && capture["token_absent"] == true
            && capture["worker_root_empty"] == true
            && capture["original_process_gone"] == true
            && capture["kernel_drained"] == true
            && capture["actual_stop_observed"] == true,
        "265 protective stop capture missing"
    );
    let retirement = reader.json(&binding(&stop["retirement"])?, true)?;
    ensure!(
        retirement["schema"] == "horizon-native265-qualification-unit-retirement-v1"
            && retirement["producer_restarted"] == false
            && retirement["sealed_packages_and_diagnostics_preserved"] == true
            && reader.json(&binding(&retirement["before"])?, false)?["capture"] == capture,
        "265 qualification retirement differs"
    );
    let tb = binding(&h["first_guard_token"])?;
    ensure!(
        tb.path
            == Path::new("/var/lib/jetstreamer/horizon-native265-startup-tokens")
                .join(iid)
                .join("guard-admission.json"),
        "265 token path differs"
    );
    let t = reader.json(&tb, true)?;
    let expected = format!("{}\n", tb.sha256).into_bytes();
    let checksum = BoundFile {
        path: tb.path.with_file_name("guard-admission.sha256"),
        sha256: hex_lower(&Sha256::digest(&expected)),
    };
    ensure!(
        reader.bytes(&checksum, 65)? == expected,
        "265 token checksum differs"
    );
    let gp = reader.json(&binding(&h["guard_plan"])?, true)?;
    let g = reader.json(&binding(&h["first_guard_sample"])?, true)?;
    let j = reader.json(&binding(&h["first_guard_pid1_journal"])?, true)?;
    ensure!(
        t["guard_plan"] == h["guard_plan"]
            && t["guard_sample"] == h["first_guard_sample"]
            && t["guard_pid1_journal"] == h["first_guard_pid1_journal"],
        "265 first-fire evidence substituted"
    );
    native265_guard::token_valid(
        &p,
        &pb.sha256,
        &t,
        &gp,
        &g,
        &j,
        iid,
        pid,
        num(&t, "recorded_monotonic_us")?,
        num(&h, "recorded_unix_seconds")?,
    )?;
    ensure!(
        num(&h, "recorded_monotonic_us")? >= num(&t, "recorded_monotonic_us")?
            && num(&h, "recorded_monotonic_us")? < num(&p, "expires_monotonic_us")?
            && num(&a, "expires_unix_seconds")? > num(&a, "recorded_unix_seconds")?
            && num(&a, "expires_unix_seconds")? - num(&a, "recorded_unix_seconds")? <= 60
            && num(&a, "recorded_unix_seconds")? <= num(&h, "recorded_unix_seconds")?
            && num(&h, "recorded_unix_seconds")? <= num(&a, "expires_unix_seconds")?,
        "265 admission/handoff clocks differ"
    );
    native265_capture::retention_values(&h["retention"])?;
    native265_capture::sandbox_values_read(&h["producer"], &p, &pb, reader)?;
    ensure!(
        h["producer"]["InvocationID"] == iid && text(&h["producer"], "MainPID")? == pid.to_string(),
        "265 handoff producer differs"
    );
    let unit = binding(&h["unit_file"])?;
    reader.bytes(&unit, 65536)?;
    ensure!(
        reader.canonical(Path::new(text(&h["producer"], "FragmentPath")?))? == unit.path,
        "265 handoff unit file substituted"
    );
    Ok((h, a))
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    claim_read(c, &FsEvidence)
}
pub(super) fn claim_read(c: &PipelineClaim, reader: &impl EvidenceReader) -> Result<()> {
    ensure!(
        c.evidence.len() == 1,
        "265 requires exactly its running origin"
    );
    namespace(
        &c.evidence[0].path,
        "horizon-native265-running-",
        "intent.json",
    )?;
    let r = reader.json(&c.evidence[0], true)?;
    checked(c, &r)?;
    let (h, a) = startup_read(&binding(&r["startup_handoff"])?, reader)?;
    ensure!(
        h["invocation_id"] == c.invocation_id
            && h["main_pid"] == r["main_pid"]
            && h["producer"]["ExecStart"] == r["expected_exec_start"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["fleet"]
            && h["admission"] == r["admission"]
            && r["boot_id"] == a["boot_id"]
            && num(&r, "recorded_unix_seconds")? >= num(&h, "recorded_unix_seconds")?,
        "265 origin substitutes handoff/observation"
    );
    let spec = reader.json(&binding(&r["capture_spec"])?, true)?;
    ensure!(
        spec["schema"] == "jetstreamer-native265-running-capture-spec-v1"
            && spec["startup_handoff"] == r["startup_handoff"]
            && spec["output"].as_str() == c.evidence[0].path.to_str(),
        "265 capture spec differs"
    );
    Ok(())
}
pub(super) fn live(c: &PipelineClaim, current: &Value) -> Result<()> {
    claim(c)?;
    let r = sealed(&c.evidence[0])?;
    ensure!(
        current["Id"] == UNIT
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && text(current, "MainPID")? == num(&r, "main_pid")?.to_string()
            && pipeline_status::same_exec_start(
                &c.expected_exec_start,
                text(current, "ExecStart")?
            ),
        "265 live owner changed"
    );
    let (h, a) = startup(&binding(&r["startup_handoff"])?)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "265 live boot changed"
    );
    native265_capture::check_live(&h)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_is_exact() {
        assert!(scope("private-cold-snapshot-verification", UNIT));
        assert!(!scope("upload-readback", UNIT));
        assert!(!scope(
            "private-cold-snapshot-verification",
            native210::UNIT
        ));
        assert_eq!(
            pipeline_unit_range("private-cold-snapshot-verification", UNIT).unwrap(),
            265..=265
        );
    }
    #[test]
    fn running_origin_rejects_partial_neighbor_or_authorizing_claims() {
        let claim = PipelineClaim {
            epoch: 265,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let mut r = json!({"schema":SCHEMA,"epoch":265,"unit":UNIT,"invocation_id":claim.invocation_id,"expected_exec_start":claim.expected_exec_start,"private_run_root":ROOT,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"bootstrap_slot":114_479_281u64,"accounts_hash":ACCOUNTS_HASH,"maximum_memory_bytes":MEMORY,"maximum_scratch_bytes":SCRATCH,"resource_samples_taken":0,"replay_entries":0,"native_input_qualified":false,"ordinary_replay_claim":false,"public_sidecar_countdown_authorized":true,"main_pid":42,"recorded_unix_seconds":1792778400u64,"sampled_at_utc":"2026-10-23T18:00:00Z"});
        deny(&mut r);
        checked(&claim, &r).unwrap();
        for key in r.as_object().unwrap().keys() {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(checked(&claim, &bad).is_err(), "{key}");
        }
        for (key, value) in [
            ("test_sha256", json!(native210::TEST_SHA)),
            ("unit", json!(native210::UNIT)),
            ("entry_replay", json!(true)),
            ("maximum_memory_bytes", json!(256u64 << 30)),
            ("main_pid", json!(1)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(checked(&claim, &bad).is_err(), "{key}");
        }
        assert!(super::claim(&claim).is_err());
    }
}
