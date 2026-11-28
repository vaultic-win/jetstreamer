//! Exact gated bootstrap-only epoch211 owner. No replay/publication authority.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch211-native-input-running-v1";
pub(super) const UNIT: &str = "archive-211-v1616-native-input-actual-v1.service";
pub(super) const GUARD_UNIT: &str = "horizon-native211-protective-v1.service";
pub(super) const RETENTION: &str = "horizon-native211-terminal-retention.target";
pub(super) const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input211-v1616-capped-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon-211-native-input-gated-20261119-v1/native-input-test";
pub(super) const TEST_SHA: &str =
    "2b1c0dd8b8cfcf0bbb80e52864c4b78a8348b1bc96dc97cbdfc4fee1094b8773";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-211-native-guard-gated-cac91a65-20261119-v1/horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "a91f0cc1f3a018f11731b97bbeb2132790a4dbd63dec93b7aa9abbaafeeb6d9a";
pub(super) const SNAPSHOT_SHA: &str =
    "958a8e5aad2423350f04470dffbd90fd8d7e458f7f8e774e15dd86d43291b5fb";
pub(super) const ACCOUNTS_HASH: &str = "xiEDMtStmnD9Pc8Ph9rJ4dFhfvvqZDSPeX89wjPELXx";
pub(super) const MEMORY: u64 = 137_438_953_472;
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("211 number {k}"))
}
pub(super) fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("211 string {k}"))
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
    format!(
        "{{ path={TEST} ; argv[]={TEST} runtime::native211_input::native_epoch211_cold_input_matches_canonical_accounts_commitment --exact --ignored --test-threads=1 --nocapture"
    )
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
        "211 namespace differs"
    );
    Ok(())
}
pub(super) fn sealed(b: &BoundFile) -> Result<Value> {
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer") && b.path.canonicalize()? == b.path,
        "211 sealed namespace"
    );
    for p in b.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "211 evidence ancestor changed"
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
            "211 byte evidence namespace"
        );
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
            "211 byte evidence custody"
        );
        for p in b.path.ancestors().skip(1) {
            let m = fs::symlink_metadata(p)?;
            ensure!(
                m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
                "211 byte evidence parent"
            );
        }
        let bytes = read_stable_bounded(&b.path, maximum, "211 immutable byte evidence")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == b.sha256,
            "211 byte evidence digest"
        );
        Ok(bytes)
    }
}
pub(super) fn prestart_values(q: &Value, review: &Value, source: &Value) -> Result<()> {
    ensure!(
        review["schema"] == "horizon-native211-current-fleet-review-v1"
            && review["epoch"] == 211
            && review["Main_accepted"] == true,
        "211 startup review scope differs"
    );
    no_authority(review)?;
    no_authority(q)?;
    let launchers = source["artifacts"]
        .as_array()
        .context("211 published artifacts")?
        .iter()
        .filter(|r| r["role"] == "launcher")
        .collect::<Vec<_>>();
    ensure!(
        launchers.len() == 1,
        "211 exact launcher provenance missing/ambiguous"
    );
    let artifact = binding(&launchers[0]["artifact"])?;
    ensure!(
        artifact.path.starts_with("/var/lib/jetstreamer"),
        "211 launcher artifact namespace"
    );
    let sha = artifact.sha256.as_str();
    ensure!(hex(sha, 64), "211 launcher artifact digest");
    ensure!(
        q["schema"] == "horizon-native211-prestart-qualification-v1"
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
        "211 prestart qualification differs from published launcher"
    );
    Ok(())
}
fn checked(c: &PipelineClaim, r: &Value) -> Result<()> {
    ensure!(
        c.epoch == 211
            && scope(&c.phase, &c.unit)
            && hex(&c.invocation_id, 32)
            && c.expected_exec_start.split(" ; ignore_errors=").next() == Some(command().as_str())
            && r["schema"] == SCHEMA
            && r["epoch"] == 211
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["private_run_root"] == ROOT
            && r["test_sha256"] == TEST_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["bootstrap_slot"] == 91_151_575u64
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
        "211 closed running origin differs"
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
        "horizon-native211-execution-",
        "guarded-startup-handoff.json",
    )?;
    let h = reader.json(hb, true)?;
    no_authority(&h)?;
    let iid = text(&h, "invocation_id")?;
    let pid: u32 = num(&h, "main_pid")?.try_into()?;
    ensure!(
        h["schema"] == "horizon-native211-guarded-startup-v1"
            && h["unit"] == UNIT
            && hex(iid, 32)
            && pid > 1
            && h["native_input_qualified"] == false,
        "211 handoff differs"
    );
    let pb = binding(&h["startup_plan"])?;
    namespace(&pb.path, "horizon-native211-startup-plan-", "plan.json")?;
    let p = reader.json(&pb, true)?;
    let a = reader.json(&binding(&h["admission"])?, true)?;
    no_authority(&a)?;
    ensure!(
        p["schema"] == "horizon-native211-startup-plan-v1"
            && p["epoch"] == 211
            && p["unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["worker_root"] == ROOT
            && p["bootstrap_slot"] == 91_151_575u64
            && p["snapshot_sha256"] == SNAPSHOT_SHA
            && p["maximum_memory_bytes"] == MEMORY
            && p["maximum_root_physical_bytes"] == SCRATCH
            && p["harness"] == json!({"path":TEST,"sha256":TEST_SHA})
            && p["guard"] == json!({"path":GUARD,"sha256":GUARD_SHA})
            && p["token_root"] == "/var/lib/jetstreamer/horizon-native211-startup-tokens"
            && p["admission"] == h["admission"]
            && a["schema"] == "horizon-native211-current-fleet-admission-v1"
            && a["epoch"] == 211
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
        "211 startup/admission pins differ"
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
        source["schema"] == "horizon-native211-source-publication-v1"
            && source["remote_ref"] == "refs/heads/account-updates"
            && hex(text(&source, "remote_head")?, 40)
            && source["all_required_dependencies_in_remote"] == true
            && source["exact_deployed_source_provenance_reviewed"] == true
            && source["no_untracked_required_source"] == true,
        "211 source publication absent"
    );
    let review = reader.json(&binding(&a["review"])?, true)?;
    ensure!(
        review["source_publication"] == a["source_publication"],
        "211 admission review/source mismatch"
    );
    let q = reader.json(&binding(&review["prestart_qualification"])?, true)?;
    prestart_values(&q, &review, &source)?;
    reader.json(&binding(&q["qualification_evidence"])?, false)?;
    let tb = binding(&h["first_guard_token"])?;
    ensure!(
        tb.path
            == Path::new("/var/lib/jetstreamer/horizon-native211-startup-tokens")
                .join(iid)
                .join("guard-admission.json"),
        "211 token path differs"
    );
    let t = reader.json(&tb, true)?;
    let expected = format!("{}\n", tb.sha256).into_bytes();
    let checksum = BoundFile {
        path: tb.path.with_file_name("guard-admission.sha256"),
        sha256: hex_lower(&Sha256::digest(&expected)),
    };
    ensure!(
        reader.bytes(&checksum, 65)? == expected,
        "211 token checksum differs"
    );
    let gp = reader.json(&binding(&h["guard_plan"])?, true)?;
    let g = reader.json(&binding(&h["first_guard_sample"])?, true)?;
    let j = reader.json(&binding(&h["first_guard_pid1_journal"])?, true)?;
    ensure!(
        t["guard_plan"] == h["guard_plan"]
            && t["guard_sample"] == h["first_guard_sample"]
            && t["guard_pid1_journal"] == h["first_guard_pid1_journal"],
        "211 first-fire evidence substituted"
    );
    native211_guard::token_valid(
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
        "211 admission/handoff clocks differ"
    );
    native211_capture::retention_values(&h["retention"])?;
    native211_capture::sandbox_values_read(&h["producer"], &p, &pb, reader)?;
    ensure!(
        h["producer"]["InvocationID"] == iid && text(&h["producer"], "MainPID")? == pid.to_string(),
        "211 handoff producer differs"
    );
    let unit = binding(&h["unit_file"])?;
    reader.bytes(&unit, 65536)?;
    ensure!(
        reader.canonical(Path::new(text(&h["producer"], "FragmentPath")?))? == unit.path,
        "211 handoff unit file substituted"
    );
    Ok((h, a))
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    claim_read(c, &FsEvidence)
}
pub(super) fn claim_read(c: &PipelineClaim, reader: &impl EvidenceReader) -> Result<()> {
    ensure!(
        c.evidence.len() == 1,
        "211 requires exactly its running origin"
    );
    namespace(
        &c.evidence[0].path,
        "horizon-native211-running-",
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
        "211 origin substitutes handoff/observation"
    );
    let spec = reader.json(&binding(&r["capture_spec"])?, true)?;
    ensure!(
        spec["schema"] == "jetstreamer-native211-running-capture-spec-v1"
            && spec["startup_handoff"] == r["startup_handoff"]
            && spec["output"].as_str() == c.evidence[0].path.to_str(),
        "211 capture spec differs"
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
        "211 live owner changed"
    );
    let (h, a) = startup(&binding(&r["startup_handoff"])?)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "211 live boot changed"
    );
    native211_capture::check_live(&h)?;
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
            211..=211
        );
    }
    #[test]
    fn running_origin_rejects_partial_neighbor_or_authorizing_claims() {
        let claim = PipelineClaim {
            epoch: 211,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let mut r = json!({"schema":SCHEMA,"epoch":211,"unit":UNIT,"invocation_id":claim.invocation_id,"expected_exec_start":claim.expected_exec_start,"private_run_root":ROOT,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"bootstrap_slot":91_151_575u64,"accounts_hash":ACCOUNTS_HASH,"maximum_memory_bytes":MEMORY,"maximum_scratch_bytes":SCRATCH,"resource_samples_taken":0,"replay_entries":0,"native_input_qualified":false,"ordinary_replay_claim":false,"public_sidecar_countdown_authorized":true,"main_pid":42,"recorded_unix_seconds":1792778400u64,"sampled_at_utc":"2026-10-23T18:00:00Z"});
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
