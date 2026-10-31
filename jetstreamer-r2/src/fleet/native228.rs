//! Closed bootstrap-only 228 owner. Never an epoch replay/publication gate.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch228-native-input-running-v1";
pub(super) const UNIT: &str = "horizon-native-input-228-capped-1bfa8d51-v1.service";
pub(super) const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input228-v1620-capped-v1";
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon-228-native-test-optimized-d3fe9c72-v1/native-input-test";
pub(super) const TEST_SHA: &str =
    "d3fe9c72d542237c97504e0b680fe51e2eb4365b8a9343a631f9bc7512529827";
pub(super) const GUARD: &str = "/var/lib/jetstreamer/horizon-228-native-main-guard-b7da8d62-v1/jetstreamer-horizon-standalone-guard";
pub(super) const GUARD_SHA: &str =
    "b7da8d629d6e2500a0533c71cf05916e52b6ff136bb75b9a3bad74a72947f67b";
pub(super) const INPUT: &str = "/var/lib/jetstreamer/horizon-contiguous-228-230-current-46b4b4a-v1";
pub(super) const GENESIS: &str =
    "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2";
pub(super) const SNAPSHOT: &str =
    "snapshot-98495291-GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq.tar.zst";
pub(super) const SNAPSHOT_SHA: &str =
    "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3";
pub(super) const GENESIS_SHA: &str =
    "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub(super) const ACCOUNTS_HASH: &str = "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq";
pub(super) const PLAN: &str =
    "/var/lib/jetstreamer/horizon-228-native-cold-plan-v1/native-cold-plan.json";
pub(super) const PLAN_SHA: &str =
    "3e954d65dff36c26453c68983003a9e3ae3e269bacb5917e50a191e3243d9734";
pub(super) const SCRATCH: u64 = 300_000_000_000;
pub(super) const MEMORY: u64 = 128u64 << 30;
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-cold-snapshot-verification" && unit == UNIT
}
pub(super) fn command() -> String {
    format!(
        "{{ path={TEST} ; argv[]={TEST} epoch228_profile::tests::native_epoch228_cold_input_matches_canonical_accounts_commitment --exact --ignored --test-threads=1 --nocapture"
    )
}
pub(super) fn no_authority(v: &Value) -> Result<()> {
    for flag in [
        "entry_replay",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "228 native grants authority: {flag}");
    }
    Ok(())
}
fn immutable_owner(path: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "228 origin is not immutable and owned by its trusted writer"
    );
    Ok(())
}
pub(super) fn immutable_json(b: &BoundFile) -> Result<Value> {
    immutable_owner(&b.path, 0)?;
    bound_json(b)
}
fn checked(c: &PipelineClaim, r: &Value) -> Result<()> {
    ensure!(
        c.epoch == 228
            && scope(&c.phase, &c.unit)
            && c.expected_exec_start
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(command().as_str())
            && r["schema"] == SCHEMA
            && r["epoch"] == 228
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["private_run_root"] == ROOT
            && r["test_sha256"] == TEST_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["genesis_sha256"] == GENESIS_SHA
            && r["bootstrap_slot"] == 98_495_291u64
            && r["accounts_hash"] == ACCOUNTS_HASH
            && r["maximum_memory_bytes"] == MEMORY
            && r["maximum_scratch_bytes"] == SCRATCH
            && r["cold_plan"] == json!({"path":PLAN,"sha256":PLAN_SHA})
            && r["resource_samples_taken"] == 0
            && r["replay_entries"] == 0
            && r["native_input_qualified"] == false
            && r["ordinary_replay_claim"] == false,
        "228 native owner, input, fingerprint or mode differs"
    );
    no_authority(r)?;
    ensure!(
        r["public_sidecar_countdown_authorized"] == true,
        "228 active verification status authority missing"
    );
    ensure!(
        utc_seconds(r["sampled_at_utc"].as_str().context("228 origin UTC")?)?
            == r["recorded_unix_seconds"]
                .as_u64()
                .context("228 origin clock")?,
        "228 origin clocks disagree"
    );
    Ok(())
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    ensure!(
        !c.evidence.is_empty() && c.evidence.len() <= 4,
        "228 origin evidence count"
    );
    let r = immutable_json(&c.evidence[0])?;
    checked(c, &r)?;
    let extras = ["guard", "admission", "guard_plan"]
        .iter()
        .map(|k| serde_json::from_value::<BoundFile>(r[*k].clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        c.evidence.iter().skip(1).all(|e| extras.contains(e)),
        "228 unrelated origin evidence"
    );
    let a = immutable_json(&extras[1])?;
    // Guard samples use the existing no-clobber 0600 writer. Their exact digest
    // is frozen by the immutable origin; do not demand a different writer mode.
    let g = bound_json(&extras[0])?;
    let p = immutable_json(&extras[2])?;
    native228_capture::protection(
        &a,
        &g,
        &p,
        r["recorded_unix_seconds"]
            .as_u64()
            .context("228 capture time")?,
    )?;
    ensure!(
        g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["pid"] == r["main_pid"]
            && g["plan_sha256"] == extras[2].sha256,
        "228 guard owner or plan differs"
    );
    Ok(())
}
pub(super) fn live(c: &PipelineClaim, current: &Value) -> Result<()> {
    claim(c)?;
    let r = bound_json(&c.evidence[0])?;
    ensure!(
        current["Id"] == UNIT
            && current["InvocationID"] == c.invocation_id
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["MainPID"]
                .as_str()
                .and_then(|n| n.parse::<u64>().ok())
                == r["main_pid"].as_u64()
            && pipeline_status::same_exec_start(
                &c.expected_exec_start,
                current["ExecStart"].as_str().context("228 command")?
            ),
        "228 native live owner changed"
    );
    native228_capture::sandbox(&native228_capture::properties(UNIT)?)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PipelineClaim, Value) {
        let c = PipelineClaim {
            epoch: 228,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let mut r = json!({"schema":SCHEMA,"epoch":228,"unit":UNIT,"invocation_id":c.invocation_id,"expected_exec_start":c.expected_exec_start,
            "private_run_root":ROOT,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,
            "bootstrap_slot":98495291u64,"accounts_hash":ACCOUNTS_HASH,"maximum_memory_bytes":MEMORY,"maximum_scratch_bytes":SCRATCH,
            "cold_plan":{"path":PLAN,"sha256":PLAN_SHA},"resource_samples_taken":0,"replay_entries":0,"native_input_qualified":false,"ordinary_replay_claim":false,
            "sampled_at_utc":"2026-10-23T18:00:00Z","recorded_unix_seconds":1792778400u64,"public_sidecar_countdown_authorized":true});
        for flag in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            r[flag] = json!(false);
        }
        (c, r)
    }
    #[test]
    fn native228_owner_fingerprints_and_mode_are_closed() {
        let (c, r) = fixture();
        checked(&c, &r).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 228..=228);
        assert!(pipeline_unit_range("upload-readback", &c.unit).is_err());
        for key in r.as_object().unwrap().keys() {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(checked(&c, &bad).is_err(), "{key}");
        }
        for (key, value) in [
            (
                "test_sha256",
                json!("1446cd728b4408208f125d073ecc52b1ae4205df095747dad7e91f3581ce4bf3"),
            ),
            ("epoch", json!(227)),
            ("entry_replay", json!(true)),
            ("maximum_memory_bytes", json!(256u64 << 30)),
            ("bootstrap_slot", json!(89423445u64)),
        ] {
            let mut bad = r.clone();
            bad[key] = value;
            assert!(checked(&c, &bad).is_err(), "{key}");
        }
        let mut bad: PipelineClaim =
            serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        bad.unit = singleton227_admission::NATIVE_UNIT.into();
        assert!(checked(&bad, &r).is_err());
        bad = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        bad.phase = "upload-readback".into();
        assert!(checked(&bad, &r).is_err());
        assert!(!scope(
            &c.phase,
            "archive-228-v1620-native-input-other.service"
        ));
    }
    #[test]
    fn immutable_origin_rejects_another_owner_writes_and_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("intent.json");
        fs::write(&p, b"{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        let uid = fs::metadata(&p).unwrap().uid();
        immutable_owner(&p, uid).unwrap();
        assert!(immutable_owner(&p, uid + 1).is_err());
        let link = dir.path().join("link.json");
        symlink(&p, &link).unwrap();
        assert!(immutable_owner(&link, uid).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(immutable_owner(&p, uid).is_err());
    }
}
