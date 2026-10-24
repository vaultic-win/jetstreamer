//! Closed bootstrap-only 210 owner. Never an epoch replay/publication gate.
//! The additive `native210-small` build selects the separately sealed96GB
//! generation for every lifecycle operation. Default retains the original300GB
//! tuple; neither generation may borrow the other's origin, guard or terminal.
use super::*;
pub(super) const SCHEMA: &str = "jetstreamer-private-epoch210-native-input-running-v1";
pub(super) const UNIT: &str = if cfg!(feature = "native210-small") {
    "archive-210-v1616-native-input-small-v2.service"
} else {
    "archive-210-v1616-native-input-actual-v1.service"
};
pub(super) const ROOT: &str = if cfg!(feature = "native210-small") {
    "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-small-v2"
} else {
    "/home/ubuntu/.jetstreamer-private/native-input210-v1616-capped-v1"
};
pub(super) const TEST: &str =
    "/var/lib/jetstreamer/horizon-210-native-input-optimized-v1/native-input-test";
pub(super) const TEST_SHA: &str =
    "2f33396ed027cefbb2529bee194a83e0d0c8dcd079b76cc9410a53852ad1cec6";
pub(super) const GUARD: &str = if cfg!(feature = "native210-small") {
    "/var/lib/jetstreamer/horizon-210-native-small-main-guard-v2/jetstreamer-horizon-standalone-guard"
} else {
    "/var/lib/jetstreamer/horizon-210-native-main-guard-v1/jetstreamer-horizon-standalone-guard"
};
pub(super) const GUARD_SHA: &str = if cfg!(feature = "native210-small") {
    "2f4f33097a90579d4433a7e9ab0aaeb4e7d3a422b5ff36b188b0e6c5d1a8e38d"
} else {
    "646c08e3f528672675532a16501414257d5fd2e7a49e273a45b50287df10a4c7"
};
pub(super) const INPUT: &str =
    "/var/lib/jetstreamer/horizon-focused-210-complete-span-store8-ca2e38b-v1";
pub(super) const SNAPSHOT: &str =
    "snapshot-90719638-3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ.tar.zst";
pub(super) const SNAPSHOT_SHA: &str =
    "3f67f416d254d7fb795bc902d5c47a6ae374fa36c173c00411d4b541fc610ccd";
pub(super) const GENESIS_SHA: &str =
    "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub(super) const ACCOUNTS_HASH: &str = "3C18JGi6UtMvAi6M4AUPC96redPqo7h6QnAsrUi8d3SJ";
pub(super) const PLAN: &str = if cfg!(feature = "native210-small") {
    "/var/lib/jetstreamer/horizon-210-native-small-cold-plan-v2/native-cold-plan.json"
} else {
    "/var/lib/jetstreamer/horizon-210-native-cold-plan-v1/native-cold-plan.json"
};
pub(super) const PLAN_SHA: &str = if cfg!(feature = "native210-small") {
    "dafaa24dabacedbf6d11a2d61127313f1186e802c80941872f436313cf41383b"
} else {
    "9d693ef2c3a8c3c967cd1a1cd1ff6534db86203325c25b2e53c2fd8534e56b46"
};
pub(super) const SCRATCH: u64 = if cfg!(feature = "native210-small") {
    96_000_000_000
} else {
    300_000_000_000
};
pub(super) const MEMORY: u64 = 128u64 << 30;
pub(super) const UNIT_FILE: &str = if cfg!(feature = "native210-small") {
    "/etc/systemd/system/archive-210-v1616-native-input-small-v2.service"
} else {
    "/etc/systemd/system/archive-210-v1616-native-input-actual-v1.service"
};
pub(super) const UNIT_FILE_SHA: &str = if cfg!(feature = "native210-small") {
    "3532f2cf94e07aca3ab6db33a9e659e4837eaec50ccc55ef5f4e3119a99aedd8"
} else {
    "474e889f9d40294654f52a3f2ce0f3d3d06b89fc5f19cd97695f5aa5f42ccb24"
};
pub(super) const ORIGIN: &str = if cfg!(feature = "native210-small") {
    "/var/lib/jetstreamer/horizon-210-native-capture-small-v2/intent.json"
} else {
    "/var/lib/jetstreamer/horizon-210-native-capture-actual-v1/intent.json"
};
pub(super) fn small_envelope(cold: &Value) -> Result<()> {
    if !cfg!(feature = "native210-small") {
        return Ok(());
    }
    let binding = small_model(cold)?;
    small_census(&immutable_json(&binding)?)
}
fn small_model(cold: &Value) -> Result<BoundFile> {
    let binding: BoundFile = serde_json::from_value(cold["snapshot_census"].clone())?;
    ensure!(
        binding.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-native210-snapshot-census-actual-v1/census.json"
            )
            && binding.sha256 == "8a012e925c15ee5a8471e882c64873efcdd67b76d00e6ecc75875fc2f38216c6"
            && cold["disk_envelope_model"]
                == json!({"formula":"2*dense_4096_rounded_file_bytes+metadata_allowance_bytes+1073741824",
            "modeled_bytes":64_835_780_608u64,"maximum_root_physical_bytes":SCRATCH,"bounded_experiment_only":true,
            "original_300gb_generation_preserved":true}),
        "210 small census/model binding differs"
    );
    Ok(binding)
}
fn small_census(census: &Value) -> Result<()> {
    ensure!(
        census["schema"] == "jetstreamer-native-readonly-snapshot-census-v1"
            && census["epoch"] == 210
            && census["snapshot_sha256"] == SNAPSHOT_SHA
            && census["census"]["dense_4096_rounded_file_bytes"] == 28_689_416_192u64
            && census["census"]["metadata_allowance_bytes"] == 6_383_206_400u64
            && census["census"]["twice_dense_plus_metadata_plus_one_gib_bytes"]
                == 64_835_780_608u64
            && census["snapshot_extracted"] == false
            && census["bank_constructed"] == false
            && census["native_execution_authorized"] == false
            && 64_835_780_608u64 < SCRATCH,
        "210 small census scope differs"
    );
    Ok(())
}
pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-cold-snapshot-verification" && unit == UNIT
}
pub(super) fn unit_name(unit: &str) -> bool {
    matches!(
        unit,
        "archive-210-v1616-native-input-actual-v1.service"
            | "archive-210-v1616-native-input-small-v2.service"
    )
}
pub(super) fn command() -> String {
    format!(
        "{{ path={TEST} ; argv[]={TEST} runtime::native210_input::native_epoch210_cold_input_matches_canonical_accounts_commitment --exact --ignored --test-threads=1 --nocapture"
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
        ensure!(v[flag] == false, "210 native grants authority: {flag}");
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
        "210 origin is not immutable and owned by its trusted writer"
    );
    Ok(())
}
pub(super) fn immutable_json(b: &BoundFile) -> Result<Value> {
    immutable_owner(&b.path, 0)?;
    bound_json(b)
}
fn checked(c: &PipelineClaim, r: &Value) -> Result<()> {
    ensure!(
        c.epoch == 210
            && scope(&c.phase, &c.unit)
            && c.expected_exec_start
                .split_once(" ; ignore_errors=")
                .map(|(s, _)| s)
                == Some(command().as_str())
            && r["schema"] == SCHEMA
            && r["epoch"] == 210
            && r["unit"] == UNIT
            && r["invocation_id"] == c.invocation_id
            && r["expected_exec_start"] == c.expected_exec_start
            && r["private_run_root"] == ROOT
            && r["test_sha256"] == TEST_SHA
            && r["snapshot_sha256"] == SNAPSHOT_SHA
            && r["genesis_sha256"] == GENESIS_SHA
            && r["bootstrap_slot"] == 90_719_638u64
            && r["accounts_hash"] == ACCOUNTS_HASH
            && r["maximum_memory_bytes"] == MEMORY
            && r["maximum_scratch_bytes"] == SCRATCH
            && r["cold_plan"] == json!({"path":PLAN,"sha256":PLAN_SHA})
            && r["unit_file"] == json!({"path":UNIT_FILE,"sha256":UNIT_FILE_SHA})
            && r["resource_samples_taken"] == 0
            && r["replay_entries"] == 0
            && r["native_input_qualified"] == false
            && r["ordinary_replay_claim"] == false,
        "210 native owner, input, fingerprint or mode differs"
    );
    no_authority(r)?;
    ensure!(
        r["public_sidecar_countdown_authorized"] == true,
        "210 active verification status authority missing"
    );
    ensure!(
        utc_seconds(r["sampled_at_utc"].as_str().context("210 origin UTC")?)?
            == r["recorded_unix_seconds"]
                .as_u64()
                .context("210 origin clock")?,
        "210 origin clocks disagree"
    );
    Ok(())
}
pub(super) fn claim(c: &PipelineClaim) -> Result<()> {
    ensure!(
        !c.evidence.is_empty() && c.evidence.len() <= 4,
        "210 origin evidence count"
    );
    ensure!(
        c.evidence[0].path == Path::new(ORIGIN),
        "210 requires its terminal-capturable registered attempt"
    );
    let r = immutable_json(&c.evidence[0])?;
    checked(c, &r)?;
    let extras = ["guard", "admission", "guard_plan"]
        .iter()
        .map(|k| serde_json::from_value::<BoundFile>(r[*k].clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        c.evidence.iter().skip(1).all(|e| extras.contains(e)),
        "210 unrelated origin evidence"
    );
    let a = immutable_json(&extras[1])?;
    // Guard samples use the existing no-clobber0600 writer. Their exact digest
    // is frozen by the immutable origin; do not demand a different writer mode.
    let g = bound_json(&extras[0])?;
    let p = immutable_json(&extras[2])?;
    native210_capture::protection(
        &a,
        &g,
        &p,
        r["recorded_unix_seconds"]
            .as_u64()
            .context("210 capture time")?,
    )?;
    ensure!(
        g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["pid"] == r["main_pid"]
            && g["plan_sha256"] == extras[2].sha256,
        "210 guard owner or plan differs"
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
                current["ExecStart"].as_str().context("210 command")?
            ),
        "210 native live owner changed"
    );
    native210_capture::sandbox(&native210_capture::properties(UNIT)?)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_generation_model_and_census_cannot_borrow_or_expand_authority() {
        let mut cold = json!({"snapshot_census":{
            "path":"/var/lib/jetstreamer/horizon-native210-snapshot-census-actual-v1/census.json",
            "sha256":"8a012e925c15ee5a8471e882c64873efcdd67b76d00e6ecc75875fc2f38216c6"},
            "disk_envelope_model":{"formula":"2*dense_4096_rounded_file_bytes+metadata_allowance_bytes+1073741824",
                "modeled_bytes":64_835_780_608u64,"maximum_root_physical_bytes":SCRATCH,"bounded_experiment_only":true,
                "original_300gb_generation_preserved":true}});
        small_model(&cold).unwrap();
        let mut receipt = json!({"schema":"jetstreamer-native-readonly-snapshot-census-v1","epoch":210,
            "snapshot_sha256":SNAPSHOT_SHA,"census":{"dense_4096_rounded_file_bytes":28_689_416_192u64,
                "metadata_allowance_bytes":6_383_206_400u64,"twice_dense_plus_metadata_plus_one_gib_bytes":64_835_780_608u64},
            "snapshot_extracted":false,"bank_constructed":false,"native_execution_authorized":false});
        small_census(&receipt).unwrap();
        for pointer in [
            "/snapshot_census/path",
            "/snapshot_census/sha256",
            "/disk_envelope_model/modeled_bytes",
            "/disk_envelope_model/maximum_root_physical_bytes",
            "/disk_envelope_model/bounded_experiment_only",
        ] {
            let mut bad = cold.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(small_model(&bad).is_err(), "{pointer}");
        }
        for pointer in [
            "/epoch",
            "/snapshot_sha256",
            "/census/twice_dense_plus_metadata_plus_one_gib_bytes",
            "/snapshot_extracted",
            "/bank_constructed",
            "/native_execution_authorized",
        ] {
            let mut bad = receipt.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(small_census(&bad).is_err(), "{pointer}");
        }
        cold["disk_envelope_model"]["maximum_root_physical_bytes"] = json!(64_000_000_000u64);
        receipt["epoch"] = json!(227);
        assert!(small_model(&cold).is_err());
        assert!(small_census(&receipt).is_err());
    }
    fn fixture() -> (PipelineClaim, Value) {
        let c = PipelineClaim {
            epoch: 210,
            phase: "private-cold-snapshot-verification".into(),
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: format!("{} ; ignore_errors=no }}", command()),
            evidence: vec![],
        };
        let mut r = json!({"schema":SCHEMA,"epoch":210,"unit":UNIT,"invocation_id":c.invocation_id,"expected_exec_start":c.expected_exec_start,
            "private_run_root":ROOT,"test_sha256":TEST_SHA,"snapshot_sha256":SNAPSHOT_SHA,"genesis_sha256":GENESIS_SHA,
            "bootstrap_slot":90719638u64,"accounts_hash":ACCOUNTS_HASH,"maximum_memory_bytes":MEMORY,"maximum_scratch_bytes":SCRATCH,
            "cold_plan":{"path":PLAN,"sha256":PLAN_SHA},"unit_file":{"path":UNIT_FILE,"sha256":UNIT_FILE_SHA},"resource_samples_taken":0,"replay_entries":0,"native_input_qualified":false,"ordinary_replay_claim":false,
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
    fn native210_owner_fingerprints_and_mode_are_closed() {
        assert!(unit_name(
            "archive-210-v1616-native-input-actual-v1.service"
        ));
        assert!(unit_name("archive-210-v1616-native-input-small-v2.service"));
        assert!(!unit_name("archive-210-v1616-native-input-other.service"));
        let other_generation = if cfg!(feature = "native210-small") {
            "archive-210-v1616-native-input-actual-v1.service"
        } else {
            "archive-210-v1616-native-input-small-v2.service"
        };
        assert!(!scope(
            "private-cold-snapshot-verification",
            other_generation
        ));
        let (c, r) = fixture();
        checked(&c, &r).unwrap();
        assert_eq!(pipeline_unit_range(&c.phase, &c.unit).unwrap(), 210..=210);
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
            "archive-210-v1616-native-input-other.service"
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
