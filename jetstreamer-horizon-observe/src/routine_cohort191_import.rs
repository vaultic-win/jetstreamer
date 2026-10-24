//! First post-producer191 observation while the real native import is pending.
use super::*;
const IMPORTER: &str = "jetstreamer-root-import-e191-194-t5-20261016-v2-r2-e191-194-2.service";
const IMPORT_IID: &str = "611c55c179654410a5dddce41fd6c019";
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
pub(super) fn enabled(p: &Plan) -> bool {
    p.cohort191_delivery
        .as_ref()
        .is_some_and(|s| s.import_pending)
}
pub(super) fn adoption_clocks(old: u64, target: u64, captured: u64) -> Result<()> {
    let gap = target
        .checked_sub(old)
        .context("191 pending adoption precedes accepted predecessor")?;
    ensure!(
        (1800..=7200).contains(&gap) && gap % 1800 == 0,
        "191 import adoption must retain bounded original30minute grid"
    );
    ensure!(
        captured > old && captured <= target,
        "191 pending capture must follow predecessor and precede target"
    );
    Ok(())
}
fn shape(v: &Value, target: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-cohort191-import-pending-transition-v1"
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && v["public_batch"].is_null()
            && v["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= target)
            && v["producer"]["MainPID"] == "0"
            && v["producer"]["NRestarts"] == "0"
            && v["producer"]["ActiveState"] == "inactive"
            && v["controller"]["Id"]
                == "jetstreamer-epochs191-194-target5-controller-v2-r2.service"
            && v["controller"]["InvocationID"] == "c741f57764384e07a08484e6451f8f0c"
            && v["controller"]["ActiveState"] == "active"
            && v["controller"]["SubState"] == "running"
            && v["importer"]["Id"] == IMPORTER
            && v["importer"]["InvocationID"] == IMPORT_IID
            && v["importer"]["ActiveState"] == "active"
            && v["importer"]["SubState"] == "running"
            && v["resource_samples"] == 0,
        "191 pending proof lacks terminal producer or actual original importer"
    );
    for flag in [
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
        "archive_readiness_claimed",
        "public_import_verified",
        "verification_authorized",
        "upload_authorized",
        "local_retirement_authorized",
    ] {
        ensure!(v[flag] == false, "191 pending proof grants {flag}");
    }
    let end = &v["producer_terminal"];
    ensure!(
        end["UNIT"]
            == "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service"
            && end["INVOCATION_ID"] == "ea93199ed2fa470d99de248c2a10b246"
            && end["_PID"] == "1"
            && end["_UID"] == "0"
            && end["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "191 pending proof lacks native producer exit"
    );
    let captured = v["recorded_unix_seconds"]
        .as_u64()
        .context("191 pending capture time missing")?;
    let ended = end["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("191 pending native end time missing")?
        .parse::<u64>()?;
    ensure!(
        ended > 0
            && ended
                <= captured
                    .checked_mul(1_000_000)
                    .context("191 capture clock overflow")?,
        "191 pending capture backdates native producer exit"
    );
    for role in ["controller", "importer"] {
        ensure!(
            v[role]["LoadState"] == "loaded"
                && v[role]["NRestarts"] == "0"
                && v[role]["MainPID"]
                    .as_str()
                    .is_some_and(|s| s.parse::<u64>().is_ok_and(|n| n > 0)),
            "191 pending proof lacks a live original actor"
        );
    }
    jetstreamer_horizon_observe::cohort191_delivery_model::validate_native_terminal(
        &v["native_events"],
        target,
    )?;
    Ok(())
}
pub(super) fn validate(p: &Plan, v: &Value) -> Result<()> {
    let s = p
        .cohort191_delivery
        .as_ref()
        .context("191 import profile absent")?;
    ensure!(
        s.import_pending && terminal185::enabled(p) && repair141_status::enabled(p),
        "191 pending transition must retain185terminal/141repair profiles"
    );
    shape(v, utc_seconds(&p.sample_target_utc)?)?;
    ensure!(
        v["capture_program"].as_str() == s.publisher.path.to_str()
            && v["capture_self_sha256"] == s.publisher.sha256,
        "191 pending native capture program differs"
    );
    let cb: Bound = serde_json::from_value(v["capture_plan"].clone())?;
    let c = bound_json(&cb, true)?;
    ensure!(
        c["schema"] == "jetstreamer-cohort191-import-pending-capture-plan-v1"
            && c["program"] == serde_json::to_value(&s.publisher)?
            && c["source_batch"] == v["source_batch"]
            && c["origins"] == v["origins"]
            && c["estimate_evidence"] == v["estimate_evidence"]
            && c["output"].as_str() == s.terminal_event.path.to_str()
            && c.get("observer").is_none(),
        "191 pending proof lost sealed source/forecast/origin provenance"
    );
    let source: Bound = serde_json::from_value(v["source_batch"].clone())?;
    ensure!(
        source.sha256 == "52a8ddc2be6c8301404f4cd2ad058faab49d28aefb8e30ee64563e8a23ead746",
        "191 pending source batch differs"
    );
    Ok(())
}
pub(super) fn capture(p: &Plan, observer: &Bound) -> Result<()> {
    let s = p
        .cohort191_delivery
        .as_ref()
        .context("191 pending profile")?;
    let v = bound_json(&s.terminal_event, false)?;
    validate(p, &v)?;
    private_dir(&s.event_directory)?;
    let output = s
        .event_directory
        .join(format!("event-{}.json", stamp(&p.sample_target_utc)));
    let package = delivery198::seal_values(
        p,
        "import191-capture",
        &[(
            "plan.json",
            json!({"schema":"jetstreamer-cohort191-import-pending-observation-plan-v1","bootstrap":s.terminal_event,"observer":observer,"output":output}),
        )],
    )?;
    let plan = file(package.join("plan.json"), true)?;
    child(
        &s.publisher,
        &[
            "observe-import-pending191".into(),
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256,
            "--self-sha256".into(),
            s.publisher.sha256.clone(),
        ],
        false,
        &p.cycle_directory.join("child-import191-capture.json"),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_adoption_uses_real_capture_and_only_the_original_grid() {
        for gap in [1800, 3600, 5400, 7200] {
            adoption_clocks(10000, 10000 + gap, 11000).unwrap();
        }
        for target in [9999, 10000, 11799, 11801, 12400, 15401, 17201, 19000] {
            assert!(adoption_clocks(10000, target, 11000).is_err());
        }
        for captured in [9999, 10000, 15401] {
            assert!(adoption_clocks(10000, 15400, captured).is_err());
        }
    }
    #[test]
    fn import_variant_never_relabels_the_all_public_native_terminal_profile() {
        let mut v = json!({"schema":"jetstreamer-cohort191-terminal-transition-v1","public_batch":{"path":"public"}});
        assert!(shape(&v, 20000).is_err());
        v["schema"] = json!("jetstreamer-cohort191-import-pending-transition-v1");
        assert!(shape(&v, 20000).is_err());
    }
}
