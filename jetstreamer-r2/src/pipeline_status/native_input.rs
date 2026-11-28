//! Status-only origin for centrally registered zero-entry native input tests.
//! No manufactured legacy replay launch, archive, resource sample or authority.
use super::*;

pub(super) fn selected(p: &Plan) -> bool {
    p.binding.claim_phase == "private-cold-snapshot-verification"
}

fn registered_origin(p: &Plan, origin: &Value, fleet: &Value) -> Result<()> {
    ensure!(
        selected(p)
            && p.phase == "verification"
            && p.peer_units.is_empty()
            && p.phase_handoff_event.is_none(),
        "native input status profile differs"
    );
    let fp = bound_json(&Bound {
        path: fleet["plan"]
            .as_str()
            .context("native accepted plan")?
            .into(),
        sha256: fleet["plan_sha256"]
            .as_str()
            .context("native accepted plan digest")?
            .into(),
    })?;
    let claims = fp["pipeline_claims"]
        .as_array()
        .context("native accepted pipeline claims")?
        .iter()
        .filter(|c| {
            c["epoch"] == p.epoch
                && c["unit"] == p.binding.unit
                && c["invocation_id"] == p.binding.invocation_id
                && c["phase"] == p.binding.claim_phase
        })
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "native input needs one exact registered fleet claim"
    );
    fleet::validate_native_input_status_claim(claims[0])?;
    ensure!(
        claims[0]["expected_exec_start"]
            .as_str()
            .is_some_and(|s| same_exec_start(s, &p.binding.expected_exec_start))
            && claims[0]["evidence"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["path"].as_str() == p.origin_launch.path.to_str()
                    && row["sha256"] == p.origin_launch.sha256))
            && origin["invocation_id"] == p.binding.invocation_id
            && origin["resource_samples_taken"] == 0,
        "native input origin is not the immutable registered intent"
    );
    for key in [
        "entry_replay",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(origin[key] == false, "native input origin grants authority");
    }
    ensure!(
        p.binding.origin_unit == p.binding.unit
            && p.binding.origin_invocation_id == p.binding.invocation_id,
        "native input origin clock differs"
    );
    if p.origin_launch.path.file_name().and_then(|s| s.to_str()) == Some("intent.json") {
        ensure!(
            fs::symlink_metadata(p.origin_launch.path.with_file_name("result.json"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "native input already reached terminal handoff"
        );
    }
    zero_jet(p)
}
pub(super) fn validate_origin(p: &Plan, origin: &Value, fleet: &Value) -> Result<()> {
    registered_origin(p, origin, fleet)
}

pub(super) fn zero_jet(p: &Plan) -> Result<()> {
    absent_jet(
        &p.jet_path,
        &p.origin_launch.path,
        p.epoch,
        p.expected_jet_size_bytes,
    )
}
fn absent_jet(path: &Path, origin: &Path, epoch: u64, expected: u64) -> Result<()> {
    let parent = origin.parent().context("native intent parent")?;
    ensure!(
        expected == 0
            && path == parent.join(format!("epoch-{epoch}.jet"))
            && parent.canonicalize()? == parent
            && fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "zero-entry native stage must have no jet, including an empty placeholder"
    );
    Ok(())
}
pub(super) fn selected_clock(
    observer: &Value,
    origin: &Value,
    fleet: &Value,
    initial_event: bool,
    now: u64,
) -> Result<String> {
    let old = observer["recorded_at_utc"]
        .as_str()
        .context("native resource clock")?;
    let resource = fleet::utc_seconds(old)?;
    let event = origin["recorded_unix_seconds"]
        .as_u64()
        .context("native intent clock")?;
    let event_text = origin["sampled_at_utc"]
        .as_str()
        .context("native intent canonical UTC clock")?;
    ensure!(
        fleet::utc_seconds(event_text)? == event,
        "native intent UTC/numeric clocks disagree"
    );
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("native fleet clock")?;
    ensure!(
        resource <= recorded
            && event <= recorded
            && recorded <= now
            && now >= resource
            && now - resource <= 1800,
        "native input needs a fresh coordinated resource cycle"
    );
    if event > resource {
        ensure!(
            initial_event && now >= event && now - event <= 300,
            "native initial status needs its accepted launch event"
        );
        Ok(event_text.into())
    } else {
        Ok(old.into())
    }
}
pub(super) fn sample(p: &Plan, observer: &Value, fleet: &Value, now: u64) -> Result<String> {
    let origin = bound_json(&p.origin_launch)?;
    registered_origin(p, &origin, fleet)?;
    ensure!(
        fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["inventory"]["anomalies"] == 0,
        "native fleet observation differs"
    );
    ensure!(
        fleet["first_epoch"].as_u64().is_some_and(|n| n <= p.epoch)
            && fleet["last_epoch"].as_u64().is_some_and(|n| n >= p.epoch),
        "native epoch unassigned"
    );
    let entries = fleet["epochs"]
        .as_array()
        .context("native epoch census")?
        .iter()
        .filter(|e| e["epoch"] == p.epoch)
        .collect::<Vec<_>>();
    ensure!(
        entries.len() == 1
            && matches!(
                entries[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "native status cannot relabel a ready, replaying or delivery epoch"
    );
    let active = fleet["active"]
        .as_array()
        .context("native active census")?
        .iter()
        .filter(|e| e["epoch"] == p.epoch)
        .collect::<Vec<_>>();
    ensure!(
        active.len() == 1
            && active[0]["phase"] == p.binding.claim_phase
            && active[0]["private_qualification_only"] == true
            && p.binding.live_matches(&active[0]["unit"]),
        "native input overlaps another live epoch owner"
    );
    ensure!(
        p.estimated_remaining_millis > 0
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty(),
        "native input needs a definite all-stage sidecar estimate and evidence"
    );
    let initial = fleet["metadata_event"]["path"].as_str() == p.origin_launch.path.to_str()
        && fleet["metadata_event"]["sha256"] == p.origin_launch.sha256;
    selected_clock(observer, &origin, fleet, initial, now)
}
pub(super) fn matches(
    receipt: &StatusPublicationReceipt,
    epoch: u64,
    census: &BTreeMap<String, Value>,
) -> bool {
    receipt.epoch == epoch
        && receipt.status.phase == "verification"
        && receipt.status.jet_size_bytes == 0
        && receipt.pipeline_binding.as_ref().is_some_and(|b| {
            b.claim_phase == "private-cold-snapshot-verification"
                && b.validate(epoch, "verification").is_ok()
                && census.get(&b.unit).is_some_and(|u| b.live_matches(u))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn native_zero_size_means_absence_not_an_empty_archive_or_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let origin = dir.path().join("registered-origin.json");
        let jet = dir.path().join("epoch-223.jet");
        absent_jet(&jet, &origin, 223, 0).unwrap();
        assert!(absent_jet(&jet, &origin, 227, 0).is_err());
        assert!(absent_jet(&jet, &origin, 223, 1).is_err());
        fs::write(&jet, []).unwrap();
        assert!(absent_jet(&jet, &origin, 223, 0).is_err());
        fs::remove_file(&jet).unwrap();
        std::os::unix::fs::symlink(dir.path().join("missing"), &jet).unwrap();
        assert!(absent_jet(&jet, &origin, 223, 0).is_err());
    }
    #[test]
    fn native_clock_uses_verified_initial_event_then_new_resource_sample() {
        let origin =
            json!({"recorded_unix_seconds":1792774959u64,"sampled_at_utc":"2026-10-23T17:02:39Z"});
        let old = json!({"recorded_at_utc":"2026-10-23T17:00:00Z"});
        let fleet = json!({"recorded_unix_seconds":1792774960u64});
        assert_eq!(
            selected_clock(&old, &origin, &fleet, true, 1792774961).unwrap(),
            "2026-10-23T17:02:39Z"
        );
        assert!(selected_clock(&old, &origin, &fleet, false, 1792774961).is_err());
        let newer = json!({"recorded_at_utc":"2026-10-23T17:14:20Z"});
        let fleet = json!({"recorded_unix_seconds":1792775665u64});
        assert_eq!(
            selected_clock(&newer, &origin, &fleet, false, 1792775666).unwrap(),
            "2026-10-23T17:14:20Z"
        );
        let mut wrong = origin;
        wrong["sampled_at_utc"] = json!("2026-10-23T17:02:38Z");
        assert!(selected_clock(&old, &wrong, &fleet, true, 1792775666).is_err());
    }
}
