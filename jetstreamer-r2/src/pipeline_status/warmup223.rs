//! Actual bounded entry replay under qualification; never a zero-entry test.
use super::*;
const UNIT: &str = "horizon-qualify-223-v1620-warmup-resource-d15ee08b-v1.service";
const UNITS: [&str; 2] = [
    UNIT,
    "horizon-qualify-223-v1620-warmup-resource-8457f800-v2.service",
];
pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 223
        && p.binding.claim_phase == "private-warmup-reproduction"
        && UNITS.contains(&p.binding.unit.as_str())
}
pub(super) fn validate_origin(p: &Plan, r: &Value, f: &Value) -> Result<()> {
    ensure!(
        selected(p)
            && p.phase == "verification"
            && p.peer_units.is_empty()
            && p.phase_handoff_event.is_none(),
        "warmup status profile differs"
    );
    let fp = bound_json(&Bound {
        path: f["plan"].as_str().context("warmup fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("warmup plan digest")?
            .into(),
    })?;
    let claims = fp["pipeline_claims"]
        .as_array()
        .context("warmup accepted claims")?
        .iter()
        .filter(|c| {
            c["epoch"] == 223
                && c["unit"] == p.binding.unit
                && c["invocation_id"] == p.binding.invocation_id
                && c["phase"] == p.binding.claim_phase
        })
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "warmup status needs one exact registered claim"
    );
    fleet::validate_warmup223_status_claim(claims[0])?;
    ensure!(
        claims[0]["evidence"]
            .as_array()
            .is_some_and(|a| a.len() == 1
                && a[0]["path"].as_str() == p.origin_launch.path.to_str()
                && a[0]["sha256"] == p.origin_launch.sha256)
            && claims[0]["expected_exec_start"]
                .as_str()
                .is_some_and(|s| same_exec_start(s, &p.binding.expected_exec_start))
            && r["invocation_id"] == p.binding.invocation_id
            && r["entry_replay"] == true
            && r["public_sidecar_countdown_authorized"] == true
            && r["resource_samples_taken"] == 0
            && r["ordinary_replay_claim"] == false
            && r["publication_authorized"] == false
            && r["remote_mutations"] == false
            && r["r2_mutations"] == false,
        "warmup origin must truthfully identify its bounded entry execution and deny archive authority"
    );
    ensure!(
        p.binding.origin_unit == p.binding.unit
            && p.binding.origin_invocation_id == p.binding.invocation_id,
        "warmup clock changed"
    );
    for name in ["resource.json", "failure.json"] {
        let root = fleet::warmup223_status_jet_path(&p.binding.unit)?
            .parent()
            .context("warmup output parent")?
            .parent()
            .context("warmup root")?
            .to_owned();
        ensure!(
            fs::symlink_metadata(root.join("receipts").join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "warmup reached terminal handoff; reconcile status lifecycle"
        );
    }
    jet_identity(p)?;
    Ok(())
}
pub(super) fn jet_identity(p: &Plan) -> Result<Option<FileIdentity>> {
    ensure!(
        p.jet_path == fleet::warmup223_status_jet_path(&p.binding.unit)?,
        "warmup jet path differs"
    );
    optional_jet(&p.jet_path, p.expected_jet_size_bytes)
}
fn optional_jet(path: &Path, expected: u64) -> Result<Option<FileIdentity>> {
    ensure!(
        path.is_absolute()
            && path
                .parent()
                .is_some_and(|p| p.canonicalize().is_ok_and(|v| v == p)),
        "warmup jet parent is not canonical"
    );
    match fs::symlink_metadata(path) {
        Ok(_) => {
            let i = regular_identity(path)?;
            ensure!(i.length == expected, "warmup current jet length differs");
            Ok(Some(i))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(expected == 0, "warmup absent jet has nonzero model bytes");
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}
pub(super) fn sample(p: &Plan, o: &Value, f: &Value, now: u64) -> Result<String> {
    let origin = bound_json(&p.origin_launch)?;
    validate_origin(p, &origin, f)?;
    ensure!(
        f["sampled_at_utc"] == o["recorded_at_utc"] && f["inventory"]["anomalies"] == 0,
        "warmup observation differs"
    );
    ensure!(
        f["first_epoch"].as_u64().is_some_and(|n| n <= 223)
            && f["last_epoch"].as_u64().is_some_and(|n| n >= 223),
        "warmup epoch is unassigned"
    );
    let entries = f["epochs"]
        .as_array()
        .context("warmup epoch census")?
        .iter()
        .filter(|e| e["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        entries.len() == 1
            && matches!(
                entries[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "warmup cannot relabel ready or delivery work"
    );
    let active = f["active"]
        .as_array()
        .context("warmup active census")?
        .iter()
        .filter(|e| e["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        active.len() == 1
            && active[0]["phase"] == p.binding.claim_phase
            && active[0]["private_qualification_only"] == true
            && p.binding.live_matches(&active[0]["unit"]),
        "warmup status overlaps another owner"
    );
    ensure!(
        p.estimated_remaining_millis > 0
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty(),
        "warmup needs an evidence-backed all-stage sidecar estimate"
    );
    let initial = f["metadata_event"]["path"].as_str() == p.origin_launch.path.to_str()
        && f["metadata_event"]["sha256"] == p.origin_launch.sha256;
    native_input::selected_clock(o, &origin, f, initial, now)
}
pub(super) fn matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    c: &BTreeMap<String, Value>,
) -> bool {
    r.epoch == 223
        && epoch == 223
        && r.status.phase == "verification"
        && r.pipeline_binding.as_ref().is_some_and(|b| {
            UNITS.contains(&b.unit.as_str())
                && b.claim_phase == "private-warmup-reproduction"
                && b.validate(epoch, "verification").is_ok()
                && c.get(&b.unit).is_some_and(|u| b.live_matches(u))
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_bounded_work_can_have_missing_empty_or_growing_regular_jet_but_never_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("epoch-223.jet");
        assert!(optional_jet(&p, 0).unwrap().is_none());
        assert!(optional_jet(&p, 1).is_err());
        fs::write(&p, []).unwrap();
        assert_eq!(optional_jet(&p, 0).unwrap().unwrap().length, 0);
        fs::write(&p, b"header").unwrap();
        assert_eq!(optional_jet(&p, 6).unwrap().unwrap().length, 6);
        assert!(optional_jet(&p, 0).is_err());
        fs::remove_file(&p).unwrap();
        std::os::unix::fs::symlink(t.path().join("missing"), &p).unwrap();
        assert!(optional_jet(&p, 0).is_err());
    }
}
