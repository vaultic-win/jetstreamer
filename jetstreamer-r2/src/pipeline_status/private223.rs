//! Same-observation status for exact private 223 assembly and independent scans.
//! Uses the normal pipeline publisher and inactive lifecycle, never another loop.
use super::*;
use serde_json::json;
pub(super) fn selected(p: &Plan) -> bool {
    p.epoch == 223 && fleet::private223_status_scope(&p.binding.claim_phase, &p.binding.unit)
}
pub(super) fn validate_origin(p: &Plan, r: &Value, f: &Value) -> Result<()> {
    ensure!(
        selected(p)
            && p.phase == "verification"
            && p.peer_units.is_empty()
            && p.phase_handoff_event.is_none()
            && p.binding.origin_unit == p.binding.unit
            && p.binding.origin_invocation_id == p.binding.invocation_id,
        "private 223 status owner/clock/phase differs"
    );
    let jet = fleet::private223_status_origin(
        &p.binding.claim_phase,
        &p.binding.unit,
        &p.binding.invocation_id,
        r,
        &json!({"path":p.origin_launch.path,"sha256":p.origin_launch.sha256}),
        f,
    )?;
    ensure!(
        p.jet_path == jet
            && r["producer_at_capture"]["InvocationID"] == p.binding.invocation_id
            && r["producer_at_capture"]["ExecStart"]
                .as_str()
                .is_some_and(|s| same_exec_start(s, &p.binding.expected_exec_start))
            && r["producer_limits_at_capture"]["ExecMainStartTimestampMonotonic"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n > 0),
        "private 223 status archive or captured invocation differs"
    );
    Ok(())
}
pub(super) fn sample(p: &Plan, o: &Value, f: &Value, now: u64) -> Result<String> {
    let origin = bound_json(&p.origin_launch)?;
    validate_origin(p, &origin, f)?;
    ensure!(
        f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["inventory"]["anomalies"] == 0
            && p.estimated_remaining_millis > 0
            && !p.estimate_basis.trim().is_empty()
            && !p.estimate_evidence.is_empty(),
        "private 223 status lacks accepted sample or inclusive sidecar estimate"
    );
    let epochs = f["epochs"]
        .as_array()
        .context("private 223 complete epoch census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        epochs.len() == 1
            && matches!(
                epochs[0]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "private 223 status cannot relabel ready or delivery work"
    );
    let active = f["active"]
        .as_array()
        .context("private 223 complete active census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
        .collect::<Vec<_>>();
    ensure!(
        active.len() == 1
            && active[0]["phase"] == p.binding.claim_phase
            && active[0]["ordinary_replay_claim"] == false
            && (p.binding.live_matches(&active[0]["producer"])
                || p.binding.live_matches(&active[0]["unit"])),
        "private 223 status has overlapping or changed work"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("private 223 observer replay census")?
        .iter()
        .filter(|r| {
            r["range"] == "223-223"
                && r["producer_unit"] == p.binding.unit
                && r["expected_producer_invocation_id"] == p.binding.invocation_id
        })
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["status"] == "observed"
            && rows[0]["error"].is_null()
            && rows[0]["observation"]["invocation_binding_stable"] == true
            && rows[0]["observation"]["worker_before"]["private_archive_parent"]["ordinary_replay_worker"]
                == false
            && rows[0]["observation"]["worker_after"]["private_archive_parent"]["ordinary_replay_worker"]
                == false,
        "private 223 status lacks typed same-observation parent telemetry"
    );
    let archive = &rows[0]["observation"]["worker_after"]["private_archive_parent"];
    ensure!(
        archive["archive_path"].as_str() == p.jet_path.to_str()
            && archive["archive_snapshot"]["length"].as_u64().unwrap_or(0)
                == p.expected_jet_size_bytes,
        "private 223 status bytes differ from same-observation archive snapshot"
    );
    let sample = o["recorded_at_utc"]
        .as_str()
        .context("private 223 observation clock")?;
    let t = fleet::utc_seconds(sample)?;
    ensure!(
        t <= now
            && now - t <= 1800
            && f["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|s| s >= t && s <= now),
        "private 223 status sample stale or future"
    );
    Ok(sample.into())
}
pub(super) fn jet_identity(p: &Plan) -> Result<Option<FileIdentity>> {
    ensure!(
        p.jet_path
            .parent()
            .is_some_and(|d| d.canonicalize().is_ok_and(|c| c == d)),
        "private 223 status archive parent redirected"
    );
    let o = bound_json(&p.observer)?;
    let owners = o["diagnostic_replays"]
        .as_array()
        .context("private 223 status archive owner census")?
        .iter()
        .filter(|r| {
            r["range"] == "223-223"
                && r["producer_unit"] == p.binding.unit
                && r["expected_producer_invocation_id"] == p.binding.invocation_id
                && r["status"] == "observed"
        })
        .collect::<Vec<_>>();
    ensure!(
        owners.len() == 1,
        "private 223 status archive snapshot owner differs"
    );
    let snapshot =
        &owners[0]["observation"]["worker_after"]["private_archive_parent"]["archive_snapshot"];
    ensure!(
        snapshot.is_object()
            || (snapshot.is_null()
                && p.binding.claim_phase == "private-assembly-only"
                && p.expected_jet_size_bytes == 0),
        "private 223 status archive snapshot missing"
    );
    match fs::symlink_metadata(&p.jet_path) {
        Ok(m) => {
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.mode() & 0o777 == 0o600
                    && m.len() <= 160u64 << 30,
                "private 223 status archive ownership/type/envelope differs"
            );
            if snapshot.is_null() {
                return Ok(None);
            }
            ensure!(
                snapshot["device"] == m.dev() && snapshot["inode"] == m.ino(),
                "private 223 status archive replaced since observation"
            );
            let mut id = regular_identity(&p.jet_path)?;
            if p.binding.claim_phase == "private-assembly-only" {
                // Exact d147 assembler is append-only. Preserve sampled bytes
                // while tolerating subsequent growth by that same live owner.
                ensure!(
                    id.length >= p.expected_jet_size_bytes,
                    "private 223 assembly shrank below sampled length"
                );
                id.length = p.expected_jet_size_bytes;
                id.modified_seconds = 0;
                id.modified_nanoseconds = 0;
            } else {
                ensure!(
                    id.length == p.expected_jet_size_bytes,
                    "private 223 retained assembly length changed"
                );
            }
            Ok(Some(id))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(
                p.binding.claim_phase == "private-assembly-only"
                    && p.expected_jet_size_bytes == 0
                    && snapshot.is_null(),
                "private 223 source unexpectedly missing"
            );
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}
pub(super) fn matches(
    r: &StatusPublicationReceipt,
    epoch: u64,
    c: &BTreeMap<String, Value>,
) -> bool {
    epoch == 223
        && r.epoch == 223
        && r.status.phase == "verification"
        && r.pipeline_binding.as_ref().is_some_and(|b| {
            fleet::private223_status_scope(&b.claim_phase, &b.unit)
                && b.validate(epoch, "verification").is_ok()
                && c.get(&b.unit).is_some_and(|u| b.live_matches(u))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(phase: &str, unit: &str) -> Binding {
        Binding {
            unit: unit.into(),
            invocation_id: "1".repeat(32),
            expected_exec_start: "actual command".into(),
            claim_phase: phase.into(),
            origin_unit: unit.into(),
            origin_invocation_id: "1".repeat(32),
            model_path: "/private/model.json".into(),
            model_sha256: "a".repeat(64),
            fleet_path: "/private/fleet.json".into(),
            fleet_sha256: "b".repeat(64),
        }
    }
    #[test]
    fn status_and_inactive_binding_are_closed_to_exact_private_223_owners() {
        for (phase, unit) in [
            (
                "private-assembly-only",
                "horizon-assemble-223-native20-native25-v1.service",
            ),
            (
                "private-verification-only",
                "horizon-verify-223-native20-native25-private-v3-v1.service",
            ),
        ] {
            let b = binding(phase, unit);
            b.validate(223, "verification").unwrap();
            assert!(b.validate(224, "verification").is_err());
            assert!(b.validate(223, "replay").is_err());
            let mut bad = b.clone();
            bad.origin_invocation_id = "2".repeat(32);
            assert!(bad.validate(223, "verification").is_err());
            let mut bad = b;
            bad.unit = "horizon-assemble-224-native20-native25-v1.service".into();
            assert!(bad.validate(223, "verification").is_err());
        }
    }
}
