//! The original uploader failed after its readback. Its reservation survives this exit.
use super::*;

const BEFORE: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v142-20261120-v1/fleet-v1.json";
const BEFORE_SHA: &str = "30946b66893e1eea952919f6fe2b21fee9d4fc520a9dfdda43c75040427735c4";
const AFTER: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v143-20261120-v1/fleet-v1.json";
const AFTER_SHA: &str = "72560e837f9c269c135bdca23070d0863c3a24f2627d1e5aa24426d120bc3b37";
const FRAGMENT: &str = "/run/systemd/transient/horizon-upload-247-singleton-20261119-v1.service";
const FRAGMENT_SHA: &str = "8fda7cae77e9442f0801b1e6c0843e914e24b2ec629c4ba729d0ab6242a7d6ff";
const JOURNAL_FIELDS: &str = "_PID,_UID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,MESSAGE,EXIT_CODE,EXIT_STATUS,UNIT_RESULT,__MONOTONIC_TIMESTAMP";

pub(super) fn witness() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../fixtures/terminal-delivery247-v143.json"
    ))?)
}
pub(super) fn booking() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon-singleton211-bookings-v133-20261120-v1/booking-delivery247.json",
        "aeb7e93b51a8d8a6dc3ba31f00f79c56e65fbcb7ec3afffecf39bb5c3f148f5d",
    )
}
pub(super) fn fleet_owner(e: &Value) -> Result<()> {
    let proof = witness()?;
    terminal_census(&e["unit"], &proof)?;
    ensure!(
        e["finalization_evidence"].is_null() && e["current_sidecar_eta_valid"] == false,
        "original epoch247 terminal pipeline claims changed"
    );
    Ok(())
}

fn transition(before: &Value, after: &Value, e: &Value) -> Result<()> {
    let proof = witness()?;
    let change = &proof["transition"];
    ensure!(
        after["previous_fleet"] == json!(Bound::new(BEFORE, BEFORE_SHA))
            && after["transitions"]
                .as_array()
                .context("terminal changes")?
                .iter()
                .filter(|t| t["unit"] == UNIT247)
                .eq(std::iter::once(change)),
        "original epoch247 exit transition changed"
    );
    for (fleet, phase, live) in [(before, "before", true), (after, "after", false)] {
        let mut expected = e.clone();
        expected["sampled_at_utc"] = fleet["sampled_at_utc"].clone();
        expected["unit"] = change[phase].clone();
        expected["live"] = json!(live);
        ensure!(
            fleet["unit_census"][UNIT247] == change[phase]
                && fleet["pipelines"]
                    .as_array()
                    .context("original pipeline census")?
                    .iter()
                    .filter(|p| related(p))
                    .eq(std::iter::once(&expected))
                && fleet["active"]
                    .as_array()
                    .context("original active census")?
                    .iter()
                    .filter(|p| related(p))
                    .eq(live.then_some(&expected)),
            "original epoch247 {phase} census changed"
        );
    }
    Ok(())
}
pub(super) fn verify_evidence(e: &Value) -> Result<()> {
    booking().sealed()?;
    transition(
        &Bound::new(BEFORE, BEFORE_SHA).json()?,
        &Bound::new(AFTER, AFTER_SHA).json()?,
        e,
    )
}

fn manager(current: &Value, proof: &Value) -> Result<()> {
    terminal_census(current, proof)?;
    for (field, expected) in proof["manager"]
        .as_object()
        .context("terminal manager properties")?
    {
        ensure!(
            &current[field] == expected,
            "original epoch247 manager changed {field}"
        );
    }
    Ok(())
}
fn terminal_census(current: &Value, proof: &Value) -> Result<()> {
    for (field, expected) in proof["transition"]["after"]
        .as_object()
        .context("terminal fleet properties")?
    {
        // PID1 can clear the ExecStart display history on daemon reload. Only the
        // exact empty history of the same command is accepted alongside the
        // original PID1 journal and independent execution timestamps.
        let cleared =
            field == "ExecStart" && current[field] == proof["transition"]["before"][field];
        ensure!(
            &current[field] == expected || cleared,
            "epoch247 terminal identity changed {field}"
        );
    }
    Ok(())
}
fn journal(bytes: &[u8], proof: &Value) -> Result<()> {
    let rows: Vec<_> = std::str::from_utf8(bytes)?
        .lines()
        .map(|line| -> Result<Value> {
            let mut event: Value = serde_json::from_str(line)?;
            event
                .as_object_mut()
                .context("PID1 event")?
                .retain(|field, _| JOURNAL_FIELDS.split(',').any(|k| k == field));
            Ok(event)
        })
        .collect::<Result<_>>()?;
    ensure!(
        json!(rows) == proof["journal"],
        "epoch247 original PID1 start, exit or result changed"
    );
    Ok(())
}

pub(super) fn observe(n: &mut Native, current: &Value) -> Result<()> {
    let proof = witness()?;
    manager(current, &proof)?;
    Bound::new(FRAGMENT, FRAGMENT_SHA).bytes(false)?;
    let journal_bytes = n.run(
        "/usr/bin/journalctl",
        &[
            "--boot=0",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT247}"),
            &format!("INVOCATION_ID={IID247}"),
            "--output=json",
            &format!("--output-fields={JOURNAL_FIELDS}"),
            "--no-pager",
        ],
    )?;
    journal(&journal_bytes, &proof)?;
    live::verify_drained_group(UNIT247)?;
    n.check()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry() -> Value {
        let w = witness().unwrap();
        json!({"epoch":247,"phase":"upload-readback","live":false,"expected_invocation_id":IID247,
            "unit":w["transition"]["after"],"sampled_at_utc":"2026-11-20T18:37:44Z",
            "ordinary_replay_claim":false,"finalization_evidence":null,"current_sidecar_eta_valid":false,
            "grants_launch_or_publication_authority":false,"evidence":[Bound::new(REVIEW,REVIEW_SHA),Bound::new(FLEET_OWNER,FLEET_OWNER_SHA)]})
    }
    fn row() -> capacity::Reservation {
        capacity::Reservation {
            unit: UNIT247.into(),
            invocation_id: IID247.into(),
            maximum_memory_bytes: 7_000_000_000,
            remaining_disk_growth_bytes: 185_370_916_960,
            minimum_free_bytes: 3_000_000_000_000,
            source: booking(),
            release: None,
        }
    }
    fn fleet(e: &Value) -> Value {
        json!({"pipelines":[e],"active":[],"unit_census":{(UNIT247):e["unit"]},"sampled_at_utc":e["sampled_at_utc"]})
    }
    #[test]
    fn v144_original_exit_retains_one_complete_booking_and_no_live_owner() {
        let e = entry();
        let f = fleet(&e);
        validate_roster(&f, &[row()]).unwrap();
        for key in [
            "Id",
            "InvocationID",
            "MainPID",
            "ExecStart",
            "ControlGroup",
            "ActiveState",
            "Result",
            "ExecMainStatus",
            "NRestarts",
        ] {
            let mut bad = e.clone();
            bad["unit"][key] = json!("changed");
            assert!(validate_roster(&fleet(&bad), &[row()]).is_err(), "{key}");
        }
        for field in [
            "evidence",
            "live",
            "expected_invocation_id",
            "phase",
            "current_sidecar_eta_valid",
            "grants_launch_or_publication_authority",
        ] {
            let mut bad = e.clone();
            bad[field] = Value::Null;
            assert!(validate_roster(&fleet(&bad), &[row()]).is_err(), "{field}");
        }
        for (field, value) in [
            ("pipelines", json!([])),
            ("pipelines", json!([e, e])),
            ("active", json!([e])),
            ("active", json!([{"epoch":247,"phase":"replay"}])),
            ("active", json!([{"epoch":999,"producer":{"Id":UNIT247}}])),
        ] {
            let mut bad = f.clone();
            bad[field] = value;
            assert!(validate_roster(&bad, &[row()]).is_err(), "{field}");
        }
        assert!(validate_roster(&f, &[]).is_err());
        assert!(validate_roster(&f, &[row(), row()]).is_err());
        let mut released = row();
        released.release = Some(booking());
        assert!(validate_roster(&f, &[released]).is_err());
        let mut wrong_source = row();
        wrong_source.source.sha256 = "0".repeat(64);
        assert!(validate_roster(&f, &[wrong_source]).is_err());
    }
    fn events(rows: &Value) -> Vec<u8> {
        rows.as_array()
            .unwrap()
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }
    #[test]
    fn original_pid1_and_manager_evidence_is_required_after_readback() {
        let w = witness().unwrap();
        let mut owner = w["transition"]["after"].clone();
        owner
            .as_object_mut()
            .unwrap()
            .extend(w["manager"].as_object().unwrap().clone());
        manager(&owner, &w).unwrap();
        owner["ExecStart"] = w["transition"]["before"]["ExecStart"].clone();
        manager(&owner, &w).unwrap();
        for key in [
            "ExecMainCode",
            "ControlPID",
            "Job",
            "FragmentPath",
            "DropInPaths",
            "ExecMainExitTimestampMonotonic",
            "Restart",
            "MemoryMax",
        ] {
            let mut bad = owner.clone();
            bad[key] = json!("changed");
            assert!(manager(&bad, &w).is_err(), "{key}");
        }
        journal(&events(&w["journal"]), &w).unwrap();
        for (index, field) in [
            (0, "_PID"),
            (1, "_BOOT_ID"),
            (1, "INVOCATION_ID"),
            (1, "EXIT_STATUS"),
            (2, "UNIT_RESULT"),
            (3, "__MONOTONIC_TIMESTAMP"),
        ] {
            let mut bad = w["journal"].clone();
            bad[index][field] = json!("changed");
            assert!(journal(&events(&bad), &w).is_err(), "{field}");
        }
        let mut missing = w["journal"].clone();
        missing.as_array_mut().unwrap().remove(1);
        assert!(journal(&events(&missing), &w).is_err());
        let e = entry();
        let after = fleet(&e);
        let mut live = e.clone();
        live["live"] = json!(true);
        live["unit"] = w["transition"]["before"].clone();
        let mut before = fleet(&live);
        before["active"] = json!([live]);
        let mut receipt = after.clone();
        receipt["previous_fleet"] = json!(Bound::new(BEFORE, BEFORE_SHA));
        receipt["transitions"] = json!([w["transition"]]);
        transition(&before, &receipt, &e).unwrap();
        receipt["transitions"][0]["before"]["MainPID"] = json!("0");
        assert!(transition(&before, &receipt, &e).is_err());
    }

    #[test]
    #[ignore = "requires the original host, root-read evidence and a fresh private capture directory"]
    fn original_v144_manager_journal_and_full_booking_on_host() -> Result<()> {
        let fleet = Bound::new(
            "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v144-20261120-v1/fleet-v1.json",
            "0e67d36186987d4332c508b3d1318f6923a1b0275d8825662ebb7305c314ad9f",
        )
        .json()?;
        let packet = Bound::new("/var/lib/jetstreamer/horizon-native257-current-bookings-v144-ops-v1/current-ledger.json",
            "82fa5c89127a1e54e36366682a42a3abd1edd570d99b507b7b9b807f7d1eae3e").sealed()?;
        let rows: Vec<capacity::Reservation> =
            serde_json::from_value(packet["reservations"].clone())?;
        validate_roster(&fleet, &rows)?;
        let e = fleet["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| selected(e))
            .context("original delivery")?;
        verify_inputs(e)?;
        let root = PathBuf::from(std::env::var("HORIZON247_TERMINAL_CAPTURE")?);
        fs::create_dir(&root)?;
        let mut n = Native {
            root,
            counter: 0,
            deadline: None,
        };
        for _ in 0..2 {
            let current = n.show(UNIT247)?;
            observe(&mut n, &current)?;
        }
        Ok(())
    }
}
