//! The full epoch 211 invocation retained by later admissions.
use super::*;

const RECEIPT: &str = "/var/lib/jetstreamer/horizon-singleton211-execution-launch-v133-v1/guarded-startup-handoff.json";
const RECEIPT_SHA: &str = "e020a85afd55cd04afdc9d1a3366c63723788993833ae01eb6c8b67e8d679487";
const PLAN: &str =
    "/var/lib/jetstreamer/horizon-singleton211-guard-binding-full-v133-a/guard-plan.json";
pub(super) const ATTEMPT: &str = "full-v133-a";
const LAUNCHER_SHA: &str = "169a553cb0298a9ed2e29574767ad637fb765e9f0347f0432cbe3a077d5da72f";
pub(super) const IID: &str = "49ea83a3a5e94e99af51153d2fd79e92";
pub(super) fn handoff() -> Bound {
    Bound::new(RECEIPT, RECEIPT_SHA)
}
pub(super) fn control() -> periodic::Control {
    let package = launch::package(ATTEMPT, "guard-units");
    periodic::Control {
        unit: GUARD_UNIT.into(),
        timer: TIMER.into(),
        maximum_memory_bytes: 268435456,
        service_source: Bound::new(
            package.join(GUARD_UNIT),
            "58e338ae44ba2893d98a99c4218075f9d73ea3fbe65784c857aec3e62e8adbda",
        ),
        timer_source: Bound::new(
            package.join(TIMER),
            "e0b1485bf4f8d1b89c47e82e3d4510e0d3b2ae7668bcadc6bfd6a39dcbc846d0",
        ),
        guard_plan: Bound::new(
            PLAN,
            "c1b0c00364ac04dba153db09dc0515d0566d7f1d3462ed30ef93830057c8bf7f",
        ),
        executable: Bound::new(
            GUARD,
            "6c57429040ec3e059d8f3887d162df4d3228a3282d49a7472cd14910f32361ae",
        ),
    }
}
pub(super) fn active(e: &Value) -> bool {
    e["producer"]["Id"] == UNIT
}
pub(super) fn observed(e: &Value) -> bool {
    e["producer_unit"] == UNIT
}
pub(super) fn registered(fleet: &Value) -> bool {
    fleet["diagnostics"]
        .as_array()
        .is_some_and(|v| v.iter().any(|e| e["unit"]["Id"] == UNIT))
}
pub(super) fn validate(
    fleet: &Value,
    observer: &Value,
    rows: &[capacity::Reservation],
    h: &Value,
    a: &Value,
) -> Result<()> {
    let handoff = handoff();
    let current = &fleet["unit_census"][UNIT];
    live::same_owner(&h["producer"], current)?;
    let diagnostics = fleet["diagnostics"]
        .as_array()
        .context("211 diagnostic census")?;
    ensure!(
        diagnostics.len() == 1,
        "unexpected diagnostic owner with full211"
    );
    let d = &diagnostics[0];
    let claim = |e: &Value| {
        e["epoch"] == 211
            && e["launch_receipt"] == json!(handoff.path)
            && e["launch_receipt_sha256"] == RECEIPT_SHA
            && e["scope_first_epoch"] == 211
            && e["scope_last_epoch"] == 211
    };
    ensure!(
        claim(d) && d["live"] == true && d["unit"] == *current && d["launch_invocation_id"] == IID,
        "full211 diagnostic receipt differs"
    );
    let entries: Vec<_> = fleet["active"]
        .as_array()
        .context("active fleet")?
        .iter()
        .filter(|e| e["epoch"] == 211 || active(e))
        .collect();
    ensure!(
        entries.len() == 1
            && claim(entries[0])
            && entries[0]["producer"] == *current
            && entries[0]["phase"] == "diagnostic-qualification"
            && entries[0]["scratch_path"] == ROOT
            && entries[0]["ordinary_replay_claim"] == false,
        "full211 active owner changed"
    );
    ensure!(
        entries[0]["current_sidecar_eta_valid"] == false
            && entries[0].get("controller").is_none()
            && d["terminal_outcome_requires_canary_receipt"] == false,
        "full211 diagnostic scope differs"
    );
    let inventory: Vec<_> = fleet["inventory"]["entries"]
        .as_array()
        .context("archive inventory")?
        .iter()
        .filter(|e| e["epoch"] == 211)
        .collect();
    ensure!(
        inventory.len() == 1 && inventory[0]["state"] == "missing",
        "full211 overlaps an existing archive or has incomplete inventory"
    );
    ensure!(
        fleet["terminal_replays"]
            .as_array()
            .context("terminal replay census")?
            .iter()
            .all(|e| e["epoch"] != 211 && e["unit"]["Id"] != UNIT),
        "full211 also represented as terminal"
    );
    for r in observer["replays"]
        .as_array()
        .context("ordinary replay observations")?
    {
        let (first, last) = text(r, "range")?
            .split_once('-')
            .context("invalid replay range")?;
        ensure!(
            !(first.parse::<u64>()?..=last.parse::<u64>()?).contains(&211)
                && [
                    "controller_before",
                    "producer_before",
                    "controller_after",
                    "producer_after"
                ]
                .iter()
                .all(|k| r[*k]["unit"] != UNIT && r[*k]["invocation_id"] != IID),
            "full211 also represented as ordinary replay"
        );
    }
    let observed: Vec<_> = observer["diagnostic_replays"]
        .as_array()
        .context("observed diagnostics")?
        .iter()
        .filter(|e| observed(e) || e["range"] == "211-211")
        .collect();
    ensure!(
        observed.len() == 1,
        "incomplete full211 diagnostic observation"
    );
    let d = observed[0];
    let o = &d["observation"];
    ensure!(
        d["range"] == "211-211"
            && d["producer_unit"] == UNIT
            && d["expected_producer_invocation_id"] == IID
            && d["scratch_path"] == ROOT
            && [
                "ordinary_replay_claim",
                "current_sidecar_eta_valid",
                "replay_launch_authorized",
                "publication_authorized",
                "r2_mutations"
            ]
            .iter()
            .all(|k| d[*k] == false)
            && d["status"] == "observed"
            && d["error"].is_null()
            && o["range"] == "211-211"
            && o["scratch_path"] == ROOT
            && o["invocation_binding_stable"] == true
            && o["useful_work"]["journal_invocation_id"] == IID,
        "full211 incomplete or substituted observation"
    );
    for role in [
        "controller_before",
        "producer_before",
        "controller_after",
        "producer_after",
    ] {
        let r = &o[role];
        ensure!(
            r["unit"] == UNIT
                && r["invocation_id"] == IID
                && r["main_pid"] == h["main_pid"]
                && r["load_state"] == "loaded"
                && r["active_state"] == "active"
                && r["sub_state"] == "running"
                && r["restarts"] == 0
                && r["result"] == "success"
                && r["control_group"] == format!("/system.slice/{UNIT}")
                && r["cgroup"]["gauges"]["memory.max"] == (MEMORY / 4096) * 4096
                && r["cgroup"]["gauges"]["memory.swap.max"] == 0,
            "full211 observer limits/owner differ"
        );
    }
    let r: Vec<_> = rows.iter().filter(|r| r.unit == UNIT).collect();
    ensure!(
        r.len() == 1
            && r[0].invocation_id == IID
            && r[0].maximum_memory_bytes == MEMORY
            && r[0].remaining_disk_growth_bytes >= SCRATCH
            && r[0].minimum_free_bytes >= num(a, "protected_existing_floor_bytes")?
            && r[0].release.is_none(),
        "full211 original obligations were reduced or omitted"
    );
    ensure!(
        a["mode"] == "full-replay"
            && a["candidate_incremental_peak_bytes"] == SCRATCH
            && a["maximum_memory_bytes"] == MEMORY
            && h["guard_plan"] == json!(control().guard_plan),
        "full211 original admission changed"
    );
    Ok(())
}
pub(super) fn authenticate(
    n: &mut Native,
    fleet: &Value,
    observer: &Value,
    rows: &[capacity::Reservation],
) -> Result<()> {
    let (h, a) = original_owner(n)?;
    validate(fleet, observer, rows, &h, &a)
}
pub(super) fn original_owner(n: &mut Native) -> Result<(Value, Value)> {
    let h = validate_saved_handoff(Path::new(RECEIPT), RECEIPT_SHA, LAUNCHER_SHA)?;
    let a = binding(&h["admission"])?.sealed()?;
    ensure!(
        text(&a, "boot_id")? == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "full211 handoff belongs to a different boot"
    );
    let plan = binding(&h["startup_plan"])?;
    let review = binding(&a["review"])?.sealed()?;
    let owner = launch::producer(
        n,
        Some(IID),
        &plan,
        &launch::cpus(&review)?,
        LAUNCHER_SHA,
        true,
    )?;
    live::same_owner(&owner, &h["producer"])?;
    let mut argv = vec![NODE.to_owned()];
    argv.extend(launch::node_args());
    ensure!(
        fs::read(format!("/proc/{}/cmdline", num(&h, "main_pid")?))?
            == (argv.join("\0") + "\0").as_bytes(),
        "full211 native replay arguments changed"
    );
    Ok((h, a))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row() -> capacity::Reservation {
        capacity::Reservation {
            unit: UNIT.into(),
            invocation_id: IID.into(),
            maximum_memory_bytes: MEMORY,
            remaining_disk_growth_bytes: SCRATCH,
            minimum_free_bytes: 3_908_104_436_088,
            source: handoff(),
            release: None,
        }
    }

    // Retain the exact observed v134 tuple, including the actual outer diagnostic
    // form, to catch both loosened validation and assumptions about absent fields.
    fn fixture() -> (Value, Value, Value, Value) {
        let projection: Value =
            serde_json::from_str(include_str!("full211_peer_v134.json")).unwrap();
        let h = json!({"producer":projection["owner"],"main_pid":1962046,"guard_plan":control().guard_plan});
        let a = json!({"mode":"full-replay","maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":SCRATCH,"protected_existing_floor_bytes":row().minimum_free_bytes});
        let mut claim = projection["claim"].clone();
        claim["producer"] = projection["owner"].clone();
        let mut diagnostic = projection["diagnostic"].clone();
        diagnostic["unit"] = projection["owner"].clone();
        let fleet = json!({"active":[claim],"diagnostics":[diagnostic],"unit_census":{UNIT:projection["owner"]},"inventory":{"entries":[{"epoch":211,"state":"missing"}]},"terminal_replays":[]});
        let mut d = projection["observed"].clone();
        for role in [
            "producer_before",
            "producer_after",
            "controller_before",
            "controller_after",
        ] {
            d["observation"][role] = projection["observed_owner"].clone();
        }
        (fleet, json!({"replays":[],"diagnostic_replays":[d]}), h, a)
    }

    #[test]
    fn v134_full211_rejects_stale_substituted_and_duplicate_owners() {
        let (f, o, h, a) = fixture();
        validate(&f, &o, &[row()], &h, &a).unwrap();
        let rejected = |f: &Value, o: &Value| assert!(validate(f, o, &[row()], &h, &a).is_err());
        for (path, value) in [
            ("/active/0/launch_receipt_sha256", json!("0".repeat(64))),
            ("/diagnostics/0/live", json!(false)),
            ("/active/0/ordinary_replay_claim", json!(true)),
            ("/active/0/producer/MainPID", json!("1")),
            ("/inventory/entries/0/state", json!("ready-pair")),
            ("/terminal_replays", json!([{"epoch":211}])),
            ("/diagnostics", json!([])),
            ("/active", json!([f["active"][0], f["active"][0]])),
        ] {
            let mut changed = f.clone();
            *changed.pointer_mut(path).unwrap() = value;
            rejected(&changed, &o);
        }
        for (path, value) in [
            ("/diagnostic_replays/0/status", json!("unavailable")),
            ("/diagnostic_replays/0/publication_authorized", json!(true)),
            (
                "/diagnostic_replays/0/observation/controller_after/invocation_id",
                json!("0".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/producer_before/cgroup/gauges/memory.max",
                json!(MEMORY),
            ),
            ("/replays", json!([{"range":"210-212"}])),
            (
                "/diagnostic_replays",
                json!([o["diagnostic_replays"][0], o["diagnostic_replays"][0]]),
            ),
        ] {
            let mut changed = o.clone();
            *changed.pointer_mut(path).unwrap() = value;
            rejected(&f, &changed);
        }
        for rows in [
            vec![],
            vec![row(), row()],
            vec![capacity::Reservation {
                release: Some(handoff()),
                ..row()
            }],
            vec![capacity::Reservation {
                remaining_disk_growth_bytes: SCRATCH - 1,
                ..row()
            }],
            vec![capacity::Reservation {
                maximum_memory_bytes: MEMORY - 1,
                ..row()
            }],
            vec![capacity::Reservation {
                minimum_free_bytes: row().minimum_free_bytes - 1,
                ..row()
            }],
        ] {
            assert!(validate(&f, &o, &rows, &h, &a).is_err());
        }
        let mut h = h;
        h["guard_plan"]["sha256"] = json!("b".repeat(64));
        assert!(validate(&f, &o, &[row()], &h, &a).is_err());
    }

    #[test]
    #[ignore = "reopens the original private v133 handoff, v134 observation and complete fleet"]
    fn original_v134_roster_with_previous_ten_reservations() {
        let f = Bound::new(
            "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v134-20261120-v1/fleet-v1.json",
            "50b4cef884e6268032d36756e893d461d52866d68e3461f80ee06d1da73059b2",
        )
        .json()
        .unwrap();
        let o = Bound::new(
            "/home/ubuntu/.codex/diagnostics/horizon-resume-observer-20261120-v134.json",
            "8c3d80cd6aa3ff0e5802ad3b9f4e71c072c6b6c5aeb10b64b5678a7ad3a0ba4a",
        )
        .json()
        .unwrap();
        let h = validate_saved_handoff(Path::new(RECEIPT), RECEIPT_SHA, LAUNCHER_SHA).unwrap();
        let a = binding(&h["admission"]).unwrap().sealed().unwrap();
        let review = binding(&a["review"]).unwrap().sealed().unwrap();
        let old = binding(&review["reservation_ledger"])
            .unwrap()
            .sealed()
            .unwrap();
        let mut rows: Vec<_> = serde_json::from_value(old["reservations"].clone()).unwrap();
        assert_eq!(rows.len(), 10);
        rows.push(row());
        validate(&f, &o, &rows, &h, &a).unwrap();
        peers::validate(&f, &rows).unwrap();
        finalization::validate_roster(&f, &o, &rows, text(&a, "boot_id").unwrap(), true).unwrap();
        assert!(finalization::validate(&f, &o, &rows, text(&a, "boot_id").unwrap()).is_err());
    }
}
