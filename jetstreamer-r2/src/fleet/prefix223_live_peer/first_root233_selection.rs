//! Intrinsic metadata for the authenticated, first-root-only 233 peer.
//! No caller-supplied invocation or guard choice can create this profile.
use super::*;
use crate::fleet::first_root233 as c;

#[derive(Clone, PartialEq, Eq, Serialize)]
pub(in crate::fleet) struct FirstRoot233GuardProfile {
    pub owner: String,
    pub owner_invocation_id: String,
    pub guard_plan: BoundFile,
    pub authenticated_launch: BoundFile,
}

fn profile(
    f: &Value,
    row: &Value,
    d: &DiagnosticClaim,
    launch: &Value,
    plan: &Value,
) -> Result<FirstRoot233GuardProfile> {
    let owner = singleton227_admission::active_owner(row)?;
    let guard_plan: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
    ensure!(
        d.epoch == 233
            && d.unit == c::UNIT
            && private_prefix::iid(&d.invocation_id)
            && row["epoch"] == 233
            && row["phase"] == "private-known-root-prefix"
            && row["ordinary_replay_claim"] == false
            && row["launch_receipt"].as_str() == d.launch_receipt.path.to_str()
            && row["launch_receipt_sha256"] == d.launch_receipt.sha256
            && owner["Id"] == c::UNIT
            && owner["InvocationID"] == d.invocation_id
            && f["unit_census"][c::UNIT] == *owner
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["NRestarts"] == "0"
            && owner["MainPID"]
                .as_str()
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n > 1)
            && owner["ControlGroup"] == format!("/system.slice/{}", c::UNIT)
            && owner["ExecStart"]
                .as_str()
                .zip(launch["expected_exec_start"].as_str())
                .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b))
            && c::guard_matches(d, launch, plan)
            && guard_plan.path.is_absolute()
            && canonical_digest(&json!(guard_plan.sha256)),
        "first root 233 intrinsic profile changed accepted claim, launch, owner or guard plan"
    );
    Ok(FirstRoot233GuardProfile {
        owner: d.unit.clone(),
        owner_invocation_id: d.invocation_id.clone(),
        guard_plan,
        authenticated_launch: d.launch_receipt.clone(),
    })
}

pub(in crate::fleet) fn first_root233_guard_selection_profiles(
    f: &Value,
) -> Result<BTreeMap<String, FirstRoot233GuardProfile>> {
    // Keep the complete original census and closed-profile overlap checks.
    without(f)?;
    let mut result = BTreeMap::new();
    for row in rows(f)? {
        if singleton227_admission::active_owner(row)?["Id"] != c::UNIT {
            continue;
        }
        // This reads the exact accepted Plan claim and checks the captured
        // launch, including admission, native inputs and first-root-only gates.
        let (d, launch) = claim(f, row)?;
        live(&d, singleton227_admission::active_owner(row)?)?;
        let binding: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
        let plan = native209::immutable_json(&binding)?;
        let selected = profile(f, row, &d, &launch, &plan)?;
        ensure!(
            result.insert(d.unit, selected).is_none(),
            "first root 233 duplicate intrinsic guard profile"
        );
    }
    Ok(result)
}

#[cfg(test)]
fn inputs() -> (DiagnosticClaim, Value, Value, Value, Value) {
    let (d, mut launch) = c::launch_fixture();
    launch["guard_plan"] = json!({"path":"/sealed/guard233.json","sha256":"d".repeat(64)});
    launch["guard_minimum_free_bytes"] = json!(2_000_000_000_000u64);
    let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1",
        "unit":c::UNIT,"invocation_id":d.invocation_id,"filesystem":"/","worker_root":c::ROOT,
        "receipt_directory":c::GUARD_RECEIPTS,"minimum_free_bytes":launch["guard_minimum_free_bytes"],
        "maximum_root_physical_bytes":437_438_953_472u64,"maximum_worker_vmas":3500000});
    let row = json!({"epoch":233,"phase":"private-known-root-prefix","ordinary_replay_claim":false,
        "launch_receipt":d.launch_receipt.path,"launch_receipt_sha256":d.launch_receipt.sha256,
        "producer":{"Id":c::UNIT,"InvocationID":d.invocation_id,"MainPID":"42","NRestarts":"0",
            "ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{}",c::UNIT),
            "ExecStart":launch["expected_exec_start"]}});
    let f = json!({"active":[row],"unit_census":{(c::UNIT):row["producer"]}});
    (d, launch, plan, row, f)
}

#[cfg(test)]
pub(in crate::fleet) fn fixture() -> (Value, FirstRoot233GuardProfile) {
    let (d, launch, plan, row, f) = inputs();
    let p = profile(&f, &row, &d, &launch, &plan).unwrap();
    (row, p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_root233_intrinsic_profile_binds_claim_launch_raw_owner_and_guard_without_promotion() {
        let (d, launch, plan, row, f) = inputs();
        let p = profile(&f, &row, &d, &launch, &plan).unwrap();
        assert_eq!(p.owner_invocation_id, d.invocation_id);
        assert_eq!(p.authenticated_launch, d.launch_receipt);
        assert_eq!(p.guard_plan.sha256, "d".repeat(64));
        assert_eq!(roster(&f).unwrap(), BTreeSet::from([c::UNIT.to_owned()]));
        assert_eq!(launch["full_epoch_qualified"], false);
        assert_eq!(launch["ordinary_replay_authorized"], false);
        for pointer in [
            "/launch_receipt",
            "/launch_receipt_sha256",
            "/phase",
            "/ordinary_replay_claim",
            "/producer/InvocationID",
            "/producer/MainPID",
            "/producer/ControlGroup",
            "/producer/ExecStart",
            "/producer/NRestarts",
        ] {
            let mut bad = row.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(profile(&f, &bad, &d, &launch, &plan).is_err(), "{pointer}");
        }
        let mut replaced = f.clone();
        replaced["unit_census"][c::UNIT]["InvocationID"] = json!("e".repeat(32));
        assert!(profile(&replaced, &row, &d, &launch, &plan).is_err());
        for (key, value) in [
            ("worker_root", json!("/foreign")),
            ("invocation_id", json!("e".repeat(32))),
            ("receipt_directory", json!("/foreign")),
            ("maximum_root_physical_bytes", json!(1)),
            ("native_main", json!({"borrowed":true})),
        ] {
            let mut bad = plan.clone();
            bad[key] = value;
            assert!(profile(&f, &row, &d, &launch, &bad).is_err(), "{key}");
        }
        for (key, value) in [
            ("full_epoch_qualified", json!(true)),
            ("ordinary_replay_authorized", json!(true)),
            ("candidate_incremental_disk_reservation_bytes", json!(1)),
            ("maximum_memory_bytes", json!(1)),
            ("terminal_root_slot", json!(101087999)),
            ("worker_sha256", json!("e".repeat(64))),
        ] {
            let mut bad = launch.clone();
            bad[key] = value;
            assert!(profile(&f, &row, &d, &bad, &plan).is_err(), "{key}");
        }
    }

    #[test]
    fn first_root233_resources_reserve_full_disk_and_remaining_hard_cap_without_rss_credit() {
        let (d, mut launch, _, _, _) = inputs();
        let cap = c::MEMORY / 4096 * 4096;
        let charge = 80_000_000_000u64;
        assert_eq!(disk_reservation(&d, &launch).unwrap(), c::DISK_RESERVATION);
        for rss in [0, 1, 150_000_000_000u64] {
            launch["observed_peak_rss_bytes"] = json!(rss);
            launch["observed_scratch_bytes"] = json!(rss);
            assert_eq!(
                memory_obligation(&d, &launch, cap, charge, 0, 4096).unwrap(),
                cap - charge + (1u64 << 30)
            );
            assert_eq!(disk_reservation(&d, &launch).unwrap(), c::DISK_RESERVATION);
        }
        for (max, used, swap, page) in [
            (cap - 4096, charge, 0, 4096),
            (cap + 4096, charge, 0, 4096),
            (cap, cap + 1, 0, 4096),
            (cap, charge, 1, 4096),
            (cap, charge, 0, 0),
            (cap, charge, 0, 5000),
        ] {
            assert!(memory_obligation(&d, &launch, max, used, swap, page).is_err());
        }
        let mut bad = launch.clone();
        bad["maximum_memory_bytes"] = json!(1);
        assert!(memory_obligation(&d, &bad, cap, charge, 0, 4096).is_err());
        let mut bad = launch;
        bad["candidate_incremental_disk_reservation_bytes"] = json!(1);
        assert!(disk_reservation(&d, &bad).is_err());
    }

    #[test]
    fn first_root233_selected_guard_is_accepted_by_the_full210_resource_consumer() {
        let (d, launch, plan, _, _) = inputs();
        let sha = launch["guard_plan"]["sha256"].as_str().unwrap();
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "plan":launch["guard_plan"]["path"],"plan_sha256":sha,"guard_sha256":c::GUARD_SHA,
            "recorded_unix_seconds":1000,"producer_invocation_id":d.invocation_id,
            "producer":{"invocation_id":d.invocation_id,"restarts":0,"active":"active","sub":"running",
                "cgroup":format!("/system.slice/{}",c::UNIT),"kill_mode":"control-group","delegated":false},
            "producer_stop_enabled":true,"minimum_free_bytes":plan["minimum_free_bytes"],
            "available_bytes":plan["minimum_free_bytes"],"maximum_worker_vmas":3500000,
            "maximum_root_physical_bytes":plan["maximum_root_physical_bytes"],
            "root_physical_observation":{"maximum_physical_bytes":plan["maximum_root_physical_bytes"],
                "exceeds_budget":false,"conservative_physical_bytes":123},"workers":[[42,100]],
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,
            "canary_target_error":null,"target_handoff_error":null,"remote_mutations":false,"r2_mutations":false});
        guard_shape(&d, &launch, &plan, &g, sha, 900, 1000).unwrap();
        for (pointer, value) in [
            ("/guard_sha256", json!("e".repeat(64))),
            ("/plan", json!("/foreign.json")),
            ("/plan_sha256", json!("e".repeat(64))),
            ("/producer/invocation_id", json!("e".repeat(32))),
            ("/producer/cgroup", json!("/system.slice/foreign.service")),
            ("/producer/delegated", json!(true)),
            ("/producer_stop_enabled", json!(false)),
            ("/trip_reason", json!("disk-floor")),
            ("/available_bytes", json!(0)),
            (
                "/root_physical_observation/conservative_physical_bytes",
                json!(437_438_953_473u64),
            ),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard_shape(&d, &launch, &plan, &bad, sha, 900, 1000).is_err(),
                "{pointer}"
            );
        }
        assert!(guard_shape(&d, &launch, &plan, &g, sha, 1001, 1001).is_err());
        assert!(guard_shape(&d, &launch, &plan, &g, sha, 900, 2801).is_err());
    }
}
