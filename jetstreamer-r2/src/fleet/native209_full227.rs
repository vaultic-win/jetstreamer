//! Preserve the live full227 owner while admitting the distinct native209 job.
use super::singleton227 as c;
use super::*;

fn full_owner(row: &Value) -> Result<bool> {
    let owner = singleton227_admission::active_owner(row)?;
    if owner["Id"] == singleton227_admission::NATIVE_UNIT {
        return Ok(false);
    }
    if owner["Id"] == canary227::UNIT {
        canary227_peer::row_scope(row)?;
        return Ok(false);
    }
    ensure!(owner["Id"] == c::UNIT, "209 unknown epoch227 owner");
    Ok(true)
}

fn full_rows(f: &Value) -> Result<Vec<&Value>> {
    // Authentication precedes classification. Leave the raw row and guard
    // binding intact for the dedicated canary disk and memory adapters.
    canary227_peer::validate_delegation(f)?;
    classify_full_rows(f)
}

fn classify_full_rows(f: &Value) -> Result<Vec<&Value>> {
    canary227_peer::roster(f)?;
    let mut selected = Vec::new();
    for row in f["active"]
        .as_array()
        .context("209 full 227 owner census")?
        .iter()
        .filter(|row| row["epoch"] == 227)
    {
        if full_owner(row)? {
            ensure!(selected.is_empty(), "209 duplicate full227 owner");
            selected.push(row);
        }
    }
    Ok(selected)
}

fn claim(f: &Value, row: &Value) -> Result<(DiagnosticClaim, Value)> {
    let owner = singleton227_admission::active_owner(row)?;
    ensure!(
        row["epoch"] == 227 && owner["Id"] == c::UNIT,
        "209 unknown epoch227 owner"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("209 full227 fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("209 full227 plan digest")?
            .into(),
    })?)?;
    let matches = p
        .diagnostics
        .iter()
        .filter(|d| d.epoch == 227 && d.unit == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "209 full227 needs one authenticated diagnostic claim"
    );
    let d = matches[0];
    ensure!(
        d.invocation_id == owner["InvocationID"]
            && d.scratch_path == Path::new(c::ROOT)
            && private157::binding(&d.launch_receipt)["path"] == row["launch_receipt"]
            && d.launch_receipt.sha256 == row["launch_receipt_sha256"]
            && owner["NRestarts"] == "0"
            && diagnostic_stage_running(owner),
        "209 full227 invocation, command or launch changed"
    );
    let launch = bound_json(&d.launch_receipt)?;
    ensure!(
        launch["evidence"]["units"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
            && launch["evidence"]["units"][0]["unit"] == d.unit
            && launch["evidence"]["units"][0]["invocation_id"] == d.invocation_id
            && launch["evidence"]["units"][0]["main_pid"]
                .as_u64()
                .map(|n| n.to_string())
                .as_deref()
                == owner["MainPID"].as_str(),
        "209 full227 launch owner changed"
    );
    c::bindings(d, &launch)?;
    ensure!(
        c::same_command(&owner["ExecStart"], &launch),
        "209 full227 live command changed"
    );
    Ok((
        DiagnosticClaim {
            epoch: d.epoch,
            unit: d.unit.clone(),
            invocation_id: d.invocation_id.clone(),
            scratch_path: d.scratch_path.clone(),
            launch_receipt: BoundFile {
                path: d.launch_receipt.path.clone(),
                sha256: d.launch_receipt.sha256.clone(),
            },
        },
        launch,
    ))
}

#[allow(clippy::too_many_arguments)]
fn guard(
    g: &Value,
    p: &Value,
    launch: &Value,
    d: &DiagnosticClaim,
    owner: &Value,
    sample: u64,
    now: u64,
    plan_sha: &str,
) -> Result<()> {
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("209 full227 guard clock")?;
    ensure!(
        p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && c::guard_matches(d, launch, p)
            && t >= sample
            && t <= now
            && now - t <= 1800
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::SINGLETON_GUARD_SHA
            && g["plan_sha256"] == plan_sha
            && p["unit"] == d.unit
            && p["invocation_id"] == d.invocation_id
            && g["producer_invocation_id"] == d.invocation_id
            && g["producer"]["invocation_id"] == d.invocation_id
            && g["producer"]["cgroup"] == owner["ControlGroup"]
            && g["producer"]["pid"]
                .as_u64()
                .map(|n| n.to_string())
                .as_deref()
                == owner["MainPID"].as_str()
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::PEAK)
            && g["maximum_worker_vmas"] == 3500000
            && g.get("native_main").is_some_and(Value::is_null)
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["workers"].as_array().is_some_and(|v| v
                .iter()
                .all(|w| w[0].as_u64().is_some_and(|pid| pid > 1)
                    && w[1].as_u64().is_some_and(|n| n > 0 && n < 3500000)))
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "209 protected full227 guard changed, stale or tripped"
    );
    Ok(())
}

type Split = (Value, BTreeMap<String, BoundFile>, u64, Vec<Value>);
pub(super) fn allocation(o: &Value, g: &Value, iid: &str) -> Result<(u64, u64, u64)> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("209 full227 observer census")?
        .iter()
        .filter(|r| r["producer_unit"] == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "209 full227 needs one coordinated whole-root sample"
    );
    let row = rows[0];
    let sample = &row["observation"];
    ensure!(
        row["status"] == "observed"
            && row["error"].is_null()
            && row["scratch_path"] == c::ROOT
            && sample["scratch_path"] == c::ROOT
            && sample["invocation_binding_stable"] == true
            && sample["producer_before"]["unit"] == c::UNIT
            && sample["producer_after"]["unit"] == c::UNIT
            && sample["producer_before"]["invocation_id"] == iid
            && sample["producer_after"]["invocation_id"] == iid,
        "209 full227 allocation sample has another owner or directory scope"
    );
    let sampled = sample["conservative_observed_physical_bytes"]
        .as_u64()
        .filter(|n| *n <= c::PEAK)
        .context("209 full227 sampled whole-root allocation exceeds envelope")?;
    let guarded = g["root_physical_observation"]["conservative_physical_bytes"]
        .as_u64()
        .filter(|n| *n <= c::PEAK)
        .context("209 full227 current guarded allocation exceeds envelope")?;
    Ok((sampled.min(guarded), sampled, guarded))
}
pub(super) fn split(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<Split> {
    let mut reduced = f.clone();
    let mut reduced_guards = guards
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                BoundFile {
                    path: v.path.clone(),
                    sha256: v.sha256.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut growth = 0u64;
    let mut measurements = Vec::new();
    for row in full_rows(f)? {
        let owner = singleton227_admission::active_owner(row)?;
        ensure!(measurements.is_empty(), "209 duplicate full227 owner");
        let (d, launch) = claim(f, row)?;
        let b = reduced_guards
            .remove(&d.unit)
            .context("209 full227 needs latest protective guard")?;
        let g = bound_json(&b)?;
        let plan: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
        guard(
            &g,
            &bound_json(&plan)?,
            &launch,
            &d,
            owner,
            sample,
            now,
            &plan.sha256,
        )?;
        let (credit, sampled, guarded) = allocation(o, &g, &d.invocation_id)?;
        growth = c::PEAK - credit;
        measurements.push(json!({"epoch":227,"unit":d.unit,"invocation_id":d.invocation_id,
            "launch":private157::binding(&d.launch_receipt),"guard":private157::binding(&b),
            "remaining_growth_bytes":growth,"scratch_growth_credit_bytes":credit,
            "sampled_whole_root_physical_bytes":sampled,"guarded_whole_root_physical_bytes":guarded,
            "accounting":"whole-root envelope less min(coordinated same-IID whole-root allocation,current whole-root guard allocation); actual free space bracketed by admission"}));
    }
    reduced["active"]
        .as_array_mut()
        .context("209 reduced full227 census")?
        .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != c::UNIT));
    Ok((reduced, reduced_guards, growth, measurements))
}

fn memory_limits(
    plan: &Value,
    launch: &Value,
    cap: u64,
    high: u64,
    charge: u64,
    swap: u64,
    page: u64,
) -> Result<u64> {
    let requested_max = 225_000_000_000u64;
    let requested_high = 150_000_000_000u64;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "209 invalid host page size"
    );
    ensure!(
        plan["schema"] == "jetstreamer-private-epoch227-singleton-resource-plan-v1"
            && plan["mode"] == "replay"
            && plan["unit"] == c::UNIT
            && plan["memory_max_bytes"] == requested_max
            && plan["memory_high_bytes"] == requested_high
            && launch["sandbox"]["MemoryMax"] == "225000000000"
            && launch["sandbox"]["MemoryHigh"] == "150000000000"
            && launch["sandbox"]["MemorySwapMax"] == "0"
            && cap > 0
            && high > 0
            && cap == requested_max / page * page
            && high == requested_high / page * page
            && swap == 0
            && charge <= cap,
        "209 full227 requested or kernel-rounded hard memory envelope changed"
    );
    Ok(cap - charge)
}

pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let mut total = 0u64;
    let mut evidence = Vec::new();
    for row in full_rows(f)? {
        let owner = singleton227_admission::active_owner(row)?;
        let (d, launch) = claim(f, row)?;
        ensure!(
            owner["ControlGroup"] == format!("/system.slice/{}", d.unit),
            "209 full227 cgroup escaped"
        );
        let root = Path::new("/sys/fs/cgroup/system.slice").join(&d.unit);
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(root.join(name))?.trim().parse()?)
        };
        let plan = bound_json(&serde_json::from_value(launch["resource_plan"].clone())?)?;
        let cap = read("memory.max")?;
        let high = read("memory.high")?;
        let charge = read("memory.current")?;
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .context("209 host page size unavailable")?;
        let remaining = memory_limits(
            &plan,
            &launch,
            cap,
            high,
            charge,
            read("memory.swap.max")?,
            page,
        )?;
        total = total
            .checked_add(remaining)
            .context("209 full227 memory overflow")?;
        evidence.push(json!({"epoch":227,"unit":d.unit,"invocation_id":d.invocation_id,
            "hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,
            "remaining_hard_memory_growth_bytes":remaining,"resource_plan":launch["resource_plan"],
            "requested_memory_max_bytes":plan["memory_max_bytes"],"requested_memory_high_bytes":plan["memory_high_bytes"],
            "kernel_memory_high_bytes":high,"host_page_size_bytes":page}));
    }
    Ok((total, evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn canary_row() -> Value {
        json!({"epoch":227,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "scratch_path":canary227::ROOT,
            "launch_receipt":"/var/lib/jetstreamer/horizon-227-v1625-canary-capture-selection-v2/launch.json",
            "launch_receipt_sha256":"b".repeat(64),
            "producer":{"Id":canary227::UNIT,"InvocationID":"a".repeat(32),"MainPID":"42",
                "NRestarts":"0","LoadState":"loaded","Type":"exec","Result":"success",
                "ActiveState":"active","SubState":"running",
                "ControlGroup":format!("/system.slice/{}",canary227::UNIT)}})
    }
    fn mixed_canary_fleet() -> Value {
        let row = canary_row();
        json!({"active":[{"epoch":209,"producer":{"Id":singleton209::UNIT}},row],
            "unit_census":{canary227::UNIT:row["producer"]},
            "failed_history":{"227":"preserved"}})
    }
    #[test]
    fn mixed_canary_routes_only_to_its_adapter_without_consuming_its_raw_row() {
        let f = mixed_canary_fleet();
        let before = f.clone();
        assert!(classify_full_rows(&f).unwrap().is_empty());
        assert_eq!(f, before);
        // Shape alone cannot pass the production gate: this fixture has no
        // authenticated fleet plan or launch. Both resource entry points fail.
        assert!(full_rows(&f).is_err());
        assert!(memory(&f).is_err());
        assert!(split(&f, &json!({}), &BTreeMap::new(), 100, 101).is_err());
    }
    #[test]
    fn unrelated_owner_and_guard_survive_both_full227_resource_entrypoints() {
        let f = json!({"active":[{"epoch":209,"producer":{"Id":singleton209::UNIT}}],
            "unit_census":{},"failed_history":{"227":"preserved"}});
        let guards = BTreeMap::from([(
            singleton209::UNIT.to_owned(),
            BoundFile {
                path: "/sealed/guard209.json".into(),
                sha256: "c".repeat(64),
            },
        )]);
        let (view, remaining, growth, evidence) = split(&f, &json!({}), &guards, 100, 101).unwrap();
        assert_eq!(view, f);
        assert_eq!(remaining, guards);
        assert_eq!(growth, 0);
        assert!(evidence.is_empty());
        let (memory, evidence) = memory(&f).unwrap();
        assert_eq!(memory, 0);
        assert!(evidence.is_empty());
    }
    #[test]
    fn native_and_full_profiles_remain_distinct_and_unknown_227_is_rejected() {
        let native = json!({"epoch":227,"producer":{"Id":singleton227_admission::NATIVE_UNIT}});
        let full = json!({"epoch":227,"producer":{"Id":c::UNIT}});
        let f = json!({"active":[native,full,{"epoch":209,"producer":{"Id":singleton209::UNIT}}],"unit_census":{}});
        assert_eq!(classify_full_rows(&f).unwrap(), vec![&f["active"][1]]);
        let mut unknown = f.clone();
        unknown["active"][0]["producer"]["Id"] = json!("unknown-227.service");
        assert!(classify_full_rows(&unknown).is_err());
        let mut duplicate = f.clone();
        duplicate["active"].as_array_mut().unwrap().push(full);
        assert!(classify_full_rows(&duplicate).is_err());
    }
    #[test]
    fn delegation_rejects_changed_identity_scope_duplicates_and_conflicting_full_epoch() {
        let f = mixed_canary_fleet();
        for (pointer, value) in [
            ("/active/1/producer/InvocationID", json!("d".repeat(32))),
            ("/active/1/producer/MainPID", json!("43")),
            ("/active/1/producer/NRestarts", json!("1")),
            ("/active/1/producer/ActiveState", json!("inactive")),
            ("/active/1/scratch_path", json!("/another-root")),
            ("/active/1/launch_receipt", json!("/another-launch.json")),
            ("/active/1/ordinary_replay_claim", json!(true)),
            (
                "/active/1/producer/Id",
                json!("horizon-qualify-227-v1625-bounded-resource-old.service"),
            ),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(classify_full_rows(&bad).is_err(), "{pointer}");
        }
        for extra in [canary_row(), json!({"epoch":227,"producer":{"Id":c::UNIT}})] {
            let mut bad = f.clone();
            bad["active"].as_array_mut().unwrap().push(extra);
            assert!(classify_full_rows(&bad).is_err());
        }
        let mut omitted = f.clone();
        omitted["active"].as_array_mut().unwrap().pop();
        assert!(classify_full_rows(&omitted).is_err());
    }
    #[test]
    fn decimal_requested_limits_accept_only_exact_kernel_page_rounding() {
        let p = json!({"schema":"jetstreamer-private-epoch227-singleton-resource-plan-v1","mode":"replay","unit":c::UNIT,
            "memory_max_bytes":225000000000u64,"memory_high_bytes":150000000000u64});
        let l = json!({"sandbox":{"MemoryMax":"225000000000","MemoryHigh":"150000000000","MemorySwapMax":"0"}});
        let cap = 224999997440u64;
        let high = 149999996928u64;
        let charge = 80000000000u64;
        assert_eq!(
            memory_limits(&p, &l, cap, high, charge, 0, 4096).unwrap(),
            cap - charge
        );
        for (max, watermark, used, swap, page) in [
            (cap - 4096, high, charge, 0, 4096),
            (cap + 4096, high, charge, 0, 4096),
            (cap, high - 4096, charge, 0, 4096),
            (cap, high + 4096, charge, 0, 4096),
            (225000000000, high, charge, 0, 4096),
            (cap, high, cap + 1, 0, 4096),
            (cap, high, charge, 1, 4096),
            (cap, high, charge, 0, 0),
            (cap, high, charge, 0, 5000),
            (cap, high, charge, 0, 8192),
            (cap, high, charge, 0, 1),
        ] {
            assert!(memory_limits(&p, &l, max, watermark, used, swap, page).is_err());
        }
        for pointer in ["/memory_max_bytes", "/memory_high_bytes"] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(1);
            assert!(memory_limits(&bad, &l, cap, high, charge, 0, 4096).is_err());
        }
        for pointer in [
            "/sandbox/MemoryMax",
            "/sandbox/MemoryHigh",
            "/sandbox/MemorySwapMax",
        ] {
            let mut bad = l.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("1");
            assert!(memory_limits(&p, &bad, cap, high, charge, 0, 4096).is_err());
        }
    }
    #[test]
    fn whole_root_credit_uses_the_smaller_bound_and_rejects_wrong_scope_or_invocation() {
        let iid = "a".repeat(32);
        let row = json!({"producer_unit":c::UNIT,"status":"observed","error":null,"scratch_path":c::ROOT,
            "observation":{"scratch_path":c::ROOT,"invocation_binding_stable":true,
                "producer_before":{"unit":c::UNIT,"invocation_id":iid},
                "producer_after":{"unit":c::UNIT,"invocation_id":iid},
                "conservative_observed_physical_bytes":78_473_859_072u64}});
        let o = json!({"diagnostic_replays":[row]});
        let mut g =
            json!({"root_physical_observation":{"conservative_physical_bytes":80_000_000_000u64}});
        assert_eq!(allocation(&o, &g, &iid).unwrap().0, 78_473_859_072);
        g["root_physical_observation"]["conservative_physical_bytes"] = json!(70_000_000_000u64);
        assert_eq!(allocation(&o, &g, &iid).unwrap().0, 70_000_000_000);
        for (pointer, value) in [
            (
                "/diagnostic_replays/0/scratch_path",
                json!(format!("{}/scratch", c::ROOT)),
            ),
            (
                "/diagnostic_replays/0/observation/scratch_path",
                json!("/other"),
            ),
            (
                "/diagnostic_replays/0/observation/producer_before/invocation_id",
                json!("b".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/producer_after/invocation_id",
                json!("b".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/invocation_binding_stable",
                json!(false),
            ),
            (
                "/diagnostic_replays/0/observation/conservative_observed_physical_bytes",
                json!(c::PEAK + 1),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(allocation(&bad, &g, &iid).is_err(), "{pointer}");
        }
        let mut duplicate = o.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert!(allocation(&duplicate, &g, &iid).is_err());
    }
    #[test]
    fn full227_guard_cannot_borrow_native_identity_or_understate_the_whole_root_cap() {
        let d = DiagnosticClaim {
            epoch: 227,
            unit: c::UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: c::ROOT.into(),
            launch_receipt: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "b".repeat(64),
            },
        };
        let launch = json!({"schema":c::SCHEMA,"epoch":227,"private_run_root":c::ROOT,
            "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,
            "manifest_fingerprint":c::FINGERPRINT,"bootstrap_slot":98063464u64,"canonical_root_slot":98495291u64,
            "terminal_slot":98495999u64,"output_slot_start":98064000u64,"output_slot_count":432000,"runtime":"solana-v1.6.20",
            "maximum_scratch_bytes":c::SCRATCH,"experimental_envelope_bytes":c::PEAK,"maximum_runtime_seconds":259200,
            "upstream_shrink_budget_cap":true,"guard_minimum_free_bytes":1000,"required_initial_free_bytes":1000+c::PEAK,
            "expected_exec_start":format!("{} ; ignore_errors=no }}",c::expected_command()),
            "runtime_promotion_authorized":false,"full_epoch_qualified":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":d.unit,"invocation_id":d.invocation_id,
            "filesystem":"/","worker_root":c::ROOT,"minimum_free_bytes":1000,"maximum_root_physical_bytes":c::PEAK,
            "maximum_worker_vmas":3500000});
        let owner = json!({"ControlGroup":format!("/system.slice/{}",c::UNIT),"MainPID":"42"});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":1000,
            "guard_sha256":c::SINGLETON_GUARD_SHA,"plan_sha256":"b".repeat(64),"producer_invocation_id":d.invocation_id,
            "producer":{"invocation_id":d.invocation_id,"pid":42,"cgroup":owner["ControlGroup"],"active":"active","sub":"running","restarts":0},
            "producer_stop_enabled":true,"maximum_root_physical_bytes":c::PEAK,
            "root_physical_observation":{"maximum_physical_bytes":c::PEAK,"conservative_physical_bytes":1000,"exceeds_budget":false},
            "maximum_worker_vmas":3500000,"workers":[[43,100]],"native_main":null,
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,
            "minimum_free_bytes":1000,"available_bytes":2000,"remote_mutations":false,"r2_mutations":false});
        guard(&g, &p, &launch, &d, &owner, 999, 1001, &"b".repeat(64)).unwrap();
        for (pointer, value) in [
            ("/guard_sha256", json!(c::NATIVE_GUARD_SHA)),
            ("/producer_invocation_id", json!("c".repeat(32))),
            ("/producer/pid", json!(44)),
            ("/maximum_root_physical_bytes", json!(c::SCRATCH)),
            ("/root_physical_observation/exceeds_budget", json!(true)),
            ("/producer_stop_enabled", json!(false)),
            ("/trip_reason", json!("disk-floor")),
            ("/native_main", json!({"main_pid":42})),
            ("/workers", json!([])),
            ("/available_bytes", json!(999)),
            ("/recorded_unix_seconds", json!(998)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard(&bad, &p, &launch, &d, &owner, 999, 1001, &"b".repeat(64)).is_err(),
                "{pointer}"
            );
        }
        let mut bad = p.clone();
        bad["worker_root"] = json!(singleton227_admission::NATIVE_ROOT);
        assert!(guard(&g, &bad, &launch, &d, &owner, 999, 1001, &"b".repeat(64)).is_err());
        assert!(guard(&g, &p, &launch, &d, &owner, 999, 2801, &"b".repeat(64)).is_err());
    }
}
