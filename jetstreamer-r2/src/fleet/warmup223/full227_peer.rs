//! Expanded v2 admission accounts for the exact already-running full 227 owner.
use super::super::singleton227 as lane;
use super::super::*;
pub(super) const IID: &str = "a10f37b57711425a81633c62c66438d5";
const GUARD: &str = "horizon-singleton227-protective-v1.service";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-singleton227-guard-receipts-v1";
fn require_timer(read: impl FnOnce(&str, &str) -> Result<BTreeMap<String, String>>) -> Result<()> {
    let properties = read(
        "horizon-singleton227-protective-v1.timer",
        "ActiveState,SubState",
    )?;
    ensure!(
        properties.get("ActiveState").map(String::as_str) == Some("active"),
        "v2 full 227 guard timer inactive"
    );
    Ok(())
}
fn owner(row: &Value) -> &Value {
    if row["producer"].is_object() {
        &row["producer"]
    } else {
        &row["unit"]
    }
}
fn effective_limit(requested: u64, page_size: u64) -> Result<u64> {
    ensure!(
        page_size > 0 && page_size.is_power_of_two(),
        "invalid kernel page size"
    );
    Ok(requested / page_size * page_size)
}
fn memory_envelope(
    requested: &Value,
    properties: &BTreeMap<String, String>,
    kernel: &BTreeMap<String, u64>,
    page_size: u64,
) -> Result<()> {
    for (key, file) in [
        ("MemoryHigh", "memory.high"),
        ("MemoryMax", "memory.max"),
        ("MemorySwapMax", "memory.swap.max"),
    ] {
        let raw = requested[key]
            .as_str()
            .context("v2 sealed requested memory limit missing")?;
        ensure!(
            properties.get(key).map(String::as_str) == Some(raw),
            "v2 full 227 requested systemd memory limit changed:{key}"
        );
        let expected = effective_limit(raw.parse()?, page_size)?;
        ensure!(
            kernel.get(file) == Some(&expected),
            "v2 full 227 effective kernel memory limit changed:{file}"
        );
    }
    Ok(())
}
fn roster(f: &Value) -> Result<&Value> {
    let rows = f["active"].as_array().context("v2 complete owner census")?;
    ensure!(
        rows.len() == 4,
        "v2 requires exactly three old owners plus full 227; recompute for any added or missing owner"
    );
    for (name, iid) in super::OWNERS.into_iter().skip(1) {
        ensure!(
            rows.iter()
                .filter(|r| owner(r)["Id"] == name
                    && owner(r)["InvocationID"] == iid
                    && owner(r)["NRestarts"] == "0")
                .count()
                == 1,
            "v2 old owner omitted or changed"
        );
    }
    let matches = rows
        .iter()
        .filter(|r| {
            r["epoch"] == 227
                && r["phase"] == "diagnostic-qualification"
                && owner(r)["Id"] == lane::UNIT
                && owner(r)["InvocationID"] == IID
                && owner(r)["NRestarts"] == "0"
        })
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "v2 requires the exact already-registered full 227 invocation"
    );
    Ok(matches[0])
}
pub(super) fn accepted(f: &Value) -> Result<DiagnosticClaim> {
    let row = roster(f)?;
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"].as_str().context("v2 full 227 fleet plan")?.into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("v2 full 227 fleet plan digest")?
            .into(),
    })?)?;
    let claims = p
        .diagnostics
        .iter()
        .filter(|c| c.unit == lane::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "v2 full 227 registered claim missing/duplicate"
    );
    let prior = claims[0];
    let c = DiagnosticClaim {
        epoch: prior.epoch,
        unit: prior.unit.clone(),
        invocation_id: prior.invocation_id.clone(),
        scratch_path: prior.scratch_path.clone(),
        launch_receipt: BoundFile {
            path: prior.launch_receipt.path.clone(),
            sha256: prior.launch_receipt.sha256.clone(),
        },
    };
    ensure!(
        c.invocation_id == IID
            && c.launch_receipt.path.to_str() == row["launch_receipt"].as_str()
            && c.launch_receipt.sha256 == row["launch_receipt_sha256"]
            && c.scratch_path == Path::new(lane::ROOT),
        "v2 full 227 accepted binding differs"
    );
    lane::bindings(&c, &bound_json(&c.launch_receipt)?)?;
    Ok(c)
}
pub(super) fn protect(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let c = accepted(f)?;
    let origin = bound_json(&c.launch_receipt)?;
    let old = owner(roster(f)?);
    let u = current
        .get(lane::UNIT)
        .context("v2 full 227 owner absent")?;
    for key in [
        "Id",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        ensure!(u[key] == old[key], "v2 full 227 identity changed:{key}");
    }
    ensure!(
        diagnostic_stage_running(u) && lane::same_command(&u["ExecStart"], &origin),
        "v2 full 227 command/state changed"
    );
    let caps = singleton227_capture::properties(lane::UNIT, "MemoryHigh,MemoryMax,MemorySwapMax")?;
    let page_size = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .context("v2 kernel page size unavailable")?;
    let expected_group = format!("/system.slice/{}", lane::UNIT);
    ensure!(
        u["ControlGroup"] == expected_group,
        "v2 full 227 cgroup path differs"
    );
    let group = Path::new("/sys/fs/cgroup").join(expected_group.trim_start_matches('/'));
    ensure!(
        group.canonicalize()? == group,
        "v2 full 227 cgroup path redirected"
    );
    let kernel = ["memory.high", "memory.max", "memory.swap.max"]
        .into_iter()
        .map(|name| {
            Ok((
                name.to_owned(),
                fs::read_to_string(group.join(name))?
                    .trim()
                    .parse::<u64>()?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    memory_envelope(&origin["sandbox"], &caps, &kernel, page_size)
}
fn remaining_memory(o: &Value, cap: u64) -> Result<u64> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("v2 full 227 resource census")?
        .iter()
        .filter(|r| r["producer_unit"] == lane::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["status"] == "observed"
            && rows[0]["observation"]["invocation_binding_stable"] == true,
        "v2 full 227 stable resource sample missing/duplicate"
    );
    let row = &rows[0]["observation"];
    let mut charges = Vec::new();
    for phase in ["producer_before", "producer_after"] {
        ensure!(
            row[phase]["unit"] == lane::UNIT
                && row[phase]["invocation_id"] == IID
                && row[phase]["restarts"] == 0,
            "v2 full 227 sampled identity differs"
        );
        charges.push(
            row[phase]["cgroup"]["gauges"]["memory.current"]
                .as_u64()
                .context("v2 full 227 cgroup charge missing")?,
        );
    }
    let charged = *charges.iter().min().unwrap();
    cap.checked_sub(charged)
        .context("v2 full 227 exceeded captured hard memory cap")
}
pub(super) fn sample_memory(o: &Value, f: &Value) -> Result<u64> {
    let c = accepted(f)?;
    let origin = bound_json(&c.launch_receipt)?;
    let cap = origin["sandbox"]["MemoryMax"]
        .as_str()
        .context("v2 full 227 hard cap")?
        .parse::<u64>()?;
    ensure!(
        cap == 225_000_000_000
            && origin["sandbox"]["MemoryHigh"] == "150000000000"
            && origin["sandbox"]["MemorySwapMax"] == "0",
        "v2 full 227 captured memory policy differs"
    );
    let pending = remaining_memory(o, cap)?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("v2 host memory sample")?;
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .and_then(|n| n.checked_mul(1024))
        .context("v2 total memory sample")?;
    let required = (608u64 << 30)
        .checked_add(pending)
        .context("v2 expanded memory overflow")?;
    ensure!(
        available >= required
            && available
                >= (total / 10)
                    .checked_add(128u64 << 30)
                    .and_then(|n| n.checked_add(pending))
                    .context("v2 90 percent memory arithmetic overflow")?,
        "v2 expanded memory envelope does not fit"
    );
    Ok(pending)
}
pub(super) fn guard(f: &Value, sample: u64, now: u64) -> Result<super::guard_receipt::Selection> {
    let c = accepted(f)?;
    let origin = bound_json(&c.launch_receipt)?;
    let selected = super::guard_receipt::select(GUARD, Path::new(RECEIPTS), sample, now, 120)?;
    let pb: BoundFile = serde_json::from_value(origin["guard_plan"].clone())?;
    let p = bound_json(&pb)?;
    let g = &selected.receipt;
    ensure!(
        lane::guard_matches(&c, &origin, &p)
            && p["unit"] == lane::UNIT
            && p["invocation_id"] == IID
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan_sha256"] == pb.sha256
            && g["guard_sha256"] == lane::SINGLETON_GUARD_SHA
            && g["producer_invocation_id"] == IID
            && g["producer"]["invocation_id"] == IID
            && g["producer"]["pid"].as_u64() == origin["evidence"]["units"][0]["main_pid"].as_u64()
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == lane::PEAK
            && g["maximum_worker_vmas"] == 3_500_000
            && g["workers"].as_array().is_some_and(|a| a.len() == 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3_500_000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null)),
        "v2 full 227 protective guard differs or tripped"
    );
    require_timer(singleton227_capture::properties)?;
    Ok(selected)
}
pub(super) fn budget(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    floor: u64,
    sample: u64,
    now: u64,
    full_guard: &Value,
) -> Result<Value> {
    let free_before = singleton227_admission::disk_free()?;
    accepted(f)?;
    let pending = sample_memory(o, f)?;
    let (credit, sampled_allocation, guarded_allocation) =
        native209_full227::allocation(o, full_guard, IID)?;
    let remaining = lane::PEAK
        .checked_sub(credit)
        .context("v3 full 227 allocation credit exceeds envelope")?;
    // Derived arithmetic subcensus only, never an accepted or published fleet.
    // The complete four-owner census above remains the authority.
    let mut old = f.clone();
    old["active"] = json!(
        f["active"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["epoch"] != 227)
            .collect::<Vec<_>>()
    );
    let (growth, measurements) =
        singleton227_admission::protected_growth(&old, o, guards, sample, now)?;
    let protected = floor
        .checked_add(growth)
        .and_then(|n| n.checked_add(remaining))
        .context("v2 expanded disk arithmetic overflow")?;
    ensure!(
        protected <= 2_000_000_000_000,
        "v2 expanded protected disk exceeds the sealed 2 TB floor; raise the generation before launch"
    );
    let (after_growth, _) = singleton227_admission::protected_growth(&old, o, guards, sample, now)?;
    let free_after = singleton227_admission::disk_free()?;
    ensure!(
        after_growth <= growth
            && free_before >= 2_300_000_000_000
            && free_after >= 2_300_000_000_000,
        "v3 growth/free-space bracket changed or no longer fits"
    );
    Ok(
        json!({"schema":"jetstreamer-warmup223-expanded-budget-v3","complete_owner_count":4,"old_three_remaining_growth_bytes":growth,"old_three_growth_evidence":measurements,"full227_remaining_growth_bytes":remaining,"full227_scratch_credit_bytes":credit,"full227_sampled_whole_root_bytes":sampled_allocation,"full227_guarded_whole_root_bytes":guarded_allocation,"century_floor_bytes":floor,"required_protected_disk_bytes":protected,"required_initial_disk_bytes":2_300_000_000_000u64,"candidate_scratch_bytes":300_000_000_000u64,"full227_remaining_hard_memory_bytes":pending,"required_initial_memory_bytes":(608u64<<30)+pending,"memory_target_percent":90,"actual_free_before_bytes":free_before,"actual_free_after_bytes":free_after,"after_old_three_growth_bytes":after_growth,"publication_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn validate_budget(v: &Value) -> Result<()> {
    let credit = v["full227_scratch_credit_bytes"]
        .as_u64()
        .context("saved full 227 credit missing")?;
    let remaining = lane::PEAK
        .checked_sub(credit)
        .context("saved full 227 credit exceeds cap")?;
    let credited = v["schema"] == "jetstreamer-warmup223-expanded-budget-v3";
    if credited {
        let sampled = v["full227_sampled_whole_root_bytes"]
            .as_u64()
            .context("saved full 227 sample allocation")?;
        let guarded = v["full227_guarded_whole_root_bytes"]
            .as_u64()
            .context("saved full 227 guarded allocation")?;
        ensure!(
            sampled <= lane::PEAK
                && guarded <= lane::PEAK
                && credit == sampled.min(guarded)
                && v["actual_free_before_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= 2_300_000_000_000)
                && v["actual_free_after_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= 2_300_000_000_000)
                && v["after_old_three_growth_bytes"]
                    .as_u64()
                    .zip(v["old_three_remaining_growth_bytes"].as_u64())
                    .is_some_and(|(a, b)| a <= b),
            "saved full 227 credit/bracket mismatch"
        );
    }
    let sum = v["old_three_remaining_growth_bytes"]
        .as_u64()
        .and_then(|n| n.checked_add(remaining))
        .and_then(|n| n.checked_add(v["century_floor_bytes"].as_u64()?))
        .context("v2 saved disk budget overflow/missing")?;
    let pending = v["full227_remaining_hard_memory_bytes"]
        .as_u64()
        .context("v2 saved memory budget missing")?;
    ensure!(
        (credited || (v["schema"] == "jetstreamer-warmup223-expanded-budget-v2" && credit == 0))
            && v["complete_owner_count"] == 4
            && v["full227_remaining_growth_bytes"] == remaining
            && v["candidate_scratch_bytes"] == 300_000_000_000u64
            && v["required_protected_disk_bytes"] == sum
            && sum <= 2_000_000_000_000
            && v["required_initial_disk_bytes"] == 2_300_000_000_000u64
            && v["required_initial_memory_bytes"]
                == (608u64 << 30)
                    .checked_add(pending)
                    .context("v2 saved memory overflow")?
            && v["memory_target_percent"] == 90
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "v2 expanded budget differs from the sealed envelope"
    );
    let b: BoundFile = serde_json::from_value(v["full227_guard"].clone())?;
    let g = bound_json(&b)?;
    if credited {
        ensure!(
            v["full227_guarded_whole_root_bytes"]
                == g["root_physical_observation"]["conservative_physical_bytes"],
            "saved credit does not match bound full 227 guard"
        );
    }
    super::guard_receipt::validate_history(&v["full227_guard_history"], &g)?;
    ensure!(
        v["full227_guard_history"]["unit"] == GUARD
            && v["full227_guard_history"]["maximum_age_seconds"] == 120
            && g["producer_invocation_id"] == IID
            && g["guard_sha256"] == lane::SINGLETON_GUARD_SHA,
        "v2 saved full 227 protective evidence differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_timer_getter_accepts_timer_and_preserves_active_gate() {
        for state in ["active", "inactive", "failed"] {
            let result = require_timer(|name, fields| {
                assert_eq!(name, "horizon-singleton227-protective-v1.timer");
                assert_eq!(fields, "ActiveState,SubState");
                Ok([
                    ("ActiveState".into(), state.into()),
                    ("SubState".into(), "waiting".into()),
                ]
                .into_iter()
                .collect())
            });
            assert_eq!(result.is_ok(), state == "active");
        }
        assert!(require_timer(|_, _| anyhow::bail!("property read failed")).is_err());
        assert!(require_timer(|_, _| Ok(BTreeMap::new())).is_err());
    }
    #[test]
    fn kernel_memory_limits_are_page_rounded_without_weakening_requested_policy() {
        assert_eq!(
            effective_limit(225_000_000_000, 4096).unwrap(),
            224_999_997_440
        );
        assert_eq!(
            effective_limit(150_000_000_000, 4096).unwrap(),
            149_999_996_928
        );
        assert_eq!(effective_limit(0, 4096).unwrap(), 0);
        assert!(effective_limit(225_000_000_000, 0).is_err());
        assert!(effective_limit(225_000_000_000, 3).is_err());
    }
    #[test]
    fn requested_systemd_and_effective_kernel_caps_are_independent_gates() {
        let requested =
            json!({"MemoryHigh":"150000000000","MemoryMax":"225000000000","MemorySwapMax":"0"});
        let properties = [
            ("MemoryHigh".into(), "150000000000".into()),
            ("MemoryMax".into(), "225000000000".into()),
            ("MemorySwapMax".into(), "0".into()),
        ]
        .into_iter()
        .collect::<BTreeMap<String, String>>();
        let kernel = [
            ("memory.high".into(), 149_999_996_928),
            ("memory.max".into(), 224_999_997_440),
            ("memory.swap.max".into(), 0),
        ]
        .into_iter()
        .collect::<BTreeMap<String, u64>>();
        memory_envelope(&requested, &properties, &kernel, 4096).unwrap();
        for key in ["MemoryHigh", "MemoryMax", "MemorySwapMax"] {
            let mut wrong = properties.clone();
            wrong.insert(key.into(), "1".into());
            assert!(memory_envelope(&requested, &wrong, &kernel, 4096).is_err());
        }
        for name in ["memory.high", "memory.max", "memory.swap.max"] {
            let mut wrong = kernel.clone();
            *wrong.get_mut(name).unwrap() += 4096;
            assert!(memory_envelope(&requested, &properties, &wrong, 4096).is_err());
        }
        let mut rounded_properties = properties.clone();
        rounded_properties.insert("MemoryHigh".into(), "149999996928".into());
        assert!(memory_envelope(&requested, &rounded_properties, &kernel, 4096).is_err());
        let mut unrounded_kernel = kernel.clone();
        unrounded_kernel.insert("memory.max".into(), 225_000_000_000);
        assert!(memory_envelope(&requested, &properties, &unrounded_kernel, 4096).is_err());
    }
    fn fleet() -> Value {
        let mut rows = super::super::OWNERS
            .iter()
            .skip(1)
            .map(|(n, i)| json!({"producer":{"Id":n,"InvocationID":i,"NRestarts":"0"}}))
            .collect::<Vec<_>>();
        rows.push(json!({"epoch":227,"phase":"diagnostic-qualification","unit":{"Id":lane::UNIT,"InvocationID":IID,"NRestarts":"0"}}));
        json!({"active":rows})
    }
    #[test]
    fn expanded_roster_rejects_missing_extra_or_replaced_peers() {
        let good = fleet();
        roster(&good).unwrap();
        for choice in 0..3 {
            let mut bad = good.clone();
            match choice {
                0 => {
                    bad["active"].as_array_mut().unwrap().pop();
                }
                1 => bad["active"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"epoch":209})),
                _ => bad["active"][3]["unit"]["InvocationID"] = json!("0".repeat(32)),
            };
            assert!(roster(&bad).is_err());
        }
    }
    #[test]
    fn full227_memory_headroom_uses_lower_charge_and_exact_sampled_owner() {
        let m = |charge| json!({"unit":lane::UNIT,"invocation_id":IID,"restarts":0,"cgroup":{"gauges":{"memory.current":charge}}});
        let o = json!({"diagnostic_replays":[{"producer_unit":lane::UNIT,"status":"observed","observation":{"invocation_binding_stable":true,"producer_before":m(90),"producer_after":m(110)}}]});
        assert_eq!(remaining_memory(&o, 225).unwrap(), 135);
        let mut bad = o.clone();
        bad["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
            json!("wrong");
        assert!(remaining_memory(&bad, 225).is_err());
        assert!(remaining_memory(&o, 89).is_err());
    }
}
