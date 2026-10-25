//! Closed selection-v2 bounded canary peer, separate from any full epoch 227.
//! Raw fleet, failures and claims are preserved; only derived accounting removes it.
use super::canary227 as c;
use super::*;
mod memory;
pub(super) use memory::validate_saved_memory_row;
pub(super) const PROTECTIVE: &str = "horizon-canary227-v1625-protective-selection-v2.service";
const LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-227-v1625-canary-capture-selection-v2/launch.json";
const PREFIX223_MEMORY_FLOOR: u64 = 480u64 << 30;
const PREFIX223_IID: &str = "e70aaf097e7c4583b216aba454145910";
pub(super) fn add_memory(base: u64, top_up: u64, growth: u64) -> Result<u64> {
    base.checked_add(top_up)
        .and_then(|n| n.checked_add(growth))
        .context("canary protected memory overflow")
}
pub(super) fn memory_floor(f: &Value, total: u64) -> Result<Value> {
    ensure!(total > 0, "canary peer host total memory absent");
    let census = f["unit_census"]
        .as_object()
        .context("memory floor complete census missing")?;
    for row in f["active"]
        .as_array()
        .context("memory floor active census missing")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        if owner["Id"] == prefix223_native20::UNIT {
            ensure!(
                census.get(prefix223_native20::UNIT) == Some(owner),
                "memory floor native223 owner omitted from raw census"
            );
        }
    }
    let live = census
        .get(prefix223_native20::UNIT)
        .is_some_and(diagnostic_stage_running);
    if live {
        ensure!(
            census[prefix223_native20::UNIT]["InvocationID"] == PREFIX223_IID,
            "memory floor belongs to an unmodeled native223 owner"
        );
    }
    let baseline = total / 10;
    let floor = if live { PREFIX223_MEMORY_FLOOR } else { 0 };
    let effective = baseline.max(floor);
    Ok(
        json!({"host_total_memory_bytes":total,"host_baseline_bytes":baseline,
        "native223_live":live,"native223_available_memory_floor_bytes":floor,
        "effective_available_memory_floor_bytes":effective,"memory_floor_top_up_bytes":effective-baseline}),
    )
}
fn host_total_memory() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemTotal:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
                .and_then(|n| n.checked_mul(1024))
        })
        .context("canary peer actual host total memory missing")
}
fn iid(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0')
    })
}
pub(super) fn row_scope(row: &Value) -> Result<()> {
    let u = singleton227_admission::active_owner(row)?;
    ensure!(
        row["epoch"] == 227
            && row["phase"] == "diagnostic-qualification"
            && row["ordinary_replay_claim"] == false
            && u["Id"] == c::UNIT
            && iid(&u["InvocationID"])
            && u["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 1)
            && u["NRestarts"] == "0"
            && u["LoadState"] == "loaded"
            && u["Type"] == "exec"
            && u["Result"] == "success"
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["ControlGroup"] == format!("/system.slice/{}", c::UNIT)
            && row["scratch_path"] == c::ROOT
            && row["launch_receipt"] == LAUNCH
            && canonical_digest(&row["launch_receipt_sha256"]),
        "bounded canary peer requires its exact selection-v2 owner, whole-root scope and captured origin"
    );
    Ok(())
}
pub(super) fn roster(f: &Value) -> Result<bool> {
    for (name, owner) in f["unit_census"]
        .as_object()
        .context("canary peer complete raw census missing")?
    {
        ensure!(
            !name.starts_with("horizon-qualify-227-v1625-bounded-resource-")
                || name == c::UNIT
                || !diagnostic_stage_running(owner),
            "unmodeled bounded canary omitted from active census"
        );
    }
    let rows = f["active"]
        .as_array()
        .context("canary peer active census missing")?;
    let mut found = false;
    for row in rows {
        let u = singleton227_admission::active_owner(row)?;
        let name = u["Id"].as_str().context("canary peer owner name missing")?;
        if name == c::UNIT {
            ensure!(!found, "duplicate bounded canary peer");
            row_scope(row)?;
            ensure!(
                f["unit_census"].get(c::UNIT) == Some(u),
                "bounded canary missing from original complete unit census"
            );
            found = true;
        } else {
            ensure!(
                !name.starts_with("horizon-qualify-227-v1625-bounded-resource-"),
                "unmodeled bounded canary generation"
            );
        }
    }
    if found {
        ensure!(
            rows.iter().filter(|r| r["epoch"] == 227).count() == 1,
            "bounded canary cannot coexist with another epoch 227 owner"
        );
    } else {
        ensure!(
            !f["unit_census"]
                .get(c::UNIT)
                .is_some_and(diagnostic_stage_running),
            "live bounded canary was omitted from active owner accounting"
        );
    }
    Ok(found)
}
struct Peer {
    d: DiagnosticClaim,
    launch: Value,
    owner: Value,
}
fn accepted(f: &Value) -> Result<Option<Peer>> {
    if !roster(f)? {
        return Ok(None);
    }
    let row = f["active"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| singleton227_admission::active_owner(r).is_ok_and(|u| u["Id"] == c::UNIT))
        .context("canary peer missing")?;
    let owner = singleton227_admission::active_owner(row)?;
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("canary peer plan missing")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("canary peer plan SHA missing")?
            .into(),
    })?)?;
    let claims = p
        .diagnostics
        .iter()
        .filter(|d| d.unit == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "bounded canary requires one original diagnostic claim"
    );
    let d = claims[0];
    ensure!(
        d.epoch == 227
            && d.invocation_id == owner["InvocationID"]
            && d.scratch_path == Path::new(c::ROOT)
            && d.launch_receipt.path == Path::new(LAUNCH)
            && private157::binding(&d.launch_receipt)["path"] == row["launch_receipt"]
            && d.launch_receipt.sha256 == row["launch_receipt_sha256"],
        "bounded canary claim differs from accepted owner"
    );
    let launch = native209::immutable_json(&d.launch_receipt)?;
    launch_scope(d, &launch, owner)?;
    Ok(Some(Peer {
        d: DiagnosticClaim {
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
        owner: owner.clone(),
    }))
}
/// Authenticate delegation without measuring or removing the canary. Its
/// existing disk and memory adapters still own all resource accounting.
pub(super) fn validate_delegation(f: &Value) -> Result<()> {
    accepted(f).context("full 227 adapter cannot delegate an unauthenticated canary")?;
    Ok(())
}
fn launch_scope(d: &DiagnosticClaim, r: &Value, u: &Value) -> Result<()> {
    validate_diagnostic_launch(r, d)?;
    ensure!(
        c::launch_matches(d, r)
            && r["unit"] == c::UNIT
            && r["invocation_id"] == d.invocation_id
            && r["main_pid"].as_u64().map(|v| v.to_string()).as_deref() == u["MainPID"].as_str()
            && r["evidence"]["units"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1
                    && rows[0]["unit"] == c::UNIT
                    && rows[0]["invocation_id"] == d.invocation_id
                    && rows[0]["main_pid"] == r["main_pid"]
                    && rows[0]["restarts"] == 0)
            && c::same_command(&u["ExecStart"], &r["expected_exec_start"]),
        "bounded canary captured launch identity differs"
    );
    let a = bound_json(&serde_json::from_value(
        r["fresh_resource_admission"].clone(),
    )?)?;
    ensure!(
        a["schema"] == "jetstreamer-private-epoch227-v1625-canary-admission-v1"
            && a["admitted"] == true
            && a["mode"] == "bounded-canary"
            && a["unit"] == c::UNIT
            && a["private_run_root"] == c::ROOT
            && a["candidate_incremental_peak_bytes"] == c::CANDIDATE
            && a["maximum_scratch_bytes"] == c::SCRATCH
            && a["maximum_memory_bytes"] == c::MEMORY
            && a["protected_existing_floor_bytes"] == r["guard_minimum_free_bytes"]
            && a["required_initial_free_bytes"] == r["required_initial_free_bytes"]
            && a["canary_plan"] == r["resource_plan"]
            && a["input_capability"] == r["input_capability"]
            && a["resource_proposal"] == r["resource_proposal"]
            && a["observer"] == r["observer"]
            && a["fleet"] == r["fleet"]
            && a["older_producers_and_guards_preserved"] == true
            && a["fresh_complete_census_passed"] == true
            && a["all_immutable_inputs_rehashed"] == true
            && a["producer_started"] == false
            && a["snapshot_restored"] == false
            && a["resource_samples_taken"] == 0,
        "bounded canary lost original admitted claims or origin"
    );
    native227_v1625::no_authority(&a)?;
    let original_fleet = bound_json(&serde_json::from_value(a["fleet"].clone())?)?;
    original_memory(&a, &original_fleet)?;
    if let Some(profile) = a.get("output_credit_profile") {
        ensure!(
            profile == output_credit204205::PROFILE
                && a["output_credit_evidence_before"]["profile"] == *profile
                && a["output_credit_evidence_after"]["profile"] == *profile
                && a["park_maintenance_idle_required"] == true,
            "bounded canary admission has unknown output-credit lineage"
        );
    }
    Ok(())
}
fn original_memory(a: &Value, original_fleet: &Value) -> Result<()> {
    let native223_live = original_fleet["unit_census"]
        .get(prefix223_native20::UNIT)
        .is_some_and(diagnostic_stage_running);
    if native223_live {
        let total = a["memory_floor_policy"]["host_total_memory_bytes"]
            .as_u64()
            .context("canary admission has no native223 floor policy")?;
        ensure!(
            a["memory_floor_policy"] == memory_floor(original_fleet, total)?
                && a["output_credit_profile"] == output_credit204205::PROFILE,
            "canary original admission did not protect the native223 runtime floor"
        );
        let required = a["memory_floor_policy"]["effective_available_memory_floor_bytes"]
            .as_u64()
            .and_then(|n| n.checked_add(c::MEMORY))
            .and_then(|n| n.checked_add(a["auxiliary_remaining_memory_growth_bytes"].as_u64()?))
            .context("canary original memory arithmetic missing or overflow")?;
        ensure!(
            a["required_available_memory_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
                && a["available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required),
            "canary original admission under-reserved protected native223 memory"
        );
    }
    Ok(())
}
fn view(f: &Value) -> Result<Value> {
    let mut v = f.clone();
    v["active"]
        .as_array_mut()
        .context("canary derived active census missing")?
        .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != c::UNIT));
    Ok(v)
}
fn owner_current(peer: &Peer, p: &BTreeMap<String, String>) -> Result<()> {
    let v = serde_json::to_value(p)?;
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ControlGroup",
        "ActiveState",
        "SubState",
    ] {
        ensure!(
            v[key] == peer.owner[key],
            "bounded canary current identity changed:{key}"
        );
    }
    ensure!(
        v["ExecMainPID"]
            .as_str()
            .and_then(|v| v.parse::<u64>().ok())
            == peer.launch["main_pid"].as_u64()
            && v["ExecMainStartTimestampMonotonic"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                == peer.launch["producer_start_monotonic_microseconds"]
                    .as_u64()
                    .filter(|v| *v > 0),
        "bounded canary latest PID/start differs from actual captured start"
    );
    canary227_capture::sandbox(
        p,
        peer.launch["expected_exec_start"]
            .as_str()
            .context("canary peer command missing")?,
    )
    .context("bounded canary producer sandbox differs from its captured command")?;
    Ok(())
}
const PROPERTIES: &str = "Id,LoadState,InvocationID,MainPID,NRestarts,ControlGroup,ExecMainPID,ExecMainStartTimestampMonotonic,Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Transient,FragmentPath,RemainAfterExit,Result,ActiveState,SubState,ExecStart";
fn properties(peer: &Peer) -> Result<BTreeMap<String, String>> {
    let p = singleton227_capture::properties(c::UNIT, PROPERTIES)?;
    owner_current(peer, &p)?;
    Ok(p)
}
fn memory_values(cap: u64, high: u64, charge: u64, swap: u64, page: u64) -> Result<u64> {
    ensure!(
        page > 0
            && page.is_power_of_two()
            && cap == c::MEMORY / page * page
            && high == c::HIGH / page * page
            && swap == 0
            && charge <= cap,
        "bounded canary kernel-rounded memory cap/charge differs"
    );
    Ok(cap - charge)
}
fn kernel(peer: &Peer) -> Result<Value> {
    let before = properties(peer)?;
    let root = Path::new("/sys/fs/cgroup/system.slice").join(c::UNIT);
    let read =
        |name: &str| -> Result<u64> { Ok(fs::read_to_string(root.join(name))?.trim().parse()?) };
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .context("canary page size unavailable")?;
    let cap = read("memory.max")?;
    let high = read("memory.high")?;
    let charge_before = read("memory.current")?;
    let swap = read("memory.swap.max")?;
    ensure!(read("pids.max")? == 512, "canary kernel task cap differs");
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    let f = cpu.split_whitespace().collect::<Vec<_>>();
    ensure!(f.len() == 2, "canary CPU cap fields missing");
    let quota: u64 = f[0].parse()?;
    let period: u64 = f[1].parse()?;
    ensure!(
        period > 0 && period.checked_mul(8) == Some(quota),
        "canary kernel CPU cap differs"
    );
    let charge_after = read("memory.current")?;
    memory_values(cap, high, charge_before, swap, page)?;
    memory_values(cap, high, charge_after, swap, page)?;
    let charge = charge_before.min(charge_after);
    let remaining = memory_values(cap, high, charge, swap, page)?;
    ensure!(
        read("memory.max")? == cap
            && read("memory.high")? == high
            && read("memory.swap.max")? == swap
            && read("pids.max")? == 512
            && fs::read_to_string(root.join("cpu.max"))? == cpu,
        "canary kernel caps changed during memory observation"
    );
    ensure!(
        before == properties(peer)?,
        "canary limits identity changed"
    );
    Ok(
        json!({"requested_memory_max_bytes":c::MEMORY,"requested_memory_high_bytes":c::HIGH,"kernel_memory_max_bytes":cap,"kernel_memory_high_bytes":high,"host_page_size_bytes":page,"current_cgroup_charge_bytes":charge,"cgroup_charge_before_bytes":charge_before,"cgroup_charge_after_bytes":charge_after,"remaining_hard_memory_growth_bytes":remaining,"memory_swap_max_bytes":0,"tasks_max":512,"cpu_quota_usec":quota,"cpu_period_usec":period,"systemd_properties":before}),
    )
}
fn guard(g: &Value, p: &Value, peer: &Peer, plan_sha: &str, sample: u64, now: u64) -> Result<()> {
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("canary peer guard clock missing")?;
    ensure!(
        t >= sample
            && t <= now
            && now - t <= 1800
            && c::guard_matches(&peer.d, &peer.launch, p)
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::GUARD_SHA
            && g["plan_sha256"] == plan_sha
            && g["producer_invocation_id"] == peer.d.invocation_id
            && g["producer"]["invocation_id"] == peer.d.invocation_id
            && g["producer"]["pid"] == peer.launch["main_pid"]
            && g["producer"]["cgroup"] == peer.owner["ControlGroup"]
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restarts"] == 0
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer_stop_enabled"] == true
            && g["bounded_canary"] == p["bounded_canary"]
            && g["bounded_measurement"] == false
            && g.get("native_main").is_some_and(Value::is_null)
            && g["canary_target_stop_valid"] == false
            && g["maximum_root_physical_bytes"] == c::SCRATCH
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::SCRATCH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::SCRATCH)
            && g["maximum_worker_vmas"] == 3500000
            && g["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|n| n > 1)
                && w[0][1].as_u64().is_some_and(|n| n > 0 && n < 3500000))
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(p["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "bounded canary guard is stale, tripped, draining or another resource profile"
    );
    Ok(())
}
fn protection(
    peer: &Peer,
    sample: u64,
    now: u64,
    provided: Option<&BoundFile>,
) -> Result<(BoundFile, Value, Value)> {
    let plan: BoundFile = serde_json::from_value(peer.launch["guard_plan"].clone())?;
    let p = native209::immutable_json(&plan)?;
    ensure!(
        c::guard_matches(&peer.d, &peer.launch, &p),
        "canary peer protective plan differs"
    );
    let directory = Path::new(
        p["receipt_directory"]
            .as_str()
            .context("canary peer guard directory missing")?,
    );
    let latest = warmup223::completed_guard_binding(PROTECTIVE, directory, sample, now)?;
    let b: BoundFile = serde_json::from_value(latest["binding"].clone())?;
    ensure!(
        provided.is_none_or(|given| *given == b),
        "canary peer did not receive the latest completed guard"
    );
    let g = bound_json(&b)?;
    guard(&g, &p, peer, &plan.sha256, sample, now)?;
    let manager = canary227_capture::manager(&g, &plan, now)
        .context("bounded canary peer protective service or timer validation failed")?;
    Ok((b, g, json!({"completed":latest,"manager":manager})))
}
fn sample_time(f: &Value) -> Result<u64> {
    utc_seconds(
        f["sampled_at_utc"]
            .as_str()
            .context("canary peer sample time absent")?,
    )
}
fn remaining(sampled: u64, guarded: u64) -> Result<(u64, u64)> {
    ensure!(
        sampled <= c::SCRATCH && guarded <= c::SCRATCH,
        "canary whole-root allocation exceeds 300 GB cap"
    );
    let credit = sampled.min(guarded);
    Ok((
        c::SCRATCH
            .checked_sub(credit)
            .and_then(|n| n.checked_add(c::CONTROL_METADATA))
            .context("canary remaining growth overflow")?,
        credit,
    ))
}
fn allocation(peer: &Peer, o: &Value, g: &Value) -> Result<(u64, u64, u64)> {
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("canary whole-root observer census absent")?
        .iter()
        .filter(|r| r["producer_unit"] == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "canary requires exactly one same-IID whole-root observation"
    );
    let d = rows[0];
    let r = &d["observation"];
    ensure!(
        d["status"] == "observed"
            && d["error"].is_null()
            && d["scratch_path"] == c::ROOT
            && r["scratch_path"] == c::ROOT
            && r["invocation_binding_stable"] == true,
        "canary scratch-only or missing observation cannot earn whole-root credit"
    );
    let mut started = None;
    for key in [
        "producer_before",
        "producer_after",
        "controller_before",
        "controller_after",
    ] {
        let u = &r[key];
        ensure!(
            u["unit"] == c::UNIT
                && u["invocation_id"] == peer.d.invocation_id
                && u["main_pid"] == peer.launch["main_pid"]
                && u["restarts"] == 0
                && u["control_group"] == peer.owner["ControlGroup"]
                && u["active_state"] == "active"
                && u["sub_state"] == "running"
                && u["rss"]["census_stable"] == true,
            "canary whole-root observation changed producer identity"
        );
        let processes = u["rss"]["processes"]
            .as_array()
            .context("canary sampled process start census absent")?;
        let main = processes
            .iter()
            .filter(|p| p["pid"] == peer.launch["main_pid"])
            .collect::<Vec<_>>();
        ensure!(
            main.len() == 1,
            "canary sampled main PID missing or duplicated"
        );
        let start = main[0]["start_ticks"]
            .as_u64()
            .filter(|v| *v > 0)
            .context("canary sampled main start missing")?;
        ensure!(
            started.is_none_or(|v| v == start),
            "canary sampled PID reused within observation"
        );
        started = Some(start);
    }
    let pass = |v: &Value| -> Result<u64> {
        v["physical_bytes"]
            .as_u64()
            .filter(|n| *n <= c::SCRATCH)
            .context("canary raw whole-root allocation pass missing or over cap")
    };
    let (s1, s2) = (pass(&r["scratch_pass_1"])?, pass(&r["scratch_pass_2"])?);
    let (g1, g2) = (
        pass(&g["root_physical_observation"]["first"])?,
        pass(&g["root_physical_observation"]["second"])?,
    );
    ensure!(
        r["conservative_observed_physical_bytes"] == s1.max(s2)
            && g["root_physical_observation"]["conservative_physical_bytes"] == g1.max(g2),
        "canary budget maximum does not reproduce raw allocation passes"
    );
    let sampled = s1.min(s2);
    let guarded = g1.min(g2);
    let mut worker_pid = None;
    for key in ["worker_before", "worker_after"] {
        let w = &r[key];
        let pid = w["pid"]
            .as_u64()
            .filter(|n| *n > 1)
            .context("canary worker PID missing")?;
        let path = Path::new(
            w["executable"]
                .as_str()
                .context("canary worker executable missing")?,
        );
        ensure!(
            w["matching_workers"] == 1
                && w["executable_beneath_bound_scratch"] == true
                && path.starts_with(c::ROOT)
                && path.file_name().is_some_and(|n| n == "historical-worker")
                && w["vmas"].as_u64().is_some_and(|n| n > 0 && n < 3500000)
                && worker_pid.is_none_or(|p| p == pid)
                && g["workers"][0][0] == pid,
            "canary sampled/guarded worker identity, count or VMA bound differs"
        );
        worker_pid = Some(pid);
    }
    let (growth, credit) = remaining(sampled, guarded)?;
    Ok((growth, credit, sampled))
}
type Split = (Value, BTreeMap<String, BoundFile>, u64, Vec<Value>);
pub(super) fn split(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<Split> {
    let mut remaining_guards: BTreeMap<String, BoundFile> =
        serde_json::from_value(serde_json::to_value(guards)?)?;
    let Some(peer) = accepted(f)? else {
        return Ok((f.clone(), remaining_guards, 0, vec![]));
    };
    let b = remaining_guards
        .remove(c::UNIT)
        .context("live canary omitted from complete protected guard set")?;
    let (binding, g, proof) = protection(&peer, sample, now, Some(&b))?;
    let (_, recorded_credit, sampled) = allocation(&peer, o, &g)?;
    let owner_before = properties(&peer)?;
    let current_allocation = canary227_allocation::observe(Path::new(c::ROOT), || {
        ensure!(
            owner_before == properties(&peer)?,
            "canary allocation owner changed during current proof"
        );
        Ok(())
    })?;
    let current_credit = current_allocation["allocation_lower_bound_bytes"]
        .as_u64()
        .context("canary current allocation proof missing")?;
    let (growth, credit) = remaining(recorded_credit, current_credit)?;
    Ok((
        view(f)?,
        remaining_guards,
        growth,
        vec![
            json!({"epoch":227,"unit":c::UNIT,"invocation_id":peer.d.invocation_id,"launch":private157::binding(&peer.d.launch_receipt),"guard":private157::binding(&binding),"actual_guard_timer_proof":proof,"sampled_whole_root_physical_bytes":sampled,"guarded_whole_root_physical_bytes":g["root_physical_observation"]["conservative_physical_bytes"],"current_allocation_integrity_proof":current_allocation,"whole_root_allocation_credit_bytes":credit,"control_metadata_bytes":c::CONTROL_METADATA,"remaining_growth_bytes":growth,"accounting":"300 GB whole-root cap less minimum coordinated/current guarded/current unique allocation, plus separate 16 MiB external control metadata"}),
        ],
    ))
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let Some(peer) = accepted(f)? else {
        return Ok((0, vec![]));
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let (guard_binding, guard_sample, protection) = protection(&peer, sample_time(f)?, now, None)?;
    let caps = kernel(&peer)?;
    let floor = memory_floor(f, host_total_memory()?)?;
    let remaining = caps["remaining_hard_memory_growth_bytes"]
        .as_u64()
        .context("canary remaining memory absent")?;
    let top_up = floor["memory_floor_top_up_bytes"]
        .as_u64()
        .context("canary memory floor top-up absent")?;
    let row = memory::row(
        &peer.d.invocation_id,
        caps,
        floor,
        guard_binding,
        guard_sample,
        protection,
    )?;
    Ok((add_memory(remaining, top_up, memory::GUARD)?, vec![row]))
}
fn static_caps(k: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for key in [
        "requested_memory_max_bytes",
        "requested_memory_high_bytes",
        "kernel_memory_max_bytes",
        "kernel_memory_high_bytes",
        "host_page_size_bytes",
        "memory_swap_max_bytes",
        "tasks_max",
        "cpu_quota_usec",
        "cpu_period_usec",
        "systemd_properties",
    ] {
        result.insert(
            key.into(),
            k.get(key).context("canary static cap missing")?.clone(),
        );
    }
    Ok(Value::Object(result))
}
pub(super) fn limits(f: &Value) -> Result<Option<Value>> {
    let Some(peer) = accepted(f)? else {
        return Ok(None);
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    protection(&peer, sample_time(f)?, now, None)?;
    Ok(Some(static_caps(&kernel(&peer)?)?))
}
pub(super) fn current(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let Some(peer) = accepted(f)? else {
        return Ok(());
    };
    let u = current
        .get(c::UNIT)
        .context("current complete census omitted live canary")?;
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ControlGroup",
        "ActiveState",
        "SubState",
    ] {
        ensure!(
            u[key] == peer.owner[key],
            "canary peer current manager identity changed:{key}"
        );
    }
    ensure!(
        c::same_command(&u["ExecStart"], &peer.launch["expected_exec_start"]),
        "canary peer current command changed"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    protection(&peer, sample_time(f)?, now, None)?;
    kernel(&peer)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> Peer {
        let (mut d, mut r) = c::peer_fixture();
        d.launch_receipt.path = LAUNCH.into();
        r["unit"] = json!(c::UNIT);
        r["invocation_id"] = json!(d.invocation_id);
        r["main_pid"] = json!(42);
        r["producer_start_monotonic_microseconds"] = json!(123000000);
        let owner = json!({"Id":c::UNIT,"Type":"exec","LoadState":"loaded","ActiveState":"active","SubState":"running","Result":"success","MainPID":"42","InvocationID":d.invocation_id,"NRestarts":"0","ControlGroup":format!("/system.slice/{}",c::UNIT),"ExecStart":r["expected_exec_start"]});
        Peer {
            d,
            launch: r,
            owner,
        }
    }
    fn row(p: &Peer) -> Value {
        json!({"epoch":227,"phase":"diagnostic-qualification","ordinary_replay_claim":false,"scratch_path":c::ROOT,"launch_receipt":LAUNCH,"launch_receipt_sha256":p.d.launch_receipt.sha256,"producer":p.owner})
    }
    fn fleet(p: &Peer) -> Value {
        json!({"active":[row(p)],"unit_census":{c::UNIT:p.owner},"gates":{"227":{"state":"failed-needs-repair","old":"immutable"}}})
    }
    fn guard_fixture(p: &Peer) -> (Value, Value) {
        let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":c::UNIT,"invocation_id":p.d.invocation_id,"filesystem":"/","worker_root":c::ROOT,"minimum_free_bytes":p.launch["guard_minimum_free_bytes"],"maximum_root_physical_bytes":c::SCRATCH,"maximum_worker_vmas":3500000,"bounded_canary":{"expected_uid":1000,"maximum_drainage_seconds":120,"target_stop_intent":Path::new(c::ROOT).join("receipts/target-stop.json")}});
        let guard = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","recorded_unix_seconds":101,"guard_sha256":c::GUARD_SHA,"plan_sha256":"plan","producer_invocation_id":p.d.invocation_id,"producer":{"invocation_id":p.d.invocation_id,"pid":42,"cgroup":format!("/system.slice/{}",c::UNIT),"active":"active","sub":"running","load_state":"loaded","result":"success","restarts":0,"restart_policy":"no","kill_mode":"control-group","delegated":false},"producer_stop_enabled":true,"bounded_canary":plan["bounded_canary"],"bounded_measurement":false,"native_main":null,"canary_target_stop_valid":false,"maximum_root_physical_bytes":c::SCRATCH,"root_physical_observation":{"maximum_physical_bytes":c::SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":100000000000u64,"first":{"physical_bytes":90000000000u64},"second":{"physical_bytes":100000000000u64}},"maximum_worker_vmas":3500000,"workers":[[55,1000]],"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,"minimum_free_bytes":plan["minimum_free_bytes"],"available_bytes":3000000000000u64,"remote_mutations":false,"r2_mutations":false});
        (plan, guard)
    }
    fn observer(p: &Peer) -> Value {
        let unit = json!({"unit":c::UNIT,"invocation_id":p.d.invocation_id,"main_pid":42,"restarts":0,"control_group":p.owner["ControlGroup"],"active_state":"active","sub_state":"running","rss":{"census_stable":true,"processes":[{"pid":42,"start_ticks":12300}]}});
        let worker = json!({"pid":55,"executable":Path::new(c::ROOT).join("scratch/run/historical-worker"),"matching_workers":1,"executable_beneath_bound_scratch":true,"vmas":1000});
        json!({"diagnostic_replays":[{"producer_unit":c::UNIT,"status":"observed","error":null,"scratch_path":c::ROOT,"observation":{"scratch_path":c::ROOT,"invocation_binding_stable":true,"producer_before":unit,"producer_after":unit,"controller_before":unit,"controller_after":unit,"worker_before":worker,"worker_after":worker,"conservative_observed_physical_bytes":150000000000u64,"scratch_pass_1":{"physical_bytes":150000000000u64},"scratch_pass_2":{"physical_bytes":140000000000u64}}}]})
    }
    #[test]
    fn exact_canary_is_not_a_full_epoch_and_omitted_duplicate_or_other_generation_fails() {
        let p = peer();
        let f = fleet(&p);
        assert!(roster(&f).unwrap());
        let mut omitted = f.clone();
        omitted["active"] = json!([]);
        assert!(roster(&omitted).is_err());
        let mut duplicate = f.clone();
        duplicate["active"].as_array_mut().unwrap().push(row(&p));
        assert!(roster(&duplicate).is_err());
        for (key, value) in [
            ("scratch_path", json!(format!("{}/scratch", c::ROOT))),
            ("ordinary_replay_claim", json!(true)),
            ("epoch", json!(228)),
        ] {
            let mut changed = row(&p);
            changed[key] = value;
            assert!(row_scope(&changed).is_err());
        }
        let mut old = f.clone();
        old["active"][0]["producer"]["Id"] =
            json!("horizon-qualify-227-v1625-bounded-resource-old.service");
        assert!(roster(&old).is_err());
        let mut hidden = f.clone();
        hidden["unit_census"]["horizon-qualify-227-v1625-bounded-resource-old.service"] =
            p.owner.clone();
        assert!(roster(&hidden).is_err());
    }
    #[test]
    fn derived_accounting_preserves_raw_claims_gates_and_history() {
        let p = peer();
        let mut f = fleet(&p);
        let extra = json!({"epoch":204,"producer":{"Id":"other"},"claim":"unchanged"});
        f["active"].as_array_mut().unwrap().push(extra.clone());
        let reduced = view(&f).unwrap();
        assert_eq!(reduced["active"], json!([extra]));
        assert_eq!(reduced["unit_census"], f["unit_census"]);
        assert_eq!(reduced["gates"], f["gates"]);
        assert_eq!(f["active"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn complete_roster_accepts_canary_without_dropping_native223() {
        let p = peer();
        let mut f = fleet(&p);
        assert_eq!(prefix223_native20_admission::roster(&f).unwrap().len(), 1);
        f["active"]
            .as_array_mut()
            .unwrap()
            .push(prefix223_live_peer::fixture_row());
        assert_eq!(prefix223_live_peer::roster(&f).unwrap().len(), 2);
    }
    #[test]
    fn separate_metadata_and_minimum_raw_allocations_survive_reclaim() {
        let p = peer();
        let (_, g) = guard_fixture(&p);
        let o = observer(&p);
        let (growth, credit, sampled) = allocation(&p, &o, &g).unwrap();
        assert_eq!(sampled, 140000000000);
        assert_eq!(credit, 90000000000);
        assert_eq!(growth, 210000000000 + c::CONTROL_METADATA);
        assert_eq!(
            remaining(c::SCRATCH, c::SCRATCH).unwrap().0,
            c::CONTROL_METADATA
        );
        assert!(remaining(c::SCRATCH + 1, 0).is_err());
        let mut reclaimed = g.clone();
        reclaimed["root_physical_observation"]["first"]["physical_bytes"] = json!(0);
        assert_eq!(allocation(&p, &o, &reclaimed).unwrap().0, c::CANDIDATE);
    }
    #[test]
    fn no_credit_for_scratch_only_missing_wrong_iid_pid_or_worker() {
        let p = peer();
        let (_, g) = guard_fixture(&p);
        let o = observer(&p);
        for (path, value) in [
            (
                "/diagnostic_replays/0/scratch_path",
                json!(format!("{}/scratch", c::ROOT)),
            ),
            (
                "/diagnostic_replays/0/observation/producer_after/invocation_id",
                json!("b".repeat(32)),
            ),
            (
                "/diagnostic_replays/0/observation/producer_after/main_pid",
                json!(43),
            ),
            (
                "/diagnostic_replays/0/observation/worker_after/pid",
                json!(56),
            ),
            (
                "/diagnostic_replays/0/observation/producer_after/rss/processes/0/start_ticks",
                json!(456),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(allocation(&p, &bad, &g).is_err(), "{path}");
        }
        let mut missing = o.clone();
        missing["diagnostic_replays"][0]["observation"]["scratch_pass_1"]
            .as_object_mut()
            .unwrap()
            .remove("physical_bytes");
        assert!(allocation(&p, &missing, &g).is_err());
    }
    #[test]
    fn exact_guard_rejects_full_profile_stale_wrong_owner_and_draining() {
        let p = peer();
        let (plan, g) = guard_fixture(&p);
        guard(&g, &plan, &p, "plan", 100, 102).unwrap();
        for (path, value) in [
            ("/maximum_root_physical_bytes", json!(471798691840u64)),
            ("/producer_invocation_id", json!("b".repeat(32))),
            ("/producer/pid", json!(43)),
            ("/recorded_unix_seconds", json!(99)),
            ("/trip_reason", json!("disk")),
            ("/producer_stop_enabled", json!(false)),
            ("/canary_target_stop_valid", json!(true)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(guard(&bad, &plan, &p, "plan", 100, 102).is_err(), "{path}");
        }
        assert!(guard(&g, &plan, &p, "plan", 100, 2000).is_err());
        let mut full = plan.clone();
        full["maximum_root_physical_bytes"] = json!(471798691840u64);
        assert!(guard(&g, &full, &p, "plan", 100, 102).is_err());
    }
    #[test]
    fn cap_brackets_exclude_variable_memory_charge() {
        let k = json!({"requested_memory_max_bytes":c::MEMORY,"requested_memory_high_bytes":c::HIGH,
            "kernel_memory_max_bytes":224999997440u64,"kernel_memory_high_bytes":149999996928u64,
            "host_page_size_bytes":4096,"memory_swap_max_bytes":0,"tasks_max":512,
            "cpu_quota_usec":800000,"cpu_period_usec":100000,"systemd_properties":{},
            "current_cgroup_charge_bytes":100,"remaining_hard_memory_growth_bytes":1000});
        let mut grown = k.clone();
        grown["current_cgroup_charge_bytes"] = json!(200);
        grown["remaining_hard_memory_growth_bytes"] = json!(900);
        assert_eq!(static_caps(&k).unwrap(), static_caps(&grown).unwrap());
        grown["kernel_memory_max_bytes"] = json!(999);
        assert_ne!(static_caps(&k).unwrap(), static_caps(&grown).unwrap());
    }
    #[test]
    fn requested_and_kernel_rounded_caps_are_distinct_and_remaining_is_not_rss() {
        let page = 4096;
        let max = c::MEMORY / page * page;
        let high = c::HIGH / page * page;
        assert_eq!(memory_values(max, high, 100, 0, page).unwrap(), max - 100);
        assert!(memory_values(c::MEMORY, c::HIGH, 100, 0, page).is_err());
        assert!(memory_values(max, high, max + 1, 0, page).is_err());
        assert!(memory_values(max, high, 100, 1, page).is_err());
        assert!(memory_values(max, high, 100, 0, 0).is_err());
    }
    #[test]
    fn native223_floor_top_up_is_once_and_survives_derived_active_view() {
        let mut f = fleet(&peer());
        let row = prefix223_live_peer::fixture_row();
        let owner = singleton227_admission::active_owner(&row).unwrap().clone();
        f["unit_census"][prefix223_native20::UNIT] = owner;
        f["active"].as_array_mut().unwrap().push(row);
        let total = 1_000_000_000_000u64;
        let policy = memory_floor(&f, total).unwrap();
        assert_eq!(
            policy["memory_floor_top_up_bytes"],
            PREFIX223_MEMORY_FLOOR - total / 10
        );
        assert_eq!(
            policy["effective_available_memory_floor_bytes"],
            PREFIX223_MEMORY_FLOOR
        );
        let mut derived = f.clone();
        derived["active"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["epoch"] != 223);
        assert_eq!(memory_floor(&derived, total).unwrap(), policy);
        assert_eq!(
            memory_floor(&f, 10_000_000_000_000).unwrap()["memory_floor_top_up_bytes"],
            0
        );
        let inactive = fleet(&peer());
        assert_eq!(
            memory_floor(&inactive, total).unwrap()["memory_floor_top_up_bytes"],
            0
        );
        assert!(memory_floor(&f, 0).is_err());
        let mut missing = f.clone();
        missing["unit_census"]
            .as_object_mut()
            .unwrap()
            .remove(prefix223_native20::UNIT);
        assert!(memory_floor(&missing, total).is_err());
        f["unit_census"][prefix223_native20::UNIT]["InvocationID"] = json!("foreign");
        assert!(memory_floor(&f, total).is_err());
        assert_eq!(
            add_memory(
                total / 10 + c::MEMORY,
                PREFIX223_MEMORY_FLOOR - total / 10,
                123
            )
            .unwrap(),
            PREFIX223_MEMORY_FLOOR + c::MEMORY + 123
        );
        assert!(add_memory(u64::MAX, 1, 0).is_err());
        assert!(add_memory(u64::MAX - 1, 1, 1).is_err());
    }
    #[test]
    fn original_admission_requires_native223_floor_proof_and_nonoverflowing_growth() {
        let mut f = fleet(&peer());
        let row = prefix223_live_peer::fixture_row();
        f["unit_census"][prefix223_native20::UNIT] =
            singleton227_admission::active_owner(&row).unwrap().clone();
        f["active"].as_array_mut().unwrap().push(row);
        let required = PREFIX223_MEMORY_FLOOR + c::MEMORY + 123;
        let good = json!({"output_credit_profile":output_credit204205::PROFILE,
            "memory_floor_policy":memory_floor(&f,1_000_000_000_000).unwrap(),
            "auxiliary_remaining_memory_growth_bytes":123,"required_available_memory_bytes":required,
            "available_memory_bytes":required});
        original_memory(&good, &f).unwrap();
        for (key, v) in [
            ("memory_floor_policy", Value::Null),
            ("output_credit_profile", json!("legacy")),
            ("required_available_memory_bytes", json!(required - 1)),
            ("available_memory_bytes", json!(required - 1)),
            ("auxiliary_remaining_memory_growth_bytes", json!(u64::MAX)),
        ] {
            let mut bad = good.clone();
            bad[key] = v;
            assert!(original_memory(&bad, &f).is_err(), "{key}");
        }
        original_memory(&Value::Null, &fleet(&peer())).unwrap();
    }
}
