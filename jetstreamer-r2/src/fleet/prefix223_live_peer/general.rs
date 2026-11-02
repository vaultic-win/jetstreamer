//! Existing ordinary root-cohort replay protected by the maintenance accountant.
//! This is accounting of a real owner, never admission or a runtime exception.
use super::*;

const UNIT: &str = "horizon-qualify-237-general-target1-budget620-v2.service";
const IID: &str = "3949b88a4ca34fc892a19f219cebd476";
const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-budget620-v2";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-237-budget620-preparation-v2/actual-launch.json";
const LAUNCH_SHA: &str = "9647e8c4e7989c6ca3909b83cf11f77a0a2eb5e1e69dce87067ba01526645bb6";
const FIRST: &str =
    "/var/lib/jetstreamer/horizon-237-budget620-operational-handoff-v2/first-fire.json";
const FIRST_SHA: &str = "14f0c42a454912c8ebd568ef651688570452d286114a2daee4f32278931288a2";
const PLAN: &str = "/var/lib/jetstreamer/horizon-237-budget620-guard-bound-v2/guard-plan.json";
const PLAN_SHA: &str = "97c5791aafe0f930c867ae857d4aa6f9a505fc2065ad7fb14fbb92c8b04b9702";
const GUARD: &str = "horizon-237-budget620-protective-v2.service";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-237-budget620-guard-receipts-v2";
const GROWTH: u64 = 620_000_000_000;
const FLOOR: u64 = 749_249_191_922;
const MEMORY: u64 = 225_000_000_000;
const HIGH: u64 = 150_000_000_000;
const GUARD_MEMORY: u64 = 1 << 30;

pub(super) fn selector(unit: &str) -> Option<(&'static str, &'static str)> {
    (unit == UNIT).then_some((GUARD, RECEIPTS))
}
fn selected(row: &Value) -> bool {
    ["producer", "unit", "controller"]
        .iter()
        .any(|key| row[*key]["Id"] == UNIT)
}
fn rows(f: &Value) -> Result<Vec<&Value>> {
    Ok(f["active"]
        .as_array()
        .context("ordinary peer complete active census")?
        .iter()
        .filter(|r| selected(r))
        .collect())
}
fn identity(u: &Value) -> Result<()> {
    ensure!(
        u["Id"] == UNIT
            && u["InvocationID"] == IID
            && u["NRestarts"] == "0"
            && u["LoadState"] == "loaded"
            && u["MainPID"] == "2030542"
            && u["ControlGroup"] == format!("/system.slice/{UNIT}")
            && u["ActiveState"] == "active"
            && u["SubState"] == "running",
        "ordinary replay peer original live identity changed"
    );
    Ok(())
}
fn live(u: &Value) -> Result<()> {
    identity(u)?;
    ensure!(
        u["Type"] == "exec",
        "ordinary replay peer current Type changed"
    );
    Ok(())
}
fn shape(f: &Value) -> Result<()> {
    let selected = rows(f)?;
    ensure!(selected.len() <= 1, "duplicate ordinary replay peer");
    for row in selected {
        let u = singleton227_admission::active_owner(row)?;
        live(u)?;
        ensure!(
            row["epoch"] == 237
                && row["phase"] == "replay"
                && row.get("ordinary_replay_claim").is_none_or(|v| v == true)
                && f["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["epoch"] == 237)
                    .count()
                    == 1
                && f["unit_census"][UNIT] == *u,
            "ordinary replay peer scope/census changed"
        );
        let gates: Vec<_> = f["epochs"]
            .as_array()
            .context("ordinary peer retained epoch gates")?
            .iter()
            .filter(|r| r["epoch"] == 237)
            .collect();
        ensure!(
            gates.len() == 1
                && gates[0]["gate_evidence"]
                    .as_array()
                    .is_some_and(|e| e.contains(&json!({"path":LAUNCH,"sha256":LAUNCH_SHA}))
                        && e.contains(&json!({"path":FIRST,"sha256":FIRST_SHA}))),
            "ordinary replay peer actual launch/first-fire evidence omitted"
        );
    }
    Ok(())
}
pub(super) fn without(f: &Value) -> Result<Value> {
    shape(f)?;
    let mut view = f.clone();
    // Only the private legacy arithmetic view is reduced. Every caller adds the
    // exact owner's full obligations back; raw census/history are untouched.
    view["active"]
        .as_array_mut()
        .unwrap()
        .retain(|r| !selected(r));
    Ok(view)
}
pub(super) fn names(f: &Value) -> Result<BTreeSet<String>> {
    shape(f)?;
    Ok(rows(f)?.iter().map(|_| UNIT.to_owned()).collect())
}
fn immutable(path: &str, sha: &str) -> Result<Value> {
    native209::immutable_json(&BoundFile {
        path: path.into(),
        sha256: sha.into(),
    })
}
fn provenance(f: &Value) -> Result<(Value, Value)> {
    shape(f)?;
    let launch = immutable(LAUNCH, LAUNCH_SHA)?;
    let first = immutable(FIRST, FIRST_SHA)?;
    let plan = immutable(PLAN, PLAN_SHA)?;
    validate_provenance(&launch, &first, &plan)?;
    Ok((launch, plan))
}
fn validate_provenance(launch: &Value, first: &Value, plan: &Value) -> Result<()> {
    // This original receipt did not capture Type; require it on the genuine
    // current census and live properties rather than inventing source fields.
    identity(&launch["manager"])?;
    ensure!(
        launch["schema"] == "operator-ordinary237-budget620-actual-launch-v2"
            && launch["epoch"] == 237
            && launch["launched"] == true
            && launch["evidence"]["units"] == json!([{"unit":UNIT,"invocation_id":IID}])
            && launch["private_output_only"] == true
            && launch["publication_authorized"] == false
            && launch["r2_mutations"] == false
            && first["schema"]
                == "operator-ordinary237-budget620-genuine-first-worker-guard-fire-v2"
            && first["unit"] == UNIT
            && first["actual_producer_invocation_id"] == IID
            && first["guard_unit"] == GUARD
            && first["guard_timer"] == GUARD.replace(".service", ".timer")
            && first["one_actual_worker_required_and_present"] == true
            && first["guard_floor_bytes"] == FLOOR
            && first["whole_root_cap_bytes"] == GROWTH
            && first["guard"]["plan"] == PLAN
            && first["guard"]["plan_sha256"] == PLAN_SHA
            && first["guard"]["guard_sha256"] == singleton207::GUARD_SHA
            && first["r2_archive_or_sidecar_mutations"] == false
            && plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == UNIT
            && plan["invocation_id"] == IID
            && plan["filesystem"] == "/"
            && plan["worker_root"] == ROOT
            && plan["minimum_free_bytes"] == FLOOR
            && plan["maximum_root_physical_bytes"] == GROWTH
            && plan["maximum_worker_vmas"] == 3_500_000
            && plan["receipt_directory"] == RECEIPTS,
        "ordinary replay peer actual source launch/guard lineage changed"
    );
    Ok(())
}
fn guard_shape(g: &Value, sample: u64, now: u64) -> Result<()> {
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("ordinary peer guard clock")?;
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == singleton207::GUARD_SHA
            && g["plan"] == PLAN
            && g["plan_sha256"] == PLAN_SHA
            && t >= sample
            && t <= now
            && now - t <= 1800
            && g["producer_invocation_id"] == IID
            && g["producer"]["invocation_id"] == IID
            && g["producer"]["pid"] == 2_030_542
            && g["producer"]["restarts"] == 0
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer_stop_enabled"] == true
            && g["minimum_free_bytes"] == FLOOR
            && g["available_bytes"].as_u64().is_some_and(|n| n >= FLOOR)
            && g["maximum_root_physical_bytes"] == GROWTH
            && g["maximum_worker_vmas"] == 3_500_000
            && g["root_physical_observation"]["maximum_physical_bytes"] == GROWTH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= GROWTH)
            && g["workers"].as_array().is_some_and(|w| w.len() == 1)
            && g["workers"][0][0].as_u64().is_some_and(|n| n > 1)
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3_500_000)
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error",
                "target_handoff_error",
                "bounded_canary",
                "target_handoff",
                "native_main"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["bounded_measurement"] == false
            && g["scratch_deleted"] == false
            && g["r2_mutations"] == false
            && g["remote_mutations"] == false,
        "ordinary replay peer protective evidence changed, stale or tripped"
    );
    Ok(())
}
pub(super) fn disk(
    f: &Value,
    guards: &mut BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    if names(f)?.is_empty() {
        return Ok((0, vec![]));
    }
    provenance(f)?;
    let b = guards
        .remove(UNIT)
        .context("ordinary replay peer guard omitted")?;
    ensure!(
        b.path.parent() == Some(Path::new(RECEIPTS)),
        "ordinary peer guard receipt escaped source directory"
    );
    guard_shape(&bound_json(&b)?, sample, now)?;
    let completed = warmup223::completed_guard_binding(GUARD, Path::new(RECEIPTS), sample, now)?;
    ensure!(
        completed["binding"] == private157::binding(&b),
        "ordinary peer guard is not latest completed fire"
    );
    let timer = singleton227_capture::properties(
        &GUARD.replace(".service", ".timer"),
        "ActiveState,SubState",
    )?;
    singleton227_capture::require(
        &timer,
        &[("ActiveState", "active"), ("SubState", "waiting")],
    )?;
    Ok((
        GROWTH,
        vec![json!({"epoch":237,"unit":UNIT,"invocation_id":IID,
        "remaining_growth_bytes":GROWTH,"scratch_growth_credit_bytes":0,"minimum_free_bytes":FLOOR,
        "guard":private157::binding(&b),"source":"full conservative ordinary root-cohort reservation"})],
    ))
}
fn caps(properties: &BTreeMap<String, String>, launch: &Value) -> Result<()> {
    singleton227_capture::require(
        properties,
        &[
            ("Type", "exec"),
            ("User", "ubuntu"),
            ("Restart", "no"),
            ("MemoryMax", "225000000000"),
            ("MemoryHigh", "150000000000"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("AllowedCPUs", "16-31"),
            ("CPUAffinity", "16-31"),
            ("ReadWritePaths", ROOT),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
        ],
    )?;
    ensure!(
        properties
            .get("ExecStart")
            .zip(launch["manager"]["ExecStart"].as_str())
            .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "ordinary replay peer command changed"
    );
    Ok(())
}
const PROPERTIES: &str = "Type,User,Restart,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,AllowedCPUs,CPUAffinity,ReadWritePaths,ProtectHome,ProtectSystem,ExecStart";
pub(super) fn current(f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    if names(f)?.is_empty() {
        return Ok(());
    }
    let (launch, _) = provenance(f)?;
    let current = census
        .get(UNIT)
        .context("ordinary replay peer current owner omitted")?;
    live(current)?;
    ensure!(
        pipeline_status::same_exec_start(
            current["ExecStart"]
                .as_str()
                .context("ordinary peer current command")?,
            launch["manager"]["ExecStart"]
                .as_str()
                .context("ordinary peer source command")?
        ),
        "ordinary replay peer current command changed"
    );
    caps(
        &singleton227_capture::properties(UNIT, PROPERTIES)?,
        &launch,
    )
}
pub(super) fn limits(f: &Value) -> Result<Value> {
    if names(f)?.is_empty() {
        return Ok(json!({}));
    }
    let (launch, _) = provenance(f)?;
    let producer = singleton227_capture::properties(UNIT, PROPERTIES)?;
    caps(&producer, &launch)?;
    let guard = singleton227_capture::properties(GUARD, "MemoryMax,TasksMax,ExecStart")?;
    singleton227_capture::require(&guard, &[("MemoryMax", "1073741824")])?;
    Ok(json!({(UNIT):{"producer":producer,"guard":guard}}))
}
fn memory_growth(
    cap: u64,
    high: u64,
    charge: u64,
    swap: u64,
    guard: u64,
    page: u64,
) -> Result<u64> {
    ensure!(
        page.is_power_of_two()
            && (4096..=65536).contains(&page)
            && cap == MEMORY / page * page
            && high == HIGH / page * page
            && charge <= cap
            && swap == 0
            && guard == GUARD_MEMORY,
        "ordinary replay peer hard memory/high/swap/guard ceiling changed"
    );
    (cap - charge)
        .checked_add(guard)
        .context("ordinary replay peer memory overflow")
}
pub(super) fn validate_saved_row(row: &Value) -> Result<()> {
    if row["unit"] != UNIT {
        return Ok(());
    }
    let number = |key: &str| -> Result<u64> {
        row[key]
            .as_u64()
            .with_context(|| format!("ordinary peer saved memory integer missing: {key}"))
    };
    let expected = memory_growth(
        number("hard_memory_cap_bytes")?,
        number("kernel_memory_high_bytes")?,
        number("current_cgroup_charge_bytes")?,
        number("memory_swap_max_bytes")?,
        number("guard_hard_memory_reserved_bytes")?,
        number("host_page_size_bytes")?,
    )?;
    ensure!(
        row["invocation_id"] == IID && number("remaining_hard_memory_growth_bytes")? == expected,
        "ordinary peer saved memory identity or additive obligation changed"
    );
    Ok(())
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    if names(f)?.is_empty() {
        return Ok((0, vec![]));
    }
    provenance(f)?;
    let root = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    ensure!(
        root.canonicalize()? == root,
        "ordinary replay peer cgroup redirected"
    );
    let read = |n: &str| -> Result<u64> { Ok(fs::read_to_string(root.join(n))?.trim().parse()?) };
    let (cap, high, charge, swap) = (
        read("memory.max")?,
        read("memory.high")?,
        read("memory.current")?,
        read("memory.swap.max")?,
    );
    let props = singleton227_capture::properties(GUARD, "MemoryMax")?;
    singleton227_capture::require(&props, &[("MemoryMax", "1073741824")])?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    let growth = memory_growth(cap, high, charge, swap, GUARD_MEMORY, page)?;
    Ok((
        growth,
        vec![
            json!({"unit":UNIT,"invocation_id":IID,"hard_memory_cap_bytes":cap,
        "kernel_memory_high_bytes":high,"current_cgroup_charge_bytes":charge,"memory_swap_max_bytes":swap,
        "guard_hard_memory_reserved_bytes":GUARD_MEMORY,"remaining_hard_memory_growth_bytes":growth,
        "host_page_size_bytes":page}),
        ],
    ))
}
#[cfg(test)]
mod tests;
