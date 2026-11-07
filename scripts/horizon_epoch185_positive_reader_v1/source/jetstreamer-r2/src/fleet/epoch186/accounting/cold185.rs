//! Consume the same exact native task through setup, running and terminal retention.
//! No unit-prefix exception, resource credit, replay or publication authority.
use super::*;

pub(super) fn actual(plan: &Value, clock: u64) -> Result<Option<Value>> {
    let current = crate::fleet::cold185::enrollment::current_allocation(plan, clock)?;
    if let Some(value) = &current {
        validate_aggregate(value, &plan["epoch185_cold_startpre_registration"])?;
    }
    Ok(current)
}

/// Prove the exact epoch 185 fleet. Initial setup validates the genuine old
/// Frame against its actual prelaunch tuple; running and terminal retention use
/// the real current Frame. Current freshness, owners, obligations, native census
/// and emitted bindings always use actual evidence. Historical bindings stay raw.
pub(super) fn accepted_basis(
    spec: &SpecView<'_>,
    bundle: &BundleView<'_>,
    current: Option<&Value>,
    clock: u64,
) -> Result<u64> {
    let Some(current) = current else {
        return evidence::accepted_basis(spec, bundle, clock);
    };
    crate::fleet::cold185::enrollment::validate_reader_bridge(
        bundle.fleet_plan,
        bundle.fleet,
        current,
        clock,
    )?;
    if retained_current_frame(current)? {
        // Later samples own their real current Frame. The typed enrollment
        // bridge validates original launch provenance without borrowing an old
        // observer or rebinding a historical Frame to the current fleet.
        return evidence::accepted_basis(spec, bundle, clock);
    }
    let old_fleet: BoundFile = serde_json::from_value(current["prior_fleet"].clone())?;
    let old_plan: BoundFile = serde_json::from_value(current["prior_fleet_plan"].clone())?;
    let old_fleet_value = protected_generated(&old_fleet)?;
    let old_plan_value = io::read(&old_plan)?;
    ensure!(
        old_fleet_value == current["prior_fleet_value"]
            && old_plan_value == current["prior_fleet_plan_value"],
        "cold185 original prelaunch fleet or plan changed"
    );
    ensure!(
        bundle.fleet["previous_fleet"] == current["prior_fleet"]
            && bundle.fleet["observer_receipt"] == old_fleet_value["observer_receipt"]
            && bundle.fleet["observer_sha256"] == old_fleet_value["observer_sha256"]
            && bundle.fleet["sampled_at_utc"] == old_fleet_value["sampled_at_utc"]
            && bundle.fleet["plan"] == json!(spec.fleet_plan.path)
            && bundle.fleet["plan_sha256"] == spec.fleet_plan.sha256,
        "cold185 successor is not the genuine same-sample complete fleet"
    );
    let inherited_spec = SpecView {
        observer: spec.observer,
        fleet: &old_fleet,
        fleet_plan: &old_plan,
        completion: spec.completion,
        resource_parent: spec.resource_parent,
        phase_events: spec.phase_events,
        reader191: spec.reader191,
        transfer191: spec.transfer191,
        correction191: spec.correction191,
        closed185: spec.closed185,
        guards: spec.guards,
        allow_retained144_terminal: spec.allow_retained144_terminal,
    };
    let inherited_bundle = BundleView {
        observer: bundle.observer,
        fleet: &old_fleet_value,
        fleet_plan: &old_plan_value,
        completion: bundle.completion,
        parent: bundle.parent,
        events: bundle.events,
        reader: bundle.reader,
        transfer: bundle.transfer,
        correction: bundle.correction,
        closed185: bundle.closed185,
        standing: bundle.standing,
    };
    evidence::accepted_basis(&inherited_spec, &inherited_bundle, clock)
}

fn retained_current_frame(current: &Value) -> Result<bool> {
    match current["stage"].as_str() {
        Some("start-pre") => {
            ensure!(
                current["guard_pending"] == true,
                "cold185 original setup guard missing"
            );
            Ok(false)
        }
        Some("running" | "terminal") => {
            ensure!(
                current["guard_pending"] == false,
                "cold185 retained lifecycle claims pending setup"
            );
            Ok(true)
        }
        _ => anyhow::bail!("cold185 unknown current Frame lifecycle"),
    }
}

fn validate_aggregate(value: &Value, registration: &Value) -> Result<()> {
    let binding: BoundFile = serde_json::from_value(registration.clone())?;
    ensure!(
        binding.path.is_absolute()
            && digest(&binding.sha256, 64)
            && value["registration"] == *registration,
        "cold185 reader does not select the fleet's exact native task"
    );
    let rows = value["peers"]
        .as_array()
        .context("cold185 complete peer family")?;
    ensure!(
        rows.len() == 1
            && matches!(
                value["stage"].as_str(),
                Some("start-pre" | "running" | "terminal")
            )
            && value["guard_pending"].as_bool().is_some()
            && (value["stage"] != "start-pre" || value["guard_pending"] == true)
            && (value["stage"] == "start-pre" || value["guard_pending"] == false),
        "cold185 retained family requires one original actor and its exact lifecycle"
    );
    let mut units = BTreeSet::new();
    let mut iids = BTreeSet::new();
    let mut parent = 0usize;
    let mut data = 0u64;
    for row in rows {
        let unit = string(row, "/unit")?;
        let iid = string(row, "/invocation_id")?;
        ensure!(
            units.insert(unit) && iids.insert(iid) && digest(iid, 32),
            "cold185 reader duplicate or invalid native owner"
        );
        ensure!(
            row["cold185_registration"] == *registration
                && row["native_pool_suballocation"] == false
                && row["source_bindings"]
                    .as_array()
                    .is_some_and(|v| !v.is_empty()),
            "cold185 reader loses original task custody or borrows native pool"
        );
        let bytes = number(row, "/data_reservation_bytes")?;
        let memory = number(row, "/memory_max_bytes")?;
        ensure!(memory > 0, "cold185 reader omits finite hard memory charge");
        ensure!(
            bytes > 0
                && row["guard_pending"] == value["guard_pending"]
                && number(row, "/reserved_guard_memory_bytes")? == 256u64 << 20
                && number(row, "/actual_actor_memory_hard_limit_bytes")?.checked_add(256u64 << 20)
                    == Some(memory),
            "cold185 retained guard memory is omitted or counted twice"
        );
        parent += 1;
        data = data.checked_add(bytes).context("cold185 DATA overflow")?;
    }
    ensure!(
        parent == 1 && data == number(value, "/candidate_DATA_bytes")?,
        "cold185 reader DATA charge is omitted, duplicated or crossed"
    );
    ensure!(
        number(value, "/guard_floor_bytes")? > 0,
        "cold185 reader loses actual guard floor"
    );
    ensure!(
        value["native"].is_object()
            && value["source_bindings"]
                .as_array()
                .is_some_and(|v| !v.is_empty()),
        "cold185 reader lacks complete native/task source evidence"
    );
    Ok(())
}

pub(super) fn peers(current: Option<&Value>) -> Result<Vec<Value>> {
    current
        .map(|v| Ok(v["peers"].as_array().context("cold185 peer array")?.clone()))
        .transpose()
        .map(Option::unwrap_or_default)
}

pub(super) fn guard_sources(current: Option<&Value>) -> Result<Vec<Value>> {
    let Some(current) = current.filter(|v| v["stage"] == "running") else {
        return Ok(Vec::new());
    };
    let source: BoundFile = serde_json::from_value(current["guard_history"]["receipt"].clone())?;
    ensure!(
        source.path.is_absolute() && digest(&source.sha256, 64),
        "cold185 completed guard source binding malformed"
    );
    Ok(vec![binding(&source)])
}

pub(super) fn guard_floor(current: Option<&Value>) -> Result<u64> {
    current
        .map(|v| number(v, "/guard_floor_bytes"))
        .transpose()
        .map(|v| v.unwrap_or(0))
}

/// A genuine normal observer's exact retained actor is charged by the typed
/// peer, not again as a generic diagnostic owner. Foreign rows remain ordinary.
pub(in crate::fleet) fn observer_owned(
    diagnostic: &Value,
    current: Option<&Value>,
) -> Result<bool> {
    let Some(current) = current else {
        return Ok(false);
    };
    let event = &current["registration_value"];
    if diagnostic["producer_unit"] != event["actor_unit"] {
        return Ok(false);
    }
    ensure!(
        retained_current_frame(current)?,
        "cold185 setup actor cannot enter normal observer owner table"
    );
    ensure!(
        diagnostic["range"] == "185"
            && diagnostic["expected_producer_invocation_id"] == event["actor_invocation_id"]
            && diagnostic["scratch_path"] == event["run_root"],
        "cold185 observer declaration crosses original range, actor or scratch custody"
    );
    if current["stage"] == "running" {
        ensure!(
            diagnostic["status"] == "observed"
                && diagnostic["observation"]["invocation_binding_stable"] == true,
            "cold185 running actor lacks genuine stable normal observation"
        );
        let actor = string(event, "/actor_unit")?;
        let actual_pid = string(&current["native"][actor], "/MainPID")?.parse::<u64>()?;
        ensure!(actual_pid > 1, "cold185 running native actor PID missing");
        for role in ["producer", "controller"] {
            for end in ["before", "after"] {
                let row = &diagnostic["observation"][format!("{role}_{end}")];
                ensure!(
                    row["unit"] == event["actor_unit"]
                        && row["invocation_id"] == event["actor_invocation_id"]
                        && row["restarts"] == 0
                        && row["active_state"] == "active"
                        && row["sub_state"] == "running"
                        && row["main_pid"] == actual_pid,
                    "cold185 observer current owner is crossed, restarted or no longer running"
                );
            }
        }
    }
    Ok(true)
}

pub(in crate::fleet) fn fleet_diagnostic_owned(
    row: &Value,
    current: Option<&Value>,
) -> Result<bool> {
    let Some(current) = current else {
        return Ok(false);
    };
    let event = &current["registration_value"];
    let actor = string(event, "/actor_unit")?;
    if row["unit"]["Id"] != actor {
        return Ok(false);
    }
    let actual = current["native"][actor]
        .as_object()
        .context("cold185 actual fleet actor")?;
    let observed = row["unit"]
        .as_object()
        .context("cold185 fleet diagnostic native actor")?;
    ensure!(!observed.is_empty(), "cold185 empty fleet diagnostic owner");
    for (key, value) in observed {
        let genuine = actual
            .get(key)
            .context("cold185 fleet diagnostic field lacks current native proof")?;
        let same = if key == "ExecStart" {
            crate::pipeline_status::same_exec_start(
                value.as_str().context("cold185 fleet actor command")?,
                genuine.as_str().context("cold185 actual actor command")?,
            )
        } else {
            value == genuine
        };
        ensure!(
            same,
            "cold185 fleet diagnostic changed native actor property {key}"
        );
    }
    match current["stage"].as_str() {
        Some("start-pre" | "running") => ensure!(
            row["live"] == true,
            "cold185 admitted native diagnostic is not live"
        ),
        Some("terminal") => ensure!(
            row["live"] == false,
            "cold185 terminal diagnostic falsely claims live replay"
        ),
        _ => anyhow::bail!("cold185 unknown fleet diagnostic lifecycle"),
    }
    Ok(true)
}

pub(in crate::fleet) fn observer_census(observer: &Value, current: Option<&Value>) -> Result<()> {
    let Some(current) = current else {
        return Ok(());
    };
    let actor = &current["registration_value"]["actor_unit"];
    let diagnostics = observer["diagnostic_replays"]
        .as_array()
        .context("cold185 complete diagnostic census")?;
    let exact = diagnostics
        .iter()
        .filter(|row| row["producer_unit"] == *actor)
        .collect::<Vec<_>>();
    if retained_current_frame(current)? {
        ensure!(
            exact.len() == 1,
            "cold185 retained normal observer omitted or duplicated actor"
        );
        ensure!(
            observer_owned(exact[0], Some(current))?,
            "cold185 expected typed diagnostic missing"
        );
    } else {
        ensure!(
            exact.is_empty(),
            "cold185 initial setup observer already claims the new actor"
        );
    }
    for row in observer["replays"]
        .as_array()
        .context("cold185 complete ordinary replay census")?
    {
        ensure!(
            row["producer_unit"] != *actor && row["controller_unit"] != *actor,
            "cold185 actor also appears as an ordinary replay declaration"
        );
        for role in ["producer", "controller"] {
            for end in ["before", "after"] {
                ensure!(
                    row[format!("{role}_{end}")]["unit"] != *actor,
                    "cold185 actor also appears as an ordinary replay owner"
                );
            }
        }
    }
    Ok(())
}

/// The typed actor peer owns its memory and DATA, so it must not also enter the
/// generic owner table. Preserve its finite replay CPU commitment separately.
pub(super) fn cpu_quota(current: Option<&Value>) -> Result<u64> {
    let Some(current) = current else {
        return Ok(0);
    };
    retained_current_frame(current)?;
    if current["stage"] == "terminal" {
        return Ok(0);
    }
    ensure!(
        matches!(current["stage"].as_str(), Some("start-pre" | "running")),
        "cold185 unknown CPU promise lifecycle"
    );
    let actor = string(&current["registration_value"], "/actor_unit")?;
    let raw = string(&current["native"][actor], "/CPUQuotaPerSecUSec")?;
    let micros = io::unit_micros(raw).context("cold185 actor requires finite replay CPU quota")?;
    ensure!(
        micros == 4_000_000,
        "cold185 actor changed qualified four-core CPU promise"
    );
    Ok(micros)
}

pub(super) fn peer_data(row: &Value) -> Result<bool> {
    crate::fleet::cold185::enrollment::validate_peer(row)?;
    Ok(number(row, "/data_reservation_bytes")? > 0)
}

/// Preserve original sources, actor identity and all debt across the complete
/// builder. Only authenticated completed guard rollover may change comparison
/// views. Each side independently repeats native custody and lifecycle checks;
/// comparison never resets setup clocks or grants fresh launch authority.
pub(super) fn stable(before: Option<&Value>, after: Option<&Value>) -> Result<()> {
    match (before, after) {
        (None, None) => Ok(()),
        (Some(left), Some(right)) => {
            super::cold185_rollover::compare_allocations(left, right)?;
            Ok(())
        }
        _ => anyhow::bail!("cold185 original actor appeared or vanished during reader"),
    }
}

/// Resolve an unused exact original-reader output namespace from the real task,
/// so the prelaunch observer's completed namespace is never reused or replaced.
pub(in crate::fleet) fn reader_output_namespace(
    inputs: &Value,
    root: &Path,
    observer_sha: &str,
) -> Result<PathBuf> {
    let plan_bound: BoundFile = serde_json::from_value(inputs["fleet_plan"].clone())?;
    let plan = io::read(&plan_bound)?;
    let Some(actual) = actual(&plan, now()?)? else {
        return output_path(root, observer_sha, None);
    };
    let fleet_bound: BoundFile = serde_json::from_value(inputs["fleet"].clone())?;
    let fleet = protected_generated(&fleet_bound)?;
    crate::fleet::cold185::enrollment::validate_reader_bridge(&plan, &fleet, &actual, now()?)?;
    let iid = actual["registration_value"]["actor_invocation_id"]
        .as_str()
        .context("cold185 exact reader actor invocation")?;
    output_path(root, observer_sha, Some(iid))
}
fn output_path(root: &Path, observer_sha: &str, actor_iid: Option<&str>) -> Result<PathBuf> {
    ensure!(
        digest(observer_sha, 64),
        "cold185 output observer digest malformed"
    );
    match actor_iid {
        None => Ok(root.join(observer_sha)),
        Some(iid) => {
            ensure!(
                digest(iid, 32),
                "cold185 reader invocation digest malformed"
            );
            Ok(root.join(format!("{observer_sha}-cold185-{iid}")))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderAcceptanceSpec {
    schema: String,
    registration: BoundFile,
    fleet_acceptance: BoundFile,
    original_reader: BoundFile,
    original_reader_completion: BoundFile,
    output: PathBuf,
}
const FOUR_FAMILY_CONTRACT: &str = "/home/sol/.jetstreamer-private/retained161-all-failure-families-source-20261105-v2/FULL_CURRENT_READER_QUALIFICATION_CONTRACT.SOURCE_ONLY.json";
const FOUR_FAMILY_CONTRACT_SHA: &str =
    "82f947c258abce7f2edb1f00d67b4e1c3c04cd8e05c5bfa4d928471a65adf076";

fn four_family_rows(output: &Value, contract: &Value) -> Result<Value> {
    let rows = output["active_peer_allocations"]
        .as_array()
        .context("cold185 original reader peer census")?;
    let required = contract["required_family_rows"]
        .as_array()
        .context("cold185 exact original four families")?;
    ensure!(
        required.len() == 4,
        "cold185 reader changed original family contract count"
    );
    let mut selected = serde_json::Map::new();
    for expected in required {
        let found = rows
            .iter()
            .filter(|row| row["unit"] == expected["unit"])
            .collect::<Vec<_>>();
        ensure!(
            found.len() == 1,
            "cold185 reader omitted or duplicated original family"
        );
        let row = found[0];
        ensure!(
            row["invocation_id"] == expected["original_iid"],
            "cold185 original family invocation crossed"
        );
        for key in [
            "state",
            "memory_max_bytes",
            "data_reservation_bytes",
            "ordinary_replay_claim",
            "new_allocation_authorized",
            "compressed_input_verified",
            "repair_backlog_open",
        ] {
            ensure!(
                row[key] == expected[key],
                "cold185 reader changed original family policy: {key}"
            );
        }
        for (key, value) in expected["branch_required_flags"]
            .as_object()
            .context("cold185 family branch flags")?
        {
            ensure!(
                row[key] == *value,
                "cold185 reader changed original branch flag"
            );
        }
        ensure!(
            row["source_bindings"] == expected["required_source_bindings"],
            "cold185 reader changed original family source census"
        );
        if !expected["required_original_native_journal"].is_null() {
            ensure!(
                row["native_journal"] == expected["required_original_native_journal"],
                "cold185 reader changed original native journal provenance"
            );
        }
        let family = expected["family"]
            .as_u64()
            .context("cold185 original family number")?;
        ensure!(
            [4, 5, 6, 7].contains(&family)
                && selected.insert(family.to_string(), row.clone()).is_none(),
            "cold185 reader duplicate or foreign historical family"
        );
    }
    Ok(Value::Object(selected))
}

/// This command consumes a real completed original production-reader invocation;
/// it never substitutes fixtures, replays a partial test, or writes a success
/// wrapper from a caller-supplied boolean. All four emitted original files and
/// their full original family rows are independently rehashed below.
pub(crate) fn capture_reader_acceptance() -> Result<()> {
    let (spec_binding, self_sha) = crate::fleet::cold185::parsed("prove-cold185-current-reader")?;
    let spec: ReaderAcceptanceSpec = serde_json::from_value(
        crate::fleet::cold185::native::read_json(&spec_binding, 4 << 20)?,
    )?;
    ensure!(
        spec.schema == "horizon-epoch185-complete-current-reader-acceptance-spec-v1",
        "cold185 reader acceptance spec schema"
    );
    let fleet_proof = crate::fleet::cold185::native::read_json(&spec.fleet_acceptance, 4 << 20)?;
    ensure!(
        fleet_proof["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
            && fleet_proof["kind"] == "fleet_enrollment"
            && fleet_proof["registration"] == binding(&spec.registration),
        "cold185 reader has no genuine same-registration fleet acceptance"
    );
    let reader = protected_generated(&spec.original_reader)?;
    ensure!(
        reader["schema"] == "failed4-current-complete-accounting-reader-proof-v1"
            && reader["unit"] == crate::fleet::failed4_current_accounting_reader::UNIT
            && reader["image"]
                == json!({"path":fs::read_link("/proc/self/exe")?,"sha256":self_sha})
            && reader["raw_history_preserved"] == true
            && reader["all_DATA_promises_preserved"] == true,
        "cold185 acceptance needs the exact qualified full production-reader image and output"
    );
    let reader_spec_bound: BoundFile = serde_json::from_value(reader["spec"].clone())?;
    let reader_spec = io::read(&reader_spec_bound)?;
    let inputs = &reader_spec["resource_accounting"];
    let current_plan_bound: BoundFile = serde_json::from_value(inputs["fleet_plan"].clone())?;
    let current_fleet_bound: BoundFile = serde_json::from_value(inputs["fleet"].clone())?;
    let plan = io::read(&current_plan_bound)?;
    let fleet = protected_generated(&current_fleet_bound)?;
    ensure!(
        plan["epoch185_cold_startpre_registration"] == binding(&spec.registration)
            && fleet_proof["actual_fleet"] == binding(&current_fleet_bound)
            && fleet_proof["actual_fleet_plan"] == binding(&current_plan_bound),
        "cold185 current reader is bound to a different native task or full fleet"
    );
    let before = actual(&plan, now()?)?.context("cold185 actual reader owner missing")?;
    let task = crate::fleet::cold185::native::read_json(&spec.registration, 4 << 20)?;
    let original_task_bound: BoundFile = serde_json::from_value(task["task"].clone())?;
    let native_task = crate::fleet::cold185::load(&original_task_bound, now()?)?;
    crate::fleet::cold185::enrollment::validate_reader_bridge(&plan, &fleet, &before, now()?)?;
    let completed = io::read(&spec.original_reader_completion)?;
    ensure!(
        completed["schema"] == "terminal199-parent-memory-original-reader-completion-v1"
            && completed["reader_proof"] == binding(&spec.original_reader)
            && completed["program"] == reader["image"]
            && completed["original_outer_reaped"] == true
            && completed["original_cgroup_empty"] == true
            && completed["original_descriptors_drained"] == true
            && completed["original_native"]["InvocationID"] == reader["invocation_id"]
            && completed["original_native"]["Result"] == "success"
            && completed["original_native"]["ExecMainStatus"] == "0",
        "cold185 reader lacks original successful native completion and drainage"
    );
    let original_journal_bound: BoundFile =
        serde_json::from_value(completed["original_PID1_journal"].clone())?;
    let original_journal = io::read(&original_journal_bound)?;
    ensure!(
        original_journal["unit"] == reader["unit"]
            && original_journal["invocation_id"] == reader["invocation_id"]
            && original_journal["original_rows"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|row| row["_PID"] == "1"
                    && row["INVOCATION_ID"] == reader["invocation_id"]
                    && row["MESSAGE"]
                        .as_str()
                        .is_some_and(|m| m.contains("Deactivated successfully")))),
        "cold185 reader completion has no genuine original PID1 success"
    );
    let contract_bound = BoundFile {
        path: FOUR_FAMILY_CONTRACT.into(),
        sha256: FOUR_FAMILY_CONTRACT_SHA.into(),
    };
    let contract = protected_generated(&contract_bound)?;
    let mut selected_family_rows = None;
    let mut output_bindings = serde_json::Map::new();
    for role in [
        "original_raw_builder_before",
        "original_raw_builder_after",
        "accounting_before",
        "accounting",
    ] {
        let bound: BoundFile = serde_json::from_value(reader[role].clone())?;
        ensure!(
            bound.path.parent() == spec.original_reader.path.parent(),
            "cold185 output escaped original reader transaction directory"
        );
        let output = protected_generated(&bound)?;
        ensure!(
            output["fleet"] == binding(&current_fleet_bound)
                && output["cold185_startpre_native_task_before"] == before
                && output["cold185_startpre_native_task_after"] == before,
            "cold185 full reader outputs lost exact current task or complete fleet binding"
        );
        let families = four_family_rows(&output, &contract)?;
        if let Some(previous) = &selected_family_rows {
            ensure!(
                *previous == families,
                "cold185 original four families changed between full reader outputs"
            );
        } else {
            selected_family_rows = Some(families);
        }
        for row in output["active_peer_allocations"]
            .as_array()
            .context("cold185 complete output peers")?
        {
            for source in row["source_bindings"]
                .as_array()
                .context("cold185 original peer source bindings")?
            {
                let b: BoundFile = serde_json::from_value(source.clone())?;
                if b.path.extension().is_some_and(|e| e == "json") {
                    protected_generated(&b)?;
                }
            }
        }
        output_bindings.insert(role.into(), json!(bound));
    }
    let after =
        actual(&plan, now()?)?.context("cold185 reader owner vanished during proof acceptance")?;
    stable(Some(&before), Some(&after))?;
    let at = now()?;
    ensure!(
        reader["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|t| t <= at && at - t <= 300),
        "cold185 original full reader completion is not fresh"
    );
    let ready = &native_task["ready"];
    let value = json!({"schema":"horizon-epoch185-native-owner-enrollment-v4",
        "kind":"current_reader_native_acceptance","epoch":185,
        "actor_unit":native_task["actor_unit"],"actor_invocation_id":native_task["actor_invocation_id"],
        "ready_pid":ready["pid"],"ready_start_ticks":ready["start_ticks"],
        "admission_sha256":native_task["admission"]["sha256"],"restarts":0,
        "phase":"verification","root_operator_owner":true,"actual_start_pre_evidence_accepted":true,
        "numeric_delivery_eta_millis":fleet_proof["numeric_delivery_eta_millis"],
        "sampled_at":at,"resource_credit_bytes":0,"registration":spec.registration,
        "task":original_task_bound,"fleet_acceptance":spec.fleet_acceptance,
        "actual_fleet":current_fleet_bound,"actual_fleet_plan":current_plan_bound,
        "underlying_accepted_proof":spec.original_reader,"original_reader_completion":spec.original_reader_completion,
        "original_output_bindings":output_bindings,"four_original_families_contract":contract_bound,
        "exact_original_families":[4,5,6,7],"all_four_original_family_rows_rehashed_and_equal":true,
        "actual_native_before":before,"actual_native_after":after,"spec":spec_binding,
        "self_sha256":self_sha,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    crate::fleet::cold185::persist(&spec.output, &value)?;
    println!(
        "{}",
        json!({"reader_acceptance":spec.output,"underlying_original_reader":value["underlying_accepted_proof"],
        "original_four_families_preserved":true,"resource_credit_bytes":0})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn registration() -> Value {
        json!({"path":"/var/lib/jetstreamer/horizon-epoch185-native-startpre-registrations-20261105-v1/fixture/task.json","sha256":"a".repeat(64)})
    }
    // Pure shape tests exercise accounting, not native qualification. Production
    // can reach this shape only after enrollment::current_allocation revalidates
    // the genuine task, actual ControlPID, guard and original source clocks.
    fn aggregate() -> Value {
        let registration = registration();
        let source = json!([registration]);
        let row = json!({"unit":"fixture-actor.service","invocation_id":"b".repeat(32),
            "memory_max_bytes":(128u64<<30)+(256u64<<20),
            "actual_actor_memory_hard_limit_bytes":128u64<<30,
            "reserved_guard_memory_bytes":256u64<<20,"guard_pending":true,
            "data_reservation_bytes":800,"native_pool_suballocation":false,
            "cold185_registration":registration,"source_bindings":source});
        json!({"registration":registration,"candidate_DATA_bytes":800,"guard_pending":true,"stage":"start-pre",
            "guard_floor_bytes":1000,"native":{},"source_bindings":source,"peers":[row]})
    }
    #[test]
    fn full_actor_data_and_reserved_guard_memory_preserve_historical_reservations() {
        let value = aggregate();
        validate_aggregate(&value, &registration()).unwrap();
        let rows = peers(Some(&value)).unwrap();
        assert_eq!(
            rows.iter()
                .map(|v| v["memory_max_bytes"].as_u64().unwrap())
                .sum::<u64>(),
            (128u64 << 30) + (256u64 << 20)
        );
        assert_eq!(guard_floor(Some(&value)).unwrap(), 1000);
        assert!(rows.iter().all(|v| v["native_pool_suballocation"] == false));
    }
    #[test]
    fn running_and_terminal_keep_original_memory_and_data_without_setup_authority() {
        let original = aggregate();
        assert!(!retained_current_frame(&original).unwrap());
        for stage in ["running", "terminal"] {
            let mut current = original.clone();
            current["stage"] = json!(stage);
            current["guard_pending"] = json!(false);
            current["peers"][0]["guard_pending"] = json!(false);
            validate_aggregate(&current, &registration()).unwrap();
            assert!(retained_current_frame(&current).unwrap());
            assert_eq!(
                current["peers"][0]["memory_max_bytes"],
                original["peers"][0]["memory_max_bytes"]
            );
            assert_eq!(
                current["candidate_DATA_bytes"],
                original["candidate_DATA_bytes"]
            );
            current["peers"][0]["reserved_guard_memory_bytes"] = json!(0);
            assert!(validate_aggregate(&current, &registration()).is_err());
        }
        for stage in ["queued", "ready", "retired"] {
            let mut current = original.clone();
            current["stage"] = json!(stage);
            assert!(retained_current_frame(&current).is_err());
            assert!(validate_aggregate(&current, &registration()).is_err());
        }
    }
    #[test]
    fn absent_cold185_selector_adds_no_peer_or_credit() {
        assert!(peers(None).unwrap().is_empty());
        assert_eq!(guard_floor(None).unwrap(), 0);
        stable(None, None).unwrap();
    }
    fn running_observer_fixture() -> (Value, Value) {
        let mut current = aggregate();
        current["stage"] = json!("running");
        current["guard_pending"] = json!(false);
        current["peers"][0]["guard_pending"] = json!(false);
        current["registration_value"] = json!({"actor_unit":"fixture-actor.service",
            "actor_invocation_id":"b".repeat(32),"run_root":"/original/185"});
        current["native"] = json!({"fixture-actor.service":{"MainPID":"123"}});
        let owner = json!({"unit":"fixture-actor.service","invocation_id":"b".repeat(32),
            "restarts":0,"active_state":"active","sub_state":"running","main_pid":123});
        let row = json!({"producer_unit":"fixture-actor.service","expected_producer_invocation_id":"b".repeat(32),
            "range":"185","scratch_path":"/original/185","status":"observed",
            "observation":{"invocation_binding_stable":true,"producer_before":owner,
                "producer_after":owner,"controller_before":owner,"controller_after":owner}});
        (current, row)
    }
    #[test]
    fn exact_retained_observer_skips_duplicate_owner_but_preserves_foreign_rows() {
        let (current, row) = running_observer_fixture();
        assert!(observer_owned(&row, Some(&current)).unwrap());
        assert!(!observer_owned(&row, None).unwrap());
        let mut foreign = row.clone();
        foreign["producer_unit"] = json!("neighbor.service");
        assert!(!observer_owned(&foreign, Some(&current)).unwrap());
        for (pointer, changed) in [
            ("/range", json!("184")),
            ("/scratch_path", json!("/foreign")),
            ("/expected_producer_invocation_id", json!("c".repeat(32))),
            ("/observation/producer_after/main_pid", json!(124)),
            ("/observation/controller_before/restarts", json!(1)),
            ("/observation/invocation_binding_stable", json!(false)),
        ] {
            let mut bad = row.clone();
            *bad.pointer_mut(pointer).unwrap() = changed;
            assert!(observer_owned(&bad, Some(&current)).is_err(), "{pointer}");
        }
    }
    #[test]
    fn fleet_diagnostic_keeps_exact_live_or_terminal_raw_actor_without_duplicate_owner() {
        let (mut current, _) = running_observer_fixture();
        current["native"]["fixture-actor.service"]["Id"] = json!("fixture-actor.service");
        current["native"]["fixture-actor.service"]["MemoryMax"] = json!("137438953472");
        let mut row = json!({"unit":current["native"]["fixture-actor.service"],"live":true});
        assert!(fleet_diagnostic_owned(&row, Some(&current)).unwrap());
        let mut wrong = row.clone();
        wrong["unit"]["MemoryMax"] = json!("0");
        assert!(fleet_diagnostic_owned(&wrong, Some(&current)).is_err());
        let mut foreign = row.clone();
        foreign["unit"]["Id"] = json!("neighbor.service");
        assert!(!fleet_diagnostic_owned(&foreign, Some(&current)).unwrap());
        current["stage"] = json!("terminal");
        current["native"]["fixture-actor.service"]["MainPID"] = json!("0");
        current["native"]["fixture-actor.service"]["InvocationID"] = json!("");
        row["unit"] = current["native"]["fixture-actor.service"].clone();
        assert!(fleet_diagnostic_owned(&row, Some(&current)).is_err());
        row["live"] = json!(false);
        assert!(fleet_diagnostic_owned(&row, Some(&current)).unwrap());
        assert_eq!(row["unit"]["InvocationID"], "");
        assert_eq!(
            current["registration_value"]["actor_invocation_id"],
            "b".repeat(32)
        );
    }
    #[test]
    fn observer_census_rejects_duplicate_omitted_or_cross_classified_typed_actor() {
        let (current, row) = running_observer_fixture();
        let observer = json!({"diagnostic_replays":[row],"replays":[]});
        observer_census(&observer, Some(&current)).unwrap();
        let mut bad = observer.clone();
        bad["diagnostic_replays"] = json!([]);
        assert!(observer_census(&bad, Some(&current)).is_err());
        let mut bad = observer.clone();
        bad["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(observer["diagnostic_replays"][0].clone());
        assert!(observer_census(&bad, Some(&current)).is_err());
        let mut bad = observer.clone();
        bad["replays"] = json!([{"producer_before":{"unit":"fixture-actor.service"}}]);
        assert!(observer_census(&bad, Some(&current)).is_err());
    }
    #[test]
    fn terminal_observer_retains_historical_identity_while_pending_setup_is_rejected() {
        let (mut current, mut row) = running_observer_fixture();
        current["stage"] = json!("terminal");
        current["native"] = json!({});
        row["status"] = json!("unavailable");
        row["observation"] = Value::Null;
        assert!(observer_owned(&row, Some(&current)).unwrap());
        current["stage"] = json!("start-pre");
        current["guard_pending"] = json!(true);
        assert!(observer_owned(&row, Some(&current)).is_err());
    }
    #[test]
    fn typed_actor_cpu_is_charged_once_until_actual_terminal_lifecycle() {
        let mut current = aggregate();
        current["registration_value"] = json!({"actor_unit":"fixture-actor.service"});
        current["native"] = json!({"fixture-actor.service":{"CPUQuotaPerSecUSec":"4s"}});
        assert_eq!(cpu_quota(None).unwrap(), 0);
        assert_eq!(cpu_quota(Some(&current)).unwrap(), 4_000_000);
        current["stage"] = json!("running");
        current["guard_pending"] = json!(false);
        assert_eq!(cpu_quota(Some(&current)).unwrap(), 4_000_000);
        current["native"]["fixture-actor.service"]["CPUQuotaPerSecUSec"] = json!("infinity");
        assert!(cpu_quota(Some(&current)).is_err());
        current["stage"] = json!("terminal");
        assert_eq!(cpu_quota(Some(&current)).unwrap(), 0);
        assert_eq!(current["candidate_DATA_bytes"], 800);
    }
    #[test]
    fn crossed_task_or_missing_source_custody_is_rejected() {
        let mut value = aggregate();
        value["registration"]["sha256"] = json!("d".repeat(64));
        assert!(validate_aggregate(&value, &registration()).is_err());
        let mut value = aggregate();
        value["peers"][0]["source_bindings"] = json!([]);
        assert!(validate_aggregate(&value, &registration()).is_err());
    }
    #[test]
    fn actor_and_guard_cannot_alias_or_hide_charges_in_retained_pool() {
        for (pointer, replacement) in [
            ("/peers/0/reserved_guard_memory_bytes", json!(0)),
            ("/peers/0/actual_actor_memory_hard_limit_bytes", json!(0)),
            ("/peers/0/native_pool_suballocation", json!(true)),
            ("/peers/0/memory_max_bytes", json!(0)),
        ] {
            let mut value = aggregate();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_aggregate(&value, &registration()).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn guard_cannot_duplicate_data_and_actor_cannot_drop_its_reservation() {
        for (pointer, replacement) in [
            ("/guard_pending", json!(false)),
            ("/peers/0/data_reservation_bytes", json!(0)),
            ("/candidate_DATA_bytes", json!(799)),
            ("/guard_floor_bytes", json!(0)),
        ] {
            let mut value = aggregate();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_aggregate(&value, &registration()).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn before_after_rejects_owner_task_or_guard_handoff_without_resetting_clock() {
        let before = aggregate();
        stable(Some(&before), Some(&before)).unwrap();
        for pointer in [
            "/peers/0/invocation_id",
            "/registration/sha256",
            "/guard_floor_bytes",
        ] {
            let mut after = before.clone();
            *after.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(stable(Some(&before), Some(&after)).is_err());
        }
        assert!(stable(Some(&before), None).is_err());
    }
    fn four_family_fixture() -> (Value, Value) {
        let expected = (4..=7).map(|family| json!({"family":family,
            "unit":format!("original-family-{family}.service"),"original_iid":format!("{family:032x}"),
            "state":"retained-failed","memory_max_bytes":68u64<<30,"data_reservation_bytes":800,
            "ordinary_replay_claim":false,"new_allocation_authorized":false,
            "compressed_input_verified":false,"repair_backlog_open":true,
            "branch_required_flags":{"original_scope_preserved":true},
            "required_source_bindings":[],"required_original_native_journal":null})).collect::<Vec<_>>();
        let rows = expected
            .iter()
            .map(|e| {
                let mut row = e.clone();
                row["invocation_id"] = e["original_iid"].clone();
                row["source_bindings"] = e["required_source_bindings"].clone();
                row["original_scope_preserved"] = json!(true);
                row
            })
            .collect::<Vec<_>>();
        (
            json!({"active_peer_allocations":rows}),
            json!({"required_family_rows":expected}),
        )
    }
    #[test]
    fn complete_reader_keeps_each_original_family_alongside_new185_peer() {
        let (mut output, contract) = four_family_fixture();
        let before = four_family_rows(&output, &contract).unwrap();
        output["active_peer_allocations"]
            .as_array_mut()
            .unwrap()
            .push(json!({"unit":"new185.service"}));
        assert_eq!(four_family_rows(&output, &contract).unwrap(), before);
        assert_eq!(before.as_object().unwrap().len(), 4);
    }
    #[test]
    fn full_reader_rejects_missing_duplicate_crossed_or_reclassified_original_family() {
        let (output, contract) = four_family_fixture();
        let mut missing = output.clone();
        missing["active_peer_allocations"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        assert!(four_family_rows(&missing, &contract).is_err());
        let mut duplicate = output.clone();
        duplicate["active_peer_allocations"]
            .as_array_mut()
            .unwrap()
            .push(output["active_peer_allocations"][0].clone());
        assert!(four_family_rows(&duplicate, &contract).is_err());
        for (pointer, replacement) in [
            (
                "/active_peer_allocations/0/invocation_id",
                json!("f".repeat(32)),
            ),
            (
                "/active_peer_allocations/1/repair_backlog_open",
                json!(false),
            ),
            (
                "/active_peer_allocations/2/data_reservation_bytes",
                json!(0),
            ),
            ("/active_peer_allocations/3/memory_max_bytes", json!(0)),
            (
                "/active_peer_allocations/0/original_scope_preserved",
                json!(false),
            ),
        ] {
            let mut crossed = output.clone();
            *crossed.pointer_mut(pointer).unwrap() = replacement;
            assert!(four_family_rows(&crossed, &contract).is_err(), "{pointer}");
        }
    }
    #[test]
    fn exact_reader_output_separates_actual_actor_from_consumed_prelaunch_namespace() {
        let root = Path::new("/var/lib/jetstreamer/reader-root");
        let hash = "a".repeat(64);
        let iid = "b".repeat(32);
        assert_eq!(output_path(root, &hash, None).unwrap(), root.join(&hash));
        assert_eq!(
            output_path(root, &hash, Some(&iid)).unwrap(),
            root.join(format!("{hash}-cold185-{iid}"))
        );
        assert_ne!(
            output_path(root, &hash, Some(&iid)).unwrap(),
            output_path(root, &hash, None).unwrap()
        );
        assert!(output_path(root, &hash, Some("../foreign")).is_err());
        assert!(output_path(root, &"A".repeat(64), Some(&iid)).is_err());
        assert!(output_path(root, &hash, Some(&"c".repeat(31))).is_err());
    }
}
