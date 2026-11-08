//! Evidence interpretation. Every core permission flag is derived here.
use super::*;
#[path = "evidence_current199_growth.rs"]
mod current199_growth;
#[path = "recovered_resource_frame_adapter.rs"]
mod recovered_resource_frame_adapter;

pub(super) fn accepted(s: &Spec, b: &Bundle, time: u64) -> Result<u64> {
    ensure!(
        s.schema == "jetstreamer-epoch186-current-census-admission-spec-v2",
        "epoch 186 admission spec schema differs"
    );
    accepted_basis(
        &accounting::SpecView::from(s),
        &accounting::BundleView::from(b),
        time,
    )
}
pub(super) fn owners(s: &Spec, b: &Bundle) -> Result<Vec<core::Owner>> {
    owners_basis(
        &accounting::SpecView::from(s),
        &accounting::BundleView::from(b),
    )
}
pub(super) fn obligations(
    s: &Spec,
    b: &Bundle,
    floor: u64,
) -> Result<(Vec<core::Obligation>, Vec<core::Disposition>)> {
    obligations_basis(
        &accounting::SpecView::from(s),
        &accounting::BundleView::from(b),
        floor,
    )
}

pub(super) fn accepted_basis(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    time: u64,
) -> Result<u64> {
    let sample = utc_seconds(string(b.observer, "/recorded_at_utc")?)?;
    ensure!(
        b.observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample <= time
            && time - sample <= 1800
            && b.fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && b.fleet["first_epoch"] == 101
            && b.fleet["last_epoch"] == 200
            && b.fleet["observer_receipt"].as_str() == s.observer.path.to_str()
            && b.fleet["observer_sha256"] == s.observer.sha256
            && b.fleet["sampled_at_utc"] == b.observer["recorded_at_utc"]
            && b.fleet["plan"].as_str() == s.fleet_plan.path.to_str()
            && b.fleet["plan_sha256"] == s.fleet_plan.sha256
            && b.fleet_plan["observer"] == binding(s.observer)
            && b.fleet["inventory"]["anomalies"] == 0,
        "epoch 186 basis is stale, incomplete, or binds another sample"
    );
    let epochs = b.fleet["epochs"]
        .as_array()
        .context("complete epoch census")?;
    ensure!(
        epochs.len() == 100
            && (101..=200).all(|e| epochs.iter().filter(|r| r["epoch"] == e).count() == 1),
        "complete 101–200 fleet census missing or duplicated"
    );
    let normal = b.completion["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
        && b.completion["observer"] == binding(s.observer)
        && b.completion["fleet"] == binding(s.fleet)
        && b.completion["fleet_plan"] == binding(s.fleet_plan)
        && b.completion["sampled_at_utc"] == b.observer["recorded_at_utc"]
        && b.parent["schema"] == "jetstreamer-normal-routine-frame-parent-acceptance-v1"
        && b.parent["accepted"] == true
        && b.parent["observer"] == binding(s.observer)
        && b.parent["fleet"] == binding(s.fleet)
        && b.parent["completion"] == binding(s.completion)
        && b.parent["mandatory_cohort191_zero_credit_correction"] == binding(s.correction191)
        && b.parent["new191_closure_incremental_DATA_credit_bytes"] == 0;
    let recovered = recovered_resource_frame_adapter::accepted(s, b, time)?;
    ensure!(
        normal || recovered,
        "accepted complete routine/resource parent lineage differs"
    );
    ensure!(
        s.phase_events.len() == b.events.len(),
        "bound phase event missing"
    );
    for (event, value) in s.phase_events.iter().zip(b.events) {
        ensure!(
            value["schema"] == event.schema,
            "event schema differs from sealed policy"
        );
        let raw = value
            .pointer(&event.clock_pointer)
            .context("event clock missing")?;
        let clock = match raw.as_u64() {
            Some(clock) => clock,
            None => utc_seconds(raw.as_str().context("event clock is not UTC or integer")?)?,
        };
        ensure!(clock <= time, "event is in future");
    }
    assembly154_collected::selected(s, b)?;
    Ok(sample)
}

fn range(row: &Value) -> Result<(u64, u64)> {
    let value = string(row, "/range")?;
    let (first, last) = value.split_once('-').unwrap_or((value, value));
    let (first, last) = (first.parse()?, last.parse()?);
    ensure!(
        (101..=200).contains(&first) && first <= last && last <= 200,
        "foreign owner range"
    );
    Ok((first, last))
}

fn start_in_rss(rss: &Value, pid: u64) -> Result<u64> {
    ensure!(
        rss["census_stable"] == true && rss["error"].is_null(),
        "unstable owner RSS census"
    );
    let rows = rss["processes"]
        .as_array()
        .context("owner RSS process census")?;
    let matching = rows.iter().filter(|r| r["pid"] == pid).collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "main PID absent or duplicated in RSS census"
    );
    let start = number(matching[0], "/start_ticks")?;
    ensure!(start > 0, "zero process start time");
    Ok(start)
}

fn owner(row: &Value, before: &Value, after: &Value, role: core::Role) -> Result<core::Owner> {
    let (first, last) = range(row)?;
    for field in [
        "unit",
        "invocation_id",
        "main_pid",
        "restarts",
        "active_state",
        "sub_state",
        "control_group",
    ] {
        ensure!(
            before[field] == after[field],
            "sample owner identity changed: {field}"
        );
    }
    let pid = number(after, "/main_pid")?;
    let start = start_in_rss(&after["rss"], pid)?;
    ensure!(
        pid > 1
            && start_in_rss(&before["rss"], pid)? == start
            && row["invocation_binding_stable"] == true
            && after["active_state"] == "active"
            && after["sub_state"] == "running"
            && after["restarts"] == 0,
        "owner not identity-stable and running"
    );
    Ok(core::Owner {
        unit: string(after, "/unit")?.into(),
        iid: string(after, "/invocation_id")?.into(),
        pid,
        start_ticks: start,
        role,
        first_epoch: first,
        last_epoch: last,
        restarts: 0,
        identity_stable: true,
        guard_required: true,
        has_memory_accounting: true,
    })
}

fn insert(table: &mut BTreeMap<String, core::Owner>, owner: core::Owner) -> Result<()> {
    if let Some(old) = table.get(&owner.unit) {
        ensure!(
            old == &owner,
            "conflicting roles or identity for repeated epoch owner"
        );
    } else {
        ensure!(
            !table.values().any(|r| r.iid == owner.iid),
            "invocation assigned to two owner units"
        );
        table.insert(owner.unit.clone(), owner);
    }
    Ok(())
}

pub(super) fn owners_basis(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
) -> Result<Vec<core::Owner>> {
    let direct163_owner = super::super::direct163::owned_owner(b.fleet_plan)?;
    let first128_owner = super::super::direct163::first128::owned_owner(b.fleet_plan)?;
    let cold185_owner =
        crate::fleet::cold185::enrollment::current_allocation(b.fleet_plan, now()?)?;
    accounting::cold185::observer_census(b.observer, cold185_owner.as_ref())?;
    let mut table = BTreeMap::new();
    let ordinary = b.observer["replays"]
        .as_array()
        .context("ordinary replay census")?;
    for row in ordinary {
        insert(
            &mut table,
            owner(
                row,
                &row["producer_before"],
                &row["producer_after"],
                core::Role::ReplayProducer,
            )?,
        )?;
        insert(
            &mut table,
            owner(
                row,
                &row["controller_before"],
                &row["controller_after"],
                core::Role::ReplayController,
            )?,
        )?;
    }
    for diagnostic in b.observer["diagnostic_replays"]
        .as_array()
        .context("diagnostic census")?
    {
        if diagnostic["producer_unit"] == super::super::direct163::first128::PARENT128 {
            if let Some(owner) = &first128_owner {
                ensure!(
                    diagnostic["expected_producer_invocation_id"] == owner["iid"],
                    "bounded observer owner crossed"
                );
            } else {
                ensure!(
                    diagnostic["status"] == "unavailable",
                    "bounded observed worker has no live typed owner"
                );
            }
            continue;
        }
        if accounting::cold185::observer_owned(diagnostic, cold185_owner.as_ref())? {
            continue;
        }
        if diagnostic["producer_unit"] == super::super::direct163::UNIT {
            let owner = direct163_owner
                .as_ref()
                .context("direct163 observer has no typed enrollment")?;
            ensure!(
                diagnostic["expected_producer_invocation_id"] == owner["iid"],
                "direct163 observer owner crossed"
            );
            continue;
        }
        if diagnostic["status"] == "observed" {
            let row = &diagnostic["observation"];
            if diagnostic["native_durable_prefix141"] == true {
                let native = &row["native_prefix141_evidence"];
                let iid = native["invocation_id"]
                    .as_str()
                    .context("native141 observed IID")?;
                super::super::durable_prefix141::contract::validate(native, iid, &native["plan"])?;
                let mut current = owner(
                    row,
                    &row["producer_before"],
                    &row["producer_after"],
                    core::Role::Repair,
                )?;
                ensure!(
                    current.unit == super::super::durable_prefix141::UNIT && current.iid == iid,
                    "native141 resource owner differs"
                );
                // Its exact peer authenticates the independent native guard.
                current.guard_required = false;
                insert(&mut table, current)?;
                continue;
            }
            if row["producer_after"]["active_state"] == "active"
                && row["producer_after"]["sub_state"] == "running"
            {
                insert(
                    &mut table,
                    owner(
                        row,
                        &row["producer_before"],
                        &row["producer_after"],
                        core::Role::DiagnosticReplay,
                    )?,
                )?;
            }
        } else {
            let unit = string(diagnostic, "/producer_unit")?;
            if unit == super::super::charge136_retry0003::contract::scope::UNIT {
                let retained = super::super::charge136_retry0003::actual()?
                    .context("retry-0003 terminal retained allocation missing")?;
                super::super::charge136_retry0003::terminal_observer(diagnostic, &retained)?;
                continue;
            }
            if unit == super::super::charge136_retry0005::contract::scope::UNIT {
                let retained = super::super::charge136_retry0005::actual()?
                    .context("retry-0005 terminal retained allocation missing")?;
                super::super::charge136_retry0005::terminal_observer(diagnostic, &retained)?;
                continue;
            }
            if unit == super::super::charge136_retry0004::contract::scope::UNIT {
                let retained = super::super::charge136_retry0004::actual()?
                    .context("retry-0004 terminal retained allocation missing")?;
                super::super::charge136_retry0004::terminal_observer(diagnostic, &retained)?;
                continue;
            }
            if unit == super::super::charge136_retry0002::contract::scope::UNIT {
                let retained = super::super::charge136_retry0002::actual()?
                    .context("retry-0002 terminal retained allocation missing")?;
                super::super::charge136_retry0002::terminal_observer(diagnostic, &retained)?;
                continue;
            }
            if unit == super::super::charge136::contract::scope::UNIT {
                let retained = crate::charge136_lifecycle::retained_allocation()?
                    .context("unavailable 136 diagnostic lacks typed terminal allocation")?;
                super::super::charge136::terminal_observer(diagnostic, &retained)?;
                continue;
            }
            if diagnostic["native_durable_prefix141"] == true {
                super::super::durable_prefix141::terminal_owner(unit)?;
                continue;
            }
            let native = &b.fleet["unit_census"][unit];
            ensure!(
                native["MainPID"] == "0"
                    && (matches!(native["ActiveState"].as_str(), Some("inactive" | "failed"))
                        || (s.allow_retained144_terminal
                            && accounting::retained144_terminal(unit, native)))
                    && native["ControlGroup"] == "",
                "unavailable diagnostic still owns resources"
            );
        }
    }
    for (event, value) in s.phase_events.iter().zip(b.events) {
        for selected in &event.owners {
            if let Some(launch) = &selected.launch {
                ensure!(
                    selected.manager_pointer.is_none() && selected.rss_pointer.is_none(),
                    "ambiguous launch and captured event owner"
                );
                let launch_owner =
                    io::launch_owner(value, selected, launch).with_context(|| {
                        format!(
                            "phase launch owner source: {}",
                            accounting::evidence_path(&event.source.path)
                        )
                    })?;
                insert(&mut table, launch_owner)?;
                continue;
            }
            let native = value
                .pointer(
                    selected
                        .manager_pointer
                        .as_deref()
                        .context("manager pointer missing")?,
                )
                .context("event manager record missing")?;
            let rss = value
                .pointer(
                    selected
                        .rss_pointer
                        .as_deref()
                        .context("RSS pointer missing")?,
                )
                .context("event RSS record missing")?;
            let pid = string(native, "/MainPID")?.parse::<u64>()?;
            ensure!(
                native["ActiveState"] == "active"
                    && native["SubState"] == "running"
                    && native["NRestarts"] == "0",
                "event owner is not running and stable"
            );
            insert(
                &mut table,
                core::Owner {
                    unit: string(native, "/Id")?.into(),
                    iid: string(native, "/InvocationID")?.into(),
                    pid,
                    start_ticks: start_in_rss(rss, pid)?,
                    role: selected.role.clone(),
                    first_epoch: selected.first_epoch,
                    last_epoch: selected.last_epoch,
                    restarts: 0,
                    identity_stable: true,
                    has_memory_accounting: true,
                    guard_required: matches!(
                        selected.role,
                        core::Role::ReplayProducer
                            | core::Role::ReplayController
                            | core::Role::DiagnosticReplay
                    ),
                },
            )?;
        }
    }
    // The latest complete fleet may repeat one producer on multiple epoch rows.
    // Deduplicate only the same exact native unit and IID. Never trust its count.
    if let Some(owner) = first128_owner {
        insert(&mut table, serde_json::from_value(owner)?)?;
    }
    if let Some(owner) = direct163_owner {
        insert(&mut table, serde_json::from_value(owner)?)?;
    }
    accounting::cold185::fleet_active_census(b.fleet, cold185_owner.as_ref())?;
    for row in b.fleet["active"]
        .as_array()
        .context("fleet active census")?
    {
        // This exact native actor is already charged by its authenticated typed
        // allocation. In setup its PID is ControlPID, never a normal MainPID
        // observer owner. No foreign active row bypasses the ordinary census.
        if accounting::cold185::fleet_active_owned(row, cold185_owner.as_ref())? {
            continue;
        }
        for key in ["producer", "controller", "unit"] {
            let Some(native) = row.get(key) else { continue };
            if !native.is_object() {
                continue;
            }
            let name = string(native, "/Id")?;
            let expected = table
                .get(name)
                .context("fleet active owner missing from observer/events")?;
            ensure!(
                native["InvocationID"] == expected.iid
                    && native["MainPID"].as_str() == Some(expected.pid.to_string().as_str())
                    && native["NRestarts"] == "0"
                    && row["epoch"]
                        .as_u64()
                        .is_some_and(
                            |epoch| (expected.first_epoch..=expected.last_epoch).contains(&epoch)
                        ),
                "fleet active native identity/scope differs"
            );
        }
    }
    for row in b.fleet["diagnostics"]
        .as_array()
        .context("fleet diagnostic census")?
    {
        if accounting::cold185::fleet_diagnostic_owned(row, cold185_owner.as_ref())? {
            continue;
        }
        if row["live"] == true {
            let native = &row["unit"];
            let expected = table
                .get(string(native, "/Id")?)
                .context("unaccounted fleet diagnostic")?;
            ensure!(
                native["InvocationID"] == expected.iid,
                "diagnostic IID differs"
            );
        }
    }
    ensure!(!table.is_empty(), "empty complete owner census");
    Ok(table.into_values().collect())
}

pub(super) fn pressure_and_progress(b: &Bundle) -> Result<()> {
    let psi = &b.observer["host_global_pressure"]["cross_sample"];
    let elapsed = number(psi, "/elapsed_millis")?;
    ensure!(
        psi["status"] == "observed" && elapsed >= 1_800_000,
        "pressure history is not comparable"
    );
    for (name, fraction) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            psi["counter_delta_usec"][name]
                .as_u64()
                .zip(elapsed.checked_mul(fraction))
                .is_some_and(|(delta, bound)| delta <= bound),
            "pressure bound exceeded: {name}"
        );
    }
    let mut rows = b.observer["replays"]
        .as_array()
        .context("progress census")?
        .iter()
        .collect::<Vec<_>>();
    rows.extend(
        b.observer["diagnostic_replays"]
            .as_array()
            .context("private progress census")?
            .iter()
            .filter(|r| r["status"] == "observed" && r["native_durable_prefix141"] != true)
            .map(|r| &r["observation"])
            .filter(|r| {
                r["producer_after"]["active_state"] == "active"
                    && r["producer_after"]["sub_state"] == "running"
            }),
    );
    for row in rows {
        ensure!(
            row["useful_work"]["sufficient_for_rates"] == true
                && row["useful_work"]["slots_per_second"]
                    .as_f64()
                    .is_some_and(|v| v.is_finite() && v > 0.)
                && row["worker_after"]["matching_workers"] == 1
                && row["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|v| v > 0 && v < 3_500_000),
            "live replay lacks progress or its qualified VMA/worker envelope"
        );
        for counter in [
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
            "memory_events.max",
        ] {
            ensure!(
                row["cross_sample"]["producer_cgroup_counter_delta"][counter] == 0,
                "live producer memory event: {counter}"
            );
        }
    }
    Ok(())
}

pub(super) fn obligations_basis(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    floor: u64,
) -> Result<(Vec<core::Obligation>, Vec<core::Disposition>)> {
    ensure!(
        s.reader191.sha256 == READER_SHA
            && s.transfer191.sha256 == TRANSFER_SHA
            && s.correction191.sha256 == CORRECTION_SHA
            && s.closed185.sha256 == CLOSED185_SHA,
        "unreviewed historical closure or accounting correction"
    );
    ensure!(
        b.reader["schema"] == "jetstreamer-original191-growth-reservation-view-v2"
            && b.reader["transfer"] == binding(s.transfer191)
            && b.reader["physical_free_space_credit_bytes"] == 0
            && b.transfer["schema"] == "jetstreamer-original191-growth-transfer-v2"
            && b.transfer["new_original191_replay_future_growth_bytes"] == 0
            && b.transfer["physical_free_space_credit_bytes"] == 0
            && b.closed185["schema"] == "jetstreamer-horizon-old185-attempt-growth-closed-v2"
            && b.closed185["physical_space_credit_bytes"] == 0
            && b.closed185["old_attempt_fenced"] == true
            && b.correction["schema"]
                == "jetstreamer-horizon-cohort191-closure-accounting-correction-v1"
            && b.correction["authoritative_prior_transfer"] == binding(s.transfer191)
            && b.correction["new_closure_incremental_DATA_release_bytes"] == 0
            && b.correction["new_closure_physical_credit_bytes"] == 0
            && b.correction["DATA_floor_bytes_unchanged"] == DATA_FLOOR,
        "historical dispositions grant no extra physical or DATA credit"
    );
    let mut rows: Vec<core::Obligation> =
        serde_json::from_value(b.reader["projected_reservation_rows"].clone())?;
    let original = rows.clone();
    // Preserve the historical standing frontier; current 199 is an independent addition.
    if let Some(context) = crate::fleet::ordinary199::terminal_context(b.fleet_plan)? {
        current199_growth::append_retained(s, b, &mut rows, &context)?;
    } else {
        current199_growth::append(s, b, &mut rows)?;
    }
    if let Some(growth) = super::super::recovery199::accounting::growth(b.fleet_plan)? {
        let row: core::Obligation = serde_json::from_value(growth)?;
        ensure!(
            !rows.iter().any(|r| r.claim_key == row.claim_key),
            "recovery199 new growth already present; refusing duplicate charge"
        );
        rows.push(row);
    }
    for live in b.observer["replays"]
        .as_array()
        .context("live growth owner census")?
    {
        let (first, _) = range(live)?;
        let iid = string(live, "/producer_after/invocation_id")?;
        let matching = rows
            .iter()
            .filter(|r| r.epoch == first && r.producer_invocation_id == iid)
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "current producer lacks same-invocation retained growth obligation"
        );
        let observed = number(live, "/scratch_pass_1/physical_bytes")?
            .max(number(live, "/scratch_pass_2/physical_bytes")?);
        ensure!(
            observed <= matching[0].outstanding_bytes,
            "current producer exceeds its retained historical growth envelope"
        );
    }
    for (epoch, iid, minimum) in [
        (141, "e639f007d482464f8a251455659d2ede", 512 * core::GIB),
        (152, "1a7e8cde872b45f786979150d5639ab4", 768 * core::GIB),
        (155, "518ff0bf0bbb4413a155a63f95907163", 768 * core::GIB),
        (183, "489e219d38d14d4594d8649ff698f666", 768 * core::GIB),
    ] {
        ensure!(
            rows.iter()
                .filter(|r| r.epoch == epoch
                    && r.producer_invocation_id == iid
                    && r.outstanding_bytes >= minimum)
                .count()
                == 1,
            "missing retained historical obligation for epoch {epoch}"
        );
    }
    ensure!(
        rows.iter()
            .filter(|r| r.epoch == 185
                && r.producer_invocation_id == "0de9498a3c2f4c6dbd7350d052fc7e02"
                && r.outstanding_bytes == 0)
            .count()
            == 1,
        "old epoch 185 closure is already zero and must stay zero"
    );
    // Replace only the proven floor row with a larger current authenticated floor.
    let century = rows
        .iter_mut()
        .find(|r| r.claim_key == "floor/century-home-sol")
        .context("floor row missing")?;
    century.outstanding_bytes = century.outstanding_bytes.max(floor);
    let retained = &b.standing["retained_promises"];
    ensure!(
        b.standing["schema"] == "jetstreamer-queue193-data-standing-admission-v2"
            && b.standing["accepted_prepared_generation_and_standing_claim"] == true
            && retained["allocation_or_consumption_credit_bytes"] == 0
            && retained["all_historical_images_and_failed_evidence_retained"] == true
            && number(retained, "/initial_total_bytes")? >= DATA_FLOOR,
        "standing DATA promise frontier missing or understated"
    );
    // Retain every promise from the accepted standing ledger, including earmark,
    // compiler/bootstrap and margins. It is an independent maximum, not free space.
    let row_sum = original.iter().try_fold(0u64, |n, r| {
        n.checked_add(r.outstanding_bytes)
            .context("row sum overflow")
    })?;
    let standing = number(retained, "/initial_total_bytes")?;
    if standing > row_sum {
        rows.push(core::Obligation {
            claim_key: "standing/additional-retained-promises".into(),
            epoch: 0,
            producer_invocation_id: String::new(),
            outstanding_bytes: standing - row_sum,
        });
    }
    let disposition = core::Disposition {
        claim_key: "epoch191/ea93199ed2fa470d99de248c2a10b246".into(),
        producer_invocation_id: "ea93199ed2fa470d99de248c2a10b246".into(),
        original_bytes: 768 * core::GIB,
        remaining_bytes: 0,
        closure: core::Proof {
            path: s.transfer191.path.to_string_lossy().into_owned(),
            sha256: s.transfer191.sha256.clone(),
        },
        reader_view: core::Proof {
            path: s.reader191.path.to_string_lossy().into_owned(),
            sha256: s.reader191.sha256.clone(),
        },
        verified_by_wrapper: true,
        physical_credit_bytes: 0,
    };
    core::project_obligations(&rows, std::slice::from_ref(&disposition))?;
    Ok((rows, vec![disposition]))
}

pub(super) fn candidate(s: &Spec, b: &Bundle) -> Result<core::Candidate> {
    let q = &b.qualification;
    ensure!(
        q.schema == "jetstreamer-epoch186-current-worker-qualification-acceptance-v2"
            && q.worker_sha256 == WORKER
            && q.node_sha256 == NODE
            && q.snapshot_sha256 == SNAPSHOT
            && q.candidate_plan == s.candidate_plan
            && q.input_capability == s.input_capability
            && digest(&q.ledger_fingerprint_sha256, 64),
        "missing exact current-worker qualification acceptance"
    );
    let unit = string(&b.plan, "/unit")?;
    ensure!(
        b.plan["schema"] == "jetstreamer-private-epoch186-current-census-resource-plan-v2"
            && b.plan["epoch"] == 186
            && b.plan["worker_sha256"] == WORKER
            && b.plan["node_sha256"] == NODE
            && b.plan["snapshot_sha256"] == SNAPSHOT
            && b.plan["ledger_fingerprint_sha256"] == q.ledger_fingerprint_sha256
            && b.plan["guard_binary"] == binding(&q.guard_binary)
            && serde_json::from_value::<Limits>(b.plan["resource_limits"].clone())?
                == q.resource_limits,
        "candidate resource/input fingerprint differs from exact qualification"
    );
    ensure!(
        b.input["schema"] == "jetstreamer-private-epoch186-capped-input-capability-v2"
            && b.input["worker_sha256"] == WORKER
            && b.input["node_sha256"] == NODE
            && b.input["snapshot_sha256"] == SNAPSHOT
            && b.input["worker_feature"] == "capped-shrink-candidate"
            && b.input["bootstrap_slot"] == 80_351_283
            && b.input["terminal_root_slot"] == 80_783_539
            && b.input["all_immutable_inputs_rehashed"] == true
            && b.input["worker_spawned"] == false
            && b.input["snapshot_restored"] == false,
        "storage capability does not bind exact capped inputs"
    );
    // A storage-only receipt is deliberately insufficient. The separate runtime
    // receipt must contain real process/snapshot/fingerprint observations.
    ensure!(
        b.runtime["schema"] == "jetstreamer-epoch186-current-worker-runtime-capability-v2"
            && b.runtime["worker_sha256"] == WORKER
            && b.runtime["node_sha256"] == NODE
            && b.runtime["snapshot_sha256"] == SNAPSHOT
            && b.runtime["ledger_fingerprint_sha256"] == q.ledger_fingerprint_sha256
            && b.runtime["invocation_id"] == q.qualification_invocation_id
            && number(&b.runtime, "/worker_process/pid")? > 1
            && number(&b.runtime, "/worker_process/start_ticks")? > 0
            && number(&b.runtime, "/snapshot_restored_slot")? == 80_351_283
            && number(&b.runtime, "/observed_replayed_slot")? > 80_351_283
            && b.runtime["checkpoint_accounts_hash"]
                == "Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8",
        "actual current-worker runtime/input capability missing; storage-only is insufficient"
    );
    ensure!(
        b.resource["schema"] == "jetstreamer-epoch186-bounded-resource-capability-v2"
            && b.resource["worker_sha256"] == WORKER
            && b.resource["invocation_id"] == q.qualification_invocation_id
            && b.resource["runtime"] == binding(&q.runtime)
            && serde_json::from_value::<Limits>(b.resource["resource_limits"].clone())?
                == q.resource_limits
            && number(&b.resource, "/measured_stop_physical_bytes")?
                >= q.resource_limits.whole_root_stop_bytes
            && number(&b.resource, "/measured_stop_overshoot_bytes")?
                <= q.resource_limits.overshoot_bytes
            && b.resource["native_stop"]["MainPID"] == "0"
            && b.resource["native_stop"]["InvocationID"] == q.qualification_invocation_id
            && b.resource["native_stop"]["NRestarts"] == "0",
        "exact native stop/overshoot/resource capability missing"
    );
    ensure!(
        b.first_guard["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && b.first_guard["guard_sha256"] == q.guard_binary.sha256
            && b.first_guard["plan_sha256"] == q.guard_plan.sha256
            && b.first_guard["producer_invocation_id"] == q.qualification_invocation_id
            && b.first_guard["trip_reason"].is_null()
            && b.first_guard["worker_observation_error"].is_null()
            && b.first_guard["maximum_worker_vmas"] == q.resource_limits.maximum_vmas
            && b.first_guard["workers"]
                .as_array()
                .is_some_and(|workers| workers.len() == 1
                    && workers[0][0].as_u64().is_some_and(|pid| pid > 1)
                    && workers[0][1]
                        .as_u64()
                        .is_some_and(|vmas| vmas > 0 && vmas <= q.resource_limits.maximum_vmas))
            && b.candidate_guard_plan["unit"] == q.qualification_unit
            && b.candidate_guard_plan["invocation_id"] == q.qualification_invocation_id
            && b.candidate_guard_plan["maximum_root_physical_bytes"]
                == q.resource_limits.whole_root_stop_bytes,
        "actual exact guard first-fire capability missing"
    );
    for value in [&b.plan, &b.runtime, &b.resource] {
        for key in [
            "full_cold_epoch_peak_qualified",
            "ordinary_replay_claim",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(
                value[key] == false,
                "private qualification contains unsupported authority: {key}"
            );
        }
    }
    let l = &q.resource_limits;
    Ok(core::Candidate {
        epoch: 186,
        unit: unit.into(),
        memory_max_bytes: l.memory_max_bytes,
        whole_root_stop_bytes: l.whole_root_stop_bytes,
        overshoot_bytes: l.overshoot_bytes,
        parent_bytes: l.parent_bytes,
        native_runtime_seconds: l.native_runtime_seconds,
        tasks_max: l.tasks_max,
        maximum_vmas: l.maximum_vmas,
        cpu_quota_micros: l.cpu_quota_micros,
        bounded_resource_profile_qualified: true,
        runtime_and_inputs_qualified: true,
        exact_new_guard_and_first_fire_capability_qualified: true,
        snapshot_and_ledger_fingerprint_match: true,
        canonical_publication_requested: false,
        full_cold_peak_claimed: false,
    })
}

#[cfg(test)]
pub(in crate::fleet) fn complete_early141_entry_regression(
    frame: &BoundFile,
    plan: &BoundFile,
    native: &std::collections::BTreeMap<String, Value>,
) -> Result<Value> {
    recovered_resource_frame_adapter::complete_early141_entry_regression(frame, plan, native)
}
