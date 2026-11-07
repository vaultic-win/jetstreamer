//! Independent, explicit original 199 parent-only memory selection.
//! Raw193 GiB, terminal context v2, controller/guard1 GiB and DATA768 GiB are preserved.
//! No source, fixture, selector success or low RSS is replay admission.
#![deny(warnings)]
pub mod admission_bridge;
pub mod cached145;
pub mod census_capture;
mod context_inputs;
mod current_binding;
use context_inputs::ContextInputs;
mod directory_anchor;
mod fsutil;
pub mod model;
mod process_references;
mod validate;
use anyhow::{Context, Result, ensure};
use fsutil as f;
use horizon_recovered_resource_frame_retained199_v2::ordinary199;
use jetstreamer_typed_memory::VerifiedPeerMemory;
use model::*;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};
/// Private fields prevent a JSON object or arithmetic-only caller from creating authority.
#[derive(Debug)]
pub struct VerifiedParentMemory {
    raw_total_bytes: u64,
    effective_total_bytes: u64,
    raw_peer_bytes: u64,
    effective_peer_bytes: u64,
    parent_selection_applied: bool,
    evidence: Value,
}
impl VerifiedParentMemory {
    pub fn raw_total_bytes(&self) -> u64 {
        self.raw_total_bytes
    }
    pub fn effective_total_bytes(&self) -> u64 {
        self.effective_total_bytes
    }
    pub fn raw_peer_bytes(&self) -> u64 {
        self.raw_peer_bytes
    }
    pub fn effective_peer_bytes(&self) -> u64 {
        self.effective_peer_bytes
    }
    pub fn selected_parent_retirement_bytes(&self) -> u64 {
        if self.parent_selection_applied {
            PARENT
        } else {
            0
        }
    }
    pub fn evidence(&self) -> &Value {
        &self.evidence
    }
    /// Present only when the full constructor authenticated the explicit
    /// current-plan witness context. Absence preserves legacy evidence bytes.
    pub fn input_verification_context(&self) -> Option<&Value> {
        self.evidence.get("input_verification_context")
    }
    /// Independent from the original199 selection; raw145 lineage remains intact.
    pub fn selected_cached145_parent_retirement_bytes(&self) -> u64 {
        if self.evidence["completed_cached145_parent_retirement_bytes"] == PARENT {
            PARENT
        } else {
            0
        }
    }
}
fn qualified(a: &Artifact, scope: &str) -> Result<()> {
    let q = f::immutable(
        a.qualification
            .as_ref()
            .context("actual artifact qualification is required")?,
    )?;
    ensure!(
        q["schema"] == "terminal199-parent-memory-qualified-artifact-v1"
            && q["scope"] == scope
            && q["program"] == json!(a.program)
            && q["prod_clippy_passed"] == true
            && q["test_clippy_passed"] == true
            && q["all_required_tests_passed"] == true
            && q["actual_native_capability_passed"] == true
            && q["replay_launch_authorized"] == false
            && q["memory_credit_bytes"] == 0
            && q["DATA_credit_bytes"] == 0,
        "unqualified exact parent-memory reader/census artifact"
    );
    f::immutable(&f::bound(&q["source_and_dependency_freeze"])?)?;
    let native = f::immutable(&f::bound(&q["actual_native_capability"])?)?;
    ensure!(
        native["program"] == json!(a.program)
            && native["scope"] == scope
            && native["actual_native_capability_passed"] == true
            && native["memory_credit_bytes"] == 0
            && native["DATA_credit_bytes"] == 0,
        "qualified artifact native capability crossed"
    );
    let seal = f::immutable(&f::bound(&q["deployment_seal"])?)?;
    sealed_member(&seal, &a.program, "0555")?;
    let raw = f::bytes(&a.program, 128 << 20, true)?;
    ensure!(raw.starts_with(b"\x7fELF"), "qualified program is not ELF");
    Ok(())
}
fn sealed_member(seal: &Value, b: &Bound, mode: &str) -> Result<()> {
    let root = Path::new(
        seal["destination"]
            .as_str()
            .context("normal seal destination")?,
    );
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["replay_launch_authorized"] == false
            && seal["publication_authorized"] == false
            && seal["remote_mutations"] == false
            && seal["r2_mutations"] == false
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(
                    |r| r["name"].as_str().is_some_and(|n| root.join(n) == b.path)
                        && r["sha256"] == b.sha256
                        && r["mode"] == mode
                )
                .count()
                == 1),
        "exact normal seal member absent/duplicated/crossed"
    );
    Ok(())
}
fn registration(r: &Request) -> Result<Policy> {
    let parent = r
        .registration
        .path
        .parent()
        .context("registration parent")?;
    ensure!(
        parent.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-original199-parent-memory-registration-"))
            && r.registration
                .path
                .file_name()
                .is_some_and(|n| n == "registration.json"),
        "parent selector registration namespace differs"
    );
    let seal = f::immutable(&r.registration_seal)?;
    sealed_member(&seal, &r.registration, "0444")?;
    let p: Policy = serde_json::from_value(f::immutable(&r.registration)?)?;
    validate::policy(&p)?;
    qualified(&p.census, "terminal199-parent-only-memory-census")?;
    f::bytes(&p.controller_source, 1 << 20, true)?;
    f::bytes(&p.guard_source, 1 << 20, true)?;
    f::bytes(&p.controller_executable, 128 << 20, false)?;
    let review = f::immutable(&p.census_scope_review)?;
    ensure!(
        review["schema"] == "terminal199-parent-memory-exhaustive-scope-review-v1"
            && review["census_program"] == json!(p.census.program)
            && review["native_units"] == json!(p.native_units)
            && review["controller_source"] == json!(p.controller_source)
            && review["guard_source"] == json!(p.guard_source)
            && review["all_actual_original199_launcher_paths_classified"] == true
            && review["omitted_launcher_paths"]
                .as_array()
                .is_some_and(Vec::is_empty)
            && review["required_process_dimensions"]
                == json!([
                    "argv",
                    "cwd",
                    "descriptors",
                    "executable",
                    "mappings",
                    "source"
                ]),
        "exhaustive native/source/process scope not independently registered"
    );
    Ok(p)
}
fn current_equal(a: &Value, t: &Current) -> bool {
    current_binding::matches(a, t)
}

fn original_completion(
    b: &Bound,
    proof: &Bound,
    program: &Bound,
    unit: &str,
    iid: &str,
) -> Result<()> {
    let a = f::immutable(b)?;
    ensure!(
        a["schema"] == "terminal199-parent-memory-original-reader-completion-v1"
            && a["reader_proof"] == json!(proof)
            && a["program"] == json!(program)
            && a["original_outer_reaped"] == true
            && a["original_cgroup_empty"] == true
            && a["original_descriptors_drained"] == true,
        "original reader completion/drain proof absent"
    );
    let n = &a["original_native"];
    ensure!(
        n["Id"] == unit
            && n["InvocationID"] == iid
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["NRestarts"] == "0"
            && n["ExecMainStatus"] == "0"
            && n["Result"] == "success"
            && n["Job"] == ""
            && ((n["ActiveState"] == "active" && n["SubState"] == "exited")
                || (n["ActiveState"] == "inactive" && n["SubState"] == "dead")),
        "original reader did not succeed and drain"
    );
    let journal = f::immutable(&f::bound(&a["original_PID1_journal"])?)?;
    let drain = f::immutable(&f::bound(&a["original_drain"])?)?;
    ensure!(
        journal["unit"] == unit
            && journal["invocation_id"] == iid
            && journal["result"] == "success"
            && journal["exec_main_status"] == 0
            && drain["unit"] == unit
            && drain["invocation_id"] == iid
            && drain["outer_reaped"] == true
            && drain["cgroup_empty"] == true
            && drain["descriptors_drained"] == true,
        "original native journal/drain bindings crossed or incomplete"
    );
    Ok(())
}
fn reader(
    current: &Current,
    reader_binding: &Bound,
    program: &Artifact,
    acceptance: &Bound,
    now: u64,
) -> Result<(Value, Value, Value, Value)> {
    qualified(program, "terminal199-parent-memory-current-reader")?;
    let p = f::immutable(reader_binding)?;
    ensure!(
        p["schema"] == "failed4-current-complete-accounting-reader-proof-v1"
            && p["unit"] == "horizon-failed4-current-accounting-reader-20261104-v1.service"
            && p["image"] == json!(program.program)
            && p["raw_history_preserved"] == true
            && p["all_DATA_promises_preserved"] == true
            && p["captured141_existing_selection_only"] == true
            && p["failed4_memory_selection_enabled"] == false
            && p["memory_budget_credit_applied_bytes"] == 0
            && p["DATA_credit_bytes"] == 0
            && p["physical_credit_bytes"] == 0
            && p["admission_authorized"] == false
            && p["replay_launch_authorized"] == false
            && p["archive_mutations"] == false
            && p["sidecar_mutations"] == false
            && p["r2_mutations"] == false
            && p["new_resource_observations"] == 0,
        "fresh full original accounting reader proof differs"
    );
    f::fresh(f::n(&p, "recorded_unix_seconds")?, now, 300)?;
    let spec = f::immutable(&f::bound(&p["spec"])?)?;
    ensure!(
        spec["schema"] == "failed4-current-complete-accounting-reader-spec-v1"
            && current_equal(&spec["resource_accounting"], current)
            && spec["captured141_memory_retirement"]["current"] == json!(current),
        "original reader current tuple crossed"
    );
    original_completion(
        acceptance,
        reader_binding,
        &program.program,
        p["unit"].as_str().context("reader unit")?,
        p["invocation_id"].as_str().context("reader IID")?,
    )?;
    for key in [
        "external_booking",
        "retention_plan",
        "original_raw_builder_before",
        "original_raw_builder_after",
    ] {
        f::json(&f::bound(&p[key])?)?;
    }
    let before = f::immutable(&f::bound(&p["accounting_before"])?)?;
    let after = f::immutable(&f::bound(&p["accounting"])?)?;
    ensure!(
        current_equal(&before, current) && current_equal(&after, current),
        "complete before/after accounting tuple crossed"
    );
    Ok((p, spec, before, after))
}
fn terminal(
    p: &Policy,
    current: &Current,
    before: &Value,
    after: &Value,
    inputs: &ContextInputs,
) -> Result<()> {
    let c = &inputs.retained;
    let proof = ordinary199::load_for_context(&json!(c.original_enrollment()), c)?
        .context("original199 exact enrollment missing")?;
    let observer = f::json(&current.observer)?;
    let frame = f::json(&current.frame)?;
    proof.validate_observer_retained(&observer, c)?;
    c.validate_current_observer(&observer)?;
    ensure!(
        frame["bindings"]["observer"] == json!(current.observer)
            && frame["epoch199_terminal_context"] == json!(inputs.binding)
            && frame["epoch199_enrollment"] == json!(c.original_enrollment())
            && frame["epoch199_promises"] == proof.accounting(),
        "actual current retained Frame/enrollment/promises crossed"
    );
    for end in ["before", "after"] {
        let n = &frame[format!("native_census_{end}")];
        c.validate_current_membership(n)?;
        proof.validate_native_retained(n, c)?;
    }
    let rb = validate::terminal_raw_row(before)?;
    let ra = validate::terminal_raw_row(after)?;
    ensure!(
        rb == ra,
        "raw193GiB/768GiB peer changed across complete builders"
    );
    for a in [before, after] {
        ensure!(
            a["original199_terminal_context"] == json!(inputs.binding)
                && a["epoch199_promises"] == proof.accounting(),
            "raw retained199 original promises/context crossed"
        );
    }
    validate::failed_state(&inputs.state(&p.quarantined_state)?)?;
    c.revalidate_inputs()
}
fn census(p: &Policy, r: &Request, now: u64, inputs: &ContextInputs) -> Result<Census> {
    let scope = Path::new("/var/lib/jetstreamer/horizon-original199-parent-memory-census-v1")
        .join(&r.current.observer.sha256);
    ensure!(
        r.census
            .path
            .file_name()
            .is_some_and(|n| n == "census.json")
            && r.census.path.parent().and_then(Path::parent) == Some(scope.as_path()),
        "qualified census namespace crossed"
    );
    let c: Census = serde_json::from_value(f::immutable(&r.census)?)?;
    f::fresh(c.recorded_unix_seconds, now, 300)?;
    ensure!(
        c.schema == "terminal199-parent-memory-complete-current-census-v1"
            && c.current == r.current
            && c.program == p.census.program
            && c.scope_review == p.census_scope_review
            && c.controller_source == p.controller_source
            && c.guard_source == p.guard_source
            && c.source_custody_unchanged
            && c.mutation_count == 0
            && c.complete_native_unit_universe == p.native_units,
        "current qualified complete census scope/source/tuple differs"
    );
    let roots = c
        .complete_source_roots
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        roots
            == BTreeSet::from([
                "/usr/local/lib/jetstreamer/horizon-epoch199-backfill-controller-guard-20261102-v1"
                    .into()
            ])
            && roots.len() == c.complete_source_roots.len(),
        "future source root census incomplete"
    );
    ensure!(
        census_capture::source_listing_stable(
            &f::immutable(&c.source_listing_before)?,
            &f::immutable(&c.source_listing_after)?
        )?,
        "actual original launcher/source universe changed"
    );
    validate::endpoint(p, &c.before)?;
    validate::endpoint(p, &c.after)?;
    ensure!(
        census_capture::normalize_native_pair(
            &json!(c.before.native),
            &json!(c.after.native),
            inputs
        )? == json!(c.before.native)
            && c.before.controller_state == c.after.controller_state,
        "native controller/source custody changed during parent closure"
    );
    for e in [&c.before, &c.after] {
        for l in &e.launcher_findings {
            let q = f::immutable(&l.qualification)?;
            ensure!(
                q["schema"] == "terminal199-parent-memory-launcher-no-retry-custody-v1"
                    && q["unit"] == l.unit
                    && q["source"] == json!(l.source)
                    && q["disposition"] == l.disposition
                    && q["may_start_original_parent"] == false
                    && q["census_program"] == json!(p.census.program),
                "actual future launcher/source custody not qualified"
            );
        }
    }
    Ok(c)
}
fn baseline(
    r: &Request,
    reader: &Value,
    before: &Value,
    after: &Value,
    now: u64,
) -> Result<(VerifiedPeerMemory, Value)> {
    let captured_before = f::immutable(&f::bound(&reader["captured141_selection_before"])?)?;
    let captured_after = f::immutable(&f::bound(&reader["captured141_selection"])?)?;
    let b = jetstreamer_typed_memory::revalidate_captured_selection(&captured_before, before, now)?;
    let a = jetstreamer_typed_memory::revalidate_captured_selection(&captured_after, after, now)?;
    ensure!(
        a.raw_total_bytes() == f::n(reader, "raw_total_memory_promises_bytes")?
            && a.raw_total_bytes() == b.raw_total_bytes()
            && a.effective_total_bytes() == b.effective_total_bytes()
            && a.raw_peer_bytes() == b.raw_peer_bytes()
            && a.effective_peer_bytes() == b.effective_peer_bytes(),
        "complete current141 baseline changed between complete reader passes"
    );
    match &r.baseline {
        Baseline::Captured141Only { captured141 } => {
            ensure!(
                *captured141 == f::bound(&reader["captured141_selection"])?,
                "captured141 baseline belongs to other accounting"
            );
            Ok((a, captured_after))
        }
        Baseline::Captured141AndFailed4 {
            captured141,
            combined,
            combined_command_proof,
            combined_command_acceptance,
            combined_program,
        } => {
            qualified(
                combined_program,
                "terminal199-parent-memory-combined-current-reader",
            )?;
            let p = f::immutable(combined_command_proof)?;
            ensure!(
                p["schema"] == "failed4-current-combined-memory-selection-proof-v1"
                    && p["current"] == json!(r.current)
                    && p["current_reader"] == json!(r.current_reader)
                    && p["image"] == json!(combined_program.program)
                    && p["accounting"] == reader["accounting"]
                    && p["combined_selection"] == json!(combined)
                    && p["captured141_selection"] == json!(captured141)
                    && p["failed4_reduction_bytes"] == 68 * GIB
                    && p["raw_history_preserved"] == true
                    && p["DATA_credit_bytes"] == 0
                    && p["physical_credit_bytes"] == 0,
                "combined source/fixture/other tuple cannot replace original current baseline"
            );
            f::fresh(f::n(&p, "recorded_unix_seconds")?, now, 300)?;
            original_completion(
                combined_command_acceptance,
                combined_command_proof,
                &combined_program.program,
                p["unit"].as_str().context("combined unit")?,
                p["invocation_id"].as_str().context("combined IID")?,
            )?;
            let ce = f::immutable(captured141)?;
            let co = f::immutable(combined)?;
            let v = jetstreamer_typed_memory::failed4::revalidate(&co, after, now, &ce)?;
            ensure!(
                v.raw_total_bytes() == a.raw_total_bytes()
                    && v.raw_peer_bytes() == a.raw_peer_bytes()
                    && a.effective_total_bytes().checked_sub(68 * GIB)
                        == Some(v.effective_total_bytes())
                    && a.effective_peer_bytes().checked_sub(68 * GIB)
                        == Some(v.effective_peer_bytes()),
                "failed4 combined deduction repeated/missing/crossed"
            );
            Ok((v, co))
        }
    }
}
/// Point-of-use reader. This is deliberately separate from the retained-v2 raw builder.
/// It requires fresh genuine original full-reader and independent complete-census evidence.
pub fn select(request: &Request, now: u64) -> Result<VerifiedParentMemory> {
    ensure!(
        request.schema == "terminal199-parent-only-memory-selection-request-v1" && now > 0,
        "explicit parent-only request required"
    );
    let p = registration(request)?;
    let (reader, _, before, after) = reader(
        &request.current,
        &request.current_reader,
        &request.reader_program,
        &request.current_reader_acceptance,
        now,
    )?;
    let inputs = ContextInputs::for_current(&p, &request.current)?;
    terminal(&p, &request.current, &before, &after, &inputs)?;
    let c = census(&p, request, now, &inputs)?;
    census_capture::recheck(&p, &after, &inputs)?;
    let (base, baseline_evidence) = baseline(request, &reader, &before, &after, now)?;
    let (effective_total, effective_peer) = validate::compose(
        base.raw_total_bytes(),
        base.effective_total_bytes(),
        base.raw_peer_bytes(),
        base.effective_peer_bytes(),
    )?;
    // Revalidate the selected sealed copy or unchanged legacy state route after every consumer.
    validate::failed_state(&inputs.state(&p.quarantined_state)?)?;
    let mut evidence = json!({"schema":"terminal199-parent-only-effective-memory-selection-v1","request":request,
        "recorded_unix_seconds":now,"raw_total_memory_promises_bytes":base.raw_total_bytes(),"baseline_effective_total_bytes":base.effective_total_bytes(),
        "effective_total_memory_promises_bytes":effective_total,"raw_peer_memory_bytes":base.raw_peer_bytes(),
        "baseline_effective_peer_bytes":base.effective_peer_bytes(),"effective_peer_memory_bytes":effective_peer,
        "baseline_evidence":baseline_evidence,"raw_accounting_serde_json_sha256":f::sha(&serde_json::to_vec(&after)?),
        "raw_original199_memory_bytes":RAW_MEMORY,"original199_parent_retirement_bytes":PARENT,
        "selected_original199_parent_bytes":0,"retained_original199_controller_bytes":GIB/2,
        "retained_original199_guard_bytes":GIB/2,"retained_original199_DATA_bytes":DATA,
        "terminal_context_v2_unchanged":true,"raw_history_preserved":true,"all_DATA_promises_preserved":true,
        "current_census_recorded_unix_seconds":c.recorded_unix_seconds,"physical_credit_bytes":0,"DATA_credit_bytes":0,
        "CPU_credit_micros":0,"guards_changed":false,"controller_stopped":false,"archive_mutations":false,"sidecar_mutations":false,
        "r2_mutations":false,"publication_authorized":false,"replay_launch_authorized":false,"admission_authorized":false,
        "fresh_point_of_use_native_resource_and_candidate_admission_required":true});
    if inputs.retained.selected_inputs().is_some() {
        evidence["input_verification_context"] = json!(inputs.binding);
    }
    let selected = VerifiedParentMemory {
        raw_total_bytes: base.raw_total_bytes(),
        effective_total_bytes: effective_total,
        raw_peer_bytes: base.raw_peer_bytes(),
        effective_peer_bytes: effective_peer,
        parent_selection_applied: true,
        evidence,
    };
    match &request.completed_cached145 {
        Some(closure) => {
            cached145::apply(selected, closure, &request.current, &before, &after, now)
        }
        None => Ok(selected),
    }
}
/// None leaves every legacy baseline byte unchanged; no selector is implicitly enabled.
pub fn preserve_baseline(base: VerifiedPeerMemory) -> VerifiedParentMemory {
    VerifiedParentMemory {
        raw_total_bytes: base.raw_total_bytes(),
        effective_total_bytes: base.effective_total_bytes(),
        raw_peer_bytes: base.raw_peer_bytes(),
        effective_peer_bytes: base.effective_peer_bytes(),
        parent_selection_applied: false,
        evidence: Value::Null,
    }
}
/// A persisted selected view is never trusted as arithmetic; rerun the full constructor.
pub fn revalidate(evidence: &Value, now: u64) -> Result<VerifiedParentMemory> {
    ensure!(
        evidence["schema"] == "terminal199-parent-only-effective-memory-selection-v1",
        "parent selection schema differs"
    );
    let request: Request = serde_json::from_value(evidence["request"].clone())?;
    let result = select(&request, now)?;
    ensure!(
        result.evidence == *evidence,
        "parent memory evidence differs from independent full revalidation"
    );
    Ok(result)
}

/// Continuity only: no memory getters and no new-admission authority.
#[derive(Debug)]
pub struct GuardContinuity {
    _validated: (),
}
/// A running guard reauthenticates its admission-bound historical proof at its
/// actual original acceptance clock, then performs current scoped source/state/
/// native/process/job checks through select. It cannot issue a fresh memory view.
pub fn revalidate_running_guard(evidence: &Value, now: u64) -> Result<GuardContinuity> {
    let accepted = f::n(evidence, "recorded_unix_seconds")?;
    ensure!(
        accepted > 0 && accepted <= now,
        "guard evidence acceptance clock differs"
    );
    revalidate(evidence, accepted)?;
    Ok(GuardContinuity { _validated: () })
}

#[cfg(test)]
mod tests;
