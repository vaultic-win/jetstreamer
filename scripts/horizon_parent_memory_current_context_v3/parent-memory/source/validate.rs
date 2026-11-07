use crate::{fsutil as f, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};
pub fn policy(p: &Policy) -> Result<()> {
    ensure!(
        p.schema == "terminal199-parent-only-memory-retirement-policy-v1"
            && p.enabled
            && p.terminal_context.path == Path::new(REGISTRY)
            && p.terminal_context.sha256 == REGISTRY_SHA
            && p.controller_source.path == Path::new(SCRIPT)
            && p.controller_source.sha256 == SCRIPT_SHA
            && p.guard_source.path == Path::new(GUARD_SCRIPT)
            && p.guard_source.sha256 == GUARD_SHA
            && p.quarantined_state.path == Path::new(STATE)
            && p.quarantined_state.sha256 == STATE_SHA
            && p.controller_start_ticks > 0
            && p.raw_memory_bytes == RAW_MEMORY
            && p.selected_parent_bytes == 0
            && p.residual_controller_guard_bytes == RESIDUAL
            && p.data_bytes == DATA,
        "explicit original199 parent-only policy/source/context/caps differ"
    );
    ensure!(
        p.controller_argv.len() > 2
            && p.controller_argv[1] == SCRIPT
            && f::sha(&serde_json::to_vec(&p.controller_argv)?) == CONTROLLER_ARGV_SHA
            && p.controller_argv
                .iter()
                .all(|a| !a.starts_with("--retry-failed")),
        "original controller exact argv/no-retry contract changed"
    );
    let names = p.native_units.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        names.len() == p.native_units.len()
            && [PRODUCER, CONTROLLER, GUARD, TIMER]
                .iter()
                .all(|u| names.contains(*u)),
        "closed relevant native family incomplete/duplicated"
    );
    Ok(())
}
pub fn failed_state(s: &Value) -> Result<()> {
    let a = s["assignments"]
        .as_object()
        .context("quarantine assignments")?;
    ensure!(
        s["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && a.len() == 1
            && a["lane-a"]["phase"] == "failed"
            && a["lane-a"]["unit"] == PRODUCER
            && a["lane-a"]["first_epoch"] == 199
            && a["lane-a"]["last_epoch"] == 200
            && a["lane-a"]["attempt"] == 1
            && a["lane-a"]["source_recovery"] == false
            && a["lane-a"]["adopt_only"] == false
            && s["attempts"] == json!({"199-200":1})
            && s["completed"].as_object().is_some_and(|m| m.is_empty())
            && s["import_owner"].is_null()
            && s["manifest_fingerprint"]
                == "sha256:581f9ef3a74fc80a8b6b2754a7f4def480c8092d20529f446784f0d73dae810b",
        "controller no longer quarantines the exact occupied failed original lane"
    );
    Ok(())
}
// Match the canonical decimal strings emitted by systemd without allocation.
// Keep JSON numbers, alternate spelling and overflow outside the native contract.
fn native_decimal_equals(value: &Value, expected: u64) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
        return false;
    }
    text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u64>().ok() == Some(expected)
}

pub fn controller(n: &Value) -> Result<()> {
    ensure!(
        n["Id"] == CONTROLLER
            && n["InvocationID"] == CONTROLLER_IID
            && native_decimal_equals(&n["MainPID"], CONTROLLER_PID)
            && n["ControlPID"] == "0"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["Job"] == ""
            && f::sha(&serde_json::to_vec(&n["ExecStart"])?) == CONTROLLER_RENDERED_COMMAND_SHA
            && n["MemoryAccounting"] == "yes"
            && native_decimal_equals(&n["MemoryMax"], GIB / 2)
            && n["MemorySwapMax"] == "0"
            && n["Delegate"] == "no"
            && n["ControlGroup"] == format!("/system.slice/{CONTROLLER}"),
        "original quarantined controller native identity/hard promise changed"
    );
    Ok(())
}
/// Production accepts only the opaque selector authenticated from the exact
/// current plan. This is not a second global context allowlist.
pub(crate) fn terminal_raw_row_for_context(a: &Value, inputs: &crate::ContextInputs) -> Result<Value> {
    let row = terminal_raw_row_shape(a, inputs.binding())?;
    if inputs.retained.selected_inputs().is_some() {
        ensure!(row["original_enrollment"] == json!(inputs.retained.original_enrollment()),
            "selected raw original199 enrollment crossed its authenticated current context");
    }
    Ok(row)
}
// Preserve historical legacy tests without opening any legacy runtime inputs.
#[cfg(test)]
pub fn terminal_raw_row(a: &Value) -> Result<Value> {
    terminal_raw_row_shape(a, &Bound { path: REGISTRY.into(), sha256: REGISTRY_SHA.into() })
}
fn terminal_raw_row_shape(a: &Value, context: &Bound) -> Result<Value> {
    let rows = a["active_peer_allocations"]
        .as_array()
        .context("full raw peer allocations")?;
    let matching = rows
        .iter()
        .filter(|r| {
            r["state"] == "retained-terminal-original199"
                || r["invocation_id"] == PRODUCER_IID
                || r["unit"] == PRODUCER
        })
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1,
        "original199 raw memory row absent/duplicated"
    );
    let r = matching[0];
    ensure!(
        r["state"] == "retained-terminal-original199"
            && r["unit"] == PRODUCER
            && r["invocation_id"] == PRODUCER_IID
            && r["memory_max_bytes"] == RAW_MEMORY
            && r["parent_memory_bytes"] == PARENT
            && r["controller_memory_bytes"] == GIB / 2
            && r["guard_memory_bytes"] == GIB / 2
            && r["data_reservation_bytes"] == DATA
            && r["native_pool_suballocation"] == false
            && r["memory_credit_bytes"] == 0
            && r["DATA_credit_bytes"] == 0
            && r["credit_bytes"] == 0
            && r["resource_release_qualified"] == false
            && r["ordinary_replay_claim"] == false
            && r["terminal_context"] == json!(context),
        "original199 raw193GiB/768GiB context or no-credit lineage changed"
    );
    let growth = a["projected_obligations"]
        .as_array()
        .context("complete raw DATA obligations")?;
    let matching = growth
        .iter()
        .filter(|r| r["producer_invocation_id"] == PRODUCER_IID)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1
            && matching[0]["epoch"] == 199
            && matching[0]["claim_key"]
                == format!("epoch199/current-enrolled-growth/{PRODUCER_IID}")
            && matching[0]["outstanding_bytes"] == DATA,
        "original199 DATA missing/reduced/duplicated"
    );
    let hard = a["current_owner_hard_limits"]
        .as_object()
        .context("complete current hard limits")?;
    ensure!(
        [PRODUCER, CONTROLLER, GUARD, TIMER]
            .iter()
            .all(|u| !hard.contains_key(*u)),
        "original199 already double charged as ordinary current owner"
    );
    Ok(r.clone())
}
fn process(p: &Policy, r: &Process) -> Result<()> {
    ensure!(
        r.pid > 1 && r.start_ticks > 0 && f::hex(&r.invocation_id, 32),
        "bad census process identity"
    );
    match r.role.as_str() {
        "quarantined-original-controller" => ensure!(
            r.pid == CONTROLLER_PID
                && r.start_ticks == p.controller_start_ticks
                && r.unit == CONTROLLER
                && r.invocation_id == CONTROLLER_IID
                && r.command_source == p.controller_source
                && r.executable == p.controller_executable
                && r.argv == p.controller_argv
                && r.cgroup == format!("/system.slice/{CONTROLLER}"),
            "controller process/executable/source/argv changed"
        ),
        "original-stop-only-guard" => ensure!(
            r.unit == GUARD
                && r.command_source == p.guard_source
                && r.cgroup == format!("/system.slice/{GUARD}"),
            "unknown guard source/process"
        ),
        "qualified-read-only-census" => ensure!(
            r.executable == p.census.program,
            "foreign census reader process"
        ),
        _ => anyhow::bail!("unreserved original199 process/worker/importer/retry owner"),
    }
    ensure!(
        r.descriptor_refs.is_empty() && r.mmap_refs.is_empty(),
        "original worker descriptor/mmap is still held"
    );
    Ok(())
}
pub fn endpoint(p: &Policy, e: &Endpoint) -> Result<()> {
    let wanted = p.native_units.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        e.native.keys().cloned().collect::<BTreeSet<_>>() == wanted
            && e.controller_state == p.quarantined_state
            && e.scanned_process_count > 0
            && e.unresolved_processes.is_empty()
            && e.unreadable_processes.is_empty()
            && e.unresolved_launchers.is_empty()
            && e.original_worker_cgroup_members.is_empty()
            && e.original_worker_descriptor_holders.is_empty()
            && e.original_worker_mmap_holders.is_empty()
            && e.original_worker_cgroup == format!("/system.slice/{PRODUCER}"),
        "complete native/process/launcher census or positive original worker drain missing"
    );
    let dimensions = e
        .scanned_dimensions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        dimensions
            == BTreeSet::from([
                "argv",
                "cwd",
                "descriptors",
                "executable",
                "mappings",
                "source"
            ])
            && e.scanned_dimensions.len() == dimensions.len(),
        "process reference census omitted a dimension"
    );
    controller(&e.native[CONTROLLER])?;
    let w = &e.native[PRODUCER];
    ensure!(
        w["Id"] == PRODUCER
            && w["LoadState"] == "not-found"
            && w["InvocationID"] == ""
            && w["MainPID"] == "0"
            && w["ControlPID"] == "0"
            && w["ActiveState"] == "inactive"
            && w["SubState"] == "dead"
            && w["Job"] == "",
        "original parent is live/replaced/staged"
    );
    let g = &e.native[GUARD];
    ensure!(
        g["Id"] == GUARD && g["Job"] == "",
        "guard native identity/queued job differs"
    );
    if g["LoadState"] != "not-found" {
        ensure!(
            g["MemoryAccounting"] == "yes"
                && native_decimal_equals(&g["MemoryMax"], GIB / 2)
                && g["MemorySwapMax"] == "0"
                && g["Restart"] == "no"
                && g["NRestarts"] == "0",
            "retained guard exceeds its independent halfGiB hard promise"
        );
    } else {
        ensure!(
            g["MainPID"] == "0" && g["ControlPID"] == "0" && g["ActiveState"] == "inactive",
            "collected guard has hidden live work"
        );
    }
    ensure!(
        e.native[TIMER]["Id"] == TIMER && e.native[TIMER]["Job"] == "",
        "timer native identity/job differs"
    );
    let mut process_ids = BTreeSet::new();
    let mut controllers = 0;
    for r in &e.matching_processes {
        ensure!(
            process_ids.insert((r.pid, r.start_ticks)),
            "duplicate process reference"
        );
        process(p, r)?;
        if r.role == "quarantined-original-controller" {
            controllers += 1;
        }
    }
    ensure!(
        controllers == 1,
        "exact current controller process missing/duplicated"
    );
    if let Some(pid) = g["MainPID"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|p| *p > 1)
    {
        ensure!(
            e.matching_processes
                .iter()
                .filter(|r| r.pid == pid
                    && r.unit == GUARD
                    && r.role == "original-stop-only-guard"
                    && g["InvocationID"] == r.invocation_id)
                .count()
                == 1,
            "live guard process/source custody missing or duplicated"
        );
    }
    let mut findings = BTreeSet::new();
    for l in &e.launcher_findings {
        ensure!(
            wanted.contains(&l.unit)
                && findings.insert(l.unit.clone())
                && !l.may_start_original_parent,
            "unknown/duplicate or unresolved future launch capability"
        );
        match l.disposition.as_str() {
            "quarantined-original-controller" => ensure!(
                l.unit == CONTROLLER
                    && l.source == p.controller_source
                    && l.current_invocation_id.as_deref() == Some(CONTROLLER_IID),
                "controller source no-retry custody differs"
            ),
            "original-stop-only-guard" => ensure!(
                (l.unit == GUARD || l.unit == TIMER) && l.source == p.guard_source,
                "future guard source is not exact stop-only implementation"
            ),
            "original-collected-worker" => ensure!(
                l.unit == PRODUCER && l.current_invocation_id.is_none(),
                "collected worker regained a current owner"
            ),
            "persistently-fenced-future-source" => {
                let n = &e.native[&l.unit];
                ensure!(
                    n["LoadState"] == "masked"
                        && n["MainPID"] == "0"
                        && n["ControlPID"] == "0"
                        && n["Job"] == ""
                        && n["ActiveState"] == "inactive"
                        && l.current_invocation_id.is_none(),
                    "future launcher lacks persistent mask/native custody"
                );
            }
            _ => anyhow::bail!("unqualified future launch disposition"),
        }
    }
    ensure!(
        findings == wanted,
        "complete native family not covered by future-launch custody"
    );
    Ok(())
}
pub fn compose(
    raw_total: u64,
    baseline_total: u64,
    raw_peer: u64,
    baseline_peer: u64,
) -> Result<(u64, u64)> {
    ensure!(
        raw_total >= raw_peer
            && baseline_total >= baseline_peer
            && baseline_total <= raw_total
            && baseline_peer <= raw_peer
            && raw_total - baseline_total == raw_peer - baseline_peer
            && baseline_peer >= RAW_MEMORY,
        "baseline absent/duplicated reductions or retained193GiB missing"
    );
    Ok((
        baseline_total
            .checked_sub(PARENT)
            .context("parent exceeds complete effective total")?,
        baseline_peer
            .checked_sub(PARENT)
            .context("parent exceeds complete effective peers")?,
    ))
}
