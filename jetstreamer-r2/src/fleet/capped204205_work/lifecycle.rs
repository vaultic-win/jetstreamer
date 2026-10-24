//! Actual ownership transitions. Every input is bounded metadata; private V4
//! completion remains separate from independent archive and publication gates.
use super::*;

pub(super) fn plan_scope(p: &Value) -> Result<()> {
    let epoch = number(p, "epoch")?;
    profile(epoch)?;
    let root = Path::new(string(p, "run_root")?);
    let guard = Path::new(string(p, "guard_directory")?);
    let leaf = |path: &Path, prefix: &str| {
        path.file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix(prefix))
            .is_some_and(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
    };
    ensure!(
        p["schema"] == "jetstreamer-capped204205-continuation-plan-v1"
            && namespace(epoch, string(p, "producer_unit")?)
            && string(p, "guard_unit")?
                .starts_with(&format!("horizon-guard-{epoch}-capped-continuation-"))
            && string(p, "guard_unit")?.ends_with(".service")
            && root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && leaf(root, &format!("checkpoint-continuation-{epoch}-"))
            && guard.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && leaf(guard, &format!("horizon-capped-guard-{epoch}-"))
            && p["worker"]["sha256"] == WORKER_SHA
            && canonical_digest(&p["node_sha256"])
            && canonical_digest(&p["guard_sha256"]),
        "capture requires the closed actual 204/205 continuation plan scope"
    );
    Ok(())
}

pub(super) fn origin(c: &Claim, i: &Inputs) -> Result<()> {
    let p = &i.plan;
    plan_scope(p)?;
    let l = &i.launch;
    let a = &i.admission;
    let (old, old_iid, _, _) = profile(c.epoch)?;
    let capture = evidence::bound(&serde_json::from_value(p["source_capture"].clone())?, true)?;
    ensure!(
        capture["schema"] == "jetstreamer-capped204205-source-capture-v1"
            && capture["epoch"] == c.epoch
            && capture["original_unit"] == old
            && capture["original_invocation_id"] == old_iid
            && capture["prefix_archive"] == p["prefix_archive"]
            && capture["prefix_bytes"] == p["prefix_bytes"]
            && capture["prefix_manifest_sha256"] == p["metadata"]["prefix_manifest"]["sha256"]
            && capture["frozen_root_owned_readonly"] == true
            && capture["metadata_policy_rederived"] == true
            && capture["publication_authorized"] == false
            && capture["r2_mutations"] == false
            && a["source_capture_sha256"] == p["source_capture"]["sha256"]
            && a["prefix_sha256"] == p["prefix_archive"]["sha256"]
            && a["snapshot_sha256"] == p["restart_snapshot"]["sha256"]
            && a["worker_sha256"] == p["worker"]["sha256"]
            && a["complete_fleet_and_effective_guards_protected"] == true
            && a["restore_suffix_validation_and_assembly_overlap_included"] == true,
        "continuation origin lost actual retained prefix or complete-path admission"
    );
    for key in ["idle_before", "idle_after"] {
        let idle = &capture[key];
        ensure!(
            idle["schema"] == "jetstreamer-capped204205-source-idle-v1"
                && idle["epoch"] == c.epoch
                && idle["unit"] == old
                && idle["historical_invocation_id"] == old_iid
                && idle["current_source_idle"] == true
                && idle["process_reference_census"]["references"]
                    .as_array()
                    .is_some_and(Vec::is_empty),
            "original capped owner lacks captured positive inactivity"
        );
    }
    let journal: BoundFile = serde_json::from_value(p["metadata"]["manager_journal"].clone())?;
    let origin_start =
        capture::manager_history(&evidence::bytes(&journal, true)?, old, old_iid, true)?;
    ensure!(
        number(l, "epoch_started_unix_millis")? == origin_start,
        "continuation elapsed time differs from the original authoritative start"
    );
    let expected = evidence::expected_command(p, a, &c.producer_plan)?;
    ensure!(
        evidence::command_matches(&expected, string(l, "expected_exec_start")?),
        "continuation launch command differs from the actual admitted node and plan"
    );
    let first = evidence::bound(&serde_json::from_value(l["first_guard"].clone())?, true)?;
    let census: BTreeMap<String, Value> = serde_json::from_value(l["unit_census"].clone())?;
    let first_ms = number(&first, "recorded_unix_millis")?;
    evidence::guard(p, l, &first, &census, first_ms)?;
    ensure!(
        l["main_pid"].as_u64().is_some_and(|pid| pid > 1)
            && l["main_pid"] == first["processes"]["main_pid"],
        "launch PID differs from the independently observed first guard"
    );
    let start_journal: BoundFile = serde_json::from_value(l["manager_journal"].clone())?;
    let start = capture::manager_history(
        &evidence::bytes(&start_journal, true)?,
        string(p, "producer_unit")?,
        string(l, "invocation_id")?,
        false,
    )?;
    ensure!(
        start <= first_ms && first_ms - start <= 900_000,
        "first guard is detached from actual continuation start"
    );
    Ok(())
}

pub(super) fn policy(c: &Claim, p: &Value) -> Result<()> {
    ensure!(
        p["epoch"] == c.epoch
            && p["producer_plan"] == private157::binding(&c.producer_plan)
            && p["launch"] == private157::binding(&c.launch)
            && p["frame"] == private157::binding(&c.frame),
        "sidecar ETA model is not bound to the actual plan, launch and coordinated frame"
    );
    let evidence = p["estimate_evidence"]
        .as_array()
        .context("ETA evidence census missing")?;
    ensure!(
        !evidence.is_empty(),
        "sidecar ETA lacks hash-bound planning or measured evidence"
    );
    for b in evidence {
        evidence::bound(&serde_json::from_value(b.clone())?, true)?;
    }
    Ok(())
}

pub(super) fn terminal_frame(
    p: &Value,
    l: &Value,
    f: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<Value> {
    let terminal = evidence::bound(
        &serde_json::from_value(f["terminal_snapshot"].clone())?,
        true,
    )?;
    evidence::terminal_proof(p, l, &terminal)?;
    let name = string(p, "producer_unit")?;
    ensure!(
        terminal["current_unit"]
            == serde_json::to_value(
                census
                    .get(name)
                    .context("terminal producer omitted from current census")?
            )?,
        "terminal producer differs from current complete census"
    );
    Ok(terminal)
}

pub(super) fn unresolved(
    c: &Claim,
    p: &Value,
    census: &BTreeMap<String, Value>,
    error: &str,
) -> Value {
    let owners = census
        .iter()
        .filter(|(name, v)| {
            capture::epoch_scope(c.epoch, name)
                && *name != p["guard_unit"].as_str().unwrap_or("")
                && !idle(v)
        })
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>();
    json!({"epoch":c.epoch,"phase":"capped204205-unresolved","unit":owners.first(),
        "unresolved_owners":owners,"live":!owners.is_empty(),"ownership_unresolved":true,
        "positive_inactivity_confirmed":false,"current_sidecar_eta_valid":false,
        "frame":private157::binding(&c.frame),"reason":error,
        "ordinary_replay_claim":false,"publication_authorized":false,"r2_mutations":false})
}

pub(super) fn cleanup_allowed(f: &Value, epoch: u64) -> bool {
    f.get("capped204205_work").is_none_or(|v| {
        v.as_array().is_some_and(|rows| {
            rows.iter().filter(|r| r["epoch"] == epoch).all(|r| {
                r["positive_inactivity_confirmed"] == true
                    && r["live"] == false
                    && r["ownership_unresolved"] != true
            })
        })
    })
}

pub(super) fn cleanup_current(
    f: &Value,
    epoch: u64,
    current: &BTreeMap<String, Value>,
    owners: &[(String, String)],
) -> Result<bool> {
    let Some(rows) = f.get("capped204205_work") else {
        return Ok(false);
    };
    let rows = rows.as_array().context("invalid capped cleanup roster")?;
    let matches = rows
        .iter()
        .filter(|r| r["epoch"] == epoch)
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return Ok(false);
    }
    ensure!(
        matches.len() == 1 && cleanup_allowed(f, epoch),
        "capped cleanup is unresolved or has active ownership"
    );
    let row = matches[0];
    let p = evidence::bound(&serde_json::from_value(row["producer_plan"].clone())?, true)?;
    let l = evidence::bound(&serde_json::from_value(row["launch"].clone())?, true)?;
    let frame = evidence::bound(&serde_json::from_value(row["frame"].clone())?, true)?;
    let proof = evidence::bound(
        &serde_json::from_value(frame["inactivity_snapshot"].clone())?,
        true,
    )?;
    // Validate the exact captured frame before applying the fresh race check.
    let captured = serde_json::from_value(frame["unit_census_after"].clone())?;
    evidence::inactive(&p, &l, &frame, &captured)?;
    let actors: Vec<Actor> = serde_json::from_value(frame["downstream_actors"].clone())?;
    let (original, original_iid, _, _) = profile(epoch)?;
    ensure!(
        owners.len() == 1
            && (owners[0]
                == (
                    string(&p, "producer_unit")?.into(),
                    string(&l, "invocation_id")?.into()
                )
                || owners[0] == (original.into(), original_iid.into())
                || actors
                    .iter()
                    .any(|a| owners[0] == (a.unit.clone(), a.invocation_id.clone()))),
        "cleanup publication belongs to a different continuation or downstream owner"
    );
    for (name, old) in &captured {
        if !capture::epoch_scope(epoch, name) {
            continue;
        }
        let fresh = current
            .get(name)
            .context("capped cleanup owner omitted from fresh census")?;
        ensure!(
            idle(fresh)
                && (fresh == old
                    || (fresh["LoadState"] == "not-found" && fresh["InvocationID"] == "")),
            "capped cleanup owner changed or became active"
        );
        inactive_status::no_pending_owner_trigger(name, fresh["LoadState"] == "not-found")?;
        capture::group(name)?;
    }
    capped204205_admission::original_idle(
        current.get(original).context("original owner missing")?,
        epoch,
    )?;
    let references = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(string(&p, "run_root")?),
    )?;
    ensure!(
        references.references.is_empty(),
        "capped cleanup has a live private-root reference"
    );
    // The terminal map binds each downstream owner as well as the producer.
    for (name, iid) in owners {
        if name == string(&p, "producer_unit")? {
            continue;
        }
        if name == original {
            let journal: BoundFile =
                serde_json::from_value(p["metadata"]["manager_journal"].clone())?;
            let raw = evidence::bytes(&journal, true)?;
            capture::manager_history(&raw, original, original_iid, true)?;
            capture::manager_terminal(&raw, original, original_iid)?;
            continue;
        }
        let terminal = &proof["downstream_terminals"][name];
        let raw = evidence::bytes(
            &serde_json::from_value(terminal["manager_journal"].clone())?,
            true,
        )?;
        capture::manager_terminal(&raw, name, iid)?;
        ensure!(
            terminal["invocation_id"] == *iid && idle(&terminal["current_unit"]),
            "downstream status owner lacks its exact durable terminal history"
        );
    }
    Ok(true)
}
