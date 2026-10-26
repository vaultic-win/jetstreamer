//! Lossless typed resource peers for captured completed-archive delivery.
//! Raw fleet rows remain intact. Only a fully proved peer leaves legacy views.
use super::*;
struct Peer {
    spec: Spec,
    binding: BoundFile,
    launch: Value,
    admission: Value,
    row: Value,
    claim: Value,
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("completed peer string absent: {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("completed peer integer absent: {k}"))
}
fn selected(row: &Value) -> bool {
    singleton227_admission::active_owner(row)
        .ok()
        .and_then(|u| u["Id"].as_str())
        .is_some_and(|n| n.starts_with("horizon-qualify-") && n.contains("-generic-"))
}
pub(super) fn claim_launch(claim: &PipelineClaim) -> Result<(BoundFile, Value, Spec, Value)> {
    ensure!(
        pipeline_scope(&claim.phase, &claim.unit) == Some(claim.epoch),
        "completed peer claim namespace differs"
    );
    let mut found = Vec::new();
    for b in &claim.evidence {
        let v = read(b)?;
        if v["schema"] == "jetstreamer-completed-archive-phase-launch-v1" {
            found.push((b.clone(), v));
        }
    }
    ensure!(
        found.len() == 1,
        "completed peer needs exactly one immutable captured launch"
    );
    let (binding, launch) = found.pop().unwrap();
    let spec: Spec = serde_json::from_value(read(&serde_json::from_value(
        launch["phase_spec"].clone(),
    )?)?)?;
    shape(&spec)?;
    let issuer = string(&launch, "issuer_sha256")?;
    ensure!(
        is_lower_hex(issuer, 64),
        "completed peer launch issuer digest differs"
    );
    launch::validate_saved(&launch, &spec, spec.phase, issuer)?;
    let admission = read(&serde_json::from_value(launch["admission"].clone())?)?;
    let archive = spec.origin.root().join("output");
    ensure!(
        spec.epoch == claim.epoch
            && spec.units[spec.phase.name()] == claim.unit
            && launch["invocation_id"] == claim.invocation_id
            && pipeline_status::same_exec_start(
                &claim.expected_exec_start,
                string(&launch["effective_unit"], "ExecStart")?
            )
            && admission["schema"] == RECEIPT
            && admission["admitted"] == true
            && admission["issuer_sha256"] == spec.programs["launcher"].artifact.sha256
            && admission
                .get("launcher_transition")
                .cloned()
                .unwrap_or(Value::Null)
                == serde_json::to_value(&spec.launcher_transition)?
            && admission["epoch"] == spec.epoch
            && admission["phase"] == spec.phase.name()
            && admission["origin"] == serde_json::to_value(&spec.origin)?
            && admission["tools"] == serde_json::to_value(&spec.tools)?
            && admission["programs"] == serde_json::to_value(&spec.programs)?
            && admission["decoder_capacity"] == serde_json::to_value(&spec.decoder_capacity)?
            && admission["state_root"] == serde_json::to_value(&spec.state_root)?
            && admission["units"] == serde_json::to_value(&spec.units)?
            && admission["guard_units"] == serde_json::to_value(&spec.guard_units)?
            && admission["startup_plan"] == private157::binding(&spec.startup_plan)
            && admission["argv"] == serde_json::to_value(command(&spec, &archive)?)?
            && admission["capacity"]["resource_basis"] == spec.resource_basis
            && admission["capacity"]["additional_bytes"] == METADATA
            && admission["capacity"]["memory_before"]["candidate_memory_max_bytes"]
                == spec.phase.profile().1
            && admission["capacity"]["memory_after"]["candidate_memory_max_bytes"]
                == spec.phase.profile().1,
        "completed peer admission/launch/registered claim differs"
    );
    Ok((binding, launch, spec, admission))
}
pub(in crate::fleet) fn claim_names(claim: &PipelineClaim) -> Result<BTreeSet<String>> {
    if pipeline_scope(&claim.phase, &claim.unit).is_none() {
        return Ok(BTreeSet::new());
    }
    let (_, _, s, _) = claim_launch(claim)?;
    Ok(BTreeSet::from([s.guard_units[s.phase.name()].clone()]))
}

fn terminal_guard_row(row: &Value, guard: &str, protection: &Value) -> Result<()> {
    let history = &protection["completed"]["history"];
    let selected = string(history, "guard_invocation_id")?;
    ensure!(
        row["Id"] == guard
            && row["LoadState"] == "loaded"
            && row["Type"] == "oneshot"
            && row["ActiveState"] == "inactive"
            && row["SubState"] == "dead"
            && row["MainPID"] == "0"
            && row["ControlGroup"] == ""
            && row["NRestarts"] == "0"
            && row["Result"] == "success"
            && row["ExecMainStatus"] == "0"
            && row["InvocationID"] == selected
            && protection["latest_sample"]["guard_invocation_id"] == selected
            && pipeline_status::same_exec_start(
                string(history, "expected_exec_start")?,
                string(row, "ExecStart")?
            ),
        "completed rollover endpoint is not the selected terminal-success guard firing"
    );
    Ok(())
}

fn no_relevant_jobs(names: &BTreeSet<String>) -> Result<Value> {
    let output = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--plain",
            "--no-pager",
            "--full",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "completed rollover pending-job lookup failed"
    );
    let stdout = std::str::from_utf8(&output.stdout)?;
    ensure!(
        !stdout.split_whitespace().any(|word| names.contains(word)),
        "completed producer or guard has a pending systemd job"
    );
    Ok(json!({"units":names,"raw_stdout":stdout,"exit_code":output.status.code()}))
}

fn rollover_endpoint(
    peer: &Peer,
    census: &BTreeMap<String, Value>,
    minimum: u64,
    now: u64,
) -> Result<(String, Value, BTreeSet<String>)> {
    let owner_name = peer.spec.units[peer.spec.phase.name()].clone();
    let owner = census
        .get(&owner_name)
        .context("completed rollover owner omitted from raw census")?;
    owner_matches(peer, owner)?;
    let guard_name = peer.spec.guard_units[peer.spec.phase.name()].clone();
    let guard_row = census
        .get(&guard_name)
        .context("completed rollover guard omitted from raw census")?;
    let plan: BoundFile = serde_json::from_value(peer.launch["guard_plan"].clone())?;
    let plan_contents = read(&plan)?;
    let completed = warmup223::completed_guard_binding(
        &guard_name,
        Path::new(string(&plan_contents, "receipt_directory")?),
        minimum,
        now,
    )?;
    let sample: BoundFile = serde_json::from_value(completed["binding"].clone())?;
    let protection = guard(
        peer,
        &BTreeMap::from([(owner_name.clone(), sample)]),
        census,
        minimum,
        now,
    )?;
    terminal_guard_row(guard_row, &guard_name, &protection)?;
    Ok((
        guard_name.clone(),
        json!({
            "schema":"jetstreamer-completed-archive-nonlaunching-guard-endpoint-v1",
            "epoch":peer.spec.epoch,
            "phase":peer.spec.phase,
            "protected_unit":owner_name.clone(),
            "guard_unit":guard_name.clone(),
            "claim":peer.claim.clone(),
            "authenticated_launch":private157::binding(&peer.binding),
            "phase_spec":peer.launch["phase_spec"].clone(),
            "guard_plan":private157::binding(&plan),
            "guard_executable":peer.spec.programs["guard"].artifact.clone(),
            "raw_owner":owner,
            "raw_guard":guard_row,
            "protection":protection,
            "no_stop_files_confirmed":true
        }),
        BTreeSet::from([owner_name, guard_name]),
    ))
}

fn attach_pending_jobs(
    mut result: BTreeMap<String, Value>,
    pending_names: BTreeSet<String>,
) -> Result<BTreeMap<String, Value>> {
    if result.is_empty() {
        return Ok(result);
    }
    let jobs = no_relevant_jobs(&pending_names)?;
    for endpoint in result.values_mut() {
        endpoint["pending_jobs"] = jobs.clone();
    }
    Ok(result)
}

fn fleet_rollover_scope(claim: &PipelineClaim) -> bool {
    matches!(claim.epoch, 207 | 209)
        && pipeline_scope(&claim.phase, &claim.unit) == Some(claim.epoch)
}

/// Capture one independently authenticated endpoint for the only volatile
/// actor in an authenticated completed pipeline: its periodic, non-launching guard.
/// Terminal predecessors are intentionally skipped; their owners are not live.
pub(in crate::fleet) fn guard_rollover_endpoints(
    claims: &[PipelineClaim],
    census: &BTreeMap<String, Value>,
    minimum: u64,
    now: u64,
) -> Result<BTreeMap<String, Value>> {
    let mut pending_names = BTreeSet::new();
    let mut result = BTreeMap::new();
    for claim in claims.iter().filter(|claim| fleet_rollover_scope(claim)) {
        // Scope is only routing. The immutable launch/spec/origin remains the
        // mandatory authority for both epoch 207 and epoch 209.
        let (binding, launch, spec, admission) = claim_launch(claim)?;
        let owner = census
            .get(&claim.unit)
            .context("completed rollover owner omitted from raw census")?;
        if owner["ActiveState"] != "active" || owner["SubState"] != "running" {
            continue;
        }
        let peer = Peer {
            spec,
            binding,
            launch,
            admission,
            row: Value::Null,
            claim: serde_json::to_value(claim)?,
        };
        let (guard_name, endpoint, names) = rollover_endpoint(&peer, census, minimum, now)?;
        pending_names.extend(names);
        ensure!(
            result.insert(guard_name, endpoint).is_none(),
            "completed rollover guard is claimed more than once"
        );
    }
    attach_pending_jobs(result, pending_names)
}

/// Derive every turnover-capable auxiliary guard from the authenticated
/// completed peers in the fleet, never from a unit-name suffix.
pub(in crate::fleet) fn peer_guard_rollover_endpoints(
    fleet: &Value,
    census: &BTreeMap<String, Value>,
    minimum: u64,
    now: u64,
) -> Result<BTreeMap<String, Value>> {
    let mut pending_names = BTreeSet::new();
    let mut result = BTreeMap::new();
    for peer in accepted(fleet)? {
        let (guard_name, endpoint, names) = rollover_endpoint(&peer, census, minimum, now)?;
        pending_names.extend(names);
        ensure!(
            result.insert(guard_name, endpoint).is_none(),
            "completed peer rollover guard is claimed more than once"
        );
    }
    attach_pending_jobs(result, pending_names)
}

fn endpoint_shape(
    endpoint: &Value,
    census: &BTreeMap<String, Value>,
    guard_name: &str,
) -> Result<()> {
    let owner = string(endpoint, "protected_unit")?;
    let epoch = number(endpoint, "epoch")?;
    let claim_phase = string(&endpoint["claim"], "phase")?;
    let expected_phase = match claim_phase {
        "full-verification" => "full",
        "plugin-verification" => "plugin",
        "upload-readback" => "upload",
        _ => bail!("completed rollover claim phase differs"),
    };
    let claim_evidence = endpoint["claim"]["evidence"]
        .as_array()
        .context("completed rollover claim evidence differs")?;
    ensure!(
        endpoint["schema"] == "jetstreamer-completed-archive-nonlaunching-guard-endpoint-v1"
            && pipeline_scope(claim_phase, owner) == Some(epoch)
            && endpoint["claim"]["epoch"].as_u64() == Some(epoch)
            && endpoint["claim"]["unit"].as_str() == Some(owner)
            && endpoint["phase"].as_str() == Some(expected_phase)
            && endpoint["claim"]["invocation_id"] == endpoint["raw_owner"]["InvocationID"]
            && endpoint["raw_owner"]["Id"].as_str() == Some(owner)
            && string(&endpoint["claim"], "expected_exec_start")
                .ok()
                .zip(endpoint["raw_owner"]["ExecStart"].as_str())
                .is_some_and(|(expected, actual)| {
                    pipeline_status::same_exec_start(expected, actual)
                })
            && claim_evidence.contains(&endpoint["authenticated_launch"])
            && endpoint["phase_spec"]["path"].as_str().is_some()
            && endpoint["phase_spec"]["sha256"]
                .as_str()
                .is_some_and(|digest| is_lower_hex(digest, 64))
            && endpoint["guard_unit"] == guard_name
            && endpoint["raw_owner"]
                == *census
                    .get(owner)
                    .context("completed rollover endpoint owner disappeared")?
            && endpoint["raw_guard"]
                == *census
                    .get(guard_name)
                    .context("completed rollover endpoint guard disappeared")?
            && endpoint["no_stop_files_confirmed"] == true
            && endpoint["pending_jobs"]["units"]
                .as_array()
                .is_some_and(|units| {
                    [owner, guard_name]
                        .iter()
                        .all(|name| units.iter().any(|value| value.as_str() == Some(name)))
                })
            && endpoint["pending_jobs"]["raw_stdout"]
                .as_str()
                .is_some_and(|raw| {
                    !raw.split_whitespace()
                        .any(|word| word == owner || word == guard_name)
                })
            && endpoint["pending_jobs"]["exit_code"] == 0,
        "completed rollover endpoint lost raw identity, no-stop, or pending-job proof"
    );
    terminal_guard_row(&endpoint["raw_guard"], guard_name, &endpoint["protection"])
}

/// Compare complete raw censuses without normalizing either one. Only the two
/// volatile fields of an independently authenticated, terminal-success
/// completed-phase periodic guard may differ. The returned evidence retains both raw
/// endpoint rows and both independently selected latest completions.
pub(in crate::fleet) fn authenticated_guard_rollovers(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    before_endpoints: &BTreeMap<String, Value>,
    after_endpoints: &BTreeMap<String, Value>,
) -> Result<Vec<Value>> {
    if before == after {
        return Ok(Vec::new());
    }
    ensure!(
        before.keys().eq(after.keys()),
        "fleet unit roster changed during completed guard rollover"
    );
    let mut normalized = after.clone();
    let mut evidence = Vec::new();
    for (name, before_row) in before
        .iter()
        .filter(|(name, row)| after.get(*name) != Some(*row))
    {
        let before_endpoint = before_endpoints
            .get(name)
            .context("changed fleet actor is not an authenticated completed guard")?;
        let after_endpoint = after_endpoints
            .get(name)
            .context("changed fleet actor lacks its second authenticated guard endpoint")?;
        endpoint_shape(before_endpoint, before, name)?;
        endpoint_shape(after_endpoint, after, name)?;
        let owner = string(before_endpoint, "protected_unit")?;
        ensure!(
            before_endpoint["protected_unit"] == after_endpoint["protected_unit"]
                && before_endpoint["claim"] == after_endpoint["claim"]
                && before_endpoint["authenticated_launch"]
                    == after_endpoint["authenticated_launch"]
                && before_endpoint["guard_plan"] == after_endpoint["guard_plan"]
                && before_endpoint["guard_executable"] == after_endpoint["guard_executable"]
                && before_endpoint["phase_spec"] == after_endpoint["phase_spec"]
                && before_endpoint["protection"]["properties"]
                    == after_endpoint["protection"]["properties"]
                && before.get(owner) == after.get(owner)
                && before_endpoint["raw_owner"] == after_endpoint["raw_owner"],
            "completed guard rollover changed its claim, executable, plan, controls, or producer"
        );
        let before_iid = string(before_row, "InvocationID")?;
        let after_row = after
            .get(name)
            .context("completed rollover after row absent")?;
        let after_iid = string(after_row, "InvocationID")?;
        ensure!(
            before_iid != after_iid
                && pipeline_status::same_exec_start(
                    string(before_row, "ExecStart")?,
                    string(after_row, "ExecStart")?
                ),
            "completed guard change is not one genuine invocation rollover"
        );
        let mut stable = after_row.clone();
        stable["InvocationID"] = before_row["InvocationID"].clone();
        stable["ExecStart"] = before_row["ExecStart"].clone();
        ensure!(
            stable == *before_row,
            "completed guard changed nonvolatile service state"
        );
        let before_sample = number(
            &before_endpoint["protection"]["latest_sample"],
            "recorded_unix_seconds",
        )?;
        let after_sample = number(
            &after_endpoint["protection"]["latest_sample"],
            "recorded_unix_seconds",
        )?;
        ensure!(
            after_sample >= before_sample,
            "completed guard completion clock moved backwards"
        );
        normalized.insert(name.clone(), before_row.clone());
        evidence.push(json!({"guard_unit":name,"protected_unit":owner,
            "raw_before":before_row,"raw_after":after_row,
            "endpoint_before":before_endpoint,"endpoint_after":after_endpoint,
            "only_invocation_and_rendered_exec_start_changed":true,
            "producer_unchanged":true,"nonlaunching_guard_only":true}));
    }
    ensure!(
        normalized == *before && !evidence.is_empty(),
        "fleet unit identities or commands changed outside authenticated completed guard rollover"
    );
    Ok(evidence)
}
pub(in crate::fleet) fn authenticated_guard_rollover_brackets(
    before: &BTreeMap<String, Value>,
    after: &BTreeMap<String, Value>,
    current: &BTreeMap<String, Value>,
    before_endpoints: &BTreeMap<String, Value>,
    after_endpoints: &BTreeMap<String, Value>,
    current_endpoints: &BTreeMap<String, Value>,
) -> Result<Value> {
    Ok(json!({
        "before_after":authenticated_guard_rollovers(
            before, after, before_endpoints, after_endpoints)?,
        "before_final":authenticated_guard_rollovers(
            before, current, before_endpoints, current_endpoints)?,
        "all_non_guard_rows_exact":true,
        "raw_endpoint_censuses_preserved":true
    }))
}
fn owner_matches(p: &Peer, owner: &Value) -> Result<()> {
    let expected = &p.launch["owner"];
    for k in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        ensure!(
            expected.get(k).is_some() && expected[k] == owner[k],
            "completed peer actual owner changed: {k}"
        );
    }
    ensure!(
        owner["NRestarts"] == "0"
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["ExecStart"]
                .as_str()
                .zip(p.launch["effective_unit"]["ExecStart"].as_str())
                .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "completed peer actual command or live state differs"
    );
    Ok(())
}
fn accepted(f: &Value) -> Result<Vec<Peer>> {
    let active = f["active"]
        .as_array()
        .context("completed peer full active roster absent")?;
    if !active.iter().any(selected) {
        return Ok(Vec::new());
    }
    let plan = bound_json(&BoundFile {
        path: string(f, "plan")?.into(),
        sha256: string(f, "plan_sha256")?.into(),
    })?;
    let claims: Vec<PipelineClaim> = serde_json::from_value(plan["pipeline_claims"].clone())?;
    let mut epochs = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut result = Vec::new();
    for row in active.iter().filter(|r| selected(r)) {
        let owner = singleton227_admission::active_owner(row)?;
        let name = string(owner, "Id")?;
        let matching = claims.iter().filter(|c| c.unit == name).collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "completed peer registered claim missing or duplicated"
        );
        let claim = matching[0];
        let (binding, launch, spec, admission) = claim_launch(claim)?;
        let peer = Peer {
            spec,
            binding,
            launch,
            admission,
            row: row.clone(),
            claim: serde_json::to_value(claim)?,
        };
        row_shape(&peer, claim, f)?;
        ensure!(
            epochs.insert(peer.spec.epoch)
                && roots.insert(peer.spec.state_root.clone())
                && active
                    .iter()
                    .filter(|r| r["epoch"] == peer.spec.epoch)
                    .count()
                    == 1,
            "completed peer overlaps another owner or metadata root"
        );
        result.push(peer);
    }
    Ok(result)
}
fn row_shape(p: &Peer, claim: &PipelineClaim, f: &Value) -> Result<()> {
    let owner = singleton227_admission::active_owner(&p.row)?;
    owner_matches(p, owner)?;
    ensure!(
        p.row["epoch"] == claim.epoch
            && p.row["phase"] == claim.phase
            && p.row["live"] == true
            && p.row["ordinary_replay_claim"] == false
            && p.row["expected_invocation_id"] == claim.invocation_id
            && p.row["evidence"] == serde_json::to_value(&claim.evidence)?
            && f["unit_census"]
                .get(&p.spec.guard_units[p.spec.phase.name()])
                .is_some()
            && f["unit_census"][&claim.unit] == *owner,
        "completed peer row differs from registered launch/full raw census"
    );
    Ok(())
}
/// Metadata-only intrinsic selection inputs from the same authenticated peer
/// reader used by ordinary capacity. No caller-chosen guard path is accepted.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub(in crate::fleet) struct GuardSelectionProfile {
    pub owner: String,
    pub owner_invocation_id: String,
    pub epoch: u64,
    pub guard_unit: String,
    pub receipt_directory: PathBuf,
    pub guard_plan: BoundFile,
    pub guard_sha256: String,
    pub authenticated_launch: BoundFile,
}
pub(in crate::fleet) fn peer_guard_selection_profiles(
    f: &Value,
) -> Result<BTreeMap<String, GuardSelectionProfile>> {
    let mut result = BTreeMap::new();
    for p in accepted(f)? {
        let owner = p.spec.units[p.spec.phase.name()].clone();
        let guard_plan: BoundFile = serde_json::from_value(p.launch["guard_plan"].clone())?;
        let plan = read(&guard_plan)?;
        let directory = PathBuf::from(string(&plan, "receipt_directory")?);
        let m = fs::symlink_metadata(&directory)?;
        let iid = string(&p.launch, "invocation_id")?.to_owned();
        ensure!(
            plan["unit"] == owner
                && plan["invocation_id"] == iid
                && directory.is_absolute()
                && directory.canonicalize()? == directory
                && m.is_dir()
                && m.uid() == 0
                && m.mode() & 0o077 == 0,
            "completed peer intrinsic guard profile differs from authenticated launch custody"
        );
        let profile = GuardSelectionProfile {
            owner: owner.clone(),
            owner_invocation_id: iid,
            epoch: p.spec.epoch,
            guard_unit: p.spec.guard_units[p.spec.phase.name()].clone(),
            receipt_directory: directory,
            guard_plan,
            guard_sha256: p.spec.programs["guard"].artifact.sha256.clone(),
            authenticated_launch: p.binding,
        };
        ensure!(
            result.insert(owner, profile).is_none(),
            "completed intrinsic guard profile duplicated"
        );
    }
    Ok(result)
}
pub(in crate::fleet) fn peer_names(f: &Value) -> Result<BTreeSet<String>> {
    Ok(accepted(f)?
        .iter()
        .map(|p| p.spec.units[p.spec.phase.name()].clone())
        .collect())
}
fn project(f: &Value, peers: &[Peer]) -> Result<Value> {
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("completed peer projection roster absent")?
        .retain(|r| !peers.iter().any(|p| p.row == *r));
    Ok(view)
}
pub(in crate::fleet) fn peer_view(f: &Value) -> Result<Value> {
    project(f, &accepted(f)?)
}
pub(in crate::fleet) fn peer_guards(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
) -> Result<BTreeMap<String, BoundFile>> {
    let names = peer_names(f)?;
    Ok(bounds
        .iter()
        .filter(|(n, _)| !names.contains(*n))
        .map(|(n, b)| (n.clone(), b.clone()))
        .collect())
}
fn source(p: &Peer) -> Result<()> {
    let state = fs::symlink_metadata(&p.spec.state_root)?;
    ensure!(
        p.spec.state_root.canonicalize()? == p.spec.state_root
            && state.is_dir()
            && state.uid() == 1000
            && state.mode() & 0o077 == 0,
        "completed peer metadata root custody changed"
    );
    if let Origin::Singleton207 {
        launch,
        native_input,
        terminal,
        cohort_publication,
    } = &p.spec.origin
    {
        singleton207::delivery::custody(launch, native_input, terminal, cohort_publication)?;
        let pair = read_local_archive(&p.spec.origin.root().join("output"), 207)?;
        singleton207::delivery::cohort(&read(cohort_publication)?, &pair)?;
        ensure!(
            p.admission["archive"] == singleton209_delivery::pair_identity(&pair),
            "207 completed peer source changed"
        );
        return Ok(());
    }
    let Origin::Singleton209 {
        launch,
        native_input,
        cohort_publication,
    } = &p.spec.origin
    else {
        bail!("unsupported completed peer origin")
    };
    let (_, original) = full209_status::claim(launch)?;
    ensure!(
        original["native_input"] == private157::binding(native_input)
            && read(native_input)?["native_input_qualified"] == true,
        "completed peer native provenance changed"
    );
    singleton209_delivery::source_terminal(&original)?;
    capped204205_work::empty_terminal_cgroup(singleton209::UNIT)?;
    inactive_status::no_pending_owner_trigger(singleton209::UNIT, false)?;
    let pair = read_local_archive(&Path::new(singleton209::ROOT).join("output"), p.spec.epoch)?;
    singleton209_delivery::cohort(&read(cohort_publication)?, &pair)?;
    ensure!(
        p.admission["archive"] == singleton209_delivery::pair_identity(&pair),
        "completed peer admitted source pair changed"
    );
    Ok(())
}
fn current(p: &Peer, census: &BTreeMap<String, Value>) -> Result<(Value, Value)> {
    let name = &p.spec.units[p.spec.phase.name()];
    let owner = census
        .get(name)
        .context("completed peer actual owner omitted")?;
    ensure!(
        census.contains_key(&p.spec.guard_units[p.spec.phase.name()]),
        "completed peer guard omitted from complete census"
    );
    owner_matches(p, owner)?;
    owner_matches(p, &unit(name)?)?;
    let argv: Vec<String> = serde_json::from_value(p.launch["argv"].clone())?;
    let effective = check_unit(&p.spec, &argv)?;
    let process = launch::process(&p.spec, owner, &argv)?;
    ensure!(
        process["start_ticks"] == p.launch["process"]["start_ticks"]
            && process["native_start_clock"] == p.launch["process"]["native_start_clock"],
        "completed peer process PID was reused or replaced"
    );
    source(p)?;
    Ok((effective, process))
}
pub(in crate::fleet) fn peer_current(
    f: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let mut view = census.clone();
    for p in accepted(f)? {
        current(&p, census)?;
        // A timer guard can be inactive between successful firings. Only its
        // authenticated auxiliary name leaves the generic live-owner race check.
        view.remove(&p.spec.guard_units[p.spec.phase.name()]);
    }
    Ok(view)
}
fn guard(
    p: &Peer,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    minimum: u64,
    now: u64,
) -> Result<Value> {
    let name = &p.spec.units[p.spec.phase.name()];
    let bound = bounds
        .get(name)
        .context("completed peer protective sample omitted")?;
    let plan = read(&serde_json::from_value(p.launch["guard_plan"].clone())?)?;
    let sample = launch::read_sample(bound, &plan)?;
    ensure!(
        sample["plan_sha256"] == p.launch["guard_plan"]["sha256"]
            && sample["plan"] == p.launch["guard_plan"]["path"],
        "completed peer latest guard plan changed"
    );
    launch::current_guard_shape(
        &p.spec,
        &p.admission,
        &plan,
        &sample,
        census
            .get(name)
            .context("completed peer protected owner absent")?,
        minimum,
        now,
    )?;
    let completions = warmup223::completed_guard_successor(
        &p.spec.guard_units[p.spec.phase.name()],
        Path::new(string(&plan, "receipt_directory")?),
        bound,
        minimum,
        now,
    )?;
    ensure!(
        completions["supplied"]["binding"] == private157::binding(bound),
        "completed peer supplied guard is not a genuine completed firing"
    );
    let latest_binding: BoundFile =
        serde_json::from_value(completions["latest"]["binding"].clone())?;
    let latest_sample = launch::read_sample(&latest_binding, &plan)?;
    ensure!(
        latest_sample["plan_sha256"] == p.launch["guard_plan"]["sha256"]
            && latest_sample["plan"] == p.launch["guard_plan"]["path"],
        "completed peer successor guard plan changed"
    );
    launch::current_guard_shape(
        &p.spec,
        &p.admission,
        &plan,
        &latest_sample,
        census
            .get(name)
            .context("completed peer protected owner absent after guard successor")?,
        minimum,
        now,
    )?;
    ensure!(
        completions["supplied"]["receipt"] == sample
            && completions["latest"]["receipt"] == latest_sample
            && completions["supplied"]["history"]["executable"]
                == serde_json::to_value(&p.spec.programs["guard"].artifact.path)?
            && completions["latest"]["history"]["executable"]
                == serde_json::to_value(&p.spec.programs["guard"].artifact.path)?,
        "completed peer guard history, receipt, or immutable executable changed"
    );
    let completed = &completions["latest"];
    let props = empty_properties::properties(
        &p.spec,
        true,
        "MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ExecStart,ReadWritePaths,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges,Restart,KillMode,Delegate,Type,User,DropInPaths,NeedDaemonReload,Transient,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment",
    )?;
    validate_guard_controls(&props)?;
    singleton227_capture::require(
        &props,
        &[
            ("MemoryMax", "1073741824"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "256"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("Type", "oneshot"),
            ("User", "root"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
        ],
    )?;
    ensure!(
        props["ReadWritePaths"] == string(&plan, "receipt_directory")?
            && pipeline_status::same_exec_start(
                &props["ExecStart"],
                string(&completed["history"], "expected_exec_start")?
            )
            && completed["history"]["executable"]
                == serde_json::to_value(&p.spec.programs["guard"].artifact.path)?,
        "completed peer installed guard namespace or command changed"
    );
    let timer = barrier::guard_timer_properties(&p.spec.guard_units[p.spec.phase.name()])?;
    validate_guard_timer(&timer, &p.spec.guard_units[p.spec.phase.name()])?;
    Ok(
        json!({"binding":bound,"sample":sample,"supplied_completed":completions["supplied"],
            "latest_binding":latest_binding,"latest_sample":latest_sample,"completed":completed,
            "properties":props,"timer":timer}),
    )
}
fn sample_seconds(f: &Value) -> Result<u64> {
    utc_seconds(string(f, "sampled_at_utc")?)
}
/// Authenticate a captured child before its first fleet registration. Reuses
/// exactly the live native/source and installed protective-control validators.
pub(super) fn captured_live(claim: &PipelineClaim) -> Result<Value> {
    let (binding, launch, spec, admission) = claim_launch(claim)?;
    let p = Peer {
        spec,
        binding,
        launch,
        admission,
        row: Value::Null,
        claim: serde_json::to_value(claim)?,
    };
    let names = BTreeSet::from([
        claim.unit.clone(),
        p.spec.guard_units[p.spec.phase.name()].clone(),
    ]);
    // The caller separately brackets the complete campaign census. This local
    // proof must not run global discovery with only the new child's two names.
    let census = names
        .iter()
        .map(|name| Ok((name.clone(), unit(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let (effective, process) = current(&p, &census)?;
    let plan = read(&serde_json::from_value(p.launch["guard_plan"].clone())?)?;
    let minimum = number(&p.admission, "recorded_unix_seconds")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let selected = warmup223::completed_guard_binding(
        &p.spec.guard_units[p.spec.phase.name()],
        Path::new(string(&plan, "receipt_directory")?),
        minimum,
        now,
    )?;
    let bound: BoundFile = serde_json::from_value(selected["binding"].clone())?;
    let protection = guard(
        &p,
        &BTreeMap::from([(claim.unit.clone(), bound)]),
        &census,
        minimum,
        now,
    )?;
    Ok(
        json!({"owner":census[&claim.unit],"effective_unit":effective,"process":process,"protection":protection}),
    )
}
pub(in crate::fleet) fn peer_limits(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    let mut limits = serde_json::Map::new();
    for p in accepted(f)? {
        let (effective, _) = current(&p, census)?;
        let protection = guard(&p, bounds, census, sample_seconds(f)?, now)?;
        limits.insert(
            p.spec.units[p.spec.phase.name()].clone(),
            json!({"producer":effective,"guard":protection["properties"]}),
        );
    }
    Ok(json!(limits))
}
fn resource_evidence(p: &Peer, current: &Value, protection: Value) -> Result<(Value, Value, u64)> {
    let cap = p.spec.phase.profile().1;
    let charge = string(current, "native_memory_current")?.parse::<u64>()?;
    ensure!(charge <= cap, "completed peer exceeded native memory cap");
    let growth = cap
        .checked_add(2 << 30)
        .context("completed peer guard/issuer memory overflow")?;
    Ok((
        json!({"epoch":p.spec.epoch,"unit":p.spec.units[p.spec.phase.name()],"invocation_id":p.launch["invocation_id"],
        "launch":p.binding,"remaining_growth_bytes":METADATA,"allocation_credit_bytes":0,"protection":protection}),
        json!({"epoch":p.spec.epoch,"unit":p.spec.units[p.spec.phase.name()],"invocation_id":p.launch["invocation_id"],
            "hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,"guard_hard_memory_reserved_bytes":1u64<<30,
            "metadata_issuer_hard_memory_reserved_bytes":1u64<<30,"cache_or_resident_memory_credit_bytes":0,
            "remaining_hard_memory_growth_bytes":growth,"launch":p.binding,
            "accounting":"full admitted phase MemoryMax plus independent guard and bounded metadata issuer hard maxima once; no cgroup, cache, RSS or allocation credit"}),
        growth,
    ))
}
pub(in crate::fleet) fn peer_resources(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<(u64, Vec<Value>, u64, Vec<Value>)> {
    let (mut disk, mut memory, mut de, mut me) = (0u64, 0u64, Vec::new(), Vec::new());
    for p in accepted(f)? {
        let (_, process) = current(&p, census)?;
        let protection = guard(&p, bounds, census, sample_seconds(f)?, now)?;
        let (d, m, growth) = resource_evidence(&p, &process, protection)?;
        disk = disk
            .checked_add(METADATA)
            .context("completed peer disk overflow")?;
        memory = memory
            .checked_add(growth)
            .context("completed peer memory overflow")?;
        de.push(d);
        me.push(m);
    }
    Ok((disk, de, memory, me))
}
fn host_shape(p: &Peer, o: &Value) -> Result<Value> {
    let at = utc_seconds(string(o, "recorded_at_utc")?)?;
    let started = number(
        &p.launch["process"]["native_start_clock"],
        "started_unix_seconds",
    )?;
    let captured = number(&p.launch, "captured_unix_seconds")?;
    ensure!(
        started <= captured,
        "completed peer native process clock postdates capture"
    );
    let post_sample = started > at;
    ensure!(
        post_sample || captured <= at || p.launch.get("capture_recovery").is_some(),
        "completed peer pre-sample owner lacks contemporaneous launch evidence"
    );
    let mut observations = Vec::new();
    for phase in ["before", "after"] {
        let host = &o["host_resident_memory"][phase];
        ensure!(
            host["status"] == "observed"
                && host["rss"]["census_stable"] == true
                && host["rss"]["error"].is_null(),
            "completed peer whole host RSS unavailable or unstable"
        );
        let found = host["rss"]["processes"]
            .as_array()
            .context("completed peer host processes absent")?
            .iter()
            .filter(|r| r["pid"] == p.launch["process"]["pid"])
            .collect::<Vec<_>>();
        if post_sample {
            ensure!(
                found
                    .iter()
                    .all(|r| r["start_ticks"] != p.launch["process"]["start_ticks"]),
                "completed peer post-sample claim appears in the earlier host window"
            );
            continue;
        }
        ensure!(
            found.len() == 1
                && found[0]["start_ticks"] == p.launch["process"]["start_ticks"]
                && found[0]["rss_bytes"].as_u64().is_some_and(|n| n > 0),
            "completed peer missing or PID reused in coordinated host RSS"
        );
        observations.push((*found[0]).clone());
    }
    // No worker-shaped surrogate is accepted. Whole-host RSS already includes
    // this actual process and descendants; its hard growth is charged elsewhere.
    for r in o["replays"]
        .as_array()
        .context("completed peer ordinary observations absent")?
    {
        reject_replay_alias(p, r)?;
    }
    for r in o["diagnostic_replays"]
        .as_array()
        .context("completed peer diagnostics absent")?
    {
        ensure!(
            r["producer_unit"] != p.spec.units[p.spec.phase.name()]
                && r["controller_unit"] != p.spec.units[p.spec.phase.name()],
            "completed peer must use actual whole host RSS, not a replay diagnostic"
        );
        if r["status"] == "observed" {
            reject_replay_alias(p, &r["observation"])?;
        }
    }
    Ok(
        json!({"unit":p.spec.units[p.spec.phase.name()],"invocation_id":p.launch["invocation_id"],"launch":p.binding,
        "phase":p.spec.phase,"sampled_at_utc":o["recorded_at_utc"],"host_processes":observations,
        "post_sample_initial_event":post_sample,"native_process_started_unix_seconds":started,
        "full_hard_memory_reserved_bytes":p.spec.phase.profile().1+(2u64<<30),"full_disk_growth_reserved_bytes":METADATA,
        "included_in_whole_host_resident_memory":!post_sample,"executing_entry_replay":false,
        "fabricated_worker_rss":false,"disk_or_hard_memory_growth_exempted":false}),
    )
}
// The caller first authenticates the scoped saved capture through claim_launch.
pub(super) fn capture_observer(claim: &PipelineClaim, o: &Value) -> Result<Value> {
    let (binding, launch, spec, admission) = claim_launch(claim)?;
    let p = Peer {
        binding,
        launch,
        spec,
        admission,
        row: Value::Null,
        claim: serde_json::to_value(claim)?,
    };
    host_shape(&p, o)
}
fn reject_replay_alias(p: &Peer, r: &Value) -> Result<()> {
    for role in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            r[role]["unit"] != p.spec.units[p.spec.phase.name()]
                && r[role]["rss"]["processes"]
                    .as_array()
                    .is_none_or(|rows| rows.iter().all(|r| r["pid"] != p.launch["process"]["pid"])),
            "completed peer RSS was attributed to an executing replay"
        );
    }
    Ok(())
}
pub(in crate::fleet) fn peer_observation(f: &Value, o: &Value) -> Result<()> {
    let peers = accepted(f)?;
    if peers.is_empty() {
        return Ok(());
    }
    ensure!(
        f["sampled_at_utc"] == o["recorded_at_utc"],
        "completed peer observer clock differs"
    );
    for p in peers {
        observation(&p, f, o)?;
    }
    Ok(())
}
pub(in crate::fleet) fn peer_window_names(f: &Value, o: &Value) -> Result<BTreeSet<String>> {
    // These are delivery overhead, never a surrogate stable replay window.
    // Earlier owners need both actual host RSS brackets; positive post-sample
    // starts need current native/guard proof and receive no sampled RSS credit.
    peer_observation(f, o)?;
    peer_names(f)
}
pub(in crate::fleet) fn peer_memory_views(
    f: &Value,
    o: &Value,
) -> Result<(Value, Value, BTreeMap<String, Value>)> {
    peer_observation(f, o)?;
    let peers = accepted(f)?;
    let mut owners = BTreeMap::new();
    for p in &peers {
        ensure!(
            owners
                .insert(
                    p.spec.units[p.spec.phase.name()].clone(),
                    observation(p, f, o)?
                )
                .is_none(),
            "completed peer memory owner duplicated"
        );
    }
    Ok((project(f, &peers)?, o.clone(), owners))
}
fn observation(p: &Peer, f: &Value, o: &Value) -> Result<Value> {
    let mut proof = host_shape(p, o)?;
    if proof["post_sample_initial_event"] == true {
        let census: BTreeMap<String, Value> = serde_json::from_value(f["unit_census"].clone())?;
        let (_, process) = current(p, &census)?;
        let plan = read(&serde_json::from_value(p.launch["guard_plan"].clone())?)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let minimum = utc_seconds(string(o, "recorded_at_utc")?)?;
        let completed = warmup223::completed_guard_binding(
            &p.spec.guard_units[p.spec.phase.name()],
            Path::new(string(&plan, "receipt_directory")?),
            minimum,
            now,
        )?;
        let bound: BoundFile = serde_json::from_value(completed["binding"].clone())?;
        let bounds = BTreeMap::from([(p.spec.units[p.spec.phase.name()].clone(), bound)]);
        proof["current_protection"] = guard(p, &bounds, &census, minimum, now)?;
        proof["actual_current_process"] = process;
        proof["full_hard_memory_reserved_bytes"] = json!(p.spec.phase.profile().1 + (2u64 << 30));
        proof["earlier_host_rss_presence_claimed"] = json!(false);
    }
    Ok(proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fleet_rollover_scope_accepts_exact_207_and_209_claims_and_rejects_unvalidated_names() {
        let claim = |epoch: u64, phase: &str, unit: &str| PipelineClaim {
            epoch,
            phase: phase.into(),
            unit: unit.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: "sealed command".into(),
            evidence: Vec::new(),
        };
        assert!(fleet_rollover_scope(&claim(
            207,
            "full-verification",
            "horizon-qualify-207-generic-full-v1.service"
        )));
        assert!(fleet_rollover_scope(&claim(
            209,
            "plugin-verification",
            "horizon-qualify-209-generic-plugin-v1.service"
        )));
        for foreign in [
            claim(
                208,
                "full-verification",
                "horizon-qualify-208-generic-full-v1.service",
            ),
            claim(
                207,
                "full-verification",
                "horizon-qualify-209-generic-full-v1.service",
            ),
            claim(207, "replay", "horizon-qualify-207-generic-full-v1.service"),
            claim(
                207,
                "full-verification",
                "horizon-qualify-207-generic-full.service",
            ),
            claim(
                207,
                "full-verification",
                "foreign-qualify-207-generic-full-v1.service",
            ),
        ] {
            assert!(!fleet_rollover_scope(&foreign), "{}", foreign.unit);
        }
        // Production immediately calls claim_launch after this routing gate;
        // this predicate alone never authenticates an endpoint.
    }
    fn rollover_fixture() -> (
        BTreeMap<String, Value>,
        BTreeMap<String, Value>,
        BTreeMap<String, Value>,
        BTreeMap<String, Value>,
    ) {
        let owner = "horizon-qualify-209-generic-plugin-v12.service";
        let guard = "horizon-generic209-plugin-protective-v12.service";
        let before_iid = "a".repeat(32);
        let after_iid = "b".repeat(32);
        let command = |start: &str, pid: u64| {
            format!(
                "{{ path=/sealed/guard ; argv[]=/sealed/guard /sealed/plan --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[{start}] ; stop_time=[{start}] ; pid={pid} ; code=exited ; status=0/0 }}",
                "c".repeat(64),
                "d".repeat(64)
            )
        };
        let owner_row = json!({"Id":owner,"LoadState":"loaded","Type":"exec","ActiveState":"active",
            "SubState":"running","InvocationID":"e".repeat(32),"MainPID":"42","ControlGroup":format!("/system.slice/{owner}"),
            "NRestarts":"0","Result":"success","ExecMainStatus":"0","ExecStart":"owner command"});
        let guard_row = |iid: &str, start: &str, pid: u64| {
            json!({"Id":guard,"LoadState":"loaded","Type":"oneshot",
            "ActiveState":"inactive","SubState":"dead","InvocationID":iid,"MainPID":"0","ControlGroup":"",
            "NRestarts":"0","Result":"success","ExecMainStatus":"0","ExecStart":command(start,pid)})
        };
        let endpoint = |iid: &str, raw: Value, recorded: u64| {
            json!({
                "schema":"jetstreamer-completed-archive-nonlaunching-guard-endpoint-v1",
                "epoch":209,"phase":"plugin",
                "protected_unit":owner,"guard_unit":guard,
                "claim":{"epoch":209,"phase":"plugin-verification","unit":owner,
                    "invocation_id":"e".repeat(32),"expected_exec_start":"owner command",
                    "evidence":[{"path":"/sealed/launch.json","sha256":"f".repeat(64)}]},
                "authenticated_launch":{"path":"/sealed/launch.json","sha256":"f".repeat(64)},
                "phase_spec":{"path":"/sealed/spec.json","sha256":"1".repeat(64)},
                "guard_plan":{"path":"/sealed/plan.json","sha256":"c".repeat(64)},
                "guard_executable":{"path":"/sealed/guard","sha256":"d".repeat(64)},
                "raw_owner":owner_row,"raw_guard":raw,
                "protection":{"sample":{"guard_invocation_id":iid,"recorded_unix_seconds":recorded},
                    "latest_sample":{"guard_invocation_id":iid,"recorded_unix_seconds":recorded},
                    "completed":{"history":{"guard_invocation_id":iid,"expected_exec_start":command("n/a",0)}},
                    "properties":{"ExecStart":"immutable exact guard command","ExecStop":""}},
                "no_stop_files_confirmed":true,
                "pending_jobs":{"units":[owner,guard],"raw_stdout":"","exit_code":0}
            })
        };
        let raw_before = guard_row(&before_iid, "before", 101);
        let raw_after = guard_row(&after_iid, "after", 202);
        let before = BTreeMap::from([
            (owner.into(), owner_row.clone()),
            (guard.into(), raw_before.clone()),
        ]);
        let after = BTreeMap::from([
            (owner.into(), owner_row.clone()),
            (guard.into(), raw_after.clone()),
        ]);
        let before_endpoints =
            BTreeMap::from([(guard.into(), endpoint(&before_iid, raw_before, 100))]);
        let after_endpoints =
            BTreeMap::from([(guard.into(), endpoint(&after_iid, raw_after, 130))]);
        (before, after, before_endpoints, after_endpoints)
    }
    fn fixture(phase: Phase) -> (Peer, PipelineClaim, Value, Value) {
        let spec = super::super::tests::fixture(phase);
        let name = &spec.units[phase.name()];
        let guard = &spec.guard_units[phase.name()];
        let iid = "b".repeat(32);
        let command = "{ path=/sealed/tool ; argv[]=/sealed/tool 209 ; ignore_errors=no }";
        let owner = json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":"42","NRestarts":"0",
            "ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{name}"),"ExecStart":command});
        let binding = BoundFile {
            path: "/sealed/actual-launch.json".into(),
            sha256: "a".repeat(64),
        };
        let claim = PipelineClaim {
            epoch: 209,
            phase: match phase {
                Phase::Full => "full-verification",
                Phase::Plugin => "plugin-verification",
                Phase::Upload => "upload-readback",
            }
            .into(),
            unit: name.clone(),
            invocation_id: iid.clone(),
            expected_exec_start: command.into(),
            evidence: vec![binding.clone()],
        };
        let row = json!({"epoch":209,"phase":claim.phase,"live":true,"unit":owner,"ordinary_replay_claim":false,
            "expected_invocation_id":iid,"evidence":claim.evidence});
        let fleet = json!({"sampled_at_utc":"1970-01-01T00:16:40Z","unit_census":{name:owner,guard:{"MainPID":"0"}},"active":[row]});
        let process =
            json!({"pid":42,"start_ticks":123,"native_start_clock":{"started_unix_seconds":901}});
        let launch = json!({"owner":owner,"effective_unit":{"ExecStart":command},"invocation_id":iid,"process":process,"captured_unix_seconds":920});
        let peer = Peer {
            spec,
            binding,
            launch,
            admission: json!({}),
            row,
            claim: serde_json::to_value(&claim).unwrap(),
        };
        let process = json!({"pid":42,"start_ticks":123,"rss_bytes":4096});
        let host = json!({"status":"observed","rss":{"census_stable":true,"error":null,"processes":[process]}});
        let observer = json!({"recorded_at_utc":"1970-01-01T00:16:40Z","host_resident_memory":{"before":host,"after":host},"replays":[],"diagnostic_replays":[]});
        (peer, claim, fleet, observer)
    }
    #[test]
    fn completed_peer_absent_keeps_legacy_observer_and_unknown_owner_policy_unchanged() {
        let fleet = json!({"active":[{"epoch":205,"unit":{"Id":"legacy205.service"}}],"unit_census":{"legacy205.service":{"Id":"legacy205.service"}}});
        let observer = json!({"recorded_at_utc":"2026-10-25T23:28:00Z"});
        peer_observation(&fleet, &observer).unwrap();
        let (view, sample, owners) = peer_memory_views(&fleet, &observer).unwrap();
        assert_eq!(view, fleet);
        assert_eq!(sample, observer);
        assert!(owners.is_empty());
    }
    #[test]
    fn completed209_periodic_guard_rollover_accepts_only_authenticated_terminal_success_iids() {
        let (before, after, before_endpoints, after_endpoints) = rollover_fixture();
        let proof =
            authenticated_guard_rollovers(&before, &after, &before_endpoints, &after_endpoints)
                .unwrap();
        assert_eq!(proof.len(), 1);
        let guard = proof[0]["guard_unit"].as_str().unwrap();
        assert_eq!(proof[0]["raw_before"], before[guard]);
        assert_eq!(proof[0]["raw_after"], after[guard]);
        assert_eq!(proof[0]["producer_unchanged"], true);
        assert_eq!(proof[0]["nonlaunching_guard_only"], true);
    }
    #[test]
    fn maintenance_three_brackets_accept_authenticated_auxiliary_turnover_only() {
        let (before, after, before_endpoints, after_endpoints) = rollover_fixture();
        let owner = "horizon-qualify-209-generic-plugin-v12.service";
        assert_eq!(before[owner], after[owner]);
        let brackets = authenticated_guard_rollover_brackets(
            &before,
            &after,
            &after,
            &before_endpoints,
            &after_endpoints,
            &after_endpoints,
        )
        .unwrap();
        assert_eq!(brackets["before_after"].as_array().unwrap().len(), 1);
        assert_eq!(brackets["before_final"].as_array().unwrap().len(), 1);
        assert_eq!(brackets["raw_endpoint_censuses_preserved"], true);
        let mut changed = after.clone();
        changed.get_mut(owner).unwrap()["MainPID"] = json!("99");
        assert!(
            authenticated_guard_rollover_brackets(
                &before,
                &after,
                &changed,
                &before_endpoints,
                &after_endpoints,
                &after_endpoints,
            )
            .is_err()
        );
    }
    #[test]
    fn completed209_guard_rollover_rejects_producer_failure_stop_restart_and_pending_jobs() {
        let (before, after, before_endpoints, after_endpoints) = rollover_fixture();
        let guard = "horizon-generic209-plugin-protective-v12.service";
        let owner = "horizon-qualify-209-generic-plugin-v12.service";
        let mut bad = after.clone();
        bad.get_mut(owner).unwrap()["InvocationID"] = json!("0".repeat(32));
        assert!(
            authenticated_guard_rollovers(&before, &bad, &before_endpoints, &after_endpoints)
                .is_err()
        );
        for (field, value) in [
            ("Result", json!("exit-code")),
            ("ActiveState", json!("deactivating")),
            ("SubState", json!("stop")),
            ("NRestarts", json!("1")),
            ("ExecMainStatus", json!("1")),
        ] {
            let mut rows = after.clone();
            let mut endpoints = after_endpoints.clone();
            rows.get_mut(guard).unwrap()[field] = value.clone();
            endpoints.get_mut(guard).unwrap()["raw_guard"][field] = value;
            assert!(
                authenticated_guard_rollovers(&before, &rows, &before_endpoints, &endpoints)
                    .is_err(),
                "{field}"
            );
        }
        let mut endpoints = after_endpoints.clone();
        endpoints.get_mut(guard).unwrap()["pending_jobs"]["raw_stdout"] =
            json!(format!("88 {owner} stop running\n"));
        assert!(
            authenticated_guard_rollovers(&before, &after, &before_endpoints, &endpoints).is_err()
        );
        for pointer in [
            "/claim/invocation_id",
            "/authenticated_launch/sha256",
            "/phase_spec/sha256",
            "/guard_plan/sha256",
            "/guard_executable/sha256",
            "/protection/properties/ExecStart",
        ] {
            let mut endpoints = before_endpoints.clone();
            *endpoints
                .get_mut(guard)
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = json!("changed");
            assert!(
                authenticated_guard_rollovers(&before, &after, &endpoints, &after_endpoints)
                    .is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn completed209_guard_rollover_preserves_raw_censuses_and_rejects_suffix_exemptions() {
        let (before, mut after, before_endpoints, after_endpoints) = rollover_fixture();
        let before_saved = before.clone();
        let after_saved = after.clone();
        authenticated_guard_rollovers(&before, &after, &before_endpoints, &after_endpoints)
            .unwrap();
        assert_eq!(before, before_saved);
        assert_eq!(after, after_saved);
        let foreign = "horizon-generic209-plugin-protective-foreign.service";
        after.insert(
            foreign.into(),
            after["horizon-generic209-plugin-protective-v12.service"].clone(),
        );
        assert!(
            authenticated_guard_rollovers(&before, &after, &before_endpoints, &after_endpoints)
                .is_err()
        );
    }
    #[test]
    fn completed_peer_registered_row_binds_launch_claim_and_complete_census() {
        let (p, c, f, _) = fixture(Phase::Full);
        row_shape(&p, &c, &f).unwrap();
        for (field, value) in [
            ("phase", json!("replay")),
            ("live", json!(false)),
            ("expected_invocation_id", json!("c".repeat(32))),
            ("evidence", json!([])),
            ("ordinary_replay_claim", json!(true)),
        ] {
            let (mut p, c, f, _) = fixture(Phase::Full);
            p.row[field] = value;
            assert!(row_shape(&p, &c, &f).is_err(), "accepted {field}");
        }
        let mut changed = f.clone();
        changed["unit_census"][&c.unit]["MainPID"] = json!("99");
        assert!(row_shape(&p, &c, &changed).is_err());
        let mut changed = f;
        changed["unit_census"]
            .as_object_mut()
            .unwrap()
            .remove(&p.spec.guard_units["full"]);
        assert!(row_shape(&p, &c, &changed).is_err());
    }
    #[test]
    fn completed_peer_owner_rejects_changed_pid_iid_restart_and_exact_command() {
        let (p, _, _, _) = fixture(Phase::Plugin);
        let good = p.launch["owner"].clone();
        owner_matches(&p, &good).unwrap();
        for (key, value) in [
            ("MainPID", "99"),
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("ActiveState", "inactive"),
            ("ControlGroup", "/foreign"),
            ("ExecStart", "foreign"),
        ] {
            let mut changed = good.clone();
            changed[key] = json!(value);
            assert!(owner_matches(&p, &changed).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn completed_peer_both_brackets_reserve_all_three_full_caps_guard_issuer_and_disk_once() {
        for phase in [Phase::Full, Phase::Plugin, Phase::Upload] {
            let (p, _, _, _) = fixture(phase);
            let cap = phase.profile().1;
            for charge in [0, cap / 2, cap] {
                let process = json!({"native_memory_current":charge.to_string()});
                let (disk, memory, total) =
                    resource_evidence(&p, &process, json!({"latest_guard":true})).unwrap();
                assert_eq!(disk["remaining_growth_bytes"], METADATA);
                assert_eq!(disk["allocation_credit_bytes"], 0);
                assert_eq!(memory["hard_memory_cap_bytes"], cap);
                assert_eq!(memory["guard_hard_memory_reserved_bytes"], 1u64 << 30);
                assert_eq!(
                    memory["metadata_issuer_hard_memory_reserved_bytes"],
                    1u64 << 30
                );
                assert_eq!(memory["cache_or_resident_memory_credit_bytes"], 0);
                assert_eq!(total, cap + (2u64 << 30));
                assert_eq!(memory["remaining_hard_memory_growth_bytes"], total);
            }
            assert!(
                resource_evidence(
                    &p,
                    &json!({"native_memory_current":(cap+1).to_string()}),
                    Value::Null
                )
                .is_err()
            );
        }
    }
    #[test]
    fn completed_peer_projection_preserves_unrelated_unproved_rows_and_raw_census() {
        let (p, _, mut f, _) = fixture(Phase::Full);
        let unrelated = json!({"epoch":205,"unit":{"Id":"live205.service"}});
        let unknown =
            json!({"epoch":210,"unit":{"Id":"horizon-qualify-210-generic-full-foreign.service"}});
        f["active"]
            .as_array_mut()
            .unwrap()
            .extend([unrelated.clone(), unknown.clone()]);
        let original = f.clone();
        let projected = project(&f, &[p]).unwrap();
        assert_eq!(projected["active"], json!([unrelated, unknown]));
        assert_eq!(projected["unit_census"], original["unit_census"]);
        assert_eq!(f, original);
        assert!(peer_view(&original).is_err());
    }
    #[test]
    fn completed_peer_presample_owner_requires_both_real_host_pid_and_start_ticks() {
        let (p, _, _, good) = fixture(Phase::Full);
        let proof = host_shape(&p, &good).unwrap();
        assert_eq!(proof["post_sample_initial_event"], false);
        assert_eq!(proof["host_processes"].as_array().unwrap().len(), 2);
        for phase in ["before", "after"] {
            let mut bad = good.clone();
            bad["host_resident_memory"][phase]["rss"]["processes"] = json!([]);
            assert!(host_shape(&p, &bad).is_err());
            let mut bad = good.clone();
            bad["host_resident_memory"][phase]["rss"]["processes"][0]["start_ticks"] = json!(122);
            assert!(host_shape(&p, &bad).is_err());
            let mut bad = good.clone();
            bad["host_resident_memory"][phase]["rss"]["census_stable"] = json!(false);
            assert!(host_shape(&p, &bad).is_err());
        }
        let mut bad = good.clone();
        bad["replays"] = json!([{"producer_after":{"unit":p.spec.units["full"]}}]);
        assert!(host_shape(&p, &bad).is_err());
        let mut bad = good;
        bad["diagnostic_replays"] =
            json!([{"producer_unit":p.spec.units["full"],"status":"unavailable"}]);
        assert!(host_shape(&p, &bad).is_err());
    }
    #[test]
    fn completed209_recovered_presample_child_needs_both_actual_rss_brackets() {
        let (mut p, _, _, o) = fixture(Phase::Full);
        p.launch["captured_unix_seconds"] = json!(1100);
        assert!(host_shape(&p, &o).is_err());
        // Production reaches this branch only after claim_launch authenticates
        // the exact recovery pins and both old/new sealed binary attestations.
        p.launch["capture_recovery"] = json!({"authenticated_by_claim_launch":true});
        let proof = host_shape(&p, &o).unwrap();
        assert_eq!(proof["host_processes"].as_array().unwrap().len(), 2);
        assert_eq!(proof["post_sample_initial_event"], false);
        for phase in ["before", "after"] {
            let mut bad = o.clone();
            bad["host_resident_memory"][phase]["rss"]["processes"] = json!([]);
            assert!(host_shape(&p, &bad).is_err());
            let mut bad = o.clone();
            bad["host_resident_memory"][phase]["rss"]["processes"][0]["start_ticks"] = json!(999);
            assert!(host_shape(&p, &bad).is_err());
        }
    }
    #[test]
    fn completed_peer_positive_postsample_start_never_fabricates_earlier_rss_or_credit() {
        let (mut p, _, _, mut o) = fixture(Phase::Upload);
        p.launch["process"]["native_start_clock"]["started_unix_seconds"] = json!(1001);
        p.launch["captured_unix_seconds"] = json!(1002);
        for phase in ["before", "after"] {
            o["host_resident_memory"][phase]["rss"]["processes"] = json!([]);
        }
        let proof = host_shape(&p, &o).unwrap();
        assert_eq!(proof["post_sample_initial_event"], true);
        assert_eq!(proof["included_in_whole_host_resident_memory"], false);
        assert_eq!(proof["host_processes"], json!([]));
        assert_eq!(
            proof["full_hard_memory_reserved_bytes"],
            (16u64 << 30) + (2u64 << 30)
        );
        let mut bad = o.clone();
        bad["host_resident_memory"]["before"]["rss"]["processes"] =
            json!([{"pid":42,"start_ticks":123,"rss_bytes":4096}]);
        assert!(host_shape(&p, &bad).is_err());
        p.launch["process"]["native_start_clock"]["started_unix_seconds"] = json!(1000);
        assert!(host_shape(&p, &o).is_err());
        p.launch["process"]["native_start_clock"]["started_unix_seconds"] = json!(1003);
        assert!(host_shape(&p, &o).is_err());
    }
}
