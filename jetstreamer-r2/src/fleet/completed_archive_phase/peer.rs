//! Lossless typed resource peers for captured completed-archive delivery.
//! Raw fleet rows remain intact. Only a fully proved peer leaves legacy views.
use super::*;
struct Peer {
    spec: Spec,
    binding: BoundFile,
    launch: Value,
    admission: Value,
    row: Value,
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
fn claim_launch(claim: &PipelineClaim) -> Result<(BoundFile, Value, Spec, Value)> {
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
    let archive = Path::new(singleton209::ROOT).join("output");
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
            && admission["issuer_sha256"] == issuer
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
    let Origin::Singleton209 {
        launch,
        native_input,
        cohort_publication,
    } = &p.spec.origin;
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
    let completed = warmup223::completed_guard_binding(
        &p.spec.guard_units[p.spec.phase.name()],
        Path::new(string(&plan, "receipt_directory")?),
        minimum,
        now,
    )?;
    ensure!(
        completed["binding"] == private157::binding(bound),
        "completed peer guard is not the latest genuine completed firing"
    );
    let props = singleton227_capture::properties(
        &p.spec.guard_units[p.spec.phase.name()],
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
        json!({"binding":bound,"sample":sample,"completed":completed,"properties":props,"timer":timer}),
    )
}
fn sample_seconds(f: &Value) -> Result<u64> {
    utc_seconds(string(f, "sampled_at_utc")?)
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
        post_sample || captured <= at,
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
