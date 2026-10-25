//! Complete conservative accounting for a registered, guarded 204/205 owner.
//! Derived legacy views never alter the accepted fleet or claim zero resources.
use super::*;
struct Peer {
    claim: Claim,
    input: Inputs,
    row: Value,
}
fn selected(row: &Value) -> bool {
    row["phase"] == "capped204205-continuation"
        || row["phase"] == "capped204205-unresolved"
        || row["unit"]["Id"]
            .as_str()
            .is_some_and(|name| namespace(204, name) || namespace(205, name))
}
fn accepted(f: &Value) -> Result<Vec<Peer>> {
    let active = f["active"]
        .as_array()
        .context("capped peer active census")?;
    if !active.iter().any(selected) {
        return Ok(Vec::new());
    }
    let plan = bound_json(&BoundFile {
        path: string(f, "plan")?.into(),
        sha256: string(f, "plan_sha256")?.into(),
    })?;
    let claims: Vec<Claim> = serde_json::from_value(plan["capped204205_work"].clone())?;
    let mut epochs = BTreeSet::new();
    let mut result = Vec::new();
    for row in active.iter().filter(|row| selected(row)) {
        let epoch = number(row, "epoch")?;
        profile(epoch)?;
        ensure!(epochs.insert(epoch), "duplicate capped resource peer");
        let matches = claims
            .iter()
            .filter(|c| c.epoch == epoch)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "capped peer lacks one lossless accepted claim"
        );
        let claim: Claim = serde_json::from_value(serde_json::to_value(matches[0])?)?;
        let input = read_inputs(&claim)?;
        let observer = evidence::bound(
            &serde_json::from_value(input.frame["observer"].clone())?,
            false,
        )?;
        ensure!(
            input.frame["observer"]["path"] == f["observer_receipt"]
                && input.frame["observer"]["sha256"] == f["observer_sha256"],
            "capped peer has another coordinated observation"
        );
        let census = serde_json::from_value(f["unit_census"].clone())?;
        let evaluation = evaluate(
            &claim,
            &input,
            &observer,
            &census,
            number(f, "recorded_unix_seconds")?,
        )?;
        ensure!(
            evaluation.row == *row && row["live"] == true && row["ownership_unresolved"] != true,
            "capped peer is unresolved or differs from its authenticated frame"
        );
        // Downstream statuses remain supported, but cannot silently inherit the
        // producer's live guard or become a zero-growth resource exemption.
        ensure!(
            row["unit"]["Id"] == input.plan["producer_unit"],
            "capped downstream needs its separately qualified resource envelope before sibling admission"
        );
        result.push(Peer {
            claim,
            input,
            row: row.clone(),
        });
    }
    Ok(result)
}
pub(in crate::fleet) fn peer_names(f: &Value) -> Result<BTreeSet<String>> {
    accepted(f)?
        .iter()
        .map(|p| Ok(string(&p.input.plan, "producer_unit")?.into()))
        .collect()
}
fn observation_binding(
    p: &Value,
    l: &Value,
    registration: &Value,
    observer: &Value,
    manager_start: u64,
) -> Result<()> {
    let expected = capture::observer_registration(p, l)?;
    ensure!(
        registration["diagnostic_replay"] == expected
            && registration["next_sole_30_minute_observer_must_include_producer"] == true
            && registration["observer_config_modified"] == false,
        "capped peer has no exact next-observer registration proposal"
    );
    let name = string(p, "producer_unit")?;
    let rows = observer["diagnostic_replays"]
        .as_array()
        .context("capped peer diagnostic census missing")?
        .iter()
        .filter(|r| r["producer_unit"] == name)
        .collect::<Vec<_>>();
    let sample = utc_seconds(string(observer, "recorded_at_utc")?)?
        .checked_mul(1000)
        .context("capped sample clock overflow")?;
    if rows.is_empty() {
        ensure!(
            sample <= manager_start,
            "next sole observer omitted the launched capped producer"
        );
        return Ok(());
    }
    ensure!(rows.len() == 1, "duplicate capped observer registration");
    let row = rows[0];
    ensure!(
        row["range"] == expected["range"]
            && row["scratch_path"] == expected["scratch_path"]
            && row["expected_producer_invocation_id"] == l["invocation_id"]
            && row["ordinary_replay_claim"] == false,
        "capped coordinated diagnostic registration changed"
    );
    if row["status"] == "unavailable" {
        ensure!(
            row["observation"].is_null() && row["error"].as_str().is_some_and(|s| !s.is_empty()),
            "capped unavailable diagnostic lacks explicit failure evidence"
        );
        // Independent fresh guard and hard kernel limits remain mandatory. This
        // is registered telemetry failure, never a claim of measured RSS or inactivity.
        return Ok(());
    }
    let obs = &row["observation"];
    ensure!(
        row["status"] == "observed"
            && row["error"].is_null()
            && obs["invocation_binding_stable"] == true,
        "capped diagnostic observation invalid"
    );
    for phase in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            obs[phase]["unit"] == name
                && obs[phase]["invocation_id"] == l["invocation_id"]
                && obs[phase]["main_pid"] == l["main_pid"]
                && obs[phase]["restarts"] == 0
                && obs[phase]["active_state"] == "active"
                && obs[phase]["sub_state"] == "running",
            "capped successful diagnostic lost exact launched owner"
        );
    }
    Ok(())
}
pub(super) fn registration(claim: &Claim, input: &Inputs, observer: &Value) -> Result<()> {
    let frame = &input.frame;
    let registration = evidence::bound(
        &serde_json::from_value(frame["next_observer_registration"].clone())?,
        true,
    )?;
    ensure!(
        registration["schema"] == "jetstreamer-capped204205-next-observer-registration-v1"
            && registration["epoch"] == claim.epoch
            && registration["origin_launch"] == private157::binding(&claim.launch),
        "capped observer registration detached from actual launch"
    );
    let journal: BoundFile = serde_json::from_value(input.launch["manager_journal"].clone())?;
    let start = capture::manager_history(
        &evidence::bytes(&journal, true)?,
        string(&input.plan, "producer_unit")?,
        string(&input.launch, "invocation_id")?,
        false,
    )?;
    observation_binding(&input.plan, &input.launch, &registration, observer, start)
}
pub(in crate::fleet) fn peer_observation(f: &Value, observer: &Value) -> Result<()> {
    for peer in accepted(f)? {
        registration(&peer.claim, &peer.input, observer)?;
    }
    Ok(())
}
/// A workerless exemption is only for the exact typed Assembly owner. Its
/// authority comes from two accepted bound phase frames and the existing full
/// conservative admission, never from an unavailable diagnostic by itself.
pub(in crate::fleet) fn peer_clean_assembly_window(
    f: &Value,
    o: &Value,
) -> Result<BTreeSet<String>> {
    Ok(assembly_owners(f, o, true)?.into_keys().collect())
}
pub(in crate::fleet) fn peer_assembly_memory_owners(
    f: &Value,
    o: &Value,
) -> Result<BTreeMap<String, Value>> {
    assembly_owners(f, o, false)
}
fn assembly_owners(f: &Value, o: &Value, expanded: bool) -> Result<BTreeMap<String, Value>> {
    let peers = accepted(f)?;
    let mut names = BTreeMap::new();
    for peer in peers
        .iter()
        .filter(|p| p.row["current_stage"] == "assembly")
    {
        registration(&peer.claim, &peer.input, o)?;
        let end = utc_seconds(string(o, "recorded_at_utc")?)?
            .checked_mul(1000)
            .context("assembly window end overflow")?;
        let begin = if expanded {
            let elapsed = number(&o["host_global_pressure"]["cross_sample"], "elapsed_millis")?;
            ensure!(
                elapsed >= 1_800_000,
                "assembly needs the same clean coordinated host window"
            );
            end.checked_sub(elapsed)
                .context("assembly window starts before epoch")?
        } else {
            end
        };
        let previous_bound: BoundFile =
            serde_json::from_value(peer.input.frame["previous_fleet"].clone())?;
        let previous = bound_json(&previous_bound)?;
        ensure!(
            previous["schema"] == SCHEMA
                && previous["first_epoch"] == 201
                && previous["last_epoch"] == 300
                && previous["inventory"]["anomalies"] == 0,
            "assembly predecessor fleet is foreign or unresolved"
        );
        let prior = accepted(&previous)?;
        let matches = prior
            .iter()
            .filter(|p| p.claim.epoch == peer.claim.epoch)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "assembly has no unique earlier accepted owner frame"
        );
        let old = matches[0];
        ensure!(
            old.claim.launch == peer.claim.launch
                && old.claim.producer_plan == peer.claim.producer_plan
                && old.claim.admission == peer.claim.admission
                && old.row["current_stage"] == "assembly"
                && number(&old.input.frame, "sampled_unix_millis")?
                    <= number(&peer.input.frame, "sampled_unix_millis")?,
            "assembly predecessor changed owner/admission, phase, or time direction"
        );
        let old_guard = evidence::bound(
            &serde_json::from_value(old.input.frame["guard_snapshot"].clone())?,
            true,
        )?;
        let guard = evidence::bound(
            &serde_json::from_value(peer.input.frame["guard_snapshot"].clone())?,
            true,
        )?;
        if expanded {
            assembly_window(&old_guard, &guard, begin, end)?;
        } else {
            assembly_phase_pair(&old_guard, &guard, begin, end)?;
        }
        ensure!(
            number(&peer.input.frame, "sampled_unix_millis")? >= end,
            "assembly frame predates coordinated window end"
        );
        let name = string(&peer.input.plan, "producer_unit")?;
        let proof = json!({"schema":"jetstreamer-typed-capped-assembly-memory-owner-v1","epoch":peer.claim.epoch,
            "unit":name,"invocation_id":peer.input.launch["invocation_id"],"main_pid":guard["processes"]["main_pid"],
            "role":"assembly-non-replay","sampled_at_utc":o["recorded_at_utc"],"phase":guard["phase"],
            "window_begin_millis":begin,"window_end_millis":end,"expanded_clean_window":expanded,
            "frame":private157::binding(&peer.claim.frame),"launch":private157::binding(&peer.claim.launch),
            "admission":private157::binding(&peer.claim.admission),"producer_plan":private157::binding(&peer.claim.producer_plan),
            "guard_snapshot":peer.input.frame["guard_snapshot"],"previous_fleet":private157::binding(&previous_bound),
            "included_in_whole_host_resident_memory":true,"fabricated_worker_rss":false,
            "disk_or_hard_memory_growth_exempted":false,"admission_authorized":false});
        ensure!(
            names.insert(name.into(), proof).is_none(),
            "duplicate assembly window owner"
        );
    }
    Ok(names)
}
fn assembly_window(old: &Value, current: &Value, begin: u64, end: u64) -> Result<()> {
    ensure!(
        end.checked_sub(begin).is_some_and(|n| n >= 1_800_000),
        "assembly clean window is too short"
    );
    assembly_phase_pair(old, current, begin, end)
}
fn assembly_phase_pair(old: &Value, current: &Value, begin: u64, end: u64) -> Result<()> {
    ensure!(
        begin <= end
            && old["schema"] == "jetstreamer-capped204205-guard-heartbeat-v1"
            && current["schema"] == old["schema"]
            && current["epoch"] == old["epoch"]
            && current["plan_sha256"] == old["plan_sha256"]
            && current["producer_unit"] == old["producer_unit"]
            && current["producer_invocation_id"] == old["producer_invocation_id"]
            && current["guard_unit"] == old["guard_unit"]
            && current["guard_invocation_id"] == old["guard_invocation_id"]
            && current["processes"]["main_pid"] == old["processes"]["main_pid"]
            && current["phase"] == old["phase"]
            && current["phase"]["stage"] == "assembly"
            && number(&current["phase"], "started_unix_millis")? <= begin
            && number(old, "recorded_unix_millis")? <= number(current, "recorded_unix_millis")?
            && number(current, "recorded_unix_millis")? >= end
            && [old, current].iter().all(|g| g["processes"]["workers"]
                .as_array()
                .is_some_and(Vec::is_empty)
                && g["trip"] == false
                && g["producer_stop_enabled"] == true),
        "assembly clean window is missing, backward, foreign, short, stale, or contains a historical worker"
    );
    Ok(())
}

pub(in crate::fleet) fn peer_legacy_view(f: &Value) -> Result<Value> {
    let peers = accepted(f)?;
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("capped legacy view")?
        .retain(|r| !peers.iter().any(|p| p.row == *r));
    Ok(view)
}
pub(in crate::fleet) fn peer_legacy_guards(
    f: &Value,
    guards: &BTreeMap<String, BoundFile>,
) -> Result<BTreeMap<String, BoundFile>> {
    let names = peer_names(f)?;
    Ok(guards
        .iter()
        .filter(|(name, _)| !names.contains(*name))
        .map(|(n, b)| {
            (
                n.clone(),
                BoundFile {
                    path: b.path.clone(),
                    sha256: b.sha256.clone(),
                },
            )
        })
        .collect())
}
fn current_peer(peer: &Peer, current: &BTreeMap<String, Value>) -> Result<()> {
    let p = &peer.input.plan;
    let l = &peer.input.launch;
    let name = string(p, "producer_unit")?;
    let owner = current
        .get(name)
        .context("capped peer omitted from current census")?;
    ensure!(
        live(owner)
            && owner["InvocationID"] == l["invocation_id"]
            && owner["MainPID"] == peer.row["unit"]["MainPID"]
            && pipeline_status::same_exec_start(
                string(l, "expected_exec_start")?,
                string(owner, "ExecStart")?
            ),
        "capped peer changed actual owner or command"
    );
    let guard = current
        .get(string(p, "guard_unit")?)
        .context("capped peer guard omitted")?;
    ensure!(
        live(guard)
            && guard["InvocationID"] == l["guard_invocation_id"]
            && evidence::command_matches(
                &evidence::expected_guard_command(
                    p,
                    &peer.input.admission,
                    &peer.claim.producer_plan,
                    string(l, "invocation_id")?
                )?,
                string(guard, "ExecStart")?
            ),
        "capped peer guard changed identity or exact command"
    );
    Ok(())
}
pub(in crate::fleet) fn peer_current(
    f: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let peers = accepted(f)?;
    let mut view = current.clone();
    for p in &peers {
        current_peer(p, current)?;
        view.remove(string(&p.input.plan, "guard_unit")?);
    }
    // Only authenticated auxiliary guards are removed from the generic owner
    // race check. Producers stay present and must match the full active roster.
    Ok(view)
}
fn heartbeat(
    peer: &Peer,
    bounds: &BTreeMap<String, BoundFile>,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    current_peer(peer, current)?;
    let name = string(&peer.input.plan, "producer_unit")?;
    let b = bounds
        .get(name)
        .context("capped peer needs its current protective heartbeat")?;
    let g = evidence::bound(b, true)?;
    evidence::guard(
        &peer.input.plan,
        &peer.input.launch,
        &g,
        current,
        now.checked_mul(1000)
            .context("capped peer clock overflow")?,
    )?;
    if peer.row["current_stage"] == "assembly" {
        let accepted_guard = evidence::bound(
            &serde_json::from_value(peer.input.frame["guard_snapshot"].clone())?,
            true,
        )?;
        assembly_progress(&accepted_guard, &g)?;
    }
    ensure!(
        g["kernel_limits"] == peer.input.admission["kernel_limits"]
            && g["resource_proposal"] == peer.input.admission["resource_proposal"],
        "capped peer guard lost actual admitted limits"
    );
    Ok(g)
}
fn assembly_progress(previous: &Value, current: &Value) -> Result<()> {
    let old = &previous["phase"];
    let new = &current["phase"];
    ensure!(
        old["stage"] == "assembly"
            && matches!(new["stage"].as_str(), Some("assembly" | "complete"))
            && old["epoch"] == new["epoch"]
            && old["invocation_id"] == new["invocation_id"]
            && old["plan_sha256"] == new["plan_sha256"]
            && old["schema"] == new["schema"]
            && number(previous, "recorded_unix_millis")?
                <= number(current, "recorded_unix_millis")?
            && (new["stage"] == "complete"
                && number(new, "started_unix_millis")? >= number(old, "started_unix_millis")?
                || new == old)
            && current["processes"]["workers"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "capped assembly regressed, changed identity/clock, or regained a historical worker"
    );
    Ok(())
}
fn props(name: &str) -> Result<BTreeMap<String, String>> {
    singleton227_capture::properties(
        name,
        "Id,InvocationID,MainPID,NRestarts,ActiveState,SubState,ControlGroup,ExecStart,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,Environment,CPUAffinity",
    )
}
fn field(p: &BTreeMap<String, String>, key: &str) -> Result<u64> {
    p.get(key)
        .context("capped peer property missing")?
        .parse()
        .with_context(|| format!("capped peer integer property: {key}"))
}
fn duration(value: &str) -> Result<u64> {
    for (suffix, mul) in [
        ("us", 1u64),
        ("ms", 1000),
        ("min", 60_000_000),
        ("h", 3_600_000_000),
        ("s", 1_000_000),
    ] {
        if let Some(n) = value.strip_suffix(suffix) {
            let n: u64 = n.parse()?;
            return n.checked_mul(mul).context("capped peer duration overflow");
        }
    }
    bail!("unsupported finite capped peer systemd duration")
}
fn identity(properties: &BTreeMap<String, String>, unit: &Value) -> Result<()> {
    for key in [
        "Id",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "ControlGroup",
    ] {
        ensure!(
            properties.get(key).map(String::as_str) == unit[key].as_str(),
            "capped peer live property changed: {key}"
        );
    }
    ensure!(
        pipeline_status::same_exec_start(
            properties
                .get("ExecStart")
                .context("capped peer command missing")?,
            string(unit, "ExecStart")?
        ),
        "capped peer current command changed"
    );
    Ok(())
}
fn cgroup(properties: &BTreeMap<String, String>, unit: &str) -> Result<PathBuf> {
    let group = properties
        .get("ControlGroup")
        .context("capped peer cgroup")?;
    ensure!(
        *group == format!("/system.slice/{unit}"),
        "capped peer escaped cgroup"
    );
    Ok(Path::new("/sys/fs/cgroup").join(&group[1..]))
}
fn read(root: &Path, key: &str) -> Result<u64> {
    Ok(fs::read_to_string(root.join(key))?.trim().parse()?)
}
fn producer_limits(
    peer: &Peer,
    g: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<(Value, u64)> {
    let p = &peer.input.plan;
    let name = string(p, "producer_unit")?;
    let properties = props(name)?;
    identity(&properties, &current[name])?;
    let k = &peer.input.admission["kernel_limits"];
    if let Some(value) = k.get("thread_profile") {
        let profile: super::super::capped204205_thread_profile::ThreadProfile =
            serde_json::from_value(value.clone())?;
        profile.check_manager(&properties)?;
        ensure!(
            g["actual_kernel_limits"]["thread_profile"] == *value
                && g["processes"]["thread_profile"] == *value,
            "current guard lost exact thread profile"
        );
        profile.check_process(field(&properties, "MainPID")?.try_into()?)?;
        for worker in g["processes"]["workers"]
            .as_array()
            .context("thread profile worker census")?
        {
            profile.check_process(number(worker, "pid")?.try_into()?)?;
        }
    }
    let page = number(&g["actual_kernel_limits"], "host_page_size_bytes")?;
    ensure!(
        page >= 4096 && page.is_power_of_two(),
        "capped peer host page invalid"
    );
    for (key, expected) in [
        ("MemoryMax", "requested_memory_max_bytes"),
        ("MemoryHigh", "requested_memory_high_bytes"),
        ("MemorySwapMax", "memory_swap_max_bytes"),
        ("TasksMax", "tasks_max"),
    ] {
        ensure!(
            field(&properties, key)? == number(k, expected)?,
            "capped peer requested limit changed: {key}"
        );
    }
    for (key, expected) in [
        ("CPUQuotaPerSecUSec", "cpu_quota_usec_per_second"),
        ("RuntimeMaxUSec", "runtime_max_usec"),
    ] {
        ensure!(
            duration(
                properties
                    .get(key)
                    .context("capped peer duration missing")?
            )? == number(k, expected)?,
            "capped peer duration changed: {key}"
        );
    }
    let root = cgroup(&properties, name)?;
    let maximum = read(&root, "memory.max")?;
    let high = read(&root, "memory.high")?;
    ensure!(
        maximum == number(k, "requested_memory_max_bytes")? / page * page
            && high == number(k, "requested_memory_high_bytes")? / page * page
            && read(&root, "memory.swap.max")? == 0
            && read(&root, "pids.max")? == number(k, "tasks_max")?,
        "capped peer effective kernel limits changed"
    );
    let cpu = fs::read_to_string(root.join("cpu.max"))?;
    let words = cpu.split_whitespace().collect::<Vec<_>>();
    ensure!(words.len() == 2, "capped peer CPU shape");
    let quota: u64 = words[0].parse()?;
    let period: u64 = words[1].parse()?;
    ensure!(
        period > 0
            && u128::from(quota) * 1_000_000
                == u128::from(number(k, "cpu_quota_usec_per_second")?) * u128::from(period),
        "capped peer effective CPU quota changed"
    );
    let charge = read(&root, "memory.current")?;
    let remaining = maximum
        .checked_sub(charge)
        .context("capped peer exceeds memory cap")?;
    Ok((
        json!({"systemd_properties":properties,"kernel_memory_max_bytes":maximum,"kernel_memory_high_bytes":high,"memory_swap_max_bytes":0,"tasks_max":number(k,"tasks_max")?,"cpu_max":cpu.trim(),"host_page_size_bytes":page}),
        remaining,
    ))
}
fn guard_memory(peer: &Peer, current: &BTreeMap<String, Value>) -> Result<(Value, u64)> {
    let name = string(&peer.input.plan, "guard_unit")?;
    let properties = props(name)?;
    identity(&properties, &current[name])?;
    let expected = number(
        &peer.input.admission["capability_evidence"],
        "guard_memory_max_bytes",
    )?;
    ensure!(
        field(&properties, "MemoryMax")? == expected && field(&properties, "MemorySwapMax")? == 0,
        "capped independent guard memory limit changed"
    );
    let root = cgroup(&properties, name)?;
    let maximum = read(&root, "memory.max")?;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(
        page >= 4096
            && maximum == expected / (page as u64) * (page as u64)
            && read(&root, "memory.swap.max")? == 0,
        "capped guard effective cap changed"
    );
    let charge = read(&root, "memory.current")?;
    Ok((
        json!({"unit":name,"systemd_properties":properties,"hard_memory_cap_bytes":maximum,"current_cgroup_charge_bytes":charge}),
        maximum
            .checked_sub(charge)
            .context("capped guard exceeds memory cap")?,
    ))
}
pub(in crate::fleet) fn peer_limits(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for p in accepted(f)? {
        let g = heartbeat(&p, bounds, current, now)?;
        let (limits, _) = producer_limits(&p, &g, current)?;
        let (guard, _) = guard_memory(&p, current)?;
        result.insert(
            string(&p.input.plan, "producer_unit")?.into(),
            json!({"producer":limits,"guard":guard["systemd_properties"]}),
        );
    }
    Ok(json!(result))
}
pub(in crate::fleet) fn peer_memory(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let mut total = 0u64;
    let mut evidence = Vec::new();
    for p in accepted(f)? {
        let g = heartbeat(&p, bounds, current, now)?;
        let (_, producer) = producer_limits(&p, &g, current)?;
        let (guard, guard_remaining) = guard_memory(&p, current)?;
        let remaining = producer
            .checked_add(guard_remaining)
            .context("capped combined memory overflow")?;
        total = total
            .checked_add(remaining)
            .context("capped peer memory sum overflow")?;
        evidence.push(json!({"epoch":p.claim.epoch,"unit":p.input.plan["producer_unit"],"invocation_id":p.input.launch["invocation_id"],"guard":guard,"remaining_hard_memory_growth_bytes":remaining,"accounting":"producer and independent guard remaining memory.max minus memory.current; never RSS or a zero-growth claim"}));
    }
    Ok((total, evidence))
}
pub(in crate::fleet) fn peer_disk(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    current: &BTreeMap<String, Value>,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let mut total = 0u64;
    let mut evidence = Vec::new();
    for p in accepted(f)? {
        let g = heartbeat(&p, bounds, current, now)?;
        let growth = number(&p.input.plan, "candidate_incremental_peak_bytes")?;
        ensure!(
            growth >= number(&p.input.plan, "maximum_root_physical_bytes")?,
            "capped peer lacks complete disk envelope"
        );
        total = total
            .checked_add(growth)
            .context("capped peer disk sum overflow")?;
        evidence.push(json!({"epoch":p.claim.epoch,"unit":p.input.plan["producer_unit"],"invocation_id":p.input.launch["invocation_id"],"guard":private157::binding(bounds.get(string(&p.input.plan,"producer_unit")?).context("capped peer guard binding")?),"remaining_growth_bytes":growth,"scratch_growth_credit_bytes":0,"guard_observed_physical_bytes":g["root_physical_observation"]["conservative_physical_bytes"],"accounting":"complete admitted root and external metadata envelope; no credit from unsupported or reclaimable allocation telemetry"}));
    }
    Ok((total, evidence))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn current_peer_requires_independent_guard_exact_command_and_invocation() {
        let name = "horizon-qualify-205-capped-continuation-fixture.service";
        let guard_name = "horizon-guard-205-capped-continuation-fixture.service";
        let plan = json!({"epoch":205,"producer_unit":name,"guard_unit":guard_name,"guard_sha256":"b".repeat(64)});
        let admission = json!({"capability_evidence":{"control":{"path":"/sealed/control","sha256":"b".repeat(64)}}});
        let launch = json!({"invocation_id":"c".repeat(32),"guard_invocation_id":"d".repeat(32),"expected_exec_start":"{ path=/sealed/node ; argv[]=/sealed/node 205 ; ignore_errors=no }"});
        let claim = Claim {
            epoch: 205,
            producer_plan: BoundFile {
                path: "/sealed/plan.json".into(),
                sha256: "a".repeat(64),
            },
            admission: BoundFile {
                path: "/sealed/admission.json".into(),
                sha256: "a".repeat(64),
            },
            launch: BoundFile {
                path: "/sealed/launch.json".into(),
                sha256: "a".repeat(64),
            },
            frame: BoundFile {
                path: "/sealed/frame.json".into(),
                sha256: "a".repeat(64),
            },
            eta_policy: BoundFile {
                path: "/sealed/eta.json".into(),
                sha256: "a".repeat(64),
            },
        };
        let command = evidence::expected_guard_command(
            &plan,
            &admission,
            &claim.producer_plan,
            "cccccccccccccccccccccccccccccccc",
        )
        .unwrap();
        let unit = json!({"Id":name,"LoadState":"loaded","InvocationID":launch["invocation_id"],"MainPID":"42","NRestarts":"0","ActiveState":"active","SubState":"running","ExecStart":launch["expected_exec_start"]});
        let guard = json!({"Id":guard_name,"LoadState":"loaded","InvocationID":launch["guard_invocation_id"],"MainPID":"43","NRestarts":"0","ActiveState":"active","SubState":"running","ExecStart":format!("{command} ; ignore_errors=no }}")});
        let peer = Peer {
            claim,
            input: Inputs {
                plan,
                admission,
                launch,
                frame: json!({}),
                policy: json!({}),
            },
            row: json!({"unit":unit}),
        };
        let current = BTreeMap::from([(name.into(), unit), (guard_name.into(), guard)]);
        current_peer(&peer, &current).unwrap();
        for (field, value) in [
            ("InvocationID", json!("e".repeat(32))),
            ("ExecStart", json!("foreign command")),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("inactive")),
        ] {
            let mut changed = current.clone();
            changed.get_mut(guard_name).unwrap()[field] = value;
            assert!(current_peer(&peer, &changed).is_err(), "{field}");
        }
        let mut absent = current;
        absent.remove(guard_name);
        assert!(current_peer(&peer, &absent).is_err());
    }
    #[test]
    fn finite_systemd_durations_are_checked_and_not_unbounded() {
        for (raw, us) in [
            ("12us", 12),
            ("12ms", 12_000),
            ("2s", 2_000_000),
            ("2min", 120_000_000),
            ("1h", 3_600_000_000),
        ] {
            assert_eq!(duration(raw).unwrap(), us);
        }
        for raw in [
            "infinity",
            "max",
            "1h 2min",
            "1.5s",
            "18446744073709551615h",
        ] {
            assert!(duration(raw).is_err());
        }
    }
    #[test]
    fn next_poll_requires_registration_but_prelaunch_observer_is_only_context() {
        let p = json!({"epoch":205,"producer_unit":"horizon-qualify-205-capped-continuation-fixture.service","run_root":"/home/ubuntu/.jetstreamer-private/checkpoint-continuation-205-fixture"});
        let l = json!({"invocation_id":"a".repeat(32),"main_pid":42});
        let expected = capture::observer_registration(&p, &l).unwrap();
        let registration = json!({"diagnostic_replay":expected,"next_sole_30_minute_observer_must_include_producer":true,"observer_config_modified":false});
        let mut o = json!({"recorded_at_utc":"2026-10-24T10:00:00Z","diagnostic_replays":[]});
        let sample = utc_seconds("2026-10-24T10:00:00Z").unwrap() * 1000;
        observation_binding(&p, &l, &registration, &o, sample + 1).unwrap();
        assert!(observation_binding(&p, &l, &registration, &o, sample - 1).is_err());
        let row = json!({"range":expected["range"],"scratch_path":expected["scratch_path"],"producer_unit":p["producer_unit"],"expected_producer_invocation_id":l["invocation_id"],
            "ordinary_replay_claim":false,"status":"unavailable","observation":null,"error":"workerless prefix validation"});
        o["diagnostic_replays"] = json!([row]);
        observation_binding(&p, &l, &registration, &o, sample - 1).unwrap();
        let mut foreign = o.clone();
        foreign["diagnostic_replays"][0]["expected_producer_invocation_id"] = json!("b".repeat(32));
        assert!(observation_binding(&p, &l, &registration, &foreign, sample - 1).is_err());
        o["diagnostic_replays"].as_array_mut().unwrap().push(row);
        assert!(observation_binding(&p, &l, &registration, &o, sample - 1).is_err());
    }
    #[test]
    fn no_capped_owner_does_not_remove_or_modify_legacy_census() {
        let f = json!({"active":[],"unit_census":{"legacy.service":{"MainPID":"42"}},"failures":[{"epoch":213}]});
        assert_eq!(peer_legacy_view(&f).unwrap(), f);
        assert!(peer_names(&f).unwrap().is_empty());
        let guards = BTreeMap::new();
        assert!(peer_legacy_guards(&f, &guards).unwrap().is_empty());
        let current = BTreeMap::from([("legacy.service".into(), json!({"MainPID":"42"}))]);
        assert_eq!(peer_current(&f, &current).unwrap(), current);
        let mut unmodeled = f;
        unmodeled["active"] = json!([{"epoch":205,"phase":"capped204205-unresolved","unit":{"Id":"horizon-qualify-205-capped-continuation-unmodeled.service"}}]);
        assert!(peer_names(&unmodeled).is_err());
        assert!(peer_legacy_view(&unmodeled).is_err());
        assert!(peer_current(&unmodeled, &current).is_err());
    }
}

#[cfg(test)]
mod assembly_window_tests {
    use super::*;
    fn guard(at: u64) -> Value {
        json!({"schema":"jetstreamer-capped204205-guard-heartbeat-v1","epoch":204,
            "plan_sha256":"a".repeat(64),"producer_unit":"producer204.service","producer_invocation_id":"b".repeat(32),
            "guard_unit":"guard204.service","guard_invocation_id":"c".repeat(32),
            "recorded_unix_millis":at,"trip":false,"producer_stop_enabled":true,
            "phase":{"schema":"jetstreamer-capped204205-continuation-phase-v1","epoch":204,
                "plan_sha256":"a".repeat(64),"invocation_id":"b".repeat(32),"stage":"assembly","started_unix_millis":1000},
            "processes":{"main_pid":42,"workers":[]}})
    }
    #[test]
    fn only_same_authenticated_workerless_assembly_can_cover_a_complete_host_window() {
        let old = guard(1800);
        let current = guard(1_802_000);
        assembly_window(&old, &current, 2000, 1_802_000).unwrap();
        for (path, value) in [
            ("/phase", Value::Null),
            ("/phase/stage", json!("native_restore")),
            ("/phase/stage", json!("unresolved")),
            ("/phase/started_unix_millis", json!(2001)),
            ("/phase/invocation_id", json!("d".repeat(32))),
            ("/guard_unit", Value::Null),
            ("/guard_invocation_id", json!("d".repeat(32))),
            ("/producer_invocation_id", json!("d".repeat(32))),
            ("/processes/main_pid", json!(43)),
            ("/processes/workers", json!([{"pid":90}])),
            ("/recorded_unix_millis", json!(1_801_999)),
            ("/trip", json!(true)),
            ("/producer_stop_enabled", json!(false)),
        ] {
            let mut bad = current.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                assembly_window(&old, &bad, 2000, 1_802_000).is_err(),
                "{path}"
            );
        }
        assert!(assembly_window(&old, &current, 2001, 1_802_000).is_err());
        assert!(assembly_window(&current, &old, 2000, 1_802_000).is_err());
        let mut missing = current.clone();
        missing.as_object_mut().unwrap().remove("phase");
        assert!(assembly_window(&old, &missing, 2000, 1_802_000).is_err());
    }
    #[test]
    fn current_admission_bracket_never_regresses_an_accepted_assembly_or_releases_its_caps() {
        let old = guard(1800);
        let current = guard(1_802_000);
        assembly_progress(&old, &current).unwrap();
        let mut complete = current.clone();
        complete["phase"]["stage"] = json!("complete");
        complete["phase"]["started_unix_millis"] = json!(1_802_000);
        assembly_progress(&old, &complete).unwrap();
        for (path, value) in [
            ("/phase/stage", json!("suffix_validation")),
            ("/phase/stage", json!("native_restore")),
            ("/phase/started_unix_millis", json!(999)),
            ("/phase/invocation_id", json!("d".repeat(32))),
            ("/recorded_unix_millis", json!(1799)),
            ("/processes/workers", json!([{"pid":90}])),
        ] {
            let mut bad = current.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(assembly_progress(&old, &bad).is_err(), "{path}");
        }
    }
}
