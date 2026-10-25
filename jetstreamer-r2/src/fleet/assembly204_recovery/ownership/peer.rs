//! A separate typed peer branch charges every recovery actor and the assembly
//! guard. Only authenticated rows leave the older accounting adapters.
use super::*;
struct Peer {
    claim: Claim,
    row: Value,
    frame: Value,
    launch: Value,
    stage: downstream::Stage,
}
fn selected(r: &Value) -> bool {
    r["phase"] == "assembly-recovery204"
        || r["unit"]["Id"].as_str().is_some_and(|s| scope(s, 204, 204))
}
fn accepted(f: &Value) -> Result<Vec<Peer>> {
    let active = f["active"]
        .as_array()
        .context("204 recovery peer active roster")?;
    if !active.iter().any(selected) {
        return Ok(Vec::new());
    }
    let plan = bound_json(&BoundFile {
        path: s(f, "plan")?.into(),
        sha256: s(f, "plan_sha256")?.into(),
    })?;
    let c: Claim = serde_json::from_value(plan["assembly204_recovery"].clone())?;
    let rows = active.iter().filter(|r| selected(r)).collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "204 recovery duplicate or missing accepted owner"
    );
    let frame = read(&c.frame)?;
    ensure!(
        frame["observer"]["path"] == f["observer_receipt"]
            && frame["observer"]["sha256"] == f["observer_sha256"],
        "204 peer observer differs from accepted fleet"
    );
    let observer = bound_json(&serde_json::from_value(frame["observer"].clone())?)?;
    let current = serde_json::from_value(f["unit_census"].clone())?;
    let expected = row(&c, &observer, &current, n(f, "recorded_unix_seconds")?)?;
    ensure!(
        expected == *rows[0] && expected["live"] == true,
        "204 recovery peer differs from authenticated current claim"
    );
    let launch = read(&c.actor_launch)?;
    let stage = serde_json::from_value(launch["stage"].clone())?;
    Ok(vec![Peer {
        claim: c,
        row: expected,
        frame,
        launch,
        stage,
    }])
}
pub(in crate::fleet) fn peer_names(f: &Value) -> Result<BTreeSet<String>> {
    Ok(accepted(f)?.iter().map(|p| p.stage.unit().into()).collect())
}
pub(in crate::fleet) fn peer_view(f: &Value) -> Result<Value> {
    let peers = accepted(f)?;
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("204 recovery peer view")?
        .retain(|r| !peers.iter().any(|p| p.row == *r));
    Ok(view)
}
pub(in crate::fleet) fn peer_observation(f: &Value, o: &Value) -> Result<()> {
    for p in accepted(f)? {
        ensure!(
            bound_json(&serde_json::from_value(p.frame["observer"].clone())?)? == *o,
            "204 recovery peer uses another observer"
        );
    }
    Ok(())
}
pub(in crate::fleet) fn peer_memory_owners(
    f: &Value,
    o: &Value,
) -> Result<BTreeMap<String, Value>> {
    let mut owners = BTreeMap::new();
    for p in accepted(f)?
        .into_iter()
        .filter(|p| p.stage == downstream::Stage::Assembly)
    {
        ensure!(
            bound_json(&serde_json::from_value(p.frame["observer"].clone())?)? == *o,
            "204 recovery memory uses another observer"
        );
        let at = utc_seconds(s(o, "recorded_at_utc")?)?
            .checked_mul(1000)
            .context("204 host sample clock overflow")?;
        let started = n(&p.launch, "started_unix_millis")?;
        ensure!(
            started > 0 && started <= at && n(&p.frame, "sampled_unix_millis")? >= at,
            "204 recovery actor did not cover the coordinated host sample"
        );
        let guard_bound: BoundFile = serde_json::from_value(p.frame["guard_snapshot"].clone())?;
        let heartbeat = read(&guard_bound)?;
        let plan = read(&p.claim.recovery_plan)?;
        guard_shape(
            &heartbeat,
            &plan,
            &p.claim.recovery_plan,
            &p.launch,
            n(&p.frame, "sampled_unix_millis")?,
        )?;
        let pid = s(&p.launch["owner"], "MainPID")?.parse::<u64>()?;
        let proof = json!({"schema":"jetstreamer-typed-recovery204-assembly-memory-owner-v1",
            "epoch":204,"role":"assembly-non-replay","unit":UNIT,"invocation_id":p.launch["invocation_id"],
            "main_pid":pid,"sampled_at_utc":o["recorded_at_utc"],"window_begin_millis":at,"window_end_millis":at,
            "phase":{"stage":"assembly","epoch":204,"invocation_id":p.launch["invocation_id"],"started_unix_millis":started},
            "frame":p.claim.frame,"origin_launch":p.claim.launch,"actor_launch":p.claim.actor_launch,
            "recovery_plan":p.claim.recovery_plan,"admission":p.claim.admission,"guard_snapshot":guard_bound,
            "included_in_whole_host_resident_memory":true,"fabricated_worker_rss":false,
            "disk_or_hard_memory_growth_exempted":false,"admission_authorized":false});
        ensure!(
            owners.insert(UNIT.into(), proof).is_none(),
            "204 recovery memory owner duplicated"
        );
    }
    Ok(owners)
}
pub(in crate::fleet) fn peer_guards(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
) -> Result<BTreeMap<String, BoundFile>> {
    let peers = peer_names(f)?;
    Ok(bounds
        .iter()
        .filter(|(n, _)| !peers.contains(*n))
        .map(|(n, b)| (n.clone(), b.clone()))
        .collect())
}
fn current(p: &Peer, census: &BTreeMap<String, Value>) -> Result<()> {
    let owner = census
        .get(p.stage.unit())
        .context("204 recovery resource owner omitted")?;
    ensure!(is_live(owner), "204 recovery resource owner inactive");
    same_owner(&p.launch["owner"], owner)?;
    if p.stage == downstream::Stage::Assembly {
        let guard = census
            .get(GUARD)
            .context("204 recovery resource guard omitted")?;
        ensure!(is_live(guard), "204 recovery guard inactive");
        same_owner(&p.launch["guard"], guard)?;
    }
    let old = census
        .get(OLD_UNIT)
        .context("204 original resource owner omitted")?;
    ensure!(
        is_idle(old) && (old["InvocationID"] == OLD_IID || old["InvocationID"] == ""),
        "204 original live/replaced during resource check"
    );
    Ok(())
}
pub(in crate::fleet) fn peer_current(
    f: &Value,
    census: &BTreeMap<String, Value>,
) -> Result<BTreeMap<String, Value>> {
    let mut view = census.clone();
    for p in accepted(f)? {
        current(&p, census)?;
        if p.stage == downstream::Stage::Assembly {
            view.remove(GUARD);
        }
    }
    Ok(view)
}
fn protection(p: &Peer, bounds: &BTreeMap<String, BoundFile>, now: u64) -> Result<Value> {
    let bound = bounds
        .get(p.stage.unit())
        .context("204 recovery protection omitted")?;
    if p.stage == downstream::Stage::Assembly {
        ensure!(
            p.frame["guard_snapshot"] == private157::binding(bound),
            "204 protected guard is not the actual issued frame snapshot"
        );
        let g = read(bound)?;
        let plan = read(&p.claim.recovery_plan)?;
        let actual_millis: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        ensure!(
            actual_millis / 1000 >= now && actual_millis / 1000 - now <= 900,
            "204 resource transaction clock differs"
        );
        guard_shape(&g, &plan, &p.claim.recovery_plan, &p.launch, actual_millis)?;
        Ok(g)
    } else {
        ensure!(
            private157::binding(bound) == private157::binding(&p.claim.frame),
            "204 downstream protection must bind exact current frame"
        );
        let frame = read(bound)?;
        let at = n(&frame, "sampled_unix_millis")?;
        ensure!(
            at / 1000 <= now && now - at / 1000 <= 900,
            "204 downstream protection frame stale"
        );
        Ok(frame)
    }
}
pub(in crate::fleet) fn peer_limits(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<Value> {
    let mut limits = serde_json::Map::new();
    for p in accepted(f)? {
        current(&p, census)?;
        protection(&p, bounds, now)?;
        let actor = kernel(
            census.get(p.stage.unit()).context("204 peer actor")?,
            p.stage.memory(),
        )?;
        let guard = if p.stage == downstream::Stage::Assembly {
            kernel(census.get(GUARD).context("204 peer guard")?, GUARD_MEMORY)?
        } else {
            Value::Null
        };
        limits.insert(
            p.stage.unit().into(),
            json!({"producer":actor,"guard":guard}),
        );
    }
    Ok(json!(limits))
}
pub(in crate::fleet) fn peer_resources(
    f: &Value,
    bounds: &BTreeMap<String, BoundFile>,
    census: &BTreeMap<String, Value>,
    now: u64,
) -> Result<(u64, Vec<Value>, u64, Vec<Value>)> {
    let mut disk = 0u64;
    let mut memory = 0u64;
    let mut de = Vec::new();
    let mut me = Vec::new();
    for p in accepted(f)? {
        current(&p, census)?;
        let proof = protection(&p, bounds, now)?;
        let actor = kernel(
            census.get(p.stage.unit()).context("204 peer actor")?,
            p.stage.memory(),
        )?;
        let guard = if p.stage == downstream::Stage::Assembly {
            kernel(census.get(GUARD).context("204 peer guard")?, GUARD_MEMORY)?
        } else {
            Value::Null
        };
        let growth = n(&actor, "remaining_hard_memory_growth_bytes")?
            .checked_add(if guard.is_null() {
                0
            } else {
                n(&guard, "remaining_hard_memory_growth_bytes")?
            })
            .context("204 peer memory overflow")?;
        memory = memory
            .checked_add(growth)
            .context("204 peer total memory overflow")?;
        // Retain the full admitted disk envelope even when files have already
        // allocated blocks. No caller-asserted or RSS credit is available.
        let admitted = if p.stage == downstream::Stage::Assembly {
            read(&p.claim.admission)?["incremental_disk_reserve_bytes"]
                .as_u64()
                .context("204 peer disk envelope")?
        } else {
            let a = read(&serde_json::from_value(p.frame["stage_admission"].clone())?)?;
            n(
                &read(&serde_json::from_value(a["capacity"].clone())?)?,
                "additional_bytes",
            )?
        };
        disk = disk
            .checked_add(admitted)
            .context("204 peer disk total overflow")?;
        me.push(json!({"epoch":204,"unit":p.stage.unit(),"invocation_id":p.launch["invocation_id"],"producer":actor,"guard":guard,"remaining_hard_memory_growth_bytes":growth,
            "accounting":"actual actor and independent guard memory.max minus memory.current; no RSS credit"}));
        de.push(json!({"epoch":204,"unit":p.stage.unit(),"remaining_growth_bytes":admitted,"allocation_credit_bytes":0,"protection":proof}));
    }
    Ok((disk, de, memory, me))
}

pub(in crate::fleet) fn qualification_successor(
    f: &Value,
    census: &BTreeMap<String, Value>,
    unit: &str,
    iid: &str,
    actor_launch: &BoundFile,
) -> Result<()> {
    let peers = accepted(f)?;
    ensure!(peers.len() == 1, "qualification requires one authenticated recovery 204 owner");
    let p = &peers[0];
    ensure!(
        p.claim.epoch == 204
            && p.stage.unit() == unit
            && p.row["unit"]["InvocationID"] == iid
            && p.claim.actor_launch == *actor_launch,
        "qualification recovery 204 successor identity differs"
    );
    current(p, census)?;
    let observer = bound_json(&serde_json::from_value(p.frame["observer"].clone())?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        row(&p.claim, &observer, census, now)? == p.row,
        "qualification recovery 204 row changed or became stale"
    );
    Ok(())
}
