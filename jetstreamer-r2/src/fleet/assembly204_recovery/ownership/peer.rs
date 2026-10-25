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
        let plan = read(&p.claim.recovery_plan)?;
        let actual_millis = now_millis()?;
        ensure!(
            actual_millis / 1000 >= now && actual_millis / 1000 - now <= 900,
            "204 resource transaction clock differs"
        );
        assembly_protection_with(p, bound, &plan, &read, &live_guard::load)
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
fn assembly_protection_with(
    p: &Peer,
    bound: &BoundFile,
    plan: &Value,
    historical: &impl Fn(&BoundFile) -> Result<Value>,
    current: &impl Fn(&Value, &BoundFile, &Value) -> Result<live_guard::Heartbeat>,
) -> Result<Value> {
    ensure!(
        p.frame["guard_snapshot"] == private157::binding(bound),
        "204 protected guard is not the actual issued frame snapshot"
    );
    let origin = historical(bound)?;
    let captured = n(&p.frame, "sampled_unix_millis")?;
    guard_shape(&origin, plan, &p.claim.recovery_plan, &p.launch, captured)?;
    let live = current(plan, &p.claim.recovery_plan, &p.launch)?;
    ensure!(
        live.value["started_unix_millis"] == origin["started_unix_millis"]
            && n(&live.value, "recorded_unix_millis")? >= n(&origin, "recorded_unix_millis")?,
        "204 current heartbeat changed its guard origin or moved backwards"
    );
    Ok(
        json!({"schema":"jetstreamer-recovery204-live-resource-protection-v1",
        "historical_guard_snapshot":private157::binding(bound),"historical_guard":origin,
        "historical_frame_sampled_unix_millis":captured,"current_heartbeat":live.evidence()?}),
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
        let (disk_evidence, memory_evidence, growth) =
            resource_evidence(&p, proof, actor, guard, admitted)?;
        memory = memory
            .checked_add(growth)
            .context("204 peer total memory overflow")?;
        me.push(memory_evidence);
        de.push(disk_evidence);
    }
    Ok((disk, de, memory, me))
}
fn resource_evidence(
    p: &Peer,
    proof: Value,
    actor: Value,
    guard: Value,
    admitted: u64,
) -> Result<(Value, Value, u64)> {
    let growth = n(&actor, "remaining_hard_memory_growth_bytes")?
        .checked_add(if guard.is_null() {
            0
        } else {
            n(&guard, "remaining_hard_memory_growth_bytes")?
        })
        .context("204 peer memory overflow")?;
    let mut memory = json!({"epoch":204,"unit":p.stage.unit(),"invocation_id":p.launch["invocation_id"],"producer":actor,"guard":guard,"remaining_hard_memory_growth_bytes":growth,
        "accounting":"actual actor and independent guard memory.max minus memory.current; no RSS credit"});
    if p.stage == downstream::Stage::Assembly {
        memory["live_guard_protection"] = proof.clone();
    }
    Ok((
        json!({"epoch":204,"unit":p.stage.unit(),"remaining_growth_bytes":admitted,"allocation_credit_bytes":0,"protection":proof}),
        memory,
        growth,
    ))
}

pub(in crate::fleet) fn qualification_successor(
    f: &Value,
    census: &BTreeMap<String, Value>,
    unit: &str,
    iid: &str,
    actor_launch: &BoundFile,
) -> Result<()> {
    let peers = accepted(f)?;
    ensure!(
        peers.len() == 1,
        "qualification requires one authenticated recovery 204 owner"
    );
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

#[cfg(test)]
mod live_guard_tests {
    use super::*;
    fn bound(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/sealed").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn live_owner(name: &str, invocation: &str, pid: &str) -> Value {
        json!({"Id":name,"InvocationID":invocation,"MainPID":pid,"NRestarts":"0",
            "LoadState":"loaded","ActiveState":"active","SubState":"running",
            "ControlGroup":format!("/system.slice/{name}"),"ExecStart":"{ path=/sealed/helper ; argv[]=/sealed/helper ; ignore_errors=no }"})
    }
    fn fixture() -> (Peer, BoundFile, Value, Value) {
        let snapshot = bound("frame.guard.json");
        let plan = json!({"source_capture":private157::binding(&bound("sources.json")),
            "guard_spec":private157::binding(&bound("guard-spec.json"))});
        let launch = json!({"invocation_id":"d".repeat(32),"guard_invocation_id":"e".repeat(32),
            "owner":live_owner(UNIT,&"d".repeat(32),"10"),
            "guard":live_owner(GUARD,&"e".repeat(32),"11")});
        let peer = Peer {
            claim: Claim {
                epoch: 204,
                recovery_plan: bound("plan.json"),
                admission: bound("admission.json"),
                launch: bound("launch.json"),
                actor_launch: bound("actor-launch.json"),
                frame: bound("frame.json"),
                eta_policy: bound("eta.json"),
            },
            row: Value::Null,
            frame: json!({"guard_snapshot":private157::binding(&snapshot),"sampled_unix_millis":1_000_000}),
            launch,
            stage: downstream::Stage::Assembly,
        };
        let guard = json!({"schema":"jetstreamer-epoch204-assembly-recovery-guard-heartbeat-v1","epoch":204,
            "plan_sha256":peer.claim.recovery_plan.sha256,"source_capture":plan["source_capture"],"guard_spec":plan["guard_spec"],
            "producer_unit":UNIT,"guard_unit":GUARD,"producer_invocation_id":peer.launch["invocation_id"],
            "guard_invocation_id":peer.launch["guard_invocation_id"],"recorded_unix_millis":1_000_000,
            "started_unix_millis":900_000,"trip":false,"producer_stop_enabled":true,"source_custody_unchanged":true,
            "original_owner_idle":true,"kernel_memory_max_bytes":MEMORY,"kernel_memory_high_bytes":48u64<<30,
            "memory_swap_max_bytes":0,"cpu_quota_usec_per_second":8_000_000,"tasks_max":512,
            "maximum_millis":DURATION,"maximum_output_bytes":OUTPUT_MAX});
        (peer, snapshot, plan, guard)
    }
    fn prove(
        p: &Peer,
        snapshot: &BoundFile,
        plan: &Value,
        origin: &Value,
        live: &Value,
        now: u64,
    ) -> Result<Value> {
        assembly_protection_with(
            p,
            snapshot,
            plan,
            &|b| {
                ensure!(
                    private157::binding(b) == private157::binding(snapshot),
                    "unexpected historical binding"
                );
                Ok(origin.clone())
            },
            &|plan, b, launch| live_guard::fixture_heartbeat(live, plan, b, launch, now),
        )
    }
    #[test]
    fn old_legitimate_frame_uses_fresh_exact_current_heartbeat_and_preserves_raw_evidence() {
        let (p, snapshot, plan, origin) = fixture();
        let mut live = origin.clone();
        live["recorded_unix_millis"] = json!(1_600_000);
        assert!(guard_shape(&origin, &plan, &p.claim.recovery_plan, &p.launch, 1_600_000).is_err());
        let proof = prove(&p, &snapshot, &plan, &origin, &live, 1_600_001).unwrap();
        assert_eq!(
            proof["historical_guard_snapshot"],
            private157::binding(&snapshot)
        );
        assert_eq!(proof["historical_guard"], origin);
        assert_eq!(proof["current_heartbeat"]["heartbeat"], live);
        let raw = proof["current_heartbeat"]["raw_json"].as_str().unwrap();
        assert_eq!(serde_json::from_str::<Value>(raw).unwrap(), live);
        assert_eq!(
            proof["current_heartbeat"]["binding"]["sha256"],
            hex_lower(&Sha256::digest(raw.as_bytes()))
        );
        assert_eq!(
            proof["current_heartbeat"]["binding"]["path"],
            format!("{ROOT}/guard-heartbeat.json")
        );
        assert_eq!(proof["current_heartbeat"]["checked_unix_millis"], 1_600_001);
    }
    #[test]
    fn current_heartbeat_failures_never_fall_back_to_history() {
        let (p, snapshot, plan, origin) = fixture();
        let mut live = origin.clone();
        live["recorded_unix_millis"] = json!(1_600_000);
        assert!(
            assembly_protection_with(
                &p,
                &snapshot,
                &plan,
                &|_| Ok(origin.clone()),
                &|_, _, _| bail!("live heartbeat absent")
            )
            .is_err()
        );
        prove(&p, &snapshot, &plan, &origin, &live, 1_615_000).unwrap();
        assert!(prove(&p, &snapshot, &plan, &origin, &live, 1_615_001).is_err());
        assert!(prove(&p, &snapshot, &plan, &origin, &Value::Null, 1_600_000).is_err());
        for (key, value) in [
            ("trip", json!(true)),
            ("producer_stop_enabled", json!(false)),
            ("source_custody_unchanged", json!(false)),
            ("original_owner_idle", json!(false)),
            ("producer_unit", json!(OLD_UNIT)),
            ("guard_unit", json!(OLD_GUARD)),
            ("producer_invocation_id", json!("f".repeat(32))),
            ("guard_invocation_id", json!("f".repeat(32))),
            ("source_capture", json!({})),
            ("guard_spec", json!({})),
            ("plan_sha256", json!("b".repeat(64))),
            ("kernel_memory_max_bytes", json!(MEMORY + 1)),
            ("kernel_memory_high_bytes", json!((48u64 << 30) - 1)),
            ("memory_swap_max_bytes", json!(1)),
            ("tasks_max", json!(513)),
            ("cpu_quota_usec_per_second", json!(8_000_001)),
            ("started_unix_millis", json!(900_001)),
            ("recorded_unix_millis", json!(1_600_002)),
            ("maximum_millis", json!(DURATION + 1)),
            ("maximum_output_bytes", json!(OUTPUT_MAX + 1)),
        ] {
            let mut changed = live.clone();
            changed[key] = value;
            assert!(
                prove(&p, &snapshot, &plan, &origin, &changed, 1_600_001).is_err(),
                "accepted {key}"
            );
        }
        live["recorded_unix_millis"] = json!(999_999);
        assert!(prove(&p, &snapshot, &plan, &origin, &live, 1_000_001).is_err());
    }
    #[test]
    fn historical_snapshot_binding_time_and_identity_cannot_be_replaced() {
        let (mut p, snapshot, plan, origin) = fixture();
        let mut live = origin.clone();
        live["recorded_unix_millis"] = json!(1_600_000);
        let mut foreign = snapshot.clone();
        foreign.sha256 = "b".repeat(64);
        assert!(prove(&p, &foreign, &plan, &origin, &live, 1_600_000).is_err());
        for (key, value) in [
            ("recorded_unix_millis", json!(984_999)),
            ("source_capture", json!({})),
            ("guard_invocation_id", json!("f".repeat(32))),
            ("trip", json!(true)),
            ("kernel_memory_max_bytes", json!(MEMORY - 1)),
        ] {
            let mut changed = origin.clone();
            changed[key] = value;
            assert!(
                prove(&p, &snapshot, &plan, &changed, &live, 1_600_000).is_err(),
                "accepted historical {key}"
            );
        }
        p.frame["sampled_unix_millis"] = json!(1_015_001);
        assert!(prove(&p, &snapshot, &plan, &origin, &live, 1_600_000).is_err());
    }
    #[test]
    fn both_resource_brackets_retain_distinct_live_proofs_and_all_disk_actor_and_guard_charges() {
        let (p, snapshot, plan, origin) = fixture();
        let admitted = 171_932_909_568u64;
        let mut proofs = Vec::new();
        for (at, actor_current, guard_current) in [
            (1_600_000u64, 28u64 << 30, 6u64 << 20),
            (1_601_000, 29u64 << 30, 7u64 << 20),
        ] {
            let mut live = origin.clone();
            live["recorded_unix_millis"] = json!(at);
            let proof = prove(&p, &snapshot, &plan, &origin, &live, at + 1).unwrap();
            let actor = json!({"memory_max_bytes":MEMORY,"memory_current_bytes":actor_current,"remaining_hard_memory_growth_bytes":MEMORY-actor_current});
            let guard = json!({"memory_max_bytes":GUARD_MEMORY,"memory_current_bytes":guard_current,"remaining_hard_memory_growth_bytes":GUARD_MEMORY-guard_current});
            let (disk, memory, growth) =
                resource_evidence(&p, proof.clone(), actor, guard, admitted).unwrap();
            assert_eq!(disk["remaining_growth_bytes"], admitted);
            assert_eq!(disk["allocation_credit_bytes"], 0);
            assert_eq!(disk["protection"], proof);
            assert_eq!(memory["live_guard_protection"], proof);
            assert_eq!(memory["producer"]["memory_max_bytes"], MEMORY);
            assert_eq!(memory["guard"]["memory_max_bytes"], GUARD_MEMORY);
            assert_eq!(
                growth,
                (MEMORY - actor_current) + (GUARD_MEMORY - guard_current)
            );
            proofs.push(proof);
        }
        assert_ne!(
            proofs[0]["current_heartbeat"]["binding"]["sha256"],
            proofs[1]["current_heartbeat"]["binding"]["sha256"]
        );
        assert_eq!(
            proofs[0]["historical_guard_snapshot"],
            proofs[1]["historical_guard_snapshot"]
        );
    }
    #[test]
    fn fresh_heartbeat_cannot_cover_changed_or_restarted_current_kernel_owners() {
        let (p, _, _, _) = fixture();
        let mut census = BTreeMap::from([
            (UNIT.into(), p.launch["owner"].clone()),
            (GUARD.into(), p.launch["guard"].clone()),
            (
                OLD_UNIT.into(),
                json!({"InvocationID":OLD_IID,"MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead"}),
            ),
        ]);
        current(&p, &census).unwrap();
        for name in [UNIT, GUARD] {
            for (key, value) in [
                ("NRestarts", json!("1")),
                ("InvocationID", json!("f".repeat(32))),
                ("MainPID", json!("99")),
                ("ControlGroup", json!("/system.slice/foreign.service")),
            ] {
                let mut changed = census.clone();
                changed.get_mut(name).unwrap()[key] = value;
                assert!(current(&p, &changed).is_err(), "accepted {name} {key}");
            }
        }
        census.remove(GUARD);
        assert!(current(&p, &census).is_err());
    }
}
