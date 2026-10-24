//! Shared closed accounting for the actual native 20 full-prefix223 peer.
//! Never alters the accepted fleet, claims, history or producer.
use super::prefix223_native20 as c;
use super::*;
const IID: &str = "e70aaf097e7c4583b216aba454145910";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon-native223-prefix-capture-actual-v1/launch.json";
const LAUNCH_SHA: &str = "a629f2a5eb1a6be5e3ec38e66769f0698841fb7ccc8d43110ac3bfd73df99ac3";

fn roster_scope(f: &Value) -> Result<()> {
    let mut seen = false;
    for row in f["active"]
        .as_array()
        .context("peer 223 full 223 complete census")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        if owner["Id"] != c::UNIT {
            ensure!(row["epoch"] != 223, "unmodeled active223 peer");
            continue;
        }
        ensure!(
            !seen
                && owner["InvocationID"] == IID
                && owner["NRestarts"] == "0"
                && row["launch_receipt"] == LAUNCH
                && row["launch_receipt_sha256"] == LAUNCH_SHA
                && row["epoch"] == 223
                && row["phase"] == "private-known-root-prefix"
                && row["ordinary_replay_claim"] == false,
            "peer 223 full 223 duplicate or changed owner scope"
        );
        seen = true;
    }
    Ok(())
}

fn claim(f: &Value, row: &Value) -> Result<(DiagnosticClaim, Value)> {
    let owner = singleton227_admission::active_owner(row)?;
    ensure!(
        row["epoch"] == 223
            && owner["Id"] == c::UNIT
            && owner["InvocationID"] == IID
            && row["launch_receipt"] == LAUNCH
            && row["launch_receipt_sha256"] == LAUNCH_SHA
            && row["phase"] == "private-known-root-prefix"
            && row["ordinary_replay_claim"] == false,
        "peer 223 unknown epoch 223 owner"
    );
    let p: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("peer 223 full 223 fleet plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("peer 223 full 223 plan digest")?
            .into(),
    })?)?;
    let matches = p
        .diagnostics
        .iter()
        .filter(|d| d.epoch == 223 && d.unit == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "peer 223 full 223 needs one authenticated diagnostic claim"
    );
    let d = matches[0];
    ensure!(
        d.invocation_id == IID
            && d.invocation_id == owner["InvocationID"]
            && d.launch_receipt.path == Path::new(LAUNCH)
            && d.launch_receipt.sha256 == LAUNCH_SHA
            && d.scratch_path == Path::new(c::ROOT)
            && private157::binding(&d.launch_receipt)["path"] == row["launch_receipt"]
            && d.launch_receipt.sha256 == row["launch_receipt_sha256"]
            && owner["NRestarts"] == "0"
            && diagnostic_stage_running(owner),
        "peer 223 full 223 invocation, command or launch changed"
    );
    let launch = native209::immutable_json(&d.launch_receipt)?;
    ensure!(
        launch["evidence"]["units"]
            .as_array()
            .is_some_and(|v| v.len() == 1)
            && launch["evidence"]["units"][0]["unit"] == d.unit
            && launch["evidence"]["units"][0]["invocation_id"] == d.invocation_id
            && launch["evidence"]["units"][0]["main_pid"]
                .as_u64()
                .map(|n| n.to_string())
                .as_deref()
                == owner["MainPID"].as_str(),
        "peer 223 full 223 launch owner changed"
    );
    c::bindings(d, &launch)?;
    ensure!(
        c::same_command(&owner["ExecStart"]),
        "peer 223 full 223 live command changed"
    );
    Ok((
        DiagnosticClaim {
            epoch: d.epoch,
            unit: d.unit.clone(),
            invocation_id: d.invocation_id.clone(),
            scratch_path: d.scratch_path.clone(),
            launch_receipt: BoundFile {
                path: d.launch_receipt.path.clone(),
                sha256: d.launch_receipt.sha256.clone(),
            },
        },
        launch,
    ))
}

#[allow(clippy::too_many_arguments)]
fn guard(
    g: &Value,
    p: &Value,
    launch: &Value,
    d: &DiagnosticClaim,
    owner: &Value,
    sample: u64,
    now: u64,
    plan_sha: &str,
) -> Result<()> {
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("peer 223 full 223 guard clock")?;
    ensure!(
        p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && c::guard_matches(d, launch, p)
            && t >= sample
            && t <= now
            && now - t <= 1800
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == c::GUARD_SHA
            && g["plan_sha256"] == plan_sha
            && p["unit"] == d.unit
            && p["invocation_id"] == d.invocation_id
            && g["producer_invocation_id"] == d.invocation_id
            && g["producer"]["invocation_id"] == d.invocation_id
            && g["producer"]["cgroup"] == owner["ControlGroup"]
            && g["producer"]["pid"]
                .as_u64()
                .map(|n| n.to_string())
                .as_deref()
                == owner["MainPID"].as_str()
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["maximum_physical_bytes"] == c::PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= c::PEAK)
            && g["maximum_worker_vmas"] == 3500000
            && g.get("native_main").is_some_and(Value::is_null)
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["workers"].as_array().is_some_and(|v| v
                .iter()
                .all(|w| w[0].as_u64().is_some_and(|pid| pid > 1)
                    && w[1].as_u64().is_some_and(|n| n > 0 && n < 3500000)))
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error",
                "canary_target_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "peer 223 protected full 223 guard changed, stale or tripped"
    );
    Ok(())
}

type Split = (Value, BTreeMap<String, BoundFile>, u64, Vec<Value>);
pub(super) fn allocation(o: &Value, g: &Value, iid: &str) -> Result<(u64, u64, u64)> {
    ensure!(iid == IID, "peer 223 allocation belongs to another attempt");
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("peer 223 full 223 observer census")?
        .iter()
        .filter(|r| r["producer_unit"] == c::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1,
        "peer 223 full 223 needs one coordinated whole-root sample"
    );
    let row = rows[0];
    let sample = &row["observation"];
    ensure!(
        row["status"] == "observed"
            && row["error"].is_null()
            && row["scratch_path"] == c::ROOT
            && sample["scratch_path"] == c::ROOT
            && sample["invocation_binding_stable"] == true
            && sample["producer_before"]["unit"] == c::UNIT
            && sample["producer_after"]["unit"] == c::UNIT
            && sample["producer_before"]["invocation_id"] == iid
            && sample["producer_after"]["invocation_id"] == iid,
        "peer 223 full 223 allocation sample has another owner or directory scope"
    );
    let sampled = sample["conservative_observed_physical_bytes"]
        .as_u64()
        .filter(|n| *n <= c::PEAK)
        .context("peer 223 full 223 sampled whole-root allocation exceeds envelope")?;
    let guarded = g["root_physical_observation"]["conservative_physical_bytes"]
        .as_u64()
        .filter(|n| *n <= c::PEAK)
        .context("peer 223 full 223 current guarded allocation exceeds envelope")?;
    Ok((sampled.min(guarded), sampled, guarded))
}
fn split(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<Split> {
    roster_scope(f)?;
    let mut reduced = f.clone();
    let mut reduced_guards = guards
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                BoundFile {
                    path: v.path.clone(),
                    sha256: v.sha256.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut growth = 0u64;
    let mut measurements = Vec::new();
    for row in f["active"]
        .as_array()
        .context("peer 223 full 223 census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
    {
        let owner = singleton227_admission::active_owner(row)?;
        ensure!(measurements.is_empty(), "peer 223 duplicate full 223 owner");
        let (d, launch) = claim(f, row)?;
        let b = reduced_guards
            .remove(&d.unit)
            .context("peer 223 full 223 needs latest protective guard")?;
        let g = bound_json(&b)?;
        let plan: BoundFile = serde_json::from_value(launch["guard_plan"].clone())?;
        guard(
            &g,
            &bound_json(&plan)?,
            &launch,
            &d,
            owner,
            sample,
            now,
            &plan.sha256,
        )?;
        let (credit, sampled, guarded) = allocation(o, &g, &d.invocation_id)?;
        growth = c::PEAK - credit;
        measurements.push(json!({"epoch":223,"unit":d.unit,"invocation_id":d.invocation_id,
            "launch":private157::binding(&d.launch_receipt),"guard":private157::binding(&b),
            "remaining_growth_bytes":growth,"scratch_growth_credit_bytes":credit,
            "sampled_whole_root_physical_bytes":sampled,"guarded_whole_root_physical_bytes":guarded,
            "accounting":"whole-root envelope less min(coordinated same-IID whole-root allocation,current whole-root guard allocation); actual free space bracketed by admission"}));
    }
    reduced["active"]
        .as_array_mut()
        .context("peer 223 reduced full 223 census")?
        .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != c::UNIT));
    Ok((reduced, reduced_guards, growth, measurements))
}

fn memory_limits(
    launch: &Value,
    cap: u64,
    high: u64,
    charge: u64,
    swap: u64,
    page: u64,
) -> Result<u64> {
    let requested_max = c::MEMORY;
    let requested_high = 150_000_000_000u64;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "peer 223 invalid host page size"
    );
    ensure!(
        launch["maximum_memory_bytes"] == c::MEMORY
            && launch["experimental_envelope_bytes"] == c::PEAK
            && launch["sandbox"]["MemoryMax"] == "225000000000"
            && launch["sandbox"]["MemoryHigh"] == "150000000000"
            && launch["sandbox"]["MemorySwapMax"] == "0"
            && cap > 0
            && high > 0
            && cap == requested_max / page * page
            && high == requested_high / page * page
            && swap == 0
            && charge <= cap,
        "peer 223 full 223 requested or kernel-rounded hard memory envelope changed"
    );
    Ok(cap - charge)
}

fn peer_memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    roster_scope(f)?;
    let mut total = 0u64;
    let mut evidence = Vec::new();
    for row in f["active"]
        .as_array()
        .context("peer 223 full 223 memory census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
    {
        let owner = singleton227_admission::active_owner(row)?;
        let (d, launch) = claim(f, row)?;
        ensure!(
            owner["ControlGroup"] == format!("/system.slice/{}", d.unit),
            "peer 223 full 223 cgroup escaped"
        );
        let root = Path::new("/sys/fs/cgroup/system.slice").join(&d.unit);
        let read = |name: &str| -> Result<u64> {
            Ok(fs::read_to_string(root.join(name))?.trim().parse()?)
        };
        let cap = read("memory.max")?;
        let high = read("memory.high")?;
        let charge = read("memory.current")?;
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .context("peer 223 host page size unavailable")?;
        let remaining = memory_limits(&launch, cap, high, charge, read("memory.swap.max")?, page)?;
        total = total
            .checked_add(remaining)
            .context("peer 223 full 223 memory overflow")?;
        evidence.push(
            json!({"epoch":223,"unit":d.unit,"invocation_id":d.invocation_id,
            "hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,
            "remaining_hard_memory_growth_bytes":remaining,"resource_plan":launch["resource_plan"],
            "requested_memory_max_bytes":c::MEMORY,"requested_memory_high_bytes":150_000_000_000u64,
            "kernel_memory_high_bytes":high,"host_page_size_bytes":page}),
        );
    }
    Ok((total, evidence))
}

// A derived accounting view is never written or accepted as a new fleet.
fn without_peer(f: &Value) -> Result<Value> {
    roster_scope(f)?;
    let mut view = f.clone();
    view["active"]
        .as_array_mut()
        .context("peer 223 accounting view")?
        .retain(|row| {
            singleton227_admission::active_owner(row).map_or(true, |u| u["Id"] != c::UNIT)
        });
    Ok(view)
}
// Preserve the generic cap contract for every other owner. Only the exact
// authenticated full-prefix223 peer is split into its existing launch/sandbox
// validator; the derived view is never a fleet replacement.
fn protected_caps(row: &Value, launch: &Value, p: &BTreeMap<String, String>) -> Result<Value> {
    roster_scope(&json!({"active":[row]}))?;
    let owner = singleton227_admission::active_owner(row)?;
    ensure!(
        owner["Id"] == c::UNIT && owner["ControlGroup"] == format!("/system.slice/{}", c::UNIT),
        "peer 223 protected cap owner differs"
    );
    prefix223_native20_capture::sandbox(p)?;
    let mut caps = serde_json::Map::new();
    for key in [
        "MemoryHigh",
        "MemoryMax",
        "MemorySwapMax",
        "CPUQuotaPerSecUSec",
        "TasksMax",
    ] {
        let observed = p.get(key).context("peer 223 missing protected cap")?;
        ensure!(
            launch["sandbox"][key] == *observed,
            "peer 223 cap differs from immutable launch:{key}"
        );
        caps.insert(key.into(), json!(observed));
    }
    ensure!(
        p.get("ControlGroup").map(String::as_str) == owner["ControlGroup"].as_str(),
        "peer 223 protected control group differs"
    );
    caps.insert("ControlGroup".into(), json!(p["ControlGroup"]));
    Ok(Value::Object(caps))
}
pub(super) fn limits(f: &Value) -> Result<Value> {
    roster(f)?;
    let mut result = singleton227_admission::limits(&without_peer(f)?)?;
    for row in f["active"]
        .as_array()
        .context("peer 223 cap census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
    {
        let (d, launch) = claim(f, row)?;
        let properties = singleton227_capture::properties(
            &d.unit,
            "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,OOMPolicy,OOMScoreAdjust,Result,ActiveState,SubState,NRestarts,ExecStart,ControlGroup",
        )?;
        let caps = protected_caps(row, &launch, &properties)?;
        ensure!(
            result
                .as_object_mut()
                .context("peer 223 cap object")?
                .insert(d.unit, caps)
                .is_none(),
            "peer 223 duplicate protected cap owner"
        );
    }
    Ok(result)
}
pub(super) fn roster(f: &Value) -> Result<BTreeSet<String>> {
    let view = without_peer(f)?;
    let base = full210_peer::without_peer(&view)?;
    let mut names = prefix223_native20_admission::roster(&base)?;
    if view["active"].as_array().unwrap().len() != base["active"].as_array().unwrap().len() {
        ensure!(
            names.insert(singleton210::UNIT.into()),
            "duplicate full 210 roster owner"
        );
    }
    if f["active"]
        .as_array()
        .context("peer 223 full active roster")?
        .len()
        != view["active"].as_array().unwrap().len()
    {
        ensure!(
            names.insert(c::UNIT.into()),
            "duplicate peer 223 roster owner"
        );
    }
    Ok(names)
}
pub(super) fn disk(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    roster(f)?;
    let (view, remaining, extra, mut evidence) = split(f, o, guards, sample, now)?;
    let (view, remaining, extra210, proof210) =
        full210_peer::split(&view, o, &remaining, sample, now)?;
    evidence.extend(proof210);
    let (base, rest) = prefix223_native20_peer228::disk(&view, o, &remaining, sample, now)?;
    evidence.extend(rest);
    Ok((
        base.checked_add(extra)
            .and_then(|n| n.checked_add(extra210))
            .context("peer 223 total disk overflow")?,
        evidence,
    ))
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    roster(f)?;
    let (extra, mut evidence) = peer_memory(f)?;
    let view = without_peer(f)?;
    let (extra210, proof210) = full210_peer::memory(&view)?;
    evidence.extend(proof210);
    let (base, rest) = prefix223_native20_peer228::memory(&full210_peer::without_peer(&view)?)?;
    evidence.extend(rest);
    Ok((
        base.checked_add(extra)
            .and_then(|n| n.checked_add(extra210))
            .context("peer 223 total memory overflow")?,
        evidence,
    ))
}
fn current_shape(expected: &Value, observed: &Value) -> Result<()> {
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ControlGroup",
        "ActiveState",
        "SubState",
    ] {
        ensure!(
            expected[key] == observed[key],
            "peer 223 manager changed:{key}"
        );
    }
    ensure!(
        diagnostic_stage_running(observed) && c::same_command(&observed["ExecStart"]),
        "peer 223 is not the original live command"
    );
    Ok(())
}
pub(super) fn current(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    roster(f)?;
    full210_peer::current(f, current)?;
    for row in f["active"]
        .as_array()
        .context("peer 223 current census")?
        .iter()
        .filter(|r| r["epoch"] == 223)
    {
        claim(f, row)?;
        let expected = singleton227_admission::active_owner(row)?;
        current_shape(
            expected,
            current
                .get(c::UNIT)
                .context("peer 223 current owner missing")?,
        )?;
        let properties = singleton227_capture::properties(
            c::UNIT,
            "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,ProtectHome,ProtectSystem,ProtectControlGroups,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,OOMPolicy,OOMScoreAdjust,Result,ActiveState,SubState,NRestarts,ExecStart",
        )?;
        prefix223_native20_capture::sandbox(&properties)?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn fixture_row() -> Value {
    let launch: Value = serde_json::from_slice(include_bytes!(
        "../../tests/fixtures/prefix223-peer/launch.json"
    ))
    .unwrap();
    let pid = launch["evidence"]["units"][0]["main_pid"].as_u64().unwrap();
    json!({"epoch":223,"phase":"private-known-root-prefix","ordinary_replay_claim":false,
        "launch_receipt":LAUNCH,"launch_receipt_sha256":LAUNCH_SHA,
        "producer":{"Id":c::UNIT,"LoadState":"loaded","InvocationID":IID,"MainPID":pid.to_string(),"NRestarts":"0",
            "ControlGroup":format!("/system.slice/{}",c::UNIT),"ActiveState":"active","SubState":"running",
            "ExecStart":launch["expected_exec_start"]}})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full210_is_retained_as_one_typed_peer_and_never_hidden_as_a_native_or_foreign_owner() {
        let row = json!({"epoch":210,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "unit":{"Id":singleton210::UNIT,"InvocationID":"a".repeat(32),"NRestarts":"0"}});
        let f = json!({"active":[row]});
        let original = f.clone();
        assert_eq!(
            roster(&f).unwrap(),
            [singleton210::UNIT.to_owned()].into_iter().collect()
        );
        assert_eq!(f, original);
        for (pointer, value) in [
            ("/active/0/epoch", json!(209)),
            ("/active/0/phase", json!("replay")),
            ("/active/0/ordinary_replay_claim", json!(true)),
            ("/active/0/unit/Id", json!("unknown210.service")),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(roster(&bad).is_err(), "{pointer}");
        }
    }
    fn launch() -> Value {
        serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/prefix223-peer/launch.json"
        ))
        .unwrap()
    }
    #[test]
    fn protected_caps_keep_actual_223_envelope_and_reject_changed_owner_or_limits() {
        let row = fixture_row();
        let launch = launch();
        let mut props = launch["sandbox"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect::<BTreeMap<_, _>>();
        props.insert("ControlGroup".into(), format!("/system.slice/{}", c::UNIT));
        let caps = protected_caps(&row, &launch, &props).unwrap();
        assert_eq!(caps["MemoryMax"], "225000000000");
        assert_eq!(caps["MemoryHigh"], "150000000000");
        assert_eq!(caps.as_object().unwrap().len(), 6);
        for key in [
            "MemoryMax",
            "MemoryHigh",
            "MemorySwapMax",
            "CPUQuotaPerSecUSec",
            "TasksMax",
            "ControlGroup",
        ] {
            let mut changed = props.clone();
            changed.insert(key.into(), "changed".into());
            assert!(protected_caps(&row, &launch, &changed).is_err(), "{key}");
            changed.remove(key);
            assert!(
                protected_caps(&row, &launch, &changed).is_err(),
                "missing {key}"
            );
        }
        for pointer in [
            "/epoch",
            "/producer/InvocationID",
            "/producer/Id",
            "/producer/ControlGroup",
            "/launch_receipt_sha256",
        ] {
            let mut changed = row.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                protected_caps(&changed, &launch, &props).is_err(),
                "{pointer}"
            );
        }
        let mut changed = launch.clone();
        changed["sandbox"]["MemoryMax"] = json!("137438953472");
        assert!(protected_caps(&row, &changed, &props).is_err());
        let f = json!({"active":[row,{"epoch":207,"unit":{"Id":"unchanged-other.service"}}]});
        let original = f.clone();
        let view = without_peer(&f).unwrap();
        assert_eq!(view["active"], json!([f["active"][1]]));
        assert_eq!(f, original);
    }
    #[test]
    fn actual_launch_and_guard_fixture_bind_the_exact_new_attempt_without_host_observation() {
        let launch = launch();
        let row = fixture_row();
        let owner = singleton227_admission::active_owner(&row).unwrap();
        assert_eq!(
            hex_lower(&Sha256::digest(include_bytes!(
                "../../tests/fixtures/prefix223-peer/launch.json"
            ))),
            LAUNCH_SHA
        );
        let d = DiagnosticClaim {
            epoch: 223,
            unit: c::UNIT.into(),
            invocation_id: IID.into(),
            scratch_path: c::ROOT.into(),
            launch_receipt: BoundFile {
                path: LAUNCH.into(),
                sha256: LAUNCH_SHA.into(),
            },
        };
        assert!(c::launch_matches(&d, &launch));
        let g: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/prefix223-peer/guard.json"
        ))
        .unwrap();
        let p: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/prefix223-peer/guard-plan.json"
        ))
        .unwrap();
        let plan_sha = launch["guard_plan"]["sha256"].as_str().unwrap();
        let t = g["recorded_unix_seconds"].as_u64().unwrap();
        guard(&g, &p, &launch, &d, owner, t, t, plan_sha).unwrap();
        for (pointer, value) in [
            ("/guard_sha256", json!("a".repeat(64))),
            ("/producer/invocation_id", json!("b".repeat(32))),
            ("/maximum_root_physical_bytes", json!(300_000_000_000u64)),
            ("/trip_reason", json!("disk")),
            ("/available_bytes", json!(c::FLOOR - 1)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                guard(&bad, &p, &launch, &d, owner, t, t, plan_sha).is_err(),
                "{pointer}"
            );
        }
        let mut wrong = p.clone();
        wrong["worker_root"] = json!(format!("{}/scratch", c::ROOT));
        assert!(guard(&g, &wrong, &launch, &d, owner, t, t, plan_sha).is_err());
        assert!(guard(&g, &p, &launch, &d, owner, t + 1, t + 1, plan_sha).is_err());
        assert!(guard(&g, &p, &launch, &d, owner, t, t + 1801, plan_sha).is_err());
    }
    #[test]
    fn peer_roster_and_accounting_view_preserve_original_claims_and_failed_history() {
        let history = native210_peer_history::fixture(false);
        let other = json!({"epoch":209,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "unit":{"Id":singleton209::UNIT,"InvocationID":"a".repeat(32),"NRestarts":"0"}});
        let row = fixture_row();
        let f = json!({"active":[other,row],"diagnostics":history["diagnostics"],"epochs":history["epochs"],
            "unit_census":history["unit_census"],"plan":"original-accepted-plan","plan_sha256":"b".repeat(64)});
        let before = f.clone();
        assert_eq!(roster(&f).unwrap().len(), 2);
        assert!(
            prefix223_native20_admission::roster(&f).is_err(),
            "223's own self-overlap guard must remain unchanged"
        );
        let view = without_peer(&f).unwrap();
        assert_eq!(view["active"], json!([other]));
        for field in [
            "diagnostics",
            "epochs",
            "unit_census",
            "plan",
            "plan_sha256",
        ] {
            assert_eq!(view[field], f[field], "{field}");
        }
        assert_eq!(f, before);
        for (pointer, value) in [
            ("/epoch", json!(210)),
            ("/phase", json!("replay")),
            ("/ordinary_replay_claim", json!(true)),
            ("/launch_receipt_sha256", json!("a".repeat(64))),
            ("/producer/InvocationID", json!("b".repeat(32))),
            ("/producer/NRestarts", json!("1")),
        ] {
            let mut bad = row.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(without_peer(&json!({"active":[bad]})).is_err(), "{pointer}");
        }
        assert!(without_peer(&json!({"active":[row,row]})).is_err());
        assert!(
            without_peer(&json!({"active":[{"epoch":223,"unit":{"Id":"unknown223.service"}}]}))
                .is_err()
        );
        let owner = singleton227_admission::active_owner(&row).unwrap();
        current_shape(owner, owner).unwrap();
        let mut changed = owner.clone();
        changed["MainPID"] = json!("1");
        assert!(current_shape(owner, &changed).is_err());
    }
    #[test]
    fn whole_root_credit_is_same_invocation_bounded_and_requires_actual_observation() {
        let row = json!({"producer_unit":c::UNIT,"status":"observed","error":null,"scratch_path":c::ROOT,
            "observation":{"scratch_path":c::ROOT,"invocation_binding_stable":true,
                "producer_before":{"unit":c::UNIT,"invocation_id":IID},"producer_after":{"unit":c::UNIT,"invocation_id":IID},
                "conservative_observed_physical_bytes":70_000_000_000u64}});
        let o = json!({"diagnostic_replays":[row]});
        let g =
            json!({"root_physical_observation":{"conservative_physical_bytes":80_000_000_000u64}});
        assert_eq!(allocation(&o, &g, IID).unwrap().0, 70_000_000_000);
        let mut smaller = g.clone();
        smaller["root_physical_observation"]["conservative_physical_bytes"] =
            json!(60_000_000_000u64);
        assert_eq!(allocation(&o, &smaller, IID).unwrap().0, 60_000_000_000);
        let mut bootstrap = o.clone();
        bootstrap["diagnostic_replays"][0]["observation"]["conservative_observed_physical_bytes"] =
            json!(0);
        // Initial restoration has no slot/entry progress or output; keep the whole envelope reserved.
        assert_eq!(allocation(&bootstrap, &g, IID).unwrap().0, 0);
        for pointer in ["/scratch_path", "/observation/scratch_path"] {
            let mut bad = row.clone();
            *bad.pointer_mut(pointer).unwrap() = json!(format!("{}/scratch", c::ROOT));
            assert!(allocation(&json!({"diagnostic_replays":[bad]}), &g, IID).is_err());
        }
        assert!(allocation(&json!({"diagnostic_replays":[]}), &g, IID).is_err());
        assert!(allocation(&json!({"diagnostic_replays":[row,row]}), &g, IID).is_err());
        assert!(allocation(&o, &g, &"a".repeat(32)).is_err());
    }
    #[test]
    fn raw_225gb_limits_only_accept_exact_kernel_rounding_and_remaining_charge() {
        let v = launch();
        let cap = 224_999_997_440;
        let high = 149_999_996_928;
        let used = 80_000_000_000;
        assert_eq!(
            memory_limits(&v, cap, high, used, 0, 4096).unwrap(),
            cap - used
        );
        for (max, watermark, charge, swap, page) in [
            (225_000_000_000, high, used, 0, 4096),
            (cap + 4096, high, used, 0, 4096),
            (cap, high + 4096, used, 0, 4096),
            (cap, high, cap + 1, 0, 4096),
            (cap, high, used, 1, 4096),
            (cap, high, used, 0, 0),
            (cap, high, used, 0, 5000),
        ] {
            assert!(memory_limits(&v, max, watermark, charge, swap, page).is_err());
        }
        let mut changed = v;
        changed["maximum_memory_bytes"] = json!(300_000_000_000u64);
        assert!(memory_limits(&changed, cap, high, used, 0, 4096).is_err());
    }
}
