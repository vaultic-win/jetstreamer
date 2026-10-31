//! Account for a live native 209 peer without removing any unrelated owner.
use super::native209 as peer;
use super::*;

fn accepted(f: &Value) -> Result<Option<PipelineClaim>> {
    let rows = f["active"]
        .as_array()
        .context("228 complete active census")?;
    let mut found = None;
    for row in rows {
        let owner = singleton227_admission::active_owner(row)?;
        if owner["Id"] != peer::UNIT {
            continue;
        }
        ensure!(found.is_none(), "228 duplicate native 209 peer");
        ensure!(
            row["epoch"] == 209
                && row["phase"] == "private-cold-snapshot-verification"
                && row["ordinary_replay_claim"] == false
                && owner["ControlGroup"] == format!("/system.slice/{}", peer::UNIT),
            "228 native 209 peer shape differs"
        );
        let plan: Plan = serde_json::from_value(bound_json(&BoundFile {
            path: f["plan"].as_str().context("228 peer fleet plan")?.into(),
            sha256: f["plan_sha256"]
                .as_str()
                .context("228 peer plan digest")?
                .into(),
        })?)?;
        let matches = plan
            .pipeline_claims
            .iter()
            .filter(|c| c.unit == peer::UNIT)
            .collect::<Vec<_>>();
        ensure!(
            matches.len() == 1,
            "228 native 209 registered origin absent or duplicate"
        );
        let c: PipelineClaim = serde_json::from_value(serde_json::to_value(matches[0])?)?;
        ensure!(
            c.invocation_id == owner["InvocationID"]
                && c.evidence == serde_json::from_value::<Vec<BoundFile>>(row["evidence"].clone())?,
            "228 native 209 accepted origin changed"
        );
        peer::live(&c, owner)?;
        found = Some(c);
    }
    Ok(found)
}

fn reduced(f: &Value, c: &PipelineClaim) -> Result<Value> {
    let mut reduced = f.clone();
    reduced["active"]
        .as_array_mut()
        .context("228 derived active census")?
        .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != c.unit));
    Ok(reduced)
}

pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let Some(c) = accepted(f)? else {
        return native209_admission::auxiliary_memory(f);
    };
    let group = Path::new("/sys/fs/cgroup/system.slice").join(&c.unit);
    let read =
        |name: &str| -> Result<u64> { Ok(fs::read_to_string(group.join(name))?.trim().parse()?) };
    let cap = read("memory.max")?;
    let high = read("memory.high")?;
    let charge = read("memory.current")?;
    ensure!(
        cap == peer::MEMORY
            && high == 112u64 << 30
            && read("memory.swap.max")? == 0
            && charge <= cap,
        "228 native 209 cgroup memory controls differ"
    );
    let remaining = cap - charge;
    let (base, mut evidence) = native209_admission::auxiliary_memory(&reduced(f, &c)?)?;
    evidence.push(json!({"epoch":209,"unit":c.unit,"invocation_id":c.invocation_id,
        "hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,
        "remaining_hard_memory_growth_bytes":remaining,"origin":private157::binding(&c.evidence[0])}));
    Ok((
        base.checked_add(remaining)
            .context("228 peer memory overflow")?,
        evidence,
    ))
}

fn guard(g: &Value, c: &PipelineClaim, origin: &Value, sample: u64, now: u64) -> Result<()> {
    let plan: BoundFile = serde_json::from_value(origin["guard_plan"].clone())?;
    let p = peer::immutable_json(&plan)?;
    let t = g["recorded_unix_seconds"]
        .as_u64()
        .context("228209 guard clock")?;
    ensure!(
        t >= sample
            && t <= now
            && now - t <= 1800
            && p["unit"] == peer::UNIT
            && p["invocation_id"] == c.invocation_id
            && p["worker_root"] == peer::ROOT
            && p["filesystem"] == "/"
            && p["maximum_root_physical_bytes"] == peer::SCRATCH
            && p["maximum_worker_vmas"] == 3500000
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == peer::GUARD_SHA
            && g["plan_sha256"] == plan.sha256
            && g["producer_invocation_id"] == c.invocation_id
            && g["producer"]["invocation_id"] == c.invocation_id
            && g["producer"]["pid"] == origin["main_pid"]
            && g["producer"]["cgroup"] == format!("/system.slice/{}", c.unit)
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g["native_main"] == p["native_main"]
            && g["native_main"]["executable"] == peer::TEST
            && g["native_main"]["sha256"] == peer::TEST_SHA
            && g["native_main"]["main_pid"] == origin["main_pid"]
            && g["maximum_root_physical_bytes"] == peer::SCRATCH
            && g["root_physical_observation"]["maximum_physical_bytes"] == peer::SCRATCH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= peer::SCRATCH)
            && g["maximum_worker_vmas"] == 3500000
            && g["workers"].as_array().is_some_and(|r| r.len() == 1)
            && g["workers"][0][0] == origin["main_pid"]
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
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
        "228 native 209 protective guard differs or tripped"
    );
    Ok(())
}

pub(super) fn disk(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let Some(c) = accepted(f)? else {
        return native209_admission::protected_growth(f, o, guards, sample, now);
    };
    let mut remaining_guards: BTreeMap<String, BoundFile> =
        serde_json::from_value(serde_json::to_value(guards)?)?;
    let binding = remaining_guards
        .remove(peer::UNIT)
        .context("228209 current protective guard missing")?;
    let g = bound_json(&binding)?;
    let origin = peer::immutable_json(&c.evidence[0])?;
    guard(&g, &c, &origin, sample, now)?;
    let (base, mut evidence) =
        native209_admission::protected_growth(&reduced(f, &c)?, o, &remaining_guards, sample, now)?;
    // No sampled scratch credit: reclaimed allocations cannot reduce this reservation.
    evidence.push(
        json!({"epoch":209,"unit":c.unit,"invocation_id":c.invocation_id,
        "remaining_growth_bytes":peer::SCRATCH,"scratch_growth_credit_bytes":0,
        "origin":private157::binding(&c.evidence[0]),"guard":private157::binding(&binding)}),
    );
    Ok((
        base.checked_add(peer::SCRATCH)
            .context("228209 disk overflow")?,
        evidence,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn derived_peer_subcensus_preserves_failed_history_and_every_other_owner() {
        let c = PipelineClaim {
            epoch: 209,
            phase: "private-cold-snapshot-verification".into(),
            unit: peer::UNIT.into(),
            invocation_id: "a".repeat(32),
            expected_exec_start: "fixture".into(),
            evidence: vec![],
        };
        let f = json!({"active":[
            {"epoch":209,"unit":{"Id":peer::UNIT}},
            {"epoch":223,"unit":{"Id":"new-v2-owner"}},
            {"epoch":227,"producer":{"Id":singleton227::UNIT}},
            {"epoch":999,"unknown":"never silently discard"}
        ],"failed":[{"epoch":223,"generation":"v1"}],"plan":"accepted-original"});
        let view = reduced(&f, &c).unwrap();
        assert_eq!(view["active"].as_array().unwrap().len(), 3);
        assert_eq!(view["active"][0], f["active"][1]);
        assert_eq!(view["active"][1], f["active"][2]);
        assert_eq!(view["active"][2], f["active"][3]);
        assert_eq!(view["failed"], f["failed"]);
        assert_eq!(view["plan"], f["plan"]);
        assert_eq!(f["active"].as_array().unwrap().len(), 4);
        assert!(accepted(&json!({"active":[{"unknown":true}]})).is_err());
    }
}
