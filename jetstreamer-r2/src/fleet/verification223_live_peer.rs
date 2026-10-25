//! Preserve all existing prefix/full210 owners and add only exact private verification.
use super::assembly223_live_peer as base;
use super::verification223 as c;
use super::*;
#[cfg(test)]
pub(super) use base::fixture_row;
fn without(f: &Value) -> Result<Value> {
    let mut seen = false;
    let mut count = 0;
    for row in f["active"]
        .as_array()
        .context("verification 223 complete owner roster")?
    {
        if row["epoch"] == 223 {
            count += 1;
        }
        let owner = singleton227_admission::active_owner(row)?;
        if owner["Id"] != c::UNIT {
            continue;
        }
        ensure!(
            !seen
                && row["epoch"] == 223
                && row["phase"] == "private-verification-only"
                && row["ordinary_replay_claim"] == false
                && owner["NRestarts"] == "0"
                && owner["InvocationID"]
                    .as_str()
                    .is_some_and(|s| s.len() == 32)
                && row["launch_receipt"] == format!("{}/launch.json", c::STATE)
                && canonical_digest(&row["launch_receipt_sha256"]),
            "verification 223 duplicate, changed or unrelated owner"
        );
        seen = true;
    }
    ensure!(
        !seen || count == 1,
        "verification 223 overlaps another active epoch 223 owner"
    );
    let mut out = f.clone();
    out["active"]
        .as_array_mut()
        .unwrap()
        .retain(|r| singleton227_admission::active_owner(r).map_or(true, |u| u["Id"] != c::UNIT));
    Ok(out)
}
fn claim(f: &Value, row: &Value) -> Result<(DiagnosticClaim, Value)> {
    let plan: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: f["plan"]
            .as_str()
            .context("verification 223 fleet plan")?
            .into(),
        sha256: f["plan_sha256"]
            .as_str()
            .context("verification 223 plan digest")?
            .into(),
    })?)?;
    let found = plan
        .diagnostics
        .iter()
        .filter(|d| c::namespace(d))
        .collect::<Vec<_>>();
    ensure!(
        found.len() == 1,
        "verification 223 needs exactly one authenticated claim"
    );
    let d = found[0];
    let owner = singleton227_admission::active_owner(row)?;
    ensure!(
        owner["InvocationID"] == d.invocation_id
            && owner["Id"] == d.unit
            && row["launch_receipt"].as_str() == d.launch_receipt.path.to_str()
            && row["launch_receipt_sha256"] == d.launch_receipt.sha256
            && c::root_scope(&d.scratch_path),
        "verification 223 claim/accepted owner differs"
    );
    let r = checked_diagnostic_launch(d)?;
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
        r,
    ))
}
fn rows(f: &Value) -> Result<Vec<&Value>> {
    Ok(f["active"]
        .as_array()
        .context("verification 223 owner census")?
        .iter()
        .filter(|r| singleton227_admission::active_owner(r).is_ok_and(|u| u["Id"] == c::UNIT))
        .collect())
}
pub(super) fn roster(f: &Value) -> Result<BTreeSet<String>> {
    let v = without(f)?;
    let mut names = base::roster(&v)?;
    if !rows(f)?.is_empty() {
        ensure!(
            names.insert(c::UNIT.into()),
            "verification 223 duplicate capacity owner"
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
    let v = without(f)?;
    let mut remaining = guards
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
    let mut extra = 0u64;
    let mut evidence = Vec::new();
    for row in rows(f)? {
        let (d, r) = claim(f, row)?;
        let gb = remaining
            .remove(c::UNIT)
            .context("verification 223 protective guard omitted")?;
        let g = bound_json(&gb)?;
        let pb: BoundFile = serde_json::from_value(r["guard_plan"].clone())?;
        let p = bound_json(&pb)?;
        let t = g["recorded_unix_seconds"]
            .as_u64()
            .context("verification 223 guard timestamp")?;
        ensure!(
            c::guard_matches(&d, &r, &p)
                && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                && g["bounded_measurement"] == false
                && g.get("target_handoff").is_some_and(Value::is_null)
                && g["producer"]["unit"] == c::UNIT
                && g["producer"]["kill_mode"] == "control-group"
                && g["producer"]["delegated"] == false
                && t >= sample
                && t <= now
                && now - t <= 1800
                && g["guard_sha256"] == c::GUARD_SHA
                && g["plan_sha256"] == pb.sha256
                && g["producer_invocation_id"] == d.invocation_id
                && g["producer"]["invocation_id"] == d.invocation_id
                && g["producer"]["active"] == "active"
                && g["producer"]["sub"] == "running"
                && g["producer"]["restarts"] == 0
                && g["producer"]["cgroup"] == format!("/system.slice/{}", c::UNIT)
                && g["producer"]["pid"]
                    .as_u64()
                    .map(|n| n.to_string())
                    .as_deref()
                    == singleton227_admission::active_owner(row)?["MainPID"].as_str()
                && g["producer_stop_enabled"] == true
                && g["workers"].as_array().is_some_and(Vec::is_empty)
                && g["minimum_free_bytes"] == p["minimum_free_bytes"]
                && g["available_bytes"]
                    .as_u64()
                    .zip(p["minimum_free_bytes"].as_u64())
                    .is_some_and(|(a, b)| a >= b)
                && [
                    "trip_reason",
                    "worker_observation_error",
                    "target_handoff_error"
                ]
                .iter()
                .all(|k| g.get(*k).is_some_and(Value::is_null))
                && g["r2_mutations"] == false
                && g["remote_mutations"] == false,
            "verification 223 protective evidence changed/stale/tripped"
        );
        let selected = warmup223::completed_guard_binding(
            c::GUARD_UNIT,
            Path::new(c::GUARD_RECEIPTS),
            sample,
            now,
        )?;
        ensure!(
            selected["binding"] == private157::binding(&gb),
            "verification 223 guard is not latest completed fire"
        );
        let timer = singleton227_capture::properties(
            &c::GUARD_UNIT.replace(".service", ".timer"),
            "ActiveState",
        )?;
        ensure!(
            timer.get("ActiveState").is_some_and(|s| s == "active"),
            "verification 223 protective timer inactive"
        );
        // No guessed allocation credit: the natural guard does not measure the
        // root. Keep the entire capped archive/metadata claim reserved.
        extra = extra
            .checked_add(c::PEAK)
            .context("verification 223 growth overflow")?;
        evidence.push(json!({"epoch":223,"unit":d.unit,"invocation_id":d.invocation_id,"guard":private157::binding(&gb),
            "remaining_growth_bytes":c::PEAK,"scratch_growth_credit_bytes":0,"source":"exact bounded private verifier; conservative full output reservation"}));
    }
    let (n, more) = base::disk(&v, o, &remaining, sample, now)?;
    evidence.extend(more);
    Ok((
        n.checked_add(extra)
            .context("verification 223 combined growth overflow")?,
        evidence,
    ))
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    roster(f)?;
    let mut extra = 0u64;
    let mut proof = Vec::new();
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        c::live_limits(&d.scratch_path)?;
        let path = Path::new("/sys/fs/cgroup/system.slice").join(c::UNIT);
        ensure!(
            path.canonicalize()? == path,
            "verification 223 cgroup redirected"
        );
        let read =
            |n: &str| -> Result<u64> { Ok(fs::read_to_string(path.join(n))?.trim().parse()?) };
        let cap = read("memory.max")?;
        let charge = read("memory.current")?;
        ensure!(
            cap == c::MEMORY
                && read("memory.high")? == (48u64 << 30)
                && read("memory.swap.max")? == 0
                && charge <= cap,
            "verification 223 cgroup envelope changed"
        );
        extra = extra
            .checked_add(cap - charge)
            .context("verification 223 memory overflow")?;
        proof.push(json!({"unit":d.unit,"invocation_id":d.invocation_id,"hard_memory_cap_bytes":cap,"current_cgroup_charge_bytes":charge,"remaining_hard_memory_growth_bytes":cap-charge}));
    }
    let (n, more) = base::memory(&without(f)?)?;
    proof.extend(more);
    Ok((
        n.checked_add(extra)
            .context("verification 223 combined memory overflow")?,
        proof,
    ))
}
pub(super) fn limits(f: &Value) -> Result<Value> {
    roster(f)?;
    let mut out = base::limits(&without(f)?)?;
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        let p = c::live_limits(&d.scratch_path)?;
        ensure!(
            out.as_object_mut()
                .context("protected caps")?
                .insert(c::UNIT.into(), json!(p))
                .is_none(),
            "verification 223 cap collision"
        );
    }
    Ok(out)
}
pub(super) fn current(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    roster(f)?;
    base::current(&without(f)?, current)?;
    for row in rows(f)? {
        let (d, _) = claim(f, row)?;
        let live = current
            .get(c::UNIT)
            .context("verification 223 current owner omitted")?;
        c::validate_live(&d, live)?;
        let old = singleton227_admission::active_owner(row)?;
        for k in [
            "Id",
            "InvocationID",
            "MainPID",
            "NRestarts",
            "ControlGroup",
            "ActiveState",
            "SubState",
        ] {
            ensure!(old[k] == live[k], "verification 223 owner changed:{k}");
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn assembly() -> Value {
        json!({"epoch":223,"phase":"private-verification-only","ordinary_replay_claim":false,
            "launch_receipt":format!("{}/launch.json",c::STATE),"launch_receipt_sha256":"c".repeat(64),
            "producer":{"Id":c::UNIT,"InvocationID":"1".repeat(32),"NRestarts":"0"}})
    }
    #[test]
    fn exact_assembly_keeps_full_210_and_all_failed_history_in_the_authoritative_fleet() {
        let full = json!({"epoch":210,"phase":"diagnostic-qualification","ordinary_replay_claim":false,
            "unit":{"Id":singleton210::UNIT,"InvocationID":"a".repeat(32),"NRestarts":"0"}});
        let f = json!({"active":[full,assembly()],"diagnostics":[{"history":"retained"}],"epochs":[{"epoch":223,"state":"failed-needs-repair"}],
            "plan":"/unchanged/plan","plan_sha256":"b".repeat(64),"unit_census":{"kept":{}}});
        let original = f.clone();
        let v = without(&f).unwrap();
        assert_eq!(v["active"], json!([full]));
        assert_eq!(
            roster(&f).unwrap(),
            BTreeSet::from([c::UNIT.to_owned(), singleton210::UNIT.to_owned()])
        );
        for field in [
            "diagnostics",
            "epochs",
            "plan",
            "plan_sha256",
            "unit_census",
        ] {
            assert_eq!(v[field], f[field], "{field}");
        }
        assert_eq!(f, original);
    }
    #[test]
    fn unknown_or_overlapping_223_is_never_erased_from_capacity() {
        let row = assembly();
        assert!(without(&json!({"active":[row,row]})).is_err());
        assert!(without(&json!({"active":[row,base::fixture_row()]})).is_err());
        for (pointer, value) in [
            ("/epoch", json!(222)),
            ("/phase", json!("replay")),
            ("/ordinary_replay_claim", json!(true)),
            ("/producer/NRestarts", json!("1")),
            ("/launch_receipt_sha256", json!("unbound")),
        ] {
            let mut bad = row.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(roster(&json!({"active":[bad]})).is_err(), "{pointer}");
        }
        assert!(
            roster(&json!({"active":[{"epoch":223,"producer":{"Id":"unmodeled.service"}}]}))
                .is_err()
        );
    }
}
