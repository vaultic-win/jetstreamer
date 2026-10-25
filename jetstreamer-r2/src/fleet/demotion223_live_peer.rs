//! Exact registered repair tasks retain their complete live envelope.
//! This adapter never gives credit for a pending replacement or reclaimed data.
use super::{verification223_live_peer as base, *};
#[cfg(test)]
pub(super) use base::fixture_row;

pub(super) fn selected(row: &Value) -> bool {
    singleton227_admission::active_owner(row)
        .ok()
        .and_then(|u| u["Id"].as_str())
        .is_some_and(|n| demotion223_status::scope("epoch223-demotion-repair", n))
}
fn rows(f: &Value) -> Result<Vec<&Value>> {
    Ok(f["active"]
        .as_array()
        .context("223 repair peer roster")?
        .iter()
        .filter(|r| selected(r))
        .collect())
}
fn contract(f: &Value, row: &Value) -> Result<Value> {
    demotion223_status::resource_contract(&demotion223_status::accepted_claim(f, row)?)
}
pub(super) fn without(f: &Value) -> Result<Value> {
    let selected = rows(f)?;
    ensure!(
        selected.len() <= 1
            && (selected.is_empty()
                || f["active"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["epoch"] == 223)
                    .count()
                    == 1),
        "223 repair overlaps another accepted owner"
    );
    for row in selected {
        demotion223_status::accepted_claim(f, row)?;
    }
    let mut copy = f.clone();
    copy["active"]
        .as_array_mut()
        .unwrap()
        .retain(|r| !self::selected(r));
    Ok(copy)
}
pub(super) fn roster(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = base::roster(&without(f)?)?;
    for row in rows(f)? {
        ensure!(
            names.insert(demotion223_status::accepted_claim(f, row)?.unit),
            "duplicate223 repair peer"
        );
    }
    Ok(names)
}
pub(super) fn guard_evidence(f: &Value, name: &str, binding: &BoundFile) -> Result<Option<Value>> {
    for row in rows(f)? {
        let c = demotion223_status::accepted_claim(f, row)?;
        if c.unit == name {
            let v = contract(f, row)?;
            ensure!(
                v["guard_plan"] == private157::binding(binding),
                "223 accepted guard plan changed"
            );
            return Ok(Some(v));
        }
    }
    Ok(None)
}
pub(super) fn disk(
    f: &Value,
    o: &Value,
    guards: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(u64, Vec<Value>)> {
    let mut rest = guards.clone();
    let mut extra = 0u64;
    let mut evidence = Vec::new();
    for row in rows(f)? {
        let c = demotion223_status::accepted_claim(f, row)?;
        let b = rest
            .remove(&c.unit)
            .context("223 repair protective guard omitted")?;
        let v = guard_evidence(f, &c.unit, &b)?.context("223 repair guard missing")?;
        extra = extra
            .checked_add(
                v["remaining_disk_growth_bytes"]
                    .as_u64()
                    .context("223 disk envelope")?,
            )
            .context("223 disk overflow")?;
        evidence.push(v);
    }
    let (base, mut other) = base::disk(&without(f)?, o, &rest, sample, now)?;
    other.extend(evidence);
    Ok((
        base.checked_add(extra).context("223 total disk overflow")?,
        other,
    ))
}
pub(super) fn memory(f: &Value) -> Result<(u64, Vec<Value>)> {
    let (mut total, mut evidence) = base::memory(&without(f)?)?;
    for row in rows(f)? {
        let v = contract(f, row)?;
        // Deliberately full caps, including accepted guard and issuer. Do not
        // subtract current charge or the separately pending candidate budget.
        total = total
            .checked_add(
                v["complete_actor_memory_reservation_bytes"]
                    .as_u64()
                    .context("223 full memory envelope")?,
            )
            .context("223 memory overflow")?;
        evidence.push(v);
    }
    Ok((total, evidence))
}
pub(super) fn limits(f: &Value) -> Result<Value> {
    let mut result = base::limits(&without(f)?)?;
    for row in rows(f)? {
        let c = demotion223_status::accepted_claim(f, row)?;
        let mut caps = contract(f, row)?;
        caps.as_object_mut()
            .context("223 resource map")?
            .remove("observed_unix_millis");
        for key in ["kernel", "guard_kernel"] {
            caps[key]
                .as_object_mut()
                .context("223 kernel map")?
                .remove("current");
        }
        ensure!(
            result
                .as_object_mut()
                .context("223 limits map")?
                .insert(c.unit, caps)
                .is_none(),
            "223 cap owner collision"
        );
    }
    Ok(result)
}
pub(super) fn current(f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    base::current(&without(f)?, census)?;
    for row in rows(f)? {
        let c = demotion223_status::accepted_claim(f, row)?;
        let live = census
            .get(&c.unit)
            .context("223 accepted current owner omitted")?;
        demotion223_status::validate_claim(&c, Some(live))?;
    }
    current_guards(f, census)?;
    Ok(())
}
fn actor_row(actor: &Value, row: &Value) -> Result<()> {
    ensure!(
        row["Id"] == actor["unit"]
            && row["InvocationID"] == actor["invocation_id"]
            && row["NRestarts"] == "0"
            && row["ActiveState"] == "active"
            && row["SubState"] == "running"
            && row["ControlGroup"] == actor["cgroup"]
            && row["MainPID"].as_str().and_then(|s| s.parse::<u64>().ok()) == actor["pid"].as_u64()
            && row["ExecStart"]
                .as_str()
                .zip(actor["expected_exec_start"].as_str())
                .is_some_and(|(a, b)| pipeline_status::same_exec_start(a, b)),
        "223 accepted guard replaced/restarted or changed command/cgroup"
    );
    Ok(())
}
pub(super) fn current_guards(f: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    for row in rows(f)? {
        let v = contract(f, row)?;
        let guard = &v["guard_actor"];
        let name = guard["unit"].as_str().context("223 accepted guard name")?;
        actor_row(guard, &f["unit_census"][name])?;
        actor_row(
            guard,
            census.get(name).context("223 accepted guard omitted")?,
        )?;
    }
    Ok(())
}

pub(super) fn accepted_guard_names(f: &Value) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for row in rows(f)? {
        let v = contract(f, row)?;
        ensure!(
            names.insert(
                v["guard_actor"]["unit"]
                    .as_str()
                    .context("223 guard name")?
                    .into()
            ),
            "223 duplicate guard"
        );
    }
    Ok(names)
}

fn host_actor(o: &Value, actor: &Value) -> Result<()> {
    for phase in ["before", "after"] {
        let host = &o["host_resident_memory"][phase];
        ensure!(
            host["status"] == "observed"
                && host["rss"]["census_stable"] == true
                && host["rss"]["error"].is_null(),
            "223 host RSS census unavailable/unstable"
        );
        let matches: Vec<_> = host["rss"]["processes"]
            .as_array()
            .context("223 host RSS processes")?
            .iter()
            .filter(|p| p["pid"] == actor["pid"])
            .collect();
        ensure!(
            matches.len() == 1
                && matches[0]["start_ticks"] == actor["start_ticks"]
                && matches[0]["rss_bytes"].as_u64().is_some_and(|n| n > 0),
            "223 actor missing/reused in whole host RSS"
        );
    }
    Ok(())
}
pub(super) fn memory_owners(f: &Value, o: &Value) -> Result<BTreeMap<String, Value>> {
    without(f)?;
    let mut proofs = BTreeMap::new();
    for row in rows(f)? {
        let c = demotion223_status::accepted_claim(f, row)?;
        let v = contract(f, row)?;
        for actor in [&v["actor"], &v["guard_actor"]] {
            host_actor(o, actor)?;
        }
        proofs.insert(c.unit.clone(),json!({"schema":"jetstreamer-epoch223-repair-non-replay-memory-owner-v1","unit":c.unit,"invocation_id":c.invocation_id,
            "sampled_at_utc":o["recorded_at_utc"],"resource_contract":v,"included_in_whole_host_resident_memory":true,
            "executing_entry_replay":false,"disk_or_hard_memory_growth_exempted":false}));
    }
    Ok(proofs)
}

pub(super) fn memory_views(
    f: &Value,
    o: &Value,
) -> Result<(Value, Value, BTreeMap<String, Value>)> {
    let proofs = memory_owners(f, o)?;
    Ok((without(f)?, normalize_observer(o, &proofs)?, proofs))
}
fn normalize_observer(o: &Value, proofs: &BTreeMap<String, Value>) -> Result<Value> {
    let mut view = o.clone();
    for row in o["replays"]
        .as_array()
        .context("223 ordinary RSS observations")?
    {
        ensure!(
            !proofs.contains_key(row["producer_after"]["unit"].as_str().unwrap_or("")),
            "223 repair cannot be an ordinary replay observation"
        );
    }
    let diagnostics = view["diagnostic_replays"]
        .as_array_mut()
        .context("223 diagnostic RSS observations")?;
    for row in diagnostics.iter() {
        if let Some(proof) = proofs.get(row["producer_unit"].as_str().unwrap_or("")) {
            ensure!(
                row["status"] == "observed"
                    && row["error"].is_null()
                    && row["observation"]["invocation_binding_stable"] == true
                    && row["observation"]["producer_before"]["invocation_id"]
                        == proof["invocation_id"]
                    && row["observation"]["producer_after"]["invocation_id"]
                        == proof["invocation_id"],
                "223 repair diagnostic observation differs"
            );
        }
    }
    diagnostics.retain(|r| !proofs.contains_key(r["producer_unit"].as_str().unwrap_or("")));
    for row in o["replays"].as_array().unwrap().iter().chain(
        diagnostics
            .iter()
            .filter_map(|r| (r["status"] == "observed").then_some(&r["observation"])),
    ) {
        for proof in proofs.values() {
            for role in [
                "controller_before",
                "controller_after",
                "producer_before",
                "producer_after",
            ] {
                for key in ["actor", "guard_actor"] {
                    let pid = &proof["resource_contract"][key]["pid"];
                    ensure!(
                        row[role]["rss"]["processes"]
                            .as_array()
                            .is_none_or(|p| p.iter().all(|p| p["pid"] != *pid)),
                        "223 repair/guard RSS attributed to executing replay"
                    );
                }
            }
        }
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let actor = json!({"unit":"horizon-guard-223-demotion-fixture.service","invocation_id":"a".repeat(32),"pid":12,"cgroup":"/system.slice/horizon-guard-223-demotion-fixture.service","expected_exec_start":"fixture-command"});
        let row = json!({"Id":actor["unit"],"InvocationID":actor["invocation_id"],"MainPID":"12","ControlGroup":actor["cgroup"],"NRestarts":"0","ActiveState":"active","SubState":"running","ExecStart":"fixture-command"});
        (actor, row)
    }
    #[test]
    fn accepted_guard_identity_rejects_replacement_restart_command_and_malformed_pid() {
        let (actor, row) = fixture();
        actor_row(&actor, &row).unwrap();
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("NRestarts", json!("1")),
            ("MainPID", json!(12)),
            ("ControlGroup", json!("/foreign")),
            ("ExecStart", json!("foreign-command")),
            ("SubState", json!("dead")),
        ] {
            let mut bad = row.clone();
            bad[key] = value;
            assert!(actor_row(&actor, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn repair_claim_scope_rejects_foreign_epoch_phase_and_ordinary_replay_before_file_reads() {
        let valid = json!({"epoch":223,"phase":"epoch223-demotion-repair","ordinary_replay_claim":false,
            "unit":{"Id":"horizon-native-input-223-demotion-fixture.service"}});
        for (key, value) in [
            ("epoch", json!(222)),
            ("phase", json!("private-cold-snapshot-verification")),
            ("ordinary_replay_claim", json!(true)),
        ] {
            let mut bad = valid.clone();
            bad[key] = value;
            assert!(
                demotion223_status::accepted_claim(&json!({}), &bad)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("scope changed")
            );
        }
        assert!(
            without(&json!({"active":[valid.clone(),valid]}))
                .unwrap_err()
                .to_string()
                .contains("overlaps")
        );
    }
    #[test]
    fn repair_overhead_stays_in_host_rss_and_never_becomes_an_entry_replay_lane() {
        let name = "horizon-native-input-223-demotion-fixture.service";
        let actor = json!({"pid":12,"start_ticks":30});
        let host = json!({"status":"observed","rss":{"census_stable":true,"error":null,"processes":[{"pid":12,"start_ticks":30,"rss_bytes":1000}]}});
        let o = json!({"host_resident_memory":{"before":host,"after":host},"replays":[],"diagnostic_replays":[{"producer_unit":name,"status":"observed","error":null,"observation":{"invocation_binding_stable":true,"producer_before":{"invocation_id":"a"},"producer_after":{"invocation_id":"a"}}}]});
        host_actor(&o, &actor).unwrap();
        let proofs = BTreeMap::from([(
            name.into(),
            json!({"invocation_id":"a","resource_contract":{"actor":actor,"guard_actor":{"pid":13}}}),
        )]);
        let normalized = normalize_observer(&o, &proofs).unwrap();
        assert_eq!(
            normalized["host_resident_memory"],
            o["host_resident_memory"]
        );
        assert_eq!(normalized["replays"], json!([]));
        assert_eq!(normalized["diagnostic_replays"], json!([]));
        assert_eq!(o["diagnostic_replays"].as_array().unwrap().len(), 1);
        let mut reused = o.clone();
        reused["host_resident_memory"]["after"]["rss"]["processes"][0]["start_ticks"] = json!(31);
        assert!(host_actor(&reused, &actor).is_err());
        let mut missing = o.clone();
        missing["host_resident_memory"]["before"]["rss"]["processes"] = json!([]);
        assert!(host_actor(&missing, &actor).is_err());
        let mut changed = o.clone();
        changed["diagnostic_replays"][0]["observation"]["producer_after"]["invocation_id"] =
            json!("b");
        assert!(normalize_observer(&changed, &proofs).is_err());
        let mut wrong_lane = o.clone();
        wrong_lane["replays"] = json!([{"producer_after":{"unit":"other"},"producer_before":{"rss":{"processes":[{"pid":12}]}}}]);
        assert!(normalize_observer(&wrong_lane, &proofs).is_err());
    }
}
