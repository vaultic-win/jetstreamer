//! An admitted zero-entry native input test may join the existing sample.
//! The event never replaces resource observation or rewrites campaign history.
use super::*;

pub(in crate::fleet) fn event_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA
            && previous["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && proof["schema"] == NATIVE20.intent_schema
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b))
            && proof["resource_samples_taken"] == 0,
        "native20 event cannot replace the accepted resource sample"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("native20 event clock")?;
    ensure!(
        clock > utc_seconds(sampled)?
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "native20 event stale or backdated"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("native20 predecessor plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("native20 predecessor digest")?
            .into(),
    })?)?;
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|c| c.unit == NATIVE20.unit)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "native20 event needs exactly one new owner"
    );
    let claim = claims[0];
    validate(claim)?;
    ensure!(
        p.metadata_event.as_ref() == claim.evidence.first()
            && claim.invocation_id == proof["invocation_id"]
            && p.pipeline_claims.len() == old.pipeline_claims.len() + 1
            && !old.pipeline_claims.iter().any(|c| c.unit == NATIVE20.unit)
            && old
                .pipeline_claims
                .iter()
                .all(|c| p.pipeline_claims.contains(c)),
        "native20 event changed pipeline history"
    );
    let mut names = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    names.insert(NATIVE20.unit.into());
    ensure!(
        names == p.tracked_units.iter().cloned().collect::<BTreeSet<_>>()
            && old.diagnostics.len() == p.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt)),
        "native20 event hid or changed prior owners"
    );
    ensure!(
        old.gates.len() == p.gates.len(),
        "native20 gate census differs"
    );
    for (epoch, gate) in &old.gates {
        let new = p.gates.get(epoch).context("native20 gate missing")?;
        ensure!(
            new.state == gate.state
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 223 || new.next_action == gate.next_action),
            "native20 event changed unrelated work"
        );
    }
    ensure!(
        p.gates[&223].state == "failed-needs-repair",
        "native input test cannot close223 repair"
    );
    Ok(())
}

fn protected_owners(previous: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    let rows = previous["active"]
        .as_array()
        .context("native20 prior active census")?;
    ensure!(
        rows.len() == 3,
        "native20 expected three protected replay owners"
    );
    let mut names = BTreeSet::new();
    for row in rows {
        let before = if row["producer"].is_object() {
            &row["producer"]
        } else {
            &row["unit"]
        };
        let name = before["Id"].as_str().context("native20 protected unit")?;
        ensure!(
            names.insert(name.to_string()),
            "duplicate native20 protected unit"
        );
        let current = census
            .get(name)
            .context("native20 protected owner missing")?;
        for key in [
            "Id",
            "InvocationID",
            "MainPID",
            "NRestarts",
            "ActiveState",
            "SubState",
        ] {
            ensure!(
                current[key] == before[key],
                "native20 protected owner changed:{name}:{key}"
            );
        }
        ensure!(
            current["NRestarts"] == "0"
                && diagnostic_stage_running(current)
                && pipeline_status::same_exec_start(
                    before["ExecStart"]
                        .as_str()
                        .context("native20 prior command")?,
                    current["ExecStart"]
                        .as_str()
                        .context("native20 current command")?
                ),
            "native20 protected command or live identity changed"
        );
    }
    for (name, state) in census {
        ensure!(
            !diagnostic_stage_running(state) || names.contains(name) || name == NATIVE20.unit,
            "native20 unaccounted live competitor:{name}"
        );
    }
    Ok(())
}

pub(in crate::fleet) fn event_census(p: &Plan, census: &BTreeMap<String, Value>) -> Result<()> {
    if let Some(binding) = &p.metadata_event {
        let proof = bound_json(binding)?;
        if proof["schema"] == NATIVE20.intent_schema {
            let previous = bound_json(
                p.previous_fleet
                    .as_ref()
                    .context("native20 event prior fleet")?,
            )?;
            protected_owners(&previous, census)?;
            let claim = p
                .pipeline_claims
                .iter()
                .find(|c| c.unit == NATIVE20.unit)
                .context("native20 event claim")?;
            validate_live(
                claim,
                census
                    .get(NATIVE20.unit)
                    .context("native20 new owner missing")?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, BTreeMap<String, Value>) {
        let mut census = BTreeMap::new();
        let mut active = Vec::new();
        for index in 0..3 {
            let name = format!("horizon-protected-{index}.service");
            let state = json!({"Id":name,"InvocationID":format!("{index:032x}"),"MainPID":"42",
                "NRestarts":"0","ActiveState":"active","SubState":"running",
                "ExecStart":"{ path=/sealed/worker ; argv[]=/sealed/worker --fixed ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }"});
            active.push(json!({"producer":state}));
            census.insert(name, state);
        }
        (json!({"active":active}), census)
    }
    #[test]
    fn event_preserves_all_three_old_owners_and_rejects_new_competitors() {
        let (previous, census) = fixture();
        protected_owners(&previous, &census).unwrap();
        for key in ["InvocationID", "MainPID", "NRestarts", "ExecStart"] {
            let mut bad = census.clone();
            bad.get_mut("horizon-protected-0.service").unwrap()[key] = json!("changed");
            assert!(protected_owners(&previous, &bad).is_err(), "{key}");
        }
        let mut extra = census.clone();
        extra.insert(
            "untracked.service".into(),
            census.values().next().unwrap().clone(),
        );
        assert!(protected_owners(&previous, &extra).is_err());
    }
}
