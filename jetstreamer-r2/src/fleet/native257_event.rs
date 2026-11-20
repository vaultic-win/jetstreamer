//! Preserve unrelated owners and the original resource sample across epoch 257 events.
use super::native257 as c;
use super::native265::{num, sealed, text};
use super::*;
pub(super) fn prior(f: &Value) -> Result<Plan> {
    let plan = BoundFile {
        path: text(f, "plan")?.into(),
        sha256: text(f, "plan_sha256")?.into(),
    };
    Ok(serde_json::from_value(bound_json(&plan)?)?)
}
pub(super) fn owner(plan: &Plan) -> Result<Option<&PipelineClaim>> {
    let mut registered = plan.pipeline_claims.iter().filter(|r| r.unit == c::UNIT);
    let first = registered.next();
    ensure!(
        registered.next().is_none(),
        "native257 duplicate registered owner"
    );
    if let Some(r) = first {
        c::claim(r)?;
    }
    Ok(first)
}
pub(super) fn predecessor(
    previous: &Value,
    p: &Plan,
    event: &Value,
    sampled: &str,
    wall: u64,
) -> Result<()> {
    let b = p
        .metadata_event
        .as_ref()
        .context("native257 event binding")?;
    let o = owner(p)?.context("native257 event needs registered ownership")?;
    let running = event["schema"] == c::SCHEMA;
    let start = if running {
        ensure!(
            o.evidence.first() == Some(b),
            "native257 event substituted registered claim"
        );
        num(event, "recorded_unix_seconds")?
    } else {
        native257_terminal::validate(event, b)?;
        ensure!(
            event["running_origin"] == private157::binding(&o.evidence[0]),
            "native257 terminal registration differs"
        );
        num(event, "recorded_unix_seconds")?
    };
    ensure!(
        sealed(b)? == *event
            && start <= wall
            && wall - start <= 300
            && start > num(previous, "recorded_unix_seconds")?
            && p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == super::SCHEMA
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && previous["sampled_at_utc"] == sampled
            && event["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|f| event["fleet"] == private157::binding(f)),
        "native257 event substituted resource observer or prior fleet"
    );
    let old = prior(previous)?;
    if running {
        ensure!(
            owner(&old)?.is_none()
                && p.pipeline_claims.len() == old.pipeline_claims.len() + 1
                && old
                    .pipeline_claims
                    .iter()
                    .all(|r| p.pipeline_claims.contains(r)),
            "native257 changed existing pipeline ownership"
        );
        for r in previous["active"]
            .as_array()
            .context("native257 old active")?
        {
            if let Some(epoch) = r["epoch"].as_u64() {
                ensure!(epoch != 257, "native257 existing owner");
            } else {
                ensure!(
                    !parse_observer_claim_range(text(r, "range")?)?.contains(&257),
                    "native257 overlapping active range"
                );
            }
        }
    } else {
        ensure!(
            old.pipeline_claims == p.pipeline_claims && event["sampled_at_utc"] == sampled,
            "native257 terminal lost original registered history"
        );
    }
    let mut expected = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    if running {
        expected.insert(c::UNIT.to_owned());
    }
    ensure!(
        expected == p.tracked_units.iter().cloned().collect()
            && p.tracked_units.len() == expected.len()
            && p.schema == old.schema
            && p.first_epoch == old.first_epoch
            && p.last_epoch == old.last_epoch
            && p.observer == old.observer
            && p.status_receipt_directory == old.status_receipt_directory
            && p.runtime_handoff157 == old.runtime_handoff157
            && p.continuation203_runtime_extension == old.continuation203_runtime_extension
            && p.epoch203_ram_auxiliary.is_none()
            && old.epoch203_ram_auxiliary.is_none()
            && p.gates.len() == old.gates.len()
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt)),
        "native257 unrelated fleet settings changed"
    );
    for (epoch, g) in &old.gates {
        let n = p.gates.get(epoch).context("native257 gate omitted")?;
        ensure!(
            native265_event::same_operator_status(&g.operator_status, &n.operator_status)
                && serde_json::to_value(&g.reserve_stop)? == serde_json::to_value(&n.reserve_stop)?,
            "native257 unrelated status/reserve changed"
        );
        if *epoch == 257 {
            ensure!(
                n.evidence.contains(b)
                    && g.evidence.iter().all(|v| n.evidence.contains(v))
                    && n.evidence.iter().all(|v| v == b || g.evidence.contains(v))
                    && (if running {
                        matches!(
                            g.state.as_str(),
                            "not-yet-staged"
                                | "staged-admissible"
                                | "blocked-qualification"
                                | "failed-needs-repair"
                        ) && n.state == "blocked-qualification"
                    } else {
                        g.state == "blocked-qualification"
                            && n.state
                                == if event["native_input_qualified"] == true {
                                    "blocked-qualification"
                                } else {
                                    "failed-needs-repair"
                                }
                    }),
                "native257 outcome gate mismatch"
            );
        } else {
            ensure!(
                n.state == g.state && n.evidence == g.evidence && n.next_action == g.next_action,
                "native257 unrelated gate changed"
            );
        }
    }
    Ok(())
}
fn telemetry(v: &Value, c: &PipelineClaim) -> Result<()> {
    let mut rows = v["diagnostic_replays"]
        .as_array()
        .context("native257 diagnostic telemetry census")?
        .iter()
        .filter(|r| r["range"] == "257-257" || r["producer_unit"] == super::native257::UNIT);
    let r = rows
        .next()
        .context("native257 missing resource observation")?;
    let obs = &r["observation"];
    ensure!(
        rows.next().is_none()
            && r["status"] == "observed"
            && r["expected_producer_invocation_id"] == c.invocation_id
            && r["range"] == "257-257"
            && r["producer_unit"] == super::native257::UNIT
            && r["native_resource_only"] == true
            && r["scratch_path"] == super::native257::ROOT
            && r["ordinary_replay_claim"] == false
            && r["entry_replay"] == false
            && obs["invocation_binding_stable"] == true
            && obs["resource_only"] == true
            && obs["native_input_qualified"] == false
            && obs["entry_replay"] == false
            && obs["publication_authorized"] == false,
        "native257 observation missing/ambiguous"
    );
    let origin = sealed(&c.evidence[0])?;
    let (h, _) = super::native257::startup(&native265::binding(&origin["startup_handoff"])?)?;
    let gp = sealed(&native265::binding(&h["guard_plan"])?)?;
    telemetry_images(obs, &origin, &gp)
}
fn telemetry_images(obs: &Value, origin: &Value, gp: &Value) -> Result<()> {
    let main = num(origin, "main_pid")?;
    let mut members = Vec::new();
    for side in ["before", "after"] {
        let image = &obs[format!("native_main_{side}")];
        ensure!(
            image["executable"] == super::native257::TEST
                && image["sha256"] == super::native257::TEST_SHA
                && image["pid"] == origin["main_pid"],
            "native257 telemetry harness differs"
        );
        let u = &obs[format!("producer_{side}")];
        let child = obs
            .get(format!("native_child_{side}").as_str())
            .context("native257 missing child census")?;
        ensure!(
            u["unit"] == c::UNIT
                && u["invocation_id"] == origin["invocation_id"]
                && u["main_pid"] == main
                && u["control_group"] == format!("/system.slice/{}", c::UNIT)
                && u["rss"]["census_stable"] == true
                && u["rss"].get("error") == Some(&Value::Null),
            "native257 RSS owner"
        );
        let rows = u["rss"]["processes"]
            .as_array()
            .context("native257 telemetry process census")?;
        let mut pids = BTreeMap::new();
        for row in rows {
            ensure!(
                pids.insert(num(row, "pid")?, num(row, "start_ticks")?)
                    .is_none(),
                "native257 duplicate telemetry PID"
            );
        }
        ensure!(
            pids.get(&main) == Some(&num(gp, "main_start_ticks")?) && (1..=2).contains(&pids.len()),
            "native257 main start or process count"
        );
        if pids.len() == 1 {
            ensure!(child.is_null(), "native257 phantom worker");
        } else {
            let pid = num(child, "pid")?;
            ensure!(
                pid != main
                    && child["parent_pid"] == main
                    && child["executable"] == native265::WORKER
                    && child["sha256"] == native265::WORKER_SHA
                    && pids.get(&pid) == Some(&num(child, "start_ticks")?)
                    && num(child, "start_ticks")? >= num(gp, "main_start_ticks")?,
                "native257 telemetry worker changed"
            );
        }
        members.push(pids);
    }
    ensure!(
        members[0] == members[1],
        "native257 unstable process membership"
    );
    for role in ["native_main", "native_child"] {
        let before = &obs[format!("{role}_before")];
        let after = &obs[format!("{role}_after")];
        if !before.is_null() {
            for field in ["mapped_inode", "mapped_device"] {
                ensure!(
                    num(before, field)? == num(after, field)?,
                    "native257 mapped executable changed"
                );
            }
        }
    }
    Ok(())
}
pub(super) fn census_check(
    p: &Plan,
    previous: &Value,
    observation: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<()> {
    let active = current.get(c::UNIT).is_some_and(diagnostic_stage_running);
    let registered = owner(p)?;
    let Some(owner) = registered else {
        ensure!(!active, "unregistered native257 live owner");
        if previous.is_object() && previous["unit_census"].get(c::UNIT).is_some() {
            ensure!(
                owner(&prior(previous)?)?.is_none(),
                "native257 registered predecessor dropped"
            );
        }
        return Ok(());
    };
    let predecessor = p
        .previous_fleet
        .as_ref()
        .context("native257 missing fleet predecessor")?;
    let event = p.metadata_event.as_ref().map(bound_json).transpose()?;
    let origin = sealed(&owner.evidence[0])?;
    let initial = p.metadata_event.as_ref() == owner.evidence.first();
    if !initial {
        ensure!(
            self::owner(&prior(previous)?)? == Some(owner),
            "native257 previous fleet changed ownership"
        );
    }
    let same = previous["observer_receipt"].as_str() == p.observer.path.to_str()
        && previous["observer_sha256"] == p.observer.sha256;
    if !same {
        ensure!(
            observation["cadence"]["previous_sample"] == previous["observer_receipt"]
                && observation["cadence"]["previous_sample_sha256"] == previous["observer_sha256"]
                && observation["cadence"]["previous_sample_recorded_at_utc"]
                    == previous["sampled_at_utc"],
            "native257 observation chain interrupted"
        );
    }
    if initial
        || event
            .as_ref()
            .is_some_and(|v| v["schema"] == native257_terminal::SCHEMA)
    {
        ensure!(
            event.as_ref().context("native257 event")?["fleet"] == private157::binding(predecessor),
            "native257 predecessor mismatch"
        );
        native265_capture::peers(previous, current, c::UNIT)?;
    }
    if active {
        ensure!(
            p.gates[&257].state == "blocked-qualification",
            "native257 live gate"
        );
        if private157::binding(&p.observer) != origin["observer"] {
            telemetry(observation, owner)?;
        }
    } else {
        let proofs = p.gates[&257]
            .evidence
            .iter()
            .map(|b| Ok((b, bound_json(b)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut terminal = proofs
            .iter()
            .filter(|(_, v)| v["schema"] == native257_terminal::SCHEMA);
        let (b, proof) = terminal
            .next()
            .context("native257 terminal lacks decision evidence")?;
        ensure!(
            terminal.next().is_none()
                && proof["running_origin"] == private157::binding(&owner.evidence[0]),
            "native257 ambiguous terminal"
        );
        native257_terminal::validate(proof, b)?;
        native257_terminal::matches(
            current
                .get(c::UNIT)
                .context("native257 terminal owner missing")?,
            proof,
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_resource_observation_brackets_require_the_original_main_and_optional_direct_worker() {
        let origin = json!({"invocation_id":"a".repeat(32),"main_pid":42});
        let gp = json!({"main_start_ticks":5});
        let mut observation = json!({});
        for side in ["before", "after"] {
            observation[format!("native_main_{side}")] = json!({"pid":42,"executable":c::TEST,"sha256":c::TEST_SHA,"mapped_inode":111,"mapped_device":222});
            observation[format!("native_child_{side}")] = json!({"pid":43,"parent_pid":42,"executable":native265::WORKER,"sha256":native265::WORKER_SHA,"start_ticks":7,"mapped_inode":112,"mapped_device":222});
            observation[format!("producer_{side}")] = json!({"unit":c::UNIT,"invocation_id":origin["invocation_id"],"main_pid":42,"control_group":format!("/system.slice/{}",c::UNIT),"rss":{"census_stable":true,"error":null,"processes":[{"pid":42,"start_ticks":5},{"pid":43,"start_ticks":7}]}});
        }
        telemetry_images(&observation, &origin, &gp).unwrap();
        for key in [
            "/native_child_before/pid",
            "/native_child_before/parent_pid",
            "/native_child_after/sha256",
            "/native_child_after/start_ticks",
            "/native_child_after/mapped_inode",
            "/native_main_before/executable",
            "/producer_before/control_group",
            "/producer_after/rss/processes/0/start_ticks",
        ] {
            let mut bad = observation.clone();
            *bad.pointer_mut(key).unwrap() = Value::Null;
            assert!(telemetry_images(&bad, &origin, &gp).is_err(), "{key}");
        }
        observation["native_child_before"] = Value::Null;
        observation["producer_before"]["rss"]["processes"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(telemetry_images(&observation, &origin, &gp).is_err());
        observation["native_child_after"] = Value::Null;
        observation["producer_after"]["rss"]["processes"]
            .as_array_mut()
            .unwrap()
            .pop();
        telemetry_images(&observation, &origin, &gp).unwrap();
    }
}
