// Preserve unrelated owners and the original resource sample across native bootstrap events.
use super::current as c;
use super::*;
use crate::fleet::native265::{num, sealed, text};
pub(in crate::fleet) fn prior(f: &Value) -> Result<Plan> {
    let plan = BoundFile {
        path: text(f, "plan")?.into(),
        sha256: text(f, "plan_sha256")?.into(),
    };
    Ok(serde_json::from_value(bound_json(&plan)?)?)
}
pub(in crate::fleet) fn owner(plan: &Plan) -> Result<Option<&PipelineClaim>> {
    let mut registered = plan.pipeline_claims.iter().filter(|r| r.unit == c::UNIT);
    let first = registered.next();
    ensure!(
        registered.next().is_none(),
        "native bootstrap duplicate registered owner"
    );
    if let Some(r) = first {
        c::claim(r)?;
    }
    Ok(first)
}
pub(in crate::fleet) fn predecessor(
    previous: &Value,
    p: &Plan,
    event: &Value,
    sampled: &str,
    wall: u64,
) -> Result<()> {
    let b = p
        .metadata_event
        .as_ref()
        .context("native bootstrap event binding")?;
    let o = owner(p)?.context("native bootstrap event needs registered ownership")?;
    let running = event["schema"] == c::SCHEMA || UNIT==native266::UNIT && event["schema"]==native266_recovery::SCHEMA;
    let start = if running {
        ensure!(
            o.evidence.first() == Some(b),
            "native bootstrap event substituted registered claim"
        );
        num(event, "recorded_unix_seconds")?
    } else {
        terminal::validate(event, b)?;
        ensure!(
            event["running_origin"] == private157::binding(&o.evidence[0]),
            "native bootstrap terminal registration differs"
        );
        num(event, "recorded_unix_seconds")?
    };
    let old = prior(previous)?;
    let replaced = if running && UNIT == native257::UNIT {
        let predecessor = owner(&old)?;
        if let Some(prior_owner) = predecessor {
            native257::verify_replacement(prior_owner, o, event, &old)?;
        }
        predecessor
    } else {
        None
    };
    ensure!(
        sealed(b)? == *event
            && start <= wall
            && wall - start <= 300
            && start > num(previous, "recorded_unix_seconds")?
            && p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == crate::fleet::SCHEMA
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && previous["sampled_at_utc"] == sampled
            && event["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|f| event["fleet"] == private157::binding(f)),
        "native bootstrap event substituted resource observer or prior fleet"
    );
    let direct = UNIT==native266::UNIT && !running && owner(&old)?.is_none() && sealed(&o.evidence[0])?["schema"] == native266_recovery::SCHEMA;
    if direct { ensure!(event["running_origin"]==private157::binding(&o.evidence[0]) && event["sampled_at_utc"]==sampled,"different directly recovered terminal"); }
    if running || direct {
        ensure!(
            owner(&old)? == replaced
                && p.pipeline_claims.len() == old.pipeline_claims.len() + usize::from(replaced.is_none())
                && old
                    .pipeline_claims
                    .iter()
                    .all(|r| Some(r) == replaced || p.pipeline_claims.contains(r)),
            "native bootstrap changed existing pipeline ownership"
        );
        for r in previous["active"]
            .as_array()
            .context("native bootstrap old active")?
        {
            if let Some(epoch) = r["epoch"].as_u64() {
                ensure!(epoch != EPOCH, "native bootstrap existing owner");
            } else {
                ensure!(
                    !parse_observer_claim_range(text(r, "range")?)?.contains(&EPOCH),
                    "native bootstrap overlapping active range"
                );
            }
        }
    } else {
        ensure!(
            old.pipeline_claims == p.pipeline_claims && event["sampled_at_utc"] == sampled,
            "native bootstrap terminal lost original registered history"
        );
    }
    let mut expected = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    if running || direct {
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
        "native bootstrap unrelated fleet settings changed"
    );
    for (epoch, g) in &old.gates {
        let n = p
            .gates
            .get(epoch)
            .context("native bootstrap gate omitted")?;
        ensure!(
            native265_event::same_operator_status(&g.operator_status, &n.operator_status)
                && serde_json::to_value(&g.reserve_stop)? == serde_json::to_value(&n.reserve_stop)?,
            "native bootstrap unrelated status/reserve changed"
        );
        if *epoch == EPOCH {
            ensure!(
                n.evidence.contains(b)
                    && g.evidence.iter().all(|v| n.evidence.contains(v))
                    && n.evidence.iter().all(|v| v == b || g.evidence.contains(v) || direct && v==&o.evidence[0])
                    && (!direct || n.evidence.contains(&o.evidence[0]))
                    && (if running {
                        matches!(
                            g.state.as_str(),
                            "not-yet-staged"
                                | "staged-admissible"
                                | "blocked-qualification"
                                | "failed-needs-repair"
                        ) && n.state == "blocked-qualification"
                    } else {
                        (g.state == "blocked-qualification" || direct && matches!(g.state.as_str(),"not-yet-staged"|"staged-admissible"|"failed-needs-repair"))
                            && n.state
                                == if event["native_input_qualified"] == true {
                                    "blocked-qualification"
                                } else {
                                    "failed-needs-repair"
                                }
                    }),
                "native bootstrap outcome gate mismatch"
            );
        } else {
            ensure!(
                n.state == g.state && n.evidence == g.evidence && n.next_action == g.next_action,
                "native bootstrap unrelated gate changed"
            );
        }
    }
    Ok(())
}
fn telemetry(v: &Value, c: &PipelineClaim) -> Result<()> {
    let mut rows = v["diagnostic_replays"]
        .as_array()
        .context("native bootstrap diagnostic telemetry census")?
        .iter()
        .filter(|r| r["range"] == RANGE || r["producer_unit"] == c::UNIT);
    let r = rows
        .next()
        .context("native bootstrap missing resource observation")?;
    let obs = &r["observation"];
    ensure!(
        rows.next().is_none()
            && r["status"] == "observed"
            && r["expected_producer_invocation_id"] == c.invocation_id
            && r["range"] == RANGE
            && r["producer_unit"] == c::UNIT
            && r["native_resource_only"] == true
            && r["scratch_path"] == c::ROOT
            && r["ordinary_replay_claim"] == false
            && r["entry_replay"] == false
            && obs["invocation_binding_stable"] == true
            && obs["resource_only"] == true
            && obs["native_input_qualified"] == false
            && obs["entry_replay"] == false
            && obs["publication_authorized"] == false,
        "native bootstrap observation missing/ambiguous"
    );
    let origin = sealed(&c.evidence[0])?;
    let (h, _) = c::startup(&native265::binding(&origin["startup_handoff"])?)?;
    let gp = sealed(&native265::binding(&h["guard_plan"])?)?;
    c::observation_mount(obs, &h)?;
    telemetry_images(obs, &origin, &gp)
}
fn telemetry_images(obs: &Value, origin: &Value, gp: &Value) -> Result<()> {
    let main = num(origin, "main_pid")?;
    let mut members = Vec::new();
    for side in ["before", "after"] {
        let image = &obs[format!("native_main_{side}")];
        ensure!(
            image["executable"] == c::TEST
                && image["sha256"] == c::TEST_SHA
                && image["pid"] == origin["main_pid"],
            "native bootstrap telemetry harness differs"
        );
        let u = &obs[format!("producer_{side}")];
        let child = obs
            .get(format!("native_child_{side}").as_str())
            .context("native bootstrap missing child census")?;
        ensure!(
            u["unit"] == c::UNIT
                && u["invocation_id"] == origin["invocation_id"]
                && u["main_pid"] == main
                && u["control_group"] == format!("/system.slice/{}", c::UNIT)
                && u["rss"]["census_stable"] == true
                && u["rss"].get("error") == Some(&Value::Null),
            "native bootstrap RSS owner"
        );
        let rows = u["rss"]["processes"]
            .as_array()
            .context("native bootstrap telemetry process census")?;
        let mut pids = BTreeMap::new();
        for row in rows {
            ensure!(
                pids.insert(num(row, "pid")?, num(row, "start_ticks")?)
                    .is_none(),
                "native bootstrap duplicate telemetry PID"
            );
        }
        ensure!(
            pids.get(&main) == Some(&num(gp, "main_start_ticks")?) && (1..=2).contains(&pids.len()),
            "native bootstrap main start or process count"
        );
        if pids.len() == 1 {
            ensure!(child.is_null(), "native bootstrap phantom worker");
        } else {
            let pid = num(child, "pid")?;
            ensure!(
                pid != main
                    && child["parent_pid"] == main
                    && child["executable"] == c::PROFILE.worker.path
                    && child["sha256"] == c::PROFILE.worker.sha256
                    && pids.get(&pid) == Some(&num(child, "start_ticks")?)
                    && num(child, "start_ticks")? >= num(gp, "main_start_ticks")?,
                "native bootstrap telemetry worker changed"
            );
        }
        members.push(pids);
    }
    ensure!(
        members[0] == members[1],
        "native bootstrap unstable process membership"
    );
    for role in ["native_main", "native_child"] {
        let before = &obs[format!("{role}_before")];
        let after = &obs[format!("{role}_after")];
        if !before.is_null() {
            for field in ["mapped_inode", "mapped_device"] {
                ensure!(
                    num(before, field)? == num(after, field)?,
                    "native bootstrap mapped executable changed"
                );
            }
        }
    }
    Ok(())
}
pub(in crate::fleet) fn census_check(
    p: &Plan,
    previous: &Value,
    observation: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<()> {
    let active = current.get(c::UNIT).is_some_and(diagnostic_stage_running);
    let registered = owner(p)?;
    let Some(owner) = registered else {
        ensure!(!active, "unregistered native bootstrap live owner");
        if previous.is_object() && previous["unit_census"].get(c::UNIT).is_some() {
            ensure!(
                owner(&prior(previous)?)?.is_none(),
                "native bootstrap registered predecessor dropped"
            );
        }
        return Ok(());
    };
    let predecessor = p
        .previous_fleet
        .as_ref()
        .context("native bootstrap missing fleet predecessor")?;
    let event = p.metadata_event.as_ref().map(bound_json).transpose()?;
    let origin = sealed(&owner.evidence[0])?;
    let initial = p.metadata_event.as_ref() == owner.evidence.first();
    let direct = UNIT==native266::UNIT && self::owner(&prior(previous)?)?.is_none() && origin["schema"] == native266_recovery::SCHEMA
        && event.as_ref().is_some_and(|e|e["schema"]==terminal::SCHEMA && e["running_origin"]==private157::binding(&owner.evidence[0]));
    if !initial && !direct {
        let prior_plan = prior(previous)?;
        let earlier = self::owner(&prior_plan)?;
        if earlier != Some(owner) {
            ensure!(UNIT == native257::UNIT && !active && p.metadata_event.is_none()
                && p.admission_transition_guard.is_none() && native257::recovered_origin(&origin)
                && origin["fleet"] == private157::binding(predecessor)
                && origin["observer"]["sha256"] == previous["observer_sha256"]
                && p.gates[&EPOCH].state == "blocked-qualification",
                "native bootstrap previous fleet changed ownership");
            native257::verify_replacement(
                earlier.context("missing predecessor for closed 257 replacement")?,
                owner, &origin, &prior_plan)?;
        }
    }
    let same = previous["observer_receipt"].as_str() == p.observer.path.to_str()
        && previous["observer_sha256"] == p.observer.sha256;
    if !same {
        let continuous = observation["cadence"]["previous_sample"] == previous["observer_receipt"]
            && observation["cadence"]["previous_sample_sha256"] == previous["observer_sha256"]
            && observation["cadence"]["previous_sample_recorded_at_utc"] == previous["sampled_at_utc"];
        let recovered = !continuous && !active && p.metadata_event.is_none()
            && p.admission_transition_guard.is_none()
            && (native257::seven_delivery_predecessor(predecessor, previous, &p.observer, observation)?
                || native257::stopped_292_observer_predecessor(predecessor, previous, &p.observer, observation)?
                || native257::failed_296_observer_predecessor(predecessor, previous, &p.observer, observation)?);
        if !continuous && !recovered {
            ensure!(UNIT == native266::UNIT && p.metadata_event.is_none() && p.admission_transition_guard.is_none(),
                "native bootstrap observation chain interrupted for {UNIT}");
            horizon_singleton211_launch::native266::validate_observer_predecessor(
                &predecessor.path, &predecessor.sha256, &p.observer.path, observation,
            )?;
        }
    }
    if initial
        || event
            .as_ref()
            .is_some_and(|v| v["schema"] == terminal::SCHEMA)
    {
        ensure!(
            event.as_ref().context("native bootstrap event")?["fleet"]
                == private157::binding(predecessor),
            "native bootstrap predecessor mismatch"
        );
        if UNIT==native266::UNIT && origin["schema"]==native266_recovery::SCHEMA {
            native266_recovery::peers(previous,current,c::UNIT)?;
        } else { native265_capture::peers(previous, current, c::UNIT)?; }
    }
    if active {
        ensure!(
            p.gates[&EPOCH].state == "blocked-qualification",
            "native bootstrap live gate"
        );
        if private157::binding(&p.observer) != origin["observer"] {
            telemetry(observation, owner)?;
        }
    } else {
        let proofs = p.gates[&EPOCH]
            .evidence
            .iter()
            .map(|b| Ok((b, bound_json(b)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut terminal = proofs
            .iter()
            .filter(|(_, v)| v["schema"] == terminal::SCHEMA);
        let (b, proof) = terminal
            .next()
            .context("native bootstrap terminal lacks decision evidence")?;
        ensure!(
            terminal.next().is_none()
                && proof["running_origin"] == private157::binding(&owner.evidence[0]),
            "native bootstrap ambiguous terminal"
        );
        terminal::validate(proof, b)?;
        terminal::matches(
            current
                .get(c::UNIT)
                .context("native bootstrap terminal owner missing")?,
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
            observation[format!("native_child_{side}")] = json!({"pid":43,"parent_pid":42,"executable":c::PROFILE.worker.path,"sha256":c::PROFILE.worker.sha256,"start_ticks":7,"mapped_inode":112,"mapped_device":222});
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
