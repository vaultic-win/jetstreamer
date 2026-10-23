//! An admitted zero-entry native input test may join the existing sample.
//! The event never replaces resource observation or rewrites campaign history.
use super::*;

const TERMINAL_SCHEMA: &str = "jetstreamer-private-epoch223-native-v1620-terminal-event-v1";
#[cfg(test)]
const ACTUAL_IID: &str = "41684426155f4124a64b10c55ffeed96";
const ACTUAL_INTENT: &str = "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-v1620-actual-v1/intent.json";
const ACTUAL_INTENT_SHA: &str = "2d6f4a1b081d700e4b0a68488a1eb69e2f68301dcbd6dc27a1883c2b5a8d88c8";

fn terminal_journal(binding: &BoundFile, owner: &Profile, iid: &str) -> Result<(bool, u64)> {
    let bytes = read_stable_bounded(&binding.path, 16 << 20, "native20 terminal journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == binding.sha256,
        "native20 terminal journal digest"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "native20 terminal journal bounds"
    );
    let mut terminal = None;
    let mut last = 0u64;
    for row in rows {
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("native20 journal clock")?
            .parse::<u64>()?;
        ensure!(clock >= last, "native20 terminal journal clock rollback");
        last = clock;
        let message = row["MESSAGE"]
            .as_str()
            .context("native20 terminal journal message")?;
        if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == owner.unit && row["INVOCATION_ID"] == iid,
                "native20 foreign manager event"
            );
            let success = message == format!("{}: Deactivated successfully.", owner.unit);
            let failed = message.starts_with(&format!("{}: Failed with result '", owner.unit))
                && message.ends_with("'.");
            if success || failed {
                ensure!(
                    terminal.replace((success, clock)).is_none(),
                    "native20 duplicate terminal manager event"
                );
            }
        } else {
            ensure!(
                row["_SYSTEMD_UNIT"] == owner.unit && row["_SYSTEMD_INVOCATION_ID"] == iid,
                "native20 foreign child journal"
            );
        }
    }
    terminal.context("native20 exact terminal manager event absent")
}
pub(super) fn terminal_proof(proof: &Value) -> Result<(&'static Profile, String, bool, u64)> {
    let owner = profile(proof["unit"].as_str().context("native20 terminal unit")?)?;
    let iid = proof["invocation_id"]
        .as_str()
        .context("native20 terminal invocation")?;
    ensure!(
        owner.intent_schema == NATIVE20.intent_schema
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "native20 terminal approved profile/identity"
    );
    ensure!(
        proof["schema"] == TERMINAL_SCHEMA
            && proof["unit"] == owner.unit
            && proof["invocation_id"] == iid
            && proof["resource_samples_taken"] == 0,
        "native20 terminal proof scope"
    );
    for key in [
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "native_input_qualified",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            proof[key] == false,
            "native20 terminal event grants authority"
        );
    }
    let input: BoundFile = serde_json::from_value(proof["intent"].clone())?;
    ensure!(
        input.path == Path::new(owner.state).join("intent.json")
            && (owner.unit != NATIVE20.unit
                || (input.path == Path::new(ACTUAL_INTENT) && input.sha256 == ACTUAL_INTENT_SHA)),
        "native20 terminal intent differs"
    );
    let i = bound_json(&input)?;
    ensure!(
        i["invocation_id"] == iid
            && i["schema"] == owner.intent_schema
            && i["plan_sha256"] == owner.plan_sha
            && i["self_sha256"] == owner.self_sha
            && i["test_sha256"] == owner.test_sha,
        "native20 terminal intent identity"
    );
    let journal: BoundFile = serde_json::from_value(proof["journal"].clone())?;
    let (success, clock) = terminal_journal(&journal, owner, iid)?;
    if proof["result"].is_null() {
        ensure!(
            !success
                && fs::symlink_metadata(Path::new(owner.state).join("result.json"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "native20 missing result is not a proved failed terminal"
        );
    } else {
        let result: BoundFile = serde_json::from_value(proof["result"].clone())?;
        ensure!(
            result.path == Path::new(owner.state).join("result.json"),
            "native20 terminal result path"
        );
        let r = bound_json(&result)?;
        ensure!(
            r["schema"] == "jetstreamer-private-epoch223-native-v1620-ram-snapshot-result-v1"
                && r["invocation_id"] == iid
                && r["plan_sha256"] == owner.plan_sha
                && r["self_sha256"] == owner.self_sha
                && r["test_sha256"] == owner.test_sha
                && r["exact_ignored_test_count"] == 1
                && r["elapsed_millis"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= 2_100_000),
            "native20 terminal result identity"
        );
        for key in [
            "entry_replay",
            "full_peak_qualified",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(r[key] == false, "native20 result grants authority");
        }
        if success {
            ensure!(
                r["child_success"] == true
                    && r["child_exit_code"] == 0
                    && r["trip"].is_null()
                    && r["resource_capture_error"].is_null(),
                "native20 clean manager contradicts supervisor result"
            );
        }
    }
    Ok((owner, iid.into(), success, clock))
}
pub(in crate::fleet) fn terminal_status_identity(proof: &Value) -> Result<(String, String)> {
    let (owner, iid, _, _) = terminal_proof(proof)?;
    Ok((owner.unit.into(), iid))
}
pub(in crate::fleet) fn terminal_predecessor(
    previous: &Value,
    p: &Plan,
    proof: &Value,
    sampled: &str,
    now: u64,
) -> Result<()> {
    let (owner, iid, _, terminal_clock) = terminal_proof(proof)?;
    ensure!(
        p.first_epoch == 201
            && p.last_epoch == 300
            && p.admission_transition_guard.is_none()
            && previous["schema"] == SCHEMA
            && previous["sampled_at_utc"] == sampled
            && proof["sampled_at_utc"] == sampled
            && previous["observer_receipt"].as_str() == p.observer.path.to_str()
            && previous["observer_sha256"] == p.observer.sha256
            && proof["observer"] == private157::binding(&p.observer)
            && p.previous_fleet
                .as_ref()
                .is_some_and(|b| proof["fleet"] == private157::binding(b)),
        "native20 terminal event cannot replace resource sample"
    );
    let clock = proof["recorded_unix_seconds"]
        .as_u64()
        .context("native20 terminal event clock")?;
    ensure!(
        clock >= terminal_clock / 1_000_000
            && clock <= now
            && now - clock <= 300
            && previous["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n < clock),
        "native20 terminal event stale or backdated"
    );
    let old: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"]
            .as_str()
            .context("native20 terminal previous plan")?
            .into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("native20 terminal previous digest")?
            .into(),
    })?)?;
    ensure!(
        p.pipeline_claims == old.pipeline_claims
            && p.tracked_units == old.tracked_units
            && p.diagnostics.len() == old.diagnostics.len()
            && old
                .diagnostics
                .iter()
                .all(|d| p.diagnostics.iter().any(|n| n.epoch == d.epoch
                    && n.unit == d.unit
                    && n.invocation_id == d.invocation_id
                    && n.scratch_path == d.scratch_path
                    && n.launch_receipt == d.launch_receipt))
            && p.gates.len() == old.gates.len(),
        "native20 terminal event changed owner history"
    );
    let claims = p
        .pipeline_claims
        .iter()
        .filter(|c| c.unit == owner.unit && c.invocation_id == iid)
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1,
        "native20 terminal event lacks original owner"
    );
    validate(claims[0])?;
    for (epoch, gate) in &old.gates {
        let new = p
            .gates
            .get(epoch)
            .context("native20 terminal gate missing")?;
        ensure!(
            new.state == gate.state
                && gate.evidence.iter().all(|e| new.evidence.contains(e))
                && (*epoch == 223 || new.next_action == gate.next_action),
            "native20 terminal event changed unrelated gate"
        );
    }
    ensure!(
        p.gates[&223].state == "failed-needs-repair",
        "native20 terminal cannot close epoch223repair"
    );
    Ok(())
}
pub(in crate::fleet) fn terminal_census(p: &Plan, before: &BTreeMap<String, Value>) -> Result<()> {
    let Some(binding) = &p.metadata_event else {
        return Ok(());
    };
    let proof = bound_json(binding)?;
    if proof["schema"] != TERMINAL_SCHEMA {
        return Ok(());
    }
    let (owner, iid, success, _) = terminal_proof(&proof)?;
    let current = before
        .get(owner.unit)
        .context("native20 terminal owner absent")?;
    let collected = current["LoadState"] == "not-found"
        && current["ActiveState"] == "inactive"
        && current["SubState"] == "dead"
        && current["InvocationID"] == "";
    let stopped = current["LoadState"] == "loaded"
        && current["InvocationID"] == iid
        && current["NRestarts"] == "0"
        && matches!(
            (
                current["ActiveState"].as_str(),
                current["SubState"].as_str()
            ),
            (Some("inactive"), Some("dead")) | (Some("failed"), Some("failed"))
        )
        && (!success || current["Result"] == "success");
    ensure!(
        (collected || stopped) && current["MainPID"] == "0",
        "native20 terminal owner live or replaced"
    );
    let prior = bound_json(
        p.previous_fleet
            .as_ref()
            .context("native20 terminal previous fleet")?,
    )?;
    let mut protected = prior.clone();
    protected["active"] = Value::Array(
        prior["active"]
            .as_array()
            .context("native20 terminal active census")?
            .iter()
            .filter(|row| row["epoch"] != 223)
            .cloned()
            .collect(),
    );
    protected_owners_for(&protected, before, owner.unit)
}

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
        .filter(|c| {
            profile(&c.unit).is_ok_and(|p| p.intent_schema == NATIVE20.intent_schema)
                && p.metadata_event.as_ref() == c.evidence.first()
        })
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
            && !old.pipeline_claims.iter().any(|c| c.unit == claim.unit)
            && old
                .pipeline_claims
                .iter()
                .all(|c| p.pipeline_claims.contains(c)),
        "native20 event changed pipeline history"
    );
    let mut names = old.tracked_units.iter().cloned().collect::<BTreeSet<_>>();
    names.insert(claim.unit.clone());
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

#[cfg(test)]
fn protected_owners(previous: &Value, census: &BTreeMap<String, Value>) -> Result<()> {
    protected_owners_for(previous, census, NATIVE20.unit)
}
fn protected_owners_for(
    previous: &Value,
    census: &BTreeMap<String, Value>,
    native_unit: &str,
) -> Result<()> {
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
            !diagnostic_stage_running(state) || names.contains(name) || name == native_unit,
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
            let claim = p
                .pipeline_claims
                .iter()
                .find(|c| {
                    c.evidence.first() == Some(binding)
                        && profile(&c.unit).is_ok_and(|p| p.intent_schema == NATIVE20.intent_schema)
                })
                .context("native20 event claim")?;
            protected_owners_for(&previous, census, &claim.unit)?;
            validate_live(
                claim,
                census
                    .get(&claim.unit)
                    .context("native20 new owner missing")?,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn terminal_fixture(rows: &[Value]) -> (tempfile::TempDir, BoundFile) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.jsonl");
        let bytes = rows
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        fs::write(&path, bytes.as_bytes()).unwrap();
        let binding = BoundFile {
            path,
            sha256: hex_lower(&Sha256::digest(bytes.as_bytes())),
        };
        (dir, binding)
    }
    #[test]
    fn terminal_manager_history_requires_exact_iid_unique_outcome_and_clock_order() {
        let child = json!({"_PID":"42","_SYSTEMD_UNIT":NATIVE20.unit,"_SYSTEMD_INVOCATION_ID":ACTUAL_IID,"MESSAGE":"running 1 test","__REALTIME_TIMESTAMP":"1000000"});
        let manager = json!({"_PID":"1","UNIT":NATIVE20.unit,"INVOCATION_ID":ACTUAL_IID,"MESSAGE":format!("{}: Deactivated successfully.",NATIVE20.unit),"__REALTIME_TIMESTAMP":"2000000"});
        let rows = vec![child.clone(), manager.clone()];
        let (_dir, b) = terminal_fixture(&rows);
        assert_eq!(
            terminal_journal(&b, &NATIVE20, ACTUAL_IID).unwrap(),
            (true, 2_000_000)
        );
        for variant in 0..4 {
            let mut bad = rows.clone();
            match variant {
                0 => bad[1]["INVOCATION_ID"] = json!("0".repeat(32)),
                1 => {
                    bad.pop();
                }
                2 => bad.push(manager.clone()),
                _ => bad.swap(0, 1),
            };
            let (_dir, b) = terminal_fixture(&bad);
            assert!(
                terminal_journal(&b, &NATIVE20, ACTUAL_IID).is_err(),
                "{variant}"
            );
        }
        let mut failure = manager;
        failure["MESSAGE"] = json!(format!("{}: Failed with result 'timeout'.", NATIVE20.unit));
        let (_dir, b) = terminal_fixture(&[child, failure]);
        assert_eq!(
            terminal_journal(&b, &NATIVE20, ACTUAL_IID).unwrap(),
            (false, 2_000_000)
        );
    }
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
