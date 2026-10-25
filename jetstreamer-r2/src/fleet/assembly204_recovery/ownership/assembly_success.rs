//! Natural assembly success keeps the original producer/guard identities even
//! after PID1 clears the inactive units' invocation fields. No identity is filled in.
use super::*;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    schema: String,
    context: AcceptedContext,
    #[serde(default)]
    observer_history: Vec<BoundFile>,
    #[serde(default)]
    full209_terminal_peer: Option<full209_terminal_peer::Proof>,
    launch: BoundFile,
    guard_current: Value,
    guard_manager_journal: BoundFile,
    guard_cgroup_empty: bool,
    guard_cgroup: Value,
    census_before: BTreeMap<String, Value>,
    census_after: BTreeMap<String, Value>,
}

fn terminal_owner(current: &Value, expected: &Value) -> Result<()> {
    let iid = s(expected, "InvocationID")?;
    ensure!(
        id(iid)
            && current["Id"] == expected["Id"]
            && current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == iid || current["InvocationID"] == "")
            && command_matches(s(current, "ExecStart")?, s(expected, "ExecStart")?),
        "204 natural assembly owner is live, replaced, restarted or not successful"
    );
    Ok(())
}

fn completion_window(raw: &[u8], name: &str, iid: &str) -> Result<(u64, u64)> {
    let start = manager_shape(raw, name, iid, true)?;
    let rows = serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let finish = rows
        .iter()
        .find(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
        .context("204 exact natural completion absent")?;
    Ok((
        start,
        s(finish, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1000,
    ))
}

fn facts(
    t: &Value,
    origin: &Origin,
    launch: &Value,
    plan: &Value,
    outcome: &Value,
    producer: &[u8],
    guard: &[u8],
) -> Result<()> {
    ensure!(
        origin.schema == "jetstreamer-epoch204-assembly-success-origin-v1"
            && t["unit"] == UNIT
            && t["result"] == "natural_success"
            && launch["unit"] == UNIT
            && launch["stage"] == "assembly"
            && t["invocation_id"] == launch["invocation_id"]
            && launch["owner"]["Id"] == UNIT
            && launch["owner"]["InvocationID"] == launch["invocation_id"]
            && launch["guard_unit"] == GUARD
            && launch["guard"]["Id"] == GUARD
            && launch["guard"]["InvocationID"] == launch["guard_invocation_id"]
            && origin.guard_cgroup_empty
            && t["cgroup_empty"] == true
            && origin.census_before == origin.census_after
            && origin.census_before.get(UNIT) == Some(&t["current_unit"])
            && origin.census_before.get(GUARD) == Some(&origin.guard_current),
        "204 natural assembly origin, guard or complete census differs"
    );
    validate_closed_ownership(&origin.census_before, None)?;
    terminal_owner(&t["current_unit"], &launch["owner"])?;
    terminal_owner(&origin.guard_current, &launch["guard"])?;
    let (start, finish) = completion_window(producer, UNIT, s(launch, "invocation_id")?)?;
    let (guard_start, guard_finish) =
        completion_window(guard, GUARD, s(launch, "guard_invocation_id")?)?;
    ensure!(
        launch["started_unix_millis"] == start
            && guard_start <= n(outcome, "finished_unix_millis")?
            && finish <= guard_finish
            && start <= n(outcome, "started_unix_millis")?
            && n(outcome, "started_unix_millis")? <= n(outcome, "finished_unix_millis")?
            && n(outcome, "finished_unix_millis")? <= finish
            && outcome["schema"] == "jetstreamer-epoch204-assembly-only-recovery-outcome-v1"
            && outcome["epoch"] == 204
            && outcome["unit"] == UNIT
            && outcome["invocation_id"] == launch["invocation_id"]
            && outcome["guard_unit"] == GUARD
            && outcome["guard_invocation_id"] == launch["guard_invocation_id"]
            && outcome["plan_sha256"] == launch["recovery_plan"]["sha256"]
            && outcome["executable_sha256"] == plan["executable_sha256"]
            && outcome["admission_sha256"] == launch["admission"]["sha256"]
            && outcome["source_capture"] == plan["source_capture"]
            && outcome["original_terminal"] == plan["original_terminal"]
            && outcome["suffix_proof"] == plan["suffix_proof"]
            && outcome["original_invocation_id"] == OLD_IID
            && outcome["original_outcome"] == "failed_or_stopped"
            && outcome["private_output"] == OUTPUT
            && outcome["epoch_started_unix_millis"] == ORIGIN
            && outcome["slots_merged"] == 432000
            && outcome["source_archives"] == 2
            && n(outcome, "archive_bytes")? > 0
            && n(outcome, "archive_bytes")? <= OUTPUT_MAX
            && is_lower_hex(s(outcome, "archive_sha256")?, 64)
            && outcome["no_replay"] == true
            && outcome["new_native_initialization_performed"] == false
            && outcome["independent_final_archive_verification_passed"] == false
            && outcome["current_plugin_verification_passed"] == false,
        "204 natural assembly outcome or original manager clocks differ"
    );
    deny(&outcome["authority"])
}

fn origin_launch(origin: &Origin) -> Result<(context::WorkContext, Value, Value)> {
    let context = context::WorkContext::new(
        origin.context.fleet.clone(),
        origin.context.observer.clone(),
        origin.observer_history.clone(),
    )?
    .with_full209_terminal_peer(origin.full209_terminal_peer.clone());
    let f = bound_json(&origin.context.fleet)?;
    let accepted_plan = bound_json(&BoundFile {
        path: s(&f, "plan")?.into(),
        sha256: s(&f, "plan_sha256")?.into(),
    })?;
    let claim: Claim = serde_json::from_value(accepted_plan["assembly204_recovery"].clone())?;
    ensure!(
        claim.actor_launch == origin.launch && claim.launch == origin.launch,
        "204 terminal changed its accepted assembly launch"
    );
    let launch = read(&origin.launch)?;
    let plan = read(&claim.recovery_plan)?;
    validate_launch(&launch, &claim.recovery_plan, &plan, &claim.admission)?;
    Ok((context, launch, plan))
}

pub(super) fn validate(t: &Value, producer: &[u8]) -> Result<()> {
    let origin: Origin = serde_json::from_value(t["assembly_success_origin"].clone())?;
    let (context, launch, plan) = origin_launch(&origin)?;
    context.validate_saved(&origin.census_before)?;
    let outcome = read(&serde_json::from_value(t["outcome"].clone())?)?;
    let guard = sealed(&origin.guard_manager_journal, 8 << 20)?;
    facts(t, &origin, &launch, &plan, &outcome, producer, &guard)
}

pub(in crate::fleet::assembly204_recovery) fn capture(
    c: &super::super::downstream::Capture,
    spec: &BoundFile,
    self_sha: &str,
) -> Result<()> {
    private(&c.output_directory)?;
    let mut origin = Origin {
        schema: "jetstreamer-epoch204-assembly-success-origin-v1".into(),
        context: c.context.clone(),
        observer_history: c.observer_history.clone(),
        full209_terminal_peer: c.full209_terminal_peer.clone(),
        launch: c.launch.clone(),
        guard_current: Value::Null,
        guard_manager_journal: BoundFile {
            path: c.output_directory.join("success-guard-manager.jsonl"),
            sha256: String::new(),
        },
        guard_cgroup_empty: true,
        guard_cgroup: Value::Null,
        census_before: BTreeMap::new(),
        census_after: BTreeMap::new(),
    };
    let (context, launch, plan) = origin_launch(&origin)?;
    origin.census_before = context.census(&context::closed_names())?;
    no_overlap_current(&origin.census_before, None)?;
    let before = origin
        .census_before
        .get(UNIT)
        .context("204 terminal producer omitted")?
        .clone();
    origin.guard_current = origin
        .census_before
        .get(GUARD)
        .context("204 terminal guard omitted")?
        .clone();
    terminal_owner(&before, &launch["owner"])?;
    terminal_owner(&origin.guard_current, &launch["guard"])?;
    let group = capped204205_work::empty_terminal_cgroup(UNIT)?;
    origin.guard_cgroup = capped204205_work::empty_terminal_cgroup(GUARD)?;
    let producer = manager(UNIT)?;
    let guard = manager(GUARD)?;
    completion_window(&producer, UNIT, s(&launch, "invocation_id")?)?;
    completion_window(&guard, GUARD, s(&launch, "guard_invocation_id")?)?;
    let refs =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        refs.references.is_empty(),
        "204 completed assembly still has process references"
    );
    let outcome = c
        .outcome
        .as_deref()
        .context("204 successful assembly outcome missing")?;
    ensure!(
        outcome == Path::new(ROOT).join("outcome.json"),
        "204 assembly outcome path differs"
    );
    let file = custody::open_source(outcome)?;
    ensure!(
        file.metadata()?.len() <= 16 << 20
            && file.metadata()?.uid() == 0
            && file.metadata()?.nlink() == 1,
        "204 outcome custody invalid"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    custody::write_bytes(&c.output_directory.join("success-manager.jsonl"), &producer)?;
    custody::write_bytes(&origin.guard_manager_journal.path, &guard)?;
    origin.guard_manager_journal = binding(&origin.guard_manager_journal.path)?;
    origin.census_after = context.census(&context::closed_names())?;
    no_overlap_current(&origin.census_after, None)?;
    ensure!(
        manager_records_equal(&manager(UNIT)?, &producer)?
            && manager_records_equal(&manager(GUARD)?, &guard)?,
        "204 terminal manager lineage changed during capture"
    );
    let t = json!({"schema":"jetstreamer-epoch204-assembly-recovery-success-terminal-v1","unit":UNIT,
        "invocation_id":launch["invocation_id"],"result":"natural_success","current_unit":before,
        "manager_journal":binding(&c.output_directory.join("success-manager.jsonl"))?,"outcome":binding(outcome)?,
        "cgroup_empty":true,"cgroup":group,"assembly_success_origin":origin,"issuer":issuer(spec,self_sha),"authority":denied()});
    // Outcome, original IIDs, both real journals and raw current census are
    // authenticated before a terminal receipt is issued. No archive bytes read.
    facts(
        &t,
        &serde_json::from_value(t["assembly_success_origin"].clone())?,
        &launch,
        &plan,
        &read(&binding(outcome)?)?,
        &producer,
        &guard,
    )?;
    validate_success_terminal(&t, UNIT, s(&launch, "invocation_id")?)?;
    write(&c.output_directory.join("terminal.json"), &t)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn collected_terminal_owners() -> Value {
        serde_json::from_str(include_str!("fixtures/collected-terminal-owners.json")).unwrap()
    }
    #[test]
    fn collected_terminal_raw_commands_match_both_display_shapes_without_rewriting_owners() {
        // Exact original launch and collected current rows from the actual
        // producer/guard diagnosis; PID1 cleared their current IID and times.
        let rows = collected_terminal_owners();
        let unchanged = rows.clone();
        for kind in ["owner", "guard"] {
            let current = &rows[kind]["raw_current"];
            let original = &rows[kind]["raw_original"];
            let actual_command = s(current, "ExecStart").unwrap();
            let original_command = s(original, "ExecStart").unwrap();
            assert_ne!(actual_command, original_command);
            assert!(command_matches(actual_command, original_command));
            assert!(command_matches(original_command, actual_command));
            let configured_command = format!(
                "{} }}",
                original_command.split(" ; start_time=").next().unwrap()
            );
            assert!(command_matches(actual_command, &configured_command));
            assert!(command_matches(&configured_command, original_command));
            terminal_owner(current, original).unwrap();
            assert_eq!(current["InvocationID"], "");
            assert_eq!(current["MainPID"], "0");
            assert_ne!(current["InvocationID"], original["InvocationID"]);
            assert_ne!(current["MainPID"], original["MainPID"]);
        }
        assert_eq!(rows, unchanged);
    }
    #[test]
    fn collected_terminal_raw_commands_reject_executable_arguments_and_error_policy_changes() {
        let rows = collected_terminal_owners();
        for kind in ["owner", "guard"] {
            let original = &rows[kind]["raw_original"];
            let current = &rows[kind]["raw_current"];
            let command = s(current, "ExecStart").unwrap();
            for (old, new) in [
                ("path=/var/lib/jetstreamer/", "path=/foreign/"),
                ("argv[]=/var/lib/jetstreamer/", "argv[]=/foreign/"),
                ("/plan.json", "/foreign-plan.json"),
                ("--plan-sha256 fbe4", "--plan-sha256 0000"),
                ("--self-sha256 2fe7", "--self-sha256 0000"),
                ("ignore_errors=no", "ignore_errors=yes"),
            ] {
                let changed = command.replacen(old, new, 1);
                assert_ne!(command, changed);
                assert!(!command_matches(
                    &changed,
                    s(original, "ExecStart").unwrap()
                ));
                assert!(!command_matches(
                    s(original, "ExecStart").unwrap(),
                    &changed
                ));
                let mut bad = current.clone();
                bad["ExecStart"] = json!(changed);
                assert!(
                    terminal_owner(&bad, original).is_err(),
                    "accepted {kind} {old}"
                );
            }
            let changed_guard = if kind == "guard" {
                command.replacen(" --guard", "", 1)
            } else {
                command.replacen(" ; ignore_errors=", " --guard ; ignore_errors=", 1)
            };
            let mut bad = current.clone();
            bad["ExecStart"] = json!(changed_guard);
            assert!(terminal_owner(&bad, original).is_err());
        }
    }
    #[test]
    fn collected_terminal_raw_commands_keep_terminal_identity_and_success_gates() {
        let rows = collected_terminal_owners();
        for kind in ["owner", "guard"] {
            for (field, value) in [
                ("Id", "foreign.service"),
                ("LoadState", "not-found"),
                ("InvocationID", "ffffffffffffffffffffffffffffffff"),
                ("MainPID", "1"),
                ("NRestarts", "1"),
                ("ActiveState", "active"),
                ("SubState", "running"),
                ("Result", "exit-code"),
                ("ExecMainStatus", "1"),
            ] {
                let mut bad = rows[kind]["raw_current"].clone();
                bad[field] = json!(value);
                assert!(
                    terminal_owner(&bad, &rows[kind]["raw_original"]).is_err(),
                    "accepted {kind} {field}"
                );
            }
        }
    }
    fn b(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/fixture").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn owner(name: &str, iid: &str, pid: &str) -> Value {
        json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":pid,"NRestarts":"0",
            "ActiveState":"inactive","SubState":"dead","Result":"success","ExecMainStatus":"0",
            "ExecStart":"{ path=/sealed/assembler ; argv[]=/sealed/assembler ; ignore_errors=no }"})
    }
    fn journal(name: &str, iid: &str, start: u64, finish: u64) -> Vec<u8> {
        let rows = [
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,
            "__REALTIME_TIMESTAMP":(start*1000+999).to_string(),"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {name}.")}),
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,
            "__REALTIME_TIMESTAMP":(finish*1000+999).to_string(),"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{name}: Deactivated successfully.")}),
        ];
        rows.iter()
            .map(|v| serde_json::to_string(v).unwrap() + "\n")
            .collect::<String>()
            .into_bytes()
    }
    fn fixture() -> (Value, Origin, Value, Value, Value, Vec<u8>, Vec<u8>) {
        let iid = "d".repeat(32);
        let guard_iid = "e".repeat(32);
        let launch = json!({"unit":UNIT,"stage":"assembly","invocation_id":iid,"guard_unit":GUARD,"guard_invocation_id":guard_iid,
            "owner":owner(UNIT,&iid,"10"),"guard":owner(GUARD,&guard_iid,"11"),"started_unix_millis":1000,
            "recovery_plan":b("plan.json"),"admission":b("admission.json")});
        let plan = json!({"executable_sha256":"b".repeat(64),"source_capture":b("sources.json"),
            "original_terminal":b("original-terminal.json"),"suffix_proof":b("suffix.json")});
        let outcome = json!({"schema":"jetstreamer-epoch204-assembly-only-recovery-outcome-v1","epoch":204,"unit":UNIT,
            "invocation_id":iid,"guard_unit":GUARD,"guard_invocation_id":guard_iid,"plan_sha256":launch["recovery_plan"]["sha256"],
            "executable_sha256":plan["executable_sha256"],"admission_sha256":launch["admission"]["sha256"],
            "source_capture":plan["source_capture"],"original_terminal":plan["original_terminal"],"suffix_proof":plan["suffix_proof"],
            "original_invocation_id":OLD_IID,"original_outcome":"failed_or_stopped","private_output":OUTPUT,
            "epoch_started_unix_millis":ORIGIN,"slots_merged":432000,"source_archives":2,"archive_bytes":114228848867u64,
            "archive_sha256":"c".repeat(64),"started_unix_millis":1001,"finished_unix_millis":2000,
            "no_replay":true,"new_native_initialization_performed":false,"independent_final_archive_verification_passed":false,
            "current_plugin_verification_passed":false,"authority":denied()});
        let census: BTreeMap<String, Value> = context::closed_names()
            .into_iter()
            .map(|n| {
                let row = owner(&n, "", "0");
                (n, row)
            })
            .collect();
        let origin = Origin {
            schema: "jetstreamer-epoch204-assembly-success-origin-v1".into(),
            context: AcceptedContext {
                fleet: b("fleet.json"),
                observer: b("observer.json"),
            },
            observer_history: vec![],
            full209_terminal_peer: None,
            launch: b("launch.json"),
            guard_current: census[GUARD].clone(),
            guard_manager_journal: b("guard-journal.jsonl"),
            guard_cgroup_empty: true,
            guard_cgroup: json!({"absent":true}),
            census_before: census.clone(),
            census_after: census.clone(),
        };
        let terminal = json!({"unit":UNIT,"invocation_id":iid,"result":"natural_success","current_unit":census[UNIT],"cgroup_empty":true});
        // A guard starting after the producer is permitted; its exact original
        // IID and natural finish, not an assumed launch ordering, are required.
        (
            terminal,
            origin,
            launch,
            plan,
            outcome,
            journal(UNIT, &iid, 1000, 2000),
            journal(GUARD, &guard_iid, 1100, 2100),
        )
    }
    #[test]
    fn collected_assembly_success_keeps_empty_current_iids_and_exact_original_journals() {
        let (terminal, origin, launch, plan, outcome, producer, guard) = fixture();
        facts(
            &terminal, &origin, &launch, &plan, &outcome, &producer, &guard,
        )
        .unwrap();
        assert_eq!(terminal["current_unit"]["InvocationID"], "");
        assert_eq!(origin.guard_current["InvocationID"], "");
        assert_ne!(
            terminal["invocation_id"],
            terminal["current_unit"]["InvocationID"]
        );
        assert_eq!(
            completion_window(&producer, UNIT, s(&launch, "invocation_id").unwrap()).unwrap(),
            (1000, 2000)
        );
    }
    #[test]
    fn collected_success_requires_both_complete_same_iid_pid1_journals() {
        let (terminal, origin, launch, plan, outcome, producer, guard) = fixture();
        for (p, g) in [
            (vec![], guard.clone()),
            (producer.clone(), vec![]),
            (journal(UNIT, &"f".repeat(32), 1000, 2000), guard.clone()),
            (
                producer.clone(),
                journal(GUARD, &"f".repeat(32), 1100, 2100),
            ),
            (
                journal(GUARD, s(&launch, "invocation_id").unwrap(), 1000, 2000),
                guard.clone(),
            ),
        ] {
            assert!(facts(&terminal, &origin, &launch, &plan, &outcome, &p, &g).is_err());
        }
        for field in ["_PID", "_UID", "INVOCATION_ID", "UNIT", "MESSAGE"] {
            let mut rows: Vec<Value> = std::str::from_utf8(&producer)
                .unwrap()
                .lines()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            rows[1][field] = json!("foreign");
            let bad = rows
                .iter()
                .map(|v| serde_json::to_string(v).unwrap() + "\n")
                .collect::<String>();
            assert!(
                facts(
                    &terminal,
                    &origin,
                    &launch,
                    &plan,
                    &outcome,
                    bad.as_bytes(),
                    &guard
                )
                .is_err(),
                "accepted {field}"
            );
        }
        let mut rows: Vec<Value> = std::str::from_utf8(&producer)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        rows.pop();
        assert!(
            facts(
                &terminal,
                &origin,
                &launch,
                &plan,
                &outcome,
                serde_json::to_string(&rows[0]).unwrap().as_bytes(),
                &guard
            )
            .is_err()
        );
    }
    #[test]
    fn collected_success_rejects_replacements_restarts_live_claims_and_changed_census() {
        let (terminal, origin, launch, plan, outcome, producer, guard) = fixture();
        for name in [UNIT, GUARD] {
            for (key, value) in [
                ("InvocationID", json!("f".repeat(32))),
                ("NRestarts", json!("1")),
                ("MainPID", json!("12")),
                ("ActiveState", json!("active")),
                ("SubState", json!("running")),
                ("Result", json!("exit-code")),
                ("ExecMainStatus", json!("1")),
                ("ExecStart", json!("/foreign")),
            ] {
                let mut t = terminal.clone();
                let mut o: Origin =
                    serde_json::from_value(serde_json::to_value(&origin).unwrap()).unwrap();
                o.census_before.get_mut(name).unwrap()[key] = value;
                o.census_after = o.census_before.clone();
                if name == UNIT {
                    t["current_unit"] = o.census_before[UNIT].clone();
                } else {
                    o.guard_current = o.census_before[GUARD].clone();
                }
                assert!(
                    facts(&t, &o, &launch, &plan, &outcome, &producer, &guard).is_err(),
                    "accepted {name} {key}"
                );
            }
        }
        let mut o: Origin = serde_json::from_value(serde_json::to_value(&origin).unwrap()).unwrap();
        o.census_before.insert(
            "horizon-qualify-204-foreign.service".into(),
            json!({"MainPID":"10","NRestarts":"0","ActiveState":"active","SubState":"running"}),
        );
        o.census_after = o.census_before.clone();
        assert!(facts(&terminal, &o, &launch, &plan, &outcome, &producer, &guard).is_err());
        o.census_before
            .remove("horizon-qualify-204-foreign.service");
        assert!(facts(&terminal, &o, &launch, &plan, &outcome, &producer, &guard).is_err());
        o.census_before.remove(OLD_UNIT);
        o.census_after = o.census_before.clone();
        assert!(facts(&terminal, &o, &launch, &plan, &outcome, &producer, &guard).is_err());
    }
    #[test]
    fn collected_success_cannot_relabel_failure_or_swap_outcome_source_and_clock_bindings() {
        let (terminal, origin, launch, plan, outcome, producer, guard) = fixture();
        for (key, value) in [
            ("schema", json!("failed")),
            ("unit", json!(OLD_UNIT)),
            ("invocation_id", json!("f".repeat(32))),
            ("guard_invocation_id", json!("f".repeat(32))),
            ("source_capture", json!({})),
            ("plan_sha256", json!("f".repeat(64))),
            ("admission_sha256", json!("f".repeat(64))),
            ("original_outcome", json!("natural_success")),
            ("started_unix_millis", json!(999)),
            ("finished_unix_millis", json!(2001)),
            ("slots_merged", json!(431999)),
            ("independent_final_archive_verification_passed", json!(true)),
            ("current_plugin_verification_passed", json!(true)),
        ] {
            let mut changed = outcome.clone();
            changed[key] = value;
            assert!(
                facts(
                    &terminal, &origin, &launch, &plan, &changed, &producer, &guard
                )
                .is_err(),
                "accepted {key}"
            );
        }
        let mut failed = terminal.clone();
        failed["result"] = json!("failed");
        assert!(
            facts(
                &failed, &origin, &launch, &plan, &outcome, &producer, &guard
            )
            .is_err()
        );
        let failure = json!({"_PID":"1","_UID":"0","UNIT":UNIT,"INVOCATION_ID":launch["invocation_id"],
            "__REALTIME_TIMESTAMP":"1500000","MESSAGE":"horizon-qualify-204-assembly-only-recovery-v2.service: Failed","MESSAGE_ID":"failure"});
        let rows: Vec<Value> = std::str::from_utf8(&producer)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        let bad = [rows[0].clone(), failure, rows[1].clone()]
            .iter()
            .map(|v| serde_json::to_string(v).unwrap() + "\n")
            .collect::<String>();
        assert!(
            facts(
                &terminal,
                &origin,
                &launch,
                &plan,
                &outcome,
                bad.as_bytes(),
                &guard
            )
            .is_err()
        );
    }
}
