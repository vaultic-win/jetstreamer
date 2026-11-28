// One fixed, successful check-only predecessor for the paired retirement phase.
// This is provenance and fresh terminal closure, never a second live PID waiver.
const CHECK_UNIT: &str = "horizon-235237-index939-check-only-v1.service";
const RETIRE_UNIT: &str = "horizon-235237-index939-retire-v1.service";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletedCurrentCheck {
    plan: Evidence,
    result: Evidence,
    terminal: Evidence,
}
fn peer_shape(p: &Plan) -> Result<()> {
    if let Some(o) = &p.current_operation {
        if !o.check_only {
            ensure!(
                p.completed_check.is_some(),
                "retirement lacks successful check predecessor"
            );
        }
    }
    if let Some(peer) = &p.completed_check {
        let o = p
            .current_operation
            .as_ref()
            .context("predecessor without current operation")?;
        ensure!(
            o.unit == RETIRE_UNIT && !o.check_only,
            "predecessor only belongs to fixed retirement phase"
        );
        let mut paths = BTreeSet::new();
        for e in [&peer.plan, &peer.result, &peer.terminal] {
            ensure!(
                e.uid == 0
                    && ordinary_path(&e.path)
                    && e.path.starts_with("/var/lib/jetstreamer")
                    && valid_sha(&e.sha256)
                    && paths.insert(e.path.clone()),
                "unsafe or overlapping completed-check evidence"
            );
        }
        ensure!(
            !paths.contains(&o.plan_path),
            "current and previous plans overlap"
        );
    }
    Ok(())
}
fn peer_selection(p: &Plan) -> Result<Value> {
    let mut v = serde_json::to_value(p)?;
    let object = v.as_object_mut().context("selection is not an object")?;
    object.remove("current_operation");
    object.remove("completed_check");
    Ok(v)
}
fn peer_result_binding(
    p: &Plan,
    previous: &Plan,
    result: &Value,
    terminal: &Value,
) -> Result<Actor> {
    let supplied = p
        .completed_check
        .as_ref()
        .context("missing completed check")?;
    let next = p
        .current_operation
        .as_ref()
        .context("missing successor operation")?;
    let old = previous
        .current_operation
        .as_ref()
        .context("missing predecessor operation")?;
    ensure!(
        previous.completed_check.is_none()
            && old.check_only
            && old.unit == CHECK_UNIT
            && next.unit == RETIRE_UNIT
            && !next.check_only,
        "foreign or chained phase predecessor"
    );
    validate_plan(previous)?;
    ensure!(
        old.plan_path == supplied.plan.path
            && old.digest_transport != next.digest_transport
            && old.plan_path != next.plan_path
            && old.installed != next.installed
            && serde_json::to_value(&old.binary)? == serde_json::to_value(&next.binary)?,
        "phase transports or qualified executables differ"
    );
    ensure!(
        peer_selection(p)? == peer_selection(previous)?,
        "check and retirement selections/readsets/authority differ"
    );
    ensure!(
        result["status"] == "check-passed"
            && result["operation"] == supplied.plan.sha256
            && result["payload_read"] == false
            && result["capacity_credit_bytes"] == 0
            && result["indexes"] == serde_json::to_value(&previous.indexes)?
            && result["preserved_source_archives"] == serde_json::to_value(&previous.owners)?
            && result["source_review"] == serde_json::to_value(&previous.source_review)?,
        "predecessor result is not the exact successful no-payload check"
    );
    let auth = &result["reference_closure"]["authenticated_current_operation"];
    let iid = auth["invocation_id"]
        .as_str()
        .context("predecessor actual IID")?;
    let pid = auth["pid"].as_u64().context("predecessor actual PID")?;
    let ticks = auth["start_ticks"]
        .as_u64()
        .context("predecessor actual start ticks")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && pid > 0
            && ticks > 0
            && auth["unit"] == CHECK_UNIT
            && auth["plan_sha256"] == supplied.plan.sha256
            && auth["argv"] == serde_json::to_value(&old.argv)?
            && auth["self_source_recipe"] == serde_json::to_value(&old.recipe)?
            && auth["native"]["Id"] == CHECK_UNIT
            && auth["native"]["InvocationID"] == iid,
        "successful check lacks original exact native payload binding"
    );
    ensure!(
        terminal["schema"] == "horizon-index-completed-current-check-terminal-v1"
            && terminal["original_unit"] == CHECK_UNIT
            && terminal["original_invocation_id"] == iid
            && terminal["original_main_pid"] == pid
            && terminal["original_start_ticks"] == ticks,
        "terminal proof belongs to another check payload"
    );
    let actual = &terminal["actual_terminal"];
    for (key, value) in [
        ("Id", CHECK_UNIT),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("NRestarts", "0"),
        ("Job", ""),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            actual[key] == value,
            "original check terminal {key} differs"
        );
    }
    let events = terminal["PID1_events"]
        .as_array()
        .context("missing original PID1 events")?;
    ensure!(
        events.iter().any(|e| e["UNIT"] == CHECK_UNIT
            && e["INVOCATION_ID"] == iid
            && e["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.ends_with("Deactivated successfully."))),
        "missing genuine original successful PID1 completion"
    );
    Ok(Actor {
        unit: CHECK_UNIT.into(),
        invocation_id: iid.into(),
        historical_provenance: Some(ActorProvenance {
            evidence: supplied.terminal.clone(),
            unit_json_pointer: "/original_unit".into(),
            invocation_id_json_pointer: "/original_invocation_id".into(),
        }),
    })
}
pub(super) fn completed_current_check(p: &Plan, jobs: &str) -> Result<Option<Value>> {
    let Some(peer) = &p.completed_check else {
        return Ok(None);
    };
    peer_shape(p)?;
    let previous: Plan = serde_json::from_slice(&evidence(&peer.plan)?)?;
    let result: Value = serde_json::from_slice(&evidence(&peer.result)?)?;
    let terminal: Value = serde_json::from_slice(&evidence(&peer.terminal)?)?;
    let actor = peer_result_binding(p, &previous, &result, &terminal)?;
    let old = previous
        .current_operation
        .as_ref()
        .context("old operation")?;
    installed_bytes(&old.installed, &old.recipe)?;
    ensure!(
        !jobs.split_whitespace().any(|s| s == CHECK_UNIT),
        "completed check has queued relaunch"
    );
    let out = native_output(
        "/usr/bin/systemctl",
        &[
            "show",
            CHECK_UNIT,
            "--all",
            "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,NRestarts,Restart,Job,Triggers,TriggeredBy,OnSuccess,OnFailure,DropInPaths,FragmentPath,Result,ExecMainStatus",
        ],
    )?;
    let text = std::str::from_utf8(&out.stdout)?;
    let m = props(text)?;
    no_triggers(&m)?;
    ensure!(
        m.get("Id") == Some(&CHECK_UNIT)
            && m.get("ControlGroup") == Some(&"")
            && m.get("Result") == Some(&"success")
            && m.get("ExecMainStatus") == Some(&"0"),
        "predecessor current terminal result changed"
    );
    if m.get("LoadState") == Some(&"loaded") {
        ensure!(
            m.get("FragmentPath") == Some(&old.installed.to_str().context("old installed UTF8")?),
            "predecessor installed FragmentPath changed"
        );
    }
    let state = actor_state(&actor, text, out.status.code(), Some(&terminal))?;
    Ok(Some(
        json!({"installed":old.installed,"recipe_sha256":old.recipe.sha256,"plan":peer.plan,"result":peer.result,"terminal":peer.terminal,"actual_terminal":state,"same_qualified_executable":old.binary,"same_selection_and_readsets":true,"live_PID_exemption":false}),
    ))
}
#[cfg(test)]
mod completed_check_tests {
    use super::*;
    fn ev(path: impl Into<PathBuf>) -> Evidence {
        Evidence {
            path: path.into(),
            sha256: "a".repeat(64),
            uid: 0,
        }
    }
    fn operation(check: bool, preflight: bool) -> Operation {
        let unit = if check { CHECK_UNIT } else { RETIRE_UNIT };
        let binary = ev("/var/lib/jetstreamer/pair/qualified-tool");
        let plan_path = PathBuf::from(if check {
            "/var/lib/jetstreamer/pair/check.json"
        } else {
            "/var/lib/jetstreamer/pair/retire.json"
        });
        let mut argv = vec![
            binary.path.display().to_string(),
            "--plan".into(),
            plan_path.display().to_string(),
            "--plan-sha256".into(),
            "env".into(),
            "--self-sha256".into(),
            binary.sha256.clone(),
        ];
        if check {
            argv.push("--check-only".into());
        } else if preflight {
            argv.push("--retirement-preflight".into());
        }
        Operation {
            unit: unit.into(),
            installed: Path::new("/etc/systemd/system").join(unit),
            recipe: ev(Path::new("/var/lib/jetstreamer/pair").join(unit)),
            binary,
            plan_path,
            digest_transport: PathBuf::from(if check {
                "/var/lib/jetstreamer/pair/check.env"
            } else {
                "/var/lib/jetstreamer/pair/retire.env"
            }),
            check_only: check,
            retirement_preflight: preflight,
            argv,
            expected_read_only_paths: Vec::new(),
            expected_bind_read_only_paths: String::new(),
        }
    }
    fn clone_plan(p: &Plan) -> Plan {
        serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap()
    }
    fn pair(preflight: bool) -> (Plan, Plan, Value, Value) {
        let mut old = crate::tests::plan();
        old.current_operation = Some(operation(true, false));
        let mut next = clone_plan(&old);
        next.current_operation = Some(operation(false, preflight));
        let mut plan_binding = ev(old.current_operation.as_ref().unwrap().plan_path.clone());
        plan_binding.sha256 = hash(&serde_json::to_vec(&old).unwrap());
        next.completed_check = Some(CompletedCurrentCheck {
            plan: plan_binding,
            result: ev("/var/lib/jetstreamer/pair/check-result.json"),
            terminal: ev("/var/lib/jetstreamer/pair/check-terminal.json"),
        });
        let iid = "b".repeat(32);
        let o = old.current_operation.as_ref().unwrap();
        let result = json!({"status":"check-passed","operation":next.completed_check.as_ref().unwrap().plan.sha256,"indexes":old.indexes,"preserved_source_archives":old.owners,"source_review":old.source_review,"payload_read":false,"capacity_credit_bytes":0,"reference_closure":{"authenticated_current_operation":{"unit":CHECK_UNIT,"invocation_id":iid,"pid":42,"start_ticks":123,"plan_sha256":next.completed_check.as_ref().unwrap().plan.sha256,"argv":o.argv,"self_source_recipe":o.recipe,"native":{"Id":CHECK_UNIT,"InvocationID":iid}}}});
        let terminal = json!({"schema":"horizon-index-completed-current-check-terminal-v1","original_unit":CHECK_UNIT,"original_invocation_id":iid,"original_main_pid":42,"original_start_ticks":123,"actual_terminal":{"Id":CHECK_UNIT,"ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","ControlGroup":"","NRestarts":"0","Job":"","Result":"success","ExecMainStatus":"0"},"PID1_events":[{"UNIT":CHECK_UNIT,"INVOCATION_ID":iid,"MESSAGE":"Completed check. Deactivated successfully."}]});
        (next, old, result, terminal)
    }
    #[test]
    fn successful_fixed_check_binds_both_no_mutation_preflight_and_retirement() {
        for preflight in [false, true] {
            let (next, old, result, terminal) = pair(preflight);
            validate_plan(&next).unwrap();
            validate_plan(&old).unwrap();
            let actor = peer_result_binding(&next, &old, &result, &terminal).unwrap();
            assert_eq!(actor.unit, CHECK_UNIT);
            assert_eq!(actor.invocation_id, "b".repeat(32));
            assert!(indirect_reference(
                b"tool\0--plan=/var/lib/jetstreamer/pair/check.json\0",
                &next
            ));
            assert!(!indirect_reference(
                b"tool\0--plan=/var/lib/jetstreamer/pair/check.json-sibling\0",
                &next
            ));
        }
    }
    #[test]
    fn completed_check_never_normalizes_selection_header_graph_or_authority_changes() {
        let (next, old, result, terminal) = pair(false);
        for (pointer, value) in [
            ("/indexes/0/header_hex", json!("00")),
            ("/indexes/0/original_ctime", json!(0)),
            ("/indexes/0/identity/inode", json!(999)),
            ("/source_review/sha256", json!("c".repeat(64))),
            ("/remote_mutations", json!(true)),
            ("/state", json!("/var/lib/jetstreamer/other-state")),
        ] {
            let mut v = serde_json::to_value(&next).unwrap();
            *v.pointer_mut(pointer).unwrap() = value;
            let altered: Plan = serde_json::from_value(v).unwrap();
            assert!(
                peer_result_binding(&altered, &old, &result, &terminal).is_err(),
                "{pointer}"
            );
        }
        let mut wrong = clone_plan(&next);
        wrong.current_operation.as_mut().unwrap().binary.sha256 = "c".repeat(64);
        assert!(peer_result_binding(&wrong, &old, &result, &terminal).is_err());
    }
    #[test]
    fn completed_check_requires_exact_success_payload_and_original_terminal_pid1_evidence() {
        let (next, old, result, terminal) = pair(false);
        for (pointer, value) in [
            ("/status", json!("failed")),
            ("/payload_read", json!(true)),
            ("/capacity_credit_bytes", json!(1)),
            ("/operation", json!("c".repeat(64))),
            (
                "/reference_closure/authenticated_current_operation/start_ticks",
                json!(124),
            ),
        ] {
            let mut altered = result.clone();
            *altered.pointer_mut(pointer).unwrap() = value;
            assert!(
                peer_result_binding(&next, &old, &altered, &terminal).is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            ("/original_main_pid", json!(43)),
            ("/actual_terminal/Result", json!("exit-code")),
            ("/actual_terminal/ExecMainStatus", json!("1")),
            ("/actual_terminal/MainPID", json!("42")),
            ("/actual_terminal/Job", json!("99")),
            ("/PID1_events", json!([])),
        ] {
            let mut altered = terminal.clone();
            *altered.pointer_mut(pointer).unwrap() = value;
            assert!(
                peer_result_binding(&next, &old, &result, &altered).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn phase_chains_missing_predecessors_or_shared_transports_are_rejected() {
        let (next, old, result, terminal) = pair(false);
        let mut missing = clone_plan(&next);
        missing.completed_check = None;
        assert!(validate_plan(&missing).is_err());
        let mut chained = clone_plan(&old);
        chained.completed_check = Some(CompletedCurrentCheck {
            plan: ev("/var/lib/jetstreamer/pair/previous.json"),
            result: ev("/var/lib/jetstreamer/pair/previous-result.json"),
            terminal: ev("/var/lib/jetstreamer/pair/previous-terminal.json"),
        });
        assert!(peer_result_binding(&next, &chained, &result, &terminal).is_err());
        let mut shared = clone_plan(&next);
        shared.current_operation.as_mut().unwrap().digest_transport = old
            .current_operation
            .as_ref()
            .unwrap()
            .digest_transport
            .clone();
        assert!(peer_result_binding(&shared, &old, &result, &terminal).is_err());
        let mut check_with_peer = clone_plan(&next);
        check_with_peer.current_operation = Some(operation(true, false));
        assert!(peer_shape(&check_with_peer).is_err());
        let mut invalid_mode = clone_plan(&old);
        invalid_mode
            .current_operation
            .as_mut()
            .unwrap()
            .retirement_preflight = true;
        assert!(validate_plan(&invalid_mode).is_err());
    }
}
#[cfg(test)]
mod actual_command_native_tests {
    use super::*;
    #[test]
    #[ignore = "Root separately admitted metadata-only query of the fixed already closed923 check service"]
    fn native_closed923_command_properties_use_genuine_direct_array_representation() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let unit = "horizon-235237-index923-check-only-v1.service";
        let raw = systemctl(&[
            "show",
            unit,
            "--all",
            "--property=ActiveState,MainPID,ControlPID,NRestarts,Job",
        ])
        .unwrap();
        let m = props(&raw).unwrap();
        assert_eq!(m.get("ActiveState"), Some(&"failed"));
        for key in ["MainPID", "ControlPID", "NRestarts"] {
            assert_eq!(m.get(key), Some(&"0"));
        }
        assert_eq!(m.get("Job"), Some(&""));
        let object = "/org/freedesktop/systemd1/unit/horizon_2d235237_2dindex923_2dcheck_2donly_2dv1_2eservice";
        for (property, expected) in [("ExecStart", 1), ("ExecCondition", 0), ("ExecReload", 0)] {
            let out = native_output(
                "/usr/bin/busctl",
                &[
                    "--json=short",
                    "--timeout=2s",
                    "get-property",
                    "org.freedesktop.systemd1",
                    object,
                    "org.freedesktop.systemd1.Service",
                    property,
                ],
            )
            .unwrap();
            assert!(out.status.success());
            let commands = parse_commands(&out.stdout).unwrap();
            assert_eq!(commands.len(), expected);
            if property == "ExecStart" {
                assert_eq!(commands[0].1.last().unwrap(), "--check-only");
                assert!(!commands[0].2);
            }
        }
    }
}
