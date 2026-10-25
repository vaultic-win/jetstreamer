//! Completed downstream owners retain their actual launch identity after PID1
//! clears the inactive unit's current invocation. Raw manager state is preserved.
use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    schema: String,
    stage: Stage,
    context: AcceptedContext,
    #[serde(default)]
    observer_history: Vec<BoundFile>,
    launch: BoundFile,
    queued_jobs_before: BoundFile,
    queued_jobs_after: BoundFile,
    census_before: BTreeMap<String, Value>,
    census_after: BTreeMap<String, Value>,
}
#[derive(Clone)]
struct Inputs {
    launch: Value,
    stage_spec: Value,
    admission: Value,
}
fn terminal_owner(current: &Value, launch: &Value) -> Result<()> {
    let expected = &launch["owner"];
    let iid = s(launch, "invocation_id")?;
    ensure!(
        id(iid)
            && expected["InvocationID"] == iid
            && current["Id"] == expected["Id"]
            && current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == iid || current["InvocationID"] == "")
            && ownership::command_matches(
                s(current, "ExecStart")?,
                s(launch, "expected_exec_start")?
            )
            && ownership::command_matches(
                s(expected, "ExecStart")?,
                s(launch, "expected_exec_start")?
            ),
        "204 completed downstream owner is live, replaced, restarted or not successful"
    );
    Ok(())
}
fn origin_inputs(origin: &Origin) -> Result<(context::WorkContext, Inputs)> {
    let context = context::WorkContext::new(
        origin.context.fleet.clone(),
        origin.context.observer.clone(),
        origin.observer_history.clone(),
    )?;
    let fleet = bound_json(&origin.context.fleet)?;
    let accepted_plan = bound_json(&BoundFile {
        path: s(&fleet, "plan")?.into(),
        sha256: s(&fleet, "plan_sha256")?.into(),
    })?;
    let claim: ownership::Claim =
        serde_json::from_value(accepted_plan["assembly204_recovery"].clone())?;
    ensure!(
        claim.actor_launch == origin.launch,
        "204 completed stage changed its accepted actor launch"
    );
    let launch = read(&origin.launch)?;
    ensure!(
        launch["recovery_plan"] == private157::binding(&claim.recovery_plan)
            && launch["admission"] == private157::binding(&claim.admission),
        "204 completed downstream launch changed its original assembly lineage"
    );
    let original = read(&claim.launch)?;
    ownership::validate_launch(
        &original,
        &claim.recovery_plan,
        &read(&claim.recovery_plan)?,
        &claim.admission,
    )?;
    let stage_spec = read(&serde_json::from_value(launch["stage_spec"].clone())?)?;
    let admission = read(&serde_json::from_value(launch["stage_admission"].clone())?)?;
    let raw = sealed(
        &serde_json::from_value(launch["manager_journal"].clone())?,
        8 << 20,
    )?;
    ensure!(
        launch["started_unix_millis"]
            == ownership::manager_shape(
                &raw,
                origin.stage.unit(),
                s(&launch, "invocation_id")?,
                false
            )?,
        "204 completed downstream original launch clock differs"
    );
    // These are saved, sealed qualifications. Do not reapply the launch-only
    // 15-minute admission deadline to a stage that legitimately ran for hours.
    let x: StageSpec = serde_json::from_value(stage_spec.clone())?;
    ensure!(
        x.stage == origin.stage,
        "204 completed stage spec phase differs"
    );
    let (source, _) = lineage::load_source(&x.source)?;
    let candidate = capacity::candidate_with_anchor(
        x.stage,
        n(&source, "archive_bytes")?,
        anchor_reserve(&x)?,
    )?;
    let cap = read(&serde_json::from_value(admission["capacity"].clone())?)?;
    capacity::validate_capacity(&cap, candidate.memory_max_bytes, candidate.additional_bytes)?;
    capacity::validate_provenance(&cap)?;
    Ok((
        context,
        Inputs {
            launch,
            stage_spec,
            admission,
        },
    ))
}
fn queued_jobs(raw: &[u8]) -> Result<()> {
    ensure!(
        inactive_status::queued_job_units(raw)?
            .iter()
            .all(|name| !name
                .split(|c: char| !c.is_ascii_digit())
                .any(|number| number == "204")),
        "204 completed downstream has a queued replacement or trigger job"
    );
    Ok(())
}
fn jobs() -> Result<Vec<u8>> {
    let output = ProcessCommand::new("/usr/bin/systemctl")
        .args([
            "list-jobs",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 8 << 20,
        "204 downstream queued-job census incomplete"
    );
    queued_jobs(&output.stdout)?;
    Ok(output.stdout)
}
fn facts(
    t: &Value,
    origin: &Origin,
    input: &Inputs,
    outcome: &Value,
    raw: &[u8],
    jobs: (&[u8], &[u8]),
) -> Result<()> {
    ensure!(
        jobs.0 == jobs.1,
        "204 downstream queued-job census changed during capture"
    );
    queued_jobs(jobs.0)?;
    let stage = origin.stage;
    let launch = &input.launch;
    let x = &input.stage_spec;
    let admission = &input.admission;
    let iid = s(launch, "invocation_id")?;
    ensure!(
        origin.schema == "jetstreamer-epoch204-downstream-success-origin-v1"
            && stage != Stage::Assembly
            && t["unit"] == stage.unit()
            && t["result"] == "natural_success"
            && t["invocation_id"] == iid
            && t["cgroup_empty"] == true
            && origin.census_before == origin.census_after
            && origin.census_before.get(stage.unit()) == Some(&t["current_unit"])
            && launch["schema"] == "jetstreamer-epoch204-assembly-recovery-launch-v1"
            && launch["epoch"] == 204
            && launch["stage"] == serde_json::to_value(stage)?
            && launch["unit"] == stage.unit()
            && launch["owner"]["Id"] == stage.unit()
            && is_live(&launch["owner"])
            && launch["main_pid"] == launch["owner"]["MainPID"]
            && launch["guard_unit"] == ""
            && launch["guard"].is_null()
            && launch["producer_limits"]["memory_max_bytes"] == stage.memory()
            && launch["epoch_started_unix_millis"] == ORIGIN
            && x["schema"] == "jetstreamer-epoch204-assembly-recovery-stage-spec-v1"
            && x["stage"] == serde_json::to_value(stage)?
            && admission["schema"] == "jetstreamer-epoch204-assembly-recovery-stage-admission-v1"
            && admission["stage"] == serde_json::to_value(stage)?
            && admission["stage_spec"] == launch["stage_spec"]
            && admission["source"] == x["source"]
            && admission["runner"]["sha256"] == launch["issuer"]["executable_sha256"],
        "204 completed downstream launch, admission, spec or complete census differs"
    );
    ownership::validate_closed_ownership(&origin.census_before, None)?;
    terminal_owner(&t["current_unit"], launch)?;
    let start = ownership::manager_shape(raw, stage.unit(), iid, true)?;
    let finish = serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .find(|row| row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
        .context("204 downstream natural completion absent")?;
    let finish = s(&finish, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1000;
    let at = n(&outcome["issuer"], "recorded_unix_seconds")?;
    ensure!(
        launch["started_unix_millis"] == start
            && start / 1000 <= at
            && at <= finish / 1000
            && n(admission, "recorded_unix_seconds")? <= start / 1000
            && start / 1000 - n(admission, "recorded_unix_seconds")? <= 900
            && outcome["schema"] == "jetstreamer-epoch204-assembly-recovery-stage-outcome-v1"
            && outcome["stage"] == serde_json::to_value(stage)?
            && outcome["unit"] == stage.unit()
            && outcome["invocation_id"] == iid
            && outcome["source"] == x["source"]
            && outcome["spec"] == launch["stage_spec"]
            && outcome["admission"] == launch["stage_admission"]
            && outcome["predecessor_gates"] == x["gates"]
            && outcome["issuer"]["invocation_id"] == iid
            && outcome["issuer"]["spec"] == launch["stage_spec"]
            && outcome["issuer"]["executable_sha256"] == admission["runner"]["sha256"]
            && outcome["passed"] == true
            && outcome["local_retirement_authorized"] == false
            && outcome["retirement_boundary_only"] == (stage == Stage::Boundary)
            && n(outcome, "archive_bytes")? > 0
            && n(outcome, "archive_bytes")? <= OUTPUT_MAX
            && is_lower_hex(s(outcome, "archive_sha256")?, 64),
        "204 completed downstream outcome or genuine manager window differs"
    );
    deny(&launch["authority"])?;
    deny(&admission["authority"])?;
    deny(&outcome["authority"])
}
pub(in crate::fleet::assembly204_recovery) fn validate(t: &Value, raw: &[u8]) -> Result<()> {
    let origin: Origin = serde_json::from_value(t["downstream_success_origin"].clone())?;
    let (context, input) = origin_inputs(&origin)?;
    context.validate_saved(&origin.census_before)?;
    let outcome = read(&serde_json::from_value(t["outcome"].clone())?)?;
    let x: StageSpec = serde_json::from_value(input.stage_spec.clone())?;
    ensure!(
        t["outcome"]["path"]
            == x.output_directory
                .join("outcome.json")
                .to_string_lossy()
                .as_ref(),
        "204 completed downstream outcome path differs"
    );
    let (source, _) = lineage::load_source(&x.source)?;
    ensure!(
        outcome["archive_bytes"] == source["archive_bytes"]
            && outcome["archive_sha256"] == source["archive_sha256"],
        "204 completed downstream immutable archive tuple differs"
    );
    ensure!(
        outcome["predecessor_outcomes"] == serde_json::to_value(gates(&x)?)?,
        "204 completed downstream predecessor outcomes differ"
    );
    let before_jobs = sealed(&origin.queued_jobs_before, 8 << 20)?;
    let after_jobs = sealed(&origin.queued_jobs_after, 8 << 20)?;
    facts(
        t,
        &origin,
        &input,
        &outcome,
        raw,
        (&before_jobs, &after_jobs),
    )
}
pub(super) fn capture(c: &Capture, spec: &BoundFile, self_sha: &str) -> Result<()> {
    private(&c.output_directory)?;
    let mut origin = Origin {
        schema: "jetstreamer-epoch204-downstream-success-origin-v1".into(),
        stage: c.stage,
        context: c.context.clone(),
        observer_history: c.observer_history.clone(),
        launch: c.launch.clone(),
        queued_jobs_before: BoundFile {
            path: c.output_directory.join("queued-jobs-before.txt"),
            sha256: String::new(),
        },
        queued_jobs_after: BoundFile {
            path: c.output_directory.join("queued-jobs-after.txt"),
            sha256: String::new(),
        },
        census_before: BTreeMap::new(),
        census_after: BTreeMap::new(),
    };
    ensure!(
        c.stage != Stage::Assembly,
        "204 assembly has its own collected-success proof"
    );
    let (context, input) = origin_inputs(&origin)?;
    let before_jobs = jobs()?;
    custody::write_bytes(&origin.queued_jobs_before.path, &before_jobs)?;
    origin.queued_jobs_before = binding(&origin.queued_jobs_before.path)?;
    origin.census_before = context.census(&context::closed_names())?;
    ownership::no_overlap_current(&origin.census_before, None)?;
    let before = origin
        .census_before
        .get(c.stage.unit())
        .context("204 completed downstream owner omitted")?
        .clone();
    terminal_owner(&before, &input.launch)?;
    let group = capped204205_work::empty_terminal_cgroup(c.stage.unit())?;
    let raw = ownership::manager(c.stage.unit())?;
    ownership::manager_shape(
        &raw,
        c.stage.unit(),
        s(&input.launch, "invocation_id")?,
        true,
    )?;
    let refs =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(ROOT))?;
    ensure!(
        refs.references.is_empty(),
        "204 completed downstream output retains process references"
    );
    let x: StageSpec = serde_json::from_value(input.stage_spec.clone())?;
    let outcome = c
        .outcome
        .as_deref()
        .context("204 successful downstream outcome missing")?;
    ensure!(
        outcome == x.output_directory.join("outcome.json"),
        "204 downstream outcome path differs"
    );
    let file = custody::open_source(outcome)?;
    ensure!(
        file.metadata()?.len() <= 16 << 20
            && file.metadata()?.uid() == 0
            && file.metadata()?.nlink() == 1,
        "204 downstream outcome custody invalid"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    custody::write_bytes(&c.output_directory.join("success-manager.jsonl"), &raw)?;
    let after_jobs = jobs()?;
    custody::write_bytes(&origin.queued_jobs_after.path, &after_jobs)?;
    origin.queued_jobs_after = binding(&origin.queued_jobs_after.path)?;
    origin.census_after = context.census(&context::closed_names())?;
    ownership::no_overlap_current(&origin.census_after, None)?;
    ensure!(
        ownership::manager_records_equal(&ownership::manager(c.stage.unit())?, &raw)?,
        "204 downstream manager lineage changed during capture"
    );
    let t = json!({"schema":"jetstreamer-epoch204-assembly-recovery-success-terminal-v1","unit":c.stage.unit(),
        "invocation_id":input.launch["invocation_id"],"result":"natural_success","current_unit":before,
        "manager_journal":binding(&c.output_directory.join("success-manager.jsonl"))?,"outcome":binding(outcome)?,
        "cgroup_empty":true,"cgroup":group,"downstream_success_origin":origin,"issuer":issuer(spec,self_sha),"authority":denied()});
    ownership::validate_success_terminal(&t, c.stage.unit(), s(&input.launch, "invocation_id")?)?;
    write(&c.output_directory.join("terminal.json"), &t)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/fixture").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn owner(name: &str, iid: &str, active: bool) -> Value {
        json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":if active {"11"}else{"0"},"NRestarts":"0",
            "ActiveState":if active {"active"}else{"inactive"},"SubState":if active {"running"}else{"dead"},
            "Result":"success","ExecMainStatus":"0","ExecStart":"{ path=/sealed/r2 ; argv[]=/sealed/r2 stage ; ignore_errors=no }"})
    }
    fn journal(stage: Stage, iid: &str) -> Vec<u8> {
        [json!({"_PID":"1","_UID":"0","UNIT":stage.unit(),"INVOCATION_ID":iid,
            "__REALTIME_TIMESTAMP":"1000000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":format!("Started {}.",stage.unit())}),
         json!({"_PID":"1","_UID":"0","UNIT":stage.unit(),"INVOCATION_ID":iid,
            "__REALTIME_TIMESTAMP":"2000000","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",stage.unit())})]
            .iter().map(Value::to_string).collect::<Vec<_>>().join("\n").into_bytes()
    }
    fn fixture(stage: Stage) -> (Value, Origin, Inputs, Value, Vec<u8>) {
        let iid = "d".repeat(32);
        let context = AcceptedContext {
            fleet: b("fleet.json"),
            observer: b("observer.json"),
        };
        let source = json!({"kind":"AssemblyRecovery204","completion":b("completion.json")});
        let stage_spec = json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-spec-v1","stage":stage,
            "context":context,"source":source,"gates":[]});
        let launch = json!({"schema":"jetstreamer-epoch204-assembly-recovery-launch-v1","epoch":204,"stage":stage,"unit":stage.unit(),
            "invocation_id":iid,"main_pid":"11","owner":owner(stage.unit(),&iid,true),"guard_unit":"","guard":null,
            "expected_exec_start":owner(stage.unit(),&iid,true)["ExecStart"],"accepted_context":context,
            "producer_limits":{"memory_max_bytes":stage.memory()},"epoch_started_unix_millis":ORIGIN,
            "stage_spec":b("stage.json"),"stage_admission":b("stage-admission.json"),"started_unix_millis":1000,
            "issuer":{"executable_sha256":"c".repeat(64)},"authority":denied()});
        let admission = json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-admission-v1","stage":stage,"stage_spec":b("stage.json"),
            "source":source,"runner":{"sha256":"c".repeat(64)},"recorded_unix_seconds":1,"authority":denied()});
        let outcome = json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-outcome-v1","stage":stage,"unit":stage.unit(),"invocation_id":iid,
            "source":source,"spec":b("stage.json"),"admission":b("stage-admission.json"),"predecessor_gates":[],"passed":true,
            "local_retirement_authorized":false,"retirement_boundary_only":stage==Stage::Boundary,"archive_bytes":114228848867u64,
            "archive_sha256":"e".repeat(64),"issuer":{"invocation_id":iid,"spec":b("stage.json"),"executable_sha256":"c".repeat(64),"recorded_unix_seconds":2},"authority":denied()});
        let census: BTreeMap<String, Value> = context::closed_names()
            .into_iter()
            .map(|name| {
                let row = owner(&name, "", false);
                (name, row)
            })
            .collect();
        let terminal = json!({"unit":stage.unit(),"invocation_id":iid,"result":"natural_success","cgroup_empty":true,"current_unit":census[stage.unit()]});
        let origin = Origin {
            schema: "jetstreamer-epoch204-downstream-success-origin-v1".into(),
            stage,
            context: context.clone(),
            observer_history: vec![],
            launch: b("launch.json"),
            queued_jobs_before: b("jobs-before.txt"),
            queued_jobs_after: b("jobs-after.txt"),
            census_before: census.clone(),
            census_after: census,
        };
        let input = Inputs {
            launch,
            stage_spec,
            admission,
        };
        (terminal, origin, input, outcome, journal(stage, &iid))
    }
    #[test]
    fn all_downstream_successes_keep_the_raw_cleared_iid_and_original_launch() {
        for stage in [
            Stage::Full,
            Stage::Plugin,
            Stage::Boundary,
            Stage::Import,
            Stage::Upload,
        ] {
            let (t, o, i, result, raw) = fixture(stage);
            facts(&t, &o, &i, &result, &raw, (b"", b"")).unwrap();
            assert_eq!(t["current_unit"]["InvocationID"], "");
            assert_ne!(t["current_unit"]["InvocationID"], t["invocation_id"]);
        }
    }
    #[test]
    fn downstream_success_rejects_replacement_live_failed_or_changed_command_owner() {
        for (key, value) in [
            ("InvocationID", json!("f".repeat(32))),
            ("MainPID", json!("22")),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("failed")),
            ("SubState", json!("failed")),
            ("LoadState", json!("not-found")),
            ("Result", json!("exit-code")),
            ("ExecMainStatus", json!("1")),
            ("ExecStart", json!("replacement")),
        ] {
            let (mut t, mut o, i, result, raw) = fixture(Stage::Full);
            t["current_unit"][key] = value;
            o.census_before
                .insert(Stage::Full.unit().into(), t["current_unit"].clone());
            o.census_after = o.census_before.clone();
            assert!(
                facts(&t, &o, &i, &result, &raw, (b"", b"")).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn downstream_success_requires_complete_stable_census_with_no_other_live_204_owner() {
        let (t, o, i, result, raw) = fixture(Stage::Plugin);
        let mut missing = o.clone();
        missing.census_before.remove(OLD_UNIT);
        missing.census_after = missing.census_before.clone();
        assert!(facts(&t, &missing, &i, &result, &raw, (b"", b"")).is_err());
        let mut replaced = o.clone();
        replaced.census_after.insert(
            Stage::Upload.unit().into(),
            owner(Stage::Upload.unit(), "", true),
        );
        assert!(facts(&t, &replaced, &i, &result, &raw, (b"", b"")).is_err());
        let mut overlap = o.clone();
        overlap.census_before.insert(
            "horizon-unknown-204.service".into(),
            owner("horizon-unknown-204.service", "", true),
        );
        overlap.census_after = overlap.census_before.clone();
        assert!(facts(&t, &overlap, &i, &result, &raw, (b"", b"")).is_err());
    }
    #[test]
    fn downstream_success_needs_original_pid1_natural_completion_not_exit_zero_assertions() {
        let (t, o, i, result, raw) = fixture(Stage::Import);
        let text = String::from_utf8(raw).unwrap();
        for bad in [
            text.replace(&"d".repeat(32), &"f".repeat(32)),
            text.replace("\"_PID\":\"1\"", "\"_PID\":\"2\""),
            text.lines().next().unwrap().to_string(),
            text.replace(
                "Deactivated successfully.",
                "Failed with result 'exit-code'.",
            ),
            text.replace("2000000", "500000"),
        ] {
            assert!(facts(&t, &o, &i, &result, bad.as_bytes(), (b"", b"")).is_err());
        }
    }
    #[test]
    fn downstream_success_binds_stage_spec_admission_outcome_issuer_and_manager_clock() {
        let (t, o, i, result, raw) = fixture(Stage::Upload);
        for (key, value) in [
            ("stage", json!("full")),
            ("unit", json!(Stage::Full.unit())),
            ("invocation_id", json!("f".repeat(32))),
            ("source", json!({})),
            ("spec", json!(b("different.json"))),
            ("admission", json!(b("different.json"))),
            ("predecessor_gates", json!([{}])),
            ("passed", json!(false)),
            ("local_retirement_authorized", json!(true)),
            ("retirement_boundary_only", json!(true)),
            ("archive_bytes", json!(0)),
            ("archive_sha256", json!("bad")),
        ] {
            let mut changed = result.clone();
            changed[key] = value;
            assert!(
                facts(&t, &o, &i, &changed, &raw, (b"", b"")).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("invocation_id", json!("f".repeat(32))),
            ("spec", json!(b("different.json"))),
            ("executable_sha256", json!("f".repeat(64))),
            ("recorded_unix_seconds", json!(3)),
        ] {
            let mut changed = result.clone();
            changed["issuer"][key] = value;
            assert!(
                facts(&t, &o, &i, &changed, &raw, (b"", b"")).is_err(),
                "issuer {key}"
            );
        }
    }
    #[test]
    fn downstream_success_rejects_queued_unknown_replacements_and_changed_job_census() {
        let (t, o, i, result, raw) = fixture(Stage::Full);
        let pending = b"123 horizon-unrecognized-204-trigger.service start waiting\n";
        assert!(facts(&t, &o, &i, &result, &raw, (pending, pending)).is_err());
        let unrelated = b"123 horizon-full-verify-205.service start waiting\n";
        assert!(facts(&t, &o, &i, &result, &raw, (unrelated, unrelated)).is_ok());
        assert!(facts(&t, &o, &i, &result, &raw, (b"", unrelated)).is_err());
        assert!(facts(&t, &o, &i, &result, &raw, (b"malformed", b"malformed")).is_err());
    }
    #[test]
    fn downstream_success_rejects_cross_stage_and_admission_rebinding() {
        let (t, o, i, result, raw) = fixture(Stage::Plugin);
        for (member, key, value) in [
            ("launch", "stage", json!("full")),
            ("launch", "main_pid", json!("999")),
            (
                "launch",
                "stage_admission",
                json!(b("another-admission.json")),
            ),
            ("launch", "producer_limits", json!({"memory_max_bytes":0})),
            ("admission", "stage", json!("full")),
            ("admission", "source", json!({})),
            ("admission", "stage_spec", json!(b("another-stage.json"))),
            ("admission", "runner", json!({"sha256":"f".repeat(64)})),
            ("admission", "recorded_unix_seconds", json!(3)),
            ("stage_spec", "stage", json!("full")),
        ] {
            let mut changed = i.clone();
            match member {
                "launch" => changed.launch[key] = value,
                "admission" => changed.admission[key] = value,
                _ => changed.stage_spec[key] = value,
            }
            assert!(
                facts(&t, &o, &changed, &result, &raw, (b"", b"")).is_err(),
                "{member} {key}"
            );
        }
        let (t, o, i, result, raw) = fixture(Stage::Assembly);
        assert!(facts(&t, &o, &i, &result, &raw, (b"", b"")).is_err());
    }
}
