//! Root-only metadata captures. These commands never execute native inputs.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginSpec {
    schema: String,
    issuer_unit: String,
    manager_journal: BoundFile,
    failed_origin: BoundFile,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskSpec {
    schema: String,
    issuer_unit: String,
    runtime_plan: BoundFile,
    runner: Actor,
    origin_clock: BoundFile,
    admission_policy: BoundFile,
    eta_policy: BoundFile,
    launch_output: PathBuf,
    task_output: PathBuf,
}

pub(super) fn dispatch() -> Option<Result<()>> {
    let args: Vec<String> = env::args().collect();
    let role = args.get(1)?.as_str();
    if !matches!(role, "capture-epoch223-origin" | "capture-epoch223-task") {
        return None;
    }
    Some(run(&args))
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 7 && args[3] == "--spec-sha256" && args[5] == "--self-sha256",
        "223 capture requires exact hash-bound arguments"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "223 capture requires root");
    let binding = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let executable = BoundFile {
        path: fs::read_link("/proc/self/exe")?,
        sha256: args[6].clone(),
    };
    bound_file(&executable.path, &executable.sha256, 256 << 20)?;
    match args[1].as_str() {
        "capture-epoch223-origin" => {
            let spec: OriginSpec = read_bound(&binding)?;
            ensure!(
                spec.schema == "jetstreamer-epoch223-origin-capture-spec-v1",
                "223 origin capture schema"
            );
            let issuer = own_role(&spec.issuer_unit, &args[1], &binding, &executable)?;
            let journal = bound_bytes(&spec.manager_journal, 0, 16 << 20)?;
            let origin = OriginClock {
                schema: "jetstreamer-epoch223-e70a-origin-clock-v1".into(),
                unit: OLD_UNIT.into(),
                invocation_id: OLD_IID.into(),
                original_start_unix_millis: origin_start(&journal)?,
                terminal_journal_sha256: spec.manager_journal.sha256.clone(),
                manager_journal: spec.manager_journal,
                failed_origin: spec.failed_origin,
                repair_closed: false,
            };
            validate_origin(&origin, millis()?)?;
            verify_reference(&origin.failed_origin)?;
            observe(&issuer)?;
            // The origin schema is deliberately exact; capture provenance is a separate receipt.
            let value = json!({"schema":origin.schema,"unit":origin.unit,"invocation_id":origin.invocation_id,
                "original_start_unix_millis":origin.original_start_unix_millis,
                "manager_journal":origin.manager_journal,"failed_origin":origin.failed_origin,
                "terminal_journal_sha256":origin.terminal_journal_sha256,"repair_closed":false});
            persist(&spec.output, &value)?;
        }
        "capture-epoch223-task" => {
            let spec: TaskSpec = read_bound(&binding)?;
            ensure!(
                spec.schema == "jetstreamer-epoch223-task-capture-spec-v1",
                "223 task capture schema"
            );
            let issuer = own_role(&spec.issuer_unit, &args[1], &binding, &executable)?;
            let plan: RuntimePlan = read_bound(&spec.runtime_plan)?;
            ensure!(
                plan.schema == "jetstreamer-epoch223-demotion-runtime-plan-v3"
                    && plan.mode == "bracket"
                    && plan.plan.unit == spec.runner.unit
                    && spec
                        .runner
                        .unit
                        .starts_with("horizon-qualify-223-demotion-bracket-"),
                "223 task plan scope"
            );
            let x = plan.prerequisites.context("223 task prerequisites")?;
            ensure!(
                x.origin_clock == spec.origin_clock && x.admission_policy == spec.admission_policy,
                "223 task plan bindings differ"
            );
            let origin: OriginClock = read_bound(&spec.origin_clock)?;
            validate_origin(&origin, millis()?)?;
            validate_origin_journal(&origin)?;
            verify_reference(&spec.admission_policy)?;
            verify_reference(&spec.eta_policy)?;
            observe(&spec.runner)?;
            ensure!(
                fs::read_link(format!("/proc/{}/exe", spec.runner.pid))?
                    == spec.runner.executable.path,
                "223 task actual runner ELF differs"
            );
            check_control_kernel(&plan.plan)?;
            observe(&issuer)?;
            persist(
                &spec.launch_output,
                &json!({"schema":"jetstreamer-epoch223-demotion-actor-launch-v1",
                "runtime_plan":spec.runtime_plan,"actor":spec.runner,"captured_by":issuer,
                "capture_spec":binding,"recorded_unix_millis":millis()?,"actual_manager_and_process_verified":true,
                "native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
            )?;
            let launch_bytes = read_owned(&spec.launch_output, 0)?;
            let launch = BoundFile {
                path: spec.launch_output,
                sha256: hex(&Sha256::digest(&launch_bytes)),
            };
            observe(&spec.runner)?;
            persist(
                &spec.task_output,
                &json!({"schema":"jetstreamer-epoch223-demotion-repair-task-v1",
                "epoch":223,"phase":"admission-rendezvous","actor":spec.runner,
                "origin_clock":spec.origin_clock,"original_start_unix_millis":origin.original_start_unix_millis,
                "admission_policy":spec.admission_policy,"actor_launch":launch,"eta_policy":spec.eta_policy,
                "publication_authorized":false,"r2_mutations":false}),
            )?;
        }
        _ => bail!("223 unknown metadata capture role"),
    }
    Ok(())
}
fn own_role(unit: &str, command: &str, spec: &BoundFile, executable: &BoundFile) -> Result<Actor> {
    ensure!(
        unit.starts_with("horizon-admit-223-demotion-")
            && unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "223 capture unit scope"
    );
    let row = properties(unit)?;
    let actor = Actor {
        unit: unit.into(),
        invocation_id: env::var("INVOCATION_ID")?,
        pid: std::process::id(),
        start_ticks: start_ticks(std::process::id())?,
        cgroup: format!("/system.slice/{unit}"),
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        executable: executable.clone(),
        expected_exec_start: String::new(),
    };
    let actor = Actor {
        expected_exec_start: exact_helper_command(&actor, command, spec, "--spec-sha256"),
        ..actor
    };
    observe(&actor)?;
    ensure!(properties(unit)? == row, "223 capture manager changed");
    Ok(actor)
}
