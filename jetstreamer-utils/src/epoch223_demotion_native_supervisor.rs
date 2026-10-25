//! Exact new-harness supervisor. No production worker or entry replay is run.
//! Native issuer/guard roles still require their own source/runtime qualification.
use super::*;
const TEST: &str =
    "runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    harness: BoundFile,
    snapshot: BoundFile,
    genesis: BoundFile,
    origin_clock: BoundFile,
    admission_policy: BoundFile,
    source_qa: BoundFile,
    run_root: PathBuf,
    bootstrap_slot: u64,
    local_floor_bytes: u64,
    issuer_executable: BoundFile,
    issuer_qualification: BoundFile,
    guard_executable: BoundFile,
    guard_qualification: BoundFile,
    accounting_executable: BoundFile,
    accounting_qualification: BoundFile,
    maximum_wait_millis: u64,
    maximum_execution_millis: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    schema: String,
    phase: String,
    runtime_plan: BoundFile,
    status_task: BoundFile,
    runner: Actor,
    issuer: Actor,
    issuer_spec: BoundFile,
    guard: BoundFile,
    request: Option<BoundFile>,
    control_grant: Option<BoundFile>,
    capacity_result: BoundFile,
    allocation_proof: Option<BoundFile>,
    recorded_unix_millis: u64,
    original_start_unix_millis: u64,
    native_execution_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
pub(super) fn caps(unit: &str, high: u64, max: u64) -> Result<()> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    for (name, value) in [
        ("memory.high", high),
        ("memory.max", max),
        ("memory.swap.max", 0),
    ] {
        ensure!(
            fs::read_to_string(root.join(name))?.trim().parse::<u64>()? == value,
            "223 native supervisor kernel cap differs:{name}"
        );
    }
    Ok(())
}
struct Wait<'a> {
    plan: &'a Plan,
    binding: &'a BoundFile,
    actor: &'a Actor,
    origin: &'a OriginClock,
    phase: &'a str,
    request: Option<&'a BoundFile>,
    control: Option<&'a BoundFile>,
}
fn permission(w: Wait<'_>) -> Result<(BoundFile, Grant, GuardProof)> {
    let path = w
        .plan
        .run_root
        .join(format!("native-{}-grant.json", w.phase));
    let started = Instant::now();
    loop {
        ensure!(
            elapsed(started)? < w.plan.maximum_wait_millis,
            "223 native one-shot permission deadline"
        );
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        let bytes = read_owned(&path, 0)?;
        let binding = BoundFile {
            path: path.clone(),
            sha256: hex(&Sha256::digest(&bytes)),
        };
        let grant: Grant = serde_json::from_slice(&bytes)?;
        let spawn = w.phase == "spawn";
        let issue: IssueSpec = read_bound(&grant.issuer_spec)?;
        ensure!(
            issue.schema == "jetstreamer-epoch223-demotion-native-issue-spec-v1"
                && issue.status_task == grant.status_task
                && issue.phase == w.phase
                && issue.issuer_unit == grant.issuer.unit
                && issue.runtime_plan == *w.binding
                && issue.runner == *w.actor
                && issue.guard == grant.guard
                && issue.request.as_ref() == w.request
                && issue.control_grant.as_ref() == w.control
                && grant.issuer.expected_exec_start
                    == exact_helper_command(
                        &grant.issuer,
                        "issue-epoch223-demotion-native",
                        &grant.issuer_spec,
                        "--spec-sha256"
                    ),
            "223 native issuer command/spec differs"
        );
        ensure!(
            grant.schema == "jetstreamer-epoch223-demotion-native-grant-v1"
                && grant.phase == w.phase
                && grant.runtime_plan == *w.binding
                && grant.runner == *w.actor
                && grant.original_start_unix_millis == w.origin.original_start_unix_millis
                && grant.request.as_ref() == w.request
                && grant.control_grant.as_ref() == w.control
                && grant.native_execution_authorized == spawn
                && !grant.publication_authorized
                && !grant.r2_mutations
                && fresh(grant.recorded_unix_millis, millis()?)
                && grant.issuer.executable == w.plan.issuer_executable
                && grant.issuer.pid != w.actor.pid,
            "223 native permission is foreign/stale/repeated"
        );
        if let Some(request) = w.request {
            let value: Value = read_bound(request)?;
            ensure!(
                value["recorded_unix_millis"]
                    .as_u64()
                    .is_some_and(|n| n <= grant.recorded_unix_millis),
                "223 native spawn grant predates actual hash-complete request"
            );
        }
        issuance::validate_status_task(
            &grant.status_task,
            w.actor,
            w.binding,
            &w.plan.origin_clock,
            &grant.guard,
            &w.plan.accounting_executable,
            &w.plan.accounting_qualification,
        )?;
        let issuer_qualification: Value = read_bound(&w.plan.issuer_qualification)?;
        ensure!(
            issuer_qualification["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
                && issuer_qualification["executable_sha256"] == w.plan.issuer_executable.sha256
                && issuer_qualification[if spawn {
                    "native_spawn_issuer_qualified"
                } else {
                    "native_control_issuer_qualified"
                }] == true,
            "223 native issuer role has not been independently qualified"
        );
        let guard: GuardProof = read_bound(&grant.guard)?;
        let guard_qualification: Value = read_bound(&w.plan.guard_qualification)?;
        ensure!(
            guard.actor.executable == w.plan.guard_executable
                && guard.watched_runner == *w.actor
                && guard.run_root == w.plan.run_root
                && guard.admission_policy == w.plan.admission_policy
                && guard.target_slot == 96_335_538
                && guard.protective_guard_proven
                && guard.producer_stop_enabled
                && !guard.publication_authorized
                && !guard.r2_mutations
                && guard.actor.pid != w.actor.pid
                && guard.actor.pid != grant.issuer.pid
                && guard_qualification["schema"]
                    == "jetstreamer-epoch223-demotion-role-qualification-v1"
                && guard_qualification["executable_sha256"] == w.plan.guard_executable.sha256
                && guard_qualification["native_input_guard_qualified"] == true,
            "223 native input needs a real independently qualified native guard"
        );
        let guard_plan: Value = read_bound(&guard.guard_plan)?;
        ensure!(
            guard_plan["runtime_plan"] == binding_value(w.binding),
            "223 native guard watches another plan"
        );
        let result: Value = read_bound(&grant.capacity_result)?;
        let qualification: Value = read_bound(&w.plan.accounting_qualification)?;
        let budget = if spawn { 130u64 << 30 } else { 18u64 << 30 };
        ensure!(
            qualification["complete_memory_accounting_qualified"] == true
                && qualification["executable_sha256"] == w.plan.accounting_executable.sha256
                && result["schema"] == "jetstreamer-epoch223-demotion-capacity-result-v1"
                && result["self_sha256"] == w.plan.accounting_executable.sha256
                && result["upstream_accounting_source_commit"]
                    == "af09802051463086cf8f47de3bf200717d84e094"
                && result["context"]["phase"] == w.phase
                && result["context"]["job_kind"] == "native-input"
                && result["context"]["runtime_plan"] == binding_value(w.binding)
                && result["context"]["local_floor_bytes"] == w.plan.local_floor_bytes
                && result["context"]["producer"] == serde_json::to_value(w.actor)?
                && result["context"]["issuer"] == serde_json::to_value(&grant.issuer)?
                && result["context"]["guard"] == serde_json::to_value(&guard.actor)?
                && result["capacity"]["candidate_accounting_final"]["candidate_memory_max_bytes"]
                    == budget
                && result["capacity"]["century_floor_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= w.plan.local_floor_bytes)
                && result["capacity"]["all_live_growth_and_century_floor_protected"] == true,
            "223 native allocation lacks corrected complete-accounting context"
        );
        ensure!(
            grant.allocation_proof.is_some() == spawn,
            "223 native control/spawn allocation proof mismatch"
        );
        if let Some(binding) = &grant.allocation_proof {
            let allocation: Value = read_bound(binding)?;
            ensure!(
                allocation["schema"] == "jetstreamer-epoch223-demotion-native-allocation-proof-v1"
                    && allocation["runner"] == serde_json::to_value(w.actor)?
                    && allocation["issuer"] == serde_json::to_value(&grant.issuer)?
                    && allocation["request"] == serde_json::to_value(&grant.request)?
                    && allocation["control_grant"] == serde_json::to_value(&grant.control_grant)?
                    && allocation["capacity_result"] == binding_value(&grant.capacity_result)
                    && allocation["effective_memory_high_bytes"] == (112u64 << 30)
                    && allocation["effective_memory_max_bytes"] == (128u64 << 30)
                    && allocation["manager_configuration_not_changed_by_this_issuer"] == true,
                "223 native immutable allocation does not bind actual kernel envelope"
            );
        }
        observe(w.actor)?;
        observe(&grant.issuer)?;
        observe(&guard.actor)?;
        if spawn {
            caps(&w.plan.unit, 112u64 << 30, 128u64 << 30)?;
        } else {
            caps(&w.plan.unit, 14u64 << 30, 16u64 << 30)?;
        }
        ensure!(
            fresh(grant.recorded_unix_millis, millis()?)
                && elapsed(started)? < w.plan.maximum_wait_millis,
            "223 native grant expired before acceptance"
        );
        return Ok((binding, grant, guard));
    }
}
pub(super) fn run(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let plan: Plan = read_bound(binding)?;
    ensure!(
        plan.schema == "jetstreamer-epoch223-demotion-native-supervisor-plan-v1"
            && plan.harness.sha256 == HARNESS
            && plan.snapshot.sha256 == SNAPSHOT
            && plan.genesis.sha256 == GENESIS
            && plan.bootstrap_slot == 96_335_538
            && plan.local_floor_bytes > 0
            && plan.maximum_wait_millis > 0
            && plan.maximum_wait_millis <= 120_000
            && plan.maximum_execution_millis > 0
            && plan.maximum_execution_millis <= 129_600_000,
        "223 native supervisor closed plan differs"
    );
    ensure!(
        plan.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && plan.run_root.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("native-input223-v1620-demotion-"))
            && plan.snapshot.path
                == Path::new("/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1")
                    .join(SNAPSHOT_NAME)
            && plan.genesis.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/genesis.bin"
                )
            && plan.source_qa.sha256
                == "3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f",
        "223 native actual input paths/source QA differ"
    );
    let actor = roles::own_role(
        &plan.unit,
        "supervise-epoch223-demotion-native",
        binding,
        executable,
    )?;
    let root = fs::symlink_metadata(&plan.run_root)?;
    let scratch = plan.run_root.join("scratch");
    let metadata = fs::symlink_metadata(&scratch)?;
    ensure!(
        plan.run_root.canonicalize()? == plan.run_root
            && root.uid() == 1000
            && root.mode() & 0o077 == 0
            && scratch.canonicalize()? == scratch
            && metadata.is_dir()
            && metadata.uid() == 1000
            && metadata.mode() & 0o777 == 0o700
            && fs::read_dir(&scratch)?.next().is_none(),
        "223 native scratch must be original empty uid1000 mode0700"
    );
    let origin: OriginClock = read_bound(&plan.origin_clock)?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    issuance::published(
        &plan.run_root.join("native-start.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-start-v1","runtime_plan":binding,"actor":actor,
        "origin_clock":plan.origin_clock,"original_start_unix_millis":origin.original_start_unix_millis,
        "native_inputs_hashed":false,"native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let (control, control_grant, guard) = permission(Wait {
        plan: &plan,
        binding,
        actor: &actor,
        origin: &origin,
        phase: "control",
        request: None,
        control: None,
    })?;
    issuance::published(
        &plan.run_root.join("native-control-accepted.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-control-accepted-v1","runner":actor,"grant":control,
        "original_start_unix_millis":origin.original_start_unix_millis,"native_execution_authorized":false}),
    )?;
    // No control permission renewal while hashing. The later spawn grant is new.
    bound_file(&plan.harness.path, HARNESS, 256 << 20)?;
    bound_file(&plan.snapshot.path, SNAPSHOT, SNAPSHOT_SIZE)?;
    bound_file(&plan.genesis.path, GENESIS, 64 << 20)?;
    verify_reference(&plan.source_qa)?;
    observe(&actor)?;
    observe(&guard.actor)?;
    let request = issuance::published(
        &plan.run_root.join("native-spawn-request.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-spawn-request-v1","runtime_plan":binding,"runner":actor,
        "control_grant":control,"recorded_unix_millis":millis()?,"original_start_unix_millis":origin.original_start_unix_millis,
        "native_inputs_hashed":true,"worker_spawned":false,"native_execution_authorized":false}),
    )?;
    let (spawn, spawn_grant, spawn_guard) = permission(Wait {
        plan: &plan,
        binding,
        actor: &actor,
        origin: &origin,
        phase: "spawn",
        request: Some(&request),
        control: Some(&control),
    })?;
    ensure!(
        spawn_guard.actor == guard.actor
            && spawn_guard.guard_plan == guard.guard_plan
            && spawn_grant.status_task == control_grant.status_task,
        "223 native original guard was replaced during hashing"
    );
    issuance::published(
        &plan.run_root.join("native-spawn-accepted.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-spawn-accepted-v1","runner":actor,"grant":spawn,
        "request":request,"original_start_unix_millis":origin.original_start_unix_millis,"native_execution_authorized":true}),
    )?;
    let current_root = fs::symlink_metadata(&plan.run_root)?;
    let current_scratch = fs::symlink_metadata(&scratch)?;
    ensure!(
        current_root.dev() == root.dev()
            && current_root.ino() == root.ino()
            && current_scratch.dev() == metadata.dev()
            && current_scratch.ino() == metadata.ino()
            && current_scratch.uid() == 1000
            && current_scratch.mode() & 0o777 == 0o700
            && fs::read_dir(&scratch)?.next().is_none(),
        "223 native original empty scratch changed during hashing"
    );
    let stdout_path = plan.run_root.join("native-stdout.txt");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&stdout_path)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(plan.run_root.join("native-stderr.txt"))?;
    let args = [
        TEST,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ];
    observe(&actor)?;
    observe(&spawn_guard.actor)?;
    caps(&plan.unit, 112u64 << 30, 128u64 << 30)?;
    ensure!(
        fresh(spawn_grant.recorded_unix_millis, millis()?),
        "223 native spawn grant expired before actual child start"
    );
    let child = Command::new(&plan.harness.path)
        .args(args)
        .env_clear()
        .env("JETSTREAMER_EPOCH223_V1620_TEST_SCRATCH", &scratch)
        .uid(1000)
        .gid(1000)
        .process_group(0)
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let mut child = ChildGroup(child, false);
    let pid = child.0.id();
    let ticks = start_ticks(pid)?;
    ensure!(
        fs::read_link(format!("/proc/{pid}/exe"))? == plan.harness.path
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::{}", actor.cgroup),
        "223 native actual child identity differs"
    );
    let child_status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    for key in ["Uid:", "Gid:"] {
        let ids = child_status
            .lines()
            .find(|line| line.starts_with(key))
            .context("223 native child credentials")?;
        ensure!(
            ids.split_whitespace()
                .skip(1)
                .eq(["1000", "1000", "1000", "1000"]),
            "223 native harness is not fully unprivileged"
        );
    }
    for key in ["CapEff:", "CapAmb:"] {
        ensure!(
            child_status
                .lines()
                .find(|line| line.starts_with(key))
                .and_then(|line| line.split_whitespace().nth(1))
                == Some("0000000000000000"),
            "223 native harness inherited effective or ambient capabilities"
        );
    }
    let expected_argv: Vec<String> = std::iter::once(plan.harness.path.display().to_string())
        .chain(args.into_iter().map(String::from))
        .collect();
    let command = fs::read(format!("/proc/{pid}/cmdline"))?;
    ensure!(
        command.len() <= 65536 && command.last() == Some(&0),
        "223 native actual argv bounds"
    );
    let argv = command[..command.len() - 1]
        .split(|byte| *byte == 0)
        .map(|word| Ok(std::str::from_utf8(word)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        argv == expected_argv
            && start_ticks(pid)? == ticks
            && fs::read_link(format!("/proc/{pid}/exe"))? == plan.harness.path,
        "223 native actual argv/start/ELF changed before launch capture"
    );
    let launch = issuance::published(
        &plan.run_root.join("native-launch.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-launch-v1","status_task":control_grant.status_task,"supervisor":actor,"harness":plan.harness,
        "harness_pid":pid,"harness_start_ticks":ticks,"harness_argv":argv,"snapshot":plan.snapshot,"genesis":plan.genesis,
        "origin_clock":plan.origin_clock,"original_start_unix_millis":origin.original_start_unix_millis,
        "source_commit":"551728fda72afd36ce6f8652ddb0020ec249e860","worker_sha256":WORKER,
        "source_qa_sha256":plan.source_qa.sha256,"scratch_root":scratch,"actual_child_identity_captured":true,
        "native_input_only":true,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let started = Instant::now();
    let mut next_guard = Instant::now();
    let status = loop {
        ensure!(
            elapsed(started)? < plan.maximum_execution_millis,
            "223 native execution bound"
        );
        if Instant::now() >= next_guard {
            observe(&actor)?;
            observe(&guard.actor)?;
            caps(&plan.unit, 112u64 << 30, 128u64 << 30)?;
            ensure!(
                free_bytes(&plan.run_root)? >= plan.local_floor_bytes,
                "223 native local floor"
            );
            next_guard = Instant::now() + Duration::from_secs(15);
        }
        if let Some(status) = child.0.try_wait()? {
            child.1 = true;
            break status;
        }
        thread::sleep(Duration::from_millis(200));
    };
    stdout.sync_all()?;
    stderr.sync_all()?;
    stdout.set_permissions(fs::Permissions::from_mode(0o400))?;
    stderr.set_permissions(fs::Permissions::from_mode(0o400))?;
    let bytes = read_owned_max(&stdout_path, 0, 64 << 20)?;
    let stdout_binding = BoundFile {
        path: stdout_path,
        sha256: hex(&Sha256::digest(&bytes)),
    };
    issuance::published(
        &plan.run_root.join("native-result.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-native-result-v1","launch":launch,"harness_stdout":stdout_binding,
        "harness_sha256":HARNESS,"harness_pid":pid,"harness_start_ticks":ticks,"harness_exit_code":status.code().unwrap_or(-1),
        "harness_reaped":true,"success":status.success(),"publication_authorized":false,"r2_mutations":false}),
    )?;
    ensure!(status.success(), "223 new native harness failed");
    Ok(())
}

pub(super) struct GuardContext {
    pub(super) unit: String,
    pub(super) run_root: PathBuf,
    pub(super) local_floor_bytes: u64,
    pub(super) executable: BoundFile,
    pub(super) admission_policy: BoundFile,
}
pub(super) fn guard_context(binding: &BoundFile) -> Result<GuardContext> {
    let plan: Plan = read_bound(binding)?;
    ensure!(
        plan.schema == "jetstreamer-epoch223-demotion-native-supervisor-plan-v1"
            && plan.harness.sha256 == HARNESS
            && plan.bootstrap_slot == 96_335_538,
        "223 native guard plan purpose differs"
    );
    Ok(GuardContext {
        unit: plan.unit,
        run_root: plan.run_root,
        local_floor_bytes: plan.local_floor_bytes,
        executable: plan.guard_executable,
        admission_policy: plan.admission_policy,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueSpec {
    schema: String,
    phase: String,
    issuer_unit: String,
    runtime_plan: BoundFile,
    status_task: BoundFile,
    runner: Actor,
    guard: BoundFile,
    request: Option<BoundFile>,
    control_grant: Option<BoundFile>,
    accounting_basis: BoundFile,
    accounting_directory: PathBuf,
    maximum_lock_wait_millis: u64,
    maximum_acknowledgment_wait_millis: u64,
}
pub(super) fn issue(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let spec: IssueSpec = read_bound(binding)?;
    ensure!(
        spec.schema == "jetstreamer-epoch223-demotion-native-issue-spec-v1"
            && matches!(spec.phase.as_str(), "control" | "spawn")
            && spec.maximum_acknowledgment_wait_millis > 0
            && spec.maximum_acknowledgment_wait_millis <= 120_000,
        "223 native issuer closed stage/wait differs"
    );
    let spawn = spec.phase == "spawn";
    let plan: Plan = read_bound(&spec.runtime_plan)?;
    let context = guard_context(&spec.runtime_plan)?;
    ensure!(
        plan.issuer_executable == *executable
            && plan.unit == spec.runner.unit
            && spec.runner.expected_exec_start
                == exact_helper_command(
                    &spec.runner,
                    "supervise-epoch223-demotion-native",
                    &spec.runtime_plan,
                    "--spec-sha256"
                )
            && spec.request.is_some() == spawn
            && spec.control_grant.is_some() == spawn,
        "223 native issuer exact plan/runner/stage differs"
    );
    let issuer = roles::own_role(
        &spec.issuer_unit,
        "issue-epoch223-demotion-native",
        binding,
        executable,
    )?;
    let origin: OriginClock = read_bound(&plan.origin_clock)?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    let guard: GuardProof = read_bound(&spec.guard)?;
    let guard_plan: GuardPlan = read_bound(&guard.guard_plan)?;
    ensure!(
        guard.actor.executable == context.executable
            && guard.watched_runner == spec.runner
            && guard.run_root == context.run_root
            && guard.target_slot == 96_335_538
            && guard.admission_policy == context.admission_policy
            && guard.protective_guard_proven
            && guard.producer_stop_enabled
            && guard_plan.runtime_plan == spec.runtime_plan
            && guard_plan.guard_unit == guard.actor.unit
            && guard_plan.ready_output == spec.guard.path
            && guard_plan.protected_floor_bytes == plan.local_floor_bytes
            && guard.actor.expected_exec_start
                == exact_helper_command(
                    &guard.actor,
                    "guard-epoch223-demotion",
                    &guard.guard_plan,
                    "--plan-sha256"
                )
            && guard.actor.pid != issuer.pid
            && guard.actor.pid != spec.runner.pid
            && issuer.pid != spec.runner.pid,
        "223 native issuer lacks original exact independently armed guard"
    );
    issuance::validate_status_task(
        &spec.status_task,
        &spec.runner,
        &spec.runtime_plan,
        &plan.origin_clock,
        &spec.guard,
        &plan.accounting_executable,
        &plan.accounting_qualification,
    )?;
    let basis: issuance::Basis = read_bound(&spec.accounting_basis)?;
    ensure!(
        basis.schema == "jetstreamer-epoch223-demotion-accounting-basis-v1"
            && basis.legacy_nonparticipating_admissions_quiescent,
        "223 native basis/nonparticipating custody differs"
    );
    let own_qualification: Value = read_bound(&plan.issuer_qualification)?;
    let guard_qualification: Value = read_bound(&plan.guard_qualification)?;
    ensure!(
        own_qualification["schema"] == "jetstreamer-epoch223-demotion-role-qualification-v1"
            && own_qualification["executable_sha256"] == executable.sha256
            && own_qualification[if spawn {
                "native_spawn_issuer_qualified"
            } else {
                "native_control_issuer_qualified"
            }] == true
            && guard_qualification["schema"]
                == "jetstreamer-epoch223-demotion-role-qualification-v1"
            && guard_qualification["executable_sha256"] == guard.actor.executable.sha256
            && guard_qualification["native_input_guard_qualified"] == true,
        "223 native issuing/guard routes have not been independently qualified"
    );
    let qualification: Value = read_bound(&plan.accounting_qualification)?;
    ensure!(
        qualification["complete_memory_accounting_qualified"] == true
            && qualification["executable_sha256"] == plan.accounting_executable.sha256
            && qualification["upstream_accounting_source_commit"]
                == "af09802051463086cf8f47de3bf200717d84e094",
        "223 native corrected accounting unqualified"
    );
    bound_file(
        &plan.accounting_executable.path,
        &plan.accounting_executable.sha256,
        512 << 20,
    )?;
    let requested = if spawn {
        let control: Grant = read_bound(
            spec.control_grant
                .as_ref()
                .context("223 native original control")?,
        )?;
        ensure!(
            control.phase == "control"
                && control.status_task == spec.status_task
                && control.runtime_plan == spec.runtime_plan
                && control.runner == spec.runner
                && control.guard == spec.guard
                && !control.native_execution_authorized
                && control.original_start_unix_millis == origin.original_start_unix_millis,
            "223 native control changed"
        );
        let accepted: Value = read_bound(&BoundFile {
            path: plan.run_root.join("native-control-accepted.json"),
            sha256: hex(&Sha256::digest(&read_owned(
                &plan.run_root.join("native-control-accepted.json"),
                0,
            )?)),
        })?;
        ensure!(
            accepted["runner"] == serde_json::to_value(&spec.runner)?
                && accepted["grant"]
                    == binding_value(
                        spec.control_grant
                            .as_ref()
                            .context("223 native control binding")?
                    ),
            "223 native control not consumed"
        );
        let request: Value = read_bound(
            spec.request
                .as_ref()
                .context("223 native hash-complete request")?,
        )?;
        ensure!(
            spec.request.as_ref().context("223 native request")?.path
                == plan.run_root.join("native-spawn-request.json")
                && request["schema"] == "jetstreamer-epoch223-demotion-native-spawn-request-v1"
                && request["runtime_plan"] == binding_value(&spec.runtime_plan)
                && request["runner"] == serde_json::to_value(&spec.runner)?
                && request["control_grant"]
                    == binding_value(spec.control_grant.as_ref().context("223 native control")?)
                && request["original_start_unix_millis"] == origin.original_start_unix_millis
                && request["native_inputs_hashed"] == true
                && request["worker_spawned"] == false,
            "223 native actual post-hash request differs"
        );
        request["recorded_unix_millis"]
            .as_u64()
            .context("223 native request timestamp")?
    } else {
        millis()?
    };
    ensure!(
        fresh(requested, millis()?),
        "223 native request stale before admission"
    );
    let lock = custody::Custody::acquire(spec.maximum_lock_wait_millis)?;
    observe(&spec.runner)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    caps(&plan.unit, 14u64 << 30, 16u64 << 30)?;
    let capacity = issuance::calculate(issuance::Calculation {
        phase: &spec.phase,
        run_root: &plan.run_root,
        local_floor_bytes: plan.local_floor_bytes,
        job_kind: "native-input",
        plan: &spec.runtime_plan,
        producer: &spec.runner,
        guard: &guard.actor,
        issuer: &issuer,
        basis: &basis,
        accounting_executable: &plan.accounting_executable,
        directory: &spec.accounting_directory,
    })?;
    let result: Value = read_bound(&capacity)?;
    ensure!(
        fresh(requested, millis()?)
            && free_bytes(&plan.run_root)?
                >= result["capacity"]["required_initial_free_bytes"]
                    .as_u64()
                    .context("223 native full disk fit")?,
        "223 native request/disk changed before commit"
    );
    let (high, max) = if spawn {
        (112u64 << 30, 128u64 << 30)
    } else {
        (14u64 << 30, 16u64 << 30)
    };
    if spawn {
        lock.validate()?;
        observe(&spec.runner)?;
        observe(&guard.actor)?;
        caps(&plan.unit, 14u64 << 30, 16u64 << 30)?;
        let target = protective::Custody::open(&spec.runner)?;
        target
            .file("memory.max", true)?
            .write_all(format!("{max}\n").as_bytes())?;
        target
            .file("memory.high", true)?
            .write_all(format!("{high}\n").as_bytes())?;
    }
    issuance::published(
        &plan
            .run_root
            .join(format!("native-{}-custody.json", spec.phase)),
        &lock.evidence()?,
    )?;
    caps(&plan.unit, high, max)?;
    let allocation = if spawn {
        Some(issuance::published(
            &plan.run_root.join("native-spawn-allocation.json"),
            &json!({
        "schema":"jetstreamer-epoch223-demotion-native-allocation-proof-v1","runner":spec.runner,"issuer":issuer,
        "request":spec.request,"status_task":spec.status_task,"control_grant":spec.control_grant,"capacity_result":capacity,
        "effective_memory_high_bytes":high,"effective_memory_max_bytes":max,"effective_memory_swap_max_bytes":0,
        "manager_configuration_not_changed_by_this_issuer":true,"recorded_unix_millis":millis()?,
        "native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        )?)
    } else {
        None
    };
    let value = json!({"schema":"jetstreamer-epoch223-demotion-native-grant-v1","phase":spec.phase,
        "runtime_plan":spec.runtime_plan,"status_task":spec.status_task,"runner":spec.runner,"issuer":issuer,"issuer_spec":binding,
        "guard":spec.guard,"request":spec.request,"control_grant":spec.control_grant,"capacity_result":capacity,"allocation_proof":allocation,
        "recorded_unix_millis":millis()?,"original_start_unix_millis":origin.original_start_unix_millis,
        "native_execution_authorized":spawn,"publication_authorized":false,"r2_mutations":false});
    // The native grant file itself is the final ready marker. Nothing can
    // authorize native work until this no-clobber publication appears.
    let marker = issuance::commit_marker(
        || {
            observe(&spec.runner)?;
            observe(&issuer)?;
            observe(&guard.actor)?;
            caps(&plan.unit, high, max)?;
            lock.validate()?;
            ensure!(
                fresh(requested, millis()?),
                "223 native request expired at final commit"
            );
            Ok(())
        },
        || {
            issuance::published(
                &plan
                    .run_root
                    .join(format!("native-{}-grant.json", spec.phase)),
                &value,
            )
        },
    )?;
    drop(lock); // never hold admission custody during long read-only hashing
    let outcome = (|| -> Result<()> {
        let started = Instant::now();
        let path = plan
            .run_root
            .join(format!("native-{}-accepted.json", spec.phase));
        loop {
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    let accepted: Value = serde_json::from_slice(&read_owned(&path, 0)?)?;
                    ensure!(
                        accepted["runner"] == serde_json::to_value(&spec.runner)?
                            && accepted["grant"] == binding_value(&marker),
                        "223 native actual acknowledgment differs"
                    );
                    return Ok(());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            ensure!(
                elapsed(started)? < spec.maximum_acknowledgment_wait_millis,
                "223 native acknowledgment timeout"
            );
            thread::sleep(Duration::from_millis(100));
        }
    })();
    issuance::preserve_after_marker(
        &plan.run_root,
        &format!("native-{}", spec.phase),
        &marker,
        &marker,
        &spec.runner,
        &guard.actor,
        outcome,
    )
}
