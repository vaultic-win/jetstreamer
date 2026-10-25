//! Exact control issuance over a new complete-accounting calculation.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Basis {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    protected_guards: BTreeMap<String, BoundFile>,
    driver_qualification: BoundFile,
    guard_qualification: BoundFile,
    legacy_nonparticipating_admissions_quiescent: bool,
}
pub(super) fn validate_control_capacity(grant: &ControlGrant, x: &Prerequisites) -> Result<()> {
    let result: Value = read_bound(&grant.context_qualification)?;
    let qualification: Value = read_bound(&x.accounting_qualification)?;
    ensure!(
        result["schema"] == "jetstreamer-epoch223-demotion-capacity-result-v1"
            && result["self_sha256"] == x.accounting_executable.sha256
            && result["upstream_accounting_source_commit"]
                == "af09802051463086cf8f47de3bf200717d84e094"
            && qualification["complete_memory_accounting_qualified"] == true
            && qualification["executable_sha256"] == x.accounting_executable.sha256
            && result["context"]["phase"] == "control"
            && result["context"]["job_kind"] == "bracket"
            && result["context"]["runtime_plan"] == binding_value(&grant.runtime_plan)
            && result["context"]["producer"] == serde_json::to_value(&grant.runner)?
            && result["context"]["issuer"] == serde_json::to_value(&grant.issuer)?
            && result["capacity"]["candidate_accounting_final"]["candidate_memory_max_bytes"]
                == (18u64 << 30)
            && result["capacity"]["all_live_growth_and_century_floor_protected"] == true,
        "223 control grant lacks exact newly computed complete accounting"
    );
    let guard: GuardProof = read_bound(&grant.guard)?;
    ensure!(
        result["context"]["guard"] == serde_json::to_value(&guard.actor)?,
        "223 control accounting guard changed"
    );
    let recorded = result["capacity"]["recorded_unix_seconds"]
        .as_u64()
        .and_then(|n| n.checked_mul(1000))
        .context("223 control accounting clock")?;
    ensure!(
        recorded <= grant.recorded_unix_millis && fresh(recorded, millis()?),
        "223 control accounting is stale"
    );
    Ok(())
}
pub(super) fn published(path: &Path, value: &Value) -> Result<BoundFile> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    published_bytes(path, &bytes)
}
fn published_bytes(path: &Path, bytes: &[u8]) -> Result<BoundFile> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "223 root metadata publication requires root"
    );
    let parent = path.parent().context("223 root publication parent")?;
    let before = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && before.is_dir()
            && matches!(before.uid(), 0 | 1000)
            && before.mode() & 0o077 == 0,
        "223 root metadata requires original private parent"
    );
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    let after = fs::symlink_metadata(parent)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.uid() == after.uid()
            && before.mode() == after.mode(),
        "223 publication parent changed"
    );
    temp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("223 immutable publication failed: {e}"))?;
    File::open(parent)?.sync_all()?;
    let bytes = read_owned(path, 0)?;
    Ok(BoundFile {
        path: path.into(),
        sha256: hex(&Sha256::digest(&bytes)),
    })
}
pub(super) fn control(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let spec: IssueSpec = read_bound(binding)?;
    ensure!(
        spec.schema == "jetstreamer-epoch223-demotion-admission-issue-spec-v1"
            && spec.maximum_acknowledgment_wait_millis > 0
            && spec.maximum_acknowledgment_wait_millis <= 120_000,
        "223 control issuer spec/wait differs"
    );
    let issuer = roles::own_role(
        &spec.issuer_unit,
        "issue-epoch223-demotion-control",
        binding,
        executable,
    )?;
    let runtime: RuntimePlan = read_bound(&spec.runtime_plan)?;
    ensure!(
        runtime.schema == "jetstreamer-epoch223-demotion-runtime-plan-v3"
            && runtime.mode == "bracket",
        "223 control runtime scope"
    );
    let p = &runtime.plan;
    validate_plan(p)?;
    let x = runtime
        .prerequisites
        .as_ref()
        .context("223 control prerequisites")?;
    ensure!(
        x.issuer_executable == *executable
            && x.native_input == spec.native_input
            && x.origin_clock == spec.origin_clock
            && x.admission_policy == spec.admission_policy,
        "223 control prerequisites differ"
    );
    let task: RepairTask = read_bound(&spec.repair_task)?;
    let origin: OriginClock = read_bound(&spec.origin_clock)?;
    let guard: GuardProof = read_bound(&spec.guard)?;
    let guard_plan: GuardPlan = read_bound(&guard.guard_plan)?;
    let native: NativeProof = read_bound(&spec.native_input)?;
    native.validate()?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    for b in [
        &native.launch,
        &native.result,
        &native.journal,
        &native.issuer,
        &task.actor_launch,
        &task.eta_policy,
        &spec.admission_policy,
    ] {
        verify_reference(b)?;
    }
    let basis: Basis = read_bound(&spec.accounting_basis)?;
    ensure!(
        basis.schema == "jetstreamer-epoch223-demotion-accounting-basis-v1"
            && basis.observer == spec.accepted_observer
            && basis.fleet == spec.accepted_fleet
            && basis.legacy_nonparticipating_admissions_quiescent,
        "223 control lacks exact complete basis/quiescent nonparticipating issuers"
    );
    let qualification: Value = read_bound(&x.accounting_qualification)?;
    ensure!(
        qualification["upstream_accounting_source_commit"]
            == "af09802051463086cf8f47de3bf200717d84e094"
            && qualification["executable_sha256"] == x.accounting_executable.sha256
            && qualification["complete_memory_accounting_qualified"] == true,
        "223 corrected accounting executable is not qualified"
    );
    bound_file(
        &x.accounting_executable.path,
        &x.accounting_executable.sha256,
        512 << 20,
    )?;
    let lock = custody::Custody::acquire(spec.maximum_lock_wait_millis)?;
    lock.validate()?;
    observe(&task.actor)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    check_control_kernel(p)?;
    let capacity_binding = calculate(Calculation {
        phase: "control",
        p,
        plan: &spec.runtime_plan,
        producer: &task.actor,
        guard: &guard.actor,
        issuer: &issuer,
        basis: &basis,
        x,
        directory: &spec.accounting_directory,
    })?;
    let grant = ControlGrant {
        schema: "jetstreamer-epoch223-demotion-control-grant-v1".into(),
        epoch: 223,
        runtime_plan: spec.runtime_plan.clone(),
        runner: task.actor.clone(),
        issuer: issuer.clone(),
        issuer_spec: binding.clone(),
        parent_sha256: p.node.sha256.clone(),
        worker_sha256: WORKER.into(),
        snapshot_sha256: SNAPSHOT.into(),
        native_input: spec.native_input.clone(),
        origin_clock: spec.origin_clock.clone(),
        admission_policy: spec.admission_policy.clone(),
        accepted_observer: spec.accepted_observer.clone(),
        accepted_fleet: spec.accepted_fleet.clone(),
        context_qualification: capacity_binding,
        repair_task: spec.repair_task.clone(),
        guard: spec.guard.clone(),
        recorded_unix_millis: millis()?,
        protected_floor_bytes: guard_plan.protected_floor_bytes,
        read_only_hashing_authorized: true,
        native_execution_authorized: false,
        full_fleet_census_complete: true,
        overlap_replacement_detected: false,
        publication_authorized: false,
        r2_mutations: false,
    };
    let ready = Ready {
        schema: "jetstreamer-epoch223-demotion-control-ready-v1".into(),
        runtime_plan: spec.runtime_plan.clone(),
        runner: task.actor.clone(),
        admission: BoundFile {
            path: PathBuf::new(),
            sha256: String::new(),
        },
    };
    validate_admission(
        p,
        x,
        &spec.runtime_plan,
        &task.actor,
        &ready,
        &grant,
        &origin,
        &task,
        &guard,
        millis()?,
    )?;
    validate_control_capacity(&grant, x)?;
    validate_issue_and_guard_plan(
        p,
        &spec.runtime_plan,
        &grant,
        &task,
        &guard,
        &spec,
        &guard_plan,
    )?;
    lock.validate()?;
    observe(&task.actor)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    check_control_kernel(p)?;
    let grant_binding = published(
        &p.run_root.join("receipts/control-grant.json"),
        &serde_json::to_value(&grant)?,
    )?;
    published(
        &p.run_root.join("receipts/control-custody.json"),
        &lock.evidence()?,
    )?;
    published(
        &p.run_root.join("receipts/admission-ready.json"),
        &json!({
        "schema":ready.schema,"runtime_plan":ready.runtime_plan,"runner":ready.runner,"admission":grant_binding}),
    )?;
    observe(&task.actor)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    lock.validate()?;
    drop(lock); // never reserve custody across read-only input hashing
    let started = Instant::now();
    loop {
        let path = p.run_root.join("receipts/admission-accepted.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = read_owned(&path, 1000)?;
                let accepted: Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    accepted["runner"] == serde_json::to_value(&task.actor)?
                        && accepted["admission"] == binding_value(&grant_binding)
                        && accepted["read_only_hashing_authorized"] == true
                        && accepted["native_execution_authorized"] == false,
                    "223 control acknowledgment differs"
                );
                observe(&task.actor)?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            started.elapsed() < Duration::from_millis(spec.maximum_acknowledgment_wait_millis),
            "223 control acknowledgment deadline"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

struct Calculation<'a> {
    phase: &'a str,
    p: &'a Plan,
    plan: &'a BoundFile,
    producer: &'a Actor,
    guard: &'a Actor,
    issuer: &'a Actor,
    basis: &'a Basis,
    x: &'a Prerequisites,
    directory: &'a Path,
}
fn calculate(calculation: Calculation<'_>) -> Result<BoundFile> {
    let Calculation {
        phase,
        p,
        plan,
        producer,
        guard,
        issuer,
        basis,
        x,
        directory,
    } = calculation;
    private_directory(directory)?;
    let capacity_path = directory.join(format!("{phase}-capacity.json"));
    let accounting_spec = published(
        &directory.join(format!("{phase}-capacity-spec.json")),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-capacity-spec-v1",
        "context":{"job_kind":"bracket","phase":phase,"runtime_plan":plan,
            "producer":producer,"guard":guard,"issuer":issuer,
            "driver_qualification":basis.driver_qualification,"guard_qualification":basis.guard_qualification},
        "resource_basis":{"observer":basis.observer,"fleet":basis.fleet,"protected_guards":basis.protected_guards},
        "output":capacity_path}),
    )?;
    let mut child = Command::new(&x.accounting_executable.path)
        .arg("compute-demotion223-capacity")
        .arg(&accounting_spec.path)
        .args([
            "--spec-sha256",
            &accounting_spec.sha256,
            "--self-sha256",
            &x.accounting_executable.sha256,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(status.success(), "223 complete accounting refused control");
            break;
        }
        if started.elapsed() >= Duration::from_secs(90) {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("223 complete accounting deadline");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let bytes = read_owned(&capacity_path, 0)?;
    let capacity_binding = published_bytes(
        &p.run_root.join(format!("receipts/{phase}-capacity.json")),
        &bytes,
    )?;
    let result: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        result["schema"] == "jetstreamer-epoch223-demotion-capacity-result-v1"
            && result["spec"] == binding_value(&accounting_spec)
            && result["self_sha256"] == x.accounting_executable.sha256
            && result["context"]["producer"] == serde_json::to_value(producer)?
            && result["context"]["guard"] == serde_json::to_value(guard)?
            && result["context"]["issuer"] == serde_json::to_value(issuer)?
            && result["capacity"]["all_live_growth_and_century_floor_protected"] == true,
        "223 control accounting result differs"
    );
    Ok(capacity_binding)
}

pub(super) fn spawn(binding: &BoundFile, executable: &BoundFile) -> Result<()> {
    let spec: super::spawn::Issue = read_bound(binding)?;
    ensure!(
        spec.schema == "jetstreamer-epoch223-demotion-spawn-issue-spec-v1"
            && spec.maximum_acknowledgment_wait_millis > 0
            && spec.maximum_acknowledgment_wait_millis <= 120_000,
        "223 spawn issuer spec/wait differs"
    );
    let issuer = roles::own_role(
        &spec.issuer_unit,
        "issue-epoch223-demotion-spawn",
        binding,
        executable,
    )?;
    let runtime: RuntimePlan = read_bound(&spec.runtime_plan)?;
    ensure!(
        runtime.schema == "jetstreamer-epoch223-demotion-runtime-plan-v3"
            && runtime.mode == "bracket",
        "223 spawn runtime scope"
    );
    let p = &runtime.plan;
    validate_plan(p)?;
    let x = runtime
        .prerequisites
        .as_ref()
        .context("223 spawn prerequisites")?;
    let control: ControlGrant = read_bound(&spec.control_grant)?;
    let guard: GuardProof = read_bound(&spec.guard)?;
    let origin: OriginClock = read_bound(&x.origin_clock)?;
    let native: NativeProof = read_bound(&spec.native_input)?;
    native.validate()?;
    validate_origin(&origin, millis()?)?;
    validate_origin_journal(&origin)?;
    ensure!(
        control.schema == "jetstreamer-epoch223-demotion-control-grant-v1"
            && control.runtime_plan == spec.runtime_plan
            && control.runner == spec.runner
            && control.guard == spec.guard
            && control.origin_clock == x.origin_clock
            && control.native_input == spec.native_input
            && x.native_input == spec.native_input
            && control.admission_policy == x.admission_policy
            && x.issuer_executable == *executable
            && control.read_only_hashing_authorized
            && !control.native_execution_authorized
            && guard.actor.executable == x.guard_executable
            && guard.watched_runner == spec.runner
            && guard.protective_guard_proven
            && guard.producer_stop_enabled
            && issuer.pid != spec.runner.pid
            && issuer.pid != guard.actor.pid,
        "223 spawn is not the original one-shot control/guard/runner"
    );
    let request: Value = serde_json::from_slice(&bound_bytes(&spec.request, 1000, 1 << 20)?)?;
    let requested = request["recorded_unix_millis"]
        .as_u64()
        .context("223 actual post-hash request clock")?;
    ensure!(
        spec.request.path == p.run_root.join("receipts/spawn-request.json")
            && request["schema"] == "jetstreamer-epoch223-demotion-spawn-request-v1"
            && request["runtime_plan"] == binding_value(&spec.runtime_plan)
            && request["control_grant"] == binding_value(&spec.control_grant)
            && request["runner"] == serde_json::to_value(&spec.runner)?
            && request["native_input"] == binding_value(&spec.native_input)
            && request["original_start_unix_millis"] == origin.original_start_unix_millis
            && request["native_inputs_hashed"] == true
            && request["worker_spawned"] == false
            && request["native_execution_authorized"] == false
            && fresh(requested, millis()?),
        "223 spawn lacks a genuine fresh post-hash request"
    );
    let accepted: Value = serde_json::from_slice(&read_owned(
        &p.run_root.join("receipts/admission-accepted.json"),
        1000,
    )?)?;
    ensure!(
        accepted["schema"] == "jetstreamer-epoch223-demotion-rendezvous-accepted-v1"
            && accepted["runner"] == serde_json::to_value(&spec.runner)?
            && accepted["admission"] == binding_value(&spec.control_grant)
            && accepted["read_only_hashing_authorized"] == true
            && accepted["native_execution_authorized"] == false,
        "223 spawn control was not consumed by the original runner"
    );
    let basis: Basis = read_bound(&spec.accounting_basis)?;
    ensure!(
        basis.schema == "jetstreamer-epoch223-demotion-accounting-basis-v1"
            && basis.legacy_nonparticipating_admissions_quiescent,
        "223 spawn lacks complete quiescent basis"
    );
    let qualification: Value = read_bound(&x.accounting_qualification)?;
    ensure!(
        qualification["upstream_accounting_source_commit"]
            == "af09802051463086cf8f47de3bf200717d84e094"
            && qualification["executable_sha256"] == x.accounting_executable.sha256
            && qualification["complete_memory_accounting_qualified"] == true,
        "223 spawn accounting unqualified"
    );
    bound_file(
        &x.accounting_executable.path,
        &x.accounting_executable.sha256,
        512 << 20,
    )?;
    let lock = custody::Custody::acquire(spec.maximum_lock_wait_millis)?;
    observe(&spec.runner)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    check_control_kernel(p)?;
    let capacity = calculate(Calculation {
        phase: "spawn",
        p,
        plan: &spec.runtime_plan,
        producer: &spec.runner,
        guard: &guard.actor,
        issuer: &issuer,
        basis: &basis,
        x,
        directory: &spec.accounting_directory,
    })?;
    ensure!(
        fresh(requested, millis()?),
        "223 request expired during fresh allocation calculation"
    );
    let result: Value = read_bound(&capacity)?;
    let minimum = result["capacity"]["required_initial_free_bytes"]
        .as_u64()
        .context("223 full admission disk envelope")?;
    ensure!(
        free_bytes(&p.run_root)? >= minimum,
        "223 disk fit changed before allocation commit"
    );
    lock.validate()?;
    observe(&spec.runner)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    check_control_kernel(p)?;
    let target = protective::Custody::open(&spec.runner)?;
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "223 allocation page size"
    );
    let (high, max) = (
        150_000_000_000u64 / page * page,
        225_000_000_000u64 / page * page,
    );
    // No native execution has been permitted. Increasing the original cgroup's
    // cap under shared custody records the full reservation before publication.
    target
        .file("memory.max", true)?
        .write_all(format!("{max}\n").as_bytes())?;
    target
        .file("memory.high", true)?
        .write_all(format!("{high}\n").as_bytes())?;
    check_limits(p, 150_000_000_000, 225_000_000_000, high, max)?;
    let allocation = published(
        &p.run_root.join("receipts/spawn-allocation.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-allocation-proof-v1","request":spec.request,
        "accounting_executable":x.accounting_executable,"accounting_qualification":x.accounting_qualification,
        "capacity_result":capacity,"capacity":result["capacity"],"recorded_unix_millis":millis()?,
        "runner":spec.runner,"issuer":issuer,"custody":lock.evidence()?,
        "effective_memory_high_bytes":high,"effective_memory_max_bytes":max,
        "publication_authorized":false,"r2_mutations":false}),
    )?;
    let grant_value = json!({"schema":"jetstreamer-epoch223-demotion-spawn-grant-v1",
        "runtime_plan":spec.runtime_plan,"control_grant":spec.control_grant,"request":spec.request,
        "runner":spec.runner,"issuer":issuer,"issuer_spec":binding,"native_input":spec.native_input,
        "guard":spec.guard,"allocation_proof":allocation,"recorded_unix_millis":millis()?,
        "requested_memory_high_bytes":150_000_000_000u64,"requested_memory_max_bytes":225_000_000_000u64,
        "effective_memory_high_bytes":high,"effective_memory_max_bytes":max,
        "protected_floor_bytes":control.protected_floor_bytes,"native_execution_authorized":true,
        "ordinary_replay_authorized":false,"publication_authorized":false,"r2_mutations":false});
    let grant: super::spawn::Grant = serde_json::from_value(grant_value.clone())?;
    super::spawn::validate_allocation(&grant, x, requested)?;
    let grant_binding = published(&p.run_root.join("receipts/spawn-grant.json"), &grant_value)?;
    published(
        &p.run_root.join("receipts/spawn-ready.json"),
        &json!({
        "schema":"jetstreamer-epoch223-demotion-spawn-ready-v1","runtime_plan":spec.runtime_plan,
        "request":spec.request,"runner":spec.runner,"grant":grant_binding}),
    )?;
    observe(&spec.runner)?;
    observe(&issuer)?;
    observe(&guard.actor)?;
    check_limits(p, 150_000_000_000, 225_000_000_000, high, max)?;
    lock.validate()?;
    drop(lock);
    let started = Instant::now();
    loop {
        let path = p.run_root.join("receipts/spawn-accepted.json");
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let bytes = read_owned(&path, 1000)?;
                let accepted: Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    accepted["runner"] == serde_json::to_value(&spec.runner)?
                        && accepted["grant"] == binding_value(&grant_binding),
                    "223 spawn acknowledgment differs"
                );
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            started.elapsed() < Duration::from_millis(spec.maximum_acknowledgment_wait_millis),
            "223 spawn acknowledgment deadline"
        );
        thread::sleep(Duration::from_millis(100));
    }
}
