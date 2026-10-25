use super::*;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Grant {
    schema: String,
    runtime_plan: BoundFile,
    control_grant: BoundFile,
    request: BoundFile,
    runner: Actor,
    issuer: Actor,
    issuer_spec: BoundFile,
    native_input: BoundFile,
    guard: BoundFile,
    allocation_proof: BoundFile,
    recorded_unix_millis: u64,
    requested_memory_high_bytes: u64,
    requested_memory_max_bytes: u64,
    effective_memory_high_bytes: u64,
    effective_memory_max_bytes: u64,
    protected_floor_bytes: u64,
    native_execution_authorized: bool,
    ordinary_replay_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    schema: String,
    runtime_plan: BoundFile,
    request: BoundFile,
    runner: Actor,
    grant: BoundFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Issue {
    pub(super) schema: String,
    pub(super) runtime_plan: BoundFile,
    pub(super) control_grant: BoundFile,
    pub(super) request: BoundFile,
    pub(super) runner: Actor,
    pub(super) native_input: BoundFile,
    pub(super) guard: BoundFile,
    pub(super) allocation_proof: BoundFile,
    pub(super) issuer_unit: String,
    pub(super) accounting_basis: BoundFile,
    pub(super) accounting_directory: PathBuf,
    pub(super) maximum_lock_wait_millis: u64,
    pub(super) maximum_acknowledgment_wait_millis: u64,
}
pub(super) struct Accepted {
    token: BoundFile,
    grant_binding: BoundFile,
    grant: Grant,
    guard: GuardProof,
}
fn valid_clock(issued: u64, requested: u64, now: u64) -> bool {
    issued >= requested && fresh(issued, now)
}
pub(super) fn admit(runtime: &Runtime, p: &Plan, iid: &str) -> Result<Value> {
    let (r, _) = runtime.decoded.get().context("223 runtime plan missing")?;
    let x = r
        .prerequisites
        .as_ref()
        .context("223 spawn prerequisites missing")?;
    let mut session = runtime
        .session
        .lock()
        .map_err(|_| anyhow::anyhow!("223 spawn lock poisoned"))?;
    session.spawn_gate.begin(x.maximum_spawn_wait_millis)?;
    let start = Instant::now();
    let result = wait(p, iid, x, &mut session, start);
    if result.is_err() {
        session.spawn_gate.phase = Phase::Closed;
    }
    result
}
fn wait(p: &Plan, iid: &str, x: &Prerequisites, s: &mut Session, start: Instant) -> Result<Value> {
    let c = s
        .accepted
        .as_ref()
        .context("223 control grant not accepted")?;
    ensure!(
        s.gate.phase == Phase::Released(c.ready.sha256.clone()) && c.actor.invocation_id == iid,
        "223 read-only control permission not consumed by this actor"
    );
    // The first grant authorizes bounded read-only input validation, not native
    // allocation. Its old age cannot invalidate completed valid hashing, and
    // cannot be refreshed into native authority. A different grant is mandatory.
    let _: Ready = read_bound(&c.ready)?;
    let _: ControlGrant = read_bound(&c.admission_binding)?;
    observe(&c.actor)?;
    observe(&c.guard.actor)?;
    check_control_kernel(p)?;
    let requested = millis()?;
    let request_path = p.run_root.join("receipts/spawn-request.json");
    persist(
        &request_path,
        &json!({"schema":"jetstreamer-epoch223-demotion-spawn-request-v1",
        "runtime_plan":c.admission.runtime_plan,"control_grant":c.admission_binding,
        "runner":c.actor,"native_input":x.native_input,"original_start_unix_millis":c.original_start_unix_millis,
        "read_only_validation_elapsed_millis":elapsed(s.hashing_started.context("223 hashing phase absent")?)?,
        "recorded_unix_millis":requested,"native_inputs_hashed":true,"worker_spawned":false,
        "native_execution_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let bytes = read_owned(&request_path, unsafe { libc::geteuid() })?;
    let request = BoundFile {
        path: request_path,
        sha256: hex(&Sha256::digest(&bytes)),
    };
    loop {
        s.spawn_gate.waiting(elapsed(start)?)?;
        let path = p.run_root.join("receipts/spawn-ready.json");
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e.into()),
            Ok(_) => {
                let bytes = read_owned(&path, 0)?;
                let token_binding = BoundFile {
                    path,
                    sha256: hex(&Sha256::digest(&bytes)),
                };
                let token: Token = serde_json::from_slice(&bytes)?;
                ensure!(
                    token.schema == "jetstreamer-epoch223-demotion-spawn-ready-v1"
                        && token.runtime_plan == c.admission.runtime_plan
                        && token.runner == c.actor
                        && token.request == request,
                    "223 spawn token was borrowed or replaced"
                );
                let g: Grant = read_bound(&token.grant)?;
                validate(&g, &request, c, x, requested, millis()?)?;
                let issue: Issue = read_bound(&g.issuer_spec)?;
                ensure!(
                    issue.schema == "jetstreamer-epoch223-demotion-spawn-issue-spec-v1"
                        && issue.runtime_plan == g.runtime_plan
                        && issue.control_grant == g.control_grant
                        && issue.request == g.request
                        && issue.runner == g.runner
                        && issue.native_input == g.native_input
                        && issue.guard == g.guard
                        && issue.maximum_acknowledgment_wait_millis > 0,
                    "223 spawn issuer spec differs"
                );
                validate_allocation(&g, x, requested)?;
                let guard: GuardProof = read_bound(&g.guard)?;
                ensure!(
                    guard.actor == c.guard.actor
                        && guard.guard_plan == c.guard.guard_plan
                        && guard.watched_runner == c.actor
                        && guard.protective_guard_proven
                        && guard.producer_stop_enabled
                        && guard.admission_policy == x.admission_policy
                        && guard.worker_sha256 == WORKER
                        && guard.target_slot == TERMINAL
                        && guard.run_root == p.run_root
                        && !guard.publication_authorized
                        && !guard.r2_mutations,
                    "223 spawn grant lacks the live original protective guard"
                );
                observe(&g.runner)?;
                observe(&g.issuer)?;
                observe(&guard.actor)?;
                check_limits(
                    p,
                    g.requested_memory_high_bytes,
                    g.requested_memory_max_bytes,
                    g.effective_memory_high_bytes,
                    g.effective_memory_max_bytes,
                )?;
                ensure!(
                    valid_clock(g.recorded_unix_millis, requested, millis()?),
                    "223 spawn grant expired during validation"
                );
                s.spawn_gate
                    .accept(elapsed(start)?, &token_binding.sha256)?;
                persist(
                    &p.run_root.join("receipts/spawn-accepted.json"),
                    &json!({
                    "schema":"jetstreamer-epoch223-demotion-spawn-accepted-v1","runner":g.runner,
                    "request":request,"token":token_binding,"grant":token.grant,
                    "original_start_unix_millis":c.original_start_unix_millis,"worker_spawned":false,
                    "native_execution_authorized":true,"ordinary_replay_authorized":false,
                    "publication_authorized":false,"r2_mutations":false}),
                )?;
                ensure!(
                    valid_clock(g.recorded_unix_millis, requested, millis()?),
                    "223 grant expired before release"
                );
                s.spawn_gate.release(&token_binding.sha256)?;
                let evidence = json!({"schema":"jetstreamer-epoch223-demotion-runtime-spawn-admission-v2",
                    "control_grant":c.admission_binding,"spawn_grant":token.grant,
                    "request":request,"actual_runner":g.runner,"actual_guard":guard.actor,
                    "original_start_unix_millis":c.original_start_unix_millis,
                    "ordinary_replay_authorized":false,"publication_authorized":false,"r2_mutations":false});
                s.spawn_accepted = Some(Accepted {
                    token: token_binding,
                    grant_binding: token.grant,
                    grant: g,
                    guard,
                });
                return Ok(evidence);
            }
        }
    }
}
fn validate(
    g: &Grant,
    request: &BoundFile,
    c: &super::Accepted,
    x: &Prerequisites,
    requested: u64,
    now: u64,
) -> Result<()> {
    ensure!(
        g.schema == "jetstreamer-epoch223-demotion-spawn-grant-v1"
            && g.runtime_plan == c.admission.runtime_plan
            && g.control_grant == c.admission_binding
            && g.request == *request
            && g.runner == c.actor
            && g.native_input == x.native_input
            && valid_clock(g.recorded_unix_millis, requested, now)
            && g.native_execution_authorized
            && !g.ordinary_replay_authorized
            && !g.publication_authorized
            && !g.r2_mutations,
        "223 requires one new post-hash allocation/spawn grant"
    );
    ensure!(
        g.issuer.executable == x.issuer_executable
            && g.issuer.pid != g.runner.pid
            && g.issuer.pid != c.guard.actor.pid
            && g.issuer.unit.starts_with("horizon-admit-223-demotion-")
            && g.issuer.expected_exec_start
                == exact_helper_command(
                    &g.issuer,
                    "issue-epoch223-demotion-spawn",
                    &g.issuer_spec,
                    "--spec-sha256"
                )
            && g.requested_memory_high_bytes == 150_000_000_000
            && g.requested_memory_max_bytes == 225_000_000_000
            && g.protected_floor_bytes == c.admission.protected_floor_bytes,
        "223 spawn issuer or closed allocation envelope differs"
    );
    Ok(())
}
pub(super) fn validate_allocation(g: &Grant, x: &Prerequisites, requested: u64) -> Result<()> {
    let proof: Value = read_bound(&g.allocation_proof)?;
    let result_binding: BoundFile = serde_json::from_value(proof["capacity_result"].clone())?;
    let result: Value = read_bound(&result_binding)?;
    let guard: GuardProof = read_bound(&g.guard)?;
    ensure!(
        result["schema"] == "jetstreamer-epoch223-demotion-capacity-result-v1"
            && result["self_sha256"] == x.accounting_executable.sha256
            && result["upstream_accounting_source_commit"]
                == "af09802051463086cf8f47de3bf200717d84e094"
            && result["context"]["phase"] == "spawn"
            && result["context"]["job_kind"] == "bracket"
            && result["context"]["runtime_plan"] == binding_value(&g.runtime_plan)
            && result["context"]["local_floor_bytes"] == g.protected_floor_bytes
            && result["context"]["producer"] == serde_json::to_value(&g.runner)?
            && result["context"]["issuer"] == serde_json::to_value(&g.issuer)?
            && result["context"]["guard"] == serde_json::to_value(&guard.actor)?
            && result["capacity"] == proof["capacity"]
            && result["capacity"]["candidate_accounting_final"]["candidate_memory_max_bytes"]
                == 225_000_000_000u64 + (2u64 << 30),
        "223 spawn allocation lacks exact newly computed full candidate capacity"
    );
    let qualification: Value = read_bound(&x.accounting_qualification)?;
    bound_file(
        &x.accounting_executable.path,
        &x.accounting_executable.sha256,
        512 << 20,
    )?;
    ensure!(
        proof["schema"] == "jetstreamer-epoch223-demotion-allocation-proof-v1"
            && proof["request"] == binding_value(&g.request)
            && proof["accounting_executable"] == binding_value(&x.accounting_executable)
            && proof["accounting_qualification"] == binding_value(&x.accounting_qualification)
            && proof["recorded_unix_millis"]
                .as_u64()
                .is_some_and(|n| n >= requested && n <= g.recorded_unix_millis)
            && qualification["upstream_accounting_source_commit"]
                == "af09802051463086cf8f47de3bf200717d84e094"
            && qualification["executable_sha256"] == x.accounting_executable.sha256
            && qualification["complete_memory_accounting_qualified"] == true
            && proof["capacity"]["schema"] == "jetstreamer-horizon-maintenance-capacity-v1"
            && proof["capacity"]["memory_before"].is_object()
            && proof["capacity"]["memory_after"].is_object()
            && proof["capacity"]["all_live_growth_and_century_floor_protected"] == true,
        "223 allocation is not a qualified complete-accounting result; old399 evidence is not authority"
    );
    Ok(())
}
pub(super) fn guard(runtime: &Runtime) -> Result<()> {
    let mut s = runtime
        .session
        .lock()
        .map_err(|_| anyhow::anyhow!("223 guard lock poisoned"))?;
    let result: Result<()> = (|| {
        let a = s
            .spawn_accepted
            .as_ref()
            .context("223 no consumed spawn grant")?;
        ensure!(
            s.spawn_gate.phase == Phase::Released(a.token.sha256.clone()),
            "223 native execution lacks single-use spawn permission"
        );
        let _: Token = read_bound(&a.token)?;
        let _: Grant = read_bound(&a.grant_binding)?;
        observe(&a.grant.runner)?;
        observe(&a.guard.actor)
    })();
    if result.is_err() {
        s.spawn_gate.phase = Phase::Closed;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn slow_valid_hash_uses_distinct_fresh_spawn_grant_without_renewing_control() {
        let mut control = Rendezvous::new();
        control.begin(120000).unwrap();
        control.accept(1, &"a".repeat(64)).unwrap();
        control.release(&"a".repeat(64)).unwrap();
        // Hashing takes longer than the first grant's freshness. No native
        // permission existed during that interval and the epoch clock stays1.
        let original_epoch_start = 1_u64;
        let post_hash_request = 900001_u64;
        assert!(!fresh(10, post_hash_request));
        assert!(!valid_clock(10, post_hash_request, post_hash_request + 1));
        let mut spawn = Rendezvous::new();
        spawn.begin(120000).unwrap();
        assert!(valid_clock(
            post_hash_request,
            post_hash_request,
            post_hash_request + 1
        ));
        spawn.accept(1, &"b".repeat(64)).unwrap();
        spawn.release(&"b".repeat(64)).unwrap();
        assert_eq!(control.phase, Phase::Released("a".repeat(64)));
        assert_eq!(original_epoch_start, 1);
        assert!(control.begin(120000).is_err());
        assert!(spawn.release(&"b".repeat(64)).is_err());
    }
    #[test]
    fn pre_hash_grant_or_expired_post_hash_grant_never_admits_spawn() {
        assert!(!valid_clock(999, 1000, 1001));
        assert!(!valid_clock(1000, 1000, 121001));
        let mut spawn = Rendezvous::new();
        spawn.begin(1000).unwrap();
        assert!(spawn.accept(1000, &"a".repeat(64)).is_err());
        assert!(spawn.begin(1000).is_err());
    }
}
