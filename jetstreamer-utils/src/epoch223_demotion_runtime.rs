// Binary-local epoch 223 admission interface. No ordinary profile imports this.
use super::*;
use std::{collections::BTreeMap, sync::OnceLock};

const MAX_WAIT_MILLIS: u64 = 120_000;
const MAX_ADMISSION_AGE_MILLIS: u64 = 120_000;
const HASH_MEMORY_HIGH: u64 = 14 << 30;
const HASH_MEMORY_MAX: u64 = 16 << 30;
mod native_capture {
    include!("epoch223_demotion_native_capture.rs");
}
mod issuance {
    include!("epoch223_demotion_issue.rs");
}
mod custody {
    include!("epoch223_demotion_custody.rs");
}
mod protective {
    include!("epoch223_demotion_guard.rs");
}
mod roles {
    include!("epoch223_demotion_roles.rs");
}
pub(super) fn role_entry() -> Option<Result<()>> {
    roles::dispatch()
}
mod spawn {
    include!("epoch223_demotion_spawn.rs");
}
const HARNESS: &str = "a280b1f48f0bb430c482e01a03b4b800ee8f95f326590059e4cdf4873b14a22b";
const OLD_UNIT: &str = "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service";
const OLD_IID: &str = "e70aaf097e7c4583b216aba454145910";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimePlan {
    schema: String,
    mode: String,
    pub plan: Plan,
    prerequisites: Option<Prerequisites>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Prerequisites {
    native_input: BoundFile,
    origin_clock: BoundFile,
    admission_policy: BoundFile,
    guard_executable: BoundFile,
    issuer_executable: BoundFile,
    maximum_wait_millis: u64,
    maximum_spawn_wait_millis: u64,
    accounting_executable: BoundFile,
    accounting_qualification: BoundFile,
}
#[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Actor {
    unit: String,
    invocation_id: String,
    pid: u32,
    start_ticks: u64,
    cgroup: String,
    boot_id: String,
    executable: BoundFile,
    expected_exec_start: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    schema: String,
    runtime_plan: BoundFile,
    runner: Actor,
    admission: BoundFile,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginClock {
    schema: String,
    unit: String,
    invocation_id: String,
    original_start_unix_millis: u64,
    manager_journal: BoundFile,
    failed_origin: BoundFile,
    terminal_journal_sha256: String,
    repair_closed: bool,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct NativeProof {
    schema: String,
    source_commit: String,
    worker_sha256: String,
    harness_sha256: String,
    test_name: String,
    source_qa_sha256: String,
    manager_success: bool,
    restart_count: u32,
    snapshot_sha256: String,
    genesis_sha256: String,
    success: bool,
    bootstrap_slot: u64,
    bank_hash: String,
    accounts_hash: String,
    last_blockhash: String,
    capitalization: u64,
    transaction_count: u64,
    tick_height: u64,
    next_write_version: u64,
    slot_complete: bool,
    replay_entries: u64,
    bootstrap_writes: u64,
    passed_tests: u64,
    ignored_tests: u64,
    actual_unit: String,
    actual_invocation_id: String,
    launch: BoundFile,
    result: BoundFile,
    journal: BoundFile,
    issuer: BoundFile,
    entry_replay: bool,
    canonical_prefix_qualified: bool,
    native_restart_qualified: bool,
    full_epoch_qualified: bool,
    runtime_promotion_authorized: bool,
    repair_closed: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairTask {
    schema: String,
    epoch: u64,
    phase: String,
    actor: Actor,
    origin_clock: BoundFile,
    original_start_unix_millis: u64,
    admission_policy: BoundFile,
    actor_launch: BoundFile,
    eta_policy: BoundFile,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardProof {
    schema: String,
    actor: Actor,
    watched_runner: Actor,
    guard_plan: BoundFile,
    admission_policy: BoundFile,
    run_root: PathBuf,
    worker_sha256: String,
    target_slot: u64,
    protective_guard_proven: bool,
    producer_stop_enabled: bool,
    recorded_unix_millis: u64,
    publication_authorized: bool,
    r2_mutations: bool,
}
#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ControlGrant {
    schema: String,
    epoch: u64,
    runtime_plan: BoundFile,
    runner: Actor,
    issuer: Actor,
    issuer_spec: BoundFile,
    parent_sha256: String,
    worker_sha256: String,
    snapshot_sha256: String,
    native_input: BoundFile,
    origin_clock: BoundFile,
    admission_policy: BoundFile,
    accepted_observer: BoundFile,
    accepted_fleet: BoundFile,
    context_qualification: BoundFile,
    repair_task: BoundFile,
    guard: BoundFile,
    recorded_unix_millis: u64,
    protected_floor_bytes: u64,
    read_only_hashing_authorized: bool,
    native_execution_authorized: bool,
    full_fleet_census_complete: bool,
    overlap_replacement_detected: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssueSpec {
    schema: String,
    runtime_plan: BoundFile,
    runner_launch: BoundFile,
    native_input: BoundFile,
    origin_clock: BoundFile,
    admission_policy: BoundFile,
    accepted_observer: BoundFile,
    accepted_fleet: BoundFile,
    repair_task: BoundFile,
    guard: BoundFile,
    issuer_unit: String,
    accounting_basis: BoundFile,
    accounting_directory: PathBuf,
    maximum_acknowledgment_wait_millis: u64,
    maximum_lock_wait_millis: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardPlan {
    schema: String,
    watched_runner: Actor,
    runtime_plan: BoundFile,
    admission_policy: BoundFile,
    run_root: PathBuf,
    worker_sha256: String,
    target_slot: u64,
    maximum_scratch_bytes: u64,
    protected_floor_bytes: u64,
    guard_unit: String,
    ready_output: PathBuf,
    stop_output: PathBuf,
}

// The only mutable state is local to one invocation. Timeout, malformed evidence,
// repeat admission or repeat spawn closes it permanently; no file renews a clock.
#[derive(Debug, PartialEq, Eq)]
enum Phase {
    New,
    Waiting,
    Accepted(String),
    Released(String),
    Closed,
}
struct Rendezvous {
    phase: Phase,
    limit: u64,
    last_elapsed: u64,
}
impl Rendezvous {
    fn new() -> Self {
        Self {
            phase: Phase::New,
            limit: 0,
            last_elapsed: 0,
        }
    }
    fn begin(&mut self, maximum: u64) -> Result<()> {
        if self.phase != Phase::New || !(1..=MAX_WAIT_MILLIS).contains(&maximum) {
            self.phase = Phase::Closed;
            anyhow::bail!("223 rendezvous cannot be renewed or widened");
        }
        self.limit = maximum;
        self.phase = Phase::Waiting;
        Ok(())
    }
    fn waiting(&mut self, elapsed: u64) -> Result<()> {
        if self.phase != Phase::Waiting || elapsed >= self.limit || elapsed < self.last_elapsed {
            self.phase = Phase::Closed;
            anyhow::bail!("223 admission rendezvous closed or expired");
        }
        self.last_elapsed = elapsed;
        Ok(())
    }
    fn accept(&mut self, elapsed: u64, token: &str) -> Result<()> {
        self.waiting(elapsed)?;
        if !digest(token) || token == "0".repeat(64) {
            self.phase = Phase::Closed;
            anyhow::bail!("223 invalid admission token");
        }
        self.phase = Phase::Accepted(token.into());
        Ok(())
    }
    fn release(&mut self, token: &str) -> Result<()> {
        if self.phase != Phase::Accepted(token.into()) {
            self.phase = Phase::Closed;
            anyhow::bail!("223 spawn admission is single use");
        }
        self.phase = Phase::Released(token.into());
        Ok(())
    }
}

fn same_metadata(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
}
fn read_owned(path: &Path, uid: u32) -> Result<Vec<u8>> {
    read_owned_max(path, uid, 1 << 20)
}
fn read_owned_max(path: &Path, uid: u32, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "223 noncanonical evidence"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "223 evidence must be bounded, immutable and correctly owned"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        same_metadata(&before, &file.metadata()?),
        "223 evidence changed while opening"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && same_metadata(&before, &file.metadata()?)
            && same_metadata(&before, &fs::symlink_metadata(path)?)
            && path.canonicalize()? == path,
        "223 evidence changed while reading"
    );
    Ok(bytes)
}
fn read_bound<T: serde::de::DeserializeOwned>(b: &BoundFile) -> Result<T> {
    Ok(serde_json::from_slice(&bound_bytes(b, 0, 1 << 20)?)?)
}
fn bound_bytes(b: &BoundFile, uid: u32, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        digest(&b.sha256) && b.sha256 != "0".repeat(64),
        "223 invalid evidence digest"
    );
    let bytes = read_owned_max(&b.path, uid, maximum)?;
    ensure!(
        hex(&Sha256::digest(&bytes)) == b.sha256,
        "223 bound bytes differ"
    );
    Ok(bytes)
}
fn binding_value(b: &BoundFile) -> Value {
    json!({"path":b.path,"sha256":b.sha256})
}
fn millis() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()
        .context("223 clock overflow")
}
fn elapsed(start: Instant) -> Result<u64> {
    start
        .elapsed()
        .as_millis()
        .try_into()
        .context("223 wait overflow")
}
fn fresh(at: u64, now: u64) -> bool {
    at > 0 && at <= now && now - at <= MAX_ADMISSION_AGE_MILLIS
}
fn start_ticks(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .context("223 process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("223 start ticks")?
        .parse()
        .context("223 invalid start ticks")
}
fn properties(unit: &str) -> Result<BTreeMap<String, String>> {
    properties_with(
        unit,
        "Id,ActiveState,SubState,MainPID,InvocationID,NRestarts,ControlGroup,ExecStart,User,Type,Restart",
    )
}
fn properties_with(unit: &str, keys: &str) -> Result<BTreeMap<String, String>> {
    ensure!(
        unit.ends_with(".service")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "223 unsafe unit"
    );
    let mut child = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--no-pager", &format!("--property={keys}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() >= Duration::from_secs(2) {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("223 manager identity query exceeded two seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.stdout.len() <= 65536 && output.stderr.len() <= 65536,
        "223 manager reply bounds"
    );
    ensure!(
        output.status.success(),
        "223 manager identity lookup failed"
    );
    let mut map = BTreeMap::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("223 malformed manager property")?;
        ensure!(
            map.insert(key.into(), value.into()).is_none(),
            "223 duplicate manager property"
        );
    }
    Ok(map)
}
fn command_matches(actual: &str, expected: &str) -> bool {
    actual
        .split(" ; start_time=")
        .next()
        .unwrap_or(actual)
        .trim_end_matches(" }")
        == expected.trim_end_matches(" }")
}
fn observe(a: &Actor) -> Result<()> {
    ensure!(
        identity(&a.invocation_id)
            && a.invocation_id != "0".repeat(32)
            && a.pid > 1
            && a.start_ticks > 0
            && a.cgroup == format!("/system.slice/{}", a.unit)
            && a.boot_id == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "223 actor scope changed"
    );
    bound_file(&a.executable.path, &a.executable.sha256, 256 << 20)?;
    let row = properties(&a.unit)?;
    let expected_user = if a.unit.starts_with("horizon-admit-223-demotion-")
        || a.unit.starts_with("horizon-guard-223-demotion-")
    {
        "root"
    } else {
        "ubuntu"
    };
    ensure!(
        row.get("User").map(String::as_str) == Some(expected_user)
            && row.get("Type").map(String::as_str) == Some("exec")
            && row.get("Restart").map(String::as_str) == Some("no"),
        "223 actor user differs"
    );
    for (key, expected) in [
        ("Id", a.unit.as_str()),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", a.invocation_id.as_str()),
        ("NRestarts", "0"),
        ("ControlGroup", a.cgroup.as_str()),
    ] {
        ensure!(
            row.get(key).map(String::as_str) == Some(expected),
            "223 actor manager identity changed:{key}"
        );
    }
    ensure!(
        row.get("MainPID").and_then(|s| s.parse::<u32>().ok()) == Some(a.pid)
            && row
                .get("ExecStart")
                .is_some_and(|s| command_matches(s, &a.expected_exec_start))
            && a.expected_exec_start.starts_with(&format!(
                "{{ path={} ; argv[]={}",
                a.executable.path.display(),
                a.executable.path.display()
            ))
            && start_ticks(a.pid)? == a.start_ticks
            && fs::read_to_string(format!("/proc/{}/cgroup", a.pid))?.trim()
                == format!("0::{}", a.cgroup),
        "223 actor PID/argv/start/cgroup changed"
    );
    ensure!(
        properties(&a.unit)? == row,
        "223 actor changed across identity capture"
    );
    Ok(())
}
fn own_actor(p: &Plan, iid: &str, plan: &BoundFile, self_sha: &str) -> Result<Actor> {
    let path = fs::read_link("/proc/self/exe")?;
    let a = Actor {
        unit: p.unit.clone(),
        invocation_id: iid.into(),
        pid: std::process::id(),
        start_ticks: start_ticks(std::process::id())?,
        cgroup: format!("/system.slice/{}", p.unit),
        boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        executable: BoundFile {
            path: path.clone(),
            sha256: self_sha.into(),
        },
        expected_exec_start: format!(
            "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
            path.display(),
            path.display(),
            plan.path.display(),
            plan.sha256,
            self_sha
        ),
    };
    observe(&a)?;
    Ok(a)
}

impl NativeProof {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "jetstreamer-epoch223-demotion-native-input-proof-v1"
                && self.source_commit == "551728fda72afd36ce6f8652ddb0020ec249e860"
                && self.worker_sha256 == WORKER
                && self.harness_sha256 == HARNESS
                && self.test_name
                    == "runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment"
                && self.source_qa_sha256
                    == "3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f"
                && self.manager_success
                && self.restart_count == 0
                && self.success
                && self.snapshot_sha256 == SNAPSHOT
                && self.genesis_sha256 == GENESIS
                && self.bootstrap_slot == 96_335_538
                && self.slot_complete
                && self.bank_hash == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
                && self.accounts_hash == "Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE"
                && self.last_blockhash == "9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa"
                && self.capitalization == 503_889_539_326_183_230
                && self.transaction_count == 27_822_879_094
                && self.tick_height == 6_165_474_496
                && self.next_write_version == 105_933_183_112
                && self.replay_entries == 0
                && self.bootstrap_writes == 0
                && self.passed_tests == 1
                && self.ignored_tests == 0
                && self
                    .actual_unit
                    .starts_with("horizon-native-input-223-demotion-")
                && self.actual_unit.ends_with(".service")
                && self
                    .actual_unit
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && identity(&self.actual_invocation_id)
                && self.actual_invocation_id != "0".repeat(32)
                && !self.entry_replay
                && !self.canonical_prefix_qualified
                && !self.native_restart_qualified
                && !self.full_epoch_qualified
                && !self.runtime_promotion_authorized
                && !self.repair_closed
                && !self.publication_authorized
                && !self.r2_mutations,
            "223 exact new-harness native proof differs"
        );
        Ok(())
    }
}

struct Accepted {
    ready: BoundFile,
    admission_binding: BoundFile,
    admission: ControlGrant,
    guard: GuardProof,
    actor: Actor,
    original_start_unix_millis: u64,
}
struct Session {
    gate: Rendezvous,
    spawn_gate: Rendezvous,
    accepted: Option<Accepted>,
    hashing_started: Option<Instant>,
    spawn_accepted: Option<spawn::Accepted>,
}
pub(super) struct Runtime {
    decoded: OnceLock<(RuntimePlan, String)>,
    session: std::sync::Mutex<Session>,
}
impl Runtime {
    pub fn new() -> Self {
        Self {
            decoded: OnceLock::new(),
            session: std::sync::Mutex::new(Session {
                gate: Rendezvous::new(),
                spawn_gate: Rendezvous::new(),
                accepted: None,
                hashing_started: None,
                spawn_accepted: None,
            }),
        }
    }
    pub fn decode(&self, bytes: &[u8]) -> Result<Plan> {
        let r: RuntimePlan = serde_json::from_slice(bytes)?;
        ensure!(
            r.schema == "jetstreamer-epoch223-demotion-runtime-plan-v3"
                && ((r.mode == "capability" && r.prerequisites.is_none())
                    || (r.mode == "bracket"
                        && r.prerequisites
                            .as_ref()
                            .is_some_and(|x| (1..=MAX_WAIT_MILLIS)
                                .contains(&x.maximum_wait_millis)
                                && (1..=MAX_WAIT_MILLIS).contains(&x.maximum_spawn_wait_millis)))),
            "223 exact runtime plan required; legacy plans cannot launch"
        );
        let p = r.plan.clone();
        self.decoded
            .set((r, hex(&Sha256::digest(bytes))))
            .map_err(|_| anyhow::anyhow!("223 runtime plan decoded twice"))?;
        Ok(p)
    }
    pub fn before_inputs(
        &self,
        p: &Plan,
        iid: &str,
        binding: &BoundFile,
        self_sha: &str,
        capability: bool,
    ) -> Result<()> {
        let (r, decoded_sha) = self.decoded.get().context("223 runtime plan absent")?;
        ensure!(
            binding.sha256 == *decoded_sha && digest(PARENT_SHA) && p.node.sha256 == PARENT_SHA,
            "223 parent/runtime-plan binding differs"
        );
        let _: RuntimePlan = read_bound(binding)?;
        ensure!(
            (r.mode == "capability") == capability,
            "223 runtime mode/argv mismatch"
        );
        if capability {
            return Ok(());
        }
        let x = r
            .prerequisites
            .as_ref()
            .context("223 runtime prerequisites absent")?;
        let mut session = self
            .session
            .lock()
            .map_err(|_| anyhow::anyhow!("223 rendezvous lock poisoned"))?;
        session.gate.begin(x.maximum_wait_millis)?;
        let start = Instant::now();
        let result = self.wait(p, iid, binding, self_sha, x, start, &mut session);
        if let Err(error) = &result {
            session.gate.phase = Phase::Closed;
            persist(
                &p.run_root.join("receipts/admission-failure.json"),
                &json!({
                "schema":"jetstreamer-epoch223-demotion-rendezvous-failure-v1","unit":p.unit,
                "reported_runner_invocation_id":iid,"runner_pid":std::process::id(),
                "runtime_plan":binding_value(binding),"elapsed_wait_millis":elapsed(start)?,
                "error":format!("{error:#}"),"worker_spawned":false,"native_input_read":false,
                "publication_authorized":false,"r2_mutations":false}),
            )
            .with_context(|| {
                format!("223 rendezvous failed ({error:#}); failure receipt write also failed")
            })?;
        }
        result
    }
    fn wait(
        &self,
        p: &Plan,
        iid: &str,
        binding: &BoundFile,
        self_sha: &str,
        x: &Prerequisites,
        start: Instant,
        session: &mut Session,
    ) -> Result<()> {
        let actor = own_actor(p, iid, binding, self_sha)?;
        let origin: OriginClock = read_bound(&x.origin_clock)?;
        validate_origin(&origin, millis()?)?;
        validate_origin_journal(&origin)?;
        let ready_path = p.run_root.join("receipts/admission-ready.json");
        persist(
            &p.run_root.join("receipts/rendezvous-start.json"),
            &json!({
            "schema":"jetstreamer-epoch223-demotion-rendezvous-start-v1","runtime_plan":binding_value(binding),
            "runner":actor,"origin_clock":binding_value(&x.origin_clock),
            "original_start_unix_millis":origin.original_start_unix_millis,
            "maximum_wait_millis":x.maximum_wait_millis,"recorded_unix_millis":millis()?,
            "native_input_read":false,"worker_spawned":false,"entry_replay":false,
            "publication_authorized":false,"r2_mutations":false}),
        )?;
        loop {
            session.gate.waiting(elapsed(start)?)?;
            match fs::symlink_metadata(&ready_path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    thread::sleep(Duration::from_millis(100))
                }
                Err(e) => return Err(e.into()),
                Ok(_) => {
                    let bytes = read_owned(&ready_path, 0)?;
                    let ready_binding = BoundFile {
                        path: ready_path,
                        sha256: hex(&Sha256::digest(&bytes)),
                    };
                    let ready: Ready = serde_json::from_slice(&bytes)?;
                    let admission: ControlGrant = read_bound(&ready.admission)?;
                    let native: NativeProof = read_bound(&x.native_input)?;
                    native.validate()?;
                    // Proof inputs are immutable metadata, never snapshots or entries.
                    for b in [
                        &native.launch,
                        &native.result,
                        &native.journal,
                        &native.issuer,
                        &origin.manager_journal,
                        &origin.failed_origin,
                        &x.admission_policy,
                    ] {
                        verify_reference(b)?;
                    }
                    let task: RepairTask = read_bound(&admission.repair_task)?;
                    let guard: GuardProof = read_bound(&admission.guard)?;
                    let issue: IssueSpec = read_bound(&admission.issuer_spec)?;
                    let guard_plan: GuardPlan = read_bound(&guard.guard_plan)?;
                    validate_admission(
                        p,
                        x,
                        binding,
                        &actor,
                        &ready,
                        &admission,
                        &origin,
                        &task,
                        &guard,
                        millis()?,
                    )?;
                    validate_issue_and_guard_plan(
                        p,
                        binding,
                        &admission,
                        &task,
                        &guard,
                        &issue,
                        &guard_plan,
                    )?;
                    verify_reference(&task.actor_launch)?;
                    verify_reference(&task.eta_policy)?;
                    for b in [
                        &admission.accepted_observer,
                        &admission.accepted_fleet,
                        &admission.context_qualification,
                        &guard.guard_plan,
                    ] {
                        verify_reference(b)?;
                    }
                    observe(&actor)?;
                    observe(&admission.issuer)?;
                    observe(&guard.actor)?;
                    issuance::validate_control_capacity(&admission, x)?;
                    check_control_kernel(p)?;
                    session
                        .gate
                        .accept(elapsed(start)?, &ready_binding.sha256)?;
                    session.gate.release(&ready_binding.sha256)?;
                    persist(
                        &p.run_root.join("receipts/admission-accepted.json"),
                        &json!({
                        "schema":"jetstreamer-epoch223-demotion-rendezvous-accepted-v1",
                        "runtime_plan":binding_value(binding),"ready":binding_value(&ready_binding),
                        "admission":binding_value(&ready.admission),"runner":actor,
                        "guard":guard.actor,"original_start_unix_millis":origin.original_start_unix_millis,
                        "native_input_read":false,"worker_spawned":false,
                        "read_only_hashing_authorized":true,"native_execution_authorized":false,
                        "publication_authorized":false,"r2_mutations":false}),
                    )?;
                    session.accepted = Some(Accepted {
                        ready: ready_binding,
                        admission_binding: ready.admission,
                        admission,
                        guard,
                        actor,
                        original_start_unix_millis: origin.original_start_unix_millis,
                    });
                    session.hashing_started = Some(Instant::now());
                    return Ok(());
                }
            }
        }
    }
    pub fn before_spawn(&self, p: &Plan, iid: &str) -> Result<Value> {
        spawn::admit(self, p, iid)
    }
    pub fn guard(&self) -> Result<()> {
        spawn::guard(self)
    }
}

fn verify_reference(b: &BoundFile) -> Result<()> {
    ensure!(
        !bound_bytes(b, 0, 16 << 20)?.is_empty(),
        "223 empty referenced evidence"
    );
    Ok(())
}
fn validate_origin(o: &OriginClock, now: u64) -> Result<()> {
    ensure!(
        o.schema == "jetstreamer-epoch223-e70a-origin-clock-v1"
            && o.unit == OLD_UNIT
            && o.invocation_id == OLD_IID
            && o.original_start_unix_millis > 0
            && o.original_start_unix_millis < now
            && !o.repair_closed
            && o.terminal_journal_sha256
                == "58e40c27ef840b8843b531d4ce372e955ae55c878638651979672904706c627f"
            && o.manager_journal.sha256 == o.terminal_journal_sha256
            && o.failed_origin.sha256
                == "f1aa68c425b6bfad05417d196f20bae77de0f67c0bb61d19556f77946e2083ba",
        "223 original e70a clock/identity differs"
    );
    Ok(())
}
fn origin_start(bytes: &[u8]) -> Result<u64> {
    let mut selected = None;
    for row in serde_json::Deserializer::from_slice(bytes).into_iter::<Value>() {
        let row = row?;
        if row["_PID"] == "1"
            && row["UNIT"] == OLD_UNIT
            && row["INVOCATION_ID"] == OLD_IID
            && row["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Started {OLD_UNIT} - ")))
        {
            let micros = row["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("223 origin manager timestamp")?
                .parse::<u64>()?;
            ensure!(
                micros > 0 && selected.replace(micros / 1000).is_none(),
                "223 duplicate/invalid original start"
            );
        }
    }
    selected.context("223 genuine original manager start missing")
}
fn validate_origin_journal(o: &OriginClock) -> Result<()> {
    let bytes = read_owned_max(&o.manager_journal.path, 0, 16 << 20)?;
    ensure!(
        hex(&Sha256::digest(&bytes)) == o.manager_journal.sha256
            && origin_start(&bytes)? == o.original_start_unix_millis,
        "223 original clock was reset or journal changed"
    );
    Ok(())
}
fn exact_helper_command(actor: &Actor, command: &str, spec: &BoundFile, flag: &str) -> String {
    format!(
        "{{ path={} ; argv[]={} {command} {} {flag} {} --self-sha256 {} ; ignore_errors=no }}",
        actor.executable.path.display(),
        actor.executable.path.display(),
        spec.path.display(),
        spec.sha256,
        actor.executable.sha256
    )
}
#[allow(clippy::too_many_arguments)]
fn validate_issue_and_guard_plan(
    p: &Plan,
    plan: &BoundFile,
    a: &ControlGrant,
    t: &RepairTask,
    g: &GuardProof,
    i: &IssueSpec,
    q: &GuardPlan,
) -> Result<()> {
    ensure!(
        i.schema == "jetstreamer-epoch223-demotion-admission-issue-spec-v1"
            && i.runtime_plan == *plan
            && i.runner_launch == t.actor_launch
            && i.native_input == a.native_input
            && i.origin_clock == a.origin_clock
            && i.admission_policy == a.admission_policy
            && i.accepted_observer == a.accepted_observer
            && i.accepted_fleet == a.accepted_fleet
            && i.repair_task == a.repair_task
            && i.guard == a.guard
            && a.issuer.expected_exec_start
                == exact_helper_command(
                    &a.issuer,
                    "issue-epoch223-demotion-control",
                    &a.issuer_spec,
                    "--spec-sha256"
                ),
        "223 admission issuer command/spec bindings differ"
    );
    ensure!(
        q.schema == "jetstreamer-epoch223-demotion-guard-plan-v1"
            && q.runtime_plan == *plan
            && q.guard_unit == g.actor.unit
            && q.ready_output == a.guard.path
            && q.watched_runner == a.runner
            && q.admission_policy == a.admission_policy
            && q.run_root == p.run_root
            && q.worker_sha256 == WORKER
            && q.target_slot == TERMINAL
            && q.maximum_scratch_bytes == MAX_SCRATCH
            && q.protected_floor_bytes == a.protected_floor_bytes
            && g.actor.expected_exec_start
                == exact_helper_command(
                    &g.actor,
                    "guard-epoch223-demotion",
                    &g.guard_plan,
                    "--plan-sha256"
                ),
        "223 exact independent guard command/plan differs"
    );
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn validate_admission(
    p: &Plan,
    x: &Prerequisites,
    plan: &BoundFile,
    actor: &Actor,
    r: &Ready,
    a: &ControlGrant,
    o: &OriginClock,
    t: &RepairTask,
    g: &GuardProof,
    now: u64,
) -> Result<()> {
    ensure!(
        r.schema == "jetstreamer-epoch223-demotion-control-ready-v1"
            && r.runtime_plan == *plan
            && r.runner == *actor,
        "223 ready token names another plan/actual actor"
    );
    ensure!(
        a.schema == "jetstreamer-epoch223-demotion-control-grant-v1"
            && a.epoch == 223
            && a.runtime_plan == *plan
            && a.runner == *actor
            && a.parent_sha256 == p.node.sha256
            && a.worker_sha256 == WORKER
            && a.snapshot_sha256 == SNAPSHOT
            && a.native_input == x.native_input
            && a.origin_clock == x.origin_clock
            && a.admission_policy == x.admission_policy
            && fresh(a.recorded_unix_millis, now)
            && a.full_fleet_census_complete
            && !a.overlap_replacement_detected
            && !a.publication_authorized
            && !a.r2_mutations,
        "223 admission scope/freshness differs"
    );
    ensure!(
        a.read_only_hashing_authorized
            && !a.native_execution_authorized
            && a.protected_floor_bytes > 0
            && a.protected_floor_bytes == p.minimum_free_bytes,
        "223 control grant cannot authorize allocation or execution"
    );
    ensure!(
        a.issuer.unit.starts_with("horizon-admit-223-demotion-")
            && a.issuer.executable == x.issuer_executable
            && a.issuer.pid != actor.pid
            && a.issuer.invocation_id != actor.invocation_id,
        "223 admission has no independent exact issuer actor"
    );
    ensure!(
        t.schema == "jetstreamer-epoch223-demotion-repair-task-v1"
            && t.epoch == 223
            && t.phase == "admission-rendezvous"
            && t.actor == *actor
            && t.origin_clock == x.origin_clock
            && t.original_start_unix_millis == o.original_start_unix_millis
            && t.admission_policy == x.admission_policy
            && !t.publication_authorized
            && !t.r2_mutations,
        "223 genuine repair task/original clock differs"
    );
    ensure!(
        g.schema == "jetstreamer-epoch223-demotion-guard-ready-v1"
            && g.watched_runner == *actor
            && g.actor.unit.starts_with("horizon-guard-223-demotion-")
            && g.actor.executable == x.guard_executable
            && g.actor.pid != actor.pid
            && g.actor.pid != a.issuer.pid
            && g.actor.invocation_id != actor.invocation_id
            && g.actor.invocation_id != a.issuer.invocation_id
            && g.actor.boot_id == actor.boot_id
            && a.issuer.boot_id == actor.boot_id
            && g.admission_policy == x.admission_policy
            && g.run_root == p.run_root
            && g.worker_sha256 == WORKER
            && g.target_slot == TERMINAL
            && g.protective_guard_proven
            && g.producer_stop_enabled
            && fresh(g.recorded_unix_millis, now)
            && !g.publication_authorized
            && !g.r2_mutations,
        "223 independent exact guard binding differs"
    );
    Ok(())
}
fn check_control_kernel(p: &Plan) -> Result<()> {
    check_limits(
        p,
        HASH_MEMORY_HIGH,
        HASH_MEMORY_MAX,
        HASH_MEMORY_HIGH,
        HASH_MEMORY_MAX,
    )
}
fn check_limits(
    p: &Plan,
    high: u64,
    max: u64,
    effective_high: u64,
    effective_max: u64,
) -> Result<()> {
    let root = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })?;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "223 invalid kernel page size"
    );
    ensure!(
        effective_high == high / page * page && effective_max == max / page * page,
        "223 kernel rounding differs"
    );
    for (file, expected) in [
        ("memory.high", effective_high),
        ("memory.max", effective_max),
        ("memory.swap.max", 0),
    ] {
        ensure!(
            fs::read_to_string(root.join(file))?.trim().parse::<u64>()? == expected,
            "223 actual kernel bound changed:{file}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str) -> BoundFile {
        BoundFile {
            path: PathBuf::from(format!("/sealed/fixture-{name}")),
            sha256: "a".repeat(64),
        }
    }
    fn plan_value() -> Value {
        json!({"schema":PLAN_SCHEMA,"unit":"horizon-qualify-223-demotion-bracket-fixture.service",
            "node":file("parent"),"worker":"/sealed/fixture-worker",
            "snapshot":format!("/sealed/{SNAPSHOT_NAME}"),"ledger_directory":"/sealed/fixture-ledger",
            "epoch_hashes":file("hashes"),"run_root":"/home/ubuntu/.jetstreamer-private/qualification-223-demotion-bracket-fixture",
            "target_slot":TERMINAL,"terminal_slot":TERMINAL,"minimum_free_bytes":MINIMUM_FREE,"maximum_runtime_seconds":600})
    }
    fn actor(unit: &str, pid: u32, iid: &str) -> Actor {
        Actor {
            unit: unit.into(),
            invocation_id: iid.repeat(32),
            pid,
            start_ticks: 100,
            cgroup: format!("/system.slice/{unit}"),
            boot_id: "fixture-boot".into(),
            executable: file(unit),
            expected_exec_start: "fixture command; not executed".into(),
        }
    }
    fn native() -> NativeProof {
        serde_json::from_value(json!({"schema":"jetstreamer-epoch223-demotion-native-input-proof-v1",
            "source_commit":"551728fda72afd36ce6f8652ddb0020ec249e860","worker_sha256":WORKER,
            "harness_sha256":HARNESS,"test_name":"runtime::tests::native_epoch223_cold_input_matches_canonical_accounts_commitment",
            "source_qa_sha256":"3d5ea04ae0658070be51a8b410e2d6af8e0305bade8b7df455957e9db77a2f0f",
            "manager_success":true,"restart_count":0,"snapshot_sha256":SNAPSHOT,"genesis_sha256":GENESIS,
            "success":true,"bootstrap_slot":96335538,"bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F",
            "accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE",
            "last_blockhash":"9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa","capitalization":503889539326183230u64,
            "transaction_count":27822879094u64,"tick_height":6165474496u64,"next_write_version":105933183112u64,
            "slot_complete":true,"replay_entries":0,"bootstrap_writes":0,"passed_tests":1,"ignored_tests":0,
            "actual_unit":"horizon-native-input-223-demotion-fixture.service","actual_invocation_id":"b".repeat(32),
            "launch":file("native-launch"),"result":file("native-result"),"journal":file("native-journal"),"issuer":file("native-issuer-receipt"),
            "entry_replay":false,"canonical_prefix_qualified":false,"native_restart_qualified":false,
            "full_epoch_qualified":false,"runtime_promotion_authorized":false,"repair_closed":false,
            "publication_authorized":false,"r2_mutations":false})).unwrap()
    }

    #[test]
    fn rendezvous_timeout_cannot_be_renewed() {
        let mut gate = Rendezvous::new();
        gate.begin(1000).unwrap();
        gate.waiting(999).unwrap();
        assert!(gate.accept(1000, &"a".repeat(64)).is_err());
        assert!(gate.begin(1000).is_err());
        assert!(gate.accept(0, &"a".repeat(64)).is_err());
        assert_eq!(gate.phase, Phase::Closed);
    }
    #[test]
    fn rendezvous_cannot_rewind_swap_or_reuse_admission() {
        let mut rewind = Rendezvous::new();
        rewind.begin(1000).unwrap();
        rewind.waiting(500).unwrap();
        assert!(rewind.waiting(499).is_err());
        let mut changed = Rendezvous::new();
        changed.begin(1000).unwrap();
        changed.accept(999, &"a".repeat(64)).unwrap();
        assert!(changed.release(&"b".repeat(64)).is_err());
        assert!(changed.release(&"a".repeat(64)).is_err());
        let mut once = Rendezvous::new();
        once.begin(1000).unwrap();
        once.accept(999, &"a".repeat(64)).unwrap();
        once.release(&"a".repeat(64)).unwrap();
        assert!(once.release(&"a".repeat(64)).is_err());
    }
    #[test]
    fn rendezvous_rejects_invalid_budget_and_token_without_reset() {
        for maximum in [0, MAX_WAIT_MILLIS + 1] {
            let mut gate = Rendezvous::new();
            assert!(gate.begin(maximum).is_err());
            assert!(gate.begin(1).is_err());
        }
        let mut gate = Rendezvous::new();
        gate.begin(100).unwrap();
        assert!(gate.accept(0, &"0".repeat(64)).is_err());
        assert!(gate.accept(1, &"a".repeat(64)).is_err());
    }
    #[test]
    fn native_proof_rejects_old_harness_ignored_test_and_promoted_authority() {
        let valid = native();
        valid.validate().unwrap();
        let value = serde_json::to_value(valid).unwrap();
        for (field, replacement) in [
            (
                "harness_sha256",
                json!("526448fac7ff1db52450947cdbb0acab46cacf96d356ff36325b7b87c0596486"),
            ),
            ("worker_sha256", json!("a".repeat(64))),
            ("schema", json!("jetstreamer-native223-cold-input-proof-v1")),
            ("ignored_tests", json!(1)),
            ("passed_tests", json!(0)),
            ("manager_success", json!(false)),
            ("restart_count", json!(1)),
            ("slot_complete", json!(false)),
            ("capitalization", json!(503889539326183232u64)),
            ("entry_replay", json!(true)),
            ("repair_closed", json!(true)),
            ("publication_authorized", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = value.clone();
            bad[field] = replacement;
            assert!(
                serde_json::from_value::<NativeProof>(bad)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn actual_origin_clock_requires_unique_original_manager_start() {
        let start = json!({"_PID":"1","UNIT":OLD_UNIT,"INVOCATION_ID":OLD_IID,
            "MESSAGE":format!("Started {OLD_UNIT} - Fixture description."),"__REALTIME_TIMESTAMP":"1792806478075603"});
        let bytes = serde_json::to_vec(&start).unwrap();
        assert_eq!(origin_start(&bytes).unwrap(), 1792806478075);
        let mut other = start;
        other["INVOCATION_ID"] = json!("c".repeat(32));
        assert!(origin_start(&serde_json::to_vec(&other).unwrap()).is_err());
        let duplicate = [bytes.clone(), b"\n".to_vec(), bytes].concat();
        assert!(origin_start(&duplicate).is_err());
    }
    #[test]
    fn legacy_plan_and_serialized_hook_selection_are_rejected() {
        let base = plan_value();
        assert!(
            Runtime::new()
                .decode(&serde_json::to_vec(&base).unwrap())
                .is_err()
        );
        let envelope = json!({"schema":"jetstreamer-epoch223-demotion-runtime-plan-v3","mode":"capability","plan":base,"prerequisites":null});
        let runtime = Runtime::new();
        runtime
            .decode(&serde_json::to_vec(&envelope).unwrap())
            .unwrap();
        assert!(
            runtime
                .decode(&serde_json::to_vec(&envelope).unwrap())
                .is_err()
        );
        let mut bad = envelope;
        bad["mode"] = json!("bracket");
        assert!(
            Runtime::new()
                .decode(&serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
        bad["mode"] = json!("capability");
        bad["select_storage_hook"] = json!("ordinary");
        assert!(
            Runtime::new()
                .decode(&serde_json::to_vec(&bad).unwrap())
                .is_err()
        );
    }
    #[test]
    fn ordinary_profile_hook_remains_noop_and_cannot_decode_private_envelope() {
        let base = plan_value();
        let p: Plan = serde_json::from_value(base.clone()).unwrap();
        DiskStorage
            .before_inputs(&p, "fixture-iid", &file("plan"), &"a".repeat(64))
            .unwrap();
        DiskStorage
            .decode_plan(&serde_json::to_vec(&base).unwrap())
            .unwrap();
        let envelope = json!({"schema":"jetstreamer-epoch223-demotion-runtime-plan-v3","mode":"capability","plan":base,"prerequisites":null});
        assert!(
            DiskStorage
                .decode_plan(&serde_json::to_vec(&envelope).unwrap())
                .is_err()
        );
    }
    #[test]
    fn no_spawn_or_guard_is_admitted_without_real_rendezvous() {
        let runtime = Runtime::new();
        let p: Plan = serde_json::from_value(plan_value()).unwrap();
        assert!(runtime.before_spawn(&p, &"a".repeat(32)).is_err());
        assert!(runtime.guard().is_err());
    }
    #[test]
    fn stable_metadata_reader_rejects_mutable_aliased_and_mismatched_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("proof.json");
        let bytes = br#"{"capitalization":503889539326183230}"#;
        fs::write(&path, bytes).unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(read_owned(&path, uid).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        let captured = read_owned(&path, uid).unwrap();
        let binding = BoundFile {
            path: path.clone(),
            sha256: hex(&Sha256::digest(bytes)),
        };
        assert_eq!(bound_bytes(&binding, uid, 1024).unwrap(), captured);
        let mismatched = BoundFile {
            path: path.clone(),
            sha256: "b".repeat(64),
        };
        assert!(bound_bytes(&mismatched, uid, 1024).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&captured).unwrap()["capitalization"].as_u64(),
            Some(503889539326183230)
        );
        let link = root.path().join("alias");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_owned(&link, uid).is_err());
        let hard = root.path().join("hard");
        fs::hard_link(&path, &hard).unwrap();
        assert!(read_owned(&path, uid).is_err());
    }
    #[test]
    fn freshness_is_finite_and_never_allows_future_or_missing_time() {
        assert!(fresh(1, MAX_ADMISSION_AGE_MILLIS + 1));
        assert!(!fresh(1, MAX_ADMISSION_AGE_MILLIS + 2));
        assert!(!fresh(0, 1));
        assert!(!fresh(2, 1));
    }

    #[test]
    fn actor_guard_and_original_clock_cannot_be_borrowed() {
        let p: Plan = serde_json::from_value(plan_value()).unwrap();
        let root = file("runtime-plan");
        let runner = actor(&p.unit, 101, "a");
        let issuer = actor("horizon-admit-223-demotion-fixture.service", 102, "b");
        let guard_actor = actor("horizon-guard-223-demotion-fixture.service", 103, "c");
        let x = Prerequisites {
            native_input: file("native"),
            origin_clock: file("origin"),
            admission_policy: file("policy"),
            guard_executable: guard_actor.executable.clone(),
            issuer_executable: issuer.executable.clone(),
            maximum_wait_millis: 1000,
            maximum_spawn_wait_millis: 1000,
            accounting_executable: file("accountant"),
            accounting_qualification: file("accountant-qualification"),
        };
        let origin = OriginClock {
            schema: "jetstreamer-epoch223-e70a-origin-clock-v1".into(),
            unit: OLD_UNIT.into(),
            invocation_id: OLD_IID.into(),
            original_start_unix_millis: 1,
            manager_journal: file("origin-journal"),
            failed_origin: file("failure"),
            terminal_journal_sha256: "a".repeat(64),
            repair_closed: false,
        };
        let ready = Ready {
            schema: "jetstreamer-epoch223-demotion-control-ready-v1".into(),
            runtime_plan: root.clone(),
            runner: runner.clone(),
            admission: file("admission"),
        };
        let mut a = ControlGrant {
            schema: "jetstreamer-epoch223-demotion-control-grant-v1".into(),
            epoch: 223,
            runtime_plan: root.clone(),
            runner: runner.clone(),
            issuer,
            issuer_spec: file("issue-spec"),
            parent_sha256: p.node.sha256.clone(),
            worker_sha256: WORKER.into(),
            snapshot_sha256: SNAPSHOT.into(),
            native_input: x.native_input.clone(),
            origin_clock: x.origin_clock.clone(),
            admission_policy: x.admission_policy.clone(),
            accepted_observer: file("observer"),
            accepted_fleet: file("fleet"),
            context_qualification: file("context"),
            repair_task: file("task"),
            guard: file("guard"),
            recorded_unix_millis: 10,
            protected_floor_bytes: 2000000000000,
            read_only_hashing_authorized: true,
            native_execution_authorized: false,
            full_fleet_census_complete: true,
            overlap_replacement_detected: false,
            publication_authorized: false,
            r2_mutations: false,
        };
        let mut task = RepairTask {
            schema: "jetstreamer-epoch223-demotion-repair-task-v1".into(),
            epoch: 223,
            phase: "admission-rendezvous".into(),
            actor: runner.clone(),
            origin_clock: x.origin_clock.clone(),
            original_start_unix_millis: 1,
            admission_policy: x.admission_policy.clone(),
            actor_launch: file("launch"),
            eta_policy: file("eta"),
            publication_authorized: false,
            r2_mutations: false,
        };
        let mut guard = GuardProof {
            schema: "jetstreamer-epoch223-demotion-guard-ready-v1".into(),
            actor: guard_actor,
            watched_runner: runner.clone(),
            guard_plan: file("guard-plan"),
            admission_policy: x.admission_policy.clone(),
            run_root: p.run_root.clone(),
            worker_sha256: WORKER.into(),
            target_slot: TERMINAL,
            protective_guard_proven: true,
            producer_stop_enabled: true,
            recorded_unix_millis: 10,
            publication_authorized: false,
            r2_mutations: false,
        };
        validate_admission(
            &p, &x, &root, &runner, &ready, &a, &origin, &task, &guard, 11,
        )
        .unwrap();
        task.original_start_unix_millis = 10;
        assert!(
            validate_admission(
                &p, &x, &root, &runner, &ready, &a, &origin, &task, &guard, 11
            )
            .is_err()
        );
        task.original_start_unix_millis = 1;
        guard.watched_runner.pid += 1;
        assert!(
            validate_admission(
                &p, &x, &root, &runner, &ready, &a, &origin, &task, &guard, 11
            )
            .is_err()
        );
        guard.watched_runner = runner.clone();
        a.runner.invocation_id = "d".repeat(32);
        assert!(
            validate_admission(
                &p, &x, &root, &runner, &ready, &a, &origin, &task, &guard, 11
            )
            .is_err()
        );
        a.runner = runner.clone();
        a.overlap_replacement_detected = true;
        assert!(
            validate_admission(
                &p, &x, &root, &runner, &ready, &a, &origin, &task, &guard, 11
            )
            .is_err()
        );
    }
}
