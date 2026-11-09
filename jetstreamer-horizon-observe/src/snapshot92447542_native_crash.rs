//! Actual process-exit/recovery controls over persistent isolated generation sessions.
//! Every invocation is independently admitted; durable operation bindings use the
//! immutable session SHA rather than the expiring current-owner admission SHA.
//! No production Plan, generation selector or lifecycle qualification is created.
use super::*;

const EXIT_CODE: i32 = 197;
const WARM_ACCEPTANCE_SHA: &str =
    "08a653826ef167e5e474ef9ce6b795d5aee345ddc4005f1d2008ce7aeb407937";
const WARM_PATH: &str = "/home/ubuntu/.jetstreamer-private/qualification-snapshot92447542-native-engine-1045-roundtrip-v2/cache/snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst";
const PEAK: u64 = 2 * SIZE + 2 * SLACK;

fn serialize_bound<S: serde::Serializer>(
    b: &Bound,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    #[derive(Serialize)]
    struct View<'a> {
        path: &'a Path,
        sha256: &'a str,
    }
    View {
        path: &b.path,
        sha256: &b.sha256,
    }
    .serialize(serializer)
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Transport {
    RealGcs,
    VerifiedWarmCopy,
    NonzeroExit,
    Truncated,
    OversizedSparse,
    Corrupt,
    HoldOpen,
    LiveMeasuredTestFloor,
    SymlinkOutput,
    HardlinkedOutput,
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Mutation {
    None,
    DestinationCollision,
    ReceiptCollision,
    SubstituteQuarantine,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WarmSeed {
    #[serde(serialize_with = "serialize_bound")]
    acceptance: Bound,
    #[serde(serialize_with = "serialize_bound")]
    result: Bound,
    path: PathBuf,
    identity: Identity,
    digests: Digests,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSpec {
    schema: String,
    case_id: String,
    root: PathBuf,
    root_identity: DirectoryIdentity,
    warm_seed: WarmSeed,
    transport: Transport,
    mutation: Mutation,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    schema: String,
    case_id: String,
    root: PathBuf,
    root_identity: DirectoryIdentity,
    cache_identity: DirectoryIdentity,
    state_identity: DirectoryIdentity,
    source_identity: Identity,
    source_digests: Digests,
    #[serde(serialize_with = "serialize_bound")]
    history: Bound,
    #[serde(serialize_with = "serialize_bound")]
    reference_policy: Bound,
    #[serde(serialize_with = "serialize_bound")]
    test_binary: Bound,
    #[serde(serialize_with = "serialize_bound")]
    engine_lineage: Bound,
    #[serde(serialize_with = "serialize_bound")]
    gcloud: Bound,
    warm_seed: WarmSeed,
    attempt_prefix: String,
    transport: Transport,
    mutation: Mutation,
    maximum_fixture_bytes: u64,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Action {
    PrepareWarmSession,
    Check,
    CheckAndEvict,
    Evict,
    Restore,
    RestoreRecover,
    VerifyRestored,
    WrongCheckHash,
    WrongRecoverySession,
    ValidatePredecessor,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ExpectedRejection {
    TransferExit,
    Timeout,
    InitialMeasuredTestFloor,
    LiveMeasuredTestFloor,
    StagingBound,
    WrongSize,
    DigestMismatch,
    UnsafeStage,
    DestinationCollision,
    ReceiptCollision,
    QuarantineSubstitution,
    CheckHash,
    RecoveryAuthority,
}
impl ExpectedRejection {
    fn matches(self, text: &str) -> bool {
        match self {
            Self::TransferExit => text.contains("exact-generation transfer failed"),
            Self::Timeout => text.contains("restore runtime exhausted"),
            Self::InitialMeasuredTestFloor => {
                text.contains("full restore does not fit above protected floor")
            }
            Self::LiveMeasuredTestFloor => text.contains("protected free-space floor crossed"),
            Self::StagingBound => text.contains("restore staging bound exceeded"),
            Self::WrongSize => text.contains("unsafe SDK output"),
            Self::DigestMismatch => text.contains("compressed generation digest mismatch"),
            Self::UnsafeStage => {
                text.contains("unsafe SDK staging member")
                    || text.contains("foreign temporary retained")
            }
            Self::DestinationCollision => {
                text.contains("publication boundary crossed")
                    || text.contains("destination appeared during transfer")
            }
            Self::ReceiptCollision => {
                text.contains("occupied receipt") || text.contains("conflicting lifecycle journal")
            }
            Self::QuarantineSubstitution => text.contains("substituted quarantine preserved"),
            Self::CheckHash => text.contains("mutable or mismatching evidence"),
            Self::RecoveryAuthority => [
                "predecessor",
                "prior phase",
                "prior actual-exit",
                "original PID1",
                "original live process",
                "prior process did not end",
                "consumer is live/restarted/triggered",
                "prior attempt was not created",
                "prior invocation",
                "mutable or mismatching evidence",
                "wrong predecessor",
            ]
            .iter()
            .any(|s| text.contains(s)),
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    schema: String,
    /// This existing strict envelope supplies the fresh actual-IID resource,
    /// lineage, fleet, owner, protected floor, isolated-root and output bindings.
    execution: EngineAdmission,
    action: Action,
    session: Option<Bound>,
    preparation: Option<Bound>,
    exit_after_phase: Option<String>,
    hold_after_phase: Option<String>,
    hold_seconds: u64,
    expected_rejection: Option<ExpectedRejection>,
    predecessor: Option<Bound>,
    /// Original restore creator; distinct from the latest recovery process.
    attempt_origin: Option<Bound>,
    actual_restore_runtime_seconds: u64,
    /// New restores choose a new suffix; recovery repeats the original attempt.
    attempt: String,
    measured_initial_test_floor_rejection: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Predecessor {
    schema: String,
    session: Bound,
    original_invocation_admission: Bound,
    actual_phase_witness: Bound,
    terminal_pid1_events: Bound,
    current_terminal_properties: BTreeMap<String, String>,
    expected_stage_identity: Option<DirectoryIdentity>,
}
struct Gate {
    bound: Bound,
    invocation: Invocation,
    profile: EngineProfile,
    start: Instant,
    start_identity: (u32, u64),
    before: Value,
}
fn bound_ref(p: &Path) -> Result<Bound> {
    let v = reference(p)?;
    Ok(Bound {
        path: p.into(),
        sha256: v["sha256"].as_str().context("bound hash")?.into(),
    })
}
fn phases() -> [Phase; 23] {
    [
        Phase::CheckDurable,
        Phase::EvictionIntentDurable,
        Phase::QuarantineRenameDurable,
        Phase::MovedProofDurable,
        Phase::UnlinkIntentDurable,
        Phase::UnlinkDurable,
        Phase::EvictedDurable,
        Phase::RestoreIntentDurable,
        Phase::RestoreStageDurable,
        Phase::RestoreStageOwnedDurable,
        Phase::RestoreChildSpawned,
        Phase::RestoreStageFrozen,
        Phase::RestorePayloadFrozen,
        Phase::RestorePublishIntentDurable,
        Phase::RestorePublishRenameDurable,
        Phase::RestoreReceiptDurable,
        Phase::RestoreStageCleaned,
        Phase::RestoreFailureIntentDurable,
        Phase::RestoreFailureStageCleaned,
        Phase::RestoreFailureCompletionDurable,
        Phase::RestoreRecoveryIntentDurable,
        Phase::RestoreRecoveryStageCleaned,
        Phase::RestoreRecoveryCompletionDurable,
    ]
}
fn phase_named(name: &str) -> Result<Phase> {
    phases()
        .into_iter()
        .find(|p| format!("{p:?}") == name)
        .context("unknown durable exit phase")
}
fn checked_root(path: &Path, identity: &DirectoryIdentity) -> Result<()> {
    ensure!(
        path.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && path.file_name().and_then(|p| p.to_str()).is_some_and(|s| s
                .starts_with("qualification-snapshot92447542-native-crash-")
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'))
            && path.canonicalize()? == path
            && DirectoryIdentity::of(&fs::symlink_metadata(path)?) == *identity
            && identity.uid == 1000
            && identity.gid == 1000
            && identity.mode & 0o7777 == 0o700,
        "invalid isolated crash root"
    );
    Ok(())
}
impl Gate {
    fn open() -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "explicit Root crash invocation required"
        );
        let bound = Bound {
            path: env::var_os("JETSTREAMER_SNAPSHOT92447542_CRASH_ADMISSION")
                .context("crash admission path required")?
                .into(),
            sha256: env::var("JETSTREAMER_SNAPSHOT92447542_CRASH_ADMISSION_SHA256")
                .context("crash admission hash required")?,
        };
        let invocation: Invocation = decode(&bound)?;
        let a = &invocation.execution;
        ensure!(
            invocation.schema == "jetstreamer-snapshot92447542-native-crash-invocation-v1"
                && a.schema == "jetstreamer-snapshot92447542-native-engine-admission-v1"
                && a.route == "persistent-native-session-invocation"
                && a.issued_unix_seconds <= now()?
                && now()? <= a.expires_unix_seconds
                && a.expires_unix_seconds > a.issued_unix_seconds
                && a.expires_unix_seconds - a.issued_unix_seconds <= 180
                && (60..=7200).contains(&a.maximum_run_seconds)
                && (1..=7200).contains(&invocation.actual_restore_runtime_seconds)
                && a.maximum_fixture_bytes == PEAK
                && a.protected_floor_bytes >= CENTURY_MINIMUM,
            "wrong or stale native crash admission"
        );
        if let Some(name) = &invocation.exit_after_phase {
            phase_named(name)?;
            ensure!(
                invocation.expected_rejection.is_none(),
                "exit and rejection outcomes cannot be conflated"
            );
        }
        if invocation.expected_rejection.is_some() {
            ensure!(
                invocation.exit_after_phase.is_none(),
                "rejection must not be reported as process exit"
            );
        }
        if let Some(name) = &invocation.hold_after_phase {
            phase_named(name)?;
            ensure!(
                invocation.exit_after_phase.is_none()
                    && invocation.expected_rejection.is_none()
                    && invocation.hold_seconds > 0
                    && invocation.hold_seconds <= a.maximum_run_seconds.saturating_sub(30),
                "live-owner hold is a separate finite admitted producer"
            );
        } else {
            ensure!(
                invocation.hold_seconds == 0,
                "hold seconds require an admitted hold phase"
            );
        }
        let actual = fs::canonicalize("/proc/self/exe")?;
        let (h, m) = evidence::hash_file(&actual, 256 << 20)?;
        ensure!(
            actual == a.test_binary.path
                && h == a.test_binary.sha256
                && m.uid() == 0
                && m.mode() & 0o222 == 0
                && Identity::of(&m) == Identity::of(&fs::metadata("/proc/self/exe")?),
            "wrong native crash image"
        );
        lineage(&a.engine_lineage, &a.test_binary.sha256)?;
        validate_fleet(a)?;
        let profile: EngineProfile = decode(&a.profile)?;
        let output = a.output.parent().context("output parent")?;
        private_dir(output)?;
        ensure!(
            a.output.file_name() == Some(std::ffi::OsStr::new("native-crash-result.json"))
                && absent(&a.output)?,
            "occupied or unsafe crash result"
        );
        checked_root(&a.fixture_root, &a.fixture_identity)?;
        let identity = stat(std::process::id())?;
        let before = native_service(&profile, identity, output, &a.fixture_root)?;
        ensure!(
            duration_seconds(&profile.expected_properties["RuntimeMaxUSec"])?
                == a.maximum_run_seconds,
            "runtime differs from native booking"
        );
        let hidden: BTreeSet<_> = profile
            .expected_properties
            .get("InaccessiblePaths")
            .context("original path projection missing")?
            .split_whitespace()
            .collect();
        ensure!(
            hidden == BTreeSet::from([CACHE_ROOT, STATE]),
            "original cache and state must remain inaccessible"
        );
        ensure!(
            fs::symlink_metadata(Path::new(CACHE_ROOT).join(NAME)).is_err(),
            "original payload visible to isolated crash case"
        );
        Ok(Self {
            bound,
            invocation,
            profile,
            start: Instant::now(),
            start_identity: identity,
            before,
        })
    }
    fn native(&self) -> Result<Value> {
        let a = &self.invocation.execution;
        checked_root(&a.fixture_root, &a.fixture_identity)?;
        ensure!(
            free_bytes(&a.fixture_root)? >= a.protected_floor_bytes,
            "campaign protected floor crossed during native case"
        );
        ensure!(
            self.start.elapsed().as_secs() < a.maximum_run_seconds,
            "crash invocation runtime exhausted"
        );
        for p in &a.protected_owners {
            owner(&p.unit, &p.invocation_id, &p.exec_start)?;
        }
        native_service(
            &self.profile,
            self.start_identity,
            a.output.parent().context("output parent")?,
            &a.fixture_root,
        )
    }
    fn result_parent(&self) -> Result<&Path> {
        self.invocation
            .execution
            .output
            .parent()
            .context("result parent")
    }
}
fn warm_seed(seed: &WarmSeed) -> Result<()> {
    ensure!(
        seed.acceptance.sha256 == WARM_ACCEPTANCE_SHA && seed.path == Path::new(WARM_PATH),
        "unrecognized warm generation source"
    );
    let a: Value = decode(&seed.acceptance)?;
    let r: Value = decode(&seed.result)?;
    ensure!(
        a["schema"] == "horizon1045-genuine-isolated-fixed-generation-roundtrip-completion-v1"
            && a["Main_accepted_genuine_isolated_fixed_generation_shared_engine_roundtrip_only"]
                == true
            && a["proofs"]["result"]
                == json!({"path":seed.result.path,"sha256":seed.result.sha256})
            && a["isolated_warm_seed"] == json!(seed.path)
            && a["restored_identity"] == serde_json::to_value(&seed.identity)?
            && a["full_object_digests"] == serde_json::to_value(&seed.digests)?
            && r["schema"] == "jetstreamer-snapshot92447542-native-engine-roundtrip-v1"
            && r["uri"] == URI
            && r["generation"] == GENERATION
            && r["bytes"] == SIZE
            && r["shared_engine_check_evict_restore_passed"] == true
            && r["restored_identity"] == serde_json::to_value(&seed.identity)?
            && r["full_object_digests"] == serde_json::to_value(&seed.digests)?,
        "warm generation evidence chain differs"
    );
    validate_digests(&seed.digests, None)?;
    ensure!(
        seed.identity.uid == 0
            && seed.identity.gid == 0
            && seed.identity.mode & 0o7777 == 0o444
            && seed.identity.links == 1
            && seed.identity.length == SIZE
            && Identity::of(&fs::symlink_metadata(&seed.path)?) == seed.identity
            && seed.path.canonicalize()? == seed.path,
        "warm source inode or custody changed"
    );
    Ok(())
}
fn new_dir(path: &Path, uid: u32) -> Result<Directory> {
    ensure!(absent(path)?, "case directory already exists");
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let f = File::open(path)?;
    chown(&f, uid, uid)?;
    f.sync_all()?;
    File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Directory::open(path, &DirectoryIdentity::of(&f.metadata()?))
}
fn copy_generation(
    seed: &WarmSeed,
    target: &Path,
    uid: u32,
    mut guard: impl FnMut() -> Result<()>,
) -> Result<()> {
    warm_seed(seed)?;
    let source_parent = seed.path.parent().context("warm parent")?;
    let source = Directory::open(
        source_parent,
        &DirectoryIdentity::of(&fs::symlink_metadata(source_parent)?),
    )?;
    let mut input = source.open_file(NAME)?;
    ensure!(
        Identity::of(&input.metadata()?) == seed.identity,
        "opened warm seed differs"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    let mut buffer = vec![0; 4 << 20];
    let mut bytes = 0u64;
    loop {
        guard()?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).context("warm byte overflow")?;
        ensure!(bytes <= SIZE, "warm source grew");
        output.write_all(&buffer[..n])?;
    }
    ensure!(
        bytes == SIZE
            && Identity::of(&input.metadata()?) == seed.identity
            && Identity::of(&fs::symlink_metadata(&seed.path)?) == seed.identity,
        "warm source changed during streaming copy"
    );
    chown(&output, uid, uid)?;
    output.sync_all()?;
    File::open(target.parent().context("copy parent")?)?.sync_all()?;
    Ok(())
}
#[test]
fn actual_prepare_warm_generation_session() -> Result<()> {
    let g = Gate::open()?;
    ensure!(
        matches!(g.invocation.action, Action::PrepareWarmSession)
            && g.invocation.session.is_none()
            && g.invocation.exit_after_phase.is_none(),
        "not a warm-session preparation admission"
    );
    let spec: SessionSpec = decode(
        g.invocation
            .preparation
            .as_ref()
            .context("preparation spec missing")?,
    )?;
    let a = &g.invocation.execution;
    ensure!(
        spec.schema == "jetstreamer-snapshot92447542-native-crash-session-spec-v1"
            && spec.root == a.fixture_root
            && spec.root_identity == a.fixture_identity
            && spec.case_id.len() <= 48
            && !spec.case_id.is_empty()
            && spec
                .case_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && fs::read_dir(&spec.root)?.next().is_none(),
        "invalid or occupied crash session root"
    );
    warm_seed(&spec.warm_seed)?;
    ensure!(
        free_bytes(&spec.root)?
            >= a.protected_floor_bytes
                .checked_add(PEAK)
                .context("preparation reservation overflow")?,
        "warm case does not fit above protected floor"
    );
    let cache = new_dir(&spec.root.join("cache"), 1000)?;
    let state = new_dir(&spec.root.join("state"), 0)?;
    let worker_directory = spec.root.join("worker-capabilities");
    let _workers = new_dir(&worker_directory, 0)?;
    fs::set_permissions(&worker_directory, fs::Permissions::from_mode(0o755))?;
    File::open(&worker_directory)?.sync_all()?;
    File::open(&spec.root)?.sync_all()?;
    copy_generation(&spec.warm_seed, &cache.path.join(NAME), 1000, || {
        g.native()?;
        ensure!(
            free_bytes(&spec.root)? >= a.protected_floor_bytes,
            "warm copy floor crossed"
        );
        Ok(())
    })?;
    let (source, digests, _) = hash_at(
        &cache,
        NAME,
        None,
        Some(&spec.warm_seed.digests.sha256),
        || {
            g.native()?;
            Ok(())
        },
    )?;
    ensure!(
        source.uid == 1000 && source.gid == 1000 && source.mode & 0o7777 == 0o600,
        "prepared source custody differs"
    );
    let history_path = state.path.join("isolated-source-history.json");
    persist(
        &history_path,
        &json!({"schema":"jetstreamer-snapshot92447542-isolated-warm-source-history-v1","source":spec.warm_seed.path,"verified_warm_acceptance":{"path":spec.warm_seed.acceptance.path,"sha256":spec.warm_seed.acceptance.sha256},"uri":URI,"generation":GENERATION,"identity":source,"digests":digests,"preparation_admission":{"path":g.bound.path,"sha256":g.bound.sha256},"original_snapshot_body_read":false}),
    )?;
    let policy_path = state.path.join("isolated-reference-policy.json");
    persist(
        &policy_path,
        &json!({"schema":"jetstreamer-snapshot92447542-persistent-isolated-reference-policy-v1","root":spec.root,"source_identity":source,"case_id":spec.case_id,"scope":"this persistent isolated case and its separately admitted owned children; never production consumers"}),
    )?;
    let session = Session {
        schema: "jetstreamer-snapshot92447542-native-crash-session-v1".into(),
        case_id: spec.case_id.clone(),
        root: spec.root.clone(),
        root_identity: spec.root_identity,
        cache_identity: cache.identity,
        state_identity: state.identity,
        source_identity: source,
        source_digests: digests,
        history: bound_ref(&history_path)?,
        reference_policy: bound_ref(&policy_path)?,
        test_binary: Bound {
            path: a.test_binary.path.clone(),
            sha256: a.test_binary.sha256.clone(),
        },
        engine_lineage: Bound {
            path: a.engine_lineage.path.clone(),
            sha256: a.engine_lineage.sha256.clone(),
        },
        gcloud: Bound {
            path: a.gcloud.path.clone(),
            sha256: a.gcloud.sha256.clone(),
        },
        warm_seed: spec.warm_seed,
        attempt_prefix: format!("slot92447542-restore-crash-{}-", spec.case_id),
        transport: spec.transport,
        mutation: spec.mutation,
        maximum_fixture_bytes: PEAK,
    };
    g.native()?;
    persist(
        &a.output,
        &json!({"schema":"jetstreamer-snapshot92447542-prepared-crash-session-material-v1","admission":{"path":g.bound.path,"sha256":g.bound.sha256},"session_document":session,"session_still_requires_independent_Rust_sealing":true,"data_retirement_authorized":false,"lifecycle_qualification":false}),
    )?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCapability {
    schema: String,
    issued_unix_seconds: u64,
    start_before_unix_seconds: u64,
    run_until_unix_seconds: u64,
    session_sha256: String,
    #[serde(serialize_with = "serialize_bound")]
    test_binary: Bound,
    parent: Owner,
    parent_pid: u32,
    parent_start_ticks: u64,
    control_group: String,
    root: PathBuf,
    root_identity: DirectoryIdentity,
    stage: PathBuf,
    stage_identity: DirectoryIdentity,
    destination: PathBuf,
    warm_path: PathBuf,
    warm_identity: Identity,
    expected_sha256: String,
    transport: Transport,
    live_floor_fill_bytes: u64,
}
fn publish_worker_document(directory: &Path, name: &str, value: &Value) -> Result<Bound> {
    component(name)?;
    ensure!(
        directory.canonicalize()? == directory,
        "worker capability directory not canonical"
    );
    let m = fs::symlink_metadata(directory)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o7777 == 0o755,
        "unsafe public worker-capability directory"
    );
    let path = directory.join(name);
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    serde_json::to_writer(&mut temporary, value)?;
    temporary.write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&path)
        .map_err(|e| anyhow::anyhow!("worker capability collision: {e}"))?;
    File::open(directory)?.sync_all()?;
    bound_ref(&path)
}
fn worker_parent(cap: &WorkerCapability) -> Result<()> {
    ensure!(
        now()? <= cap.run_until_unix_seconds,
        "worker execution deadline reached"
    );
    ensure!(
        DirectoryIdentity::of(&fs::symlink_metadata(&cap.root)?) == cap.root_identity
            && DirectoryIdentity::of(&fs::symlink_metadata(&cap.stage)?) == cap.stage_identity,
        "worker root/stage replaced"
    );
    let p = status(cap.parent_pid)?;
    ids(&p, "Uid", 0)?;
    ids(&p, "Gid", 0)?;
    ensure!(
        stat(cap.parent_pid)?.1 == cap.parent_start_ticks
            && cgroup(cap.parent_pid)? == cap.control_group,
        "worker parent start/cgroup differs"
    );
    let actual = owner(
        &cap.parent.unit,
        &cap.parent.invocation_id,
        &cap.parent.exec_start,
    )?;
    ensure!(
        actual["MainPID"].as_str() == Some(cap.parent_pid.to_string().as_str()),
        "worker parent is not actual MainPID"
    );
    Ok(())
}
#[test]
fn admitted_native_transport_worker() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000,
        "native transport worker must run as UID1000"
    );
    let bound = Bound {
        path: env::var_os("JETSTREAMER_SNAPSHOT92447542_CRASH_WORKER_CAPABILITY")
            .context("worker capability path")?
            .into(),
        sha256: env::var("JETSTREAMER_SNAPSHOT92447542_CRASH_WORKER_CAPABILITY_SHA256")
            .context("worker capability hash")?,
    };
    let cap: WorkerCapability = decode(&bound)?;
    ensure!(
        cap.schema == "jetstreamer-snapshot92447542-native-owned-worker-capability-v1"
            && cap.issued_unix_seconds <= now()?
            && now()? <= cap.start_before_unix_seconds
            && cap.start_before_unix_seconds > cap.issued_unix_seconds
            && cap.start_before_unix_seconds - cap.issued_unix_seconds <= 180
            && cap.run_until_unix_seconds > now()?
            && cap.run_until_unix_seconds - cap.issued_unix_seconds <= 7200
            && is_sha(&cap.session_sha256)
            && cap.warm_path == Path::new(WARM_PATH)
            && cap.destination != cap.warm_path
            && cap.destination == cap.stage.join(NAME)
            && cap.stage.parent() == Some(cap.root.join("cache").as_path()),
        "wrong worker capability"
    );
    let pid = std::process::id();
    let s = status(pid)?;
    ids(&s, "Uid", 1000)?;
    ids(&s, "Gid", 1000)?;
    ensure!(
        s.get("Groups").is_some_and(String::is_empty)
            && capability(&s, "CapEff")? == 0
            && capability(&s, "CapPrm")? == 0
            && capability(&s, "CapAmb")? == 0
            && s.get("NoNewPrivs").map(String::as_str) == Some("1")
            && stat(pid)?.0 == pid
            && cgroup(pid)? == cap.control_group,
        "worker actual kernel envelope differs"
    );
    let actual = fs::canonicalize("/proc/self/exe")?;
    let (h, m) = evidence::hash_file(&actual, 256 << 20)?;
    ensure!(
        actual == cap.test_binary.path
            && h == cap.test_binary.sha256
            && m.uid() == 0
            && m.mode() & 0o222 == 0,
        "worker image differs"
    );
    worker_parent(&cap)?;
    let go_path = bound
        .path
        .parent()
        .context("worker grant parent")?
        .join(format!("go-{pid}.json"));
    let deadline = Instant::now() + Duration::from_secs(30);
    while absent(&go_path)? {
        ensure!(
            Instant::now() < deadline,
            "parent child-witness acknowledgement timed out"
        );
        worker_parent(&cap)?;
        thread::sleep(Duration::from_millis(10));
    }
    let go_bound = bound_ref(&go_path)?;
    let go: Value = decode(&go_bound)?;
    ensure!(
        go["schema"] == "jetstreamer-snapshot92447542-native-child-start-v1"
            && go["worker_capability_sha256"] == bound.sha256
            && go["session_sha256"] == cap.session_sha256
            && go["parent_pid"] == cap.parent_pid
            && go["parent_start_ticks"] == cap.parent_start_ticks
            && go["child_pid"] == pid
            && go["child_start_ticks"] == stat(pid)?.1,
        "parent acknowledged another child identity"
    );
    let owned_stage = Directory::open(&cap.stage, &cap.stage_identity)?;
    let component = component(NAME)?;
    let fd = unsafe {
        libc::openat(
            owned_stage.file.as_raw_fd(),
            component.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "owned worker no-clobber open failed: {}",
        std::io::Error::last_os_error()
    );
    let file = unsafe { File::from_raw_fd(fd) };
    match cap.transport {
        Transport::RealGcs => {
            bail!("real GCS uses the production SDK command, never the local worker")
        }
        Transport::NonzeroExit => {
            file.sync_all()?;
            std::process::exit(71)
        }
        Transport::Truncated => {
            let mut f = file;
            f.write_all(b"deliberate native truncation")?;
            f.sync_all()?;
        }
        Transport::OversizedSparse => {
            file.set_len(SIZE + SLACK + 1)?;
            file.sync_all()?;
            while now()? <= cap.run_until_unix_seconds {
                worker_parent(&cap)?;
                thread::sleep(Duration::from_millis(100));
            }
        }
        Transport::HoldOpen => {
            let mut f = file;
            f.write_all(b"native owned transfer holding stage FD")?;
            f.sync_all()?;
            while now()? <= cap.run_until_unix_seconds {
                worker_parent(&cap)?;
                thread::sleep(Duration::from_millis(100));
            }
        }
        Transport::SymlinkOutput => {
            drop(file);
            fs::remove_file(&cap.destination)?;
            std::os::unix::fs::symlink(&cap.warm_path, &cap.destination)?;
            File::open(&cap.stage)?.sync_all()?;
        }
        Transport::HardlinkedOutput => {
            drop(file);
            fs::remove_file(&cap.destination)?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&cap.destination)?;
            f.write_all(b"native owned hardlink refusal")?;
            f.sync_all()?;
            fs::hard_link(&cap.destination, cap.stage.join("owned-hardlink-alias"))?;
            File::open(&cap.stage)?.sync_all()?;
        }
        Transport::VerifiedWarmCopy | Transport::Corrupt | Transport::LiveMeasuredTestFloor => {
            let parent = cap.warm_path.parent().context("warm parent")?;
            let dir = Directory::open(
                parent,
                &DirectoryIdentity::of(&fs::symlink_metadata(parent)?),
            )?;
            let mut input = dir.open_file(NAME)?;
            ensure!(
                Identity::of(&input.metadata()?) == cap.warm_identity,
                "worker warm source differs"
            );
            let mut output = file;
            let mut copied = 0u64;
            let mut buffer = vec![0; 4 << 20];
            loop {
                worker_parent(&cap)?;
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                copied = copied
                    .checked_add(n as u64)
                    .context("worker size overflow")?;
                ensure!(copied <= SIZE, "warm source grew");
                output.write_all(&buffer[..n])?;
            }
            ensure!(
                copied == SIZE && Identity::of(&input.metadata()?) == cap.warm_identity,
                "worker warm source changed"
            );
            if cap.transport == Transport::Corrupt {
                use std::io::{Seek, SeekFrom};
                output.seek(SeekFrom::Start(SIZE / 2))?;
                output.write_all(b"NATIVE-INTENTIONAL-DIGEST-CORRUPTION")?;
            }
            if cap.transport == Transport::LiveMeasuredTestFloor {
                ensure!(
                    cap.live_floor_fill_bytes == SLACK + (4 << 20) + 1,
                    "unexpected physical test-floor fill budget"
                );
                let block = vec![0xa5; 1 << 20];
                let mut remaining = cap.live_floor_fill_bytes;
                while remaining > 0 {
                    worker_parent(&cap)?;
                    let n = remaining.min(block.len() as u64) as usize;
                    output.write_all(&block[..n])?;
                    remaining -= n as u64;
                    output.sync_data()?;
                }
            }
            output.sync_all()?;
            File::open(&cap.stage)?.sync_all()?;
            if cap.transport == Transport::LiveMeasuredTestFloor {
                while now()? <= cap.run_until_unix_seconds {
                    worker_parent(&cap)?;
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    Ok(())
}
fn verify_disposition(
    g: &Gate,
    session_bound: &Bound,
    current_stage: Option<&DirectoryIdentity>,
    bound: &Bound,
) -> Result<Value> {
    let p: Predecessor = decode(bound)?;
    ensure!(
        p.schema == "jetstreamer-snapshot92447542-native-session-predecessor-v1"
            && p.session.path == session_bound.path
            && p.session.sha256 == session_bound.sha256
            && p.expected_stage_identity.as_ref() == current_stage,
        "wrong predecessor session/stage binding"
    );
    let old: Invocation = decode(&p.original_invocation_admission)?;
    let old_session = old
        .session
        .as_ref()
        .context("predecessor has no persistent session")?;
    ensure!(
        old.schema == "jetstreamer-snapshot92447542-native-crash-invocation-v1"
            && old_session.path == session_bound.path
            && old_session.sha256 == session_bound.sha256
            && old.execution.test_binary.sha256 == g.invocation.execution.test_binary.sha256
            && old.execution.engine_lineage.sha256 == g.invocation.execution.engine_lineage.sha256,
        "predecessor invocation authority differs"
    );
    let op: EngineProfile = decode(&old.execution.profile)?;
    ensure!(
        op.invocation_id != g.profile.invocation_id,
        "new invocation impersonates prior owner"
    );
    let witness: Value = decode(&p.actual_phase_witness)?;
    ensure!(
        witness["schema"] == "jetstreamer-snapshot92447542-native-process-phase-v1"
            && witness["session_sha256"] == session_bound.sha256
            && witness["actual_unit"] == op.unit
            && witness["actual_invocation_id"] == op.invocation_id
            && witness["admission_sha256"] == p.original_invocation_admission.sha256
            && witness["actual_main_pid"] == op.expected_properties["MainPID"].parse::<u32>()?,
        "prior phase does not bind the original live process"
    );
    let expected_status = if let Some(exit_phase) = old
        .exit_after_phase
        .as_ref()
        .or(old.hold_after_phase.as_ref())
    {
        ensure!(
            witness["will_exit_code"] == EXIT_CODE && witness["phase"] == exit_phase.as_str(),
            "prior actual-exit phase differs"
        );
        EXIT_CODE.to_string()
    } else {
        "0".into()
    };
    let current = || -> Result<BTreeMap<String, String>> {
        let actual = evidence::properties(
            &op.unit,
            &p.current_terminal_properties
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(","),
        )?;
        ensure!(
            actual == p.current_terminal_properties,
            "prior terminal envelope changed"
        );
        terminal_values(&op.unit, &actual)?;
        ensure!(
            actual.get("Restart").map(String::as_str) == Some("no")
                && actual.get("ExecMainStatus") == Some(&expected_status),
            "prior process did not end with its admitted outcome"
        );
        Ok(actual)
    };
    let before = current()?;
    let raw = root_bound_file(&p.terminal_pid1_events, 4 << 20, true)?;
    let rows: Vec<Value> = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        !rows.is_empty()
            && rows.iter().all(|r| r["_PID"] == "1"
                && r["UNIT"] == op.unit
                && r["INVOCATION_ID"] == op.invocation_id)
            && rows.iter().any(|r| matches!(
                r["CODE_FUNC"].as_str(),
                Some("unit_log_failure" | "unit_log_success")
            )),
        "original PID1 evidence does not prove this process ended"
    );
    ensure!(
        current()? == before,
        "prior owner raced during closure validation"
    );
    g.native()?;
    Ok(
        json!({"predecessor_disposition":{"path":bound.path,"sha256":bound.sha256},"original_admission":{"path":p.original_invocation_admission.path,"sha256":p.original_invocation_admission.sha256},"actual_phase":{"path":p.actual_phase_witness.path,"sha256":p.actual_phase_witness.sha256},"original_owner":{"unit":op.unit,"invocation_id":op.invocation_id,"exec_start":op.expected_properties["ExecStart"]},"terminal_properties":before,"terminal_pid1_events":{"path":p.terminal_pid1_events.path,"sha256":p.terminal_pid1_events.sha256},"scope":"positive original process-terminal/PID1 and exact fresh current-owner proof; no absent-PID shortcut"}),
    )
}

fn verify_predecessor(
    g: &Gate,
    session: &Bound,
    stage: Option<&DirectoryIdentity>,
) -> Result<Value> {
    verify_disposition(
        g,
        session,
        stage,
        g.invocation
            .predecessor
            .as_ref()
            .context("fresh predecessor disposition required")?,
    )
}

fn stage_identity_for(cache: &Path, attempt: &str) -> Result<Option<DirectoryIdentity>> {
    if attempt.is_empty() {
        return Ok(None);
    }
    match fs::symlink_metadata(cache.join(format!(".{attempt}"))) {
        Ok(m) => Ok(Some(DirectoryIdentity::of(&m))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct StageHandle {
    pid: u32,
    start_ticks: u64,
    descriptor: u32,
    path: PathBuf,
    identity: Identity,
    flags: u64,
}

fn descriptor_flags(path: &Path) -> Result<u64> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take((16 << 10) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16 << 10, "oversized SDK descriptor info");
    let text = std::str::from_utf8(&bytes)?;
    let rows: Vec<_> = text
        .lines()
        .filter_map(|s| s.strip_prefix("flags:"))
        .collect();
    ensure!(rows.len() == 1, "ambiguous SDK descriptor flags");
    Ok(u64::from_str_radix(rows[0].trim(), 8)?)
}

// Inspect only /proc descriptor metadata; never duplicate or read the download.
// The caller separately authenticates the live SDK/group and the admitted stage.
fn stage_handle(pid: u32, descriptor: u32, stage: &Directory) -> Result<Option<StageHandle>> {
    stage.validate()?;
    let before = stat(pid)?;
    let path = PathBuf::from(format!("/proc/{pid}/fd/{descriptor}"));
    let target = fs::read_link(&path)?;
    if target.parent() != Some(stage.path.as_path())
        || !matches!(target.file_name().and_then(|s| s.to_str()), Some(s) if s == NAME || s == format!("{NAME}_.gstmp"))
    {
        return Ok(None);
    }
    let flags = descriptor_flags(&PathBuf::from(format!("/proc/{pid}/fdinfo/{descriptor}")))?;
    if !matches!(
        flags as i32 & libc::O_ACCMODE,
        libc::O_WRONLY | libc::O_RDWR
    ) {
        return Ok(None);
    }
    let opened = fs::metadata(&path)?;
    let named = fs::symlink_metadata(&target)?;
    let same_inode = |m: &fs::Metadata| {
        m.is_file()
            && m.dev() == stage.identity.device
            && m.ino() == opened.ino()
            && m.uid() == stage.identity.uid
            && m.gid() == stage.identity.gid
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() > 0
            && m.len() <= SIZE + SLACK
    };
    ensure!(
        same_inode(&opened) && same_inode(&named),
        "unsafe SDK stage handle"
    );
    ensure!(stat(pid)? == before, "SDK descriptor owner changed");
    stage.validate()?;
    Ok(Some(StageHandle {
        pid,
        start_ticks: before.1,
        descriptor,
        path: target,
        identity: Identity::of(&opened),
        flags,
    }))
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct SdkGroupMember {
    pid: u32,
    start_ticks: u64,
    thread_ids: Vec<u32>,
}

// An unreaped Child retains its original PGID authority. Never stop a group
// identified only by an old numeric PID or by a previously persisted witness.
fn live_owned_leader(child: &OwnedSdk, group: &str) -> Result<u32> {
    let pid = child.0.as_ref().context("SDK already reaped")?.id();
    ensure!(
        pid > 1
            && pid != std::process::id()
            && unsafe { libc::getpgrp() } != pid as i32
            && !child.exited()?
            && stat(pid)?.0 == pid
            && cgroup(pid)? == group,
        "SDK group no longer belongs to the live unreaped child"
    );
    Ok(pid)
}

fn sdk_group(pid: u32, group: &str, stopped: bool) -> Result<Vec<SdkGroupMember>> {
    let mut members = Vec::new();
    let mut processes = 0usize;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(candidate) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        processes += 1;
        ensure!(processes <= 8192, "SDK process census bound exceeded");
        let identity = match stat(candidate) {
            Ok(v) => v,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue
            }
            Err(e) => return Err(e),
        };
        if identity.0 != pid {
            continue;
        }
        ensure!(
            cgroup(candidate)? == group,
            "foreign member joined owned SDK group"
        );
        let mut tids = Vec::new();
        for task in fs::read_dir(format!("/proc/{candidate}/task"))? {
            let task = task?;
            let tid = task
                .file_name()
                .to_str()
                .context("SDK thread name")?
                .parse::<u32>()?;
            if stopped {
                let s = status(tid)?;
                ensure!(
                    s.get("State").is_some_and(|s| s.starts_with('T'))
                        && s.get("TracerPid").map(String::as_str) == Some("0"),
                    "SDK thread has not stopped"
                );
            }
            tids.push(tid);
            ensure!(tids.len() <= 512, "SDK thread census bound exceeded");
        }
        tids.sort_unstable();
        ensure!(
            !tids.is_empty() && stat(candidate)? == identity,
            "SDK member changed during census"
        );
        members.push(SdkGroupMember {
            pid: candidate,
            start_ticks: identity.1,
            thread_ids: tids,
        });
        ensure!(members.len() <= 128, "SDK group census bound exceeded");
    }
    members.sort_by_key(|p| p.pid);
    ensure!(
        members.iter().any(|p| p.pid == pid),
        "SDK leader absent from its owned group"
    );
    Ok(members)
}

fn validate_sdk_members(members: &[SdkGroupMember]) -> Result<()> {
    for member in members {
        let s = status(member.pid)?;
        ids(&s, "Uid", 1000)?;
        ids(&s, "Gid", 1000)?;
        ensure!(
            s.get("Groups").is_some_and(String::is_empty)
                && capability(&s, "CapEff")? == 0
                && capability(&s, "CapPrm")? == 0
                && capability(&s, "CapAmb")? == 0
                && s.get("NoNewPrivs").map(String::as_str) == Some("1")
                && s.get("TracerPid").map(String::as_str) == Some("0")
                && stat(member.pid)?.1 == member.start_ticks,
            "SDK stage writer kernel identity differs"
        );
    }
    Ok(())
}

fn stop_owned_sdk_group(child: &OwnedSdk, group: &str) -> Result<Vec<SdkGroupMember>> {
    let pid = live_owned_leader(child, group)?;
    ensure!(
        unsafe { libc::kill(-(pid as i32), libc::SIGSTOP) } == 0,
        "cannot stop the owned SDK group"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        live_owned_leader(child, group)?;
        let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
        ensure!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    &mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                )
            } == 0,
            "owned SDK stop waitid failed"
        );
        if unsafe { info.si_pid() } != pid
            || info.si_code != libc::CLD_STOPPED
            || unsafe { info.si_status() } != libc::SIGSTOP
        {
            ensure!(
                Instant::now() < deadline,
                "owned SDK SIGSTOP completion not observed"
            );
            thread::sleep(Duration::from_millis(5));
            continue;
        }
        match sdk_group(pid, group, true) {
            Ok(members) => return Ok(members),
            Err(e)
                if e.to_string() == "SDK thread has not stopped" && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => return Err(e),
        }
    }
}

struct HeldSdkStage {
    leader: u32,
    group: Vec<SdkGroupMember>,
    handle: StageHandle,
    stage: PathBuf,
    stage_identity: DirectoryIdentity,
}

struct CaseEnvironment<'a> {
    gate: &'a Gate,
    session: &'a Session,
    session_bound: &'a Bound,
    cache: Directory,
    state: Directory,
    object: ObjectSpec,
    bindings: Bindings,
    phase_counter: Cell<u32>,
    phases: RefCell<Vec<String>>,
    children: RefCell<Vec<Value>>,
    case_floor: Cell<Option<u64>>,
    observation_counter: Cell<u32>,
    mutation_applied: Cell<bool>,
    held_sdk_stage: RefCell<Option<HeldSdkStage>>,
}
impl CaseEnvironment<'_> {
    fn held_stage_witness(&self) -> Result<Option<Value>> {
        let binding = self
            .held_sdk_stage
            .borrow()
            .as_ref()
            .map(|held| (held.stage.clone(), held.stage_identity.clone()));
        let Some((path, identity)) = binding else {
            return Ok(None);
        };
        let stage = Directory::open(&path, &identity)?;
        Ok(Some(self.validate_held_sdk_stage(&stage)?))
    }

    fn validate_held_sdk_stage(&self, stage: &Directory) -> Result<Value> {
        let held = self.held_sdk_stage.borrow();
        let held = held
            .as_ref()
            .context("actual held SDK stage handle missing")?;
        ensure!(
            stage.path == held.stage && stage.identity == held.stage_identity,
            "held SDK stage binding changed"
        );
        let current = sdk_group(held.leader, &self.gate.profile.control_group, true)?;
        ensure!(current == held.group, "stopped SDK membership changed");
        validate_sdk_members(&current)?;
        let handle = stage_handle(held.handle.pid, held.handle.descriptor, stage)?
            .context("SDK stage descriptor closed before actual parent exit")?;
        ensure!(handle == held.handle, "held SDK stage descriptor changed");
        Ok(
            json!({"schema":"jetstreamer-snapshot92447542-held-real-sdk-stage-v1",
            "session_sha256":self.session_bound.sha256,"admission_sha256":self.gate.bound.sha256,
            "actual_unit":self.gate.profile.unit,"actual_invocation_id":self.gate.profile.invocation_id,
            "actual_parent_pid":std::process::id(),"stage":held.stage,"stage_identity":held.stage_identity,
            "transport":"real-gcs","owned_unreaped_leader":held.leader,
            "leader_stop_waitid_confirmed":true,"leader_stop_signal":"SIGSTOP",
            "stopped_group_members":current,"actual_writable_stage_descriptor":handle,
            "descriptor_body_read_or_duplicated":false,"resume_before_parent_exit":false}),
        )
    }

    fn hold_sdk_stage_for_exit(&self, child: &OwnedSdk, stage: &Directory) -> Result<()> {
        ensure!(
            self.session.transport == Transport::RealGcs,
            "SDK handle-at-death case requires real-gcs transport"
        );
        ensure!(
            self.gate.invocation.actual_restore_runtime_seconds >= 90,
            "SDK handle wait requires a ninety-second restore budget"
        );
        let group = &self.gate.profile.control_group;
        let pid = live_owned_leader(child, group)?;
        let start = stat(pid)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let (writer, fd) = loop {
            self.native()?;
            ensure!(
                live_owned_leader(child, group)? == pid && stat(pid)? == start,
                "SDK leader changed before stage handle"
            );
            ensure!(
                Instant::now() < deadline,
                "real SDK writable stage handle was not reached"
            );
            ensure!(
                free_bytes(&stage.path)?
                    >= self.case_floor.get().context("restore booking missing")?,
                "protected free-space floor crossed while awaiting SDK handle"
            );
            ensure!(
                staged_bytes(stage)? <= SIZE + SLACK,
                "restore staging bound exceeded while awaiting SDK handle"
            );
            let members = sdk_group(pid, group, false)?;
            validate_sdk_members(&members)?;
            let mut found = None;
            for member in members {
                let mut descriptors = 0;
                for entry in fs::read_dir(format!("/proc/{}/fd", member.pid))? {
                    let entry = entry?;
                    let fd = entry
                        .file_name()
                        .to_str()
                        .context("SDK descriptor name")?
                        .parse::<u32>()?;
                    descriptors += 1;
                    ensure!(descriptors <= 4096, "SDK descriptor census bound exceeded");
                    match stage_handle(member.pid, fd, stage) {
                        Ok(Some(_)) => {
                            found = Some((member.pid, fd));
                            break;
                        }
                        Ok(None) => (),
                        Err(e)
                            if e.downcast_ref::<std::io::Error>()
                                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                        {
                            ()
                        }
                        Err(e) => return Err(e),
                    }
                }
                if found.is_some() {
                    break;
                }
            }
            if let Some(found) = found {
                break found;
            }
            thread::sleep(Duration::from_millis(20));
        };
        let members = stop_owned_sdk_group(child, group)?;
        validate_sdk_members(&members)?;
        let handle = stage_handle(writer, fd, stage)?
            .context("SDK stage handle closed before group stopped")?;
        ensure!(
            members
                .iter()
                .any(|m| m.pid == writer && m.start_ticks == handle.start_ticks),
            "stage writer escaped the stopped SDK group"
        );
        self.held_sdk_stage.replace(Some(HeldSdkStage {
            leader: pid,
            group: members,
            handle,
            stage: stage.path.clone(),
            stage_identity: stage.identity.clone(),
        }));
        // No SIGCONT: the verified writer and its open descriptor remain stopped
        // through exit197. OwnedSdk Drop kills/reaps on any failed gate instead.
        let witness = self.validate_held_sdk_stage(stage)?;
        persist(
            &self
                .gate
                .result_parent()?
                .join("actual-held-sdk-stage.json"),
            &witness,
        )?;
        Ok(())
    }

    fn native(&self) -> Result<Value> {
        let profile = self.gate.native()?;
        self.cache.validate()?;
        self.state.validate()?;
        ensure!(
            self.object.is_fixed_generation() && self.session.maximum_fixture_bytes == PEAK,
            "fixture object cannot satisfy an actual generation crash case"
        );
        let mut queue = vec![(self.session.root.clone(), 0u32)];
        let mut entries = 0u32;
        let mut physical = 0u64;
        while let Some((path, depth)) = queue.pop() {
            entries += 1;
            ensure!(
                entries <= 256 && depth <= 6,
                "native case tree bound exceeded"
            );
            let m = fs::symlink_metadata(&path)?;
            ensure!(
                m.dev() == self.session.root_identity.device
                    && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
                "foreign case tree entry"
            );
            physical = physical
                .checked_add(m.blocks().checked_mul(512).context("case block overflow")?)
                .context("case size overflow")?;
            ensure!(
                physical <= PEAK,
                "native case exceeded physical reservation"
            );
            if m.is_dir() {
                for child in fs::read_dir(path)? {
                    queue.push((child?.path(), depth + 1));
                }
            }
        }
        warm_seed(&self.session.warm_seed)?;
        Ok(profile)
    }
    fn observe_space(&self, path: &Path) -> Result<u64> {
        let available = free_bytes(path)?;
        let index = self.observation_counter.get();
        self.observation_counter
            .set(index.checked_add(1).context("space observation overflow")?);
        let crossed = self.case_floor.get().is_some_and(|floor| available < floor);
        if index < 4 || crossed {
            let name = if crossed {
                "actual-test-floor-crossed.json".to_owned()
            } else {
                format!("actual-space-{index:03}.json")
            };
            let output = self.gate.result_parent()?.join(name);
            if absent(&output)? {
                persist(
                    &output,
                    &json!({"schema":"jetstreamer-snapshot92447542-actual-native-statvfs-v1","session_sha256":self.session_bound.sha256,"actual_unit":self.gate.profile.unit,"actual_invocation_id":self.gate.profile.invocation_id,"path":path,"measured_available_bytes":available,"admitted_campaign_protected_floor_bytes":self.gate.invocation.execution.protected_floor_bytes,"deliberate_test_floor_bytes":self.case_floor.get(),"test_floor_crossed":crossed,"measurement":"actual-statvfs; not an injected or modeled observation","sampled_unix_seconds":now()?}),
                )?;
            }
        }
        Ok(available)
    }
    fn apply_mutation(&self, phase: Phase) -> Result<()> {
        if self.mutation_applied.get() {
            return Ok(());
        }
        let mutation = &self.session.mutation;
        match mutation {
            Mutation::None => (),
            Mutation::DestinationCollision if phase == Phase::RestorePublishIntentDurable => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(self.cache.path.join(NAME))?;
                f.write_all(b"owned-native-case foreign-destination collision sentinel")?;
                f.sync_all()?;
                self.cache.sync()?;
                self.mutation_applied.set(true);
            }
            Mutation::ReceiptCollision if phase == Phase::RestorePublishIntentDurable => {
                persist(
                    &self.state.path.join(state_name("restored")),
                    &json!({"schema":"native-owned-receipt-collision-sentinel-v1","session_sha256":self.session_bound.sha256,"not_a_restore_receipt":true}),
                )?;
                self.mutation_applied.set(true);
            }
            Mutation::SubstituteQuarantine if phase == Phase::QuarantineRenameDurable => {
                let q = format!("{PREFIX}-quarantine");
                rename_noreplace(
                    &self.state,
                    &q,
                    &self.state,
                    "native-preserved-owned-original",
                )?;
                copy_generation(
                    &self.session.warm_seed,
                    &self.state.path.join(&q),
                    1000,
                    || {
                        self.native()?;
                        Ok(())
                    },
                )?;
                self.mutation_applied.set(true);
            }
            _ => (),
        }
        Ok(())
    }
}
impl Environment for CaseEnvironment<'_> {
    fn cache(&self) -> &Directory {
        &self.cache
    }
    fn state(&self) -> &Directory {
        &self.state
    }
    fn source_identity(&self) -> &Identity {
        &self.session.source_identity
    }
    fn bindings(&self) -> &Bindings {
        &self.bindings
    }
    fn object(&self) -> &ObjectSpec {
        &self.object
    }
    fn available_bytes(&self, p: &Path) -> Result<u64> {
        self.observe_space(p)
    }
    fn history(&self) -> Result<Value> {
        let v: Value = decode(&self.session.history)?;
        ensure!(
            v["schema"] == "jetstreamer-snapshot92447542-isolated-warm-source-history-v1"
                && v["uri"] == URI
                && v["generation"] == GENERATION
                && v["identity"] == serde_json::to_value(&self.session.source_identity)?
                && v["digests"] == serde_json::to_value(&self.session.source_digests)?,
            "persistent source history differs"
        );
        Ok(v)
    }
    fn consumers(&self) -> Result<Value> {
        self.native()?;
        let p: Value = decode(&self.session.reference_policy)?;
        ensure!(
            p["schema"] == "jetstreamer-snapshot92447542-persistent-isolated-reference-policy-v1"
                && p["root"] == json!(self.session.root)
                && p["source_identity"] == serde_json::to_value(&self.session.source_identity)?,
            "persistent reference policy differs"
        );
        let scan = process_references::scan(Path::new("/proc"), &self.session.root)?;
        let aliases = inode_references(
            Path::new("/proc"),
            self.session.source_identity.device,
            self.session.source_identity.inode,
        )?;
        ensure!(
            scan.references.is_empty() && aliases.is_empty(),
            "isolated case has a live path or inode reader"
        );
        Ok(
            json!({"consumers":[],"scope":"persistent-isolated-full-generation-only; not production consumers","path_scan":scan,"inode_aliases":aliases,"policy_sha256":self.session.reference_policy.sha256}),
        )
    }
    fn metadata(&self) -> Result<Vec<u8>> {
        let mut first = None;
        let bytes = metadata_core(&self.session.gcloud, |pid, point| {
            match point {
                SdkWitnessPoint::Spawned => {
                    child_witness(pid, &self.gate.profile.control_group)?;
                    first = Some((pid, stat(pid)?));
                }
                SdkWitnessPoint::BeforeReap => {
                    let s = status(pid)?;
                    ids(&s, "Uid", 1000)?;
                    ids(&s, "Gid", 1000)?;
                    ensure!(
                        first == Some((pid, stat(pid)?)),
                        "metadata child start identity changed"
                    );
                }
            }
            Ok(())
        })?;
        shutdown_witness(first.context("metadata child absent")?.0)?;
        Ok(bytes)
    }
    fn restore_request(&self) -> Option<RestoreRequest> {
        match self.gate.invocation.action {
            Action::Restore
            | Action::RestoreRecover
            | Action::VerifyRestored
            | Action::WrongRecoverySession => Some(RestoreRequest {
                attempt: self.gate.invocation.attempt.clone(),
                maximum_runtime_seconds: self.gate.invocation.actual_restore_runtime_seconds,
                admission_sha256: self.gate.bound.sha256.clone(),
            }),
            _ => None,
        }
    }
    fn restore_admission(&self, verified: &str) -> Result<Booking> {
        self.native()?;
        ensure!(
            verified == self.session.source_digests.sha256,
            "verified generation digest changed"
        );
        let protected = self.gate.invocation.execution.protected_floor_bytes;
        let floor = if self.gate.invocation.measured_initial_test_floor_rejection {
            self.observe_space(&self.cache.path)?
                .checked_add(1)
                .context("initial test floor overflow")?
        } else if self.session.transport == Transport::LiveMeasuredTestFloor {
            let actual = self.observe_space(&self.cache.path)?;
            let reserve = SIZE
                .checked_add(SLACK)
                .and_then(|v| v.checked_add(4 << 20))
                .context("test-floor reserve overflow")?;
            let floor = actual
                .checked_sub(reserve)
                .context("test-floor reservation does not fit")?;
            ensure!(
                floor >= protected,
                "live test floor would weaken the campaign protected floor"
            );
            floor
        } else {
            protected
        };
        self.case_floor.set(Some(floor));
        persist(
            &self
                .gate
                .result_parent()?
                .join("restore-booking-observation.json"),
            &json!({"schema":"jetstreamer-snapshot92447542-native-actual-restore-booking-v1","session_sha256":self.session_bound.sha256,"current_admission_sha256":self.gate.bound.sha256,"campaign_protected_floor_bytes":protected,"actual_shared_engine_floor_bytes":floor,"measured_test_floor":floor!=protected,"synthetic_observation":false}),
        )?;
        Ok(Booking {
            protected_floor_bytes: floor,
            owner: Owner {
                unit: self.gate.profile.unit.clone(),
                invocation_id: self.gate.profile.invocation_id.clone(),
                exec_start: self.gate.profile.expected_properties["ExecStart"].clone(),
            },
            protected_owners: self.gate.invocation.execution.protected_owners.clone(),
        })
    }
    fn guard_owners(&self, _: &Booking) -> Result<()> {
        self.native()?;
        Ok(())
    }
    fn spawn_download(&self, destination: &Path) -> Result<OwnedSdk> {
        self.native()?;
        let stage = self
            .cache
            .path
            .join(format!(".{}", self.gate.invocation.attempt));
        ensure!(
            destination == stage.join(NAME),
            "native transport escaped admitted attempt"
        );
        let mut worker_grant: Option<Bound> = None;
        let mut command = if self.session.transport == Transport::RealGcs {
            let mut c = sdk_command(&self.session.gcloud)?;
            c.args([
                "storage",
                "cp",
                "--no-clobber",
                "--quiet",
                "--account=sam.johnson@anza.xyz",
                "--billing-project=principal-lane-200702",
                URI,
            ])
            .arg(destination);
            c
        } else {
            let token_directory = self.session.root.join("worker-capabilities");
            let stage_identity = DirectoryIdentity::of(&fs::symlink_metadata(&stage)?);
            let capability = WorkerCapability {
                schema: "jetstreamer-snapshot92447542-native-owned-worker-capability-v1".into(),
                issued_unix_seconds: now()?,
                start_before_unix_seconds: now()? + 180,
                run_until_unix_seconds: self.gate.invocation.execution.issued_unix_seconds
                    + self.gate.invocation.execution.maximum_run_seconds,
                session_sha256: self.session_bound.sha256.clone(),
                test_binary: Bound {
                    path: self.session.test_binary.path.clone(),
                    sha256: self.session.test_binary.sha256.clone(),
                },
                parent: Owner {
                    unit: self.gate.profile.unit.clone(),
                    invocation_id: self.gate.profile.invocation_id.clone(),
                    exec_start: self.gate.profile.expected_properties["ExecStart"].clone(),
                },
                parent_pid: std::process::id(),
                parent_start_ticks: self.gate.start_identity.1,
                control_group: self.gate.profile.control_group.clone(),
                root: self.session.root.clone(),
                root_identity: self.session.root_identity.clone(),
                stage: stage.clone(),
                stage_identity,
                destination: destination.into(),
                warm_path: self.session.warm_seed.path.clone(),
                warm_identity: self.session.warm_seed.identity.clone(),
                expected_sha256: self.session.source_digests.sha256.clone(),
                transport: self.session.transport.clone(),
                live_floor_fill_bytes: SLACK + (4 << 20) + 1,
            };
            let bound = publish_worker_document(
                &token_directory,
                &format!("worker-{}.json", now()?),
                &serde_json::to_value(&capability)?,
            )?;
            worker_grant = Some(Bound {
                path: bound.path.clone(),
                sha256: bound.sha256.clone(),
            });
            let mut c = Command::new(&self.session.test_binary.path);
            c.env_clear().env("PATH","/usr/bin:/bin").env("JETSTREAMER_SNAPSHOT92447542_CRASH_WORKER_CAPABILITY",&bound.path).env("JETSTREAMER_SNAPSHOT92447542_CRASH_WORKER_CAPABILITY_SHA256",&bound.sha256)
                .args(["--exact","snapshot92447542_cache::native_engine::process_crash::admitted_native_transport_worker","--test-threads=1"])
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            unsafe {
                c.pre_exec(|| {
                    if libc::setpgid(0, 0) != 0
                        || libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setgid(1000) != 0
                        || libc::setuid(1000) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            c
        };
        let owned = OwnedSdk(Some(command.spawn()?));
        let pid = owned.0.as_ref().context("owned native child")?.id();
        let witness = child_witness(pid, &self.gate.profile.control_group)?;
        if let Some(grant) = &worker_grant {
            publish_worker_document(
                grant.path.parent().context("worker grant parent")?,
                &format!("go-{pid}.json"),
                &json!({"schema":"jetstreamer-snapshot92447542-native-child-start-v1","worker_capability_sha256":grant.sha256,"session_sha256":self.session_bound.sha256,"parent_pid":std::process::id(),"parent_start_ticks":self.gate.start_identity.1,"child_pid":pid,"child_start_ticks":witness["start_ticks"]}),
            )?;
        }
        self.children.borrow_mut().push(witness.clone());
        persist(
            &self
                .gate
                .result_parent()?
                .join(format!("actual-transfer-child-{pid}.json")),
            &json!({"schema":"jetstreamer-snapshot92447542-native-transfer-child-v1","session_sha256":self.session_bound.sha256,"parent_invocation_id":self.gate.profile.invocation_id,"transport":self.session.transport,"actual_child":witness,"fresh_GCS_body_transfer":self.session.transport==Transport::RealGcs,"verified_warm_generation_transfer":self.session.transport==Transport::VerifiedWarmCopy}),
        )?;
        if self.gate.invocation.exit_after_phase.as_deref() == Some("RestoreChildSpawned")
            || self.gate.invocation.hold_after_phase.as_deref() == Some("RestoreChildSpawned")
        {
            let stage_identity = DirectoryIdentity::of(&fs::symlink_metadata(&stage)?);
            let stage_directory = Directory::open(&stage, &stage_identity)?;
            self.hold_sdk_stage_for_exit(&owned, &stage_directory)?;
        }
        Ok(owned)
    }
    fn after_phase(&self, phase: Phase) -> Result<()> {
        self.native()?;
        let index = self.phase_counter.get();
        self.phase_counter
            .set(index.checked_add(1).context("phase counter overflow")?);
        let name = format!("{phase:?}");
        self.phases.borrow_mut().push(name.clone());
        let exits = self.gate.invocation.exit_after_phase.as_deref() == Some(name.as_str());
        let stage_identity = stage_identity_for(&self.cache.path, &self.gate.invocation.attempt)?;
        let held_stage = self.held_stage_witness()?;
        if phase == Phase::RestoreChildSpawned
            && (exits || self.gate.invocation.hold_after_phase.as_deref() == Some(name.as_str()))
        {
            ensure!(
                held_stage.is_some(),
                "actual SDK handle missing at requested death phase"
            );
        }
        persist(
            &self
                .gate
                .result_parent()?
                .join(format!("phase-{index:03}.json")),
            &json!({"schema":"jetstreamer-snapshot92447542-native-process-phase-v1","session_sha256":self.session_bound.sha256,"admission_sha256":self.gate.bound.sha256,"actual_unit":self.gate.profile.unit,"actual_invocation_id":self.gate.profile.invocation_id,"actual_main_pid":std::process::id(),"actual_start_identity":self.gate.start_identity,"phase":name,"owned_transfer_children":*self.children.borrow(),"stage_identity":stage_identity,"held_real_sdk_stage":held_stage,"elapsed_millis":self.gate.start.elapsed().as_millis(),"will_exit_code":if exits||self.gate.invocation.hold_after_phase.as_deref()==Some(name.as_str()){Some(EXIT_CODE)}else{None},"will_hold_live_owner":self.gate.invocation.hold_after_phase.as_deref()==Some(name.as_str()),"ordinary_modeled_interruption":false,"lifecycle_qualification":false}),
        )?;
        if exits {
            self.held_stage_witness()?;
            std::process::exit(EXIT_CODE);
        }
        if self.gate.invocation.hold_after_phase.as_deref() == Some(name.as_str()) {
            ensure!(
                self.gate
                    .start
                    .elapsed()
                    .as_secs()
                    .checked_add(self.gate.invocation.hold_seconds)
                    .and_then(|n| n.checked_add(5))
                    .is_some_and(|n| n < self.gate.invocation.execution.maximum_run_seconds),
                "live-owner hold does not fit admitted runtime"
            );
            let until = Instant::now() + Duration::from_secs(self.gate.invocation.hold_seconds);
            while Instant::now() < until {
                self.gate.native()?;
                self.held_stage_witness()?;
                thread::sleep(Duration::from_millis(200));
            }
            self.held_stage_witness()?;
            std::process::exit(EXIT_CODE);
        }
        self.apply_mutation(phase)
    }
    fn authorize_recovery(
        &self,
        prior: &Value,
        stage: Option<&DirectoryIdentity>,
    ) -> Result<Value> {
        self.native()?;
        ensure!(
            prior["native_session_sha256"] == self.session_bound.sha256
                && prior["self_sha256"] == self.session.test_binary.sha256,
            "prior attempt belongs to another persistent session/image"
        );
        let immediate = verify_predecessor(self.gate, self.session_bound, stage)?;
        let original_bound = self
            .gate
            .invocation
            .attempt_origin
            .as_ref()
            .or(self.gate.invocation.predecessor.as_ref())
            .context("original attempt creator disposition required")?;
        let origin = verify_disposition(self.gate, self.session_bound, stage, original_bound)?;
        ensure!(
            origin["original_owner"] == prior["original_owner"]
                && origin["original_admission"]["sha256"] == prior["admission_sha256"],
            "prior attempt was not created by that actual process/admission"
        );
        Ok(
            json!({"original_attempt_creator":origin,"immediately_previous_invocation":immediate,"fresh_current_invocation":{"unit":self.gate.profile.unit,"invocation_id":self.gate.profile.invocation_id,"MainPID":std::process::id()},"persistent_session_sha256":self.session_bound.sha256}),
        )
    }
}
fn case_environment<'a>(g: &'a Gate, s: &'a Session, b: &'a Bound) -> Result<CaseEnvironment<'a>> {
    let a = &g.invocation.execution;
    ensure!(
        s.schema == "jetstreamer-snapshot92447542-native-crash-session-v1"
            && s.root == a.fixture_root
            && s.root_identity == a.fixture_identity
            && s.maximum_fixture_bytes == PEAK
            && s.test_binary.path == a.test_binary.path
            && s.test_binary.sha256 == a.test_binary.sha256
            && s.engine_lineage.path == a.engine_lineage.path
            && s.engine_lineage.sha256 == a.engine_lineage.sha256
            && s.gcloud.path == a.gcloud.path
            && s.gcloud.sha256 == a.gcloud.sha256
            && s.attempt_prefix == format!("slot92447542-restore-crash-{}-", s.case_id),
        "persistent native authority differs from fresh invocation"
    );
    if g.invocation.exit_after_phase.as_deref() == Some("RestoreChildSpawned")
        || g.invocation.hold_after_phase.as_deref() == Some("RestoreChildSpawned")
    {
        ensure!(
            s.transport == Transport::RealGcs && g.invocation.actual_restore_runtime_seconds >= 90,
            "SDK handle-at-death requires real-gcs transport and a ninety-second restore budget"
        );
    }
    if !g.invocation.attempt.is_empty() {
        ensure!(
            g.invocation.attempt.starts_with(&s.attempt_prefix)
                && g.invocation.attempt.len() <= 100
                && g.invocation
                    .attempt
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "attempt escaped persistent session prefix"
        );
    }
    if matches!(
        g.invocation.action,
        Action::Restore
            | Action::RestoreRecover
            | Action::VerifyRestored
            | Action::WrongRecoverySession
    ) {
        ensure!(
            !g.invocation.attempt.is_empty(),
            "restore/recovery attempt required"
        );
    }
    validate_digests(&s.source_digests, Some(&s.warm_seed.digests.sha256))?;
    let cache = Directory::open(&s.root.join("cache"), &s.cache_identity)?;
    let state = Directory::open(&s.root.join("state"), &s.state_identity)?;
    ensure!(
        s.history.path == state.path.join("isolated-source-history.json")
            && s.reference_policy.path == state.path.join("isolated-reference-policy.json"),
        "session evidence escaped private case state"
    );
    let e = CaseEnvironment {
        gate: g,
        session: s,
        session_bound: b,
        cache,
        state,
        object: ObjectSpec::fixed_generation(),
        bindings: Bindings::isolated(
            &b.sha256,
            &s.test_binary.sha256,
            &s.reference_policy.sha256,
            &s.engine_lineage.sha256,
        )?,
        phase_counter: Cell::new(0),
        phases: RefCell::new(vec![]),
        children: RefCell::new(vec![]),
        case_floor: Cell::new(None),
        observation_counter: Cell::new(0),
        mutation_applied: Cell::new(false),
        held_sdk_stage: RefCell::new(None),
    };
    e.native()?;
    e.history()?;
    Ok(e)
}
fn actual_check(e: &CaseEnvironment<'_>) -> Result<String> {
    let b = bound_ref(&e.state.path.join(state_name("check")))?;
    let value: Value = decode(&b)?;
    ensure!(
        value["schema"] == "jetstreamer-snapshot92447542-isolated-check-v1"
            && value["native_session_sha256"] == e.session_bound.sha256
            && value["self_sha256"] == e.session.test_binary.sha256
            && value["source_identity"] == serde_json::to_value(&e.session.source_identity)?,
        "stored check is not this real persistent operation"
    );
    let d: Digests = serde_json::from_value(value["digests"].clone())?;
    validate_digests(&d, Some(&e.session.source_digests.sha256))?;
    Ok(b.sha256)
}
fn payload_enrollment(e: &CaseEnvironment<'_>) -> Result<BTreeMap<String, Value>> {
    let mut output = BTreeMap::new();
    let mut pending = vec![(e.session.root.clone(), 0u32)];
    let mut count = 0u32;
    while let Some((path, depth)) = pending.pop() {
        count += 1;
        ensure!(
            count <= 256 && depth <= 6,
            "payload enrollment bound exceeded"
        );
        let m = fs::symlink_metadata(&path)?;
        if m.is_dir() {
            output.insert(
                path.to_string_lossy().into_owned(),
                serde_json::to_value(DirectoryIdentity::of(&m))?,
            );
            for child in fs::read_dir(path)? {
                pending.push((child?.path(), depth + 1));
            }
        } else if path.extension() != Some(std::ffi::OsStr::new("json"))
            && path.file_name() != Some(std::ffi::OsStr::new("retirement.lock"))
        {
            let target = if m.file_type().is_symlink() {
                Some(fs::read_link(&path)?)
            } else {
                None
            };
            output.insert(
                path.to_string_lossy().into_owned(),
                json!({"identity":Identity::of(&m),"symlink_target":target}),
            );
        }
    }
    Ok(output)
}
fn assert_rejection_state(e: &CaseEnvironment<'_>, expected: ExpectedRejection) -> Result<()> {
    let stage = e.cache.path.join(format!(".{}", e.gate.invocation.attempt));
    let restored = e.state.path.join(state_name("restored"));
    match expected {
        ExpectedRejection::TransferExit
        | ExpectedRejection::Timeout
        | ExpectedRejection::LiveMeasuredTestFloor
        | ExpectedRejection::StagingBound
        | ExpectedRejection::WrongSize
        | ExpectedRejection::DigestMismatch => {
            ensure!(
                e.cache.absent(NAME)? && absent(&restored)? && absent(&stage)?,
                "failed transfer published data or retained an owned stage"
            );
            let completion = load(&e.state.path.join(format!(
                "{}-failure-completion.json",
                e.gate.invocation.attempt
            )))?;
            ensure!(
                completion["schema"]
                    == "jetstreamer-snapshot92447542-isolated-restore-failure-cleaned-v1"
                    && completion["owned_temporary_absent"] == true,
                "full shared failure completion missing"
            );
            if matches!(expected, ExpectedRejection::LiveMeasuredTestFloor) {
                let crossing = load(
                    &e.gate
                        .result_parent()?
                        .join("actual-test-floor-crossed.json"),
                )?;
                ensure!(
                    crossing["test_floor_crossed"] == true
                        && crossing["measured_available_bytes"]
                            .as_u64()
                            .context("actual available missing")?
                            < crossing["deliberate_test_floor_bytes"]
                                .as_u64()
                                .context("test floor missing")?,
                    "measured live test-floor crossing was not observed"
                );
            }
        }
        ExpectedRejection::InitialMeasuredTestFloor => ensure!(
            e.cache.absent(NAME)?
                && absent(&restored)?
                && absent(&stage)?
                && e.children.borrow().is_empty()
                && absent(
                    &e.state
                        .path
                        .join(format!("{}-intent.json", e.gate.invocation.attempt))
                )?,
            "initial measured floor refusal started transport or an attempt"
        ),
        ExpectedRejection::UnsafeStage => ensure!(
            !absent(&stage)?
                && e.cache.absent(NAME)?
                && absent(&restored)?
                && absent(&e.state.path.join(format!(
                    "{}-failure-completion.json",
                    e.gate.invocation.attempt
                )))?,
            "unsafe stage was not preserved"
        ),
        ExpectedRejection::DestinationCollision => ensure!(
            fs::read(e.cache.path.join(NAME))?
                == b"owned-native-case foreign-destination collision sentinel"
                && !absent(&stage)?
                && absent(&restored)?,
            "foreign destination or owned unpublished stage was lost"
        ),
        ExpectedRejection::ReceiptCollision => {
            let r = load(&restored)?;
            ensure!(
                r["schema"] == "native-owned-receipt-collision-sentinel-v1"
                    && r["session_sha256"] == e.session_bound.sha256
                    && !e.cache.absent(NAME)?
                    && !absent(&stage)?,
                "foreign receipt or committed payload was lost"
            );
            hash_at(
                &e.cache,
                NAME,
                None,
                Some(&e.session.source_digests.sha256),
                || {
                    e.native()?;
                    Ok(())
                },
            )?;
        }
        ExpectedRejection::QuarantineSubstitution => ensure!(
            !e.state.absent(&format!("{PREFIX}-quarantine"))?
                && !e.state.absent("native-preserved-owned-original")?
                && absent(&e.state.path.join(state_name("evicted")))?,
            "quarantine substitution removed an original or foreign inode"
        ),
        ExpectedRejection::CheckHash => ensure!(
            Identity::of(&fs::symlink_metadata(e.cache.path.join(NAME))?)
                == e.session.source_identity
                && absent(&e.state.path.join(state_name("eviction-intent")))?,
            "wrong check hash mutated the source"
        ),
        ExpectedRejection::RecoveryAuthority => (),
    }
    Ok(())
}
#[test]
fn actual_process_exit_or_native_case() -> Result<()> {
    let g = Gate::open()?;
    ensure!(
        !matches!(g.invocation.action, Action::PrepareWarmSession)
            && g.invocation.preparation.is_none(),
        "preparation is a separate admitted action"
    );
    let bound = g
        .invocation
        .session
        .as_ref()
        .context("persistent sealed session required")?;
    let session: Session = decode(bound)?;
    let e = case_environment(&g, &session, bound)?;
    if g.invocation.predecessor.is_some()
        && !matches!(
            g.invocation.action,
            Action::RestoreRecover | Action::WrongRecoverySession | Action::ValidatePredecessor
        )
    {
        let identity = stage_identity_for(&e.cache.path, &g.invocation.attempt)?;
        verify_predecessor(&g, bound, identity.as_ref())?;
    }
    let before_payload = if matches!(
        g.invocation.expected_rejection,
        Some(ExpectedRejection::RecoveryAuthority | ExpectedRejection::CheckHash)
    ) {
        Some(payload_enrollment(&e)?)
    } else {
        None
    };
    let attempt = (|| -> Result<()> {
        match g.invocation.action {
            Action::PrepareWarmSession => bail!("wrong selected test"),
            Action::ValidatePredecessor => {
                let identity = stage_identity_for(&e.cache.path, &g.invocation.attempt)?;
                verify_predecessor(&g, bound, identity.as_ref())?;
                Ok(())
            }
            Action::Check => core::run_check(&e),
            Action::CheckAndEvict => {
                core::run_check(&e)?;
                let h = actual_check(&e)?;
                core::run_evict(&e, &h)
            }
            Action::Evict => {
                let h = actual_check(&e)?;
                core::run_evict(&e, &h)
            }
            Action::Restore => {
                let h = actual_check(&e)?;
                core::run_restore(&e, &h)
            }
            Action::RestoreRecover => {
                let h = actual_check(&e)?;
                core::run_recover_restore(&e, &h)
            }
            Action::WrongCheckHash => {
                let actual = actual_check(&e)?;
                let wrong = if actual != "0".repeat(64) {
                    "0".repeat(64)
                } else {
                    "1".repeat(64)
                };
                core::run_evict(&e, &wrong)
            }
            Action::WrongRecoverySession => {
                let h = actual_check(&e)?;
                let prior = load(
                    &e.state
                        .path
                        .join(format!("{}-intent.json", g.invocation.attempt)),
                )?;
                ensure!(
                    prior["native_session_sha256"] == bound.sha256,
                    "baseline prior session invalid"
                );
                core::run_recover_restore(&e, &h)
            }
            Action::VerifyRestored => {
                let receipt = load(&e.state.path.join(state_name("restored")))?;
                let actual = Identity::of(&fs::symlink_metadata(e.cache.path.join(NAME))?);
                ensure!(
                    receipt["schema"] == "jetstreamer-snapshot92447542-isolated-restored-v1"
                        && receipt["native_session_sha256"] == bound.sha256
                        && receipt["new_identity"] == serde_json::to_value(&actual)?
                        && receipt["digests"] == serde_json::to_value(&session.source_digests)?
                        && actual.uid == 0
                        && actual.gid == 0
                        && actual.mode & 0o7777 == 0o444
                        && actual.inode != session.source_identity.inode,
                    "actual restored object/receipt differs"
                );
                hash_at(
                    &e.cache,
                    NAME,
                    Some(&actual),
                    Some(&session.source_digests.sha256),
                    || {
                        e.native()?;
                        Ok(())
                    },
                )?;
                Ok(())
            }
        }
    })();
    if let Err(error) = &attempt {
        let message = format!("{error:#}");
        persist(
            &g.result_parent()?.join("native-operation-error.json"),
            &json!({"schema":"jetstreamer-snapshot92447542-native-operation-error-v1",
                "persistent_session":{"path":bound.path,"sha256":bound.sha256},
                "fresh_invocation_admission":{"path":g.bound.path,"sha256":g.bound.sha256},
                "actual_unit":g.profile.unit,"actual_invocation_id":g.profile.invocation_id,
                "actual_main_pid":std::process::id(),"operation_error":message,
                "requested_exit_phase":g.invocation.exit_after_phase,
                "expected_rejection":g.invocation.expected_rejection,
                "completed_phases":*e.phases.borrow(),"lifecycle_qualification":false}),
        )
        .with_context(|| format!("persist native diagnostic for original error: {message}"))?;
    }
    if let Some(phase) = &g.invocation.exit_after_phase {
        return match attempt {
            Err(error) => Err(error).with_context(|| {
                format!("native operation failed before actual exit phase {phase}")
            }),
            Ok(()) => bail!("requested actual process-exit frontier {phase} was not reached"),
        };
    }
    let error = match attempt {
        Ok(()) => {
            ensure!(
                g.invocation.expected_rejection.is_none(),
                "expected native rejection did not occur"
            );
            None
        }
        Err(err) => {
            let Some(expected) = g.invocation.expected_rejection.as_ref() else {
                return Err(err).context("unexpected native case failure");
            };
            let text = err.to_string();
            ensure!(
                expected.matches(&text),
                "native rejection occurred at a different gate: {text}"
            );
            Some(text)
        }
    };
    for child in e.children.borrow().iter() {
        let pid = child["pid"].as_u64().context("child PID")?;
        shutdown_witness(pid.try_into()?)?;
    }
    if let Some(expected) = g.invocation.expected_rejection {
        assert_rejection_state(&e, expected)?;
    }
    if let Some(before) = before_payload {
        ensure!(
            payload_enrollment(&e)? == before,
            "rejected authority/hash changed payload custody or inode enrollment"
        );
    }
    let after = e.native()?;
    ensure!(
        g.before["properties"] == after["properties"],
        "current native owner changed"
    );
    persist(
        &g.invocation.execution.output,
        &json!({"schema":"jetstreamer-snapshot92447542-native-process-case-result-v1","persistent_session":{"path":bound.path,"sha256":bound.sha256},"fresh_invocation_admission":{"path":g.bound.path,"sha256":g.bound.sha256},"actual_unit":g.profile.unit,"actual_invocation_id":g.profile.invocation_id,"actual_main_pid":std::process::id(),"normal_helper_lineage_sha256":session.engine_lineage.sha256,"native_harness_sha256":session.test_binary.sha256,"uri":URI,"generation":GENERATION,"source_bytes":SIZE,"source_digests":session.source_digests,"input":"genuine verified warm fixed-generation object; never a tiny fixture","transport":session.transport,"mutation":session.mutation,"expected_rejection_kind":g.invocation.expected_rejection,"expected_rejection_observed":error,"previous_invocation_disposition":g.invocation.predecessor.as_ref().map(|b|json!({"path":b.path,"sha256":b.sha256})),"original_attempt_disposition":g.invocation.attempt_origin.as_ref().map(|b|json!({"path":b.path,"sha256":b.sha256})),"phases":*e.phases.borrow(),"children":*e.children.borrow(),"before":g.before,"after":after,"actual_process_exit_this_invocation":false,"modeled_process_interruption":false,"modeled_space_observation":false,"original_cache_body_read":false,"lifecycle_qualification":false,"production_eviction_authorized":false}),
    )?;
    Ok(())
}

// Small kernel controls for the observer/stop primitives. They make no Session,
// fixed-generation, SDK-transfer, crash-frontier or lifecycle acceptance claim.
#[cfg(test)]
mod stage_handle_tests {
    use super::*;

    fn stage(path: &Path) -> Result<Directory> {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Directory::open(path, &DirectoryIdentity::of(&fs::symlink_metadata(path)?))
    }

    #[test]
    fn writable_descriptor_requires_the_exact_private_single_link_stage_file() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = stage(root.path())?;
        let destination = root.path().join(NAME);
        let mut writer = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&destination)?;
        writer.write_all(b"kernel observer control")?;
        writer.sync_all()?;
        let pid = std::process::id();
        let fd: u32 = writer.as_raw_fd().try_into()?;
        let observed =
            stage_handle(pid, fd, &directory)?.context("writable stage handle absent")?;
        assert_eq!(observed.identity.inode, writer.metadata()?.ino());
        let reader = File::open(&destination)?;
        assert!(stage_handle(pid, reader.as_raw_fd().try_into()?, &directory)?.is_none());
        let foreign = tempfile::tempdir()?;
        assert!(stage_handle(pid, fd, &stage(foreign.path())?)?.is_none());
        fs::hard_link(&destination, root.path().join("foreign-alias"))?;
        assert!(stage_handle(pid, fd, &directory).is_err());
        fs::remove_file(root.path().join("foreign-alias"))?;
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))?;
        assert!(stage_handle(pid, fd, &directory).is_err());
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o600))?;
        drop(writer);
        assert!(stage_handle(pid, fd, &directory).is_err());
        Ok(())
    }

    fn owned_writer(destination: &Path) -> Result<OwnedSdk> {
        let mut command = Command::new("/usr/bin/bash");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args([
                "--noprofile",
                "--norc",
                "-c",
                "umask 077; exec 9>\"$1\"; printf 'kernel stage control' >&9; IFS= read -r held",
                "owned-kernel-stage-control",
            ])
            .arg(destination)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = OwnedSdk(Some(command.spawn()?));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            ensure!(!child.exited()?, "kernel stage control child exited early");
            if fs::metadata(destination).is_ok_and(|m| m.len() > 0) {
                return Ok(child);
            }
            ensure!(
                Instant::now() < deadline,
                "kernel stage control writer timed out"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn owned_group_stop_retains_the_descriptor_and_resume_invalidates_the_stop_proof() -> Result<()>
    {
        let root = tempfile::tempdir()?;
        let directory = stage(root.path())?;
        let mut child = owned_writer(&root.path().join(NAME))?;
        let group = cgroup(std::process::id())?;
        let pid = live_owned_leader(&child, &group)?;
        let members = stop_owned_sdk_group(&child, &group)?;
        let before =
            stage_handle(pid, 9, &directory)?.context("stopped writer descriptor absent")?;
        assert_eq!(sdk_group(pid, &group, true)?, members);
        assert_eq!(stage_handle(pid, 9, &directory)?.as_ref(), Some(&before));
        ensure!(
            unsafe { libc::kill(-(pid as i32), libc::SIGCONT) } == 0,
            "resume kernel control"
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while sdk_group(pid, &group, true).is_ok() {
            ensure!(
                Instant::now() < deadline,
                "resume did not invalidate stopped-thread proof"
            );
            thread::sleep(Duration::from_millis(5));
        }
        child.finish()?;
        assert!(stage_handle(pid, 9, &directory).is_err());
        assert!(live_owned_leader(&child, &group).is_err());
        Ok(())
    }

    #[test]
    fn foreign_group_and_replaced_stage_refuse_before_claiming_a_held_handle() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = stage(root.path())?;
        let child = owned_writer(&root.path().join(NAME))?;
        let group = cgroup(std::process::id())?;
        let pid = live_owned_leader(&child, &group)?;
        assert!(stop_owned_sdk_group(&child, "/foreign-control-group").is_err());
        assert!(!status(pid)?["State"].starts_with('T'));
        let parent = tempfile::tempdir()?;
        let moved = parent.path().join("preserved-stage");
        fs::rename(root.path(), &moved)?;
        fs::create_dir(root.path())?;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
        assert!(stage_handle(pid, 9, &directory).is_err());
        // Drop kills/reaps this still-unreaped owned group even on a refusal.
        drop(child);
        assert!(fs::metadata(format!("/proc/{pid}")).is_err());
        Ok(())
    }
}
