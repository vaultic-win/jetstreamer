//! Build-bound, private continuation of the exact independently verified epoch213 prefix.
//! No canonical sidecar, publication, retirement, or remote mutation is performed here.

use {
    super::*,
    jetstreamer_horizon::archive::{ArchiveProvenanceV4, merge_checkpoint_restart_segments},
    jetstreamer_node::{
        archive_checksum::{
            archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
        },
        segment_manifest::read_and_validate_segment_manifest_from,
    },
    serde_json::{Value as JsonValue, json},
    std::{
        fs::{File, OpenOptions},
        io::{BufReader, Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStrExt,
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            },
        },
    },
};

const EPOCH: u64 = 213;
const START: u64 = 92_016_000;
const RESTART: u64 = 92_447_542;
const END: u64 = 92_447_999;
const PREFIX_SHA: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
const MANIFEST_SHA: &str = "1d74158c418f67443837b01ae3d218ace43c1e9998e6a91c4d3ead6e2b5e0581";
const NATIVE_SHA: &str = "f8bc219d738598eeb96df1f8cef0aac8144d1b1330b2c2397a84d4754869e24e";
const SNAPSHOT_SHA: &str = "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08";
const WORKER_SHA: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const SNAPSHOT_SIZE: u64 = 8_894_131_881;
const PREFIX_SIZE: u64 = 125_316_500_795;
// Retain the sealed older-growth claims and century floor plus a distinct
// 384-GiB private restore/index/assembly budget. Fresh fleet admission remains
// independently required; this is not an automatic concurrency controller.
const MIN_INITIAL_FREE_BYTES: u64 = 3_391_836_623_574;
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    producer_unit: String,
    node_sha256: String,
    prefix_archive: Evidence,
    prefix_manifest: Evidence,
    native_probe: Evidence,
    restart_snapshot: Evidence,
    worker: Evidence,
    genesis_archive: Evidence,
    run_root: PathBuf,
    minimum_free_bytes: u64,
}

/// Only a complete independent prefix reread can construct this proof.
/// Its fields are private; ordinary replay call sites always pass None.
pub(crate) struct ValidatedPrefix {
    manifest: HistoricalSegmentManifest,
    snapshot: PathBuf,
}

/// Private proof implementations are constructible only by their exact,
/// independently validated epoch-specific diagnostic runners.
pub(crate) trait RestartProof: Sync {
    fn snapshot_sha256(&self) -> [u8; 32];
    fn snapshot_size(&self) -> u64;
    fn covers_trusted_root(&self, epoch: u64, bootstrap: u64, start: u64, end: u64) -> bool;
    fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        qualification: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String>;
    fn verify_native_checkpoint(
        &self,
        actual: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        initialized_cursor: u64,
        ticks_per_slot: u64,
    ) -> Result<(), String>;
}
impl RestartProof for ValidatedPrefix {
    fn snapshot_sha256(&self) -> [u8; 32] {
        ValidatedPrefix::snapshot_sha256(self)
    }
    fn snapshot_size(&self) -> u64 {
        ValidatedPrefix::snapshot_size(self)
    }
    fn covers_trusted_root(&self, e: u64, b: u64, s: u64, n: u64) -> bool {
        ValidatedPrefix::covers_trusted_root(self, e, b, s, n)
    }
    fn validate_invocation(
        &self,
        e: u64,
        b: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        c: bool,
        a: bool,
        r: bool,
    ) -> Result<(), String> {
        ValidatedPrefix::validate_invocation(self, e, b, q, c, a, r)
    }
    fn verify_native_checkpoint(
        &self,
        a: &historical::HistoricalCheckpoint,
        w: [u8; 32],
        _: u64,
        _: u64,
    ) -> Result<(), String> {
        ValidatedPrefix::verify_native_checkpoint(self, a, w)
    }
}

pub(super) fn require(ok: bool, message: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(message.into()) }
}

pub(super) fn sha(value: &str) -> Result<[u8; 32], String> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "digest must contain exactly 64 lowercase hexadecimal characters",
    )?;
    let mut result = [0; 32];
    for (i, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

pub(super) fn sealed_bytes(evidence: &Evidence, max: u64) -> Result<Vec<u8>, String> {
    require(
        evidence.path.is_absolute()
            && fs::canonicalize(&evidence.path).map_err(|e| e.to_string())? == evidence.path,
        "sealed evidence path must be absolute and canonical",
    )?;
    let mut file = open_regular_nofollow(&evidence.path).map_err(|e| e.to_string())?;
    let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= max,
        "evidence must be bounded, singly linked, root-owned and non-writable",
    )?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    require(
        bytes.len() as u64 == metadata.len()
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == sha(&evidence.sha256)?
            && archive_file_identity(&file).map_err(|e| e.to_string())? == identity
            && path_matches_archive_identity(&evidence.path, identity)
                .map_err(|e| e.to_string())?,
        "sealed evidence digest or identity changed",
    )?;
    Ok(bytes)
}

pub(crate) fn validate_cli(
    enabled: bool,
    epochs: (u64, u64),
    explicit_verify: Option<bool>,
    verify_count: usize,
    explicit_destination: bool,
    forbidden_override: bool,
) -> Result<(), String> {
    require(
        enabled,
        "checkpoint continuation requires its dedicated diagnostic build",
    )?;
    require(
        epochs == (EPOCH, EPOCH)
            && explicit_verify == Some(true)
            && verify_count == 1
            && explicit_destination
            && !forbidden_override,
        "checkpoint continuation requires only epoch213, one explicit --verify, an explicit private destination, and its plan/hash options",
    )
}

fn validate_plan(plan: &Plan, destination: &Path) -> Result<(), String> {
    require(
        plan.schema == "jetstreamer-private-epoch213-checkpoint-continuation-plan-v1"
            && plan.epoch == EPOCH,
        "continuation plan schema or epoch mismatch",
    )?;
    require(
        plan.producer_unit
            .starts_with("horizon-qualify-213-checkpoint-continuation-")
            && plan.producer_unit.ends_with(".service")
            && plan
                .producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && sha(&plan.node_sha256)? != [0; 32],
        "plan must bind an exact persistent continuation unit and node digest",
    )?;
    for (input, expected) in [
        (&plan.prefix_archive, PREFIX_SHA),
        (&plan.prefix_manifest, MANIFEST_SHA),
        (&plan.native_probe, NATIVE_SHA),
        (&plan.restart_snapshot, SNAPSHOT_SHA),
        (&plan.worker, WORKER_SHA),
        (&plan.genesis_archive, GENESIS_SHA),
    ] {
        require(
            input.sha256 == expected,
            "continuation input differs from the exact qualified artifact",
        )?;
    }
    let leaf = plan
        .run_root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    require(
        plan.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-213-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && destination == plan.run_root.join("ledger")
            && plan.minimum_free_bytes >= MIN_INITIAL_FREE_BYTES,
        "continuation needs an isolated private run root, exact ledger destination, and retained admission bound",
    )?;
    require(
        plan.restart_snapshot
            .path
            .file_name()
            .and_then(|s| s.to_str())
            == Some("snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst"),
        "restart snapshot filename mismatch",
    )?;
    require(
        plan.genesis_archive
            .path
            .file_name()
            .and_then(|s| s.to_str())
            == Some("genesis.tar.bz2"),
        "genesis archive filename mismatch",
    )?;
    for input in [
        &plan.prefix_archive,
        &plan.prefix_manifest,
        &plan.native_probe,
        &plan.restart_snapshot,
        &plan.worker,
        &plan.genesis_archive,
    ] {
        require(
            input.path.is_absolute() && !input.path.starts_with(&plan.run_root),
            "a retained input must be absolute and outside the new private run",
        )?;
    }
    Ok(())
}

pub(super) fn checkpoint_matches(
    expected: &SegmentCheckpointSummary,
    actual: &SegmentCheckpointSummary,
) -> Result<(), String> {
    require(
        expected.slot == actual.slot
            && expected.bank_hash == actual.bank_hash
            && expected.accounts_hash == actual.accounts_hash
            && expected.last_blockhash == actual.last_blockhash
            && expected.capitalization == actual.capitalization
            && expected.transaction_count == actual.transaction_count
            && expected.tick_height == actual.tick_height
            && expected.slot_complete
            && actual.slot_complete
            && actual.write_count == 0,
        "native restart checkpoint differs from the verified prefix terminal state",
    )
}

impl ValidatedPrefix {
    pub(crate) fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT_SHA).expect("literal digest")
    }
    pub(crate) fn snapshot_size(&self) -> u64 {
        SNAPSHOT_SIZE
    }
    pub(crate) fn covers_trusted_root(
        &self,
        epoch: u64,
        bootstrap: u64,
        output_start: u64,
        end: u64,
    ) -> bool {
        epoch == EPOCH
            && bootstrap == RESTART
            && output_start == RESTART + 1
            && end == END
            && self.manifest.epoch == EPOCH
            && self.manifest.output_slot_start == START
            && self.manifest.output_slot_count == RESTART - START + 1
            && self.manifest.bootstrap.slot == 92_015_419
            && self.manifest.terminal.slot == RESTART
            && self.manifest.archive_sha256 == sha(PREFIX_SHA).expect("literal digest")
            && self.manifest.worker_executable_sha256 == sha(WORKER_SHA).expect("literal digest")
            && self.manifest.bootstrap.slot < self.manifest.terminal.slot
    }
    pub(crate) fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        qualification: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        require(
            cfg!(feature = "epoch213-checkpoint-continuation-diagnostic")
                && !carried
                && !audited
                && !retain
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path())
                && qualification.is_some_and(|q| {
                    q.epoch == EPOCH
                        && q.bootstrap_slot == RESTART
                        && q.replay_start == RESTART + 1
                        && self.covers_trusted_root(
                            epoch,
                            q.bootstrap_slot,
                            q.output_slot_start,
                            q.end_inclusive,
                        )
                }),
            "checkpoint-restart proof cannot authorize another epoch, range, state source or runtime carry",
        )
    }
    pub(crate) fn verify_native_checkpoint(
        &self,
        actual: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
    ) -> Result<(), String> {
        require(
            worker == sha(WORKER_SHA)?,
            "continuation worker digest mismatch",
        )?;
        let summary = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(actual)?,
        );
        checkpoint_matches(&self.manifest.terminal, &summary)
    }
}

pub(super) fn available_bytes(path: &Path) -> Result<u64, String> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .ok_or("free-space arithmetic overflow".into())
}

pub(super) fn authenticate_service(unit: &str) -> Result<String, String> {
    let invocation = env::var("INVOCATION_ID")
        .map_err(|_| "continuation must run in its persistent systemd service")?;
    require(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid systemd invocation identity",
    )?;
    let output=std::process::Command::new("systemctl").args(["show",unit,
        "--property=InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,ActiveState,SubState"])
        .output().map_err(|e|e.to_string())?;
    require(
        output.status.success(),
        "cannot authenticate the continuation service",
    )?;
    let text = String::from_utf8(output.stdout).map_err(|e| e.to_string())?;
    validate_service_identity(&text, &invocation, std::process::id())?;
    Ok(invocation)
}

fn validate_service_identity(text: &str, invocation: &str, pid: u32) -> Result<(), String> {
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("malformed service identity")?;
        require(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate service identity field",
        )?;
    }
    let value = |key: &str| fields.get(key).map(String::as_str).unwrap_or("");
    require(
        value("InvocationID") == invocation
            && value("MainPID") == pid.to_string()
            && value("NRestarts") == "0"
            && value("Restart") == "no"
            && value("KillMode") == "control-group"
            && value("Delegate") == "no"
            && matches!(value("ActiveState"), "active" | "activating"),
        "continuation unit is not this exact zero-restart, non-restarting process",
    )?;
    Ok(())
}

pub(super) fn require_retained_input(path: &Path, expected_size: u64) -> Result<(), String> {
    require(
        path.is_absolute() && fs::canonicalize(path).map_err(|e| e.to_string())? == path,
        "retained archive path must be canonical",
    )?;
    let file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    require(
        metadata.nlink() == 1
            && metadata.len() == expected_size
            && metadata.mode() & 0o022 == 0
            && (metadata.uid() == 0 || metadata.uid() == unsafe { libc::geteuid() }),
        "retained archive ownership, link count, mode or size mismatch",
    )
}

pub(super) fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir(path)
        .and_then(|_| fs::set_permissions(path, fs::Permissions::from_mode(0o700)))
        .map_err(|e| format!("cannot create private directory {}: {e}", path.display()))
}

pub(super) fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    File::open(path.parent().ok_or("missing parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}

pub(super) fn require_no_checksum(path: &Path) -> Result<(), String> {
    let sidecar = jetstreamer_node::archive_checksum::archive_checksum_path(path)
        .map_err(|e| e.to_string())?;
    require(
        matches!(fs::symlink_metadata(sidecar), Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "a private continuation must remain canonical-sidecar-free",
    )
}

pub(super) fn runtime_checkpoint(
    summary: &SegmentCheckpointSummary,
) -> Result<RuntimeStateCheckpoint, String> {
    Ok(RuntimeStateCheckpoint {
        slot: summary.slot,
        bank_hash: summary
            .bank_hash
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: summary
            .accounts_hash
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        last_blockhash: summary
            .last_blockhash
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        capitalization: summary.capitalization,
        transaction_count: summary.transaction_count,
        tick_height: summary.tick_height,
        slot_complete: summary.slot_complete,
        next_write_version: summary.next_write_version,
    })
}

fn build_provenance(
    prefix: &HistoricalSegmentManifest,
    suffix: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenanceV4, String> {
    prefix.validate().map_err(|e| e.to_string())?;
    suffix.validate().map_err(|e| e.to_string())?;
    require(
        prefix.runtime.runtime_profile == "solana-v1.6.16"
            && prefix.runtime.runtime_revision == "86c26f843276581509c3434acc2efbf4202c44e0"
            && prefix.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH
            && prefix.epoch == EPOCH
            && prefix.output_slot_start == START
            && prefix.output_slot_end().map_err(|e| e.to_string())? == RESTART + 1
            && prefix.terminal.slot == RESTART
            && suffix.epoch == EPOCH
            && suffix.output_slot_start == RESTART + 1
            && suffix.output_slot_end().map_err(|e| e.to_string())? == END + 1
            && suffix.terminal.slot == END
            && suffix.bootstrap.slot == RESTART
            && suffix.bootstrap_archive_sha256 == Some(sha(SNAPSHOT_SHA)?)
            && prefix.archive_sha256 == sha(PREFIX_SHA)?
            && prefix.worker_executable_sha256 == sha(WORKER_SHA)?
            && suffix.worker_executable_sha256 == sha(WORKER_SHA)?
            && prefix.runtime.genesis_hash == suffix.runtime.genesis_hash
            && prefix.runtime.runtime_target == suffix.runtime.runtime_target,
        "continuation assembly source scope mismatch",
    )?;
    checkpoint_matches(&prefix.terminal, &suffix.bootstrap)?;
    let mut normalized_start = 0u64;
    let mut segments = Vec::new();
    for source in [prefix, suffix] {
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: normalized_start,
        };
        normalized_start = mapping
            .archive_end_exclusive()
            .ok_or("normalized write-version overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: source.output_slot_count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: match source.runtime.runtime_admission {
                SegmentRuntimeAdmission::Verified => RuntimeAdmission::Verified,
                SegmentRuntimeAdmission::Candidate => RuntimeAdmission::Candidate,
            },
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions: mapping,
        });
    }
    let value = ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: format!(
                "{}/checkpoint-continuation-v1",
                archive_generation_profile()
            ),
            genesis_hash: prefix
                .runtime
                .genesis_hash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: prefix.bootstrap.slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: prefix
                    .bootstrap
                    .accounts_hash
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
            },
            requested_slot_start: START,
            requested_slot_count: END - START + 1,
            transaction_metadata: archive_transaction_metadata_policy(START, END - START + 1),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: RESTART + 1,
                predecessor: runtime_checkpoint(&prefix.terminal)?,
                successor: runtime_checkpoint(&suffix.bootstrap)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: sha(SNAPSHOT_SHA)?,
                successor_bootstrap_write_count: suffix.bootstrap.write_count,
            }],
        },
    };
    value.validate().map_err(|e| e.to_string())?;
    Ok(value)
}

fn assemble(
    prefix_path: &Path,
    prefix: &HistoricalSegmentManifest,
    suffix_path: &Path,
    suffix: &HistoricalSegmentManifest,
    output: &Path,
) -> Result<JsonValue, String> {
    let provenance = build_provenance(prefix, suffix)?;
    assemble_sources(
        prefix_path,
        prefix,
        suffix_path,
        suffix,
        output,
        &provenance,
    )
}
pub(super) fn assemble_sources(
    prefix_path: &Path,
    prefix: &HistoricalSegmentManifest,
    suffix_path: &Path,
    suffix: &HistoricalSegmentManifest,
    output: &Path,
    provenance: &ArchiveProvenanceV4,
) -> Result<JsonValue, String> {
    let mut sources = Vec::new();
    let mut identities = Vec::new();
    for (path, manifest) in [(prefix_path, prefix), (suffix_path, suffix)] {
        let file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
        let measurement = file.try_clone().map_err(|e| e.to_string())?;
        let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
        identities.push((path.to_path_buf(), measurement, identity));
        sources.push(RuntimeSegmentSource::new(
            BufReader::new(file),
            manifest.archive_sha256,
            manifest
                .terminal
                .last_blockhash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
        ));
    }
    require_no_checksum(output)?;
    let sink = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)
        .map_err(|e| e.to_string())?;
    let (sink, stats) = merge_checkpoint_restart_segments(
        sources,
        sink,
        ArchiveWriterConfig::default(),
        provenance,
    )
    .map_err(|e| e.to_string())?;
    sink.sync_all().map_err(|e| e.to_string())?;
    drop(sink);
    for (path, file, identity) in identities {
        require(
            archive_file_identity(&file).map_err(|e| e.to_string())? == identity
                && path_matches_archive_identity(&path, identity).map_err(|e| e.to_string())?,
            "assembly source identity changed",
        )?;
    }
    File::open(output.parent().ok_or("missing output parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    require_no_checksum(output)?;
    Ok(
        json!({"source_archives":stats.source_archives,"slots_merged":stats.slots_merged,
        "account_updates_rebased":stats.account_updates_rebased,"provenance_version":4}),
    )
}

pub(crate) async fn run(
    plan_path: PathBuf,
    plan_sha: String,
    destination: PathBuf,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    restart_tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    require(
        cfg!(feature = "epoch213-checkpoint-continuation-diagnostic"),
        "private continuation build is required",
    )?;
    let bytes = sealed_bytes(
        &Evidence {
            path: plan_path.clone(),
            sha256: plan_sha.clone(),
        },
        1 << 20,
    )?;
    let plan: Plan = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    validate_plan(&plan, &destination)?;
    sealed_bytes(
        &Evidence {
            path: fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
            sha256: plan.node_sha256.clone(),
        },
        256 << 20,
    )?;
    let invocation = authenticate_service(&plan.producer_unit)?;
    require(
        unsafe { libc::geteuid() } != 0,
        "run continuation as the isolated replay user",
    )?;
    let metadata = fs::symlink_metadata(&plan.run_root).map_err(|e| e.to_string())?;
    require(
        fs::canonicalize(&plan.run_root).map_err(|e| e.to_string())? == plan.run_root
            && metadata.is_dir()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && fs::read_dir(&plan.run_root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none(),
        "private run root must be canonical, owner-only and empty",
    )?;
    let lease_path = Path::new(PRIVATE_ROOT).join("checkpoint-continuation-213.lock");
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lease_path)
        .map_err(|e| e.to_string())?;
    let lease_metadata = lease.metadata().map_err(|e| e.to_string())?;
    require(
        lease_metadata.is_file()
            && lease_metadata.nlink() == 1
            && lease_metadata.uid() == unsafe { libc::geteuid() }
            && lease_metadata.mode() & 0o077 == 0
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another private continuation holds the lease, or its lease identity is unsafe",
    )?;
    let allow_candidate = env_truthy_default("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", false);
    let selection = compatibility::select_runtime(START..END + 1, allow_candidate)?;
    require(
        selection.backend == compatibility::RuntimeBackend::SolanaV1_6_16
            && configured_historical_worker_executable(selection.descriptor)? == plan.worker.path,
        "ordinary registry or exact worker path differs from continuation plan",
    )?;
    sealed_bytes(&plan.worker, 256 << 20)?;
    sealed_bytes(&plan.prefix_manifest, 1 << 20)?;
    let native: JsonValue = serde_json::from_slice(&sealed_bytes(&plan.native_probe, 1 << 20)?)
        .map_err(|e| e.to_string())?;
    let genesis = sealed_bytes(&plan.genesis_archive, 10 << 20)?;
    require_retained_input(&plan.prefix_archive.path, PREFIX_SIZE)?;
    require_retained_input(&plan.restart_snapshot.path, SNAPSHOT_SIZE)?;
    let prefix_file =
        open_regular_nofollow(&plan.prefix_archive.path).map_err(|e| e.to_string())?;
    let prefix_identity = archive_file_identity(&prefix_file).map_err(|e| e.to_string())?;
    require(
        prefix_file.metadata().map_err(|e| e.to_string())?.len() == PREFIX_SIZE,
        "prefix length mismatch",
    )?;
    require_no_checksum(&plan.prefix_archive.path)?;
    require(
        available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "private continuation free-space admission failed",
    )?;
    let archive_path = plan.prefix_archive.path.clone();
    let manifest_path = plan.prefix_manifest.path.clone();
    info!("independently validating complete retained epoch213 prefix before continuation");
    let manifest = tokio::task::spawn_blocking(move || {
        read_and_validate_segment_manifest_from(archive_path, manifest_path)
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    require_no_checksum(&plan.prefix_archive.path)?;
    require(
        manifest.archive_sha256 == sha(PREFIX_SHA)?
            && manifest.worker_executable_sha256 == sha(WORKER_SHA)?
            && manifest.runtime.runtime_profile == "solana-v1.6.16"
            && manifest.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH
            && path_matches_archive_identity(&plan.prefix_archive.path, prefix_identity)
                .map_err(|e| e.to_string())?,
        "validated prefix identity or qualified runtime changed",
    )?;
    let validated = ValidatedPrefix {
        manifest,
        snapshot: plan.restart_snapshot.path.clone(),
    };
    require(
        validated.covers_trusted_root(EPOCH, RESTART, RESTART + 1, END),
        "prefix does not cover the required ordinary epoch root",
    )?;
    let previous_native: SegmentCheckpointSummary =
        serde_json::from_value(native["native_checkpoint"].clone()).map_err(|e| e.to_string())?;
    require(
        native["assessment"]["native_consensus_state_matches"] == true
            && native["assessment"]["replay_entries_sent"] == 0
            && native["worker"]["sha256"] == WORKER_SHA
            && native["snapshot"]["sha256"] == SNAPSHOT_SHA,
        "native probe does not bind the expected restart",
    )?;
    checkpoint_matches(&validated.manifest.terminal, &previous_native)?;
    require(
        !shutdown.load(Ordering::SeqCst),
        "continuation cancelled before worker launch",
    )?;
    require(
        available_bytes(&plan.run_root)? >= plan.minimum_free_bytes,
        "free-space admission changed during prefix reread",
    )?;
    for name in ["ledger", "scratch", "output", "receipts"] {
        create_private_dir(&plan.run_root.join(name))?;
    }
    write_new(&destination.join("genesis.tar.bz2"), &genesis)?;
    let suffix = plan.run_root.join("output/epoch-213-suffix.jet");
    let output = plan
        .run_root
        .join("output/epoch-213-checkpoint-restart-v4.jet");
    require_no_checksum(&suffix)?;
    let qualification = QualificationPlan {
        epoch: EPOCH,
        bootstrap_slot: RESTART,
        replay_start: RESTART + 1,
        output_slot_start: RESTART + 1,
        end_inclusive: END,
    };
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([(
            RESTART,
            BankHashExpectation::LegacyAccountsHash(
                validated
                    .manifest
                    .terminal
                    .accounts_hash
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
            ),
        )]),
        Some(shutdown.clone()),
    ));
    let result = run_geyser_replay(
        EPOCH,
        allow_candidate,
        &destination,
        &plan.run_root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(validated.snapshot.clone()),
        shutdown.clone(),
        cursor,
        restart_tracker,
        Some(verifier.clone()),
        suffix.clone(),
        Some(qualification),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&validated),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    require(
        !shutdown.load(Ordering::SeqCst),
        "continuation was interrupted",
    )?;
    verifier.finish()?;
    publish_historical_segment_manifest(EPOCH, qualification, &suffix, &result, allow_candidate)?;
    require_no_checksum(&suffix)?;
    let suffix_manifest = read_and_validate_segment_manifest(&suffix).map_err(|e| e.to_string())?;
    let stats = assemble(
        &plan.prefix_archive.path,
        &validated.manifest,
        &suffix,
        &suffix_manifest,
        &output,
    )?;
    require_no_checksum(&plan.prefix_archive.path)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-v1",
        "producer_unit":plan.producer_unit,"producer_invocation_id":invocation,"node_sha256":plan.node_sha256,
        "plan":{"path":plan_path,"sha256":plan_sha},"prefix_archive_sha256":PREFIX_SHA,
        "restart_snapshot_sha256":SNAPSHOT_SHA,"suffix_archive_sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&suffix_manifest.archive_sha256),
        "private_output":output,"assembly":stats,"fresh_prefix_full_validation_passed":true,
        "fresh_native_checkpoint_matches":true,"canonical_root_slot":RESTART,
        "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "initial_boundary_requires_separate_adjacent_evidence":true,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false});
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_new(&plan.run_root.join("receipts/continuation.json"), &bytes)?;
    info!(
        "private epoch213 checkpoint continuation assembled; independent final/plugin verification and publication gates remain closed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_identity_rejects_foreign_restarted_or_unsafe_units() {
        let invocation = "0123456789abcdef0123456789abcdef";
        let good = format!(
            "InvocationID={invocation}\nMainPID=123\nNRestarts=0\nRestart=no\nKillMode=control-group\nDelegate=no\nActiveState=active\nSubState=running\n"
        );
        validate_service_identity(&good, invocation, 123).unwrap();
        assert!(validate_service_identity(&good, invocation, 124).is_err());
        for (old, new) in [
            (invocation, "ffffffffffffffffffffffffffffffff"),
            ("NRestarts=0", "NRestarts=1"),
            ("Restart=no", "Restart=on-failure"),
            ("KillMode=control-group", "KillMode=process"),
            ("Delegate=no", "Delegate=yes"),
            ("ActiveState=active", "ActiveState=inactive"),
            ("MainPID=123\n", ""),
        ] {
            assert!(validate_service_identity(&good.replace(old, new), invocation, 123).is_err());
        }
        assert!(
            validate_service_identity(&(good.clone() + "NRestarts=0\n"), invocation, 123).is_err()
        );
        assert!(validate_service_identity(&(good + "malformed\n"), invocation, 123).is_err());
    }

    fn prefix() -> HistoricalSegmentManifest {
        serde_json::from_str(include_str!(
            "../tests/fixtures/epoch213-prefix-segment.json"
        ))
        .unwrap()
    }

    fn validated() -> ValidatedPrefix {
        ValidatedPrefix {
            manifest: prefix(),
            snapshot: PathBuf::from("/snapshot"),
        }
    }

    fn plan() -> Plan {
        let input = |name: &str, digest: &str| Evidence {
            path: PathBuf::from("/var/lib/jetstreamer/test").join(name),
            sha256: digest.into(),
        };
        Plan {
            schema: "jetstreamer-private-epoch213-checkpoint-continuation-plan-v1".into(),
            epoch: EPOCH,
            producer_unit: "horizon-qualify-213-checkpoint-continuation-test-v1.service".into(),
            node_sha256: "1".repeat(64),
            prefix_archive: input("prefix.jet", PREFIX_SHA),
            prefix_manifest: input("prefix.segment.json", MANIFEST_SHA),
            native_probe: input("native-checkpoint.json", NATIVE_SHA),
            restart_snapshot: input(
                "snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst",
                SNAPSHOT_SHA,
            ),
            worker: input("worker", WORKER_SHA),
            genesis_archive: input("genesis.tar.bz2", GENESIS_SHA),
            run_root: Path::new(PRIVATE_ROOT).join("checkpoint-continuation-213-test-v1"),
            minimum_free_bytes: MIN_INITIAL_FREE_BYTES,
        }
    }

    fn suffix() -> HistoricalSegmentManifest {
        let mut value = prefix();
        value.output_slot_start = RESTART + 1;
        value.output_slot_count = END - RESTART;
        value.archive_sha256 = [0x55; 32];
        value.bootstrap_archive_sha256 = Some(sha(SNAPSHOT_SHA).unwrap());
        value.runtime.generation_profile = "new-parent/exact-same-worker".into();
        value.bootstrap = value.terminal.clone();
        value.bootstrap.write_count = 0;
        value.bootstrap.next_write_version = 94_273_483_349;
        value.terminal = value.bootstrap.clone();
        value.terminal.slot = END;
        value.terminal.tick_height += (END - RESTART) * 64;
        value.terminal.transaction_count += 100;
        value.terminal.next_write_version += 200;
        value.emitted_raw_write_versions =
            value.bootstrap.next_write_version..value.terminal.next_write_version;
        value
    }

    #[test]
    fn cli_is_private_build_bound_and_does_not_relax_focused_qualification() {
        validate_cli(true, (EPOCH, EPOCH), Some(true), 1, true, false).unwrap();
        for (enabled, epochs, verify, count, destination, forbidden) in [
            (false, (EPOCH, EPOCH), Some(true), 1, true, false),
            (true, (212, 213), Some(true), 1, true, false),
            (true, (214, 214), Some(true), 1, true, false),
            (true, (EPOCH, EPOCH), None, 1, true, false),
            (true, (EPOCH, EPOCH), Some(false), 1, true, false),
            (true, (EPOCH, EPOCH), Some(true), 2, true, false),
            (true, (EPOCH, EPOCH), Some(true), 1, false, false),
            (true, (EPOCH, EPOCH), Some(true), 1, true, true),
        ] {
            assert!(validate_cli(enabled, epochs, verify, count, destination, forbidden).is_err());
        }
        let snapshot =
            Path::new("snapshot-92447542-4gX8J8Y3c36L6W4D38ax2RYShfKmYxHWuDHAkQKeNzqd.tar.zst");
        let q = QualificationPlan {
            epoch: EPOCH,
            bootstrap_slot: RESTART,
            replay_start: RESTART + 1,
            output_slot_start: RESTART + 1,
            end_inclusive: END,
        };
        let expected = BTreeMap::from([(
            RESTART,
            BankHashExpectation::LegacyAccountsHash(
                prefix().terminal.accounts_hash.parse::<Hash>().unwrap(),
            ),
        )]);
        assert!(
            qualification_expectations(
                expected,
                q,
                snapshot,
                compatibility::SOLANA_V1_6_16_RUNTIME.bootstrap
            )
            .is_err()
        );
    }

    #[test]
    fn plan_pins_all_inputs_and_an_isolated_private_destination() {
        let good = plan();
        validate_plan(&good, &good.run_root.join("ledger")).unwrap();
        assert!(validate_plan(&good, Path::new("/home/ubuntu/horizon")).is_err());
        for field in [
            "prefix_archive",
            "prefix_manifest",
            "native_probe",
            "restart_snapshot",
            "worker",
            "genesis_archive",
        ] {
            let mut value = serde_json::to_value(plan()).unwrap();
            value[field]["sha256"] = json!("0".repeat(64));
            let bad: Plan = serde_json::from_value(value).unwrap();
            assert!(validate_plan(&bad, &bad.run_root.join("ledger")).is_err());
        }
        let mut bad = plan();
        bad.run_root = PathBuf::from("/home/ubuntu/horizon");
        assert!(validate_plan(&bad, &bad.run_root.join("ledger")).is_err());
        let mut bad = plan();
        bad.minimum_free_bytes -= 1;
        assert!(validate_plan(&bad, &bad.run_root.join("ledger")).is_err());
        let mut bad = plan();
        bad.prefix_archive.path = bad.run_root.join("prefix.jet");
        assert!(validate_plan(&bad, &bad.run_root.join("ledger")).is_err());
        let mut value = serde_json::to_value(plan()).unwrap();
        value["publish_through_epoch"] = json!(213);
        assert!(serde_json::from_value::<Plan>(value).is_err());
    }

    #[test]
    fn inherited_root_coverage_is_exact_and_cannot_cross_unsupported_epochs() {
        let good = validated();
        assert!(good.covers_trusted_root(EPOCH, RESTART, RESTART + 1, END));
        for (epoch, bootstrap, start, end) in [
            (212, RESTART, RESTART + 1, END),
            (214, RESTART, RESTART + 1, END),
            (EPOCH, RESTART - 1, RESTART + 1, END),
            (EPOCH, RESTART, RESTART + 2, END),
            (EPOCH, RESTART, RESTART + 1, END + 1),
        ] {
            assert!(!good.covers_trusted_root(epoch, bootstrap, start, end));
        }
        let mut changed = validated();
        changed.manifest.archive_sha256[0] ^= 1;
        assert!(!changed.covers_trusted_root(EPOCH, RESTART, RESTART + 1, END));
        let mut changed = validated();
        changed.manifest.output_slot_count -= 1;
        assert!(!changed.covers_trusted_root(EPOCH, RESTART, RESTART + 1, END));
    }

    #[test]
    fn native_tuple_must_match_but_raw_write_cursors_remain_independent() {
        let good = prefix().terminal;
        let mut native = good.clone();
        native.write_count = 0;
        native.next_write_version += 12345;
        checkpoint_matches(&good, &native).unwrap();
        let mutations: [fn(&mut SegmentCheckpointSummary); 9] = [
            |v| v.slot += 1,
            |v| v.bank_hash.push('x'),
            |v| v.accounts_hash.push('x'),
            |v| v.last_blockhash.push('x'),
            |v| v.capitalization += 1,
            |v| v.transaction_count += 1,
            |v| v.tick_height += 1,
            |v| v.slot_complete = false,
            |v| v.write_count = 1,
        ];
        for mutate in mutations {
            let mut bad = native.clone();
            mutate(&mut bad);
            assert!(checkpoint_matches(&good, &bad).is_err());
        }
    }

    #[test]
    fn v4_builder_preserves_both_generations_and_normalizes_restart_cursors() {
        let prefix = prefix();
        let suffix = suffix();
        let value = build_provenance(&prefix, &suffix).unwrap();
        assert_eq!(value.base.requested_slot_start, START);
        assert_eq!(value.base.requested_slot_count, 432_000);
        assert_eq!(value.base.runtime_segments[0].slot_count, 431_543);
        assert_eq!(value.base.runtime_segments[1].slot_count, 457);
        assert_ne!(
            value.base.runtime_segments[0].generation_profile,
            value.base.runtime_segments[1].generation_profile
        );
        assert_eq!(
            value.base.runtime_segments[0].write_versions.archive_start,
            0
        );
        assert_eq!(
            value.base.runtime_segments[1].write_versions.archive_start,
            prefix.emitted_raw_write_versions.end - prefix.emitted_raw_write_versions.start
        );
        assert_ne!(
            value.base.handoffs[0].predecessor.next_write_version,
            value.base.handoffs[0].successor.next_write_version
        );
        assert_eq!(
            value.base.handoffs[0].successor_bootstrap_archive_sha256,
            sha(SNAPSHOT_SHA).unwrap()
        );
    }

    #[test]
    fn v4_builder_rejects_unbound_snapshot_worker_and_incomplete_suffix() {
        let p = prefix();
        let mut s = suffix();
        s.bootstrap_archive_sha256 = None;
        assert!(build_provenance(&p, &s).is_err());
        s = suffix();
        s.worker_executable_sha256[0] ^= 1;
        assert!(build_provenance(&p, &s).is_err());
        s = suffix();
        s.output_slot_count -= 1;
        s.terminal.slot -= 1;
        assert!(build_provenance(&p, &s).is_err());
        s = suffix();
        s.bootstrap.accounts_hash = p.bootstrap.accounts_hash.clone();
        assert!(build_provenance(&p, &s).is_err());
    }
}
