//! Narrow, root-reviewed admission of one independently verified epoch-223 V3
//! native 20 / native 25 assembly. Does not promote the runtime registry or access R2.
//!
//! Root audits private evidence and opens root-only receipt sinks. It hands off
//! only the verified copy, permanently drops to the public directory's owner,
//! then uses the existing recoverable absence-only transaction. Original
//! assembly/prefix/suffix and all verification logs remain untouched.

#[path = "epoch213_publish/write_scope.rs"]
mod write_scope;

#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "epoch223_assembly/handoff.rs"]
mod handoff;
#[allow(dead_code)]
#[path = "epoch223_assembly/final_evidence.rs"]
mod qualified;
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{ArchiveProvenance, ArchiveReader, encode_archive_provenance};
use jetstreamer_horizon_observe::source_idle223;
use jetstreamer_node::{
    archive_checksum::{measure_open_archive, open_regular_nofollow, prepare_archive_permissions},
    archive_publish::{
        ArchiveBatchItem, acknowledge_archive_publication_batch, preflight_archive_publication,
        publish_verified_archive_batch_if_absent_with_context_and_lock_timeout,
    },
    segment_manifest::sha256_hex_string,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    time::Duration,
};

const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
const UID: u32 = 1000;
const GID: u32 = 1000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    verification: Evidence,
    verifier: Evidence,
    verifier_launch: Evidence,
    verifier_terminal_journal: Evidence,
    archive_sha256: String,
    archive_bytes: u64,
    publication_stage: PathBuf,
    receipt_directory: PathBuf,
    full_receipt_directory: PathBuf,
    plugin_receipt_directory: PathBuf,
    artifact_publication_authorized: bool,
    runtime_registry_promotion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}

fn digest(value: &str) -> Result<[u8; 32]> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase SHA-256"
    );
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&value[2 * i..2 * i + 2], 16)?;
    }
    Ok(bytes)
}

fn canonical(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical path: {}",
        path.display()
    );
    Ok(())
}

fn private_root_directory(path: &Path) -> Result<File> {
    canonical(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "receipt directory is not root-private"
    );
    ensure!(
        identity(&m) == identity(&fs::symlink_metadata(path)?),
        "directory changed"
    );
    Ok(file)
}

fn absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "namespace already exists: {}",
        path.display()
    );
    Ok(())
}

fn root_evidence(e: &Evidence, limit: u64) -> Result<Vec<u8>> {
    digest(&e.sha256)?;
    canonical(&e.path)?;
    let mut file = open_regular_nofollow(&e.path)?;
    let before = identity(&file.metadata()?);
    ensure!(
        before.uid == 0 && before.links == 1 && before.mode & 0o022 == 0 && before.len <= limit,
        "unsafe root evidence"
    );
    let mut bytes = Vec::new();
    (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit
            && identity(&file.metadata()?) == before
            && identity(&fs::symlink_metadata(&e.path)?) == before,
        "evidence changed or oversized"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == e.sha256,
        "evidence digest mismatch: {}",
        e.path.display()
    );
    Ok(bytes)
}

fn bound_json(e: &Evidence) -> Result<Value> {
    Ok(serde_json::from_slice(&root_evidence(e, 4 << 20)?)?)
}

fn json_binding(value: &Value) -> Result<Evidence> {
    Ok(Evidence {
        path: value["path"]
            .as_str()
            .context("missing evidence path")?
            .into(),
        sha256: value["sha256"]
            .as_str()
            .context("missing evidence SHA-256")?
            .into(),
    })
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-private-epoch223-v3-publication-plan-v1"
            && plan.artifact_publication_authorized
            && !plan.runtime_registry_promotion_authorized
            && !plan.remote_mutations
            && !plan.r2_mutations,
        "wrong publication authority"
    );
    digest(&plan.archive_sha256)?;
    digest(&plan.verification.sha256)?;
    ensure!(
        plan.archive_bytes > 0
            && plan.archive_bytes <= 160u64 << 30
            && evidence::is_sha(&plan.verifier.sha256)
            && plan.verifier_launch.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-223-private-verification-capture-v1/launch.json"
                ),
        "archive/verifier scope differs"
    );
    // A pre-existing, root-owned work parent can be the sole writable sandbox
    // mount while the actual no-clobber stage remains absent until admission.
    // Root ownership, non-writability and same-filesystem checks still run
    // immediately before any stage or sink is created.
    let bounded_work_stage = plan.publication_stage.file_name() == Some("stage".as_ref())
        && plan.publication_stage.parent().is_some_and(|parent| {
            parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && parent.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .starts_with("horizon-223-publication-work-")
                })
        });
    ensure!(bounded_work_stage, "wrong private handoff namespace");
    ensure!(
        plan.receipt_directory != plan.full_receipt_directory
            && plan.receipt_directory != plan.plugin_receipt_directory
            && plan.full_receipt_directory != plan.plugin_receipt_directory,
        "receipt namespaces overlap"
    );
    Ok(())
}

struct Accepted {
    archive: PathBuf,
    identity: Identity,
    inputs: qualified::Inputs,
    prepared: qualified::Prepared,
    terminal: Value,
    idle: Value,
}
fn accept(v: &Value, plan: &Plan) -> Result<Accepted> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-verification-v1"
            && v["epoch"] == 223
            && v["unit"] == qualified::VERIFY_UNIT
            && v["runner_sha256"] == plan.verifier.sha256
            && v["archive_sha256"] == plan.archive_sha256
            && v["archive_bytes"] == plan.archive_bytes,
        "private 223 verification scope differs"
    );
    for key in [
        "independent_final_archive_verification_passed",
        "current_plugin_verification_passed",
    ] {
        ensure!(v[key] == true, "missing independent 223 check: {key}");
    }
    for key in [
        "runtime_admission_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "private 223 verifier acquired authority: {key}"
        );
    }
    root_evidence(&plan.verifier, 128 << 20)?;
    ensure!(
        plan.verifier
            .path
            .file_name()
            .is_some_and(|n| n == "jetstreamer-epoch223-private-verify")
            && plan.verifier.path.parent().is_some_and(|p| p.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("horizon-223-private-v3-final-tools-"))),
        "private 223 verifier is outside the sealed final-tools package"
    );
    let inputs: qualified::Inputs = serde_json::from_value(v["inputs"].clone())?;
    let prepared = qualified::prepare(&inputs)?;
    ensure!(
        v["expected_provenance_sha256"] == prepared.provenance_sha256
            && v["producer_outcome"] == serde_json::to_value(&inputs.assembly_receipt)?
            && v["producer_terminal"] == prepared.terminal_history
            && v["boundary_metadata"] == serde_json::to_value(&inputs.boundary_metadata)?
            && v["source_path"] == qualified::SOURCE,
        "independent 223 source lineage differs"
    );
    let archive = PathBuf::from(
        v["archive_path"]
            .as_str()
            .context("private 223 archive path")?,
    );
    let dir = archive.parent().context("private 223 archive parent")?;
    ensure!(
        archive.file_name().is_some_and(|n| n == "epoch-223.jet")
            && dir.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-private-v3-scan-")
                    && n.len() > "horizon-223-private-v3-scan-".len()
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            && plan.verification.path == dir.join("verification.json"),
        "private 223 scan namespace differs"
    );
    let invocation = v["invocation_id"]
        .as_str()
        .filter(|s| qualified::iid(s))
        .context("actual verifier invocation")?;
    let launch = bound_json(&plan.verifier_launch)?;
    ensure!(
        launch["schema"] == "jetstreamer-private223-v3-verification-launch-v1"
            && launch["epoch"] == 223
            && launch["unit"] == qualified::VERIFY_UNIT
            && launch["invocation_id"] == invocation
            && launch["verifier_sha256"] == plan.verifier.sha256
            && launch["verification_plan"] == v["plan"]
            && launch["private_directory"] == dir.to_str().context("non-UTF8 scan path")?
            && launch["launched"] == true,
        "actual verifier capture differs"
    );
    let pid = launch["producer_at_capture"]["MainPID"]
        .as_str()
        .context("actual verifier captured PID")?;
    ensure!(
        v["owner_at_start"]["MainPID"] == pid && v["owner_at_start"]["InvocationID"] == invocation,
        "private verifier receipt is not the captured owner"
    );
    let terminal = qualified::terminal(
        &root_evidence(&plan.verifier_terminal_journal, 8 << 20)?,
        qualified::VERIFY_UNIT,
        invocation,
        pid,
        "private epoch 223 V3 verification complete; import/publication gates remain closed",
    )?;
    let vp = bound_json(&json_binding(&v["plan"])?)?;
    ensure!(
        vp["schema"] == "jetstreamer-private-epoch223-v3-verification-plan-v1"
            && vp["inputs"] == v["inputs"]
            && vp["private_directory"] == dir.to_str().unwrap()
            && vp["capacity"] == v["capacity"]
            && vp["full_verifier"] == v["full"]["binary"]
            && vp["plugin"] == v["plugin"]["binary"],
        "private verification plan differs"
    );
    let expected = bound_json(&json_binding(&v["provenance_expectation"])?)?;
    ensure!(
        expected["schema"] == "jetstreamer-private-epoch223-provenance-expectation-v1"
            && expected["expected_provenance_sha256"] == prepared.provenance_sha256
            && expected["expected_provenance_encoded_bytes"] == prepared.provenance.len()
            && expected["handoff_request"] == serde_json::to_value(&inputs.handoff_request)?
            && expected["handoff_receipt"] == serde_json::to_value(&inputs.handoff_receipt)?
            && expected["source_manifest_scope_validated"] == true
            && expected["provenance_derived_without_target_bytes"] == true
            && expected["assembled_target_bytes_used_for_provenance"] == false,
        "223 provenance expectation is not independently source-derived"
    );
    for (key, binary_sha, args) in [
        ("full", FULL, qualified::full_args(&archive, &prepared)),
        ("plugin", PLUGIN, qualified::plugin_args(dir)),
    ] {
        ensure!(
            v[key]["binary"]["sha256"] == binary_sha
                && v[key]["exit_code"] == 0
                && v[key]["arguments"] == serde_json::to_value(args)?,
            "223 scan arguments/binary differ: {key}"
        );
        root_evidence(&json_binding(&v[key]["binary"])?, 128 << 20)?;
        let log = json_binding(&v[key]["log"])?;
        ensure!(
            log.path == dir.join(format!("{key}.log")),
            "223 scan log escaped private attempt"
        );
        root_evidence(&log, 64 << 20)?;
        let log_id: Identity = serde_json::from_value(v[key]["log"]["identity"].clone())?;
        ensure!(
            identity(&fs::symlink_metadata(&log.path)?) == log_id,
            "223 scan log identity changed"
        );
    }
    let id: Identity = serde_json::from_value(v["archive_identity"].clone())?;
    ensure!(
        id.len == plan.archive_bytes && id.uid == 0 && id.links == 1 && id.mode & 0o777 == 0o400,
        "223 private scan copy ownership differs"
    );
    let idle = source_idle223::observe_verification(invocation, &archive)?;
    Ok(Accepted {
        archive,
        identity: id,
        inputs,
        prepared,
        terminal,
        idle,
    })
}
fn validate_archive(file: &File, expected: &str) -> Result<()> {
    let reader = ArchiveReader::open(BufReader::new(file.try_clone()?))
        .map_err(|e| anyhow::anyhow!("archive open: {e}"))?;
    ensure!(
        reader.header().slot_start == 96336000 && reader.header().slot_count == 432000,
        "incomplete epoch 223 coverage"
    );
    let provenance = reader
        .provenance()
        .map_err(|e| anyhow::anyhow!("provenance decode: {e}"))?
        .context("missing V3 provenance")?;
    ensure!(
        matches!(provenance, ArchiveProvenance::V3(_)),
        "223 mixture requires V3 provenance"
    );
    let encoded = encode_archive_provenance(&provenance)
        .map_err(|e| anyhow::anyhow!("provenance encode: {e}"))?;
    ensure!(
        format!("{:x}", Sha256::digest(&encoded)) == expected,
        "independent 223 source provenance differs"
    );
    Ok(())
}

struct Sink {
    file: File,
    parent: File,
}
impl Sink {
    fn create(directory: &Path, name: &str) -> Result<Self> {
        let parent = private_root_directory(directory)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(name))?;
        file.sync_all()?;
        parent.sync_all()?;
        Ok(Self { file, parent })
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        let metadata = self.file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o777 == 0o600
                && metadata.len() == 0,
            "receipt sink changed or already written"
        );
        self.file.write_all(bytes)?;
        self.file.sync_all()?;
        self.parent.sync_all()?;
        Ok(())
    }
    fn json(&mut self, value: &Value) -> Result<()> {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        self.write(&bytes)
    }
}

fn drop_to_archive_owner() -> Result<()> {
    ensure!(
        fs::read_dir("/proc/self/task")?.count() == 1,
        "privilege transition requires single-threaded publisher"
    );
    ensure!(
        unsafe { libc::setgroups(0, std::ptr::null()) } == 0,
        "clear supplementary groups"
    );
    ensure!(
        unsafe { libc::setresgid(GID, GID, GID) } == 0,
        "drop group identity"
    );
    ensure!(
        unsafe { libc::setresuid(UID, UID, UID) } == 0,
        "drop user identity"
    );
    let (mut r, mut e, mut s) = (0, 0, 0);
    ensure!(
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) } == 0 && (r, e, s) == (UID, UID, UID),
        "user identity was not permanently dropped"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    for name in ["CapPrm:", "CapEff:", "CapAmb:"] {
        ensure!(
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .context("missing capability field")?
                .trim()
                == "0000000000000000",
            "capability retained after drop"
        );
    }
    Ok(())
}

fn validate_self(self_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "publisher admission requires root"
    );
    let mut exe = File::open("/proc/self/exe")?;
    let exe_id = identity(&exe.metadata()?);
    ensure!(
        exe_id.uid == 0 && exe_id.links == 1 && exe_id.mode & 0o022 == 0,
        "unsafe running publisher"
    );
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = exe.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    ensure!(
        format!("{:x}", hasher.finalize()) == self_sha && identity(&exe.metadata()?) == exe_id,
        "publisher self digest mismatch"
    );
    Ok(())
}

fn run(binding: Evidence, self_sha: &str) -> Result<()> {
    validate_self(self_sha)?;
    let plan: Plan = serde_json::from_slice(&root_evidence(&binding, 4 << 20)?)?;
    validate_plan(&plan)?;
    let verification = bound_json(&plan.verification)?;
    let accepted = accept(&verification, &plan)?;
    let archive = accepted.archive;
    let expected_id = accepted.identity;
    let private_dir = archive.parent().unwrap();
    private_root_directory(private_dir)?;
    let original = Path::new(qualified::SOURCE);
    canonical(original)?;
    let original_file = open_regular_nofollow(original)?;
    let original_id: Identity = serde_json::from_value(verification["source_identity"].clone())?;
    ensure!(
        identity(&original_file.metadata()?) == original_id
            && identity(&fs::symlink_metadata(original)?) == original_id,
        "retained original 223 assembly changed"
    );
    let producer = json_binding(&verification["producer_outcome"])?;
    let provenance = json_binding(&verification["provenance_expectation"])?;
    let destination = Path::new("/home/ubuntu/horizon");
    canonical(destination)?;
    let dm = fs::symlink_metadata(destination)?;
    ensure!(
        dm.is_dir() && dm.uid() == UID && dm.gid() == GID && dm.mode() & 0o7777 == 0o3770,
        "public directory ownership/mode changed"
    );
    for path in [
        destination.join("epoch-223.jet"),
        destination.join("epoch-223.jet.sha256"),
        destination.join("epoch-223.jet.segment.json"),
    ] {
        absent(&path)?;
    }
    absent(&archive.with_extension("jet.sha256"))?;
    absent(&plan.publication_stage)?;
    canonical(plan.publication_stage.parent().unwrap())?;
    let stage_parent = fs::metadata(plan.publication_stage.parent().unwrap())?;
    ensure!(
        stage_parent.uid() == 0
            && stage_parent.mode() & 0o022 == 0
            && stage_parent.mode() & 0o001 != 0
            && stage_parent.dev() == dm.dev(),
        "unsafe/cross-filesystem handoff parent"
    );
    let file = open_regular_nofollow(&archive)?;
    ensure!(
        identity(&file.metadata()?) == expected_id
            && identity(&fs::symlink_metadata(&archive)?) == expected_id
            && expected_id.dev == dm.dev(),
        "verified private copy identity changed"
    );
    validate_archive(&file, &accepted.prepared.provenance_sha256)?;
    // Reject split writable bind mounts before sinks, chown or movement.
    let rename_mount_id = write_scope::same_mount(&[
        private_dir,
        plan.publication_stage.parent().unwrap(),
        destination,
    ])?;
    let write_scope = write_scope::confine(&[
        private_dir,
        plan.publication_stage.parent().unwrap(),
        &plan.receipt_directory,
        &plan.full_receipt_directory,
        &plan.plugin_receipt_directory,
        destination,
    ])?;
    // Open root-only durable sinks before permanently dropping privileges.
    // No later pathname access can grant the archive user these permissions.
    let mut intent = Sink::create(&plan.receipt_directory, "intent.json")?;
    let mut receipt = Sink::create(&plan.receipt_directory, "publication.json")?;
    let mut full_gate = Sink::create(&plan.full_receipt_directory, "epoch-223.full.ok")?;
    let mut plugin_gate = Sink::create(&plan.plugin_receipt_directory, "epoch-223.plugin.ok")?;
    let context = json!({"schema":"jetstreamer-exact-epoch223-v3-publication-context-v1","epoch":223,"plan":binding,"publisher_sha256":self_sha,"verification":plan.verification,"scanner_terminal":accepted.terminal,"scanner_idle":accepted.idle,"verifier_launch":plan.verifier_launch,"canonical_boundary_metadata":accepted.inputs.boundary_metadata,"archive_sha256":plan.archive_sha256,"archive_bytes":plan.archive_bytes,"expected_provenance_sha256":accepted.prepared.provenance_sha256,"private_runner_sha256":plan.verifier.sha256,"rename_mount_id":rename_mount_id,"write_scope":write_scope,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
    intent.json(&context)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&plan.publication_stage)?;
    let stage = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&plan.publication_stage)?;
    ensure!(
        unsafe { libc::fchown(stage.as_raw_fd(), UID, GID) } == 0,
        "assign private handoff owner"
    );
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), UID, GID) } == 0,
        "assign archive owner"
    );
    prepare_archive_permissions(&file, destination)?;
    file.sync_all()?;
    let staged = plan.publication_stage.join("epoch-223.jet");
    // Fresh, root-controlled stage; do not replace anything, even during handoff.
    let from = std::ffi::CString::new(archive.as_os_str().as_encoded_bytes())?;
    let to = std::ffi::CString::new(staged.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no-clobber private handoff rename failed"
    );
    stage.sync_all()?;
    File::open(private_dir)?.sync_all()?;
    File::open(plan.publication_stage.parent().unwrap())?.sync_all()?;
    let measured = measure_open_archive(&file)?;
    ensure!(
        sha256_hex_string(&measured.sha256) == plan.archive_sha256,
        "independent import digest differs"
    );
    ensure!(
        file.metadata()?.len() == plan.archive_bytes,
        "independent 223 import length differs"
    );
    let after = qualified::prepare(&accepted.inputs)?;
    ensure!(
        after.provenance == accepted.prepared.provenance
            && after.assembly == accepted.prepared.assembly,
        "223 sources changed during import measurement"
    );
    // Rehash protected evidence after the expensive archive measurement.
    root_evidence(&plan.verification, 4 << 20)?;
    root_evidence(&producer, 4 << 20)?;
    root_evidence(&provenance, 4 << 20)?;
    ensure!(
        identity(&original_file.metadata()?) == original_id
            && identity(&fs::symlink_metadata(original)?) == original_id,
        "retained original assembly changed during admission"
    );
    drop_to_archive_owner()?;
    preflight_archive_publication(&plan.publication_stage, destination)?;
    let publication = publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
        digest(&binding.sha256)?,
        &[223],
        &[ArchiveBatchItem {
            epoch: 223,
            staged_archive: staged,
            destination_archive: destination.join("epoch-223.jet"),
            evidence: measured,
        }],
        &serde_json::to_vec(&context)?,
        Duration::from_secs(60),
    )?;
    let item = &publication.publications[0];
    ensure!(
        item.evidence.sha256 == measured.sha256,
        "published digest changed"
    );
    receipt.json(&json!({"schema":"jetstreamer-exact-epoch223-v3-publication-receipt-v1","epoch":223,"context":context,"transaction_id":sha256_hex_string(&publication.transaction_id),"archive_path":item.archive_path,"checksum_path":item.checksum_path,"archive_sha256":plan.archive_sha256,"archive_bytes":plan.archive_bytes,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,"private_runner_sha256":plan.verifier.sha256,"committed":true,"original_assembly_preserved":true,"runtime_registry_promoted":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}))?;
    // Receipt is durable before either uploader gate becomes parseable. These
    // held root-owned descriptors cannot replace any existing .ok receipt.
    full_gate
        .write(format!("{} {FULL} {}\n", plan.archive_sha256, plan.verifier.sha256).as_bytes())?;
    plugin_gate.write(
        format!(
            "{} {PLUGIN} {}\n",
            plan.archive_sha256, plan.verifier.sha256
        )
        .as_bytes(),
    )?;
    acknowledge_archive_publication_batch(destination, publication.transaction_id)?;
    println!("epoch 223 exact V3 artifact committed locally; no R2 mutation or registry promotion");
    Ok(())
}

/// Exercise the actual FD/credential/transaction sequence with fake bytes only
/// beneath a distinct capability namespace. Never opens the real Horizon
/// directory or any campaign archive/receipt. This proves filesystem capability,
/// not archive validity or publication admission.
fn capability_probe(root: &Path, self_sha: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    validate_self(self_sha)?;
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-223-publication-capability-")),
        "wrong capability namespace"
    );
    private_root_directory(root)?;
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "capability directory must be empty"
    );
    let receipts = root.join("receipts");
    fs::DirBuilder::new().mode(0o700).create(&receipts)?;
    let mut sink = Sink::create(&receipts, "capability.json")?;
    let stage = root.join("stage");
    let destination = root.join("destination");
    for (path, mode) in [(&stage, 0o700), (&destination, 0o3770)] {
        fs::DirBuilder::new().mode(mode).create(path)?;
        let fd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            unsafe { libc::fchown(fd.as_raw_fd(), UID, GID) } == 0,
            "capability directory owner"
        );
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
        fd.sync_all()?;
    }
    let staged = stage.join("epoch-223.jet");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staged)?;
    file.write_all(b"private filesystem capability fixture; NOT a Horizon archive\n")?;
    ensure!(
        unsafe { libc::fchown(file.as_raw_fd(), UID, GID) } == 0,
        "capability fixture owner"
    );
    prepare_archive_permissions(&file, &destination)?;
    file.sync_all()?;
    let evidence = measure_open_archive(&file)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o755))?;
    File::open(root)?.sync_all()?;
    let rename_mount_id = write_scope::same_mount(&[&stage, &destination])?;
    let write_scope = write_scope::confine(&[&stage, &destination, &receipts])?;
    ensure!(
        fs::write(root.join("forbidden-write"), b"must not exist").is_err(),
        "write scope did not deny an out-of-scope write"
    );
    drop_to_archive_owner()?;
    preflight_archive_publication(&stage, &destination)?;
    let context = b"epoch223 private filesystem capability only; no archive admission";
    let publication = publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
        Sha256::digest(context).into(),
        &[223],
        &[ArchiveBatchItem {
            epoch: 223,
            staged_archive: staged,
            destination_archive: destination.join("epoch-223.jet"),
            evidence,
        }],
        context,
        Duration::from_secs(5),
    )?;
    sink.json(&json!({"schema":"jetstreamer-private-epoch223-publication-capability-v1","publisher_sha256":self_sha,"diagnostic_fixture":true,"rename_mount_id":rename_mount_id,"write_scope":write_scope,"outside_write_denied":true,"filesystem_transaction_passed":true,"root_receipt_fd_survives_permanent_privilege_drop":true,"effective_uid":unsafe{libc::geteuid()},"archive_sha256":sha256_hex_string(&evidence.sha256),"transaction_id":sha256_hex_string(&publication.transaction_id),"archive_publication_authorized":false,"runtime_registry_promotion_authorized":false,"r2_mutations":false}))?;
    acknowledge_archive_publication_batch(&destination, publication.transaction_id)?;
    println!("private publication filesystem capability passed; no campaign archive touched");
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() == 4 && args[0] == "--capability-probe" && args[2] == "--self-sha256" {
        digest(&args[3])?;
        return capability_probe(Path::new(&args[1]), &args[3]);
    }
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: jetstreamer-epoch223-publish PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    digest(&args[4])?;
    run(
        Evidence {
            path: args[0].clone().into(),
            sha256: args[2].clone(),
        },
        &args[4],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan_value() -> Value {
        let bound = json!({"path":"/private/evidence.json","sha256":"a".repeat(64)});
        json!({"schema":"jetstreamer-private-epoch223-v3-publication-plan-v1",
        "verification":bound,"verifier":bound,"verifier_launch":{"path":"/var/lib/jetstreamer/horizon-223-private-verification-capture-v1/launch.json","sha256":"a".repeat(64)},"verifier_terminal_journal":bound,
        "archive_sha256":"b".repeat(64),"archive_bytes":1024,
        "publication_stage":"/var/lib/jetstreamer/horizon-223-publication-work-test/stage",
        "receipt_directory":"/private/import","full_receipt_directory":"/private/full","plugin_receipt_directory":"/private/plugin",
        "artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }
    #[test]
    fn publication_authority_is_explicit_local_and_epoch_scoped() {
        let value = plan_value();
        validate_plan(&serde_json::from_value(value.clone()).unwrap()).unwrap();
        for (key, replacement) in [
            (
                "schema",
                json!("jetstreamer-private-epoch223-v4-publication-plan-v1"),
            ),
            ("artifact_publication_authorized", json!(false)),
            ("runtime_registry_promotion_authorized", json!(true)),
            ("remote_mutations", json!(true)),
            ("r2_mutations", json!(true)),
            ("archive_bytes", json!(0)),
            ("archive_bytes", json!((160u64 << 30) + 1)),
            (
                "publication_stage",
                json!("/var/lib/jetstreamer/horizon-224-publication-work-test/stage"),
            ),
            (
                "publication_stage",
                json!("/tmp/horizon-223-publication-work-test/stage"),
            ),
            ("full_receipt_directory", json!("/private/import")),
        ] {
            let mut bad = value.clone();
            bad[key] = replacement;
            assert!(
                validate_plan(&serde_json::from_value(bad).unwrap()).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn verification_never_acquires_publication_or_remote_authority() {
        let p: Plan = serde_json::from_value(plan_value()).unwrap();
        let base = json!({"schema":"jetstreamer-private-epoch223-verification-v1","epoch":223,
            "unit":qualified::VERIFY_UNIT,"runner_sha256":p.verifier.sha256,
            "archive_sha256":p.archive_sha256,"archive_bytes":p.archive_bytes,
            "independent_final_archive_verification_passed":true,"current_plugin_verification_passed":true,
            "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false});
        for key in [
            "runtime_admission_authorized",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "retirement_authorized",
            "r2_mutations",
        ] {
            let mut bad = base.clone();
            bad[key] = json!(true);
            assert!(
                accept(&bad, &p)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("acquired authority"),
                "{key}"
            );
        }
        for key in [
            "independent_final_archive_verification_passed",
            "current_plugin_verification_passed",
        ] {
            let mut bad = base.clone();
            bad[key] = json!(false);
            assert!(
                accept(&bad, &p)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("missing independent"),
                "{key}"
            );
        }
    }
}
