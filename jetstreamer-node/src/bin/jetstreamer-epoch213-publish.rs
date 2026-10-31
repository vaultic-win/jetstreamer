//! Narrow, root-reviewed admission of one independently verified epoch-213 V4
//! continuation. Does not promote the runtime registry or access R2.
//!
//! Root audits private evidence and opens root-only receipt sinks. It hands off
//! only the verified copy, permanently drops to the public directory's owner,
//! then uses the existing recoverable absence-only transaction. Original
//! assembly/prefix/suffix and all verification logs remain untouched.

#[path = "epoch213_publish/write_scope.rs"]
mod write_scope;

use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{ArchiveProvenance, ArchiveReader, encode_archive_provenance};
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

const RUNNER: &str = "8d9bd29c60c8ea5870e2169255acaae8d2f7436c4ec130dc8154d28cc4628130";
const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
const PROVENANCE: &str = "a85a2df80f7d6ca8720e597f372661df65fd0d891e41d420a3db6f866ab4121b";
const EXPECTATION: &str = "f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5";
const ANCHOR_EVIDENCE: &str = "fc635af1c740bd0a1a9a81b141631e49a43d625b0dffffc1d187d3106f2845e8";
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
    initial_anchor: Evidence,
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
    Ok(serde_json::from_value(value.clone())?)
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-private-epoch213-v4-publication-plan-v1"
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
            && plan.archive_bytes <= 128 * 1024 * 1024 * 1024
            && plan.initial_anchor.sha256 == ANCHOR_EVIDENCE,
        "archive/anchor scope differs"
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
                        .starts_with("horizon-213-publication-work-")
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

fn expected_full(archive: &str) -> Value {
    json!([
        archive,
        "--full",
        "--anchor",
        "92015999",
        "9xdazt5sEpSUzwYi9nTRMmXJDuP4kLdcY9ZXAM5oQVi7",
        "--expected-terminal",
        "92447999",
        "2SMgef3T3X5aeHZy1USrSR5qEJqwQbsz2yVr3tRs25Ki",
        "--threads",
        "8",
        "--expected-provenance-sha256",
        PROVENANCE
    ])
}

fn validate_verification(v: &Value, plan: &Plan) -> Result<(PathBuf, Identity)> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch213-verification-v1"
            && v["epoch"] == 213
            && v["runner_sha256"] == RUNNER
            && v["archive_sha256"] == plan.archive_sha256
            && v["expected_provenance_sha256"] == PROVENANCE,
        "wrong private verification binding"
    );
    for flag in [
        "independent_final_archive_verification_passed",
        "current_plugin_verification_passed",
    ] {
        ensure!(v[flag] == true, "missing independent verification");
    }
    for flag in [
        "runtime_admission_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "private verifier acquired authority");
    }
    let archive = PathBuf::from(v["archive_path"].as_str().context("missing archive path")?);
    let dir = archive.parent().context("no private archive parent")?;
    ensure!(
        archive.file_name() == Some(std::ffi::OsStr::new("epoch-213.jet"))
            && dir.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && dir
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("horizon-213-private-scan-")),
        "archive outside exact private scan namespace"
    );
    let archive_text = archive.to_str().context("non-UTF8 archive")?;
    ensure!(
        v["full"]["binary"]["sha256"] == FULL
            && v["full"]["exit_code"] == 0
            && v["full"]["arguments"] == expected_full(archive_text),
        "full scan is not strict anchored/canonical-terminal/provenance proof"
    );
    ensure!(
        v["plugin"]["binary"]["sha256"] == PLUGIN
            && v["plugin"]["exit_code"] == 0
            && v["plugin"]["arguments"]
                == json!([
                    "213:213",
                    dir.to_str().context("non-UTF8 directory")?,
                    "--threads",
                    "8",
                    "--verify-only"
                ]),
        "plugin scan is not exact current byte-consuming verification"
    );
    let id: Identity = serde_json::from_value(v["archive_identity"].clone())?;
    ensure!(
        id.len == plan.archive_bytes && id.uid == 0 && id.links == 1 && id.mode & 0o777 == 0o400,
        "private archive identity differs"
    );
    ensure!(
        v["provenance_expectation"]["sha256"] == EXPECTATION,
        "expected provenance was not source-derived"
    );
    Ok((archive, id))
}

fn validate_producer(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch213-checkpoint-continuation-v1"
            && v["producer_unit"]
                == "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service"
            && v["producer_invocation_id"] == "1dfd29e7ced140b3ba407359cbdc0ee1"
            && v["node_sha256"]
                == "83398ece0317a6ab3b321f9e1eb8d0c7f76f21f1cb5997cd07899ba19f2992f3"
            && v["plan"]["sha256"]
                == "83eeb441502e39510ad7610ae6dac9165d9f5a6f32afaeab1f19205e9ab6f144"
            && v["prefix_archive_sha256"]
                == "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9"
            && v["suffix_archive_sha256"]
                == "3360ba3da029865522511a821c30851447a7a6eca5e9fe28cd536181edf07d03"
            && v["restart_snapshot_sha256"]
                == "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08"
            && v["fresh_prefix_full_validation_passed"] == true
            && v["fresh_native_checkpoint_matches"] == true
            && v["canonical_root_slot"] == 92447542
            && v["assembly"]["slots_merged"] == 432000
            && v["assembly"]["source_archives"] == 2
            && v["assembly"]["provenance_version"] == 4,
        "producer lineage or canonical restart root differs"
    );
    Ok(())
}

fn validate_archive(file: &File) -> Result<()> {
    let reader = ArchiveReader::open(BufReader::new(file.try_clone()?))
        .map_err(|e| anyhow::anyhow!("archive open: {e}"))?;
    ensure!(
        reader.header().slot_start == 92016000 && reader.header().slot_count == 432000,
        "not complete epoch 213 coverage"
    );
    let provenance = reader
        .provenance()
        .map_err(|e| anyhow::anyhow!("provenance decode: {e}"))?
        .context("missing restart provenance")?;
    ensure!(
        matches!(provenance, ArchiveProvenance::V4(_)),
        "not restarted V4 lineage"
    );
    let encoded = encode_archive_provenance(&provenance)
        .map_err(|e| anyhow::anyhow!("provenance encode: {e}"))?;
    ensure!(
        format!("{:x}", Sha256::digest(&encoded)) == PROVENANCE,
        "exact independently expected V4 provenance differs"
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
    let (archive, expected_id) = validate_verification(&verification, &plan)?;
    let private_dir = archive.parent().unwrap();
    private_root_directory(private_dir)?;
    let original = Path::new(
        "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-213-ae43646-v1/output/epoch-213-checkpoint-restart-v4.jet",
    );
    ensure!(
        verification["source_path"] == original.to_str().unwrap(),
        "wrong retained original assembly"
    );
    canonical(original)?;
    let original_file = open_regular_nofollow(original)?;
    let original_id: Identity = serde_json::from_value(verification["source_identity"].clone())?;
    ensure!(
        identity(&original_file.metadata()?) == original_id
            && identity(&fs::symlink_metadata(original)?) == original_id,
        "retained original assembly changed or disappeared"
    );
    let producer = json_binding(&verification["producer_outcome"])?;
    validate_producer(&bound_json(&producer)?)?;
    let provenance = json_binding(&verification["provenance_expectation"])?;
    let expected = bound_json(&provenance)?;
    ensure!(
        expected["expected_provenance_sha256"] == PROVENANCE
            && expected["assembled_target_opened"] == false
            && expected["source_manifest_scope_validated"] == true,
        "not independent source provenance expectation"
    );
    root_evidence(&plan.initial_anchor, 4 << 20)?;
    // Rehash the exact producer and verifier plan evidence as well as both logs.
    root_evidence(&json_binding(&verification["plan"])?, 4 << 20)?;
    for key in ["full", "plugin"] {
        root_evidence(&json_binding(&verification[key]["binary"])?, 256 << 20)?;
        let log = &verification[key]["log"];
        let path = PathBuf::from(log["path"].as_str().context("missing log path")?);
        ensure!(
            path == private_dir.join(format!("{key}.log")),
            "log outside private verified attempt"
        );
        root_evidence(
            &Evidence {
                path,
                sha256: log["sha256"].as_str().context("missing log digest")?.into(),
            },
            64 << 20,
        )?;
    }
    let destination = Path::new("/home/ubuntu/horizon");
    canonical(destination)?;
    let dm = fs::symlink_metadata(destination)?;
    ensure!(
        dm.is_dir() && dm.uid() == UID && dm.gid() == GID && dm.mode() & 0o7777 == 0o3770,
        "public directory ownership/mode changed"
    );
    for path in [
        destination.join("epoch-213.jet"),
        destination.join("epoch-213.jet.sha256"),
        destination.join("epoch-213.jet.segment.json"),
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
    validate_archive(&file)?;
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
    let mut full_gate = Sink::create(&plan.full_receipt_directory, "epoch-213.full.ok")?;
    let mut plugin_gate = Sink::create(&plan.plugin_receipt_directory, "epoch-213.plugin.ok")?;
    let context = json!({"schema":"jetstreamer-exact-epoch213-v4-publication-context-v1","epoch":213,"plan":binding,"publisher_sha256":self_sha,"verification":plan.verification,"initial_anchor":plan.initial_anchor,"archive_sha256":plan.archive_sha256,"archive_bytes":plan.archive_bytes,"expected_provenance_sha256":PROVENANCE,"private_runner_sha256":RUNNER,"rename_mount_id":rename_mount_id,"write_scope":write_scope,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
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
    let staged = plan.publication_stage.join("epoch-213.jet");
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
        &[213],
        &[ArchiveBatchItem {
            epoch: 213,
            staged_archive: staged,
            destination_archive: destination.join("epoch-213.jet"),
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
    receipt.json(&json!({"schema":"jetstreamer-exact-epoch213-v4-publication-receipt-v1","epoch":213,"context":context,"transaction_id":sha256_hex_string(&publication.transaction_id),"archive_path":item.archive_path,"checksum_path":item.checksum_path,"archive_sha256":plan.archive_sha256,"archive_bytes":plan.archive_bytes,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,"private_runner_sha256":RUNNER,"committed":true,"original_assembly_preserved":true,"runtime_registry_promoted":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}))?;
    // Receipt is durable before either uploader gate becomes parseable. These
    // held root-owned descriptors cannot replace any existing .ok receipt.
    full_gate.write(format!("{} {FULL} {RUNNER}\n", plan.archive_sha256).as_bytes())?;
    plugin_gate.write(format!("{} {PLUGIN} {RUNNER}\n", plan.archive_sha256).as_bytes())?;
    acknowledge_archive_publication_batch(destination, publication.transaction_id)?;
    println!("epoch213 exact V4 artifact committed locally; no R2 mutation or registry promotion");
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
                .starts_with("horizon-213-publication-capability-")),
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
    let staged = stage.join("epoch-213.jet");
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
    let context = b"epoch213 private filesystem capability only; no archive admission";
    let publication = publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
        Sha256::digest(context).into(),
        &[213],
        &[ArchiveBatchItem {
            epoch: 213,
            staged_archive: staged,
            destination_archive: destination.join("epoch-213.jet"),
            evidence,
        }],
        context,
        Duration::from_secs(5),
    )?;
    sink.json(&json!({"schema":"jetstreamer-private-epoch213-publication-capability-v1","publisher_sha256":self_sha,"diagnostic_fixture":true,"rename_mount_id":rename_mount_id,"write_scope":write_scope,"outside_write_denied":true,"filesystem_transaction_passed":true,"root_receipt_fd_survives_permanent_privilege_drop":true,"effective_uid":unsafe{libc::geteuid()},"archive_sha256":sha256_hex_string(&evidence.sha256),"transaction_id":sha256_hex_string(&publication.transaction_id),"archive_publication_authorized":false,"runtime_registry_promotion_authorized":false,"r2_mutations":false}))?;
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
        "usage: jetstreamer-epoch213-publish PLAN --plan-sha256 HEX --self-sha256 HEX"
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
    fn plan() -> Plan {
        serde_json::from_value(json!({"schema":"jetstreamer-private-epoch213-v4-publication-plan-v1","verification":{"path":"/var/lib/private/verification.json","sha256":"a".repeat(64)},"initial_anchor":{"path":"/var/lib/private/anchor.json","sha256":ANCHOR_EVIDENCE},"archive_sha256":"b".repeat(64),"archive_bytes":100,"publication_stage":"/var/lib/jetstreamer/horizon-213-publication-work-test/stage","receipt_directory":"/var/lib/private/publication","full_receipt_directory":"/var/lib/private/full","plugin_receipt_directory":"/var/lib/private/plugin","artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false})).unwrap()
    }
    fn verification() -> Value {
        let path = "/var/lib/jetstreamer/horizon-213-private-scan-test/epoch-213.jet";
        json!({"schema":"jetstreamer-private-epoch213-verification-v1","epoch":213,"runner_sha256":RUNNER,"archive_sha256":"b".repeat(64),"expected_provenance_sha256":PROVENANCE,"archive_path":path,"archive_identity":{"dev":1,"ino":2,"len":100,"uid":0,"gid":0,"mode":0o100400,"links":1,"mtime":1,"mtime_ns":0,"ctime":1,"ctime_ns":0},"full":{"binary":{"sha256":FULL},"exit_code":0,"arguments":expected_full(path)},"plugin":{"binary":{"sha256":PLUGIN},"exit_code":0,"arguments":["213:213","/var/lib/jetstreamer/horizon-213-private-scan-test","--threads","8","--verify-only"]},"provenance_expectation":{"sha256":EXPECTATION},"independent_final_archive_verification_passed":true,"current_plugin_verification_passed":true,"runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn exact_full_and_plugin_binding_is_required() {
        validate_verification(&verification(), &plan()).unwrap();
        for (pointer, value) in [
            ("/runner_sha256", json!(FULL)),
            ("/epoch", json!(301)),
            ("/full/arguments", json!(["--full", "--internal-full"])),
            ("/full/exit_code", json!(1)),
            ("/plugin/arguments", json!(["213:213", "--bench"])),
            ("/archive_identity/len", json!(99)),
            ("/archive_identity/links", json!(2)),
            ("/archive_sha256", json!("c".repeat(64))),
            ("/provenance_expectation/sha256", json!(FULL)),
            ("/publication_authorized", json!(true)),
            ("/current_plugin_verification_passed", json!(false)),
        ] {
            let mut changed = verification();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_verification(&changed, &plan()).is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn authority_cannot_expand_to_registry_remote_or_other_epoch() {
        let p = plan();
        validate_plan(&p).unwrap();
        let mut p = plan();
        p.r2_mutations = true;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.runtime_registry_promotion_authorized = true;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.artifact_publication_authorized = false;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.publication_stage = "/home/ubuntu/horizon".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.full_receipt_directory = p.plugin_receipt_directory.clone();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn canonical_digests_only() {
        assert!(digest(&"a".repeat(64)).is_ok());
        for value in ["A".repeat(64), "b".repeat(63), "g".repeat(64)] {
            assert!(digest(&value).is_err());
        }
    }

    #[test]
    fn dedicated_work_parent_keeps_absent_stage_inside_exact_private_namespace() {
        let mut p = plan();
        p.publication_stage = "/var/lib/jetstreamer/horizon-213-publication-work-test/stage".into();
        validate_plan(&p).unwrap();
        for path in [
            "/var/lib/jetstreamer/other/stage",
            "/var/lib/jetstreamer/horizon-214-publication-work-test/stage",
            "/var/lib/jetstreamer/horizon-213-publication-work-test/other",
            "/var/lib/jetstreamer/horizon-213-publication-work-test/nested/stage",
            "/home/ubuntu/horizon-213-publication-work-test/stage",
        ] {
            p.publication_stage = path.into();
            assert!(validate_plan(&p).is_err(), "{path}");
        }
    }
    #[test]
    fn sinks_never_overwrite_or_accept_nonprivate_parent() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut sink = Sink::create(dir.path(), "test.json").unwrap();
        sink.json(&json!({"complete":true})).unwrap();
        assert!(sink.write(b"replacement").is_err());
        assert!(Sink::create(dir.path(), "test.json").is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Sink::create(dir.path(), "other.json").is_err());
    }
    #[test]
    fn producer_scope_cannot_be_substituted() {
        let good = json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-v1","producer_unit":"horizon-qualify-213-checkpoint-continuation-ae43646-v1.service","producer_invocation_id":"1dfd29e7ced140b3ba407359cbdc0ee1","node_sha256":"83398ece0317a6ab3b321f9e1eb8d0c7f76f21f1cb5997cd07899ba19f2992f3","plan":{"sha256":"83eeb441502e39510ad7610ae6dac9165d9f5a6f32afaeab1f19205e9ab6f144"},"prefix_archive_sha256":"e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9","suffix_archive_sha256":"3360ba3da029865522511a821c30851447a7a6eca5e9fe28cd536181edf07d03","restart_snapshot_sha256":"bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08","fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,"canonical_root_slot":92447542,"assembly":{"slots_merged":432000,"source_archives":2,"provenance_version":4}});
        validate_producer(&good).unwrap();
        for (pointer, value) in [
            ("/producer_invocation_id", json!("foreign")),
            ("/node_sha256", json!(FULL)),
            ("/prefix_archive_sha256", json!(PLUGIN)),
            ("/suffix_archive_sha256", json!(PLUGIN)),
            ("/restart_snapshot_sha256", json!(FULL)),
            ("/assembly/slots_merged", json!(431999)),
            ("/canonical_root_slot", json!(92447999)),
            ("/fresh_native_checkpoint_matches", json!(false)),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_producer(&changed).is_err(), "{pointer}");
        }
    }
    #[test]
    fn duplicate_or_unknown_plan_fields_fail_closed() {
        assert!(
            serde_json::from_str::<Plan>(r#"{"schema":"x","schema":"y"}"#)
                .unwrap_err()
                .to_string()
                .contains("duplicate field")
        );
        assert!(
            serde_json::from_str::<Plan>(r#"{"unreviewed_authority":true}"#)
                .unwrap_err()
                .to_string()
                .contains("unknown field")
        );
    }
    #[test]
    fn root_evidence_rejects_changed_bytes_symlinks_and_hardlinks() {
        use std::os::unix::fs::PermissionsExt;
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence");
        fs::write(&path, b"bound bytes").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let expected = Evidence {
            path: path.clone(),
            sha256: format!("{:x}", Sha256::digest(b"bound bytes")),
        };
        root_evidence(&expected, 1024).unwrap();
        assert!(root_evidence(&expected, 3).is_err());
        fs::write(&path, b"other bytes").unwrap();
        assert!(root_evidence(&expected, 1024).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            root_evidence(
                &Evidence {
                    path: link,
                    sha256: expected.sha256.clone()
                },
                1024
            )
            .is_err()
        );
        fs::hard_link(&path, dir.path().join("hard")).unwrap();
        assert!(root_evidence(&expected, 1024).is_err());
    }
}
