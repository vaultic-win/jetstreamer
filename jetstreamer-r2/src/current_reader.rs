//! Current-branch verification of staged archives and authenticated R2 readback.
//! Transport remains in the uploader; this module never writes remote objects.
pub(crate) mod staged247;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[path = "current_reader/operator_equivalence205.rs"]
mod operator_equivalence205;
#[path = "current_reader/recovery205.rs"]
pub mod recovery205;

// Conservative closure: changes to any reader crate, workspace resolution,
// vendored dependency, build input or compiler configuration require qualification.
const READER_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    ".cargo",
    "src",
    "jetstreamer-firehose",
    "jetstreamer-horizon",
    "jetstreamer-plugin",
    "jetstreamer-utils",
    "vendor",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
];

// The staged publication build checks these scopes against the actual pipeline
// and full verifier depfiles, including their external PoH source and the
// existing utility library. Standalone utility binaries do not enter either
// reader. Cargo resolution, features, build scripts and vendor trees do.
const PUBLISHED_READER_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    ".cargo",
    "build.rs",
    "rust-toolchain",
    "rust-toolchain.toml",
    "vendor",
    "src",
    "jetstreamer-horizon",
    "jetstreamer-firehose",
    "jetstreamer-plugin",
    "historical-runtime/v1_0_8/worker/src/poh_backend.rs",
    "jetstreamer-utils/Cargo.toml",
    "jetstreamer-utils/build.rs",
    "jetstreamer-utils/build_support",
    "jetstreamer-utils/src/lib.rs",
    "jetstreamer-utils/src/clickhouse.rs",
    "jetstreamer-utils/src/horizon_legacy_shred.rs",
    "jetstreamer-utils/src/horizon_legacy_entry.rs",
    "jetstreamer-utils/src/horizon_legacy_poh.rs",
    "jetstreamer-utils/src/horizon_legacy_source.rs",
    "jetstreamer-utils/src/horizon_legacy_bundle.rs",
    "jetstreamer-utils/src/horizon_legacy_acquisition.rs",
    "jetstreamer-utils/src/horizon_legacy_byte_diagnostic.rs",
    "jetstreamer-utils/src/horizon_legacy_recovery.rs",
    "jetstreamer-utils/src/horizon_legacy_v1_5_6.rs",
    "jetstreamer-utils/src/horizon_ledger_tar.rs",
    "jetstreamer-utils/src/horizon_ledger_bzip.rs",
];

fn reader_paths(plan: &Plan) -> &'static [&'static str] {
    if staged247::published_reader(plan) {
        PUBLISHED_READER_PATHS
    } else {
        READER_PATHS
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    repository: PathBuf,
    origin_url: String,
    reader_commit: String,
    pipeline: Bound,
    full_verifier: Bound,
    qualification: Bound,
    scratch_directory: PathBuf,
    threads: usize,
    maximum_archive_bytes: u64,
    minimum_free_bytes: u64,
    epoch_expectations: BTreeMap<u64, Bound>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochExpectation {
    schema: String,
    epoch: u64,
    parent_slot: u64,
    parent_blockhash: String,
    terminal_slot: u64,
    terminal_blockhash: String,
    provenance_sha256: Option<String>,
    independent_evidence: Vec<Bound>,
    #[serde(default)]
    successor: Option<SuccessorExpectation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuccessorExpectation {
    slot: u64,
    response: Bound,
    request: Bound,
}

fn validate_successor_values(
    e: &EpochExpectation,
    response: &Value,
    request: &Value,
) -> Result<()> {
    let s = e.successor.as_ref().context("missing successor")?;
    let end = e
        .epoch
        .checked_add(1)
        .and_then(|n| n.checked_mul(432000))
        .context("epoch overflow")?;
    let expected_request = json!([s.slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]);
    ensure!(
        s.slot >= end
            && request["endpoint"] == "https://api.mainnet-beta.solana.com"
            && request["request"]["jsonrpc"] == "2.0"
            && request["request"]["method"] == "getBlock"
            && request["request"]["params"] == expected_request
            && request["response_sha256"] == s.response.sha256
            && response["jsonrpc"] == "2.0"
            && response["id"].as_u64().is_some()
            && response["id"] == request["request"]["id"]
            && response.get("error").is_none()
            && response["result"]["parentSlot"] == e.terminal_slot
            && response["result"]["previousBlockhash"] == e.terminal_blockhash,
        "successor RPC evidence does not prove skipped epoch tail"
    );
    let blockhash = response["result"]["blockhash"]
        .as_str()
        .context("successor blockhash")?;
    ensure!(
        bs58::decode(blockhash)
            .into_vec()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .len()
            == 32,
        "invalid successor blockhash"
    );
    ensure!(
        e.independent_evidence.contains(&s.response) && e.independent_evidence.contains(&s.request),
        "successor not bound in independent evidence"
    );
    Ok(())
}

fn full_arguments(
    archive: &Path,
    epoch: u64,
    threads: usize,
    e: &EpochExpectation,
) -> Result<Vec<String>> {
    let first = epoch.checked_mul(432000).context("epoch overflow")?;
    let last = first.checked_add(431999).context("epoch overflow")?;
    ensure!(
        ((e.schema == "horizon-current-reader-epoch-expectation-v1"
            && e.successor.is_none()
            && e.terminal_slot == last)
            || (e.schema == "horizon-current-reader-epoch-expectation-v2"
                && e.successor.is_some()
                && (first..last).contains(&e.terminal_slot)))
            && e.epoch == epoch
            && e.parent_slot < first
            && !e.independent_evidence.is_empty(),
        "missing independent full-epoch parent/terminal expectations"
    );
    for hash in [&e.parent_blockhash, &e.terminal_blockhash] {
        // bs58's std feature is not required by the standalone uploader.
        // Do not rely on another workspace target enabling its StdError impl.
        let decoded = bs58::decode(hash)
            .into_vec()
            .map_err(|error| anyhow::anyhow!("invalid boundary blockhash: {error}"))?;
        ensure!(decoded.len() == 32, "invalid boundary blockhash");
    }
    let mut args = vec![
        archive.to_str().context("non-UTF8 archive")?.into(),
        "--full".into(),
        "--threads".into(),
        threads.to_string(),
        "--anchor".into(),
        e.parent_slot.to_string(),
        e.parent_blockhash.clone(),
        "--expected-terminal".into(),
        e.terminal_slot.to_string(),
        e.terminal_blockhash.clone(),
    ];
    if let Some(s) = &e.successor {
        validate_successor_values(e, &bound_json(&s.response)?, &bound_json(&s.request)?)?;
        args.extend([
            "--expected-successor".into(),
            s.slot.to_string(),
            e.terminal_slot.to_string(),
            e.terminal_blockhash.clone(),
        ]);
    }
    if let Some(digest) = &e.provenance_sha256 {
        ensure!(hex(digest, 64), "invalid expected provenance digest");
        args.extend(["--expected-provenance-sha256".into(), digest.clone()]);
    }
    Ok(args)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Qualification {
    schema: String,
    reader_commit: String,
    pipeline: Bound,
    full_verifier: Bound,
    cargo_features: Vec<String>,
    rustc_flags: Vec<String>,
    // Some qualified builds need larger native worker stacks. Bind the value
    // into immutable acceptance instead of relying on the operator's shell.
    #[serde(default)]
    minimum_thread_stack_bytes: Option<u64>,
    source_build_evidence: Vec<Bound>,
    source_artifact_correspondence_accepted: bool,
    full_and_plugin_capabilities_accepted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteObject {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub length: u64,
    pub sha256: String,
}

pub struct Gate {
    plan: Plan,
    plan_binding: Bound,
    epoch: u64,
    length: u64,
    digest: String,
    directory: PathBuf,
    retained: Option<staged247::Retained>,
    local_playback: Value,
    remote_playback: Option<Value>,
    minimum_thread_stack_bytes: Option<u64>,
}

fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(before.is_file(), "not a regular file: {}", path.display());
    let mut digest = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "file changed while hashing"
    );
    Ok((format!("{:x}", digest.finalize()), before.len()))
}

fn bound_file(binding: &Bound) -> Result<()> {
    ensure!(
        hex(&binding.sha256, 64)
            && binding.path.is_absolute()
            && binding.path.canonicalize()? == binding.path,
        "invalid evidence binding"
    );
    let m = fs::symlink_metadata(&binding.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0,
        "evidence must be root-owned and immutable"
    );
    ensure!(
        hash_file(&binding.path)?.0 == binding.sha256,
        "evidence digest mismatch: {}",
        binding.path.display()
    );
    Ok(())
}

fn bound_json(binding: &Bound) -> Result<Value> {
    bound_file(binding)?;
    ensure!(
        fs::metadata(&binding.path)?.len() <= 1024 * 1024,
        "oversized reader metadata"
    );
    let bytes = fs::read(&binding.path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == binding.sha256,
        "reader metadata changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn private_directory(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical private directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "reader scratch must be a root-owned private directory"
    );
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<Bound> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(&bytes)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(Bound {
        path: path.into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}

fn git(plan: &Plan, args: &[&str]) -> Result<String> {
    // Verification runs as root, but a fetch must not leave root-owned objects
    // in the operator's repository and prevent subsequent commits or pushes.
    let owner = fs::metadata(&plan.repository)?;
    let output = Command::new("/usr/bin/git")
        .uid(owner.uid())
        .gid(owner.gid())
        .arg("-c")
        .arg(format!("safe.directory={}", plan.repository.display()))
        .arg("-C")
        .arg(&plan.repository)
        .args(args)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "reader Git command {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn current_branch(plan: &Plan) -> Result<(String, Value)> {
    ensure!(
        git(plan, &["remote", "get-url", "origin"])? == plan.origin_url,
        "reader repository origin changed"
    );
    git(
        plan,
        &[
            "fetch",
            "origin",
            "refs/heads/account-updates:refs/remotes/origin/account-updates",
        ],
    )?;
    let head = git(
        plan,
        &["rev-parse", "refs/remotes/origin/account-updates^{commit}"],
    )?;
    ensure!(hex(&head, 40), "invalid fetched reader commit");
    git(
        plan,
        &["merge-base", "--is-ancestor", &plan.reader_commit, &head],
    )?;
    let mut args = vec![
        "diff",
        "--name-only",
        "--no-renames",
        &plan.reader_commit,
        &head,
        "--",
    ];
    args.extend_from_slice(reader_paths(plan));
    let changed = git(plan, &args)?;
    if !changed.is_empty() {
        // Only the individually reviewed exact operator-only blob transition is
        // equivalent. Any additional/revised source, dependency, feature, mode or
        // compiler/build input still requires qualification and full playback.
        operator_equivalence205::validate(plan, &head, &changed).context(
            "current account-updates reader changed; qualify new artifacts and repeat full playback",
        )?;
    }
    let equivalence = if changed.is_empty() {
        json!({"schema":"horizon-reader-byte-identical-source-v1",
            "compared_paths":reader_paths(plan)})
    } else {
        operator_equivalence205::record(&changed)
    };
    Ok((head, equivalence))
}

fn validate_qualification(plan: &Plan, q: &Qualification) -> Result<()> {
    validate_thread_stack(q.minimum_thread_stack_bytes)?;
    ensure!(
        q.schema == "horizon-current-reader-main-acceptance-v1"
            && q.reader_commit == plan.reader_commit
            && q.pipeline == plan.pipeline
            && q.full_verifier == plan.full_verifier
            && q.source_artifact_correspondence_accepted
            && q.full_and_plugin_capabilities_accepted
            && !q.source_build_evidence.is_empty(),
        "missing exact current-reader qualification"
    );
    // Feature/flag sets are retained in the hashed Main acceptance, not inferred
    // from an unrelated binary's name or a commit's ancestry.
    ensure!(
        q.cargo_features
            .iter()
            .chain(&q.rustc_flags)
            .all(|s| !s.is_empty()),
        "invalid compiler configuration evidence"
    );
    Ok(())
}

fn validate_thread_stack(bytes: Option<u64>) -> Result<()> {
    ensure!(
        bytes.is_none_or(|bytes| (2 * 1024 * 1024..=64 * 1024 * 1024).contains(&bytes)),
        "qualified reader thread stack must be between 2 and 64 MiB"
    );
    Ok(())
}

fn configure_thread_stack(command: &mut Command, bytes: Option<u64>) -> Result<()> {
    validate_thread_stack(bytes)?;
    if let Some(bytes) = bytes {
        command.env("RUST_MIN_STACK", bytes.to_string());
    }
    Ok(())
}

fn validate_report(report: &Value, epoch: u64, source: &str, invocation: &[String]) -> Result<()> {
    let first = epoch.checked_mul(432000).context("epoch range overflow")?;
    let last = first.checked_add(431999).context("epoch range overflow")?;
    let r = &report["report"];
    ensure!(
        report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && report["full_epoch_verified"] == true
            && report["source"] == json!(source)
            && report["invocation"] == json!(invocation)
            && report["expected_first_slot"] == first
            && report["expected_last_slot"] == last
            && r["epoch"] == epoch
            && r["first_slot"] == first
            && r["last_slot"] == last
            && r["slots"] == 432000
            && r["worker_count"].as_u64().is_some_and(|n| n > 0),
        "plugin report does not prove the requested full epoch and invocation"
    );
    ensure!(
        r["blocks"]
            .as_u64()
            .zip(r["skipped"].as_u64())
            .and_then(|(a, b)| a.checked_add(b))
            == Some(432000),
        "plugin slot totals differ"
    );
    for key in [
        "entries",
        "transactions",
        "transaction_updates",
        "orphan_updates",
        "epoch_updates",
        "account_data_bytes",
    ] {
        ensure!(r[key].as_u64().is_some(), "missing plugin count {key}");
    }
    ensure!(
        r["stream_digest"].as_array().is_some_and(
            |a| a.len() == 32 && a.iter().all(|v| v.as_u64().is_some_and(|b| b <= 255))
        ),
        "missing plugin stream digest"
    );
    Ok(())
}

// Source and invocation differ between the two independently validated reports.
// Compare the full plugin payload, including every counter and stream digest.
fn matching_playback(local: &Value, public: &Value) -> Result<()> {
    let local = local["report"]["report"]
        .as_object()
        .context("missing local plugin counters")?;
    let public = public["report"]["report"]
        .as_object()
        .context("missing public plugin counters")?;
    ensure!(
        local == public,
        "public verification counters or stream digest differ from local playback"
    );
    Ok(())
}

fn check_readback_capacity(plan: &Plan, length: u64) -> Result<()> {
    // This is an operation-specific admission check, not another replay poll.
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(plan.scratch_directory.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "readback filesystem capacity unavailable"
    );
    let stat = unsafe { stat.assume_init() };
    let free = u128::from(stat.f_bavail) * u128::from(stat.f_frsize);
    ensure!(
        free >= u128::from(plan.minimum_free_bytes) + u128::from(length),
        "readback copy would cross admitted filesystem floor"
    );
    Ok(())
}

impl Gate {
    pub fn prepare(
        binding: Bound,
        epoch: u64,
        archive: &Path,
        length: u64,
        digest: &str,
        retained: Option<staged247::Retained>,
    ) -> Result<Self> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "current-reader verification requires root"
        );
        let plan: Plan = serde_json::from_value(bound_json(&binding)?)?;
        ensure!(
            plan.schema == "horizon-current-reader-plan-v1"
                && hex(&plan.reader_commit, 40)
                && hex(digest, 64)
                && length > 0
                && length <= plan.maximum_archive_bytes
                && (1..=32).contains(&plan.threads)
                && plan.minimum_free_bytes > 0
                && plan.repository.is_absolute()
                && plan.repository.canonicalize()? == plan.repository
                && (plan.origin_url.starts_with("git@") || plan.origin_url.starts_with("ssh://")),
            "invalid current-reader plan"
        );
        let qualification: Qualification =
            serde_json::from_value(bound_json(&plan.qualification)?)?;
        validate_qualification(&plan, &qualification)?;
        for evidence in &qualification.source_build_evidence {
            bound_file(evidence)?;
        }
        bound_file(&plan.pipeline)?;
        bound_file(&plan.full_verifier)?;
        let expectation_binding = plan
            .epoch_expectations
            .get(&epoch)
            .context("missing epoch boundary evidence")?;
        let expectation: EpochExpectation =
            serde_json::from_value(bound_json(expectation_binding)?)?;
        let full_args = full_arguments(archive, epoch, plan.threads, &expectation)?;
        for evidence in &expectation.independent_evidence {
            bound_file(evidence)?;
        }
        private_directory(&plan.scratch_directory)?;
        let (current, source_equivalence) = current_branch(&plan)?;
        check_readback_capacity(
            &plan,
            if retained.is_some() {
                staged247::BUDGET
            } else {
                0
            },
        )?;
        let directory = plan.scratch_directory.join(format!(
            "epoch-{epoch}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let mut gate = Self {
            plan,
            plan_binding: binding,
            epoch,
            length,
            digest: digest.into(),
            directory,
            retained,
            local_playback: Value::Null,
            remote_playback: None,
            minimum_thread_stack_bytes: qualification.minimum_thread_stack_bytes,
        };
        ensure!(
            archive.file_name().and_then(|n| n.to_str()) == Some(&format!("epoch-{epoch}.jet")),
            "noncanonical local archive name"
        );
        let args = full_args;
        gate.command(&gate.plan.full_verifier, &args)?;
        gate.local_playback = gate.playback(
            archive
                .parent()
                .and_then(Path::to_str)
                .context("archive parent")?,
            "local",
            None,
        )?;
        write_json(
            &gate.directory.join("local-acceptance.json"),
            &json!({"schema":"horizon-current-reader-local-acceptance-v1","fetched_branch_commit":current,"source_equivalence":source_equivalence,"reader_plan":gate.plan_binding,"local_playback":gate.local_playback,"full_verifier":gate.plan.full_verifier,"full_invocation":args,"full_exit_code":0,"minimum_thread_stack_bytes":gate.minimum_thread_stack_bytes}),
        )?;
        Ok(gate)
    }

    fn command(&self, executable: &Bound, args: &[String]) -> Result<()> {
        bound_file(executable)?;
        let mut command = Command::new(&executable.path);
        command.args(args).stdin(Stdio::null());
        configure_thread_stack(&mut command, self.minimum_thread_stack_bytes)?;
        let status = command.status()?;
        ensure!(
            status.success(),
            "reader {} failed with {status}; no readiness publication permitted",
            executable.path.display()
        );
        bound_file(executable)
    }

    fn playback(&self, source: &str, label: &str, inventory: Option<&Bound>) -> Result<Value> {
        let path = self.directory.join(format!("{label}-plugin.json"));
        let mut args = vec![
            self.epoch.to_string(),
            source.into(),
            "--verify-only".into(),
            "--threads".into(),
            self.plan.threads.to_string(),
            "--verification-report".into(),
            path.to_str().context("non-UTF8 report")?.into(),
        ];
        if let Some(binding) = inventory {
            bound_file(binding)?;
            args.extend([
                "--archive-inventory".into(),
                binding.path.to_str().context("non-UTF8 inventory")?.into(),
            ]);
        }
        self.command(&self.plan.pipeline, &args)?;
        let mut invocation = vec![
            self.plan
                .pipeline
                .path
                .to_str()
                .context("non-UTF8 pipeline")?
                .into(),
        ];
        invocation.extend(args);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.len() <= 1024 * 1024,
            "invalid plugin result file"
        );
        let report: Value = serde_json::from_slice(&fs::read(&path)?)?;
        validate_report(&report, self.epoch, source, &invocation)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        File::open(&path)?.sync_all()?;
        let binding = Bound {
            path,
            sha256: hash_file(&self.directory.join(format!("{label}-plugin.json")))?.0,
        };
        Ok(
            json!({"report":report,"report_binding":binding,"pipeline":self.plan.pipeline,"invocation":invocation,"process_exit_code":0}),
        )
    }

    /// The caller hashes the authenticated stream. The staged recovery additionally
    /// compares those bytes with its retained, identity-bound inode.
    pub fn create_readback(&self) -> Result<staged247::Sink> {
        if let Some(prior) = &self.retained {
            check_readback_capacity(&self.plan, staged247::BUDGET)?;
            return prior.stream();
        }
        Ok(staged247::Sink::HashOnly)
    }

    pub fn verify_remote(&mut self, remote: RemoteObject, public_origin: &str) -> Result<()> {
        self.remote_playback = None;
        ensure!(
            remote.key == format!("epoch-{}.jet", self.epoch)
                && remote.length == self.length
                && remote.sha256 == self.digest
                && !remote.bucket.is_empty()
                && !remote.etag.is_empty(),
            "remote playback identity mismatch"
        );
        if let Some(prior) = &self.retained {
            prior.verify_object(&remote)?;
            prior.proof()?;
        }
        let inventory = write_json(
            &self.directory.join("public-archive-inventory.json"),
            &json!({
                "schema":"horizon-r2-chronological-audit-inventory-v1",
                "bucket":remote.bucket, "observed_at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                "objects":[{"epoch":self.epoch, "key":remote.key, "bytes":remote.length,
                    "etag":format!("\"{}\"",remote.etag)}]
            }),
        )?;
        let result = self.playback(public_origin, "remote", Some(&inventory))?;
        matching_playback(&self.local_playback, &result)?;
        self.remote_playback = Some(json!({
            "object":remote, "public_origin":public_origin, "archive_inventory":inventory,
            "playback":result
        }));
        Ok(())
    }

    /// Invoke after local source revalidation and remote identity recheck, just
    /// before committing the readiness sidecar. Missing playback fails closed.
    pub fn publication_receipt(&self) -> Result<Bound> {
        let remote = self
            .remote_playback
            .as_ref()
            .context("full remote plugin playback is missing")?;
        let reuse = self.retained.as_ref().map(|r| r.proof()).transpose()?;
        let (current, source_equivalence) = current_branch(&self.plan)?;
        bound_file(&self.plan.pipeline)?;
        bound_file(&self.plan.full_verifier)?;
        let mut receipt = json!({
            "schema":"horizon-r2-current-reader-playback-acceptance-v1",
            "epoch":self.epoch,"reader_commit":self.plan.reader_commit,
            "fetched_branch_commit_before_sidecar":current,"compared_reader_paths":reader_paths(&self.plan),
            "source_equivalence":source_equivalence,
            "reader_plan":self.plan_binding,"qualification":self.plan.qualification,
            "local_playback":self.local_playback,"remote_playback":remote,
            "minimum_thread_stack_bytes":self.minimum_thread_stack_bytes,
            "verified_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "readiness_sidecar_committed":false
        });
        if let Some(proof) = reuse {
            receipt["retained_staged_readback_verified"] = proof;
        }
        write_json(
            &self.directory.join("remote-playback-acceptance.json"),
            &receipt,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "root native validation of sealed independent skipped-tail RPC evidence"]
    fn native_skipped_tail_expectation_generates_strict_verifier_arguments() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let binding: Bound =
            serde_json::from_str(&std::env::var("HORIZON_TEST_TAIL_EXPECTATION").unwrap()).unwrap();
        let e: EpochExpectation = serde_json::from_value(bound_json(&binding).unwrap()).unwrap();
        let args = full_arguments(Path::new("/private/epoch-251.jet"), 251, 2, &e).unwrap();
        let i = args
            .iter()
            .position(|x| x == "--expected-successor")
            .unwrap();
        assert_eq!(&args[i + 1..i + 3], &["108864012", "108863995"]);
        assert_eq!(args[i + 3], "86y6Vyi2ZFR8e9wXhnsS2NSrnuH7rFwZYdu3pHLVHufa");
        assert!(args.iter().any(|x| x == "--full"));
        assert!(!args.iter().any(|x| x == "--internal-full"));
        for evidence in &e.independent_evidence {
            bound_file(evidence).unwrap();
        }
        let mut wrong = e;
        wrong.schema = "horizon-current-reader-epoch-expectation-v1".into();
        assert!(full_arguments(Path::new("/private/epoch-251.jet"), 251, 2, &wrong).is_err());
    }

    fn complete_report() -> Value {
        json!({"schema":"jetstreamer-horizon-plugin-playback-v1", "source":"/readback",
            "invocation":["pipeline", "--verify-only"], "full_epoch_verified":true,
            "expected_first_slot":108432000u64, "expected_last_slot":108863999u64,
            "report":{"epoch":251,"first_slot":108432000u64,"last_slot":108863999u64,
                "slots":432000,"worker_count":4,"blocks":431999,"skipped":1,
                "entries":1,"transactions":1,"transaction_updates":1,"orphan_updates":1,
                "epoch_updates":1,"account_data_bytes":1,"stream_digest":vec![0;32]}})
    }

    fn check(v: &Value) -> Result<()> {
        validate_report(
            v,
            251,
            "/readback",
            &["pipeline".into(), "--verify-only".into()],
        )
    }

    #[test]
    fn local_public_equality_requires_matching_counters_and_digest() {
        let local = json!({"report":complete_report()});
        let mut public = local.clone();
        public["report"]["source"] = json!("https://fixture.invalid/");
        matching_playback(&local, &public).unwrap();
        for key in local["report"]["report"].as_object().unwrap().keys() {
            let mut bad = public.clone();
            bad["report"]["report"].as_object_mut().unwrap().remove(key);
            assert!(matching_playback(&local, &bad).is_err(), "{key}");
        }
        assert!(matching_playback(&Value::Null, &Value::Null).is_err());
        public["report"]["report"]["stream_digest"][0] = json!(255);
        assert!(matching_playback(&local, &public).is_err());
    }

    #[test]
    fn complete_playback_accepts_legitimate_leader_skips() {
        check(&complete_report()).unwrap();
    }

    #[test]
    fn full_verifier_gets_independent_parent_terminal_and_provenance() {
        let mut e = EpochExpectation {
            schema: "horizon-current-reader-epoch-expectation-v1".into(),
            epoch: 251,
            parent_slot: 108431999,
            parent_blockhash: bs58::encode([1; 32]).into_string(),
            terminal_slot: 108863999,
            terminal_blockhash: bs58::encode([2; 32]).into_string(),
            provenance_sha256: Some("a".repeat(64)),
            independent_evidence: vec![Bound {
                path: "/expectation".into(),
                sha256: "b".repeat(64),
            }],
            successor: None,
        };
        let args = full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).unwrap();
        assert!(
            args.windows(3)
                .any(|v| v[0] == "--anchor" && v[1] == "108431999" && v[2] == e.parent_blockhash)
        );
        assert!(args.windows(3).any(|v| v[0] == "--expected-terminal"
            && v[1] == "108863999"
            && v[2] == e.terminal_blockhash));
        assert!(
            args.windows(2)
                .any(|v| v[0] == "--expected-provenance-sha256" && v[1] == "a".repeat(64))
        );
        for invalid in ["0".to_string(), bs58::encode([1; 31]).into_string()] {
            let parent = std::mem::replace(&mut e.parent_blockhash, invalid.clone());
            assert!(full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).is_err());
            e.parent_blockhash = parent;
            let terminal = std::mem::replace(&mut e.terminal_blockhash, invalid);
            assert!(full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).is_err());
            e.terminal_blockhash = terminal;
        }
        e.terminal_slot -= 1;
        assert!(full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).is_err());
        e.terminal_slot += 1;
        e.parent_slot += 1;
        assert!(full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).is_err());
        e.parent_slot -= 1;
        e.independent_evidence.clear();
        assert!(full_arguments(Path::new("/epoch-251.jet"), 251, 2, &e).is_err());
    }

    #[test]
    fn skipped_tail_requires_bound_finalized_successor_rpc() {
        let response_binding = Bound {
            path: "/successor.json".into(),
            sha256: "a".repeat(64),
        };
        let request_binding = Bound {
            path: "/request.json".into(),
            sha256: "b".repeat(64),
        };
        let hash = bs58::encode([1; 32]).into_string();
        let mut e = EpochExpectation {
            schema: "horizon-current-reader-epoch-expectation-v2".into(),
            epoch: 251,
            parent_slot: 108431999,
            parent_blockhash: hash.clone(),
            terminal_slot: 108863995,
            terminal_blockhash: hash.clone(),
            provenance_sha256: None,
            independent_evidence: vec![response_binding.clone(), request_binding.clone()],
            successor: Some(SuccessorExpectation {
                slot: 108864012,
                response: response_binding,
                request: request_binding,
            }),
        };
        let response = json!({"jsonrpc":"2.0","id":7,"result":{"parentSlot":108863995,"previousBlockhash":hash,"blockhash":hash}});
        let request = json!({"endpoint":"https://api.mainnet-beta.solana.com","response_sha256":"a".repeat(64),"request":{"jsonrpc":"2.0","id":7,"method":"getBlock","params":[108864012,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]}});
        validate_successor_values(&e, &response, &request).unwrap();
        for (pointer, value) in [
            ("/result/parentSlot", json!(108863994)),
            (
                "/result/previousBlockhash",
                json!(bs58::encode([2; 32]).into_string()),
            ),
            ("/id", json!(8)),
            ("/error", json!({"code":-1})),
        ] {
            let mut wrong = response.clone();
            if pointer == "/error" {
                wrong["error"] = value;
            } else {
                *wrong.pointer_mut(pointer).unwrap() = value;
            }
            assert!(validate_successor_values(&e, &wrong, &request).is_err());
        }
        let mut wrong = request.clone();
        wrong["request"]["params"][1]["commitment"] = json!("confirmed");
        assert!(validate_successor_values(&e, &response, &wrong).is_err());
        e.independent_evidence.clear();
        assert!(validate_successor_values(&e, &response, &request).is_err());
    }

    #[test]
    fn incomplete_wrong_epoch_or_wrong_source_playback_is_rejected() {
        for (pointer, replacement) in [
            ("/report/epoch", json!(250)),
            ("/report/first_slot", json!(108432001)),
            ("/report/last_slot", json!(108863998)),
            ("/report/slots", json!(431999)),
            ("/report/worker_count", json!(0)),
            ("/report/blocks", json!(432000)),
            ("/source", json!("/original-local")),
            ("/full_epoch_verified", json!(false)),
            ("/invocation", json!(["pipeline", "--bench"])),
            ("/report/stream_digest", json!([0])),
            ("/report/account_data_bytes", Value::Null),
        ] {
            let mut v = complete_report();
            *v.pointer_mut(pointer).unwrap() = replacement;
            assert!(check(&v).is_err(), "accepted altered {pointer}");
        }
    }

    fn plan(repository: &Path) -> Plan {
        let binding = Bound {
            path: "/reader".into(),
            sha256: "a".repeat(64),
        };
        Plan {
            schema: "horizon-current-reader-plan-v1".into(),
            repository: repository.into(),
            origin_url: "unused".into(),
            reader_commit: "b".repeat(40),
            pipeline: binding.clone(),
            full_verifier: binding.clone(),
            qualification: binding,
            scratch_directory: "/scratch".into(),
            threads: 2,
            maximum_archive_bytes: 1024,
            minimum_free_bytes: 1024,
            epoch_expectations: BTreeMap::new(),
        }
    }

    #[test]
    fn qualification_requires_exact_source_artifacts_and_accepted_capabilities() {
        let p = plan(Path::new("/repository"));
        let mut q = Qualification {
            schema: "horizon-current-reader-main-acceptance-v1".into(),
            reader_commit: p.reader_commit.clone(),
            pipeline: p.pipeline.clone(),
            full_verifier: p.full_verifier.clone(),
            cargo_features: vec![],
            rustc_flags: vec![],
            minimum_thread_stack_bytes: None,
            source_build_evidence: vec![p.pipeline.clone()],
            source_artifact_correspondence_accepted: true,
            full_and_plugin_capabilities_accepted: true,
        };
        validate_qualification(&p, &q).unwrap();
        q.minimum_thread_stack_bytes = Some(64 * 1024 * 1024);
        validate_qualification(&p, &q).unwrap();
        q.minimum_thread_stack_bytes = Some(64 * 1024 * 1024 + 1);
        assert!(validate_qualification(&p, &q).is_err());
        q.minimum_thread_stack_bytes = None;
        q.reader_commit = "c".repeat(40);
        assert!(validate_qualification(&p, &q).is_err());
        q.reader_commit = p.reader_commit.clone();
        q.pipeline.sha256 = "d".repeat(64);
        assert!(validate_qualification(&p, &q).is_err());
        q.pipeline = p.pipeline.clone();
        q.full_and_plugin_capabilities_accepted = false;
        assert!(validate_qualification(&p, &q).is_err());
        q.full_and_plugin_capabilities_accepted = true;
        q.source_build_evidence.clear();
        assert!(validate_qualification(&p, &q).is_err());
    }

    #[test]
    fn qualified_stack_overrides_inherited_setting_in_real_child() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "test \"$RUST_MIN_STACK\" = 67108864"])
            .env("RUST_MIN_STACK", "1");
        configure_thread_stack(&mut command, Some(64 * 1024 * 1024)).unwrap();
        assert!(command.status().unwrap().success());
        for invalid in [0, 2 * 1024 * 1024 - 1, 64 * 1024 * 1024 + 1, u64::MAX] {
            assert!(configure_thread_stack(&mut command, Some(invalid)).is_err());
        }
        let mut legacy = Command::new("/bin/sh");
        configure_thread_stack(&mut legacy, None).unwrap();
        assert_eq!(legacy.get_envs().count(), 0);
    }

    #[test]
    fn hashing_refuses_symlink_and_receipt_cannot_clobber() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.json");
        let bound = write_json(&path, &json!({"success":true})).unwrap();
        assert_eq!(hash_file(&path).unwrap().0, bound.sha256);
        assert!(write_json(&path, &json!({"success":false})).is_err());
        let link = dir.path().join("symlink");
        std::os::unix::fs::symlink(path, &link).unwrap();
        assert!(hash_file(&link).is_err());
    }

    #[test]
    fn missing_remote_playback_never_produces_publication_receipt() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Gate {
            plan: plan(dir.path()),
            plan_binding: Bound {
                path: "/plan".into(),
                sha256: "a".repeat(64),
            },
            epoch: 251,
            length: 1,
            digest: "a".repeat(64),
            directory: dir.path().into(),
            retained: None,
            local_playback: json!({}),
            remote_playback: None,
            minimum_thread_stack_bytes: None,
        };
        assert!(
            gate.publication_receipt()
                .unwrap_err()
                .to_string()
                .contains("playback is missing")
        );
        assert!(!dir.path().join("remote-playback-acceptance.json").exists());
    }

    #[test]
    #[ignore = "requires root and uid/gid 1000 for native repository-owner qualification"]
    fn root_fetch_preserves_repository_owner() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let remote = dir.path().join("remote.git");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&remote).unwrap();
        for path in [dir.path(), repo.as_path(), remote.as_path()] {
            std::os::unix::fs::chown(path, Some(1000), Some(1000)).unwrap();
        }
        git(&plan(&remote), &["init", "--bare"]).unwrap();
        let p = plan(&repo);
        git(&p, &["init"]).unwrap();
        git(
            &p,
            &[
                "fetch",
                remote.to_str().unwrap(),
                "+refs/heads/*:refs/remotes/fixture/*",
            ],
        )
        .unwrap();
        for path in [repo.join(".git/objects"), repo.join(".git/FETCH_HEAD")] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.uid(), 1000);
            assert_eq!(metadata.gid(), 1000);
        }
        assert_eq!(unsafe { libc::geteuid() }, 0);
    }

    #[test]
    fn fetched_branch_checks_actual_reader_sources_not_just_ancestry() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        let remote = dir.path().join("remote.git");
        fs::create_dir(&repo).unwrap();
        let mut p = plan(&repo);
        // Copy the invoking repository's configured identity; never substitute
        // a test author or set author/committer environment variables.
        let configured = |key: &str| {
            let output = Command::new("git").args(["config", key]).output().unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        git(&p, &["init", "-b", "account-updates"]).unwrap();
        git(&p, &["config", "user.name", &configured("user.name")]).unwrap();
        git(&p, &["config", "user.email", &configured("user.email")]).unwrap();
        fs::create_dir(repo.join("src")).unwrap();
        fs::write(repo.join("src/reader.rs"), "reader-v1").unwrap();
        git(&p, &["add", "."]).unwrap();
        git(&p, &["commit", "-m", "Initial reader test fixture"]).unwrap();
        p.reader_commit = git(&p, &["rev-parse", "HEAD"]).unwrap();
        assert!(
            Command::new("git")
                .args(["init", "--bare"])
                .arg(&remote)
                .output()
                .unwrap()
                .status
                .success()
        );
        p.origin_url = remote.to_str().unwrap().into();
        git(&p, &["remote", "add", "origin", &p.origin_url]).unwrap();
        git(&p, &["push", "origin", "account-updates"]).unwrap();
        assert_eq!(current_branch(&p).unwrap().0, p.reader_commit);
        fs::write(repo.join("README.md"), "Documentation only").unwrap();
        git(&p, &["add", "."]).unwrap();
        git(&p, &["commit", "-m", "Unrelated documentation fixture"]).unwrap();
        git(&p, &["push", "origin", "account-updates"]).unwrap();
        assert_ne!(current_branch(&p).unwrap().0, p.reader_commit);
        fs::write(repo.join("src/reader.rs"), "reader-v2").unwrap();
        git(&p, &["add", "."]).unwrap();
        git(&p, &["commit", "-m", "Changed reader fixture"]).unwrap();
        git(&p, &["push", "origin", "account-updates"]).unwrap();
        assert!(current_branch(&p).is_err());
    }
}
