//! Fixed-census, read-only finalized RPC metadata acquisition. No replay/R2 access.
#[allow(dead_code)]
#[path = "horizon_gap_audit_bin.rs"]
mod audit;

use {
    anyhow::{Context, Result, ensure},
    audit::{BoundFile, collect_batch, digest, read_bound, valid_sha},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::{
            fd::AsRawFd,
            unix::{
                ffi::OsStrExt,
                fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            },
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    },
};

const CENSUS_SHA: &str = "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f";
const FIRST: u64 = 60_911_751;
const LAST: u64 = 61_328_765;
const TARGETS: usize = 18_283;
const MAX_BYTES: u64 = 1 << 30;
const MIN_FREE: u64 = 1 << 30;
const MAX_SECONDS: u64 = 21_600;
const MAX_ATTEMPTS: usize = 10_000;
const MAX_RESPONSE: u64 = 65_536;
const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
const BATCH: usize = 3;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    census: BoundFile,
    curl: BoundFile,
    root: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Metadata {
    pub(crate) slot: u64,
    pub(crate) parent_slot: u64,
    pub(crate) final_poh_hash: String,
    pub(crate) previous_poh_hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetReceipt {
    schema: String,
    census_sha256: String,
    plan_sha256: String,
    unit: String,
    invocation_id: String,
    request: BoundFile,
    response: BoundFile,
    metadata: Metadata,
    hidden_poh_hashes_recovered: bool,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}

fn ascii_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-epoch140-gap-metadata-fetch-plan-v1",
        "wrong plan schema"
    );
    ensure!(
        plan.census.sha256 == CENSUS_SHA,
        "wrong fixed complete census"
    );
    ensure!(
        plan.unit
            .starts_with("horizon-epoch140-gap-metadata-fetch-")
            && plan.unit.ends_with(".service")
            && ascii_name(&plan.unit),
        "wrong unit scope"
    );
    let leaf = plan
        .root
        .file_name()
        .and_then(|s| s.to_str())
        .context("root leaf")?;
    ensure!(
        plan.root.parent() == Some(Path::new("/var/lib"))
            && leaf.starts_with("jetstreamer-epoch140-gap-metadata-")
            && ascii_name(leaf),
        "wrong private root scope"
    );
    ensure!(
        !plan.census.path.starts_with(&plan.root) && !plan.curl.path.starts_with(&plan.root),
        "retained inputs must be outside output root"
    );
    ensure!(
        plan.curl.path.file_name().is_some_and(|s| s == "curl"),
        "wrong curl member name"
    );
    Ok(())
}

fn target_map(census: &Value) -> Result<BTreeMap<u64, u64>> {
    ensure!(
        census["schema"] == "jetstreamer-horizon-finalized-paged-gap-census-v1"
            && census["first_slot"] == FIRST
            && census["last_slot"] == LAST
            && census["post_gap_targets"] == TARGETS
            && census["skipped_slots"] == 66_314
            && census["expected_tick_boundaries"] == 84_597,
        "census scope/count mismatch"
    );
    for key in [
        "full_gap_audit_complete",
        "target_getblock_metadata_complete",
        "hidden_poh_hashes_recovered",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(census[key] == false, "census authority mismatch: {key}");
    }
    let mut targets = BTreeMap::new();
    let mut previous = FIRST;
    let mut hidden = 0u64;
    for gap in census["gap_candidates"]
        .as_array()
        .context("missing candidates")?
    {
        let slot = gap["slot"].as_u64().context("slot integer")?;
        let parent = gap["parent_slot"].as_u64().context("parent integer")?;
        ensure!(
            slot > previous
                && slot <= LAST
                && parent >= FIRST
                && parent < slot - 1
                && parent >= previous,
            "invalid ordered gap"
        );
        ensure!(
            gap["skipped_slots"] == slot - parent - 1
                && gap["expected_tick_boundaries"] == slot - parent,
            "gap arithmetic mismatch"
        );
        hidden += slot - parent - 1;
        ensure!(targets.insert(slot, parent).is_none(), "duplicate target");
        previous = slot;
    }
    ensure!(
        targets.len() == TARGETS && hidden == 66_314,
        "incomplete census"
    );
    Ok(targets)
}

fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "directory must be canonical and root-private"
    );
    Ok(())
}

fn available(path: &Path) -> Result<u64> {
    let name = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), value.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let value = unsafe { value.assume_init() };
    value
        .f_bavail
        .checked_mul(value.f_frsize)
        .context("free-space overflow")
}

fn validate_service(properties: &str, invocation: &str, pid: u32) -> Result<()> {
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "bad invocation ID"
    );
    let mut fields = BTreeMap::new();
    for line in properties.lines() {
        let (key, value) = line.split_once('=').context("malformed unit properties")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate unit property"
        );
    }
    let field = |key| fields.get(key).copied().unwrap_or("");
    ensure!(
        field("InvocationID") == invocation
            && field("MainPID") == pid.to_string()
            && field("NRestarts") == "0"
            && field("Restart") == "no"
            && field("KillMode") == "control-group"
            && field("Delegate") == "no"
            && matches!(field("ActiveState"), "active" | "activating"),
        "not this exact persistent non-restarting service"
    );
    Ok(())
}

pub(crate) fn authenticate(unit: &str) -> Result<String> {
    let invocation = env::var("INVOCATION_ID").context("persistent systemd service required")?;
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "--property=InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,ActiveState",
        ])
        .output()?;
    ensure!(result.status.success(), "unit query failed");
    validate_service(
        std::str::from_utf8(&result.stdout)?,
        &invocation,
        std::process::id(),
    )?;
    Ok(invocation)
}

fn atomic_write(path: &Path, bytes: &[u8], invocation: &str) -> Result<BoundFile> {
    let parent = path.parent().context("missing parent")?;
    private_dir(parent)?;
    ensure!(ascii_name(invocation), "bad atomic-write suffix");
    let leaf = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("missing leaf")?;
    let temporary = parent.join(format!(".{leaf}.partial-{invocation}"));
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    let from = std::ffi::CString::new(temporary.as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error())
            .context("no-clobber publication failed; partial preserved");
    }
    File::open(parent)?.sync_all()?;
    Ok(BoundFile {
        path: path.into(),
        sha256: digest(bytes),
    })
}

fn budget_tree(root: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    let mut files = 0usize;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let m = fs::symlink_metadata(entry.path())?;
        ensure!(
            m.uid() == 0 && m.mode() & 0o077 == 0,
            "foreign output member"
        );
        if m.is_dir() {
            private_dir(&entry.path())?;
            for file in fs::read_dir(entry.path())? {
                let m = fs::symlink_metadata(file?.path())?;
                ensure!(
                    m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o077 == 0,
                    "foreign/nonregular output"
                );
                bytes = bytes.checked_add(m.len()).context("budget overflow")?;
                files += 1;
            }
        } else {
            ensure!(m.is_file() && m.nlink() == 1, "nonregular output member");
            bytes = bytes.checked_add(m.len()).context("budget overflow")?;
            files += 1;
        }
        ensure!(
            bytes <= MAX_BYTES && files <= 60_000,
            "output budget exceeded"
        );
    }
    Ok(bytes)
}

fn request(slots: &[u64]) -> Value {
    json!(slots.iter().map(|slot| json!({"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]})).collect::<Vec<_>>())
}

fn parsed_metadata(
    request: &Value,
    response: &[u8],
    targets: &BTreeMap<u64, u64>,
) -> Result<Vec<Metadata>> {
    ensure!(
        request
            .as_array()
            .is_some_and(|a| !a.is_empty() && a.len() <= BATCH),
        "wrong bounded metadata request size"
    );
    let mut successes = BTreeMap::new();
    collect_batch(
        request,
        &serde_json::from_slice(response)?,
        &targets.keys().copied().collect(),
        &mut successes,
    )?;
    successes
        .into_iter()
        .map(|(slot, (parent, final_hash, previous_hash))| {
            ensure!(
                targets.get(&slot) == Some(&parent),
                "target parent mismatch at {slot}"
            );
            Ok(Metadata {
                slot,
                parent_slot: parent,
                final_poh_hash: final_hash,
                previous_poh_hash: previous_hash,
            })
        })
        .collect()
}

struct OwnedCurl {
    child: Child,
    waited: bool,
}

impl Drop for OwnedCurl {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn response(curl: &Path, bytes: &[u8]) -> Result<(bool, Vec<u8>, Vec<u8>)> {
    let child = Command::new(curl)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args([
            "--disable",
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--max-time",
            "45",
            "--max-filesize",
            "65536",
            "--header",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            ENDPOINT,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    finish_transport(child, bytes, Duration::from_secs(50))
}

fn finish_transport(
    child: Child,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(bool, Vec<u8>, Vec<u8>)> {
    let mut owner = OwnedCurl {
        child,
        waited: false,
    };
    let stdout = owner.child.stdout.take().context("curl stdout")?;
    let stderr = owner.child.stderr.take().context("curl stderr")?;
    let body_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let error_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.take(8193).read_to_end(&mut bytes).map(|_| bytes)
    });
    owner
        .child
        .stdin
        .take()
        .context("curl stdin")?
        .write_all(bytes)?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = owner.child.try_wait()? {
            owner.waited = true;
            break status;
        }
        ensure!(
            started.elapsed() < timeout,
            "owned curl exceeded independent runtime bound"
        );
        thread::sleep(Duration::from_millis(100));
    };
    let body = body_reader
        .join()
        .map_err(|_| anyhow::anyhow!("body reader panicked"))??;
    let mut stderr = error_reader
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
    let bounded = body.len() as u64 <= MAX_RESPONSE && stderr.len() <= 8192;
    stderr.truncate(8192);
    // Preserve the bounded captured prefix for diagnosis, but it is never
    // parsed/checkpointed when a complete response could not be captured.
    Ok((status.success() && bounded, body, stderr))
}

fn evidence_inside(bound: &BoundFile, root: &Path, kind: &str) -> Result<()> {
    ensure!(
        bound.path.parent() == Some(root.join(kind).as_path())
            && bound.path.extension().is_some_and(|s| s == "json"),
        "checkpoint binding outside owned evidence tree"
    );
    Ok(())
}

fn resume_targets(
    plan: &Plan,
    plan_sha: &str,
    targets: &BTreeMap<u64, u64>,
) -> Result<BTreeMap<u64, BoundFile>> {
    let mut complete = BTreeMap::new();
    let directory = plan.root.join("targets");
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if path
            .file_name()
            .is_some_and(|s| s.as_encoded_bytes().starts_with(b"."))
        {
            continue;
        }
        let mut bytes = Vec::new();
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?
            .take(16_385)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 16_384, "oversized target receipt");
        let bound = BoundFile {
            path: path.clone(),
            sha256: digest(&bytes),
        };
        let receipt: TargetReceipt = serde_json::from_slice(&read_bound(&bound)?)?;
        ensure!(
            receipt.schema == "jetstreamer-epoch140-finalized-gap-target-v1"
                && receipt.census_sha256 == CENSUS_SHA
                && receipt.plan_sha256 == plan_sha
                && receipt.unit == plan.unit
                && !receipt.hidden_poh_hashes_recovered
                && !receipt.replay_launch_authorized
                && !receipt.publication_authorized
                && !receipt.r2_mutations,
            "wrong target checkpoint authority/owner"
        );
        ensure!(
            path == directory.join(format!("target-{}.json", receipt.metadata.slot)),
            "wrong target checkpoint name"
        );
        evidence_inside(&receipt.request, &plan.root, "requests")?;
        evidence_inside(&receipt.response, &plan.root, "responses")?;
        let values = parsed_metadata(
            &serde_json::from_slice(&read_bound(&receipt.request)?)?,
            &read_bound(&receipt.response)?,
            targets,
        )?;
        ensure!(
            values.contains(&receipt.metadata),
            "checkpoint metadata differs from original finalized response"
        );
        ensure!(
            complete.insert(receipt.metadata.slot, bound).is_none(),
            "duplicate target checkpoint"
        );
    }
    Ok(complete)
}

/// Independently authenticate a completed fixed-census collector before native
/// acquisition. This grants no native/replay/publication authority. Every target
/// and original RPC binding is reread; completion or checkpoint presence alone
/// cannot substitute for this check.
#[allow(dead_code)] // Shared with the native consumer, not called by collection.
pub(crate) fn validate_complete_collection(
    plan_path: &Path,
    plan_sha: &str,
    complete_path: &Path,
    complete_sha: &str,
) -> Result<Vec<Metadata>> {
    let binding = BoundFile {
        path: plan_path.into(),
        sha256: plan_sha.into(),
    };
    let plan: Plan = serde_json::from_slice(&read_bound(&binding)?)?;
    validate_plan(&plan)?;
    private_dir(&plan.root)?;
    ensure!(
        complete_path == plan.root.join("complete.json"),
        "wrong completion path"
    );
    let census: Value = serde_json::from_slice(&read_bound(&plan.census)?)?;
    let targets = target_map(&census)?;
    let complete: Value = serde_json::from_slice(&read_bound(&BoundFile {
        path: complete_path.into(),
        sha256: complete_sha.into(),
    })?)?;
    validate_completion_header(&complete, &binding, &plan)?;
    let verified = resume_targets(&plan, plan_sha, &targets)?;
    ensure!(verified.len() == TARGETS, "incomplete verified target set");
    let declared = complete["target_receipts"]
        .as_array()
        .context("missing target bindings")?;
    validate_declared_targets(declared, &verified)?;
    let mut metadata = Vec::with_capacity(TARGETS);
    for (entry, (&slot, bound)) in declared.iter().zip(&verified) {
        let entry: BoundFile = serde_json::from_value(entry.clone())?;
        ensure!(
            entry.path == bound.path && entry.sha256 == bound.sha256,
            "changed, dropped, reordered or substituted target binding"
        );
        let receipt: TargetReceipt = serde_json::from_slice(&read_bound(bound)?)?;
        ensure!(receipt.metadata.slot == slot, "target key changed");
        metadata.push(receipt.metadata);
    }
    // Recheck the two top-level immutable objects after the complete reread.
    read_bound(&binding)?;
    read_bound(&BoundFile {
        path: complete_path.into(),
        sha256: complete_sha.into(),
    })?;
    Ok(metadata)
}

#[allow(dead_code)] // Shared with the native consumer.
fn validate_declared_targets(
    declared: &[Value],
    verified: &BTreeMap<u64, BoundFile>,
) -> Result<()> {
    ensure!(
        declared.len() == verified.len(),
        "incomplete declared target set"
    );
    for (entry, bound) in declared.iter().zip(verified.values()) {
        let entry: BoundFile = serde_json::from_value(entry.clone())?;
        ensure!(
            entry.path == bound.path && entry.sha256 == bound.sha256,
            "changed, dropped, reordered or substituted target binding"
        );
    }
    Ok(())
}

#[allow(dead_code)] // Shared with the native consumer.
fn validate_completion_header(complete: &Value, binding: &BoundFile, plan: &Plan) -> Result<()> {
    ensure!(
        complete["schema"] == "jetstreamer-epoch140-finalized-gap-metadata-collection-v1"
            && complete["plan"]["path"].as_str() == binding.path.to_str()
            && complete["plan"]["sha256"] == binding.sha256
            && complete["census"]["path"].as_str() == plan.census.path.to_str()
            && complete["census"]["sha256"] == CENSUS_SHA
            && complete["unit"] == plan.unit
            && complete["invocation_id"]
                .as_str()
                .is_some_and(|v| v.len() == 32
                    && v.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && complete["first_slot"] == FIRST
            && complete["last_slot"] == LAST
            && complete["verified_targets"] == TARGETS
            && complete["finalized_parent_and_hash_metadata_complete"] == true,
        "wrong complete collector scope/owner/bindings"
    );
    for key in [
        "hidden_poh_hashes_recovered",
        "source_obscuration_proven",
        "canonical_root_qualified",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            complete[key] == false,
            "collector authority mismatch: {key}"
        );
    }
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let check = args.len() == 6 && args[5] == "--check-only";
    ensure!(
        (args.len() == 5 || check) && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: jetstreamer-epoch140-gap-metadata-fetch PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && valid_sha(&args[4])
            && digest(&fs::read("/proc/self/exe")?) == args[4],
        "root and exact executable digest required"
    );
    let binding = BoundFile {
        path: args[0].clone().into(),
        sha256: args[2].clone(),
    };
    let plan: Plan = serde_json::from_slice(&read_bound(&binding)?)?;
    validate_plan(&plan)?;
    private_dir(&plan.root)?;
    ensure!(
        available(&plan.root)? >= MIN_FREE,
        "private evidence filesystem reserve unavailable"
    );
    let targets = target_map(&serde_json::from_slice(&read_bound(&plan.census)?)?)?;
    let _curl_bytes = read_bound(&plan.curl)?;
    let unit = if check {
        format!(
            "{}-check.service",
            plan.unit.strip_suffix(".service").context("unit suffix")?
        )
    } else {
        plan.unit.clone()
    };
    let invocation = authenticate(&unit)?;
    if check {
        println!(
            "{}",
            json!({"check_only":true,"targets":targets.len(),"network_requests":0,"output_writes":0,"replay_launch_authorized":false})
        );
        return Ok(());
    }
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(plan.root.join("collector.lock"))?;
    let lm = lock.metadata()?;
    ensure!(
        lm.is_file() && lm.uid() == 0 && lm.nlink() == 1 && lm.mode() & 0o077 == 0,
        "invalid collector lock"
    );
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another collector owns this output"
    );
    for name in ["requests", "responses", "targets", "events"] {
        let directory = plan.root.join(name);
        if !directory.exists() {
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
        }
        private_dir(&directory)?;
    }
    File::open(&plan.root)?.sync_all()?;
    let mut written = budget_tree(&plan.root)?;
    let mut complete = resume_targets(&plan, &args[2], &targets)?;
    ensure!(
        !plan.root.join("complete.json").exists(),
        "completion already exists; verify it rather than rerun collector"
    );
    let start = Instant::now();
    let mut failures = 0u32;
    let mut attempted = 0usize;
    while complete.len() != targets.len() {
        ensure!(
            start.elapsed().as_secs() < MAX_SECONDS && attempted < MAX_ATTEMPTS,
            "bounded collection incomplete; retained verified progress may be resumed explicitly"
        );
        ensure!(
            available(&plan.root)? >= MIN_FREE + (1 << 20) && written + (1 << 20) <= MAX_BYTES,
            "private evidence reserve/budget exhausted; all progress preserved"
        );
        let slots: Vec<_> = targets
            .keys()
            .filter(|slot| !complete.contains_key(slot))
            .take(BATCH)
            .copied()
            .collect();
        let req = request(&slots);
        let req_bytes = serde_json::to_vec(&req)?;
        let stem = format!("{invocation}-{attempted:06}");
        let req_binding = atomic_write(
            &plan.root.join("requests").join(format!("{stem}.json")),
            &req_bytes,
            &invocation,
        )?;
        let transport = response(&plan.curl.path, &req_bytes);
        let (ok, body, stderr) = transport
            .unwrap_or_else(|error| (false, Vec::new(), format!("{error:#}").into_bytes()));
        let resp_binding = atomic_write(
            &plan.root.join("responses").join(format!("{stem}.json")),
            &body,
            &invocation,
        )?;
        let parsed = if ok {
            parsed_metadata(&req, &body, &targets)
        } else {
            Err(anyhow::anyhow!(
                "curl transport failed; raw body/error retained"
            ))
        };
        let mut success_count = 0;
        let mut diagnostic = String::new();
        match parsed {
            Ok(values) => {
                for value in values {
                    let receipt = TargetReceipt {
                        schema: "jetstreamer-epoch140-finalized-gap-target-v1".into(),
                        census_sha256: CENSUS_SHA.into(),
                        plan_sha256: args[2].clone(),
                        unit: plan.unit.clone(),
                        invocation_id: invocation.clone(),
                        request: BoundFile {
                            path: req_binding.path.clone(),
                            sha256: req_binding.sha256.clone(),
                        },
                        response: BoundFile {
                            path: resp_binding.path.clone(),
                            sha256: resp_binding.sha256.clone(),
                        },
                        metadata: value.clone(),
                        hidden_poh_hashes_recovered: false,
                        replay_launch_authorized: false,
                        publication_authorized: false,
                        r2_mutations: false,
                    };
                    let bytes = serde_json::to_vec(&receipt)?;
                    let bound = atomic_write(
                        &plan
                            .root
                            .join("targets")
                            .join(format!("target-{}.json", value.slot)),
                        &bytes,
                        &invocation,
                    )?;
                    written += bytes.len() as u64;
                    complete.insert(value.slot, bound);
                    success_count += 1;
                }
            }
            Err(error) => diagnostic = format!("{error:#}"),
        }
        let event = serde_json::to_vec(
            &json!({"schema":"jetstreamer-epoch140-gap-metadata-attempt-v1","plan":binding,"invocation_id":invocation,"request":req_binding,"response":resp_binding,"transport_success":ok,"response_capture_complete":ok && body.len() as u64 <= MAX_RESPONSE,"response_capture_limit_bytes":MAX_RESPONSE,"stderr":String::from_utf8_lossy(&stderr),"validation_error":diagnostic,"new_targets":success_count,"verified_targets":complete.len(),"publication_authorized":false,"r2_mutations":false}),
        )?;
        atomic_write(
            &plan.root.join("events").join(format!("{stem}.json")),
            &event,
            &invocation,
        )?;
        written += req_bytes.len() as u64 + body.len() as u64 + event.len() as u64;
        attempted += 1;
        failures = if success_count == 0 { failures + 1 } else { 0 };
        if attempted == 1 || attempted.is_multiple_of(25) {
            eprintln!(
                "finalized-gap-metadata attempts={attempted} verified_targets={} total={TARGETS}",
                complete.len()
            );
        }
        ensure!(
            failures < 8,
            "eight consecutive attempts made no progress; preserve errors and retry only after diagnosis"
        );
        let delay = if success_count == slots.len() {
            2
        } else {
            (5u64 << failures.min(5)).min(120)
        };
        thread::sleep(Duration::from_secs(delay));
    }
    // Independently reread every original RPC binding again before claiming
    // collection completion; checkpoint existence alone is never sufficient.
    let verified = resume_targets(&plan, &args[2], &targets)?;
    ensure!(
        verified.len() == TARGETS,
        "final checkpoint census incomplete"
    );
    let bytes = serde_json::to_vec(
        &json!({"schema":"jetstreamer-epoch140-finalized-gap-metadata-collection-v1","plan":binding,"census":plan.census,"unit":plan.unit,"invocation_id":invocation,"first_slot":FIRST,"last_slot":LAST,"verified_targets":verified.len(),"target_receipts":verified.values().collect::<Vec<_>>(),"finalized_parent_and_hash_metadata_complete":true,"hidden_poh_hashes_recovered":false,"source_obscuration_proven":false,"canonical_root_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    ensure!(
        written + bytes.len() as u64 <= MAX_BYTES
            && available(&plan.root)? >= MIN_FREE + bytes.len() as u64,
        "final receipt would exceed private budget/reserve"
    );
    let result = atomic_write(&plan.root.join("complete.json"), &bytes, &invocation)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-epoch140-gap-metadata-fetch-plan-v1".into(),
            unit: "horizon-epoch140-gap-metadata-fetch-test.service".into(),
            census: BoundFile {
                path: "/immutable/gap-census.json".into(),
                sha256: CENSUS_SHA.into(),
            },
            curl: BoundFile {
                path: "/immutable/curl".into(),
                sha256: "a".repeat(64),
            },
            root: "/var/lib/jetstreamer-epoch140-gap-metadata-test".into(),
        }
    }

    fn rpc(slot: u64, parent: u64) -> Value {
        json!({"jsonrpc":"2.0","id":slot,"result":{"parentSlot":parent,"blockhash":"11111111111111111111111111111111","previousBlockhash":"11111111111111111111111111111111"}})
    }

    #[test]
    fn fixed_plan_and_unknown_fields_cannot_expand_scope() {
        let mut p = plan();
        validate_plan(&p).unwrap();
        p.census.sha256 = "b".repeat(64);
        assert!(validate_plan(&p).is_err());
        p.census.sha256 = CENSUS_SHA.into();
        p.root = "/home/sol/metadata".into();
        assert!(validate_plan(&p).is_err());
        p.root = plan().root;
        p.unit = "horizon-replay-140.service".into();
        assert!(validate_plan(&p).is_err());
        let mut v = json!({"schema":plan().schema,"unit":plan().unit,"census":plan().census,"curl":plan().curl,"root":plan().root});
        v["endpoint"] = json!("https://example.com");
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }

    #[test]
    fn completion_consumer_requires_all_scope_owner_and_authority_bindings() {
        let p = plan();
        let binding = BoundFile {
            path: "/sealed/plan.json".into(),
            sha256: "a".repeat(64),
        };
        let good = json!({"schema":"jetstreamer-epoch140-finalized-gap-metadata-collection-v1",
            "plan":binding,"census":p.census,"unit":p.unit,"invocation_id":"a".repeat(32),
            "first_slot":FIRST,"last_slot":LAST,"verified_targets":TARGETS,
            "finalized_parent_and_hash_metadata_complete":true,"hidden_poh_hashes_recovered":false,
            "source_obscuration_proven":false,"canonical_root_qualified":false,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        validate_completion_header(&good, &binding, &p).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                validate_completion_header(&changed, &binding, &p).is_err(),
                "accepted absent {key}"
            );
        }
        for (pointer, value) in [
            ("/plan/sha256", json!("b".repeat(64))),
            ("/plan/path", json!("/different/plan.json")),
            ("/census/sha256", json!("b".repeat(64))),
            ("/census/path", json!("/different/census.json")),
            ("/verified_targets", json!(TARGETS - 1)),
            ("/publication_authorized", json!(true)),
            ("/invocation_id", json!("A".repeat(32))),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_completion_header(&changed, &binding, &p).is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn completion_consumer_rejects_dropped_reordered_and_substituted_checkpoints() {
        let verified = BTreeMap::from([
            (
                104,
                BoundFile {
                    path: "/private/targets/target-104.json".into(),
                    sha256: "a".repeat(64),
                },
            ),
            (
                108,
                BoundFile {
                    path: "/private/targets/target-108.json".into(),
                    sha256: "b".repeat(64),
                },
            ),
        ]);
        let good: Vec<_> = verified.values().map(|v| json!(v)).collect();
        validate_declared_targets(&good, &verified).unwrap();
        let mut swapped = good.clone();
        swapped.swap(0, 1);
        assert!(validate_declared_targets(&swapped, &verified).is_err());
        assert!(validate_declared_targets(&good[..1], &verified).is_err());
        let mut duplicate = good.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(validate_declared_targets(&duplicate, &verified).is_err());
        let mut changed = good;
        changed[0]["sha256"] = json!("c".repeat(64));
        assert!(validate_declared_targets(&changed, &verified).is_err());
    }

    #[test]
    fn canonical_request_partial_rpc_errors_and_exact_parent_are_required() {
        let targets = BTreeMap::from([(104, 101), (108, 105)]);
        let req = request(&[104, 108]);
        let bytes=serde_json::to_vec(&json!([rpc(104,101),{"jsonrpc":"2.0","id":108,"error":{"code":429,"message":"rate limited"}}])).unwrap();
        let values = parsed_metadata(&req, &bytes, &targets).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].slot, 104);
        let wrong = serde_json::to_vec(&json!([rpc(104, 100), rpc(108, 105)])).unwrap();
        assert!(parsed_metadata(&req, &wrong, &targets).is_err());
        let duplicate = serde_json::to_vec(&json!([rpc(104, 101), rpc(104, 101)])).unwrap();
        assert!(parsed_metadata(&req, &duplicate, &targets).is_err());
        let mut nonfinal = req.clone();
        nonfinal[0]["params"][1]["commitment"] = json!("confirmed");
        assert!(parsed_metadata(&nonfinal, &bytes, &targets).is_err());
        assert!(parsed_metadata(&request(&[]), b"[]", &targets).is_err());
        assert!(parsed_metadata(&request(&[104, 108, 109, 110]), b"[]", &targets).is_err());
    }

    #[test]
    fn exact_service_identity_rejects_restarts_foreign_pid_and_delegate() {
        let id = "a".repeat(32);
        let source = format!(
            "InvocationID={id}\nMainPID=123\nNRestarts=0\nRestart=no\nKillMode=control-group\nDelegate=no\nActiveState=activating\n"
        );
        validate_service(&source, &id, 123).unwrap();
        for changed in [
            source.replace("NRestarts=0", "NRestarts=1"),
            source.replace("Delegate=no", "Delegate=yes"),
            source.replace("Restart=no", "Restart=always"),
            source.replace("MainPID=123", "MainPID=124"),
        ] {
            assert!(validate_service(&changed, &id, 123).is_err());
        }
    }

    #[test]
    fn complete_fixed_census_arithmetic_and_authority_fail_closed() {
        let mut previous = FIRST;
        let gaps:Vec<_>=(0..TARGETS).map(|index|{
            let skipped=if index<11_465 {4}else{3};
            let parent=previous; previous+=skipped+1;
            json!({"parent_slot":parent,"slot":previous,"skipped_slots":skipped,"expected_tick_boundaries":skipped+1})
        }).collect();
        let mut census = json!({"schema":"jetstreamer-horizon-finalized-paged-gap-census-v1","first_slot":FIRST,"last_slot":LAST,"post_gap_targets":TARGETS,"skipped_slots":66314,"expected_tick_boundaries":84597,"gap_candidates":gaps,"full_gap_audit_complete":false,"target_getblock_metadata_complete":false,"hidden_poh_hashes_recovered":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        assert_eq!(target_map(&census).unwrap().len(), TARGETS);
        census["gap_candidates"][0]["parent_slot"] = json!(FIRST + 1);
        assert!(target_map(&census).is_err());
        census["gap_candidates"][0]["parent_slot"] = json!(FIRST);
        census["replay_launch_authorized"] = json!(true);
        assert!(target_map(&census).is_err());
    }

    #[test]
    fn transport_fixture() {
        match env::var("JETSTREAMER_METADATA_TEST_FIXTURE").as_deref() {
            Ok("sleep") => thread::sleep(Duration::from_secs(10)),
            Ok("large") => {
                let _ = std::io::stdout().write_all(&vec![b'x'; MAX_RESPONSE as usize + 8192]);
            }
            _ => {}
        }
    }

    fn fixture(mode: &str) -> Child {
        let namespace = module_path!().split_once("::").unwrap().1;
        let fixture = format!("{namespace}::transport_fixture");
        Command::new(env::current_exe().unwrap())
            .args(["--exact", &fixture, "--nocapture"])
            .env("JETSTREAMER_METADATA_TEST_FIXTURE", mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }

    #[test]
    fn transport_bounds_output_and_kills_only_owned_timed_out_child() {
        let child = fixture("large");
        let (ok, bytes, _) = finish_transport(child, b"[]", Duration::from_secs(5)).unwrap();
        assert!(!ok);
        assert_eq!(bytes.len() as u64, MAX_RESPONSE + 1);
        let mut other = Command::new("/bin/sleep").arg("5").spawn().unwrap();
        assert!(finish_transport(fixture("sleep"), b"[]", Duration::from_millis(100)).is_err());
        assert!(other.try_wait().unwrap().is_none());
        other.kill().unwrap();
        other.wait().unwrap();
    }

    #[test]
    fn root_atomic_checkpoint_resume_revalidates_original_rpc_and_never_clobbers() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut p = plan();
        p.root = dir.path().to_path_buf();
        for name in ["requests", "responses", "targets"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(p.root.join(name))
                .unwrap();
        }
        let id = "a".repeat(32);
        let plan_sha = "c".repeat(64);
        let targets = BTreeMap::from([(104, 101)]);
        let req = atomic_write(
            &p.root.join("requests/r.json"),
            &serde_json::to_vec(&request(&[104])).unwrap(),
            &id,
        )
        .unwrap();
        let resp = atomic_write(
            &p.root.join("responses/r.json"),
            &serde_json::to_vec(&json!([rpc(104, 101)])).unwrap(),
            &id,
        )
        .unwrap();
        let receipt = TargetReceipt {
            schema: "jetstreamer-epoch140-finalized-gap-target-v1".into(),
            census_sha256: CENSUS_SHA.into(),
            plan_sha256: plan_sha.clone(),
            unit: p.unit.clone(),
            invocation_id: id.clone(),
            request: req,
            response: resp,
            metadata: Metadata {
                slot: 104,
                parent_slot: 101,
                final_poh_hash: "11111111111111111111111111111111".into(),
                previous_poh_hash: "11111111111111111111111111111111".into(),
            },
            hidden_poh_hashes_recovered: false,
            replay_launch_authorized: false,
            publication_authorized: false,
            r2_mutations: false,
        };
        let target = p.root.join("targets/target-104.json");
        let bytes = serde_json::to_vec(&receipt).unwrap();
        atomic_write(&target, &bytes, &id).unwrap();
        assert_eq!(resume_targets(&p, &plan_sha, &targets).unwrap().len(), 1);
        assert!(resume_targets(&p, &"d".repeat(64), &targets).is_err());
        assert!(atomic_write(&target, b"replacement", &"b".repeat(32)).is_err());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        let wrong = BTreeMap::from([(104, 100)]);
        assert!(resume_targets(&p, &plan_sha, &wrong).is_err());
        fs::set_permissions(&p.root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_dir(&p.root).is_err());
    }
}
