//! Contents-only retirement of the exact guard-stopped epoch166 retry6 scratch.
//! The old run, retained output, inputs, cursor, shared locks and all resource
//! promises survive. This executable has no archive removal or R2 operation.
mod custody;
mod held_partial;
mod process_references;
mod references;
mod stopped_tree;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-retry6-166-scratch-retire-20261119-v2/retire";
const BASE: &str = "/var/lib/jetstreamer/epoch166-retry6-scratch-retirement-20261119-v2";
const DESTINATION: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51";
const RUN: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328";
const SCRATCH: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328/scratch";
const INTENT: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-intent.json";
const INTENT_SHA: &str = "3901e732145152e22372c63c32c3744833cfc1c10f45d11e9e7a9c34fed25074";
const STOP: &str = "/var/lib/jetstreamer/retry6-preparation-20261117-v1/epoch166/local3retry6/guard-state/receipts/stop-completion.json";
const STOP_SHA: &str = "34a92966ddb3007db7f1a06bfb0668f48856ebaa725937eacd9088df0a050f01";
const ADMISSION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_REPLACEMENT_ADMISSION.json";
const ADMISSION_SHA: &str = "24033084033ab661720ea714cce584fdee4464a14e845563bb43de200ca0eb81";
const PROTECTION: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_GUARD_PROTECTION.json";
const PROTECTION_SHA: &str = "21cb4ced79b12be21c3f5011f7de183909078afa3f4826ef3c0e509bed0afa5d";
const NATIVE: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ACTUAL_PRODUCER_NATIVE.json";
const NATIVE_SHA: &str = "13ff678b5b2115dda95fa74729333422cb89d584bc8889736bbba24f52c71c75";
const ORIGINAL_ARGV: &str = "/var/lib/jetstreamer/retry6-single166-guarded-launch-20261117-v1/epoch166/ORIGINAL_PRODUCER_ARGV.json";
const ORIGINAL_ARGV_SHA: &str = "fa143fc5729f237f3ec78eb78d9ff18f2d3aea2b81793cd08850e14aa47d0bf7";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/preflight-166-v4.json";
const MANIFEST_SHA: &str = "c632ae8d95748f563d8c47db587afa9139b165298004c3fa6820332c4d89b6b4";
const PACKAGE_SEAL: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/deployment-seal-receipt.json";
const PACKAGE_SEAL_SHA: &str = "59f3e31877df7f267859d9385135214b7c2c17c66b52e117c1cd88874761dbcc";
const LINEAGE: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/predecessor-capability.json";
const LINEAGE_SHA: &str = "4732c772b708cccd676115d794a1cb366cb89364db1c8e1f46f5455e0333ddf8";
const UNIT: &str = "horizon-qualify-166-replacement-local3retry6-20261110-v1.service";
const GUARD: &str = "horizon-guard-replacement-166-local3retry6-20261110-v1";
const IID: &str = "b3992e492e1a4d49a9e4e4a01a13c815";
const GUARD_PLAN_SHA: &str = "76262c90040585430d13caae4c836826f6ddf5a8b8def76992dc5e6b8ef325f3";
const NODE: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-node";
const NODE_SHA: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER: &str = "/usr/local/lib/jetstreamer/horizon-independent166-singleton-package-20261109-v1/jetstreamer-historical-worker-v1-5-6";
const WORKER_SHA: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const SOURCE_COMMIT: &str = "e6f48efe2749d35d6875fdd3cbd7f6f4379adf75";
const REVIEWED_SOURCE_SHAS: [&str; 4] = [
    "3bc5262f5541acbbd252d5cba5a25995d2b92869c659aa67367b9fff420b7bdc",
    "b7e61de4ccbb3af1a02a62bd974128e560ee50d6b92f878ebbb8e2f529b765ee",
    "c1f4379dee50367b3c7ab092440a520834bac82c66889df8799db7ee3d101ee5",
    "6b3da9c985dface7d7d555323018b74db20fb5ec654f24c0d3c5f01c06f1729c",
];
const FINGERPRINT: &str = "sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const DEVICE: u64 = 64512;
const RUN_INODE: u64 = 103678018;
const SCRATCH_INODE: u64 = 103678021;
const ARCHIVE_INODE: u64 = 103678035;
const ARCHIVE_BYTES: u64 = 56_173_984_550;
const STATE_INODE: u64 = 103678019;
const STATE_BYTES: u64 = 222;
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const UID: u32 = 1001;
const GID: u32 = 1003;
const MAX_JSON: u64 = 32 << 20;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
impl Bound {
    fn fixed(path: &str, digest: &str) -> Self {
        Self {
            path: path.into(),
            sha256: digest.into(),
        }
    }
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    owner: String,
    epoch: u64,
    run: PathBuf,
    scratch: PathBuf,
    device: u64,
    run_inode: u64,
    scratch_inode: u64,
    stop_intent: Bound,
    stop_completion: Bound,
    admission: Bound,
    guard_protection: Bound,
    no_resume_review: Bound,
    dependency_review: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_partial_completion: Option<Bound>,
    shared_locks: Vec<custody::LockBinding>,
    retire_scratch_contents: bool,
    preserve_archive_and_inputs: bool,
    preserve_cohort_state: bool,
    preserve_scratch_root: bool,
    resource_credit_bytes: u64,
    resource_promise_ending_authorized: bool,
    replay_launch_authorized: bool,
    archive_deletion_authorized: bool,
    remote_mutations: bool,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NoResumeReview {
    schema: String,
    owner: String,
    epoch: u64,
    run: PathBuf,
    scratch: PathBuf,
    producer_unit: String,
    producer_invocation_id: String,
    original_native: Bound,
    original_argv: Bound,
    manifest: Bound,
    package_seal: Bound,
    source_lineage: Bound,
    stop_completion: Bound,
    node: Bound,
    worker: Bound,
    source_commit: String,
    cohort_state_sha256: String,
    // These must be original build/native provenance and exact reviewed sources,
    // not this review itself or a new statement repeating the desired conclusion.
    exact_source_image_evidence: Vec<Bound>,
    reviewed_source_evidence: Vec<Bound>,
    analysis: Bound,
    exact_source_image_binding_established: bool,
    no_admitted_scratch_continuation: bool,
    no_native_bank_or_writer_cursor: bool,
    original_invocation_restarts_from_bootstrap: bool,
    snapshot_exports_and_indirect_readers_reviewed: bool,
    preserve_partial_archive_and_inputs: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_partial_completion: Option<Bound>,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn lower_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn raw(path: &Path, max: u64, uid: u32) -> Result<Vec<u8>> {
    let mut file = custody::open_regular(path, uid)?;
    let before = custody::identity(&file.metadata()?);
    ensure!(file.metadata()?.len() <= max, "bound file exceeds limit");
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= max
            && custody::identity(&file.metadata()?) == before
            && custody::identity(&fs::symlink_metadata(path)?) == before,
        "bound file changed"
    );
    Ok(bytes)
}
fn bound(b: &Bound, max: u64) -> Result<Vec<u8>> {
    ensure!(lower_sha(&b.sha256), "invalid bound digest");
    let bytes = raw(&b.path, max, 0)?;
    ensure!(
        sha(&bytes) == b.sha256,
        "bound evidence changed: {}",
        b.path.display()
    );
    Ok(bytes)
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    ensure!(parent == Path::new(BASE), "foreign output scope");
    let parent_fd = custody::open_directory(parent)?;
    let meta = parent_fd.metadata()?;
    ensure!(
        meta.uid() == 0 && meta.mode() & 0o7777 == 0o700,
        "unsafe output directory"
    );
    let name = std::ffi::CString::new(path.file_name().context("output name")?.as_bytes())?;
    let temporary = std::ffi::CString::new(format!(
        ".receipt-writing-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ))?;
    let fd = unsafe {
        libc::openat(
            parent_fd.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "private receipt creation failed: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    file.sync_all()?;
    ensure!(
        unsafe {
            libc::renameat2(
                parent_fd.as_raw_fd(),
                temporary.as_ptr(),
                parent_fd.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "receipt no-clobber publication failed: {}",
        std::io::Error::last_os_error()
    );
    parent_fd.sync_all()?;
    Ok(())
}
struct Held {
    locks: Vec<File>,
    ancestors: Vec<(PathBuf, File, Value)>,
    output: File,
    output_identity: Value,
}
impl Held {
    fn recheck(&self, p: &Plan) -> Result<()> {
        custody::recheck_locks(&p.shared_locks, &self.locks)?;
        custody::recheck_ancestors(&self.ancestors)?;
        ensure!(
            custody::directory_identity(&self.output.metadata()?) == self.output_identity
                && custody::directory_identity(
                    &custody::open_directory(Path::new(BASE))?.metadata()?
                ) == self.output_identity,
            "private lifecycle directory changed"
        );
        Ok(())
    }
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        held_partial::schema_matches(
            &p.schema,
            "horizon-retry6-166-scratch-retirement-plan",
            &p.held_partial_completion
        ) && p.owner == "/root"
            && p.epoch == 166
            && p.run == Path::new(RUN)
            && p.scratch == Path::new(SCRATCH)
            && p.device == DEVICE
            && p.run_inode == RUN_INODE
            && p.scratch_inode == SCRATCH_INODE
            && p.stop_intent == Bound::fixed(INTENT, INTENT_SHA)
            && p.stop_completion == Bound::fixed(STOP, STOP_SHA)
            && p.admission == Bound::fixed(ADMISSION, ADMISSION_SHA)
            && p.guard_protection == Bound::fixed(PROTECTION, PROTECTION_SHA)
            && p.retire_scratch_contents
            && p.preserve_archive_and_inputs
            && p.preserve_cohort_state
            && p.preserve_scratch_root
            && p.resource_credit_bytes == 0
            && !p.resource_promise_ending_authorized
            && !p.replay_launch_authorized
            && !p.archive_deletion_authorized
            && !p.remote_mutations,
        "exact limited retry6 scratch authority required"
    );
    custody::validate_locks(&p.shared_locks)?;
    if let Some(binding) = &p.held_partial_completion {
        held_partial::validate_binding(binding)?;
    }
    for b in [&p.no_resume_review, &p.dependency_review] {
        ensure!(
            b.path.is_absolute() && lower_sha(&b.sha256) && !b.path.starts_with(DESTINATION),
            "review must survive retirement"
        );
    }
    Ok(())
}
fn scope_sha(p: &Plan) -> Result<String> {
    // A restarted cleanup needs a fresh dependency closure. That evidence may
    // change without changing the immutable target, original proof or ledger.
    let mut value = serde_json::to_value(p)?;
    value
        .as_object_mut()
        .context("plan object")?
        .remove("dependency_review");
    Ok(sha(&serde_json::to_vec(&value)?))
}
fn validate_no_resume(r: &NoResumeReview) -> Result<()> {
    ensure!(
        held_partial::schema_matches(
            &r.schema,
            "horizon-retry6-166-no-resume-review",
            &r.held_partial_completion
        ) && r.owner == "/root"
            && r.epoch == 166
            && r.run == Path::new(RUN)
            && r.scratch == Path::new(SCRATCH)
            && r.producer_unit == UNIT
            && r.producer_invocation_id == IID
            && r.original_native == Bound::fixed(NATIVE, NATIVE_SHA)
            && r.original_argv == Bound::fixed(ORIGINAL_ARGV, ORIGINAL_ARGV_SHA)
            && r.manifest == Bound::fixed(MANIFEST, MANIFEST_SHA)
            && r.package_seal == Bound::fixed(PACKAGE_SEAL, PACKAGE_SEAL_SHA)
            && r.source_lineage == Bound::fixed(LINEAGE, LINEAGE_SHA)
            && r.stop_completion == Bound::fixed(STOP, STOP_SHA)
            && r.node == Bound::fixed(NODE, NODE_SHA)
            && r.worker == Bound::fixed(WORKER, WORKER_SHA)
            && r.source_commit == SOURCE_COMMIT
            && r.cohort_state_sha256 == STATE_SHA
            && r.exact_source_image_binding_established
            && r.no_admitted_scratch_continuation
            && r.no_native_bank_or_writer_cursor
            && r.original_invocation_restarts_from_bootstrap
            && r.snapshot_exports_and_indirect_readers_reviewed
            && r.preserve_partial_archive_and_inputs,
        "exact build/state-bound no-resume review required; source lineage alone is insufficient"
    );
    for set in [&r.exact_source_image_evidence, &r.reviewed_source_evidence] {
        ensure!(
            !set.is_empty() && set.len() <= 64,
            "missing exact build/source evidence"
        );
        for b in set {
            ensure!(
                b.path.is_absolute() && !b.path.starts_with(DESTINATION) && lower_sha(&b.sha256),
                "invalid retained build/source binding"
            );
        }
    }
    ensure!(
        REVIEWED_SOURCE_SHAS.iter().all(|digest| r
            .reviewed_source_evidence
            .iter()
            .any(|b| b.sha256 == *digest)),
        "exact reviewed node/runtime/snapshot/worker source set required"
    );
    for b in &r.exact_source_image_evidence {
        ensure!(
            ![
                LINEAGE_SHA,
                PACKAGE_SEAL_SHA,
                NODE_SHA,
                WORKER_SHA,
                NATIVE_SHA,
                ORIGINAL_ARGV_SHA,
                MANIFEST_SHA
            ]
            .contains(&b.sha256.as_str())
                && !REVIEWED_SOURCE_SHAS.contains(&b.sha256.as_str()),
            "capability lineage, seal, source or artifact alone is not exact production build proof"
        );
    }
    Ok(())
}
fn no_resume(p: &Plan) -> Result<NoResumeReview> {
    let r: NoResumeReview = serde_json::from_slice(&bound(&p.no_resume_review, MAX_JSON)?)?;
    validate_no_resume(&r)?;
    ensure!(
        r.held_partial_completion == p.held_partial_completion,
        "plan and no-resume review disagree about partial custody"
    );
    for b in [
        &r.original_native,
        &r.original_argv,
        &r.manifest,
        &r.package_seal,
        &r.source_lineage,
        &r.stop_completion,
        &r.node,
        &r.worker,
        &r.analysis,
    ]
    .into_iter()
    .chain(r.exact_source_image_evidence.iter())
    .chain(r.reviewed_source_evidence.iter())
    {
        ensure!(
            b.path != p.no_resume_review.path && b.path != p.dependency_review.path,
            "review cannot stand in for original build/source evidence"
        );
        bound(b, 128 << 20)?;
    }
    let state = raw(&Path::new(RUN).join("cohort-state.json"), STATE_BYTES, UID)?;
    ensure!(
        sha(&state) == r.cohort_state_sha256,
        "reviewed cohort state changed"
    );
    let value: Value = serde_json::from_slice(&state)?;
    ensure!(
        value
            == json!({"schema":"jetstreamer-root-cohort-run-v1","start_epoch":166,
        "end_epoch":166,"status":"running-private","manifest_fingerprint":FINGERPRINT}),
        "unreviewed continuation/cursor state"
    );
    Ok(r)
}
fn unit_closed(unit: &str) -> Result<Value> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-pId,LoadState,ActiveState,SubState,MainPID,ControlPID,NRestarts,Job,InvocationID",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() < 65_536,
        "native unit query failed"
    );
    let fields: BTreeMap<_, _> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| line.split_once('=').context("native field"))
        .collect::<Result<_>>()?;
    validate_closed(&fields, unit)?;
    Ok(serde_json::to_value(fields)?)
}
fn validate_closed(fields: &BTreeMap<&str, &str>, unit: &str) -> Result<()> {
    ensure!(
        fields.get("Id") == Some(&unit)
            && fields.get("ActiveState") == Some(&"inactive")
            && fields.get("SubState") == Some(&"dead")
            && fields.get("Job") == Some(&"")
            && fields.get("MainPID").is_none_or(|v| *v == "0")
            && fields.get("ControlPID").is_none_or(|v| *v == "0")
            && fields.get("NRestarts").is_none_or(|v| *v == "0"),
        "old producer or guard is active or queued: {unit}"
    );
    Ok(())
}
fn stopped_proof(p: &Plan) -> Result<()> {
    let i: Value = serde_json::from_slice(&bound(&p.stop_intent, MAX_JSON)?)?;
    let s: Value = serde_json::from_slice(&bound(&p.stop_completion, MAX_JSON)?)?;
    let a: Value = serde_json::from_slice(&bound(&p.admission, MAX_JSON)?)?;
    let g: Value = serde_json::from_slice(&bound(&p.guard_protection, MAX_JSON)?)?;
    ensure!(
        i["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
            && i["producer_invocation_id"] == IID
            && i["plan_sha256"] == GUARD_PLAN_SHA
            && i["reason"] == "DATA-fulfillment-observation-failed"
            && s["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
            && s["producer_invocation_id"] == IID
            && s["plan_sha256"] == GUARD_PLAN_SHA
            && s["terminal"]["active"] == "inactive"
            && s["terminal"]["sub"] == "dead"
            && s["terminal"]["pid"] == 0
            && s["terminal"]["restarts"] == 0
            && s["scratch_deleted"] == false
            && s["r2_mutations"] == false
            && a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["epoch"] == 166
            && a["producer_unit"] == UNIT
            && a["producer_invocation_id"] == IID
            && a["fresh_admission_passed"] == true
            && a["resource_credit_bytes"] == 0
            && g["schema"] == "horizon-standard-live-peer-protection-v1"
            && g["epoch"] == 166
            && g["producer_unit"] == UNIT
            && g["producer_invocation_id"] == IID
            && g["admission"] == serde_json::to_value(&p.admission)?,
        "genuine exact retry6 stop proof required"
    );
    Ok(())
}
fn gates(p: &Plan) -> Result<Value> {
    stopped_proof(p)?;
    let review = no_resume(p)?;
    let units = [
        UNIT.to_owned(),
        format!("{GUARD}.service"),
        format!("{GUARD}.timer"),
    ];
    let mut closed = BTreeMap::new();
    for unit in &units {
        closed.insert(unit.clone(), unit_closed(unit)?);
    }
    let dependency = references::dependency(p)?;
    let mounts = references::mounts()?;
    // Deliberately scope to this old destination, not all epoch166 work.
    let processes = process_references::scan(Path::new("/proc"), Path::new(DESTINATION))?;
    ensure!(
        processes.references.is_empty(),
        "live references to old retry6 destination"
    );
    let staged = references::staged(&dependency)?;
    for (unit, before) in &closed {
        ensure!(
            unit_closed(unit)? == *before,
            "old owner changed during gates"
        );
    }
    Ok(
        json!({"closed_units":closed,"no_resume_review":p.no_resume_review,
        "cohort_state_sha256":review.cohort_state_sha256,"dependency_review":p.dependency_review,
        "mounts":mounts,"process_reference_scan":processes,"staged":staged}),
    )
}
fn check(p: &Plan, plan_sha: &str, held: &Held) -> Result<()> {
    held.recheck(p)?;
    let evidence = gates(p)?;
    let root = stopped_tree::open_root(Path::new(SCRATCH), DEVICE, SCRATCH_INODE)?;
    let first = stopped_tree::capture(&root, DEVICE, UID, GID)?;
    let second = stopped_tree::capture(&root, DEVICE, UID, GID)?;
    ensure!(
        first == second && first.len() > 100_000,
        "scratch changed or is already empty"
    );
    let retained = custody::preserved(true, p.held_partial_completion.as_ref())?;
    let final_gates = gates(p)?;
    ensure!(
        custody::preserved(false, p.held_partial_completion.as_ref())?.identities
            == retained.identities,
        "retained files changed during check"
    );
    ensure!(
        stopped_tree::capture(&root, DEVICE, UID, GID)? == first,
        "scratch changed during retained proof"
    );
    let bytes = serde_json::to_vec(&first)?;
    let ledger = Path::new(BASE).join("LEDGER.json");
    held.recheck(p)?;
    atomic(&ledger, &bytes)?;
    let receipt = json!({"schema":"horizon-retry6-166-scratch-retirement-check-v1",
        "owner":"/root","epoch":166,"run":RUN,"scratch":SCRATCH,
        "scratch_device":DEVICE,"scratch_inode":SCRATCH_INODE,"plan_sha256":plan_sha,"scope_sha256":scope_sha(p)?,
        "ledger":{"path":ledger,"sha256":sha(&bytes)},"entry_count":first.len(),
        "preserved":retained,"first_gates":evidence,"final_gates":final_gates,
        "recorded_unix_seconds":now()?,"archive_deletion_authorized":false,"remote_mutations":false,
        "replay_launch_authorized":false,"resource_credit_bytes":0,"resource_promise_ending_authorized":false});
    atomic(
        &Path::new(BASE).join("CHECK.json"),
        &serde_json::to_vec_pretty(&receipt)?,
    )?;
    println!(
        "{}",
        json!({"check":Path::new(BASE).join("CHECK.json"),"entries":first.len(),"scratch_retired":false})
    );
    Ok(())
}
fn execute(p: &Plan, plan_sha: &str, held: &Held) -> Result<()> {
    held.recheck(p)?;
    ensure!(
        !Path::new(BASE).join("COMPLETE.json").try_exists()?,
        "retirement already completed; preserve its receipt"
    );
    let check_path = Path::new(BASE).join("CHECK.json");
    let check_bytes = raw(&check_path, MAX_JSON, 0)?;
    let check: Value = serde_json::from_slice(&check_bytes)?;
    ensure!(
        check["schema"] == "horizon-retry6-166-scratch-retirement-check-v1"
            && check["scope_sha256"] == scope_sha(p)?
            && check["scratch"] == SCRATCH
            && check["scratch_inode"] == SCRATCH_INODE,
        "check receipt differs"
    );
    let retained: custody::Preserved = serde_json::from_value(check["preserved"].clone())?;
    ensure!(
        custody::preserved(false, p.held_partial_completion.as_ref())?.identities
            == retained.identities,
        "protected sibling changed"
    );
    let ledger: Bound = serde_json::from_value(check["ledger"].clone())?;
    ensure!(
        ledger.path == Path::new(BASE).join("LEDGER.json"),
        "foreign ledger"
    );
    let expected: stopped_tree::Ledger = serde_json::from_slice(&bound(&ledger, 256 << 20)?)?;
    ensure!(
        expected.len() == check["entry_count"].as_u64().context("entry count")? as usize,
        "ledger count differs"
    );
    let evidence = gates(p)?;
    let root = stopped_tree::open_root(Path::new(SCRATCH), DEVICE, SCRATCH_INODE)?;
    let current = stopped_tree::capture(&root, DEVICE, UID, GID)?;
    let intent_path = Path::new(BASE).join("INTENT.json");
    let resuming = intent_path.try_exists()?;
    if resuming {
        let intent: Value = serde_json::from_slice(&raw(&intent_path, MAX_JSON, 0)?)?;
        ensure!(
            intent["schema"] == "horizon-retry6-166-scratch-retirement-intent-v1"
                && intent["scope_sha256"] == scope_sha(p)?
                && intent["ledger"] == check["ledger"]
                && intent["scope"] == SCRATCH
                && intent["preserved"] == check["preserved"]
                && intent["check"] == json!({"path":check_path,"sha256":sha(&check_bytes)}),
            "resume intent differs"
        );
    }
    stopped_tree::validate_remaining(&expected, &current, resuming)?;
    if !resuming {
        let intent = json!({"schema":"horizon-retry6-166-scratch-retirement-intent-v1",
            "owner":"/root","epoch":166,"plan_sha256":plan_sha,"scope_sha256":scope_sha(p)?,
            "check":{"path":check_path,"sha256":sha(&check_bytes)},
            "ledger":check["ledger"],"preserved":check["preserved"],"first_gates":evidence,
            "recorded_unix_seconds":now()?,"scope":SCRATCH,"resource_credit_bytes":0,
            "resource_promise_ending_authorized":false,"archive_deletion_authorized":false,"remote_mutations":false});
        atomic(&intent_path, &serde_json::to_vec_pretty(&intent)?)?;
    }
    // Refresh mounts/readers immediately before the only destructive operation.
    // No archive hash is repeated here; exact metadata remains pinned to CHECK.
    let pre_remove = gates(p)?;
    ensure!(
        custody::preserved(false, p.held_partial_completion.as_ref())?.identities
            == retained.identities,
        "retained files changed before unlink"
    );
    held.recheck(p)?;
    let removed = stopped_tree::remove_contents(&root, &expected, DEVICE, UID, GID)?;
    let after = custody::preserved(true, p.held_partial_completion.as_ref())?;
    ensure!(
        after == retained,
        "protected content changed after retirement"
    );
    let final_gates = gates(p)?;
    held.recheck(p)?;
    let final_tree = stopped_tree::capture(&root, DEVICE, UID, GID)?;
    stopped_tree::validate_remaining(&expected, &final_tree, true)?;
    ensure!(
        final_tree.len() == 1,
        "scratch was repopulated before completion"
    );
    let complete = json!({"schema":"horizon-retry6-166-scratch-retirement-complete-v1",
        "owner":"/root","epoch":166,"plan_sha256":plan_sha,"scope_sha256":scope_sha(p)?,
        "intent":{"path":intent_path,"sha256":sha(&raw(&intent_path,MAX_JSON,0)?)},
        "scratch":SCRATCH,"scratch_inode":SCRATCH_INODE,"retired_entry_count":removed,
        "resumed":resuming,"scratch_root_preserved":true,"scratch_empty":true,
        "preserved":after,"pre_remove_gates":pre_remove,"final_gates":final_gates,
        "recorded_unix_seconds":now()?,"resource_credit_bytes":0,"resource_promise_ending_authorized":false,
        "archive_deletion_authorized":false,"remote_mutations":false,"replay_launch_authorized":false,
        "physical_reclamation_accounting_separately_required":true});
    atomic(
        &Path::new(BASE).join("COMPLETE.json"),
        &serde_json::to_vec_pretty(&complete)?,
    )?;
    println!(
        "{}",
        json!({"complete":Path::new(BASE).join("COMPLETE.json"),"retired_entries":removed,"scratch_empty":true})
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 7
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && lower_sha(&args[3])
            && lower_sha(&args[5])
            && matches!(args[6].as_str(), "--check-only" | "--execute"),
        "usage: retire PLAN --plan-sha256 SHA --self-sha256 SHA (--check-only|--execute)"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && fs::read_link("/proc/self/exe")? == Path::new(IMAGE),
        "normally sealed root runtime required"
    );
    let mut live_image = File::open("/proc/self/exe")?;
    let image_identity = custody::identity(&live_image.metadata()?);
    let mut image_bytes = Vec::new();
    Read::by_ref(&mut live_image)
        .take((128 << 20) + 1)
        .read_to_end(&mut image_bytes)?;
    ensure!(
        image_bytes.len() <= 128 << 20
            && sha(&image_bytes) == args[5]
            && custody::identity(&live_image.metadata()?) == image_identity
            && custody::identity(&fs::symlink_metadata(IMAGE)?) == image_identity
            && sha(&raw(Path::new(IMAGE), 128 << 20, 0)?) == args[5],
        "running image differs from separately supplied self digest or normal sealed pathname"
    );
    let plan_bytes = raw(Path::new(&args[1]), MAX_JSON, 0)?;
    ensure!(sha(&plan_bytes) == args[3], "plan digest differs");
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_plan(&plan)?;
    let locks = custody::hold_locks(&plan.shared_locks)?;
    let out = custody::open_directory(Path::new(BASE))?;
    ensure!(
        out.metadata()?.uid() == 0
            && out.metadata()?.mode() & 0o7777 == 0o700
            && unsafe { libc::flock(out.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "private lifecycle receipt directory required and must be exclusively locked"
    );
    let ancestors = custody::hold_ancestors(Path::new(RUN))?;
    let held = Held {
        locks,
        ancestors,
        output_identity: custody::directory_identity(&out.metadata()?),
        output: out,
    };
    match args[6].as_str() {
        "--check-only" => check(&plan, &args[3], &held)?,
        "--execute" => execute(&plan, &args[3], &held)?,
        _ => unreachable!(),
    }
    held.recheck(&plan)?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
