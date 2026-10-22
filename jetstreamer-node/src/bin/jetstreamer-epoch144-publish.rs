//! Exact144 V4 artifact import. Preserves the root-owned original, requires both
//! private scans, copies/hashes independently, and commits checksum last through
//! the existing absence-only transaction after a permanent UID/GID drop.
#[path = "epoch144_publish/capacity.rs"]
mod capacity;
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
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
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch144-assembly-only-20261022-v2/epoch-144-assembly-only-v4.jet";
const PUBLIC: &str = "/home/sol/horizon";
const DIGEST: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const LENGTH: u64 = 109177480876;
const PROVENANCE: &str = "170dec96fb56881135293366ef1c85d8d790918f51a2c9d2fc4fbbc6beced819";
const AUDITOR: &str = "9a84a6475d0475a22d780845b25a692e5f2454e16689d2940446eb152e20eeae";
const RUNNER: &str = "7dfe0fdabbee8e5f79b131c2b7cece49dbebe489168fe195a9086ab25f0b8810";
const FULL: &str = "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7";
const PLUGIN: &str = "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9";
// Conservative existing seven-producer protection, NOT the century floor.
// This profile never lowers any live guard. Freshly qualifying a smaller
// envelope requires a separate source/plan transition, not editing this value.
const PROTECTED: u64 = 4740696923590;
const MARGIN: u64 = 1 << 30;
const UID: u32 = 1001;
const GID: u32 = 1003;
// The writer lock opens every ancestor O_RDONLY|O_DIRECTORY, not O_PATH.
// Only fresh, non-sensitive work roots get this mode; receipts stay0700.
const WORK_MODE: u32 = 0o755;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    evidence: Bound,
    observer: Bound,
    fleet: Bound,
    century_floor: Bound,
    work_directory: PathBuf,
    receipt_directory: PathBuf,
    artifact_publication_authorized: bool,
    runtime_registry_promotion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
    #[serde(default)]
    refreshed_capacity: Option<capacity::Refresh>,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn binding(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn absent(p: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(p),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "namespace exists:{}",
        p.display()
    );
    Ok(())
}
fn directory(p: &Path, owner: u32, mode: u32) -> Result<File> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical directory"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_dir()
            && m.uid() == owner
            && m.mode() & 0o7777 == mode
            && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(p)?),
        "directory ownership/mode/identity differs"
    );
    Ok(f)
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        ((p.schema == "jetstreamer-exact144-v4-publication-plan-v1"
            && p.refreshed_capacity.is_none())
            || (p.schema == "jetstreamer-exact144-v4-publication-plan-v2"
                && p.refreshed_capacity.is_some()))
            && p.artifact_publication_authorized
            && !p.runtime_registry_promotion_authorized
            && !p.remote_mutations
            && !p.r2_mutations,
        "wrong publication authority"
    );
    ensure!(
        p.work_directory.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && p.work_directory.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("epoch144-publication-work-")),
        "wrong work namespace"
    );
    ensure!(
        p.receipt_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.receipt_directory.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-epoch144-publication-")),
        "wrong receipt namespace"
    );
    ensure!(
        p.evidence
            .path
            .file_name()
            .is_some_and(|n| n == "evidence.json")
            && p.evidence.path.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch144-publication-evidence-"))),
        "foreign evidence namespace"
    );
    Ok(())
}
fn validate_evidence(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private144-publication-evidence-v1"
            && v["epoch"] == 144
            && v["tool_sha256"] == AUDITOR
            && v["archive_path"] == SOURCE
            && v["archive_sha256"] == DIGEST
            && v["archive_bytes"] == LENGTH
            && v["expected_provenance_sha256"] == PROVENANCE
            && v["independent_full_and_plugin_receipts_validated"] == true
            && v["fresh_archive_hash_performed"] == false
            && v["copy_performed"] == false,
        "foreign or incomplete scan audit"
    );
    for flag in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "runtime_registry_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "auditor acquired authority:{flag}");
    }
    let id = v["archive_identity"]
        .as_array()
        .context("source identity")?;
    ensure!(
        id.len() == 10 && id[2] == LENGTH && id[3] == 0 && id[4] == 0o100600 && id[5] == 1,
        "unsafe original identity"
    );
    Ok(())
}
fn validate_archive(f: &File) -> Result<()> {
    let mut opened = f.try_clone()?;
    opened.seek(SeekFrom::Start(0))?;
    let reader = ArchiveReader::open(BufReader::new(opened))
        .map_err(|e| anyhow::anyhow!("archive header:{e}"))?;
    ensure!(
        reader.header().slot_start == 62208000 && reader.header().slot_count == 432000,
        "not complete144"
    );
    let p = reader
        .provenance()
        .map_err(|e| anyhow::anyhow!("provenance:{e}"))?
        .context("missing V4")?;
    ensure!(matches!(p, ArchiveProvenance::V4(_)), "not V4");
    let bytes =
        encode_archive_provenance(&p).map_err(|e| anyhow::anyhow!("provenance encoding:{e}"))?;
    ensure!(
        evidence::sha(&bytes) == PROVENANCE,
        "independent V4 expectation differs"
    );
    Ok(())
}
fn original(v: &Value) -> Result<File> {
    let path = Path::new(SOURCE);
    ensure!(path.canonicalize()? == path, "source noncanonical");
    let f = open_regular_nofollow(path)?;
    ensure!(
        json!(evidence::identity(&f.metadata()?)) == v["archive_identity"]
            && json!(evidence::identity(&fs::symlink_metadata(path)?)) == v["archive_identity"],
        "original changed"
    );
    absent(&path.with_extension("jet.sha256"))?;
    Ok(f)
}
fn utc(s: &str) -> Result<u64> {
    let expected = s;
    let s = std::ffi::CString::new(s)?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(s.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "invalid UTC");
    let n = unsafe { libc::timegm(&mut tm) };
    ensure!(n >= 0, "invalid clock");
    ensure!(
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        ) == expected,
        "noncanonical UTC"
    );
    Ok(n as u64)
}
fn live_owners(fleet: &Value) -> Result<()> {
    let mut seen = std::collections::BTreeMap::new();
    for row in fleet["active"].as_array().context("active fleet census")? {
        for key in ["controller", "producer", "unit"] {
            let owner = &row[key];
            if !owner.is_object() {
                continue;
            }
            let unit = owner["Id"].as_str().context("owner unit")?;
            if let Some(previous) = seen.insert(unit, owner) {
                ensure!(previous == owner, "inconsistent duplicate owner");
                continue;
            }
            let result = Command::new("/usr/bin/systemctl")
                .args([
                    "show",
                    unit,
                    "--property=Id,InvocationID,MainPID,NRestarts,ActiveState,SubState,ExecStart",
                ])
                .output()?;
            ensure!(result.status.success(), "live owner observation failed");
            let text = std::str::from_utf8(&result.stdout)?;
            let fields: std::collections::BTreeMap<_, _> =
                text.lines().filter_map(|l| l.split_once('=')).collect();
            ensure!(
                fields.get("ActiveState") == Some(&"active")
                    && fields.get("SubState") == Some(&"running")
                    && fields.get("NRestarts") == Some(&"0"),
                "fleet owner not live zero-restart"
            );
            for (key, value) in fields {
                if key == "ExecStart" {
                    let expected = owner[key].as_str().context("bound command")?;
                    ensure!(
                        value
                            .split_once(" ; ignore_errors=")
                            .map(|p| p.0)
                            .zip(expected.split_once(" ; ignore_errors=").map(|p| p.0))
                            .is_some_and(|(actual, expected)| actual == expected),
                        "fleet command changed:{unit}"
                    );
                    continue;
                }
                ensure!(owner[key] == value, "fleet owner changed:{unit}:{key}");
            }
        }
    }
    ensure!(!seen.is_empty(), "empty owner census");
    Ok(())
}
fn resources(p: &Plan) -> Result<Value> {
    ensure!(
        p.century_floor.path
            == Path::new(
                "/home/sol/.jetstreamer-private/century-floor-epoch201-audit-20261019-v1/verification-v3/century-floor.json"
            )
            && p.century_floor.sha256
                == "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682",
        "unqualified century census"
    );
    let floor = read(&p.century_floor, false)?;
    ensure!(
        floor["schema"] == "jetstreamer-horizon-century-jet-floor-v1"
            && floor["samples"].as_array().is_some_and(|s| s.len() == 1)
            && floor["samples"][0]["epoch"] == 201
            && floor["samples"][0]["jet_size_bytes"] == 102605729507u64,
        "century sample differs"
    );
    let sample_bytes = floor["samples"][0]["jet_size_bytes"]
        .as_u64()
        .context("canonical sample length")?;
    let sample_count = floor["samples"].as_array().unwrap().len() as u64;
    let floor_bytes = sample_bytes
        .checked_mul(2)
        .context("floor overflow")?
        .div_ceil(sample_count);
    ensure!(
        floor["arithmetic"]["floor_bytes"] == floor_bytes && floor_bytes == 205211459014,
        "floor arithmetic differs"
    );
    for (path_key, sha_key) in [
        (
            "private_resource_verification",
            "private_resource_verification_sha256",
        ),
        ("r2_receipt", "r2_receipt_sha256"),
    ] {
        read(
            &Bound {
                path: floor["samples"][0][path_key]
                    .as_str()
                    .context("floor proof path")?
                    .into(),
                sha256: floor["samples"][0][sha_key]
                    .as_str()
                    .context("floor proof digest")?
                    .into(),
            },
            false,
        )?;
    }
    let o = read(&p.observer, false)?;
    let fleet = read(&p.fleet, false)?;
    let sample = utc(o["recorded_at_utc"].as_str().context("observer clock")?)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let replay_count = capacity::replay_count(p)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample <= now
            && now - sample <= 1800
            && o["cadence"]["routine_minimum_interval_enforced"] == true
            && o["replays"]
                .as_array()
                .is_some_and(|a| a.len() == replay_count
                    && a.iter().all(|r| r["invocation_binding_stable"] == true
                        && r["controller_after"]["restarts"] == 0
                        && r["producer_after"]["restarts"] == 0)),
        "stale or unstable resource sample"
    );
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["sampled_at_utc"] == o["recorded_at_utc"]
            && fleet["observer_sha256"] == p.observer.sha256
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["inventory"]["anomalies"] == 0,
        "incomplete fleet binding"
    );
    let (protected, refreshed) = if p.refreshed_capacity.is_some() {
        let (bytes, report) = capacity::qualify(p, &o, &fleet, floor_bytes)?;
        (bytes, report)
    } else {
        (PROTECTED, Value::Null)
    };
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= protected + LENGTH + MARGIN)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 192 * 1024 * 1024),
        "sample cannot fit independent copy above unchanged protections"
    );
    actual_free(protected, LENGTH)?;
    live_owners(&fleet)?;
    Ok(
        json!({"observer":p.observer,"fleet":p.fleet,"century_floor":p.century_floor,"century_floor_bytes":floor_bytes,"protected_remaining_and_guards_bytes":protected,"copy_bytes":LENGTH,"margin_bytes":MARGIN,"century_floor_recomputed":true,"refreshed_capacity":refreshed,"policy":"separate growth/delivery and guard protection, not the century floor; no live guard lowered"}),
    )
}
fn actual_free(protected: u64, remaining: u64) -> Result<()> {
    let name = std::ffi::CString::new("/home/sol")?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(name.as_ptr(), &mut st) } == 0,
        "statvfs"
    );
    let available = st
        .f_bavail
        .checked_mul(st.f_frsize)
        .context("free overflow")?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
        })
        .context("memory availability")?;
    ensure!(
        available >= protected + remaining + MARGIN && memory >= 192 * 1024 * 1024,
        "actual copy admission/guard rejected"
    );
    Ok(())
}
struct Sink {
    file: File,
    directory: File,
}
impl Sink {
    fn create(dir: &Path, name: &str) -> Result<Self> {
        let directory = directory(dir, 0, 0o700)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir.join(name))?;
        file.sync_all()?;
        directory.sync_all()?;
        Ok(Self { file, directory })
    }
    fn write(&mut self, b: &[u8]) -> Result<()> {
        let m = self.file.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600
                && m.len() == 0,
            "receipt sink changed"
        );
        self.file.write_all(b)?;
        self.file.sync_all()?;
        self.directory.sync_all()?;
        Ok(())
    }
    fn json(&mut self, v: &Value) -> Result<()> {
        let mut b = serde_json::to_vec_pretty(v)?;
        b.push(b'\n');
        self.write(&b)
    }
}
fn drop_owner() -> Result<()> {
    ensure!(
        fs::read_dir("/proc/self/task")?.count() == 1,
        "single-threaded privilege transition required"
    );
    ensure!(
        unsafe { libc::setgroups(0, std::ptr::null()) } == 0
            && unsafe { libc::setresgid(GID, GID, GID) } == 0
            && unsafe { libc::setresuid(UID, UID, UID) } == 0,
        "permanent credential drop failed"
    );
    let (mut r, mut e, mut s) = (0, 0, 0);
    ensure!(
        unsafe { libc::getresuid(&mut r, &mut e, &mut s) } == 0 && (r, e, s) == (UID, UID, UID),
        "uid not permanent"
    );
    ensure!(
        unsafe { libc::getresgid(&mut r, &mut e, &mut s) } == 0 && (r, e, s) == (GID, GID, GID),
        "gid not permanent"
    );
    let status = fs::read_to_string("/proc/self/status")?;
    for name in ["CapPrm:", "CapEff:", "CapAmb:"] {
        ensure!(
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .context("capabilities")?
                .trim()
                == "0000000000000000",
            "capability survived drop"
        );
    }
    Ok(())
}
fn assign(f: &File) -> Result<()> {
    ensure!(
        unsafe { libc::fchown(f.as_raw_fd(), UID, GID) } == 0,
        "copy ownership assignment failed"
    );
    Ok(())
}
fn finish_copy_permissions(file: &File, destination: &Path) -> Result<()> {
    // Set mode while root still owns the newly created copy. After chown,
    // root deliberately lacks CAP_FOWNER and must not chmod the sol-owned file.
    prepare_archive_permissions(file, destination)
        .context("prepare root-owned copy permissions before handoff")?;
    assign(file)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == UID
            && m.gid() == GID
            && m.mode() & 0o7777 == 0o440
            && m.nlink() == 1,
        "copy permission handoff differs"
    );
    file.sync_all()?;
    Ok(())
}
fn copy_checked(
    input: &mut impl Read,
    output: &mut impl Write,
    length: u64,
    expected: &str,
    mut guard: impl FnMut(u64) -> Result<()>,
) -> Result<()> {
    let mut sha = Sha256::new();
    let mut buffer = vec![0; 8 << 20];
    let mut written = 0u64;
    loop {
        guard(length - written)?;
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        written = written
            .checked_add(n as u64)
            .context("copy size overflow")?;
        ensure!(written <= length, "source grew");
        sha.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    ensure!(
        written == length && format!("{:x}", sha.finalize()) == expected,
        "copy digest/length differs"
    );
    Ok(())
}
fn audit_inputs(v: &Value) -> Result<()> {
    for key in [
        "full",
        "plugin",
        "producer_outcome",
        "provenance_expectation",
        "boundaries",
        "plan",
    ] {
        read(&binding(&v[key])?, false)?;
    }
    for stage in ["full", "plugin"] {
        let b = binding(&v["logs"][stage])?;
        evidence::bound_file(&b.path, &b.sha256, 64 << 20, false)?;
    }
    evidence::bound_file(
        Path::new(
            "/usr/local/lib/jetstreamer/horizon-epoch144-publication-evidence-candidate-20261022-v1/jetstreamer-epoch144-publication-evidence",
        ),
        AUDITOR,
        128 << 20,
        true,
    )?;
    Ok(())
}
fn run(p: &Plan, plan: &Bound, self_sha: &str, check: bool) -> Result<()> {
    validate_plan(p)?;
    let v = read(&p.evidence, false)?;
    validate_evidence(&v)?;
    audit_inputs(&v)?;
    let source = original(&v)?;
    let dest = Path::new(PUBLIC);
    let public = directory(dest, UID, 0o3770)?;
    ensure!(public.metadata()?.gid() == GID, "destination group differs");
    let work = directory(&p.work_directory, 0, WORK_MODE)?;
    ensure!(
        work.metadata()?.dev() == source.metadata()?.dev()
            && work.metadata()?.dev() == public.metadata()?.dev(),
        "cross-filesystem copy/import"
    );
    directory(&p.receipt_directory, 0, 0o700)?;
    for d in ["full", "plugin"] {
        directory(&p.receipt_directory.join(d), 0, 0o700)?;
    }
    for n in [
        "epoch-144.jet",
        "epoch-144.jet.sha256",
        "epoch-144.jet.segment.json",
    ] {
        absent(&dest.join(n))?;
    }
    let stage = p.work_directory.join("stage");
    absent(&stage)?;
    let mount = write_scope::same_mount(&[&p.work_directory, dest])?;
    let admission = resources(p)?;
    let protected = admission["protected_remaining_and_guards_bytes"]
        .as_u64()
        .context("admitted protection missing")?;
    if check {
        println!("exact144 publication preflight passed; no writes, copy, hash or import");
        return Ok(());
    }
    let scope = write_scope::confine(&[&p.work_directory, &p.receipt_directory, dest])?;
    let context = json!({"schema":"jetstreamer-exact144-v4-publication-context-v1","epoch":144,"plan":plan,"publisher_sha256":self_sha,"evidence":p.evidence,"admission":admission,"mount_id":mount,"kernel_write_scope":scope,"original_preserved":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut intent = Sink::create(&p.receipt_directory, "intent.json")?;
    let mut result = Sink::create(&p.receipt_directory, "publication.json")?;
    let mut full = Sink::create(&p.receipt_directory.join("full"), "epoch-144.full.ok")?;
    let mut plugin = Sink::create(&p.receipt_directory.join("plugin"), "epoch-144.plugin.ok")?;
    intent.json(&context)?;
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let stage_dir = directory(&stage, 0, 0o700)?;
    let copied = stage.join("epoch-144.jet");
    let mut output = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&copied)?;
    let mut input = source.try_clone()?;
    copy_checked(&mut input, &mut output, LENGTH, DIGEST, |remaining| {
        actual_free(protected, remaining)
    })?;
    output.sync_all()?;
    stage_dir.sync_all()?;
    work.sync_all()?;
    ensure!(
        output.metadata()?.ino() != source.metadata()?.ino(),
        "copy shares source inode"
    );
    original(&v)?;
    validate_archive(&output)?;
    let current_public = directory(dest, UID, 0o3770)?;
    ensure!(
        current_public.metadata()?.gid() == GID
            && current_public.metadata()?.dev() == public.metadata()?.dev()
            && current_public.metadata()?.ino() == public.metadata()?.ino(),
        "destination replaced during copy"
    );
    let current_work = directory(&p.work_directory, 0, WORK_MODE)?;
    ensure!(
        current_work.metadata()?.dev() == work.metadata()?.dev()
            && current_work.metadata()?.ino() == work.metadata()?.ino(),
        "work root replaced during copy"
    );
    finish_copy_permissions(&output, dest)?;
    assign(&stage_dir)?;
    stage_dir.sync_all()?;
    let measured = measure_open_archive(&output)?;
    ensure!(
        sha256_hex_string(&measured.sha256) == DIGEST,
        "independent copied archive reread differs"
    );
    audit_inputs(&v)?;
    read(&p.evidence, false)?;
    original(&v)?;
    actual_free(protected, 0)?;
    if p.refreshed_capacity.is_some() {
        let (current, _) = capacity::qualify(
            p,
            &read(&p.observer, false)?,
            &read(&p.fleet, false)?,
            205211459014,
        )?;
        ensure!(
            current == protected,
            "admitted protection changed before import"
        );
    }
    live_owners(&read(&p.fleet, false)?)?;
    let transaction: [u8; 32] = Sha256::digest(evidence::bound_file(
        &plan.path,
        &plan.sha256,
        4 << 20,
        true,
    )?)
    .into();
    drop_owner()?;
    preflight_archive_publication(&stage, dest)?;
    let publication = publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
        transaction,
        &[144],
        &[ArchiveBatchItem {
            epoch: 144,
            staged_archive: copied,
            destination_archive: dest.join("epoch-144.jet"),
            evidence: measured,
        }],
        &serde_json::to_vec(&context)?,
        Duration::from_secs(60),
    )?;
    result.json(&json!({"schema":"jetstreamer-exact144-v4-publication-receipt-v1","epoch":144,"context":context,"archive_sha256":DIGEST,"archive_bytes":LENGTH,"transaction_id":sha256_hex_string(&publication.transaction_id),"archive_path":publication.publications[0].archive_path,"checksum_path":publication.publications[0].checksum_path,"committed":true,"original_assembly_preserved":true,"copy_rehashed_independently":true,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,"private_runner_sha256":RUNNER,"retirement_authorized":false,"runtime_registry_promoted":false,"remote_mutations":false,"r2_mutations":false}))?;
    full.write(format!("{DIGEST} {FULL} {RUNNER}\n").as_bytes())?;
    plugin.write(format!("{DIGEST} {PLUGIN} {RUNNER}\n").as_bytes())?;
    acknowledge_archive_publication_batch(dest, publication.transaction_id)?;
    println!("exact144 artifact committed locally; original preserved; no R2 mutation");
    Ok(())
}
/// Disposable proof of the same FD, privilege-drop and transaction sequence.
/// Never opens SOURCE or PUBLIC and never grants campaign admission.
fn capability(root: &Path, self_sha: &str) -> Result<()> {
    ensure!(
        root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && root.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("epoch144-publication-capability-")),
        "foreign capability root"
    );
    directory(root, 0, WORK_MODE)?;
    ensure!(
        fs::read_dir(root)?.next().is_none(),
        "capability root not empty"
    );
    let receipts = root.join("receipts");
    let stage = root.join("stage");
    let dest = root.join("destination");
    for path in [&receipts, &stage, &dest] {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    let mut sink = Sink::create(&receipts, "capability.json")?;
    let stage_dir = directory(&stage, 0, 0o700)?;
    let destination = directory(&dest, 0, 0o700)?;
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o3770))
        .context("prepare root-owned fixture directory mode")?;
    assign(&stage_dir)?;
    assign(&destination)?;
    let copied = stage.join("epoch-144.jet");
    let mut f = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&copied)?;
    f.write_all(b"private filesystem capability only; NOT a Horizon archive\n")?;
    finish_copy_permissions(&f, &dest)?;
    stage_dir.sync_all()?;
    destination.sync_all()?;
    File::open(root)?.sync_all()?;
    let measured = measure_open_archive(&f)?;
    let mount = write_scope::same_mount(&[&stage, &dest])?;
    let scope = write_scope::confine(&[&stage, &dest, &receipts])?;
    ensure!(
        fs::write(root.join("forbidden-write"), b"must not exist").is_err(),
        "write confinement failed"
    );
    drop_owner()?;
    // chown may clear directory SGID. Only this disposable fixture's permanent
    // owner restores its mode; production never chmods the real public folder.
    destination
        .set_permissions(fs::Permissions::from_mode(0o3770))
        .context("fixture owner restores SGID")?;
    preflight_archive_publication(&stage, &dest)?;
    let context = b"exact144 disposable filesystem capability, no campaign admission";
    let publication = publish_verified_archive_batch_if_absent_with_context_and_lock_timeout(
        Sha256::digest(context).into(),
        &[144],
        &[ArchiveBatchItem {
            epoch: 144,
            staged_archive: copied,
            destination_archive: dest.join("epoch-144.jet"),
            evidence: measured,
        }],
        context,
        Duration::from_secs(5),
    )?;
    sink.json(&json!({"schema":"jetstreamer-exact144-publication-capability-v1","publisher_sha256":self_sha,"diagnostic_fixture":true,"mount_id":mount,"kernel_write_scope":scope,"outside_write_denied":true,"filesystem_transaction_passed":true,"root_receipt_fd_survives_permanent_privilege_drop":true,"effective_uid":unsafe{libc::geteuid()},"effective_gid":unsafe{libc::getegid()},"transaction_id":sha256_hex_string(&publication.transaction_id),"artifact_publication_authorized":false,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false}))?;
    acknowledge_archive_publication_batch(&dest, publication.transaction_id)?;
    println!("exact144 disposable filesystem capability passed; no campaign artifacts touched");
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() == 5 && a[1] == "--capability-probe" && a[3] == "--self-sha256" {
        ensure!(unsafe { libc::geteuid() } == 0, "capability requires root");
        evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[4], 256 << 20, true)?;
        return capability(Path::new(&a[2]), &a[4]);
    }
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: exact144-publish PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 256 << 20, true)?;
    let b = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan =
        serde_json::from_slice(&evidence::bound_file(&b.path, &b.sha256, 4 << 20, true)?)?;
    run(&p, &b, &a[5], check)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        json!({"schema":"jetstreamer-private144-publication-evidence-v1","epoch":144,"tool_sha256":AUDITOR,"archive_path":SOURCE,"archive_sha256":DIGEST,"archive_bytes":LENGTH,"expected_provenance_sha256":PROVENANCE,"independent_full_and_plugin_receipts_validated":true,"fresh_archive_hash_performed":false,"copy_performed":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,"archive_identity":[1,2,LENGTH,0,0o100600,1,1,0,1,0]})
    }
    #[test]
    fn scan_evidence_does_not_grant_publication_or_replace_a_copy_hash() {
        validate_evidence(&fixture()).unwrap();
        for (pointer, value) in [
            ("/epoch", json!(213)),
            ("/tool_sha256", json!(RUNNER)),
            ("/archive_path", json!(PUBLIC)),
            ("/archive_sha256", json!(PROVENANCE)),
            ("/archive_bytes", json!(1)),
            ("/expected_provenance_sha256", json!(DIGEST)),
            (
                "/independent_full_and_plugin_receipts_validated",
                json!(false),
            ),
            ("/fresh_archive_hash_performed", json!(true)),
            ("/copy_performed", json!(true)),
            ("/archive_identity/5", json!(2)),
            ("/publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut v = fixture();
            *v.pointer_mut(pointer).unwrap() = value;
            assert!(validate_evidence(&v).is_err(), "{pointer}");
        }
    }
    #[test]
    fn plan_cannot_expand_authority_or_write_namespaces() {
        let b = json!({"path":"/sealed/input.json","sha256":"a".repeat(64)});
        let fixture = json!({"schema":"jetstreamer-exact144-v4-publication-plan-v1",
            "evidence":{"path":"/var/lib/jetstreamer/horizon-epoch144-publication-evidence-test/evidence.json","sha256":"a".repeat(64)},
            "observer":b,"fleet":b,"century_floor":b,
            "work_directory":"/home/sol/.jetstreamer-private/epoch144-publication-work-test",
            "receipt_directory":"/var/lib/jetstreamer/horizon-epoch144-publication-test",
            "artifact_publication_authorized":true,"runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_plan(&serde_json::from_value(fixture.clone()).unwrap()).unwrap();
        for (pointer, value) in [
            ("/schema", json!("generic-v4")),
            ("/artifact_publication_authorized", json!(false)),
            ("/runtime_registry_promotion_authorized", json!(true)),
            ("/remote_mutations", json!(true)),
            ("/r2_mutations", json!(true)),
            ("/work_directory", json!("/home/sol")),
            ("/receipt_directory", json!(PUBLIC)),
            ("/evidence/path", json!("/tmp/evidence.json")),
        ] {
            let mut v = fixture.clone();
            *v.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_plan(&serde_json::from_value(v).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut refreshed = fixture.clone();
        refreshed["refreshed_capacity"] = json!({"schema":"jetstreamer-exact144-delivery-capacity-refresh-v1","growth_claims":[]});
        assert!(validate_plan(&serde_json::from_value(refreshed.clone()).unwrap()).is_err());
        refreshed["schema"] = json!("jetstreamer-exact144-v4-publication-plan-v2");
        validate_plan(&serde_json::from_value(refreshed).unwrap()).unwrap();
        let mut no_refresh = fixture.clone();
        no_refresh["schema"] = json!("jetstreamer-exact144-v4-publication-plan-v2");
        assert!(validate_plan(&serde_json::from_value(no_refresh).unwrap()).is_err());
        let mut v = fixture;
        v["overwrite_existing"] = json!(true);
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }
    #[test]
    fn inherited_protection_is_not_relabelled_as_the_century_floor() {
        assert!(PROTECTED > 205211459014 + 2473901162496);
        assert_eq!(PROTECTED + LENGTH + MARGIN, 4850948146290);
    }
    #[test]
    fn clock_rejects_normalized_dates_and_trailing_data() {
        assert!(utc("2026-10-22T12:28:00Z").is_ok());
        assert!(utc("2026-02-31T12:28:00Z").is_err());
        assert!(utc("2026-10-22T12:28:00Z extra").is_err());
    }
    #[test]
    fn copy_checks_guard_before_writing_and_rejects_wrong_bytes_or_size() {
        let bytes = b"private fixture";
        let expected = evidence::sha(bytes);
        let mut out = Vec::new();
        let mut guards = Vec::new();
        copy_checked(
            &mut &bytes[..],
            &mut out,
            bytes.len() as u64,
            &expected,
            |n| {
                guards.push(n);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(out, bytes);
        assert_eq!(guards, vec![bytes.len() as u64, 0]);
        let mut out = Vec::new();
        assert!(
            copy_checked(
                &mut &bytes[..],
                &mut out,
                bytes.len() as u64,
                &expected,
                |_| anyhow::bail!("guard rejected")
            )
            .is_err()
        );
        assert!(out.is_empty());
        for (size, hash) in [
            (bytes.len() as u64 - 1, expected.clone()),
            (bytes.len() as u64 + 1, expected.clone()),
            (bytes.len() as u64, DIGEST.to_owned()),
        ] {
            assert!(
                copy_checked(&mut &bytes[..], &mut Vec::new(), size, &hash, |_| Ok(())).is_err()
            );
        }
    }
}
