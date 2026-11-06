//! Fixed163 restore-only source capability. No entry-processing call exists.
#[allow(dead_code)]
mod historical;
mod native_guards;
use anyhow::{Context, Result, ensure};
use historical::{
    HistoricalInitialization, HistoricalRuntimeClient, SOLANA_V1_5_6_CANDIDATE,
    SnapshotInitialization, WorkerSpawn,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const SLOT: u64 = 70_415_741;
const GENERATION: u64 = 1_634_787_272_998_262;
const SIZE: u64 = 1_901_405_026;
const WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const HASH: &str = "2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY";
const NAME: &str = "snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst";
const EXPORT_FLOOR: u64 = 642_177_138_688;
const UNIT: &str = "horizon-epoch163-native-input-20261106-v1.service";
const MEMORY: u64 = 128 << 30;
const SCRATCH_MAXIMUM: u64 = 40 << 30;
const SCRATCH_MAXIMUM_INODES: u64 = 131072;
// Linux capability ABI; libc does not expose these capability numbers.
const SYS_ADMIN_BIT: u64 = 1 << 21;
// The canonical producer profile is epoch163_snapshot_profile.rs, not the
// earlier unbuilt private bootstrap profile. Never relabel its receipt.
const DOWNLOAD_SCHEMA: &str = "jetstreamer-epoch163-snapshot-download-receipt-v1";
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    program: Bound,
    worker: Bound,
    genesis: Bound,
    download: Bound,
    admission_program: Bound,
    admission: PathBuf,
    snapshot: PathBuf,
    ledger: PathBuf,
    scratch: PathBuf,
    protected_filesystem: PathBuf,
    state: PathBuf,
    minimum_free_bytes: u64,
    minimum_available_memory_bytes: u64,
    maximum_runtime_seconds: u64,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "SHA shape"
    );
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn bound(b: &Bound, max: u64) -> Result<Vec<u8>> {
    ensure!(
        b.path.is_absolute() && b.path.canonicalize()? == b.path,
        "canonical bound path"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&b.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o222 == 0 && m.nlink() == 1 && m.len() <= max,
        "immutable singly-linked Root source"
    );
    let mut out = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut out)?;
    let actual: [u8; 32] = Sha256::digest(&out).into();
    ensure!(
        out.len() as u64 == m.len() && actual == digest(&b.sha256)?,
        "bound SHA/length"
    );
    ensure!(
        identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(&b.path)?),
        "bound changed"
    );
    Ok(out)
}
fn json_bound(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&bound(b, 4 << 20)?)?)
}
fn admission_binding(p: &Path) -> Result<Bound> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical admitted path"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1
            && m.len() <= 4 << 20,
        "immutable Root original admission"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "admission changed"
    );
    Ok(Bound {
        path: p.into(),
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}
fn private(p: &Path) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "private Root directory"
    );
    Ok(())
}
fn write_new(p: &Path, v: &Value) -> Result<()> {
    private(p.parent().context("receipt parent")?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let mut raw = serde_json::to_vec(v)?;
    raw.push(b'\n');
    f.write_all(&raw)?;
    f.sync_all()?;
    File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn free(p: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } == 0,
        "statvfs"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail.checked_mul(s.f_frsize).context("space overflow")
}
fn available() -> Result<u64> {
    let m = fs::read_to_string("/proc/meminfo")?;
    let n = m
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("MemAvailable")?
        .split_whitespace()
        .next()
        .context("memory number")?
        .parse::<u64>()?;
    n.checked_mul(1024).context("memory overflow")
}
fn resources(p: &Plan, start: Instant) -> Result<()> {
    ensure!(
        start.elapsed().as_secs() < p.maximum_runtime_seconds,
        "original native deadline"
    );
    let cg = format!("/system.slice/{UNIT}");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{cg}"),
        "native exact cgroup"
    );
    let root = Path::new("/sys/fs/cgroup").join(cg.trim_start_matches('/'));
    ensure!(
        fs::read_to_string(root.join("memory.max"))?.trim() == MEMORY.to_string()
            && fs::read_to_string(root.join("memory.swap.max"))?.trim() == "0",
        "native hard/swap limits"
    );
    let current = fs::read_to_string(root.join("memory.current"))?
        .trim()
        .parse::<u64>()?;
    ensure!(current <= MEMORY, "native current exceeds hard maximum");
    scratch_limits(&p.scratch)?;
    native_guards::readonly(&p.snapshot)?;
    native_guards::readonly(&p.ledger)?;
    native_guards::vmas(&root, &cg)?;
    let required = remaining_memory_floor(p.minimum_available_memory_bytes, current)?;
    ensure!(
        available()? >= required,
        "native/exporter available-memory floor"
    );
    ensure!(
        free(&p.protected_filesystem)? >= p.minimum_free_bytes,
        "native protected DATA floor"
    );
    Ok(())
}
fn validate_scratch_limits(
    kind: libc::c_long,
    bytes: u64,
    inodes: u64,
    flags: libc::c_ulong,
) -> Result<()> {
    // The historical client executes its measured private worker copy here.
    let required = libc::ST_NOSUID | libc::ST_NODEV;
    ensure!(
        kind == libc::TMPFS_MAGIC
            && bytes > 0
            && bytes <= SCRATCH_MAXIMUM
            && inodes > 0
            && inodes <= SCRATCH_MAXIMUM_INODES
            && flags & required == required
            && flags & libc::ST_NOEXEC == 0
            && flags & libc::ST_RDONLY == 0,
        "native scratch requires bounded writable nodev,nosuid,exec tmpfs for measured worker copy"
    );
    Ok(())
}
fn status_field<'a>(raw: &'a str, name: &str) -> Result<&'a str> {
    let prefix = format!("{name}:");
    let values = raw
        .lines()
        .filter_map(|line| line.strip_prefix(prefix.as_str()))
        .collect::<Vec<_>>();
    ensure!(values.len() == 1, "exact own status field {name}");
    Ok(values[0].trim())
}
fn validate_no_remount_authority(capabilities: [u64; 5], no_new_privileges: &str) -> Result<()> {
    ensure!(
        capabilities.iter().all(|bits| bits & SYS_ADMIN_BIT == 0) && no_new_privileges == "1",
        "native owner must not regain scratch remount authority"
    );
    Ok(())
}
fn validate_scratch_temp_paths(
    scratch: &Path,
    directories: [Option<std::ffi::OsString>; 3],
) -> Result<()> {
    ensure!(
        directories[0].as_deref() == Some(scratch.as_os_str()),
        "TMPDIR must use bounded scratch"
    );
    for optional in &directories[1..] {
        ensure!(
            optional
                .as_deref()
                .is_none_or(|path| path == scratch.as_os_str()),
            "temporary directory alias escapes bounded scratch"
        );
    }
    Ok(())
}
fn scratch_limits(path: &Path) -> Result<()> {
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut kind = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statfs(name.as_ptr(), kind.as_mut_ptr()) } == 0
            && unsafe { libc::statvfs(name.as_ptr(), space.as_mut_ptr()) } == 0,
        "actual native scratch filesystem limits"
    );
    let kind = unsafe { kind.assume_init() };
    let space = unsafe { space.assume_init() };
    let bytes = space
        .f_blocks
        .checked_mul(space.f_frsize)
        .context("scratch capacity overflow")?;
    validate_scratch_limits(kind.f_type, bytes, space.f_files, space.f_flag)?;
    let status = fs::read_to_string("/proc/self/status")?;
    validate_no_remount_authority(
        [
            u64::from_str_radix(status_field(&status, "CapEff")?, 16)?,
            u64::from_str_radix(status_field(&status, "CapPrm")?, 16)?,
            u64::from_str_radix(status_field(&status, "CapInh")?, 16)?,
            u64::from_str_radix(status_field(&status, "CapAmb")?, 16)?,
            u64::from_str_radix(status_field(&status, "CapBnd")?, 16)?,
        ],
        status_field(&status, "NoNewPrivs")?,
    )?;
    validate_scratch_temp_paths(
        path,
        [
            env::var_os("TMPDIR"),
            env::var_os("TMP"),
            env::var_os("TEMP"),
        ],
    )
}
fn remaining_memory_floor(initial: u64, current: u64) -> Result<u64> {
    ensure!(
        initial >= EXPORT_FLOOR + MEMORY + (2u64 << 30) + (512u64 << 20) + (8u64 << 30)
            && current <= MEMORY,
        "native memory arithmetic scope"
    );
    initial
        .checked_sub(current)
        .context("remaining native memory floor underflow")
}
fn validate_download(d: &Value, p: &Plan) -> Result<String> {
    ensure!(
        d["schema"] == DOWNLOAD_SCHEMA
            && d["epoch"] == 163
            && d["generation"].as_str() == Some(GENERATION.to_string().as_str())
            && d["path"] == json!(p.snapshot)
            && d["bytes"] == SIZE
            && d["crc32c_base64"] == "bpbuVg=="
            && d["md5_base64"] == "GIvvcL0yXKjY2dumxRsJrg=="
            && d["compressed_input_verified"] == true
            && d["replay_launch_authorized"] == false
            && d["publication_authorized"] == false
            && d["r2_mutations"] == false,
        "exact original verified download required"
    );
    let sha = d["sha256"].as_str().context("download SHA")?;
    digest(sha)?;
    Ok(sha.into())
}
fn validate_admission(a: &Value, p: &Plan, pb: &Bound, iid: &str, t: u64) -> Result<()> {
    ensure!(
        a["schema"] == "epoch163-native-input-admission-v2"
            && a["admitted"] == true
            && a["issuer"] == json!(p.admission_program)
            && a["plan"] == json!(pb)
            && a["program"] == json!(p.program)
            && a["download"] == json!(p.download)
            && a["worker"] == json!(p.worker)
            && a["actor_invocation_id"] == iid
            && a["actor_pid"] == std::process::id()
            && a["native_restore_only"] == true
            && a["replay_launch_authorized"] == false
            && a["publication_authorized"] == false
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false,
        "exact invocation-bound native-only admission"
    );
    ensure!(
        a["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|n| n <= t && t - n <= 180)
            && a["actor_memory_bytes"] == 128u64 << 30
            && a["protected_existing_DATA_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 4_720_000_000_000)
            && a["candidate_incremental_DATA_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 40u64 << 30)
            && a["minimum_available_memory_bytes"] == p.minimum_available_memory_bytes
            && a["minimum_free_bytes"] == p.minimum_free_bytes
            && a["protected_filesystem"] == json!(p.protected_filesystem)
            && a["scratch_maximum_bytes"] == SCRATCH_MAXIMUM
            && a["scratch_maximum_inodes"] == SCRATCH_MAXIMUM_INODES
            && a["vma_stop"] == native_guards::VMA_STOP
            && a["mapped_worker_image_required"] == true
            && a["read_only_input_namespace_required"] == true,
        "fresh full native resource admission required"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "Root exact CLI PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let pb = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_slice(&bound(&pb, 1 << 20)?)?;
    ensure!(
        p.schema == "epoch163-native-input-plan-v3"
            && p.program.path == fs::read_link("/proc/self/exe")?
            && p.program.sha256 == args[5]
            && p.worker.sha256 == WORKER
            && p.admission == p.state.join("admission.json"),
        "native exact tool scope"
    );
    bound(&p.program, 256 << 20)?;
    bound(&p.worker, 256 << 20)?;
    bound(&p.admission_program, 256 << 20)?;
    ensure!(
        p.genesis.path == p.ledger.join("genesis.tar.bz2")
            && p.genesis.sha256
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && !p.ledger.join("genesis.bin").try_exists()?,
        "canonical genesis archive and no shadow source"
    );
    bound(&p.genesis, 10 << 20)?;
    ensure!(
        p.snapshot.file_name().and_then(|s| s.to_str()) == Some(NAME)
            && p.snapshot.is_absolute()
            && p.snapshot.canonicalize()? == p.snapshot
            && (60..=7200).contains(&p.maximum_runtime_seconds)
            && p.minimum_available_memory_bytes
                >= EXPORT_FLOOR + (128u64 << 30) + (2u64 << 30) + (512u64 << 20) + (8u64 << 30)
            && p.minimum_free_bytes >= 4_720_000_000_000u64 + SCRATCH_MAXIMUM,
        "exact source and full resource envelope"
    );
    native_guards::layout(&p.snapshot, &p.ledger, &p.scratch, &p.state)?;
    private(&p.ledger)?;
    private(p.snapshot.parent().context("immutable snapshot parent")?)?;
    native_guards::readonly(&p.snapshot)?;
    native_guards::readonly(&p.ledger)?;
    private(&p.scratch)?;
    private(&p.state)?;
    ensure!(
        p.protected_filesystem == Path::new("/home/sol")
            && p.protected_filesystem.canonicalize()? == p.protected_filesystem
            && fs::metadata(&p.protected_filesystem)?.dev() == fs::metadata(&p.ledger)?.dev()
            && fs::metadata(&p.scratch)?.dev() != fs::metadata(&p.protected_filesystem)?.dev(),
        "native host DATA identity must be separate from private scratch tmpfs"
    );
    scratch_limits(&p.scratch)?;
    ensure!(fs::read_dir(&p.scratch)?.next().is_none(), "fresh scratch");
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "systemd invocation"
    );
    // The owner waits held until the reviewed full-resource issuer publishes its
    // immutable receipt for this real PID/IID. No snapshot body opens before it.
    write_new(
        &p.state.join("ready.json"),
        &json!({"schema":"epoch163-native-input-held-v1","plan":pb,"iid":iid,"pid":std::process::id(),"snapshot_body_opened":false}),
    )?;
    let held = Instant::now();
    while !p.admission.try_exists()? {
        ensure!(
            held.elapsed().as_secs() < 120,
            "original held admission deadline"
        );
        thread::sleep(Duration::from_millis(100));
    }
    let admission = admission_binding(&p.admission)?;
    validate_admission(&json_bound(&admission)?, &p, &pb, &iid, now()?)?;
    let d = json_bound(&p.download)?;
    let sha = validate_download(&d, &p)?;
    let start = Instant::now();
    resources(&p, start)?;
    write_new(
        &p.state.join("initial-guard.json"),
        &json!({"schema":"epoch163-native-input-inprocess-first-guard-v1","plan":pb,"admission":admission,"iid":iid,"pid":std::process::id(),"sampled_unix_seconds":now()?,"available_memory_bytes":available()?,"protected_filesystem":p.protected_filesystem,"free_bytes":free(&p.protected_filesystem)?,"scratch_maximum_bytes":SCRATCH_MAXIMUM,"scratch_maximum_inodes":SCRATCH_MAXIMUM_INODES,"vma_stop":native_guards::VMA_STOP,"mapped_worker_image_required":true,"read_only_input_namespace_required":true,"trip":false,"snapshot_body_opened":false}),
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let td = done.clone();
    let state = p.state.clone();
    let raw = serde_json::from_slice::<Plan>(&bound(&pb, 1 << 20)?)?;
    let guardian = thread::spawn(move || {
        let mut heartbeat = Instant::now();
        while !td.load(Ordering::Acquire) {
            if let Err(e) = resources(&raw, start) {
                let _ = write_new(
                    &state.join("guard-trip.json"),
                    &json!({"reason":format!("{e:#}"),"pid":std::process::id()}),
                );
                eprintln!("epoch163 native guard failed: {e:#}");
                std::process::exit(1);
            }
            if heartbeat.elapsed() >= Duration::from_secs(60) {
                eprintln!(
                    "epoch163 native restore heartbeat; elapsed={} original_deadline_remaining={}; heartbeat is not input success",
                    start.elapsed().as_secs(),
                    raw.maximum_runtime_seconds
                        .saturating_sub(start.elapsed().as_secs())
                );
                heartbeat = Instant::now();
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
    let result = (|| -> Result<Value> {
        eprintln!(
            "epoch163 native snapshot verification and v1.5.6 bootstrap start; no replay entries"
        );
        let expected = solana_hash::Hash::from_str(HASH)?.to_bytes();
        let mut client = HistoricalRuntimeClient::spawn(
            SOLANA_V1_5_6_CANDIDATE,
            WorkerSpawn {
                executable: p.worker.path.clone(),
                initialization: HistoricalInitialization::SnapshotArchive(SnapshotInitialization {
                    ledger_path: p.ledger.clone(),
                    archive_path: p.snapshot.clone(),
                    expected_slot: SLOT,
                    expected_accounts_hash: expected,
                    expected_archive_sha256: Some(digest(&sha)?),
                    expected_archive_size: Some(SIZE),
                    scratch_parent: Some(p.scratch.clone()),
                }),
            },
        )?;
        ensure!(
            client.executable_sha256() == digest(WORKER)? && client.initialized().slot == SLOT,
            "actual mapped worker/bootstrap differs"
        );
        let worker_pid = client
            .worker_pid()
            .context("actual initialized worker PID")?;
        let cg = format!("/system.slice/{UNIT}");
        let worker_start_ticks = native_guards::mapped_worker(worker_pid, &p.scratch, WORKER, &cg)?;
        let checkpoint = client.freeze_checkpoint(SLOT)?;
        ensure!(
            checkpoint.slot == SLOT
                && checkpoint.accounts_hash == expected
                && checkpoint.slot_complete
                && checkpoint.writes.is_empty(),
            "native checkpoint identity or bootstrap writes"
        );
        ensure!(
            client.worker_pid() == Some(worker_pid),
            "original worker PID changed"
        );
        ensure!(
            native_guards::mapped_worker(worker_pid, &p.scratch, WORKER, &cg)?
                == worker_start_ticks,
            "mapped original worker changed before Shutdown"
        );
        ensure!(worker_start_ticks > 0, "original worker start ticks absent");
        client.shutdown()?;
        resources(&p, start)?;
        Ok(
            json!({"schema":"epoch163-native-input-outcome-v3","bootstrap_generation":GENERATION,"bootstrap_slot":SLOT,"snapshot_integrity_verified":true,"mapped_worker_image_verified":true,"vma_guards_enforced":true,"source_mounts_read_only":true,"mapped_worker_sha256":WORKER,"worker_shutdown_acknowledged":true,"worker_shutdown_and_reap_passed":false,"worker_pid":worker_pid,"worker_start_ticks":worker_start_ticks,"replay_entries_sent":0,"native_bank_hash":solana_hash::Hash::new_from_array(checkpoint.bank_hash).to_string(),"native_accounts_hash":HASH,"plan":pb,"admission":admission,"download":p.download,"source_sha256":sha,"actor_invocation_id":iid,"original_capability_actor_drained":false,"publication_authorized":false,"r2_mutations":false}),
        )
    })();
    done.store(true, Ordering::Release);
    guardian
        .join()
        .map_err(|_| anyhow::anyhow!("guardian panic"))?;
    match result {
        Ok(v) => write_new(&p.state.join("outcome.json"), &v)?,
        Err(e) => {
            write_new(
                &p.state.join("failure.json"),
                &json!({"error":format!("{e:#}"),"iid":iid,"publication_authorized":false,"r2_mutations":false}),
            )?;
            return Err(e);
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch163 input capability failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Root no-SYS_ADMIN/NoNewPrivs sandbox with explicitly mounted fresh <=2MiB tmpfs; writes only its newly created disposable probe"]
    fn root_actual_scratch_tmpfs_allocation_stops_at_kernel_limit() {
        ensure_root_scratch_probe().unwrap();
    }
    fn ensure_root_scratch_probe() -> Result<()> {
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "Root scratch probe identity"
        );
        let root = PathBuf::from(env::var("JETSTREAMER_NATIVE163_TMPFS_PROBE_ROOT")?);
        private(&root)?;
        scratch_limits(&root)?;
        ensure!(
            fs::read_dir(&root)?.next().is_none(),
            "fresh disposable scratch probe root"
        );
        let name = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        ensure!(
            unsafe { libc::statvfs(name.as_ptr(), space.as_mut_ptr()) } == 0,
            "probe statvfs"
        );
        let space = unsafe { space.assume_init() };
        let capacity = space
            .f_blocks
            .checked_mul(space.f_frsize)
            .context("probe capacity overflow")?;
        ensure!(
            capacity > 0 && capacity <= 2 << 20,
            "disposable probe limited to2MiB"
        );
        let output = root.join("owned-capacity-probe");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output)?;
        let block = [0u8; 65536];
        let mut exhausted = false;
        for _ in 0..35 {
            match file.write_all(&block) {
                Ok(()) => {}
                Err(error) => {
                    ensure!(
                        error.raw_os_error() == Some(libc::ENOSPC),
                        "unexpected capacity failure: {error}"
                    );
                    exhausted = true;
                    break;
                }
            }
        }
        ensure!(
            exhausted && file.metadata()?.len() <= capacity,
            "kernel tmpfs byte ceiling not enforced"
        );
        file.sync_all()?;
        let length = file.metadata()?.len();
        drop(file);
        fs::remove_file(&output)?;
        File::open(&root)?.sync_all()?;
        ensure!(
            fs::read_dir(&root)?.next().is_none(),
            "owned probe cleanup only"
        );
        println!(
            "{}",
            json!({"schema":"epoch163-native-scratch-kernel-limit-control-v1","actual_capacity_bytes":capacity,"actual_probe_length":length,"kernel_ENOSPC_observed":true,"probe_removed":true,"native_worker_started":false,"input_capability_claimed":false})
        );
        Ok(())
    }
    fn b() -> Bound {
        Bound {
            path: "/sealed/member".into(),
            sha256: "a".repeat(64),
        }
    }
    fn plan() -> Plan {
        Plan {
            schema: "epoch163-native-input-plan-v3".into(),
            program: b(),
            worker: b(),
            genesis: b(),
            download: b(),
            admission_program: b(),
            admission: "/private/admission.json".into(),
            snapshot: Path::new("/private").join(NAME),
            ledger: "/private".into(),
            scratch: "/private/scratch".into(),
            protected_filesystem: "/home/sol".into(),
            state: "/private/state".into(),
            minimum_free_bytes: 4_720_000_000_000 + SCRATCH_MAXIMUM,
            minimum_available_memory_bytes: 790_890_381_312,
            maximum_runtime_seconds: 7200,
        }
    }
    fn download(p: &Plan) -> Value {
        json!({"schema":DOWNLOAD_SCHEMA,"epoch":163,"generation":GENERATION.to_string(),"path":p.snapshot,"bytes":SIZE,"crc32c_base64":"bpbuVg==","md5_base64":"GIvvcL0yXKjY2dumxRsJrg==","sha256":"a".repeat(64),"compressed_input_verified":true,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false})
    }
    #[test]
    fn only_exact_bootstrap_generation_digest_and_authority_are_accepted() {
        let p = plan();
        let good = download(&p);
        validate_download(&good, &p).unwrap();
        for (k, v) in [
            ("schema", json!("another")),
            ("schema", json!("epoch163-bootstrap-download-v1")),
            ("epoch", json!(162)),
            ("generation", json!("1634787272998263")),
            ("bytes", json!(SIZE + 1)),
            ("crc32c_base64", json!("wrong")),
            ("md5_base64", json!("wrong")),
            ("sha256", json!("0")),
            ("compressed_input_verified", json!(false)),
            ("publication_authorized", json!(true)),
            ("replay_launch_authorized", json!(true)),
            ("r2_mutations", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[k] = v;
            assert!(validate_download(&bad, &p).is_err(), "{k}");
        }
    }
    #[test]
    fn scratch_cannot_use_host_disk_or_exceed_kernel_allocation_limits() {
        let flags = libc::ST_NODEV | libc::ST_NOSUID;
        validate_scratch_limits(
            libc::TMPFS_MAGIC,
            SCRATCH_MAXIMUM,
            SCRATCH_MAXIMUM_INODES,
            flags,
        )
        .unwrap();
        validate_scratch_limits(libc::TMPFS_MAGIC, 2 << 20, 1024, flags).unwrap();
        for (kind, bytes, inodes, mode) in [
            (0, SCRATCH_MAXIMUM, SCRATCH_MAXIMUM_INODES, flags),
            (libc::TMPFS_MAGIC, 0, SCRATCH_MAXIMUM_INODES, flags),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM + 4096,
                SCRATCH_MAXIMUM_INODES,
                flags,
            ),
            (libc::TMPFS_MAGIC, SCRATCH_MAXIMUM, 0, flags),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM,
                SCRATCH_MAXIMUM_INODES + 1,
                flags,
            ),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM,
                SCRATCH_MAXIMUM_INODES,
                flags & !libc::ST_NODEV,
            ),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM,
                SCRATCH_MAXIMUM_INODES,
                flags & !libc::ST_NOSUID,
            ),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM,
                SCRATCH_MAXIMUM_INODES,
                flags | libc::ST_NOEXEC,
            ),
            (
                libc::TMPFS_MAGIC,
                SCRATCH_MAXIMUM,
                SCRATCH_MAXIMUM_INODES,
                flags | libc::ST_RDONLY,
            ),
        ] {
            assert!(validate_scratch_limits(kind, bytes, inodes, mode).is_err());
        }
    }
    #[test]
    fn native_scratch_limit_cannot_be_removed_by_actor_remount() {
        let admin = SYS_ADMIN_BIT;
        validate_no_remount_authority([0; 5], "1").unwrap();
        for index in 0..5 {
            let mut caps = [0; 5];
            caps[index] = admin;
            assert!(validate_no_remount_authority(caps, "1").is_err());
        }
        assert!(validate_no_remount_authority([0; 5], "0").is_err());
        assert_eq!(status_field("CapEff:\t0\n", "CapEff").unwrap(), "0");
        assert!(status_field("CapEff:\t0\nCapEff:\t0\n", "CapEff").is_err());
        assert!(status_field("", "CapEff").is_err());
    }
    #[test]
    fn all_temporary_directory_aliases_stay_inside_bounded_scratch() {
        let scratch = Path::new("/bounded/scratch");
        let own = || Some(scratch.as_os_str().to_os_string());
        validate_scratch_temp_paths(scratch, [own(), None, None]).unwrap();
        validate_scratch_temp_paths(scratch, [own(), own(), own()]).unwrap();
        assert!(validate_scratch_temp_paths(scratch, [None, None, None]).is_err());
        for index in 0..3 {
            let mut aliases = [own(), own(), own()];
            aliases[index] = Some("/tmp".into());
            assert!(validate_scratch_temp_paths(scratch, aliases).is_err());
        }
    }
    #[test]
    fn fresh_native_admission_binds_host_floor_and_scratch_mount_envelope() {
        let p = plan();
        let pb = b();
        let iid = "c".repeat(32);
        let good = json!({"schema":"epoch163-native-input-admission-v2","admitted":true,
            "issuer":p.admission_program,"plan":pb,"program":p.program,"download":p.download,"worker":p.worker,
            "actor_invocation_id":iid,"actor_pid":std::process::id(),"native_restore_only":true,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "recorded_unix_seconds":9900,"actor_memory_bytes":128u64<<30,"protected_existing_DATA_bytes":4720000000000u64,
            "candidate_incremental_DATA_bytes":SCRATCH_MAXIMUM,"minimum_available_memory_bytes":p.minimum_available_memory_bytes,
            "minimum_free_bytes":p.minimum_free_bytes,"protected_filesystem":p.protected_filesystem,
            "scratch_maximum_bytes":SCRATCH_MAXIMUM,"scratch_maximum_inodes":SCRATCH_MAXIMUM_INODES,"vma_stop":native_guards::VMA_STOP,"mapped_worker_image_required":true,"read_only_input_namespace_required":true});
        validate_admission(&good, &p, &pb, &iid, 10000).unwrap();
        for (key, changed) in [
            ("protected_filesystem", json!("/tmp")),
            ("scratch_maximum_bytes", json!(SCRATCH_MAXIMUM + 1)),
            ("scratch_maximum_inodes", json!(SCRATCH_MAXIMUM_INODES + 1)),
            ("vma_stop", json!(0)),
            ("mapped_worker_image_required", json!(false)),
            ("read_only_input_namespace_required", json!(false)),
            ("protected_existing_DATA_bytes", json!(4719999999999u64)),
            ("actor_invocation_id", json!("d".repeat(32))),
            ("actor_pid", json!(0)),
            ("actor_memory_bytes", json!(0)),
            (
                "candidate_incremental_DATA_bytes",
                json!(SCRATCH_MAXIMUM - 1),
            ),
            ("recorded_unix_seconds", json!(10001)),
            ("recorded_unix_seconds", json!(9819)),
            ("minimum_available_memory_bytes", json!(0)),
            ("minimum_free_bytes", json!(0)),
            ("remote_mutations", json!(true)),
            ("replay_launch_authorized", json!(true)),
        ] {
            let mut bad = good.clone();
            bad[key] = changed;
            assert!(
                validate_admission(&bad, &p, &pb, &iid, 10000).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn runtime_memory_releases_only_actual_exact_cgroup_usage_and_keeps_exporter() {
        let initial = 790_890_381_312;
        assert_eq!(remaining_memory_floor(initial, 0).unwrap(), initial);
        assert_eq!(
            remaining_memory_floor(initial, MEMORY).unwrap(),
            EXPORT_FLOOR + (2u64 << 30) + (512u64 << 20) + (8u64 << 30)
        );
        assert!(remaining_memory_floor(initial, MEMORY + 1).is_err());
        assert!(remaining_memory_floor(initial - 1, 0).is_err());
    }
    #[test]
    fn typed_plan_rejects_replay_and_unknown_fields() {
        let mut p = serde_json::to_value(
            json!({"schema":"epoch163-native-input-plan-v1","allow_replay":true}),
        )
        .unwrap();
        assert!(serde_json::from_value::<Plan>(p.clone()).is_err());
        p["r2_mutations"] = json!(true);
        assert!(serde_json::from_value::<Plan>(p).is_err());
    }
    #[test]
    fn digest_shape_is_lowercase_exact_and_not_shell_text() {
        for s in [
            "".into(),
            "0".repeat(63),
            "A".repeat(64),
            "`id`".into(),
            "g".repeat(64),
        ] {
            assert!(digest(&s).is_err());
        }
        assert_eq!(digest(&"00".repeat(32)).unwrap(), [0; 32]);
    }
}
