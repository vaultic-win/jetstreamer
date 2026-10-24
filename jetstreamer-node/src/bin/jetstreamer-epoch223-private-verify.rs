//! Independent bounded private V3 full/current-plugin verification for epoch 223.
//! Copies actual assembled bytes once; preserves every original and grants no import.
#![recursion_limit = "256"]
#[allow(dead_code)]
#[path = "epoch223_assembly/capacity.rs"]
mod capacity;
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
use handoff::Bound;
use jetstreamer_horizon::archive::{ArchiveProvenance, ArchiveReader, encode_archive_provenance};
use jetstreamer_horizon_observe::source_idle223;
use jetstreamer_node::archive_checksum::open_regular_nofollow;
use qualified::{Identity, identity};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const LIMIT: u64 = 160 << 30;
const MAX_SECONDS: u64 = 86400;
const LOG_LIMIT: u64 = 64 << 20;
const MARKER: &str =
    "private epoch 223 V3 verification complete; import/publication gates remain closed";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    inputs: qualified::Inputs,
    capacity: Bound,
    capacity_tool_sha256: String,
    full_verifier: Bound,
    plugin: Bound,
    private_directory: PathBuf,
}
fn seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn absent(p: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(p),Err(e)if e.kind()==std::io::ErrorKind::NotFound),
        "private verifier output/sidecar already exists: {}",
        p.display()
    );
    Ok(())
}
fn free(p: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?;
    let mut s = unsafe { std::mem::zeroed::<libc::statvfs>() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0,
        "private verifier statvfs failed"
    );
    s.f_bavail
        .checked_mul(s.f_frsize)
        .context("private verifier disk overflow")
}
fn memory() -> Result<u64> {
    fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .context("private verifier available memory")?
        .checked_mul(1024)
        .context("private verifier memory overflow")
}
fn properties() -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",qualified::VERIFY_UNIT,"--no-pager",
    "--property=Id,InvocationID,MainPID,NRestarts,Restart,ActiveState,SubState,Type,RuntimeMaxUSec,MemoryMax,MemoryHigh,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,User,Group,UMask,PrivateNetwork,ProtectHome,ProtectSystem,ReadWritePaths,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,KillMode,Delegate,ControlGroup"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 32768,
        "private verifier owner unavailable"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("private verifier property shape")?;
        ensure!(
            fields.insert(k.into(), json!(v)).is_none(),
            "duplicate private verifier property"
        );
    }
    Ok(Value::Object(fields))
}
fn owner(p: &Value, iid: &str, directory: &Path) -> Result<()> {
    ensure!(
        qualified::iid(iid)
            && p["Id"] == qualified::VERIFY_UNIT
            && p["InvocationID"] == iid
            && p["MainPID"].as_str().and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id()),
        "private verifier is not its actual persistent owner"
    );
    ensure!(
        p["ControlGroup"] == format!("/system.slice/{}", qualified::VERIFY_UNIT),
        "private verifier control group differs"
    );
    for (k, v) in [
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("Type", "exec"),
        ("RuntimeMaxUSec", "1d"),
        ("MemoryMax", "68719476736"),
        ("MemoryHigh", "51539607552"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
        ("User", "root"),
        ("Group", "root"),
        ("UMask", "0077"),
        ("PrivateNetwork", "yes"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("NoNewPrivileges", "yes"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(p[k] == v, "private verifier sandbox differs:{k}");
    }
    ensure!(
        p["ReadWritePaths"].as_str() == directory.to_str(),
        "private verifier writable scope differs"
    );
    for k in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            p[k].as_str().map(|s| s
                .split_whitespace()
                .collect::<std::collections::BTreeSet<_>>())
                == Some(std::collections::BTreeSet::from([
                    "cap_dac_override",
                    "cap_sys_ptrace"
                ])),
            "private verifier capability set differs"
        );
    }
    Ok(())
}
fn write(path: &Path, value: &Value, floor: u64) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    ensure!(
        bytes.len() < 1 << 20
            && free(path.parent().unwrap())?
                >= floor
                    .checked_add(bytes.len() as u64 + 1)
                    .context("metadata floor overflow")?,
        "private verification metadata exceeds reserved space"
    );
    let mut t = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    t.write_all(&bytes)?;
    t.write_all(b"\n")?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("private verification metadata occupied: {e}"))?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn unchanged(file: &File, path: &Path, id: &Identity) -> Result<()> {
    ensure!(
        identity(&file.metadata()?) == *id
            && identity(&fs::symlink_metadata(path)?) == *id
            && path.canonicalize()? == path,
        "private verification bytes/identity changed"
    );
    Ok(())
}
fn header(file: &File, expected: &str) -> Result<()> {
    let r = ArchiveReader::open(BufReader::new(file.try_clone()?))
        .map_err(|e| anyhow::anyhow!("private V3 reader: {e}"))?;
    ensure!(
        r.header().epoch == 223
            && r.header().slot_start == 96336000
            && r.header().slot_count == 432000,
        "private V3 archive is not the complete exact epoch"
    );
    let p = r.provenance()?.context("private V3 provenance absent")?;
    ensure!(
        matches!(p, ArchiveProvenance::V3(_)),
        "mixed native 20/native 25 output must remain V3"
    );
    ensure!(
        evidence::sha(&encode_archive_provenance(&p)?) == expected,
        "private output differs from independent source-derived provenance"
    );
    Ok(())
}
fn kill(pidfd: &OwnedFd) {
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        );
    }
}
struct Log {
    file: File,
    bytes: u64,
    directory: PathBuf,
    floor: u64,
}
fn drain<R: Read + AsRawFd>(
    mut pipe: R,
    log: &Mutex<Log>,
    failed: &AtomicBool,
    pidfd: &OwnedFd,
    deadline: Instant,
) -> Result<()> {
    let fd = pipe.as_raw_fd();
    let result = (|| -> Result<()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        ensure!(
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
            "private scan pipe flags unavailable"
        );

        let mut buf = [0u8; 65536];
        loop {
            if failed.load(Ordering::Acquire) {
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "private scan execution bound reached"
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN | libc::POLLHUP,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut poll, 1, 1000) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e.into());
            }
            if n == 0 {
                continue;
            }
            match pipe.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut l = log
                        .lock()
                        .map_err(|_| anyhow::anyhow!("private scan log poisoned"))?;
                    ensure!(
                        l.bytes
                            .checked_add(n as u64)
                            .is_some_and(|b| b <= LOG_LIMIT)
                            && free(&l.directory)?
                                >= l.floor
                                    .checked_add((1 << 20) + n as u64)
                                    .context("log floor overflow")?,
                        "private scan log/disk envelope crossed"
                    );
                    l.file.write_all(&buf[..n])?;
                    l.bytes += n as u64;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::Interrupted =>
                {
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    })();
    if result.is_err() {
        failed.store(true, Ordering::Release);
        kill(pidfd);
    }
    result
}
fn scan(
    binary: &Bound,
    arguments: &[String],
    path: &Path,
    floor: u64,
    started: Instant,
) -> Result<Value> {
    evidence::bound_file(&binary.path, &binary.sha256, 128 << 20, true)?;
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let log = Mutex::new(Log {
        file: f,
        bytes: 0,
        directory: path.parent().unwrap().into(),
        floor,
    });
    let failed = AtomicBool::new(false);
    let mut child = Command::new(&binary.path)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        let _ = child.kill();
        let _ = child.wait();
        return Err(error.into());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let stdout = child.stdout.take().context("private scan stdout")?;
    let stderr = child.stderr.take().context("private scan stderr")?;
    let Some(allowance) = MAX_SECONDS
        .checked_sub(started.elapsed().as_secs())
        .filter(|n| *n > 0)
    else {
        kill(&pidfd);
        let _ = child.wait();
        anyhow::bail!("private scan total execution bound reached");
    };
    let deadline = Instant::now() + Duration::from_secs(allowance);
    let scan_started = Instant::now();
    let result = std::thread::scope(|scope| -> Result<_> {
        let out = scope.spawn(|| drain(stdout, &log, &failed, &pidfd, deadline));
        let err = scope.spawn(|| drain(stderr, &log, &failed, &pidfd, deadline));
        let status = child.wait()?;
        let a = out
            .join()
            .map_err(|_| anyhow::anyhow!("stdout drainer panicked"))?;
        let b = err
            .join()
            .map_err(|_| anyhow::anyhow!("stderr drainer panicked"))?;
        a?;
        b?;
        ensure!(
            status.success() && !failed.load(Ordering::Acquire),
            "private scan failed; retain its log"
        );
        Ok(status)
    });
    let l = log
        .into_inner()
        .map_err(|_| anyhow::anyhow!("private scan log poisoned"))?;
    l.file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    result?;
    drop(l);
    fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    File::open(path)?.sync_all()?;
    evidence::bound_file(&binary.path, &binary.sha256, 128 << 20, true)?;
    let f = open_regular_nofollow(path)?;
    let id = identity(&f.metadata()?);
    let measured = jetstreamer_node::archive_checksum::measure_open_archive(&f)?;
    unchanged(&f, path, &id)?;
    Ok(
        json!({"binary":binary,"arguments":arguments,"exit_code":0,"elapsed_millis":u64::try_from(scan_started.elapsed().as_millis())?,
        "log":{"path":path,"sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&measured.sha256),"identity":id},"log_limit_bytes":LOG_LIMIT}),
    )
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch223-v3-verification-plan-v1"
            && p.full_verifier.sha256 == qualified::FULL
            && p.plugin.sha256 == qualified::PLUGIN
            && evidence::is_sha(&p.capacity_tool_sha256)
            && p.private_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.private_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-private-v3-scan-")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "private V3 verification plan/scope differs"
    );
    Ok(())
}
fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private V3 verification requires root"
    );
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &args[2], 128 << 20, true)?;
    let plan_binding = Bound {
        path: args[0].clone().into(),
        sha256: args[1].clone(),
    };
    let p: Plan = serde_json::from_value(qualified::read(&plan_binding, true)?)?;
    scope(&p)?;
    let iid = env::var("INVOCATION_ID").context("private verifier requires persistent owner")?;
    let own = properties()?;
    owner(&own, &iid, &p.private_directory)?;
    let dir = fs::symlink_metadata(&p.private_directory)?;
    ensure!(
        p.private_directory.canonicalize()? == p.private_directory
            && dir.is_dir()
            && dir.uid() == 0
            && dir.mode() & 0o777 == 0o700
            && fs::read_dir(&p.private_directory)?.next().is_none(),
        "private verifier needs a fresh canonical root-private attempt directory"
    );
    let prepared = qualified::prepare(&p.inputs)?;
    let admitted = qualified::read(&p.capacity, true)?;
    let (floor, required_memory) = capacity::validate(
        &admitted,
        &p.capacity_tool_sha256,
        seconds()?,
        capacity::Kind::Verification,
    )?;
    for k in ["observer", "fleet"] {
        let b: Bound = serde_json::from_value(admitted[k].clone())?;
        qualified::read(&b, true)?;
    }
    let invocation = prepared.assembly["invocation_id"].as_str().unwrap();
    let idle = source_idle223::observe_assembly(invocation)?;
    let source = open_regular_nofollow(Path::new(qualified::SOURCE))?;
    let source_id = identity(&source.metadata()?);
    ensure!(
        source_id.uid == 0
            && source_id.links == 1
            && source_id.mode & 0o777 == 0o600
            && source_id.len > 0
            && source_id.len <= LIMIT
            && prepared.assembly["archive_bytes"] == source_id.len
            && source_id.dev == dir.dev(),
        "private assembled source identity/filesystem differs"
    );
    absent(Path::new(&format!("{}.sha256", qualified::SOURCE)))?;
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(qualified::VERIFY_UNIT);
    ensure!(
        cg.canonicalize()? == cg,
        "private verifier cgroup redirected"
    );
    let cap: u64 = fs::read_to_string(cg.join("memory.max"))?.trim().parse()?;
    let charged: u64 = fs::read_to_string(cg.join("memory.current"))?
        .trim()
        .parse()?;
    ensure!(
        cap == 64u64 << 30
            && charged <= cap
            && memory()?
                .checked_add(charged)
                .is_some_and(|n| n >= required_memory)
            && free(&p.private_directory)?
                >= floor
                    .checked_add(LIMIT + (256 << 20))
                    .context("private verification disk envelope overflow")?,
        "private verification current memory/disk envelope does not fit"
    );
    capacity::validate(
        &admitted,
        &p.capacity_tool_sha256,
        seconds()?,
        capacity::Kind::Verification,
    )?;
    ensure!(
        properties()? == own,
        "private verifier owner changed before intent"
    );
    write(
        &p.private_directory.join("intent.json"),
        &json!({"schema":"jetstreamer-private223-v3-verification-intent-v1","unit":qualified::VERIFY_UNIT,
        "invocation_id":iid,"self_sha256":args[2],"plan":plan_binding,"inputs":p.inputs,"capacity":p.capacity,"owner_at_start":own,
        "assembly_source_idle":idle,"source_identity":source_id,"private_directory":p.private_directory,"required_guard_minimum_free_bytes":floor,
        "maximum_archive_bytes":LIMIT,"maximum_log_bytes_each":LOG_LIMIT,"maximum_runtime_seconds":MAX_SECONDS,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
        floor,
    )?;
    let expectation = p.private_directory.join("expectation.json");
    write(
        &expectation,
        &json!({"schema":"jetstreamer-private-epoch223-provenance-expectation-v1",
        "expected_provenance_sha256":prepared.provenance_sha256,"expected_provenance_encoded_bytes":prepared.provenance.len(),"source_manifest_scope_validated":true,
        "handoff_request":p.inputs.handoff_request,"handoff_receipt":p.inputs.handoff_receipt,"provenance_derived_without_target_bytes":true,"assembled_target_bytes_used_for_provenance":false,"runtime_promotion_authorized":false,"publication_authorized":false}),
        floor,
    )?;
    let expectation_bytes = fs::read(&expectation)?;
    let expectation_binding =
        json!({"path":expectation,"sha256":evidence::sha(&expectation_bytes)});
    let archive = p.private_directory.join("epoch-223.jet");
    absent(&archive.with_extension("jet.sha256"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?;
    let started = Instant::now();
    let mut copied = 0u64;
    let mut hash = Sha256::new();
    let mut input = &source;
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ensure!(
            copied
                .checked_add(n as u64)
                .is_some_and(|b| b <= source_id.len)
                && started.elapsed().as_secs() < MAX_SECONDS
                && free(&p.private_directory)?
                    >= floor
                        .checked_add((1 << 20) + n as u64)
                        .context("private copy floor overflow")?,
            "private copy archive/runtime/floor bound crossed"
        );
        output.write_all(&buf[..n])?;
        hash.update(&buf[..n]);
        copied += n as u64;
    }
    output.sync_all()?;
    drop(output);
    File::open(&p.private_directory)?.sync_all()?;
    let digest = format!("{:x}", hash.finalize());
    ensure!(
        copied == source_id.len && prepared.assembly["archive_sha256"] == digest,
        "private copy hash/length differs from actual assembly"
    );
    unchanged(&source, Path::new(qualified::SOURCE), &source_id)?;
    let stage = open_regular_nofollow(&archive)?;
    let stage_id = identity(&stage.metadata()?);
    header(&stage, &prepared.provenance_sha256)?;
    let copy_millis = u64::try_from(started.elapsed().as_millis())?;
    let full = scan(
        &p.full_verifier,
        &qualified::full_args(&archive, &prepared),
        &p.private_directory.join("full.log"),
        floor,
        started,
    )?;
    unchanged(&stage, &archive, &stage_id)?;
    unchanged(&source, Path::new(qualified::SOURCE), &source_id)?;
    let plugin = scan(
        &p.plugin,
        &qualified::plugin_args(&p.private_directory),
        &p.private_directory.join("plugin.log"),
        floor,
        started,
    )?;
    unchanged(&stage, &archive, &stage_id)?;
    unchanged(&source, Path::new(qualified::SOURCE), &source_id)?;
    header(&stage, &prepared.provenance_sha256)?;
    let after = qualified::prepare(&p.inputs)?;
    ensure!(
        after.provenance == prepared.provenance
            && after.assembly == prepared.assembly
            && properties()? == own,
        "private verification inputs or bounded owner changed"
    );
    let idle_after = source_idle223::observe_assembly(invocation)?;
    write(
        &p.private_directory.join("verification.json"),
        &json!({"schema":"jetstreamer-private-epoch223-verification-v1","epoch":223,"unit":qualified::VERIFY_UNIT,
        "invocation_id":iid,"owner_at_start":own,"plan":plan_binding,"runner_sha256":args[2],"inputs":p.inputs,"capacity":p.capacity,
        "producer_outcome":p.inputs.assembly_receipt,"producer_terminal":prepared.terminal_history,"provenance_expectation":expectation_binding,
        "boundary_metadata":p.inputs.boundary_metadata,"expected_provenance_sha256":prepared.provenance_sha256,
        "source_path":qualified::SOURCE,"source_identity":source_id,"archive_path":archive,"archive_sha256":digest,"archive_bytes":copied,
        "archive_identity":stage_id,"copy_and_hash_millis":copy_millis,"full":full,"plugin":plugin,"assembly_source_idle_after":idle_after,
        "independent_final_archive_verification_passed":true,"current_plugin_verification_passed":true,
        "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}),
        floor,
    )?;
    ensure!(
        free(&p.private_directory)? >= floor,
        "private verification metadata consumed protected disk floor"
    );
    println!("{MARKER}");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("private epoch 223 verification refused: {e:#}");
        std::process::exit(1)
    }
}
