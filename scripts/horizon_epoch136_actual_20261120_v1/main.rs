//! Root supervisor for one fixed restore/reproduction. No import/publication.
#[path = "contract.rs"]
mod contract;
use anyhow::{Context, Result, ensure};
use contract::scope;
use contract::{Admission, Bound, Plan, admission_shape, digest, plan_shape, scope::*};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicI32, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "socket.rs"]
mod fixed_socket;
#[path = "handoff.rs"]
mod lifecycle_gate;
#[path = "meter.rs"]
mod physical_meter;
#[path = "root_meter.rs"]
mod root_budget;
static SIGNAL: AtomicI32 = AtomicI32::new(0);
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn absent(p: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "136 path occupied or unreadable: {}",
        p.display()
    );
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    nanos: i64,
    ctime: i64,
    cnanos: i64,
}
fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        mtime: m.mtime(),
        nanos: m.mtime_nsec(),
        ctime: m.ctime(),
        cnanos: m.ctime_nsec(),
    }
}
fn immutable(path: &Path, maximum: u64) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical immutable path"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "mutable/unsafe immutable file"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(
        identity(&before) == identity(&f.metadata()?),
        "file changed at open"
    );
    Ok(f)
}
fn hash_file(f: &mut File, maximum: u64) -> Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0; 128 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .context("hash length overflow")?;
        ensure!(count <= maximum, "hash byte limit");
        h.update(&buffer[..n]);
    }
    Ok((hex(&h.finalize()), count))
}
fn bound(b: &Bound, maximum: u64) -> Result<()> {
    ensure!(digest(&b.sha256, 64), "digest syntax");
    let mut f = immutable(&b.path, maximum)?;
    let before = identity(&f.metadata()?);
    ensure!(
        hash_file(&mut f, maximum)?.0 == b.sha256
            && identity(&f.metadata()?) == before
            && identity(&fs::symlink_metadata(&b.path)?) == before,
        "bound SHA/identity differs"
    );
    Ok(())
}
fn value(b: &Bound) -> Result<Value> {
    bound(b, 16 << 20)?;
    Ok(serde_json::from_slice(&fs::read(&b.path)?)?)
}
fn fixed(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let dir = path.parent().context("receipt parent")?;
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        dir.canonicalize()? == dir && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "unsafe receipt parent"
    );
    let mut t = tempfile::NamedTempFile::new_in(dir)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(t.as_file_mut(), v)?;
    t.write_all(b"\n")?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt exists: {e}"))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}
fn directory(path: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0,
        "directory ownership"
    );
    Ok(())
}
fn copy(source: &Path, destination: &Path, sha: &str, size: u64) -> Result<()> {
    let mut input = immutable(source, size)?;
    let initial = identity(&input.metadata()?);
    ensure!(initial.len == size, "copy source size");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)?;
    let mut h = Sha256::new();
    let mut buffer = [0; 128 * 1024];
    let mut count = 0u64;
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("copy overflow")?;
        ensure!(count <= size, "copy grew");
        output.write_all(&buffer[..n])?;
        h.update(&buffer[..n]);
    }
    ensure!(
        count == size
            && hex(&h.finalize()) == sha
            && identity(&input.metadata()?) == initial
            && identity(&fs::symlink_metadata(source)?) == initial,
        "copy source changed or SHA differs"
    );
    output.sync_all()?;
    output.set_permissions(fs::Permissions::from_mode(0o444))?;
    // Reopen and rehash the newly retained copy, not only the source stream.
    bound(
        &Bound {
            path: destination.into(),
            sha256: sha.into(),
        },
        size,
    )?;
    Ok(())
}
fn provenance() -> Result<()> {
    let d = value(&fixed(DOWNLOAD, DOWNLOAD_SHA))?;
    let t = value(&fixed(TERMINAL, TERMINAL_SHA))?;
    ensure!(
        d["schema"] == "jetstreamer-epoch136-hourly-snapshot-download-receipt-v1"
            && d["sha256"] == SNAPSHOT_SHA
            && d["bytes"] == SNAPSHOT_BYTES
            && d["path"] == SOURCE
            && d["generation"] == "1634786441363281"
            && d["invocation_id"] == INPUT_IID
            && d["compressed_input_verified"] == true
            && t["schema"] == "jetstreamer-epoch136-hourly-input-terminal-v1"
            && t["input_completed"] == true
            && t["invocation_id"] == INPUT_IID
            && t["allocation"]["state"] == "completed-retained-input"
            && t["allocation"]["data_reservation_bytes"] == 3_308_702_239u64
            && t["allocation"]["memory_max_bytes"] == 0,
        "hourly compressed input provenance differs"
    );
    for v in [&d, &t] {
        for key in [
            "publication_authorized",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(v[key] == false, "input provenance acquired authority");
        }
    }
    let m = fs::symlink_metadata(SOURCE)?;
    ensure!(
        m.dev() == d["device"].as_u64().context("input device")?
            && m.ino() == d["inode"].as_u64().context("input inode")?
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o444
            && m.len() == SNAPSHOT_BYTES,
        "frozen input inode/custody differs"
    );
    Ok(())
}
// Only this generated, non-sensitive checkpoint input is made readable by the
// credential-dropped node. Supervisor receipts and original source custody stay
// private. Final descriptor permissions are independent of the service umask.
fn stage_checkpoint(path: &Path) -> Result<()> {
    let text = format!("{SNAPSHOT_NAME}\n{ROOT_NAME}\n");
    ensure!(
        hex(&Sha256::digest(text.as_bytes())) == CHECKPOINT_SHA,
        "compiled checkpoint SHA"
    );
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    file.set_permissions(fs::Permissions::from_mode(0o444))?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o444
            && metadata.len() == text.len() as u64,
        "generated checkpoint reader custody differs"
    );
    bound(
        &Bound {
            path: path.into(),
            sha256: CHECKPOINT_SHA.into(),
        },
        text.len() as u64,
    )?;
    Ok(())
}
fn stage(p: &Plan) -> Result<()> {
    let root = Path::new(ROOT);
    absent(root)?;
    directory(root, 0o711, 0, 0)?;
    for leaf in ["inputs", "receipts"] {
        directory(&root.join(leaf), 0o700, 0, 0)?;
    }
    directory(&root.join("receipts/guard"), 0o700, 0, 0)?;
    for leaf in ["ledger", "scratch", "output"] {
        directory(&root.join(leaf), 0o700, UID, GID)?;
    }
    copy(
        Path::new(SOURCE),
        &root.join("inputs").join(SNAPSHOT_NAME),
        SNAPSHOT_SHA,
        SNAPSHOT_BYTES,
    )?;
    copy(
        Path::new(GENESIS_PATH),
        &root.join("inputs/genesis.tar.bz2"),
        GENESIS_SHA,
        GENESIS_BYTES,
    )?;
    copy(
        Path::new(GENESIS_PATH),
        &root.join("ledger/genesis.tar.bz2"),
        GENESIS_SHA,
        GENESIS_BYTES,
    )?;
    stage_checkpoint(&root.join("inputs").join(CHECKPOINT_FILE))?;
    fs::set_permissions(root.join("inputs"), fs::Permissions::from_mode(0o555))?;
    File::open(root.join("inputs"))?.sync_all()?;
    persist(
        &root.join("receipts/inputs.json"),
        &json!({"schema":"jetstreamer-epoch136-actual-20261120-input-capability-v1",
        "download":fixed(DOWNLOAD,DOWNLOAD_SHA),"terminal":fixed(TERMINAL,TERMINAL_SHA),"snapshot_sha256":SNAPSHOT_SHA,
        "snapshot_bytes":SNAPSHOT_BYTES,"node":p.node,"worker":fixed(WORKER_PATH,WORKER_SHA),"genesis_sha256":GENESIS_SHA,
        "checkpoints_sha256":CHECKPOINT_SHA,"source_custody_changed":false,"worker_spawned":false,"snapshot_restored":false,
        "ordinary_replay_claim":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )
}
// The native node was qualified at TOOLS. The root-owned package can be
// projected there as the very same directory without copying its members.
fn tools_destination(destination: &Value) -> Result<()> {
    if destination == contract::TOOLS {
        return Ok(());
    }
    const SEALED: &str =
        "/var/lib/jetstreamer/horizon_runtime_data/epoch136-production-images-20261120-v1/tools";
    ensure!(destination == SEALED, "unexpected production package");
    let backing = fs::symlink_metadata(SEALED)?;
    let visible = fs::symlink_metadata(contract::TOOLS)?;
    ensure!(
        backing.is_dir()
            && visible.is_dir()
            && backing.uid() == 0
            && backing.mode() & 0o222 == 0
            && backing.dev() == visible.dev()
            && backing.ino() == visible.ino(),
        "runtime tools differ from the sealed directory"
    );
    Ok(())
}
fn seal(p: &Plan) -> Result<()> {
    let s = value(&p.tools_seal)?;
    ensure!(
        s["schema"] == "jetstreamer-sealed-deployment-receipt-v1",
        "136 tools seal scope"
    );
    tools_destination(&s["destination"])?;
    let members = s["members"].as_array().context("136 tools members")?;
    for b in [
        &p.node,
        &p.helper,
        &p.worker,
        &p.qualification,
        &p.source_proof,
        &p.history,
    ] {
        ensure!(
            members
                .iter()
                .filter(
                    |m| m["name"].as_str() == b.path.file_name().and_then(|n| n.to_str())
                        && m["sha256"] == b.sha256
                )
                .count()
                == 1,
            "136 tool is not sealed member"
        );
        bound(b, 512 << 20)?;
    }
    bound(&p.worker, 256 << 20)?;
    contract::qualification(p, &value(&p.qualification)?, &value(&p.source_proof)?)?;
    bound(&fixed(GUARD_PATH, GUARD_SHA), 64 << 20)?;
    Ok(())
}
fn command_result(mut c: Command, seconds: u64) -> Result<(bool, Vec<u8>)> {
    c.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = c.spawn()?;
    let mut pipe = child.stdout.take().context("command stdout")?;
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut out = Vec::new();
        let r = pipe
            .by_ref()
            .take((1 << 20) + 1)
            .read_to_end(&mut out)
            .map(|_| out);
        let _ = tx.send(r);
    });
    let begin = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if begin.elapsed() >= Duration::from_secs(seconds) {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("bounded command timeout")
        }
        thread::sleep(Duration::from_millis(20));
    };

    let out = rx.recv_timeout(Duration::from_secs(1))??;
    ensure!(out.len() <= 1 << 20, "command output too large");
    Ok((status.success(), out))
}
fn command_output(c: Command, seconds: u64) -> Result<Vec<u8>> {
    let (success, out) = command_result(c, seconds)?;
    ensure!(success, "bounded command failed");
    Ok(out)
}
fn systemctl(args: &[&str]) -> Result<Vec<u8>> {
    let mut c = Command::new("/usr/bin/systemctl");
    c.args(args);
    command_output(c, 5)
}
fn native(unit: &str) -> Result<Value> {
    ensure!(
        [UNIT, GUARD_UNIT, GUARD_TIMER].contains(&unit),
        "foreign native unit"
    );
    let out = systemctl(&[
        "show",
        unit,
        "--no-pager",
        "--property=Id,LoadState,Type,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,Result,ExecMainStatus,ExecStart,ControlGroup,MemoryHigh,MemoryMax,MemorySwapMax,MemoryAccounting,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,Delegate,KillMode,NoNewPrivileges,TimeoutStartUSec,Unit,LastTriggerUSecMonotonic,ExecMainStartTimestampMonotonic",
    ])?;
    let mut map = serde_json::Map::new();
    for l in std::str::from_utf8(&out)?.lines() {
        let (k, v) = l.split_once('=').context("native property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate native property"
        );
    }
    Ok(Value::Object(map))
}
fn duration(v: &Value, key: &str) -> Result<u64> {
    contract::native_duration_micros(v[key].as_str().context("136 native duration field")?)
}

fn native_owner(n: &Value, iid: &str) -> Result<()> {
    ensure!(
        n["Id"] == UNIT
            && n["Type"] == "exec"
            && n["ControlPID"] == "0"
            && n["InvocationID"] == iid
            && n["MainPID"]
                .as_str()
                .context("136 native PID must be a string")?
                == std::process::id().to_string()
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["ControlGroup"] == format!("/system.slice/{UNIT}")
            && n["MemoryAccounting"] == "yes"
            && n["MemoryHigh"]
                .as_str()
                .context("136 native high must be a string")?
                == ROOT_STOP.to_string()
            && n["MemoryMax"]
                .as_str()
                .context("136 native cap must be a string")?
                == MEMORY.to_string()
            && n["MemorySwapMax"] == "0"
            && n["TasksMax"] == "512"
            && n["Delegate"] == "no"
            && n["KillMode"] == "control-group"
            && n["NoNewPrivileges"] == "yes"
            && duration(n, "CPUQuotaPerSecUSec")? == CPU_MICROS
            && duration(n, "RuntimeMaxUSec")? == (WORK_SECONDS + REAP_SECONDS) * 1_000_000,
        "136 native identity or bounded contract differs"
    );
    Ok(())
}
fn free() -> Result<u64> {
    let p = std::ffi::CString::new(ROOT)?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(unsafe { libc::statvfs(p.as_ptr(), &mut s) } == 0, "statvfs");
    s.f_bavail.checked_mul(s.f_frsize).context("free overflow")
}
fn start(pid: u32) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    ensure!(
        s.starts_with(&format!("{pid} (")) && s.len() < 65536,
        "PID stat shape"
    );
    let tail = s.rsplit_once(')').context("PID comm")?.1;
    ensure!(
        !matches!(tail.split_whitespace().next(), Some("Z" | "X" | "x")),
        "dead PID"
    );
    Ok(tail
        .split_whitespace()
        .nth(19)
        .context("PID start")?
        .parse()?)
}
fn pids() -> Result<Vec<u32>> {
    Ok(
        fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{UNIT}/cgroup.procs"))?
            .lines()
            .map(str::parse)
            .collect::<std::result::Result<Vec<_>, _>>()?,
    )
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
struct Worker {
    pid: u32,
    start_ticks: u64,
    exe: PathBuf,
    sha256: String,
}
fn worker(expected: Option<u32>) -> Result<Option<Worker>> {
    let mut found = None;
    for pid in pids()? {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let exe = match fs::read_link(proc.join("exe")) {
            Ok(v) => v,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT) | Some(libc::ESRCH)) => {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        let name = exe.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if exe.starts_with(ROOT)
            || name.starts_with("historical-worker")
            || name.starts_with("jetstreamer-historical-worker")
        {
            ensure!(
                name == "historical-worker"
                    && exe.starts_with(Path::new(ROOT).join("scratch"))
                    && found.is_none(),
                "136 escaped/duplicate worker"
            );
            let ticks = start(pid)?;
            let mut f = OpenOptions::new().read(true).open(proc.join("exe"))?;
            let before = identity(&f.metadata()?);
            ensure!(
                before.len <= 256 << 20
                    && hash_file(&mut f, 256 << 20)?.0 == WORKER_SHA
                    && identity(&f.metadata()?) == before,
                "136 materialized worker digest"
            );
            ensure!(
                fs::read_to_string(proc.join("maps"))?.lines().count() as u64 <= VMA
                    && start(pid)? == ticks
                    && fs::read_link(proc.join("exe"))? == exe,
                "136 worker identity/VMA"
            );
            found = Some(Worker {
                pid,
                start_ticks: ticks,
                exe,
                sha256: WORKER_SHA.into(),
            });
        }
    }
    if let Some(pid) = expected {
        ensure!(
            found.as_ref().is_some_and(|w| w.pid == pid),
            "136 expected worker absent"
        );
    }
    Ok(found)
}
fn replay_credentials(pid: u32) -> Result<()> {
    let s = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let get = |k: &str| {
        s.lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap_or("")
            .trim()
    };
    ensure!(
        get("Uid:") == "1001\t1001\t1001\t1001"
            && get("Gid:") == "1003\t1003\t1003\t1003"
            && get("Groups:").is_empty()
            && get("NoNewPrivs:") == "1"
            && ["CapEff:", "CapPrm:", "CapAmb:"]
                .iter()
                .all(|k| get(k) == "0000000000000000"),
        "136 replay credentials/capabilities differ"
    );
    Ok(())
}
// Keep command construction side-effect free so the exact cleared environment
// and worker-owned private-parent contract are regression tested before spawn.
fn configured_node_command(p: &Plan, root: &Path) -> Command {
    let mut c = Command::new(&p.node.path);
    c.arg("136")
        .arg(root.join("ledger"))
        .arg("--verify")
        .arg(format!("--qualification-end-slot={END}"))
        .arg(format!(
            "--snapshot-archive={}",
            root.join("inputs").join(SNAPSHOT_NAME).display()
        ))
        .arg(format!(
            "--epoch-hashes={}",
            root.join("inputs").join(CHECKPOINT_FILE).display()
        ))
        .arg(format!(
            "--horizon-output={}",
            root.join("output").join(OUTPUT).display()
        ))
        .arg(format!(
            "--replay-scratch={}",
            root.join("scratch").display()
        ))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("RUST_LOG", "info")
        .env("TMPDIR", root.join("scratch"))
        // The node runs as UID/GID below. Its private-root parent must be owned
        // by that worker, while supervisor ROOT/receipts/socket stay root-owned.
        .env(
            "JETSTREAMER_PRIVATE_RUN_ROOT",
            root.join("scratch/private-run"),
        )
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_4_25", WORKER_PATH)
        .env("JETSTREAMER_HISTORICAL_TRACE", "1")
        .env("SOLANA_RAYON_THREADS", "3")
        .env("RAYON_NUM_THREADS", "3")
        .env("JETSTREAMER_HISTORICAL_POH_THREADS", "3")
        .env("JETSTREAMER_RIPGET_THREADS", "8")
        .env("JETSTREAMER_HISTORICAL_INITIALIZE_TIMEOUT_SECS", "3600")
        .env("JETSTREAMER_HISTORICAL_CHECKPOINT_TIMEOUT_SECS", "600")
        .env("JETSTREAMER_HISTORICAL_REAP_TIMEOUT_SECS", "120")
        .env(SOCKET_ENV, root.join("entry.sock"))
        .env(SUPERVISOR_ENV, std::process::id().to_string())
        .stdin(Stdio::null())
        .process_group(0);
    c
}
fn node_command(p: &Plan) -> Result<Command> {
    let root = Path::new(ROOT);
    let mut c = configured_node_command(p, root);
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(root.join("output/reproduction.log"))?;
    c.stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
    // Only async-signal-safe syscalls run in the forked child. Drop all three
    // IDs, supplementary groups, ambient caps, and ability to acquire privilege.
    unsafe {
        c.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(GID, GID, GID) != 0
                || libc::setresuid(UID, UID, UID) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                ) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(c)
}

fn guard_stop_shape(guard: &Value, timer: &Value, sha: &str) -> Result<bool> {
    if guard["LoadState"] == "not-found" && timer["LoadState"] == "not-found" {
        return Ok(false);
    }
    let expected = format!(
        "{{ path={GUARD_PATH} ; argv[]={GUARD_PATH} {ROOT}/receipts/guard-plan.json --plan-sha256 {sha} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time="
    );
    ensure!(
        guard["Id"] == GUARD_UNIT
            && guard["Type"] == "oneshot"
            && guard["ExecStart"]
                .as_str()
                .is_some_and(|v| v.starts_with(&expected) && v.matches(" ; argv[]=").count() == 1)
            && timer["Id"] == GUARD_TIMER
            && timer["Unit"] == GUARD_UNIT,
        "136 refuses to stop a foreign guard or timer"
    );
    Ok(true)
}
fn cleanup_terminal(unit: &str, v: &Value) -> bool {
    let timer = unit == GUARD_TIMER;
    matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
        && matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
        && matches!(v["SubState"].as_str(), Some("dead" | "failed"))
        && (v["MainPID"] == "0" || (timer && v["MainPID"].is_null()))
        && (v["ControlPID"] == "0" || (timer && v["ControlPID"].is_null()))
        && (v["ControlGroup"] == "" || v["ControlGroup"].is_null())
}
fn cleanup_native_output(unit: &str, success: bool, out: &[u8]) -> Result<Value> {
    ensure!(
        [GUARD_UNIT, GUARD_TIMER].contains(&unit),
        "foreign cleanup unit"
    );
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(out)?.lines() {
        let (key, value) = line.split_once('=').context("cleanup native property")?;
        ensure!(
            values.insert(key.into(), json!(value)).is_none(),
            "duplicate cleanup property"
        );
    }
    let value = Value::Object(values);
    ensure!(value["Id"] == unit, "cleanup native unit differs");
    ensure!(
        success || (value["LoadState"] == "not-found" && cleanup_terminal(unit, &value)),
        "cleanup native query failed without positive collected-unit evidence"
    );
    Ok(value)
}
fn cleanup_native(unit: &str) -> Result<Value> {
    let mut command = Command::new("/usr/bin/systemctl");
    command.args(["show",unit,"--no-pager",
        "--property=Id,LoadState,Type,InvocationID,MainPID,ControlPID,NRestarts,ActiveState,SubState,ExecStart,Unit,ControlGroup"]);
    let (success, out) = command_result(command, 5)?;
    cleanup_native_output(unit, success, &out)
}
fn stop_owned_guard(iid: &str, sha: &str) -> Result<()> {
    let plan = value(&fixed(&format!("{ROOT}/receipts/guard-plan.json"), sha))?;
    ensure!(
        plan["unit"] == UNIT && plan["invocation_id"] == iid && plan["worker_root"] == ROOT,
        "136 guard cleanup ownership differs"
    );
    let guard = cleanup_native(GUARD_UNIT)?;
    let timer = cleanup_native(GUARD_TIMER)?;
    if guard_stop_shape(&guard, &timer, sha)? {
        systemctl(&["stop", GUARD_TIMER])?;
        // Stopping the timer may collect an already-finished transient service.
        // Only this exact previously authenticated lease may use that state.
        let remaining = cleanup_native(GUARD_UNIT)?;
        if remaining["LoadState"] != "not-found" {
            ensure!(
                guard_stop_shape(&remaining, &timer, sha)?,
                "owned guard disappeared ambiguously"
            );
            systemctl(&["stop", GUARD_UNIT])?;
        }
        ensure!(
            cleanup_terminal(GUARD_UNIT, &cleanup_native(GUARD_UNIT)?)
                && cleanup_terminal(GUARD_TIMER, &cleanup_native(GUARD_TIMER)?),
            "owned guard or timer did not drain"
        );
    }
    Ok(())
}
struct OwnedGuard {
    cleanup: Box<dyn FnMut() -> Result<()>>,
    armed: bool,
}
impl OwnedGuard {
    fn stop(&mut self) -> Result<()> {
        (self.cleanup)()?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for OwnedGuard {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = (self.cleanup)()
        {
            eprintln!("epoch 136 owned guard cleanup failed: {error:#}");
        }
    }
}
fn arm_guard(iid: &str, floor: u64) -> Result<(Value, String, OwnedGuard)> {
    ensure!(
        fs::metadata(ROOT)?.dev() == fs::metadata(contract::FILESYSTEM)?.dev(),
        "136 guard filesystem differs from actual replay storage"
    );
    for name in [GUARD_UNIT, GUARD_TIMER] {
        let n = native(name)?;
        ensure!(
            n["LoadState"] == "not-found" && n["MainPID"].as_str().is_none_or(|p| p == "0"),
            "136 guard namespace occupied"
        );
    }
    let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,
        "filesystem":contract::FILESYSTEM,"worker_root":ROOT,"minimum_free_bytes":floor,"maximum_worker_vmas":VMA,
        "maximum_root_physical_bytes":ROOT_STOP,"receipt_directory":Path::new(ROOT).join("receipts/guard")});
    contract::validate_guard_scope(&plan, iid, floor)?;
    let path = Path::new(ROOT).join("receipts/guard-plan.json");
    persist(&path, &plan)?;
    let sha = hex(&Sha256::digest(fs::read(&path)?));
    let cleanup_iid = iid.to_owned();
    let cleanup_sha = sha.clone();
    let guard = OwnedGuard {
        cleanup: Box::new(move || stop_owned_guard(&cleanup_iid, &cleanup_sha)),
        armed: true,
    };
    let mut c = Command::new("/usr/bin/systemd-run");
    c.args([
        "--quiet",
        "--unit",
        GUARD_UNIT,
        "--on-active=1s",
        "--on-unit-active=60s",
        "--timer-property=AccuracySec=1s",
        "--property=Type=oneshot",
        "--property=User=root",
        "--property=MemoryAccounting=yes",
        "--property=MemoryMax=536870912",
        "--property=MemorySwapMax=0",
        "--property=CPUQuota=100%",
        "--property=TasksMax=32",
        "--property=TimeoutStartSec=90",
        "--property=TimeoutStopSec=15",
        "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "--property=AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL",
        "--property=NoNewPrivileges=yes",
        "--property=ProtectSystem=strict",
        "--property=ProtectHome=read-only",
        "--property=PrivateTmp=yes",
        "--property=Restart=no",
        "--property=StandardOutput=null",
    ])
    .arg(format!("--property=ReadWritePaths={ROOT}/receipts/guard"))
    .arg(GUARD_PATH)
    .arg(path)
    .arg("--plan-sha256")
    .arg(&sha)
    .arg("--self-sha256")
    .arg(GUARD_SHA);
    command_output(c, 10)?;
    Ok((plan, sha, guard))
}
fn guard_fire_shape(
    v: &Value,
    iid: &str,
    sha: &str,
    owner_pid: u32,
    worker_pid: Option<u32>,
    floor: u64,
    clock: (u64, u64),
) -> Result<()> {
    let (after, time) = clock;
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("guard sample clock")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["producer_invocation_id"] == iid
            && v["producer"]["invocation_id"] == iid
            && v["producer"]["pid"] == owner_pid
            && v["producer"]["restarts"] == 0
            && v["producer"]["active"] == "active"
            && v["producer"]["sub"] == "running"
            && v["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && v["guard_sha256"] == GUARD_SHA
            && v["plan_sha256"] == sha
            && v["producer_stop_enabled"] == true
            && v["minimum_free_bytes"] == floor
            && v["maximum_root_physical_bytes"] == ROOT_STOP
            && v["maximum_worker_vmas"] == VMA
            && v["trip_reason"].is_null()
            && v["worker_observation_error"].is_null()
            && v["root_physical_observation_error"].is_null()
            && v["root_physical_observation"]["exceeds_budget"] == false
            && v["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= ROOT_STOP)
            && v["available_bytes"].as_u64().is_some_and(|n| n >= floor)
            && at >= after
            && at <= time
            && time - at <= 180
            && v["bounded_measurement"] == false
            && v["bounded_canary"].is_null()
            && v["native_main"].is_null(),
        "136 actual guard sample is foreign/stale/unavailable/tripped"
    );
    if let Some(pid) = worker_pid {
        let w = v["workers"].as_array().context("guard workers")?;
        ensure!(
            w.len() == 1 && w[0][0] == pid && w[0][1].as_u64().is_some_and(|n| n <= VMA),
            "136 initial guard has not observed exactly the real worker"
        );
    }
    Ok(())
}
fn typed_timer_monotonic(raw: &[u8]) -> Result<u64> {
    ensure!(raw.len() <= 64, "typed timer timestamp exceeds bound");
    let text = std::str::from_utf8(raw)?;
    let number = text
        .strip_prefix("t ")
        .and_then(|s| s.strip_suffix('\n'))
        .context("timer monotonic property must be a typed u64")?
        .parse::<u64>()?;
    ensure!(
        number > 0 && text == format!("t {number}\n"),
        "timer monotonic timestamp is zero or noncanonical"
    );
    Ok(number)
}
fn timer_object_path(unit: &str) -> Result<String> {
    ensure!(
        !unit.is_empty()
            && unit.len() <= 255
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid timer object unit"
    );
    let mut out = String::from("/org/freedesktop/systemd1/unit/");
    for byte in unit.bytes() {
        if byte.is_ascii_alphanumeric() {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("_{byte:02x}"));
        }
    }
    Ok(out)
}
fn actual_timer_trigger() -> Result<u64> {
    let path = timer_object_path(GUARD_TIMER)?;
    let mut command = Command::new("/usr/bin/busctl");
    command.args([
        "--system",
        "get-property",
        "org.freedesktop.systemd1",
        &path,
        "org.freedesktop.systemd1.Timer",
        "LastTriggerUSecMonotonic",
    ]);
    typed_timer_monotonic(&command_output(command, 5)?)
}

fn actual_guard(iid: &str, sha: &str, pid: Option<u32>, floor: u64, after: u64) -> Result<Value> {
    let timer = native(GUARD_TIMER)?;
    ensure!(
        timer["ActiveState"] == "active" && timer["Unit"] == GUARD_UNIT,
        "136 guard timer disarmed"
    );
    let trigger = actual_timer_trigger()?;
    let n = native(GUARD_UNIT)?;
    let guard_iid = n["InvocationID"].as_str().context("actual guard IID")?;
    ensure!(
        digest(guard_iid, 32)
            && n["Type"] == "oneshot"
            && n["ControlPID"] == "0"
            && duration(&n, "TimeoutStartUSec")? == 90_000_000
            && n["MainPID"] == "0"
            && n["NRestarts"] == "0"
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && trigger > 0
            && n["ExecMainStartTimestampMonotonic"]
                .as_str()
                .context("guard actual start")?
                .parse::<u64>()?
                >= trigger,
        "136 guard has no successful actual timer fire"
    );
    let command = n["ExecStart"].as_str().context("guard command")?;
    let expected = format!(
        "{{ path={GUARD_PATH} ; argv[]={GUARD_PATH} {ROOT}/receipts/guard-plan.json --plan-sha256 {sha} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time="
    );
    ensure!(
        command.starts_with(&expected) && command.matches(" ; argv[]=").count() == 1,
        "136 guard command differs"
    );
    let path = Path::new(ROOT)
        .join("receipts/guard")
        .join(format!("sample-{guard_iid}.json"));
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && m.len() <= 1 << 20,
        "unsafe guard receipt"
    );
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    let v: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        v["guard_invocation_id"] == guard_iid,
        "guard receipt IID mismatch"
    );
    guard_fire_shape(
        &v,
        iid,
        sha,
        std::process::id(),
        pid,
        floor,
        (after, now()?),
    )?;
    Ok(json!({"sample":v,"native":n,"timer":timer,"timer_trigger_usec_monotonic":trigger}))
}
struct OwnedChild(Child, bool);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.1 {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGCONT);
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}
fn peer(stream: &UnixStream, node: u32) -> Result<()> {
    let mut c: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut c as *mut libc::ucred).cast(),
                &mut len,
            )
        } == 0
            && c.pid == node as i32
            && c.uid == UID
            && c.gid == GID,
        "136 entry peer differs"
    );
    Ok(())
}
fn request(bytes: &[u8], node: u32) -> Result<u32> {
    let text = std::str::from_utf8(bytes)?;
    let a = text.split_whitespace().collect::<Vec<_>>();
    ensure!(
        bytes.len() <= 256
            && text.ends_with('\n')
            && a.len() == 3
            && a[0] == BARRIER_VERSION
            && a[1].parse::<u32>()? == node,
        "136 ready request differs"
    );
    Ok(a[2].parse()?)
}
fn measured_root(expected: &Identity) -> Result<root_budget::Observation> {
    let m = identity(&fs::symlink_metadata(ROOT)?);
    ensure!(
        m.dev == expected.dev && m.ino == expected.ino,
        "136 root replaced"
    );
    let v = root_budget::observe(Path::new(ROOT), ROOT_STOP)?;
    ensure!(!v.exceeds_budget, "136 physical root stop");
    Ok(v)
}
extern "C" fn signal(sig: i32) {
    SIGNAL.store(sig, Ordering::SeqCst);
}
fn install_signals() -> Result<()> {
    for s in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP] {
        let mut a: libc::sigaction = unsafe { std::mem::zeroed() };
        a.sa_sigaction = signal as *const () as usize;
        ensure!(
            unsafe { libc::sigemptyset(&mut a.sa_mask) } == 0
                && unsafe { libc::sigaction(s, &a, std::ptr::null_mut()) } == 0,
            "136 signal install"
        );
    }
    Ok(())
}
fn root_result(v: &Value) -> Result<()> {
    ensure!(
        v["schema_version"] == 1
            && v["epoch"] == 136
            && v["worker_executable_sha256"] == WORKER_SHA
            && v["runtime"]["runtime_profile"] == "solana-v1.4.25"
            && v["output_slot_start"] == FIRST
            && v["output_slot_count"] == COUNT
            && v["bootstrap"]["slot"] == BOOTSTRAP
            && v["bootstrap"]["accounts_hash"] == "J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN"
            && v["bootstrap"]["slot_complete"] == true
            && v["terminal"]["slot"] == END
            && v["terminal"]["accounts_hash"] == "HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8"
            && v["terminal"]["slot_complete"] == true
            && v["archive_sha256"]
                .as_str()
                .is_some_and(|s| digest(s, 64) && s != "0".repeat(64)),
        "136 output is not the exact restored hourly 7396-slot segment"
    );
    Ok(())
}
fn output() -> Result<Value> {
    let path = Path::new(ROOT).join("output").join(OUTPUT);
    absent(&PathBuf::from(format!("{}.sha256", path.display())))?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        m.is_file() && m.uid() == UID && m.nlink() == 1 && m.mode() & 0o077 == 0 && m.len() > 0,
        "unsafe private output"
    );
    let meta = PathBuf::from(format!("{}.segment.json", path.display()));
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&meta)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == UID && m.nlink() == 1 && m.len() <= 1 << 20,
        "unsafe producer manifest"
    );
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    let v = serde_json::from_slice(&bytes)?;
    root_result(&v)?;
    Ok(
        json!({"path":path,"producer_segment":v,"producer_segment_sha256":hex(&Sha256::digest(&bytes)),"independent_archive_verification_performed":false}),
    )
}
fn supervise(p: &Plan, a: &Admission, iid: &str) -> Result<Value> {
    let root = Path::new(ROOT);
    let root_id = identity(&fs::symlink_metadata(root)?);
    let initial = measured_root(&root_id)?;
    ensure!(
        free()?
            >= a.protected_existing_free_bytes
                .checked_add(RESERVE)
                .context("136 guard floor overflow")?,
        "136 free floor before entry"
    );
    persist(
        &root.join("receipts/pre-restore-meter.json"),
        &json!({"complete":true,"recorded_unix_seconds":now()?,"observation":initial,"restore_started":false}),
    )?;
    let (_socket_root_descriptor, listener) = fixed_socket::bind()?;
    listener.set_nonblocking(true)?;
    let (_guard_plan, guard_sha, mut owned_guard) =
        arm_guard(iid, a.protected_existing_free_bytes)?;
    // Require a real complete protective fire before even spawning the node.
    let before = Instant::now();
    loop {
        if actual_guard(iid, &guard_sha, None, a.protected_existing_free_bytes, 0).is_ok() {
            break;
        }
        ensure!(
            before.elapsed() < Duration::from_secs(120),
            "136 pre-spawn guard timeout"
        );
        thread::sleep(Duration::from_millis(200));
    }
    ensure!(
        now()? < a.launch_expires_unix_seconds,
        "136 launch admission expired during staging"
    );
    lifecycle_gate::wait(p, a, iid, &guard_sha, &initial)?;
    let mut owned = OwnedChild(node_command(p)?.spawn()?, false);
    let node = owned.0.id();
    let node_start = start(node)?;
    let started = Instant::now();
    let mut released = false;
    let mut release = Value::Null;
    let mut bound_worker = None;
    let mut pending = Some(physical_meter::Pending::begin(root.into(), ROOT_STOP)?);
    let mut last_scan = Instant::now();
    let mut last_guard = Instant::now();
    let mut last_guard_sample = Value::Null;
    let mut root_peak = initial.conservative_physical_bytes;
    let outcome = (|| -> Result<Value> {
        loop {
            ensure!(SIGNAL.load(Ordering::SeqCst) == 0, "136 external signal");
            ensure!(
                started.elapsed() < Duration::from_secs(WORK_SECONDS),
                "136 work deadline"
            );
            let current = identity(&fs::symlink_metadata(root)?);
            ensure!(
                current.dev == root_id.dev && current.ino == root_id.ino,
                "136 root identity changed"
            );
            ensure!(
                free()? >= a.protected_existing_free_bytes,
                "136 filesystem floor"
            );
            if let Some(scan) = &pending
                && let Some(v) = scan.poll()?
            {
                ensure!(!v.exceeds_budget, "136 physical root stop");
                root_peak = root_peak.max(v.conservative_physical_bytes);
                pending = None;
                last_scan = Instant::now();
            }
            if pending.is_none() && last_scan.elapsed() >= Duration::from_secs(5) {
                pending = Some(physical_meter::Pending::begin(root.into(), ROOT_STOP)?);
            }
            if !released {
                ensure!(
                    started.elapsed() < Duration::from_secs(180),
                    "136 pre-initialize entry timeout"
                );
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        peer(&stream, node)?;
                        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
                        let mut bytes = Vec::new();
                        for _ in 0..=256 {
                            let mut b = [0];
                            stream.read_exact(&mut b)?;
                            bytes.push(b[0]);
                            if b[0] == b'\n' {
                                break;
                            }
                        }
                        let pid = request(&bytes, node)?;
                        replay_credentials(node)?;
                        replay_credentials(pid)?;
                        let observed = worker(Some(pid))?.context("136 worker not materialized")?;
                        let ready_at = now()?;
                        let wait = Instant::now();
                        let actual = loop {
                            ensure!(
                                wait.elapsed() < Duration::from_secs(120)
                                    && SIGNAL.load(Ordering::SeqCst) == 0,
                                "136 first worker guard timeout"
                            );
                            if let Ok(v) = actual_guard(
                                iid,
                                &guard_sha,
                                Some(pid),
                                a.protected_existing_free_bytes,
                                ready_at,
                            ) {
                                break v;
                            }
                            ensure!(
                                free()? >= a.protected_existing_free_bytes,
                                "136 first-fire free floor"
                            );
                            if let Some(scan) = &pending
                                && let Some(v) = scan.poll()?
                            {
                                ensure!(!v.exceeds_budget, "136 first-fire root stop");
                                pending = None;
                            }
                            thread::sleep(Duration::from_millis(200));
                        };
                        // A fresh complete descriptor scan is mandatory here. No
                        // old result, pending scan, zero or scan error is admitted.
                        while let Some(scan) = &pending {
                            if let Some(v) = scan.poll()? {
                                ensure!(!v.exceeds_budget, "136 pending entry root stop");
                                pending = None;
                            } else {
                                thread::sleep(Duration::from_millis(100));
                            }
                        }
                        let measured = measured_root(&root_id)?;
                        root_peak = root_peak.max(measured.conservative_physical_bytes);
                        ensure!(
                            start(node)? == node_start
                                && worker(Some(pid))?.as_ref() == Some(&observed),
                            "136 node/worker replaced before restore"
                        );
                        native_owner(&native(UNIT)?, iid)?;
                        release = json!({"schema":"jetstreamer-epoch136-actual-20261120-entry-v1","invocation_id":iid,"node_pid":node,
                        "node_start_ticks":node_start,"worker":observed,"guard":actual,"complete_root_meter":measured,
                        "recorded_unix_seconds":now()?,"bootstrap":BOOTSTRAP,"first":FIRST,"end":END,"slot_count":COUNT,
                        "strict_bootstrap_checkpoint_still_required":true,"restoration_claimed":false,"publication_authorized":false});
                        persist(&root.join("receipts/entry.json"), &release)?;
                        last_guard_sample = release["guard"]["sample"].clone();
                        stream.write_all(b"R")?;
                        released = true;
                        bound_worker = Some(observed);
                        last_guard = Instant::now();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
                    Err(e) => return Err(e.into()),
                }
            }
            if released && last_guard.elapsed() >= Duration::from_secs(5) {
                native_owner(&native(UNIT)?, iid)?;
                // A natural close can reap the worker before the node returns;
                // the node still has a <= 6 h deadline and private output must
                // validate before success. A second or substituted worker denies.
                if let Some(w) = worker(None)? {
                    ensure!(
                        bound_worker.as_ref() == Some(&w),
                        "136 worker changed after release"
                    );
                }
                match actual_guard(iid, &guard_sha, None, a.protected_existing_free_bytes, 0) {
                    Ok(v) => last_guard_sample = v["sample"].clone(),
                    Err(_) => {
                        // An actual guard scan may be in flight. Its pending fire
                        // is not a measurement; retain only the previous positive
                        // fire within its finite age, alongside our separate
                        // bounded asynchronous physical meter.
                        ensure!(
                            native(GUARD_TIMER)?["ActiveState"] == "active",
                            "136 backup timer disarmed"
                        );
                        guard_fire_shape(
                            &last_guard_sample,
                            iid,
                            &guard_sha,
                            std::process::id(),
                            None,
                            a.protected_existing_free_bytes,
                            (0, now()?),
                        )?;
                    }
                }
                last_guard = Instant::now();
            }
            if let Some(status) = owned.0.try_wait()? {
                owned.1 = true;
                ensure!(released, "136 node exited without entry release");
                ensure!(status.success(), "136 node failed: {status}");
                return output();
            }
            thread::sleep(Duration::from_millis(100));
        }
    })();
    if !owned.1 {
        unsafe {
            libc::kill(-(node as i32), libc::SIGCONT);
            libc::kill(-(node as i32), libc::SIGKILL);
        }
        let _ = owned.0.wait();
        owned.1 = true;
    }
    // Reap/kill only processes still in this exact owned cgroup. A PID is
    // signaled through a pidfd to close PID reuse, never by a retained integer.
    let reap = Instant::now();
    loop {
        let rest = pids()?
            .into_iter()
            .filter(|p| *p != std::process::id())
            .collect::<Vec<_>>();
        if rest.is_empty() {
            break;
        }
        ensure!(
            reap.elapsed() < Duration::from_secs(REAP_SECONDS),
            "136 descendants did not drain"
        );
        for pid in rest {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            if fd >= 0 {
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd,
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    );
                    libc::close(fd);
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    let final_meter = match measured_root(&root_id) {
        Ok(v) => json!({"complete":true,"observation":v}),
        Err(e) => json!({"complete":false,"error":format!("{e:#}")}),
    };
    let outcome = outcome.and_then(|v| {
        ensure!(
            final_meter["complete"] == true,
            "136 final physical measurement unavailable or over bound"
        );
        Ok(v)
    });
    let receipt = json!({"schema":"jetstreamer-epoch136-actual-20261120-result-v1","epoch":136,"unit":UNIT,"invocation_id":iid,
        "node":p.node,"worker_sha256":WORKER_SHA,"snapshot_sha256":SNAPSHOT_SHA,"entry":release,"entry_released":released,
        "bootstrap":BOOTSTRAP,"output_slot_start":FIRST,"output_slot_count":COUNT,"terminal_root_slot":END,"excluded_epoch_slots":55,
        "original_failure":{"slot":FAILURE_SLOT,"entry":197,"transaction":113,"instruction":2,"signature":TARGET_SIGNATURE},"success":outcome.is_ok(),
        "output":outcome.as_ref().ok(),"error":outcome.as_ref().err().map(|e|format!("{e:#}")),"final_complete_root_meter":final_meter,
        "peak_observed_root_physical_bytes":root_peak,"data_reservation_bytes":DATA,"memory_max_bytes":MEMORY,
        "overshoot_reservation_bytes":RESERVE,"overshoot_bound_qualified":false,"cgroup_descendants_empty":true,
        "original_repair_backlog_open":true,"old_prefix_equivalence_proven":false,"full_epoch_span_proven":false,
        "ordinary_replay_claim":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    persist(&root.join("receipts/result.json"), &receipt)?;
    owned_guard.stop()?;
    outcome.map(|_| receipt)
}
fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.as_slice().get(1).is_some_and(|v| v == "--inspect") {
        ensure!(args.len() == 2, "--inspect accepts no other arguments");
        println!("{}", contract::description());
        return Ok(());
    }
    ensure!(
        args.len() == 10
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && args[6] == "--admission"
            && args[8] == "--admission-sha256",
        "usage: suffix PLAN --plan-sha256 HEX --self-sha256 HEX --admission FILE --admission-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "136 supervisor requires root"
    );
    install_signals()?;
    let plan_binding = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let p: Plan = serde_json::from_value(value(&plan_binding)?)?;
    plan_shape(&p)?;
    ensure!(
        p.helper.path == fs::read_link("/proc/self/exe")? && p.helper.sha256 == args[5],
        "136 helper generation differs"
    );
    seal(&p)?;
    let admission_binding = Bound {
        path: args[7].clone().into(),
        sha256: args[9].clone(),
    };
    ensure!(
        admission_binding.path == Path::new(contract::ADMISSION_PATH),
        "136 admission path differs"
    );
    let a: Admission = serde_json::from_value(value(&admission_binding)?)?;
    admission_shape(&p, &plan_binding, &a, now()?)?;
    contract::capacity(&a, &value(&a.resource_accounting)?)?;
    let retained_before = value(&p.history)?;
    bound(&a.writer, 256 << 20)?;
    provenance()?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        digest(&iid, 32)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "136 actual native invocation differs"
    );
    native_owner(&native(UNIT)?, &iid)?;
    absent(Path::new(ROOT))?;
    // Check actual free bytes on the parent filesystem before spending DATA.
    let parent = Path::new(ROOT).parent().context("136 root parent")?;
    let c = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0
            && s.f_bavail
                .checked_mul(s.f_frsize)
                .is_some_and(|n| n >= a.required_initial_free_bytes),
        "136 initial DATA does not fit"
    );
    stage(&p)?;
    ensure!(
        retained_before == value(&p.history)?,
        "retained history review changed while staging new generation"
    );
    persist(
        &Path::new(ROOT).join("receipts/launch.json"),
        &json!({"schema":"jetstreamer-epoch136-actual-20261120-launch-v1","plan":plan_binding,"admission":admission_binding,"unit":UNIT,"invocation_id":iid,"pid":std::process::id(),"start_ticks":start(std::process::id())?,"native":native(UNIT)?,"data_reservation_bytes":DATA,"memory_max_bytes":MEMORY,"publication_authorized":false}),
    )?;
    supervise(&p, &a, &iid)?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch 136 bounded hourly reproduction: {e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
#[path = "tests.rs"]
mod tests;
