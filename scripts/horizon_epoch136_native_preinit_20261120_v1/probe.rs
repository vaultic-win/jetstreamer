//! A real production-node CLI/worker Hello probe. This binary cannot send `R`.
//! The original production paths are projected only inside a systemd namespace.
#[path = "../horizon_epoch136_actual_20261120_v1/socket.rs"]
mod fixed_socket;
#[path = "../horizon_epoch136_actual_20261120_v1/scope.rs"]
mod scope;
use anyhow::{Context, Result, bail, ensure};
use scope::*;
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
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const NODE_SHA: &str = "bf702870fa328cf3fc43dd12a3943cab059fb7b0aa4ea1d3753c6a09b940cd71";
const MEMORY: u64 = 2 << 30;
const GROWTH: u64 = 4 << 30;
const UNIT: &str = "horizon-node-native-qualification-136-preinit-g1.service";
const STAGE_UNIT: &str = "horizon-node-native-qualification-136-preinit-stage-g1.service";
const PREDECESSOR: &str = "horizon-archive-publication-build-g1.service";
const WORK: &str = "/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/epoch136-native-preinit-20261120-g1";
const NODE: &str =
    "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/tools/jetstreamer-node";

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn hex(v: &[u8]) -> String {
    v.iter().map(|b| format!("{b:02x}")).collect()
}
fn sha(path: &Path, expected: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(before.is_file(), "hash input is not a file");
    let mut h = Sha256::new();
    let mut buf = [0u8; 131072];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let after = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && after.dev() == named.dev()
            && after.ino() == named.ino()
            && hex(&h.finalize()) == expected,
        "SHA or inode changed: {}",
        path.display()
    );
    Ok(())
}
fn persist(path: &Path, v: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn native(unit: &str, property: &str) -> Result<String> {
    let o = Command::new("/usr/bin/systemctl")
        .args(["show", unit, "--value", "--property", property])
        .output()?;
    ensure!(o.status.success(), "systemctl {} {} failed", unit, property);
    Ok(String::from_utf8(o.stdout)?.trim().to_owned())
}
fn cgroup() -> Result<PathBuf> {
    let t = fs::read_to_string("/proc/self/cgroup")?;
    Ok(Path::new("/sys/fs/cgroup").join(
        t.lines()
            .find_map(|l| l.strip_prefix("0::"))
            .context("cgroup v2")?
            .trim_start_matches('/'),
    ))
}
fn controls(unit: &str) -> Result<PathBuf> {
    ensure!(unsafe { libc::geteuid() } == 0, "root supervisor required");
    let cg = cgroup()?;
    let slice = cg.parent().context("serial aggregate cgroup")?;
    ensure!(
        slice.file_name().and_then(|s| s.to_str()) == Some("horizon136preinit.slice")
            && fs::read_to_string(slice.join("memory.max"))?.trim() == MEMORY.to_string()
            && fs::read_to_string(slice.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(slice.join("pids.max"))?.trim() == "128",
        "probe and guard must share the original serial aggregate bounds"
    );
    let cpu = fs::read_to_string(slice.join("cpu.max"))?;
    let parts: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        parts.len() == 2 && parts[0] == parts[1],
        "serial aggregate CPU limit"
    );
    ensure!(
        cg.file_name().and_then(|n| n.to_str()) == Some(unit),
        "wrong serial unit"
    );
    ensure!(
        fs::read_to_string(cg.join("memory.max"))?.trim() == MEMORY.to_string()
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0",
        "memory/swap limits changed"
    );
    let c = fs::read_to_string(cg.join("cpu.max"))?;
    let v: Vec<_> = c.split_whitespace().collect();
    ensure!(
        v.len() == 2 && v[0] == v[1],
        "one CPU serial limit required"
    );
    ensure!(
        fs::read_to_string(cg.join("pids.max"))?
            .trim()
            .parse::<u64>()?
            <= 128,
        "task bound exceeded"
    );
    ensure!(
        native(PREDECESSOR, "MainPID")? == "0"
            && matches!(
                native(PREDECESSOR, "ActiveState")?.as_str(),
                "inactive" | "failed"
            ),
        "publication build has not drained"
    );
    Ok(cg)
}
/// Check the private 172 identity on the fleet that the parent actually signed.
fn verify_172(fleet: &Value, state: &str, pid: &str, invocation: &str) -> Result<()> {
    const IID: &str = "5a691c24655a4ff489531d8d7cc50254";
    let mut owners = fleet["actual_active_private_diagnostics"]
        .as_array()
        .context("fleet private owner list")?
        .iter()
        .filter(|r| r["epoch"] == 172);
    if let Some(owner) = owners.next() {
        ensure!(
            owners.next().is_none()
                && state == "active"
                && pid == "2823601"
                && invocation == IID
                && owner["unit"]["InvocationID"] == IID
                && owner["admission"]["sha256"]
                    == "3c4134506e7cd31f22a550456fd41e8f6e92f9c48b91c5059fc7b0d2bed621d8",
            "172 active owner disagrees with fleet"
        );
    } else {
        ensure!(
            matches!(state, "inactive" | "failed")
                && pid == "0"
                && (invocation.is_empty() || invocation == IID)
                && fleet["terminal172_closure"]["sha256"]
                    == "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7",
            "172 terminal owner disagrees with fleet"
        );
    }
    Ok(())
}

/// Parent supplies a fresh no-clobber release only after the actual guard
/// prefire and complete fleet have accepted this invocation.
fn release(path: &Path, digest: &str, unit: &str, gate: bool) -> Result<Value> {
    let _cg = controls(unit)?;
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.uid() == 0
            && m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() < 16 << 20,
        "release custody"
    );
    sha(path, digest)?;
    let request: Value = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        request["schema"] == "horizon-epoch136-preinit-serial-request-v1"
            && request["unit"] == unit,
        "wrong serial request"
    );
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "invocation identity"
    );
    let ready = path
        .parent()
        .context("request parent")?
        .join(format!("actual-{iid}"))
        .join("release.json");
    let started = Instant::now();
    let mut heartbeat = Instant::now();
    loop {
        match fs::symlink_metadata(&ready) {
            Ok(m) => {
                ensure!(
                    m.uid() == 0
                        && m.is_file()
                        && m.nlink() == 1
                        && m.mode() & 0o222 == 0
                        && m.len() < 16 << 20,
                    "actual release custody"
                );
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
        ensure!(
            started.elapsed() < Duration::from_secs(120),
            "parent actual invocation/guard release timed out; no useful work started"
        );
        if heartbeat.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "{} awaiting parent actual guard release for {}; elapsed {}s; expires at 120s",
                now()?,
                iid,
                started.elapsed().as_secs()
            );
            heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(200));
    }
    let v: Value = serde_json::from_slice(&fs::read(&ready)?)?;
    let release_digest = hex(&Sha256::digest(fs::read(&ready)?));
    let seal_path = ready
        .parent()
        .context("token package")?
        .join("deployment-seal-receipt.json");
    let seal_meta = fs::symlink_metadata(&seal_path)?;
    ensure!(
        seal_meta.is_file()
            && seal_meta.uid() == 0
            && seal_meta.nlink() == 1
            && seal_meta.mode() & 0o222 == 0,
        "token seal custody"
    );
    let seal: Value = serde_json::from_slice(&fs::read(&seal_path)?)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"]
                == ready
                    .parent()
                    .context("token package")?
                    .to_str()
                    .context("token UTF8")?
            && seal["members"]
                .as_array()
                .context("token seal members")?
                .iter()
                .any(|m| m["name"] == "release.json" && m["sha256"] == release_digest),
        "matching normal Rust seal required for actual invocation release"
    );
    let t = now()?;
    let born = v["recorded_unix_seconds"]
        .as_u64()
        .context("release timestamp")?;
    let expiry = v["expires_unix_seconds"]
        .as_u64()
        .context("release expiry")?;
    ensure!(
        v["schema"] == "horizon-epoch136-preinit-serial-release-v1"
            && v["unit"] == unit
            && v["invocation_id"] == iid
            && v["request_sha256"] == digest
            && born <= t
            && t < expiry
            && expiry - born <= 900
            && v["memory_max_bytes"] == MEMORY
            && v["cpu_quota_micros"] == 1_000_000
            && v["maximum_new_bytes"] == GROWTH
            && v["no_initialize_authorized"] == true
            && v["serial_guard_prefire_passed"] == true
            && v["source_contained_in_origin_account_updates"] == true,
        "fresh parent serial release missing or stale"
    );
    for field in ["complete_fleet", "serial_guard_prefire", "source_proof"] {
        let b = &v[field];
        sha(
            Path::new(b["path"].as_str().context("proof path")?),
            b["sha256"].as_str().context("proof SHA")?,
        )?;
    }
    let guard: Value = serde_json::from_slice(&fs::read(
        v["serial_guard_prefire"]["path"]
            .as_str()
            .context("guard path")?,
    )?)?;
    ensure!(
        guard["schema"] == "jetstreamer-horizon-build-guard-sample-v1"
            && guard["unit"] == unit
            && guard["actor_invocation_id"] == iid
            && guard["native_ActiveState"] == "activating"
            && guard["native_SubState"] == "start-pre"
            && guard["native_MainPID"] == 0
            && guard["native_NRestarts"] == 0
            && guard["trip"] == false
            && guard["native_owner_stable"] == true
            && guard["memory_max_bytes"] == MEMORY
            && guard["cpu_quota_usec"] == 1_000_000
            && guard["tasks_max"] == 128
            && guard["maximum_root_bytes"] == GROWTH,
        "guard does not prove this native pre-start actor and unchanged bounds"
    );
    if gate {
        ensure!(
            guard["native_ControlPID"] == std::process::id()
                && native(unit, "ControlPID")? == std::process::id().to_string()
                && native(unit, "MainPID")? == "0"
                && native(unit, "ActiveState")? == "activating"
                && native(unit, "SubState")? == "start-pre",
            "guard control PID is not this actual start gate"
        );
    }
    let binding = &v["complete_fleet"];
    let fleet_path = Path::new(binding["path"].as_str().context("fleet path")?);
    ensure!(
        fleet_path.canonicalize()? == fleet_path
            && fleet_path.starts_with("/var/lib/jetstreamer/horizon_runtime_data")
            && fleet_path
                .file_name()
                .is_some_and(|n| n == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        "unexpected fleet location"
    );
    let meta = fs::symlink_metadata(fleet_path)?;
    ensure!(
        meta.uid() == 0 && meta.mode() & 0o022 == 0 && meta.len() < 16 << 20,
        "fleet custody"
    );
    let bytes = fs::read(fleet_path)?;
    ensure!(
        binding["sha256"] == hex(&Sha256::digest(&bytes)),
        "fleet bytes changed"
    );
    let actor = "horizon-qualify-172-trace-hourly-20261120-v1.service";
    verify_172(
        &serde_json::from_slice(&bytes)?,
        &native(actor, "ActiveState")?,
        &native(actor, "MainPID")?,
        &native(actor, "InvocationID")?,
    )?;
    controls(unit)?;
    Ok(v)
}
fn directory(p: &Path, mode: u32, uid: u32, gid: u32) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0,
        "fixture chown"
    );
    Ok(())
}
fn stage(work: &Path) -> Result<()> {
    ensure!(
        work.canonicalize()? == work
            && work.starts_with(
                "/home/sol/.jetstreamer-private/epoch168-trace-worker-build-20261120-v1/work/"
            ),
        "fixture must use booked HOME-backed serial image"
    );
    let fixture = work.join("fixture");
    directory(&fixture, 0o711, 0, 0)?;
    let root = fixture.join("reproduction");
    directory(&root, 0o711, 0, 0)?;
    directory(&fixture.join("tools"), 0o755, 0, 0)?;
    directory(&root.join("inputs"), 0o755, 0, 0)?;
    for leaf in ["ledger", "scratch", "output"] {
        directory(&root.join(leaf), 0o700, UID, GID)?;
    }
    // This zero-length mount point is never accepted as input by the node.
    let _placeholder = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(root.join("inputs").join(SNAPSHOT_NAME))?;
    sha(Path::new(GENESIS_PATH), GENESIS_SHA)?;
    for target in [
        root.join("inputs/genesis.tar.bz2"),
        root.join("ledger/genesis.tar.bz2"),
    ] {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&target)?;
        let mut input = File::open(GENESIS_PATH)?;
        ensure!(
            std::io::copy(&mut input, &mut output)? == GENESIS_BYTES,
            "genesis size"
        );
        output.sync_all()?;
        output.set_permissions(fs::Permissions::from_mode(0o444))?;
        output.sync_all()?;
        sha(&target, GENESIS_SHA)?;
    }
    let text = format!("{SNAPSHOT_NAME}\n{ROOT_NAME}\n");
    ensure!(
        hex(&Sha256::digest(text.as_bytes())) == CHECKPOINT_SHA,
        "checkpoint digest"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(root.join("inputs").join(CHECKPOINT_FILE))?;
    f.write_all(text.as_bytes())?;
    f.set_permissions(fs::Permissions::from_mode(0o444))?;
    f.sync_all()?;
    persist(
        &work.join("stage.json"),
        &json!({"schema":"horizon-epoch136-native-preinit-stage-v1","at":now()?,"fixture":fixture,"worker_started":false,"snapshot_copied":false}),
    )
}
fn credentials(pid: u32) -> Result<Value> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let f = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .unwrap_or("")
            .trim()
            .to_owned()
    };
    ensure!(
        f("Uid:") == "1001\t1001\t1001\t1001"
            && f("Gid:") == "1003\t1003\t1003\t1003"
            && f("Groups:").is_empty()
            && f("NoNewPrivs:") == "1"
            && ["CapEff:", "CapPrm:", "CapAmb:"]
                .iter()
                .all(|k| f(k) == "0000000000000000"),
        "node/worker credentials"
    );
    Ok(
        json!({"pid":pid,"status":status,"stat":fs::read_to_string(format!("/proc/{pid}/stat"))?,"cgroup":fs::read_to_string(format!("/proc/{pid}/cgroup"))?}),
    )
}
fn command(work: &Path) -> Result<Command> {
    let root = Path::new(ROOT);
    let mut c = Command::new(NODE);
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
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(work.join("node.log"))?;
    c.stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log));
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
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            unsafe {
                libc::kill(-(self.0.id() as i32), libc::SIGKILL);
            }
            let _ = self.0.wait();
        }
    }
}
fn request(stream: &mut UnixStream, node: u32) -> Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut n = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut n,
            )
        } == 0
            && cred.pid == node as i32
            && cred.uid == UID
            && cred.gid == GID,
        "foreign gate peer"
    );
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut bytes = Vec::new();
    while bytes.len() < 256 {
        let mut b = [0];
        stream.read_exact(&mut b)?;
        bytes.push(b[0]);
        if b[0] == b'\n' {
            break;
        }
    }
    let s = String::from_utf8(bytes)?;
    let fields: Vec<_> = s.split_whitespace().collect();
    ensure!(
        fields.len() == 3
            && fields[0] == BARRIER_VERSION
            && fields[1] == node.to_string()
            && s.ends_with('\n'),
        "foreign gate request"
    );
    let worker = fields[2].parse::<u32>()?;
    ensure!(worker > 1 && worker != node, "invalid worker PID");
    Ok(worker)
}
fn run(work: &Path, parent: &Value) -> Result<()> {
    let root = Path::new(ROOT);
    let actual = fs::metadata(root)?;
    let fixture = fs::metadata(work.join("fixture/reproduction"))?;
    ensure!(
        actual.dev() == fixture.dev()
            && actual.ino() == fixture.ino()
            && actual.uid() == 0
            && actual.gid() == 0
            && actual.mode() & 0o7777 == 0o711,
        "actual generation is not the isolated fixture projection"
    );
    let source = fs::metadata(SOURCE)?;
    let input = fs::metadata(root.join("inputs").join(SNAPSHOT_NAME))?;
    ensure!(
        source.dev() == input.dev()
            && source.ino() == input.ino()
            && source.len() == SNAPSHOT_BYTES
            && input.mode() & 0o222 == 0,
        "snapshot bind differs"
    );
    sha(Path::new(NODE), NODE_SHA)?;
    sha(Path::new(WORKER_PATH), WORKER_SHA)?;
    sha(&root.join("inputs").join(CHECKPOINT_FILE), CHECKPOINT_SHA)?;
    let (_directory, listener) = fixed_socket::bind()?;
    listener.set_nonblocking(true)?;
    let mut c = command(work)?;
    persist(
        &work.join("invocation.json"),
        &json!({"node":NODE,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,
        "argv":c.get_args().collect::<Vec<_>>(),"environment":c.get_envs().collect::<Vec<_>>(),"parent_release":parent,
        "at":now()?,"initialize_authorized":false}),
    )?;
    let mut child = Owned(c.spawn()?);
    let node = child.0.id();
    let started = Instant::now();
    let mut heartbeat = Instant::now();
    let mut stream = loop {
        ensure!(
            started.elapsed() < Duration::from_secs(480),
            "real node did not reach barrier within eight minutes"
        );
        if let Some(exit) = child.0.try_wait()? {
            bail!("real node exited before barrier: {exit}; see node.log");
        }
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(e) => return Err(e.into()),
        }
        if heartbeat.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "{} waiting for genuine node/worker pre-Initialize barrier; elapsed {}s",
                now()?,
                started.elapsed().as_secs()
            );
            heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(100));
    };
    let worker = request(&mut stream, node)?;
    let node_identity = credentials(node)?;
    let worker_identity = credentials(worker)?;
    ensure!(
        worker_identity["status"]
            .as_str()
            .context("worker status")?
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .context("worker parent")?
            .trim()
            == node.to_string(),
        "worker is not the node's child"
    );
    ensure!(
        node_identity["cgroup"] == worker_identity["cgroup"]
            && node_identity["cgroup"] == fs::read_to_string("/proc/self/cgroup")?,
        "worker left native cgroup"
    );
    let worker_exe = fs::read_link(format!("/proc/{worker}/exe"))?;
    ensure!(
        worker_exe.starts_with(root.join("scratch/.historical-runtime"))
            && worker_exe.ends_with("bound-worker/historical-worker"),
        "worker not genuine bound image"
    );
    sha(&worker_exe, WORKER_SHA)?;
    let bound = worker_exe
        .parent()
        .and_then(Path::parent)
        .context("worker private root")?
        .join("bound-bootstrap")
        .join(SNAPSHOT_NAME);
    ensure!(
        fs::metadata(&bound)?.len() == SNAPSHOT_BYTES,
        "native bound snapshot length"
    );
    sha(&bound, SNAPSHOT_SHA)?;
    persist(
        &work.join("barrier.json"),
        &json!({"schema":"horizon-epoch136-native-preinit-barrier-v1","at":now()?,"node":node_identity,"worker":worker_identity,
        "bound_snapshot":bound,"bound_snapshot_sha256":SNAPSHOT_SHA,"worker_executable":worker_exe,"node_sha256":NODE_SHA,
        "worker_sha256":WORKER_SHA,"barrier_version":BARRIER_VERSION,"release_byte_sent":false,"initialize_authorized":false}),
    )?;
    // There is deliberately no affirmative branch in this probe.
    stream.write_all(b"D")?;
    drop(stream);
    let denied = Instant::now();
    let exit = loop {
        if let Some(exit) = child.0.try_wait()? {
            break exit;
        }
        ensure!(
            denied.elapsed() < Duration::from_secs(130),
            "node failed to reap after denial"
        );
        thread::sleep(Duration::from_millis(100));
    };
    ensure!(!exit.success(), "denial unexpectedly succeeded");
    ensure!(
        fs::symlink_metadata(format!("/proc/{worker}"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "worker remains after denial"
    );
    ensure!(
        fs::symlink_metadata(&bound).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "node did not retire its temporary bound snapshot after denial"
    );
    let log = fs::read_to_string(work.join("node.log"))?;
    ensure!(
        log.contains("136 restore release denied"),
        "missing exact production denial diagnostic"
    );
    persist(
        &work.join("PASS.json"),
        &json!({"schema":"horizon-epoch136-native-preinit-result-v1","at":now()?,"node_sha256":NODE_SHA,
        "worker_sha256":WORKER_SHA,"genuine_cli_snapshot_binding_and_hello_reached":true,"denial_returned_nonzero":true,"worker_reaped":true,
        "initialize_release_sent":false,"snapshot_restored":false,"slots_replayed":0,"actual_worker_guard_qualified":false,"publication_authorized":false,
        "note":"This proves the real pre-Initialize route and fail-closed denial. The production guard/payload release and snapshot restoration remain separate gates."}),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 5
            && matches!(
                args[1].as_str(),
                "stage" | "run" | "gate-stage" | "gate-run"
            ),
        "usage: probe stage|run|gate-stage|gate-run WORK REQUEST_PATH REQUEST_SHA256"
    );
    let work = Path::new(&args[2]);
    ensure!(
        work == Path::new(WORK),
        "foreign native probe work generation"
    );
    let unit = if args[1].ends_with("stage") {
        STAGE_UNIT
    } else {
        UNIT
    };
    let parent = release(
        Path::new(&args[3]),
        &args[4],
        unit,
        args[1].starts_with("gate-"),
    )?;
    let result = if args[1].starts_with("gate-") {
        Ok(())
    } else if args[1] == "stage" {
        stage(work)
    } else {
        run(work, &parent)
    };
    if let Err(e) = &result {
        let _ = persist(
            &work.join("FAIL.json"),
            &json!({"schema":"horizon-epoch136-native-preinit-failure-v1","at":now()?,"error":format!("{e:#}"),"initialize_authorized":false}),
        );
    }
    result
}

#[cfg(test)]
mod owner_tests {
    use super::*;
    #[test]
    fn a_terminal_fleet_requires_the_bound_closure_and_drained_actor() {
        let mut f = json!({"actual_active_private_diagnostics": [{"epoch":168}], "terminal172_closure": {"sha256": "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7"}});
        assert!(verify_172(&f, "failed", "0", "5a691c24655a4ff489531d8d7cc50254").is_ok());
        assert!(verify_172(&f, "active", "2823601", "5a691c24655a4ff489531d8d7cc50254").is_err());
        f["terminal172_closure"] = Value::Null;
        assert!(verify_172(&f, "inactive", "0", "").is_err());
    }
}
