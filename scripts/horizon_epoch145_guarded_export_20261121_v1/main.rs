//! Epoch 145 private export. The supervising process enforces the shared phase
//! lock, native resource fit and worker lifetime in one capped systemd unit.
#[allow(dead_code)]
#[path = "../horizon_epoch145_private_prefix_v8/custody.rs"]
mod custody;
#[path = "../../jetstreamer-node/src/epoch145_extract.rs"]
mod epoch145_extract;
#[allow(dead_code)]
#[path = "../horizon_epoch145_private_prefix_v8/model.rs"]
mod model;
#[allow(dead_code)]
#[path = "../horizon_epoch145_private_prefix_v8/native.rs"]
mod native;
pub use jetstreamer_node::{archive_checksum, segment_manifest};
mod capacity;
mod closed166;
mod continuity;
#[cfg(early145_only)]
mod early166;
#[cfg(incident145_only)]
mod incident145;
#[cfg(incident145_only)]
mod incident_fit;
mod joint;
mod joint_candidate;
mod joint_worker;
mod materialized;
mod partial;
mod peer_terminal;
mod post;
mod publication;
#[cfg(any(publication166_only, test))]
mod publication_fit166;
mod publication_tree;
mod recover;
mod source_lease;
mod stable;

use anyhow::{Context, Result, ensure};
use capacity::{BYTES, RUNTIME, UNIT};
use model::{
    Bound, MANIFEST, MANIFEST_SHA, SOURCE, SOURCE_BYTES, SOURCE_SHA, WITNESS, WITNESS_SHA,
};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};
const HOLDING_LOCK: &str =
    "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock";
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch145-guarded-export-20261121-v1";
const OUTPUT: &str = "/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1";
static LAST: AtomicU64 = AtomicU64::new(0);

fn privilege() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    Ok(())
}
fn verify_cgroup() -> Result<String> {
    let cg = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        cg.trim() == format!("0::/system.slice/{UNIT}"),
        "wrong execution service"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    let parts = fs::read_to_string(group.join("cpu.max"))?;
    let cpu = parts
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<Vec<u64>, _>>()?;
    ensure!(
        cpu.len() == 2
            && cpu[0] > 0
            && cpu[0] == cpu[1]
            && fs::read_to_string(group.join("memory.max"))?.trim() == "2147483648"
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(group.join("pids.max"))?.trim() == "128",
        "execution cgroup bounds"
    );
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(custody::hex(&iid, 32), "wrong invocation");
    Ok(iid)
}
fn check_self(sha: &str) -> Result<()> {
    check_image(sha, &Path::new(BASE).join("deployment-v4/export145"))
}
fn check_image(sha: &str, path: &Path) -> Result<()> {
    privilege()?;
    let this = fs::metadata("/proc/self/exe")?;
    let disk = fs::metadata(&path)?;
    ensure!(
        this.dev() == disk.dev() && this.ino() == disk.ino(),
        "unsealed image"
    );
    custody::bytes(
        &Bound {
            path: path.to_owned(),
            sha256: sha.to_owned(),
        },
        64 << 20,
        true,
    )?;
    let seal_path = path.parent().unwrap().join("deployment-seal-receipt.json");
    let seal_identity = custody::frozen_identity(&seal_path)?;
    ensure!(seal_identity.bytes < 1 << 20, "oversized deployment seal");
    let seal = custody::json(
        &Bound {
            sha256: custody::sha(&fs::read(&seal_path)?),
            path: seal_path,
        },
        true,
    )?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == path.parent().unwrap().to_str().unwrap()
            && seal["members"].as_array().is_some_and(|r| r
                .iter()
                .any(|v| v["name"] == "export145" && v["sha256"] == sha && v["mode"] == "0555")),
        "normal production seal"
    );
    Ok(())
}
fn lock() -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(HOLDING_LOCK)?;
    let m = f.metadata()?;
    let named = fs::symlink_metadata(HOLDING_LOCK)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o777 == 0o600
            && m.nlink() == 1
            && m.dev() == 64512
            && m.ino() == 95818311
            && named.ino() == m.ino()
            && named.dev() == m.dev(),
        "wrong holding lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "holding phase is occupied"
    );
    Ok(f)
}
fn source_identity() -> Result<()> {
    native::original()?;
    let w = custody::evidence(&Bound {
        path: WITNESS.into(),
        sha256: WITNESS_SHA.into(),
    })?;
    let m = custody::frozen_identity(Path::new(SOURCE))?;
    ensure!(
        w["original_IID"] == model::ORIGINAL_IID
            && w["original_PID1_success_event"]["_PID"] == "1"
            && w["original_PID1_success_event"]["UNIT"] == model::ORIGINAL_UNIT
            && w["producer_recorded_archive_sha256"] == SOURCE_SHA
            && w["archive"]["path"] == SOURCE
            && w["archive"]["device"] == m.device
            && w["archive"]["inode"] == m.inode
            && w["archive"]["mtime_ns"].as_i64().map(i128::from) == Some(m.mtime_ns)
            && m.bytes == SOURCE_BYTES
            && w["producer_segment_manifest"]["path"] == MANIFEST
            && w["producer_segment_manifest"]["sha256"] == MANIFEST_SHA,
        "historical source generation"
    );
    custody::bytes(
        &Bound {
            path: MANIFEST.into(),
            sha256: MANIFEST_SHA.into(),
        },
        1 << 20,
        true,
    )?;
    let retired = custody::evidence(&Bound {
        path: Path::new(RUNTIME)
            .join("held141-collection-retirement-20261120-v1/ACTUAL_LOCAL_RETIREMENT.json"),
        sha256: "e95f3b627ec8be3acb5889deb1632c2dc5ca2ce920e2b5db4e0ec0d0f4c8eba1".into(),
    })?;
    ensure!(
        retired["allocated_member_bytes"] == 539_456_057_344u64
            && retired["actual_native_completion"]["sha256"]
                == "fb1a3b6dd316201bbc985ec2b13ab137fb2653007b47bee86cd4fc888a49974e",
        "141 retirement changed"
    );
    Ok(())
}
fn pending() -> Result<()> {
    let s = capacity::run(
        "/usr/bin/systemctl",
        &["list-jobs", "--no-pager", "--no-legend", "--output=json"],
        "8",
    )?;
    for line in s.lines().filter(|l| !l.trim().is_empty()) {
        let u = line.split_whitespace().nth(1).context("native job row")?;
        ensure!(
            u == UNIT
                || !(u.starts_with("horizon-")
                    && ["holding", "held141", "-park", "-census"]
                        .iter()
                        .any(|k| u.contains(k))),
            "waiting holding task: {u}"
        );
    }
    Ok(())
}
fn existing_directories() -> Result<(PathBuf, PathBuf)> {
    let state = Path::new(BASE).join("state");
    let out = PathBuf::from(OUTPUT);
    custody::private_directory(&state)?;
    custody::private_directory(&out)?;
    ensure!(
        fs::metadata(&state)?.dev() == 64512 && fs::metadata(&out)?.dev() == 64512,
        "data outside HOME"
    );
    Ok((state, out))
}
fn freeze(pid: u32) -> Result<()> {
    ensure!(
        unsafe { libc::kill(pid.try_into()?, libc::SIGSTOP) } == 0,
        "stop private worker"
    );
    let start = Instant::now();
    loop {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
        if status
            .lines()
            .any(|l| l.starts_with("State:") && l.split_whitespace().nth(1) == Some("T"))
        {
            return Ok(());
        }
        ensure!(
            start.elapsed() < Duration::from_secs(2),
            "private worker did not stop"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
// A slow PID1 census may block during unit reload. Only retry its explicit
// timeout (or pending fresh disk measurement) after the isolated worker has
// reached a kernel stop. Never accept a changed topology, resource deficit
// or any other command failure as an observation.
fn prove_stopped_child(pid: u32, ticks: u64) -> Result<()> {
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    ensure!(
        native::ticks(pid)? == ticks
            && status
                .lines()
                .any(|line| line.starts_with("State:")
                    && line.split_whitespace().nth(1) == Some("T"))
            && status.lines().any(|line| line.starts_with("PPid:")
                && line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|p| p.parse::<u32>().ok())
                    == Some(std::process::id())),
        "stopped child identity or state changed"
    );
    Ok(())
}
fn while_stopped(
    pid: u32,
    ticks: u64,
    mut deadline: Instant,
    mut observe: impl FnMut() -> Result<Value>,
) -> Result<Value> {
    #[cfg(incident_missed_clock145_only)]
    let mut pending_until: Option<(incident_fit::missed_clock::Pending, Instant)> = None;
    loop {
        #[cfg(incident_missed_clock145_only)]
        if let Some((_, limit)) = &pending_until {
            ensure!(Instant::now() < *limit, "missed RSS replacement hard deadline");
        }
        // Leave room for the complete 10s census and timeout's 2s kill bound.
        ensure!(
            deadline.saturating_duration_since(Instant::now()) >= Duration::from_secs(12),
            "stopped worker fresh-census deadline"
        );
        prove_stopped_child(pid, ticks)?;
        match observe() {
            Ok(sample) => {
                #[cfg(incident_missed_clock145_only)]
                if let Some((held, limit)) = &pending_until {
                    held.confirm(&sample)?;
                    ensure!(Instant::now() <= *limit && custody::now()? <= held.deadline, "late replacement price");
                    incident_fit::missed_clock::stopped_leases(pid, ticks)?;
                }
                ensure!(
                    cfg!(any(incident_rejoin145_only, incident_post145_only))
                        || Instant::now() < deadline,
                    "late stopped-worker observation"
                );
                prove_stopped_child(pid, ticks)?;
                return Ok(sample);
            }
            #[cfg(incident_missed_clock145_only)]
            Err(e) if e.is::<incident_fit::missed_clock::Pending>() => {
                let hold = e.downcast_ref::<incident_fit::missed_clock::Pending>().unwrap();
                let utc = hold.deadline;
                let now = custody::now()?;
                ensure!(utc > now && utc - now <= 2400, "invalid single replacement deadline");
                let (original, limit) = pending_until.get_or_insert_with(|| (hold.clone(), Instant::now() + Duration::from_secs(utc - now)));
                ensure!(hold == original && Instant::now() < *limit, "registered replacement changed");
                incident_fit::missed_clock::stopped_leases(pid, ticks)?;
                thread::sleep(Duration::from_secs(5));
                deadline = *limit;
            }
            Err(e)
                if (cfg!(continuity145_only) && e.is::<peer_terminal::Pending>())
                    || (cfg!(any(incident_rejoin145_only, incident_post145_only))
                        && (e.is::<capacity::Reprice>()
                            || e.is::<capacity::TopologyTimeout>())) =>
            {
                eprintln!("epoch145 holding stopped verifier {pid}: {e}");
                thread::sleep(if cfg!(test) {
                    Duration::from_millis(20)
                } else {
                    Duration::from_secs(10)
                });
                deadline = Instant::now() + Duration::from_secs(90);
            }
            Err(e)
                if e.is::<capacity::TopologyTimeout>()
                    || e.is::<capacity::GuardInFlight>()
                    || e.is::<capacity::Reprice>() =>
            {
                eprintln!("epoch145 waiting with worker {pid} stopped: {e:#}");
                thread::sleep(Duration::from_secs(1));
            }
            Err(e) => return Err(e),
        }
    }
}
fn allocate(root: &Path, bytes: u64, minimum: u64) -> Result<tempfile::NamedTempFile> {
    let before = capacity::home()?.0;
    let rounded = bytes.div_ceil(4096) * 4096;
    ensure!(
        before >= minimum.checked_add(rounded).context("preallocation size")?,
        "insufficient free space before preallocation"
    );
    let t = tempfile::NamedTempFile::new_in(root)?;
    let len = i64::try_from(bytes)?;
    let rc = unsafe { libc::fallocate(t.as_file().as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, 0, len) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("reserve single canonical inode");
    }
    t.as_file().sync_all()?;
    let m = t.as_file().metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.len() == 0
            && m.blocks() * 512 >= rounded
            && capacity::home()?.0 >= minimum,
        "physical reservation or peer floor lost"
    );
    Ok(t)
}
fn readline() -> Result<String> {
    let mut s = String::new();
    ensure!(
        std::io::stdin().lock().read_line(&mut s)? <= 4096 && !s.is_empty(),
        "missing supervisor barrier"
    );
    Ok(s)
}
fn child(sha: &str, parent: u32, lock_fd: i32) -> Result<()> {
    check_self(sha)?;
    let iid = verify_cgroup()?;
    let p = unsafe { libc::getppid() } as u32;
    ensure!(p == parent && p > 1, "wrong supervisor");
    let a = fs::metadata(format!("/proc/{p}/exe"))?;
    let b = fs::metadata("/proc/self/exe")?;
    let k = fs::metadata(format!("/proc/self/fd/{lock_fd}"))?;
    ensure!(
        a.dev() == b.dev() && a.ino() == b.ino() && k.dev() == 64512 && k.ino() == 95818311,
        "supervisor or lock descriptor changed"
    );
    // This is the same open-file description held by the guard from before
    // fork. Its flock survives if either process exits before the other.
    ensure!(
        unsafe { libc::flock(lock_fd, libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "inherited lock"
    );
    let (state, out) = existing_directories()?;
    let state = state.join(&iid);
    let v: Value = serde_json::from_str(&readline()?)?;
    ensure!(
        v["iid"] == iid
            && v["pid"] == std::process::id()
            && v["parent"] == parent
            && v["bytes"] == BYTES,
        "guard release crossed"
    );
    let floor = capacity::n(&v, "protected")?;
    source_lease::arm_break_signal()?;
    let lease = |s: &str| -> Result<_> {
        let path = Path::new(s);
        let id = source_lease::FileIdentity::from(&fs::symlink_metadata(path)?);
        source_lease::ReadLease::acquire(path, id)
    };
    let archive = lease(SOURCE)?;
    let manifest = lease(MANIFEST)?;
    let t = match recover::predecessor(&out)? {
        Some(p) => {
            ensure!(
                v["reused"] == p.to_str().unwrap(),
                "crossed predecessor release"
            );
            recover::open(&p)?
        }
        None => {
            ensure!(v["reused"].is_null(), "missing previously allocated output");
            allocate(&out, BYTES, floor)?
        }
    };
    let m = t.as_file().metadata()?;
    custody::write_new(
        &state.join("allocated.json"),
        &json!({"iid":iid,"pid":std::process::id(),"device":m.dev(),"inode":m.ino(),"allocated_bytes":m.blocks()*512,"logical_bytes":m.len(),"temporary":t.path()}),
    )?;
    let ready: Value = serde_json::from_str(&readline()?)?;
    ensure!(
        ready["iid"] == iid && ready["inode"] == m.ino() && ready["pid"] == std::process::id(),
        "missing post-allocation guard"
    );
    archive.check()?;
    manifest.check()?;
    let msha = decode_sha(MANIFEST_SHA)?;
    eprintln!("authenticating retained epoch 145 source, {SOURCE_BYTES} bytes");
    let mut source = epoch145_extract::PinnedSource::open(
        Path::new(SOURCE),
        Path::new(MANIFEST),
        msha,
        epoch145_extract::PINNED_WORKER_SHA256,
    )?;
    archive.check()?;
    manifest.check()?;
    custody::write_new(
        &state.join("source-validated.json"),
        &json!({"iid":iid,"at":custody::now()?,"archive_sha256":SOURCE_SHA,"manifest_sha256":MANIFEST_SHA}),
    )?;
    let extraction = source.extract_private_with_temporary(&out, BYTES, Some(t), |next| {
        archive
            .check()
            .and_then(|_| manifest.check())
            .map_err(std::io::Error::other)?;
        if next > BYTES {
            return Err(std::io::Error::other("private output bound"));
        }
        let previous = LAST.load(Ordering::Relaxed);
        if next.saturating_sub(previous) >= 1 << 30 {
            eprintln!("canonical epoch 145 encoded {next}/{BYTES} bytes");
            LAST.store(next, Ordering::Relaxed);
        }
        Ok(())
    })?;
    ensure!(
        extraction.archive_bytes == BYTES
            && extraction.independent_output_reread_passed
            && extraction.source_archive_sha256 == SOURCE_SHA
            && extraction.output_slot_count == 432000
            && !extraction.publication_authorized,
        "private output contract"
    );
    archive.check()?;
    manifest.check()?;
    custody::write_new(
        &state.join("extraction-complete.json"),
        &json!({"schema":"horizon-epoch145-guarded-private-prefix-completion-v1","actor_iid":iid,"at_unix_seconds":custody::now()?,"extraction":extraction,
    "archive_publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
fn decode_sha(s: &str) -> Result<[u8; 32]> {
    ensure!(custody::hex(s, 64), "digest syntax");
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}
fn supervise(fleet: Bound, sha: &str, execute: bool) -> Result<()> {
    check_self(sha)?;
    let iid = verify_cgroup()?;
    let lock = lock()?;
    pending()?;
    source_identity()?;
    let (state, out) = existing_directories()?;
    let predecessor = recover::predecessor(&out)?;
    let needed = if predecessor.is_some() {
        0
    } else {
        capacity::output_allocation()
    };
    let fit = capacity::capture(&fleet)?;
    fit.topology()?;
    let initial = fit.await_current(needed)?;
    if !execute {
        println!(
            "{}",
            json!({"fit":fit.evidence,"initial":initial,"stage":"private preflight"})
        );
        return Ok(());
    }
    let state = state.join(&iid);
    fs::DirBuilder::new().mode(0o700).create(&state)?;
    let x = std::process::id();
    let fd = lock.as_raw_fd();
    let mut command = Command::new("/proc/self/exe");
    command
        .args(["worker", sha, &x.to_string(), &fd.to_string()])
        .stdin(Stdio::piped());
    // Kill a worker whose supervising native guard dies, including the race
    // between fork and installing the parent-death signal.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() as u32 != x
                || libc::fcntl(fd, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::other("lost supervisor or lock"));
            }
            Ok(())
        });
    }
    let mut worker = command.spawn()?;
    let pid = worker.id();
    let mut input = worker.stdin.take().context("worker barrier")?;
    let guard = (|| -> Result<()> {
        let sample = fit.await_current(needed)?;
        pending()?;
        let ticks = native::ticks(pid)?;
        let release = json!({"iid":iid,"parent":x,"pid":pid,"start_ticks":ticks,"bytes":BYTES,"reused":predecessor,"protected":sample["protected_bytes"]});
        custody::write_new(
            &state.join("first-guard.json"),
            &json!({"time":custody::now()?,"fit":fit.evidence,"sample":sample,"barrier":release}),
        )?;
        writeln!(input, "{release}")?;
        input.flush()?;
        let start = Instant::now();
        let allocation = loop {
            let p = state.join("allocated.json");
            if p.try_exists()? {
                break custody::evidence(&custody::binding(&p)?)?;
            }
            ensure!(
                worker.try_wait()?.is_none() && start.elapsed() < Duration::from_secs(120),
                "worker failed or timed out in allocation"
            );
            thread::sleep(Duration::from_millis(100));
        };
        let temp = Path::new(allocation["temporary"].as_str().context("temporary path")?);
        let m = fs::symlink_metadata(temp)?;
        ensure!(
            temp.parent() == Some(out.as_path())
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.blocks() * 512 >= capacity::output_allocation()
                && allocation["device"] == m.dev()
                && allocation["inode"] == m.ino()
                && allocation["pid"] == pid
                && allocation["iid"] == iid,
            "wrong allocated inode"
        );
        fit.topology()?;
        let a = fit.await_current(0)?;
        let post = json!({"iid":iid,"pid":pid,"inode":m.ino(),"sample":a,"at":custody::now()?});
        custody::write_new(&state.join("post-allocation-guard.json"), &post)?;
        writeln!(input, "{post}")?;
        input.flush()?;
        drop(input);
        let mut last = Instant::now();
        loop {
            if let Some(status) = worker.try_wait()? {
                ensure!(status.success(), "private exporter exited {status}");
                break;
            }
            ensure!(
                start.elapsed() < Duration::from_secs(72 * 3600),
                "export execution deadline expired"
            );
            let guard_wait = match fit.current(0) {
                Ok(_) => false,
                Err(e) if e.is::<capacity::GuardInFlight>() => true,
                Err(e) => return Err(e),
            };
            if guard_wait || last.elapsed() >= Duration::from_secs(30) {
                if let Err(e) = freeze(pid) {
                    if worker.try_wait()?.is_some_and(|s| s.success()) {
                        break;
                    }
                    return Err(e);
                }
                let sample =
                    while_stopped(pid, ticks, Instant::now() + Duration::from_secs(90), || {
                        fit.topology().and_then(|_| fit.current(0))
                    })?;
                ensure!(
                    unsafe { libc::kill(pid.try_into()?, libc::SIGCONT) } == 0,
                    "resume private worker"
                );
                println!("{} epoch145 guard {}", custody::now()?, sample);
                last = Instant::now();
            }
            thread::sleep(Duration::from_secs(3));
        }
        let receipt =
            custody::evidence(&custody::binding(&state.join("extraction-complete.json"))?)?;
        ensure!(
            receipt["actor_iid"] == iid && receipt["extraction"]["archive_bytes"] == BYTES,
            "missing worker completion"
        );
        custody::write_new(
            &state.join("complete.json"),
            &json!({"iid":iid,"at":custody::now()?,"receipt":custody::binding(&state.join("extraction-complete.json"))?,"r2_mutations":false}),
        )?;
        Ok(())
    })();
    if let Err(err) = &guard {
        let _ = worker.kill();
        let _ = worker.wait();
        let _ = custody::write_new(
            &state.join("failed.json"),
            &json!({"iid":iid,"at":custody::now()?,"error":format!("{err:#}")}),
        );
    }
    guard
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch145: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(publication166_only)]
fn run() -> Result<()> {
    privilege()?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [path, digest] = args.as_slice() else {
        anyhow::bail!("usage: publication-fit ROOT_FLEET SHA256")
    };
    let result = publication_fit166::measure(&Bound {
        path: path.into(),
        sha256: digest.clone(),
    })?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
#[cfg(not(publication166_only))]
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    match a.as_slice() {
        #[cfg(incident_v5y_guard_recovery145_only)]
        [_, mode, sha] if mode == "check-recovery-custody" => materialized::check_recovery_custody(sha),
        #[cfg(incident_five_lane145_only)]
        [_, mode, fleet, digest, sha] if mode == "check-serial-handback" => {
            incident_fit::preflight(
                Bound {
                    path: fleet.into(),
                    sha256: digest.clone(),
                },
                sha,
            )
        }
        #[cfg(all(partial145_only, not(joint145_only), not(continuity145_only)))]
        [_, mode, parent, sha] if mode == "recover-append" => partial::append(parent.parse()?, sha),
        #[cfg(all(materialized145_only, not(joint145_only), not(incident_post145_only)))]
        [_, mode, fleet, digest, sha] if mode == "recover-full-output" => materialized::run(
            Bound {
                path: fleet.into(),
                sha256: digest.clone(),
            },
            sha,
        ),
        #[cfg(all(materialized145_only, not(joint145_only), not(incident_post145_only)))]
        [_, mode, parent, sha] if mode == "recover-worker" => {
            materialized::verify(parent.parse()?, sha)
        }
        #[cfg(any(not(materialized145_only), joint145_only))]
        [_, mode, fleet, digest, sha, tail @ ..] if mode == "joint-fit" => joint::inspect(
            Bound {
                path: fleet.into(),
                sha256: digest.clone(),
            },
            sha,
            tail,
        ),
        #[cfg(any(not(incident145_only), incident_post145_only))]
        [_, mode, path, digest, full, sha] if mode == "publish" => publication::publish(
            Bound {
                path: path.into(),
                sha256: digest.clone(),
            },
            full,
            sha,
            cfg!(joint145_only),
        ),
        #[cfg(any(not(incident145_only), incident_post145_only))]
        [_, mode, path, digest, sha] if mode == "post-full" => post::full(
            Bound {
                path: path.into(),
                sha256: digest.clone(),
            },
            sha,
            cfg!(joint145_only),
        ),
        #[cfg(not(any(joint145_only, materialized145_only)))]
        [_, mode, sha, parent, fd] if mode == "worker" => child(sha, parent.parse()?, fd.parse()?),
        #[cfg(not(any(joint145_only, materialized145_only)))]
        [_, mode, path, digest, sha] if mode == "preflight" || mode == "run" => supervise(
            Bound {
                path: path.into(),
                sha256: digest.clone(),
            },
            sha,
            mode == "run",
        ),
        _ => anyhow::bail!("usage: export145 preflight|run FLEET FLEET_SHA SELF_SHA"),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_scan_holds_only_the_owned_worker() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let r = freeze(pid);
        unsafe {
            libc::kill(pid as i32, libc::SIGCONT);
        }
        child.kill().unwrap();
        child.wait().unwrap();
        r.unwrap();
    }
    #[test]
    fn stopped_child_retries_only_proved_transients_and_obeys_its_deadline() {
        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let ticks = native::ticks(pid).unwrap();
        freeze(pid).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut calls = 0;
        let sample = while_stopped(pid, ticks, deadline, || {
            calls += 1;
            if calls == 1 {
                return Err(capacity::TopologyTimeout.into());
            }
            Ok(json!({"positive_fit":true}))
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(sample["positive_fit"], true);
        #[cfg(incident_rejoin145_only)]
        {
            let mut attempts = 0;
            let held = while_stopped(pid, ticks, deadline, || {
                attempts += 1;
                if attempts < 3 {
                    return Err(capacity::Reprice("test HOME 90/100".into()).into());
                }
                Ok(json!({"positive_fit":true}))
            })
            .unwrap();
            assert_eq!(attempts, 3);
            assert_eq!(held["positive_fit"], true);
        }
        #[cfg(incident_timeout145_only)]
        {
            let mut attempts = 0;
            while_stopped(pid, ticks, deadline, || {
                prove_stopped_child(pid, ticks)?;
                attempts += 1;
                if attempts <= 2 {
                    return Err(capacity::TopologyTimeout.into());
                }
                Ok(json!({"positive_fit":true}))
            })
            .unwrap();
            assert_eq!(attempts, 3);
            prove_stopped_child(pid, ticks).unwrap();
        }
        let mut failures = 0;
        assert!(
            while_stopped(pid, ticks, deadline, || {
                failures += 1;
                anyhow::bail!("distinct replay owner")
            })
            .is_err()
        );
        assert_eq!(failures, 1);
        assert!(while_stopped(pid, ticks, Instant::now(), || panic!("expired")).is_err());
        assert!(while_stopped(pid, ticks + 1, deadline, || panic!("wrong child")).is_err());
        assert!(
            fs::read_to_string(format!("/proc/{pid}/status"))
                .unwrap()
                .contains("State:\tT")
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }
    #[test]
    fn reservation_is_physical_without_extending_logical_eof() {
        let t = tempfile::tempdir().unwrap();
        let f = allocate(t.path(), 65537, 0).unwrap();
        let m = f.as_file().metadata().unwrap();
        assert_eq!(m.len(), 0);
        assert!(m.blocks() * 512 >= 69632);
    }
    #[test]
    fn invalid_floor_rejects_before_creating_a_file() {
        let t = tempfile::tempdir().unwrap();
        assert!(allocate(t.path(), 65537, u64::MAX).is_err());
        assert!(fs::read_dir(t.path()).unwrap().next().is_none());
    }
    #[test]
    fn exact_budget_and_hash() {
        assert_eq!(capacity::output_allocation(), 105610997760);
        assert!(decode_sha(MANIFEST_SHA).is_ok());
        assert!(decode_sha("bad").is_err());
    }
}
