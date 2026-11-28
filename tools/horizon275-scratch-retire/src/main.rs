//! Retire individually qualified files and AccountsDb trees from stopped workers.
mod accounts229_bundle;
mod appendvec229;
mod appendvec288;
mod appendvec292;
mod appendvec292_bundle;
mod ext4_228;
mod failed296_bundle;
mod index230;
mod interval141;
mod parked_accounts;
#[path = "../../../scripts/horizon_standard_backfill_scratch_retirement_20261110_v1/source/process_references.rs"]
mod process_references;
mod selective_accounts;
mod snapshot230;
mod snapshot230_window;
mod snapshot266;
mod snapshot288;
mod snapshot296;
mod stopped_bootstrap;
#[path = "../../../scripts/horizon_standard_backfill_scratch_retirement_20261110_v1/source/stopped_tree.rs"]
mod stopped_tree;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, Metadata, OpenOptions},
    io::{self, BufReader, BufWriter, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

const CUSTODY: &str = "/var/lib/jetstreamer/horizon275-stopped-worker-custody-v317/completion.json";
const CUSTODY_SHA: &str = "ea9ae30533968115e998580028a8c77faf7358329bef20bf57bec45ee26ceb72";
const CENSUS: &str =
    "/var/lib/jetstreamer/horizon275-stopped-worker-custody-v317/accounts-state-census.json";
const CENSUS_SHA: &str = "c85c0ec5e658aab3a7a553c313222520cf3da0e61899e250ee081fbe172b414e";
const PROFILE: &str = "/var/lib/jetstreamer/horizon275-full-v301-a2/profile.json";
const PROFILE_SHA: &str = "906d455cbdbad8a0d187e2d69d1983ff42516dee3796197fb916e1f9cb242cb0";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon275-accounts-state-retirement-v318";
const UNIT: &str = "horizon-qualify-275-root-singleton-v301.service";
const GUARD: &str = "horizon-275-full-protective-v301.service";
const TIMER: &str = "horizon-275-full-protective-v301.timer";
const INVOCATION: &str = "356b1b94bd19492abc2085991a99aa35";
const CYCLE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const LOCAL_LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const SCANNER: &str =
    "/home/ubuntu/.codex/diagnostics/horizon248-retirement-preflight-v233-a1/scheduled-readers.py";
const SCANNER_SHA: &str = "37658a5146f2e09bd50927cb5d07cb75cdbb129a237513d5fdec2901c524ef64";
const JSON_LIMIT: u64 = 4 << 20;
const LEDGER_LIMIT: u64 = 384 << 20;

#[derive(Deserialize, Serialize)]
struct Binding {
    path: PathBuf,
    sha256: String,
}

fn identity(m: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
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

fn digest(reader: &mut impl Read) -> Result<String> {
    let mut hash = Sha256::new();
    io::copy(reader, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

fn open_regular(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical file"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NOATIME)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && identity(&m) == identity(&path.symlink_metadata()?),
        "unexpected file identity"
    );
    Ok(f)
}

fn read_bound<T: serde::de::DeserializeOwned>(
    path: &Path,
    expected: &str,
    limit: u64,
) -> Result<T> {
    let mut f = open_regular(path)?;
    let m = f.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= limit,
        "unsafe proof: {}",
        path.display()
    );
    ensure!(
        digest(&mut (&mut f).take(limit + 1))? == expected,
        "proof digest changed: {}",
        path.display()
    );
    use io::Seek as _;
    f.rewind()?;
    let result = serde_json::from_reader(BufReader::new(&f))?;
    ensure!(
        identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&path.symlink_metadata()?),
        "proof changed while read"
    );
    Ok(result)
}

fn value(binding: &Value) -> Result<Value> {
    let b: Binding = serde_json::from_value(binding.clone())?;
    ensure!(
        b.path.starts_with("/var/lib/jetstreamer"),
        "foreign evidence"
    );
    read_bound(&b.path, &b.sha256, JSON_LIMIT)
}

fn write_json(path: &Path, payload: &impl Serialize) -> Result<Binding> {
    let f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o400)
        .open(path)?;
    let mut writer = BufWriter::new(f);
    serde_json::to_writer(&mut writer, payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(Binding {
        path: path.into(),
        sha256: digest(&mut open_regular(path)?)?,
    })
}

fn lock(path: &str) -> Result<File> {
    let f = open_regular(Path::new(path))?;
    let m = f.metadata()?;
    ensure!(
        matches!(m.uid(), 0 | 1000) && m.mode() & 0o077 == 0,
        "unexpected lock owner or mode"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock busy: {path}"
    );
    Ok(f)
}

fn terminal_unit(unit: &str) -> Result<()> {
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "Id,ActiveState,MainPID,ControlPID,ControlGroup,Job,InvocationID",
        ])
        .output()?;
    ensure!(output.status.success(), "could not inspect {unit}");
    let text = String::from_utf8(output.stdout)?;
    for required in [
        format!("Id={unit}"),
        "ActiveState=inactive".into(),
        "Job=".into(),
    ] {
        ensure!(
            text.lines().any(|line| line == required),
            "{unit} is not drained"
        );
    }
    for line in text.lines() {
        if let Some((key, value)) = line.split_once('=') {
            match key {
                "MainPID" | "ControlPID" => ensure!(value == "0", "{unit} still owns a PID"),
                "ControlGroup" => ensure!(value.is_empty(), "{unit} still owns a cgroup"),
                "InvocationID" if unit == UNIT => ensure!(
                    value.is_empty() || value == INVOCATION,
                    "foreign producer invocation"
                ),
                _ => (),
            }
        }
    }
    Ok(())
}

fn scheduled(scope: &Path, target: &Path) -> Result<Value> {
    let v = scheduled_census(scope, target)?;
    ensure!(
        v["remaining"] == json!([]),
        "scheduled scratch reference appeared: {v}"
    );
    Ok(v)
}

fn scheduled_census(scope: &Path, target: &Path) -> Result<Value> {
    // Invoke the existing scheduled-reader scanner with the original run's
    // path boundary. Keep the literal target out of the caller's argv.
    let code = r#"import hashlib,json,sys
from pathlib import Path
path=Path(sys.argv[1]); raw=path.read_bytes()
assert hashlib.sha256(raw).hexdigest()==sys.argv[2]
old=b'roots=[p.parents[1] for p in targets]'; assert raw.count(old)==1
ns={'EXACT_RUN_ROOT':Path(sys.argv[3]),'__name__':'scheduled_census'}
exec(compile(raw.replace(old,b'roots=[EXACT_RUN_ROOT for p in targets]'),str(path),'exec'),ns)
ns['TARGETS']=[sys.argv[4]]
print(json.dumps(ns['scan']()))"#;
    let output = Command::new("/usr/bin/python3")
        .args(["-B", "-c", code, SCANNER, SCANNER_SHA])
        .arg(scope)
        .arg(target)
        .output()?;
    ensure!(
        output.status.success(),
        "scheduled reader scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout)?;
    ensure!(
        v["files"].as_u64().is_some_and(|n| n > 0)
            && v["inspected_command_sources"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && v["remaining"].is_array()
            && v["unresolved"] == json!([]),
        "scheduled scratch reference appeared: {v}"
    );
    Ok(v)
}

fn assert_no_nested_mount(target: &Path) -> Result<()> {
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mounts.lines() {
        let mount = line
            .split_ascii_whitespace()
            .nth(4)
            .context("missing mountpoint")?;
        ensure!(
            !Path::new(mount).starts_with(target),
            "mount under retired scratch"
        );
    }
    Ok(())
}

fn available(path: &Path) -> Result<u64> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};
    let c = CString::new(path.as_os_str().as_bytes())?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let s = unsafe { s.assume_init() };
    s.f_bavail.checked_mul(s.f_frsize).context("space overflow")
}

fn retire_bootstrap(
    receipts: &Path,
    scope: &Path,
    target: &Path,
    source: &Path,
    snapshot: &Value,
    self_sha: &str,
) -> Result<()> {
    let previous: Value = read_bound(
        &receipts.join("completion.json"),
        "afd0e7d1ab808916f91b1aec31fe71196360207765eaf3dccc1dab2c9f0f922e",
        JSON_LIMIT,
    )?;
    ensure!(
        previous["empty_root_retained"] == true,
        "AccountsDb retirement is not closed"
    );
    let parent = target
        .parent()
        .and_then(Path::parent)
        .context("missing retired run parent")?
        .join("bound-bootstrap");
    let name = source.file_name().context("missing bootstrap name")?;
    let copy = parent.join(name);
    ensure!(
        copy.starts_with(scope) && parent.canonicalize()? == parent && copy != source,
        "wrong bootstrap copy scope"
    );
    let mut retained = open_regular(source)?;
    let mut candidate = open_regular(&copy)?;
    let keep = retained.metadata()?;
    let remove = candidate.metadata()?;
    let expected = snapshot["sha256"]
        .as_str()
        .context("missing bootstrap hash")?;
    ensure!(
        identity(&keep) != identity(&remove)
            && keep.uid() == 0
            && keep.mode() & 0o222 == 0
            && remove.uid() == 1000
            && snapshot["bytes"] == keep.len()
            && keep.len() == remove.len()
            && digest(&mut retained)? == expected
            && digest(&mut candidate)? == expected,
        "bootstrap copy and sealed input differ"
    );
    for unit in [UNIT, GUARD, TIMER] {
        terminal_unit(unit)?;
    }
    assert_no_nested_mount(&copy)?;
    let schedule = scheduled(scope, &copy)?;
    let consumers = process_references::scan(Path::new("/proc"), &copy)?;
    ensure!(
        consumers.inspected_processes > 0 && consumers.references.is_empty(),
        "live bootstrap-copy references"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&parent)?;
    let relative = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join(name);
    let stable = |a: &Metadata, opened: &File, pathname: &Path| -> Result<bool> {
        Ok(identity(a) == identity(&opened.metadata()?)
            && identity(a) == identity(&pathname.symlink_metadata()?))
    };
    ensure!(
        stable(&remove, &candidate, &relative)? && stable(&keep, &retained, source)?,
        "bootstrap identity changed"
    );
    let removed_bytes = remove
        .blocks()
        .checked_mul(512)
        .context("bootstrap allocation overflow")?;
    let free_before = available(scope)?;
    let intent = write_json(
        &receipts.join("bootstrap-intent.json"),
        &json!({
            "copy":copy,"device":remove.dev(),"inode":remove.ino(),"sha256":expected,"retained_snapshot":snapshot,
            "self_sha256":self_sha,"allocated_bytes":removed_bytes,"free_at_attempt_start_bytes":free_before,
            "scheduled":schedule,"consumers":consumers,
        }),
    )?;
    ensure!(
        stable(&remove, &candidate, &relative)? && stable(&keep, &retained, source)?,
        "bootstrap changed after durable intent"
    );
    use std::{ffi::CString, os::unix::ffi::OsStrExt as _};
    let name = CString::new(name.as_bytes())?;
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "unlink bootstrap copy: {}",
        io::Error::last_os_error()
    );
    drop(candidate);
    dir.sync_all()?;
    ensure!(
        copy.symlink_metadata()
            .is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            && stable(&keep, &retained, source)?,
        "bootstrap custody failed after unlink"
    );
    let report = write_json(
        &receipts.join("bootstrap-completion.json"),
        &json!({
            "intent":intent,"allocated_bytes_removed":removed_bytes,"free_after_bytes":available(scope)?,
            "retained_snapshot":snapshot,"r2_mutations":false,
        }),
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if let Some(mode @ ("--drain-interval2-141" | "--drain-interval3-141" | "--drain-interval4-141" | "--drain-interval5-141")) =
        args.get(1).map(String::as_str)
    {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 4,
            "usage: horizon275-scratch-retire {mode} SELF_SHA256 TERMINAL_SHA256"
        );
        let mut binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut binary)? == args[2],
            "unsealed retirement image"
        );
        let ordinal = match mode {
            "--drain-interval2-141" => 2,
            "--drain-interval3-141" => 3,
            "--drain-interval4-141" => 4,
            _ => 5,
        };
        return interval141::drain(ordinal, &args[3]);
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "--check-duplicate-index-230"
                | "--retire-duplicate-index-230"
                | "--check-duplicate-index-230-second"
                | "--retire-duplicate-index-230-second"
        )
    ) {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 3,
            "epoch 230 duplicate-index check or retirement requires exactly SELF_SHA256"
        );
        let mut binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut binary)? == args[2],
            "unsealed retirement image"
        );
        let replay = if args[1].ends_with("-second") {
            &index230::SECOND
        } else {
            &index230::FIRST
        };
        return index230::run(replay, args[1].starts_with("--retire-"));
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--check-held-failed-296" | "--retire-held-failed-296")
    ) {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 5,
            "usage: horizon275-scratch-retire --check-held-failed-296|--retire-held-failed-296 SELF_SHA256 RECHECK RECHECK_SHA256"
        );
        let mut binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut binary)? == args[2],
            "unsealed retirement image"
        );
        return failed296_bundle::run(
            args[1] == "--retire-held-failed-296",
            Binding { path: args[3].clone().into(), sha256: args[4].clone() },
        );
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--check-held-accounts-229" | "--retire-held-accounts-229")
    ) {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 5,
            "usage: horizon275-scratch-retire --check-held-accounts-229|--retire-held-accounts-229 SELF_SHA256 RECHECK RECHECK_SHA256"
        );
        let mut binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut binary)? == args[2],
            "unsealed retirement image"
        );
        return accounts229_bundle::run(
            args[1] == "--retire-held-accounts-229",
            Binding { path: args[3].clone().into(), sha256: args[4].clone() },
        );
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--check-bootstrap-296" | "--retire-bootstrap-296"
            | "--check-bootstrap-266-114910768" | "--retire-bootstrap-266-114910768"
            | "--check-bootstrap-230-99430284" | "--retire-bootstrap-230-99430284"
            | "--check-bootstrap-230-99437433" | "--retire-bootstrap-230-99437433"
            | "--check-bootstrap-230-99461591" | "--retire-bootstrap-230-99461591"
            | "--check-bootstrap-230-99476782" | "--retire-bootstrap-230-99476782")
    ) {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 5,
            "usage: horizon275-scratch-retire --check-bootstrap-296|--retire-bootstrap-296|--check-bootstrap-230-SLOT|--retire-bootstrap-230-SLOT SELF_SHA256 GENERATION_RECHECK METADATA_SHA256"
        );
        let mut binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut binary)? == args[2],
            "unsealed retirement image"
        );
        if args[1].ends_with("-266-114910768") {
            return snapshot266::run(args[1].starts_with("--retire-"), &args[2], Path::new(&args[3]), &args[4]);
        }
        if args[1].ends_with("-230-99437433") {
            return snapshot230::run(args[1].starts_with("--retire-"), &args[2], Path::new(&args[3]), &args[4]);
        }
        if let Some(window) = snapshot230_window::for_command(&args[1]) {
            return snapshot230_window::run(window, args[1].starts_with("--retire-"),
                &args[2], Path::new(&args[3]), &args[4]);
        }
        return snapshot296::run(
            args[1] == "--retire-bootstrap-296",
            &args[2],
            Path::new(&args[3]),
            &args[4],
        );
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some("--check-held-ext4-228" | "--retire-held-ext4-228")
    ) {
        let apply = args[1] == "--retire-held-ext4-228";
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == if apply { 5 } else { 3 },
            "usage: horizon275-scratch-retire --check-held-ext4-228 SELF_SHA256 or --retire-held-ext4-228 SELF_SHA256 FLEET_SHA256 REMOTE_RECHECK_SHA256"
        );
        let binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut &binary)? == args[2],
            "unsealed retirement image"
        );
        if apply {
            return ext4_228::retire(&args[2], &args[3], &args[4]);
        }
        return ext4_228::check(&args[2]);
    }
    if matches!(
        args.get(1).map(String::as_str),
        Some(
            "--check-parked-229"
                | "--retire-parked-229"
                | "--check-parked-292"
                | "--retire-parked-292"
                | "--check-failed-stage-292"
                | "--retire-failed-stage-292"
                | "--check-parked-288"
                | "--retire-parked-288"
                | "--check-288-stage-bundle"
                | "--retire-288-stage-bundle"
                | "--check-292-stage-bundle"
                | "--retire-292-stage-bundle"
        )
    ) {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 5,
            "usage: horizon275-scratch-retire --check-parked-EPOCH|--retire-parked-EPOCH|--check-failed-stage-292|--retire-failed-stage-292|--check-EPOCH-stage-bundle|--retire-EPOCH-stage-bundle SELF_SHA256 EVIDENCE EVIDENCE_SHA256"
        );
        let binary = File::open("/proc/self/exe")?;
        let metadata = binary.metadata()?;
        ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o222 == 0 && digest(&mut &binary)? == args[2],
            "unsealed retirement image"
        );
        let apply = args[1].starts_with("--retire-");
        let comparison = Binding {
            path: args[3].clone().into(),
            sha256: args[4].clone(),
        };
        if args[1].ends_with("-288-stage-bundle") {
            return appendvec288::retire_bundle(apply, &args[2], comparison);
        }
        if args[1].ends_with("-292-stage-bundle") {
            return appendvec292_bundle::run(apply, &args[2], comparison);
        }
        if args[1].ends_with("-229") {
            return appendvec229::run(apply, &args[2], comparison);
        }
        if args[1].ends_with("-288") {
            return appendvec288::run(apply, &args[2], comparison);
        }
        return appendvec292::run(
            apply,
            args[1].ends_with("-failed-stage-292"),
            &args[2],
            comparison,
        );
    }
    ensure!(
        unsafe { libc::geteuid() } == 0
            && (args.len() == 3
                || (args.len() == 4
                    && matches!(
                        args[1].as_str(),
                        "--apply-unpacked-288" | "--apply-unpacked-292"
                    ))),
        "usage: horizon275-scratch-retire MODE SELF_SHA256 [BATCH for --apply-unpacked-288/292]"
    );
    let apply = match args[1].as_str() {
        "--check-only"
        | "--check-227"
        | "--check-bootstrap-288"
        | "--check-bootstrap-292"
        | "--check-unpacked-288"
        | "--check-unpacked-292" => false,
        "--apply"
        | "--retire-bootstrap-copy"
        | "--apply-227"
        | "--retire-bootstrap-288"
        | "--retire-bootstrap-292"
        | "--apply-unpacked-288"
        | "--apply-unpacked-292" => true,
        _ => anyhow::bail!("unknown operation"),
    };
    ensure!(
        digest(&mut File::open("/proc/self/exe")?)? == args[2],
        "self digest differs"
    );
    if matches!(
        args[1].as_str(),
        "--check-bootstrap-288" | "--retire-bootstrap-288"
    ) {
        return snapshot288::run(apply, &args[2]);
    }
    if matches!(
        args[1].as_str(),
        "--check-bootstrap-292" | "--retire-bootstrap-292"
    ) {
        return snapshot288::run292(apply, &args[2]);
    }
    let accounts_epoch = match args[1].as_str() {
        "--check-unpacked-288" | "--apply-unpacked-288" => Some(288),
        "--check-unpacked-292" | "--apply-unpacked-292" => Some(292),
        _ => None,
    };
    if let Some(epoch) = accounts_epoch {
        let batch = if apply {
            Some(
                args.get(3)
                    .context("specify a zero-based retirement batch")?
                    .parse()?,
            )
        } else {
            None
        };
        return selective_accounts::run(epoch, &args[2], batch);
    }
    let _cycle = lock(CYCLE_LOCK)?;
    let _mutation = lock(LOCAL_LOCK)?;
    if matches!(args[1].as_str(), "--check-227" | "--apply-227") {
        return stopped_bootstrap::run(apply, &args[2]);
    }
    let state = Path::new(RECEIPTS);
    let m = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let closed: Value = read_bound(Path::new(CUSTODY), CUSTODY_SHA, JSON_LIMIT)?;
    let census: Value = read_bound(Path::new(CENSUS), CENSUS_SHA, JSON_LIMIT)?;
    let terminal = value(&closed["closed"])?;
    let native = value(&terminal["native_exit"])?;
    let stop = value(&native["stop_completion"])?;
    let intent = value(&native["stop_intent"])?;
    let export = value(&closed["worker_capability"])?;
    let profile: Value = read_bound(Path::new(PROFILE), PROFILE_SHA, JSON_LIMIT)?;
    ensure!(
        terminal["epoch"] == 275
            && terminal["producer"]["Id"] == UNIT
            && stop["producer_invocation_id"] == INVOCATION
            && stop["plan_sha256"] == intent["sample"]["plan_sha256"]
            && intent["reason"] == "root-physical-budget"
            && stop["terminal"]["pid"] == 0
            && stop["terminal"]["active"] == "inactive"
            && stop["scratch_deleted"] == false
            && export["unsupported_operation"] == true
            && export["worker"] == profile["worker"]
            && closed["archive"]["full_epoch"] == false
            && census["custody"]["sha256"] == CUSTODY_SHA,
        "terminal evidence does not bind retirement"
    );
    let scope = Path::new(
        terminal["retained"]["run_root"]
            .as_str()
            .context("missing run root")?,
    );
    let scratch = Path::new(
        terminal["retained"]["scratch"]
            .as_str()
            .context("missing scratch")?,
    );
    let target = Path::new(
        closed["accounts_state_path"]
            .as_str()
            .context("missing AccountsDb path")?,
    );
    ensure!(
        scope.starts_with("/home/ubuntu/.jetstreamer-private/qualification-275-root-v301-a2")
            && scratch.starts_with(scope)
            && target.starts_with(scratch)
            && target
                .file_name()
                .is_some_and(|name| name == "accounts-state")
            && census["target"]["path"].as_str() == target.to_str(),
        "wrong AccountsDb scope"
    );
    let device = census["target"]["device"]
        .as_u64()
        .context("missing device")?;
    let inode = census["target"]["inode"]
        .as_u64()
        .context("missing inode")?;
    let root = stopped_tree::open_root(target, device, inode)?;
    let snapshot = Path::new(
        profile["snapshot"]["path"]
            .as_str()
            .context("missing bootstrap")?,
    );
    let bootstrap = open_regular(snapshot)?.metadata()?;
    ensure!(
        !snapshot.starts_with(target)
            && bootstrap.uid() == 0
            && bootstrap.mode() & 0o222 == 0
            && profile["snapshot"]["device"] == bootstrap.dev()
            && profile["snapshot"]["inode"] == bootstrap.ino()
            && profile["snapshot"]["bytes"] == bootstrap.len(),
        "bootstrap identity changed"
    );
    let archive = Path::new(
        closed["archive"]["path"]
            .as_str()
            .context("missing retained archive")?,
    );
    ensure!(
        archive.starts_with(scope) && !archive.starts_with(target),
        "archive crosses retirement boundary"
    );
    let mut partial = open_regular(archive)?;
    let a = partial.metadata()?;
    ensure!(
        closed["archive"]["device"] == a.dev()
            && closed["archive"]["inode"] == a.ino()
            && closed["archive"]["bytes"] == a.len()
            && closed["archive"]["sha256"] == digest(&mut partial)?,
        "retained archive changed"
    );
    if args[1] == "--retire-bootstrap-copy" {
        return retire_bootstrap(
            state,
            scope,
            target,
            snapshot,
            &profile["snapshot"],
            &args[2],
        );
    }
    let check = state.join("check.json");
    let pending = state.join("intent.json");
    let complete = state.join("completion.json");
    ensure!(!complete.exists(), "retirement is already complete");
    let (expected, qualified_ledger) = if apply {
        let check_file = open_regular(&check)?;
        ensure!(
            check_file.metadata()?.uid() == 0 && check_file.metadata()?.mode() & 0o222 == 0,
            "unsealed check receipt"
        );
        let check: Value = serde_json::from_reader(check_file)?;
        ensure!(
            check["self_sha256"] == args[2]
                && check["custody_sha256"] == CUSTODY_SHA
                && check["census_sha256"] == CENSUS_SHA,
            "wrong check receipt"
        );
        let ledger: Binding = serde_json::from_value(check["ledger"].clone())?;
        ensure!(ledger.path == state.join("ledger.json"), "foreign ledger");
        let entries = read_bound(&ledger.path, &ledger.sha256, LEDGER_LIMIT)?;
        (entries, Some(ledger.sha256))
    } else {
        ensure!(
            !check.exists() && !pending.exists(),
            "check already recorded"
        );
        (stopped_tree::capture(&root, device, 1000, 1000)?, None)
    };
    let resuming = pending.exists();
    if resuming {
        let prior = open_regular(&pending)?;
        let m = prior.metadata()?;
        ensure!(
            m.uid() == 0 && m.mode() & 0o222 == 0 && m.len() <= JSON_LIMIT,
            "unsealed retirement intent"
        );
        let prior: Value = serde_json::from_reader(prior)?;
        ensure!(
            prior["self_sha256"] == args[2]
                && prior["custody_sha256"] == CUSTODY_SHA
                && prior["census_sha256"] == CENSUS_SHA
                && prior["device"] == device
                && prior["inode"] == inode
                && prior["ledger_sha256"].as_str() == qualified_ledger.as_deref(),
            "wrong retirement intent"
        );
    }
    let current = stopped_tree::capture(&root, device, 1000, 1000)?;
    stopped_tree::validate_remaining(&expected, &current, resuming)?;
    let entry_count = current.len();
    drop(current);
    for unit in [UNIT, GUARD, TIMER] {
        terminal_unit(unit)?;
    }
    assert_no_nested_mount(target)?;
    let schedule = scheduled(scope, target)?;
    let consumers = process_references::scan(Path::new("/proc"), target)?;
    ensure!(
        consumers.inspected_processes > 0 && consumers.references.is_empty(),
        "live AccountsDb references: {:?}",
        consumers.references
    );
    ensure!(
        identity(&a) == identity(&partial.metadata()?)
            && identity(&a) == identity(&archive.symlink_metadata()?),
        "retained archive changed during preflight"
    );
    let free_before = available(scope)?;
    if !apply {
        let ledger = write_json(&state.join("ledger.json"), &expected)?;
        let report = write_json(
            &check,
            &json!({"self_sha256":args[2],"custody_sha256":CUSTODY_SHA,"census_sha256":CENSUS_SHA,
            "ledger":ledger,"entry_count":entry_count,"measured_allocated_bytes":closed["accounts_state_allocated_bytes"],"scheduled":schedule,"consumers":consumers}),
        )?;
        println!("{}", serde_json::to_string(&report)?);
        return Ok(());
    }
    if !resuming {
        write_json(
            &pending,
            &json!({"self_sha256":args[2],"custody_sha256":CUSTODY_SHA,"census_sha256":CENSUS_SHA,
            "ledger_sha256":qualified_ledger,"initial_entries":entry_count,"device":device,"inode":inode,"free_before_bytes":free_before}),
        )?;
    }
    let removed = stopped_tree::remove_contents(&root, &expected, device, 1000, 1000)?;
    ensure!(
        root.metadata()?.ino() == target.symlink_metadata()?.ino()
            && identity(&a) == identity(&archive.symlink_metadata()?),
        "scratch or retained archive identity changed"
    );
    let report = write_json(
        &complete,
        &json!({"stopped_invocation":INVOCATION,"preserved_archive":closed["archive"],"removed_entries_this_attempt":removed,
        "measured_allocated_bytes_before":closed["accounts_state_allocated_bytes"],"free_at_attempt_start_bytes":free_before,
        "free_after_bytes":available(scope)?,"empty_root_retained":true,"scheduled":schedule,"consumers":consumers,"r2_mutations":false}),
    )?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
