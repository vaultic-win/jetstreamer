//! Retire the single closed acquisition copy of the sealed epoch 266 CID index.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
    process::Command,
};

const ACQUISITION: &str = "/var/lib/jetstreamer/horizon266-index-acquire-v1/transfer/cid.body";
const SEALED: &str = "/var/lib/jetstreamer/horizon266-index-acquire-v1/cache/sealed/epoch-266-bafyreihxdx3dwzmgzbfpzo7z4n744c6cjnn63j3mg2mewkauxoa2tgxxqu-mainnet-cid-to-offset-and-size.index";
const SHA: &str = "41c9792e0c142984a28f8f653f970223c5525d3c22bfef0df01cd3f7150ac915";
const UNIT: &str = "horizon266-index-acquire-v1.service";
const IID: &str = "b1a89d8deda341c5a19510f55a9e6202";
const RETIRE_UNIT: &str = "foundation-266-acquisition-retire-v234-a4.service";
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const STATE: &str = "/home/ubuntu/.codex/diagnostics/horizon266-acquisition-retire-v234-a1";

fn stamp(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() as i128 * 1_000_000_000 + m.mtime_nsec() as i128,
        m.ctime() as i128 * 1_000_000_000 + m.ctime_nsec() as i128
    ])
}

fn open_regular(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0
            && stamp(&meta) == stamp(&path.symlink_metadata()?),
        "unexpected custody at {}",
        path.display()
    );
    Ok(f)
}

fn hash(f: &mut File) -> Result<String> {
    let mut buf = vec![0; 1 << 20];
    let mut h = Sha256::new();
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}

fn document(path: &Path, sha: &str) -> Result<Value> {
    let f = open_regular(path)?;
    let before = stamp(&f.metadata()?);
    let mut bytes = Vec::new();
    (&f).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1 << 20
            && format!("{:x}", Sha256::digest(&bytes)) == sha
            && before == stamp(&f.metadata()?)
            && before == stamp(&path.symlink_metadata()?),
        "changed evidence {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn reference(value: &Value) -> Result<(&Path, &str)> {
    Ok((
        Path::new(value["path"].as_str().context("missing bound path")?),
        value["sha256"].as_str().context("missing bound SHA")?,
    ))
}

fn bound(value: &Value) -> Result<Value> {
    let (path, digest) = reference(value)?;
    document(path, digest)
}

fn command(path: &str, args: &[&str]) -> Result<Vec<u8>> {
    let result = Command::new("/usr/bin/timeout")
        .args(["--kill-after=1s", "30s", path])
        .args(args)
        .output()?;
    ensure!(
        result.status.success(),
        "{} failed with {}",
        path,
        result.status
    );
    ensure!(
        result.stdout.len() <= 1 << 20,
        "oversized evidence from {}",
        path
    );
    Ok(result.stdout)
}

fn drained() -> Result<()> {
    let raw = command(
        "/usr/bin/systemctl",
        &[
            "show",
            UNIT,
            "-p",
            "Id,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,ControlGroup,TriggeredBy,Result,LoadState",
        ],
    )?;
    let state: BTreeMap<_, _> = std::str::from_utf8(&raw)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .collect();
    ensure!(
        state.get("Id") == Some(&UNIT)
            && state.get("ActiveState") == Some(&"inactive")
            && state.get("SubState") == Some(&"dead")
            && ["MainPID", "ControlPID", "NRestarts"]
                .iter()
                .all(|key| state.get(key) == Some(&"0"))
            && ["Job", "ControlGroup", "TriggeredBy"]
                .iter()
                .all(|key| state.get(key) == Some(&""))
            && (state.get("InvocationID") == Some(&IID)
                || (state.get("LoadState") == Some(&"not-found")
                    && state.get("InvocationID") == Some(&"")))
            && state.get("Result") == Some(&"success")
            && !Path::new("/sys/fs/cgroup/system.slice").join(UNIT).exists(),
        "original index acquisition is not drained"
    );
    let uid = format!("UNIT={UNIT}");
    let inv = format!("INVOCATION_ID={IID}");
    let raw = command(
        "/usr/bin/journalctl",
        &[
            "-b",
            "--no-pager",
            "-o",
            "json",
            "--output-fields=_PID,_UID,UNIT,INVOCATION_ID,MESSAGE_ID",
            "_PID=1",
            "_UID=0",
            &uid,
            &inv,
        ],
    )?;
    let rows: Vec<Value> = std::str::from_utf8(&raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<_>>()?;
    ensure!(
        rows.iter().all(|r| r["_PID"] == "1"
            && r["_UID"] == "0"
            && r["UNIT"] == UNIT
            && r["INVOCATION_ID"] == IID)
            && rows
                .iter()
                .filter(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
                .count()
                == 1,
        "missing exact native success for the original acquisition"
    );
    Ok(())
}

fn census(plan: &Value, retiring: bool) -> Result<Value> {
    let (script, script_hash) = reference(&plan["census"])?;
    let (readers, readers_hash) = reference(&plan["scheduled_readers"])?;
    for (path, expected) in [(script, script_hash), (readers, readers_hash)] {
        ensure!(
            hash(&mut open_regular(path)?)? == expected,
            "changed scanner script"
        );
    }
    let raw = command(
        "/usr/bin/python3",
        &[
            "-B",
            script.to_str().context("census path")?,
            readers.to_str().context("reader scan path")?,
        ],
    )?;
    let v: Value = serde_json::from_slice(&raw)?;
    let rows = |r: &Value| r.as_array().cloned().context("missing census list");
    let own_origin = format!("/run/systemd/transient/{RETIRE_UNIT}");
    let own_cgroup = format!("0::/system.slice/{RETIRE_UNIT}");
    let own_retirement = retiring && fs::read_to_string("/proc/self/cgroup")?.trim() == own_cgroup;
    let mut foreign = Vec::new();
    for row in rows(&v["static_transitive"]["remaining"])? {
        if rows(&row["targets"])?
            .iter()
            .all(|target| target != ACQUISITION)
        {
            continue;
        }
        // The current finite unit's ReadWritePaths entry is visible to the
        // scan. An indirect reference or a different unit is a real consumer.
        if !(own_retirement && row["origin"] == own_origin && rows(&row["chain"])?.is_empty()) {
            foreign.push(row["origin"].clone());
        }
    }
    ensure!(
        foreign.is_empty(),
        "staged acquisition readers: {foreign:?}"
    );
    ensure!(
        v["read_only"] == true
            && v["authority"] == false
            && v["identities"][ACQUISITION].is_object()
            && rows(&v["exact_process_readers"])?
                .iter()
                .all(|r| r[3] != ACQUISITION)
            && rows(&v["static_transitive"]["unresolved"])?.is_empty(),
        "the raw acquisition still has a current, staged, or unresolved reader"
    );
    Ok(v)
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().context("record parent")?)?.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        args.len() == 5 && matches!(args[1].as_str(), "check" | "retire"),
        "expected check|retire PLAN PLAN_SHA SELF_SHA"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0 && hash(&mut File::open("/proc/self/exe")?)? == args[4],
        "unexpected effective user or executable"
    );
    let path = Path::new(&args[2]);
    let state = Path::new(STATE);
    ensure!(
        path == state.join("plan.json")
            && state.canonicalize()? == state
            && state.metadata()?.uid() == 0
            && state.metadata()?.mode() & 0o777 == 0o700,
        "wrong private plan directory"
    );
    let plan = document(path, &args[3])?;
    ensure!(
        plan["schema"] == "foundation-closed-266-acquisition-retirement-v1"
            && plan["local_duplicate_retirement_authorized"] == true
            && plan["remote_mutations"] == false,
        "unapproved acquisition retirement"
    );
    let comparison = bound(&plan["comparison"])?;
    let origin = bound(&comparison["original"])?;
    let seal = bound(&comparison["sealed_copy"])?;
    let fetch = bound(&comparison["acquisition"])?;
    let keeper_name = Path::new(SEALED)
        .file_name()
        .and_then(|s| s.to_str())
        .context("sealed name")?;
    ensure!(
        comparison["files"] == json!([ACQUISITION, SEALED])
            && comparison["digest"] == SHA
            && origin["unit"] == UNIT
            && origin["invocation"] == IID
            && origin["success"] == true
            && origin["cgroup_drained"] == true
            && origin["acquisition"] == comparison["acquisition"]
            && origin["seal"] == comparison["sealed_copy"]
            && fetch["index"]["epoch"] == 266
            && fetch["index"]["full_sha256"] == SHA
            && fetch["identity"] == comparison["identities"][0]
            && seal["destination"] == json!(Path::new(SEALED).parent())
            && seal["members"].as_array().is_some_and(|members| members
                .iter()
                .filter(|m| m["source"] == ACQUISITION
                    && m["name"] == keeper_name
                    && m["sha256"] == SHA
                    && m["bytes"] == fetch["index"]["total_bytes"]
                    && m["mode"] == "0444")
                .count()
                == 1),
        "sealed index does not bind the original acquisition"
    );
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(LOCK)?;
    let m = lock.metadata()?;
    ensure!(
        m.uid() == 1000
            && m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o600
            && stamp(&m) == stamp(&Path::new(LOCK).symlink_metadata()?)
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "shared mutation lock is busy or its identity changed"
    );
    drained()?;
    let target = Path::new(ACQUISITION);
    let keeper = Path::new(SEALED);
    let mut a = open_regular(target)?;
    let mut k = open_regular(keeper)?;
    let a_id = stamp(&a.metadata()?);
    let k_id = stamp(&k.metadata()?);
    ensure!(
        comparison["identities"] == json!([a_id, k_id])
            && a.metadata()?.dev() == k.metadata()?.dev()
            && a.metadata()?.ino() != k.metadata()?.ino()
            && hash(&mut a)? == SHA
            && hash(&mut k)? == SHA,
        "duplicate index identity or digest mismatch"
    );
    drop(a);
    drop(k);
    let inspection = census(&plan, args[1] == "retire")?;
    drained()?;
    let m = target.symlink_metadata()?;
    ensure!(
        stamp(&m) == a_id
            && stamp(&keeper.symlink_metadata()?) == k_id
            && m.nlink() == 1
            && keeper.symlink_metadata()?.nlink() == 1
            && m.blocks() * 512 == comparison["physically_recoverable_if_unused"],
        "index custody changed before retirement"
    );
    let record = json!({"target": ACQUISITION, "retained": SEALED, "sha256": SHA,
        "target_identity": a_id, "retained_identity": k_id, "plan_sha256": args[3],
        "self_sha256": args[4], "allocated_target_bytes": m.blocks() * 512,
        "no_current_or_staged_readers": true, "census": inspection, "remote_mutations": false});
    if args[1] == "check" {
        println!(
            "{}",
            json!({"allocation_verified_bytes":m.blocks()*512, "retirement_performed":false})
        );
        return Ok(());
    }
    persist(&state.join("intent.json"), &record)?;
    // The bound single-link inode and its root-only parent are still pinned under the shared lock.
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(target.parent().context("acquisition directory")?)?;
    let projected =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())).join("cid.body");
    ensure!(
        stamp(&projected.symlink_metadata()?) == a_id,
        "unlink target changed"
    );
    ensure!(
        unsafe { libc::unlinkat(dir.as_raw_fd(), c"cid.body".as_ptr(), 0) } == 0,
        "unlinkat: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    ensure!(
        target
            .symlink_metadata()
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            && stamp(&keeper.symlink_metadata()?) == k_id,
        "retirement outcome differs"
    );
    persist(
        &state.join("completion.json"),
        &json!({"plan_sha256":args[3],"self_sha256":args[4],
        "removed":ACQUISITION,"retained":SEALED,"sha256":SHA,"allocated_bytes_unlinked":m.blocks()*512,
        "remote_mutations":false,"reservations_changed":false}),
    )?;
    println!(
        "{}",
        json!({"allocated_bytes_unlinked":m.blocks()*512, "retirement_performed":true})
    );
    Ok(())
}
