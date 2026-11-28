//! Remove only the redundant CID indexes of two closed epoch 140 recordings.
//! All recording outputs and the successful third attempt's original index stay in place.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::Command,
};

#[allow(dead_code)]
#[path = "../horizon_epoch170_checkpoint_suffix/evidence.rs"]
mod evidence;
#[path = "../../jetstreamer-horizon-observe/src/process_references.rs"]
mod process_references;
use evidence::command;
include!("../horizon_epoch157_lanej_rotation_20261128_v1/consumer_plans.rs");

const PRIVATE: &str = "/home/sol/.jetstreamer-private";
const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const RECEIPTS: &str = "closed140-recording-index-retirement-20261128-v1";
const ATTEMPTS: [&str; 3] = [
    "epoch140-suffix-recording-20261127-v1",
    "epoch140-suffix-recording-20261127-retry1",
    "epoch140-suffix-recording-20261127-retry2",
];
const INDEX: &str = "epoch-140-bafyreie6irqbqnf4mvjxbfaqak6luoebx3aqxejfydtbehbgzt476heiqu-mainnet-cid-to-offset-and-size.index";
const INODES: [u64; 3] = [110166971, 111345687, 115345968];
const PARENTS: [u64; 3] = [110166969, 111345678, 115344889];
const LENGTH: u64 = 5_257_952_670;
const HASH: &str = "8bc0d92bb1b40daf2becca7c07dc20eaa0121ec4b7723ba77a68efe8f0807723";
const SURVEY: &str = "/home/sol/.jetstreamer-private/next-170-169-bootstrap-20261128.lIpsC5N8/EPOCH140_DUPLICATE_CONTENTS.json";
const SURVEY_SHA: &str = "84b75058dceb3298016d1ada8671b5e642feb97cf398b155d8ccce604b6a7ce3";
const FAILED_GUARD: &str = "horizon-guard-epoch140-suffix-recording-20261127-retry1.service";

fn index_dir(i: usize) -> PathBuf {
    Path::new(PRIVATE)
        .join(ATTEMPTS[i])
        .join("recording/ledger/compact-indexes/140")
}

fn file_stamp(m: &fs::Metadata) -> Value {
    let ns = |s: i64, n: i64| s as i128 * 1_000_000_000 + n as i128;
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.blocks(),
        ns(m.mtime(), m.mtime_nsec()) as i64,
        ns(m.ctime(), m.ctime_nsec()) as i64
    ])
}

fn same_index(i: usize, sample: &Value) -> Result<(File, u64)> {
    let parent = index_dir(i);
    let path = parent.join(INDEX);
    ensure!(
        path.canonicalize()? == path && sample["path"].as_str() == path.to_str(),
        "indirect or unregistered index"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let dp = dir.metadata()?;
    ensure!(
        (dp.dev(), dp.ino()) == (64512, PARENTS[i]),
        "different index directory"
    );
    let st = fs::symlink_metadata(&path)?;
    ensure!(
        st.is_file()
            && (
                st.dev(),
                st.ino(),
                st.nlink(),
                st.uid(),
                st.gid(),
                st.mode(),
                st.len()
            ) == (64512, INODES[i], 1, 1001, 1003, 0o100600, LENGTH)
            && file_stamp(&st) == sample["identity"],
        "index differs from full content proof: {}",
        path.display()
    );
    Ok((dir, st.blocks() * 512))
}

fn pins(i: usize, file: &str, sha: &str) -> Result<Value> {
    evidence::bound(&json!({"path":Path::new(RUNTIME).join(ATTEMPTS[i]).join(file),"sha256":sha}))
}

fn lineage() -> Result<Value> {
    let first = pins(
        0,
        "PRIVATE_RECORDING_TERMINAL.json",
        "8239306c5bc34f402ed4bf9584b37dff3a96eedb13218b61dfb813aa8c5febcc",
    )?;
    let second = pins(
        1,
        "RETRY1_TERMINAL_FOR_RETRY2.json",
        "bed81264c197942f9ad5bc3b8f6a84ec50b3c4363d70de1bdcb22ea9be3ebeac",
    )?;
    let third = pins(
        2,
        "PRIVATE_SUFFIX_ACCEPTANCE.json",
        "375cdc234f4592ddc30448a6eba8a870079cdcb952baa66f8ea523d67d375e5c",
    )?;
    ensure!(
        first["producer_invocation_id"] == "9aedc166422d468fb67bcf0ee70ef576"
            && first["recording_complete"] == false
            && second["invocation_id"] == "44facb5de13b42b383a4b8eba90a8fcd"
            && second["result"] == "runtime-timeout"
            && third["invocation_id"] == "44b43ec053464171a7ae8491f3db9336"
            && third["start_slot"] == 60_911_752
            && third["end_slot"] == 60_911_999
            && third["recorded_slots"] == 248,
        "different recording lineage"
    );
    for (record, i, expected_size) in [
        (
            &second["retained_partial"],
            1,
            second["partial_bytes"].as_u64(),
        ),
        (&third["archive"], 2, third["archive_bytes"].as_u64()),
    ] {
        let p = Path::new(PRIVATE)
            .join(ATTEMPTS[i])
            .join("recording/epoch-140-suffix.jet");
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && record["path"].as_str() == p.to_str()
                && m.is_file()
                && Some(m.len()) == expected_size,
            "recording output missing"
        );
    }
    evidence::bound(&second["native_terminal"])?;
    evidence::bound(&third["native_terminal"])?;
    Ok(
        json!({"retained_partial":second["retained_partial"],"accepted_recording":third["archive"],"manifest":third["segment_manifest"]}),
    )
}

// Match actual data roots and command lines that construct those paths using the private base.
// A reference to a retained root-owned historical receipt does not open a cache.
fn terms(text: &str) -> Vec<&'static str> {
    ATTEMPTS[..2]
        .iter()
        .copied()
        .filter(|name| {
            text.contains(&format!("{PRIVATE}/{name}"))
                || (text.contains(PRIVATE)
                    && [format!("'{name}'"), format!("\"{name}\"")]
                        .iter()
                        .any(|s| text.contains(s)))
        })
        .collect()
}

fn idle() -> Result<()> {
    evidence::idle("horizon-epoch140-suffix-recording.service")?;
    for attempt in ATTEMPTS {
        for suffix in ["timer", "service"] {
            let unit = format!("horizon-guard-{attempt}.{suffix}");
            evidence::idle(&unit)?;
            let state = evidence::props(&unit, "Id,LoadState,TriggeredBy,Job")?;
            ensure!(
                state["TriggeredBy"].is_empty() && state["Job"].is_empty(),
                "guard rearmed: {unit}"
            );
        }
    }
    Ok(())
}

fn staged() -> Result<Value> {
    idle()?;
    let mut rg = Command::new("/usr/bin/rg");
    rg.args([
        "--no-config",
        "--files-with-matches",
        "--null",
        "-F",
        "--hidden",
        "--no-ignore",
        "--text",
    ]);
    for n in &ATTEMPTS[..2] {
        rg.args(["-e", n]);
    }
    for d in [
        "/etc/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/home/sol/.config/systemd/user",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/etc/crontab",
    ] {
        if Path::new(d).try_exists()? {
            rg.arg(d);
        }
    }
    let search = rg.output()?;
    ensure!(
        matches!(search.status.code(), Some(0 | 1)),
        "definition scan: {}",
        String::from_utf8_lossy(&search.stderr)
    );
    for filename in search.stdout.split(|b| *b == 0).filter(|b| !b.is_empty()) {
        let path = Path::new(std::str::from_utf8(filename)?);
        ensure!(
            path == Path::new("/run/systemd/transient").join(FAILED_GUARD)
                && evidence::digest(&fs::read(path)?)
                    == "f40d6d6259b15d43a809a0c30506b87957b682dda8a44c0945779bcd0e31d485",
            "unreviewed scheduled definition {}",
            path.display()
        );
        let guard = evidence::props(FAILED_GUARD, "InvocationID,LoadState,Restart,ControlGroup")?;
        ensure!(
            guard["InvocationID"] == "a56aa716ed304ceba0e7c4d326c08a1a"
                && guard["Restart"] == "no"
                && guard["ControlGroup"].is_empty(),
            "guard identity changed"
        );
    }
    let listing = command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--plain",
            "--all",
            "--no-pager",
            "--no-legend",
            "--type=service,timer,path,socket",
        ],
    )?;
    let jobs = command(
        "/usr/bin/systemctl",
        &["list-jobs", "--plain", "--no-pager", "--no-legend"],
    )?;
    let mut units = BTreeSet::new();
    for line in listing.lines() {
        let mut fields = line.split_whitespace();
        let unit = fields.next().context("missing unit")?;
        if !matches!(fields.nth(1), Some("inactive" | "failed")) {
            units.insert(unit);
        }
    }
    for line in jobs.lines() {
        if let Some(unit) = line.split_whitespace().nth(1) {
            if unit
                .rsplit_once('.')
                .is_some_and(|(_, k)| matches!(k, "service" | "timer" | "path" | "socket"))
            {
                units.insert(unit);
            }
        }
    }
    let mut cache = PlanCache::default();
    let mut checked = 0;
    for batch in units.iter().copied().collect::<Vec<_>>().chunks(128) {
        for p in native_plans(batch, true)? {
            if matches!(p.state.as_str(), "inactive" | "failed" | "gone") || p.closed.is_some() {
                continue;
            }
            let direct = terms(&p.projection);
            let nested = artifacts(&p.projection, &mut cache)?;
            ensure!(
                direct.is_empty() && nested.is_empty(),
                "executable reference {} {} {:?} {:?}",
                p.unit,
                p.sub,
                direct,
                nested
            );
            checked += 1;
        }
    }
    ensure!(checked > 0, "empty native plans");
    Ok(json!({"units":units.len(),"executable":checked,"plans":cache.examined}))
}

fn kernel() -> Result<()> {
    let targets = [index_dir(0), index_dir(1)];
    for p in &targets {
        let scan = process_references::scan(Path::new("/proc"), p)?;
        ensure!(
            scan.references.is_empty() && scan.inspected_processes > 0,
            "active process references {:?}",
            scan.references
        );
    }
    let relative = targets
        .iter()
        .map(|p| Ok(Path::new("/").join(p.strip_prefix("/home/sol")?)))
        .collect::<Result<Vec<_>>>()?;
    let mut namespaces = BTreeSet::new();
    for item in fs::read_dir("/proc")? {
        let p = item?.path();
        if !p
            .file_name()
            .context("proc entry")?
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let result = (|| -> io::Result<()> {
            for entry in fs::read_dir(p.join("fd"))? {
                match entry?.path().metadata() {
                    Ok(st) if st.dev() == 64512 && INODES[..2].contains(&st.ino()) => {
                        return Err(io::Error::other("CID index is open"));
                    }
                    Err(e)
                        if e.kind() != io::ErrorKind::NotFound
                            && e.raw_os_error() != Some(libc::ESRCH) =>
                    {
                        return Err(e);
                    }
                    _ => (),
                }
            }
            for line in BufReader::new(File::open(p.join("maps"))?).lines() {
                let line = line?;
                let mut c = line.split_ascii_whitespace().skip(3);
                if c.next() == Some("fc:00")
                    && c.next()
                        .and_then(|n| n.parse::<u64>().ok())
                        .is_some_and(|i| INODES[..2].contains(&i))
                {
                    return Err(io::Error::other("CID index is mapped"));
                }
            }
            let ns = p.join("ns/mnt").metadata()?.ino();
            if namespaces.insert(ns) {
                let mountinfo = fs::read_to_string(p.join("mountinfo"))?;
                if mountinfo
                    .lines()
                    .filter_map(|s| s.split_ascii_whitespace().nth(3))
                    .any(|s| relative.iter().any(|t| Path::new(s).starts_with(t)))
                {
                    return Err(io::Error::other("index directory has a bind mount"));
                }
            }
            Ok(())
        })();
        if let Err(err) = result {
            if err.kind() != io::ErrorKind::NotFound && err.raw_os_error() != Some(libc::ESRCH) {
                return Err(err.into());
            }
        }
    }
    Ok(())
}

fn locked(path: &Path, dev: u64, ino: u64) -> Result<File> {
    ensure!(path.canonicalize()? == path, "indirect lock");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && (m.dev(), m.ino(), m.nlink()) == (dev, ino, 1),
        "changed lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0,
        "lock failed"
    );
    Ok(f)
}

fn run(mode: &str) -> Result<Value> {
    ensure!(
        matches!(mode, "check" | "retire") && unsafe { libc::geteuid() } == 0,
        "use the sealed root operator"
    );
    let base = Path::new(RUNTIME).join(RECEIPTS);
    let exe = fs::read_link("/proc/self/exe")?;
    let package = exe.parent().context("package")?;
    ensure!(package.parent() == Some(base.as_path()), "unsealed package");
    let seal = evidence::reference(&package.join("deployment-seal-receipt.json"))?;
    ensure!(
        evidence::member(&seal, "retire")? == exe,
        "unrecognized image"
    );
    let _campaign = locked(
        Path::new("/run/horizon-epoch171-to136-g1.operation.lock"),
        26,
        3453440,
    )?;
    let _local = locked(
        &Path::new(PRIVATE).join("r2-receipts/local-mutation.lock"),
        64512,
        101135013,
    )?;
    let survey = evidence::bound(&json!({"path":SURVEY,"sha256":SURVEY_SHA}))?;
    let rows = survey["files"].as_array().context("survey files")?;
    ensure!(
        survey["sha256"] == HASH && survey["bytes_per_file"] == LENGTH && rows.len() == 3,
        "different hash proof"
    );
    same_index(2, &rows[2])?;
    let output = lineage()?;
    let done = base.join("COMPLETE.json");
    if done.try_exists()? {
        for i in 0..2 {
            ensure!(
                absent(&index_dir(i).join(INDEX))?,
                "retired index reappeared"
            );
        }
        return evidence::reference(&done);
    }
    let staged = staged()?;
    kernel()?;
    let checked = base.join("CHECKED.json");
    if mode == "check" {
        for (i, r) in rows.iter().enumerate() {
            same_index(i, r)?;
        }
        if !checked.try_exists()? {
            evidence::receipt(
                &checked,
                &json!({"survey":SURVEY_SHA,"operator":seal,"lineage":output,"staged":staged}),
            )?;
        }
        return evidence::reference(&checked);
    }
    let check_ref = evidence::reference(&checked)?;
    let check = evidence::bound(&check_ref)?;
    ensure!(
        check["survey"] == SURVEY_SHA && check["operator"] == seal && check["lineage"] == output,
        "different check"
    );
    let intent = base.join("INTENT.json");
    if !intent.try_exists()? {
        for (i, r) in rows.iter().enumerate() {
            same_index(i, r)?;
        }
        evidence::receipt(
            &intent,
            &json!({"check":check_ref,"staged":staged,"available_before":evidence::available()?.0}),
        )?;
    }
    let intent_ref = evidence::reference(&intent)?;
    let claim = evidence::bound(&intent_ref)?;
    ensure!(claim["check"] == check_ref, "different intent");
    let mut allocated = 0;
    for (i, row) in rows[..2].iter().enumerate() {
        let path = index_dir(i).join(INDEX);
        let rec = base.join(format!("REMOVED_{}.json", INODES[i]));
        if !rec.try_exists()? {
            let bytes = if absent(&path)? {
                0
            } else {
                let (dir, blocks) = same_index(i, row)?;
                same_index(2, &rows[2])?;
                let name = CString::new(INDEX)?;
                ensure!(
                    unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
                    "unlink: {}",
                    io::Error::last_os_error()
                );
                dir.sync_all()?;
                blocks
            };
            ensure!(absent(&path)?, "index still present");
            evidence::receipt(
                &rec,
                &json!({"path":path,"inode":INODES[i],"allocated_bytes":bytes,"intent":intent_ref}),
            )?;
        }
        let item = evidence::bound(&evidence::reference(&rec)?)?;
        ensure!(
            item["intent"] == intent_ref
                && item["path"].as_str() == path.to_str()
                && absent(&path)?,
            "receipt mismatch"
        );
        allocated += evidence::num(&item, "allocated_bytes")?;
    }
    same_index(2, &rows[2])?;
    ensure!(lineage()? == output, "recording output changed");
    let before = evidence::num(&claim, "available_before")?;
    let after = evidence::available()?.0;
    evidence::receipt(
        &done,
        &json!({"intent":intent_ref,"allocated_bytes_removed":allocated,"available_before":before,
        "available_after":after,"conservative_credit":allocated.min(after.saturating_sub(before)),
        "retained":rows[2],"lineage":output,"sha256":HASH}),
    )
}

fn absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}

fn main() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(args.len() == 2, "usage: retire check|retire");
    println!("{}", run(&args[1])?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_and_current_cache_have_distinct_paths() {
        assert!(terms("/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-recording-20261127-retry1/NATIVE_TERMINAL.json").is_empty());
        assert_eq!(terms(index_dir(0).to_str().unwrap()), [ATTEMPTS[0]]);
        assert_eq!(terms(index_dir(1).to_str().unwrap()), [ATTEMPTS[1]]);
        assert!(terms(index_dir(2).to_str().unwrap()).is_empty());
        assert_ne!(PARENTS[0], PARENTS[1]);
    }
}
