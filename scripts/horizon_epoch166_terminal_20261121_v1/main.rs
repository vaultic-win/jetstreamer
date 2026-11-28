//! Capture the committed local archive from the selected original producer.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
mod cadence;
mod receipt;
#[cfg(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
#[path = "../horizon_epoch166_retry10_delivery_20261121_v1/wait.rs"]
mod wait;

#[cfg(feature = "retry10")]
#[path = "../horizon_epoch166_retry10_delivery_20261121_v1/generation.rs"]
mod generation;
#[cfg(any(
    all(
        feature = "retry10",
        any(
            feature = "metered168",
            feature = "source167",
            feature = "retry170",
            feature = "full172"
        )
    ),
    all(
        feature = "metered168",
        any(feature = "source167", feature = "retry170", feature = "full172")
    ),
    all(feature = "source167", any(feature = "retry170", feature = "full172")),
    all(feature = "retry170", feature = "full172")
))]
compile_error!("select a single terminal producer generation");
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
#[path = "peers.rs"]
mod generation;
#[cfg(all(
    feature = "metered168",
    not(any(feature = "cold168", feature = "retry10"))
))]
#[path = "../horizon_epoch168_full_metered_20261121_v1/terminal.rs"]
mod generation;
#[cfg(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
use generation::{LIVE_SHA, PRODUCER_IID as IID, PRODUCER_UNIT as UNIT, TERMINAL_ROOT as ROOT};

#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch166-terminal-20261121-v1";
#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const LIVE_SHA: &str = "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe";
#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const UNIT: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
#[cfg(not(any(
    feature = "metered168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const EPOCH: u64 = 166;
#[cfg(feature = "metered168")]
const EPOCH: u64 = 168;
#[cfg(any(feature = "source167", feature = "retry170", feature = "full172"))]
use generation::EPOCH;
const SUCCEEDED: &str = "7ad2d189f7e94e70a38c781354912448";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const STOPPING: &str = "de5b426a63be47a7b6ac3eaac82e2f6f";
const FAILED: &str = "be02cf6855d2428ba40df7e9d022f03d";
const PROCESS_EXITED: &str = "98e322203f7a4ed290d09fe03c09fe15";

fn s(v: &Value) -> Result<&str> {
    v.as_str().context("expected string")
}
fn small(p: &Path, max: usize) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= max as u64,
        "unexpected file or size: {}",
        p.display()
    );
    let mut bytes = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len(),
        "file size changed: {}",
        p.display()
    );
    Ok(bytes)
}
fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new("/usr/bin/timeout")
        .args(["--kill-after=2", "12", program])
        .args(args)
        .output()?;
    ensure!(
        out.status.success(),
        "{} failed: {}",
        program,
        String::from_utf8_lossy(&out.stderr)
    );
    ensure!(out.stdout.len() < 4 << 20, "unexpected command output size");
    Ok(String::from_utf8(out.stdout)?)
}
fn show(unit: &str) -> Result<BTreeMap<String, String>> {
    let raw = run(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
            "-p",
            "Id,ActiveState,SubState,MainPID,ControlPID,ControlGroup,InvocationID,Job,NRestarts",
        ],
    )?;
    raw.lines()
        .map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.into(), v.into()))
                .context("malformed systemctl result")
        })
        .collect()
}
fn process_bound(p: &Value) -> Result<bool> {
    let pid = p["pid"].as_u64().context("PID")?;
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let raw = match fs::read_to_string(path) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    let ticks = raw
        .rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse::<u64>()?;
    Ok(p["start_ticks"] == ticks)
}
fn exit_events(records: &[Value], boot_id: &str) -> Result<Value> {
    let mut start = None;
    let mut end = None;
    for e in records {
        ensure!(
            e["_PID"] == "1"
                && e["_BOOT_ID"] == boot_id
                && e["UNIT"] == UNIT
                && e["INVOCATION_ID"] == IID,
            "foreign manager record"
        );
        match e["MESSAGE_ID"].as_str() {
            Some(STARTED) => {
                ensure!(
                    start.replace(e["__MONOTONIC_TIMESTAMP"].clone()).is_none(),
                    "duplicate start"
                );
            }
            Some(SUCCEEDED) => {
                ensure!(end.replace(e.clone()).is_none(), "duplicate success");
            }
            Some(STOPPING | FAILED) => {
                anyhow::bail!("explicit stop or failure needs repair review")
            }
            Some(PROCESS_EXITED) => ensure!(
                e["EXIT_CODE"] == "exited" && e["EXIT_STATUS"] == "0",
                "abnormal exit"
            ),
            _ => {}
        }
    }
    let end = end.context("original node has no PID 1 success record")?;
    let start = start.context("original node has no PID 1 start record")?;
    ensure!(
        s(&start)?.parse::<u64>()? < s(&end["__MONOTONIC_TIMESTAMP"])?.parse::<u64>()?,
        "terminal time precedes start"
    );
    Ok(end)
}
fn checked_live() -> Result<Value> {
    let path = Path::new(ROOT).join("LIVE.json");
    let bytes = small(&path, 1 << 20)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == LIVE_SHA && path.symlink_metadata()?.uid() == 0,
        "incorrect live witness"
    );
    let live: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        live["epoch"] == EPOCH
            && live["native"]["manager"]["Id"] == UNIT
            && live["native"]["manager"]["InvocationID"] == IID,
        "foreign native generation"
    );
    Ok(live)
}
fn closed(live: &Value) -> Result<BTreeMap<String, String>> {
    let v = show(UNIT)?;
    ensure!(
        v.get("ActiveState").is_some_and(|v| v == "inactive")
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"].is_empty()
            && v["NRestarts"] == "0",
        "{EPOCH} node or control still active, failed, or queued"
    );
    ensure!(
        v["InvocationID"].is_empty() || v["InvocationID"] == IID,
        "unit has another invocation"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    ensure!(
        !group.try_exists()?
            && !process_bound(&live["native"]["parent"])?
            && !process_bound(&live["native"]["worker"])?,
        "{EPOCH} process or cgroup remains"
    );
    Ok(v)
}
fn complete(live: &Value) -> Result<Value> {
    let state = closed(live)?;
    let boot = s(&live["boot_id"])?.replace('-', "");
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "")
            == boot,
        "host boot generation changed"
    );
    let text = run(
        "/usr/bin/journalctl",
        &[
            "--no-pager",
            "--all",
            "-o",
            "json",
            "--output-fields=_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS",
            &format!("_BOOT_ID={boot}"),
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
        ],
    )?;
    let records = text
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<Vec<Value>, _>>()?;
    let event = exit_events(&records, &boot)?;
    #[cfg(not(any(
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    )))]
    let evidence = receipt::inspect(live)?;
    #[cfg(any(
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    let evidence = receipt::inspect_with_boundary(live, &generation::boundary(live)?)?;
    ensure!(
        closed(live)? == state,
        "unit changed during terminal capture"
    );
    Ok(
        json!({"schema":format!("terminal{EPOCH}-success-v1"),"epoch":EPOCH,"producer_invocation_id":IID,
        "live":{"path":Path::new(ROOT).join("LIVE.json"),"sha256":LIVE_SHA},"source_admission":live["admission"],
        (format!("terminal_{EPOCH}_disposition")):"node-published-local-cohort","local_archive":evidence["local_archive"],"committed_receipt":evidence["committed_receipt"],"transaction_id":evidence["transaction_id"],
        "producer_log":evidence["producer_log"],"manager_terminal":event,"producer_unit":UNIT,"resource_credit_bytes":0,"reservation_ending_bytes":0,
        "archive_publication_authorized":false,"new_producer_authorized":false,"canonical_r2_verified":false}),
    )
}
fn record(value: &Value) -> Result<()> {
    let root = Path::new(ROOT);
    let meta = root.symlink_metadata()?;
    ensure!(
        root.canonicalize()? == root
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0
            && unsafe { libc::geteuid() } == 0,
        "private root-owned directory required"
    );
    let path = root.join("TERMINAL_SUCCESS.json");
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    publish_exact(&path, &bytes)
}
fn publish_exact(path: &Path, bytes: &[u8]) -> Result<()> {
    let root = path.parent().context("receipt directory")?;
    if path.try_exists()? {
        ensure!(
            small(path, 1 << 20)? == bytes,
            "conflicting terminal evidence"
        );
        return Ok(());
    }
    let tmp = root.join(format!(
        ".{}-{}.partial",
        path.file_name().context("receipt name")?.to_string_lossy(),
        std::process::id()
    ));
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&tmp)?;
    let result = (|| -> Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        // Publish without replacing an existing receipt.
        let old = std::ffi::CString::new(tmp.as_os_str().as_encoded_bytes())?;
        let new = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
        if unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                old.as_ptr(),
                libc::AT_FDCWD,
                new.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } < 0
        {
            let e = std::io::Error::last_os_error();
            ensure!(
                e.kind() == std::io::ErrorKind::AlreadyExists && small(path, 1 << 20)? == bytes,
                "terminal publish: {e}"
            );
        }
        fs::File::open(root)?.sync_all()?;
        Ok(())
    })();
    if tmp.try_exists()? {
        fs::remove_file(tmp)?;
    }
    result
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    if args == ["inspect-live-namespace"] {
        println!("{}", generation::live_namespace(&checked_live()?)?);
        return Ok(());
    }
    #[cfg(not(any(
        feature = "retry10",
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    )))]
    if let [mode, path] = args.as_slice()
        && matches!(mode.as_str(), "inspect-cadence" | "dispatch-cadence")
    {
        println!(
            "{}",
            cadence::select(Path::new(path), mode == "dispatch-cadence")?
        );
        return Ok(());
    }
    #[cfg(any(
        feature = "retry10",
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    if args == ["wait-record"] {
        let value = wait::committed(&checked_live()?)?;
        record(&value)?;
        println!("{}", serde_json::to_string(&value)?);
        return Ok(());
    }
    ensure!(
        args.len() == 1 && matches!(args[0].as_str(), "inspect" | "record"),
        "usage: terminal166 inspect|record"
    );
    let live = checked_live()?;
    if args[0] == "inspect"
        && (process_bound(&live["native"]["parent"])? || process_bound(&live["native"]["worker"])?)
    {
        let current = show(UNIT)?;
        ensure!(
            current["InvocationID"] == IID && current["NRestarts"] == "0",
            "unexpected producer invocation"
        );
        println!(
            "{}",
            json!({"epoch":EPOCH,"outcome":"awaiting-original-node-exit","node_alive":process_bound(&live["native"]["parent"])?,"worker_alive":process_bound(&live["native"]["worker"])?,"resource_credit_bytes":0})
        );
        return Ok(());
    }
    let evidence = complete(&live)?;
    if args[0] == "record" {
        record(&evidence)?;
    }
    println!("{}", serde_json::to_string(&evidence)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_ordered_success_from_the_original_manager_generation_passes() {
        let event = |id: &str, t: &str| json!({"_PID":"1","_BOOT_ID":"boot","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE_ID":id,"__MONOTONIC_TIMESTAMP":t});
        let start = event(STARTED, "20");
        let finish = event(SUCCEEDED, "30");
        assert!(exit_events(&[start.clone(), finish.clone()], "boot").is_ok());
        for bad in [
            event(FAILED, "25"),
            event(STOPPING, "25"),
            event(PROCESS_EXITED, "25"),
            event(STARTED, "21"),
            event(SUCCEEDED, "26"),
        ] {
            assert!(exit_events(&[start.clone(), bad, finish.clone()], "boot").is_err());
        }
        assert!(exit_events(std::slice::from_ref(&start), "boot").is_err());
        assert!(exit_events(&[start.clone(), event(SUCCEEDED, "5")], "boot").is_err());
        assert!(exit_events(&[start, finish], "another-boot").is_err());
    }
}
