//! Read-only qualification of one stopped epoch169 partial for potential holding.
//! No retirement, canonical publication, resource credit or replay authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const RUN: &str = "/home/sol/.jetstreamer-private/epoch169-standard-lane-20261109-v1/replacement-local2-20261110-v1/private/destination-99fd88ae3977469031317185e462e9adc14336d9b131d4b9afdcf5f5d91203fa/work/root-cohort-169-169/run-1123930-1794344387009889404";
const OUTPUT: &str =
    "/var/lib/jetstreamer/epoch169-local2-holding-review-20261119-v1/INSPECTION.json";
const LENGTH: u64 = 56_565_561_764;

fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.blocks(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn closed() -> Result<Value> {
    let mut evidence = Vec::new();
    for unit in [
        "horizon-qualify-169-replacement-local2-20261110-v1.service",
        "horizon-guard-replacement-169-local2-20261110-v1.service",
        "horizon-guard-replacement-169-local2-20261110-v1.timer",
    ] {
        let result = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-pId,ActiveState,SubState,MainPID,ControlPID,Job,InvocationID",
            ])
            .output()?;
        ensure!(
            result.status.success() && result.stderr.is_empty(),
            "native unit query failed"
        );
        let s = String::from_utf8(result.stdout)?;
        let mut fields = serde_json::Map::new();
        for line in s.lines() {
            let (key, value) = line.split_once('=').context("unit field")?;
            ensure!(
                fields.insert(key.into(), json!(value)).is_none(),
                "duplicate field"
            );
        }
        let v = Value::Object(fields);
        ensure!(
            v["Id"] == unit
                && v["ActiveState"] == "inactive"
                && v["SubState"] == "dead"
                && v["Job"] == ""
                && (v["MainPID"].is_null() || v["MainPID"] == "0")
                && (v["ControlPID"].is_null() || v["ControlPID"] == "0"),
            "owner is not closed: {unit}"
        );
        evidence.push(v);
    }
    Ok(json!(evidence))
}
fn references() -> Result<Value> {
    let processes =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), Path::new(RUN))?;
    let staged =
        jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(Path::new(RUN))?;
    Ok(json!({"processes":processes,"staged":staged}))
}
fn main() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && std::env::args().len() == 1,
        "root; no arguments"
    );
    let output = Path::new(OUTPUT);
    let parent = output.parent().context("output parent")?;
    let parent_md = fs::symlink_metadata(parent)?;
    ensure!(
        parent_md.is_dir()
            && parent_md.uid() == 0
            && parent_md.mode() & 0o7777 == 0o700
            && parent.canonicalize()? == parent
            && fs::read_dir(parent)?.next().is_none(),
        "empty root metadata leaf required"
    );
    let path = Path::new(RUN).join("archives/epoch-169.jet");
    ensure!(path.canonicalize()? == path, "canonical source required");
    let before = fs::symlink_metadata(&path)?;
    ensure!(
        before.is_file()
            && before.dev() == 64512
            && before.ino() == 105710021
            && before.len() == LENGTH
            && before.blocks() == 110479776
            && before.uid() == 1001
            && before.gid() == 1003
            && before.mode() & 0o7777 == 0o600
            && before.nlink() == 1,
        "exact source identity changed"
    );
    ensure!(
        !path.with_extension("jet.sha256").try_exists()?,
        "unexpected readiness sidecar"
    );
    let closed_before = closed()?;
    let refs_before = references()?;
    // Preserve negative consumer findings too; do not hash an actively used candidate.
    let clean = refs_before["processes"]["references"] == json!([])
        && refs_before["staged"]["references"] == json!([]);
    let mut digest = None;
    if clean {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        ensure!(
            identity(&file.metadata()?) == identity(&before),
            "source changed before hash"
        );
        let mut hash = Sha256::new();
        let mut buffer = vec![0; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            total = total.checked_add(n as u64).context("length overflow")?;
            ensure!(total <= LENGTH, "source grew");
            hash.update(&buffer[..n]);
        }
        ensure!(
            total == LENGTH && identity(&file.metadata()?) == identity(&before),
            "source changed while hashing"
        );
        digest = Some(format!("{:x}", hash.finalize()));
    }
    let closed_after = closed()?;
    let refs_after = references()?;
    ensure!(
        closed_before == closed_after
            && identity(&fs::symlink_metadata(&path)?) == identity(&before),
        "candidate changed"
    );
    let clear_after = refs_after["processes"]["references"] == json!([])
        && refs_after["staged"]["references"] == json!([]);
    let evidence = json!({"schema":"horizon-epoch169-local2-closed-prefix-inspection-v1",
        "owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "source":path,"source_identity":identity(&before),"length":LENGTH,"sha256":digest,
        "source_stable":true,"native_owners":closed_after,"references_before":refs_before,"references_after":refs_after,
        "native_consumers_clear":clean&&clear_after,"complete_transitive_consumer_graph_qualified":false,
        "holding_custody_exists":false,"local_retirement_authorized":false,"canonical_publication_authorized":false,
        "replay_launch_authorized":false,"resource_credit_bytes":0,"remote_mutations":false});
    let bytes = serde_json::to_vec_pretty(&evidence)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"receipt":output,"sha256":format!("{:x}",Sha256::digest(&bytes)),
        "native_consumers_clear":clean&&clear_after,"local_retirement_authorized":false})
    );
    Ok(())
}
