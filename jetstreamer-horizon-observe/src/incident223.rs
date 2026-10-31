//! Exact terminal 223 evidence capture; never qualifies, deletes or retries work.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon-qualify-223-singleton-postcount-ad1d65a-v1.service";
const IID: &str = "04ef9d97a36446d49b452d982cb0be46";
const GUARD: &str = "horizon-223-singleton-guard-ad1d65a-v1.timer";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/singleton-223-postcount-ad1d65a-v1/private/destination-cdf56414a2668d0cccbbcba1765002397973c1cfaeda2df3a4dee4df1f51fd38/work/root-cohort-223-223/run-2560162-1792612414816300237/archives/epoch-223.jet";
const ERROR: &str = "historical execution mismatch at slot 96542806 entry 40 transaction 0 signature 2EZUUdThX1NSxiyFKnRS6Bn4ptkLAySmmCsQpVToH9MbjdkXEUYPLqzLumcLkG12FoNi4tNE2jrnxVfKigFNCdNu: expected None, got Some(InstructionError { instruction_index: 0, error: Custom(2) })";

fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn id(m: &fs::Metadata) -> (u64, u64, u64, u64, u32, u32, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.nlink(),
        m.uid(),
        m.mode(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn unit(name: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager","--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,MainPID,Result,ExecMainStatus,Restart,TriggeredBy"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 65536,
        "unit lookup failed"
    );
    let mut values = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("malformed unit property")?;
        ensure!(values.insert(k, v).is_none(), "duplicate property");
    }
    Ok(serde_json::to_value(values)?)
}
fn terminal(p: &Value, guard: &Value) -> Result<()> {
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("InvocationID", IID),
        ("NRestarts", "0"),
        ("MainPID", "0"),
        ("Result", "exit-code"),
        ("ExecMainStatus", "1"),
        ("Restart", "no"),
        ("TriggeredBy", ""),
    ] {
        ensure!(p[k] == v, "producer is live, changed or ambiguous: {k}");
    }
    ensure!(
        guard["Id"] == GUARD && guard["ActiveState"] == "inactive" && guard["SubState"] == "dead",
        "terminal producer guard timer is not stopped"
    );
    Ok(())
}
fn journal(records: &[Value]) -> Result<()> {
    ensure!(
        !records.is_empty() && records.len() <= 32,
        "invalid selected journal census"
    );
    let mut failures = 0;
    let mut bootstrap = 0;
    for r in records {
        ensure!(
            r["_SYSTEMD_UNIT"] == UNIT
                && r["_SYSTEMD_INVOCATION_ID"] == IID
                && r["_UID"] == "1000"
                && r["_PID"] == "2560162",
            "foreign selected journal owner"
        );
        let msg = r["MESSAGE"].as_str().context("missing journal message")?;
        if msg.contains(ERROR) {
            failures += 1;
        }
        if msg.contains("historical checkpoint slot=96335538 ")
            && msg.contains("accounts_hash=Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE ")
            && msg.contains(" writes=0 ")
        {
            bootstrap += 1;
        }
    }
    ensure!(
        failures == 2 && bootstrap == 1,
        "exact failure/bootstrap evidence absent or duplicate"
    );
    Ok(())
}
fn archive_hash(path: &Path) -> Result<Value> {
    ensure!(path.canonicalize()? == path, "archive path is noncanonical");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 1000
            && before.nlink() == 1
            && before.mode() & 0o077 == 0
            && before.len() > 0,
        "unsafe partial archive"
    );
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        bytes = bytes
            .checked_add(n as u64)
            .context("hash length overflow")?;
    }
    ensure!(
        bytes == before.len()
            && id(&before) == id(&f.metadata()?)
            && id(&before) == id(&fs::symlink_metadata(path)?),
        "partial changed during hash"
    );
    Ok(
        json!({"path":path,"sha256":format!("{:x}",hasher.finalize()),"bytes":bytes,"device":before.dev(),"inode":before.ino(),"preserve":true,"complete_archive":false,"validation_claimed":false}),
    )
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 4 && args[2] == "--self-sha256",
        "usage: OUTPUT --self-sha256 HEX (root)"
    );
    let self_bytes = fs::read("/proc/self/exe")?;
    ensure!(
        args[3].len() == 64 && digest(&self_bytes) == args[3],
        "wrong running executable"
    );
    let output = Path::new(&args[1]);
    ensure!(
        output.is_absolute()
            && output.file_name().and_then(|s| s.to_str()) == Some("incident.json")
            && output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer")),
        "output must be isolated private incident.json"
    );
    let parent = output.parent().context("missing output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && !output.try_exists()?,
        "unsafe or existing output"
    );
    let before = unit(UNIT)?;
    let guard = unit(GUARD)?;
    terminal(&before, &guard)?;
    let records = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--grep=historical checkpoint slot=|historical execution mismatch|abandoning replay",
            "--no-pager",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        records.status.success() && records.stdout.len() < 512 * 1024,
        "journal capture failed or oversized"
    );
    let selected: Vec<Value> = std::str::from_utf8(&records.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    journal(&selected)?;
    ensure!(
        !Path::new(&format!("{ARCHIVE}.sha256")).try_exists()?
            && !Path::new(&format!("{ARCHIVE}.segment.json")).try_exists()?,
        "partial unexpectedly has canonical or terminal evidence"
    );
    let archive = archive_hash(Path::new(ARCHIVE))?;
    let after = unit(UNIT)?;
    let guard_after = unit(GUARD)?;
    terminal(&after, &guard_after)?;
    ensure!(
        before == after && guard == guard_after,
        "owner changed while capturing evidence"
    );
    let receipt = json!({"schema":"jetstreamer-private-epoch223-terminal-vote-mismatch-v1","epoch":223,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"producer":after,"guard":guard_after,"journal_export_sha256":digest(&records.stdout),"selected_journal":selected,"failure_slot":96542806,"failure":ERROR,"partial_archive":archive,"self_sha256":args[3],"repair_closed":false,"source_cause_proven":false,"scratch_retirement_authorized":false,"archive_retirement_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &receipt)?;
    f.write_all(b"\n")?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("223 incident capture failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_partial_hash_rejects_symlink_and_hardlink() {
        if unsafe { libc::geteuid() } != 1000 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("partial.jet");
        fs::write(&p, b"retained partial, not verification evidence").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let got = archive_hash(&p).unwrap();
        assert_eq!(
            got["sha256"],
            digest(b"retained partial, not verification evidence")
        );
        assert_eq!(got["complete_archive"], false);
        let link = d.path().join("alias.jet");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(archive_hash(&link).is_err());
        fs::remove_file(&link).unwrap();
        fs::hard_link(&p, &link).unwrap();
        assert!(archive_hash(&p).is_err());
    }
    fn record(msg: &str) -> Value {
        json!({"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,"_UID":"1000","_PID":"2560162","MESSAGE":msg})
    }
    fn records() -> Vec<Value> {
        vec![
            record(
                "historical checkpoint slot=96335538 accounts_hash=Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE writes=0 next_write_version=1",
            ),
            record(ERROR),
            record(ERROR),
        ]
    }
    #[test]
    fn accepts_exact_failure_not_other_slot_signature_or_owner() {
        let good = records();
        journal(&good).unwrap();
        for (k, v) in [
            ("_SYSTEMD_INVOCATION_ID", "foreign"),
            ("_UID", "0"),
            ("MESSAGE", "other failure"),
        ] {
            let mut bad = good.clone();
            bad[1][k] = json!(v);
            assert!(journal(&bad).is_err());
        }
        let mut bad = good.clone();
        bad.push(good[1].clone());
        assert!(journal(&bad).is_err());
    }
    #[test]
    fn rejects_live_restarted_or_replaced_producer() {
        let mut p = json!({});
        for (k, v) in [
            ("Id", UNIT),
            ("LoadState", "loaded"),
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("InvocationID", IID),
            ("NRestarts", "0"),
            ("MainPID", "0"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("Restart", "no"),
            ("TriggeredBy", ""),
        ] {
            p[k] = json!(v);
        }
        let g = json!({"Id":GUARD,"ActiveState":"inactive","SubState":"dead"});
        terminal(&p, &g).unwrap();
        for (k, v) in [
            ("ActiveState", "active"),
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("Restart", "on-failure"),
            ("TriggeredBy", "retry.timer"),
        ] {
            let mut b = p.clone();
            b[k] = json!(v);
            assert!(terminal(&b, &g).is_err());
        }
        let mut b = g;
        b["ActiveState"] = json!("active");
        assert!(terminal(&p, &b).is_err());
    }
}
