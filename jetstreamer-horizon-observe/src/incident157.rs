//! Exact read-only capture of the collected157 missing-terminal incident.
//! No service changes, replay, resource sample, deletion, or network access.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
};
const PRODUCER: &str = "jetstreamer-root-sweep-e157-t3-20261014-v1-r2-e157-157-lane-j-1.service";
const IID: &str = "d66eddeac8304adfbd17e4ebe1c6c1f9";
const CONTROLLER: &str = "jetstreamer-epoch157-target3-controller-v1-r2.service";
const CONTROLLER_IID: &str = "fcba4ece12fa462faf9062a3ad607879";
const STATE: &str = "/var/lib/jetstreamer-root-sweep-epoch157-target3-20261014-v1/state.json";
const HASHES: &str = "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output/.epoch-157-runtime-segment-hashes.txt";
const ERROR: &str = "qualification requires the exact canonical terminal checkpoint at slot 68255999; none was supplied";
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn stable(path: &Path, private: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical157input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.len() <= 16 << 20
            && a.mode() & 0o022 == 0
            && (!private || (a.uid() == 0 && a.mode() & 0o077 == 0)),
        "unsafe157input"
    );
    let mut b = Vec::new();
    f.read_to_end(&mut b)?;
    let c = f.metadata()?;
    let d = fs::symlink_metadata(path)?;
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(id(&a) == id(&c) && id(&a) == id(&d), "157input changed");
    Ok(b)
}
fn unit(name: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager","--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,MainPID,Result,ExecMainStatus,ExecStart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 65536,
        "157unit probe failed"
    );
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("157unit field")?;
        ensure!(fields.insert(k, v).is_none(), "duplicate157field");
    }
    Ok(serde_json::to_value(fields)?)
}
fn validate(
    state: &Value,
    controller: &Value,
    producer: &Value,
    records: &[Value],
    hashes: &str,
) -> Result<()> {
    let a = &state["assignments"]["lane-j"];
    ensure!(
        state["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && state["configuration_sha256"]
                == "351fc1d59dcb160b9557a512e6b5c53a217c468475bd4ffee00c71b716188e10"
            && a["first_epoch"] == 157
            && a["last_epoch"] == 157
            && a["phase"] == "failed"
            && a["unit"] == PRODUCER
            && a["pid"] == 1725802
            && a["pid_start_time"] == 47872133
            && a["failure"] == "producer ended without one live v2 receipt",
        "157not exact quarantined assignment"
    );
    ensure!(
        controller["Id"] == CONTROLLER
            && controller["InvocationID"] == CONTROLLER_IID
            && controller["NRestarts"] == "0"
            && controller["ActiveState"] == "active"
            && controller["ExecStart"]
                .as_str()
                .is_some_and(|s| !s.contains("--retry-failed")),
        "157controller changed or retry armed"
    );
    ensure!(
        producer["LoadState"] == "not-found"
            && producer["ActiveState"] == "inactive"
            && producer["MainPID"] == "0"
            && producer["InvocationID"] == "",
        "157producer live or replaced"
    );
    let errors = records
        .iter()
        .filter(|r| r["MESSAGE"].as_str().is_some_and(|s| s.contains(ERROR)))
        .count();
    ensure!(
        errors == 2
            && records.iter().all(|r| r["_SYSTEMD_UNIT"] == PRODUCER
                && r["_SYSTEMD_INVOCATION_ID"] == IID
                && r["_UID"] == "1001")
            && records.iter().any(|r| r["_PID"] == "1725802"
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|s| s.contains("runtime segment 1 failed after 2 attempt(s)"))),
        "157journal lacks exact terminal failure"
    );
    ensure!(
        hashes.lines().count() == 3
            && hashes
                .contains("snapshot-68140176-3TNSv7MXDB4GxhyRyHJcuBNeXaumYC8W8vu5WrwCXhhZ.tar.bz2")
            && hashes
                .contains("snapshot-68255828-AVreSVPd46H4WiihQ2pFUcRExPRQwL1MxhzQHVGky8bH.tar.bz2")
            && !hashes.contains("snapshot-68255999-"),
        "157checkpoint input differs"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 4 && args[2] == "--self-sha256" && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch157-incident OUTPUT --self-sha256 HEX (root)"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == args[3],
        "157collector self hash differs"
    );
    let output = Path::new(&args[1]);
    let parent = output.parent().context("157output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && !output.try_exists()?,
        "unsafe or occupied157destination"
    );
    let state = stable(Path::new(STATE), true)?;
    let hashes = stable(Path::new(HASHES), false)?;
    let controller = unit(CONTROLLER)?;
    let producer = unit(PRODUCER)?;
    let journal = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            "--since=2026-10-21 15:04:14 UTC",
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
        ])
        .output()?;
    ensure!(
        journal.status.success() && journal.stdout.len() <= 16 << 20,
        "157journal capture failed/oversized"
    );
    let text = std::str::from_utf8(&journal.stdout)?;
    let records: Vec<Value> = text
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    let parsed: Value = serde_json::from_slice(&state)?;
    validate(
        &parsed,
        &controller,
        &producer,
        &records,
        std::str::from_utf8(&hashes)?,
    )?;
    ensure!(
        state == stable(Path::new(STATE), true)?
            && hashes == stable(Path::new(HASHES), false)?
            && controller == unit(CONTROLLER)?
            && producer == unit(PRODUCER)?,
        "157capture ownership/input race"
    );
    let receipt = json!({"schema":"jetstreamer-epoch157-missing-terminal-incident-v1","host":"dev-samjohnson","epoch":157,
        "collector_sha256":args[3],"producer_invocation_id":IID,"controller":controller,"producer":producer,
        "controller_state":parsed,"controller_state_sha256":sha(&state),"journal_raw_utf8":text,"journal_sha256":sha(&journal.stdout),
        "journal_entry_count":records.len(),"checkpoint_list_utf8":std::str::from_utf8(&hashes)?,"checkpoint_list_sha256":sha(&hashes),
        "failure":{"kind":"missing-canonical-terminal-checkpoint","slot":68255999,"last_trusted_root":68255828,"message":ERROR},
        "retry_path_quarantined":true,"original_prefix_and_snapshot_must_be_preserved":true,
        "replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"service_mutations":false,"resource_samples":0,"r2_mutations":false});
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &receipt)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("157incident capture failed closed: {e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Vec<Value>, String) {
        let state = json!({"schema":"jetstreamer-adaptive-root-cohort-sweep-v3",
            "configuration_sha256":"351fc1d59dcb160b9557a512e6b5c53a217c468475bd4ffee00c71b716188e10",
            "assignments":{"lane-j":{"first_epoch":157,"last_epoch":157,"phase":"failed","unit":PRODUCER,
                "pid":1725802,"pid_start_time":47872133,"failure":"producer ended without one live v2 receipt"}}});
        let controller = json!({"Id":CONTROLLER,"InvocationID":CONTROLLER_IID,"NRestarts":"0","ActiveState":"active","ExecStart":"sealed exact command"});
        let producer = json!({"LoadState":"not-found","ActiveState":"inactive","MainPID":"0","InvocationID":""});
        let records=[ERROR,ERROR,"runtime segment 1 failed after 2 attempt(s)"].into_iter().map(|message|json!({"MESSAGE":message,"_SYSTEMD_UNIT":PRODUCER,"_SYSTEMD_INVOCATION_ID":IID,"_UID":"1001","_PID":"1725802"})).collect();
        let hashes="snapshot-67823809-bootstrap.tar.bz2\nsnapshot-68140176-3TNSv7MXDB4GxhyRyHJcuBNeXaumYC8W8vu5WrwCXhhZ.tar.bz2\nsnapshot-68255828-AVreSVPd46H4WiihQ2pFUcRExPRQwL1MxhzQHVGky8bH.tar.bz2\n".into();
        (state, controller, producer, records, hashes)
    }
    #[test]
    fn exact_quarantine_requires_real_missing_root_and_both_failed_attempts() {
        let (state, controller, producer, records, hashes) = fixture();
        validate(&state, &controller, &producer, &records, &hashes).unwrap();
        assert!(validate(&state, &controller, &producer, &records[..2], &hashes).is_err());
        assert!(validate(&state, &controller, &producer, &records[1..], &hashes).is_err());
        let mut bad = state.clone();
        bad["assignments"]["lane-j"]["phase"] = json!("producer");
        assert!(validate(&bad, &controller, &producer, &records, &hashes).is_err());
        let mut bad = controller.clone();
        bad["ExecStart"] = json!("--retry-failed");
        assert!(validate(&state, &bad, &producer, &records, &hashes).is_err());
        let mut bad = producer.clone();
        bad["MainPID"] = json!("1725802");
        assert!(validate(&state, &controller, &bad, &records, &hashes).is_err());
        let mut bad = records.clone();
        bad[0]["_SYSTEMD_INVOCATION_ID"] = json!(CONTROLLER_IID);
        assert!(validate(&state, &controller, &producer, &bad, &hashes).is_err());
        assert!(
            validate(
                &state,
                &controller,
                &producer,
                &records,
                &hashes.replace("68255828", "68255999")
            )
            .is_err()
        );
    }
    #[test]
    fn wrong_or_live_assignment_cannot_be_failure_proof() {
        assert!(validate(&json!({}), &json!({}), &json!({}), &[], "").is_err());
        assert_ne!(PRODUCER, CONTROLLER);
        assert_ne!(IID, CONTROLLER_IID);
    }
}
