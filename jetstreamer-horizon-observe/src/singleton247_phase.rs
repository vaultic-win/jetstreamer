//! Closed post-firehose phase evidence. Never proves terminal/drain or publication.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command};

pub const UNIT: &str = "horizon-qualify-247-reboot-20261117-v2.service";
pub const IID: &str = "d091bb68ff2648159c76f690b3b7fee3";
pub const PID: u64 = 50887;
pub const NODE: &str =
    "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node";
const NODE_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
const COMMAND: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 247 /home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon247-controls0345-v1/preflight-247-target1.json --cohort-manifest-fingerprint=sha256:12070bfb11a9153cd41b0d1179397947fd718e9891849d2e9a793d02dba098f3 --snapshot-archive=/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst";
const MARKER: &str = "jetstreamer::firehose] 🚒 firehose finished successfully.";

pub fn validate_owner(u: &Value) -> Result<()> {
    for (k, v) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", IID),
        ("MainPID", "50887"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
    ] {
        ensure!(u[k] == v, "epoch247 finalization owner differs: {k}");
    }
    ensure!(
        u["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "epoch247 finalization cgroup differs"
    );
    let command = u["ExecStart"].as_str().context("missing ExecStart")?;
    ensure!(
        command.starts_with(&format!(
            "{{ path={NODE} ; argv[]={COMMAND} ; ignore_errors=no ; start_time="
        )) && command.matches("{ path=").count() == 1,
        "epoch247 finalization command differs"
    );
    Ok(())
}
fn immutable_node() -> Result<()> {
    let p = Path::new(NODE);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 256 << 20,
        "unsafe epoch247 node"
    );
    let bytes = fs::read(p)?;
    let end = fs::symlink_metadata(p)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && m.dev() == end.dev()
            && m.ino() == end.ino()
            && m.len() == end.len()
            && m.mtime() == end.mtime()
            && m.mtime_nsec() == end.mtime_nsec()
            && format!("{:x}", Sha256::digest(&bytes)) == NODE_SHA,
        "epoch247 node changed"
    );
    let proc = Path::new("/proc").join(PID.to_string()).join("exe");
    let mapped = fs::metadata(&proc)?;
    ensure!(
        fs::read_link(&proc)? == p && mapped.dev() == m.dev() && mapped.ino() == m.ino(),
        "epoch247 mapped node differs"
    );
    Ok(())
}
pub fn select_event(records: &[Value], sample: u64) -> Result<Option<Value>> {
    let mut selected = None;
    for r in records {
        if !r["MESSAGE"].as_str().is_some_and(|s| s.ends_with(MARKER)) {
            continue;
        }
        ensure!(
            r["_SYSTEMD_UNIT"] == UNIT
                && r["_SYSTEMD_INVOCATION_ID"] == IID
                && r["_PID"] == "50887"
                && r["_UID"] == "1000"
                && r["_EXE"] == NODE
                && r["_CMDLINE"] == COMMAND,
            "unbound epoch247 firehose event"
        );
        let micros = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("phase timestamp missing")?
            .parse::<u64>()?;
        ensure!(micros > 0, "zero phase timestamp");
        if micros / 1_000_000 > sample {
            continue;
        }
        ensure!(selected.is_none(), "duplicate epoch247 firehose event");
        selected = Some(
            json!({"event":r,"sampled_unix_seconds":sample,"phase":"producer-finalization","ordinary_replay_claim":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false}),
        );
    }
    Ok(selected)
}
pub fn capture(u: &Value, sample: u64) -> Result<Option<Value>> {
    validate_owner(u)?;
    immutable_node()?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--unit",
            UNIT,
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            "--grep",
            "firehose finished successfully",
            "--since",
            "2026-11-19 14:50:00 UTC",
            "--until",
            &format!("@{sample}"),
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "epoch247 phase journal failed/oversized"
    );
    let records = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    select_event(&records, sample)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Value {
        json!({"MESSAGE":format!("[x INFO {MARKER}"),"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,"_PID":"50887","_UID":"1000","_EXE":NODE,"_CMDLINE":COMMAND,"__REALTIME_TIMESTAMP":"1795100497145709"})
    }
    #[test]
    fn exact_phase_event_is_not_a_terminal_or_release_claim() {
        let r = record();
        assert!(
            select_event(std::slice::from_ref(&r), 1795100496)
                .unwrap()
                .is_none()
        );
        let p = select_event(std::slice::from_ref(&r), 1795100497)
            .unwrap()
            .unwrap();
        for key in [
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "ordinary_replay_claim",
        ] {
            assert_eq!(p[key], false);
        }
        assert!(select_event(&[r.clone(), r], 1795100498).is_err());
    }
    #[test]
    fn substituted_event_identity_or_missing_clock_fails_closed() {
        for key in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_EXE",
            "_CMDLINE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut r = record();
            r[key] = json!("wrong");
            assert!(select_event(&[r], u64::MAX).is_err(), "{key}");
        }
        assert!(select_event(&[], u64::MAX).unwrap().is_none());
    }
    #[test]
    fn exact_owner_rejects_restart_command_and_state_changes() {
        let u = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"active","SubState":"running","InvocationID":IID,"MainPID":"50887","ControlPID":"0","NRestarts":"0","ControlGroup":format!("/system.slice/{UNIT}"),"ExecStart":format!("{{ path={NODE} ; argv[]={COMMAND} ; ignore_errors=no ; start_time=[x] }}")});
        validate_owner(&u).unwrap();
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "InvocationID",
            "MainPID",
            "ControlPID",
            "NRestarts",
            "ControlGroup",
            "ExecStart",
        ] {
            let mut bad = u.clone();
            bad[key] = json!("wrong");
            assert!(validate_owner(&bad).is_err(), "{key}");
        }
    }
}
