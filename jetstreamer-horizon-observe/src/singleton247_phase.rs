//! Closed post-firehose phase evidence. Never proves terminal/drain or publication.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::MetadataExt, path::Path, process::Command};

#[derive(Clone, Copy, Debug)]
pub struct Profile {
    pub epoch: u64,
    pub unit: &'static str,
    pub iid: &'static str,
    pub pid: u64,
    pub node: &'static str,
    pub node_sha: &'static str,
    pub command: &'static str,
}
pub fn profile(epoch: u64) -> Result<Profile> {
    Ok(match epoch {
        247 => Profile {
            epoch: 247,
            unit: "horizon-qualify-247-reboot-20261117-v2.service",
            iid: "d091bb68ff2648159c76f690b3b7fee3",
            pid: 50887,
            node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
            node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
            command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 247 /home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon247-controls0345-v1/preflight-247-target1.json --cohort-manifest-fingerprint=sha256:12070bfb11a9153cd41b0d1179397947fd718e9891849d2e9a793d02dba098f3 --snapshot-archive=/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst",
        },
        248 => Profile {
            epoch: 248,
            unit: "horizon-qualify-248-reboot-20261117-v1.service",
            iid: "16f84e36b65645a7be7d28d08e3d40cc",
            pid: 74807,
            node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
            node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
            command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 248 /home/ubuntu/.jetstreamer-private/qualification-248-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon248-controls2402-v1/preflight-248-target1.json --cohort-manifest-fingerprint=sha256:0d1fff23b95c5b9c462af81387414c13c10a1fdce6699d5a4bd204bcf7719bbf --snapshot-archive=/var/lib/jetstreamer/horizon248-bootstrap-copy2454-work-v1/projection/bootstrap/snapshot-107135393-BvNzVFUVa9kQwGJQxKFyDVPcBd8yVRbVDaN8YLr28i95.tar.zst",
        },
        249 => Profile {
            epoch: 249,
            unit: "horizon-qualify-249-reboot-20261117-v1.service",
            iid: "dbf4a4d19de84f31b3897da87622156e",
            pid: 86201,
            node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
            node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
            command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 249 /home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json --cohort-manifest-fingerprint=sha256:1eba23638b04526c0ee06e2ddda702eb21c3e9bedb7010729d430b1443d080bc --snapshot-archive=/var/lib/jetstreamer/horizon-contiguous-249-251-current-46b4b4a-v1/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst",
        },
        250 => Profile {
            epoch: 250,
            unit: "horizon-qualify-250-reboot-20261117-v1.service",
            iid: "a59fe93cc1d443abbb33317600227600",
            pid: 473260,
            node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
            node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
            command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 250 /home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json --cohort-manifest-fingerprint=sha256:7517bfa7560d6d353cd7c683b1491195ccb5fec689a57e2e1a6bb099fe3e7bc4 --snapshot-archive=/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-107999217-4GDh8KkBUc2Yj6Xa3qLWGVkNSm44i4XSk8PXWSN2s274.tar.zst",
        },
        251 => Profile {
            epoch: 251,
            unit: "horizon-qualify-251-replacement-20261118-v1.service",
            iid: "cd2477bfec7f4e498545762c633e7bb0",
            pid: 760779,
            node: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node",
            node_sha: "02f42f2988dd31437e2c874414f247667200663c874042783406b5517b0d519b",
            command: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node 251 /home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json --cohort-manifest-fingerprint=sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e --snapshot-archive=/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
        },
        _ => anyhow::bail!("unqualified singleton finalization epoch"),
    })
}
const MARKER: &str = "jetstreamer::firehose] 🚒 firehose finished successfully.";

pub fn validate_owner(p: Profile, u: &Value) -> Result<()> {
    let expected_pid = p.pid.to_string();
    for (k, v) in [
        ("Id", p.unit),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", p.iid),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
    ] {
        ensure!(u[k] == v, "singleton finalization owner differs: {k}");
    }
    ensure!(
        u["MainPID"].as_str() == Some(expected_pid.as_str()),
        "singleton finalization PID differs"
    );
    ensure!(
        u["ControlGroup"] == format!("/system.slice/{}", p.unit),
        "singleton finalization cgroup differs"
    );
    let command = u["ExecStart"].as_str().context("missing ExecStart")?;
    ensure!(
        command.starts_with(&format!(
            "{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=",
            p.node, p.command
        )) && command.matches("{ path=").count() == 1,
        "singleton finalization command differs"
    );
    Ok(())
}
fn immutable_node(p: Profile) -> Result<()> {
    let node = Path::new(p.node);
    let m = fs::symlink_metadata(node)?;
    ensure!(
        node.canonicalize()? == node
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 256 << 20,
        "unsafe singleton node"
    );
    let bytes = fs::read(node)?;
    let end = fs::symlink_metadata(node)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && m.dev() == end.dev()
            && m.ino() == end.ino()
            && m.len() == end.len()
            && m.mtime() == end.mtime()
            && m.mtime_nsec() == end.mtime_nsec()
            && format!("{:x}", Sha256::digest(&bytes)) == p.node_sha,
        "singleton node changed"
    );
    let proc = Path::new("/proc").join(p.pid.to_string()).join("exe");
    let mapped = fs::metadata(&proc)?;
    ensure!(
        fs::read_link(&proc)? == node && mapped.dev() == m.dev() && mapped.ino() == m.ino(),
        "singleton mapped node differs"
    );
    Ok(())
}
pub fn select_event(p: Profile, records: &[Value], sample: u64) -> Result<Option<Value>> {
    let mut selected = None;
    let expected_pid = p.pid.to_string();
    for r in records {
        if !r["MESSAGE"].as_str().is_some_and(|s| s.ends_with(MARKER)) {
            continue;
        }
        ensure!(
            r["_SYSTEMD_UNIT"] == p.unit
                && r["_SYSTEMD_INVOCATION_ID"] == p.iid
                && r["_PID"].as_str() == Some(expected_pid.as_str())
                && r["_UID"] == "1000"
                && r["_EXE"] == p.node
                && r["_CMDLINE"] == p.command,
            "unbound singleton firehose event"
        );
        let micros = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("phase timestamp missing")?
            .parse::<u64>()?;
        ensure!(micros > 0, "zero phase timestamp");
        if micros / 1_000_000 > sample {
            continue;
        }
        ensure!(selected.is_none(), "duplicate singleton firehose event");
        selected = Some(
            json!({"epoch":p.epoch,"event":r,"sampled_unix_seconds":sample,"phase":"producer-finalization","ordinary_replay_claim":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false}),
        );
    }
    Ok(selected)
}
pub fn capture(p: Profile, u: &Value, sample: u64) -> Result<Option<Value>> {
    validate_owner(p, u)?;
    immutable_node(p)?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--unit",
            p.unit,
            &format!("_SYSTEMD_INVOCATION_ID={}", p.iid),
            "--grep",
            "firehose finished successfully",
            "--since",
            "2026-11-19 14:50:00 UTC",
            "--until",
            &format!("@{sample}"),
        ])
        .output()?;
    validate_journal_result(out.status.code(), &out.stdout, &out.stderr)?;
    let records = out
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    select_event(p, &records, sample)
}
fn validate_journal_result(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> Result<()> {
    // journalctl --grep returns 1 when no record matches. An advancing replay
    // normally has no completion marker; that empty result is not a failure.
    ensure!(
        (code == Some(0) || (code == Some(1) && stdout.is_empty() && stderr.is_empty()))
            && stdout.len() <= 1 << 20,
        "singleton phase journal failed/oversized"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn journal_no_match_is_empty_but_actual_failures_remain_errors() {
        assert!(validate_journal_result(Some(1), b"", b"").is_ok());
        assert!(validate_journal_result(Some(0), b"{}\n", b"").is_ok());
        assert!(validate_journal_result(Some(1), b"{}\n", b"").is_err());
        assert!(validate_journal_result(Some(1), b"", b"permission denied").is_err());
        assert!(validate_journal_result(Some(2), b"", b"").is_err());
        assert!(validate_journal_result(None, b"", b"").is_err());
        assert!(validate_journal_result(Some(0), &vec![0; (1 << 20) + 1], b"").is_err());
    }
    fn record(p: Profile) -> Value {
        json!({"MESSAGE":format!("[x INFO {MARKER}"),"_SYSTEMD_UNIT":p.unit,"_SYSTEMD_INVOCATION_ID":p.iid,"_PID":p.pid.to_string(),"_UID":"1000","_EXE":p.node,"_CMDLINE":p.command,"__REALTIME_TIMESTAMP":"1795100497145709"})
    }
    #[test]
    fn each_exact_phase_event_retains_reservations_and_cutoff() {
        for epoch in 247..=251 {
            let p = profile(epoch).unwrap();
            let r = record(p);
            assert!(
                select_event(p, std::slice::from_ref(&r), 1795100496)
                    .unwrap()
                    .is_none()
            );
            let proof = select_event(p, std::slice::from_ref(&r), 1795100497)
                .unwrap()
                .unwrap();
            assert_eq!(proof["epoch"], epoch);
            for key in [
                "terminal_completion_proven",
                "resource_release_authorized",
                "publication_authorized",
                "ordinary_replay_claim",
            ] {
                assert_eq!(proof[key], false);
            }
            assert!(select_event(p, &[r.clone(), r], 1795100498).is_err());
        }
    }
    #[test]
    fn each_substituted_event_identity_or_missing_clock_fails_closed() {
        for epoch in 247..=251 {
            let p = profile(epoch).unwrap();
            for key in [
                "_SYSTEMD_UNIT",
                "_SYSTEMD_INVOCATION_ID",
                "_PID",
                "_UID",
                "_EXE",
                "_CMDLINE",
                "__REALTIME_TIMESTAMP",
            ] {
                let mut r = record(p);
                r[key] = json!("wrong");
                assert!(select_event(p, &[r], u64::MAX).is_err(), "{epoch}/{key}");
            }
            assert!(select_event(p, &[], u64::MAX).unwrap().is_none());
            let other = profile(if epoch == 247 { 248 } else { 247 }).unwrap();
            assert!(select_event(p, &[record(other)], u64::MAX).is_err());
        }
        assert!(profile(246).is_err());
        assert!(profile(252).is_err());
    }
    #[test]
    fn each_exact_owner_rejects_restart_command_and_state_changes() {
        for epoch in 247..=251 {
            let p = profile(epoch).unwrap();
            let u = json!({"Id":p.unit,"LoadState":"loaded","ActiveState":"active","SubState":"running","InvocationID":p.iid,"MainPID":p.pid.to_string(),"ControlPID":"0","NRestarts":"0","ControlGroup":format!("/system.slice/{}",p.unit),"ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=[x] }}",p.node,p.command)});
            validate_owner(p, &u).unwrap();
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
                assert!(validate_owner(p, &bad).is_err(), "{epoch}/{key}");
            }
        }
    }
}
