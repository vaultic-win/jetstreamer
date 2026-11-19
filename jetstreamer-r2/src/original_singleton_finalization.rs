//! Exact original 248–251 post-firehose owners. EOF proves phase only, never
//! terminal processes, archive verification, publication or resource release.
use super::*;
use std::process::Command;

#[derive(Clone, Copy)]
struct Profile {
    epoch: u64,
    unit: &'static str,
    iid: &'static str,
    pid: u64,
    node: &'static str,
    node_sha: &'static str,
    command: &'static str,
    manifest: &'static str,
    manifest_sha: &'static str,
    terminal_slot: u64,
}
const PROFILES: [Profile; 4] = [
    Profile {
        epoch: 248,
        unit: "horizon-qualify-248-reboot-20261117-v1.service",
        iid: "16f84e36b65645a7be7d28d08e3d40cc",
        pid: 74807,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 248 /home/ubuntu/.jetstreamer-private/qualification-248-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon248-controls2402-v1/preflight-248-target1.json --cohort-manifest-fingerprint=sha256:0d1fff23b95c5b9c462af81387414c13c10a1fdce6699d5a4bd204bcf7719bbf --snapshot-archive=/var/lib/jetstreamer/horizon248-bootstrap-copy2454-work-v1/projection/bootstrap/snapshot-107135393-BvNzVFUVa9kQwGJQxKFyDVPcBd8yVRbVDaN8YLr28i95.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon248-controls2402-v1/preflight-248-target1.json",
        manifest_sha: "81d2f1bed8dd60b2553844c213ce2733c90f3ace94cb5d39a279c2b234178dc0",
        terminal_slot: 107567999,
    },
    Profile {
        epoch: 249,
        unit: "horizon-qualify-249-reboot-20261117-v1.service",
        iid: "dbf4a4d19de84f31b3897da87622156e",
        pid: 86201,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 249 /home/ubuntu/.jetstreamer-private/qualification-249-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json --cohort-manifest-fingerprint=sha256:1eba23638b04526c0ee06e2ddda702eb21c3e9bedb7010729d430b1443d080bc --snapshot-archive=/var/lib/jetstreamer/horizon-contiguous-249-251-current-46b4b4a-v1/snapshot-107567592-DBPics19TxLy8wawfQYvS65d72vKvFGLCW9HZv5q6GeH.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon249-controls2418-v1/preflight-249-target1.json",
        manifest_sha: "7245a95843d5866456f7c9b012e72b60ae8bfa7a7e68be61c1a1bbe29b30dc1b",
        terminal_slot: 107999999,
    },
    Profile {
        epoch: 250,
        unit: "horizon-qualify-250-reboot-20261117-v1.service",
        iid: "a59fe93cc1d443abbb33317600227600",
        pid: 473260,
        node: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node",
        node_sha: "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
        command: "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node 250 /home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json --cohort-manifest-fingerprint=sha256:7517bfa7560d6d353cd7c683b1491195ccb5fec689a57e2e1a6bb099fe3e7bc4 --snapshot-archive=/home/ubuntu/.jetstreamer-private/qualification-250-reboot-20261117-v1/input/snapshot-107999217-4GDh8KkBUc2Yj6Xa3qLWGVkNSm44i4XSk8PXWSN2s274.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon250-controls2402-v1/preflight-250-target1.json",
        manifest_sha: "fa914595e610da263d2d7eb22a4dc2a23eb7ad95665cc277459877bed7215cce",
        terminal_slot: 108431999,
    },
    Profile {
        epoch: 251,
        unit: "horizon-qualify-251-replacement-20261118-v1.service",
        iid: "cd2477bfec7f4e498545762c633e7bb0",
        pid: 760779,
        node: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node",
        node_sha: "02f42f2988dd31437e2c874414f247667200663c874042783406b5517b0d519b",
        command: "/var/lib/jetstreamer/horizon234-production-eabd0b6a-candidate922-v1/jetstreamer-node 251 /home/ubuntu/.jetstreamer-private/qualification-251-replacement-20261118-v1/output --verify --root-checkpoint-cohort --cohort-manifest=/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json --cohort-manifest-fingerprint=sha256:e214b640c55cc6ec0e431c66f9cbd0076c4620578c2dea1e6c2324e7f616789e --snapshot-archive=/var/lib/jetstreamer/horizon251-native-input-20261118-v1/snapshot-108431365-C5eqGwzDFEDfeBovidro6WnY3Drw7caJ2p2mjnJbGJVE.tar.zst",
        manifest: "/var/lib/jetstreamer/horizon251-single-epoch-manifest-20261118-v1/preflight-251-single-epoch.json",
        manifest_sha: "e40e8d0341440d29cff7cd35e79e5f713d7908ce42f3a1c4995e1b2924551f14",
        terminal_slot: 108863999,
    },
];
const SCHEMA: &str = "jetstreamer-original-singleton-finalization-events-v1";
const EOF: &str = "jetstreamer::firehose] 🚒 firehose finished successfully.";
fn profile(unit: &str) -> Option<Profile> {
    PROFILES.iter().copied().find(|p| p.unit == unit)
}
pub(super) fn scope(unit: &str) -> Option<u64> {
    profile(unit).map(|p| p.epoch)
}
pub(super) fn original_owner(unit: &str, iid: &str) -> bool {
    profile(unit).is_some_and(|p| p.iid == iid)
}
fn owner(p: Profile, current: &Value) -> Result<()> {
    let expected_pid = p.pid.to_string();
    for (key, expected) in [
        ("Id", p.unit),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", p.iid),
        ("NRestarts", "0"),
    ] {
        ensure!(
            current[key] == expected,
            "singleton finalization owner differs: {key}"
        );
    }
    ensure!(
        current["MainPID"].as_str() == Some(expected_pid.as_str()),
        "singleton finalization PID differs"
    );
    ensure!(
        current["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(prefix, rest)| prefix
                == format!("{{ path={} ; argv[]={}", p.node, p.command)
                && rest.starts_with("no ;")),
        "singleton finalization command differs"
    );
    Ok(())
}
fn inputs(p: Profile) -> Result<()> {
    for (path, digest, limit) in [
        (p.node, p.node_sha, 128 << 20),
        (p.manifest, p.manifest_sha, 1 << 20),
    ] {
        let path = Path::new(path);
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o222 == 0,
            "unsealed singleton finalization input"
        );
        let bytes = read_stable_bounded(path, limit, "singleton finalization input")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == digest,
            "singleton finalization input digest differs"
        );
        if path == Path::new(p.node) {
            let proc = Path::new("/proc").join(p.pid.to_string()).join("exe");
            let mapped = fs::metadata(&proc)?;
            ensure!(
                fs::read_link(&proc)? == path
                    && mapped.dev() == meta.dev()
                    && mapped.ino() == meta.ino(),
                "singleton finalization mapped node differs"
            );
        }
    }
    Ok(())
}
fn events(p: Profile, records: &[Value], sample: u64) -> Result<Value> {
    let cutoff = sample
        .checked_mul(1_000_000)
        .context("singleton sample overflow")?;
    let last = format!("jetstreamer::firehose] processed slot {}", p.terminal_slot);
    let mut selected = Vec::new();
    for marker in [last.as_str(), EOF] {
        let matching: Vec<_> = records
            .iter()
            .filter(|r| r["MESSAGE"].as_str().is_some_and(|s| s.ends_with(marker)))
            .collect();
        ensure!(
            matching.len() == 1,
            "singleton finalization marker missing or duplicated"
        );
        let r = matching[0];
        ensure!(
            r["_SYSTEMD_UNIT"] == p.unit
                && r["_SYSTEMD_INVOCATION_ID"] == p.iid
                && r["_PID"].as_str() == Some(p.pid.to_string().as_str())
                && r["_UID"] == "1000"
                && r["_EXE"] == p.node
                && r["_CMDLINE"] == p.command,
            "singleton finalization journal owner differs"
        );
        let stamp = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("singleton event timestamp missing")?
            .parse::<u64>()?;
        ensure!(
            stamp > 0 && stamp <= cutoff,
            "singleton EOF/last slot is after coordinated sample"
        );
        selected.push((stamp, r));
    }
    ensure!(
        selected[0].0 < selected[1].0,
        "singleton final slot/EOF events unordered"
    );
    Ok(
        serde_json::json!({"schema":SCHEMA,"epoch":p.epoch,"unit":p.unit,"invocation_id":p.iid,
        "node_sha256":p.node_sha,"manifest_sha256":p.manifest_sha,"sampled_unix_seconds":sample,
        "events":selected.iter().map(|(_,r)|*r).collect::<Vec<_>>(),"terminal_slot":p.terminal_slot,
        "replay_terminal_observed":true,"archive_close_observed":false,"producer_terminal_proven":false,
        "resource_release_authorized":false,"independent_full_verification_passed":false,
        "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}
pub(super) fn observe(current: &Value, sample: u64) -> Result<Value> {
    let p = profile(
        current["Id"]
            .as_str()
            .context("singleton finalization unit missing")?,
    )
    .context("unqualified singleton finalization unit")?;
    owner(p, current)?;
    inputs(p)?;
    let output = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={}", p.iid),
            &format!("_SYSTEMD_UNIT={}", p.unit),
            "-g",
            &format!(
                "processed slot {}|firehose finished successfully",
                p.terminal_slot
            ),
            "-n",
            "16",
            "--no-pager",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "singleton finalization journal unavailable"
    );
    let records = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    events(p, &records, sample)
}
pub(super) fn matches_primary(entry: &Value, row: &Value) -> bool {
    let Some(p) = entry["unit"]["Id"].as_str().and_then(profile) else {
        return false;
    };
    entry["epoch"] == p.epoch
        && entry["phase"] == "producer-finalization"
        && entry["live"] == true
        && entry["unit"]["InvocationID"] == p.iid
        && entry["finalization_evidence"]["schema"] == SCHEMA
        && entry["finalization_evidence"]["epoch"] == p.epoch
        && entry["finalization_evidence"]["unit"] == p.unit
        && entry["finalization_evidence"]["invocation_id"] == p.iid
        && entry["finalization_evidence"]["replay_terminal_observed"] == true
        && row["range"] == format!("{0}-{0}", p.epoch)
        && row["invocation_binding_stable"] == true
        && [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ]
        .iter()
        .all(|role| {
            let r = &row[*role];
            r["unit"] == p.unit
                && r["invocation_id"] == p.iid
                && r["restarts"] == 0
                && r["active_state"] == "active"
                && r["sub_state"] == "running"
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn records(p: Profile) -> Vec<Value> {
        [format!("jetstreamer::firehose] processed slot {}",p.terminal_slot),EOF.into()]
            .into_iter().enumerate().map(|(i,message)| json!({"MESSAGE":format!("[x INFO {message}"),
                "_SYSTEMD_UNIT":p.unit,"_SYSTEMD_INVOCATION_ID":p.iid,"_PID":p.pid.to_string(),
                "_UID":"1000","_EXE":p.node,"_CMDLINE":p.command,"__REALTIME_TIMESTAMP":((10+i)*1_000_000).to_string()})).collect()
    }
    #[test]
    fn all_profiles_require_own_ordered_slot_and_eof_before_sample() {
        for p in PROFILES {
            let r = records(p);
            assert!(events(p, &r, 10).is_err());
            let proof = events(p, &r, 11).unwrap();
            assert_eq!(proof["terminal_slot"], (p.epoch + 1) * 432000 - 1);
            assert_eq!(proof["epoch"], p.epoch);
            for flag in [
                "archive_close_observed",
                "producer_terminal_proven",
                "resource_release_authorized",
                "independent_full_verification_passed",
                "publication_authorized",
                "replay_launch_authorized",
                "r2_mutations",
            ] {
                assert_eq!(proof[flag], false);
            }
            let mut duplicate = r.clone();
            duplicate.push(r[1].clone());
            assert!(events(p, &duplicate, 11).is_err());
            let mut bad = r.clone();
            bad[1]["__REALTIME_TIMESTAMP"] = json!("10000000");
            assert!(events(p, &bad, 11).is_err());
            let mut bad = r.clone();
            bad[0]["MESSAGE"] = json!("processed slot 107135999");
            assert!(events(p, &bad, 11).is_err());
            for key in [
                "_SYSTEMD_UNIT",
                "_SYSTEMD_INVOCATION_ID",
                "_PID",
                "_UID",
                "_EXE",
                "_CMDLINE",
            ] {
                let mut bad = r.clone();
                bad[1][key] = json!("replacement");
                assert!(events(p, &bad, 11).is_err(), "{}/{key}", p.epoch);
            }
            for other in PROFILES {
                if other.epoch != p.epoch {
                    assert!(events(other, &r, 11).is_err());
                }
            }
        }
    }
    #[test]
    fn original_owners_and_commands_are_closed_to_replacements() {
        for p in PROFILES {
            let current = json!({"Id":p.unit,"InvocationID":p.iid,"MainPID":p.pid.to_string(),
                "LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0",
                "ExecStart":format!("{{ path={} ; argv[]={} ; ignore_errors=no ; start_time=now ; }}",p.node,p.command)});
            owner(p, &current).unwrap();
            assert_eq!(scope(p.unit), Some(p.epoch));
            assert!(original_owner(p.unit, p.iid));
            assert!(!original_owner(p.unit, "replacement"));
            for key in [
                "Id",
                "InvocationID",
                "MainPID",
                "LoadState",
                "ActiveState",
                "SubState",
                "NRestarts",
                "ExecStart",
            ] {
                let mut bad = current.clone();
                bad[key] = json!("replacement");
                assert!(owner(p, &bad).is_err());
            }
        }
        assert!(scope("horizon-qualify-265.service").is_none());
    }
    #[test]
    fn exact_primary_rows_share_one_pipeline_owner_without_cross_epoch_aliasing() {
        for p in PROFILES {
            let role = json!({"unit":p.unit,"invocation_id":p.iid,"restarts":0,"active_state":"active","sub_state":"running"});
            let row = json!({"range":format!("{0}-{0}",p.epoch),"invocation_binding_stable":true,
                "controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role});
            let entry = json!({"epoch":p.epoch,"phase":"producer-finalization","live":true,
                "unit":{"Id":p.unit,"InvocationID":p.iid},"finalization_evidence":events(p,&records(p),11).unwrap()});
            assert!(matches_primary(&entry, &row));
            for field in [
                "controller_before",
                "controller_after",
                "producer_before",
                "producer_after",
            ] {
                let mut bad = row.clone();
                bad[field]["invocation_id"] = json!("replacement");
                assert!(!matches_primary(&entry, &bad));
            }
            let mut bad = entry.clone();
            bad["epoch"] = json!(p.epoch + 1);
            assert!(!matches_primary(&bad, &row));
            let mut bad = entry.clone();
            bad["finalization_evidence"]["epoch"] = json!(p.epoch + 1);
            assert!(!matches_primary(&bad, &row));
            let mut bad = row.clone();
            bad["range"] = json!("248-251");
            assert!(!matches_primary(&entry, &bad));
        }
    }
}
