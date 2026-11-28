//! Observational finalization of the original 247 singleton. Its replay EOF is
//! not terminal process proof, independent archive verification, or capacity.
use super::*;
use std::process::Command;

pub(super) const UNIT: &str = "horizon-qualify-247-reboot-20261117-v2.service";
pub(super) const IID: &str = "d091bb68ff2648159c76f690b3b7fee3";
const PID: &str = "50887";
const NODE: &str =
    "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-node";
const NODE_SHA: &str = "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1";
const MANIFEST: &str = "/var/lib/jetstreamer/horizon247-controls0345-v1/preflight-247-target1.json";
const MANIFEST_SHA: &str = "e63e298a0eaa9408a4cc56c396c7701af9a55ec5499c0d9c9ded934971da04f6";
const DEST: &str = "/home/ubuntu/.jetstreamer-private/qualification-247-reboot-20261117-v2/output";
const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon247-bootstrap-copy0347-work-v2/projection/bootstrap/snapshot-106703614-AtkJcCAEp3EfF4ymeeN9t3YvHuAq3aykuQ6vogtDYcf9.tar.zst";
const LAST_SLOT: &str = "processed slot 107135999";
const EOF: &str = "firehose finished successfully.";
const CLOSE: &str = "horizon archive complete: slots=432000 blocks=407228 txs=642148066 tx_updates=1343563420 orphan_updates=451291198 epochs=1 buckets=3375 bytes=180370916960 (payload 1091604388152 uncompressed)";

fn command() -> String {
    format!(
        "{{ path={NODE} ; argv[]={NODE} 247 {DEST} --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint=sha256:12070bfb11a9153cd41b0d1179397947fd718e9891849d2e9a793d02dba098f3 --snapshot-archive={SNAPSHOT}"
    )
}

fn owner(current: &Value) -> Result<()> {
    for (key, expected) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", IID),
        ("MainPID", PID),
        ("NRestarts", "0"),
    ] {
        ensure!(
            current[key] == expected,
            "247 finalization owner differs: {key}"
        );
    }
    ensure!(
        current["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(prefix, rest)| prefix == command() && rest.starts_with("no ;")),
        "247 finalization command differs"
    );
    Ok(())
}

fn events(records: &[Value], sample: u64) -> Result<Value> {
    let cutoff = sample
        .checked_mul(1_000_000)
        .context("247 sample overflow")?;
    let mut selected = Vec::new();
    for marker in [LAST_SLOT, EOF, CLOSE] {
        let matching: Vec<_> = records
            .iter()
            .filter(|r| r["MESSAGE"].as_str().is_some_and(|m| m.ends_with(marker)))
            .collect();
        ensure!(matching.len() <= 1, "247 finalization event duplicated");
        let Some(record) = matching.first() else {
            ensure!(marker == CLOSE, "247 replay completion event absent");
            continue;
        };
        ensure!(
            record["_SYSTEMD_UNIT"] == UNIT
                && record["_SYSTEMD_INVOCATION_ID"] == IID
                && record["_PID"] == PID
                && record["_UID"] == "1000"
                && record["_EXE"] == NODE,
            "247 finalization event owner differs"
        );
        let stamp = record["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("247 event timestamp")?
            .parse::<u64>()?;
        ensure!(stamp > 0, "247 event has zero timestamp");
        if stamp > cutoff {
            ensure!(marker == CLOSE, "247 replay completion is after sample");
            // A later archive close cannot be backdated to a replay EOF sample.
            continue;
        }
        selected.push((stamp, *record));
    }
    ensure!(
        selected.len() >= 2 && selected.windows(2).all(|w| w[0].0 < w[1].0),
        "247 finalization events are unordered"
    );
    Ok(
        serde_json::json!({"schema":"jetstreamer-singleton247-finalization-events-v1",
        "unit":UNIT,"invocation_id":IID,"node_sha256":NODE_SHA,
        "sampled_unix_seconds":sample,"events":selected.iter().map(|(_,r)|*r).collect::<Vec<_>>(),
        "terminal_slot":107135999,"replay_terminal_observed":true,
        "archive_close_observed":selected.len()==3,"producer_terminal_proven":false,
        "resource_release_authorized":false,"independent_full_verification_passed":false,
        "publication_authorized":false,"replay_launch_authorized":false,"r2_mutations":false}),
    )
}

pub(super) fn observe(current: &Value, sample: u64) -> Result<Value> {
    owner(current)?;
    for (path, expected, limit) in [
        (NODE, NODE_SHA, 128 << 20),
        (MANIFEST, MANIFEST_SHA, 1 << 20),
    ] {
        let path = Path::new(path);
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            path.canonicalize()? == path
                && meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o222 == 0,
            "247 finalization input is unsealed"
        );
        let bytes = read_stable_bounded(path, limit, "247 finalization input")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == expected,
            "247 finalization input digest differs"
        );
    }
    let output = Command::new("/usr/bin/journalctl")
        .args([
            &format!("_SYSTEMD_INVOCATION_ID={IID}"),
            &format!("_SYSTEMD_UNIT={UNIT}"),
            "-g",
            "processed slot 107135999|firehose finished successfully|horizon archive complete:",
            "-n",
            "16",
            "--no-pager",
            "-o",
            "json",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "247 finalization journal unavailable"
    );
    let records = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<Value>, _>>()?;
    events(&records, sample)
}

/// Permit one authenticated pre-transition primary row to remain as telemetry.
/// This does not make unrelated overlapping replay/delivery claims acceptable.
pub(super) fn matches_primary(entry: &Value, replay: &Value) -> bool {
    if jetstreamer_horizon_observe::full265::matches_primary(entry, replay)
        || super::original_singleton_finalization::matches_primary(entry, replay)
    {
        return true;
    }
    entry["epoch"] == 247
        && entry["phase"] == "producer-finalization"
        && entry["live"] == true
        && entry["unit"]["Id"] == UNIT
        && entry["unit"]["InvocationID"] == IID
        && entry["finalization_evidence"]["schema"]
            == "jetstreamer-singleton247-finalization-events-v1"
        && entry["finalization_evidence"]["replay_terminal_observed"] == true
        && replay["range"] == "247-247"
        && replay["invocation_binding_stable"] == true
        && [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ]
        .iter()
        .all(|role| {
            let r = &replay[*role];
            r["unit"] == UNIT
                && r["invocation_id"] == IID
                && r["restarts"] == 0
                && r["active_state"] == "active"
                && r["sub_state"] == "running"
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn records() -> Vec<Value> {
        [LAST_SLOT, EOF, CLOSE].into_iter().enumerate().map(|(i,m)| json!({
            "MESSAGE":format!("INFO ] {m}"),"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,
            "_PID":PID,"_UID":"1000","_EXE":NODE,"__REALTIME_TIMESTAMP":((10+i as u64)*1_000_000).to_string()
        })).collect()
    }
    #[test]
    fn cutoff_separates_eof_from_later_archive_close_and_never_releases_capacity() {
        let r = records();
        assert!(events(&r, 10).is_err());
        let proof = events(&r, 11).unwrap();
        assert_eq!(proof["archive_close_observed"], false);
        assert_eq!(proof["events"].as_array().unwrap().len(), 2);
        assert_eq!(proof["producer_terminal_proven"], false);
        assert_eq!(proof["resource_release_authorized"], false);
        assert_eq!(events(&r, 12).unwrap()["archive_close_observed"], true);
        assert_eq!(
            events(&r[..2], 12).unwrap()["archive_close_observed"],
            false
        );
        let mut bad = r.clone();
        bad[1]["__REALTIME_TIMESTAMP"] = json!("10000000");
        assert!(events(&bad, 12).is_err());
        for field in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_EXE",
        ] {
            let mut bad = r.clone();
            bad[1][field] = json!("replacement");
            assert!(events(&bad, 12).is_err());
        }
        let mut duplicate = r.clone();
        duplicate.push(r[1].clone());
        assert!(events(&duplicate, 12).is_err());
    }
    #[test]
    fn exact_owner_and_command_only() {
        let v = json!({"Id":UNIT,"InvocationID":IID,"MainPID":PID,"LoadState":"loaded",
            "ActiveState":"active","SubState":"running","NRestarts":"0",
            "ExecStart":format!("{} ; ignore_errors=no ; start_time=now ; }}",command())});
        owner(&v).unwrap();
        for (k, x) in [
            ("InvocationID", "replacement"),
            ("MainPID", "0"),
            ("NRestarts", "1"),
            ("SubState", "exited"),
            ("ExecStart", "other"),
        ] {
            let mut bad = v.clone();
            bad[k] = json!(x);
            assert!(owner(&bad).is_err());
        }
    }
    #[test]
    fn only_original_observer_row_can_share_finalization_owner() {
        let role = json!({"unit":UNIT,"invocation_id":IID,"restarts":0,"active_state":"active","sub_state":"running"});
        let row = json!({"range":"247-247","invocation_binding_stable":true,
            "controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role});
        let entry = json!({"epoch":247,"phase":"producer-finalization","live":true,
            "unit":{"Id":UNIT,"InvocationID":IID},"finalization_evidence":events(&records(),11).unwrap()});
        assert!(matches_primary(&entry, &row));
        let mut bad = row.clone();
        bad["producer_after"]["invocation_id"] = json!("replacement");
        assert!(!matches_primary(&entry, &bad));
        let mut bad = entry.clone();
        bad["phase"] = json!("verification");
        assert!(!matches_primary(&bad, &row));
        let mut bad = row.clone();
        bad["range"] = json!("247-248");
        assert!(!matches_primary(&entry, &bad));
    }
}
