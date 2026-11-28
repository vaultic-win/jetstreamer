//! Capture the drained prefix producer for the private epoch 186 assembler.
use super::*;
use std::{path::PathBuf, process::Command};

const COMPLETION_SCHEMA: &str = "horizon-epoch186-guarded-replay-completion-v1";
const CLEAN_DEACTIVATION: &str = "7ad2d189f7e94e70a38c781354912448";
const SEGMENT_READBACK: &str = "published verified historical segment evidence ";

fn check_terminal(unit: &Value, invocation: &str, node_pid: u64) -> Result<()> {
    ensure!(
        iid(invocation)
            && node_pid > 1
            && unit["Id"] == UNIT
            && unit["LoadState"] == "loaded"
            && unit["ActiveState"] == "inactive"
            && unit["SubState"] == "dead"
            && unit["InvocationID"] == invocation
            && text(unit, "ExecMainPID")?.parse::<u64>()? == node_pid
            && unit["MainPID"] == "0"
            && unit["ControlPID"] == "0"
            && unit["Job"] == ""
            && unit["Restart"] == "no"
            && unit["NRestarts"] == "0"
            && unit["Result"] == "success"
            && unit["ExecMainCode"] == "1"
            && unit["ExecMainStatus"] == "0",
        "the adopted epoch 186 producer is not cleanly terminal"
    );
    guard::check_producer_journal(unit)
}

fn journal_records(filters: &[&str]) -> Result<Vec<Value>> {
    let output = Command::new("/usr/bin/timeout")
        .args([
            "10",
            "/usr/bin/journalctl",
            "--boot",
            "--quiet",
            "--no-pager",
            "-o",
            "json",
        ])
        .args(filters)
        .env_clear()
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        output.status.success() && output.stderr.is_empty() && output.stdout.len() < 1 << 20,
        "cannot capture the invocation's native journal records"
    );
    std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| serde_json::from_str(line).context("invalid system journal record"))
        .collect()
}

fn check_journal(
    manager: &[Value],
    producer: &[Value],
    invocation: &str,
    node_pid: u64,
    path: &Path,
) -> Result<()> {
    ensure!(
        manager.iter().any(|record| {
            record["_PID"] == "1"
                && record["_UID"] == "0"
                && record["UNIT"] == UNIT
                && record["INVOCATION_ID"] == invocation
                && record["MESSAGE_ID"] == CLEAN_DEACTIVATION
        }),
        "the adopted invocation lacks PID 1 success evidence"
    );
    let readback_marker = format!("{SEGMENT_READBACK}{}", path.display());
    let pid = node_pid.to_string();
    ensure!(
        producer.iter().any(|record| {
            record["_PID"] == pid
                && record["_SYSTEMD_UNIT"] == UNIT
                && record["_SYSTEMD_INVOCATION_ID"] == invocation
                && record["MESSAGE"]
                    .as_str()
                    .is_some_and(|message| message.ends_with(&readback_marker))
        }),
        "the adopted producer has no successful manifest readback for this archive"
    );
    Ok(())
}

fn bound_document(reference: &Value, path: &Path, mode: u32) -> Result<Value> {
    ensure!(
        reference["path"] == json!(path),
        "foreign guard evidence path"
    );
    document(path, text(reference, "sha256")?, mode)
}

struct AdoptedPrefix {
    invocation: String,
    node_pid: u64,
}

fn adopted_prefix(path: &Path, sha: &str) -> Result<AdoptedPrefix> {
    let check = document(path, sha, 0o400)?;
    let state = Path::new(STATE);
    let invocation = text(&check, "producer_invocation_id")?;
    let guard_iid = text(&check, "guard_invocation_id")?;
    let adoption = &check["adoption"];
    let node_pid = number(adoption, "node_pid")?;
    ensure!(
        check["schema"] == "horizon-epoch186-live-guard-check-v1"
            && check["epoch"] == EPOCH
            && check["stage"] == "adopted"
            && iid(invocation)
            && iid(guard_iid)
            && iid(text(&check, "timer_invocation_id")?)
            && node_pid > 1
            && node_pid != number(adoption, "worker_pid")?
            && text(&check, "producer_start_ticks")?.parse::<u64>()? > 0
            && adoption["node_start_ticks"] == check["producer_start_ticks"]
            && text(adoption, "worker_start_ticks")?.parse::<u64>()? > 0
            && adoption["worker_sha256"] == source::WORKER_SHA,
        "a successful live prefix worker adoption is required"
    );
    let plan_ref = &check["plan"];
    let plan = bound_document(plan_ref, &state.join("ACTUAL_GUARD_PLAN.json"), 0o400)?;
    let sample = bound_document(
        &check["sample"],
        &state
            .join("guard-receipts")
            .join(format!("sample-{guard_iid}.json")),
        0o600,
    )?;
    let observed_at = number(&sample, "recorded_unix_seconds")?;
    ensure!(
        plan["invocation_id"] == invocation
            && sample["guard_invocation_id"] == guard_iid
            && sample["producer"]["pid"] == node_pid
            && guard::validate_sample(plan_ref, &plan, &sample, observed_at, true)?
                == Some(number(adoption, "worker_pid")?),
        "guard sample does not bind the adopted prefix processes"
    );
    let quote = bound_document(
        &check["prestart_capacity"],
        &state.join("PRESTART_CAPACITY.json"),
        0o400,
    )?;
    ensure!(
        quote["schema"] == price::CAPACITY_SCHEMA
            && quote["source_entry"]["unit"] == UNIT
            && quote["source_entry"]["argv"] == json!(source::argv())
            && quote["source_entry"]["bootstrap"]["sha256"] == source::BOOTSTRAP_SHA
            && quote["resource_screen"]["home_and_memory_fit"] == true
            && quote["resource_screen"]["guard_minimum_free_bytes"] == plan["minimum_free_bytes"]
            && number(&quote, "recorded_unix_seconds")? <= observed_at,
        "adopted producer does not bind the prepared output and bootstrap"
    );
    Ok(AdoptedPrefix {
        invocation: invocation.into(),
        node_pid,
    })
}

fn open_frozen_output(path: &Path) -> Result<(File, Metadata)> {
    ensure!(
        path.canonicalize()? == path,
        "indirect output {}",
        path.display()
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o222 == 0 && meta.len() > 0,
        "output must be frozen, nonempty and singly linked: {}",
        path.display()
    );
    stable(path, &file, &meta)?;
    Ok((file, meta))
}

fn completion(
    invocation: &str,
    manifest: &Value,
    manifest_path: &Path,
    manifest_sha: &str,
    archive_sha: &str,
) -> Result<Value> {
    ensure!(
        manifest["schema_version"] == 1
            && manifest["epoch"] == EPOCH
            && manifest["output_slot_start"] == FIRST_SLOT
            && manifest["output_slot_count"] == END_SLOT - FIRST_SLOT + 1
            && manifest["worker_executable_sha256"] == source::WORKER_SHA
            && manifest["bootstrap"]["slot"] == 80_351_283
            && manifest["bootstrap"]["accounts_hash"]
                == "Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8"
            && manifest["bootstrap"]["slot_complete"] == true
            && manifest["terminal"]["slot"] == END_SLOT
            && manifest["terminal"]["accounts_hash"]
                == "EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9"
            && manifest["terminal"]["slot_complete"] == true
            && manifest["archive_sha256"] == archive_sha,
        "producer manifest does not describe the measured epoch 186 prefix and checkpoint"
    );
    Ok(json!({
        "schema": COMPLETION_SCHEMA,
        "unit": UNIT,
        "invocation_id": invocation,
        "result": "success",
        "exit_status": 0,
        "restarts": 0,
        "archive": binding(source::ARCHIVE, archive_sha),
        "manifest": binding(manifest_path, manifest_sha),
        "bootstrap_payload_sha256": source::BOOTSTRAP_SHA,
    }))
}

pub(crate) fn capture_prefix(path: &Path, sha: &str) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "prefix completion capture requires root read access"
    );
    let AdoptedPrefix {
        invocation,
        node_pid,
    } = adopted_prefix(path, sha)?;
    let before = guard::properties(UNIT)?;
    check_terminal(&before, &invocation, node_pid)?;
    let archive_path = Path::new(source::ARCHIVE);
    let manifest_path = PathBuf::from(format!("{}.segment.json", source::ARCHIVE));
    let manager = journal_records(&[
        "_PID=1",
        "_UID=0",
        &format!("UNIT={UNIT}"),
        &format!("INVOCATION_ID={invocation}"),
        &format!("MESSAGE_ID={CLEAN_DEACTIVATION}"),
    ])?;
    let producer = journal_records(&[
        "--grep",
        SEGMENT_READBACK,
        &format!("_SYSTEMD_UNIT={UNIT}"),
        &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
        &format!("_PID={node_pid}"),
    ])?;
    check_journal(&manager, &producer, &invocation, node_pid, &manifest_path)?;
    let (manifest_file, manifest_meta) = open_frozen_output(&manifest_path)?;
    let mut bytes = Vec::new();
    (&manifest_file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1 << 20, "oversized producer manifest");
    let manifest_sha = format!("{:x}", Sha256::digest(&bytes));
    let manifest = serde_json::from_slice(&bytes)?;
    let (mut archive, archive_meta) = open_frozen_output(archive_path)?;
    let receipt = completion(
        &invocation,
        &manifest,
        &manifest_path,
        &manifest_sha,
        &hash(&mut archive)?,
    )?;
    stable(archive_path, &archive, &archive_meta)?;
    stable(&manifest_path, &manifest_file, &manifest_meta)?;
    ensure!(
        guard::properties(UNIT)? == before,
        "producer changed during completion capture"
    );
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVOCATION: &str = "1234567890abcdef1234567890abcdef";
    const NODE_PID: u64 = 42;

    #[test]
    fn terminal_must_identify_the_clean_nonrestarting_adopted_process() {
        let state = json!({
            "Id": UNIT, "LoadState": "loaded", "ActiveState": "inactive", "SubState": "dead",
            "InvocationID": INVOCATION, "ExecMainPID": NODE_PID.to_string(), "MainPID": "0",
            "ControlPID": "0", "Job": "", "Restart": "no", "NRestarts": "0",
            "Result": "success", "ExecMainCode": "1", "ExecMainStatus": "0",
            "StandardOutput": "journal", "StandardError": "inherit", "RemainAfterExit": "no",
        });
        check_terminal(&state, INVOCATION, NODE_PID).unwrap();
        for (field, wrong) in [
            ("LoadState", "not-found"),
            ("InvocationID", ""),
            ("InvocationID", "99999999999999999999999999999999"),
            ("ExecMainPID", "43"),
            ("ActiveState", "active"),
            ("NRestarts", "1"),
            ("Result", "timeout"),
            ("ExecMainCode", "2"),
            ("ExecMainStatus", "1"),
            ("StandardError", "append"),
        ] {
            let mut changed = state.clone();
            changed[field] = wrong.into();
            assert!(
                check_terminal(&changed, INVOCATION, NODE_PID).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn journal_requires_manager_success_and_the_adopted_nodes_exact_readback() {
        let path = Path::new("/private/archive.jet.segment.json");
        let mut manager = [json!({
            "_PID": "1", "_UID": "0", "UNIT": UNIT, "INVOCATION_ID": INVOCATION,
            "MESSAGE_ID": CLEAN_DEACTIVATION,
        })];
        let mut producer = [json!({
            "_PID": NODE_PID.to_string(), "_SYSTEMD_UNIT": UNIT,
            "_SYSTEMD_INVOCATION_ID": INVOCATION,
            "MESSAGE": format!("[INFO jetstreamer_node] {SEGMENT_READBACK}{}", path.display()),
        })];
        check_journal(&manager, &producer, INVOCATION, NODE_PID, path).unwrap();
        assert!(
            check_journal(
                &manager,
                &producer,
                INVOCATION,
                NODE_PID,
                Path::new("/private/other.jet.segment.json")
            )
            .is_err()
        );
        producer[0]["_PID"] = "43".into();
        assert!(check_journal(&manager, &producer, INVOCATION, NODE_PID, path).is_err());
        producer[0]["_PID"] = NODE_PID.to_string().into();
        manager[0]["_PID"] = "43".into();
        assert!(check_journal(&manager, &producer, INVOCATION, NODE_PID, path).is_err());
    }

    #[test]
    fn receipt_binds_both_outputs_and_rejects_a_different_checkpoint_or_archive() {
        let manifest_sha = "a".repeat(64);
        let archive_sha = "b".repeat(64);
        let manifest_path = PathBuf::from(format!("{}.segment.json", source::ARCHIVE));
        let mut manifest = json!({
            "schema_version":1,"epoch":EPOCH,"output_slot_start":FIRST_SLOT,
            "output_slot_count":END_SLOT-FIRST_SLOT+1,"worker_executable_sha256":source::WORKER_SHA,
            "archive_sha256":archive_sha,
            "bootstrap":{"slot":80_351_283,"accounts_hash":"Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8","slot_complete":true},
            "terminal":{"slot":END_SLOT,"accounts_hash":"EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9","slot_complete":true},
        });
        let receipt = completion(
            INVOCATION,
            &manifest,
            &manifest_path,
            &manifest_sha,
            &archive_sha,
        )
        .unwrap();
        assert_eq!(
            receipt,
            json!({
                "schema":"horizon-epoch186-guarded-replay-completion-v1", "unit":UNIT,
                "invocation_id":INVOCATION, "result":"success", "exit_status":0, "restarts":0,
                "archive":{"path":source::ARCHIVE,"sha256":archive_sha},
                "manifest":{"path":manifest_path,"sha256":manifest_sha},
                "bootstrap_payload_sha256":source::BOOTSTRAP_SHA,
            })
        );
        assert!(
            completion(
                INVOCATION,
                &manifest,
                &manifest_path,
                &manifest_sha,
                &"c".repeat(64)
            )
            .is_err()
        );
        manifest["terminal"]["slot"] = (END_SLOT + 1).into();
        assert!(
            completion(
                INVOCATION,
                &manifest,
                &manifest_path,
                &manifest_sha,
                &archive_sha
            )
            .is_err()
        );
    }
}
