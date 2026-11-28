//! Verify the exact private epoch 266 restart window after its producer exits.

use super::*;
use exit::{WINDOW266_NODE as NODE, WINDOW266_UNIT as UNIT};

const BOOTSTRAP: u64 = 114_929_697;
const LAST: u64 = 114_936_474;
const FIRST: u64 = BOOTSTRAP + 1;
const RUN_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114936474-v1";
const PID1_EXIT: &str =
    "/var/lib/jetstreamer/horizon266-window-pid1-exit-v1/evidence/pid1-exit.json";
const BOOTSTRAP_ACCOUNTS: &str = "BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di";
const TERMINAL_ACCOUNTS: &str = "GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA";
const WORKER_SHA: &str = "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
const SNAPSHOT_SHA: &str = "6712b4359e3513c9fd76751e85e2fad23fb73bc55e034dec60bc77ade27c6d10";

fn check_manifest(manifest: &HistoricalSegmentManifest) -> Result<()> {
    ensure!(
        manifest.epoch == EPOCH
            && manifest.output_slot_start == FIRST
            && manifest.output_slot_count == LAST - BOOTSTRAP
            && manifest.bootstrap.slot == BOOTSTRAP
            && manifest.bootstrap.accounts_hash == BOOTSTRAP_ACCOUNTS
            && manifest.bootstrap.slot_complete
            && manifest.terminal.slot == LAST
            && manifest.terminal.accounts_hash == TERMINAL_ACCOUNTS
            && manifest.terminal.slot_complete
            && manifest.runtime.runtime_profile == "solana-v1.8.11"
            && manifest.runtime.runtime_revision == "423a4d65461e36fefb371a2f164c20c4e7ed5afa"
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA
            && manifest
                .bootstrap_archive_sha256
                .as_ref()
                .map(sha256_hex_string)
                .as_deref()
                == Some(SNAPSHOT_SHA),
        "foreign epoch 266 archive, worker, snapshot, or accounts checkpoint"
    );
    Ok(())
}

fn events(invocation: &str) -> Result<Vec<Value>> {
    journal_rows(&[
        "--lines=5",
        "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,_SYSTEMD_CGROUP,_PID,_UID,_EXE,_BOOT_ID",
        &format!(
            "--grep=verified epoch 266 native restart at slot {BOOTSTRAP} before replay entries|historical checkpoint slot={LAST} |snapshot verification complete|published verified historical segment evidence "
        ),
        &format!("_SYSTEMD_UNIT={UNIT}"),
        &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
    ])
}

fn check_events(
    rows: &[Value],
    captured: &UnitState,
    manifest: &HistoricalSegmentManifest,
    manifest_path: &Path,
    invocation: &str,
    pid: u32,
    boot: &str,
) -> Result<()> {
    let expected = [
        format!("verified epoch 266 native restart at slot {BOOTSTRAP} before replay entries"),
        checkpoint_message(&manifest.terminal),
        "snapshot verification complete".to_owned(),
        format!(
            "published verified historical segment evidence {}",
            manifest_path.display()
        ),
    ];
    ensure!(
        rows.len() == expected.len(),
        "epoch 266 verification markers are incomplete or repeated"
    );
    let mut previous = state_timestamp(captured, "ExecMainStartTimestampMonotonic")?;
    let end = state_timestamp(captured, "ExecMainExitTimestampMonotonic")?;
    let group = format!("/system.slice/{UNIT}");
    let pid = pid.to_string();
    for (row, message) in rows.iter().zip(expected) {
        let stamp = timestamp(row)?;
        let (_, body) = string(row, "MESSAGE")?
            .split_once("] ")
            .context("missing native log prefix")?;
        ensure!(
            row["_SYSTEMD_UNIT"] == UNIT
                && row["_SYSTEMD_INVOCATION_ID"] == invocation
                && row["_SYSTEMD_CGROUP"] == group
                && row["_PID"] == pid
                && row["_UID"] == "1000"
                && row["_BOOT_ID"] == boot
                && row["_EXE"] == NODE
                && previous < stamp
                && stamp < end
                && body == message,
            "foreign, out-of-order, or mismatching epoch 266 native marker: {message}"
        );
        previous = stamp;
    }
    Ok(())
}

pub(super) fn collect(launch_sha: &str, exit_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let (launch_ref, launch, pid) = exit::window266_launch(launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    ensure!(
        launch["run_root"] == RUN_ROOT,
        "foreign epoch 266 output root"
    );
    let group = format!("/system.slice/{UNIT}");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot, 32), "invalid running boot ID");
    let exit_ref = Reference::new(PID1_EXIT, exit_sha);
    let captured = exit::read_window266(&exit_ref, &launch_ref, invocation, pid, &boot)?;
    let state = unit_state(UNIT)?;
    let finished = clean_exit(
        &state,
        Some(&captured),
        UNIT,
        invocation,
        pid,
        producer_drained(&group)?,
    )?;
    let manager = manager_events(UNIT)?;
    window230::check_manager(
        UNIT,
        invocation,
        &manager,
        &boot,
        state_timestamp(finished, "ExecMainExitTimestampMonotonic")?,
    )?;

    let root = Path::new(RUN_ROOT);
    let archive_path = root.join("output/epoch-266-slots-114929698-114936474.jet");
    let manifest_path = archive_path.with_extension("jet.segment.json");
    let result_path = root.join("receipts/window.json");
    let (archive, archive_id) = open_source(&archive_path)?;
    let (manifest_file, manifest_id) = open_source(&manifest_path)?;
    let (result_file, result_id) = open_source(&result_path)?;
    let manifest_bytes = read_small(&manifest_file, manifest_id)?;
    let result_bytes = read_small(&result_file, result_id)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    let result: Value = serde_json::from_slice(&result_bytes)?;
    check_manifest(&manifest)?;
    let node_plan: Reference = serde_json::from_value(launch["node_plan"].clone())?;
    let plan = node_plan.read()?;
    let predecessor: Reference = serde_json::from_value(plan["predecessor_terminal"].clone())?;
    let previous = predecessor.read()?;
    let archive_sha = sha256_hex_string(&manifest.archive_sha256);
    ensure!(
        result["schema"] == "foundation-epoch266-private-window-result-v1"
            && result["epoch"] == EPOCH
            && result["invocation_id"] == invocation
            && result["plan"] == json!(node_plan)
            && result["first_slot"] == FIRST
            && result["last_slot"] == LAST
            && result["archive"] == json!(archive_path)
            && result["archive_sha256"] == archive_sha
            && result["predecessor_terminal"] == previous["terminal_checkpoint"]
            && result["native_bootstrap"] == json!(manifest.bootstrap)
            && result["native_terminal"] == json!(manifest.terminal)
            && window230::same_checkpoint(
                &previous["terminal_checkpoint"],
                &result["native_bootstrap"]
            )
            && result["whole_prefix_reread"] == true
            && result["actual_native_restart_verified"] == true
            && result["canonical_terminal_verified"] == true
            && result["original_epoch_root_still_required"] == true
            && result["publication_authorized"] == false,
        "epoch 266 result does not bind the exact native segment and predecessor checkpoint"
    );
    let native = events(invocation)?;
    check_events(
        &native,
        finished,
        &manifest,
        &manifest_path,
        invocation,
        pid,
        &boot,
    )?;
    ensure!(
        native_archive(
            &archive_path,
            &manifest_path,
            &archive,
            archive_id,
            &manifest_file,
            manifest_id
        )? == manifest,
        "native validator read a different epoch 266 manifest"
    );
    verify_archive_terminal(&archive, &manifest)?;
    let final_state = unit_state(UNIT)?;
    clean_exit(
        &final_state,
        Some(&captured),
        UNIT,
        invocation,
        pid,
        producer_drained(&group)?,
    )?;
    ensure!(
        !archive_path.with_extension("jet.sha256").try_exists()?
            && manager_events(UNIT)? == manager
            && events(invocation)? == native
            && launch_ref.read()? == launch
            && node_plan.read()? == plan
            && predecessor.read()? == previous,
        "epoch 266 terminal evidence changed during native verification"
    );
    unchanged(&archive_path, &archive, archive_id)?;
    unchanged(&manifest_path, &manifest_file, manifest_id)?;
    unchanged(&result_path, &result_file, result_id)?;

    let staging = stage_package(parent)?;
    let receipt = write_sealed(
        &staging.path().join("terminal-evidence.json"),
        &json!({
            "schema": "foundation-epoch266-private-window-terminal-evidence-v1",
            "epoch": EPOCH, "unit": UNIT, "invocation_id": invocation, "producer_pid": pid,
            "launch": launch_ref, "pid1_exit": exit_ref, "boot_id": boot,
            "producer_exit_status": 0, "producer_drained": true,
            "native_manifest_complete_verified": true, "predecessor_consensus_fields_match": true,
            "first_slot": FIRST, "last_slot": LAST, "slot_count": LAST - BOOTSTRAP,
            "bootstrap_checkpoint": manifest.bootstrap, "terminal_checkpoint": manifest.terminal,
            "predecessor_terminal": predecessor,
            "producer_result": Reference::new(result_path, &digest(&result_bytes)),
            "archive": {"path": archive_path, "identity": archive_id, "sha256": archive_sha},
            "segment_manifest": {"path": manifest_path, "identity": manifest_id, "sha256": digest(&manifest_bytes)},
            "manager_events": manager, "native_events": native,
            "original_epoch_root_still_required": true, "publication_authorized": false,
        }),
    )?;
    persist_package(staging, destination, parent)?;
    Ok(
        json!({"terminal_evidence": Reference::new(destination.join("terminal-evidence.json"), &receipt.sha256)}),
    )
}
