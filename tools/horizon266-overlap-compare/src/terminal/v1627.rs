//! Terminal acceptance for the exact Foundation epoch 230 v1.6.27 invocation.

use super::*;

pub(super) const STATE: &str = "/var/lib/jetstreamer/horizon230-v1627-replay-runtime-v1";
pub(super) const LAUNCH_SHA: &str =
    "3a2f5a058c76a59707af77f98973c283d4542c8308d5a514a22ae1cb6534a7a6";
pub(super) const UNIT: &str = "horizon-qualify-230-v1627-window-v1.service";
pub(super) const IID: &str = "6c878d138821422d8a848d6bd16d63a9";
pub(super) const NODE: &str =
    "/var/lib/jetstreamer/horizon230-v1627-diagnostic-318e9028-v1/jetstreamer-node";
pub(super) const EXIT_SCHEMA: &str = "foundation-epoch230-v1627-window-pid1-exit-v1";
const EXIT: &str = "/var/lib/jetstreamer/horizon230-v1627-replay-exit-v1/pid1-exit.json";
const BOOTSTRAP: u64 = 99_461_591;
const LAST: u64 = 99_468_089;
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-230-v1627-window-v1/work/output/epoch-230-v1-6-27-diagnostic.jet";
const WORKER_SHA: &str = "bbb8f5e693ce5f37d9f6673e0f54f8f53e8ba11b0f0ab669b10813e67bc053a8";
const REVISION: &str = "c5d174c1701b795d702654a76ddd458c4d8b97ea";
const BOOTSTRAP_ACCOUNTS: &str = "9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7";
const TERMINAL_ACCOUNTS: &str = "5kWV3NT4f15DCB3XkmiYSLu9a1H88XK4GYGEV54nimcQ";
const TERMINAL_BLOCK: &str = "4wPbVJwpgJJHqGazjcbM5CjrZFvgzXFKHtaVoNf2VWJf";

pub(super) fn load_launch() -> Result<(Reference, Value, u32)> {
    let state = Path::new(STATE);
    let reference = Reference::new(state.join("cadence-registration.json"), LAUNCH_SHA);
    let launch = reference.read()?;
    ensure!(
        launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["kind"] == "epoch230-private-v1627-window"
            && launch["epoch"] == 230
            && launch["unit"] == UNIT
            && launch["invocation_id"] == IID
            && launch["node_path"] == NODE
            && launch["launched"] == true
            && launch["canonical_epoch_publication_authorized"] == false,
        "epoch 230 exit capture requires the exact guarded launch"
    );
    let pid: u32 = serde_json::from_value(launch["main_pid"].clone())?;
    let guard: Reference = serde_json::from_value(launch["active_guard"].clone())?;
    let sample = guard.read_guard_sample(&state.join("guard-receipts"))?;
    ensure!(
        pid > 1
            && sample["producer"]["pid"] == pid
            && sample["producer_invocation_id"] == IID
            && sample["plan_sha256"] == launch["guard_plan"]["sha256"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null(),
        "epoch 230 initial guard does not bind the exact producer"
    );
    Ok((reference, launch, pid))
}

fn authorize_manifest(manifest: &HistoricalSegmentManifest) -> Result<()> {
    ensure!(
        manifest.epoch == 230
            && manifest.output_slot_start == BOOTSTRAP + 1
            && manifest.output_slot_count == LAST - BOOTSTRAP
            && manifest.bootstrap.slot == BOOTSTRAP
            && manifest.bootstrap.accounts_hash == BOOTSTRAP_ACCOUNTS
            && manifest.bootstrap.slot_complete
            && manifest.terminal.slot == LAST
            && manifest.terminal.accounts_hash == TERMINAL_ACCOUNTS
            && manifest.terminal.last_blockhash == TERMINAL_BLOCK
            && manifest.terminal.slot_complete
            && manifest.runtime.runtime_revision == REVISION
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA,
        "foreign v1.6.27 archive bounds, executable or checkpoint"
    );
    Ok(())
}

fn check_manager(rows: &[Value], boot: &str, exit: u64) -> Result<()> {
    let from = rows
        .iter()
        .position(|event| event["INVOCATION_ID"] == IID)
        .context("PID1 lacks the original producer start")?;
    let (started, terminal) = match &rows[from..] {
        [starting, started, terminal] | [starting, started, terminal, _]
            if starting["MESSAGE_ID"] == UNIT_STARTING
                && timestamp(starting)? < timestamp(started)? =>
        {
            (started, terminal)
        }
        _ => bail!("PID1 lifecycle changed after the admitted invocation"),
    };
    ensure!(
        rows[from..].iter().all(|row| row["_PID"] == "1"
            && row["_UID"] == "0"
            && row["_BOOT_ID"] == boot
            && row["UNIT"] == UNIT
            && row["INVOCATION_ID"] == IID)
            && started["MESSAGE_ID"] == UNIT_STARTED
            && terminal["MESSAGE_ID"] == UNIT_SUCCESS
            && terminal["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
            && timestamp(started)? < exit
            && exit <= timestamp(terminal)?,
        "PID1 does not prove a unique successful v1.6.27 invocation"
    );
    if let Some(resources) = rows[from..].get(3) {
        ensure!(
            resources["MESSAGE_ID"] == UNIT_RESOURCES
                && timestamp(terminal)? < timestamp(resources)?,
            "unexpected manager event after epoch 230 exit"
        );
    }
    Ok(())
}

fn check_events(
    rows: &[Value],
    manifest: &HistoricalSegmentManifest,
    sidecar: &Path,
    boot: &str,
    pid: u32,
    start: u64,
    end: u64,
) -> Result<()> {
    ensure!(
        rows.len() == 4,
        "v1.6.27 requires four unique native checkpoint and archive markers"
    );
    let messages = [
        checkpoint_message(&manifest.bootstrap),
        checkpoint_message(&manifest.terminal),
        "snapshot verification complete".to_owned(),
        format!(
            "published verified historical segment evidence {}",
            sidecar.display()
        ),
    ];
    let group = format!("/system.slice/{UNIT}");
    let pid = pid.to_string();
    let mut previous = start;
    for (row, message) in rows.iter().zip(messages) {
        let stamp = timestamp(row)?;
        let (_, body) = string(row, "MESSAGE")?
            .split_once("] ")
            .context("missing native log prefix")?;
        ensure!(
            row["_SYSTEMD_UNIT"] == UNIT
                && row["_SYSTEMD_INVOCATION_ID"] == IID
                && row["_SYSTEMD_CGROUP"] == group
                && row["_PID"] == pid
                && row["_UID"] == "1000"
                && row["_BOOT_ID"] == boot
                && row["_EXE"] == NODE
                && previous < stamp
                && stamp < end
                && body == message,
            "foreign or mismatching native epoch 230 marker: {message}"
        );
        previous = stamp;
    }
    Ok(())
}

pub(super) fn collect(exit_path: &Path, exit_digest: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    ensure!(
        exit_path == Path::new(EXIT),
        "foreign epoch 230 exit receipt location"
    );
    let exit_ref = Reference::new(exit_path, exit_digest);
    let (launch_ref, launch, pid) = load_launch()?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot, 32), "invalid boot identity");
    let captured = exit::read_v1627(&exit_ref, &launch_ref, pid, &boot)?;
    let state = unit_state(UNIT)?;
    let group = format!("/system.slice/{UNIT}");
    let finished = clean_exit(
        &state,
        Some(&captured),
        UNIT,
        IID,
        pid,
        producer_drained(&group)?,
    )?;
    let start = state_timestamp(finished, "ExecMainStartTimestampMonotonic")?;
    let end = state_timestamp(finished, "ExecMainExitTimestampMonotonic")?;
    let manager = manager_events(UNIT)?;
    check_manager(&manager, &boot, end)?;
    let archive_path = Path::new(ARCHIVE);
    let manifest_path = PathBuf::from(format!("{ARCHIVE}.segment.json"));
    let (archive, archive_id) = open_source(archive_path)?;
    let (manifest_file, manifest_id) = open_source(&manifest_path)?;
    let manifest_bytes = read_small(&manifest_file, manifest_id)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    authorize_manifest(&manifest)?;
    let events = producer_events(UNIT, IID, BOOTSTRAP, LAST)?;
    check_events(&events, &manifest, &manifest_path, &boot, pid, start, end)?;
    ensure!(
        native_archive(
            archive_path,
            &manifest_path,
            &archive,
            archive_id,
            &manifest_file,
            manifest_id
        )? == manifest,
        "native validator opened a different v1.6.27 manifest"
    );
    verify_archive_terminal(&archive, &manifest)?;
    ensure!(
        unit_state(UNIT)? == state
            && producer_drained(&group)?
            && manager_events(UNIT)? == manager
            && producer_events(UNIT, IID, BOOTSTRAP, LAST)? == events
            && launch_ref.read()? == launch,
        "producer identity changed during v1.6.27 final verification"
    );
    unchanged(archive_path, &archive, archive_id)?;
    unchanged(&manifest_path, &manifest_file, manifest_id)?;
    let staging = stage_package(parent)?;
    let receipt = write_sealed(
        &staging.path().join("terminal-evidence.json"),
        &json!({
            "schema": "foundation-epoch230-v1627-private-terminal-evidence-v1",
            "epoch": 230, "unit": UNIT, "invocation_id": IID, "producer_pid": pid, "boot_id": boot,
            "launch": launch_ref, "pid1_exit": exit_ref, "producer_exit_status": 0,
            "producer_drained": true, "manager_events": manager, "native_events": events,
            "first_slot": manifest.output_slot_start, "last_slot": LAST, "slot_count": manifest.output_slot_count,
            "bootstrap_checkpoint": manifest.bootstrap, "terminal_checkpoint": manifest.terminal,
            "archive": {"path":archive_path,"sha256":sha256_hex_string(&manifest.archive_sha256),"identity":archive_id},
            "segment_manifest": {"path":manifest_path,"sha256":digest(&manifest_bytes),"identity":manifest_id},
            "native_manifest_complete_verified": true, "publication_authorized": false,
        }),
    )?;
    persist_package(staging, destination, parent)?;
    Ok(
        json!({"terminal_evidence": Reference::new(destination.join("terminal-evidence.json"), &receipt.sha256)}),
    )
}
