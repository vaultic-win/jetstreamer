//! Verify the exact private epoch 266 restart window after its producer exits.

use super::*;
pub(super) struct Window {
    pub(super) state: &'static str,
    pub(super) unit: &'static str,
    pub(super) node: &'static str,
    pub(super) profile_sha: &'static str,
    root: &'static str,
    pid1_exit: &'static str,
    terminal: &'static str,
    guard: &'static str,
    timer: &'static str,
    bootstrap: u64,
    last: u64,
    bootstrap_accounts: &'static str,
    terminal_accounts: &'static str,
    snapshot_sha: &'static str,
}

pub(super) const WINDOW: Window = Window {
    state: "/var/lib/jetstreamer/horizon266-window-114929698-114936474-runtime-v1",
    unit: "horizon-qualify-checkpoint-continuation-266-window-114936474-v1.service",
    node: "/var/lib/jetstreamer/horizon266-window-node-10fe8f2f-v1/jetstreamer-node",
    profile_sha: "f7562054a31277bc38747652f9a79e6967b393d8713499e6998841390cb4c5d6",
    root: "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114936474-v1",
    pid1_exit: "/var/lib/jetstreamer/horizon266-window-pid1-exit-v1/evidence/pid1-exit.json",
    terminal: "/var/lib/jetstreamer/horizon266-window-terminal-collector-v1/evidence/terminal-evidence.json",
    guard: "horizon-266-window-114936474-protective-v1.service",
    timer: "horizon-266-window-114936474-protective-v1.timer",
    bootstrap: 114_929_697,
    last: 114_936_474,
    bootstrap_accounts: "BevfHbX1MRE8ySXdbzp8WZB5i4W1spPhbsZ8UEUhU7di",
    terminal_accounts: "GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA",
    snapshot_sha: "6712b4359e3513c9fd76751e85e2fad23fb73bc55e034dec60bc77ade27c6d10",
};

pub(super) const SUCCESSOR: Window = Window {
    state: "/var/lib/jetstreamer/horizon266-window-114936475-114943135-runtime-v1",
    unit: "horizon-qualify-checkpoint-continuation-266-window-114943135-v1.service",
    node: "/var/lib/jetstreamer/horizon266-window-node-cafc9416-v1/jetstreamer-node",
    profile_sha: "eacf3e685a72ad196734b20d7a8a00924176cb6e324aea6ce52f55a983e1fc30",
    root: "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114943135-v1",
    pid1_exit: "/var/lib/jetstreamer/horizon266-successor-window-pid1-exit-v1/evidence/pid1-exit.json",
    terminal: "/var/lib/jetstreamer/horizon266-successor-window-terminal-collector-v1/evidence/terminal-evidence.json",
    guard: "horizon-266-window-114943135-protective-v1.service",
    timer: "horizon-266-window-114943135-protective-v1.timer",
    bootstrap: 114_936_474,
    last: 114_943_135,
    bootstrap_accounts: "GqAWTNQiWMCFTZLC1N3SXe2NmykFDcMQdn4Saj4ALSCA",
    terminal_accounts: "6yDbxQ1pi5QgyLa7byJ7SnRRbh3ekSHeYkSVUDCnbyDt",
    snapshot_sha: "95acb06384414d38adb6d576a4de1e4f5233a654521fc0f18b5c1a530af6d444",
};

pub(super) const FOLLOWING: Window = Window {
    state: "/var/lib/jetstreamer/horizon266-window-114943136-114949777-runtime-v1",
    unit: "horizon-qualify-checkpoint-continuation-266-window-114949777-v1.service",
    node: "/var/lib/jetstreamer/horizon266-following-window-node-42f2a7c3-v1/jetstreamer-node",
    profile_sha: "4709cbc3baf7d27acc46e2ea6d2aec7a658bf4ecc23a70f0f571c27ba61068f6",
    root: "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-266-window-114949777-v1",
    pid1_exit: "/var/lib/jetstreamer/horizon266-following-window-pid1-exit-v1/evidence/pid1-exit.json",
    terminal: "/var/lib/jetstreamer/horizon266-following-window-terminal-collector-v1/evidence/terminal-evidence.json",
    guard: "horizon-266-window-114949777-protective-v1.service",
    timer: "horizon-266-window-114949777-protective-v1.timer",
    bootstrap: 114_943_135,
    last: 114_949_777,
    bootstrap_accounts: SUCCESSOR.terminal_accounts,
    terminal_accounts: "2P1wpm3BgAxTEZ13B5dFR6iWvqiN63LLNV6Yf61Qw9Zd",
    snapshot_sha: "7ea9fcd83d72dc205719ecc683c2394076746505795227bec1312216590d07c2",
};

impl Window {
    fn archive(&self) -> PathBuf {
        Path::new(self.root).join(format!(
            "output/epoch-266-slots-{}-{}.jet",
            self.bootstrap + 1,
            self.last,
        ))
    }
}

const WORKER_SHA: &str = "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";

fn check_manifest(scope: &Window, manifest: &HistoricalSegmentManifest) -> Result<()> {
    ensure!(
        manifest.epoch == EPOCH
            && manifest.output_slot_start == (scope.bootstrap + 1)
            && manifest.output_slot_count == scope.last - scope.bootstrap
            && manifest.bootstrap.slot == scope.bootstrap
            && manifest.bootstrap.accounts_hash == scope.bootstrap_accounts
            && manifest.bootstrap.slot_complete
            && manifest.terminal.slot == scope.last
            && manifest.terminal.accounts_hash == scope.terminal_accounts
            && manifest.terminal.slot_complete
            && manifest.runtime.runtime_profile == "solana-v1.8.11"
            && manifest.runtime.runtime_revision == "423a4d65461e36fefb371a2f164c20c4e7ed5afa"
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA
            && manifest
                .bootstrap_archive_sha256
                .as_ref()
                .map(sha256_hex_string)
                .as_deref()
                == Some(scope.snapshot_sha),
        "foreign epoch 266 archive, worker, snapshot, or accounts checkpoint"
    );
    Ok(())
}

fn events(scope: &Window, invocation: &str) -> Result<Vec<Value>> {
    let (unit, bootstrap, last) = (scope.unit, scope.bootstrap, scope.last);
    journal_rows(&[
        "--lines=5",
        "--output-fields=MESSAGE,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,_SYSTEMD_CGROUP,_PID,_UID,_EXE,_BOOT_ID",
        &format!(
            "--grep=verified epoch 266 native restart at slot {bootstrap} before replay entries|historical checkpoint slot={last} |snapshot verification complete|published verified historical segment evidence "
        ),
        &format!("_SYSTEMD_UNIT={unit}"),
        &format!("_SYSTEMD_INVOCATION_ID={invocation}"),
    ])
}

fn check_events(
    scope: &Window,
    rows: &[Value],
    captured: &UnitState,
    manifest: &HistoricalSegmentManifest,
    manifest_path: &Path,
    invocation: &str,
    pid: u32,
    boot: &str,
) -> Result<()> {
    let (unit, bootstrap) = (scope.unit, scope.bootstrap);
    let expected = [
        format!("verified epoch 266 native restart at slot {bootstrap} before replay entries"),
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
    let group = format!("/system.slice/{unit}");
    let pid = pid.to_string();
    for (row, message) in rows.iter().zip(expected) {
        let stamp = timestamp(row)?;
        let (_, body) = string(row, "MESSAGE")?
            .split_once("] ")
            .context("missing native log prefix")?;
        ensure!(
            row["_SYSTEMD_UNIT"] == unit
                && row["_SYSTEMD_INVOCATION_ID"] == invocation
                && row["_SYSTEMD_CGROUP"] == group
                && row["_PID"] == pid
                && row["_UID"] == "1000"
                && row["_BOOT_ID"] == boot
                && row["_EXE"] == scope.node
                && previous < stamp
                && stamp < end
                && body == message,
            "foreign, out-of-order, or mismatching epoch 266 native marker: {message}"
        );
        previous = stamp;
    }
    Ok(())
}

pub(super) fn collect(scope: &Window, launch_sha: &str, exit_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let unit = scope.unit;
    let parent = destination_parent(destination)?;
    let (launch_ref, launch, pid) = exit::window266_launch(scope, launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    ensure!(
        launch["run_root"] == scope.root,
        "foreign epoch 266 output root"
    );
    let group = format!("/system.slice/{unit}");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot, 32), "invalid running boot ID");
    let exit_ref = Reference::new(scope.pid1_exit, exit_sha);
    let captured = exit::read_window266(scope, &exit_ref, &launch_ref, invocation, pid, &boot)?;
    let state = unit_state(unit)?;
    let finished = clean_exit(
        &state,
        Some(&captured),
        unit,
        invocation,
        pid,
        producer_drained(&group)?,
    )?;
    let manager = manager_events(unit)?;
    window230::check_manager(
        unit,
        invocation,
        &manager,
        &boot,
        state_timestamp(finished, "ExecMainExitTimestampMonotonic")?,
    )?;

    let root = Path::new(scope.root);
    let archive_path = scope.archive();
    let manifest_path = archive_path.with_extension("jet.segment.json");
    let result_path = root.join("receipts/window.json");
    let (archive, archive_id) = open_source(&archive_path)?;
    let (manifest_file, manifest_id) = open_source(&manifest_path)?;
    let (result_file, result_id) = open_source(&result_path)?;
    let manifest_bytes = read_small(&manifest_file, manifest_id)?;
    let result_bytes = read_small(&result_file, result_id)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    let result: Value = serde_json::from_slice(&result_bytes)?;
    check_manifest(scope, &manifest)?;
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
            && result["first_slot"] == (scope.bootstrap + 1)
            && result["last_slot"] == scope.last
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
    let native = events(scope, invocation)?;
    check_events(
        scope,
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
    let final_state = unit_state(unit)?;
    clean_exit(
        &final_state,
        Some(&captured),
        unit,
        invocation,
        pid,
        producer_drained(&group)?,
    )?;
    ensure!(
        !archive_path.with_extension("jet.sha256").try_exists()?
            && manager_events(unit)? == manager
            && events(scope, invocation)? == native
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
            "epoch": EPOCH, "unit": unit, "invocation_id": invocation, "producer_pid": pid,
            "launch": launch_ref, "pid1_exit": exit_ref, "boot_id": boot,
            "producer_exit_status": 0, "producer_drained": true,
            "native_manifest_complete_verified": true, "predecessor_consensus_fields_match": true,
            "first_slot": (scope.bootstrap + 1), "last_slot": scope.last, "slot_count": scope.last - scope.bootstrap,
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

pub(super) fn finish(scope: &Window, launch_sha: &str) -> Result<Value> {
    require_root()?;
    let unit = scope.unit;
    let _lock = predecessor::lock_cadence()?;
    let (launch_ref, launch, pid) = exit::window266_launch(scope, launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let (native, terminal) = predecessor::sealed_document(Path::new(scope.terminal))?;
    let archive = scope.archive();
    ensure!(
        terminal["schema"] == "foundation-epoch266-private-window-terminal-evidence-v1"
            && terminal["epoch"] == EPOCH
            && terminal["unit"] == unit
            && terminal["invocation_id"] == invocation
            && terminal["producer_pid"] == pid
            && terminal["launch"] == json!(launch_ref)
            && terminal["boot_id"] == boot
            && terminal["producer_exit_status"] == 0
            && terminal["producer_drained"] == true
            && terminal["native_manifest_complete_verified"] == true
            && terminal["predecessor_consensus_fields_match"] == true
            && terminal["first_slot"] == (scope.bootstrap + 1)
            && terminal["last_slot"] == scope.last
            && terminal["slot_count"] == scope.last - scope.bootstrap
            && terminal["terminal_checkpoint"]["slot"] == scope.last
            && terminal["original_epoch_root_still_required"] == true
            && terminal["publication_authorized"] == false,
        "epoch 266 window terminal does not bind the original guarded producer"
    );
    let exit_ref: Reference = serde_json::from_value(terminal["pid1_exit"].clone())?;
    ensure!(
        exit_ref.path == Path::new(scope.pid1_exit),
        "foreign epoch 266 PID1 proof"
    );
    let captured = exit::read_window266(scope, &exit_ref, &launch_ref, invocation, pid, &boot)?;
    let group = format!("/system.slice/{unit}");
    let verify = || -> Result<UnitState> {
        let current = unit_state(unit)?;
        clean_exit(
            &current,
            Some(&captured),
            unit,
            invocation,
            pid,
            producer_drained(&group)?,
        )?;
        for (key, path) in [
            ("archive", archive.clone()),
            (
                "segment_manifest",
                archive.with_extension("jet.segment.json"),
            ),
        ] {
            let identity: FileIdentity = serde_json::from_value(terminal[key]["identity"].clone())?;
            ensure!(
                terminal[key]["path"] == json!(path)
                    && hex(string(&terminal[key], "sha256")?, 64)
                    && open_source(&path)?.1 == identity,
                "epoch 266 window {key} changed after native readback"
            );
        }
        ensure!(
            native.read()? == terminal,
            "epoch 266 native terminal changed"
        );
        Ok(current)
    };
    verify()?;

    let token_ref: Reference = serde_json::from_value(launch["launch_token"].clone())?;
    let token = token_ref.read()?;
    let timer_invocation = string(&token, "guard_timer_invocation")?;
    ensure!(
        token["unit"] == unit
            && token["invocation_id"] == invocation
            && token["guard_plan"] == launch["guard_plan"]
            && hex(timer_invocation, 32),
        "epoch 266 window guard token differs"
    );
    let state = Path::new(scope.state);
    let completion = state.join("terminal.json");
    let intent = state.join("terminal-drain-intent.json");
    let expected = json!({
        "schema":"foundation-epoch266-private-window-drain-intent-v1",
        "unit":unit, "invocation_id":invocation, "launch":launch_ref, "pid1_exit":exit_ref,
        "native_terminal":native, "guard_plan":launch["guard_plan"],
        "guard_timer_invocation":timer_invocation, "publication_authorized":false,
    });
    let timer = predecessor::timer_state(scope.timer)?;
    let active = timer
        .get("ActiveState")
        .is_some_and(|value| value == "active");
    ensure!(
        timer.get("Id").is_some_and(|value| value == scope.timer)
            && timer.get("Job").is_some_and(String::is_empty)
            && if active {
                timer.get("Unit").is_some_and(|value| value == scope.guard)
                    && timer
                        .get("InvocationID")
                        .is_some_and(|value| value == timer_invocation)
            } else {
                timer
                    .get("ActiveState")
                    .is_some_and(|value| value == "inactive")
            },
        "epoch 266 window guard timer ownership changed"
    );
    if completion.try_exists()? {
        let (receipt, done) = predecessor::sealed_document(&completion)?;
        ensure!(
            timer
                .get("ActiveState")
                .is_some_and(|value| value == "inactive")
                && done["schema"] == "foundation-epoch266-private-window-drain-v1"
                && done["launch"] == json!(launch_ref)
                && done["native_terminal"] == json!(native)
                && done["invocation_id"] == invocation
                && done["guard_drained"] == true,
            "existing epoch 266 window closure or guard changed"
        );
        predecessor::guard_drained(scope.guard)?;
        return Ok(json!({"terminal":receipt, "already_completed":true}));
    }
    let intent = if intent.try_exists()? {
        let (receipt, prior) = predecessor::sealed_document(&intent)?;
        ensure!(prior == expected, "epoch 266 window stop intent changed");
        receipt
    } else {
        ensure!(
            active,
            "epoch 266 window guard timer stopped without a recorded intent"
        );
        predecessor::seal_in_state(&intent, &expected)?
    };
    if active {
        command("/usr/bin/systemctl", &["--system", "stop", scope.timer])?;
    }
    let timer_after = predecessor::timer_state(scope.timer)?;
    ensure!(
        timer_after
            .get("ActiveState")
            .is_some_and(|value| value == "inactive")
            && timer_after.get("Job").is_some_and(String::is_empty),
        "epoch 266 window guard timer has not drained"
    );
    let guard_after = {
        let mut observation = predecessor::guard_drained(scope.guard);
        for _ in 0..12 {
            if observation.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            observation = predecessor::guard_drained(scope.guard);
        }
        observation?
    };
    let producer = verify()?;
    let terminal = predecessor::seal_in_state(
        &completion,
        &json!({
            "schema":"foundation-epoch266-private-window-drain-v1",
            "epoch":EPOCH, "unit":unit, "invocation_id":invocation, "launch":launch_ref,
            "pid1_exit":exit_ref, "native_terminal":native, "intent":intent,
            "timer_after":timer_after, "guard_after":guard_after, "producer":producer,
            "guard_drained":true, "state":"local-segment-committed", "publication_authorized":false,
            "next_action":"Bind the verified private window to the epoch 266 continuation and retain original-epoch-root verification.",
        }),
    )?;
    Ok(json!({"terminal":terminal, "already_completed":false}))
}
