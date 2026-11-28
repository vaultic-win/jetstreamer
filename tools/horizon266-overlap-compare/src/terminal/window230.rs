//! Terminal acceptance for the guarded Foundation epoch 230 windows.

use super::*;

pub(super) struct Window<'a> {
    pub(super) state: &'static str,
    pub(super) launch_sha: &'a str,
    pub(super) unit: &'static str,
    pub(super) invocation: &'a str,
    pub(super) node: &'static str,
    pub(super) exit_schema: &'static str,
    pub(super) capture_timeout_ms: i32,
    kind: &'static str,
    exit_path: &'static str,
    receipt_schema: &'static str,
    bootstrap: u64,
    last: u64,
    archive: &'static str,
    worker_sha: &'static str,
    revision: &'static str,
    bootstrap_accounts: &'static str,
    terminal_accounts: &'static str,
    terminal_block: &'static str,
    profile_sha: Option<&'static str>,
}

pub(super) const V1627: Window<'static> = Window {
    state: "/var/lib/jetstreamer/horizon230-v1627-replay-runtime-v1",
    launch_sha: "3a2f5a058c76a59707af77f98973c283d4542c8308d5a514a22ae1cb6534a7a6",
    unit: "horizon-qualify-230-v1627-window-v1.service",
    invocation: "6c878d138821422d8a848d6bd16d63a9",
    node: "/var/lib/jetstreamer/horizon230-v1627-diagnostic-318e9028-v1/jetstreamer-node",
    exit_schema: "foundation-epoch230-v1627-window-pid1-exit-v1",
    capture_timeout_ms: 14_500_000,
    kind: "epoch230-private-v1627-window",
    exit_path: "/var/lib/jetstreamer/horizon230-v1627-replay-exit-v1/pid1-exit.json",
    receipt_schema: "foundation-epoch230-v1627-private-terminal-evidence-v1",
    bootstrap: 99_461_591,
    last: 99_468_089,
    archive: "/home/ubuntu/.jetstreamer-private/qualification-230-v1627-window-v1/work/output/epoch-230-v1-6-27-diagnostic.jet",
    worker_sha: "bbb8f5e693ce5f37d9f6673e0f54f8f53e8ba11b0f0ab669b10813e67bc053a8",
    revision: "c5d174c1701b795d702654a76ddd458c4d8b97ea",
    bootstrap_accounts: "9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7",
    terminal_accounts: "5kWV3NT4f15DCB3XkmiYSLu9a1H88XK4GYGEV54nimcQ",
    terminal_block: "4wPbVJwpgJJHqGazjcbM5CjrZFvgzXFKHtaVoNf2VWJf",
    profile_sha: None,
};

pub(super) const ADJACENT: Window<'static> = Window {
    state: "/var/lib/jetstreamer/horizon230-adjacent-99445304-runtime-v1",
    launch_sha: "aeaa1889903df19f737eed77bcd38e0df66f61b268ee1b38afe834b6bb28964f",
    unit: "horizon-qualify-230-adjacent-99445304-v1.service",
    invocation: "f7f7aec34ae04d10bf41261ec552273b",
    node: "/var/lib/jetstreamer/horizon230-continuation-stock-10eaffb0-v1/jetstreamer-node",
    exit_schema: "foundation-epoch230-adjacent-window-pid1-exit-v1",
    capture_timeout_ms: 86_460_000,
    kind: "epoch230-private-adjacent-99445304-window",
    exit_path: "/var/lib/jetstreamer/horizon230-adjacent-replay-exit-v1/evidence/pid1-exit.json",
    receipt_schema: "foundation-epoch230-adjacent-private-terminal-evidence-v1",
    bootstrap: 99_445_304,
    last: 99_461_591,
    archive: "/home/ubuntu/.jetstreamer-private/qualification-230-adjacent-99445304-v1/work/output/epoch-230-slots-99445305-99461591.jet",
    worker_sha: "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c",
    revision: "77bdb45d4af61fc687161ec06cc0178ff79726d5",
    bootstrap_accounts: "2pNDSLmCHAnK2eLvMHmEBnfUmjnSDfqcQ45zak3VR9kc",
    terminal_accounts: "9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7",
    terminal_block: "3eCGmf32ft6eWrGpfgLoaLziT4Fm3215pDWwvD1DJRvq",
    profile_sha: Some("d01cf1c1a583c41e885ea74f57aea21a5e5178554e94bca16d01674a5bff1d1b"),
};

const NEXT_BOOTSTRAP: u64 = 99_468_089;
const NEXT_SOURCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-next-v1627-543c2b6f-v1/source-window.json",
    "6531da54f429164fbbb5c0a4c5ac6569b3247cc82b18ae641e7dd9de318a0a0b",
);

pub(super) fn next_v1627<'a>(launch_sha: &'a str, invocation: &'a str) -> Result<Window<'a>> {
    ensure!(hex(launch_sha, 64) && hex(invocation, 32), "invalid epoch 230 launch identity");
    Ok(Window {
        state: "/var/lib/jetstreamer/horizon230-next-v1627-window-runtime-v1",
        launch_sha,
        unit: "horizon-qualify-230-next-v1627-99468089-v1.service",
        invocation,
        node: "/var/lib/jetstreamer/horizon230-next-v1627-543c2b6f-v1/jetstreamer-node",
        exit_schema: "foundation-epoch230-next-v1627-window-pid1-exit-v1",
        capture_timeout_ms: 14_500_000,
        kind: "epoch230-private-next-v1627-window",
        exit_path: "/var/lib/jetstreamer/horizon230-next-v1627-window-exit-v1/evidence/pid1-exit.json",
        receipt_schema: "foundation-epoch230-next-v1627-private-terminal-evidence-v1",
        bootstrap: NEXT_BOOTSTRAP,
        last: 99_476_782,
        archive: "/home/ubuntu/.jetstreamer-private/qualification-230-next-v1627-99468089-v1/work/output/epoch-230-slots-99468090-99476782.jet",
        bootstrap_accounts: "5kWV3NT4f15DCB3XkmiYSLu9a1H88XK4GYGEV54nimcQ",
        terminal_accounts: "26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK",
        terminal_block: "4YA55n2wFwsuMw7FBCDC6HVKkxjkUhikYFc5JD6dM4qt",
        profile_sha: Some("f289cdf8e6c6d85f387a2deac22c2c7ef19fcb1b4b98bc75230162a2cbf71447"),
        ..V1627
    })
}

pub(super) fn retry_next_v1627<'a>(launch_sha: &'a str, invocation: &'a str) -> Result<Window<'a>> {
    Ok(Window {
        state: "/var/lib/jetstreamer/horizon230-next-v1627-retry-runtime-v2",
        unit: "horizon-qualify-230-next-v1627-99468089-v2.service",
        exit_schema: "foundation-epoch230-next-v1627-retry-pid1-exit-v2",
        kind: "epoch230-private-next-v1627-worker-retry",
        exit_path: "/var/lib/jetstreamer/horizon230-next-v1627-retry-exit-v2/evidence/pid1-exit.json",
        receipt_schema: "foundation-epoch230-next-v1627-retry-terminal-evidence-v2",
        archive: "/home/ubuntu/.jetstreamer-private/qualification-230-next-v1627-99468089-v2/work/output/epoch-230-slots-99468090-99476782.jet",
        worker_sha: "4deff048e3837f9f7f1fa1121f764e78b9fe1fc67084ea8edde75b0d078bfeb2",
        profile_sha: Some("eaaff300d82fe6576331b49876b910e5f296efb61e19a5239505554ac209c95e"),
        ..next_v1627(launch_sha, invocation)?
    })
}

const PRECEDING_WINDOW: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/terminal.json",
    "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2",
);
const FOLLOWING_WINDOW: (&str, &str) = (
    "/var/lib/jetstreamer/horizon230-v1627-terminal-collector-state-v1/evidence/terminal-evidence.json",
    "f040aafc2b2d182e11f6baf2df911957ecc301609fc329932fa724a56c344f56",
);

pub(super) fn same_checkpoint(left: &Value, right: &Value) -> bool {
    // Write-version cursors are local to their replay and the restored worker.
    [
        "slot",
        "bank_hash",
        "accounts_hash",
        "last_blockhash",
        "capitalization",
        "transaction_count",
        "tick_height",
        "slot_complete",
    ]
    .into_iter()
    .all(|key| {
        left.get(key)
            .is_some_and(|value| !value.is_null() && Some(value) == right.get(key))
    }) && left["slot_complete"] == true
}

fn adjacent_seams(manifest: &HistoricalSegmentManifest) -> Result<Value> {
    let before = Reference::new(PRECEDING_WINDOW.0, PRECEDING_WINDOW.1);
    let after = Reference::new(FOLLOWING_WINDOW.0, FOLLOWING_WINDOW.1);
    let left = before.read()?;
    let right = after.read()?;
    ensure!(
        left["state"] == "local-segment-committed"
            && left["guard_drained"] == true
            && right["schema"] == V1627.receipt_schema
            && right["native_manifest_complete_verified"] == true
            && right["producer_drained"] == true
            && same_checkpoint(&left["checkpoint"], &json!(manifest.bootstrap))
            && same_checkpoint(&right["bootstrap_checkpoint"], &json!(manifest.terminal)),
        "adjacent epoch 230 checkpoint differs from a sealed neighboring window"
    );
    Ok(json!({"preceding":before,"following":after,"consensus_fields_match":true}))
}

pub(super) fn load_launch(window: &Window<'_>) -> Result<(Reference, Value, u32)> {
    let state = Path::new(window.state);
    let reference = Reference::new(state.join("cadence-registration.json"), window.launch_sha);
    let launch = reference.read()?;
    ensure!(
        launch["schema"] == "jetstreamer-historical-performance-launch-receipt-v1"
            && launch["kind"] == window.kind
            && launch["epoch"] == 230
            && launch["unit"] == window.unit
            && launch["invocation_id"] == window.invocation
            && launch["node_path"] == window.node
            && window.profile_sha.is_none_or(|sha| {
                launch["profile"] == json!(Reference::new(state.join("profile.json"), sha))
            })
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
            && sample["producer_invocation_id"] == window.invocation
            && sample["plan_sha256"] == launch["guard_plan"]["sha256"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null(),
        "epoch 230 initial guard does not bind the exact producer"
    );
    Ok((reference, launch, pid))
}

fn authorize_manifest(window: &Window<'_>, manifest: &HistoricalSegmentManifest) -> Result<()> {
    ensure!(
        manifest.epoch == 230
            && manifest.output_slot_start == window.bootstrap + 1
            && manifest.output_slot_count == window.last - window.bootstrap
            && manifest.bootstrap.slot == window.bootstrap
            && manifest.bootstrap.accounts_hash == window.bootstrap_accounts
            && manifest.bootstrap.slot_complete
            && manifest.terminal.slot == window.last
            && manifest.terminal.accounts_hash == window.terminal_accounts
            && manifest.terminal.last_blockhash == window.terminal_block
            && manifest.terminal.slot_complete
            && manifest.runtime.runtime_revision == window.revision
            && sha256_hex_string(&manifest.worker_executable_sha256) == window.worker_sha,
        "foreign epoch 230 archive bounds, executable or checkpoint"
    );
    Ok(())
}

pub(super) fn check_manager(
    unit: &str,
    invocation: &str,
    rows: &[Value],
    boot: &str,
    exit: u64,
) -> Result<()> {
    let from = rows
        .iter()
        .position(|event| event["INVOCATION_ID"] == invocation)
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
            && row["UNIT"] == unit
            && row["INVOCATION_ID"] == invocation)
            && started["MESSAGE_ID"] == UNIT_STARTED
            && terminal["MESSAGE_ID"] == UNIT_SUCCESS
            && terminal["MESSAGE"] == format!("{unit}: Deactivated successfully.")
            && timestamp(started)? < exit
            && exit <= timestamp(terminal)?,
        "PID1 does not prove a unique successful invocation for {unit}"
    );
    if let Some(resources) = rows[from..].get(3) {
        ensure!(
            resources["MESSAGE_ID"] == UNIT_RESOURCES
                && timestamp(terminal)? < timestamp(resources)?,
            "unexpected manager event after {unit} exit"
        );
    }
    Ok(())
}

fn check_events(
    window: &Window<'_>,
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
        "epoch 230 requires four unique native checkpoint and archive markers"
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
    let group = format!("/system.slice/{}", window.unit);
    let pid = pid.to_string();
    let mut previous = start;
    for (row, message) in rows.iter().zip(messages) {
        let stamp = timestamp(row)?;
        let (_, body) = string(row, "MESSAGE")?
            .split_once("] ")
            .context("missing native log prefix")?;
        ensure!(
            row["_SYSTEMD_UNIT"] == window.unit
                && row["_SYSTEMD_INVOCATION_ID"] == window.invocation
                && row["_SYSTEMD_CGROUP"] == group
                && row["_PID"] == pid
                && row["_UID"] == "1000"
                && row["_BOOT_ID"] == boot
                && row["_EXE"] == window.node
                && previous < stamp
                && stamp < end
                && body == message,
            "foreign or mismatching native epoch 230 marker: {message}"
        );
        previous = stamp;
    }
    Ok(())
}

pub(super) fn collect(
    window: &Window<'_>,
    exit_path: &Path,
    exit_digest: &str,
    destination: &Path,
) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    ensure!(
        exit_path == Path::new(window.exit_path),
        "foreign epoch 230 exit receipt location"
    );
    let exit_ref = Reference::new(exit_path, exit_digest);
    let (launch_ref, launch, pid) = load_launch(window)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    ensure!(hex(&boot, 32), "invalid boot identity");
    let captured = exit::read_window230(window, &exit_ref, &launch_ref, pid, &boot)?;
    let state = unit_state(window.unit)?;
    let group = format!("/system.slice/{}", window.unit);
    let finished = clean_exit(
        &state,
        Some(&captured),
        window.unit,
        window.invocation,
        pid,
        producer_drained(&group)?,
    )?;
    let start = state_timestamp(finished, "ExecMainStartTimestampMonotonic")?;
    let end = state_timestamp(finished, "ExecMainExitTimestampMonotonic")?;
    let manager = manager_events(window.unit)?;
    check_manager(window.unit, window.invocation, &manager, &boot, end)?;
    let archive_path = Path::new(window.archive);
    let manifest_path = PathBuf::from(format!("{}.segment.json", window.archive));
    let (archive, archive_id) = open_source(archive_path)?;
    let (manifest_file, manifest_id) = open_source(&manifest_path)?;
    let manifest_bytes = read_small(&manifest_file, manifest_id)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    authorize_manifest(window, &manifest)?;
    let events = producer_events(
        window.unit,
        window.invocation,
        window.bootstrap,
        window.last,
    )?;
    check_events(
        window,
        &events,
        &manifest,
        &manifest_path,
        &boot,
        pid,
        start,
        end,
    )?;
    ensure!(
        native_archive(
            archive_path,
            &manifest_path,
            &archive,
            archive_id,
            &manifest_file,
            manifest_id
        )? == manifest,
        "native validator opened a different epoch 230 manifest"
    );
    verify_archive_terminal(&archive, &manifest)?;
    let seam_evidence = match window.bootstrap {
        slot if slot == ADJACENT.bootstrap => Some(adjacent_seams(&manifest)?),
        NEXT_BOOTSTRAP => {
            let source = Reference::new(NEXT_SOURCE.0, NEXT_SOURCE.1);
            let expected = source.read()?;
            ensure!(
                expected["schema"] == "foundation-epoch230-next-v1627-source-window-v1"
                    && expected["first_slot"] == window.bootstrap + 1
                    && expected["last_slot"] == window.last
                    && same_checkpoint(&expected["bootstrap"], &json!(manifest.bootstrap))
                    && same_checkpoint(&expected["terminal"], &json!(manifest.terminal)),
                "next epoch 230 replay differs from its authenticated checkpoint seam"
            );
            Some(json!({"source_window": source, "consensus_fields_match": true}))
        }
        _ => None,
    };
    ensure!(
        unit_state(window.unit)? == state
            && producer_drained(&group)?
            && manager_events(window.unit)? == manager
            && producer_events(
                window.unit,
                window.invocation,
                window.bootstrap,
                window.last
            )? == events
            && launch_ref.read()? == launch,
        "producer identity changed during epoch 230 terminal verification"
    );
    unchanged(archive_path, &archive, archive_id)?;
    unchanged(&manifest_path, &manifest_file, manifest_id)?;
    let staging = stage_package(parent)?;
    let mut evidence = json!({
            "schema": window.receipt_schema,
            "epoch": 230, "unit": window.unit, "invocation_id": window.invocation, "producer_pid": pid, "boot_id": boot,
            "launch": launch_ref, "pid1_exit": exit_ref, "producer_exit_status": 0,
            "producer_drained": true, "manager_events": manager, "native_events": events,
            "first_slot": manifest.output_slot_start, "last_slot": window.last, "slot_count": manifest.output_slot_count,
            "bootstrap_checkpoint": manifest.bootstrap, "terminal_checkpoint": manifest.terminal,
            "archive": {"path":archive_path,"sha256":sha256_hex_string(&manifest.archive_sha256),"identity":archive_id},
            "segment_manifest": {"path":manifest_path,"sha256":digest(&manifest_bytes),"identity":manifest_id},
            "native_manifest_complete_verified": true, "publication_authorized": false,
    });
    if let Some(seams) = seam_evidence {
        evidence["adjacent_checkpoints"] = seams;
    }
    let receipt = write_sealed(&staging.path().join("terminal-evidence.json"), &evidence)?;
    persist_package(staging, destination, parent)?;
    Ok(
        json!({"terminal_evidence": Reference::new(destination.join("terminal-evidence.json"), &receipt.sha256)}),
    )
}

pub(super) fn finish_retry(window: &Window<'_>) -> Result<Value> {
    const GUARD: &str = "horizon-230-next-v1627-99468089-protective-v2.service";
    const TIMER: &str = "horizon-230-next-v1627-99468089-protective-v2.timer";
    const TERMINAL: &str = "/var/lib/jetstreamer/horizon230-next-v1627-retry-terminal-collector-v2/evidence/terminal-evidence.json";
    require_root()?;
    let _lock = predecessor::lock_cadence()?;
    let (launch_ref, launch, pid) = load_launch(window)?;
    let (native, terminal) = predecessor::sealed_document(Path::new(TERMINAL))?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().replace('-', "");
    ensure!(
        terminal["schema"] == window.receipt_schema
            && terminal["epoch"] == 230
            && terminal["unit"] == window.unit
            && terminal["launch"] == json!(launch_ref)
            && terminal["invocation_id"] == window.invocation
            && terminal["producer_pid"] == pid
            && terminal["boot_id"] == boot
            && terminal["producer_exit_status"] == 0
            && terminal["producer_drained"] == true
            && terminal["native_manifest_complete_verified"] == true
            && terminal["adjacent_checkpoints"]["consensus_fields_match"] == true
            && terminal["first_slot"] == window.bootstrap + 1
            && terminal["last_slot"] == window.last
            && terminal["slot_count"] == window.last - window.bootstrap
            && terminal["terminal_checkpoint"]["slot"] == window.last
            && terminal["publication_authorized"] == false,
        "epoch 230 retry terminal differs from the original verified invocation"
    );
    let exit_ref: Reference = serde_json::from_value(terminal["pid1_exit"].clone())?;
    ensure!(exit_ref.path == Path::new(window.exit_path), "foreign epoch 230 retry PID1 proof");
    let captured = exit::read_window230(window, &exit_ref, &launch_ref, pid, &boot)?;
    let group = format!("/system.slice/{}", window.unit);
    let archive = Path::new(window.archive);
    let manifest = archive.with_extension("jet.segment.json");
    let verify = || -> Result<UnitState> {
        let current = unit_state(window.unit)?;
        clean_exit(&current, Some(&captured), window.unit, window.invocation, pid, producer_drained(&group)?)?;
        for (key, path) in [("archive", archive), ("segment_manifest", manifest.as_path())] {
            let output = &terminal[key];
            let identity: FileIdentity = serde_json::from_value(output["identity"].clone())?;
            ensure!(output["path"] == json!(path)
                && hex(string(output, "sha256")?, 64)
                && open_source(path)?.1 == identity,
                "epoch 230 retry {key} changed after native verification");
        }
        ensure!(native.read()? == terminal && launch_ref.read()? == launch, "epoch 230 retry evidence changed");
        Ok(current)
    };
    verify()?;
    let token_ref: Reference = serde_json::from_value(launch["launch_token"].clone())?;
    let token = token_ref.read()?;
    let timer_invocation = string(&token, "guard_timer_invocation")?;
    ensure!(token["unit"] == window.unit && token["invocation_id"] == window.invocation
        && token["guard_plan"] == launch["guard_plan"] && hex(timer_invocation, 32),
        "epoch 230 retry guard token differs");
    let state = Path::new(window.state);
    let completion = state.join("terminal.json");
    let intent = state.join("terminal-drain-intent.json");
    let expected = json!({
        "schema":"foundation-epoch230-next-v1627-retry-drain-intent-v2",
        "unit":window.unit,"invocation_id":window.invocation,"launch":launch_ref,
        "pid1_exit":exit_ref,"native_terminal":native,"guard_plan":launch["guard_plan"],
        "guard_timer_invocation":timer_invocation,"publication_authorized":false,
    });
    let timer = predecessor::timer_state(TIMER)?;
    let active = timer.get("ActiveState").is_some_and(|value| value == "active");
    ensure!(timer.get("Id").is_some_and(|value| value == TIMER)
        && timer.get("Job").is_some_and(String::is_empty)
        && if active {
            timer.get("Unit").is_some_and(|value| value == GUARD)
                && timer.get("InvocationID").is_some_and(|value| value == timer_invocation)
        } else {
            timer.get("ActiveState").is_some_and(|value| value == "inactive")
        }, "epoch 230 retry guard timer ownership changed");
    if completion.try_exists()? {
        let (reference, done) = predecessor::sealed_document(&completion)?;
        ensure!(!active && done["schema"] == "foundation-epoch230-next-v1627-retry-drain-v2"
            && done["launch"] == json!(launch_ref) && done["native_terminal"] == json!(native)
            && done["invocation_id"] == window.invocation && done["guard_drained"] == true,
            "existing epoch 230 retry closure changed");
        predecessor::guard_drained(GUARD)?;
        return Ok(json!({"terminal":reference,"already_completed":true}));
    }
    let intent = if intent.try_exists()? {
        let (reference, prior) = predecessor::sealed_document(&intent)?;
        ensure!(prior == expected, "epoch 230 retry stop intent changed");
        reference
    } else {
        ensure!(active, "epoch 230 retry guard timer stopped without a recorded intent");
        predecessor::seal_in_state(&intent, &expected)?
    };
    if active {
        command("/usr/bin/systemctl", &["--system", "stop", TIMER])?;
    }
    let timer_after = predecessor::timer_state(TIMER)?;
    ensure!(timer_after.get("ActiveState").is_some_and(|value| value == "inactive")
        && timer_after.get("Job").is_some_and(String::is_empty),
        "epoch 230 retry guard timer has not drained");
    let mut guard_after = predecessor::guard_drained(GUARD);
    for _ in 0..12 {
        if guard_after.is_ok() { break; }
        std::thread::sleep(std::time::Duration::from_millis(250));
        guard_after = predecessor::guard_drained(GUARD);
    }
    let terminal = predecessor::seal_in_state(&completion, &json!({
        "schema":"foundation-epoch230-next-v1627-retry-drain-v2","epoch":230,
        "unit":window.unit,"invocation_id":window.invocation,"launch":launch_ref,
        "pid1_exit":exit_ref,"native_terminal":native,"intent":intent,"timer_after":timer_after,
        "guard_after":guard_after?,"producer":verify()?,"guard_drained":true,
        "state":"local-segment-committed","publication_authorized":false,
        "next_action":"Bind the verified private window to the epoch 230 continuation.",
    }))?;
    Ok(json!({"terminal":terminal,"already_completed":false}))
}

#[cfg(test)]
#[test]
fn adjacent_checkpoint_binds_consensus_but_allows_distinct_runtime_cursors() {
    let prior = json!({
        "slot": 1, "bank_hash": "bank", "accounts_hash": "accounts", "last_blockhash": "poh",
        "capitalization": 505_531_210_091_131_930_u64, "transaction_count": 13,
        "tick_height": 12, "slot_complete": true, "next_write_version": 21,
    });
    let mut restored = prior.clone();
    restored["next_write_version"] = json!(42);
    assert!(same_checkpoint(&prior, &restored));
    restored["capitalization"] = json!(505_531_210_091_131_931_u64);
    assert!(!same_checkpoint(&prior, &restored));
    assert!(!same_checkpoint(
        &json!({"slot_complete": true}),
        &json!({"slot_complete": true})
    ));
}
