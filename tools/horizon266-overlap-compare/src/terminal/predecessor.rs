use super::*;

const BOOTSTRAP: u64 = 114_910_768;
const FIRST: u64 = 114_912_000;
const LAST: u64 = 114_923_430;
const ANCHOR: &str = "FxGem4zq3seyLHAAgu7wUNega2s6RbMGdr48EnQZaLmU";
const PREFIX_SHA: &str = "4567fbb6d2cf9aaa1d5286f165601f22a855eb04ebcc27904cdf3096dc93dd6f";
const POH: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-dense-prefix-poh-readback-v1/receipt.json",
    "d2d7b86a114853a4716ce206409abf9fef9b93e7bc02891def8b3ae7ba583a90",
);
const EXIT: &str =
    "/var/lib/jetstreamer/horizon266-original-predecessor-exit-v1/evidence/pid1-exit.json";

fn checkpoint(manifest: &HistoricalSegmentManifest) -> Result<NativeRestore> {
    let observed = bound_json(JOURNAL, JOURNAL_SHA)?;
    let restore = bound_json(RESTORE, RESTORE_SHA)?;
    ensure!(
        restore["native_result"] == observed
            && restore["native_result_journal_bytes"]
                == json!({"path": JOURNAL, "sha256": JOURNAL_SHA}),
        "independent checkpoint restore and journal differ"
    );
    let native: NativeRestore = serde_json::from_value(observed)?;
    let terminal = &manifest.terminal;
    ensure!(
        manifest.epoch == EPOCH
            && manifest.output_slot_start == FIRST
            && manifest.output_slot_end()? == LAST + 1
            && manifest.bootstrap.slot == BOOTSTRAP
            && manifest.bootstrap.accounts_hash == "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK"
            && manifest.runtime.runtime_profile == "solana-v1.8.11"
            && manifest.runtime.runtime_revision == RUNTIME_REVISION
            && manifest.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && sha256_hex_string(&manifest.worker_executable_sha256) == WORKER_SHA
            && native.snapshot_generation == 1641767192954871
            && native.snapshot_sha256 == SNAPSHOT_SHA
            && native.worker_sha256 == WORKER_SHA
            && native.replay_entries_sent == 0
            && native.initialization_writes == 0
            && native.initialized_cursor == RESTART_CURSOR
            && native.next_write_version == RESTART_CURSOR
            && native.slot_complete
            && native.slot == LAST
            && terminal.slot == LAST
            && terminal.bank_hash == native.bank_hash
            && terminal.accounts_hash == native.accounts_hash
            && terminal.last_blockhash == native.last_blockhash
            && terminal.last_blockhash == SEAM_BLOCK
            && terminal.capitalization == native.capitalization
            && terminal.transaction_count == native.transactions_at_root
            && terminal.tick_height == native.tick_height
            && terminal.slot_complete,
        "epoch 266 predecessor scope or terminal consensus fields differ from the independent restore"
    );
    Ok(native)
}

fn normalize_prefix(file: &File) -> Result<Overlap> {
    let mut archive = ArchiveReader::open(BufReader::new(file))?;
    let header = archive.header();
    ensure!(
        header.epoch == EPOCH
            && header.slot_start == FIRST
            && header.slot_count == LAST - FIRST + 1,
        "foreign epoch 266 prefix bounds"
    );
    archive.verify_chain = true;
    let range = FIRST..LAST + 1;
    let mut visitor = Overlap::new(EPOCH, range.clone(), ANCHOR, Some(range)).with_epoch_events();
    let count = archive.read_slots(FIRST, LAST - FIRST + 1, &mut visitor)?;
    visitor.validate(count, true)?;
    ensure!(
        visitor.parent_hash == SEAM_BLOCK,
        "epoch 266 prefix ends at a different block"
    );
    Ok(visitor)
}

pub(super) fn collect(launch_sha: &str, exit_sha: &str, destination: &Path) -> Result<Value> {
    require_root()?;
    let parent = destination_parent(destination)?;
    let unit = exit::PREDECESSOR_UNIT;
    let (launch_ref, launch, pid) = exit::predecessor_launch(launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    let node = string(&launch, "node_path")?;
    let profile_ref: Reference = serde_json::from_value(launch["profile"].clone())?;
    let profile: Profile = serde_json::from_value(profile_ref.read()?)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let exit_ref = Reference::new(EXIT, exit_sha);
    let captured = exit::read_predecessor(&exit_ref, &launch_ref, invocation, pid, &boot)?;
    let state = unit_state(unit)?;
    let group = format!("/system.slice/{unit}");
    let terminal = clean_exit(
        &state,
        Some(&captured),
        unit,
        invocation,
        pid,
        producer_drained(&group)?,
    )?;
    let start = state_timestamp(terminal, "ExecMainStartTimestampMonotonic")?;
    let end = state_timestamp(terminal, "ExecMainExitTimestampMonotonic")?;
    let events = manager_events(unit)?;
    let terminal_event = events
        .iter()
        .rfind(|event| event["MESSAGE_ID"] != UNIT_RESOURCES)
        .context("missing epoch 266 manager exit event")?;
    ensure!(
        terminal_event["MESSAGE_ID"] == UNIT_SUCCESS
            && terminal_event["INVOCATION_ID"] == invocation
            && terminal_event["_BOOT_ID"] == boot
            && timestamp(terminal_event)? >= end,
        "PID1 last exit does not match the captured predecessor"
    );

    let (manifest_file, manifest_id) = open_source(&profile.persistent_segment_manifest)?;
    let manifest_bytes = read_small(&manifest_file, manifest_id)?;
    let manifest: HistoricalSegmentManifest = serde_json::from_slice(&manifest_bytes)?;
    let restored = checkpoint(&manifest)?;
    let producer = producer_events(unit, invocation, BOOTSTRAP, LAST)?;
    let expected = [
        checkpoint_message(&manifest.bootstrap),
        checkpoint_message(&manifest.terminal),
        "snapshot verification complete".to_owned(),
        format!(
            "published verified historical segment evidence {}",
            profile.persistent_segment_manifest.display()
        ),
    ];
    ensure!(
        producer.len() == expected.len(),
        "missing or duplicate native predecessor markers"
    );
    let mut prior = start;
    for (row, message) in producer.iter().zip(expected) {
        let stamp = timestamp(row)?;
        ensure!(
            row["_SYSTEMD_UNIT"] == unit
                && row["_SYSTEMD_INVOCATION_ID"] == invocation
                && row["_SYSTEMD_CGROUP"] == group
                && row["_PID"] == pid.to_string()
                && row["_UID"] == "1000"
                && row["_EXE"] == node
                && row["_BOOT_ID"] == boot
                && prior < stamp
                && stamp < end
                && string(row, "MESSAGE")?
                    .split_once("] ")
                    .is_some_and(|(_, body)| body == message),
            "foreign or mismatching native predecessor marker"
        );
        prior = stamp;
    }
    let (archive, archive_id) = open_source(&profile.persistent_archive)?;
    ensure!(
        native_archive(
            &profile.persistent_archive,
            &profile.persistent_segment_manifest,
            &archive,
            archive_id,
            &manifest_file,
            manifest_id
        )? == manifest,
        "native validator read a different epoch 266 predecessor manifest"
    );
    verify_archive_terminal(&archive, &manifest)?;
    let poh = bound_json(POH.0, POH.1)?;
    ensure!(
        poh["archive"]["path"] == DENSE
            && poh["archive"]["sha256"] == PREFIX_SHA
            && poh["full_poh_recomputed"] == true
            && poh["poh_mismatches"] == 0
            && poh["first_slot"] == FIRST
            && poh["last_slot"] == LAST,
        "foreign retained prefix PoH proof"
    );
    let dense_path = Path::new(DENSE);
    let (dense, dense_id) = open_source(dense_path)?;
    let mut hash = Sha256::new();
    io::copy(&mut BufReader::with_capacity(8 << 20, &dense), &mut hash)?;
    ensure!(
        format!("{:x}", hash.finalize()) == PREFIX_SHA,
        "retained epoch 266 prefix digest changed"
    );
    (&dense).seek(SeekFrom::Start(0))?;
    (&archive).seek(SeekFrom::Start(0))?;
    let old = normalize_prefix(&dense)?;
    let new = normalize_prefix(&archive)?;
    let normalized = normalized::compare("epoch 266 predecessor prefix", &old, &new)?;
    ensure!(
        old.versions.next_raw == Some(OLD_CURSOR)
            && new.versions.first_raw == Some(manifest.emitted_raw_write_versions.start)
            && new.versions.next_raw == Some(manifest.terminal.next_write_version),
        "native write cursor differs from its verified prefix"
    );
    unchanged(dense_path, &dense, dense_id)?;
    unchanged(&profile.persistent_archive, &archive, archive_id)?;
    unchanged(
        &profile.persistent_segment_manifest,
        &manifest_file,
        manifest_id,
    )?;
    ensure!(
        unit_state(unit)? == state
            && producer_drained(&group)?
            && manager_events(unit)? == events
            && producer_events(unit, invocation, BOOTSTRAP, LAST)? == producer
            && launch_ref.read()? == launch,
        "producer evidence changed during predecessor verification"
    );
    let stage = stage_package(parent)?;
    let evidence = write_sealed(
        &stage.path().join("terminal-evidence.json"),
        &json!({
            "schema":"foundation-epoch266-private-predecessor-terminal-evidence-v1",
            "epoch":EPOCH,"unit":unit,"invocation_id":invocation,"boot_id":boot,"launch":launch_ref,
            "pid1_exit":exit_ref,"producer_drained":true,"producer_exit_status":0,
            "replay_first_slot":BOOTSTRAP + 1,"first_slot":FIRST,"last_slot":LAST,"positions":LAST-FIRST+1,
            "archive":{"path":profile.persistent_archive,"sha256":sha256_hex_string(&manifest.archive_sha256),"identity":archive_id},
            "segment_manifest":{"path":profile.persistent_segment_manifest,"sha256":digest(&manifest_bytes),"identity":manifest_id},
            "terminal_checkpoint":manifest.terminal,"native_manifest_complete_verified":true,
            "retained_prefix_sha256":PREFIX_SHA,"retained_poh":{"path":POH.0,"sha256":POH.1},
            "normalized_sha256":sha256_hex_string(&normalized),"full_prefix_normalized_match":true,
            "retained_cursor":old.versions.next_raw,"predecessor_cursor":new.versions.next_raw,
            "independent_restore_cursor":restored.next_write_version,"terminal_consensus_fields_match":true,
            "producer_messages":producer,"publication_authorized":false,
        }),
    )?;
    persist_package(stage, destination, parent)?;
    Ok(
        json!({"terminal_evidence":Reference::new(destination.join("terminal-evidence.json"), &evidence.sha256)}),
    )
}

const STATE: &str = "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon266-predecessor-terminal-collector-state-v1/evidence/terminal-evidence.json";
const GUARD: &str = "horizon-266-original-predecessor-protective-v1.service";
const TIMER: &str = "horizon-266-original-predecessor-protective-v1.timer";
const CADENCE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";

fn sealed_document(path: &Path) -> Result<(Reference, Value)> {
    let (file, identity) = open(path)?;
    let reference = Reference::new(path, &digest(&read_small(&file, identity)?));
    let document = reference.read()?;
    unchanged(path, &file, identity)?;
    Ok((reference, document))
}

fn seal_in_state(path: &Path, value: &Value) -> Result<Reference> {
    let parent = path.parent().context("epoch 266 evidence parent")?;
    let stage = stage_package(parent)?;
    let staged = stage.path().join("receipt.json");
    let reference = write_sealed(&staged, value)?;
    install_package(&staged, path)?;
    File::open(parent)?.sync_all()?;
    Ok(Reference::new(path, &reference.sha256))
}

fn timer_state() -> Result<UnitState> {
    let output = command(
        "/usr/bin/systemctl",
        &[
            "--system",
            "show",
            TIMER,
            "--property=Id,ActiveState,Job,InvocationID,Unit",
        ],
    )?;
    Ok(std::str::from_utf8(&output)?
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect())
}

fn guard_drained() -> Result<UnitState> {
    let guard = unit_state(GUARD)?;
    ensure!(
        guard
            .get("ActiveState")
            .is_some_and(|s| matches!(s.as_str(), "inactive" | "failed"))
            && guard.get("MainPID").is_some_and(|s| s == "0")
            && guard.get("ControlPID").is_some_and(|s| s == "0")
            && guard.get("ControlGroup").is_some_and(String::is_empty)
            && guard.get("Job").is_some_and(String::is_empty)
            && producer_drained(&format!("/system.slice/{GUARD}"))?,
        "epoch 266 guard process has not drained"
    );
    Ok(guard)
}

fn validate_finished_terminal(
    terminal: &Value,
    launch: &Reference,
    invocation: &str,
    boot: &str,
    profile: &Profile,
) -> Result<()> {
    let restored: NativeRestore = serde_json::from_value(bound_json(JOURNAL, JOURNAL_SHA)?)?;
    let checkpoint = &terminal["terminal_checkpoint"];
    ensure!(
        terminal["schema"] == "foundation-epoch266-private-predecessor-terminal-evidence-v1"
            && terminal["epoch"] == EPOCH
            && terminal["unit"] == exit::PREDECESSOR_UNIT
            && terminal["launch"] == json!(launch)
            && terminal["invocation_id"] == invocation
            && terminal["boot_id"] == boot
            && terminal["producer_drained"] == true
            && terminal["producer_exit_status"] == 0
            && terminal["replay_first_slot"] == BOOTSTRAP + 1
            && terminal["first_slot"] == FIRST
            && terminal["last_slot"] == LAST
            && terminal["positions"] == LAST - FIRST + 1
            && terminal["native_manifest_complete_verified"] == true
            && terminal["full_prefix_normalized_match"] == true
            && terminal["terminal_consensus_fields_match"] == true
            && terminal["retained_prefix_sha256"] == PREFIX_SHA
            && hex(string(terminal, "normalized_sha256")?, 64)
            && terminal["archive"]["path"] == json!(profile.persistent_archive)
            && terminal["segment_manifest"]["path"] == json!(profile.persistent_segment_manifest)
            && terminal["publication_authorized"] == false
            && checkpoint["slot"] == LAST
            && checkpoint["bank_hash"] == restored.bank_hash
            && checkpoint["accounts_hash"] == restored.accounts_hash
            && checkpoint["last_blockhash"] == restored.last_blockhash
            && checkpoint["capitalization"] == restored.capitalization
            && checkpoint["transaction_count"] == restored.transactions_at_root
            && checkpoint["tick_height"] == restored.tick_height
            && checkpoint["slot_complete"] == true,
        "epoch 266 predecessor terminal does not bind the verified native prefix"
    );
    for key in ["archive", "segment_manifest"] {
        let identity: FileIdentity = serde_json::from_value(terminal[key]["identity"].clone())?;
        let path = Path::new(string(&terminal[key], "path")?);
        ensure!(
            open_source(path)?.1 == identity && hex(string(&terminal[key], "sha256")?, 64),
            "epoch 266 predecessor {key} changed after verification"
        );
    }
    Ok(())
}

/// Retire the exact producer's timer only after the independent terminal collector commits.
pub(super) fn finish(launch_sha: &str) -> Result<Value> {
    require_root()?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(CADENCE_LOCK)?;
    ensure!(
        lock.metadata()?.uid() == 0 && lock.metadata()?.mode() & 0o022 == 0,
        "unsafe Foundation cadence lock"
    );
    // SAFETY: the lock file remains open until this operation completes.
    ensure!(
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } == 0,
        "cannot lock Foundation cadence"
    );

    let state = Path::new(STATE);
    let unit = exit::PREDECESSOR_UNIT;
    let (launch_ref, launch, pid) = exit::predecessor_launch(launch_sha)?;
    let invocation = string(&launch, "invocation_id")?;
    let profile_ref: Reference = serde_json::from_value(launch["profile"].clone())?;
    let profile: Profile = serde_json::from_value(profile_ref.read()?)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let (native, terminal) = sealed_document(Path::new(TERMINAL))?;
    validate_finished_terminal(&terminal, &launch_ref, invocation, &boot, &profile)?;
    let exit_ref: Reference = serde_json::from_value(terminal["pid1_exit"].clone())?;
    ensure!(
        exit_ref.path == Path::new(EXIT),
        "foreign predecessor exit path"
    );
    let captured = exit::read_predecessor(&exit_ref, &launch_ref, invocation, pid, &boot)?;
    let verify_exit = || -> Result<UnitState> {
        let current = unit_state(unit)?;
        clean_exit(
            &current,
            Some(&captured),
            unit,
            invocation,
            pid,
            producer_drained(&format!("/system.slice/{unit}"))?,
        )?;
        Ok(current)
    };
    verify_exit()?;

    let token_ref: Reference = serde_json::from_value(launch["launch_token"].clone())?;
    let token = token_ref.read()?;
    let timer_invocation = string(&token, "guard_timer_invocation")?;
    ensure!(
        token["unit"] == unit
            && token["invocation_id"] == invocation
            && token["guard_plan"] == launch["guard_plan"]
            && hex(timer_invocation, 32),
        "foreign predecessor guard token"
    );
    let completion_path = state.join("terminal.json");
    if completion_path.try_exists()? {
        let (reference, done) = sealed_document(&completion_path)?;
        ensure!(
            done["schema"] == "foundation-epoch266-private-predecessor-drain-v1"
                && done["native_terminal"] == json!(native)
                && done["launch"] == json!(launch_ref)
                && done["guard_drained"] == true,
            "existing predecessor completion changed"
        );
        ensure!(
            timer_state()?
                .get("ActiveState")
                .is_some_and(|s| s == "inactive"),
            "epoch 266 timer is active again"
        );
        guard_drained()?;
        return Ok(json!({"terminal": reference, "already_completed": true}));
    }

    let intent_path = state.join("terminal-drain-intent.json");
    let intent = json!({"schema":"foundation-epoch266-private-predecessor-drain-intent-v1",
        "unit":unit,"invocation_id":invocation,"launch":launch_ref,"native_terminal":native,
        "pid1_exit":exit_ref,"guard_plan":launch["guard_plan"],"guard_timer_invocation":timer_invocation,
        "publication_authorized":false});
    let timer = timer_state()?;
    let active = timer.get("ActiveState").is_some_and(|s| s == "active");
    let already_intended = intent_path.try_exists()?;
    ensure!(
        timer.get("Id").is_some_and(|s| s == TIMER)
            && timer.get("Job").is_some_and(String::is_empty)
            && if active {
                timer.get("Unit").is_some_and(|s| s == GUARD)
                    && timer
                        .get("InvocationID")
                        .is_some_and(|s| s == timer_invocation)
            } else {
                already_intended && timer.get("ActiveState").is_some_and(|s| s == "inactive")
            },
        "epoch 266 timer is foreign or its stop is unrecorded"
    );
    let intent_ref = if already_intended {
        let (reference, recorded) = sealed_document(&intent_path)?;
        ensure!(recorded == intent, "predecessor drain intent changed");
        reference
    } else {
        seal_in_state(&intent_path, &intent)?
    };
    if active {
        command("/usr/bin/systemctl", &["--system", "stop", TIMER])?;
    }
    // The timer cannot start another guard. Allow any current guard to exit on its own.
    let guard_after = {
        let mut drained = guard_drained();
        for _ in 0..12 {
            if drained.is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            drained = guard_drained();
        }
        drained?
    };
    let timer_after = timer_state()?;
    ensure!(
        timer_after
            .get("ActiveState")
            .is_some_and(|s| s == "inactive")
            && timer_after.get("Job").is_some_and(String::is_empty),
        "epoch 266 timer has not drained"
    );
    let producer = verify_exit()?;
    validate_finished_terminal(&native.read()?, &launch_ref, invocation, &boot, &profile)?;
    let reference = seal_in_state(
        &completion_path,
        &json!({
            "schema":"foundation-epoch266-private-predecessor-drain-v1",
            "epoch":EPOCH,"unit":unit,"invocation_id":invocation,"launch":launch_ref,
            "native_terminal":native,"pid1_exit":exit_ref,"intent":intent_ref,
            "timer_after":timer_after,"guard_after":guard_after,"producer":producer,
            "guard_drained":true,"state":"local-segment-committed","publication_authorized":false,
            "next_action":"Bind the verified predecessor and the retained overlap before admitting the next private epoch 266 interval.",
        }),
    )?;
    Ok(json!({"terminal": reference, "already_completed": false}))
}
