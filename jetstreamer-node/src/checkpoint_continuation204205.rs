//! Persistent exact 638/949-slot continuation of the original capped prefixes.
//! Private source preservation and V4 construction only; no public sidecar.
use super::checkpoint_continuation::{
    RestartProof, authenticate_service, available_bytes, create_private_dir, require,
    require_no_checksum, runtime_checkpoint, write_new,
};
use super::*;
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    capped_control204205::{self as control, Bound, Phase, Plan, Stage},
    capped_prefix204205::{self as capped, AssemblyOptions, InputPolicy},
    segment_manifest::read_and_validate_segment_manifest_from,
};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(crate) fn validate_cli(
    epochs: (u64, u64),
    verify: Option<bool>,
    count: usize,
    destination: bool,
    forbidden: bool,
) -> Result<(), String> {
    require(
        cfg!(feature = "capped204205-checkpoint-continuation-diagnostic")
            && epochs.0 == epochs.1
            && matches!(epochs.0, 204 | 205)
            && verify == Some(true)
            && count == 1
            && destination
            && !forbidden,
        "closed capped 204/205 continuation requires its exclusive build, one exact epoch, one --verify, explicit private destination and no ordinary overrides",
    )
}

#[derive(Clone, Copy)]
struct ActualNative {
    checkpoint: RuntimeStateCheckpoint,
    writes: u64,
    worker: [u8; 32],
    cursor: u64,
    ticks: u64,
}
impl ActualNative {
    fn receipt(&self) -> Value {
        let c = &self.checkpoint;
        json!({"slot":c.slot,"bank_hash":c.bank_hash.to_string(),
            "accounts_hash_kind":"legacy_accounts_hash","accounts_hash":c.accounts_hash.to_string(),
            "last_blockhash":c.last_blockhash.to_string(),"capitalization":c.capitalization,
            "transaction_count":c.transaction_count,"tick_height":c.tick_height,
            "slot_complete":c.slot_complete,"next_write_version":c.next_write_version,
            "bootstrap_write_count":self.writes,"initialized_next_write_version":self.cursor,
            "initialized_ticks_per_slot":self.ticks,"worker_sha256":jetstreamer_node::segment_manifest::sha256_hex_string(&self.worker)})
    }
}
struct Validated {
    profile: capped::Profile,
    policy: InputPolicy,
    snapshot: PathBuf,
    actual_native: Mutex<Option<ActualNative>>,
}
impl RestartProof for Validated {
    fn snapshot_sha256(&self) -> [u8; 32] {
        capped::parse_sha(self.profile.snapshot_sha256).unwrap()
    }
    fn snapshot_size(&self) -> u64 {
        self.profile.snapshot_bytes
    }
    fn covers_trusted_root(&self, e: u64, b: u64, start: u64, end: u64) -> bool {
        e == self.profile.epoch
            && b == self.profile.restart
            && start == self.profile.restart + 1
            && end == self.profile.end
    }
    fn validate_invocation(
        &self,
        e: u64,
        b: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        require(
            cfg!(feature = "capped204205-checkpoint-continuation-diagnostic")
                && !carried
                && !audited
                && !retain
                && b.snapshot_archive() == Some(self.snapshot.as_path())
                && q.is_some_and(|q| {
                    q.epoch == e
                        && q.replay_start == self.profile.restart + 1
                        && self.covers_trusted_root(
                            e,
                            q.bootstrap_slot,
                            q.output_slot_start,
                            q.end_inclusive,
                        )
                }),
            "closed capped restart proof cannot authorize another scope, runtime carry or ordinary reuse",
        )
    }
    fn verify_native_checkpoint(
        &self,
        actual: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        let summary = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(actual)?,
        );
        let checkpoint = runtime_checkpoint(&summary)?;
        let writes = actual
            .writes
            .len()
            .try_into()
            .map_err(|_| "bootstrap write count overflow")?;
        self.policy
            .native_barrier(checkpoint, writes, worker, cursor, ticks)
            .map_err(|e| e.to_string())?;
        let mut recorded = self
            .actual_native
            .lock()
            .map_err(|_| "native barrier state poisoned")?;
        require(recorded.is_none(), "actual native barrier attempted twice")?;
        *recorded = Some(ActualNative {
            checkpoint,
            writes,
            worker,
            cursor,
            ticks,
        });
        info!(
            "closed capped {} actual native tuple barrier passed before any suffix entry; raw cursor={cursor}",
            self.profile.epoch
        );
        Ok(())
    }
}

struct GuardWatch {
    done: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for GuardWatch {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
fn heartbeat(
    p: &Plan,
    plan_sha: &str,
    iid: &str,
    guard_iid: Option<&str>,
) -> Result<Value, String> {
    let value = control::guard_heartbeat(
        p,
        plan_sha,
        iid,
        control::now_millis().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    require(
        guard_iid.is_none_or(|iid| value["guard_invocation_id"] == iid),
        "independent guard invocation changed",
    )?;
    Ok(value)
}
fn watch_guard(
    p: Plan,
    plan_sha: String,
    iid: String,
    guard_iid: String,
    shutdown: Arc<AtomicBool>,
) -> GuardWatch {
    let done = Arc::new(AtomicBool::new(false));
    let stopped = done.clone();
    let worker = std::thread::spawn(move || {
        while !stopped.load(Ordering::SeqCst) {
            // Root replaces the small heartbeat atomically. Retry a read-side
            // identity race; never renew a stale timestamp or guard invocation.
            let mut valid = false;
            for _ in 0..3 {
                if heartbeat(&p, &plan_sha, &iid, Some(&guard_iid)).is_ok() {
                    valid = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if !valid {
                shutdown.store(true, Ordering::SeqCst);
                eprintln!(
                    "closed capped continuation lost its independent protective guard; preserving private artifacts and exiting"
                );
                // A stalled archive read must not outlive its guard. The bound
                // service's required KillMode=control-group reaps its worker.
                std::process::exit(1);
            }
            for _ in 0..50 {
                if stopped.load(Ordering::SeqCst) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });
    GuardWatch {
        done,
        worker: Some(worker),
    }
}

fn phase(p: &Plan, old: &mut Phase, next: Stage) -> Result<(), String> {
    *old = old
        .transition(next, control::now_millis().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    control::atomic_json(&p.phase_path(), old, 1000, true).map_err(|e| e.to_string())
}

fn source_identity(p: &Plan, v: &Value, file: &File) -> Result<(), String> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    let i = &v["archive_identity"];
    require(
        p.prefix_archive
            .path
            .canonicalize()
            .map_err(|e| e.to_string())?
            == p.prefix_archive.path
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() == p.prefix_bytes
            && i["device"] == m.dev()
            && i["inode"] == m.ino()
            && i["bytes"] == m.len()
            && i["mtime"] == m.mtime()
            && i["mtime_nanos"] == m.mtime_nsec()
            && i["ctime"] == m.ctime()
            && i["ctime_nanos"] == m.ctime_nsec(),
        "retained frozen prefix identity differs from actual root custody capture",
    )
}

struct GuardedSink<'a> {
    file: File,
    plan: &'a Plan,
    plan_sha: &'a str,
    iid: &'a str,
    guard_iid: &'a str,
    checked: Instant,
}
impl Write for GuardedSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.checked.elapsed() >= Duration::from_secs(1) {
            heartbeat(self.plan, self.plan_sha, self.iid, Some(self.guard_iid))
                .map_err(std::io::Error::other)?;
            if available_bytes(&self.plan.run_root).map_err(std::io::Error::other)?
                < self.plan.protected_existing_floor_bytes
            {
                return Err(std::io::Error::other(
                    "protected filesystem floor during V4 assembly",
                ));
            }
            self.checked = Instant::now();
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub(crate) async fn run(
    plan_path: PathBuf,
    plan_sha: String,
    destination: PathBuf,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<(), String> {
    require(
        cfg!(feature = "capped204205-checkpoint-continuation-diagnostic"),
        "exclusive closed capped continuation build required",
    )?;
    let p: Plan = serde_json::from_slice(
        &control::sealed(
            &Bound {
                path: plan_path.clone(),
                sha256: plan_sha.clone(),
            },
            4 << 20,
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    p.validate(&destination).map_err(|e| e.to_string())?;
    let profile = capped::profile(p.epoch).map_err(|e| e.to_string())?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "private capped continuation requires isolated UID1000",
    )?;
    control::sealed(
        &Bound {
            path: fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
            sha256: p.node_sha256.clone(),
        },
        256 << 20,
    )
    .map_err(|e| e.to_string())?;
    let iid = authenticate_service(&p.producer_unit)?;
    let (policy, expected_manifest) = p
        .metadata
        .authenticate(p.epoch)
        .map_err(|e| e.to_string())?;
    let capture: Value = serde_json::from_slice(
        &control::sealed(&p.source_capture, 4 << 20).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    control::validate_capture(
        &p,
        &capture,
        &expected_manifest,
        control::now_millis().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let admission_bytes =
        control::stable_read(&p.admission_receipt, 4 << 20, 0, true).map_err(|e| e.to_string())?;
    let admitted: Value = serde_json::from_slice(&admission_bytes).map_err(|e| e.to_string())?;
    control::validate_admission(
        &p,
        &plan_sha,
        &admitted,
        control::now_millis().map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // Authenticate the fleet sample's real immutable bytes rather than a named
    // digest inside a positive admission assertion.
    let fleet: Bound =
        serde_json::from_value(admitted["fleet_observation"].clone()).map_err(|e| e.to_string())?;
    control::sealed(&fleet, 64 << 20).map_err(|e| e.to_string())?;
    let resource_proposal: Bound =
        serde_json::from_value(admitted["resource_proposal"].clone()).map_err(|e| e.to_string())?;
    control::sealed(&resource_proposal, 8 << 20).map_err(|e| e.to_string())?;
    require(
        available_bytes(&p.run_root)? >= p.initial_free_bytes().map_err(|e| e.to_string())?,
        "complete-path initial free-space envelope no longer fits",
    )?;
    let root = fs::symlink_metadata(&p.run_root).map_err(|e| e.to_string())?;
    require(
        p.run_root.canonicalize().map_err(|e| e.to_string())? == p.run_root
            && root.is_dir()
            && root.uid() == 1000
            && root.mode() & 0o077 == 0
            && fs::read_dir(&p.run_root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none(),
        "fresh owner-private continuation root required",
    )?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(
            Path::new("/home/ubuntu/.jetstreamer-private")
                .join(format!("capped-checkpoint-continuation-{}.lock", p.epoch)),
        )
        .map_err(|e| e.to_string())?;
    let lm = lock.metadata().map_err(|e| e.to_string())?;
    require(
        lm.is_file()
            && lm.nlink() == 1
            && lm.uid() == 1000
            && lm.mode() & 0o077 == 0
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "closed continuation epoch lease occupied or unsafe",
    )?;
    let mut stage = Phase {
        schema: "jetstreamer-capped204205-continuation-phase-v1".into(),
        epoch: p.epoch,
        plan_sha256: plan_sha.clone(),
        invocation_id: iid.clone(),
        stage: Stage::WaitingForGuard,
        started_unix_millis: control::now_millis().map_err(|e| e.to_string())?,
    };
    control::atomic_json(&p.phase_path(), &stage, 1000, false).map_err(|e| e.to_string())?;
    let waiting = Instant::now();
    let first_guard = loop {
        if let Ok(value) = heartbeat(&p, &plan_sha, &iid, None) {
            break value;
        }
        require(
            !shutdown.load(Ordering::SeqCst) && waiting.elapsed() <= Duration::from_secs(90),
            "no actual independent guard first fire; no prefix body or snapshot was read",
        )?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let guard_iid = first_guard["guard_invocation_id"]
        .as_str()
        .ok_or("guard IID missing")?
        .to_owned();
    let _watch = watch_guard(
        p.clone(),
        plan_sha.clone(),
        iid.clone(),
        guard_iid.clone(),
        shutdown.clone(),
    );
    let candidate = env_truthy_default("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", false);
    let selection =
        select_runtime_for_invocation(profile.restart + 1..profile.end + 1, candidate, true)?;
    require(
        selection.backend == compatibility::RuntimeBackend::SolanaV1_6_16
            && configured_historical_worker_executable(selection.descriptor)? == p.worker.path,
        "exact capped worker/registry selection differs",
    )?;
    control::sealed(&p.worker, 256 << 20).map_err(|e| e.to_string())?;
    let genesis = control::sealed(&p.genesis_archive, 10 << 20).map_err(|e| e.to_string())?;
    let retained = open_regular_nofollow(&p.prefix_archive.path).map_err(|e| e.to_string())?;
    source_identity(&p, &capture, &retained)?;
    let retained_identity = archive_file_identity(&retained).map_err(|e| e.to_string())?;
    require_no_checksum(&p.prefix_archive.path)?;
    phase(&p, &mut stage, Stage::PrefixValidation)?;
    let archive = p.prefix_archive.path.clone();
    let manifest_path = p.metadata.prefix_manifest.path.clone();
    let reread = tokio::task::spawn_blocking(move || {
        read_and_validate_segment_manifest_from(archive, manifest_path).map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    require(
        reread == expected_manifest
            && archive_file_identity(&retained).map_err(|e| e.to_string())? == retained_identity
            && path_matches_archive_identity(&p.prefix_archive.path, retained_identity)
                .map_err(|e| e.to_string())?,
        "full original prefix reread differs or retained source changed",
    )?;
    source_identity(&p, &capture, &retained)?;
    heartbeat(&p, &plan_sha, &iid, Some(&guard_iid))?;
    for name in ["ledger", "scratch", "output", "receipts"] {
        create_private_dir(&p.run_root.join(name))?;
    }
    write_new(&destination.join("genesis.tar.bz2"), &genesis)?;
    let validated = Validated {
        profile,
        policy,
        snapshot: p.restart_snapshot.path.clone(),
        actual_native: Mutex::new(None),
    };
    let suffix = p
        .run_root
        .join(format!("output/epoch-{}-suffix.jet", p.epoch));
    let output = p.run_root.join(format!(
        "output/epoch-{}-checkpoint-restart-v4.jet",
        p.epoch
    ));
    require_no_checksum(&suffix)?;
    require_no_checksum(&output)?;
    let q = QualificationPlan {
        epoch: p.epoch,
        bootstrap_slot: profile.restart,
        replay_start: profile.restart + 1,
        output_slot_start: profile.restart + 1,
        end_inclusive: profile.end,
    };
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([(
            profile.restart,
            BankHashExpectation::LegacyAccountsHash(
                profile
                    .restart_accounts
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
            ),
        )]),
        Some(shutdown.clone()),
    ));
    phase(&p, &mut stage, Stage::NativeRestore)?;
    let replay = run_geyser_replay(
        p.epoch,
        candidate,
        &destination,
        &p.run_root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(validated.snapshot.clone()),
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        suffix.clone(),
        Some(q),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&validated),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    require(
        !shutdown.load(Ordering::SeqCst),
        "closed capped suffix interrupted; preserve all private artifacts",
    )?;
    verifier.finish()?;
    phase(&p, &mut stage, Stage::SuffixValidation)?;
    publish_historical_segment_manifest(p.epoch, q, &suffix, &replay, candidate)?;
    require_no_checksum(&suffix)?;
    let suffix_manifest = read_and_validate_segment_manifest(&suffix).map_err(|e| e.to_string())?;
    let native = validated
        .actual_native
        .lock()
        .map_err(|_| "native state poisoned")?
        .ok_or("actual suffix did not pass its native barrier")?;
    let barrier = validated
        .policy
        .native_barrier(
            native.checkpoint,
            native.writes,
            native.worker,
            native.cursor,
            native.ticks,
        )
        .map_err(|e| e.to_string())?;
    let metadata =
        archive_transaction_metadata_policy(profile.start, profile.end - profile.start + 1);
    let provenance = barrier
        .provenance(&suffix_manifest, &archive_generation_profile(), metadata)
        .map_err(|e| e.to_string())?;
    control::atomic_json(&p.run_root.join("receipts/suffix.json"), &json!({
        "schema":"jetstreamer-capped204205-private-suffix-v1","epoch":p.epoch,"plan_sha256":plan_sha,
        "producer_invocation_id":iid,"prefix_sha256":p.prefix_archive.sha256,"suffix_manifest":suffix_manifest,
        "native_checkpoint":native.receipt(),"worker_sha256":p.worker.sha256,"complete_prefix_reread":true,
        "actual_suffix_native_barrier_passed":true,"provenance_version":4,
        "assembly_profile":provenance.base.assembly_profile,"authority":control::denied_authority(),
    }), 1000, false).map_err(|e| e.to_string())?;
    require(
        available_bytes(&p.run_root)?
            >= p.protected_existing_floor_bytes
                .checked_add(p.prefix_bytes)
                .and_then(|n| n.checked_add(32 << 30))
                .ok_or("assembly free-space arithmetic overflow")?,
        "private suffix is complete; preserve it until full V4 assembly reserve fits",
    )?;
    heartbeat(&p, &plan_sha, &iid, Some(&guard_iid))?;
    source_identity(&p, &capture, &retained)?;
    phase(&p, &mut stage, Stage::Assembly)?;
    let prefix_reader = open_regular_nofollow(&p.prefix_archive.path).map_err(|e| e.to_string())?;
    let suffix_reader = open_regular_nofollow(&suffix).map_err(|e| e.to_string())?;
    let suffix_identity = archive_file_identity(&suffix_reader).map_err(|e| e.to_string())?;
    let suffix_handle = suffix_reader.try_clone().map_err(|e| e.to_string())?;
    let sink = GuardedSink {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output)
            .map_err(|e| e.to_string())?,
        plan: &p,
        plan_sha: &plan_sha,
        iid: &iid,
        guard_iid: &guard_iid,
        checked: Instant::now(),
    };
    let (sink, stats) = barrier
        .assemble(
            &suffix_manifest,
            BufReader::new(prefix_reader),
            BufReader::new(suffix_reader),
            sink,
            AssemblyOptions {
                writer: ArchiveWriterConfig::default(),
                generation: &archive_generation_profile(),
                metadata,
            },
        )
        .map_err(|e| e.to_string())?;
    sink.file.sync_all().map_err(|e| e.to_string())?;
    File::open(output.parent().ok_or("output parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    require(
        archive_file_identity(&retained).map_err(|e| e.to_string())? == retained_identity
            && path_matches_archive_identity(&p.prefix_archive.path, retained_identity)
                .map_err(|e| e.to_string())?
            && archive_file_identity(&suffix_handle).map_err(|e| e.to_string())? == suffix_identity
            && path_matches_archive_identity(&suffix, suffix_identity)
                .map_err(|e| e.to_string())?,
        "assembly source identity changed; preserve private artifacts and fail closed",
    )?;
    for archive in [&p.prefix_archive.path, &suffix, &output] {
        require_no_checksum(archive)?;
    }
    control::atomic_json(&p.run_root.join("receipts/continuation.json"), &json!({
        "schema":"jetstreamer-capped204205-private-continuation-v1","epoch":p.epoch,"plan_sha256":plan_sha,
        "producer_invocation_id":iid,"guard_invocation_id":guard_iid,"admission_sha256":capped::hex_sha(&admission_bytes),
        "source_capture":p.source_capture,"prefix_archive":p.prefix_archive,"suffix_manifest":suffix_manifest,
        "private_output":output,"provenance_version":4,"assembly_profile":provenance.base.assembly_profile,
        "native_checkpoint":native.receipt(),"slots_merged":stats.slots_merged,
        "source_archives":stats.source_archives,"account_updates_rebased":stats.account_updates_rebased,
        "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "independent_adjacent_boundary_receipts_still_required":true,"authority":control::denied_authority(),
    }), 1000, false).map_err(|e| e.to_string())?;
    phase(&p, &mut stage, Stage::Complete)?;
    info!(
        "closed capped {} private suffix and V4 assembly complete; final/current-plugin/publication gates remain separate",
        p.epoch
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_cli_rejects_ranges_ordinary_builds_and_overrides() {
        for epochs in [(203, 203), (204, 205), (205, 206), (206, 206)] {
            assert!(validate_cli(epochs, Some(true), 1, true, false).is_err());
        }
        for epoch in [204, 205] {
            assert_eq!(
                validate_cli((epoch, epoch), Some(true), 1, true, false).is_ok(),
                cfg!(feature = "capped204205-checkpoint-continuation-diagnostic")
            );
            assert!(validate_cli((epoch, epoch), Some(true), 1, true, true).is_err());
            assert!(validate_cli((epoch, epoch), None, 0, true, false).is_err());
        }
    }
}
