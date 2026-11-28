//! Explicit private suffix replay from a pressure checkpoint. This route never
//! waives the canonical terminal, grants resource admission, or publishes a sidecar.
use super::*;
use checkpoint_continuation::{Evidence, RestartProof, checkpoint_matches, require, sealed_bytes};
use jetstreamer_node::archive_checksum::{
    ArchiveFileIdentity, archive_file_identity, open_regular_nofollow,
    path_matches_archive_identity,
};
use std::{fs::File, os::unix::fs::MetadataExt};

pub(crate) struct ValidatedResume {
    prefix: PathBuf,
    snapshot: PathBuf,
    manifest: HistoricalSegmentManifest,
    snapshot_manifest: HistoricalHandoffSnapshotManifest,
    end: u64,
    suffix: PathBuf,
    pinned: Vec<(PathBuf, File, ArchiveFileIdentity)>,
    native_checked: AtomicBool,
}

pub(crate) fn validate_mode(
    focused: bool,
    verifies: usize,
    incompatible: bool,
) -> Result<(), String> {
    require(
        focused && verifies == 1 && !incompatible,
        "checkpoint resume requires standalone focused qualification, exactly one --verify, and no export, carry, cohort, directory load or recovery override",
    )
}

fn scope(
    q: QualificationPlan,
    manifest: &HistoricalSegmentManifest,
    end: u64,
) -> Result<(), String> {
    require(
        q.epoch == manifest.epoch
            && q.bootstrap_slot == manifest.terminal.slot
            && manifest.terminal.slot.checked_add(1) == Some(q.replay_start)
            && q.output_slot_start == q.replay_start
            && manifest
                .output_slot_end()
                .is_ok_and(|end| end == q.replay_start)
            && q.end_inclusive == end
            && q.bootstrap_slot < end
            && manifest.output_slot_start == epoch_to_slot_range(q.epoch).0
            && manifest.runtime.runtime_profile == "solana-v1.7.15",
        "checkpoint resume range, epoch prefix coverage or runtime differs",
    )
}

impl ValidatedResume {
    pub(crate) fn load(
        report: &Path,
        report_sha: &str,
        exit_proof: Evidence,
        q: QualificationPlan,
        snapshot: &Path,
        suffix: &Path,
    ) -> Result<Self, String> {
        let bytes = sealed_bytes(
            &Evidence {
                path: report.into(),
                sha256: report_sha.into(),
            },
            4 << 20,
        )?;
        let report: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        qualification_checkpoint_exit::load(&exit_proof, &report, report_sha, q.epoch)?;
        require(
            report["schema"] == "horizon-pressure-checkpoint-paused-v3"
                && report["worker_shutdown_acknowledged"] == true
                && report["worker_reap_verified"] == true
                && report["worker_shutdown"]["state"] == "reaped"
                && report["full_range_completed"] == false
                && report["resource_release_authorized"] == false
                && report["publication_authorized"] == false
                && report["resume_authorized"] == false,
            "checkpoint resume requires a sealed paused-v3 report with synchronous worker reap",
        )?;
        let pid: i32 = report["producer_pid"]
            .as_u64()
            .ok_or("missing producer PID")?
            .try_into()
            .map_err(|_| "producer PID overflow")?;
        require(pid > 1, "invalid producer PID")?;
        let absent = unsafe { libc::kill(pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
        require(
            absent,
            "checkpoint producer exists after the recorded exit proof",
        )?;
        let prefix = PathBuf::from(
            report["verified_prefix"]["path"]
                .as_str()
                .ok_or("missing prefix path")?,
        );
        require(
            report["snapshot"]["path"].as_str() == snapshot.to_str(),
            "checkpoint snapshot path differs",
        )?;
        let end = report["intended_terminal_slot"]
            .as_u64()
            .ok_or("missing intended terminal")?;
        let parent = suffix.parent().ok_or("suffix has no parent")?;
        let metadata = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        require(
            parent.is_absolute()
                && parent.canonicalize().map_err(|e| e.to_string())? == parent
                && metadata.is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "resume output requires an owned private canonical parent",
        )?;
        require(
            fs::symlink_metadata(suffix).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                && fs::symlink_metadata(suffix.with_extension("restart-v4.jet"))
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "resume requires fresh suffix and assembly destinations",
        )?;
        let paths = [
            prefix.clone(),
            jetstreamer_node::segment_manifest::segment_manifest_path(&prefix)
                .map_err(|e| e.to_string())?,
            snapshot.into(),
            handoff_snapshot_manifest_path(snapshot).map_err(|e| e.to_string())?,
        ];
        let mut pinned = Vec::new();
        for path in paths {
            require(
                path.is_absolute() && path.canonicalize().map_err(|e| e.to_string())? == path,
                "resume input path must be canonical",
            )?;
            let file = open_regular_nofollow(&path).map_err(|e| e.to_string())?;
            let identity = archive_file_identity(&file).map_err(|e| e.to_string())?;
            let m = file.metadata().map_err(|e| e.to_string())?;
            require(
                m.uid() == unsafe { libc::geteuid() } && m.nlink() == 1 && m.mode() & 0o077 == 0,
                "resume input must be singly linked and owner-private",
            )?;
            pinned.push((path, file, identity));
        }
        info!("checkpoint resume independently rereading complete prefix and snapshot");
        let (manifest, snapshot_manifest) =
            jetstreamer_node::checkpoint_bundle::read_and_validate_checkpoint_bundle(
                &prefix, snapshot,
            )?;
        scope(q, &manifest, end)?;
        require(
            report["epoch"] == q.epoch
                && report["selected_source_slot"] == manifest.terminal.slot
                && serde_json::from_value::<HistoricalSegmentManifest>(
                    report["verified_prefix"]["segment"].clone(),
                )
                .map_err(|e| e.to_string())?
                    == manifest
                && serde_json::from_value::<[u8; 32]>(report["verified_prefix"]["sha256"].clone())
                    .map_err(|e| e.to_string())?
                    == manifest.archive_sha256
                && serde_json::from_value::<[u8; 32]>(report["snapshot"]["sha256"].clone())
                    .map_err(|e| e.to_string())?
                    == snapshot_manifest.archive_sha256
                && report["snapshot"]["length"] == snapshot_manifest.archive_size,
            "paused report differs from independently reread checkpoint bundle",
        )?;
        let value = Self {
            prefix,
            snapshot: snapshot.into(),
            manifest,
            snapshot_manifest,
            end,
            suffix: suffix.into(),
            pinned,
            native_checked: AtomicBool::new(false),
        };
        value.revalidate()?;
        Ok(value)
    }

    fn revalidate(&self) -> Result<(), String> {
        for (path, file, identity) in &self.pinned {
            require(
                archive_file_identity(file).map_err(|e| e.to_string())? == *identity
                    && path_matches_archive_identity(path, *identity).map_err(|e| e.to_string())?,
                "checkpoint resume input identity changed",
            )?;
        }
        Ok(())
    }

    /// The exported accounts hash is a local restart commitment, not an external
    /// canonical root. Validate it without inserting it into the trusted list.
    /// The actual restored worker still has to pass `verify_native_checkpoint`.
    pub(crate) fn validate_bootstrap_expectation(
        &self,
        q: QualificationPlan,
        snapshot: &Path,
        expectation: BankHashExpectation,
    ) -> Result<(), String> {
        self.revalidate()?;
        scope(q, &self.manifest, self.end)?;
        let hash = self
            .manifest
            .terminal
            .accounts_hash
            .parse::<Hash>()
            .map_err(|e| e.to_string())?;
        require(
            snapshot == self.snapshot
                && self.snapshot_manifest.snapshot_slot == q.bootstrap_slot
                && self.snapshot_manifest.accounts_hash == hash.to_string()
                && expectation == BankHashExpectation::LegacyAccountsHash(hash),
            "checkpoint resume bootstrap differs from the validated local bundle",
        )
    }

    pub(crate) fn require_terminal(
        &self,
        verifier: Option<&SnapshotVerifier>,
    ) -> Result<(), String> {
        require(
            verifier.is_some_and(|v| v.expected.contains_key(&self.end)),
            "checkpoint resume requires the exact canonical terminal in the verification set",
        )
    }

    pub(crate) fn assemble(
        &self,
        suffix: &Path,
        manifest: &HistoricalSegmentManifest,
    ) -> Result<(), String> {
        self.revalidate()?;
        require(
            self.native_checked.load(Ordering::SeqCst) && suffix == self.suffix,
            "checkpoint assembly requires the actual suffix worker native restart barrier",
        )?;
        require(
            manifest.epoch == self.manifest.epoch
                && manifest.output_slot_start == self.manifest.terminal.slot + 1
                && manifest.output_slot_end().ok() == self.end.checked_add(1)
                && manifest.terminal.slot == self.end
                && manifest.runtime == self.manifest.runtime
                && manifest.worker_executable_sha256 == self.manifest.worker_executable_sha256
                && manifest.bootstrap_archive_sha256 == Some(self.snapshot_manifest.archive_sha256),
            "checkpoint suffix coverage, runtime or snapshot binding differs",
        )?;
        checkpoint_matches(&self.manifest.terminal, &manifest.bootstrap)?;
        let mut cursor = 0;
        let mut segments = Vec::new();
        for source in [&self.manifest, manifest] {
            let mapping = WriteVersionNormalization {
                worker_start: source.emitted_raw_write_versions.start,
                worker_end_exclusive: source.emitted_raw_write_versions.end,
                archive_start: cursor,
            };
            cursor = mapping
                .archive_end_exclusive()
                .ok_or("normalized cursor overflow")?;
            segments.push(RuntimeSegmentProvenance {
                slot_start: source.output_slot_start,
                slot_count: source.output_slot_count,
                generation_profile: source.runtime.generation_profile.clone(),
                runtime_profile: source.runtime.runtime_profile.clone(),
                runtime_admission: match source.runtime.runtime_admission {
                    SegmentRuntimeAdmission::Verified => RuntimeAdmission::Verified,
                    SegmentRuntimeAdmission::Candidate => RuntimeAdmission::Candidate,
                },
                runtime_revision: source.runtime.runtime_revision.clone(),
                runtime_toolchain: source.runtime.runtime_toolchain.clone(),
                worker_executable_sha256: Some(source.worker_executable_sha256),
                write_versions: mapping,
            });
        }
        let start = self.manifest.output_slot_start;
        let count = self
            .end
            .checked_sub(start)
            .and_then(|n| n.checked_add(1))
            .ok_or("assembly coverage overflow")?;
        let provenance = jetstreamer_horizon::archive::ArchiveProvenanceV4 {
            base: ArchiveProvenanceV3 {
                assembly_profile: "private-pressure-checkpoint-resume-v1".into(),
                genesis_hash: self
                    .manifest
                    .runtime
                    .genesis_hash
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
                bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
                bootstrap_state: StateCommitment {
                    slot: self.manifest.bootstrap.slot,
                    kind: StateCommitmentKind::LegacyAccountsHash,
                    hash: self
                        .manifest
                        .bootstrap
                        .accounts_hash
                        .parse::<Hash>()
                        .map_err(|e| e.to_string())?,
                },
                requested_slot_start: start,
                requested_slot_count: count,
                transaction_metadata: archive_transaction_metadata_policy(start, count),
                runtime_segments: segments,
                handoffs: vec![RuntimeHandoffProvenance {
                    boundary_slot: manifest.output_slot_start,
                    predecessor: checkpoint_continuation::runtime_checkpoint(
                        &self.manifest.terminal,
                    )?,
                    successor: checkpoint_continuation::runtime_checkpoint(&manifest.bootstrap)?,
                    successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                    successor_bootstrap_archive_sha256: self.snapshot_manifest.archive_sha256,
                    successor_bootstrap_write_count: manifest.bootstrap.write_count,
                }],
            },
        };
        provenance.validate().map_err(|e| e.to_string())?;
        let output = suffix.with_extension("restart-v4.jet");
        checkpoint_continuation::assemble_sources(
            &self.prefix,
            &self.manifest,
            suffix,
            manifest,
            &output,
            &provenance,
        )?;
        self.revalidate()?;
        info!(
            "private checkpoint assembly {} complete; full/current-plugin/canonical publication and resource-release gates remain independent",
            output.display()
        );
        Ok(())
    }
}

impl RestartProof for ValidatedResume {
    fn snapshot_sha256(&self) -> [u8; 32] {
        self.snapshot_manifest.archive_sha256
    }
    fn snapshot_size(&self) -> u64 {
        self.snapshot_manifest.archive_size
    }
    fn restored_verification(&self) -> Result<historical_replay::RestoredCheckpointTrust, String> {
        self.revalidate()?;
        require(
            self.native_checked.load(Ordering::SeqCst),
            "pressure restart requires the actual native barrier before verifier construction",
        )?;
        Ok(
            historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(
                self.end,
            ),
        )
    }
    fn covers_trusted_root(&self, _: u64, _: u64, _: u64, _: u64) -> bool {
        false
    }
    fn validate_invocation(
        &self,
        epoch: u64,
        bootstrap: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        carried: bool,
        audited: bool,
        retain: bool,
    ) -> Result<(), String> {
        self.revalidate()?;
        require(
            !carried
                && !audited
                && !retain
                && epoch == self.manifest.epoch
                && bootstrap.snapshot_archive() == Some(self.snapshot.as_path()),
            "checkpoint resume cannot borrow cohort or carry authority",
        )?;
        scope(
            q.ok_or("checkpoint resume requires focused qualification")?,
            &self.manifest,
            self.end,
        )
    }
    fn verify_native_checkpoint(
        &self,
        actual: &historical::HistoricalCheckpoint,
        worker: [u8; 32],
        initialized_cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        self.revalidate()?;
        require(
            worker == self.manifest.worker_executable_sha256
                && ticks == 64
                && actual.next_write_version == initialized_cursor,
            "checkpoint restored worker or native cursor differs",
        )?;
        checkpoint_matches(
            &self.manifest.terminal,
            &segment_checkpoint_summary(&historical_replay::HistoricalCheckpointSummary::try_from(
                actual,
            )?),
        )?;
        self.native_checked
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "checkpoint native barrier was attempted twice")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (
        ValidatedResume,
        QualificationPlan,
        historical::HistoricalCheckpoint,
    ) {
        let start = epoch_to_slot_range(252).0;
        let hash = Hash::new_from_array([1; 32]).to_string();
        let terminal = SegmentCheckpointSummary {
            slot: start + 9,
            bank_hash: hash.clone(),
            accounts_hash: hash.clone(),
            last_blockhash: hash.clone(),
            capitalization: 42,
            transaction_count: 7,
            tick_height: (start + 10) * 64,
            slot_complete: true,
            write_count: 0,
            next_write_version: 1000,
        };
        let runtime = SegmentRuntimeIdentity {
            generation_profile: "test".into(),
            runtime_profile: "solana-v1.7.15".into(),
            runtime_admission: SegmentRuntimeAdmission::Candidate,
            runtime_revision: "revision".into(),
            runtime_toolchain: "toolchain".into(),
            runtime_target: "target".into(),
            genesis_hash: hash.clone(),
        };
        let manifest = HistoricalSegmentManifest {
            schema_version: 1,
            epoch: 252,
            output_slot_start: start,
            output_slot_count: 10,
            runtime: runtime.clone(),
            worker_executable_sha256: [2; 32],
            archive_sha256: [3; 32],
            bootstrap_archive_sha256: None,
            bootstrap: SegmentCheckpointSummary {
                slot: start - 1,
                tick_height: start * 64,
                ..terminal.clone()
            },
            terminal: terminal.clone(),
            emitted_raw_write_versions: 1..1000,
        };
        let snapshot = PathBuf::from(format!("/private/snapshot-{}-{hash}.tar.bz2", start + 9));
        let snapshot_manifest = HistoricalHandoffSnapshotManifest {
            schema_version: 1,
            boundary_slot: start + 10,
            snapshot_slot: start + 9,
            accounts_hash: hash,
            archive_path: snapshot.display().to_string(),
            archive_size: 123,
            archive_sha256: [4; 32],
            source_runtime: runtime,
            source_worker_executable_sha256: [2; 32],
            terminal: terminal.clone(),
        };
        let q = QualificationPlan {
            epoch: 252,
            bootstrap_slot: start + 9,
            replay_start: start + 10,
            output_slot_start: start + 10,
            end_inclusive: start + 19,
        };
        let actual = historical::HistoricalCheckpoint {
            slot: terminal.slot,
            bank_hash: [1; 32],
            accounts_hash: [1; 32],
            last_blockhash: [1; 32],
            capitalization: 42,
            transaction_count: 7,
            tick_height: terminal.tick_height,
            slot_complete: true,
            writes: Vec::new(),
            next_write_version: 7,
        };
        (
            ValidatedResume {
                prefix: "/private/prefix.jet".into(),
                snapshot,
                manifest,
                snapshot_manifest,
                end: q.end_inclusive,
                suffix: "/private/suffix.jet".into(),
                pinned: Vec::new(),
                native_checked: AtomicBool::new(false),
            },
            q,
            actual,
        )
    }

    #[test]
    fn resume_accepts_local_bootstrap_without_inventing_a_canonical_root() {
        let (proof, q, actual) = fixture();
        let hash = Hash::new_from_array([1; 32]);
        let terminal_hash = Hash::new_from_array([8; 32]);
        let expected = BTreeMap::from([
            (
                q.bootstrap_slot - 1,
                BankHashExpectation::LegacyAccountsHash(hash),
            ),
            (
                q.replay_start,
                BankHashExpectation::LegacyAccountsHash(hash),
            ),
            (
                q.end_inclusive,
                BankHashExpectation::LegacyAccountsHash(terminal_hash),
            ),
            (
                q.end_inclusive + 1,
                BankHashExpectation::LegacyAccountsHash(hash),
            ),
        ]);
        let bootstrap = compatibility::SOLANA_V1_7_15_RUNTIME.bootstrap;
        assert!(
            qualification_expectations(expected.clone(), q, &proof.snapshot, bootstrap, None)
                .unwrap_err()
                .contains("absent")
        );
        let scoped =
            qualification_expectations(expected, q, &proof.snapshot, bootstrap, Some(&proof))
                .unwrap();
        assert_eq!(scoped.len(), 2);
        assert!(!scoped.contains_key(&q.bootstrap_slot));
        assert!(!proof.native_checked.load(Ordering::SeqCst));
        assert!(proof.restored_verification().is_err());
        let verifier = SnapshotVerifier::new(scoped, None);
        proof.require_terminal(Some(&verifier)).unwrap();
        proof
            .verify_native_checkpoint(&actual, [2; 32], 7, 64)
            .unwrap();
        assert!(matches!(proof.restored_verification().unwrap(),
            historical_replay::RestoredCheckpointTrust::LocalBootstrapWithCanonicalTerminal(end) if end == q.end_inclusive));
        verifier.verify_legacy_accounts_hash(q.replay_start, hash);
        assert!(verifier.finish().is_err());
        verifier.verify_legacy_accounts_hash(q.end_inclusive, terminal_hash);
        assert!(verifier.finish().is_ok());
    }

    #[test]
    fn resume_expectations_reject_conflicts_missing_terminal_and_changed_bundle() {
        let (mut proof, q, _) = fixture();
        let hash = Hash::new_from_array([1; 32]);
        let bootstrap = compatibility::SOLANA_V1_7_15_RUNTIME.bootstrap;
        let mut expected = BTreeMap::from([
            (
                q.bootstrap_slot,
                BankHashExpectation::LegacyAccountsHash(hash),
            ),
            (
                q.end_inclusive,
                BankHashExpectation::LegacyAccountsHash(hash),
            ),
        ]);
        let scoped = qualification_expectations(
            expected.clone(),
            q,
            &proof.snapshot,
            bootstrap,
            Some(&proof),
        )
        .unwrap();
        assert_eq!(scoped, expected);
        expected.insert(
            q.bootstrap_slot,
            BankHashExpectation::LegacyAccountsHash(Hash::new_unique()),
        );
        assert!(
            qualification_expectations(
                expected.clone(),
                q,
                &proof.snapshot,
                bootstrap,
                Some(&proof)
            )
            .unwrap_err()
            .contains("does not match the canonical")
        );
        expected.remove(&q.bootstrap_slot);
        expected.remove(&q.end_inclusive);
        expected.insert(
            q.end_inclusive - 1,
            BankHashExpectation::LegacyAccountsHash(hash),
        );
        assert!(
            qualification_expectations(
                expected.clone(),
                q,
                &proof.snapshot,
                bootstrap,
                Some(&proof)
            )
            .unwrap_err()
            .contains("exact canonical terminal")
        );
        expected.insert(
            q.end_inclusive,
            BankHashExpectation::LegacyAccountsHash(hash),
        );
        proof.snapshot_manifest.accounts_hash = Hash::new_unique().to_string();
        assert!(
            qualification_expectations(expected, q, &proof.snapshot, bootstrap, Some(&proof))
                .unwrap_err()
                .contains("validated local bundle")
        );
    }

    #[test]
    fn resume_scope_preserves_full_prefix_and_original_terminal() {
        let (proof, q, _) = fixture();
        assert!(scope(q, &proof.manifest, proof.end).is_ok());
        for mutate in [
            (|q: &mut QualificationPlan| q.epoch += 1) as fn(&mut QualificationPlan),
            |q| q.bootstrap_slot += 1,
            |q| q.replay_start += 1,
            |q| q.output_slot_start += 1,
            |q| q.end_inclusive -= 1,
        ] {
            let mut changed = q;
            mutate(&mut changed);
            assert!(scope(changed, &proof.manifest, proof.end).is_err());
        }
        let mut changed = proof.manifest.clone();
        changed.output_slot_start += 1;
        assert!(scope(q, &changed, proof.end).is_err());
        for count in [9, 11] {
            let mut changed = proof.manifest.clone();
            changed.output_slot_count = count;
            assert!(scope(q, &changed, proof.end).is_err());
        }
    }

    #[test]
    fn resume_cannot_use_prefix_as_a_substitute_for_canonical_terminal() {
        let (proof, q, _) = fixture();
        assert!(!proof.covers_trusted_root(
            q.epoch,
            q.bootstrap_slot,
            q.output_slot_start,
            q.end_inclusive
        ));
        assert!(proof.require_terminal(None).is_err());
        let earlier = SnapshotVerifier::new(
            BTreeMap::from([(
                q.bootstrap_slot,
                BankHashExpectation::LegacyAccountsHash(Hash::new_from_array([1; 32])),
            )]),
            None,
        );
        assert!(proof.require_terminal(Some(&earlier)).is_err());
        let exact = SnapshotVerifier::new(
            BTreeMap::from([(
                q.end_inclusive,
                BankHashExpectation::LegacyAccountsHash(Hash::new_from_array([1; 32])),
            )]),
            None,
        );
        assert!(proof.require_terminal(Some(&exact)).is_ok());
    }

    #[test]
    fn resume_checks_actual_worker_consensus_and_keeps_cursors_independent() {
        let (proof, _, actual) = fixture();
        assert_ne!(
            actual.next_write_version,
            proof.manifest.terminal.next_write_version
        );
        assert!(
            proof
                .verify_native_checkpoint(&actual, [9; 32], 7, 64)
                .is_err()
        );
        assert!(
            proof
                .verify_native_checkpoint(&actual, [2; 32], 8, 64)
                .is_err()
        );
        assert!(
            proof
                .verify_native_checkpoint(&actual, [2; 32], 7, 32)
                .is_err()
        );
        for mutate in [
            (|c: &mut historical::HistoricalCheckpoint| c.slot += 1)
                as fn(&mut historical::HistoricalCheckpoint),
            |c| c.bank_hash[0] ^= 1,
            |c| c.accounts_hash[0] ^= 1,
            |c| c.last_blockhash[0] ^= 1,
            |c| c.capitalization += 1,
            |c| c.transaction_count += 1,
            |c| c.tick_height += 1,
            |c| c.slot_complete = false,
        ] {
            let mut changed = actual.clone();
            mutate(&mut changed);
            assert!(
                proof
                    .verify_native_checkpoint(&changed, [2; 32], 7, 64)
                    .is_err()
            );
        }
        proof
            .verify_native_checkpoint(&actual, [2; 32], 7, 64)
            .unwrap();
        assert!(
            proof
                .verify_native_checkpoint(&actual, [2; 32], 7, 64)
                .is_err()
        );
    }
    #[test]
    fn resume_requires_explicit_focused_verification_and_excludes_other_routes() {
        for focused in [false, true] {
            for count in 0..3 {
                for mixed in [false, true] {
                    assert_eq!(
                        validate_mode(focused, count, mixed).is_ok(),
                        focused && count == 1 && !mixed
                    );
                }
            }
        }
    }
}
