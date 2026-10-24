//! Closed source custody, admission and independent-guard contracts for the
//! original capped 204/205 prefixes. No asserted JSON can construct a native
//! barrier. Production callers must authenticate every sealed input first.
use crate::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    capped_prefix204205::{self as capped, InputPolicy, MetadataInputs},
    segment_manifest::HistoricalSegmentManifest,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub original_launch: Bound,
    pub producer_result: Bound,
    pub terminal_properties: Bound,
    pub manager_journal: Bound,
    pub prefix_manifest: Bound,
    pub prefix_validation: Bound,
}

/// Future artifact digests are supplied only after actual natural completion
/// and capture. This type is an input description, never successful proof.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub epoch: u64,
    pub producer_unit: String,
    pub guard_unit: String,
    pub node_sha256: String,
    pub guard_sha256: String,
    pub metadata: Metadata,
    pub source_capture: Bound,
    pub prefix_archive: Bound,
    pub prefix_bytes: u64,
    pub restart_snapshot: Bound,
    pub worker: Bound,
    pub genesis_archive: Bound,
    // Root publishes this immutable receipt after sealing the complete plan.
    // Its content binds the plan hash, avoiding a circular pair of digests.
    pub admission_receipt: PathBuf,
    pub run_root: PathBuf,
    pub guard_directory: PathBuf,
    pub protected_existing_floor_bytes: u64,
    pub candidate_incremental_peak_bytes: u64,
    pub maximum_root_physical_bytes: u64,
    pub maximum_process_rss_bytes: u64,
    pub maximum_worker_vmas: u64,
    pub maximum_stage_millis: u64,
}

/// Actual proposed systemd/cgroup controls, independently qualified by the
/// resource emitter and bound in a separate immutable resource proposal.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KernelLimits {
    pub requested_memory_max_bytes: u64,
    pub requested_memory_high_bytes: u64,
    pub memory_swap_max_bytes: u64,
    pub tasks_max: u64,
    pub cpu_quota_usec_per_second: u64,
    pub runtime_max_usec: u64,
}
impl KernelLimits {
    pub fn validate(&self, p: &Plan) -> Result<()> {
        ensure!(
            self.requested_memory_max_bytes >= p.maximum_process_rss_bytes
                && self.requested_memory_high_bytes > 0
                && self.requested_memory_high_bytes <= self.requested_memory_max_bytes
                && self.memory_swap_max_bytes == 0
                && (1..=512).contains(&self.tasks_max)
                && (1..=8_000_000).contains(&self.cpu_quota_usec_per_second)
                && self.runtime_max_usec > 0
                && p.maximum_stage_millis
                    .checked_mul(6_000)
                    .is_some_and(|n| self.runtime_max_usec <= n),
            "invalid independently qualified producer kernel limits"
        );
        Ok(())
    }
}

pub fn now_millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}

fn unit_name(name: &str, prefix: &str) -> bool {
    name.starts_with(prefix)
        && name.len() > prefix.len() + ".service".len()
        && name.len() <= 256
        && name.ends_with(".service")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub fn invocation(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
}

impl Plan {
    pub fn validate(&self, destination: &Path) -> Result<()> {
        let p = capped::profile(self.epoch)?;
        let leaf = self
            .run_root
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let prefix = format!("checkpoint-continuation-{}-", p.epoch);
        ensure!(
            self.schema == "jetstreamer-capped204205-continuation-plan-v1"
                && unit_name(
                    &self.producer_unit,
                    &format!("horizon-qualify-{}-capped-continuation-", p.epoch)
                )
                && unit_name(
                    &self.guard_unit,
                    &format!("horizon-guard-{}-capped-continuation-", p.epoch)
                )
                && self.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
                && leaf
                    .strip_prefix(&prefix)
                    .is_some_and(|s| !s.is_empty()
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                && destination == self.run_root.join("ledger")
                && self.guard_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && self
                    .guard_directory
                    .file_name()
                    .and_then(|s| s.to_str())
                    .and_then(|s| s.strip_prefix(&format!("horizon-capped-guard-{}-", p.epoch)))
                    .is_some_and(|s| !s.is_empty()
                        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
            "wrong closed continuation owner/output/guard scope"
        );
        ensure!(
            capped::parse_sha(&self.node_sha256)? != [0; 32]
                && capped::parse_sha(&self.guard_sha256)? != [0; 32]
                && self.metadata.original_launch.sha256 == p.launch_sha256
                && self.prefix_archive.path == p.prefix_path()
                && self.prefix_bytes > 0
                && self.restart_snapshot.path == Path::new(p.snapshot_path)
                && self.restart_snapshot.sha256 == p.snapshot_sha256
                && self.worker.sha256 == capped::WORKER_SHA256
                && self.genesis_archive.sha256 == capped::GENESIS_SHA256
                && self
                    .genesis_archive
                    .path
                    .file_name()
                    .is_some_and(|n| n == "genesis.tar.bz2"),
            "continuation changes original source, retained snapshot or worker/genesis identity"
        );
        for b in self.metadata.bounds().into_iter().chain([
            &self.source_capture,
            &self.prefix_archive,
            &self.restart_snapshot,
            &self.worker,
            &self.genesis_archive,
        ]) {
            ensure!(
                b.path.is_absolute()
                    && !b.path.starts_with(&self.run_root)
                    && !b.path.starts_with(&self.guard_directory)
                    && capped::parse_sha(&b.sha256)? != [0; 32],
                "overlapping/invalid bound input"
            );
        }
        ensure!(
            self.admission_receipt.is_absolute()
                && !self.admission_receipt.starts_with(&self.run_root)
                && !self.admission_receipt.starts_with(&self.guard_directory),
            "invalid admission output path"
        );
        // A minimum experiment envelope, not a claimed observed peak. Fresh
        // full-fleet admission may require more; never use native-only budgets.
        ensure!(
            self.protected_existing_floor_bytes > 0
                && self.candidate_incremental_peak_bytes >= (256 << 30)
                && self.maximum_root_physical_bytes
                    >= self
                        .prefix_bytes
                        .checked_add(32 << 30)
                        .context("assembly budget overflow")?
                && self.maximum_root_physical_bytes <= self.candidate_incremental_peak_bytes
                && self.maximum_process_rss_bytes > 0
                && self.maximum_worker_vmas > 0
                && (60_000..=172_800_000).contains(&self.maximum_stage_millis),
            "complete restore/suffix/assembly and process guard envelope required"
        );
        self.initial_free_bytes()?;
        Ok(())
    }

    pub fn initial_free_bytes(&self) -> Result<u64> {
        self.protected_existing_floor_bytes
            .checked_add(self.candidate_incremental_peak_bytes)
            .context("complete-path admission arithmetic overflow")
    }

    pub fn phase_path(&self) -> PathBuf {
        self.run_root.join("continuation-phase.json")
    }
    pub fn heartbeat_path(&self) -> PathBuf {
        self.guard_directory.join("heartbeat.json")
    }
}

impl Metadata {
    pub fn bounds(&self) -> [&Bound; 6] {
        [
            &self.original_launch,
            &self.producer_result,
            &self.terminal_properties,
            &self.manager_journal,
            &self.prefix_manifest,
            &self.prefix_validation,
        ]
    }
    pub fn authenticate(&self, epoch: u64) -> Result<(InputPolicy, HistoricalSegmentManifest)> {
        let [launch, result, props, journal, manifest, reader]: [Vec<u8>; 6] = self
            .bounds()
            .map(|b| sealed(b, 4 << 20))
            .into_iter()
            .collect::<Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("metadata arity"))?;
        let policy = capped::bind_metadata(
            epoch,
            MetadataInputs {
                launch: &launch,
                producer_result: &result,
                terminal_properties: &props,
                manager_journal: &journal,
                prefix_manifest: &manifest,
                prefix_validation: &reader,
            },
        )?;
        Ok((policy, serde_json::from_slice(&manifest)?))
    }
}

pub fn sealed(bound: &Bound, maximum: u64) -> Result<Vec<u8>> {
    let bytes = stable_read(&bound.path, maximum, 0, true)?;
    ensure!(
        capped::hex_sha(&bytes) == bound.sha256,
        "sealed input hash differs: {}",
        bound.path.display()
    );
    Ok(bytes)
}

fn uid1000_access(uid: u32, gid: u32, mode: u32, execute: bool) -> bool {
    let bit = if execute { 1 } else { 4 };
    let shift = if uid == 1000 {
        6
    } else if gid == 1000 {
        3
    } else {
        0
    };
    mode & (bit << shift) != 0
}
/// Conservative UID1000/primary-GID1000 DAC audit. Do not rely on root's
/// ability to traverse private ancestry or on supplemental groups/ACLs that
/// the separately qualified producer sandbox may not inherit.
pub fn require_uid1000_readable(path: &Path) -> Result<()> {
    require_uid1000_access(path, false)
}
pub fn require_uid1000_traversable(path: &Path) -> Result<()> {
    require_uid1000_access(path, true)
}
fn require_uid1000_access(path: &Path, directory: bool) -> Result<()> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical UID1000 input path"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        if directory { m.is_dir() } else { m.is_file() },
        "wrong UID1000 input type"
    );
    ensure!(
        uid1000_access(m.uid(), m.gid(), m.mode(), directory),
        "input not accessible to UID1000: {}",
        path.display()
    );
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && uid1000_access(m.uid(), m.gid(), m.mode(), true),
            "private ancestry blocks UID1000: {}",
            parent.display()
        );
    }
    Ok(())
}

/// Bounded no-follow read, with a complete before/open/after identity check.
/// Root heartbeat replacement is allowed between calls, never during a call.
pub fn stable_read(path: &Path, maximum: u64, uid: u32, readonly: bool) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let mut file = open_regular_nofollow(path)?;
    let identity = archive_file_identity(&file)?;
    let m = file.metadata()?;
    ensure!(
        m.uid() == uid
            && m.nlink() == 1
            && m.len() <= maximum
            && m.mode() & (if readonly { 0o222 } else { 0o077 }) == 0,
        "unsafe evidence ownership/mode/size"
    );
    let mut bytes = Vec::new();
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && archive_file_identity(&file)? == identity
            && path_matches_archive_identity(path, identity)?,
        "evidence changed during bounded read"
    );
    Ok(bytes)
}

/// Parent must already be canonical and owned by the expected UID. The caller
/// decides whether a mutable heartbeat/phase or immutable evidence is needed.
pub fn atomic_json(path: &Path, value: &impl Serialize, owner: u32, replace: bool) -> Result<()> {
    let parent = path.parent().context("evidence parent")?;
    let dir = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && dir.is_dir()
            && dir.uid() == owner
            && dir.mode() & 0o022 == 0,
        "unsafe evidence directory"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    serde_json::to_writer_pretty(file.as_file_mut(), value)?;
    file.as_file_mut().write_all(b"\n")?;
    file.as_file().sync_all()?;
    if replace {
        file.persist(path)
            .map_err(|e| anyhow::anyhow!("atomic replace: {e}"))?;
    } else {
        file.persist_noclobber(path)
            .map_err(|e| anyhow::anyhow!("immutable publication: {e}"))?;
    }
    let after = fs::symlink_metadata(parent)?;
    ensure!(
        dir.dev() == after.dev()
            && dir.ino() == after.ino()
            && dir.uid() == after.uid()
            && dir.mode() == after.mode()
            && parent.canonicalize()? == parent,
        "evidence parent changed"
    );
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    WaitingForGuard,
    PrefixValidation,
    NativeRestore,
    SuffixValidation,
    Assembly,
    Complete,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Phase {
    pub schema: String,
    pub epoch: u64,
    pub plan_sha256: String,
    pub invocation_id: String,
    pub stage: Stage,
    pub started_unix_millis: u64,
}

impl Phase {
    pub fn validate(&self, p: &Plan, plan_sha: &str, iid: &str, now: u64) -> Result<()> {
        ensure!(
            self.schema == "jetstreamer-capped204205-continuation-phase-v1"
                && self.epoch == p.epoch
                && self.plan_sha256 == plan_sha
                && self.invocation_id == iid
                && invocation(iid)
                && self.started_unix_millis <= now
                && now - self.started_unix_millis <= p.maximum_stage_millis,
            "wrong/stale continuation guard phase"
        );
        Ok(())
    }
    pub fn transition(&self, next: Stage, now: u64) -> Result<Self> {
        ensure!(
            next as u8 == self.stage as u8 + 1 && now >= self.started_unix_millis,
            "phase rewound or renewed"
        );
        Ok(Self {
            stage: next,
            started_unix_millis: now,
            ..self.clone()
        })
    }
}

pub fn validate_admission(p: &Plan, plan_sha: &str, v: &Value, now: u64) -> Result<()> {
    let limits: KernelLimits = serde_json::from_value(v["kernel_limits"].clone())?;
    limits.validate(p)?;
    let proposal: Bound = serde_json::from_value(v["resource_proposal"].clone())?;
    let original_fleet: Bound = serde_json::from_value(v["fleet_observation"].clone())?;
    let mirror: Bound = serde_json::from_value(v["fleet_observation_readable_mirror"].clone())?;
    ensure!(
        mirror.sha256 == original_fleet.sha256
            && mirror.path != original_fleet.path
            && mirror.path.is_absolute()
            && !mirror.path.starts_with(&p.run_root),
        "fleet mirror must preserve exact original bytes without replacing accepted lineage"
    );
    ensure!(
        proposal.path.is_absolute() && capped::parse_sha(&proposal.sha256)? != [0; 32],
        "actual complete-path resource proposal binding missing"
    );
    let sampled = v["recorded_unix_millis"]
        .as_u64()
        .context("admission timestamp")?;
    ensure!(
        v["schema"] == "jetstreamer-capped204205-continuation-admission-v1"
            && v["admitted"] == true
            && v["epoch"] == p.epoch
            && v["plan_sha256"] == plan_sha
            && v["node_sha256"] == p.node_sha256
            && v["source_capture_sha256"] == p.source_capture.sha256
            && v["prefix_sha256"] == p.prefix_archive.sha256
            && v["snapshot_sha256"] == p.restart_snapshot.sha256
            && v["worker_sha256"] == p.worker.sha256
            && v["producer_unit"] == p.producer_unit
            && v["guard_unit"] == p.guard_unit
            && v["guard_sha256"] == p.guard_sha256
            && v["protected_existing_floor_bytes"] == p.protected_existing_floor_bytes
            && v["candidate_incremental_peak_bytes"] == p.candidate_incremental_peak_bytes
            && v["maximum_root_physical_bytes"] == p.maximum_root_physical_bytes
            && v["maximum_process_rss_bytes"] == p.maximum_process_rss_bytes
            && v["maximum_worker_vmas"] == p.maximum_worker_vmas
            && v["available_bytes"]
                .as_u64()
                .is_some_and(|n| p.initial_free_bytes().is_ok_and(|floor| n >= floor))
            && v["complete_fleet_and_effective_guards_protected"] == true
            && v["restore_suffix_validation_and_assembly_overlap_included"] == true
            && v["fleet_observation"]["path"]
                .as_str()
                .is_some_and(|s| s.starts_with('/'))
            && v["fleet_observation"]["sha256"]
                .as_str()
                .is_some_and(|s| capped::parse_sha(s).is_ok_and(|d| d != [0; 32]))
            && sampled <= now
            && now - sampled <= 900_000,
        "requires a fresh complete-path, exact-package fleet admission"
    );
    for flag in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[flag] == false,
            "admission grants unrelated authority: {flag}"
        );
    }
    Ok(())
}

/// Does not assert historical success on its own. Capture tool first rederives
/// the InputPolicy, then records live idle census and freezes the actual file.
pub fn validate_capture(
    p: &Plan,
    v: &Value,
    manifest: &HistoricalSegmentManifest,
    now: u64,
) -> Result<()> {
    let profile = capped::profile(p.epoch)?;
    let sampled = v["recorded_unix_millis"]
        .as_u64()
        .context("capture timestamp")?;
    ensure!(
        v["schema"] == "jetstreamer-capped204205-source-capture-v1"
            && v["epoch"] == p.epoch
            && v["original_unit"] == profile.original_unit
            && v["original_invocation_id"] == profile.original_invocation
            && v["prefix_archive"] == serde_json::to_value(&p.prefix_archive)?
            && v["prefix_bytes"] == p.prefix_bytes
            && v["prefix_manifest_sha256"] == p.metadata.prefix_manifest.sha256
            && v["manifest_content_sha256"] == capped::hex_sha(&serde_json::to_vec(manifest)?)
            && v["frozen_root_owned_readonly"] == true
            && v["metadata_policy_rederived"] == true
            && manifest.archive_sha256 == capped::parse_sha(&p.prefix_archive.sha256)?
            && sampled <= now
            && now - sampled <= 900_000,
        "source capture does not bind this actual complete retained prefix"
    );
    for field in ["idle_before", "idle_after"] {
        let idle = &v[field];
        ensure!(
            idle["schema"] == "jetstreamer-capped204205-source-idle-v1"
                && idle["epoch"] == p.epoch
                && idle["unit"] == profile.original_unit
                && idle["historical_invocation_id"] == profile.original_invocation
                && idle["source_root"] == profile.original_root
                && idle["current_source_idle"] == true
                && idle["process_reference_census"]["references"]
                    .as_array()
                    .is_some_and(|a| a.is_empty()),
            "current complete original-root idle proof missing"
        );
    }
    ensure!(
        v["publication_authorized"] == false && v["r2_mutations"] == false,
        "capture grants publication"
    );
    Ok(())
}

pub fn guard_heartbeat(p: &Plan, plan_sha: &str, iid: &str, now: u64) -> Result<Value> {
    ensure!(
        matches!(fs::symlink_metadata(p.guard_directory.join("stop-intent.json")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "guard already tripped"
    );
    let bytes = stable_read(&p.heartbeat_path(), 1 << 20, 0, true)?;
    let v: Value = serde_json::from_slice(&bytes)?;
    validate_guard_heartbeat(p, plan_sha, iid, now, &v)?;
    Ok(v)
}

fn validate_guard_heartbeat(
    p: &Plan,
    plan_sha: &str,
    iid: &str,
    now: u64,
    v: &Value,
) -> Result<()> {
    let sampled = v["recorded_unix_millis"]
        .as_u64()
        .context("guard timestamp")?;
    ensure!(
        v["schema"] == "jetstreamer-capped204205-guard-heartbeat-v1"
            && v["epoch"] == p.epoch
            && v["plan_sha256"] == plan_sha
            && v["producer_invocation_id"] == iid
            && invocation(iid)
            && v["guard_invocation_id"].as_str().is_some_and(invocation)
            && v["guard_sha256"] == p.guard_sha256
            && v["guard_unit"] == p.guard_unit
            && v["producer_unit"] == p.producer_unit
            && v["trip"] == false
            && v["minimum_free_bytes"] == p.protected_existing_floor_bytes
            && v["maximum_root_physical_bytes"] == p.maximum_root_physical_bytes
            && v["maximum_process_rss_bytes"] == p.maximum_process_rss_bytes
            && v["maximum_worker_vmas"] == p.maximum_worker_vmas
            && v["producer_stop_enabled"] == true
            && sampled <= now
            && now - sampled <= 60_000
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "missing fresh actual invocation-bound protective guard heartbeat"
    );
    Ok(())
}

pub fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn denied_authority() -> Value {
    json!({"canonical_sidecar_authorized":false,"publication_authorized":false,
        "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_readability_does_not_substitute_for_the_actual_producer_permissions() {
        assert!(!uid1000_access(0, 0, 0o700, true));
        assert!(!uid1000_access(0, 0, 0o400, false));
        assert!(uid1000_access(0, 0, 0o444, false));
        assert!(uid1000_access(0, 0, 0o755, true));
        assert!(uid1000_access(1000, 1000, 0o700, true));
        assert!(uid1000_access(0, 1000, 0o750, true));
        assert!(!uid1000_access(1000, 1000, 0o040, false));
    }
    fn bound(name: &str) -> Bound {
        Bound {
            path: Path::new("/sealed").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn plan(epoch: u64) -> Plan {
        let s = capped::profile(epoch).unwrap();
        Plan {
            schema: "jetstreamer-capped204205-continuation-plan-v1".into(),
            epoch,
            producer_unit: format!("horizon-qualify-{epoch}-capped-continuation-fixture.service"),
            guard_unit: format!("horizon-guard-{epoch}-capped-continuation-fixture.service"),
            node_sha256: "1".repeat(64),
            guard_sha256: "2".repeat(64),
            metadata: Metadata {
                original_launch: Bound {
                    path: s.launch_path.into(),
                    sha256: s.launch_sha256.into(),
                },
                producer_result: bound("result"),
                terminal_properties: bound("properties"),
                manager_journal: bound("journal"),
                prefix_manifest: bound("manifest"),
                prefix_validation: bound("reader"),
            },
            source_capture: bound("capture"),
            prefix_archive: Bound {
                path: s.prefix_path(),
                sha256: "2a".repeat(32),
            },
            prefix_bytes: 100_000_000_000,
            restart_snapshot: Bound {
                path: s.snapshot_path.into(),
                sha256: s.snapshot_sha256.into(),
            },
            worker: Bound {
                path: "/sealed/historical-worker".into(),
                sha256: capped::WORKER_SHA256.into(),
            },
            genesis_archive: Bound {
                path: "/sealed/genesis.tar.bz2".into(),
                sha256: capped::GENESIS_SHA256.into(),
            },
            admission_receipt: "/sealed/admission.json".into(),
            run_root: format!(
                "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-{epoch}-fixture"
            )
            .into(),
            guard_directory: format!("/var/lib/jetstreamer/horizon-capped-guard-{epoch}-fixture")
                .into(),
            protected_existing_floor_bytes: 1_000_000_000_000,
            candidate_incremental_peak_bytes: 256 << 30,
            maximum_root_physical_bytes: 240 << 30,
            maximum_process_rss_bytes: 150 << 30,
            maximum_worker_vmas: 3_500_000,
            maximum_stage_millis: 86_400_000,
        }
    }
    fn admitted(p: &Plan) -> Value {
        json!({"schema":"jetstreamer-capped204205-continuation-admission-v1",
            "admitted":true,"epoch":p.epoch,"plan_sha256":"3".repeat(64),"node_sha256":p.node_sha256,
            "source_capture_sha256":p.source_capture.sha256,"prefix_sha256":p.prefix_archive.sha256,
            "snapshot_sha256":p.restart_snapshot.sha256,"worker_sha256":p.worker.sha256,
            "producer_unit":p.producer_unit,"guard_unit":p.guard_unit,"guard_sha256":p.guard_sha256,
            "protected_existing_floor_bytes":p.protected_existing_floor_bytes,
            "candidate_incremental_peak_bytes":p.candidate_incremental_peak_bytes,
            "maximum_root_physical_bytes":p.maximum_root_physical_bytes,
            "maximum_process_rss_bytes":p.maximum_process_rss_bytes,"maximum_worker_vmas":p.maximum_worker_vmas,
            "available_bytes":p.initial_free_bytes().unwrap(),"recorded_unix_millis":1_000_000,
            "complete_fleet_and_effective_guards_protected":true,
            "restore_suffix_validation_and_assembly_overlap_included":true,"fleet_observation":bound("fleet.json"),
            "ordinary_replay_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,
            "retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "resource_proposal":bound("resources.json"),"fleet_observation_readable_mirror":bound("fleet-mirror.json"),"kernel_limits":{
                "requested_memory_max_bytes":192u64<<30,"requested_memory_high_bytes":176u64<<30,
                "memory_swap_max_bytes":0,"tasks_max":512,"cpu_quota_usec_per_second":8_000_000,
                "runtime_max_usec":86_400_000_000u64}})
    }
    #[test]
    fn plans_pin_both_scopes_and_complete_path_budgets() {
        for epoch in [204, 205] {
            let p = plan(epoch);
            p.validate(&p.run_root.join("ledger")).unwrap();
            let mut copied_launch = p.clone();
            copied_launch.metadata.original_launch.path =
                "/sealed-readable/original-launch.json".into();
            copied_launch
                .validate(&copied_launch.run_root.join("ledger"))
                .unwrap();
            assert!(p.validate(&p.run_root.join("public")).is_err());
            let original = serde_json::to_value(&p).unwrap();
            for (pointer, value) in [
                ("/epoch", json!(203)),
                ("/producer_unit", json!("horizon-qualify-213-other.service")),
                ("/prefix_archive/path", json!("/other/epoch.jet")),
                ("/restart_snapshot/sha256", json!("b".repeat(64))),
                ("/worker/sha256", json!("b".repeat(64))),
                ("/metadata/original_launch/sha256", json!("b".repeat(64))),
                ("/candidate_incremental_peak_bytes", json!(192u64 << 30)),
                ("/maximum_root_physical_bytes", json!(1)),
                ("/maximum_stage_millis", json!(0)),
                ("/protected_existing_floor_bytes", json!(u64::MAX)),
                ("/guard_directory", json!("/tmp/guard")),
                (
                    "/admission_receipt",
                    json!(p.run_root.join("admission.json")),
                ),
            ] {
                let mut changed = original.clone();
                *changed.pointer_mut(pointer).unwrap() = value;
                let changed: Plan = serde_json::from_value(changed).unwrap();
                assert!(
                    changed.validate(&changed.run_root.join("ledger")).is_err(),
                    "{epoch}: {pointer}"
                );
            }
        }
    }
    #[test]
    fn guard_receipts_require_the_real_same_package_live_owner_and_fresh_protection() {
        let p = plan(204);
        let good = json!({"schema":"jetstreamer-capped204205-guard-heartbeat-v1","epoch":204,
            "plan_sha256":"3".repeat(64),"producer_invocation_id":"b".repeat(32),
            "guard_invocation_id":"c".repeat(32),"recorded_unix_millis":100_000,
            "guard_sha256":p.guard_sha256,"guard_unit":p.guard_unit,"producer_unit":p.producer_unit,
            "trip":false,"minimum_free_bytes":p.protected_existing_floor_bytes,
            "maximum_root_physical_bytes":p.maximum_root_physical_bytes,
            "maximum_process_rss_bytes":p.maximum_process_rss_bytes,"maximum_worker_vmas":p.maximum_worker_vmas,
            "producer_stop_enabled":true,"remote_mutations":false,"r2_mutations":false});
        validate_guard_heartbeat(&p, &"3".repeat(64), &"b".repeat(32), 100_000, &good).unwrap();
        assert!(
            validate_guard_heartbeat(&p, &"3".repeat(64), &"b".repeat(32), 160_001, &good).is_err()
        );
        for (key, value) in [
            ("trip", json!(true)),
            ("producer_stop_enabled", json!(false)),
            ("guard_invocation_id", json!("0".repeat(32))),
            ("producer_invocation_id", json!("d".repeat(32))),
            ("guard_sha256", json!("4".repeat(64))),
            ("minimum_free_bytes", json!(1)),
            ("recorded_unix_millis", json!(100_001)),
            ("maximum_worker_vmas", json!(1)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(
                validate_guard_heartbeat(&p, &"3".repeat(64), &"b".repeat(32), 100_000, &bad)
                    .is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn admission_is_fresh_exact_and_cannot_grant_publication_or_skip_full_fleet_protection() {
        for epoch in [204, 205] {
            let p = plan(epoch);
            let good = admitted(&p);
            validate_admission(&p, &"3".repeat(64), &good, 1_000_000).unwrap();
            assert!(validate_admission(&p, &"3".repeat(64), &good, 1_900_001).is_err());
            for (key, value) in [
                ("plan_sha256", json!("4".repeat(64))),
                ("prefix_sha256", json!("4".repeat(64))),
                ("source_capture_sha256", json!("4".repeat(64))),
                (
                    "available_bytes",
                    json!(p.initial_free_bytes().unwrap() - 1),
                ),
                ("maximum_worker_vmas", json!(3)),
                ("maximum_process_rss_bytes", json!(1)),
                ("recorded_unix_millis", json!(1_000_001)),
                (
                    "complete_fleet_and_effective_guards_protected",
                    json!(false),
                ),
                (
                    "restore_suffix_validation_and_assembly_overlap_included",
                    json!(false),
                ),
                ("publication_authorized", json!(true)),
                ("r2_mutations", json!(true)),
            ] {
                let mut bad = good.clone();
                bad[key] = value;
                assert!(
                    validate_admission(&p, &"3".repeat(64), &bad, 1_000_000).is_err(),
                    "{key}"
                );
            }
        }
    }
    #[test]
    fn phases_keep_an_absolute_deadline_and_exact_actual_owner() {
        let p = plan(204);
        let first = Phase {
            schema: "jetstreamer-capped204205-continuation-phase-v1".into(),
            epoch: 204,
            plan_sha256: "3".repeat(64),
            invocation_id: "b".repeat(32),
            stage: Stage::WaitingForGuard,
            started_unix_millis: 100,
        };
        first
            .validate(&p, &"3".repeat(64), &"b".repeat(32), 100)
            .unwrap();
        assert!(
            first
                .validate(&p, &"3".repeat(64), &"c".repeat(32), 100)
                .is_err()
        );
        assert!(
            first
                .validate(&p, &"3".repeat(64), &"b".repeat(32), 99)
                .is_err()
        );
        assert!(
            first
                .validate(
                    &p,
                    &"3".repeat(64),
                    &"b".repeat(32),
                    100 + p.maximum_stage_millis + 1
                )
                .is_err()
        );
        assert!(first.transition(Stage::WaitingForGuard, 101).is_err());
        assert!(first.transition(Stage::NativeRestore, 101).is_err());
        assert!(first.transition(Stage::NativeRestore, 99).is_err());
        let next = first.transition(Stage::PrefixValidation, 101).unwrap();
        assert!(next.transition(Stage::WaitingForGuard, 102).is_err());
        assert!(!invocation(&"0".repeat(32)));
        assert!(!invocation(&"A".repeat(32)));
    }
    #[test]
    fn source_capture_binds_actual_frozen_prefix_and_two_complete_idle_censuses() {
        for epoch in [204, 205] {
            let p = plan(epoch);
            let s = capped::profile(epoch).unwrap();
            let mut manifest: HistoricalSegmentManifest = serde_json::from_slice(include_bytes!(
                "../tests/fixtures/epoch203-capped-shrink-root.manifest.json"
            ))
            .unwrap();
            manifest.epoch = epoch;
            manifest.output_slot_start = s.start;
            manifest.output_slot_count = s.restart - s.start + 1;
            manifest.archive_sha256 = capped::parse_sha(&p.prefix_archive.sha256).unwrap();
            manifest.bootstrap.slot = s.bootstrap;
            manifest.bootstrap.accounts_hash = s.bootstrap_accounts.into();
            manifest.bootstrap.tick_height = s.bootstrap * 64;
            manifest.terminal.slot = s.restart;
            manifest.terminal.accounts_hash = s.restart_accounts.into();
            manifest.terminal.tick_height = s.restart * 64;
            let idle = json!({"schema":"jetstreamer-capped204205-source-idle-v1","epoch":epoch,
                "unit":s.original_unit,"historical_invocation_id":s.original_invocation,"source_root":s.original_root,
                "current_source_idle":true,"process_reference_census":{"references":[]}});
            let good = json!({"schema":"jetstreamer-capped204205-source-capture-v1","epoch":epoch,
                "recorded_unix_millis":1_000_000,"original_unit":s.original_unit,"original_invocation_id":s.original_invocation,
                "prefix_archive":p.prefix_archive,"prefix_bytes":p.prefix_bytes,
                "prefix_manifest_sha256":p.metadata.prefix_manifest.sha256,
                "manifest_content_sha256":capped::hex_sha(&serde_json::to_vec(&manifest).unwrap()),
                "frozen_root_owned_readonly":true,"metadata_policy_rederived":true,
                "idle_before":idle,"idle_after":idle,"publication_authorized":false,"r2_mutations":false});
            validate_capture(&p, &good, &manifest, 1_000_000).unwrap();
            for (pointer, value) in [
                ("/epoch", json!(203)),
                ("/prefix_bytes", json!(1)),
                ("/frozen_root_owned_readonly", json!(false)),
                ("/metadata_policy_rederived", json!(false)),
                ("/idle_before/current_source_idle", json!(false)),
                ("/idle_after/source_root", json!("/other")),
                (
                    "/idle_after/process_reference_census/references",
                    json!(["live writer"]),
                ),
                ("/manifest_content_sha256", json!("4".repeat(64))),
            ] {
                let mut bad = good.clone();
                *bad.pointer_mut(pointer).unwrap() = value;
                assert!(
                    validate_capture(&p, &bad, &manifest, 1_000_000).is_err(),
                    "{pointer}"
                );
            }
            assert!(validate_capture(&p, &good, &manifest, 1_900_001).is_err());
        }
    }
    #[test]
    fn immutable_publication_is_no_clobber_and_bounded_reads_reject_links_and_writable_data() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let owner = unsafe { libc::geteuid() };
        let root = dir.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("receipt.json");
        atomic_json(&path, &json!({"counter":u64::MAX}), owner, false).unwrap();
        let bytes = stable_read(&path, 1024, owner, true).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["counter"],
            u64::MAX
        );
        assert!(atomic_json(&path, &json!({"counter":0}), owner, false).is_err());
        assert!(stable_read(&path, 1, owner, true).is_err());
        let alias = root.join("alias");
        symlink(&path, &alias).unwrap();
        assert!(stable_read(&alias, 1024, owner, true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(stable_read(&path, 1024, owner, true).is_err());
    }
}
