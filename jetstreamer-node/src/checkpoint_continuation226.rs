//! Exact private epoch 226 repair, split into independently admitted durable stages.
//! Scoped extraction may read the pinned custody object through its admitted broker.
//! The repair produces only private replay and assembly evidence.
#[path = "checkpoint226_r2.rs"]
pub(super) mod held_r2;

use super::checkpoint_continuation::{
    Evidence, RestartProof, authenticate_service, available_bytes, checkpoint_matches,
    create_private_dir, require, require_no_checksum, require_retained_input, runtime_checkpoint,
    sealed_bytes, sha, write_new,
};
use super::epoch226_interior::{InteriorSelection, reencode_archive_interior};
use super::*;
use jetstreamer_horizon::archive::{
    ArchiveProvenanceV3, ArchiveProvenanceV4, ArchiveReader, RuntimeSegmentSource,
    merge_runtime_segments,
};
use jetstreamer_node::{
    archive_checksum::{
        archive_file_identity, open_regular_nofollow, path_matches_archive_identity,
    },
    segment_manifest::{
        SegmentManifestError, read_and_validate_seekable_segment_manifest,
        read_and_validate_segment_manifest_from,
    },
};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom},
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

const EPOCH: u64 = 226;
const START: u64 = 97_632_000;
const ROOT: u64 = 98_063_464;
const END: u64 = 98_063_999;
const ORIGINAL_START: u64 = 97_200_000;
const ORIGINAL_COUNT: u64 = 863_465;
const ORIGINAL_SIZE: u64 = 265_610_094_371;
const ORIGINAL_SHA: &str = "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9";
const ORIGINAL_MANIFEST_SHA: &str =
    "53a69d801e70866b0bc048e1b3a75d9c16c1fb93995503157fc206742f3cdcf6";
const ORIGINAL_WORKER: &str = "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd";
const WORKER: &str = "7a831420bb1498ddb0268309ce69f615c7f0c6d90cfab940896a03dc38b5336a";
const SNAPSHOT: &str = "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07";
const SNAPSHOT_SIZE: u64 = 10_261_480_487;
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const NATIVE_REVIEW: &str = "6c96fffd1725c39c61236f25263efbb4055647e58f014ad41f2497e67e4cbd00";
const RESTORE_PROOF: &str = "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b";
const VERIFIED225: &str = "809deec8ff64f53107e7eac16c120e19bfbc16d63db06c435205ec3e0f11c156";
const ORIGINAL_PATH: &str = "/home/ubuntu/.jetstreamer-private/qualification-225-v1625-natural-root-shrink-budget-2f856bd-v1/output/epoch-225.jet";
const PRIVATE_ROOT: &str = "/home/ubuntu/.jetstreamer-private";
const ASSEMBLY_PROFILE: &str = "jetstreamer-private/epoch226-explicit-2dcc-to-7a-handoff-v1";

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Stage {
    Extract {
        original_archive: Evidence,
        original_manifest: Evidence,
        native_review: Evidence,
        restore_proof: Evidence,
        verified225: Evidence,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        held_broker: Option<Evidence>,
    },
    Replay {
        prefix_archive: Evidence,
        prefix_manifest: Evidence,
        extraction: Evidence,
        snapshot: Evidence,
        worker: Evidence,
        genesis: Evidence,
    },
    Assemble {
        prefix_archive: Evidence,
        prefix_manifest: Evidence,
        extraction: Evidence,
        suffix_archive: Evidence,
        suffix_manifest: Evidence,
        replay: Evidence,
    },
}
impl Stage {
    fn name(&self) -> &'static str {
        match self {
            Self::Extract { .. } => "extract",
            Self::Replay { .. } => "replay",
            Self::Assemble { .. } => "assemble",
        }
    }
    fn evidence(&self) -> Vec<&Evidence> {
        match self {
            Self::Extract {
                original_archive,
                original_manifest,
                native_review,
                restore_proof,
                verified225,
                held_broker,
            } => [
                original_archive,
                original_manifest,
                native_review,
                restore_proof,
                verified225,
            ]
            .into_iter()
            .chain(held_broker.iter())
            .collect(),
            Self::Replay {
                prefix_archive,
                prefix_manifest,
                extraction,
                snapshot,
                worker,
                genesis,
            } => vec![
                prefix_archive,
                prefix_manifest,
                extraction,
                snapshot,
                worker,
                genesis,
            ],
            Self::Assemble {
                prefix_archive,
                prefix_manifest,
                extraction,
                suffix_archive,
                suffix_manifest,
                replay,
            } => vec![
                prefix_archive,
                prefix_manifest,
                extraction,
                suffix_archive,
                suffix_manifest,
                replay,
            ],
        }
    }
}
#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    producer_unit: String,
    node_sha256: String,
    admission: Evidence,
    run_root: PathBuf,
    minimum_free_bytes: u64,
    stage: Stage,
}

/// Check private feature scope before the shared CLI dispatches any other
/// top-level operation, including failed-prefix recovery and network probes.
pub(crate) fn validate_entrypoint(args: &[String]) -> Result<(), String> {
    let Some((epoch, rest)) = args.split_first() else {
        return Ok(());
    };
    if matches!(epoch.as_str(), "-h" | "--help") && rest.is_empty() {
        return Ok(());
    }
    require(
        parse_epoch_range(epoch)? == (EPOCH, EPOCH)
            && rest.iter().all(|arg| {
                !arg.starts_with('-')
                    || arg == "--verify"
                    || arg.starts_with("--checkpoint-continuation-plan=")
                    || arg.starts_with("--checkpoint-continuation-plan-sha256=")
            }),
        "private 226 build accepts only its scoped continuation operation",
    )
}
pub(crate) fn validate_cli(
    epochs: (u64, u64),
    verify: Option<bool>,
    count: usize,
    destination: bool,
    forbidden: bool,
) -> Result<(), String> {
    require(
        cfg!(feature = "epoch226-checkpoint-continuation-diagnostic")
            && epochs == (EPOCH, EPOCH)
            && verify == Some(true)
            && count == 1
            && destination
            && !forbidden,
        "private 226 repair requires its exclusive build, only 226, one --verify and explicit private destination",
    )
}
fn value(e: &Evidence) -> Result<Value, String> {
    serde_json::from_slice(&sealed_bytes(e, 4 << 20)?).map_err(|e| e.to_string())
}
fn bind(e: &Evidence, expected: &str) -> Result<(), String> {
    require(e.sha256 == expected, "226 retained evidence digest differs")
}
fn hash_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = open_regular_nofollow(path).map_err(|e| e.to_string())?;
    let before = archive_file_identity(&file).map_err(|e| e.to_string())?;
    let digest = hash_handle(&mut file)?;
    require(
        archive_file_identity(&file).map_err(|e| e.to_string())? == before
            && path_matches_archive_identity(path, before).map_err(|e| e.to_string())?,
        "226 source changed while hashing",
    )?;
    Ok(digest)
}
fn hash_handle(file: &mut File) -> Result<[u8; 32], String> {
    let before = archive_file_identity(file).map_err(|e| e.to_string())?;
    let digest = hash_seekable(file)?;
    require(
        archive_file_identity(file).map_err(|e| e.to_string())? == before,
        "226 opened source changed while hashing",
    )?;
    Ok(digest)
}
fn hash_seekable(file: &mut (impl Read + Seek + ?Sized)) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(digest.finalize().into())
}
fn write_json(path: &Path, v: &impl serde::Serialize) -> Result<(), String> {
    let mut bytes = serde_json::to_vec_pretty(v).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}
fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(|e| e.to_string())
}
fn stage_digest(s: &Stage) -> Result<String, String> {
    Ok(hex_digest(&Sha256::digest(
        serde_json::to_vec(s).map_err(|e| e.to_string())?,
    )))
}
fn hex_digest(bytes: &[u8]) -> String {
    let digest: &[u8; 32] = bytes.try_into().expect("SHA-256 length");
    jetstreamer_node::segment_manifest::sha256_hex_string(digest)
}
fn admission(p: &Plan, a: &Value) -> Result<(), String> {
    let floor = a["protected_existing_floor_bytes"]
        .as_u64()
        .ok_or("226 protected floor missing")?;
    let peak = a["candidate_incremental_peak_bytes"]
        .as_u64()
        .ok_or("226 incremental peak missing")?;
    require(
        a["schema"] == "jetstreamer-epoch226-scoped-repair-admission-v1"
            && a["admitted"] == true
            && a["epoch"] == EPOCH
            && a["operation"] == p.stage.name()
            && a["node_sha256"] == p.node_sha256
            && a["stage_sha256"] == stage_digest(&p.stage)?
            && a["producer_unit"] == p.producer_unit
            && a["run_root"] == p.run_root.to_string_lossy().as_ref()
            && floor > 0
            && peak > 0
            && floor.checked_add(peak) == Some(p.minimum_free_bytes)
            && a["complete_fleet_and_century_floor_bound"] == true
            && a["actual_guard_and_owner_qualified"] == true
            && a["exact_stage_scope_qualified"] == true
            && a["original_native_source_evidence_accepted"] == true
            && a["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| now().is_ok_and(|n| t <= n && n - t <= 900)),
        "226 requires a fresh exact-stage full-path admission and guard; native-only admission is insufficient",
    )?;
    if matches!(&p.stage, Stage::Replay { .. }) {
        require(
            a["exact_worker_artifact_and_feature_scope_qualified"] == true,
            "226 suffix requires authenticated actual 7a worker build/features, not only its native restore proof",
        )?;
    }
    if matches!(
        &p.stage,
        Stage::Extract {
            held_broker: Some(_),
            ..
        }
    ) {
        require(
            a["authenticated_held_source_qualified"] == true,
            "226 remote extraction requires its scoped authenticated broker admission",
        )?;
    }
    for flag in [
        "ordinary_replay_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        require(a[flag] == false, "226 admission grants unrelated authority")?;
    }
    require(
        available_bytes(&p.run_root)? >= p.minimum_free_bytes,
        "226 admitted free-space envelope unavailable",
    )
}
fn expected_root() -> SegmentCheckpointSummary {
    SegmentCheckpointSummary {
        slot: ROOT,
        bank_hash: "2qWtzMF3aJBSujYSm3U1jXfkvRMFsYd9JSj3FVT2cQmN".into(),
        accounts_hash: "4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR".into(),
        last_blockhash: "6AbTZxGyURin7ToVWXxFQsifVhrBhAvgiZXgK7eoL5Yq".into(),
        capitalization: 504_710_780_192_825_835,
        transaction_count: 29_520_872_731,
        tick_height: 6_276_061_760,
        slot_complete: true,
        write_count: 1054,
        next_write_version: 111_241_712_667,
    }
}
fn prefix_scope(m: &HistoricalSegmentManifest) -> Result<(), String> {
    m.validate().map_err(|e| e.to_string())?;
    require(
        m.epoch == EPOCH
            && m.output_slot_start == START
            && m.output_slot_count == ROOT - START + 1
            && m.worker_executable_sha256 == sha(ORIGINAL_WORKER)?
            && m.runtime.runtime_profile == "solana-v1.6.25"
            && m.runtime.runtime_revision == compatibility::SOLANA_V1_6_25_REVISION
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
            && m.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH
            && m.bootstrap.slot == 97_199_617
            && m.bootstrap_archive_sha256.is_none()
            && m.terminal == expected_root(),
        "226 selected prefix scope/native identity differs",
    )
}
fn extraction(e: &Evidence, prefix: &Evidence, manifest: &Evidence) -> Result<(), String> {
    let v = value(e)?;
    require(
        v["schema"] == "jetstreamer-private-epoch226-interior-extraction-v1"
            && v["original_archive_sha256"] == ORIGINAL_SHA
            && v["source_must_be_retained"] == true
            && v["original_manifest_sha256"] == ORIGINAL_MANIFEST_SHA
            && v["prefix_archive_sha256"] == prefix.sha256
            && v["prefix_manifest_sha256"] == manifest.sha256
            && v["independent_output_reread_passed"] == true
            && v["epoch"] == EPOCH
            && v["selected_slots"] == ROOT - START + 1
            && v["missing_suffix_slots"] == END - ROOT
            && v["publication_authorized"] == false
            && v["canonical_sidecar_authorized"] == false,
        "226 extraction receipt does not bind the actual private selected prefix",
    )
}
fn read_prefix(
    archive: &Evidence,
    manifest: &Evidence,
    receipt: &Evidence,
) -> Result<HistoricalSegmentManifest, String> {
    extraction(receipt, archive, manifest)?;
    sealed_bytes(manifest, 1 << 20)?;
    require_no_checksum(&archive.path)?;
    let m = read_and_validate_segment_manifest_from(&archive.path, &manifest.path)
        .map_err(|e| e.to_string())?;
    prefix_scope(&m)?;
    require(
        m.archive_sha256 == sha(&archive.sha256)?,
        "226 prefix archive differs",
    )?;
    Ok(m)
}

trait SeekableArchive: Read + Seek {}
impl<T: Read + Seek> SeekableArchive for T {}

fn extract(p: &Plan) -> Result<Value, String> {
    let Stage::Extract {
        original_archive,
        original_manifest,
        native_review,
        restore_proof,
        verified225,
        held_broker,
    } = &p.stage
    else {
        return Err("226 extraction stage missing".into());
    };
    for (e, d) in [
        (original_archive, ORIGINAL_SHA),
        (original_manifest, ORIGINAL_MANIFEST_SHA),
        (native_review, NATIVE_REVIEW),
        (restore_proof, RESTORE_PROOF),
        (verified225, VERIFIED225),
    ] {
        bind(e, d)?;
    }
    require(
        original_archive.path == Path::new(ORIGINAL_PATH),
        "226 original source path differs",
    )?;
    sealed_bytes(original_manifest, 1 << 20)?;
    let _ = value(native_review)?;
    let _ = value(restore_proof)?;
    let verification = value(verified225)?;
    require(
        verification["epoch"] == 225
            && verification["independent_final_archive_verification_passed"] == true
            && verification["current_plugin_verification_passed"] == true
            && verification["original_source"] == ORIGINAL_PATH
            && verification["source_must_be_retained"] == true,
        "226 initial boundary requires the exact accepted 225 verification",
    )?;
    let held = held_broker
        .as_ref()
        .map(|plan| -> Result<_, String> {
            let description: held_r2::HeldObject =
                serde_json::from_slice(&sealed_bytes(plan, 1 << 20)?).map_err(|e| e.to_string())?;
            description
                .accept(ORIGINAL_SIZE, ORIGINAL_SHA)
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    info!(
        "private 226 extraction: independent whole combined-source digest and deep validation starting"
    );
    let original = if let Some(object) = &held {
        let on_transport_error = |e: std::io::Error| SegmentManifestError::Invalid(e.to_string());
        read_and_validate_seekable_segment_manifest(
            &original_archive.path,
            &original_manifest.path,
            NonZeroUsize::new(4).unwrap(),
            || object.open().map_err(on_transport_error),
            || object.recheck().map_err(on_transport_error),
        )
    } else {
        require_retained_input(&original_archive.path, ORIGINAL_SIZE)?;
        read_and_validate_segment_manifest_from(&original_archive.path, &original_manifest.path)
    }
    .map_err(|e| e.to_string())?;
    require(
        original.epoch == 225
            && original.output_slot_start == ORIGINAL_START
            && original.output_slot_count == ORIGINAL_COUNT
            && original.archive_sha256 == sha(ORIGINAL_SHA)?
            && original.worker_executable_sha256 == sha(ORIGINAL_WORKER)?
            && original.terminal == expected_root(),
        "226 original combined source scope differs",
    )?;
    let (source, identity, digest): (Box<dyn SeekableArchive + '_>, _, _) =
        if let Some(object) = &held {
            let mut reader = object.open().map_err(|e| e.to_string())?;
            let digest = hash_seekable(&mut reader)?;
            (Box::new(reader), None, digest)
        } else {
            let mut reader =
                open_regular_nofollow(&original_archive.path).map_err(|e| e.to_string())?;
            let identity = archive_file_identity(&reader).map_err(|e| e.to_string())?;
            let digest = hash_handle(&mut reader)?;
            (Box::new(reader), Some(identity), digest)
        };
    require(
        digest == sha(ORIGINAL_SHA)?,
        "226 actual extraction handle differs from the authenticated whole source",
    )?;
    let recheck_source = || match (&held, identity) {
        (Some(object), None) => object.recheck().map_err(|e| e.to_string()),
        (None, Some(identity)) => require(
            path_matches_archive_identity(&original_archive.path, identity)
                .map_err(|e| e.to_string())?,
            "226 original source changed during extraction",
        ),
        _ => Err("226 original source identity is unavailable".into()),
    };
    let prefix = p.run_root.join("output/epoch-226-prefix.jet");
    let sink = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&prefix)
        .map_err(|e| e.to_string())?;
    let selection = InteriorSelection {
        epoch: EPOCH,
        start: START,
        count: ROOT - START + 1,
        first_parent_slot: START - 1,
        first_parent_blockhash: "FCuybZCvPTeZyEtxdLJZKYEUp9wYmrJRujEV8du8YtVB"
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        terminal_last_blockhash: expected_root()
            .last_blockhash
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
    };
    info!(
        "private 226 extraction: validating and copying 431465 interior slots; original source stays retained"
    );
    let (sink, stats) = reencode_archive_interior(
        BufReader::new(source),
        sink,
        ArchiveWriterConfig::default(),
        selection,
    )
    .map_err(|e| e.to_string())?;
    sink.sync_all().map_err(|e| e.to_string())?;
    drop(sink);
    recheck_source()?;
    let mut selected = original;
    selected.epoch = EPOCH;
    selected.output_slot_start = START;
    selected.output_slot_count = ROOT - START + 1;
    selected.archive_sha256 = hash_file(&prefix)?;
    selected.emitted_raw_write_versions = stats
        .emitted_raw_write_versions
        .clone()
        .ok_or("226 selected prefix unexpectedly emitted no writes")?;
    prefix_scope(&selected)?;
    let manifest = prefix.with_extension("jet.segment.json");
    write_json(&manifest, &selected)?;
    let reread =
        read_and_validate_segment_manifest_from(&prefix, &manifest).map_err(|e| e.to_string())?;
    require(reread == selected, "226 independent prefix reread differs")?;
    // The full manifest reread checks range/provenance/raw versions. Compare the
    // independently decoded output semantic digest as a separate preservation gate.
    let mut reader = ArchiveReader::open(BufReader::new(
        open_regular_nofollow(&prefix).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let mut digest = jetstreamer_horizon::archive::SemanticDigest::new();
    require(
        reader
            .read_slots(START, ROOT - START + 1, &mut digest)
            .map_err(|e| e.to_string())?
            == ROOT - START + 1
            && digest.finish().map_err(|e| e.to_string())? == stats.output_semantic_sha256,
        "226 independent output semantic reread differs",
    )?;
    recheck_source()?;
    let mut receipt = json!({"schema":"jetstreamer-private-epoch226-interior-extraction-v1","epoch":EPOCH,
        "original_archive_sha256":ORIGINAL_SHA,"original_manifest_sha256":ORIGINAL_MANIFEST_SHA,
        "source_must_be_retained":true,"prefix_archive":prefix,"prefix_archive_sha256":hex_digest(&selected.archive_sha256),
        "prefix_manifest":manifest,"prefix_manifest_sha256":hex_digest(&hash_file(&manifest)?),
        "selected_slots":ROOT-START+1,"missing_suffix_slots":END-ROOT,
        "selected_source_semantic_sha256":hex_digest(&stats.selected_source_semantic_sha256),
        "output_semantic_sha256":hex_digest(&stats.output_semantic_sha256),
        "independent_output_reread_passed":true,"canonical_sidecar_authorized":false,"publication_authorized":false});
    if let Some(plan) = held_broker {
        receipt["authenticated_held_broker"] = json!(plan);
    }
    Ok(receipt)
}

struct ValidatedPrefix {
    manifest: HistoricalSegmentManifest,
    snapshot: PathBuf,
    barrier_passed: AtomicBool,
}
impl RestartProof for ValidatedPrefix {
    fn snapshot_sha256(&self) -> [u8; 32] {
        sha(SNAPSHOT).unwrap()
    }
    fn snapshot_size(&self) -> u64 {
        SNAPSHOT_SIZE
    }
    fn covers_trusted_root(&self, e: u64, b: u64, s: u64, n: u64) -> bool {
        e == EPOCH && b == ROOT && s == ROOT + 1 && n == END && prefix_scope(&self.manifest).is_ok()
    }
    fn validate_invocation(
        &self,
        e: u64,
        b: &ReplayBootstrap,
        q: Option<QualificationPlan>,
        c: bool,
        a: bool,
        r: bool,
    ) -> Result<(), String> {
        require(
            cfg!(feature = "epoch226-checkpoint-continuation-diagnostic")
                && !c
                && !a
                && !r
                && b.snapshot_archive() == Some(self.snapshot.as_path())
                && q.is_some_and(|q| {
                    q.epoch == EPOCH
                        && q.replay_start == ROOT + 1
                        && self.covers_trusted_root(
                            e,
                            q.bootstrap_slot,
                            q.output_slot_start,
                            q.end_inclusive,
                        )
                }),
            "226 restart proof cannot authorize 227 warmup suppression or another span",
        )
    }
    fn verify_native_checkpoint(
        &self,
        a: &historical::HistoricalCheckpoint,
        w: [u8; 32],
        cursor: u64,
        ticks: u64,
    ) -> Result<(), String> {
        let actual = segment_checkpoint_summary(
            &historical_replay::HistoricalCheckpointSummary::try_from(a)?,
        );
        require(
            w == sha(WORKER)?
                && ticks == 64
                && actual.write_count == 0
                && actual.next_write_version == cursor,
            "226 actual suffix worker/cursor/ticks/bootstrap writes differ",
        )?;
        checkpoint_matches(&self.manifest.terminal, &actual)?;
        require(
            !self.barrier_passed.swap(true, Ordering::SeqCst),
            "226 native barrier repeated",
        )?;
        info!(
            "private 226 actual native restart barrier passed; recording all 535 slots with this worker's cursor"
        );
        Ok(())
    }
}
async fn replay(
    p: &Plan,
    shutdown: Arc<AtomicBool>,
    cursor: Arc<ReplayCursor>,
    tracker: Arc<RestartTracker>,
) -> Result<Value, String> {
    let Stage::Replay {
        prefix_archive,
        prefix_manifest,
        extraction,
        snapshot,
        worker,
        genesis,
    } = &p.stage
    else {
        return Err("226 replay stage missing".into());
    };
    bind(snapshot, SNAPSHOT)?;
    bind(worker, WORKER)?;
    bind(genesis, GENESIS)?;
    require(
        snapshot.path.file_name().and_then(|v| v.to_str())
            == Some("snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst"),
        "226 restart snapshot name differs",
    )?;
    info!(
        "private 226 replay stage: independent selected-prefix reread starting before any worker spawn"
    );
    let manifest = read_prefix(prefix_archive, prefix_manifest, extraction)?;
    require_retained_input(&snapshot.path, SNAPSHOT_SIZE)?;
    sealed_bytes(worker, 256 << 20)?;
    let genesis_bytes = sealed_bytes(genesis, 10 << 20)?;
    // The fresh stage admission includes this prefix reread and native restore.
    // Keep its already armed guard/owner; do not impose a second 15-minute issue
    // deadline after a potentially hour-long source validation.
    authenticate_service(&p.producer_unit)?;
    require(
        available_bytes(&p.run_root)? >= p.minimum_free_bytes,
        "226 restore reserve changed during admitted prefix validation",
    )?;
    let candidate = env_truthy_default("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", false);
    let selection = select_runtime_for_invocation(ROOT + 1..END + 1, candidate, true)?;
    require(
        candidate
            && selection.descriptor.identity.name == "solana-v1.6.25"
            && selection.descriptor.identity.revision == compatibility::SOLANA_V1_6_25_REVISION
            && selection.admission == compatibility::AdmissionLevel::Candidate
            && configured_historical_worker_executable(selection.descriptor)? == worker.path,
        "226 exact private runtime/worker selection differs",
    )?;
    let ledger = p.run_root.join("ledger");
    write_new(&ledger.join("genesis.tar.bz2"), &genesis_bytes)?;
    let proof = ValidatedPrefix {
        manifest,
        snapshot: snapshot.path.clone(),
        barrier_passed: AtomicBool::new(false),
    };
    let q = QualificationPlan {
        epoch: EPOCH,
        bootstrap_slot: ROOT,
        replay_start: ROOT + 1,
        output_slot_start: ROOT + 1,
        end_inclusive: END,
    };
    let verifier = Arc::new(SnapshotVerifier::new(
        BTreeMap::from([(
            ROOT,
            BankHashExpectation::LegacyAccountsHash(
                expected_root()
                    .accounts_hash
                    .parse::<Hash>()
                    .map_err(|e| e.to_string())?,
            ),
        )]),
        Some(shutdown.clone()),
    ));
    let output = p.run_root.join("output/epoch-226-suffix.jet");
    let result = run_geyser_replay(
        EPOCH,
        candidate,
        &ledger,
        &p.run_root.join("scratch"),
        &ReplayBootstrap::SnapshotArchive(proof.snapshot.clone()),
        shutdown.clone(),
        cursor,
        tracker,
        Some(verifier.clone()),
        output.clone(),
        Some(q),
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        Some(&proof),
        epoch223_qualification::TailMode::Disabled,
    )
    .await?
    .completed()?;
    require(
        !shutdown.load(Ordering::SeqCst) && proof.barrier_passed.load(Ordering::SeqCst),
        "226 suffix interrupted or actual native barrier absent",
    )?;
    verifier.finish()?;
    publish_historical_segment_manifest(EPOCH, q, &output, &result)?;
    let suffix = read_and_validate_segment_manifest(&output).map_err(|e| e.to_string())?;
    suffix_scope(&suffix)?;
    require_no_checksum(&output)?;
    Ok(
        json!({"schema":"jetstreamer-private-epoch226-suffix-v1","epoch":EPOCH,
        "prefix_archive_sha256":prefix_archive.sha256,"extraction":extraction,
        "snapshot_sha256":SNAPSHOT,"worker_sha256":WORKER,
        "suffix_archive":output,"suffix_archive_sha256":hex_digest(&suffix.archive_sha256),
        "suffix_manifest_sha256":hex_digest(&hash_file(&output.with_extension("jet.segment.json"))?),
        "actual_native_checkpoint_matches":true,"remaining_slots_replayed":END-ROOT,
        "suffix_complete":true,"source_must_be_retained":true,
        "canonical_sidecar_authorized":false,"publication_authorized":false}),
    )
}
fn suffix_scope(m: &HistoricalSegmentManifest) -> Result<(), String> {
    m.validate().map_err(|e| e.to_string())?;
    require(
        m.epoch == EPOCH
            && m.output_slot_start == ROOT + 1
            && m.output_slot_count == END - ROOT
            && m.bootstrap.slot == ROOT
            && m.terminal.slot == END
            && m.terminal.slot_complete
            && m.bootstrap.write_count == 0
            && m.bootstrap_archive_sha256 == Some(sha(SNAPSHOT)?)
            && m.worker_executable_sha256 == sha(WORKER)?
            && m.runtime.runtime_profile == "solana-v1.6.25"
            && m.runtime.runtime_revision == compatibility::SOLANA_V1_6_25_REVISION
            && m.runtime.genesis_hash == compatibility::MAINNET_GENESIS_HASH
            && m.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate,
        "226 suffix is not the exact complete 535-slot private recording",
    )?;
    checkpoint_matches(&expected_root(), &m.bootstrap)
}

/// Use the existing explicit V3 worker-generation transition model. V4 is untouched.
fn provenance(
    prefix: &HistoricalSegmentManifest,
    suffix: &HistoricalSegmentManifest,
) -> Result<ArchiveProvenanceV3, String> {
    prefix_scope(prefix)?;
    suffix_scope(suffix)?;
    checkpoint_matches(&prefix.terminal, &suffix.bootstrap)?;
    require(
        prefix.runtime.runtime_profile == suffix.runtime.runtime_profile
            && prefix.runtime.runtime_revision == suffix.runtime.runtime_revision
            && prefix.runtime.runtime_toolchain == suffix.runtime.runtime_toolchain
            && prefix.runtime.runtime_target == suffix.runtime.runtime_target,
        "226 worker-generation handoff cannot conceal a runtime/toolchain transition",
    )?;
    let mut next = 0;
    let mut segments = Vec::new();
    for source in [prefix, suffix] {
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: next,
        };
        next = mapping
            .archive_end_exclusive()
            .ok_or("226 normalized write range overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: source.output_slot_count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions: mapping,
        });
    }
    let v = ArchiveProvenanceV3 {
        assembly_profile: ASSEMBLY_PROFILE.into(),
        genesis_hash: compatibility::MAINNET_GENESIS_HASH
            .parse::<Hash>()
            .map_err(|e| e.to_string())?,
        bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
        bootstrap_state: StateCommitment {
            slot: prefix.bootstrap.slot,
            kind: StateCommitmentKind::LegacyAccountsHash,
            hash: prefix
                .bootstrap
                .accounts_hash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
        },
        requested_slot_start: START,
        requested_slot_count: END - START + 1,
        transaction_metadata: archive_transaction_metadata_policy(START, END - START + 1),
        runtime_segments: segments,
        handoffs: vec![RuntimeHandoffProvenance {
            boundary_slot: ROOT + 1,
            predecessor: runtime_checkpoint(&prefix.terminal)?,
            successor: runtime_checkpoint(&suffix.bootstrap)?,
            successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
            successor_bootstrap_archive_sha256: sha(SNAPSHOT)?,
            successor_bootstrap_write_count: 0,
        }],
    };
    v.validate().map_err(|e| e.to_string())?;
    require(
        ArchiveProvenanceV4 { base: v.clone() }.validate().is_err(),
        "226 distinct worker identities unexpectedly passed the unchanged V4 invariant",
    )?;
    Ok(v)
}
fn assemble(p: &Plan) -> Result<Value, String> {
    let Stage::Assemble {
        prefix_archive,
        prefix_manifest,
        extraction,
        suffix_archive,
        suffix_manifest,
        replay,
    } = &p.stage
    else {
        return Err("226 assembly stage missing".into());
    };
    let prefix = read_prefix(prefix_archive, prefix_manifest, extraction)?;
    sealed_bytes(suffix_manifest, 1 << 20)?;
    require_no_checksum(&suffix_archive.path)?;
    let suffix =
        read_and_validate_segment_manifest_from(&suffix_archive.path, &suffix_manifest.path)
            .map_err(|e| e.to_string())?;
    require(
        suffix.archive_sha256 == sha(&suffix_archive.sha256)?,
        "226 suffix archive digest differs",
    )?;
    let r = value(replay)?;
    require(
        r["schema"] == "jetstreamer-private-epoch226-suffix-v1"
            && r["epoch"] == EPOCH
            && r["prefix_archive_sha256"] == prefix_archive.sha256
            && r["worker_sha256"] == WORKER
            && r["suffix_archive_sha256"] == suffix_archive.sha256
            && r["suffix_manifest_sha256"] == suffix_manifest.sha256
            && r["extraction"] == serde_json::to_value(extraction).map_err(|e| e.to_string())?
            && r["suffix_complete"] == true
            && r["actual_native_checkpoint_matches"] == true
            && r["publication_authorized"] == false,
        "226 assembly requires exact successful private suffix receipt",
    )?;
    let provenance = provenance(&prefix, &suffix)?;
    let output = p.run_root.join("output/epoch-226-worker-transition-v3.jet");
    let mut sources = Vec::new();
    let mut identities = Vec::new();
    for (e, m) in [(prefix_archive, &prefix), (suffix_archive, &suffix)] {
        let file = open_regular_nofollow(&e.path).map_err(|e| e.to_string())?;
        identities.push((
            e.path.clone(),
            archive_file_identity(&file).map_err(|e| e.to_string())?,
        ));
        sources.push(RuntimeSegmentSource::new(
            BufReader::new(file),
            m.archive_sha256,
            m.terminal
                .last_blockhash
                .parse::<Hash>()
                .map_err(|e| e.to_string())?,
        ));
    }
    let sink = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)
        .map_err(|e| e.to_string())?;
    let (sink, stats) =
        merge_runtime_segments(sources, sink, ArchiveWriterConfig::default(), &provenance)
            .map_err(|e| e.to_string())?;
    sink.sync_all().map_err(|e| e.to_string())?;
    drop(sink);
    for (path, identity) in identities {
        require(
            path_matches_archive_identity(&path, identity).map_err(|e| e.to_string())?,
            "226 assembly source identity changed",
        )?;
    }
    require(
        stats.slots_merged == END - START + 1,
        "226 assembly coverage differs",
    )?;
    require_no_checksum(&output)?;
    Ok(
        json!({"schema":"jetstreamer-private-epoch226-explicit-worker-handoff-v1","epoch":EPOCH,
        "output":output,"archive_sha256":hex_digest(&hash_file(&output)?),"provenance_version":3,
        "assembly_profile":ASSEMBLY_PROFILE,"prefix_worker_sha256":ORIGINAL_WORKER,"suffix_worker_sha256":WORKER,
        "source_slots":[ROOT-START+1,END-ROOT],"assembled_slots":stats.slots_merged,
        "source_must_be_retained":true,"original_container_sha256":ORIGINAL_SHA,
        "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "artifact_specific_import_qualification_required":true,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}),
    )
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
        cfg!(feature = "epoch226-checkpoint-continuation-diagnostic"),
        "226 dedicated build required",
    )?;
    let p: Plan = serde_json::from_slice(&sealed_bytes(
        &Evidence {
            path: plan_path.clone(),
            sha256: plan_sha.clone(),
        },
        1 << 20,
    )?)
    .map_err(|e| e.to_string())?;
    let leaf = p
        .run_root
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("");
    require(
        p.schema == "jetstreamer-private-epoch226-scoped-repair-plan-v1"
            && p.epoch == EPOCH
            && p.run_root.parent() == Some(Path::new(PRIVATE_ROOT))
            && leaf.starts_with("checkpoint-continuation-226-")
            && leaf.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && destination == p.run_root.join("ledger")
            && p.producer_unit
                .starts_with("horizon-qualify-226-checkpoint-continuation-")
            && p.producer_unit.ends_with(".service")
            && p.producer_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && sha(&p.node_sha256)? != [0; 32],
        "226 exact owner/path scope differs",
    )?;
    for e in p
        .stage
        .evidence()
        .into_iter()
        .chain(std::iter::once(&p.admission))
    {
        require(
            e.path.is_absolute() && !e.path.starts_with(&p.run_root) && sha(&e.sha256)? != [0; 32],
            "226 input path/digest overlaps its fresh stage output",
        )?;
    }
    sealed_bytes(
        &Evidence {
            path: fs::read_link("/proc/self/exe").map_err(|e| e.to_string())?,
            sha256: p.node_sha256.clone(),
        },
        256 << 20,
    )?;
    require(
        unsafe { libc::geteuid() } == 1000,
        "226 private repair requires isolated UID 1000",
    )?;
    let invocation = authenticate_service(&p.producer_unit)?;
    let metadata = fs::symlink_metadata(&p.run_root).map_err(|e| e.to_string())?;
    require(
        p.run_root.canonicalize().map_err(|e| e.to_string())? == p.run_root
            && metadata.is_dir()
            && metadata.uid() == 1000
            && metadata.mode() & 0o077 == 0
            && fs::read_dir(&p.run_root)
                .map_err(|e| e.to_string())?
                .next()
                .is_none(),
        "226 stage root must be fresh and private",
    )?;
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(PRIVATE_ROOT).join("checkpoint-continuation-226.lock"))
        .map_err(|e| e.to_string())?;
    let lm = lease.metadata().map_err(|e| e.to_string())?;
    require(
        lm.is_file()
            && lm.nlink() == 1
            && lm.uid() == 1000
            && lm.mode() & 0o077 == 0
            && unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "226 stage lease occupied or unsafe",
    )?;
    admission(&p, &value(&p.admission)?)?;
    for name in ["ledger", "scratch", "output", "receipts"] {
        create_private_dir(&p.run_root.join(name))?;
    }
    info!(
        "private 226 {} stage started; independently admitted source preservation remains mandatory",
        p.stage.name()
    );
    let result = match &p.stage {
        Stage::Extract { .. } => extract(&p)?,
        Stage::Replay { .. } => replay(&p, shutdown, cursor, tracker).await?,
        Stage::Assemble { .. } => assemble(&p)?,
    };
    let receipt = p.run_root.join(format!("receipts/{}.json", p.stage.name()));
    // Stage receipt is durable only after the output directory entries are durable.
    File::open(p.run_root.join("output"))
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())?;
    write_json(&receipt, &result)?;
    write_json(
        &p.run_root.join("receipts/owner.json"),
        &json!({"producer_unit":p.producer_unit,
        "invocation_id":invocation,"plan":{"path":plan_path,"sha256":plan_sha},"operation":p.stage.name(),
        "receipt":receipt,"receipt_sha256":hex_digest(&hash_file(&receipt)?),"source_must_be_retained":true,
        "publication_authorized":false,"r2_mutations":false}),
    )?;
    info!(
        "private 226 {} stage complete; output preserved; final Full/Plugin/import/publication gates remain closed",
        p.stage.name()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic selected/suffix manifests for structural rejection tests. These
    // are not observations of an extracted prefix or a completed suffix.
    fn manifests() -> (HistoricalSegmentManifest, HistoricalSegmentManifest) {
        let original = include_bytes!("../tests/fixtures/epoch226-original-combined.manifest.json");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(original)),
            sha(ORIGINAL_MANIFEST_SHA).unwrap()
        );
        let mut prefix: HistoricalSegmentManifest = serde_json::from_slice(original).unwrap();
        prefix.epoch = EPOCH;
        prefix.output_slot_start = START;
        prefix.output_slot_count = ROOT - START + 1;
        prefix.archive_sha256 = [1; 32];
        prefix.emitted_raw_write_versions.start = 110_000_000_000;
        let mut suffix = prefix.clone();
        suffix.output_slot_start = ROOT + 1;
        suffix.output_slot_count = END - ROOT;
        suffix.archive_sha256 = [2; 32];
        suffix.worker_executable_sha256 = sha(WORKER).unwrap();
        suffix.bootstrap_archive_sha256 = Some(sha(SNAPSHOT).unwrap());
        suffix.bootstrap = expected_root();
        suffix.bootstrap.write_count = 0;
        suffix.bootstrap.next_write_version = 111_561_971_623;
        suffix.terminal = suffix.bootstrap.clone();
        suffix.terminal.slot = END;
        suffix.terminal.next_write_version += 2;
        suffix.terminal.tick_height = 64 * (END + 1);
        suffix.emitted_raw_write_versions = 111_561_971_623..111_561_971_625;
        (prefix, suffix)
    }
    #[test]
    fn explicit_worker_handoff_keeps_native_cursors_and_does_not_weaken_v4() {
        let (prefix, suffix) = manifests();
        let v = provenance(&prefix, &suffix).unwrap();
        assert_eq!(v.requested_slot_count, 432000);
        assert_eq!(
            v.runtime_segments[0].worker_executable_sha256,
            Some(sha(ORIGINAL_WORKER).unwrap())
        );
        assert_eq!(
            v.runtime_segments[1].worker_executable_sha256,
            Some(sha(WORKER).unwrap())
        );
        assert_eq!(
            v.handoffs[0].predecessor.next_write_version,
            111_241_712_667
        );
        assert_eq!(v.handoffs[0].successor.next_write_version, 111_561_971_623);
        assert_eq!(
            v.runtime_segments[1].write_versions.archive_start,
            prefix.emitted_raw_write_versions.end - prefix.emitted_raw_write_versions.start
        );
        assert!(v.validate().is_ok());
        assert!(ArchiveProvenanceV4 { base: v }.validate().is_err());
    }
    #[test]
    fn worker_scope_gaps_root_mutations_and_bootstrap_writes_fail_closed() {
        let (prefix, suffix) = manifests();
        for mutation in 0..8 {
            let mut bad = suffix.clone();
            match mutation {
                0 => bad.worker_executable_sha256 = sha(ORIGINAL_WORKER).unwrap(),
                1 => bad.output_slot_start += 1,
                2 => bad.output_slot_count -= 1,
                3 => bad.terminal.slot -= 1,
                4 => bad.bootstrap.bank_hash = prefix.bootstrap.bank_hash.clone(),
                5 => bad.bootstrap.write_count = 1,
                6 => bad.bootstrap_archive_sha256 = None,
                _ => bad.runtime.runtime_revision = "unqualified".into(),
            }
            assert!(
                provenance(&prefix, &bad).is_err(),
                "accepted mutation {mutation}"
            );
        }
        let mut bad = prefix.clone();
        bad.output_slot_count -= 1;
        assert!(provenance(&bad, &suffix).is_err());
    }
    #[test]
    fn stage_input_digest_changes_with_any_worker_or_prefix_binding() {
        let e = |name: &str| Evidence {
            path: Path::new("/sealed").join(name),
            sha256: "a".repeat(64),
        };
        let first = Stage::Replay {
            prefix_archive: e("prefix"),
            prefix_manifest: e("manifest"),
            extraction: e("extraction"),
            snapshot: e("snapshot"),
            worker: e("worker"),
            genesis: e("genesis"),
        };
        let mut other: Stage =
            serde_json::from_value(serde_json::to_value(&first).unwrap()).unwrap();
        let Stage::Replay { worker, .. } = &mut other else {
            unreachable!()
        };
        worker.sha256 = "b".repeat(64);
        assert_ne!(stage_digest(&first).unwrap(), stage_digest(&other).unwrap());
    }
    #[test]
    fn exact_span_records_all_missing_slots_instead_of_227_warmup() {
        assert_eq!(ROOT - START + 1, 431465);
        assert_eq!(END - ROOT, 535);
        assert_eq!(END - START + 1, 432000);
        let q = QualificationPlan {
            epoch: EPOCH,
            bootstrap_slot: ROOT,
            replay_start: ROOT + 1,
            output_slot_start: ROOT + 1,
            end_inclusive: END,
        };
        assert_eq!(q.slot_count(), 535);
        assert_ne!(q.output_slot_start, 98_064_000);
    }
    #[test]
    fn native_consensus_equality_does_not_equate_local_cursors() {
        let original = expected_root();
        let mut restored = original.clone();
        restored.write_count = 0;
        restored.next_write_version = 111_561_971_623;
        assert!(checkpoint_matches(&original, &restored).is_ok());
        for field in 0..8 {
            let mut bad = restored.clone();
            match field {
                0 => bad.slot -= 1,
                1 => bad.bank_hash = "11111111111111111111111111111111".into(),
                2 => bad.accounts_hash = "11111111111111111111111111111111".into(),
                3 => bad.last_blockhash = "11111111111111111111111111111111".into(),
                4 => bad.capitalization -= 1,
                5 => bad.transaction_count -= 1,
                6 => bad.tick_height -= 1,
                _ => bad.slot_complete = false,
            }
            assert!(checkpoint_matches(&original, &bad).is_err());
        }
    }
    #[test]
    fn exclusive_entrypoint_rejects_other_operations_before_shared_dispatch() {
        let args = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        for v in [
            args(&["--failed-prefix220-recover", "/plan", "hash", "node"]),
            args(&["--post-update-capacity-probe"]),
            args(&["--probe-successor-boundary=123"]),
            args(&["226", "/dst", "--require-local-epoch167-index"]),
            args(&["227", "/dst", "--verify"]),
        ] {
            assert!(validate_entrypoint(&v).is_err());
        }
        assert!(
            validate_entrypoint(&args(&[
                "226-226",
                "/dst",
                "--verify",
                "--checkpoint-continuation-plan=/plan",
                "--checkpoint-continuation-plan-sha256=hash"
            ]))
            .is_ok()
        );
        assert!(validate_entrypoint(&args(&["--help"])).is_ok());
    }
    #[test]
    fn cli_rejects_other_epoch_missing_verification_and_ordinary_overrides() {
        for (range, verify, count, destination, forbidden) in [
            ((227, 227), Some(true), 1, true, false),
            ((226, 226), None, 0, true, false),
            ((226, 226), Some(true), 1, false, false),
            ((226, 226), Some(true), 1, true, true),
        ] {
            assert!(validate_cli(range, verify, count, destination, forbidden).is_err());
        }
    }
    #[cfg(feature = "epoch226-checkpoint-continuation-diagnostic")]
    #[test]
    fn exclusive_build_accepts_only_exact_private_cli() {
        assert!(validate_cli((226, 226), Some(true), 1, true, false).is_ok());
        assert!(validate_cli((226, 226), Some(true), 2, true, false).is_err());
    }
}
