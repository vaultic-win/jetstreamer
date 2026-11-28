//! Retire one reproducible GCS intake after the verified private 266 seam.

use super::{
    appendvec292::failed::no_readers,
    snapshot296::{BoundCache, evict_cache, stamp},
    *,
};

const STATE: &str = "/var/lib/jetstreamer/horizon266-bootstrap-114910768-retirement-v1";
const CACHE: &str = "/home/ubuntu/.jetstreamer-private/epoch266-predecessor-intake-v1";
const NAME: &str = "snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
const SIZE: u64 = 16_826_334_350;
const GENERATION: u64 = 1_641_767_242_524_970;
const SHA: &str = "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
const INTAKE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-predecessor-intake-stage-v1/custody.json",
    "afd03e2258229848a2878f1c2ff75b424ebf810b79fec65788c75ac5111a5959",
);
const RESTORE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-predecessor-intake-stage-v1/gcs-restore.json",
    "28eda0c04e4214768674b1f9966a9fae6d7a4f783ddf399806275982a3755439",
);
const SEAM: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-boundary-account-proof-runtime-v1/private-seam.json",
    "4abaa6a0a424ba2befb221dde64ed8afc107df66e474c5ca5542007c8507dadd",
);
const DRAIN: (&str, &str) = (
    "/var/lib/jetstreamer/horizon266-original-predecessor-runtime-v1/failed-verification-drain.json",
    "ad2ca2388e3f1febb08a2c81548bba7e7b200bb46b5e4479b7b5f573b7ed5055",
);
const PRODUCER: &str = "horizon-qualify-266-original-predecessor-v1.service";
const TIMER: &str = "horizon-266-original-predecessor-protective-v1.timer";
const GUARD: &str = "horizon-266-original-predecessor-protective-v1.service";
const COLLECTOR: &str = "epoch266-boundary-account-proof-v1.service";

fn checked_archive(value: &Value) -> Result<(PathBuf, Value)> {
    let path = PathBuf::from(value["path"].as_str().context("missing archive path")?);
    let meta = open_regular(&path)?.metadata()?;
    let nanos = |sec, ns| i128::from(sec) * 1_000_000_000 + i128::from(ns);
    let expected = &value["identity"];
    ensure!(
        expected["device"] == meta.dev()
            && expected["inode"] == meta.ino()
            && expected["bytes"] == meta.len()
            && expected["mtime_ns"] == json!(nanos(meta.mtime(), meta.mtime_nsec()))
            && expected["ctime_ns"] == json!(nanos(meta.ctime(), meta.ctime_nsec())),
        "retained epoch 266 evidence changed: {}",
        path.display()
    );
    Ok((path, stamp(&meta)))
}

fn drained_guard(expected: &Value) -> Result<()> {
    let feedback = Command::new("/usr/bin/systemctl")
        .args(["show", GUARD, "-p", "Id,ActiveState,SubState,Result,InvocationID,MainPID,ControlPID,ControlGroup,Job,Restart,TriggeredBy"])
        .output()?;
    ensure!(
        feedback.status.success(),
        "could not inspect the recorded epoch 266 guard"
    );
    let status = std::str::from_utf8(&feedback.stdout)?;
    for (key, fixed) in [
        ("Id", GUARD),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ControlGroup", ""),
        ("Job", ""),
        ("Restart", "no"),
        ("TriggeredBy", ""),
    ] {
        ensure!(
            status.lines().any(|line| line == format!("{key}={fixed}")),
            "epoch 266 guard does not bind the drained {key} state"
        );
        if key != "TriggeredBy" {
            ensure!(
                expected[key] == fixed,
                "epoch 266 guard differs from its drain evidence"
            );
        }
    }
    let invocation = expected["InvocationID"]
        .as_str()
        .context("missing drained guard invocation")?;
    ensure!(
        invocation.len() == 32
            && invocation.bytes().all(|byte| byte.is_ascii_hexdigit())
            && status
                .lines()
                .any(|line| line == format!("InvocationID={invocation}"))
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(GUARD)
                .try_exists()?,
        "epoch 266 guard invocation changed or still owns a cgroup"
    );
    Ok(())
}

pub(super) fn run(
    apply: bool,
    self_sha: &str,
    proof_path: &Path,
    metadata_sha: &str,
) -> Result<()> {
    let state = Path::new(STATE);
    let meta = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0
            && proof_path.parent() == Some(state)
            && proof_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with("generation-recheck-") && name.ends_with(".json")
                ),
        "unsafe epoch 266 retirement evidence paths"
    );
    let proof: Value = read_bound(proof_path, metadata_sha, JSON_LIMIT)?;
    let object = value(&proof["metadata"])?;
    let path = Path::new(CACHE).join(NAME);
    let name = format!("114910768/{NAME}");
    let uri = format!("gs://mainnet-beta-ledger-us-ny5/{name}#{GENERATION}");
    let restore: Value = read_bound(Path::new(RESTORE.0), RESTORE.1, JSON_LIMIT)?;
    let custody: Value = read_bound(Path::new(INTAKE.0), INTAKE.1, JSON_LIMIT)?;
    ensure!(
        proof["schema"] == "foundation-epoch266-bootstrap-114910768-generation-recheck-v1"
            && proof["snapshot_sha256"] == SHA
            && object["bucket"] == "mainnet-beta-ledger-us-ny5"
            && object["name"] == name
            && object["generation"] == GENERATION.to_string()
            && object["storage_url"] == uri
            && object["size"] == SIZE
            && object["crc32c_hash"] == "i85Rcw=="
            && object["md5_hash"] == "frRtvWbKEzOW/onIQa3MeQ=="
            && object["etag"] == "CKrSrcrbpfUCEAE="
            && restore["versioned_uri"] == uri
            && restore["destination"] == json!(path)
            && restore["snapshot_slot"] == 114_910_768
            && restore["generation"] == GENERATION
            && restore["file"]["size"] == SIZE
            && restore["file"]["sha256"] == SHA
            && restore["file"]["crc32c_base64"] == object["crc32c_hash"]
            && restore["file"]["md5_base64"] == object["md5_hash"]
            && custody["gcs_restore"] == json!({"path":RESTORE.0,"sha256":RESTORE.1})
            && custody["input"]["path"] == json!(path)
            && custody["input"]["sha256"] == SHA
            && custody["input"]["inode"] == restore["file"]["inode"]
            && custody["input"]["device"] == restore["file"]["device"]
            && custody["actual_readonly_projection_verified"] == true,
        "epoch 266 bootstrap differs from the independently restored generation"
    );
    let seam: Value = read_bound(Path::new(SEAM.0), SEAM.1, JSON_LIMIT)?;
    let drain: Value = read_bound(Path::new(DRAIN.0), DRAIN.1, JSON_LIMIT)?;
    let preceding = value(&seam["preceding_witness"])?;
    let following = value(&seam["following_terminal"])?;
    ensure!(
        drain["guard_drained"] == true
            && drain["invocation_id"] == preceding["invocation_id"]
            && preceding["producer_drained"] == true
            && preceding["native_manifest_complete_verified"] == true
            && preceding["terminal_consensus_fields_match"] == true
            && preceding["ordered_frames_excluding_boundary_batch_match"] == true
            && preceding["boundary_pre_account_histories"]["per_account_order_and_content_match"]
                == true
            && following["producer_drained"] == true
            && following["native_manifest_complete_verified"] == true
            && seam["retained_prefix"] == preceding["assembly_prefix"]
            && seam["following_archive"] == following["archive"]
            && seam["covered_slots"] == json!([114_912_000, 114_929_697])
            && seam["publication_authorized"] == false,
        "epoch 266 seam lacks bound drained replay evidence"
    );
    let retained_ref: Binding = serde_json::from_value(seam["retained_prefix"].clone())?;
    let mut retained = open_regular(&retained_ref.path)?;
    let retained_stamp = stamp(&retained.metadata()?);
    ensure!(
        digest(&mut retained)? == retained_ref.sha256,
        "retained prefix SHA-256 differs"
    );
    let archives = [
        checked_archive(&preceding["archive"])?,
        checked_archive(&preceding["segment_manifest"])?,
        checked_archive(&following["archive"])?,
        checked_archive(&following["segment_manifest"])?,
        (retained_ref.path, retained_stamp),
    ];
    let archive_state = || -> Result<()> {
        for (path, expected) in &archives {
            ensure!(
                stamp(&open_regular(path)?.metadata()?) == *expected,
                "retained input changed: {}",
                path.display()
            );
        }
        Ok(())
    };
    archive_state()?;
    let observe = || -> Result<(Value, Value)> {
        for unit in [PRODUCER, TIMER, COLLECTOR] {
            terminal_unit(unit)?;
        }
        drained_guard(&drain["guard_after"])?;
        assert_no_nested_mount(&path)?;
        let report = no_readers(Path::new(CACHE), &path, &[])?;
        Ok((report["scheduled"].clone(), report["processes"].clone()))
    };
    evict_cache(
        BoundCache {
            apply,
            state,
            path: &path,
            size: SIZE,
            owner: 0,
            sha: SHA,
            restore: &restore,
            proof: &proof,
            metadata_sha,
            context: json!({"source":path,"source_sha256":SHA,"seam_sha256":SEAM.1,
            "drain_sha256":DRAIN.1,"restore_sha256":RESTORE.1,"tool_sha256":self_sha,"generation":object}),
        },
        observe,
        archive_state,
    )
}
