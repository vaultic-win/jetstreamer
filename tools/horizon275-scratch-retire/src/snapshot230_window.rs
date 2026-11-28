//! Release authenticated epoch 230 bootstrap caches after their consumers and guards close.
use super::{
    appendvec292::failed::{StoppedReference, no_readers},
    snapshot296::{BoundCache, evict_cache},
    *,
};

pub(super) struct Window {
    slot: u64,
    end: u64,
    cache: &'static str,
    name: &'static str,
    size: u64,
    owner: u32,
    sha: &'static str,
    generation: u64,
    bucket: &'static str,
    prefix: &'static str,
    crc32c: &'static str,
    md5: &'static str,
    etag: &'static str,
    restore_sha: &'static str,
    closure: (&'static str, &'static str, &'static str),
    native: Option<(&'static str, &'static str)>,
    playback: &'static str,
    archive_sha: &'static str,
    unit: &'static str,
    timer: &'static str,
}

const V1627: Window = Window {
    slot: 99_461_591,
    end: 99_468_089,
    cache: "/home/ubuntu/.jetstreamer-private/epoch230-v1627-intake.HlU7mFu7",
    name: "snapshot-99461591-9Hgyrxkc5h5mkAwPL7rUGASHZFMByNzE1TYmCPb4z4e7.tar.zst",
    size: 10_317_931_499,
    owner: 0,
    sha: "8d151ada8340711fc20b47a7f3d80e092a41137ef87d4525dd8398def106d8b7",
    generation: 1_633_485_613_712_596,
    bucket: "mainnet-beta-ledger-us-ny5",
    prefix: "99360309/hourly",
    crc32c: "rOWSpA==",
    md5: "r2Gw+vGr2hWcjdHpQmK9zA==",
    etag: "CNSJgY7YtPMCEAE=",
    restore_sha: "fff5a46baf3be1bb524a3e9584519378a87748ab2f439d41f1b8cb41da9d40d8",
    closure: (
        "/var/lib/jetstreamer/horizon230-v1627-replay-runtime-v1/terminal.json",
        "db618cf906b39ffe64f80b7a0c90febaa4d54054cac4a74e2fed12cea772846e",
        "foundation-epoch230-v1627-private-drain-v1",
    ),
    native: Some((
        "/var/lib/jetstreamer/horizon230-v1627-terminal-collector-state-v1/evidence/terminal-evidence.json",
        "f040aafc2b2d182e11f6baf2df911957ecc301609fc329932fa724a56c344f56",
    )),
    playback: "/var/lib/jetstreamer/horizon230-v1627-poh-readback-v1/receipt.json",
    archive_sha: "605ce4e8f9568a136f463864a7db881882bd3664e1f0c3dfec8f829e882e4ded",
    unit: "horizon-qualify-230-v1627-window-v1.service",
    timer: "horizon-230-v1627-window-protective-v1.timer",
};
const SECOND: Window = Window {
    slot: 99_476_782,
    end: 99_516_304,
    cache: "/home/ubuntu/.jetstreamer-private/epoch230-checkpoint-99476782-generation-1633495975351467-v1",
    name: "snapshot-99476782-26wibqVauVjaet3eM6o8hssvaXi4awt7ndjwCaYJZyPK.tar.zst",
    size: 10_387_606_500,
    owner: 1000,
    sha: "82e04448803996e9d2924d177acd6c66998bfaf183f29aaf43af3026669b8114",
    generation: 1_633_495_975_351_467,
    bucket: "mainnet-beta-ledger-europe-fr2",
    prefix: "99359376/hourly",
    crc32c: "3L5Fxg==",
    md5: "0xxB7JSGFBjmkid/adDPqQ==",
    etag: "CKup6dr+tPMCEAE=",
    restore_sha: "fcc255cae73653fee3763fee08897bc82d1c45b3750a86342f1c884762c19e9a",
    closure: (
        "/var/lib/jetstreamer/horizon230-middle-hourly-second-runtime-v1/terminal.json",
        "2ed2322cffebec1575bc9ba4dea1894e9e710c3b970c9db504153869f70a9b56",
        "foundation-epoch230-middle-hourly-second-terminal-v1",
    ),
    native: None,
    playback: "/var/lib/jetstreamer/horizon230-hourly-second-poh-readback-v1/receipt.json",
    archive_sha: "c81f2f9afa04c7ee2f03205ce351d4d1a852c46ff93e3063c895ff3facfb4ba3",
    unit: "horizon-qualify-230-middle-hourly-second-v1.service",
    timer: "horizon-230-middle-hourly-second-protective-v1.timer",
};

const VOTE: Window = Window {
    slot: 99_430_284,
    end: 99_437_433,
    cache: "/home/ubuntu/.jetstreamer-private/epoch230-mismatch-99430284-v1.OjKV2hXf",
    name: "snapshot-99430284-BNZTcU9y17US1ucG9dMqKdL2PgUpQou2PPDArWKrBoWu.tar.zst",
    size: 10_243_100_016,
    owner: 1000,
    sha: "4b0b16de74ba067d18eeec76326390c767d5fa0389083e5e837c27d5c37befeb",
    generation: 1_633_485_628_677_598,
    bucket: "mainnet-beta-ledger-us-ny5",
    prefix: "99360309/hourly",
    crc32c: "vDpQxg==",
    md5: "2Tz0guFk4bbzOj88Yo+j6w==",
    etag: "CN67kpXYtPMCEAE=",
    restore_sha: "e9663e5eaeae578acbaec85f32fe1b6da0d07a0043b75c0294fd99b17a74de82",
    closure: (
        "/var/lib/jetstreamer/horizon230-vote-boundary-runtime-v1/terminal.json",
        "6ba3d174d03109316e58b7e043d7daa9fa0e4ae29bfb1ab7b6424601bc96cdea",
        "foundation-epoch230-vote-boundary-terminal-v1",
    ),
    native: None,
    playback: "/var/lib/jetstreamer/horizon230-vote-boundary-poh-readback-v1/receipt.json",
    archive_sha: "72e506f3cd9f5db0c0d932bc9ce32e6547c64058305d1a3d3d7cae577ecf8f73",
    unit: "horizon-perf-epoch230-vote-boundary@v1.service",
    timer: "horizon-230-vote-boundary-protective-v1.timer",
};

const VOTE_FAILED_READER: &str = "horizon-perf-epoch230-bounded-mismatch@v2.service";
const VOTE_FAILED_RECIPE_SHA: &str =
    "2ad8d278829a46aa2d4ed58c24c3987f08bdefccf3c04a1eec9f35bed81136f9";

pub(super) fn for_command(command: &str) -> Option<&'static Window> {
    match command {
        "--check-bootstrap-230-99430284" | "--retire-bootstrap-230-99430284" => Some(&VOTE),
        "--check-bootstrap-230-99461591" | "--retire-bootstrap-230-99461591" => Some(&V1627),
        "--check-bootstrap-230-99476782" | "--retire-bootstrap-230-99476782" => Some(&SECOND),
        _ => None,
    }
}

fn vote_terminal(closed: &Value, played: &Value) -> Result<(Value, Value)> {
    const INVOCATION: &str = "5c3f5abbfd8048f39f61fe9bbc73c1f5";
    const ARCHIVE: &str = "/var/lib/jetstreamer/horizon230-vote-boundary-sealed-segment-v1/epoch-230-vote-boundary-demotion-diagnostic.jet";
    const END_HASH: &str = "FPZQp7MtEYAgjjbWHtJGnbf9biFai7GDndKejnQXgPFP";
    let exit: Binding = serde_json::from_value(closed["manager_exit"].clone())?;
    let exit: Value = read_bound(&exit.path, &exit.sha256, JSON_LIMIT)?;
    let validation: Binding = serde_json::from_value(closed["validation"].clone())?;
    let validation: Value = read_bound(&validation.path, &validation.sha256, JSON_LIMIT)?;
    ensure!(
        closed["invocation_id"] == INVOCATION
            && closed["canonical_slots"] == json!([VOTE.slot + 1, VOTE.end])
            && closed["archive"]["path"] == ARCHIVE
            && closed["archive"]["sha256"] == VOTE.archive_sha
            && exit["_PID"] == "1"
            && exit["UNIT"] == VOTE.unit
            && exit["INVOCATION_ID"] == INVOCATION
            && exit["MESSAGE"] == format!("{}: Deactivated successfully.", VOTE.unit)
            && validation["validation"] == "pass"
            && validation["output_slot_start"] == VOTE.slot + 1
            && validation["output_slot_count"] == VOTE.end - VOTE.slot
            && validation["terminal_slot"] == VOTE.end
            && validation["archive_sha256"] == VOTE.archive_sha
            && validation["archive_bytes"] == closed["archive_bytes"]
            && played["archive_identity"]["length"] == closed["archive_bytes"]
            && played["closure_sha256"] == VOTE.closure.1,
        "vote-boundary segment or manager exit does not match the sealed run"
    );
    let mut archive = closed["archive"].clone();
    archive["identity"] = played["archive_identity"].clone();
    Ok((archive, json!({"slot":VOTE.end,"last_blockhash":END_HASH})))
}

fn terminal(window: &Window, played: &Value) -> Result<(Value, Value)> {
    let (path, sha, schema) = window.closure;
    let closed: Value = read_bound(Path::new(path), sha, JSON_LIMIT)?;
    ensure!(
        closed["schema"] == schema
            && closed["guard_drained"] == true
            && closed["publication_authorized"] == false,
        "epoch 230 window is not closed"
    );
    if window.slot == VOTE.slot {
        return vote_terminal(&closed, played);
    }
    ensure!(
        closed["unit"] == window.unit && closed["state"] == "local-segment-committed",
        "epoch 230 window did not commit a local segment"
    );
    let (body, checkpoint) = if let Some((path, sha)) = window.native {
        ensure!(
            closed["native_terminal"] == json!({"path":path,"sha256":sha}),
            "foreign epoch 230 native result"
        );
        let native: Value = read_bound(Path::new(path), sha, JSON_LIMIT)?;
        ensure!(
            native["native_manifest_complete_verified"] == true
                && native["producer_drained"] == true
                && native["producer_exit_status"] == 0
                && native["invocation_id"] == closed["invocation_id"]
                && native["bootstrap_checkpoint"]["slot"] == window.slot
                && native["archive"]["sha256"] == window.archive_sha,
            "epoch 230 native terminal differs from the closed window"
        );
        (native, "terminal_checkpoint")
    } else {
        ensure!(
            closed["archive"]["native_sha256"] == window.archive_sha,
            "epoch 230 closed archive digest changed"
        );
        (closed, "checkpoint")
    };
    ensure!(
        body["first_slot"] == window.slot + 1
            && body["last_slot"] == window.end
            && body[checkpoint]["slot"] == window.end,
        "foreign epoch 230 playback range"
    );
    Ok((body["archive"].clone(), body[checkpoint].clone()))
}

pub(super) fn run(
    window: &Window,
    apply: bool,
    self_sha: &str,
    proof_path: &Path,
    metadata_sha: &str,
) -> Result<()> {
    let state = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon230-bootstrap-{}-retirement-v1",
        window.slot
    ));
    let meta = state.symlink_metadata()?;
    ensure!(
        state.canonicalize()? == state
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o077 == 0
            && proof_path.parent() == Some(&state)
            && proof_path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(
                    |name| name.starts_with("generation-recheck-") && name.ends_with(".json")
                ),
        "unsafe epoch 230 retirement evidence paths"
    );
    let path = Path::new(window.cache).join(window.name);
    let proof: Value = read_bound(proof_path, metadata_sha, JSON_LIMIT)?;
    let object = &proof["object"];
    ensure!(
        proof["schema"] == "foundation-epoch230-closed-bootstrap-generation-recheck-v1"
            && proof["snapshot_sha256"] == window.sha
            && object["bucket"] == window.bucket
            && object["name"] == format!("{}/{}", window.prefix, window.name)
            && object["generation"] == window.generation.to_string()
            && object["size"] == window.size
            && object["crc32c"] == window.crc32c
            && object["md5"] == window.md5
            && object["etag"] == window.etag,
        "epoch 230 GCS restore identity differs"
    );
    let restore: Value = read_bound(
        &state.join("prior-restore.json"),
        window.restore_sha,
        JSON_LIMIT,
    )?;
    ensure!(
        restore["snapshot_slot"] == window.slot
            && restore["generation"] == window.generation
            && restore["destination"] == json!(path)
            && restore["file"]["sha256"] == window.sha
            && restore["file"]["size"] == window.size
            && restore["file"]["crc32c_base64"] == window.crc32c
            && restore["file"]["md5_base64"] == window.md5,
        "prior restore differs from the pinned epoch 230 generation"
    );
    let reader: Binding = serde_json::from_value(proof["playback"].clone())?;
    ensure!(
        reader.path == Path::new(window.playback),
        "foreign epoch 230 playback path"
    );
    let played: Value = read_bound(&reader.path, &reader.sha256, JSON_LIMIT)?;
    let (archive, edge) = terminal(window, &played)?;
    ensure!(
        played["schema"] == "foundation-epoch230-closed-window-full-poh-v1"
            && played["first_slot"] == window.slot + 1
            && played["last_slot"] == window.end
            && played["slots"] == window.end - window.slot
            && played["archive_sha256"] == window.archive_sha
            && played["archive_path"] == archive["path"]
            && played["terminal_blockhash"] == edge["last_blockhash"]
            && played["producer_exit_status"] == 0
            && played["all_positions_read"] == true
            && played["full_poh_verified"] == true
            && played["publication_authorized"] == false,
        "independent epoch 230 playback is incomplete"
    );
    let adjacent: Value = read_bound(
        Path::new("/var/lib/jetstreamer/horizon230-adjacent-99445304-runtime-v1/profile.json"),
        "d01cf1c1a583c41e885ea74f57aea21a5e5178554e94bca16d01674a5bff1d1b",
        JSON_LIMIT,
    )?;
    ensure!(
        adjacent["readonly_bindings"]
            .as_array()
            .is_some_and(|rows| rows.len() == 4
                && rows
                    .iter()
                    .all(|row| row["path"].as_str().is_some_and(|p| Path::new(p) != path))),
        "the adjacent epoch 230 replay needs this bootstrap"
    );
    let archive_path = Path::new(archive["path"].as_str().context("archive path")?);
    let archive_state = || -> Result<()> {
        let meta = open_regular(archive_path)?.metadata()?;
        let id = &archive["identity"];
        let nanos = |s: i64, f: i64| i128::from(s) * 1_000_000_000 + i128::from(f);
        let timestamps_match = if window.native.is_some() {
            id["bytes"] == meta.len()
                && id["mtime_ns"] == json!(nanos(meta.mtime(), meta.mtime_nsec()))
                && id["ctime_ns"] == json!(nanos(meta.ctime(), meta.ctime_nsec()))
        } else {
            id["length"] == meta.len()
                && id["modified_seconds"] == meta.mtime()
                && id["modified_nanoseconds"] == meta.mtime_nsec()
                && id["changed_seconds"] == meta.ctime()
                && id["changed_nanoseconds"] == meta.ctime_nsec()
        };
        ensure!(
            id["device"] == meta.dev() && id["inode"] == meta.ino() && timestamps_match,
            "epoch 230 retained archive changed after playback"
        );
        Ok(())
    };
    archive_state()?;
    let observe = || -> Result<(Value, Value)> {
        terminal_unit(window.unit)?;
        terminal_unit(window.timer)?;
        assert_no_nested_mount(&path)?;
        let stopped: &[(&str, &str, StoppedReference)] = if window.slot == VOTE.slot {
            terminal_unit("horizon-230-bounded-mismatch-protective-v2.timer")?;
            let fragment = Path::new("/run/systemd/transient").join(VOTE_FAILED_READER);
            if fragment.try_exists()? {
                let mut recipe = open_regular(&fragment)?;
                let meta = recipe.metadata()?;
                ensure!(
                    meta.uid() == 0
                        && meta.mode() & 0o022 == 0
                        && digest(&mut recipe)? == VOTE_FAILED_RECIPE_SHA
                        && identity(&meta) == identity(&fragment.symlink_metadata()?),
                    "changed failed vote-boundary reader definition"
                );
            }
            &[(
                VOTE_FAILED_READER,
                "b02e106a069b4cc080bdc5b8a948fe55",
                StoppedReference::Direct(VOTE_FAILED_RECIPE_SHA),
            )]
        } else {
            &[]
        };
        let report = no_readers(Path::new(window.cache), &path, stopped)?;
        Ok((report["scheduled"].clone(), report["processes"].clone()))
    };
    let context = json!({"source":path,"source_sha256":window.sha,"terminal_sha256":window.closure.1,
        "verified_archive_sha256":reader.sha256,"restore_sha256":window.restore_sha,
        "tool_sha256":self_sha,"generation":object});
    evict_cache(
        BoundCache {
            apply,
            state: &state,
            path: &path,
            size: window.size,
            owner: window.owner,
            sha: window.sha,
            restore: &restore,
            proof: &proof,
            metadata_sha,
            context,
        },
        observe,
        archive_state,
    )
}
