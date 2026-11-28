//! Release a closed epoch 230 bootstrap whose immutable GCS generation is still available.
use super::{
    appendvec292::failed::{StoppedReference, no_readers},
    snapshot296::{BoundCache, evict_cache},
    *,
};

const STATE: &str = "/var/lib/jetstreamer/horizon230-bootstrap-99437433-retirement-v1";
const CACHE: &str =
    "/home/ubuntu/.jetstreamer-private/epoch230-checkpoint-99437433-generation-1633495968730072-v1";
const NAME: &str = "snapshot-99437433-eAarFVYbpioWaBvd5S9RMHo1AyLbixgaTsBWLxYUaDr.tar.zst";
const SIZE: u64 = 10_294_666_827;
const SHA: &str = "3f93d04ff105ceca127a3c0464beec7e980eeb81b4a2e52a352f5d545614bef0";
const RESTORE_SHA: &str = "c344348baf0d2a27d2df0b064a76ae7a9f90d60517defd42151f74d8a70fd764";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon230-first-7871-runtime-v1/terminal.json";
const TERMINAL_SHA: &str = "16d546332a37fccd20a7b2609908288b426276a01908c6e255db886aba6ea8d2";
const PLAYBACK: &str = "/var/lib/jetstreamer/horizon230-first-7871-poh-readback-v1/receipt.json";
const ARCHIVE_SHA: &str = "d20d2f74e02133ded807d9c9a3633ab638476b1ca64cb73d778b5e39909cae46";
const HISTORICAL: &str = "horizon-qualify-230-middle-hourly-first-v1.service";
const HISTORICAL_UNIT_SHA: &str =
    "43b07efdb2768acd7602b42d376bfa356cd1bf157bd0563c5e32f07c5f8fc466";

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
        "unsafe epoch 230 retirement evidence paths"
    );
    let path = Path::new(CACHE).join(NAME);
    let proof: Value = read_bound(proof_path, metadata_sha, JSON_LIMIT)?;
    let object = &proof["object"];
    ensure!(
        proof["schema"] == "foundation-epoch230-bootstrap-99437433-generation-recheck-v1"
            && proof["snapshot_sha256"] == SHA
            && object["bucket"] == "mainnet-beta-ledger-europe-fr2"
            && object["name"] == format!("99359376/hourly/{NAME}")
            && object["generation"] == "1633495968730072"
            && object["size"] == SIZE
            && object["crc32c"] == "fCDbNw=="
            && object["md5"] == "JPckKo4OeMxLGLMKjTsnYA=="
            && object["etag"] == "CNiX1df+tPMCEAE=",
        "epoch 230 GCS restore identity differs"
    );
    let restore: Value = read_bound(&state.join("prior-restore.json"), RESTORE_SHA, JSON_LIMIT)?;
    ensure!(
        restore["snapshot_slot"] == 99_437_433
            && restore["generation"] == 1_633_495_968_730_072u64
            && restore["destination"] == json!(path)
            && restore["file"]["sha256"] == SHA
            && restore["file"]["size"] == SIZE
            && restore["file"]["crc32c_base64"] == object["crc32c"]
            && restore["file"]["md5_base64"] == object["md5"],
        "epoch 230 prior restore differs from the pinned generation"
    );
    let terminal: Value = read_bound(Path::new(TERMINAL), TERMINAL_SHA, JSON_LIMIT)?;
    let playback: Binding = serde_json::from_value(proof["playback"].clone())?;
    ensure!(
        playback.path == Path::new(PLAYBACK),
        "foreign epoch 230 playback path"
    );
    let confirmed: Value = read_bound(&playback.path, &playback.sha256, JSON_LIMIT)?;
    ensure!(
        terminal["schema"] == "foundation-epoch230-first-7871-terminal-v1"
            && terminal["guard_drained"] == true
            && terminal["snapshot_verified"] == true
            && terminal["state"] == "local-segment-committed"
            && terminal["first_slot"] == 99_437_434
            && terminal["last_slot"] == 99_445_304
            && terminal["archive"]["native_sha256"] == ARCHIVE_SHA
            && terminal["archive"]["independent_sha256"] == ARCHIVE_SHA
            && confirmed["schema"] == "foundation-epoch230-first-7871-full-poh-verified-v1"
            && confirmed["archive_path"] == terminal["archive"]["path"]
            && confirmed["archive_sha256"] == ARCHIVE_SHA
            && confirmed["producer_exit_status"] == 0
            && confirmed["full_poh_verified"] == true
            && confirmed["first_slot"] == terminal["first_slot"]
            && confirmed["last_slot"] == terminal["last_slot"]
            && confirmed["terminal_blockhash"] == terminal["checkpoint"]["last_blockhash"],
        "epoch 230 closed segment lacks independent full PoH verification"
    );
    let next: Value = read_bound(
        Path::new("/var/lib/jetstreamer/horizon230-adjacent-99445304-runtime-v1/profile.json"),
        "d01cf1c1a583c41e885ea74f57aea21a5e5178554e94bca16d01674a5bff1d1b",
        JSON_LIMIT,
    )?;
    ensure!(
        next["first_slot"] == 99_445_305
            && next["readonly_bindings"]
                .as_array()
                .is_some_and(|rows| rows.len() == 4
                    && rows
                        .iter()
                        .all(|row| row["path"].as_str().is_some_and(|p| Path::new(p) != path))),
        "the adjacent replay still needs this bootstrap"
    );
    let archive = Path::new(
        terminal["archive"]["path"]
            .as_str()
            .context("archive path")?,
    );
    let archive_state = || -> Result<()> {
        let meta = open_regular(archive)?.metadata()?;
        let original = &terminal["archive"]["identity"];
        ensure!(
            original["device"] == meta.dev()
                && original["inode"] == meta.ino()
                && original["length"] == meta.len()
                && original["modified_seconds"] == meta.mtime()
                && original["modified_nanoseconds"] == meta.mtime_nsec()
                && original["changed_seconds"] == meta.ctime()
                && original["changed_nanoseconds"] == meta.ctime_nsec(),
            "epoch 230 retained archive changed after verification"
        );
        Ok(())
    };
    archive_state()?;
    let observe = || -> Result<(Value, Value)> {
        terminal_unit("horizon-230-middle-hourly-first-protective-v1.timer")?;
        terminal_unit("horizon-230-first-7871-protective-v1.timer")?;
        assert_no_nested_mount(&path)?;
        let fragment = Path::new("/run/systemd/transient").join(HISTORICAL);
        if fragment.try_exists()? {
            let mut recipe = open_regular(&fragment)?;
            let snapshot = recipe.metadata()?;
            ensure!(
                snapshot.uid() == 0
                    && snapshot.mode() & 0o022 == 0
                    && digest(&mut recipe)? == HISTORICAL_UNIT_SHA
                    && identity(&snapshot) == identity(&fragment.symlink_metadata()?),
                "the stopped epoch 230 reader definition changed"
            );
        }
        let report = no_readers(
            Path::new(CACHE),
            &path,
            &[(
                HISTORICAL,
                "763d461014f042f7bc4591a3b8ec9ac5",
                StoppedReference::Direct(
                    "2958a5fdab5e30753652da911a1a4eb925eb2da9539ebda8bcfd037cfc3cd90e",
                ),
            )],
        )?;
        Ok((report["scheduled"].clone(), report["processes"].clone()))
    };
    let context = json!({"source":path,"source_sha256":SHA,"terminal_sha256":TERMINAL_SHA,
        "verified_archive_sha256":playback.sha256,"restore_sha256":RESTORE_SHA,
        "tool_sha256":self_sha,"generation":object});
    evict_cache(
        BoundCache {
            apply,
            state,
            path: &path,
            size: SIZE,
            owner: 1000,
            sha: SHA,
            restore: &restore,
            proof: &proof,
            metadata_sha,
            context,
        },
        observe,
        archive_state,
    )
}
