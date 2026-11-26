use super::*;

const PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch186-verification-tail-inputs-20261126-v1";
const PACKAGE_SHA: &str = "6dc0f3bb84d85b295fdfe1d7e95bd7b734d5cd3b646c2eb5c462dbfc613cf465";
const RECEIPT_SHA: &str = "7fc0568fc742f6951cef18be7aa49d29605d8fb7f9c4f0bd5082364f4d3811b6";
const BOOTSTRAP: &str = "/home/sol/.jetstreamer-private/epoch186-delivery-tail-20261126.TgC4CkS9/inputs/snapshot-80783539-EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9.tar.zst";
const BOOTSTRAP_SHA: &str = "ae0762718ea638c1a9a94c6bec4bef0d341fe7272346a80cb3c72e8016589cf3";
const BOOTSTRAP_BYTES: u64 = 6_838_562_806;
const TERMINAL: u64 = 80_791_699;
const TERMINAL_NAME: &str =
    "snapshot-80791699-GWUc3stuKEJrz77BfMxZ1Ma9wYwwqH2AF8e9Amo98vwC.tar.zst";
const TERMINAL_SHA: &str = "fa39f4b5b0c6351fe22e5fcf5ab995d38b14f25c68f78d306d6a8a07bc0b5e3d";
const OVERRIDE: &str = "/run/horizon-car-slot-ranges-186-tail";
const VIEW: &str = "/run/horizon-epoch186-verification-tail";
const TAIL_ROOT: &str = "/home/sol/.jetstreamer-private/epoch186-verification-tail-20261126-v1";
const HASHES: &str = "epoch-hashes-186-tail.txt";
const HASHES_SHA: &str = "7446dafec6823a1cc10fb9c025e26ec9b9015b89f092ad7ce7d2fc801b7531f5";
const OVERRIDE_SHA: &str = "69b53f197fb93d261b9f8a319c1b6474c9f246388636a678f476a8639d242d53";
const TABLES: [(u64, &str, &str); 2] = [
    (
        186,
        "epoch-186-slot-ranges.repaired.raw",
        "33a7a0c30eb1a5ca0f98d726f424886a03336fbdeb10a889460128536308c3c4",
    ),
    (
        187,
        "epoch-187-slot-ranges.repaired.raw",
        "efc5bf0c9ead135fac3a5dc6a9d961704119cd0726b1820fe240bd12d634fdab",
    ),
];

pub fn inspect() -> Result<Value> {
    let package = Path::new(PACKAGE);
    let deployed = seal(package, PACKAGE_SHA)?;
    for (name, sha, bytes) in [
        ("TAIL_INPUTS.json", RECEIPT_SHA, 3_275),
        ("POST_EPOCH_ROOT_GCS.json", TERMINAL_SHA, 810),
        ("manifest.json", OVERRIDE_SHA, 492),
        (HASHES, HASHES_SHA, 142),
        (TABLES[0].1, TABLES[0].2, 5_184_000),
        (TABLES[1].1, TABLES[1].2, 5_184_000),
    ] {
        seal_member(&deployed, name, sha, bytes, "0444")?;
        verify_file(&package.join(name), sha, bytes, 0o444)?;
    }

    let prefix = source::inspect(false)?;
    let receipt = document(&package.join("TAIL_INPUTS.json"), RECEIPT_SHA, 0o444)?;
    let terminal = document(
        &package.join("POST_EPOCH_ROOT_GCS.json"),
        TERMINAL_SHA,
        0o444,
    )?;
    ensure!(
        receipt["schema"] == "horizon-epoch186-verification-tail-sealed-inputs-v1"
            && receipt["replay_launch_authorized"] == false
            && receipt["tail_bootstrap"]["path"] == BOOTSTRAP
            && receipt["tail_bootstrap"]["sha256"] == BOOTSTRAP_SHA
            && receipt["tail_bootstrap"]["bytes"] == BOOTSTRAP_BYTES
            && receipt["tail_bootstrap"]["slot"] == END_SLOT
            && receipt["tail_bootstrap"]["generation"]
                == prefix["trusted_checkpoint"]["generation"]
            && receipt["candidate_tail_slots"] == json!([END_SLOT + 1, LAST_EPOCH_SLOT])
            && receipt["private_verification_slots"] == json!([LAST_EPOCH_SLOT + 1, TERMINAL])
            && receipt["post_epoch_verification_checkpoint"]["slot"] == TERMINAL
            && receipt["post_epoch_verification_checkpoint"]["generation"]
                == 1_634_788_451_044_366_u64
            && terminal["bucket"] == "mainnet-beta-ledger-us-ny5"
            && terminal["name"] == format!("{END_SLOT}/hourly/{TERMINAL_NAME}")
            && terminal["generation"] == "1634788451044366",
        "different epoch 186 tail input or reference checkpoint"
    );

    let snapshot = Path::new(BOOTSTRAP);
    let (snapshot_file, snapshot_meta) = open_root_file(snapshot, 0o444)?;
    ensure!(
        snapshot_meta.dev() == number(&receipt["tail_bootstrap"], "device")?
            && snapshot_meta.ino() == number(&receipt["tail_bootstrap"], "inode")?
            && snapshot_meta.len() == BOOTSTRAP_BYTES
            && (snapshot_meta.mtime(), snapshot_meta.mtime_nsec()) == (1_795_651_405, 397_157_366)
            && (snapshot_meta.ctime(), snapshot_meta.ctime_nsec()) == (1_795_652_079, 599_318_084),
        "different retained tail snapshot identity"
    );
    stable(snapshot, &snapshot_file, &snapshot_meta)?;
    let snapshot_name = snapshot.file_name().context("missing bootstrap name")?;
    let snapshot_name = snapshot_name.to_str().context("non-UTF-8 bootstrap name")?;
    let config = document(&package.join("manifest.json"), OVERRIDE_SHA, 0o444)?;
    ensure!(
        config
            == json!({
                "schema":"jetstreamer-local-slot-ranges-overrides-v1",
                "entries": TABLES.map(|(epoch,name,sha)| json!({
                    "epoch":epoch,"path":format!("{OVERRIDE}/{name}"),"sha256":sha
                }))
            }),
        "different two-epoch slot index projection"
    );

    let node_view = format!("{VIEW}/jetstreamer-node");
    let worker_view = format!("{VIEW}/jetstreamer-historical-worker-v1-6-15");
    let snapshot_view = format!("{VIEW}/{snapshot_name}");
    let hashes_view = format!("{VIEW}/{HASHES}");
    let manifest_view = format!("{OVERRIDE}/manifest.json");
    let mut bindings = vec![
        (text(&prefix["node"], "path")?.to_owned(), node_view.clone()),
        (
            text(&prefix["worker"], "path")?.to_owned(),
            worker_view.clone(),
        ),
        (
            text(&prefix["genesis"], "path")?.to_owned(),
            format!("{TAIL_ROOT}/ledger/genesis.tar.bz2"),
        ),
        (BOOTSTRAP.to_owned(), snapshot_view.clone()),
        (format!("{PACKAGE}/{HASHES}"), hashes_view.clone()),
        (format!("{PACKAGE}/manifest.json"), manifest_view.clone()),
    ];
    bindings.extend(
        TABLES.map(|(_, name, _)| (format!("{PACKAGE}/{name}"), format!("{OVERRIDE}/{name}"))),
    );
    Ok(json!({
        "schema":"horizon-epoch186-verification-tail-source-entry-v1",
        "input_receipt":binding(package.join("TAIL_INPUTS.json"), RECEIPT_SHA),
        "node":prefix["node"], "worker":prefix["worker"], "genesis":prefix["genesis"],
        "bootstrap":receipt["tail_bootstrap"], "terminal_checkpoint_metadata":binding(package.join("POST_EPOCH_ROOT_GCS.json"), TERMINAL_SHA),
        "argv":[node_view, EPOCH.to_string(), format!("{TAIL_ROOT}/ledger"), "--verify".to_owned(),
            format!("--qualification-end-slot={TERMINAL}"), format!("--snapshot-archive={snapshot_view}"),
            format!("--epoch-hashes={hashes_view}"), format!("--horizon-output={TAIL_ROOT}/private/epoch-186-verification-tail.jet")],
        "environment":{
            "JETSTREAMER_HISTORICAL_WORKER_V1_6_15":worker_view,
            "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST":manifest_view,
            "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256":OVERRIDE_SHA,
            "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME":"1",
            "JETSTREAMER_PRIVATE_RUN_ROOT":format!("{TAIL_ROOT}/private"),
            "TMPDIR":format!("{TAIL_ROOT}/tmp")
        },
        "read_only_inputs":bindings.into_iter().map(|(source,target)| json!({
            "source":source,"target":target
        })).collect::<Vec<_>>(),
        "candidate_epoch_slots":receipt["candidate_tail_slots"],
        "private_only_verification_slots":receipt["private_verification_slots"],
        "private_tree":TAIL_ROOT,"fresh_capacity_and_guard_required":true,
        "replay_launch_authorized":false,"canonical_publication_authorized":false,"r2_mutations":false
    }))
}
