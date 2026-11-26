use super::*;

const OLD: &str = "/usr/local/lib/jetstreamer/deploy-epoch186-singleton-20261020-v1";
const OLD_SEAL: &str = "e70206a82a0c47b4e9def3c9814d1f351d591a72bb71666a977406dc03ada23b";
const NODE_DEPLOYMENT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-local-index-successor-20261121-v1/deployment";
const NODE_SEAL: &str = "f78d66c9d4a12f58d4f6551ef8d1bce330bbb2c35b89beb2b80c98ad750a9410";
pub const NODE_SHA: &str = "6b0f3089c1c1108dbbbea76a06625d3b285de647f83b50791ead121e1af81699";
pub const NODE_BYTES: u64 = 65_296_952;
const WORKER: &str = "jetstreamer-historical-worker-v1-6-15";
pub const WORKER_SHA: &str = "9339aa0ee5c39e91ec446bfa561c0e81280a0ddc474a03cf5bb0ce07a3674893";
pub const WORKER_BYTES: u64 = 8_961_328;
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const MANIFEST: &str = "preflight-186-singleton-v4.json";
const MANIFEST_SHA: &str = "58c38fb8e6b6f4adce290cccfe8922613a6cffda5cb3eb320de424438e11d47e";
const FINGERPRINT: &str = "sha256:08f4c224485297f5468d2a3d43bb5e73bbd9993c873d949c2f62de41d2a7029d";
const BOOTSTRAP: &str = "snapshot-80351283-Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8.tar.zst";
const BOOTSTRAP_SHA: &str = "2b128e27dce19d7df54cbcdba52e9fc6e6897fcdce288d05369c41e9382b5112";
const BOOTSTRAP_BYTES: u64 = 7_316_986_109;
const BOOTSTRAP_SLOT: u64 = 80_351_283;
const CHECKPOINT: &str = "snapshot-80783539-EWu2G86akFM3CKJ8D4YZzi8ASZeaPKm2WXLG239Zjnj9.tar.zst";
const HASH_PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch186-capped-inputs-20261023-v1";
const HASH_PACKAGE_SHA: &str = "743fc065e54c6e1256b83d3025eb0823ad7e184ca5f402ec4357c9e20cf40de1";
const HASH_FILE: &str = "epoch-hashes-186.txt";
const HASH_FILE_SHA: &str = "71df68fa46e108d9a9ae905654796ca73255a058e662578accb1695ea44932c4";
const TABLE_PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/car-slot-ranges-186-20261125-v1";
const TABLE_SEAL: &str = "9655a04b1f023341080936d8e8e9dede27aed5251e8534c2f40c544e8d000c6c";
const TABLE: &str = "epoch-186-slot-ranges.repaired.raw";
const TABLE_SHA: &str = "33a7a0c30eb1a5ca0f98d726f424886a03336fbdeb10a889460128536308c3c4";
const OVERRIDE_SHA: &str = "82b844bb8b02f1d5140351962e8e5936eba6be75dec0da04a6e7ec3f69efcf44";
const OVERRIDE_DIR: &str = "/run/horizon-car-slot-ranges-186";
const TRANSPORT: &str = "/home/sol/.jetstreamer-private/epoch186-worker-transport-20261125.vNDlHWHQ/WORKER_SOURCE_TRANSPORT_QUALIFIED.json";
const TRANSPORT_SHA: &str = "0738a7895f688b32f9d53b6f8ee76c7154256029d33bbe230d0f1e4dd1fc7053";
const VIEW: &str = "/run/horizon-epoch186-bounded-source";
pub const NODE_VIEW: &str = "/run/horizon-epoch186-bounded-source/jetstreamer-node";
pub const NODE_IMAGE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch167-local-index-successor-20261121-v1/deployment/jetstreamer-node";

pub fn argv() -> Vec<String> {
    vec![
        NODE_VIEW.to_owned(),
        EPOCH.to_string(),
        format!("{ROOT}/ledger"),
        "--verify".to_owned(),
        format!("--qualification-end-slot={END_SLOT}"),
        format!("--snapshot-archive={VIEW}/{BOOTSTRAP}"),
        format!("--epoch-hashes={VIEW}/{HASH_FILE}"),
        format!("--horizon-output={ROOT}/private/epoch-186-bounded.jet"),
    ]
}

pub fn environment() -> Value {
    json!({
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_15":format!("{VIEW}/{WORKER}"),
        "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST":format!("{OVERRIDE_DIR}/manifest.json"),
        "JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256":OVERRIDE_SHA,
        "JETSTREAMER_ALLOW_CANDIDATE_RUNTIME":"1",
        "JETSTREAMER_PRIVATE_RUN_ROOT":format!("{ROOT}/private"),
        "TMPDIR":format!("{ROOT}/tmp"),
        "SOLANA_RAYON_THREADS":"8","RAYON_NUM_THREADS":"8","JETSTREAMER_REPLAY_THREADS":"8"
    })
}

pub fn adopted_bindings() -> [(String, String); 7] {
    [
        (NODE_IMAGE.to_owned(), NODE_VIEW.to_owned()),
        (format!("{OLD}/{WORKER}"), format!("{VIEW}/{WORKER}")),
        (format!("{OLD}/{BOOTSTRAP}"), format!("{VIEW}/{BOOTSTRAP}")),
        (
            format!("{OLD}/genesis.tar.bz2"),
            format!("{ROOT}/ledger/genesis.tar.bz2"),
        ),
        (
            format!("{HASH_PACKAGE}/{HASH_FILE}"),
            format!("{VIEW}/{HASH_FILE}"),
        ),
        (
            format!("{TABLE_PACKAGE}/manifest.json"),
            format!("{OVERRIDE_DIR}/manifest.json"),
        ),
        (
            format!("{TABLE_PACKAGE}/{TABLE}"),
            format!("{OVERRIDE_DIR}/{TABLE}"),
        ),
    ]
}

fn check_manifest(doc: &Value) -> Result<(Value, Value)> {
    let epoch = &doc["manifest"];
    let cohorts = epoch["verification_cohorts"]
        .as_array()
        .context("missing verification cohorts")?;
    ensure!(
        doc["manifest_fingerprint"] == FINGERPRINT
            && epoch["first_epoch"] == EPOCH
            && epoch["last_epoch"] == EPOCH
            && cohorts.len() == 1,
        "different epoch 186 cohort"
    );
    let roots = cohorts[0]["root_checkpoints"]
        .as_array()
        .context("missing checkpoint")?;
    let boot = &cohorts[0]["bootstrap"];
    ensure!(
        cohorts[0]["runtime"] == "solana-v1.6.15"
            && roots.len() == 1
            && boot["slot"] == BOOTSTRAP_SLOT
            && boot["generation"] == 1_634_788_465_979_613_u64
            && boot["size"] == BOOTSTRAP_BYTES
            && text(boot, "uri")?.ends_with(&format!("/{BOOTSTRAP}"))
            && roots[0]["slot"] == END_SLOT
            && roots[0]["anchor_slot"] == END_SLOT
            && roots[0]["generation"] == 1_634_788_585_189_220_u64
            && text(&roots[0], "uri")?.ends_with(&format!("/{CHECKPOINT}")),
        "different epoch 186 bootstrap or checkpoint generation"
    );
    Ok((boot.clone(), roots[0].clone()))
}

pub fn inspect(rehash_bootstrap: bool) -> Result<Value> {
    let old = Path::new(OLD);
    let old_seal = seal(old, OLD_SEAL)?;
    let node_dir = Path::new(NODE_DEPLOYMENT);
    let node_seal = seal(node_dir, NODE_SEAL)?;
    let node = node_dir.join("jetstreamer-node");
    let worker = old.join(WORKER);
    let genesis = old.join("genesis.tar.bz2");
    let manifest = old.join(MANIFEST);
    let snapshot = old.join(BOOTSTRAP);

    seal_member(&node_seal, "jetstreamer-node", NODE_SHA, NODE_BYTES, "0555")?;
    seal_member(&old_seal, WORKER, WORKER_SHA, WORKER_BYTES, "0555")?;
    seal_member(&old_seal, "genesis.tar.bz2", GENESIS_SHA, 20_144, "0444")?;
    seal_member(&old_seal, MANIFEST, MANIFEST_SHA, 11_721, "0444")?;
    seal_member(&old_seal, BOOTSTRAP, BOOTSTRAP_SHA, BOOTSTRAP_BYTES, "0444")?;
    verify_file(&node, NODE_SHA, NODE_BYTES, 0o555)?;
    verify_file(&worker, WORKER_SHA, WORKER_BYTES, 0o555)?;
    verify_file(&genesis, GENESIS_SHA, 20_144, 0o444)?;
    let (boot, checkpoint) = check_manifest(&document(&manifest, MANIFEST_SHA, 0o444)?)?;

    let (mut boot_file, boot_m) = open_root_file(&snapshot, 0o444)?;
    ensure!(
        (boot_m.dev(), boot_m.ino(), boot_m.len()) == (2304, 6_164_008, BOOTSTRAP_BYTES)
            && boot_m.mtime() == 1_792_467_038
            && boot_m.mtime_nsec() == 521_077_026
            && boot_m.ctime() == boot_m.mtime()
            && boot_m.ctime_nsec() == boot_m.mtime_nsec(),
        "retained epoch 186 bootstrap inode changed"
    );
    if rehash_bootstrap {
        ensure!(
            hash(&mut boot_file)? == BOOTSTRAP_SHA,
            "retained bootstrap digest changed"
        );
    }
    stable(&snapshot, &boot_file, &boot_m)?;

    let hashes_dir = Path::new(HASH_PACKAGE);
    let hashes_seal = seal(hashes_dir, HASH_PACKAGE_SHA)?;
    seal_member(&hashes_seal, HASH_FILE, HASH_FILE_SHA, 142, "0444")?;
    let hashes = hashes_dir.join(HASH_FILE);
    verify_file(&hashes, HASH_FILE_SHA, 142, 0o444)?;

    let table_dir = Path::new(TABLE_PACKAGE);
    let table_seal = seal(table_dir, TABLE_SEAL)?;
    seal_member(&table_seal, TABLE, TABLE_SHA, 5_184_000, "0444")?;
    seal_member(&table_seal, "manifest.json", OVERRIDE_SHA, 281, "0444")?;
    verify_file(&table_dir.join(TABLE), TABLE_SHA, 5_184_000, 0o444)?;
    let override_manifest = table_dir.join("manifest.json");
    let override_config = document(&override_manifest, OVERRIDE_SHA, 0o444)?;
    ensure!(
        override_config
            == json!({"schema":"jetstreamer-local-slot-ranges-overrides-v1",
            "entries":[{"epoch":EPOCH,"path":format!("{OVERRIDE_DIR}/{TABLE}"),"sha256":TABLE_SHA}]}),
        "epoch 186 override projects a different table"
    );
    let transport = document(Path::new(TRANSPORT), TRANSPORT_SHA, 0o444)?;
    ensure!(
        transport["candidate_node"] == binding(&node, NODE_SHA)
            && transport["candidate_worker"] == binding(&worker, WORKER_SHA)
            && transport["override_manifest"] == binding(&override_manifest, OVERRIDE_SHA)
            && transport["index_mount"] == OVERRIDE_DIR
            && transport["stage_run"] == json!(["boundary", "repaired-seek", "warmup"])
            && transport["full_epoch_source_claimed"] == false
            && transport["historical_worker_started"] == false
            && transport["admission_authorized"] == false,
        "different epoch 186 source transport qualification"
    );
    let guard = guard::verify_image()?;

    Ok(json!({
        "schema":"horizon-epoch186-bounded-source-entry-v1", "epoch":EPOCH,
        "source_commit":transport["candidate_source_commit"],
        "node":binding(node,NODE_SHA), "worker":binding(worker,WORKER_SHA),
        "genesis":binding(genesis,GENESIS_SHA), "bootstrap":binding(snapshot,BOOTSTRAP_SHA),
        "bootstrap_metadata":boot, "bootstrap_bytes_rehashed":rehash_bootstrap,
        "cohort_manifest":binding(manifest,MANIFEST_SHA), "cohort_fingerprint":FINGERPRINT,
        "trusted_checkpoint":checkpoint, "checkpoint_hashes":binding(hashes,HASH_FILE_SHA),
        "override_manifest":binding(override_manifest,OVERRIDE_SHA),
        "repaired_table":binding(table_dir.join(TABLE),TABLE_SHA),
        "transport_qualification":binding(TRANSPORT,TRANSPORT_SHA),
        "read_only_inputs":adopted_bindings().map(|(source,target)| json!({"source":source,"target":target})),
        "argv":argv(), "environment":environment(),
        "unit":UNIT,"guard_service":GUARD_UNIT,"guard_timer":TIMER,"guard":guard,"private_tree":ROOT,
        "limits":{
            "memory_max_bytes":MEMORY,"guard_memory_max_bytes":GUARD_MEMORY,
            "cpu_quota_micros":CPU,"guard_cpu_quota_micros":GUARD_CPU,
            "memory_swap_max_bytes":0,"tasks_max":TASKS,"runtime_max_seconds":RUNTIME_SECS,
            "tree_physical_stop_bytes":TREE_CAP,"tree_reservation_bytes":TREE_BOOKING,"worker_vmas":VMAS
        },
        "first_recorded_slot":FIRST_SLOT,"last_slot":END_SLOT,
        "remaining_epoch_slots":LAST_EPOCH_SLOT-END_SLOT, "whole_epoch_complete":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_the_focused_qualification_and_binds_local_indexes() {
        let argv = argv();
        assert_eq!(argv[0], NODE_VIEW);
        assert_eq!(argv[1], "186");
        assert!(argv.contains(&"--verify".to_owned()));
        assert!(argv.contains(&format!("--qualification-end-slot={END_SLOT}")));
        assert!(
            !argv
                .iter()
                .any(|arg| arg.starts_with("--root-checkpoint-cohort")
                    || arg.starts_with("--publish-through-epoch"))
        );
        assert_eq!(LAST_EPOCH_SLOT - END_SLOT, 460);
        assert_eq!(
            environment()["JETSTREAMER_SLOT_RANGES_OVERRIDE_MANIFEST_SHA256"],
            OVERRIDE_SHA
        );
    }
}
