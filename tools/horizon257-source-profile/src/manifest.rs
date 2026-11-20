use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub const FINGERPRINT: &str =
    "sha256:1db8722474c1b2b30d08c6956767d25bf7ee52e88bf43cb3d73b004eb622ea14";

fn object(v: &Value, slot: u64, generation: u64, hash: &str, size: u64) -> Result<()> {
    let uri = format!("gs://mainnet-beta-ledger-us-ny5/{slot}/snapshot-{slot}-{hash}.tar.zst");
    ensure!(
        v["generation"] == generation
            && v["slot"] == slot
            && v["anchor_slot"] == slot
            && v["accounts_hash"] == hash
            && v["size"] == size
            && v["source"] == "root"
            && v["uri"] == uri
            && v["versioned_uri"] == format!("{uri}#{generation}"),
        "root snapshot identity or GCS generation differs"
    );
    Ok(())
}

pub fn validate(v: &Value) -> Result<Value> {
    singleton(
        v,
        257,
        FINGERPRINT,
        (
            111022755,
            1639569360423179,
            "8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3",
            15020667485,
        ),
        (
            111455524,
            1640034318698892,
            "EKfxe81ej53cPZXptcBTgvJLQwSZ3k4nqdaxyUGTRYCw",
            15200618734,
        ),
    )
}
pub fn validate261(v: &Value) -> Result<Value> {
    singleton(
        v,
        261,
        "sha256:c5667ace6837b1f039bad3c4f66937ecad4f5d4596bb491ee5070292b59d7919",
        (
            112751208,
            1640541082024797,
            "Hgio4phsEt74AkKo6KdVmFzDoK35yS3fUkF6u3RkhSut",
            15435685203,
        ),
        (
            113182967,
            1640768983113907,
            "39EumnbfaaQdkf2ZMjL1uvVR9T9HcmE1RUP1xeCfpXVU",
            15858223025,
        ),
    )
}
fn singleton(
    v: &Value,
    epoch: u64,
    fingerprint: &str,
    b: (u64, u64, &str, u64),
    k: (u64, u64, &str, u64),
) -> Result<Value> {
    let m = &v["manifest"];
    ensure!(
        v["manifest_fingerprint"] == fingerprint
            && m["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && m["epoch_slots"] == 432000
            && m["first_epoch"] == epoch
            && m["last_epoch"] == epoch
            && m["publication_boundary_epoch"] == epoch,
        "singleton manifest identity"
    );
    ensure!(
        m["epochs"].as_array().is_some_and(|a| a.len() == 1)
            && m["verification_cohorts"]
                .as_array()
                .is_some_and(|a| a.len() == 1),
        "singleton membership"
    );
    let e = &m["epochs"][0];
    let c = &m["verification_cohorts"][0];
    ensure!(
        e["epoch"] == epoch
            && c["first_epoch"] == epoch
            && c["last_epoch"] == epoch
            && e["runtime"] == "solana-v1.7.15"
            && c["runtime"] == e["runtime"],
        "singleton runtime"
    );
    ensure!(
        e["bootstrap"] == c["bootstrap"]
            && e["post_bootstrap_root_checkpoints"] == c["root_checkpoints"]
            && c["root_checkpoints"]
                .as_array()
                .is_some_and(|a| a.len() == 1),
        "root bindings disagree"
    );
    let bootstrap = &e["bootstrap"];
    let checkpoint = &c["root_checkpoints"][0];
    object(bootstrap, b.0, b.1, b.2, b.3)?;
    object(checkpoint, k.0, k.1, k.2, k.3)?;
    Ok(
        json!({"manifest_fingerprint":fingerprint,"runtime":e["runtime"],"bootstrap":bootstrap,"final_checkpoint":checkpoint,"snapshot_bodies_checked":false}),
    )
}
