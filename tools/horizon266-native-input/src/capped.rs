//! Reuse the original GCS generation and compare the candidate to its recorded bank.
use super::{Checkpoint, Initialized, SLOT, SNAPSHOT, WORKER_SHA, identity, read_small};
use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) const PACKET: &str =
    "/var/lib/jetstreamer/horizon266-capped-cold-inputs-v200-a2/inputs.json";
pub(crate) const PACKET_SHA: &str =
    "124212ab9f62ae6ea30998b02955a0530b2b56de3c2a1339a3b5204b6fe53a8a";
pub(crate) const INPUT_SCHEMA: &str = "horizon266-capped-worker-cold-inputs-v1";
const NODE: &str = "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node";
const NODE_SHA: &str = "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32";

pub(crate) fn measurement_verified(packet: &Value) -> bool {
    packet["bootstrap"]["generation"] == 1_641_767_242_524_970u64
        && packet["bootstrap"]["slot"] == SLOT
        && packet["snapshot"]["path"] == SNAPSHOT
        && packet["candidate"]["sha256"] == WORKER_SHA
        && packet["candidate_bootstrap_executed"] == false
        && packet["replay_admitted"] == false
}

pub(crate) fn validate_extra(packet: &Value) -> Result<()> {
    read_small(
        Path::new(
            "/var/lib/jetstreamer/horizon266-capped-cold-inputs-v200-a2/deployment-seal-receipt.json",
        ),
        "2704effc8d76cd27e1a358b8af94cd614b3e510d3419831d643014bdd61aad9b",
        16 << 10,
    )?;
    ensure!(
        packet["node"]["path"] == NODE
            && packet["node"]["sha256"] == NODE_SHA
            && packet["node"]["identity"] == identity(Path::new(NODE))?,
        "qualified producer identity changed"
    );
    Ok(())
}

pub(crate) fn match_original(
    packet: &Value,
    initial: &Initialized,
    bank: &Checkpoint,
) -> Result<()> {
    ensure!(
        packet["expected_initialized"] == json!(initial),
        "initialized state differs from the original worker"
    );
    ensure!(
        packet["expected_checkpoint"] == json!(bank),
        "bank checkpoint differs from the original worker"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InitializedSource;

    #[test]
    fn comparison_includes_bank_hash_capitalization_and_write_cursor() {
        let initial = Initialized {
            genesis_hash: "genesis".into(),
            source: InitializedSource::Genesis,
            slot: SLOT,
            last_blockhash: vec![1; 32],
            ticks_per_slot: 64,
            next_write_version: 3,
        };
        let checkpoint = Checkpoint {
            slot: SLOT,
            bank_hash: vec![2; 32],
            accounts_hash: vec![3; 32],
            last_blockhash: initial.last_blockhash.clone(),
            capitalization: 8,
            transaction_count: 5,
            tick_height: 9,
            slot_complete: true,
            writes: vec![],
            next_write_version: 3,
        };
        let packet = json!({"expected_initialized":initial,"expected_checkpoint":checkpoint});
        match_original(&packet, &initial, &checkpoint).unwrap();
        for field in [
            "bank_hash",
            "capitalization",
            "transaction_count",
            "next_write_version",
        ] {
            let mut changed = packet.clone();
            changed["expected_checkpoint"][field] = Value::Null;
            assert!(match_original(&changed, &initial, &checkpoint).is_err());
        }
        let mut changed = initial.clone();
        changed.last_blockhash.clear();
        assert!(match_original(&packet, &changed, &checkpoint).is_err());
    }
}
