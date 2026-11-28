//! Reconstitute only the native gap records needed inside epoch 140's output suffix.
//! The following 141 gap and canonical root remain outside this input.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
#[path = "epoch140_suffix_warmup.rs"]
mod warmup;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use jetstreamer_utils::{
    horizon_legacy_bundle::{OriginalBundleIndex, OriginalSlotIndex, POH_COMPLETION_SHA256},
    horizon_legacy_entry::decode_v1_4_25_padded_wire_entries,
    horizon_legacy_shred::{assemble_v1_4_25_padded_batches, decode_v1_4_25_complete_slot_meta},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const CUT: u64 = 60_911_751;
const END: u64 = 60_911_999;
const ROOT: u64 = 61_328_765;
const SIZE: u64 = 6_730_171;
const OUTPUT_PARENT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch140-suffix-gap-input-20261121-v1";
const PROTECTION: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch199-delivery-recovery-20261121-v1/ORIGINAL140_PROTECTED_PREFIX_INPUT_AND_EXACT_VERIFIERS.json";
const PROTECTION_SHA: &str = "b81aa9d38775e3a73662108d8ddb4056ea2947d77a644fe75022f5f48d5cd8ec";
const NATIVE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-complete-20261020-v1/native.json";
const NATIVE_SHA: &str = "53f1aa88f8f5f24aed1e291ff02318c102fac3bfb8ececf5c215c9fb70c11b20";
const EDGE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-cut-inspection-complete-20261020-v1/cut.json";
const EDGE_SHA: &str = "dc4135977d89875b13f365a7888e38ed7fb627fd0c5bcb952c43dcccd3c45fcc";
const ROOTS: &str = "/usr/local/lib/jetstreamer/deploy-epochs136-147-target4-20261011-v2/preflight-136-147-target4-v4.json";
const ROOTS_SHA: &str = "ec62e2ce730a28033e5626e7afdb59c2b6e73a2ce188ae1040a77a7a09e396c3";
const INDEX: &str =
    "/home/sol/.jetstreamer-private/epoch141-original-bundle-20261023-v1/index.json";
const INDEX_SHA: &str = "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3";
const COMPLETE: &str =
    "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/completion.json";
const TARGETS: &str =
    "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/targets";
const RAW: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/target-acquisitions";
const RESPONSE: &str =
    "/var/lib/jetstreamer/horizon-epoch141-source-equivalence-20261023-v1/response.json";
const RESPONSE_SHA: &str = "d5b39bce230ee7b23da9b245c9d274ee59279fa6566b477958ddb4ef909c9f11";

fn read_json(path: &Path, sha: &str, limit: u64) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        path, sha, limit, false,
    )?)?)
}

fn str_field<'a>(obj: &'a Value, key: &str) -> Result<&'a str> {
    obj[key].as_str().with_context(|| format!("missing {key}"))
}

fn value(record: &Value, family: &str, key: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        record["family"] == family && record["key_base64"] == STANDARD.encode(key),
        "wrong native family or key"
    );
    Ok(STANDARD.decode(str_field(record, "value_base64")?)?)
}

fn verified_rpc(bytes: &[u8], slot: u64, parent: u64, anchors: &Value) -> Result<Vec<Vec<u8>>> {
    let rpc: Value = serde_json::from_slice(bytes)?;
    let block = &rpc["result"];
    ensure!(
        rpc["jsonrpc"] == "2.0"
            && rpc["id"] == slot
            && rpc.get("error").is_none()
            && block["parentSlot"] == parent
            && block["blockhash"] == anchors["final_poh_hash"]
            && block["previousBlockhash"] == anchors["previous_poh_hash"],
        "independent block identity differs"
    );
    let txs = block["transactions"]
        .as_array()
        .context("missing RPC transactions")?;
    ensure!(txs.len() <= 65_536, "oversized RPC list");
    txs.iter()
        .map(|tx| {
            let pair = tx["transaction"].as_array().context("missing wire tuple")?;
            ensure!(
                tx["version"] == "legacy" && pair.len() == 2 && pair[1] == "base64",
                "invalid legacy wire tuple"
            );
            let text = pair[0].as_str().context("missing wire bytes")?;
            ensure!(text.len() <= 1644, "oversized base64");
            let wire = STANDARD.decode(text)?;
            ensure!(
                !wire.is_empty() && wire.len() <= 1232 && STANDARD.encode(&wire) == text,
                "invalid legacy wire bytes"
            );
            Ok(wire)
        })
        .collect()
}

fn rebuild(
    row: &OriginalSlotIndex,
    raw: &Value,
    target: &Value,
    independent: Option<&[Vec<u8>]>,
) -> Result<(Vec<u8>, Value)> {
    let (slot, parent) = (row.slot, row.parent_slot);
    let o = &raw["outcome"];
    let a = &target["finalized_metadata"];
    ensure!(
        raw["slot"] == slot
            && raw["parent_slot"] == parent
            && o["status"] == "raw-acquired"
            && target["slot"] == slot
            && target["parent_slot"] == parent
            && target["diagnostic_passed"] == true
            && a["slot"] == slot
            && a["parent_slot"] == parent,
        "crossed native or finalized record"
    );
    let meta = &o["first_metadata"][0];
    let records = o["records"].as_array().context("missing native records")?;
    ensure!(records.first() == Some(meta), "SlotMeta recheck differs");
    let meta =
        decode_v1_4_25_complete_slot_meta(&value(meta, "meta", &slot.to_be_bytes())?, slot, parent)
            .map_err(anyhow::Error::msg)?;
    let count = usize::try_from(meta.last_index)? + 1;
    ensure!(
        count <= 65_528
            && records.len() == count + 8
            && o["summary"]["expected_data_shreds"] == count,
        "incomplete shred count"
    );
    let shreds = (0..count)
        .map(|i| {
            let mut key = [0u8; 16];
            key[..8].copy_from_slice(&slot.to_be_bytes());
            key[8..].copy_from_slice(&(i as u64).to_be_bytes());
            value(&records[8 + i], "data_shred", &key)
        })
        .collect::<Result<Vec<_>>>()?;
    let batches = assemble_v1_4_25_padded_batches(
        slot,
        parent,
        meta.last_index,
        &shreds.iter().map(Vec::as_slice).collect::<Vec<_>>(),
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        batches.len() == row.batch_count as usize
            && batches
                .iter()
                .map(|b| b.last_index)
                .eq(meta.completed_data_indexes),
        "wrong complete batch endpoints"
    );
    let mut record = row.batch_count.to_le_bytes().to_vec();
    let mut wire = Sha256::new();
    wire.update(b"jetstreamer-epoch140-original-wire-sequence-v1\0");
    wire.update(slot.to_le_bytes());
    let (mut entries, mut ticks, mut transactions) = (0usize, 0usize, 0usize);
    let mut last = None;
    for batch in batches {
        record.extend_from_slice(&u32::try_from(batch.bytes.len())?.to_le_bytes());
        record.extend_from_slice(&batch.bytes);
        for entry in decode_v1_4_25_padded_wire_entries(&batch.bytes)
            .map_err(anyhow::Error::msg)?
            .entries
        {
            entries += 1;
            if entry.transactions.is_empty() {
                ticks += 1;
            }
            last = Some(entry.metadata.hash);
            for tx in entry.transactions {
                if let Some(expected) = independent {
                    ensure!(
                        expected.get(transactions).map(Vec::as_slice) == Some(tx),
                        "independent transaction differs at slot {slot}, index {transactions}"
                    );
                }
                wire.update(u32::try_from(tx.len())?.to_le_bytes());
                wire.update(tx);
                transactions += 1;
            }
        }
    }
    ensure!(
        independent.is_none_or(|src| src.len() == transactions),
        "independent source transaction count differs"
    );
    let observations = &target["diagnostic"]["byte_observations"];
    let final_hash = last.context("missing final entry")?;
    ensure!(
        ticks as u64 == (slot - parent) * 64
            && observations["entries"] == entries
            && observations["transactions"] == transactions
            && bs58::encode(final_hash).into_string() == a["final_poh_hash"]
            && record.len() as u64 == row.length
            && evidence::sha(&record) == row.sha256,
        "reconstructed record differs from independently bound entry index or PoH target"
    );
    wire.update((transactions as u64).to_le_bytes());
    Ok((
        record,
        json!({"record":row,"entries":entries,"ticks":ticks,"transactions":transactions,"wire_sequence_sha256":format!("{:x}",wire.finalize()),
        "independent_rpc_transactions_compared":independent.is_some(),"finalized_anchors":a}),
    ))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    ensure!(
        args.len() == 1 && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch140-suffix-gap-input NEW_PRIVATE_OUTPUT"
    );
    let out = PathBuf::from(&args[0]);
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        iid.len() == 32
            && evidence::is_sha(&iid.repeat(2))
            && out == Path::new(OUTPUT_PARENT).join(&iid)
            && out.canonicalize()? == out
            && fs::metadata(&out)?.uid() == 0
            && fs::metadata(&out)?.mode() & 0o077 == 0
            && fs::read_dir(&out)?.next().is_none(),
        "new private invocation directory required"
    );
    let protection = read_json(Path::new(PROTECTION), PROTECTION_SHA, 64 << 10)?;
    let native = read_json(Path::new(NATIVE), NATIVE_SHA, 64 << 10)?;
    ensure!(
        protection["source_identity"]["bytes"] == 103138915297u64
            && native["native_result"]["native_checkpoint"]["slot"] == CUT
            && native["native_result"]["native_checkpoint"]["write_count"] == 0
            && native["replay_entries_sent"] == 0,
        "wrong original source or cut"
    );
    let edge = read_json(Path::new(EDGE), EDGE_SHA, 64 << 10)?;
    let cut = &edge["epoch140"]["inspected_slot"];
    let checkpoint = &native["native_result"]["native_checkpoint"];
    ensure!(
        edge["epoch140"]["whole_source_sha256"] == protection["original_whole_digest"]
            && cut["slot"] == CUT
            && cut["observed_blockhash"] == checkpoint["last_blockhash"]
            && cut["observed_next_write_version"] == native["original_producer_cursor"]
            && checkpoint["next_write_version"] == 28_087_370_409u64
            && native["original_producer_cursor"] == 28_029_693_043u64,
        "restored cut and retained raw cursor disagree with the recorded independent evidence"
    );
    let roots = read_json(Path::new(ROOTS), ROOTS_SHA, 4 << 20)?;
    let root = &roots["manifest"]["epochs"]
        .as_array()
        .context("missing epoch plans")?
        .iter()
        .find(|plan| plan["epoch"] == 141)
        .context("epoch 141 missing")?["post_bootstrap_root_checkpoints"][0];
    ensure!(
        root["slot"] == ROOT
            && root["source"] == "root"
            && root["generation"] == 1_634_786_682_225_857u64
            && root["accounts_hash"] == "8LfMXtdKmPEvMcBzEz2XZ56HZ8pUPGSaWGA6mYG4dAFY",
        "wrong post-cut root obligation"
    );
    let index: OriginalBundleIndex = serde_json::from_slice(&evidence::bound_file(
        Path::new(INDEX),
        INDEX_SHA,
        8 << 20,
        false,
    )?)?;
    index.validate().map_err(anyhow::Error::msg)?;
    let targets = read_json(Path::new(COMPLETE), POH_COMPLETION_SHA256, 4 << 20)?;
    let targets = targets["target_receipts"]
        .as_array()
        .context("missing PoH targets")?;
    let count = index.slots.partition_point(|s| s.slot <= END);
    ensure!(
        targets.len() == index.slots.len()
            && count == 10
            && index.slots[count].parent_slot == END
            && index.slots[count].slot == END + 5
            && index.scope_first_slot == CUT
            && index.scope_last_slot == ROOT
            && index.slots[count].offset == SIZE,
        "gap scope or cross-epoch witness differs"
    );
    let first_rpc = read_json(Path::new(RESPONSE), RESPONSE_SHA, 2 << 20)?;
    let first_rpc = STANDARD.decode(str_field(&first_rpc, "raw_base64")?)?;
    let data_path = out.join("suffix-gap-entries.data");
    let mut data = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&data_path)?;
    let mut rows = Vec::new();
    let mut whole = Sha256::new();
    for (row, bound) in index.slots[..count].iter().zip(targets) {
        let target_path = Path::new(TARGETS).join(format!("slot-{}.json", row.slot));
        ensure!(
            bound["path"].as_str() == target_path.to_str(),
            "wrong target path"
        );
        let target = read_json(&target_path, str_field(bound, "sha256")?, 1 << 20)?;
        let raw_bound = &target["raw_target"];
        let raw_path = Path::new(RAW).join(format!("slot-{}.json", row.slot));
        ensure!(
            raw_bound["path"].as_str() == raw_path.to_str(),
            "wrong native path"
        );
        let raw = read_json(&raw_path, str_field(raw_bound, "sha256")?, 4 << 20)?;
        let rpc = (row.slot == index.slots[0].slot)
            .then(|| {
                verified_rpc(
                    &first_rpc,
                    row.slot,
                    row.parent_slot,
                    &target["finalized_metadata"],
                )
            })
            .transpose()?;
        let (record, mut observed) = rebuild(row, &raw, &target, rpc.as_deref())?;
        observed["poh_target"] = bound.clone();
        observed["raw_target"] = raw_bound.clone();
        data.write_all(&record)?;
        whole.update(&record);
        rows.push(observed);
    }
    data.sync_all()?;
    drop(data);
    let mut data = File::open(&data_path)?;
    ensure!(data.metadata()?.len() == SIZE, "wrong reconstructed extent");
    for row in &index.slots[..count] {
        let mut record = vec![0; usize::try_from(row.length)?];
        data.read_exact(&mut record)?;
        ensure!(
            evidence::sha(&record) == row.sha256,
            "independent record reread differs"
        );
    }
    let next = &index.slots[count];
    let next_path = Path::new(TARGETS).join(format!("slot-{}.json", next.slot));
    ensure!(
        targets[count]["path"].as_str() == next_path.to_str(),
        "wrong successor gap path"
    );
    let neighbor = read_json(&next_path, str_field(&targets[count], "sha256")?, 1 << 20)?;
    ensure!(
        neighbor["diagnostic_passed"] == true
            && neighbor["finalized_metadata"]["parent_slot"] == END
            && neighbor["finalized_metadata"]["previous_poh_hash"]
                == edge["epoch140"]["observed_terminal_blockhash"],
        "finalized successor differs from epoch end"
    );
    let restarts = warmup::qualify(
        &rows,
        &native,
        &edge["epoch140"],
        &neighbor["finalized_metadata"],
    )?;
    let receipt = json!({"schema":"jetstreamer-epoch140-suffix-gap-input-v1","invocation_id":iid,"protected_original_sha256":PROTECTION_SHA,
        "native_cut_receipt_sha256":NATIVE_SHA,"native_cut":native["native_result"]["native_checkpoint"],
        "cut_archive_observation_sha256":EDGE_SHA,"post_cut_root_manifest_sha256":ROOTS_SHA,"post_cut_root":root,"original_raw_cursor":native["original_producer_cursor"],"original_full_index_sha256":INDEX_SHA,"complete_poh_receipt_sha256":POH_COMPLETION_SHA256,
        "output_first_slot":CUT+1,"output_last_slot":END,"required_post_cut_root_slot":ROOT,"remaining_gap_targets_after_output":index.slots.len()-count,
        "historical_warmup_restarts":restarts,"first_following_gap_finalized_metadata":neighbor["finalized_metadata"],"first_following_gap_target":targets[count],"first_following_gap":index.slots[count],"gap_records":rows,"data":{"path":data_path,"bytes":SIZE,"sha256":format!("{:x}",whole.finalize())},
        "independent_rpc_response_receipt_sha256":RESPONSE_SHA,"all_record_digests_reread":true,"selected_prefix_verified":false,"new_recording_worker_executed":false,"historical_warmup_recorded_epoch140_archive":false,
        "cached_finalized_rpc_sequences_reread":1,"historical_runtime_source_comparisons":2*count,"canonical_root_matched":false,"assembly_authorized":false,"publication_authorized":false});
    evidence::write_receipt(&out.join("suffix-gap-input.json"), &receipt)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_values_bind_the_column_family_and_entire_composite_key() {
        let key = [4; 16];
        let record =
            json!({"family":"data_shred","key_base64":STANDARD.encode(key),"value_base64":"AQ=="});
        assert_eq!(value(&record, "data_shred", &key).unwrap(), [1]);
        assert!(value(&record, "meta", &key).is_err());
        assert!(value(&record, "data_shred", &[4; 8]).is_err());
        assert!(value(&record, "data_shred", &[5; 16]).is_err());
    }

    #[test]
    fn independent_response_must_bind_both_hashes_parent_and_legacy_wire() {
        let anchors = json!({"final_poh_hash":"next","previous_poh_hash":"prev"});
        let block = json!({"jsonrpc":"2.0","id":17,"result":{"parentSlot":11,
            "previousBlockhash":"prev","blockhash":"next","transactions":[
            {"version":"legacy","transaction":["AQ==","base64"]}]}});
        let compare = |v: &Value| verified_rpc(&serde_json::to_vec(v).unwrap(), 17, 11, &anchors);
        assert_eq!(compare(&block).unwrap(), vec![vec![1]]);
        for (pointer, replacement) in [
            ("/id", json!(11)),
            ("/result/parentSlot", json!(12)),
            ("/result/blockhash", json!("prev")),
            ("/result/previousBlockhash", json!("other")),
            ("/result/transactions/0/version", json!(0)),
            ("/result/transactions/0/transaction/1", json!("base58")),
            ("/result/transactions/0/transaction/0", json!("")),
        ] {
            let mut bad = block.clone();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(compare(&bad).is_err(), "{pointer}");
        }
    }
}
