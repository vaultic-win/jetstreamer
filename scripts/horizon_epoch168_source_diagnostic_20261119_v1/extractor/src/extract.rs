//! Local source evidence only. No fetch, worker, canonical-state, or launch route.
use jetstreamer_firehose::{node::{Node, RawNode}, transaction::parse_versioned_transaction_from_slice};
use cid::Cid;
use serde_cbor::Value as Cbor;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use solana_instruction_error::InstructionError;
#[cfg(test)]
use solana_transaction_error::TransactionError;
use std::{collections::{BTreeMap, BTreeSet}, io::{Cursor, Read}, ops::Range};

pub const MAX_INPUT: usize = 256 << 20;
const MAX_FRAME: usize = 2 << 20;
const MAX_NODES: usize = 131_072;
const MAX_ENTRIES: usize = 65_536;
const MAX_TRANSACTIONS: usize = 65_536;
const MAX_TRANSACTION: usize = 1232;
const MAX_META: usize = 1 << 20;
const MAX_CONTINUATIONS: usize = 4096;

#[derive(Clone, Debug)]
pub struct Target {
    pub epoch: u64,
    pub slot: u64,
    pub entry: usize,
    pub transaction: usize,
    pub signature: String,
    pub instruction: u8,
}
impl Target {
    pub fn incident() -> Self {
        Self { epoch: 168, slot: 72_728_191, entry: 433, transaction: 532,
            signature: "3qysw2HZ4pE11jjL3HpXA9UJ6kxqPkY2se93agYERfzDNoweP6sxqvhPGPjBkmwmD2m9SrRB96y75Vbi3mACtrpz".into(), instruction: 0 }
    }
    fn validate(&self) -> Result<(), String> {
        require(self.slot / 432_000 == self.epoch, "selector epoch/slot mismatch")?;
        require(self.entry < MAX_ENTRIES && self.transaction < MAX_TRANSACTIONS,
            "selector index exceeds bound")?;
        let signature: solana_signature::Signature = self.signature.parse()
            .map_err(|e| format!("invalid selector signature: {e}"))?;
        require(signature.to_string() == self.signature, "noncanonical selector signature")
    }
}

pub struct Extraction {
    pub report: Value,
    pub members: BTreeMap<String, Vec<u8>>,
}
struct Frame {
    cid: Cid,
    wire: Range<usize>, // Includes exact CAR length prefix and CID.
    node: Node,
}
pub fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
fn require(ok: bool, reason: &str) -> Result<(), String> {
    if ok { Ok(()) } else { Err(reason.into()) }
}
fn array(v: &Cbor) -> Result<&[Cbor], String> {
    match v { Cbor::Array(a) => Ok(a), _ => Err("expected CBOR array".into()) }
}
fn unsigned(v: &Cbor) -> Result<u64, String> {
    match v { Cbor::Integer(n) => u64::try_from(*n).map_err(|_| "invalid unsigned field".into()),
        _ => Err("expected unsigned integer".into()) }
}
fn blob(v: &Cbor) -> Result<&[u8], String> {
    match v { Cbor::Bytes(b) => Ok(b), _ => Err("expected byte string".into()) }
}
fn link(v: &Cbor) -> Result<Cid, String> {
    // Normal source helper accepts CAR DAG-CBOR CID representation; keep its semantics.
    jetstreamer_firehose::node_reader::cid_from_cbor_link(v).map_err(|e| e.to_string())
}
fn links(v: &Cbor, max: usize) -> Result<(), String> {
    let a = array(v)?;
    require(a.len() <= max, "CID list exceeds bound")?;
    for item in a { link(item)?; }
    Ok(())
}
fn dataframe_shape(v: &Cbor) -> Result<(), String> {
    let a = array(v)?;
    require((5..=6).contains(&a.len()), "dataframe field count")?;
    require(unsigned(&a[0])? == 6, "dataframe kind")?;
    for field in &a[1..4] { if !matches!(field, Cbor::Null) { unsigned(field)?; } }
    require(blob(&a[4])?.len() <= MAX_META, "dataframe bytes exceed bound")?;
    if let Some(next) = a.get(5) {
        if !matches!(next, Cbor::Null) { links(next, MAX_CONTINUATIONS)?; }
    }
    Ok(())
}
fn node_shape(v: &Cbor) -> Result<(), String> {
    // Guard the normal decoder's intentionally lenient historical field defaults.
    let a = array(v)?;
    let kind = unsigned(a.first().ok_or("empty source node")?)?;
    match kind {
        0 => {
            require(a.len() == 5, "transaction field count")?;
            dataframe_shape(&a[1])?; dataframe_shape(&a[2])?;
            unsigned(&a[3])?; unsigned(&a[4])?;
        }
        1 => {
            require(a.len() == 4, "entry field count")?;
            unsigned(&a[1])?;
            require(blob(&a[2])?.len() == 32, "entry hash length")?;
            links(&a[3], MAX_TRANSACTIONS)?;
        }
        2 => {
            require(a.len() == 6, "block field count")?;
            unsigned(&a[1])?;
            require(array(&a[2])?.len() <= MAX_ENTRIES, "shredding count bound")?;
            links(&a[3], MAX_ENTRIES)?;
            let meta = array(&a[4])?;
            require((2..=5).contains(&meta.len()), "slot metadata field count")?;
            unsigned(&meta[0])?; unsigned(&meta[1])?;
            if let Some(height) = meta.get(2) {
                if !matches!(height, Cbor::Null) { unsigned(height)?; }
            }
            link(&a[5])?;
        }
        5 => {
            require(a.len() == 3, "rewards field count")?;
            unsigned(&a[1])?; dataframe_shape(&a[2])?;
        }
        6 => dataframe_shape(v)?,
        _ => return Err("only slot transaction/entry/rewards/block/dataframe nodes are accepted".into()),
    }
    Ok(())
}
fn varint(bytes: &[u8], pos: &mut usize) -> Result<usize, String> {
    let mut value = 0u64;
    for i in 0..10 {
        let b = *bytes.get(*pos).ok_or("truncated CAR varint")?;
        *pos += 1;
        require(i != 9 || b <= 1, "CAR varint overflow")?;
        value |= u64::from(b & 127) << (i * 7);
        if b & 128 == 0 {
            require(i == 0 || b != 0, "nonminimal CAR varint")?;
            return usize::try_from(value).map_err(|_| "CAR length overflow".into());
        }
    }
    Err("unterminated CAR varint".into())
}
fn section<'a>(bytes: &'a [u8], pos: &mut usize, max: usize) -> Result<&'a [u8], String> {
    let len = varint(bytes, pos)?;
    require(len > 0 && len <= max, "CAR section size bound")?;
    let end = pos.checked_add(len).ok_or("CAR offset overflow")?;
    let result = bytes.get(*pos..end).ok_or("truncated CAR section")?;
    *pos = end;
    Ok(result)
}
fn parse_car(bytes: &[u8]) -> Result<Vec<Frame>, String> {
    require(!bytes.is_empty() && bytes.len() <= MAX_INPUT, "input size bound")?;
    let mut pos = 0;
    let header = section(bytes, &mut pos, 1024)?;
    let header: Cbor = serde_cbor::from_slice(header).map_err(|e| e.to_string())?;
    let Cbor::Map(header) = header else { return Err("CAR header is not a map".into()); };
    require(header.get(&Cbor::Text("version".into())) == Some(&Cbor::Integer(1)), "CAR version differs")?;
    let roots = header.get(&Cbor::Text("roots".into())).ok_or("CAR roots absent")?;
    links(roots, 16)?;
    let mut frames = Vec::new();
    let mut seen = BTreeSet::new();
    while pos < bytes.len() {
        require(frames.len() < MAX_NODES, "source node count bound")?;
        let start = pos;
        let body = section(bytes, &mut pos, MAX_FRAME)?;
        let raw = RawNode::from_cursor(&mut Cursor::new(body.to_vec())).map_err(|e| e.to_string())?;
        raw.verify_sha256_cid().map_err(|e| e.to_string())?;
        let cid = *raw.get_cid();
        require(seen.insert(cid), "duplicate source CID")?;
        // Fixed canonical CIDv1/dag-cbor/sha256 encodes to 36 bytes.
        let cid_bytes = cid.to_bytes();
        require(body.starts_with(&cid_bytes), "noncanonical source CID encoding")?;
        let value: Cbor = serde_cbor::from_slice(&body[cid_bytes.len()..]).map_err(|e| e.to_string())?;
        node_shape(&value)?;
        let node = raw.parse().map_err(|e| e.to_string())?;
        frames.push(Frame { cid, wire: start..pos, node });
    }
    require(!frames.is_empty(), "CAR has no nodes")?;
    Ok(frames)
}

fn reassemble(first: &jetstreamer_firehose::dataframe::DataFrame,
    frames: &[Frame], by_cid: &BTreeMap<Cid, usize>, max: usize) -> Result<Vec<u8>, String> {
    let mut result = first.data.as_slice().to_vec();
    require(result.len() <= max, "reassembled frame exceeds bound")?;
    let mut next = first.next.as_deref();
    let mut seen = BTreeSet::new();
    while let Some(cids) = next {
        // Multiple sibling chains have ambiguous continuation ordering in the old helper.
        require(cids.len() <= 1, "branched dataframe requires a separately reviewed adapter")?;
        let Some(cid) = cids.first() else { break; };
        require(seen.insert(*cid) && seen.len() <= MAX_CONTINUATIONS, "dataframe cycle or count bound")?;
        let frame = &frames[*by_cid.get(cid).ok_or("missing continuation CID")?];
        let Node::DataFrame(df) = &frame.node else { return Err("continuation has wrong kind".into()); };
        let len = result.len().checked_add(df.data.len()).ok_or("dataframe size overflow")?;
        require(len <= max, "reassembled frame exceeds bound")?;
        result.extend_from_slice(df.data.as_slice());
        next = df.next.as_deref();
    }
    if let Some(hash) = first.hash {
        jetstreamer_firehose::node::verify_hash(&result, hash).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

fn decode_metadata_frame(frame: &[u8]) -> Result<(Vec<u8>, &'static str), String> {
    // The normal tighter helper is crate-private. Keep its 1MiB output and
    // window bound here; never use the public helper's much larger bound.
    let decompress = || -> Result<Vec<u8>, String> {
        let mut decoder = zstd::Decoder::new(frame).map_err(|e| e.to_string())?;
        decoder.window_log_max(20).map_err(|e| e.to_string())?;
        let mut bytes = Vec::new();
        decoder.take(MAX_META as u64 + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        require(bytes.len() <= MAX_META, "decompressed metadata exceeds bound")?;
        Ok(bytes)
    };
    let claimed_zstd = frame.starts_with(&[0x28,0xb5,0x2f,0xfd]) ||
        (frame.len() >= 4 && frame[0] & 0xf0 == 0x50 && frame[1..4] == [0x2a,0x4d,0x18]);
    match decompress() {
        Ok(bytes) => Ok((bytes, "zstd")),
        Err(error) if claimed_zstd =>
            Err(format!("claimed zstd metadata rejected: {error}")),
        Err(_) => Ok((frame.to_vec(), "raw")),
    }
}
fn prevalidate_protobuf(bytes: &[u8], keys: usize, instructions: usize)
    -> Result<solana_storage_proto::convert::generated::TransactionStatusMeta, String> {
    let proto: solana_storage_proto::convert::generated::TransactionStatusMeta =
        prost_011::Message::decode(bytes).map_err(|e| e.to_string())?;
    require(!proto.inner_instructions_none || proto.inner_instructions.is_empty(), "contradictory inner-instruction absence flag")?;
    require(!proto.log_messages_none || proto.log_messages.is_empty(), "contradictory log absence flag")?;
    require(!proto.return_data_none || proto.return_data.is_none(), "contradictory return-data absence flag")?;
    if let Some(data) = &proto.return_data {
        require(data.program_id.len() == 32, "return-data program id length")?;
    }
    for address in proto.loaded_writable_addresses.iter().chain(&proto.loaded_readonly_addresses) {
        require(address.len() == 32, "loaded address length")?;
    }
    // This incident predates versioned address-table transactions.
    require(proto.loaded_writable_addresses.is_empty() && proto.loaded_readonly_addresses.is_empty(),
        "legacy source metadata contains loaded addresses")?;
    for group in &proto.inner_instructions {
        require(group.index <= u8::MAX as u32 && (group.index as usize) < instructions,
            "inner-instruction group index")?;
        for instruction in &group.instructions {
            require(instruction.program_id_index <= u8::MAX as u32 && (instruction.program_id_index as usize) < keys,
                "inner-instruction program index")?;
            require(instruction.accounts.iter().all(|i| usize::from(*i) < keys), "inner-instruction account index")?;
        }
    }
    for token in proto.pre_token_balances.iter().chain(&proto.post_token_balances) {
        require(token.account_index <= u8::MAX as u32 && (token.account_index as usize) < keys,
            "token account index")?;
        if let Some(amount) = &token.ui_token_amount {
            require(amount.decimals <= u8::MAX as u32, "token decimals overflow")?;
        }
    }
    Ok(proto)
}

pub fn extract(bytes: &[u8], target: &Target) -> Result<Extraction, String> {
    target.validate()?;
    let frames = parse_car(bytes)?;
    let by_cid: BTreeMap<_, _> = frames.iter().enumerate().map(|(i, f)| (f.cid, i)).collect();
    let blocks: Vec<_> = frames.iter().enumerate().filter_map(|(i, f)| match &f.node {
        Node::Block(b) => Some((i, b)), _ => None }).collect();
    require(blocks.len() == 1, "input must contain exactly one complete target slot block")?;
    let (block_frame, block) = blocks[0];
    require(block.slot == target.slot && block.slot / 432_000 == target.epoch, "block selector differs")?;
    require(block.meta.parent_slot < block.slot, "invalid parent slot")?;
    require(block_frame + 1 == frames.len(), "target block must close the CAR segment")?;
    let rewards: Vec<_> = frames.iter().enumerate().filter_map(|(i,f)| match &f.node {
        Node::Rewards(r) => Some((i,r)), _ => None }).collect();
    require(rewards.len() == 1, "complete target slot requires exactly one rewards node")?;
    let (rewards_frame,rewards) = rewards[0];
    require(rewards.slot == target.slot && frames[rewards_frame].cid == block.rewards && rewards_frame < block_frame,
        "block rewards CID/slot association differs")?;
    let entry_frames: Vec<_> = frames.iter().enumerate().filter_map(|(i, f)| match &f.node {
        Node::Entry(e) => Some((i, e)), _ => None }).collect();
    require(entry_frames.len() <= MAX_ENTRIES && target.entry < entry_frames.len(), "entry index absent or bound")?;
    // Both the block's explicit links and the normal firehose's encounter order must agree.
    let encounter_cids: Vec<_> = entry_frames.iter().map(|(i, _)| frames[*i].cid).collect();
    require(block.entries == encounter_cids, "block entry links/order differ from source encounter order")?;
    let mut tx_cids = Vec::new();
    let mut ancestry = Vec::new();
    let mut selected = None;
    for (entry_index, (frame_index, entry)) in entry_frames.iter().enumerate() {
        let first = tx_cids.len();
        tx_cids.extend(entry.transactions.iter().copied());
        require(tx_cids.len() <= MAX_TRANSACTIONS, "transaction count bound")?;
        if entry_index == target.entry {
            require((first..tx_cids.len()).contains(&target.transaction), "target transaction is outside target entry")?;
            selected = Some((*frame_index, target.transaction - first));
        }
        ancestry.push(json!({"entry_index":entry_index,"cid":frames[*frame_index].cid.to_string(),
            "frame_offset":frames[*frame_index].wire.start,"frame_bytes":frames[*frame_index].wire.len(),
            "num_hashes":entry.num_hashes,"hash":entry.hash.to_string(),
            "transaction_range_start":first,"transaction_range_end_exclusive":tx_cids.len()}));
    }
    let encounter_tx: Vec<_> = frames.iter().filter_map(|f| match &f.node {
        Node::Transaction(_) => Some(f.cid), _ => None }).collect();
    require(tx_cids == encounter_tx, "entry transaction links/order differ from source encounter order")?;
    let mut unique = BTreeSet::new();
    let mut seen_target_signatures = 0;
    for (index, cid) in tx_cids.iter().enumerate() {
        require(unique.insert(*cid), "duplicate transaction entry reference")?;
        let frame = &frames[*by_cid.get(cid).ok_or("entry transaction CID absent")?];
        let Node::Transaction(tx) = &frame.node else { return Err("entry CID references nontransaction".into()); };
        require(tx.slot == target.slot && tx.index == Some(index as u64), "source transaction slot/index differs from entry ordering")?;
        // Parse every bounded wire transaction so a duplicate target signature cannot hide elsewhere.
        let wire = reassemble(&tx.data, &frames, &by_cid, MAX_TRANSACTION)?;
        let parsed = parse_versioned_transaction_from_slice(&wire).map_err(|e| e.to_string())?;
        let signature = parsed.signatures.first().ok_or("source transaction lacks signature")?.to_string();
        if signature == target.signature {
            seen_target_signatures += 1;
            require(index == target.transaction, "target signature appears at foreign transaction index")?;
        }
    }
    require(seen_target_signatures == 1, "target signature missing or duplicated")?;
    let cid = tx_cids[target.transaction];
    let tx_frame = *by_cid.get(&cid).ok_or("target CID absent")?;
    let Node::Transaction(tx) = &frames[tx_frame].node else { unreachable!() };
    let wire = reassemble(&tx.data, &frames, &by_cid, MAX_TRANSACTION)?;
    let parsed = parse_versioned_transaction_from_slice(&wire).map_err(|e| e.to_string())?;
    parsed.sanitize().map_err(|e| format!("transaction sanitization: {e}"))?;
    parsed.verify_and_hash_message().map_err(|e| format!("signature/message verification: {e}"))?;
    require(bincode::serialize(&parsed).map_err(|e| e.to_string())? == wire,
        "transaction parser did not preserve exact canonical wire bytes")?;
    let solana_message::VersionedMessage::Legacy(message) = &parsed.message else {
        return Err("epoch168 target must use legacy message layout".into());
    };
    let instruction = message.instructions.get(usize::from(target.instruction)).ok_or("target instruction absent")?;
    let program = message.account_keys.get(usize::from(instruction.program_id_index)).ok_or("invalid program index")?;
    let accounts: Result<Vec<_>, String> = instruction.accounts.iter().map(|index| {
        message.account_keys.get(usize::from(*index)).map(|key| json!({"index":index,"address":key.to_string()}))
            .ok_or_else(|| "instruction account index out of range".into()) }).collect();
    let compressed_meta = reassemble(&tx.metadata, &frames, &by_cid, MAX_META)?;
    require(!compressed_meta.is_empty(), "required source status is missing")?;
    let (metadata_bytes, metadata_compression) = decode_metadata_frame(&compressed_meta)?;
    // Prevalidate upstream conversion's unchecked narrowing/return-data unwrap,
    // then call the byte-identical normal source decoder and its status checks.
    let raw_proto = prevalidate_protobuf(&metadata_bytes, message.account_keys.len(), message.instructions.len())?;
    let meta = crate::source_status::decode_transaction_status_meta(target.slot, &metadata_bytes).map_err(|e| e.to_string())?;
    require(meta.status == Ok(()), "source status differs from exact expected success")?;
    require(raw_proto.err.is_none(), "successful source status must not contain original error bytes")?;
    require(meta.pre_balances.len() == message.account_keys.len() && meta.post_balances.len() == message.account_keys.len(),
        "source balance vectors do not match message account keys")?;
    let (entry_frame, within_entry) = selected.ok_or("selected entry absent")?;
    require(tx_frame < entry_frame && entry_frame < block_frame, "transaction/entry/block source order differs")?;
    let mut members = BTreeMap::new();
    members.insert("source.car".into(), bytes.to_vec());
    members.insert("transaction-source-frame.car-section".into(), bytes[frames[tx_frame].wire.clone()].to_vec());
    members.insert("entry-source-frame.car-section".into(), bytes[frames[entry_frame].wire.clone()].to_vec());
    members.insert("block-source-frame.car-section".into(), bytes[frames[block_frame].wire.clone()].to_vec());
    members.insert("rewards-source-frame.car-section".into(), bytes[frames[rewards_frame].wire.clone()].to_vec());
    members.insert("transaction.wire".into(), wire);
    members.insert("message.wire".into(), parsed.message.serialize());
    members.insert("status-source-frame.bin".into(), compressed_meta);
    members.insert("status.protobuf".into(), metadata_bytes);
    let normalized_proto: solana_storage_proto::convert::generated::TransactionStatusMeta = meta.clone().into();
    members.insert("status.normalized.protobuf".into(), prost_011::Message::encode_to_vec(&normalized_proto));
    members.insert("status.result.bincode".into(), bincode::serialize(&meta.status).map_err(|e| e.to_string())?);
    // The original success has no error field; preserve its absence in the raw Protobuf.
    // Never synthesize error bytes for a successful source transaction.
    members.insert("logs.json".into(), serde_json::to_vec_pretty(&meta.log_messages).map_err(|e| e.to_string())?);
    members.insert("inner-instructions.json".into(), serde_json::to_vec_pretty(&meta.inner_instructions).map_err(|e| e.to_string())?);
    let missing = [
        (!meta.log_messages.is_some()).then_some("canonical_log_messages"),
        (!meta.inner_instructions.is_some()).then_some("canonical_inner_instructions"),
        block.meta.block_height.is_none().then_some("block_height"),
        meta.compute_units_consumed.is_none().then_some("canonical_compute_units_consumed"),
        meta.cost_units.is_none().then_some("canonical_cost_units"),
        Some("authenticated_parent_final_entry_hash"),
        Some("pre_target_bank_and_accounts_state"),
        Some("canonical_execution_raw_vm_error"),
    ].into_iter().flatten().collect::<Vec<_>>();
    let report = json!({"schema":"jetstreamer-epoch168-target-source-diagnostic-v1",
        "epoch":target.epoch,"slot":target.slot,"entry_index":target.entry,
        "transaction_slot_index":target.transaction,"transaction_within_entry_index":within_entry,
        "signature":target.signature,"signature_message_verified":true,
        "source_status":{"status":"Ok","error":null,"original_error_field_present":false},
        "observed_worker_status_from_saved_incident":{"instruction":target.instruction,"error":"ProgramFailedToComplete"},
        "error_variants_remain_distinct":true,"metadata_compression":metadata_compression,
        "transaction_cid":cid.to_string(),"entry_cid":frames[entry_frame].cid.to_string(),
        "block_cid":frames[block_frame].cid.to_string(),"parent_slot":block.meta.parent_slot,
        "rewards_cid":frames[rewards_frame].cid.to_string(),
        "slot_meta":block.meta.to_json(),"entry_ancestry":ancestry,
        "instruction":{"index":target.instruction,"program_id_index":instruction.program_id_index,
            "program_address":program.to_string(),"accounts":accounts?,"data":instruction.data},
        "logs_present":meta.log_messages.is_some(),"inner_instructions_present":meta.inner_instructions.is_some(),
        "protobuf_absence_flags":{"log_messages_none":raw_proto.log_messages_none,
            "inner_instructions_none":raw_proto.inner_instructions_none,"return_data_none":raw_proto.return_data_none},
        "compute_units_consumed":meta.compute_units_consumed,"cost_units":meta.cost_units,
        "missing_fields":missing,"input_sha256":sha(bytes),"input_bytes":bytes.len(),
        "poh_work_verified":false,"canonical_ancestry_proven":false,"source_completeness_proven":false,
        "provider_generation_authenticated_by_extractor":false,"runtime_acceptance_proven":false,
        "replay_launch_authorized":false,"runtime_promotion_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    Ok(Extraction { report, members })
}

#[cfg(test)]
#[path = "extract_tests.rs"]
mod tests;
