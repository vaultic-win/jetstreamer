//! Authored only: none of these controls has been run.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use solana_transaction_status::TransactionStatusMeta;

// Exact signed transaction.wire from the first normal transaction.rs decoder fixture.
// It is a historical vote with one instruction. These synthetic slot/status wrappers
// qualify parsing/selecting only; they do not assert canonical epoch168 execution.
const SIGNED_WIRE: &str = "AYbTMUdKwOfLPFey+AwyctaBtizbmzA4GiKpHwj+4ZrfKJu+xyl67fjZA6Nn1P8bg57V3OnuZVmUWyx8eSIdEwgBAAMFBRm4eNZlQLMYzIafIkHEG3bCnw0fIZY+Zqt/itnGLqcFGbhso5XTeMn5AgdGOiWLQlHMPlUD7ru2OG1kkuQjSgan1RcZLwqvxvJl4/t3zHragsUp0L47E24tAFUgAAAABqfVFxjHdMkoVmOYaR1etoteuKObS21cc1VbIQAAAAAHYUgdNXR0u3xNdiTr072z2DVec9EQQ/wNo1OAAAAAALY8zyGeltaQlaJeQ5wMCwZM8BOX2PZ5LVgiytnw6PELAQQEAQIDAD0CAAAAAgAAAAAAAAB9FAEBAAAAAH4UAQEAAAAA8qsHs5MMwvaTJoc++kGCUvyGn9od2r8SeheTKCk1uFgA";
fn put_varint(mut value: usize, destination: &mut Vec<u8>) {
    while value >= 128 { destination.push((value as u8 & 127) | 128); value >>= 7; }
    destination.push(value as u8);
}
fn add_section(body: &[u8], destination: &mut Vec<u8>) {
    put_varint(body.len(), destination); destination.extend_from_slice(body);
}
fn source_link(cid: Cid) -> Cbor {
    let mut bytes = vec![0]; bytes.extend_from_slice(&cid.to_bytes()); Cbor::Bytes(bytes)
}
fn node(value: Cbor) -> (Cid, Vec<u8>) {
    let bytes = serde_cbor::to_vec(&value).unwrap();
    let hash = multihash::Multihash::wrap(0x12, &Sha256::digest(&bytes)).unwrap();
    let cid = Cid::new_v1(0x71, hash);
    let mut body = cid.to_bytes(); body.extend_from_slice(&bytes);
    (cid, body)
}
fn df(bytes: Vec<u8>) -> Cbor {
    Cbor::Array(vec![Cbor::Integer(6),Cbor::Null,Cbor::Null,Cbor::Null,Cbor::Bytes(bytes)])
}
fn status(error: Option<InstructionError>) -> Vec<u8> {
    let native = TransactionStatusMeta { status:match error {Some(error)=>Err(TransactionError::InstructionError(0,error)),None=>Ok(())},
        pre_balances:vec![1_000_000;5],post_balances:vec![995_000;5],fee:5_000,
        ..TransactionStatusMeta::default() };
    let proto: solana_storage_proto::convert::generated::TransactionStatusMeta = native.into();
    prost_011::Message::encode_to_vec(&proto)
}
struct Fixture {
    wire: Vec<u8>, metadata: Vec<u8>, declared_index: u64, declared_slot: u64,
    reverse_block_entries: bool,
}
impl Fixture {
    fn normal() -> Self {
        Self { wire:STANDARD.decode(SIGNED_WIRE).unwrap(),metadata:status(None),
            declared_index:0,declared_slot:72_728_191,reverse_block_entries:false }
    }
    fn encode(self) -> (Vec<u8>, Target) {
        let parsed = parse_versioned_transaction_from_slice(&self.wire).unwrap();
        let target = Target {epoch:168,slot:72_728_191,entry:1,transaction:0,
            signature:parsed.signatures[0].to_string(),instruction:0};
        let (transaction_cid,transaction) = node(Cbor::Array(vec![Cbor::Integer(0),df(self.wire),df(self.metadata),
            Cbor::Integer(self.declared_slot.into()),Cbor::Integer(self.declared_index.into())]));
        let (tick_cid,tick) = node(Cbor::Array(vec![Cbor::Integer(1),Cbor::Integer(1),
            Cbor::Bytes(vec![1;32]),Cbor::Array(vec![])]));
        let (entry_cid,entry) = node(Cbor::Array(vec![Cbor::Integer(1),Cbor::Integer(1),
            Cbor::Bytes(vec![2;32]),Cbor::Array(vec![source_link(transaction_cid)])]));
        let (rewards_cid,rewards) = node(Cbor::Array(vec![Cbor::Integer(5),Cbor::Integer(72_728_191),df(vec![])]));
        let mut entries = vec![source_link(tick_cid),source_link(entry_cid)];
        if self.reverse_block_entries { entries.reverse(); }
        let (block_cid,block) = node(Cbor::Array(vec![Cbor::Integer(2),Cbor::Integer(72_728_191),
            Cbor::Array(vec![]),Cbor::Array(entries),Cbor::Array(vec![Cbor::Integer(72_728_190),Cbor::Integer(1_634_000_000)]),
            source_link(rewards_cid)]));
        let header = serde_cbor::to_vec(&Cbor::Map([
            (Cbor::Text("version".into()),Cbor::Integer(1)),
            (Cbor::Text("roots".into()),Cbor::Array(vec![source_link(block_cid)]))
        ].into_iter().collect())).unwrap();
        let mut car = vec![]; add_section(&header,&mut car);
        for body in [tick,transaction,entry,rewards,block] {add_section(&body,&mut car);}
        (car,target)
    }
}
fn rejected(car: &[u8], target: &Target) -> String {
    match extract(car,target) {Ok(_) => panic!("unexpected extraction acceptance"),Err(e) => e}
}

#[test]
fn normal_parser_fixture_retains_exact_bytes_and_missing_optional_fields() {
    let fixture = Fixture::normal(); let wire = fixture.wire.clone(); let meta = fixture.metadata.clone();
    let (car,target) = fixture.encode(); let result = extract(&car,&target).unwrap();
    assert_eq!(result.members["source.car"],car);
    assert_eq!(result.members["transaction.wire"],wire);
    assert_eq!(result.members["status.protobuf"],meta);
    assert_eq!(result.report["transaction_within_entry_index"],0);
    assert_eq!(result.report["source_status"]["status"],"Ok");
    assert_eq!(result.report["canonical_ancestry_proven"],false);
    assert_eq!(result.report["runtime_acceptance_proven"],false);
    assert_eq!(result.report["logs_present"],false);
    assert!(result.report["missing_fields"].as_array().unwrap().contains(&json!("canonical_log_messages")));
}
#[test]
fn incident_selector_cannot_accept_synthetic_fixture() {
    let (car,_) = Fixture::normal().encode();
    assert!(!rejected(&car,&Target::incident()).is_empty());
}
#[test]
fn epoch_slot_selector_must_agree() {
    let (car,mut target) = Fixture::normal().encode(); target.epoch = 141;
    assert!(rejected(&car,&target).contains("epoch/slot"));
}
#[test]
fn foreign_slot_rejects_normal_source_block() {
    let (car,mut target) = Fixture::normal().encode(); target.slot += 1;
    assert!(rejected(&car,&target).contains("block selector"));
}
#[test]
fn entry_index_must_select_transaction_bearing_entry() {
    let (car,mut target) = Fixture::normal().encode(); target.entry = 0;
    assert!(rejected(&car,&target).contains("outside target entry"));
}
#[test]
fn absent_entry_index_rejects() {
    let (car,mut target) = Fixture::normal().encode(); target.entry = 2;
    assert!(rejected(&car,&target).contains("entry index absent"));
}
#[test]
fn absent_transaction_index_rejects() {
    let (car,mut target) = Fixture::normal().encode(); target.transaction = 1;
    assert!(rejected(&car,&target).contains("outside target entry"));
}
#[test]
fn selector_index_bounds_apply_before_normal_parser() {
    let (car,mut target) = Fixture::normal().encode(); target.transaction = MAX_TRANSACTIONS;
    assert!(rejected(&car,&target).contains("selector index"));
}
#[test]
fn foreign_signature_rejects_without_substitution() {
    let (car,mut target) = Fixture::normal().encode();
    target.signature = solana_signature::Signature::from([8u8;64]).to_string();
    assert!(rejected(&car,&target).contains("signature missing"));
}
#[test]
fn wrong_source_transaction_index_rejects_rehashed_valid_nodes() {
    let mut fixture = Fixture::normal(); fixture.declared_index = 1;
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("slot/index"));
}
#[test]
fn wrong_source_transaction_slot_rejects_rehashed_valid_nodes() {
    let mut fixture = Fixture::normal(); fixture.declared_slot += 1;
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("slot/index"));
}
#[test]
fn block_entry_links_must_match_source_order() {
    let mut fixture = Fixture::normal(); fixture.reverse_block_entries = true;
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("entry links/order"));
}
#[test]
fn source_success_rejects_computational_budget_exceeded() {
    let mut fixture = Fixture::normal(); fixture.metadata = status(Some(InstructionError::ComputationalBudgetExceeded));
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("exact expected success"));
}
#[test]
fn required_status_cannot_be_defaulted_when_missing() {
    let mut fixture = Fixture::normal(); fixture.metadata.clear();
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("status is missing"));
}
#[test]
fn corrupt_signature_in_rehashed_normal_source_fails_crypto() {
    let mut fixture = Fixture::normal(); fixture.wire[1] ^= 1;
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("signature/message verification"));
}
#[test]
fn altered_payload_cannot_keep_original_source_cid() {
    let (mut car,target) = Fixture::normal().encode();
    *car.last_mut().unwrap() ^= 1;
    assert!(rejected(&car,&target).contains("CID"));
}
#[test]
fn oversized_section_rejects_before_allocation_or_source_decode() {
    let (car,target) = Fixture::normal().encode();
    let mut position = 0; section(&car,&mut position,1024).unwrap();
    let mut changed = car[..position].to_vec(); put_varint(MAX_FRAME+1,&mut changed);
    assert!(rejected(&changed,&target).contains("section size bound"));
}
#[test]
fn oversized_metadata_rejects_normal_cbor_shape() {
    let mut fixture = Fixture::normal(); fixture.metadata = vec![0;MAX_META+1];
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("dataframe bytes exceed bound"));
}
#[test]
fn truncated_normal_source_section_rejects() {
    let (mut car,target) = Fixture::normal().encode(); car.pop();
    assert!(rejected(&car,&target).contains("truncated CAR section"));
}
#[test]
fn nonminimal_length_encoding_rejects() {
    let (car,target) = Fixture::normal().encode();
    assert!(car[0] < 128);
    let mut changed = vec![car[0] | 128,0]; changed.extend_from_slice(&car[1..]);
    assert!(rejected(&changed,&target).contains("nonminimal"));
}

#[test]
fn bounded_zstd_status_uses_the_normal_protobuf_decoder() {
    let mut fixture = Fixture::normal();
    fixture.metadata = zstd::encode_all(fixture.metadata.as_slice(),1).unwrap();
    let (car,target) = fixture.encode(); let result = extract(&car,&target).unwrap();
    assert_eq!(result.report["metadata_compression"],"zstd");
}
#[test]
fn oversized_zstd_status_cannot_fall_back_to_raw_protobuf() {
    let mut fixture = Fixture::normal();
    fixture.metadata = zstd::encode_all(vec![0u8;MAX_META+1].as_slice(),1).unwrap();
    let (car,target) = fixture.encode();
    assert!(rejected(&car,&target).contains("claimed zstd metadata rejected"));
}
#[test]
fn skippable_zstd_prefix_cannot_bypass_decompression_bound() {
    let compressed = zstd::encode_all(vec![0u8;MAX_META+1].as_slice(),1).unwrap();
    for magic in 0x50..=0x5f {
        let mut prefixed = vec![magic,0x2a,0x4d,0x18,0,0,0,0];
        prefixed.extend_from_slice(&compressed);
        assert!(decode_metadata_frame(&prefixed).unwrap_err().contains("claimed zstd metadata rejected"));
    }
}
#[test]
fn malformed_return_data_is_an_error_before_upstream_unwrap() {
    let mut fixture = Fixture::normal();
    let mut proto: solana_storage_proto::convert::generated::TransactionStatusMeta = prost_011::Message::decode(fixture.metadata.as_slice()).unwrap();
    proto.return_data_none = false;
    proto.return_data = Some(solana_storage_proto::convert::generated::ReturnData{program_id:vec![1;31],data:vec![]});
    fixture.metadata = prost_011::Message::encode_to_vec(&proto);
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("program id length"));
}
#[test]
fn malformed_wide_inner_group_index_cannot_truncate() {
    let mut fixture = Fixture::normal();
    let mut proto: solana_storage_proto::convert::generated::TransactionStatusMeta = prost_011::Message::decode(fixture.metadata.as_slice()).unwrap();
    proto.inner_instructions_none = false;
    proto.inner_instructions = vec![solana_storage_proto::convert::generated::InnerInstructions{index:256,instructions:vec![]}];
    fixture.metadata = prost_011::Message::encode_to_vec(&proto);
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("group index"));
}
#[test]
fn contradictory_log_absence_cannot_discard_present_logs() {
    let mut fixture = Fixture::normal();
    let mut proto: solana_storage_proto::convert::generated::TransactionStatusMeta = prost_011::Message::decode(fixture.metadata.as_slice()).unwrap();
    proto.log_messages_none = true; proto.log_messages = vec!["present".into()];
    fixture.metadata = prost_011::Message::encode_to_vec(&proto);
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("contradictory log"));
}

#[test]
fn source_success_rejects_program_failed_to_complete() {
    let mut fixture = Fixture::normal(); fixture.metadata = status(Some(InstructionError::ProgramFailedToComplete));
    let (car,target) = fixture.encode(); assert!(rejected(&car,&target).contains("exact expected success"));
}
#[test]
fn successful_source_preserves_original_error_absence() {
    let (car,target) = Fixture::normal().encode(); let result = extract(&car,&target).unwrap();
    assert_eq!(result.report["source_status"]["original_error_field_present"],false);
    assert!(!result.members.contains_key("status.source-error.bincode"));
    assert_eq!(result.members["status.result.bincode"],bincode::serialize(&Ok::<(),TransactionError>(())).unwrap());
}
