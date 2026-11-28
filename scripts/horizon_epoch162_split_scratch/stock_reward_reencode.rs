//! Private diagnostic. Re-encode only epoch 162's first closed V2 bucket in
//! memory with the production writer. The stock source supplies an order and
//! write versions only. The candidate supplies every emitted account byte.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use jetstreamer_horizon::account_updates::AccountUpdateView;
use jetstreamer_horizon::archive::{
    ArchiveWriter, ArchiveWriterConfig, BlockNotification, BucketDecoder, BucketHeader,
    Compression, Consumption, EntryRecord, EpochMeta, FileHeader, SlotKind, SlotVisitor,
    parse_file_header,
};
use jetstreamer_horizon::transactions::Transaction;
use lencode::Decode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use solana_address::Address;

const START: u64 = 69_984_000;
const SLOTS: u64 = 128;
const FIRST_VERSION: u64 = 48_865_027_866;
const STOCK_STORED: &str = "0c15ede2c85e5ddb984df1e669fe97a21cf8ea8750f42ccb5fd229f34bc7aeaf";
const CAPPED_STORED: &str = "1747874ff4a026a376e42204d303e30263e5cb3bfa2fba5389b4b9bc7eefbe23";
const STOCK_EXPANDED: &str = "076d522c7eeff54b81fdfc2fe0abf674ff0fe2e714d2b4864d73d9232b36cdec";
const CAPPED_EXPANDED: &str = "fe25fba463d33e9aaae3fc7c5ef041ec67224e272e9a57e225dde87952df9b8d";
const EXPANDED_LEN: u64 = 203_859_634;
const STAKE: &str = "Stake11111111111111111111111111111111111111";
const VOTE: &str = "Vote111111111111111111111111111111111111111";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

struct Bucket {
    file: FileHeader,
    header: BucketHeader,
    raw: Vec<u8>,
}

impl Bucket {
    fn open(path: &Path, expected: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut file = File::open(path)?;
        let mut prefix = [0; 4096];
        file.read_exact(&mut prefix)?;
        let (fh, offset) = parse_file_header(&prefix)?;
        assert_eq!(
            (fh.epoch, fh.slot_start, fh.slot_count, fh.bucket_slots),
            (162, START, 7077, 128)
        );
        assert_eq!(fh.prime_table_id, 7441304762425479931);
        let mut encoded = &prefix[offset..];
        let before = encoded.len();
        let header = BucketHeader::decode_ext(&mut encoded, None)?;
        let header_len = before - encoded.len();
        assert_eq!(
            (
                header.first_slot,
                u64::from(header.slot_count),
                header.uncompressed_len
            ),
            (START, SLOTS, EXPANDED_LEN)
        );
        assert!(header.stored_len < 32 * 1024 * 1024);
        let mut raw = vec![0; header_len + usize::try_from(header.stored_len)?];
        file.seek(SeekFrom::Start(offset as u64))?;
        file.read_exact(&mut raw)?;
        assert_eq!(digest(&raw[header_len..]), expected);
        Ok(Self {
            file: fh,
            header,
            raw,
        })
    }

    fn visit(&self, count: u64, visitor: &mut impl SlotVisitor) {
        let mut decoder = BucketDecoder::for_file_header(&self.file).unwrap();
        decoder.verify_chain = true;
        decoder.set_consumption(visitor.consumption());
        assert_eq!(
            decoder
                .decode_bucket(&self.raw, START, count, visitor)
                .unwrap(),
            count
        );
        assert_eq!(u64::from(decoder.slots_remaining()), SLOTS - count);
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Write {
    key: Address,
    owner: Address,
    lamports: u64,
    executable: bool,
    rent_epoch: u64,
    version: u64,
    data: Vec<u8>,
}
impl Write {
    fn capture(a: &AccountUpdateView<'_>) -> Self {
        Self {
            key: a.pubkey,
            owner: a.owner,
            lamports: a.lamports,
            executable: a.executable,
            rent_epoch: a.rent_epoch,
            version: a.write_version,
            data: a.data.to_vec(),
        }
    }
    fn view(&self) -> AccountUpdateView<'_> {
        AccountUpdateView {
            pubkey: self.key,
            owner: self.owner,
            lamports: self.lamports,
            executable: self.executable,
            rent_epoch: self.rent_epoch,
            write_version: self.version,
            data: &self.data,
        }
    }
}

#[derive(Default)]
struct Capture {
    writes: Vec<Write>,
    block_rewards: Vec<(Address, String, i64)>,
}
impl SlotVisitor for Capture {
    fn consumption(&self) -> Consumption {
        Consumption::all().without_block_account_update_arenas()
    }
    fn on_pre_account_update(&mut self, slot: u64, a: &AccountUpdateView<'_>) {
        assert_eq!(slot, START);
        self.writes.push(Write::capture(a));
    }
    fn on_block(&mut self, block: &BlockNotification, _: &[EntryRecord]) {
        let BlockNotification::Block(meta) = block else {
            panic!("missing epoch boundary block")
        };
        self.block_rewards = meta
            .rewards
            .as_slice()
            .iter()
            .map(|r| (r.pubkey, format!("{:?}", r.reward_type), r.lamports))
            .collect();
    }
}

fn restore(stock: &[Write], capped: &[Write]) -> Result<Vec<Write>, &'static str> {
    if stock.len() != 8142 || capped.len() != stock.len() {
        return Err("different number of pre-writes");
    }
    let positions: BTreeMap<_, _> = capped.iter().enumerate().map(|(i, a)| (a.key, i)).collect();
    let keys: BTreeSet<_> = stock.iter().map(|a| a.key).collect();
    if positions.len() != capped.len() || keys.len() != stock.len() {
        return Err("duplicate key");
    }
    let stake: Address = STAKE.parse().unwrap();
    let vote: Address = VOTE.parse().unwrap();
    let mut restored = Vec::with_capacity(stock.len());
    for (index, expected) in stock.iter().enumerate() {
        let source = *positions.get(&expected.key).ok_or("missing reward key")?;
        if expected.version != FIRST_VERSION + index as u64
            || capped[source].version != FIRST_VERSION + source as u64
        {
            return Err("different version interval");
        }
        if source != index
            && (!(1..=8138).contains(&index)
                || !(1..=8138).contains(&source)
                || (expected.owner != stake && expected.owner != vote))
        {
            return Err("outside first-slot reward scope");
        }
        let mut actual = capped[source].clone();
        actual.version = expected.version;
        if actual != *expected {
            return Err("different account contents");
        }
        restored.push(actual);
    }
    Ok(restored)
}

fn reward_evidence(stock: &Capture, capped: &Capture) -> Value {
    assert_eq!(stock.block_rewards, capped.block_rewards);
    let mut types = BTreeMap::new();
    for (_, kind, _) in &stock.block_rewards {
        *types.entry(kind.clone()).or_insert(0usize) += 1;
    }
    let distinct: BTreeSet<_> = stock.block_rewards.iter().map(|r| r.0).collect();
    let measured = |capture: &Capture| {
        let indexes: BTreeMap<_, _> = capture.writes[1..=8138]
            .iter()
            .enumerate()
            .map(|(i, w)| (w.key, i + 1))
            .collect();
        let order: Vec<_> = capture
            .block_rewards
            .iter()
            .filter_map(|r| indexes.get(&r.0))
            .collect();
        json!({"reward_entries_that_name_a_scoped_write":order.len(),
               "unique_scoped_write_keys_named":order.iter().collect::<BTreeSet<_>>().len(),
               "matched_entries_increasing_in_write_order":order.windows(2).all(|w|w[0]<w[1])})
    };
    json!({"block_reward_entries":stock.block_rewards.len(),"distinct_block_reward_keys":distinct.len(),
           "by_reward_type":types,"stock":measured(stock),"capped":measured(capped)})
}

struct Emitter<'a> {
    writer: ArchiveWriter<Vec<u8>>,
    repaired: Option<&'a [Write]>,
    suppressed_pre: usize,
}
impl SlotVisitor for Emitter<'_> {
    fn consumption(&self) -> Consumption {
        Consumption::all().without_block_account_update_arenas()
    }
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        match kind {
            SlotKind::Block => self.writer.begin_slot(slot).unwrap(),
            SlotKind::Skipped => self.writer.write_skipped_slot(slot).unwrap(),
        }
    }
    fn on_epoch(&mut self, meta: &EpochMeta) {
        self.writer.write_epoch_meta(meta).unwrap();
    }
    fn on_pre_account_update(&mut self, slot: u64, a: &AccountUpdateView<'_>) {
        if slot == START
            && let Some(repaired) = self.repaired
        {
            if self.suppressed_pre == 0 {
                for record in repaired {
                    self.writer.write_orphan_update(&record.view()).unwrap();
                }
            }
            self.suppressed_pre += 1;
        } else {
            self.writer.write_orphan_update(a).unwrap();
        }
    }
    fn on_transaction(&mut self, _slot: u64, _index: u32, tx: &Transaction) {
        self.writer.write_transaction(tx).unwrap();
    }
    fn on_post_account_update(&mut self, _slot: u64, a: &AccountUpdateView<'_>) {
        self.writer.write_orphan_update(a).unwrap();
    }
    fn on_block(&mut self, block: &BlockNotification, entries: &[EntryRecord]) {
        if let BlockNotification::Block(meta) = block {
            self.writer.end_slot(meta, entries).unwrap();
        }
    }
}

fn reencode(bucket: &Bucket, repaired: Option<&[Write]>) -> Value {
    // The strict guard hashes the expanded V2 slot stream. Bypass the
    // lossless outer compressor to hash those exact bytes in bounded memory.
    let config = ArchiveWriterConfig {
        compression: Compression::None,
        ..ArchiveWriterConfig::default()
    };
    let mut writer = ArchiveWriter::new(Vec::new(), 162, START, 7077, config).unwrap();
    writer
        .preserve_initial_poh_anchor(START, bucket.header.poh_start_hash)
        .unwrap();
    let mut emitter = Emitter {
        writer,
        repaired,
        suppressed_pre: 0,
    };
    bucket.visit(SLOTS, &mut emitter);
    assert_eq!(emitter.suppressed_pre, repaired.map_or(0, |r| r.len()));
    let (raw, stats) = emitter.writer.finish().unwrap();
    assert_eq!(
        (stats.buckets, stats.slots, stats.transactions),
        (1, 128, 60211)
    );
    let (_, offset) = parse_file_header(&raw).unwrap();
    let mut remaining = &raw[offset..];
    let h = BucketHeader::decode_ext(&mut remaining, None).unwrap();
    assert_eq!(h.poh_start_hash, bucket.header.poh_start_hash);
    assert_eq!(h.compression, Compression::None);
    assert_eq!(h.stored_len, EXPANDED_LEN);
    assert_eq!(h.uncompressed_len, EXPANDED_LEN);
    json!({"encoded_slot_stream_sha256":digest(&remaining[..h.stored_len as usize]),"bytes":h.stored_len,
           "first_slot":h.first_slot,"slots":h.slot_count,"blocks":stats.blocks,"transactions":stats.transactions,
           "account_updates":stats.account_updates,"orphan_account_updates":stats.orphan_account_updates})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: stock_reward_reencode STOCK.jet CAPPED.jet".into());
    }
    let stock = Bucket::open(Path::new(&args[0]), STOCK_STORED)?;
    let capped = Bucket::open(Path::new(&args[1]), CAPPED_STORED)?;
    assert_eq!(stock.header.poh_start_hash, capped.header.poh_start_hash);
    let mut left = Capture::default();
    stock.visit(1, &mut left);
    let mut right = Capture::default();
    capped.visit(1, &mut right);
    let ordered = restore(&left.writes, &right.writes)?;
    let mut corrupt = right.writes.clone();
    corrupt[1].lamports ^= 1;
    assert_eq!(
        restore(&left.writes, &corrupt).err(),
        Some("different account contents")
    );
    let mut corrupt = right.writes.clone();
    corrupt[1].version += 1;
    assert_eq!(
        restore(&left.writes, &corrupt).err(),
        Some("different version interval")
    );
    let control = reencode(&stock, None);
    assert_eq!(control["encoded_slot_stream_sha256"], STOCK_EXPANDED);
    let original = reencode(&capped, None);
    assert_eq!(original["encoded_slot_stream_sha256"], CAPPED_EXPANDED);
    let projected = reencode(&capped, Some(&ordered));
    assert_eq!(projected, control);
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"horizon-162-first-reward-reencoding-qualification-v1",
        "stock_reencoded":control,"candidate_reencoded":original,"candidate_with_stock_reward_positions":projected,
        "mutated_candidate_content_rejected":true,"mutated_candidate_source_version_rejected":true,
        "first_block_reward_evidence":reward_evidence(&left,&right),
        "scope":"first 128 positions only; no archive or manifest issued"})
        )?
    );
    Ok(())
}
