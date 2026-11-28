//! Compare decoded events in the first complete bucket of two local Horizon files.
//! A closed bucket can be read from a partial stock file without a footer.
//! The report retains each phase's ordering and every write version. Its
//! separate first-slot account comparison is diagnostic and issues no acceptance.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{
        BlockNotification, BucketDecoder, BucketHeader, Consumption, EntryRecord, EpochMeta,
        MAX_BUCKET_STORED_BYTES, MAX_FILE_HEADER_BYTES, SemanticDigest, SlotKind, SlotVisitor,
        parse_file_header,
    },
};
use lencode::Decode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type Hash = [u8; 32];
type FirstPositions = BTreeMap<Hash, (usize, Hash, u64)>;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Phase {
    Slot,
    Epoch,
    Pre,
    Transaction,
    Post,
    Block,
}
use Phase::*;

const PHASES: [(Phase, &str); 6] = [
    (Slot, "slot"),
    (Epoch, "epoch"),
    (Pre, "pre"),
    (Transaction, "transaction"),
    (Post, "post"),
    (Block, "block_and_entries"),
];

struct Frame {
    slot: u64,
    events: BTreeMap<Phase, Vec<Hash>>,
}

#[derive(Default)]
struct Decoded {
    frames: Vec<Frame>,
    first_pre: Vec<(Hash, Hash, u64, Hash)>,
    reference: Option<FirstPositions>,
    projected_pre: BTreeMap<usize, Hash>,
    projection_valid: bool,
}

fn event(f: impl FnOnce(&mut SemanticDigest)) -> Hash {
    let mut digest = SemanticDigest::new();
    f(&mut digest);
    digest.finish().expect("encode full decoded event")
}

impl Decoded {
    fn push(&mut self, phase: Phase, digest: Hash) {
        self.frames
            .last_mut()
            .expect("slot started")
            .events
            .entry(phase)
            .or_default()
            .push(digest);
    }
}

impl SlotVisitor for Decoded {
    fn consumption(&self) -> Consumption {
        Consumption::all().without_block_account_update_arenas()
    }
    fn on_slot_start(&mut self, slot: u64, kind: SlotKind) {
        self.frames.push(Frame {
            slot,
            events: BTreeMap::new(),
        });
        self.push(Slot, event(|d| d.on_slot_start(slot, kind)));
    }
    fn on_epoch(&mut self, meta: &EpochMeta) {
        self.push(Epoch, event(|d| d.on_epoch(meta)));
    }
    fn on_pre_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        let strict = event(|d| d.on_pre_account_update(slot, update));
        self.push(Pre, strict);
        if self.frames.len() == 1 {
            let key = update.pubkey.to_bytes();
            let owner = update.owner.to_bytes();
            if let Some(reference) = &self.reference {
                let position = self.first_pre.len();
                let mut destination = position;
                let mut restored_digest = strict;
                if let Some(&(original_position, original_owner, original_version)) =
                    reference.get(&key)
                {
                    if original_owner != owner {
                        self.projection_valid = false;
                    } else if position != original_position
                        || update.write_version != original_version
                    {
                        if matches!(
                            update.owner.to_string().as_str(),
                            "Stake11111111111111111111111111111111111111"
                                | "Vote111111111111111111111111111111111111111"
                        ) {
                            destination = original_position;
                            let restored = AccountUpdateView {
                                write_version: original_version,
                                ..*update
                            };
                            restored_digest = event(|d| d.on_pre_account_update(slot, &restored));
                        } else {
                            self.projection_valid = false;
                        }
                    }
                } else {
                    self.projection_valid = false;
                }
                if self
                    .projected_pre
                    .insert(destination, restored_digest)
                    .is_some()
                {
                    self.projection_valid = false;
                }
            }
            let without_version = AccountUpdateView {
                write_version: 0,
                ..*update
            };
            self.first_pre.push((
                key,
                owner,
                update.write_version,
                event(|d| d.on_pre_account_update(slot, &without_version)),
            ));
        }
    }
    fn on_transaction(
        &mut self,
        slot: u64,
        index: u32,
        tx: &jetstreamer_horizon::transactions::Transaction,
    ) {
        self.push(
            Phase::Transaction,
            event(|d| d.on_transaction(slot, index, tx)),
        );
    }
    fn on_post_account_update(&mut self, slot: u64, update: &AccountUpdateView<'_>) {
        self.push(Post, event(|d| d.on_post_account_update(slot, update)));
    }
    fn on_block(&mut self, block: &BlockNotification, entries: &[EntryRecord]) {
        self.push(Block, event(|d| d.on_block(block, entries)));
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn read(
    path: &Path,
    reference: Option<FirstPositions>,
) -> Result<(Value, Decoded), Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let before = file.metadata()?;
    let mut prefix = vec![0; before.len().min(MAX_FILE_HEADER_BYTES + 32) as usize];
    file.read_exact(&mut prefix)?;
    let (header, offset) = parse_file_header(&prefix)?;
    drop(prefix);
    file.seek(SeekFrom::Start(offset as u64))?;
    let bucket = BucketHeader::decode_ext(&mut file, None)?;
    let raw_len = file
        .stream_position()?
        .checked_sub(offset as u64)
        .and_then(|header_len| header_len.checked_add(bucket.stored_len))
        .ok_or("bucket length overflow")?;
    if bucket.first_slot != header.slot_start
        || bucket.slot_count == 0
        || bucket.stored_len > MAX_BUCKET_STORED_BYTES
        || (offset as u64)
            .checked_add(raw_len)
            .is_none_or(|end| end > before.len())
    {
        return Err("missing or invalid first bucket".into());
    }
    file.seek(SeekFrom::Start(offset as u64))?;
    let mut raw = vec![0; usize::try_from(raw_len)?];
    file.read_exact(&mut raw)?;
    let mut visitor = Decoded {
        reference,
        projection_valid: true,
        ..Decoded::default()
    };
    let mut decoder = BucketDecoder::for_file_header(&header)?;
    decoder.verify_chain = true;
    decoder.set_consumption(visitor.consumption());
    let observed = decoder.decode_bucket(
        &raw,
        bucket.first_slot,
        u64::from(bucket.slot_count),
        &mut visitor,
    )?;
    if observed != u64::from(bucket.slot_count)
        || decoder.slots_remaining() != 0
        || visitor.frames.len() as u64 != observed
        || before.len() != file.metadata()?.len()
        || before.modified()? != file.metadata()?.modified()?
    {
        return Err("incomplete first bucket or source changed".into());
    }
    Ok((
        json!({"epoch":header.epoch,"archive_slot_start":header.slot_start,"archive_slot_count":header.slot_count,
        "bucket_slots":header.bucket_slots,"first":bucket.first_slot,"count":observed,
        "prime_table":header.prime_table_id,"anchor":bucket.poh_start_hash.to_string()}),
        visitor,
    ))
}

fn aggregate(events: &[Hash]) -> String {
    let mut sh = Sha256::new();
    sh.update(b"Horizon diagnostic ordered event digests v1");
    sh.update((events.len() as u64).to_le_bytes());
    for d in events {
        sh.update(d);
    }
    hex(sh.finalize())
}

fn compare(a: &Decoded, b: &Decoded) -> Value {
    assert_eq!(a.frames.len(), b.frames.len());
    let mut totals = BTreeMap::new();
    let mut differing = Vec::new();
    let mut aligned = 0;
    let mut projection_matches = b.reference.is_some() && b.projection_valid;
    for (index, (left, right)) in a.frames.iter().zip(&b.frames).enumerate() {
        assert_eq!(left.slot, right.slot);
        let mut differences = BTreeMap::new();
        for (phase, name) in PHASES {
            let x = left
                .events
                .get(&phase)
                .map(Vec::as_slice)
                .unwrap_or_default();
            let y = right
                .events
                .get(&phase)
                .map(Vec::as_slice)
                .unwrap_or_default();
            if index == 0 && phase == Pre {
                projection_matches &= b.projected_pre.len() == x.len()
                    && x.iter()
                        .enumerate()
                        .all(|(i, original)| Some(original) == b.projected_pre.get(&i));
            } else {
                projection_matches &= x == y;
            }
            let (left_total, right_total, mismatch_total) = totals.entry(name).or_insert((0, 0, 0));
            *left_total += x.len();
            *right_total += y.len();
            if x != y {
                let n = x.iter().zip(y).filter(|(u, v)| u != v).count() + x.len().abs_diff(y.len());
                *mismatch_total += n;
                let k = x
                    .iter()
                    .zip(y)
                    .position(|(u, v)| u != v)
                    .unwrap_or(x.len().min(y.len()));
                differences.insert(
                    name,
                    json!({"left_count":x.len(),"right_count":y.len(),"unequal":n,
                    "first_index":k,"first_left":x.get(k).map(hex),"first_right":y.get(k).map(hex),
                    "left_ordered_sha256":aggregate(x),"right_ordered_sha256":aggregate(y)}),
                );
            }
        }
        if differences.is_empty() {
            aligned += 1;
        } else {
            differing.push(json!({"slot":left.slot,"phases":differences}));
        }
    }
    let rows_a = &a.first_pre;
    let rows_b = &b.first_pre;
    let as_set = |rows: &[(Hash, Hash, u64, Hash)]| {
        rows.iter()
            .map(|r| (r.0, r.1, r.3))
            .collect::<BTreeSet<_>>()
    };
    let versions_equal =
        rows_a.len() == rows_b.len() && rows_a.iter().zip(rows_b).all(|(x, y)| x.2 == y.2);
    let unique = |rows: &[(Hash, Hash, u64, Hash)]| {
        rows.iter().map(|r| r.0).collect::<BTreeSet<_>>().len() == rows.len()
    };
    let mut moved = BTreeMap::new();
    if unique(rows_a) && unique(rows_b) {
        let by_key: BTreeMap<_, _> = rows_b.iter().enumerate().map(|(i, r)| (r.0, i)).collect();
        for (i, r) in rows_a.iter().enumerate() {
            if by_key.get(&r.0).is_some_and(|j| *j != i) {
                *moved.entry(hex(r.1)).or_insert(0usize) += 1;
            }
        }
    }
    let contiguous = [rows_a, rows_b].into_iter().all(|rows| {
        rows.windows(2)
            .all(|w| w[0].2.checked_add(1) == Some(w[1].2))
    });
    json!({"strictly_equal_slots":aligned,"strict_equality":differing.is_empty(),
        "ordered_events_equal_after_projecting_first_pre_stake_vote_to_left_positions_and_versions":
            projection_matches && versions_equal && unique(rows_a) && unique(rows_b),
        "phase_totals_left_right_unequal":totals,"differing_slots":differing,
        "first_pre_content_probe":{"left_rows":rows_a.len(),"right_rows":rows_b.len(),
          "unique_pubkeys":unique(rows_a)&&unique(rows_b),"same_ordered_write_versions":versions_equal,
          "both_contiguous": contiguous,
          "same_keyed_contents_excluding_only_write_version":unique(rows_a)&&unique(rows_b)&&as_set(rows_a)==as_set(rows_b),
          "moved_positions_by_owner_hex":moved}})
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: compare_first_bucket LEFT.jet RIGHT.jet".into());
    }
    let (lh, left) = read(Path::new(&args[0]), None)?;
    let positions = left
        .first_pre
        .iter()
        .enumerate()
        .map(|(index, row)| (row.0, (index, row.1, row.2)))
        .collect();
    let (rh, right) = read(Path::new(&args[1]), Some(positions))?;
    if lh != rh {
        return Err("unmatched source identity, coverage or initial PoH anchor".into());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"horizon-first-bucket-semantic-comparison-v1",
        "scope":lh,"comparison":compare(&left,&right)})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(
        reference: Option<FirstPositions>,
        swapped: bool,
        changed_data: bool,
        changed_post_version: bool,
    ) -> Decoded {
        let mut decoded = Decoded {
            reference,
            projection_valid: true,
            ..Decoded::default()
        };
        let stake: AccountUpdateView<'_> = AccountUpdateView {
            pubkey: "Stake11111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            owner: "Stake11111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            lamports: 123,
            executable: false,
            rent_epoch: 4,
            write_version: 100,
            data: &[12],
        };
        let vote = AccountUpdateView {
            pubkey: "Vote111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            owner: "Vote111111111111111111111111111111111111111"
                .parse()
                .unwrap(),
            data: if changed_data { &[14] } else { &[13] },
            ..stake
        };
        decoded.on_slot_start(10, SlotKind::Block);
        for (index, account) in if swapped {
            [vote, stake]
        } else {
            [stake, vote]
        }
        .into_iter()
        .enumerate()
        {
            decoded.on_pre_account_update(
                10,
                &AccountUpdateView {
                    write_version: 100 + index as u64,
                    ..account
                },
            );
        }
        decoded.on_slot_start(11, SlotKind::Block);
        decoded.on_post_account_update(
            11,
            &AccountUpdateView {
                write_version: if changed_post_version { 103 } else { 102 },
                ..stake
            },
        );
        decoded
    }

    #[test]
    fn projection_only_reconciles_the_first_pre_reward_permutation() {
        let left = fixture(None, false, false, false);
        for (swapped, data, post, strict, projected) in [
            (false, false, false, true, true),
            (true, false, false, false, true),
            (true, true, false, false, false),
            (true, false, true, false, false),
        ] {
            let positions = left
                .first_pre
                .iter()
                .enumerate()
                .map(|(i, r)| (r.0, (i, r.1, r.2)))
                .collect();
            let right = fixture(Some(positions), swapped, data, post);
            let result = compare(&left, &right);
            assert_eq!(result["strict_equality"], strict);
            assert_eq!(
                result["ordered_events_equal_after_projecting_first_pre_stake_vote_to_left_positions_and_versions"],
                projected
            );
        }
    }
}
