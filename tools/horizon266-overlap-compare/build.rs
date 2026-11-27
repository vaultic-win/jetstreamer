//! Reuse the sealed epoch 168 visitor without altering it or the epoch 167
//! extractor that pins its exact bytes.

use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

const SOURCE: &str = "../../scripts/horizon_epoch168_joint_capacity_20261126_v1/joint-source-compare/joint_compare.rs";
const SOURCE_SHA: &str = "5541b615993ca7b52752ec45d2fe9164220d08aa1fde55cc3a3a68f27fdf1d8b";

fn one_replace(text: String, old: &str, new: &str) -> String {
    assert_eq!(text.matches(old).count(), 1, "qualified adaptation: {old}");
    text.replace(old, new)
}

fn main() {
    let source = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join(SOURCE);
    println!("cargo:rerun-if-changed={}", source.display());
    let bytes = fs::read(source).expect("read the sealed normalized visitor");
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), SOURCE_SHA);
    let code = String::from_utf8(bytes).unwrap();
    let first = "#[derive(Default, Debug, PartialEq, Eq)]";
    let first_test = "#[cfg(test)]\nmod tests";
    assert_eq!(code.matches(first).count(), 1);
    assert_eq!(code.matches("type Failure").count(), 1);
    assert_eq!(code.matches(first_test).count(), 1);
    let visitor = code[code.find(first).unwrap()..code.find("type Failure").unwrap()].to_owned();
    let mut visitor = one_replace(visitor, "struct Versions {", "pub(crate) struct Versions {");
    for field in ["first_event", "first_raw", "next_raw"] {
        let old = format!("    {field}: Option<u64>,");
        let new = format!("    pub(crate) {field}: Option<u64>,");
        visitor = one_replace(visitor, &old, &new);
    }
    visitor = one_replace(
        visitor,
        "struct Overlap {",
        "pub(crate) struct Overlap {\n    epoch: u64,",
    );
    for (field, kind) in [
        ("range", "Range<u64>"),
        ("parent_slot", "u64"),
        ("parent_hash", "String"),
        ("versions", "Versions"),
    ] {
        let old = format!("    {field}: {kind},");
        let new = format!("    pub(crate) {field}: {kind},");
        visitor = one_replace(visitor, &old, &new);
    }
    for (old, new) in [
        (
            "    fn new(range:",
            "    pub(crate) fn new(epoch: u64, range:",
        ),
        (
            "            parent_slot: range.start - 1,",
            "            epoch,\n            parent_slot: range.start - 1,",
        ),
        (
            "    fn validate(&self, count: u64)",
            "    pub(crate) fn validate(&self, count: u64, require_terminal_block: bool)",
        ),
        (
            "|| self.parent_slot != self.range.end - 1",
            "|| (require_terminal_block && self.parent_slot != self.range.end - 1)\n            || self.parent_slot < self.range.start",
        ),
        ("value.epoch != 168", "value.epoch != self.epoch"),
    ] {
        visitor = one_replace(visitor, old, new);
    }
    visitor = one_replace(
        visitor,
        "    envelope_count: usize,",
        "    envelope_count: usize,\n    compare_epoch_events: bool,",
    );
    visitor = one_replace(
        visitor,
        "            envelope_count: 0,",
        "            envelope_count: 0,\n            compare_epoch_events: false,",
    );
    visitor = one_replace(
        visitor,
        "    fn update_version(&mut self, raw: u64) -> u64 {",
        r#"    pub(crate) fn with_epoch_events(mut self) -> Self {
        self.compare_epoch_events = true;
        self
    }

    fn update_version(&mut self, raw: u64) -> u64 {"#,
    );
    visitor = one_replace(
        visitor,
        r#"            || value.num_reward_partitions.is_some()
            || value.updates.iter().next().is_some()
        {
            self.error
                .get_or_insert("unexpected nonempty or misplaced epoch envelope");
        }"#,
        r#"            || (!self.compare_epoch_events
                && (value.num_reward_partitions.is_some() || value.updates.iter().next().is_some()))
        {
            self.error.get_or_insert("unexpected nonempty or misplaced epoch envelope");
            return;
        }
        if self.compare_epoch_events {
            let mut normalized = EpochMeta::new_boxed();
            normalized.epoch = value.epoch;
            normalized.start_slot = value.start_slot;
            normalized.slot_count = value.slot_count;
            normalized.first_block_slot = value.first_block_slot;
            normalized.num_reward_partitions = value.num_reward_partitions;
            for (account, data) in value.updates.iter() {
                let update = AccountUpdateView {
                    pubkey: account.pubkey,
                    lamports: account.lamports,
                    owner: account.owner,
                    executable: account.executable,
                    rent_epoch: account.rent_epoch,
                    write_version: self.update_version(account.write_version),
                    data,
                };
                if normalized.updates.push(&update).is_err() {
                    self.error.get_or_insert("epoch update exceeds its original arena");
                    return;
                }
            }
            self.digest.on_epoch(&normalized);
        }"#,
    );
    let tests = one_replace(
        code[code.find(first_test).unwrap()..].to_owned(),
        "let slot = BOOTSTRAP + 1;",
        "let slot = 101;",
    );
    let tests = one_replace(
        tests,
        "Overlap::new(slot..slot + 1, BASE_ANCHOR, None)",
        "Overlap::new(168, slot..slot + 1, \"fixture\", None)",
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("normalized.rs");
    fs::write(out, format!("{IMPORTS}\n{visitor}\n{COMPARE}\n{tests}")).unwrap();
}

const IMPORTS: &str = r#"
use std::{io, mem, ops::Range};
use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{SemanticDigest, SlotKind, SlotVisitor},
    block_metas::BlockNotification, entries::EntryRecord,
    epochs::EpochMeta, transactions::Transaction,
};
use lencode::prelude::*;
use sha2::{Digest, Sha256};
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
"#;

const COMPARE: &str = r#"
pub(crate) fn compare(label: &str, left: &Overlap, right: &Overlap) -> io::Result<[u8; 32]> {
    if left.range != right.range || left.frames.len() != right.frames.len() {
        return Err(invalid("comparison range or frame count differs"));
    }
    if let Some((left_frame, _)) = left.frames.iter().zip(&right.frames).find(|(a, b)| a != b) {
        return Err(io::Error::new(io::ErrorKind::InvalidData,
            format!("{label} normalized event mismatch at slot {}", left_frame.slot)));
    }
    if left.parent_hash != right.parent_hash || left.parent_slot != right.parent_slot {
        return Err(invalid("overlap terminal block differs"));
    }
    let mut digest = Sha256::new();
    for frame in &left.frames {
        digest.update(frame.slot.to_le_bytes());
        digest.update(frame.digest);
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
#[test]
fn full_prefix_normalizes_epoch_writes_and_preserves_their_values() {
    fn encode(raw: u64, lamports: u64, partitions: u64) -> [u8; 32] {
        let mut visitor = Overlap::new(266, 101..102, "fixture", Some(101..102)).with_epoch_events();
        visitor.on_slot_start(101, SlotKind::Block);
        let mut meta = EpochMeta::new_boxed();
        meta.epoch = 266;
        meta.start_slot = 101;
        meta.slot_count = 1;
        meta.first_block_slot = 101;
        meta.num_reward_partitions = Some(partitions);
        meta.updates.push(&AccountUpdateView {
            pubkey: Default::default(), lamports, owner: Default::default(),
            executable: false, rent_epoch: 0, write_version: raw, data: &[17],
        }).unwrap();
        visitor.on_epoch(&meta);
        assert!(visitor.error.is_none());
        visitor.versions.finish_slot().unwrap();
        assert_eq!(visitor.versions.next_raw, Some(raw + 1));
        visitor.digest.finish().unwrap()
    }
    assert_eq!(encode(12, 2, 3), encode(1200, 2, 3));
    assert_ne!(encode(12, 2, 3), encode(1200, 3, 3));
    assert_ne!(encode(12, 2, 3), encode(1200, 2, 4));
}
"#;
