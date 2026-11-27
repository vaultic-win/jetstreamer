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
"#;
