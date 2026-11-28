"""Derive a standalone 167 reader from the two exactly qualified sources."""
import argparse
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parents[1]
NORMALIZED = SCRIPTS/"horizon_epoch168_joint_capacity_20261126_v1/joint-source-compare/joint_compare.rs"
RETAINED = HERE.parent/"retained_overlap.rs"
NORMALIZED_SHA = "5541b615993ca7b52752ec45d2fe9164220d08aa1fde55cc3a3a68f27fdf1d8b"
RETAINED_SHA = "ed8ae8826cb51ee9e879414eb430c1bc1d49bb669a94de742027853ac2013b1c"


def checked(path, expected):
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(f"qualified source changed: {path}")
    return data.decode()


def interval(text, first, last):
    if text.count(first) != 1 or text.count(last) != 1:
        raise ValueError("ambiguous extraction bounds in qualified source")
    begin = text.index(first)
    end = text.index(last, begin)
    return text[begin:end]


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"ambiguous qualified source adaptation: {old}")
    return text.replace(old, new)


def write(path, text):
    with path.open("x") as file:
        file.write(text)


def stage(out):
    normalized = checked(NORMALIZED, NORMALIZED_SHA)
    retained = checked(RETAINED, RETAINED_SHA)
    visitor = interval(normalized, "#[derive(Default, Debug, PartialEq, Eq)]", "fn file_identity(")
    visitor = replace(visitor, "value.epoch != 168", "value.epoch != 167")
    visitor = replace(visitor, "joint_raw_start={} joint_raw_end_exclusive={}",
                      "retry_raw_start={} retry_raw_end_exclusive={}")
    tests = normalized[normalized.index("#[cfg(test)]"):]
    tests = replace(tests, "BOOTSTRAP + 1", "SEAM + 1")
    tests = replace(tests, "BASE_ANCHOR, None", "ANCHOR, None")
    listener_imports = """use std::{io::{self, Read, Seek}, mem, ops::Range};
use jetstreamer_horizon::{account_updates::AccountUpdateView,
    archive::{ArchiveReader, SemanticDigest, SlotKind, SlotVisitor}, block_metas::BlockNotification,
    entries::EntryRecord, epochs::EpochMeta, transactions::Transaction};
use lencode::prelude::*;
use sha2::{Digest, Sha256};
"""
    write(out/"normalized.rs", listener_imports+visitor+tests)

    constants = interval(retained, "const SEAM:", "fn require(")
    constants = "\n".join(line for line in constants.splitlines()
                            if not line.startswith("const PREVIOUS_HASH:"))+"\n"
    identity = interval(retained, "fn require(", "#[derive(Default)]")
    header = interval(retained, "    let mut header = Vec::new();", "    let mut window = Window")
    frames = interval(retained, "    decoder.set_consumption(window.consumption());",
                      "    require(\n        file.stream_position()? == LENGTH")
    frames = replace(frames, "decode_slot_frame(SEAM, &mut window)?;",
                     "decode_slot_frame(SEAM + 1, &mut window)?;")
    frames = replace(frames, """        require(
            window.valid,
            "slot coverage, ancestry, checkpoint, or account write mismatch",
        )?;""", """        if let Some(reason) = window.error {
            return Err(format!("retained bucket {first}: {reason}").into());
        }""")
    disk_imports = """use std::{fs::{File, OpenOptions}, io::{self, Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt}, path::Path};
use jetstreamer_horizon::archive::{
    BucketDecoder, BucketHeader, BucketIndexEntry, FORMAT_VERSION_V2, MAX_FILE_HEADER_BYTES,
    SlotVisitor, parse_file_header};
use lencode::prelude::*;
use super::{Failure, Overlap};
"""
    begin = """
pub(super) fn read(path: &Path) -> Result<Overlap, Failure> {
    let mut file = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    check_file(&file, path)?;
"""
    bounds = "    let mut window = Overlap::new(SEAM+1..END, SEAM_HASH, None);\n"
    end = """    require(file.stream_position()? == LENGTH && window.parent_hash == LAST_HASH,
            "retained window lacks the exact physical terminal")?;
    window.validate(END - SEAM - 1)?;
    check_file(&file, path)?;
    let reopened = OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    check_file(&reopened, path)?;
    Ok(window)
}
"""
    write(out/"retained.rs", disk_imports+constants+identity+begin+header+bounds+frames+end)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700)
    stage(args.output)
