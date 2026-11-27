//! Select the supported 170 prefix and bind the retained replay's Bank to the closed bridge.
use super::{
    PrefixView,
    epoch167_assembly::{child_witness, doc, open},
    selected_prefix::{PrefixScope, verify_document},
};
use jetstreamer_horizon::archive::ArchiveReader;
use serde_json::{Value, json};
use std::{error::Error, fs::File, io, os::unix::fs::MetadataExt, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const ORIGINAL: &str = concat!(
    "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1/replacement-local3retry7-20261110-v1/",
    "replacement-local3retry10-20261121-v1/cold-retry13-20261122/private/",
    "destination-9d7fbc3a094253cd1318488f6a60e44900245948f42eba157699ae1df4828fd6/",
    "work/root-cohort-170-170/run-751461-1795386600702051609/archives/epoch-170.jet"
);
const CLOSED: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73726716-20261127-v1/CLOSED_BRIDGE_COMPARISON.json";
const CLOSED_SHA: &str = "1170a8a64a6d2e99c3ff06bf5d7829ce4474f1b0dfb184c8b3df720247937387";
const ORIGINAL_WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const BRIDGE_WORKER: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const FIRST: u64 = 73_440_000;
const STOP: u64 = 73_711_488;
const SEAM: u64 = 73_706_460;
const LENGTH: u64 = 74_610_089_740;
const BLOCK: &str = "6oTeUyUXUCDoM4dAbeBV9DDyLMKBXNyFRPsL48bUYmAU";
const BANK: &str = "ggS3hRABy7tV8UHdMZHdSUtb4Vt14VoSMdhJjg66JCK";

fn original_identity(file: &File) -> io::Result<()> {
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || (m.dev(), m.ino(), m.len()) != (64512, 113981980, LENGTH)
        || (m.mtime(), m.mtime_nsec()) != (1795523540, 877640313)
        || (m.ctime(), m.ctime_nsec()) != (1795523540, 877640313)
    {
        return Err(super::invalid("changed retained epoch 170 source"));
    }
    Ok(())
}

fn bridge_identity(file: &File) -> io::Result<Value> {
    let m = file.metadata()?;
    Ok(json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ]))
}

fn seam() -> Result<(Value, u64)> {
    let receipt = doc(Path::new(CLOSED), CLOSED_SHA, 0)?;
    let checkpoint = &receipt["checkpoints"][0];
    let bridge = &receipt["closed_segment"];
    if receipt["mode"] != "closed"
        || checkpoint["slot"] != SEAM
        || checkpoint["bank_hash"] != BANK
        || checkpoint["last_blockhash"] != BLOCK
        || checkpoint["next_write_version"] != bridge["raw_write_versions"]["start"]
    {
        return Err("closed bridge bootstrap changed".into());
    }
    let old = open(Path::new(ORIGINAL))?;
    original_identity(&old)?;
    let mut left = ArchiveReader::open(PrefixView::open(&old, 170, FIRST, STOP)?)?;
    let bridge_path = Path::new(
        bridge["path"]
            .as_str()
            .ok_or("missing closed bridge path")?,
    );
    let new = open(bridge_path)?;
    if bridge_identity(&new)? != bridge["identity"] {
        return Err("closed bridge identity changed".into());
    }
    let mut right = ArchiveReader::open(&new)?;
    let (before, old_cursor) = child_witness(&mut left, ORIGINAL_WORKER, 170, SEAM)?;
    let (after, new_cursor) = child_witness(&mut right, BRIDGE_WORKER, 170, SEAM)?;
    if before["slot_hashes"]["bank_hash"] != BANK
        || after["slot_hashes"]["bank_hash"] != BANK
        || before["slot_hashes"]["data_sha256"] != after["slot_hashes"]["data_sha256"]
        || Some(new_cursor) != checkpoint["next_write_version"].as_u64()
    {
        return Err("first-child Bank, SlotHashes bytes or bridge cursor mismatch".into());
    }
    original_identity(&open(Path::new(ORIGINAL))?)?;
    if bridge_identity(&open(bridge_path)?)? != bridge["identity"] {
        return Err("closed bridge path changed during first-child comparison".into());
    }
    Ok((
        json!({"schema":"horizon-epoch170-retained-prefix-bank-v1","checkpoint":checkpoint,
        "original":before,"bridge":after,"original_child_first_raw":old_cursor,
        "bridge_child_first_raw":new_cursor,"closed_comparison":{"path":CLOSED,"sha256":CLOSED_SHA}}),
        old_cursor,
    ))
}

pub(super) fn inspect() -> Result<()> {
    println!("{}", seam()?.0);
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let (bank, next) = seam()?;
    let mut result = verify_document(&PrefixScope {
        schema: "horizon-epoch170-private-selected-prefix-evidence-v1",
        path: ORIGINAL,
        epoch: 170,
        first: FIRST,
        physical_end: STOP,
        bytes: LENGTH,
        source_sha: "606d183c98201d039d83b037f696ce39e4c53a6be1963c79361190a63908a85d",
        seam: SEAM,
        seam_hash: BLOCK,
        next_raw: Some(next),
        check_identity: original_identity,
    })?;
    result["checkpoint_bank"] = bank;
    result["canonical_publication_authorized"] = false.into();
    println!("{result}");
    Ok(())
}
