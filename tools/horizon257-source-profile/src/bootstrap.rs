//! Separate expensive input verification from the invocation's 60-second admission lease.
use super::{hash, read_checked};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const SNAPSHOT: &str = "/var/lib/jetstreamer/horizon-contiguous-257-260-current-46b4b4a-v1/snapshot-111022755-8bRdfjkM7Lst2wWtAyv56VKTprAYt1DKPuVy2HzK1wX3.tar.zst";
const FILES: &[(&str, &str, u64)] = &[
    (
        SNAPSHOT,
        "3e2b236f2cba29fbfe40f39f133fe9c845df9280e3fc6dd1cb70e4e018a4744d",
        15020667485,
    ),
    (
        "/var/lib/jetstreamer/horizon253255-node-index-20261118-v2/jetstreamer-node",
        "2789f8211dafc4230a084910867db99699e6470b4a08a6fd8cc6dc00bf080f32",
        49064824,
    ),
    (
        "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15",
        "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
        6519904,
    ),
    (
        "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2",
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        20144,
    ),
];
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn check_file(path: &Path, digest: &str, len: u64) -> Result<Value> {
    ensure!(
        path.canonicalize()? == path && path.is_absolute(),
        "noncanonical asset"
    );
    for p in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted ancestors"
        );
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1
            && m.len() == len,
        "asset custody/length"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let id = identity(&m);
    ensure!(identity(&f.metadata()?) == id, "asset open race");
    let mut h = Sha256::new();
    let mut buf = vec![0; 1 << 20];
    let mut n = 0;
    loop {
        let count = f.read(&mut buf)?;
        if count == 0 {
            break;
        }
        n += count as u64;
        ensure!(n <= len, "asset grew");
        h.update(&buf[..count]);
    }
    ensure!(
        n == len
            && format!("{:x}", h.finalize()) == digest
            && identity(&f.metadata()?) == id
            && identity(&fs::symlink_metadata(path)?) == id,
        "asset changed or hash differs: {}",
        path.display()
    );
    Ok(json!({"path":path,"sha256":digest,"identity":id}))
}
pub fn measure() -> Result<Value> {
    let sealed = Path::new("/var/lib/jetstreamer/horizon257-source-ranges-20261120-v1");
    let native: Value = serde_json::from_slice(&read_checked(
        sealed,
        "native-comparison.json",
        16384,
        "63ba26a3f981663b7b2dfdfccb3fede543fc5a65ee4e7d1a069765c1da099f4a",
    )?)?;
    ensure!(
        native["total_blocks"] == 144
            && native["total_sections"] == 225181
            && native["all_cids_checked"] == true,
        "native comparison"
    );
    let original: Value = serde_json::from_slice(&read_checked(
        Path::new(SNAPSHOT).parent().unwrap(),
        "deployment-seal-receipt.json",
        16384,
        "94359e4d3bc0b89edf5b75d44d58d5c59fab8676c92a6461ece5145cdd0e55a9",
    )?)?;
    ensure!(
        original["members"]
            .as_array()
            .context("snapshot seal")?
            .iter()
            .any(
                |m| m["name"] == Path::new(SNAPSHOT).file_name().unwrap().to_str().unwrap()
                    && m["sha256"] == FILES[0].1
                    && m["bytes"] == FILES[0].2
                    && m["mode"] == "0444"
            ),
        "snapshot seal does not bind selected input"
    );
    let manifest: Value = serde_json::from_slice(&read_checked(
        Path::new(super::MANIFEST),
        super::MANIFEST_FILE,
        16384,
        "ae1086309d65ced3a7024c073c3f2ed57fe9aef60084f3934fe9796ebd304027",
    )?)?;
    let roots = super::manifest::validate(&manifest)?;
    let files = FILES
        .iter()
        .map(|&(path, sha, len)| check_file(Path::new(path), sha, len))
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"schema":"horizon257-bootstrap-inputs-v1","epoch":257,"files":files,"singleton_manifest":roots,"corrected_ranges_sha256":native["candidate_sha256"],"native_window_comparison_sha256":hash(&read_checked(sealed,"native-comparison.json",16384,"63ba26a3f981663b7b2dfdfccb3fede543fc5a65ee4e7d1a069765c1da099f4a")?),"all_native_input_bytes_verified":true,"ordinary_compact_payloads_verified":false,"native_runtime_qualified":false,"admission_authorized":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )
}
