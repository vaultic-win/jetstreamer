//! Original-owner admission, using the same native cohort contract as the node importer.
#[allow(dead_code)]
#[path = "../../jetstreamer-node/src/cohort_publication.rs"]
mod cohort;
#[cfg(receiver_fixture)]
mod fixture;

use anyhow::{Context, Result, ensure};
use jetstreamer_node::segment_manifest::sha256_hex_string as hex;
use serde_json::json;
use std::{fs, os::unix::fs::MetadataExt, path::Path};

fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(s.len() == 64 && s.bytes().all(|x| x.is_ascii_hexdigit()));
    let mut value = [0; 32];
    for (i, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(value)
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(receiver_fixture)]
    if let [cmd, dir, fingerprint, bootstrap, checkpoint, last] = args.as_slice()
        && cmd == "fixture"
    {
        return fixture::publish(
            Path::new(dir),
            166,
            digest(fingerprint)?,
            digest(bootstrap)?,
            digest(checkpoint)?,
            digest(last)?,
        );
    }
    #[cfg(receiver_fixture)]
    if let [cmd, epoch, dir, fingerprint, bootstrap, checkpoint, last] = args.as_slice()
        && cmd == "fixture-epoch"
    {
        return fixture::publish(
            Path::new(dir),
            epoch.parse()?,
            digest(fingerprint)?,
            digest(bootstrap)?,
            digest(checkpoint)?,
            digest(last)?,
        );
    }
    let [cmd, epoch, receipt, fingerprint, other] = args.as_slice() else {
        anyhow::bail!("usage: admit EPOCH RECEIPT FINGERPRINT DISTINCT_TARGET");
    };
    ensure!(cmd == "admit");
    let other = Path::new(other);
    let m = fs::symlink_metadata(other)?;
    let a = cohort::admit_committed_cohort_receipt(
        Path::new(receipt),
        digest(fingerprint)?,
        &[epoch.parse()?],
        cohort::DestinationBinding {
            path: other,
            device: m.dev(),
            inode: m.ino(),
        },
    )
    .map_err(anyhow::Error::msg)?;
    let [member] = a.members.as_slice() else {
        anyhow::bail!("expected singleton");
    };
    a.revalidate().map_err(anyhow::Error::msg)?;
    println!(
        "{}",
        json!({"transaction":hex(&a.transaction_id),"source":a.source_path,
        "archive":member.archive_path,"sidecar":member.checksum_path,"sha256":hex(&member.sha256),
        "root_checkpoint_gate":a.root_checkpoint_gate,"uid":fs::metadata(&a.source_path).context("source owner")?.uid()})
    );
    Ok(())
}
