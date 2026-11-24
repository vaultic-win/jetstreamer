use solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey};
use std::{
    env,
    fs::OpenOptions,
    io::{self, BufWriter, Write},
    path::PathBuf,
};

pub(crate) fn directory(slot: Slot) -> Option<PathBuf> {
    match slot {
        99_368_200 | 99_368_201 => {
            env::var_os("JETSTREAMER_EPOCH230_BANK_TRACE_DIR").map(PathBuf::from)
        }
        _ => None,
    }
}

/// Each record contains a 32-byte public key followed by its 32-byte account hash.
pub(crate) fn capture_account_hashes(slot: Slot, hashes: &[(Pubkey, Hash)]) -> io::Result<()> {
    let directory = match directory(slot) {
        Some(directory) => directory,
        None => return Ok(()),
    };
    let mut ordered = hashes.to_vec();
    ordered.sort_unstable_by_key(|(pubkey, _)| *pubkey);
    let path = directory.join(format!("slot-{}-account-hashes.bin", slot));
    let mut output = BufWriter::new(OpenOptions::new().write(true).create_new(true).open(path)?);
    for (pubkey, hash) in ordered {
        output.write_all(pubkey.as_ref())?;
        output.write_all(hash.as_ref())?;
    }
    output.flush()?;
    output.get_ref().sync_all()?;
    eprintln!(
        "epoch230_account_hashes slot={} records={}",
        slot,
        hashes.len()
    );
    Ok(())
}
