use crate::bank::RewardInfo;
use solana_sdk::{clock::Slot, hash::Hash, pubkey::Pubkey};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

pub(crate) fn directory(slot: Slot) -> Option<PathBuf> {
    match slot {
        99_368_200 | 99_368_201 => {
            env::var_os("JETSTREAMER_EPOCH230_BANK_TRACE_DIR").map(PathBuf::from)
        }
        _ => None,
    }
}

fn write_once(path: &Path, bytes: &[u8]) -> io::Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut output) => {
            output.write_all(bytes)?;
            output.sync_all()?;
            fs::File::open(path.parent().expect("epoch 230 trace directory"))?.sync_all()
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if fs::read(path)?.as_slice() == bytes {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "epoch 230 trace changed",
                ))
            }
        }
        Err(error) => Err(error),
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
    let mut output = Vec::with_capacity(64 * hashes.len());
    for (pubkey, hash) in ordered {
        output.extend_from_slice(pubkey.as_ref());
        output.extend_from_slice(hash.as_ref());
    }
    write_once(&path, &output)?;
    eprintln!(
        "epoch230_account_hashes slot={} records={}",
        slot,
        hashes.len()
    );
    Ok(())
}

/// Save the bank's block-level rewards, including eager rent and the fee payout.
pub(crate) fn capture_rewards(slot: Slot, rewards: &[(Pubkey, RewardInfo)]) -> io::Result<()> {
    let directory = match directory(slot) {
        Some(directory) => directory,
        None => return Ok(()),
    };
    let path = directory.join(format!("slot-{}-block-rewards.tsv", slot));
    let mut output = Vec::new();
    for (pubkey, reward) in rewards {
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{:?}",
            pubkey, reward.reward_type, reward.lamports, reward.post_balance, reward.commission,
        )?;
    }
    write_once(&path, &output)
}
