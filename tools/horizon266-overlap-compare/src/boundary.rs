//! Compare account histories within the first produced block of epoch 266.
//! This proves a private checkpoint witness. The retained archive supplies
//! the published event order and its original write-version assignments.

use jetstreamer_horizon::{
    account_updates::AccountUpdateView,
    archive::{SemanticDigest, SlotVisitor},
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const SLOT: u64 = 114_912_004;
pub(crate) const WRITES: usize = 430_340;

#[derive(Default)]
pub(crate) struct PreAccountBatch {
    histories: BTreeMap<[u8; 32], Vec<[u8; 32]>>,
    versions: Vec<u64>,
}

impl PreAccountBatch {
    pub(crate) fn push(&mut self, version: u64, update: &AccountUpdateView<'_>) -> bool {
        if self.versions.len() == WRITES {
            return false;
        }
        let mut digest = SemanticDigest::new();
        digest.on_pre_account_update(
            SLOT,
            &AccountUpdateView {
                write_version: 0,
                ..*update
            },
        );
        let Ok(content) = digest.finish() else {
            return false;
        };
        self.histories
            .entry(update.pubkey.to_bytes())
            .or_default()
            .push(content);
        self.versions.push(version);
        true
    }

    pub(crate) fn seal(self) -> Option<[u8; 32]> {
        self.digest(WRITES)
    }

    fn digest(mut self, count: usize) -> Option<[u8; 32]> {
        if self.versions.len() != count || count == 0 {
            return None;
        }
        self.versions.sort_unstable();
        if !self
            .versions
            .windows(2)
            .all(|pair| pair[0].checked_add(1) == Some(pair[1]))
        {
            return None;
        }
        let mut digest = Sha256::new();
        digest.update(b"jetstreamer-epoch266-per-account-boundary-v1");
        digest.update(SLOT.to_le_bytes());
        digest.update((count as u64).to_le_bytes());
        digest.update(self.versions[0].to_le_bytes());
        digest.update((self.histories.len() as u64).to_le_bytes());
        for (key, history) in self.histories {
            digest.update(key);
            digest.update((history.len() as u64).to_le_bytes());
            for content in history {
                digest.update(content);
            }
        }
        Some(digest.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(events: &[(u8, u64, u64)]) -> PreAccountBatch {
        let mut batch = PreAccountBatch::default();
        for &(key, value, version) in events {
            assert!(batch.push(
                version,
                &AccountUpdateView {
                    pubkey: [key; 32].into(),
                    lamports: value,
                    owner: Default::default(),
                    executable: false,
                    rent_epoch: 0,
                    write_version: version,
                    data: &[1, 2, 3],
                }
            ));
        }
        batch
    }

    #[test]
    fn accepts_only_per_account_history_equivalence_with_same_version_extent() {
        let reference = batch(&[(1, 10, 50), (2, 30, 51), (1, 20, 52)]).digest(3);
        assert!(reference.is_some());
        assert_eq!(
            reference,
            batch(&[(2, 30, 50), (1, 10, 51), (1, 20, 52)]).digest(3)
        );
        assert_ne!(
            reference,
            batch(&[(1, 20, 50), (2, 30, 51), (1, 10, 52)]).digest(3)
        );
        assert_ne!(
            reference,
            batch(&[(1, 10, 50), (2, 31, 51), (1, 20, 52)]).digest(3)
        );
        assert_ne!(
            reference,
            batch(&[(1, 10, 51), (2, 30, 52), (1, 20, 53)]).digest(3)
        );
        assert!(
            batch(&[(1, 10, 50), (2, 30, 50), (1, 20, 52)])
                .digest(3)
                .is_none()
        );
        assert!(
            batch(&[(1, 10, 50), (2, 30, 52), (1, 20, 53)])
                .digest(3)
                .is_none()
        );
        assert!(batch(&[(1, 10, 50), (2, 30, 51)]).digest(3).is_none());
    }
}
