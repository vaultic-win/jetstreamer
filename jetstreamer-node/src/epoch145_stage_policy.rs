//! Source-only review policy for one private epoch 145 qualification.
//!
//! This module performs no I/O and grants no replay or publication authority.
//! The existing focused parent records the 71-slot verification tail in the
//! diagnostic container. Canonical prefix extraction needs its own reviewed
//! implementation and receipts; it is deliberately not simulated here.

pub const EPOCH: u64 = 145;
pub const BOOTSTRAP: u64 = 62_639_490;
pub const OUTPUT_FIRST: u64 = 62_640_000;
pub const OUTPUT_LAST: u64 = 63_071_999;
pub const VERIFIED_TERMINAL: u64 = 63_072_070;
pub const WORKER_END_EXCLUSIVE: u64 = 63_936_000;
pub const SNAPSHOT_BYTES: u64 = 2_569_233_422;
pub const SNAPSHOT_SHA256: &str =
    "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae";
pub const WORKER_SHA256: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
pub const GENESIS_SHA256: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub const MANIFEST_SHA256: &str =
    "ec62e2ce730a28033e5626e7afdb59c2b6e73a2ce188ae1040a77a7a09e396c3";
pub const BOOTSTRAP_ACCOUNTS_HASH: &str = "59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT";
pub const TERMINAL_ACCOUNTS_HASH: &str = "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactScope<'a> {
    pub epoch: u64,
    pub bootstrap: u64,
    pub output_first: u64,
    pub output_last: u64,
    pub verification_terminal: u64,
    pub publication_through_epoch: u64,
    pub snapshot_bytes: u64,
    pub snapshot_sha256: &'a str,
    pub worker_sha256: &'a str,
    pub genesis_sha256: &'a str,
    pub trusted_manifest_sha256: &'a str,
    pub bootstrap_accounts_hash: &'a str,
    pub terminal_accounts_hash: &'a str,
}

impl Default for ExactScope<'static> {
    fn default() -> Self {
        Self {
            epoch: EPOCH,
            bootstrap: BOOTSTRAP,
            output_first: OUTPUT_FIRST,
            output_last: OUTPUT_LAST,
            verification_terminal: VERIFIED_TERMINAL,
            publication_through_epoch: EPOCH,
            snapshot_bytes: SNAPSHOT_BYTES,
            snapshot_sha256: SNAPSHOT_SHA256,
            worker_sha256: WORKER_SHA256,
            genesis_sha256: GENESIS_SHA256,
            trusted_manifest_sha256: MANIFEST_SHA256,
            bootstrap_accounts_hash: BOOTSTRAP_ACCOUNTS_HASH,
            terminal_accounts_hash: TERMINAL_ACCOUNTS_HASH,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub replay_first: u64,
    pub replay_count: u64,
    pub warmup_count: u64,
    pub canonical_output_count: u64,
    pub verification_tail_count: u64,
    pub focused_container_count: u64,
}

/// Validate only the exact proposal's geometry and pinned expected identities.
/// Equality here is not file verification. The production reader must perform
/// full descriptor-bound hashing, custody and receipt checks before execution.
pub fn validate_scope(scope: &ExactScope<'_>) -> Result<Geometry, &'static str> {
    if scope != &ExactScope::default() {
        return Err("scope or trusted input identity differs from exact epoch 145 proposal");
    }
    if scope.verification_terminal >= WORKER_END_EXCLUSIVE {
        return Err("verification terminal exceeds retained worker boundary");
    }
    let replay_first = scope.bootstrap.checked_add(1).ok_or("bootstrap overflow")?;
    let replay_count = scope
        .verification_terminal
        .checked_sub(replay_first)
        .and_then(|n| n.checked_add(1))
        .ok_or("replay range overflow")?;
    let canonical_output_count = scope
        .output_last
        .checked_sub(scope.output_first)
        .and_then(|n| n.checked_add(1))
        .ok_or("output range overflow")?;
    let warmup_count = scope
        .output_first
        .checked_sub(replay_first)
        .ok_or("warmup exceeds output start")?;
    let verification_tail_count = scope
        .verification_terminal
        .checked_sub(scope.output_last)
        .ok_or("trusted terminal precedes canonical output end")?;
    let focused_container_count = canonical_output_count
        .checked_add(verification_tail_count)
        .ok_or("focused range overflow")?;
    if replay_count != warmup_count + focused_container_count {
        return Err("replay and recording ranges do not reconcile");
    }
    Ok(Geometry {
        replay_first,
        replay_count,
        warmup_count,
        canonical_output_count,
        verification_tail_count,
        focused_container_count,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveExtent {
    pub epoch: u64,
    pub first_slot: u64,
    pub slot_count: u64,
}

/// A complete focused source and a canonical candidate have different ranges.
/// Never pass the unextracted focused container to a canonical epoch plugin.
pub fn require_focused_source(extent: ArchiveExtent) -> Result<(), &'static str> {
    let g = validate_scope(&ExactScope::default())?;
    if extent
        != (ArchiveExtent {
            epoch: EPOCH,
            first_slot: OUTPUT_FIRST,
            slot_count: g.focused_container_count,
        })
    {
        return Err("focused container does not bind the complete trusted-root span");
    }
    Ok(())
}

pub fn require_canonical_candidate(extent: ArchiveExtent) -> Result<(), &'static str> {
    let g = validate_scope(&ExactScope::default())?;
    if extent
        != (ArchiveExtent {
            epoch: EPOCH,
            first_slot: OUTPUT_FIRST,
            slot_count: g.canonical_output_count,
        })
    {
        return Err("canonical candidate must contain exactly all epoch 145 slots");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_plan_separates_509_warmup_432000_output_and_71_tail_slots() {
        assert_eq!(
            validate_scope(&ExactScope::default()).unwrap(),
            Geometry {
                replay_first: 62_639_491,
                replay_count: 432_580,
                warmup_count: 509,
                canonical_output_count: 432_000,
                verification_tail_count: 71,
                focused_container_count: 432_071,
            }
        );
    }

    #[test]
    fn epoch_end_is_not_a_substitute_for_the_later_trusted_root() {
        let scope = ExactScope {
            verification_terminal: OUTPUT_LAST,
            ..ExactScope::default()
        };
        assert!(validate_scope(&scope).is_err());
    }

    #[test]
    fn publication_boundary_cannot_include_epoch146() {
        let scope = ExactScope {
            publication_through_epoch: 146,
            ..ExactScope::default()
        };
        assert!(validate_scope(&scope).is_err());
    }

    #[test]
    fn bootstrap_inside145_would_omit_early_output() {
        let scope = ExactScope {
            bootstrap: OUTPUT_FIRST + 1,
            ..ExactScope::default()
        };
        assert!(validate_scope(&scope).is_err());
    }

    #[test]
    fn changed_worker_snapshot_or_trusted_hash_rejects() {
        let original = ExactScope::default();
        for changed in [
            ExactScope {
                snapshot_sha256: WORKER_SHA256,
                ..original.clone()
            },
            ExactScope {
                worker_sha256: SNAPSHOT_SHA256,
                ..original.clone()
            },
            ExactScope {
                terminal_accounts_hash: BOOTSTRAP_ACCOUNTS_HASH,
                ..original.clone()
            },
            ExactScope {
                trusted_manifest_sha256: GENESIS_SHA256,
                ..original
            },
        ] {
            assert!(validate_scope(&changed).is_err());
        }
    }

    #[test]
    fn full_focused_container_cannot_masquerade_as_canonical_epoch145() {
        let source = ArchiveExtent {
            epoch: EPOCH,
            first_slot: OUTPUT_FIRST,
            slot_count: 432_071,
        };
        assert!(require_focused_source(source).is_ok());
        assert!(require_canonical_candidate(source).is_err());
    }

    #[test]
    fn shortened_source_or_missing_final_epoch_slot_rejects() {
        let canonical = ArchiveExtent {
            epoch: EPOCH,
            first_slot: OUTPUT_FIRST,
            slot_count: 432_000,
        };
        assert!(require_canonical_candidate(canonical).is_ok());
        assert!(require_focused_source(canonical).is_err());
        assert!(
            require_canonical_candidate(ArchiveExtent {
                slot_count: 431_999,
                ..canonical
            })
            .is_err()
        );
    }
}
