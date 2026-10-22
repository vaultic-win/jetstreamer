#![deny(missing_docs)]
//! Shared utilities for Jetstreamer components.
//!
//! Currently this crate provides helpers for spawning local ClickHouse
//! instances that were previously part of the deprecated Geyser plugin crate.

/// ClickHouse process management helpers.
pub mod clickhouse;

/// Bounded diagnostic assembly of pinned Solana v1.4.25 data shreds.
pub mod horizon_legacy_shred;

/// Bounded diagnostic decoding of pinned Solana v1.4.25 entry batches.
pub mod horizon_legacy_entry;

/// Bounded diagnostic verification of pinned legacy entry/tick/PoH chains.
pub mod horizon_legacy_poh;

/// Raw diagnostic acquisition independent of strict legacy recovery qualification.
pub mod horizon_legacy_acquisition;
/// Non-authorizing byte interpretation of an acquired legacy target, preserving connectivity.
pub mod horizon_legacy_byte_diagnostic;
/// Exact-key diagnostic binding from native legacy candidates to complete PoH chains.
pub mod horizon_legacy_recovery;

/// Explicit pinned Solana v1.5.6 diagnostic legacy-record recovery profile.
pub mod horizon_legacy_v1_5_6;

/// Bounded diagnostic collection of a complete flat RocksDB tar file set.
pub mod horizon_ledger_tar;

/// Digest-bound diagnostic collection of a retained bzip2 RocksDB tar.
pub mod horizon_ledger_bzip;

/// Optional, diagnostic complete-census native RocksDB resolution, not source completeness.
#[cfg(feature = "sst-capability-tests")]
pub mod horizon_ledger_native;

/// Re-exported ClickHouse utility types and functions.
pub use clickhouse::{
    ClickhouseError, ClickhouseStartResult, start, start_client, stop, stop_sync,
};
