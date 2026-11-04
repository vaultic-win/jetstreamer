//! Exact immutable ledger profile, shared only by its metadata and download tools.
#[allow(unused_imports)]
pub(super) use super::epoch141_ledger_common::{CRC, GENERATION, MD5, SIZE, URI};
pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
    super::epoch141_ledger_common::LEDGER_OBJECT;
pub(super) const EPOCH: u64 = 141;
pub(super) const FILENAME: &str = "rocksdb.tar.bz2";
pub(super) const PLAN_SCHEMA: &str = "jetstreamer-epoch141-ledger-download-plan-v1";
pub(super) const METADATA_PLAN_SCHEMA: &str = "jetstreamer-epoch141-ledger-metadata-plan-v1";
pub(super) const METADATA_SCHEMA: &str = "jetstreamer-epoch141-ledger-metadata-receipt-v1";
pub(super) const RECEIPT_SCHEMA: &str = "jetstreamer-epoch141-ledger-download-receipt-v1";
pub(super) const STOP_INTENT_SCHEMA: &str = "jetstreamer-epoch141-ledger-download-stop-intent-v1";
pub(super) const STOP_COMPLETION_SCHEMA: &str =
    "jetstreamer-epoch141-ledger-download-stop-completion-v1";
pub(super) const INITIAL_GUARD_SCHEMA: &str =
    "jetstreamer-epoch141-ledger-download-initial-guard-v1";
