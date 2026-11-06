//! Generation-pinned epoch 163 bootstrap; compressed acquisition only.
pub(super) const EPOCH: u64 = 163;
pub(super) const FILENAME: &str =
    "snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst";
pub(super) const GENERATION: &str = "1634787272998262";
pub(super) const SIZE: u64 = 1_901_405_026;
pub(super) const CRC: &str = "bpbuVg==";
pub(super) const MD5: &str = "GIvvcL0yXKjY2dumxRsJrg==";
pub(super) const URI: &str = "gs://mainnet-beta-ledger-us-ny5/70415741/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst#1634787272998262";
pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
    super::epoch141_ledger_common::ObjectSpec {
        bucket: "mainnet-beta-ledger-us-ny5",
        name: "70415741/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst",
        generation: GENERATION,
        size: SIZE,
        crc: CRC,
        md5: MD5,
        uri: URI,
    };
pub(super) const METADATA_SCHEMA: &str = "jetstreamer-epoch163-snapshot-metadata-receipt-v1";
pub(super) const METADATA_PLAN_SCHEMA: &str = "jetstreamer-epoch163-snapshot-metadata-plan-v1";
pub(super) const PLAN_SCHEMA: &str = "jetstreamer-epoch163-snapshot-download-plan-v1";
pub(super) const RECEIPT_SCHEMA: &str = "jetstreamer-epoch163-snapshot-download-receipt-v1";
pub(super) const STOP_INTENT_SCHEMA: &str = "jetstreamer-epoch163-snapshot-download-stop-intent-v1";
pub(super) const STOP_COMPLETION_SCHEMA: &str =
    "jetstreamer-epoch163-snapshot-download-stop-completion-v1";
pub(super) const INITIAL_GUARD_SCHEMA: &str =
    "jetstreamer-epoch163-snapshot-download-initial-guard-v1";
