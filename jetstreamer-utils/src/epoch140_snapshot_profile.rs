//! Compile-time exact 60911751 snapshot identity; no caller-selectable cloud object.
pub(super) const EPOCH: u64 = 140;
pub(super) const FILENAME: &str =
    "snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst";
pub(super) const GENERATION: &str = "1634786631155900";
pub(super) const SIZE: u64 = 2_741_858_751;
pub(super) const CRC: &str = "wif3BA==";
pub(super) const MD5: &str = "bEVjbHoOexfklmZRKtsfSw==";
pub(super) const URI: &str = "gs://mainnet-beta-ledger-us-ny5/60911751/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst#1634786631155900";
pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
    super::epoch141_ledger_common::ObjectSpec {
        bucket: "mainnet-beta-ledger-us-ny5",
        name: "60911751/snapshot-60911751-GyFbDnPnUWrFStHKfwWC98xJpmBQKjLyJ9sMf2m6MrWR.tar.zst",
        generation: GENERATION,
        size: SIZE,
        crc: CRC,
        md5: MD5,
        uri: URI,
    };
pub(super) const PLAN_SCHEMA: &str = "jetstreamer-epoch140-snapshot-download-plan-v1";
pub(super) const METADATA_SCHEMA: &str = "jetstreamer-epoch140-snapshot-metadata-receipt-v1";
pub(super) const METADATA_PLAN_SCHEMA: &str = "jetstreamer-epoch140-snapshot-metadata-plan-v1";
pub(super) const RECEIPT_SCHEMA: &str = "jetstreamer-epoch140-snapshot-download-receipt-v1";
pub(super) const STOP_INTENT_SCHEMA: &str = "jetstreamer-epoch140-snapshot-download-stop-intent-v1";
pub(super) const STOP_COMPLETION_SCHEMA: &str =
    "jetstreamer-epoch140-snapshot-download-stop-completion-v1";
pub(super) const INITIAL_GUARD_SCHEMA: &str =
    "jetstreamer-epoch140-snapshot-download-initial-guard-v1";
