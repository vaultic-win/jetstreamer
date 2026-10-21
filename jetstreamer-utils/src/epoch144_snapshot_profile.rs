//! Compile-time epoch144 retained-prefix restart source, metadata only.
//! Restore and continuation require separately qualified implementations.
pub(super) const EPOCH: u64 = 144;
pub(super) const GENERATION: &str = "1634786788446253";
pub(super) const SIZE: u64 = 2_569_233_422;
pub(super) const CRC: &str = "K4VB8A==";
pub(super) const MD5: &str = "9XLFNdvEJOFXo9YPOsNBOA==";
pub(super) const URI: &str = "gs://mainnet-beta-ledger-us-ny5/62639490/snapshot-62639490-59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT.tar.zst#1634786788446253";
pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
    super::epoch141_ledger_common::ObjectSpec {
        bucket: "mainnet-beta-ledger-us-ny5",
        name: "62639490/snapshot-62639490-59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT.tar.zst",
        generation: GENERATION,
        size: SIZE,
        crc: CRC,
        md5: MD5,
        uri: URI,
    };
pub(super) const METADATA_SCHEMA: &str = "jetstreamer-epoch144-snapshot-metadata-receipt-v1";
pub(super) const METADATA_PLAN_SCHEMA: &str = "jetstreamer-epoch144-snapshot-metadata-plan-v1";
