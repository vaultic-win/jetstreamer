//! Fixed epoch227 compressed input staging only; never restore/replay/publication.
mod profile {
    pub(super) const EPOCH: u64 = 227;
    pub(super) const PROTECTED_FLEET: bool = true;
    pub(super) const PLAN_SCHEMA: &str = "horizon-epoch227-bootstrap-prepare-plan-v1";
    pub(super) const RECEIPT_SCHEMA: &str = "horizon-epoch227-bootstrap-prepared-v1";
    // Full older203/223/225 future-growth protection plus thirteen-sample century floor.
    pub(super) const MINIMUM_PROTECTED_FREE: u64 = 3_615_543_542_675;
    pub(super) const FILENAME: &str =
        "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";
    pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
        super::epoch141_ledger_common::ObjectSpec {
            bucket: "mainnet-beta-ledger-us-ny5",
            name: "98063464/snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst",
            generation: "1632781197930817",
            size: 10_261_480_487,
            crc: "1B+EYQ==",
            md5: "OZLsTULdemOCogrGldWj5Q==",
            uri: "gs://mainnet-beta-ledger-us-ny5/98063464/snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst#1632781197930817",
        };
}
include!("bootstrap_prepare.rs");
