//! Fixed epoch 223 source; existing sealed deployments remain unchanged.
mod profile {
    pub(super) const EPOCH: u64 = 223;
    pub(super) const PROTECTED_FLEET: bool = false;
    pub(super) const PLAN_SCHEMA: &str = "horizon-epoch223-bootstrap-prepare-plan-v1";
    pub(super) const RECEIPT_SCHEMA: &str = "horizon-epoch223-bootstrap-prepared-v1";
    pub(super) const MINIMUM_PROTECTED_FREE: u64 = 1_812_422_681_711;
    pub(super) const FILENAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub(super) const OBJECT: super::epoch141_ledger_common::ObjectSpec =
        super::epoch141_ledger_common::ObjectSpec {
            bucket: "mainnet-beta-ledger-us-ny5",
            name: "96335538/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst",
            generation: "1631874643386184",
            size: 9_815_262_303,
            crc: "cV1Wjg==",
            md5: "NmLA5GiE4J+FtPUflKI55Q==",
            uri: "gs://mainnet-beta-ledger-us-ny5/96335538/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst#1631874643386184",
        };
}
include!("bootstrap_prepare.rs");
