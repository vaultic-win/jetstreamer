//! Separate v1.6.20 first16-entry qualification; no root or publication authority.
//! The old parent requires an epoch/root output range, so it retains that request.
//! The exact worker rejects every entry after 96335554 before decoding or mutation.
//! Neither a target stop nor any produced artifact qualifies an epoch or root.
#![recursion_limit = "256"]
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = "99f643ff0dbbcd37d1fbc524a1c1088d7273c7fc91330df059d30d51b8b0fcd4";
    pub const WORKER: &str = "52d6c86a8103b8965ca68ead96af471a7899a0a0e6e69c48989b39fd5d922f0c";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_20";
    pub const RUNTIME: &str = "solana-v1.6.20";
    pub const REVISION: &str = "77bdb45d4af61fc687161ec06cc0178ff79726d5";
    pub const WORKER_ID: &str = "jetstreamer-historical-worker-v1-6-20";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_335_554;
    pub const TERMINAL: u64 = 96_767_522;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    pub const MINIMUM_FREE: u64 = 2_300_000_000_000;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 3600;
    pub const ENFORCED_FREE: u64 = 2_000_000_000_000;
    pub const MEMORY_RESERVE: u64 = 480u64 << 30;
    pub const INITIAL_AVAILABLE: u64 = 608u64 << 30;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[
        SNAPSHOT_NAME,
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst",
    ];
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-warmup-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-warmup-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-warmup-stop-v1";
    pub const CAPABILITY_SCHEMA: &str =
        "jetstreamer-private-epoch223-v1620-warmup-input-capability-v1";
    pub const GUARD_SCHEMA: &str = "jetstreamer-private-epoch223-v1620-warmup-guard-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-v1620-warmup-resource-";
    pub const ROOT_PREFIX: &str = "qualification-223-v1620-prefix-warmup-";
}
include!("epoch223_warmup_resource_shared.rs");
