//! Private failure-context reproduction using an entry-bounded worker.
//! The old parent requires an epoch/root output range, so it retains that request.
//! The exact worker rejects every entry after96335554 before decoding or mutation.
//! Neither a target stop nor any produced artifact qualifies an epoch or root.
#![recursion_limit = "256"]
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = "90474659be2a4a7d1cc9d4dfe3d5ab1587adb1b388b83163b2bf16c771624f66";
    pub const WORKER: &str = "b99691fd5995fe5f06e508cfd8f156b8e5cb7342ddab503fb2383e42e712d025";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
    pub const RUNTIME: &str = "solana-v1.6.25";
    pub const REVISION: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";
    pub const WORKER_ID: &str = "jetstreamer-historical-worker-v1-6-25";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_335_554;
    pub const TERMINAL: u64 = 96_767_522;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    pub const MINIMUM_FREE: u64 = 548_289_182_611;
    pub const MAX_SCRATCH: u64 = 300_000_000_000;
    pub const MAX_RUNTIME: u64 = 3600;
    pub const ENFORCED_FREE: u64 = 1_511_435_598_739;
    pub const MEMORY_RESERVE: u64 = 448u64 << 30;
    pub const INITIAL_AVAILABLE: u64 = 576u64 << 30;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[
        SNAPSHOT_NAME,
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst",
    ];
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-stop-v1";
    pub const CAPABILITY_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-input-capability-v1";
    pub const GUARD_SCHEMA: &str = "jetstreamer-private-epoch223-warmup-guard-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-warmup-resource-";
    pub const ROOT_PREFIX: &str = "qualification-223-v1625-prefix-warmup-";
}
include!("epoch223_warmup_resource_shared.rs");
