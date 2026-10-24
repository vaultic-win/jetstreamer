//! Private epoch 225 measurement; no runtime, root, or publication promotion.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-225-canary.jet";
    pub const PARENT_SHA: &str = "";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 225;
    pub const TARGET: u64 = 97_202_500;
    pub const TERMINAL: u64 = 97_631_459;
    pub const INITIAL_REPLAY: u64 = 97_199_618;
    pub const MINIMUM_FREE: u64 = 3_185_678_193_366;
    pub const MAX_SCRATCH: u64 = 256 << 30;
    pub const MAX_RUNTIME: u64 = 3600;
    pub const SNAPSHOT_SIZE: u64 = 10_177_204_112;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch225-bounded-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch225-bounded-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch225-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-225-bounded-resource-";
    pub const ROOT_PREFIX: &str = "bounded-resource-225-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-97631459-EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    #[cfg(not(feature = "epoch225-v1-6-25-diagnostic"))]
    pub const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
    #[cfg(feature = "epoch225-v1-6-25-diagnostic")]
    pub const WORKER: &str = "74f805991023434932080b6db20385d36ec26d8a1dd9bbd7a33848099145859a";
    pub const WORKER_ENV: &str = if cfg!(feature = "epoch225-v1-6-25-diagnostic") {
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_25"
    } else {
        "JETSTREAMER_HISTORICAL_WORKER_V1_6_20"
    };
    pub const SNAPSHOT: &str = "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    #[cfg(test)]
    legacy_profile_tests!();
}
fn main() {
    bounded_resource_runner::main();
}
