//! Private canonical-root prefix attempt; no full-epoch peak or publication authority.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-203-prefix.jet";
    pub const PARENT_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 203;
    pub const TARGET: u64 = 88_127_580;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 87_695_516;
    pub const MINIMUM_FREE: u64 = 3_185_678_193_366;
    pub const MAX_SCRATCH: u64 = 768 << 30;
    pub const MAX_RUNTIME: u64 = 259200;
    pub const SNAPSHOT_SIZE: u64 = 8_142_103_526;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch203-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch203-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch203-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-203-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "root-prefix-resource-203-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    #[cfg(test)]
    root_profile_tests!();
}
fn main() {
    bounded_resource_runner::main();
}
