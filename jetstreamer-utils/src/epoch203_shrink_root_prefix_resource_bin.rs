//! Separate shrink-cap canonical-root qualification; never ordinary replay or publication.
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
    pub const PLAN_SCHEMA: &str =
        "jetstreamer-private-epoch203-shrink-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch203-shrink-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch203-shrink-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-203-shrink-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "shrink-root-prefix-resource-203-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc";
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

#[cfg(test)]
mod profile_tests {
    use super::profile::*;
    #[test]
    fn capped_worker_keeps_the_original_root_and_resource_contract() {
        assert_eq!(
            WORKER,
            "4aeca56378a4bb2c55d0e590c1e334c4afa6a375a2c0d94894b412bea261f1cc"
        );
        assert_eq!(
            PARENT_SHA,
            "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d"
        );
        assert_eq!(TARGET, 88_127_580);
        assert_eq!(MAX_SCRATCH, 768 << 30);
        assert_eq!(MAX_RUNTIME, 259200);
        assert_eq!(MINIMUM_FREE, 3_185_678_193_366);
        assert_eq!(RAYON_THREADS, 16);
        assert!(ROOT_PREFIX.starts_with("shrink-"));
        assert!(PLAN_SCHEMA.contains("-shrink-root-prefix-"));
        assert!(RESULT_SCHEMA.contains("-shrink-root-prefix-"));
    }
}
