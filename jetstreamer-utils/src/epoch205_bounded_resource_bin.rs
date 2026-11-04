//! Private fixed-work epoch 205 resource probe, never full-prefix qualification.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-205-canary.jet";
    pub const PARENT_SHA: &str = "025757b9b337abf05435c427f143f590d9bfa542b5e4493aae783c158b4f2d3d";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 205;
    pub const TARGET: u64 = 88_584_000;
    pub const TERMINAL: u64 = 88_991_050;
    pub const INITIAL_REPLAY: u64 = 88_559_362;
    // Rejection-only baseline: six-sample century floor plus a separate 416-GiB
    // experiment envelope (256 scratch + 128 archive + 32 buffer). Fresh
    // admission must recompute the century floor and add every older remaining
    // growth claim. This is not a measured peak or permission to add a lane.
    pub const MINIMUM_FREE: u64 = 231_874_716_783 + (416 << 30);
    pub const MAX_SCRATCH: u64 = 256 << 30;
    pub const MAX_RUNTIME: u64 = 21_600;
    pub const SNAPSHOT_SIZE: u64 = 8_225_957_010;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch205-bounded-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch205-bounded-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch205-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-205-bounded-resource-";
    pub const ROOT_PREFIX: &str = "bounded-resource-205-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-88559361-83H83cZe1j8pnukHcZiXxKRyvCNUAZjcR43Wv9aQtnYA.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88991050-BAsq3Vn4KyLYuLqrevCL2dnE1fjLyA6NSX9qQjG7VCDp.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "24b722b37fa87462876dc05916bafa98da13f095c95aaed7159e9008efa7352e";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    #[cfg(test)]
    legacy_profile_tests!();
}
fn main() {
    bounded_resource_runner::main();
}

#[cfg(test)]
mod profile_tests {
    use super::profile::*;

    #[test]
    fn exact205_measurement_is_neither_root_prefix_nor_full_epoch_admission() {
        const { assert!(!NATURAL_ROOT_FINISH) };
        assert_eq!(INITIAL_REPLAY, 88_559_362);
        assert_eq!(TARGET, 88_584_000);
        assert_eq!(TARGET - 88_560_000, 24_000);
        assert_eq!(TERMINAL, 88_991_050);
        assert_eq!(88_991_999 - TERMINAL, 949);
        const { assert!(TARGET < TERMINAL) };
        assert_eq!(MAX_SCRATCH, 256 << 30);
        assert_eq!(MINIMUM_FREE, 231_874_716_783 + (416 << 30));
        assert_eq!(MAX_RUNTIME, 21_600);
        assert_eq!(RAYON_THREADS, 16);
        assert_eq!(CHECKPOINT_NAMES.len(), 2);
        assert_eq!(SNAPSHOT_SIZE, 8_225_957_010);
        assert_eq!(WORKER_ENV, "JETSTREAMER_HISTORICAL_WORKER_V1_6_16");
        assert!(!PARENT_SHA.is_empty());
    }
}
