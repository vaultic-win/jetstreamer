//! Private same-input capped-shrink measurement, never full-epoch qualification.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-225-canary.jet";
    pub const PARENT_SHA: &str = "3915f57819e5822e7112ee1932dc47caf5e9812605ad56cc309976e4f681f242";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 225;
    pub const TARGET: u64 = 97_202_500;
    pub const TERMINAL: u64 = 97_631_459;
    pub const INITIAL_REPLAY: u64 = 97_199_618;
    pub const MINIMUM_FREE: u64 = 3_185_678_193_366;
    pub const MAX_SCRATCH: u64 = 256 << 30;
    pub const MAX_RUNTIME: u64 = 3600;
    pub const SNAPSHOT_SIZE: u64 = 10_177_204_112;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch225-shrink-budget-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch225-shrink-budget-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch225-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-225-bounded-resource-shrink-budget-";
    pub const ROOT_PREFIX: &str = "bounded-resource-225-shrink-budget-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-97631459-EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
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

#[cfg(test)]
mod profile_tests {
    use super::profile::*;
    #[test]
    fn selected_worker_keeps_original_work_and_resource_limits() {
        assert_eq!(
            WORKER,
            "2dcc9b84a6ce27edba3d3b053c6e6170f66a2337f12a5aae54900c3ad9e2eedd"
        );
        assert_eq!(
            PARENT_SHA,
            "3915f57819e5822e7112ee1932dc47caf5e9812605ad56cc309976e4f681f242"
        );
        assert_eq!(
            (INITIAL_REPLAY, TARGET, TERMINAL),
            (97_199_618, 97_202_500, 97_631_459)
        );
        assert_eq!(
            (MAX_SCRATCH, MAX_RUNTIME, MINIMUM_FREE),
            (256 << 30, 3600, 3_185_678_193_366)
        );
        assert_eq!(RAYON_THREADS, 16);
        assert!(PLAN_SCHEMA.contains("-shrink-budget-"));
        assert!(UNIT_PREFIX.contains("-shrink-budget-"));
        assert!(ROOT_PREFIX.contains("-shrink-budget-"));
    }
}
