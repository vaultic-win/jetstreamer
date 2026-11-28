//! Fixed-work private measurement of the prepared epoch 224 v1.6.25 repair.
//! Neither reaching the target nor passing its resource capture qualifies an epoch.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = false;
    pub const ARCHIVE_NAME: &str = "epoch-224-canary.jet";
    pub const PARENT_SHA: &str = "bcb76f90515465ee3b19486a18da907d15d4a3fbe310d66e0c3912a5daa4e257";
    pub const RAYON_THREADS: u32 = 16;
    pub const EPOCH: u64 = 224;
    pub const TARGET: u64 = 96_800_000;
    // The parent still plans its exact supported complete span. This runner
    // controls a private stop well before its canonical terminal checkpoint.
    pub const TERMINAL: u64 = 97_631_459;
    pub const INITIAL_REPLAY: u64 = 96_767_523;
    // Only the verified five-sample century floor plus this diagnostic's
    // 640-GiB budget. The immutable launch plan must additionally protect all
    // older live growth, measured by fresh independent fleet admission.
    // This lower bound is not admission, and is never a full-span peak estimate.
    pub const MINIMUM_FREE: u64 = 234_739_760_267 + (640 << 30);
    pub const MAX_SCRATCH: u64 = 448 << 30;
    pub const MAX_RUNTIME: u64 = 259_200;
    pub const SNAPSHOT_SIZE: u64 = 9_705_551_147;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch224-bounded-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch224-bounded-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch224-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-224-bounded-resource-";
    pub const ROOT_PREFIX: &str = "bounded-resource-224-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-97631459-EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[
        SNAPSHOT_NAME,
        "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst",
        TERMINAL_NAME,
    ];
    pub const WORKER: &str = "f26fb8598aef4091356be31a0ee322c2e428609f201390cce26ec60df9c62c45";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
    pub const SNAPSHOT: &str = "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1";
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
    fn measurement_is_not_a_root_or_full_epoch_qualification() {
        const { assert!(!NATURAL_ROOT_FINISH) };
        assert_eq!(INITIAL_REPLAY, 96_767_523);
        assert_eq!(TARGET, 96_800_000);
        const { assert!(TARGET < 97_199_617 && TARGET < 97_199_999 && TARGET < TERMINAL) };
        assert_eq!(CHECKPOINT_NAMES.len(), 3);
        assert_eq!(MAX_SCRATCH, 448 << 30);
        assert_eq!(MINIMUM_FREE, 234_739_760_267 + (640 << 30));
        assert_eq!(RAYON_THREADS, 16);
        assert_eq!(WORKER_ENV, "JETSTREAMER_HISTORICAL_WORKER_V1_6_25");
        assert!(!PARENT_SHA.is_empty());
    }
}
