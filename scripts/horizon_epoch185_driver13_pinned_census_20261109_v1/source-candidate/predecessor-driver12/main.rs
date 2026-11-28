//! Exact epoch 185 private root-prefix orchestration. Source only until Root qualification.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-185-prefix.jet";
    pub const PARENT_SHA: &str = "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887";
    pub const RAYON_THREADS: u32 = 8;
    pub const EPOCH: u64 = 185;
    pub const TARGET: u64 = 80_351_283;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 79_919_284;
    // Experimental STOP ceilings. Never a qualified full-epoch planning bound.
    pub const MAX_SCRATCH: u64 = 384 << 30;
    pub const MINIMUM_FREE: u64 = 3_503_746_342_342;
    pub const MAX_RUNTIME: u64 = 259_200;
    pub const SNAPSHOT_SIZE: u64 = 7_250_303_600;
    pub const PLAN_SCHEMA: &str = "horizon-private-epoch185-capped-root-prefix-plan-v4";
    pub const RESULT_SCHEMA: &str = "horizon-private-epoch185-capped-root-prefix-resource-v4";
    pub const STOP_SCHEMA: &str = "horizon-private-epoch185-capped-root-prefix-stop-v4";
    pub const UNIT_PREFIX: &str = "horizon-qualify-185-capped-cold-";
    pub const ROOT_PREFIX: &str = "capped-root-prefix-185-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-79919283-Hozk66F2tKQuhouHceuwU9xZzWaXksnBeU1JBysRBmmf.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-80351283-Dq1knez4dNLE3zsSM69ve8Gd96LKJLJz4f56ysEHjfT8.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "6eef40863851927d0611fd90dd7c68528c8e1491a0fc18a28de492afa67316bd";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_15";
    pub const SNAPSHOT: &str = "218173053f960ab1917adaae99b1680fdd75968d95f22aae6ffd41aef37f9ef2";
}
mod adapter;
mod bounded_resource_runner;
fn main() {
    if let Err(error) = adapter::dispatch() {
        adapter::failed(&format!("{error:#}"));
        std::process::exit(1);
    }
}
