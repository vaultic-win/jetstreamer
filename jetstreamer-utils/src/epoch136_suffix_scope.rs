//! Closed diagnostic scope, shared as source only. No admission authority.
#![allow(dead_code)] // Each closed consumer uses a different part of this table.
pub const UNIT: &str = "horizon-qualify-136-hourly-suffix-reproduction-20261027-v8.service";
pub const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch136-hourly-suffix-run-parent-20261027-v8/reproduction";
pub const GUARD_UNIT: &str = "horizon-guard-136-hourly-suffix-reproduction-20261027-v8.service";
pub const GUARD_TIMER: &str = "horizon-guard-136-hourly-suffix-reproduction-20261027-v8.timer";
pub const ADMIT_UNIT: &str = "horizon-epoch136-hourly-suffix-admission-20261027-v8.service";
pub const UID: u32 = 1001;
pub const GID: u32 = 1003;
pub const SNAPSHOT_NAME: &str =
    "snapshot-59176548-J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN.tar.zst";
pub const ROOT_NAME: &str =
    "snapshot-59183944-HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8.tar.zst";
pub const SNAPSHOT_SHA: &str = "14d16801fc2da62aaa4a3384e04963ec0bb9741c0c1f2911decf51aa11ca6f51";
pub const SNAPSHOT_BYTES: u64 = 3_170_290_207;
pub const WORKER_SHA: &str = "fce05d551d8154ebda6ff6b3791d02f60b0e0a1e3a69982ea06fa7c31c34b759";
pub const WORKER_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch136-capped-inputs-20261023-v1/jetstreamer-historical-worker-v1-4-25";
pub const OLD_NODE_SHA: &str = "d0c784a403d65819de70a499fc4d981217fd16fc30b70fac7e5ec979d0423ff0";
pub const GUARD_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch186-nonblocking-meter-candidate-20261027-v1/jetstreamer-horizon-standalone-guard";
pub const GUARD_SHA: &str = "8bbb0d88fcc90d01152836cdd021af59172933ab9266bcc45d2495fec19d42bd";
pub const GENESIS_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch136-capped-inputs-20261023-v1/genesis.tar.bz2";
pub const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
pub const GENESIS_BYTES: u64 = 20_144;
pub const CHECKPOINT_SHA: &str = "f8b3b7111dcf6fd03099a9f7bf45d0418475ba76bda78d943811cc2a75de6fc3";
pub const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch136-hourly-snapshot-input-20261027-v1/transfer/attempt-v1/snapshot-59176548-J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN.tar.zst";
pub const DOWNLOAD: &str =
    "/var/lib/jetstreamer/epoch136-hourly-snapshot-input-20261027-v1/receipts/download.json";
pub const DOWNLOAD_SHA: &str = "4ac1d403b032808b10b3564ca643a8326d942116ac164949c86562bd6659419e";
pub const TERMINAL: &str =
    "/var/lib/jetstreamer/epoch136-hourly-snapshot-input-20261027-v1/receipts/terminal.json";
pub const TERMINAL_SHA: &str = "36917858e2df9cd252fe63bfad46bcd19c37941a348c9f9192e72c3af595cfb4";
pub const INPUT_IID: &str = "87a7a1bba8f34dbd8ae373bf0193cd70";
pub const BOOTSTRAP: u64 = 59_176_548;
pub const FIRST: u64 = BOOTSTRAP + 1;
pub const END: u64 = 59_183_944;
pub const COUNT: u64 = 7_396;
pub const FAILURE_SLOT: u64 = 59_183_097;
pub const ROOT_STOP: u64 = 64 << 30;
pub const RESERVE: u64 = 8 << 30;
pub const DATA: u64 = 72 << 30;
pub const MEMORY: u64 = 68 << 30;
pub const CPU_MICROS: u64 = 3_000_000;
pub const WORK_SECONDS: u64 = 21_600;
pub const REAP_SECONDS: u64 = 120;
pub const VMA: u64 = 3_500_000;
pub const FLOOR: u64 = 4_478_054_272_454;
pub const SOCKET_ENV: &str = "JETSTREAMER_EPOCH136_HOURLY_GATE";
pub const SUPERVISOR_ENV: &str = "JETSTREAMER_EPOCH136_HOURLY_SUPERVISOR_PID";
pub const BARRIER_VERSION: &str = "epoch136-hourly-before-initialize-v1";
pub const CHECKPOINT_FILE: &str = "epoch-hashes-136-hourly-suffix.txt";
pub const OUTPUT: &str = "epoch136-suffix-through-root.jet";
