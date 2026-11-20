//! Fixed new actual-input generation. Historical attempts are read-only evidence.
#![allow(dead_code)]
pub const UID: u32 = 1001;
pub const GID: u32 = 1003;
pub const SNAPSHOT_NAME: &str =
    "snapshot-59176548-J6ef2VSpLh1ofwD4zXGLAJkNs4i6yZ5JzTr5qG1jBSNN.tar.zst";
pub const ROOT_NAME: &str =
    "snapshot-59183944-HHd1o9dwpbyderGihEgb9inCBtMhqtoU855aFJPxnzk8.tar.zst";
pub const SNAPSHOT_SHA: &str = "14d16801fc2da62aaa4a3384e04963ec0bb9741c0c1f2911decf51aa11ca6f51";
pub const SNAPSHOT_BYTES: u64 = 3_170_290_207;
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
pub const CHECKPOINT_FILE: &str = "epoch-hashes-136-hourly-suffix.txt";
pub const OUTPUT: &str = "epoch136-suffix-through-root.jet";

pub const BASE: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
pub const ROOT: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/reproduction";
pub const TOOLS: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/tools";
pub const UNIT: &str = "horizon-qualify-136-actual-20261120-g1.service";
pub const GUARD_UNIT: &str = "horizon-guard-136-actual-20261120-g1.service";
pub const GUARD_TIMER: &str = "horizon-guard-136-actual-20261120-g1.timer";
pub const ADMISSION_PATH: &str =
    "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/admission.json";
pub const SOCKET_ENV: &str = "JETSTREAMER_EPOCH136_ACTUAL_20261120_GATE";
pub const SUPERVISOR_ENV: &str = "JETSTREAMER_EPOCH136_ACTUAL_20261120_SUPERVISOR_PID";
pub const BARRIER_VERSION: &str = "epoch136-actual-20261120-before-initialize-v1";
pub const WORKER_SHA: &str = "3ea95997d956de6a8c7fa431e679d496a5d3c31e15f8a104a8ddb0086646ea3d";
pub const WORKER_PATH: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1/tools/jetstreamer-historical-worker-v1-4-25";
pub const GUARD_PATH: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/guard-v1/guard";
pub const GUARD_SHA: &str = "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016";
pub const QUALIFICATION_SHA: &str =
    "a84600699abc7ca36230fa6bb994e6d5c3cf099a9481ecad02a6c2e6178e9f81";
pub const QUALIFIED_WORKER_COMMIT: &str = "061b47a6447c733771a12160ea52ee5f044e20a8";
pub const TARGET_SIGNATURE: &str =
    "2B96JV6WYJDwxNF3MS4KtS4jb1ToCcQ3xxhcKNysJsdK1jbZ45NCF1EiEWk5GK7Yr5LGVzrT1fBA6Jnvc9VU36L3";
