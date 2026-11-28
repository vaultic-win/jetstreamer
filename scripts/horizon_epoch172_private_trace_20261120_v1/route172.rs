//! Authenticated private epoch 172 diagnostic route.
pub const EPOCH: u64 = 172;
pub const EPOCH_KEY: &str = "172";
pub const UNIT: &str = "horizon-qualify-172-metered-hourly-20261120-g3.service";
pub const TIMER: &str = "horizon-guard-172-metered-hourly-20261120-g3.timer";
pub const GUARD_SERVICE: &str = "horizon-guard-172-metered-hourly-20261120-g3.service";
pub const LANE: &str = "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1";
pub const RUN: &str = "metered-hourly-20261120-g3";
pub const DEST: &str = "/home/sol/.jetstreamer-private/epoch172-standard-lane-20261110-v1/metadata-probes/metered-hourly-20261120-g3";
pub const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3";
pub const RECEIPTS: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3/guard-receipts";
pub const PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3/admission-v1";
pub const ADMIT: &str = "admit172";
pub const GATE: &str = "gate172";
pub const TRACE: &str = "trace172";
pub const PAYLOAD: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch172-metered-admission-20261120-g3/admission-v1/trace172";
pub const NODE_PACKAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-independent172-singleton-package-20261110-v1";
pub const NODE: &str = "/usr/local/lib/jetstreamer/horizon-independent172-singleton-package-20261110-v1/jetstreamer-node";
pub const RETIRED: &str =
    "/var/lib/jetstreamer/local2-mismatch172-retirement-20261114-v1/epoch172/completion.json";
pub const RETIRED_SHA: &str = "188fb4e9b1b79f508883affd3ec88a5a4fcd9361063a4ac74f077a9c666e901f";
pub const LANE_INO: u64 = 107282698;
pub const PARENT_INO: u64 = 107283290;
pub const BOOK_SHA: &str = "d0fa07c259fdb5dadc4ce564d3afc562b32180354db16788ba083fb670e96027";
pub const BOOK_MEMORY: u64 = 708249923584;
pub const SNAP: &str = "snapshot-74379198-7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj.tar.zst";
pub const SNAP_SLOT: u64 = 74379198;
pub const SNAP_GENERATION: &str = "1634786215364147";
pub const SNAP_HASH: &str = "7sUN98jiB8FuSu3nkpCm1gLBbPbFH1HtfocPKPV7asPj";
pub const TERMINAL: &str = "snapshot-74382131-oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo.tar.zst";
pub const TERMINAL_SLOT: u64 = 74382131;
pub const TERMINAL_GENERATION: &str = "1634787172918779";
pub const TERMINAL_HASH: &str = "oFYTx673sc7Sq4Dw74vsAby6SHVAbin3QtT8dmGzaLo";
pub const SNAP_BYTES: u64 = 2110486214;
pub const SNAP_SHA: &str = "fa7936328f4a4898ce9f35fd2892d9ba8f8ba03df345f8bc282ee6e913b2cc5f";
pub const TARGET: u64 = 74380784;
pub const ENTRY: u64 = 645;
pub const ORDINAL: u64 = 984;
pub const SIGNATURE: &str =
    "4Mc3qYm8t2AewCC1pax3hp11X7krbVmeWrAzcq8KqB2xtdut6i9fxo8XiMYU31jURU926HunHN2UZo7cQwdQ1chV";
pub const CANONICAL_ERROR: &str = "ComputationalBudgetExceeded";
pub const LOCAL_ERROR: &str = "ProgramFailedToComplete";
pub const TRACE_SWITCH: &str = "JETSTREAMER_HISTORICAL_TRACE_EPOCH172";
pub const ORIGINAL_IID: &str = "5359f45fc6df479ca62b17912f08e43d";
pub const ORIGINAL_TERMINAL_SHA: &str =
    "cc7b8ea179ba89efff7d96224941d591e13fa71f6b13e3efb7b4cdc1c716c0cf";
pub const CANONICAL_RPC_SHA: &str =
    "347700bb892006620a5d9d0a195cc13dce3725a6b6296f295ded5aeb498c24c6";
pub const HEADERS_SHA: &str = "47f19b3e5ca44acf625f63cc7f6a4ef9b05b96fbc011f15ad884d85dca8a9005";
pub const CHECKSUM_HEADER: &str = "x-goog-hash: crc32c=yysMog==,md5=rOc4FiXjMYrupror5w4K1w==";
pub const TAR_MEMBERS: u64 = 385702;
pub const TAR_BYTES: u64 = 9193597739;
pub const CANONICAL_LOG_COUNT: usize = 45;
pub const METER_ROWS: usize = 10;
pub const PREDECESSOR_SHA: &str =
    "854539f0d9450b388e136092567438134efaab19f0570dee7bdeb4fcf53120c7";
pub const HOURLY: &[u8] = include_bytes!("hourly-route.json");
pub const CANONICAL_LOGS: &[u8] = include_bytes!("canonical-logs.json");
pub const UNPATCHED_LOGS: &[u8] = include_bytes!("unpatched-logs.json");
pub const GATE_ALIAS: &str = "/run/horizon-172-trace-gate";
pub const BARRIER_ALIAS: &str = "/run/horizon-172-trace-barrier";
pub const PAYLOAD_ALIAS: &str = "/run/horizon-172-trace-payload";
pub const SNAP_ALIAS: &str = "/run/horizon-172-incident-snapshot";
