pub(crate) const EPOCH: u64 = 229;
pub(crate) const BOOTSTRAP: u64 = 98_927_417;
pub(super) const FIRST: u64 = 98_928_000;
pub(super) const END: u64 = 98_939_266;
pub(crate) const DIVERGENT_SLOT: u64 = 98_931_633;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch229-called-program-demotion-candidate";
pub(super) const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH229_DEMOTION";
pub(super) const WORKER_SHA: Option<&str> =
    option_env!("JETSTREAMER_EPOCH229_DEMOTION_WORKER_SHA256");
pub(super) const RUN_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v1/run";
pub(super) const OUTPUT: &str = "epoch-229-program-demotion-diagnostic.jet";
pub(super) const BOOT_ACCOUNTS: &str = "528ZGQNBRBC7RWW9SXMSBrPsa8Gf2admhkyKWe3n8ZmT";
pub(super) const BOOT_BANK: &str = "J4fxR4FnK4QL43TGbNkLcYg5SsxCA7wK9RVPqL9mQTXN";
pub(super) const BOOT_POH: &str = "5G78DNcN6Nc2aswmBF7QFqB7ecAtyeUUAiPy99wrRrJj";
pub(super) const BOOT_CAPITALIZATION: u64 = 505_120_690_366_497_539;
pub(super) const BOOT_TRANSACTIONS: u64 = 30_398_735_376;
pub(super) const BOOT_TICK_HEIGHT: u64 = 6_331_354_752;
pub(super) const BOOT_WRITE_VERSION: u64 = 114_635_886_212;
pub(super) const TERMINAL_ACCOUNTS: &str = "61jJuhUUEDjQKbwocjURSWvzujFopxnh2hQetKKRcrp7";
pub(super) const DIVERGENT_BANK: &str = "7eZpcd8gDPTZ7cGasN6K6YpFiQGbGPJvGeovtAbBrorU";
pub(super) const SNAPSHOT_SHA: &str =
    "f387a86c08b0db24830967fa733e0fe2dab1f902dc21798c1b0f1cde0f948b76";
pub(super) const SNAPSHOT_BYTES: u64 = 10_249_077_874;
pub(super) const WIRE: &[u8] =
    include_bytes!("../../../historical-runtime/fixtures/epoch229-98931633-tx1764.bin");
pub(super) const TRANSACTION_INDEX: usize = 1764;
pub(super) const EPOCH_ARGS: [&str; 2] = ["229", "229-229"];
pub(crate) const CAPABILITY_ARG: &str = "--epoch229-demotion-capability";
pub(super) const CAPABILITY_SCHEMA: &str =
    "jetstreamer-private-epoch229-demotion-parent-capability-v1";
