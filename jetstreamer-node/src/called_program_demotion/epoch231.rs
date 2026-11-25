pub(crate) const EPOCH: u64 = 231;
pub(crate) const BOOTSTRAP: u64 = 99_791_404;
pub(super) const FIRST: u64 = 99_792_000;
pub(super) const END: u64 = 99_803_089;
pub(crate) const DIVERGENT_SLOT: u64 = 99_791_498;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch231-called-program-demotion-candidate";
pub(super) const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH231_DEMOTION";
pub(super) const WORKER_SHA: Option<&str> =
    option_env!("JETSTREAMER_EPOCH231_DEMOTION_WORKER_SHA256");
pub(super) const RUN_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/epoch231-demotion-tmpfs-v1/run";
pub(super) const OUTPUT: &str = "epoch-231-program-demotion-diagnostic.jet";
pub(super) const BOOT_ACCOUNTS: &str = "Hn6PFpfb4b63XELLfqGYLbFk8c8hJtujeQbFR1WmNW84";
pub(super) const BOOT_BANK: &str = "D5S4nJLsTDc1iXdeVSnMNX4ncSexZr91RSAPf1o5Z8Bz";
pub(super) const BOOT_POH: &str = "EUrfErKEdAKsWnvgh4TcseCN23E1eBVLczcLRP7ejnQM";
pub(super) const BOOT_CAPITALIZATION: u64 = 505_530_177_172_993_166;
pub(super) const BOOT_TRANSACTIONS: u64 = 31_284_676_462;
pub(super) const BOOT_TICK_HEIGHT: u64 = 6_386_649_920;
pub(super) const BOOT_WRITE_VERSION: u64 = 117_805_064_913;
pub(super) const TERMINAL_ACCOUNTS: &str = "42P5KSaezAgfvTUMtuFUiEtjpsmagMA2UbWoWJPAKCqr";
// The next slot's finalized vote signs this exact parent Bank hash.
pub(super) const DIVERGENT_BANK: &str = "AVQgPbNJkaCS79o1SFgM1V89GAc2BNDReYCaJG48N7TK";
pub(super) const SNAPSHOT_SHA: &str =
    "2992a8234c790c0feb836b933b68665b223107b0838c23eee32219ce5dc4f9ca";
pub(super) const SNAPSHOT_BYTES: u64 = 10_615_540_172;
pub(super) const WIRE: &[u8] = include_bytes!(
    "../../../historical-runtime/v1_6_20/worker/tests/fixtures/epoch231-warmup-99791498-tx698.bin"
);
pub(super) const TRANSACTION_INDEX: usize = 698;
pub(super) const EPOCH_ARGS: [&str; 2] = ["231", "231-231"];
pub(crate) const CAPABILITY_ARG: &str = "--epoch231-demotion-capability";
pub(super) const CAPABILITY_SCHEMA: &str =
    "jetstreamer-private-epoch231-demotion-parent-capability-v1";
