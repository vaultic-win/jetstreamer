pub(crate) const EPOCH: u64 = 230;
pub(crate) const BOOTSTRAP: u64 = 99_430_284;
pub(super) const FIRST: u64 = BOOTSTRAP + 1;
pub(super) const END: u64 = 99_437_433;
pub(crate) const DIVERGENT_SLOT: u64 = 99_435_889;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch230-vote-boundary-demotion-candidate";
pub(super) const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH230_VOTE_BOUNDARY_DEMOTION";
pub(super) const WORKER_SHA: Option<&str> =
    Some("d8b7865f19ebca62b8695fc9887f6215f7f680ea8a47a937caa2d49123a5af84");
pub(super) const RUN_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/epoch230-vote-boundary-demotion-tmpfs-v1/run";
pub(super) const OUTPUT: &str = "epoch-230-vote-boundary-demotion-diagnostic.jet";
pub(super) const BOOT_ACCOUNTS: &str = "BNZTcU9y17US1ucG9dMqKdL2PgUpQou2PPDArWKrBoWu";
pub(super) const BOOT_BANK: &str = "8dU4h2XDLuq3LK3MPmZVJWFs6ickRpodKH41rR9Js837";
pub(super) const BOOT_POH: &str = "37oW1AN4YWGKB4Kfpceyavymna88d6MLhSVW4reRknBY";
pub(super) const BOOT_CAPITALIZATION: u64 = 505_531_254_795_191_169;
pub(super) const BOOT_TRANSACTIONS: u64 = 30_912_582_044;
pub(super) const BOOT_TICK_HEIGHT: u64 = 6_363_538_240;
pub(super) const BOOT_WRITE_VERSION: u64 = 116_459_009_297;
pub(super) const TERMINAL_ACCOUNTS: &str = "eAarFVYbpioWaBvd5S9RMHo1AyLbixgaTsBWLxYUaDr";
// The first successful vote for this Bank signs the independently observed hash.
pub(super) const DIVERGENT_BANK: &str = "4mYxpg1PeZuARGpmapLJiXyUU1LqFiv5U2RjJTzCMCyq";
pub(super) const SNAPSHOT_SHA: &str =
    "4b0b16de74ba067d18eeec76326390c767d5fa0389083e5e837c27d5c37befeb";
pub(super) const SNAPSHOT_BYTES: u64 = 10_243_100_016;
pub(super) const WIRE: &[u8] =
    include_bytes!("../../../historical-runtime/fixtures/epoch230-99435889-tx1618.bin");
pub(super) const TRANSACTION_INDEX: usize = 1618;
pub(super) const EPOCH_ARGS: [&str; 2] = ["230", "230-230"];
pub(crate) const CAPABILITY_ARG: &str = "--epoch230-vote-boundary-demotion-capability";
pub(super) const CAPABILITY_SCHEMA: &str =
    "jetstreamer-private-epoch230-vote-boundary-demotion-parent-capability-v1";
