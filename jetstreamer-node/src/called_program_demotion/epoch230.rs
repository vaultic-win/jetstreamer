pub(crate) const EPOCH: u64 = 230;
pub(crate) const BOOTSTRAP: u64 = 99_359_376;
pub(super) const FIRST: u64 = 99_360_000;
pub(super) const END: u64 = 99_375_855;
pub(crate) const DIVERGENT_SLOT: u64 = 99_368_201;
pub(crate) const BACKEND: &str = "solana-v1.6.20-epoch230-called-program-demotion-candidate";
pub(super) const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_EPOCH230_DEMOTION";
pub(super) const WORKER_SHA: Option<&str> =
    option_env!("JETSTREAMER_EPOCH230_DEMOTION_WORKER_SHA256");
pub(super) const RUN_ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/epoch230-demotion-tmpfs-v328/run";
pub(super) const OUTPUT: &str = "epoch-230-program-demotion-diagnostic.jet";
pub(super) const BOOT_ACCOUNTS: &str = "CykUWyU9f91ZqjX3tbHTsU4XK1zyBjLYTkkxvb2VdsUn";
pub(super) const BOOT_BANK: &str = "7PocVnyaKWeyXuqpEYMx6ERoycKrwcTLJaLMPAB52azc";
pub(super) const BOOT_POH: &str = "8b45DY4RaBLFCYcgsbAkJwFGzytVDVYYcnYgo7cqfuYF";
pub(super) const BOOT_CAPITALIZATION: u64 = 505_325_492_931_098_515;
pub(super) const BOOT_TRANSACTIONS: u64 = 30_839_958_954;
pub(super) const BOOT_TICK_HEIGHT: u64 = 6_359_000_128;
pub(super) const BOOT_WRITE_VERSION: u64 = 116_194_083_839;
pub(super) const TERMINAL_ACCOUNTS: &str = "HouDs53rM8iQ8fuUwyZRFEukWj9ZW6HoHx4fXCSFQRBJ";
pub(super) const DIVERGENT_BANK: &str = "89zqtixCP9j6kauK8iKNHLveCsSQY5LBynQiXXew5FQ5";
pub(super) const SNAPSHOT_SHA: &str =
    "583a053d2a20a11aa232f4e848717ed75a3974ab2de564536f015b8fc9018669";
pub(super) const SNAPSHOT_BYTES: u64 = 10_888_743_994;
pub(super) const WIRE: &[u8] =
    include_bytes!("../../../historical-runtime/fixtures/epoch230-99368201-tx680.bin");
pub(super) const TRANSACTION_INDEX: usize = 680;
pub(super) const EPOCH_ARGS: [&str; 2] = ["230", "230-230"];
pub(crate) const CAPABILITY_ARG: &str = "--epoch230-demotion-capability";
pub(super) const CAPABILITY_SCHEMA: &str =
    "jetstreamer-private-epoch230-demotion-parent-capability-v1";
