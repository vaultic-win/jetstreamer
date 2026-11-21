const WORKER: &str = "/var/lib/jetstreamer/horizon-supported235-shrink-debt-e3f15eb2-v1/jetstreamer-historical-worker-v1-7-15";
const WORKER_SHA: &str = "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4";
const GENESIS: &str =
    "/var/lib/jetstreamer/horizon-foundation-holding-probe-input-v1/genesis.tar.bz2";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const WORKER_BYTES: u64 = 6_519_904;
const BACKEND: &str = "solana-v1.7.15";
const SOLANA_COMMIT: &str = "4892eb4e1ad278d5249b6cda8983f88effb3e98b";
include!("session.rs");

struct Checks;
impl RuntimeChecks for Checks {}
fn run() -> Result<()> {
    run_with::<Checks>()
}
