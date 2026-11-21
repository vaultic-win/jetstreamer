//! Epoch 212 exact-worker bootstrap harness.
#![recursion_limit = "256"]
#[path = "../../horizon265-native-input/src/gate.rs"]
mod first_guard;
#[path = "../../horizon261-native-input/src/gate.rs"]
mod gate;
mod profile;
mod tmpfs;

fn main() {
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--validate-inputs")])
    {
        finish(validate_inputs());
    } else {
        finish(run());
    }
}

fn validate_inputs() -> Result<()> {
    inputs()?;
    println!(
        "{}",
        json!({"schema":"horizon212-sealed-input-validation-v1",
      "input_packet_sha256":PACKET_SHA,"snapshot_sha256":SNAPSHOT_SHA,
      "bootstrap_slot":SLOT,"measured_identities_accepted":true,"worker_started":false,
      "native_runtime_qualified":false,"replay_launch_authorized":false,"remote_mutations":false})
    );
    Ok(())
}
const WORKER: &str = "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
const WORKER_SHA: &str = "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41";
const GENESIS: &str =
    "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/genesis.tar.bz2";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const BACKEND: &str = "solana-v1.6.16";
const SOLANA_COMMIT: &str = "86c26f843276581509c3434acc2efbf4202c44e0";
const WORKER_BYTES: u64 = 9_050_240;
include!("../../horizon265-native-input/src/session.rs");

struct Checks;
impl RuntimeChecks for Checks {}
fn run() -> Result<()> {
    run_with::<Checks>()
}
