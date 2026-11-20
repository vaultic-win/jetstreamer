//! Epoch 257 exact-worker bootstrap harness.
#![recursion_limit = "256"]
#[path = "../../horizon265-native-input/src/gate.rs"]
mod gate;
mod profile;

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
        json!({"schema":"horizon257-sealed-input-validation-v1",
      "input_packet_sha256":PACKET_SHA,"snapshot_sha256":SNAPSHOT_SHA,
      "bootstrap_slot":SLOT,"measured_identities_accepted":true,"worker_started":false,
      "native_runtime_qualified":false,"replay_launch_authorized":false,"remote_mutations":false})
    );
    Ok(())
}
include!("../../horizon265-native-input/src/shared.rs");
