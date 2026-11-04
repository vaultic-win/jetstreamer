//! Authentication of the future RAM replay sandbox, never admission.
//! Writes only one no-clobber private capability metadata receipt.
use jetstreamer_horizon_observe::ram_replay_sandbox;

fn main() {
    if let Err(e) = ram_replay_sandbox::run_probe() {
        eprintln!("RAM replay sandbox rejected: {e:#}");
        std::process::exit(1);
    }
}
