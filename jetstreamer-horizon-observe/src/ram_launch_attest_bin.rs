fn main() {
    if let Err(error) = jetstreamer_horizon_observe::ram_launch_attest::run() {
        eprintln!("RAM launch evidence collection failed closed: {error:#}");
        std::process::exit(1);
    }
}
