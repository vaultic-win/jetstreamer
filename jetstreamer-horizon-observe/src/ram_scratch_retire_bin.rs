fn main() {
    if let Err(error) = jetstreamer_horizon_observe::ram_scratch_retire::run() {
        eprintln!("RAM scratch retirement failed closed: {error:#}");
        std::process::exit(1);
    }
}
