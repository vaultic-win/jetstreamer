fn main() {
    if let Err(error) = jetstreamer_horizon_observe::ram_lifecycle_qualify::run() {
        eprintln!("RAM lifecycle qualification failed closed: {error:#}");
        std::process::exit(1);
    }
}
