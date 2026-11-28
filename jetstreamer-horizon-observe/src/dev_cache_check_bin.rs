fn main() {
    if let Err(error) = jetstreamer_horizon_observe::dev_cache_check::run() {
        eprintln!("dev-cache check failed closed: {error:#}");
        std::process::exit(1);
    }
}
