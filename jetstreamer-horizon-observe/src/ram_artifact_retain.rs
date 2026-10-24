fn main() {
    if let Err(error) = jetstreamer_horizon_observe::ram_artifact_retention::run() {
        eprintln!("retention failed closed: {error:#}");
        std::process::exit(1);
    }
}
