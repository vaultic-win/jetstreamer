fn main() {
    if let Err(error) = jetstreamer_horizon_observe::native141_admit::run() {
        eprintln!("native 141 admission failed closed: {error:#}");
        std::process::exit(1);
    }
}
