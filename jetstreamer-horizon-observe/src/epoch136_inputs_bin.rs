fn main() {
    if let Err(error) = jetstreamer_horizon_observe::epoch136_inputs::run() {
        eprintln!("epoch136 input capability failed closed: {error:#}");
        std::process::exit(1);
    }
}
