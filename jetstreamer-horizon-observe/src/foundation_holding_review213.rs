fn main() {
    if let Err(error) = jetstreamer_horizon_observe::foundation_holding213_review::run_cli() {
        eprintln!("Foundation213 holding review refused: {error:#}");
        std::process::exit(1);
    }
}
