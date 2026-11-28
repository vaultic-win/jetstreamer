fn main() {
    if let Err(error) = horizon_singleton211_launch::run_from_environment() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
