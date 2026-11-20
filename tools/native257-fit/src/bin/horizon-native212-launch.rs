fn main() {
    if let Err(error) = horizon_singleton211_launch::native212::run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
