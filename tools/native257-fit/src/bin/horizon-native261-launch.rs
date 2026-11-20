fn main() {
    if let Err(error) = horizon_singleton211_launch::native261::run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}
