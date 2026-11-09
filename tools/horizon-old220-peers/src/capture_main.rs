//! Separately admitted read-only five-peer capture. Never executes legacy jobs.
mod native_capture;
fn main() {
    if let Err(error) = native_capture::run() {
        eprintln!("old220 peer capture refused: {error:#}");
        std::process::exit(1);
    }
}
