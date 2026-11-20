use anyhow::{Result, ensure};
use std::path::Path;
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: horizon-native257-fit SEALED_REVIEW SHA256 NEW_EVIDENCE_DIR"
    );
    println!(
        "{}",
        horizon_singleton211_launch::native257_fit::run(
            Path::new(&args[1]),
            &args[2],
            Path::new(&args[3])
        )?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
