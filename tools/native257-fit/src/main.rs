use anyhow::{Result, ensure};
use std::path::Path;
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "qualify-full211-window" {
        println!(
            "{}",
            horizon_singleton211_launch::native257_fit::qualify_full211_window(Path::new(
                &args[2]
            ))?
        );
        return Ok(());
    }
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
