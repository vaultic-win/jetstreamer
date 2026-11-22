use anyhow::{Result, ensure};
use std::path::Path;
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 3 && args[1] == "measure-266-turnover" {
        println!(
            "{}",
            horizon_singleton211_launch::native266_full::measure_turnover_allocation(Path::new(
                &args[2]
            ))?
        );
        return Ok(());
    }
    if args.get(1).is_some_and(|op| op == "epoch228-full") {
        println!(
            "{}",
            horizon_singleton211_launch::native266_full::dispatch228(&args[2..])?
        );
        return Ok(());
    }
    if args.get(1).is_some_and(|op| op == "epoch266-turnover") {
        println!(
            "{}",
            horizon_singleton211_launch::native266_full::dispatch_turnover(&args[2..])?
        );
        return Ok(());
    }
    if args.get(1).is_some_and(|op| op == "epoch266-instructions") {
        println!(
            "{}",
            horizon_singleton211_launch::native266_full::dispatch_instructions(&args[2..])?
        );
        return Ok(());
    }
    if args.get(1).is_some_and(|op| op == "epoch266-full") {
        let result = horizon_singleton211_launch::native266_full::dispatch(&args[2..])?;
        println!("{result}");
        return Ok(());
    }
    if args.len() == 5 && args[1] == "epoch228-demotion-control" {
        println!(
            "{}",
            horizon_singleton211_launch::native228_demotion_fit::controller::run(
                Path::new(&args[2]),
                &args[3],
                Path::new(&args[4]),
            )?
        );
        return Ok(());
    }
    if args.len() == 6 && args[1] == "epoch228-demotion" {
        ensure!(
            matches!(args[2].as_str(), "initial" | "held"),
            "epoch 228 phase"
        );
        println!(
            "{}",
            horizon_singleton211_launch::native228_demotion_fit::run(
                Path::new(&args[3]),
                &args[4],
                Path::new(&args[5]),
                args[2] == "held",
            )?
        );
        return Ok(());
    }
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
