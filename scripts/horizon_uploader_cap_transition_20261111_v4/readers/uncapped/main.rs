#![deny(warnings)]
#[allow(dead_code)]
mod evidence;
#[allow(dead_code)]
mod census;
fn main() {
    if let Err(error) = census::run_cli() {
        eprintln!("isolated uncapped census rejected: {error:#}");
        std::process::exit(1);
    }
}
