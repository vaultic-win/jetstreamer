//! Read-only validation of an exact, separately authorized uploader cap handoff.
#![deny(warnings)]
mod capped;
#[allow(dead_code)]
mod census;
#[allow(dead_code)]
mod evidence;
fn main() {
    if let Err(error) = capped::run() {
        eprintln!("capped uploader census rejected: {error:#}");
        std::process::exit(1);
    }
}
