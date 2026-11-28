//! Exact original-bootstrap serialized observation; no restoration or replay.
#![allow(dead_code)]
#[cfg(test)]
mod leader_schedule;
#[cfg(test)]
mod poh_backend;
#[cfg(test)]
mod runtime;
mod snapshot;

fn main() {
    if let Err(error) = snapshot::private_clock::run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
