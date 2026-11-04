//! Fixed-input read-only serialized clock observation, never a runtime restore.
#![allow(dead_code)]
mod snapshot;

// Existing snapshot regressions reference the normal runtime's builtin table.
#[cfg(test)]
mod leader_schedule;
#[cfg(test)]
mod poh_backend;
#[cfg(test)]
mod runtime;

fn main() {
    if let Err(error) = snapshot::private_clock::run() {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
