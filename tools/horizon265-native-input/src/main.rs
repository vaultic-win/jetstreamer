//! Epoch 265 exact-worker bootstrap harness.
#![recursion_limit = "256"]
mod gate;
mod profile;

fn main() {
    finish(run());
}
include!("shared.rs");
