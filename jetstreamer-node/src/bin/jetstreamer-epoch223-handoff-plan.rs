//! Metadata-only223 handoff CLI; shared core also gates private V3 assembly.
#![recursion_limit = "256"]
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
#[path = "epoch223_assembly/handoff.rs"]
#[allow(dead_code)]
mod handoff;
fn main() {
    handoff::entry();
}
