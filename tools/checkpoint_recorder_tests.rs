//! Compile the production recorder and presence map directly against qualified
//! node dependencies. This bounded native harness does not admit a replay.
#![allow(dead_code)]
#[path = "../jetstreamer-node/src/slot_presence.rs"]
mod slot_presence;
use slot_presence::{SlotPresenceMap, SlotPresenceState};
#[path = "../jetstreamer-node/src/horizon.rs"]
mod horizon;
