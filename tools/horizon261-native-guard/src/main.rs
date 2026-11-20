//! Epoch 261 exact-worker protective guard.
#[path = "../../horizon265-native-guard/src/processes.rs"]
mod processes;
mod profile;
mod root_budget;
#[path = "../../horizon261-native-input/src/tmpfs.rs"]
mod tmpfs;
include!("../../horizon265-native-guard/src/shared.rs");
