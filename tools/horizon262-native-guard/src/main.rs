//! Epoch 262 exact-worker protective guard.
#[path = "../../horizon265-native-guard/src/processes.rs"]
mod processes;
mod profile;
#[path = "../../horizon261-native-guard/src/root_budget.rs"]
mod root_budget;
#[path = "../../horizon262-native-input/src/tmpfs.rs"]
mod tmpfs;
include!("../../horizon265-native-guard/src/shared.rs");
