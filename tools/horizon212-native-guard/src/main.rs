//! Epoch 212 exact-worker protective guard.
#[path = "../../horizon265-native-guard/src/processes.rs"]
mod processes;
mod profile;
#[path = "../../horizon261-native-guard/src/root_budget.rs"]
mod root_budget;
#[path = "../../horizon212-native-input/src/tmpfs.rs"]
mod tmpfs;
const WORKER: &str = "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget";
const WORKER_SHA: &str = "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41";
include!("../../horizon265-native-guard/src/guard.rs");
