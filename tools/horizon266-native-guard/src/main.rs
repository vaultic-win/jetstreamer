//! Epoch 266 exact-worker protective guard.
#[cfg(feature = "capped-worker")]
#[path = "../../horizon266-native-input/src/capped_site.rs"]
mod capped_site;
#[path = "../../horizon265-native-guard/src/processes.rs"]
mod processes;
mod profile;
#[path = "../../horizon261-native-guard/src/root_budget.rs"]
mod root_budget;
#[path = "../../horizon266-native-input/src/tmpfs.rs"]
mod tmpfs;
#[cfg(not(feature = "capped-worker"))]
const WORKER: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11";
#[cfg(not(feature = "capped-worker"))]
const WORKER_SHA: &str = "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae";
#[cfg(feature = "capped-worker")]
use capped_site::{WORKER, WORKER_SHA};
include!("../../horizon265-native-guard/src/guard.rs");
