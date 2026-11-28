//! Preserve PID1's exact terminal and verify the closed 73,726,717–73,746,882 replay.
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod segment_evidence;

const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73726716-20261127-v1/attempt-2";
const CAPTURE_DIR: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/predecessor-exit";
const UNIT: &str = "horizon-qualify-170-from-73726716-20261127-v1.service";
const IID: &str = "04b0750aead84a83914d18edea9c8736";
const SLOTS: [u64; 2] = [73_726_716, 73_746_882];
const HASHES: [&str; 2] = [
    "FWdNzr1DnDLqiWmKfNtUbuBqmSz5gqJ3XE55d98LCw3M",
    "UjWmG6TowgFrbT6Ntd1vcH9m4E6LXX9AsaVG8727mW6",
];

const RELEASE_SHA: &str = "b0bb87af6c93f61c90727d9dfcf775d469d567e7baf8246f0a436b74284820fa";
const PROGRESS_SHA: &str = "7659706f6bdc5b496196fdb96a39ecff94e3b7955bafde2e1dd4c572b7bf8de4";
const SIGNED_DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/closure-tools";
const SIGNED_CHECKPOINTS: &[(u64, &str)] = &[(
    73_746_882,
    "701d627d08c1c2ba956f51f0db47b0a20c1fd504359cb4e8b05f0723d03e61dc",
)];

fn main() -> anyhow::Result<()> {
    bounded_report::run(bounded_report::previous_segment)
}
