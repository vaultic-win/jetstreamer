//! Pin and verify the 73,746,883–73,766,969 interval against its four snapshots and votes.
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod segment_evidence;

const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/attempt-2";
const CAPTURE_DIR: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-20261127-v1/predecessor-exit";
const UNIT: &str = "horizon-qualify-170-from-73746882-20261127-v1.service";
const IID: &str = "c3ab30cfeb05428bb8f5c48a5a44822c";
const RELEASE_SHA: &str = "a943145ddc01d4eaff76041eaf131818228e2cb484c32bc7753e84a8dc64bdef";
const PROGRESS_SHA: &str = "51aaa67e0eeb7bd1da0ed85e718ade911a6ae425e21be20383cb0f715c834d02";
const SLOTS: [u64; 4] = [73_746_882, 73_753_554, 73_760_367, 73_766_969];
const HASHES: [&str; 4] = [
    "UjWmG6TowgFrbT6Ntd1vcH9m4E6LXX9AsaVG8727mW6",
    "H2N735BwDow5DsyhJX58KiVnvpFiNtDuJpagw2zjkMu4",
    "7gcF7iqN9FvU2JrCkdqX7DmeV1X1AvZaGYoJjrLkCrsF",
    "9mYMWeKx1ZWjsBcGLUhmDGbdkY2GMCmdFnE6UxfAeQjW",
];
const SIGNED_DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/package";
const SIGNED_CHECKPOINTS: &[(u64, &str)] = &[
    (
        73_746_882,
        "701d627d08c1c2ba956f51f0db47b0a20c1fd504359cb4e8b05f0723d03e61dc",
    ),
    (
        73_753_554,
        "a7339abbeb10539faf4a0554ada23007044dd63991f850398a20fc05aaeb642e",
    ),
    (
        73_760_367,
        "f30e1752318adbf5f697f1fd4d13969006452d9f42b17961964df4760ef45c2c",
    ),
    (
        73_766_969,
        "37b6c60c61404dc19a58ca6a34f42091aea35509fd2bbb8c8d520fa660ae3d42",
    ),
];

fn main() -> anyhow::Result<()> {
    bounded_report::run(bounded_report::previous_segment)
}
