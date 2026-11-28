//! Read the private 73,766,970–73,773,645 segment after its invocation-bound exit.
#[allow(dead_code)]
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod segment_evidence;

use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-ram-20261128-v1";
const CAPTURE_DIR: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-ram-20261128-v1/hourly-exit";
const UNIT: &str = "horizon-qualify-170-from-73766969-ram-20261128-v1.service";
const SIGNED_DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-20261127-v1/package";
const SIGNED_CHECKPOINTS: &[(u64, &str)] = &[
    (
        73_766_969,
        "37b6c60c61404dc19a58ca6a34f42091aea35509fd2bbb8c8d520fa660ae3d42",
    ),
    (
        73_773_645,
        "2ae4b69dfba0cabadea0fd6eb7ca9f1a582bff95c3ba20e75a977cba43a013de",
    ),
];
const SLOTS: [u64; 2] = [73_766_969, 73_773_645];
const HASHES: [&str; 2] = [
    "9mYMWeKx1ZWjsBcGLUhmDGbdkY2GMCmdFnE6UxfAeQjW",
    "GEvQZbTmrNhrdazo7Ps8NB53WoMujqmsgQtrdCtEEhtG",
];

// The installed reader is built from the accepted release and protected-progress receipts.
// The unbound package can compile and run its tests before the replay is issued.
const IID: &str = match option_env!("HORIZON_HOURLY170_READ_INVOCATION") {
    Some(v) => v,
    None => "",
};
const RELEASE_SHA: &str = match option_env!("HORIZON_HOURLY170_READ_RELEASE") {
    Some(v) => v,
    None => "",
};
const PROGRESS_SHA: &str = match option_env!("HORIZON_HOURLY170_READ_PROGRESS") {
    Some(v) => v,
    None => "",
};
const SCOPE: &str = "a4ca94b87bb1a301d76eacab1b3421dd52f96b5a4e5d0074b73dd6a3d3a63078";

fn valid_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value.bytes().any(|b| b != b'0')
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn predecessor(release: &Value) -> Result<(Value, Value)> {
    let root = Path::new(ROOT);
    let scope_ref = json!({"path":root.join("AFTER_FLOOR_WRITER_INTERFACE.json"),"sha256":SCOPE});
    ensure!(
        release["interface"] == scope_ref,
        "release names a different hourly 170 scope"
    );
    let scope = evidence::bound(&scope_ref)?;
    let (reference, first) = bounded_report::previous_segment(release)?;
    let prior = evidence::bound(&scope["predecessor"])?;
    let stopped = evidence::bound(&scope["stopped_custody"])?;
    ensure!(
        scope["retained_comparison"] == reference
            && reference["sha256"]
                == "d6b93f8deedb8110fa0011588c07a95dae5a50d2438f74df10966ab8c7b9f4ba"
            && scope["predecessor"]["sha256"]
                == "9b19751acffdde6dad4714f0079dd7e3bd7a9949fcdfbbc9fc9e8e74013680fd"
            && prior["comparison"] == reference
            && prior["actual_terminal"] == first
            && stopped["matched_bootstrap"] == first
            && stopped["verified_complete_segment"] == false
            && stopped["producer_invocation_id"] == "e589078414194de38fe902a9df0f5b0c"
            && first["slot"] == SLOTS[0]
            && first["slot_complete"] == true
            && scope["first_new_slot"] == SLOTS[0] + 1
            && scope["last"] == SLOTS[1],
        "foreign previous segment, stopped partial, or hourly range"
    );
    Ok((reference, first))
}

fn main() -> Result<()> {
    ensure!(
        valid_hex(IID, 32) && valid_hex(RELEASE_SHA, 64) && valid_hex(PROGRESS_SHA, 64),
        "build the installed reader from the exact invocation, release and protected progress"
    );
    bounded_report::run(predecessor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absent_and_malformed_binding_fields() {
        assert!(!valid_hex("", 32));
        assert!(!valid_hex(&"0".repeat(64), 64));
        assert!(!valid_hex(&"a".repeat(63), 64));
        assert!(!valid_hex(&"A".repeat(64), 64));
        assert!(valid_hex(SCOPE, 64));
    }
}
