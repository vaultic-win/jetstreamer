//! Compare and retain the exact RAM-backed gap before the prepared 73,766,969 bootstrap.
#[allow(dead_code)]
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod gap_anchor;
mod segment_evidence;
mod staged_following;

use anyhow::Result;
use gap_anchor::{HASHES, SIGNED_CHECKPOINTS, SIGNED_DIRECTORY, SLOTS, retained_checkpoint};

const ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v3";
const CAPTURE_DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1/third-ram-exit";
const UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v3.service";
const IID: &str = "5f7a0dc3b03346b7b7cfa17a51e150aa";
const RELEASE_SHA: &str = "bbbd90b4e78b50abd57e2dac56bf32c9384981a561d85bcf1b3b7b8c46725459";
const PROGRESS_SHA: &str = "142dd34052a7377936fdeb140d79c14de9889d0be23f67fc1ca89c1c51b5adcb";

fn main() -> Result<()> {
    if std::env::args().skip(1).eq(["prepare"]) {
        println!("{}", serde_json::to_string(&staged_following::prepare()?)?);
        return Ok(());
    }
    bounded_report::run(retained_checkpoint)
}
