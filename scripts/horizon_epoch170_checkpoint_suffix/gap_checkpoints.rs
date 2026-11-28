//! Compare the restored 73,760,367 checkpoint from the interrupted recording,
//! then verify the separate 6,602-position recording before the next bootstrap.
#[allow(dead_code)]
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod gap_anchor;
mod gap_floor_stop;
mod ram_bootstrap_stop;
mod ram_gap_drain;
mod segment_evidence;

use anyhow::{Result, ensure};
use gap_anchor::{HASHES, SIGNED_CHECKPOINTS, SIGNED_DIRECTORY, SLOTS, retained_checkpoint};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-20261128-v1";
const CAPTURE_DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1/predecessor-exit";
const UNIT: &str = "horizon-qualify-170-from-73760367-20261128-v1.service";
const IID: &str = "d8ea1fcfbd6646839b9593752f4afdef";
const RELEASE_SHA: &str = "44b41b89424986469020d592e8d1d87d831be596cc7b62f1bdfe500093718d04";
const PROGRESS_SHA: &str = "2f31a88b4f179262386db0c291821c8dde6ae3a82ea46e76479815fa84482d9f";
fn main() -> Result<()> {
    if std::env::args().skip(1).eq(["floor-stop"]) {
        println!("{}", gap_floor_stop::report(false)?);
        return Ok(());
    }
    if let Some(
        action @ ("ram-floor-stop"
        | "ram-drain-check"
        | "ram-drain"
        | "ram-second-floor-stop"
        | "ram-second-drain-check"
        | "ram-second-drain"),
    ) = std::env::args()
        .skip(1)
        .collect::<Vec<_>>()
        .as_slice()
        .first()
        .map(String::as_str)
    {
        ensure!(
            std::env::args().count() == 2,
            "unexpected RAM closure argument"
        );
        println!("{}", ram_gap_drain::run(action)?);
        return Ok(());
    }
    bounded_report::run(retained_checkpoint)
}
