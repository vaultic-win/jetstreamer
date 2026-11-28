//! Compare the restored 73,760,367 checkpoint from the interrupted recording,
//! then verify the separate 6,602-position recording before the next bootstrap.
#[allow(dead_code)]
mod bounded_report;
mod bridge_exit;
#[allow(dead_code)]
mod evidence;
mod segment_evidence;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-20261128-v1";
const CAPTURE_DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73766969-gap-20261128-v1/predecessor-exit";
const UNIT: &str = "horizon-qualify-170-from-73760367-20261128-v1.service";
const IID: &str = "d8ea1fcfbd6646839b9593752f4afdef";
const RELEASE_SHA: &str = "44b41b89424986469020d592e8d1d87d831be596cc7b62f1bdfe500093718d04";
const PROGRESS_SHA: &str = "2f31a88b4f179262386db0c291821c8dde6ae3a82ea46e76479815fa84482d9f";
const SLOTS: [u64; 2] = [73_760_367, 73_766_969];
const HASHES: [&str; 2] = [
    "7gcF7iqN9FvU2JrCkdqX7DmeV1X1AvZaGYoJjrLkCrsF",
    "9mYMWeKx1ZWjsBcGLUhmDGbdkY2GMCmdFnE6UxfAeQjW",
];
const SIGNED_DIRECTORY: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73746882-20261127-v1/package";
const SIGNED_CHECKPOINTS: &[(u64, &str)] = &[
    (
        73_760_367,
        "f30e1752318adbf5f697f1fd4d13969006452d9f42b17961964df4760ef45c2c",
    ),
    (
        73_766_969,
        "37b6c60c61404dc19a58ca6a34f42091aea35509fd2bbb8c8d520fa660ae3d42",
    ),
];

fn retained_checkpoint(release: &Value) -> Result<(Value, Value)> {
    let anchor_ref = &release["independent_checkpoint"];
    let expected = json!({"path":Path::new(ROOT).join("INDEPENDENT_CHECKPOINT.json"),"sha256":"1031f72af7900560d972c0a4b0c50f5f42e0c548e883e0eafbe3eaa0dec1f4eb"});
    ensure!(
        anchor_ref == &expected && release.get("closed_comparison").is_none(),
        "different gap predecessor"
    );
    let anchor = evidence::bound(anchor_ref)?;
    let source = evidence::bound(&anchor["source_packet"])?;
    let stop = evidence::bound(&anchor["verified_original_stop"])?;
    ensure!(
        anchor["closed_segment"] == false
            && source["predecessor_closed_segment_claimed"] == false
            && source["positions"] == 6602
            && source["first_new_slot"] == SLOTS[0] + 1
            && source["terminal_slot"] == SLOTS[1]
            && anchor["source_packet"]["sha256"]
                == "b7d63248b4e83a6ebfe04b9ee54e3fb9d40c71d8597e535f8a01526878f09061"
            && stop["properties"]["InvocationID"] == "c3ab30cfeb05428bb8f5c48a5a44822c"
            && stop["properties"]["ExecMainCode"] == "2"
            && stop["properties"]["ExecMainStatus"] == "15",
        "original recording did not end at the retained guard stop"
    );
    let description = &source["original_log"];
    let log_path = Path::new(evidence::word(description, "path")?);
    let log_id = evidence::stamp(log_path)?;
    let bytes = evidence::trusted(log_path)?;
    ensure!(
        log_id[0] == description["device"]
            && log_id[1] == description["inode"]
            && log_id[2] == description["length"]
            && evidence::digest(&bytes) == description["sha256"],
        "original checkpoint log changed"
    );
    let text = std::str::from_utf8(&bytes)?;
    let offset = usize::try_from(evidence::num(description, "checkpoint_offset")?)?;
    ensure!(
        text.get(offset..).and_then(|suffix| suffix.lines().next())
            == description["checkpoint_line"].as_str(),
        "original checkpoint line changed"
    );
    let mut points = segment_evidence::checkpoints(text, &HASHES, 1)?;
    let checkpoint = points.pop().context("missing original checkpoint")?;
    let vote = evidence::bound(&source["signed_references"]["73760367"])?;
    ensure!(
        vote["bank_hash"] == checkpoint["bank_hash"]
            && vote["last_blockhash"] == checkpoint["last_blockhash"]
            && vote["slot"] == checkpoint["slot"],
        "original checkpoint differs from its finalized vote"
    );
    let path = log_path
        .parent()
        .context("missing original working tree")?
        .join("ledger/epoch-170.diagnostic.jet");
    let (_file, identity) = segment_evidence::open_artifact(&path, 1001)?;
    ensure!(
        identity
            == json!([
                64512,
                115474509,
                4887402614u64,
                1795825286,
                3859549,
                1795825286,
                3859549
            ])
            && !path.with_extension("jet.segment.json").try_exists()?,
        "retained partial changed or acquired a manifest"
    );
    Ok((
        json!({"independent_checkpoint":anchor_ref,"original_guard_stop":anchor["guard_stop"],
               "original_partial":{"path":path,"identity":identity,"closed_segment":false}}),
        checkpoint,
    ))
}

fn main() -> Result<()> {
    bounded_report::run(retained_checkpoint)
}
