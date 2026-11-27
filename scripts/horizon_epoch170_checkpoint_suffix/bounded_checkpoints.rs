//! Preserve PID1's exact terminal and verify the closed 73,726,717–73,746,882 replay.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

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

fn agree(a: &Value, b: &Value, fields: &[&str]) -> Result<()> {
    for &k in fields {
        ensure!(
            !a[k].is_null() && a[k] == b[k],
            "checkpoint field {k} differs"
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 1 && matches!(args[0].as_str(), "capture-exit" | "bootstrap" | "closed"),
        "use capture-exit, bootstrap or closed"
    );
    let root = Path::new(ROOT);
    let release_ref = evidence::reference(&root.join("SUCCESSOR_RELEASE.json"))?;
    ensure!(
        release_ref["sha256"] == "b0bb87af6c93f61c90727d9dfcf775d469d567e7baf8246f0a436b74284820fa",
        "foreign release"
    );
    let release = evidence::bound(&release_ref)?;
    let actor = evidence::bound(&release["actor"])?;
    let scope = evidence::bound(&release["interface"])?;
    ensure!(
        actor["unit"] == UNIT
            && actor["producer_invocation_id"] == IID
            && release["producer_invocation_id"] == IID
            && release["interface"] == actor["interface"],
        "foreign producer"
    );
    if args[0] == "capture-exit" {
        return bridge_exit::capture(&actor, &release_ref);
    }
    let closed = args[0] == "closed";
    let exit = if closed {
        segment_evidence::clean_exit(&actor)?
    } else {
        Value::Null
    };
    let proof = evidence::bound(
        &json!({"path":root.join("FIRST_PROTECTED_PROGRESS.json"),"sha256":"7659706f6bdc5b496196fdb96a39ecff94e3b7955bafde2e1dd4c572b7bf8de4"}),
    )?;
    ensure!(
        proof["release"] == release_ref
            && proof["actor"] == release["actor"]
            && proof["producer_pid"] == actor["producer_pid"],
        "foreign first progress"
    );
    let logpath = Path::new(evidence::word(&scope, "log")?);
    let (mut f, id) = segment_evidence::open_artifact(logpath, 0)?;
    let progress = &proof["progress"];
    let start = evidence::num(progress, "first_log_byte")?;
    let last = evidence::num(progress, "last_log_byte")?;
    ensure!(
        id[0] == progress["log_device"]
            && id[1] == progress["log_inode"]
            && start < last
            && last <= 8192 * 1024
            && last <= f.metadata()?.len(),
        "unbound log"
    );
    let mut prefix = vec![0; usize::try_from(last)?];
    f.read_exact(&mut prefix)?;
    ensure!(
        std::str::from_utf8(&prefix[usize::try_from(start)?..])?
            == evidence::word(progress, "line")?,
        "first progress log line changed"
    );
    if closed {
        let len = f.metadata()?.len();
        ensure!(len <= 512 << 20, "oversized closed log");
        f.seek(SeekFrom::Start(last))?;
        f.take(len - last + 1).read_to_end(&mut prefix)?;
        ensure!(
            u64::try_from(prefix.len())? == len && evidence::stamp(logpath)? == id,
            "closed log changed"
        );
    }
    let points = segment_evidence::checkpoints(
        std::str::from_utf8(&prefix)?,
        &HASHES,
        if closed { 2 } else { 1 },
    )?;
    let old = evidence::bound(&release["closed_comparison"])?;
    let prior = old["checkpoints"]
        .as_array()
        .and_then(|p| p.last())
        .context("prior endpoint")?;
    agree(
        &points[0],
        prior,
        &[
            "slot",
            "bank_hash",
            "accounts_hash",
            "last_blockhash",
            "capitalization",
            "transaction_count",
            "tick_height",
            "slot_complete",
        ],
    )?;
    let snapshot_counter_delta = i128::from(evidence::num(&points[0], "next_write_version")?)
        - i128::from(evidence::num(prior, "next_write_version")?);
    let report = if closed {
        let proof_path = Path::new(CAPTURE_DIR)
            .with_file_name("closure-tools")
            .join("reference-73746882.json");
        let signed = evidence::reference(&proof_path)?;
        ensure!(
            signed["sha256"] == "701d627d08c1c2ba956f51f0db47b0a20c1fd504359cb4e8b05f0723d03e61dc",
            "changed finalized checkpoint evidence"
        );
        agree(
            &points[1],
            &evidence::bound(&signed)?,
            &["slot", "bank_hash", "last_blockhash"],
        )?;
        let run = Path::new(evidence::word(&scope, "run")?);
        let segment = segment_evidence::closed_segment(
            &json!({"output":run.join("ledger/epoch-170.diagnostic.jet"),"worker_sha256":scope["profile"]["worker"]}),
            &points,
        )?;
        ensure!(
            segment["raw_write_versions"]["start"] == points[0]["next_write_version"]
                && segment["raw_write_versions"]["end"] == points[1]["next_write_version"],
            "raw writer span differs"
        );
        json!({"comparison":"closed","closed_segment":segment,"signed_endpoint":signed,"pid1_exit":exit})
    } else {
        json!({"comparison":"bootstrap"})
    };
    println!(
        "{}",
        serde_json::to_string(
            &json!({"schema":"horizon-170-successor-closed-checkpoint-comparison-v1","release":release_ref,"actor":release["actor"],"interface":release["interface"],"predecessor":release["closed_comparison"],"checkpoints":points,"snapshot_restart_raw_counter_delta":snapshot_counter_delta.to_string(),"evidence":report,"canonical_publication_authorized":false})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_accepts_raw_counter_rebasing_only_with_matching_consensus() {
        let old = json!({"slot": 73726716, "bank_hash":"B", "next_write_version":17});
        let mut restarted = json!({"slot": 73726716, "bank_hash":"B", "next_write_version":49});
        assert!(agree(&old, &restarted, &["slot", "bank_hash"]).is_ok());
        restarted["bank_hash"] = json!("other");
        assert!(agree(&old, &restarted, &["slot", "bank_hash"]).is_err());
        assert!(agree(&old, &restarted, &["absent"]).is_err());
    }
}
