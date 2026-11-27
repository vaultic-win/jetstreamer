//! Common checks for guarded bounded epoch 170 windows with frozen checkpoint inputs.
use super::{
    HASHES, IID, PROGRESS_SHA, RELEASE_SHA, ROOT, SIGNED_CHECKPOINTS, SIGNED_DIRECTORY, SLOTS,
    UNIT, bridge_exit, evidence, segment_evidence,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

fn agree(a: &Value, b: &Value, fields: &[&str]) -> Result<()> {
    for &k in fields {
        ensure!(
            !a[k].is_null() && a[k] == b[k],
            "checkpoint field {k} differs"
        );
    }
    Ok(())
}

fn checked_votes(points: &[Value]) -> Result<Vec<Value>> {
    ensure!(
        SIGNED_CHECKPOINTS.last().map(|v| v.0) == SLOTS.last().copied(),
        "terminal vote is not bound"
    );
    let mut signed = Vec::new();
    for &(slot, sha256) in SIGNED_CHECKPOINTS {
        let checkpoint = points
            .iter()
            .find(|p| p["slot"] == slot)
            .context("missing checkpoint")?;
        let path = Path::new(SIGNED_DIRECTORY).join(format!("reference-{slot}.json"));
        let r = json!({"path":path,"sha256":sha256});
        agree(
            checkpoint,
            &evidence::bound(&r)?,
            &["slot", "bank_hash", "last_blockhash"],
        )?;
        signed.push(r);
    }
    Ok(signed)
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 1 && matches!(args[0].as_str(), "capture-exit" | "bootstrap" | "closed"),
        "use capture-exit, bootstrap or closed"
    );
    let root = Path::new(ROOT);
    let release_ref = evidence::reference(&root.join("SUCCESSOR_RELEASE.json"))?;
    ensure!(release_ref["sha256"] == RELEASE_SHA, "foreign release");
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
        &json!({"path":root.join("FIRST_PROTECTED_PROGRESS.json"),"sha256":PROGRESS_SHA}),
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
        if closed { SLOTS.len() } else { 1 },
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
        let signed = checked_votes(&points)?;
        let endpoint = points.last().context("missing endpoint")?;
        let run = Path::new(evidence::word(&scope, "run")?);
        let segment = segment_evidence::closed_segment(
            &json!({"output":run.join("ledger/epoch-170.diagnostic.jet"),"worker_sha256":scope["profile"]["worker"]}),
            &points,
        )?;
        ensure!(
            segment["raw_write_versions"]["start"] == points[0]["next_write_version"]
                && segment["raw_write_versions"]["end"] == endpoint["next_write_version"],
            "raw writer span differs"
        );
        let mut report = json!({"comparison":"closed","closed_segment":segment,
            "signed_endpoint":signed.last().context("missing signed endpoint")?,"pid1_exit":exit});
        if signed.len() > 1 {
            report["signed_checkpoints"] = json!(signed);
        }
        report
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
