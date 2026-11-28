//! Preserve evidence from the stopped 6,602-position recording without calling it a segment.
use super::{
    HASHES, IID, PROGRESS_SHA, RELEASE_SHA, ROOT, SLOTS, UNIT, evidence, segment_evidence,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

const STOP: &str = "d273dad0851b24ecfad432cb7c41460ccbd75af980075c0017935f928163f60a";
const END: &str = "f172a50e67d53e91798e2ee6c723ad4e699e03ac36ce7c2a7bf67b6bc6a08c69";
const PROGRESS: &str = "] progress slot ";

fn last_batch(text: &str) -> Result<Value> {
    let line = text
        .lines()
        .rev()
        .find(|line| line.contains(PROGRESS))
        .context("missing replay progress")?;
    let (_, data) = line
        .split_once(PROGRESS)
        .context("invalid progress marker")?;
    let mut fields = data.split_whitespace();
    let (slot, terminal) = fields
        .next()
        .context("missing progress slot")?
        .split_once('/')
        .context("invalid slot bounds")?;
    let slot: u64 = slot.parse()?;
    let terminal: u64 = terminal.parse()?;
    let counts: Vec<_> = fields.collect();
    let count = |name: &str| -> Result<u64> {
        let mut values = counts.iter().filter_map(|part| part.strip_prefix(name));
        let value = values.next().context("missing progress counter")?.parse()?;
        ensure!(values.next().is_none(), "duplicate progress counter");
        Ok(value)
    };
    ensure!(
        SLOTS[0] < slot && slot < terminal && terminal == SLOTS[1],
        "unexpected last progress slot"
    );
    Ok(
        json!({"slot":slot,"terminal_slot":terminal,"transactions":count("txs=")?,"account_updates":count("accounts=")?,"line":line}),
    )
}

fn pinned(name: &str, sha: &str) -> Result<(Value, Value)> {
    let reference = json!({"path":Path::new(ROOT).join(name),"sha256":sha});
    Ok((evidence::bound(&reference)?, reference))
}

pub(super) fn report() -> Result<Value> {
    evidence::idle(UNIT)?;
    let (release, release_ref) = pinned("SUCCESSOR_RELEASE.json", RELEASE_SHA)?;
    let (progress, first_ref) = pinned("FIRST_PROTECTED_PROGRESS.json", PROGRESS_SHA)?;
    let (intent, intent_ref) = pinned("guard-receipts/stop-intent.json", STOP)?;
    let (end, end_ref) = pinned("guard-receipts/stop-completion.json", END)?;
    let actor = evidence::bound(&release["actor"])?;
    let scope = evidence::bound(&release["interface"])?;
    let sample = &intent["sample"];
    ensure!(
        actor["unit"] == UNIT
            && actor["producer_invocation_id"] == IID
            && actor["interface"] == release["interface"]
            && release["producer_invocation_id"] == IID
            && progress["actor"] == release["actor"]
            && progress["release"] == release_ref
            && intent["reason"] == "filesystem-floor"
            && sample["trip_reason"] == intent["reason"]
            && intent["producer_invocation_id"] == IID
            && end["producer_invocation_id"] == IID
            && intent["plan_sha256"] == release["guard_plan"]["sha256"]
            && end["plan_sha256"] == intent["plan_sha256"]
            && end["intent"] == intent_ref["path"]
            && end["scratch_deleted"] == false
            && end["terminal"]["pid"] == 0
            && sample["producer_stop_enabled"] == true
            && sample["available_bytes"] == 9_638_111_191_040u64
            && sample["minimum_free_bytes"] == 9_639_135_481_492u64,
        "guard stop does not identify this recording"
    );
    let (original, previous_checkpoint) = super::retained_checkpoint(&release)?;
    let log = Path::new(evidence::word(&scope, "log")?);
    let log_id = evidence::stamp(log)?;
    let bytes = evidence::trusted(log)?;
    let text = std::str::from_utf8(&bytes)?;
    let run = Path::new(evidence::word(&scope, "run")?);
    let partial = run.join("ledger/epoch-170.diagnostic.jet");
    let manifest = partial.with_extension("jet.segment.json");
    ensure!(
        log == run.join("producer.log")
            && log_id[0] == progress["progress"]["log_device"]
            && log_id[1] == progress["progress"]["log_inode"]
            && text
                .lines()
                .filter(|l| l.contains("] historical checkpoint slot="))
                .count()
                == 1
            && !manifest.try_exists()?,
        "changed or completed stopped recording"
    );
    let points = segment_evidence::checkpoints(text, &HASHES, 1)?;
    let checkpoint = points.first().context("missing bootstrap")?;
    ensure!(
        checkpoint["bank_hash"] == previous_checkpoint["bank_hash"]
            && checkpoint["last_blockhash"] == previous_checkpoint["last_blockhash"]
            && checkpoint["accounts_hash"] == previous_checkpoint["accounts_hash"],
        "restored checkpoint differs from retained source"
    );
    let latest = last_batch(text)?;
    let (mut file, id) = segment_evidence::open_artifact(&partial, 1001)?;
    ensure!(
        id == json!([
            64512, 117645283, 179918633, 1795833953, 171200977, 1795833953, 171200977
        ]),
        "different retained partial"
    );
    let mut hash = Sha256::new();
    let length = std::io::copy(&mut file, &mut hash)?;
    let sha = format!("{:x}", hash.finalize());
    let boot = evidence::word(&actor, "boot_id")?.replace('-', "");
    let journal = evidence::command(
        "/usr/bin/journalctl",
        &[
            "-q",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("_BOOT_ID={boot}"),
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={IID}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
    )?;
    let mut rows = journal.lines();
    let terminal: Value = serde_json::from_str(rows.next().context("missing PID1 deactivation")?)?;
    ensure!(
        rows.next().is_none()
            && terminal["UNIT"] == UNIT
            && terminal["INVOCATION_ID"] == IID
            && terminal["_BOOT_ID"] == boot
            && length == id[2]
            && !manifest.try_exists()?
            && evidence::stamp(log)? == log_id
            && evidence::stamp(&partial)? == id,
        "stopped evidence changed during readback"
    );
    evidence::idle(UNIT)?;
    ensure!(
        !fs::exists(
            Path::new("/sys/fs/cgroup/system.slice")
                .join(UNIT)
                .join("cgroup.procs")
        )?,
        "producer cgroup still present"
    );
    Ok(
        json!({"schema":"horizon-epoch170-private-floor-stop-custody-v1","unit":UNIT,"invocation_id":IID,
        "actor":release["actor"],"release":release_ref,"first_progress":first_ref,"stop_intent":intent_ref,
        "stop_completion":end_ref,"pid1_deactivation":terminal,"original_recording":original,
        "bootstrap_checkpoint":checkpoint,"last_logged_progress":latest,
        "log":{"path":log,"identity":log_id,"sha256":evidence::digest(&bytes)},
        "partial":{"path":partial,"identity":id,"sha256":sha},"segment_manifest_present":false,
        "terminal_checkpoint_observed":false,"closed_segment":false,"resource_credit_bytes":0,"publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_progress_requires_exact_bounds_and_unique_counts() {
        let row = "[t] progress slot 73761053/73766969 (10%) txs=357393 accounts=973133";
        assert_eq!(last_batch(row).unwrap()["slot"], 73_761_053);
        assert!(last_batch(&format!("{row} txs=0")).is_err());
        assert!(last_batch(&row.replace("73761053", "73766969")).is_err());
    }
}
