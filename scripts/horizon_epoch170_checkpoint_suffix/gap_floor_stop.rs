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

fn pinned(root: &str, name: &str, sha: &str) -> Result<(Value, Value)> {
    let reference = json!({"path":Path::new(root).join(name),"sha256":sha});
    Ok((evidence::bound(&reference)?, reference))
}

pub(super) const RAM_ROOT: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73760367-ram-20261128-v1";
pub(super) const RAM_UNIT: &str = "horizon-qualify-170-from-73760367-ram-20261128-v1.service";
pub(super) const RAM_IID: &str = "2f1418eb4b6842ca97fe2336df2e7877";

pub(super) fn report(ram: bool) -> Result<Value> {
    let (root, unit, iid, release_sha, first_sha, intent_sha, end_sha) = if ram {
        (
            RAM_ROOT,
            RAM_UNIT,
            RAM_IID,
            "d7d36819e3f6dca05493fb5242a355e868475c547a6c7169a93ad31da7bdc625",
            "91ba467a765d8a722abbf6ac09e2cfc35f23da1f4506dd424b1709f9499c81b0",
            "3a654e628d2ab4f0fca2961489ea5ab0ee8d9c07e6268ef71369014dcd4645a6",
            "33062d66c2ad4c32c1ed283ceb68527290a46bcc1510cd021f2503233bad3bcf",
        )
    } else {
        (ROOT, UNIT, IID, RELEASE_SHA, PROGRESS_SHA, STOP, END)
    };
    let (free, floor, partial_id) = if ram {
        (
            9_612_153_085_952u64,
            9_612_696_788_810u64,
            json!([
                64512, 117965079, 35906273, 1795839696, 294350616, 1795839696, 294350616
            ]),
        )
    } else {
        (
            9_638_111_191_040u64,
            9_639_135_481_492u64,
            json!([
                64512, 117645283, 179918633, 1795833953, 171200977, 1795833953, 171200977
            ]),
        )
    };
    evidence::idle(unit)?;
    let (release, release_ref) = pinned(root, "SUCCESSOR_RELEASE.json", release_sha)?;
    let (progress, first_ref) = pinned(root, "FIRST_PROTECTED_PROGRESS.json", first_sha)?;
    let (intent, intent_ref) = pinned(root, "guard-receipts/stop-intent.json", intent_sha)?;
    let (end, end_ref) = pinned(root, "guard-receipts/stop-completion.json", end_sha)?;
    let actor = evidence::bound(&release["actor"])?;
    let scope = evidence::bound(&release["interface"])?;
    let sample = &intent["sample"];
    ensure!(
        actor["unit"] == unit
            && actor["producer_invocation_id"] == iid
            && actor["interface"] == release["interface"]
            && release["producer_invocation_id"] == iid
            && progress["actor"] == release["actor"]
            && progress["release"] == release_ref
            && intent["reason"] == "filesystem-floor"
            && sample["trip_reason"] == intent["reason"]
            && intent["producer_invocation_id"] == iid
            && end["producer_invocation_id"] == iid
            && intent["plan_sha256"] == release["guard_plan"]["sha256"]
            && end["plan_sha256"] == intent["plan_sha256"]
            && end["intent"] == intent_ref["path"]
            && end["scratch_deleted"] == false
            && end["terminal"]["pid"] == 0
            && sample["producer_stop_enabled"] == true
            && sample["available_bytes"] == free
            && sample["minimum_free_bytes"] == floor,
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
    ensure!(id == partial_id, "different retained partial");
    let mut hash = Sha256::new();
    let length = std::io::copy(&mut file, &mut hash)?;
    let sha = format!("{:x}", hash.finalize());
    if ram {
        ensure!(
            sha == "fb8e424a871f1910888e962acf7de4ed92f984004ddf8cd0a6d7ea937e26b270"
                && evidence::digest(&bytes)
                    == "32fc0cde9751c56e7eec6f831158df3a8d16e6d67d62479d7ae74d878ddf574c"
                && latest["slot"] == 73_760_551
                && latest["transactions"] == 99_006
                && latest["account_updates"] == 240_044,
            "RAM recording or final progress changed"
        );
    }
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
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=7ad2d189f7e94e70a38c781354912448",
        ],
    )?;
    let mut rows = journal.lines();
    let terminal: Value = serde_json::from_str(rows.next().context("missing PID1 deactivation")?)?;
    ensure!(
        rows.next().is_none()
            && terminal["UNIT"] == unit
            && terminal["INVOCATION_ID"] == iid
            && terminal["_BOOT_ID"] == boot
            && length == id[2]
            && !manifest.try_exists()?
            && evidence::stamp(log)? == log_id
            && evidence::stamp(&partial)? == id,
        "stopped evidence changed during readback"
    );
    evidence::idle(unit)?;
    ensure!(
        !fs::exists(
            Path::new("/sys/fs/cgroup/system.slice")
                .join(unit)
                .join("cgroup.procs")
        )?,
        "producer cgroup still present"
    );
    Ok(
        json!({"schema":"horizon-epoch170-private-floor-stop-custody-v1","unit":unit,"invocation_id":iid,
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
