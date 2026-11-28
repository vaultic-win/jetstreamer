//! Verify the two hourly checkpoints on the released 170 bridge. The first mode
//! reads only the frozen 09:18 log prefix. The second requires a closed producer.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use std::{fs, io::Read, path::Path};

mod bridge_exit;
#[allow(dead_code)]
mod evidence;
use evidence::{bound, digest, num, reference, stamp, word};
mod segment_evidence;
use segment_evidence::*;

const CAPTURE_DIR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73726716-20261127-v1/bridge-exit-capture-v1";
const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1";
const FLEET: &str = "/var/lib/jetstreamer/horizon_runtime_data/root091808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const UNIT: &str = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service";
const IID: &str = "3a5e311489834552ab5fda89379f9481";
const SLOTS: [u64; 3] = [73706460, 73713261, 73726716];

fn compare_signed(observed: &[Value], signed: &Value) -> Result<()> {
    let references = signed["checkpoints"]
        .as_array()
        .context("missing signed votes")?;
    ensure!(
        references.len() == 2 && signed["commitment"] == "finalized",
        "expected both finalized votes"
    );
    for (&slot, canonical) in SLOTS[1..].iter().zip(references) {
        ensure!(
            canonical["slot"] == slot
                && !word(canonical, "bank_hash")?.is_empty()
                && !word(canonical, "last_blockhash")?.is_empty(),
            "wrong signed checkpoint at {slot}"
        );
    }
    for (actual, canonical) in observed.iter().skip(1).zip(references) {
        for key in ["slot", "bank_hash", "last_blockhash"] {
            ensure!(
                actual[key] == canonical[key],
                "replay field {key} differs from signed vote or finalized block at {}",
                canonical["slot"]
            );
        }
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 1 && matches!(args[0].as_str(), "observed" | "closed" | "capture-exit"),
        "expected observed, capture-exit, or closed"
    );
    let closed = args[0] == "closed";
    let root = Path::new(ROOT);
    let release_ref = reference(&root.join("BRIDGE_RELEASE.json"))?;
    ensure!(
        release_ref["sha256"] == "efaed5ab6874108fc47e2633b7a40834687c5442a7e3bec43c9bf2a88c9ec86a",
        "foreign release"
    );
    let release = bound(&release_ref)?;
    let actor = bound(&release["actor"])?;
    if args[0] == "capture-exit" {
        return bridge_exit::capture(&actor, &release_ref);
    }
    let interface = bound(&release["interface"])?;
    let fleet_ref = json!({"path":FLEET,"sha256":"d71cf9b7e3ae5ff6f6537d243b0a029304004db0fadd263c9f845311d96a6759"});
    let fleet = bound(&fleet_ref)?;
    let bridge = &fleet["current_private170_checkpoint_bridge"];
    let work = &bridge["native_diagnostic"]["observation"]["useful_work"];
    ensure!(
        release["producer_invocation_id"] == IID
            && actor["unit"] == UNIT
            && actor["producer_invocation_id"] == IID
            && actor["interface"] == release["interface"]
            && bridge["release"] == release_ref
            && work["journal_invocation_id"] == IID,
        "foreign fleet or actor"
    );
    let log = &work["append_log_evidence"];
    ensure!(
        log["read_offset_bytes"] == 0
            && log["path"] == interface["log"]
            && log["producer_main_pid"] == actor["producer_pid"]
            && log["stdout_append_binding_verified"] == true,
        "foreign log"
    );
    let exit = if closed {
        clean_exit(&actor)?
    } else {
        Value::Null
    };
    let logpath = Path::new(word(log, "path")?);
    let (mut f, id) = open_artifact(logpath, 0)?;
    let n = num(log, "read_bytes")?;
    ensure!(
        id[0] == log["device"] && id[1] == log["inode"] && n <= 8 << 20 && n <= f.metadata()?.len(),
        "foreign or truncated log"
    );
    let mut bytes = vec![0; usize::try_from(n)?];
    f.read_exact(&mut bytes)?;
    ensure!(digest(&bytes) == log["read_sha256"], "frozen log changed");
    if closed {
        ensure!(f.metadata()?.len() <= 512 << 20, "oversized log");
        f.take((512 << 20) - n + 1).read_to_end(&mut bytes)?;
        ensure!(
            id[2] == bytes.len() && stamp(logpath)? == id,
            "closed log changed"
        );
    }
    let hash_path = root.join("bridge-73726716/epoch-hashes.txt");
    let hash_ref = reference(&hash_path)?;
    ensure!(
        hash_ref["sha256"] == "cd2fe29ec2587598f3e6dd12347764bcfb6853e057b711f18b9339b6c5ef8e98",
        "snapshot list differs"
    );
    let list = fs::read_to_string(&hash_path)?;
    let hashes = SLOTS
        .iter()
        .zip(list.lines())
        .map(|(slot, line)| {
            line.strip_prefix(&format!("snapshot-{slot}-"))
                .and_then(|s| s.strip_suffix(".tar.zst"))
                .context("wrong snapshot name")
        })
        .collect::<Result<Vec<_>>>()?;
    let observed = checkpoints(
        std::str::from_utf8(&bytes)?,
        &hashes,
        if closed { 3 } else { 2 },
    )?;
    let votes = json!({"path":"/var/lib/jetstreamer/horizon_runtime_data/epoch170-from-73726716-20261127-v1/signed-checkpoint-references-v1/SIGNED_CHECKPOINT_REFERENCES.json","sha256":"1a97981d657ced75641973e09e37b1a87061c135b71a3906cd4d5544261197ee"});
    compare_signed(&observed, &bound(&votes)?)?;
    let archive = if closed {
        closed_segment(&interface, &observed)?
    } else {
        Value::Null
    };
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"epoch170-bridge-checkpoint-comparison-v1","mode":args[0],"release":release_ref,
        "sample":fleet_ref,"log_prefix":log,"snapshot_list":hash_ref, "signed_vote_references":votes,"checkpoints":observed,"closed_segment":archive,"pid1_exit":exit,
        "publication_authorized":false,"resource_credit_bytes":0})
        )?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SUMMARY: &str = "[time INFO  jetstreamer_node::historical_replay] historical checkpoint slot=73706460 bank_hash=B accounts_hash=A last_blockhash=L capitalization=10 transactions=2 tick_height=3 complete=true writes=0 next_write_version=1";
    const VERIFY: &str =
        "[time INFO  jetstreamer_node] verified legacy accounts hash at slot 73706460";
    #[test]
    fn rejects_a_bank_hash_mismatch_at_either_hourly_checkpoint() {
        let a = json!({"slot":SLOTS[1],"bank_hash":"B","last_blockhash":"L"});
        let b = json!({"slot":SLOTS[2],"bank_hash":"C","last_blockhash":"M"});
        let refs = json!({"commitment":"finalized","checkpoints":[a,b]});
        let mut checkpoints = vec![json!({"slot":SLOTS[0]}), a, b];
        compare_signed(&checkpoints[..2], &refs).unwrap();
        compare_signed(&checkpoints, &refs).unwrap();
        checkpoints[2]["bank_hash"] = json!("wrong");
        assert!(compare_signed(&checkpoints, &refs).is_err());
        checkpoints[1]["bank_hash"] = json!("wrong");
        assert!(compare_signed(&checkpoints[..2], &refs).is_err());
    }
    #[test]
    fn requires_one_native_confirmation_and_the_pinned_accounts_hash() {
        let hashes = ["A", "unused", "unused"];
        let good = format!("{VERIFY}\n{SUMMARY}\n");
        assert_eq!(checkpoints(&good, &hashes, 1).unwrap()[0]["bank_hash"], "B");
        for bad in [
            SUMMARY.to_owned(),
            format!("{good}{VERIFY}"),
            format!("{good}{SUMMARY}"),
            good.replace("accounts_hash=A", "accounts_hash=Z"),
            good.replace("complete=true", "complete=false"),
            good.replace("writes=0", "writes=0 writes=1"),
        ] {
            assert!(checkpoints(&bad, &hashes, 1).is_err());
        }
    }
}
