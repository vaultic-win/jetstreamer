//! Verify the two hourly checkpoints on the released 170 bridge. The first mode
//! reads only the frozen 09:18 log prefix. The second requires a closed producer.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

mod bridge_exit;
#[allow(dead_code)]
mod evidence;
use evidence::{bound, command, digest, idle, num, reference, stamp, word};

const ROOT: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-storage-witness-recovery-20261127-v1/suffix-run-v1";
const FLEET: &str = "/var/lib/jetstreamer/horizon_runtime_data/root091808-live166167170-20261127-v1/ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const UNIT: &str = "horizon-qualify-170-checkpoint-suffix-20261127-v1.service";
const IID: &str = "3a5e311489834552ab5fda89379f9481";
const SLOTS: [u64; 3] = [73706460, 73713261, 73726716];

fn checkpoints(log: &str, hashes: &[&str], count: usize) -> Result<Vec<Value>> {
    ensure!(hashes.len() == SLOTS.len(), "unexpected snapshot list");
    let mut result = Vec::new();
    for (&slot, &hash) in SLOTS.iter().zip(hashes).take(count) {
        let verified = format!(" jetstreamer_node] verified legacy accounts hash at slot {slot}");
        let marker =
            format!(" jetstreamer_node::historical_replay] historical checkpoint slot={slot} ");
        let mut confirmations = log.lines().filter(|line| line.ends_with(&verified));
        let mut checkpoints = log.lines().filter_map(|line| line.split_once(&marker));
        ensure!(
            confirmations.next().is_some() && confirmations.next().is_none(),
            "missing or duplicate verification at {slot}"
        );
        let (_, body) = checkpoints
            .next()
            .with_context(|| format!("missing checkpoint {slot}"))?;
        ensure!(checkpoints.next().is_none(), "duplicate checkpoint {slot}");
        let mut fields = BTreeMap::new();
        for field in body.split_whitespace() {
            let (k, v) = field.split_once('=').context("invalid checkpoint field")?;
            ensure!(
                fields.insert(k, v).is_none(),
                "duplicate checkpoint field {k}"
            );
        }
        ensure!(
            fields.get("accounts_hash") == Some(&hash) && fields.get("complete") == Some(&"true"),
            "checkpoint identity mismatch at {slot}"
        );
        let field = |k| {
            fields
                .get(k)
                .copied()
                .with_context(|| format!("missing {k} at {slot}"))
        };
        let number = |k| -> Result<u64> { Ok(field(k)?.parse()?) };
        result.push(json!({"slot":slot,"bank_hash":field("bank_hash")?, "accounts_hash":hash, "last_blockhash":field("last_blockhash")?,
            "capitalization":number("capitalization")?, "transaction_count":number("transactions")?, "tick_height":number("tick_height")?,
            "slot_complete":true,"write_count":number("writes")?, "next_write_version":number("next_write_version")?}));
    }
    Ok(result)
}
fn open_artifact(p: &Path, uid: u32) -> Result<(File, Value)> {
    ensure!(p.canonicalize()? == p, "indirect artifact");
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    let identity = stamp(p)?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && identity[0] == m.dev()
            && identity[1] == m.ino(),
        "foreign artifact"
    );
    Ok((f, identity))
}
fn clean_exit(actor: &Value) -> Result<Value> {
    idle(UNIT)?;
    let native = bridge_exit::native_exit(actor)?;
    ensure!(
        native["ExecMainCode"] == "1"
            && native["ExecMainStatus"] == "0"
            && native["Result"] == "success",
        "native main process did not exit zero"
    );
    let boot = word(actor, "boot_id")?.replace('-', "");
    let records = command(
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
        ],
    )?;
    let mut success = None;
    for line in records.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["MESSAGE_ID"] != "98e322203f7a4ed290d09fe03c09fe15",
            "PID1 recorded process failure"
        );
        if row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448" {
            ensure!(
                success.is_none()
                    && row["INVOCATION_ID"] == IID
                    && row["UNIT"] == UNIT
                    && row["_BOOT_ID"] == boot,
                "conflicting exit"
            );
            success = Some(row);
        }
    }
    Ok(json!({"journal":success.context("no clean invocation-bound PID1 exit")?, "native":native}))
}
fn closed_segment(interface: &Value, observed: &[Value]) -> Result<Value> {
    let p = Path::new(word(interface, "output")?);
    let manifest = p.with_extension("jet.segment.json");
    let (f, id) = open_artifact(&manifest, 1001)?;
    let mut data = Vec::new();
    f.take((1 << 20) + 1).read_to_end(&mut data)?;
    ensure!(
        data.len() <= 1 << 20 && stamp(&manifest)? == id,
        "changed or oversized manifest"
    );
    let m: Value = serde_json::from_slice(&data)?;
    ensure!(
        m["schema_version"] == 1
            && m["epoch"] == 170
            && m["output_slot_start"] == SLOTS[0] + 1
            && m["output_slot_count"] == SLOTS[2] - SLOTS[0]
            && m["worker_executable_sha256"] == interface["worker_sha256"]
            && m["bootstrap"] == observed[0]
            && m["terminal"] == observed[2],
        "segment identity or coverage mismatch"
    );
    let (mut f, archive_id) = open_artifact(p, 1001)?;
    let mut hash = Sha256::new();
    let n = std::io::copy(&mut f, &mut hash)?;
    let sha = format!("{:x}", hash.finalize());
    ensure!(
        n > 0
            && archive_id[2] == n
            && stamp(p)? == archive_id
            && stamp(&manifest)? == id
            && m["archive_sha256"] == sha,
        "archive readback mismatch"
    );
    Ok(
        json!({"path":p,"identity":archive_id,"sha256":sha,"manifest":{"path":manifest,"sha256":digest(&data)},"raw_write_versions":m["emitted_raw_write_versions"]}),
    )
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
    let archive = if closed {
        closed_segment(&interface, &observed)?
    } else {
        Value::Null
    };
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"epoch170-bridge-checkpoint-comparison-v1","mode":args[0],"release":release_ref,
        "sample":fleet_ref,"log_prefix":log,"snapshot_list":hash_ref,"checkpoints":observed,"closed_segment":archive,"pid1_exit":exit,
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
