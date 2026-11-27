//! Check sealed native checkpoint, invocation and private segment evidence.
use super::{IID, SLOTS, UNIT, bridge_exit, evidence::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
pub(super) fn checkpoints(log: &str, hashes: &[&str], count: usize) -> Result<Vec<Value>> {
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
pub(super) fn open_artifact(p: &Path, uid: u32) -> Result<(File, Value)> {
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
pub(super) fn clean_exit(actor: &Value) -> Result<Value> {
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
pub(super) fn closed_segment(interface: &Value, observed: &[Value]) -> Result<Value> {
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
            && m["output_slot_count"] == SLOTS[SLOTS.len() - 1] - SLOTS[0]
            && m["worker_executable_sha256"] == interface["worker_sha256"]
            && m["bootstrap"] == observed[0]
            && m["terminal"] == observed[SLOTS.len() - 1],
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
