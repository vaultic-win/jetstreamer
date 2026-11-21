//! Observe the original singleton's completed publication and native termination.
//! Its 9-CPU, 68-GiB and disk bookings remain present in all resource totals.
use super::*;
use std::io::{Read, Seek, SeekFrom};

pub const NODE: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
const IID: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
const LANE: &str = "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1/replacement-local3retry9-20261110-v1";
const TXNS: &str = "private/destination-a016b4284060be2297b683ac3b88b986ff008872d936fd6e13eb4a9564ac54ae/evidence/archive-batches/destination-000000000000fc00-000000000596025a";
const MANIFEST: &str = "sha256:08b441e89d7c9456aba5026ce206db8e08a14f96cb31cbad94a4a5c5e6e5622b";
const MARKER: &str =
    "root-checkpoint cohort 166-166 published 1 archive(s) with checksums in transaction ";

pub fn drained() -> Result<()> {
    let s = joint_candidate::show(
        NODE,
        "Id,ActiveState,MainPID,ControlPID,Job,InvocationID,ControlGroup",
    )?;
    ensure!(
        s["Id"] == NODE
            && s["ActiveState"] == "inactive"
            && s["MainPID"] == "0"
            && s["ControlPID"] == "0"
            && s["Job"] == ""
            && (s["InvocationID"] == "" || s["InvocationID"] == IID)
            && !Path::new("/sys/fs/cgroup/system.slice").join(NODE).exists()
            && native::ticks(2452922).ok() != Some(349365780)
            && native::ticks(2453240).ok() != Some(349367290),
        "166 still executing, queued, or replaced"
    );
    Ok(())
}
fn transaction<'a>(log: &'a str, directory: &Path) -> Result<(&'a str, PathBuf)> {
    let mut terminal = log
        .lines()
        .filter_map(|l| l.split_once(MARKER).map(|(_, v)| v));
    let row = terminal
        .next()
        .context("166 has no durable singleton publication")?;
    ensure!(terminal.next().is_none(), "ambiguous singleton commit");
    let (tx, rest) = row
        .split_once("; receipt ")
        .context("166 transaction message")?;
    let path = directory.join(format!("batch-{tx}.json"));
    ensure!(
        custody::hex(tx, 64) && rest.strip_suffix(" is durable") == path.to_str(),
        "166 publication receipt path"
    );
    Ok((tx, path))
}
pub fn evidence() -> Result<Value> {
    drained()?;
    let witness = Path::new(RUNTIME).join("epoch166-terminal-20261121-v1");
    let live = Bound {
        path: witness.join("LIVE.json"),
        sha256: "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe".into(),
    };
    let l = custody::evidence(&live)?;
    let terminal = custody::binding(&witness.join("TERMINAL_SUCCESS.json"))?;
    let t = custody::evidence(&terminal)?;
    ensure!(
        l["epoch"] == 166
            && t["epoch"] == 166
            && t["live"] == json!(live)
            && t["source_admission"] == l["admission"]
            && t["producer_invocation_id"] == IID
            && t["terminal_166_disposition"] == "node-published-local-cohort"
            && t["resource_credit_bytes"] == 0,
        "166 shared terminal witness differs"
    );
    post::terminal_for(NODE, IID)?;
    let root = Path::new(LANE);
    for (name, p) in [
        ("producer_log", root.join("producer.log")),
        ("private_batch_receipts", root.join(TXNS)),
        ("output", root.join("output")),
    ] {
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && l[name]["path"] == json!(p)
                && l[name]["device"] == m.dev()
                && l[name]["inode"] == m.ino(),
            "166 retained namespace changed"
        );
    }
    let log = root.join("producer.log");
    let mut fd = File::open(&log)?;
    let m = fd.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && log.canonicalize()? == log && m.nlink() == 1,
        "166 stdout ownership"
    );
    fd.seek(SeekFrom::Start(m.len().saturating_sub(128 << 10)))?;
    let mut tail = Vec::new();
    fd.take(128 << 10).read_to_end(&mut tail)?;
    let quoted = String::from_utf8_lossy(&tail);
    let (tx, path) = transaction(&quoted, &root.join(TXNS))?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let before = source_lease::FileIdentity::from(&f.metadata()?);
    ensure!(
        path.canonicalize()? == path
            && f.metadata()?.is_file()
            && f.metadata()?.nlink() == 1
            && before.bytes <= 2 << 20,
        "166 receipt identity"
    );
    let mut data = Vec::new();
    f.read_to_end(&mut data)?;
    ensure!(
        source_lease::FileIdentity::from(&f.metadata()?) == before
            && source_lease::FileIdentity::from(&fs::symlink_metadata(&path)?) == before,
        "166 receipt changed"
    );
    let r: Value = serde_json::from_slice(&data)?;
    let commit = Bound {
        path: path.clone(),
        sha256: custody::sha(&data),
    };
    ensure!(
        t["committed_receipt"] == json!(commit),
        "different 166 batch in root terminal witness"
    );
    let output = root.join("output");
    let d = fs::symlink_metadata(&output)?;
    let rows = r["outcome"]["members"]
        .as_array()
        .context("166 committed members")?;
    ensure!(
        r["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && r["transaction_id"] == tx
            && r["manifest_fingerprint"] == MANIFEST
            && r["epochs"] == json!([166])
            && r["outcome"]["kind"] == "committed"
            && r["destination"]["device"] == d.dev()
            && r["destination"]["inode"] == d.ino()
            && r["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && r["root_checkpoint_gate"]["members"][0]["epoch"] == 166
            && rows.len() == 1
            && rows[0]["epoch"] == 166
            && rows[0]["archive_sha256"]
                .as_str()
                .is_some_and(|x| custody::hex(x, 64)),
        "foreign 166 transaction"
    );
    drained()?;
    Ok(
        json!({"unit":NODE,"invocation_id":IID,"pid1_success":true,"live":live,"terminal":terminal,"original_node":[2452922,349365780],
        "original_worker":[2453240,349367290],"batch":{"path":path,"sha256":custody::sha(&data)},
        "transaction":tx,"archive_sha256":rows[0]["archive_sha256"],"resource_credit_bytes":0}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requires_single_original_batch_name() {
        let tx = "a".repeat(64);
        let directory = Path::new("/data");
        let row = format!("node {MARKER}{tx}; receipt /data/batch-{tx}.json is durable");
        assert!(transaction(&row, directory).is_ok());
        assert!(transaction(&row.replace("/data/", "/foreign/"), directory).is_err());
        assert!(transaction(&format!("{row}\n{row}"), directory).is_err());
    }
}
