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
fn terminal_witness(path: &Path, live: &Bound, l: &Value) -> Result<(Bound, Value)> {
    let before = custody::frozen_identity(path)?;
    ensure!(
        before.mode & 0o7777 == 0o400,
        "166 terminal record is not root-private and sealed"
    );
    let (terminal, t) = joint_candidate::immutable(path)?;
    let boot = l["boot_id"]
        .as_str()
        .context("166 original boot")?
        .replace('-', "");
    let manager = &t["manager_terminal"];
    ensure!(
        custody::frozen_identity(path)? == before
            && l["epoch"] == 166
            && t["epoch"] == 166
            && t["schema"] == "terminal166-success-v1"
            && t["live"] == json!(live)
            && t["source_admission"] == l["admission"]
            && t["producer_unit"] == NODE
            && t["producer_invocation_id"] == IID
            && t["terminal_166_disposition"] == "node-published-local-cohort"
            && t["resource_credit_bytes"] == 0
            && t["reservation_ending_bytes"] == 0
            && t["archive_publication_authorized"] == false
            && t["new_producer_authorized"] == false
            && t["canonical_r2_verified"] == false
            && custody::hex(&boot, 32)
            && manager["_BOOT_ID"] == boot
            && manager["_PID"] == "1"
            && manager["UNIT"] == NODE
            && manager["INVOCATION_ID"] == IID
            && manager["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "166 shared terminal witness differs"
    );
    Ok((terminal, t))
}
pub fn evidence() -> Result<Value> {
    drained()?;
    let witness = Path::new(RUNTIME).join("epoch166-terminal-20261121-v1");
    let live = Bound {
        path: witness.join("LIVE.json"),
        sha256: "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe".into(),
    };
    let l = custody::evidence(&live)?;
    let (terminal, t) = terminal_witness(&witness.join("TERMINAL_SUCCESS.json"), &live, &l)?;
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
        t["committed_receipt"] == json!(commit) && t["transaction_id"] == tx,
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
    let archive = output.join("epoch-166.jet");
    let m = fs::symlink_metadata(&archive)?;
    let local = &t["local_archive"];
    ensure!(
        archive.canonicalize()? == archive
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 1001
            && m.len() > 0
            && m.mode() & 0o022 == 0
            && local
                == &json!({"path":archive,"device":m.dev(),"inode":m.ino(),"size":m.len(),"sha256":rows[0]["archive_sha256"]})
            && rows[0]["committed_archive"]["device"] == m.dev()
            && rows[0]["committed_archive"]["inode"] == m.ino()
            && rows[0]["committed_archive"]["length"] == m.len(),
        "166 committed archive no longer bound"
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
    #[ignore = "requires a root-owned mode-0400 terminal wire fixture"]
    fn native_terminal_wire() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("TERMINAL_SUCCESS.json");
        let live = Bound {
            path: dir.path().join("LIVE.json"),
            sha256: "d".repeat(64),
        };
        let l = json!({"epoch":166,"admission":{"path":"/original","sha256":"a".repeat(64)},"boot_id":"98d519fa-c309-4b01-bdac-87844db51fc7"});
        let t = json!({"schema":"terminal166-success-v1","epoch":166,"producer_invocation_id":IID,
            "live":live,"source_admission":l["admission"],"terminal_166_disposition":"node-published-local-cohort",
            "local_archive":{"path":"/original/epoch-166.jet","device":1,"inode":2,"size":3,"sha256":"f".repeat(64)},
            "committed_receipt":{"path":"/original/receipt","sha256":"b".repeat(64)},"transaction_id":"c".repeat(64),
            "producer_log":{"device":1,"inode":5},"manager_terminal":{"_PID":"1","_BOOT_ID":"98d519fac3094b01bdac87844db51fc7",
            "UNIT":NODE,"INVOCATION_ID":IID,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"},
            "producer_unit":NODE,"resource_credit_bytes":0,"reservation_ending_bytes":0,"archive_publication_authorized":false,
            "new_producer_authorized":false,"canonical_r2_verified":false});
        let wire = serde_json::to_vec_pretty(&t).unwrap();
        fs::write(&path, &wire).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            terminal_witness(&path, &live, &l).unwrap(),
            (
                Bound {
                    path: path.clone(),
                    sha256: custody::sha(&wire)
                },
                t.clone()
            )
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(terminal_witness(&path, &live, &l).is_err());
        for (key, value) in [
            ("schema", json!("unknown")),
            ("resource_credit_bytes", json!(1)),
            ("source_admission", Value::Null),
            ("producer_invocation_id", json!("0".repeat(32))),
            ("manager_terminal", Value::Null),
        ] {
            let mut bad = t.clone();
            bad[key] = value;
            fs::write(&path, serde_json::to_vec(&bad).unwrap()).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
            assert!(terminal_witness(&path, &live, &l).is_err());
        }
    }
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
