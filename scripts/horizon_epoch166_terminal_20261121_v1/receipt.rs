//! Inspect local evidence from the already authenticated node. No archive bytes are copied.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::os::unix::ffi::OsStrExt;

fn identity(path: &Path, uid: u32) -> Result<Value> {
    ensure!(
        fs::canonicalize(path)? == path,
        "unexpected symlink: {}",
        path.display()
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == uid && m.mode() & 0o022 == 0,
        "unexpected file ownership/type: {}",
        path.display()
    );
    Ok(
        json!({"device":m.dev(),"inode":m.ino(),"mode":m.mode(),"uid":m.uid(),"gid":m.gid(),"link_count":m.nlink(),
        "length":m.size(),"modified_seconds":m.mtime(),"modified_nanoseconds":m.mtime_nsec(),
        "changed_seconds":m.ctime(),"changed_nanoseconds":m.ctime_nsec()}),
    )
}
fn dir(w: &Value) -> Result<PathBuf> {
    let p = PathBuf::from(s(&w["path"])?);
    ensure!(fs::canonicalize(&p)? == p, "non-canonical directory");
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        m.is_dir()
            && m.uid() == 1001
            && m.mode() & 0o077 == 0
            && w["device"] == m.dev()
            && w["inode"] == m.ino(),
        "directory ownership or identity changed"
    );
    Ok(p)
}
fn digest_string(value: &Value) -> Result<&str> {
    let x = s(value)?;
    ensure!(
        x.len() == 64
            && x.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid lowercase SHA-256"
    );
    Ok(x)
}
fn b58_hash(value: &Value) -> Result<Value> {
    let b = bs58::decode(s(value)?).into_vec()?;
    ensure!(b.len() == 32, "expected a 32-byte snapshot hash");
    Ok(json!(b))
}
// Old Faithful's final 64 slot-range rows and Blockzilla's last Compact V2 block
// independently place the last produced block at 72,143,999. The latter's
// blockhash registry binds the hash below. A terminal Bank is the last produced
// block; epoch coverage also includes any trailing skips.
const LAST_BLOCK: u64 = 72_143_999;
const LAST_BLOCK_HASH: [u8; 32] = [
    0x02, 0x97, 0x73, 0x8f, 0xbe, 0x93, 0x6f, 0x2a, 0x42, 0x0f, 0x58, 0x11, 0x64, 0xa0, 0x59, 0xa3,
    0x21, 0x27, 0x07, 0xb5, 0x3c, 0x02, 0x21, 0x82, 0x79, 0x60, 0x1c, 0x14, 0x50, 0x1b, 0x77, 0x23,
];

pub(super) struct TerminalBoundary {
    pub epoch: u64,
    pub last_block: u64,
    pub last_block_hash: [u8; 32],
}

const BOUNDARY166: TerminalBoundary = TerminalBoundary {
    epoch: 166,
    last_block: LAST_BLOCK,
    last_block_hash: LAST_BLOCK_HASH,
};

fn gate(live: &Value, receipt: &Value, boundary: &TerminalBoundary) -> Result<()> {
    ensure!(
        receipt["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && receipt["manifest_fingerprint"] == live["manifest_fingerprint"]
            && receipt["epochs"] == json!([boundary.epoch]),
        "wrong source receipt"
    );
    let g = &receipt["root_checkpoint_gate"];
    let checkpoint = &live["checkpoint"];
    ensure!(
        g["kind"] == "sealed-root-checkpoint-cohort"
            && g["version"] == 1
            && g["verified_manifest_checkpoints"]
                == json!([{"slot":checkpoint["slot"], "accounts_hash":b58_hash(&checkpoint["accounts_hash"])?}]),
        "trusted manifest checkpoint mismatch"
    );
    let members = g["members"].as_array().context("missing gate members")?;
    ensure!(
        members.len() == 1 && members[0]["epoch"] == boundary.epoch,
        "wrong gate membership"
    );
    let boot = &members[0]["bootstrap"];
    let end = &members[0]["terminal"];
    ensure!(
        boot["slot_complete"] == true
            && end["slot_complete"] == true
            && boot["slot"] == live["bootstrap"]["slot"]
            && boot["accounts_hash"] == b58_hash(&live["bootstrap"]["accounts_hash"])?
            && end["slot"] == boundary.last_block
            && end["last_blockhash"] == json!(boundary.last_block_hash)
            && live["epoch_bounds"][0]
                .as_u64()
                .is_some_and(|start| start <= boundary.last_block)
            && live["epoch_bounds"][1]
                .as_u64()
                .is_some_and(|end_slot| boundary.last_block <= end_slot),
        "bootstrap or complete terminal Bank mismatch"
    );
    let context: Value =
        serde_json::from_slice(&STANDARD.decode(s(&receipt["publication_context_base64"])?)?)?;
    let fp = context["manifest_fingerprint"]
        .as_array()
        .context("context fingerprint")?;
    let bytes = fp
        .iter()
        .map(|v| u8::try_from(v.as_u64().context("fingerprint byte")?).map_err(Into::into))
        .collect::<Result<Vec<u8>>>()?;
    let encoded = bytes.iter().map(|n| format!("{n:02x}")).collect::<String>();
    ensure!(
        bytes.len() == 32
            && format!("sha256:{encoded}") == s(&live["manifest_fingerprint"])?
            && context["schema"] == "jetstreamer-root-checkpoint-gate-context-v1"
            && context["epochs"] == receipt["epochs"]
            && context["gate"] == *g,
        "inconsistent embedded publication context"
    );
    Ok(())
}
pub(super) fn inspect(live: &Value) -> Result<Value> {
    inspect_with_boundary(live, &BOUNDARY166)
}

pub(super) fn inspect_with_boundary(live: &Value, boundary: &TerminalBoundary) -> Result<Value> {
    let epoch = boundary.epoch;
    let output = dir(&live["output"])?;
    let batches = dir(&live["private_batch_receipts"])?;
    let log = Path::new(s(&live["producer_log"]["path"])?);
    let log_id = identity(log, 0)?;
    ensure!(
        log_id["device"] == live["producer_log"]["device"]
            && log_id["inode"] == live["producer_log"]["inode"],
        "producer log replaced"
    );
    // The final success line is emitted after the cohort's cleanup_after_commit().
    let mut f = fs::File::open(log)?;
    f.seek(SeekFrom::End(-i64::try_from(
        f.metadata()?.len().min(131072),
    )?))?;
    let mut tail = Vec::new();
    f.take(131072).read_to_end(&mut tail)?;
    let prefix = format!(
        "root-checkpoint cohort {epoch}-{epoch} published 1 archive(s) with checksums in transaction "
    );
    let text = String::from_utf8_lossy(&tail);
    let markers: Vec<_> = text
        .lines()
        .filter_map(|line| line.split_once(prefix.as_str()).map(|(_, tail)| tail))
        .collect();
    ensure!(
        markers.len() == 1,
        "expected one final local publication marker"
    );
    let (tx, location) = markers[0]
        .split_once("; receipt ")
        .context("partial publication marker")?;
    ensure!(
        tx.len() == 64
            && tx
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid transaction ID"
    );
    let rp = batches.join(format!("batch-{tx}.json"));
    let published = location
        .strip_suffix(" is durable")
        .context("incomplete receipt marker")?;
    ensure!(Path::new(published) == rp, "marker names another receipt");
    let rid = identity(&rp, 1001)?;
    let raw = small(&rp, 32 << 20)?;
    let receipt: Value = serde_json::from_slice(&raw)?;
    gate(live, &receipt, boundary)?;
    ensure!(
        receipt["transaction_id"] == tx
            && receipt["destination"]["device"] == live["output"]["device"]
            && receipt["destination"]["inode"] == live["output"]["inode"]
            && receipt["destination"]["path_base64"]
                == STANDARD.encode(output.as_os_str().as_bytes()),
        "foreign transaction/destination"
    );
    let o = &receipt["outcome"];
    let m = o["members"]
        .as_array()
        .context("missing publication members")?;
    ensure!(
        o["kind"] == "committed" && m.len() == 1 && m[0]["epoch"] == epoch,
        "no single committed epoch {epoch}"
    );
    let m = &m[0];
    for k in [
        "initial_archive",
        "initial_checksum",
        "initial_manifest",
        "manifest_path_base64",
        "committed_manifest",
    ] {
        ensure!(
            m.get(k) == Some(&Value::Null),
            "unexpected prior or segment artifact {k}"
        );
    }
    let archive = output.join(format!("epoch-{epoch}.jet"));
    let sum = output.join(format!("epoch-{epoch}.jet.sha256"));
    let a = identity(&archive, 1001)?;
    let c = identity(&sum, 1001)?;
    let h = digest_string(&m["archive_sha256"])?;
    ensure!(
        m["archive_path_base64"] == STANDARD.encode(archive.as_os_str().as_bytes())
            && m["checksum_path_base64"] == STANDARD.encode(sum.as_os_str().as_bytes()),
        "foreign local output names"
    );
    ensure!(
        a == m["committed_archive"]
            && c == m["committed_checksum"]
            && a["length"].as_u64().context("missing length")? > 0,
        "committed output identity changed"
    );
    ensure!(
        small(&sum, 1024)? == format!("{h}  epoch-{epoch}.jet\n").as_bytes(),
        "local checksum mismatch"
    );
    ensure!(
        a == identity(&archive, 1001)?
            && c == identity(&sum, 1001)?
            && rid == identity(&rp, 1001)?
            && log_id == identity(log, 0)?,
        "evidence changed during observation"
    );
    Ok(
        json!({"transaction_id":tx,"local_archive":{"path":archive,"device":a["device"],"inode":a["inode"],"size":a["length"],"sha256":h},
        "committed_receipt":{"path":rp,"sha256":format!("{:x}",Sha256::digest(raw))},"producer_log":log_id}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, chown};

    fn inputs() -> (Value, Value) {
        let a = [39u8; 32];
        let b = [78u8; 32];
        let fp = [19u8; 32];
        let live = json!({"bootstrap":{"slot":71711708,"accounts_hash":bs58::encode(a).into_string()},"checkpoint":{"slot":72143703,"accounts_hash":bs58::encode(b).into_string()},"epoch_bounds":[71712000,72143999],"manifest_fingerprint":format!("sha256:{}","13".repeat(32))});
        let gate = json!({"kind":"sealed-root-checkpoint-cohort","version":1,"verified_manifest_checkpoints":[{"slot":72143703,"accounts_hash":b}],
            "members":[{"epoch":166,"bootstrap":{"slot_complete":true,"slot":71711708,"accounts_hash":a},"terminal":{"slot_complete":true,"slot":72143999,"last_blockhash":LAST_BLOCK_HASH}}]});
        let ctx = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1","manifest_fingerprint":fp,"epochs":[166],"gate":gate});
        let receipt = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","epochs":[166],"manifest_fingerprint":live["manifest_fingerprint"],"root_checkpoint_gate":gate,"publication_context_base64":STANDARD.encode(serde_json::to_vec(&ctx).unwrap())});
        (live, receipt)
    }
    #[test]
    fn receipt_binds_complete_epoch_bootstrap_checkpoint_and_serialized_gate() {
        let (live, r) = inputs();
        assert!(gate(&live, &r, &BOUNDARY166).is_ok());
        let foreign = TerminalBoundary {
            epoch: 168,
            ..BOUNDARY166
        };
        assert!(gate(&live, &r, &foreign).is_err());
        for (ptr, v) in [
            ("/schema", json!("v1")),
            (
                "/root_checkpoint_gate/members/0/terminal/last_blockhash",
                json!([0]),
            ),
            ("/epochs", json!([167])),
            (
                "/root_checkpoint_gate/members/0/terminal/slot",
                json!(72143703),
            ),
            (
                "/root_checkpoint_gate/verified_manifest_checkpoints/0/accounts_hash",
                json!([0]),
            ),
            (
                "/root_checkpoint_gate/members/0/bootstrap/slot_complete",
                json!(false),
            ),
            ("/publication_context_base64", json!("e30=")),
        ] {
            let mut changed = r.clone();
            *changed.pointer_mut(ptr).unwrap() = v;
            assert!(gate(&live, &changed, &BOUNDARY166).is_err(), "{ptr}");
        }
    }
    #[test]
    #[ignore = "run as root in the admitted private fixture directory"]
    fn native_committed_inode_fixture() -> Result<()> {
        let (live, r) = inputs();
        committed_inode_fixture("TERMINAL166_PRIVATE_FIXTURE", live, r, &BOUNDARY166)
    }

    #[cfg(feature = "metered168")]
    #[test]
    #[ignore = "requires the actual producer witness and a private fixture directory"]
    fn metered168_committed_inode_fixture() -> Result<()> {
        generation_inode_fixture()
    }

    #[cfg(any(
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    #[test]
    #[ignore = "requires the anchored RPC proof and original producer witness"]
    fn finalized_generation_committed_inode_fixture() -> Result<()> {
        generation_inode_fixture()
    }

    #[cfg(any(
        feature = "metered168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    fn generation_inode_fixture() -> Result<()> {
        let live = checked_live()?;
        let expected = generation::boundary(&live)?;
        let checkpoint = &live["checkpoint"];
        let bootstrap = &live["bootstrap"];
        let fp = s(&live["manifest_fingerprint"])?
            .strip_prefix("sha256:")
            .context("manifest prefix")?;
        let fingerprint = (0..32)
            .map(|i| u8::from_str_radix(&fp[2 * i..2 * i + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let gate = json!({"kind":"sealed-root-checkpoint-cohort","version":1,
            "verified_manifest_checkpoints":[{"slot":checkpoint["slot"],"accounts_hash":b58_hash(&checkpoint["accounts_hash"])?}],
            "members":[{"epoch":EPOCH,"bootstrap":{"slot_complete":true,"slot":bootstrap["slot"],"accounts_hash":b58_hash(&bootstrap["accounts_hash"])?},
                "terminal":{"slot_complete":true,"slot":expected.last_block,"last_blockhash":expected.last_block_hash}}]});
        let ctx = json!({"schema":"jetstreamer-root-checkpoint-gate-context-v1","manifest_fingerprint":fingerprint,"epochs":[EPOCH],"gate":gate});
        let r = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","epochs":[EPOCH],"manifest_fingerprint":live["manifest_fingerprint"],
            "root_checkpoint_gate":gate,"publication_context_base64":STANDARD.encode(serde_json::to_vec(&ctx)?)});
        let mut foreign = live.clone();
        foreign["independent_boundary"]["sha256"] = json!("0".repeat(64));
        assert!(generation::boundary(&foreign).is_err());
        assert!(super::gate(&live, &r, &BOUNDARY166).is_err());
        committed_inode_fixture(
            &format!("TERMINAL{EPOCH}_PRIVATE_FIXTURE"),
            live,
            r,
            &expected,
        )
    }

    fn committed_inode_fixture(
        env: &str,
        mut live: Value,
        mut r: Value,
        boundary: &TerminalBoundary,
    ) -> Result<()> {
        let epoch = boundary.epoch;
        ensure!(
            unsafe { libc::geteuid() } == 0,
            "fixture needs root ownership for producer log"
        );
        let fixture = PathBuf::from(std::env::var(env)?);
        ensure!(
            fixture.is_absolute() && !fixture.try_exists()?,
            "fresh fixture required"
        );
        fs::create_dir(&fixture)?;
        let out = fixture.join("output");
        let batches = fixture.join("receipts");
        let dir_ref = |p: &Path| -> Result<Value> {
            fs::create_dir(p)?;
            chown(p, Some(1001), Some(1003))?;
            fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
            let m = p.metadata()?;
            Ok(json!({"path":p,"device":m.dev(),"inode":m.ino()}))
        };
        live["output"] = dir_ref(&out)?;
        live["private_batch_receipts"] = dir_ref(&batches)?;
        let write = |p: &Path, b: &[u8], uid: u32| -> Result<()> {
            fs::write(p, b)?;
            chown(p, Some(uid), Some(1003))?;
            fs::set_permissions(p, fs::Permissions::from_mode(0o600))?;
            Ok(())
        };
        let archive = out.join(format!("epoch-{epoch}.jet"));
        let checksum = out.join(format!("epoch-{epoch}.jet.sha256"));
        let data = b"archive-identity fixture";
        let hash = format!("{:x}", Sha256::digest(data));
        let tx = "6f".repeat(32);
        let rp = batches.join(format!("batch-{tx}.json"));
        write(&archive, data, 1001)?;
        write(
            &checksum,
            format!("{hash}  epoch-{epoch}.jet\n").as_bytes(),
            1001,
        )?;
        r["transaction_id"] = json!(tx);
        r["destination"] = json!({"device":live["output"]["device"],"inode":live["output"]["inode"],"path_base64":STANDARD.encode(out.as_os_str().as_bytes())});
        r["outcome"] = json!({"kind":"committed","members":[{"epoch":epoch,"archive_path_base64":STANDARD.encode(archive.as_os_str().as_bytes()),"checksum_path_base64":STANDARD.encode(checksum.as_os_str().as_bytes()),"archive_sha256":hash,"initial_archive":null,"initial_checksum":null,"initial_manifest":null,"manifest_path_base64":null,"committed_manifest":null,"committed_archive":identity(&archive,1001)?,"committed_checksum":identity(&checksum,1001)?}]});
        write(&rp, &serde_json::to_vec(&r)?, 1001)?;
        let log = fixture.join("producer.log");
        write(&log,format!("root-checkpoint cohort {epoch}-{epoch} published 1 archive(s) with checksums in transaction {tx}; receipt {} is durable\n",rp.display()).as_bytes(),0)?;
        let m = log.metadata()?;
        live["producer_log"] = json!({"path":log,"device":m.dev(),"inode":m.ino()});
        let good = inspect_with_boundary(&live, boundary)?;
        assert_eq!(good["local_archive"]["sha256"], hash);
        let original = r.clone();
        r["outcome"]["kind"] = json!("rolled_back");
        write(&rp, &serde_json::to_vec(&r)?, 1001)?;
        assert!(inspect_with_boundary(&live, boundary).is_err());
        write(&rp, &serde_json::to_vec(&original)?, 1001)?;
        fs::hard_link(&archive, out.join("alias"))?;
        assert!(inspect_with_boundary(&live, boundary).is_err());
        fs::remove_file(out.join("alias"))?;
        write(&checksum, b"bad\n", 1001)?;
        assert!(inspect_with_boundary(&live, boundary).is_err());
        Ok(())
    }
}
