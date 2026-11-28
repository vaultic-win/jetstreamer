//! Read-only immutable input proof. Never restores a Bank or starts a worker.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const INPUT: &str = "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1";
const CAPPED: &str = "/var/lib/jetstreamer/horizon-227-capped-candidate-710f6523-v1";
const FINGERPRINT: &str = "sha256:99fa3de5ed1da720b76e33196d4ef4da9dda57202f12af90eaab60f84f9ecd31";
const SNAPSHOT: &str = "snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst";

fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
fn bound(path: &Path, sha: &str, maximum: u64) -> Result<Value> {
    ensure!(
        digest(sha) && path.is_absolute() && path.canonicalize()? == path,
        "invalid input binding"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "unsafe immutable input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        identity(&before, &file.metadata()?),
        "input replaced at open"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        bytes = bytes.checked_add(n as u64).context("input size overflow")?;
        ensure!(bytes <= maximum, "input grew");
        hash.update(&buffer[..n]);
    }
    let actual = format!("{:x}", hash.finalize());
    ensure!(
        actual == sha && bytes == before.len() && identity(&before, &fs::symlink_metadata(path)?),
        "input changed or digest differs"
    );
    Ok(
        json!({"path":path,"sha256":actual,"bytes":bytes,"device":before.dev(),"inode":before.ino()}),
    )
}
fn manifest_scope(v: &Value) -> Result<()> {
    ensure!(
        v["manifest_fingerprint"] == FINGERPRINT,
        "manifest fingerprint differs"
    );
    let m = &v["manifest"];
    ensure!(
        m["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && m["first_epoch"] == 227
            && m["last_epoch"] == 227,
        "manifest scope differs"
    );
    let cohorts = m["verification_cohorts"]
        .as_array()
        .context("cohort list")?;
    ensure!(cohorts.len() == 1, "cohort census differs");
    let c = &cohorts[0];
    ensure!(
        c["first_epoch"] == 227
            && c["last_epoch"] == 227
            && c["runtime"] == "solana-v1.6.20"
            && c["publication_gate"] == "all-archives-validated-and-final-root-verified"
            && c["bootstrap"]["slot"] == 98063464u64,
        "cohort binding differs"
    );
    let roots = c["root_checkpoints"].as_array().context("root list")?;
    ensure!(
        roots.len() == 1 && roots[0]["slot"] == 98495291u64,
        "canonical root census differs"
    );
    Ok(())
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 4
            && args[2] == "--self-sha256"
            && digest(&args[3])
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch227-input-capability RECEIPT --self-sha256 SHA (root)"
    );
    let output = Path::new(&args[1]);
    let parent = output.parent().context("receipt parent")?;
    ensure!(
        parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-227-input-capability-")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            && output.file_name().is_some_and(|n| n == "capability.json"),
        "receipt scope differs"
    );
    let d = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && d.is_dir() && d.uid() == 0 && d.mode() & 0o077 == 0,
        "unsafe receipt parent"
    );
    ensure!(!output.try_exists()?, "receipt already exists");
    let own = fs::read_link("/proc/self/exe")?;
    let own_binding = bound(&own, &args[3], 100 << 20)?;
    let mut inputs = Vec::new();
    for (directory, name, sha, limit) in [
        (
            INPUT,
            "jetstreamer-node",
            "f2c11e5b596e5a0107ddded523c310a1deb71b9206e95f3113f5ac713b920e11",
            100 << 20,
        ),
        (
            INPUT,
            "genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            1 << 20,
        ),
        (
            INPUT,
            "preflight227-singleton.json",
            "6a7f2ec35ded81d3577a062db0b4ddddf64b8a812856173c7600fb75ce7dcf53",
            1 << 20,
        ),
        (
            INPUT,
            SNAPSHOT,
            "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07",
            11u64 << 30,
        ),
        (
            CAPPED,
            "jetstreamer-historical-worker-v1-6-20",
            "710f6523d15b960f79d91935d18d581a341e04e649df26ccd0a2b31ae9bc3eeb",
            100 << 20,
        ),
        (
            CAPPED,
            "deployment-seal-receipt.json",
            "7b8f8823595225490146dac1d61c0130cdbbe3b600f3a323eeda278da6bd28ff",
            1 << 20,
        ),
    ] {
        inputs.push(bound(&Path::new(directory).join(name), sha, limit)?);
    }
    manifest_scope(&serde_json::from_slice(&fs::read(
        Path::new(INPUT).join("preflight227-singleton.json"),
    )?)?)?;
    let value = json!({"schema":"jetstreamer-private-epoch227-capped-input-capability-v1","epoch":227,
        "self":own_binding,"inputs":inputs,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "manifest_fingerprint":FINGERPRINT,"bootstrap_slot":98063464u64,"canonical_root_slot":98495291u64,
        "output_slot_start":98064000u64,"output_slot_end":98495999u64,"all_immutable_inputs_rehashed":true,
        "worker_spawned":false,"snapshot_restored":false,"archive_created":false,"replay_launch_authorized":false,
        "native_input_qualified":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), &value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(output)
        .map_err(|e| anyhow::anyhow!("receipt exists or cannot publish: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> Value {
        json!({"manifest_fingerprint":FINGERPRINT,"manifest":{
            "schema":"jetstreamer-gcs-snapshot-preflight-v4","first_epoch":227,"last_epoch":227,
            "verification_cohorts":[{"first_epoch":227,"last_epoch":227,"runtime":"solana-v1.6.20",
                "publication_gate":"all-archives-validated-and-final-root-verified",
                "bootstrap":{"slot":98063464u64},"root_checkpoints":[{"slot":98495291u64}]}]}})
    }
    #[test]
    fn scope_requires_original_runtime_and_canonical_singleton_root() {
        manifest_scope(&manifest()).unwrap();
        for (pointer, value) in [
            ("/manifest_fingerprint", json!("sha256:wrong")),
            ("/manifest/first_epoch", json!(223)),
            (
                "/manifest/verification_cohorts/0/runtime",
                json!("solana-v1.6.25"),
            ),
            (
                "/manifest/verification_cohorts/0/bootstrap/slot",
                json!(98063465),
            ),
            (
                "/manifest/verification_cohorts/0/root_checkpoints/0/slot",
                json!(98495999),
            ),
            (
                "/manifest/verification_cohorts/0/publication_gate",
                Value::Null,
            ),
        ] {
            let mut changed = manifest();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(manifest_scope(&changed).is_err(), "accepted {pointer}");
        }
    }
}
