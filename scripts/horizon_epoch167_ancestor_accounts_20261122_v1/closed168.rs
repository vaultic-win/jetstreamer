//! Retire only the stopped full-metered worker's four private AppendVec shards.
use super::*;
use std::os::fd::AsRawFd;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-closed-accounts-20261122-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles168.json");
pub(super) const CHECK_SCHEMA: &str = "horizon168-stopped-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon168-stopped-accounts-complete-v1";
const IID: &str = "9cebb1d022124fb08588e93e055d5446";
const BOOT_SHA: &str = "f1a8902dcb00eb59266a2f688d05f7d406af1999eb78956bfd0c46056571ad04";

fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() * 1_000_000_000 + m.mtime_nsec(),
        m.ctime() * 1_000_000_000 + m.ctime_nsec()
    ])
}

fn open_input(row: &Value) -> Result<File> {
    let path = Path::new(string(row, "path")?);
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.dev() == DEVICE
            && row["identity"] == identity(&m)
            && row["identity"] == identity(&fs::symlink_metadata(path)?)
            && (row["links"].is_null() || row["links"] == m.nlink()),
        "changed retained file {}",
        path.display()
    );
    Ok(f)
}

fn digest(row: &Value) -> Result<String> {
    let mut file = open_input(row)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut file, &mut hash)?;
    ensure!(
        row["identity"] == identity(&file.metadata()?)
            && row["identity"] == identity(&open_input(row)?.metadata()?),
        "retained input changed during read"
    );
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn leases(manifest: &Value) -> Result<Vec<File>> {
    let rows = manifest["profiles"]["full-metered"]["leases"]
        .as_array()
        .context("missing publication and mutation locks")?;
    ensure!(rows.len() == 2, "incomplete lock set");
    rows.iter()
        .map(|row| {
            let file = open_input(row)?;
            ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "occupied {}",
                row["path"]
            );
            Ok(file)
        })
        .collect()
}

pub(super) fn gates(p: &Value, manifest: &Value) -> Result<Value> {
    let target = Path::new(string(p, "target")?);
    let worker = bound(&manifest["worker"])?;
    let stop = bound(&manifest["stop"])?;
    let payload = bound(&manifest["payload"])?;
    let admission = bound(&manifest["admission"])?;
    let argv = bound(&manifest["launch"])?;
    let scratch = Path::new(string(&worker["observer_row"], "scratch_path")?);
    ensure!(
        p["iid"] == IID
            && admission["producer_invocation_id"] == IID
            && worker["admission"] == manifest["admission"]
            && stop["producer_invocation_id"] == IID
            && stop["terminal"]["pid"] == 0
            && stop["scratch_deleted"] == false
            && payload["epoch"] == 168
            && payload["whole_root_cap"] == 288u64 << 30
            && payload["bootstrap"]["slot"] == 72_575_704
            && payload["bootstrap_file"]["sha256"] == BOOT_SHA
            && payload["root_checkpoint"]["slot"] == 73_007_829
            && target.starts_with(scratch.join(".historical-runtime"))
            && target.file_name().is_some_and(|n| n == "accounts-state")
            && path_identity_matches(target, p)?,
        "foreign stopped worker, target or snapshot"
    );
    closed(string(&payload, "producer_unit")?)?;
    let guard = string(&payload, "guard_unit")?;
    closed(&format!("{guard}.service"))?;
    closed(&format!("{guard}.timer"))?;
    let args = argv.as_array().context("producer argv")?;
    ensure!(
        args.contains(&json!("--setenv=JETSTREAMER_CLEAR_ACCOUNTS_ON_START=true"))
            && args.contains(&json!("--setenv=JETSTREAMER_LOAD_FROM_DIR=0"))
            && args.last()
                == Some(&json!(format!(
                    "--snapshot-archive={}",
                    string(&payload["bootstrap_file"], "path")?
                ))),
        "original run did not cold start from the retained snapshot"
    );
    let saved = p["preserved"].as_array().context("preserved inputs")?;
    ensure!(
        saved.len() == 8
            && saved[1]["path"] == payload["bootstrap_file"]["path"]
            && saved[2]["path"] == payload["retained_terminal_partial"]["path"],
        "missing protected prefixes or bootstrap"
    );
    for f in saved {
        ensure!(
            !Path::new(string(f, "path")?).starts_with(target),
            "protected input inside target"
        );
        open_input(f)?;
    }
    let snapshots = target
        .parent()
        .context("runtime")?
        .join("unpacked/snapshots");
    let mut banks = fs::read_dir(&snapshots)?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    banks.sort();
    ensure!(
        banks == ["72575704", "status_cache"]
            && Path::new(string(&saved[4], "path")?) == snapshots.join("72575704/72575704")
            && sha(&fs::read(string(&saved[3], "path")?)?) == p["cohort_sha256"],
        "retained bank or cohort changed"
    );
    for pair in payload["indexes"].as_array().context("compact indexes")? {
        open_input(&pair["source"])?;
        open_input(&pair["independent_trace_copy"])?;
    }
    open_input(&payload["genesis"])?;
    witness_disjoint(target, &manifest["witness"])?;
    Ok(
        json!({"owner":IID,"scope":target,"admission":manifest["admission"],"stop":manifest["stop"],
              "payload":manifest["payload"],"preserved":saved,"witness":manifest["witness"]}),
    )
}

fn path_identity_matches(target: &Path, row: &Value) -> Result<bool> {
    let m = target.symlink_metadata()?;
    Ok(m.is_dir()
        && m.dev() == DEVICE
        && m.ino() == 109775327
        && row["inode"] == m.ino()
        && target.canonicalize()? == target)
}

pub(super) fn check_inventory(
    p: &Value,
    manifest: &Value,
    ledger: &stopped_tree::Ledger,
    allocated: u64,
) -> Result<()> {
    check_appendvecs(p, ledger, allocated, 288 << 30)?;
    ensure!(
        p["expected_entries"] == (ledger.len() - 1) as u64 && p["expected_bytes"] == allocated,
        "enrolled AppendVec set changed"
    );
    let j = bound(&manifest["payload"])?;
    let worker = bound(&manifest["worker"])?;
    let saved = p["preserved"].as_array().context("protected inputs")?;
    ensure!(
        digest(&saved[1])? == BOOT_SHA
            && digest(&saved[7])? == BOOT_SHA
            && digest(&saved[6])? == worker["worker_sha256"]
            && digest(&j["genesis"])? == j["genesis"]["sha256"],
        "bootstrap, worker or genesis hash changed"
    );
    let indexes = j["indexes"].as_array().context("compact indexes")?;
    ensure!(indexes.len() == 3, "incomplete indexes");
    for pair in indexes {
        ensure!(
            digest(&pair["source"])? == digest(&pair["independent_trace_copy"])?,
            "original and diagnostic index differ"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires original host and immutable evidence"]
    fn stopped_metered168_accepts_original_and_rejects_changed_inputs() {
        let manifest: Value = serde_json::from_slice(PROFILE).unwrap();
        let row = &manifest["profiles"]["full-metered"];
        gates(row, &manifest).unwrap();
        for key in ["iid", "inode", "cohort_sha256"] {
            let mut bad = row.clone();
            bad[key] = Value::Null;
            assert!(gates(&bad, &manifest).is_err());
        }
        let mut bad = row.clone();
        bad["preserved"][0]["identity"][1] = json!(0);
        assert!(gates(&bad, &manifest).is_err());
    }
}
