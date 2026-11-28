//! Retire the exact unpacked no-worker accounts and two obsolete compact-index caches.
use super::retirement_evidence::{digest, open_input, pinned_path, staged_references};
pub(super) use super::retirement_evidence::{verify_campaign_lock, verify_image};
use super::*;
use std::os::fd::AsRawFd;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/closed145198-input-retirement-20261128-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles145198_closed.json");
pub(super) const CHECK_SCHEMA: &str = "horizon-145198-closed-input-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon-145198-closed-input-complete-v1";
const UNIT: &str = "horizon-epoch145-no-worker-plan-20261101-v1.service";
const IID: &str = "128b9c382fcb492c817ea9baf0432f70";
const P145: &str = "/home/sol/.jetstreamer-private/epoch145-no-worker-plan-20261101-v1/scratch/.historical-runtime/jetstreamer-historical-parent-yj3eTI/jetstreamer-historical-v1.4.25-wC3uLj/unpacked/accounts";
const I145: &str = "/home/sol/.jetstreamer-private/epoch145-cached-b2a09f57de39c384/work/ledger/compact-indexes/145";
const I198: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/output/compact-indexes/198";

pub(super) fn owner(p: &Value) -> Result<(u32, u32)> {
    match string(p, "target")? {
        P145 => Ok((0, 0)),
        I145 => Ok((1001, 1001)),
        I198 => Ok((1001, 1003)),
        _ => anyhow::bail!("unknown closed input scope"),
    }
}

pub(super) fn leases(manifest: &Value) -> Result<Vec<File>> {
    let file = open_input(&manifest["scope"]["leases"]["local_mutation"])?;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "local mutation lease held"
    );
    Ok(vec![file])
}

pub(super) fn gates(p: &Value, _: &Value) -> Result<Value> {
    let target = Path::new(string(p, "target")?);
    let epoch = p["epoch"].as_u64().context("closed epoch")?;
    let delivery = bound(&p["delivery"])?;
    let archive_sha = string(&delivery, "archive_sha256")?;
    ensure!(
        delivery["epoch"] == epoch
            && archive_sha.len() == 64
            && archive_sha.bytes().all(|c| c.is_ascii_hexdigit()),
        "foreign canonical readback"
    );
    let fleet = bound(&p["fleet"])?;
    ensure!(
        fleet["epochs"].as_array().is_some_and(|items| items
            .iter()
            .any(|row| row["epoch"] == epoch
                && row["state"] == "remote-ready"
                && row["inventory_state"] == "ready-pair")),
        "closed input lacks a confirmed ready pair"
    );
    for proof in p["boundaries"]
        .as_array()
        .context("missing boundary evidence")?
    {
        ensure!(
            !super::retirement_evidence::bound_bytes(proof, 1 << 20)?.is_empty(),
            "missing boundary proof"
        );
    }
    if target == Path::new(P145) {
        let terminal = bound(&p["terminal"])?;
        let seal = bound(&p["input_seal"])?;
        let snapshot = &p["snapshot"];
        let native = unit(UNIT)?;
        ensure!(
            p["iid"] == IID
                && terminal["native_terminal"]["InvocationID"] == IID
                && terminal["native_terminal"]["Result"] == "timeout"
                && terminal["worker_execution_forbidden_by_NoExecPaths"] == true
                && terminal["actual_worker_start_not_claimed"] == true
                && terminal["no_archive_created"] == true
                && terminal["snapshot_and_image_rehashed_by_Rust_sealer"] == p["input_seal"]
                && native["Id"] == UNIT
                && native["InvocationID"] == IID
                && native["ActiveState"] == "failed"
                && native["MainPID"] == "0"
                && native["ControlPID"] == "0"
                && native["Job"].is_empty()
                && native["ControlGroup"].is_empty()
                && native["Triggers"].is_empty()
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(UNIT)
                    .try_exists()?,
            "no-worker scope is live or lacks the exact bounded timeout"
        );
        let snapshot_path = pinned_path(snapshot)?;
        ensure!(
            !snapshot_path.starts_with(target)
                && seal["members"]
                    .as_array()
                    .is_some_and(|rows| rows.iter().any(|row| row["name"]
                        .as_str()
                        .is_some_and(|name| snapshot_path.ends_with(name))
                        && row["sha256"] == snapshot["sha256"])),
            "sealed reproducible bootstrap missing"
        );
    } else if target == Path::new(I145) {
        let retirement = bound(&p["terminal"])?;
        ensure!(
            epoch == 145 && retirement["schema"] == p["terminal_schema"],
            "closed epoch 145 diagnostic evidence changed"
        );
    } else {
        let terminal = bound(&p["terminal"])?;
        let prior_audit = super::retirement_evidence::bound_bytes(
            &terminal["authenticated_retirement_receipt"],
            1 << 20,
        )?;
        ensure!(
            target == Path::new(I198)
                && epoch == 198
                && p["boundaries"]
                    .as_array()
                    .is_some_and(|rows| rows.len() == 2)
                && delivery["remote_sha256_readback"] == true
                && terminal["r2_mutations"] == false
                && !prior_audit.is_empty()
                && terminal["removed_allocated_bytes"]
                    .as_u64()
                    .is_some_and(|bytes| bytes > 0),
            "closed epoch 198 delivery or terminal differs"
        );
    }
    if target != Path::new(P145) {
        let origins = bound(&p["reproducible_indexes"])?;
        let members = p["indexes"]
            .as_object()
            .context("missing closed index members")?;
        ensure!(members.len() == 2, "unexpected compact index pair");
        for (name, member) in members {
            let source = &origins[name];
            ensure!(
                source["status"] == 200
                    && source["bytes"] == member["length"]
                    && source["url"] == format!("https://files.old-faithful.net/{epoch}/{name}"),
                "unverified compact index origin"
            );
        }
    }
    let mut visited = std::collections::BTreeSet::new();
    for dir in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/etc/cron.d",
    ] {
        if Path::new(dir).try_exists()? {
            staged_references(Path::new(dir), &[target], &[], &mut visited)?;
        }
    }
    Ok(json!({"profile":p,"archive_sha256":archive_sha}))
}

pub(super) fn check_inventory(
    p: &Value,
    _: &Value,
    ledger: &stopped_tree::Ledger,
    bytes: u64,
) -> Result<()> {
    let target = Path::new(string(p, "target")?);
    ensure!(
        p["expected_bytes"] == bytes && p["expected_entries"] == (ledger.len() - 1) as u64,
        "selected allocation differs"
    );
    for (name, entry) in ledger {
        let row = serde_json::to_value(entry)?;
        if name.is_empty() {
            ensure!(
                row["directory"] == true && row["inode"] == p["inode"],
                "wrong root"
            );
        } else if target == Path::new(P145) {
            let digits = |n: &str| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit());
            ensure!(
                row["directory"] == false
                    && name
                        .split_once('.')
                        .is_some_and(|(a, b)| digits(a) && digits(b)),
                "unexpected unpacked account name"
            );
        } else {
            let member = p["indexes"].get(name).context("unexpected index name")?;
            ensure!(
                row["directory"] == false
                    && row["inode"] == member["inode"]
                    && row["blocks"] == member["blocks"]
                    && row["length"] == member["length"],
                "closed index identity changed"
            );
        }
    }
    if target == Path::new(P145) {
        ensure!(
            digest(&p["snapshot"])? == p["snapshot"]["sha256"],
            "retained bootstrap digest changed"
        );
    }
    Ok(())
}
