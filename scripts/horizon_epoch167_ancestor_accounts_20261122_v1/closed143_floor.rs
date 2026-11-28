//! Retire only the four stopped AccountsDb shards from this private 143 invocation.
use super::retirement_evidence::{
    digest, drained, open_input, path, pinned_path, staged_references,
};
pub(super) use super::retirement_evidence::{verify_campaign_lock, verify_image};
use super::*;
use std::os::fd::AsRawFd;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch143-second-floor-accounts-20261128-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles143_floor.json");
pub(super) const CHECK_SCHEMA: &str = "horizon-143-second-floor-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon-143-second-floor-accounts-complete-v1";
const IID: &str = "a04721854c644797903440d2a7eade08";
const WORK: &str = "/home/sol/.jetstreamer-private/epoch143-second-hourly-20261128-v1";

pub(super) fn leases(manifest: &Value) -> Result<Vec<File>> {
    // Every issuer of this interval takes the campaign lock. This namespace has no private epoch lockfile.
    let lock = open_input(&manifest["scope"]["leases"]["local_mutation"])?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "local mutation lease held"
    );
    Ok(vec![lock])
}

pub(super) fn gates(p: &Value, _: &Value) -> Result<Value> {
    let terminal = bound(&p["terminal"])?;
    let plan = bound(&terminal["guard_plan"])?;
    let stop = bound(&terminal["stop_completion"])?;
    let intent = bound(&terminal["stop_intent"])?;
    let custody = bound(&p["source"])?;
    let first = bound(&p["closure"])?;
    let contract = bound(&p["contract"])?;
    let target = Path::new(string(p, "target")?);
    let parent =
        Path::new(WORK).join("scratch/.historical-runtime/jetstreamer-historical-parent-NM5GOs");
    ensure!(
        target == parent.join("jetstreamer-historical-v1.4.25-GEHzvy/accounts-state")
            && target.canonicalize()? == target
            && target.symlink_metadata()?.ino() == 120127494,
        "unregistered account root"
    );
    ensure!(
        terminal["invocation_id"] == IID
            && terminal["disposition"] == "filesystem-floor-guard-stop-incomplete"
            && terminal["completed_epoch"] == false
            && terminal["output"]["bytes"] == 0
            && p["iid"] == IID
            && p["unit"] == terminal["unit"]
            && plan["unit"] == terminal["unit"]
            && plan["worker_root"] == WORK
            && plan["invocation_id"] == IID
            && intent["producer_invocation_id"] == IID
            && intent["reason"] == "filesystem-floor"
            && intent["plan_sha256"] == terminal["guard_plan"]["sha256"]
            && stop["plan_sha256"] == intent["plan_sha256"]
            && stop["intent"] == terminal["stop_intent"]["path"]
            && stop["producer_invocation_id"] == IID
            && stop["terminal"]["pid"] == 0
            && stop["scratch_deleted"] == false,
        "foreign stop or incomplete native drain"
    );
    let rows = p["protected"]
        .as_array()
        .context("missing retained files")?;
    ensure!(
        rows.len() == 5
            && custody["slot"] == 61_787_631
            && custody["generation"] == 1634786651485428u64
            && first["terminal_slot"] == custody["slot"]
            && custody["snapshot"]["path"] == rows[0]["path"]
            && custody["snapshot"]["sha256"] == rows[0]["sha256"]
            && rows[1]["path"] == terminal["output"]["path"]
            && rows[1]["identity"][1] == terminal["output"]["inode"]
            && first["archive"]["sha256"] == rows[3]["sha256"]
            && first["segment_manifest"]["sha256"] == rows[4]["sha256"]
            && contract["last_slot"] == 61_794_627,
        "wrong source custody, archive or interval"
    );
    for row in rows {
        ensure!(
            !pinned_path(row)?.starts_with(target),
            "retirement intersects retained evidence"
        );
    }
    for name in [
        "horizon-qualify-143-second-hourly-20261128-v2.service",
        "horizon-guard-143-second-hourly-20261128-v2.service",
        "horizon-guard-143-second-hourly-20261128-v2.timer",
    ] {
        drained(name)?;
    }
    let mut visited = std::collections::BTreeSet::new();
    for dir in [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/run/systemd/system",
        "/run/systemd/transient",
        "/run/systemd/generator",
        "/run/systemd/generator.early",
        "/run/systemd/generator.late",
        "/etc/cron.d",
    ] {
        if Path::new(dir).try_exists()? {
            staged_references(Path::new(dir), &[&parent, target], &[], &mut visited)?;
        }
    }
    Ok(
        json!({"terminal":p["terminal"],"plan":terminal["guard_plan"],"custody":p["source"],"predecessor":p["closure"],"retained":rows,"iid":IID,"restart_slot":custody["slot"]}),
    )
}

pub(super) fn check_inventory(
    p: &Value,
    _: &Value,
    entries: &stopped_tree::Ledger,
    bytes: u64,
) -> Result<()> {
    check_appendvecs(p, entries, bytes, 24_372_051_968)?;
    ensure!(
        p["expected_bytes"] == bytes && p["expected_entries"] == (entries.len() - 1) as u64,
        "stopped shard inventory changed"
    );
    let boot = &p["protected"][0];
    ensure!(
        digest(boot)? == string(boot, "sha256")? && path(boot)?.is_file(),
        "bootstrap changed before retirement"
    );
    Ok(())
}
