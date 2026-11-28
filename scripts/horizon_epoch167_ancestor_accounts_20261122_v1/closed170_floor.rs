//! Reclaim the four closed AppendVec shards from the disk-backed interval after the RAM segment.
use super::retirement_evidence::{digest, drained, open_input, path, staged_references};
pub(super) use super::retirement_evidence::{leases, verify_campaign_lock, verify_image};
use super::*;
use std::collections::BTreeSet;

pub(super) const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch170-after-ram-floor-accounts-20261128-v1";
pub(super) const PROFILE: &[u8] = include_bytes!("profiles170_floor.json");
pub(super) const CHECK_SCHEMA: &str = "horizon-170-after-ram-accounts-check-v1";
pub(super) const COMPLETE_SCHEMA: &str = "horizon-170-after-ram-accounts-complete-v1";
const IID: &str = "e589078414194de38fe902a9df0f5b0c";
const UNIT: &str = "horizon-qualify-170-from-73766969-20261127-v1.service";
const BYTES: u64 = 21_702_422_528;
const SLOT: u64 = 73_766_969;

fn names(dir: &Path) -> Result<BTreeSet<String>> {
    fs::read_dir(dir)?
        .map(|item| {
            item?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("non-UTF8 entry in {}", dir.display()))
        })
        .collect()
}

fn matches_names(dir: &Path, expected: &[&str]) -> Result<()> {
    ensure!(
        names(dir)? == expected.iter().map(|s| s.to_string()).collect(),
        "unexpected preserved state in {}",
        dir.display()
    );
    Ok(())
}

fn validate_stop(p: &Value, terminal: &Value, scope: &Value) -> Result<()> {
    let actor = bound(&terminal["actor"])?;
    let grant = bound(&terminal["release"])?;
    let plan = bound(&terminal["guard_plan"])?;
    let intent = bound(&terminal["guard_stop"]["stop_intent"])?;
    let completion = bound(&terminal["guard_stop"]["stop_completion"])?;
    let drain = bound(&p["drain"])?;
    let native = &terminal["pid1_terminal"];
    ensure!(
        terminal["schema"] == "horizon-170-after-ram-private-floor-stop-v1"
            && terminal["producer_invocation_id"] == IID
            && actor["producer_invocation_id"] == IID
            && native["INVOCATION_ID"] == IID
            && native["_PID"] == "1"
            && native["UNIT"] == UNIT
            && native["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && grant["actor"] == terminal["actor"]
            && grant["interface"] == p["contract"]
            && grant["guard_plan"] == terminal["guard_plan"]
            && plan["unit"] == UNIT
            && plan["invocation_id"] == IID
            && intent["reason"] == "filesystem-floor"
            && intent["sample"]["trip_reason"] == intent["reason"]
            && intent["sample"]["available_bytes"]
                .as_u64()
                .context("missing observed free space")?
                < plan["minimum_free_bytes"]
                    .as_u64()
                    .context("missing guard floor")?
            && intent["sample"]["minimum_free_bytes"] == plan["minimum_free_bytes"]
            && intent["plan_sha256"] == terminal["guard_plan"]["sha256"]
            && completion["producer_invocation_id"] == intent["producer_invocation_id"]
            && completion["producer_invocation_id"] == IID
            && completion["plan_sha256"] == intent["plan_sha256"]
            && completion["intent"] == terminal["guard_stop"]["stop_intent"]["path"]
            && completion["terminal"]["pid"] == 0
            && completion["terminal"]["active"] == "inactive"
            && completion["scratch_deleted"] == false
            && terminal["verified_complete_segment"] == false
            && terminal["terminal_checkpoint_accepted"] == false
            && terminal["archive_publication_authorized"] == false
            && terminal["matched_bootstrap"]["slot"] == SLOT
            && terminal["final_progress"]["slot"] == 73_767_819u64
            && drain["guard_drained"] == true
            && drain["producer_inactive"] == true
            && drain["custody"] == p["terminal"]
            && drain["release"] == terminal["release"]
            && drain["timer_invocation"] == grant["guard_timer_invocation_id"]
            && p["iid"] == IID
            && p["unit"] == UNIT
            && scope["expected_producer_unit"] == UNIT,
        "different historical 170 floor stop or unconfirmed guard drain"
    );
    Ok(())
}

pub(super) fn gates(p: &Value, _: &Value) -> Result<Value> {
    let terminal = bound(&p["terminal"])?;
    let scope = bound(&p["contract"])?;
    validate_stop(p, &terminal, &scope)?;
    let custody = bound(&p["source"])?;
    let previous = bound(&p["closure"])?;
    let review = &p["restore"];
    let build = bound(&review["node_build"])?;
    let keep = &p["protected"];
    let run = Path::new(string(&scope, "run")?);
    let parent = run.join("scratch/.historical-runtime/jetstreamer-historical-parent-Ai9ZGd");
    let runtime = parent.join("jetstreamer-historical-v1.5.6-ycPc6p");
    let target = Path::new(string(p, "target")?);
    ensure!(
        target == runtime.join("accounts-state")
            && target.canonicalize()? == target
            && target.symlink_metadata()?.ino() == 119603206
            && p["inode"] == 119603206
            && scope["following_input"] == p["source"]
            && scope["bootstrap"] == SLOT
            && scope["first_new_slot"] == SLOT + 1
            && scope["last"] == 73_787_145u64
            && previous["actual_terminal"] == terminal["matched_bootstrap"]
            && previous["archive"]["path"] == keep["predecessor_archive"]["path"]
            && previous["archive"]["sha256"] == keep["predecessor_archive"]["sha256"]
            && previous["archive"]["manifest"]["sha256"] == keep["predecessor_manifest"]["sha256"]
            && keep["partial"]["path"] == terminal["partial"]["path"]
            && keep["partial"]["sha256"] == terminal["partial"]["sha256"]
            && path(&keep["partial"])? == run.join("ledger/epoch-170.diagnostic.jet")
            && keep["log"]["sha256"] == terminal["log"]["sha256"]
            && path(&keep["log"])? == run.join("producer.log")
            && path(&keep["bank"])? == runtime.join("unpacked/snapshots/73766969/73766969")
            && custody["destination"] == keep["bootstrap"]["path"]
            && custody["archive_sha256"] == keep["bootstrap"]["sha256"]
            && keep["node"]["sha256"] == scope["profile"]["node"]["sha256"]
            && keep["node"]["path"] == scope["profile"]["node"]["path"]
            && keep["bound_worker"]["sha256"] == scope["profile"]["worker"]
            && build["source_commit"] == "5b8cdc8c0b1e95cd7900f7b154e1729426010d39"
            && build["node"]["sha256"] == keep["node"]["sha256"]
            && review["node_source_commit"] == build["source_commit"]
            && review["in_place_native_bank_resume"] == false
            && review["archive_and_bank_preserved"] == true
            && !Path::new(string(&terminal, "manifest_absent")?).try_exists()?,
        "changed source, cold restart, partial archive or retirement root"
    );
    matches_names(
        &parent,
        &["bound-worker", "jetstreamer-historical-v1.5.6-ycPc6p"],
    )?;
    matches_names(
        &runtime,
        &["accounts-state", "genesis-unpacked", "unpacked"],
    )?;
    matches_names(
        &runtime.join("unpacked/snapshots"),
        &["73766969", "status_cache"],
    )?;
    matches_names(&runtime.join("unpacked/snapshots/73766969"), &["73766969"])?;
    for row in keep
        .as_object()
        .context("missing protected material")?
        .values()
    {
        ensure!(
            !path(row)?.starts_with(target),
            "retirement intersects protected file"
        );
        open_input(row)?;
    }
    for unit in [
        UNIT,
        string(&scope, "expected_guard_unit")?,
        string(&scope, "expected_guard_timer")?,
    ] {
        drained(unit)?;
    }
    let mut visited = BTreeSet::new();
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
        json!({"terminal":p["terminal"],"drain":p["drain"],"contract":p["contract"],
              "source":p["source"],"predecessor":p["closure"],"cold_restart":review,"retained":keep,"iid":IID}),
    )
}

pub(super) fn check_inventory(
    p: &Value,
    _: &Value,
    entries: &stopped_tree::Ledger,
    bytes: u64,
) -> Result<()> {
    check_appendvecs(p, entries, bytes, BYTES)?;
    ensure!(
        p["expected_bytes"] == bytes && p["expected_entries"] == (entries.len() - 1) as u64,
        "retirement inventory differs from the stopped generation"
    );
    for name in ["bootstrap", "partial", "node", "bound_worker"] {
        let row = &p["protected"][name];
        ensure!(
            digest(row)? == string(row, "sha256")?,
            "changed retained {name}"
        );
    }
    Ok(())
}
