//! Separate no-clobber ending writer. Check receipts alone cannot end a promise.
use super::checker::{self as c, AncestryVerifier, R};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub const END_ROOT: &str = "/var/lib/jetstreamer/horizon-original154-unused-future-DATA-20261110-v1/edc1d1915dcb4c2785d2cf24cdaa10c2";
fn private_parent(path: &Path) -> R<()> {
    c::need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical ending parent required",
    )?;
    let m = fs::symlink_metadata(path)?;
    c::need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root ending directory required",
    )
}
fn durable(path: &Path, v: &Value) -> R<()> {
    let parent = path.parent().ok_or("ending parent")?;
    private_parent(parent)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, v)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
/// Caller driver must prove exact sealed image, native finite helper identity/cap/guard and
/// current Root ownership before entering. This function creates intent BEFORE fresh check.
/// A failed check leaves intent permanently retained and grants zero selected resource credit.
/// Root may select only the actual ending after this actor drains; consumers and guard handoff
/// remain separate. No in-place change to HEAD, original receipts, files or systemd is performed.
pub fn end(plan: &Value, verify_ancestry: AncestryVerifier) -> R<Value> {
    c::need(
        plan["schema"] == "horizon-original154-future-DATA-ending-plan-v1"
            && plan["owner"] == "/root",
        "exact ending plan required",
    )?;
    let prior = c::bound(&plan["qualified_check"])?;
    c::need(
        prior["schema"] == "horizon-original154-future-DATA-check-v1"
            && prior["original_invocation_id"] == c::IID
            && prior["current_authority"] == plan["check_plan"]["current_authority"]
            && prior["proposed_unused_future_DATA_bytes"] == c::ENDED_DATA
            && prior["scope_accounted_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 16 << 30)
            && prior["DATA_ending_selected"] == false,
        "genuine successful exact check required",
    )?;
    let now = c::clock()?;
    let at = c::number(&prior, "recorded_unix_seconds")?;
    c::need(now >= at && now - at <= 300, "qualified check expired")?;
    let root = Path::new(END_ROOT);
    private_parent(root)?;
    // Shared no-clobber intent prevents parallel checks from selecting this owner twice.
    c::need(
        !root.join("ended.json").try_exists()?,
        "original154 ending already exists",
    )?;
    durable(
        &root.join("intent.json"),
        &json!({"schema":"horizon-original154-future-DATA-ending-intent-v1","original_invocation_id":c::IID,"qualified_check":plan["qualified_check"],"recorded_unix_seconds":now,"memory_credit_bytes":0,"ending_selected":false}),
    )?;
    let actual = c::check(&plan["check_plan"], verify_ancestry)?;
    c::need(
        actual["current_authority"] == prior["current_authority"]
            && actual["scope_facts_sha256"] == prior["scope_facts_sha256"]
            && actual["protected_peers_after"] == prior["protected_peers_after"]
            && actual["family_after"] == prior["family_after"],
        "fresh ending check changed scope/owner/authority",
    )?;
    let ended = json!({"schema":"horizon-original154-future-DATA-ended-v1","owner":"/root","original_invocation_id":c::IID,
        "previous_complete_DATA_authority":actual["current_authority"],"previous_complete_DATA_bytes":c::BASE_DATA,"complete_DATA_bytes":c::BASE_DATA-c::ENDED_DATA,
        "complete_projected_memory_bytes":c::BASE_MEMORY,"original_DATA_reservation_bytes":c::OLD_DATA,"retained_DATA_bytes":c::RETAINED_DATA,
        "unused_future_DATA_ended_bytes":c::ENDED_DATA,"new_memory_credit_bytes":0,"physical_bytes_removed":0,
        "qualified_check":plan["qualified_check"],"genuine_fresh_check":actual,"recorded_unix_seconds":c::clock()?,
        "all_original_files_and_receipts_retained":true,"Root_selection_pending_actor_drain":true,"effective_consumers_and_continuous_guard_handoff_pending":true,
        "replay_admission_authorized":false,"guard_mutations":false,"remote_mutations":false});
    durable(&root.join("ended.json"), &ended)?;
    Ok(ended)
}
