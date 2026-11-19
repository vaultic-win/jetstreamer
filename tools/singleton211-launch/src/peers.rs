//! Retained native211 terminal and separately admitted native265. No resource-release credit.
use super::*;
const UNIT211: &str = "archive-211-v1616-native-input-actual-v1.service";
const UNIT265: &str = "horizon-265-native-input-20261119-v1.service";
const TEST265: &str =
    "/var/lib/jetstreamer/horizon265-native-input-daa786c0-20261119-v1/horizon265-native-input";
const TEST265_SHA: &str = "0dbcd28e231f7158b88701666bff89cbdf36cc2033c0e5e826e54a8c87db76e9";
pub(super) fn native(e: &Value) -> bool {
    e["phase"] == "private-cold-snapshot-verification"
        && ((e["epoch"] == 211 && e["unit"]["Id"] == UNIT211)
            || (e["epoch"] == 265 && e["unit"]["Id"] == UNIT265))
}
pub(super) fn validate(e: &Value, fleet: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    ensure!(native(e), "unsupported native peer");
    let unit = text(&e["unit"], "Id")?;
    let iid = text(e, "expected_invocation_id")?;
    ensure!(
        hex(iid, 32)
            && e["unit"] == fleet["unit_census"][unit]
            && e["sampled_at_utc"] == fleet["sampled_at_utc"]
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false,
        "native peer census changed"
    );
    let r = rows
        .iter()
        .find(|r| r.unit == unit && r.invocation_id == iid)
        .context("native peer unbooked")?;
    // Keep all original caps and disk obligations, even after terminal211.
    ensure!(
        r.release.is_none(),
        "native peer memory credit needs separate qualified drain integration"
    );
    if unit == UNIT211 {
        peer211::validate(fleet, rows)?;
    } else {
        ensure!(
            e["live"] == true
                && r.maximum_memory_bytes == 128_000_000_000
                && r.remaining_disk_growth_bytes >= 506_191_984_640,
            "native265 retained hard envelope differs"
        );
        let evidence = e["evidence"].as_array().context("native265 origin")?;
        ensure!(evidence.len() == 1, "native265 origin coverage");
        let origin = binding(&evidence[0])?.sealed()?;
        ensure!(
            origin["schema"] == "jetstreamer-private-epoch265-native-input-running-v1"
                && origin["epoch"] == 265
                && origin["unit"] == UNIT265
                && origin["invocation_id"] == iid
                && origin["test_sha256"] == TEST265_SHA
                && origin["maximum_memory_bytes"] == r.maximum_memory_bytes
                && origin["maximum_scratch_bytes"] == r.remaining_disk_growth_bytes
                && origin["native_input_qualified"] == false
                && origin["replay_entries"] == 0,
            "native265 registered origin differs"
        );
        no_authority(&origin)?;
    }
    Ok(())
}
pub(super) fn mapped(e: &Value) -> Result<()> {
    if e["unit"]["Id"] == UNIT265 {
        Bound::new(TEST265, TEST265_SHA).artifact()?;
        let pid = text(&e["unit"], "MainPID")?.parse::<u64>()?;
        ensure!(pid > 1, "native265 PID missing");
        let p = PathBuf::from(format!("/proc/{pid}/exe"));
        ensure!(
            fs::read_link(&p)? == Path::new(TEST265)
                && metadata_identity(&fs::metadata(&p)?) == identity(Path::new(TEST265))?,
            "native265 mapped image changed"
        );
    }
    Ok(())
}
