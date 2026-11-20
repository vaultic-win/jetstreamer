//! Exact live delivery owner, measured inside the coordinated observer cadence.
//! Reuses native process-image checks and ordinary unit/cgroup/RSS sampling.
use super::*;
use serde_json::json;
const UNIT: &str = "horizon-upload-247-singleton-20261119-v1.service";
const IID: &str = "69218e2e0924497ea595a1227a6c31db";
const PID: u32 = 1439838;
const IMAGE: &str =
    "/var/lib/jetstreamer/horizon-full265-fast-consumers-20261119-v1/jetstreamer-r2";
const IMAGE_SHA: &str = "4f70b21bd930a6e2890088eb236858ca1952a2dfa4c6404bfb9d9e68d07ba0ba";
pub(super) fn validate(c: &Config) -> Result<()> {
    if !c.delivery247_resource_only {
        return Ok(());
    }
    for r in c.replays.iter().chain(&c.diagnostic_replays) {
        ensure!(
            r.producer_unit != UNIT
                && r.controller_unit != UNIT
                && r.expected_producer_invocation_id != IID
                && r.expected_controller_invocation_id != IID,
            "delivery247 cannot alias replay telemetry"
        );
    }
    ensure!(
        c.epoch203_ram_auxiliary.is_none(),
        "delivery247 is not an auxiliary replay"
    );
    Ok(())
}
fn main_ticks(rss: &Value) -> Result<u64> {
    ensure!(
        rss["census_stable"] == true && rss["error"].is_null(),
        "delivery247 RSS unavailable"
    );
    let rows: Vec<_> = rss["processes"]
        .as_array()
        .context("delivery247 RSS processes")?
        .iter()
        .filter(|p| p["pid"] == PID)
        .collect();
    ensure!(
        rows.len() == 1,
        "delivery247 main missing/duplicated in RSS census"
    );
    rows[0]["start_ticks"]
        .as_u64()
        .context("delivery247 main start ticks")
}
fn process_starts(u: &UnitObservation) -> Result<BTreeMap<u64, u64>> {
    let rss = serde_json::to_value(&u.rss)?;
    let mut found = BTreeMap::new();
    for p in rss["processes"]
        .as_array()
        .context("delivery247 complete cgroup RSS census")?
    {
        let pid = p["pid"].as_u64().context("delivery child PID")?;
        let start = p["start_ticks"].as_u64().context("delivery child start")?;
        ensure!(
            found.insert(pid, start).is_none(),
            "duplicate delivery process"
        );
    }
    Ok(found)
}
fn endpoint(u: &UnitObservation) -> Result<u64> {
    ensure!(
        u.unit == UNIT
            && u.invocation_id == IID
            && u.main_pid == u64::from(PID)
            && u.load_state == "loaded"
            && u.active_state == "active"
            && u.sub_state == "running"
            && u.restarts == 0
            && u.control_group == Path::new(&format!("/system.slice/{UNIT}")),
        "delivery247 resource owner changed"
    );
    let raw = serde_json::to_value(u)?;
    // Kernel hard cap is page-aligned; retain actual measured gauges and full RSS.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    ensure!(page > 0, "delivery247 page size");
    let cap = 7_000_000_000u64 / (page as u64) * (page as u64);
    ensure!(
        raw["cgroup"]["gauges"]["memory.max"] == cap
            && raw["cgroup"]["gauges"]["memory.swap.max"] == 0,
        "delivery247 original kernel cap changed"
    );
    main_ticks(&raw["rss"])
}
fn observe(clock: u64) -> Result<Value> {
    let before = observe_unit(UNIT, IID)?;
    let first_ticks = endpoint(&before)?;
    let image_before = native_input_diagnostic::mapped_image_at(
        Path::new(IMAGE),
        IMAGE_SHA,
        PID,
        Path::new("/proc"),
        0,
    )?;
    let after = observe_unit(UNIT, IID)?;
    let last_ticks = endpoint(&after)?;
    let image_after = native_input_diagnostic::mapped_image_at(
        Path::new(IMAGE),
        IMAGE_SHA,
        PID,
        Path::new("/proc"),
        0,
    )?;
    ensure!(
        stable_unit(&before, &after)
            && first_ticks == last_ticks
            && process_starts(&before)? == process_starts(&after)?
            && image_before["mapped_inode"] == image_after["mapped_inode"]
            && image_before["mapped_device"] == image_after["mapped_device"],
        "delivery247 identity changed during same-cadence sample"
    );
    Ok(
        json!({"range":"247-247","sampled_unix_seconds":clock,"resource_only":true,
        "delivery_resource_only":true,"phase":"upload-readback",
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "mapped_image_before":image_before,"mapped_image_after":image_after,
        "invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
fn row(result: Result<Value>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    json!({"range":"247-247","producer_unit":UNIT,"expected_producer_invocation_id":IID,
        "delivery_resource_only":true,"status":status,"observation":observation,"error":error,
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,
        "resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(enabled: bool, clock: u64) -> Vec<Value> {
    if enabled {
        vec![row(observe(clock))]
    } else {
        Vec::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_delivery_is_unavailable_not_zero_rss_or_replay() {
        let v = row(Err(anyhow!("original uploader finished")));
        assert_eq!(v["status"], "unavailable");
        assert!(v["observation"].is_null());
        for k in [
            "entry_replay",
            "ordinary_replay_claim",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
            "r2_mutations",
        ] {
            assert_eq!(v[k], false);
        }
    }
    #[test]
    fn actual_pid_required_once_in_stable_rss_census() {
        let good =
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123}]});
        assert_eq!(main_ticks(&good).unwrap(), 123);
        for value in [
            json!({"census_stable":false,"error":null,"processes":[{"pid":PID,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":42,"start_ticks":123}]}),
            json!({"census_stable":true,"error":null,"processes":[{"pid":PID,"start_ticks":123},{"pid":PID,"start_ticks":123}]}),
        ] {
            assert!(main_ticks(&value).is_err());
        }
    }
}
