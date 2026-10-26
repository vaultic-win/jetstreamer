//! Fresh observation bootstrap for the single sealed Full209 capture recovery.
//! The old accepted fleet remains historical; no intermediate fleet is invented.
use super::*;
fn predecessor(o: &Value, at: u64) -> Result<BoundFile> {
    let c = &o["cadence"];
    let b = BoundFile {
        path: string(c, "previous_sample")?.into(),
        sha256: string(c, "previous_sample_sha256")?.into(),
    };
    let previous = utc_seconds(string(c, "previous_sample_recorded_at_utc")?)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous < at
            && c["observed_interval_seconds"] == at - previous
            && c["minimum_interval_seconds"] == 1800
            && ((c["observation_reason"] == "routine"
                && c["routine_minimum_interval_enforced"] == true
                && at - previous >= 1800)
                || (c["observation_reason"] == "user-requested-status"
                    && c["routine_minimum_interval_enforced"] == false))
            && o["mutation"]["producer_or_controller_signals_sent"] == false
            && o["mutation"]["service_state_changed"] == false
            && o["mutation"]["remote_mutations"] == false
            && o["mutation"]["r2_mutations"] == false,
        "completed209 late event observer cadence/mutation chain differs"
    );
    Ok(b)
}
pub(in crate::fleet::completed_archive_phase) fn chain(
    observer: &BoundFile,
    o: &Value,
    original: &BoundFile,
    historical: &Value,
) -> Result<()> {
    let original_at = utc_seconds(string(historical, "recorded_at_utc")?)?;
    let mut binding = observer.clone();
    let mut current = o.clone();
    // Bounded metadata reads only, never another live observation.
    for _ in 0..64 {
        if binding == *original {
            ensure!(
                current == *historical,
                "completed209 historical observer changed"
            );
            return Ok(());
        }
        let at = utc_seconds(string(&current, "recorded_at_utc")?)?;
        ensure!(
            at > original_at,
            "completed209 observer chain bypassed admitted sample"
        );
        let next = predecessor(&current, at)?;
        let next_value = read(&next)?;
        ensure!(
            next_value["recorded_at_utc"] == current["cadence"]["previous_sample_recorded_at_utc"],
            "completed209 observer predecessor timestamp differs"
        );
        binding = next;
        current = next_value;
    }
    bail!("completed209 observer chain exceeds recovery bound")
}
pub(super) fn context(
    previous: &Value,
    observer: &BoundFile,
    o: &Value,
    l: &Value,
    a: &Value,
    c: &PipelineClaim,
) -> Result<bool> {
    if l.get("capture_recovery").is_none() {
        accepted_child(previous, observer, o, l)?;
        return Ok(false);
    }
    // checked_launch has authenticated the exact v12 recovery pins, distinct
    // capturer seal, unchanged release, original admission and current protection.
    let original: BoundFile =
        serde_json::from_value(a["capacity"]["resource_basis"]["observer"].clone())?;
    let historical = read(&original)?;
    accepted(previous, &original, &historical)?;
    ensure!(
        observer != &original,
        "completed209 recovery requires a fresh successor observer"
    );
    chain(observer, o, &original, &historical)?;
    let proof = peer::capture_observer(c, o)?;
    ensure!(
        proof["post_sample_initial_event"] == false
            && proof["included_in_whole_host_resident_memory"] == true
            && proof["host_processes"]
                .as_array()
                .is_some_and(|v| v.len() == 2),
        "completed209 late recovery requires both real child host RSS brackets"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed209_late_observer_requires_forward_hash_bound_cadence_and_no_mutations() {
        let good = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2",
            "cadence":{"previous_sample":"/sealed/previous.json","previous_sample_sha256":"a".repeat(64),
                "previous_sample_recorded_at_utc":"1970-01-01T00:15:00Z","observed_interval_seconds":1800,
                "minimum_interval_seconds":1800,"observation_reason":"routine","routine_minimum_interval_enforced":true},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false}});
        predecessor(&good, 2700).unwrap();
        for (pointer, value) in [
            ("/cadence/observed_interval_seconds", json!(1799)),
            ("/cadence/minimum_interval_seconds", json!(30)),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
            (
                "/cadence/previous_sample_recorded_at_utc",
                json!("1970-01-01T00:45:00Z"),
            ),
            ("/mutation/service_state_changed", json!(true)),
            ("/mutation/r2_mutations", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(predecessor(&bad, 2700).is_err(), "{pointer}");
        }
    }
}
