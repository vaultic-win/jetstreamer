//! Same-cadence resident/cgroup telemetry after a closed singleton firehose ends.
use super::*;
use serde_json::json;

fn properties(p: singleton247_phase::Profile) -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", p.unit, "--property", "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ExecStart,ControlGroup"])
        .output()?;
    ensure!(out.status.success(), "singleton phase manager read failed");
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("invalid manager property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate manager property"
        );
    }
    Ok(Value::Object(map))
}

pub(super) fn epochs(config: &Config) -> Result<Vec<u64>> {
    let mut epochs = config.singleton_finalization_epochs.clone();
    if config.singleton247_finalization {
        epochs.push(247);
    }
    let mut seen = std::collections::BTreeSet::new();
    for &epoch in &epochs {
        if epoch != 265 {
            singleton247_phase::profile(epoch)?;
        }
        ensure!(seen.insert(epoch), "duplicate singleton finalization owner");
    }
    Ok(epochs)
}
pub(super) fn validate(config: &Config) -> Result<()> {
    for epoch in epochs(config)? {
        if epoch == 265 {
            ensure!(
                config.epoch203_ram_auxiliary.is_none(),
                "265 finalization auxiliary overlap"
            );
            for r in config.replays.iter().chain(&config.diagnostic_replays) {
                let (first, last) = r.range.split_once('-').unwrap_or((&r.range, &r.range));
                ensure!(
                    !(first.parse::<u64>()?..=last.parse::<u64>()?).contains(&265)
                        && r.producer_unit != jetstreamer_horizon_observe::full265::UNIT
                        && r.controller_unit != jetstreamer_horizon_observe::full265::UNIT,
                    "265 finalization replay overlap"
                );
            }
            continue;
        }
        let p = singleton247_phase::profile(epoch)?;
        ensure!(
            config.epoch203_ram_auxiliary.is_none(),
            "finalization owner not part of auxiliary replay envelope"
        );
        for r in config.replays.iter().chain(&config.diagnostic_replays) {
            let (first, last) = r.range.split_once('-').unwrap_or((&r.range, &r.range));
            let (first, last) = (first.parse::<u64>()?, last.parse::<u64>()?);
            ensure!(
                !(first..=last).contains(&epoch)
                    && r.producer_unit != p.unit
                    && r.controller_unit != p.unit
                    && r.expected_producer_invocation_id != p.iid
                    && r.expected_controller_invocation_id != p.iid,
                "finalization owner overlaps replay census"
            );
        }
    }
    Ok(())
}
fn identity(p: singleton247_phase::Profile, u: &UnitObservation) -> Result<()> {
    ensure!(
        u.unit == p.unit
            && u.invocation_id == p.iid
            && u.main_pid == p.pid
            && u.control_group == Path::new(&format!("/system.slice/{}", p.unit)),
        "singleton resource owner differs"
    );
    let r = serde_json::to_value(&u.rss)?;
    ensure!(
        r["census_stable"] == true
            && r["error"].is_null()
            && r["processes"]
                .as_array()
                .is_some_and(|processes| processes.iter().any(|process| process["pid"] == p.pid)),
        "singleton RSS census unavailable"
    );
    Ok(())
}
fn observe(p: singleton247_phase::Profile, sample: u64) -> Result<Value> {
    let manager_before = properties(p)?;
    let phase = singleton247_phase::capture(p, &manager_before, sample)?
        .context("singleton firehose completion absent at sample clock")?;
    let before = observe_unit(p.unit, p.iid)?;
    identity(p, &before)?;
    let after = observe_unit(p.unit, p.iid)?;
    identity(p, &after)?;
    let manager_after = properties(p)?;
    singleton247_phase::validate_owner(p, &manager_after)?;
    ensure!(
        manager_before == manager_after && stable_unit(&before, &after),
        "singleton finalization owner changed during telemetry"
    );
    let before_rss = serde_json::to_value(&before.rss)?;
    let after_rss = serde_json::to_value(&after.rss)?;
    let main_ticks = |r: &Value| {
        r["processes"]
            .as_array()
            .and_then(|processes| processes.iter().find(|process| process["pid"] == p.pid))
            .and_then(|p| p["start_ticks"].as_u64())
    };
    ensure!(
        main_ticks(&before_rss).is_some() && main_ticks(&before_rss) == main_ticks(&after_rss),
        "singleton PID reused"
    );
    Ok(
        json!({"range":format!("{0}-{0}",p.epoch),"resource_only":true,"post_replay_finalization":true,
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "phase_evidence":phase,"invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
fn row(p: singleton247_phase::Profile, result: Result<Value>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    json!({"range":format!("{0}-{0}",p.epoch),"producer_unit":p.unit,"expected_producer_invocation_id":p.iid,
        "post_replay_resource_only":true,"status":status,"observation":observation,"error":error,
        "ordinary_replay_claim":false,"entry_replay":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(epoch: u64, sample: u64) -> Result<Value> {
    if epoch == 265 {
        return full265_telemetry::sample(sample);
    }
    let p = singleton247_phase::profile(epoch)?;
    Ok(row(p, observe(p, sample)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finalization_failure_is_explicit_and_keeps_reservations() {
        let r = row(
            singleton247_phase::profile(247).unwrap(),
            Err(anyhow!("original owner terminated")),
        );
        assert_eq!(r["status"], "unavailable");
        assert!(r["observation"].is_null());
        for k in [
            "ordinary_replay_claim",
            "entry_replay",
            "terminal_completion_proven",
            "resource_release_authorized",
            "publication_authorized",
        ] {
            assert_eq!(r[k], false);
        }
    }
    #[test]
    fn finalization_cannot_alias_a_replay_owner() {
        let mut c = tests_config();
        c.singleton247_finalization = true;
        validate(&c).unwrap();
        c.replays.push(serde_json::from_value(json!({"range":"247-247","controller_unit":"other.service","producer_unit":"other.service","expected_controller_invocation_id":"a".repeat(32),"expected_producer_invocation_id":"a".repeat(32),"scratch_path":"/scratch","worker_executable_basename":"worker"})).unwrap());
        assert!(validate(&c).is_err());
        c.replays[0].range = "248-248".into();
        c.replays[0].producer_unit = singleton247_phase::profile(247).unwrap().unit.into();
        assert!(validate(&c).is_err());
    }
    #[test]
    fn plural_profiles_reject_duplicates_unknown_and_overlap() {
        let mut c = tests_config();
        c.singleton_finalization_epochs = vec![247, 248, 249, 250, 251];
        validate(&c).unwrap();
        c.singleton247_finalization = true;
        assert!(validate(&c).is_err());
        c.singleton247_finalization = false;
        c.singleton_finalization_epochs.push(252);
        assert!(validate(&c).is_err());
        for epoch in [248, 249, 250, 251] {
            let mut c = tests_config();
            c.singleton_finalization_epochs = vec![epoch];
            c.replays.push(serde_json::from_value(json!({"range":format!("{epoch}-{epoch}"),"controller_unit":"other.service","producer_unit":"other.service","expected_controller_invocation_id":"a".repeat(32),"expected_producer_invocation_id":"a".repeat(32),"scratch_path":"/scratch","worker_executable_basename":"worker"})).unwrap());
            assert!(validate(&c).is_err());
            let p = singleton247_phase::profile(epoch).unwrap();
            let r = row(p, Err(anyhow!("absent")));
            assert_eq!(r["range"], format!("{epoch}-{epoch}"));
            assert_eq!(r["producer_unit"], p.unit);
            assert_eq!(r["resource_release_authorized"], false);
        }
    }
    fn tests_config() -> Config {
        serde_json::from_value(json!({"schema":CONFIG_SCHEMA,"previous_sample":"/x","minimum_interval_seconds":1800,"not_before_utc":"2026-11-19T15:33:00Z","filesystem_path":"/","output":"/out","replays":[]})).unwrap()
    }
}
