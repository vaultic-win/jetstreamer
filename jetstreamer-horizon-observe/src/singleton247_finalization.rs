//! Same-cadence resident/cgroup telemetry after epoch247's firehose has ended.
use super::*;
use serde_json::json;

fn properties() -> Result<Value> {
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", singleton247_phase::UNIT, "--property", "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,ExecStart,ControlGroup"])
        .output()?;
    ensure!(out.status.success(), "epoch247 phase manager read failed");
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

pub(super) fn validate(config: &Config) -> Result<()> {
    if !config.singleton247_finalization {
        return Ok(());
    }
    ensure!(
        config.epoch203_ram_auxiliary.is_none(),
        "finalization owner not part of auxiliary replay envelope"
    );
    for r in config.replays.iter().chain(&config.diagnostic_replays) {
        let (first, last) = r.range.split_once('-').unwrap_or((&r.range, &r.range));
        let (first, last) = (first.parse::<u64>()?, last.parse::<u64>()?);
        ensure!(
            !(first..=last).contains(&247)
                && r.producer_unit != singleton247_phase::UNIT
                && r.controller_unit != singleton247_phase::UNIT
                && r.expected_producer_invocation_id != singleton247_phase::IID
                && r.expected_controller_invocation_id != singleton247_phase::IID,
            "finalization owner overlaps replay census"
        );
    }
    Ok(())
}
fn identity(u: &UnitObservation) -> Result<()> {
    ensure!(
        u.unit == singleton247_phase::UNIT
            && u.invocation_id == singleton247_phase::IID
            && u.main_pid == singleton247_phase::PID
            && u.control_group == Path::new(&format!("/system.slice/{}", singleton247_phase::UNIT)),
        "epoch247 resource owner differs"
    );
    let r = serde_json::to_value(&u.rss)?;
    ensure!(
        r["census_stable"] == true
            && r["error"].is_null()
            && r["processes"]
                .as_array()
                .is_some_and(|p| p.iter().any(|p| p["pid"] == singleton247_phase::PID)),
        "epoch247 RSS census unavailable"
    );
    Ok(())
}
fn observe(sample: u64) -> Result<Value> {
    let manager_before = properties()?;
    let phase = singleton247_phase::capture(&manager_before, sample)?
        .context("epoch247 firehose completion absent at sample clock")?;
    let before = observe_unit(singleton247_phase::UNIT, singleton247_phase::IID)?;
    identity(&before)?;
    let after = observe_unit(singleton247_phase::UNIT, singleton247_phase::IID)?;
    identity(&after)?;
    let manager_after = properties()?;
    singleton247_phase::validate_owner(&manager_after)?;
    ensure!(
        manager_before == manager_after && stable_unit(&before, &after),
        "epoch247 finalization owner changed during telemetry"
    );
    let before_rss = serde_json::to_value(&before.rss)?;
    let after_rss = serde_json::to_value(&after.rss)?;
    let main_ticks = |r: &Value| {
        r["processes"]
            .as_array()
            .and_then(|p| p.iter().find(|p| p["pid"] == singleton247_phase::PID))
            .and_then(|p| p["start_ticks"].as_u64())
    };
    ensure!(
        main_ticks(&before_rss).is_some() && main_ticks(&before_rss) == main_ticks(&after_rss),
        "epoch247 PID reused"
    );
    Ok(
        json!({"range":"247-247","resource_only":true,"post_replay_finalization":true,
        "controller_before":before,"producer_before":before,"controller_after":after,"producer_after":after,
        "phase_evidence":phase,"invocation_binding_stable":true,"useful_work":{"sufficient_for_rates":false,"entry_progress_observed":false},
        "entry_replay":false,"ordinary_replay_claim":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}
fn row(result: Result<Value>) -> Value {
    let (status, observation, error) = match result {
        Ok(v) => ("observed", Some(v), None),
        Err(e) => ("unavailable", None, Some(format!("{e:#}"))),
    };
    json!({"range":"247-247","producer_unit":singleton247_phase::UNIT,"expected_producer_invocation_id":singleton247_phase::IID,
        "post_replay_resource_only":true,"status":status,"observation":observation,"error":error,
        "ordinary_replay_claim":false,"entry_replay":false,"terminal_completion_proven":false,"resource_release_authorized":false,"publication_authorized":false,"r2_mutations":false})
}
pub(super) fn sample(sample: u64) -> Value {
    row(observe(sample))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finalization_failure_is_explicit_and_keeps_reservations() {
        let r = row(Err(anyhow!("original owner terminated")));
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
        c.replays[0].producer_unit = singleton247_phase::UNIT.into();
        assert!(validate(&c).is_err());
    }
    fn tests_config() -> Config {
        serde_json::from_value(json!({"schema":CONFIG_SCHEMA,"previous_sample":"/x","minimum_interval_seconds":1800,"not_before_utc":"2026-11-19T15:33:00Z","filesystem_path":"/","output":"/out","replays":[]})).unwrap()
    }
}
