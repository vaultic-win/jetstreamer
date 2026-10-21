//! A completed metadata oneshot may leave its own recorded live census row.
//! No replay/controller/verification ownership transition is normalized here.
use super::*;
fn same_census(
    recorded: &Value,
    current: &BTreeMap<String, Value>,
    name: &str,
    completion: &Value,
) -> Result<()> {
    ensure!(
        name.starts_with("horizon-routine-cycle-101-200-")
            && (name.ends_with("-v2.service")
                || name == "horizon-routine-cycle-101-200-20261021T173800Z-prefix157-v1.service"),
        "foreign metadata cycle namespace"
    );
    let before = &recorded[name];
    let after = current.get(name).context("metadata unit omitted")?;
    let same_command = before["ExecStart"]
        .as_str()
        .zip(after["ExecStart"].as_str())
        .is_some_and(|(a, b)| {
            a.split_once(" ; ignore_errors=")
                .zip(b.split_once(" ; ignore_errors="))
                .is_some_and(|(a, b)| a.0 == b.0)
        });
    ensure!(
        before["Id"] == name
            && after["Id"] == name
            && before["InvocationID"] == completion["invocation_id"]
            && after["InvocationID"] == before["InvocationID"]
            && before["NRestarts"] == "0"
            && after["NRestarts"] == "0"
            && before["Type"] == "oneshot"
            && after["Type"] == "oneshot"
            && before["ActiveState"] == "activating"
            && before["SubState"] == "start"
            && before["MainPID"]
                .as_str()
                .is_some_and(|s| s.parse::<u32>().is_ok_and(|n| n > 0))
            && after["ActiveState"] == "active"
            && after["SubState"] == "exited"
            && after["MainPID"] == "0"
            && after["Result"] == "success"
            && after["ExecMainStatus"] == "0"
            && same_command,
        "metadata oneshot did not complete under the exact same identity and command"
    );
    let mut comparison = serde_json::to_value(current)?;
    comparison[name] = before.clone();
    ensure!(
        comparison == *recorded,
        "fleet changed outside authenticated metadata completion"
    );
    Ok(())
}
pub(super) fn validate(
    plan: &Plan,
    fleet: &Value,
    current: &BTreeMap<String, Value>,
) -> Result<()> {
    if serde_json::to_value(current)? == fleet["unit_census"] {
        return Ok(());
    }
    let b = plan
        .metadata_completion
        .as_ref()
        .context("fleet changed; reconcile before cleanup")?;
    let c = bound_json(b)?;
    let pinned157 = plan.epoch == 157
        && plan.fleet.path
            == Path::new(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261021T163800Z.json",
            )
        && b.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T163800Z-v2/completion.json",
            )
        && b.sha256 == "b1f3f3fc8b6e4e84ae5804d0c09110d78bf5e0a7c9693b7d6cdf249cfd146d86";
    let pinned144 = plan.epoch == 144
        && plan.fleet.path
            == Path::new(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261021T173800Z.json",
            )
        && b.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T173800Z-prefix157-v1/completion.json",
            )
        && b.sha256 == "e5e208fc27ed7207fefe1300eaff8adeca7a5ee36187b9a236c42e58a2f5d8fb";
    ensure!(
        (pinned157 || pinned144)
            && c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && c["fleet"]["path"].as_str() == plan.fleet.path.to_str()
            && c["fleet"]["sha256"] == plan.fleet.sha256
            && c["fleet_plan"]["path"] == fleet["plan"]
            && c["fleet_plan"]["sha256"] == fleet["plan_sha256"]
            && c["observer"]["sha256"] == fleet["observer_sha256"]
            && c["sampled_at_utc"] == fleet["sampled_at_utc"]
            && c["inventory"]["anomalies"] == 0
            && c["new_resource_samples"] == 0,
        "foreign metadata completion binding"
    );
    for flag in [
        "archive_mutations",
        "sidecar_mutations",
        "replay_launch_authorized",
        "deletions",
    ] {
        ensure!(
            c[flag] == false,
            "metadata completion grants unrelated authority"
        );
    }
    let cycle: Bound = serde_json::from_value(c["plan"].clone())?;
    let p = bound_json(&cycle)?;
    ensure!(
        p["sample_target_utc"] == c["sampled_at_utc"]
            && p["fleet_output"].as_str() == plan.fleet.path.to_str(),
        "metadata plan scope differs"
    );
    let name = p["cycle_unit"].as_str().context("metadata unit absent")?;
    same_census(&fleet["unit_census"], current, name, &c)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root-only exact16:38 completed metadata cycle; read-only full claim census, no R2 access"]
    fn exact_metadata_completion_is_the_only_changed_census_row() {
        let b=Bound {path:"/usr/local/lib/jetstreamer/horizon-epoch157-status-cleanup-plan-20261021-v1/plan.json".into(),sha256:"e66010c184f37c6d6805137bdd6f100e15a9343da611c66043c7fd391eb4cd15".into()};
        let mut p: Plan = serde_json::from_value(bound_json(&b).unwrap()).unwrap();
        p.metadata_completion=Some(Bound {path:"/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T163800Z-v2/completion.json".into(),sha256:"b1f3f3fc8b6e4e84ae5804d0c09110d78bf5e0a7c9693b7d6cdf249cfd146d86".into()});
        let fleet = bound_json(&p.fleet).unwrap();
        let names = fleet["unit_census"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        let current = fleet::census(&names, 101, 200).unwrap();
        validate(&p, &fleet, &current).unwrap();
        p.metadata_completion = None;
        assert!(validate(&p, &fleet, &current).is_err());
    }
    #[test]
    fn only_successful_same_invocation_metadata_terminal_is_allowed() {
        let name = "horizon-routine-cycle-101-200-20261021T163800Z-v2.service";
        let before = json!({"Id":name,"InvocationID":"a".repeat(32),"Type":"oneshot","NRestarts":"0","ActiveState":"activating","SubState":"start","MainPID":"123","ExecStart":"sealed metadata command ; ignore_errors=no ; stop_time=[n/a]"});
        let mut after = before.clone();
        after["ActiveState"] = json!("active");
        after["SubState"] = json!("exited");
        after["MainPID"] = json!("0");
        after["Result"] = json!("success");
        after["ExecMainStatus"] = json!("0");
        let recorded = json!({name:before,"producer.service":{"InvocationID":"b".repeat(32)}});
        let current: BTreeMap<String, Value> = serde_json::from_value(
            json!({name:after,"producer.service":{"InvocationID":"b".repeat(32)}}),
        )
        .unwrap();
        let completion = json!({"invocation_id":"a".repeat(32)});
        same_census(&recorded, &current, name, &completion).unwrap();
        for (key, value) in [
            ("InvocationID", json!("f".repeat(32))),
            ("Result", json!("exit-code")),
            ("MainPID", json!("456")),
            ("Type", json!("exec")),
            ("ExecStart", json!("different ; ignore_errors=no")),
        ] {
            let mut bad = current.clone();
            bad.get_mut(name).unwrap()[key] = value;
            assert!(
                same_census(&recorded, &bad, name, &completion).is_err(),
                "accepted{key}"
            );
        }
        let mut bad = current;
        bad.get_mut("producer.service").unwrap()["InvocationID"] = json!("f".repeat(32));
        assert!(same_census(&recorded, &bad, name, &completion).is_err());
    }
    #[test]
    fn exact_prefix157_cycle_may_normalize_only_its_own_terminal_row() {
        let name = "horizon-routine-cycle-101-200-20261021T173800Z-prefix157-v1.service";
        let before = json!({"Id":name,"InvocationID":"a".repeat(32),"Type":"oneshot","NRestarts":"0","ActiveState":"activating","SubState":"start","MainPID":"123","ExecStart":"sealed metadata command ; ignore_errors=no ; stop_time=[n/a]"});
        let mut after = before.clone();
        for (key, value) in [
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("MainPID", "0"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
        ] {
            after[key] = json!(value);
        }
        let recorded = json!({name:before,"producer.service":{"InvocationID":"b".repeat(32)}});
        let current: BTreeMap<String, Value> = serde_json::from_value(
            json!({name:after,"producer.service":{"InvocationID":"b".repeat(32)}}),
        )
        .unwrap();
        let completion = json!({"invocation_id":"a".repeat(32)});
        same_census(&recorded, &current, name, &completion).unwrap();
        let mut bad = current;
        bad.get_mut("producer.service").unwrap()["InvocationID"] = json!("f".repeat(32));
        assert!(same_census(&recorded, &bad, name, &completion).is_err());
    }
}
