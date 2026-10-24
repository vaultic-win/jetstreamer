//! Current already-running protective fires for one typed admitted continuation.
//! Reads existing immutable guard receipts and PID1 history; never fires a guard,
//! creates an observation, changes the accepted fleet or grants another claim.
use super::*;
fn selector(name: &str) -> Result<&'static str> {
    Ok(match name {
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service" => {
            "horizon-ownroot225-protective-v1.service"
        }
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service" => {
            "horizon-prefix205-protective-v1.service"
        }
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service" => {
            "horizon-prefix204-protective-v1.service"
        }
        "horizon-singleton-209-capped-4aeca563-v1.service" => {
            "horizon-singleton209-protective-v1.service"
        }
        prefix223_native20::UNIT => prefix223_native20::PROTECTIVE,
        _ => anyhow::bail!("unmodeled Foundation continuation protective owner:{name}"),
    })
}
fn roster(f: &Value) -> Result<BTreeMap<String, &'static str>> {
    let mut services = BTreeMap::new();
    for row in f["active"]
        .as_array()
        .context("continuation guard owner census")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("continuation guard producer")?;
        ensure!(
            services.insert(name.into(), selector(name)?).is_none(),
            "duplicate continuation guard owner"
        );
    }
    ensure!(
        services.len() == 5,
        "continuation requires the exact five protected owners"
    );
    Ok(services)
}
pub(super) fn same_guard(old: &Value, current: &Value, plan: &Value, owner: &Value) -> Result<()> {
    for key in [
        "plan",
        "plan_sha256",
        "guard_sha256",
        "producer_invocation_id",
        "minimum_free_bytes",
        "maximum_worker_vmas",
        "maximum_root_physical_bytes",
        "native_main",
        "producer_stop_enabled",
    ] {
        ensure!(
            old.get(key) == current.get(key),
            "continuation guard changed admitted scope:{key}"
        );
    }
    // Stop semantics remain the existing per-owner contract enforced by
    // prefix223_live_peer::disk on every refreshed set. In particular the exact
    // legacy 225 guard/plan has implicit stops and no producer_stop_enabled key.
    // Presence and value above cannot change from the admitted receipt.
    ensure!(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == owner["Id"]
            && plan["invocation_id"] == owner["InvocationID"]
            && current["producer"]["invocation_id"] == owner["InvocationID"]
            && current["producer"]["pid"]
                .as_u64()
                .map(|p| p.to_string())
                .as_deref()
                == owner["MainPID"].as_str()
            && current["producer"]["cgroup"] == owner["ControlGroup"],
        "continuation guard is not the same protected producer and sealed plan"
    );
    Ok(())
}
pub(super) fn refresh(
    f: &Value,
    original: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(BTreeMap<String, BoundFile>, Value)> {
    let services = roster(f)?;
    refresh_selected(f, original, sample, now, services)
}
/// The caller has separately proved the closed two-terminal transition. Keep
/// the original five-owner wrapper and every live guard predicate unchanged.
pub(super) fn refresh_terminal_pair(
    f: &Value,
    original: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
) -> Result<(BTreeMap<String, BoundFile>, Value)> {
    super::terminal_pair::live_roster(f)?;
    let services = original
        .keys()
        .map(|name| Ok((name.clone(), selector(name)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    ensure!(
        services.len() == 3,
        "terminal-pair continuation needs its three exact live guards"
    );
    refresh_selected(f, original, sample, now, services)
}
fn refresh_selected(
    f: &Value,
    original: &BTreeMap<String, BoundFile>,
    sample: u64,
    now: u64,
    services: BTreeMap<String, &'static str>,
) -> Result<(BTreeMap<String, BoundFile>, Value)> {
    ensure!(
        services.keys().eq(original.keys()),
        "continuation changed the original protective owner roster"
    );
    let mut selected = BTreeMap::new();
    let mut histories = serde_json::Map::new();
    for row in f["active"]
        .as_array()
        .context("continuation guard owner census")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = owner["Id"]
            .as_str()
            .context("continuation guard producer")?;
        let service = *services
            .get(name)
            .context("continuation owner guard missing")?;
        ensure!(
            !selected.contains_key(name),
            "duplicate continuation guard owner"
        );
        let old = bound_json(
            original
                .get(name)
                .context("admitted continuation guard omitted")?,
        )?;
        let plan_binding: BoundFile =
            serde_json::from_value(json!({"path":old["plan"],"sha256":old["plan_sha256"]}))?;
        let plan = bound_json(&plan_binding)?;
        let directory = Path::new(
            plan["receipt_directory"]
                .as_str()
                .context("sealed guard receipt directory")?,
        );
        ensure!(
            directory.starts_with("/var/lib/jetstreamer"),
            "continuation guard receipt scope is not root evidence"
        );
        let proof = warmup223::completed_guard_binding(service, directory, sample, now)?;
        let binding: BoundFile = serde_json::from_value(proof["binding"].clone())?;
        let current = bound_json(&binding)?;
        same_guard(&old, &current, &plan, owner)?;
        let timer = singleton227_capture::properties(
            &service.replace(".service", ".timer"),
            "Unit,ActiveState,SubState",
        )?;
        ensure!(
            timer.get("Unit").is_some_and(|s| s == service)
                && timer.get("ActiveState").is_some_and(|s| s == "active")
                && timer
                    .get("SubState")
                    .is_some_and(|s| matches!(s.as_str(), "waiting" | "running")),
            "continuation protective timer stopped or retargeted:{name}"
        );
        histories.insert(name.into(),json!({"original":private157::binding(original.get(name).unwrap()),"current":proof,"timer":timer}));
        selected.insert(name.into(), binding);
    }
    ensure!(
        selected.keys().eq(services.keys()) && selected.keys().eq(original.keys()),
        "continuation must preserve its complete validated protective guard roster"
    );
    Ok((selected, Value::Object(histories)))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_five_guard_shapes_keep_legacy225_and_modern_stop_contracts() {
        let fixtures: Vec<Value> = serde_json::from_str(include_str!(
            "fixtures/foundation213-current-five-guards.json"
        ))
        .unwrap();
        assert_eq!(fixtures.len(), 5);
        for fixture in fixtures {
            let old = &fixture["receipt"];
            let owner = &fixture["owner"];
            let plan = &fixture["plan"];
            let mut current = old.clone();
            current["guard_invocation_id"] = json!("f".repeat(32));
            current["recorded_unix_seconds"] =
                json!(old["recorded_unix_seconds"].as_u64().unwrap() + 900);
            selector(owner["Id"].as_str().unwrap()).unwrap();
            same_guard(old, &current, plan, owner).unwrap();
            let legacy = owner["Id"].as_str().unwrap().contains("225-natural-root");
            if legacy {
                assert_eq!(
                    old["guard_sha256"],
                    "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560"
                );
                assert_eq!(
                    old["plan_sha256"],
                    "831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22"
                );
                for key in [
                    "producer_stop_enabled",
                    "maximum_root_physical_bytes",
                    "native_main",
                ] {
                    assert!(old.get(key).is_none());
                    let mut changed = current.clone();
                    changed[key] = Value::Null;
                    assert!(same_guard(old, &changed, plan, owner).is_err());
                }
            } else {
                assert_eq!(old["producer_stop_enabled"], true);
                let mut missing = current.clone();
                missing
                    .as_object_mut()
                    .unwrap()
                    .remove("producer_stop_enabled");
                assert!(same_guard(old, &missing, plan, owner).is_err());
                current["producer_stop_enabled"] = json!(false);
                assert!(same_guard(old, &current, plan, owner).is_err());
            }
        }
    }
    #[test]
    fn exact_current_five_owner_roster_selects_each_guard_and_rejects_legacy207() {
        let expected = [
            (
                "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
                "horizon-ownroot225-protective-v1.service",
                225,
            ),
            (
                "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
                "horizon-prefix205-protective-v1.service",
                205,
            ),
            (
                "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
                "horizon-prefix204-protective-v1.service",
                204,
            ),
            (
                "horizon-singleton-209-capped-4aeca563-v1.service",
                "horizon-singleton209-protective-v1.service",
                209,
            ),
            (
                prefix223_native20::UNIT,
                prefix223_native20::PROTECTIVE,
                223,
            ),
        ];
        let rows = expected.iter().map(|(unit, _, epoch)| {
            let owner = json!({"Id":unit,"InvocationID":"a".repeat(32),"MainPID":"42","ControlGroup":format!("/system.slice/{unit}")});
            if *epoch == 223 { json!({"epoch":epoch,"unit":owner}) } else { json!({"epoch":epoch,"producer":owner}) }
        }).collect::<Vec<_>>();
        let fleet = json!({"active":rows});
        let selected = roster(&fleet).unwrap();
        for (unit, guard, _) in expected {
            assert_eq!(selected.get(unit), Some(&guard));
        }
        let mut legacy = fleet.clone();
        legacy["active"][3]["producer"]["Id"] = json!(native207::UNIT);
        assert!(roster(&legacy).is_err());
        let mut unknown = fleet.clone();
        unknown["active"][3]["producer"]["Id"] = json!("unknown.service");
        assert!(roster(&unknown).is_err());
        let mut missing = fleet.clone();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(roster(&missing).is_err());
        let mut duplicate = fleet.clone();
        duplicate["active"][3] = duplicate["active"][0].clone();
        assert!(roster(&duplicate).is_err());
    }
    #[test]
    fn continuation_guard_cannot_change_plan_owner_cap_or_producer_invocation() {
        let owner = json!({"Id":"horizon-singleton-209-capped-4aeca563-v1.service","InvocationID":"a".repeat(32),"MainPID":"42","ControlGroup":format!("/system.slice/{}","horizon-singleton-209-capped-4aeca563-v1.service")});
        let plan = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-singleton-209-capped-4aeca563-v1.service","invocation_id":"a".repeat(32)});
        let old = json!({"plan":"/sealed/guard.json","plan_sha256":"b".repeat(64),"guard_sha256":"c".repeat(64),"producer_invocation_id":"a".repeat(32),"minimum_free_bytes":100,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":300000000000u64,"native_main":null,"producer":{"invocation_id":"a".repeat(32),"pid":42,"cgroup":owner["ControlGroup"]},"producer_stop_enabled":true});
        same_guard(&old, &old, &plan, &owner).unwrap();
        for pointer in [
            "/plan_sha256",
            "/guard_sha256",
            "/producer_invocation_id",
            "/minimum_free_bytes",
            "/maximum_root_physical_bytes",
            "/producer/pid",
            "/producer/cgroup",
            "/producer_stop_enabled",
        ] {
            let mut changed = old.clone();
            *changed.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                same_guard(&old, &changed, &plan, &owner).is_err(),
                "{pointer}"
            );
        }
        assert!(selector("horizon-unmodeled-maintenance.service").is_err());
    }
}
