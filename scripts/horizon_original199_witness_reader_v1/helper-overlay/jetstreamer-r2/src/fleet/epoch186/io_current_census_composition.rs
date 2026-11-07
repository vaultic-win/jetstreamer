//! Compose disjoint current guard rollovers before historical completion checks.
//! These are comparison views only. Raw census and all promise rows stay intact.
use super::*;
use crate::fleet::ordinary199 as exact;

type Census = BTreeMap<String, Value>;

/// The existing exact enrollment validator also checks the declaration's image,
/// trip paths and namespace. Do not accept a caller-selected enrollment alias.
fn epoch199_view_legacy(
    declarations: &[GuardSpec],
    fleet: &Value,
    before: &Census,
    after: &Census,
) -> Result<(Census, Value)> {
    if [exact::GUARD, exact::TIMER]
        .iter()
        .all(|name| before.get(*name) == after.get(*name))
    {
        return Ok((after.clone(), Value::Null));
    }
    let selected = declarations
        .iter()
        .filter(|g| g.unit == exact::GUARD)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "current 199 rollover needs one exact guard declaration"
    );
    let g = selected[0];
    ensure!(
        matches!(g.kind, GuardKind::Epoch199Append),
        "current 199 rollover guard kind differs"
    );
    let proof = epoch199_append::enrollment_for_plan(g, fleet)?;
    ensure!(
        fleet[exact::FIELD] == serde_json::to_value(&proof.binding)?,
        "current 199 rollover enrollment differs from accepted fleet"
    );
    let old = Value::Object(before.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let raw = Value::Object(after.iter().map(|(k, v)| (k.clone(), v.clone())).collect());
    let normalized = proof.normalize_guard_for_plan(&old, &raw, fleet)?;
    let view = checked_view(before, after, &normalized)?;
    proof.revalidate_inputs()?;
    let evidence = json!({
        "schema":"jetstreamer-current199-enrolled-guard-comparison-v1",
        "enrollment":proof.binding,"guard_declaration":{
            "kind":"epoch199-append","unit":g.unit,"timer":g.timer,
            "binary":g.binary,"command_sha256":g.command_sha256,"plan":g.plan,
            "stop_intent":g.stop_intent,"stop_completion":g.stop_completion},
        "before_guard":before[exact::GUARD],"after_guard":after[exact::GUARD],
        "before_timer":before[exact::TIMER],"after_timer":after[exact::TIMER],
        "controller_and_producer_unchanged":true,"raw_observations_preserved":true,
        "current_append_guard_authentication_still_required":true,
        "new_resource_observations":0,"resource_credit_bytes":0,
        "replay_launch_authorized":false,"publication_authorized":false
    });
    Ok((view, evidence))
}

pub(super) fn epoch199_view(
    declarations: &[GuardSpec],
    fleet: &Value,
    before: &Census,
    after: &Census,
) -> Result<(Census, Value)> {
    let mut plan = json!({crate::fleet::recovery199_contract::FIELD:fleet[crate::fleet::recovery199_contract::FIELD]});
    if !fleet[crate::fleet::recovery199_contract::TERMINAL_FIELD].is_null() {
        plan[crate::fleet::recovery199_contract::TERMINAL_FIELD] =
            fleet[crate::fleet::recovery199_contract::TERMINAL_FIELD].clone();
    }
    let Some(p) = crate::fleet::recovery199_contract::load_plan(&plan)? else {
        return epoch199_view_legacy(declarations, fleet, before, after);
    };
    let raw = serde_json::to_value(after)?;
    let old = serde_json::to_value(before)?;
    let adjusted: Census = serde_json::from_value(p.normalize_guard(&old, &raw)?)?;
    let (view, evidence) = epoch199_view_legacy(declarations, fleet, before, &adjusted)?;
    Ok((
        view,
        json!({"schema":"recovery199-composed-native-census-comparison-v1","recovery199_enrollment":p.binding,"original199_comparison":evidence,"raw_observations_preserved":true,"new_resource_observations":0,"memory_or_DATA_credit_bytes":0}),
    ))
}

/// Strengthen the existing exact normalizer: never hide an additional field or
/// any field beyond completed invocation metadata and this timer's deadline.
fn checked_view(before: &Census, after: &Census, normalized: &Value) -> Result<Census> {
    ensure!(
        before.keys().eq(after.keys()),
        "current guard rollover census membership changed"
    );
    for name in exact::FAMILY {
        ensure!(
            before.contains_key(name) && after.contains_key(name),
            "current 199 family incomplete"
        );
    }
    for name in [exact::CONTROLLER, exact::PRODUCER] {
        ensure!(
            before[name] == after[name],
            "current 199 protected owner changed: {name}"
        );
    }
    let (a, b) = (&before[exact::GUARD], &after[exact::GUARD]);
    ensure!(
        crate::pipeline_status::same_exec_start(string(a, "/ExecStart")?, string(b, "/ExecStart")?),
        "current 199 guard command changed"
    );
    let mut stable = [
        a.as_object().context("current 199 old guard")?.clone(),
        b.as_object().context("current 199 new guard")?.clone(),
    ];
    for key in [
        "InvocationID",
        "ExecStart",
        "ExecMainPID",
        "ExecMainStartTimestamp",
        "ExecMainExitTimestamp",
    ] {
        ensure!(
            stable[0].get(key).is_some_and(Value::is_string)
                && stable[1].get(key).is_some_and(Value::is_string),
            "current 199 guard metadata absent: {key}"
        );
        stable[0].remove(key);
        stable[1].remove(key);
    }
    ensure!(
        stable[0] == stable[1],
        "current 199 guard changed another field"
    );
    if a["InvocationID"] == b["InvocationID"] {
        ensure!(
            a == b,
            "current 199 unchanged guard IID changed its native metadata"
        );
    }
    let mut timer = [
        before[exact::TIMER]
            .as_object()
            .context("current 199 old timer")?
            .clone(),
        after[exact::TIMER]
            .as_object()
            .context("current 199 new timer")?
            .clone(),
    ];
    for row in &mut timer {
        ensure!(
            row.remove("TimersMonotonic").is_some_and(|v| v.is_string()),
            "current 199 timer schedule missing"
        );
    }
    ensure!(
        timer[0] == timer[1],
        "current 199 timer changed another field"
    );
    let normalized = normalized
        .as_object()
        .context("current 199 comparison view")?;
    ensure!(
        normalized.keys().eq(after.keys()),
        "current 199 normalized membership changed"
    );
    for (name, raw) in after {
        let wanted = if [exact::GUARD, exact::TIMER].contains(&name.as_str()) {
            &before[name]
        } else {
            raw
        };
        ensure!(
            normalized.get(name) == Some(wanted),
            "current 199 projection changed another row: {name}"
        );
    }
    Ok(normalized
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect())
}

/// A successful projection is not a census acceptance. The remaining full map
/// must pass the existing cached guard validator or the unchanged legacy gate.
pub(super) fn finish(
    epoch199: Value,
    cached: impl FnOnce() -> Result<Value>,
    historical: impl FnOnce() -> Result<Value>,
) -> Result<Value> {
    let (cached145, coordinator) = match cached() {
        Ok(proof) => (proof, Value::Null),
        Err(cached_error) => (
            Value::Null,
            historical().with_context(|| {
                format!("current guard composition rejected cached route: {cached_error:#}")
            })?,
        ),
    };
    if epoch199.is_null() {
        return Ok(if cached145.is_null() {
            coordinator
        } else {
            cached145
        });
    }
    Ok(
        json!({"schema":"jetstreamer-current-guard-census-composition-v1",
        "epoch199_guard_comparison":epoch199,"cached145_guard_census_rollover":cached145,
        "completed_coordinator_transition":coordinator,"raw_observations_preserved":true,
        "new_resource_observations":0,"resource_credit_bytes":0,
        "replay_launch_authorized":false,"publication_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Census, Census, Value) {
        let command = "{ path=/sealed/guard ; argv[]=/sealed/guard plan ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        let guard = json!({"Id":exact::GUARD,"InvocationID":"a".repeat(32),
            "ExecStart":command,"ExecMainPID":"100","ExecMainStartTimestamp":"old-start",
            "ExecMainExitTimestamp":"old-stop","MemoryMax":"536870912","Result":"success",
            "ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0"});
        let before = Census::from([
            (exact::GUARD.into(), guard),
            (
                exact::TIMER.into(),
                json!({"Id":exact::TIMER,"Unit":exact::GUARD,"TimersMonotonic":"old"}),
            ),
            (
                exact::CONTROLLER.into(),
                json!({"Id":exact::CONTROLLER,"InvocationID":"c".repeat(32)}),
            ),
            (
                exact::PRODUCER.into(),
                json!({"Id":exact::PRODUCER,"InvocationID":"d".repeat(32)}),
            ),
            (
                "cached-guard".into(),
                json!({"InvocationID":"1".repeat(32)}),
            ),
            (
                "historical-coordinator".into(),
                json!({"ActiveState":"inactive","MainPID":"0"}),
            ),
        ]);
        let mut after = before.clone();
        after.get_mut(exact::GUARD).unwrap()["InvocationID"] = json!("b".repeat(32));
        after.get_mut(exact::GUARD).unwrap()["ExecMainPID"] = json!("101");
        after.get_mut(exact::TIMER).unwrap()["TimersMonotonic"] = json!("new");
        after.get_mut("cached-guard").unwrap()["InvocationID"] = json!("2".repeat(32));
        let mut view = after.clone();
        for name in [exact::GUARD, exact::TIMER] {
            view.insert(name.into(), before[name].clone());
        }
        let raw = Value::Object(view.into_iter().collect());
        (before, after, raw)
    }
    #[test]
    fn combined_disjoint_rollovers_preserve_raw_and_historical_rows() {
        let (before, after, view) = fixture();
        let original = after.clone();
        let projected = checked_view(&before, &after, &view).unwrap();
        assert_ne!(projected["cached-guard"], before["cached-guard"]);
        assert_eq!(
            projected["historical-coordinator"],
            before["historical-coordinator"]
        );
        assert_eq!(after, original);
        let proof = finish(
            json!({"route":"199"}),
            || {
                assert!(
                    projected
                        .iter()
                        .all(|(k, v)| k == "cached-guard" || before.get(k) == Some(v))
                );
                Ok(json!({"route":"cached145"}))
            },
            || anyhow::bail!("historical route must not run for accepted current guards"),
        )
        .unwrap();
        assert_eq!(
            proof["cached145_guard_census_rollover"]["route"],
            "cached145"
        );
        assert_eq!(proof["resource_credit_bytes"], 0);
        assert_eq!(proof["completed_coordinator_transition"], Value::Null);
    }
    #[test]
    fn each_single_route_requires_the_remaining_census_gate() {
        let proof = finish(
            json!({"route":"199"}),
            || anyhow::bail!("no cached change"),
            || Ok(Value::Null),
        )
        .unwrap();
        assert_eq!(proof["epoch199_guard_comparison"]["route"], "199");
        assert_eq!(
            finish(
                Value::Null,
                || Ok(json!({"route":"145"})),
                || anyhow::bail!("unused")
            )
            .unwrap()["route"],
            "145"
        );
        for route in [Value::Null, json!({"route":"199"})] {
            assert!(
                finish(
                    route,
                    || anyhow::bail!("unrelated change"),
                    || anyhow::bail!("historical pins differ")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn protected_owner_or_extra_owner_cannot_be_projected_away() {
        let (before, after, view) = fixture();
        for name in [exact::CONTROLLER, exact::PRODUCER] {
            let mut bad = after.clone();
            bad.get_mut(name).unwrap()["InvocationID"] = json!("f".repeat(32));
            assert!(checked_view(&before, &bad, &view).is_err());
        }
        let mut bad = after;
        bad.insert("unexpected.service".into(), json!({"MainPID":"123"}));
        assert!(checked_view(&before, &bad, &view).is_err());
    }
    #[test]
    fn changed_command_cap_sandbox_or_unknown_field_is_rejected() {
        let (before, after, view) = fixture();
        for (key, value) in [
            ("ExecStart", "foreign command"),
            ("MemoryMax", "infinity"),
            ("Result", "exit-code"),
            ("MainPID", "123"),
            ("ProtectSystem", "no"),
            ("unknown", "added"),
        ] {
            let mut bad = after.clone();
            bad.get_mut(exact::GUARD).unwrap()[key] = json!(value);
            assert!(checked_view(&before, &bad, &view).is_err(), "{key}");
        }
    }
    #[test]
    fn timer_identity_policy_and_foreign_projection_are_rejected() {
        let (before, after, view) = fixture();
        for key in ["Id", "Unit", "InvocationID", "CPUQuotaPerSecUSec"] {
            let mut bad = after.clone();
            bad.get_mut(exact::TIMER).unwrap()[key] = json!("foreign");
            assert!(checked_view(&before, &bad, &view).is_err(), "{key}");
        }
        let mut bad = view;
        bad["historical-coordinator"]["MainPID"] = json!("123");
        assert!(checked_view(&before, &after, &bad).is_err());
    }
    #[test]
    fn unrelated_change_or_historical_pin_failure_never_becomes_guard_success() {
        let (before, mut after, _) = fixture();
        after.get_mut("historical-coordinator").unwrap()["MainPID"] = json!("123");
        let mut candidate = after.clone();
        for name in [exact::GUARD, exact::TIMER] {
            candidate.insert(name.into(), before[name].clone());
        }
        let view = checked_view(
            &before,
            &after,
            &Value::Object(candidate.into_iter().collect()),
        )
        .unwrap();
        for reason in [
            "foreign completion",
            "changed self hash",
            "different observer",
            "historical fleet differs",
        ] {
            assert!(
                finish(
                    json!({"route":"199"}),
                    || {
                        ensure!(
                            view.iter()
                                .all(|(k, v)| k == "cached-guard" || before.get(k) == Some(v)),
                            "unrelated native change"
                        );
                        Ok(json!({"route":"145"}))
                    },
                    || anyhow::bail!("{reason}")
                )
                .is_err()
            );
        }
    }

    fn declaration(kind: &str) -> GuardSpec {
        serde_json::from_value(json!({"kind":kind,"unit":exact::GUARD,"timer":exact::TIMER,
            "binary":{"path":"/foreign/guard","sha256":"a".repeat(64)},
            "command_sha256":"b".repeat(64),
            "plan":{"path":"/foreign/enrollment.json","sha256":"c".repeat(64)},
            "sample":null,"stop_intent":"/foreign/stop-intent.json",
            "stop_completion":"/foreign/stop-completion.json"}))
        .unwrap()
    }
    #[test]
    fn missing_duplicate_wrong_kind_or_foreign_enrollment_rejects_before_io() {
        let (before, after, _) = fixture();
        assert!(epoch199_view(&[], &Value::Null, &before, &after).is_err());
        assert!(
            epoch199_view(
                &[
                    declaration("epoch199-append"),
                    declaration("epoch199-append")
                ],
                &Value::Null,
                &before,
                &after
            )
            .unwrap_err()
            .to_string()
            .contains("one exact guard")
        );
        assert!(
            epoch199_view(
                &[declaration("adaptive-controller")],
                &Value::Null,
                &before,
                &after
            )
            .unwrap_err()
            .to_string()
            .contains("kind differs")
        );
        assert!(
            epoch199_view(
                &[declaration("epoch199-append")],
                &Value::Null,
                &before,
                &after
            )
            .unwrap_err()
            .to_string()
            .contains("exact scope")
        );
    }
    #[test]
    fn same_guard_iid_cannot_claim_changed_completed_metadata() {
        let (before, mut after, view) = fixture();
        after.get_mut(exact::GUARD).unwrap()["InvocationID"] =
            before[exact::GUARD]["InvocationID"].clone();
        assert!(
            checked_view(&before, &after, &view)
                .unwrap_err()
                .to_string()
                .contains("unchanged guard IID")
        );
    }

    #[test]
    fn actual0958_static_four_row_projection_keeps_every_other_accepted_field() {
        let fixture: Value =
            serde_json::from_str(include_str!("current_census_composition0958.fixture.json"))
                .unwrap();
        assert_eq!(fixture["is_failed_live_reader_capture"], false);
        let before: Census = serde_json::from_value(fixture["before"].clone()).unwrap();
        let after: Census =
            serde_json::from_value(fixture["after_comparison_projection"].clone()).unwrap();
        assert_eq!(fixture["changed_rows"].as_array().unwrap().len(), 4);
        let mut candidate = after.clone();
        for name in [exact::GUARD, exact::TIMER] {
            candidate.insert(name.into(), before[name].clone());
        }
        let projected = checked_view(
            &before,
            &after,
            &Value::Object(candidate.into_iter().collect()),
        )
        .unwrap();
        let cached_guard = "horizon-qualify-145-cached-b2a09f57de39c384-guard.service";
        let cached_timer = "horizon-qualify-145-cached-b2a09f57de39c384-guard.timer";
        crate::fleet::cached145_census_rollover::shape(
            &before[cached_guard],
            &projected[cached_guard],
        )
        .unwrap();
        crate::fleet::cached145_timer::pair(
            cached_timer,
            &before[cached_timer],
            &projected[cached_timer],
        )
        .unwrap();
        let mut remaining = projected;
        for name in [cached_guard, cached_timer] {
            remaining.insert(name.into(), before[name].clone());
        }
        assert_eq!(remaining, before);
        for timer in [cached_timer, exact::TIMER] {
            assert!(remaining[timer].get("Type").is_none());
            assert!(remaining[timer].get("MainPID").is_none());
        }
    }
}
