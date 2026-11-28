//! One observational suffix owner addition. No launch or resource authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const SCHEMA: &str = "jetstreamer-epoch154-suffix-owner-transition-v1";
pub const UNIT: &str = "horizon-qualify-154-checkpoint-continuation-20261029-v1.service";
pub const PHASE: &str = "private-checkpoint-suffix154";
pub const NEXT_ACTION: &str = "Private checkpoint suffix is executing under its exact producer and guard; preserve every reservation and await terminal qualification. No publication is authorized.";
pub const TERMINAL_NEXT_ACTION: &str = "Private checkpoint suffix exited during assembly; retain the exact drained producer, all DATA and the open repair backlog while assembly recovery continues. No completion or publication is authorized.";
pub fn retained_terminal_binding() -> Value {
    json!({"path":"/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1/terminal.json",
    "sha256":"ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b"})
}
const RESTORE: &str = "horizon-qualify-154-native-restore-20261028-v1.service";
const UNITS: [&str; 6] = [
    UNIT,
    "horizon-epoch154-suffix-admission-20261029-v1.service",
    "horizon-native154-suffix-control-20261029-v1.service",
    "horizon-guard-154-checkpoint-continuation-20261029-v1.service",
    "horizon-guard-154-checkpoint-continuation-20261029-v1.timer",
    "horizon-stop-154-checkpoint-continuation-20261029-v1.service",
];

/// Interpret only already authenticated canonical allocation/terminal evidence.
/// Terminal adoption is observational: the original event still binds 64 GiB
/// launch history and zero resource credit; all 360 GiB DATA remains retained.
pub fn allocation(
    actual: &Value,
    owner_binding: &crate::Bound,
    owner: &Value,
    release: &Value,
    terminal: Option<(&crate::Bound, &Value)>,
) -> Result<()> {
    ensure!(
        actual["unit"] == UNIT
            && actual["invocation_id"] == owner["producer_invocation_id"]
            && actual["data_reservation_bytes"] == 360u64 << 30
            && actual["physical_retirement_credit_bytes"] == 0
            && actual["remaining_growth_released"] == false
            && actual["publication_authorized"] == false,
        "154 allocation lost exact owner or full retained DATA"
    );
    if actual["memory_max_bytes"] == 64u64 << 30 {
        let native = &actual["native"];
        ensure!(
            terminal.is_none()
                && native["Id"] == UNIT
                && native["InvocationID"] == owner["producer_invocation_id"]
                && native["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|p| p > 1)
                && matches!(
                    native["ActiveState"].as_str(),
                    Some("active" | "activating" | "deactivating")
                ),
            "154 live allocation cannot borrow terminal proof or fake its live producer"
        );
        return Ok(());
    }
    ensure!(
        actual["memory_max_bytes"] == 0,
        "154 allocation has an unknown memory promise"
    );
    let (binding, t) =
        terminal.context("154 zero memory requires canonical bound terminal proof")?;
    ensure!(
        binding.path.as_os_str()
            == std::path::Path::new(
                "/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1/terminal.json"
            )
            .as_os_str()
            && binding.sha256 == "ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b",
        "154 terminal source is not canonical hash-bound evidence"
    );
    let iid = "edc1d1915dcb4c2785d2cf24cdaa10c2";
    let n = &t["terminal_native"];
    let current = &actual["native"];
    ensure!(
        owner["producer_invocation_id"] == iid
            && release["producer_invocation_id"] == iid
            && t["schema"] == "jetstreamer-epoch154-suffix-terminal-v1"
            && t["owner"] == json!(owner_binding)
            && t["producer_invocation_id"] == iid
            && t["control_group_drained"] == true
            && t["data_reservation_bytes"] == 360u64 << 30
            && t["memory_released_bytes"] == 64u64 << 30
            && t["remaining_growth_released"] == false
            && t["archive_completion_claimed"] == false
            && t["publication_authorized"] == false
            && t["r2_mutations"] == false
            && t["repair_backlog_open"] == true
            && n["Id"] == UNIT
            && n["InvocationID"] == iid
            && n["MainPID"] == "0"
            && n["ControlGroup"] == ""
            && n["ActiveState"] == "failed"
            && n["SubState"] == "failed"
            && n["Result"] == "exit-code"
            && n["ExecMainCode"] == "1"
            && n["ExecMainStatus"] == "1"
            && n["NRestarts"] == "0"
            && n["MemoryMax"] == "68719476736"
            && n["MemorySwapMax"] == "0"
            && current["Id"] == UNIT
            && current["MainPID"] == "0"
            && current["ControlGroup"] == ""
            && ((current["InvocationID"] == iid
                && current["ActiveState"] == "failed"
                && current["SubState"] == "failed"
                && current["ExecMainCode"] == "1"
                && current["ExecMainStatus"] == "1"
                && current["Result"] == "exit-code")
                || (current["InvocationID"] == ""
                    && current["ActiveState"] == "inactive"
                    && current["SubState"] == "dead"))
            && t["recorded_unix_seconds"]
                .as_u64()
                .zip(release["recorded_unix_seconds"].as_u64())
                .is_some_and(|(a, b)| a >= b),
        "154 terminal adoption changed original failed owner, drained state, DATA or authority"
    );
    // The same authenticated retained branch is valid at first entry and later
    // revalidation; neither grants a live producer or any retirement credit.
    Ok(())
}

pub fn claim(event: &Value, owner: &Value) -> Value {
    json!({"epoch":154,"phase":PHASE,"unit":UNIT,
        "invocation_id":owner["producer_invocation_id"],
        "expected_exec_start":owner["native"]["ExecStart"],
        "evidence":[event["owner"],event["release"]]})
}

pub fn event_clock(
    event: &Value,
    owner: &Value,
    release: &Value,
    now: u64,
    new: bool,
) -> Result<u64> {
    let at = release["recorded_unix_seconds"]
        .as_u64()
        .context("154 release clock")?;
    let iid = owner["producer_invocation_id"]
        .as_str()
        .context("154 owner IID")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "154 malformed owner IID"
    );
    ensure!(
        event["schema"] == SCHEMA
            && event["epoch"] == 154
            && event["unit"] == UNIT
            && owner["schema"] == "jetstreamer-epoch154-suffix-owner-v1"
            && owner["native"]["Id"] == UNIT
            && owner["native"]["InvocationID"] == iid
            && release["schema"] == "jetstreamer-epoch154-suffix-exec-release-v1"
            && release["producer_invocation_id"] == iid
            && release["owner"] == event["owner"]
            && release["entry_replay_authorized"] == true
            && release["ordinary_replay_authorized"] == false
            && release["publication_authorized"] == false
            && release["r2_mutations"] == false
            && event["recorded_unix_seconds"] == at
            && at <= now
            && (!new || now - at <= 1800)
            && event["data_reservation_bytes"] == (360u64 << 30)
            && event["memory_max_bytes"] == (64u64 << 30)
            && event["resource_credit_bytes"] == 0
            && event["new_resource_samples"] == 0,
        "154 event changed actual owner, release clock, caps or resource credit"
    );
    for key in [
        "remaining_growth_released",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(event[key] == false, "154 event grants authority: {key}");
    }
    Ok(at)
}

pub struct Delta<'a> {
    pub previous_plan: &'a Value,
    pub next_plan: &'a Value,
    pub previous_fleet: &'a Value,
    pub event: &'a Value,
    pub owner: &'a Value,
    pub release: &'a Value,
    pub now: u64,
    pub resource_refresh: Option<(&'a Value, &'a [Value], &'a Value)>,
}

fn observer_clock(v: &Value) -> Result<u64> {
    crate::utc_seconds(v["recorded_at_utc"].as_str().context("154 observer UTC")?)
}

pub fn validate_resource_refresh(
    event: &Value,
    old: &Value,
    next: &Value,
    before: &Value,
    intermediate: &[Value],
    after: &Value,
    now: u64,
) -> Result<()> {
    let refresh = &event["resource_refresh"];
    let middle = refresh["intermediate_observers"].as_array();
    ensure!(
        refresh["schema"] == "jetstreamer-suffix154-genuine-observer-refresh-v1"
            && refresh
                .as_object()
                .is_some_and(|v| v.len() == if middle.is_some() { 4 } else { 3 })
            && (middle.is_some() || refresh["intermediate_observers"].is_null())
            && intermediate.len() <= crate::MAXIMUM_OBSERVATION_BRIDGE_INTERMEDIATES
            && middle.map_or(0, Vec::len) == intermediate.len()
            && refresh["previous_observer"] == old["observer"]
            && refresh["observer"] == next["observer"]
            && event["resource_observer"] == old["observer"]
            && before["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "154 refresh lost actual observer bindings or source census"
    );
    let first = observer_clock(before)?;
    let mut clock = first;
    let mut head = &refresh["previous_observer"];
    for (bound, observation) in middle
        .into_iter()
        .flatten()
        .zip(intermediate)
        .chain(std::iter::once((&refresh["observer"], after)))
    {
        let at = observer_clock(observation)?;
        ensure!(
            observation["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && observation["cadence"]["previous_sample"] == head["path"]
                && observation["cadence"]["previous_sample_sha256"] == head["sha256"]
                && observation["cadence"]["routine_minimum_interval_enforced"] == true
                && observation["cadence"]["minimum_interval_seconds"] == 1800
                && at
                    >= clock
                        .checked_add(1800)
                        .context("154 observer clock overflow")?
                && observation["cadence"]["observed_interval_seconds"] == at - clock,
            "154 refresh lost a genuine scheduled observer link"
        );
        head = bound;
        clock = at;
    }
    ensure!(
        clock <= now
            && now - clock <= 1800
            && event["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|at| first < at && at <= clock),
        "154 refresh is stale, backdated or skips its real release"
    );
    Ok(())
}

pub fn validate_delta(d: &Delta<'_>) -> Result<()> {
    let observer = if d.event["resource_refresh"].is_null() {
        ensure!(
            d.resource_refresh.is_none(),
            "154 undeclared observer refresh"
        );
        &d.previous_plan["observer"]
    } else {
        let (before, intermediate, after) = d
            .resource_refresh
            .context("154 actual observer refresh sources")?;
        validate_resource_refresh(
            d.event,
            d.previous_plan,
            d.next_plan,
            before,
            intermediate,
            after,
            d.now,
        )?;
        &d.next_plan["observer"]
    };
    event_clock(
        d.event,
        d.owner,
        d.release,
        d.now,
        d.event["resource_refresh"].is_null(),
    )?;
    ensure!(
        d.event["previous_fleet"] == d.next_plan["previous_fleet"]
            && d.event["previous_plan"]
                == json!({"path":d.previous_fleet["plan"],"sha256":d.previous_fleet["plan_sha256"]})
            && d.event["previous_metadata_event"] == d.previous_plan["metadata_event"]
            && d.event["resource_observer"] == d.previous_plan["observer"]
            && d.next_plan["observer"] == *observer,
        "154 event changed predecessor or genuine resource clock"
    );
    let old = d.previous_plan["pipeline_claims"]
        .as_array()
        .context("154 previous claims")?;
    ensure!(
        old.iter()
            .filter(|c| c["epoch"] == 154
                && c["unit"] == RESTORE
                && c["phase"] == "private-cold-snapshot-verification")
            .count()
            == 1
            && !old.iter().any(|c| c["unit"] == UNIT),
        "154 event lacks exact retained restore or duplicates its suffix"
    );
    let tracked = d.previous_plan["tracked_units"]
        .as_array()
        .context("154 previous tracked units")?;
    let next = d.next_plan["tracked_units"]
        .as_array()
        .context("154 next tracked units")?;
    ensure!(
        next.starts_with(tracked),
        "154 event dropped or reordered tracked history"
    );
    let mut expected_units = tracked
        .iter()
        .map(|v| v.as_str().map(str::to_owned).context("154 tracked name"))
        .collect::<Result<BTreeSet<_>>>()?;
    expected_units.extend(
        d.previous_fleet["unit_census"]
            .as_object()
            .context("154 prior census")?
            .keys()
            .cloned(),
    );
    expected_units.extend(UNITS.into_iter().map(str::to_owned));
    let selected = next
        .iter()
        .map(|v| v.as_str().map(str::to_owned).context("154 selected name"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        selected.len() == next.len() && selected == expected_units,
        "154 event changed unrelated census scope"
    );
    let mut expected = d.previous_plan.clone();
    for key in [
        "observer",
        "output",
        "previous_fleet",
        "metadata_event",
        "tracked_units",
    ] {
        expected[key] = d.next_plan[key].clone();
    }
    expected["pipeline_claims"]
        .as_array_mut()
        .context("154 retained claims")?
        .push(claim(d.event, d.owner));
    expected["gates"]["154"]["evidence"]
        .as_array_mut()
        .context("154 retained gate evidence")?
        .push(d.next_plan["metadata_event"].clone());
    expected["gates"]["154"]["next_action"] = if d.event["retained_terminal"].is_null() {
        json!(NEXT_ACTION)
    } else {
        ensure!(
            d.event["retained_terminal"] == retained_terminal_binding(),
            "154 event terminal binding differs"
        );
        json!(TERMINAL_NEXT_ACTION)
    };
    ensure!(
        expected == *d.next_plan,
        "154 event changed retained claims, gates, diagnostics or reservations"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn terminal_fixture() -> (Value, crate::Bound, Value, Value, crate::Bound, Value) {
        let terminal: Value =
            serde_json::from_str(include_str!("/home/sol/.jetstreamer-private/epoch199-retained-frame-library-qa-20261104-v5/source/src/fixtures/terminal154-first-adoption.json")).unwrap();
        let owner_binding = serde_json::from_value(terminal["owner"].clone()).unwrap();
        let owner = json!({"producer_invocation_id":terminal["producer_invocation_id"]});
        let release = json!({"producer_invocation_id":terminal["producer_invocation_id"],"recorded_unix_seconds":1793328313});
        let binding = crate::Bound {
            path: "/var/lib/jetstreamer/horizon-native154-suffix-20261029-v1/terminal.json".into(),
            sha256: "ec1f4455f70444f63602c7b26700c0eaee8d7528f2f00befb6fd327c9b19b16b".into(),
        };
        let actual = json!({"unit":UNIT,"invocation_id":terminal["producer_invocation_id"],"data_reservation_bytes":360u64<<30,
            "memory_max_bytes":0,"physical_retirement_credit_bytes":0,"remaining_growth_released":false,"publication_authorized":false,
            "native":terminal["terminal_native"]});
        (actual, owner_binding, owner, release, binding, terminal)
    }
    #[test]
    fn first_entry_can_adopt_only_the_bound_exact_failed154_with_full_retained_data() {
        let (actual, ob, owner, release, b, t) = terminal_fixture();
        allocation(&actual, &ob, &owner, &release, Some((&b, &t))).unwrap();
        assert_eq!(actual["data_reservation_bytes"], 386547056640u64);
        assert_eq!(actual["memory_max_bytes"], 0);
        let mut unloaded = actual.clone();
        for (k, v) in [
            ("InvocationID", ""),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ] {
            unloaded["native"][k] = json!(v);
        }
        allocation(&unloaded, &ob, &owner, &release, Some((&b, &t))).unwrap();
        assert!(allocation(&actual, &ob, &owner, &release, None).is_err());
        let mut wrong = b.clone();
        wrong.path = "/unbound/terminal.json".into();
        assert!(allocation(&actual, &ob, &owner, &release, Some((&wrong, &t))).is_err());
        let mut wrong = b.clone();
        wrong.sha256 = "a".repeat(64);
        assert!(allocation(&actual, &ob, &owner, &release, Some((&wrong, &t))).is_err());
    }
    #[test]
    fn terminal_adoption_rejects_forged_live_memory_or_retirement_credit() {
        let (actual, ob, owner, release, b, t) = terminal_fixture();
        for (pointer, value) in [
            ("/memory_max_bytes", json!(64u64 << 30)),
            ("/memory_max_bytes", json!(1)),
            ("/data_reservation_bytes", json!(0)),
            ("/physical_retirement_credit_bytes", json!(64u64 << 30)),
            ("/remaining_growth_released", json!(true)),
            ("/native/MainPID", json!("42")),
            ("/native/ControlGroup", json!("/system.slice/live")),
            ("/native/InvocationID", json!("f".repeat(32))),
        ] {
            let mut bad = actual.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                allocation(&bad, &ob, &owner, &release, Some((&b, &t))).is_err(),
                "{pointer}"
            );
        }
        let mut fake = actual.clone();
        fake["memory_max_bytes"] = json!(64u64 << 30);
        assert!(allocation(&fake, &ob, &owner, &release, None).is_err());
        for (pointer, value) in [
            ("/control_group_drained", json!(false)),
            ("/owner/sha256", json!("f".repeat(64))),
            ("/producer_invocation_id", json!("f".repeat(32))),
            ("/memory_released_bytes", json!(0)),
            ("/remaining_growth_released", json!(true)),
            ("/archive_completion_claimed", json!(true)),
            ("/publication_authorized", json!(true)),
            ("/r2_mutations", json!(true)),
            ("/repair_backlog_open", json!(false)),
            ("/terminal_native/ExecMainStatus", json!("0")),
            ("/terminal_native/ControlGroup", json!("/live")),
            ("/recorded_unix_seconds", json!(1)),
        ] {
            let mut bad = t.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                allocation(&actual, &ob, &owner, &release, Some((&b, &bad))).is_err(),
                "{pointer}"
            );
        }
    }
    fn fixture() -> (Value, Value, Value, Value, Value, Value) {
        let owner_binding = json!({"path":"/owner.json","sha256":"a".repeat(64)});
        let release_binding = json!({"path":"/release.json","sha256":"b".repeat(64)});
        let old = json!({"observer":{"path":"/observer.json","sha256":"c".repeat(64)},"tracked_units":[RESTORE],
            "pipeline_claims":[{"epoch":154,"unit":RESTORE,"phase":"private-cold-snapshot-verification","evidence":["exact retained proof"]}],
            "gates":{"154":{"state":"blocked-qualification","evidence":["old"],"next_action":"old"}},
            "metadata_event":null,"diagnostics":["retained"],"standing_reservation":123});
        let fleet = json!({"plan":"/old-plan.json","plan_sha256":"d".repeat(64),"unit_census":{RESTORE:{"MainPID":"0"}}});
        let owner = json!({"schema":"jetstreamer-epoch154-suffix-owner-v1","producer_invocation_id":"e".repeat(32),
            "native":{"Id":UNIT,"InvocationID":"e".repeat(32),"ExecStart":"exact captured command"}});
        let release = json!({"schema":"jetstreamer-epoch154-suffix-exec-release-v1","producer_invocation_id":"e".repeat(32),
            "owner":owner_binding,"recorded_unix_seconds":1000,"entry_replay_authorized":true,
            "ordinary_replay_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let event = json!({"schema":SCHEMA,"epoch":154,"unit":UNIT,"owner":owner_binding,"release":release_binding,
            "previous_fleet":{"path":"/old-fleet.json","sha256":"f".repeat(64)},
            "previous_plan":{"path":"/old-plan.json","sha256":"d".repeat(64)},"previous_metadata_event":null,
            "resource_observer":old["observer"],"recorded_unix_seconds":1000,"data_reservation_bytes":360u64<<30,
            "memory_max_bytes":64u64<<30,"resource_credit_bytes":0,"new_resource_samples":0,
            "remaining_growth_released":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let mut next = old.clone();
        next["previous_fleet"] = event["previous_fleet"].clone();
        next["metadata_event"] = json!({"path":"/event.json","sha256":"a".repeat(64)});
        next["output"] = json!("/next-fleet.json");
        for name in UNITS {
            next["tracked_units"]
                .as_array_mut()
                .unwrap()
                .push(json!(name));
        }
        next["pipeline_claims"]
            .as_array_mut()
            .unwrap()
            .push(claim(&event, &owner));
        let event_binding = next["metadata_event"].clone();
        next["gates"]["154"]["evidence"]
            .as_array_mut()
            .unwrap()
            .push(event_binding);
        next["gates"]["154"]["next_action"] = json!(NEXT_ACTION);
        (old, next, fleet, event, owner, release)
    }
    #[test]
    fn delayed_registration_uses_real_next_observer_without_backdating_release() {
        let (old, mut next, fleet, mut event, owner, release) = fixture();
        next["observer"] = json!({"path":"/actual-next-observer.json","sha256":"f".repeat(64)});
        event["resource_refresh"] = json!({"schema":"jetstreamer-suffix154-genuine-observer-refresh-v1",
            "previous_observer":old["observer"],"observer":next["observer"]});
        let before = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"1970-01-01T00:00:00Z"});
        let after = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"1970-01-01T00:30:00Z",
            "cadence":{"previous_sample":old["observer"]["path"],"previous_sample_sha256":old["observer"]["sha256"],
                "minimum_interval_seconds":1800,"observed_interval_seconds":1800,"routine_minimum_interval_enforced":true}});
        let check = |event: &Value, next: &Value, after: &Value, sources: bool| {
            validate_delta(&Delta {
                previous_plan: &old,
                next_plan: next,
                previous_fleet: &fleet,
                event,
                owner: &owner,
                release: &release,
                now: 1801,
                resource_refresh: sources.then_some((&before, &[][..], after)),
            })
        };
        check(&event, &next, &after, true).unwrap();
        assert!(check(&event, &next, &after, false).is_err());
        for (pointer, value) in [
            ("/cadence/previous_sample_sha256", json!("changed")),
            ("/cadence/observed_interval_seconds", json!(1799)),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
            ("/recorded_at_utc", json!("1970-01-01T00:15:00Z")),
            ("/schema", json!("foreign")),
        ] {
            let mut changed = after.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(check(&event, &next, &changed, true).is_err(), "{pointer}");
        }
        let mut bad = next.clone();
        bad["observer"]["sha256"] = json!("changed");
        assert!(check(&event, &bad, &after, true).is_err());
        let mut bad = event.clone();
        bad["resource_refresh"]["previous_observer"]["sha256"] = json!("changed");
        assert!(check(&bad, &next, &after, true).is_err());
        let mut bad = next.clone();
        bad["standing_reservation"] = json!(0);
        assert!(check(&event, &bad, &after, true).is_err());

        // Delayed adoption can span real scheduled observations. It must retain
        // every link; an old release clock alone grants no freshness exception.
        let middle_bound = next["observer"].clone();
        next["observer"] = json!({"path":"/second-actual-observer.json","sha256":"e".repeat(64)});
        event["resource_refresh"]["intermediate_observers"] = json!([middle_bound]);
        event["resource_refresh"]["observer"] = next["observer"].clone();
        let mut second = after.clone();
        second["recorded_at_utc"] = json!("1970-01-01T01:00:00Z");
        second["cadence"]["previous_sample"] = middle_bound["path"].clone();
        second["cadence"]["previous_sample_sha256"] = middle_bound["sha256"].clone();
        validate_delta(&Delta {
            previous_plan: &old,
            next_plan: &next,
            previous_fleet: &fleet,
            event: &event,
            owner: &owner,
            release: &release,
            now: 3601,
            resource_refresh: Some((&before, std::slice::from_ref(&after), &second)),
        })
        .unwrap();
        assert!(
            validate_delta(&Delta {
                previous_plan: &old,
                next_plan: &next,
                previous_fleet: &fleet,
                event: &event,
                owner: &owner,
                release: &release,
                now: 3601,
                resource_refresh: Some((&before, &[], &second))
            })
            .is_err()
        );
        assert!(
            validate_delta(&Delta {
                previous_plan: &old,
                next_plan: &next,
                previous_fleet: &fleet,
                event: &event,
                owner: &owner,
                release: &release,
                now: 10000,
                resource_refresh: Some((&before, std::slice::from_ref(&after), &second))
            })
            .is_err()
        );
    }
    #[test]
    fn actual_release_appends_one_owner_and_preserves_every_prior_obligation() {
        let (old, next, fleet, event, owner, release) = fixture();
        validate_delta(&Delta {
            previous_plan: &old,
            next_plan: &next,
            previous_fleet: &fleet,
            event: &event,
            owner: &owner,
            release: &release,
            now: 1001,
            resource_refresh: None,
        })
        .unwrap();
        for pointer in [
            "/observer/sha256",
            "/pipeline_claims/0/evidence/0",
            "/diagnostics/0",
            "/standing_reservation",
            "/gates/154/state",
        ] {
            let mut changed = next.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(
                validate_delta(&Delta {
                    previous_plan: &old,
                    next_plan: &changed,
                    previous_fleet: &fleet,
                    event: &event,
                    owner: &owner,
                    release: &release,
                    now: 1001,
                    resource_refresh: None,
                })
                .is_err(),
                "{pointer}"
            );
        }
    }
    #[test]
    fn authority_credit_identity_and_release_clock_cannot_be_rewritten() {
        let (_, _, _, event, owner, release) = fixture();
        for key in [
            "resource_credit_bytes",
            "new_resource_samples",
            "recorded_unix_seconds",
            "memory_max_bytes",
            "replay_launch_authorized",
            "remaining_growth_released",
        ] {
            let mut changed = event.clone();
            changed[key] = json!(1);
            assert!(
                event_clock(&changed, &owner, &release, 1001, true).is_err(),
                "{key}"
            );
        }
        assert!(event_clock(&event, &owner, &release, 999, true).is_err());
        assert!(event_clock(&event, &owner, &release, 2801, true).is_err());
        event_clock(&event, &owner, &release, 2801, false).unwrap();
    }
}
