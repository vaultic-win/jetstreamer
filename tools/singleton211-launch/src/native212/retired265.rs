//! Release only the nominal RAM of the completed native 265 diagnostic in a
//! reviewed 212 arithmetic view. Its separately registered live v3 owner remains.
use super::*;

const OLD: &str = "horizon-265-native-input-20261119-v1.service";
const IID: &str = "ce5f66a82fdd4c0e93ca99f27b925112";
const CAP: u64 = 128_000_000_000;
const GUARD: &str = "horizon-native265-protective-v1.service";
const TIMER: &str = "horizon-native265-protective-v1.timer";
const FIELD: &str = "completed_native265_diagnostic_memory_release";
const SOURCE: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-singleton211-original-native265-booking-20261120-v1/booking-native265.json",
    "3aba0672f8b2e1012aedc630a499c30f35fec974e24c0b73ff54e7a8678bfff5",
);
const OLD_GROWTH: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native265-runtime-growth-release-20261120-v2/release.json",
    "0c316a1587b9e164bbb8ca488f131486b45cb367fa36b28015d27ad0b732d225",
);
const TERMINAL: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native265-terminal-proof-2048-20261119-v1/proof.json",
    "62d7d71ee1a9c7215c4fffa7d5fec49ef449bb6be24de3e450432217a3efa519",
);
const PLAN: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native265-startup-plan-native-20261119-v1/plan.json",
    "d4b85afe49e74d9a7f8e5c96393c8d5d023b1437b281ee0de186d59f6e4f23b7",
);
const TOKEN: (&str, &str) = (
    "/var/lib/jetstreamer/horizon-native265-startup-tokens/ce5f66a82fdd4c0e93ca99f27b925112/guard-admission.json",
    "38201691bbc6c63f036b536fd3604237afe2f4b630c6c9c9ff14348295f47e86",
);

fn pin((path, sha): (&str, &str)) -> Bound {
    Bound::new(path, sha)
}

fn authorization(v: &Value) -> Result<()> {
    ensure!(
        v == &json!({"original_booking":pin(SOURCE),"terminal":pin(TERMINAL),
    "no_pending_or_future_original_diagnostic_confirmed":true}),
        "unregistered native265 memory closure"
    );
    Ok(())
}

fn row(rows: &[capacity::Reservation], currents: &BTreeMap<String, u64>) -> Result<usize> {
    let mut found = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.unit == OLD || r.invocation_id == IID);
    let (idx, r) = found
        .next()
        .context("completed native265 reservation missing")?;
    ensure!(
        found.next().is_none()
            && r.unit == OLD
            && r.invocation_id == IID
            && r.source == pin(SOURCE)
            && r.maximum_memory_bytes == CAP
            && r.remaining_disk_growth_bytes == 0
            && r.minimum_free_bytes >= 3_216_541_534_488
            && r.release.is_none()
            && !currents.contains_key(OLD),
        "invalid, live or already released native265 diagnostic"
    );
    Ok(idx)
}

fn expired(plan: &Value, token: &Value, boot: &str, clock: u64) -> Result<()> {
    ensure!(
        plan["schema"] == "horizon-native265-startup-plan-v1"
            && token["schema"] == "horizon-native265-first-guard-token-v1"
            && plan["unit"] == OLD
            && token["unit"] == OLD
            && token["invocation_id"] == IID
            && token["main_pid"] == 1307638
            && plan["boot_id"] == boot
            && token["boot_id"] == boot
            && token["startup_plan_sha256"] == PLAN.1
            && token["admission"] == plan["admission"]
            && num(plan, "issued_monotonic_us")? <= num(token, "recorded_monotonic_us")?
            && num(token, "recorded_monotonic_us")? < num(plan, "expires_monotonic_us")?
            && num(plan, "expires_monotonic_us")? < clock,
        "old native265 startup authority is live or different"
    );
    Ok(())
}

fn dormant(state: &Value, unit: &str) -> Result<()> {
    ensure!(
        state["Id"] == unit
            && state["LoadState"] == "loaded"
            && state["ActiveState"] == "inactive"
            && state["SubState"] == "dead"
            && state["Job"] == ""
            && state["DropInPaths"] == ""
            && (unit == TIMER || (state["MainPID"] == "0" && state["ControlPID"] == "0"))
            && (unit != OLD
                || (state["InvocationID"] == IID
                    && state["Restart"] == "no"
                    && state["TriggeredBy"] == "")),
        "old native265 diagnostic unit or guard has pending work"
    );
    Ok(())
}

pub(crate) fn apply(
    n: &mut Native,
    review: &Value,
    host: &mut native257_fit::BookedHost,
) -> Result<Option<Value>> {
    let Some(choice) = review.get(FIELD) else {
        return Ok(None);
    };
    authorization(choice)?;
    let idx = row(&host.rows, &host.currents)?;
    let growth = host
        .release
        .as_ref()
        .context("missing independently verified native265 scratch retirement")?;
    ensure!(
        growth["release"] == json!(pin(OLD_GROWTH))
            && growth["released_memory_bytes"] == 0
            && growth["current_scope"]["terminal"]["InvocationID"] == IID
            && growth["current_scope"]["terminal"]["Result"] == "success",
        "native265 growth-only evidence changed"
    );
    let plan = pin(PLAN).sealed()?;
    let token = pin(TOKEN).sealed()?;
    expired(&plan, &token, &host.boot, mono()?)?;
    let mut states = BTreeMap::new();
    let mut drained_states = BTreeMap::new();
    for unit in [OLD, GUARD, TIMER] {
        let before = n.show(unit)?;
        dormant(&before, unit)?;
        live::verify_drained_group(unit)?;
        let after = n.show(unit)?;
        dormant(&after, unit)?;
        live::same_manager_properties(unit, &before, &after)?;
        states.insert(unit, before);
        drained_states.insert(unit, after);
    }
    let closure = binding(&review["resource_review"])?;
    let signed = closure.sealed()?;
    ensure!(
        signed["Main_accepted"] == true
            && signed["single_campaign_controller_confirmed"] == true
            && signed[FIELD] == *choice
            && signed["boot_id"] == host.boot
            && ["fleet", "observer", "reservation_ledger"]
                .iter()
                .all(|k| signed[*k] == review[*k]),
        "completed native265 closure missing from current accepted resource review"
    );
    host.rows[idx].release = Some(closure.clone());
    Ok(Some(
        json!({"schema":"horizon-native212-completed-native265-memory-release-v1","unit":OLD,"invocation_id":IID,
        "review":closure,"growth_only":pin(OLD_GROWTH),"terminal":pin(TERMINAL),"expired_plan":pin(PLAN),"expired_token":pin(TOKEN),
        "current_owners":states,"owners_after_drain":drained_states,"released_memory_bytes":CAP,"additional_disk_credit_bytes":0,"physical_allocation_credit_bytes":0,"inherited_floor_credit_bytes":0}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn guard_sample(raw: &str) -> Value {
        let mut fields = serde_json::Map::new();
        for line in raw.lines() {
            let (key, value) = line.split_once('=').unwrap();
            assert!(fields.insert(key.into(), json!(value)).is_none());
        }
        Value::Object(fields)
    }

    #[test]
    fn v149_guard_drain_accepts_the_two_original_orderings() -> Result<()> {
        let first = guard_sample(include_str!(
            "../fixtures/native265-guard-v149-1077.properties"
        ));
        let second = guard_sample(include_str!(
            "../fixtures/native265-guard-v149-1078.properties"
        ));
        assert_eq!(
            first["After"],
            "system.slice basic.target sysinit.target systemd-journald.socket"
        );
        assert_eq!(
            second["After"],
            "basic.target systemd-journald.socket sysinit.target system.slice"
        );
        assert_ne!(first, second);
        dormant(&first, GUARD)?;
        dormant(&second, GUARD)?;
        live::same_manager_properties(GUARD, &first, &second)?;
        live::same_manager_properties(GUARD, &second, &first)
    }

    #[test]
    fn v149_guard_drain_rejects_relation_and_scalar_drift_from_either_sample() {
        let before = guard_sample(include_str!(
            "../fixtures/native265-guard-v149-1077.properties"
        ));
        let after = guard_sample(include_str!(
            "../fixtures/native265-guard-v149-1078.properties"
        ));
        for (key, value) in [
            (
                "After",
                "basic.target systemd-journald.socket sysinit.target",
            ),
            (
                "After",
                "system.slice basic.target sysinit.target rogue.socket",
            ),
            (
                "After",
                "system.slice basic.target sysinit.target systemd-journald.socket rogue.socket",
            ),
            (
                "After",
                "system.slice basic.target sysinit.target systemd-journald.socket system.slice",
            ),
            ("Requires", "system.slice sysinit.target sysinit.target"),
            ("TriggeredBy", "unexpected.timer"),
            ("Job", "42"),
            ("ExecStart", "/bin/false"),
            ("Environment", "OTHER=1"),
            ("ReadWritePaths", "/other"),
            ("ActiveState", "active"),
            ("InvocationID", "ffffffffffffffffffffffffffffffff"),
        ] {
            let mut changed = after.clone();
            changed[key] = json!(value);
            assert!(
                live::same_manager_properties(GUARD, &before, &changed).is_err(),
                "{key}"
            );
            assert!(
                live::same_manager_properties(GUARD, &changed, &before).is_err(),
                "{key}"
            );
        }
        let mut changed = after.clone();
        changed["Requires"] = json!("system.slice sysinit.target sysinit.target");
        assert!(live::same_manager_properties(GUARD, &changed, &changed).is_err());
        changed = after.clone();
        changed.as_object_mut().unwrap().remove("Result");
        assert!(live::same_manager_properties(GUARD, &before, &changed).is_err());
        changed["UnexpectedProperty"] = json!("");
        assert!(live::same_manager_properties(GUARD, &before, &changed).is_err());
        let mut left = before;
        left["Environment"] = json!("A=1 B=2");
        let mut right = after;
        right["Environment"] = json!("B=2 A=1");
        assert!(live::same_manager_properties(GUARD, &left, &right).is_err());
    }

    #[test]
    fn only_original_completed_row_after_growth_can_release_memory() {
        let mut r = capacity::Reservation {
            unit: OLD.into(),
            invocation_id: IID.into(),
            maximum_memory_bytes: CAP,
            remaining_disk_growth_bytes: 0,
            minimum_free_bytes: 3_216_541_534_488,
            source: pin(SOURCE),
            release: None,
        };
        let mut current = BTreeMap::new();
        assert_eq!(row(std::slice::from_ref(&r), &current).unwrap(), 0);
        assert!(row(&[r.clone(), r.clone()], &current).is_err());
        current.insert(OLD.into(), 1);
        assert!(row(std::slice::from_ref(&r), &current).is_err());
        current.clear();
        r.remaining_disk_growth_bytes = 1;
        assert!(row(std::slice::from_ref(&r), &current).is_err());
        r.remaining_disk_growth_bytes = 0;
        r.release = Some(pin(TERMINAL));
        assert!(row(std::slice::from_ref(&r), &current).is_err());
    }
    #[test]
    fn ordinary_scratch_receipt_cannot_authorize_memory() {
        assert!(
            authorization(&json!({"terminal":pin(TERMINAL),"released_memory_bytes":0})).is_err()
        );
        assert!(authorization(&json!({"original_booking":pin(SOURCE),"terminal":pin(TERMINAL),"no_pending_or_future_original_diagnostic_confirmed":false})).is_err());
        authorization(&json!({"original_booking":pin(SOURCE),"terminal":pin(TERMINAL),"no_pending_or_future_original_diagnostic_confirmed":true})).unwrap();
    }
    #[test]
    fn release_delta_preserves_the_separate_ordinary_265_cap_and_every_disk_obligation() {
        let old = capacity::Reservation {
            unit: OLD.into(),
            invocation_id: IID.into(),
            maximum_memory_bytes: CAP,
            remaining_disk_growth_bytes: 0,
            minimum_free_bytes: 3_216_541_534_488,
            source: pin(SOURCE),
            release: None,
        };
        let mut live = old.clone();
        live.unit = "horizon-qualify-265-replacement-20261119-v3.service".into();
        live.invocation_id = "182de64d33674f95b7758d410eb1812b".into();
        live.remaining_disk_growth_bytes = 506_191_984_640;
        let mut rows = [old, live];
        let currents = BTreeMap::from([(rows[1].unit.clone(), 1024)]);
        let project = |rows: &[capacity::Reservation]| {
            capacity::candidate_arithmetic(
                (u64::MAX, u64::MAX, u64::MAX),
                280_581_611_288,
                rows,
                &currents,
                (0, 0),
                (423_669_149_696, 256_536_870_912),
            )
            .unwrap()
        };
        let before = project(&rows);
        let index = row(&rows, &currents).unwrap();
        rows[index].release = Some(pin(TERMINAL));
        let after = project(&rows);
        assert!(rows[1].release.is_none());
        for key in [
            "memory_obligation_after_bytes",
            "remaining_hard_growth_bytes",
        ] {
            assert_eq!(num(&before, key).unwrap() - num(&after, key).unwrap(), CAP);
        }
        for key in [
            "protected_existing_floor_bytes",
            "required_initial_free_bytes",
            "retained_disk_growth_bytes",
            "allocation_credit_taken_bytes",
        ] {
            assert_eq!(before[key], after[key]);
        }
    }
    #[test]
    fn original_token_expires_even_while_retained() {
        let p = json!({"schema":"horizon-native265-startup-plan-v1","unit":OLD,"boot_id":"boot","admission":pin(PLAN),"issued_monotonic_us":2,"expires_monotonic_us":10});
        let mut t = json!({"schema":"horizon-native265-first-guard-token-v1","unit":OLD,"invocation_id":IID,"main_pid":1307638,"boot_id":"boot","startup_plan_sha256":PLAN.1,"admission":pin(PLAN),"recorded_monotonic_us":5});
        expired(&p, &t, "boot", 11).unwrap();
        assert!(expired(&p, &t, "boot", 10).is_err());
        assert!(expired(&p, &t, "different", 11).is_err());
        t["invocation_id"] = json!("f".repeat(32));
        assert!(expired(&p, &t, "boot", 11).is_err());
    }
}
