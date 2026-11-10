//! Bridge adapter around the one shared DATA guard reader. Historical guard pins are retained.
use super::*;
pub(super) struct Selection {
    pub protection: Value,
    pub registration: Option<Value>,
    accepted: Option<data_guard_reader::Accepted>,
    original: Value,
    original_protection: Value,
    epoch: u64,
    original_start: u64,
    pid: u64,
}
impl Selection {
    fn context(&self) -> R<data_guard_reader::Context<'_>> {
        Ok(data_guard_reader::Context {
            epoch: self.epoch,
            unit: s(&self.original, "Id")?,
            iid: s(&self.original, "InvocationID")?,
            pid: self.pid,
            start: self.original_start,
            original_protection: &self.original_protection,
        })
    }
}
fn epoch(original: &Value) -> R<u64> {
    let unit = s(original, "Id")?;
    let e = unit
        .strip_prefix("horizon-qualify-")
        .and_then(|v| v.strip_suffix("-replacement-local2-20261110-v1.service"))
        .ok_or("exact original local2 unit required")?
        .parse()?;
    need(
        (166..=172).contains(&e),
        "exact local2 epoch scope required",
    )?;
    Ok(e)
}
fn handoff_path(epoch: u64) -> R<PathBuf> {
    need(
        (166..=172).contains(&epoch),
        "explicit local2 handoff scope",
    )?;
    Ok(PathBuf::from(format!(
        "/var/lib/jetstreamer/local2-data-guard-handoffs-20261110-v1/epoch{epoch}/ROOT_ACTUAL_CONTINUOUS_GUARD_HANDOFF_COMPLETE.json"
    )))
}
fn registry_entry(registry: &Value, original: &Value) -> R<Option<Value>> {
    need(
        registry["schema"] == "horizon-local2-DATA-guard-handoff-registration-v1",
        "bridge handoff registry schema",
    )?;
    let rows = registry["registrations"]
        .as_array()
        .ok_or("bridge handoff registrations")?;
    need(rows.len() <= 7, "bounded exact-owner handoff registrations")?;
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let e = n(row, "epoch")?;
        need(
            (166..=172).contains(&e)
                && row["producer_unit"]
                    == format!("horizon-qualify-{e}-replacement-local2-20261110-v1.service")
                && seen.insert(s(row, "producer_unit")?.to_owned()),
            "duplicate or foreign bridge handoff owner",
        )?;
    }
    let Some(row) = rows.iter().find(|r| r["producer_unit"] == original["Id"]) else {
        return Ok(None);
    };
    need(
        row["epoch"] == epoch(original)?
            && row["producer_invocation_id"] == original["InvocationID"]
            && row["DATA_guard_handoff"].is_object(),
        "bridge handoff changed original invocation",
    )?;
    Ok(Some(row["DATA_guard_handoff"].clone()))
}
fn terminal(v: &Value, unit: &Value, service: bool) -> R<()> {
    need(
        v["Id"] == *unit
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == "",
        "superseded original guard is not natively drained",
    )?;
    if service {
        need(
            v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["NRestarts"] == "0"
                && v["ControlGroup"] == "",
            "superseded original guard still owns native work",
        )?;
    }
    Ok(())
}
fn command(service: &Value, accepted: &data_guard_reader::Accepted) -> R<()> {
    let image = s(&accepted.runtime, "path")?;
    let plan = s(&accepted.protection["plan"], "path")?;
    let hash = s(&accepted.protection["plan"], "sha256")?;
    let image_hash = s(&accepted.runtime, "sha256")?;
    let prefix = format!(
        "{{ path={image} ; argv[]={image} {plan} --plan-sha256 {hash} --self-sha256 {image_hash} ; ignore_errors=no ; "
    );
    need(
        s(service, "ExecStart")?.starts_with(&prefix),
        "actual successor guard command differs from exact image/plan/self SHA",
    )
}
pub(super) fn select(old: &Value, original: &Value) -> R<Selection> {
    let e = epoch(original)?;
    let original_protection =
        bound(&Path::new(batch_for(e)?).join(format!("epoch{e}/ACTUAL_GUARD_PROTECTION.json")))?;
    need(
        hash_bound(&original_protection)? == *old,
        "original protection changed",
    )?;
    let registry: Value = serde_json::from_str(include_str!("guard-handoffs.json"))?;
    let binding = match registry_entry(&registry, original)? {
        Some(binding) => Some(binding),
        None => {
            // Exact predeclared Root output namespace permits the qualified reader to
            // authenticate a newly completed handoff without a circular precomputed digest.
            // Missing files retain the original branch; any present invalid proof fails closed.
            let path = handoff_path(e)?;
            if path.try_exists()? {
                Some(bound(&path)?)
            } else {
                None
            }
        }
    };
    let mut selected = Selection {
        protection: old.clone(),
        registration: binding,
        accepted: None,
        original: original.clone(),
        original_protection,
        epoch: e,
        original_start: start(original)?,
        pid: s(original, "MainPID")?.parse()?,
    };
    if let Some(binding) = &selected.registration {
        let accepted = data_guard_reader::load_handoff(binding, &selected.context()?, now()?)?;
        owner(&accepted.handoff["producer_before"], original)?;
        owner(&accepted.handoff["producer_after"], original)?;
        for (key, service) in [("timer_unit", false), ("guard_unit", true)] {
            terminal(&native(s(old, key)?)?, &old[key], service)?;
        }
        let timer = native(s(&accepted.protection, "timer_unit")?)?;
        need(
            timer["Id"] == accepted.protection["timer_unit"]
                && timer["InvocationID"] == accepted.protection["timer_invocation_id"]
                && timer["ActiveState"] == "active"
                && timer["Triggers"] == accepted.protection["guard_unit"]
                && timer["Job"] == "",
            "new protective timer is not natively active after original drain",
        )?;
        command(&native(s(&accepted.protection, "guard_unit")?)?, &accepted)?;
        selected.protection = accepted.protection.clone();
        selected.accepted = Some(accepted);
    }
    Ok(selected)
}
pub(super) fn validate_current(selection: &Selection, plan: &Value, sample: &Value) -> R<()> {
    if let Some(accepted) = &selection.accepted {
        need(*plan == accepted.plan, "current successor plan changed")?;
        data_guard_reader::sample(accepted, sample, &selection.context()?, now()?, true)
    } else {
        need(
            sample["guard_sha256"] == GUARD,
            "original guard SHA changed without handoff",
        )
    }
}
pub(super) fn validate_capture(selection: &Selection, capture: &Value, sample: &Value) -> R<()> {
    if let Some(accepted) = &selection.accepted {
        data_guard_reader::proof(accepted, capture, sample, &selection.context()?)?;
        command(&capture["guard_service"], accepted)?;
        owner(&capture["actual_producer"], &selection.original)?;
    }
    Ok(())
}
pub(super) fn annotate(selection: &Selection, capture: &mut Value) {
    if let Some(accepted) = &selection.accepted {
        capture["DATA_guard_handoff"] = selection.registration.clone().unwrap_or(Value::Null);
        capture["original_guard_protection"] = selection.original_protection.clone();
        capture["current_guard_protection"] = accepted.handoff["new_protection"].clone();
        capture["current_guard_image"] = accepted.runtime.clone();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_handoff_namespace_cannot_select_another_epoch_or_unqualified_output() {
        assert!(super::handoff_path(165).is_err());
        assert!(super::handoff_path(173).is_err());
        assert_eq!(
            super::handoff_path(172).unwrap(),
            std::path::PathBuf::from(
                "/var/lib/jetstreamer/local2-data-guard-handoffs-20261110-v1/epoch172/ROOT_ACTUAL_CONTINUOUS_GUARD_HANDOFF_COMPLETE.json"
            )
        );
    }

    use super::*;
    fn original() -> Value {
        json!({"Id":"horizon-qualify-166-replacement-local2-20261110-v1.service","InvocationID":"a".repeat(32)})
    }
    fn row() -> Value {
        json!({"epoch":166,"producer_unit":original()["Id"],"producer_invocation_id":original()["InvocationID"],"DATA_guard_handoff":{"path":"/retained/handoff.json","sha256":"b".repeat(64)}})
    }
    fn registry(rows: Value) -> Value {
        json!({"schema":"horizon-local2-DATA-guard-handoff-registration-v1","registrations":rows})
    }
    #[test]
    fn no_registered_handoff_keeps_original_guard_route() {
        assert!(
            registry_entry(&registry(json!([])), &original())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            registry_entry(&registry(json!([row()])), &original())
                .unwrap()
                .unwrap(),
            row()["DATA_guard_handoff"]
        );
    }
    #[test]
    fn duplicate_foreign_or_changed_invocation_cannot_select_handoff() {
        assert!(registry_entry(&registry(json!([row(), row()])), &original()).is_err());
        for (key, value) in [
            ("producer_unit", json!("foreign.service")),
            ("producer_invocation_id", json!("c".repeat(32))),
            ("epoch", json!(173)),
            ("DATA_guard_handoff", Value::Null),
        ] {
            let mut r = row();
            r[key] = value;
            assert!(
                registry_entry(&registry(json!([r])), &original()).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn original_sha_cannot_be_replaced_without_accepted_shared_reader() {
        let selected = Selection {
            protection: json!({}),
            registration: None,
            accepted: None,
            original: original(),
            original_protection: json!({}),
            epoch: 166,
            original_start: 1,
            pid: 2,
        };
        validate_current(&selected, &json!({}), &json!({"guard_sha256":GUARD})).unwrap();
        assert!(
            validate_current(
                &selected,
                &json!({}),
                &json!({"guard_sha256":"b".repeat(64)})
            )
            .is_err()
        );
    }
    #[test]
    fn terminal_old_guard_cannot_retain_processes_or_a_pending_job() {
        let unit = json!("old.service");
        let v = json!({"Id":unit,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Job":"","MainPID":"0","ControlPID":"0","NRestarts":"0","ControlGroup":""});
        terminal(&v, &unit, true).unwrap();
        for key in [
            "MainPID",
            "ControlPID",
            "NRestarts",
            "ControlGroup",
            "Job",
            "ActiveState",
        ] {
            let mut changed = v.clone();
            changed[key] = json!("changed");
            assert!(terminal(&changed, &unit, true).is_err(), "{key}");
        }
    }
    #[test]
    fn native_successor_exec_requires_actual_distinct_image_plan_and_hashes() {
        let accepted = data_guard_reader::Accepted {
            protection: json!({"plan":{"path":"/sealed/plan/guard-plan.json","sha256":"c".repeat(64)}}),
            plan: Value::Null,
            runtime: json!({"path":"/sealed/image/guard","sha256":"b".repeat(64)}),
            registration: Value::Null,
            native_witness: Value::Null,
            handoff: Value::Null,
        };
        let exec = format!(
            "{{ path=/sealed/image/guard ; argv[]=/sealed/image/guard /sealed/plan/guard-plan.json --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=[date] ; stop_time=[date] ; pid=123 ; code=exited ; status=0 }}",
            "c".repeat(64),
            "b".repeat(64)
        );
        command(&json!({"ExecStart":exec}), &accepted).unwrap();
        for changed in [
            exec.replace("/sealed/image/guard", "/other/guard"),
            exec.replace(&"b".repeat(64), GUARD),
            exec.replace("/sealed/plan/guard-plan.json", "/other/guard-plan.json"),
        ] {
            assert!(command(&json!({"ExecStart":changed}), &accepted).is_err());
        }
    }
}
