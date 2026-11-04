//! Authenticate an existing controller-before-producer reserve stop. No stopping,
//! replay launch, archive mutation or resource observation happens here.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub epoch: u64,
    pub controller_unit: String,
    pub controller_invocation_id: String,
    pub producer_unit: String,
    pub producer_invocation_id: String,
    pub intent: Bound,
    pub completion: Bound,
}

impl Evidence {
    pub fn owners(&self) -> Vec<(String, String)> {
        vec![
            (
                self.controller_unit.clone(),
                self.controller_invocation_id.clone(),
            ),
            (
                self.producer_unit.clone(),
                self.producer_invocation_id.clone(),
            ),
        ]
    }

    pub fn validate(
        &self,
        current: &BTreeMap<String, Value>,
        minimum_time: u64,
        now: u64,
    ) -> Result<()> {
        let intent = read(&self.intent)?;
        let completion = read(&self.completion)?;
        validate_values(self, &intent, &completion, current, minimum_time, now)
    }
}

// Guard receipts use Python's fractional UTC ISO form. Accept only explicit
// UTC, not an arbitrary suffix silently converted to Z. Preserve subsecond
// order while reusing the calendar/date validation of the fleet parser.
fn timestamp(value: &str) -> Result<(u64, u32)> {
    let body = value
        .strip_suffix('Z')
        .or_else(|| value.strip_suffix("+00:00"))
        .context("reserve timestamp must be explicit UTC")?;
    let (whole, fraction) = body.split_once('.').unwrap_or((body, ""));
    ensure!(
        whole.len() == 19
            && (fraction.is_empty() && !body.contains('.')
                || !fraction.is_empty()
                    && fraction.len() <= 9
                    && fraction.bytes().all(|b| b.is_ascii_digit())),
        "malformed reserve timestamp"
    );
    let seconds = fleet::utc_seconds(&format!("{whole}Z"))?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u32>()? * 10u32.pow(9 - fraction.len() as u32)
    };
    Ok((seconds, nanos))
}

fn read(bound: &Bound) -> Result<Value> {
    ensure!(
        bound.path.is_absolute() && bound.path.canonicalize()? == bound.path,
        "noncanonical reserve evidence"
    );
    let m = fs::symlink_metadata(&bound.path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unsafe reserve evidence"
    );
    let bytes = read_stable_bounded(&bound.path, 65536, "reserve stop evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "reserve evidence digest changed"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn stopped(value: &Value, invocation: &str, systemd: bool) -> bool {
    let field = |a, b| if systemd { &value[a] } else { &value[b] };
    field("ActiveState", "active_state") == "inactive"
        && field("SubState", "sub_state") == "dead"
        && (field("LoadState", "load_state") == "loaded"
            || systemd && value["LoadState"] == "not-found" && value["InvocationID"] == "")
        && field("Result", "result") == "success"
        && (field("InvocationID", "invocation_id") == invocation
            || field("InvocationID", "invocation_id") == "")
        && if systemd {
            value["MainPID"] == "0" && value["NRestarts"] == "0"
        } else {
            value["main_pid"] == 0 && value["restarts"] == 0 && value["worker_count"] == 0
        }
}

fn validate_values(
    e: &Evidence,
    intent: &Value,
    completion: &Value,
    current: &BTreeMap<String, Value>,
    minimum_time: u64,
    now: u64,
) -> Result<()> {
    ensure!(
        e.epoch > 0 && e.controller_unit != e.producer_unit,
        "reserve stop must name one owned singleton"
    );
    ensure!(
        e.producer_unit.starts_with("jetstreamer-root-sweep-")
            && e.producer_unit
                .contains(&format!("-e{}-{}-", e.epoch, e.epoch))
            && [&e.controller_unit, &e.producer_unit]
                .iter()
                .all(|unit| unit.len() <= 255
                    && unit.ends_with(".service")
                    && unit
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))),
        "reserve evidence requires an exact singleton unit scope"
    );
    ensure!(
        intent["schema"] == "jetstreamer-adaptive-replay-reserve-stop-intent-v1"
            && completion["schema"] == "jetstreamer-adaptive-replay-reserve-stop-completion-v1"
            && completion["intent_receipt"].as_str() == e.intent.path.to_str(),
        "reserve stop schemas or intent differ"
    );
    let start = timestamp(
        intent["observed_at_utc"]
            .as_str()
            .context("stop intent time missing")?,
    )?;
    let end = timestamp(
        completion["observed_at_utc"]
            .as_str()
            .context("stop completion time missing")?,
    )?;
    ensure!(
        start.0 >= minimum_time && end >= start && end.0 <= now,
        "reserve stop chronology differs"
    );
    let floor = intent["minimum_free_bytes"]
        .as_u64()
        .context("stop floor missing")?;
    ensure!(
        floor > 0
            && intent["available_bytes"]
                .as_u64()
                .is_some_and(|n| n < floor)
            && completion["minimum_free_bytes"] == floor
            && completion["filesystem"] == intent["filesystem"]
            && completion["controller_stop"]["return_code"] == 0
            && completion["producer_stop"]["return_code"] == 0
            && completion["scratch_deleted"] == false,
        "not a completed protected-space stop"
    );
    ensure!(
        intent["stop_order"] == serde_json::json!(["controller", "producer"]),
        "wrong reserve stop order"
    );
    for receipt in [intent, completion] {
        ensure!(
            receipt["controller_unit"] == e.controller_unit
                && receipt["producer_unit"] == e.producer_unit
                && receipt["expected_controller_invocation_id"] == e.controller_invocation_id
                && receipt["expected_producer_invocation_id"] == e.producer_invocation_id
                && receipt["remote_mutations"] == false
                && receipt["r2_mutations"] == false,
            "reserve owner or authority differs"
        );
    }
    for (unit, iid, label) in [
        (
            &e.controller_unit,
            &e.controller_invocation_id,
            "controller",
        ),
        (&e.producer_unit, &e.producer_invocation_id, "producer"),
    ] {
        ensure!(
            iid.len() == 32
                && iid
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "invalid reserve owner ID"
        );
        let before = &intent[format!("{label}_sample")];
        ensure!(
            before["unit"] == *unit
                && before["invocation_id"] == *iid
                && before["active_state"] == "active"
                && before["sub_state"] == "running"
                && before["load_state"] == "loaded"
                && before["main_pid"].as_u64().is_some_and(|n| n > 0)
                && before["restarts"] == 0,
            "reserve intent does not authenticate live owner"
        );
        ensure!(
            completion[format!("{label}_final")]["unit"] == *unit
                && stopped(&completion[format!("{label}_final")], iid, false),
            "reserve completion owner not stopped"
        );
        ensure!(
            stopped(
                current
                    .get(unit)
                    .context("reserve owner omitted from census")?,
                iid,
                true
            ),
            "reserve owner is active, replaced or ambiguous"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (Evidence, Value, Value, BTreeMap<String, Value>) {
        let e = Evidence {
            epoch: 185,
            controller_unit: "jetstreamer-epoch185-controller.service".into(),
            controller_invocation_id: "a".repeat(32),
            producer_unit: "jetstreamer-root-sweep-test-e185-185-lane-a-1.service".into(),
            producer_invocation_id: "b".repeat(32),
            intent: Bound {
                path: "/evidence/intent.json".into(),
                sha256: "c".repeat(64),
            },
            completion: Bound {
                path: "/evidence/completion.json".into(),
                sha256: "d".repeat(64),
            },
        };
        let mut intent = json!({"schema":"jetstreamer-adaptive-replay-reserve-stop-intent-v1",
            "observed_at_utc":"2026-10-20T16:43:07.397399+00:00",
            "minimum_free_bytes":100,"available_bytes":99,"filesystem":"/home/sol",
            "controller_unit":e.controller_unit,"producer_unit":e.producer_unit,
            "expected_controller_invocation_id":e.controller_invocation_id,
            "expected_producer_invocation_id":e.producer_invocation_id,
            "remote_mutations":false,"r2_mutations":false,"stop_order":["controller","producer"]});
        let mut completion = intent.clone();
        completion["schema"] = json!("jetstreamer-adaptive-replay-reserve-stop-completion-v1");
        completion["observed_at_utc"] = json!("2026-10-20T16:43:09.924538+00:00");
        completion["intent_receipt"] = json!(e.intent.path);
        completion["controller_stop"] = json!({"return_code":0});
        completion["producer_stop"] = json!({"return_code":0});
        completion["scratch_deleted"] = json!(false);
        let mut current = BTreeMap::new();
        for (label, (unit, iid)) in ["controller", "producer"].into_iter().zip(e.owners()) {
            intent[format!("{label}_sample")] = json!({"unit":unit,"invocation_id":iid,
                "active_state":"active","sub_state":"running","load_state":"loaded",
                "main_pid":123,"restarts":0});
            completion[format!("{label}_final")] = json!({"unit":unit,"invocation_id":"",
                "active_state":"inactive","sub_state":"dead","load_state":"loaded",
                "main_pid":0,"restarts":0,"worker_count":0,"result":"success"});
            current.insert(unit, json!({"InvocationID":"","ActiveState":"inactive",
                "SubState":"dead","LoadState":"loaded","MainPID":"0","NRestarts":"0","Result":"success"}));
        }
        (e, intent, completion, current)
    }

    #[test]
    fn explicit_utc_and_calendar_are_strict() {
        assert_eq!(
            timestamp("2026-10-20T16:43:07.397399+00:00").unwrap(),
            timestamp("2026-10-20T16:43:07.397399Z").unwrap()
        );
        for bad in [
            "2026-10-20T16:43:07.1+01:00",
            "2026-10-20T16:43:07.1-00:00",
            "2026-10-20T16:43:07",
            "2026-10-20T16:43:07.Z",
            "2026-10-20T16:43:07.xZ",
            "2026-10-20T16:43:07.1234567890Z",
            "2026-02-30T16:43:07Z",
            "2026-10-20T25:43:07Z",
            "2026-10-20T16:43:07junkZ",
        ] {
            assert!(timestamp(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn cleared_or_retained_invocations_are_authenticated() {
        let (e, i, mut c, mut current) = fixture();
        let now = fleet::utc_seconds("2026-10-20T17:00:00Z").unwrap();
        validate_values(&e, &i, &c, &current, 0, now).unwrap();
        for (label, (unit, iid)) in ["controller", "producer"].into_iter().zip(e.owners()) {
            c[format!("{label}_final")]["invocation_id"] = json!(iid);
            current.get_mut(&unit).unwrap()["InvocationID"] = json!(iid);
        }
        validate_values(&e, &i, &c, &current, 0, now).unwrap();
        assert!(validate_values(&e, &i, &c, &current, now, now).is_err());
        let producer = current.get_mut(&e.producer_unit).unwrap();
        producer["LoadState"] = json!("not-found");
        producer["InvocationID"] = json!("");
        validate_values(&e, &i, &c, &current, 0, now).unwrap();
        current.get_mut(&e.producer_unit).unwrap()["InvocationID"] =
            json!(e.producer_invocation_id);
        assert!(validate_values(&e, &i, &c, &current, 0, now).is_err());
    }

    #[test]
    fn changed_stop_proofs_fail_closed() {
        let (e, i, c, current) = fixture();
        let now = fleet::utc_seconds("2026-10-20T17:00:00Z").unwrap();
        for (pointer, replacement) in [
            ("/minimum_free_bytes", json!(99)),
            ("/available_bytes", json!(100)),
            ("/stop_order", json!(["producer", "controller"])),
            ("/controller_sample/invocation_id", json!("f".repeat(32))),
            ("/producer_sample/restarts", json!(1)),
            ("/r2_mutations", json!(true)),
        ] {
            let mut changed = i.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_values(&e, &changed, &c, &current, 0, now).is_err(),
                "{pointer}"
            );
        }
        for (pointer, replacement) in [
            ("/producer_stop/return_code", json!(1)),
            ("/controller_final/unit", json!("foreign.service")),
            ("/producer_final/result", json!("signal")),
            ("/producer_final/main_pid", json!(7)),
            ("/producer_final/worker_count", json!(1)),
            ("/scratch_deleted", json!(true)),
            ("/remote_mutations", json!(true)),
            (
                "/observed_at_utc",
                json!("2026-10-20T16:43:07.397398+00:00"),
            ),
        ] {
            let mut changed = c.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                validate_values(&e, &i, &changed, &current, 0, now).is_err(),
                "{pointer}"
            );
        }
    }

    #[test]
    fn live_replacement_restart_or_missing_owner_blocks_cleanup() {
        let (e, i, c, current) = fixture();
        let now = fleet::utc_seconds("2026-10-20T17:00:00Z").unwrap();
        for (unit, _) in e.owners() {
            for (field, value) in [
                ("InvocationID", "f".repeat(32)),
                ("ActiveState", "active".into()),
                ("MainPID", "1".into()),
                ("NRestarts", "1".into()),
                ("Result", "signal".into()),
            ] {
                let mut changed = current.clone();
                changed.get_mut(&unit).unwrap()[field] = json!(value);
                assert!(validate_values(&e, &i, &c, &changed, 0, now).is_err());
            }
            let mut changed = current.clone();
            changed.remove(&unit);
            assert!(validate_values(&e, &i, &c, &changed, 0, now).is_err());
        }
    }

    #[test]
    fn wrong_epoch_scope_and_future_stop_are_not_terminal_authority() {
        let (mut e, i, c, current) = fixture();
        let now = fleet::utc_seconds("2026-10-20T17:00:00Z").unwrap();
        e.epoch = 186;
        assert!(validate_values(&e, &i, &c, &current, 0, now).is_err());
        e.epoch = 185;
        assert!(validate_values(&e, &i, &c, &current, 0, now - 3600).is_err());
        let mut changed = c.clone();
        changed["producer_stop"]["return_code"] = json!("0");
        assert!(validate_values(&e, &i, &changed, &current, 0, now).is_err());
    }
}
