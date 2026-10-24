//! One upload-to-readback handoff for an unchanged, authenticated native uploader.
use super::*;

pub(crate) const SCHEMA: &str = "jetstreamer-cohort191-same-owner-readback-clock-v2";
const STATUS_DIRECTORY: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub epoch: u64,
    pub accepted_fleet: Bound,
    pub status_fleet: Bound,
    pub routine_completion: Bound,
    pub accepted_event: Bound,
    pub previous_status_publication: Bound,
    pub readback_start_journal: Bound,
}

fn row(state: &Value, epoch: u64) -> Result<&Value> {
    let rows: Vec<_> = state["epochs"]
        .as_array()
        .context("readback queue rows")?
        .iter()
        .filter(|row| row["epoch"] == epoch)
        .collect();
    ensure!(rows.len() == 1, "readback epoch missing or duplicated");
    Ok(rows[0])
}

fn same_owner(before: &Value, after: &Value) -> Result<()> {
    ensure!(
        before["stage"] == "upload"
            && after["stage"] == "readback"
            && before["task_owner"].is_object(),
        "readback requires an actual upload owner"
    );
    let mut projected = before.clone();
    projected["stage"] = json!("readback");
    ensure!(
        projected == *after,
        "readback changed uploader, archive, receipts or original start"
    );
    Ok(())
}

fn marker_shape(
    marker: &Value,
    epoch: u64,
    before: &Value,
    resource: u64,
    event: u64,
) -> Result<()> {
    let owner = &before["task_owner"];
    let message: Value = serde_json::from_str(
        marker["MESSAGE"]
            .as_str()
            .context("readback journal message")?,
    )?;
    let time = marker["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("readback journal time")?
        .parse::<u64>()?;
    ensure!(
        marker["_SYSTEMD_UNIT"] == owner["unit"]
            && marker["_SYSTEMD_INVOCATION_ID"] == owner["invocation_id"]
            && marker["_PID"].as_str().and_then(|n| n.parse::<u64>().ok()) == owner["pid"].as_u64()
            && owner["pid"].as_u64().is_some_and(|n| n > 0)
            && marker["_UID"] == "0"
            && marker["_EXE"] == owner["program"]["path"]
            && marker["__CURSOR"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 4096)
            && message["event"] == "r2-readback-start"
            && message["key"] == format!("epoch-{epoch}.jet")
            && message["expected_sha256"] == before["archive_sha256"]
            && message["expected_etag"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
            && message["total_bytes"] == before["archive_length"]
            && message["hashed_bytes"] == 0
            && message["elapsed_millis"] == 0
            && message["whole_file_sha256_verified"] == false
            && resource.checked_mul(1_000_000).is_some_and(|n| n < time)
            && event.checked_mul(1_000_000).is_some_and(|n| time <= n),
        "readback marker is foreign, backdated, or claims integrity"
    );
    Ok(())
}

fn authenticate_marker(marker: &Value) -> Result<()> {
    let time = marker["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("readback marker time")?
        .parse::<u64>()?
        / 1_000_000;
    let unit = marker["_SYSTEMD_UNIT"]
        .as_str()
        .context("readback marker unit")?;
    let iid = marker["_SYSTEMD_INVOCATION_ID"]
        .as_str()
        .context("readback marker invocation")?;
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "-u",
            unit,
            &format!("_SYSTEMD_INVOCATION_ID={iid}"),
            "--since",
            &format!("@{time}"),
            "--until",
            &format!(
                "@{}",
                time.checked_add(1)
                    .context("readback journal time overflow")?
            ),
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "readback journal unavailable or oversized"
    );
    let records: Vec<Value> = output
        .stdout
        .split(|b| *b == b'\n')
        .filter(|b| !b.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        records.iter().filter(|v| *v == marker).count() == 1,
        "readback marker is not the exact original native journal record"
    );
    Ok(())
}

pub(crate) fn config(clock: &Value) -> Result<Option<Config>> {
    if clock["schema"] != SCHEMA {
        return Ok(None);
    }
    Ok(Some(serde_json::from_value(
        clock["same_owner_readback"].clone(),
    )?))
}

pub(crate) fn completed_coordinator(
    clock: &Value,
    fleet: &Value,
    name: &str,
    before: &Value,
    after: &Value,
) -> Result<bool> {
    let Some(c) = config(clock)? else {
        return Ok(false);
    };
    let cycle = Path::new(fleet["plan"].as_str().context("readback fleet plan")?)
        .parent()
        .and_then(Path::parent)
        .context("readback cycle")?;
    let suffix = cycle
        .file_name()
        .and_then(|v| v.to_str())
        .context("readback coordinator name")?;
    let expected_name = format!("horizon-routine-cycle-101-200-{suffix}.service");
    if name != expected_name {
        return Ok(false);
    }
    let completion = bound(&c.routine_completion, false)?;
    let iid = completion["invocation_id"]
        .as_str()
        .context("readback coordinator invocation")?;
    let coordinator = (expected_name, iid.into());
    Ok(growth_transfer::successful_coordinator_exit(
        name,
        before,
        after,
        &coordinator,
    ))
}

pub(crate) fn previous_shape(
    previous: &Value,
    c: &Config,
    observer: &Value,
    observer_binding: &Value,
) -> Result<()> {
    ensure!(
        (191..=194).contains(&c.epoch)
            && c.previous_status_publication.path.parent() == Some(Path::new(STATUS_DIRECTORY))
            && previous["schema"] == PIPELINE_STATUS_RECEIPT_SCHEMA
            && previous["epoch"] == c.epoch
            && previous["status"]["epoch"] == c.epoch
            && previous["status"]["phase"] == "upload"
            && previous["status"]["sampled_at_utc"] == observer["recorded_at_utc"]
            && previous["observer_receipt"] == observer_binding["path"]
            && previous["observer_receipt_sha256"] == observer_binding["sha256"]
            && previous["authenticated_readback"] == true
            && previous["pipeline_binding"]["unit"] == queue::UNIT
            && previous["pipeline_binding"]["invocation_id"] == "0defba8ed0844040a2601c68d79060b2"
            && previous["pipeline_binding"]["claim_phase"] == "cohort191-delivery"
            && previous["pipeline_binding"]["origin_unit"] == UNIT
            && previous["pipeline_binding"]["origin_invocation_id"] == IID
            && previous["pipeline_binding"]["fleet_path"] == json!(c.status_fleet.path)
            && previous["pipeline_binding"]["fleet_sha256"] == c.status_fleet.sha256,
        "readback prior status is not the accepted frame's exact upload owner"
    );
    Ok(())
}

pub(super) fn validate(p: &Capture, observer: &Value, clock: &Value) -> Result<()> {
    let c = config(clock)?.context("missing same-owner readback configuration")?;
    let fleet = bound(&c.accepted_fleet, false)?;
    let status_fleet = bound(&c.status_fleet, false)?;
    let completion = bound(&c.routine_completion, false)?;
    let accepted = bound(&c.accepted_event, false)?;
    let resource = fleet::utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("readback resource clock")?,
    )?;
    let event = clock["recorded_unix_seconds"]
        .as_u64()
        .context("readback event time")?;
    let sample = &observer["recorded_at_utc"];
    let fleet_plan = Path::new(fleet["plan"].as_str().context("readback fleet plan")?);
    let cycle = fleet_plan
        .parent()
        .and_then(Path::parent)
        .context("readback cycle namespace")?;
    ensure!(
        c.accepted_fleet.path.parent()
            == Some(Path::new(
                "/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"
            ))
            && cycle.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2"
                ))
            && c.routine_completion.path == cycle.join("completion.json")
            && c.status_fleet.path == cycle.join("public198-provisional-fleet.json")
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && fleet["sampled_at_utc"] == *sample
            && fleet["observer_receipt"] == json!(p.observer.path)
            && fleet["observer_sha256"] == p.observer.sha256
            && completion["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && completion["sampled_at_utc"] == *sample
            && completion["fleet"] == json!(c.accepted_fleet)
            && completion["observer"] == json!(p.observer)
            && completion["cohort191_delivery"]["event"] == json!(c.accepted_event)
            && completion["cohort191_delivery"]["status_publications"]
                .as_array()
                .is_some_and(|entries| entries
                    .iter()
                    .filter(|b| **b == json!(c.previous_status_publication))
                    .count()
                    == 1)
            && status_fleet["schema"] == fleet["schema"]
            && status_fleet["sampled_at_utc"] == *sample
            && status_fleet["observer_receipt"] == fleet["observer_receipt"]
            && status_fleet["observer_sha256"] == fleet["observer_sha256"]
            && status_fleet["plan"] == fleet["plan"]
            && status_fleet["plan_sha256"] == fleet["plan_sha256"]
            && clock["observer"] == json!(p.observer)
            && clock["terminal"] == json!(p.native_terminal_proof)
            && clock["resource_samples_taken"] == 0
            && clock["publication_authorized"] == false
            && clock["r2_mutations"] == false
            && p.native_pending_proof.is_none(),
        "readback clock does not bind the accepted fleet/completion"
    );
    let claims = fleet["active"]
        .as_array()
        .context("readback accepted claim census")?;
    ensure!(
        claims
            .iter()
            .filter(|r| r["epoch"] == c.epoch
                && r["phase"] == "cohort191-delivery"
                && r["expected_invocation_id"] == "0defba8ed0844040a2601c68d79060b2"
                && r["evidence"]
                    .as_array()
                    .is_some_and(|a| a.contains(&json!(c.accepted_event))))
            .count()
            == 1,
        "readback event is absent from the accepted fleet claim"
    );
    ensure!(
        status_fleet["active"]
            .as_array()
            .is_some_and(|claims| claims
                .iter()
                .filter(|r| r["epoch"] == c.epoch
                    && r["phase"] == "cohort191-delivery"
                    && r["expected_invocation_id"] == "0defba8ed0844040a2601c68d79060b2"
                    && r["evidence"]
                        .as_array()
                        .is_some_and(|a| a.contains(&json!(c.accepted_event))))
                .count()
                == 1),
        "readback publication fleet does not bind the accepted native event"
    );
    validate_event(&accepted, resource)?;
    ensure!(
        accepted["observer"] == json!(p.observer)
            && accepted["native_event_clock"].is_null()
            && accepted["native_terminal_proof"] == json!(p.native_terminal_proof),
        "readback accepted event changed resource or origin"
    );
    let old_state = bound(
        &serde_json::from_value::<Bound>(accepted["queue"]["state"].clone())?,
        true,
    )?;
    let current_binding = p.queue.as_ref().context("readback native queue missing")?;
    let state = bound(&current_binding.state, true)?;
    ensure!(
        clock["queue_state"] == json!(current_binding.state)
            && clock["queue_plan"] == json!(current_binding.plan)
            && accepted["queue"]["plan"] == json!(current_binding.plan)
            && clock["queue_invocation_id"] == state["invocation_id"]
            && state["invocation_id"] == old_state["invocation_id"]
            && state["invocation_id"] == "0defba8ed0844040a2601c68d79060b2"
            && state["status"] == "managing"
            && old_state["status"] == "managing"
            && state["revision"]
                .as_u64()
                .zip(old_state["revision"].as_u64())
                .is_some_and(|(new, old)| new > old)
            && state["updated_unix_millis"]
                .as_u64()
                .is_some_and(|n| event.checked_mul(1000).is_some_and(|end| n <= end))
            && state["plan"] == old_state["plan"],
        "readback queue ownership changed"
    );
    same_owner(row(&old_state, c.epoch)?, row(&state, c.epoch)?)?;
    for other in [191, 192, 193, 194].into_iter().filter(|e| *e != c.epoch) {
        ensure!(
            row(&old_state, other)? == row(&state, other)?,
            "another delivery phase changed during readback handoff"
        );
    }
    let marker = bound(&c.readback_start_journal, true)?;
    marker_shape(&marker, c.epoch, row(&old_state, c.epoch)?, resource, event)?;
    authenticate_marker(&marker)?;
    previous_shape(
        &bound(&c.previous_status_publication, false)?,
        &c,
        observer,
        &json!(p.observer),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn before() -> Value {
        json!({"epoch":191,"stage":"upload","archive_sha256":"archive","archive_length":1000,
            "started_unix_seconds":90,"full_receipt":"full","plugin_receipt":"plugin",
            "task_owner":{"unit":"uploader.service","invocation_id":"actual-iid","pid":17,"start_ticks":42,
                "program":{"path":"/tools/r2","sha256":"program"}}})
    }
    #[test]
    fn readback_cannot_change_owner_receipts_archive_or_original_clock() {
        let old = before();
        let mut current = old.clone();
        current["stage"] = json!("readback");
        same_owner(&old, &current).unwrap();
        for (key, value) in [
            ("task_owner", Value::Null),
            ("full_receipt", json!("other")),
            ("plugin_receipt", json!("other")),
            ("archive_length", json!(1001)),
            ("archive_sha256", json!("other")),
            ("started_unix_seconds", json!(91)),
            ("stage", json!("source-revalidation")),
        ] {
            let mut changed = current.clone();
            changed[key] = value;
            assert!(same_owner(&old, &changed).is_err(), "{key}");
        }
        let mut replacement = current.clone();
        replacement["task_owner"]["invocation_id"] = json!("replacement");
        assert!(same_owner(&old, &replacement).is_err());
    }
    #[test]
    fn marker_must_be_original_same_pid_start_after_the_resource_sample() {
        let message = json!({"event":"r2-readback-start","key":"epoch-191.jet","expected_sha256":"archive",
            "expected_etag":"etag","total_bytes":1000,"hashed_bytes":0,"elapsed_millis":0,"whole_file_sha256_verified":false});
        let marker = json!({"MESSAGE":message.to_string(),"_SYSTEMD_UNIT":"uploader.service",
            "_SYSTEMD_INVOCATION_ID":"actual-iid","_PID":"17","_UID":"0","_EXE":"/tools/r2",
            "__CURSOR":"native-cursor","__REALTIME_TIMESTAMP":"101500000"});
        marker_shape(&marker, 191, &before(), 100, 102).unwrap();
        for key in [
            "_SYSTEMD_UNIT",
            "_SYSTEMD_INVOCATION_ID",
            "_PID",
            "_UID",
            "_EXE",
            "__CURSOR",
        ] {
            let mut changed = marker.clone();
            changed[key] = json!("");
            assert!(
                marker_shape(&changed, 191, &before(), 100, 102).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("whole_file_sha256_verified", json!(true)),
            ("hashed_bytes", json!(1)),
            ("expected_sha256", json!("foreign")),
            ("expected_etag", json!("")),
            ("event", json!("r2-readback-verified")),
            ("total_bytes", json!(1001)),
        ] {
            let mut changed = marker.clone();
            let mut bad = message.clone();
            bad[key] = value;
            changed["MESSAGE"] = json!(bad.to_string());
            assert!(
                marker_shape(&changed, 191, &before(), 100, 102).is_err(),
                "{key}"
            );
        }
        assert!(marker_shape(&marker, 192, &before(), 100, 102).is_err());
        assert!(marker_shape(&marker, 191, &before(), 102, 103).is_err());
        assert!(marker_shape(&marker, 191, &before(), 100, 101).is_err());
    }
    #[test]
    fn prior_upload_must_belong_to_exact_resource_frame_and_original_queue() {
        let c = Config {
            epoch: 191,
            accepted_fleet: Bound {
                path: "/fleet.json".into(),
                sha256: "fleet".into(),
            },
            status_fleet: Bound {
                path: "/status-fleet.json".into(),
                sha256: "status-fleet".into(),
            },
            routine_completion: Bound {
                path: "/completion".into(),
                sha256: "completion".into(),
            },
            accepted_event: Bound {
                path: "/event".into(),
                sha256: "event".into(),
            },
            previous_status_publication: Bound {
                path: Path::new(STATUS_DIRECTORY).join("receipt.json"),
                sha256: "prior".into(),
            },
            readback_start_journal: Bound {
                path: "/marker".into(),
                sha256: "marker".into(),
            },
        };
        let observer = json!({"recorded_at_utc":"2026-10-24T09:16:00Z"});
        let binding = json!({"path":"/observer.json","sha256":"observer"});
        let prior = json!({"schema":PIPELINE_STATUS_RECEIPT_SCHEMA,"epoch":191,"authenticated_readback":true,
            "observer_receipt":"/observer.json","observer_receipt_sha256":"observer",
            "status":{"epoch":191,"phase":"upload","sampled_at_utc":observer["recorded_at_utc"]},
            "pipeline_binding":{"unit":queue::UNIT,"invocation_id":"0defba8ed0844040a2601c68d79060b2",
                "claim_phase":"cohort191-delivery","origin_unit":UNIT,"origin_invocation_id":IID,
                "fleet_path":"/status-fleet.json","fleet_sha256":"status-fleet"}});
        previous_shape(&prior, &c, &observer, &binding).unwrap();
        for pointer in [
            "/epoch",
            "/authenticated_readback",
            "/observer_receipt_sha256",
            "/status/phase",
            "/status/sampled_at_utc",
            "/pipeline_binding/invocation_id",
            "/pipeline_binding/fleet_sha256",
            "/pipeline_binding/fleet_path",
            "/pipeline_binding/origin_invocation_id",
        ] {
            let mut changed = prior.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(
                previous_shape(&changed, &c, &observer, &binding).is_err(),
                "{pointer}"
            );
        }
        assert!(
            config(&json!({"schema":"jetstreamer-cohort191-native-handoff-clock-v2"}))
                .unwrap()
                .is_none()
        );
    }
}
