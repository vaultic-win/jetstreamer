//! Terminal task custody, never archive completion or publication authority.
use super::*;

pub(super) fn candidate(m: &Value) -> bool {
    m["MainPID"] == "0"
        && ((m["ActiveState"] == "inactive" && m["SubState"] == "dead")
            || (m["ActiveState"] == "failed" && m["SubState"] == "failed"))
}
fn shape(l: &Value, p: &c::Plan, m: &Value) -> Result<bool> {
    let clean = m["Result"] == "success"
        && m["ExecMainStatus"] == "0"
        && m["ActiveState"] == "inactive"
        && m["SubState"] == "dead";
    ensure!(
        candidate(m)
            && m["Id"] == p.unit
            && m["LoadState"] == "loaded"
            && m["NRestarts"] == "0"
            && (clean || m["Result"] != "success")
            && (m["InvocationID"] == l["invocation_id"] || (clean && m["InvocationID"] == ""))
            && m["Result"].as_str().is_some_and(|v| !v.is_empty())
            && m["ExecMainStatus"]
                .as_str()
                .and_then(|v| v.parse::<u64>().ok())
                .is_some()
            && pipeline_status::same_exec_start(
                text(m, "ExecStart")?,
                text(&l["actor"]["manager"], "ExecStart")?
            ),
        "epoch 225 terminal task is live, replaced, restarted or ambiguous"
    );
    Ok(clean)
}
fn history(
    records: &[Value],
    unit: &str,
    iid: &str,
    clean: bool,
    result: &str,
) -> Result<Vec<Value>> {
    ensure!(
        !records.is_empty() && records.len() < 256,
        "epoch 225 terminal PID1 history empty or truncated"
    );
    let own = records
        .iter()
        .filter(|r| r["_PID"] == "1" && r["_UID"] == "0" && r["UNIT"] == unit)
        .collect::<Vec<_>>();
    let starts = own
        .iter()
        .filter(|r| {
            r["INVOCATION_ID"] == iid
                && r["MESSAGE"]
                    .as_str()
                    .is_some_and(|m| m.starts_with(&format!("Started {unit} -")))
        })
        .collect::<Vec<_>>();
    let expected = if clean {
        format!("{unit}: Deactivated successfully.")
    } else {
        format!("{unit}: Failed with result '{result}'.")
    };
    let ends = own
        .iter()
        .filter(|r| r["INVOCATION_ID"] == iid && r["MESSAGE"] == expected)
        .collect::<Vec<_>>();
    ensure!(
        starts.len() == 1 && ends.len() == 1,
        "epoch 225 terminal lacks one exact PID1 start and outcome"
    );
    let clock = |r: &Value| -> Result<u64> { Ok(text(r, "__REALTIME_TIMESTAMP")?.parse()?) };
    let started = clock(starts[0])?;
    ensure!(
        clock(ends[0])? > started
            && own
                .iter()
                .all(|r| clock(r).is_ok_and(|n| n < started || r["INVOCATION_ID"] == iid)),
        "epoch 225 terminal history is reordered or contains a replacement"
    );
    // Preserve every matching manager record, including exit-code/signal detail.
    Ok(own
        .into_iter()
        .filter(|r| r["INVOCATION_ID"] == iid)
        .cloned()
        .collect())
}
fn verified_candidate(b: &BoundFile, l: &Value, p: &c::Plan, pb: &BoundFile) -> Result<BoundFile> {
    let result = fb(&c::binding(&p.root.join("extraction.json"))?);
    let value = bound_json(&result)?;
    ensure!(
        value["schema"] == "jetstreamer-epoch225-prefix-extraction-result-v1"
            && value["launch"] == json!(b)
            && value["plan"] == json!(pb)
            && value["admission"] == l["admission"]
            && value["authority"] == c::denied()
            && value["result"]["epoch"] == 225
            && value["result"]["output_slot_count"] == 432000
            && value["result"]["source_archive_sha256"]
                == "77c0f95a020ceb6c45e323f4ce1bb48066fd0b379615bd5c9dbcb67f9082d6f9"
            && value["result"]["source_manifest_sha256"] == c::MANIFEST_SHA
            && value["result"]["source_runtime_admission"] == "candidate"
            && value["result"]["epoch226_tail_is_private"] == true
            && value["result"]["independent_output_reread_passed"] == true
            && value["result"]["full_verification_passed"] == false
            && value["result"]["current_plugin_verification_passed"] == false
            && value["result"]["publication_authorized"] == false
            && value["candidate_identity"]
                == c::identity(&fs::symlink_metadata(p.root.join("epoch-225.jet"))?),
        "epoch 225 terminal task has no unchanged private candidate evidence"
    );
    Ok(result)
}
pub(super) fn rows(
    b: &BoundFile,
    l: &Value,
    p: &c::Plan,
    pb: &BoundFile,
    manager: &Value,
) -> Result<Vec<Value>> {
    let clean = shape(l, p, manager)?;
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            &p.unit,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "epoch 225 terminal PID1 history unavailable"
    );
    let records = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let events = history(
        &records,
        &p.unit,
        text(l, "invocation_id")?,
        clean,
        text(manager, "Result")?,
    )?;
    let result = if clean {
        verified_candidate(b, l, p, pb)
    } else {
        Err(anyhow::anyhow!(
            "epoch 225 extraction terminated: result={} status={}",
            manager["Result"],
            manager["ExecMainStatus"]
        ))
    };
    ensure!(
        c::manager(&p.unit)? == *manager,
        "epoch 225 terminal owner changed during evidence capture"
    );
    Ok(build_rows(b, manager, result, events))
}

fn build_rows(
    b: &BoundFile,
    manager: &Value,
    result: Result<BoundFile>,
    events: Vec<Value>,
) -> Vec<Value> {
    let failure = result.as_ref().err().map(|e| format!("{e:#}"));
    let failed = failure.is_some();
    let result = result.ok();
    [225,226].into_iter().map(|epoch|json!({"epoch":epoch,
        "phase":if failed {"private-prefix-extraction-failed"}else{"private-prefix-extraction-complete"},
        "terminal_outcome":if failed {"failed-needs-repair"}else{"private-candidate-complete"},
        "live":false,"producer":manager,"launch":b,"result":result,"failure":failure,
        "manager_events":events,"source_must_be_retained":true,"retained226_private_slots":431465,
        "missing226_suffix_slots":535,"ordinary_replay_claim":false,
        "archive_or_sidecar_completion_claimed":false,"authority":c::denied()})).collect()
}

pub(super) fn validate_cleanup(
    row: &Value,
    current: &Value,
    owner: &(String, String),
) -> Result<()> {
    ensure!(
        row["live"] == false
            && row["archive_or_sidecar_completion_claimed"] == false
            && row["authority"] == c::denied()
            && matches!(row["epoch"].as_u64(), Some(225 | 226)),
        "foreign epoch 225 terminal status evidence"
    );
    let b: BoundFile = serde_json::from_value(row["launch"].clone())?;
    let (l, p, _, _) = launch(&b)?;
    ensure!(
        owner.0 == p.unit && owner.1 == text(&l, "invocation_id")?,
        "epoch 225 cleanup replaced the status owner"
    );
    validate_saved(row, current, &l, &p)
}
fn validate_saved(row: &Value, current: &Value, l: &Value, p: &c::Plan) -> Result<()> {
    let historical = &row["producer"];
    let clean = shape(l, p, historical)?;
    shape(l, p, current)?;
    for key in [
        "Id",
        "InvocationID",
        "MainPID",
        "NRestarts",
        "ActiveState",
        "SubState",
        "Result",
        "ExecMainStatus",
    ] {
        ensure!(
            historical[key] == current[key],
            "epoch 225 terminal owner changed: {key}"
        );
    }
    let records = row["manager_events"]
        .as_array()
        .context("epoch 225 terminal manager evidence absent")?;
    history(
        records,
        &p.unit,
        text(l, "invocation_id")?,
        clean,
        text(historical, "Result")?,
    )?;
    ensure!(
        matches!(
            row["terminal_outcome"].as_str(),
            Some("failed-needs-repair" | "private-candidate-complete")
        ),
        "epoch 225 terminal outcome absent"
    );
    if row["terminal_outcome"] == "private-candidate-complete" {
        ensure!(
            clean && !row["result"].is_null() && row["failure"].is_null(),
            "epoch 225 candidate completion lacks clean task evidence"
        );
    } else {
        ensure!(
            row["failure"].as_str().is_some_and(|v| !v.is_empty()),
            "epoch 225 failed task lost its failure detail"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(clean: bool) -> (c::Plan, Value, Value, Vec<Value>) {
        let p: c::Plan = serde_json::from_str(include_str!(
            "../../../../docs/examples/epoch225-extraction/plan.example.json"
        ))
        .unwrap();
        let iid = "a".repeat(32);
        let command = "{ path=/sealed/extractor ; argv[]=/sealed/extractor ; ignore_errors=no }";
        let l = json!({"invocation_id":iid,"actor":{"manager":{"ExecStart":command}}});
        let m = json!({"Id":p.unit,"LoadState":"loaded","MainPID":"0","NRestarts":"0",
            "InvocationID":iid,"ActiveState":if clean {"inactive"}else{"failed"},"SubState":if clean {"dead"}else{"failed"},
            "Result":if clean {"success"}else{"exit-code"},"ExecMainStatus":if clean {"0"}else{"1"},"ExecStart":command});
        let record = |at: &str, msg: String| json!({"_PID":"1","_UID":"0","UNIT":p.unit,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":at,"MESSAGE":msg});
        let records = vec![
            record("1000", format!("Started {} - Private extraction.", p.unit)),
            record(
                "2000",
                if clean {
                    format!("{}: Deactivated successfully.", p.unit)
                } else {
                    format!("{}: Failed with result 'exit-code'.", p.unit)
                },
            ),
        ];
        (p, l, m, records)
    }
    fn binding() -> BoundFile {
        BoundFile {
            path: "/sealed/launch.json".into(),
            sha256: "b".repeat(64),
        }
    }
    #[test]
    fn e225_failed_and_clean_without_candidate_tasks_remain_failed_with_both_epoch_debts() {
        for clean in [false, true] {
            let (p, l, m, records) = fixture(clean);
            assert_eq!(shape(&l, &p, &m).unwrap(), clean);
            let proof = history(
                &records,
                &p.unit,
                text(&l, "invocation_id").unwrap(),
                clean,
                text(&m, "Result").unwrap(),
            )
            .unwrap();
            let rows = build_rows(
                &binding(),
                &m,
                Err(anyhow::anyhow!(
                    "preserved exact error or missing extraction receipt"
                )),
                proof,
            );
            assert_eq!(rows.len(), 2);
            for (row, epoch) in rows.iter().zip([225, 226]) {
                assert_eq!(row["epoch"], epoch);
                assert_eq!(row["terminal_outcome"], "failed-needs-repair");
                assert_eq!(row["live"], false);
                assert_eq!(row["source_must_be_retained"], true);
                assert_eq!(row["missing226_suffix_slots"], 535);
                assert_eq!(row["archive_or_sidecar_completion_claimed"], false);
                assert_eq!(row["authority"], c::denied());
                validate_saved(row, &m, &l, &p).unwrap();
            }
        }
        let (p, l, m, records) = fixture(true);
        let proof = history(
            &records,
            &p.unit,
            text(&l, "invocation_id").unwrap(),
            true,
            "success",
        )
        .unwrap();
        let rows = build_rows(&binding(), &m, Ok(binding()), proof);
        assert_eq!(rows[0]["terminal_outcome"], "private-candidate-complete");
        assert_eq!(rows[0]["archive_or_sidecar_completion_claimed"], false);
        validate_saved(&rows[0], &m, &l, &p).unwrap();
    }
    #[test]
    fn e225_terminal_evidence_rejects_live_replaced_restarted_or_fabricated_outcomes() {
        let (p, l, m, records) = fixture(false);
        for (key, value) in [
            ("MainPID", json!("42")),
            ("InvocationID", json!("c".repeat(32))),
            ("NRestarts", json!("1")),
            ("ExecStart", json!("foreign")),
            ("Id", json!("foreign.service")),
            ("LoadState", json!("not-found")),
            ("ActiveState", json!("active")),
        ] {
            let mut bad = m.clone();
            bad[key] = value;
            assert!(shape(&l, &p, &bad).is_err(), "{key}");
        }
        let mut replaced = records.clone();
        replaced[1]["INVOCATION_ID"] = json!("c".repeat(32));
        assert!(
            history(
                &replaced,
                &p.unit,
                text(&l, "invocation_id").unwrap(),
                false,
                "exit-code"
            )
            .is_err()
        );
        let mut duplicate = records.clone();
        duplicate.push(records[1].clone());
        assert!(
            history(
                &duplicate,
                &p.unit,
                text(&l, "invocation_id").unwrap(),
                false,
                "exit-code"
            )
            .is_err()
        );
        let mut backward = records.clone();
        backward[1]["__REALTIME_TIMESTAMP"] = json!("999");
        assert!(
            history(
                &backward,
                &p.unit,
                text(&l, "invocation_id").unwrap(),
                false,
                "exit-code"
            )
            .is_err()
        );
        assert!(
            history(
                &records,
                &p.unit,
                text(&l, "invocation_id").unwrap(),
                true,
                "success"
            )
            .is_err()
        );
        let (p, l, mut clear, records) = fixture(true);
        clear["InvocationID"] = json!("");
        shape(&l, &p, &clear).unwrap();
        let row = build_rows(&binding(), &clear, Ok(binding()), records).remove(0);
        validate_saved(&row, &clear, &l, &p).unwrap();
        let mut changed = clear;
        changed["InvocationID"] = json!("d".repeat(32));
        assert!(validate_saved(&row, &changed, &l, &p).is_err());
    }
}
