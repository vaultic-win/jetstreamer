//! Completed native-input proof, never entry replay or launch authority.
use super::*;
const IID: &str = "504e627aed934e59baba97dcdf10cf4c";
const UNIT: &str = "archive-223-warmup-snapshot-actual-v1.service";
const INIT: &str = "initialized slot=96335538 last_blockhash=9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa next_write_version=105933183112";
const CHECKPOINT: &str = "checkpoint slot=96335538 bank_hash=8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F accounts_hash=Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE last_blockhash=9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa capitalization=503889539326183230 transactions=27822879094 tick_height=6165474496 complete=true";
fn validate(result: &Value, journal: &Value) -> Result<Value> {
    ensure!(
        result["schema"] == "jetstreamer-private-epoch223-warmup-v1625-ram-snapshot-result-v1"
            && result["invocation_id"] == IID
            && result["child_success"] == true
            && result["child_exit_code"] == 0
            && result["exact_ignored_test_count"] == 2
            && result["elapsed_millis"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 1_800_000)
            && result.get("trip").is_some_and(Value::is_null)
            && result
                .get("resource_capture_error")
                .is_some_and(Value::is_null),
        "cold223 input result differs"
    );
    for key in [
        "entry_replay",
        "full_peak_qualified",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(result[key] == false, "input test grants authority");
    }
    let rows = journal.as_array().context("cold223 journal array")?;
    ensure!(!rows.is_empty() && rows.len() <= 4096, "journal bounds");
    let mut markers = [None; 4];
    let mut previous_clock = 0u64;
    for (index, row) in rows.iter().enumerate() {
        let message = row["MESSAGE"].as_str().context("journal message")?;
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("journal clock")?
            .parse::<u64>()?;
        ensure!(clock >= previous_clock, "journal clock rollback");
        previous_clock = clock;
        let marker = if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == UNIT && row["INVOCATION_ID"] == IID,
                "foreign manager record"
            );
            ensure!(
                !message.contains("Failed")
                    && !message.contains("failed")
                    && !message.contains("Main process exited"),
                "manager failure"
            );
            (message == format!("{UNIT}: Deactivated successfully.")).then_some(3)
        } else {
            ensure!(
                row["_SYSTEMD_UNIT"] == UNIT && row["_SYSTEMD_INVOCATION_ID"] == IID,
                "foreign child record"
            );
            if message.ends_with(INIT) {
                Some(0)
            } else if message.starts_with("checkpoint slot=") {
                ensure!(message == CHECKPOINT, "canonical checkpoint differs");
                Some(1)
            } else if message.starts_with("test result:") {
                ensure!(
                    message.starts_with(
                        "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; "
                    ),
                    "test count differs"
                );
                Some(2)
            } else {
                None
            }
        };
        if let Some(marker) = marker {
            ensure!(markers[marker].replace(index).is_none(), "duplicate marker");
        }
    }
    let positions = markers
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .context("missing input/terminal proof")?;
    ensure!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "completion order differs"
    );
    Ok(
        json!({"slot":96_335_538u64,"bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F",
        "accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE",
        "last_blockhash":"9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa",
        "next_write_version":105_933_183_112u64,"capitalization":503_889_539_326_183_230u64,
        "transaction_count":27_822_879_094u64,"tick_height":6_165_474_496u64,"slot_complete":true}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    result: BoundFile,
    journal: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-warmup223-input")?;
    let spec: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        spec.schema == "jetstreamer-cold223-input-capture-spec-v1"
            && spec.result.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-warmup-actual-v1/result.json"
                )
            && spec.result.sha256
                == "f873da7a9b4671100c382dfeb8d2600824087ec3758b9f0ffbdeb79ccdf79619"
            && spec.journal.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-cycle314-native223-passed-v1/native223-completion-journal.json"
                )
            && spec.journal.sha256
                == "9828dbf7917f109ada963d9229f5202b26464fb95848ae745d4df54b0ce55dbb"
            && spec.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && spec
                .output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-cold223-input-proof-")),
        "capture scope differs"
    );
    let checkpoint = validate(&bound_json(&spec.result)?, &bound_json(&spec.journal)?)?;
    private157::immutable_receipt(
        &spec.output_directory.join("input-proof.json"),
        &json!({
        "schema":"jetstreamer-cold223-input-proof-v1","epoch":223,"unit":UNIT,"invocation_id":IID,
        "spec":private157::binding(&binding),"result":private157::binding(&spec.result),
        "journal":private157::binding(&spec.journal),"self_sha256":self_sha,"checkpoint":checkpoint,
        "native_input_qualified":true,"entry_replay":false,"repair_closed":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,
        "remote_mutations":false,"resource_observation_performed":false}),
    )?;
    println!("cold223 input proof captured; no replay or publication authority");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let result = json!({"schema":"jetstreamer-private-epoch223-warmup-v1625-ram-snapshot-result-v1",
            "invocation_id":IID,"child_success":true,"child_exit_code":0,"exact_ignored_test_count":2,"elapsed_millis":1_656_520,
            "trip":null,"resource_capture_error":null,"entry_replay":false,"full_peak_qualified":false,
            "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let child = |message: &str, clock: &str| json!({"_PID":"42","_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":IID,"MESSAGE":message,"__REALTIME_TIMESTAMP":clock});
        let journal = json!([child(INIT,"1"),child(CHECKPOINT,"2"),child("test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 63 filtered out; finished in 1655.88s","3"),
            {"_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE":format!("{UNIT}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"4"}]);
        (result, journal)
    }
    #[test]
    fn exact_checkpoint_is_lossless_and_requires_ordered_clean_terminal() {
        let (result, journal) = fixture();
        let checkpoint = validate(&result, &journal).unwrap();
        assert_eq!(
            checkpoint["capitalization"].as_u64(),
            Some(503_889_539_326_183_230)
        );
        assert!(
            serde_json::to_string(&checkpoint)
                .unwrap()
                .contains("503889539326183230")
        );
        for index in 0..4 {
            let mut bad = journal.clone();
            bad.as_array_mut().unwrap().remove(index);
            assert!(validate(&result, &bad).is_err());
        }
        let mut bad = journal.clone();
        bad[1]["MESSAGE"] = json!(CHECKPOINT.replace("503889539326183230", "503889539326183232"));
        assert!(validate(&result, &bad).is_err());
        let mut bad = journal.clone();
        bad.as_array_mut().unwrap().swap(1, 2);
        assert!(validate(&result, &bad).is_err());
    }
    #[test]
    fn foreign_failed_or_entry_replay_evidence_cannot_qualify_inputs() {
        let (result, journal) = fixture();
        for (key, value) in [
            ("child_success", json!(false)),
            ("entry_replay", json!(true)),
            ("trip", json!("timeout")),
            ("exact_ignored_test_count", json!(0)),
        ] {
            let mut bad = result.clone();
            bad[key] = value;
            assert!(validate(&bad, &journal).is_err());
        }
        let mut bad = journal.clone();
        bad[3]["INVOCATION_ID"] = json!("a".repeat(32));
        assert!(validate(&result, &bad).is_err());
    }
}
