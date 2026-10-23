//! Independent native tuple proof. Never entry replay or epoch completion.
use super::*;
const MARKER: &str = "epoch223-v1620-native-input slot=96335538 bank_hash=8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F accounts_hash=Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE last_blockhash=9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa capitalization=503889539326183230 transaction_count=27822879094 tick_height=6165474496 next_write_version=105933183112 replay_entries=0 bootstrap_writes=0";
fn checkpoint(rows: &[Value], unit: &str, iid: &str) -> Result<Value> {
    ensure!(
        !rows.is_empty() && rows.len() <= 4096,
        "native223 proof journal bounds"
    );
    let mut markers = [None; 3];
    let mut last = 0u64;
    for (index, row) in rows.iter().enumerate() {
        let clock = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("native223 proof clock")?
            .parse::<u64>()?;
        ensure!(clock >= last, "native223 proof clock rollback");
        last = clock;
        let message = row["MESSAGE"].as_str().context("native223 proof message")?;
        let selected = if row["_PID"] == "1" {
            ensure!(
                row["UNIT"] == unit && row["INVOCATION_ID"] == iid,
                "native223 foreign manager proof"
            );
            (message == format!("{unit}: Deactivated successfully.")).then_some(2)
        } else {
            ensure!(
                row["_SYSTEMD_UNIT"] == unit && row["_SYSTEMD_INVOCATION_ID"] == iid,
                "native223 foreign child proof"
            );
            if message.contains("epoch223-v1620-native-input ") {
                ensure!(
                    message.ends_with(MARKER),
                    "native223 canonical tuple differs"
                );
                Some(0)
            } else if message.starts_with("test result:") {
                ensure!(
                    message.starts_with(
                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                    ),
                    "native223 actual test count/outcome differs"
                );
                Some(1)
            } else {
                None
            }
        };
        if let Some(selected) = selected {
            ensure!(
                markers[selected].replace(index).is_none(),
                "native223 duplicate qualification marker"
            );
        }
    }
    let positions = markers
        .into_iter()
        .collect::<Option<Vec<_>>>()
        .context("native223 tuple/test/clean-terminal proof missing")?;
    ensure!(
        positions.windows(2).all(|w| w[0] < w[1]),
        "native223 qualification order differs"
    );
    Ok(
        json!({"slot":96_335_538u64,"bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F",
        "accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE","last_blockhash":"9cdE7Epzr7jcLCz8Ke2Lndf8DBqb3DJmxedKaKuCJHaa",
        "capitalization":503_889_539_326_183_230u64,"transaction_count":27_822_879_094u64,"tick_height":6_165_474_496u64,
        "next_write_version":105_933_183_112u64,"slot_complete":true,"bootstrap_writes":0,"replay_entries":0}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    terminal_event: BoundFile,
    output_directory: PathBuf,
}
pub(in crate::fleet) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-native223-input")?;
    let spec: Spec = serde_json::from_value(bound_json(&binding)?)?;
    ensure!(
        spec.schema == "jetstreamer-native223-input-capture-spec-v1"
            && spec.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && spec
                .output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-native223-input-proof-")),
        "native223 input proof scope"
    );
    let event = bound_json(&spec.terminal_event)?;
    let (profile, iid, success, _) = native20_event::terminal_proof(&event)?;
    ensure!(success, "native223 input did not terminate successfully");
    let journal: BoundFile = serde_json::from_value(event["journal"].clone())?;
    let bytes = read_stable_bounded(&journal.path, 16 << 20, "native223 qualification journal")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == journal.sha256,
        "native223 qualification journal digest"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let checkpoint = checkpoint(&rows, profile.unit, &iid)?;
    let output = spec.output_directory.join("input-proof.json");
    private157::immutable_receipt(
        &output,
        &json!({"schema":"jetstreamer-native223-cold-input-proof-v1","epoch":223,
        "unit":profile.unit,"invocation_id":iid,"runtime_profile":"solana-v1.6.20","harness_sha256":profile.test_sha,
        "spec":private157::binding(&binding),"terminal_event":private157::binding(&spec.terminal_event),"self_sha256":self_sha,
        "checkpoint":checkpoint,"native_input_qualified":true,"entry_replay":false,"canonical_prefix_qualified":false,
        "native_restart_qualified":false,"assembly_qualified":false,"repair_closed":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"resource_samples_taken":0}),
    )?;
    println!("{}", output.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<Value> {
        let unit = NATIVE20_RELEASE.unit;
        let iid = "c".repeat(32);
        let child = |message: &str, clock: &str| json!({"_PID":"42","_SYSTEMD_UNIT":unit,"_SYSTEMD_INVOCATION_ID":iid,"MESSAGE":message,"__REALTIME_TIMESTAMP":clock});
        vec![
            child(MARKER, "1"),
            child(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 59 filtered out; finished in 12.34s",
                "2",
            ),
            json!({"_PID":"1","UNIT":unit,"INVOCATION_ID":iid,"MESSAGE":format!("{unit}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"3"}),
        ]
    }
    #[test]
    fn canonical_tuple_retains_large_consensus_integer_and_ordered_test_completion() {
        let rows = fixture();
        let iid = "c".repeat(32);
        let tuple = checkpoint(&rows, NATIVE20_RELEASE.unit, &iid).unwrap();
        assert_eq!(
            tuple["capitalization"].as_u64(),
            Some(503_889_539_326_183_230)
        );
        assert!(
            serde_json::to_string(&tuple)
                .unwrap()
                .contains("503889539326183230")
        );
        for index in 0..rows.len() {
            let mut bad = rows.clone();
            bad.remove(index);
            assert!(checkpoint(&bad, NATIVE20_RELEASE.unit, &iid).is_err());
        }
        let mut bad = rows.clone();
        bad[0]["MESSAGE"] = json!(MARKER.replace("503889539326183230", "503889539326183232"));
        assert!(checkpoint(&bad, NATIVE20_RELEASE.unit, &iid).is_err());
        let mut bad = rows.clone();
        bad.swap(0, 1);
        assert!(checkpoint(&bad, NATIVE20_RELEASE.unit, &iid).is_err());
        let mut bad = rows;
        bad[1]["MESSAGE"] =
            json!("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 60 filtered out");
        assert!(checkpoint(&bad, NATIVE20_RELEASE.unit, &iid).is_err());
    }
}
