// Pure validation shared by the separate full-root producer and its issuer.
// Inputs are actual immutable captured metadata; this module emits no proof.
use serde_json::Value;

pub fn validate(
    proof: &Value,
    task: &Value,
    result: &Value,
    journal: &[u8],
    qualification: &Value,
    capture_spec: &Value,
) -> Result<(), String> {
    let require = |ok: bool, message: &str| if ok { Ok(()) } else { Err(message.to_owned()) };
    let actor = &task["actor"];
    let unit = actor["unit"].as_str().ok_or("bracket task unit missing")?;
    let iid = actor["invocation_id"]
        .as_str()
        .ok_or("bracket task invocation missing")?;
    require(
        unit.starts_with("horizon-qualify-223-demotion-bracket-")
            && unit.ends_with(".service")
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && iid != "0".repeat(32),
        "prior bracket task scope differs",
    )?;
    require(
        proof["schema"] == "jetstreamer-epoch223-full-root-prior-bracket-proof-v1"
            && capture_spec["schema"]
                == "jetstreamer-epoch223-full-root-prior-bracket-capture-spec-v1"
            && proof["issuer"]["unit"] == capture_spec["issuer_unit"]
            && task["schema"] == "jetstreamer-epoch223-demotion-active-task-v1"
            && task["job_kind"] == "bracket"
            && task["epoch"] == 223
            && proof["original_start_unix_millis"] == 1792806478075u64
            && task["original_start_unix_millis"] == proof["original_start_unix_millis"]
            && proof["task"] == capture_spec["task"]
            && proof["result"] == capture_spec["result"]
            && proof["journal"] == capture_spec["journal"]
            && proof["origin_clock"] == capture_spec["origin_clock"]
            && proof["role_qualification"] == capture_spec["role_qualification"]
            && proof["captured_unix_millis"]
                .as_u64()
                .is_some_and(|n| n > 1792806478075)
            && proof["publication_authorized"] == false
            && proof["r2_mutations"] == false,
        "prior bracket proof/capture/original clock differs",
    )?;
    require(
        qualification["schema"] == "jetstreamer-epoch223-full-root-demotion-role-qualification-v1"
            && qualification["executable_sha256"] == proof["issuer"]["executable"]["sha256"]
            && qualification["bracket_proof_capture_qualified"] == true,
        "actual prior bracket capture helper is not qualified",
    )?;
    let manager = &proof["terminal_manager"];
    require(
        manager["Id"] == unit
            && manager["InvocationID"] == iid
            && manager["ActiveState"] == "inactive"
            && matches!(manager["SubState"].as_str(), Some("dead" | "exited"))
            && manager["MainPID"] == "0"
            && manager["NRestarts"] == "0"
            && manager["Result"] == "success"
            && manager["ExecMainStatus"] == "0",
        "prior bracket lacks its actual clean terminal manager frame",
    )?;
    let manifest = &result["producer_segment_manifest"];
    require(
        result["schema"] == "jetstreamer-private-epoch223-demotion-bracket-result-v1"
            && result["epoch"] == 223
            && result["unit"] == unit
            && result["invocation_id"] == iid
            && result["runner_sha256"] == actor["executable"]["sha256"]
            && result["worker_sha256"]
                == "0f8cc22ad76365f4feb1ef328ce77babbb5242a9b5edb38e9bd076528bc530c0"
            && result["snapshot_sha256"]
                == "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
            && result["target_slot"] == 96544588u64
            && result["terminal_root_slot"] == 96544588u64
            && result["success"] == true
            && result["error"].is_null()
            && result["natural_parent_completion_required"] == true
            && result["child_return_code"] == 0
            && result["external_signal"] == 0
            && result["archive_length"].as_u64().is_some_and(|n| n > 0)
            && manifest["worker_executable_sha256"] == result["worker_sha256"]
            && manifest["runtime"]["runtime_profile"]
                == "solana-v1.6.20-epoch223-called-program-demotion-candidate"
            && manifest["bootstrap"]["slot"] == 96335538u64
            && manifest["bootstrap"]["bank_hash"] == "8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"
            && manifest["output_slot_start"] == 96336000u64
            && manifest["output_slot_count"] == 208589u64
            && manifest["terminal"]["slot"] == 96544588u64
            && manifest["terminal"]["slot_complete"] == true,
        "prior bracket did not naturally complete the exact sealed semantic comparison",
    )?;
    for field in [
        "canonical_prefix_independently_qualified",
        "full_cold_epoch_peak_qualified",
        "ordinary_replay_authorized",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        require(
            result["authority"][field] == false,
            "prior bracket cannot carry root/epoch/publication authority",
        )?;
    }
    journal_events(journal, unit, iid)
}
fn journal_events(journal: &[u8], unit: &str, iid: &str) -> Result<(), String> {
    let require = |ok: bool, message: &str| if ok { Ok(()) } else { Err(message.to_owned()) };
    let events = [
        "epoch223 demotion real Bank verified slot=96544586 bank_hash=3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso",
        "epoch223 demotion exact native wire success slot=96544587 transaction_index=432",
        "epoch223 demotion real Bank verified slot=96544587 bank_hash=5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7",
        "epoch223 demotion exact native wire success slot=96544588 transaction_index=0",
        "epoch223 demotion bracket verified terminal=96544588 complete=true publication_authorized=false",
    ];
    let mut positions = [None; 5];
    let (mut started, mut terminal) = (None, None);
    let mut latest_iid = None;
    for (index, row) in serde_json::Deserializer::from_slice(journal)
        .into_iter::<Value>()
        .enumerate()
    {
        let row = row.map_err(|e| e.to_string())?;
        if row["_PID"] == "1" && row["_UID"] == "0" && row["UNIT"] == unit {
            latest_iid = Some(row["INVOCATION_ID"].as_str().unwrap_or("").to_owned());
        }
        if row["_PID"] == "1"
            && row["_UID"] == "0"
            && row["UNIT"] == unit
            && row["INVOCATION_ID"] == iid
        {
            let message = row["MESSAGE"]
                .as_str()
                .ok_or("bracket PID1 message absent")?;
            if message.starts_with(&format!("Started {unit} - ")) {
                require(
                    started.replace(index).is_none(),
                    "duplicate bracket PID1 start",
                )?;
            }
            if message == format!("{unit}: Deactivated successfully.") {
                require(
                    terminal.replace(index).is_none(),
                    "duplicate bracket terminal",
                )?;
            }
            require(
                !message.contains("Failed")
                    && !message.contains("Main process exited")
                    && !message.contains("Scheduled restart job"),
                "bracket manager failure/restart",
            )?;
        }
        if row["_SYSTEMD_UNIT"] != unit || row["_SYSTEMD_INVOCATION_ID"] != iid {
            continue;
        }
        let message = row["MESSAGE"].as_str().unwrap_or("");
        if !message.contains("INFO") || !message.contains("jetstreamer_node::epoch223_demotion]") {
            continue;
        }
        for (event, position) in events.iter().zip(positions.iter_mut()) {
            if message.ends_with(event) {
                require(
                    position.replace(index).is_none(),
                    "duplicate actual bracket diagnostic",
                )?;
            }
        }
    }
    require(
        started.zip(terminal).is_some_and(|(s, t)| s < t)
            && latest_iid.as_deref() == Some(iid)
            && positions.iter().all(Option::is_some),
        "actual bracket manager history or causal observations missing",
    )?;
    let order: Vec<_> = positions.iter().map(|p| p.unwrap()).collect();
    require(
        order.windows(2).all(|p| p[0] < p[1])
            && started.unwrap() < order[0]
            && order[4] < terminal.unwrap(),
        "actual bracket causal diagnostics out of order",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn rows() -> Vec<Value> {
        let unit = "horizon-qualify-223-demotion-bracket-source-fixture.service";
        let iid = "a".repeat(32);
        let mut rows = vec![
            json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"MESSAGE":format!("Started {unit} - Source fixture.")}),
        ];
        for message in [
            "epoch223 demotion real Bank verified slot=96544586 bank_hash=3PMZX37CYLF9Ay87r1aKREnf1cZoWDLRKXRAMx5TZYso",
            "epoch223 demotion exact native wire success slot=96544587 transaction_index=432",
            "epoch223 demotion real Bank verified slot=96544587 bank_hash=5UsE976GhKUXyUyKG1tUDiN7cT2BPYvKJN7Wx1ptJHm7",
            "epoch223 demotion exact native wire success slot=96544588 transaction_index=0",
            "epoch223 demotion bracket verified terminal=96544588 complete=true publication_authorized=false",
        ] {
            rows.push(json!({"_SYSTEMD_UNIT":unit,"_SYSTEMD_INVOCATION_ID":iid,"MESSAGE":format!("[source fixture INFO jetstreamer_node::epoch223_demotion] {message}")}));
        }
        rows.push(json!({"_PID":"1","_UID":"0","UNIT":unit,"INVOCATION_ID":iid,"MESSAGE":format!("{unit}: Deactivated successfully.")}));
        rows
    }
    fn check(rows: &[Value]) -> Result<(), String> {
        let bytes = rows
            .iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        journal_events(
            bytes.as_bytes(),
            "horizon-qualify-223-demotion-bracket-source-fixture.service",
            &"a".repeat(32),
        )
    }
    #[test]
    fn prior_bracket_needs_every_real_causal_record_and_clean_ordered_manager_history() {
        let original = rows();
        check(&original).unwrap();
        for missing in 0..original.len() {
            let mut bad = original.clone();
            bad.remove(missing);
            assert!(check(&bad).is_err(), "missing {missing}");
        }
        let mut swapped = original.clone();
        swapped.swap(2, 3);
        assert!(check(&swapped).is_err());
        let mut duplicate = original.clone();
        duplicate.insert(2, original[1].clone());
        assert!(check(&duplicate).is_err());
        let mut wrong_bank = original.clone();
        wrong_bank[1]["MESSAGE"] = json!(
            "[INFO jetstreamer_node::epoch223_demotion] epoch223 demotion real Bank verified slot=96544586 bank_hash=foreign"
        );
        assert!(check(&wrong_bank).is_err());
        let mut wrong_wire = original.clone();
        wrong_wire[2]["MESSAGE"] = json!(
            "[INFO jetstreamer_node::epoch223_demotion] epoch223 demotion exact native wire success slot=96544587 transaction_index=431"
        );
        assert!(check(&wrong_wire).is_err());
        let mut wrong_iid = original.clone();
        wrong_iid[4]["_SYSTEMD_INVOCATION_ID"] = json!("b".repeat(32));
        assert!(check(&wrong_iid).is_err());
        let mut reused = original;
        let mut replacement = reused.last().unwrap().clone();
        replacement["INVOCATION_ID"] = json!("b".repeat(32));
        reused.push(replacement);
        assert!(check(&reused).is_err());
    }
}
