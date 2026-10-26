//! Compare complete terminal observations by parsed content, retaining each
//! original byte stream and digest as separate authenticated capture evidence.
use super::*;
const SNAPSHOT: &str = "jetstreamer-singleton209-terminal-snapshot-v1";
const MANAGER_FIELDS: [&str; 12] = [
    "Id",
    "LoadState",
    "Type",
    "ActiveState",
    "SubState",
    "InvocationID",
    "NRestarts",
    "Result",
    "ExecMainStatus",
    "ExecStart",
    "ControlGroup",
    "MainPID",
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: String,
    invocation_id: String,
    manager: BTreeMap<String, String>,
    events: Vec<Value>,
    journal_rows: Vec<Value>,
    journal_raw: String,
    journal_sha256: String,
}
fn validate(value: &Value) -> Result<Snapshot> {
    let s: Snapshot = serde_json::from_value(value.clone())?;
    ensure!(
        s.schema == SNAPSHOT && is_lower_hex(&s.invocation_id, 32),
        "209 terminal snapshot schema or original IID differs"
    );
    ensure!(
        s.manager
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BTreeSet::from(MANAGER_FIELDS),
        "209 terminal snapshot manager fields are missing or unknown"
    );
    let p = &s.manager;
    ensure!(
        p["Id"] == c::UNIT
            && p["LoadState"] == "loaded"
            && p["MainPID"] == "0"
            && p["NRestarts"] == "0"
            && (p["InvocationID"] == s.invocation_id || p["InvocationID"].is_empty())
            && p["ActiveState"] == "inactive"
            && p["SubState"] == "dead"
            && p["Result"] == "success"
            && p["ExecMainStatus"] == "0"
            && c::same_command(&json!(p["ExecStart"])),
        "209 terminal snapshot lost its exact successful source owner"
    );
    ensure!(
        !s.journal_raw.is_empty()
            && s.journal_raw.len() <= 2 << 20
            && is_lower_hex(&s.journal_sha256, 64)
            && hex_lower(&Sha256::digest(s.journal_raw.as_bytes())) == s.journal_sha256,
        "209 terminal snapshot raw journal hash or bound differs"
    );
    let parsed = serde_json::Deserializer::from_str(&s.journal_raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        parsed == s.journal_rows && !s.journal_rows.is_empty() && s.journal_rows.len() < 256,
        "209 terminal snapshot full parsed history differs from raw journal"
    );
    let mut cursors = BTreeSet::new();
    let mut last = 0u64;
    for row in &s.journal_rows {
        ensure!(
            row.is_object() && row["_PID"] == "1" && row["_UID"] == "0" && row["UNIT"] == c::UNIT,
            "209 terminal snapshot contains a foreign or malformed manager row"
        );
        let cursor = row["__CURSOR"]
            .as_str()
            .context("209 terminal snapshot cursor missing")?;
        let time = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("209 terminal snapshot row time missing")?
            .parse::<u64>()?;
        ensure!(
            !cursor.is_empty()
                && cursors.insert(cursor)
                && time >= last
                && row["MESSAGE"].as_str().is_some(),
            "209 terminal snapshot repeats/reorders or malforms a manager row"
        );
        last = time;
    }
    ensure!(
        terminal_history(&s.journal_rows, &s.invocation_id)? == s.events,
        "209 terminal snapshot selected events differ from complete history"
    );
    Ok(s)
}
pub(super) fn capture(manager: Value, rows: Vec<Value>, raw: &[u8], iid: &str) -> Result<Value> {
    let selected = terminal_history(&rows, iid)?;
    let value = json!({"schema":SNAPSHOT,"invocation_id":iid,"manager":manager,"events":selected,"journal_rows":rows,
        "journal_raw":std::str::from_utf8(raw)?,"journal_sha256":hex_lower(&Sha256::digest(raw))});
    validate(&value)?;
    Ok(value)
}
pub(in crate::fleet) fn same_source_terminal(before: &Value, after: &Value) -> Result<()> {
    let a = validate(before)?;
    let b = validate(after)?;
    ensure!(
        a.invocation_id == b.invocation_id
            && a.manager == b.manager
            && a.events == b.events
            && a.journal_rows == b.journal_rows,
        "209 terminal source owner or complete parsed journal changed between captures"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    const A: &str = include_str!("fixtures/terminal-manager-key-order-a.jsonl");
    const B: &str = include_str!("fixtures/terminal-manager-key-order-b.jsonl");
    fn snapshot(raw: &str) -> Value {
        let rows = serde_json::Deserializer::from_str(raw)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        let iid = rows[0]["INVOCATION_ID"].as_str().unwrap();
        let manager = json!({"Id":c::UNIT,"LoadState":"loaded","Type":"exec","ActiveState":"inactive","SubState":"dead","InvocationID":iid,"NRestarts":"0","Result":"success","ExecMainStatus":"0","ExecStart":format!("{} ; ignore_errors=no }}", c::command()),"ControlGroup":"","MainPID":"0"});
        capture(manager, rows.clone(), raw.as_bytes(), iid).unwrap()
    }
    fn rebind_raw(v: &mut Value) {
        let raw = v["journal_rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect::<String>();
        v["journal_sha256"] = json!(hex_lower(&Sha256::digest(raw.as_bytes())));
        v["journal_raw"] = json!(raw);
    }
    #[test]
    fn source_terminal_semantics_accept_actual_manager_key_order_permutations_with_both_raw_hashes()
    {
        let a = snapshot(A);
        let b = snapshot(B);
        assert_ne!(a["journal_sha256"], b["journal_sha256"]);
        assert_eq!(a["journal_rows"], b["journal_rows"]);
        assert_eq!(a["journal_rows"].as_array().unwrap().len(), 4);
        same_source_terminal(&a, &b).unwrap();
        assert_eq!(
            a["journal_sha256"],
            "dd819c6523d8a0204206192f4cd44bb4f0c8425e424dc920e98409cf0f0c3460"
        );
        assert_eq!(
            b["journal_sha256"],
            "75dc43d91d20b58a62b6902bd60ddce78b60175dadc9d594dea4c1f31cacfe8e"
        );
    }
    #[test]
    fn source_terminal_semantics_reject_changed_extra_missing_and_reordered_complete_rows() {
        let a = snapshot(A);
        let mut changed = a.clone();
        changed["journal_rows"][3]["MESSAGE"] = json!("different resource record");
        rebind_raw(&mut changed);
        assert!(same_source_terminal(&a, &changed).is_err());
        let mut changed = a.clone();
        changed["journal_rows"][0]["extra"] = json!("new manager metadata");
        rebind_raw(&mut changed);
        assert!(same_source_terminal(&a, &changed).is_err());
        let mut changed = a.clone();
        let row = changed["journal_rows"][3].clone();
        changed["journal_rows"].as_array_mut().unwrap().push(row);
        rebind_raw(&mut changed);
        assert!(same_source_terminal(&a, &changed).is_err());
        let mut changed = a.clone();
        changed["journal_rows"].as_array_mut().unwrap().remove(3);
        rebind_raw(&mut changed);
        assert!(same_source_terminal(&a, &changed).is_err());
        let mut changed = a.clone();
        changed["journal_rows"].as_array_mut().unwrap().swap(0, 1);
        rebind_raw(&mut changed);
        assert!(same_source_terminal(&a, &changed).is_err());
        let mut changed = a.clone();
        changed["events"].as_array_mut().unwrap().reverse();
        assert!(same_source_terminal(&a, &changed).is_err());
    }
    #[test]
    fn source_terminal_semantics_reject_owner_failure_restart_hash_and_snapshot_shape_changes() {
        let a = snapshot(A);
        for (key, value) in [
            ("InvocationID", "b".repeat(32)),
            ("MainPID", "123".into()),
            ("NRestarts", "1".into()),
            ("Result", "failed".into()),
            ("ExecMainStatus", "1".into()),
            ("ControlGroup", "/foreign".into()),
            ("ExecStart", "foreign command".into()),
        ] {
            let mut bad = a.clone();
            bad["manager"][key] = json!(value);
            assert!(same_source_terminal(&a, &bad).is_err(), "{key}");
        }
        for field in [
            "schema",
            "invocation_id",
            "manager",
            "events",
            "journal_rows",
            "journal_raw",
            "journal_sha256",
        ] {
            let mut bad = a.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(same_source_terminal(&a, &bad).is_err(), "{field}");
            let mut bad = a.clone();
            bad[field] = Value::Null;
            assert!(same_source_terminal(&a, &bad).is_err(), "{field}");
        }
        for hash in ["", "bad", &"A".repeat(64), &"0".repeat(64)] {
            let mut bad = a.clone();
            bad["journal_sha256"] = json!(hash);
            assert!(same_source_terminal(&a, &bad).is_err());
        }
        let mut bad = a.clone();
        bad["unknown"] = json!(true);
        assert!(same_source_terminal(&a, &bad).is_err());
        let mut bad = a.clone();
        bad["manager"]["unknown"] = json!("value");
        assert!(same_source_terminal(&a, &bad).is_err());
        let mut bad = a.clone();
        bad["manager"].as_object_mut().unwrap().remove("Type");
        assert!(same_source_terminal(&a, &bad).is_err());
        let mut bad = a.clone();
        bad["journal_raw"] = json!("malformed");
        bad["journal_sha256"] = json!(hex_lower(&Sha256::digest(b"malformed")));
        assert!(same_source_terminal(&a, &bad).is_err());
    }
}
