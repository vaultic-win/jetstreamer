//! Accounting-only view of the exact344 sample's native227 terminal race.
//! Raw observation and host RSS stay unchanged; no released-memory/disk credit.
use super::*;
const UNIT: &str = "horizon-native-input-227-v1625-small-v2.service";
const IID: &str = "36b96647e20e41a4a82c92b77b1bb290";
const PID: u64 = 456026;
const PROOF: &str =
    "/var/lib/jetstreamer/horizon-native227-v1625-terminal-proof-small-v2/proof.json";
const PROOF_SHA: &str = "da6e00906c266f5993e0332b2abb864558db4ab4c0786d765d1828e658675d7b";
const OBSERVER: &str = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness/horizon-live-resource-sample-20261024T040300Z-diagnostics-v344.json";
const OBSERVER_SHA: &str = "7c0b389c86f2f8f360075901a954e8d40ca6692c4e0b345b6eb45fb24693c12c";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-227-v1625-native-capture-small-v2/intent.json";
const ORIGIN_SHA: &str = "0b363d7f7f63854f69d6d6681daad0205ed9f68bc395a08aa30bf1759cca1d8f";
const OLDER: &[(&str, &str)] = &[
    (
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
    (
        "horizon-singleton-209-capped-4aeca563-v1.service",
        "1bf0db73ccd44c2c90461889498d4f82",
    ),
    (
        "horizon-qualify-223-v1620-root-prefix-resource-full-v1.service",
        "e70aaf097e7c4583b216aba454145910",
    ),
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
];
fn binding(path: &str, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}
fn selected(d: &Value) -> bool {
    d["producer_unit"] == UNIT || d["observation"]["producer_after"]["unit"] == UNIT
}
fn terminal(current: &Value) -> Result<()> {
    ensure!(
        current["Id"] == UNIT
            && current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && (current["InvocationID"] == IID || current["InvocationID"] == "")
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0",
        "terminal227 observation has a live/replaced/restarted/collected owner"
    );
    Ok(())
}
fn stable_role(role: &Value, unit: &str, iid: &str) -> Result<()> {
    ensure!(
        role["unit"] == unit
            && role["invocation_id"] == iid
            && role["restarts"] == 0
            && role["active_state"] == "active"
            && role["sub_state"] == "running"
            && role["rss"]["census_stable"] == true,
        "terminal227 sample role differs"
    );
    Ok(())
}
fn older_coverage(f: &Value, o: &Value) -> Result<()> {
    let mut owners = BTreeMap::new();
    for row in f["active"]
        .as_array()
        .context("terminal227 active census")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let unit = owner["Id"].as_str().context("terminal227 active name")?;
        let iid = owner["InvocationID"]
            .as_str()
            .context("terminal227 active IID")?;
        ensure!(
            OLDER.contains(&(unit, iid))
                && owner["NRestarts"] == "0"
                && owner["ActiveState"] == "active"
                && owner["SubState"] == "running",
            "terminal227 accounting changed/hidden older owner"
        );
        if let Some(old) = owners.insert(unit.to_owned(), iid.to_owned()) {
            ensure!(old == iid, "terminal227 conflicting older owner");
        }
    }
    ensure!(
        owners.len() == OLDER.len(),
        "terminal227 older owner missing"
    );
    let mut rows = o["replays"]
        .as_array()
        .context("terminal227 replay rows")?
        .iter()
        .collect::<Vec<_>>();
    for d in o["diagnostic_replays"]
        .as_array()
        .context("terminal227 diagnostic rows")?
    {
        if d["status"] == "observed" {
            ensure!(d["error"].is_null(), "terminal227 older diagnostic error");
            rows.push(&d["observation"]);
        }
    }
    let mut seen = BTreeSet::new();
    for row in rows {
        let name = row["producer_after"]["unit"]
            .as_str()
            .context("terminal227 observed older name")?;
        let iid = owners
            .get(name)
            .context("terminal227 unaccounted other observed peer")?;
        ensure!(
            seen.insert(name.to_owned()) && row["invocation_binding_stable"] == true,
            "terminal227 duplicate/unstable older peer"
        );
        for key in ["producer_before", "producer_after"] {
            stable_role(&row[key], name, iid)?;
        }
    }
    ensure!(
        seen.len() == owners.len(),
        "terminal227 older observation missing"
    );
    Ok(())
}
fn derived(f: &Value, o: &Value, proof: &Value, current: &Value) -> Result<Value> {
    ensure!(
        f["schema"] == SCHEMA
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_receipt"] == OBSERVER
            && f["observer_sha256"] == OBSERVER_SHA
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["metadata_event"] == binding(PROOF, PROOF_SHA)
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["recorded_at_utc"] == "2026-10-24T04:03:00Z"
            && proof["schema"] == "jetstreamer-private-epoch227-v1625-native-terminal-proof-v1"
            && proof["epoch"] == 227
            && proof["unit"] == UNIT
            && proof["invocation_id"] == IID
            && proof["main_pid"] == PID
            && proof["native_input_qualified"] == true
            && proof["observer"] == binding(OBSERVER, OBSERVER_SHA)
            && proof["running_origin"] == binding(ORIGIN, ORIGIN_SHA)
            && proof["terminal_unix_microseconds"] == 1_792_814_680_290_027u64,
        "terminal227 observation is not the exact typed344 terminal transition"
    );
    native227_v1625::no_authority(proof)?;
    terminal(current)?;
    ensure!(
        utc_seconds(
            o["completed_at_utc"]
                .as_str()
                .context("terminal227 observation completion")?
        )? <= 1_792_814_680,
        "terminal227 terminal predates sampled identity"
    );
    let diags = o["diagnostic_replays"]
        .as_array()
        .context("terminal227 observed diagnostics")?;
    let selected = diags.iter().filter(|d| selected(d)).collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "terminal227 observed owner count differs"
    );
    let d = selected[0];
    let row = &d["observation"];
    ensure!(
        d["producer_unit"] == UNIT
            && d["expected_producer_invocation_id"] == IID
            && d["status"] == "observed"
            && d["error"].is_null()
            && d["native_resource_only"] == true
            && d["entry_replay"] == false
            && d["ordinary_replay_claim"] == false
            && d["range"] == "227-227"
            && row["invocation_binding_stable"] == true
            && row["resource_only"] == true
            && row["entry_replay"] == false,
        "terminal227 row is not the exact stable resource-only native observation"
    );
    for key in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        stable_role(&row[key], UNIT, IID)?;
        ensure!(
            row[key]["main_pid"] == PID,
            "terminal227 sampled PID changed"
        );
    }
    let mut view = o.clone();
    view["diagnostic_replays"]
        .as_array_mut()
        .unwrap()
        .retain(|d| !self::selected(d));
    older_coverage(f, &view)?;
    view["terminal_observation_accounting"] = json!({"schema":"jetstreamer-native227-terminal-observation-accounting-v1",
        "terminal_proof":binding(PROOF,PROOF_SHA),"original_observer":binding(OBSERVER,OBSERVER_SHA),
        "excluded_unit":UNIT,"excluded_invocation_id":IID,"current_terminal_manager":current,
        "original_observer_unchanged":true,"host_resident_snapshot_unchanged":true,
        "released_memory_credit_bytes":0,"released_disk_credit_bytes":0,
        "old_native_rss":"retained exactly once in unchanged host/non-lane resident accounting; excluded from lane marginal average",
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    Ok(view)
}
fn no_replacement(rows: &[Value]) -> Result<()> {
    let mut original_terminal = false;
    for r in rows {
        let clock = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("terminal227 journal clock")?
            .parse::<u64>()?;
        if clock < 1_792_814_680_290_027 {
            continue;
        }
        if r["_PID"] == "1" && r["UNIT"] == UNIT {
            ensure!(
                r["INVOCATION_ID"] == IID,
                "terminal227 replacement manager invocation"
            );
            if clock == 1_792_814_680_290_027
                && r["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
            {
                original_terminal = true;
            }
        } else if r["_SYSTEMD_UNIT"] == UNIT {
            ensure!(
                r["_SYSTEMD_INVOCATION_ID"] == IID,
                "terminal227 replacement worker invocation"
            );
        }
    }
    ensure!(
        original_terminal,
        "terminal227 current journal lost original terminal evidence"
    );
    Ok(())
}
pub(super) fn view(f: &Value, o: &Value) -> Result<Value> {
    let count = o["diagnostic_replays"]
        .as_array()
        .map_or(0, |d| d.iter().filter(|d| selected(d)).count());
    if count == 0 {
        return Ok(o.clone());
    }
    ensure!(
        cfg!(feature = "native227-small"),
        "terminal227 small accounting requires its selected generation"
    );
    let original = bound_json(&BoundFile {
        path: OBSERVER.into(),
        sha256: OBSERVER_SHA.into(),
    })?;
    ensure!(
        &original == o,
        "terminal227 raw observer content was replaced"
    );
    let proof = native227_v1625::immutable_json(&BoundFile {
        path: PROOF.into(),
        sha256: PROOF_SHA.into(),
    })?;
    ensure!(
        native227_v1625_terminal::validate(&proof)? == IID,
        "terminal227 typed proof IID differs"
    );
    let before = unit(UNIT)?;
    let (rows, _) = singleton227_capture::journal(UNIT)?;
    no_replacement(&rows)?;
    let view = derived(f, o, &proof, &before)?;
    let after = unit(UNIT)?;
    let (rows, _) = singleton227_capture::journal(UNIT)?;
    no_replacement(&rows)?;
    ensure!(
        before == after,
        "terminal227 current owner changed during accounting"
    );
    Ok(view)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Value) {
        let mut active = Vec::new();
        let mut diags = Vec::new();
        for (name, iid) in OLDER {
            active.push(json!({"phase":"private-known-root-prefix","producer":{"Id":name,"InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running"}}));
            let role = json!({"unit":name,"invocation_id":iid,"restarts":0,"active_state":"active","sub_state":"running","rss":{"census_stable":true}});
            diags.push(json!({"status":"observed","error":null,"observation":{"invocation_binding_stable":true,"producer_before":role,"producer_after":role}}));
        }
        let role = json!({"unit":UNIT,"invocation_id":IID,"restarts":0,"active_state":"active","sub_state":"running","main_pid":PID,"rss":{"census_stable":true}});
        diags.push(json!({"producer_unit":UNIT,"expected_producer_invocation_id":IID,"status":"observed","error":null,"native_resource_only":true,
            "entry_replay":false,"ordinary_replay_claim":false,"range":"227-227","observation":{"invocation_binding_stable":true,"resource_only":true,"entry_replay":false,
                "controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role}}));
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-24T04:03:00Z","completed_at_utc":"2026-10-24T04:03:11Z",
            "diagnostic_replays":diags,"replays":[],"host_resident_memory":{"unchanged_native_rss_bytes":64_493_019_136u64},
            "host_memory":{"conservative_available_kib":123456},"lane_rss_history":{"keep":"original"}});
        let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"observer_receipt":OBSERVER,"observer_sha256":OBSERVER_SHA,
            "sampled_at_utc":o["recorded_at_utc"],"active":active,"metadata_event":binding(PROOF,PROOF_SHA)});
        let mut p = json!({"schema":"jetstreamer-private-epoch227-v1625-native-terminal-proof-v1","epoch":227,"unit":UNIT,"invocation_id":IID,"main_pid":PID,
            "native_input_qualified":true,"observer":binding(OBSERVER,OBSERVER_SHA),"running_origin":binding(ORIGIN,ORIGIN_SHA),
            "terminal_unix_microseconds":1_792_814_680_290_027u64});
        for key in [
            "entry_replay",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "full_epoch_qualified",
            "canonical_sidecar_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            p[key] = json!(false);
        }
        let current = json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","NRestarts":"0","InvocationID":"","Result":"success","ExecMainStatus":"0"});
        (f, o, p, current)
    }
    #[test]
    fn exact_typed_terminal_race_only_changes_derived_row_census_with_zero_capacity_credit() {
        let (f, o, p, u) = fixture();
        let before = o.clone();
        let ledger = f.clone();
        let v = derived(&f, &o, &p, &u).unwrap();
        assert_eq!(v["diagnostic_replays"].as_array().unwrap().len(), 5);
        for key in [
            "host_memory",
            "host_resident_memory",
            "lane_rss_history",
            "recorded_at_utc",
            "completed_at_utc",
        ] {
            assert_eq!(v[key], o[key], "{key}");
        }
        assert_eq!(
            v["terminal_observation_accounting"]["released_memory_credit_bytes"],
            0
        );
        assert_eq!(
            v["terminal_observation_accounting"]["released_disk_credit_bytes"],
            0
        );
        assert_eq!(o, before);
        assert_eq!(f, ledger);
    }
    #[test]
    fn another_invocation_or_unit_or_proof_or_current_replacement_never_explains_disappearance() {
        let (f, o, p, u) = fixture();
        for pointer in [
            "/invocation_id",
            "/unit",
            "/main_pid",
            "/native_input_qualified",
            "/observer/sha256",
            "/running_origin/sha256",
            "/terminal_unix_microseconds",
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(derived(&f, &o, &bad, &u).is_err(), "{pointer}");
        }
        for (key, value) in [
            ("InvocationID", json!("a".repeat(32))),
            ("Id", json!("other.service")),
            ("MainPID", json!("123")),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("active")),
            ("LoadState", json!("not-found")),
        ] {
            let mut bad = u.clone();
            bad[key] = value;
            assert!(derived(&f, &o, &p, &bad).is_err(), "{key}");
        }
        let mut bad = f.clone();
        bad["metadata_event"]["sha256"] = json!("a".repeat(64));
        assert!(derived(&bad, &o, &p, &u).is_err());
        let mut bad = o.clone();
        bad["diagnostic_replays"][5]["observation"]["producer_before"]["invocation_id"] =
            json!("a".repeat(32));
        assert!(derived(&f, &bad, &p, &u).is_err());
        let mut bad = o.clone();
        bad["diagnostic_replays"][5]["native_resource_only"] = json!(false);
        assert!(derived(&f, &bad, &p, &u).is_err());
    }
    #[test]
    fn every_older_observed_peer_still_requires_its_original_complete_roster() {
        let (f, o, p, u) = fixture();
        let mut bad = o.clone();
        bad["diagnostic_replays"][0]["observation"]["producer_after"]["unit"] =
            json!("other.service");
        assert!(derived(&f, &bad, &p, &u).is_err());
        let mut bad = o.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        assert!(derived(&f, &bad, &p, &u).is_err());
        let mut bad = f.clone();
        bad["active"].as_array_mut().unwrap().pop();
        assert!(derived(&bad, &o, &p, &u).is_err());
        let mut bad = o.clone();
        let dup = bad["diagnostic_replays"][5].clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().push(dup);
        assert!(derived(&f, &bad, &p, &u).is_err());
        let mut bad = p.clone();
        bad["publication_authorized"] = json!(true);
        assert!(derived(&f, &o, &bad, &u).is_err());
    }
    #[test]
    fn a_later_cleared_replacement_is_rejected_from_original_manager_journal() {
        let row = json!({"__REALTIME_TIMESTAMP":"1792814680290027","_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE":format!("{UNIT}: Deactivated successfully.")});
        no_replacement(std::slice::from_ref(&row)).unwrap();
        let mut newer = row.clone();
        newer["__REALTIME_TIMESTAMP"] = json!("1792814680290028");
        newer["INVOCATION_ID"] = json!("a".repeat(32));
        assert!(no_replacement(&[row, newer]).is_err());
    }
}
