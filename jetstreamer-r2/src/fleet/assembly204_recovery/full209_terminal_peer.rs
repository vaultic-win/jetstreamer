//! One proved Full209 completion may leave the live-peer comparison during
//! assembly success handoff. Its raw manager state and the accepted fleet stay intact.
use super::*;

const IID: &str = "1bf0db73ccd44c2c90461889498d4f82";
const LAUNCH: &str = "341de3f9b0f8dc835e80f624452223a43a051077e0cf3a65ef66144182e4fac7";
const JOURNAL: &str = "6fe039069d39fc36500b9d08727800b5ab35e57d0c5b7ab0520d5d78ae58f3ac";
const COHORT: &str = "156014ad9f878c10e9b8a83ef74f11e4a6198ba53effaf255f1e35ed3642ffef";
const ARCHIVE: &str = "eb9c768b640d5ec2a931bc146e2827a9f9efe801f7c06147fde7966b286dbb36";

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Proof {
    launch: BoundFile,
    manager_journal: BoundFile,
    cohort_receipt: BoundFile,
}

impl Proof {
    pub(super) fn cleanup_identity(&self) -> Result<(String, String)> {
        self.pins()?;
        Ok((singleton209::UNIT.into(), IID.into()))
    }
    pub(super) fn cleanup_time(&self) -> Result<u64> {
        self.pins()?;
        let raw = sealed(&self.manager_journal, 8 << 20)?;
        ownership::manager_shape(&raw, singleton209::UNIT, IID, true)?;
        let rows = journal_values(&raw)?;
        let end = rows
            .iter()
            .find(|row| row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            .context("full209 cleanup natural terminal absent")?;
        Ok(s(end, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1_000_000)
    }
    fn pins(&self) -> Result<()> {
        ensure!(
            self.launch.sha256 == LAUNCH
                && self.manager_journal.sha256 == JOURNAL
                && self.cohort_receipt.sha256 == COHORT,
            "204 terminal Full209 peer is not the proved original launch/journal/cohort"
        );
        Ok(())
    }
    pub(super) fn project(
        &self,
        fleet: &Value,
        current: &BTreeMap<String, Value>,
        runtime: bool,
    ) -> Result<Value> {
        self.pins()?;
        // The ordinary Full209 launch validator binds its native input,
        // admission, command and original protective guard. No archive is opened.
        let frozen = read(&self.launch)?;
        let (_, launch) = full209_status::claim(&self.launch)?;
        ensure!(
            frozen == launch,
            "204 terminal Full209 launch changed during validation"
        );
        let raw = sealed(&self.manager_journal, 8 << 20)?;
        self.facts(fleet, current, &launch, &raw, &read(&self.cohort_receipt)?)?;
        if runtime {
            // Check the entire current PID1 history, not merely the saved IID
            // subset: a later completed replacement must not borrow this proof.
            ensure!(
                journal_values(&ownership::manager(singleton209::UNIT)?)? == journal_values(&raw)?,
                "204 terminal Full209 manager history changed"
            );
            inactive_status::no_pending_owner_trigger(singleton209::UNIT, false)?;
            capped204205_work::empty_terminal_cgroup(singleton209::UNIT)?;
            let refs = jetstreamer_horizon_observe::process_references::scan(
                Path::new("/proc"),
                Path::new(singleton209::ROOT),
            )?;
            ensure!(
                refs.references.is_empty(),
                "204 terminal Full209 peer retains output process references"
            );
        }
        projected(fleet)
    }
    fn facts(
        &self,
        fleet: &Value,
        current: &BTreeMap<String, Value>,
        launch: &Value,
        raw: &[u8],
        cohort: &Value,
    ) -> Result<()> {
        self.pins()?;
        let rows = fleet["active"]
            .as_array()
            .context("204 terminal Full209 accepted roster")?
            .iter()
            .filter(|row| row["epoch"] == 209)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1,
            "204 terminal Full209 accepted owner missing/duplicate"
        );
        let old = singleton227_admission::active_owner(rows[0])?;
        let owner = current
            .get(singleton209::UNIT)
            .context("204 terminal Full209 raw current owner omitted")?;
        let original = &launch["evidence"]["units"][0];
        ensure!(
            old["Id"] == singleton209::UNIT
                && old["InvocationID"] == IID
                && is_live(old)
                && old == &fleet["unit_census"][singleton209::UNIT]
                && rows[0]["launch_receipt"] == self.launch.path.to_string_lossy().as_ref()
                && rows[0]["launch_receipt_sha256"] == self.launch.sha256
                && launch["schema"] == singleton209::SCHEMA
                && launch["epoch"] == 209
                && original["unit"] == singleton209::UNIT
                && original["invocation_id"] == IID
                && original["restarts"] == 0
                && s(old, "MainPID")?.parse::<u64>()? == n(original, "main_pid")?
                && singleton209::same_command(&old["ExecStart"])
                && singleton209::same_command(&launch["expected_exec_start"])
                && owner["Id"] == singleton209::UNIT
                && owner["LoadState"] == "loaded"
                && owner["ActiveState"] == "inactive"
                && owner["SubState"] == "dead"
                && owner["MainPID"] == "0"
                && owner["NRestarts"] == "0"
                && owner["Result"] == "success"
                && owner["ExecMainStatus"] == "0"
                && (owner["InvocationID"] == IID || owner["InvocationID"] == "")
                && (owner["ControlGroup"] == "" || owner["ControlGroup"] == old["ControlGroup"])
                && singleton209::same_command(&owner["ExecStart"]),
            "204 terminal Full209 launch/accepted/current identity differs"
        );
        let start = ownership::manager_shape(raw, singleton209::UNIT, IID, true)?;
        let values = journal_values(raw)?;
        let end = values
            .iter()
            .find(|row| row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            .context("204 terminal Full209 natural finish absent")?;
        let finish = s(end, "__REALTIME_TIMESTAMP")?.parse::<u64>()? / 1000;
        let recorded = n(launch, "recorded_unix_seconds")?;
        let gate = &cohort["root_checkpoint_gate"];
        let archive = &cohort["outcome"]["members"][0];
        ensure!(
            start / 1000 <= recorded
                && recorded <= finish / 1000
                && cohort["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
                && cohort["manifest_fingerprint"] == singleton209::FINGERPRINT
                && cohort["epochs"] == json!([209])
                && gate["kind"] == "sealed-root-checkpoint-cohort"
                && gate["version"] == 1
                && gate["members"].as_array().is_some_and(|a| a.len() == 1)
                && gate["members"][0]["epoch"] == 209
                && gate["members"][0]["bootstrap"]["slot"] == 90287519u64
                && gate["members"][0]["terminal"]["slot"] == 90719999u64
                && gate["members"][0]["terminal"]["slot_complete"] == true
                && cohort["outcome"]["kind"] == "committed"
                && cohort["outcome"]["members"]
                    .as_array()
                    .is_some_and(|a| a.len() == 1)
                && archive["epoch"] == 209
                && archive["archive_sha256"] == ARCHIVE
                && archive["committed_archive"]["length"] == 111_727_866_952u64
                && archive["committed_archive"]["link_count"] == 1
                && n(&archive["committed_archive"], "changed_seconds")? <= finish / 1000,
            "204 terminal Full209 original completion/cohort/archive differs"
        );
        Ok(())
    }
}

fn projected(fleet: &Value) -> Result<Value> {
    let mut view = fleet.clone();
    view["active"]
        .as_array_mut()
        .context("204 terminal Full209 active projection")?
        .retain(|row| {
            singleton227_admission::active_owner(row)
                .ok()
                .and_then(|owner| owner["Id"].as_str())
                != Some(singleton209::UNIT)
        });
    Ok(view)
}

fn journal_values(raw: &[u8]) -> Result<Vec<Value>> {
    Ok(serde_json::Deserializer::from_slice(raw)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    type Fixture = (Proof, Value, BTreeMap<String, Value>, Value, Vec<u8>, Value);
    fn bound(name: &str, digest: &str) -> BoundFile {
        BoundFile {
            path: format!("/fixture/{name}").into(),
            sha256: digest.into(),
        }
    }
    fn owner(name: &str, iid: &str, pid: u64) -> Value {
        json!({"Id":name,"LoadState":"loaded","InvocationID":iid,"MainPID":pid.to_string(),
            "NRestarts":"0","ActiveState":"active","SubState":"running","ControlGroup":"/original",
            "ExecStart":format!("{} ; ignore_errors=no }}",singleton209::command())})
    }
    fn fixture() -> Fixture {
        let proof = Proof {
            launch: bound("launch.json", LAUNCH),
            manager_journal: bound("manager.jsonl", JOURNAL),
            cohort_receipt: bound("cohort.json", COHORT),
        };
        let old = owner(singleton209::UNIT, IID, 99);
        let mut current: BTreeMap<String, Value> = BTreeMap::from([
            (singleton209::UNIT.into(), old.clone()),
            (
                "healthy207.service".into(),
                owner("healthy207.service", &"a".repeat(32), 207),
            ),
            (
                "healthy225.service".into(),
                owner("healthy225.service", &"b".repeat(32), 225),
            ),
        ]);
        let fleet = json!({"unit_census":current,"active":[
            {"epoch":209,"producer":old,"launch_receipt":proof.launch.path,"launch_receipt_sha256":LAUNCH},
            {"epoch":207,"producer":current["healthy207.service"]},
            {"epoch":225,"producer":current["healthy225.service"]}]});
        current.insert(singleton209::UNIT.into(),json!({"Id":singleton209::UNIT,"LoadState":"loaded","InvocationID":"","MainPID":"0",
            "NRestarts":"0","ActiveState":"inactive","SubState":"dead","ControlGroup":"","Result":"success","ExecMainStatus":"0","ExecStart":old["ExecStart"]}));
        let launch = json!({"schema":singleton209::SCHEMA,"epoch":209,"recorded_unix_seconds":2000,
            "expected_exec_start":old["ExecStart"],"evidence":{"units":[{"unit":singleton209::UNIT,"invocation_id":IID,"restarts":0,"main_pid":99}]}});
        let raw = [
            json!({"_PID":"1","_UID":"0","UNIT":singleton209::UNIT,"INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":"1000000000","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","MESSAGE":"Started original."}),
            json!({"_PID":"1","_UID":"0","UNIT":singleton209::UNIT,"INVOCATION_ID":IID,"__REALTIME_TIMESTAMP":"3000000000","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{}: Deactivated successfully.",singleton209::UNIT)})
        ].iter().map(|r|serde_json::to_string(r).unwrap()+"\n").collect::<String>().into_bytes();
        let cohort = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","manifest_fingerprint":singleton209::FINGERPRINT,"epochs":[209],
            "root_checkpoint_gate":{"kind":"sealed-root-checkpoint-cohort","version":1,"members":[{"epoch":209,"bootstrap":{"slot":90287519u64},"terminal":{"slot":90719999u64,"slot_complete":true}}]},
            "outcome":{"kind":"committed","members":[{"epoch":209,"archive_sha256":ARCHIVE,"committed_archive":{"length":111727866952u64,"link_count":1,"changed_seconds":2999}}]}});
        (proof, fleet, current, launch, raw, cohort)
    }
    #[test]
    fn full209_terminal_peer_preserves_cleared_iid_raw_census_and_live_peers() {
        let (proof, fleet, current, launch, raw, cohort) = fixture();
        let before = (fleet.clone(), current.clone());
        proof
            .facts(&fleet, &current, &launch, &raw, &cohort)
            .unwrap();
        let view = projected(&fleet).unwrap();
        context::validate_peer_bindings(&view, &current).unwrap();
        singleton227_admission::owners(&view, &current).unwrap();
        assert_eq!((fleet, current.clone()), before);
        assert_eq!(current[singleton209::UNIT]["InvocationID"], "");
        assert_eq!(view["active"].as_array().unwrap().len(), 2);
        let mut retained = current;
        retained.get_mut(singleton209::UNIT).unwrap()["InvocationID"] = json!(IID);
        proof
            .facts(&before.0, &retained, &launch, &raw, &cohort)
            .unwrap();
    }
    #[test]
    fn full209_terminal_peer_rejects_replacement_restart_live_or_failed_current_owner() {
        let (proof, fleet, current, launch, raw, cohort) = fixture();
        for (key, value) in [
            ("InvocationID", json!("f".repeat(32))),
            ("NRestarts", json!("1")),
            ("MainPID", json!("12")),
            ("ActiveState", json!("active")),
            ("SubState", json!("running")),
            ("Result", json!("exit-code")),
            ("ExecMainStatus", json!("1")),
            ("ExecStart", json!("foreign")),
        ] {
            let mut bad = current.clone();
            bad.get_mut(singleton209::UNIT).unwrap()[key] = value;
            assert!(
                proof.facts(&fleet, &bad, &launch, &raw, &cohort).is_err(),
                "{key}"
            );
        }
        let mut missing = current;
        missing.remove(singleton209::UNIT);
        assert!(
            proof
                .facts(&fleet, &missing, &launch, &raw, &cohort)
                .is_err()
        );
    }
    #[test]
    fn full209_terminal_peer_rejects_missing_altered_or_foreign_pid1_history() {
        let (proof, fleet, current, launch, raw, cohort) = fixture();
        assert!(
            proof
                .facts(&fleet, &current, &launch, &[], &cohort)
                .is_err()
        );
        let rows = journal_values(&raw).unwrap();
        assert!(
            proof
                .facts(
                    &fleet,
                    &current,
                    &launch,
                    serde_json::to_string(&rows[0]).unwrap().as_bytes(),
                    &cohort
                )
                .is_err()
        );
        for key in [
            "_PID",
            "_UID",
            "UNIT",
            "INVOCATION_ID",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = rows.clone();
            bad[1][key] = json!("foreign");
            let bytes = bad
                .iter()
                .map(|r| serde_json::to_string(r).unwrap() + "\n")
                .collect::<String>();
            assert!(
                proof
                    .facts(&fleet, &current, &launch, bytes.as_bytes(), &cohort)
                    .is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn full209_terminal_peer_rejects_altered_launch_cohort_archive_and_bindings() {
        let (proof, fleet, current, launch, raw, cohort) = fixture();
        for (path, value) in [
            ("/schema", json!("foreign")),
            ("/evidence/units/0/invocation_id", json!("f".repeat(32))),
            ("/evidence/units/0/main_pid", json!(100)),
            ("/recorded_unix_seconds", json!(4000)),
            ("/expected_exec_start", json!("foreign")),
        ] {
            let mut bad = launch.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                proof.facts(&fleet, &current, &bad, &raw, &cohort).is_err(),
                "{path}"
            );
        }
        for (path, value) in [
            ("/epochs", json!([210])),
            ("/outcome/kind", json!("failed")),
            ("/outcome/members/0/archive_sha256", json!("f".repeat(64))),
            ("/outcome/members/0/committed_archive/length", json!(1)),
            (
                "/root_checkpoint_gate/members/0/terminal/slot",
                json!(90719638u64),
            ),
        ] {
            let mut bad = cohort.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                proof.facts(&fleet, &current, &launch, &raw, &bad).is_err(),
                "{path}"
            );
        }
        for index in 0..3 {
            let mut bad = proof.clone();
            match index {
                0 => bad.launch.sha256 = "f".repeat(64),
                1 => bad.manager_journal.sha256 = "f".repeat(64),
                _ => bad.cohort_receipt.sha256 = "f".repeat(64),
            }
            assert!(bad.facts(&fleet, &current, &launch, &raw, &cohort).is_err());
        }
    }
    #[test]
    fn full209_terminal_peer_projection_cannot_hide_207_225_or_a_new_live_owner() {
        let (_, fleet, current, _, _, _) = fixture();
        let view = projected(&fleet).unwrap();
        for name in ["healthy207.service", "healthy225.service"] {
            let mut bad = current.clone();
            bad.get_mut(name).unwrap()["InvocationID"] = json!("f".repeat(32));
            assert!(context::validate_peer_bindings(&view, &bad).is_err());
            assert!(singleton227_admission::owners(&view, &bad).is_err());
        }
        let mut bad = current;
        bad.insert(
            "unbound209.service".into(),
            owner("unbound209.service", &"c".repeat(32), 9),
        );
        assert!(singleton227_admission::owners(&view, &bad).is_err());
    }
    #[test]
    fn full209_terminal_peer_saved_proof_keeps_raw_owner_and_exact_evidence() {
        let (proof, fleet, current, launch, raw, cohort) = fixture();
        let document = serde_json::to_value(&proof).unwrap();
        let saved: Proof = serde_json::from_value(document.clone()).unwrap();
        saved
            .facts(&fleet, &current, &launch, &raw, &cohort)
            .unwrap();
        assert_eq!(serde_json::to_value(saved).unwrap(), document);
        assert_eq!(current[singleton209::UNIT]["InvocationID"], "");
        assert_eq!(
            fleet["unit_census"][singleton209::UNIT]["InvocationID"],
            IID
        );
        let mut stale = fleet;
        stale["active"][0]["launch_receipt_sha256"] = json!("f".repeat(64));
        assert!(
            proof
                .facts(&stale, &current, &launch, &raw, &cohort)
                .is_err()
        );
    }
}
