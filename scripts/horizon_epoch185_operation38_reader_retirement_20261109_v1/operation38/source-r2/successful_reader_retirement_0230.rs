//! Exact0230 successful reader after genuine post-Main terminal closure.
//! This child reuses unchanged retirement cleanup and never resets an actor.
use super::*;
const ACTOR: &str = "horizon-qualify-185-capped-cold-positive-positive-0230-20261109-next.service";
const ACTOR_IID: &str = "da9b57fed9f04c9fa1b0c5dba1932488";
const GUARD: &str = "horizon-guard-185-capped-cold-positive-positive-0230-20261109-next.service";
const TIMER: &str = "horizon-guard-185-capped-cold-positive-positive-0230-20261109-next.timer";
const READER_IID: &str = "09affe4ff3d547bf8c335ec98bc787e4";
const READER_PID: u64 = 3879462;
const MAIN_PID: u64 = 3889589;
fn installed() -> Installed {
    Installed {unit:READER_UNIT.into(),keeper:"horizon-positive185-reader-positive-da9b57fed9f04c9fa1b0c5dba1932488-retain.target".into(),
        argv:vec!["/usr/local/lib/jetstreamer/horizon-epoch185-inherited-census-postreader-tools-20261108-v34/jetstreamer-r2".into(),"read-failed4-current-accounting".into(),"/usr/local/lib/jetstreamer/horizon-epoch185-positive-enrolled-reader-da9b57fed9f04c9fa1b0c5dba1932488/spec.json".into(),"--spec-sha256".into(),"08a6ccbe0b9d83fccf24e3f18ef6dacb28ca78bb6b7e7edf4a57e1b467a3b07a".into(),"--self-sha256".into(),"dda7f44b24b7d9475c654efea20e2230f8374df9640b3e0bf724e7edac44c389".into()],kind:Kind::Production,
        package:"/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-positive-da9b57fed9f04c9fa1b0c5dba1932488".into(),seal:fixed("/usr/local/lib/jetstreamer/horizon-positive185-persistent-reader-positive-da9b57fed9f04c9fa1b0c5dba1932488/deployment-seal-receipt.json","443fe76ddac0c800907c0590ee63d319d3ac3e2b3125e5b5cceda5cda063025e")}
}
pub(super) fn installed_matches(actual: &Installed) -> bool {
    let expected = installed();
    matches!(actual.kind, Kind::Production)
        && actual.unit == expected.unit
        && actual.keeper == expected.keeper
        && actual.argv == expected.argv
        && actual.package == expected.package
        && actual.seal == expected.seal
}
fn terminal_shape(terminal: &Value, lifecycle: &Value) -> Result<()> {
    ensure!(
        terminal["schema"] == "horizon-epoch185-native-terminal-retention-v2"
            && terminal["actor_invocation_id"] == ACTOR_IID
            && terminal["epoch"] == 185
            && terminal["self_sha256"] == HELPER0100_SHA
            && terminal["memory_and_DATA_retained"] == true
            && terminal["resource_credit_bytes"] == 0
            && terminal["fresh_admission_authorized"] == false
            && terminal["publication_authorized"] == false,
        "exact0230 terminal closure preserves all promises and denies authority"
    );
    let context = &terminal["terminal_context"];
    ensure!(
        context["schema"] == "horizon-epoch185-genuine-drained-terminal-context-v2"
            && context["actor_unit"] == ACTOR
            && context["actor_invocation_id"] == ACTOR_IID
            && context["guard_unit"] == GUARD
            && context["timer_unit"] == TIMER
            && context["terminal_actor_result"] == "exit-code"
            && context["terminal_actor_exit_status"] == "1"
            && context["terminal_guard_result"] == "exit-code"
            && context["terminal_guard_exit_status"] == "1"
            && context["cgroup_empty"] == true
            && context["cgroup_populated"] == false
            && context["actor_cgroup_drained"] == true
            && context["guard_cgroup_drained"] == true
            && context["timer_cgroup_drained"] == true
            && context["timer_inactive"] == true
            && context["memory_and_DATA_promises_retained"] == true
            && context["resource_credit_bytes"] == 0
            && context["publication_authorized"] == false,
        "exact0230 actor/guard/timer genuine drained terminal context"
    );
    ensure!(
        lifecycle["schema"] == "horizon-epoch185-native-retained-lifecycle-v2"
            && lifecycle["actor_unit"] == ACTOR
            && lifecycle["actor_invocation_id"] == ACTOR_IID
            && lifecycle["self_sha256"] == HELPER0100_SHA
            && lifecycle["resource_credit_bytes"] == 0
            && lifecycle["fresh_admission_authorized"] == false
            && lifecycle["publication_authorized"] == false
            && lifecycle["r2_mutations"] == false,
        "exact0230 original lifecycle; no new admission"
    );
    let release = &lifecycle["release"];
    let main = &lifecycle["released_actor"];
    ensure!(
        release["actor_invocation_id"] == ACTOR_IID
            && context["release_token"] == release["token"]
            && context["release_seal"] == release["seal"]
            && context["original_start_event"] == release["original_start_event"]
            && main["pid"] == MAIN_PID
            && main["start_ticks"] == 253865423u64
            && main["path"] == driver_policy::DRIVER11
            && main["sha256"] == driver_policy::SHA11
            && main["cgroup"] == format!("0::/system.slice/{ACTOR}"),
        "exact0230 actual historical Driver11 Main and release linkage"
    );
    for event in [
        &context["original_start_event"],
        &context["original_terminal_event"],
    ] {
        ensure!(
            event["_PID"] == "1"
                && event["_UID"] == "0"
                && event["UNIT"] == ACTOR
                && event["INVOCATION_ID"] == ACTOR_IID,
            "exact0230 original PID1 events"
        );
    }
    ensure!(
        context["original_start_event"]["JOB_RESULT"] == "done"
            && context["original_terminal_event"]["UNIT_RESULT"] == "exit-code"
            && n(context, "terminal_at")? > n(release, "released_at")?
            && text(&context["original_terminal_event"], "__MONOTONIC_TIMESTAMP")?
                .parse::<u64>()?
                > text(&context["original_start_event"], "__MONOTONIC_TIMESTAMP")?
                    .parse::<u64>()?,
        "genuine0230 post-Main terminal event follows original start"
    );
    let first = &release["first_guard_value"];
    ensure!(
        first["actor_unit"] == ACTOR
            && first["actor_invocation_id"] == ACTOR_IID
            && first["guard_invocation_id"] == "ba6fbb5131714c4f9d04f8198d7285fb"
            && first["success"] == true
            && first["timer_driven"] == true
            && first["capacity_credit_bytes"] == 0,
        "actual0230 historical first guard success stays separate from0100 failure"
    );
    Ok(())
}
pub(super) fn execute(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    let terminal_binding = fixed(
        "/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/terminal.json",
        "f073eb6ce0ef97f261f205e8910ef1ed22840fc7b7e74622f46a87619a0bcf1b",
    );
    let terminal = storage::json(&terminal_binding)?;
    let lifecycle_binding = fixed(
        "/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/lifecycle.json",
        "4c00568288c78290418cfe40485e2c180066aecece5ef3920e899d370514b1f8",
    );
    let lifecycle = storage::json(&lifecycle_binding)?;
    ensure!(
        terminal["lifecycle"] == json!(lifecycle_binding),
        "exact0230 terminal lifecycle source binding"
    );
    terminal_shape(&terminal, &lifecycle)?;
    let actor = query(r, ACTOR)?;
    let main_pid_text = MAIN_PID.to_string();
    ensure!(
        actor["InvocationID"] == ACTOR_IID
            && actor["ActiveState"] == "failed"
            && actor["SubState"] == "failed"
            && actor["Result"] == "exit-code"
            && actor["ExecMainStatus"] == "1"
            && actor["ExecMainPID"] == main_pid_text.as_str()
            && actor["MainPID"] == "0"
            && actor["ControlPID"] == "0"
            && actor["ControlGroup"] == ""
            && actor["NRestarts"] == "0"
            && actor["Job"] == "",
        "exact0230 original Main remains terminal and drained"
    );
    let guard = query(r, GUARD)?;
    ensure!(
        guard["Result"] == "exit-code"
            && guard["ExecMainStatus"] == "1"
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && guard["ControlGroup"] == ""
            && guard["NRestarts"] == "0"
            && guard["Job"] == ""
            && guard["ActiveState"] == "failed",
        "original0230 guard remains failed and drained"
    );
    let timer = r.native(TIMER)?;
    ensure!(
        timer["ActiveState"] == "inactive"
            && timer["SubState"] == "dead"
            && timer["InvocationID"] == ""
            && timer["Job"] == ""
            && timer["Unit"] == GUARD,
        "owned original0230 timer remains stopped without renewed claim"
    );
    for unit in [ACTOR, GUARD, TIMER] {
        control_group_empty(unit)?;
    }
    ensure!(
        !Path::new(&format!("/proc/{MAIN_PID}")).try_exists()?,
        "original0230 Main PID remains absent"
    );
    let final_outcome = storage::json(&fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/3782-actual-c71-one-original-final-original-outcome.json",
        "c24c739b8b678ebf793e2c75665a043bbc17304a305269db2c9c48835ecc8219",
    ))?;
    ensure!(
        final_outcome["program"]
            == "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261109-v4/horizon-positive185-final"
            && final_outcome["exit_code"] == 1
            && final_outcome["exit_signal"].is_null()
            && final_outcome["wait_error"].is_null()
            && final_outcome["no_retry_or_clock_reset"] == true,
        "original0230 Final4 outcome remains failed and reaped"
    );
    let completion_binding = fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/original-enrolled-reader-completion.json",
        "b832f47364d4ebce9276bb771d9948e340a6f30a37eec5b1eb7ac69cc74fde74",
    );
    let completion = storage::json(&completion_binding)?;
    let record_binding = fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/genuine-original-persistent-reader.json",
        "5eb4d1eba858c4616a2a806e68a80f2b711db485a09d5ed342eb788102d38414",
    );
    let record = storage::json(&record_binding)?;
    let i = installed();
    ensure!(
        completion["schema"] == "terminal199-parent-memory-original-reader-completion-v1"
            && completion["unit"] == READER_UNIT
            && completion["invocation_id"] == READER_IID
            && completion["program"] == json!(fixed(HELPER0100, HELPER0100_SHA))
            && completion["original_ExecStart_argv"] == json!(i.argv)
            && completion["normal_unit_package_seal"] == json!(i.seal)
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true
            && completion["original_process_wait"]["actual_original_pidfd_exit_event"] == true
            && completion["original_process_wait"]["original_iid"] == READER_IID
            && completion["original_process_wait"]["original_pid"] == READER_PID,
        "genuine0230 exact successful persistent reader and pidfd drain"
    );
    ensure!(
        completion["actual_original_native_execution_record"] == json!(record_binding)
            && record["lifecycle"]["original_native"] == completion["original_native"]
            && record["reader_proof"] == completion["reader_proof"]
            && record["original_unit_package_seal"] == completion["normal_unit_package_seal"],
        "original0230 install and completion cannot cross"
    );
    let original = &completion["original_native"];
    successful_shape(original, READER_UNIT, READER_IID, READER_PID)?;
    let proof_binding = fixed(
        "/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/cda54fabbcad05ee9d1aba2d944926c5d0557b4662d1052fdf1f0a8e776b6c9e-cold185-da9b57fed9f04c9fa1b0c5dba1932488/proof.json",
        "6256ede849a9c9bedf6cf2c4ef98ab01c3ea88640698bd37b94a11e113fb8fd3",
    );
    let proof = storage::json(&proof_binding)?;
    ensure!(
        completion["reader_proof"] == json!(proof_binding)
            && proof["image"] == completion["program"]
            && proof["unit"] == READER_UNIT
            && proof["invocation_id"] == READER_IID
            && proof["spec"] == json!(fixed(&i.argv[2], &i.argv[4]))
            && proof["DATA_credit_bytes"] == 0
            && proof["physical_credit_bytes"] == 0
            && proof["memory_budget_credit_applied_bytes"] == 0
            && proof["admission_authorized"] == false
            && proof["replay_launch_authorized"] == false
            && proof["publication_authorized"] == false,
        "genuine0230 exact successful payload proof; no authority or credit"
    );
    let pid1_binding = fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/original-enrolled-reader-PID1.json",
        "bfbd19759998853944a657ad42bc1e7441684a3b8cf1e80caba28442c41039f2",
    );
    let pid1 = storage::json(&pid1_binding)?;
    ensure!(
        completion["original_PID1_journal"] == json!(pid1_binding)
            && pid1["unit"] == READER_UNIT
            && pid1["invocation_id"] == READER_IID
            && pid1["original_rows"]
                .as_array()
                .context("original0230 PID1 rows")?
                .contains(&completion["original_PID1_success_event"])
            && completion["original_PID1_success_event"]["_PID"] == "1"
            && completion["original_PID1_success_event"]["INVOCATION_ID"] == READER_IID,
        "original0230 successful reader PID1 source and event membership"
    );
    let outer_binding = fixed(
        "/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/original-reader-keeper-start-outer.json",
        "71948e9eae6abfe519e6854377612c3c1a66b7dca988855c1530166a2ae30e35",
    );
    let outer = storage::json(&outer_binding)?;
    ensure!(
        completion["actual_original_outer_execution"] == json!(outer_binding)
            && completion["actual_keeper_native"]["Id"] == i.keeper
            && outer["program"] == "/usr/bin/systemctl"
            && outer["argv"] == json!(["start", i.keeper])
            && outer["exit_code"] == 0
            && outer["exit_signal"].is_null()
            && outer["wait_error"].is_null()
            && outer["no_retry_or_clock_reset"] == true,
        "original0230 exact keeper-start outer was reaped"
    );
    control_proof(r, &binding(&v["native_retirement_control"])?)?;
    let context = storage::save(
        r.root,
        "exact0230-successful-reader-retirement-context.json",
        &json!({"terminal":terminal_binding,"lifecycle":lifecycle_binding,"completion":completion_binding,"record":record_binding,"actor_terminal_after_actual_Main":actor,"guard_terminal":guard,"owned_timer_stopped":timer,"all_raw_promises_preserved":true,"resource_credit_bytes":0}),
    )?;
    let done = cleanup(r, &i, original)?;
    println!(
        "{}",
        json!({"actual_successful_reader_retirement":done,"exact0230_original":true,"context":context,"no_replay_or_archive_authority":true})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "Root reads genuine retained0230 small metadata and sealed reader package; no manager actions"]
    fn actual_retained0230_terminal_and_reader_package_remain_exact_without_cleanup() {
        let terminal=storage::json(&fixed("/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/terminal.json","f073eb6ce0ef97f261f205e8910ef1ed22840fc7b7e74622f46a87619a0bcf1b")).unwrap();
        let lifecycle=storage::json(&fixed("/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2/da9b57fed9f04c9fa1b0c5dba1932488/lifecycle.json","4c00568288c78290418cfe40485e2c180066aecece5ef3920e899d370514b1f8")).unwrap();
        terminal_shape(&terminal, &lifecycle).unwrap();
        let completion=storage::json(&fixed("/home/sol/.jetstreamer-private/epoch185-positive-upstream-actual0230-original-r3-20261109-next/original-enrolled-reader-completion.json","b832f47364d4ebce9276bb771d9948e340a6f30a37eec5b1eb7ac69cc74fde74")).unwrap();
        successful_shape(
            &completion["original_native"],
            READER_UNIT,
            READER_IID,
            READER_PID,
        )
        .unwrap();
        let i = installed();
        assert!(installed_matches(&i));
        package(&i).unwrap();
        assert_eq!(completion["normal_unit_package_seal"], json!(i.seal));
        assert_eq!(completion["original_ExecStart_argv"], json!(i.argv));
    }

    fn fixture() -> (Value, Value) {
        (
            serde_json::from_str(include_str!("fixtures/original0230-terminal.json")).unwrap(),
            serde_json::from_str(include_str!("fixtures/original0230-lifecycle.json")).unwrap(),
        )
    }
    #[test]
    fn actual0230_terminal_fixture_rejects_other_actor_live_timer_credit_and_erased_Main() {
        let (terminal, lifecycle) = fixture();
        terminal_shape(&terminal, &lifecycle).unwrap();
        for (pointer, value) in [
            ("/actor_invocation_id", json!(ACTOR0100_IID)),
            ("/terminal_context/timer_inactive", json!(false)),
            ("/resource_credit_bytes", json!(1)),
            ("/terminal_context/actor_cgroup_drained", json!(false)),
        ] {
            let mut bad = terminal.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(terminal_shape(&bad, &lifecycle).is_err());
        }
        let mut bad = lifecycle.clone();
        bad["released_actor"]["pid"] = json!(0);
        assert!(terminal_shape(&terminal, &bad).is_err());
        let mut bad = lifecycle;
        bad["release"]["first_guard_value"]["success"] = json!(false);
        assert!(terminal_shape(&terminal, &bad).is_err());
    }
    #[test]
    fn exact0230_installed_tuple_cannot_borrow0100_or_current35() {
        let actual = installed();
        assert!(installed_matches(&actual));
        permitted(&actual).unwrap();
        assert!(!installed_matches(&installed0100()));
        let mut bad = installed();
        bad.argv[0] = crate::successor_roles::HELPER35_PATH.into();
        assert!(!installed_matches(&bad));
        assert!(permitted(&bad).is_err());
        let mut bad = installed();
        bad.argv[4] = "0".repeat(64);
        assert!(permitted(&bad).is_err());
        let mut bad = installed();
        bad.keeper = installed0100().keeper;
        assert!(permitted(&bad).is_err());
        let mut bad = installed();
        bad.seal.sha256 = "0".repeat(64);
        assert!(permitted(&bad).is_err());
    }
    #[test]
    fn actual0230_reader_fixture_matches_successful_native_pidfd_argv_and_package() {
        let completion: Value =
            serde_json::from_str(include_str!("fixtures/original0230-reader-completion.json"))
                .unwrap();
        let i = installed();
        successful_shape(
            &completion["original_native"],
            READER_UNIT,
            READER_IID,
            READER_PID,
        )
        .unwrap();
        assert_eq!(completion["original_ExecStart_argv"], json!(i.argv));
        assert_eq!(completion["normal_unit_package_seal"], json!(i.seal));
        assert_eq!(
            completion["original_process_wait"]["original_iid"],
            READER_IID
        );
        assert_eq!(
            completion["original_process_wait"]["actual_original_pidfd_exit_event"],
            true
        );
    }
}
