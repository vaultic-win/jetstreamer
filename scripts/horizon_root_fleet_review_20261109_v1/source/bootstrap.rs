//! Exact original172 bootstrap exception. It never supplies useful replay or point7 authority.
use super::{R, bound, command, n, need, owner_identity_observation, owner_matches, s};
use serde_json::{Value, json};
const UNIT: &str = "horizon-qualify-172-standard-20261110-v1.service";
const IID: &str = "6aa8bc6036b34c57ababa2d5855b2098";
const PID: &str = "431228";
const GUARD: &str = "horizon-guard-172-standard-20261110-v1.service";
const TIMER: &str = "horizon-guard-172-standard-20261110-v1.timer";
const START: u64 = 1_794_286_708;
const START_NATIVE: &str = "Tue 2026-11-10 04:58:28 UTC";
const GUARD_SHA: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
pub struct Inputs<'a> {
    pub declaration: &'a Value,
    pub owner: &'a Value,
    pub observation: &'a Value,
    pub admission: &'a Value,
    pub phase: &'a Value,
    pub first_guard: &'a Value,
    pub first_proof: &'a Value,
    pub current_guard: &'a Value,
    pub current_proof: &'a Value,
}
fn timer(proof: &Value, expected_iid: &str) -> R<()> {
    let t = &proof["timer"];
    need(
        t["Id"] == TIMER
            && t["InvocationID"] == expected_iid
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && matches!(
                t["SubState"].as_str(),
                Some("waiting" | "elapsed" | "running")
            )
            && t["Triggers"] == GUARD
            && t["Job"] == "",
        "original bootstrap guard timer not armed",
    )
}
fn guard_proof(guard: &Value, proof: &Value, owner: &Value) -> R<()> {
    need(
        guard["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && guard["guard_sha256"] == GUARD_SHA
            && guard["producer_invocation_id"] == owner["invocation_id"]
            && guard["producer"]["invocation_id"] == owner["invocation_id"]
            && guard["producer"]["pid"] == 431228
            && guard["producer"]["restarts"] == 0
            && guard["producer_stop_enabled"] == true
            && guard["maximum_root_physical_bytes"] == 309_237_645_312u64
            && guard["maximum_worker_vmas"] == 3_500_000
            && guard.get("trip_reason") == Some(&Value::Null)
            && guard.get("root_physical_observation_error") == Some(&Value::Null)
            && guard.get("worker_observation_error") == Some(&Value::Null)
            && guard["scratch_deleted"] == false
            && n(guard, "available_bytes")? >= n(guard, "minimum_free_bytes")?,
        "bootstrap guard protection proof failed",
    )?;
    let iid = s(guard, "guard_invocation_id")?;
    let journal = proof["journal"]
        .as_array()
        .ok_or("genuine guard PID1 journal required")?;
    let matches = |r: &&Value| r["_PID"] == "1" && r["UNIT"] == GUARD && r["INVOCATION_ID"] == iid;
    need(
        journal
            .iter()
            .filter(matches)
            .any(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            && journal.iter().filter(matches).any(|r| {
                r["JOB_RESULT"] == "done" && r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf"
            }),
        "original successful guard PID1 completion required",
    )?;
    let producer = &proof["actual_producer"];
    owner_matches(producer, owner)?;
    need(
        producer["Restart"] == "no",
        "bootstrap original restart policy changed",
    )
}
pub fn validate(i: &Inputs<'_>, clock: u64) -> R<Value> {
    let d = i.declaration;
    let owner = i.owner;
    let row = i.observation;
    need(
        d["schema"] == "horizon-Root-original172-guarded-bootstrap-declaration-v1"
            && d["epoch"] == 172
            && owner["epoch"] == 172
            && d["unit"] == UNIT
            && owner["unit"] == UNIT
            && d["invocation_id"] == IID
            && owner["invocation_id"] == IID
            && d["main_pid"] == PID
            && owner["main_pid"] == PID
            && d["wire_phase"] == "verification"
            && d["transaction_replay_claimed"] == false,
        "exact original172 bootstrap declaration required",
    )?;
    owner_identity_observation(row, owner)?;
    need(
        row["useful_work"]["matching_markers"] == 0
            && row["useful_work"]["last"].is_null()
            && row["useful_work"]["sufficient_for_rates"] == false
            && row["useful_work"]["append_log_evidence"]["stdout_append_binding_verified"] == true
            && row["useful_work"]["journal_invocation_id"] == IID,
        "bootstrap cannot replace useful transaction replay evidence",
    )?;
    let max = n(d, "maximum_bootstrap_seconds")?;
    let deadline = n(d, "bootstrap_deadline_unix_seconds")?;
    need(
        d["original_start_unix_seconds"] == START
            && d["original_start_native"] == START_NATIVE
            && max > 0
            && max <= 3600
            && deadline
                == START
                    .checked_add(max)
                    .ok_or("bootstrap deadline overflow")?
            && clock >= START
            && clock <= deadline,
        "original bootstrap lifetime expired or reset",
    )?;
    let sampled = n(&row["useful_work"], "until_unix_seconds")?;
    need(
        sampled >= START && sampled <= deadline,
        "bootstrap observation outside original startup lifetime",
    )?;
    need(
        i.admission["schema"] == "horizon-fresh-standard172-resource-admission-v1"
            && i.admission["owner"] == "/root"
            && i.admission["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53"
            && i.admission["proven_replay_count"] == 6
            && i.admission["one_additional_guarded_lane_experiment"] == true
            && n(i.admission, "recorded_unix_seconds")? <= START,
        "original172 admission required",
    )?;
    let phase = i.phase;
    need(
        phase["schema"] == "horizon-original-singleton-guarded-bootstrap-phase-handoff-v1"
            && phase["actual_admission"] == d["admission"]
            && phase["actual_first_guard"] == d["first_guard"]
            && phase["transaction_replay_claimed"] == false
            && phase["no_new_resource_sample"] == true
            && phase["replay_launch_authorized"] == false
            && phase["source_log"]["stdout_append_binding_verified"] == true
            && phase["scratch_path"] == row["scratch_path"]
            && n(phase, "recorded_unix_seconds")? >= START
            && n(phase, "recorded_unix_seconds")? <= sampled,
        "original guarded bootstrap handoff binding",
    )?;
    for k in ["producer_before", "producer_after"] {
        owner_matches(&phase[k], owner)?;
        need(
            phase[k]["ExecMainStartTimestamp"] == START_NATIVE,
            "bootstrap handoff start changed",
        )?;
    }
    guard_proof(i.first_guard, i.first_proof, owner)?;
    guard_proof(i.current_guard, i.current_proof, owner)?;
    need(
        i.first_proof["receipt"]["sha256"] == d["first_guard"]["sha256"]
            && i.first_proof["continuous_Root_supervision"] == true
            && i.first_proof["no_existing_producer_or_guard_changed"] == true
            && n(i.first_guard, "recorded_unix_seconds")? >= START
            && n(i.first_guard, "recorded_unix_seconds")? <= n(phase, "recorded_unix_seconds")?
            && i.current_guard["plan_sha256"] == i.first_guard["plan_sha256"]
            && i.current_guard["plan"] == i.first_guard["plan"]
            && i.current_guard["minimum_free_bytes"] == i.first_guard["minimum_free_bytes"],
        "bootstrap original/current guard provenance changed",
    )?;
    let timer_iid = s(&i.first_proof["timer"], "InvocationID")?;
    need(!timer_iid.is_empty(), "original timer invocation required")?;
    timer(i.first_proof, timer_iid)?;
    timer(i.current_proof, timer_iid)?;
    let max_age = n(d, "maximum_current_guard_age_seconds")?;
    let guard_at = n(i.current_guard, "recorded_unix_seconds")?;
    need(
        max_age > 0
            && max_age <= 120
            && guard_at >= START
            && clock >= guard_at
            && clock - guard_at <= max_age,
        "current bootstrap protective evidence is stale",
    )?;
    Ok(
        json!({"epoch":172,"kind":"guarded-bootstrap","phase":"verification","original_start_unix_seconds":START,"original_start_native":START_NATIVE,"bootstrap_deadline_unix_seconds":deadline,"current_guard_recorded_unix_seconds":guard_at,"maximum_current_guard_age_seconds":max_age,"timer_invocation_id":timer_iid,"declaration":d,"useful_transaction_replay":false,"measured_rate_claimed":false,"replay_admission_authorized":false,"resource_credit_bytes":0}),
    )
}
fn native_timer() -> R<Value> {
    let text = command(
        &[
            "show",
            TIMER,
            "--no-pager",
            "-p",
            "Id,LoadState,ActiveState,SubState,InvocationID,Triggers,Job",
        ],
        65536,
    )?;
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or("bootstrap timer delimiter")?;
        need(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate bootstrap timer property",
        )?;
    }
    Ok(Value::Object(map))
}
fn native_start() -> R<Value> {
    let text = command(
        &[
            "show",
            UNIT,
            "--no-pager",
            "-p",
            "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Restart,ExecMainStartTimestamp",
        ],
        65536,
    )?;
    let mut map = serde_json::Map::new();
    for line in text.lines() {
        let (k, v) = line.split_once('=').ok_or("bootstrap start delimiter")?;
        need(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate bootstrap start property",
        )?;
    }
    Ok(Value::Object(map))
}
pub fn load(d: &Value, owner: &Value, row: &Value, clock: u64) -> R<Value> {
    let admission = bound(&d["admission"])?;
    let phase = bound(&d["phase_handoff"])?;
    let first_guard = bound(&d["first_guard"])?;
    let first_proof = bound(&d["first_guard_pid1_timer"])?;
    let current_proof = bound(&d["current_guard_pid1_timer"])?;
    let current_guard = bound(&current_proof["receipt"])?;
    let mut accepted = validate(
        &Inputs {
            declaration: d,
            owner,
            observation: row,
            admission: &admission,
            phase: &phase,
            first_guard: &first_guard,
            first_proof: &first_proof,
            current_guard: &current_guard,
            current_proof: &current_proof,
        },
        clock,
    )?;
    let producer = native_start()?;
    owner_matches(&producer, owner)?;
    need(
        producer["ExecMainStartTimestamp"] == START_NATIVE && producer["Restart"] == "no",
        "bootstrap native original start changed",
    )?;
    let t = native_timer()?;
    timer(
        &json!({"timer":t}),
        s(&first_proof["timer"], "InvocationID")?,
    )?;
    accepted["native_producer_start"] = producer;
    accepted["native_timer"] = t;
    accepted["current_guard_receipt"] = current_proof["receipt"].clone();
    Ok(accepted)
}
pub fn finish(d: &Value, accepted: &Value, clock: u64) -> R<()> {
    let producer = native_start()?;
    need(
        producer == accepted["native_producer_start"],
        "bootstrap producer start changed during census",
    )?;
    let t = native_timer()?;
    timer(&json!({"timer":t}), s(accepted, "timer_invocation_id")?)?;
    need(
        clock <= n(accepted, "bootstrap_deadline_unix_seconds")?
            && clock >= n(accepted, "current_guard_recorded_unix_seconds")?
            && clock - n(accepted, "current_guard_recorded_unix_seconds")?
                <= n(accepted, "maximum_current_guard_age_seconds")?,
        "bootstrap lifetime or guard freshness expired during census",
    )?;
    for key in [
        "admission",
        "phase_handoff",
        "first_guard",
        "first_guard_pid1_timer",
        "current_guard_pid1_timer",
    ] {
        bound(&d[key])?;
    }
    bound(&accepted["current_guard_receipt"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> [Value; 9] {
        let owner = json!({"epoch":172,"unit":UNIT,"invocation_id":IID,"main_pid":PID});
        let declaration = json!({"schema":"horizon-Root-original172-guarded-bootstrap-declaration-v1","epoch":172,"unit":UNIT,"invocation_id":IID,"main_pid":PID,"wire_phase":"verification","transaction_replay_claimed":false,"original_start_unix_seconds":START,"original_start_native":START_NATIVE,"maximum_bootstrap_seconds":3600,"bootstrap_deadline_unix_seconds":START+3600,"maximum_current_guard_age_seconds":120,"admission":{"path":"/admission","sha256":"admission"},"first_guard":{"path":"/first","sha256":"first"}});
        let role = json!({"unit":UNIT,"invocation_id":IID,"main_pid":431228,"active_state":"active","sub_state":"running","restarts":0});
        let observation = json!({"range":"172","invocation_binding_stable":true,"producer_before":role,"producer_after":role,"controller_before":role,"controller_after":role,"scratch_path":"/private/172/scratch","useful_work":{"matching_markers":0,"last":null,"sufficient_for_rates":false,"append_log_evidence":{"stdout_append_binding_verified":true},"journal_invocation_id":IID,"until_unix_seconds":START+114}});
        let admission = json!({"schema":"horizon-fresh-standard172-resource-admission-v1","owner":"/root","primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","proven_replay_count":6,"one_additional_guarded_lane_experiment":true,"recorded_unix_seconds":START-1});
        let producer = json!({"Id":UNIT,"InvocationID":IID,"MainPID":PID,"ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","Restart":"no","ExecMainStartTimestamp":START_NATIVE});
        let phase = json!({"schema":"horizon-original-singleton-guarded-bootstrap-phase-handoff-v1","actual_admission":declaration["admission"],"actual_first_guard":declaration["first_guard"],"transaction_replay_claimed":false,"no_new_resource_sample":true,"replay_launch_authorized":false,"source_log":{"stdout_append_binding_verified":true},"scratch_path":"/private/172/scratch","recorded_unix_seconds":START+33,"producer_before":producer,"producer_after":producer});
        let guard = |iid: &str, time: u64| json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_sha256":GUARD_SHA,"guard_invocation_id":iid,"producer_invocation_id":IID,"producer":{"invocation_id":IID,"pid":431228,"restarts":0},"producer_stop_enabled":true,"maximum_root_physical_bytes":309_237_645_312u64,"maximum_worker_vmas":3_500_000,"trip_reason":null,"root_physical_observation_error":null,"worker_observation_error":null,"scratch_deleted":false,"available_bytes":1000,"minimum_free_bytes":100,"plan":"/sealed/guard-plan","plan_sha256":"guard-plan","recorded_unix_seconds":time});
        let proof = |iid: &str, sha: &str| json!({"receipt":{"path":"/receipt","sha256":sha},"journal":[{"_PID":"1","UNIT":GUARD,"INVOCATION_ID":iid,"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"},{"_PID":"1","UNIT":GUARD,"INVOCATION_ID":iid,"JOB_RESULT":"done","MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf"}],"actual_producer":producer,"timer":{"Id":TIMER,"InvocationID":"original-timer","LoadState":"loaded","ActiveState":"active","SubState":"waiting","Triggers":GUARD,"Job":""},"continuous_Root_supervision":true,"no_existing_producer_or_guard_changed":true});
        [
            declaration,
            owner,
            observation,
            admission,
            phase,
            guard("first-guard", START + 1),
            proof("first-guard", "first"),
            guard("current-guard", START + 100),
            proof("current-guard", "current"),
        ]
    }
    fn inputs(v: &[Value; 9]) -> Inputs<'_> {
        Inputs {
            declaration: &v[0],
            owner: &v[1],
            observation: &v[2],
            admission: &v[3],
            phase: &v[4],
            first_guard: &v[5],
            first_proof: &v[6],
            current_guard: &v[7],
            current_proof: &v[8],
        }
    }
    #[test]
    fn exact_bootstrap_accepts_identity_without_claiming_useful_replay() {
        let v = fixture();
        let r = validate(&inputs(&v), START + 120).unwrap();
        assert_eq!(r["useful_transaction_replay"], false);
        assert_eq!(r["phase"], "verification");
        assert!(super::super::owner_observation(&v[2], &v[1]).is_err());
    }
    #[test]
    fn arbitrary_owner_and_reset_start_are_rejected() {
        for (k, x) in [
            ("epoch", json!(171)),
            ("invocation_id", json!("other")),
            ("main_pid", json!("1")),
            ("original_start_unix_seconds", json!(START + 1)),
            ("maximum_bootstrap_seconds", json!(3601)),
        ] {
            let mut v = fixture();
            v[0][k] = x;
            assert!(validate(&inputs(&v), START + 120).is_err(), "{k}");
        }
    }
    #[test]
    fn startup_lifetime_and_current_guard_age_are_bounded() {
        let v = fixture();
        assert!(validate(&inputs(&v), START + 3601).is_err());
        assert!(validate(&inputs(&v), START + 221).is_err());
        let mut v = fixture();
        v[7]["recorded_unix_seconds"] = json!(START + 121);
        assert!(validate(&inputs(&v), START + 120).is_err());
    }
    #[test]
    fn genuine_pid1_success_and_original_timer_are_required() {
        let mut v = fixture();
        v[8]["journal"] = json!([]);
        assert!(validate(&inputs(&v), START + 120).is_err());
        let mut v = fixture();
        v[8]["timer"]["InvocationID"] = json!("new-timer");
        assert!(validate(&inputs(&v), START + 120).is_err());
    }
    #[test]
    fn changed_guard_plan_and_trip_never_pass() {
        for (k, x) in [
            ("plan_sha256", json!("changed")),
            ("trip_reason", json!("memory")),
            ("producer_stop_enabled", json!(false)),
            ("worker_observation_error", json!("unavailable")),
        ] {
            let mut v = fixture();
            v[7][k] = x;
            assert!(validate(&inputs(&v), START + 120).is_err(), "{k}");
        }
    }
    #[test]
    fn positive_transactions_require_the_strict_replay_path() {
        let mut v = fixture();
        v[2]["useful_work"]["matching_markers"] = json!(1);
        v[2]["useful_work"]["last"] = json!({"transactions":1});
        assert!(validate(&inputs(&v), START + 120).is_err());
        assert!(super::super::owner_observation(&v[2], &v[1]).is_ok());
    }
    #[test]
    fn changed_admission_or_bootstrap_phase_binding_is_rejected() {
        let mut v = fixture();
        v[4]["actual_admission"]["sha256"] = json!("changed");
        assert!(validate(&inputs(&v), START + 120).is_err());
        let mut v = fixture();
        v[4]["transaction_replay_claimed"] = json!(true);
        assert!(validate(&inputs(&v), START + 120).is_err());
    }
}

#[cfg(test)]
mod timer_running_regression {
    use super::*;
    #[test]
    fn original_timer_running_its_bound_guard_remains_armed() {
        let mut p = json!({"timer":{"Id":TIMER,"InvocationID":"original","LoadState":"loaded","ActiveState":"active","SubState":"running","Triggers":GUARD,"Job":""}});
        assert!(timer(&p, "original").is_ok());
        for (k, v) in [
            ("ActiveState", json!("inactive")),
            ("InvocationID", json!("replacement")),
            ("Triggers", json!("foreign.service")),
            ("SubState", json!("dead")),
            ("Job", json!("123")),
        ] {
            let old = p["timer"][k].clone();
            p["timer"][k] = v;
            assert!(timer(&p, "original").is_err(), "{k}");
            p["timer"][k] = old;
        }
    }
}
