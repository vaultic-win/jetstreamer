//! Concrete finite post-reader finalization. Commands are fixed native helper,
//! normal-sealer, exact timer activation and one actual sol read capability.
use crate::{
    ContextFile, Route, binding, events, n, now,
    process::{self, Helper, Runner},
    storage::{self, Bound},
    text, verify_seal_member,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
const REGISTRY: &str =
    "/var/lib/jetstreamer/horizon-epoch185-native-startpre-registrations-20261105-v1";
const KINDS: [(&str, &str); 4] = [
    ("fleet_enrollment", "fleet-acceptance.json"),
    ("current_reader_native_acceptance", "reader-acceptance.json"),
    ("task_acknowledgment", "task-acknowledgment.json"),
    ("status_readback", "status-readback.json"),
];
struct Sealed {
    members: BTreeMap<String, Bound>,
    receipt: Bound,
}
fn source(root: &Path, name: &str, v: &Value) -> Result<Bound> {
    storage::save(root, name, v)
}
fn package(label: &str, iid: &str) -> PathBuf {
    Path::new("/usr/local/lib/jetstreamer").join(if label == "originals" {
        format!("horizon-epoch185-readable-originals-final-{iid}")
    } else {
        format!("horizon-epoch185-positive-final-{label}-{iid}")
    })
}
fn seal(r: &mut Runner<'_>, label: &str, dest: &Path, members: &[(&str, Bound)]) -> Result<Sealed> {
    ensure!(
        members.len() <= 16 && !dest.try_exists()?,
        "normal final seal destination collision/member bound"
    );
    let plan = json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,
        "members":members.iter().map(|(name,b)|json!({"name":name,"source":b.path,"sha256":b.sha256,"mode":0o444})).collect::<Vec<_>>()});
    let pb = source(r.root, &format!("{label}-normal-seal-plan.json"), &plan)?;
    r.seal(label, &pb)?;
    let receipt = process::bind_file(&dest.join("deployment-seal-receipt.json"), 4 << 20)?;
    let record = storage::json(&receipt)?;
    let mut result = BTreeMap::new();
    for (name, b) in members {
        let actual = Bound {
            path: dest.join(name),
            sha256: b.sha256.clone(),
        };
        verify_seal_member(&record, &actual, 0o444)?;
        ensure!(
            storage::bytes(&actual, 4 << 20, true)? == storage::bytes(b, 4 << 20, false)?,
            "normal sealed member differs from exact original bytes"
        );
        result.insert((*name).into(), actual);
    }
    Ok(Sealed {
        members: result,
        receipt,
    })
}
fn member(sealed: &Sealed, name: &str) -> Result<Bound> {
    sealed
        .members
        .get(name)
        .cloned()
        .context("exact final sealed member absent")
}
fn output(registry: &Path, name: &str) -> PathBuf {
    registry.join(name)
}
fn read_receipt(
    registry: &Path,
    index: usize,
    iid: &str,
    ready: &Value,
    admission: &str,
) -> Result<(Bound, Value)> {
    let b = process::bind_file(&output(registry, KINDS[index].1), 4 << 20)?;
    let v = storage::json(&b)?;
    ensure!(
        v["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
            && v["kind"] == KINDS[index].0
            && v["actor_invocation_id"] == iid
            && v["ready_pid"] == ready["pid"]
            && v["ready_start_ticks"] == ready["start_ticks"]
            && v["admission_sha256"] == admission
            && v["restarts"] == 0
            && v["resource_credit_bytes"] == 0
            && v["phase"] == "verification",
        "original helper receipt crossed kind/IID/ready/admission/authority"
    );
    Ok((b, v))
}
pub fn critical_deadline(
    ready_started: u64,
    original_deadline: u64,
    stamps: [u64; 4],
    at: u64,
    margin: u64,
) -> Result<u64> {
    ensure!(
        original_deadline.checked_sub(ready_started) == Some(600),
        "original setup is not600seconds"
    );
    let mut end = original_deadline;
    for sampled in stamps {
        ensure!(
            ready_started <= sampled && sampled <= at,
            "original acceptance has future/crossed capture clock"
        );
        end = end.min(
            sampled
                .checked_add(30)
                .context("acceptance clock overflow")?,
        );
    }
    ensure!(
        at.checked_add(margin).is_some_and(|n| n < end),
        "irreducible final30s budget cannot fund remaining original sequence"
    );
    Ok(end)
}
pub fn release_policy(
    ready: u64,
    deadline: u64,
    stamps: [u64; 4],
    guard: u64,
    issued: u64,
    expires: u64,
    main: u64,
) -> Result<()> {
    critical_deadline(ready, deadline, stamps, issued, 0)?;
    ensure!(
        ready <= guard
            && guard <= issued
            && issued <= main
            && main < expires
            && expires <= deadline,
        "actual first-guard/token/main chronology or original setup deadline invalid"
    );
    ensure!(
        main.checked_sub(guard).is_some_and(|age| age <= 30)
            && stamps
                .iter()
                .all(|s| main.checked_sub(*s).is_some_and(|age| age <= 30)),
        "actual main entry exceeded original four-receipt or first-fire freshness"
    );
    Ok(())
}
fn wall_limit(end: u64) -> Result<Instant> {
    let left = end
        .checked_sub(now()?)
        .context("original final wall deadline expired")?;
    ensure!(left > 0, "original final wall deadline exhausted");
    Ok(Instant::now() + Duration::from_secs(left))
}
fn original_actor(v: &Value, actor: &str, iid: &str, ready: &Value) -> Result<()> {
    let expected_pid = n(ready, "pid")?.to_string();
    ensure!(
        v["Id"] == actor
            && v["InvocationID"] == iid
            && v["ActiveState"] == "activating"
            && v["SubState"] == "start-pre"
            && v["MainPID"] == "0"
            && v["ControlPID"].as_str() == Some(expected_pid.as_str())
            && v["NRestarts"] == "0"
            && v["Job"] == "",
        "original actor no longer exact unrestarted start-pre ControlPID"
    );
    Ok(())
}
fn dormant(v: &Value, timer: bool) -> Result<()> {
    ensure!(
        v["ActiveState"] == "inactive" && v["InvocationID"] == "" && v["Job"] == "",
        "original guard/timer already active or previously used"
    );
    if timer {
        ensure!(
            v["LastTriggerUSecMonotonic"] == "0",
            "original timer already triggered"
        )
    } else {
        ensure!(
            v["MainPID"] == "0" && v["ControlPID"] == "0" && v["NRestarts"] == "0",
            "original guard not dormant"
        )
    }
    Ok(())
}
fn numeric_property(v: &Value, key: &str) -> Result<u64> {
    Ok(text(v, key)?.parse()?)
}
fn first_guard_native(guard: &Value, timer: &Value, receipt: &Value, ready: &Value) -> Result<()> {
    ensure!(
        guard["InvocationID"] == receipt["guard_invocation_id"]
            && guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0"
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && guard["Job"] == ""
            && guard["NRestarts"] == "0"
            && guard["ActiveState"] == "inactive"
            && timer["ActiveState"] == "active"
            && timer["Unit"] == guard["Id"]
            && receipt["actor_pid"] == ready["pid"]
            && receipt["actor_start_ticks"] == ready["start_ticks"],
        "original first guard has no actual matching completed no-trip native success"
    );
    let trigger =
        crate::native_timer::native_timer_micros(text(timer, "LastTriggerUSecMonotonic")?)?;
    let start = numeric_property(guard, "ExecMainStartTimestampMonotonic")?;
    ensure!(
        trigger > 0
            && start >= trigger
            && start - trigger <= 5_000_000
            && receipt["timer_last_trigger_monotonic_micros"] == trigger
            && receipt["guard_start_monotonic_micros"] == start,
        "first guard is not bound to the actual native timer activation"
    );
    Ok(())
}

pub fn execute(
    c: &ContextFile,
    route: &Route,
    own: &Bound,
    task: &Value,
    envelope: &Value,
    admission: &Value,
) -> Result<()> {
    crate::validate_context(c, route, own, task, envelope, admission, now()?)?;
    let iid = text(task, "actor_invocation_id")?;
    let ready = &task["ready"];
    let started = n(ready, "started_at")?;
    let setup_end = n(task, "original_setup_deadline_unix_seconds")?;
    let request_owner =
        crate::start_request::Owner::from_ready(text(task, "actor_unit")?, iid, ready, setup_end)?;
    let request_handoff = storage::json(&c.original_start_request_handoff)?;
    crate::start_request::validate_detached(&request_handoff, &request_owner)?;
    ensure!(
        setup_end
            .checked_sub(now()?)
            .is_some_and(|left| left >= 120),
        "post-reader original600s setup cannot fund finite final attempt; no clock renewal"
    );
    let setup_until = wall_limit(setup_end)?;
    let registry = Path::new(REGISTRY).join(iid);
    let status_bound = binding(&task["current_task"])?;
    let status = storage::json(&status_bound)?;
    ensure!(
        status["authenticated_readback"] == true
            && status["owner_evidence"]["current_operator"] == "/root"
            && status["after_status"]["phase"] == "verification",
        "actual Root status source missing"
    );
    let eta = n(&status["after_status"], "estimated_remaining_millis")?;
    ensure!(eta > 0, "positive active ETA must be positive");
    let registration = storage::json(&c.registration)?;
    ensure!(
        registration["task"] == json!(c.task) && registration["actor_invocation_id"] == iid,
        "registration does not bind original captured task/IID"
    );
    let completed = storage::json(&c.original_reader_completion)?;
    let reader = storage::json(&c.original_reader)?;
    ensure!(
        reader["image"] == json!(route.helper.image)
            && completed["reader_proof"] == json!(c.original_reader)
            && completed["program"] == reader["image"]
            && completed["original_outer_reaped"] == true
            && completed["original_cgroup_empty"] == true
            && completed["original_descriptors_drained"] == true
            && completed["original_native"]["InvocationID"] == reader["invocation_id"]
            && completed["original_native"]["Result"] == "success"
            && completed["original_native"]["ExecMainStatus"] == "0",
        "real same-image original reader completion/drain missing"
    );
    let actor = text(task, "actor_unit")?;
    let guard = text(envelope, "guard_unit")?;
    let timer = text(envelope, "timer_unit")?;
    let admission_sha = text(&task["admission"], "sha256")?;
    ensure!(
        actor.starts_with("horizon-qualify-185-capped-cold-")
            && crate::unit_name(actor)
            && timer == guard.replace(".service", ".timer"),
        "exact positive native unit family"
    );
    let token_root = PathBuf::from(text(envelope, "token_root")?);
    ensure!(
        token_root.parent() == Some(Path::new("/usr/local/lib/jetstreamer"))
            && token_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch185-")),
        "exact admitted token root namespace"
    );
    let token_dest = token_root.join(iid);
    let guard_root = PathBuf::from(text(envelope, "guard_receipt_root")?);
    ensure!(
        guard_root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && guard_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("epoch185-")),
        "exact admitted guard receipt root"
    );
    for name in [
        "fleet-spec",
        "producer-specs",
        "originals",
        "readable-specs",
        "views",
    ] {
        ensure!(
            !package(name, iid).try_exists()?,
            "positive final package previously used"
        );
    }
    ensure!(
        !token_dest.try_exists()?,
        "actual-IID token destination already exists"
    );
    for (_, file) in KINDS {
        ensure!(
            !registry.join(file).try_exists()?,
            "original final proof name already used"
        )
    }
    for name in [
        "readable-fleet-acceptance.json",
        "readable-reader-acceptance.json",
        "readable-task-acknowledgment.json",
        "readable-status-readback.json",
        "lifecycle.json",
    ] {
        ensure!(
            !registry.join(name).try_exists()?,
            "original final/lifecycle output previously used"
        );
    }
    let booking = storage::json(&c.normal_pool_booking)?;
    let pool_deadline = wall_limit(n(&booking, "expires_at")?)?;
    let mut r = Runner {
        root: &c.work_root,
        helper: &route.helper.image,
        self_image: own,
        iid,
        registry: &registry,
        deadline: setup_until,
        pool_deadline,
        sequence: 0,
    };
    original_actor(&r.native(actor)?, actor, iid, ready)?;
    dormant(&r.native(guard)?, false)?;
    dormant(&r.native(timer)?, true)?;
    let fleet_spec = source(
        r.root,
        "fleet-spec-source.json",
        &json!({
        "schema":"horizon-epoch185-genuine-fleet-acceptance-spec-v1","registration":c.registration,
        "actual_fleet":c.actual_fleet,"actual_fleet_plan":c.actual_fleet_plan,
        "numeric_delivery_eta_millis":eta,"output":output(&registry,"fleet-acceptance.json")}),
    )?;
    let sealed = seal(
        &mut r,
        "fleet-spec",
        &package("fleet-spec", iid),
        &[("spec.json", fleet_spec)],
    )?;
    r.helper(Helper::Fleet, &member(&sealed, "spec.json")?)?;
    let (fleet_bound, fleet) = read_receipt(&registry, 0, iid, ready, admission_sha)?;
    // First ORIGINAL fleet acceptance starts the final30-second proof window.
    let first = n(&fleet, "sampled_at")?;
    let first_end = first
        .checked_add(30)
        .context("first fleet clock overflow")?
        .min(setup_end);
    r.deadline = wall_limit(first_end)?.min(setup_until);
    let reader_spec = source(
        r.root,
        "reader-spec-source.json",
        &json!({
        "schema":"horizon-epoch185-complete-current-reader-acceptance-spec-v1","registration":c.registration,
        "fleet_acceptance":fleet_bound,"original_reader":c.original_reader,
        "original_reader_completion":c.original_reader_completion,"output":output(&registry,"reader-acceptance.json")}),
    )?;
    let make_task_spec = |kind: &str, name: &str| {
        json!({
        "schema":"horizon-epoch185-task-status-bridge-spec-v1","kind":kind,"task":c.task,
        "status_readback":status_bound,"expected_actor_unit":actor,"expected_actor_invocation_id":iid,
        "expected_ready":task["ready_binding"],"output":output(&registry,name)})
    };
    let ack_spec = source(
        r.root,
        "ack-spec-source.json",
        &make_task_spec("task_acknowledgment", "task-acknowledgment.json"),
    )?;
    let status_spec = source(
        r.root,
        "status-spec-source.json",
        &make_task_spec("status_readback", "status-readback.json"),
    )?;
    let producers = seal(
        &mut r,
        "producer-specs",
        &package("producer-specs", iid),
        &[
            ("reader.json", reader_spec),
            ("ack.json", ack_spec),
            ("status.json", status_spec),
        ],
    )?;
    r.helper(Helper::Reader, &member(&producers, "reader.json")?)?;
    r.helper(Helper::TaskStatus, &member(&producers, "ack.json")?)?;
    r.helper(Helper::TaskStatus, &member(&producers, "status.json")?)?;
    let mut raw = Vec::new();
    let mut stamps = [0; 4];
    let mut originals = Vec::new();
    let original_names = ["fleet.json", "reader.json", "task.json", "status.json"];
    for (i, _) in original_names.iter().enumerate() {
        let (b, v) = read_receipt(&registry, i, iid, ready, admission_sha)?;
        stamps[i] = n(&v, "sampled_at")?;
        let original = binding(&v["underlying_accepted_proof"])?;
        originals.push((original_names[i], original));
        raw.push((b, v));
    }
    let end = critical_deadline(started, setup_end, stamps, now()?, 10)?;
    r.deadline = wall_limit(end)?.min(setup_until);
    let copies = seal(&mut r, "originals", &package("originals", iid), &originals)?;
    let readable_names = [
        "readable-fleet-acceptance.json",
        "readable-reader-acceptance.json",
        "readable-task-acknowledgment.json",
        "readable-status-readback.json",
    ];
    let mut specs = Vec::new();
    for (i, _) in original_names.iter().enumerate() {
        let spec = source(
            r.root,
            &format!("readable-{i}-source.json"),
            &json!({
            "schema":"horizon-epoch185-readable-original-proof-spec-v1","task":c.task,
            "original_bridge":raw[i].0,"readable_underlying":member(&copies,original_names[i])?,
            "normal_copy_seal":copies.receipt,"output":output(&registry,readable_names[i])}),
        )?;
        specs.push((original_names[i], spec));
    }
    let lifecycle_spec = source(
        r.root,
        "lifecycle-spec-source.json",
        &json!({
        "schema":"horizon-epoch185-native-retained-capture-spec-v2","registration":c.registration,
        "previous_fleet":c.actual_fleet,"previous_plan":c.actual_fleet_plan,
        "prestart_fleet_acceptance":raw[0].0,"prestart_reader_acceptance":raw[1].0,
        "lifecycle":null,"output":output(&registry,"lifecycle.json")}),
    )?;
    specs.push(("lifecycle.json", lifecycle_spec));
    let readable_specs = seal(
        &mut r,
        "readable-specs",
        &package("readable-specs", iid),
        &specs,
    )?;
    for name in original_names {
        r.helper(Helper::Readable, &member(&readable_specs, name)?)?
    }
    let mut views = Vec::new();
    for (i, _) in readable_names.iter().enumerate() {
        let b = process::bind_file(&output(&registry, readable_names[i]), 4 << 20)?;
        let v = storage::json(&b)?;
        ensure!(
            v["sampled_at"] == raw[i].1["sampled_at"]
                && v["kind"] == KINDS[i].0
                && v["original_bridge"] == json!(raw[i].0)
                && v["underlying_accepted_proof"] == json!(member(&copies, original_names[i])?),
            "readable view changed original proof clock/source or kind"
        );
        views.push((readable_names[i], b));
    }
    let final_views = seal(&mut r, "views", &package("views", iid), &views)?;
    let mut sol = Vec::new();
    for name in readable_names {
        sol.push(member(&final_views, name)?)
    }
    for name in original_names {
        sol.push(member(&copies, name)?)
    }
    r.sol_read(&sol)?;
    critical_deadline(started, setup_end, stamps, now()?, 10)?;
    // Arm both event listeners before the only timer activation. No actor
    // restart, manual guard invocation, retry, or token replacement is allowed.
    let guard_watch = events::Watch::new(&guard_root)?;
    let control = PathBuf::from(text(envelope, "control_root")?);
    let main_watch = events::Watch::new(&control)?;
    let since = now()?;
    r.start_timer(timer)?;
    let (guard_binding, first_guard) =
        guard_watch.guard(&guard_root, actor, iid, admission_sha, r.deadline)?;
    let journal_raw = r.root.join("ORIGINAL_FIRST_GUARD_PID1.jsonl");
    let journal = events::guard_completed(
        guard,
        text(&first_guard, "guard_invocation_id")?,
        since,
        r.deadline,
        &journal_raw,
    )?;
    source(
        r.root,
        "ORIGINAL_FIRST_GUARD_PID1.json",
        &json!({"unit":guard,
        "invocation_id":first_guard["guard_invocation_id"],"original_rows":journal,
        "original_raw_journal":process::bind_file(&journal_raw,1<<20)?}),
    )?;
    first_guard_native(&r.native(guard)?, &r.native(timer)?, &first_guard, ready)?;
    // All original reader/native/readability gates and the real first guard
    // passed while Job was empty. Restore only the scheduler request for this
    // same still-held process so PID1 emits its normal start-done at main entry.
    // Runner retains the original final30s/pool deadlines for every command.
    let restored_request = crate::start_request::restore(&mut r, &request_owner, &request_handoff)?;
    let restored_request = source(
        r.root,
        "ORIGINAL_START_REQUEST_RESTORED.json",
        &restored_request,
    )?;
    let issued = now()?;
    let expires = setup_end
        .min(n(admission, "expires_at")?)
        .min(issued.checked_add(15).context("token expiry overflow")?);
    release_policy(
        started,
        setup_end,
        stamps,
        n(&first_guard, "sampled_at")?,
        issued,
        expires,
        issued,
    )?;
    let token = json!({"schema":"horizon-epoch185-native-gate-v4","epoch":185,"actor_unit":actor,
        "actor_invocation_id":iid,"admission_sha256":admission_sha,"driver_sha256":route.driver.sha256,
        "ready_pid":ready["pid"],"ready_start_ticks":ready["start_ticks"],"ready_sha256":task["ready_sha256"],
        "guard_unit":guard,"timer_unit":timer,"guard_result":first_guard,"issued_at":issued,"expires_at":expires,
        "fleet_enrollment":member(&final_views,readable_names[0])?,
        "current_reader_native_acceptance":member(&final_views,readable_names[1])?,
        "task_acknowledgment":member(&final_views,readable_names[2])?,
        "status_readback":member(&final_views,readable_names[3])?});
    let token_source = source(r.root, "original-token-source.json", &token)?;
    let token_seal = seal(
        &mut r,
        "token",
        &token_dest,
        &[("token.json", token_source)],
    )?;
    main_watch.main_event(
        &control.join("private-stdout-stderr.log"),
        wall_limit(expires)?.min(r.deadline),
    )?;
    // Only post-release AUTHENTICATION may use the still-original600s budget.
    // No token, service, timer, admission or proof clock is changed after here.
    r.deadline = setup_until.min(Instant::now() + Duration::from_secs(22));
    r.helper(
        Helper::Lifecycle,
        &member(&readable_specs, "lifecycle.json")?,
    )?;
    let lifecycle_bound = process::bind_file(&output(&registry, "lifecycle.json"), 4 << 20)?;
    let lifecycle = storage::json(&lifecycle_bound)?;
    ensure!(
        lifecycle["schema"] == "horizon-epoch185-native-retained-lifecycle-v2"
            && lifecycle["actor_invocation_id"] == iid
            && lifecycle["task"] == json!(c.task)
            && lifecycle["release"]["token"] == json!(member(&token_seal, "token.json")?)
            && lifecycle["release"]["first_guard"] == json!(guard_binding),
        "qualified lifecycle did not prove this original actual release"
    );
    let main_entered = n(&lifecycle["release"], "released_at")?;
    release_policy(
        started,
        setup_end,
        stamps,
        n(&token["guard_result"], "sampled_at")?,
        issued,
        expires,
        main_entered,
    )?;
    source(
        r.root,
        "ORIGINAL_POSITIVE_RELEASE_AUTHENTICATED.json",
        &json!({
        "schema":"horizon-positive185-original-postreader-release-authenticated-v1",
        "original_task":c.task,"original_registration":c.registration,"original_reader":c.original_reader,
        "original_reader_completion":c.original_reader_completion,"original_lifecycle":lifecycle_bound,
        "original_start_request_handoff":c.original_start_request_handoff,
        "actual_original_start_request_restored":restored_request,
        "original_ready_started_at":started,"original_setup_deadline":setup_end,
        "original_acceptance_sampled_at":stamps,"actual_original_main_entry":main_entered,
        "normal_token_seal":token_seal.receipt,"all_existing_metadata_clocks_preserved":true,
        "epoch_completion_claimed":false,"publication_authorized":false,"resource_credit_bytes":0}),
    )?;
    println!("Original positive release authenticated; epoch completion/publication not claimed");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formatted_native_first_guard_matches_exact_driver11_receipt() {
        let trigger = 2508234141704u64;
        let start = trigger + 1000;
        let ready = json!({"pid":123,"start_ticks":987});
        let guard = json!({"Id":"guard.service","InvocationID":"a".repeat(32),"Result":"success",
            "ExecMainStatus":"0","MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","ActiveState":"inactive",
            "ExecMainStartTimestampMonotonic":start.to_string()});
        let timer = json!({"ActiveState":"active","Unit":"guard.service","LastTriggerUSecMonotonic":"4w 1d 43min 54.141704s"});
        let receipt = json!({"guard_invocation_id":"a".repeat(32),"actor_pid":123,"actor_start_ticks":987,
            "timer_last_trigger_monotonic_micros":trigger,"guard_start_monotonic_micros":start});
        first_guard_native(&guard, &timer, &receipt, &ready).unwrap();
        let mut crossed = receipt.clone();
        crossed["timer_last_trigger_monotonic_micros"] = json!(trigger + 1);
        assert!(first_guard_native(&guard, &timer, &crossed, &ready).is_err());
        for raw in [
            "0",
            "infinity",
            "18446744073709551616",
            "1.0000001s",
            "1us 1s",
        ] {
            let mut changed = timer.clone();
            changed["LastTriggerUSecMonotonic"] = json!(raw);
            assert!(first_guard_native(&guard, &changed, &receipt, &ready).is_err());
        }
    }
    #[test]
    fn long_reader_then_late_original_proofs_fit_without_refresh() {
        release_policy(1000, 1600, [1120, 1121, 1122, 1123], 1125, 1126, 1140, 1128).unwrap();
        assert!(
            release_policy(1000, 1600, [1010, 1121, 1122, 1123], 1125, 1126, 1140, 1128).is_err()
        );
    }
    #[test]
    fn irreducible30s_stage_budget_fails_before_timer_arm() {
        assert!(critical_deadline(1000, 1600, [1120; 4], 1141, 10).is_err());
        assert_eq!(
            critical_deadline(1000, 1600, [1120; 4], 1130, 10).unwrap(),
            1150
        );
    }
    #[test]
    fn main_entry_must_fit_original_four_clocks_and_token() {
        assert!(release_policy(1000, 1600, [1120; 4], 1125, 1126, 1200, 1151).is_err());
        assert!(release_policy(1000, 1600, [1120; 4], 1125, 1126, 1128, 1128).is_err());
    }
    #[test]
    fn no_clock_renewal_future_capture_or_changed_setup() {
        assert!(critical_deadline(1000, 1601, [1120; 4], 1126, 1).is_err());
        assert!(critical_deadline(1000, 1600, [1127; 4], 1126, 1).is_err());
        assert!(release_policy(1000, 1600, [1120; 4], 1127, 1126, 1140, 1128).is_err());
    }
    #[test]
    fn completed_guard_requires_actual_timer_monotonic_and_ready_binding() {
        let ready = json!({"pid":123,"start_ticks":987});
        let guard = json!({"Id":"guard.service","InvocationID":"a".repeat(32),"Result":"success",
            "ExecMainStatus":"0","MainPID":"0","ControlPID":"0","Job":"","NRestarts":"0","ActiveState":"inactive",
            "ExecMainStartTimestampMonotonic":"1001000"});
        let timer = json!({"ActiveState":"active","Unit":"guard.service","LastTriggerUSecMonotonic":"1000000"});
        let receipt = json!({"guard_invocation_id":"a".repeat(32),"actor_pid":123,"actor_start_ticks":987,
            "timer_last_trigger_monotonic_micros":1000000,"guard_start_monotonic_micros":1001000});
        first_guard_native(&guard, &timer, &receipt, &ready).unwrap();
        let mut bad = timer.clone();
        bad["LastTriggerUSecMonotonic"] = json!("0");
        assert!(first_guard_native(&guard, &bad, &receipt, &ready).is_err());
        let mut bad = guard;
        bad["ControlPID"] = json!("12");
        assert!(first_guard_native(&bad, &timer, &receipt, &ready).is_err());
    }
}
