//! Exact prospective enrollment and prestart charge for the already booked epoch 170 lane.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

const V10: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-metered-hourly-v10";
const V10_PROVIDER_SHA: &str = "07c9d8a9fa3dda492348eff10e6eac13e9f496abb5d380f076b436e52e498e90";
const V10_SEAL_SHA: &str = "dd7b7dea1f90c170e6942b329980964b238fc5e539194e66519a55b940d253a6";
const V5W: &str = "incident-replay-fit-20261121-v1/tools-homefloor-145-v5v-custody-recovery-v1";

const HOST_MEMORY_WITH_RESERVE: u64 = 810_658_050_048;
const HOST_CPU_MICROS: u64 = 64_000_000;
const MAX_QUOTE_AGE: u64 = 120;

pub(super) fn enrollment_path(fleet_sha: &str) -> PathBuf {
    rt(BASE).join(format!("OBSERVER_ENROLLMENT-{fleet_sha}.json"))
}

fn unused_route(active: &Value) -> Result<()> {
    let active_timer = string(active, "timer")?;
    let timer = properties(active_timer)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["SubState"] == "waiting"
            && !Path::new(string(active, "next_output")?).exists(),
        "coordinated observer already advanced or is absent"
    );
    ensure!(
        timer["Triggers"]
            == format!(
                "{}.service",
                active_timer
                    .strip_suffix(".timer")
                    .context("wrong cadence timer")?
            ),
        "different coordinated observer trigger"
    );
    for peer in active["replays"]
        .as_array()
        .context("missing current producer roster")?
    {
        let m = properties(string(peer, "unit")?)?;
        ensure!(
            m["ActiveState"] == "active"
                && m["NRestarts"] == "0"
                && m["InvocationID"] == peer["invocation_id"],
            "coordinated peer changed"
        );
    }
    for unit in [UNIT, TIMER, GUARD_UNIT] {
        let m = properties(unit)?;
        ensure!(
            m["LoadState"] == "not-found" && m["ActiveState"] == "inactive",
            "candidate or guard already exists: {unit}"
        );
    }
    Ok(())
}

fn enrollment_body(
    observer: &Value,
    guard: &Value,
    cadence: &Value,
    log_device: u64,
    log_inode: u64,
) -> Result<Value> {
    let active = &observer["active_fleet"];
    let mut candidate = observer
        .as_object()
        .context("missing candidate observer route")?
        .clone();
    candidate.remove("active_fleet");
    candidate.remove("incumbent_unit");
    candidate.insert("log_device".to_owned(), json!(log_device));
    candidate.insert("log_inode".to_owned(), json!(log_inode));
    Ok(
        json!({"schema":"horizon-epoch170-metered-observer-enrollment-v1",
        "prospective_only":true,"fleet":active["fleet"],"previous_sample":active["observer"],
        "incumbent_timer":active["timer"],"scheduled_observer":active["next_observer"],
        "incumbent_registration":cadence["registration"],"incumbent":cadence["incumbent"],
        "guard_qualification":guard["qualification"],"candidate_root":guard["root"],
        "candidate":candidate,"activation_granted":false,"observer_switch_performed":false}),
    )
}

pub(super) fn enrollment(profile: &Value, guard_sha: &str, incumbent: &Value) -> Result<Value> {
    let observer = &profile["observer"];
    let active = &observer["active_fleet"];
    unused_route(active)?;
    let guard = guard_ready(profile, guard_sha)?;
    let first = cadence_registration(incumbent)?;
    let log_path = Path::new(string(observer, "append_log")?);
    let log = file(log_path, 0)?;
    let m = log.metadata()?;
    ensure!(
        m.len() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o600,
        "prepare the dedicated root-owned empty append log before recording enrollment"
    );
    ensure!(
        first == cadence_registration(incumbent)?,
        "cadence owner changed during enrollment"
    );
    unused_route(active)?;
    stable(log_path, &log, &m)?;
    enrollment_body(observer, &guard, &first, m.dev(), m.ino())
}

fn retained_booking(
    native: &Value,
    profile: &Value,
    enrollment: &Value,
    enrollment_ref: &Value,
    now: u64,
) -> Result<Value> {
    let observer = &profile["observer"];
    let active = &observer["active_fleet"];
    let book = &native["bookings"]["170"];
    let terminal = &profile["previous"]["terminal"];
    let physical = number(book, "physical_bytes")?;
    let remaining = number(book, "remaining_bytes")?;
    let age = now
        .checked_sub(number(native, "recorded_unix_seconds")?)
        .context("native capture timestamp is in the future")?;
    ensure!(
        age <= MAX_QUOTE_AGE
            && native["schema"] == "horizon-incident-replay-fit-v1"
            && native["epoch"] == 145
            && native["fleet"] == active["fleet"]
            && native["fits"] == true
            && native["candidate"].is_null()
            && native["bounded_qualification"].is_null()
            && native["replacements"].get("170").is_none()
            && native["status_registration"]["invocation_id"]
                == enrollment["incumbent"]["invocation_id"]
            && native["failed_cold170"]["terminal"] == *terminal
            && native["failed_cold170"]["reservation_ending_bytes"] == 0
            && native["resource_credit_bytes"] == 0
            && native["replay_launch_authorized"] == false
            && native["complete_cpu_quota_micros"] == HOST_CPU_MICROS
            && native["complete_memory_plus_reserve_bytes"] == HOST_MEMORY_WITH_RESERVE
            && book["root"] == LANE
            && book["run"] == json!(run(OLD_RUN))
            && book["cap_bytes"] == CAP
            && book["measurement"] == "two complete stopped-tree walks"
            && physical.checked_add(remaining) == Some(CAP)
            && remaining > 0,
        "native capture does not fund the exact retained epoch 170 booking"
    );
    let available = number(native, "available_HOME_bytes")?;
    let needed = number(native, "complete_required_HOME_bytes")?;
    let fully_booked_floor = number(native, "protected_raw_floor_bytes")?;
    let mut absolute = MIN_FLOOR.max(number(native, "active168_guard_floor")?);
    if let Some(floor) = native["candidate136"]["guard_floor"].as_u64() {
        absolute = absolute.max(floor);
    }
    for peer in native["survivors"]
        .as_object()
        .context("missing native survivor guards")?
        .values()
    {
        absolute = absolute.max(number(&peer["guard"], "floor")?);
    }
    for lane in native["replacements"]
        .as_object()
        .context("missing replacement guards")?
        .values()
    {
        absolute = absolute.max(number(lane, "floor")?);
    }
    // The base is a whole-fleet quote and already includes exactly one term
    // for this 384 GiB tree. Preserve every incumbent floor and the full
    // borrower's remaining allowance. No predecessor bytes become credit.
    ensure!(
        fully_booked_floor <= needed,
        "invalid complete-fleet capture"
    );
    let floor = needed
        .checked_sub(remaining)
        .context("candidate exceeds funded whole-fleet requirement")?
        .max(absolute);
    let complete = needed.max(
        floor
            .checked_add(remaining)
            .context("candidate budget overflow")?,
    );
    ensure!(
        available >= complete
            && number(native, "available_memory_bytes")?
                >= number(native, "required_available_memory_bytes")?,
        "full metered 170 does not fit within the retained whole-tree booking"
    );
    let mut quote = native.clone();
    quote["epoch"] = json!(170);
    quote["protected_raw_floor_bytes"] = json!(floor);
    quote["complete_required_HOME_bytes"] = json!(complete);
    quote["bookings"]["170"]["run"] = profile["actor"]["run"].clone();
    quote["epoch170_metered_full"] = json!({"stage":"prestart", "producer_unit":UNIT,"guard_timer":TIMER,
        "worker_sha256":WORKER_SHA,"source_profile_sha256":sha(&serde_json::to_vec(profile)?),
        "guard_qualification":enrollment["guard_qualification"],"candidate_root":enrollment["candidate_root"],
        "observer_enrollment":enrollment_ref,"retained_retry13_terminal":terminal,
        "prior_run":book["run"],"prestart_whole_tree_physical_bytes":physical,"remaining_whole_tree_bytes":remaining,
        "original_complete_required_home_bytes":needed,"reassigned_prepaid_bookings":1,
        "absolute_incumbent_floor_bytes":absolute,"first_guard_required_before_release":true,
        "resource_credit_bytes":0});
    Ok(quote)
}

pub(super) fn quote(
    profile: &Value,
    guard_sha: &str,
    enrollment_ref: &Value,
    route: &str,
    provider_seal_sha: &str,
) -> Result<Value> {
    let active = &profile["observer"]["active_fleet"];
    let fleet = &active["fleet"];
    ensure!(
        enrollment_ref["path"] == json!(enrollment_path(string(fleet, "sha256")?)),
        "foreign enrollment path for selected fleet"
    );
    let candidate = bound(enrollment_ref, 0)?;
    ensure!(
        candidate == enrollment(profile, guard_sha, &candidate["incumbent_registration"])?,
        "candidate enrollment differs from current ownership"
    );
    let provider = match route {
        "v10" => {
            ensure!(
                provider_seal_sha == V10_SEAL_SHA,
                "wrong retained v10 provider seal"
            );
            rt(V10)
        }
        "v5w" => rt(V5W),
        _ => bail!("unknown epoch 170 capacity provider deployment"),
    };
    let sealed = reference(
        &provider.join("deployment-seal-receipt.json"),
        provider_seal_sha,
    );
    let seal = bound(&sealed, 0)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(provider),
        "foreign native provider seal"
    );
    let member = seal["members"]
        .as_array()
        .context("missing native provider members")?
        .iter()
        .find(|row| row["name"] == "post-stop-fit")
        .context("native capacity provider absent from seal")?;
    let program_sha = string(member, "sha256")?;
    ensure!(
        route != "v10" || program_sha == V10_PROVIDER_SHA,
        "foreign retained v10 native provider executable"
    );
    let program = reference(&provider.join("post-stop-fit"), program_sha);
    image(&program)?;
    let mut command = Command::new("/usr/bin/timeout");
    command.args(["150", "/usr/bin/python3", "-IB", string(&program, "path")?]);
    if route == "v10" {
        command.arg("--hourly170=prestart");
    }
    let output = command
        .args(["145", string(fleet, "path")?, string(fleet, "sha256")?])
        .output()?;
    ensure!(
        output.status.success(),
        "sealed {route} fleet provider rejected the complete current roster: {}",
        output.status
    );
    let native: Value =
        serde_json::from_slice(&output.stdout).context("invalid native provider output")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut result = retained_booking(&native, profile, &candidate, enrollment_ref, now)?;
    ensure!(
        cadence_registration(&candidate["incumbent_registration"])?["incumbent"]
            == candidate["incumbent"],
        "cadence owner changed during live pricing"
    );
    unused_route(active)?;
    result["epoch170_metered_full"]["native_capture_receipt"] = json!({"program":program,"deployment":sealed,
        "source_json_sha256":sha(&output.stdout),"source_epoch":145,"recorded_unix_seconds":native["recorded_unix_seconds"]});
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> (Value, Value, Value, Value) {
        let fleet = json!({"path":"/fleet","sha256":"fleet"});
        let terminal = json!({"path":"/retry13","sha256":"123"});
        let profile = json!({"actor":{"run":run(NEW_RUN)},"previous":{"terminal":terminal},"observer":{"candidate_range":"170","producer_unit":UNIT,
            "worker_sha256":WORKER_SHA,"active_fleet":{"fleet":fleet,"observer":"sample","timer":"timer","next_observer":"next"}}});
        let guard = json!({"qualification":"qualified","root":"root"});
        let cadence = json!({"registration":"active","incumbent":{"invocation_id":"writer"}});
        let enrollment =
            enrollment_body(&profile["observer"], &guard, &cadence, 64512, 77).unwrap();
        let enrollment_ref = json!({"path":"/enroll","sha256":"hash"});
        let native = json!({"schema":"horizon-incident-replay-fit-v1","epoch":145,"fleet":fleet,"recorded_unix_seconds":1000,"fits":true,"candidate":null,
            "bounded_qualification":null,"status_registration":{"invocation_id":"writer"},"failed_cold170":{"terminal":terminal,"reservation_ending_bytes":0},
            "resource_credit_bytes":0,"replay_launch_authorized":false,"complete_cpu_quota_micros":HOST_CPU_MICROS,"complete_memory_plus_reserve_bytes":HOST_MEMORY_WITH_RESERVE,
            "bookings":{"170":{"root":LANE,"run":run(OLD_RUN),"cap_bytes":CAP,"measurement":"two complete stopped-tree walks","physical_bytes":CAP-(2<<30),"remaining_bytes":2u64<<30}},
            "available_HOME_bytes":MIN_FLOOR+(6u64<<30),"complete_required_HOME_bytes":MIN_FLOOR+(5u64<<30),
            "protected_raw_floor_bytes":MIN_FLOOR+(5u64<<30),"active168_guard_floor":MIN_FLOOR+(4u64<<30),
            "candidate136":{"guard_floor":MIN_FLOOR+177},"survivors":{},"replacements":{},"available_memory_bytes":123,"required_available_memory_bytes":111});
        (native, profile, enrollment, enrollment_ref)
    }

    #[test]
    fn enrollment_binds_old_cadence_and_new_log_without_a_claim() {
        let (_, _, e, _) = case();
        assert_eq!(e["incumbent"]["invocation_id"], "writer");
        assert_eq!(e["candidate"]["log_inode"], 77);
        assert_eq!(e["candidate"]["worker_sha256"], WORKER_SHA);
        assert_eq!(e["activation_granted"], false);
    }

    #[test]
    fn quote_rebooks_once_and_preserves_the_highest_incumbent_floor() {
        let (n, p, e, r) = case();
        let q = retained_booking(&n, &p, &e, &r, 1010).unwrap();
        assert_eq!(q["epoch"], 170);
        assert_eq!(q["bookings"]["170"]["run"], p["actor"]["run"]);
        assert_eq!(q["protected_raw_floor_bytes"], MIN_FLOOR + (4u64 << 30));
        assert_eq!(q["complete_required_HOME_bytes"], MIN_FLOOR + (6u64 << 30));
        assert_eq!(q["epoch170_metered_full"]["observer_enrollment"], r);
        assert_eq!(q["resource_credit_bytes"], 0);
    }

    #[test]
    fn quote_rejects_stale_or_already_spent_capacity_and_live_competitors() {
        let (n, p, e, r) = case();
        assert!(retained_booking(&n, &p, &e, &r, 1121).is_err());
        for (field, value) in [
            ("resource_credit_bytes", json!(1)),
            ("available_HOME_bytes", json!(MIN_FLOOR)),
            ("replacements", json!({"170":{"floor":MIN_FLOOR}})),
            ("status_registration", json!({"invocation_id":"old"})),
        ] {
            let mut bad = n.clone();
            bad[field] = value;
            assert!(
                retained_booking(&bad, &p, &e, &r, 1010).is_err(),
                "accepted {field}"
            );
        }
    }
}
