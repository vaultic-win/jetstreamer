//! Exact prospective enrollment and prestart charge for the already booked epoch 170 lane.
use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

const V10: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-metered-hourly-v10";
const V10_PROVIDER_SHA: &str = "07c9d8a9fa3dda492348eff10e6eac13e9f496abb5d380f076b436e52e498e90";
const V10_SEAL_SHA: &str = "dd7b7dea1f90c170e6942b329980964b238fc5e539194e66519a55b940d253a6";
const V5W: &str = "incident-replay-fit-20261121-v1/tools-homefloor-145-v5v-custody-recovery-v1";
const FULL170: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-v1";
const FULL170_V9: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-v3";
const FULL170_V13: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-v5";
const FULL170_RETRY5: &str = "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-v6";
const FULL170_RETRY5_V10: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-v7";
const FULL170_INDEPENDENT: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-independent-v1";
const FULL170_AFTER_STOP: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-170-full-metered-independent-v4";
const RETRY5_UNIT: &str = "horizon-qualify-168-full-metered-cold-v5-20261125.service";
const RETRY5_TIMER: &str = "horizon-guard-168-full-metered-cold-v5-20261125.timer";
const V12_REGISTRATION: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V12_ACTIVE.json";
const V12_ACTIVE_SHA: &str = "b42e7b3c5327438cd355357f73f2574c05ffbd67fd9597aa7d05c17f8324cc54";
pub(super) const V13_REGISTRATION: &str =
    "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V13_ACTIVE.json";
const V13_READY: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V13_READY.json";
const V13_PACKAGE: &str =
    "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v13-entry146";
const V13_RECEIVER_SHA: &str = "4ec9ca4476a6e8ed21090e9dfeb58582916b00610f5145a9181a8cadc0dbb695";
const V13_WRITER_SHA: &str = "3d2401bb1bfe9a65f68503c2feca30c0630ea876ad04fa01d1a6a5eda374e8ab";
pub(super) const V14_REGISTRATION: &str =
    "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V14_ACTIVE.json";
const V14_READY: &str = "survivor172-cadence-20261122-v1/FAILED166_CADENCE_V14_READY.json";
const V14_PACKAGE: &str =
    "survivor172-cadence-20261122-v1/tools-cold168-retry5-failed166-v14-entry146";
const V14_RECEIVER_SHA: &str = "30e9b44288e02b17dccf4517ef0b03ed8088ac80d6e0a0313e8c8c0195ccdf82";
const V14_WRITER_SHA: &str = "960088fc35cf205c67a52c755810f8deb3518225695e366afd4216a794aed4b6";
const V14_SEAL_SHA: &str = "1b9f179d7ad7802c637f2203f0d1151b0a244b328fabc872936dcb11c54ec2fd";
const RETRY5_SHA: &str = "906eabc8de4ead288fcae3b514daff4a18786fd9e7200ff8fbbac6a96e933716";
const RETRY4_STOP_SHA: &str = "b0538a4dee05df924a8d04f8562866df701c03996498963552a932059826cdab";
const V9_PHASE: &str = "v9-semantic-complete-drained";
const V10_PHASE: &str = "v10-semantic-complete-drained";
const INDEPENDENT_PHASE: &str = "independent-semantic-complete-v10-drained";

const HOST_MEMORY_WITH_RESERVE: u64 = 810_658_050_048;
const HOST_CPU_MICROS: u64 = 64_000_000;
const MAX_QUOTE_AGE: u64 = 120;

struct VerifierCompletion {
    phase: &'static str,
    invocation: &'static str,
    handoff: &'static str,
    checker: &'static str,
    checker_sha: &'static str,
    submission_sha: &'static str,
    start_sha: &'static str,
    schema: &'static str,
}

const V9_COMPLETION: VerifierCompletion = VerifierCompletion {
    phase: V9_PHASE,
    invocation: "ebdfc34db47c4e7699ea5ccbada5d604",
    handoff: "epoch145-semantic-continuity-20261121-v1/v9-census-name-handoff",
    checker: "epoch145-semantic-continuity-20261121-v1/tools-v9-census-recovery",
    checker_sha: "8766c269034824f114eb1906e1913188f615309b51243e8e23ca111936efeebd",
    submission_sha: "33cef3c0ae1bc0aebe1bd8ab950c781c518ce646656f8ffbc66229aaf823c973",
    start_sha: "eaf570320604963b6270c1aa2854c48f6cc0c3a5254c829a699d9b6272e6b2c4",
    schema: "horizon-epoch145-v8-census-successor-semantic-completion-v1",
};

// These identities match retry5_fit.py's V10 owner used by the sealed pricing provider.
const V10_COMPLETION: VerifierCompletion = VerifierCompletion {
    phase: V10_PHASE,
    invocation: "104f023c5cd24a55b6585ef525b80067",
    handoff: "epoch145-semantic-continuity-20261121-v1/v10-census-name-handoff",
    checker: "epoch145-semantic-continuity-20261121-v1/tools-v10-census-recovery",
    checker_sha: "29aac4e0527dcea47f4e9bcb14c5e071b67b8d749669873cc04d7cd1cc5d4e75",
    submission_sha: "63afb9ef8ffa492e2fe12b05b9eccd6bd2e1c533d024f59ebeb21460e43da8cf",
    start_sha: "ed1dd13fb7803f31e90b7040b09359a484f0fef2608bce74a0c65bd2c37fa605",
    schema: "horizon-epoch145-v9-census-successor-semantic-completion-v1",
};

fn check_verifier_completion(
    owner: &VerifierCompletion,
    phase: &Value,
    completion: &Value,
) -> Result<()> {
    let handoff = rt(owner.handoff);
    let invocation = owner.invocation;
    let recovery = reference(
        &rt(&format!(
            "epoch145-guarded-export-20261121-v1/state/{invocation}/recovery-started.json"
        )),
        owner.start_sha,
    );
    let submission = reference(&handoff.join("START_RESULT.json"), owner.submission_sha);
    let checker = reference(
        &rt(owner.checker).join("deployment-seal-receipt.json"),
        owner.checker_sha,
    );
    let startup = &completion["startup_evidence"];
    let success = &completion["native_success"];
    ensure!(
        phase["stage"] == owner.phase
            && phase["completed_invocation_id"] == invocation
            && phase["Id"] == "horizon-holding-export145-20261121-v1.service"
            && phase["MainPID"] == "0"
            && phase["completion"]["path"] == json!(handoff.join("SEMANTIC_COMPLETION.json"))
            && phase["checker_seal"] == checker
            && completion["schema"] == owner.schema
            && completion["invocation_id"] == invocation
            && startup["invocation_id"] == invocation
            && startup["start"] == recovery
            && completion["start"] == recovery
            && startup["submission_result"] == submission
            && startup["worker_seal"] == checker
            && success["INVOCATION_ID"] == invocation
            && success["UNIT"] == "horizon-holding-export145-20261121-v1.service"
            && success["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && success["_PID"] == "1"
            && completion["publication_authorized"] == false
            && completion["r2_mutations"] == false,
        "different epoch 145 {} completion, checker, or startup custody",
        owner.phase
    );
    Ok(())
}

fn validate_verifier_phase(owner: &VerifierCompletion, phase: &Value) -> Result<()> {
    ensure!(
        phase["completion"]["path"] == json!(rt(owner.handoff).join("SEMANTIC_COMPLETION.json")),
        "different epoch 145 {} completion path",
        owner.phase
    );
    check_verifier_completion(owner, phase, &bound(&phase["completion"], 0)?)
}

fn validate_independent_phase(package: &Path, phase: &Value) -> Result<()> {
    let selection = &phase["selection"];
    ensure!(
        selection["path"] == json!(package.join("independent145-selection.json"))
            && phase["stage"] == INDEPENDENT_PHASE
            && phase["Id"] == "horizon-holding-export145-20261121-v1.service"
            && phase["MainPID"] == "0"
            && phase["previous_verifier_invocation_id"] == V10_COMPLETION.invocation
            && phase["resource_credit_bytes"] == 0,
        "incomplete independent epoch 145 handback"
    );
    let selection = bound(selection, 0)?;
    let terminal = &phase["semantic_receipt"];
    let (root, invocation) = match selection["candidate"].as_str() {
        Some("four") => (
            rt("epoch145-parallel-full-verification-20261126-v1"),
            "cb3313b857d94b9f82e06d5c033c0ac5",
        ),
        Some("scaled") => (
            rt("epoch145-parallel-full-verification-20261126-v1/scaled-candidate-v1"),
            "a89c1de125694cb3bdcef19a8c82848a",
        ),
        _ => bail!("unknown independent epoch 145 verification"),
    };
    ensure!(
        selection["schema"] == "horizon-epoch146-independent-145-selection-v1"
            && selection["terminal"] == *terminal
            && terminal["path"] == json!(root.join("INDEPENDENT_TERMINAL_ACCEPTED.json"))
            && phase["completed_invocation_id"] == invocation
            && phase["native_handback"]["stopped"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "different independent epoch 145 terminal selection"
    );
    let receipt = bound(terminal, 0)?;
    let report = &receipt["report"];
    ensure!(
        receipt["schema"] == "horizon-epoch145-independent-terminal-acceptance-v1"
            && receipt["epoch"] == 145
            && receipt["native"]["InvocationID"] == invocation
            && receipt["native"]["ExecMainStatus"] == "0"
            && report["invocation_id"] == invocation
            && report["archive_sha256"]
                == "df194137df5de51ae628160854cabafc9e180b4e7058cab3fba6aac4621a7b4d"
            && report["source_tail_verified"] == true
            && report["verified_canonical_slots"] == 432000
            && receipt["r2_mutations"] == false,
        "independent epoch 145 result does not prove the exact frozen archive"
    );
    Ok(())
}

fn validate_v13_actor(active: &Value, previous: &Value) -> Result<()> {
    let old = &previous["new"];
    let actor = &active["new"];
    ensure!(
        active["schema"] == "horizon-epoch166-cadence-rejoin-active-v1"
            && active["old"] == *old
            && actor["unit"] == old["unit"]
            && actor["invocation_id"] != old["invocation_id"]
            && number(actor, "start_ticks")? > number(old, "start_ticks")?
            && ["path", "device", "inode"]
                .iter()
                .all(|key| actor["lock"][*key] == old["lock"][*key]),
        "different V13 cadence actor or V12 predecessor"
    );
    Ok(())
}

pub(super) fn check_metered_cadence(
    active: &Value,
    ready: &Value,
    seal: &Value,
    after_stop: bool,
) -> Result<()> {
    let (ready_path, package_path, receiver_sha, writer_sha) = if after_stop {
        (V14_READY, V14_PACKAGE, V14_RECEIVER_SHA, V14_WRITER_SHA)
    } else {
        (V13_READY, V13_PACKAGE, V13_RECEIVER_SHA, V13_WRITER_SHA)
    };
    let package = rt(package_path);
    let previous_ref = reference(&rt(V12_REGISTRATION), V12_ACTIVE_SHA);
    let receiver = reference(&package.join("full170_status.py"), receiver_sha);
    ensure!(
        active["ready"]["path"] == json!(rt(ready_path))
            && ready["schema"] == "horizon-epoch166-cadence-rejoin-ready-v1"
            && ready["package"]["path"] == json!(package.join("deployment-seal-receipt.json"))
            && seal["destination"] == json!(package)
            && seal["remote_mutations"] == false
            && ready["old_owner"] == previous_ref
            && ready["full170_receiver"] == receiver
            && ready["retry5_generation"]
                == reference(&package.join("retry5-168-generation.json"), RETRY5_SHA)
            && ready["retained_retry4_stop"]
                == reference(
                    &rt("epoch168-retry4-rebook-20261123-v1/guard-receipts/stop-completion.json"),
                    RETRY4_STOP_SHA,
                )
            && active["new"]["program"] == json!(package.join("status_cycle.py")),
        "different V13 cadence receiver or V12 predecessor"
    );
    let members = seal["members"]
        .as_array()
        .context("missing metered cadence members")?;
    for (name, hash) in [
        ("full170_status.py", receiver_sha),
        ("status_cycle.py", writer_sha),
        ("retry5-168-generation.json", RETRY5_SHA),
    ] {
        let mut selected = members.iter().filter(|row| row["name"] == name);
        let member = selected
            .next()
            .context("missing sealed V13 cadence member")?;
        ensure!(
            member["mode"] == "0444" && member["sha256"] == hash && selected.next().is_none(),
            "different sealed V13 cadence member {name}"
        );
        image(&reference(&package.join(name), hash))?;
    }
    let fleet = bound(&ready["fleet"], 0)?;
    ensure!(
        ready["config"] == fleet["sole_next_observer"]
            && ready["timer"] == fleet["sole_next_timer"],
        "V13 changed the inherited observer clock"
    );
    if after_stop {
        let stop = &ready["retry5_scan_stop"];
        let terminal = bound(&stop["terminal"], 0)?;
        ensure!(
            ready["package"]["sha256"] == V14_SEAL_SHA
                && stop["producer_invocation_id"] == terminal["producer_invocation_id"]
                && stop["resource_credit_bytes"] == 0
                && stop["reservation_ending_bytes"] == 0,
            "different V14 stop or receiver"
        );
    }
    validate_v13_actor(active, &bound(&previous_ref, 0)?)
}

fn drained_provider(price: &Value, enrollment: &Value) -> Result<Option<PathBuf>> {
    let phase = &price["phase145"];
    let capture = &price["epoch170_metered_full"]["native_capture_receipt"];
    let incumbent = &enrollment["incumbent_registration"];
    let v13 = incumbent["path"] == json!(rt(V13_REGISTRATION));
    let v14 = incumbent["path"] == json!(rt(V14_REGISTRATION));
    let retry5 = !price["full170_retry5_owner"].is_null();
    let v10 = phase["stage"] == V10_PHASE;
    let independent = phase["stage"] == INDEPENDENT_PHASE;
    let package = rt(if v14 {
        FULL170_AFTER_STOP
    } else if independent {
        FULL170_INDEPENDENT
    } else {
        match (v13, retry5, v10) {
            (true, true, true) => FULL170_RETRY5_V10,
            (true, true, false) => FULL170_RETRY5,
            (true, false, _) => FULL170_V13,
            _ => FULL170_V9,
        }
    });
    let receipt = package.join("deployment-seal-receipt.json");
    let program = package.join("post-stop-fit");
    if !v13
        && incumbent["path"] != json!(rt(V12_REGISTRATION))
        && phase["stage"] != V9_PHASE
        && !v10
        && !independent
        && !retry5
        && ![
            FULL170_V9,
            FULL170_V13,
            FULL170_RETRY5,
            FULL170_RETRY5_V10,
            FULL170_INDEPENDENT,
        ]
        .iter()
        .any(|route| capture["program"]["path"] == json!(rt(route).join("post-stop-fit")))
        && !v14
    {
        return Ok(None);
    }
    let matching_cadence = if v14 {
        independent && !retry5 && !price["full170_retry5_stopped"].is_null()
    } else {
        (!(v10 || independent) || v13 && retry5)
            && (v13 || !retry5 && *incumbent == reference(&rt(V12_REGISTRATION), V12_ACTIVE_SHA))
    };
    ensure!(
        matching_cadence
            && capture["program"]["path"] == json!(program)
            && capture["deployment"]["path"] == json!(receipt)
            && capture["source_epoch"] == 145
            && capture["recorded_unix_seconds"] == price["recorded_unix_seconds"],
        "epoch 170 quote requires the registered cadence and its matching provider"
    );
    Ok(Some(package))
}

fn check_retry5_price(price: &Value, fleet: &Value) -> Result<()> {
    let rows: Vec<_> = fleet["actual_executing_replays"]
        .as_array()
        .context("missing current replay roster")?
        .iter()
        .filter(|row| row["epoch"] == 168)
        .collect();
    let owner = &price["full170_retry5_owner"];
    if owner.is_null() {
        ensure!(
            rows.is_empty(),
            "epoch 170 price omitted the live retry5 owner"
        );
        let stopped = &price["full170_retry5_stopped"];
        if !stopped.is_null() {
            let stop = &stopped["stop"];
            let terminal = bound(&stop["terminal"], 0)?;
            let producer = properties(RETRY5_UNIT)?;
            let timer = properties(RETRY5_TIMER)?;
            let floor = number(stopped, "floor")?;
            ensure!(
                *stop == fleet["cold168_retry5_physical_scan_stop"]
                    && stop["producer_invocation_id"] == terminal["producer_invocation_id"]
                    && floor > 0
                    && number(price, "active168_guard_floor")? == 0
                    && producer["ActiveState"] == "inactive"
                    && timer["ActiveState"] == "inactive"
                    && producer["MainPID"] == "0"
                    && timer["InvocationID"] == "",
                "epoch 170 lost the stopped retry5 budget"
            );
            check_retry5_budget(price, floor)?;
        }
        return Ok(());
    }
    let [row] = rows.as_slice() else {
        bail!("epoch 170 price requires one protected retry5 fleet row");
    };
    let peer = &price["replacements"]["168"];
    ensure!(
        owner["producer_unit"] == RETRY5_UNIT
            && row["unit"]["Id"] == RETRY5_UNIT
            && row["unit"]["InvocationID"] == owner["producer_invocation_id"]
            && row["start_ticks"] == owner["start_ticks"]
            && row["admission"] == owner["admission"]
            && !owner["admission"].is_null()
            && !owner["first_worker"].is_null()
            && owner["timer"] == RETRY5_TIMER
            && row["guard_timer"]["Id"] == RETRY5_TIMER
            && row["guard_timer"]["InvocationID"] == owner["timer_invocation_id"]
            && [
                "producer_unit",
                "producer_invocation_id",
                "producer_pid",
                "start_ticks",
                "admission",
                "plan",
                "timer",
                "timer_invocation_id",
                "floor",
                "processes"
            ]
            .iter()
            .all(|key| peer[*key] == owner[*key])
            && peer["processes"].as_array().is_some_and(|p| p.len() == 2)
            && !peer["guard"].is_null(),
        "different retry5 claimant, admission or guard in epoch 170 price"
    );
    let floor = number(owner, "floor")?;
    ensure!(
        number(price, "active168_guard_floor")? == floor,
        "different live retry5 floor"
    );
    check_retry5_budget(price, floor)
}

fn check_retry5_budget(price: &Value, floor: u64) -> Result<()> {
    let projection = &price["full170_retry5_projection"];
    let booking = &price["bookings"]["168"];
    let retry5 = &price["retry5_complete_booking"];
    let base = number(projection, "native_current_HOME_bytes")?;
    let zero = number(projection, "native_zero_remaining_HOME_bytes")?;
    let donor = number(projection, "donor_HOME_bytes")?;
    let growth = number(booking, "remaining_bytes")?;
    let lag = number(retry5, "outside_cap_stop_allowance_bytes")?;
    ensure!(
        0 < zero
            && zero <= base
            && base <= donor
            && floor > 0
            && number(retry5, "retained_guard_floor_bytes")? == floor
            && number(retry5, "retained_base_HOME_bytes")? == donor
            && number(retry5, "candidate_remaining_bytes")? == growth
            && number(booking, "cap_bytes")? == 512 << 30
            && number(booking, "physical_bytes")?.checked_add(growth) == Some(512 << 30)
            && lag == 8 << 30,
        "different retained retry5 allowance or disk floor"
    );
    let joint_required = donor
        .checked_add(lag)
        .and_then(|v| v.max(floor).checked_add(growth));
    let joint_zero = (donor - (base - zero))
        .checked_add(lag)
        .and_then(|v| v.max(floor).checked_add(growth));
    ensure!(
        joint_required == Some(number(projection, "funded_current_HOME_bytes")?)
            && joint_required == Some(number(retry5, "complete_required_HOME_bytes")?)
            && joint_required
                == Some(number(
                    &price["epoch159_donor_cover"],
                    "native_home_required"
                )?)
            && joint_required
                == Some(number(
                    &price["epoch170_metered_full"],
                    "original_complete_required_home_bytes"
                )?)
            && joint_zero == Some(number(projection, "funded_zero_remaining_HOME_bytes")?)
            && joint_zero == Some(number(price, "full170_zero_remaining_native_HOME_bytes")?),
        "epoch 170 did not charge retry5 exactly once in both projections"
    );
    Ok(())
}

pub(super) fn validate_drained_price(price: &Value, enrollment: &Value) -> Result<()> {
    let Some(package) = drained_provider(price, enrollment)? else {
        return Ok(());
    };
    let phase = &price["phase145"];
    let capture = &price["epoch170_metered_full"]["native_capture_receipt"];
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        now.checked_sub(number(price, "recorded_unix_seconds")?)
            .is_some_and(|age| age <= MAX_QUOTE_AGE),
        "stale or future epoch 170 quote"
    );
    let seal = bound(&capture["deployment"], 0)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(package)
            && (package == rt(FULL170_V9) || seal["remote_mutations"] == false)
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["name"] == "post-stop-fit"
                    && row["mode"] == "0555"
                    && row["sha256"] == capture["program"]["sha256"])),
        "epoch 170 quote provider differs from its sealed member"
    );
    image(&capture["program"])?;
    if package != rt(FULL170_V9) {
        let registration = cadence_registration(&enrollment["incumbent_registration"])?;
        let actor = &registration["incumbent"];
        let quoted = &price["status_registration"];
        ensure!(
            *actor == enrollment["incumbent"]
                && quoted["consumer_seal"] == registration["package"]
                && ["invocation_id", "pid", "start_ticks"]
                    .iter()
                    .all(|key| quoted[*key] == actor[*key]),
            "epoch 170 quote belongs to a different V13 writer"
        );
        check_retry5_price(price, &bound(&price["fleet"], 0)?)?;
        if !price["full170_retry5_owner"].is_null() {
            let owner = &price["full170_retry5_owner"];
            let producer = properties(RETRY5_UNIT)?;
            let timer = properties(RETRY5_TIMER)?;
            ensure!(
                producer["ActiveState"] == "active"
                    && producer["InvocationID"] == owner["producer_invocation_id"]
                    && timer["ActiveState"] == "active"
                    && timer["InvocationID"] == owner["timer_invocation_id"],
                "retry5 producer or guard timer changed after joint pricing"
            );
        }
    }
    if package == rt(FULL170_INDEPENDENT) || package == rt(FULL170_AFTER_STOP) {
        return validate_independent_phase(&package, phase);
    }
    let owner = if package == rt(FULL170_RETRY5_V10) {
        &V10_COMPLETION
    } else {
        &V9_COMPLETION
    };
    validate_verifier_phase(owner, phase)
}

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
    let needed = number(native, "complete_required_HOME_bytes")?;
    let fully_booked_floor = number(native, "protected_raw_floor_bytes")?;
    let donor = &native["epoch159_donor_cover"];
    let donor_required = number(donor, "native_home_required")?;
    let available =
        number(native, "available_HOME_bytes")?.min(number(donor, "native_home_available")?);
    let zero_native = number(native, "full170_zero_remaining_native_HOME_bytes")
        .context("provider lacks the full-epoch zero remaining-allowance calculation")?;
    ensure!(
        donor["schema"] == "horizon-145-drained-159-donor-cover-v1"
            && donor["fleet"] == active["fleet"]
            && donor["native_recorded_unix_seconds"] == native["recorded_unix_seconds"]
            && donor["credited_retirement_bytes"] == 0
            && donor["replay_launch_authorized"] == false
            && donor_required >= needed,
        "native donor cover does not bind the complete prepaid budget"
    );
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
    ensure!(
        zero_native <= needed,
        "zero-growth native floor exceeds the current requirement"
    );
    let donor_overhead = donor_required - needed;
    let zero_donor = zero_native
        .checked_add(donor_overhead)
        .context("zero-growth donor floor overflow")?;
    let protected_basis = donor_required.max(
        zero_donor
            .checked_add(remaining)
            .context("protected prepaid booking overflow")?,
    );
    let floor = (protected_basis - remaining).max(absolute);
    let complete = floor
        .checked_add(remaining)
        .context("candidate budget overflow")?;
    let extra = complete - protected_basis;
    ensure!(
        available >= complete,
        "full metered 170 HOME requirement {complete} exceeds {available} available bytes at protected floor {floor}"
    );
    ensure!(
        extra <= number(donor, "remaining_home_bytes")?,
        "full metered 170 extra reservation of {extra} bytes exceeds the donor remainder"
    );
    ensure!(
        number(native, "available_memory_bytes")?
            >= number(native, "required_available_memory_bytes")?,
        "full metered 170 does not fit within the retained memory booking"
    );
    let mut quote = native.clone();
    quote["epoch"] = json!(170);
    quote["protected_raw_floor_bytes"] = json!(floor);
    quote["available_HOME_bytes"] = json!(available);
    quote["complete_required_HOME_bytes"] = json!(complete);
    quote["bookings"]["170"]["run"] = profile["actor"]["run"].clone();
    quote["epoch170_metered_full"] = json!({"stage":"prestart", "producer_unit":UNIT,"guard_timer":TIMER,
        "worker_sha256":WORKER_SHA,"source_profile_sha256":sha(&serde_json::to_vec(profile)?),
        "guard_qualification":enrollment["guard_qualification"],"candidate_root":enrollment["candidate_root"],
        "observer_enrollment":enrollment_ref,"retained_retry13_terminal":terminal,
        "prior_run":book["run"],"prestart_whole_tree_physical_bytes":physical,"remaining_whole_tree_bytes":remaining,
        "original_complete_required_home_bytes":needed,"reassigned_prepaid_bookings":1,
        "donor_required_HOME_bytes":protected_basis,"zero_remaining_donor_floor_bytes":zero_donor,
        "additional_reservation_bytes":extra,
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
        "full170" => rt(FULL170),
        "full170-v9" => rt(FULL170_V9),
        "full170-v9-v13" => rt(FULL170_V13),
        "full170-v9-v13-retry5" => rt(FULL170_RETRY5),
        "full170-v10-v13-retry5" => rt(FULL170_RETRY5_V10),
        "full170-independent-v13-retry5" => rt(FULL170_INDEPENDENT),
        "full170-independent-v14-after-stop" => rt(FULL170_AFTER_STOP),
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
    } else if route.starts_with("full170") {
        command.arg("--full170=prestart");
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
    validate_drained_price(&result, &candidate)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion_fixture(owner: &VerifierCompletion) -> (Value, Value) {
        let handoff = rt(owner.handoff);
        let invocation = owner.invocation;
        let recovery = reference(
            &rt(&format!(
                "epoch145-guarded-export-20261121-v1/state/{invocation}/recovery-started.json"
            )),
            owner.start_sha,
        );
        let submission = reference(&handoff.join("START_RESULT.json"), owner.submission_sha);
        let checker = reference(
            &rt(owner.checker).join("deployment-seal-receipt.json"),
            owner.checker_sha,
        );
        let phase = json!({"stage": owner.phase, "completed_invocation_id": invocation,
            "Id": "horizon-holding-export145-20261121-v1.service", "MainPID": "0",
            "completion": {"path": handoff.join("SEMANTIC_COMPLETION.json"), "sha256": "fixture"},
            "checker_seal": checker});
        let completion = json!({"schema": owner.schema,
            "invocation_id": invocation, "start": recovery,
            "startup_evidence": {"invocation_id": invocation, "start": recovery,
                "submission_result": submission, "worker_seal": checker},
            "native_success": {"INVOCATION_ID": invocation, "UNIT": "horizon-holding-export145-20261121-v1.service",
                "MESSAGE_ID": "7ad2d189f7e94e70a38c781354912448", "_PID": "1"},
            "publication_authorized": false, "r2_mutations": false});
        (phase, completion)
    }

    #[test]
    fn each_phase_binds_its_owner_and_separate_startup_receipts() {
        for (owner, previous) in [
            (&V9_COMPLETION, &V10_COMPLETION),
            (&V10_COMPLETION, &V9_COMPLETION),
        ] {
            let (phase, completion) = completion_fixture(owner);
            check_verifier_completion(owner, &phase, &completion).unwrap();
            let (foreign_phase, foreign_completion) = completion_fixture(previous);
            assert!(check_verifier_completion(owner, &phase, &foreign_completion).is_err());
            assert!(check_verifier_completion(owner, &foreign_phase, &completion).is_err());

            let startup = &completion["startup_evidence"];
            let mut crossed = completion.clone();
            crossed["startup_evidence"]["start"] = startup["submission_result"].clone();
            crossed["startup_evidence"]["submission_result"] = startup["start"].clone();
            assert!(check_verifier_completion(owner, &phase, &crossed).is_err());
        }
    }

    #[test]
    fn v12_enrollment_requires_the_v9_provider_and_phase() {
        let enrollment = json!({"incumbent_registration": {"path": rt(V12_REGISTRATION)}});
        let historic = json!({"phase145": {"stage": "v6-semantic-complete-drained"}});
        assert!(
            validate_drained_price(&historic, &enrollment)
                .unwrap_err()
                .to_string()
                .contains("requires the registered cadence and its matching provider")
        );
        assert!(validate_drained_price(&historic, &Value::Null).is_ok());
    }

    #[test]
    fn v13_and_v12_quotes_require_their_matching_provider() {
        let v12 =
            json!({"incumbent_registration":reference(&rt(V12_REGISTRATION), V12_ACTIVE_SHA)});
        let v13 = json!({"incumbent_registration":reference(&rt(V13_REGISTRATION), "fixture")});
        for (package, phase, exact, foreign) in [
            (FULL170_V9, V9_PHASE, &v12, &v13),
            (FULL170_V13, V9_PHASE, &v13, &v12),
            (FULL170_RETRY5, V9_PHASE, &v13, &v12),
            (FULL170_RETRY5_V10, V10_PHASE, &v13, &v12),
            (FULL170_INDEPENDENT, INDEPENDENT_PHASE, &v13, &v12),
        ] {
            let dir = rt(package);
            let mut native = json!({"phase145":{"stage":phase}, "recorded_unix_seconds":1,
                "epoch170_metered_full":{"native_capture_receipt":{
                    "program":{"path":dir.join("post-stop-fit")},
                    "deployment":{"path":dir.join("deployment-seal-receipt.json")},
                    "source_epoch":145,"recorded_unix_seconds":1}}});
            if matches!(
                package,
                FULL170_RETRY5 | FULL170_RETRY5_V10 | FULL170_INDEPENDENT
            ) {
                native["full170_retry5_owner"] = json!({"fixture": true});
            }
            assert_eq!(drained_provider(&native, exact).unwrap(), Some(dir));
            assert!(drained_provider(&native, foreign).is_err());
            assert!(drained_provider(&native, &Value::Null).is_err());
            if phase == INDEPENDENT_PHASE {
                let mut without_retry5 = native.clone();
                without_retry5["full170_retry5_owner"] = Value::Null;
                assert!(drained_provider(&without_retry5, exact).is_err());
            }
            native["phase145"]["stage"] = json!(if phase == V10_PHASE {
                V9_PHASE
            } else {
                V10_PHASE
            });
            assert!(drained_provider(&native, exact).is_err());
        }
    }

    #[test]
    fn v14_quote_requires_the_exact_stopped_route_and_no_live_retry5_owner() {
        let v14 = json!({"incumbent_registration":reference(&rt(V14_REGISTRATION), "fixture")});
        let v13 = json!({"incumbent_registration":reference(&rt(V13_REGISTRATION), "fixture")});
        let dir = rt(FULL170_AFTER_STOP);
        let mut quote = json!({"phase145":{"stage":INDEPENDENT_PHASE}, "recorded_unix_seconds":1,
            "full170_retry5_stopped":{"floor":512},
            "epoch170_metered_full":{"native_capture_receipt":{
                "program":{"path":dir.join("post-stop-fit")},
                "deployment":{"path":dir.join("deployment-seal-receipt.json")},
                "source_epoch":145,"recorded_unix_seconds":1}}});
        assert_eq!(drained_provider(&quote, &v14).unwrap(), Some(dir));
        assert!(drained_provider(&quote, &v13).is_err());
        quote["full170_retry5_owner"] = json!({"fixture":true});
        assert!(drained_provider(&quote, &v14).is_err());
        quote["full170_retry5_owner"] = Value::Null;
        quote["full170_retry5_stopped"] = Value::Null;
        assert!(drained_provider(&quote, &v14).is_err());
    }

    #[test]
    fn full170_requires_the_protected_retry5_owner_and_both_charges() {
        let owner = json!({
            "producer_unit": RETRY5_UNIT, "producer_invocation_id": "producer", "producer_pid": 21,
            "start_ticks": 100, "admission": "admission", "first_worker": "first",
            "plan": "guard-plan", "timer": RETRY5_TIMER, "timer_invocation_id": "timer",
            "floor": 136u64 << 30, "processes": [[21, 100, 5, 6], [22, 101, 5, 7]],
            "guard": "guard"
        });
        let fleet = json!({"actual_executing_replays": [{"epoch": 168,
            "unit": {"Id": RETRY5_UNIT, "InvocationID": "producer"}, "start_ticks": 100,
            "admission": "admission", "guard_timer": {"Id": RETRY5_TIMER, "InvocationID": "timer"}
        }]});
        let quote = json!({"full170_retry5_owner": owner, "active168_guard_floor": 136u64 << 30,
            "replacements": {"168": owner},
            "bookings": {"168": {"cap_bytes": 512u64 << 30, "physical_bytes": 492u64 << 30,
                                  "remaining_bytes": 20u64 << 30}},
            "retry5_complete_booking": {"outside_cap_stop_allowance_bytes": 8u64 << 30,
                "retained_guard_floor_bytes": 136u64 << 30, "retained_base_HOME_bytes": 130u64 << 30,
                "candidate_remaining_bytes": 20u64 << 30, "complete_required_HOME_bytes": 158u64 << 30},
            "full170_retry5_projection": {"native_current_HOME_bytes": 120u64 << 30,
                "native_zero_remaining_HOME_bytes": 97u64 << 30, "donor_HOME_bytes": 130u64 << 30,
                "funded_current_HOME_bytes": 158u64 << 30, "funded_zero_remaining_HOME_bytes": 156u64 << 30},
            "epoch159_donor_cover": {"native_home_required": 158u64 << 30},
            "epoch170_metered_full": {"original_complete_required_home_bytes": 158u64 << 30},
            "full170_zero_remaining_native_HOME_bytes": 156u64 << 30
        });
        check_retry5_price(&quote, &fleet).unwrap();
        check_retry5_price(&Value::Null, &json!({"actual_executing_replays": []})).unwrap();
        assert!(check_retry5_price(&Value::Null, &fleet).is_err());
        for (path, wrong) in [
            (
                "/full170_retry5_owner/producer_invocation_id",
                json!("other"),
            ),
            ("/full170_retry5_owner/timer_invocation_id", json!("other")),
            ("/replacements/168/plan", json!("other")),
            ("/bookings/168/remaining_bytes", json!(0)),
            (
                "/full170_zero_remaining_native_HOME_bytes",
                json!(136u64 << 30),
            ),
            (
                "/epoch159_donor_cover/native_home_required",
                json!(168u64 << 30),
            ),
        ] {
            let mut bad = quote.clone();
            *bad.pointer_mut(path).unwrap() = wrong;
            assert!(check_retry5_price(&bad, &fleet).is_err(), "{path}");
        }
    }

    #[test]
    fn v13_cadence_rejects_a_different_predecessor_or_lock_owner() {
        let old = json!({"unit":OBSERVER_UNIT,"invocation_id":"old","start_ticks":1,
            "lock":{"path":"/consumer","inode":1,"device":2,"fd":3}});
        let previous = json!({"new":old});
        let mut next = old.clone();
        next["invocation_id"] = json!("new");
        next["start_ticks"] = json!(2);
        next["lock"]["fd"] = json!(6);
        let handoff = json!({"schema":"horizon-epoch166-cadence-rejoin-active-v1",
            "new":next,"old":old});
        validate_v13_actor(&handoff, &previous).unwrap();
        for (pointer, value) in [
            ("/new/lock/inode", json!(3)),
            ("/new/start_ticks", json!(1)),
            ("/new/invocation_id", json!("old")),
            ("/old/invocation_id", json!("foreign")),
        ] {
            let mut wrong = handoff.clone();
            *wrong.pointer_mut(pointer).unwrap() = value;
            assert!(validate_v13_actor(&wrong, &previous).is_err(), "{pointer}");
        }
    }

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
            "epoch159_donor_cover":{"schema":"horizon-145-drained-159-donor-cover-v1","fleet":fleet,
                "native_recorded_unix_seconds":1000,"credited_retirement_bytes":0,"replay_launch_authorized":false,
                "native_home_required":MIN_FLOOR+(5u64<<30),"native_home_available":MIN_FLOOR+(16u64<<30),
                "remaining_home_bytes":1u64<<30},
            "full170_zero_remaining_native_HOME_bytes":MIN_FLOOR+(3u64<<30),
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
    fn quote_arms_the_donor_floor_without_recharging_the_prepaid_booking() {
        let (mut base, profile, enrollment, reference) = case();
        let donor_required = MIN_FLOOR + (8u64 << 30);
        base["epoch159_donor_cover"]["native_home_required"] = json!(donor_required);
        assert!(retained_booking(&base, &profile, &enrollment, &reference, 1010).is_err());
        base["available_HOME_bytes"] = json!(donor_required);
        let quote = retained_booking(&base, &profile, &enrollment, &reference, 1010).unwrap();
        assert_eq!(quote["complete_required_HOME_bytes"], donor_required);
        assert_eq!(
            quote["protected_raw_floor_bytes"],
            donor_required - (2u64 << 30)
        );
        assert_eq!(
            quote["epoch170_metered_full"]["additional_reservation_bytes"],
            0
        );
    }

    #[test]
    fn quote_preserves_the_donor_floor_at_full_prepaid_growth() {
        let (mut base, profile, enrollment, reference) = case();
        let zero_native = MIN_FLOOR + (5u64 << 30);
        base["full170_zero_remaining_native_HOME_bytes"] = json!(zero_native);
        base["epoch159_donor_cover"]["native_home_required"] = json!(zero_native + (1u64 << 30));
        let protected = zero_native + (1u64 << 30);
        assert!(retained_booking(&base, &profile, &enrollment, &reference, 1010).is_err());
        base["available_HOME_bytes"] = json!(protected + (2u64 << 30));
        let quote = retained_booking(&base, &profile, &enrollment, &reference, 1010).unwrap();
        assert_eq!(quote["protected_raw_floor_bytes"], protected);
        assert_eq!(
            quote["complete_required_HOME_bytes"],
            protected + (2u64 << 30)
        );
        assert_eq!(
            quote["epoch170_metered_full"]["additional_reservation_bytes"],
            0
        );
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
