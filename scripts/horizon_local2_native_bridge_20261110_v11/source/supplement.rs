//! A bounded current-owner supplement; no old observation is filled or retimed.
use super::*;
fn utc(value: &str) -> R<u64> {
    let b = value.as_bytes();
    need(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z'
            && [0..4, 5..7, 8..10, 11..13, 14..16, 17..19]
                .iter()
                .all(|r| b[r.clone()].iter().all(u8::is_ascii_digit)),
        "exact supplement UTC string required",
    )?;
    let output = Command::new("/usr/bin/date")
        .args(["--date", value, "+%s"])
        .output()?;
    need(
        output.status.success() && output.stderr.is_empty(),
        "supplement UTC parse",
    )?;
    Ok(std::str::from_utf8(&output.stdout)?.trim().parse()?)
}
fn shape(request: &Value, d: &Value, observer: &Value, phase: &Value, at: u64) -> R<u64> {
    need(
        request["schema"] == "horizon-precutoff169-census-supplement-request-v1"
            && request["owner"] == "/root"
            && request["primary_thread"] == THREAD
            && request["epoch"] == 169
            && request["no_observer_rewrite"] == true
            && request["no_memory_target_or_operating_point_credit"] == true,
        "exact Root census-only request required",
    )?;
    need(
        d["epoch"] == 169
            && d["invocation_id"] == IID169
            && d["main_pid"] == "1123930"
            && d["original_start_unix_seconds"] == START169
            && matches!(s(d, "phase")?, "bootstrap" | "replay"),
        "actual pre-cutoff169 owner identity required",
    )?;
    need(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == "2026-11-10T21:00:22Z",
        "accepted original v2 observer required",
    )?;
    let cutoff = utc(s(observer, "recorded_at_utc")?)?;
    need(
        START169 <= cutoff && cutoff <= at,
        "supplement must preserve actual pre-cutoff birth",
    )?;
    let rows = observer["replays"]
        .as_array()
        .ok_or("observer replay rows")?;
    need(
        rows.len() == 3
            && rows
                .iter()
                .all(|r| matches!(r["range"].as_str(), Some("166" | "167" | "168")))
            && rows
                .iter()
                .map(|r| r["range"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == 3,
        "exact three-row original observer omission required",
    )?;
    let expires = n(request, "expires_unix_seconds")?;
    need(
        expires == utc(s(request, "next_observer_utc")?)?
            && expires > at
            && expires
                <= cutoff
                    .checked_add(1800)
                    .ok_or("supplement expiry overflow")?,
        "census supplement must expire by next ordinary1800-second cutoff",
    )?;
    need(
        phase["epoch"] == 169
            && phase["phase"] == d["phase"]
            && phase["source_start_unix_seconds"] == START169
            && phase["no_new_resource_sample"] == true
            && phase["source_log"]["producer_invocation_id"] == IID169
            && n(phase, "recorded_unix_seconds")? >= cutoff
            && n(phase, "recorded_unix_seconds")? <= at,
        "current phase event is separate from original observer clock",
    )?;
    need(
        phase["transaction_replay_claimed"] == (d["phase"] == "replay")
            && ((d["phase"] == "bootstrap" && phase["latest_target_progress"].is_null())
                || (d["phase"] == "replay"
                    && phase["latest_target_progress"]["epoch"] == 169
                    && n(&phase["latest_target_progress"], "transactions")? > 0)),
        "supplement cannot fabricate replay progress",
    )?;
    Ok(expires)
}
pub(super) fn make(
    binding: &Value,
    request: &Value,
    d: &Value,
    self_sha: &str,
    at: u64,
) -> R<Value> {
    let observer = hash_bound(&request["observer"])?;
    let phase = hash_bound(&d["phase_event"])?;
    let expires = shape(request, d, &observer, &phase, at)?;
    let birth = birth169()?;
    let status_bytes = raw(Path::new(STATUS169))?;
    need(
        sha(&status_bytes) == STATUS169_SHA,
        "original narrow bootstrap status evidence changed",
    )?;
    let status: Value = serde_json::from_slice(&status_bytes)?;
    need(
        status["epoch"] == 169
            && status["latest_target_progress"].is_null()
            && status["transaction_replay_claimed"] == false
            && status["producer_after"]["InvocationID"] == IID169,
        "original status clock and bootstrap state preserved",
    )?;
    let completion =
        hash_bound(&json!({"path":STATUS169_COMPLETE,"sha256":STATUS169_COMPLETE_SHA}))?;
    need(
        completion["authenticated_readback"] == true
            && completion["actual_owner_event"] == json!({"path":STATUS169,"sha256":STATUS169_SHA}),
        "original narrow status must retain authenticated readback evidence",
    )?;
    let _ = hash_bound(&completion["status_receipt"])?;
    let next = hash_bound(&request["next_observer_receipt"])?;
    need(
        next["next_utc"] == request["next_observer_utc"],
        "genuine next sole observer receipt binding required",
    )?;
    let launch = hash_bound(&d["launch_proof"])?;
    let native_before = native(s(d, "unit")?)?;
    owner(&native_before, &birth["native"])?;
    let protection = hash_bound(&d["guard_protection"])?;
    let current_guard = guard(&protection, &native_before)?;
    let native_after = native(s(d, "unit")?)?;
    owner(&native_after, &native_before)?;
    need(
        launch["source_start_unix_seconds"] == START169
            && launch["producer_identity"]["pid"] == PID169
            && process(PID169, s(d, "unit")?)? == launch["producer_identity"],
        "current exact169 producer/process identity must survive supplement",
    )?;
    let finished = now()?;
    need(
        finished >= at && finished < expires,
        "supplement expired during current guard capture",
    )?;
    Ok(
        json!({"schema":"horizon-standard-precutoff-owner-census-supplement-v1","owner":"/root","primary_thread":THREAD,"epoch":169,"recorded_unix_seconds":finished,"creator":{"path":IMAGE,"sha256":self_sha},"request":binding,"observer":request["observer"],"observer_recorded_at_utc":observer["recorded_at_utc"],"source_next_observer_receipt":request["next_observer_receipt"],"expires_unix_seconds":expires,"birth_binding":{"path":BIRTH169,"sha256":BIRTH169_SHA},"actual_original_guarded_launch":birth["launch"],"original_narrow_status_event":{"path":STATUS169,"sha256":STATUS169_SHA},"original_narrow_status_completion":{"path":STATUS169_COMPLETE,"sha256":STATUS169_COMPLETE_SHA},"original_start_unix_seconds":START169,"unit":d["unit"],"invocation_id":IID169,"main_pid":PID169,"phase":d["phase"],"launch_proof":d["launch_proof"],"phase_event":d["phase_event"],"admission":d["admission"],"guard_protection":d["guard_protection"],"first_guard_pid1_timer":d["first_guard_pid1_timer"],"current_guard_pid1_timer_capture":current_guard,"producer_before":native_before,"producer_after":native_after,"current_owner_coverage_only":true,"in_current_observer":false,"original_observer_rewritten":false,"new_resource_sample":false,"rss_or_rate_claimed":false,"memory_target_credit":false,"operating_point_credit":false,"resource_credit_bytes":0,"promise_ending_bytes":0,"replay_launch_authorized":false,"remote_mutations":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Value, Value, u64) {
        let cutoff = 1794344422u64;
        let at = cutoff + 300;
        let request = json!({"schema":"horizon-precutoff169-census-supplement-request-v1","owner":"/root","primary_thread":THREAD,"epoch":169,"no_observer_rewrite":true,"no_memory_target_or_operating_point_credit":true,"expires_unix_seconds":cutoff+1800,"next_observer_utc":"2026-11-10T21:30:22Z"});
        let d = json!({"epoch":169,"invocation_id":IID169,"main_pid":PID169.to_string(),"original_start_unix_seconds":START169,"phase":"bootstrap"});
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-11-10T21:00:22Z","replays":[{"range":"166"},{"range":"167"},{"range":"168"}]});
        let phase = json!({"epoch":169,"phase":"bootstrap","source_start_unix_seconds":START169,"no_new_resource_sample":true,"source_log":{"producer_invocation_id":IID169},"recorded_unix_seconds":at,"transaction_replay_claimed":false,"latest_target_progress":null});
        (request, d, observer, phase, at)
    }
    #[test]
    fn precutoff_bootstrap_is_separate_current_census_only() {
        let f = fixture();
        assert_eq!(shape(&f.0, &f.1, &f.2, &f.3, f.4).unwrap(), 1794346222);
    }
    #[test]
    fn cannot_extend_expiry_past_original_next_cadence() {
        let mut f = fixture();
        f.0["expires_unix_seconds"] = json!(1794348022u64);
        f.0["next_observer_utc"] = json!("2026-11-10T22:00:22Z");
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn expiry_is_not_reset_from_new_capture_time() {
        let f = fixture();
        assert!(shape(&f.0, &f.1, &f.2, &f.3, 1794346222).is_err());
    }
    #[test]
    fn actual_birth_cannot_be_shifted_after_cutoff() {
        let mut f = fixture();
        f.1["original_start_unix_seconds"] = json!(1794344430u64);
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn unknown_invocation_rejected() {
        let mut f = fixture();
        f.1["invocation_id"] = json!("a".repeat(32));
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn sampled169_cannot_use_omission_route() {
        let mut f = fixture();
        f.2["replays"]
            .as_array_mut()
            .unwrap()
            .push(json!({"range":"169"}));
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn duplicate_old_rows_do_not_prove_complete_original_census() {
        let mut f = fixture();
        f.2["replays"][2]["range"] = json!("167");
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn future_event_clock_rejected() {
        let mut f = fixture();
        f.3["recorded_unix_seconds"] = json!(f.4 + 1);
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn bootstrap_never_inherits_target_transactions() {
        let mut f = fixture();
        f.3["latest_target_progress"] = json!({"epoch":169,"transactions":1});
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_err());
    }
    #[test]
    fn real_later_target_event_can_change_current_phase_without_retiming_birth() {
        let mut f = fixture();
        f.1["phase"] = json!("replay");
        f.3["phase"] = json!("replay");
        f.3["transaction_replay_claimed"] = json!(true);
        f.3["latest_target_progress"] = json!({"epoch":169,"transactions":1});
        assert!(shape(&f.0, &f.1, &f.2, &f.3, f.4).is_ok());
    }
}
