//! Proposed finite metadata route, not admitted, built or executed.
//! Intended module: jetstreamer-r2/src/fleet/cold185/task_status_bridge.rs.
//! Reuses qualified native task authentication; never queries/mutates R2,
//! starts a unit, publishes a token, or grants replay/publication authority.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    TaskAcknowledgment,
    StatusReadback,
}
impl Kind {
    fn wire(self) -> &'static str {
        match self {
            Self::TaskAcknowledgment => "task_acknowledgment",
            Self::StatusReadback => "status_readback",
        }
    }
    fn file(self) -> &'static str {
        match self {
            Self::TaskAcknowledgment => "task-acknowledgment.json",
            Self::StatusReadback => "status-readback.json",
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    kind: Kind,
    task: BoundFile,
    status_readback: BoundFile,
    expected_actor_unit: String,
    expected_actor_invocation_id: String,
    expected_ready: BoundFile,
    output: PathBuf,
}

fn n(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("bridge missing nonnegative integer {key}"))
}
fn s<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("bridge missing string {key}"))
}

/// Source receipt's already-qualified status-only publisher uses sorted compact
/// JSON plus one LF. This checks its actual authenticated readback digest; it
/// does not reinterpret the receipt as a fresh remote observation.
fn wire_digest(payload: &Value) -> Result<String> {
    let sorted: BTreeMap<&str, &Value> = payload
        .as_object()
        .context("bridge status payload object")?
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let mut raw = serde_json::to_vec(&sorted)?;
    raw.push(b'\n');
    Ok(hex_lower(&Sha256::digest(&raw)))
}

/// Pure validation called only with native::read_json custody-checked inputs
/// and a super::load result (which reauthenticates actual native ownership).
fn validate(spec: &Spec, proof: &Value, status: &Value, now: u64) -> Result<u64> {
    let driver = super::driver::from_proof(proof)?;
    ensure!(
        spec.schema == "horizon-epoch185-task-status-bridge-spec-v1",
        "bridge spec schema changed"
    );
    ensure!(
        is_lower_hex(&spec.expected_actor_invocation_id, 32)
            && spec
                .expected_actor_unit
                .starts_with("horizon-qualify-185-capped-cold-")
            && spec.expected_actor_unit.ends_with(".service"),
        "bridge actor scope"
    );
    ensure!(
        spec.output
            == Path::new(ROOT)
                .join(&spec.expected_actor_invocation_id)
                .join(spec.kind.file()),
        "bridge output crossed actual IID or receipt kind"
    );
    ensure!(
        proof["schema"] == TASK_SCHEMA
            && proof["stage"] == "start-pre"
            && proof["guard_pending"] == true
            && proof["no_replay_or_publication_or_credit"] == true
            && proof["capacity_credit_bytes"] == 0
            && proof["task"] == json!(spec.task)
            && proof["actor_unit"] == spec.expected_actor_unit
            && proof["actor_invocation_id"] == spec.expected_actor_invocation_id,
        "bridge is not the exact live original gated task"
    );
    let ready = &proof["ready"];
    let started = n(ready, "started_at")?;
    let deadline = n(proof, "original_setup_deadline_unix_seconds")?;
    ensure!(
        started <= now
            && now < deadline
            && deadline > started
            && deadline - started <= 600
            && proof["ready_binding"] == json!(spec.expected_ready)
            && proof["ready_sha256"] == spec.expected_ready.sha256
            && ready["schema"] == "horizon-epoch185-worker-ready-v4"
            && ready["epoch"] == 185
            && ready["actor_unit"] == spec.expected_actor_unit
            && ready["actor_invocation_id"] == spec.expected_actor_invocation_id
            && ready["admission_sha256"] == proof["admission"]["sha256"]
            && ready["driver_sha256"] == driver.sha256
            && n(ready, "pid")? > 1
            && n(ready, "start_ticks")? > 0
            && proof["mapped_driver"]["pid"] == ready["pid"]
            && proof["mapped_driver"]["start_ticks"] == ready["start_ticks"],
        "bridge original ready/deadline/process changed"
    );
    let expected_control_pid = n(ready, "pid")?.to_string();
    let actor = &proof["native"][spec.expected_actor_unit.as_str()];
    ensure!(
        actor["InvocationID"] == spec.expected_actor_invocation_id
            && actor["NRestarts"] == "0"
            && actor["ActiveState"] == "activating"
            && actor["SubState"] == "start-pre"
            && actor["MainPID"] == "0"
            && actor["ControlPID"].as_str() == Some(expected_control_pid.as_str()),
        "bridge native actor is not the same unrestarted ControlPID"
    );
    let admission = &proof["admission_value"];
    ensure!(
        n(admission, "issued_at")? <= now
            && now < n(admission, "expires_at")?
            && admission["unit"] == spec.expected_actor_unit
            && admission["task_owner"] == "Root"
            && admission["status_readback"] == json!(spec.status_readback)
            && proof["current_task"] == json!(spec.status_readback)
            && proof["source_bindings"]["current_task"] == json!(spec.status_readback),
        "bridge status crossed the original admitted Root owner or binding"
    );
    ensure!(
        status["schema"] == "horizon-status-only-correction-v1"
            && status["epoch"] == 185
            && status["key"] == "epoch-185.epoch-status.json"
            && status["authenticated_readback"] == true
            && status["owner_evidence"]["current_operator"] == "/root"
            && status["archive_publication_authorized"] == false
            && status["replay_launch_authorized"] == false,
        "bridge has no authenticated exact-key Root status source"
    );
    let payload = &status["after_status"];
    let object = payload
        .as_object()
        .context("bridge six-field status object")?;
    let keys = [
        "epoch",
        "jet_size_bytes",
        "elapsed_execution_millis",
        "estimated_remaining_millis",
        "phase",
        "sampled_at_utc",
    ];
    ensure!(
        object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)),
        "bridge status wire key set changed"
    );
    for key in &keys[..4] {
        n(payload, key)?;
    }
    let eta = n(payload, "estimated_remaining_millis")?;
    let at = crate::fleet::utc_seconds(s(payload, "sampled_at_utc")?)?;
    ensure!(
        payload["epoch"] == 185
            && payload["phase"] == "verification"
            && eta > 0
            && status["estimated_remaining_millis"] == eta
            && status["sampled_at_utc"] == payload["sampled_at_utc"]
            && at <= now
            && now - at < 1800,
        "bridge status owner phase/ETA/time invalid or stale"
    );
    let etag = s(status, "after_etag")?;
    ensure!(
        !etag.is_empty()
            && !etag.chars().any(char::is_control)
            && is_lower_hex(s(status, "after_sha256")?, 64)
            && status["after_sha256"] == wire_digest(payload)?,
        "bridge authenticated payload digest/ETag changed"
    );
    Ok(eta)
}

pub(super) fn stable(a: &Value, b: &Value) -> Result<()> {
    for key in [
        "actor_unit",
        "actor_invocation_id",
        "ready",
        "ready_binding",
        "ready_sha256",
        "mapped_driver",
        "native",
        "stage",
        "guard_pending",
        "admission",
        "current_task",
        "original_setup_deadline_unix_seconds",
    ] {
        ensure!(
            a[key] == b[key],
            "bridge native/source changed before commit: {key}"
        );
    }
    Ok(())
}

pub(in crate::fleet) fn run() -> Result<()> {
    let (spec_bound, self_sha) = super::parsed("prove-cold185-task-status")?;
    let spec: Spec = serde_json::from_value(super::native::read_json(&spec_bound, 4 << 20)?)?;
    // Reads validate Root-owned canonical immutable custody and bound digest.
    // load validates the original spec, ready-file bytes, actual process executable,
    // argv, UID/start ticks, original admission and native actor/guard/timer policy.
    let status = super::native::read_json(&spec.status_readback, 4 << 20)?;
    let before = super::load(&spec.task, super::now()?)?;
    validate(&spec, &before, &status, super::now()?)?;
    let after = super::load(&spec.task, super::now()?)?;
    stable(&before, &after)?;
    let status_after = super::native::read_json(&spec.status_readback, 4 << 20)?;
    ensure!(
        status_after == status,
        "bridge immutable status drift before commit"
    );
    let at = super::now()?;
    let eta = validate(&spec, &after, &status_after, at)?;
    let underlying = match spec.kind {
        Kind::TaskAcknowledgment => json!(spec.task),
        Kind::StatusReadback => json!(spec.status_readback),
    };
    let receipt = json!({"schema":"horizon-epoch185-native-owner-enrollment-v4",
        "kind":spec.kind.wire(),"epoch":185,"actor_unit":spec.expected_actor_unit,
        "actor_invocation_id":spec.expected_actor_invocation_id,
        "ready_pid":after["ready"]["pid"],"ready_start_ticks":after["ready"]["start_ticks"],
        "admission_sha256":after["admission"]["sha256"],"restarts":0,
        "phase":"verification","root_operator_owner":true,
        "actual_start_pre_evidence_accepted":true,"numeric_delivery_eta_millis":eta,
        "sampled_at":at,"resource_credit_bytes":0,"underlying_accepted_proof":underlying,
        "task":spec.task,"status_source":spec.status_readback,"ready":spec.expected_ready,
        "actual_native_before":before["native"],"actual_native_after":after["native"],
        "source_bindings":after["source_bindings"],"spec":spec_bound,"self_sha256":self_sha,
        "replay_launch_authorized":false,"ordinary_full_replay_authorized":false,
        "publication_authorized":false,"r2_mutations":false});
    super::persist(&spec.output, &receipt)?;
    println!(
        "{}",
        json!({"receipt":spec.output,"kind":spec.kind.wire(),
        "replay_launch_authorized":false,"publication_authorized":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic pure-policy fixtures only: never accepted native/R2 evidence.
    fn fixture() -> (Spec, Value, Value, u64) {
        let now = 1_783_296_000u64; // synthetic 2026-07-06T00:00:00Z
        let iid = "a".repeat(32);
        let actor = "horizon-qualify-185-capped-cold-positive-fixture.service";
        let binding = |p: &str| json!({"path":p,"sha256":"b".repeat(64)});
        let task = binding("/fixture/sealed/task.json");
        let status_bound = binding("/fixture/sealed/status.json");
        let ready_bound = binding("/fixture/ready.json");
        let spec: Spec = serde_json::from_value(json!({
            "schema":"horizon-epoch185-task-status-bridge-spec-v1", "kind":"task_acknowledgment",
            "task":task,"status_readback":status_bound,"expected_actor_unit":actor,
            "expected_actor_invocation_id":iid,"expected_ready":ready_bound,
            "output":Path::new(ROOT).join(&iid).join("task-acknowledgment.json")}))
        .unwrap();
        let ready = json!({"schema":"horizon-epoch185-worker-ready-v4","epoch":185,
            "actor_unit":actor,"actor_invocation_id":iid,"started_at":now-100,
            "pid":123,"start_ticks":987,"admission_sha256":"c".repeat(64),
            "driver_sha256":DRIVER_SHA});
        let mut native = serde_json::Map::new();
        native.insert(
            actor.to_owned(),
            json!({"InvocationID":iid,"NRestarts":"0",
            "ActiveState":"activating","SubState":"start-pre","MainPID":"0","ControlPID":"123"}),
        );
        let proof = json!({"schema":TASK_SCHEMA,"stage":"start-pre","guard_pending":true,
            "no_replay_or_publication_or_credit":true,"capacity_credit_bytes":0,
            "task":task,"actor_unit":actor,"actor_invocation_id":iid,"ready":ready,
            "ready_binding":ready_bound,"ready_sha256":"b".repeat(64),
            "original_setup_deadline_unix_seconds":now+400,
            "envelope_value":{"self_program":DRIVER,"self_sha256":DRIVER_SHA},
            "source_bindings":{"current_task":status_bound,"driver":{"path":DRIVER,"sha256":DRIVER_SHA}},
            "mapped_driver":{"pid":123,"start_ticks":987,"path":DRIVER,"sha256":DRIVER_SHA},
            "native":native,
            "admission":{"sha256":"c".repeat(64)},
            "admission_value":{"unit":actor,"task_owner":"Root","issued_at":now-200,
                "expires_at":now+1000,"status_readback":status_bound},
            "current_task":status_bound});
        let payload = json!({"epoch":185,"jet_size_bytes":0,"elapsed_execution_millis":10,
            "estimated_remaining_millis":123456,"phase":"verification",
            "sampled_at_utc":crate::fleet::input161::utc(now-10).unwrap()});
        let status = json!({"schema":"horizon-status-only-correction-v1","epoch":185,
            "key":"epoch-185.epoch-status.json","authenticated_readback":true,
            "owner_evidence":{"current_operator":"/root"},"archive_publication_authorized":false,
            "replay_launch_authorized":false,"after_status":payload,
            "estimated_remaining_millis":123456,"sampled_at_utc":payload["sampled_at_utc"],
            "after_etag":"\"fixture-etag\"","after_sha256":wire_digest(&payload).unwrap()});
        (spec, proof, status, now)
    }
    #[test]
    fn delayed_original_task_can_be_acknowledged_only_while_actual_setup_remains_live() {
        let (spec, proof, status, now) = fixture();
        assert_eq!(validate(&spec, &proof, &status, now).unwrap(), 123456);
        assert!(validate(&spec, &proof, &status, now + 400).is_err());
        assert!(validate(&spec, &proof, &status, now - 101).is_err());
    }
    #[test]
    fn crossed_owner_ready_process_admission_or_stage_is_rejected() {
        let (spec, proof, status, now) = fixture();
        for (pointer, value) in [
            ("/actor_invocation_id", json!("d".repeat(32))),
            ("/ready/pid", json!(124)),
            ("/mapped_driver/start_ticks", json!(988)),
            ("/admission/sha256", json!("d".repeat(64))),
            ("/admission_value/task_owner", json!("/other")),
            ("/stage", json!("running")),
            ("/guard_pending", json!(false)),
            ("/current_task/sha256", json!("d".repeat(64))),
        ] {
            let mut bad = proof.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate(&spec, &bad, &status, now).is_err(),
                "accepted {pointer}"
            );
        }
    }
    #[test]
    fn spoofed_status_owner_readback_key_digest_or_noninteger_eta_is_rejected() {
        let (spec, proof, status, now) = fixture();
        for (pointer, value) in [
            ("/owner_evidence/current_operator", json!("/other")),
            ("/authenticated_readback", json!(false)),
            ("/key", json!("epoch-186.epoch-status.json")),
            ("/after_sha256", json!("0".repeat(64))),
            ("/after_status/estimated_remaining_millis", json!(0)),
            ("/after_status/estimated_remaining_millis", json!(true)),
            ("/after_status/estimated_remaining_millis", json!("123456")),
            ("/after_status/phase", json!("replay")),
        ] {
            let mut bad = status.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate(&spec, &proof, &bad, now).is_err(),
                "accepted {pointer}"
            );
        }
    }
    #[test]
    fn authentic_digest_does_not_excuse_future_or_expired_status() {
        let (spec, proof, status, now) = fixture();
        for at in [now + 1, now - 1800] {
            let mut bad = status.clone();
            let stamp = crate::fleet::input161::utc(at).unwrap();
            bad["after_status"]["sampled_at_utc"] = json!(stamp);
            bad["sampled_at_utc"] = json!(stamp);
            bad["after_sha256"] = json!(wire_digest(&bad["after_status"]).unwrap());
            assert!(validate(&spec, &proof, &bad, now).is_err());
        }
    }
    #[test]
    fn status_extra_fields_restart_and_crossed_output_are_rejected() {
        let (mut spec, proof, status, now) = fixture();
        let mut extra = status.clone();
        extra["after_status"]["extra"] = json!(1);
        assert!(validate(&spec, &proof, &extra, now).is_err());
        let mut changed = proof.clone();
        changed["native"][spec.expected_actor_unit.as_str()]["NRestarts"] = json!("1");
        assert!(validate(&spec, &changed, &status, now).is_err());
        assert!(stable(&proof, &changed).is_err());
        spec.kind = Kind::StatusReadback;
        assert!(validate(&spec, &proof, &status, now).is_err());
        spec.output = Path::new(ROOT)
            .join(&spec.expected_actor_invocation_id)
            .join(spec.kind.file());
        assert!(validate(&spec, &proof, &status, now).is_ok());
    }
}
