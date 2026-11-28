//! Exact 16:04 sample / 16:06 terminal transition. Historical RSS remains charged;
//! neither this observation nor the operator's status grants capacity or delivery.
use super::*;
pub(crate) const UNIT: &str = "horizon-qualify-247-reboot-20261117-v2.service";
pub(crate) const IID: &str = "d091bb68ff2648159c76f690b3b7fee3";
const TERMINAL_PATH: &str =
    "/var/lib/jetstreamer/horizon-singleton-delivery247-20261119-v1/terminal-handoff.json";
const TERMINAL_SHA: &str = "cb3dcc396a776034019133b9c542f443c3c9636867938a36e75c4c6ae50f377a";
const DRAIN_PATH: &str =
    "/var/lib/jetstreamer/horizon-singleton-delivery247-20261119-v1/terminal-drain.json";
const DRAIN_SHA: &str = "e4cd3c344ad0b1aeac6d5a8309d6306c7ae935788e362617efe994f564e2face";
const OBSERVER_SHA: &str = "11e1a09bf708f588bbc5540fcfb752de9a66740c24dee4db97cf38d77512a8cd";
const SAMPLE: &str = "2026-11-19T16:04:00Z";
const SCHEMA: &str = "horizon247-terminal-conservative-rss-v1";
const STATUS_ROOT: &str = "/home/ubuntu/.codex/diagnostics/horizon247-terminal-status-20261119-v1";
fn pinned(path: &str, sha: &str) -> Result<Value> {
    let p = Path::new(path);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0,
        "unsafe exact247 transition evidence"
    );
    bound_json(&BoundFile {
        path: p.into(),
        sha256: sha.into(),
    })
}
fn terminal_owner(current: &Value, terminal: &Value, drain: &Value, now: u64) -> Result<()> {
    ensure!(
        terminal["schema"] == "horizon-singleton-delivery-handoff-v1"
            && terminal["epoch"] == 247
            && drain["schema"] == "horizon-singleton-terminal-drain-v1"
            && drain["epoch"] == 247
            && drain["terminal_handoff"] == json!({"path":TERMINAL_PATH,"sha256":TERMINAL_SHA})
            && drain["producer"] == terminal["producer"]
            && drain["producer_cgroup_drained"] == true
            && drain["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| n <= now),
        "247 terminal/drain binding differs"
    );
    for (key, expected) in [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            current[key] == expected && terminal["producer"]["unit"][key] == expected,
            "247 terminal owner changed: {key}"
        );
    }
    ensure!(
        current["ControlGroup"] == ""
            && current["ExecStart"]
                .as_str()
                .zip(terminal["producer"]["unit"]["ExecStart"].as_str())
                .is_some_and(|(current, original)| {
                    pipeline_status::same_exec_start(original, current)
                }),
        "247 terminal command/cgroup changed"
    );
    for census in ["first_census", "second_census"] {
        ensure!(
            drain[census]["cgroup_present"] == false
                && drain[census]["descendant_processes"] == 0
                && drain[census]["original_cgroup"] == format!("/system.slice/{UNIT}")
                && drain[census]["properties"]["ControlPID"] == "0"
                && drain[census]["properties"]["ControlGroup"] == "",
            "247 prior drain differs"
        );
    }
    for proof in [terminal, drain] {
        for flag in [
            "resource_release_authorized",
            "publication_authorized",
            "replay_launch_authorized",
            "remote_mutations",
            "local_retirement_authorized",
        ] {
            ensure!(
                proof[flag] == false,
                "247 transition grants unexpected authority"
            );
        }
    }
    Ok(())
}
pub(super) fn capture(
    current: &Value,
    observer: &Value,
    observer_sha: &str,
    now: u64,
) -> Result<Value> {
    ensure!(
        observer["recorded_at_utc"] == SAMPLE && observer_sha == OBSERVER_SHA,
        "247 historical sample differs"
    );
    let terminal = pinned(TERMINAL_PATH, TERMINAL_SHA)?;
    let drain = pinned(DRAIN_PATH, DRAIN_SHA)?;
    terminal_owner(current, &terminal, &drain, now)?;
    Ok(proof(current))
}
fn proof(current: &Value) -> Value {
    json!({"schema":SCHEMA,"epoch":247,"unit":UNIT,"invocation_id":IID,
        "sampled_at_utc":SAMPLE,"observer_sha256":OBSERVER_SHA,"current_unit":current,
        "terminal_handoff":{"path":TERMINAL_PATH,"sha256":TERMINAL_SHA},
        "terminal_drain":{"path":DRAIN_PATH,"sha256":DRAIN_SHA},
        "historical_rss_retained_as_non_replay":true,"current_live_owner":false,
        "resource_release_authorized":false,"admission_authorized":false,"publication_authorized":false})
}
pub(crate) fn historical_row(ledger: &Value, row: &Value) -> Result<bool> {
    if row["producer_after"]["unit"] != UNIT {
        return Ok(false);
    }
    let proof = &ledger["terminal247_conservative_rss"];
    ensure!(
        proof["schema"] == SCHEMA
            && proof["unit"] == UNIT
            && proof["invocation_id"] == IID
            && proof["sampled_at_utc"] == SAMPLE
            && ledger["sampled_at_utc"] == SAMPLE
            && ledger["observer_sha256"] == OBSERVER_SHA
            && proof["observer_sha256"] == OBSERVER_SHA
            && proof["current_unit"] == ledger["unit_census"][UNIT]
            && proof["terminal_handoff"] == json!({"path":TERMINAL_PATH,"sha256":TERMINAL_SHA})
            && proof["terminal_drain"] == json!({"path":DRAIN_PATH,"sha256":DRAIN_SHA})
            && proof["historical_rss_retained_as_non_replay"] == true
            && proof["current_live_owner"] == false
            && proof["resource_release_authorized"] == false
            && proof["admission_authorized"] == false
            && proof["publication_authorized"] == false,
        "247 historical RSS proof differs"
    );
    let current = &proof["current_unit"];
    ensure!(
        current["Id"] == UNIT
            && current["InvocationID"] == IID
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["MainPID"] == "0"
            && current["NRestarts"] == "0"
            && current["Result"] == "success"
            && current["ControlGroup"] == "",
        "247 current owner not terminal"
    );
    ensure!(
        row["range"] == "247-247"
            && row["invocation_binding_stable"] == true
            && row["post_replay_finalization"] == true
            && row["resource_only"] == true,
        "247 historical row phase differs"
    );
    for role in [
        "controller_before",
        "controller_after",
        "producer_before",
        "producer_after",
    ] {
        ensure!(
            row[role]["unit"] == UNIT
                && row[role]["invocation_id"] == IID
                && row[role]["restarts"] == 0
                && row[role]["active_state"] == "active"
                && row[role]["sub_state"] == "running",
            "247 historical row owner differs"
        );
    }
    Ok(true)
}
pub(super) fn status_matches(
    evidence: &OperatorStatusEvidence,
    status: &EpochStatus,
    object: &MutableRemoteObject,
    current: &Value,
    now: u64,
) -> Result<bool> {
    let profiles = [
        (
            &evidence.basis,
            "intent.json",
            "ec66051f6e599502ec3c8674da27c2caa855a5b0893bbbf6ef4c6eb5d2430e2b",
        ),
        (
            &evidence.completion,
            "completion.json",
            "a1570028aa826db237a8d3e16de08438fdf63e6516b7fe1b6b59113819095c7b",
        ),
        (
            &evidence.raw_status,
            "readback.json",
            "52d9cdd1796c619b0917261c3acc57696bb0bddd88a78729e3a3515a1d60fa9a",
        ),
    ];
    let mut values = Vec::new();
    for (binding, name, digest) in profiles {
        let path = format!("{STATUS_ROOT}/{name}");
        ensure!(
            binding.path == Path::new(&path) && binding.sha256 == digest,
            "247 operator status profile differs"
        );
        values.push(pinned(&path, digest)?);
    }
    let terminal = pinned(TERMINAL_PATH, TERMINAL_SHA)?;
    let drain = pinned(DRAIN_PATH, DRAIN_SHA)?;
    terminal_owner(current, &terminal, &drain, now)?;
    status_values(
        &values[0],
        &values[1],
        &values[2],
        status,
        &object.bytes,
        &object.etag,
        now,
    )
}
pub(super) fn status_values(
    basis: &Value,
    completion: &Value,
    raw: &Value,
    status: &EpochStatus,
    bytes: &[u8],
    etag: &str,
    now: u64,
) -> Result<bool> {
    let seconds = basis["remaining_seconds"]
        .as_object()
        .context("247 delivery estimate missing")?;
    let fields = [
        "current_full_reader",
        "current_local_plugin",
        "current_remote_plugin",
        "serial_delivery_queue",
        "source_revalidation_and_sidecar",
        "upload_and_authenticated_readback",
    ];
    ensure!(
        seconds.len() == fields.len(),
        "247 delivery estimate fields differ"
    );
    let total = fields
        .iter()
        .try_fold(0_u64, |sum, key| {
            seconds[*key].as_u64().and_then(|n| sum.checked_add(n))
        })
        .and_then(|n| n.checked_mul(1000));
    let sampled = utc_seconds(&status.sampled_at_utc)?;
    Ok(
        basis["schema"] == "horizon247-postterminal-operator-status-v1"
            && basis["epoch"] == 247
            && basis["owner"] == "/root"
            && basis["thread_id"] == "01a1b2db-33e3-7163-a8b3-480390e3aaf3"
            && basis["stage"] == "postterminal-delivery-admission"
            && basis["terminal_handoff_sha256"] == TERMINAL_SHA
            && basis["terminal_drain_sha256"] == DRAIN_SHA
            && basis["archive_or_sidecar_mutation"] == false
            && basis["replay_launch_authorized"] == false
            && basis["estimate_high_uncertainty"] == true
            && basis["original_producer"]["InvocationID"] == IID
            && basis["original_producer"]["ActiveState"] == "inactive"
            && basis["status"] == *raw
            && *raw == serde_json::to_value(status)?
            && status.epoch == 247
            && status.phase == "verification"
            && total == Some(status.estimated_remaining_millis)
            && completion["schema"] == "horizon-status-only-correction-completion-v1"
            && completion["epoch"] == 247
            && completion["key"] == "epoch-247.epoch-status.json"
            && completion["owner"] == "/root"
            && completion["new_sha256"] == hex_lower(&Sha256::digest(bytes))
            && completion["new_sha256"] == basis["replacement_sha256"]
            && completion["new_etag"] == format!("\"{etag}\"")
            && completion["before_etag"] == basis["before_etag"]
            && completion["before_sha256"] == basis["before_sha256"]
            && completion["sampled_at_utc"] == status.sampled_at_utc
            && completion["authenticated_exact_byte_readback"] == true
            && completion["archive_or_sidecar_mutation"] == false
            && sampled <= now
            && now - sampled <= 1800,
    )
}

pub(super) fn validate_current(current: &Value, now: u64) -> Result<()> {
    terminal_owner(
        current,
        &pinned(TERMINAL_PATH, TERMINAL_SHA)?,
        &pinned(DRAIN_PATH, DRAIN_SHA)?,
        now,
    )
}

#[cfg(test)]
pub(crate) fn test_historical_ledger(ledger: &mut Value) {
    let current = json!({"Id":UNIT,"InvocationID":IID,"ActiveState":"inactive","SubState":"dead",
        "MainPID":"0","NRestarts":"0","Result":"success","ControlGroup":"","LoadState":"loaded",
        "ExecMainStatus":"0","ExecStart":"exact-command"});
    ledger["sampled_at_utc"] = json!(SAMPLE);
    ledger["observer_sha256"] = json!(OBSERVER_SHA);
    ledger["unit_census"] = json!({(UNIT):current});
    ledger["terminal247_conservative_rss"] = proof(&current);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_receipts_require_same_clean_owner_and_zero_descendants() {
        let mut ledger = json!({});
        test_historical_ledger(&mut ledger);
        let current = &ledger["unit_census"][UNIT];
        let mut terminal = json!({"schema":"horizon-singleton-delivery-handoff-v1","epoch":247,
            "producer":{"unit":current},"resource_release_authorized":false,"publication_authorized":false,
            "replay_launch_authorized":false,"remote_mutations":false,"local_retirement_authorized":false});
        let census = json!({"cgroup_present":false,"descendant_processes":0,"original_cgroup":format!("/system.slice/{UNIT}"),
            "properties":{"ControlPID":"0","ControlGroup":""}});
        let mut drain = json!({"schema":"horizon-singleton-terminal-drain-v1","epoch":247,
            "terminal_handoff":{"path":TERMINAL_PATH,"sha256":TERMINAL_SHA},"producer":terminal["producer"],
            "producer_cgroup_drained":true,"recorded_unix_seconds":100,"first_census":census,"second_census":census,
            "resource_release_authorized":false,"publication_authorized":false,"replay_launch_authorized":false,
            "remote_mutations":false,"local_retirement_authorized":false});
        terminal_owner(current, &terminal, &drain, 100).unwrap();
        // PID1 can clear execution-history fields after reload without changing
        // the retained invocation, configured command, or terminal outcome.
        let original = "{ path=/sealed/node ; argv[]=/sealed/node 247 ; ignore_errors=no ; start_time=[Tue 2026-11-17 02:31:12 UTC] ; stop_time=[Thu 2026-11-19 16:06:18 UTC] ; pid=50887 ; code=exited ; status=0 }";
        let cleared = "{ path=/sealed/node ; argv[]=/sealed/node 247 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        let mut retained = terminal.clone();
        retained["producer"]["unit"]["ExecStart"] = json!(original);
        let mut retained_drain = drain.clone();
        retained_drain["producer"] = retained["producer"].clone();
        let mut observed = current.clone();
        observed["ExecStart"] = json!(cleared);
        terminal_owner(&observed, &retained, &retained_drain, 100).unwrap();
        for changed in [
            cleared.replace("node 247", "node 248"),
            cleared.replace("ignore_errors=no", "ignore_errors=yes"),
            format!("{cleared} ; {cleared}"),
        ] {
            observed["ExecStart"] = json!(changed);
            assert!(terminal_owner(&observed, &retained, &retained_drain, 100).is_err());
        }
        assert!(terminal_owner(current, &terminal, &drain, 99).is_err());
        for key in [
            "InvocationID",
            "ActiveState",
            "MainPID",
            "NRestarts",
            "ExecStart",
            "Result",
            "ControlGroup",
        ] {
            let mut bad = current.clone();
            bad[key] = json!("changed");
            assert!(
                terminal_owner(&bad, &terminal, &drain, 100).is_err(),
                "{key}"
            );
        }
        drain["second_census"]["descendant_processes"] = json!(1);
        assert!(terminal_owner(current, &terminal, &drain, 100).is_err());
        drain["second_census"]["descendant_processes"] = json!(0);
        terminal["resource_release_authorized"] = json!(true);
        assert!(terminal_owner(current, &terminal, &drain, 100).is_err());
    }
    #[test]
    fn operator_status_requires_authenticated_bytes_owner_clock_and_complete_estimate() {
        let raw = json!({"epoch":247,"jet_size_bytes":180370916960_u64,"elapsed_execution_millis":221903141,
            "estimated_remaining_millis":77400000,"sampled_at_utc":"2026-11-19T16:09:36Z","phase":"verification"});
        let status: EpochStatus = serde_json::from_value(raw.clone()).unwrap();
        let bytes = serde_json::to_vec(&raw).unwrap();
        let digest = hex_lower(&Sha256::digest(&bytes));
        let basis = json!({"schema":"horizon247-postterminal-operator-status-v1","epoch":247,"owner":"/root",
            "thread_id":"01a1b2db-33e3-7163-a8b3-480390e3aaf3","stage":"postterminal-delivery-admission",
            "terminal_handoff_sha256":TERMINAL_SHA,"terminal_drain_sha256":DRAIN_SHA,"archive_or_sidecar_mutation":false,
            "replay_launch_authorized":false,"estimate_high_uncertainty":true,"original_producer":{"InvocationID":IID,"ActiveState":"inactive"},
            "status":raw,"replacement_sha256":digest,"before_etag":"old","before_sha256":"old-digest",
            "remaining_seconds":{"current_full_reader":7200,"current_local_plugin":21600,"current_remote_plugin":28800,
            "serial_delivery_queue":7200,"source_revalidation_and_sidecar":1800,"upload_and_authenticated_readback":10800}});
        let completion = json!({"schema":"horizon-status-only-correction-completion-v1","epoch":247,"key":"epoch-247.epoch-status.json",
            "owner":"/root","new_sha256":digest,"new_etag":"\"etag\"","before_etag":"old","before_sha256":"old-digest",
            "sampled_at_utc":status.sampled_at_utc,"authenticated_exact_byte_readback":true,"archive_or_sidecar_mutation":false});
        let now = utc_seconds(&status.sampled_at_utc).unwrap();
        assert!(status_values(&basis, &completion, &raw, &status, &bytes, "etag", now).unwrap());
        assert!(
            !status_values(&basis, &completion, &raw, &status, &bytes, "different", now).unwrap()
        );
        assert!(
            !status_values(&basis, &completion, &raw, &status, b"changed", "etag", now).unwrap()
        );
        assert!(
            !status_values(
                &basis,
                &completion,
                &raw,
                &status,
                &bytes,
                "etag",
                now + 1801
            )
            .unwrap()
        );
        let mut bad = basis.clone();
        bad["remaining_seconds"]["serial_delivery_queue"] = json!(7201);
        assert!(!status_values(&bad, &completion, &raw, &status, &bytes, "etag", now).unwrap());
        let mut bad = completion.clone();
        bad["authenticated_exact_byte_readback"] = json!(false);
        assert!(!status_values(&basis, &bad, &raw, &status, &bytes, "etag", now).unwrap());
    }
}
