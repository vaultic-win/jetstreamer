//! Immutable package, metadata policy and disposable enforcement capability.
use super::*;
#[cfg(test)]
mod tests;

// This profile constructs an exact metadata-free command. Accept only the one
// well-formed systemd display record; never normalize argv or other profiles.
fn probe_exec_start_matches(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    let Some(expected) = expected.strip_suffix(" }") else {
        return false;
    };
    let Some((identity, metadata)) = actual.split_once(" ; start_time=") else {
        return false;
    };
    if identity != expected {
        return false;
    }
    let Some(metadata) = metadata.strip_suffix(" }") else {
        return false;
    };
    let fields: Vec<_> = metadata.split(" ; ").collect();
    let timestamp = |s: &str| {
        s.strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .is_some_and(|s| !s.is_empty() && !s.contains(['[', ']', '{', '}', ';', '\n', '\r']))
    };
    fields.len() == 5
        && timestamp(fields[0])
        && fields[1].strip_prefix("stop_time=").is_some_and(timestamp)
        && fields[2].strip_prefix("pid=").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok()
        })
        && matches!(fields[3], "code=exited" | "code=killed" | "code=dumped")
        && fields[4].strip_prefix("status=").is_some_and(|s| {
            !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u32>().is_ok()
        })
}

pub(super) fn proposal(s: &Spec, p: &Value, r: &Value) -> Result<()> {
    let epoch = number(p, "epoch")?;
    original(epoch)?;
    ensure!(
        p["schema"] == "jetstreamer-capped204205-continuation-plan-v1"
            && r["schema"] == "jetstreamer-capped204205-resource-proposal-v1"
            && r["producer_plan"] == private157::binding(&s.producer_plan)
            && r["source_closure"] == private157::binding(&s.source_closure)
            && r["resource_capability"] == private157::binding(&s.resource_capability)
            && p["node_sha256"] == s.producer.sha256
            && p["guard_sha256"] == s.control.sha256,
        "capped proposal does not bind the exact final immutable plan/package"
    );
    for key in [
        "epoch",
        "node_sha256",
        "guard_sha256",
        "producer_unit",
        "guard_unit",
        "run_root",
        "protected_existing_floor_bytes",
        "candidate_incremental_peak_bytes",
        "maximum_root_physical_bytes",
        "maximum_process_rss_bytes",
        "maximum_worker_vmas",
    ] {
        ensure!(
            r[key] == p[key],
            "capped resource proposal differs from producer plan:{key}"
        );
    }
    denied(r)?;
    let root = number(p, "maximum_root_physical_bytes")?;
    let metadata = number(r, "external_control_metadata_bytes")?;
    ensure!(
        metadata >= 16 << 20
            && number(p, "candidate_incremental_peak_bytes")?
                >= root
                    .checked_add(metadata)
                    .context("capped disk staging overflow")?
            && number(p, "candidate_incremental_peak_bytes")? >= 256 << 30
            && root
                >= number(p, "prefix_bytes")?
                    .checked_add(32 << 30)
                    .context("capped assembly overlap overflow")?
            && (1..=3_500_000).contains(&number(p, "maximum_worker_vmas")?),
        "capped full root/assembly/control/VMA envelope is under-reserved"
    );
    let k = &r["kernel_limits"];
    ensure!(
        k.as_object().is_some_and(|o| o.len() == 6),
        "capped kernel limits must have exactly six numeric fields"
    );
    let memory = number(k, "requested_memory_max_bytes")?;
    let high = number(k, "requested_memory_high_bytes")?;
    let runtime = number(k, "runtime_max_usec")?;
    let max_runtime = number(p, "maximum_stage_millis")?
        .checked_mul(6000)
        .context("capped runtime overflow")?;
    ensure!(
        number(p, "maximum_process_rss_bytes")? > 0
            && memory >= number(p, "maximum_process_rss_bytes")?
            && high > 0
            && high <= memory
            && number(k, "memory_swap_max_bytes")? == 0
            && (1..=512).contains(&number(k, "tasks_max")?)
            && (1..=8_000_000).contains(&number(k, "cpu_quota_usec_per_second")?)
            && runtime > 0
            && runtime <= max_runtime
            && (1 << 20..=1 << 30).contains(&number(r, "guard_memory_max_bytes")?),
        "capped kernel guard envelope is not complete/bounded"
    );
    Ok(())
}
fn bound_member(v: &Value) -> Result<BoundFile> {
    let b: BoundFile = serde_json::from_value(v.clone())?;
    ensure!(
        canonical_digest(&json!(b.sha256)),
        "capped source member digest malformed"
    );
    Ok(b)
}
pub(super) fn source_closure(s: &Spec, p: &Value) -> Result<()> {
    native209_admission::sealed_file(&s.producer.path, &s.producer.sha256, None)?;
    native209_admission::sealed_file(&s.control.path, &s.control.sha256, None)?;
    let v = native209::immutable_json(&s.source_closure)?;
    ensure!(
        v["schema"] == "jetstreamer-capped204205-source-closure-v1"
            && v["producer"] == private157::binding(&s.producer)
            && v["control"] == private157::binding(&s.control)
            && v["worker_sha256"] == p["worker"]["sha256"]
            && v["exclusive_feature"] == "capped204205-checkpoint-continuation-diagnostic"
            && v["source_revision"].as_str().is_some_and(|s| s.len() == 40
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && canonical_digest(&v["complete_dependency_closure_sha256"])
            && v["original_raw_native_tuple_and_cursor_rules_preserved"] == true,
        "capped exact exclusive source closure is missing"
    );
    denied(&v)?;
    let files = v["source_files"]
        .as_object()
        .context("capped sealed source files missing")?;
    for name in [
        "Cargo.lock",
        "capped_prefix204205.rs",
        "capped_control204205.rs",
        "checkpoint_continuation204205.rs",
        "capped204205_resource_probe.rs",
        "guard_core.rs",
    ] {
        ensure!(
            files.contains_key(name),
            "capped source closure omitted:{name}"
        );
    }
    ensure!(
        (6..=256).contains(&files.len()),
        "capped source closure bounds"
    );
    for b in files.values() {
        let b = bound_member(b)?;
        native209_admission::sealed_file(&b.path, &b.sha256, None)?;
    }
    Ok(())
}
fn capability_value(s: &Spec, p: &Value, r: &Value, v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-capped204205-resource-capability-v1"
            && v["capability_kind"] == "disposable-equivalent-sandbox-guard"
            && v["epoch"] == p["epoch"]
            && v["producer"] == private157::binding(&s.producer)
            && v["control"] == private157::binding(&s.control)
            && v["source_closure"] == private157::binding(&s.source_closure)
            && v["kernel_limits"] == r["kernel_limits"]
            && v["guard_memory_max_bytes"] == r["guard_memory_max_bytes"]
            && v["maximum_root_physical_bytes"] == p["maximum_root_physical_bytes"]
            && v["maximum_process_rss_bytes"] == p["maximum_process_rss_bytes"]
            && v["maximum_worker_vmas"] == p["maximum_worker_vmas"]
            && v["bounded_enforcement_proven"] == true
            && v["observed_production_peak_claimed"] == false
            && v["native_initialized"] == false
            && v["archive_body_read"] == false,
        "capped complete-path enforcement capability missing or unqualified"
    );
    denied(v)?;
    ensure!(
        v["host_machine_id"].as_str().is_some_and(|s| s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0')),
        "capped capability has no exact host identity"
    );
    for key in [
        "whole_process_tree_bounded",
        "whole_root_bounded",
        "guard_trip_stops_exact_invocation",
        "unproven_guard_blocks_stage_entry",
        "monotonic_stage_deadlines",
        "restore_suffix_assembly_overlap_included",
        "native_barrier_precedes_entries",
        "no_canonical_sidecar_or_publication",
    ] {
        ensure!(
            v["enforcement"][key] == true,
            "capped equivalent-sandbox proof missing:{key}"
        );
    }
    ensure!(
        v["stages"]
            == json!([
                "prefix_validation",
                "native_restore",
                "suffix_validation",
                "assembly"
            ])
            && v["probe_unit"]
                .as_str()
                .is_some_and(|n| n.starts_with("horizon-capped204205-resource-probe-")
                    && n.ends_with(".service"))
            && v["probe_invocation_id"]
                .as_str()
                .is_some_and(|n| n.len() == 32
                    && n.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && n.bytes().any(|b| b != b'0')),
        "capped equivalent-sandbox probe owner/stages invalid"
    );
    Ok(())
}
pub(super) fn capability(s: &Spec, p: &Value, r: &Value) -> Result<Value> {
    let v = native209::immutable_json(&s.resource_capability)?;
    capability_value(s, p, r, &v)?;
    let machine = fs::read_to_string("/etc/machine-id")?;
    ensure!(
        v["host_machine_id"] == machine.trim(),
        "capped enforcement capability belongs to another host"
    );
    let probe = bound_member(&v["probe"])?;
    native209_admission::sealed_file(&probe.path, &probe.sha256, None)?;
    let closure = native209::immutable_json(&s.source_closure)?;
    ensure!(
        closure["resource_probe"] == private157::binding(&probe),
        "capped capability probe is not in the exact source closure"
    );
    let probe_plan_binding = bound_member(&v["probe_plan"])?;
    let probe_plan = native209::immutable_json(&probe_plan_binding)?;
    ensure!(
        probe_plan["schema"] == "jetstreamer-capped204205-resource-probe-plan-v1"
            && probe_plan["epoch"] == p["epoch"]
            && probe_plan["producer"] == private157::binding(&s.producer)
            && probe_plan["control"] == private157::binding(&s.control)
            && probe_plan["source_closure"] == private157::binding(&s.source_closure),
        "capped probe plan has another package/scope"
    );
    for key in [
        "kernel_limits",
        "guard_memory_max_bytes",
        "maximum_root_physical_bytes",
        "maximum_process_rss_bytes",
        "maximum_worker_vmas",
    ] {
        ensure!(
            probe_plan[key] == v[key],
            "capped probe plan changed enforced envelope:{key}"
        );
    }
    let result = native209::immutable_json(&bound_member(&v["probe_receipt"])?)?;
    probe_result(&v, &probe, &probe_plan_binding, &result)?;
    let terminal = native209::immutable_json(&bound_member(&v["terminal_properties"])?)?;
    dormant(&terminal, string(&v, "probe_unit")?)?;
    ensure!(
        terminal["LoadState"] == "loaded"
            && terminal["Type"] == "exec"
            && terminal["InvocationID"] == v["probe_invocation_id"]
            && terminal["Result"] == "success"
            && terminal["ExecMainStatus"] == "0"
            && terminal["ActiveState"] == "inactive"
            && terminal["SubState"] == "dead",
        "capped enforcement probe lacks genuine terminal success"
    );
    let pid = number(&v, "probe_main_pid")?;
    ensure!(
        pid > 1
            && terminal["ExecMainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(pid),
        "capped probe lost its actual executed PID"
    );
    let command = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} ; ignore_errors=no }}",
        probe.path.display(),
        probe.path.display(),
        probe_plan_binding.path.display(),
        probe_plan_binding.sha256,
        probe.sha256
    );
    ensure!(
        probe_exec_start_matches(&command, string(&terminal, "ExecStart")?),
        "capped probe command differs from exact package/plan"
    );
    let journal = native209::immutable_json(&bound_member(&v["manager_journal"])?)?;
    let rows = journal
        .as_array()
        .context("capped probe manager journal must be a bounded JSON array")?;
    ensure!(
        !rows.is_empty() && rows.len() <= 8192,
        "capped probe journal bounds"
    );
    let manager = rows
        .iter()
        .filter(|row| {
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["_MACHINE_ID"] == v["host_machine_id"]
                && row["UNIT"] == v["probe_unit"]
                && row["INVOCATION_ID"] == v["probe_invocation_id"]
        })
        .collect::<Vec<_>>();
    let success = format!("{}: Deactivated successfully.", string(&v, "probe_unit")?);
    ensure!(
        manager
            .iter()
            .filter(|row| row["MESSAGE"] == success)
            .count()
            == 1
            && !manager.iter().any(|row| row["MESSAGE"]
                .as_str()
                .is_some_and(|text| text.contains("Failed")
                    || text.contains("Failed with result")
                    || text.contains("Main process exited"))),
        "capped enforcement proof lacks unique clean PID1 completion"
    );
    let stdout = rows
        .iter()
        .filter(|row| {
            row["_UID"] == "0"
                && row["_MACHINE_ID"] == v["host_machine_id"]
                && row["_PID"].as_str().and_then(|s| s.parse::<u64>().ok()) == Some(pid)
                && row["_SYSTEMD_UNIT"] == v["probe_unit"]
                && row["_SYSTEMD_INVOCATION_ID"] == v["probe_invocation_id"]
                && row["_EXE"].as_str() == probe.path.to_str()
                && row["MESSAGE"]
                    .as_str()
                    .and_then(|text| serde_json::from_str::<Value>(text).ok())
                    .is_some_and(|message| message == result)
        })
        .count();
    ensure!(
        stdout == 1,
        "capped resource enforcement result lacks one exact actual probe stdout record"
    );
    Ok(v)
}
fn probe_result(cap: &Value, probe: &BoundFile, plan: &BoundFile, result: &Value) -> Result<()> {
    ensure!(
        result["schema"] == "jetstreamer-capped204205-resource-probe-result-v1"
            && result["self_sha256"] == probe.sha256
            && result["plan_sha256"] == plan.sha256
            && result["probe_unit"] == cap["probe_unit"]
            && result["probe_invocation_id"] == cap["probe_invocation_id"]
            && result["epoch"] == cap["epoch"]
            && result["enforcement"] == cap["enforcement"]
            && result["kernel_limits"] == cap["kernel_limits"]
            && result["bounded_enforcement_proven"] == true
            && result["native_initialized"] == false
            && result["archive_body_read"] == false,
        "capped actual probe result does not prove this exact package/envelope"
    );
    denied(result)?;
    let actual = &result["actual_kernel"];
    let k = &cap["kernel_limits"];
    let page = number(actual, "host_page_size_bytes")?;
    ensure!(
        page > 0 && page.is_power_of_two(),
        "capped probe page size absent"
    );
    let max = number(k, "requested_memory_max_bytes")?;
    let high = number(k, "requested_memory_high_bytes")?;
    let guard = number(cap, "guard_memory_max_bytes")?;
    let period = number(actual, "cpu_period_usec")?;
    ensure!(
        page <= high.min(max).min(guard)
            && actual["requested_memory_max_bytes"] == max
            && actual["requested_memory_high_bytes"] == high
            && actual["kernel_memory_max_bytes"] == max / page * page
            && actual["kernel_memory_high_bytes"] == high / page * page
            && actual["memory_swap_max_bytes"] == 0
            && actual["tasks_max"] == k["tasks_max"]
            && actual["runtime_max_usec"] == k["runtime_max_usec"]
            && actual["guard_requested_memory_max_bytes"] == guard
            && actual["guard_kernel_memory_max_bytes"] == guard / page * page
            && period > 0
            && u128::from(number(actual, "cpu_quota_usec")?) * 1_000_000
                == u128::from(number(k, "cpu_quota_usec_per_second")?) * u128::from(period),
        "capped observed probe cgroup/systemd limits differ from the reserved envelope"
    );
    Ok(())
}
pub(super) fn policy(s: &Spec, p: &Value, v: &Value) -> Result<()> {
    let epoch = number(p, "epoch")?;
    let (old, iid) = original(epoch)?;
    ensure!(
        v["schema"] == "jetstreamer-capped204205-admission-inputs-v1"
            && v["validated"] == true
            && v["epoch"] == epoch
            && v["plan_sha256"] == s.producer_plan.sha256
            && v["self_sha256"] == s.control.sha256
            && v["proposal"] == *p
            && v["source_capture_sha256"] == p["source_capture"]["sha256"]
            && v["resource_samples_taken"] == 0
            && v["source_idle_censuses_taken"] == 1,
        "capped validator did not authenticate the exact final plan"
    );
    for key in [
        "archive_body_read",
        "snapshot_body_read",
        "native_initialized",
        "fresh_admission_passed",
        "guard_proven",
        "suffix_execution_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "capped input policy grants premature authority:{key}"
        );
    }
    let input = &v["input_policy"];
    for key in [
        "current_source_idleness_proven",
        "resource_admission_passed",
        "native_initialized",
        "suffix_execution_authorized",
        "assembly_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            input[key] == false,
            "capped rederived metadata policy grants premature authority:{key}"
        );
    }
    ensure!(
        input["schema"] == "jetstreamer-capped204205-native-input-policy-v1"
            && input["epoch"] == epoch
            && input["original_unit"] == old
            && input["original_invocation_id"] == iid
            && input["restart_snapshot"]["sha256"] == p["restart_snapshot"]["sha256"]
            && input["restart_snapshot"]["path"] == p["restart_snapshot"]["path"]
            && input["native_worker_must_rehash_full_snapshot"] == true
            && input["actual_suffix_must_repeat_native_barrier"] == true,
        "capped metadata/native policy changed original source/tuple rules"
    );
    for (key, member) in [
        ("original_launch_sha256", "original_launch"),
        ("producer_result_sha256", "producer_result"),
        ("terminal_properties_sha256", "terminal_properties"),
        ("manager_journal_sha256", "manager_journal"),
        ("prefix_manifest_sha256", "prefix_manifest"),
        ("prefix_validation_sha256", "prefix_validation"),
    ] {
        ensure!(
            input[key] == p["metadata"][member]["sha256"],
            "capped input policy lost reader/metadata binding:{key}"
        );
    }
    let idle = &v["source_idle"];
    for key in [
        "resource_sample_performed",
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
    ] {
        ensure!(
            idle[key] == false,
            "capped source closure grants unrelated authority:{key}"
        );
    }
    let root = Path::new(string(&p["prefix_archive"], "path")?)
        .parent()
        .and_then(Path::parent)
        .context("capped original source root missing")?;
    ensure!(
        idle["schema"] == "jetstreamer-capped204205-source-idle-v1"
            && idle["epoch"] == epoch
            && idle["unit"] == old
            && idle["historical_invocation_id"] == iid
            && idle["source_root"] == root.to_string_lossy().as_ref()
            && idle["current_source_idle"] == true
            && idle["process_reference_census"]["references"] == json!([]),
        "capped original source still active or referenced"
    );
    for (key, bytes) in [
        ("archive_identity", number(p, "prefix_bytes")?),
        (
            "retained_snapshot_identity",
            number(&input["restart_snapshot"], "bytes")?,
        ),
    ] {
        let i = &v[key];
        ensure!(
            i["bytes"] == bytes
                && i["uid"] == 0
                && i["links"] == 1
                && number(i, "mode")? & 0o222 == 0
                && number(i, "device")? > 0
                && number(i, "inode")? > 0,
            "capped retained input is not frozen/unique:{key}"
        );
    }
    ensure!(
        canonical_digest(&v["manifest_content_sha256"]),
        "capped typed manifest content digest absent"
    );
    Ok(())
}
pub(super) fn validate_plan(s: &Spec, p: &Value) -> Result<Value> {
    native209_admission::sealed_file(&s.control.path, &s.control.sha256, None)?;
    let output = ProcessCommand::new("/usr/bin/timeout")
        .args(["--signal=TERM", "--kill-after=5s", "120s"])
        .arg(&s.control.path)
        .arg("validate-plan")
        .arg(&s.producer_plan.path)
        .arg("--plan-sha256")
        .arg(&s.producer_plan.sha256)
        .arg("--self-sha256")
        .arg(&s.control.sha256)
        .env("LC_ALL", "C")
        .output()?;
    ensure!(
        output.status.success()
            && output.stdout.len() <= 64 << 10
            && output.stderr.len() <= 64 << 10,
        "capped sealed input validator failed or exceeded output bounds"
    );
    native209_admission::sealed_file(&s.control.path, &s.control.sha256, None)?;
    let v: Value = serde_json::from_slice(&output.stdout)?;
    policy(s, p, &v)?;
    Ok(v)
}
pub(super) fn stable_policies(before: &Value, after: &Value) -> Result<()> {
    for key in [
        "epoch",
        "plan_sha256",
        "self_sha256",
        "proposal",
        "input_policy",
        "source_capture_sha256",
        "manifest_content_sha256",
        "archive_identity",
        "retained_snapshot_identity",
    ] {
        ensure!(
            before.get(key).is_some() && before[key] == after[key],
            "capped retained input/policy changed during admission:{key}"
        );
    }
    Ok(())
}
