//! Consume separately sealed controller exit evidence without promoting it to
//! archive verification, a resource reservation release, or fresh admission.
use super::checkpoint_continuation::{Evidence, require, sealed_bytes};
use serde_json::Value;

// Qualified issuer: e0045863 source, three rejection tests plus real clean-exit
// and remaining-descendant systemd controls. A new issuer requires qualification.
const ISSUER: &str = "52cd459e6e21b2e6ed6063269ddd88968a330bab97b39ad3830411ed5a003517";
// Adds exact-byte receipt reuse only after repeating all live exit checks.
// Qualified with root-private conflict/link tests and a controller crash after
// publication of an authentic native producer's proof, followed by fresh reuse.
const RECOVERABLE_ISSUER: &str = "ea70093e85a113c5879e8625a2bf90730da94ac6a335ff248f9e38689e1047e6";

pub(crate) fn load(
    evidence: &Evidence,
    report: &Value,
    report_sha: &str,
    epoch: u64,
) -> Result<(), String> {
    let proof: Value =
        serde_json::from_slice(&sealed_bytes(evidence, 4 << 20)?).map_err(|e| e.to_string())?;
    let plan_binding: Evidence = serde_json::from_value(proof["plan"].clone())
        .map_err(|e| format!("invalid exit plan binding: {e}"))?;
    let plan: Value = serde_json::from_slice(&sealed_bytes(&plan_binding, 4 << 20)?)
        .map_err(|e| e.to_string())?;
    validate(&proof, &plan, report, report_sha, epoch)?;
    let worker_pid: i32 = report["worker_shutdown"]["worker_pid"]
        .as_u64()
        .ok_or("missing reaped worker PID")?
        .try_into()
        .map_err(|_| "worker PID overflow")?;
    require(
        unsafe { libc::kill(worker_pid, 0) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "checkpoint worker exists after the recorded exit proof",
    )
}

fn validate(
    proof: &Value,
    plan: &Value,
    report: &Value,
    report_sha: &str,
    epoch: u64,
) -> Result<(), String> {
    super::checkpoint_continuation::sha(report_sha)?;
    require(
        proof["schema"] == "horizon-pressure-exit-proof-v1"
            && proof["tool_sha256"]
                .as_str()
                .is_some_and(|issuer| [ISSUER, RECOVERABLE_ISSUER].contains(&issuer))
            && plan["schema"] == "horizon-pressure-exit-plan-v1"
            && proof["epoch"] == epoch
            && plan["epoch"] == epoch
            && report["epoch"] == epoch
            && proof["producer_pid_absent"] == true
            && proof["worker_pid_absent"] == true
            && proof["checkpoint_bundle_validation_required"] == true
            && proof["full_parent_firehose_qualified"] == false
            && proof["resource_release_authorized"] == false
            && proof["resume_authorized"] == false
            && proof["publication_authorized"] == false,
        "exit proof issuer, epoch or authority differs",
    )?;
    // The producer's private paused file may be copied into an immutable seal.
    // Bind its exact content; retain the original path via the sealed exit plan.
    require(
        proof["report"] == plan["report"]
            && plan["report"]["sha256"] == report_sha
            && plan["report"]["path"]
                .as_str()
                .is_some_and(|s| std::path::Path::new(s).is_absolute()),
        "exit proof is bound to another paused report",
    )?;
    let unit = plan["unit"].as_str().ok_or("missing exit unit")?;
    let iid = plan["invocation_id"]
        .as_str()
        .ok_or("missing exit invocation")?;
    let pid = plan["producer_pid"]
        .as_u64()
        .ok_or("missing exit producer PID")?;
    let worker = report["worker_shutdown"]["worker_pid"]
        .as_u64()
        .ok_or("missing reaped worker PID")?;
    require(
        unit.starts_with("horizon-")
            && unit.ends_with(".service")
            && unit.len() < 200
            && !unit.contains("..")
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && pid > 1
            && pid <= i32::MAX as u64
            && worker > 1
            && worker <= i32::MAX as u64
            && worker != pid
            && report["producer_pid"] == pid
            && report["producer_invocation_id"] == iid,
        "exit proof producer identity differs",
    )?;
    let before = &proof["producer_before"];
    let after = &proof["producer_after"];
    let cg = format!("/system.slice/{unit}");
    require(
        before == after
            && after["Id"] == unit
            && after["InvocationID"] == iid
            && after["LoadState"] == "loaded"
            && after["ExecMainPID"] == pid.to_string()
            && after["MainPID"] == "0"
            && after["ControlPID"] == "0"
            && after["ExecMainCode"] == "1"
            && after["ExecMainStatus"] == "0"
            && after["Result"] == "success"
            && after["NRestarts"] == "0"
            && after["Restart"] == "no"
            && after["KillMode"] == "control-group"
            && after["Delegate"] == "no"
            && (after["ControlGroup"] == "" || after["ControlGroup"] == cg)
            && ((after["ActiveState"] == "inactive" && after["SubState"] == "dead")
                || (after["ActiveState"] == "active" && after["SubState"] == "exited")),
        "exit proof lacks a stable clean terminal producer",
    )?;
    for key in ["cgroup_before", "cgroup_after"] {
        let group = &proof[key];
        require(
            group["path"] == format!("/sys/fs/cgroup{cg}")
                && (group["state"] == "absent"
                    || (group["state"] == "empty"
                        && group["events"].as_str().is_some_and(|s| {
                            s.lines()
                                .filter(|l| l.starts_with("populated "))
                                .collect::<Vec<_>>()
                                == vec!["populated 0"]
                        }))),
            "exit proof does not establish an empty expected cgroup",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixture() -> (Value, Value, Value) {
        let plan = json!({"schema":"horizon-pressure-exit-plan-v1","unit":"horizon-example.service",
            "invocation_id":"a".repeat(32),"producer_pid":1234,"epoch":252,
            "report":{"path":"/private/paused.json","sha256":"b".repeat(64)}});
        let terminal = json!({"Id":plan["unit"],"LoadState":"loaded","InvocationID":plan["invocation_id"],
            "ExecMainPID":"1234","MainPID":"0","ControlPID":"0","ExecMainCode":"1","ExecMainStatus":"0",
            "Result":"success","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no",
            "ControlGroup":"","ActiveState":"active","SubState":"exited"});
        let group = json!({"path":"/sys/fs/cgroup/system.slice/horizon-example.service","state":"empty","events":"populated 0\nfrozen 0\n"});
        let proof = json!({"schema":"horizon-pressure-exit-proof-v1","tool_sha256":ISSUER,"epoch":252,
            "report":plan["report"],"producer_pid_absent":true,"worker_pid_absent":true,
            "checkpoint_bundle_validation_required":true,"full_parent_firehose_qualified":false,
            "resource_release_authorized":false,"resume_authorized":false,"publication_authorized":false,
            "producer_before":terminal,"producer_after":terminal,"cgroup_before":group,"cgroup_after":group});
        let report = json!({"epoch":252,"producer_pid":1234,"producer_invocation_id":plan["invocation_id"],
            "worker_shutdown":{"worker_pid":1235}});
        (proof, plan, report)
    }
    #[test]
    fn binds_issuer_plan_report_epoch_and_exit_scope() {
        let (mut proof, plan, report) = fixture();
        validate(&proof, &plan, &report, &"b".repeat(64), 252).unwrap();
        proof["tool_sha256"] = json!(RECOVERABLE_ISSUER);
        validate(&proof, &plan, &report, &"b".repeat(64), 252).unwrap();
        assert!(validate(&proof, &plan, &report, &"c".repeat(64), 252).is_err());
        assert!(validate(&proof, &plan, &report, &"b".repeat(64), 253).is_err());
        for (key, value) in [
            ("tool_sha256", json!("c".repeat(64))),
            ("resume_authorized", json!(true)),
            ("resource_release_authorized", json!(true)),
            ("producer_pid_absent", json!(false)),
            ("worker_pid_absent", json!(false)),
            ("checkpoint_bundle_validation_required", json!(false)),
        ] {
            let mut bad = proof.clone();
            bad[key] = value;
            assert!(
                validate(&bad, &plan, &report, &"b".repeat(64), 252).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn rejects_replaced_or_live_producers_and_cgroup_descendants() {
        let (proof, plan, report) = fixture();
        for (key, value) in [
            ("InvocationID", json!("b".repeat(32))),
            ("ExecMainPID", json!("99")),
            ("SubState", json!("running")),
            ("NRestarts", json!("1")),
            ("KillMode", json!("process")),
            ("Delegate", json!("yes")),
        ] {
            let mut bad = proof.clone();
            bad["producer_before"][key] = value.clone();
            bad["producer_after"][key] = value;
            assert!(
                validate(&bad, &plan, &report, &"b".repeat(64), 252).is_err(),
                "{key}"
            );
        }
        for value in [
            json!("populated 1\n"),
            json!("populated 0\npopulated 1\n"),
            Value::Null,
        ] {
            let mut bad = proof.clone();
            bad["cgroup_after"]["events"] = value;
            assert!(validate(&bad, &plan, &report, &"b".repeat(64), 252).is_err());
        }
        let mut bad = report.clone();
        bad["producer_pid"] = json!(4321);
        assert!(validate(&proof, &plan, &bad, &"b".repeat(64), 252).is_err());
    }
    #[test]
    #[ignore = "requires independently sealed native systemd exit proof and paused report"]
    fn consumes_actual_native_exit_proof() {
        let proof = Evidence {
            path: std::env::var_os("HORIZON_NATIVE_EXIT_PROOF")
                .unwrap()
                .into(),
            sha256: std::env::var("HORIZON_NATIVE_EXIT_PROOF_SHA256").unwrap(),
        };
        let report = Evidence {
            path: std::env::var_os("HORIZON_NATIVE_PAUSED_REPORT")
                .unwrap()
                .into(),
            sha256: std::env::var("HORIZON_NATIVE_PAUSED_REPORT_SHA256").unwrap(),
        };
        let report_value =
            serde_json::from_slice(&sealed_bytes(&report, 4 << 20).unwrap()).unwrap();
        load(&proof, &report_value, &report.sha256, 252).unwrap();
    }
}
