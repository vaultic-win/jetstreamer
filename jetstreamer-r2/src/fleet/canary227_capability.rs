//! Bind the actual no-worker capability to its immutable plan and PID1 completion.
use super::canary227 as c;
use super::singleton227_capture::{journal, properties, require};
use super::*;
mod collected;
fn scope(v: &Value, plan: &Value, b: &BoundFile) -> Result<(String, PathBuf)> {
    let unit = plan["unit"].as_str().context("227 capability unit")?;
    let root = PathBuf::from(plan["run_root"].as_str().context("227 capability root")?);
    ensure!(
        unit.starts_with("horizon-qualify-227-v1625-bounded-resource-")
            && unit.ends_with("-capability-v1.service")
            && unit
                .bytes()
                .all(|n| n.is_ascii_alphanumeric() || b"-_.".contains(&n))
            && unit != c::UNIT
            && root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && root != Path::new(c::ROOT)
            && root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("bounded-resource-227-v1625-")
                    && n.bytes()
                        .all(|x| x.is_ascii_alphanumeric() || b"-_".contains(&x)))
            && b.path == root.join("receipts/capability.json")
            && plan["schema"] == "jetstreamer-private-epoch227-v1625-comparison-plan-v1"
            && plan["node"] == json!({"path":c::NODE,"sha256":c::NODE_SHA})
            && plan["worker"] == c::WORKER
            && plan["snapshot"] == c::SNAPSHOT
            && plan["ledger_directory"] == c::INPUT
            && plan["target_slot"] == c::TARGET
            && plan["terminal_slot"] == c::TERMINAL
            && plan["maximum_runtime_seconds"] == c::RUNTIME_MAX
            && v["invocation_id"].as_str().is_some_and(|n| n.len() == 32
                && n.bytes()
                    .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))),
        "227 capability immutable scope differs"
    );
    Ok((unit.into(), root))
}
pub(super) fn validate(b: &BoundFile, v: &Value) -> Result<Value> {
    let plan_binding = BoundFile {
        path: v["bindings"]["plan_path"]
            .as_str()
            .context("227 capability plan path")?
            .into(),
        sha256: v["bindings"]["plan_sha256"]
            .as_str()
            .context("227 capability plan sha")?
            .into(),
    };
    let plan = native227_v1625::immutable_json(&plan_binding)?;
    let (unit, root) = scope(v, &plan, b)?;
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o400,
        "227 unsafe actual capability receipt"
    );
    let fragment = PathBuf::from(format!("/etc/systemd/system/{unit}"));
    let unit_binding: BoundFile = serde_json::from_value(private157::file_binding(&fragment)?)?;
    native209_admission::sealed_file(&fragment, &unit_binding.sha256, None)?;
    ensure!(
        fs::symlink_metadata(&fragment)?.mode() & 0o7777 == 0o444,
        "227 capability unit not readonly"
    );
    if collected::applies(b) {
        return collected::validate(b, v, &plan_binding, &unit_binding);
    }
    let fields = "Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,TimeoutStartUSec,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,InvocationID,ExecMainStartTimestampMonotonic,ExecMainExitTimestampMonotonic,ExecMainPID,ExecMainCode,ExecMainStatus,Result,ActiveState,SubState,NRestarts,ExecStart,Transient,FragmentPath,RemainAfterExit";
    let before = properties(&unit, fields)?;
    require(
        &before,
        &[
            ("Type", "oneshot"),
            ("User", "ubuntu"),
            ("Group", "ubuntu"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("MemoryHigh", "150000000000"),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("TimeoutStartUSec", "10min"),
            ("ProtectHome", "read-only"),
            ("ProtectSystem", "strict"),
            ("PrivateNetwork", "no"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", ""),
            (
                "ReadWritePaths",
                root.to_str().context("227 capability root UTF8")?,
            ),
            ("ExecMainCode", "1"),
            ("ExecMainStatus", "0"),
            ("Result", "success"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("NRestarts", "0"),
            ("Transient", "no"),
            (
                "FragmentPath",
                fragment.to_str().context("227 capability fragment UTF8")?,
            ),
            ("RemainAfterExit", "no"),
        ],
    )?;
    ensure!(
        before["ExecMainPID"].parse::<u64>()? > 1,
        "227 capability actual PID missing"
    );
    let expected = format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {} --storage-capability ; ignore_errors=no }}",
        c::RUNNER,
        c::RUNNER,
        plan_binding.path.display(),
        plan_binding.sha256,
        c::RUNNER_SHA
    );
    ensure!(
        c::same_command(&json!(before["ExecStart"]), &json!(expected)),
        "227 capability actual command differs"
    );
    let (rows, sha) = journal(&unit)?;
    let success = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == unit
                && r["INVOCATION_ID"] == v["invocation_id"]
                && r["MESSAGE"] == format!("{unit}: Deactivated successfully.")
        })
        .collect::<Vec<_>>();
    ensure!(
        success.len() == 1,
        "227 capability missing unique PID1 completion"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let started = before["ExecMainStartTimestampMonotonic"].parse::<u64>()?;
    let exited = before["ExecMainExitTimestampMonotonic"].parse::<u64>()?;
    let completed = success[0]["__MONOTONIC_TIMESTAMP"]
        .as_str()
        .context("227 capability manager completion clock")?
        .parse::<u64>()?;
    ensure!(
        started > 0
            && exited >= started
            && completed >= exited
            && completed - exited <= 5_000_000
            && success[0]["_BOOT_ID"] == boot
            && (before["InvocationID"].is_empty()
                || before["InvocationID"]
                    == v["invocation_id"].as_str().context("227 capability IID")?),
        "227 capability success does not bind the latest terminal PID/start/exit or boot"
    );

    ensure!(
        properties(&unit, fields)? == before && bound_json(b)? == *v,
        "227 capability identity changed during validation"
    );
    Ok(
        json!({"plan":private157::binding(&plan_binding),"unit_file":private157::binding(&unit_binding),"actual_terminal_properties":before,"manager_completion":success[0],"journal_sha256":sha,"resource_observation_performed":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_cannot_reuse_actual_canary_root_or_unit() {
        let mut p = json!({"schema":"jetstreamer-private-epoch227-v1625-comparison-plan-v1","unit":"horizon-qualify-227-v1625-bounded-resource-d01adb19-capability-v1.service","run_root":"/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-capability-v1","node":{"path":c::NODE,"sha256":c::NODE_SHA},"worker":c::WORKER,"snapshot":c::SNAPSHOT,"ledger_directory":c::INPUT,"target_slot":c::TARGET,"terminal_slot":c::TERMINAL,"maximum_runtime_seconds":c::RUNTIME_MAX});
        let v = json!({"invocation_id":"a".repeat(32)});
        let b=BoundFile{path:"/home/ubuntu/.jetstreamer-private/bounded-resource-227-v1625-d01adb19-capability-v1/receipts/capability.json".into(),sha256:"b".repeat(64)};
        scope(&v, &p, &b).unwrap();
        for (key, bad) in [
            ("unit", json!(c::UNIT)),
            ("run_root", json!(c::ROOT)),
            ("target_slot", json!(c::TERMINAL)),
            ("node", json!({"path":c::NODE,"sha256":"0".repeat(64)})),
        ] {
            let good = p[key].clone();
            p[key] = bad;
            assert!(scope(&v, &p, &b).is_err(), "{key}");
            p[key] = good;
        }
    }
}
