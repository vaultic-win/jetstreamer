//! Preserve the production 157 claim while no historical worker is rate-bearing.
use super::*;
const PROOF: &str = "/usr/local/lib/jetstreamer/horizon-epoch157-verification-pause-evidence-20261021-v1/pause.json";
const SHA: &str = "7551fdeafd0c5773dfb52a1b0df8b867f09e1dc1b2939569568bf5ede99789c2";
const UNIT: &str = "jetstreamer-root-sweep-e157-t3-20261014-v1-r2-e157-157-lane-j-1.service";
const IID: &str = "d66eddeac8304adfbd17e4ebe1c6c1f9";
const CTRL: &str = "jetstreamer-epoch157-target3-controller-v1-r2.service";
const CTRL_IID: &str = "fcba4ece12fa462faf9062a3ad607879";
fn owner(current: &Value, unit: &str, iid: &str) -> Result<bool> {
    let live = current["ActiveState"] == "active" && current["SubState"] == "running";
    if live {
        ensure!(
            current["Id"] == unit && current["InvocationID"] == iid && current["NRestarts"] == "0",
            "157 runtime handoff owner changed"
        );
    }
    Ok(live)
}
fn subphase(current: &Value) -> Result<&'static str> {
    let group = current["ControlGroup"]
        .as_str()
        .context("157cgroup missing")?;
    ensure!(
        group == format!("/system.slice/{UNIT}"),
        "157cgroup differs"
    );
    let pids = fs::read_to_string(
        Path::new("/sys/fs/cgroup")
            .join(group.trim_start_matches('/'))
            .join("cgroup.procs"),
    )?;
    let mut verifying = false;
    let mut workers = 0;
    ensure!(pids.lines().count() <= 256, "157process census too large");
    for pid in pids.lines() {
        let pid: u32 = pid.parse()?;
        let root = Path::new("/proc").join(pid.to_string());
        let exe = match fs::read_link(root.join("exe")) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if exe.file_name().and_then(|n| n.to_str()) == Some("historical-worker")
            && exe.starts_with(
                "/home/sol/.jetstreamer-private/epochs150-173-20260923-v2/lane-j/output",
            )
        {
            workers += 1;
        }
        for task in fs::read_dir(root.join("task"))? {
            let name = fs::read_to_string(task?.path().join("comm"));
            if name.is_ok_and(|s| s.starts_with("segment-verify-")) {
                verifying = true;
            }
        }
    }
    ensure!(workers <= 1, "157multiple workers during handoff");
    Ok(if workers == 1 {
        "replay-unmodeled"
    } else if verifying {
        "runtime-segment-verification"
    } else {
        "runtime-handoff-unresolved"
    })
}
pub(super) fn observe(
    plan: &Plan,
    observer: &Value,
    census: &BTreeMap<String, Value>,
    sample: &str,
) -> Result<Option<Value>> {
    let Some(binding) = &plan.runtime_handoff157 else {
        return Ok(None);
    };
    ensure!(
        binding.path == Path::new(PROOF)
            && binding.sha256 == SHA
            && plan.first_epoch == 101
            && plan.last_epoch == 200,
        "foreign 157 runtime handoff binding"
    );
    let proof = bound_json(binding)?;
    ensure!(
        proof["schema"] == "jetstreamer-epoch157-runtime-verification-pause-v1"
            && proof["producer_iid"] == IID
            && proof["controller_iid"] == CTRL_IID
            && proof["epoch157_eta_unavailable"] == true,
        "157pause evidence differs"
    );
    for flag in [
        "replay_launch_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(proof[flag] == false, "157pause evidence grants authority");
    }
    let producer = census
        .get(UNIT)
        .context("157producer omitted from full census")?;
    let controller = census
        .get(CTRL)
        .context("157controller omitted from full census")?;
    let live = owner(producer, UNIT, IID)? && owner(controller, CTRL, CTRL_IID)?;
    let ordinary = observer["replays"]
        .as_array()
        .context("replay census")?
        .iter()
        .any(|r| r["range"] == "157");
    if ordinary {
        return Ok(Some(
            json!({"epoch":157,"live":false,"ordinary_replay_restored":true,
            "evidence":{"path":binding.path,"sha256":binding.sha256},"current_sidecar_eta_valid":false}),
        ));
    }
    let phase = if live {
        subphase(producer)?
    } else {
        "runtime-owner-terminal-review"
    };
    Ok(Some(
        json!({"epoch":157,"phase":phase,"live":live,"producer":producer,"controller":controller,
        "sampled_at_utc":sample,"ordinary_replay_restored":false,"current_sidecar_eta_valid":false,
        "replay_slots_still_queued":115823,"downstream_allowance_preserved_seconds":43200,
        "evidence":{"path":binding.path,"sha256":binding.sha256},"resource_basis":"Full invocation census only; excluded from rate-bearing resource model; preserve conservative growth claims and do not infer new admission.",
        "publication_authorized":false,"inactivity_or_cleanup_proven":false}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_cannot_hide_as_runtime_verification() {
        let mut unit = json!({"Id":UNIT,"InvocationID":IID,"NRestarts":"0","ActiveState":"active","SubState":"running"});
        assert!(owner(&unit, UNIT, IID).unwrap());
        unit["InvocationID"] = json!("f".repeat(32));
        assert!(owner(&unit, UNIT, IID).is_err());
    }
}
