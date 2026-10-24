//! Exact empty-receipts first-launch repair. Adopt a genuine live verifier;
//! never restart it or replace any failed history/intent.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn write(p: &Path, v: &Value) -> Result<Bound> {
    fleet::persist(p, v)?;
    bound_path(p, 4 << 20, 0)
}
const FAILED_IID: &str = "57790645fcc641f0a0ef93596f65ff03";
const FULL: &str = "horizon-full-verify-191-native191-20261023-v1.service";
const FULL_IID: &str = "2ea71518e5ea48a3986c8f2fb07b34e5";
const FAILURE_SHA: &str = "410644c73b496d4659deedc8c26d9767bec81f3833a53680b6cc674f2d5c4e6e";
fn proof(p: &Value) -> Result<Value> {
    let r = custody::bound(&binding(&p["recovery_full191"])?, true)?;
    ensure!(
        r["schema"] == "jetstreamer-exact191-failed-queue-adoption-v1",
        "191 unsupported queue recovery"
    );
    let failure = binding(&r["failure"])?;
    ensure!(
        failure.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-cohort191-full-prelaunch-failure-20261024-v1/failure.json"
            )
            && failure.sha256 == FAILURE_SHA,
        "191 recovery failure provenance changed"
    );
    let f = custody::bound(&failure, true)?;
    ensure!(
        f["verifier_state_entries"] == json!([]) && f["verification_complete"] == false,
        "191 failure already had verifier output"
    );
    let wrapper = binding(&r["wrapper_launch"])?;
    ensure!(
        wrapper.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-cohort191-canonical-verification-20261023-v1/epoch-191/full/launch.json"
            )
            && wrapper.sha256 == "8224b860dc820590e8a78ef4ffa1ab57f9a564a5d17f465f63e14d6b7b4dffa7",
        "191 actual repaired wrapper launch differs"
    );
    let w = custody::bound(&wrapper, false)?;
    ensure!(
        w["schema"] == "horizon-cohort191-native-verification-launch-v1"
            && w["epoch"] == 191
            && w["claim"]["unit"] == FULL
            && w["claim"]["invocation_id"] == FULL_IID
            && w["verification_complete"] == false
            && w["runner_sha256"]
                == "b89641f4bfe5cdd141652cd32905233937439725ca523ec18b66a411460e436a",
        "191 repaired wrapper is not genuine exact native actor"
    );
    Ok(r)
}
pub(super) fn validate(p: &Value) -> Result<()> {
    let r = proof(p)?;
    let old_b = binding(&r["failed_state"])?;
    ensure!(
        old_b.path == Path::new(ROOT).join("history/state-000002.json"),
        "191 wrong failed queue revision"
    );
    let old = custody::bound(&old_b, true)?;
    ensure!(
        old["status"] == "failed"
            && old["revision"] == 2
            && old["invocation_id"] == FAILED_IID
            && old["failure"] == "191 short client failed; preserve task and intent"
            && old["epochs"].as_array().is_some_and(|rows| rows.len() == 4
                && rows.iter().zip(191..=194).all(|(x, e)| x["epoch"] == e
                    && x["stage"] == "queued-full"
                    && x["task_owner"].is_null())),
        "191 failed queue has another result or work"
    );
    ensure!(
        bound_path(&Path::new(ROOT).join("state.json"), 4 << 20, 0)?.sha256 == old_b.sha256,
        "191 recovery head changed; never retry an adopted queue"
    );
    let admission = custody::bound(&binding(&r["old_admission"])?, true)?;
    ensure!(
        admission["queue_invocation_id"] == FAILED_IID
            && admission["queue_plan"] == old["plan"]
            && admission["epoch"] == 191
            && admission["stage"] == "full"
            && admission["dispatch_plan"] == r["dispatch_plan"],
        "191 original failed intake differs"
    );
    let d = custody::bound(&binding(&r["dispatch_plan"])?, true)?;
    ensure!(
        d["source_batch"] == p["source_batch"]
            && d["public_batch"] == p["public_batch"]
            && d["os_claim_transfer"] == p["os_claim_transfer"],
        "191 recovery changed imports or OS obligations"
    );
    let u = manager(FULL)?;
    ensure!(
        u["InvocationID"] == FULL_IID
            && u["ActiveState"] == "active"
            && u["SubState"] == "running"
            && u["NRestarts"] == "0"
            && u["MainPID"] == "1616932",
        "191 actual repaired full verifier changed"
    );
    ensure!(
        pipeline_status::same_exec_start(
            custody::bound(&binding(&r["wrapper_launch"])?, false)?["claim"]["expected_exec_start"].as_str().context("191 wrapper command missing")?,
            u["ExecStart"].as_str().context("191 manager command missing")?
        ),
        "191 repaired verifier command changed"
    );
    Ok(())
}
pub(super) fn state(p: &Value, plan: &Bound, iid: &str, pid: u64, start: u64) -> Result<Value> {
    validate(p)?;
    let r = proof(p)?;
    let old = custody::bound(&binding(&r["failed_state"])?, true)?;
    let root = Path::new(ROOT).join("recovery-full191-v1");
    ensure!(!root.try_exists()?, "191 recovery already published");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    File::open(Path::new(ROOT))?.sync_all()?;
    let old_admission = custody::bound(&binding(&r["old_admission"])?, true)?;
    let mut a = old_admission;
    a["queue_plan"] = json!(plan);
    a["queue_invocation_id"] = json!(iid);
    a["recovery"] = p["recovery_full191"].clone();
    let ab = write(&root.join("admission.json"), &a)?;
    let u = manager(FULL)?;
    let native_pid = number(&json!({"pid":text(&u,"MainPID")?.parse::<u64>()?}), "pid")?;
    let program = binding(&custody::bound(&binding(&r["dispatch_plan"])?, true)?["program"])?;
    let process = json!({"pid":native_pid,"start_ticks":ticks(native_pid)?,"cgroup":format!("/system.slice/{FULL}"),"executable":program.path});
    let lb = write(
        &root.join("launch.json"),
        &json!({"schema":"jetstreamer-cohort191-verification-recovery-launch-v1","epoch":191,"stage":"full","native_owner":u,"process_identity":process,"failure":r["failure"],"wrapper_launch":r["wrapper_launch"],"dispatch_plan":r["dispatch_plan"],"verification_complete":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let owner = launched_owner(&custody::bound(&lb, false)?, &ab, &lb, &program)?;
    let mut s = old;
    s.as_object_mut()
        .context("191 old state")?
        .remove("failure");
    s["status"] = json!("managing");
    s["plan"] = json!(plan);
    s["invocation_id"] = json!(iid);
    s["manager_pid"] = json!(pid);
    s["manager_start_ticks"] = json!(start);
    s["recovery"] = p["recovery_full191"].clone();
    s["epochs"][0]["stage"] = json!("full-verification");
    s["epochs"][0]["task_owner"] = owner;
    Ok(s)
}
