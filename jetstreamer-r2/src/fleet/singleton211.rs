//! Full211 lifecycle bridge. Shared Rust validator authenticates the original held-gate chain.
use super::*;
pub(super) const SCHEMA: &str = "horizon-singleton211-guarded-startup-v1";
pub(super) const UNIT: &str = "horizon-singleton-211-capped-4aeca563-v1.service";
pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-211-singleton-capped-v1";
pub(super) const FINGERPRINT: &str =
    "sha256:d00f6c8ff2d66ec302aea39267ace8c28931d2602c9f5185c913eb5c96ab667b";
const GATE: &str =
    "/var/lib/jetstreamer/horizon-singleton211-launch-20261120-v4/horizon-singleton211-launch";
const NODE: &str = "/var/lib/jetstreamer/horizon-singleton211-production-node-c17619b16d5d20f0-v1/jetstreamer-node";
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit.starts_with("horizon-singleton-211-")
}
pub(super) fn launch(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    ensure!(
        c.epoch == 211
            && c.unit == UNIT
            && c.scratch_path == Path::new(ROOT)
            && v["schema"] == SCHEMA
            && v["invocation_id"] == c.invocation_id,
        "full211 claim differs"
    );
    let sha = v["launcher_sha256"]
        .as_str()
        .context("full211 launcher SHA")?;
    ensure!(canonical_digest(&json!(sha)), "invalid full211 image SHA");
    let validated = horizon_singleton211_launch::validate_saved_handoff(
        &c.launch_receipt.path,
        &c.launch_receipt.sha256,
        sha,
    )?;
    ensure!(validated == *v, "handoff reader disagreement");
    Ok(())
}
pub(super) fn same_command(v: &Value) -> bool {
    let Some(s) = v.as_str().and_then(|s| s.split(" ; ignore_errors=").next()) else {
        return false;
    };
    s.starts_with(&format!("{{ path={GATE} ; argv[]={GATE} gate /var/lib/jetstreamer/horizon-singleton211-startup-plan-"))
        && !s.contains('\n')
}
pub(super) fn live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    live_with_observation(
        c,
        current,
        || {
            singleton227_capture::properties(
                UNIT,
                "Id,InvocationID,MainPID,MemoryMax,MemorySwapMax,Restart,KillMode,Delegate,NRestarts",
            )
        },
        |pid| {
            let mapped = PathBuf::from(format!("/proc/{pid}/exe"));
            Ok((
                fs::read_link(&mapped)?,
                fs::metadata(&mapped)?,
                fs::symlink_metadata(NODE)?,
            ))
        },
    )
}
// Keep all validation in the production path; tests substitute only OS observations.
pub(super) fn live_with_observation(
    c: &DiagnosticClaim,
    current: &Value,
    properties: impl FnOnce() -> Result<BTreeMap<String, String>>,
    mapped_image: impl FnOnce(&str) -> Result<(PathBuf, fs::Metadata, fs::Metadata)>,
) -> Result<()> {
    let v = bound_json(&c.launch_receipt)?;
    launch(c, &v)?;
    let command = |v: &Value| {
        v.as_str()
            .and_then(|s| s.split(" ; ignore_errors=").next())
            .map(str::to_owned)
    };
    ensure!(
        same_command(&current["ExecStart"])
            && command(&current["ExecStart"]) == command(&v["producer"]["ExecStart"])
            && current["InvocationID"] == c.invocation_id
            && current["MainPID"]
                == v["main_pid"]
                    .as_u64()
                    .context("full211 main PID")?
                    .to_string()
                    .as_str()
            && current["NRestarts"] == "0",
        "full211 live owner changed"
    );
    let props = properties()?;
    singleton227_capture::require(
        &props,
        &[
            ("Id", UNIT),
            ("InvocationID", &c.invocation_id),
            ("MainPID", current["MainPID"].as_str().context("mainPID")?),
            ("MemoryMax", "225000000000"),
            ("MemorySwapMax", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("NRestarts", "0"),
        ],
    )?;
    let pid = current["MainPID"].as_str().context("full211 live PID")?;
    let (mapped, a, b) = mapped_image(pid)?;
    ensure!(mapped == Path::new(NODE), "full211 node was replaced");
    ensure!(
        a.dev() == b.dev() && a.ino() == b.ino() && a.len() == b.len(),
        "full211 mapped inode changed"
    );
    Ok(())
}
pub(super) fn transition(
    previous: &Value,
    p: &Plan,
    c: &DiagnosticClaim,
    g: &Value,
    gp: &Value,
    now: u64,
) -> Result<()> {
    let v = bound_json(&c.launch_receipt)?;
    launch(c, &v)?;
    let a = bound_json(&serde_json::from_value(v["admission"].clone())?)?;
    let old = p
        .previous_fleet
        .as_ref()
        .context("full211 predecessor missing")?;
    ensure!(
        a["fleet"] == private157::binding(old) && a["observer"] == private157::binding(&p.observer),
        "full211 does not bind actual predecessor"
    );
    let b: BoundFile = serde_json::from_value(v["first_guard_sample"].clone())?;
    ensure!(
        bound_json(&b)? == *g
            && bound_json(&serde_json::from_value(v["guard_plan"].clone())?)? == *gp,
        "full211 first-fire substitution"
    );
    let started = v["recorded_unix_seconds"]
        .as_u64()
        .context("full211 launch clock")?;
    ensure!(
        started <= now && now - started <= 900,
        "full211 transition stale"
    );
    // The common caller already preserves diagnostic history. Preserve every
    // pipeline claim and ordinary active owner as well; no terminal credit here.
    let previous_plan: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"].as_str().context("old plan")?.into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("old plan SHA")?
            .into(),
    })?)?;
    ensure!(
        p.pipeline_claims == previous_plan.pipeline_claims
            && p.tracked_units.iter().all(|s| !s.is_empty()),
        "full211 dropped pipeline history"
    );
    for u in &previous_plan.tracked_units {
        ensure!(p.tracked_units.contains(u), "full211 dropped tracked owner");
    }
    let current = unit(UNIT)?;
    live(c, &current)
}
