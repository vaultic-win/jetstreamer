//! Register the first guarded 266 entry replay without replacing its completed cold history.
use super::*;
#[path = "../../../tools/horizon266_entry_registration.rs"]
pub(super) mod bridge;

pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.unit == bridge::UNIT
}
pub(super) fn claim(c: &DiagnosticClaim, r: &Value) -> Result<Value> {
    ensure!(
        namespace(c)
            && c.epoch == 266
            && c.scratch_path == Path::new(bridge::ROOT)
            && c.invocation_id == r["iid"].as_str().context("266 entry owner")?
            && r["schema"] == bridge::SCHEMA,
        "epoch 266 fleet diagnostic"
    );
    let proof =
        bridge::validate(&json!({"path":c.launch_receipt.path,"sha256":c.launch_receipt.sha256}))?;
    ensure!(
        proof["iid"] == c.invocation_id && proof["pid"] == r["pid"],
        "different original 266 entry witness"
    );
    Ok(proof)
}
pub(super) fn live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let proof = claim(c, &bound_json(&c.launch_receipt)?)?;
    let pid = proof["pid"].as_u64().context("epoch 266 PID")?;
    let command = current["ExecStart"]
        .as_str()
        .and_then(|s| s.split(" ; ignore_errors=").next())
        .context("266 manager command")?;
    ensure!(
        current["Id"] == bridge::UNIT
            && current["InvocationID"] == c.invocation_id
            && current["MainPID"].as_str().and_then(|s|s.parse::<u64>().ok())==Some(pid)
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && proof["expected_command"] == command,
        "266 manager owner changed"
    );
    let props = singleton227_capture::properties(
        bridge::UNIT,
        "Id,InvocationID,MainPID,MemoryMax,MemorySwapMax,Restart,KillMode,Delegate,NRestarts",
    )?;
    let cap = proof["memory"]
        .as_u64()
        .context("266 admission cap")?
        .to_string();
    let pidstr = pid.to_string();
    singleton227_capture::require(
        &props,
        &[
            ("Id", bridge::UNIT),
            ("InvocationID", &c.invocation_id),
            ("MainPID", &pidstr),
            ("MemoryMax", &cap),
            ("MemorySwapMax", "0"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("NRestarts", "0"),
        ],
    )?;
    bridge::mapped_node(pid)
}
pub(super) fn transition(
    previous: &Value,
    p: &Plan,
    c: &DiagnosticClaim,
    g: &Value,
    gp: &Value,
    now: u64,
) -> Result<()> {
    let proof = claim(c, &bound_json(&c.launch_receipt)?)?;
    let gb: BoundFile = serde_json::from_value(proof["guard"].clone())?;
    ensure!(
        p.admission_transition_guard.as_ref() == Some(&gb)
            && bound_json(&gb)? == *g
            && bound_json(&serde_json::from_value(proof["plan"].clone())?)? == *gp,
        "266 first guard substitution"
    );
    let start = proof["release_time"].as_u64().context("266 released at")?;
    ensure!(start <= now, "epoch 266 release in future");
    let mut cursor = p
        .previous_fleet
        .as_ref()
        .context("266 original fleet")?
        .clone();
    let mut found = false;
    for _ in 0..64 {
        if private157::binding(&cursor) == proof["fleet"] {
            found = true;
            break;
        }
        let prior = bound_json(&cursor)?;
        ensure!(
            prior["schema"] == SCHEMA
                && prior["first_epoch"] == p.first_epoch
                && prior["last_epoch"] == p.last_epoch,
            "266 unrelated predecessor"
        );
        cursor = serde_json::from_value(prior["previous_fleet"].clone())?;
    }
    ensure!(found, "266 admitted predecessor lost");
    let prev: Plan = serde_json::from_value(bound_json(&BoundFile {
        path: previous["plan"].as_str().context("prior plan")?.into(),
        sha256: previous["plan_sha256"]
            .as_str()
            .context("prior plan SHA")?
            .into(),
    })?)?;
    ensure!(
        p.pipeline_claims == prev.pipeline_claims
            && prev
                .tracked_units
                .iter()
                .all(|u| p.tracked_units.contains(u)),
        "266 dropped assigned owners"
    );
    live(c, &unit(bridge::UNIT)?)
}
