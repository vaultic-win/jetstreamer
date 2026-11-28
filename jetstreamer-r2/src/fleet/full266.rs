//! Register original guarded epochs 228 and 266 entry replays.
use super::*;
#[path = "../../../tools/horizon266_entry_registration.rs"]
pub(super) mod bridge;

fn profile(c: &DiagnosticClaim) -> Option<&'static bridge::Pilot> {
    [
        &bridge::FULL228,
        &bridge::FULL266,
        &bridge::SUCCESSOR266,
        &bridge::TURNOVER266,
        &bridge::BOUNDED266,
        &bridge::BOUNDED_RETRY266,
    ]
    .into_iter()
    .find(|p| c.unit == p.unit)
}
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    profile(c).is_some()
}
pub(super) fn claim(c: &DiagnosticClaim, r: &Value) -> Result<Value> {
    let pilot = profile(c).context("unknown entry unit")?;
    ensure!(
        c.epoch == pilot.epoch
            && c.scratch_path == Path::new(pilot.root)
            && c.invocation_id == r["iid"].as_str().context("entry replay owner")?
            && r["schema"] == pilot.schema,
        "entry replay fleet diagnostic"
    );
    let proof =
        pilot.validate(&json!({"path":c.launch_receipt.path,"sha256":c.launch_receipt.sha256}))?;
    ensure!(
        proof["iid"] == c.invocation_id && proof["pid"] == r["pid"],
        "different original entry witness"
    );
    Ok(proof)
}
pub(super) fn live(c: &DiagnosticClaim, current: &Value) -> Result<()> {
    let proof = claim(c, &bound_json(&c.launch_receipt)?)?;
    let pilot = profile(c).context("unknown entry unit")?;
    let pid = proof["pid"].as_u64().context("entry replay PID")?;
    let command = current["ExecStart"]
        .as_str()
        .and_then(|s| s.split(" ; ignore_errors=").next())
        .context("entry replay manager command")?;
    ensure!(
        current["Id"] == pilot.unit
            && current["InvocationID"] == c.invocation_id
            && current["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                == Some(pid)
            && current["NRestarts"] == "0"
            && current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && proof["expected_command"] == command,
        "entry replay manager owner changed"
    );
    let props = singleton227_capture::properties(
        pilot.unit,
        "Id,InvocationID,MainPID,MemoryMax,MemorySwapMax,Restart,KillMode,Delegate,NRestarts",
    )?;
    let cap = proof["memory"]
        .as_u64()
        .context("entry replay admission cap")?
        .to_string();
    let pidstr = pid.to_string();
    singleton227_capture::require(
        &props,
        &[
            ("Id", pilot.unit),
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
    pilot.mapped_node(pid)
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
        "entry replay first guard substitution"
    );
    let start = proof["release_time"]
        .as_u64()
        .context("entry replay released at")?;
    ensure!(start <= now, "entry replay release in future");
    let mut cursor = p
        .previous_fleet
        .as_ref()
        .context("entry replay original fleet")?
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
            "entry replay unrelated predecessor"
        );
        cursor = serde_json::from_value(prior["previous_fleet"].clone())?;
    }
    ensure!(found, "entry replay admitted predecessor lost");
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
        "entry replay dropped assigned owners"
    );
    live(c, &unit(&c.unit)?)
}
