//! Bind the epoch 252 uploader to the completed regional replay and drained guard.
use super::*;

pub(super) const REPLAY: &str = "horizon-qualify-252-regional-singleton-v1.service";
pub(super) const UPLOADER: &str = "horizon-upload-252-current-reader-v1.service";
pub(super) const CLAIM: &str =
    "/var/lib/jetstreamer/horizon252-current-reader-delivery-v1/pipeline-claim.json";
const TIMER: &str = "horizon-252-regional-singleton-protective-v1.timer";
const GUARD: &str = "horizon-252-regional-singleton-protective-v1.service";
const HANDOFF: &str = "/var/lib/jetstreamer/horizon252-local-delivery-handoff-v1/completion.json";
const ARCHIVE: &str = "/home/ubuntu/.jetstreamer-private/qualification-252-regional-singleton-v1/output/epoch-252.jet";
const PREPARATION: &str =
    "/var/lib/jetstreamer/horizon252-current-reader-preparation-v2/preparation.json";
const PREPARATION_SHA: &str = "395e7ef4e8a37bab73514fe963502f1d634a08f6d1eda5ae85414ffc46331367";

pub(super) fn terminal(n: &mut Native, booking: &Value) -> Result<Option<Bound>> {
    let path = Path::new(HANDOFF);
    if !path.try_exists()? {
        return Ok(None);
    }
    let handoff = Bound::new(path, hash(path)?);
    let body = handoff.sealed()?;
    let source = &body["terminal"];
    let prep = Bound::new(PREPARATION, PREPARATION_SHA);
    let preparation = prep.sealed()?;
    ensure!(
        body["schema"] == "foundation-epoch252-local-delivery-handoff-v1"
            && body["epoch"] == 252
            && body["publication_authorized"] == false
            && body["fresh_fleet_admission_pending"] == true
            && body["fresh_target_inventory_pending"] == true
            && body["preparation"] == json!(prep)
            && body["read_plan"] == preparation["read_plan"]
            && body["uploader"] == preparation["uploader"]
            && source["schema"] == "foundation-epoch252-committed-cohort-source-v1"
            && source["state"] == "local-cohort-committed"
            && source["epoch"] == 252
            && source["unit"] == REPLAY
            && source["invocation_id"] == booking["owners"][REPLAY]["InvocationID"]
            && source["publication_authorized"] == false
            && source["archive"]["path"] == ARCHIVE
            && source["archive"]["identity"]["length"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "epoch 252 handoff does not match the booked replay and reader plan"
    );
    let timer = n.show_fields(TIMER, "ActiveState,Job")?;
    ensure!(
        timer["ActiveState"] == "inactive" && timer["Job"] == "",
        "epoch 252 guard timer is active"
    );
    for unit in [REPLAY, GUARD] {
        let row = n.show_fields(
            unit,
            "ActiveState,MainPID,ControlPID,ControlGroup,Job,InvocationID,Result",
        )?;
        ensure!(
            matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
                && row["MainPID"] == "0"
                && row["ControlPID"] == "0"
                && row["ControlGroup"] == ""
                && row["Job"] == ""
                && !Path::new("/sys/fs/cgroup/system.slice").join(unit).exists(),
            "epoch 252 owner {unit} has not drained"
        );
        if unit == REPLAY {
            ensure!(
                row["Result"] == "success"
                    && (row["InvocationID"] == ""
                        || row["InvocationID"] == source["invocation_id"]),
                "epoch 252 terminal producer identity changed"
            );
        }
    }
    Ok(Some(handoff))
}
