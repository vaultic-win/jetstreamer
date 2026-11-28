//! Authority for adopting the retained inode only after the registered fadfe2d4 uploader drains.
use super::*;
use jetstreamer_horizon_observe::successor247 as owner;

const PRIOR_UNIT: &str = "horizon-upload-247-staged-fadfe2d4-v1.service";
const PRIOR_IID: &str = "e434de7095a5407f80353b8f1df5eea8";
const ORIGINAL_PID: u32 = 2774321;
const ORIGINAL_START_TICKS: &str = "44413482";
const BOOT: &str = "3b17d0055c3a4a0e8841da097e0957b5";
const EVENT: &str =
    "/var/lib/jetstreamer/horizon247-staged-owner-v165-fadfe2d4-v1/running-event.json";
const EVENT_SHA: &str = "bcc72204b8e30fd76e006c86086645b05c050d172fc6391f53928553cb7d5ea8";

fn different_process(stat: &str) -> Result<bool> {
    let ticks = stat
        .rsplit_once(')')
        .context("invalid prior uploader stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing prior uploader process start")?;
    Ok(ticks != ORIGINAL_START_TICKS)
}
pub(super) fn check_drained() -> Result<()> {
    drained(PRIOR_UNIT, PRIOR_IID)?;
    match fs::read_to_string(format!("/proc/{ORIGINAL_PID}/stat")) {
        Ok(stat) => ensure!(
            different_process(&stat)?,
            "original staged uploader still present"
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
pub(super) fn terminal() -> Result<Value> {
    let event_ref = Bound {
        path: EVENT.into(),
        sha256: EVENT_SHA.into(),
    };
    let event = bound_json(&event_ref)?;
    let registered = owner::load(&event["claim"])?;
    ensure!(
        event["unit"] == PRIOR_UNIT
            && registered.iid == PRIOR_IID
            && registered.pid == ORIGINAL_PID
            && event["original_ledger"].is_object()
            && registered.proof["admission"] == event["admission"]
            && registered.proof["booking"] == event["booking"]
            && registered.proof["launch"] == event["launch"],
        "different staged 247 predecessor"
    );
    let ledger = bound_json(&serde_json::from_value(event["retained_ledger"].clone())?)?;
    let actual = ledger["reservations"]
        .as_array()
        .context("staged 247 reservations")?
        .iter()
        .find(|r| r["unit"] == PRIOR_UNIT)
        .context("missing original 247 reservation")?;
    ensure!(
        actual["invocation_id"] == PRIOR_IID
            && actual["maximum_memory_bytes"] == owner::BOOKED
            && actual["remaining_disk_growth_bytes"] == owner::DISK
            && actual.get("release") == Some(&Value::Null)
            && actual["source"] == event["source"],
        "different staged 247 booking"
    );
    let failed = failed_owner(PRIOR_UNIT, PRIOR_IID)?;
    ensure!(
        failed["_BOOT_ID"] == BOOT,
        "different boot for original uploader terminal"
    );
    check_drained()?;
    Ok(
        json!({"unit":PRIOR_UNIT,"invocation_id":PRIOR_IID,"pid":ORIGINAL_PID,"start_ticks":ORIGINAL_START_TICKS,
        "registration":event_ref,"claim":event["claim"],"booking":event["booking"],"launch":event["launch"],
        "admission":event["admission"],"retained_ledger":event["retained_ledger"],"systemd_failure":failed,"reservations_released":false}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_uploader_rejects_its_original_live_process_and_foreign_terminal() {
        let stat = |ticks: &str| {
            format!(
                "2774321 (uploader (phase)) R {} {ticks} 0",
                "0 ".repeat(18).trim_end()
            )
        };
        assert!(!different_process(&stat(ORIGINAL_START_TICKS)).unwrap());
        assert!(different_process(&stat("55555555")).unwrap());
        assert!(different_process("incomplete").is_err());
        let row = json!({"_PID":"1","UNIT":PRIOR_UNIT,"INVOCATION_ID":PRIOR_IID,"MESSAGE_ID":"d9b373ed55a64feb8242e02dbe79a49c","UNIT_RESULT":"exit-code"});
        assert!(failed(std::slice::from_ref(&row), PRIOR_UNIT, PRIOR_IID).is_ok());
        assert!(failed(&[row], PRIOR_UNIT, staged::IID).is_err());
    }
}
