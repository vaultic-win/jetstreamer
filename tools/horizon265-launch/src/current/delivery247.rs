//! Preserve the actual, separately admitted epoch247 delivery during replay admission.
use super::*;
const UNIT247: &str = "horizon-upload-247-singleton-20261119-v1.service";
const IID247: &str = "69218e2e0924497ea595a1227a6c31db";
const PID247: u64 = 1439838;
const UPLOADER: &str =
    "/var/lib/jetstreamer/horizon-full265-fast-consumers-20261119-v1/jetstreamer-r2";
const UPLOADER_SHA: &str = "4f70b21bd930a6e2890088eb236858ca1952a2dfa4c6404bfb9d9e68d07ba0ba";
const REVIEW: &str = "/var/lib/jetstreamer/horizon247-delivery-admission-20261119-v1/review.json";
const REVIEW_SHA: &str = "e246fbcd736561f926d3d998b6ad25ba189e829e6852c781b4f286234e9b500a";
const OWNER: &str =
    "/home/ubuntu/.codex/diagnostics/horizon247-delivery-admission-20261119-v1/initial-owner.txt";
const OWNER_SHA: &str = "6612e4c2f7f3de9c2ee85cd508575456a3fc85d16bd3e09d842905e521d24f21";
const FLEET_OWNER: &str = "/home/ubuntu/.codex/diagnostics/horizon-fleet-cycle0010-20261120-v1/delivery247-initial-owner.json";
const FLEET_OWNER_SHA: &str = "52f5c892af9acef8d2cb273ec6a2a5737facfb504e0d9e2f71f4434720a7a3f9";

pub(super) fn selected(e: &Value) -> bool {
    e["epoch"] == 247 && e["phase"] == "upload-readback" && e["unit"]["Id"] == UNIT247
}
pub(super) fn validate(e: &Value, fleet: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    ensure!(
        selected(e)
            && e["live"] == true
            && e["expected_invocation_id"] == IID247
            && e["unit"]["InvocationID"] == IID247
            && e["unit"]["MainPID"].as_str() == Some("1439838")
            && e["unit"] == fleet["unit_census"][UNIT247]
            && e["sampled_at_utc"] == fleet["sampled_at_utc"]
            && e["ordinary_replay_claim"] == false
            && e["grants_launch_or_publication_authority"] == false
            && e["evidence"]
                == json!([
                    Bound::new(REVIEW, REVIEW_SHA),
                    Bound::new(FLEET_OWNER, FLEET_OWNER_SHA)
                ]),
        "epoch247 delivery identity/evidence changed"
    );
    for key in ["pipelines", "active"] {
        ensure!(
            fleet[key]
                .as_array()
                .context("delivery census")?
                .iter()
                .filter(|v| *v == e)
                .count()
                == 1,
            "epoch247 delivery missing or duplicated in {key}"
        );
    }
    let bookings: Vec<_> = rows.iter().filter(|r| r.unit == UNIT247).collect();
    ensure!(
        bookings.len() == 1,
        "epoch247 delivery booking missing/duplicated"
    );
    let r = bookings[0];
    ensure!(
        r.invocation_id == IID247
            && r.maximum_memory_bytes == 7_000_000_000
            && r.remaining_disk_growth_bytes == 185_370_916_960
            && r.minimum_free_bytes == 3_000_000_000_000
            && r.release.is_none(),
        "epoch247 complete memory/readback/metadata/floor booking changed"
    );
    Ok(())
}
pub(super) fn verify_inputs() -> Result<()> {
    let review = Bound::new(REVIEW, REVIEW_SHA).sealed()?;
    ensure!(
        review["schema"] == "horizon247-current-reader-delivery-booking-v1"
            && review["Main_accepted"] == true
            && review["planned_unit"] == UNIT247
            && review["delivery_memory_bytes"] == 7_000_000_000u64
            && review["maximum_readback_bytes"] == 180_370_916_960u64
            && review["maximum_metadata_log_temporary_growth_bytes"] == 5_000_000_000u64
            && review["reader_floor_bytes"] == 3_000_000_000_000u64
            && review["uploader"] == json!(Bound::new(UPLOADER, UPLOADER_SHA)),
        "epoch247 original delivery admission changed"
    );
    Bound::new(OWNER, OWNER_SHA).bytes(false)?;
    let owner_evidence = Bound::new(FLEET_OWNER, FLEET_OWNER_SHA).json()?;
    ensure!(
        owner_evidence["source"] == json!(Bound::new(OWNER, OWNER_SHA)),
        "epoch247 fleet owner evidence lost its original native capture"
    );
    binding(&review["original_247_handoff"])?.json()?;
    Bound::new(UPLOADER, UPLOADER_SHA).artifact()?;
    let mapped = PathBuf::from(format!("/proc/{PID247}/exe"));
    ensure!(
        fs::read_link(&mapped)? == Path::new(UPLOADER)
            && metadata_identity(&fs::metadata(&mapped)?) == identity(Path::new(UPLOADER))?,
        "epoch247 mapped uploader changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Vec<capacity::Reservation>) {
        let unit = json!({"Id":UNIT247,"InvocationID":IID247,"MainPID":PID247.to_string()});
        let e = json!({"epoch":247,"phase":"upload-readback","live":true,"expected_invocation_id":IID247,
            "unit":unit,"sampled_at_utc":"sample","ordinary_replay_claim":false,
            "grants_launch_or_publication_authority":false,
            "evidence":[Bound::new(REVIEW,REVIEW_SHA),Bound::new(FLEET_OWNER,FLEET_OWNER_SHA)]});
        let f = json!({"pipelines":[e],"active":[e],"unit_census":{(UNIT247):unit},"sampled_at_utc":"sample",
            "diagnostics":[],"auxiliary_diagnostics":[]});
        let r = capacity::Reservation {
            unit: UNIT247.into(),
            invocation_id: IID247.into(),
            maximum_memory_bytes: 7_000_000_000,
            remaining_disk_growth_bytes: 185_370_916_960,
            minimum_free_bytes: 3_000_000_000_000,
            source: Bound::new("/unused", "a".repeat(64)),
            release: None,
        };
        (e, f, vec![r])
    }
    #[test]
    fn full_finalization_adapter_keeps_delivery_separate_and_fully_booked() {
        let (_, f, r) = fixture();
        finalization::validate(&f, &json!({"diagnostic_replays":[]}), &r, &"b".repeat(32)).unwrap();
        for field in [
            "maximum_memory_bytes",
            "remaining_disk_growth_bytes",
            "minimum_free_bytes",
        ] {
            let mut raw = serde_json::to_value(&r[0]).unwrap();
            raw[field] = json!(1);
            let changed = vec![serde_json::from_value(raw).unwrap()];
            assert!(
                finalization::validate(
                    &f,
                    &json!({"diagnostic_replays":[]}),
                    &changed,
                    &"b".repeat(32)
                )
                .is_err()
            );
        }
        assert!(
            finalization::validate(&f, &json!({"diagnostic_replays":[]}), &[], &"b".repeat(32))
                .is_err()
        );
    }
    #[test]
    fn replacement_missing_active_and_resource_release_are_rejected() {
        let (e, f, mut r) = fixture();
        let mut wrong = e.clone();
        wrong["expected_invocation_id"] = json!("0".repeat(32));
        assert!(validate(&wrong, &f, &r).is_err());
        let mut missing = f.clone();
        missing["active"] = json!([]);
        assert!(validate(&e, &missing, &r).is_err());
        r[0].release = Some(Bound::new("/unused", "a".repeat(64)));
        assert!(validate(&e, &f, &r).is_err());
    }
}
