//! Preserve the actual, separately admitted epoch247 delivery during replay admission.
use super::*;
mod staged;
mod successor;
pub(super) use successor::evidence::UNIT as SUCCESSOR_UNIT;
mod terminal;
pub(super) use staged::UNIT as STAGED_UNIT;
pub(super) const UNIT247: &str = "horizon-upload-247-singleton-20261119-v1.service";
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

fn original(e: &Value) -> bool {
    e["epoch"] == 247 && e["phase"] == "upload-readback" && e["unit"]["Id"] == UNIT247
}
pub(super) fn selected(e: &Value) -> bool {
    original(e) || staged::selected(e) || successor::selected(e)
}
fn related(entry: &Value) -> bool {
    if staged::selected(entry) || successor::selected(entry) {
        return false;
    }
    if staged::mentions(entry) {
        return true;
    }
    entry["epoch"] == 247
        || entry["expected_invocation_id"] == IID247
        || ["unit", "producer", "controller"]
            .iter()
            .any(|role| entry[*role]["Id"] == UNIT247 || entry[*role]["InvocationID"] == IID247)
}

pub(super) fn validate_roster(fleet: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    let entries = fleet["pipelines"].as_array().context("pipeline census")?;
    staged::validate_roster(fleet, rows)?;
    successor::roster(fleet, rows)?;
    let found: Vec<_> = entries.iter().filter(|e| related(e)).collect();
    if found.is_empty() {
        ensure!(
            !rows
                .iter()
                .any(|r| r.unit == UNIT247 || r.invocation_id == IID247)
                && !fleet["active"]
                    .as_array()
                    .context("active census")?
                    .iter()
                    .any(related),
            "original epoch247 booking or active owner missing from pipeline census"
        );
        return Ok(());
    }
    ensure!(found.len() == 1, "duplicate epoch247 pipeline");
    validate(found[0], fleet, rows)
}

pub(super) fn validate(e: &Value, fleet: &Value, rows: &[capacity::Reservation]) -> Result<()> {
    ensure!(
        original(e)
            && e["live"].is_boolean()
            && e["expected_invocation_id"] == IID247
            && e["unit"]["InvocationID"] == IID247
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
    let live = e["live"] == true;
    let active: Vec<_> = fleet["active"]
        .as_array()
        .context("active census")?
        .iter()
        .filter(|a| related(a))
        .collect();
    ensure!(
        if live {
            active.as_slice() == [e]
        } else {
            active.is_empty()
        },
        "epoch247 active membership changed"
    );
    ensure!(
        fleet["pipelines"]
            .as_array()
            .context("pipeline census")?
            .iter()
            .filter(|a| related(a))
            .eq(std::iter::once(e)),
        "epoch247 pipeline membership changed"
    );
    if live {
        live::same_owner(&terminal::witness()?["transition"]["before"], &e["unit"])?;
    } else {
        terminal::fleet_owner(e)?;
    }
    let bookings: Vec<_> = rows
        .iter()
        .filter(|r| r.unit == UNIT247 || r.invocation_id == IID247)
        .collect();
    ensure!(
        bookings.len() == 1,
        "epoch247 delivery booking missing/duplicated"
    );
    let r = bookings[0];
    ensure!(
        r.unit == UNIT247
            && r.invocation_id == IID247
            && r.maximum_memory_bytes == 7_000_000_000
            && r.remaining_disk_growth_bytes == 185_370_916_960
            && r.minimum_free_bytes == 3_000_000_000_000
            && r.release.is_none()
            && (live || r.source == terminal::booking()),
        "epoch247 complete memory/readback/metadata/floor booking changed"
    );
    Ok(())
}
pub(super) fn verify_inputs(e: &Value) -> Result<()> {
    if successor::selected(e) {
        let o = successor::owner()?;
        ensure!(
            e["expected_invocation_id"] == o.iid
                && e["evidence"] == json!([o.proof["booking"], o.proof["launch"]]),
            "successor provenance differs"
        );
        return Ok(());
    }
    if staged::selected(e) {
        return staged::verify_inputs(e);
    }
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
    if e["live"] == false {
        return terminal::verify_evidence(e);
    }
    let mapped = PathBuf::from(format!("/proc/{PID247}/exe"));
    ensure!(
        fs::read_link(&mapped)? == Path::new(UPLOADER)
            && metadata_identity(&fs::metadata(&mapped)?) == identity(Path::new(UPLOADER))?,
        "epoch247 mapped uploader changed"
    );
    Ok(())
}

pub(super) fn owner_cap(row: &capacity::Reservation) -> u64 {
    if row.unit == STAGED_UNIT || row.unit == SUCCESSOR_UNIT {
        staged::HARD_CAP
    } else {
        row.maximum_memory_bytes
    }
}

pub(super) fn staged_owner(current: &Value) -> Result<()> {
    if current["Id"] == SUCCESSOR_UNIT {
        return successor::live_owner(current);
    }
    staged::manager(current)?;
    staged::mapped_owner()
}

pub(super) fn terminal_owner(n: &mut Native, current: &Value) -> Result<()> {
    if current["Id"] == STAGED_UNIT {
        return staged::terminal(n, current);
    }
    terminal::observe(n, current)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value, Vec<capacity::Reservation>) {
        let unit = terminal::witness().unwrap()["transition"]["before"].clone();
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
    #[test]
    fn delivery_cannot_escape_exact_sample_evidence_or_membership() {
        let (e, f, rows) = fixture();
        validate(&e, &f, &rows).unwrap();
        for field in [
            "evidence",
            "sampled_at_utc",
            "unit",
            "expected_invocation_id",
        ] {
            let mut bad = e.clone();
            bad[field] = Value::Null;
            assert!(validate(&bad, &f, &rows).is_err(), "accepted {field}");
        }
        for field in ["pipelines", "active"] {
            let mut bad = f.clone();
            bad[field] = json!([e, e]);
            assert!(
                finalization::validate(
                    &bad,
                    &json!({"diagnostic_replays":[]}),
                    &rows,
                    &"b".repeat(32)
                )
                .is_err(),
                "accepted duplicate {field}"
            );
        }
        let mut bad = f.clone();
        bad["unit_census"][UNIT247]["InvocationID"] = json!("f".repeat(32));
        assert!(validate(&e, &bad, &rows).is_err());
    }
}
