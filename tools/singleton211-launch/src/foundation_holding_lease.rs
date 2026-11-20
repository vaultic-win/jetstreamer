//! Continuous native capacity evidence for one serialized Foundation restore.
//! All state that grants continuation is private to the already admitted process.
use super::*;
use std::cell::{Cell, RefCell};

const INTERVAL_US: u64 = 60_000_000;
const MAX_GAP_US: u64 = 300_000_000;
const ACTIVE: &str =
    "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/active-restore-session.json";

pub struct RestoreLease {
    basis: Value,
    marker: Bound,
    marker_identity: Identity,
    custody: Value,
    actor: Value,
    floor: u64,
    last: Cell<u64>,
    deadline: u64,
    sequence: Cell<u64>,
    previous: RefCell<Value>,
}

fn window(last: u64, current: u64, deadline: u64) -> Result<u64> {
    let elapsed = current
        .checked_sub(last)
        .context("restore monotonic clock reversed")?;
    ensure!(
        current <= deadline && elapsed <= MAX_GAP_US,
        "restore capacity continuity expired"
    );
    Ok(elapsed)
}

fn marker_scope(
    v: &Value,
    review: &Value,
    custody: &Value,
    actor: &Value,
    time: u64,
) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-foundation-serialized-restore-session-v1"
            && v["Main_accepted"] == true
            && v["admissions_serialized"] == true
            && v["custody"] == *custody
            && v["unit"] == actor["unit"]
            && v["unit"]
                .as_str()
                .is_some_and(|u| u.starts_with("horizon-") && u.ends_with(".service"))
            && [
                "holding_artifact",
                "boot_id",
                "fleet",
                "observer",
                "reservation_ledger",
                "century"
            ]
            .iter()
            .all(|k| !review[k].is_null() && v[k] == review[k])
            && num(v, "valid_from_unix_seconds")? <= time
            && time <= num(v, "expires_unix_seconds")?,
        "exclusive restore booking changed, revoked or expired"
    );
    no_authority(v)
}

impl RestoreLease {
    /// Starts from strict review/fleet age checks. The optional marker enables
    /// continuous renewal only for exactly this custody, roster, ledger and actor.
    pub fn start(
        basis: &Value,
        custody: &Value,
        remaining: u64,
        floor: u64,
    ) -> Result<Option<Self>> {
        let first = checked(basis, remaining, None)?;
        ensure!(
            num(&first, "minimum_free_bytes")? <= floor,
            "protected growth/floor increased"
        );
        let review = binding(basis)?.sealed()?;
        let Some(marker) = review.get("restore_session") else {
            return Ok(None);
        };
        let marker = binding(marker)?;
        ensure!(
            marker.path == Path::new(ACTIVE),
            "restore session must use the current exclusive booking"
        );
        let marker_identity = identity(&marker.path)?;
        let v = marker.sealed()?;
        ensure!(
            identity(&marker.path)? == marker_identity,
            "exclusive session replaced at admission"
        );
        let time = now()?;
        marker_scope(&v, &review, custody, &first, time)?;
        let last = mono()?;
        let deadline = (num(&v, "expires_unix_seconds")? - time)
            .checked_mul(1_000_000)
            .and_then(|n| last.checked_add(n))
            .context("restore lease duration overflow")?;
        Ok(Some(Self {
            basis: basis.clone(),
            marker,
            marker_identity,
            custody: custody.clone(),
            actor: first.clone(),
            floor,
            last: Cell::new(last),
            deadline,
            sequence: Cell::new(0),
            previous: RefCell::new(first["evidence"].clone()),
        }))
    }

    pub(crate) fn check_anchor(&self, review: &Value) -> Result<()> {
        window(self.last.get(), mono()?, self.deadline)?;
        marker_scope(
            &self.marker.sealed()?,
            review,
            &self.custody,
            &self.actor,
            now()?,
        )
    }

    pub fn renew(&self, force: bool, remaining: impl FnOnce() -> Result<u64>) -> Result<()> {
        ensure!(
            identity(&self.marker.path)? == self.marker_identity,
            "exclusive restore booking replaced or revoked"
        );
        let since = window(self.last.get(), mono()?, self.deadline)?;
        if !force && since < INTERVAL_US {
            return Ok(());
        }
        let current = checked(&self.basis, remaining()?, Some(self))?;
        ensure!(
            [
                "unit",
                "invocation_id",
                "holding_artifact",
                "st_dev",
                "boot_id",
                "fleet",
                "observer",
                "reservation_ledger",
                "century"
            ]
            .iter()
            .all(|k| current[k] == self.actor[k]),
            "restore actor or frozen host booking changed"
        );
        ensure!(
            num(&current, "minimum_free_bytes")? <= self.floor,
            "protected growth/floor increased"
        );
        let finish = mono()?;
        window(self.last.get(), finish, self.deadline)?;
        self.last.set(finish);
        self.sequence.set(
            self.sequence
                .get()
                .checked_add(1)
                .context("renewal sequence overflow")?,
        );
        *self.previous.borrow_mut() = current["evidence"].clone();
        Ok(())
    }

    pub fn evidence(&self) -> Value {
        json!({"session":self.marker,"previous":*self.previous.borrow(),"completed_renewals":self.sequence.get(),"unit":self.actor["unit"],"invocation_id":self.actor["invocation_id"],"reserved_floor_bytes":self.floor})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continuous_checked_renewals_outlive_the_initial_snapshot_only_without_a_gap() {
        let deadline = 3_600_000_000;
        let mut last = 0;
        for minute in 1..=40 {
            let current = minute * INTERVAL_US;
            assert_eq!(window(last, current, deadline).unwrap(), INTERVAL_US);
            last = current;
        }
        assert!(window(last, last - 1, deadline).is_err());
        assert!(window(last, last + MAX_GAP_US + 1, deadline).is_err());
        assert!(window(last, last + 1, last).is_err());
    }

    #[test]
    #[ignore = "reopens sealed v134 private fleet, observer, handoff and custody evidence"]
    fn genuine_v134_renewal_rejects_substituted_roster_and_ledger() -> Result<()> {
        let fleet = Bound::new(
            "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v134-20261120-v1/fleet-v1.json",
            "50b4cef884e6268032d36756e893d461d52866d68e3461f80ee06d1da73059b2",
        );
        let f = fleet.json()?;
        let observer = Bound::new(text(&f, "observer_receipt")?, text(&f, "observer_sha256")?);
        let o = observer.json()?;
        let h = full211_peer::handoff().sealed()?;
        let a = binding(&h["admission"])?.sealed()?;
        let ledger = binding(&a["reservation_ledger"])?;
        let original_review = binding(&a["review"])?.sealed()?;
        binding(&original_review["century"])?.sealed()?;
        let mut rows: Vec<capacity::Reservation> =
            serde_json::from_value(ledger.sealed()?["reservations"].clone())?;
        ensure!(rows.len() == 10, "changed historical booking");
        rows.push(capacity::Reservation {
            unit: UNIT.into(),
            invocation_id: text(&h["producer"], "InvocationID")?.into(),
            maximum_memory_bytes: MEMORY,
            remaining_disk_growth_bytes: SCRATCH,
            minimum_free_bytes: num(&a, "protected_existing_floor_bytes")?,
            source: full211_peer::handoff(),
            release: None,
        });
        full211_peer::validate(&f, &o, &rows, &h, &a)?;
        let mut missing = rows.clone();
        missing.pop();
        ensure!(
            full211_peer::validate(&f, &o, &missing, &h, &a).is_err(),
            "dropped full211 owner accepted"
        );
        let old = Bound::new(
            "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1/receipts/custody-deb72dca9736bf4dcf23d689f095fd133f5be9abf5bdf1e564d5c2614c546d22.json",
            "adfdf702dd71d53553431408e93cb0a565f83ac932e50d71383760d16ac77a9f",
        );
        ensure!(
            old.sealed()?["artifact"] == "failed-v5-234",
            "historical custody changed"
        );
        let actor = json!({"unit":"horizon-foundation-private-restore.service"});
        let review = json!({"holding_artifact":{"path":"/var/lib/jetstreamer/horizon223-holding-production-facdd1e9-20261120-v1/jetstreamer-r2","sha256":"b88cf6d908b3f03e6d9bbabc833762b0a72f77dcb1ba3e337bbde4d5dfbbb49d"},"boot_id":a["boot_id"],"fleet":fleet,"observer":observer,"reservation_ledger":ledger,"century":original_review["century"]});
        let t = num(&f, "recorded_unix_seconds")?;
        let mut marker = review.clone();
        let b = serde_json::to_value(old)?;
        for (k, v) in [
            (
                "schema",
                json!("horizon-foundation-serialized-restore-session-v1"),
            ),
            ("Main_accepted", json!(true)),
            ("admissions_serialized", json!(true)),
            ("custody", b.clone()),
            ("unit", actor["unit"].clone()),
            ("valid_from_unix_seconds", json!(t)),
            ("expires_unix_seconds", json!(t + 3600)),
        ] {
            marker[k] = v;
        }
        deny_authority(&mut marker);
        marker_scope(&marker, &review, &b, &actor, t + 600)?;
        for k in [
            "custody",
            "unit",
            "boot_id",
            "fleet",
            "observer",
            "reservation_ledger",
            "century",
            "holding_artifact",
            "admissions_serialized",
            "Main_accepted",
        ] {
            let mut wrong = marker.clone();
            wrong[k] = Value::Null;
            assert!(
                marker_scope(&wrong, &review, &b, &actor, t + 600).is_err(),
                "{k}"
            );
        }
        assert!(marker_scope(&marker, &review, &b, &actor, t + 3601).is_err());
        Ok(())
    }
}
