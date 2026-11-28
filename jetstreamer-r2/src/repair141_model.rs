//! Pure planning for the exact stopped 141 recovery. No filesystem, process,
//! replay, receipt or R2 authority. Historical throughput is a planning seed.
pub const BOOTSTRAP: u64 = 60_911_751;
pub const ROOT: u64 = 61_328_765;
pub const TERMINAL: u64 = 61_343_999;
#[derive(Clone, Debug)]
pub struct Rate {
    pub first_slot: u64,
    pub last_slot: u64,
    pub elapsed_microseconds: u64,
}
#[derive(Clone, Debug)]
pub struct Policy {
    pub engineering_millis: u64,
    pub capacity_millis: u64,
    pub bootstrap_millis: u64,
    pub checkpoint_close_restore_millis: u64,
    pub downstream_millis: u64,
    pub prerequisites_parallel: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forecast {
    pub prerequisite_millis: u64,
    pub root_replay_millis: u64,
    pub suffix_replay_millis: u64,
    pub estimated_remaining_millis: u64,
}
fn add(a: u64, b: u64) -> Result<u64, String> {
    a.checked_add(b)
        .ok_or("141 repair estimate overflow".into())
}
fn replay(slots: u64, rate: &Rate) -> Result<u64, String> {
    if rate.first_slot < BOOTSTRAP
        || rate.first_slot >= rate.last_slot
        || rate.last_slot > ROOT
        || rate.elapsed_microseconds == 0
    {
        return Err("141 invalid historical root rate".into());
    }
    let numerator = u128::from(slots) * u128::from(rate.elapsed_microseconds);
    let denominator = u128::from(rate.last_slot - rate.first_slot) * 1000;
    u64::try_from(numerator.div_ceil(denominator))
        .map_err(|_| "141 replay projection overflow".into())
}
pub fn forecast(rate: &Rate, p: &Policy) -> Result<Forecast, String> {
    if [
        p.engineering_millis,
        p.capacity_millis,
        p.bootstrap_millis,
        p.checkpoint_close_restore_millis,
        p.downstream_millis,
    ]
    .contains(&0)
    {
        return Err(
            "141 every unqualified recovery stage needs a positive reviewed allowance".into(),
        );
    }
    let prerequisite_millis = if p.prerequisites_parallel {
        p.engineering_millis.max(p.capacity_millis)
    } else {
        add(p.engineering_millis, p.capacity_millis)?
    };
    // No credit for 60942360 or a private partial: there is no durable Bank
    // checkpoint beyond 60911751. Even the pre-epoch bootstrap tail is redone.
    let root_replay_millis = replay(ROOT - BOOTSTRAP, rate)?;
    let suffix_replay_millis = replay(TERMINAL - ROOT, rate)?;
    let mut total = add(prerequisite_millis, p.bootstrap_millis)?;
    for n in [
        root_replay_millis,
        suffix_replay_millis,
        p.checkpoint_close_restore_millis,
        p.downstream_millis,
    ] {
        total = add(total, n)?;
    }
    Ok(Forecast {
        prerequisite_millis,
        root_replay_millis,
        suffix_replay_millis,
        estimated_remaining_millis: total,
    })
}
/// An authenticated current work owner is required independently. An idle or
/// terminal job cannot acquire ownership merely by retaining its old IID.
pub fn active_shape(
    load: &str,
    active: &str,
    sub: &str,
    pid: u64,
    restarts: u64,
    iid: &str,
    expected: &str,
) -> bool {
    load == "loaded"
        && active == "active"
        && sub == "running"
        && pid > 0
        && restarts == 0
        && iid == expected
        && iid.len() == 32
        && iid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn same_owned_version(expected: Option<&str>, observed: Option<&str>) -> bool {
    expected == observed
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rate() -> Rate {
        Rate {
            first_slot: 60_939_865,
            last_slot: 60_941_559,
            elapsed_microseconds: 1_749_194_714,
        }
    }
    fn policy() -> Policy {
        Policy {
            engineering_millis: 86_400_000,
            capacity_millis: 172_800_000,
            bootstrap_millis: 21_600_000,
            checkpoint_close_restore_millis: 43_200_000,
            downstream_millis: 129_600_000,
            prerequisites_parallel: true,
        }
    }
    #[test]
    fn cold_recovery_redoes_the_full_bootstrap_to_root_not_the_last_logged_remainder() {
        let r = rate();
        let p = policy();
        let f = forecast(&r, &p).unwrap();
        assert_eq!(f.root_replay_millis, 430_601_349);
        assert_eq!(f.suffix_replay_millis, 15_730_362);
        assert_eq!(f.estimated_remaining_millis, 813_531_711);
        assert_eq!(ROOT - BOOTSTRAP, 417_014);
        assert_eq!(TERMINAL - ROOT, 15_234);
        assert!(f.root_replay_millis > replay(ROOT - 60_942_360, &r).unwrap());
        assert_eq!(
            f.estimated_remaining_millis,
            f.prerequisite_millis
                + p.bootstrap_millis
                + f.root_replay_millis
                + f.suffix_replay_millis
                + p.checkpoint_close_restore_millis
                + p.downstream_millis
        );
        assert!(f.estimated_remaining_millis > 0);
    }
    #[test]
    fn engineering_and_capacity_overlap_only_when_explicitly_reviewed() {
        let mut p = policy();
        let parallel = forecast(&rate(), &p).unwrap();
        p.prerequisites_parallel = false;
        let serial = forecast(&rate(), &p).unwrap();
        assert_eq!(
            serial.estimated_remaining_millis - parallel.estimated_remaining_millis,
            86_400_000
        );
    }
    #[test]
    fn invalid_or_reset_progress_never_becomes_a_numeric_rate() {
        for r in [
            Rate {
                first_slot: 2,
                last_slot: 3,
                elapsed_microseconds: 1,
            },
            Rate {
                first_slot: ROOT,
                last_slot: ROOT,
                elapsed_microseconds: 1,
            },
            Rate {
                first_slot: BOOTSTRAP,
                last_slot: ROOT + 1,
                elapsed_microseconds: 1,
            },
            Rate {
                first_slot: BOOTSTRAP,
                last_slot: ROOT,
                elapsed_microseconds: 0,
            },
        ] {
            assert!(forecast(&r, &policy()).is_err());
        }
    }
    #[test]
    fn missing_qualification_budget_cannot_hide_unimplemented_recovery() {
        let mut p = policy();
        p.checkpoint_close_restore_millis = 0;
        assert!(forecast(&rate(), &p).is_err());
        p = policy();
        p.engineering_millis = u64::MAX;
        assert!(forecast(&rate(), &p).is_err());
    }
    #[test]
    fn stopped_replaced_restarting_and_retained_exited_jobs_cannot_own_repair_status() {
        let iid = "e639f007d482464f8a251455659d2ede";
        assert!(active_shape("loaded", "active", "running", 2, 0, iid, iid));
        for (load, active, sub, pid, restarts, actual) in [
            ("not-found", "inactive", "dead", 0, 0, ""),
            ("loaded", "active", "exited", 0, 0, iid),
            ("loaded", "failed", "failed", 0, 0, iid),
            ("loaded", "active", "running", 2, 1, iid),
            (
                "loaded",
                "active",
                "running",
                2,
                0,
                "a639f007d482464f8a251455659d2ede",
            ),
        ] {
            assert!(!active_shape(load, active, sub, pid, restarts, actual, iid));
        }
    }
    #[test]
    fn replaced_deleted_or_newly_created_status_cannot_pass_an_older_owner_gate() {
        assert!(same_owned_version(None, None));
        assert!(same_owned_version(Some("old"), Some("old")));
        assert!(!same_owned_version(None, Some("new")));
        assert!(!same_owned_version(Some("old"), None));
        assert!(!same_owned_version(Some("old"), Some("new")));
    }
    #[test]
    fn replay_arithmetic_rounds_up_exactly_and_never_credits_saved_partial_bytes() {
        let r = Rate {
            first_slot: BOOTSTRAP,
            last_slot: BOOTSTRAP + 3,
            elapsed_microseconds: 1_000_001,
        };
        assert_eq!(replay(1, &r).unwrap(), 334);
        let f = forecast(&r, &policy()).unwrap();
        assert!(f.root_replay_millis >= 139_004_806);
    }
}
