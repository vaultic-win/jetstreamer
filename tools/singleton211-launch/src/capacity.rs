//! Hard limits, including dormant commitments, determine fit. RSS never releases a cap.
use super::*;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reservation {
    pub unit: String,
    pub invocation_id: String,
    pub maximum_memory_bytes: u64,
    pub remaining_disk_growth_bytes: u64,
    pub minimum_free_bytes: u64,
    pub source: Bound,
    /// A drain receipt is necessary but not sufficient: live::drain rechecks kernel state.
    pub release: Option<Bound>,
}
pub(super) fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("capacity overflow")
}
pub(super) fn arithmetic(
    total: u64,
    available: u64,
    disk: u64,
    century: u64,
    rows: &[Reservation],
    currents: &BTreeMap<String, u64>,
    (auxiliary_overhead, periodic_controls): (u64, u64),
) -> Result<Value> {
    candidate_arithmetic(
        (total, available, disk),
        century,
        rows,
        currents,
        (auxiliary_overhead, periodic_controls),
        (MEMORY, SCRATCH),
    )
}

pub(super) fn candidate_arithmetic(
    (total, available, disk): (u64, u64, u64),
    century: u64,
    rows: &[Reservation],
    currents: &BTreeMap<String, u64>,
    (auxiliary_overhead, periodic_controls): (u64, u64),
    (candidate_memory, candidate_disk): (u64, u64),
) -> Result<Value> {
    ensure!(
        candidate_memory > 0 && candidate_disk > 0,
        "empty candidate"
    );
    booked_arithmetic(
        (total, available, disk),
        century,
        rows,
        currents,
        (auxiliary_overhead, periodic_controls),
        (candidate_memory, candidate_disk),
    )
}

// The holding worker already has a hard memory booking. Its restore consumes
// only the exact extra disk supplied by the closed-artifact restore plan.
pub(super) fn booked_arithmetic(
    (total, available, disk): (u64, u64, u64),
    century: u64,
    rows: &[Reservation],
    currents: &BTreeMap<String, u64>,
    (auxiliary_overhead, periodic_controls): (u64, u64),
    (candidate_memory, candidate_disk): (u64, u64),
) -> Result<Value> {
    ensure!(century > 0, "missing canonical century reserve");
    let mut hard = add(
        add(add(HOST, CONTROL)?, auxiliary_overhead)?,
        periodic_controls,
    )?;
    let mut growth = hard;
    let mut disk_growth = 0;
    let mut inherited = century;
    let mut seen = BTreeSet::new();
    for r in rows {
        ensure!(
            seen.insert(&r.unit) && r.maximum_memory_bytes > 0,
            "duplicate/zero reservation"
        );
        // Floors survive a memory release: terminal output is still resident.
        inherited = inherited.max(r.minimum_free_bytes);
        disk_growth = add(disk_growth, r.remaining_disk_growth_bytes)?;
        if r.release.is_some() {
            ensure!(
                !currents.contains_key(&r.unit),
                "released owner still active"
            );
            continue;
        }
        let current = currents.get(&r.unit).copied().unwrap_or(0);
        ensure!(
            current <= r.maximum_memory_bytes,
            "current memory exceeds cap"
        );
        hard = add(hard, r.maximum_memory_bytes)?;
        growth = add(growth, r.maximum_memory_bytes - current)?;
    }
    ensure!(
        currents.keys().all(|u| seen.contains(u)),
        "unaccounted current memory"
    );
    hard = add(hard, candidate_memory)?;
    growth = add(growth, candidate_memory)?;
    let floor = inherited.max(add(century, disk_growth)?);
    let disk_required = add(floor, candidate_disk)?;
    ensure!(
        hard <= total,
        "all hard reservations plus candidate exceed physical memory: {hard} > {total}"
    );
    ensure!(
        growth <= available,
        "remaining hard growth exceeds MemAvailable: {growth} > {available}"
    );
    ensure!(
        disk_required <= disk,
        "candidate and all retained growth exceed disk: {disk_required} > {disk}"
    );
    Ok(
        json!({"memory_obligation_after_bytes":hard,"remaining_hard_growth_bytes":growth,
        "protected_existing_floor_bytes":floor,"required_initial_free_bytes":disk_required,
        "host_memory_total_bytes":total,"available_memory_bytes":available,"observed_available_bytes":disk,
        "host_reserve_bytes":HOST,"control_reserve_bytes":CONTROL,"fixed_auxiliary_overhead_bytes":auxiliary_overhead,"periodic_control_envelope_bytes":periodic_controls,"century_floor_bytes":century,
        "retained_disk_growth_bytes":disk_growth,"allocation_credit_taken_bytes":0}),
    )
}
pub(super) fn century(v: &Value, fleet: &Value) -> Result<u64> {
    ensure!(
        v["schema"] == "horizon-native211-qualified-century-census-v1",
        "century schema"
    );
    let rows = v["entries"].as_array().context("century entries")?;
    let ready: BTreeMap<_, _> = fleet["inventory"]["entries"]
        .as_array()
        .context("inventory")?
        .iter()
        .filter(|r| r["state"] == "ready-pair")
        .map(|r| {
            Ok((
                num(r, "epoch")?,
                (
                    num(r, "archive_length")?,
                    text(r, "sidecar_sha256")?.to_owned(),
                ),
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(
        !rows.is_empty() && rows.len() == ready.len() && fleet["inventory"]["anomalies"] == 0,
        "canonical census membership"
    );
    let mut seen = BTreeSet::new();
    let mut sum = 0;
    for r in rows {
        let epoch = num(r, "epoch")?;
        let bytes = num(r, "canonical_jet_bytes")?;
        ensure!(
            (200..=300).contains(&epoch) && seen.insert(epoch) && bytes > 0,
            "invalid century entry"
        );
        ensure!(
            ready.get(&epoch) == Some(&(bytes, text(r, "archive_sha256")?.to_owned())),
            "canonical inventory changed"
        );
        for field in ["full_verification", "current_plugin", "remote_readback"] {
            binding(&r[field])?.json()?;
        }
        ensure!(
            r["normal_full_plugin_and_remote_gates_accepted"] == true,
            "unaccepted canonical gates"
        );
        sum = add(sum, bytes)?;
    }
    Ok(add(sum, sum)?.div_ceil(rows.len() as u64))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn reservation(unit: &str, hard: u64) -> Reservation {
        Reservation {
            unit: unit.into(),
            invocation_id: "a".repeat(32),
            maximum_memory_bytes: hard,
            remaining_disk_growth_bytes: 10,
            minimum_free_bytes: 20,
            source: Bound::new("/unused", "a".repeat(64)),
            release: None,
        }
    }
    #[test]
    fn current_five_lane_hard_budget_cannot_admit_a_sixth_native_restore() {
        let rows = vec![
            reservation("replays", 1_132_166_365_184),
            reservation("audit", 7_000_000_000),
            reservation("aux", 2_640_509_440),
        ];
        assert!(
            arithmetic(
                1_212_136_964_096,
                1_000_000_000_000,
                9_000_000_000_000,
                100,
                &rows,
                &BTreeMap::new(),
                (0, 0)
            )
            .is_err()
        );
    }
    #[test]
    fn release_preserves_disk_growth_and_floor_and_rejects_live_credit() {
        let mut row = reservation("peer.service", 250_000_000_000);
        let total = HOST + CONTROL + MEMORY;
        assert!(
            arithmetic(
                total,
                total,
                u64::MAX,
                100,
                &[row.clone()],
                &BTreeMap::new(),
                (0, 0)
            )
            .is_err()
        );
        row.release = Some(Bound::new("/drain", "b".repeat(64)));
        let result = arithmetic(
            total,
            total,
            u64::MAX,
            100,
            &[row.clone()],
            &BTreeMap::new(),
            (0, 0),
        )
        .unwrap();
        assert_eq!(result["protected_existing_floor_bytes"], 110);
        assert!(
            arithmetic(
                total,
                total,
                u64::MAX,
                100,
                &[row],
                &BTreeMap::from([("peer.service".into(), 1)]),
                (0, 0)
            )
            .is_err()
        );
    }
    #[test]
    fn auxiliary_overhead_survives_terminal_release_and_counts_against_both_memory_gates() {
        let auxiliary = 2_640_509_440;
        let total = HOST + CONTROL + MEMORY + auxiliary;
        let mut released = reservation("terminal.service", 250_000_000_000);
        released.release = Some(Bound::new("/drain", "b".repeat(64)));
        let rows = [released];
        let currents = BTreeMap::new();
        let v = arithmetic(
            total,
            total,
            u64::MAX,
            100,
            &rows,
            &currents,
            (auxiliary, 0),
        )
        .unwrap();
        assert_eq!(v["memory_obligation_after_bytes"], total);
        assert_eq!(v["remaining_hard_growth_bytes"], total);
        assert_eq!(v["fixed_auxiliary_overhead_bytes"], auxiliary);
        assert_eq!(v["protected_existing_floor_bytes"], 110);
        assert!(
            arithmetic(
                total - 1,
                total,
                u64::MAX,
                100,
                &rows,
                &currents,
                (auxiliary, 0)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                total,
                total - 1,
                u64::MAX,
                100,
                &rows,
                &currents,
                (auxiliary, 0)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                100,
                &rows,
                &currents,
                (u64::MAX, 0)
            )
            .is_err()
        );
    }
    #[test]
    fn overflow_missing_and_duplicate_owners_fail() {
        let r = reservation("peer.service", 1);
        assert!(
            arithmetic(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                1,
                &[r.clone(), r],
                &BTreeMap::new(),
                (0, 0)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                u64::MAX,
                &[],
                &BTreeMap::new(),
                (0, 0)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                1,
                &[],
                &BTreeMap::from([("missing".into(), 1)]),
                (0, 0)
            )
            .is_err()
        );
    }
    #[test]
    fn periodic_controls_are_additional_full_hard_and_growth_even_without_active_processes() {
        let periodic = 4_294_967_296;
        let auxiliary = 2_640_509_440;
        let total = HOST + CONTROL + MEMORY + auxiliary + periodic;
        let rows = [];
        let current = BTreeMap::new();
        let result = arithmetic(
            total,
            total,
            u64::MAX,
            100,
            &rows,
            &current,
            (auxiliary, periodic),
        )
        .unwrap();
        assert_eq!(result["memory_obligation_after_bytes"], total);
        assert_eq!(result["remaining_hard_growth_bytes"], total);
        assert_eq!(result["periodic_control_envelope_bytes"], periodic);
        assert_eq!(result["control_reserve_bytes"], CONTROL);
        assert!(
            arithmetic(
                total - 1,
                total,
                u64::MAX,
                100,
                &rows,
                &current,
                (auxiliary, periodic)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                total,
                total - 1,
                u64::MAX,
                100,
                &rows,
                &current,
                (auxiliary, periodic)
            )
            .is_err()
        );
        assert!(
            arithmetic(
                u64::MAX,
                u64::MAX,
                u64::MAX,
                100,
                &rows,
                &current,
                (0, u64::MAX)
            )
            .is_err()
        );
    }
}
