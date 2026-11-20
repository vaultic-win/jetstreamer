//! Capacity-only consumer for epoch 257 with the current epoch 211 booking.
//! No systemd activation, resource release, token publication or remote writes.
use super::*;
#[path = "failed_boundary205206.rs"]
mod failed_boundary205206;
#[path = "native211_cold_growth.rs"]
mod native211_cold_growth;

const SCRATCH257: &str = "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
const BASELINE: &str =
    "/var/lib/jetstreamer/horizon-singleton211-bookings-v126-20261120-v1/current-ledger.json";
const BASELINE_SHA: &str = "0a5ca1924d2b4c1bb5cf1cab5b6888299633d06faada66a5c94d0291311e53ee";
pub(super) const NATIVE257_MEMORY: u64 = 120_000_000_000;
pub(super) const NATIVE257_DISK: u64 = 256_000_000_000;

fn preserves_baseline(
    old: &[capacity::Reservation],
    current: &[capacity::Reservation],
) -> Result<()> {
    ensure!(old.len() == 10, "incorrect v126 cohort");
    for p in old {
        let r = current
            .iter()
            .find(|r| r.unit == p.unit)
            .context("missing historical owner")?;
        ensure!(
            r.invocation_id == p.invocation_id
                && r.maximum_memory_bytes == p.maximum_memory_bytes
                && r.remaining_disk_growth_bytes >= p.remaining_disk_growth_bytes
                && r.minimum_free_bytes >= p.minimum_free_bytes,
            "historical booking changed without registered transition: {}",
            p.unit
        );
    }
    Ok(())
}

fn scenarios(
    resources: (u64, u64, u64),
    century: u64,
    rows: &[capacity::Reservation],
    currents: &BTreeMap<String, u64>,
    overhead: (u64, u64),
    combined_control_excess: u64,
) -> Value {
    let fit = |memory, disk| match capacity::candidate_arithmetic(
        resources,
        century,
        rows,
        currents,
        overhead,
        (memory, disk),
    ) {
        Ok(v) => json!({"fits":true,"capacity":v}),
        Err(e) => json!({"fits":false,"reason":e.to_string()}),
    };
    if rows.iter().any(|r| r.unit == UNIT) {
        return json!({"limited_native257_with_booked_full211":fit(NATIVE257_MEMORY,NATIVE257_DISK)});
    }
    json!({"limited_native257":fit(NATIVE257_MEMORY,NATIVE257_DISK),"ordinary211":fit(MEMORY,SCRATCH),
        "combined_control_excess_bytes":combined_control_excess,"limited_native257_and_ordinary211":fit(NATIVE257_MEMORY+MEMORY+combined_control_excess,NATIVE257_DISK+SCRATCH)})
}

fn existing_scratch_filesystem() -> Result<(PathBuf, u64)> {
    let path = Path::new(SCRATCH257);
    let used = match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.is_dir() && m.uid() == 1000 && m.gid() == 1000 && m.mode() & 0o777 == 0o700,
                "wrong scratch owner or mode"
            );
            path
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            path.parent().context("scratch parent")?
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(used.canonicalize()? == used, "scratch mount alias");
    let m = fs::metadata(used)?;
    Ok((used.to_owned(), m.dev()))
}

pub(super) struct BookedHost {
    pub resources: (u64, u64, u64),
    pub rows: Vec<capacity::Reservation>,
    pub currents: BTreeMap<String, u64>,
    pub overhead: (u64, u64),
    pub century: u64,
    pub release: Option<Value>,
    pub full211_growth: Option<Value>,
    pub boundary_memory: Option<Value>,
    pub retry_memory: Option<Value>,
    pub native211_growth: Option<Value>,
    pub boot: String,
    pub device: u64,
}

pub(super) fn booked_host(
    n: &mut Native,
    review: &Value,
    path: &Path,
    native257_held: Option<bool>,
) -> Result<BookedHost> {
    booked_host_for(n, review, path, native257_held, None)
}

pub(super) fn booked_host_for(
    n: &mut Native,
    review: &Value,
    path: &Path,
    native257_held: Option<bool>,
    continuation: Option<&foundation_holding_capacity::RestoreLease>,
) -> Result<BookedHost> {
    let candidate = native257_held.map(|held| {
        (
            (native257::UNIT, native257::GUARD_UNIT, native257::TIMER),
            held,
        )
    });
    booked_host_candidate(n, review, path, candidate, continuation)
}

pub(super) type Candidate = ((&'static str, &'static str, &'static str), bool);

pub(super) fn booked_host_candidate(
    n: &mut Native,
    review: &Value,
    path: &Path,
    candidate: Option<Candidate>,
    continuation: Option<&foundation_holding_capacity::RestoreLease>,
) -> Result<BookedHost> {
    // An initial admission always requires fresh authoritative inputs. Only an
    // uninterrupted restore may use its frozen, exclusively booked baseline
    // while this function repeats the complete live owner and resource census.
    let current = |fleet: &Value| -> Result<()> {
        if let Some(lease) = continuation {
            lease.check_anchor(review)
        } else {
            fresh(num(fleet, "recorded_unix_seconds")?, now()?, 300)?;
            fresh(num(review, "recorded_unix_seconds")?, now()?, 300)
        }
    };
    no_authority(review)?;
    ensure!(
        review["Main_accepted"] == true && review["single_campaign_controller_confirmed"] == true,
        "capacity review not accepted"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(review["boot_id"] == boot.trim(), "boot changed");
    let fleet = binding(&review["fleet"])?.json()?;
    let observer = binding(&review["observer"])?.json()?;
    ensure!(
        fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["observer_receipt"] == review["observer"]["path"]
            && fleet["observer_sha256"] == review["observer"]["sha256"]
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["memory_target"]["valid"] == true,
        "fleet and observer binding changed"
    );
    current(&fleet)?;
    let (rows, overhead, periodic) = admission::reservations(review)?;
    let previous = Bound::new(BASELINE, BASELINE_SHA).sealed()?;
    preserves_baseline(
        &serde_json::from_value::<Vec<_>>(previous["reservations"].clone())?,
        &rows,
    )?;
    peers::validate(&fleet, &rows)?;
    let full211 = full211_peer::registered(&fleet);
    if full211 {
        full211_peer::authenticate(n, &fleet, &observer, &rows)?;
    }
    ensure!(
        rows.iter().any(|r| r.unit == UNIT) == full211,
        "full211 booking and current fleet differ"
    );
    finalization::validate_roster(&fleet, &observer, &rows, boot.trim(), full211)?;
    finalization::verify_inputs(&fleet)?;
    if let Some(((producer, guard, _), _)) = candidate {
        ensure!(
            rows.iter().all(|r| r.unit != producer && r.unit != guard),
            "candidate already booked"
        );
    }
    let allowed = candidate.and_then(|(units, held)| held.then_some(units));
    let currents = live::census_with_held(n, review, &fleet, &rows, &periodic, allowed, full211)?;
    let (mut effective, release) =
        native265_growth::arithmetic_view(n, review, &rows, boot.trim())?;
    let century = capacity::century(&binding(&review["century"])?.sealed()?, &fleet)?;
    let device = fs::metadata(path)?.dev();
    // The original bookings have one shared filesystem floor. Compare its
    // authenticated observer path with the candidate's actual backing device.
    let ledger_fs = Path::new(text(&observer["filesystem"], "path")?);
    ensure!(
        ledger_fs.is_absolute()
            && ledger_fs.canonicalize()? == ledger_fs
            && fs::metadata(ledger_fs)?.dev() == device,
        "existing disk reservations need a per-device transition"
    );
    let boundary_memory =
        failed_boundary205206::apply(n, review, &fleet, &currents, &mut effective)?;
    let retry_memory = failed_boundary205206::retry_memory::apply(
        n,
        review,
        &fleet,
        &currents,
        &mut effective,
        boundary_memory.as_ref(),
    )?;
    let native211_growth =
        native211_cold_growth::apply(n, review, &fleet, &currents, &mut effective, device)?;
    let mut resources = live::resources_at(path)?;
    let full211_growth = if full211 {
        ensure!(
            device == fs::metadata(ROOT)?.dev(),
            "candidate and full211 allocation are on different devices"
        );
        let firing = full211_window::Firing::capture(n)?;
        let row = effective
            .iter_mut()
            .find(|r| r.unit == UNIT)
            .context("missing full211 arithmetic row")?;
        resources.2 = resources.2.min(live::resources_at(path)?.2);
        Some(firing.capacity(row, &mut resources.2)?)
    } else {
        None
    };
    ensure!(
        Some(resources.0) == num(&observer["host_memory"], "total_kib")?.checked_mul(1024),
        "physical host changed"
    );
    current(&fleet)?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path && fs::metadata(path)?.dev() == device,
        "capacity filesystem identity changed"
    );
    n.check()?;
    Ok(BookedHost {
        resources,
        rows: effective,
        full211_growth,
        boundary_memory,
        retry_memory,
        native211_growth,
        currents,
        overhead: (overhead, periodic::total(&periodic)?),
        century,
        release,
        boot: boot.trim().to_owned(),
        device,
    })
}

pub(super) fn evaluate(
    n: &mut Native,
    review: &Value,
    source: &Bound,
    held: bool,
) -> Result<Value> {
    no_authority(review)?;
    ensure!(
        review["schema"] == "horizon-native257-resource-review-v1"
            && review["Main_accepted"] == true
            && review["single_campaign_controller_confirmed"] == true
            && review["epoch"] == 257,
        "unaccepted capacity review"
    );
    let (path, device) = existing_scratch_filesystem()?;
    let control_bytes = review["control_units"]
        .as_array()
        .context("control units")?
        .iter()
        .try_fold(0, |sum, unit| {
            capacity::add(sum, num(unit, "maximum_memory_bytes")?)
        })?;
    let combined_control_excess =
        capacity::add(control_bytes, 2 * 268_435_456)?.saturating_sub(CONTROL);
    let host = booked_host(n, review, &path, Some(held))?;
    let mut result = scenarios(
        host.resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        combined_control_excess,
    );
    if let Some(growth) = &host.full211_growth {
        let selected = &mut result["limited_native257_with_booked_full211"];
        if selected["fits"] == true {
            selected["capacity"]["allocation_credit_taken_bytes"] =
                growth["guard"]["lower_physical"].clone();
        }
    }
    ensure!(
        host.device == device && existing_scratch_filesystem()? == (path.clone(), device),
        "scratch backing changed during fit"
    );
    n.check()?;
    let mut fit = json!({"schema":"horizon-native257-current-fit-v1","epoch":257,"review":source,"boot_id":host.boot,
       "fleet":review["fleet"],"observer":review["observer"],"reservation_ledger":review["reservation_ledger"],
       "v126_minimum":Bound::new(BASELINE,BASELINE_SHA),"native265_runtime_growth_release":host.release,
       "scratch_filesystem":path,"scratch_st_dev":device,"actual_scratch_present":path==Path::new(SCRATCH257),"actual_current_memory":host.currents,
       "cpu_affinity_qualified":false,"scenarios":result,"recorded_unix_seconds":now()?,
       "admission_authorized":false,"replay_launch_authorized":false,"remote_mutations":false});
    if host.rows.iter().any(|r| r.unit == UNIT) {
        fit["full211_handoff"] = json!(full211_peer::handoff());
        fit["full211_growth"] = json!(host.full211_growth);
    }
    if let Some(proof) = host.native211_growth {
        fit["native211_cold_growth_release"] = proof;
    }
    if let Some(proof) = host.boundary_memory {
        fit["failed_boundary205206_memory_release"] = proof;
    }
    if let Some(proof) = host.retry_memory {
        fit["completed_boundary205206_retry_memory_release"] = proof;
    }
    Ok(fit)
}

/// Capture two consecutive natural firings without starting a worker, timer or guard.
pub fn qualify_full211_window(evidence: &Path) -> Result<Value> {
    use std::os::unix::fs::DirBuilderExt;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && evidence.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && evidence
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-native257-full211-window-")),
        "rollover evidence namespace or identity"
    );
    trusted_parents(evidence)?;
    match fs::DirBuilder::new().mode(0o700).create(evidence) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let m = fs::symlink_metadata(evidence)?;
            ensure!(
                m.is_dir()
                    && m.uid() == 0
                    && m.gid() == 0
                    && m.mode() & 0o7777 == 0o700
                    && evidence.canonicalize()? == evidence
                    && fs::read_dir(evidence)?.next().is_none(),
                "precreated qualification leaf must be empty and root private"
            );
        }
        Err(e) => return Err(e.into()),
    }
    save_json(
        evidence,
        "started.json",
        &json!({"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"monotonic_us":mono()?}),
    )?;
    let mut n = Native {
        root: evidence.into(),
        counter: 0,
        deadline: Some(
            mono()?
                .checked_add(55_000_000)
                .context("qualification clock overflow")?,
        ),
    };
    let result = full211_window::qualify(&mut n);
    match &result {
        Ok(v) => {
            save_json(evidence, "window.json", v)?;
        }
        Err(e) => {
            save_json(
                evidence,
                "failure.json",
                &json!({"error":format!("{e:#}"),"guard_or_producer_mutations":false}),
            )?;
        }
    }
    result
}
pub fn run(review: &Path, sha256: &str, evidence: &Path) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "system and sealed evidence require privileged read access"
    );
    let source = Bound::new(review, sha256);
    let v = source.sealed()?;
    ensure!(
        evidence.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && evidence
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.starts_with("horizon-native257-fit-")),
        "new local evidence namespace"
    );
    absent(evidence)?;
    trusted_parents(evidence)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(evidence)?;
    let mut n = Native {
        root: evidence.to_owned(),
        counter: 0,
        deadline: Some(
            mono()?
                .checked_add(180_000_000)
                .context("review deadline overflow")?,
        ),
    };
    let out = evaluate(&mut n, &v, &source, false);
    match &out {
        Ok(result) => {
            save_json(evidence, "fit.json", result)?;
        }
        Err(e) => {
            save_json(
                evidence,
                "failure.json",
                &json!({"schema":"horizon-native257-fit-failure-v1","reason":format!("{e:#}"),"review":source,"admission_authorized":false}),
            )?;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn booked_full211_and_its_guard_are_charged_once() {
        let producer = capacity::Reservation {
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            maximum_memory_bytes: MEMORY,
            remaining_disk_growth_bytes: SCRATCH,
            minimum_free_bytes: 0,
            source: full211_peer::handoff(),
            release: None,
        };
        let guard = full211_peer::control().maximum_memory_bytes;
        let resources = (
            HOST + CONTROL + MEMORY + guard + NATIVE257_MEMORY,
            u64::MAX,
            1 + SCRATCH + NATIVE257_DISK,
        );
        let cases = scenarios(resources, 1, &[producer], &BTreeMap::new(), (0, guard), 0);
        assert_eq!(cases.as_object().unwrap().len(), 1);
        let fit = json!({"scenarios":cases,"full211_handoff":full211_peer::handoff()});
        let review = |mode: &str| json!({"full211_capacity":mode});
        let mode = native257::selected_scenario(&review("full211-booked"), &fit).unwrap();
        let result = &fit["scenarios"][mode];
        assert_eq!(result["fits"], true);
        assert_eq!(
            result["capacity"]["memory_obligation_after_bytes"],
            resources.0
        );
        assert_eq!(
            result["capacity"]["required_initial_free_bytes"],
            resources.2
        );
        for mode in ["preserve-full211", "native257-first"] {
            assert!(native257::selected_scenario(&review(mode), &fit).is_err());
            native257::selected_scenario(&review(mode), &json!({})).unwrap();
        }
        assert!(native257::selected_scenario(&review("full211-booked"), &json!({})).is_err());
    }
    #[test]
    fn historical_lowered_or_removed_bookings_are_rejected() {
        let rows: Vec<_> = (0..10)
            .map(|n| capacity::Reservation {
                unit: format!("peer-{n}.service"),
                invocation_id: "a".repeat(32),
                maximum_memory_bytes: 50,
                remaining_disk_growth_bytes: 100,
                minimum_free_bytes: 200,
                source: Bound::new("/test", "c".repeat(64)),
                release: None,
            })
            .collect();
        preserves_baseline(&rows, &rows).unwrap();
        assert!(preserves_baseline(&rows, &rows[..9]).is_err());
        let mut changed = rows.clone();
        changed[1].minimum_free_bytes -= 1;
        assert!(preserves_baseline(&rows, &changed).is_err());
        let mut changed = rows.clone();
        changed[4].remaining_disk_growth_bytes -= 1;
        assert!(preserves_baseline(&rows, &changed).is_err());
    }
    #[test]
    fn check_211_and_257_both_compete_for_the_same_disk() {
        let total = 1_400_000_000_000;
        let r = scenarios(
            (total, total, 400_000_000_000),
            10_000_000_000,
            &[],
            &BTreeMap::new(),
            (0, 0),
            0,
        );
        assert_eq!(r["limited_native257"]["fits"], true);
        assert_eq!(r["ordinary211"]["fits"], false);
        assert_eq!(r["limited_native257_and_ordinary211"]["fits"], false);
        assert_eq!(
            r["limited_native257"]["capacity"]["required_initial_free_bytes"],
            266_000_000_000u64
        );
    }
}
