//! Capacity-only consumer for epoch 257 before the ordinary 211 launch.
//! No systemd activation, resource release, token publication or remote writes.
use super::*;

const SCRATCH257: &str = "/home/ubuntu/.jetstreamer-private/native-input257-selected-20261120-v1";
const BASELINE: &str =
    "/var/lib/jetstreamer/horizon-singleton211-bookings-v126-20261120-v1/current-ledger.json";
const BASELINE_SHA: &str = "0a5ca1924d2b4c1bb5cf1cab5b6888299633d06faada66a5c94d0291311e53ee";
const NATIVE257_MEMORY: u64 = 120_000_000_000;
const NATIVE257_DISK: u64 = 256_000_000_000;

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
    pub boot: String,
    pub device: u64,
}

pub(super) fn booked_host(
    n: &mut Native,
    review: &Value,
    path: &Path,
    native257_held: Option<bool>,
) -> Result<BookedHost> {
    no_authority(review)?;
    ensure!(
        review["Main_accepted"] == true && review["single_campaign_controller_confirmed"] == true,
        "capacity review not accepted"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(review["boot_id"] == boot.trim(), "boot changed");
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
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
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 300)?;
    let (rows, overhead, periodic) = admission::reservations(review)?;
    let previous = Bound::new(BASELINE, BASELINE_SHA).sealed()?;
    preserves_baseline(
        &serde_json::from_value::<Vec<_>>(previous["reservations"].clone())?,
        &rows,
    )?;
    peers::validate(&fleet, &rows)?;
    finalization::validate(&fleet, &observer, &rows, boot.trim())?;
    finalization::verify_inputs(&fleet)?;
    // This is an original 211 preactivation census with *no* candidate exceptions.
    // A live full211, 257, or unknown peer must obtain its own complete booking.
    if native257_held.is_some() {
        ensure!(
            rows.iter().all(|r| r.unit != native257::UNIT),
            "native257 already booked"
        );
    }
    let allowed = (native257_held == Some(true)).then_some((
        native257::UNIT,
        native257::GUARD_UNIT,
        native257::TIMER,
    ));
    let currents = live::census_with_held(n, review, &fleet, &rows, &periodic, allowed)?;
    let (effective, release) = native265_growth::arithmetic_view(n, review, &rows, boot.trim())?;
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
    let resources = live::resources_at(path)?;
    ensure!(
        Some(resources.0) == num(&observer["host_memory"], "total_kib")?.checked_mul(1024),
        "physical host changed"
    );
    fresh(num(&fleet, "recorded_unix_seconds")?, now()?, 300)?;
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path && fs::metadata(path)?.dev() == device,
        "capacity filesystem identity changed"
    );
    n.check()?;
    Ok(BookedHost {
        resources,
        rows: effective,
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
    let result = scenarios(
        host.resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        combined_control_excess,
    );
    ensure!(
        host.device == device && existing_scratch_filesystem()? == (path.clone(), device),
        "scratch backing changed during fit"
    );
    n.check()?;
    Ok(
        json!({"schema":"horizon-native257-current-fit-v1","epoch":257,"review":source,"boot_id":host.boot,
       "fleet":review["fleet"],"observer":review["observer"],"reservation_ledger":review["reservation_ledger"],
       "v126_minimum":Bound::new(BASELINE,BASELINE_SHA),"native265_runtime_growth_release":host.release,
       "scratch_filesystem":path,"scratch_st_dev":device,"actual_scratch_present":path==Path::new(SCRATCH257),"actual_current_memory":host.currents,
       "cpu_affinity_qualified":false,"scenarios":result,"recorded_unix_seconds":now()?,
       "admission_authorized":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )
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
