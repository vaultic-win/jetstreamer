//! Fit the existing 168 standard reservation and every live peer/auxiliary obligation.
//! This measurement has no side effects and returns no reusable capacity credits.
#[path = "fit_audit.rs"]
mod audit;
#[path = "../horizon_audit90_budget_v11_20261120_v1/fit.rs"]
mod audit_budget;
#[path = "../horizon_independent_cold166_20261120_v1/prepare/auxiliary_phases.rs"]
mod auxiliary_phases;
#[path = "../horizon_epoch168_trace_admission_20261120_v1/fit_disk.rs"]
mod disk;
#[allow(dead_code)]
#[path = "../horizon_audit79_budget_v10_20261120_v1/audit_budget.rs"]
mod previous_audit_budget;
pub(super) use audit::observe as observe_audit;
#[path = "fit_peers.rs"]
mod live;
#[allow(dead_code)]
#[path = "../horizon_170_join_independent166_20261120_v1/peer.rs"]
mod peer;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::Path};

fn n(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
fn sum(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("resource count overflow")
}
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry7-recovery-20261120-v1/launch-state/epoch170/POST_GUARD_CAPACITY.json";
const BASE_SHA: &str = "b66c665624dd0a4f2e6bde63412ff1373b22eb561fad289021d3d306f8cf1cf5";
fn aux(fleet: &Value, e: &Value) -> Result<Value> {
    let a = &fleet["retry9_auxiliary_commitments"];
    let retained = &e["retained_capacities"]["auxiliary"]["retained_bookings"];
    for (k, v) in retained.as_object().context("retained auxiliary")? {
        if !matches!(
            k.as_str(),
            "phase_admissions"
                | "maximum_concurrent_phase_memory_bytes"
                | "maximum_concurrent_phase_cpu_quota_micros"
        ) {
            ensure!(a[k] == *v, "changed auxiliary {k}");
        }
    }
    let (bindings, mem, cpu) = auxiliary_phases::load(fleet)?;
    ensure!(
        retained["phase_admissions"] == bindings
            && mem == n(retained, "maximum_concurrent_phase_memory_bytes")?
            && cpu == n(retained, "maximum_concurrent_phase_cpu_quota_micros")?,
        "serial auxiliary allowance changed"
    );
    let native = auxiliary_phases::native(mem, cpu)?;
    let more = retained_build_images(&native)?;
    let p = Path::new(
        "/home/sol/.jetstreamer-private/epoch168-source-diagnostic-build-20261119-v1/build.ext4",
    );
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.uid() == 0
            && m.dev() == fs::metadata("/home/sol")?.dev()
            && m.ino() == 93716862
            && m.len() == n(a, "build_fixed_image_bytes")?,
        "fixed 4 GiB HOME image changed"
    );
    let fixed_remaining = m
        .len()
        .saturating_sub(m.blocks().checked_mul(512).context("image allocation")?);
    let growth = [
        fixed_remaining,
        n(&more, "remaining_growth_bytes")?,
        n(a, "holding_restore_overlap_bytes")?,
        n(a, "holding_staging_bytes")?,
        n(a, "build_outside_allowance_bytes")?,
    ]
    .into_iter()
    .try_fold(0, sum)?;
    Ok(
        json!({"retained_bookings":a,"phase_admissions":bindings,"native":native,"corrected_images":more,"fixed_image_remaining_growth_bytes":fixed_remaining,"remaining_growth_bytes":growth,"memory_bytes":mem,"cpu_quota_micros":cpu}),
    )
}
pub(super) fn memory() -> Result<(u64, u64)> {
    let data = fs::read_to_string("/proc/meminfo")?;
    let get = |key: &str| -> Result<u64> {
        let mut w = data
            .lines()
            .find_map(|s| s.strip_prefix(key))
            .context("host memory")?
            .split_whitespace();
        let k = w.next().context("host memory value")?.parse::<u64>()?;
        ensure!(
            w.next() == Some("kB") && w.next().is_none(),
            "host memory units"
        );
        k.checked_mul(1024).context("host memory bytes")
    };
    Ok((get("MemTotal:")?, get("MemAvailable:")?))
}
pub(super) fn cores() -> Result<u64> {
    let mut set = std::mem::MaybeUninit::<libc::cpu_set_t>::zeroed();
    ensure!(
        unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), set.as_mut_ptr())
        } == 0,
        "CPU affinity"
    );
    let allowed = unsafe { libc::CPU_COUNT(&set.assume_init()) };
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    ensure!(online > 0 && allowed > 0, "empty CPU allocation");
    Ok((online as u64).min(allowed as u64))
}
pub fn inspect(fleet_path: &Path, fleet_sha: &str, own_iid: Option<&str>) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "host admission requires privileged native observation"
    );
    let fleet = crate::json_pin(fleet_path, fleet_sha)?;
    let e = peer::evidence()?;
    ensure!(
        fleet["complete_DATA_bytes"] == 6_794_761_027_378u64
            && fleet["complete_projected_memory_bytes"] == 761_131_708_416u64
            && fleet["independent166_post_guard_capacity"] == e["post_guard_capacity"]
            && fleet["all_reservation_ending_bytes"] == 0,
        "fleet lost the complete historical allocation"
    );
    let baseline = peer::bound(&peer::pair(BASE, BASE_SHA))?;
    let prior = &baseline["combined_additive_resources"];
    let owners = live::owners(&fleet, &e)?;
    let local168 = crate::active168(&fleet)?;
    let before = live::resident(&owners, own_iid, &local168)?;
    let memory_before = memory()?;
    let free_before = disk::free()?;
    let obligation = &fleet["continuing_audit_obligation"];
    let audit = observe_audit(obligation)?;
    let auxiliary = aux(&fleet, &e)?;
    let roots = disk::measure()?;
    let own_growth = n(&roots, "remaining_standard_root_bytes")?;
    let growth = sum(n(&roots, "peer_remaining_growth_bytes")?, own_growth)?;
    let margin = sum(10u64 << 30, n(&auxiliary, "remaining_growth_bytes")?)?;
    let overlap = 64u64 << 20;
    // Fund the full independent 166 cap as a disjoint tree. No existing reservation
    // is ended. Count the original 168 tree once, with its guard metadata in FLOOR.
    let raw = [peer::FLOOR, growth, margin, overlap, peer::CAP]
        .into_iter()
        .try_fold(0, sum)?;
    let fit = json!({"complete_concurrent_remaining_growth_bytes":growth,"fresh_subtree_overlap_bytes":overlap,"unrelated_growth_margin_bytes":margin,"additional_growth_not_covered_by_existing_promise_bytes":peer::CAP,"required_raw_available_bytes":raw});
    let free = free_before.min(disk::free()?);
    let data = audit::data(&fit, free, obligation)?;
    ensure!(audit == observe_audit(obligation)?, "audit owner changed");
    let after = live::resident(&owners, own_iid, &local168)?;
    ensure!(
        owners == live::owners(&fleet, &e)? && local168 == crate::active168(&fleet)?,
        "peer topology changed"
    );
    let memory_after = memory()?;
    ensure!(memory_before.0 == memory_after.0, "host memory changed");
    // Use the retained RSS-based admission model. Cgroup anon + file_mapped and
    // process PSS independently bound the contribution of each actual live owner.
    // Normal page cache, unrelated services and historical samples count for zero.
    let realized = before.iter().try_fold(0, |acc, (epoch, first)| {
        sum(
            acc,
            (*first).min(*after.get(epoch).context("peer disappeared")?),
        )
    })?;
    let full = sum(
        sum(n(&fleet, "complete_projected_memory_bytes")?, 16u64 << 30)?,
        n(&auxiliary, "memory_bytes")?,
    )?;
    let available = memory_before.1.min(memory_after.1);
    let cpu = cores()?;
    let booked_cpu = sum(43_000_000, n(&auxiliary, "cpu_quota_micros")?)?;
    let resources = audit_budget::requirements(
        &json!({"resource_checks":{"complete_memory_plus_reserve_bytes":full,"memory_accounting":{"required_available_bytes":full.checked_sub(realized).context("resident exceeds booked memory")?},"booked_cpu_quota_micros":booked_cpu}}),
        memory_before.0,
        available,
        cpu,
    )?;
    ensure!(
        resources["complete_memory_plus_reserve_bytes"]
            == prior["complete_memory_plus_reserve_bytes"]
            && resources["complete_cpu_quota_micros"] == prior["complete_cpu_quota_micros"],
        "historical CPU/memory budget changed"
    );
    // Upper bound even if all old CPU commitments and candidate execution coincide.
    let overlap_cpu = sum(n(prior, "complete_cpu_quota_micros")?, 13_250_000)?;
    ensure!(
        cpu * 1_000_000 >= overlap_cpu,
        "complete simultaneous CPU fit"
    );
    let protected = n(&data, "required_DATA_bytes")?;
    let required = sum(protected, crate::CANDIDATE_DISK)?;
    ensure!(
        disk::free()? >= required,
        "final HOME availability below full fit"
    );
    Ok(
        json!({"schema":"epoch136-donor171-fresh-full-host-fit-v1","fleet":{"path":fleet_path,"sha256":fleet_sha},"historical_capacity":peer::pair(BASE,BASE_SHA),"protected_raw_floor_bytes":protected,"standard_root_allocated_bytes":roots["standard_root_allocated_bytes"],"remaining_standard_root_bytes":own_growth,"root_cap_bytes":guard168::CAP,"roots":roots,"exact_audit_DATA":data,"complete_required_DATA_bytes":required,"available_HOME_bytes":free,"audit_owner":audit,"auxiliary":auxiliary,"total_memory_bytes":memory_before.0,"complete_memory_plus_reserve_bytes":resources["complete_memory_plus_reserve_bytes"],"available_memory_bytes":available,"resident_live_peer_bytes":realized,"resources":resources,"simultaneous_cpu_upper_bound_micros":overlap_cpu,"live_peer_bindings":owners,"resource_credit_bytes":0,"resource_promise_ending_bytes":0,"candidate_additive_home_growth_ceiling_bytes":crate::CANDIDATE_DISK,"candidate_additive_memory_bytes":0,"epoch168_current_identity":local168}),
    )
}
fn retained_build_images(native: &Value) -> Result<Value> {
    let receipt = peer::pair(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch168-trace-worker-build-20261120-v1/CAPACITY_CORRECTION.json",
        "8c82f230abad0d64cd4107a3c708856079b0ca76cdbc171f97f00e10953818d1",
    );
    let c = peer::bound(&receipt)?;
    ensure!(
        c["original_serial_allowance"] == 2u64 << 30
            && c["serial_cpu"] == 1_000_000
            && c["additive_build_memory_authorized"] == 0
            && c["producer_reservation_endings"] == 0
            && c["audit_reservation_endings"] == 0
            && c["physical_images_retained"] == json!([16u64 << 30, 32u64 << 30]),
        "corrected serial allowance changed"
    );
    let builds = native["workers"]
        .as_array()
        .context("auxiliary workers")?
        .iter()
        .filter(|w| {
            w["unit"]
                .as_str()
                .is_some_and(|s| s.starts_with("horizon-168-") && s.contains("build"))
        })
        .collect::<Vec<_>>();
    ensure!(
        builds.len() <= 1
            && builds.iter().all(|w| w["memory_max_bytes"]
                .as_u64()
                .is_some_and(|m| m > 0 && m <= 2u64 << 30)
                && w["cpu_quota_micros"]
                    .as_u64()
                    .is_some_and(|c| c > 0 && c <= 1_000_000)),
        "epoch168 exceeded its corrected serial build slot"
    );
    let mut growth = 0;
    let mut images = vec![];
    for (role, bytes, ino) in [
        ("extractor", 16u64 << 30, 96143687),
        ("trace-worker", 32u64 << 30, 96148004),
    ] {
        let path =
            format!("/home/sol/.jetstreamer-private/epoch168-{role}-build-20261120-v1/build.ext4");
        let p = Path::new(&path);
        let m = fs::symlink_metadata(p)?;
        ensure!(
            p.canonicalize()? == p
                && m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o7777 == 0o600
                && m.len() == bytes
                && m.ino() == ino
                && m.dev() == fs::metadata("/home/sol")?.dev(),
            "retained fixed build image changed: {role}"
        );
        let physical = m
            .blocks()
            .checked_mul(512)
            .context("image allocation overflow")?;
        let remaining = bytes.saturating_sub(physical);
        growth = sum(growth, remaining)?;
        images.push(json!({"path":path,"inode":ino,"maximum_bytes":bytes,"allocated_bytes":physical,"remaining_growth_bytes":remaining}));
    }
    Ok(
        json!({"correction":receipt,"images":images,"remaining_growth_bytes":growth,"serial_memory_max_bytes":2u64<<30,"serial_cpu_quota_micros":1_000_000,"additional_execution_bytes":0}),
    )
}
