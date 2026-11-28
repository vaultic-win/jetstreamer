//! Current-fleet capacity, before opening either real epoch 228 input. No launches.
use super::*;
use std::os::unix::fs::DirBuilderExt;
#[path = "native228_demotion_control.rs"]
pub mod controller;

const COLD: &str = "horizon-native-input-228-demotion-16d4b158-v1.service";
const GUARD228: &str = "horizon-native-input-228-demotion-guard-v1.service";
const TIMER228: &str = "horizon-native-input-228-demotion-guard-v1.timer";
const ROOT228: &str = "/home/ubuntu/.jetstreamer-private/native-input228-v1620-demotion-v1";
const FULL_ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-228-demotion-root-tail-v1";
const FULL: &str = "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service";
const WORKER228: &str =
    "/var/lib/jetstreamer/horizon228-demotion-bank-9d2fd8d4-v158-v2-qualified/worker";
const WORKER_DIGEST: &str = "16d4b15881979bb7d65a0f49408580d4508b451a5953f35cbb60505d2e3cee00";
const COLD_MEMORY: u64 = 128 << 30;
const COLD_DISK: u64 = 300_268_435_456;
const FULL_DISK: u64 = 619_781_740_655;

fn scratch(name: &str, held: bool) -> Result<(PathBuf, u64)> {
    let path = Path::new(name);
    let used = match fs::symlink_metadata(path) {
        Ok(m) => {
            ensure!(
                m.is_dir() && m.uid() == 1000 && m.gid() == 1000 && m.mode() & 0o777 == 0o700,
                "wrong epoch 228 scratch custody"
            );
            path
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !held => {
            path.parent().context("scratch parent")?
        }
        Err(e) => return Err(e.into()),
    };
    ensure!(used.canonicalize()? == used, "epoch 228 scratch alias");
    Ok((used.to_owned(), fs::metadata(used)?.dev()))
}
fn protected_unit(n: &mut Native, held: bool) -> Result<Value> {
    let current = n.show(COLD)?;
    if held {
        let iid = text(&current, "InvocationID")?;
        live::finite_owner(&current, COLD, iid, COLD_MEMORY)?;
        ensure!(
            current["Type"] == "exec",
            "original worker must be systemd MainPID"
        );
        gate::held_image(text(&current, "MainPID")?.parse()?, iid, COLD, WORKER228)?;
    } else {
        ensure!(
            current["MainPID"] == "0"
                && current["ControlPID"] == "0"
                && current["Job"] == ""
                && matches!(current["ActiveState"].as_str(), Some("inactive" | "failed")),
            "228 native owner exists"
        );
    }
    Ok(current)
}
fn charges(review: &Value) -> Result<Value> {
    let controls = review["control_units"]
        .as_array()
        .context("control units")?;
    let controller = text(review, "epoch228_controller_unit")?;
    ensure!(
        controller.starts_with("horizon228-demotion-cold-control-")
            && controller.ends_with(".service")
            && controller
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b".-".contains(&v)),
        "epoch 228 controller name"
    );
    let mut found = false;
    let mut total = 256u64 << 20;
    for row in controls {
        let unit = text(row, "unit")?;
        let bytes = num(row, "maximum_memory_bytes")?;
        ensure!(
            unit != COLD && unit != GUARD228 && unit != FULL && bytes > 0,
            "duplicate candidate booking"
        );
        if unit == controller {
            ensure!(!found && bytes == 512 << 20, "epoch 228 controller cap");
            found = true;
        }
        total = capacity::add(total, bytes)?;
    }
    ensure!(
        found && total <= CONTROL,
        "epoch 228 guard and controller not fully booked"
    );
    Ok(
        json!({"controller":controller,"controller_bytes":512u64<<20,"guard_bytes":256u64<<20,"control_total_bytes":total,"control_reserve_bytes":CONTROL}),
    )
}

fn apply_retry(
    rows: &mut [capacity::Reservation],
    observed: Option<&Value>,
    review: &Value,
) -> Result<Option<Value>> {
    let election = review.get("epoch228_completed_retry_memory");
    let Some(retry) = observed else {
        ensure!(
            election.is_none(),
            "epoch 228 retry election lacks fresh original drainage"
        );
        return Ok(None);
    };
    let name = text(retry, "unit")?;
    let row = rows
        .iter_mut()
        .find(|row| row.unit == name)
        .context("missing completed retry row")?;
    let original = row
        .release
        .as_ref()
        .context("retry still booked in effective view")?;
    ensure!(
        name == "horizon205206-adjacent-boundary-v137-v2.service"
            && text(retry, "invocation_id")? == "5c0fb3eb5d594e06981838633f47dfaf"
            && row.invocation_id == text(retry, "invocation_id")?
            && row.maximum_memory_bytes == 125_000_000_000
            && num(retry, "released_memory_bytes")? == row.maximum_memory_bytes
            && retry["bridge"] == json!(original)
            && retry["original_ledger_unchanged"] == true
            && retry["inherited_floor_credit_bytes"] == 0
            && retry["physical_allocation_credit_bytes"] == 0
            && retry["released_disk_growth_bytes"] == 0,
        "distinct retry memory binding"
    );
    if let Some(e) = election {
        let requested = &review["completed_boundary205206_retry_memory_release"];
        ensure!(
            e == &json!({"unit":COLD,"scope":"epoch228-cold","bridge":original})
                && requested
                    == &json!({"bridge":original,"no_pending_or_future_retry_confirmed":true}),
            "retry authorization is not for this cold producer"
        );
        return Ok(Some(retry.clone()));
    }
    row.release = None;
    Ok(None)
}

fn fit(host: &native257_fit::BookedHost, memory: u64, disk: u64) -> Value {
    match capacity::candidate_arithmetic(
        host.resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        (memory, disk),
    ) {
        Ok(mut c) => {
            if let Some(g) = &host.full211_growth {
                c["allocation_credit_taken_bytes"] = g["guard"]["lower_physical"].clone();
            }
            json!({"fits":true,"capacity":c})
        }
        Err(e) => json!({"fits":false,"reason":e.to_string()}),
    }
}
fn evaluate(n: &mut Native, review: &Value, source: &Bound, held: bool) -> Result<Value> {
    ensure!(
        review["schema"] == "horizon-native228-demotion-resource-review-v1"
            && review["epoch"] == 228,
        "epoch 228 resource-review scope"
    );
    let controls = charges(review)?;
    let controller = text(&controls, "controller")?;
    let own = n.show(controller)?;
    live::finite_owner(&own, controller, text(&own, "InvocationID")?, 512 << 20)?;
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{controller}"),
        "outside booked epoch 228 controller"
    );
    let (path, device) = scratch(ROOT228, held)?;
    let full_before = scratch(FULL_ROOT, false)?;
    ensure!(
        full_before.1 == device && fs::metadata("/")?.dev() == device,
        "scratch and inherited ext4 floor devices differ"
    );
    let worker = Bound::new(WORKER228, WORKER_DIGEST);
    worker.artifact()?;
    let before = protected_unit(n, held)?;
    let mut host = native257_fit::booked_host_candidate(
        n,
        review,
        &path,
        Some(((COLD, GUARD228, TIMER228), held)),
        None,
    )?;
    ensure!(
        host.rows
            .iter()
            .all(|r| r.unit != FULL && r.unit != controller),
        "candidate/controls already in producer ledger"
    );
    let retry = apply_retry(&mut host.rows, host.retry_memory.as_ref(), review)?;
    let final_resources = live::resources_at(&path)?;
    ensure!(
        final_resources.0 == host.resources.0
            && scratch(ROOT228, held)? == (path.clone(), device)
            && scratch(FULL_ROOT, false)? == full_before
            && host.device == device,
        "scratch or host changed"
    );
    host.resources.1 = host.resources.1.min(final_resources.1);
    host.resources.2 = host.resources.2.min(final_resources.2);
    let cold = fit(&host, COLD_MEMORY, COLD_DISK);
    // A cold-only choice cannot discharge this reservation for a full root-tail replay.
    if let Some(proof) = &retry {
        let name = text(proof, "unit")?;
        host.rows
            .iter_mut()
            .find(|r| r.unit == name)
            .context("retry row")?
            .release = None;
    }
    let full = fit(&host, 225_000_000_000, FULL_DISK);
    let after = protected_unit(n, held)?;
    if held {
        live::same_owner(&before, &after)?;
    }
    let outer = n.show(controller)?;
    live::same_owner(&own, &outer)?;
    live::finite_owner(&outer, controller, text(&outer, "InvocationID")?, 512 << 20)?;
    fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    n.check()?;
    Ok(
        json!({"schema":"horizon-native228-demotion-current-fit-v1","epoch":228,"unit":COLD,"held":held,"producer":after,"worker":worker,"review":source,"observer":review["observer"],"fleet":review["fleet"],"reservation_ledger":review["reservation_ledger"],"recorded_unix_seconds":now()?,"boot_id":host.boot,"control_charges":controls,"controller":outer,"disk_device":device,"cold_root":ROOT228,"full_root":FULL_ROOT,"full_unit":FULL,"scenarios":{"cold":cold,"root_tail":full},"actual_current_memory":host.currents,"full211_growth":host.full211_growth,"old_boundary_memory_release":host.boundary_memory,"epoch228_completed_retry_memory_release":retry,"additional_paired_retry_credit_bytes":0,"holding_reclamation_credit_bytes":0,"admission_authorized":false,"replay_launch_authorized":false,"remote_mutations":false}),
    )
}

pub fn run(review: &Path, sha256: &str, evidence: &Path, held: bool) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && evidence.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && evidence
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.starts_with("horizon-native228-demotion-fit-")),
        "root-only epoch 228 evidence directory"
    );
    let source = Bound::new(review, sha256);
    let r = source.sealed()?;
    absent(evidence)?;
    trusted_parents(evidence)?;
    fs::DirBuilder::new().mode(0o700).create(evidence)?;
    let mut n = Native {
        root: evidence.to_owned(),
        counter: 0,
        deadline: Some(mono()?.checked_add(180_000_000).context("clock overflow")?),
    };
    let result = evaluate(&mut n, &r, &source, held);
    match &result {
        Ok(v) => {
            save_json(evidence, "fit.json", v)?;
        }
        Err(e) => {
            save_json(
                evidence,
                "failure.json",
                &json!({"schema":"horizon-native228-demotion-fit-failure-v1","review":source,"reason":format!("{e:#}"),"admission_authorized":false}),
            )?;
        }
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_a_separately_elected_original_retry_can_fund_epoch228_cold() {
        let original = Bound::new("/protected/bridge", "a".repeat(64));
        let row = capacity::Reservation {
            unit: "horizon205206-adjacent-boundary-v137-v2.service".into(),
            invocation_id: "5c0fb3eb5d594e06981838633f47dfaf".into(),
            maximum_memory_bytes: 125_000_000_000,
            remaining_disk_growth_bytes: 7,
            minimum_free_bytes: 11,
            source: original.clone(),
            release: Some(original.clone()),
        };
        let actual = json!({"unit":row.unit,"invocation_id":row.invocation_id,"bridge":original,"original_ledger_unchanged":true,"released_memory_bytes":row.maximum_memory_bytes,"inherited_floor_credit_bytes":0,"physical_allocation_credit_bytes":0,"released_disk_growth_bytes":0});
        let reviewed = json!({"completed_boundary205206_retry_memory_release":{"bridge":original,"no_pending_or_future_retry_confirmed":true},"epoch228_completed_retry_memory":{"unit":COLD,"scope":"epoch228-cold","bridge":original}});
        let mut rows = [row.clone()];
        assert_eq!(
            apply_retry(&mut rows, Some(&actual), &reviewed).unwrap(),
            Some(actual.clone())
        );
        assert!(
            rows[0].release.is_some()
                && rows[0].remaining_disk_growth_bytes == 7
                && rows[0].minimum_free_bytes == 11
        );
        assert!(apply_retry(&mut rows, None, &reviewed).is_err());
        let mut other = reviewed.clone();
        other["epoch228_completed_retry_memory"]["scope"] = json!("full");
        assert!(apply_retry(&mut rows, Some(&actual), &other).is_err());
        let mut bad = actual.clone();
        bad["released_disk_growth_bytes"] = json!(1);
        assert!(apply_retry(&mut rows, Some(&bad), &reviewed).is_err());
        assert!(
            apply_retry(&mut rows, Some(&actual), &json!({}))
                .unwrap()
                .is_none()
                && rows[0].release.is_none()
        );
    }
    #[test]
    fn must_book_original_controller_and_guard_in_existing_pool() {
        let name = "horizon228-demotion-cold-control-v1.service";
        let mut r = json!({"epoch228_controller_unit":name,"control_units":[{"unit":name,"maximum_memory_bytes":512u64<<20}]});
        assert!(charges(&r).is_ok());
        r["control_units"][0]["maximum_memory_bytes"] = json!(256u64 << 20);
        assert!(charges(&r).is_err());
        r["control_units"] = json!([{"unit":name,"maximum_memory_bytes":512u64<<20},{"unit":"another.service","maximum_memory_bytes":1u64<<30}]);
        assert!(charges(&r).is_err());
        r["control_units"] = json!([]);
        assert!(charges(&r).is_err());
    }
    #[test]
    fn cold_and_full_preserve_entire_scratch_and_bound_copy() {
        assert_eq!(COLD_DISK, 300_000_000_000 + (256u64 << 20));
        assert_eq!(FULL_DISK, 609_271_199_744 + 10_510_540_911);
        let m = HOST + CONTROL + 225_000_000_000;
        let host = native257_fit::BookedHost {
            resources: (m, m, COLD_DISK + 500),
            rows: vec![],
            currents: BTreeMap::new(),
            overhead: (0, 0),
            century: 500,
            release: None,
            full211_growth: None,
            boundary_memory: None,
            retry_memory: None,
            native211_growth: None,
            boot: "".into(),
            device: 1,
        };
        assert_eq!(fit(&host, COLD_MEMORY, COLD_DISK)["fits"], true);
        assert_eq!(fit(&host, 225_000_000_000, FULL_DISK)["fits"], false);
    }
}
