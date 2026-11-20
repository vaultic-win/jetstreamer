//! Capacity proof for restoring a closed Foundation holding object.
use super::*;

const STATE: &str = "/var/lib/jetstreamer/horizon-foundation-closed-private-holding-v1";
const SCHEMA: &str = "horizon-foundation-closed-private-resource-review-v1";

fn actor_unit(cgroup: &str) -> Result<&str> {
    let unit = cgroup
        .trim_end()
        .strip_prefix("0::/system.slice/")
        .context("holding cgroup")?;
    ensure!(
        unit.starts_with("horizon-")
            && unit.ends_with(".service")
            && !unit.contains('/')
            && unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"@.-_".contains(&b)),
        "holding must run in its booked campaign unit"
    );
    Ok(unit)
}

fn booked_actor(
    host: &native257_fit::BookedHost,
    review: &Value,
    unit: &str,
    owner: &Value,
    iid: &str,
) -> Result<()> {
    ensure!(
        hex(iid, 32)
            && owner["Id"] == unit
            && owner["InvocationID"] == iid
            && owner["ControlGroup"] == format!("/system.slice/{unit}")
            && matches!(
                (owner["ActiveState"].as_str(), owner["SubState"].as_str()),
                (Some("active"), Some("running")) | (Some("activating"), Some("start"))
            )
            && owner["LoadState"] == "loaded"
            && owner["KillMode"] == "control-group"
            && owner["Delegate"] == "no"
            && owner["Restart"] == "no"
            && text(owner, "MainPID")?.parse::<u64>()? > 0
            && owner["NRestarts"] == "0"
            && owner["MemorySwapMax"] == "0",
        "holding owner identity changed"
    );
    let cap = text(owner, "MemoryMax")?.parse::<u64>()?;
    ensure!(cap > 0, "unbounded holding actor");
    let row = host.rows.iter().find(|r| r.unit == unit);
    let controls = review["control_units"]
        .as_array()
        .context("holding control rows")?;
    let control = controls.iter().find(|r| r["unit"] == unit);
    match (row, control) {
        (Some(r), None) => ensure!(
            r.invocation_id == iid
                && r.release.is_none()
                && r.maximum_memory_bytes == cap
                && host.currents.contains_key(unit),
            "holding reservation changed"
        ),
        (None, Some(c)) => ensure!(
            num(c, "maximum_memory_bytes")? == cap
                && periodic::stable_command(text(c, "expected_exec_start")?)?
                    == periodic::stable_command(text(owner, "ExecStart")?)?
                && owner["Restart"] == "no",
            "holding control booking changed"
        ),
        _ => bail!("holding worker must be charged exactly once"),
    }
    Ok(())
}

fn evaluate(
    n: &mut Native,
    source: &Bound,
    review: &Value,
    additional: u64,
    lease: Option<&RestoreLease>,
) -> Result<Value> {
    ensure!(
        review["schema"] == SCHEMA
            && review["host"] == "horizon-vaultic"
            && review["first_epoch"] == 201
            && review["last_epoch"] == 300
            && review["restore_only"] == true,
        "foreign holding review"
    );
    let path = Path::new(STATE).join("restores");
    trusted_parents(&path)?;
    let dir = fs::symlink_metadata(&path)?;
    ensure!(
        dir.is_dir() && dir.uid() == 0 && dir.mode() & 0o777 == 0o700,
        "private restore directory required"
    );
    let actor_artifact = binding(&review["holding_artifact"])?;
    actor_artifact.artifact()?;
    let actor = fs::metadata("/proc/self/exe")?;
    let expected = fs::metadata(&actor_artifact.path)?;
    ensure!(
        actor.dev() == expected.dev() && actor.ino() == expected.ino(),
        "holding image differs"
    );
    let group = fs::read_to_string("/proc/self/cgroup")?;
    let unit = actor_unit(&group)?;
    let iid = std::env::var("INVOCATION_ID")?;
    let before = n.show(unit)?;
    let host = native257_fit::booked_host_for(n, review, &path, None, lease)?;
    ensure!(
        text(&before, "MainPID")?.parse::<u32>()? == std::process::id(),
        "restore image must be the service MainPID"
    );
    booked_actor(&host, review, unit, &before, &iid)?;
    let after = n.show(unit)?;
    booked_actor(&host, review, unit, &after, &iid)?;
    live::same_owner(&before, &after)?;
    live::kernel_memory(&after, unit, text(&after, "MemoryMax")?.parse()?)?;
    // The worker's actual cap is already in the booked row or control envelope.
    // The outer restore path computes remaining unallocated body + metadata.
    let mut resources = live::resources_at(&path)?;
    resources.2 = resources.2.min(host.resources.2);
    ensure!(resources.0 == host.resources.0, "physical host changed");
    let capacity = capacity::booked_arithmetic(
        resources,
        host.century,
        &host.rows,
        &host.currents,
        host.overhead,
        (0, additional),
    )?;
    ensure!(
        fs::read_to_string("/proc/self/cgroup")? == group
            && fs::metadata(&path)?.dev() == host.device,
        "holding owner or filesystem changed"
    );
    if let Some(lease) = lease {
        lease.check_anchor(review)?;
    } else {
        fresh(num(review, "recorded_unix_seconds")?, now()?, 300)?;
    }
    n.check()?;
    let mut result = json!({"schema":"jetstreamer-foundation-holding-current-capacity-v1","host":"horizon-vaultic",
        "first_epoch":201,"last_epoch":300,"restore_only":true,"review":source,"fleet":review["fleet"],
        "observer":review["observer"],"reservation_ledger":review["reservation_ledger"],"century":review["century"],
        "native265_runtime_growth_release":host.release,"full211_growth":host.full211_growth,"boot_id":host.boot,"filesystem":path,"st_dev":host.device,
        "unit":unit,"invocation_id":iid,"holding_artifact":actor_artifact,"additional_bytes":additional,
        "minimum_free_bytes":capacity["protected_existing_floor_bytes"],"capacity":capacity,
        "all_live_growth_and_century_floor_protected":true,"local_retirement_authorized":false,
        "replay_launch_authorized":false,"remote_mutations":false,"recorded_unix_seconds":now()?});
    if let Some(proof) = host.native211_growth {
        result["native211_cold_growth_release"] = proof;
    }
    if let Some(proof) = host.boundary_memory {
        result["failed_boundary205206_memory_release"] = proof;
    }
    if let Some(proof) = host.retry_memory {
        result["completed_boundary205206_retry_memory_release"] = proof;
    }
    Ok(result)
}

pub fn check(basis: &Value, additional: u64) -> Result<Value> {
    checked(basis, additional, None)
}

fn checked(basis: &Value, additional: u64, lease: Option<&RestoreLease>) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private native evidence requires privileged access"
    );
    let source = binding(basis)?;
    let review = source.sealed()?;
    let root = Path::new(STATE).join(format!("capacity-{}-{}", std::process::id(), mono()?));
    trusted_parents(&root)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut native = Native {
        root: root.clone(),
        counter: 0,
        deadline: Some(
            mono()?
                .checked_add(180_000_000)
                .context("capacity deadline overflow")?,
        ),
    };
    let mut result = evaluate(&mut native, &source, &review, additional, lease);
    match &mut result {
        Ok(v) => {
            if let Some(l) = lease {
                v["continuing_restore"] = l.evidence();
            }
            let evidence = save_json(&root, "capacity.json", v)?;
            v["evidence"] = serde_json::to_value(evidence)?;
        }
        Err(e) => {
            save_json(
                &root,
                "failure.json",
                &json!({"schema":"jetstreamer-foundation-holding-current-capacity-failure-v1",
            "review":source,"reason":format!("{e:#}"),"remote_mutations":false}),
            )?;
        }
    }
    result
}

#[path = "foundation_holding_lease.rs"]
mod lease;
pub use lease::RestoreLease;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn holding_actor_requires_an_exact_systemd_service_cgroup() {
        assert_eq!(
            actor_unit("0::/system.slice/horizon-223-restore.service\n").unwrap(),
            "horizon-223-restore.service"
        );
        for value in [
            "0::/user.slice/horizon-a.service",
            "0::/system.slice/foo.service",
            "0::/system.slice/horizon-a.service/child",
            "0::/system.slice/horizon-x.service\n1::/x",
        ] {
            assert!(actor_unit(value).is_err());
        }
    }
    #[test]
    fn original_actor_cannot_be_omitted_double_counted_or_substituted() {
        let iid = "a".repeat(32);
        let unit = "horizon-restore.service";
        let v = json!({"Id":unit,"InvocationID":iid,"ControlGroup":format!("/system.slice/{unit}"),
          "ActiveState":"active","SubState":"running","MainPID":"42","LoadState":"loaded","Delegate":"no","KillMode":"control-group",
          "NRestarts":"0","MemorySwapMax":"0","MemoryMax":"1000","Restart":"no",
          "ExecStart":"{ path=/bin/test ; argv[]=/bin/test ; ignore_errors=no ; start_time=[] ; stop_time=[] ; pid=0 ; code=(null) ; status=0/0 }"});
        let empty = json!({"control_units":[]});
        let control = json!({"control_units":[{"unit":unit,"maximum_memory_bytes":1000,"expected_exec_start":v["ExecStart"]}]});
        let mut host = native257_fit::BookedHost {
            resources: (0, 0, 0),
            rows: vec![],
            currents: BTreeMap::new(),
            overhead: (0, 0),
            century: 0,
            full211_growth: None,
            boundary_memory: None,
            retry_memory: None,
            native211_growth: None,
            release: None,
            boot: String::new(),
            device: 0,
        };
        assert!(booked_actor(&host, &empty, unit, &v, &iid).is_err());
        booked_actor(&host, &control, unit, &v, &iid).unwrap();
        assert!(booked_actor(&host, &control, unit, &v, &"b".repeat(32)).is_err());
        host.rows.push(capacity::Reservation {
            unit: unit.into(),
            invocation_id: iid.clone(),
            maximum_memory_bytes: 1000,
            remaining_disk_growth_bytes: 10,
            minimum_free_bytes: 5,
            source: Bound::new("/old", "1".repeat(64)),
            release: None,
        });
        assert!(booked_actor(&host, &control, unit, &v, &iid).is_err());
        assert!(booked_actor(&host, &empty, unit, &v, &iid).is_err());
        host.currents.insert(unit.into(), 100);
        booked_actor(&host, &empty, unit, &v, &iid).unwrap();
        host.rows[0].maximum_memory_bytes += 1;
        assert!(booked_actor(&host, &empty, unit, &v, &iid).is_err());
    }
    #[test]
    fn restore_charges_exact_growth_and_preserves_the_drained_peers_disk_floor() {
        let row = capacity::Reservation {
            unit: "epoch250.service".into(),
            invocation_id: "1".repeat(32),
            maximum_memory_bytes: 1000,
            remaining_disk_growth_bytes: 28,
            minimum_free_bytes: 97,
            source: Bound::new("/old", "1".repeat(64)),
            release: Some(Bound::new("/drain", "2".repeat(64))),
        };
        let check = |disk, extra| {
            capacity::booked_arithmetic(
                (1_000_000_000_000, 900_000_000_000, disk),
                70,
                std::slice::from_ref(&row),
                &BTreeMap::new(),
                (0, 0),
                (0, extra),
            )
        };
        assert!(check(97, 0).is_err());
        assert!(check(115, 18).is_err());
        let v = check(116, 18).unwrap();
        assert_eq!(v["protected_existing_floor_bytes"], 98);
        assert_eq!(v["required_initial_free_bytes"], 116);
        assert_eq!(check(98, 0).unwrap()["allocation_credit_taken_bytes"], 0);
        assert!(check(u64::MAX, u64::MAX).is_err());
    }
}
