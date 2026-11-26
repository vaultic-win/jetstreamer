//! Supply the shared guarded startup with a fresh, invocation-bound Foundation fit.
use super::*;

pub(super) fn current(n: &mut Native, review: &Value, held: bool) -> Result<Value> {
    ensure!(
        units::affinity(review)? == "40 41 42 43 44 45 46 47",
        "epoch 262 startup does not match the measured CPU scope"
    );
    let invocation = std::env::var("INVOCATION_ID")?;
    let fit = foundation_roster::receipt(
        n,
        Some(foundation_roster::Controller {
            unit: text(review, "controller_unit")?,
            invocation: &invocation,
            held,
        }),
    )?;
    ensure!(
        fit["fleet"] == review["fleet"]
            && fit["observer"] == review["observer"]
            && fit["booking"] == review["reservation_ledger"],
        "accepted Foundation fleet changed during epoch 262 review"
    );
    let capacity = &fit["capacity"];
    ensure!(
        capacity["fits"] == true,
        "epoch 262 does not fit. Disk shortfall {} bytes, memory shortfall {} bytes",
        capacity["disk_shortfall_bytes"],
        capacity["memory_shortfall_bytes"]
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure!(review["boot_id"] == boot.trim(), "epoch 262 boot changed");
    let memory: BTreeMap<_, _> = fit["owners"]
        .as_object()
        .context("Foundation owners")?
        .iter()
        .map(|(unit, owner)| Ok((unit, num(owner, "memory_current_bytes")?)))
        .collect::<Result<_>>()?;
    let evidence = save_json(
        &n.root,
        &format!("foundation-fit-{:04}.json", n.counter),
        &fit,
    )?;
    n.check()?;
    Ok(
        json!({"boot_id":boot.trim(),"tmpfs":capacity["candidate_mount"],
        "disk_device":fit["filesystem_device"],"disk_filesystem":FILESYSTEM,
        "actual_current_memory":memory,"foundation_roster":evidence,
        "capacity":{"protected_existing_floor_bytes":capacity["protected_existing_disk_bytes"],
            "observed_available_bytes":capacity["available_disk_bytes"]}}),
    )
}
