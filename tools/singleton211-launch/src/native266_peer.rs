//! Registration of the original, separately guarded epoch 266 cold Bank worker.
use super::*;
mod terminal;
pub(super) use terminal::live_owner as terminal_owner;
const UNIT266: &str = native266::UNIT;
const GUARD266: &str = "horizon-native266-protective-v1.service";
const TIMER266: &str = "horizon-native266-protective-v1.timer";
const IID: &str = "de754f74bbac40b9877d3b912af14886";
const PHASE: &str = "private-cold-snapshot-verification";
const ROOT266: &str = "/run/horizon266-native-cold-v1";
const CAP: u64 = 192_000_000_000;

fn origin() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon-native266-running-recovered-v161-de754f74-v1/intent.json",
        "e227595f69e40e29ce62fd046b4bd3e35634c1b9a8beef73cf41251c2822f9e4",
    )
}
fn accounting() -> Bound {
    Bound::new(
        "/var/lib/jetstreamer/horizon266-native-accounting-v161-v1/accounting.json",
        "fa5d43cb4be48bde528811fbb154ebc9d98dfb436582c7f83cf2f25db808be81",
    )
}
pub(super) fn pipeline(v: &Value) -> bool {
    v["unit"]["Id"] == UNIT266 && v["epoch"] == 266 && v["phase"] == PHASE
}
pub(super) fn diagnostic(v: &Value) -> bool {
    v["producer_unit"] == UNIT266 && v["range"] == "266-266"
}
fn owns(v: &Value) -> bool {
    v["epoch"] == 266
        || ["unit", "producer", "controller"]
            .iter()
            .any(|k| v[*k]["Id"] == UNIT266)
}
fn rows<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>> {
    v[key]
        .as_array()
        .with_context(|| format!("native266 missing {key}"))
}
fn one<T>(mut rows: impl Iterator<Item = T>) -> Result<T> {
    let row = rows.next().context("native266 owner missing")?;
    ensure!(rows.next().is_none(), "duplicate native266 owner");
    Ok(row)
}
fn observation(d: &Value, handoff: &Value, tmpfs: &Value) -> Result<()> {
    let o = &d["observation"];
    ensure!(
        diagnostic(d)
            && d["expected_producer_invocation_id"] == IID
            && d["scratch_path"] == ROOT266
            && d["status"] == "observed"
            && d.get("error") == Some(&Value::Null)
            && d["native_resource_only"] == true
            && [
                "entry_replay",
                "ordinary_replay_claim",
                "publication_authorized",
                "r2_mutations"
            ]
            .iter()
            .all(|k| d[*k] == false)
            && o["range"] == d["range"]
            && o["scratch_path"] == d["scratch_path"]
            && o["invocation_binding_stable"] == true
            && o["resource_only"] == true
            && o["native_input_diagnostic"] == true
            && [
                "entry_replay",
                "native_input_qualified",
                "publication_authorized",
                "remote_mutations",
                "r2_mutations"
            ]
            .iter()
            .all(|k| o[*k] == false)
            && o["useful_work"]["entry_progress_observed"] == false
            && o["useful_work"]["sufficient_for_rates"] == false,
        "native266 diagnostic scope or observation differs"
    );
    let mut usage = 0;
    for (when, pass) in [("before", "scratch_pass_1"), ("after", "scratch_pass_2")] {
        let producer = &o[format!("producer_{when}")];
        let rss = &producer["rss"];
        let gauges = &producer["cgroup"]["gauges"];
        ensure!(
            o[format!("controller_{when}")] == *producer
                && producer["unit"] == UNIT266
                && producer["invocation_id"] == IID
                && producer["main_pid"] == 2_563_315
                && producer["control_group"] == format!("/system.slice/{UNIT266}")
                && producer["active_state"] == "active"
                && producer["sub_state"] == "running"
                && producer["restarts"] == 0
                && producer["result"] == "success"
                && gauges["memory.max"] == CAP
                && gauges["memory.swap.max"] == 0
                && rss["census_stable"] == true
                && rss.get("error") == Some(&Value::Null),
            "native266 cgroup owner"
        );
        let members = rows(rss, "processes")?;
        ensure!(members.len() == 2, "native266 RSS roster");
        for (role, image, pid, ticks) in [
            ("native_main", "harness", 2_563_315u64, 37_399_871u64),
            ("native_child", "worker", 2_563_592, 37_400_994),
        ] {
            let m = &o[format!("{role}_{when}")];
            let pin = &handoff[image];
            let r = one(members.iter().filter(|p| p["pid"] == pid))?;
            ensure!(
                r["start_ticks"] == ticks
                    && m["executable"] == pin["path"]
                    && m["sha256"] == pin["sha256"]
                    && m["pid"] == pid
                    && m["historical_worker_claim"] == false
                    && (role == "native_main"
                        || (m["parent_pid"] == 2_563_315 && m["start_ticks"] == ticks)),
                "native266 process identity"
            );
            let before = &o[format!("{role}_before")];
            for k in ["mapped_device", "mapped_inode"] {
                ensure!(
                    num(m, k)? > 0 && m[k] == before[k],
                    "native266 mapped image changed"
                );
            }
        }
        let mount = &o[pass];
        let used = num(mount, "conservative_physical_bytes")?;
        ensure!(
            mount["device"] == tmpfs["device"]
                && mount["inode"] == tmpfs["inode"]
                && mount["tmpfs_capacity_bytes"] == tmpfs["bytes"]
                && mount["total_inodes"] == tmpfs["inodes"]
                && mount["exceeds_budget"] == false
                && used <= num(tmpfs, "maximum_root_physical_bytes")?
                && num(mount, "free_inodes")? >= num(tmpfs, "minimum_free_inodes")?,
            "native266 tmpfs measurement"
        );
        usage = usage.max(used);
    }
    ensure!(
        o["scratch_measurement_method"] == "dedicated tmpfs superblock"
            && o["conservative_observed_physical_bytes"] == usage,
        "native266 tmpfs accounting"
    );
    Ok(())
}

pub(super) fn validate(
    f: &Value,
    o: &Value,
    bookings: &[capacity::Reservation],
    boot: &str,
) -> Result<()> {
    let pipelines = rows(f, "pipelines")?;
    let active = rows(f, "active")?;
    let diagnostics = rows(o, "diagnostic_replays")?;
    let census = &f["unit_census"][UNIT266];
    let booked = bookings.iter().any(|r| r.unit == UNIT266);
    if !booked
        && !pipelines.iter().any(owns)
        && !active.iter().any(owns)
        && !diagnostics
            .iter()
            .any(|r| r["producer_unit"] == UNIT266 || r["range"] == "266-266")
        && census["ActiveState"] != "active"
        && census["ActiveState"] != "activating"
    {
        return Ok(());
    }
    let entry = one(pipelines.iter().filter(|e| owns(e)))?;
    let running = entry["live"]
        .as_bool()
        .context("native266 lifecycle state")?;
    let related_diagnostics = diagnostics
        .iter()
        .filter(|d| {
            d["producer_unit"] == UNIT266
                || d["range"] == "266-266"
                || d["expected_producer_invocation_id"] == IID
                || d["observation"]["producer_before"]["unit"] == UNIT266
                || d["observation"]["producer_after"]["unit"] == UNIT266
        })
        .collect::<Vec<_>>();
    ensure!(
        pipeline(entry)
            && entry["unit"] == *census
            && entry["expected_invocation_id"] == IID
            && entry["evidence"] == json!([origin()])
            && entry["private_qualification_only"] == true
            && entry["sampled_at_utc"] == f["sampled_at_utc"]
            && [
                "ordinary_replay_claim",
                "current_sidecar_eta_valid",
                "grants_launch_or_publication_authority"
            ]
            .iter()
            .all(|k| entry[*k] == false)
            && entry.get("finalization_evidence") == Some(&Value::Null),
        "native266 private fleet owner differs"
    );
    ensure!(
        !rows(o, "replays")?.iter().any(|r| r["range"] == "266-266"
            || r["producer_unit"] == UNIT266
            || r["producer_before"]["unit"] == UNIT266),
        "native266 private owner also reported as replay"
    );
    let ac = accounting().sealed()?;
    let r = one(bookings.iter().filter(|r| r.unit == UNIT266))?;
    ensure!(
        serde_json::to_value(r)? == ac["reservation"] && ac["capacity_credit"] == 0,
        "native266 original protected booking changed"
    );
    let h = binding(&ac["startup_handoff"])?;
    let handoff = native266::validate_saved_handoff(&h.path, &h.sha256)?;
    let intent = origin().sealed()?;
    let admitted = binding(&handoff["admission"])?.sealed()?;
    ensure!(
        intent["startup_handoff"] == json!(h)
            && intent["admission"] == handoff["admission"]
            && intent["boot_id"] == boot
            && admitted["boot_id"] == boot
            && intent["unit"] == UNIT266
            && intent["invocation_id"] == IID
            && intent["replay_entries"] == 0
            && intent["resource_samples_taken"] == 0
            && intent["entry_replay"] == false
            && intent["ordinary_replay_claim"] == false,
        "native266 accepted original capture changed"
    );
    if !running {
        ensure!(
            !active.iter().any(owns),
            "native266 terminal also marked active"
        );
        return terminal::roster(f, o, &related_diagnostics, &handoff, &ac, boot);
    }
    ensure!(
        one(active.iter().filter(|e| owns(e)))? == entry,
        "native266 active roster changed"
    );
    live::same_owner(&handoff["producer"], census)?;
    observation(
        one(related_diagnostics.into_iter())?,
        &handoff,
        &ac["original"]["tmpfs_charged_within_producer"],
    )
}

pub(super) fn guard(
    n: &mut Native,
    review: &Value,
    bookings: &[capacity::Reservation],
) -> Result<()> {
    let controls = rows(review, "control_units")?;
    let mut registered = controls.iter().filter(|v| v["unit"] == GUARD266);
    if !bookings.iter().any(|r| r.unit == UNIT266) {
        ensure!(
            registered.next().is_none(),
            "native266 guard without producer booking"
        );
        return Ok(());
    }
    let ac = accounting().sealed()?;
    ensure!(
        one(registered)? == &ac["control_unit"],
        "native266 original guard funding changed"
    );
    let orig = &ac["original"];
    for (unit, field) in [(GUARD266, "guard_source"), (TIMER266, "timer_source")] {
        let bound = binding(&orig[field])?;
        let source = bound.bytes(true)?;
        let path = Path::new("/etc/systemd/system").join(unit);
        let manager = n.show(unit)?;
        ensure!(
            manager["Id"] == unit
                && manager["LoadState"] == "loaded"
                && manager["DropInPaths"] == ""
                && manager["FragmentPath"] == json!(path)
                && fs::read(&path)? == source,
            "native266 protective unit source"
        );
        if unit == TIMER266 {
            ensure!(
                manager["ActiveState"] == "active"
                    && matches!(manager["SubState"].as_str(), Some("waiting" | "running"))
                    && manager["Unit"] == GUARD266
                    && manager["Result"] == "success",
                "native266 protective cadence"
            );
        } else {
            ensure!(
                manager["TriggeredBy"] == TIMER266
                    && manager["MemoryMax"] == "268435456"
                    && manager["MemorySwapMax"] == "0"
                    && manager["Restart"] == "no"
                    && manager["Result"] == "success"
                    && periodic::stable_command(text(&manager, "ExecStart")?)?
                        == periodic::stable_command(text(
                            &ac["control_unit"],
                            "expected_exec_start"
                        )?)?,
                "native266 protective service differs"
            );
        }
    }
    binding(&orig["guard_executable"])?.artifact()?;
    binding(&orig["guard_plan"])?.sealed()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the real sealed v161 fleet and owner evidence"]
    fn accepted_v161_peer_preserves_original_booking_and_refuses_substitutions() {
        let review = Bound::new(
            "/var/lib/jetstreamer/horizon-native257-current-bookings-v161-ops-v1/review.json",
            "b6b44c8e6e4ad8eed7ae9346d792ec9539e8935a7f460c69882f47b560260c3e",
        )
        .sealed()
        .unwrap();
        let fleet = binding(&review["fleet"]).unwrap().json().unwrap();
        let observer = binding(&review["observer"]).unwrap().json().unwrap();
        let (mut reservations, _, _) = admission::reservations(&review).unwrap();
        let boot = text(&review, "boot_id").unwrap();
        finalization::validate_roster(&fleet, &observer, &reservations, boot, true).unwrap();
        let mut bad = observer.clone();
        let row = bad["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| diagnostic(v))
            .unwrap();
        row["observation"]["native_child_after"]["start_ticks"] = json!(37_400_995);
        assert!(validate(&fleet, &bad, &reservations, boot).is_err());
        let mut bad = fleet.clone();
        let v = bad["active"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| pipeline(v))
            .unwrap()
            .clone();
        bad["active"].as_array_mut().unwrap().push(v);
        assert!(validate(&bad, &observer, &reservations, boot).is_err());
        reservations
            .iter_mut()
            .find(|r| r.unit == UNIT266)
            .unwrap()
            .maximum_memory_bytes -= 1;
        assert!(validate(&fleet, &observer, &reservations, boot).is_err());
    }
}
