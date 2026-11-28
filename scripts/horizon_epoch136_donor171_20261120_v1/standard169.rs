//! Account for the original standard 169 CPU reservation separately from focused 169.
use super::*;
use crate::standard169_cpu_lease::{STANDARD169_CPU as STANDARD_CPU, STANDARD169_PLAN as STANDARD};
use crate::standard169_lineage::{MEASURE, focused_family, standard_names, standard_source};
use std::collections::BTreeMap;

const ROOT: &str = "/var/lib/jetstreamer";
const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const FOCUSED: (&str, &str) = (
    "epoch169-focused-admission-20261120-v4/POST_GUARD_CAPACITY.json",
    "803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc",
);
const FULL172: (&str, &str) = (
    "epoch172-full-half-core-20261120-v1/POST_GUARD_CAPACITY.json",
    "e94d1b2cb8eed6c1df6ffa4e5958a24e660ef25fbd7e9a80e99a1cf914afc9eb",
);
const FOCUSED_UNIT: &str = "horizon-qualify-169-focused-20261120-v4.service";
const FOCUSED_GUARD: &str = "horizon-guard-169-focused-20261120-v4";
const BORROW: u64 = 3_000_000 + 1_000_000 + 250_000;
const FAMILIES: &[&str] = &[
    "horizon-qualify-169-*",
    "horizon-guard-169-*",
    "horizon-guard-replacement-169-*",
    "horizon-replacement-169-*",
    "horizon-local-replacement169-*",
    "horizon-retry*-peer169-*",
    "jetstreamer-root-sweep-e159-173-t1-20261016-v1-r2-e169-*",
    "jetstreamer-root-source-recovery-e159-173-t1-20261016-v1-r2-e169-*",
];

fn pinned(root: &str, entry: (&str, &str)) -> Result<Value> {
    json_pin(&Path::new(root).join(entry.0), entry.1)
}

fn budget(inherited: u64, standard: u64, focused: u64, full: u64, host: u64) -> Result<Value> {
    ensure!(
        inherited == 43_000_000
            && standard == STANDARD_CPU
            && focused == 63_250_000
            && full == focused + 750_000
            && full <= host,
        "unexpected CPU reservation lineage"
    );
    // The other three 9-core original reservations and all seven remaining cores survive.
    let other_original = inherited
        .checked_sub(4 * standard)
        .context("incomplete historical funding")?;
    let retained_standard = standard
        .checked_sub(BORROW)
        .context("insufficient idle standard reservation")?;
    Ok(
        json!({"original_four_actor_booking_micros":inherited,"original_actor_quota_micros":standard,
        "other_original_cpu_micros":other_original,"independent_focused169_and_predecessors_micros":focused,
        "complete_current_cpu_micros":full,"candidate_cpu_micros":BORROW,
        "unfenced_simultaneous_micros":full+BORROW,"prospective_unassigned_standard169_micros":retained_standard,
        "prospective_host_total_with_exclusive_loan_micros":full,"online_and_allowed_cpu_micros":host}),
    )
}

fn current_family() -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for (cmd, field) in [("list-units", "unit"), ("list-unit-files", "unit_file")] {
        let mut c = Command::new("/usr/bin/systemctl");
        c.args([cmd, "--no-pager", "--no-legend", "--output=json"]);
        if cmd == "list-units" {
            c.arg("--all");
        }
        let out = c.args(FAMILIES).output()?;
        ensure!(
            out.status.success(),
            "cannot enumerate {cmd} for standard 169"
        );
        for row in serde_json::from_slice::<Vec<Value>>(&out.stdout)? {
            let name = row[field].as_str().context("missing systemd unit name")?;
            ensure!(
                !name.contains('/') && (name.ends_with(".service") || name.ends_with(".timer")),
                "invalid 169 unit"
            );
            names.insert(name.to_owned());
        }
    }
    Ok(names)
}

pub(super) fn requested(plan: &Value) -> Result<bool> {
    match plan.get("standard169_cpu_loan") {
        None => Ok(false),
        Some(loan) => {
            ensure!(
                loan == &json!({"standard_route":binding(&Path::new(ROOT).join(STANDARD.0), STANDARD.1),
                "cpu_quota_micros":BORROW}),
                "unrecognized standard 169 CPU loan"
            );
            Ok(true)
        }
    }
}

/// A retained, collected transient still needs its mask. Discover new names
/// as well, so a branch or unit change cannot silently extend an existing loan.
pub(super) fn routes() -> Result<BTreeSet<String>> {
    standard_names(
        &standard_source(Path::new(ROOT), json_pin)?,
        &current_family()?,
    )
}

pub(super) fn valid_name(name: &str) -> bool {
    let simple = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    let extension = name.ends_with(".service") || name.ends_with(".timer");
    simple
        && extension
        && (name == "jetstreamer-epochs159-173-target1-controller-v1-r2.service"
            || (!focused_family(name)
                && FAMILIES.iter().any(|pattern| {
                    let (prefix, tail) = pattern.split_once('*').unwrap();
                    let infix = tail.trim_end_matches('*');
                    name.strip_prefix(prefix).is_some_and(|s| s.contains(infix))
                })))
}

pub(super) fn inspect(fleet_path: &Path, fleet_sha: &str) -> Result<Value> {
    let fleet = json_pin(fleet_path, fleet_sha)?;
    ensure!(
        fleet_path.parent().and_then(Path::parent) == Some(Path::new(RUNTIME))
            && fleet_path.file_name().and_then(|v| v.to_str())
                == Some("ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && fleet["owner"] == "/root"
            && now()?
                .checked_sub(n(&fleet, "recorded_unix_seconds")?)
                .is_some_and(|s| s < 2400),
        "fresh root fleet required"
    );
    let route = standard_source(Path::new(ROOT), json_pin)?;
    let focused = pinned(RUNTIME, FOCUSED)?;
    let full = pinned(RUNTIME, FULL172)?;
    let original = full["owners"]["169"]["iid"]
        .as_str()
        .context("focused identity")?;
    let f = fleet["actual_active_private_diagnostics"]
        .as_array()
        .context("diagnostics")?
        .iter()
        .find(|v| v["epoch"] == 169)
        .context("no focused 169 owner")?;
    ensure!(
        f["unit"]["Id"] == FOCUSED_UNIT
            && f["unit"]["InvocationID"] == original
            && full["owners"]["169"]["unit"] == FOCUSED_UNIT,
        "unrecognized live focused 169 owner"
    );
    let current = show(FOCUSED_UNIT)?;
    ensure!(
        current["ActiveState"] == "active"
            && current["SubState"] == "running"
            && current["InvocationID"] == original
            && current["MainPID"] == f["unit"]["MainPID"]
            && current["NRestarts"] == "0"
            && current["Job"] == "",
        "live focused identity changed"
    );
    let family = current_family()?;
    let mut closure = BTreeMap::new();
    for name in standard_names(&route, &family)? {
        let row = show(&name)?;
        ensure!(
            closed(&row),
            "standard 169 launch route is occupied: {name}"
        );
        cgroup_empty(&name)?;
        closure.insert(
            name,
            json!({"load":row["LoadState"],"active":row["ActiveState"],"job":row["Job"]}),
        );
    }
    let timer = format!("{FOCUSED_GUARD}.timer");
    for name in family.iter().filter(|s| {
        focused_family(s)
            && s.as_str() != FOCUSED_UNIT
            && **s != timer
            && **s != format!("{FOCUSED_GUARD}.service")
    }) {
        ensure!(
            closed(&show(name)?),
            "different focused generation active: {name}"
        );
        cgroup_empty(name)?;
    }
    let timer_state = show(&timer)?;
    ensure!(
        timer_state["ActiveState"] == "active"
            && timer_state["Job"] == ""
            && timer_state["InvocationID"] == f["guard_timer"]["InvocationID"]
            && f["guard_timer"]["Id"] == timer
            && f["post_guard_capacity"] == binding(&Path::new(RUNTIME).join(FOCUSED.0), FOCUSED.1)
            && fleet["current_full172_post_guard_fit"]
                == binding(&Path::new(RUNTIME).join(FULL172.0), FULL172.1)
            && current_family()? == family
            && show(FOCUSED_UNIT)?["InvocationID"] == original,
        "169 changed during native census"
    );
    let accounting = budget(
        n(&pinned(ROOT, MEASURE)?, "complete_booked_cpu_quota_micros")?,
        STANDARD_CPU,
        n(&focused, "simultaneous_cpu_upper_bound_micros")?,
        n(&full, "complete_cpu_quota_micros")?,
        super::fit::cores()? * 1_000_000,
    )?;
    Ok(
        json!({"schema":"horizon-136-standard169-cpu-preflight-v1","at":now()?,
        "fleet":binding(fleet_path,fleet_sha),"current_focused_unit":FOCUSED_UNIT,"focused_invocation":original,
        "original_booking":binding(&Path::new(ROOT).join(MEASURE.0),MEASURE.1),"standard_route":binding(&Path::new(ROOT).join(STANDARD.0),STANDARD.1),
        "current_standard_routes":closure,"accounting":accounting,"observed_disjoint_focused_family":family.iter().filter(|s|focused_family(s)).collect::<Vec<_>>(),
        "cpu_loan_established":false,"resource_credit_micros":0,"admission_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_requires_the_exact_historical_route_and_quota() {
        assert!(!requested(&json!({})).unwrap());
        let plan = json!({"standard169_cpu_loan":{"standard_route":binding(&Path::new(ROOT).join(STANDARD.0), STANDARD.1),"cpu_quota_micros":BORROW}});
        assert!(requested(&plan).unwrap());
        let mut wrong = plan;
        wrong["standard169_cpu_loan"]["cpu_quota_micros"] = json!(STANDARD_CPU);
        assert!(requested(&wrong).is_err());
        for bad in [
            "../../other.service",
            "horizon-retry3-peer167-operation.service",
            FOCUSED_UNIT,
            "horizon-guard-169-focused-20261120-v4.timer",
            "other/169.service",
        ] {
            assert!(!valid_name(bad));
        }
        for name in [
            "horizon-retry3-peer169-native-operation-20261113-v1.service",
            "jetstreamer-root-sweep-e159-173-t1-20261016-v1-r2-e169-173-r3.service",
        ] {
            assert!(valid_name(name));
        }
    }

    #[test]
    fn retained_cpu_and_residual_are_conserved() {
        let a = budget(43_000_000, 9_000_000, 63_250_000, 64_000_000, 64_000_000).unwrap();
        assert_eq!(a["other_original_cpu_micros"], 7_000_000);
        assert_eq!(a["prospective_unassigned_standard169_micros"], 4_750_000);
        assert_eq!(a["unfenced_simultaneous_micros"], 68_250_000);
        assert!(budget(43_000_000, 9_000_000, 63_250_000, 64_000_000, 63_000_000).is_err());
        assert!(budget(43_000_000, 8_000_000, 63_250_000, 64_000_000, 64_000_000).is_err());
    }
    #[test]
    fn fixed_routes_and_discovered_helpers_exclude_the_independent_live_generation() {
        let actor = "horizon-qualify-169-replacement-local3retry3-20261110-v1.service";
        let known = "jetstreamer-epochs159-173-target1-controller-v1-r2.service";
        let mut fixed: Vec<String> = (0..25)
            .map(|i| format!("horizon-guard-169-standard-{i}.service"))
            .collect();
        fixed.extend([actor.to_owned(), known.to_owned()]);
        let route = json!({"producer_unit":actor,"closed_units":fixed});
        let discovered = BTreeSet::from([
            FOCUSED_UNIT.to_owned(),
            format!("{FOCUSED_GUARD}.timer"),
            "horizon-retry4-peer169-prepare.service".to_owned(),
        ]);
        let names = standard_names(&route, &discovered).unwrap();
        assert!(names.contains(actor) && names.contains("horizon-retry4-peer169-prepare.service"));
        assert!(names.iter().all(|v| !focused_family(v)));
        let mut crossed = route;
        crossed["closed_units"][0] = json!(FOCUSED_UNIT);
        assert!(standard_names(&crossed, &discovered).is_err());
    }
}
