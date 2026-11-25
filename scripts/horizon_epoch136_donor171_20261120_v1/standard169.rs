//! Account for the original standard 169 CPU reservation separately from focused 169.
use super::*;
use crate::standard169_cpu_lease::{STANDARD169_CPU as STANDARD_CPU, STANDARD169_PLAN as STANDARD};
use std::collections::BTreeMap;

const ROOT: &str = "/var/lib/jetstreamer";
const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const MEASURE: (&str, &str) = (
    "local3-preparation-operation-20261112-v2/MEASURE_CONTROL.json",
    "08389bfc34aa5863439c778bc1c91c10a641867fc4898fdaa489bb87d4e3b3bf",
);
const TEMPLATE: (&str, &str) = (
    "local2-scratch-retirement-source-preparation-20261112-v1/local3/ROOT_CONTROL.SOURCE_TEMPLATE.json",
    "d9c18548f50a1cc7ec742f0d9657d84415ec0b2e84c9a40277611dd0f38d591c",
);
const NATIVE: (&str, &str) = (
    "retry3-peer169-guarded-launch-20261113-v1/epoch169/ACTUAL_PRODUCER_NATIVE.json",
    "f9af27b04da8f30c6601205ae9f41bab916819097da99c8fb77b29347fd764b4",
);
const ARGV: (&str, &str) = (
    "retry3-peer169-guarded-launch-20261113-v1/epoch169/ORIGINAL_PRODUCER_ARGV.json",
    "9510a75208becd7a7a7b2987cc2df22f795adc890c68f590f58a23ef43103ac3",
);
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

fn focused_family(name: &str) -> bool {
    name.starts_with("horizon-qualify-169-focused-")
        || name.starts_with("horizon-guard-169-focused-")
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
    standard_names(&standard_source()?, &current_family()?)
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

fn standard_names(route: &Value, discovered: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut fixed: BTreeSet<String> = serde_json::from_value(route["closed_units"].clone())?;
    let actor = route["producer_unit"]
        .as_str()
        .context("standard 169 unit")?;
    ensure!(
        fixed.len() == 27
            && fixed.contains(actor)
            && fixed.contains("jetstreamer-epochs159-173-target1-controller-v1-r2.service")
            && route["closed_units"]
                .as_array()
                .is_some_and(|v| v.len() == fixed.len())
            && fixed.iter().all(|v| !focused_family(v)),
        "original 169 closure changed"
    );
    // Prepare helpers from the actual retry3 operation may already have been collected by PID 1.
    for u in [
        "horizon-local-replacement169-check-only-retry3-peer169-20261113-v1.service",
        "horizon-local-replacement169-check-only-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-measure-only-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-prepare-retry3-peer169-20261113-v2.service",
        "horizon-local-replacement169-prepare-local2-r2-20261110-v11.service",
        "horizon-retry3-peer169-native-operation-20261113-v1.service",
        "horizon-retry3-peer169-native-operation-20261113-v2.service",
    ] {
        fixed.insert(u.to_owned());
    }
    fixed.extend(discovered.iter().filter(|u| !focused_family(u)).cloned());
    Ok(fixed)
}

fn standard_source() -> Result<Value> {
    let control = pinned(ROOT, MEASURE)?;
    let template = pinned(ROOT, TEMPLATE)?;
    ensure!(
        control["measure_plans"]
            .as_object()
            .context("historical plans")?
            .keys()
            .map(String::as_str)
            .eq(["166", "167", "169", "170"])
            && template["complete_booked_cpu_quota_micros"]
                == "UNRESOLVED_ACTUAL_COMPLETE_CPU_QUOTA_INCLUDING_ALL4",
        "43-core booking does not bind four actors"
    );
    for (epoch, review_sha, native_sha) in [
        (
            166,
            "fb4169614881856fd54b34ac2bba7084835ddaabf8d09839aae1f24e17c69687",
            "c180951c9190a2e036f6c5e631549f1f080ee930919d0571bc4318ffcf6548f9",
        ),
        (
            167,
            "9dfadb367f4e1c5753f4fb7400710d0572f5aa4898be7b86c2732ee0e8bc0570",
            "d99f578a9c7a5e8959b9c9428e5b5d2dc67d789cf28c20632971b69a3f3b3c5b",
        ),
        (
            169,
            "22af8f0473bcbafacb1b917f23ff689247c2bba2550a6b25396f9dcca07ecfff",
            "c640be6087639116e530f2d3d22b09d4741694ef5b2a7557aade34c3b87b8721",
        ),
        (
            170,
            "22a7b8125f818038fe8912e63a2b2c4a9555cb0407d75f2401e1547801f5e5c7",
            "74f722daeecb30e4d1540fdedd6be4e5a9ec6c3b2b9cefd5c3a23fe9894c5ba8",
        ),
    ] {
        let dir = Path::new(ROOT);
        let review = json_pin(&dir.join(format!("local3-preparation-operation-20261112-v3/epoch{epoch}/epoch{epoch}-PRELAUNCH_REVIEW.json")), review_sha)?;
        let native = json_pin(
            &dir.join(format!(
                "local3-guarded-launch-20261112-v2/epoch{epoch}/ACTUAL_PRODUCER_NATIVE.json"
            )),
            native_sha,
        )?;
        ensure!(
            review["epoch"] == epoch
                && review["complete_booked_cpu_quota_micros"]
                    == control["complete_booked_cpu_quota_micros"]
                && review["all_prior_promises_retained"] == true
                && review["exclusive_original_slot_replacement"] == true
                && native["Id"]
                    == format!("horizon-qualify-{epoch}-replacement-local3-20261110-v1.service")
                && native["ActiveState"] == "active"
                && native["CPUQuotaPerSecUSec"] == "9s",
            "historical epoch {epoch} does not bind its portion of the common CPU booking"
        );
    }
    let route = pinned(ROOT, STANDARD)?;
    let native = pinned(ROOT, NATIVE)?;
    let argv: Vec<String> = serde_json::from_value(pinned(ROOT, ARGV)?)?;
    let review = &route["review"];
    let path = Path::new(review["path"].as_str().context("retry3 review path")?);
    let rev = json_pin(
        path,
        review["sha256"].as_str().context("retry3 review digest")?,
    )?;
    ensure!(
        route["epoch"] == 169
            && rev["epoch"] == 169
            && rev["exclusive_original_slot_replacement"] == true
            && rev["complete_booked_cpu_quota_micros"]
                == control["complete_booked_cpu_quota_micros"]
            && native["CPUQuotaPerSecUSec"] == "9s"
            && native["ActiveState"] == "active"
            && native["Id"] == route["producer_unit"]
            && argv.contains(&format!(
                "--unit={}",
                native["Id"].as_str().context("original unit")?
            ))
            && argv.contains(&"--property=CPUQuota=900%".into()),
        "retry3 CPU ownership changed"
    );
    Ok(route)
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
    let route = standard_source()?;
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
