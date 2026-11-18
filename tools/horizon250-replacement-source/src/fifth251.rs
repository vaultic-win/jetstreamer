//! Plan one smaller fifth-lane experiment without changing any live limit.
use super::epoch251::{bound_value, read_bound, save251};
use super::*;
use std::{collections::BTreeMap, process::Command};
const BASE: &str = "/var/lib/jetstreamer/horizon251-replacement-20261118-static-v1";
const OBS: &str = "/home/ubuntu/.codex/diagnostics/horizon-resume-observer-20261118-v59.json";
const OBS_SHA: &str = "dea5bd7b391483878a6c1bcaf274b26da441977f411f25476fefa6a46f712e21";
const FLEET: &str =
    "/home/ubuntu/.codex/diagnostics/horizon-fleet-cycle1920-20261118-v1/fleet-ledger-v1.json";
const FLEET_SHA: &str = "04dfd563e9294253ddeedcad96a429ec91c430588df6fd46f503f4e9f522fe92";
const LIVE_MAX: u64 = 251041591296;
const CANDIDATE_MAX: u64 = 128000000000;
const CANDIDATE_HIGH: u64 = 100000000000;
const HOST_RESERVE: u64 = 64 * 1024 * 1024 * 1024;
const CONTROL: u64 = 1610612736;
const ROOT_CAP: u64 = 506191984640;
const LANES: [(u64, &str, &str); 4] = [
    (
        247,
        "horizon-qualify-247-reboot-20261117-v2.service",
        "d091bb68ff2648159c76f690b3b7fee3",
    ),
    (
        248,
        "horizon-qualify-248-reboot-20261117-v1.service",
        "16f84e36b65645a7be7d28d08e3d40cc",
    ),
    (
        249,
        "horizon-qualify-249-reboot-20261117-v1.service",
        "dbf4a4d19de84f31b3897da87622156e",
    ),
    (
        250,
        "horizon-qualify-250-reboot-20261117-v1.service",
        "a59fe93cc1d443abbb33317600227600",
    ),
];
fn num(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn manager() -> Result<Vec<u8>> {
    let units: Vec<_> = LANES.iter().map(|x| x.1).collect();
    let r=Command::new("/usr/bin/systemctl").arg("show").args(units).arg("--property=Id,InvocationID,ActiveState,SubState,NRestarts,MemoryMax,MemoryHigh,MemorySwapMax,AllowedCPUs,CPUAffinity").output()?;
    ensure!(
        r.status.success() && r.stderr.is_empty(),
        "native limits capture failed"
    );
    Ok(r.stdout)
}
fn validate_manager(bytes: &[u8]) -> Result<Vec<BTreeMap<String, String>>> {
    let mut rows = Vec::new();
    for block in std::str::from_utf8(bytes)?.trim().split("\n\n") {
        let mut row = BTreeMap::new();
        for line in block.lines() {
            let (k, v) = line.split_once('=').context("property framing")?;
            ensure!(
                row.insert(k.into(), v.into()).is_none(),
                "duplicate property"
            );
        }
        rows.push(row);
    }
    ensure!(rows.len() == 4, "live owner count differs");
    for (row, (_, unit, iid)) in rows.iter().zip(LANES) {
        for (k, v) in [
            ("Id", unit),
            ("InvocationID", iid),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NRestarts", "0"),
            ("MemoryMax", "251041591296"),
            ("MemoryHigh", "167361060864"),
            ("MemorySwapMax", "0"),
        ] {
            ensure!(
                row.get(k).map(String::as_str) == Some(v),
                "live policy differs for {unit} {k}"
            );
        }
        ensure!(
            ["64-79", "80-95", "96-111"]
                .contains(&row.get("AllowedCPUs").context("cpuset")?.as_str())
                && row.get("AllowedCPUs") == row.get("CPUAffinity"),
            "candidate CPUs 0-15 not proven disjoint"
        );
    }
    Ok(rows)
}
fn memory(total: u64, non_lane: u64, ceiling: u64, candidate: u64) -> Result<Value> {
    ensure!(
        non_lane
            .checked_add(5 * 1073741824)
            .context("host overhead overflow")?
            <= HOST_RESERVE,
        "host reserve cannot cover observed non-lane usage and five guard maxima"
    );
    ensure!(
        candidate <= ceiling && CANDIDATE_HIGH < candidate,
        "candidate exceeds RSS reservation ceiling or soft limit"
    );
    let prior = 4 * LIVE_MAX;
    let booked = prior
        .checked_add(candidate)
        .and_then(|n| n.checked_add(HOST_RESERVE))
        .and_then(|n| n.checked_add(CONTROL))
        .context("memory arithmetic overflow")?;
    ensure!(booked <= total, "hard-limit obligations do not fit host");
    Ok(
        json!({"retained_live_hard_limits_bytes":prior,"candidate_hard_limit_bytes":candidate,"candidate_soft_limit_bytes":CANDIDATE_HIGH,"candidate_scheduling_reservation_bytes":candidate,"scheduling_reservation_ceiling_bytes":ceiling,"observed_non_lane_resident_bytes":non_lane,"host_reserve_bytes":HOST_RESERVE,"guard_maxima_included_in_host_reserve_bytes":5*1073741824u64,"candidate_control_allowance_bytes":CONTROL,"total_hard_obligation_with_reserves_bytes":booked,"host_total_bytes":total,"remaining_unbooked_bytes":total-booked,"existing_hard_limits_changed":false,"checkpoint_relief_relied_upon":false}),
    )
}
fn render(mut s: String) -> Result<String> {
    replace_one(&mut s, "MemoryMax=251041591296", "MemoryMax=128000000000")?;
    replace_one(&mut s, "MemoryHigh=167361060864", "MemoryHigh=100000000000")?;
    // The smaller cache profile is planned at 80 hours of replay. Retaining
    // the predecessor's 72-hour limit would terminate it before that estimate.
    replace_one(&mut s, "RuntimeMaxSec=259200", "RuntimeMaxSec=432000")?;
    ensure!(
        s.contains("AllowedCPUs=0-15")
            && s.contains("CPUAffinity=0-15")
            && s.contains("${INVOCATION_ID}/guard-admission.json")
            && s.contains("Restart=no")
            && s.contains("MemorySwapMax=0"),
        "fifth-lane guard or isolation changed"
    );
    Ok(s)
}
pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 3,
        "usage: prepare-251-fifth NEW_OUTPUT_DIRECTORY"
    );
    let out = PathBuf::from(&args[2]);
    ensure!(
        out.is_absolute()
            && out.parent().context("parent")?.canonicalize()? == out.parent().unwrap()
            && fs::symlink_metadata(&out).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "unsafe output"
    );
    let obs = bound_value(OBS, OBS_SHA)?;
    let fleet = bound_value(FLEET, FLEET_SHA)?;
    ensure!(
        fleet["observer_receipt"] == OBS
            && fleet["observer_sha256"] == OBS_SHA
            && fleet["sampled_at_utc"] == obs["recorded_at_utc"],
        "unbound fleet/observer"
    );
    let target = &fleet["memory_target"];
    ensure!(
        target["valid"] == true
            && target["executing_lanes"] == 4
            && num(target, "desired_lanes")? >= 5,
        "no fifth-lane shortfall"
    );
    let rows = obs["replays"].as_array().context("replays")?;
    ensure!(rows.len() == 4, "wrong observer census");
    let before = manager()?;
    let native = validate_manager(&before)?;
    let mut retained_current = 0u64;
    for (e, unit, iid) in LANES {
        let r = rows
            .iter()
            .find(|r| r["range"] == format!("{e}-{e}"))
            .context("missing owner")?;
        ensure!(
            r["invocation_binding_stable"] == true
                && r["producer_after"]["unit"] == unit
                && r["producer_after"]["invocation_id"] == iid
                && r["controller_after"]["invocation_id"] == iid
                && r["useful_work"]["sufficient_for_rates"] == true,
            "unstable replay owner"
        );
        for k in [
            "memory_events.max",
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
        ] {
            ensure!(
                r["producer_cgroup_counter_delta"][k] == 0,
                "observed hard memory event"
            );
        }
        let current = num(&r["producer_before"], "memory_current_bytes")?
            .min(num(&r["producer_after"], "memory_current_bytes")?);
        ensure!(
            current <= LIVE_MAX,
            "live current exceeds retained hard cap"
        );
        retained_current += current;
    }
    let budget = memory(
        num(target, "host_total_bytes")?,
        num(target, "non_lane_resident_planning_bytes")?,
        num(target, "reservation_ceiling_bytes")?,
        CANDIDATE_MAX,
    )?;
    let available = num(&obs["host_memory"], "conservative_available_kib")?
        .checked_mul(1024)
        .context("available overflow")?;
    let additional = 4 * LIVE_MAX - retained_current + CANDIDATE_MAX + HOST_RESERVE + CONTROL;
    ensure!(
        available >= additional,
        "remaining hard growth and candidate do not fit observed available memory"
    );
    let old_capacity = bound_value(
        "/var/lib/jetstreamer/horizon250-reboot-20261117-admission-Main-v2/capacity.json",
        "149297590b264c3a64bc9b1773a81adc57e7577c0d8587062054620bd2165a0a",
    )?;
    let inherited_floor = num(&old_capacity, "guard_minimum_free_bytes")?;
    let old_century_floor = num(&old_capacity, "century_floor_bytes")?;
    let planning_guard = inherited_floor.max(4 * ROOT_CAP + old_century_floor);
    let initial = planning_guard + ROOT_CAP;
    ensure!(
        num(&obs["filesystem"], "conservative_available_bytes")? >= initial,
        "disk does not fit conservative full-root claims"
    );
    let seal = bound_value(
        &format!("{BASE}/deployment-seal-receipt.json"),
        "f9f02bcae345bc27e4dc39b1a1e6122cf9010202a5b45fecfab8856ae938177c",
    )?;
    let mut sources = Vec::new();
    for member in seal["members"].as_array().context("members")? {
        let name = member["name"].as_str().context("name")?;
        if name.ends_with(".service") || name.ends_with(".timer") {
            ensure!(!name.contains('/'), "unsafe unit leaf");
            let bytes = read_bound(
                &format!("{BASE}/{name}"),
                member["sha256"].as_str().context("hash")?,
            )?;
            let text = String::from_utf8(bytes)?;
            sources.push((
                name.to_owned(),
                if name.starts_with("horizon-qualify-") {
                    render(text)?
                } else {
                    text
                },
            ));
        }
    }
    ensure!(
        sources.len() == 3 && manager()? == before,
        "service source or live policy changed"
    );
    fs::create_dir(&out)?;
    let files = sources
        .iter()
        .map(|(n, s)| save251(&out, n, s.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    let assessment = json!({"schema":"horizon251-fifth-smaller-profile-assessment-v1","epoch":251,"observer":{"path":OBS,"sha256":OBS_SHA},"fleet":{"path":FLEET,"sha256":FLEET_SHA},"sampled_at_utc":obs["recorded_at_utc"],"native_live_limit_properties":native,"memory":budget,"observed_available_memory_bytes":available,"additional_memory_with_all_retained_hard_growth_bytes":additional,"retained_current_credit_bytes":retained_current,"disk":{"available_bytes":obs["filesystem"]["conservative_available_bytes"],"retained_full_root_claims_bytes":4*ROOT_CAP,"inherited_guard_minimum_bytes":inherited_floor,"prior_century_floor_bytes":old_century_floor,"candidate_root_cap_bytes":ROOT_CAP,"planning_guard_minimum_bytes":planning_guard,"required_initial_free_bytes":initial,"allocation_credit_taken_bytes":0,"fresh_century_census_still_required":true},"desired_lanes":target["desired_lanes"],"executing_lanes":4,"proposed_lanes":5,"proven_lanes":4,"candidate_full_replay_at_smaller_limit_qualified":false,"fresh_admission_accepted":false,"replay_launch_authorized":false,"remote_mutations":false});
    let assessment = save251(
        &out,
        "capacity-assessment.json",
        &serde_json::to_vec_pretty(&assessment)?,
    )?;
    let source = json!({"schema":"horizon251-fifth-source-plan-v1","epoch":251,"files":files,"capacity_assessment":assessment,"candidate_memory_max_bytes":CANDIDATE_MAX,"candidate_memory_high_bytes":CANDIDATE_HIGH,"candidate_root_cap_bytes":ROOT_CAP,"preserve_live_epochs":[247,248,249,250],"requires_terminal_lane_event":false,"requires_one_lane_experiment":true,"requires_fresh_admission":true,"requires_smaller_profile_qualification":true,"requires_actual_invocation_guard_before_work":true,"reuses_dormant_251_root_and_network_route":true,"existing_live_units_mutated":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false});
    let source = save251(
        &out,
        "source-plan.json",
        &serde_json::to_vec_pretty(&source)?,
    )?;
    let mut members = files;
    members.extend([assessment, source]);
    let members:Vec<_>=members.iter().map(|m|json!({"source":m["path"],"name":Path::new(m["path"].as_str().unwrap()).file_name().unwrap().to_string_lossy(),"sha256":m["sha256"],"mode":292})).collect();
    save251(
        &out,
        "deployment-plan.json",
        &serde_json::to_vec_pretty(
            &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":"/var/lib/jetstreamer/horizon251-fifth-20261118-static-v2","members":members}),
        )?,
    )?;
    File::open(&out)?.sync_all()?;
    File::open(out.parent().unwrap())?.sync_all()?;
    println!("{}", out.display());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn smaller_profile_runtime_covers_the_replay_planning_allowance() {
        let source = "MemoryMax=251041591296\nMemoryHigh=167361060864\nRuntimeMaxSec=259200\nAllowedCPUs=0-15\nCPUAffinity=0-15\n${INVOCATION_ID}/guard-admission.json\nRestart=no\nMemorySwapMax=0\n";
        let output = render(source.into()).unwrap();
        assert!(output.contains("RuntimeMaxSec=432000"));
        assert!(output.contains("MemoryMax=128000000000"));
        assert!(render(source.replace("RuntimeMaxSec=259200", "RuntimeMaxSec=infinity")).is_err());
    }
    #[test]
    fn candidate_fits_without_releasing_live_caps() {
        let v = memory(1212136964096, 32464052224, 223779342336, CANDIDATE_MAX).unwrap();
        assert_eq!(
            v["total_hard_obligation_with_reserves_bytes"],
            1202496454656u64
        );
        assert_eq!(v["remaining_unbooked_bytes"], 9640509440u64);
        assert!(memory(1212136964096, 32464052224, 223779342336, LIVE_MAX).is_err());
        assert!(memory(1212136964096, HOST_RESERVE, 223779342336, CANDIDATE_MAX).is_err());
        assert!(memory(1200000000000, 32464052224, 223779342336, CANDIDATE_MAX).is_err());
    }
    #[test]
    fn missing_or_replaced_live_owner_is_rejected() {
        let rows=LANES.iter().map(|(_,u,i)|format!("Id={u}\nInvocationID={i}\nActiveState=active\nSubState=running\nNRestarts=0\nMemoryMax=251041591296\nMemoryHigh=167361060864\nMemorySwapMax=0\nAllowedCPUs=64-79\nCPUAffinity=64-79")).collect::<Vec<_>>().join("\n\n");
        validate_manager(rows.as_bytes()).unwrap();
        for (from, to) in [
            (LANES[3].2, "foreign"),
            ("MemoryMax=251041591296", "MemoryMax=200000000000"),
            ("NRestarts=0", "NRestarts=1"),
            ("AllowedCPUs=64-79", "AllowedCPUs=0-15"),
        ] {
            assert!(validate_manager(rows.replace(from, to).as_bytes()).is_err());
        }
        assert!(validate_manager(rows.split("\n\n").next().unwrap().as_bytes()).is_err());
    }
}
