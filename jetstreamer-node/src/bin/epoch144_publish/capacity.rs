//! Refreshed delivery-only protection. Never edits guards or admits replay.
use super::{Bound, Plan, evidence, read};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path, process::Command};

const CLAIM_TOOL: &str = "b79a05f10abe832bfc086883792a589e3f082b4edd12e8171bb33c291bdda436";
const SCRIPT: &str = "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62";
const GIB: u64 = 1 << 30;
const RANGES: [(&str, u64, &str, u64); 4] = [
    ("152-153", 512, "152-153", 2027224563712),
    ("155-156", 512, "155-156", 2336462209024),
    ("160", 768, "160", 3984782679494),
    ("191-194", 512, "191-194", 3264175144960),
];
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Refresh {
    pub(super) schema: String,
    pub(super) growth_claims: Vec<Bound>,
}

fn fields(unit: &str, properties: &str) -> Result<Value> {
    let o = Command::new("/usr/bin/systemctl")
        .args(["show", unit, &format!("--property={properties}")])
        .output()?;
    ensure!(o.status.success(), "capacity owner query failed:{unit}");
    Ok(serde_json::to_value(
        std::str::from_utf8(&o.stdout)?
            .lines()
            .map(|s| s.split_once('=').context("malformed systemd property"))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?,
    )?)
}
fn command_has(command: &str, arg: &str) -> bool {
    let option = arg.split_once('=').map(|(k, _)| format!("{k}="));
    let matches: Vec<_> = command
        .split_ascii_whitespace()
        .filter(|a| {
            option
                .as_ref()
                .map_or(*a == arg, |prefix| a.starts_with(prefix))
        })
        .collect();
    matches == [arg]
}
fn guard(
    label: &str,
    floor: u64,
    controller_unit: &str,
    controller: &str,
    producer_unit: &str,
    producer: &str,
) -> Result<Value> {
    let base = format!("jetstreamer-adaptive-reserve-package-rebind-{label}-20261021-v1");
    let unit = format!("{base}.service");
    let timer = format!("{base}.timer");
    let v = fields(
        &unit,
        "Id,InvocationID,MainPID,NRestarts,Result,ExecMainStatus,ActiveState,SubState,ExecStart,ExecMainExitTimestampMonotonic,CapabilityBoundingSet,AmbientCapabilities,ProtectHome,ProtectSystem",
    )?;
    ensure!(
        v["Id"] == unit
            && v["MainPID"] == "0"
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["ProtectHome"] == "read-only"
            && v["ProtectSystem"] == "strict"
            && v["CapabilityBoundingSet"] == "cap_sys_ptrace"
            && v["AmbientCapabilities"] == "cap_sys_ptrace"
            && v["InvocationID"].as_str().is_some_and(|s| s.len() == 32),
        "guard is not a successful actual fire:{unit}"
    );
    let exited = v["ExecMainExitTimestampMonotonic"]
        .as_str()
        .context("guard exit timestamp")?
        .parse::<u64>()?;
    let mut clock: libc::timespec = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } == 0,
        "monotonic clock failed"
    );
    let now = u64::try_from(clock.tv_sec)?
        .checked_mul(1_000_000)
        .and_then(|n| n.checked_add(u64::try_from(clock.tv_nsec).ok()? / 1000))
        .context("monotonic overflow")?;
    ensure!(
        exited != 0 && exited <= now && now - exited <= 180_000_000,
        "guard success is stale"
    );
    let t = fields(
        &timer,
        "Id,ActiveState,SubState,TimersMonotonic,NextElapseUSecMonotonic",
    )?;
    ensure!(
        t["Id"] == timer && t["ActiveState"] == "active" && t["SubState"] == "waiting",
        "guard timer not waiting:{timer}"
    );
    let command = v["ExecStart"].as_str().context("guard command")?;
    let script = match label {
        "152-153" => {
            "/usr/local/lib/jetstreamer/adaptive-reserve-epochs152-153-20261014-v1/guard-adaptive-replay-reserve.py"
        }
        "155-156" => {
            "/usr/local/lib/jetstreamer/adaptive-reserve-epochs155-156-20261016-v1/guard-adaptive-replay-reserve.py"
        }
        "160" => {
            "/usr/local/lib/jetstreamer/horizon-epoch160-reserve-refresh-20261021-v2/guard-adaptive-replay-reserve.py"
        }
        "191-194" => {
            "/usr/local/lib/jetstreamer/adaptive-reserve-epochs191-194-20261016-v1/guard-adaptive-replay-reserve.py"
        }
        _ => anyhow::bail!("foreign guard"),
    };
    evidence::bound_file(Path::new(script), SCRIPT, 1 << 20, true)?;
    for arg in [
        script.to_owned(),
        format!("--controller-unit={controller_unit}"),
        format!("--expected-controller-invocation-id={controller}"),
        format!("--producer-unit={producer_unit}"),
        format!("--expected-producer-invocation-id={producer}"),
        "--filesystem=/home/sol".into(),
        format!("--minimum-free-bytes={floor}"),
        "--maximum-worker-vmas=800000".into(),
        format!("--guard-timer={timer}"),
    ] {
        ensure!(command_has(command, &arg), "guard binding missing:{arg}");
    }
    for option in ["--intent-receipt=", "--completion-receipt="] {
        let paths: Vec<_> = command
            .split_ascii_whitespace()
            .filter_map(|s| s.strip_prefix(option))
            .collect();
        ensure!(paths.len() == 1, "guard receipt binding absent/duplicated");
        super::absent(Path::new(paths[0]))?;
    }
    Ok(json!({"unit":v,"timer":t,"script_sha256":SCRIPT,"unchanged_floor_bytes":floor}))
}
fn arithmetic(claims: u64, floor: u64, guards: u64) -> Result<(u64, u64)> {
    // Each of four growth claims already protects one 2*max-jet allowance.
    // Reserve another five for the other claimed epochs, plus the safety floor
    // and 64GiB for metadata/import staging/measurement uncertainty. No credit
    // for shrinkage, already-written bytes, or pending retirement is taken.
    let debt = floor.checked_mul(5).context("delivery debt overflow")?;
    let measured = claims
        .checked_add(debt)
        .and_then(|n| n.checked_add(floor))
        .and_then(|n| n.checked_add(64 * GIB))
        .context("capacity overflow")?;
    Ok((measured.max(guards), debt))
}
pub(super) fn qualify(p: &Plan, o: &Value, fleet: &Value, floor: u64) -> Result<(u64, Value)> {
    let s = p.refreshed_capacity.as_ref().context("refresh missing")?;
    ensure!(
        s.schema == "jetstreamer-exact144-delivery-capacity-refresh-v1"
            && s.growth_claims.len() == 4
            && floor == 205211459014,
        "wrong capacity profile"
    );
    let active = fleet["active"].as_array().context("active epoch census")?;
    let epochs: BTreeSet<_> = active
        .iter()
        .map(|a| a["epoch"].as_u64().context("active epoch"))
        .collect::<Result<_>>()?;
    ensure!(
        active.len() == 9
            && epochs == BTreeSet::from([152, 153, 155, 156, 160, 191, 192, 193, 194])
            && active.iter().all(|a| a["phase"] == "replay"),
        "delivery claim census changed"
    );
    ensure!(
        fleet["pipelines"]
            .as_array()
            .context("pipeline census")?
            .iter()
            .all(|p| p["live"] == false),
        "unbudgeted live delivery pipeline"
    );
    let mut sum = 0u64;
    let mut guards = Vec::new();
    let mut claims = Vec::new();
    for ((range, gib, label, guard_floor), binding) in RANGES.iter().zip(&s.growth_claims) {
        let c = read(binding, false)?;
        let row: Vec<_> = o["replays"]
            .as_array()
            .context("replay census")?
            .iter()
            .filter(|r| r["range"] == *range)
            .collect();
        ensure!(row.len() == 1, "growth replay absent/duplicated");
        let r = row[0];
        let (first, last) = range.split_once('-').unwrap_or((*range, *range));
        for a in active.iter().filter(|a| {
            a["epoch"].as_u64().is_some_and(|e| {
                e >= first.parse::<u64>().unwrap() && e <= last.parse::<u64>().unwrap()
            })
        }) {
            for owner in ["controller", "producer"] {
                ensure!(
                    a[owner]["Id"] == r[format!("{owner}_after")]["unit"]
                        && a[owner]["InvocationID"] == r[format!("{owner}_after")]["invocation_id"],
                    "fleet and observer claim identities differ"
                );
            }
        }
        ensure!(
            c["schema"] == "jetstreamer-horizon-growth-claim-v1"
                && c["range"] == *range
                && c["verifier_sha256"] == CLAIM_TOOL
                && c["controller_invocation_id"] == r["controller_after"]["invocation_id"]
                && c["producer_invocation_id"] == r["producer_after"]["invocation_id"]
                && c["requested_claim_gib"] == *gib
                && c["requested_claim_bytes"] == gib * GIB
                && c["scratch_multiplier"] == 2
                && c["max_jet_multiplier"] == 2
                && c["maximum_verified_jet_bytes"] == floor / 2,
            "wrong invocation-bound growth claim:{range}"
        );
        for flag in [
            "replay_launch_authorized",
            "local_deletion_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            ensure!(c[flag] == false, "growth grants authority");
        }
        let plan: Bound = Bound {
            path: c["plan"].as_str().context("growth plan")?.into(),
            sha256: c["plan_sha256"]
                .as_str()
                .context("growth plan digest")?
                .into(),
        };
        let gp = read(&plan, true)?;
        ensure!(
            gp["schema"] == "jetstreamer-horizon-growth-claim-plan-v1"
                && gp["expected_controller_invocation_id"] == c["controller_invocation_id"]
                && gp["expected_producer_invocation_id"] == c["producer_invocation_id"]
                && gp["range"] == *range
                && gp["requested_claim_gib"] == *gib
                && gp["scratch_multiplier"] == 2
                && gp["max_jet_multiplier"] == 2
                && gp["century_floor_evidence"] == serde_json::to_value(&p.century_floor)?
                && gp["output_receipt"].as_str() == binding.path.to_str(),
            "growth plan differs"
        );
        let observations = c["observations"]
            .as_array()
            .context("growth observations")?;
        ensure!(observations.len() >= 6, "insufficient growth windows");
        let last = observations.last().unwrap();
        ensure!(
            last["path"].as_str() == p.observer.path.to_str()
                && last["sha256"] == p.observer.sha256,
            "growth excludes current sample"
        );
        let inputs = gp["observations"]
            .as_array()
            .context("growth plan inputs")?;
        ensure!(
            inputs.len() == observations.len(),
            "growth input census differs"
        );
        for (input, observed) in inputs.iter().zip(observations) {
            ensure!(
                input["path"] == observed["path"] && input["sha256"] == observed["sha256"],
                "growth input binding differs"
            );
            read(&serde_json::from_value(input.clone())?, false)?;
        }
        let max_scratch = c["maximum_observed_scratch_bytes"]
            .as_u64()
            .context("maximum scratch")?;
        let formula = max_scratch
            .checked_mul(2)
            .and_then(|n| n.checked_add(floor))
            .context("growth overflow")?;
        ensure!(
            c["formula_minimum_bytes"] == formula && formula <= gib * GIB,
            "growth arithmetic differs"
        );
        for side in ["before", "after"] {
            ensure!(
                r[format!("worker_{side}")]["vmas"]
                    .as_u64()
                    .is_some_and(|n| n < 800000)
                    && r[format!("worker_{side}")]["matching_workers"] == 1,
                "VMA envelope failed"
            );
        }
        let counter = &r["cross_sample"]["producer_cgroup_counter_delta"];
        for event in [
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
        ] {
            ensure!(counter[event] == 0, "live memory failure in sample");
        }
        guards.push(guard(
            label,
            *guard_floor,
            r["controller_after"]["unit"]
                .as_str()
                .context("controller name")?,
            c["controller_invocation_id"]
                .as_str()
                .context("controller IID")?,
            r["producer_after"]["unit"]
                .as_str()
                .context("producer name")?,
            c["producer_invocation_id"]
                .as_str()
                .context("producer IID")?,
        )?);
        sum = sum.checked_add(gib * GIB).context("claim sum overflow")?;
        claims.push(json!({"binding":binding,"claim":c}));
    }
    let max_guard = RANGES.iter().map(|r| r.3).max().unwrap();
    let (protected, debt) = arithmetic(sum, floor, max_guard)?;
    Ok((
        protected,
        json!({"schema":"jetstreamer-exact144-delivery-capacity-refresh-result-v1",
        "growth_claims":claims,"unchanged_guards":guards,"sum_growth_claims_bytes":sum,
        "extra_five_epoch_delivery_debt_bytes":debt,"additional_staging_margin_bytes":64*GIB,
        "century_floor_bytes":floor,"maximum_unchanged_live_guard_bytes":max_guard,
        "protected_bytes":protected,"live_guard_changed":false,"replay_admission_authorized":false}),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_delivery_debt_and_guards_both_survive_refresh() {
        let floor = 205211459014;
        let claims = 2473901162496;
        let (protected, debt) = arithmetic(claims, floor, 3984782679494).unwrap();
        assert_eq!(debt, 5 * floor);
        assert_eq!(protected, 3984782679494);
        assert!(protected >= claims + 6 * floor + 64 * GIB);
        assert_eq!(
            arithmetic(claims, floor, 0).unwrap().0,
            claims + 6 * floor + 64 * GIB
        );
        assert!(arithmetic(u64::MAX, floor, 0).is_err());
        assert!(arithmetic(0, u64::MAX, 0).is_err());
    }
    #[test]
    fn guard_bindings_are_tokens_not_substring_matches() {
        assert!(command_has(
            "cmd --minimum-free-bytes=123 ;",
            "--minimum-free-bytes=123"
        ));
        assert!(!command_has(
            "cmd --minimum-free-bytes=1234 ;",
            "--minimum-free-bytes=123"
        ));
        assert!(!command_has(
            "cmd --minimum-free-bytes=123 --minimum-free-bytes=1 ;",
            "--minimum-free-bytes=123"
        ));
    }
    #[test]
    #[ignore = "explicit root read-only retained growth/fleet and actual guard qualification; no sample, copy or import"]
    fn actual_retained_four_claim_delivery_capacity() {
        let mut v = read(&Bound {
            path:"/usr/local/lib/jetstreamer/horizon-epoch144-publication-plan-20261022-v1/plan.json".into(),
            sha256:"be4c2f5b81ad9809286d7fa0e2d2bbbbd1d043a74ce24a213e340fbb3fe2695f".into(),
        },true).unwrap();
        v["schema"] = json!("jetstreamer-exact144-v4-publication-plan-v2");
        v["observer"] = json!({"path":"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261022T135800Z.json","sha256":"b2c48ad0905cd36d695519130bcb414ecf2e5311012b7f417fe791c744b77318"});
        v["fleet"] = json!({"path":"/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-20261022T135800Z.json","sha256":"f5c74ab7525d2446b7611157d381c56cf7c4f02a7422aba2444f1733e6283dc4"});
        let hashes = [
            "eacf5e4d57577332cb4b862d9f474e7e8605bf66db38689125dcaf03a48c8bbe",
            "6e3ab1f1bf3fb33e81faa6cb1901b68a435a4a75e64601338142e7fe07d8e84c",
            "7ce35f9e6d130a3d498f628ca3c8353830977eecbdbf3dce2fd8810d70301a6d",
            "939419414ab66d0b0b286564f96ccf90dc5d4106ed0b648941822fdcd151758f",
        ];
        let claims:Vec<_> = RANGES.iter().zip(hashes).map(|(r,sha)|json!({"path":format!("/var/lib/jetstreamer/horizon-growth-claims-20261022T135800Z-delivery144-v1/growth-{}.json",r.0),"sha256":sha})).collect();
        v["refreshed_capacity"] = json!({"schema":"jetstreamer-exact144-delivery-capacity-refresh-v1","growth_claims":claims});
        let mut p: Plan = serde_json::from_value(v).unwrap();
        super::super::validate_plan(&p).unwrap();
        let o = read(&p.observer, false).unwrap();
        let f = read(&p.fleet, false).unwrap();
        let (protected, report) = qualify(&p, &o, &f, 205211459014).unwrap();
        assert_eq!(protected, 3984782679494);
        assert_eq!(report["sum_growth_claims_bytes"], 2473901162496u64);
        assert_eq!(report["live_guard_changed"], false);
        println!(
            "qualified protection={protected}; copy+1GiB requires{}bytes; actual guards unchanged",
            protected + super::super::LENGTH + super::super::MARGIN
        );
        p.refreshed_capacity
            .as_mut()
            .unwrap()
            .growth_claims
            .swap(0, 1);
        assert!(qualify(&p, &o, &f, 205211459014).is_err());
        assert!(qualify(&p, &o, &f, 205211459015).is_err());
        let mut wrong = f;
        wrong["active"][0]["epoch"] = json!(999);
        assert!(qualify(&p, &o, &wrong, 205211459014).is_err());
    }
}
