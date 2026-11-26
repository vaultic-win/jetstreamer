//! Reuse one coordinated sample for the 201–300 resident-memory target.
//! Private long-running prefix qualifications are comparable replay lanes;
//! restore/repair/delivery stages consume RSS separately. No admission authority.
#[path = "../../tools/horizon247_recovery_delivery.rs"]
mod fourth;
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon_observe::staged247_rss::{
    CURRENT261_DIRECTORY, CURRENT261_MEMORY_CAP, CURRENT261_UNIT,
    CURRENT257_DIRECTORY, CURRENT257_IMAGE, CURRENT257_IMAGE_SHA, CURRENT257_MEMORY_CAP,
    CURRENT257_START_TICKS, CURRENT257_UNIT, RETRY257_DIRECTORY, RETRY257_MEMORY_CAP, RETRY257_UNIT,
};
use jetstreamer_horizon_observe::successor247 as successor;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const PINNED_247_UNIT: &str = "horizon-upload-247-pinned-public-v254.service";
const PINNED_247_IMAGE: &str = "/var/lib/jetstreamer/horizon211-staged-recovery-v1/jetstreamer-r2";
const PINNED_247_IMAGE_SHA: &str =
    "7271de0e309c83f8fa2f35cf9091280a8b04f66c51d3175ad1d6ff02faa4c59d";
const PINNED_247_MEMORY_CAP: u64 = 24 << 30;
const STAGED_211_RETRY_UNIT: &str = "horizon-upload-211-staged-recovery-v2.service";
const STAGED_248_UNIT: &str = "horizon-upload-248-staged-public-v259.service";
const STAGED_250_UNIT: &str = "horizon-upload-250-staged-public-v257.service";
const STAGED_265_UNIT: &str = "horizon-upload-265-staged-public-v260.service";
const STAGED_250_MEMORY_CAP: u64 = 10 << 30;
const EPOCH230_BOUNDED_MISMATCH_UNIT: &str = "horizon-perf-epoch230-bounded-mismatch@v2.service";

fn registered_upload(fleet: &Value, owner: &successor::Owner) -> Result<()> {
    let belongs = |r: &&Value| {
        r["unit"]["Id"] == fourth::unit(owner) || r["expected_invocation_id"] == owner.iid
    };
    let mut entries = fleet["pipelines"]
        .as_array()
        .context("successor pipeline census")?
        .iter()
        .filter(belongs);
    let e = entries.next().context("missing successor pipeline")?;
    ensure!(
        entries.next().is_none()
            && e["epoch"] == 247
            && e["phase"] == "upload-readback"
            && e["live"] == true
            && e["sampled_at_utc"] == fleet["sampled_at_utc"]
            && e["unit"] == fleet["unit_census"][fourth::unit(owner)]
            && e["unit"]["Id"] == fourth::unit(owner)
            && e["expected_invocation_id"] == owner.iid
            && e["unit"]["InvocationID"] == owner.iid
            && e["unit"]["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u32>().ok())
                == Some(owner.pid)
            && e["evidence"] == json!([owner.proof["booking"], owner.proof["launch"]])
            && fleet["active"]
                .as_array()
                .context("active fleet census")?
                .iter()
                .filter(belongs)
                .eq(std::iter::once(e)),
        "successor claim, native census and active fleet differ"
    );
    Ok(())
}

fn recovery_history(fleet: &Value, owner: &successor::Owner) -> Result<()> {
    if !fourth::is_fourth(owner) {
        return successor::historical_claims(fleet);
    }
    let reg = &owner.proof["old_claim_evidence"];
    let mut older = fleet.clone();
    for field in ["pipelines", "active"] {
        let entries = older[field]
            .as_array_mut()
            .context("fourth 247 fleet history")?;
        let original = entries.len();
        entries.retain(|r| {
            r["unit"]["Id"] != fourth::unit(owner) || r["expected_invocation_id"] != owner.iid
        });
        ensure!(
            original == entries.len() + 1,
            "fourth 247 owner duplicated or missing"
        );
    }
    successor::historical_claims(&older)?;
    let rows = older["pipelines"]
        .as_array()
        .context("old 247 pipelines")?
        .iter()
        .filter(|r| {
            r["unit"]["Id"] == successor::UNIT || r["expected_invocation_id"] == fourth::OLD
        })
        .collect::<Vec<_>>();
    let [r] = rows.as_slice() else {
        anyhow::bail!("missing or duplicated e434 claim");
    };
    let u = &r["unit"];
    ensure!(
        r["epoch"] == 247
            && r["phase"] == "upload-readback"
            && r["live"] == false
            && r["expected_invocation_id"] == fourth::OLD
            && r["evidence"] == *reg
            && u == &older["unit_census"][successor::UNIT]
            && u["Id"] == successor::UNIT
            && fourth::predecessor_spent(u, fourth::unit(owner))
            && !older["active"]
                .as_array()
                .context("active owners")?
                .iter()
                .any(|r| r["unit"]["Id"] == successor::UNIT
                    || r["expected_invocation_id"] == fourth::OLD),
        "e434 history changed"
    );
    Ok(())
}

// Ordinary delivery workers are charged against the fleet using their sealed launch.
fn ordinary_delivery_join(row: &Value, fleet: &Value, o: &Value, name: &str) -> Result<()> {
    use jetstreamer_horizon_observe::staged247_rss::{Endpoint, validate_delivery_endpoints};
    use std::path::Path;
    let mut entries = fleet["pipelines"]
        .as_array()
        .context("delivery pipelines")?
        .iter()
        .filter(|entry| entry["unit"]["Id"] == name);
    let entry = entries
        .next()
        .context("missing ordinary delivery pipeline")?;
    let epoch = entry["epoch"].as_u64().context("delivery epoch")?;
    let stem = name
        .strip_suffix(".service")
        .context("delivery unit name")?;
    let pinned_cap = match (epoch, name) {
        (211, STAGED_211_RETRY_UNIT) => Some(10 << 30),
        (247, PINNED_247_UNIT) => Some(PINNED_247_MEMORY_CAP),
        (248, STAGED_248_UNIT) => Some(10 << 30),
        (250, STAGED_250_UNIT) => Some(STAGED_250_MEMORY_CAP),
        (257, CURRENT257_UNIT) => Some(CURRENT257_MEMORY_CAP),
        (257, RETRY257_UNIT) => Some(RETRY257_MEMORY_CAP),
        (261, CURRENT261_UNIT) => Some(CURRENT261_MEMORY_CAP),
        (265, STAGED_265_UNIT) => Some(10 << 30),
        _ => None,
    };
    ensure!(
        (pinned_cap.is_some() || name.starts_with(&format!("horizon-upload-{epoch}-ordinary-")))
            && stem.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
        "ordinary delivery epoch or unit changed"
    );
    let root = match name {
        CURRENT257_UNIT => Path::new(CURRENT257_DIRECTORY).to_owned(),
        RETRY257_UNIT => Path::new(RETRY257_DIRECTORY).to_owned(),
        CURRENT261_UNIT => Path::new(CURRENT261_DIRECTORY).to_owned(),
        _ => Path::new("/home/ubuntu/.codex/diagnostics").join(stem),
    };
    let claim = fourth::read(&row["delivery_claim"], &root.join("pipeline-claim.json"))?;
    let records = claim["evidence"].as_array().context("delivery evidence")?;
    let launch_ref = records
        .iter()
        .find(|r| r["path"].as_str() == root.join("launch.json").to_str())
        .context("ordinary delivery launch binding")?;
    let launch = fourth::read(launch_ref, &root.join("launch.json"))?;
    let unit = &entry["unit"];
    let iid = unit["InvocationID"]
        .as_str()
        .context("ordinary invocation")?;
    let pid = unit["MainPID"]
        .as_str()
        .context("ordinary PID")?
        .parse::<u32>()?;
    let (launch_unit, ticks) = match name {
        CURRENT257_UNIT => (&launch["owner"], CURRENT257_START_TICKS),
        RETRY257_UNIT | CURRENT261_UNIT => (
            &launch["owner"],
            launch["process_start_ticks"]
                .as_u64()
                .context("ordinary delivery start ticks")?,
        ),
        _ => {
            let micros = launch["unit"]["ExecMainStartTimestampMonotonic"]
                .as_str()
                .context("ordinary launch time")?
                .parse::<u64>()?;
            (&launch["unit"], micros / 10_000)
        }
    };
    // The first 257 sample used the 247 default label. Only that immutable
    // observation can use the old label; its actual owner is validated below.
    let range = if name == CURRENT257_UNIT
        && fleet["observer_sha256"]
            == "3e9646388780c95dd70b095b9b1b7d5567b9183f3ecba7900ac6cae0781808bd"
        && fleet["observer_receipt"]
            == "/home/ubuntu/.codex/diagnostics/horizon-resume-observer-20261120-v335.json"
    {
        "247-247".to_owned()
    } else {
        format!("{epoch}-{epoch}")
    };
    ensure!(
        entries.next().is_none()
            && pid > 1
            && ticks > 0
            && entry["live"] == true
            && entry["phase"] == "upload-readback"
            && entry["sampled_at_utc"] == fleet["sampled_at_utc"]
            && fleet["active"]
                .as_array()
                .context("active owners")?
                .iter()
                .filter(|e| e["unit"]["Id"] == name)
                .eq(std::iter::once(entry))
            && unit == &fleet["unit_census"][name]
            && entry["expected_invocation_id"] == iid
            && claim["unit"] == name
            && claim["invocation_id"] == iid
            && claim["epoch"] == epoch
            && claim["phase"] == "upload-readback"
            && claim["evidence"] == entry["evidence"]
            && launch_unit["Id"] == name
            && launch_unit["InvocationID"] == iid
            && launch_unit["MainPID"] == unit["MainPID"]
            && launch_unit["ExecStart"] == claim["expected_exec_start"]
            && row["sampled_unix_seconds"]
                == super::fleet::utc_seconds(
                    o["recorded_at_utc"].as_str().context("sample clock")?
                )?
            && row["publication_authorized"] == false
            && row["resource_release_authorized"] == false
            && o["delivery_resources"]
                .as_array()
                .context("delivery RSS census")?
                .iter()
                .filter(|e| e["producer_unit"] == name
                    && e["expected_producer_invocation_id"] == iid
                    && e["status"] == "observed"
                    && e["delivery_resource_only"] == true
                    && e["range"] == range
                    && &e["observation"] == row)
                .count()
                == 1,
        "ordinary delivery claim, endpoints or sample clock changed"
    );
    let (image, image_sha, cap) = if matches!(name, CURRENT257_UNIT | RETRY257_UNIT | CURRENT261_UNIT) {
        (CURRENT257_IMAGE, CURRENT257_IMAGE_SHA, pinned_cap.context("ordinary delivery memory cap")?)
    } else if let Some(cap) = pinned_cap {
        (PINNED_247_IMAGE, PINNED_247_IMAGE_SHA, cap)
    } else {
        (fourth::IMAGE, fourth::IMAGE_SHA, successor::HARD)
    };
    validate_delivery_endpoints(
        row,
        &Endpoint {
            unit: name,
            iid,
            pid,
            ticks,
            image,
            image_sha,
            cap,
        },
        &range,
    )
}

fn checked(o: &Value, ledger: &Value) -> Result<Value> {
    ensure!(
        ledger["first_epoch"] == 201
            && ledger["last_epoch"] == 300
            && ledger["sampled_at_utc"] == o["recorded_at_utc"],
        "memory target requires same-sample 201–300 fleet"
    );
    let mut owners = BTreeMap::new();
    let mut extraction = Vec::new();
    for active in ledger["active"].as_array().context("fleet active census")? {
        let unit = if active["producer"].is_object() {
            &active["producer"]
        } else {
            &active["unit"]
        };
        let name = unit["Id"].as_str().context("active unit name")?;
        let iid = unit["InvocationID"].as_str().context("active invocation")?;
        ensure!(
            unit["ActiveState"] == "active"
                && unit["SubState"] == "running"
                && unit["NRestarts"] == "0",
            "memory owner not stable/running"
        );
        if name == jetstreamer_horizon_observe::staged247_rss::UNIT {
            ensure!(
                active["epoch"] == 247
                    && active["phase"] == "upload-readback"
                    && iid == jetstreamer_horizon_observe::staged247_rss::IID,
                "foreign staged 247 fleet entry"
            );
        }
        if active["epoch"] == 247 && active["phase"] == "upload-readback" {
            ensure!(
                matches!(
                    name,
                    successor::ORIGINAL
                        | successor::PRIOR_UNIT
                        | successor::UNIT
                        | fourth::UNIT
                        | fourth::V221_UNIT
                        | PINNED_247_UNIT
                ),
                "unregistered epoch 247 uploader"
            );
        }
        let bounded_mismatch_trace = name == EPOCH230_BOUNDED_MISMATCH_UNIT;
        if bounded_mismatch_trace {
            ensure!(
                active["epoch"] == 230
                    && active["phase"] == "diagnostic-qualification"
                    && active["ordinary_replay_claim"] == false,
                "epoch 230 bounded mismatch trace has a foreign scope"
            );
        }
        let comparable = !bounded_mismatch_trace
            && !super::fleet::focused_foundation::resource_only(name)
            && matches!(
                active["phase"].as_str(),
                Some(
                    "replay"
                        | "qualification"
                        | "private-known-root-prefix"
                        | "diagnostic-qualification"
                )
            );
        if let Some(old) = owners.insert(name.to_string(), (iid.to_string(), comparable)) {
            ensure!(
                old == (iid.to_string(), comparable),
                "duplicate memory owner conflicts"
            );
        }
        if active["phase"] == "private-held-extraction" {
            ensure!(extraction.is_empty(), "duplicate epoch 226 extraction");
            extraction.extend(super::fleet::extract226::memory_rows(
                active,
                &ledger["unit_census"],
                o,
            )?);
        }
    }
    if let [_, broker] = extraction.as_slice() {
        let name = broker["producer_after"]["unit"]
            .as_str()
            .context("226 broker unit")?;
        let iid = broker["producer_after"]["invocation_id"]
            .as_str()
            .context("226 broker invocation")?;
        ensure!(
            owners
                .insert(name.to_owned(), (iid.to_owned(), false))
                .is_none(),
            "226 broker is already registered"
        );
    }
    let mut ordinary = Vec::new();
    let mut private = Vec::new();
    let mut seen = BTreeMap::new();
    let mut historical = Vec::new();
    let mut rows = o["replays"]
        .as_array()
        .context("ordinary memory census")?
        .iter()
        .collect::<Vec<_>>();
    // Delivery is a separate resource owner, not a native or finalization diagnostic.
    // It still enters the same complete fleet-to-RSS join and gets no replay credit.
    for key in ["diagnostic_replays", "delivery_resources"] {
        for diagnostic in o[key].as_array().into_iter().flatten() {
            if diagnostic["status"] == "observed" {
                rows.push(&diagnostic["observation"]);
            }
        }
    }
    rows.extend(&extraction);
    for row in rows {
        let name = row["producer_after"]["unit"]
            .as_str()
            .context("observed memory owner")?;
        if matches!(
            name,
            PINNED_247_UNIT
                | STAGED_211_RETRY_UNIT
                | STAGED_248_UNIT
                | STAGED_250_UNIT
                | CURRENT257_UNIT
                | RETRY257_UNIT
                | CURRENT261_UNIT
                | STAGED_265_UNIT
        ) || (owners.contains_key(fourth::V221_UNIT)
            && name.starts_with("horizon-upload-")
            && name.contains("-ordinary-"))
        {
            ordinary_delivery_join(row, ledger, o, name)?;
        }
        if name == jetstreamer_horizon_observe::staged247_rss::UNIT {
            let timestamp = super::fleet::utc_seconds(
                o["recorded_at_utc"]
                    .as_str()
                    .context("staged 247 sample time")?,
            )?;
            ensure!(
                row["sampled_unix_seconds"] == timestamp,
                "stale staged 247 resource sample"
            );
            let linked = o["delivery_resources"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|d| {
                    d["producer_unit"] == name
                        && d["expected_producer_invocation_id"]
                            == jetstreamer_horizon_observe::staged247_rss::IID
                        && d["status"] == "observed"
                        && d["delivery_resource_only"] == true
                        && &d["observation"] == row
                })
                .count();
            ensure!(
                linked == 1,
                "staged 247 absent or ambiguous in delivery-specific RSS"
            );
            jetstreamer_horizon_observe::staged247_rss::validate(row)?;
        }
        if matches!(name, successor::UNIT | fourth::UNIT | fourth::V221_UNIT) {
            ensure!(
                row["sampled_unix_seconds"]
                    == super::fleet::utc_seconds(
                        o["recorded_at_utc"].as_str().context("247 sample clock")?
                    )?,
                "stale successor RSS"
            );
            let owner = fourth::load(&row["successor_owner"]["claim"])?;
            ensure!(
                name == fourth::unit(&owner),
                "fourth 247 resource/claim alias"
            );
            registered_upload(ledger, &owner)?;
            ensure!(
                o["delivery_resources"]
                    .as_array()
                    .context("delivery rows")?
                    .iter()
                    .filter(|d| d["producer_unit"] == name
                        && d["expected_producer_invocation_id"] == owner.iid
                        && d["delivery_resource_only"] == true
                        && d["status"] == "observed"
                        && &d["observation"] == row)
                    .count()
                    == 1,
                "missing or duplicate successor RSS"
            );
            fourth::validate_sample(row, &owner)?;
            recovery_history(ledger, &owner)?;
        }
        if !owners.contains_key(name) && super::fleet::terminal247::historical_row(ledger, row)? {
            ensure!(
                seen.insert(name.to_string(), ()).is_none(),
                "duplicate historical memory owner"
            );
            historical.push(name.to_string());
            private.push(row.clone());
            continue;
        }
        let Some((iid, comparable)) = owners.get(name) else {
            // No silently unaccounted observed owner, including a terminal race.
            anyhow::bail!("observed owner absent from current fleet: {name}");
        };
        ensure!(
            row["producer_after"]["invocation_id"] == *iid
                && row["invocation_binding_stable"] == true,
            "observed memory owner changed"
        );
        ensure!(
            seen.insert(name.to_string(), ()).is_none(),
            "duplicate memory observation"
        );
        if *comparable {
            ensure!(
                row["useful_work"]["sufficient_for_rates"] == true,
                "comparable lane lacks settled execution evidence"
            );
            // The generic calculator's diagnostic validation is also required
            // for these promoted qualifications, even though they are replay-sized.
            for role in ["controller", "producer"] {
                let before = &row[format!("{role}_before")];
                let after = &row[format!("{role}_after")];
                ensure!(
                    before["invocation_id"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                        && before["invocation_id"] == after["invocation_id"]
                        && before["restarts"] == 0
                        && after["restarts"] == 0
                        && before["active_state"] == "active"
                        && after["active_state"] == "active"
                        && before["sub_state"] == "running"
                        && after["sub_state"] == "running",
                    "settled memory owner unstable"
                );
            }
            ordinary.push(row.clone());
        } else {
            private.push(row.clone());
        }
    }
    ensure!(
        seen.len() == owners.len() + historical.len(),
        "active fleet owner missing from coordinated RSS telemetry"
    );
    let mut normalized = o.clone();
    normalized["replays"] = json!(ordinary);
    normalized["diagnostic_replays"] = json!(private);
    let mut report = jetstreamer_horizon_observe::routine_memory_target::report_for_century(
        &normalized,
        ordinary.len(),
        private.len(),
        200,
    );
    if report["valid"] == true {
        // The generic calculator calls every diagnostic a private lane. Here
        // comparable qualifications already live in `ordinary`; `private`
        // contains only restore/delivery/finalization owners. Preserve their
        // resident charge while removing their credit toward replay throughput.
        let desired = report["desired_production_lanes"]
            .as_u64()
            .context("replay target")?;
        let non_replay = report["aggregate_private_lane_rss_bytes"]
            .as_u64()
            .context("non-replay RSS")?;
        let overhead = report["non_lane_resident_planning_bytes"]
            .as_u64()
            .context("host overhead")?;
        report["desired_lanes"] = json!(desired);
        report["executing_lanes"] = json!(ordinary.len());
        report["executing_private_lanes"] = json!(0);
        report["lane_gap"] = json!(i128::from(desired) - i128::try_from(ordinary.len())?);
        report["non_replay_owner_count"] = json!(private.len());
        report["non_replay_resident_bytes"] = json!(non_replay);
        report["host_overhead_resident_bytes"] = json!(overhead);
        report["non_lane_resident_planning_bytes"] = json!(
            overhead
                .checked_add(non_replay)
                .context("non-lane RSS overflow")?
        );
        report["aggregate_lane_rss_bytes"] = report["aggregate_production_lane_rss_bytes"].clone();
        report["aggregate_private_lane_rss_bytes"] = json!(0);
    }
    report["sampled_at_utc"] = o["recorded_at_utc"].clone();
    report["owner_census"] = json!(owners.keys().collect::<Vec<_>>());
    report["historical_non_replay_owner_census"] = json!(historical);
    report["historical_rss_released"] = json!(false);
    report["qualification_replays_in_marginal_average"] = json!(true);
    Ok(report)
}

pub(super) fn report(o: &Value, ledger: &Value) -> Value {
    checked(o, ledger).unwrap_or_else(|e| json!({"valid":false,"target_percent":90,
        "admission_authorized":false,"limiting_gate":format!("{e:#}"),
        "next_action":"Account every live replay, qualification and delivery owner in the same coordinated RSS sample; preserve all healthy work."}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires the sealed v221 receipts and offline seven-delivery fixture"]
    fn v221_seven_deliveries_are_charged_once_without_replay_credit() -> Result<()> {
        let fixture: Value =
            serde_json::from_slice(&std::fs::read(std::env::var("HORIZON_V221_FIXTURE")?)?)?;
        assert_eq!(fixture["offline_synthetic_rss"], true);
        let mut observation = fixture["observer"].clone();
        let fleet = &fixture["fleet"];
        let owner = fourth::load(&fixture["config_fields"]["successor247_claim"])?;
        assert_eq!(fourth::unit(&owner), fourth::V221_UNIT);
        assert_eq!(owner.proof["start_ticks"], 56_984_232u64);
        let rows = observation["delivery_resources"].as_array_mut().unwrap();
        let idx = rows
            .iter()
            .position(|row| row["producer_unit"] == fourth::V221_UNIT)
            .unwrap();
        rows[idx]["observation"]["successor_owner"] = owner.proof.clone();
        let result = report(&observation, fleet);
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["non_replay_owner_count"], 7);
        assert_eq!(result["non_replay_resident_bytes"], 28 * 4096);
        assert_eq!(result["executing_lanes"], 0);
        assert_eq!(result["admission_authorized"], false);
        for i in 0..7 {
            let mut missing = observation.clone();
            missing["delivery_resources"]
                .as_array_mut()
                .unwrap()
                .remove(i);
            assert_eq!(report(&missing, fleet)["valid"], false);
            let mut stale = observation.clone();
            stale["delivery_resources"][i]["observation"]["sampled_unix_seconds"] = json!(42);
            assert_eq!(report(&stale, fleet)["valid"], false);
            let mut alias = observation.clone();
            alias["delivery_resources"][i]["observation"]["producer_after"]["invocation_id"] =
                json!(owner.iid);
            if i == idx {
                alias["delivery_resources"][i]["observation"]["producer_after"]["main_pid"] =
                    json!(42);
            }
            assert_eq!(report(&alias, fleet)["valid"], false);
        }
        let old = fleet["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .position(|row| row["unit"]["Id"] == successor::UNIT)
            .unwrap();
        let mut duplicate = fleet.clone();
        duplicate["pipelines"]
            .as_array_mut()
            .unwrap()
            .push(fleet["pipelines"][old].clone());
        assert_eq!(report(&observation, &duplicate)["valid"], false);
        let mut reactivated = fleet.clone();
        reactivated["pipelines"][old]["unit"]["MainPID"] = json!("42");
        reactivated["unit_census"][successor::UNIT] = reactivated["pipelines"][old]["unit"].clone();
        assert_eq!(report(&observation, &reactivated)["valid"], false);
        Ok(())
    }

    #[test]
    #[ignore = "requires the Foundation host's original v215 and v216 fleet receipts"]
    fn delivery_only_target_from_recorded_fleet() -> Result<()> {
        use sha2::{Digest, Sha256};
        let read = |path: &str, sha: &str| -> Result<Value> {
            let bytes = std::fs::read(path)?;
            ensure!(
                format!("{:x}", Sha256::digest(&bytes)) == sha,
                "receipt digest"
            );
            Ok(serde_json::from_slice(&bytes)?)
        };
        for (version, digest) in [
            (
                215,
                "636289e37c207c03aa1961d7500d58842a120e2c2f360374edaea4c5ff0947b9",
            ),
            (
                216,
                "32a4140f1aa544df487dcca707ffd5e6813eb10747049401898f77e12d98923d",
            ),
        ] {
            let path = format!(
                "/home/ubuntu/.codex/diagnostics/horizon-fleet-takeover-v{version}-20261120-v1/fleet-v1.json"
            );
            let fleet = read(&path, digest)?;
            let observer = read(
                fleet["observer_receipt"].as_str().unwrap(),
                fleet["observer_sha256"].as_str().unwrap(),
            )?;
            let result = report(&observer, &fleet);
            if version == 216 {
                // 265 exited between the observation and fleet construction.
                assert_eq!(result, fleet["memory_target"]);
                assert!(
                    result["limiting_gate"]
                        .as_str()
                        .unwrap()
                        .contains("horizon-upload-265-ordinary-v215.service")
                );
                continue;
            }
            assert_eq!(result["valid"], true, "{result}");
            assert_eq!(result["executing_lanes"], 0);
            assert_eq!(result["non_replay_owner_count"], 3);
            assert!(result["non_replay_resident_bytes"].as_u64().unwrap() > 0);
            assert_eq!(
                result["non_lane_resident_planning_bytes"],
                result["host_resident_planning_bytes"]
            );
            assert_eq!(result["marginal_lane_rss_bytes"], 149186228224u64);
            assert_eq!(result["admission_authorized"], false);
            println!("Recorded v{version} memory target: {result}");
        }
        Ok(())
    }

    #[test]
    fn two_actual_claims_survive_the_direct_bounded_reader_transition() -> Result<()> {
        let f: Value = serde_json::from_str(include_str!(
            "../../jetstreamer-horizon-observe/src/fixtures/successor247-history.json"
        ))?;
        assert_eq!(
            f["original_failure"]["INVOCATION_ID"],
            successor::ORIGINAL_IID
        );
        assert_eq!(f["prior_claim"]["invocation_id"], successor::PRIOR_IID);
        let mut fleet = json!({"pipelines":f["historical_fleet_rows"],"active":f["historical_active"],"unit_census":{}});
        let mut units = json!({});
        for r in fleet["pipelines"].as_array().unwrap() {
            units[r["unit"]["Id"].as_str().unwrap()] = r["unit"].clone();
        }
        fleet["unit_census"] = units;
        assert!(successor::validate_history(&fleet, &f["previous"]).is_err());
        // Original v147 was still live. Exercise a modeled exit, preserving every original claim.
        let mut ended = fleet["unit_census"][successor::PRIOR_UNIT].clone();
        for (key, value) in [
            ("ActiveState", "failed"),
            ("SubState", "failed"),
            ("MainPID", "0"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("ControlGroup", ""),
        ] {
            ended[key] = json!(value);
        }
        let idx = fleet["pipelines"]
            .as_array()
            .unwrap()
            .iter()
            .position(|r| r["unit"]["Id"] == successor::PRIOR_UNIT)
            .unwrap();
        fleet["unit_census"][successor::PRIOR_UNIT] = ended.clone();
        fleet["pipelines"][idx]["unit"] = ended;
        fleet["pipelines"][idx]["live"] = json!(false);
        fleet["active"] = json!([]);
        successor::validate_history(&fleet, &f["previous"])?;
        let prospective = successor::Owner {
            iid: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            pid: 12345,
            argv: Value::Null,
            command: String::new(),
            proof: json!({"booking":{"path":"future/booking","sha256":"a".repeat(64)},
            "launch":{"path":"future/launch","sha256":"b".repeat(64)}}),
        };
        let mut projected = fleet.clone();
        projected["sampled_at_utc"] = f["observed_fleet_time"].clone();
        let manager = json!({"Id":successor::UNIT,"InvocationID":prospective.iid,"MainPID":prospective.pid.to_string()});
        let entry = json!({"epoch":247,"phase":"upload-readback","unit":manager,"live":true,
            "expected_invocation_id":prospective.iid,"sampled_at_utc":projected["sampled_at_utc"],
            "evidence":[prospective.proof["booking"],prospective.proof["launch"]]});
        projected["unit_census"][successor::UNIT] = manager;
        projected["active"] = json!([entry]);
        projected["pipelines"]
            .as_array_mut()
            .unwrap()
            .push(entry.clone());
        registered_upload(&projected, &prospective)?;
        successor::validate_history(&projected, &f["previous"])?;
        let mut different_pid = projected.clone();
        different_pid["unit_census"][successor::UNIT]["MainPID"] = json!("42");
        assert!(registered_upload(&different_pid, &prospective).is_err());
        let mut duplicate = projected;
        duplicate["active"].as_array_mut().unwrap().push(entry);
        assert!(registered_upload(&duplicate, &prospective).is_err());
        let mut foreign = fleet.clone();
        foreign["pipelines"][idx]["evidence"][0]["sha256"] = json!("f".repeat(64));
        assert!(successor::validate_history(&foreign, &f["previous"]).is_err());
        let mut dup = fleet.clone();
        dup["pipelines"]
            .as_array_mut()
            .unwrap()
            .push(fleet["pipelines"][idx].clone());
        assert!(successor::validate_history(&dup, &f["previous"]).is_err());
        let mut never_launched = fleet.clone();
        let mut phantom = fleet["pipelines"][idx].clone();
        phantom["unit"]["Id"] = json!("horizon-upload-247-staged-99f30641-v1.service");
        phantom["expected_invocation_id"] = json!("b".repeat(32));
        never_launched["pipelines"]
            .as_array_mut()
            .unwrap()
            .push(phantom);
        assert!(successor::validate_history(&never_launched, &f["previous"]).is_err());
        let mut missing = fleet.clone();
        missing["pipelines"].as_array_mut().unwrap().remove(idx);
        assert!(successor::validate_history(&missing, &f["previous"]).is_err());
        Ok(())
    }
    #[test]
    #[ignore = "booked offline qualification with original v145 receipts and independent targeted staged RSS"]
    fn staged247_v145_memory_join_and_historical_failure() {
        use std::path::PathBuf;
        let dir = PathBuf::from(std::env::var_os("STAGED247_RSS_FIXTURES").unwrap());
        let read = |n: &str| -> Value {
            serde_json::from_slice(&std::fs::read(dir.join(n)).unwrap()).unwrap()
        };
        let fleet = read("v145-fleet.json");
        let original = read("v145-observer.json");
        assert_eq!(report(&original, &fleet)["valid"], false);
        assert_eq!(
            fleet["memory_target"]["limiting_gate"],
            "active fleet owner missing from coordinated RSS telemetry"
        );
        let mut row = read("staged-owner.json");
        let owner = &mut row["observation"];
        // Project only the registered process identities onto the two native v145
        // host censuses for this offline test. The sealed v145 report stays invalid.
        for suffix in ["before", "after"] {
            let host = original["host_resident_memory"][suffix]["rss"]["processes"]
                .as_array()
                .unwrap();
            let mut rss = owner[format!("producer_{suffix}")]["rss"].clone();
            let mut sum = 0;
            for process in rss["processes"].as_array_mut().unwrap() {
                let matches: Vec<_> = host
                    .iter()
                    .filter(|p| {
                        p["pid"] == process["pid"] && p["start_ticks"] == process["start_ticks"]
                    })
                    .collect();
                assert_eq!(matches.len(), 1);
                *process = matches[0].clone();
                sum += process["rss_bytes"].as_u64().unwrap();
            }
            rss["aggregate_rss_bytes"] = json!(sum);
            for role in ["controller", "producer"] {
                owner[format!("{role}_{suffix}")]["rss"] = rss.clone();
            }
        }
        owner["sampled_unix_seconds"] = json!(
            super::super::fleet::utc_seconds(original["recorded_at_utc"].as_str().unwrap())
                .unwrap()
        );
        let mut joined = original.clone();
        joined["delivery_resources"] = json!([row]);
        let v = report(&joined, &fleet);
        assert_eq!(v["valid"], true, "{v}");
        assert_eq!(v["executing_lanes"], 3);
        assert_eq!(v["non_replay_owner_count"], 1);
        assert_eq!(
            v["non_replay_resident_bytes"],
            joined["delivery_resources"][0]["observation"]["producer_after"]["rss"]["aggregate_rss_bytes"]
        );
        assert_eq!(v["admission_authorized"], false);
        println!("V145_OFFLINE_JOIN={v}");
        for pointer in [
            "/observation/sampled_unix_seconds",
            "/expected_producer_invocation_id",
            "/observation/staged_owner/launch/sha256",
            "/observation/mapped_image_after/sha256",
            "/observation/producer_after/invocation_id",
            "/observation/producer_after/rss/census_stable",
            "/observation/producer_after/cgroup/gauges/memory.max",
            "/observation/ordinary_replay_claim",
        ] {
            let mut altered = joined.clone();
            *altered["delivery_resources"][0]
                .pointer_mut(pointer)
                .unwrap() = Value::Null;
            assert_eq!(report(&altered, &fleet)["valid"], false, "{pointer}");
        }
        assert_eq!(original["delivery_resources"][0]["status"], "unavailable");
    }
    #[test]
    fn proven_terminal_transition_retains_historical_rss_and_raw_sample() {
        let (mut o, mut ledger) = fixture();
        let unit = super::super::fleet::terminal247::UNIT;
        let iid = super::super::fleet::terminal247::IID;
        super::super::fleet::terminal247::test_historical_ledger(&mut ledger);
        o["recorded_at_utc"] = ledger["sampled_at_utc"].clone();
        for role in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            o["diagnostic_replays"][0]["observation"][role]["unit"] = json!(unit);
            o["diagnostic_replays"][0]["observation"][role]["invocation_id"] = json!(iid);
        }
        o["diagnostic_replays"][0]["observation"]["range"] = json!("247-247");
        o["diagnostic_replays"][0]["observation"]["post_replay_finalization"] = json!(true);
        o["diagnostic_replays"][0]["observation"]["resource_only"] = json!(true);
        ledger["active"].as_array_mut().unwrap().remove(0);
        let original = o.clone();
        let r = report(&o, &ledger);
        assert_eq!(r["valid"], true, "{r}");
        assert_eq!(r["executing_lanes"], 2);
        assert_eq!(r["non_replay_resident_bytes"], 142_216_388_608_u64);
        assert_eq!(r["historical_non_replay_owner_census"], json!([unit]));
        assert_eq!(r["owner_census"].as_array().unwrap().len(), 2);
        assert_eq!(r["admission_authorized"], false);
        assert_eq!(o, original);
        for key in [
            "observer_sha256",
            "sampled_at_utc",
            "terminal247_conservative_rss",
        ] {
            let mut bad = ledger.clone();
            bad[key] = Value::Null;
            assert_eq!(report(&o, &bad)["valid"], false);
        }
        let mut bad = ledger.clone();
        bad["unit_census"][unit]["InvocationID"] = json!("replacement");
        assert_eq!(report(&o, &bad)["valid"], false);
        let mut duplicate = o.clone();
        let row = duplicate["diagnostic_replays"][0].clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(row);
        assert_eq!(report(&duplicate, &ledger)["valid"], false);
    }
    fn fixture() -> (Value, Value) {
        let mut observations = Vec::new();
        let mut active = Vec::new();
        let mut host_processes = Vec::new();
        for (pid, rss, phase) in [
            (1u64, 142_216_388_608u64, "diagnostic-qualification"),
            (2, 133_364_101_120, "private-known-root-prefix"),
            (3, 128_705_048_576, "private-known-root-prefix"),
        ] {
            let name = format!("replay-{pid}.service");
            let iid = format!("{pid:032x}");
            let process = json!({"pid":pid,"start_ticks":10,"rss_bytes":rss});
            host_processes.push(process.clone());
            let role = json!({"unit":name,"invocation_id":iid,"restarts":0,"active_state":"active","sub_state":"running",
                "rss":{"census_stable":true,"aggregate_rss_bytes":rss,"error":null,"processes":[process]}});
            let row = json!({"invocation_binding_stable":true,"producer_before":role,"controller_before":role,
                "producer_after":role,"controller_after":role,"useful_work":{"sufficient_for_rates":true}});
            observations.push(json!({"status":"observed","observation":row}));
            active.push(json!({"phase":phase,"producer":{"Id":name,"InvocationID":iid,"NRestarts":"0","ActiveState":"active","SubState":"running"}}));
        }
        let lane_sum = 142_216_388_608u64 + 133_364_101_120 + 128_705_048_576;
        let host_sum = 407_235_731_456u64;
        host_processes.push(json!({"pid":4,"start_ticks":20,"rss_bytes":host_sum-lane_sum}));
        let o = json!({"recorded_at_utc":"2026-10-23T16:43:44Z","replays":[],"diagnostic_replays":observations,
            "host_memory":{"total_kib":1_183_727_512u64},
            "host_resident_memory":{"after":{"status":"observed","rss":{"census_stable":true,"error":null,"aggregate_rss_bytes":host_sum,"processes":host_processes},
                "kernel_components_bytes":{"Slab":27_448_233_984u64,"PageTables":1_434_058_752u64,"Percpu":426_770_432,"KernelStack":36_012_032}}},
            "lane_rss_history":{"200":{"maximum_observed_lane_rss_bytes":151_000_739_840u64,"reservation_ceiling_bytes":226_501_109_760u64}}});
        let ledger = json!({"first_epoch":201,"last_epoch":300,"sampled_at_utc":o["recorded_at_utc"],"active":active});
        (o, ledger)
    }
    #[test]
    fn extraction_charges_both_same_sample_owners_without_replay_credit() {
        let (mut observer, mut ledger) = fixture();
        let node = "horizon-qualify-226-checkpoint-continuation-extract-v1.service";
        let broker = "foundation-226-original225-broker-v1.service";
        let mut owners = serde_json::Map::new();
        let mut units = serde_json::Map::new();
        let host = &mut observer["host_resident_memory"]["after"]["rss"];
        let rss = 10_000;
        for (role, name, pid) in [("producer", node, 5), ("broker", broker, 6)] {
            let iid = format!("{pid:032x}");
            let group = format!("/system.slice/{name}");
            owners.insert(
                role.to_owned(),
                json!({"unit":name,"invocation_id":iid,"pid":pid,
                "cgroup":group,"start_ticks":20,"single_process_cgroup":true}),
            );
            units.insert(
                name.to_owned(),
                json!({"Id":name,"InvocationID":iid,
                "ControlGroup":group,"MainPID":pid.to_string(),"ActiveState":"active",
                "SubState":"running","NRestarts":"0"}),
            );
            host["processes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"pid":pid,"start_ticks":20,"rss_bytes":rss}));
        }
        host["aggregate_rss_bytes"] =
            json!(host["aggregate_rss_bytes"].as_u64().unwrap() + 2 * rss);
        observer["host_resident_memory"]["before"] =
            observer["host_resident_memory"]["after"].clone();
        ledger["unit_census"] = Value::Object(units);
        let active = json!({
            "epoch":226,"phase":"private-held-extraction","ordinary_replay_claim":false,
            "sampled_at_utc":observer["recorded_at_utc"],"producer":ledger["unit_census"][node],
            "capacity_owners":owners,
        });
        ledger["active"].as_array_mut().unwrap().push(active);
        let result = report(&observer, &ledger);
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["executing_lanes"], 3);
        assert_eq!(result["non_replay_owner_count"], 2);
        assert_eq!(result["non_replay_resident_bytes"], 2 * rss);
        for key in ["producer", "broker"] {
            let mut changed = ledger.clone();
            changed["active"][3]["capacity_owners"][key]["start_ticks"] = json!(21);
            assert_eq!(report(&observer, &changed)["valid"], false);
            changed = ledger.clone();
            changed["active"][3]["capacity_owners"][key]["single_process_cgroup"] = json!(false);
            assert_eq!(report(&observer, &changed)["valid"], false);
        }
        ledger["unit_census"][broker]["InvocationID"] = json!("f".repeat(32));
        assert_eq!(report(&observer, &ledger)["valid"], false);
    }

    #[test]
    fn settled_qualifications_have_own_century_target_and_deduplicate_cohort_owners() {
        let (o, mut ledger) = fixture();
        let first = ledger["active"][0].clone();
        ledger["active"].as_array_mut().unwrap().push(first);
        let r = report(&o, &ledger);
        assert_eq!(r["valid"], true, "{r}");
        assert_eq!(r["desired_lanes"], 8);
        assert_eq!(r["executing_lanes"], 3);
        assert_eq!(r["reservation_ceiling_bytes"], 226_501_109_760u64);
        assert_eq!(r["admission_authorized"], false);
        let mut bad = o.clone();
        bad["diagnostic_replays"][0]["observation"]["producer_before"]["restarts"] = json!(1);
        assert_eq!(report(&bad, &ledger)["valid"], false);
        let mut bad = o.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().pop();
        assert_eq!(report(&bad, &ledger)["valid"], false);
    }
    #[test]
    fn missing_new_repair_owner_never_reuses_old_fleet_capacity() {
        let o =
            json!({"recorded_at_utc":"2026-10-23T16:43:44Z","replays":[],"diagnostic_replays":[]});
        let ledger = json!({"first_epoch":201,"last_epoch":300,"sampled_at_utc":o["recorded_at_utc"],
            "active":[{"phase":"private-cold-snapshot-verification","unit":{"Id":"repair.service","InvocationID":"a","ActiveState":"active","SubState":"running","NRestarts":"0"}}]});
        let result = report(&o, &ledger);
        assert_eq!(result["valid"], false);
        assert!(
            result["limiting_gate"]
                .as_str()
                .unwrap()
                .contains("missing from coordinated RSS")
        );
    }
    #[test]
    fn bounded_vote_trace_charges_rss_without_changing_the_marginal_replay_cost() {
        let (mut observer, mut ledger) = fixture();
        for role in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            observer["diagnostic_replays"][0]["observation"][role]["unit"] =
                json!(EPOCH230_BOUNDED_MISMATCH_UNIT);
        }
        ledger["active"][0]["producer"]["Id"] = json!(EPOCH230_BOUNDED_MISMATCH_UNIT);
        ledger["active"][0]["epoch"] = json!(230);
        ledger["active"][0]["ordinary_replay_claim"] = json!(false);
        let result = report(&observer, &ledger);
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["executing_production_lanes"], 2);
        assert_eq!(result["non_replay_owner_count"], 1);
        assert_eq!(result["non_replay_resident_bytes"], 142_216_388_608u64);
        assert_eq!(result["marginal_lane_rss_bytes"], 131_034_574_848u64);
        ledger["active"][0]["ordinary_replay_claim"] = json!(true);
        assert_eq!(report(&observer, &ledger)["valid"], false);
    }
    #[test]
    fn finalization_owner_retains_rss_without_counting_as_replay() {
        let (mut o, mut ledger) = fixture();
        o["diagnostic_replays"][0]["post_replay_resource_only"] = json!(true);
        o["diagnostic_replays"][0]["observation"]["useful_work"]["sufficient_for_rates"] =
            json!(false);
        let finalization = o["diagnostic_replays"][0].clone();
        ledger["active"][0]["phase"] = json!("producer-finalization");
        let report = report(&o, &ledger);
        assert_eq!(report["valid"], true, "{report}");
        assert_eq!(report["executing_lanes"], 2);
        assert_eq!(report["non_replay_owner_count"], 1);
        assert_eq!(report["non_replay_resident_bytes"], 142_216_388_608u64);
        assert_eq!(report["desired_lanes"], report["desired_production_lanes"]);
        assert_eq!(
            report["aggregate_lane_rss_bytes"].as_u64().unwrap()
                + report["non_lane_resident_planning_bytes"].as_u64().unwrap(),
            report["host_resident_planning_bytes"].as_u64().unwrap()
        );
        assert_eq!(report["owner_census"].as_array().unwrap().len(), 3);
        let mut bad = o.clone();
        bad["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        assert_eq!(super::report(&bad, &ledger)["valid"], false);
        let mut duplicate = o.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(finalization);
        assert_eq!(super::report(&duplicate, &ledger)["valid"], false);
        let mut unavailable = o.clone();
        unavailable["diagnostic_replays"][0]["status"] = json!("unavailable");
        unavailable["diagnostic_replays"][0]["observation"] = Value::Null;
        assert_eq!(super::report(&unavailable, &ledger)["valid"], false);
        ledger["active"][0]["phase"] = json!("replay");
        assert_eq!(super::report(&o, &ledger)["valid"], false);
    }
    #[test]
    fn pinned_247_requires_its_own_delivery_pipeline() {
        let (mut observer, mut ledger) = fixture();
        let mut delivery = observer["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .remove(0);
        let mut owner = ledger["active"][0]
            .as_object_mut()
            .unwrap()
            .remove("producer")
            .unwrap();
        owner["Id"] = json!(PINNED_247_UNIT);
        ledger["active"][0]["unit"] = owner;
        ledger["active"][0]["epoch"] = json!(247);
        ledger["active"][0]["phase"] = json!("upload-readback");
        delivery["observation"]["producer_after"]["unit"] = json!(PINNED_247_UNIT);
        observer["delivery_resources"] = json!([delivery]);
        ledger["pipelines"] = json!([]);
        let failure = checked(&observer, &ledger).unwrap_err();
        assert_eq!(failure.to_string(), "missing ordinary delivery pipeline");
    }

    #[test]
    fn same_sample_delivery_rss_is_required_and_never_replay_credit() {
        let (mut o, mut ledger) = fixture();
        let unit = "horizon-upload-247-singleton-20261119-v1.service";
        let iid = "69218e2e0924497ea595a1227a6c31db";
        let mut delivery = o["diagnostic_replays"][0].clone();
        for role in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            delivery["observation"][role]["unit"] = json!(unit);
            delivery["observation"][role]["invocation_id"] = json!(iid);
        }
        delivery["delivery_resource_only"] = json!(true);
        delivery["observation"]["resource_only"] = json!(true);
        delivery["observation"]["useful_work"]["sufficient_for_rates"] = json!(false);
        o["diagnostic_replays"].as_array_mut().unwrap().remove(0);
        o["delivery_resources"] = json!([delivery]);
        ledger["active"][0]["phase"] = json!("upload-readback");
        // Match the actual pipeline shape while retaining both replay owners.
        let mut owner = ledger["active"][0]
            .as_object_mut()
            .unwrap()
            .remove("producer")
            .unwrap();
        owner["Id"] = json!(unit);
        owner["InvocationID"] = json!(iid);
        ledger["active"][0]["unit"] = owner;
        let result = report(&o, &ledger);
        assert_eq!(result["valid"], true, "{result}");
        assert_eq!(result["executing_lanes"], 2);
        assert_eq!(result["non_replay_owner_count"], 1);
        assert_eq!(result["non_replay_resident_bytes"], 142_216_388_608u64);
        for mode in 0..4 {
            let mut bad = o.clone();
            match mode {
                0 => bad["delivery_resources"] = json!([]),
                1 => bad["delivery_resources"]
                    .as_array_mut()
                    .unwrap()
                    .push(delivery.clone()),
                2 => bad["delivery_resources"][0]["status"] = json!("unavailable"),
                _ => {
                    bad["delivery_resources"][0]["observation"]["producer_after"]["invocation_id"] =
                        json!("wrong")
                }
            }
            assert_eq!(report(&bad, &ledger)["valid"], false, "{mode}");
        }
        ledger["active"][0]["phase"] = json!("replay");
        assert_eq!(report(&o, &ledger)["valid"], false);
    }
}
