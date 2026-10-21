//! Exact198 replay -> authenticated active producer-finalization handoff.
//! No replay launch, archive mutation, retirement, or new resource observation.
use super::*;

const UNIT: &str = "jetstreamer-root-sweep-e198-readerfix-20261019-v1-r2-e198-198-lane-a-1.service";
const INVOCATION: &str = "e5612ef00a5b4fcab04df2c13a6b35b0";
const CONTROLLER: &str = "d64e3dccb7a54c8a9dc8160a5ca89e39";
const WRITER: &str = prefix144::DELIVERY_WRITER;
const WRITER_SHA: &str = prefix144::DELIVERY_WRITER_SHA;
const PUBLISHER: &str = "/usr/local/lib/jetstreamer/horizon-epoch198-pipeline-receipts-candidate-20261021-v1/jetstreamer-r2";
const PUBLISHER_SHA: &str = "c047afcd2d7a282bf394e29625aea1da7ca136d4aca7461e7ae2aaf54234e4c4";
const STATUS: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
const ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/private/destination-bfa4ff91eb1803c6a2d6240f014cc6508bb805e8bddd619ff64ab57cde1c5ed9/work/root-cohort-198-198/run-1165606-1792451794035486537/archives/epoch-198.jet";
pub(super) const HANDOFF_WRITER: &str = WRITER;
pub(super) const HANDOFF_WRITER_SHA: &str = WRITER_SHA;
const IMPORT_CONTROLLER: &str = "jetstreamer-epoch198-readerfix-singleton-20261019-v1-r2.service";
const SOURCE_ARCHIVE: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/output/epoch-198.jet";
const IMPORTER: &str = "jetstreamer-root-import-e198-readerfix-20261019-v1-r2-e198-198-2.service";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    proof: Bound,
    origin_publication: Bound,
    origin_observer: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    controller_recovery: Option<Bound>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    controller_handoff: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor_proof: Option<Bound>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    delayed_recovery: bool,
}

pub(super) fn pending(p: &Plan) -> bool {
    p.epoch198_delivery
        .as_ref()
        .is_some_and(|p| p.controller_handoff)
}

fn stage(
    profile: &Profile,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if profile.controller_handoff {
        (
            "controller-import-handoff",
            "publication",
            IMPORT_CONTROLLER,
            controller_recovery::CONTROLLER198,
            SOURCE_ARCHIVE,
        )
    } else {
        (
            "producer-finalization",
            "finalization",
            UNIT,
            INVOCATION,
            ARCHIVE,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffSpec {
    schema: String,
    proof: Bound,
    replay_launch_authorized: bool,
    archive_publication_authorized: bool,
    r2_archive_mutations: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sample_target_utc: Option<String>,
}
pub(super) fn recovery_interval(p: &Plan) -> Result<Option<u64>> {
    if !p
        .epoch198_delivery
        .as_ref()
        .is_some_and(|v| v.delayed_recovery)
    {
        return Ok(None);
    }
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-21T20:18:00Z"
            && p.previous_observer.sha256
                == "2eeb72a1f51220db978745c846c7b3bd9e2695a5bdb58c9969bfd0fe7fee5773"
            && p.previous_observer.path
                == Path::new(
                    "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261021T193800Z.json"
                ),
        "198 delayed recovery has foreign predecessor/target"
    );
    Ok(Some(2400))
}
pub(super) fn consume_recovery(p: &mut Plan) -> Result<()> {
    if p.epoch198_delivery
        .as_ref()
        .is_some_and(|v| v.delayed_recovery)
    {
        ensure!(
            p.sample_target_utc == "2026-10-21T20:48:00Z"
                && p.previous_observer
                    .path
                    .ends_with("sample-20261021T201800Z.json"),
            "198 delayed recovery successor differs"
        );
        p.epoch198_delivery.as_mut().unwrap().delayed_recovery = false;
    }
    Ok(())
}
pub(super) fn retime(next: &mut Plan, config: &mut Value, spec: &Bound) -> Result<()> {
    let spec: HandoffSpec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    let Some(target) = spec.sample_target_utc else {
        return Ok(());
    };
    ensure!(
        next.sample_target_utc == "2026-10-21T20:08:00Z"
            && target == "2026-10-21T20:18:00Z"
            && next.previous_observer.sha256
                == "2eeb72a1f51220db978745c846c7b3bd9e2695a5bdb58c9969bfd0fe7fee5773",
        "198 retime is not exact missed20:08 recovery"
    );
    let old = stamp(&next.sample_target_utc);
    let new = stamp(&target);
    for path in [
        &mut next.observer,
        &mut next.estimate_output,
        &mut next.fleet_output,
    ] {
        *path = PathBuf::from(
            path.to_str()
                .context("198 recovery path")?
                .replace(&old, &new),
        );
    }
    next.sample_target_utc = target;
    config["not_before_utc"] = json!(next.sample_target_utc);
    config["output"] = json!(next.observer);
    Ok(())
}

fn original_range(model: &Value) -> Result<Option<&Value>> {
    let ranges = model["ranges"]
        .as_array()
        .context("198 model ranges missing")?;
    let found: Vec<_> = ranges.iter().filter(|r| r["range"] == "198").collect();
    ensure!(
        ranges.iter().all(|r| !r["epochs"]
            .as_array()
            .is_some_and(|a| a.contains(&json!(198)))
            || r["range"] == "198"),
        "198 is not an independently publishable singleton"
    );
    ensure!(found.len() <= 1, "duplicate198 modeled range");
    Ok(found.first().copied())
}

fn profile_controller(profile: &Profile) -> Result<&'static str> {
    match &profile.controller_recovery {
        Some(binding) => controller_recovery::epoch198_controller(binding),
        None => Ok(CONTROLLER),
    }
}

fn validate_range(r: &Value, controller: &str) -> Result<()> {
    ensure!(
        matches!(controller, CONTROLLER | controller_recovery::CONTROLLER198)
            && r["epochs"] == json!([198])
            && r["expected_producer_invocation_id"] == INVOCATION
            && r["expected_controller_invocation_id"] == controller
            && r["terminal_slot"] == 85_967_999u64
            && r["epoch_additional_replay_slots"] == json!({"198":0})
            && r["epoch_downstream_allowance_seconds"] == json!({"198":43200})
            && r["archive_directory"].as_str()
                == Path::new(ARCHIVE).parent().and_then(Path::to_str)
            && r.get("elapsed_execution_millis").is_none(),
        "198 predecessor is not exact qualified singleton"
    );
    Ok(())
}

fn validate_proof(proof: &Value, target: u64, initial: bool) -> Result<()> {
    let handoff = proof["phase"] == "controller-import-handoff";
    ensure!(
        proof["schema"]
            == if handoff {
                "jetstreamer-epoch198-controller-handoff-observation-v1"
            } else {
                "jetstreamer-epoch198-delivery-observation-v1"
            }
            && proof["observer_sha256"]
                == if handoff {
                    HANDOFF_WRITER_SHA
                } else {
                    WRITER_SHA
                }
            && proof["epoch"] == 198
            && (handoff || proof["phase"] == "producer-finalization")
            && proof["before"] == proof["after"],
        "unqualified198 finalization proof"
    );
    for flag in [
        "resource_sample_taken",
        "cadence_consumed",
        "status_publication_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(proof[flag] == false, "198 proof grants authority: {flag}");
    }
    let before = &proof["before"];
    for (key, value) in [
        ("Id", if handoff { IMPORT_CONTROLLER } else { UNIT }),
        (
            "InvocationID",
            if handoff {
                controller_recovery::CONTROLLER198
            } else {
                INVOCATION
            },
        ),
        ("MainPID", if handoff { "2939002" } else { "1165606" }),
        ("NRestarts", "0"),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
    ] {
        ensure!(before[key] == value, "198 proof owner differs: {key}");
    }
    ensure!(
        before["ExecStart"].as_str().is_some_and(|s| !s.is_empty()),
        "198 proof command missing"
    );
    let observed = proof["observed_unix_seconds"]
        .as_u64()
        .context("198 proof time missing")?;
    let completed = proof["completed_unix_seconds"]
        .as_u64()
        .context("198 proof completion missing")?;
    ensure!(
        observed > 0
            && observed <= completed
            && completed < target
            && (!initial || target - observed <= 1800),
        "198 proof is future or stale for initial handoff"
    );
    let evidence = &proof["terminal_evidence"];
    ensure!(
        evidence["schema"]
            == if handoff {
                "jetstreamer-epoch198-controller-import-handoff-v1"
            } else {
                "jetstreamer-epoch198-finalization-events-v1"
            }
            && evidence["unit"] == UNIT
            && evidence["invocation_id"] == INVOCATION
            && evidence["terminal_slot"] == 85_967_999u64
            && evidence["trusted_root_slot"] == 85_967_282u64
            && evidence["node_sha256"]
                == "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887"
            && evidence["manifest_sha256"]
                == "f1d0ff0521379a4c1dcd5461dca144d5d2484b3fc2d09f1f613c5ddd0a6c4d7e"
            && evidence["replay_terminal_observed"] == true
            && evidence["archive_close_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "198 terminal proof differs"
    );
    for flag in [
        "independent_full_verification_passed",
        "publication_authorized",
        "replay_launch_authorized",
        "r2_mutations",
    ] {
        ensure!(
            evidence[flag] == false,
            "198 terminal log grants integrity authority"
        );
    }
    if handoff {
        validate_pending_evidence(evidence)?;
    }
    let events = evidence["events"]
        .as_array()
        .context("198 terminal events missing")?;
    ensure!(events.len() == 4, "198 terminal event count differs");
    let mut last = 0;
    for event in events {
        let time = event["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("198 event time missing")?
            .parse::<u64>()?;
        ensure!(
            time > last
                && time
                    <= observed
                        .checked_mul(1_000_000)
                        .context("198 proof time overflow")?
                && event["_SYSTEMD_UNIT"] == UNIT
                && event["_SYSTEMD_INVOCATION_ID"] == INVOCATION
                && event["_PID"] == "1165606"
                && event["_UID"] == "1001",
            "198 event time/owner differs"
        );
        last = time;
    }
    Ok(())
}

fn validate_pending_evidence(e: &Value) -> Result<()> {
    let producer = &e["producer"];
    let collected = producer["LoadState"] == "not-found";
    if collected {
        let manager = &e["producer_terminal_manager"];
        let time = manager["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("198 manager time")?
            .parse::<u64>()?;
        let close = e["events"][3]["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("198 close time")?
            .parse::<u64>()?;
        ensure!(
            manager["UNIT"] == UNIT
                && manager["INVOCATION_ID"] == INVOCATION
                && manager["_PID"] == "1"
                && manager["_UID"] == "0"
                && manager["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && manager["MESSAGE"] == format!("{UNIT}: Deactivated successfully.")
                && close < time,
            "198 collected producer lacks exact PID1 success"
        );
    }
    for (key, value) in [
        ("Id", UNIT),
        ("InvocationID", if collected { "" } else { INVOCATION }),
        ("LoadState", if collected { "not-found" } else { "loaded" }),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
    ] {
        ensure!(
            producer[key] == value,
            "198handoff clean producer differs: {key}"
        );
    }
    ensure!(
        (producer["ActiveState"] == "inactive" && producer["SubState"] == "dead")
            || (producer["ActiveState"] == "active" && producer["SubState"] == "exited"),
        "198handoff producer not terminal"
    );
    let state = &e["controller_state"];
    let a = &state["assignments"]["lane-a"];
    let actual_import = !e["importer"].is_null();
    if actual_import {
        let importer = &e["importer"];
        for (key, value) in [
            ("Id", IMPORTER),
            ("InvocationID", "526647ab03104a1fb8f14303819d6cda"),
            ("MainPID", "3182197"),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NRestarts", "0"),
        ] {
            ensure!(
                importer[key] == value,
                "198 actual importer proof differs:{key}"
            );
        }
        ensure!(
            importer["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(" --recover-staged-cohort-only ")
                    && s.contains(" --publish-through-epoch=198 ;"))
                && e["source_receipt_sha256"]
                    == "a1734902c86c333be889f3da731da662308b542fa2c72e2e63da566f941cd226",
            "198 actual importer lacks committed source"
        );
    }
    ensure!(
        state["schema"] == "jetstreamer-adaptive-root-cohort-sweep-v3"
            && state["configuration_sha256"]
                == "0929b892242b85f08cbe3d5828b6f4650c81c4730e5fd81f8dfe3e38f096aadd"
            && (if actual_import {
                state["import_owner"] == "lane-a"
            } else {
                state["import_owner"].is_null()
            })
            && state["assignments"]
                .as_object()
                .is_some_and(|a| a.len() == 1)
            && a["first_epoch"] == 198
            && a["last_epoch"] == 198
            && a["attempt"] == 1
            && a["unit"] == UNIT
            && a["pid"] == 1165606
            && a["pid_start_time"] == 79845173
            && (if actual_import {
                a["phase"] == "importing"
            } else {
                matches!(a["phase"].as_str(), Some("producer" | "staged"))
            })
            && a["source_recovery"] != true
            && a["failure"].is_null()
            && (if actual_import {
                a["import_unit"] == IMPORTER
            } else {
                a["import_unit"].is_null()
            })
            && e["controller_sha256"]
                == "62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e"
            && e["controller_argv_sha256"]
                == "d5c14bf6b156bc75ff4ac0f2d8fe6b3b6b9ba8dc669eda71045a566a9e03b803"
            && e["jet_path"] == SOURCE_ARCHIVE
            && e["jet_identity"]["length"] == e["archive_close_bytes"],
        "198handoff state, command or closed archive differs"
    );
    let recovery: Bound = serde_json::from_value(e["controller_recovery"].clone())?;
    ensure!(
        recovery.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-package-controller-first-fire-20261021-v1/first-fire.json"
            )
            && recovery.sha256
                == "baad8fedb7ae8ab271da2c34850b54f626b907424eeb6c9669947b7d6dce3444",
        "foreign198handoff recovery evidence"
    );
    Ok(())
}

fn read_profile(p: &Plan, model: &Value) -> Result<Option<Value>> {
    read_profile_with_archive(p, model, true)
}

fn read_profile_with_archive(
    p: &Plan,
    model: &Value,
    current_archive: bool,
) -> Result<Option<Value>> {
    let Some(profile) = &p.epoch198_delivery else {
        return Ok(None);
    };
    let (_, _, _, _, archive_path) = stage(profile);
    ensure!(
        is_101(p)?
            && !p.expected_epochs.contains(&198)
            && p.tools.r2.path == Path::new(publisher(p).0)
            && p.tools.r2.sha256 == publisher(p).1
            && profile.proof.path.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer/horizon-epoch198-delivery-observations-v1"
                )),
        "foreign198 delivery deployment/census"
    );
    tool_ok(&Bound {
        path: if profile.controller_handoff {
            HANDOFF_WRITER
        } else {
            WRITER
        }
        .into(),
        sha256: if profile.controller_handoff {
            HANDOFF_WRITER_SHA
        } else {
            WRITER_SHA
        }
        .into(),
    })?;
    let proof = bound_json(&profile.proof, false)?;
    ensure!(
        (proof["phase"] == "controller-import-handoff") == profile.controller_handoff,
        "198profile and proof phase differ"
    );
    if profile.controller_handoff {
        ensure!(
            profile.controller_recovery.is_some()
                && proof["terminal_evidence"]["controller_recovery"]
                    == serde_json::to_value(profile.controller_recovery.as_ref().unwrap())?,
            "198controller handoff requires adopted origin"
        );
    }
    let controller = profile_controller(profile)?;
    let range = original_range(model)?;
    if let Some(r) = range {
        validate_range(r, controller)?;
    }
    validate_proof(&proof, utc_seconds(&p.sample_target_utc)?, range.is_some())?;
    if let Some(previous) = &profile.predecessor_proof {
        ensure!(
            profile.controller_handoff && previous.path.parent() == profile.proof.path.parent(),
            "198predecessor only valid for forward controller handoff"
        );
        let previous = bound_json(previous, false)?;
        validate_forward(&previous, &proof, utc_seconds(&p.sample_target_utc)?, false)?;
    }
    if current_archive {
        let archive = fs::symlink_metadata(archive_path)?;
        ensure!(
            archive.is_file()
                && !archive.file_type().is_symlink()
                && archive.nlink() == 1
                && Path::new(archive_path).canonicalize()? == Path::new(archive_path)
                && archive.len()
                    == proof["terminal_evidence"]["archive_close_bytes"]
                        .as_u64()
                        .context("198 close bytes missing")?,
            "198 private archive moved/changed; authenticate actual import handoff instead"
        );
    }
    let origin = bound_json(&profile.origin_publication, false)?;
    ensure!(
        profile.origin_publication.path.parent() == Some(Path::new(STATUS))
            && origin["schema"]
                == "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1"
            && origin["bucket"] == BUCKET
            && origin["epoch"] == 198
            && origin["status"]["epoch"] == 198
            && origin["status"]["phase"] == "replay"
            && origin["authenticated_readback"] == true
            && origin["producer_invocation_id"] == INVOCATION
            && origin["controller_invocation_id"] == controller
            && (profile.controller_recovery.is_none()
                || utc_seconds(
                    origin["status"]["sampled_at_utc"]
                        .as_str()
                        .context("198 origin sample time")?
                )? >= utc_seconds("2026-10-21T15:08:00Z")?)
            && origin["observer_receipt"].as_str() == profile.origin_observer.path.to_str()
            && origin["observer_receipt_sha256"] == profile.origin_observer.sha256
            && origin["pipeline_binding"].is_null(),
        "198 original elapsed-clock receipt differs"
    );
    let observer = bound_json(&profile.origin_observer, false)?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == origin["status"]["sampled_at_utc"],
        "198 origin observer differs"
    );
    let rows = observer["replays"]
        .as_array()
        .context("198 origin census missing")?;
    ensure!(
        rows.iter()
            .filter(|r| r["range"] == "198"
                && r["invocation_binding_stable"] == true
                && r["producer_after"]["invocation_id"] == INVOCATION
                && r["producer_after"]["unit"] == UNIT
                && r["controller_after"]["invocation_id"] == controller)
            .count()
            == 1,
        "198 origin is not authenticated original replay"
    );
    Ok(Some(proof))
}

pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    if read_profile(p, model)?.is_none() {
        return Ok(model.clone());
    }
    apply_model(model, p.epoch198_delivery.as_ref().unwrap())
}

fn publisher(p: &Plan) -> (&'static str, &'static str) {
    if p.prefix144_audit.is_some() || p.completed144_prefix.is_some() {
        return (prefix144::DELIVERY_WRITER, prefix144::DELIVERY_WRITER_SHA);
    }
    if p.prefix157_audit.is_some() {
        return (prefix157::WRITER, prefix157::WRITER_SHA);
    }
    if p.runtime_handoff157.is_some() {
        return (runtime157::WRITER, runtime157::WRITER_SHA);
    }
    if pending(p) {
        return (HANDOFF_WRITER, HANDOFF_WRITER_SHA);
    }
    if p.scope_101_200
        .as_ref()
        .is_some_and(|s| s.private144_observer)
    {
        (private144::WRITER, private144::WRITER_SHA)
    } else {
        (PUBLISHER, PUBLISHER_SHA)
    }
}

fn apply_model(model: &Value, profile: &Profile) -> Result<Value> {
    if let Some(r) = original_range(model)? {
        validate_range(r, profile_controller(profile)?)?;
    }
    let mut next = model.clone();
    next["ranges"]
        .as_array_mut()
        .context("198 range census")?
        .retain(|r| r["range"] != "198");
    next["expected_observer_ranges"]
        .as_array_mut()
        .context("198 expected observer census")?
        .retain(|r| r != "198");
    let binding = serde_json::to_value(&profile.proof)?;
    let evidence = next["evidence"]
        .as_array_mut()
        .context("198 model evidence missing")?;
    if !evidence.contains(&binding) {
        evidence.push(binding);
    }
    Ok(next)
}

fn claim(profile: &Profile, proof: &Value) -> Value {
    let (phase, _, unit, invocation, _) = stage(profile);
    json!({"epoch":198,"phase":phase,"unit":unit,"invocation_id":invocation,
        "expected_exec_start":proof["before"]["ExecStart"],"evidence":[profile.proof,profile.origin_publication]})
}

pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    let Some(profile) = &p.epoch198_delivery else {
        return Ok(());
    };
    let proof = bound_json(&profile.proof, false)?;
    apply_fleet(profile, &proof, fleet)
}

fn apply_fleet(profile: &Profile, proof: &Value, fleet: &mut Value) -> Result<()> {
    if !proof["terminal_evidence"]["importer"].is_null() {
        let units = fleet["tracked_units"]
            .as_array_mut()
            .context("198 importer tracked census")?;
        if !units.contains(&json!(IMPORTER)) {
            units.push(json!(IMPORTER));
        }
    }
    let expected = claim(profile, proof);
    if fleet.get("pipeline_claims").is_none() {
        fleet["pipeline_claims"] = json!([]);
    }
    let claims = fleet["pipeline_claims"]
        .as_array_mut()
        .context("198 pipeline census")?;
    let existing: Vec<_> = claims.iter().filter(|c| c["epoch"] == 198).collect();
    if existing.is_empty() {
        claims.push(expected);
    } else {
        let prior = if let Some(binding) = &profile.predecessor_proof {
            let proof = bound_json(binding, false)?;
            let mut prior: Profile = serde_json::from_value(serde_json::to_value(profile)?)?;
            prior.proof = binding.clone();
            prior.controller_handoff = false;
            prior.predecessor_proof = None;
            Some(claim(&prior, &proof))
        } else {
            None
        };
        ensure!(
            existing.len() == 1
                && (*existing[0] == expected || prior.as_ref() == Some(existing[0])),
            "198 pipeline replaced or duplicated"
        );
        if *existing[0] != expected {
            let index = claims.iter().position(|c| c["epoch"] == 198).unwrap();
            claims[index] = expected;
        }
    }
    let gate = &mut fleet["gates"]["198"];
    ensure!(
        matches!(
            gate["state"].as_str(),
            Some("staged-admissible" | "live-replay" | "post-replay-pipeline")
        ),
        "198 handoff cannot weaken a failed/qualification gate"
    );
    gate["state"] = json!("post-replay-pipeline");
    gate["next_action"] = json!(if !proof["terminal_evidence"]["importer"].is_null() {
        "Preserve authenticated live importer526647 and owning controller, committed source receipt and original producer clock; dispatch independent full/current-plugin/upload/readback stages as canonical archive appears; no downstream allowance reset"
    } else if profile.controller_handoff {
        "Preserve exact pending controller import and original producer clock; retain independent full/plugin/import/upload/readback gates and authenticate the actual importer when ownership moves"
    } else {
        "Preserve exact live producer finalization, original elapsed clock and independent full/plugin/import/upload/readback gates; authenticate actual controller/import handoff promptly when this owner exits"
    });
    let evidence = gate["evidence"]
        .as_array_mut()
        .context("198 gate evidence")?;
    for b in [&profile.proof, &profile.origin_publication] {
        let b = serde_json::to_value(b)?;
        if !evidence.contains(&b) {
            evidence.push(b);
        }
    }
    Ok(())
}

pub(super) fn enable(
    next: &mut Plan,
    config: &mut Value,
    model: &Value,
    completion: &Value,
    spec: &Bound,
) -> Result<()> {
    ensure!(is_101(next)?, "foreign198delivery scope");
    let value: HandoffSpec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    ensure!(
        value.schema == "jetstreamer-epoch198-routine-handoff-spec-v1"
            && !value.replay_launch_authorized
            && !value.archive_publication_authorized
            && !value.r2_archive_mutations,
        "198 handoff spec authority differs"
    );
    let proof = value.proof;
    if next.epoch198_delivery.is_some() {
        return advance_pending(next, config, model, &proof);
    }
    ensure!(
        next.expected_epochs.contains(&198),
        "initial198delivery must consume replay claim"
    );
    let prior = bound_json(&next.previous_fleet, false)?;
    ensure!(
        prior["epochs"]
            .as_array()
            .context("198 prior fleet census missing")?
            .iter()
            .filter(|e| e["epoch"] == 198 && e["state"] == "live-replay")
            .count()
            == 1,
        "198 prior fleet is not a live replay; reconcile actual completion/phase instead"
    );
    let recovery = controller_recovery::epoch198_origin(model)?;
    let controller = match &recovery {
        Some(binding) => controller_recovery::epoch198_controller(binding)?,
        None => CONTROLLER,
    };
    validate_range(
        original_range(model)?.context("198 predecessor range missing")?,
        controller,
    )?;
    let bindings = completion["status_publications"]
        .as_array()
        .context("198 prior status list")?;
    let mut origins = Vec::new();
    for b in bindings {
        let b: Bound = serde_json::from_value(b.clone())?;
        if bound_json(&b, false)?["epoch"] == 198 {
            origins.push(b);
        }
    }
    ensure!(origins.len() == 1, "198 origin status missing/duplicate");
    let controller_handoff = bound_json(&proof, false)?["phase"] == "controller-import-handoff";
    next.epoch198_delivery = Some(Profile {
        proof,
        origin_publication: origins.remove(0),
        origin_observer: next.previous_observer.clone(),
        controller_recovery: recovery,
        controller_handoff,
        predecessor_proof: None,
        delayed_recovery: value.sample_target_utc.is_some(),
    });
    next.expected_epochs.retain(|e| *e != 198);
    next.tools.r2 = Bound {
        path: publisher(next).0.into(),
        sha256: publisher(next).1.into(),
    };
    read_profile(next, model)?;
    let rows = config["replays"]
        .as_array_mut()
        .context("198 observer config census")?;
    ensure!(
        rows.iter().filter(|r| r["range"] == "198").count() == 1,
        "198 configured range missing/duplicate"
    );
    rows.retain(|r| r["range"] != "198");
    next.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    Ok(())
}

fn validate_forward(previous: &Value, proof: &Value, target: u64, fresh: bool) -> Result<()> {
    validate_proof(previous, target, false)?;
    validate_proof(proof, target, fresh)?;
    ensure!(
        previous["phase"] == "producer-finalization"
            && proof["phase"] == "controller-import-handoff"
            && previous["completed_unix_seconds"].as_u64()
                <= proof["observed_unix_seconds"].as_u64()
            && previous["terminal_evidence"]["events"] == proof["terminal_evidence"]["events"]
            && previous["terminal_evidence"]["archive_close_bytes"]
                == proof["terminal_evidence"]["archive_close_bytes"],
        "198handoff is backward, changes original closed archive, or borrows another terminal"
    );
    Ok(())
}

// Preparation consumes durable accepted-cycle evidence. Only a fresh exact
// forward-handoff proof may replace the obsolete source path check; normal
// execution and ordinary successor preparation still require the current file.
pub(super) fn preparation_model(p: &Plan, model: &Value, spec: Option<&Bound>) -> Result<Value> {
    if let (Some(profile), Some(spec)) = (&p.epoch198_delivery, spec) {
        let spec: HandoffSpec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
        ensure!(
            spec.schema == "jetstreamer-epoch198-routine-handoff-spec-v1"
                && !spec.replay_launch_authorized
                && !spec.archive_publication_authorized
                && !spec.r2_archive_mutations,
            "198forward spec grants authority"
        );
        ensure!(
            !profile.controller_handoff && profile.predecessor_proof.is_none(),
            "198already beyond finalization"
        );
        let previous = read_profile_with_archive(p, model, false)?.context("198prior missing")?;
        let proof = bound_json(&spec.proof, false)?;
        validate_forward(&previous, &proof, utc_seconds(&p.sample_target_utc)?, true)?;
        return apply_model(model, profile);
    }
    effective_model(p, model)
}

fn advance_pending(
    next: &mut Plan,
    config: &mut Value,
    model: &Value,
    proof: &Bound,
) -> Result<()> {
    let previous = next
        .epoch198_delivery
        .as_ref()
        .context("198prior missing")?;
    ensure!(
        !previous.controller_handoff
            && previous.predecessor_proof.is_none()
            && previous.controller_recovery.is_some()
            && !next.expected_epochs.contains(&198)
            && !config["replays"]
                .as_array()
                .context("198config census")?
                .iter()
                .any(|r| r["range"] == "198"),
        "198pending handoff cannot replace replay or duplicate a claim"
    );
    let old =
        read_profile_with_archive(next, model, false)?.context("198previous proof missing")?;
    let current = bound_json(proof, false)?;
    validate_forward(&old, &current, utc_seconds(&next.sample_target_utc)?, true)?;
    let previous = next.epoch198_delivery.as_mut().unwrap();
    previous.predecessor_proof = Some(previous.proof.clone());
    previous.proof = proof.clone();
    previous.controller_handoff = true;
    next.tools.r2 = Bound {
        path: publisher(next).0.into(),
        sha256: publisher(next).1.into(),
    };
    read_profile(next, model)?;
    Ok(())
}

pub(super) fn namespaces(
    next: &mut Plan,
    observer_package: &mut PathBuf,
    cycle_package: &mut PathBuf,
) -> Result<()> {
    ensure!(
        is_101(next)? && next.epoch198_delivery.is_some(),
        "198 namespace requires exact delivery profile"
    );
    let stamp = stamp(&next.sample_target_utc);
    *observer_package = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-next-observer-101-200-{stamp}-{}",
        generation_101(next)
    ));
    *cycle_package = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-routine-plan-101-200-{stamp}-{}",
        generation_101(next)
    ));
    next.observer_config.path = observer_package.join("observer.json");
    next.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
        .join(format!("{stamp}-{}", generation_101(next)));
    next.cycle_unit = cycle_unit(next)?;
    if let Some(scope) = &mut next.scope_101_200 {
        scope.additional_tracked_units = vec![next.cycle_unit.clone()];
    }
    Ok(())
}

fn seal_values(p: &Plan, name: &str, values: &[(&str, Value)]) -> Result<PathBuf> {
    let stage = p.cycle_directory.join(name);
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    let mut members = Vec::new();
    for (name, value) in values {
        let bound = write_new(&stage.join(format!("source-{name}")), value)?;
        members.push(json!({"source":bound.path,"name":name,"sha256":bound.sha256,"mode":292}));
    }
    let destination = stage.join("sealed");
    let plan = write_new(
        &stage.join("seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,"members":members}),
    )?;
    child(
        &p.tools.sealer,
        &[
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256,
            "--self-sha256".into(),
            p.tools.sealer.sha256.clone(),
        ],
        false,
        &p.cycle_directory.join(format!("child-{name}-sealer.json")),
    )?;
    Ok(destination)
}

fn remaining_millis(proof: &Value, sample: &str) -> Result<u64> {
    let close = proof["terminal_evidence"]["events"][3]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("198 close time missing")?
        .parse::<u64>()?
        / 1000;
    let sample = utc_seconds(sample)?
        .checked_mul(1000)
        .context("198 sample overflow")?;
    ensure!(close <= sample, "198 archive close is after sample");
    let deadline = close
        .checked_add(43_200_000)
        .context("198 downstream deadline overflow")?;
    deadline
        .checked_sub(sample)
        .filter(|n| *n > 0)
        .context("198 downstream allowance exhausted; require reviewed estimate, no zero clamp")
}

pub(super) fn publish(p: &Plan, model: &Value, fleet: &Value, observer: &Bound) -> Result<Value> {
    let Some(profile) = &p.epoch198_delivery else {
        return Ok(Value::Null);
    };
    let proof = read_profile(p, model)?.context("198 profile missing")?;
    let (claim_phase, status_phase, owner, owner_iid, archive_path) = stage(profile);
    let mut provisional = fleet.clone();
    let ledger_path = p.cycle_directory.join("delivery198-provisional-fleet.json");
    provisional["output"] = json!(ledger_path);
    let stage = seal_values(p, "delivery198-stage", &[("fleet-plan.json", provisional)])?;
    let fleet_plan = Bound {
        path: stage.join("fleet-plan.json"),
        sha256: sha(&read_checked(
            &stage.join("fleet-plan.json"),
            LIMIT,
            0,
            true,
        )?),
    };
    child(
        &p.tools.r2,
        &[
            "fleet-reconcile".into(),
            fleet_plan.path.display().to_string(),
            "--plan-sha256".into(),
            fleet_plan.sha256,
        ],
        true,
        &p.cycle_directory.join("child-delivery198-fleet.json"),
    )?;
    let bytes = read_checked(&ledger_path, LIMIT, 0, false)?;
    let ledger: Value = serde_json::from_slice(&bytes)?;
    let bound = Bound {
        path: ledger_path,
        sha256: sha(&bytes),
    };
    ensure!(
        ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["observer_sha256"] == observer.sha256
            && ledger["inventory"]["anomalies"] == 0,
        "198 provisional fleet differs"
    );
    let meta = fs::symlink_metadata(archive_path)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.nlink() == 1
            && Path::new(archive_path).canonicalize()? == Path::new(archive_path)
            && meta.len()
                == proof["terminal_evidence"]["archive_close_bytes"]
                    .as_u64()
                    .context("198 close size missing")?,
        "198 complete archive changed"
    );
    let model_path = p
        .cycle_directory
        .join("delivery198-status/sealed/pipeline-plan.json");
    let remaining = remaining_millis(&proof, &p.sample_target_utc)?;
    let value = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":198,"phase":status_phase,
        "binding":{"unit":owner,"invocation_id":owner_iid,"expected_exec_start":proof["before"]["ExecStart"],
        "claim_phase":claim_phase,"origin_unit":UNIT,"origin_invocation_id":INVOCATION,
        "model_path":model_path,"model_sha256":"","fleet_path":bound.path,"fleet_sha256":bound.sha256},
        "observer":observer,"fleet":bound,"origin_launch":profile.origin_publication,
        "estimate_evidence":[profile.proof],"estimate_basis":"Exact active delivery owner is independently reauthenticated; actual archive close plus previously qualified43200second downstream budget, never an elapsed replay countdown or ready assertion",
        "estimated_remaining_millis":remaining,"jet_path":archive_path,"expected_jet_size_bytes":meta.len(),
        "peer_units":[],"receipt_directory":STATUS,"receipt_directory_uid":1001});
    let sealed = seal_values(p, "delivery198-status", &[("pipeline-plan.json", value)])?;
    let plan = Bound {
        path: sealed.join("pipeline-plan.json"),
        sha256: sha(&read_checked(&model_path, LIMIT, 0, true)?),
    };
    for (suffix, check) in [("check", true), ("publish", false)] {
        let mut args = vec![
            "status-publish-pipeline".into(),
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256.clone(),
        ];
        if check {
            args.push("--check-only".into());
        }
        child(
            &p.tools.r2,
            &args,
            !check,
            &p.cycle_directory
                .join(format!("child-delivery198-{suffix}.json")),
        )?;
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let path = Path::new(STATUS).join(format!("epoch-198.status-{digits}.json"));
    let bytes = read_checked(&path, LIMIT, 0, false)?;
    let receipt: Value = serde_json::from_slice(&bytes)?;
    validate_publication(p, observer, &plan, &receipt)?;
    ensure!(
        receipt["status"]["estimated_remaining_millis"] == remaining,
        "198 published ETA differs"
    );
    Ok(
        json!({"provisional_fleet":bound,"pipeline_plan":plan,"publication":{"path":path,"sha256":sha(&bytes)}}),
    )
}

fn validate_publication(p: &Plan, observer: &Bound, plan: &Bound, r: &Value) -> Result<()> {
    let (claim_phase, status_phase, owner, owner_iid, _) = stage(
        p.epoch198_delivery
            .as_ref()
            .context("198publication profile missing")?,
    );
    ensure!(
        r["schema"]
            == "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
            && r["bucket"] == BUCKET
            && r["epoch"] == 198
            && r["key"] == "epoch-198.epoch-status.json"
            && r["authenticated_readback"] == true
            && r["status"]["epoch"] == 198
            && r["status"]["phase"] == status_phase
            && r["status"]["sampled_at_utc"] == p.sample_target_utc
            && r["observer_receipt"].as_str() == observer.path.to_str()
            && r["observer_receipt_sha256"] == observer.sha256
            && r["pipeline_binding"]["unit"] == owner
            && r["pipeline_binding"]["invocation_id"] == owner_iid
            && r["pipeline_binding"]["claim_phase"] == claim_phase
            && r["pipeline_binding"]["origin_unit"] == UNIT
            && r["pipeline_binding"]["origin_invocation_id"] == INVOCATION
            && r["pipeline_binding"]["model_path"].as_str() == plan.path.to_str()
            && r["pipeline_binding"]["model_sha256"] == plan.sha256
            && r["status"]["elapsed_execution_millis"].as_u64().is_some()
            && r["status"]["estimated_remaining_millis"]
                .as_u64()
                .is_some_and(|n| n > 0),
        "198 pipeline publication binding differs"
    );
    Ok(())
}

pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    if p.epoch198_delivery.is_none() {
        ensure!(c["epoch198_delivery"].is_null(), "unexpected198 completion");
        return Ok(());
    }
    let d = &c["epoch198_delivery"];
    let observer: Bound = serde_json::from_value(c["observer"].clone())?;
    let plan: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    ensure!(
        plan.path
            == p.cycle_directory
                .join("delivery198-status/sealed/pipeline-plan.json"),
        "foreign198 pipeline plan"
    );
    let value = bound_json(&plan, true)?;
    let publication: Bound = serde_json::from_value(d["publication"].clone())?;
    let r = bound_json(&publication, false)?;
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    ensure!(
        publication.path == Path::new(STATUS).join(format!("epoch-198.status-{digits}.json"))
            && r["status"]["estimated_remaining_millis"] == value["estimated_remaining_millis"]
            && r["status"]["jet_size_bytes"] == value["expected_jet_size_bytes"],
        "198 completed status size/estimate/path differs"
    );
    validate_publication(p, &observer, &plan, &r)?;
    let fleet: Bound = serde_json::from_value(d["provisional_fleet"].clone())?;
    ensure!(
        fleet.path == p.cycle_directory.join("delivery198-provisional-fleet.json")
            && value["fleet"]["sha256"] == fleet.sha256
            && value["fleet"]["path"].as_str() == fleet.path.to_str(),
        "198 provisional fleet binding differs"
    );
    bound_json(&fleet, false)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        let b = |name: &str| Bound {
            path: format!("/fixture/{name}").into(),
            sha256: "a".repeat(64),
        };
        Profile {
            proof: b("proof"),
            origin_publication: b("origin"),
            origin_observer: b("observer"),
            controller_recovery: None,
            controller_handoff: false,
            predecessor_proof: None,
            delayed_recovery: false,
        }
    }
    #[test]
    fn delayed_recovery_is_exact_and_consumed_only_by_real_successor() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let mut profile = profile();
        profile.delayed_recovery = true;
        p.epoch198_delivery = Some(profile);
        p.sample_target_utc = "2026-10-21T20:18:00Z".into();
        p.previous_observer = Bound {path:"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261021T193800Z.json".into(),sha256:"2eeb72a1f51220db978745c846c7b3bd9e2695a5bdb58c9969bfd0fe7fee5773".into()};
        assert_eq!(recovery_interval(&p).unwrap(), Some(2400));
        assert!(consume_recovery(&mut p).is_err());
        p.previous_observer.sha256 = "a".repeat(64);
        assert!(recovery_interval(&p).is_err());
        p.sample_target_utc = "2026-10-21T20:48:00Z".into();
        p.previous_observer.path = "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261021T201800Z.json".into();
        consume_recovery(&mut p).unwrap();
        assert_eq!(recovery_interval(&p).unwrap(), None);
    }
    fn range() -> Value {
        json!({"range":"198","epochs":[198],"expected_producer_invocation_id":INVOCATION,
            "expected_controller_invocation_id":CONTROLLER,"terminal_slot":85967999,
            "epoch_additional_replay_slots":{"198":0},"epoch_downstream_allowance_seconds":{"198":43200},
            "archive_directory":Path::new(ARCHIVE).parent().unwrap(),"formula":{"198":"genuine old replay formula"}})
    }
    #[test]
    fn new_controller_is_not_a_legacy_alias_or_a_replacement_producer() {
        let legacy = profile();
        let mut r = range();
        validate_range(&r, profile_controller(&legacy).unwrap()).unwrap();
        r["expected_controller_invocation_id"] = json!(controller_recovery::CONTROLLER198);
        assert!(validate_range(&r, profile_controller(&legacy).unwrap()).is_err());
        validate_range(&r, controller_recovery::CONTROLLER198).unwrap();
        r["expected_producer_invocation_id"] = json!("f".repeat(32));
        assert!(validate_range(&r, controller_recovery::CONTROLLER198).is_err());
        assert!(validate_range(&range(), "arbitrary-controller").is_err());
    }
    fn proof() -> Value {
        let owner = json!({"Id":UNIT,"InvocationID":INVOCATION,"MainPID":"1165606","NRestarts":"0",
            "LoadState":"loaded","ActiveState":"active","SubState":"running","ExecStart":"exact fixture command"});
        let events:Vec<_>=(10..14).map(|seconds|json!({"__REALTIME_TIMESTAMP":(seconds*1_000_000u64).to_string(),
            "_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":INVOCATION,"_PID":"1165606","_UID":"1001"})).collect();
        json!({"schema":"jetstreamer-epoch198-delivery-observation-v1","observer_sha256":WRITER_SHA,
            "epoch":198,"phase":"producer-finalization","before":owner,"after":owner,
            "observed_unix_seconds":20,"completed_unix_seconds":21,
            "resource_sample_taken":false,"cadence_consumed":false,"status_publication_authorized":false,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,
            "terminal_evidence":{"schema":"jetstreamer-epoch198-finalization-events-v1","unit":UNIT,
                "invocation_id":INVOCATION,"terminal_slot":85967999,"trusted_root_slot":85967282,
                "node_sha256":"e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887",
                "manifest_sha256":"f1d0ff0521379a4c1dcd5461dca144d5d2484b3fc2d09f1f613c5ddd0a6c4d7e",
                "replay_terminal_observed":true,"archive_close_bytes":123,
                "independent_full_verification_passed":false,"publication_authorized":false,
                "replay_launch_authorized":false,"r2_mutations":false,"events":events}})
    }
    fn pending_proof() -> Value {
        let mut p = proof();
        p["schema"] = json!("jetstreamer-epoch198-controller-handoff-observation-v1");
        p["observer_sha256"] = json!(HANDOFF_WRITER_SHA);
        p["phase"] = json!("controller-import-handoff");
        p["observed_unix_seconds"] = json!(30);
        p["completed_unix_seconds"] = json!(31);
        let owner = json!({"Id":IMPORT_CONTROLLER,"InvocationID":controller_recovery::CONTROLLER198,
            "MainPID":"2939002","NRestarts":"0","LoadState":"loaded","ActiveState":"active",
            "SubState":"running","ExecStart":"exact controller fixture command"});
        p["before"] = owner.clone();
        p["after"] = owner;
        let e = &mut p["terminal_evidence"];
        e["schema"] = json!("jetstreamer-epoch198-controller-import-handoff-v1");
        e["producer"] = json!({"Id":UNIT,"InvocationID":INVOCATION,"LoadState":"loaded","MainPID":"0",
            "NRestarts":"0","Result":"success","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead"});
        e["controller_state"] = json!({"schema":"jetstreamer-adaptive-root-cohort-sweep-v3",
            "configuration_sha256":"0929b892242b85f08cbe3d5828b6f4650c81c4730e5fd81f8dfe3e38f096aadd",
            "import_owner":null,"assignments":{"lane-a":{"first_epoch":198,"last_epoch":198,"attempt":1,
                "unit":UNIT,"pid":1165606,"pid_start_time":79845173,"phase":"staged"}}});
        e["controller_sha256"] =
            json!("62592209a3fc2b659ea4bfb924bbcf34435b4228c87e56232eb6b962b907023e");
        e["controller_argv_sha256"] =
            json!("d5c14bf6b156bc75ff4ac0f2d8fe6b3b6b9ba8dc669eda71045a566a9e03b803");
        e["controller_recovery"] = json!({"path":"/usr/local/lib/jetstreamer/horizon-package-controller-first-fire-20261021-v1/first-fire.json","sha256":"baad8fedb7ae8ab271da2c34850b54f626b907424eeb6c9669947b7d6dce3444"});
        e["jet_path"] = json!(SOURCE_ARCHIVE);
        e["jet_identity"] = json!({"length":123});
        p
    }
    #[test]
    fn collected_pending_proof_requires_exact_ordered_manager_success() {
        let mut p = pending_proof();
        p["terminal_evidence"]["producer"]["LoadState"] = json!("not-found");
        p["terminal_evidence"]["producer"]["InvocationID"] = json!("");
        assert!(validate_proof(&p, 1800, true).is_err());
        p["terminal_evidence"]["producer_terminal_manager"] = json!({"UNIT":UNIT,"INVOCATION_ID":INVOCATION,"_PID":"1","_UID":"0","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{UNIT}: Deactivated successfully."),"__REALTIME_TIMESTAMP":"14000000"});
        validate_proof(&p, 1800, true).unwrap();
        for key in [
            "UNIT",
            "INVOCATION_ID",
            "_PID",
            "_UID",
            "MESSAGE_ID",
            "MESSAGE",
            "__REALTIME_TIMESTAMP",
        ] {
            let mut bad = p.clone();
            bad["terminal_evidence"]["producer_terminal_manager"][key] = json!("bad");
            assert!(validate_proof(&bad, 1800, true).is_err(), "{key}");
        }
    }
    #[test]
    fn actual_import_proof_preserves_controller_owner_and_tracks_real_child() {
        let mut p = pending_proof();
        let e = &mut p["terminal_evidence"];
        e["controller_state"]["import_owner"] = json!("lane-a");
        e["controller_state"]["assignments"]["lane-a"]["phase"] = json!("importing");
        e["controller_state"]["assignments"]["lane-a"]["import_unit"] = json!(IMPORTER);
        e["importer"] = json!({"Id":IMPORTER,"InvocationID":"526647ab03104a1fb8f14303819d6cda","MainPID":"3182197","LoadState":"loaded","ActiveState":"active","SubState":"running","NRestarts":"0","ExecStart":"exact --recover-staged-cohort-only --publish-through-epoch=198 ;"});
        e["source_receipt_sha256"] =
            json!("a1734902c86c333be889f3da731da662308b542fa2c72e2e63da566f941cd226");
        validate_proof(&p, 1800, true).unwrap();
        for pointer in [
            "/terminal_evidence/importer/InvocationID",
            "/terminal_evidence/importer/ExecStart",
            "/terminal_evidence/source_receipt_sha256",
            "/terminal_evidence/controller_state/import_owner",
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign");
            assert!(validate_proof(&bad, 1800, true).is_err(), "{pointer}");
        }
        let mut profile = profile();
        profile.controller_handoff = true;
        let mut fleet =
            json!({"tracked_units":[],"gates":{"198":{"state":"live-replay","evidence":[]}}});
        apply_fleet(&profile, &p, &mut fleet).unwrap();
        assert!(
            fleet["tracked_units"]
                .as_array()
                .unwrap()
                .contains(&json!(IMPORTER))
        );
    }
    #[test]
    fn pending_controller_proof_is_forward_clean_and_same_closed_source() {
        let p = pending_proof();
        validate_proof(&p, 1800, true).unwrap();
        validate_forward(&proof(), &p, 1800, true).unwrap();
        validate_forward(&proof(), &p, 3600, false).unwrap();
        assert!(validate_forward(&proof(), &p, 3600, true).is_err());
        assert!(validate_forward(&p, &proof(), 1800, true).is_err());
        for (pointer, value) in [
            ("/before/InvocationID", json!(INVOCATION)),
            ("/terminal_evidence/producer/LoadState", json!("not-found")),
            ("/terminal_evidence/producer/ExecMainStatus", json!("1")),
            (
                "/terminal_evidence/controller_state/import_owner",
                json!("lane-a"),
            ),
            (
                "/terminal_evidence/controller_state/assignments/lane-a/phase",
                json!("importing"),
            ),
            ("/terminal_evidence/jet_identity/length", json!(124)),
            (
                "/terminal_evidence/controller_argv_sha256",
                json!("f".repeat(64)),
            ),
            (
                "/terminal_evidence/controller_recovery/sha256",
                json!("f".repeat(64)),
            ),
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_proof(&bad, 1800, true).is_err(),
                "accepted{pointer}"
            );
        }
        let mut other = proof();
        other["terminal_evidence"]["archive_close_bytes"] = json!(124);
        assert!(validate_forward(&other, &p, 1800, true).is_err());
    }
    #[test]
    fn pending_stage_uses_controller_but_keeps_original_elapsed_origin() {
        let mut p = profile();
        p.controller_handoff = true;
        let c = claim(&p, &pending_proof());
        assert_eq!(c["unit"], IMPORT_CONTROLLER);
        assert_eq!(c["invocation_id"], controller_recovery::CONTROLLER198);
        assert_eq!(c["phase"], "controller-import-handoff");
        assert_eq!(
            c["evidence"][1],
            serde_json::to_value(&p.origin_publication).unwrap()
        );
        assert_eq!(
            remaining_millis(&proof(), "1970-01-01T00:00:30Z").unwrap(),
            remaining_millis(&pending_proof(), "1970-01-01T00:00:30Z").unwrap()
        );
    }
    #[test]
    fn pending_and_paused157_choose_the_qualified_superset_publisher() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let mut profile = profile();
        profile.controller_handoff = true;
        p.epoch198_delivery = Some(profile);
        assert_eq!(publisher(&p), (HANDOFF_WRITER, HANDOFF_WRITER_SHA));
        p.runtime_handoff157 = Some(Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        });
        assert_eq!(publisher(&p), (runtime157::WRITER, runtime157::WRITER_SHA));
    }
    #[test]
    fn pending_publication_binds_controller_and_publication_phase_not_replay_origin() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let mut profile = profile();
        profile.controller_handoff = true;
        p.epoch198_delivery = Some(profile);
        let observer = Bound {
            path: "/observer".into(),
            sha256: "a".repeat(64),
        };
        let plan = Bound {
            path: "/plan".into(),
            sha256: "b".repeat(64),
        };
        let receipt = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1",
            "bucket":BUCKET,"epoch":198,"key":"epoch-198.epoch-status.json","authenticated_readback":true,
            "observer_receipt":observer.path,"observer_receipt_sha256":observer.sha256,
            "status":{"epoch":198,"phase":"publication","sampled_at_utc":p.sample_target_utc,
                "elapsed_execution_millis":u64::MAX,"estimated_remaining_millis":1000},
            "pipeline_binding":{"unit":IMPORT_CONTROLLER,"invocation_id":controller_recovery::CONTROLLER198,
                "claim_phase":"controller-import-handoff","origin_unit":UNIT,"origin_invocation_id":INVOCATION,
                "model_path":plan.path,"model_sha256":plan.sha256}});
        validate_publication(&p, &observer, &plan, &receipt).unwrap();
        for (pointer, value) in [
            ("/status/phase", json!("finalization")),
            ("/pipeline_binding/unit", json!(UNIT)),
            ("/pipeline_binding/origin_unit", json!(IMPORT_CONTROLLER)),
            (
                "/pipeline_binding/claim_phase",
                json!("producer-finalization"),
            ),
        ] {
            let mut bad = receipt.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_publication(&p, &observer, &plan, &bad).is_err(),
                "accepted{pointer}"
            );
        }
    }
    #[test]
    fn proof_is_exact_non_authorizing_ordered_and_fresh_for_initial_transition() {
        let p = proof();
        validate_proof(&p, 1800, true).unwrap();
        validate_proof(&p, 3600, false).unwrap();
        assert!(validate_proof(&p, 1821, true).is_err());
        assert!(validate_proof(&p, 21, true).is_err());
        for (pointer, value) in [
            ("/epoch", json!(199)),
            ("/observer_sha256", json!("a".repeat(64))),
            ("/phase", json!("replay")),
            ("/after/InvocationID", json!("b".repeat(32))),
            ("/before/ActiveState", json!("inactive")),
            ("/publication_authorized", json!(true)),
            (
                "/terminal_evidence/independent_full_verification_passed",
                json!(true),
            ),
            ("/terminal_evidence/node_sha256", json!("a".repeat(64))),
            ("/terminal_evidence/terminal_slot", json!(85967998)),
            (
                "/terminal_evidence/events/1/__REALTIME_TIMESTAMP",
                json!("9000000"),
            ),
            ("/terminal_evidence/events/3/_UID", json!("0")),
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_proof(&bad, 1800, true).is_err(),
                "accepted {pointer}"
            );
        }
        let mut bad = p;
        bad["terminal_evidence"]["events"]
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(validate_proof(&bad, 1800, true).is_err());
    }
    #[test]
    fn model_removes_only_exact198_and_retains_unrelated_u64_and_private_scope() {
        let original = json!({"ranges":[range(),{"range":"160","epochs":[160],"sentinel":u64::MAX}],
            "expected_observer_ranges":["198","160","144"],"evidence":[],"other":{"original_clock":u64::MAX}});
        let next = apply_model(&original, &profile()).unwrap();
        assert_eq!(original["ranges"].as_array().unwrap().len(), 2);
        assert_eq!(next["ranges"], json!([original["ranges"][1]]));
        assert_eq!(next["expected_observer_ranges"], json!(["160", "144"]));
        assert_eq!(next["other"], original["other"]);
        assert_eq!(apply_model(&next, &profile()).unwrap(), next);
        for (key, value) in [
            ("terminal_slot", json!(85967998)),
            ("epochs", json!([198, 199])),
            ("epoch_additional_replay_slots", json!({"198":1})),
            ("archive_directory", json!("/other")),
            ("expected_producer_invocation_id", json!("b".repeat(32))),
        ] {
            let mut bad = original.clone();
            bad["ranges"][0][key] = value;
            assert!(apply_model(&bad, &profile()).is_err(), "accepted {key}");
        }
        let mut bad = original.clone();
        bad["ranges"][0]["range"] = json!("197-198");
        assert!(apply_model(&bad, &profile()).is_err());
    }
    #[test]
    fn fleet_stage_preserves_repairs_diagnostics_history_and_exact_identity() {
        let original = json!({"gates":{"198":{"state":"staged-admissible","next_action":"old","evidence":[]},
            "140":{"state":"failed-needs-repair","evidence":[{"u64":u64::MAX}]}},
            "diagnostics":[{"epoch":144}],"pipeline_claims":[{"epoch":191,"phase":"history"}]});
        let mut fleet = original.clone();
        apply_fleet(&profile(), &proof(), &mut fleet).unwrap();
        assert_eq!(fleet["gates"]["198"]["state"], "post-replay-pipeline");
        assert_eq!(fleet["gates"]["140"], original["gates"]["140"]);
        assert_eq!(fleet["diagnostics"], original["diagnostics"]);
        let expected = fleet.clone();
        apply_fleet(&profile(), &proof(), &mut fleet).unwrap();
        assert_eq!(fleet, expected);
        let mut bad = expected.clone();
        bad["pipeline_claims"][1]["invocation_id"] = json!("b".repeat(32));
        assert!(apply_fleet(&profile(), &proof(), &mut bad).is_err());
        for state in [
            "failed-needs-repair",
            "blocked-qualification",
            "remote-ready",
        ] {
            let mut bad = original.clone();
            bad["gates"]["198"]["state"] = json!(state);
            assert!(apply_fleet(&profile(), &proof(), &mut bad).is_err());
        }
    }
    #[test]
    fn downstream_deadline_is_actual_close_based_and_never_clamped_or_extended() {
        let p = proof();
        assert_eq!(
            remaining_millis(&p, "1970-01-01T00:00:20Z").unwrap(),
            43_193_000
        );
        assert!(remaining_millis(&p, "1970-01-01T00:00:12Z").is_err());
        assert!(remaining_millis(&p, "1970-01-01T12:00:13Z").is_err());
        assert!(remaining_millis(&p, "1970-01-01T12:00:14Z").is_err());
    }
    #[test]
    fn handoff_spec_rejects_extra_or_missing_authority_fields() {
        let original = json!({"schema":"jetstreamer-epoch198-routine-handoff-spec-v1","proof":profile().proof,
            "replay_launch_authorized":false,"archive_publication_authorized":false,"r2_archive_mutations":false});
        serde_json::from_value::<HandoffSpec>(original.clone()).unwrap();
        let mut bad = original.clone();
        bad["unexpected_authority"] = json!(true);
        assert!(serde_json::from_value::<HandoffSpec>(bad).is_err());
        let mut bad = original;
        bad.as_object_mut()
            .unwrap()
            .remove("archive_publication_authorized");
        assert!(serde_json::from_value::<HandoffSpec>(bad).is_err());
    }
    #[test]
    fn provisional_fleet_stays_outside_canonical_predecessor_namespace() {
        let (p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let provisional = p.cycle_directory.join("delivery198-provisional-fleet.json");
        assert_ne!(provisional.parent(), Some(Path::new(FLEET_ROOT_101)));
        assert_ne!(provisional, p.fleet_output);
    }
    #[test]
    fn delivery_generation_does_not_clobber_already_prepared_routine_plan_or_unit() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let old_unit = p.cycle_unit.clone();
        let old_directory = p.cycle_directory.clone();
        p.epoch198_delivery = Some(profile());
        let mut observer = PathBuf::from("/already-prepared/routine");
        let mut cycle = observer.clone();
        namespaces(&mut p, &mut observer, &mut cycle).unwrap();
        assert_ne!(p.cycle_unit, old_unit);
        assert_ne!(p.cycle_directory, old_directory);
        assert!(p.cycle_unit.ends_with("-delivery198-v1.service"));
        assert!(
            observer.ends_with("horizon-next-observer-101-200-20261020T103442Z-delivery198-v1")
        );
        assert!(cycle.ends_with("horizon-routine-plan-101-200-20261020T103442Z-delivery198-v1"));
        assert_eq!(p.observer_config.path, observer.join("observer.json"));
        assert_eq!(
            p.scope_101_200.unwrap().additional_tracked_units,
            [p.cycle_unit]
        );
    }
    #[test]
    fn delivery_preserves_the_explicit_private144_fleet_writer() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        assert_eq!(publisher(&p), (PUBLISHER, PUBLISHER_SHA));
        p.scope_101_200.as_mut().unwrap().private144_observer = true;
        assert_eq!(publisher(&p), (private144::WRITER, private144::WRITER_SHA));
    }
    #[test]
    fn pipeline_receipt_schema_matches_reviewed_r2_reader() {
        assert!(include_str!("../../jetstreamer-r2/src/main.rs").contains(
            "jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1"
        ));
    }
    #[test]
    fn publication_keeps_exact_phase_origin_model_and_authenticated_sample() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        p.epoch198_delivery = Some(profile());
        let observer = Bound {
            path: "/observer".into(),
            sha256: "a".repeat(64),
        };
        let plan = Bound {
            path: "/sealed/pipeline.json".into(),
            sha256: "b".repeat(64),
        };
        let original = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-pipeline-publication-receipt-v1",
            "bucket":BUCKET,"epoch":198,"key":"epoch-198.epoch-status.json","authenticated_readback":true,
            "observer_receipt":observer.path,"observer_receipt_sha256":observer.sha256,
            "status":{"epoch":198,"phase":"finalization","sampled_at_utc":p.sample_target_utc,
                "elapsed_execution_millis":u64::MAX,"estimated_remaining_millis":1000},
            "pipeline_binding":{"unit":UNIT,"invocation_id":INVOCATION,"claim_phase":"producer-finalization","origin_unit":UNIT,
                "origin_invocation_id":INVOCATION,"model_path":plan.path,"model_sha256":plan.sha256}});
        validate_publication(&p, &observer, &plan, &original).unwrap();
        for (pointer, value) in [
            ("/authenticated_readback", json!(false)),
            ("/status/phase", json!("replay")),
            (
                "/pipeline_binding/origin_invocation_id",
                json!("b".repeat(32)),
            ),
            ("/pipeline_binding/unit", json!("horizon-other.service")),
            ("/pipeline_binding/model_sha256", json!("c".repeat(64))),
            ("/status/estimated_remaining_millis", json!(0)),
            ("/status/sampled_at_utc", json!("2026-10-20T00:00:00Z")),
        ] {
            let mut bad = original.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_publication(&p, &observer, &plan, &bad).is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn no_profile_cannot_borrow_pipeline_completion_and_foreign_deployments_fail() {
        let (mut p, model, _, _, _, _, _, _) = crate::tests::fixture101();
        assert!(validate_completed(&p, &json!({"epoch198_delivery":{"publication":{}}})).is_err());
        validate_completed(&p, &json!({})).unwrap();
        p.epoch198_delivery = Some(profile());
        // Fail before reading a proof when the ordinary198 claim was not
        // explicitly transferred or when the exact publisher is not pinned.
        assert!(effective_model(&p, &model).is_err());
        p.expected_epochs.clear();
        assert!(effective_model(&p, &model).is_err());
    }

    #[test]
    fn actual_runtime_retains_fixed_metadata_only_children_and_separate_fleets() {
        let source = include_str!("routine_delivery198.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("delivery198-provisional-fleet.json"));
        for forbidden in [
            "\"sync\".into()",
            "\"restore\".into()",
            "\"status-delete\".into()",
            "\"systemd-run\"",
            "\"systemctl\", \"start\"",
        ] {
            assert!(!production.contains(forbidden));
        }
        let parent = include_str!("routine_cycle.rs");
        let body = parent
            .split("let pipeline = delivery198::publish")
            .nth(1)
            .unwrap();
        assert!(body.contains("child-fleet.json"));
    }
}
