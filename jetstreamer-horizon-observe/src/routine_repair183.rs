//! Exact admitted repair for epochs 183–184: observer/model adoption; never replay authority.
use super::*;
const CONTROLLER: &str =
    "jetstreamer-epochs183-184-readerfix-full-20261023-controller-v2-r2.service";
const PRODUCER: &str =
    "jetstreamer-root-sweep-e183-184-full-20261023-v2-r2-e183-184-lane-a-1.service";
const GUARD: &str = "jetstreamer-adaptive-reserve-epochs183-184-full-20261023-v1.service";
const GUARD_SCRIPT: &str = "/usr/local/lib/jetstreamer/adaptive-reserve-epochs191-194-20261016-v1/guard-adaptive-replay-reserve.py";
const GUARD_SHA: &str = "b62e58f5be764935a679408e1fcc446a9768170109a6639c87fd01571b9f2b62";
const GUARD_FLOOR: u64 = 3_332_894_621_696;
const FIRST_END: u64 = 79_487_999;
const FINAL_END: u64 = 79_919_999;
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epochs183-184-readerfix-20261020-v1/lane-a/private";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    schema: String,
    controller_invocation_id: String,
    producer_invocation_id: String,
    archive_directory: PathBuf,
    scratch_path: PathBuf,
    observer_before_launch: Bound,
    admission: Bound,
    guard_first_fire: Bound,
    capability: Bound,
    new_resource_samples: u64,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn scope(h: &Handoff) -> Result<()> {
    ensure!(
        h.schema == "jetstreamer-horizon-repair183-live-monitor-handoff-v1"
            && iid(&h.controller_invocation_id)
            && iid(&h.producer_invocation_id)
            && h.new_resource_samples == 0
            && !h.replay_launch_authorized
            && !h.publication_authorized
            && !h.remote_mutations
            && !h.r2_mutations,
        "repair 183 handoff grants authority or has invalid identities"
    );
    let scratch = &h.scratch_path;
    ensure!(
        scratch.is_absolute()
            && scratch.starts_with(ROOT)
            && scratch.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && scratch.file_name().and_then(|s| s.to_str()) == Some("scratch")
            && scratch
                .parent()
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("run-"))
            && scratch
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.file_name())
                .and_then(|s| s.to_str())
                == Some("root-cohort-183-184")
            && h.archive_directory
                == scratch
                    .parent()
                    .context("repair 183 run parent")?
                    .join("archives"),
        "repair 183 private archive/scratch scope differs"
    );
    ensure!(
        h.capability.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epochs183-184-package-capability-20261020-v1/capability.json"
            )
            && h.capability.sha256
                == "b98120a9a2697fd4bb004df8ebae67594222185db5e4f3cfe2474ce42333ca45",
        "repair 183 capability binding differs"
    );
    Ok(())
}
fn guard(h: &Handoff, v: &Value) -> Result<()> {
    let s = &v["sample"];
    ensure!(
        v["schema"] == "jetstreamer-horizon-repair183-guard-first-fire-v1"
            && v["admission"] == serde_json::to_value(&h.admission)?
            && v["unit"] == GUARD
            && iid(v["invocation_id"].as_str().unwrap_or(""))
            && v["actual_timer_fired_success"] == true
            && v["exit_status"] == 0
            && v["restarts"] == 0
            && v["stop_intent_absent"] == true
            && v["stop_completion_absent"] == true
            && s["armed"] == true
            && s["trip"] == false
            && s["controller"]["active_state"] == "active"
            && s["producer"]["active_state"] == "active"
            && s["controller"]["invocation_id"] == h.controller_invocation_id
            && s["producer"]["invocation_id"] == h.producer_invocation_id
            && s["controller"]["restarts"] == 0
            && s["producer"]["restarts"] == 0
            && s["minimum_free_bytes"] == GUARD_FLOOR
            && s["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= GUARD_FLOOR)
            && s["maximum_worker_vmas"] == 800000
            && s["producer"]["worker_count"] == 1
            && s["producer"]["worker_vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 800000),
        "repair 183 guard first-fire proof differs"
    );
    for key in [
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "repair 183 guard proof grants authority");
    }
    Ok(())
}
fn live_guard(h: &Handoff) -> Result<()> {
    tool_ok(&Bound {
        path: GUARD_SCRIPT.into(),
        sha256: GUARD_SHA.into(),
    })?;
    let timer = GUARD.replace(".service", ".timer");
    for (unit, is_timer) in [(GUARD, false), (timer.as_str(), true)] {
        let out=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=ActiveState,SubState,Result,NRestarts,ExecMainStatus,ExecStart,Triggers"]).output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 32768,
            "repair 183 guard manager read failed"
        );
        let text = std::str::from_utf8(&out.stdout)?;
        let values: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
        if is_timer {
            ensure!(
                values.get("ActiveState") == Some(&"active")
                    && values.get("Triggers") == Some(&GUARD),
                "repair 183 guard timer is not active for its exact service"
            );
        } else {
            ensure!(
                values.get("Result") == Some(&"success")
                    && values.get("NRestarts") == Some(&"0")
                    && values.get("ExecMainStatus") == Some(&"0"),
                "repair 183 guard is not healthy"
            );
            let command = values
                .get("ExecStart")
                .context("repair 183 guard command")?;
            ensure!(
                command
                    .split_whitespace()
                    .filter(|w| *w == GUARD_SCRIPT)
                    .count()
                    == 1,
                "repair 183 guard executable differs"
            );
            for token in [
                format!("--controller-unit={CONTROLLER}"),
                format!("--producer-unit={PRODUCER}"),
                format!(
                    "--expected-controller-invocation-id={}",
                    h.controller_invocation_id
                ),
                format!(
                    "--expected-producer-invocation-id={}",
                    h.producer_invocation_id
                ),
                format!("--minimum-free-bytes={GUARD_FLOOR}"),
                "--maximum-worker-vmas=800000".into(),
            ] {
                ensure!(
                    command.split_whitespace().filter(|w| *w == token).count() == 1,
                    "repair 183 guard command binding differs"
                );
            }
        }
    }
    Ok(())
}
fn proof(p: &Plan) -> Result<Option<Handoff>> {
    let Some(b) = &p.repair183_handoff else {
        return Ok(None);
    };
    ensure!(
        is_101(p)? && p.publication144.is_some(),
        "foreign repair 183 profile"
    );
    ensure!(
        b.path.starts_with("/usr/local/lib/jetstreamer")
            && b.path.file_name().and_then(|s| s.to_str()) == Some("handoff.json"),
        "repair 183 handoff namespace"
    );
    let h: Handoff = serde_json::from_value(bound_json(b, true)?)?;
    scope(&h)?;
    let cap = bound_json(&h.capability, true)?;
    ensure!(
        cap["epochs"] == json!([183, 184]) && cap["replay_started"] == false,
        "repair 183 original capability differs"
    );
    let admission = bound_json(&h.admission, false)?;
    ensure!(
        h.admission.path.starts_with("/var/lib/jetstreamer")
            && h.admission.path.file_name().and_then(|s| s.to_str())
                == Some("admission-receipt.json")
            && admission["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && admission["admitted"] == true
            && admission["services_started"] == false
            && admission["remote_mutations"] == false
            && admission["r2_mutations"] == false
            && admission["evidence"]["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= GUARD_FLOOR + (768u64 << 30))
            && admission["evidence"]["minimum_memory_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 320u64 << 30)
            && admission["evidence"]["minimum_vm_max_map_count"]
                .as_u64()
                .is_some_and(|n| n >= 4194304),
        "repair 183 full admission proof differs"
    );
    let manifest: Bound = serde_json::from_value(
        json!({"path":admission["manifest"],"sha256":admission["manifest_sha256"]}),
    )?;
    let m = bound_json(&manifest, true)?;
    ensure!(
        m["snapshot"]["path"]
            == "/usr/local/lib/jetstreamer/deploy-epochs183-184-readerfix-20261020-v1/snapshot-79055145-5e31BTDw97vHrceMBBfs3LxxRDfgbDs4HeANxoJpB5VJ.tar.zst"
            && m["snapshot"]["size"] == 7042035825u64
            && m["snapshot"]["crc32c_base64"] == "nQBGXw=="
            && m["snapshot"]["md5_base64"] == "9/3TqW83uPXBE5gkYfpmCg==",
        "repair 183 admitted snapshot differs"
    );
    let before = bound_json(&h.observer_before_launch, false)?;
    ensure!(
        before["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && m["json_receipts"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["path"]
                    == h.observer_before_launch.path.to_str().unwrap_or("")
                    && r["sha256"] == h.observer_before_launch.sha256)),
        "repair 183 admission does not bind the exact prelaunch observer"
    );
    guard(&h, &bound_json(&h.guard_first_fire, true)?)?;
    let mut h = h;
    h.controller_invocation_id = controller_rebind::controller(
        p,
        "183-184",
        &h.controller_invocation_id,
        &h.producer_invocation_id,
    )?;
    Ok(Some(h))
}
pub(super) fn validate_live(p: &Plan) -> Result<()> {
    if let Some(h) = proof(p)? {
        if p.controller_rebind.is_some() {
            return controller_rebind::validate_live(p);
        }
        live_guard(&h)?;
    }
    Ok(())
}
pub(super) fn extend_epochs(p: &Plan, epochs: &mut BTreeSet<u64>) -> Result<()> {
    if let Some(h) = proof(p)? {
        ensure!(
            !epochs.iter().any(|e| (183..=184).contains(e))
                || epochs.contains(&183) && epochs.contains(&184),
            "partial repair 183 prior claim"
        );
        epochs.extend([183, 184]);
        scope(&h)?;
    }
    Ok(())
}
fn apply(model: &Value, h: &Handoff) -> Result<Value> {
    scope(h)?;
    let mut v = model.clone();
    if v["unestimated_bootstrap_epochs"] == json!([183, 184]) {
        v.as_object_mut()
            .context("repair 183 model object")?
            .remove("unestimated_bootstrap_epochs");
    }
    if let Some(census) = v.get_mut("expected_observer_ranges") {
        let census = census
            .as_array_mut()
            .context("repair 183 observer census")?;
        if !census.contains(&json!("183-184")) {
            census.push(json!("183-184"));
        }
    }
    let ranges = v["ranges"].as_array_mut().context("repair 183 ranges")?;
    let indices: Vec<_> = ranges
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r["epochs"]
                .as_array()
                .is_some_and(|es| es.iter().any(|e| e == 183 || e == 184))
        })
        .map(|(i, _)| i)
        .collect();
    if indices.is_empty() {
        ensure!(
            ranges.len() == 3
                && ranges
                    .iter()
                    .map(|r| r["range"].as_str().unwrap_or(""))
                    .collect::<BTreeSet<_>>()
                    == BTreeSet::from(["152-153", "155-156", "191-194"]),
            "repair 183 baseline census differs"
        );
        ranges.push(json!({"range":"183-184","epochs":[183,184],"archive_directory":h.archive_directory,
            "expected_controller_invocation_id":h.controller_invocation_id,"expected_producer_invocation_id":h.producer_invocation_id,
            "terminal_slot":FIRST_END,"epoch_additional_replay_slots":{"183":432000,"184":432000},
            "epoch_downstream_allowance_seconds":{"183":43200,"184":86400},
            "formula":{"183":"remaining observed epoch183 slots plus432000 queued epoch184 slots / observed rate +12h downstream; shared cohort import gate is184",
                "184":"remaining observed epoch183 slots plus432000 queued epoch184 slots / observed rate +24h downstream; shared cohort import gate is184"}}));
    } else {
        ensure!(indices.len() == 1, "overlapping repair 183 claims");
        let r = &ranges[indices[0]];
        ensure!(
            r["range"] == "183-184"
                && r["epochs"] == json!([183, 184])
                && r["archive_directory"] == h.archive_directory.to_str().unwrap_or("")
                && r["expected_controller_invocation_id"] == h.controller_invocation_id
                && r["expected_producer_invocation_id"] == h.producer_invocation_id
                && r.get("elapsed_execution_millis").is_none(),
            "repair 183 existing model owner/clock differs"
        );
        let terminal = r["terminal_slot"].as_u64().context("repair 183 terminal")?;
        ensure!(
            matches!(terminal, FIRST_END | FINAL_END),
            "repair 183 terminal is outside exact cohort"
        );
        for (e, allowance) in [("183", 43200), ("184", 86400)] {
            ensure!(
                r["epoch_additional_replay_slots"][e] == FINAL_END - terminal
                    && r["epoch_downstream_allowance_seconds"][e] == allowance,
                "repair 183 gated work/allowance changed"
            );
        }
    }
    Ok(v)
}
pub(super) fn effective_model(p: &Plan, model: &Value) -> Result<Value> {
    let rebound = controller_rebind::model(p, model)?;
    let model = &rebound;
    let Some(h) = proof(p)? else {
        return Ok(model.clone());
    };
    let already = model["ranges"]
        .as_array()
        .context("repair 183 ranges")?
        .iter()
        .any(|r| r["range"] == "183-184");
    if !already {
        let continued_bootstrap = bootstrap_model(p, model);
        if continued_bootstrap {
            let prior = bound_json(&p.previous_observer, false)?;
            let checked = observation(model, &h, &prior)?;
            ensure!(
                checked["unestimated_bootstrap_epochs"] == json!([183, 184]),
                "repair 183 bootstrap predecessor changed"
            );
        }
        ensure!(
            continued_bootstrap
                || (h.observer_before_launch.path == p.previous_observer.path
                    && h.observer_before_launch.sha256 == p.previous_observer.sha256),
            "repair 183 initial predecessor differs"
        );
    }
    let mut v = apply(model, &h)?;
    let b = serde_json::to_value(p.repair183_handoff.as_ref().unwrap())?;
    let evidence = v["evidence"]
        .as_array_mut()
        .context("repair 183 evidence")?;
    if !evidence.contains(&b) {
        evidence.push(b);
    }
    Ok(v)
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    if proof(p)?.is_none() {
        return Ok(());
    }
    let tracked = fleet["tracked_units"]
        .as_array_mut()
        .context("repair 183 fleet tracked units")?;
    for unit in [CONTROLLER.to_owned(), PRODUCER.to_owned()] {
        let value = json!(unit);
        if !tracked.contains(&value) {
            tracked.push(value);
        }
    }
    for epoch in ["183", "184"] {
        let e = serde_json::to_value(p.repair183_handoff.as_ref().unwrap())?;
        let gate = &mut fleet["gates"][epoch];
        ensure!(
            gate["state"] == "failed-needs-repair",
            "repair 183 original open repair gate changed"
        );
        let evidence = gate["evidence"]
            .as_array_mut()
            .context("repair 183 gate evidence")?;
        if !evidence.contains(&e) {
            evidence.push(e);
        }
        gate["next_action"] = json!(
            "Track freshly admitted and guard-protected183-184 repair replay under its exact controller/producer identities. Shared import gate is epoch 184; preserve queued work and downstream allowances in both ETAs. Keep source incident open through canonical/full/plugin/publication and authenticated ready pairs; launch or unit tests alone are not recovery."
        );
    }
    Ok(())
}
pub(super) fn for_observation(p: &Plan, model: &Value, observed: &Value) -> Result<Value> {
    let Some(h) = proof(p)? else {
        return Ok(model.clone());
    };
    observation(model, &h, observed)
}
fn observation(model: &Value, h: &Handoff, observed: &Value) -> Result<Value> {
    let mut v = apply(model, h)?;
    let rows: Vec<_> = observed["replays"]
        .as_array()
        .context("repair 183 observation census")?
        .iter()
        .filter(|r| r["range"] == "183-184")
        .collect();
    ensure!(rows.len() == 1, "repair 183 missing/duplicate observation");
    let o = rows[0];
    ensure!(
        o["controller_before"]["unit"] == CONTROLLER
            && o["producer_before"]["unit"] == PRODUCER
            && o["scratch_path"] == h.scratch_path.to_str().unwrap_or(""),
        "repair 183 observed paths/units differ"
    );
    ensure!(
        o["invocation_binding_stable"] == true,
        "repair 183 unstable observation"
    );
    for (kind, id) in [
        ("controller", &h.controller_invocation_id),
        ("producer", &h.producer_invocation_id),
    ] {
        for point in ["before", "after"] {
            let s = &o[format!("{kind}_{point}")];
            ensure!(
                s["invocation_id"] == *id && s["restarts"] == 0 && s["active_state"] == "active",
                "repair 183 observed owner changed"
            );
        }
    }
    if o["useful_work"]["last"].is_null() {
        ensure!(
            o["useful_work"]["first"].is_null()
                && o["useful_work"]["matching_markers"] == 0
                && o["useful_work"]["counter_resets"] == 0
                && o["useful_work"]["sufficient_for_rates"] == false
                && o["useful_work"]["slots_per_second"].is_null()
                && v["ranges"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["range"] == "183-184")
                    .unwrap()["terminal_slot"]
                    == FIRST_END,
            "repair 183 absent progress is not initial bootstrap"
        );
        for point in ["before", "after"] {
            let worker = &o[format!("worker_{point}")];
            ensure!(
                worker["matching_workers"] == 1
                    && worker["executable_beneath_bound_scratch"] == true
                    && worker["vmas"]
                        .as_u64()
                        .is_some_and(|n| n > 0 && n <= 800000),
                "repair 183 bootstrap worker is not protected"
            );
        }
        v["ranges"]
            .as_array_mut()
            .unwrap()
            .retain(|r| r["range"] != "183-184");
        v["unestimated_bootstrap_epochs"] = json!([183, 184]);
        return Ok(v);
    }
    let terminal = o["useful_work"]["last"]["terminal_slot"]
        .as_u64()
        .context("repair 183 observed terminal")?;
    let ranges = v["ranges"].as_array_mut().unwrap();
    let r = ranges.iter_mut().find(|r| r["range"] == "183-184").unwrap();
    let previous = r["terminal_slot"].as_u64().unwrap();
    ensure!(
        matches!(terminal, FIRST_END | FINAL_END) && terminal >= previous,
        "repair 183 backward/unknown terminal"
    );
    r["terminal_slot"] = json!(terminal);
    for (epoch, allowance) in [("183", 43200), ("184", 86400)] {
        r["epoch_additional_replay_slots"][epoch] = json!(FINAL_END - terminal);
        r["formula"][epoch] = json!(format!(
            "remaining observed slots plus{} queued gated slots / observed rate +{allowance}s downstream; shared import gate184",
            FINAL_END - terminal
        ));
    }
    Ok(v)
}

pub(super) fn bootstrap_model(p: &Plan, model: &Value) -> bool {
    p.repair183_handoff.as_ref().is_some_and(|b| {
        model["unestimated_bootstrap_epochs"] == json!([183, 184])
            && model["ranges"]
                .as_array()
                .is_some_and(|rs| rs.len() == 3 && !rs.iter().any(|r| r["range"] == "183-184"))
            && model["expected_observer_ranges"]
                .as_array()
                .is_some_and(|rs| rs.len() == 4 && rs.contains(&json!("183-184")))
            && model["evidence"]
                .as_array()
                .is_some_and(|es| es.contains(&serde_json::to_value(b).unwrap()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn producer_namespace_fits_the_pinned_controller_id_limit() {
        let id = PRODUCER
            .strip_prefix("jetstreamer-root-sweep-")
            .unwrap()
            .strip_suffix("-e183-184-lane-a-1.service")
            .unwrap();
        assert!(id.len() <= 32);
        assert!(
            id.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        );
    }
    fn h() -> Handoff {
        serde_json::from_value(json!({"schema":"jetstreamer-horizon-repair183-live-monitor-handoff-v1","controller_invocation_id":"a".repeat(32),"producer_invocation_id":"b".repeat(32),"archive_directory":format!("{ROOT}/destination-x/work/root-cohort-183-184/run-1/archives"),"scratch_path":format!("{ROOT}/destination-x/work/root-cohort-183-184/run-1/scratch"),"observer_before_launch":{"path":"/sample","sha256":"c".repeat(64)},"admission":{"path":"/admit","sha256":"d".repeat(64)},"guard_first_fire":{"path":"/guard","sha256":"e".repeat(64)},"capability":{"path":"/usr/local/lib/jetstreamer/horizon-epochs183-184-package-capability-20261020-v1/capability.json","sha256":"b98120a9a2697fd4bb004df8ebae67594222185db5e4f3cfe2474ce42333ca45"},"new_resource_samples":0,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})).unwrap()
    }
    fn model() -> Value {
        json!({"ranges":[{"range":"152-153","epochs":[152,153]},{"range":"155-156","epochs":[155,156]},{"range":"191-194","epochs":[191,192,193,194]}],"evidence":[],"sentinel":u64::MAX})
    }
    #[test]
    fn adoption_is_exact_idempotent_and_preserves_old_ranges() {
        let old = model();
        let new = apply(&old, &h()).unwrap();
        assert_eq!(new["ranges"].as_array().unwrap().len(), 4);
        assert_eq!(
            &new["ranges"].as_array().unwrap()[..3],
            old["ranges"].as_array().unwrap().as_slice()
        );
        assert_eq!(new["sentinel"], u64::MAX);
        assert_eq!(apply(&new, &h()).unwrap(), new);
        let mut other_bootstrap = new;
        other_bootstrap["unestimated_bootstrap_epochs"] = json!([185]);
        assert_eq!(
            apply(&other_bootstrap, &h()).unwrap()["unestimated_bootstrap_epochs"],
            json!([185])
        );
    }
    #[test]
    fn wrong_scope_authority_owner_and_allowance_fail_closed() {
        for case in 0..5 {
            let mut handoff = h();
            match case {
                0 => handoff.replay_launch_authorized = true,
                1 => handoff.scratch_path = PathBuf::from("/other/scratch"),
                2 => handoff.producer_invocation_id = "x".repeat(32),
                3 => handoff.archive_directory = PathBuf::from("/other"),
                _ => handoff.new_resource_samples = 1,
            };
            assert!(apply(&model(), &handoff).is_err());
        }
        let mut adopted = apply(&model(), &h()).unwrap();
        adopted["ranges"][3]["epoch_additional_replay_slots"]["183"] = json!(0);
        assert!(apply(&adopted, &h()).is_err());
    }
    #[test]
    fn partial_and_overlapping_prior_claims_rejected() {
        let mut v = model();
        v["ranges"][0]["epochs"] = json!([152, 183]);
        assert!(apply(&v, &h()).is_err());
    }
    #[test]
    fn guard_receipt_requires_true_timer_fire_exact_owners_budget_and_one_worker() {
        let h = h();
        let good = json!({"schema":"jetstreamer-horizon-repair183-guard-first-fire-v1","admission":h.admission,"unit":GUARD,"invocation_id":"f".repeat(32),"actual_timer_fired_success":true,"exit_status":0,"restarts":0,"stop_intent_absent":true,"stop_completion_absent":true,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"sample":{"armed":true,"trip":false,"controller":{"active_state":"active","invocation_id":h.controller_invocation_id,"restarts":0},"producer":{"active_state":"active","invocation_id":h.producer_invocation_id,"restarts":0,"worker_count":1,"worker_vmas":1000},"minimum_free_bytes":GUARD_FLOOR,"available_bytes":GUARD_FLOOR+1,"maximum_worker_vmas":800000}});
        guard(&h, &good).unwrap();
        for path in [
            "/actual_timer_fired_success",
            "/stop_intent_absent",
            "/sample/armed",
            "/sample/controller/active_state",
            "/sample/producer/active_state",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = json!(false);
            assert!(guard(&h, &bad).is_err());
        }
        for (path, value) in [
            ("/sample/trip", json!(true)),
            ("/sample/producer/worker_count", json!(0)),
            ("/sample/producer/worker_vmas", json!(800001)),
            ("/sample/minimum_free_bytes", json!(GUARD_FLOOR - 1)),
            ("/sample/available_bytes", json!(GUARD_FLOOR - 1)),
            ("/sample/producer/invocation_id", json!("0".repeat(32))),
            ("/replay_launch_authorized", json!(true)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(guard(&h, &bad).is_err());
        }
    }
    #[test]
    fn initial_bootstrap_keeps_full_census_but_never_invents_a_rate_or_terminal() {
        let h = h();
        let point = |unit: &str, id: &str| json!({"unit":unit,"invocation_id":id,"restarts":0,"active_state":"active"});
        let worker =
            json!({"matching_workers":1,"executable_beneath_bound_scratch":true,"vmas":366000});
        let o = json!({"replays":[{"range":"183-184","scratch_path":h.scratch_path,"invocation_binding_stable":true,
            "controller_before":point(CONTROLLER,&h.controller_invocation_id),"controller_after":point(CONTROLLER,&h.controller_invocation_id),
            "producer_before":point(PRODUCER,&h.producer_invocation_id),"producer_after":point(PRODUCER,&h.producer_invocation_id),
            "worker_before":worker,"worker_after":worker,"useful_work":{"first":null,"last":null,"matching_markers":0,"counter_resets":0,"sufficient_for_rates":false,"slots_per_second":null}}]});
        let mut m = model();
        m["expected_observer_ranges"] = json!(["152-153", "155-156", "191-194"]);
        let filtered = observation(&m, &h, &o).unwrap();
        assert_eq!(filtered["ranges"], m["ranges"]);
        assert_eq!(
            filtered["expected_observer_ranges"]
                .as_array()
                .unwrap()
                .len(),
            4
        );
        assert_eq!(filtered["unestimated_bootstrap_epochs"], json!([183, 184]));
        for (path, value) in [
            ("/replays/0/useful_work/matching_markers", json!(1)),
            ("/replays/0/useful_work/counter_resets", json!(1)),
            ("/replays/0/useful_work/sufficient_for_rates", json!(true)),
            ("/replays/0/useful_work/slots_per_second", json!(1)),
            ("/replays/0/worker_after/matching_workers", json!(0)),
            ("/replays/0/worker_after/vmas", json!(800001)),
            ("/replays/0/producer_after/restarts", json!(1)),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(observation(&m, &h, &bad).is_err(), "{path}");
        }
        let mut advanced = apply(&m, &h).unwrap();
        advanced["ranges"][3]["terminal_slot"] = json!(FINAL_END);
        advanced["ranges"][3]["epoch_additional_replay_slots"] = json!({"183":0,"184":0});
        assert!(observation(&advanced, &h, &o).is_err());
    }
    #[test]
    fn epoch184_transition_preserves_gate_allowances_and_rejects_owner_reset() {
        let h = h();
        let point = |unit: &str, id: &str| json!({"unit":unit,"invocation_id":id,"restarts":0,"active_state":"active"});
        let mut o = json!({"replays":[{"range":"183-184","scratch_path":h.scratch_path,"invocation_binding_stable":true,"controller_before":point(CONTROLLER,&h.controller_invocation_id),"controller_after":point(CONTROLLER,&h.controller_invocation_id),"producer_before":point(PRODUCER,&h.producer_invocation_id),"producer_after":point(PRODUCER,&h.producer_invocation_id),"useful_work":{"last":{"terminal_slot":FINAL_END}}}]});
        let v = observation(&model(), &h, &o).unwrap();
        assert_eq!(
            v["ranges"][3]["epoch_additional_replay_slots"],
            json!({"183":0,"184":0})
        );
        assert_eq!(
            v["ranges"][3]["epoch_downstream_allowance_seconds"],
            json!({"183":43200,"184":86400})
        );
        o["replays"][0]["useful_work"]["last"]["terminal_slot"] = json!(FIRST_END);
        assert!(observation(&v, &h, &o).is_err());
        o["replays"][0]["useful_work"]["last"]["terminal_slot"] = json!(FINAL_END);
        o["replays"][0]["producer_after"]["restarts"] = json!(1);
        assert!(observation(&v, &h, &o).is_err());
    }
}
