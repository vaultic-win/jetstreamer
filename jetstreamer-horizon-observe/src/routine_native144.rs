//! Observe one guarded restore-only comparison while preserving prefix history.
//! This profile never supplies a production ETA or authorizes suffix execution.
use super::*;

pub(super) const UNIT: &str = "horizon-qualify-144-native-restore-20261021-v1.service";
const SCRATCH: &str = "/home/sol/.jetstreamer-private/epoch144-native-restore-20261021-v1/scratch";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-native144-observer-reader-20261021-v1/jetstreamer-r2";
const READER_SHA: &str = "70931d7eba634d1d31b3809fa267a3f6b60fea47f357399d9af371c80b29c5cd";
pub(super) fn reader() -> Bound {
    Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    invocation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    launch: Bound,
    event_fleet: Bound,
    event_plan: Bound,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}
pub(super) fn owner(p: &Plan, d: &DiagnosticClaim) -> bool {
    p.continuation144.is_none()
        && p.native144_restore.as_ref().is_some_and(|profile| {
            d.range == "144"
                && d.controller_unit == UNIT
                && d.producer_unit == UNIT
                && d.expected_controller_invocation_id == profile.invocation_id
                && d.expected_producer_invocation_id == profile.invocation_id
        })
}
pub(super) fn writer(p: &Plan) -> bool {
    p.native144_restore.is_some()
        && ((p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA)
            || public198::upload_writer(p))
        || continuation144::writer(p)
}
fn read(profile: &Profile) -> Result<(Value, Value)> {
    let launch = bound_json(&profile.launch, true)?;
    let event = bound_json(&profile.event_fleet, false)?;
    let plan = bound_json(&profile.event_plan, true)?;
    let guard_bound: Bound = serde_json::from_value(event["admission_transition_guard"].clone())?;
    // Guard receipts are root-private mode 0600, not immutable deployment members.
    let guard = bound_json(&guard_bound, false)?;
    checked(profile, &launch, &event, &plan, &guard)
}
fn checked(
    profile: &Profile,
    launch: &Value,
    event: &Value,
    plan: &Value,
    guard: &Value,
) -> Result<(Value, Value)> {
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch144-native-restore-launch-v2"
            && launch["epoch"] == 144
            && launch["unit"] == UNIT
            && launch["invocation_id"] == profile.invocation_id
            && launch["launched"] == true
            && profile.invocation_id.len() == 32
            && profile
                .invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && launch["native_probe_sha256"]
                == "a5f8dea7cf4beed6385c1b13719fd72bee3573162c3b303282f65bd2693e7237"
            && launch["input_policy_sha256"]
                == "908cb628fc955f0ac66692d2742b34c1422b3ad06130b8fc8b28a94efaee682f"
            && launch["snapshot_slot"] == 62639490
            && launch["maximum_runtime_seconds"] == 1800
            && launch["experimental_envelope_bytes"] == 40u64 << 30
            && launch["protected_existing_floor_bytes"] == 4_740_696_923_590u64,
        "native 144 launch differs"
    );
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "full_epoch_verified",
        "local_retirement_authorized",
        "replay_entries_authorized",
        "suffix_execution_authorized",
        "assembly_authorized",
        "canonical_sidecar_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            launch[flag] == false,
            "native 144 launch grants authority:{flag}"
        );
    }
    ensure!(
        event["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && event["first_epoch"] == 101
            && event["last_epoch"] == 200
            && event["producer_mutations"] == false
            && event["publication_authorized"] == false
            && event["remote_mutations"] == false
            && event["plan"].as_str() == profile.event_plan.path.to_str()
            && event["plan_sha256"] == profile.event_plan.sha256
            && plan["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
            && plan["first_epoch"] == 101
            && plan["last_epoch"] == 200
            && plan["admission_transition_guard"] == event["admission_transition_guard"]
            && event["observer_sha256"] == plan["observer"]["sha256"]
            && event["observer_receipt"] == plan["observer"]["path"]
            && event["previous_fleet"] == launch["previous_fleet"]
            && plan["previous_fleet"] == launch["previous_fleet"]
            && event["observer_sha256"] == launch["observer"]["sha256"]
            && guard["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && guard["producer_invocation_id"] == profile.invocation_id
            && guard["guard_sha256"]
                == "eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194"
            && guard.get("trip_reason").is_some_and(Value::is_null)
            && guard
                .get("worker_observation_error")
                .is_some_and(Value::is_null)
            && guard["producer"]["invocation_id"] == profile.invocation_id
            && guard["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && guard["producer"]["restarts"] == 0
            && guard["producer"]["active"] == "active"
            && guard["producer"]["sub"] == "running"
            && guard["producer"]["pid"].as_u64().is_some_and(|pid| pid > 0)
            && guard["remote_mutations"] == false
            && guard["r2_mutations"] == false
            && guard["maximum_worker_vmas"] == 3_500_000
            && guard["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|f| f >= 4_740_696_923_590)
            && guard["available_bytes"]
                .as_u64()
                .zip(guard["minimum_free_bytes"].as_u64())
                .is_some_and(|(f, n)| f >= n)
            && guard["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|pid| pid > 0)
                && w[0][1].as_u64().is_some_and(|v| v > 0 && v <= 3_500_000)),
        "native 144 requires genuine guarded admission event"
    );
    let expected = claim(profile);
    ensure!(
        plan["diagnostics"]
            .as_array()
            .context("native 144 plan history")?
            .iter()
            .filter(|d| d["unit"] == UNIT)
            .eq(std::iter::once(&expected))
            && event["diagnostics"]
                .as_array()
                .context("native 144 event history")?
                .iter()
                .filter(|d| d["unit"]["Id"] == UNIT
                    && d["launch_invocation_id"] == profile.invocation_id
                    && d["launch_receipt"].as_str() == profile.launch.path.to_str()
                    && d["launch_receipt_sha256"] == profile.launch.sha256)
                .count()
                == 1,
        "native 144 admission owner differs"
    );
    Ok((expected, event["admission_transition_guard"].clone()))
}
fn claim(profile: &Profile) -> Value {
    json!({"epoch":144,"unit":UNIT,"invocation_id":profile.invocation_id,
        "scratch_path":SCRATCH,"launch_receipt":profile.launch})
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    let Some(profile) = &p.native144_restore else {
        return Ok(());
    };
    ensure!(
        is_101(p)?
            && p.completed144_prefix.is_some()
            && p.prefix144_audit.is_none()
            && p.prefix157_audit.is_some()
            && p.runtime_handoff157.is_some()
            && p.public198_delivery.is_some()
            && public198::refreshed(p)
            && !p.expected_epochs.contains(&144)
            && writer(p)
            && p.scope_101_200
                .as_ref()
                .is_some_and(|s| s.private144_observer
                    && original141::retained144_census(p, s)
                    && (owner(p, &s.diagnostic_ranges[0])
                        || continuation144::owner(p, &s.diagnostic_ranges[0])
                        || assembly144::owner(p, &s.diagnostic_ranges[0]))),
        "foreign native 144 routine profile"
    );
    read(profile)?;
    Ok(())
}
pub(super) fn completed_transition(p: &Plan) -> Result<Option<(Value, Value)>> {
    p.native144_restore.as_ref().map(read).transpose()
}
pub(super) fn transition_template(p: &Plan, f: &Value) -> Result<bool> {
    Ok(completed_transition(p)?.is_some_and(|(_, guard)| f["admission_transition_guard"] == guard))
}
fn fold(f: &mut Value, expected: &Value, guard: &Value) -> Result<()> {
    ensure!(
        f["diagnostics"]
            .as_array()
            .context("native 144 template diagnostics")?
            .iter()
            .filter(|d| d["unit"] == UNIT)
            .eq(std::iter::once(expected)),
        "native 144 cannot replace or duplicate history"
    );
    ensure!(
        f["admission_transition_guard"].is_null() || f["admission_transition_guard"] == *guard,
        "native 144 cannot consume another admission guard"
    );
    f["admission_transition_guard"] = Value::Null;
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    continuation144::derive_fleet(p, f)?;
    if let Some((expected, guard)) = completed_transition(p)? {
        fold(f, &expected, &guard)?;
    }
    Ok(())
}
pub(super) fn observer(p: &Plan, value: &Value, observed: bool) -> Result<()> {
    let profile = p.native144_restore.as_ref().context("native 144 profile")?;
    ensure!(
        !value["replays"]
            .as_array()
            .context("native 144 ordinary census")?
            .iter()
            .any(|r| r["range"] == "144"),
        "native 144 ordinary claim forbidden"
    );
    let rows = value["diagnostic_replays"]
        .as_array()
        .context("native 144 diagnostic census")?;
    ensure!(rows.len() == 1, "native 144 diagnostic census differs");
    observer_row(&rows[0], &profile.invocation_id, observed)
}
fn observer_row(row: &Value, iid: &str, observed: bool) -> Result<()> {
    ensure!(
        row["range"] == "144"
            && row["producer_unit"] == UNIT
            && row["expected_producer_invocation_id"] == iid
            && row["scratch_path"] == SCRATCH,
        "native 144 observer owner/tree differs"
    );
    if !observed {
        ensure!(
            row["controller_unit"] == UNIT
                && row["expected_controller_invocation_id"] == iid
                && row["worker_executable_basename"] == "historical-worker"
                && row.get("append_log").is_none_or(Value::is_null),
            "native 144 config borrows legacy owner/log"
        );
        return Ok(());
    }
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            row[flag] == false,
            "native 144 observer grants authority:{flag}"
        );
    }
    match row["status"].as_str() {
        Some("unavailable") => ensure!(
            row["observation"].is_null()
                && row["error"].as_str().is_some_and(|s| !s.trim().is_empty()),
            "native 144 unavailable is not inactivity proof"
        ),
        Some("observed") => {
            let s = &row["observation"];
            ensure!(
                row["error"].is_null()
                    && s["range"] == "144"
                    && s["scratch_path"] == SCRATCH
                    && s["invocation_binding_stable"] == true,
                "native 144 observation differs"
            );
            for kind in ["controller", "producer"] {
                for point in ["before", "after"] {
                    let u = &s[format!("{kind}_{point}")];
                    ensure!(
                        u["invocation_id"] == iid
                            && u["restarts"] == 0
                            && matches!(u["active_state"].as_str(), Some("active" | "activating")),
                        "native 144 observation owner changed"
                    );
                }
            }
        }
        _ => anyhow::bail!("unknown native 144 diagnostic outcome"),
    }
    Ok(())
}
pub(super) fn enable(next: &mut Plan, config: &mut Value, spec: &Bound) -> Result<()> {
    ensure!(
        is_101(next)?
            && next.native144_restore.is_none()
            && next.completed144_prefix.is_some()
            && public198::refreshed(next),
        "native 144 requires unmigrated completed 144/native198 history"
    );
    let s: Spec = serde_json::from_slice(&bound_bytes(spec, true)?)?;
    ensure!(
        s.schema == "jetstreamer-horizon-native144-routine-spec-v1"
            && !s.replay_launch_authorized
            && !s.publication_authorized
            && !s.r2_mutations
            && s.event_fleet.path.parent() == Some(Path::new(FLEET_ROOT_101)),
        "native 144 spec scope or authority differs"
    );
    let event = bound_json(&s.event_fleet, false)?;
    let ep = bound_json(&s.event_plan, true)?;
    ensure!(
        event["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?
            && event["observer_sha256"] == next.previous_observer.sha256
            && event["sampled_at_utc"]
                == bound_json(&next.previous_observer, false)?["recorded_at_utc"]
            && ep["observer"] == serde_json::to_value(&next.previous_observer)?
            && ep["previous_fleet"] == serde_json::to_value(&next.previous_fleet)?,
        "native 144 event must follow exact completed predecessor"
    );
    let launch = bound_json(&s.launch, true)?;
    let iid = launch["invocation_id"]
        .as_str()
        .context("native 144 invocation")?
        .to_string();
    let scope = next.scope_101_200.as_mut().context("native 144 scope")?;
    migrate_observer(scope, config, &iid)?;
    next.previous_fleet = s.event_fleet.clone();
    next.fleet_template = s.event_plan.clone();
    next.native144_restore = Some(Profile {
        launch: s.launch,
        event_fleet: s.event_fleet,
        event_plan: s.event_plan,
        invocation_id: iid,
    });
    // The native observer envelope requires this qualified superset reader;
    // the older progressive reader understands claims but only the old owner envelope.
    next.tools.r2 = reader();
    next.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    validate(next)?;
    completed144::derive_fleet(next, &mut ep.clone())?;
    derive_fleet(next, &mut ep.clone())?;
    Ok(())
}

fn migrate_observer(scope: &mut Scope101200, config: &mut Value, iid: &str) -> Result<()> {
    let old = "horizon-qualify-epoch144-loader-focus-20261016-v1.service";
    ensure!(
        scope.private144_observer && scope.diagnostic_ranges.len() == 1,
        "native 144 original observer scope absent"
    );
    let owner = &scope.diagnostic_ranges[0];
    ensure!(
        owner.range == "144"
            && owner.controller_unit == old
            && owner.producer_unit == old
            && owner.expected_controller_invocation_id == private144::INVOCATION
            && owner.expected_producer_invocation_id == private144::INVOCATION,
        "native 144 cannot replace a newer observer owner"
    );
    let rows = config["diagnostic_replays"]
        .as_array_mut()
        .context("native 144 original diagnostic")?;
    ensure!(
        rows.len() == 1
            && rows[0]["range"] == "144"
            && rows[0]["controller_unit"] == old
            && rows[0]["producer_unit"] == old
            && rows[0]["expected_controller_invocation_id"] == private144::INVOCATION
            && rows[0]["expected_producer_invocation_id"] == private144::INVOCATION,
        "native 144 must migrate only original terminal diagnostic observer"
    );
    rows[0] = json!({"range":"144","controller_unit":UNIT,"producer_unit":UNIT,
        "expected_controller_invocation_id":iid,"expected_producer_invocation_id":iid,
        "scratch_path":SCRATCH,"worker_executable_basename":"historical-worker"});
    scope.diagnostic_ranges[0] = DiagnosticClaim {
        range: "144".into(),
        controller_unit: UNIT.into(),
        producer_unit: UNIT.into(),
        expected_controller_invocation_id: iid.into(),
        expected_producer_invocation_id: iid.into(),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        let b = |p: &str| Bound {
            path: p.into(),
            sha256: "a".repeat(64),
        };
        Profile {
            launch: b("/launch"),
            event_fleet: b("/event"),
            event_plan: b("/event-plan"),
            invocation_id: "b".repeat(32),
        }
    }
    fn fixture() -> (Profile, Value, Value, Value, Value) {
        let p = profile();
        let mut launch = json!({"schema":"jetstreamer-private-epoch144-native-restore-launch-v2",
            "epoch":144,"unit":UNIT,"invocation_id":p.invocation_id,"launched":true,
            "native_probe_sha256":"a5f8dea7cf4beed6385c1b13719fd72bee3573162c3b303282f65bd2693e7237",
            "input_policy_sha256":"908cb628fc955f0ac66692d2742b34c1422b3ad06130b8fc8b28a94efaee682f",
            "snapshot_slot":62639490,"maximum_runtime_seconds":1800,"experimental_envelope_bytes":40u64<<30,
            "protected_existing_floor_bytes":4740696923590u64,
            "previous_fleet":{"path":"/prior","sha256":"c".repeat(64)},"observer":{"path":"/observer","sha256":"d".repeat(64)}});
        for flag in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "full_epoch_verified",
            "local_retirement_authorized",
            "replay_entries_authorized",
            "suffix_execution_authorized",
            "assembly_authorized",
            "canonical_sidecar_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            launch[flag] = json!(false);
        }
        let guard = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1",
            "producer_invocation_id":p.invocation_id,
            "guard_sha256":"eca429932ffe9afe71aecba815ab301db46bdddbaf24b4c44af8c88bb74a6194",
            "trip_reason":null,"worker_observation_error":null,"workers":[[123,500]],
            "producer":{"invocation_id":p.invocation_id,"cgroup":format!("/system.slice/{UNIT}"),"restarts":0,"active":"active","sub":"running","pid":123},
            "remote_mutations":false,"r2_mutations":false,"maximum_worker_vmas":3500000,
            "minimum_free_bytes":4740696923590u64,"available_bytes":4740696923591u64});
        let event = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "producer_mutations":false,"publication_authorized":false,"remote_mutations":false,
            "plan":p.event_plan.path,"plan_sha256":p.event_plan.sha256,
            "observer_sha256":launch["observer"]["sha256"],"observer_receipt":"/observer","previous_fleet":launch["previous_fleet"],
            "admission_transition_guard":{"path":"/guard","sha256":"e".repeat(64)},
            "diagnostics":[{"epoch":144,"unit":{"Id":UNIT},"launch_invocation_id":p.invocation_id,"launch_receipt":"/launch","launch_receipt_sha256":p.launch.sha256}]});
        let plan = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1","first_epoch":101,"last_epoch":200,
            "admission_transition_guard":event["admission_transition_guard"],"observer":launch["observer"],
            "previous_fleet":launch["previous_fleet"],"diagnostics":[claim(&p)]});
        (p, launch, event, plan, guard)
    }
    #[test]
    fn binding_rejects_other_predecessor_launch_guard_or_publication_authority() {
        let (p, launch, event, plan, guard) = fixture();
        checked(&p, &launch, &event, &plan, &guard).unwrap();
        for (key, value) in [
            ("snapshot_slot", json!(62639999)),
            ("suffix_execution_authorized", json!(true)),
            ("publication_authorized", json!(true)),
            ("invocation_id", json!("c".repeat(32))),
        ] {
            let mut bad = launch.clone();
            bad[key] = value;
            assert!(checked(&p, &bad, &event, &plan, &guard).is_err(), "{key}");
        }
        for (key, value) in [
            ("plan_sha256", json!("f".repeat(64))),
            ("observer_sha256", json!("f".repeat(64))),
            ("previous_fleet", json!({})),
            ("admission_transition_guard", Value::Null),
            ("publication_authorized", json!(true)),
        ] {
            let mut bad = event.clone();
            bad[key] = value;
            assert!(checked(&p, &launch, &bad, &plan, &guard).is_err(), "{key}");
        }
        for (key, value) in [
            ("workers", json!([])),
            ("workers", json!([[1, 2], [3, 4]])),
            ("workers", json!([[1, 3500001]])),
            ("worker_observation_error", json!("unreadable")),
            ("trip_reason", json!("disk")),
            ("minimum_free_bytes", json!(1)),
            ("available_bytes", json!(1)),
            ("guard_sha256", json!("f".repeat(64))),
        ] {
            let mut bad = guard.clone();
            bad[key] = value;
            assert!(checked(&p, &launch, &event, &plan, &bad).is_err(), "{key}");
        }
    }
    #[test]
    fn diagnostic_fold_is_idempotent_and_preserves_prefixes_and_consensus_integers() {
        let p = profile();
        let claim = claim(&p);
        let guard = json!({"proof":"native guard"});
        let mut f = json!({"diagnostics":[{"epoch":144,"unit":"old-prefix.service","counter":u64::MAX},
            {"epoch":157,"counter":u64::MAX-1},claim],"admission_transition_guard":guard,"gates":{"144":{"counter":u64::MAX}}});
        let before = f.clone();
        fold(&mut f, &claim, &guard).unwrap();
        assert_eq!(f["diagnostics"], before["diagnostics"]);
        assert_eq!(f["gates"], before["gates"]);
        let once = f.clone();
        fold(&mut f, &claim, &guard).unwrap();
        assert_eq!(f, once);
        for kind in ["owner", "duplicate", "guard"] {
            let mut bad = f.clone();
            match kind {
                "owner" => bad["diagnostics"][2]["invocation_id"] = json!("wrong"),
                "duplicate" => bad["diagnostics"]
                    .as_array_mut()
                    .unwrap()
                    .push(claim.clone()),
                _ => bad["admission_transition_guard"] = json!({"foreign":"guard"}),
            };
            assert!(fold(&mut bad, &claim, &guard).is_err(), "{kind}");
        }
    }
    #[test]
    fn observer_migration_changes_only_exact_diagnostic_owner_and_discards_old_append_log() {
        let (mut p, _, _, _, _, _, _, _) = crate::tests::fixture101();
        let scope = p.scope_101_200.as_mut().unwrap();
        scope.private144_observer = true;
        scope.diagnostic_ranges[0].expected_controller_invocation_id =
            private144::INVOCATION.into();
        scope.diagnostic_ranges[0].expected_producer_invocation_id = private144::INVOCATION.into();
        let mut config = json!({"replays":[{"counter":u64::MAX}],"diagnostic_replays":[serde_json::to_value(&scope.diagnostic_ranges[0]).unwrap()],"previous_sample":"keep"});
        config["diagnostic_replays"][0]["append_log"] = json!({"path":"/old/log","inode":u64::MAX});
        let before = config.clone();
        let iid = "b".repeat(32);
        migrate_observer(scope, &mut config, &iid).unwrap();
        observer_row(&config["diagnostic_replays"][0], &iid, false).unwrap();
        assert!(config["diagnostic_replays"][0].get("append_log").is_none());
        assert_eq!(config["replays"], before["replays"]);
        assert_eq!(config["previous_sample"], before["previous_sample"]);
        assert!(
            migrate_observer(scope, &mut config, &iid).is_err(),
            "must not replace newer owner"
        );
        p.native144_restore = Some(profile());
        p.tools.r2 = Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        };
        assert!(is_101(&p).unwrap());
        assert!(writer(&p));
        p.native144_restore = None;
        assert!(!writer(&p));
        assert!(is_101(&p).is_err());
    }
    #[test]
    fn unavailable_native_diagnostic_never_proves_completion_or_a_live_eta() {
        let p = profile();
        let row = json!({"range":"144","producer_unit":UNIT,"expected_producer_invocation_id":p.invocation_id,
            "scratch_path":SCRATCH,"status":"unavailable","observation":null,"error":"terminal or unreadable",
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        observer_row(&row, &p.invocation_id, true).unwrap();
        for key in [
            "ordinary_replay_claim",
            "current_sidecar_eta_valid",
            "publication_authorized",
        ] {
            let mut bad = row.clone();
            bad[key] = json!(true);
            assert!(observer_row(&bad, &p.invocation_id, true).is_err());
        }
        let mut bad = row;
        bad["error"] = json!("");
        assert!(observer_row(&bad, &p.invocation_id, true).is_err());
    }
}
