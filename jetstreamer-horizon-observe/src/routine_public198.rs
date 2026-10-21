//! Public198 verification ownership and honest promotion of the partial20:18 cycle.
use super::*;
pub(super) const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch198-public-watch-reader-20261021-v2/jetstreamer-r2";
pub(super) const READER_SHA: &str =
    "d00bb3eb69491065694d0a6679c30e2b759df133000cc7cafd0f480afc7aaea5";
const ROOT: &str = "/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/20261021T201800Z-delivery198-completed144-v1";
const FULL: &str = "jetstreamer-horizon-audit-epochs182-200-v5.service";
const PLUGIN: &str = "jetstreamer-horizon-plugin-receipt-watcher-shard-e-v5-fsync.service";
const NATIVE_RUNNER: &str = "/usr/local/lib/jetstreamer/horizon-epoch198-native-verification-runner-20261021-v1/jetstreamer-horizon-verify-pair";
const NATIVE_RUNNER_SHA: &str = "e225f8309d19af230cc189ab6e43296d37795693085299c269ab51af6991ab39";
const ORIGIN: &str =
    "jetstreamer-root-sweep-e198-readerfix-20261019-v1-r2-e198-198-lane-a-1.service";
const IID: &str = "e5612ef00a5b4fcab04df2c13a6b35b0";
const IMPORT: &str = "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1-import/destination-ae2f530244e391ea343ca338abe7f4673c52fd4bc8814369fd5234d07a8db1e1/evidence/archive-batches/destination-000000000000fc00-0000000011520001/batch-b1dbb924f902ff4ad61ff937a96b2564566885d6eb950d8d5bf543f939ef9039.json";
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    promotion: Bound,
    origin: Bound,
    claims: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    native_verification: Vec<Bound>,
}

pub(super) fn native(p: &Plan) -> bool {
    p.public198_delivery
        .as_ref()
        .is_some_and(|p| !p.native_verification.is_empty())
}

pub(super) fn refreshed(p: &Plan) -> bool {
    p.public198_delivery.as_ref().is_some_and(|p| {
        p.native_verification.iter().any(|b| {
            b.path
                .starts_with("/var/lib/jetstreamer/horizon-epoch198-manager-refresh-20261021-v1")
        })
    })
}

fn manager_command_matches(old: &str, new: &str) -> bool {
    old.split_once(" ; ignore_errors=")
        .zip(new.split_once(" ; ignore_errors="))
        .is_some_and(|(a, b)| a.0 == b.0 && a.1.starts_with("no ;") && b.1.starts_with("no ;"))
}
pub(super) fn refresh_managers(p: &Plan, spec: &Bound) -> Result<()> {
    ensure!(
        is_101(p)?
            && p.sample_target_utc == "2026-10-21T21:28:00Z"
            && spec.sha256 == "89b55302366b2e027dd98a83a690f061f66e4ba0f3b065aa7bfc6e894ff12346",
        "foreign native198 manager refresh"
    );
    authenticate_named_service("horizon-native198-manager-refresh-20261021-v1.service")?;
    let mut copy: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    enable_native(&mut copy, spec)?;
    let profile = copy
        .public198_delivery
        .as_ref()
        .context("native198 refresh profile")?;
    let root = Path::new("/var/lib/jetstreamer/horizon-epoch198-manager-refresh-20261021-v1");
    absent(root)?;
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    File::open(root.parent().context("refresh parent")?)?.sync_all()?;
    let mut launches = Vec::new();
    for original in &profile.native_verification {
        let mut value = bound_json(original, false)?;
        let unit = value["claim"]["unit"].as_str().context("refresh unit")?;
        let output = Command::new("/usr/bin/systemctl").args(["show",unit,"--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,InvocationID,ExecStart,Type,Result,ControlGroup"]).output()?;
        ensure!(
            output.status.success() && output.stdout.len() < 16384,
            "cannot refresh native198 manager properties"
        );
        let mut fresh = serde_json::Map::new();
        for line in std::str::from_utf8(&output.stdout)?.lines() {
            let (key, value) = line.split_once('=').context("refresh property")?;
            ensure!(
                fresh.insert(key.into(), json!(value)).is_none(),
                "duplicate refresh property"
            );
        }
        let fresh = Value::Object(fresh);
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "MainPID",
            "NRestarts",
            "InvocationID",
            "Type",
            "Result",
            "ControlGroup",
        ] {
            ensure!(
                fresh[key] == value["unit"][key],
                "native198 {key} changed, not command metadata refresh"
            );
        }
        let old_command = value["unit"]["ExecStart"]
            .as_str()
            .context("old refresh command")?;
        let new_command = fresh["ExecStart"].as_str().context("new refresh command")?;
        ensure!(
            manager_command_matches(old_command, new_command),
            "native198 executable arguments or ignore-errors changed"
        );
        value["unit"] = fresh.clone();
        value["claim"]["expected_exec_start"] = fresh["ExecStart"].clone();
        value["manager_refresh"] = json!({"previous_launch":original,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"same_invocation_and_pid":true,"executable_arguments_unchanged":true,"new_launch":false});
        let phase = value["claim"]["phase"].as_str().context("refresh phase")?;
        launches.push(write_new(&root.join(format!("{phase}.json")), &value)?);
    }
    let bound = write_new(
        &root.join("spec.json"),
        &json!({"schema":"horizon-native198-verification-handoff-v1","launches":launches,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!("{} {}", bound.path.display(), bound.sha256);
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSpec {
    schema: String,
    launches: Vec<Bound>,
    publication_authorized: bool,
    r2_mutations: bool,
}

fn claims(profile: &Profile) -> Result<Vec<Value>> {
    if profile.native_verification.is_empty() {
        return Ok(profile.claims.clone());
    }
    ensure!(
        profile.native_verification.len() == 2,
        "native198 must bind both stages"
    );
    let mut claims = Vec::new();
    let mut phases = BTreeSet::new();
    for b in &profile.native_verification {
        let receipt = bound_json(b, false)?;
        let claim = &receipt["claim"];
        let (suffix, expected_phase) = match claim["phase"].as_str() {
            Some("full-verification") => ("full", "full-verification"),
            Some("plugin-verification") => ("plugin", "plugin-verification"),
            _ => anyhow::bail!("foreign native198 phase"),
        };
        let unit = format!("horizon-{suffix}-verify-198-native-20261021-v1.service");
        ensure!(
            receipt["schema"] == "horizon-epoch198-native-verification-launch-v1"
                && receipt["epoch"] == 198
                && claim["epoch"] == 198
                && claim["unit"] == unit
                && receipt["unit"]["Id"] == unit
                && receipt["unit"]["InvocationID"] == claim["invocation_id"]
                && receipt["unit"]["ExecStart"] == claim["expected_exec_start"]
                && receipt["unit"]["NRestarts"] == "0"
                && receipt["unit"]["ActiveState"] == "active"
                && receipt["unit"]["SubState"] == "running"
                && receipt["unit"]["Type"] == "exec"
                && receipt["runner_sha256"] == NATIVE_RUNNER_SHA
                && receipt["verification_complete"] == false
                && receipt["local_retirement_authorized"] == false
                && receipt["publication_authorized"] == false
                && receipt["r2_mutations"] == false
                && phases.insert(expected_phase),
            "invalid native198 launch proof"
        );
        let plan: Bound = serde_json::from_value(receipt["plan"].clone())?;
        let value = bound_json(&plan, true)?;
        let command = format!(
            "{{ path={NATIVE_RUNNER} ; argv[]={NATIVE_RUNNER} {} {} {NATIVE_RUNNER_SHA} ; ignore_errors=",
            plan.path.display(),
            plan.sha256
        );
        ensure!(
            value["schema"] == "horizon-verify-canonical-pair-dev-samjohnson198-v1"
                && value["epoch"] == 198
                && value["stage"] == suffix
                && value["archive_directory"] == "/home/sol/horizon"
                && value["expected_archive_sha256"]
                    == "4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb",
            "native198 plan differs"
        );
        ensure!(
            receipt["unit"]["ExecStart"]
                .as_str()
                .is_some_and(|s| s.starts_with(&command))
                && receipt["admission_observer"] == value["admission_observer"],
            "native198 executable or admission differs"
        );
        tool_ok(&Bound {
            path: NATIVE_RUNNER.into(),
            sha256: NATIVE_RUNNER_SHA.into(),
        })?;
        let mut claim = claim.clone();
        claim["evidence"]
            .as_array_mut()
            .context("native198 evidence")?
            .push(serde_json::to_value(b)?);
        claims.push(claim);
    }
    Ok(claims)
}

pub(super) fn enable_native(p: &mut Plan, spec: &Bound) -> Result<()> {
    let value: NativeSpec = serde_json::from_value(bound_json(spec, true)?)?;
    ensure!(
        value.schema == "horizon-native198-verification-handoff-v1"
            && !value.publication_authorized
            && !value.r2_mutations,
        "foreign native198 handoff"
    );
    let profile = p
        .public198_delivery
        .as_mut()
        .context("native198 requires prior public handoff")?;
    ensure!(
        profile.native_verification.is_empty(),
        "native198 already migrated"
    );
    profile.native_verification = value.launches;
    claims(profile)?;
    Ok(())
}

/// A phase-handoff event reuses the current coordinated resource sample, never
/// resamples or rewrites the canonical fleet/completion chain. Its complete
/// private census is current service/remote evidence for this one status update.
fn event_scope(
    sample: &str,
    plan_sha: &str,
    spec_sha: &str,
    writer: bool,
    already_native: bool,
) -> Result<()> {
    ensure!(
        writer
            && !already_native
            && sample == "2026-10-21T21:28:00Z"
            && plan_sha == "fdb0c0185f0c73ebe5f4b70cca5e45fb8508afc506e9ec61424c1de5bfea654c"
            && matches!(
                spec_sha,
                "89b55302366b2e027dd98a83a690f061f66e4ba0f3b065aa7bfc6e894ff12346"
                    | "f3a42392d656d183353461f4216d912f49e5a0613bbdf01e825e9c650f5a92f6"
            ),
        "foreign native198 status event"
    );
    Ok(())
}
pub(super) fn native_event(p: &Plan, pb: &Bound, spec: &Bound, self_sha: &str) -> Result<()> {
    ensure!(is_101(p)?, "foreign native198 campaign");
    event_scope(
        &p.sample_target_utc,
        &pb.sha256,
        &spec.sha256,
        writer(p),
        native(p),
    )?;
    let endpoint = env::var("HORIZON_S3_ENDPOINT").context("storage endpoint missing")?;
    ensure!(
        sha(endpoint.as_bytes()) == p.endpoint_sha256 && p.bucket == BUCKET,
        "status event endpoint differs"
    );
    let refreshed =
        spec.sha256 == "f3a42392d656d183353461f4216d912f49e5a0613bbdf01e825e9c650f5a92f6";
    let invocation = authenticate_named_service(if refreshed {
        "horizon-native198-status-handoff-20261021-v2.service"
    } else {
        "horizon-native198-status-handoff-20261021-v1.service"
    })?;
    let cb = file(p.cycle_directory.join("completion.json"), false)?;
    ensure!(
        cb.sha256 == "8e26cd0f9975f2978a57baff0b1641e96f4c58eae3af45c4b3e43daaf6969fb4",
        "accepted21:28 completion differs"
    );
    let completion = bound_json(&cb, false)?;
    next_preparation::completion_bindings(p, pb, &completion)?;
    let observer: Bound = serde_json::from_value(completion["observer"].clone())?;
    let sample = bound_json(&observer, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let seconds = utc_seconds(&p.sample_target_utc)?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && sample["recorded_at_utc"] == p.sample_target_utc
            && now >= seconds
            && now - seconds <= 1800,
        "status event resource evidence expired"
    );
    let source: Bound = serde_json::from_value(completion["fleet_plan"].clone())?;
    let mut fleet = bound_json(&source, true)?;
    let mut event: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    enable_native(&mut event, spec)?;
    derive_fleet(&event, &mut fleet)?;
    event.cycle_directory = p.cycle_directory.join(if refreshed {
        "native198-status-event-v2"
    } else {
        "native198-status-event-v1"
    });
    absent(&event.cycle_directory)?;
    fs::create_dir(&event.cycle_directory)?;
    fs::set_permissions(&event.cycle_directory, fs::Permissions::from_mode(0o700))?;
    File::open(&p.cycle_directory)?.sync_all()?;
    write_new(
        &event.cycle_directory.join("intent.json"),
        &json!({"schema":"horizon-native198-status-event-intent-v1","source_plan":pb,"source_completion":cb,"handoff":spec,"invocation_id":invocation,"self_sha256":self_sha,"coordinated_observer":observer,"new_resource_samples":0,"canonical_fleet_changed":false,"archive_mutations":false,"sidecar_mutations":false}),
    )?;
    let result = publish(&event, &fleet, &observer)?;
    ensure!(
        result["publication_skipped"] != true && !result["publication"].is_null(),
        "native198 status event did not publish; preserve partial evidence"
    );
    write_new(
        &event.cycle_directory.join("completion.json"),
        &json!({"schema":"horizon-native198-status-event-completion-v1","source_plan":pb,"source_completion":cb,"handoff":spec,"invocation_id":invocation,"self_sha256":self_sha,"result":result,"new_resource_samples":0,"canonical_fleet_changed":false,"replay_status_updates":0,"archive_mutations":false,"sidecar_mutations":false,"r2_status_mutation":true}),
    )?;
    Ok(())
}
fn file(path: PathBuf, immutable: bool) -> Result<Bound> {
    let bytes = read_checked(&path, LIMIT, 0, immutable)?;
    Ok(Bound {
        path,
        sha256: sha(&bytes),
    })
}
pub(super) fn writer(p: &Plan) -> bool {
    p.tools.r2.path == Path::new(READER) && p.tools.r2.sha256 == READER_SHA
}
fn import_proof() -> Result<()> {
    ensure!(
        sha(&read_checked(Path::new(IMPORT), LIMIT, 1001, false)?)
            == "4a35dc14d303fd3c39e256d02346f9f675f67033103046e0c1b182d7c5db3ad7",
        "198 durable import receipt changed"
    );
    Ok(())
}
fn read(profile: &Profile) -> Result<Value> {
    let value = bound_json(&profile.promotion, false)?;
    ensure!(
        value["schema"] == "jetstreamer-public198-partial-promotion-v1"
            && value["new_resource_samples"] == 0
            && value["archive_mutations"] == false
            && value["origin"] == serde_json::to_value(&profile.origin)?
            && value["claims"] == json!(profile.claims),
        "198 public profile differs"
    );
    import_proof()?;
    Ok(value)
}
pub(super) fn promoted(p: &Plan, c: &Value) -> Result<bool> {
    let Some(value) = c.get("public198_promotion") else {
        return Ok(false);
    };
    let bound: Bound = serde_json::from_value(value.clone())?;
    ensure!(
        p.cycle_directory == Path::new(ROOT)
            && bound.path == Path::new(ROOT).join("public198-promotion-v1/intent.json")
            && c["fleet_plan"]["path"]
                == json!(Path::new(ROOT).join("delivery198-stage/sealed/fleet-plan.json"))
            && c["epoch198_delivery"].is_null(),
        "foreign partial198 promotion"
    );
    let value = bound_json(&bound, false)?;
    ensure!(
        value["schema"] == "jetstreamer-public198-partial-promotion-v1"
            && value["observer"]["sha256"]
                == "a875e052381e1fdf0aee6e1e847649a0c99b808f77a27e20937e895a303f3e03"
            && value["new_resource_samples"] == 0
            && value["archive_mutations"] == false,
        "invalid198 promotion proof"
    );
    Ok(true)
}
pub(super) fn consume(p: &mut Plan, c: &Value, config: &mut Value) -> Result<()> {
    let promotion: Bound = serde_json::from_value(c["public198_promotion"].clone())?;
    let value = bound_json(&promotion, false)?;
    p.public198_delivery = Some(Profile {
        promotion,
        origin: serde_json::from_value(value["origin"].clone())?,
        claims: serde_json::from_value(value["claims"].clone())?,
        native_verification: Vec::new(),
    });
    p.epoch198_delivery = None;
    p.tools.r2 = Bound {
        path: READER.into(),
        sha256: READER_SHA.into(),
    };
    ensure!(
        p.sample_target_utc == "2026-10-21T20:48:00Z",
        "198 initial public recovery target differs"
    );
    for path in [&mut p.observer, &mut p.estimate_output, &mut p.fleet_output] {
        *path = PathBuf::from(
            path.to_str()
                .context("198 recovery path")?
                .replace("20261021T204800Z", "20261021T205800Z"),
        );
    }
    p.sample_target_utc = "2026-10-21T20:58:00Z".into();
    config["not_before_utc"] = json!(p.sample_target_utc);
    config["output"] = json!(p.observer);
    p.observer_config.sha256 = sha(&next_preparation::encoded(config)?);
    read(p.public198_delivery.as_ref().unwrap())?;
    Ok(())
}
pub(super) fn interval(p: &Plan) -> Result<Option<u64>> {
    if p.public198_delivery.is_some() && p.sample_target_utc == "2026-10-21T20:58:00Z" {
        ensure!(
            p.previous_observer.sha256
                == "a875e052381e1fdf0aee6e1e847649a0c99b808f77a27e20937e895a303f3e03",
            "198 public recovery predecessor differs"
        );
        return Ok(Some(2400));
    }
    Ok(None)
}
pub(super) fn namespaces(p: &mut Plan, observer: &mut PathBuf, cycle: &mut PathBuf) -> Result<()> {
    let stamp = stamp(&p.sample_target_utc);
    *observer = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-next-observer-101-200-{stamp}-{}",
        generation_101(p)
    ));
    *cycle = Path::new("/var/lib/jetstreamer").join(format!(
        "horizon-routine-plan-101-200-{stamp}-{}",
        generation_101(p)
    ));
    p.observer_config.path = observer.join("observer.json");
    p.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2")
        .join(format!("{stamp}-{}", generation_101(p)));
    p.cycle_unit = cycle_unit(p)?;
    p.scope_101_200
        .as_mut()
        .context("198 campaign")?
        .additional_tracked_units = vec![p.cycle_unit.clone()];
    Ok(())
}
fn fold(fleet: &mut Value, profile: &Profile) -> Result<()> {
    let rows = fleet["pipeline_claims"]
        .as_array_mut()
        .context("198 pipeline claims")?;
    rows.retain(|c| c["epoch"] != 198);
    let claims = claims(profile)?;
    rows.extend(claims.clone());
    for name in [FULL, PLUGIN] {
        let units = fleet["tracked_units"]
            .as_array_mut()
            .context("198 tracked watchers")?;
        if !units.contains(&json!(name)) {
            units.push(json!(name));
        }
    }
    for claim in &claims {
        let units = fleet["tracked_units"]
            .as_array_mut()
            .context("native198 tracked units")?;
        if !units.contains(&claim["unit"]) {
            units.push(claim["unit"].clone());
        }
    }
    fleet["gates"]["198"]["state"] = json!("post-replay-pipeline");
    fleet["gates"]["198"]["next_action"] = json!(
        "Imported198 is public locally; authenticate real198 full/plugin watcher children, publish verification ETA when active, preserve original43200second downstream deadline and receipt-gated R2 publication. Inactive stages must not retain a live countdown."
    );
    let evidence = fleet["gates"]["198"]["evidence"]
        .as_array_mut()
        .context("198 evidence")?;
    let bound = serde_json::to_value(&profile.promotion)?;
    if !evidence.contains(&bound) {
        evidence.push(bound);
    }
    Ok(())
}
pub(super) fn derive_fleet(p: &Plan, fleet: &mut Value) -> Result<()> {
    let Some(profile) = &p.public198_delivery else {
        return Ok(());
    };
    ensure!(
        writer(p) && p.epoch198_delivery.is_none() && !p.expected_epochs.contains(&198),
        "198 public profile overlaps replay/import"
    );
    read(profile)?;
    fold(fleet, profile)
}
pub(super) fn promote(p: &Plan, pb: &Bound, self_sha: &str) -> Result<()> {
    ensure!(
        p.cycle_directory == Path::new(ROOT)
            && pb.sha256 == "5820b69150677bd27c3a2dc18d8d101332c556b3e3078bd37281d409ee7e4014",
        "foreign198 promotion"
    );
    let invocation =
        authenticate_named_service("horizon-public198-promote-partial2018-20261021-v3.service")?;
    import_proof()?;
    let m = fs::symlink_metadata("/home/sol/horizon/epoch-198.jet")?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() == 99381250591 && m.mode() & 0o222 == 0,
        "198 promotion archive changed"
    );
    absent(&p.cycle_directory.join("completion.json"))?;
    ensure!(
        file(p.cycle_directory.join("failure.json"), false)?.sha256
            == "afc84dc94ebf5b8a6267a4ebf3232cdc8f36100be9cb69fe933c05eeded7f99b",
        "198 original failure changed"
    );
    let observer = file(p.observer.clone(), false)?;
    ensure!(
        observer.sha256 == "a875e052381e1fdf0aee6e1e847649a0c99b808f77a27e20937e895a303f3e03",
        "198 partial sample changed"
    );
    let model = file(p.cycle_directory.join("sealed/eta-model.json"), true)?;
    let estimates = file(p.estimate_output.clone(), false)?;
    let entries = verify_estimates(
        p,
        &bound_json(&model, true)?,
        &observer,
        &bound_json(&estimates, false)?,
    )?;
    let mut statuses = Vec::new();
    for e in entries {
        let epoch = e["epoch"].as_u64().context("198 peer epoch")?;
        let b = file(
            PathBuf::from(format!(
                "/home/sol/.jetstreamer-private/r2-status-receipts/epoch-{epoch}.status-20261021201800.json"
            )),
            false,
        )?;
        next_preparation::validate_status(&bound_json(&b, false)?, p, &observer, &e)?;
        statuses.push(b);
    }
    let origin = file(
        PathBuf::from(
            "/home/sol/.jetstreamer-private/r2-status-receipts/epoch-198.status-20261021193800.json",
        ),
        false,
    )?;
    ensure!(
        origin.sha256 == "3c69729b02f5d3d3b3c9658e19a6915b6fece5419f0de23cf2383f7d07ae21fa",
        "198 original clock receipt changed"
    );
    let mut claims = Vec::new();
    for (phase, name, iid) in [
        (
            "full-verification",
            FULL,
            "4dc3b0631e2646cca4302e6ee8807479",
        ),
        (
            "plugin-verification",
            PLUGIN,
            "db3c2cdb0f4f4572ae0cdf0ce64048bf",
        ),
    ] {
        let output = Command::new("systemctl")
            .args(["show", name, "--value", "--property=ExecStart"])
            .output()?;
        ensure!(output.status.success(), "198 watcher command missing");
        claims.push(json!({"epoch":198,"phase":phase,"unit":name,"invocation_id":iid,"expected_exec_start":std::str::from_utf8(&output.stdout)?.trim_end(),"evidence":[{"path":IMPORT,"sha256":"4a35dc14d303fd3c39e256d02346f9f675f67033103046e0c1b182d7c5db3ad7"},origin]}));
    }
    let root = p.cycle_directory.join("public198-promotion-v1");
    let intended = json!({"schema":"jetstreamer-public198-partial-promotion-v1","origin":origin,"claims":claims,"observer":observer,"failed_plan":pb,"new_resource_samples":0,"archive_mutations":false,"replay_launch_authorized":false,"stale198_status_repair_required":true});
    let promotion = if root.exists() {
        let existing = file(root.join("intent.json"), false)?;
        ensure!(
            bound_json(&existing, false)? == intended,
            "198 promotion resume intent differs"
        );
        existing
    } else {
        fs::create_dir(&root)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        File::open(&p.cycle_directory)?.sync_all()?;
        write_new(&root.join("intent.json"), &intended)?
    };
    // Promote the genuine in-window inventory byte-for-byte as history. Never
    // run today's owners against an expired resource sample or backdate them.
    let historical = file(
        p.cycle_directory.join("delivery198-provisional-fleet.json"),
        false,
    )?;
    let ledger = bound_json(&historical, false)?;
    let result = bound_json(
        &file(
            p.cycle_directory.join("child-delivery198-fleet.json"),
            false,
        )?,
        false,
    )?;
    ensure!(
        result["success"] == true
            && result["tool"]["sha256"]
                == "992d06b9f4b76bd4beecfd9be9572f780131e0c57e1f5618aebaf9fb362dc398"
            && ledger["sampled_at_utc"] == p.sample_target_utc
            && ledger["observer_sha256"] == observer.sha256
            && ledger["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|n| (1792613880..=1792615680).contains(&n))
            && ledger["inventory"]["anomalies"] == 0,
        "198 historical inventory lacks original in-window success"
    );
    let fleet_plan = file(
        p.cycle_directory
            .join("delivery198-stage/sealed/fleet-plan.json"),
        true,
    )?;
    ensure!(
        ledger["plan_sha256"] == fleet_plan.sha256,
        "198 historical fleet plan differs"
    );
    latest_fleet_unchanged(p, &bound_json(&p.previous_fleet, false)?)?;
    absent(&p.fleet_output)?;
    let bytes = read_checked(&historical.path, LIMIT, 0, false)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&p.fleet_output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    File::open(
        p.fleet_output
            .parent()
            .context("198 canonical fleet parent")?,
    )?
    .sync_all()?;
    write_new(
        &root.join("historical-checkpoint.json"),
        &json!({"source":historical,"canonical_output":p.fleet_output,"preserved_bytes_sha256":sha(&bytes),"sample_timestamp_preserved":true,"new_resource_samples":0,"current198_status_unpublished":true}),
    )?;
    let fleet = file(p.fleet_output.clone(), false)?;
    let ledger = bound_json(&fleet, false)?;
    ensure!(
        ledger["inventory"]["anomalies"] == 0 && ledger["observer_sha256"] == observer.sha256,
        "198 promoted fleet differs"
    );
    write_new(
        &p.cycle_directory.join("completion.json"),
        &json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","plan":pb,"self_sha256":self_sha,"invocation_id":invocation,"sampled_at_utc":p.sample_target_utc,"observer":observer,"model":model,"estimates":estimates,"fleet_plan":fleet_plan,"fleet":fleet,"inventory":ledger["inventory"],"status_publications":statuses,"epoch198_delivery":null,"public198_promotion":promotion,"new_resource_samples":0,"archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false}),
    )?;
    Ok(())
}
pub(super) fn publish(p: &Plan, fleet: &Value, observer: &Bound) -> Result<Value> {
    let profile = p
        .public198_delivery
        .as_ref()
        .context("198 public profile")?;
    read(profile)?;
    let ledger_path = p.cycle_directory.join("public198-provisional-fleet.json");
    let mut value = fleet.clone();
    value["output"] = json!(ledger_path);
    let package = delivery198::seal_values(p, "public198-stage", &[("fleet-plan.json", value)])?;
    let plan = file(package.join("fleet-plan.json"), true)?;
    child(
        &p.tools.r2,
        &[
            "fleet-reconcile".into(),
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256.clone(),
        ],
        true,
        &p.cycle_directory.join("child-public198-fleet.json"),
    )?;
    let provisional = file(ledger_path, false)?;
    let ledger = bound_json(&provisional, false)?;
    let owner = ledger["active"]
        .as_array()
        .context("198 active census")?
        .iter()
        .find(|e| {
            e["epoch"] == 198
                && matches!(
                    e["phase"].as_str(),
                    Some("full-verification" | "plugin-verification")
                )
        });
    let Some(owner) = owner else {
        return Ok(
            json!({"provisional_fleet":provisional,"publication_skipped":true,"reason":"No authenticated current198 verifier child; stage transition/status cleanup requires prompt reconciliation"}),
        );
    };
    let unit = &owner["unit"];
    let target = p
        .cycle_directory
        .join("public198-status/sealed/pipeline-plan.json");
    let sample = utc_seconds(&p.sample_target_utc)?
        .checked_mul(1000)
        .context("198 sample overflow")?;
    let remaining = (1792611520743u64 + 43_200_000)
        .checked_sub(sample)
        .context("198 original downstream allowance overdue")?;
    ensure!(remaining > 0, "198 allowance overdue");
    let value = json!({"schema":"jetstreamer-horizon-pipeline-status-plan-v1","epoch":198,"phase":"verification","binding":{"unit":unit["Id"],"invocation_id":unit["InvocationID"],"expected_exec_start":unit["ExecStart"],"claim_phase":owner["phase"],"origin_unit":ORIGIN,"origin_invocation_id":IID,"model_path":target,"model_sha256":"","fleet_path":provisional.path,"fleet_sha256":provisional.sha256},"observer":observer,"fleet":provisional,"origin_launch":profile.origin,"estimate_evidence":[profile.promotion],"estimate_basis":"Actual198 verifier child, original producer clock, original archive close plus43200seconds through sidecar; no allowance reset","estimated_remaining_millis":remaining,"jet_path":"/home/sol/horizon/epoch-198.jet","expected_jet_size_bytes":99381250591u64,"peer_units":[],"receipt_directory":"/home/sol/.jetstreamer-private/r2-status-receipts","receipt_directory_uid":1001});
    let package =
        delivery198::seal_values(p, "public198-status", &[("pipeline-plan.json", value)])?;
    let plan = file(package.join("pipeline-plan.json"), true)?;
    for (name, check) in [("check", true), ("publish", false)] {
        let mut args = vec![
            "status-publish-pipeline".into(),
            plan.path.display().to_string(),
            "--plan-sha256".into(),
            plan.sha256.clone(),
        ];
        if check {
            args.push("--check-only".into());
        }
        let result = child(
            &p.tools.r2,
            &args,
            !check,
            &p.cycle_directory
                .join(format!("child-public198-{name}.json")),
        );
        if let Err(error) = result {
            let failed = file(
                p.cycle_directory
                    .join(format!("child-public198-{name}.json")),
                false,
            )?;
            return Ok(
                json!({"provisional_fleet":provisional,"publication_skipped":true,"failed_child":failed,
                "reason":format!("198 status stage needs prompt repair: {error:#}"),"archive_mutations":false}),
            );
        }
    }
    let digits: String = p
        .sample_target_utc
        .chars()
        .filter(char::is_ascii_digit)
        .collect();
    let publication = file(
        PathBuf::from(format!(
            "/home/sol/.jetstreamer-private/r2-status-receipts/epoch-198.status-{digits}.json"
        )),
        false,
    )?;
    Ok(json!({"provisional_fleet":provisional,"pipeline_plan":plan,"publication":publication}))
}
pub(super) fn validate_completed(p: &Plan, c: &Value) -> Result<()> {
    let d = &c["epoch198_delivery"];
    let provisional: Bound = serde_json::from_value(d["provisional_fleet"].clone())?;
    ensure!(
        provisional.path == p.cycle_directory.join("public198-provisional-fleet.json"),
        "198 public fleet path differs"
    );
    bound_json(&provisional, false)?;
    if d["publication_skipped"] == true {
        ensure!(
            d["publication"].is_null(),
            "198 skipped stage invented publication"
        );
        return Ok(());
    }
    let plan: Bound = serde_json::from_value(d["pipeline_plan"].clone())?;
    let value = bound_json(&plan, true)?;
    let publication: Bound = serde_json::from_value(d["publication"].clone())?;
    let r = bound_json(&publication, false)?;
    ensure!(
        r["epoch"] == 198
            && r["authenticated_readback"] == true
            && r["status"]["sampled_at_utc"] == p.sample_target_utc
            && r["status"]["phase"] == "verification"
            && r["status"]["estimated_remaining_millis"] == value["estimated_remaining_millis"]
            && r["pipeline_binding"]["model_sha256"] == plan.sha256,
        "198 verification status differs"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manager_refresh_allows_only_reset_runtime_annotations_not_command_changes() {
        let before = "{ path=/immutable/runner ; argv[]=/immutable/runner /plan sha selfsha ; ignore_errors=no ; start_time=[Wed] ; pid=123 ; code=(null) ; status=0/0 }";
        let after = "{ path=/immutable/runner ; argv[]=/immutable/runner /plan sha selfsha ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        assert!(manager_command_matches(before, after));
        assert!(!manager_command_matches(
            before,
            &after.replace("/plan sha", "/other sha")
        ));
        assert!(!manager_command_matches(
            before,
            &after.replace("selfsha", "changed")
        ));
        assert!(!manager_command_matches(
            before,
            &after.replace("ignore_errors=no", "ignore_errors=yes")
        ));
        assert!(!manager_command_matches(before, "unstructured"));
    }
    #[test]
    fn phase_event_cannot_retarget_a_new_sample_plan_writer_or_repeated_handoff() {
        let sample = "2026-10-21T21:28:00Z";
        let plan = "fdb0c0185f0c73ebe5f4b70cca5e45fb8508afc506e9ec61424c1de5bfea654c";
        let spec = "89b55302366b2e027dd98a83a690f061f66e4ba0f3b065aa7bfc6e894ff12346";
        event_scope(sample, plan, spec, true, false).unwrap();
        event_scope(
            sample,
            plan,
            "f3a42392d656d183353461f4216d912f49e5a0613bbdf01e825e9c650f5a92f6",
            true,
            false,
        )
        .unwrap();
        assert!(event_scope("2026-10-21T21:58:00Z", plan, spec, true, false).is_err());
        assert!(event_scope(sample, "foreign", spec, true, false).is_err());
        assert!(event_scope(sample, plan, "foreign", true, false).is_err());
        assert!(event_scope(sample, plan, spec, false, false).is_err());
        assert!(event_scope(sample, plan, spec, true, true).is_err());
    }
    #[test]
    fn native_handoff_is_explicit_separate_and_rejects_authority_extensions() {
        let good = json!({"schema":"horizon-native198-verification-handoff-v1","launches":[],"publication_authorized":false,"r2_mutations":false});
        assert!(serde_json::from_value::<NativeSpec>(good.clone()).is_ok());
        let mut bad = good;
        bad["replay_launch_authorized"] = json!(true);
        assert!(serde_json::from_value::<NativeSpec>(bad).is_err());
        let bound = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let profile = Profile {
            promotion: bound.clone(),
            origin: bound.clone(),
            claims: vec![],
            native_verification: vec![bound],
        };
        assert!(claims(&profile).is_err());
    }
    #[test]
    fn public_handoff_preserves_unrelated_claims_and_consensus_integers() {
        let bound = Bound {
            path: "/proof".into(),
            sha256: "a".repeat(64),
        };
        let profile = Profile {
            promotion: bound.clone(),
            origin: bound,
            claims: vec![
                json!({"epoch":198,"phase":"full-verification"}),
                json!({"epoch":198,"phase":"plugin-verification"}),
            ],
            native_verification: Vec::new(),
        };
        let mut fleet = json!({"pipeline_claims":[{"epoch":198,"phase":"controller-import-handoff"},{"epoch":160,"value":u64::MAX}],"tracked_units":[],"gates":{"198":{"evidence":[]},"144":{"value":u64::MAX}}});
        fold(&mut fleet, &profile).unwrap();
        let once = fleet.clone();
        fold(&mut fleet, &profile).unwrap();
        assert_eq!(fleet, once);
        assert_eq!(fleet["gates"]["144"]["value"], u64::MAX);
        assert_eq!(fleet["pipeline_claims"][0]["epoch"], 160);
        assert!(
            fleet["pipeline_claims"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["phase"] != "controller-import-handoff")
        );
    }
}
