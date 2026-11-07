//! Typed continuation of the same admitted epoch 185 invocation.
//! A retained lifecycle is historical launch provenance, never fresh admission.
use super::*;
pub(in crate::fleet) const FIELD: &str = "epoch185_cold_lifecycle";
pub(in crate::fleet) const TERMINAL_FIELD: &str = "epoch185_cold_terminal_retention";
pub(in crate::fleet) const SCHEMA: &str = "horizon-epoch185-native-retained-lifecycle-v2";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch185-native-retained-20261105-v2";
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("cold185 lifecycle missing {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("cold185 lifecycle missing integer {k}"))
}
fn binding(v: &Value) -> Result<BoundFile> {
    let b: BoundFile = serde_json::from_value(v.clone())?;
    ensure!(
        b.path.is_absolute() && is_lower_hex(&b.sha256, 64),
        "cold185 lifecycle invalid bound source"
    );
    Ok(b)
}
fn read(v: &Value) -> Result<Value> {
    native::read_json(&binding(v)?, 16 << 20)
}

/// Pure original-release check, also used by the distinct Frame contract.
fn release_shape(v: &Value, event: &Value, proof: &Value) -> Result<()> {
    ensure!(
        v["schema"] == SCHEMA
            && v["epoch"] == 185
            && v["registration"] == proof["registration"]
            && v["task"] == event["task"]
            && v["actor_unit"] == event["actor_unit"]
            && v["actor_invocation_id"] == event["actor_invocation_id"]
            && v["ready_pid"] == event["ready_pid"]
            && v["ready_start_ticks"] == event["ready_start_ticks"]
            && v["ready_started_at"] == event["ready_started_at"]
            && v["setup_deadline_at"] == event["setup_deadline_at"]
            && v["limits"] == event["limits"]
            && v["candidate_DATA_bytes"] == event["candidate_DATA_bytes"]
            && v["guard_floor_bytes"] == event["guard_floor_bytes"]
            && v["release"] == proof["release"]
            && v["resource_credit_bytes"] == 0
            && v["publication_authorized"] == false
            && v["fresh_admission_authorized"] == false
            && v["r2_mutations"] == false,
        "cold185 lifecycle changed original owner, promises, release or authority"
    );
    ensure!(
        v["released_actor"]["path"] == super::DRIVER
            && v["released_actor"]["sha256"] == super::DRIVER_SHA
            && v["released_actor"]["pid"].as_u64().is_some_and(|p| p > 1)
            && v["released_actor"]["start_ticks"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && (proof["stage"] == "terminal" || v["released_actor"] == proof["mapped_driver"]),
        "cold185 lifecycle running MainPID/start ticks changed from actual release"
    );
    let release = &v["release"];
    let token = &release["token_value"];
    let issued = number(token, "issued_at")?;
    let expires = number(token, "expires_at")?;
    let started = number(event, "ready_started_at")?;
    let deadline = number(event, "setup_deadline_at")?;
    let fire = number(&release["first_guard_value"], "sampled_at")?;
    ensure!(
        token["schema"] == "horizon-epoch185-native-gate-v4"
            && token["epoch"] == 185
            && token["actor_unit"] == event["actor_unit"]
            && token["actor_invocation_id"] == event["actor_invocation_id"]
            && token["ready_pid"] == event["ready_pid"]
            && token["ready_start_ticks"] == event["ready_start_ticks"]
            && token["admission_sha256"] == event["admission_sha256"]
            && token["guard_result"] == release["first_guard_value"]
            && release["first_guard_value"]["success"] == true
            && release["first_guard_value"]["timer_driven"] == true
            && release["first_guard_value"]["actor_invocation_id"] == event["actor_invocation_id"]
            && release["first_guard_value"]["admission_sha256"] == event["admission_sha256"]
            && started <= fire
            && fire <= issued
            && issued < expires
            && expires <= deadline
            && issued - fire <= 30
            && deadline > started
            && deadline - started <= 600,
        "cold185 lifecycle lacks original within-deadline genuine timer release"
    );
    for k in ["token", "seal", "first_guard"] {
        binding(&release[k])?;
    }
    let sampled = number(v, "sampled_at")?;
    ensure!(
        issued <= sampled,
        "cold185 lifecycle predates actual release"
    );
    Ok(())
}

pub(in crate::fleet) fn selected(plan: &Value) -> bool {
    !plan[FIELD].is_null()
}
pub(in crate::fleet) fn load(plan: &Value, event: &Value, proof: &Value) -> Result<Value> {
    let b = binding(&plan[FIELD])?;
    let v = native::read_json(&b, 16 << 20)?;
    ensure!(
        b.path
            == Path::new(ROOT)
                .join(text(event, "actor_invocation_id")?)
                .join("lifecycle.json"),
        "cold185 lifecycle crossed original IID namespace"
    );
    release_shape(&v, event, proof)?;
    for (kind, key) in [
        ("fleet_enrollment", "prestart_fleet_acceptance"),
        (
            "current_reader_native_acceptance",
            "prestart_reader_acceptance",
        ),
    ] {
        let accepted = read(&v[key])?;
        ensure!(
            accepted["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
                && accepted["kind"] == kind
                && accepted["actor_unit"] == event["actor_unit"]
                && accepted["actor_invocation_id"] == event["actor_invocation_id"]
                && accepted["ready_pid"] == event["ready_pid"]
                && accepted["ready_start_ticks"] == event["ready_start_ticks"]
                && accepted["admission_sha256"] == event["admission_sha256"]
                && accepted["actual_start_pre_evidence_accepted"] == true
                && accepted["root_operator_owner"] == true
                && accepted["restarts"] == 0
                && accepted["resource_credit_bytes"] == 0
                && accepted["sampled_at"].as_u64().is_some_and(
                    |at| at <= number(&v["release"]["token_value"], "issued_at").unwrap_or(0)
                ),
            "cold185 lifecycle crossed original genuine fleet/reader acceptance"
        );
        ensure!(
            v["release"]["token_value"][kind] == v[key],
            "cold185 token does not bind exact original acceptance"
        );
        read(&accepted["underlying_accepted_proof"])?;
    }
    if proof["stage"] == "terminal" {
        let t = read(&plan[TERMINAL_FIELD])?;
        ensure!(
            t["schema"] == "horizon-epoch185-native-terminal-retention-v2"
                && t["lifecycle"] == json!(b)
                && t["registration"] == proof["registration"]
                && t["actor_invocation_id"] == event["actor_invocation_id"]
                && t["terminal_context"] == proof["terminal_context"]
                && !t["terminal_context"].is_null()
                && t["resource_credit_bytes"] == 0
                && t["memory_and_DATA_retained"] == true
                && t["publication_authorized"] == false
                && t["fresh_admission_authorized"] == false,
            "cold185 terminal retention lacks exact drained original invocation closure"
        );
    } else {
        ensure!(
            proof["stage"] == "running" && plan[TERMINAL_FIELD].is_null(),
            "cold185 lifecycle phase/terminal selector mismatch"
        );
    }
    Ok(v)
}

/// Remove only independently authenticated 185 additions for legacy consumers.
/// Actual bindings and original source bytes are never changed by this view.
pub(in crate::fleet) fn project_plan(
    plan: &Value,
    event: &Value,
    baseline: &Value,
) -> Result<Value> {
    let mut p = plan.clone();
    let o = p.as_object_mut().context("cold185 legacy plan object")?;
    for k in [enrollment::FIELD, FIELD, TERMINAL_FIELD] {
        o.remove(k);
    }
    let family = ["actor_unit", "guard_unit", "timer_unit"]
        .map(|k| text(event, k))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let names = p["tracked_units"]
        .as_array_mut()
        .context("cold185 legacy tracked census")?;
    for name in &family {
        ensure!(
            names.iter().filter(|n| *n == *name).count() == 1,
            "cold185 legacy view omitted or duplicated exact family"
        );
    }
    names.retain(|n| !family.iter().any(|name| n == *name));
    let claims = p["diagnostics"]
        .as_array_mut()
        .context("cold185 legacy claim census")?;
    ensure!(
        claims
            .iter()
            .filter(|c| c["unit"] == event["actor_unit"])
            .count()
            == 1,
        "cold185 legacy duplicate actor"
    );
    claims.retain(|c| c["unit"] != event["actor_unit"]);
    p["gates"]["185"] = baseline["gates"]["185"].clone();
    p["metadata_event"] = baseline["metadata_event"].clone();
    Ok(p)
}
pub(in crate::fleet) fn project_fleet(
    fleet: &Value,
    event: &Value,
    baseline: &Value,
) -> Result<Value> {
    let mut f = fleet.clone();
    let o = f.as_object_mut().context("cold185 legacy fleet object")?;
    for k in [
        enrollment::FIELD,
        FIELD,
        TERMINAL_FIELD,
        "cold185_allocation",
    ] {
        o.remove(k);
    }
    let family = ["actor_unit", "guard_unit", "timer_unit"]
        .map(|k| text(event, k))
        .into_iter()
        .collect::<Result<Vec<_>>>()?;
    let census = f["unit_census"]
        .as_object_mut()
        .context("cold185 legacy native census")?;
    for name in family {
        ensure!(
            census.remove(name).is_some(),
            "cold185 legacy raw fleet dropped role"
        );
    }
    for key in ["diagnostics", "active"] {
        f[key]
            .as_array_mut()
            .context("cold185 legacy fleet diagnostic list")?
            .retain(|r| {
                r["unit"]["Id"] != event["actor_unit"] && r["producer"]["Id"] != event["actor_unit"]
            });
    }
    if let (Some(rows), Some(old)) = (f["epochs"].as_array_mut(), baseline["epochs"].as_array()) {
        let original = old
            .iter()
            .find(|r| r["epoch"] == 185)
            .context("cold185 legacy original185 epoch row")?;
        for row in rows.iter_mut().filter(|r| r["epoch"] == 185) {
            *row = original.clone();
        }
    }
    for key in [
        "metadata_event_sampled_at_utc",
        "metadata_only",
        "resource_admission_authorized",
    ] {
        if let Some(original) = baseline.get(key) {
            f[key] = original.clone();
        } else {
            f.as_object_mut()
                .context("cold185 legacy fleet object")?
                .remove(key);
        }
    }
    f["metadata_event"] = baseline["metadata_event"].clone();
    Ok(f)
}

/// Same-sample lifecycle/terminal transitions preserve every other policy field.
fn metadata_shape(
    previous: &Value,
    old: &Value,
    plan: &Value,
    event_binding: &Value,
    sample: &str,
    terminal: bool,
) -> Result<()> {
    ensure!(
        previous["sampled_at_utc"] == sample
            && old["observer"] == plan["observer"]
            && previous["observer_receipt"] == plan["observer"]["path"]
            && previous["observer_sha256"] == plan["observer"]["sha256"]
            && !plan[enrollment::FIELD].is_null()
            && old[enrollment::FIELD] == plan[enrollment::FIELD]
            && plan["metadata_event"] == *event_binding,
        "cold185 retained metadata transition changed observer/registration"
    );
    let selector = if terminal { TERMINAL_FIELD } else { FIELD };
    ensure!(
        old[selector].is_null() && plan[selector] == *event_binding,
        "cold185 retained metadata transition repeats or substitutes event"
    );
    let mut expected = old.clone();
    for key in ["output", "previous_fleet", "metadata_event", selector] {
        expected[key] = plan[key].clone();
    }
    let gate = &mut expected["gates"]["185"];
    ensure!(
        gate["state"] == plan["gates"]["185"]["state"]
            && matches!(
                gate["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "cold185 metadata cannot close epoch repair gate"
    );
    gate["next_action"] = plan["gates"]["185"]["next_action"].clone();
    gate["evidence"]
        .as_array_mut()
        .context("cold185 retained gate evidence")?
        .push(event_binding.clone());
    ensure!(
        expected == *plan,
        "cold185 phase transition changed unrelated policy, claims or promises"
    );
    Ok(())
}
pub(in crate::fleet) fn validate_transition(
    previous: &Value,
    plan: &Value,
    sample: &str,
    event: &Value,
) -> Result<()> {
    let old = read(&json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}))?;
    ensure!(
        plan["previous_fleet"] == event["previous_fleet"],
        "cold185 lifecycle predecessor differs"
    );
    metadata_shape(
        previous,
        &old,
        plan,
        &plan["metadata_event"],
        sample,
        event["schema"] == "horizon-epoch185-native-terminal-retention-v2",
    )
}
pub(in crate::fleet) fn validate_normal(
    previous: &Value,
    plan: &Value,
    observer: &Value,
    sample: &str,
) -> Result<()> {
    let old = read(&json!({"path":previous["plan"],"sha256":previous["plan_sha256"]}))?;
    normal_shape(previous, &old, plan, observer, sample)
}
fn normal_shape(
    previous: &Value,
    old: &Value,
    plan: &Value,
    observer: &Value,
    sample: &str,
) -> Result<()> {
    ensure!(
        previous[FIELD] == plan[FIELD]
            && previous[enrollment::FIELD] == plan[enrollment::FIELD]
            && previous[TERMINAL_FIELD] == plan[TERMINAL_FIELD]
            && previous["metadata_event"] == plan["metadata_event"],
        "cold185 normal refresh replaced lifecycle or terminal provenance"
    );
    ensure!(
        old["gates"]["185"] == plan["gates"]["185"]
            && matches!(
                plan["gates"]["185"]["state"].as_str(),
                Some("failed-needs-repair" | "blocked-qualification")
            ),
        "cold185 normal observation changed private185 repair gate or evidence"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && observer["recorded_at_utc"] == sample
            && observer["cadence"]["previous_sample"] == previous["observer_receipt"]
            && observer["cadence"]["previous_sample_sha256"] == previous["observer_sha256"]
            && observer["cadence"]["routine_minimum_interval_enforced"] == true
            && utc_seconds(sample)?
                .checked_sub(utc_seconds(text(previous, "sampled_at_utc")?)?)
                .is_some_and(|n| n >= 1800),
        "cold185 continuation requires next genuine predecessor-bound scheduled v2 observation"
    );
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    registration: BoundFile,
    previous_fleet: BoundFile,
    previous_plan: BoundFile,
    prestart_fleet_acceptance: BoundFile,
    prestart_reader_acceptance: BoundFile,
    lifecycle: Option<BoundFile>,
    output: PathBuf,
}
pub(crate) fn capture() -> Result<()> {
    let (spec_binding, self_sha) = super::parsed("capture-cold185-lifecycle")?;
    let spec: CaptureSpec = serde_json::from_value(native::read_json(&spec_binding, 4 << 20)?)?;
    ensure!(
        spec.schema == "horizon-epoch185-native-retained-capture-spec-v2",
        "cold185 lifecycle capture spec"
    );
    let event = native::read_json(&spec.registration, 4 << 20)?;
    let task = binding(&event["task"])?;
    let mut proof = super::load(&task, super::now()?)?;
    proof["registration"] = json!(spec.registration);
    let terminal = proof["stage"] == "terminal";
    ensure!(
        terminal || proof["stage"] == "running",
        "cold185 retained capture requires genuine released running or drained terminal actor"
    );
    let previous = native::read_generated_json(&spec.previous_fleet, 16 << 20)?;
    let prior_plan = native::read_json(&spec.previous_plan, 16 << 20)?;
    ensure!(
        previous["plan"] == spec.previous_plan.path.to_string_lossy().as_ref()
            && previous["plan_sha256"] == spec.previous_plan.sha256
            && previous[enrollment::FIELD] == json!(spec.registration)
            && prior_plan[enrollment::FIELD] == json!(spec.registration)
            && previous["observer_receipt"] == prior_plan["observer"]["path"]
            && previous["observer_sha256"] == prior_plan["observer"]["sha256"],
        "cold185 lifecycle capture lost actual complete predecessor/registration"
    );
    if !terminal {
        let accepted = native::read_json(&spec.prestart_fleet_acceptance, 4 << 20)?;
        ensure!(
            accepted["actual_fleet"] == json!(spec.previous_fleet)
                && accepted["actual_fleet_plan"] == json!(spec.previous_plan)
                && previous["metadata_event"] == json!(spec.registration),
            "cold185 initial lifecycle must extend exact genuinely accepted prestart fleet"
        );
    }
    let mut value = if terminal {
        let lifecycle = spec
            .lifecycle
            .as_ref()
            .context("cold185 terminal requires existing immutable lifecycle")?;
        let original = native::read_json(lifecycle, 16 << 20)?;
        ensure!(
            lifecycle.path
                == Path::new(ROOT)
                    .join(text(&event, "actor_invocation_id")?)
                    .join("lifecycle.json"),
            "cold185 terminal capture crossed original lifecycle namespace"
        );
        release_shape(&original, &event, &proof)?;
        json!({"schema":"horizon-epoch185-native-terminal-retention-v2","epoch":185,"lifecycle":lifecycle,
   "registration":spec.registration,"actor_invocation_id":event["actor_invocation_id"],"terminal_context":proof["terminal_context"],
   "memory_and_DATA_retained":true,"sampled_at":super::now()?,"resource_credit_bytes":0,"publication_authorized":false,"fresh_admission_authorized":false})
    } else {
        let mut v = json!({"schema":SCHEMA,"epoch":185,"registration":spec.registration,"task":event["task"],
   "prestart_fleet_acceptance":spec.prestart_fleet_acceptance,"prestart_reader_acceptance":spec.prestart_reader_acceptance,
   "release":proof["release"],"released_actor":proof["mapped_driver"],"sampled_at":super::now()?,"resource_credit_bytes":0,"publication_authorized":false,"fresh_admission_authorized":false,"r2_mutations":false});
        for k in [
            "actor_unit",
            "actor_invocation_id",
            "ready_pid",
            "ready_start_ticks",
            "ready_started_at",
            "setup_deadline_at",
            "limits",
            "candidate_DATA_bytes",
            "guard_floor_bytes",
        ] {
            v[k] = event[k].clone();
        }
        release_shape(&v, &event, &proof)?;
        v
    };
    value["previous_fleet"] = json!(spec.previous_fleet);
    value["previous_plan"] = json!(spec.previous_plan);
    value["spec"] = json!(spec_binding);
    value["self_sha256"] = json!(self_sha);
    let expected = Path::new(ROOT)
        .join(text(&event, "actor_invocation_id")?)
        .join(if terminal {
            "terminal.json"
        } else {
            "lifecycle.json"
        });
    ensure!(
        spec.output == expected,
        "cold185 lifecycle output namespace changed"
    );
    let parent = expected
        .parent()
        .context("cold185 lifecycle output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "cold185 lifecycle output custody"
    );
    let mut raw = serde_json::to_vec_pretty(&value)?;
    raw.push(b'\n');
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&expected)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    println!("{}", expected.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bound(n: &str) -> Value {
        json!({"path":format!("/test-only/{n}.json"),"sha256":"a".repeat(64)})
    }
    fn policy() -> Value {
        json!({"observer":bound("observer"),"epoch185_cold_startpre_registration":bound("registration"),"metadata_event":bound("old-event"),"output":"/test-only/old.json","previous_fleet":bound("old-fleet"),"gates":{"185":{"state":"failed-needs-repair","next_action":"retain","evidence":[]},"199":{"state":"failed-needs-repair"}},"tracked_units":["old.service","actor.service","guard.service","guard.timer"],"diagnostics":[{"unit":"old.service"},{"unit":"actor.service"}],"original199_retained":true})
    }
    #[test]
    fn lifecycle_metadata_addition_preserves_every_unrelated_policy_field() {
        let old = policy();
        let mut p = old.clone();
        p[FIELD] = bound("lifecycle");
        p["metadata_event"] = p[FIELD].clone();
        p["output"] = json!("/test-only/new.json");
        p["previous_fleet"] = bound("current");
        p["gates"]["185"]["next_action"] = json!("same released owner; retain all promises");
        p["gates"]["185"]["evidence"] = json!([bound("lifecycle")]);
        let prev = json!({"sampled_at_utc":"2026-11-05T18:28:09Z","observer_receipt":old["observer"]["path"],"observer_sha256":old["observer"]["sha256"]});
        metadata_shape(&prev, &old, &p, &p[FIELD], "2026-11-05T18:28:09Z", false).unwrap();
        let mut bad = p.clone();
        bad["gates"]["199"]["state"] = json!("ready");
        assert!(
            metadata_shape(&prev, &old, &bad, &p[FIELD], "2026-11-05T18:28:09Z", false).is_err()
        );
    }
    #[test]
    fn phase_metadata_cannot_refresh_observer_or_repeat_lifecycle() {
        let old = policy();
        let mut p = old.clone();
        p[FIELD] = bound("lifecycle");
        p["metadata_event"] = p[FIELD].clone();
        p["gates"]["185"]["evidence"] = json!([bound("lifecycle")]);
        let prev = json!({"sampled_at_utc":"x","observer_receipt":old["observer"]["path"],"observer_sha256":old["observer"]["sha256"]});
        p["observer"] = bound("new-observer");
        assert!(metadata_shape(&prev, &old, &p, &p[FIELD], "x", false).is_err());
    }
    #[test]
    fn legacy_plan_removes_only_authenticated_family_and_restores_185_gate() {
        let p = policy();
        let baseline = json!({"gates":{"185":{"state":"failed-needs-repair","evidence":[bound("original185")]}},"metadata_event":bound("original-event")});
        let event = json!({"actor_unit":"actor.service","guard_unit":"guard.service","timer_unit":"guard.timer"});
        let v = project_plan(&p, &event, &baseline).unwrap();
        assert_eq!(v["tracked_units"], json!(["old.service"]));
        assert_eq!(v["gates"]["199"], p["gates"]["199"]);
        assert_eq!(v["original199_retained"], true);
        assert_eq!(v["observer"], p["observer"]);
        assert_eq!(v["gates"]["185"], baseline["gates"]["185"]);
        let mut bad = p;
        bad["tracked_units"]
            .as_array_mut()
            .unwrap()
            .push(json!("guard.service"));
        assert!(project_plan(&bad, &event, &baseline).is_err());
    }
    #[test]
    fn normal_refresh_rejects_reused_sample_and_missing_true_predecessor() {
        let prev = json!({"epoch185_cold_lifecycle":bound("life"),"epoch185_cold_startpre_registration":bound("reg"),"metadata_event":bound("event"),"sampled_at_utc":"2026-11-05T18:28:09Z","observer_receipt":"/test-only/old-observer.json","observer_sha256":"b".repeat(64)});
        let mut p = prev.clone();
        p["gates"]["185"] = json!({"state":"failed-needs-repair"});
        let mut obs = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-11-05T18:58:09Z","cadence":{"previous_sample":prev["observer_receipt"],"previous_sample_sha256":prev["observer_sha256"],"routine_minimum_interval_enforced":true}});
        normal_shape(&prev, &p, &p, &obs, "2026-11-05T18:58:09Z").unwrap();
        obs["cadence"]["previous_sample_sha256"] = json!("c".repeat(64));
        assert!(normal_shape(&prev, &p, &p, &obs, "2026-11-05T18:58:09Z").is_err());
    }
}

// Integrate only into the independently reviewed helper lifecycle source
// alongside LIFECYCLE_ORIGINAL_FLEET_CUSTODY.patch. Not compiled/run here.
#[cfg(test)]
mod original_fleet_writer_custody_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt,PermissionsExt};
    fn original_writer_fixture() -> (tempfile::TempDir, BoundFile, Vec<u8>) {
        assert_eq!(unsafe { libc::geteuid() },0,"custody control requires booked Root QA");
        let dir=tempfile::tempdir_in("/var/lib/jetstreamer/horizon-positive185-original-writer-custody-qa-20261107-v1").unwrap();
        // The real QA profile must supply its private Root TMPDIR, rather than
        // borrowing an unsafe/tmp ancestor as an immutable-reader exception.
        for parent in dir.path().ancestors() {
            let m=fs::symlink_metadata(parent).unwrap();
            assert_eq!(m.uid(),0);
            assert_eq!(m.mode()&0o022,0);
        }
        let raw=b"{\"schema\":\"synthetic-fleet-writer-custody-only\",\"credit_bytes\":0}\n".to_vec();
        let mut file=tempfile::NamedTempFile::new_in(dir.path()).unwrap();
        file.write_all(&raw).unwrap();file.as_file().sync_all().unwrap();
        let path=dir.path().join("original.json");file.persist_noclobber(&path).unwrap();
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode()&0o777,0o600);
        let b=BoundFile{path,sha256:hex_lower(&Sha256::digest(&raw))};
        (dir,b,raw)
    }
    #[test]
    fn original0600_writer_bytes_are_read_without_chmod_or_path_rebinding() {
        let(_dir,b,raw)=original_writer_fixture();
        let original_mode=fs::symlink_metadata(&b.path).unwrap().mode();
        let immutable_error=native::read_json(&b,16<<20).unwrap_err();
        assert!(format!("{immutable_error:#}").contains("immutable source custody"));
        let v=native::read_generated_json(&b,16<<20).unwrap();
        assert_eq!(v["credit_bytes"],0);
        assert_eq!(fs::read(&b.path).unwrap(),raw);
        assert_eq!(fs::symlink_metadata(&b.path).unwrap().mode(),original_mode);
    }
    #[test]
    fn protected_writer_path_still_rejects_symlinks_digest_drift_and_group_writes() {
        let(dir,b,_raw)=original_writer_fixture();
        let alias=dir.path().join("alias.json");
        std::os::unix::fs::symlink(&b.path,&alias).unwrap();
        let aliased=BoundFile{path:alias,sha256:b.sha256.clone()};
        assert!(native::read_generated_json(&aliased,16<<20).is_err());
        let crossed=BoundFile{path:b.path.clone(),sha256:"0".repeat(64)};
        assert!(native::read_generated_json(&crossed,16<<20).is_err());
        fs::set_permissions(&b.path,fs::Permissions::from_mode(0o620)).unwrap();
        assert!(native::read_generated_json(&b,16<<20).is_err());
    }
    #[test]
    fn generated_original_still_rejects_a_group_writable_ancestor() {
        let(dir,b,_raw)=original_writer_fixture();
        fs::set_permissions(dir.path(),fs::Permissions::from_mode(0o770)).unwrap();
        let error=native::read_generated_json(&b,16<<20).unwrap_err();
        assert!(format!("{error:#}").contains("ancestor custody changed"));
        fs::set_permissions(dir.path(),fs::Permissions::from_mode(0o700)).unwrap();
        assert!(native::read_generated_json(&b,1).is_err());
    }
}
