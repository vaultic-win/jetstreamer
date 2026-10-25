//! An explicit accepted whole-fleet context for recovery metadata operations.
//! The unchanged global census still rejects every newly unbound producer.
use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AcceptedContext {
    pub fleet: BoundFile,
    pub observer: BoundFile,
}
impl AcceptedContext {
    pub(super) fn from_basis(v: &Value) -> Result<Self> {
        Ok(Self {
            fleet: serde_json::from_value(v["fleet"].clone())?,
            observer: serde_json::from_value(v["observer"].clone())?,
        })
    }
    pub(super) fn matches_basis(&self, v: &Value) -> Result<()> {
        ensure!(
            v["fleet"] == private157::binding(&self.fleet)
                && v["observer"] == private157::binding(&self.observer),
            "204 recovery context differs from complete maintenance basis"
        );
        Ok(())
    }
    pub(super) fn historical(&self) -> Result<Value> {
        let f = accepted_fleet(&self.fleet)?;
        let o = bound_json(&self.observer)?;
        utc_seconds(s(&o, "recorded_at_utc")?)?;
        ensure!(
            f["schema"] == SCHEMA
                && f["first_epoch"] == 201
                && f["last_epoch"] == 300
                && f["observer_receipt"] == self.observer.path.to_string_lossy().as_ref()
                && f["observer_sha256"] == self.observer.sha256
                && f["sampled_at_utc"] == o["recorded_at_utc"]
                && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
            "204 recovery context is foreign or not the accepted coordinated observation"
        );
        Ok(f)
    }
    fn accepted(&self) -> Result<Value> {
        let f = self.historical()?;
        let sample = utc_seconds(s(&f, "sampled_at_utc")?)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        fresh_sample(sample, now)?;
        Ok(f)
    }
    pub(super) fn validate_saved(&self, current: &BTreeMap<String, Value>) -> Result<()> {
        let f = self.historical()?;
        ensure!(
            requested_names(&f, &BTreeSet::new())?
                .iter()
                .all(|name| current.contains_key(name)),
            "204 saved custody omits accepted or closed census names"
        );
        validate_peer_bindings(&f, current)
    }
    pub(super) fn census(&self, hints: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
        let f = self.accepted()?;
        let current = census_for(&f, hints)?;
        ensure!(
            self.accepted()? == f,
            "204 accepted context changed during metadata census"
        );
        Ok(current)
    }
}

fn event_fleet(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "fleet.json")
        && path.parent().is_some_and(|p| {
            p.parent() == Some(Path::new("/var/lib/jetstreamer"))
                && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.strip_prefix("horizon-204-assembly-fleet-event-")
                        .is_some_and(|suffix| {
                            !suffix.is_empty()
                                && suffix
                                    .bytes()
                                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                        })
                })
        })
}

fn canary_terminal_suffix(path: &Path) -> Option<&str> {
    if path.file_name()? != "fleet.json" { return None; }
    let parent = path.parent()?;
    if parent.parent()? != Path::new("/var/lib/jetstreamer") { return None; }
    let suffix = parent.file_name()?.to_str()?
        .strip_prefix("horizon-canary227-terminal-fleet-")?;
    (!suffix.is_empty() && !suffix.starts_with("spec-")
        && suffix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
        .then_some(suffix)
}
fn canary_terminal_fleet(path: &Path) -> bool { canary_terminal_suffix(path).is_some() }
fn accepted_namespace(path: &Path) -> bool {
    event_fleet(path) || canary_terminal_fleet(path)
        || path.starts_with("/var/lib/jetstreamer/horizon-campaign-fleet")
}
fn canary_terminal_members(binding: &BoundFile, f: &Value) -> Result<(BoundFile, BoundFile)> {
    let suffix = canary_terminal_suffix(&binding.path).context("227 terminal fleet namespace")?;
    let plan = BoundFile { path:s(f,"plan")?.into(), sha256:s(f,"plan_sha256")?.into() };
    let proof: BoundFile = serde_json::from_value(f["metadata_event"].clone())?;
    ensure!(
        plan.path == Path::new("/var/lib/jetstreamer")
            .join(format!("horizon-canary227-terminal-fleet-spec-{suffix}"))
            .join("plan.json")
            && proof.path == Path::new("/var/lib/jetstreamer/horizon-227-v1625-canary-terminal-selection-v2/proof.json"),
        "204 context terminal 227 event has foreign paired plan or proof"
    );
    Ok((plan, proof))
}
fn canary_terminal_fleet_value(binding: &BoundFile) -> Result<Value> {
    ensure!(canary_terminal_fleet(&binding.path), "227 terminal fleet namespace differs");
    let parent = binding.path.parent().context("227 terminal fleet parent")?;
    let d = fs::symlink_metadata(parent)?;
    ensure!(parent.canonicalize()? == parent && d.is_dir() && d.uid()==0
        && d.mode() & 0o777 == 0o700, "227 terminal fleet parent custody differs");
    let before = fs::symlink_metadata(&binding.path)?;
    ensure!(binding.path.canonicalize()? == binding.path && before.is_file()
        && before.uid()==0 && before.nlink()==1 && before.mode() & 0o022 == 0,
        "227 terminal fleet custody differs");
    let value = bound_json(binding)?;
    ensure!(identity(&before)==identity(&fs::symlink_metadata(&binding.path)?)
        && identity(&d)==identity(&fs::symlink_metadata(parent)?),
        "227 terminal fleet changed during read");
    Ok(value)
}
fn event_fleet_value(binding: &BoundFile) -> Result<Value> {
    ensure!(
        event_fleet(&binding.path),
        "204 event fleet namespace differs"
    );
    private(binding.path.parent().context("204 event fleet parent")?)?;
    let before = fs::symlink_metadata(&binding.path)?;
    ensure!(
        binding.path.canonicalize()? == binding.path
            && before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0,
        "204 event fleet custody differs"
    );
    let value = bound_json(binding)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(&binding.path)?),
        "204 event fleet changed during read"
    );
    Ok(value)
}

// Event ledgers use the existing private writer namespace. Follow immutable
// predecessor bindings iteratively: cycles reject, but normal daily refreshes
// do not consume a fixed lifetime allowance of event links.
fn accepted_fleet(binding: &BoundFile) -> Result<Value> {
    accepted_fleet_with(
        binding,
        &|b| {
            if event_fleet(&b.path) {
                event_fleet_value(b)
            } else if canary_terminal_fleet(&b.path) {
                canary_terminal_fleet_value(b)
            } else {
                bound_json(b)
            }
        },
        &|b, sealed| if sealed { read(b) } else { bound_json(b) },
        &canary227_terminal::saved_predecessor,
    )
}
fn accepted_fleet_with(
    binding: &BoundFile,
    fleet: &impl Fn(&BoundFile) -> Result<Value>,
    metadata: &impl Fn(&BoundFile, bool) -> Result<Value>,
    terminal: &impl Fn(&Value, &Value, &Value, &str, u64, &Value) -> Result<()>,
) -> Result<Value> {
    let mut next = binding.clone();
    let mut seen = BTreeSet::new();
    let mut result = None;
    loop {
        ensure!(
            seen.insert(next.path.clone()),
            "204 event fleet lineage cycles"
        );
        let canonical = next
            .path
            .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet");
        ensure!(
            accepted_namespace(&next.path),
            "204 recovery needs an accepted fleet namespace"
        );
        let f = fleet(&next)?;
        ensure!(
            f["schema"] == SCHEMA && f["first_epoch"] == 201 && f["last_epoch"] == 300,
            "204 accepted fleet assignment differs"
        );
        if result.is_none() {
            result = Some(f.clone());
        }
        if canonical {
            return result.context("204 accepted fleet missing");
        }
        if canary_terminal_fleet(&next.path) {
            let (plan_binding, proof_binding) = canary_terminal_members(&next, &f)?;
            let plan = metadata(&plan_binding, true)?;
            let proof = metadata(&proof_binding, true)?;
            let previous: BoundFile = serde_json::from_value(f["previous_fleet"].clone())?;
            ensure!(accepted_namespace(&previous.path), "227 terminal predecessor namespace");
            ensure!(!seen.contains(&previous.path), "204 event fleet lineage cycles");
            let predecessor = fleet(&previous)?;
            let observer_binding: BoundFile = serde_json::from_value(plan["observer"].clone())?;
            let observer = metadata(&observer_binding, false)?;
            let sample = s(&observer,"recorded_at_utc")?;
            let at = s(&proof,"sampled_at_utc")?;
            let recorded = n(&f,"recorded_unix_seconds")?;
            ensure!(
                plan["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
                    && plan["output"] == next.path.to_string_lossy().as_ref()
                    && plan["metadata_event"] == private157::binding(&proof_binding)
                    && plan["previous_fleet"] == private157::binding(&previous)
                    && proof["schema"] == canary227_terminal::SCHEMA
                    && proof["recorded_unix_seconds"] == utc_seconds(at)?
                    && plan["observer"]["path"] == f["observer_receipt"]
                    && plan["observer"]["sha256"] == f["observer_sha256"]
                    && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                    && f["sampled_at_utc"] == sample
                    && f["metadata_event_sampled_at_utc"] == at
                    && plan["admission_transition_guard"].is_null()
                    && f["admission_transition_guard"].is_null(),
                "204 context terminal 227 fleet lost exact plan/proof/observer lineage"
            );
            let original = BoundFile {path:s(&predecessor,"plan")?.into(),sha256:s(&predecessor,"plan_sha256")?.into()};
            let old_plan = metadata(&original,false)?;
            // Replay genuine admission at its recorded historical event time;
            // future WorkContext freshness and current peer checks stay separate.
            terminal(&predecessor,&plan,&proof,sample,recorded,&old_plan)?;
            next = previous;
            continue;
        }
        let parent = next.path.parent().context("204 event fleet parent")?;
        let plan_binding = BoundFile {
            path: s(&f, "plan")?.into(),
            sha256: s(&f, "plan_sha256")?.into(),
        };
        let event_binding: BoundFile = serde_json::from_value(f["metadata_event"].clone())?;
        ensure!(
            plan_binding.path == parent.join("plan.json")
                && event_binding.path == parent.join("event.json"),
            "204 event fleet has foreign plan or event members"
        );
        let plan = metadata(&plan_binding, true)?;
        let event = metadata(&event_binding, true)?;
        let previous: BoundFile = serde_json::from_value(f["previous_fleet"].clone())?;
        ensure!(
            accepted_namespace(&previous.path),
            "204 event predecessor namespace"
        );
        ensure!(
            !seen.contains(&previous.path),
            "204 event fleet lineage cycles"
        );
        let predecessor = fleet(&previous)?;
        let observer_binding: BoundFile = serde_json::from_value(event["observer"].clone())?;
        let observer = metadata(&observer_binding, false)?;
        let sample = utc_seconds(s(&observer, "recorded_at_utc")?)?;
        let at = utc_seconds(s(&event, "sampled_at_utc")?)?;
        ensure!(
            plan["schema"] == "jetstreamer-horizon-campaign-fleet-plan-v1"
                && plan["output"] == next.path.to_string_lossy().as_ref()
                && plan["metadata_event"] == private157::binding(&event_binding)
                && plan["previous_fleet"] == private157::binding(&previous)
                && event["schema"] == transition::EVENT_SCHEMA
                && event["metadata_only"] == true
                && event["resource_samples_taken"] == 0
                && event["previous_fleet"] == private157::binding(&previous)
                && event["original_plan"]["path"] == predecessor["plan"]
                && event["original_plan"]["sha256"] == predecessor["plan_sha256"]
                && event["observer"] == plan["observer"]
                && event["observer"]["path"] == f["observer_receipt"]
                && event["observer"]["sha256"] == f["observer_sha256"]
                && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && f["sampled_at_utc"] == observer["recorded_at_utc"]
                && f["metadata_event_sampled_at_utc"] == event["sampled_at_utc"]
                && sample <= at
                && at <= n(&f, "recorded_unix_seconds")?
                && plan["admission_transition_guard"].is_null()
                && f["admission_transition_guard"].is_null(),
            "204 event fleet lost authenticated plan/event/predecessor lineage"
        );
        deny(&event["authority"])?;
        let original: BoundFile = serde_json::from_value(event["original_plan"].clone())?;
        let old = metadata(&original, false)?;
        let frame = if event["action"] == "terminal" {
            None
        } else {
            Some(metadata(
                &serde_json::from_value(event["claim"]["frame"].clone())?,
                true,
            )?)
        };
        let mut expected =
            transition::saved_event_plan(&event, &old, &predecessor, frame.as_ref(), parent)?;
        expected["metadata_event"] = private157::binding(&event_binding);
        ensure!(
            plan == expected,
            "204 saved event changed unrelated plan fields"
        );
        next = previous;
    }
}

#[derive(Clone)]
pub(super) struct WorkContext {
    accepted: AcceptedContext,
    observer: BoundFile,
    history: Vec<BoundFile>,
}
impl WorkContext {
    pub(super) fn new(
        fleet: BoundFile,
        observer: BoundFile,
        history: Vec<BoundFile>,
    ) -> Result<Self> {
        let f = accepted_fleet(&fleet)?;
        let accepted = AcceptedContext {
            fleet,
            observer: BoundFile {
                path: s(&f, "observer_receipt")?.into(),
                sha256: s(&f, "observer_sha256")?.into(),
            },
        };
        let context = Self {
            accepted,
            observer,
            history,
        };
        context.historical()?;
        Ok(context)
    }
    pub(super) fn from_frame(frame: &Value) -> Result<Self> {
        let context = Self::new(
            serde_json::from_value(frame["previous_fleet"].clone())?,
            serde_json::from_value(frame["observer"].clone())?,
            serde_json::from_value(frame.get("observer_history").cloned().unwrap_or(json!([])))?,
        )?;
        if frame.get("accepted_context").is_some() {
            ensure!(
                frame["accepted_context"] == serde_json::to_value(&context.accepted)?,
                "204 work predecessor context differs"
            );
        } else {
            ensure!(
                context.observer == context.accepted.observer && context.history.is_empty(),
                "204 refreshed work omits its accepted predecessor context"
            );
        }
        Ok(context)
    }
    fn historical(&self) -> Result<Value> {
        let f = self.accepted.historical()?;
        let current = bound_json(&self.observer)?;
        let old = bound_json(&self.accepted.observer)?;
        let history = self
            .history
            .iter()
            .map(|b| Ok((b.clone(), bound_json(b)?)))
            .collect::<Result<Vec<_>>>()?;
        observer_chain(
            &self.observer,
            &current,
            &self.accepted.observer,
            &old,
            &history,
        )?;
        Ok(f)
    }
    fn fresh(&self) -> Result<Value> {
        let f = self.historical()?;
        let o = bound_json(&self.observer)?;
        let at = utc_seconds(s(&o, "recorded_at_utc")?)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        fresh_sample(at, now)?;
        Ok(f)
    }
    pub(super) fn census(&self, hints: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
        let f = self.fresh()?;
        let current = census_for(&f, hints)?;
        ensure!(
            self.fresh()? == f,
            "204 refresh context changed during census"
        );
        Ok(current)
    }
    pub(super) fn validate_saved(&self, current: &BTreeMap<String, Value>) -> Result<()> {
        let f = self.historical()?;
        ensure!(
            requested_names(&f, &BTreeSet::new())?
                .iter()
                .all(|n| current.contains_key(n)),
            "204 refreshed work omits accepted or closed census names"
        );
        validate_peer_bindings(&f, current)
    }
    pub(super) fn accepted_binding(&self) -> Result<Value> {
        Ok(serde_json::to_value(&self.accepted)?)
    }
}

fn fresh_sample(sample: u64, now: u64) -> Result<()> {
    ensure!(
        sample <= now && now - sample <= 1800,
        "204 coordinated observer stale/future"
    );
    Ok(())
}

fn observer_chain(
    new: &BoundFile,
    current: &Value,
    old: &BoundFile,
    prior: &Value,
    history: &[(BoundFile, Value)],
) -> Result<()> {
    if new == old {
        ensure!(
            current == prior && history.is_empty(),
            "204 same-sample history differs"
        );
        return Ok(());
    }
    let mut seen = BTreeSet::from([new.path.clone()]);
    let mut child = current;
    let last = (old.clone(), prior.clone());
    for (binding, parent) in history.iter().chain(std::iter::once(&last)) {
        ensure!(
            seen.insert(binding.path.clone()),
            "204 observer history cycles"
        );
        let at = utc_seconds(s(child, "recorded_at_utc")?)?;
        let before = utc_seconds(s(parent, "recorded_at_utc")?)?;
        let cadence = &child["cadence"];
        ensure!(
            child["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && parent["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && at > before
                && cadence["previous_sample"] == binding.path.to_string_lossy().as_ref()
                && cadence["previous_sample_sha256"] == binding.sha256
                && cadence["previous_sample_recorded_at_utc"] == parent["recorded_at_utc"]
                && cadence["minimum_interval_seconds"] == 1800
                && ((cadence["observation_reason"] == "routine"
                    && cadence["routine_minimum_interval_enforced"] == true
                    && at - before >= 1800)
                    || (cadence["observation_reason"] == "user-requested-status"
                        && cadence["routine_minimum_interval_enforced"] == false))
                && cadence["observed_interval_seconds"] == at - before,
            "204 work observer lost exact forward cadence lineage"
        );
        child = parent;
    }
    Ok(())
}

fn census_for(f: &Value, hints: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
    let names = requested_names(f, hints)?;
    let current = census(&names, 201, 300)?;
    validate_peer_bindings(f, &current)?;
    // This derived comparison excludes only the exact epoch 204 subjects
    // being captured or handed off. Raw fleet and census remain unchanged.
    let mut peers = f.clone();
    peers["active"]
        .as_array_mut()
        .context("204 context active roster")?
        .retain(|row| {
            singleton227_admission::active_owner(row)
                .ok()
                .and_then(|u| u["Id"].as_str())
                .is_none_or(|name| !subject(name))
        });
    let peer_current = current
        .iter()
        .filter(|(name, _)| !subject(name))
        .map(|(name, row)| (name.clone(), row.clone()))
        .collect();
    maintenance_capacity::current_owners(&peers, &peer_current)?;
    Ok(current)
}
pub(super) fn subject(name: &str) -> bool {
    name == OLD_UNIT
        || name == OLD_GUARD
        || name == FAILED_V1_UNIT
        || name == FAILED_V1_GUARD
        || scope(name, 204, 204)
}
pub(super) fn closed_names() -> BTreeSet<String> {
    let mut names = BTreeSet::from([
        OLD_UNIT.into(),
        OLD_GUARD.into(),
        FAILED_V1_UNIT.into(),
        FAILED_V1_GUARD.into(),
        UNIT.into(),
        GUARD.into(),
    ]);
    names.extend(
        downstream::Stage::all()
            .iter()
            .map(|stage| stage.unit().into()),
    );
    names
}
fn requested_names(f: &Value, hints: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut names = hints.clone();
    names.extend(
        f["unit_census"]
            .as_object()
            .context("204 accepted context complete raw census missing")?
            .keys()
            .cloned(),
    );
    names.extend(closed_names());
    Ok(names)
}
fn validate_peer_bindings(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    for row in f["active"]
        .as_array()
        .context("204 accepted context active roster missing")?
    {
        let owner = singleton227_admission::active_owner(row)?;
        let name = s(owner, "Id")?;
        if subject(name) {
            continue;
        }
        same_owner(
            owner,
            current
                .get(name)
                .context("204 context omitted a healthy accepted peer")?,
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn live(name: &str, pid: u64) -> Value {
        json!({"Id":name,"InvocationID":format!("{pid:032x}"),"MainPID":pid.to_string(),"NRestarts":"0","LoadState":"loaded","ActiveState":"active","SubState":"running","ControlGroup":format!("/system.slice/{name}"),"ExecStart":format!("{{ path=/sealed/worker ; argv[]=/sealed/worker {name} ; ignore_errors=no }}")})
    }
    #[test]
    fn accepted_207_209_and_225_peers_are_requested_retained_and_identity_checked() {
        let current: BTreeMap<String, Value> = BTreeMap::from([
            (
                "horizon-qualify-207-singleton-admitted-v1.service".into(),
                live("horizon-qualify-207-singleton-admitted-v1.service", 207),
            ),
            (
                "horizon-singleton-209-live.service".into(),
                live("horizon-singleton-209-live.service", 209),
            ),
            (
                "horizon-qualify-225-cohort.service".into(),
                live("horizon-qualify-225-cohort.service", 225),
            ),
        ]);
        let f = json!({"unit_census":current,"active":current.values().map(|u|json!({"producer":u})).collect::<Vec<_>>()});
        let names = requested_names(&f, &closed_names()).unwrap();
        assert!(current.keys().all(|name| names.contains(name)));
        assert!(closed_names().is_subset(&names));
        validate_peer_bindings(&f, &current).unwrap();
        let mut missing = current.clone();
        missing.remove("horizon-qualify-207-singleton-admitted-v1.service");
        assert!(validate_peer_bindings(&f, &missing).is_err());
        let mut replaced = current;
        replaced
            .get_mut("horizon-singleton-209-live.service")
            .unwrap()["InvocationID"] = json!("f".repeat(32));
        assert!(validate_peer_bindings(&f, &replaced).is_err());
        let idle = |name: &str| json!({"Id":name,"InvocationID":"","MainPID":"0","NRestarts":"0","LoadState":"not-found","ActiveState":"inactive","SubState":"dead"});
        let mut complete: BTreeMap<String, Value> =
            serde_json::from_value(f["unit_census"].clone()).unwrap();
        for name in closed_names() {
            complete.insert(name.clone(), idle(&name));
        }
        complete.get_mut(OLD_UNIT).unwrap()["InvocationID"] = json!(OLD_IID);
        ownership::validate_closed_ownership(&complete, None).unwrap();
        let mut prior_live = complete.clone();
        prior_live.insert(FAILED_V1_UNIT.into(), live(FAILED_V1_UNIT, 204));
        assert!(ownership::validate_closed_ownership(&prior_live, None).is_err());
        assert!(subject(FAILED_V1_UNIT) && subject(FAILED_V1_GUARD));
        assert_ne!(UNIT, FAILED_V1_UNIT);
        assert_eq!(
            ROOT,
            "/var/lib/jetstreamer/horizon-204-assembly-only-recovery-v2"
        );
        assert_eq!(ORIGIN, 1792749926759);
        complete.insert(
            "horizon-qualify-204-unknown-replacement.service".into(),
            live("horizon-qualify-204-unknown-replacement.service", 204),
        );
        assert!(ownership::validate_closed_ownership(&complete, None).is_err());
        assert!(!subject("horizon-qualify-204-unknown-replacement.service"));
        assert!(!names.contains("horizon-qualify-204-unknown-replacement.service"));
    }
    fn b(path: &str) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: "a".repeat(64),
        }
    }
    fn observation(at: u64, previous: Option<(&BoundFile, &Value)>) -> Value {
        let mut o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2",
            "recorded_at_utc":ownership::millis_utc(at * 1000).unwrap()});
        if let Some((binding, parent)) = previous {
            let before = utc_seconds(parent["recorded_at_utc"].as_str().unwrap()).unwrap();
            o["cadence"] = json!({"previous_sample":binding.path,"previous_sample_sha256":binding.sha256,
                "previous_sample_recorded_at_utc":parent["recorded_at_utc"],"observation_reason":"routine",
                "routine_minimum_interval_enforced":true,"minimum_interval_seconds":1800,
                "observed_interval_seconds":at-before});
        }
        o
    }
    #[test]
    fn routine_31_minute_refresh_advances_history_without_relaxing_admission_age() {
        let old = b("/fixture/old.json");
        let new = b("/fixture/new.json");
        let prior = observation(10_000, None);
        let current = observation(11_860, Some((&old, &prior)));
        observer_chain(&new, &current, &old, &prior, &[]).unwrap();
        assert!(fresh_sample(10_000, 11_860).is_err());
        fresh_sample(11_860, 11_860).unwrap();
        fresh_sample(10_000, 11_800).unwrap();
        assert!(fresh_sample(11_861, 11_860).is_err());
    }
    #[test]
    fn observer_history_requires_every_exact_forward_routine_link() {
        let old = b("/fixture/old.json");
        let middle = b("/fixture/middle.json");
        let new = b("/fixture/new.json");
        let prior = observation(10_000, None);
        let intermediate = observation(11_860, Some((&old, &prior)));
        let current = observation(13_720, Some((&middle, &intermediate)));
        let history = vec![(middle.clone(), intermediate.clone())];
        observer_chain(&new, &current, &old, &prior, &history).unwrap();
        assert!(observer_chain(&new, &current, &old, &prior, &[]).is_err());
        for (path, value) in [
            ("/cadence/previous_sample", json!("/foreign.json")),
            ("/cadence/previous_sample_sha256", json!("b".repeat(64))),
            (
                "/cadence/previous_sample_recorded_at_utc",
                json!("1970-01-01T00:00:00Z"),
            ),
            ("/cadence/observation_reason", json!("manual")),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
            ("/cadence/minimum_interval_seconds", json!(1799)),
            ("/cadence/observed_interval_seconds", json!(1859)),
            ("/recorded_at_utc", json!("1970-01-01T00:00:00Z")),
        ] {
            let mut bad = current.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                observer_chain(&new, &bad, &old, &prior, &history).is_err(),
                "{path}"
            );
        }
        let early = observation(11_799, Some((&old, &prior)));
        assert!(observer_chain(&new, &early, &old, &prior, &[]).is_err());
        assert!(
            observer_chain(
                &new,
                &current,
                &old,
                &prior,
                &[
                    (middle.clone(), intermediate.clone()),
                    (middle, intermediate)
                ]
            )
            .is_err()
        );
        observer_chain(&old, &prior, &old, &prior, &[]).unwrap();
        assert!(observer_chain(&old, &prior, &old, &prior, &history).is_err());
        assert!(observer_chain(&new, &current, &new, &prior, &history).is_err());
    }
    #[test]
    fn explicit_user_requested_status_can_advance_before_the_routine_interval() {
        let old = b("/fixture/old.json");
        let requested = b("/fixture/requested.json");
        let new = b("/fixture/new.json");
        let prior = observation(10_000, None);
        let mut status = observation(10_060, Some((&old, &prior)));
        status["cadence"]["observation_reason"] = json!("user-requested-status");
        status["cadence"]["routine_minimum_interval_enforced"] = json!(false);
        observer_chain(&requested, &status, &old, &prior, &[]).unwrap();
        let current = observation(11_920, Some((&requested, &status)));
        observer_chain(&new, &current, &old, &prior, &[(requested, status)]).unwrap();
    }
    #[test]
    fn status_exception_requires_exact_reason_enforcement_and_forward_bindings() {
        let old = b("/fixture/old.json");
        let new = b("/fixture/new.json");
        let prior = observation(10_000, None);
        let mut status = observation(10_060, Some((&old, &prior)));
        status["cadence"]["observation_reason"] = json!("user-requested-status");
        status["cadence"]["routine_minimum_interval_enforced"] = json!(false);
        for (path, value) in [
            ("/cadence/observation_reason", json!("routine")),
            ("/cadence/observation_reason", json!("manual")),
            ("/cadence/routine_minimum_interval_enforced", json!(true)),
            ("/cadence/routine_minimum_interval_enforced", Value::Null),
            ("/cadence/previous_sample", json!("/foreign.json")),
            ("/cadence/previous_sample_sha256", json!("b".repeat(64))),
            (
                "/cadence/previous_sample_recorded_at_utc",
                json!("1970-01-01T00:00:00Z"),
            ),
            ("/cadence/minimum_interval_seconds", json!(60)),
            ("/cadence/observed_interval_seconds", json!(59)),
            ("/recorded_at_utc", prior["recorded_at_utc"].clone()),
            ("/recorded_at_utc", json!("1970-01-01T00:00:00Z")),
        ] {
            let mut bad = status.clone();
            *bad.pointer_mut(path).unwrap() = value;
            assert!(
                observer_chain(&new, &bad, &old, &prior, &[]).is_err(),
                "{path}"
            );
        }
        let mut unknown = status;
        unknown["cadence"]["observation_reason"] = json!("manual");
        unknown["cadence"]["routine_minimum_interval_enforced"] = json!(true);
        assert!(observer_chain(&new, &unknown, &old, &prior, &[]).is_err());
    }
    fn event_fixture(count: usize) -> (BoundFile, BTreeMap<PathBuf, Value>) {
        let mut files = BTreeMap::new();
        let mut previous = b("/var/lib/jetstreamer/horizon-campaign-fleet/fixture/fleet.json");
        let original = b("/fixture/original-plan.json");
        let mut old = json!({"schema":"jetstreamer-horizon-campaign-fleet-plan-v1",
            "first_epoch":201,"last_epoch":300,"tracked_units":["healthy207.service"],
            "unrelated_gate":{"must_remain":true},"observer":b("/fixture/initial-observer.json"),
            "gates":{"227":{"state":"failed-needs-repair","evidence":[],"next_action":"retain failure","reserve_stop":null}},
            "unrelated_guard_floor":123456789u64});
        let mut prior = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,
            "plan":original.path,"plan_sha256":original.sha256,"unit_census":{}});
        files.insert(original.path.clone(), old.clone());
        files.insert(previous.path.clone(), prior.clone());
        for i in 0..count {
            let directory = PathBuf::from(format!(
                "/var/lib/jetstreamer/horizon-204-assembly-fleet-event-test-{i}"
            ));
            let fleet = b(directory.join("fleet.json").to_str().unwrap());
            let plan = b(directory.join("plan.json").to_str().unwrap());
            let event = b(directory.join("event.json").to_str().unwrap());
            let observer = b(&format!("/fixture/observer-{i}.json"));
            let frame = b(&format!("/fixture/frame-{i}.json"));
            let at = 10_000 + (i as u64) * 1860;
            let o = observation(at, None);
            let claim = json!({"epoch":204,"recovery_plan":b("/fixture/recovery.json"),
                "admission":b("/fixture/admission.json"),"launch":b("/fixture/origin.json"),
                "actor_launch":b("/fixture/actor.json"),"frame":frame,"eta_policy":b("/fixture/eta.json")});
            let captured = json!({"schema":"jetstreamer-epoch204-assembly-recovery-work-v1",
                "epoch":204,"epoch_started_unix_millis":ORIGIN,"recovery_plan":claim["recovery_plan"],
                "launch":claim["launch"],"actor_launch":claim["actor_launch"],
                "previous_fleet":previous,"observer":observer,"sampled_at_utc":o["recorded_at_utc"],
                "unit_census_after":{}});
            let e = json!({"schema":transition::EVENT_SCHEMA,"original_plan":{"path":prior["plan"],"sha256":prior["plan_sha256"]},
                "previous_fleet":previous,"observer":observer,"claim":claim,"sampled_at_utc":o["recorded_at_utc"],
                "metadata_only":true,"resource_samples_taken":0,"authority":denied()});
            let mut p = transition::saved_event_plan(&e, &old, &prior, Some(&captured), &directory)
                .unwrap();
            p["metadata_event"] = private157::binding(&event);
            let f = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,
                "plan":plan.path,"plan_sha256":plan.sha256,"metadata_event":event,"previous_fleet":previous,
                "observer_receipt":observer.path,"observer_sha256":observer.sha256,"sampled_at_utc":o["recorded_at_utc"],
                "metadata_event_sampled_at_utc":e["sampled_at_utc"],"recorded_unix_seconds":at,
                "unit_census":{}});
            for (binding, value) in [
                (fleet.clone(), f.clone()),
                (plan, p.clone()),
                (event, e),
                (frame, captured),
                (observer, o),
            ] {
                files.insert(binding.path, value);
            }
            previous = fleet;
            prior = f;
            old = p;
        }
        (previous, files)
    }
    fn saved_fleet(binding: &BoundFile, files: &BTreeMap<PathBuf, Value>) -> Result<Value> {
        let load = |b: &BoundFile| files.get(&b.path).cloned().context("fixture file missing");
        accepted_fleet_with(binding, &load, &|b, _| load(b),
            &|_,_,_,_,_,_| anyhow::bail!("unexpected terminal 227 fixture"))
    }
    #[test]
    fn recovery_event_namespace_and_exact_plan_lineage_have_no_daily_chain_cutoff() {
        let (binding, files) = event_fixture(64);
        assert_eq!(saved_fleet(&binding, &files).unwrap(), files[&binding.path]);
        assert!(event_fleet(&binding.path));
        for path in [
            "/var/lib/jetstreamer/horizon-204-assembly-fleet-event-/fleet.json",
            "/var/lib/jetstreamer/horizon-204-assembly-fleet-event-a/nested/fleet.json",
            "/var/lib/jetstreamer/horizon-204-assembly-fleet-event-a/other.json",
            "/var/lib/jetstreamer/horizon-204-assembly-fleet-event-a_b/fleet.json",
            "/tmp/horizon-204-assembly-fleet-event-a/fleet.json",
        ] {
            assert!(!event_fleet(Path::new(path)), "{path}");
        }
        let parent = binding.path.parent().unwrap();
        for (file, path, value) in [
            ("plan.json", "/unrelated_gate/must_remain", json!(false)),
            (
                "plan.json",
                "/assembly204_recovery/actor_launch/sha256",
                json!("f".repeat(64)),
            ),
            ("event.json", "/original_plan/sha256", json!("f".repeat(64))),
            ("event.json", "/authority/r2_mutations", json!(true)),
            ("event.json", "/resource_samples_taken", json!(1)),
            ("fleet.json", "/observer_sha256", json!("f".repeat(64))),
            (
                "fleet.json",
                "/sampled_at_utc",
                json!("1970-01-01T00:00:00Z"),
            ),
            ("fleet.json", "/plan", json!("/foreign/plan.json")),
        ] {
            let mut bad = files.clone();
            *bad.get_mut(&parent.join(file))
                .unwrap()
                .pointer_mut(path)
                .unwrap() = value;
            assert!(saved_fleet(&binding, &bad).is_err(), "{file}:{path}");
        }
    }
    #[test]
    fn recovery_event_reader_rejects_predecessor_cycles() {
        let (binding, mut files) = event_fixture(1);
        let parent = binding.path.parent().unwrap();
        files.get_mut(&parent.join("fleet.json")).unwrap()["previous_fleet"] =
            private157::binding(&binding);
        assert!(saved_fleet(&binding, &files).is_err());
    }

    #[test]
    fn terminal_event_reconstructs_exact_history_without_recursive_row_validation() {
        let (binding, mut files) = event_fixture(2);
        let directory = binding.path.parent().unwrap();
        let event_path = directory.join("event.json");
        let mut event = files[&event_path].clone();
        event.as_object_mut().unwrap().remove("claim");
        event["action"] = json!("terminal");
        event["terminal"] = private157::binding(&b("/fixture/terminal.json"));
        let old = files[&PathBuf::from(event["original_plan"]["path"].as_str().unwrap())].clone();
        let prior =
            files[&PathBuf::from(event["previous_fleet"]["path"].as_str().unwrap())].clone();
        let mut expected =
            transition::saved_event_plan(&event, &old, &prior, None, directory).unwrap();
        expected["metadata_event"] = files[&binding.path]["metadata_event"].clone();
        assert!(expected["assembly204_recovery"].is_null());
        assert_eq!(
            expected["assembly204_recovery_history"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        files.insert(event_path, event);
        files.insert(directory.join("plan.json"), expected);
        saved_fleet(&binding, &files).unwrap();
        files.get_mut(&directory.join("plan.json")).unwrap()["assembly204_recovery_terminal"]["sha256"] =
            json!("f".repeat(64));
        assert!(saved_fleet(&binding, &files).is_err());
    }
    fn canary_event_fixture() -> (BoundFile, BTreeMap<PathBuf, Value>) {
        let (previous, mut files) = event_fixture(1);
        let prior = files[&previous.path].clone();
        let original = PathBuf::from(prior["plan"].as_str().unwrap());
        let old = files[&original].clone();
        let fleet = b("/var/lib/jetstreamer/horizon-canary227-terminal-fleet-fixture-v1/fleet.json");
        let plan = b("/var/lib/jetstreamer/horizon-canary227-terminal-fleet-spec-fixture-v1/plan.json");
        let proof = b("/var/lib/jetstreamer/horizon-227-v1625-canary-terminal-selection-v2/proof.json");
        let clock = prior["recorded_unix_seconds"].as_u64().unwrap()+40;
        let at = publication203::utc(clock).unwrap();
        let terminal = json!({"schema":canary227_terminal::SCHEMA,"recorded_unix_seconds":clock,
            "sampled_at_utc":at,"release_credit_bytes":0,"preserve_original_failed227_history":true,
            "repair_gate_state":"failed-needs-repair","invocation_id":"c".repeat(32)});
        let mut next = old.clone();
        next["output"]=json!(fleet.path);next["previous_fleet"]=private157::binding(&previous);
        next["metadata_event"]=private157::binding(&proof);
        next["gates"]["227"]["evidence"]=json!([proof]);
        next["gates"]["227"]["next_action"]=json!("terminal canary; retain failed repair");
        let mut ledger=prior;
        ledger["plan"]=json!(plan.path);ledger["plan_sha256"]=json!(plan.sha256);
        ledger["metadata_event"]=private157::binding(&proof);
        ledger["previous_fleet"]=private157::binding(&previous);
        ledger["metadata_event_sampled_at_utc"]=json!(at);
        ledger["recorded_unix_seconds"]=json!(clock+1);
        files.insert(fleet.path.clone(),ledger);
        files.insert(plan.path,next);files.insert(proof.path,terminal);
        (fleet,files)
    }
    fn saved_canary_fixture(binding:&BoundFile, files:&BTreeMap<PathBuf,Value>) -> Result<Value> {
        let load=|b:&BoundFile| {
            ensure!(b.sha256=="a".repeat(64),"fixture binding digest substituted");
            files.get(&b.path).cloned().context("fixture file absent")
        };
        accepted_fleet_with(binding,&load,&|b,_|load(b),&|prior,plan,proof,sample,recorded,old| {
            // This is a pure lineage fixture, not an actual terminal proof.
            // Runtime always calls the shared real saved_predecessor validator.
            let clock=proof["recorded_unix_seconds"].as_u64().context("fixture clock")?;
            ensure!(prior["sampled_at_utc"]==sample && plan["observer"]["path"]==prior["observer_receipt"]
                && plan["observer"]["sha256"]==prior["observer_sha256"]
                && clock<=recorded && recorded-clock<=300
                && proof["release_credit_bytes"]==0 && proof["preserve_original_failed227_history"]==true
                && proof["repair_gate_state"]=="failed-needs-repair"
                && proof["invocation_id"]=="c".repeat(32),"fixture terminal transition rejected");
            canary227_terminal::saved_plan_projection(old,plan)
        })
    }
    #[test]
    fn terminal227_private_event_replays_its_actual_historical_time_and_keeps_204_claim() {
        let (binding,files)=canary_event_fixture();
        let raw=files.clone();
        let read=saved_canary_fixture(&binding,&files).unwrap();
        assert_eq!(read,files[&binding.path]);
        assert_eq!(files,raw);
        let prior=&files[&PathBuf::from(read["previous_fleet"]["path"].as_str().unwrap())];
        let old=&files[&PathBuf::from(prior["plan"].as_str().unwrap())];
        let current=&files[&PathBuf::from(read["plan"].as_str().unwrap())];
        assert_eq!(current["assembly204_recovery"],old["assembly204_recovery"]);
        assert_eq!(current["assembly204_recovery_history"],old["assembly204_recovery_history"]);
        assert!(read["recorded_unix_seconds"].as_u64().unwrap() < 20000);
        // No wall-clock input is consulted to retroactively expire a valid event.
        saved_canary_fixture(&binding,&files).unwrap();
    }
    #[test]
    fn terminal227_namespace_and_exact_separate_plan_pairing_are_closed() {
        let (binding,files)=canary_event_fixture();
        for path in [
            "/var/lib/jetstreamer/horizon-canary227-terminal-fleet-/fleet.json",
            "/var/lib/jetstreamer/horizon-canary227-terminal-fleet-spec-fixture/fleet.json",
            "/var/lib/jetstreamer/horizon-canary227-terminal-fleet-fixture/nested/fleet.json",
            "/var/lib/jetstreamer/horizon-canary227-terminal-fleet-fixture_v1/fleet.json",
            "/tmp/horizon-canary227-terminal-fleet-fixture/fleet.json",
        ] { assert!(!canary_terminal_fleet(Path::new(path)),"{path}"); }
        for (key,value) in [
            ("plan",json!("/var/lib/jetstreamer/horizon-canary227-terminal-fleet-spec-other/plan.json")),
            ("metadata_event",json!({"path":"/foreign/proof.json","sha256":"a".repeat(64)})),
            ("previous_fleet",private157::binding(&binding)),
        ] {
            let mut bad=files.clone();bad.get_mut(&binding.path).unwrap()[key]=value;
            assert!(saved_canary_fixture(&binding,&bad).is_err(),"{key}");
        }
    }
    #[test]
    fn terminal227_event_cannot_substitute_proof_observer_claim_history_or_other_fields() {
        let (binding,files)=canary_event_fixture();
        let ledger=&files[&binding.path];
        let plan=PathBuf::from(ledger["plan"].as_str().unwrap());
        let proof=PathBuf::from(ledger["metadata_event"]["path"].as_str().unwrap());
        for (file,key,value) in [
            (plan.clone(),"observer",json!({"path":"/foreign/observer.json","sha256":"a".repeat(64)})),
            (plan.clone(),"assembly204_recovery",Value::Null),
            (plan.clone(),"assembly204_recovery_history",json!([{"invented":true}])),
            (plan.clone(),"unrelated_guard_floor",json!(0)),
            (proof.clone(),"schema",json!("foreign-terminal-schema")),
            (proof.clone(),"release_credit_bytes",json!(1)),
            (proof.clone(),"preserve_original_failed227_history",json!(false)),
            (proof.clone(),"invocation_id",json!("d".repeat(32))),
            (binding.path.clone(),"observer_sha256",json!("b".repeat(64))),
            (binding.path.clone(),"metadata_event_sampled_at_utc",json!("1970-01-01T00:00:00Z")),
        ] {
            let mut bad=files.clone();bad.get_mut(&file).unwrap()[key]=value;
            assert!(saved_canary_fixture(&binding,&bad).is_err(),"{}:{key}",file.display());
        }
        let mut stale=files.clone();stale.get_mut(&binding.path).unwrap()["recorded_unix_seconds"]=
            json!(files[&proof]["recorded_unix_seconds"].as_u64().unwrap()+301);
        assert!(saved_canary_fixture(&binding,&stale).is_err());
    }

}
