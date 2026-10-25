//! An explicit accepted whole-fleet context for recovery metadata operations.
//! The unchanged global census still rejects every newly unbound producer.
use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub fleet: BoundFile,
    pub observer: BoundFile,
}
impl Context {
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
    fn accepted(&self) -> Result<Value> {
        ensure!(
            self.fleet
                .path
                .starts_with("/var/lib/jetstreamer/horizon-campaign-fleet"),
            "204 recovery needs the accepted fleet namespace"
        );
        let f = bound_json(&self.fleet)?;
        let o = bound_json(&self.observer)?;
        let sample = utc_seconds(s(&o, "recorded_at_utc")?)?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        ensure!(
            f["schema"] == SCHEMA
                && f["first_epoch"] == 201
                && f["last_epoch"] == 300
                && f["observer_receipt"] == self.observer.path.to_string_lossy().as_ref()
                && f["observer_sha256"] == self.observer.sha256
                && f["sampled_at_utc"] == o["recorded_at_utc"]
                && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
                && sample <= now
                && now - sample <= 1800,
            "204 recovery context is stale, foreign or not the accepted coordinated observation"
        );
        Ok(f)
    }
    pub(super) fn census(&self, hints: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
        let f = self.accepted()?;
        let names = requested_names(&f, hints)?;
        let current = census(&names, 201, 300)?;
        validate_peer_bindings(&f, &current)?;
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
        ensure!(
            self.accepted()? == f,
            "204 accepted context changed during metadata census"
        );
        Ok(current)
    }
}
pub(super) fn subject(name: &str) -> bool {
    name == OLD_UNIT || name == OLD_GUARD || scope(name, 204, 204)
}
pub(super) fn closed_names() -> BTreeSet<String> {
    let mut names = BTreeSet::from([OLD_UNIT.into(), OLD_GUARD.into(), UNIT.into(), GUARD.into()]);
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
        complete.insert(
            "horizon-qualify-204-unknown-replacement.service".into(),
            live("horizon-qualify-204-unknown-replacement.service", 204),
        );
        assert!(ownership::validate_closed_ownership(&complete, None).is_err());
        assert!(!subject("horizon-qualify-204-unknown-replacement.service"));
        assert!(!names.contains("horizon-qualify-204-unknown-replacement.service"));
    }
}
