//! A scheduled successor observation can precede its accepted fleet. Retain the
//! exact historical predecessor and actual launch; never synthesize either.
use super::*;
fn lineage(new: &BoundFile, observer: &Value, old: &BoundFile, previous: &Value) -> Result<()> {
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous["schema"] == observer["schema"],
        "capped observer schema differs"
    );
    if new == old {
        ensure!(observer == previous, "same observer binding changed");
        return Ok(());
    }
    let at = utc_seconds(string(observer, "recorded_at_utc")?)?;
    let before = utc_seconds(string(previous, "recorded_at_utc")?)?;
    let cadence = &observer["cadence"];
    ensure!(
        new.path != old.path
            && at > before
            && cadence["previous_sample"].as_str() == old.path.to_str()
            && cadence["previous_sample_sha256"] == old.sha256
            && cadence["previous_sample_recorded_at_utc"] == previous["recorded_at_utc"]
            && cadence["minimum_interval_seconds"] == 1800
            && cadence["observed_interval_seconds"] == at - before
            && ((cadence["observation_reason"] == "routine"
                && cadence["routine_minimum_interval_enforced"] == true
                && at - before >= 1800)
                || (cadence["observation_reason"] == "user-requested-status"
                    && cadence["routine_minimum_interval_enforced"] == false)),
        "capped successor observer lost exact forward cadence lineage"
    );
    Ok(())
}
const MAX_CHAIN_HOPS: usize = 64;
const MAX_NODE_BYTES: usize = 4 << 20;
const MAX_CHAIN_BYTES: usize = 64 << 20;
fn binding_shape(b: &BoundFile) -> Result<()> {
    ensure!(
        b.path.is_absolute()
            && b.path.components().all(|c| matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            ))
            && b.path.extension().is_some_and(|v| v == "json")
            && canonical_digest(&json!(b.sha256)),
        "invalid capped observer chain binding"
    );
    Ok(())
}
fn chain_with(
    new: &BoundFile,
    observer: &Value,
    old: &BoundFile,
    mut read: impl FnMut(&BoundFile) -> Result<Vec<u8>>,
) -> Result<()> {
    binding_shape(new)?;
    binding_shape(old)?;
    let mut binding = new.clone();
    let mut seen = BTreeSet::new();
    let mut total = 0usize;
    let mut child: Option<(BoundFile, Value)> = None;
    for hops in 0..=MAX_CHAIN_HOPS {
        binding_shape(&binding)?;
        ensure!(
            seen.insert(binding.path.clone()),
            "capped observer chain cycles or reuses a path"
        );
        ensure!(
            binding.path != old.path || binding == *old,
            "capped observer chain reached a foreign accepted-observer digest"
        );
        let raw = read(&binding)?;
        total = total
            .checked_add(raw.len())
            .context("capped observer chain byte overflow")?;
        ensure!(
            raw.len() <= MAX_NODE_BYTES
                && total <= MAX_CHAIN_BYTES
                && hex_lower(&Sha256::digest(&raw)) == binding.sha256,
            "capped observer chain exceeded metadata bounds or changed bytes"
        );
        let node: Value = serde_json::from_slice(&raw)?;
        ensure!(
            node["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
            "capped observer chain contains a foreign schema"
        );
        if let Some((child_binding, child_value)) = child {
            lineage(&child_binding, &child_value, &binding, &node)?;
        } else {
            ensure!(
                node == *observer,
                "current capped observer differs from its genuine bound bytes"
            );
        }
        if binding == *old {
            return Ok(());
        }
        ensure!(
            hops < MAX_CHAIN_HOPS,
            "capped observer chain exceeds hop bound"
        );
        let parent = BoundFile {
            path: string(&node["cadence"], "previous_sample")?.into(),
            sha256: string(&node["cadence"], "previous_sample_sha256")?.into(),
        };
        child = Some((binding, node));
        binding = parent;
    }
    bail!("capped observer chain did not reach the accepted predecessor")
}
fn launch_identity(plan: &BoundFile, admission: &BoundFile, launch: &Value) -> Result<()> {
    ensure!(
        launch["schema"] == "jetstreamer-capped204205-continuation-launch-v1"
            && launch["producer_plan"] == private157::binding(plan)
            && launch["admission"] == private157::binding(admission)
            && launch["invocation_id"].as_str().is_some_and(id),
        "capped observation handoff changed actual launch/source admission"
    );
    Ok(())
}
pub(super) fn validate(
    previous: &BoundFile,
    new: &BoundFile,
    observer: &Value,
    plan: &BoundFile,
    admission: &BoundFile,
    launch: &Value,
) -> Result<()> {
    let prior = evidence::bound(previous, false)?;
    let old = BoundFile {
        path: string(&prior, "observer_receipt")?.into(),
        sha256: string(&prior, "observer_sha256")?.into(),
    };
    // Authenticate the accepted raw predecessor through the existing typed
    // historical reader. Its old sample may expire; only the new sample is used
    // as current resource context and remains subject to ordinary freshness.
    ensure!(
        assembly204_recovery::accepted_context(previous, &old)? == prior,
        "capped handoff predecessor is not the accepted fleet"
    );
    // Every node is a genuine canonical, root-owned readonly receipt. Root may
    // seal completed observer files without changing their bytes or timestamps.
    chain_with(new, observer, &old, |b| evidence::bytes(b, true))?;
    launch_identity(plan, admission, launch)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixtures() -> (BoundFile, Value, BoundFile, Value) {
        let old = BoundFile {
            path: "/sealed/old-observer.json".into(),
            sha256: "a".repeat(64),
        };
        let new = BoundFile {
            path: "/sealed/new-observer.json".into(),
            sha256: "b".repeat(64),
        };
        let previous = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-25T21:55:00Z"});
        let current = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-25T22:26:00Z",
            "cadence":{"previous_sample":old.path,"previous_sample_sha256":old.sha256,"previous_sample_recorded_at_utc":previous["recorded_at_utc"],
            "minimum_interval_seconds":1800,"observed_interval_seconds":1860,"observation_reason":"routine","routine_minimum_interval_enforced":true}});
        (new, current, old, previous)
    }
    #[test]
    fn capped_successor_observer_keeps_genuine_expired_predecessor_lineage() {
        let (new, current, old, previous) = fixtures();
        lineage(&new, &current, &old, &previous).unwrap();
        assert!(lineage(&old, &current, &old, &previous).is_err());
        for (pointer, value) in [
            ("/cadence/previous_sample_sha256", json!("f".repeat(64))),
            ("/cadence/previous_sample", json!("/other.json")),
            (
                "/cadence/previous_sample_recorded_at_utc",
                json!("2026-10-25T21:54:00Z"),
            ),
            ("/cadence/observed_interval_seconds", json!(1800)),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
        ] {
            let mut bad = current.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(lineage(&new, &bad, &old, &previous).is_err(), "{pointer}");
        }
    }
    #[test]
    fn capped_observer_handoff_preserves_explicit_user_poll_exception_only() {
        let (new, mut current, old, previous) = fixtures();
        current["recorded_at_utc"] = json!("2026-10-25T21:56:00Z");
        current["cadence"]["observed_interval_seconds"] = json!(60);
        assert!(lineage(&new, &current, &old, &previous).is_err());
        current["cadence"]["observation_reason"] = json!("user-requested-status");
        current["cadence"]["routine_minimum_interval_enforced"] = json!(false);
        lineage(&new, &current, &old, &previous).unwrap();
        current["recorded_at_utc"] = previous["recorded_at_utc"].clone();
        current["cadence"]["observed_interval_seconds"] = json!(0);
        assert!(lineage(&new, &current, &old, &previous).is_err());
    }
    #[test]
    fn capped_observer_handoff_cannot_borrow_another_launch_plan_or_admission() {
        let (plan, _, admission, _) = fixtures();
        let launch = json!({"schema":"jetstreamer-capped204205-continuation-launch-v1","producer_plan":private157::binding(&plan),"admission":private157::binding(&admission),"invocation_id":"1".repeat(32)});
        launch_identity(&plan, &admission, &launch).unwrap();
        for key in ["producer_plan", "admission", "invocation_id"] {
            let mut bad = launch.clone();
            bad[key] = Value::Null;
            assert!(launch_identity(&plan, &admission, &bad).is_err());
        }
    }
    fn node(
        path: &str,
        time: u64,
        parent: Option<(&BoundFile, u64)>,
    ) -> (BoundFile, Value, Vec<u8>) {
        let stamp = publication203::utc(time).unwrap();
        let mut value =
            json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":stamp});
        if let Some((parent, before)) = parent {
            value["cadence"] = json!({"previous_sample":parent.path,"previous_sample_sha256":parent.sha256,
                "previous_sample_recorded_at_utc":publication203::utc(before).unwrap(),"minimum_interval_seconds":1800,
                "observed_interval_seconds":time-before,"observation_reason":"routine","routine_minimum_interval_enforced":true});
        }
        let bytes = serde_json::to_vec(&value).unwrap();
        (
            BoundFile {
                path: path.into(),
                sha256: hex_lower(&Sha256::digest(&bytes)),
            },
            value,
            bytes,
        )
    }
    fn read_saved(b: &BoundFile, files: &BTreeMap<PathBuf, Vec<u8>>) -> Result<Vec<u8>> {
        files
            .get(&b.path)
            .cloned()
            .context("missing genuine chain node")
    }
    #[test]
    fn capped_observer_chain_bridges_two_genuine_missed_cycles_without_fleet_relabeling() {
        let (old, _, oldraw) = node("/sealed/425.json", 1_000_000, None);
        let (middle, _, midraw) = node("/sealed/426.json", 1_001_800, Some((&old, 1_000_000)));
        let (new, current, newraw) =
            node("/sealed/427.json", 1_003_600, Some((&middle, 1_001_800)));
        let files = BTreeMap::from([
            (old.path.clone(), oldraw),
            (middle.path.clone(), midraw),
            (new.path.clone(), newraw),
        ]);
        chain_with(&new, &current, &old, |b| read_saved(b, &files)).unwrap();
        let mut missing = files.clone();
        missing.remove(&middle.path);
        assert!(chain_with(&new, &current, &old, |b| read_saved(b, &missing)).is_err());
        let mut changed = files.clone();
        changed.get_mut(&middle.path).unwrap().push(b' ');
        assert!(chain_with(&new, &current, &old, |b| read_saved(b, &changed)).is_err());
        let foreign = BoundFile {
            path: old.path.clone(),
            sha256: "f".repeat(64),
        };
        assert!(chain_with(&new, &current, &foreign, |b| read_saved(b, &files)).is_err());
    }
    #[test]
    fn capped_observer_chain_rejects_cycles_depth_and_unauthorized_short_edges() {
        let (old, _, raw) = node("/sealed/base.json", 1_000_000, None);
        let mut files = BTreeMap::from([(old.path.clone(), raw)]);
        let mut last = old.clone();
        let mut time = 1_000_000;
        let mut current = Value::Null;
        for i in 1..=MAX_CHAIN_HOPS + 1 {
            let (b, v, raw) = node(
                &format!("/sealed/{i}.json"),
                time + 1800,
                Some((&last, time)),
            );
            files.insert(b.path.clone(), raw);
            last = b;
            current = v;
            time += 1800;
        }
        assert!(chain_with(&last, &current, &old, |b| read_saved(b, &files)).is_err());
        let (new, current, newraw) = node("/sealed/short.json", 1_000_060, Some((&old, 1_000_000)));
        files.insert(new.path.clone(), newraw);
        assert!(chain_with(&new, &current, &old, |b| read_saved(b, &files)).is_err());
        // A path cycle cannot earn another read even when a bound reader is
        // supplied with bytes whose parent points back to the current path.
        let mut cycle = current;
        cycle["cadence"]["previous_sample"] = json!(new.path);
        let raw = serde_json::to_vec(&cycle).unwrap();
        let cyclic = BoundFile {
            path: new.path.clone(),
            sha256: hex_lower(&Sha256::digest(&raw)),
        };
        files.insert(cyclic.path.clone(), raw);
        assert!(chain_with(&cyclic, &cycle, &old, |b| read_saved(b, &files)).is_err());
    }
    #[test]
    fn capped_observer_chain_rejects_foreign_schema_noncanonical_paths_and_oversize_nodes() {
        let (old, previous, raw) = node("/sealed/base.json", 1_000_000, None);
        let files = BTreeMap::from([(old.path.clone(), raw)]);
        let foreign = BoundFile {
            path: "/sealed/../base.json".into(),
            sha256: old.sha256.clone(),
        };
        assert!(chain_with(&foreign, &previous, &old, |b| read_saved(b, &files)).is_err());
        for mut bad in [json!({"schema":"foreign"}), previous.clone()] {
            if bad["schema"] != "foreign" {
                bad["padding"] = json!("x".repeat(MAX_NODE_BYTES));
            }
            let raw = serde_json::to_vec(&bad).unwrap();
            let bound = BoundFile {
                path: old.path.clone(),
                sha256: hex_lower(&Sha256::digest(&raw)),
            };
            assert!(chain_with(&bound, &bad, &bound, |_| Ok(raw.clone())).is_err());
        }
    }
}
