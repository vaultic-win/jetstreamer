//! Extend reviewed growth maxima over a proof-bound controller-only restart.
use super::*;
const REBIND: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json";
const REBIND_SHA: &str = "a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2";
const BASES: [(&str, &str); 3] = [
    (
        "152-153",
        "bd11552bf3528b0bb1e07e25d9a20c84eb712299f06a205fd6ca6212293990b5",
    ),
    (
        "155-156",
        "a77c8caee603971a1608fddba779b6b74b9fb73e729e0daf5c4360fdb3223c46",
    ),
    (
        "191-194",
        "c5bf2df3f569845d8694231a7d2ece86e74e62e9ee88c47677734c45aeacefb6",
    ),
];
fn row<'a>(o: &'a Value, range: &str) -> Result<&'a Value> {
    let rows = o["replays"].as_array().context("growth replay census")?;
    let matches: Vec<_> = rows.iter().filter(|r| r["range"] == range).collect();
    ensure!(matches.len() == 1, "growth owner missing/duplicated");
    Ok(matches[0])
}
fn chain(previous: &BoundFile, old: &Value, next: &Value) -> Result<()> {
    let t = utc_seconds(
        old["recorded_at_utc"]
            .as_str()
            .context("old growth clock")?,
    )?;
    let n = utc_seconds(
        next["recorded_at_utc"]
            .as_str()
            .context("new growth clock")?,
    )?;
    ensure!(
        next["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && next["cadence"]["previous_sample"].as_str() == previous.path.to_str()
            && next["cadence"]["previous_sample_sha256"] == previous.sha256
            && next["cadence"]["previous_sample_recorded_at_utc"] == old["recorded_at_utc"]
            && next["cadence"]["routine_minimum_interval_enforced"] == true
            && n.checked_sub(t).is_some_and(|d| d >= 1800)
            && next["cadence"]["observed_interval_seconds"] == n - t,
        "broken/non-routine growth extension chain"
    );
    Ok(())
}
fn owner(old: &Value, new: &Value, adoption: &Value, base_controller: &Value) -> Result<()> {
    ensure!(
        new["invocation_binding_stable"] == true
            && new["scratch_path"].is_string()
            && new["scratch_path"] == old["scratch_path"]
            && new["producer_after"]["invocation_id"] == old["producer_after"]["invocation_id"]
            && new["producer_after"]["main_pid"] == old["producer_after"]["main_pid"]
            && new["producer_after"]["unit"] == old["producer_after"]["unit"]
            && new["controller_after"]["unit"] == old["controller_after"]["unit"]
            && new["worker_after"]["pid"] == old["worker_after"]["pid"]
            && new["worker_after"]["executable"] == old["worker_after"]["executable"]
            && new["worker_after"]["executable_beneath_bound_scratch"] == true
            && new["worker_after"]["matching_workers"] == 1
            && new["worker_after"]["vmas"]
                .as_u64()
                .is_some_and(|v| v > 0 && v < 800000)
            && new["useful_work"]["sufficient_for_rates"] == true
            && new["useful_work"]["slots_per_second"]
                .as_f64()
                .is_some_and(|v| v.is_finite() && v > 0.),
        "growth producer/scratch/worker changed or not progressing"
    );
    for kind in ["controller", "producer"] {
        let key = format!("{kind}_after");
        let u = &new[&key];
        ensure!(
            u["active_state"] == "active" && u["sub_state"] == "running" && u["restarts"] == 0,
            "growth owner inactive/restarted"
        );
        let before = &new[format!("{kind}_before")];
        ensure!(
            before["invocation_id"] == u["invocation_id"] && before["main_pid"] == u["main_pid"],
            "growth owner unstable within sample"
        );
    }
    ensure!(
        adoption["old_controller_invocation_id"] == *base_controller
            && adoption["producer_invocation_id"] == new["producer_after"]["invocation_id"]
            && adoption["new_controller_invocation_id"] == new["controller_after"]["invocation_id"]
            && adoption["command_unchanged"] == true
            && (old["controller_after"]["invocation_id"] == *base_controller
                || old["controller_after"]["invocation_id"]
                    == adoption["new_controller_invocation_id"]),
        "growth lacks exact controller adoption proof"
    );
    for key in [
        "memory_events.oom",
        "memory_events.oom_kill",
        "memory_events.oom_group_kill",
        "memory_events.max",
    ] {
        ensure!(
            new["cross_sample"]["producer_cgroup_counter_delta"][key] == 0,
            "growth extension memory event:{key}"
        );
    }
    Ok(())
}
fn minimum(prior_max: u64, observed: u64, jet: u64) -> Result<(u64, u64)> {
    let max = prior_max.max(observed);
    let n = max
        .checked_mul(2)
        .and_then(|v| jet.checked_mul(2).and_then(|j| v.checked_add(j)))
        .context("growth extension overflow")?;
    ensure!(n <= 512u64 << 30, "extended growth no longer fits 512 GiB");
    Ok((max, n))
}
pub(super) fn extend(s: &Spec) -> Result<Value> {
    ensure!(
        !s.growth_extension_observers.is_empty() && s.growth_extension_observers.len() <= 96,
        "growth extension required/bounded"
    );
    let last = s.growth_extension_observers.last().unwrap();
    ensure!(
        last.path == s.observer.path && last.sha256 == s.observer.sha256,
        "growth extension must reach current accepted sample"
    );
    let proof = BoundFile {
        path: REBIND.into(),
        sha256: REBIND_SHA.into(),
    };
    sealed_file(&proof)?;
    let rebind = bound_json(&proof)?;
    let mut results = serde_json::Map::new();
    for (range, sha) in BASES {
        let b = s.growth.get(range).context("growth base missing")?;
        ensure!(b.sha256 == sha, "unreviewed growth base");
        let g = bound_json(b)?;
        let observations = g["observations"].as_array().context("growth history")?;
        ensure!(
            observations.len() >= 12
                && g["range"] == range
                && g["schema"] == "jetstreamer-horizon-growth-claim-v1"
                && g["scratch_multiplier"] == 2
                && g["max_jet_multiplier"] == 2
                && g["requested_claim_bytes"] == 512u64 << 30,
            "unsupported growth base shape"
        );
        let tail = observations.last().unwrap();
        let mut previous: BoundFile =
            serde_json::from_value(json!({"path":tail["path"],"sha256":tail["sha256"]}))?;
        let mut old = bound_json(&previous)?;
        let adoption = rebind["bindings"]
            .as_array()
            .context("rebind mappings")?
            .iter()
            .find(|v| v["range"] == range)
            .context("rebind range")?;
        let mut max = g["maximum_observed_scratch_bytes"]
            .as_u64()
            .context("base scratch maximum")?;
        let jet = g["maximum_verified_jet_bytes"]
            .as_u64()
            .context("base verified jet")?;
        let (_, base_minimum) = minimum(max, 0, jet)?;
        ensure!(
            g["formula_minimum_bytes"] == base_minimum
                && row(&old, range)?["producer_after"]["invocation_id"]
                    == g["producer_invocation_id"]
                && row(&old, range)?["controller_after"]["invocation_id"]
                    == g["controller_invocation_id"],
            "base growth evidence differs"
        );
        let mut computed = base_minimum;
        for binding in &s.growth_extension_observers {
            let next = bound_json(binding)?;
            chain(&previous, &old, &next)?;
            let n = row(&next, range)?;
            owner(
                row(&old, range)?,
                n,
                adoption,
                &g["controller_invocation_id"],
            )?;
            (max, computed) = minimum(
                max,
                n["conservative_observed_physical_bytes"]
                    .as_u64()
                    .context("extension scratch")?,
                jet,
            )?;
            previous = BoundFile {
                path: binding.path.clone(),
                sha256: binding.sha256.clone(),
            };
            old = next;
        }
        results.insert(range.into(), json!({"base":private157::binding(b),"maximum_observed_scratch_bytes":max,
            "maximum_verified_jet_bytes":jet,"formula_minimum_bytes":computed,"requested_claim_bytes":512u64<<30}));
    }
    Ok(
        json!({"controller_adoption":private157::binding(&proof),"observers":s.growth_extension_observers,
        "ranges":results,"prior_maxima_preserved":true,"active_controller_claims_changed":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root exact fourteen-window growth bases and controller-rebound 06:39 sample; evidence reads only"]
    fn actual_growth_bridge_retains_all_prior_maxima() {
        let (mut s, ..) = super::super::tests::fixture();
        s.observer=BoundFile{path:"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261023T063958Z.json".into(),sha256:"87d714a3652649a2bcf2bd0f0629d3638785e76e45c9286bfd62fb7aeb0d1b99".into()};
        s.growth_extension_observers = vec![BoundFile {
            path: s.observer.path.clone(),
            sha256: s.observer.sha256.clone(),
        }];
        s.growth=BASES.into_iter().map(|(range,sha)|(range.into(),BoundFile{path:format!("/var/lib/jetstreamer/horizon-growth-claims-20261023T055958Z-five-lane-refresh-v3/growth-{range}.json").into(),sha256:sha.into()})).collect();
        let e = extend(&s).unwrap();
        for (range, _) in BASES {
            let old = bound_json(&s.growth[range]).unwrap();
            assert!(
                e["ranges"][range]["maximum_observed_scratch_bytes"]
                    .as_u64()
                    .unwrap()
                    >= old["maximum_observed_scratch_bytes"].as_u64().unwrap()
            );
            assert!(
                e["ranges"][range]["formula_minimum_bytes"]
                    .as_u64()
                    .unwrap()
                    <= 512u64 << 30
            );
        }
    }
    #[test]
    fn compaction_never_reduces_prior_maximum() {
        assert_eq!(minimum(150, 10, 20).unwrap(), (150, 340));
        assert_eq!(minimum(150, 170, 20).unwrap(), (170, 380));
        assert!(minimum(280u64 << 30, 1, 0).is_err());
        assert!(minimum(u64::MAX, 0, 1).is_err());
    }
    #[test]
    fn only_hash_linked_spaced_routine_extensions() {
        let b = BoundFile {
            path: "/prior.json".into(),
            sha256: "a".repeat(64),
        };
        let old = json!({"recorded_at_utc":"2026-10-23T05:59:58Z"});
        let next = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T06:39:58Z",
            "cadence":{"previous_sample":"/prior.json","previous_sample_sha256":b.sha256,
                "previous_sample_recorded_at_utc":old["recorded_at_utc"],"routine_minimum_interval_enforced":true,"observed_interval_seconds":2400}});
        chain(&b, &old, &next).unwrap();
        for (key, value) in [
            ("previous_sample_sha256", json!("b".repeat(64))),
            ("routine_minimum_interval_enforced", json!(false)),
            ("observed_interval_seconds", json!(1800)),
        ] {
            let mut bad = next.clone();
            bad["cadence"][key] = value;
            assert!(chain(&b, &old, &bad).is_err(), "{key}");
        }
        let mut short = next.clone();
        short["recorded_at_utc"] = json!("2026-10-23T06:00:58Z");
        short["cadence"]["observed_interval_seconds"] = json!(60);
        assert!(chain(&b, &old, &short).is_err());
    }
    #[test]
    fn controller_bridge_never_adopts_another_worker_or_scratch() {
        let unit = json!({"invocation_id":"producer","main_pid":10,"unit":"producer.service","active_state":"active","sub_state":"running","restarts":0});
        let controller = json!({"invocation_id":"old","main_pid":20,"unit":"controller.service","active_state":"active","sub_state":"running","restarts":0});
        let old = json!({"invocation_binding_stable":true,"scratch_path":"/private/scratch","producer_after":unit,"producer_before":unit,
            "controller_after":controller,"controller_before":controller,"worker_after":{"pid":11,"executable":"/private/scratch/worker","matching_workers":1,"vmas":100,"executable_beneath_bound_scratch":true},
            "useful_work":{"sufficient_for_rates":true,"slots_per_second":1.},"cross_sample":{"producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}}});
        let mut new = old.clone();
        for key in ["controller_before", "controller_after"] {
            new[key]["invocation_id"] = json!("new");
            new[key]["main_pid"] = json!(21);
        }
        let adoption = json!({"old_controller_invocation_id":"old","new_controller_invocation_id":"new","producer_invocation_id":"producer","command_unchanged":true});
        owner(&old, &new, &adoption, &json!("old")).unwrap();
        owner(&new, &new, &adoption, &json!("old")).unwrap();
        for (pointer, value) in [
            ("/scratch_path", json!("/other")),
            ("/producer_after/invocation_id", json!("replacement")),
            ("/producer_after/main_pid", json!(12)),
            ("/worker_after/pid", json!(12)),
            ("/worker_after/executable", json!("/other/worker")),
            ("/worker_after/vmas", json!(800000)),
            ("/controller_after/restarts", json!(1)),
            ("/useful_work/slots_per_second", json!(0.)),
            (
                "/cross_sample/producer_cgroup_counter_delta/memory_events.oom",
                json!(1),
            ),
        ] {
            let mut bad = new.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                owner(&old, &bad, &adoption, &json!("old")).is_err(),
                "{pointer}"
            );
        }
        let mut bad = adoption.clone();
        bad["command_unchanged"] = json!(false);
        assert!(owner(&old, &new, &bad, &json!("old")).is_err());
    }
}
