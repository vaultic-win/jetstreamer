//! Exact recovery of five package-restarted controllers; original producers live on.
use super::*;
const PROOF: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/unit-bindings.json";
const SHA: &str = "a4ce1f8dd91853e8837fb8bf17b923fa4874c726ed551e84dc7b4ae720f2fab2";
const FIRES: &str = "/usr/local/lib/jetstreamer/horizon-controller-rebind-proof-20261023-v1/first-guard-proofs.json";
const FIRES_SHA: &str = "c9cb0f531c5461f6577c4bedb50491a42f0edc33b69a2186f081e0e16d95fa6b";
const PROFILES: &str =
    "/usr/local/lib/jetstreamer/horizon-controller-rebind-guards-20261023-v1/guard-profiles.json";
const PROFILES_SHA: &str = "02ad16d0b9eae144b0273163e6a89b79f54fb5ec4d6b86ae027dafc71358d7f5";
const RANGES: [&str; 5] = ["152-153", "155-156", "191-194", "183-184", "185-185"];
const OLD: &str = "2026-10-23T05:59:58Z";
const FIRST: &str = "2026-10-23T06:39:58Z";
fn binding() -> Bound {
    Bound {
        path: PROOF.into(),
        sha256: SHA.into(),
    }
}
fn prefix(v: &Value) -> Option<&str> {
    v.as_str()?.split_once(" ; ignore_errors=").map(|(s, _)| s)
}
fn checked(v: &Value, profiles: &Value, fires: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-controller-rebind-units-v2"
            && v["host"] == "dev-samjohnson"
            && v["observer"]["sha256"]
                == "ff0e6cb88985b95fee3ee8cea8af460200ac8001e5e1ca48d4dc9b3026a289b3"
            && profiles["schema"] == "jetstreamer-controller-rebind-guard-profiles-v2"
            && fires["schema"] == "jetstreamer-controller-rebind-first-guard-proofs-v2"
            && fires["profiles"]["path"] == PROFILES
            && fires["profiles"]["sha256"] == PROFILES_SHA,
        "foreign controller-rebind evidence"
    );
    let rows = v["bindings"].as_array().context("controller bindings")?;
    let ps = profiles["profiles"].as_array().context("guard profiles")?;
    let fs = fires["proofs"].as_array().context("guard fires")?;
    ensure!(
        rows.len() == 5
            && ps.len() == 5
            && fs.len() == 5
            && rows
                .iter()
                .filter_map(|r| r["range"].as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(RANGES),
        "incomplete controller recovery"
    );
    for r in rows {
        let p = ps
            .iter()
            .find(|p| p["range"] == r["range"])
            .context("guard profile missing")?;
        let f = fs
            .iter()
            .find(|f| f["range"] == r["range"])
            .context("guard fire missing")?;
        let g = &f["evidence"];
        ensure!(
            p["identities"] == *r
                && g["armed"] == true
                && g["trip"] == false
                && g["controller"]["invocation_id"] == r["new_controller_invocation_id"]
                && g["producer"]["invocation_id"] == r["producer_invocation_id"]
                && g["producer"]["worker_count"] == 1
                && g["producer"]["worker_vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 800000)
                && g["maximum_worker_vmas"] == 800000,
            "unguarded controller recovery"
        );
        for (kind, id) in [
            ("controller", "new_controller_invocation_id"),
            ("producer", "producer_invocation_id"),
        ] {
            let name = g[kind]["unit"].as_str().context("owner unit")?;
            let old = &v["old_units"][name];
            let new = &v["current_units"][name];
            ensure!(
                new["InvocationID"] == r[id]
                    && new["ActiveState"] == "active"
                    && new["SubState"] == "running"
                    && new["NRestarts"] == "0"
                    && prefix(&old["ExecStart"]) == prefix(&new["ExecStart"]),
                "controller recovery changes command or current owner"
            );
            if kind == "producer" {
                ensure!(
                    old["InvocationID"] == new["InvocationID"] && old["MainPID"] == new["MainPID"],
                    "recovery cannot change producer or clock"
                );
            } else {
                ensure!(
                    old["InvocationID"] == r["old_controller_invocation_id"]
                        && old["InvocationID"] != new["InvocationID"],
                    "recovery old controller differs"
                );
            }
        }
    }
    Ok(())
}
fn evidence(p: &Plan) -> Result<Option<Value>> {
    let Some(b) = &p.controller_rebind else {
        return Ok(None);
    };
    ensure!(
        b.path == Path::new(PROOF) && b.sha256 == SHA && is_101(p)?,
        "unsupported controller-rebind profile"
    );
    let v = bound_json(b, true)?;
    checked(
        &v,
        &bound_json(
            &Bound {
                path: PROFILES.into(),
                sha256: PROFILES_SHA.into(),
            },
            true,
        )?,
        &bound_json(
            &Bound {
                path: FIRES.into(),
                sha256: FIRES_SHA.into(),
            },
            true,
        )?,
    )?;
    Ok(Some(v))
}
pub(super) fn interval(p: &Plan) -> Result<u64> {
    evidence(p)?;
    Ok(
        if p.previous_observer
            .path
            .to_str()
            .is_some_and(|s| s.ends_with("sample-20261023T055958Z.json"))
        {
            ensure!(
                p.sample_target_utc == FIRST,
                "controller recovery first schedule differs"
            );
            2400
        } else {
            1800
        },
    )
}
pub(super) fn controller(p: &Plan, range: &str, old: &str, producer: &str) -> Result<String> {
    let Some(v) = evidence(p)? else {
        return Ok(old.into());
    };
    let r = v["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["range"] == range)
        .context("controller range missing")?;
    ensure!(
        r["old_controller_invocation_id"] == old && r["producer_invocation_id"] == producer,
        "controller mapping cannot borrow source proof"
    );
    Ok(r["new_controller_invocation_id"]
        .as_str()
        .context("new controller")?
        .into())
}
fn transform(model: &Value, v: &Value) -> Result<Value> {
    transform_members(model, v, 5)
}
fn transform_after191(model: &Value, v: &Value) -> Result<Value> {
    let rows = model["ranges"].as_array().context("191 successor ranges")?;
    if rows.len() == 5 {
        return transform(model, v);
    }
    ensure!(
        rows.len() == 4
            && rows
                .iter()
                .filter_map(|r| r["range"].as_str())
                .collect::<BTreeSet<_>>()
                == RANGES
                    .into_iter()
                    .filter(|r| *r != "191-194")
                    .collect::<BTreeSet<_>>(),
        "191 successor may omit only the proven terminal cohort"
    );
    let mut proof = v.clone();
    proof["bindings"]
        .as_array_mut()
        .context("191 rebind history")?
        .retain(|r| r["range"] != "191-194");
    transform_members(model, &proof, 4)
}
fn transform_terminal_members(model: &Value, v: &Value, retired: &BTreeSet<&str>) -> Result<Value> {
    let actual: BTreeSet<_> = model["ranges"]
        .as_array()
        .context("terminal replay census")?
        .iter()
        .map(|r| r["range"].as_str().context("terminal range"))
        .collect::<Result<_>>()?;
    let original: BTreeSet<_> = RANGES.into_iter().collect();
    ensure!(
        actual.is_subset(&original)
            && original.difference(&actual).all(|r| retired.contains(r))
            && actual.len() == model["ranges"].as_array().unwrap().len(),
        "terminal transition omitted another live rebound owner"
    );
    let mut proof = v.clone();
    proof["bindings"]
        .as_array_mut()
        .context("terminal controller history")?
        .retain(|r| r["range"].as_str().is_some_and(|r| actual.contains(r)));
    transform_members(model, &proof, actual.len())
}
fn transform_members(model: &Value, v: &Value, expected: usize) -> Result<Value> {
    let mut m = model.clone();
    let rows = m["ranges"].as_array_mut().context("model ranges")?;
    ensure!(
        rows.len() == expected,
        "controller rebind requires its exact qualified range census"
    );
    for r in v["bindings"].as_array().unwrap() {
        let row = rows
            .iter_mut()
            .find(|x| x["range"] == r["range"])
            .context("model recovery range")?;
        ensure!(
            row["expected_producer_invocation_id"] == r["producer_invocation_id"]
                && (row["expected_controller_invocation_id"] == r["old_controller_invocation_id"]
                    || row["expected_controller_invocation_id"]
                        == r["new_controller_invocation_id"]),
            "model controller rebind changed producer/origin"
        );
        row["expected_controller_invocation_id"] = r["new_controller_invocation_id"].clone();
    }
    Ok(m)
}
pub(super) fn model(p: &Plan, m: &Value) -> Result<Value> {
    let historical = memory152::historical_model(p, m)?;
    let m = &historical;
    let Some(v) = evidence(p)? else {
        return Ok(m.clone());
    };
    let mut m = if terminal185::enabled(p) {
        terminal185::validate(p)?;
        if p.cohort191_delivery.is_some() {
            cohort191_delivery::validate(p)?;
        }
        let mut missing = BTreeSet::from(["185-185"]);
        if p.cohort191_delivery.is_some() {
            missing.insert("191-194");
        }
        transform_terminal_members(m, &v, &missing)?
    } else if p.cohort191_delivery.is_some() {
        cohort191_delivery::validate(p)?;
        transform_after191(m, &v)?
    } else {
        transform(m, &v)?
    };
    let es = m["evidence"].as_array_mut().context("model evidence")?;
    for b in [
        binding(),
        Bound {
            path: FIRES.into(),
            sha256: FIRES_SHA.into(),
        },
    ] {
        let x = serde_json::to_value(b)?;
        if !es.contains(&x) {
            es.push(x);
        }
    }
    memory152::model(p, &m)
}
fn properties(name: &str) -> Result<Value> {
    let out=Command::new("systemctl").args(["show",name,"--no-pager","--property=Id,InvocationID,MainPID,ActiveState,SubState,NRestarts,Result,ExecMainStatus,ExecStart"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "recovery owner properties unavailable"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("property shape")?;
        ensure!(m.insert(k.into(), json!(v)).is_none(), "duplicate property");
    }
    Ok(Value::Object(m))
}
pub(super) fn validate_live(p: &Plan) -> Result<()> {
    let Some(v) = evidence(p)? else { return Ok(()) };
    let profiles = bound_json(
        &Bound {
            path: PROFILES.into(),
            sha256: PROFILES_SHA.into(),
        },
        true,
    )?;
    if p.cohort191_delivery.is_some() {
        cohort191_delivery::validate(p)?;
    }
    if terminal185::enabled(p) {
        terminal185::validate(p)?;
    }
    for row in v["bindings"].as_array().unwrap() {
        if memory152::enabled(p) && row["range"] == "152-153" {
            memory152::validate_live(p)?;
            continue;
        }
        if terminal185::enabled(p) && row["range"] == "185-185" {
            continue;
        }
        if p.cohort191_delivery.is_some() && row["range"] == "191-194" {
            // Historical rebind proof is retained. Current191 custody is owned
            // by its native delivery event, never a fake fifth live replay.
            continue;
        }
        let profile = profiles["profiles"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["range"] == row["range"])
            .unwrap();
        for name in v["current_units"].as_object().unwrap().keys().filter(|n| {
            profile["argv"].as_array().unwrap().iter().any(|a| {
                a.as_str().is_some_and(|a| {
                    a == format!("--controller-unit={n}") || a == format!("--producer-unit={n}")
                })
            })
        }) {
            let actual = properties(name)?;
            let old = &v["current_units"][name];
            for key in [
                "InvocationID",
                "MainPID",
                "NRestarts",
                "ActiveState",
                "SubState",
            ] {
                ensure!(
                    actual[key] == old[key],
                    "rebound owner changed:{name}:{key}"
                );
            }
            ensure!(
                prefix(&actual["ExecStart"]) == prefix(&old["ExecStart"]),
                "rebound command changed"
            );
        }
        let guard = properties(profile["new_unit"].as_str().context("guard unit")?)?;
        ensure!(
            guard["Result"] == "success"
                && guard["ExecMainStatus"] == "0"
                && guard["NRestarts"] == "0",
            "rebound guard failed"
        );
        let timer = properties(profile["new_timer"].as_str().context("guard timer")?)?;
        ensure!(
            timer["ActiveState"] == "active",
            "rebound guard timer stopped"
        );
    }
    Ok(())
}
pub(super) fn enable(
    p: &mut Plan,
    c: &mut Value,
    op: &mut PathBuf,
    cp: &mut PathBuf,
) -> Result<()> {
    ensure!(
        bound_json(&p.previous_observer, false)?["recorded_at_utc"] == OLD,
        "controller recovery predecessor clock differs"
    );
    ensure!(
        p.controller_rebind.is_none()
            && p.sample_target_utc == "2026-10-23T06:29:58Z"
            && p.previous_observer.sha256
                == "ff0e6cb88985b95fee3ee8cea8af460200ac8001e5e1ca48d4dc9b3026a289b3"
            && p.original141_root.is_none(),
        "controller recovery requires exact accepted0559predecessor and no extra lane"
    );
    p.controller_rebind = Some(binding());
    let v = evidence(p)?.unwrap();
    for row in c["replays"].as_array_mut().context("observer rows")? {
        let b = v["bindings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["range"] == row["range"])
            .context("observer recovery range")?;
        ensure!(
            row["expected_controller_invocation_id"] == b["old_controller_invocation_id"]
                && row["expected_producer_invocation_id"] == b["producer_invocation_id"],
            "observer recovery owner differs"
        );
        row["expected_controller_invocation_id"] = b["new_controller_invocation_id"].clone();
    }
    for path in [&mut p.observer, &mut p.estimate_output, &mut p.fleet_output] {
        *path = PathBuf::from(
            path.to_str()
                .context("recovery path")?
                .replace("20261023T062958Z", "20261023T063958Z"),
        );
    }
    p.sample_target_utc = FIRST.into();
    c["not_before_utc"] = json!(FIRST);
    c["output"] = json!(p.observer);
    prefix157::namespaces(p, op, cp)?;
    p.observer_config.sha256 = sha(&next_preparation::encoded(c)?);
    validate_live(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stopped185_and_terminal191_keep_every_other_controller_clock_and_owner() {
        let proof = json!({"bindings":RANGES.iter().map(|r|json!({"range":r,"producer_invocation_id":format!("p{r}"),"old_controller_invocation_id":format!("old{r}"),"new_controller_invocation_id":format!("new{r}")})).collect::<Vec<_>>()});
        for retired in [
            BTreeSet::from(["185-185"]),
            BTreeSet::from(["185-185", "191-194"]),
        ] {
            let m = json!({"ranges":RANGES.iter().filter(|r|!retired.contains(**r)).map(|r|json!({"range":r,"expected_producer_invocation_id":format!("p{r}"),"expected_controller_invocation_id":format!("old{r}"),"elapsed_clock":u64::MAX,"downstream":43200})).collect::<Vec<_>>()});
            let next = transform_terminal_members(&m, &proof, &retired).unwrap();
            for row in next["ranges"].as_array().unwrap() {
                assert_eq!(row["elapsed_clock"], u64::MAX);
                assert_eq!(row["downstream"], 43200);
            }
            assert_eq!(
                transform_terminal_members(&next, &proof, &retired).unwrap(),
                next
            );
            let mut missing = m.clone();
            missing["ranges"].as_array_mut().unwrap().remove(0);
            assert!(transform_terminal_members(&missing, &proof, &retired).is_err());
            let mut foreign = m;
            foreign["ranges"][0]["expected_producer_invocation_id"] = json!("foreign");
            assert!(transform_terminal_members(&foreign, &proof, &retired).is_err());
        }
    }
    #[test]
    fn producer_clocks_allowances_and_large_integers_survive_mapping() {
        let rows:Vec<_>=RANGES.iter().map(|r|json!({"range":r,"producer_invocation_id":format!("p{r}"),"old_controller_invocation_id":format!("old{r}"),"new_controller_invocation_id":format!("new{r}")})).collect();
        let v = json!({"bindings":rows});
        let m = json!({"opaque":u64::MAX,"ranges":RANGES.iter().map(|r|json!({"range":r,"expected_producer_invocation_id":format!("p{r}"),"expected_controller_invocation_id":format!("old{r}"),"clock":u64::MAX,"allowance":43200})).collect::<Vec<_>>()});
        let next = transform(&m, &v).unwrap();
        assert_eq!(next["opaque"], u64::MAX);
        assert_eq!(transform(&next, &v).unwrap(), next);
        for row in next["ranges"].as_array().unwrap() {
            assert_eq!(row["clock"], u64::MAX);
            assert_eq!(row["allowance"], 43200);
        }
        let mut bad = m;
        bad["ranges"][0]["expected_producer_invocation_id"] = json!("replacement");
        assert!(transform(&bad, &v).is_err());
    }
    #[test]
    fn terminal191_successor_cannot_drop_another_rebound_owner_or_reset_clocks() {
        let rows:Vec<_> = RANGES.iter().map(|r|json!({"range":r,"producer_invocation_id":format!("p{r}"),
            "old_controller_invocation_id":format!("old{r}"),"new_controller_invocation_id":format!("new{r}")})).collect();
        let proof = json!({"bindings":rows});
        let m = json!({"ranges":RANGES.iter().filter(|r|**r != "191-194").map(|r|json!({"range":r,
            "expected_producer_invocation_id":format!("p{r}"),"expected_controller_invocation_id":format!("old{r}"),
            "clock":u64::MAX,"allowance":43200})).collect::<Vec<_>>()});
        assert!(transform(&m, &proof).is_err());
        let accepted = transform_after191(&m, &proof).unwrap();
        assert_eq!(accepted["ranges"].as_array().unwrap().len(), 4);
        for row in accepted["ranges"].as_array().unwrap() {
            assert_eq!(row["clock"], u64::MAX);
        }
        assert_eq!(transform_after191(&accepted, &proof).unwrap(), accepted);
        let mut bad = m.clone();
        bad["ranges"][0]["range"] = json!("191-194");
        assert!(transform_after191(&bad, &proof).is_err());
        let mut bad = m;
        bad["ranges"][0]["expected_producer_invocation_id"] = json!("replacement");
        assert!(transform_after191(&bad, &proof).is_err());
    }
    #[test]
    #[ignore = "root exact current controller-rebind host inputs; only metadata reads and in-memory preparation"]
    fn actual_host_recovery_preserves_all_producers_and_status_formulae() {
        let b=Bound{path:"/var/lib/jetstreamer/horizon-routine-plan-101-200-20261023T062958Z-repair185-repair183-upload144-census141-boundaries-native141-all-retry-public160-timed-scans-upload198-v1/cycle-plan.json".into(),sha256:"dd140c4a4624011b34cc18cd4c70e17dd23a4a84d866cbdc4567e41faac3db03".into()};
        let mut p: Plan = serde_json::from_value(bound_json(&b, true).unwrap()).unwrap();
        let mut c = bound_json(&p.observer_config, true).unwrap();
        let mut op = PathBuf::new();
        let mut cp = PathBuf::new();
        let old = bound_json(&p.model_template, true).unwrap();
        enable(&mut p, &mut c, &mut op, &mut cp).unwrap();
        validate_templates(
            &p,
            &old,
            &bound_json(&p.fleet_template, true).unwrap(),
            &bound_json(&p.previous_fleet, false).unwrap(),
            &bound_json(&p.previous_estimates, false).unwrap(),
            &bound_json(&p.previous_observer, false).unwrap(),
        )
        .unwrap();
        let m =
            repair185::effective_model(&p, &repair183::effective_model(&p, &old).unwrap()).unwrap();
        validate_observer_config(&p, &m, &c).unwrap();
        if let Ok(bytes) = read_checked(&p.observer, LIMIT, 0, false) {
            let observed: Value = serde_json::from_slice(&bytes).unwrap();
            let observed_model = cohort191::for_observation(&p, &m, &observed).unwrap();
            repair183::for_observation(&p, &observed_model, &observed).unwrap();
            repair185::for_observation(&p, &observed_model, &observed).unwrap();
        }
        assert_eq!(p.sample_target_utc, FIRST);
        assert_eq!(m["ranges"].as_array().unwrap().len(), 5);
        for (a, b) in old["ranges"]
            .as_array()
            .unwrap()
            .iter()
            .zip(m["ranges"].as_array().unwrap())
        {
            assert_eq!(
                a["expected_producer_invocation_id"],
                b["expected_producer_invocation_id"]
            );
            assert_eq!(
                a["epoch_downstream_allowance_seconds"],
                b["epoch_downstream_allowance_seconds"]
            );
            assert_eq!(a["terminal_slot"], b["terminal_slot"]);
        }
    }
}
