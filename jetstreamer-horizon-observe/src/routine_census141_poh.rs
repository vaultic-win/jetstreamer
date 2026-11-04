//! Exact private 141PoH handoff, no resource observation or archive mutation.
use super::*;
const UNIT: &str = "horizon-epoch141-census-poh-diagnostic-20261022-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/jetstreamer-epoch141-census-poh-diagnostic";
const TOOL_SHA: &str = "02c267ef5ac68d24cc75d22988254bb426f7c2d2805074d7a8838e6ab27e9234";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-census141-poh-candidate-20261022-v2/plan.json";
const PLAN_SHA: &str = "64334d5250d51021b8460947536a896d2bc9e7500c86aa54c1e617975aa11e98";
const READER: &str =
    "/usr/local/lib/jetstreamer/horizon-census141-poh-fleet-reader-20261022-v1/jetstreamer-r2";
const READER_SHA: &str = "1bc95d482d6fe5eb461814a9d5ac96bb9d5f11919331c98ef9fcb395c0518f75";
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    launch: Bound,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    collection: Option<Bound>,
}
pub(super) fn collected(p: &Plan) -> bool {
    p.census141_poh
        .as_ref()
        .is_some_and(|s| s.collection.is_some())
}
fn collection_shape(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-collected-gap-boundaries-v1"
            && v["epoch"] == 141
            && v["target_count"] == 18283
            && v["total_boundaries"] == 84597
            && v["hidden_boundaries"] == 66314
            && v["all_boundary_hashes_distinct"] == true
            && v["finalized_parent_and_final_hash_matches"] == true
            && v["complete_diagnostic_lineage_validated"] == true
            && v["diagnostic"]["path"] == format!("{ROOT}/completion.json")
            && v["diagnostic"]["sha256"]
                == "12cb942626d34662080dfc981dd0588b8baef39ee31e5fb35bd8fd1593e5cd4f"
            && v["tool_sha256"]
                == "7d353f068762ee101451e44e6d4cf4772375254b44c9e560a234be5634a01369"
            && v["output"]["path"]
                == "/var/lib/jetstreamer/horizon-epoch141-boundary-collection-20261022-v1/boundaries.json"
            && v["output"]["sha256"]
                == "e371b3546d62e5fdac79a497607b61ea2647c3c5d410157b3ff456709f78be4a",
        "foreign or incomplete 141boundary collection"
    );
    for flag in [
        "canonical_ancestry_proven",
        "source_completeness_proven",
        "live_state_proven",
        "runtime_boundary_input_authorized",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "collection grants authority:{flag}");
    }
    Ok(())
}
fn collection(b: &Bound) -> Result<()> {
    ensure!(
        b.path
            == Path::new(
                "/var/lib/jetstreamer/horizon-epoch141-boundary-collection-20261022-v1/collection.json"
            )
            && b.sha256 == "b7b8c12df60021b3f7fc37288b41601b2179dd670dd4ffb83316a640349f3dfd",
        "foreign 141collection binding"
    );
    let v = bound_json(b, false)?;
    collection_shape(&v)?;
    let output: Bound = serde_json::from_value(v["output"].clone())?;
    let output = bound_json(&output, false)?;
    ensure!(
        output["schema"] == "jetstreamer-epoch141-decoded-gap-boundaries-v1"
            && output["slots"].as_array().is_some_and(|a| a.len() == 18283),
        "collected boundary bytes changed"
    );
    let diagnostic: Bound = serde_json::from_value(v["diagnostic"].clone())?;
    let d = bound_json(&diagnostic, false)?;
    ensure!(
        d["full_census_poh_chains_verified"] == true
            && d["passed_targets"] == 18283
            && d["failed_targets"] == 0
            && d["verified_boundary_count"] == 84597,
        "collection lost genuine complete diagnostic"
    );
    Ok(())
}
pub(super) fn reader(p: &Plan) -> bool {
    p.census141_poh.is_some()
        && native141::all_retry_enabled(p)
        && ((p.publication144.is_none()
            && p.tools.r2.path == Path::new(READER)
            && p.tools.r2.sha256 == READER_SHA)
            || publication144::composite_reader(p))
}
fn claim(b: &Bound, v: &Value) -> Result<Value> {
    ensure!(
        b.path == Path::new(ROOT).join("intent.json")
            && v["schema"] == "jetstreamer-epoch141-census-poh-intent-v2"
            && v["tool_sha256"] == TOOL_SHA
            && v["plan"]["path"] == PLAN
            && v["plan"]["sha256"] == PLAN_SHA
            && v["owner"]["Id"] == UNIT
            && v["owner"]["NRestarts"] == "0"
            && v["owner"]["Restart"] == "no"
            && v["owner"]["Type"] == "exec"
            && v["owner"]["ActiveState"] == "active"
            && v["owner"]["SubState"] == "running"
            && v["owner"]["InvocationID"]
                .as_str()
                .is_some_and(|s| s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && v["target_count"] == 18283
            && v["expected_boundaries"] == 84597
            && v["memory_admission"]["admitted"] == true
            && v["memory_admission"]["minimum_available_bytes"] == 130u64 << 30
            && v["memory_admission"]["available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 130u64 << 30),
        "foreign private 141PoH capture"
    );
    let command = format!(
        "{{ path={TOOL} ; argv[]={TOOL} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {TOOL_SHA} --run"
    );
    ensure!(
        v["owner"]["ExecStart"]
            .as_str()
            .and_then(|s| s.split_once(" ; ignore_errors="))
            .is_some_and(|(s, t)| s == command && t.starts_with("no ;")),
        "PoH captured command changed"
    );
    for flag in [
        "publication_authorized",
        "runtime_boundary_input_authorized",
        "replay_launch_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[flag] == false, "PoH capture grants authority:{flag}");
    }
    Ok(
        json!({"epoch":141,"unit":UNIT,"invocation_id":v["owner"]["InvocationID"],"scratch_path":ROOT,"launch_receipt":b}),
    )
}
fn evidence(b: &Bound) -> Result<Value> {
    let v = bound_json(b, false)?;
    claim(b, &v)?;
    let plan = bound_json(
        &Bound {
            path: PLAN.into(),
            sha256: PLAN_SHA.into(),
        },
        true,
    )?;
    ensure!(
        plan["schema"] == "jetstreamer-epoch141-census-poh-diagnostic-plan-v1"
            && plan["output_directory"] == ROOT
            && plan["acquisition"] == v["acquisition"],
        "PoH captured plan changed"
    );
    ensure!(
        v["acquisition"]["path"]
            == "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/all-target-acquisition.json"
            && v["acquisition"]["sha256"]
                == "0335b1131663c0f8df77b3cddb5f79e49af2956067ebc46af74b9a08adafb949",
        "PoH source changed"
    );
    let raw: Bound = serde_json::from_value(v["acquisition"].clone())?;
    let raw = bound_json(&raw, false)?;
    ensure!(
        raw["native_session_complete"] == true
            && raw["complete_retained_census_revalidated_after_close"] == true
            && raw["full_target_raw_acquisition_complete"] == true
            && raw["raw_acquired_target_count"] == 18283
            && raw["recovered_target_count"] == 0
            && raw["invocation_id"] == "4721c4110425431cbddedac185e7d6e9"
            && raw["publication_authorized"] == false,
        "PoH requires closed exact 141 source"
    );
    Ok(v)
}
pub(super) fn validate(p: &Plan) -> Result<()> {
    if let Some(s) = &p.census141_poh {
        ensure!(
            reader(p) && is_101(p)? && !p.expected_epochs.contains(&141),
            "PoH profile cannot replace replay/publication"
        );
        evidence(&s.launch)?;
        if let Some(b) = &s.collection {
            collection(b)?;
        }
    }
    Ok(())
}
pub(super) fn enable(p: &mut Plan, b: &Bound) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Spec {
        schema: String,
        launch: Bound,
        #[serde(default)]
        collection: Option<Bound>,
    }
    let s: Spec = serde_json::from_value(bound_json(b, true)?)?;
    if let Some(current) = &p.census141_poh {
        ensure!(
            s.schema == "jetstreamer-census141-boundary-collection-monitor-handoff-v1"
                && current.collection.is_none()
                && s.collection.is_some()
                && serde_json::to_value(&current.launch)? == serde_json::to_value(&s.launch)?,
            "collection adoption cannot replace existing141owner/history"
        );
        collection(s.collection.as_ref().unwrap())?;
        p.census141_poh.as_mut().unwrap().collection = s.collection;
        return validate(p);
    }
    ensure!(
        native141::all_retry_enabled(p)
            && s.collection.is_none()
            && s.schema == "jetstreamer-census141-poh-monitor-handoff-v1",
        "foreign PoH handoff"
    );
    evidence(&s.launch)?;
    p.census141_poh = Some(Profile {
        launch: s.launch,
        collection: None,
    });
    p.tools.r2 = if p.publication144.is_some() {
        Bound {
            path: publication144::COMPOSITE_READER.into(),
            sha256: publication144::COMPOSITE_READER_SHA.into(),
        }
    } else {
        Bound {
            path: READER.into(),
            sha256: READER_SHA.into(),
        }
    };
    validate(p)
}
pub(super) fn derive_fleet(p: &Plan, f: &mut Value) -> Result<()> {
    let Some(s) = &p.census141_poh else {
        return Ok(());
    };
    validate(p)?;
    let c = claim(&s.launch, &bound_json(&s.launch, false)?)?;
    let rows = f["diagnostics"]
        .as_array_mut()
        .context("PoH diagnostic census")?;
    let found: Vec<_> = rows.iter().filter(|r| r["unit"] == UNIT).collect();
    ensure!(
        found.is_empty() || (found.len() == 1 && found[0] == &c),
        "PoH owner history changed"
    );
    if found.is_empty() {
        rows.push(c);
    }
    let units = f["tracked_units"]
        .as_array_mut()
        .context("PoH tracked units")?;
    if !units.contains(&json!(UNIT)) {
        units.push(json!(UNIT));
    }
    let g = &mut f["gates"]["141"];
    ensure!(
        g["state"] == "failed-needs-repair",
        "PoH cannot close repair"
    );
    g["next_action"] = json!(
        "Inspect complete private 18,283target PoH diagnostic and every retained target failure. Verify 84,597boundaries only after full input/output revalidation. Preserve raw acquisition and all earlier attempts. Diagnostic chain success is not canonical ancestry, liveness, runtime boundary, replay, root, plugin or ready-pair authority; keep 141repair open."
    );
    let e = g["evidence"].as_array_mut().context("PoH evidence")?;
    let b = serde_json::to_value(&s.launch)?;
    if !e.contains(&b) {
        e.push(b);
    }
    if let Some(collection) = &s.collection {
        let b = serde_json::to_value(collection)?;
        if !e.contains(&b) {
            e.push(b);
        }
        g["next_action"] = json!(
            "Complete private 141PoH and independent boundary collection passed for18283groups/84597distinctboundaries,including66314hidden hashes. Preserve all originals and candidate readable bundle. Qualify the exact v1.4.25 source/boundary consumer and private canonical-root path before runtime input use, route promotion,full/plugin/publication or R2 delivery. Keep 141repair open until verified ready pair; collection is not ancestry/liveness/root or launch authority."
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn collection_cannot_close_repair_or_borrow_partial_or_authorizing_evidence() {
        let mut v = json!({"schema":"jetstreamer-epoch141-collected-gap-boundaries-v1","epoch":141,"target_count":18283,"total_boundaries":84597,"hidden_boundaries":66314,
            "all_boundary_hashes_distinct":true,"finalized_parent_and_final_hash_matches":true,"complete_diagnostic_lineage_validated":true,
            "diagnostic":{"path":format!("{ROOT}/completion.json"),"sha256":"12cb942626d34662080dfc981dd0588b8baef39ee31e5fb35bd8fd1593e5cd4f"},
            "tool_sha256":"7d353f068762ee101451e44e6d4cf4772375254b44c9e560a234be5634a01369",
            "output":{"path":"/var/lib/jetstreamer/horizon-epoch141-boundary-collection-20261022-v1/boundaries.json","sha256":"e371b3546d62e5fdac79a497607b61ea2647c3c5d410157b3ff456709f78be4a"}});
        for flag in [
            "canonical_ancestry_proven",
            "source_completeness_proven",
            "live_state_proven",
            "runtime_boundary_input_authorized",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "publication_authorized",
            "retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            v[flag] = json!(false);
        }
        collection_shape(&v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(collection_shape(&bad).is_err(), "{key}");
        }
        v["publication_authorized"] = json!(true);
        assert!(collection_shape(&v).is_err());
    }
    #[test]
    fn no_profile_cannot_borrow_new_reader_or_publish_ordinary_eta() {
        let (p, ..) = crate::tests::fixture101();
        assert!(!reader(&p));
        assert!(p.census141_poh.is_none());
    }
}
