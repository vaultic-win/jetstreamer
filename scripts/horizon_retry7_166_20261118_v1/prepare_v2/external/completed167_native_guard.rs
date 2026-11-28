//! Read the actual guarded-native acceptance; never reinterpret launch success as completion.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) const RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-peer170-completed167-data-guard-20261116-v1/guard";
pub(crate) const IMAGE_SHA: &str =
    "41b1944ade002602054e97173fbad32c62b4e7225b65b3cedfe1bd930a4b0797";
const QUALIFIED_PINS: bool = true;
const GUARD_TEST_COUNT: u64 = 68;
const ARTIFACT: &str = "/var/lib/jetstreamer/private183-parent-custody-qualification-20261114-v1/holding-controls-v7/peer170-completed167-guard-build-v2/artifact-proof.json";
const ARTIFACT_SHA: &str = "b0e96ce7dbf343ea0892fc91ad4423faf3e61049160c482efda32f8398730a3f";
const SEAL_SHA: &str = "4369c6c6573fa3cbe9d6ab130ec6d8d0775c90d77437177d3df1caff2ab7a0b6";
const SOURCE_SHA: &str = "4f1ccdc797105fb5dae8c811bf0a1cb6e9c774ad4bfcec0ea649e3bd6499fe2b";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
fn binding(path: &str, sha: &str) -> Value {
    json!({"path":path,"sha256":sha})
}
pub(crate) fn qualification_binding() -> Value {
    binding(ARTIFACT, ARTIFACT_SHA)
}
pub(crate) fn seal_binding() -> Value {
    binding(
        &format!(
            "{}/deployment-seal-receipt.json",
            RUNTIME.trim_end_matches("/guard")
        ),
        SEAL_SHA,
    )
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn success(v: &Value) -> Result<()> {
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "exited"
            && v["MainPID"] == "0"
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["NRestarts"] == "0"
            && v["Result"] == "success"
            && v["ExecMainStatus"] == "0"
            && string(v, "InvocationID")?.len() == 32,
        "original successful terminal required"
    );
    Ok(())
}
fn normal_seal(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && v["sealer_sha256"] == SEALER
            && v["replay_launch_authorized"] == false
            && v["remote_mutations"] == false,
        "normal seal required"
    );
    Ok(())
}
fn native_record(q: &Value, read: &impl Fn(&Value) -> Result<Value>) -> Result<()> {
    ensure!(q["owner"] == "/root", "foreign native acceptance");
    let terminal = read(&q["original_terminal"])?;
    success(&terminal)?;
    let first = read(&q["first_timer_guard"])?;
    let actor = &first["actor"];
    ensure!(
        first["no_manual_guard_execution"] == true
            && actor["Id"] == terminal["Id"]
            && actor["InvocationID"] == terminal["InvocationID"]
            && actor["SubState"] == "start-pre"
            && actor["MainPID"] == "0"
            && actor["NRestarts"] == "0"
            && string(actor, "ControlPID")?.parse::<u64>()? > 0,
        "original guarded actor identity differs"
    );
    let receipt = read(&first["receipt"])?;
    ensure!(
        receipt["trip"] == false
            && receipt["actor_invocation_id"] == terminal["InvocationID"]
            && receipt["guard_invocation_id"] == first["guard"]["InvocationID"],
        "genuine timer guard receipt differs"
    );
    let seal = read(&q["token_seal"])?;
    normal_seal(&seal)?;
    let members = seal["members"].as_array().context("token members")?;
    ensure!(
        members.len() == 1 && members[0]["name"] == "token.json" && members[0]["mode"] == "0444",
        "exact token seal"
    );
    let token = read(&binding(
        &format!("{}/token.json", string(&seal, "destination")?),
        string(&members[0], "sha256")?,
    ))?;
    ensure!(
        token["schema"] == "private183-holding-build-prestart-token-v1"
            && token["actor_unit"] == terminal["Id"]
            && token["actor_invocation_id"] == terminal["InvocationID"]
            && token["first_timer_driven_guard"] == true
            && token["guard_receipt"] == first["receipt"]
            && token["guard_invocation_id"] == first["guard"]["InvocationID"]
            && token["guard_timer_invocation_id"] == first["timer"]["InvocationID"]
            && token["replay_admission_authorized"] == false
            && token["publication_authorized"] == false,
        "original token differs"
    );
    let journal = read(&token["journal_evidence"])?;
    ensure!(
        journal["native"] == first && journal["PID1"].as_array().is_some_and(|a| !a.is_empty()),
        "original timer journal differs"
    );
    let pid1 = read(&q["original_PID1"])?;
    ensure!(
        pid1["code"] == 0 && !string(&pid1, "stdout")?.is_empty(),
        "original PID1 collection failed"
    );
    let key = if q["phase"] == "tests" {
        "test_journal"
    } else {
        "compiler_journal"
    };
    let output = read(&q[key])?;
    ensure!(output["code"] == 0, "original invocation journal failed");
    if q["phase"] == "tests" {
        let summary = string(q, "test_summary")?;
        let found = string(&output, "stdout")?
            .lines()
            .map(serde_json::from_str::<Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            found.iter().any(|v| v["MESSAGE"] == summary),
            "test summary absent from actual journal"
        );
    }
    Ok(())
}
pub(crate) fn authenticate(
    runtime: &Value,
    qualification: &Value,
    seal_binding: &Value,
    read: impl Fn(&Value) -> Result<Value>,
) -> Result<()> {
    ensure!(
        QUALIFIED_PINS,
        "successor guard build pins are not qualified"
    );
    ensure!(
        *runtime == binding(RUNTIME, IMAGE_SHA),
        "exact guard runtime required"
    );
    ensure!(
        *qualification == binding(ARTIFACT, ARTIFACT_SHA),
        "exact native artifact required"
    );
    ensure!(
        *seal_binding
            == binding(
                "/usr/local/lib/jetstreamer/horizon-peer170-completed167-data-guard-20261116-v1/deployment-seal-receipt.json",
                SEAL_SHA
            ),
        "exact runtime seal required"
    );
    let q = read(qualification)?;
    ensure!(
        q["owner"] == "/root"
            && q["production"]["sha256"] == IMAGE_SHA
            && GUARD_TEST_COUNT > 0
            && q["accepted_test_count"] == GUARD_TEST_COUNT
            && q["source_manifest"]["sha256"] == SOURCE_SHA
            && q["guard_image_only"] == true
            && q["guard_installed_on_live_lane"] == false
            && q["runtime_execution_admitted"] == false
            && q["replay_launch_authorized"] == false
            && q["publication_authorized"] == false,
        "actual successor guard artifact differs"
    );
    let seal = read(seal_binding)?;
    normal_seal(&seal)?;
    ensure!(
        seal["destination"] == RUNTIME.trim_end_matches("/guard"),
        "guard seal destination differs"
    );
    let members = seal["members"].as_array().context("runtime members")?;
    ensure!(
        members.len() == 2
            && members
                .iter()
                .filter(|m| m["name"] == "guard" && m["sha256"] == IMAGE_SHA && m["mode"] == "0555")
                .count()
                == 1
            && members
                .iter()
                .filter(|m| m["name"] == "artifact-proof.json"
                    && m["sha256"] == ARTIFACT_SHA
                    && m["mode"] == "0444")
                .count()
                == 1,
        "runtime image/artifact pair differs"
    );
    let graphs = q["four_compiler_graphs"]
        .as_array()
        .context("four graphs")?;
    ensure!(graphs.len() == 4, "exact four graphs required");
    let mut phases = BTreeSet::new();
    for b in graphs {
        let graph = read(b)?;
        let phase = string(&graph, "phase")?;
        ensure!(
            [
                "production",
                "build-tests",
                "clippy-production",
                "clippy-tests"
            ]
            .contains(&phase)
                && phases.insert(phase.to_owned())
                && graph["source_manifest"] == q["source_manifest"]
                && graph["output_present"] == true,
            "crossed or duplicate compiler graph"
        );
        native_record(&graph, &read)?;
        if phase == "production" {
            ensure!(graph["output"] == q["production"], "production crossed");
        }
        if phase == "build-tests" {
            ensure!(graph["output"] == q["test_image"], "test image crossed");
        }
    }
    let tests = read(&q["test_acceptance"])?;
    ensure!(
        tests["actual_test_count"] == GUARD_TEST_COUNT
            && tests["image"] == q["test_image"]
            && tests["source_manifest"] == q["source_manifest"]
            && string(&tests, "test_summary")?.starts_with(
                &format!("test result: ok. {GUARD_TEST_COUNT} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")
            ),
        "actual test acceptance differs"
    );
    native_record(&tests, &read)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("native-guard-fixture.json")).unwrap()
    }
    fn check(f: &Value) -> Result<()> {
        authenticate(&f["runtime"], &f["qualification"], &f["seal"], |b| {
            let p = string(b, "path")?;
            f["documents"][p]
                .as_object()
                .context("missing actual bound document")?;
            Ok(f["documents"][p].clone())
        })
    }
    #[test]
    fn actual_guard_native_tree_is_accepted() {
        check(&fixture()).unwrap();
    }
    #[test]
    fn launch_only_record_cannot_replace_terminal() {
        let mut f = fixture();
        let paths: Vec<_> = f["documents"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        for p in paths {
            if p.ends_with("/production/ORIGINAL_TERMINAL.json") {
                f["documents"][&p] = json!({"code":0});
            }
        }
        assert!(check(&f).is_err());
    }
    #[test]
    fn failed_or_restarted_terminal_rejected() {
        for (key, val) in [
            ("ExecMainStatus", "1"),
            ("NRestarts", "1"),
            ("SubState", "running"),
        ] {
            let mut f = fixture();
            let p = f["documents"]
                .as_object()
                .unwrap()
                .keys()
                .find(|p| p.ends_with("/production/ORIGINAL_TERMINAL.json"))
                .unwrap()
                .clone();
            f["documents"][&p][key] = json!(val);
            assert!(check(&f).is_err());
        }
    }
    #[test]
    fn guard_token_identity_change_rejected() {
        let mut f = fixture();
        let p = f["documents"]
            .as_object()
            .unwrap()
            .keys()
            .find(|p| p.ends_with("/token.json"))
            .unwrap()
            .clone();
        f["documents"][&p]["actor_invocation_id"] = json!("foreign");
        assert!(check(&f).is_err());
    }
    #[test]
    fn duplicate_graph_rejected() {
        let mut f = fixture();
        f["documents"][ARTIFACT]["four_compiler_graphs"][1] =
            f["documents"][ARTIFACT]["four_compiler_graphs"][0].clone();
        assert!(check(&f).is_err());
    }
    #[test]
    fn changed_test_summary_rejected() {
        let mut f = fixture();
        let p = f["documents"][ARTIFACT]["test_acceptance"]["path"]
            .as_str()
            .unwrap()
            .to_owned();
        f["documents"][&p]["actual_test_count"] = json!(GUARD_TEST_COUNT.saturating_sub(1));
        assert!(check(&f).is_err());
    }
    #[test]
    fn foreign_runtime_and_missing_evidence_rejected() {
        let mut f = fixture();
        f["runtime"]["sha256"] = json!("0".repeat(64));
        assert!(check(&f).is_err());
        let mut f = fixture();
        f["documents"][ARTIFACT]["test_acceptance"] = json!({"path":"/missing"});
        assert!(check(&f).is_err());
    }
}
