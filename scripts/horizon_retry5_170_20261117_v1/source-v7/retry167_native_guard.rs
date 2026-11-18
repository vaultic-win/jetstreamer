//! Read the actual guarded-native acceptance; never reinterpret launch success as completion.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(crate) const RUNTIME: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch167-retry5-cap512-data-guard-20261117-v1/guard";
pub(crate) const IMAGE_SHA: &str =
    "5d53a2da4be9c50073421d4c8748cc519722734e0815a2b52c3e0e873fb3601f";
const QUALIFIED_PINS: bool = true;
const GUARD_TEST_COUNT: u64 = 95;
const ARTIFACT: &str = "/var/lib/jetstreamer/epoch167-retry5-cap512-guard-qualification-20261117-v1/artifact-proof.json";
const ARTIFACT_SHA: &str = "15334ddfd24a5614206ccb581180a70caa5112cff70a8f213000888a5089cd39";
const SEAL_SHA: &str = "0f47e86295326cbf7a12d8ca4fe91a6827d1a46242fd00aec3b8fecc6adcb7a4";
const SOURCE_SHA: &str = "bf4be2f37bf7248ee10278f4f4f824dd91e21974d18330275f4aada7bfeb597f";
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
                "/usr/local/lib/jetstreamer/horizon-epoch167-retry5-cap512-data-guard-20261117-v1/deployment-seal-receipt.json",
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
    use sha2::{Digest, Sha256};
    #[test]
    fn sealed_retry5_guard_accepts_its_original_native_build_graphs() {
        let read = |v: &Value| -> Result<Value> {
            let path = string(v, "path")?;
            let bytes = std::fs::read(path)?;
            ensure!(
                format!("{:x}", Sha256::digest(&bytes)) == string(v, "sha256")?,
                "bound evidence changed"
            );
            Ok(serde_json::from_slice(&bytes)?)
        };
        authenticate(
            &binding(RUNTIME, IMAGE_SHA),
            &qualification_binding(),
            &seal_binding(),
            read,
        )
        .unwrap();
    }
    #[test]
    fn missing_evidence_cannot_authorize_successor() {
        assert!(
            authenticate(
                &binding(RUNTIME, IMAGE_SHA),
                &qualification_binding(),
                &seal_binding(),
                |_| anyhow::bail!("missing evidence")
            )
            .is_err()
        );
    }
}
