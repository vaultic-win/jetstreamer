//! The V7 binaries accept only the V5F semantic generation, including during
//! the registrar's inspection before its READY file becomes visible.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;

const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const FAMILY: &str = "epoch145-semantic-continuity-20261121-v1";
const PRICE: &str = "incident-replay-fit-20261121-v1/tools-v20";

fn reference(row: &Value, directory: &str, name: &str) -> Result<()> {
    let path = Path::new(RUNTIME).join(directory).join(name);
    ensure!(
        row.as_object().is_some_and(|v| v.len() == 2)
            && row["path"].as_str() == path.to_str()
            && row["sha256"].as_str().is_some_and(|s| s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "unexpected reference to {}",
        path.display()
    );
    Ok(())
}

pub fn validate(plan: &Value) -> Result<()> {
    reference(
        &plan["controller_deployment"],
        "epoch136-joint-writer-20261122-v7b/controller",
        "deployment-seal-receipt.json",
    )?;
    reference(&plan["joint_fit_145"]["image"], PRICE, "post-stop-fit")?;
    reference(
        &plan["joint_fit_145"]["seal"],
        PRICE,
        "deployment-seal-receipt.json",
    )?;
    reference(
        &plan["holding145_semantic_worker"],
        FAMILY,
        "V5F_ACTUAL_ADVANCING_WORKER.json",
    )?;
    for (key, name) in [
        ("seal", "deployment-seal-receipt.json"),
        ("build", "build-proof.json"),
        ("adapter", "incident-post-phase.py"),
    ] {
        reference(
            &plan["holding145_completion"][key],
            FAMILY,
            &format!("tools-v13b/{name}"),
        )?;
    }
    if let Some(selector) = plan.get("holding145_prestart_ready") {
        reference(
            selector,
            "epoch145-fixture-phase-dispatch-20261122-v1",
            "READY.json",
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_the_selected_fixture_generation_can_pass_registration_inspection() {
        let key = |s: &str| json!({"path":format!("{RUNTIME}/{s}"),"sha256":"c".repeat(64)});
        let post = |s: &str| key(&format!("{FAMILY}/tools-v13b/{s}"));
        let mut plan = json!({
            "controller_deployment":key("epoch136-joint-writer-20261122-v7b/controller/deployment-seal-receipt.json"),
            "joint_fit_145":{"image":key(&format!("{PRICE}/post-stop-fit")),
                             "seal":key(&format!("{PRICE}/deployment-seal-receipt.json"))},
            "holding145_semantic_worker":key(&format!("{FAMILY}/V5F_ACTUAL_ADVANCING_WORKER.json")),
            "holding145_completion":{"seal":post("deployment-seal-receipt.json"),
                                     "build":post("build-proof.json"),"adapter":post("incident-post-phase.py")}
        });
        validate(&plan).unwrap();
        plan["holding145_prestart_ready"] =
            key("epoch145-fixture-phase-dispatch-20261122-v1/READY.json");
        validate(&plan).unwrap();
        for (name, replacement) in [
            (
                "controller_deployment",
                "epoch136-joint-writer-20261122-v7/controller/deployment-seal-receipt.json",
            ),
            (
                "holding145_prestart_ready",
                "epoch145-phase-dispatch-20261122-v1/READY.json",
            ),
            (
                "holding145_semantic_worker",
                "epoch145-semantic-continuity-20261121-v1/V5E_ACTUAL_ADVANCING_WORKER.json",
            ),
            (
                "controller_deployment",
                "epoch136-joint-writer-20261122-v6/controller/deployment-seal-receipt.json",
            ),
        ] {
            let mut older = plan.clone();
            older[name] = key(replacement);
            assert!(validate(&older).is_err(), "{name}");
        }
    }
}
