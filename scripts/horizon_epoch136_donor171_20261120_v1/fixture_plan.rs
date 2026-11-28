//! Each writer and parent accepts one semantic generation, including during
//! the registrar's inspection before its READY file becomes visible.
use anyhow::{Result, ensure};
use serde_json::Value;
use std::path::Path;

const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const FAMILY: &str = "epoch145-semantic-continuity-20261121-v1";
#[cfg(not(any(
    feature = "v5n-semantic",
    feature = "v5o-semantic",
    feature = "v5q-semantic"
)))]
const PRICE: &str = "incident-replay-fit-20261121-v1/tools-v20";
#[cfg(all(
    feature = "v5n-semantic",
    not(any(feature = "v5o-semantic", feature = "v5q-semantic"))
))]
const PRICE: &str = "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5n-136-v1";

#[cfg(all(
    feature = "v5n-semantic",
    not(any(feature = "v5o-semantic", feature = "v5q-semantic"))
))]
mod profile {
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261123-v8/controller";
    pub const DISPATCHER: &str = "epoch145-v5n-136-dispatch-20261123-v1";
    pub const WORKER: &str = "v5n-name-handoff/submission-result.json";
    pub const POST: &str = "tools-v13h";
}
#[cfg(all(
    feature = "retry-semantic",
    not(any(
        feature = "v5n-semantic",
        feature = "v5o-semantic",
        feature = "v5q-semantic"
    ))
))]
mod profile {
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261122-v7c/controller";
    pub const DISPATCHER: &str = "epoch145-fixture-retry1-dispatch-20261122-v1";
    pub const WORKER: &str = "V5F_RETRY1_ACTUAL_ADVANCING_WORKER.json";
    pub const POST: &str = "tools-v13c";
}
#[cfg(not(any(
    feature = "retry-semantic",
    feature = "v5n-semantic",
    feature = "v5o-semantic",
    feature = "v5q-semantic"
)))]
mod profile {
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261122-v7b/controller";
    pub const DISPATCHER: &str = "epoch145-fixture-phase-dispatch-20261122-v1";
    pub const WORKER: &str = "V5F_ACTUAL_ADVANCING_WORKER.json";
    pub const POST: &str = "tools-v13b";
}
#[cfg(all(feature = "v5o-semantic", not(feature = "v5q-semantic")))]
const PRICE: &str = "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5o-136-v1";
#[cfg(all(feature = "v5o-semantic", not(feature = "v5q-semantic")))]
mod profile {
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261123-v9/controller";
    pub const DISPATCHER: &str = "epoch145-v5o-136-dispatch-20261123-v1";
    pub const WORKER: &str = "v5o-name-handoff/submission-result.json";
    pub const POST: &str = "tools-v13j";
}
#[cfg(feature = "v5q-semantic")]
const PRICE: &str = if cfg!(feature = "v5r-semantic") {
    "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5r-136-v1"
} else {
    "incident-replay-fit-20261121-v1/tools-homefloor-145-post-v5q-136-v1"
};
#[cfg(feature = "v5q-semantic")]
mod profile {
    #[cfg(feature = "v5r-semantic")]
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261124-v11/controller";
    #[cfg(not(feature = "v5r-semantic"))]
    pub const CONTROLLER: &str = "epoch136-joint-writer-20261124-v10/controller";
    pub const DISPATCHER: &str = if cfg!(feature = "v5r-semantic") {
        "epoch145-v5r-136-dispatch-20261124-v1"
    } else {
        "epoch145-v5q-136-dispatch-20261124-v1"
    };
    pub const WORKER: &str = if cfg!(feature = "v5r-semantic") {
        "v5r-name-handoff/submission-result.json"
    } else {
        "v5q-name-handoff/submission-result.json"
    };
    pub const POST: &str = if cfg!(feature = "v5r-semantic") {
        "tools-v13l"
    } else {
        "tools-v13k"
    };
}
#[cfg(any(
    feature = "v5n-semantic",
    feature = "v5o-semantic",
    feature = "v5q-semantic"
))]
const SUBMISSION: &str = if cfg!(feature = "v5r-semantic") {
    "8c3e4d05c59f32545dff03258269e339cbde95ae4bcc5cc5a92aa8ae5514f68b"
} else if cfg!(feature = "v5q-semantic") {
    "398f1a2d5d5a50ab4d35c0f27de035d7c07023b6c8d632ef326b9fcd169cb5e9"
} else if cfg!(feature = "v5o-semantic") {
    "4d80587d22ffa0883696f96c30958b54d30fb5455bde35050e96b50c8ba8c544"
} else {
    "57eb2aadef0bd6e5591800c439fa0f2e6d701c2f4baa3dc45b5074fdddebd02e"
};
use profile::*;

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
        CONTROLLER,
        "deployment-seal-receipt.json",
    )?;
    reference(&plan["joint_fit_145"]["image"], PRICE, "post-stop-fit")?;
    reference(
        &plan["joint_fit_145"]["seal"],
        PRICE,
        "deployment-seal-receipt.json",
    )?;
    reference(&plan["holding145_semantic_worker"], FAMILY, WORKER)?;
    #[cfg(any(
        feature = "v5n-semantic",
        feature = "v5o-semantic",
        feature = "v5q-semantic"
    ))]
    ensure!(
        plan["holding145_semantic_worker"]["sha256"] == SUBMISSION,
        "different original semantic submission"
    );
    for (key, name) in [
        ("seal", "deployment-seal-receipt.json"),
        ("build", "build-proof.json"),
        ("adapter", "incident-post-phase.py"),
    ] {
        reference(
            &plan["holding145_completion"][key],
            FAMILY,
            &format!("{POST}/{name}"),
        )?;
    }
    if let Some(selector) = plan.get("holding145_prestart_ready") {
        reference(selector, DISPATCHER, "READY.json")?;
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
        let post = |s: &str| key(&format!("{FAMILY}/{POST}/{s}"));
        let mut plan = json!({
            "controller_deployment":key(&format!("{CONTROLLER}/deployment-seal-receipt.json")),
            "joint_fit_145":{"image":key(&format!("{PRICE}/post-stop-fit")),
                             "seal":key(&format!("{PRICE}/deployment-seal-receipt.json"))},
            "holding145_semantic_worker":key(&format!("{FAMILY}/{WORKER}")),
            "holding145_completion":{"seal":post("deployment-seal-receipt.json"),
                                     "build":post("build-proof.json"),"adapter":post("incident-post-phase.py")}
        });
        #[cfg(any(
            feature = "v5n-semantic",
            feature = "v5o-semantic",
            feature = "v5q-semantic"
        ))]
        {
            plan["holding145_semantic_worker"]["sha256"] = json!(SUBMISSION);
            let mut crossed = plan.clone();
            crossed["holding145_semantic_worker"]["sha256"] = json!("f".repeat(64));
            assert!(validate(&crossed).is_err());
        }
        validate(&plan).unwrap();
        plan["holding145_prestart_ready"] = key(&format!("{DISPATCHER}/READY.json"));
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
