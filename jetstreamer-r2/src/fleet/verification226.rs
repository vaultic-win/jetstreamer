//! Resource-only cadence claim for the closed epoch 226 verifier.
use super::*;
use horizon_singleton211_launch::native262::foundation_roster::assembly226 as site;

pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == site::VERIFY_PHASE && unit == site::VERIFY_UNIT
}

pub(super) fn validate(claim: &PipelineClaim) -> Result<()> {
    let (reference, launch) = site::verification_registration()?;
    let references = claim
        .evidence
        .iter()
        .map(|file| json!({"path":file.path,"sha256":file.sha256}))
        .collect::<Vec<_>>();
    ensure!(
        claim.epoch == 226
            && references == [reference, launch["plan"].clone()]
            && launch["actual"]["InvocationID"] == claim.invocation_id
            && launch["actual"]["ExecStart"]
                .as_str()
                .is_some_and(|command| {
                    pipeline_status::same_exec_start(&claim.expected_exec_start, command)
                }),
        "epoch 226 verification cadence claim differs from the admitted invocation"
    );
    Ok(())
}
