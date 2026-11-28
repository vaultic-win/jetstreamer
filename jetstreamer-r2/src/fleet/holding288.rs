//! The epoch 288 holding transfer is a resource owner with no publication claim.
use super::*;
use horizon_singleton211_launch::native262::foundation_roster::holding288::{
    ADMISSION, ADMISSION_SCHEMA, ROOT, UNIT,
};

pub(super) fn scope(phase: &str, unit: &str) -> bool {
    phase == "private-holding" && unit == UNIT
}

pub(super) fn validate(claim: &PipelineClaim) -> Result<()> {
    let [launch, admission] = claim.evidence.as_slice() else {
        anyhow::bail!("epoch 288 holding requires exact launch and admission");
    };
    let root = Path::new(ROOT);
    ensure!(
        claim.epoch == 288
            && launch.path == root.join("park-launch.json")
            && admission.path == root.join(ADMISSION),
        "foreign epoch 288 holding claim"
    );
    let launched = bound_json(launch)?;
    let booked = bound_json(admission)?;
    ensure!(
        launched["schema"] == "foundation-epoch288-partial-custody-launch-v1"
            && launched["admission"] == json!({"path":admission.path,"sha256":admission.sha256})
            && launched["actual"]["Id"] == UNIT
            && launched["actual"]["InvocationID"] == claim.invocation_id
            && launched["actual"]["ExecStart"]
                .as_str()
                .is_some_and(|command| {
                    pipeline_status::same_exec_start(&claim.expected_exec_start, command)
                })
            && booked["schema"] == ADMISSION_SCHEMA
            && booked["unit"] == UNIT
            && booked["publication_authorized"] == false
            && booked["retirement_authorized"] == false,
        "epoch 288 holding claim differs from the admitted invocation"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_private_holding_has_no_canonical_pipeline_scope() {
        assert_eq!(
            pipeline_unit_range("private-holding", UNIT).unwrap(),
            288..=288
        );
        assert!(pipeline_unit_range("upload-readback", UNIT).is_err());
        assert!(pipeline_unit_range("private-holding", "foundation-other.service").is_err());
    }
}
