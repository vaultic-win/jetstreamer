//! Distinct205 policy, sharing only the complete existing host/guard/floor math.
use super::*;
pub(super) fn candidate_with_anchor(
    stage: downstream::Stage,
    bytes: u64,
    anchor_bytes: u64,
) -> Result<maintenance_capacity::Candidate> {
    use downstream::Stage;
    ensure!(
        bytes == BYTES
            && ((stage == Stage::Full && anchor_bytes > 0 && anchor_bytes <= OUTPUT_MAX)
                || (stage != Stage::Full && anchor_bytes == 0)),
        "205 candidate length/anchor scope differs"
    );
    let additional = match stage {
        Stage::Full => bytes
            .checked_add(anchor_bytes)
            .and_then(|n| n.checked_add(128 << 20)),
        Stage::Plugin | Stage::Boundary => Some(128 << 20),
        Stage::Import => bytes.checked_add(128 << 20),
        Stage::Upload => Some(1 << 30),
        Stage::Assembly => {
            bail!("205 private assembly is already complete and is not a delivery candidate")
        }
    }
    .context("205 candidate disk overflow")?;
    Ok(maintenance_capacity::Candidate {
        additional_bytes: additional,
        memory_max_bytes: stage.memory() + (1 << 30),
        minimum_protected_disk_bytes: 0,
    })
}
pub(super) fn stage_capacity(
    basis: &Value,
    stage: downstream::Stage,
    bytes: u64,
    anchor: u64,
) -> Result<Value> {
    let c = candidate_with_anchor(stage, bytes, anchor)?;
    let result = maintenance_capacity::check_continuation205_delivery(basis, c)?;
    validate_capacity(&result, c.memory_max_bytes, c.additional_bytes)?;
    validate_provenance(&result)?;
    Ok(result)
}
pub(super) fn validate_capacity(v: &Value, memory: u64, additional: u64) -> Result<()> {
    assembly204_recovery::validate205_capacity(v, memory, additional)
}
pub(super) fn validate_provenance(v: &Value) -> Result<()> {
    assembly204_recovery::validate_shared_capacity_provenance(v)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn continuation205_candidate_covers_actual_copy_anchor_and_independent_guard() {
        use downstream::Stage;
        let c = candidate_with_anchor(Stage::Full, BYTES, 114228848867).unwrap();
        assert_eq!(c.additional_bytes, BYTES + 114228848867 + (128 << 20));
        assert_eq!(c.memory_max_bytes, 65u64 << 30);
        assert_eq!(
            candidate_with_anchor(Stage::Upload, BYTES, 0)
                .unwrap()
                .memory_max_bytes,
            17u64 << 30
        );
        assert!(candidate_with_anchor(Stage::Full, BYTES, 0).is_err());
        assert!(candidate_with_anchor(Stage::Assembly, BYTES, 0).is_err());
    }
}
