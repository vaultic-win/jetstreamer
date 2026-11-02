// Exact historical evidence only. The actual causal checks execute in one root replay.
use super::*;
mod checks {
    include!("../../historical-runtime/epoch223_continuous_causal_basis.rs");
}
pub(super) fn validate(binding: &BoundFile) -> Result<()> {
    ensure!(binding.sha256 == checks::DIAGNOSIS_SHA256,
        "continuous root canonical diagnosis digest differs");
    let diagnosis: Value = read_bound(binding)?;
    checks::validate(&diagnosis).map_err(anyhow::Error::msg)
}
