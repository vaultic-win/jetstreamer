//! Bind the admission's typed HOME measurements to the current audit generation.
use super::previous_audit_budget as previous;
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::process::Command;

pub(super) fn observe() -> Result<Value> {
    // Isolated Python reads only the embedded source and its standard library.
    // There is no mutable script path or interpreter search through PATH.
    let result = Command::new("/usr/bin/python3")
        .args(["-I", "-B", "-c", include_str!("audit_handoff.py")])
        .output()
        .context("capture chronological audit owner")?;
    ensure!(
        result.status.success() && result.stdout.len() < (1 << 20),
        "chronological audit owner: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let witness: Value = serde_json::from_slice(&result.stdout)?;
    if witness.get("epoch90_handoff").is_none() {
        // Keep the original typed v10 proof schema and complete v9-to-v10 chain.
        return previous::observe();
    }
    Ok(witness)
}

pub(super) fn validate_fleet_obligation(obligation: &Value) -> Result<()> {
    previous::validate_fleet_obligation(obligation)
}

pub(super) fn data_requirements(fit: &Value, available: u64) -> Result<Value> {
    previous::data_requirements_for(fit, available, &observe()?)
}

pub(super) fn requirements(
    prepared: &Value,
    total: u64,
    available: u64,
    cores: u64,
) -> Result<Value> {
    previous::requirements(prepared, total, available, cores)
}
