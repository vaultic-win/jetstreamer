//! Witness selection comes only from the request's exact current plan. The
//! parent-retirement policy keeps its unchanged original terminal registry.
use crate::{
    fsutil as f,
    model::{Bound, Current, Policy, STATE, STATE_SHA},
};
use anyhow::{Result, ensure};
use horizon_recovered_resource_frame_retained199_v2::{ordinary199, terminal199_context};
use serde_json::{Value, json};
use std::path::Path;

pub(crate) struct ContextInputs {
    pub(crate) binding: Bound,
    pub(crate) retained: terminal199_context::Retained,
}
fn same_binding(a: &Bound, b: &terminal199_context::Bound) -> bool {
    a.path == b.path && a.sha256 == b.sha256
}
fn require_original_registry(policy: &Bound, original: &terminal199_context::Bound) -> Result<()> {
    ensure!(
        same_binding(policy, original),
        "current input witness crosses registered original context"
    );
    Ok(())
}
fn require_state(binding: &Bound) -> Result<()> {
    ensure!(
        binding.path == Path::new(STATE) && binding.sha256 == STATE_SHA,
        "selected state reader crossed original quarantine binding"
    );
    Ok(())
}
impl ContextInputs {
    pub(crate) fn for_current(policy: &Policy, current: &Current) -> Result<Self> {
        let plan = f::json(&current.fleet_plan)?;
        let binding = plan
            .get(ordinary199::TERMINAL_FIELD)
            .filter(|v| !v.is_null())
            .map(f::bound)
            .transpose()?
            .unwrap_or_else(|| policy.terminal_context.clone());
        let retained = terminal199_context::Retained::load(&terminal199_context::Bound {
            path: binding.path.clone(),
            sha256: binding.sha256.clone(),
        })?;
        // Unwrapping a selected context does not replace the policy allowlist.
        require_original_registry(&policy.terminal_context, retained.original_context())?;
        if retained.selected_inputs().is_some() {
            ensure!(
                plan[ordinary199::FIELD] == json!(retained.original_enrollment()),
                "selected current plan lacks the exact original enrollment"
            );
        }
        Ok(Self { binding, retained })
    }
    pub(crate) fn state(&self, binding: &Bound) -> Result<Value> {
        let Some(selected) = self.retained.selected_inputs() else {
            return f::json(binding);
        };
        require_state(binding)?;
        selected.verify_member(&serde_json::from_value(json!(binding))?, 32 << 20)?;
        // The qualified library checks original identity on both sides of the
        // normally sealed exact-byte copy read; no original state FD is opened.
        Ok(serde_json::from_slice(&selected.read_quarantined_state()?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_registry_cannot_cross_legacy_policy() {
        let policy = Bound {
            path: crate::model::REGISTRY.into(),
            sha256: crate::model::REGISTRY_SHA.into(),
        };
        let original = terminal199_context::Bound {
            path: policy.path.clone(),
            sha256: policy.sha256.clone(),
        };
        require_original_registry(&policy, &original).unwrap();
        let mut crossed = original.clone();
        crossed.sha256 = "0".repeat(64);
        assert!(require_original_registry(&policy, &crossed).is_err());
        crossed = original;
        crossed.path = "/another/registry.json".into();
        assert!(require_original_registry(&policy, &crossed).is_err());
    }
    #[test]
    fn sealed_copy_route_is_only_for_exact_original_state() {
        let original = Bound {
            path: STATE.into(),
            sha256: STATE_SHA.into(),
        };
        require_state(&original).unwrap();
        let mut crossed = original.clone();
        crossed.path = "/another/state.json".into();
        assert!(require_state(&crossed).is_err());
        crossed = original;
        crossed.sha256 = "0".repeat(64);
        assert!(require_state(&crossed).is_err());
    }
}
