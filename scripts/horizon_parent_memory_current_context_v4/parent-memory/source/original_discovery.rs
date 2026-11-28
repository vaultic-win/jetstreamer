//! Exact original successful reader report scope; never a fresh budget.
use crate::{fsutil as f, model::Bound};
use anyhow::{Context,Result,ensure};
use serde_json::{Value,json};
use std::collections::BTreeSet;
const GUARD145:&str="horizon-guard145-prefix-shared72h-20261107-v8g1.service";
pub(crate) struct OriginalDiscovery { reports:BTreeSet<String> }
impl OriginalDiscovery {
    /// Called only after the complete reader constructor authenticated original
    /// qualification, native completion/drains, current tuple and fresh reports.
    pub(crate) fn from_reader(reader:&Value)->Result<Option<Self>> {
        if reader["image"]!=json!({"path":"/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2","sha256":"d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470"}) {return Ok(None);}
        ensure!(reader["schema"]=="failed4-current-complete-accounting-reader-proof-v1"
            &&reader["raw_history_preserved"]==true &&reader["all_DATA_promises_preserved"]==true
            &&reader["terminal_legacy_minimum_already_applied_once"]==true
            &&reader["memory_budget_credit_applied_bytes"]==0 &&reader["DATA_credit_bytes"]==0
            &&reader["physical_credit_bytes"]==0 &&reader["replay_launch_authorized"]==false,
            "original reader discovery scope differs");
        let mut reports=BTreeSet::new();
        for key in ["accounting_before","accounting"] {
            let binding:Bound=f::bound(&reader[key])?;
            let report=f::immutable(&binding)?;
            reports.insert(f::sha(&serde_json::to_vec(&report)?));
        }
        Ok(Some(Self { reports }))
    }
    pub(crate) fn comparison_after(&self,report:&Value)->Result<Value> {
        ensure!(self.reports.contains(&f::sha(&serde_json::to_vec(report)?)),
            "discovery raw report is not an exact authenticated original reader output");
        ensure!(!report["live145_prefix_export_before"].is_null()
            && !report["live145_prefix_export_after"].is_null(),
            "exact original145 discovery capture absent");
        let mut comparison=report["workload_discovery_after"].as_object().context("original workload map")?.clone();
        // The exact reader13 image authenticated this independently charged guard
        // in both complete raw passes. Every foreign row remains byte-equivalent.
        comparison.remove(GUARD145);
        Ok(Value::Object(comparison))
    }
}
