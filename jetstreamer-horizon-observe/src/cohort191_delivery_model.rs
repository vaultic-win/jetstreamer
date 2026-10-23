//! Candidate arithmetic for a future authenticated191–194 delivery publisher.
//! No observation, ownership proof, receipt writing, publication or admission.
//! Callers must independently authenticate every input, current phase, queue and
//! canonical ready pair. This module is deliberately not wired into the routine.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Work {
    Queued { remaining_millis: u64 },
    Active { remaining_millis: u64 },
    Complete,
}
impl Work {
    fn millis(&self) -> Result<u64> {
        match self {
            Self::Complete => Ok(0),
            Self::Queued { remaining_millis } | Self::Active { remaining_millis } => {
                ensure!(
                    *remaining_millis > 0,
                    "uncompleted stage needs positive remaining time"
                );
                Ok(*remaining_millis)
            }
        }
    }
    fn complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
    fn active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
    fn queued(&self) -> bool {
        matches!(self, Self::Queued { .. })
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub epoch: u64,
    pub full: Work,
    pub plugin: Work,
    pub boundary: Work,
    pub upload: Work,
    pub readback: Work,
    pub source_revalidation_and_sidecar: Work,
    pub authenticated_ready_pair: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub finalization: Work,
    pub import: Work,
    pub boundary_gates_sidecar: bool,
    /// Durations include actual full/plugin queue position. Full and plugin
    /// may overlap; an enforcing uploader serializes complete syncs by epoch,
    /// including each object's readback and final sidecar, not upload alone.
    /// That topology must be independently qualified before using this model.
    pub epochs: Vec<Epoch>,
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("delivery estimate overflow")
}

/// Remaining wall time to each canonical sidecar under the stated topology.
/// Queued values are explicit planning budgets, never inferred from a dead
/// worker's replay rate or mechanical subtraction from yesterday's ETA.
/// Active values must be freshly measured by the authenticated stage observer;
/// upload and readback need separate rates, progress and stall allowances.
pub fn forecast(p: &Plan) -> Result<BTreeMap<u64, u64>> {
    ensure!(
        p.schema == "jetstreamer-cohort191-delivery-forecast-v2"
            && p.epochs.iter().map(|e| e.epoch).eq(191..=194),
        "foreign, missing or reordered cohort members"
    );
    ensure!(
        p.finalization.complete() || p.import.queued(),
        "import precedes complete source finalization"
    );
    let shared = add(p.finalization.millis()?, p.import.millis()?)?;
    let mut lane = 0;
    let mut outstanding_predecessor = false;
    let mut active_syncs = 0;
    let mut result = BTreeMap::new();
    for e in &p.epochs {
        let full = e.full.millis()?;
        let plugin = e.plugin.millis()?;
        let boundary = e.boundary.millis()?;
        let upload = e.upload.millis()?;
        let readback = e.readback.millis()?;
        let commit = e.source_revalidation_and_sidecar.millis()?;
        let stages = [
            &e.full,
            &e.plugin,
            &e.boundary,
            &e.upload,
            &e.readback,
            &e.source_revalidation_and_sidecar,
        ];
        if !p.import.complete() {
            ensure!(
                stages.iter().all(|s| s.queued()),
                "public verification/delivery precedes cohort import"
            );
        }
        let gated = e.full.complete()
            && e.plugin.complete()
            && (!p.boundary_gates_sidecar || e.boundary.complete());
        let sync = [&e.upload, &e.readback, &e.source_revalidation_and_sidecar];
        let active = sync.iter().filter(|s| s.active()).count();
        ensure!(active <= 1, "sync phases overlap for one object");
        active_syncs += active;
        ensure!(
            active_syncs <= 1,
            "serialized uploader has multiple active objects"
        );
        if sync.iter().any(|s| !s.queued()) {
            ensure!(
                gated && shared == 0 && !outstanding_predecessor,
                "sync progress lacks gates or violates authenticated epoch order"
            );
        }
        ensure!(
            e.readback.queued() || e.upload.complete(),
            "readback precedes complete upload"
        );
        ensure!(
            e.source_revalidation_and_sidecar.queued()
                || (e.upload.complete() && e.readback.complete()),
            "sidecar precedes upload/readback"
        );
        if e.authenticated_ready_pair {
            ensure!(
                gated && shared == 0 && sync.iter().all(|s| s.complete()),
                "ready pair lacks complete delivery gates"
            );
            result.insert(e.epoch, 0);
            continue;
        }
        ensure!(
            !e.source_revalidation_and_sidecar.complete(),
            "uncommitted sidecar cannot have completed commit stage"
        );
        outstanding_predecessor = true;
        // The boundary stage is deliberately separate: current ordinary upload
        // needs full/plugin receipts; adjacent boundaries normally gate local
        // retirement only. Never silently make retirement a readiness gate.
        let checks = add(
            full.max(plugin),
            if p.boundary_gates_sidecar {
                boundary
            } else {
                0
            },
        )?;
        let ready = add(shared, checks)?;
        let start = lane.max(ready);
        lane = add(add(add(start, upload)?, readback)?, commit)?;
        ensure!(
            lane > 0,
            "zero remaining time without authenticated sidecar"
        );
        result.insert(e.epoch, lane);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn queued(n: u64) -> Work {
        Work::Queued {
            remaining_millis: n,
        }
    }
    fn plan() -> Plan {
        Plan {
            schema: "jetstreamer-cohort191-delivery-forecast-v2".into(),
            finalization: queued(10),
            import: queued(20),
            boundary_gates_sidecar: false,
            epochs: (191..=194)
                .map(|epoch| Epoch {
                    epoch,
                    full: queued(40),
                    plugin: queued(30),
                    boundary: queued(7),
                    upload: queued(5),
                    readback: queued(6),
                    source_revalidation_and_sidecar: queued(2),
                    authenticated_ready_pair: false,
                })
                .collect(),
        }
    }
    #[test]
    fn shared_import_and_serial_whole_sync_gate_every_member() {
        assert_eq!(
            forecast(&plan()).unwrap(),
            BTreeMap::from([(191, 83), (192, 96), (193, 109), (194, 122)])
        );
        let mut p = plan();
        p.boundary_gates_sidecar = true;
        assert_eq!(forecast(&p).unwrap()[&191], 90);
        // A plugin queue or contention delay can overtake the upload queue.
        p.epochs[1].plugin = queued(100);
        assert_eq!(forecast(&p).unwrap()[&192], 150);
    }
    #[test]
    fn measured_readback_stall_delays_remaining_objects_without_replay_fiction() {
        let mut p = plan();
        p.finalization = Work::Complete;
        p.import = Work::Complete;
        for e in &mut p.epochs {
            e.full = Work::Complete;
            e.plugin = Work::Complete;
        }
        p.epochs[0].upload = Work::Complete;
        p.epochs[0].readback = Work::Active {
            remaining_millis: 50,
        };
        assert_eq!(
            forecast(&p).unwrap(),
            BTreeMap::from([(191, 52), (192, 65), (193, 78), (194, 91)])
        );
        p.epochs[0].readback = Work::Active {
            remaining_millis: 80,
        };
        assert_eq!(forecast(&p).unwrap()[&194], 121);
    }
    #[test]
    fn only_authenticated_commit_yields_zero_and_retires_queue_position() {
        let mut p = plan();
        p.finalization = Work::Complete;
        p.import = Work::Complete;
        let e = &mut p.epochs[0];
        e.full = Work::Complete;
        e.plugin = Work::Complete;
        e.upload = Work::Complete;
        e.readback = Work::Complete;
        e.source_revalidation_and_sidecar = Work::Complete;
        assert!(forecast(&p).is_err());
        p.epochs[0].authenticated_ready_pair = true;
        assert_eq!(forecast(&p).unwrap()[&191], 0);
        // Retirement-only boundary work may remain without blocking a sidecar.
        p.boundary_gates_sidecar = true;
        assert!(forecast(&p).is_err());
    }
    #[test]
    fn ownership_topology_stage_order_incomplete_census_and_overflow_fail_closed() {
        let mut p = plan();
        p.import = Work::Active {
            remaining_millis: 20,
        };
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.epochs[0].full = Work::Active {
            remaining_millis: 40,
        };
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.epochs[0].readback = Work::Active {
            remaining_millis: 6,
        };
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.finalization = Work::Complete;
        p.import = Work::Complete;
        p.epochs[0].readback = Work::Complete;
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.epochs.pop();
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.epochs.swap(0, 1);
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.epochs[0].plugin = queued(0);
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.finalization = queued(u64::MAX);
        assert!(forecast(&p).is_err());
        let mut p = plan();
        p.finalization = Work::Complete;
        p.import = Work::Complete;
        for e in &mut p.epochs {
            e.full = Work::Complete;
            e.plugin = Work::Complete;
        }
        p.epochs[1].upload = Work::Active {
            remaining_millis: 5,
        };
        assert!(forecast(&p).is_err());
    }
}
