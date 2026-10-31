//! Forecast arithmetic and pure terminal validation for 191–194 metadata.
//! No observation, receipt writing, publication or admission.
//! Callers must independently authenticate every input, current phase, queue and
//! canonical ready pair. Native capture and the optional routine profile own those gates.
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

/// Pure terminal proof used before excluding this cohort from the ordinary
/// rate-bearing census. A root at 84239250 plus four closes is required; no
/// checkpoint is invented for the skipped tail to 84239999.
pub fn validate_native_terminal(v: &serde_json::Value, cutoff: u64) -> Result<()> {
    use serde_json::Value;
    fn fields<'a>(message: &'a str, prefix: &str) -> Result<BTreeMap<&'a str, &'a str>> {
        let message = if message.starts_with(prefix) {
            message
        } else {
            let (logger, body) = message
                .split_once("] ")
                .context("191 native logger framing")?;
            ensure!(
                logger.starts_with('[') && logger.contains(" INFO  jetstreamer_node::"),
                "191 native logger namespace"
            );
            body
        };
        let text = message
            .strip_prefix(prefix)
            .context("191 native message prefix")?;
        let text = text.split_once(" (").map_or(text, |(head, _)| head);
        let mut result = BTreeMap::new();
        for word in text.split_whitespace() {
            let (key, value) = word.split_once('=').context("191 native message field")?;
            ensure!(
                !value.is_empty() && result.insert(key, value).is_none(),
                "191 duplicate native field"
            );
        }
        Ok(result)
    }
    fn integer(f: &BTreeMap<&str, &str>, key: &str) -> Result<u64> {
        let s = f.get(key).context("191 missing native integer")?;
        ensure!(
            s.bytes().all(|b| b.is_ascii_digit()),
            "191 malformed native integer"
        );
        Ok(s.parse()?)
    }
    fn owner(row: &Value, cutoff: u64) -> Result<u64> {
        ensure!(
            row["_SYSTEMD_UNIT"]
                == "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service"
                && row["_SYSTEMD_INVOCATION_ID"] == "ea93199ed2fa470d99de248c2a10b246"
                && row["_PID"] == "2189644"
                && row["_UID"] == "1001",
            "191 native owner mismatch"
        );
        let time: u64 = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 native time")?
            .parse()?;
        ensure!(
            time > 0
                && time
                    <= cutoff
                        .checked_mul(1_000_000)
                        .context("191 native cutoff overflow")?,
            "191 native event is outside sample"
        );
        Ok(time)
    }
    ensure!(
        v["trusted_root_slot"] == 84239250u64 && v["archive_terminal_slot"] == 84239999u64,
        "191 terminal/root geometry changed"
    );
    let root_time = owner(&v["root"], cutoff)?;
    let f = fields(
        v["root"]["MESSAGE"]
            .as_str()
            .context("191 native checkpoint")?,
        "historical checkpoint ",
    )?;
    ensure!(
        f.len() == 10
            && integer(&f, "slot")? == 84239250
            && f.get("complete") == Some(&"true")
            && f.get("accounts_hash") == Some(&"GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq")
            && integer(&f, "tick_height")? == (84239250 + 1) * 64,
        "191 final canonical checkpoint differs"
    );
    for key in ["bank_hash", "accounts_hash", "last_blockhash"] {
        let h = f.get(key).context("191 native hash")?;
        ensure!(
            (32..=44).contains(&h.len())
                && h.bytes().all(
                    |b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b)
                ),
            "191 malformed native hash"
        );
    }
    for key in [
        "capitalization",
        "transactions",
        "writes",
        "next_write_version",
    ] {
        integer(&f, key)?;
    }
    let closes = v["closes"]
        .as_array()
        .context("191 native archive closes")?;
    ensure!(closes.len() == 4, "191 incomplete/duplicate close census");
    let mut previous = 0;
    for row in closes {
        let time = owner(row, cutoff)?;
        ensure!(time > previous, "191 closes are reordered or duplicated");
        previous = time;
        let f = fields(
            row["MESSAGE"].as_str().context("191 close message")?,
            "horizon archive complete: ",
        )?;
        ensure!(
            f.len() == 8
                && integer(&f, "slots")? == 432000
                && integer(&f, "epochs")? == 1
                && integer(&f, "buckets")? == 3375
                && integer(&f, "bytes")? > 0,
            "191 close scope differs"
        );
        for key in ["blocks", "txs", "tx_updates", "orphan_updates"] {
            integer(&f, key)?;
        }
    }
    ensure!(
        previous > root_time,
        "191 final close does not follow trusted root"
    );
    Ok(())
}

/// Observer-independent terminal handoff collected by the exact native reader.
/// This authenticates shape/provenance after the caller hash/owner-binds the
/// root-only receipt and its sealed collection plan. It never admits a task.
pub fn validate_terminal_transition(v: &serde_json::Value, cutoff: u64) -> Result<()> {
    use serde_json::{Value, json};
    const UNIT: &str =
        "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service";
    const IID: &str = "ea93199ed2fa470d99de248c2a10b246";
    const CTRL: &str = "jetstreamer-epochs191-194-target5-controller-v2-r2.service";
    const CID: &str = "c741f57764384e07a08484e6451f8f0c";
    fn ended(row: &Value, unit: &str, iid: &str, limit: u64) -> Result<u64> {
        ensure!(
            row["UNIT"] == unit
                && row["INVOCATION_ID"] == iid
                && row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
                && row["MESSAGE"] == format!("{unit}: Deactivated successfully."),
            "191 terminal transition lacks original natural PID1 exit"
        );
        let t = row["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("191 natural exit clock")?
            .parse::<u64>()?;
        ensure!(
            t > 0 && t <= limit,
            "191 terminal transition backdates natural completion"
        );
        Ok(t)
    }
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("191 terminal transition clock")?;
    ensure!(
        v["schema"] == "jetstreamer-cohort191-terminal-transition-v1"
            && v["first_epoch"] == 191
            && v["last_epoch"] == 194
            && at > 0
            && at <= cutoff
            && v.get("observer").is_none()
            && v["resource_samples"] == 0,
        "191 terminal transition scope/time/future observer differs"
    );
    for key in [
        "publication_authorized",
        "replay_launch_authorized",
        "archive_readiness_claimed",
        "r2_mutations",
    ] {
        ensure!(
            v[key] == false,
            "191 terminal transition acquired authority:{key}"
        );
    }
    validate_native_terminal(&v["native_events"], at)?;
    let limit = at
        .checked_mul(1_000_000)
        .context("191 terminal clock overflow")?;
    let producer_end = ended(&v["producer_terminal"], UNIT, IID, limit)?;
    let last_close = v["native_events"]["closes"][3]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("191 close clock")?
        .parse::<u64>()?;
    ensure!(
        producer_end >= last_close,
        "191 producer ended before final archive close"
    );
    let p = &v["producer"];
    ensure!(
        p["Id"] == UNIT
            && p["MainPID"] == "0"
            && p["NRestarts"] == "0"
            && p["ActiveState"] == "inactive"
            && p["SubState"] == "dead"
            && p["ControlGroup"] == ""
            && matches!(p["Job"].as_str(), Some("" | "0"))
            && ((p["LoadState"] == "loaded"
                && p["InvocationID"] == IID
                && p["Result"] == "success"
                && p["ExecMainStatus"] == "0")
                || (p["LoadState"] == "not-found" && p["InvocationID"] == "")),
        "191 producer remains active/replaced/ambiguous"
    );
    let c = &v["controller_lifecycle"];
    ensure!(
        matches!(
            c["kind"].as_str(),
            Some("retained-natural-terminal-controller" | "collected-natural-terminal-controller")
        ) && c["unit"]["Id"] == CTRL
            && c["unit"]["MainPID"] == "0"
            && c["unit"]["NRestarts"] == "0"
            && c["unit"]["ActiveState"] == "inactive"
            && c["unit"]["SubState"] == "dead"
            && c["unit"]["ControlGroup"] == ""
            && matches!(c["unit"]["Job"].as_str(), Some("" | "0")),
        "191 import controller is not proven naturally terminal"
    );
    ensure!(
        (c["unit"]["LoadState"] == "loaded"
            && c["unit"]["InvocationID"] == CID
            && c["unit"]["Result"] == "success"
            && c["unit"]["ExecMainStatus"] == "0")
            || (c["kind"] == "collected-natural-terminal-controller"
                && c["unit"]["LoadState"] == "not-found"
                && c["unit"]["InvocationID"] == ""),
        "191 current controller is a foreign or failed terminal actor"
    );
    if c["kind"] == "collected-natural-terminal-controller" {
        ensure!(
            c["terminal_capture"]["path"]
                == "/var/lib/jetstreamer/horizon-cohort191-controller-terminal-20261023-v1/terminal.json"
                && c["terminal_capture"]["sha256"]
                    .as_str()
                    .is_some_and(|s| s.len() == 64
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
            "191 collected controller lacks retained real exit capture"
        );
    }
    let controller_end = ended(&c["events"]["terminal"], CTRL, CID, limit)?;
    ensure!(
        controller_end >= producer_end
            && c["events"]["all_public"]["_SYSTEMD_UNIT"] == CTRL
            && c["events"]["all_public"]["_SYSTEMD_INVOCATION_ID"] == CID
            && c["events"]["all_public"]["_UID"] == "0"
            && c["events"]["all_public"]["MESSAGE"] == "all sealed cohorts 191-194 are public",
        "191 controller/import completion lacks original provenance"
    );
    let public_time = c["events"]["all_public"]["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("191 controller public clock")?
        .parse::<u64>()?;
    ensure!(
        public_time >= producer_end
            && public_time <= controller_end
            && c["events"]["all_public"]["_PID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 1),
        "191 natural controller public message clock/PID differs"
    );
    let import = &v["native_import"];
    ensure!(
        import["schema"] == "jetstreamer-cohort191-import-custody-v2"
            && import["source_batch"] == v["source_batch"]
            && import["public_batch"] == v["public_batch"]
            && import["controller_lifecycle"] == *c
            && import["materialized_epochs"] == json!([191, 192, 193, 194])
            && import["native_import_attestation"]["epochs"] == json!([191, 192, 193, 194])
            && import["native_import_attestation"]["receipt"] == v["public_batch"]["path"]
            && import["native_import_attestation"]["receipt_sha256"] == v["public_batch"]["sha256"],
        "191 transition lacks exact native import attestation"
    );
    let members = import["public_members"]
        .as_array()
        .context("191 terminal import census")?;
    ensure!(members.len() == 4, "191 terminal import census differs");
    for (index, (m, epoch)) in members.iter().zip(191..=194).enumerate() {
        let message = v["native_events"]["closes"][index]["MESSAGE"]
            .as_str()
            .context("191 archive-close message")?;
        let lengths = message
            .split_whitespace()
            .filter_map(|word| word.strip_prefix("bytes="))
            .collect::<Vec<_>>();
        ensure!(
            lengths.len() == 1
                && m["committed_archive"]["length"].as_u64() == Some(lengths[0].parse::<u64>()?),
            "191 imported archive length differs from its native close"
        );
        let sha = m["archive_sha256"]
            .as_str()
            .context("191 imported digest")?;
        ensure!(
            m["epoch"] == epoch
                && sha.len() == 64
                && sha
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && m["committed_archive"]["length"]
                    .as_u64()
                    .is_some_and(|n| n > 0),
            "191 terminal imported archive scope/digest/length differs"
        );
    }
    Ok(())
}

#[cfg(test)]
mod native_terminal_tests {
    use super::*;
    use serde_json::{Value, json};
    fn fixture() -> Value {
        let row = |time: u64, message: String| {
            json!({"_SYSTEMD_UNIT":"jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service",
            "_SYSTEMD_INVOCATION_ID":"ea93199ed2fa470d99de248c2a10b246","_PID":"2189644","_UID":"1001",
            "__REALTIME_TIMESTAMP":time.to_string(),"MESSAGE":message})
        };
        let root = format!(
            "historical checkpoint slot=84239250 bank_hash=GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq accounts_hash=GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq last_blockhash=GCANVakrcunYu9VRe1WdNd7xAPKGdoZNFgpQbagdB9zq capitalization=1 transactions=1 tick_height={} complete=true writes=0 next_write_version=1",
            (84239250u64 + 1) * 64
        );
        json!({"trusted_root_slot":84239250,"archive_terminal_slot":84239999,"root":row(4_000_000,root),
            "closes":(1..=4).map(|n|row(n*1_000_000+1,format!("horizon archive complete: slots=432000 blocks=1 txs=1 tx_updates=1 orphan_updates=1 epochs=1 buckets=3375 bytes={n} (payload 4 uncompressed)"))).collect::<Vec<_>>()})
    }
    #[test]
    fn accepts_trusted_root_and_skipped_tail_without_inventing_terminal_checkpoint() {
        validate_native_terminal(&fixture(), 5).unwrap();
    }
    #[test]
    fn trusted_native_messages_accept_standard_node_logger_prefix_only() {
        let mut v = fixture();
        let root = v["root"]["MESSAGE"].as_str().unwrap().to_owned();
        v["root"]["MESSAGE"] = json!(format!(
            "[2026-10-24T01:17:33.314060380Z INFO  jetstreamer_node::historical_replay] {root}"
        ));
        for row in v["closes"].as_array_mut().unwrap() {
            row["MESSAGE"] = json!(format!(
                "[2026-10-24T01:47:17Z INFO  jetstreamer_node::horizon] {}",
                row["MESSAGE"].as_str().unwrap()
            ));
        }
        validate_native_terminal(&v, 5).unwrap();
        for prefix in [
            "arbitrary ",
            "[time INFO  foreign::module] ",
            "[time ERROR  jetstreamer_node::horizon] ",
        ] {
            let mut bad = fixture();
            let text = bad["root"]["MESSAGE"].as_str().unwrap();
            bad["root"]["MESSAGE"] = json!(format!("{prefix}{text}"));
            assert!(validate_native_terminal(&bad, 5).is_err());
        }
    }
    #[test]
    #[ignore = "root-only real import-pending bootstrap; reads retained native records only, no resource sample or network"]
    fn actual_import_pending_bootstrap_native_journals_pass_without_rewriting_messages() {
        let bytes = std::fs::read(
            "/var/lib/jetstreamer/horizon-cohort191-import-pending-20261024-v1/bootstrap.json",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        validate_native_terminal(
            &v["native_events"],
            v["recorded_unix_seconds"].as_u64().unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn rejects_foreign_invocation_pid_uid_and_backdated_cutoff() {
        let good = fixture();
        for (pointer, value) in [
            ("/root/_SYSTEMD_INVOCATION_ID", json!("a".repeat(32))),
            ("/closes/2/_PID", json!("1")),
            ("/root/_UID", json!("0")),
            ("/closes/3/__REALTIME_TIMESTAMP", json!("6000000")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_native_terminal(&bad, 5).is_err(), "{pointer}");
        }
    }
    #[test]
    fn rejects_missing_reordered_duplicate_closes_and_false_root() {
        let good = fixture();
        let mut bad = good.clone();
        bad["closes"].as_array_mut().unwrap().pop();
        assert!(validate_native_terminal(&bad, 5).is_err());
        let mut bad = good.clone();
        bad["closes"].as_array_mut().unwrap().swap(1, 2);
        assert!(validate_native_terminal(&bad, 5).is_err());
        let mut bad = good.clone();
        bad["closes"][2] = bad["closes"][1].clone();
        assert!(validate_native_terminal(&bad, 5).is_err());
        let mut bad = good;
        bad["root"]["MESSAGE"] = json!(
            bad["root"]["MESSAGE"]
                .as_str()
                .unwrap()
                .replace("slot=84239250", "slot=84239999")
        );
        assert!(validate_native_terminal(&bad, 5).is_err());
    }
    fn transition_fixture() -> Value {
        let unit = "jetstreamer-root-sweep-e191-194-t5-20261016-v2-r2-e191-194-lane-a-1.service";
        let ctrl = "jetstreamer-epochs191-194-target5-controller-v2-r2.service";
        let iid = "ea93199ed2fa470d99de248c2a10b246";
        let cid = "c741f57764384e07a08484e6451f8f0c";
        let end = |name: &str, id: &str, time: &str| json!({"UNIT":name,"INVOCATION_ID":id,"_PID":"1","_UID":"0","MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448","MESSAGE":format!("{name}: Deactivated successfully."),"__REALTIME_TIMESTAMP":time});
        let snapshot = |name: &str, id: &str| json!({"Id":name,"LoadState":"loaded","InvocationID":id,"MainPID":"0","NRestarts":"0","ActiveState":"inactive","SubState":"dead","ControlGroup":"","Job":"","Result":"success","ExecMainStatus":"0"});
        let source = json!({"path":"/native/source","sha256":"a".repeat(64)});
        let public = json!({"path":"/native/public","sha256":"b".repeat(64)});
        let lifecycle = json!({"kind":"retained-natural-terminal-controller","unit":snapshot(ctrl,cid),"events":{"terminal":end(ctrl,cid,"8000000"),"all_public":{"_SYSTEMD_UNIT":ctrl,"_SYSTEMD_INVOCATION_ID":cid,"_UID":"0","_PID":"123","MESSAGE":"all sealed cohorts 191-194 are public","__REALTIME_TIMESTAMP":"7000000"}}});
        json!({"schema":"jetstreamer-cohort191-terminal-transition-v1","first_epoch":191,"last_epoch":194,"recorded_unix_seconds":9,"resource_samples":0,"publication_authorized":false,"replay_launch_authorized":false,"archive_readiness_claimed":false,"r2_mutations":false,"source_batch":source,"public_batch":public,"native_events":fixture(),"producer":snapshot(unit,iid),"producer_terminal":end(unit,iid,"6000000"),"controller_lifecycle":lifecycle,"native_import":{"schema":"jetstreamer-cohort191-import-custody-v2","source_batch":source,"public_batch":public,"controller_lifecycle":lifecycle,"materialized_epochs":[191,192,193,194],"native_import_attestation":{"epochs":[191,192,193,194],"receipt":public["path"],"receipt_sha256":public["sha256"]},"public_members":(191..=194).map(|e|json!({"epoch":e,"archive_sha256":"c".repeat(64),"committed_archive":{"length":e-190}})).collect::<Vec<_>>()}})
    }
    #[test]
    fn first_transition_needs_no_future_observer_but_requires_real_natural_end_and_import() {
        let v = transition_fixture();
        validate_terminal_transition(&v, 9).unwrap();
        assert!(v.get("observer").is_none());
        for (pointer, value) in [
            ("/producer/MainPID", json!("123")),
            ("/producer/InvocationID", json!("f".repeat(32))),
            ("/producer_terminal/INVOCATION_ID", json!("f".repeat(32))),
            (
                "/controller_lifecycle/kind",
                json!("live-original-controller"),
            ),
            ("/native_import/materialized_epochs", json!([191, 192, 193])),
            ("/native_import/public_members/2/epoch", json!(195)),
            (
                "/native_import/public_members/0/committed_archive/length",
                json!(99),
            ),
            ("/publication_authorized", json!(true)),
            ("/recorded_unix_seconds", json!(10)),
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            if pointer.starts_with("/controller_lifecycle/") {
                bad["native_import"]["controller_lifecycle"] = bad["controller_lifecycle"].clone();
            }
            assert!(validate_terminal_transition(&bad, 9).is_err(), "{pointer}");
        }
        let mut future = v;
        future["observer"] = json!({"sha256":"future"});
        assert!(validate_terminal_transition(&future, 9).is_err());
    }
    #[test]
    fn collected_controller_requires_the_real_retained_terminal_capture_binding() {
        let mut v = transition_fixture();
        v["controller_lifecycle"]["kind"] = json!("collected-natural-terminal-controller");
        v["controller_lifecycle"]["unit"]["LoadState"] = json!("not-found");
        v["controller_lifecycle"]["unit"]["InvocationID"] = json!("");
        v["controller_lifecycle"]["terminal_capture"] = json!({"path":"/var/lib/jetstreamer/horizon-cohort191-controller-terminal-20261023-v1/terminal.json","sha256":"d".repeat(64)});
        v["native_import"]["controller_lifecycle"] = v["controller_lifecycle"].clone();
        validate_terminal_transition(&v, 9).unwrap();
        v["controller_lifecycle"]
            .as_object_mut()
            .unwrap()
            .remove("terminal_capture");
        v["native_import"]["controller_lifecycle"] = v["controller_lifecycle"].clone();
        assert!(validate_terminal_transition(&v, 9).is_err());
    }
}
