//! Genuine assembly/terminal/source provenance for the separate private V3 scan.
use crate::{evidence, handoff};
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::{ArchiveProvenance, encode_archive_provenance};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, os::unix::fs::MetadataExt, path::Path};
#[path = "boundaries.rs"]
pub(super) mod boundaries;
pub(super) const ASSEMBLER: &str =
    "d1475bc12efb6f543c6772735c9ff08667b1ecd99660b01d6a390fbf87773eab";
pub(super) const ASSEMBLY_UNIT: &str = "horizon-assemble-223-native20-native25-v1.service";
pub(super) const SOURCE: &str = "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1/epoch-223-private-v3.jet";
pub(super) const VERIFY_UNIT: &str = "horizon-verify-223-native20-native25-private-v3-v1.service";
pub(super) const VERIFY_ROOT: &str =
    "/var/lib/jetstreamer/horizon-223-native20-native25-private-verification-v1";
pub(super) const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
pub(super) const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
// Exact marker emitted by the previously qualified and preserved 529fc90f binary.
// This historical protocol string must not be reformatted.
pub(super) const MARKER: &str =
    "private223 V3 assembly completed; final full/plugin/publication/repair gates remain separate";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inputs {
    pub handoff_request: handoff::Bound,
    pub handoff_receipt: handoff::Bound,
    pub assembly_plan: handoff::Bound,
    pub assembly_launch: handoff::Bound,
    pub assembly_receipt: handoff::Bound,
    pub assembly_terminal_journal: handoff::Bound,
    pub boundary_metadata: handoff::Bound,
    pub boundary_collector: handoff::Bound,
}
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub dev: u64,
    pub ino: u64,
    pub len: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub mtime: i64,
    pub mtime_ns: i64,
    pub ctime: i64,
    pub ctime_ns: i64,
}
pub(super) fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
pub(super) fn read(b: &handoff::Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        8 << 20,
        immutable,
    )?)?)
}
pub(super) fn iid(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
pub(super) fn terminal(
    raw: &[u8],
    unit: &str,
    invocation: &str,
    pid: &str,
    marker: &str,
) -> Result<Value> {
    ensure!(
        iid(invocation) && pid.parse::<u32>().is_ok_and(|p| p > 1) && raw.len() <= 8 << 20,
        "invalid actual terminal identity/journal envelope"
    );
    let mut app = Vec::new();
    let mut manager = Vec::new();
    for (n, line) in std::str::from_utf8(raw)?.lines().enumerate() {
        ensure!(
            n < 10000 && line.len() <= 65536,
            "terminal journal bounds exceeded"
        );
        let row: Value = serde_json::from_str(line)?;
        let msg = row["MESSAGE"]
            .as_str()
            .context("terminal journal message")?;
        if msg == marker {
            ensure!(
                row["_SYSTEMD_UNIT"] == unit
                    && row["_SYSTEMD_INVOCATION_ID"] == invocation
                    && row["_PID"] == pid,
                "foreign application terminal marker"
            );
            app.push((
                n,
                row["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("application terminal clock")?
                    .parse::<u64>()?,
            ));
        }
        if msg == format!("{unit}: Deactivated successfully.") {
            ensure!(
                row["_PID"] == "1" && row["UNIT"] == unit && row["INVOCATION_ID"] == invocation,
                "foreign PID1 terminal"
            );
            manager.push((
                n,
                row["__REALTIME_TIMESTAMP"]
                    .as_str()
                    .context("PID1 terminal clock")?
                    .parse::<u64>()?,
            ));
        }
        if row["_PID"] == "1" && row["UNIT"] == unit && row["INVOCATION_ID"] == invocation {
            ensure!(
                !msg.contains("Failed")
                    && !msg.contains("Failed with result")
                    && !msg.contains("Main process exited"),
                "terminal journal contains failed producer outcome"
            );
        }
    }
    ensure!(
        app.len() == 1
            && manager.len() == 1
            && app[0].0 < manager[0].0
            && app[0].1 > 0
            && app[0].1 < manager[0].1,
        "missing, duplicated or unordered application/PID1 success"
    );
    Ok(
        json!({"unit":unit,"invocation_id":invocation,"main_pid":pid,"application_line":app[0].0+1,"manager_line":manager[0].0+1,
        "application_realtime_micros":app[0].1,"manager_realtime_micros":manager[0].1,"actual_success_history_validated":true}),
    )
}
pub(super) fn canonical_metadata(inputs: &Inputs) -> Result<Value> {
    evidence::bound_file(
        &inputs.boundary_collector.path,
        &inputs.boundary_collector.sha256,
        128 << 20,
        true,
    )?;
    let v = read(&inputs.boundary_metadata, true)?;
    ensure!(
        v["schema"] == "jetstreamer-private-epoch223-boundary-metadata-v1"
            && v["epoch"] == 223
            && v["endpoint"] == boundaries::ENDPOINT
            && v["collector_sha256"] == inputs.boundary_collector.sha256
            && v["raw_rpc_responses_rehashed"] == true
            && v["finalized_commitment_requested"] == true
            && v["redirects_permitted"] == false,
        "canonical boundary collector/scope differs"
    );
    for k in [
        "archive_opened",
        "archive_initial_boundary_verified",
        "complete_coverage_verified",
        "independent_full_poh_verified",
        "runtime_promotion_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[k] == false, "canonical candidate acquired authority:{k}");
    }
    ensure!(
        v["requests"].as_object().is_some_and(|r| r.len() == 3)
            && v["responses"].as_object().is_some_and(|r| r.len() == 3),
        "canonical boundary pair census differs"
    );
    let mut rows = BTreeMap::new();
    for (role, slot) in boundaries::ROLES {
        let request: handoff::Bound = serde_json::from_value(v["requests"][role].clone())?;
        ensure!(
            read(&request, true)? == boundaries::request(slot),
            "canonical request omitted finalized exact-slot scope"
        );
        let response: handoff::Bound = serde_json::from_value(v["responses"][role].clone())?;
        rows.insert(role.into(), read(&response, true)?);
    }
    let derived = boundaries::derive(&rows)?;
    ensure!(
        v["derived"] == derived,
        "canonical boundary derivation changed"
    );
    Ok(v)
}
pub(super) struct Prepared {
    pub assembly: Value,
    pub launch: Value,
    pub boundary: Value,
    pub provenance: Vec<u8>,
    pub provenance_sha256: String,
    pub expected_updates: u64,
    pub terminal_history: Value,
}
pub(super) fn prepare(s: &Inputs) -> Result<Prepared> {
    ensure!(
        s.assembly_plan.path
            == Path::new("/var/lib/jetstreamer/horizon-223-private-assembly-launch-v1/plan.json")
            && s.assembly_launch.path
                == Path::new(
                    "/var/lib/jetstreamer/horizon-223-private-assembly-capture-v1/launch.json"
                )
            && s.assembly_receipt.path == Path::new(SOURCE).parent().unwrap().join("assembly.json"),
        "final V3 input namespace differs"
    );
    let request: handoff::Plan = serde_json::from_value(read(&s.handoff_request, true)?)?;
    let h = handoff::prepare(&request)?;
    let actual = read(&s.handoff_receipt, true)?;
    ensure!(
        actual["self_sha256"] == "137b5a3a767604ea4c9f7405dd0af7af0eb860f30e5ece52ce49017825d35c22"
            && actual["plan"] == serde_json::to_value(&s.handoff_request)?,
        "not the original qualified handoff authority"
    );
    for (key, value) in h.receipt.as_object().context("handoff object")? {
        ensure!(
            actual.get(key) == Some(value),
            "actual handoff differs:{key}"
        );
    }
    let v3 = handoff::provenance(&h.prefix, &h.tail)?;
    let expected_updates = v3
        .runtime_segments
        .last()
        .context("last V3 mapping")?
        .write_versions
        .archive_end_exclusive()
        .context("normalized event extent overflow")?;
    let provenance = encode_archive_provenance(&ArchiveProvenance::V3(v3))?;
    let provenance_sha256 = evidence::sha(&provenance);
    let plan = read(&s.assembly_plan, true)?;
    let assembly = read(&s.assembly_receipt, false)?;
    let launch = read(&s.assembly_launch, true)?;
    ensure!(
        plan["schema"] == "jetstreamer-private223-v3-assembly-plan-v1"
            && plan["handoff_request"] == serde_json::to_value(&s.handoff_request)?
            && plan["handoff_receipt"] == serde_json::to_value(&s.handoff_receipt)?
            && assembly["schema"] == "jetstreamer-private223-v3-assembly-v1"
            && assembly["epoch"] == 223
            && assembly["unit"] == ASSEMBLY_UNIT
            && assembly["self_sha256"] == ASSEMBLER
            && assembly["plan"] == serde_json::to_value(&s.assembly_plan)?
            && assembly["handoff_request"] == plan["handoff_request"]
            && assembly["handoff_receipt"] == plan["handoff_receipt"]
            && assembly["admission"] == plan["admission"]
            && assembly["private_output"] == SOURCE
            && assembly["archive_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 160u64 << 30)
            && assembly["archive_sha256"]
                .as_str()
                .is_some_and(evidence::is_sha)
            && assembly["source_archives"] == 2
            && assembly["slots_merged"] == 432000
            && assembly["account_updates_rebased"] == expected_updates
            && assembly["provenance_version"] == 3
            && assembly["planned_mappings"] == h.receipt["planned_mappings"]
            && assembly["checked_private_merge_completed"] == true,
        "actual complete V3 assembly/source normalization differs"
    );
    for k in [
        "bank_rerun_performed",
        "independent_final_archive_verification_passed",
        "current_plugin_verification_passed",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "retirement_authorized",
        "repair_closed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            assembly[k] == false,
            "assembler claimed independent authority:{k}"
        );
    }
    let invocation = assembly["invocation_id"]
        .as_str()
        .filter(|s| iid(s))
        .context("actual assembly invocation")?;
    ensure!(
        launch["schema"] == "jetstreamer-private223-v3-assembly-launch-v1"
            && launch["unit"] == ASSEMBLY_UNIT
            && launch["invocation_id"] == invocation
            && launch["assembler_sha256"] == ASSEMBLER
            && launch["assembly_plan"] == assembly["plan"]
            && launch["admission"] == assembly["admission"]
            && launch["assembly_only_no_replay"] == true
            && launch["launched"] == true,
        "actual assembly capture/terminal differs"
    );
    let pid = launch["producer_at_capture"]["MainPID"]
        .as_str()
        .context("captured actual assembler PID")?;
    let raw = evidence::bound_file(
        &s.assembly_terminal_journal.path,
        &s.assembly_terminal_journal.sha256,
        8 << 20,
        true,
    )?;
    let terminal_history = terminal(&raw, ASSEMBLY_UNIT, invocation, pid, MARKER)?;
    let boundary = canonical_metadata(s)?;
    ensure!(
        boundary["derived"]["expected_terminal"]["blockhash"] == h.tail.terminal.last_blockhash,
        "canonical terminal blockhash does not match the preserved native 25 terminal"
    );
    Ok(Prepared {
        assembly,
        launch,
        boundary,
        provenance,
        provenance_sha256,
        expected_updates,
        terminal_history,
    })
}
pub(super) fn full_args(archive: &Path, p: &Prepared) -> Vec<String> {
    vec![
        archive.display().to_string(),
        "--full".into(),
        "--anchor".into(),
        "96335999".into(),
        p.boundary["derived"]["candidate_anchor"]["blockhash"]
            .as_str()
            .unwrap()
            .into(),
        "--expected-terminal".into(),
        "96767999".into(),
        p.boundary["derived"]["expected_terminal"]["blockhash"]
            .as_str()
            .unwrap()
            .into(),
        "--threads".into(),
        "8".into(),
        "--expected-provenance-sha256".into(),
        p.provenance_sha256.clone(),
    ]
}
pub(super) fn plugin_args(directory: &Path) -> Vec<String> {
    vec![
        "223:223".into(),
        directory.display().to_string(),
        "--threads".into(),
        "8".into(),
        "--verify-only".into(),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    fn journal() -> Vec<Value> {
        vec![
            json!({"MESSAGE":MARKER,"_PID":"42","_SYSTEMD_UNIT":ASSEMBLY_UNIT,"_SYSTEMD_INVOCATION_ID":"1".repeat(32),"__REALTIME_TIMESTAMP":"1000"}),
            json!({"MESSAGE":format!("{ASSEMBLY_UNIT}: Deactivated successfully."),"_PID":"1","UNIT":ASSEMBLY_UNIT,"INVOCATION_ID":"1".repeat(32),"__REALTIME_TIMESTAMP":"2000"}),
        ]
    }
    fn encode(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| serde_json::to_string(r).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }
    #[test]
    fn actual_application_and_pid_one_history_cannot_be_replaced_by_current_absence() {
        let rows = journal();
        terminal(&encode(&rows), ASSEMBLY_UNIT, &"1".repeat(32), "42", MARKER).unwrap();
        assert!(terminal(&[], ASSEMBLY_UNIT, &"1".repeat(32), "42", MARKER).is_err());
        for (index, key, value) in [
            (0, "_PID", json!("43")),
            (0, "_SYSTEMD_INVOCATION_ID", json!("2".repeat(32))),
            (1, "__REALTIME_TIMESTAMP", json!("500")),
            (1, "UNIT", json!("foreign.service")),
        ] {
            let mut bad = rows.clone();
            bad[index][key] = value;
            assert!(
                terminal(&encode(&bad), ASSEMBLY_UNIT, &"1".repeat(32), "42", MARKER).is_err(),
                "{index}:{key}"
            );
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows[1].clone());
        assert!(
            terminal(
                &encode(&duplicate),
                ASSEMBLY_UNIT,
                &"1".repeat(32),
                "42",
                MARKER
            )
            .is_err()
        );
    }
    #[test]
    fn full_scan_binds_adjacent_epoch_edges_and_independent_v3_provenance() {
        let p = Prepared {
            assembly: Value::Null,
            launch: Value::Null,
            boundary: json!({"derived":{"candidate_anchor":{"blockhash":"actual-anchor"},"expected_terminal":{"blockhash":"actual-terminal"}}}),
            provenance: vec![],
            provenance_sha256: "a".repeat(64),
            expected_updates: 0,
            terminal_history: Value::Null,
        };
        let args = full_args(Path::new("/private/epoch-223.jet"), &p);
        assert_eq!(
            &args[2..8],
            [
                "--anchor",
                "96335999",
                "actual-anchor",
                "--expected-terminal",
                "96767999",
                "actual-terminal"
            ]
        );
        assert_eq!(args.last().unwrap(), &"a".repeat(64));
        assert!(!args.iter().any(|v| v == "96335538"));
        assert_eq!(
            plugin_args(Path::new("/private")),
            vec!["223:223", "/private", "--threads", "8", "--verify-only"]
        );
    }
}
