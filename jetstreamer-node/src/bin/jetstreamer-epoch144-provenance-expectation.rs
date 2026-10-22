//! Independent, private expectation for the exact144 checkpoint restart.
//! Reads sealed source manifests only, never the assembled archive or R2.
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon::archive::*;
use jetstreamer_node::segment_manifest::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Command,
};

const UNIT: &str = "horizon-qualify-144-checkpoint-continuation-20261022-v1.service";
const IID: &str = "8fddd3ef045c4fe5b12c7d25f43a4b73";
const PREFIX: &str = "917f700274c0ff0386cd8be2f27eb2ace9f3bc7dff38e1010d0c04bb79b8c273";
const PREFIX_MANIFEST: &str = "691d5f3768b8c283678937b49790606b6091d4ab632372bfff38664c005b544a";
const SNAPSHOT: &str = "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae";
const WORKER: &str = "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8";
const NODE: &str = "ac47031ac2cc42c0d7c343aebbfe049433fc76b7ee8d6da3ca2ac7de9f428dbd";
const PRODUCER_PLAN: &str = "7d03772b0cbb865822eec517d3e856f0c28cbd7bbcb7e24ae58ed708647cf8df";
const SOURCE: &str = "/home/sol/.jetstreamer-private/checkpoint-continuation-144-20261022-v1/output/epoch-144-checkpoint-restart-v4.jet";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    prefix_manifest: Bound,
    suffix_manifest: Bound,
    producer_outcome: Bound,
    output: PathBuf,
}
fn read(b: &Bound) -> Result<Vec<u8>> {
    evidence::bound_file(&b.path, &b.sha256, 1 << 20, true)
}
fn digest(s: &str) -> Result<[u8; 32]> {
    ensure!(evidence::is_sha(s), "noncanonical digest");
    let mut bytes = [0; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(bytes)
}
fn checkpoint(s: &SegmentCheckpointSummary) -> Result<RuntimeStateCheckpoint> {
    Ok(RuntimeStateCheckpoint {
        slot: s.slot,
        bank_hash: s.bank_hash.parse()?,
        accounts_hash_kind: AccountsHashKind::LegacyAccountsHash,
        accounts_hash: s.accounts_hash.parse()?,
        last_blockhash: s.last_blockhash.parse()?,
        capitalization: s.capitalization,
        transaction_count: s.transaction_count,
        tick_height: s.tick_height,
        slot_complete: s.slot_complete,
        next_write_version: s.next_write_version,
    })
}
fn outcome(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch144-checkpoint-continuation-v2"
            && v["producer_unit"] == UNIT
            && v["producer_invocation_id"] == IID
            && v["node_sha256"] == NODE
            && v["plan"]["sha256"] == PRODUCER_PLAN
            && v["private_output"] == SOURCE
            && v["prefix_archive_sha256"] == PREFIX
            && v["restart_snapshot_sha256"] == SNAPSHOT
            && v["canonical_root_slot"] == 62639490
            && v["remaining_slots"] == 509
            && v["assembly"]["source_archives"] == 2
            && v["assembly"]["slots_merged"] == 432000
            && v["assembly"]["provenance_version"] == 4
            && v["fresh_prefix_full_validation_passed"] == true
            && v["fresh_native_checkpoint_matches"] == true,
        "foreign or incomplete144 assembly"
    );
    for key in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "outcome grants authority:{key}");
    }
    Ok(())
}
fn derive(
    p: &HistoricalSegmentManifest,
    s: &HistoricalSegmentManifest,
    v: &Value,
) -> Result<ArchiveProvenance> {
    outcome(v)?;
    p.validate()?;
    s.validate()?;
    ensure!(
        p.epoch == 144
            && s.epoch == 144
            && p.bootstrap.slot == 62207522
            && p.output_slot_start == 62208000
            && p.output_slot_count == 431491
            && p.terminal.slot == 62639490
            && s.bootstrap.slot == 62639490
            && s.output_slot_start == 62639491
            && s.output_slot_count == 509
            && s.terminal.slot == 62639999,
        "source coverage differs"
    );
    ensure!(
        p.archive_sha256 == digest(PREFIX)?
            && s.archive_sha256
                == digest(
                    v["suffix_archive_sha256"]
                        .as_str()
                        .context("suffix digest")?
                )?
            && s.bootstrap_archive_sha256 == Some(digest(SNAPSHOT)?)
            && s.bootstrap.write_count == 0,
        "source or snapshot differs"
    );
    let mut segments = Vec::new();
    let mut normalized = 0;
    for source in [p, s] {
        ensure!(
            source.worker_executable_sha256 == digest(WORKER)?
                && source.runtime.runtime_profile == "solana-v1.4.25"
                && source.runtime.runtime_revision == "893cc7647248a3536fb6e6d0b5e51c71446b862d"
                && source.runtime.genesis_hash == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
                && source.runtime.runtime_admission == SegmentRuntimeAdmission::Candidate
                && source.runtime.runtime_toolchain
                    == "rustc 1.46.0 (04488afe3 2020-08-24); target=x86_64-unknown-linux-gnu"
                && source.runtime.runtime_target == "x86_64-unknown-linux-gnu"
                && source.runtime.runtime_toolchain == p.runtime.runtime_toolchain
                && source.runtime.runtime_target == p.runtime.runtime_target,
            "foreign runtime identity"
        );
        let mapping = WriteVersionNormalization {
            worker_start: source.emitted_raw_write_versions.start,
            worker_end_exclusive: source.emitted_raw_write_versions.end,
            archive_start: normalized,
        };
        normalized = mapping
            .archive_end_exclusive()
            .context("normalization overflow")?;
        segments.push(RuntimeSegmentProvenance {
            slot_start: source.output_slot_start,
            slot_count: source.output_slot_count,
            generation_profile: source.runtime.generation_profile.clone(),
            runtime_profile: source.runtime.runtime_profile.clone(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: source.runtime.runtime_revision.clone(),
            runtime_toolchain: source.runtime.runtime_toolchain.clone(),
            worker_executable_sha256: Some(source.worker_executable_sha256),
            write_versions: mapping,
        });
    }
    let expected = ArchiveProvenance::V4(ArchiveProvenanceV4 {
        base: ArchiveProvenanceV3 {
            assembly_profile: format!(
                "{}/epoch144-checkpoint-continuation-v2",
                s.runtime.generation_profile
            ),
            genesis_hash: p.runtime.genesis_hash.parse()?,
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_state: StateCommitment {
                slot: p.bootstrap.slot,
                kind: StateCommitmentKind::LegacyAccountsHash,
                hash: p.bootstrap.accounts_hash.parse()?,
            },
            requested_slot_start: 62208000,
            requested_slot_count: 432000,
            transaction_metadata: TransactionMetadataPolicy::observed(),
            runtime_segments: segments,
            handoffs: vec![RuntimeHandoffProvenance {
                boundary_slot: 62639491,
                predecessor: checkpoint(&p.terminal)?,
                successor: checkpoint(&s.bootstrap)?,
                successor_bootstrap_kind: BootstrapStateKind::SnapshotArchive,
                successor_bootstrap_archive_sha256: digest(SNAPSHOT)?,
                successor_bootstrap_write_count: 0,
            }],
        },
    });
    expected.validate()?;
    Ok(expected)
}
fn terminal() -> Result<()> {
    let output = Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState"]).output()?;
    ensure!(output.status.success(), "terminal observation failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let fields: std::collections::BTreeMap<_, _> =
        text.lines().filter_map(|l| l.split_once('=')).collect();
    for (k, v) in [
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
    ] {
        ensure!(
            fields.get(k) == Some(&v),
            "actual144 producer not exact clean terminal:{k}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sources() -> (HistoricalSegmentManifest, HistoricalSegmentManifest, Value) {
        let mut p: HistoricalSegmentManifest = serde_json::from_str(include_str!(
            "../../tests/fixtures/epoch213-prefix-segment.json"
        ))
        .unwrap();
        p.epoch = 144;
        p.output_slot_start = 62208000;
        p.output_slot_count = 431491;
        p.bootstrap.slot = 62207522;
        p.bootstrap.tick_height = (p.bootstrap.slot + 1) * 64;
        p.terminal.slot = 62639490;
        p.terminal.tick_height = (p.terminal.slot + 1) * 64;
        p.runtime.runtime_profile = "solana-v1.4.25".into();
        p.runtime.runtime_revision = "893cc7647248a3536fb6e6d0b5e51c71446b862d".into();
        p.runtime.runtime_toolchain =
            "rustc 1.46.0 (04488afe3 2020-08-24); target=x86_64-unknown-linux-gnu".into();
        p.archive_sha256 = digest(PREFIX).unwrap();
        p.worker_executable_sha256 = digest(WORKER).unwrap();
        let mut s = p.clone();
        s.bootstrap = p.terminal.clone();
        s.bootstrap.write_count = 0;
        s.bootstrap.next_write_version = 100;
        s.terminal.slot = 62639999;
        s.terminal.tick_height = (s.terminal.slot + 1) * 64;
        s.terminal.next_write_version = 200;
        s.output_slot_start = 62639491;
        s.output_slot_count = 509;
        s.bootstrap_archive_sha256 = Some(digest(SNAPSHOT).unwrap());
        s.archive_sha256 = [3; 32];
        s.emitted_raw_write_versions.start = 100;
        s.emitted_raw_write_versions.end = 200;
        let v = json!({"schema":"jetstreamer-private-epoch144-checkpoint-continuation-v2","producer_unit":UNIT,"producer_invocation_id":IID,
            "node_sha256":NODE,"plan":{"sha256":PRODUCER_PLAN},"private_output":SOURCE,"prefix_archive_sha256":PREFIX,
            "suffix_archive_sha256":sha256_hex_string(&s.archive_sha256),"restart_snapshot_sha256":SNAPSHOT,"canonical_root_slot":62639490,
            "remaining_slots":509,"assembly":{"source_archives":2,"slots_merged":432000,"provenance_version":4},
            "fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,
            "canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false});
        (p, s, v)
    }
    #[test]
    fn preserves_independent_cursors_and_exact_scope() {
        let (p, s, v) = sources();
        let ArchiveProvenance::V4(x) = derive(&p, &s, &v).unwrap() else {
            panic!("V4 required")
        };
        assert_eq!(x.base.requested_slot_count, 432000);
        assert_ne!(
            x.base.handoffs[0].predecessor.next_write_version,
            x.base.handoffs[0].successor.next_write_version
        );
        assert_eq!(
            x.base.runtime_segments[1].write_versions.archive_start,
            p.emitted_raw_write_versions.end - p.emitted_raw_write_versions.start
        );
    }
    #[test]
    fn rejects_checkpoint_snapshot_worker_and_namespace_substitution() {
        let (p, s, v) = sources();
        let changes: [fn(&mut HistoricalSegmentManifest); 6] = [
            |s| s.bootstrap.bank_hash = "11111111111111111111111111111111".into(),
            |s| s.bootstrap.write_count = 1,
            |s| s.output_slot_count = 508,
            |s| s.bootstrap_archive_sha256 = Some([8; 32]),
            |s| s.worker_executable_sha256 = [8; 32],
            |s| s.runtime.runtime_profile = "solana-v1.6.16".into(),
        ];
        for change in changes {
            let mut bad = s.clone();
            change(&mut bad);
            assert!(derive(&p, &bad, &v).is_err());
        }
        for (key, value) in [
            ("producer_invocation_id", json!("wrong")),
            ("publication_authorized", json!(true)),
            ("remaining_slots", json!(510)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(derive(&p, &s, &bad).is_err());
        }
    }
    #[test]
    fn source_cursor_change_changes_independent_expectation() {
        let (p, mut s, v) = sources();
        let original = encode_archive_provenance(&derive(&p, &s, &v).unwrap()).unwrap();
        s.terminal.next_write_version += 1;
        s.emitted_raw_write_versions.end += 1;
        assert_ne!(
            original,
            encode_archive_provenance(&derive(&p, &s, &v).unwrap()).unwrap()
        );
    }
}
async fn capture_boundaries(output: &Path, self_sha: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let mut blocks = Vec::new();
    for slot in [62207999u64, 62639999] {
        let request = json!({"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,{"commitment":"finalized","transactionDetails":"none","rewards":false}]});
        let mut response = client
            .post("https://api.mainnet-beta.solana.com")
            .json(&request)
            .send()
            .await?
            .error_for_status()?;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(bytes.len() + chunk.len() <= 16384, "RPC response too large");
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        let blockhash = value["result"]["blockhash"]
            .as_str()
            .context("finalized boundary block absent")?;
        let _: solana_hash::Hash = blockhash.parse()?;
        ensure!(
            value["jsonrpc"] == "2.0"
                && value["id"] == slot
                && value.get("error").is_none()
                && value["result"]["parentSlot"]
                    .as_u64()
                    .is_some_and(|n| n < slot),
            "wrong finalized RPC result"
        );
        blocks.push(json!({"slot":slot,"blockhash":blockhash,"request":request,"raw_response":std::str::from_utf8(&bytes)?,"raw_response_sha256":evidence::sha(&bytes)}));
    }
    evidence::write_receipt(
        output,
        &json!({"schema":"jetstreamer-private144-finalized-boundaries-v2","epoch":144,"rpc":"https://api.mainnet-beta.solana.com",
        "tool_sha256":self_sha,"blocks":blocks,"accounts_root_qualification_authorized":false,"runtime_admission_authorized":false,
        "canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    if a.len() == 5 && a[1] == "--capture-boundaries" && a[3] == "--self-sha256" {
        ensure!(unsafe { libc::geteuid() } == 0, "root required");
        evidence::bound_file(
            &std::fs::read_link("/proc/self/exe")?,
            &a[4],
            128 << 20,
            true,
        )?;
        return capture_boundaries(Path::new(&a[2]), &a[4]).await;
    }
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch144-provenance-expectation PLAN --plan-sha256 SHA --self-sha256 SHA (root)"
    );
    let exe = std::fs::read_link("/proc/self/exe")?;
    evidence::bound_file(&exe, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    ensure!(
        p.schema == "jetstreamer-private144-provenance-plan-v2"
            && p.prefix_manifest.sha256 == PREFIX_MANIFEST,
        "foreign144 expectation plan"
    );
    terminal()?;
    let prefix: HistoricalSegmentManifest = serde_json::from_slice(&read(&p.prefix_manifest)?)?;
    let suffix: HistoricalSegmentManifest = serde_json::from_slice(&read(&p.suffix_manifest)?)?;
    let v: Value = serde_json::from_slice(&read(&p.producer_outcome)?)?;
    let bytes = encode_archive_provenance(&derive(&prefix, &suffix, &v)?)?;
    terminal()?;
    evidence::write_receipt(
        &p.output,
        &json!({"schema":"jetstreamer-private-epoch144-provenance-expectation-v2","epoch":144,
        "prefix_manifest":p.prefix_manifest,"suffix_manifest":p.suffix_manifest,"producer_outcome":p.producer_outcome,
        "tool_sha256":a[5],"expected_provenance_sha256":evidence::sha(&bytes),"expected_provenance_encoded_bytes":bytes.len(),
        "source_manifest_scope_validated":true,"assembled_target_opened":false,"source_archives_rehashed":false,
        "independent_final_archive_verification_passed":false,"current_plugin_verification_passed":false,
        "runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    Ok(())
}
