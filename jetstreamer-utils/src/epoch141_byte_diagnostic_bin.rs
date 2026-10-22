//! Exact first-target byte interpretation, never connected recovery or PoH proof.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use jetstreamer_utils::{
    horizon_legacy_byte_diagnostic::diagnose_v1_4_25_acquired_bytes,
    horizon_legacy_recovery::{LegacySlotScope, ResolvedLegacyRecord},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
};
const RAW: &str = "/usr/local/lib/jetstreamer/horizon-repair-control-20261022-v144/epoch141-first-target-acquisition.json";
const RAW_SHA: &str = "785b52de7a18e7ca864af4c0ad234553bc16da829c7115ef798c284abab68e3b";
const TARGET: &str =
    "/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/targets/target-60911776.json";
const TARGET_SHA: &str = "3103bc3180eb4b6661cc541c748445c7b668d6837877ec034119177552f72c8d";
const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service";
const IID: &str = "ae452cc022d84d6594baf6730de9e5a7";
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    acquisition: Bound,
    finalized_target: Bound,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoded {
    family: String,
    key_base64: String,
    value_base64: Option<String>,
}
struct Owned {
    family: String,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}
struct Prepared {
    target: Value,
    first: Vec<Owned>,
    records: Vec<Owned>,
    final_hash: [u8; 32],
}
impl Owned {
    fn borrowed(&self) -> ResolvedLegacyRecord<'_> {
        ResolvedLegacyRecord {
            family: &self.family,
            key: &self.key,
            value: self.value.as_deref(),
        }
    }
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn decode(records: &Value, expected: usize) -> Result<Vec<Owned>> {
    let encoded: Vec<Encoded> = serde_json::from_value(records.clone())?;
    ensure!(encoded.len() == expected, "raw record count differs");
    encoded
        .into_iter()
        .map(|r| {
            let key = STANDARD.decode(&r.key_base64)?;
            ensure!(key.len() == 8 || key.len() == 16, "raw key length differs");
            let value = r.value_base64.map(|s| STANDARD.decode(s)).transpose()?;
            ensure!(
                value.as_ref().is_none_or(|v| v.len() <= 1 << 20),
                "raw value oversized"
            );
            Ok(Owned {
                family: r.family,
                key,
                value,
            })
        })
        .collect()
}
fn validate_acquisition(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch141-native-first-target-acquisition-v1"
            && v["epoch"] == 141
            && v["slot"] == 60911776
            && v["parent_slot"] == 60911771
            && v["invocation_id"] == IID
            && v["self_sha256"]
                == "0e7f847b520a91ba033f97181023ea20f9c833653744715c9e3448fbd4de088b"
            && v["plan_sha256"]
                == "8cd7cf25598debb078735c8925ce67a185a4dfa9aadfd2dedd5be7e8bcf40797"
            && v["admission_sha256"]
                == "a2bd3711ef52d3e13a826d4c6310860fbdd32bd4fb7c9c7569aa0bd9e48806e6"
            && v["native_session_complete"] == true
            && v["complete_retained_census_revalidated_after_close"] == true
            && v["native_session"]["batches"] == 2
            && v["native_session"]["queries"] == 787
            && v["native_session"]["complete_census_revalidated"] == true
            && v["queried_target_count"] == 1
            && v["recovered_target_count"] == 0
            && v["complete_finalized_target_census_count"] == 18283
            && v["acquisition_only"] == true
            && v["acquisition_summary"]["recorded_is_connected"] == false
            && v["acquisition_summary"]["expected_data_shreds"] == 778
            && v["acquisition_summary"]["missing_data_shred_indexes"] == json!([])
            && v["acquisition_summary"]["unexpected_data_shred_length_indexes"] == json!([]),
        "not exact closed/rehash-bound raw acquisition"
    );
    for key in [
        "full_target_census_complete",
        "source_completeness_proven",
        "live_state_proven",
        "canonical_ancestry_proven",
        "runtime_clock_authenticated",
        "hidden_poh_hashes_recovered",
        "runtime_promotion_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v[key] == false, "raw acquisition acquired authority:{key}");
    }
    Ok(())
}
fn terminal() -> Result<Value> {
    let result=Command::new("/usr/bin/systemctl").args(["show",UNIT,"--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ActiveState,SubState,Type"]).output()?;
    ensure!(result.status.success(), "native terminal query failed");
    let fields: std::collections::BTreeMap<_, _> = std::str::from_utf8(&result.stdout)?
        .lines()
        .filter_map(|s| s.split_once('='))
        .collect();
    let v = json!(fields);
    for (key, expected) in [
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("Type", "exec"),
    ] {
        ensure!(v[key] == expected, "native terminal differs:{key}");
    }
    Ok(v)
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch141-first-target-byte-diagnostic-plan-v1"
            && p.acquisition
                == Bound {
                    path: RAW.into(),
                    sha256: RAW_SHA.into()
                }
            && p.finalized_target
                == Bound {
                    path: TARGET.into(),
                    sha256: TARGET_SHA.into()
                },
        "foreign diagnostic plan"
    );
    ensure!(
        p.output.file_name().is_some_and(|s| s == "diagnostic.json")
            && p.output.parent().is_some_and(|d| d.parent()
                == Some(Path::new("/var/lib/jetstreamer"))
                && d.file_name().is_some_and(|n| n
                    .to_string_lossy()
                    .starts_with("horizon-epoch141-first-target-byte-diagnostic-"))),
        "foreign output namespace"
    );
    Ok(())
}
fn prepare(p: &Plan) -> Result<Prepared> {
    validate_plan(p)?;
    let raw = read(&p.acquisition, true)?;
    validate_acquisition(&raw)?;
    let target = read(&p.finalized_target, false)?;
    ensure!(
        target["schema"] == "jetstreamer-epoch140-finalized-gap-target-v1"
            && target["metadata"]["slot"] == 60911776
            && target["metadata"]["parent_slot"] == 60911771
            && target["hidden_poh_hashes_recovered"] == false
            && target["replay_launch_authorized"] == false
            && target["publication_authorized"] == false
            && target["r2_mutations"] == false,
        "wrong independent finalized target"
    );
    for key in ["request", "response"] {
        let b: Bound = serde_json::from_value(target[key].clone())?;
        read(&b, false)?;
    }
    let hash = bs58::decode(
        target["metadata"]["final_poh_hash"]
            .as_str()
            .context("final hash")?,
    )
    .into_vec()
    .map_err(|e| anyhow::anyhow!("invalid finalized base58 hash:{e}"))?;
    let hash: [u8; 32] = hash
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong final hash length"))?;
    let first = decode(&raw["first_metadata"], 1)?;
    let records = decode(&raw["records"], 786)?;
    let parent = p.output.parent().unwrap();
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical output parent"
    );
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(parent)?;
    let m = dir.metadata()?;
    ensure!(
        m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "output parent not root-private"
    );
    Ok(Prepared {
        target,
        first,
        records,
        final_hash: hash,
    })
}
fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    let check = a.len() == 7 && a[6] == "--check-only";
    ensure!(
        (a.len() == 6 || check)
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: byte-diagnostic PLAN --plan-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&a[1]),
        &a[3],
        1 << 20,
        true,
    )?)?;
    let Prepared {
        target,
        first,
        records,
        final_hash: hash,
    } = prepare(&p)?;
    let owner = terminal()?;
    if check {
        println!(
            "first-target byte diagnostic inputs validated; no decode, PoH, writes or recovery"
        );
        return Ok(());
    }
    evidence::write_receipt(
        &p.output.parent().unwrap().join("intent.json"),
        &json!({"schema":"jetstreamer-epoch141-first-target-byte-diagnostic-intent-v1","plan":{"path":a[1],"sha256":a[3]},"tool_sha256":a[5],"acquisition":p.acquisition,"finalized_target":p.finalized_target,"native_terminal":owner,"recorded_is_connected":false,"poh_chain_verified":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
    let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
    let result = diagnose_v1_4_25_acquired_bytes(
        &first,
        LegacySlotScope {
            slot: 60911776,
            parent_slot: 60911771,
        },
        &records,
        hash,
    );
    ensure!(
        terminal()? == owner,
        "native terminal changed during diagnostic"
    );
    read(&p.acquisition, true)?;
    read(&p.finalized_target, false)?;
    let passed = result
        .as_ref()
        .is_ok_and(|r| r.final_entry_matches_finalized_hash);
    let (diagnostic, error) = match result {
        Ok(r) => (serde_json::to_value(r)?, Value::Null),
        Err(e) => (Value::Null, json!(e)),
    };
    evidence::write_receipt(
        &p.output,
        &json!({"schema":"jetstreamer-epoch141-first-target-byte-diagnostic-v1","epoch":141,"slot":60911776,"parent_slot":60911771,"plan":{"path":a[1],"sha256":a[3]},"tool_sha256":a[5],"acquisition":p.acquisition,"finalized_target":p.finalized_target,"native_terminal":owner,"diagnostic_passed":passed,"diagnostic":diagnostic,"decode_error":error,"expected_final_poh_hash":target["metadata"]["final_poh_hash"],"connected_recovery_route_changed":false,"recovered_target_count":0,"canonical_ancestry_proven":false,"source_completeness_proven":false,"runtime_clock_authenticated":false,"poh_chain_verified":false,"hidden_poh_hashes_recovered":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    File::open(p.output.parent().unwrap())?.sync_all()?;
    ensure!(
        passed,
        "byte diagnostic failed; preserved explicit result:{}",
        p.output.display()
    );
    println!("{}", p.output.display());
    Ok(())
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plan_cannot_read_other_raw_targets_or_write_public_outputs() {
        let p=Plan{schema:"jetstreamer-epoch141-first-target-byte-diagnostic-plan-v1".into(),acquisition:Bound{path:RAW.into(),sha256:RAW_SHA.into()},finalized_target:Bound{path:TARGET.into(),sha256:TARGET_SHA.into()},output:"/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-test/diagnostic.json".into()};
        validate_plan(&p).unwrap();
        let mut p = p;
        p.output = "/home/sol/horizon/epoch-141.jet".into();
        assert!(validate_plan(&p).is_err());
        p.output="/var/lib/jetstreamer/horizon-epoch141-first-target-byte-diagnostic-test/diagnostic.json".into();
        p.acquisition.sha256 = TARGET_SHA.into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    #[ignore = "explicit root read-only exact retained acquisition decode, no writes or native rerun"]
    fn retained_actual_first_target_byte_decode() {
        let raw = read(
            &Bound {
                path: RAW.into(),
                sha256: RAW_SHA.into(),
            },
            true,
        )
        .unwrap();
        validate_acquisition(&raw).unwrap();
        let target = read(
            &Bound {
                path: TARGET.into(),
                sha256: TARGET_SHA.into(),
            },
            false,
        )
        .unwrap();
        let hash: [u8; 32] = bs58::decode(target["metadata"]["final_poh_hash"].as_str().unwrap())
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let first = decode(&raw["first_metadata"], 1).unwrap();
        let records = decode(&raw["records"], 786).unwrap();
        let first: Vec<_> = first.iter().map(Owned::borrowed).collect();
        let records: Vec<_> = records.iter().map(Owned::borrowed).collect();
        let r = diagnose_v1_4_25_acquired_bytes(
            &first,
            LegacySlotScope {
                slot: 60911776,
                parent_slot: 60911771,
            },
            &records,
            hash,
        )
        .unwrap();
        println!("{}", serde_json::to_string(&r).unwrap());
        assert!(r.final_entry_matches_finalized_hash);
        assert!(!r.recorded_is_connected && !r.poh_chain_verified);
    }
}
