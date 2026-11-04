//! Shared immutable first-target input bindings; no decoding trust or writes.
use super::evidence;
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use jetstreamer_utils::horizon_legacy_recovery::ResolvedLegacyRecord;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{path::PathBuf, process::Command};
pub(super) const RAW: &str = "/usr/local/lib/jetstreamer/horizon-repair-control-20261022-v144/epoch141-first-target-acquisition.json";
pub(super) const RAW_SHA: &str = "785b52de7a18e7ca864af4c0ad234553bc16da829c7115ef798c284abab68e3b";
pub(super) const TARGET: &str =
    "/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/targets/target-60911776.json";
pub(super) const TARGET_SHA: &str =
    "3103bc3180eb4b6661cc541c748445c7b668d6837877ec034119177552f72c8d";
const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service";
const IID: &str = "ae452cc022d84d6594baf6730de9e5a7";
#[derive(Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct Bound {
    pub(super) path: PathBuf,
    pub(super) sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Encoded {
    family: String,
    key_base64: String,
    value_base64: Option<String>,
}
pub(super) struct Owned {
    family: String,
    key: Vec<u8>,
    value: Option<Vec<u8>>,
}
impl Owned {
    pub(super) fn borrowed(&self) -> ResolvedLegacyRecord<'_> {
        ResolvedLegacyRecord {
            family: &self.family,
            key: &self.key,
            value: self.value.as_deref(),
        }
    }
}
pub(super) fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
pub(super) fn decode(records: &Value, expected: usize) -> Result<Vec<Owned>> {
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
pub(super) fn validate_acquisition(v: &Value) -> Result<()> {
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
pub(super) fn terminal() -> Result<Value> {
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
