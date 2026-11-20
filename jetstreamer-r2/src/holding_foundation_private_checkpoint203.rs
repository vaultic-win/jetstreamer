//! One closed full203 duplicate. This is byte custody, never replay authority.
use super::*;
use std::collections::BTreeMap;

pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-203-ed66145-v1";
pub(super) const RELATIVE_SOURCE: &str = "output/epoch-203-checkpoint-restart-v4.jet";
pub(super) const PRODUCER: &str = "horizon-qualify-203-checkpoint-continuation-ed66145-v1.service";
const IID: &str = "ddf3ed2de8b040758ee7a0d696159afd";
pub(super) const SHA: &str = "7efb3b28b2761cd646d20fa282d87c508249488fd0fb27ce8e033a1aed7d39ad";
const LAUNCH: &str =
    "/var/lib/jetstreamer/horizon-continuation203-launch-state-ed66145-v1/launch.json";
const LAUNCH_SHA: &str = "1068823c4c8f71ff78752e7319a2ff3f38c2f82c12c68df0030c98eaae7eb1f0";
const OUTCOME: &str =
    "/var/lib/jetstreamer/horizon-private203-verify-scan-admission-v1/continuation.json";
const OUTCOME_SHA: &str = "54272a673df64a2facf4c571332c7a10130231fba8c22ab17e122a31d6be1545";
// The genuine original is root-owned mode0600. Main must authenticate it and
// Rust-seal these exact bytes here before any native operation. Do not relax
// the shared sealed-evidence reader or treat a copied fixture as a new event.
const ORIGINAL_VERIFICATION: &str =
    "/var/lib/jetstreamer/horizon-203-private-scan-20261023-v1/verification.json";
const VERIFICATION: &str =
    "/var/lib/jetstreamer/horizon-checkpoint203-holding-lineage-v1/verification.json";
const VERIFICATION_SHA: &str = "0217aaeacae219a0808fadf9182b10859ff53a7b4411ccfacc31005c6942dc1b";
const VERIFICATION_BYTES: usize = 4884;

fn fixed(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn bindings() -> [Bound; 3] {
    [
        fixed(LAUNCH, LAUNCH_SHA),
        fixed(OUTCOME, OUTCOME_SHA),
        fixed(VERIFICATION, VERIFICATION_SHA),
    ]
}
pub(super) fn lineage_bindings() -> Value {
    json!({"original_verification":fixed(ORIGINAL_VERIFICATION,VERIFICATION_SHA),"sealed_evidence":bindings()})
}
pub(super) fn closure_requirements(
    units: &BTreeMap<String, String>,
    original: &[Bound],
) -> Result<()> {
    ensure!(
        units.get(PRODUCER).map(String::as_str) == Some(IID),
        "checkpoint203 original producer IID differs"
    );
    for b in bindings() {
        ensure!(
            original
                .iter()
                .filter(|v| v.path == b.path && v.sha256 == b.sha256)
                .count()
                == 1,
            "checkpoint203 exact original lineage missing or duplicated"
        );
    }
    Ok(())
}
fn lineage_shape(launch: &Value, outcome: &Value, verification: &Value) -> Result<()> {
    let a = Artifact::Checkpoint203;
    let source = a.source();
    let e = a.expected();
    let i = &verification["source_identity"];
    ensure!(
        launch["schema"] == "jetstreamer-private-epoch203-checkpoint-continuation-launch-v1"
            && launch["unit"] == PRODUCER
            && launch["invocation_id"] == IID
            && launch["private_run_root"] == ROOT
            && launch["epoch"] == 203
            && launch["launched"] == true
            && launch["local_retirement_authorized"] == false
            && outcome["schema"] == "jetstreamer-private-epoch203-checkpoint-continuation-v1"
            && outcome["producer_unit"] == PRODUCER
            && outcome["producer_invocation_id"] == IID
            && outcome["private_output"].as_str() == source.to_str()
            && verification["schema"] == "jetstreamer-private-epoch203-verification-v1"
            && verification["source_path"].as_str() == source.to_str()
            && verification["archive_sha256"] == SHA
            && verification["independent_final_archive_verification_passed"] == true
            && verification["current_plugin_verification_passed"] == true
            && verification["producer_outcome"]
                == serde_json::to_value(fixed(OUTCOME, OUTCOME_SHA))?
            && verification["producer_terminal"]["journal"]["invocation_id"] == IID
            && i["dev"] == e.device
            && i["ino"] == e.inode
            && i["len"] == e.length
            && i["uid"] == e.uid
            && i["gid"] == e.gid
            && i["links"] == 1
            && i["mode"] == (libc::S_IFREG | e.mode)
            && i["mtime"] == 1792746849
            && i["mtime_ns"] == 936499204
            && i["ctime"] == 1792746849
            && i["ctime_ns"] == 936499204,
        "checkpoint203 exact producer/full-duplicate lineage differs"
    );
    for v in [launch, outcome, verification] {
        ensure!(
            v["publication_authorized"] == false && v["canonical_sidecar_authorized"] == false,
            "checkpoint203 preservation evidence grants unexpected publication authority"
        );
    }
    ensure!(
        outcome["retirement_authorized"] == false && verification["retirement_authorized"] == false,
        "checkpoint203 original evidence cannot authorize this retirement"
    );
    Ok(())
}
pub(super) fn preservation() -> Result<()> {
    let b = bindings();
    lineage_shape(&saved(&b[0])?, &saved(&b[1])?, &saved(&b[2])?)
}
fn metadata_value(raw: &[u8]) -> Value {
    json!([{"name":"checkpoint203-verification.json","source":fixed(VERIFICATION,VERIFICATION_SHA),
        "sha256":VERIFICATION_SHA,"length":raw.len(),"uid":0,"gid":0,"mode":0o444,
        "raw_base64":BASE64_STANDARD.encode(raw)}])
}
pub(super) fn metadata() -> Result<Value> {
    preservation()?;
    let m = fs::symlink_metadata(VERIFICATION)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o444
            && m.len() == VERIFICATION_BYTES as u64,
        "checkpoint203 verification must be the exact readonly Root-sealed metadata role"
    );
    for suffix in [".sha256", ".segment.json"] {
        ensure!(
            retirement::absent(&PathBuf::from(format!(
                "{}{suffix}",
                Artifact::Checkpoint203.source().display()
            )))?,
            "checkpoint203 duplicate unexpectedly gained source sidecar/segment metadata"
        );
    }
    let raw = read_stable_bounded(
        Path::new(VERIFICATION),
        8192,
        "sealed checkpoint203 verification bytes",
    )?;
    let value = metadata_value(&raw);
    validate_metadata(&value)?;
    Ok(value)
}
pub(super) fn validate_metadata(value: &Value) -> Result<()> {
    let rows = value
        .as_array()
        .context("checkpoint203 raw verification metadata absent")?;
    ensure!(
        rows.len() == 1,
        "checkpoint203 requires exactly its genuine verification bytes"
    );
    let row = &rows[0];
    let raw = BASE64_STANDARD.decode(
        row["raw_base64"]
            .as_str()
            .context("checkpoint203 raw bytes absent")?,
    )?;
    ensure!(
        row["name"] == "checkpoint203-verification.json"
            && row["source"] == serde_json::to_value(fixed(VERIFICATION, VERIFICATION_SHA))?
            && row["sha256"] == VERIFICATION_SHA
            && row["length"] == VERIFICATION_BYTES
            && raw.len() == VERIFICATION_BYTES
            && hex_lower(&Sha256::digest(&raw)) == VERIFICATION_SHA
            && row["uid"] == 0
            && row["gid"] == 0
            && row["mode"] == 0o444,
        "checkpoint203 verification bytes/role were substituted or normalized"
    );
    Ok(())
}
pub(super) fn manifest(value: &Value) -> Result<()> {
    ensure!(
        value["checkpoint203_lineage"] == lineage_bindings(),
        "checkpoint203 manifest lineage changed"
    );
    preservation()?;
    validate_metadata(&value["raw_metadata"])
}

#[cfg(test)]
#[path = "holding_foundation_private_checkpoint203_tests.rs"]
mod tests;
