//! Fixed failed 223 generations: diagnostic byte custody, never replay checkpoints.
//! Share transport, full readback, restoration and retirement with Foundation holding.
use super::*;
use std::{collections::BTreeMap, sync::LazyLock};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    artifact: Artifact,
    pub root: PathBuf,
    pub relative_source: String,
    pub source_identity: Stamp,
    #[allow(dead_code)]
    allocated_bytes: u64,
    pub producer: String,
    invocation_id: String,
    lineage: Bound,
    raw_metadata: Bound,
    metadata_identity: Stamp,
}
static PROFILES: LazyLock<Vec<Profile>> = LazyLock::new(|| {
    serde_json::from_str(include_str!(
        "holding_foundation_private_partial223_profiles.json"
    ))
    .expect("compiled fixed 223 profiles")
});
pub(super) fn profile(a: Artifact) -> &'static Profile {
    PROFILES
        .iter()
        .find(|p| p.artifact == a)
        .expect("exact 223 partial role")
}
pub(super) fn applies(a: Artifact) -> bool {
    matches!(
        a,
        Artifact::Adaptive223 | Artifact::FullRoot223 | Artifact::PartialSingleton223
    )
}
pub(super) fn label(a: Artifact) -> &'static str {
    match a {
        Artifact::Adaptive223 => "adaptive-223",
        Artifact::FullRoot223 => "full-root-223",
        Artifact::PartialSingleton223 => "singleton-223",
        _ => unreachable!("exact 223 partial role"),
    }
}
pub(super) fn lineage_bindings(a: Artifact) -> Value {
    serde_json::to_value([&profile(a).lineage]).expect("fixed lineage serializes")
}
pub(super) fn closure_requirements(
    a: Artifact,
    units: &BTreeMap<String, String>,
    original: &[Bound],
) -> Result<()> {
    let p = profile(a);
    ensure!(
        units.get(&p.producer) == Some(&p.invocation_id),
        "223 original producer IID differs"
    );
    ensure!(
        original
            .iter()
            .filter(|b| b.path == p.lineage.path && b.sha256 == p.lineage.sha256)
            .count()
            == 1,
        "223 exact original failure lineage omitted or duplicated"
    );
    if a == Artifact::Adaptive223 {
        ensure!(
            units
                .get("horizon-controller-220-223-current-v1.service")
                .map(String::as_str)
                == Some("0b69b5009dc74bbda94b94d059a3daa7"),
            "223 original controller omitted"
        );
    }
    let peers: &[&str] = match a {
        Artifact::Adaptive223 => &[
            "jetstreamer-adaptive-reserve-220-223-current-v1.service",
            "jetstreamer-adaptive-reserve-220-223-current-v1.timer",
        ],
        _ => &[],
    };
    for unit in peers {
        ensure!(
            units.contains_key(*unit),
            "223 original protective owner omitted: {unit}"
        );
    }
    Ok(())
}
fn lineage_shape(a: Artifact, v: &Value) -> Result<()> {
    let p = profile(a);
    let e = &p.source_identity;
    match a {
        Artifact::Adaptive223 => {
            ensure!(
                v["schema"] == "jetstreamer-private-archive-capacity-incident-v1"
                    && v["producer_unit"] == p.producer
                    && v["producer_invocation_id"] == p.invocation_id
                    && v["terminal_state"]["active_state"] == "failed"
                    && v["terminal_state"]["main_pid"] == 0
                    && v["terminal_state"]["restarts"] == 0
                    && v["terminal_state"]["exit_status"] == 1
                    && v["controller_quarantined"] == true
                    && v["artifact_cleanup_authorized"] == false,
                "223 adaptive original failure shape differs"
            );
            let rows = v["artifacts"]
                .as_array()
                .context("223 preserved incident artifacts")?;
            ensure!(
                rows.iter()
                    .filter(|r| r["epoch"] == 223
                        && r["device"] == e.device
                        && r["inode"] == e.inode
                        && r["bytes"] == e.length)
                    .count()
                    == 1,
                "223 adaptive lineage does not preserve this exact partial"
            );
            ensure!(
                v["artifact_root"].as_str()
                    == a.source().parent().unwrap().parent().unwrap().to_str(),
                "223 adaptive original run changed"
            );
        }
        Artifact::FullRoot223 => {
            ensure!(
                v["schema"] == "jetstreamer-horizon-open-epoch-repair-v1"
                    && v["epoch"] == 223
                    && v["unit"] == p.producer
                    && v["invocation_id"] == p.invocation_id
                    && v["failure"]["terminal_exit_status"] == 1
                    && v["repaired"] == false
                    && v["retained_artifacts"]["partial_archive"].as_str() == a.source().to_str()
                    && v["retained_artifacts"]["observed_size_bytes"] == e.length
                    && v["retained_artifacts"]["body_hashed"] == false
                    && v["retained_artifacts"]["qualified"] == false
                    && v["retained_artifacts"]["receipt_archive_length_field"] == 0,
                "223 full-root original failure/inventory discrepancy must remain preserved"
            );
        }
        Artifact::PartialSingleton223 => {
            ensure!(
                v["schema"] == "jetstreamer-horizon-open-epoch-repair-v1"
                    && v["epoch"] == 223
                    && v["producer_unit"] == p.producer
                    && v["producer_invocation_id"] == p.invocation_id
                    && v["exec_main_status"] == 1
                    && v["restarts"] == 0
                    && v["automatic_restart"] == false
                    && v["guard_timer_stopped"] == true
                    && v["scratch_retirement_authorized"] == false
                    && v["retained_partial"].as_str() == a.source().to_str(),
                "223 singleton original failed generation differs"
            );
        }
        _ => bail!("foreign 223 partial"),
    }
    ensure!(
        v["publication_authorized"] == false && v["r2_mutations"] == false,
        "223 historical failure cannot authorize publication"
    );
    Ok(())
}
pub(super) fn preservation(a: Artifact) -> Result<()> {
    lineage_shape(a, &saved(&profile(a).lineage)?)
}
fn metadata_value(a: Artifact, raw: &[u8]) -> Value {
    let p = profile(a);
    json!([{"name":p.raw_metadata.path.file_name().unwrap().to_str().unwrap(),
        "source_path":p.raw_metadata.path,"sha256":p.raw_metadata.sha256,"length":raw.len(),
        "source_identity":p.metadata_identity,"uid":p.metadata_identity.uid,"gid":p.metadata_identity.gid,
        "mode":p.metadata_identity.mode,"raw_base64":BASE64_STANDARD.encode(raw)}])
}
pub(super) fn validate_metadata(a: Artifact, value: &Value) -> Result<()> {
    let rows = value.as_array().context("223 raw metadata array absent")?;
    ensure!(rows.len() == 1, "223 exact original metadata is required");
    let raw = BASE64_STANDARD.decode(
        rows[0]["raw_base64"]
            .as_str()
            .context("223 raw metadata absent")?,
    )?;
    let p = profile(a);
    ensure!(
        raw.len() as u64 == p.metadata_identity.length
            && hex_lower(&Sha256::digest(&raw)) == p.raw_metadata.sha256
            && *value == metadata_value(a, &raw),
        "223 raw metadata normalized or substituted"
    );
    Ok(())
}
pub(super) fn metadata(a: Artifact) -> Result<Value> {
    preservation(a)?;
    for suffix in [".sha256", ".segment.json"] {
        ensure!(
            retirement::absent(&PathBuf::from(format!("{}{suffix}", a.source().display())))?,
            "223 partial gained a sidecar/segment role"
        );
    }
    let p = profile(a);
    let m = fs::symlink_metadata(&p.raw_metadata.path)?;
    ensure!(
        p.raw_metadata.path.canonicalize()? == p.raw_metadata.path
            && m.is_file()
            && Stamp::of(&m) == p.metadata_identity,
        "223 original metadata identity changed"
    );
    let raw = read_stable_bounded(
        &p.raw_metadata.path,
        MAX_METADATA,
        "223 raw original metadata",
    )?;
    ensure!(
        Stamp::of(&fs::symlink_metadata(&p.raw_metadata.path)?) == p.metadata_identity,
        "223 original metadata changed during read"
    );
    let value = metadata_value(a, &raw);
    validate_metadata(a, &value)?;
    Ok(value)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspect {
    schema: String,
    artifact: Artifact,
    mapping: Bound,
    closure: Bound,
}
pub(super) fn inspect(v: Value, spec: &Bound) -> Result<()> {
    let p: Inspect = serde_json::from_value(v)?;
    ensure!(
        p.schema == "jetstreamer-partial223-native-inspect-plan-v1" && applies(p.artifact),
        "foreign 223 inspection plan"
    );
    let a = p.artifact;
    mapping(&p.mapping)?;
    let entry = clock()?;
    let before = closure::inspect(a, &p.closure, entry, true)?;
    let id = source(a)?;
    let raw = metadata(a)?;
    eprintln!(
        "{}",
        json!({"event":"partial223-native-hash-start","artifact":a,"bytes":id.length})
    );
    let proof = hash_and_etag(&a.source(), id, DEFAULT_PART_SIZE)?;
    ensure!(
        source(a)? == id && metadata(a)? == raw,
        "223 source or metadata changed during hash"
    );
    let after = closure::inspect(a, &p.closure, entry, true)?;
    let iid = env::var("INVOCATION_ID").context("223 inspection requires native invocation")?;
    let tool_sha = env::args()
        .nth(6)
        .context("223 independent executable pin absent")?;
    let value = json!({"schema":"jetstreamer-partial223-native-inspection-v1","artifact":a,
        "source":a.source(),"source_identity":a.expected(),"length":id.length,
        "sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag,"multipart_part_size":DEFAULT_PART_SIZE,
        "native_inspection_invocation_id":iid,"native_inspection_pid":std::process::id(),"tool_sha256":tool_sha,
        "inspection_spec":spec,"lineage":lineage_bindings(a),"raw_metadata":raw,
        "closure_before":before,"closure_after":after,"complete_stable_sha256_verified":true,
        "recorded_unix_seconds":clock()?,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,
        "boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
    inspection_shape(a, &value, &proof.sha256_hex)?;
    let name = format!("inspection-{}-{}.json", label(a), spec.sha256);
    let output = Path::new(STATE).join("receipts").join(&name);
    if !retirement::absent(&output)? {
        let bytes = read_stable_bounded(&output, 8 << 20, "223 prior inspection")?;
        let old = saved(&Bound {
            path: output.clone(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        })?;
        inspection_shape(a, &old, &proof.sha256_hex)?;
        ensure!(
            old["inspection_spec"] == serde_json::to_value(spec)? && old["raw_metadata"] == raw,
            "223 prior native inspection conflicts with exact spec/metadata"
        );
        println!("{}", output.display());
    } else {
        println!("{}", receipt(&name, &value)?.display());
    }
    Ok(())
}
fn inspection_shape(a: Artifact, v: &Value, sha: &str) -> Result<()> {
    ensure!(
        applies(a)
            && digest(sha)
            && sha != "0".repeat(64)
            && v["schema"] == "jetstreamer-partial223-native-inspection-v1"
            && v["artifact"] == serde_json::to_value(a)?
            && v["source"].as_str() == a.source().to_str()
            && v["source_identity"] == serde_json::to_value(a.expected())?
            && v["length"] == a.expected().length
            && v["sha256"] == sha
            && v["lineage"] == lineage_bindings(a)
            && v["complete_stable_sha256_verified"] == true
            && v["multipart_part_size"] == DEFAULT_PART_SIZE
            && v["multipart_etag"].as_str().is_some_and(|s| !s.is_empty())
            && v["native_inspection_invocation_id"]
                .as_str()
                .is_some_and(|s| s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            && v["native_inspection_pid"].as_u64().is_some_and(|n| n > 0)
            && v["tool_sha256"].as_str().is_some_and(digest)
            && v["recorded_unix_seconds"].as_u64().is_some()
            && v["local_retirement_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "223 inspection lacks exact stable native digest provenance"
    );
    no_promotion(v)?;
    validate_metadata(a, &v["raw_metadata"])?;
    for phase in ["closure_before", "closure_after"] {
        ensure!(
            v[phase]["source_identity_checked"] == true
                && v[phase]["maps_and_fds_device_inode_checked"] == true
                && v[phase]["local_retirement_authorized"] == false,
            "223 inspection omitted closed-owner/reference proof"
        );
    }
    Ok(())
}
fn pinned(a: Artifact, b: &Bound, sha: &str) -> Result<Value> {
    let v = saved(b)?;
    inspection_shape(a, &v, sha)?;
    let spec: Bound = serde_json::from_value(v["inspection_spec"].clone())?;
    ensure!(
        digest(&spec.sha256)
            && b.path
                == Path::new(STATE).join("receipts").join(format!(
                    "inspection-{}-{}.json",
                    label(a),
                    spec.sha256
                )),
        "223 foreign inspection receipt role"
    );
    let input: Inspect = serde_json::from_value(saved(&spec)?)?;
    ensure!(
        input.schema == "jetstreamer-partial223-native-inspect-plan-v1"
            && input.artifact == a
            && v["closure_before"]["closure"] == serde_json::to_value(&input.closure)?
            && v["closure_after"]["closure"] == serde_json::to_value(&input.closure)?,
        "223 inspection is not bound to its actual original input/closure"
    );
    mapping(&input.mapping)?;
    preservation(a)?;
    Ok(v)
}
pub(super) fn park_digest(p: &ParkSpec) -> Result<()> {
    pinned(
        p.artifact,
        p.inspection
            .as_ref()
            .context("223 park requires pinned native inspection")?,
        &p.sha256,
    )?;
    Ok(())
}
pub(super) fn manifest(v: &Value, a: Artifact, sha: &str) -> Result<()> {
    ensure!(
        v["partial223_lineage"] == lineage_bindings(a),
        "223 manifest changed original failed lineage"
    );
    let b: Bound = serde_json::from_value(v["partial223_inspection"].clone())?;
    ensure!(
        pinned(a, &b, sha)?["raw_metadata"] == v["raw_metadata"],
        "223 manifest original metadata differs from native inspection"
    );
    validate_metadata(a, &v["raw_metadata"])
}

#[cfg(test)]
#[path = "holding_foundation_private_partial223_tests.rs"]
mod tests;
