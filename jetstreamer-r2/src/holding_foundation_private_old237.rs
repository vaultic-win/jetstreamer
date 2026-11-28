//! Exact stopped v2 epoch 237 partial; a native full hash must be pinned first.
//! No old v1 lineage, canonical sidecar, runtime checkpoint or replay authority.
use super::*;
use std::collections::BTreeMap;

pub(super) const ROOT: &str =
    "/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-budget620-v2";
pub(super) const RELATIVE_SOURCE: &str = "state/destination-8c7367f2f955a823f78f02aa3e05000b22d3fdc277987e9f22b4fa5da9a5556d/work/root-cohort-237-237/run-2030542-1793568723686999262/archives/epoch-237.jet";
pub(super) const PRODUCER: &str = "horizon-qualify-237-general-target1-budget620-v2.service";
const PRODUCER_IID: &str = "3949b88a4ca34fc892a19f219cebd476";
const GUARD: &str = "horizon-237-budget620-protective-v2.service";
const GUARD_IID: &str = "ae3518f8f8864d90bd08c99d9b414a34";
const TIMER: &str = "horizon-237-budget620-protective-v2.timer";
const ACCEPTANCE: &str =
    "/var/lib/jetstreamer/horizon237-main-retirement-acceptance795-v1/acceptance.json";
const ACCEPTANCE_SHA: &str = "1037a35310bfba486c758c4208ce493aaf3bb3c6d434fad7c7d3e76fe3688763";
const COMPLETION: &str =
    "/var/lib/jetstreamer/horizon237-stopped-scratch-retirement-v1/completion.json";
const COMPLETION_SHA: &str = "ba99bad31a509640dcc548a782063514c3b7db910709949918f439dd41a920e4";
const REVIEW: &str =
    "/var/lib/jetstreamer/horizon237-bootstrap-restart-review-main787-v1/review.json";
const REVIEW_SHA: &str = "0d6734990a42b0b9debbee359b4a1aa875b05a4859637b2ed08ed62be782effb";
const STOP: &str = "/var/lib/jetstreamer/horizon-237-budget620-guard-receipts-v2/stop-intent.json";
const STOP_SHA: &str = "b441c23133ab8656d39a2ddc069e56ae6873251e838837dc029ce1c0f1acfd3d";
const STATE_SHA: &str = "4316367f69e54c02157df2c97129250027184f79d51a30d9bdae9b9a884d5029";

fn fixed(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn bindings() -> [Bound; 4] {
    [
        fixed(ACCEPTANCE, ACCEPTANCE_SHA),
        fixed(COMPLETION, COMPLETION_SHA),
        fixed(REVIEW, REVIEW_SHA),
        fixed(STOP, STOP_SHA),
    ]
}
pub(super) fn lineage_bindings() -> Value {
    serde_json::to_value(bindings()).expect("fixed old237 lineage serializes")
}
fn run() -> PathBuf {
    Artifact::OldV2237
        .source()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
pub(super) fn closure_requirements(
    units: &BTreeMap<String, String>,
    original: &[Bound],
) -> Result<()> {
    ensure!(
        units.get(PRODUCER).map(String::as_str) == Some(PRODUCER_IID)
            && units.get(GUARD).map(String::as_str) == Some(GUARD_IID)
            && units.get(TIMER).is_some_and(String::is_empty),
        "old v2 237 requires its exact original producer, preserved failed guard and closed timer"
    );
    for required in bindings() {
        ensure!(
            original
                .iter()
                .filter(|b| b.path == required.path && b.sha256 == required.sha256)
                .count()
                == 1,
            "old v2 237 accepted preservation/producer provenance is missing or duplicated"
        );
    }
    Ok(())
}
fn lineage_shape(a: &Value, c: &Value, r: &Value, s: &Value) -> Result<()> {
    let source = Artifact::OldV2237.source();
    let expected = Artifact::OldV2237.expected();
    let p = &c["common"]["preserved"]["partial_archive"];
    let i = &p["identity"];
    let state = &c["common"]["preserved"]["cohort_state"];
    ensure!(
        a["schema"] == "horizon237-main-exact-scratch-retirement-acceptance795-v1"
            && a["completion"] == serde_json::to_value(fixed(COMPLETION, COMPLETION_SHA))?
            && a["scratch_deleted"] == true
            && a["native_terminal_exit_status"] == 0
            && a["zero_restarts"] == true
            && a["preserved_partial_bytes"] == expected.length
            && a["retained_inputs_and_partial_identity_match_actual_check_exactly"] == true
            && a["scope_sha256"]
                == "32dd2ea5b114b9a4fd4ff0bb781ee5364c6876a3f6d3ea9c6325dec3e879e850"
            && a["scope_sha256"] == c["common"]["scope_sha256"]
            && c["schema"] == "jetstreamer-stopped237-scratch-completion-v1"
            && c["scratch_deleted"] == true
            && c["common"]["epoch"] == 237
            && c["common"]["target"] == run().join("scratch").to_str().unwrap()
            && c["common"]["tool_sha256"]
                == "43f2cb3c2c58bcf97fb30f4a0c459b20aeadad72b9e05a5aca449883a1acd27c"
            && c["common"]["archive_deletion_authorized"] == false
            && p["path"].as_str() == source.to_str()
            && p["full_digest_claimed"] == false
            && i["device"] == expected.device
            && i["inode"] == expected.inode
            && i["bytes"] == expected.length
            && i["uid"] == expected.uid
            && i["gid"] == expected.gid
            && i["mode"] == (libc::S_IFREG | expected.mode)
            && i["links"] == 1
            && i["mtime_seconds"] == 1793716861
            && i["mtime_nanoseconds"] == 385301224
            && i["ctime_seconds"] == 1793716861
            && i["ctime_nanoseconds"] == 385301224
            && state["path"].as_str() == run().join("cohort-state.json").to_str()
            && state["device"] == 66305
            && state["inode"] == 13547609
            && state["bytes"] == 222
            && state["sha256"] == STATE_SHA,
        "old v2 237 Source11 retirement/preservation does not bind the exact retained partial"
    );
    ensure!(
        r["schema"] == "jetstreamer-stopped237-bootstrap-restart-review-v1"
            && r["producer_invocation_id"] == PRODUCER_IID
            && r["original_producer_pid"] == 2030542
            && r["run_directory"].as_str() == run().to_str()
            && r["cohort_state_sha256"] == STATE_SHA
            && r["scratch_contains_replay_cursor"] == false
            && r["preserve_partial_archive_and_inputs"] == true
            && r["node_sha256"]
                == "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1"
            && r["worker_sha256"]
                == "88581898fb68efa52bbb2415eeb0c229c68d32cd36ee40d124c87761ba2b7486"
            && s["producer_invocation_id"] == PRODUCER_IID
            && s["sample"]["producer"]["invocation_id"] == PRODUCER_IID
            && s["sample"]["producer"]["pid"] == 2030542
            && s["sample"]["producer"]["cgroup"] == format!("/system.slice/{PRODUCER}"),
        "old v2 237 original producer/runtime lineage differs"
    );
    Ok(())
}
pub(super) fn preservation() -> Result<()> {
    let b = bindings();
    lineage_shape(
        &saved(&b[0])?,
        &saved(&b[1])?,
        &saved(&b[2])?,
        &saved(&b[3])?,
    )?;
    ensure!(
        retirement::absent(&run().join("scratch"))?,
        "old v2 237 scratch reappeared"
    );
    Ok(())
}
pub(super) fn metadata() -> Result<Value> {
    preservation()?;
    for suffix in [".sha256", ".segment.json"] {
        ensure!(
            retirement::absent(&PathBuf::from(format!(
                "{}{suffix}",
                Artifact::OldV2237.source().display()
            )))?,
            "old v2 237 partial unexpectedly gained archive sidecar/segment metadata"
        );
    }
    let path = run().join("cohort-state.json");
    let before = regular_identity(&path)?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.dev() == 66305
            && m.ino() == 13547609
            && m.uid() == 1000
            && m.gid() == 1000
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600
            && m.len() == 222,
        "old v2 237 retained cohort metadata identity differs"
    );
    let raw = read_stable_bounded(&path, 4096, "old v2 237 retained cohort metadata")?;
    ensure!(
        regular_identity(&path)? == before,
        "old v2 237 cohort metadata changed"
    );
    let value = json!([{"name":"cohort-state.json","device":66305,"inode":13547609,"length":raw.len(),"sha256":hex_lower(&Sha256::digest(&raw)),
        "uid":1000,"gid":1000,"mode":0o600,"raw_base64":BASE64_STANDARD.encode(raw)}]);
    validate_metadata(&value)?;
    Ok(value)
}
pub(super) fn validate_metadata(v: &Value) -> Result<()> {
    let rows = v.as_array().context("old v2 237 metadata array absent")?;
    ensure!(
        rows.len() == 1,
        "old v2 237 requires exactly its original cohort metadata"
    );
    let row = &rows[0];
    let raw = BASE64_STANDARD.decode(
        row["raw_base64"]
            .as_str()
            .context("old v2 237 metadata raw bytes absent")?,
    )?;
    ensure!(
        row["name"] == "cohort-state.json"
            && row["device"] == 66305
            && row["inode"] == 13547609
            && row["length"] == 222
            && raw.len() == 222
            && row["sha256"] == STATE_SHA
            && hex_lower(&Sha256::digest(&raw)) == STATE_SHA
            && row["uid"] == 1000
            && row["gid"] == 1000
            && row["mode"] == 0o600,
        "old v2 237 cohort metadata was substituted or normalized"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspect {
    schema: String,
    mapping: Bound,
    closure: Bound,
}
pub(super) fn inspect(v: Value, spec: &Bound) -> Result<()> {
    let p: Inspect = serde_json::from_value(v)?;
    ensure!(
        p.schema == "jetstreamer-old-v2-237-native-inspect-plan-v1",
        "foreign old v2 237 inspection plan"
    );
    mapping(&p.mapping)?;
    let entry = clock()?;
    let before = closure::inspect(Artifact::OldV2237, &p.closure, entry, true)?;
    let id = source(Artifact::OldV2237)?;
    let raw = metadata()?;
    eprintln!(
        "{}",
        json!({"event":"old-v2-237-native-hash-start","bytes":id.length})
    );
    let proof = hash_and_etag(&Artifact::OldV2237.source(), id, DEFAULT_PART_SIZE)?;
    ensure!(
        digest(&proof.sha256_hex)
            && proof.sha256_hex != "0".repeat(64)
            && source(Artifact::OldV2237)? == id
            && metadata()? == raw,
        "old v2 237 complete hash or stable source/metadata check failed"
    );
    let after = closure::inspect(Artifact::OldV2237, &p.closure, entry, true)?;
    let iid = env::var("INVOCATION_ID")
        .context("old v2 237 inspection requires an admitted native invocation")?;
    let tool_sha = env::args()
        .nth(6)
        .context("old v2 237 independent executable pin absent")?;
    ensure!(
        iid.len() == 32
            && iid
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            && digest(&tool_sha),
        "old v2 237 native inspection identity malformed"
    );
    let output = Path::new(STATE)
        .join("receipts")
        .join(format!("inspection-old-v2-237-{}.json", spec.sha256));
    if !retirement::absent(&output)? {
        // Receipt recovery keeps the original successful invocation and clock.
        // A fresh full body hash and closure have still just been checked.
        let bytes = read_stable_bounded(&output, 8 << 20, "old v2 237 prior inspection")?;
        let old = saved(&Bound {
            path: output.clone(),
            sha256: hex_lower(&Sha256::digest(&bytes)),
        })?;
        inspection_shape(&old, &proof.sha256_hex)?;
        ensure!(
            old["inspection_spec"] == serde_json::to_value(spec)? && old["raw_metadata"] == raw,
            "old v2 237 prior inspection conflicts with the current exact spec/metadata"
        );
        println!("{}", output.display());
        return Ok(());
    }
    let value = json!({"schema":"jetstreamer-old-v2-237-native-inspection-v1","artifact":"old-v2-237",
        "source":Artifact::OldV2237.source(),"source_identity":Artifact::OldV2237.expected(),"length":id.length,
        "sha256":proof.sha256_hex,"multipart_etag":proof.multipart_etag,"multipart_part_size":DEFAULT_PART_SIZE,
        "native_inspection_invocation_id":iid,"native_inspection_pid":std::process::id(),"tool_sha256":tool_sha,
        "inspection_spec":spec,"lineage":lineage_bindings(),"raw_metadata":raw,
        "closure_before":before,"closure_after":after,"complete_stable_sha256_verified":true,
        "recorded_unix_seconds":clock()?,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "canonical_archive":false,"canonical_publication_authorized":false,"full_plugin_qualified":false,
        "boundary_qualified":false,"runtime_checkpoint_qualified":false,"job_resume_authorized":false,"replay_launch_authorized":false});
    inspection_shape(&value, value["sha256"].as_str().unwrap())?;
    println!(
        "{}",
        receipt(
            &format!("inspection-old-v2-237-{}.json", spec.sha256),
            &value
        )?
        .display()
    );
    Ok(())
}
fn inspection_shape(v: &Value, sha: &str) -> Result<()> {
    ensure!(
        digest(sha)
            && sha != "0".repeat(64)
            && v["schema"] == "jetstreamer-old-v2-237-native-inspection-v1"
            && v["artifact"] == "old-v2-237"
            && v["source"].as_str() == Artifact::OldV2237.source().to_str()
            && v["source_identity"] == serde_json::to_value(Artifact::OldV2237.expected())?
            && v["length"] == Artifact::OldV2237.expected().length
            && v["sha256"] == sha
            && v["lineage"] == lineage_bindings()
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
        "old v2 237 inspection does not pin a complete stable native digest"
    );
    no_promotion(v)?;
    validate_metadata(&v["raw_metadata"])?;
    for phase in ["closure_before", "closure_after"] {
        ensure!(
            v[phase]["source_identity_checked"] == true
                && v[phase]["maps_and_fds_device_inode_checked"] == true
                && v[phase]["local_retirement_authorized"] == false,
            "old v2 237 inspection omitted closed-owner/reference evidence"
        );
    }
    Ok(())
}

#[cfg(test)]
#[path = "holding_foundation_private_old237_tests.rs"]
mod tests;
fn pinned(b: &Bound, sha: &str) -> Result<Value> {
    let v = saved(b)?;
    inspection_shape(&v, sha)?;
    let spec: Bound = serde_json::from_value(v["inspection_spec"].clone())?;
    ensure!(
        digest(&spec.sha256)
            && b.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("inspection-old-v2-237-{}.json", spec.sha256)),
        "old v2 237 inspection has a foreign receipt role"
    );
    let input: Inspect = serde_json::from_value(saved(&spec)?)?;
    ensure!(
        input.schema == "jetstreamer-old-v2-237-native-inspect-plan-v1"
            && v["closure_before"]["closure"] == serde_json::to_value(&input.closure)?
            && v["closure_after"]["closure"] == serde_json::to_value(&input.closure)?,
        "old v2 237 inspection is not bound to its actual original input/closure"
    );
    mapping(&input.mapping)?;
    preservation()?;
    Ok(v)
}
pub(super) fn park_digest(p: &ParkSpec) -> Result<()> {
    if partial223::applies(p.artifact) { return partial223::park_digest(p); }
    if p.artifact == Artifact::OldV2237 {
        pinned(
            p.inspection
                .as_ref()
                .context("old v2 237 park requires its pinned native inspection")?,
            &p.sha256,
        )?;
    } else {
        ensure!(
            p.sha256 == p.artifact.sha() && p.inspection.is_none(),
            "foreign original private digest/inspection"
        );
    }
    Ok(())
}
pub(super) fn manifest_inspection(v: &Value, sha: &str) -> Result<()> {
    ensure!(
        v["old_v2_237_preservation"] == lineage_bindings(),
        "old v2 237 manifest changed preservation lineage"
    );
    let b: Bound = serde_json::from_value(v["old_v2_237_inspection"].clone())?;
    let inspection = pinned(&b, sha)?;
    ensure!(
        inspection["raw_metadata"] == v["raw_metadata"],
        "old v2 237 manifest metadata differs from inspected bytes"
    );
    Ok(())
}
fn check_scope(v: &Value) -> Value {
    let mut v = v.clone();
    let failed234 = v["artifact"] == "failed-v5-234";
    let partial223 = matches!(v["artifact"].as_str(), Some("adaptive-223" | "full-root-223" | "singleton-223"));
    if let Some(m) = v.as_object_mut() {
        m.remove("old_v2_237_prior_check");
        m.remove("checkpoint203_prior_check");
        if partial223 {
            m.remove("partial223_prior_check");
        }
        if failed234 {
            m.remove("failed_v5_234_prior_check");
        }
    }
    v
}
pub(super) fn prior_check(b: &Bound, operation: &Value, at: u64) -> Result<()> {
    let v = saved(b)?;
    prior_check_shape(b, &v, operation, at)
}
pub(super) fn existing_check(path: &Path, operation: &Value, spec: &Bound) -> Result<bool> {
    if retirement::absent(path)? {
        return Ok(false);
    }
    let bytes = read_stable_bounded(path, 8 << 20, "successor private completed check")?;
    let b = Bound {
        path: path.into(),
        sha256: hex_lower(&Sha256::digest(&bytes)),
    };
    let v = saved(&b)?;
    ensure!(
        v["check_spec"] == serde_json::to_value(spec)?,
        "successor private existing check has a different original spec"
    );
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("successor private original check clock absent")?;
    prior_check_shape(&b, &v, operation, at)?;
    // Preserve its original time even if it is now too old for a new intent.
    // A new check admission/spec is required to obtain a fresh capability.
    Ok(true)
}
pub(super) fn prior_check_shape(b: &Bound, v: &Value, operation: &Value, at: u64) -> Result<()> {
    // Shared fresh-check policy for the exact registered successor roles.
    let artifact: Artifact = serde_json::from_value(operation["artifact"].clone())?;
    ensure!(
        artifact.requires_prior_check(),
        "foreign prior-check artifact role"
    );
    let spec: Bound = serde_json::from_value(v["check_spec"].clone())?;
    let recorded = v["recorded_unix_seconds"]
        .as_u64()
        .context("successor private prior-check time absent")?;
    ensure!(
        v["schema"]
            == format!(
                "jetstreamer-{}-private-retirement-check-v1",
                artifact.check_label()
            )
            && v["check_only"] == true
            && v["local_retirement_authorized"] == false
            && v["original_source_hash_verified"] == true
            && v["closure_after_hash"]["source_identity_checked"] == true
            && v["closure_after_hash"]["maps_and_fds_device_inode_checked"] == true
            && digest(&spec.sha256)
            && b.path
                == Path::new(STATE).join("receipts").join(format!(
                    "{}-check-{}.json",
                    artifact.check_label(),
                    spec.sha256
                ))
            && check_scope(&v["operation"]) == check_scope(operation)
            && v["source_stamp"] == serde_json::to_value(artifact.expected())?
            && recorded <= at
            && at - recorded <= 900,
        "successor private requires a matching fresh separately completed retirement check"
    );
    Ok(())
}
