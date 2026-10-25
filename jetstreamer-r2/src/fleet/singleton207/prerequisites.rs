//! Genuine metadata repair and native proof are independent, immutable gates.
use super::*;

pub(super) fn metadata_shape(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-private-epoch207-authenticated-root-metadata-evidence-v1"
            && v["epoch"] == 207
            && v["root_slot"] == 89523820u64
            && v["candidate"] == private157::binding(&binding(MANIFEST, MANIFEST_SHA))
            && v["candidate_manifest_fingerprint"] == FINGERPRINT
            && v["retained_native_input_proof"]
                == private157::binding(&binding(NATIVE, NATIVE_SHA))
            && v["generation"] == 1633927404656451u64
            && v["size"] == 8419571372u64
            && v["crc32c"] == "qIeOcA=="
            && v["md5_base64"] == "j2A9+aBmNPGRhc6DKD2AXQ=="
            && v["metadata_evidence_admission_passed"] == true
            && v["root_witnessed_attempt_bound"] == true
            && v["only_first_root_md5_changed"] == true
            && v["metadata_json_alone_proves_authentication"] == false
            && v["root_seal_is_an_executor_receipt"] == false
            && v["bootstrap_or_snapshot_rerun"] == false
            && v["native_input_qualification_newly_performed"] == false,
        "singleton 207 admitted witnessed metadata or retained native binding differs"
    );
    for k in [
        "replay_launch_authorized",
        "runtime_admission_authorized",
        "snapshot_restore_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[k] == false,
            "singleton 207 metadata grants authority: {k}"
        );
    }
    Ok(())
}
pub(super) fn preflight_shape(v: &Value) -> Result<()> {
    let p = &v["actual_preflight_stdout"];
    ensure!(
        v["schema"] == "operator-parent-witnessed-epoch207-admitted-metadata-preflight-v1"
            && v["unit"] == "horizon-207-singleton-preflight-admitted-md5-v1.service"
            && v["invocation_id"] == "7460fabcba4f4036bdbe86050fc885bf"
            && v["node"] == private157::binding(&binding(NODE, NODE_SHA))
            && v["manifest"] == private157::binding(&binding(MANIFEST, MANIFEST_SHA))
            && v["manifest_fingerprint"] == FINGERPRINT
            && v["natural_main_exit_status"] == 0
            && v["stdout_extracted_from_bound_same_invocation_journal"] == true
            && p["schema"] == "jetstreamer-private-epoch207-singleton-preflight-v1"
            && p["epoch"] == 207
            && p["bootstrap_slot"] == BOOTSTRAP
            && p["canonical_root_slots"] == json!([89523820u64, 89855469u64])
            && p["output_slot_start"] == FIRST
            && p["output_slot_end_exclusive"] == TERMINAL + 1
            && p["manifest_fingerprint"] == FINGERPRINT
            && p["candidate_only"] == true
            && p["runtime"] == "solana-v1.6.16",
        "singleton 207 actual admitted metadata preflight differs"
    );
    for object in [v, p] {
        ensure!(
            object["worker_started"] == false
                && object["snapshot_restored"] == false
                && object["replay_entries"] == 0
                && object["full_epoch_replay_qualified"] == false
                && object["publication_authorized"] == false
                && object["remote_mutations"] == false
                && object["r2_mutations"] == false,
            "singleton 207 metadata preflight grants replay evidence"
        );
    }
    ensure!(
        v["producer_started"] == false
            && v["resource_samples_taken"] == 0
            && v["replay_launch_authorized"] == false,
        "singleton 207 preflight grants launch authority"
    );
    Ok(())
}
fn raw(v: &Value, field: &str, count: usize) -> Result<()> {
    let rows = v[field]
        .as_array()
        .filter(|r| r.len() == count)
        .context("singleton 207 missing immutable subordinate evidence")?;
    for row in rows {
        let b: BoundFile = serde_json::from_value(row.clone())?;
        let bytes = read_stable_bounded(&b.path, 16 << 20, "singleton 207 subordinate evidence")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == b.sha256,
            "singleton 207 subordinate metadata/preflight evidence changed"
        );
    }
    Ok(())
}
pub(super) fn validate() -> Result<()> {
    native209::immutable_json(&binding(MANIFEST, MANIFEST_SHA))?;
    let metadata = native209::immutable_json(&binding(METADATA, METADATA_SHA))?;
    metadata_shape(&metadata)?;
    raw(&metadata, "witnessed_transport", 5)?;
    let cap = native209::immutable_json(&binding(CAPABILITY, CAPABILITY_SHA))?;
    preflight_shape(&cap)?;
    raw(&cap, "raw_evidence", 2)?;
    let native = native209::immutable_json(&binding(NATIVE, NATIVE_SHA))?;
    native207_terminal::validate(&native)?;
    Ok(())
}

/// Metadata-only hash qualification; never restores a Bank or launches a worker.
pub(super) fn prepare_inputs() -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Spec {
        schema: String,
        output: PathBuf,
    }
    let (bound, sha) = publication203::parsed_args("prepare-singleton207-inputs")?;
    let spec: Spec = serde_json::from_value(native209::immutable_json(&bound)?)?;
    ensure!(
        spec.schema == "jetstreamer-singleton207-inputs-spec-v1",
        "singleton 207 input spec differs"
    );
    admission::output(&spec.output, "inputs.json", "horizon-singleton207-inputs-")?;
    validate()?;
    for (path, hash, size) in [
        (PathBuf::from(NODE), NODE_SHA, 49004152u64),
        (PathBuf::from(WORKER), WORKER_SHA, 8960000),
        (Path::new(PACKAGE).join(SNAPSHOT), SNAPSHOT_SHA, 8474139490),
        (
            Path::new(PACKAGE).join("genesis.tar.bz2"),
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            20144,
        ),
    ] {
        native209_admission::sealed_file(&path, hash, Some(size))?;
    }
    let mut v = scope();
    v["schema"] = json!("jetstreamer-singleton207-inputs-v1");
    v["all_immutable_inputs_rehashed"] = json!(true);
    v["helper_sha256"] = json!(sha);
    v["spec"] = private157::binding(&bound);
    v["worker_started"] = json!(false);
    v["snapshot_restored"] = json!(false);
    v["resource_samples_taken"] = json!(0);
    deny_fields(&mut v);
    private157::immutable_receipt(&spec.output, &v)
}
