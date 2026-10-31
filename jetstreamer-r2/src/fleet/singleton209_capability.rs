//! Rehash the closed cached singleton 209 package without a Bank or resource poll.
use super::{singleton209 as c, *};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    output: PathBuf,
}
pub(super) fn inputs() -> Result<()> {
    for (path, sha, length) in [
        (PathBuf::from(c::NODE), c::NODE_SHA, None),
        (PathBuf::from(c::WORKER), c::WORKER_SHA, None),
        (PathBuf::from(c::PREFLIGHT), c::PREFLIGHT_SHA, None),
        (
            Path::new(c::INPUT).join(c::SNAPSHOT),
            c::SNAPSHOT_SHA,
            Some(8_543_246_873),
        ),
        (
            Path::new(c::INPUT).join("genesis.tar.bz2"),
            c::GENESIS_SHA,
            Some(20_144),
        ),
    ] {
        native209_admission::sealed_file(&path, sha, length)?;
    }
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("prepare-singleton209-inputs")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-singleton-input-capability-spec-v1"
            && s.output == Path::new(c::CAPABILITY),
        "209 capability spec/output scope differs"
    );
    if s.output.try_exists()? {
        let old = native209::immutable_json(&serde_json::from_value(private157::file_binding(
            &s.output,
        )?)?)?;
        ensure!(
            old["preparation_spec"] == private157::binding(&binding)
                && old["preparation_helper_sha256"] == self_sha,
            "209 capability retry conflicts"
        );
        c::capability(&old)?;
        return Ok(());
    }
    validate_output_destination(&s.output)?;
    inputs()?;
    let mut v = json!({"schema":"jetstreamer-private-epoch209-singleton-input-capability-v1","epoch":209,
        "node_sha256":c::NODE_SHA,"worker_sha256":c::WORKER_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,
        "genesis_sha256":c::GENESIS_SHA,"preflight_sha256":c::PREFLIGHT_SHA,"manifest_fingerprint":c::FINGERPRINT,
        "bootstrap_slot":90287519u64,"canonical_root_slot":90719638u64,"post_root_slot_count":361,
        "output_slot_start":90288000u64,"terminal_slot":90719999u64,"output_slot_count":432000,
        "all_immutable_inputs_rehashed":true,"snapshot_restored":false,"worker_spawned":false,
        "resource_samples_taken":0,"native_input_qualified":false,"replay_launch_authorized":false,
        "preparation_spec":private157::binding(&binding),"preparation_helper_sha256":self_sha});
    for key in [
        "runtime_promotion_authorized",
        "full_epoch_qualified",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        v[key] = json!(false);
    }
    c::capability(&v)?;
    private157::immutable_receipt(&s.output, &v)
}
