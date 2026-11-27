//! Encrypted byte custody for the closed first epoch 296 retry.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt;

pub(super) const ACTION: &str = "holding-foundation-296-failed-retry-park";
pub(super) const CHECK: &str = "holding-foundation-296-failed-retry-check";
const ROOT: &str = "/var/lib/jetstreamer/horizon296-closed-first-retry-custody-v1";
const CLOSED_SHA: &str = "0066541f0c6112951ffe8b5eb24c3b3da136d2ecb2806edd1b962179321cbb80";
const PROOF_SHA: &str = "f0649cddd1b976ef9da319c5f49e29c6517311048e036d8808e6d2d4b5c46f78";
const CLEAR_SHA: &str = "1efb77f6f812d345d1dde5dd5201a1088d4db178f61a30979a3c8659db424e2d";
const CLEAR_BYTES: u64 = 41_628_130_271;
// The exact offline ciphertext exceeded the 229 profile's 16 MiB allowance.
const CIPHER_OVERHEAD: u64 = 32 << 20;
const MEMORY_BYTES: u64 = 80 << 30;
const TMPFS_BYTES: u64 = 42 << 30;
const TMPFS: &str = "/tmp/foundation-296-closed-custody";
const UNIT: &str = "foundation-296-closed-retry-custody-v1.service";
const PRODUCER: &str = "horizon-qualify-296-full-retry-v1.service";
const GUARD: &str = "horizon-296-full-retry-protective-v1.service";
const TIMER: &str = "horizon-296-full-retry-protective-v1.timer";
const FORMAT: &str = "openpgp-aes256-failed-epoch296-retry";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
}

fn sealed(name: &str, sha: &str) -> Bound {
    Bound {
        path: Path::new(ROOT).join(name),
        sha256: sha.into(),
    }
}

fn exact_file(entry: &Value) -> Result<(PathBuf, Stamp)> {
    let path: PathBuf = serde_json::from_value(entry["path"].clone())?;
    let meta = fs::symlink_metadata(&path)?;
    let stamp = Stamp::of(&meta);
    ensure!(
        meta.is_file()
            && path.canonicalize()? == path
            && stamp.links == 1
            && entry["identity"]
                == json!({
                    "device":stamp.device,"inode":stamp.inode,"bytes":stamp.length,
                    "blocks":meta.blocks(),"uid":stamp.uid,"gid":stamp.gid,"links":stamp.links,
                    "mode":meta.mode(),"mtime_ns":stamp.mtime_ns,"ctime_ns":stamp.ctime_ns
                }),
        "epoch 296 retained file identity changed"
    );
    Ok((path, stamp))
}

fn source(closed: &Value) -> Result<(PathBuf, Stamp)> {
    let (path, stamp) = exact_file(&closed["source"])?;
    let (meta_path, meta) = exact_file(&closed["metadata"])?;
    ensure!(
        stamp.length == CLEAR_BYTES
            && meta.length == 222
            && hex_lower(&Sha256::digest(fs::read(&meta_path)?)) == closed["metadata"]["sha256"],
        "epoch 296 retained source or cohort metadata differs"
    );
    ensure!(
        exact_file(&closed["metadata"])?.1 == meta,
        "epoch 296 cohort metadata changed during read"
    );
    Ok((path, stamp))
}

fn verify_closed_units() -> Result<()> {
    for (unit, expected_state) in [
        (PRODUCER, "failed"),
        (GUARD, "inactive"),
        (TIMER, "inactive"),
    ] {
        let reply = std::process::Command::new("/usr/bin/systemctl")
            .args([
                "show",
                unit,
                "-p",
                "Id",
                "-p",
                "ActiveState",
                "-p",
                "Job",
                "-p",
                "InvocationID",
                "-p",
                "MainPID",
                "-p",
                "ControlPID",
            ])
            .output()?;
        let props: BTreeMap<_, _> = std::str::from_utf8(&reply.stdout)?
            .lines()
            .filter_map(|line| line.split_once('='))
            .collect();
        ensure!(
            reply.status.success()
                && props.get("Id") == Some(&unit)
                && props.get("ActiveState") == Some(&expected_state)
                && props.get("Job") == Some(&"")
                && ["MainPID", "ControlPID"]
                    .iter()
                    .all(|p| { props.get(p).is_none_or(|value| *value == "0") })
                && (unit != PRODUCER
                    || props.get("InvocationID") == Some(&"f56eac46fa2a46c7b85b7f116b1cd9c0")),
            "epoch 296 original unit is no longer at its recorded closed generation: {unit}"
        );
    }
    Ok(())
}

fn intent(closed: &Bound, key: &str, sha: &str, length: u64) -> Result<(String, Value)> {
    ensure!(
        digest(sha) && (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&length),
        "invalid epoch 296 ciphertext intent"
    );
    Ok((
        format!("failed296-encrypted-intent-{CLOSED_SHA}-{sha}.json"),
        json!({
            "schema":"foundation-epoch296-encrypted-object-intent-v1",
            "closed_evidence":closed,"object_key":key,"ciphertext_sha256":sha,
            "ciphertext_length":length,"format":FORMAT
        }),
    ))
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch296-encrypted-custody-plan-v1",
        "foreign epoch 296 custody plan"
    );
    mapping(&plan.mapping)?;
    let closed_binding = sealed("closed-byte-evidence.json", CLOSED_SHA);
    let closed = saved(&closed_binding)?;
    let proof_binding = sealed("offline-crypto-volume-proof.json", PROOF_SHA);
    let proof = saved(&proof_binding)?;
    ensure!(
        closed["schema"] == "foundation-epoch296-closed-retry-v1-byte-evidence-v1"
            && closed["source"]["sha256"] == CLEAR_SHA
            && closed["canonical_archive"] == false
            && closed["resumable_checkpoint"] == false
            && proof["schema"] == "foundation-epoch296-encrypted-partial-volume-proof-v1"
            && proof["closed_evidence"] == json!(closed_binding)
            && proof["plaintext_bytes"] == CLEAR_BYTES
            && proof["plaintext_sha256"] == CLEAR_SHA
            && proof["authenticated_decryption_verified"] == true
            && proof["remote_mutations"] == false
            && proof["tmpfs_capacity_bytes"] == TMPFS_BYTES
            && proof["cgroup_memory_cap_bytes"] == MEMORY_BYTES,
        "epoch 296 sealed crypto and closure evidence differ"
    );
    let (path, before) = source(&closed)?;
    verify_closed_units()?;
    no_references(&path)?;
    if action == CHECK {
        println!(
            "{}",
            json!({"epoch":296,"closed_evidence":closed_binding,
            "offline_proof":proof_binding,"identity_matches":true,"remote_mutations":false})
        );
        return Ok(());
    }
    accounts229::admitted_scope(UNIT, MEMORY_BYTES)?;
    let tmpfs = Path::new(TMPFS);
    accounts229::tmpfs_scope(tmpfs, TMPFS_BYTES, CLEAR_BYTES + CIPHER_OVERHEAD)?;
    let home = tmpfs.join("gpg");
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 296 holding bucket");
    let client = s3_client(&r2);
    let key = format!("{SUBPREFIX}encrypted-failed296/{CLEAR_SHA}.blob");
    let (remote, wire_sha) = openpgp::park(
        &client,
        openpgp::Park {
            object_key: &key,
            source_path: &path,
            before: &before,
            clear_sha: CLEAR_SHA,
            cipher_overhead: CIPHER_OVERHEAD,
            key_root: Path::new(ROOT),
            key_name: "failed-retry-custody.key",
            tmpfs,
            format: FORMAT,
        },
        &home,
        |sha, length| {
            let (name, value) = intent(&closed_binding, &key, sha, length)?;
            receipt(&name, &value)?;
            Ok(())
        },
        |sha, length| {
            let (name, value) = intent(&closed_binding, &key, sha, length)?;
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            Ok(Bound {
                path: Path::new(STATE).join("receipts").join(name),
                sha256: hex_lower(&Sha256::digest(bytes)),
            })
        },
        || Ok(source(&closed)?.1),
    )
    .await?;
    ensure!(
        source(&closed)?.1 == before,
        "epoch 296 source changed during transfer"
    );
    verify_closed_units()?;
    no_references(&path)?;
    let manifest = json!({
        "schema":"foundation-epoch296-encrypted-failed-retry-manifest-v1","epoch":296,
        "object_key":key,"object_etag":remote.etag,"ciphertext_length":remote.length,
        "ciphertext_sha256":wire_sha,"format":FORMAT,"plaintext_length":CLEAR_BYTES,
        "plaintext_sha256":CLEAR_SHA,"canonical_archive":false,"resumable_checkpoint":false
    });
    let bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let manifest_key = manifest_key(&manifest_sha)?;
    small_create(&client, &manifest_key, &bytes).await?;
    let result = receipt(
        &format!("failed296-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch296-encrypted-custody-v1","epoch":296,"plan":spec,
            "closed_evidence":closed_binding,"offline_proof":proof_binding,
            "manifest":manifest,"manifest_key":manifest_key,"manifest_sha256":manifest_sha,
            "invocation_id":env::var("INVOCATION_ID")?,
            "remote_ciphertext_sha256_verified":true,"remote_authenticated_decryption_verified":true,
            "restored_plaintext_reread_verified":true,"local_source_revalidated":true,
            "publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", result.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_the_closed_artifact_and_rejects_out_of_profile_ciphertext() {
        let binding = sealed("closed-byte-evidence.json", CLOSED_SHA);
        let sha = "a".repeat(64);
        let key = format!("{SUBPREFIX}encrypted-failed296/{CLEAR_SHA}.blob");
        let (name, value) = intent(&binding, &key, &sha, 41_646_490_199).unwrap();
        assert!(name.contains(CLOSED_SHA));
        assert_eq!(value["object_key"], key);
        assert!(intent(&binding, &key, &sha, CLEAR_BYTES - 1).is_err());
        assert!(intent(&binding, &key, &sha, CLEAR_BYTES + CIPHER_OVERHEAD + 1).is_err());
    }
}
