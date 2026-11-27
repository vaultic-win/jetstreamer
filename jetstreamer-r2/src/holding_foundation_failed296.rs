//! Encrypted byte custody for the closed first epoch 296 retry.
use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::DirBuilderExt;

pub(super) const ACTION: &str = "holding-foundation-296-failed-retry-park";
pub(super) const CHECK: &str = "holding-foundation-296-failed-retry-check";
pub(super) const RECHECK: &str = "holding-foundation-296-failed-retry-recheck";
const KEY_NAME: &str = "failed-retry-custody.key";
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
    let key = object_key();
    let (remote, wire_sha) = openpgp::park(
        &client,
        openpgp::Park {
            object_key: &key,
            source_path: &path,
            before: &before,
            clear_sha: CLEAR_SHA,
            cipher_overhead: CIPHER_OVERHEAD,
            key_root: Path::new(ROOT),
            key_name: KEY_NAME,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recheck {
    schema: String,
    mapping: Bound,
    custody: Bound,
    launch: Bound,
}

fn object_key() -> String {
    format!("{SUBPREFIX}encrypted-failed296/{CLEAR_SHA}.blob")
}

fn verify_manifest(manifest: &Value) -> Result<(&str, &str, u64)> {
    let wire_sha = manifest["ciphertext_sha256"]
        .as_str()
        .context("missing epoch 296 ciphertext digest")?;
    let length = manifest["ciphertext_length"]
        .as_u64()
        .context("missing epoch 296 ciphertext length")?;
    let etag = manifest["object_etag"]
        .as_str()
        .context("missing epoch 296 ciphertext ETag")?;
    let (part_digest, count) = etag.split_once('-').context("expected multipart ETag")?;
    ensure!(
        manifest["schema"] == "foundation-epoch296-encrypted-failed-retry-manifest-v1"
            && manifest["epoch"] == 296
            && manifest["object_key"] == object_key()
            && manifest["format"] == FORMAT
            && manifest["plaintext_length"] == CLEAR_BYTES
            && manifest["plaintext_sha256"] == CLEAR_SHA
            && manifest["canonical_archive"] == false
            && manifest["resumable_checkpoint"] == false
            && digest(wire_sha)
            && (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&length)
            && is_lower_hex(part_digest, 32)
            && count == length.div_ceil(DEFAULT_PART_SIZE).to_string(),
        "foreign epoch 296 encrypted manifest"
    );
    Ok((etag, wire_sha, length))
}

fn accepted(plan: &Recheck, custody: &Value, invocation: &Value) -> Result<()> {
    let closed = sealed("closed-byte-evidence.json", CLOSED_SHA);
    let proof = sealed("offline-crypto-volume-proof.json", PROOF_SHA);
    ensure!(
        plan.schema == "foundation-epoch296-encrypted-custody-recheck-plan-v1"
            && invocation["schema"] == "foundation-epoch296-encrypted-custody-launch-v1"
            && invocation["actual"]["Id"] == UNIT
            && invocation["credentials_loaded_by_manager"] == true
            && invocation["canonical_publication_authorized"] == false
            && invocation["retirement_authorized"] == false
            && custody["schema"] == "foundation-epoch296-encrypted-custody-v1"
            && custody["epoch"] == 296
            && custody["invocation_id"]
                .as_str()
                .is_some_and(|iid| is_lower_hex(iid, 32))
            && custody["invocation_id"] == invocation["actual"]["InvocationID"]
            && custody["closed_evidence"] == json!(closed)
            && custody["offline_proof"] == json!(proof)
            && custody["remote_ciphertext_sha256_verified"] == true
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_plaintext_reread_verified"] == true
            && custody["local_source_revalidated"] == true
            && custody["publication_authorized"] == false
            && custody["local_retirement_authorized"] == false,
        "no complete epoch 296 custody proof for the launched invocation"
    );
    Ok(())
}

pub(super) async fn recheck(value: Value, spec: &Bound) -> Result<()> {
    let plan: Recheck = serde_json::from_value(value)?;
    mapping(&plan.mapping)?;
    ensure!(
        ["park-launch-v1.json", "park-launch-v2.json"]
            .iter()
            .any(|file| plan.launch.path == Path::new(ROOT).join(file)),
        "foreign epoch 296 launch record"
    );
    let launch = saved(&plan.launch)?;
    let admission: Bound = serde_json::from_value(launch["admission"].clone())?;
    let booking = saved(&admission)?;
    let park_binding: Bound = serde_json::from_value(booking["spec"].clone())?;
    ensure!(
        booking["schema"] == "foundation-epoch296-encrypted-custody-admission-v1"
            && booking["unit"] == UNIT
            && park_binding.path == Path::new(ROOT).join("park.json")
            && plan.custody.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("failed296-custody-{}.json", park_binding.sha256)),
        "epoch 296 custody is outside the admitted plan"
    );
    let custody = saved(&plan.custody)?;
    ensure!(
        custody["plan"] == json!(park_binding),
        "changed epoch 296 custody plan"
    );
    accepted(&plan, &custody, &launch)?;
    let park = saved(&park_binding)?;
    ensure!(
        park["mapping"] == json!(plan.mapping),
        "changed epoch 296 holding mapping"
    );

    let manifest = &custody["manifest"];
    let (etag, wire_sha, length) = verify_manifest(manifest)?;
    let bytes = serde_json::to_vec(manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&manifest_sha)?;
    ensure!(
        custody["manifest_sha256"] == manifest_sha && custody["manifest_key"] == marker,
        "epoch 296 content-addressed manifest differs"
    );
    verify_closed_units()?;
    let (path, stamp) = source(&saved(&sealed("closed-byte-evidence.json", CLOSED_SHA))?)?;
    no_references(&path)?;
    let key = openpgp::key_file(Path::new(ROOT), KEY_NAME, false)?;
    let key_identity = Stamp::of(&fs::symlink_metadata(key)?);

    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 296 holding bucket");
    let client = s3_client(&r2);
    let remote_manifest = get_mutable_object(&client, BUCKET, &marker)
        .await?
        .context("missing epoch 296 authenticated manifest")?;
    ensure!(
        remote_manifest.bytes == bytes,
        "epoch 296 remote manifest bytes differ"
    );
    let object = object_key();
    let remote = head_archive(&client, BUCKET, &object)
        .await?
        .context("missing epoch 296 authenticated ciphertext")?;
    remote_matches(&remote, &object, length, wire_sha, Some(etag))?;
    let observed = clock()?;
    let result = receipt(
        &format!("failed296-remote-recheck-{}-{observed}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch296-encrypted-custody-recheck-v1","epoch":296,
            "spec":spec,"custody":plan.custody,"launch":plan.launch,
            "source_identity":stamp,"key_file_identity":key_identity,
            "manifest":manifest,"manifest_sha256":manifest_sha,"manifest_key":marker,
            "recorded_unix_seconds":observed,"authenticated_manifest_and_object_match":true,
            "remote_mutations":false,"publication_authorized":false,"local_retirement_authorized":false,
        }),
    )?;
    println!("{}", result.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_manifest_rejects_canonical_key_and_changed_etag() {
        let length = 41_646_490_199u64;
        let mut manifest = json!({
            "schema":"foundation-epoch296-encrypted-failed-retry-manifest-v1","epoch":296,
            "object_key":object_key(),"object_etag":format!("{}-{}", "a".repeat(32), length.div_ceil(DEFAULT_PART_SIZE)),
            "ciphertext_length":length,"ciphertext_sha256":"b".repeat(64),"format":FORMAT,
            "plaintext_length":CLEAR_BYTES,"plaintext_sha256":CLEAR_SHA,
            "canonical_archive":false,"resumable_checkpoint":false
        });
        assert!(verify_manifest(&manifest).is_ok());
        manifest["object_key"] = json!("epoch-296.jet");
        assert!(verify_manifest(&manifest).is_err());
        manifest["object_key"] = json!(object_key());
        manifest["object_etag"] = json!("weak");
        assert!(verify_manifest(&manifest).is_err());
    }

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
