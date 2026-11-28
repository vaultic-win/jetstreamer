//! Encrypted byte custody for the closed, incomplete epoch 288 archive.
use super::*;
use horizon_singleton211_launch::native262::foundation_roster::holding288::{
    ADMISSION, ADMISSION_SCHEMA, CPUS, MEMORY_BYTES, PARK, RECEIPT_BYTES, ROOT, ROSTER_SCHEMA,
    SOURCE_PROOF, TMPFS, TMPFS_BYTES, UNIT,
};
use std::os::unix::fs::DirBuilderExt;

#[path = "holding_foundation_partial288_retire.rs"]
mod retire;

const CHECK: &str = "holding-foundation-288-partial-check";
const KEY: &str = "partial-custody.key";
const FORMAT: &str = "openpgp-aes256-incomplete-epoch288-archive";
const CLEAR_BYTES: u64 = 187_178_039_910;
const CLEAR_SHA: &str = "8a94c3ce5ba068fe6515744918daf29f3cc9215bff1dc86aafdd2f5b82b2ad57";
const WIRE_OVERHEAD: u64 = 1 << 30;
const PRODUCER: &str = "horizon-qualify-288-root-shrink-debt-v1.service";
const PRODUCER_IID: &str = "88edf4dd09f343c9ac90cfff907c7b18";
const GUARD: &str = "horizon-288-full-shrink-debt-protective-v1.service";
const GUARD_TIMER: &str = "horizon-288-full-shrink-debt-protective-v1.timer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    #[serde(default)]
    admission: Option<Bound>,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, CHECK | PARK) || retire::command(action)
}

fn source_proof() -> Bound {
    Bound {
        path: Path::new(ROOT).join("closed-source-binding.json"),
        sha256: SOURCE_PROOF.into(),
    }
}

fn source(closed: &Value) -> Result<(PathBuf, Stamp)> {
    let value = &closed["source"];
    let path: PathBuf = serde_json::from_value(value["path"].clone())?;
    let meta = fs::symlink_metadata(&path)?;
    let stamp = Stamp::of(&meta);
    ensure!(
        closed["schema"] == "foundation-epoch288-full-partial-source-binding-v1"
            && closed["epoch"] == 288
            && closed["producer_invocation_id"] == PRODUCER_IID
            && closed["archive_complete"] == false
            && closed["retirement_authorized"] == false
            && closed["publication_authorized"] == false
            && value["sha256"] == CLEAR_SHA
            && path.canonicalize()? == path
            && path.file_name().is_some_and(|name| name == "epoch-288.jet")
            && meta.is_file()
            && stamp.length == CLEAR_BYTES
            && stamp.links == 1
            && (stamp.uid, stamp.gid, stamp.mode) == (1000, 1000, 0o600)
            && value["identity"]
                == json!({
                    "device":stamp.device,"inode":stamp.inode,"bytes":stamp.length,
                    "blocks":meta.blocks(),"uid":stamp.uid,"gid":stamp.gid,"links":stamp.links,
                    "mode":meta.mode(),"mtime_ns":stamp.mtime_ns,"ctime_ns":stamp.ctime_ns
                }),
        "retained epoch 288 archive identity differs"
    );
    Ok((path, stamp))
}

fn verify_stopped(closed: &Value, path: &Path) -> Result<()> {
    let terminal: Bound = serde_json::from_value(closed["terminal"].clone())?;
    let stop = saved(&terminal)?;
    ensure!(
        stop["schema"] == "foundation-epoch288-physical-budget-stop-v1"
            && stop["unit"] == PRODUCER
            && stop["invocation_id"] == PRODUCER_IID
            && stop["pid1_start"]["UNIT"] == PRODUCER
            && stop["pid1_start"]["INVOCATION_ID"] == PRODUCER_IID
            && stop["pid1_stop"]["UNIT"] == PRODUCER
            && stop["pid1_stop"]["INVOCATION_ID"] == PRODUCER_IID
            && stop["guard_drained"] == true
            && stop["resume_verified"] == false
            && stop["retained_partial"]["path"] == json!(path)
            && stop["retained_partial"]["device"] == closed["source"]["identity"]["device"]
            && stop["retained_partial"]["inode"] == closed["source"]["identity"]["inode"]
            && stop["retained_partial"]["bytes"] == CLEAR_BYTES
            && stop["guard_service_after"]["Id"] == GUARD
            && stop["guard_service_after"]["ActiveState"] == "inactive"
            && stop["guard_timer_after"]["ActiveState"] == "inactive",
        "epoch 288 terminal evidence differs"
    );
    closure::properties(PRODUCER, PRODUCER_IID, true)?;
    for unit in [GUARD, GUARD_TIMER] {
        let state = closure::properties(unit, "", true)?;
        ensure!(
            state["ActiveState"] == "inactive",
            "epoch 288 guard is still armed"
        );
    }
    Ok(())
}

fn verify_closed(closed: &Value, path: &Path) -> Result<()> {
    verify_stopped(closed, path)?;
    no_references(path)?;
    Ok(())
}

fn park_floor(admission: &Bound, before: &Stamp) -> Result<u64> {
    ensure!(
        admission.path == Path::new(ROOT).join(ADMISSION),
        "foreign epoch 288 park admission"
    );
    let booking = saved(admission)?;
    let roster: Bound = serde_json::from_value(booking["roster"].clone())?;
    let fit = saved(&roster)?;
    let at = fit["recorded_unix_seconds"]
        .as_u64()
        .context("park fit clock")?;
    let capacity = &fit["capacity"];
    ensure!(
        booking["schema"] == ADMISSION_SCHEMA
            && booking["unit"] == UNIT
            && booking["source"] == json!(source_proof())
            && booking["retirement_authorized"] == false
            && booking["publication_authorized"] == false
            && fit["schema"] == ROSTER_SCHEMA
            && fit["partial_288_custody_quote"]["source"] == json!(source_proof())
            && fit["partial_288_custody_quote"]["producer_unit"] == UNIT
            && fit["filesystem_device"] == before.device
            && clock()?.checked_sub(at).is_some_and(|age| age <= 900)
            && capacity["fits"] == true
            && capacity["candidate_total_memory_bytes"] == MEMORY_BYTES
            && capacity["candidate_disk_bytes"] == RECEIPT_BYTES,
        "epoch 288 park admission does not bind a fresh full-roster fit"
    );
    capacity["protected_existing_disk_bytes"]
        .as_u64()
        .filter(|floor| *floor > 0)
        .context("missing protected disk budget")
}

fn object_key() -> String {
    format!("{SUBPREFIX}encrypted-partial288/{CLEAR_SHA}.blob")
}

fn intent(key: &str, sha: &str, wire_bytes: u64) -> Result<(String, Value)> {
    ensure!(
        digest(sha) && (CLEAR_BYTES..=CLEAR_BYTES + WIRE_OVERHEAD).contains(&wire_bytes),
        "unexpected epoch 288 ciphertext identity"
    );
    Ok((
        format!("partial288-wire-intent-{SOURCE_PROOF}-{sha}.json"),
        json!({
            "schema":"foundation-epoch288-encrypted-partial-intent-v1",
            "source":source_proof(),"object_key":key,"format":FORMAT,
            "ciphertext_sha256":sha,"ciphertext_length":wire_bytes,
        }),
    ))
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    if retire::command(action) {
        return retire::run(action, value, spec).await;
    }
    let plan: Plan = serde_json::from_value(value)?;
    ensure!(
        command(action) && plan.schema == "foundation-epoch288-partial-custody-plan-v1",
        "foreign epoch 288 custody plan"
    );
    mapping(&plan.mapping)?;
    let closed_ref = source_proof();
    let closed = saved(&closed_ref)?;
    let (path, before) = source(&closed)?;
    verify_closed(&closed, &path)?;
    if action == CHECK {
        println!(
            "{}",
            json!({"epoch":288,"source":closed_ref,"identity_matches":true,
                "producer_invocation_id":PRODUCER_IID,"archive_complete":false,
                "remote_mutations":false,"retirement_authorized":false})
        );
        return Ok(());
    }

    let admission = plan
        .admission
        .context("epoch 288 park admission required")?;
    let floor = park_floor(&admission, &before)?;
    accounts229::admitted_scope(UNIT, MEMORY_BYTES)?;
    let process_status = fs::read_to_string("/proc/self/status")?;
    ensure!(
        process_status.lines().any(|line| line
            .strip_prefix("Cpus_allowed_list:")
            .is_some_and(|value| value.trim() == CPUS)),
        "epoch 288 park escaped its admitted CPUs"
    );
    let tmpfs = Path::new(TMPFS);
    accounts229::tmpfs_scope(tmpfs, TMPFS_BYTES, CLEAR_BYTES + WIRE_OVERHEAD)?;
    ensure!(
        available(&path)?
            >= floor
                .checked_add(RECEIPT_BYTES)
                .context("disk budget overflow")?,
        "epoch 288 park would cross the protected disk budget"
    );
    let home = tmpfs.join("gpg");
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 288 holding bucket");
    let client = s3_client(&r2);
    let key = object_key();
    let (remote, wire_sha) = openpgp::park(
        &client,
        openpgp::Park {
            object_key: &key,
            source_path: &path,
            before: &before,
            clear_sha: CLEAR_SHA,
            cipher_overhead: WIRE_OVERHEAD,
            key_root: Path::new(ROOT),
            key_name: KEY,
            tmpfs,
            format: FORMAT,
        },
        &home,
        |sha, length| {
            let (name, value) = intent(&key, sha, length)?;
            receipt(&name, &value)?;
            Ok(())
        },
        |sha, length| {
            let (name, value) = intent(&key, sha, length)?;
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
        "epoch 288 source changed during transfer"
    );
    verify_closed(&closed, &path)?;
    ensure!(
        available(&path)? >= floor,
        "epoch 288 protected disk budget crossed"
    );

    let manifest = json!({
        "schema":"foundation-epoch288-encrypted-partial-manifest-v1","epoch":288,
        "object_key":key,"object_etag":remote.etag,"ciphertext_length":remote.length,
        "ciphertext_sha256":wire_sha,"format":FORMAT,"plaintext_length":CLEAR_BYTES,
        "plaintext_sha256":CLEAR_SHA,"source":closed_ref,"archive_complete":false,
        "resumable_checkpoint":false
    });
    let bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&manifest_sha)?;
    small_create(&client, &marker, &bytes).await?;
    let result = receipt(
        &format!("partial288-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch288-encrypted-partial-custody-v1","epoch":288,
            "plan":spec,"admission":admission,"remote_bucket":BUCKET,
            "manifest":manifest,"manifest_key":marker,"manifest_sha256":manifest_sha,
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
    fn park_intent_is_bound_to_the_closed_partial_and_ciphertext() -> Result<()> {
        let object = object_key();
        let hash = "a".repeat(64);
        let (name, value) = intent(&object, &hash, CLEAR_BYTES + (1 << 20))?;
        assert!(object.starts_with("foundation_node_01/closed-private-v1/encrypted-partial288/"));
        assert!(!object.ends_with(".jet"));
        assert_eq!(value["source"], json!(source_proof()));
        assert_eq!(value["object_key"], object);
        assert!(name.contains(SOURCE_PROOF));
        assert!(intent(&object, &hash, CLEAR_BYTES - 1).is_err());
        assert!(intent(&object, &hash, CLEAR_BYTES + WIRE_OVERHEAD + 1).is_err());
        Ok(())
    }
}
