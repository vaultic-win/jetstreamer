//! Encrypted holding for the exact closed epoch 224 resource canary.
use super::*;

pub(super) const CHECK: &str = "holding-foundation-224-canary-check";
pub(super) const PARK: &str = "holding-foundation-224-canary-park";
const ROOT: &str = "/var/lib/jetstreamer/horizon224-canary-native-custody-v1";
const UNIT: &str = "foundation-224-canary-native-custody-v1.service";
const TMPFS: &str = "/tmp/foundation-224-canary-custody";
const TMPFS_BYTES: u64 = 10 << 30;
const RAM_BYTES: u64 = 16 << 30;
const CIPHER_OVERHEAD: u64 = 8 << 20;
const FORMAT: &str = "openpgp-aes256-epoch224-resource-canary";
const KEY_NAME: &str = "canary-custody.key";
const SOURCE: &str =
    "/home/ubuntu/.jetstreamer-private/bounded-resource-224-8f80ce8-v1/output/epoch-224-canary.jet";
const CLEAR_SHA: &str = "7d2bfc7dc2e57ffd8dea2989216eba0ccc2237c1658efadbe803dd747a0bd51b";
const CLEAR_BYTES: u64 = 9_598_810_524;
const PRODUCER: &str = "horizon-qualify-224-bounded-resource-8f80ce8-v1.service";
const PRODUCER_ID: &str = "7e1a9f6e0368464bbab0f2d2ab6d30f7";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
}

fn closure_binding() -> Bound {
    Bound {
        path: "/var/lib/jetstreamer/horizon224-closed-canary-holding-candidate-v1/candidate.json"
            .into(),
        sha256: "bc77cfe12be9f2f8bdcc77478634651e931c6e1b022574a5544e9eddfd9793e8".into(),
    }
}

fn crypto_binding() -> Bound {
    Bound {
        path: "/var/lib/jetstreamer/horizon224-canary-openpgp-qualification-v1/qualification.json"
            .into(),
        sha256: "a66542c905861f5729bb6098747a8457858c8de012243ca5a758d77d06c3b50c".into(),
    }
}

fn verify_evidence(closure: &Bound, closed: &Value, proof: &Value) -> Result<()> {
    ensure!(
        closed["schema"] == "foundation-epoch224-private-canary-holding-candidate-v1"
            && closed["epoch"] == 224
            && closed["producer"]["unit"] == PRODUCER
            && closed["producer"]["invocation"] == PRODUCER_ID
            && closed["producer"]["manager_drained"] == true
            && closed["producer"]["controlled_stop_slot"] == 96_800_003
            && closed["source"]["path"] == SOURCE
            && closed["source"]["sha256"] == CLEAR_SHA
            && closed["source"]["bytes"] == CLEAR_BYTES
            && closed["publication_authorized"] == false
            && closed["retirement_authorized"] == false,
        "foreign epoch 224 canary closure"
    );
    let wire_bytes = proof["ciphertext_bytes"]
        .as_u64()
        .context("missing fixture wire size")?;
    ensure!(
        proof["schema"] == "foundation-epoch224-canary-openpgp-fixture-v1"
            && proof["epoch"] == 224
            && proof["closure"] == json!(closure)
            && proof["plaintext_sha256"] == CLEAR_SHA
            && proof["plaintext_bytes"] == CLEAR_BYTES
            && (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&wire_bytes)
            && proof["authenticated_plaintext_roundtrip"] == true
            && proof["truncated_ciphertext_rejected"] == true
            && proof["source_unchanged"] == true
            && proof["r2_mutations"] == false,
        "foreign epoch 224 offline crypto evidence"
    );
    let gpg = fs::read("/usr/bin/gpg")?;
    ensure!(
        proof["gpg_sha256"] == hex_lower(&Sha256::digest(gpg)),
        "OpenPGP executable changed since the epoch 224 fixture"
    );
    Ok(())
}

fn source() -> Result<Stamp> {
    let path = Path::new(SOURCE);
    let info = fs::symlink_metadata(path)?;
    let stamp = Stamp::of(&info);
    ensure!(
        info.is_file()
            && path.canonicalize()? == path
            && stamp
                == Stamp {
                    device: 66305,
                    inode: 24588968,
                    length: CLEAR_BYTES,
                    uid: 1000,
                    gid: 1000,
                    mode: 0o644,
                    links: 1,
                    mtime_ns: 1_792_521_525_449_462_811,
                    ctime_ns: 1_792_521_525_449_462_811,
                },
        "epoch 224 canary identity changed"
    );
    Ok(stamp)
}

fn verify_drained() -> Result<()> {
    let result = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--no-pager",
            "-p",
            "Id,LoadState,ActiveState,InvocationID,MainPID,ControlPID,ControlGroup,Job",
            PRODUCER,
        ])
        .output()?;
    let properties: std::collections::BTreeMap<_, _> = std::str::from_utf8(&result.stdout)?
        .lines()
        .filter_map(|row| row.split_once('='))
        .collect();
    let value = |name| properties.get(name).copied().unwrap_or("");
    ensure!(
        (result.status.success() || value("LoadState") == "not-found")
            && value("Id") == PRODUCER
            && value("ActiveState") == "inactive"
            && matches!(value("InvocationID"), "" | PRODUCER_ID)
            && matches!(value("MainPID"), "" | "0")
            && matches!(value("ControlPID"), "" | "0")
            && value("ControlGroup").is_empty()
            && value("Job").is_empty()
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(PRODUCER)
                .try_exists()?,
        "epoch 224 canary producer is still present or has changed identity"
    );
    Ok(())
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch224-canary-custody-plan-v1",
        "foreign epoch 224 custody plan"
    );
    mapping(&plan.mapping)?;
    let closure = closure_binding();
    let proof = crypto_binding();
    verify_evidence(&closure, &saved(&closure)?, &saved(&proof)?)?;
    let before = source()?;
    verify_drained()?;
    no_references(Path::new(SOURCE))?;
    if action == CHECK {
        println!(
            "{}",
            json!({"epoch":224,"closure":closure,"offline_proof":proof,
            "source_identity":before,"tmpfs_bytes":TMPFS_BYTES,"memory_bytes":RAM_BYTES,
            "remote_mutations":false,"local_retirement_authorized":false})
        );
        return Ok(());
    }

    accounts229::admitted_scope(UNIT, RAM_BYTES)?;
    let tmpfs = Path::new(TMPFS);
    accounts229::tmpfs_scope(tmpfs, TMPFS_BYTES, CLEAR_BYTES + CIPHER_OVERHEAD)?;
    let home = tmpfs.join("gpg");
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 224 holding bucket");
    let client = s3_client(&r2);
    let object_key = format!("{SUBPREFIX}encrypted-canary224/{CLEAR_SHA}.blob");
    let intent = |sha: &str, length: u64| {
        let name = format!("canary224-intent-{}-{sha}.json", spec.sha256);
        let value = json!({"schema":"foundation-epoch224-encrypted-canary-intent-v1",
            "plan":spec,"closure":closure,"key":object_key,"ciphertext_sha256":sha,"ciphertext_length":length,
            "no_clobber":true,"local_retirement_authorized":false});
        (name, value)
    };
    let (remote, wire_sha) = openpgp::park(
        &client,
        openpgp::Park {
            object_key: &object_key,
            source_path: Path::new(SOURCE),
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
            let (name, value) = intent(sha, length);
            receipt(&name, &value)?;
            Ok(())
        },
        |sha, length| {
            let (name, value) = intent(sha, length);
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            Ok(Bound {
                path: Path::new(STATE).join("receipts").join(name),
                sha256: hex_lower(&Sha256::digest(bytes)),
            })
        },
        source,
    )
    .await?;
    ensure!(
        source()? == before,
        "epoch 224 canary changed during transport"
    );
    verify_drained()?;
    no_references(Path::new(SOURCE))?;
    let manifest = json!({"schema":"foundation-epoch224-encrypted-canary-manifest-v1","epoch":224,
        "object_key":object_key,"object_etag":remote.etag,"ciphertext_length":remote.length,
        "ciphertext_sha256":wire_sha,"format":FORMAT,"plaintext_length":CLEAR_BYTES,
        "plaintext_sha256":CLEAR_SHA,"canonical_archive":false,"resumable_checkpoint":false});
    let bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&manifest_sha)?;
    small_create(&client, &marker, &bytes).await?;
    let result = receipt(
        &format!("canary224-custody-{}.json", spec.sha256),
        &json!({"schema":"foundation-epoch224-encrypted-canary-custody-v1","epoch":224,"plan":spec,
            "closure":closure,"offline_proof":proof,"source_identity":before,
            "manifest":manifest,"manifest_key":marker,"manifest_sha256":manifest_sha,
            "invocation_id":env::var("INVOCATION_ID")?,"remote_authenticated_decryption_verified":true,
            "restored_plaintext_reread_verified":true,"local_source_revalidated":true,
            "publication_authorized":false,"local_retirement_authorized":false}),
    )?;
    println!("{}", result.display());
    Ok(())
}
