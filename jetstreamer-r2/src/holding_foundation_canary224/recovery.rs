use super::*;

pub(super) const RECHECK: &str = "holding-foundation-224-canary-recheck";
pub(super) const RESTORE: &str = "holding-foundation-224-canary-restore";
const LAUNCH: &str = "/var/lib/jetstreamer/horizon224-canary-production-launch-v1/park-launch.json";
const RESTORE_UNIT: &str = "foundation-224-canary-native-restore-v1.service";
const SUCCESS_ID: &str = "7ad2d189f7e94e70a38c781354912448";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    schema: String,
    mapping: Bound,
    launch: Bound,
    custody: Bound,
    restore_roster: Option<Bound>,
}

fn terminal(invocation: &str) -> Result<Value> {
    let output = std::process::Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={invocation}"),
            &format!("MESSAGE_ID={SUCCESS_ID}"),
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "failed to read park terminal event"
    );
    let mut rows = std::str::from_utf8(&output.stdout)?.lines();
    let row: Value = serde_json::from_str(rows.next().context("clean canary park exit missing")?)?;
    ensure!(
        rows.next().is_none()
            && row["UNIT"] == UNIT
            && row["INVOCATION_ID"] == invocation
            && row["_PID"] == "1"
            && row["_UID"] == "0"
            && row["MESSAGE_ID"] == SUCCESS_ID
            && !Path::new("/sys/fs/cgroup/system.slice")
                .join(UNIT)
                .try_exists()?,
        "canary custody invocation is not uniquely drained"
    );
    Ok(
        json!({"unit":UNIT,"invocation_id":invocation,"cursor":row["__CURSOR"],
        "terminal_microseconds":row["__REALTIME_TIMESTAMP"]}),
    )
}

async fn authenticate(client: &Client, custody: &Value) -> Result<RemoteArchive> {
    let manifest = &custody["manifest"];
    let key = encrypted_key();
    let etag = manifest["object_etag"]
        .as_str()
        .context("missing ciphertext ETag")?;
    let (digest_part, parts) = etag.split_once('-').context("expected multipart ETag")?;
    let len = manifest["ciphertext_length"]
        .as_u64()
        .context("missing ciphertext length")?;
    let sha = manifest["ciphertext_sha256"]
        .as_str()
        .context("missing ciphertext SHA-256")?;
    ensure!(
        manifest["schema"] == "foundation-epoch224-encrypted-canary-manifest-v1"
            && manifest["epoch"] == 224
            && manifest["object_key"] == key
            && manifest["format"] == FORMAT
            && manifest["plaintext_length"] == CLEAR_BYTES
            && manifest["plaintext_sha256"] == CLEAR_SHA
            && manifest["canonical_archive"] == false
            && manifest["resumable_checkpoint"] == false
            && digest(sha)
            && (CLEAR_BYTES..=CLEAR_BYTES + CIPHER_OVERHEAD).contains(&len)
            && is_lower_hex(digest_part, 32)
            && parts == len.div_ceil(DEFAULT_PART_SIZE).to_string(),
        "foreign canary manifest"
    );
    let bytes = serde_json::to_vec(manifest)?;
    let marker_sha = hex_lower(&Sha256::digest(&bytes));
    let marker = manifest_key(&marker_sha)?;
    ensure!(
        custody["manifest_key"] == marker && custody["manifest_sha256"] == marker_sha,
        "custody manifest binding differs"
    );
    let remote_marker = get_mutable_object(client, BUCKET, &marker)
        .await?
        .context("missing authenticated canary manifest")?;
    ensure!(
        remote_marker.bytes == bytes,
        "authenticated canary manifest differs"
    );
    let remote = head_archive(client, BUCKET, &key)
        .await?
        .context("missing authenticated canary ciphertext")?;
    remote_matches(&remote, &key, len, sha, Some(etag))?;
    Ok(remote)
}

async fn restore(
    client: &Client,
    remote: &RemoteArchive,
    custody: &Value,
    key_file: &Path,
    roster: &Bound,
) -> Result<PathBuf> {
    accounts229::admitted_scope(RESTORE_UNIT, 4 << 30)?;
    let quote = saved(roster)?;
    let at = quote["recorded_unix_seconds"]
        .as_u64()
        .context("missing restore roster time")?;
    let capacity = &quote["capacity"];
    let floor = capacity["protected_existing_disk_bytes"]
        .as_u64()
        .context("missing restore floor")?;
    let required = floor
        .checked_add(CLEAR_BYTES)
        .and_then(|n| n.checked_add(METADATA_RESERVE))
        .context("restore capacity overflow")?;
    ensure!(
        roster
            .path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("horizon262-foundation-roster-"))
            && clock()?.checked_sub(at).is_some_and(|age| age <= 90)
            && capacity["available_disk_bytes"]
                .as_u64()
                .is_some_and(|free| free >= required),
        "no fresh full-roster capacity for the private canary restore"
    );
    let root = Path::new(ROOT).join("restores");
    private(&root)?;
    let target = root.join("epoch-224-canary.jet");
    if !retirement::absent(&target)? {
        let meta = fs::symlink_metadata(&target)?;
        let id = regular_identity(&target)?;
        ensure!(
            meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o7777 == 0o400
                && id.length == CLEAR_BYTES
                && hash_and_etag(&target, id, DEFAULT_PART_SIZE)?.sha256_hex == CLEAR_SHA
                && available(&root)? >= floor,
            "existing private canary restore or capacity differs"
        );
        authenticate(client, custody).await?;
        return Ok(target);
    }
    ensure!(
        available(&root)? >= required,
        "private canary restore crosses protected floor"
    );
    let home = tempfile::Builder::new().prefix(".gpg-").tempdir_in(&root)?;
    let pending = tempfile::NamedTempFile::new_in(&root)?;
    let output = pending.reopen()?;
    openpgp::read_decrypted(
        client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: &encrypted_key(),
            etag: &remote.etag,
            expected_length: remote.length,
            expected_sha256: remote
                .metadata_sha256
                .as_deref()
                .context("missing ciphertext metadata SHA-256")?,
            concurrency: 2,
        },
        openpgp::gpg(home.path(), key_file)?,
        move |clear| {
            openpgp::copy_verified_plaintext(clear, &output, CLEAR_BYTES, CLEAR_SHA, || {
                ensure!(
                    available(&root)? >= floor + (1 << 20),
                    "restore crossed protected floor"
                );
                Ok(())
            })?;
            output.sync_all()?;
            Ok(())
        },
    )
    .await?;
    let id = regular_identity(pending.path())?;
    ensure!(
        id.length == CLEAR_BYTES
            && hash_and_etag(pending.path(), id, DEFAULT_PART_SIZE)?.sha256_hex == CLEAR_SHA,
        "canary restore staging differs"
    );
    authenticate(client, custody).await?;
    ensure!(
        available(target.parent().context("private restore parent")?)? >= floor,
        "restored canary crossed the protected floor"
    );
    pending
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    pending.as_file().sync_all()?;
    pending.persist_noclobber(&target)?;
    File::open(target.parent().context("private restore parent")?)?.sync_all()?;
    Ok(target)
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    let plan: Recovery = serde_json::from_value(value)?;
    ensure!(
        plan.schema == "foundation-epoch224-encrypted-canary-recovery-plan-v1"
            && plan.launch.path == Path::new(LAUNCH)
            && (action == RESTORE) == plan.restore_roster.is_some(),
        "foreign canary recovery plan"
    );
    mapping(&plan.mapping)?;
    let launch = saved(&plan.launch)?;
    let invocation = launch["invocation_id"]
        .as_str()
        .context("missing park invocation")?;
    ensure!(
        launch["schema"] == "foundation-epoch224-canary-encrypted-custody-launch-v1"
            && launch["unit"] == UNIT
            && is_lower_hex(invocation, 32),
        "foreign canary park launch"
    );
    let done = terminal(invocation)?;
    let custody = saved(&plan.custody)?;
    let applied: Bound = serde_json::from_value(custody["plan"].clone())?;
    ensure!(
        custody["schema"] == "foundation-epoch224-encrypted-canary-custody-v1"
            && custody["epoch"] == 224
            && custody["invocation_id"] == invocation
            && custody["closure"] == json!(closure_binding())
            && custody["offline_proof"] == json!(crypto_binding())
            && custody["source_identity"] == json!(expected_source())
            && custody["remote_authenticated_decryption_verified"] == true
            && custody["restored_plaintext_reread_verified"] == true
            && custody["local_source_revalidated"] == true
            && custody["publication_authorized"] == false
            && custody["local_retirement_authorized"] == false
            && plan.custody.path
                == Path::new(STATE)
                    .join("receipts")
                    .join(format!("canary224-custody-{}.json", applied.sha256))
            && saved(&applied)?["mapping"] == json!(plan.mapping),
        "canary custody does not match the completed sealed invocation"
    );
    let key_file = openpgp::key_file(Path::new(ROOT), KEY_NAME, false)?;
    let key_identity = Stamp::of(&fs::symlink_metadata(&key_file)?);
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign canary holding bucket");
    let client = s3_client(&r2);
    let remote = authenticate(&client, &custody).await?;
    let (label, staged) = if let Some(roster) = &plan.restore_roster {
        (
            "restore",
            Some(restore(&client, &remote, &custody, &key_file, roster).await?),
        )
    } else {
        ("recheck", None)
    };
    ensure!(
        Stamp::of(&fs::symlink_metadata(&key_file)?) == key_identity,
        "canary recovery key changed"
    );
    let now = clock()?;
    let result = receipt(
        &format!("canary224-{label}-{}-{now}.json", spec.sha256),
        &json!({"schema":"foundation-epoch224-encrypted-canary-recovery-v1","operation":label,"epoch":224,
            "plan":spec,"custody":plan.custody,"launch":plan.launch,"park_terminal":done,
            "manifest":custody["manifest"],"manifest_key":custody["manifest_key"],"manifest_sha256":custody["manifest_sha256"],
            "key_file_identity":key_identity,"authenticated_manifest_and_object_match":true,
            "restored_path":staged,"recorded_unix_seconds":now,"remote_mutations":false,
            "publication_authorized":false,"local_retirement_authorized":false}),
    )?;
    println!("{}", result.display());
    Ok(())
}
