//! Encrypted byte custody for the closed Foundation epoch 228 guest image.
use super::*;
use std::process::{Command, Stdio};

const PREPARE: &str = "holding-foundation-228-ext4-prepare";
const PARK: &str = "holding-foundation-228-ext4-park";
const ROOT: &str = "/var/lib/jetstreamer/horizon228-private-guest-staging-v1";
const COMPLETION: &str = "/var/lib/jetstreamer/horizon228-private-guest-staging-v1/completion.json";
const COMPLETION_SHA: &str = "50e47040a041c590e48126f21b3ce32a0bcef052f262ef7177a9a4de87791420";
const BUNDLE: &str =
    "/var/lib/jetstreamer/horizon228-private-guest-staging-v1/bundle/private-ext4.tar.zst";
const CLEAR_LEN: u64 = 35_060_711_831;
const CLEAR_SHA: &str = "e200304bbb686ec79cbb44ac175c734cdfb05f80680a4cf8a61dc9c1cbc0b8c7";
const GUEST_SHA: &str = "74f8b4e404a3c2133508e82840229a4219def94b434f2d00c1797173493b98b8";
const GUEST_LEN: u64 = 120_259_084_288;
const CIPHER: &str = "private-ext4.tar.zst.gpg";
const KEY_FILE: &str = "ext4-custody.key";
const FORMAT: &str = "openpgp-aes256-gnu-sparse-pax-zstd-ext4";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    mapping: Bound,
    staging: Bound,
    prepared: Option<Bound>,
}

pub(super) fn command(action: &str) -> bool {
    matches!(action, PREPARE | PARK)
}

fn validate_stage(bound: &Bound) -> Result<()> {
    ensure!(
        bound.path == Path::new(COMPLETION) && bound.sha256 == COMPLETION_SHA,
        "foreign epoch 228 staging receipt"
    );
    let stage = saved(bound)?;
    let bundle = &stage["staged_bundle"];
    let path = Path::new(BUNDLE);
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        stage["schema"] == "foundation-epoch228-sparse-staging-completion-v1"
            && stage["epoch"] == 228
            && stage["source_retirement_authorized"] == false
            && stage["restored_guest_sha256"] == GUEST_SHA
            && stage["closed_guest"]["logical_bytes"] == GUEST_LEN
            && bundle["path"] == BUNDLE
            && bundle["wire_sha256"] == CLEAR_SHA
            && bundle["bytes"] == CLEAR_LEN
            && bundle["storage"] == "tmpfs"
            && path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o400
            && meta.len() == CLEAR_LEN
            && bundle["device"] == meta.dev()
            && bundle["inode"] == meta.ino()
            && bundle["mtime_ns"].as_i64()
                == Some(meta.mtime() * 1_000_000_000 + meta.mtime_nsec())
            && bundle["ctime_ns"].as_i64()
                == Some(meta.ctime() * 1_000_000_000 + meta.ctime_nsec()),
        "epoch 228 sparse bundle differs from sealed staging"
    );
    Ok(())
}

fn cipher_path() -> PathBuf {
    Path::new(ROOT).join("bundle").join(CIPHER)
}

fn key_file(create: bool) -> Result<PathBuf> {
    let root = Path::new(ROOT);
    let path = root.join(KEY_FILE);
    if create {
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(mut file) => {
                let mut bytes = [0; 32];
                File::open("/dev/urandom")?.read_exact(&mut bytes)?;
                writeln!(file, "{}", hex_lower(&bytes))?;
                file.sync_all()?;
                File::open(root)?.sync_all()?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o400
            && meta.len() == 65,
        "unsafe epoch 228 custody key file"
    );
    Ok(path)
}

fn gpg(key: &Path) -> Result<Command> {
    let home = Path::new(ROOT).join("gpg");
    private(&home)?;
    let mut command = Command::new("/usr/bin/gpg");
    command
        .args(["--no-options", "--homedir"])
        .arg(home)
        .args([
            "--batch",
            "--no-tty",
            "--pinentry-mode",
            "loopback",
            "--no-symkey-cache",
            "--passphrase-file",
        ])
        .arg(key);
    Ok(command)
}

fn verify_plaintext(mut plain: impl Read, length: u64, sha: &str) -> Result<()> {
    let mut digest = Sha256::new();
    let mut remaining = length;
    let mut buffer = vec![0; 1 << 20];
    loop {
        let count = plain.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(count as u64)
            .context("decrypted bundle exceeds sealed length")?;
        digest.update(&buffer[..count]);
    }
    ensure!(
        remaining == 0 && hex_lower(&digest.finalize()) == sha,
        "decrypted bundle differs from sealed sparse bundle"
    );
    Ok(())
}

fn verify_encrypted_file(file: File, key: &Path) -> Result<()> {
    let mut child = gpg(key)?
        .arg("--decrypt")
        .stdin(file)
        .stdout(Stdio::piped())
        .spawn()?;
    let clear = verify_plaintext(
        child.stdout.take().context("missing OpenPGP output")?,
        CLEAR_LEN,
        CLEAR_SHA,
    );
    ensure!(
        child.wait()?.success(),
        "OpenPGP local authentication failed"
    );
    clear
}

fn cipher_identity(path: &Path) -> Result<FileIdentity> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o400
            && (CLEAR_LEN..=CLEAR_LEN + (16 << 20)).contains(&meta.len()),
        "unsafe epoch 228 encrypted bundle"
    );
    regular_identity(path)
}

fn prepare(plan: Plan, spec: &Bound) -> Result<()> {
    let path = cipher_path();
    let parent = path.parent().context("missing encrypted bundle parent")?;
    let encrypted_exists = path.try_exists()?;
    let key = key_file(!encrypted_exists)?;
    if !encrypted_exists {
        let temporary = tempfile::NamedTempFile::new_in(parent)?;
        let status = gpg(&key)?
            .args([
                "--rfc4880",
                "--symmetric",
                "--cipher-algo",
                "AES256",
                "--compress-algo",
                "none",
                "--s2k-digest-algo",
                "SHA512",
                "--s2k-count",
                "65011712",
                "--output",
                "-",
            ])
            .stdin(File::open(BUNDLE)?)
            .stdout(temporary.as_file().try_clone()?)
            .status()?;
        ensure!(status.success(), "epoch 228 OpenPGP encryption failed");
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        temporary.as_file().sync_all()?;
        temporary.persist_noclobber(&path)?;
        File::open(parent)?.sync_all()?;
    }
    let identity = cipher_identity(&path)?;
    verify_encrypted_file(File::open(&path)?, &key)?;
    let proof = hash_and_etag(&path, identity, DEFAULT_PART_SIZE)?;
    validate_stage(&plan.staging)?;
    let output = receipt(
        &format!("ext4-228-encrypted-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch228-encrypted-bundle-v1","epoch":228,"format":FORMAT,
            "staging":plan.staging,"prepare_spec":spec,"length":identity.length,"sha256":proof.sha256_hex,
            "identity":identity,"authenticated_decryption_verified":true,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

async fn verify_remote_restore(
    client: &Client,
    read: RemoteReadSpec<'_>,
    key: &Path,
) -> Result<()> {
    let mut child = gpg(key)?
        .arg("--decrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().context("missing OpenPGP input")?;
    let output = child.stdout.take().context("missing OpenPGP output")?;
    let compare = std::thread::spawn(move || verify_plaintext(output, CLEAR_LEN, CLEAR_SHA));
    let transfer = read_remote_sha256_resumable(client, read, &mut input).await;
    drop(input);
    let status = child.wait();
    let restored = compare
        .join()
        .map_err(|_| anyhow!("epoch 228 decrypted digest worker failed"));
    transfer?;
    ensure!(status?.success(), "OpenPGP remote authentication failed");
    restored??;
    Ok(())
}

async fn park(client: &Client, plan: Plan, spec: &Bound) -> Result<()> {
    let prepared = plan
        .prepared
        .as_ref()
        .context("missing epoch 228 encryption receipt")?;
    let sealed = saved(prepared)?;
    let path = cipher_path();
    let identity = cipher_identity(&path)?;
    let wire_sha = sealed["sha256"]
        .as_str()
        .context("missing encrypted SHA-256")?;
    ensure!(
        sealed["schema"] == "foundation-epoch228-encrypted-bundle-v1"
            && sealed["epoch"] == 228
            && sealed["format"] == FORMAT
            && sealed["staging"] == serde_json::to_value(&plan.staging)?
            && sealed["identity"] == serde_json::to_value(identity)?
            && sealed["length"] == identity.length
            && digest(wire_sha)
            && sealed["authenticated_decryption_verified"] == true
            && sealed["local_retirement_authorized"] == false,
        "foreign epoch 228 encryption receipt"
    );
    let key_file = key_file(false)?;
    let before = no_references(&path)?;
    let proof = hash_and_etag(&path, identity, DEFAULT_PART_SIZE)?;
    ensure!(
        proof.sha256_hex == wire_sha,
        "sealed epoch 228 ciphertext differs"
    );
    let object = key(wire_sha)?;
    let transport = Park {
        schema: "transport-only".into(),
        mapping: plan.mapping,
        eligibility: spec.clone(),
        source: path.clone(),
        length: identity.length,
        sha256: wire_sha.to_owned(),
    };
    claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
    let remote = verified_blob(client, &object, &transport, identity, &proof).await?;
    verify_remote_restore(
        client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: &object,
            etag: &remote.etag,
            expected_length: identity.length,
            expected_sha256: wire_sha,
            concurrency: 2,
        },
        &key_file,
    )
    .await?;
    validate_stage(&plan.staging)?;
    ensure!(
        cipher_identity(&path)? == identity,
        "epoch 228 ciphertext changed during custody"
    );
    let after = no_references(&path)?;
    let final_remote = head_archive(client, BUCKET, &object)
        .await?
        .context("epoch 228 holding object disappeared")?;
    remote_matches(
        &final_remote,
        &object,
        identity.length,
        wire_sha,
        Some(&remote.etag),
    )?;
    native_checksum(&final_remote, &proof, identity.length)?;
    let manifest = json!({
        "schema":"foundation-epoch228-ext4-holding-manifest-v1","host":host::HOST,"prefix":SUBPREFIX,
        "epoch":228,"format":FORMAT,"object_key":object,"length":identity.length,"sha256":wire_sha,
        "clear_sparse_bundle_length":CLEAR_LEN,"clear_sparse_bundle_sha256":CLEAR_SHA,
        "guest_length":GUEST_LEN,"guest_sha256":GUEST_SHA,"canonical_archive":false,
        "publication_authorized":false,"local_retirement_authorized":false
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_sha = hex_lower(&Sha256::digest(&manifest_bytes));
    let marker = manifest_key(&manifest_sha)?;
    small_create(client, &marker, &manifest_bytes).await?;
    let output = receipt(
        &format!("ext4-228-custody-{}.json", spec.sha256),
        &json!({
            "schema":"foundation-epoch228-ext4-custody-v1","bucket":BUCKET,"object_etag":remote.etag,
            "manifest_key":marker,"manifest_sha256":manifest_sha,"manifest":manifest,"staging":plan.staging,
            "prepared":prepared,"park_spec":spec,"remote_sha256_readback":true,
            "remote_authenticated_decryption_verified":true,"r2_plaintext_sha256_matches_staged_sparse_bundle":true,
            "reference_census_before":before,"reference_census_after":after,
            "publication_authorized":false,"local_retirement_authorized":false
        }),
    )?;
    println!("{}", output.display());
    Ok(())
}

pub(super) async fn run(action: &str, value: Value, spec: &Bound) -> Result<()> {
    let plan: Plan = serde_json::from_value(value)?;
    private(Path::new(ROOT))?;
    let path = cipher_path();
    private(path.parent().context("missing encrypted bundle parent")?)?;
    validate_stage(&plan.staging)?;
    if action == PREPARE {
        ensure!(
            plan.schema == "foundation-epoch228-ext4-prepare-v1" && plan.prepared.is_none(),
            "foreign epoch 228 encryption plan"
        );
        return prepare(plan, spec);
    }
    ensure!(
        action == PARK && plan.schema == "foundation-epoch228-ext4-park-v1",
        "foreign epoch 228 holding plan"
    );
    let r2 = r2_config_from_env()?;
    ensure!(r2.bucket == BUCKET, "foreign epoch 228 holding bucket");
    park(&s3_client(&r2), plan, spec).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plaintext_restore_requires_exact_length_and_digest() {
        let bytes = b"compressed sparse ext4 fixture";
        let length = bytes.len() as u64;
        let sha = hex_lower(&Sha256::digest(bytes));

        assert!(verify_plaintext(&bytes[..], length, &sha).is_ok());
        assert!(verify_plaintext(&bytes[..bytes.len() - 1], length, &sha).is_err());
        assert!(verify_plaintext(&bytes[..], length - 1, &sha).is_err());
        assert!(verify_plaintext(&bytes[..], length, CLEAR_SHA).is_err());
    }
}
