//! OpenPGP transport for the Foundation's content-addressed private holding.
use super::*;
use std::process::{ChildStdout, Command, Stdio};

pub(super) fn key_file(root: &Path, name: &str, create: bool) -> Result<PathBuf> {
    private(root)?;
    let path = root.join(name);
    if create && !path.try_exists()? {
        let mut pending = tempfile::NamedTempFile::new_in(root)?;
        let mut bytes = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        writeln!(pending.as_file_mut(), "{}", hex_lower(&bytes))?;
        pending
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        pending.as_file().sync_all()?;
        pending
            .persist_noclobber(&path)
            .context("publish owner-only OpenPGP key")?;
        File::open(root)?.sync_all()?;
    }
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.nlink() == 1
            && meta.mode() & 0o7777 == 0o400
            && meta.len() == 65,
        "unsafe OpenPGP custody key file"
    );
    Ok(path)
}

pub(super) fn gpg(home: &Path, key: &Path) -> Result<Command> {
    private(home)?;
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

pub(super) fn verify_plaintext(plain: impl Read, length: u64, sha: &str) -> Result<()> {
    copy_verified_plaintext(plain, std::io::sink(), length, sha, || Ok(()))
}

pub(super) fn copy_verified_plaintext(
    mut plain: impl Read,
    mut destination: impl Write,
    length: u64,
    sha: &str,
    mut check_capacity: impl FnMut() -> Result<()>,
) -> Result<()> {
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
        check_capacity()?;
        digest.update(&buffer[..count]);
        destination.write_all(&buffer[..count])?;
    }
    ensure!(
        remaining == 0 && hex_lower(&digest.finalize()) == sha,
        "decrypted bundle differs from sealed sparse bundle"
    );
    Ok(())
}

pub(super) fn encrypt(mut gpg: Command, source: File, destination: File) -> Result<()> {
    let status = gpg
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
        .stdin(source)
        .stdout(destination)
        .status()?;
    ensure!(status.success(), "OpenPGP encryption failed");
    Ok(())
}

pub(super) fn verify_encrypted_file(
    mut gpg: Command,
    file: File,
    clear_length: u64,
    clear_sha256: &str,
) -> Result<()> {
    let mut child = gpg
        .arg("--decrypt")
        .stdin(file)
        .stdout(Stdio::piped())
        .spawn()?;
    let clear = verify_plaintext(
        child.stdout.take().context("missing OpenPGP output")?,
        clear_length,
        clear_sha256,
    );
    ensure!(
        child.wait()?.success(),
        "OpenPGP local authentication failed"
    );
    clear
}

pub(super) async fn read_decrypted(
    client: &Client,
    read: RemoteReadSpec<'_>,
    mut gpg: Command,
    consume: impl FnOnce(ChildStdout) -> Result<()> + Send + 'static,
) -> Result<()> {
    let mut child = gpg
        .arg("--decrypt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut input = child.stdin.take().context("missing OpenPGP input")?;
    let output = child.stdout.take().context("missing OpenPGP output")?;
    let compare = std::thread::spawn(move || consume(output));
    let transfer = read_remote_sha256_resumable(client, read, &mut input).await;
    drop(input);
    let status = child.wait();
    let restored = compare
        .join()
        .map_err(|_| anyhow!("OpenPGP decrypted digest worker failed"));
    transfer?;
    ensure!(status?.success(), "OpenPGP remote authentication failed");
    restored??;
    Ok(())
}

pub(super) struct Park<'a> {
    pub(super) object_key: &'a str,
    pub(super) source_path: &'a Path,
    pub(super) before: &'a Stamp,
    pub(super) clear_sha: &'a str,
    pub(super) cipher_overhead: u64,
    pub(super) key_root: &'a Path,
    pub(super) key_name: &'a str,
    pub(super) tmpfs: &'a Path,
    pub(super) format: &'a str,
}

/// Create an encrypted object without clobbering, then independently restore
/// and rehash its plaintext through the pinned authenticated R2 read path.
pub(super) async fn park(
    client: &Client,
    park: Park<'_>,
    home: &Path,
    save_intent: impl FnOnce(&str, u64) -> Result<()>,
    recover_intent: impl FnOnce(&str, u64) -> Result<Bound>,
    revalidate: impl FnOnce() -> Result<Stamp>,
) -> Result<(RemoteArchive, String)> {
    let Park {
        object_key,
        source_path,
        before,
        clear_sha,
        cipher_overhead,
        key_root,
        key_name,
        tmpfs,
        format,
    } = park;
    let clear_bytes = before.length;
    let existing = head_archive(client, BUCKET, object_key).await?;
    let key_file = key_file(key_root, key_name, existing.is_none())?;
    let (remote, wire_sha) = if let Some(remote) = existing {
        let sha = remote
            .metadata_sha256
            .as_deref()
            .context("missing encrypted custody SHA-256")?;
        saved(&recover_intent(sha, remote.length)?)
            .context("existing encrypted object has no matching local intent")?;
        claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
        let sha = sha.to_owned();
        (remote, sha)
    } else {
        let file = tempfile::NamedTempFile::new_in(tmpfs)?;
        let source = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source_path)?;
        ensure!(
            &Stamp::of(&source.metadata()?) == before,
            "encrypted custody input changed before encryption"
        );
        encrypt(gpg(home, &key_file)?, source, file.reopen()?)?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o400))?;
        file.as_file().sync_all()?;
        verify_encrypted_file(
            gpg(home, &key_file)?,
            File::open(file.path())?,
            clear_bytes,
            clear_sha,
        )?;
        ensure!(
            &revalidate()? == before,
            "encrypted custody input changed during encryption"
        );
        let identity = regular_identity(file.path())?;
        ensure!(
            (clear_bytes..=clear_bytes + cipher_overhead).contains(&identity.length),
            "encrypted custody unexpected ciphertext length"
        );
        let proof = hash_and_etag(file.path(), identity, DEFAULT_PART_SIZE)?;
        let sha = &proof.sha256_hex;
        save_intent(sha, identity.length)?;
        claim_owner(client, host::PREFIX, &owner_bytes()?).await?;
        let (etag, _) = upload_object(
            client,
            BUCKET,
            ObjectUpload {
                key: object_key,
                epoch: None,
                path: file.path(),
                identity,
                length: identity.length,
                sha256: sha,
                format,
            },
            DEFAULT_PART_SIZE,
            2,
            false,
        )
        .await?;
        ensure!(
            etag == proof.multipart_etag,
            "encrypted custody ciphertext multipart receipt differs"
        );
        let remote = head_archive(client, BUCKET, object_key)
            .await?
            .context("encrypted custody ciphertext was not committed")?;
        remote_matches(&remote, object_key, identity.length, sha, Some(&etag))?;
        native_checksum(&remote, &proof, identity.length)?;
        (remote, sha.to_owned())
    };
    let length = remote.length;
    ensure!(
        (clear_bytes..=clear_bytes + cipher_overhead).contains(&length),
        "encrypted custody remote ciphertext length differs"
    );
    remote_matches(&remote, object_key, length, &wire_sha, Some(&remote.etag))?;
    // The upload's temporary ciphertext has been dropped. Use the same
    // bounded volume for a complete authenticated restore of the bundle.
    let restored = tempfile::NamedTempFile::new_in(tmpfs)?;
    let plain_file = restored.reopen()?;
    let expected_sha = clear_sha.to_owned();
    read_decrypted(
        client,
        RemoteReadSpec {
            bucket: BUCKET,
            key: object_key,
            etag: &remote.etag,
            expected_length: length,
            expected_sha256: &wire_sha,
            concurrency: 2,
        },
        gpg(home, &key_file)?,
        move |plain| {
            copy_verified_plaintext(plain, &plain_file, clear_bytes, &expected_sha, || Ok(()))?;
            plain_file.sync_all()?;
            Ok(())
        },
    )
    .await?;
    let restored_identity = regular_identity(restored.path())?;
    let restored_proof = hash_and_etag(restored.path(), restored_identity, DEFAULT_PART_SIZE)?;
    ensure!(
        restored_identity.length == clear_bytes && restored_proof.sha256_hex == clear_sha,
        "encrypted custody restored local bundle differs"
    );
    let final_remote = head_archive(client, BUCKET, object_key)
        .await?
        .context("encrypted custody ciphertext disappeared during verification")?;
    remote_matches(
        &final_remote,
        object_key,
        length,
        &wire_sha,
        Some(&remote.etag),
    )?;
    Ok((remote, wire_sha))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;

    #[test]
    fn published_key_is_owner_only_and_reused() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let private_root = parent.path().join("keys");
        fs::DirBuilder::new().mode(0o700).create(&private_root)?;

        let path = key_file(&private_root, "test.key", true)?;
        let original = fs::read(&path)?;
        assert_eq!(original.len(), 65);
        assert_eq!(fs::metadata(&path)?.mode() & 0o7777, 0o400);
        assert_eq!(key_file(&private_root, "test.key", true)?, path);
        assert_eq!(key_file(&private_root, "test.key", false)?, path);
        assert_eq!(fs::read(&path)?, original);
        Ok(())
    }
}
