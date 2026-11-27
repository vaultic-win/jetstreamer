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
