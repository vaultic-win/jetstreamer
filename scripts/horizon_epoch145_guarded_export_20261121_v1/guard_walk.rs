// A changed native guard can contain a torn directory walk even while its
// producer is healthy. A stopped verifier can measure the charged root again.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
    },
    path::Path,
    process::Command,
};

fn check_root(path: &Path, pinned: &File) -> Result<()> {
    let now = fs::symlink_metadata(path)?;
    let original = pinned.metadata()?;
    ensure!(
        now.is_dir()
            && path.canonicalize()? == path
            && now.dev() == original.dev()
            && now.ino() == original.ino(),
        "charged directory was replaced"
    );
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    for line in mounts.lines() {
        let mount = line
            .split_whitespace()
            .nth(4)
            .context("missing mount path")?;
        ensure!(
            !Path::new(mount).starts_with(path),
            "mount inside charged root"
        );
    }
    Ok(())
}

fn measure(path: &Path, pinned: &File, cap: u64) -> Result<Option<u64>> {
    check_root(path, pinned)?;
    // Resolve the working directory through the parent's open descriptor.
    // GNU du counts allocated blocks, deduplicates hard links, and keeps
    // symbolic links as entries. Any traversal diagnostic invalidates the pass.
    let cwd = format!("/proc/{}/fd/{}", std::process::id(), pinned.as_raw_fd());
    let result = Command::new("/usr/bin/timeout")
        .args([
            "--kill-after=1s",
            "5s",
            "/usr/bin/du",
            "--no-dereference",
            "--one-file-system",
            "--summarize",
            "--block-size=1",
            "--",
            ".",
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir(cwd)
        .output()?;
    // An ENOENT diagnostic sometimes accompanies ordinary producer churn.
    // Retry the entire pass without using even a byte of its output.
    if result.status.code() == Some(1)
        && !result.stderr.is_empty()
        && std::str::from_utf8(&result.stderr)?.lines().all(|line| {
            line.starts_with("/usr/bin/du: ") && line.ends_with(": No such file or directory")
        })
    {
        return Ok(None);
    }
    ensure!(
        result.status.success() && result.stderr.is_empty(),
        "incomplete allocation walk: {}",
        result.status
    );
    let bytes: u64 = std::str::from_utf8(&result.stdout)?
        .strip_suffix("\t.\n")
        .context("unexpected allocation walk output")?
        .parse()?;
    ensure!(
        bytes > 0 && bytes <= cap,
        "charged root exceeds its guard cap or is empty"
    );
    check_root(path, pinned)?;
    Ok(Some(bytes))
}

fn two_complete_walks(mut walk: impl FnMut() -> Result<Option<u64>>) -> Result<Option<u64>> {
    let mut first: Option<u64> = None;
    for _ in 0..4 {
        if let Some(bytes) = walk()? {
            if let Some(previous) = first {
                return Ok(Some(previous.min(bytes)));
            }
            first = Some(bytes);
        }
    }
    Ok(None)
}

pub(super) fn lower_bound(path: &Path, cap: u64) -> Result<Option<u64>> {
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let measured = two_complete_walks(|| measure(path, &fd, cap))?;
    check_root(path, &fd)?;
    Ok(measured)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn held_guard_counts_only_allocated_distinct_local_inodes() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("root");
        fs::create_dir(&root)?;
        fs::write(root.join("paid"), vec![7u8; 2 << 20])?;
        fs::hard_link(root.join("paid"), root.join("alias"))?;
        File::create(root.join("sparse"))?.set_len(1 << 30)?;
        let outside = dir.path().join("outside");
        fs::write(&outside, vec![0u8; 3 << 20])?;
        symlink(&outside, root.join("link"))?;
        let cap = 3 << 20;
        let expected = ["paid", "sparse", "link"].iter().try_fold(
            root.metadata()?.blocks() * 512,
            |sum, name| -> std::io::Result<u64> {
                Ok(sum + fs::symlink_metadata(root.join(name))?.blocks() * 512)
            },
        )?;
        assert_eq!(lower_bound(&root, cap)?, Some(expected));
        assert!(lower_bound(&root, expected - 1).is_err());
        let alias = dir.path().join("root-link");
        symlink(&root, &alias)?;
        assert!(lower_bound(&alias, cap).is_err());
        let pinned = File::open(&root)?;
        fs::rename(&root, dir.path().join("old-root"))?;
        fs::create_dir(&root)?;
        assert!(measure(&root, &pinned, cap).is_err());
        Ok(())
    }

    #[test]
    fn allocation_churn_needs_a_new_sample_without_granting_credit() -> Result<()> {
        let mut torn = [None, Some(4096), None, None].into_iter();
        assert_eq!(two_complete_walks(|| Ok(torn.next().unwrap()))?, None);
        let mut partial = [None, Some(8192), None, Some(4096)].into_iter();
        assert_eq!(
            two_complete_walks(|| Ok(partial.next().unwrap()))?,
            Some(4096)
        );
        assert!(two_complete_walks(|| Err(anyhow::anyhow!("different filesystem"))).is_err());
        Ok(())
    }
}
