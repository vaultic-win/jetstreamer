// b8e1f583 maps and staged-body parser bodies unchanged; visibility only. No old237 scope imported.
use super::*;

pub(super) fn staged_body(path: &Path) -> Result<Vec<u8>> {
    let mut target = path.to_path_buf();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..8 {
        ensure!(seen.insert(target.clone()), "cyclic staged recipe symlink");
        let m = fs::symlink_metadata(&target)?;
        if m.file_type().is_symlink() {
            let link = fs::read_link(&target)?;
            target = if link.is_absolute() {
                link
            } else {
                target.parent().context("symlink parent")?.join(link)
            };
            continue;
        }
        if target == Path::new("/dev/null")
            && m.mode() & libc::S_IFMT == libc::S_IFCHR
            && m.rdev() == libc::makedev(1, 3)
            && m.uid() == 0
        {
            // A positively identified systemd mask has no executable recipe.
            return Ok(Vec::new());
        }
        ensure!(
            m.is_file() && m.len() <= LIMIT,
            "uninspected oversized/non-regular staged recipe"
        );
        let mut f = open_read(&target)?;
        let before = f.metadata()?;
        let mut bytes = Vec::new();
        (&mut f).take(LIMIT + 1).read_to_end(&mut bytes)?;
        let after = f.metadata()?;
        ensure!(
            bytes.len() as u64 == before.len()
                && bytes.len() as u64 <= LIMIT
                && identity(&before) == identity(&after)
                && before.ctime() == after.ctime()
                && before.ctime_nsec() == after.ctime_nsec(),
            "staged recipe changed while reading"
        );
        return Ok(bytes);
    }
    anyhow::bail!("staged recipe symlink chain exceeds bound")
}

pub(super) fn maps_reference(bytes: &[u8], device: u64, inode: u64) -> Result<bool> {
    let text = std::str::from_utf8(bytes).context("non-UTF8 maps evidence")?;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().take(5).collect();
        ensure!(fields.len() == 5, "uninspected malformed maps row");
        let (major, minor) = fields[3].split_once(':').context("malformed maps device")?;
        let major = u64::from_str_radix(major, 16)?;
        let minor = u64::from_str_radix(minor, 16)?;
        let mapped_inode: u64 = fields[4].parse()?;
        if major == u64::from(libc::major(device))
            && minor == u64::from(libc::minor(device))
            && mapped_inode == inode
        {
            return Ok(true);
        }
    }
    Ok(false)
}
