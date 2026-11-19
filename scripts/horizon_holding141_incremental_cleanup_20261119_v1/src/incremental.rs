use super::*;

fn incremental_member(path: &Path, m: &fs::Metadata) -> Result<()> {
    ensure!(
        !m.file_type().is_symlink(),
        "incremental cache contains symlink"
    );
    if m.is_dir() {
        return Ok(());
    }
    ensure!(m.is_file(), "incremental cache contains special entry");
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .context("incremental member name")?;
    let lock = name.strip_suffix(".lock").is_some_and(|s| {
        s.starts_with("s-") && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    if lock {
        // rustc may create executable-mode locks; only empty lock files qualify.
        ensure!(m.len() == 0, "incremental lock carries retained bytes");
        return Ok(());
    }
    let object = name
        .strip_suffix(".o")
        .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric()));
    ensure!(
        m.mode() & 0o111 == 0
            && (object
                || matches!(
                    name,
                    "dep-graph.bin" | "query-cache.bin" | "work-products.bin" | "metadata.rmeta"
                )),
        "incremental cache contains executable, failed-test artifact or unknown member"
    );
    Ok(())
}
pub(super) fn reject_incremental_mounts(bytes: &[u8], target: &Path) -> Result<()> {
    ensure!(bytes.len() <= 4 << 20, "mount census exceeded bound");
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let fields: Vec<_> = line
            .split(|b| *b == b' ')
            .filter(|s| !s.is_empty())
            .collect();
        ensure!(
            fields.len() >= 10 && fields.contains(&b"-".as_slice()),
            "invalid mount census row"
        );
        let raw = fields[4];
        let mut decoded = Vec::new();
        let mut at = 0;
        while at < raw.len() {
            if raw[at] == b'\\' {
                ensure!(
                    at + 3 < raw.len()
                        && raw[at + 1..=at + 3]
                            .iter()
                            .all(|b| (b'0'..=b'7').contains(b)),
                    "invalid escaped mount path"
                );
                let value = (raw[at + 1] - b'0') as u16 * 64
                    + (raw[at + 2] - b'0') as u16 * 8
                    + (raw[at + 3] - b'0') as u16;
                ensure!(value > 0 && value <= 255, "invalid mount path byte");
                decoded.push(value as u8);
                at += 4;
            } else {
                decoded.push(raw[at]);
                at += 1;
            }
        }
        let mounted = Path::new(std::ffi::OsStr::from_bytes(&decoded));
        ensure!(mounted.is_absolute(), "nonabsolute mount path");
        ensure!(
            mounted != target && !mounted.starts_with(target),
            "selected incremental cache contains a mount/bind alias"
        );
    }
    Ok(())
}
pub(super) fn incremental_mounts(target: &Path) -> Result<String> {
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")?
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    reject_incremental_mounts(&bytes, target)?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
pub(super) fn cache_tree_with_policy(
    target: &Path,
    expected_uid: u32,
    incremental: bool,
) -> Result<Value> {
    let root = fs::symlink_metadata(target)?;
    ensure!(
        target.canonicalize()? == target && root.is_dir() && root.uid() == expected_uid,
        "unsafe dev-cache identity"
    );
    let mut queue = vec![(target.to_path_buf(), 0u32)];
    let mut entries = 0u64;
    let mut physical = 0u64;
    let mut regular = 0u64;
    let mut links = 0u64;
    let mut regular_inodes: BTreeMap<(u64, u64), (u64, u64)> = BTreeMap::new();
    let mut directory_inodes = BTreeSet::new();
    let mut member_identities = BTreeMap::new();
    let start = std::time::Instant::now();
    while let Some((path, depth)) = queue.pop() {
        entries += 1;
        ensure!(
            !incremental || start.elapsed().as_secs() < 120,
            "incremental metadata census runtime bound"
        );
        ensure!(
            entries <= 1_000_000 && depth <= 128,
            "cache census exceeded bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == root.dev() && (m.is_dir() || m.is_file() || m.file_type().is_symlink()),
            "foreign mount or special cache entry"
        );
        let first_inode = if incremental {
            incremental_member(&path, &m)?;
            ensure!(
                m.uid() == expected_uid && m.gid() == expected_uid && m.mode() & 0o7002 == 0,
                "incremental member owner/mode changed"
            );
            if m.is_dir() {
                ensure!(
                    directory_inodes.insert((m.dev(), m.ino())),
                    "incremental directory inode alias"
                );
            }
            member_identities.insert(
                path.strip_prefix(target)?.to_path_buf(),
                (
                    m.dev(),
                    m.ino(),
                    m.mode(),
                    m.uid(),
                    m.gid(),
                    m.nlink(),
                    m.len(),
                    m.blocks(),
                    m.mtime(),
                    m.mtime_nsec(),
                    m.ctime(),
                    m.ctime_nsec(),
                ),
            );
            if m.is_file() {
                let count = regular_inodes
                    .entry((m.dev(), m.ino()))
                    .or_insert((0, m.nlink()));
                ensure!(count.1 == m.nlink(), "incremental hardlink count changed");
                count.0 = count
                    .0
                    .checked_add(1)
                    .context("incremental link count overflow")?;
                count.0 == 1
            } else {
                true
            }
        } else {
            true
        };
        if first_inode {
            physical = physical
                .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
                .context("tree overflow")?;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("nonUTF8 cache member")?;
        ensure!(
            !name.ends_with(".jet")
                && !name.ends_with(".sha256")
                && !name.starts_with("snapshot-")
                && !name.ends_with(".tar.zst")
                && !name.ends_with(".tar.bz2"),
            "archive/snapshot/sidecar found in cache"
        );
        if m.is_dir() {
            for e in fs::read_dir(&path)? {
                queue.push((e?.path(), depth + 1));
            }
        } else if m.is_file() {
            regular += 1;
        } else {
            links += 1;
        }
    }
    if incremental {
        ensure!(
            regular_inodes.values().all(|(seen, links)| seen == links),
            "incremental cache has a hardlink outside its selected tree; preserve retained artifact"
        );
    }
    let after = fs::symlink_metadata(target)?;
    ensure!(
        root.dev() == after.dev() && root.ino() == after.ino(),
        "cache root changed"
    );
    Ok(
        json!({"path":target,"device":root.dev(),"inode":root.ino(),"uid":root.uid(),"mode":format!("{:04o}",root.mode()&0o7777),
        "physical_bytes":physical,"regular_files":regular,"symlinks_not_followed":links,"entries":entries,
        "unique_regular_inodes":if incremental {Some(regular_inodes.len())}else{None},
        "physical_bytes_deduplicated":incremental,
        "external_hardlinks_rejected":incremental,
        "home_space_credit_bytes":0,
        "metadata_identity_sha256":if incremental {Some(format!("{:x}",Sha256::digest(serde_json::to_vec(&member_identities)?)))}else{None}}),
    )
}
