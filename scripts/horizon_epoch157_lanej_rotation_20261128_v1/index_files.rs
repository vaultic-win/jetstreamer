// Anza compact index identity, full content verification, leases and kernel references.
fn lock(path: &Path, dev: u64, ino: u64) -> Result<File> {
    ensure!(
        path.canonicalize()? == path,
        "indirect lock {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let s = f.metadata()?;
    ensure!(
        s.is_file() && s.dev() == dev && s.ino() == ino && s.nlink() == 1,
        "lock identity {}",
        path.display()
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "lock busy {}",
        path.display()
    );
    Ok(f)
}

fn file_stamp(p: &Path, inode: u64, links: u64, size: u64) -> Result<Value> {
    ensure!(p.canonicalize()? == p, "indirect index");
    let s = fs::symlink_metadata(p)?;
    ensure!(
        s.is_file()
            && (
                s.dev(),
                s.ino(),
                s.nlink(),
                s.len(),
                s.uid(),
                s.gid(),
                s.mode()
            ) == (64512, inode, links, size, 1001, 1003, 0o100600),
        "index identity {}",
        p.display()
    );
    Ok(json!([
        s.dev(),
        s.ino(),
        s.nlink(),
        s.len(),
        s.blocks(),
        s.mtime(),
        s.mtime_nsec(),
        s.ctime(),
        s.ctime_nsec()
    ]))
}

fn file_hash(p: &Path, inode: u64, links: u64, size: u64, sha: &str) -> Result<Value> {
    let before = file_stamp(p, inode, links, size)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    ensure!(file.metadata()?.ino() == inode, "changed open");
    let mut h = Sha256::new();
    let mut bytes = 0;
    let mut buf = vec![0; 1 << 20];
    let mut f = file.take(size + 1);
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        bytes += n as u64;
        if bytes % (32 << 20) == 0 {
            unsafe {
                libc::posix_fadvise(
                    f.get_ref().as_raw_fd(),
                    (bytes - (32 << 20)) as i64,
                    32 << 20,
                    libc::POSIX_FADV_DONTNEED,
                );
            }
        }
    }
    ensure!(
        bytes == size
            && format!("{:x}", h.finalize()) == sha
            && file_stamp(p, inode, links, size)? == before,
        "index content {}",
        p.display()
    );
    Ok(before)
}

fn kernel_references(roots: &[PathBuf], inodes: &[u64]) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    for root in roots {
        let scan = process_references::scan(Path::new("/proc"), root)?;
        ensure!(
            scan.references.is_empty(),
            "live cache reader {}: {:?}",
            root.display(),
            scan.references
        );
        results.push(json!({"root":root,"processes":scan.inspected_processes}));
    }
    let ids = roots
        .iter()
        .map(|p| p.strip_prefix("/home/sol").map(|s| Path::new("/").join(s)))
        .collect::<Result<Vec<_>, _>>()?;
    let mut namespaces = BTreeSet::new();
    for proc in fs::read_dir("/proc")? {
        let p = proc?.path();
        if !p
            .file_name()
            .unwrap()
            .as_encoded_bytes()
            .iter()
            .all(u8::is_ascii_digit)
        {
            continue;
        }
        let census = (|| -> std::io::Result<()> {
            // Inode checks also cover descriptors and mappings reached through a bind of an ancestor.
            for fd in fs::read_dir(p.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(m) if m.dev() == 64512 && inodes.contains(&m.ino()) => {
                        return Err(std::io::Error::other("a selected compact index is open"));
                    }
                    Ok(_) => (),
                    Err(e)
                        if e.kind() == ErrorKind::NotFound
                            || e.raw_os_error() == Some(libc::ESRCH) =>
                    {
                        ()
                    }
                    Err(e) => return Err(e),
                }
            }
            let mut maps = BufReader::new(File::open(p.join("maps"))?);
            let mut line = String::new();
            while maps.read_line(&mut line)? > 0 {
                let mut f = line.split_ascii_whitespace();
                if let (Some(device), Some(inode)) = (f.nth(3), f.next()) {
                    if device == "fc:00" && inode.parse::<u64>().is_ok_and(|i| inodes.contains(&i))
                    {
                        return Err(std::io::Error::other("a selected compact index is mapped"));
                    }
                }
                line.clear();
            }
            let ns = fs::metadata(p.join("ns/mnt"))?.ino();
            if namespaces.contains(&ns) {
                return Ok(());
            }
            let info = fs::read_to_string(p.join("mountinfo"))?;
            for line in info.lines() {
                let mut cols = line.split_ascii_whitespace();
                let f = cols.nth(3).unwrap_or("");
                if ids.iter().any(|id| Path::new(f).starts_with(id)) {
                    return Err(std::io::Error::other(
                        "qualification cache mounted in a namespace",
                    ));
                }
            }
            namespaces.insert(ns);
            Ok(())
        })();
        if let Err(e) = census {
            if e.kind() != ErrorKind::NotFound && e.raw_os_error() != Some(libc::ESRCH) {
                return Err(e.into());
            }
        }
    }
    Ok(results)
}

/// Final per-file journal. Recovery credits zero when a crash lost the unlink receipt.
fn remove_checked(
    path: &Path,
    inode: u64,
    base: &Path,
    intent: &Value,
    validate: impl FnOnce() -> Result<u64>,
) -> Result<Value> {
    let receipt = base.join(format!("REMOVED_{inode}.json"));
    if receipt.try_exists()? {
        ensure!(
            matches!(fs::symlink_metadata(path),Err(e) if e.kind()==ErrorKind::NotFound),
            "retired target returned"
        );
        let old = evidence::reference(&receipt)?;
        let row = evidence::bound(&old)?;
        ensure!(
            row["path"] == json!(path) && row["inode"] == inode && row["intent"] == *intent,
            "different file retirement"
        );
        return Ok(old);
    }
    let v = match fs::symlink_metadata(path) {
        Ok(_) => {
            let allocation = validate()?;
            fs::remove_file(path)?;
            File::open(path.parent().context("parent")?)?.sync_all()?;
            ensure!(
                matches!(fs::symlink_metadata(path),Err(e) if e.kind()==ErrorKind::NotFound),
                "failed cache removal"
            );
            json!({"path":path,"inode":inode,"unlinked_allocation":allocation,"intent":intent})
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            json!({"path":path,"inode":inode,"unlinked_allocation":0,"recovered_absence":true,"intent":intent})
        }
        Err(e) => return Err(e.into()),
    };
    evidence::receipt(&receipt, &v)
}
