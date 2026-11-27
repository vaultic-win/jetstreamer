use super::*;
use std::os::fd::AsRawFd;
pub(super) fn path(row: &Value) -> Result<&Path> {
    Ok(Path::new(string(row, "path")?))
}

pub(super) fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime() * 1_000_000_000 + m.mtime_nsec(),
        m.ctime() * 1_000_000_000 + m.ctime_nsec()
    ])
}

pub(super) fn bound_metadata(m: &fs::Metadata, row: &Value) -> bool {
    row["identity"] == identity(m)
        && (row["links"].is_null() || row["links"] == m.nlink())
        && (row["uid"].is_null() || row["uid"] == m.uid())
        && (row["gid"].is_null() || row["gid"] == m.gid())
        && (row["mode"].is_null() || row["mode"] == format!("0o{:o}", m.mode() & 0o7777))
}

pub(super) fn pinned_path(row: &Value) -> Result<&Path> {
    let p = path(row)?;
    ensure!(
        p.canonicalize()? == p && bound_metadata(&p.symlink_metadata()?, row),
        "bound path changed: {}",
        p.display()
    );
    Ok(p)
}

pub(super) fn open_input(row: &Value) -> Result<File> {
    let p = pinned_path(row)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && bound_metadata(&m, row),
        "changed input: {}",
        p.display()
    );
    Ok(f)
}

pub(super) fn digest(row: &Value) -> Result<String> {
    let mut f = open_input(row)?;
    let mut hash = Sha256::new();
    std::io::copy(&mut f, &mut hash)?;
    ensure!(
        bound_metadata(&f.metadata()?, row),
        "input changed during hash"
    );
    pinned_path(row)?;
    Ok(format!("{:x}", hash.finalize()))
}

pub(super) fn bound_bytes(row: &Value, limit: u64) -> Result<Vec<u8>> {
    let bytes = read(path(row)?, limit)?;
    ensure!(
        sha(&bytes) == string(row, "sha256")?,
        "bound file digest changed: {}",
        row["path"]
    );
    Ok(bytes)
}

pub(super) fn verify_campaign_lock(file: &File, manifest: &Value) -> Result<()> {
    let row = &manifest["scope"]["leases"]["global_operation"];
    let p = pinned_path(row)?;
    ensure!(
        p == Path::new("/run/horizon-epoch171-to136-g1.operation.lock")
            && bound_metadata(&file.metadata()?, row),
        "campaign operation lock changed"
    );
    Ok(())
}

pub(super) fn leases(manifest: &Value) -> Result<Vec<File>> {
    let rows = &manifest["scope"]["leases"];
    ["local_mutation", "exact_epoch"]
        .iter()
        .map(|name| {
            let f = open_input(&rows[*name])?;
            ensure!(
                unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "occupied {}",
                rows[*name]["path"]
            );
            Ok(f)
        })
        .collect()
}

pub(super) fn verify_image(base: &Path, image: &str) -> Result<()> {
    let tools = base.join("tools");
    let seal = evidence(&tools.join("deployment-seal-receipt.json"))?;
    ensure!(
        seal["destination"] == tools.to_str().context("tools path")?
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .any(|row| row["name"] == "retire"
                    && row["mode"] == "0555"
                    && row["sha256"] == image)),
        "retirement executable is not bound by its deployment seal"
    );
    Ok(())
}

pub(super) fn staged_references(
    root: &Path,
    needles: &[&Path],
    allowed_ancestors: &[&Path],
    visited: &mut std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let p = entry?.path();
        let meta = p.symlink_metadata()?;
        if meta.is_dir() {
            staged_references(&p, needles, allowed_ancestors, visited)?;
            continue;
        }
        if !meta.is_file() && !meta.file_type().is_symlink() {
            continue;
        }
        let canonical = match p.canonicalize() {
            Ok(value) => value,
            Err(error)
                if meta.file_type().is_symlink()
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if !canonical.metadata()?.is_file() || !visited.insert(canonical.clone()) {
            continue;
        }
        let bytes = read_staged_unit(&canonical)?;
        for (i, needle) in needles.iter().enumerate() {
            if process_references::encoded_reference(
                &bytes,
                needle.as_os_str().as_encoded_bytes(),
                true,
            ) {
                // Only known, separately authenticated fragments can name the
                // broad retry4 ancestor. Neither can name the run or target.
                ensure!(
                    i == 2 && allowed_ancestors.contains(&canonical.as_path()),
                    "staged reference to stopped run: {}",
                    canonical.display()
                );
            }
        }
    }
    Ok(())
}

fn read_staged_unit(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?
        .take((4 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 4 << 20,
        "oversized indirect unit: {}",
        path.display()
    );
    Ok(bytes)
}
