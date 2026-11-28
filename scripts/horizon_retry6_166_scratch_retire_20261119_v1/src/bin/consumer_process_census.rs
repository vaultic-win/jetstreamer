//! Read-only process closure for every node of a hash-bound metadata census.
//! Uses the already reviewed fail-closed scanner; no process or file mutation.
#[path = "../process_references.rs"]
mod process_references;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

fn identity(m: &fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0 && args.len() == 3,
        "root; consumer_process_census CENSUS SHA256"
    );
    let path = Path::new(&args[1]);
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical census path required"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let md = file.metadata()?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o222 == 0
            && md.len() <= 1 << 20,
        "immutable root-owned bounded census required"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((1 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == md.len()
            && identity(&file.metadata()?) == identity(&md)
            && identity(&fs::symlink_metadata(path)?) == identity(&md)
            && format!("{:x}", Sha256::digest(&bytes)) == args[2],
        "census changed"
    );
    let census: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        census["schema"] == "horizon-closed166-retry6-transitive-consumer-census-v1",
        "retry6 metadata census required"
    );
    let nodes = census["nodes"].as_array().context("census nodes")?;
    ensure!(
        !nodes.is_empty() && nodes.len() <= 128,
        "bounded complete node set required"
    );
    let mut targets = BTreeSet::new();
    for node in nodes {
        let target = PathBuf::from(node["file"]["path"].as_str().context("node path")?);
        ensure!(
            target.is_absolute() && targets.insert(target),
            "duplicate or relative target"
        );
    }
    let mut results = Vec::new();
    for target in targets {
        let scan = process_references::scan(Path::new("/proc"), &target)?;
        eprintln!(
            "completed process census for {}; {} references",
            target.display(),
            scan.references.len()
        );
        results.push(json!({"target":target,"scan":scan}));
    }
    ensure!(
        identity(&file.metadata()?) == identity(&md)
            && identity(&fs::symlink_metadata(path)?) == identity(&md),
        "census changed during process scan"
    );
    println!(
        "{}",
        json!({"schema":"horizon-retry6-consumer-process-census-v1",
        "metadata_census":{"path":path,"sha256":args[2]},"results":results,
        "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "retirement_authorized":false,"resource_credit_bytes":0,"remote_mutations":false})
    );
    Ok(())
}
