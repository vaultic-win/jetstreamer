//! Read-only exact-tree consumer census for operator cleanup review.
//! A successful census does not authorize deletion or prove staged work absent.
#[path = "../scripts/horizon_standard166_scratch_retirement_20261110_v1/source/process_references.rs"]
mod process_references;
use anyhow::{Result, ensure};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    target: PathBuf,
    output: PathBuf,
}
fn digest(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn identity(m: &fs::Metadata) -> (u64, u64, u32, u32, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.uid(),
        m.mode(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: horizon_process_census PLAN PLAN_SHA256 SELF_SHA256"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "root required for complete process visibility"
    );
    ensure!(
        digest(Path::new("/proc/self/exe"))? == args[3],
        "self digest mismatch"
    );
    let plan_path = Path::new(&args[1]);
    ensure!(
        plan_path.is_absolute() && plan_path.canonicalize()? == plan_path,
        "noncanonical plan"
    );
    let mut plan_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(plan_path)?;
    let m = plan_file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= 1 << 20,
        "invalid plan custody"
    );
    let mut bytes = Vec::new();
    plan_file.read_to_end(&mut bytes)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == args[2],
        "plan digest mismatch"
    );
    let plan: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        plan.schema == "horizon-process-census-plan-v1",
        "unknown plan schema"
    );
    ensure!(
        plan.target.is_absolute() && plan.target.canonicalize()? == plan.target,
        "noncanonical target"
    );
    let before = fs::symlink_metadata(&plan.target)?;
    ensure!(before.is_dir(), "target is not a directory");
    let parent = plan
        .output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing output parent"))?;
    ensure!(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "noncanonical output parent"
    );
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "output requires root-private parent"
    );
    let scan = process_references::scan(Path::new("/proc"), &plan.target)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(&plan.target)?),
        "target identity changed during census"
    );
    let report = serde_json::json!({"schema":"horizon-process-census-v1","target":plan.target,"target_identity":identity(&before),"plan_sha256":args[2],"self_sha256":args[3],"scan":scan,"deletion_authorized":false,"staged_dependencies_checked":false});
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&plan.output)?;
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"receipt":plan.output,"inspected_processes":scan.inspected_processes,"references":scan.references})
    );
    Ok(())
}
