//! Resolve the authenticated plan inputs for the epoch167 retry8 preparer.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    process::Command,
};

mod peer_binding;
const ROOT_CAP: u64 = 309_237_645_312;
const THREAD: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn lower_hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn directory(p: &Path) -> Result<File> {
    ensure!(p.is_absolute(), "absolute path required");
    let mut d = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    for c in p.components() {
        match c {
            Component::RootDir => (),
            Component::Normal(n) => {
                let n = CString::new(n.as_bytes())?;
                let fd = unsafe {
                    libc::openat(
                        d.as_raw_fd(),
                        n.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                ensure!(fd >= 0, "directory traversal failed: {}", p.display());
                d = unsafe { File::from_raw_fd(fd) };
            }
            _ => anyhow::bail!("noncanonical path"),
        }
    }
    ensure!(p.canonicalize()? == p, "directory alias");
    Ok(d)
}
fn raw(p: &Path, limit: u64, immutable: bool) -> Result<Vec<u8>> {
    let parent = directory(p.parent().context("parent")?)?;
    let name = CString::new(p.file_name().context("filename")?.as_bytes())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    ensure!(fd >= 0, "open evidence failed: {}", p.display());
    let mut f = unsafe { File::from_raw_fd(fd) };
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.uid() == 0
            && a.nlink() == 1
            && a.len() <= limit
            && a.mode() & 0o022 == 0
            && (!immutable || a.mode() & 0o222 == 0),
        "unsafe evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == a.len()
            && identity(&a) == identity(&f.metadata()?)
            && identity(&a) == identity(&fs::symlink_metadata(p)?),
        "evidence changed"
    );
    Ok(bytes)
}
fn bound(b: &Bound) -> Result<Value> {
    ensure!(lower_hex(&b.sha256, 64), "digest shape");
    let bytes = raw(&b.path, 32 << 20, false)?;
    ensure!(
        digest(&bytes) == b.sha256,
        "bound evidence differs: {}",
        b.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn native(unit: &str) -> Result<BTreeMap<String, String>> {
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "native unit query failed"
    );
    let mut m = BTreeMap::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("unit field")?;
        ensure!(
            m.insert(k.into(), v.into()).is_none(),
            "duplicate native field"
        );
    }
    Ok(m)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerInput {
    schema: String,
    epoch: u64,
    attempt: String,
    admission: Bound,
    guard_protection: Bound,
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [flag] if flag == "--check-lineage" => {
            let peer_root = peer_binding::lineage()?;
            println!(
                "{}",
                json!({"schema":"horizon-167-retry8-lineage-v1","peer_root":peer_root,
                "epoch":167,"candidate_root":peer_binding::CANDIDATE_ROOT,"replay_admission":false})
            );
        }
        [plan, flag, sha] if flag == "--plan-sha256" => {
            let input: PeerInput = serde_json::from_value(bound(&Bound {
                path: plan.into(),
                sha256: sha.clone(),
            })?)?;
            ensure!(
                input.schema == "horizon-167-retry8-live166-receipts-v1"
                    && input.epoch == 167
                    && input.attempt == "local3retry8",
                "wrong peer input scope"
            );
            println!(
                "{}",
                peer_binding::observe(&input.admission, &input.guard_protection)?
            );
        }
        _ => anyhow::bail!("usage: prepare-peer --check-lineage | PLAN --plan-sha256 SHA256"),
    }
    Ok(())
}
