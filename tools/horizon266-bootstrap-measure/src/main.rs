//! Stream the selected historical snapshot once, without extracting it. Authenticate
//! the selected launch inputs and measure the tar layout used to size cold init.
use anyhow::{Context, Result, ensure};
use md5::Md5;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, BufReader, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path},
};

#[cfg(not(feature = "epoch267"))]
mod profile {
    pub(super) const SNAP: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/snapshot-114910768-HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK.tar.zst";
    pub(super) const SNAP_SHA: &str =
        "c3bfdbf63b7941a9c111a668bc03f71b197203eb52a45c9ea39e94797272babb";
    pub(super) const SNAP_BYTES: u64 = 16_826_334_350;
    pub(super) const SLOT: u64 = 114_910_768;
    pub(super) const INPUTS: &[(&str, &str, u64)] = &[
        (
            "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-node",
            "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
            48454432,
        ),
        (
            "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/jetstreamer-historical-worker-v1-8-11",
            "9f7763ff57c27bcfa112814701314c1b36366a35c7e171a7d6f3ee97ee7330ae",
            6491264,
        ),
        (
            "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            20144,
        ),
    ];
    pub(super) const PROOFS: &[(&str, &str)] = &[
        (
            "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/deployment-seal-receipt.json",
            "740d006bad5f3d0d79035d3797ed512e14b9f44d130e53d4b3666e4b52ad4e2e",
        ),
        (
            "/var/lib/jetstreamer/horizon-capability-266-266-current-46b4b4a-v1/node-manifest-capability.json",
            "085a9c1ee57b7416febf1b7a623a00e62511afbbda9df1ae5d1b41f695c147be",
        ),
        (
            "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1/preflight-233-301-target4-publish300-46b4b4a.json",
            "3c32a5d78e764cb982b246ab123eadf4fddb5eb51b6377f7afbb196aef714b81",
        ),
        (
            "/var/lib/jetstreamer/horizon-contiguous-267-270-current-46b4b4a-v1/deployment-seal-receipt.json",
            "2c18e18c5412c885b313ee06bf5ab806e0d5021b66da7ccbaa0dbe8b258b7723",
        ),
    ];

    pub(super) const EPOCH: u64 = 266;
    pub(super) const GENERATION: u64 = 1641767242524970;
    pub(super) const MD5: &str = "7eb46dbd66ca133396fe89c841adcc79";
    pub(super) const MD5_BASE64: &str = "frRtvWbKEzOW/onIQa3MeQ==";
    pub(super) const LAST_ROOT: u64 = 115343448;
    pub(super) const LAST_GENERATION: u64 = 1642024788266141;
}
#[cfg(feature = "epoch267")]
#[path = "cohort267.rs"]
mod profile;
use profile::*;

const MAX_TAR: u64 = 512 << 30;
const WINDOW_LOG_MAX: u32 = 27;
const MAX_MEMBERS: usize = 2_000_000;

fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn open(path: &Path, max: u64) -> Result<(File, Value)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input {}",
        path.display()
    );
    for dir in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(dir)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted directory {}",
            dir.display()
        );
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= max,
        "input custody or size {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let id = identity(&m);
    ensure!(identity(&f.metadata()?) == id, "open race");
    Ok((f, id))
}
fn finish(path: &Path, f: &File, id: &Value, sha: &str) -> Result<Value> {
    ensure!(
        identity(&f.metadata()?) == *id && identity(&fs::symlink_metadata(path)?) == *id,
        "input changed during measurement {}",
        path.display()
    );
    Ok(json!({"path":path,"identity":id,"sha256":sha}))
}
fn small(name: &str, sha: &str, max: u64) -> Result<Value> {
    let path = Path::new(name);
    let (mut f, id) = open(path, max)?;
    let mut h = Sha256::new();
    let n = io::copy(&mut f.by_ref().take(max + 1), &mut h)?;
    ensure!(
        id["bytes"] == n && format!("{:x}", h.finalize()) == sha,
        "input length or digest {name}"
    );
    finish(path, &f, &id, sha)
}
struct Compressed<R> {
    inner: R,
    sha: Sha256,
    md5: Md5,
    bytes: u64,
}
impl<R: Read> Read for Compressed<R> {
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(dst)?;
        self.sha.update(&dst[..n]);
        self.md5.update(&dst[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}
#[derive(Default)]
struct Totals {
    files: u64,
    logical: u64,
    packed: u64,
    rounded: u64,
    largest: u64,
}
impl Totals {
    fn add(&mut self, size: u64, packed: u64) -> Result<()> {
        ensure!(packed <= size, "stored tar bytes exceed logical size");
        self.files += 1;
        self.logical = self.logical.checked_add(size).context("logical overflow")?;
        self.packed = self
            .packed
            .checked_add(packed)
            .context("payload overflow")?;
        self.rounded = self
            .rounded
            .checked_add(
                size.checked_next_multiple_of(4096)
                    .context("rounding overflow")?,
            )
            .context("allocation overflow")?;
        self.largest = self.largest.max(size);
        Ok(())
    }
    fn json(&self) -> Value {
        json!({"files":self.files,"logical_bytes":self.logical,"tar_payload_bytes":self.packed,"sum_logical_rounded_4096":self.rounded,"largest_file_bytes":self.largest})
    }
}
fn census<R: Read>(reader: &mut R) -> Result<Value> {
    let mut archive = tar::Archive::new(reader);
    let (mut files, mut accounts) = (Totals::default(), Totals::default());
    let mut names = HashSet::new();
    let mut dirs = 0u64;
    let mut sparse = 0u64;
    for entry in archive.entries()? {
        let e = entry?;
        let p = e.path()?;
        ensure!(
            p.as_os_str().len() <= 512
                && p.components()
                    .all(|c| matches!(c, Component::Normal(_) | Component::CurDir)),
            "unsafe tar path"
        );
        let p: std::path::PathBuf = p.components().filter(|c| *c != Component::CurDir).collect();
        ensure!(
            names.len() < MAX_MEMBERS && names.insert(p.clone()),
            "duplicate or excessive tar members"
        );
        let t = e.header().entry_type();
        if t.is_dir() {
            ensure!(e.size() == 0, "nonempty directory");
            dirs += 1;
            continue;
        }
        ensure!(
            t.is_file() || t.is_gnu_sparse(),
            "unexpected tar entry type at {}",
            p.display()
        );
        let logical = e.size();
        let packed = e.header().entry_size()?;
        files.add(logical, packed)?;
        sparse += u64::from(t.is_gnu_sparse());
        if p.parent() == Some(Path::new("accounts")) {
            accounts.add(logical, packed)?;
        }
    }
    ensure!(
        accounts.files > 0
            && names.contains(Path::new("version"))
            && names.contains(Path::new("snapshots/status_cache"))
            && names.contains(Path::new(&format!("snapshots/{SLOT}/{SLOT}"))),
        "missing epoch {EPOCH} snapshot members"
    );
    Ok(
        json!({"files":files.json(),"accounts":accounts.json(),"directories":dirs,"sparse_files":sparse}),
    )
}
fn snapshot() -> Result<(Value, Value)> {
    let path = Path::new(SNAP);
    let (f, id) = open(path, SNAP_BYTES)?;
    ensure!(id["bytes"] == SNAP_BYTES, "snapshot length");
    let hashed = Compressed {
        inner: &f,
        sha: Sha256::new(),
        md5: Md5::new(),
        bytes: 0,
    };
    let mut decoder = zstd::stream::read::Decoder::new(hashed)?;
    decoder.window_log_max(WINDOW_LOG_MAX)?;
    let mut decoded = BufReader::with_capacity(1 << 20, decoder.take(MAX_TAR + 1));
    let mut layout = census(&mut decoded)?;
    let mut tail = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = decoded.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ensure!(buf[..n].iter().all(|b| *b == 0), "nonzero tar trailer");
        tail += n as u64;
    }
    let limited = decoded.into_inner();
    let total = MAX_TAR + 1 - limited.limit();
    ensure!(
        total <= MAX_TAR && total.is_multiple_of(512) && tail >= 512,
        "truncated or over-limit tar"
    );
    let h = limited.into_inner().finish().into_inner();
    ensure!(
        h.bytes == SNAP_BYTES
            && format!("{:x}", h.sha.finalize()) == SNAP_SHA
            && format!("{:x}", h.md5.finalize()) == MD5,
        "snapshot does not match sealed SHA-256 and GCS MD5"
    );
    layout["decoded_tar_bytes"] = json!(total);
    layout["zstd_window_max_bytes"] = json!(1u64 << WINDOW_LOG_MAX);
    layout["trailing_zero_bytes_after_first_terminator"] = json!(tail);
    Ok((finish(path, &f, &id, SNAP_SHA)?, layout))
}
fn main() -> Result<()> {
    ensure!(
        std::env::args_os().len() == 1,
        "usage: horizon266-bootstrap-measure"
    );
    let proofs = PROOFS
        .iter()
        .map(|&(p, s)| small(p, s, 8 << 20))
        .collect::<Result<Vec<_>>>()?;
    let mut files = Vec::new();
    for &(p, s, n) in INPUTS {
        let value = small(p, s, n)?;
        ensure!(value["identity"]["bytes"] == n, "wrong input size");
        files.push(value);
    }
    let (snap, layout) = snapshot()?;
    files.insert(0, snap);
    for v in files.iter().chain(&proofs) {
        ensure!(
            identity(&fs::symlink_metadata(
                v["path"].as_str().context("bound path")?
            )?) == v["identity"],
            "sealed input changed before receipt"
        );
    }
    let indexes_verified = format!("epoch{EPOCH}_indexes_verified");
    let result = json!({
        "schema": format!("horizon{EPOCH}-bootstrap-measure-v1"),
        "epoch": EPOCH,
        "bootstrap_slot": SLOT,
        "bootstrap_generation": GENERATION,
        "bootstrap_gcs_md5": MD5_BASE64,
        "terminal_root_slot": LAST_ROOT,
        "terminal_generation": LAST_GENERATION,
        "files": files,
        "bound_source_evidence": proofs,
        "snapshot_layout": layout,
        "snapshot_extracted": false,
        "terminal_snapshot_body_verified": false,
        (indexes_verified): false,
        "native_runtime_qualified": false,
        "entry_replay": false,
        "admission_authorized": false,
        "remote_mutations": false,
    });
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn archive(names: &[&str]) -> Vec<u8> {
        let mut a = tar::Builder::new(Vec::new());
        for &name in names {
            let mut h = tar::Header::new_gnu();
            h.set_size(3);
            h.set_mode(0o400);
            h.set_cksum();
            a.append_data(&mut h, name, &b"abc"[..]).unwrap();
        }
        a.into_inner().unwrap()
    }
    const NAMES: &[&str] = &[
        "version",
        "accounts/1.0",
        "snapshots/status_cache",
        #[cfg(not(feature = "epoch267"))]
        "snapshots/114910768/114910768",
        #[cfg(feature = "epoch267")]
        "snapshots/115343448/115343448",
    ];
    #[test]
    fn complete_layout_and_4k_rounding() {
        let result = census(&mut archive(NAMES).as_slice()).unwrap();
        assert_eq!(result["accounts"]["files"], 1);
        assert_eq!(result["files"]["logical_bytes"], 12);
        assert_eq!(result["files"]["sum_logical_rounded_4096"], 16384);
    }
    #[test]
    fn rejects_wrong_slot_and_duplicate_and_corrupt_header() {
        let mut wrong = NAMES.to_vec();
        wrong[3] = "snapshots/1/1";
        assert!(census(&mut archive(&wrong).as_slice()).is_err());
        let mut duplicates = NAMES.to_vec();
        duplicates.push(NAMES[0]);
        assert!(census(&mut archive(&duplicates).as_slice()).is_err());
        let mut damaged = archive(NAMES);
        damaged[0] ^= 1;
        assert!(census(&mut damaged.as_slice()).is_err());
    }
}
