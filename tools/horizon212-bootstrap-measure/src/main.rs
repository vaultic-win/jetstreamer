//! Stream the exact epoch 212 snapshot once, without extracting it. Authenticate
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

const SNAP: &str = "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/snapshot-91583512-548ThATYndZ7kSzuEgkRx9eVd4MD4hbLgU9ydtjZbbKV.tar.zst";
const SNAP_SHA: &str = "94d7ed8cf39d2b2d665d2c720a3381afb7555d3b3201b7c4d68d6cb0bcbb8a96";
const SNAP_BYTES: u64 = 8715614412;
const SLOT: u64 = 91583512;
const MAX_TAR: u64 = 512 << 30;
const WINDOW_LOG_MAX: u32 = 27;
const MAX_MEMBERS: usize = 2_000_000;
const INPUTS: &[(&str, &str, u64)] = &[
    (
        "/var/lib/jetstreamer/horizon-singleton211-production-node-c17619b16d5d20f0-v1/jetstreamer-node",
        "c17619b16d5d20f0d7aefc6e62ce99e68cc8b2bc88153f82183ebb0d4c5ede1d",
        49006264,
    ),
    (
        "/var/lib/jetstreamer/horizon-singleton211-production-worker-1c89b6a214f9487b-v1/jetstreamer-historical-worker-v1-6-16-shrink-budget",
        "1c89b6a214f9487babfd9dc121ade06037b371fbfcc3243f0e6ec67b6b961c41",
        9050240,
    ),
    (
        "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/genesis.tar.bz2",
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        20144,
    ),
];
const PROOFS: &[(&str, &str)] = &[
    (
        "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/deployment-seal-receipt.json",
        "38083534efb5046d93262bde551fb18dc30dfaec6995d135a61b20fffcdb1b20",
    ),
    (
        "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/snapshot-bindings-212.json",
        "80cb65fdabb9f15cb68e14a7c905b6568be9ecda10f4950c6cd58305f847ac76",
    ),
    (
        "/var/lib/jetstreamer/horizon-focused-212-complete-span-store8-ca2e38b-v1/epoch212-local-content-revalidation.json",
        "10e1735c31b0f7e4dca17a4694a9070998c865dcff14e5ab3f1525418fe59834",
    ),
    (
        "/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/deployment-seal-receipt.json",
        "f6dc9d92e2b0a245daae97da8c7c76f9aee5f58ed30d000a8b50b303bc1b6627",
    ),
    (
        "/var/lib/jetstreamer/horizon-singletons209-212-metadata-0d2856e7-v1/preflight212-singleton.json",
        "d72a58595efaf775b128ef6587e49f86ef42b69e29bd777ac40cf82a1b64ee8a",
    ),
    (
        "/var/lib/jetstreamer/horizon211-node-production-provenance-20261120-v1/node-provenance.json",
        "9599c47062d3923568980391dd3d81cbe2e2ff2a04614fb7494c147baaa5e5bd",
    ),
    (
        "/var/lib/jetstreamer/horizon211-worker-production-provenance-20261120-v1/worker-provenance.json",
        "ddef85d519503b932cd77d9db48a9076ca6a880ab64ff219c6594d2e5848fe44",
    ),
    (
        "/var/lib/jetstreamer/horizon212-generation-observation-v141-v1/generation.json",
        "5b563bb878edd22e8328284b573ec786a209ecccf045286ddf3da810fe11f1c8",
    ),
];

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
            && names.contains(Path::new("snapshots/91583512/91583512")),
        "missing epoch 212 snapshot members"
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
            && format!("{:x}", h.md5.finalize()) == "1cc1397c0fd8d48dcee0c8408783bc2e",
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
        "usage: horizon212-bootstrap-measure"
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
    let result = json!({
        "schema":"horizon212-bootstrap-inputs-v1", "epoch":212, "bootstrap_slot":SLOT,
        "bootstrap_generation":1629232341551900u64, "bootstrap_gcs_md5":"HME5fA/Y1I3O4MhAh4O8Lg==",
        "terminal_root_slot":92015419, "terminal_generation":1629495308790561u64,
        "final_output_slot":92015999, "manifest_fingerprint":"sha256:2786d8eec808864b2e54b91d28709e81fc799f9637d18349cb6a3f12ef308e8c",
        "files":files, "bound_source_evidence":proofs, "snapshot_layout":layout,
        "all_native_input_bytes_verified":true, "snapshot_extracted":false,
        "native_runtime_qualified":false, "entry_replay":false, "admission_authorized":false,
        "remote_mutations":false
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
        "snapshots/91583512/91583512",
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
