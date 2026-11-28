//! Closed epoch-265 input inventory. No native runtime or admission authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod index;
mod profile;
use profile::*;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("missing {key}"))
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn exact_keys(v: &Value, keys: &[&str]) -> Result<()> {
    let object = v.as_object().context("object required")?;
    ensure!(
        object.len() == keys.len() && keys.iter().all(|k| object.contains_key(*k)),
        "unexpected fields"
    );
    Ok(())
}
fn identity(m: &fs::Metadata) -> Value {
    json!({"device":m.dev(),"inode":m.ino(),"bytes":m.len(),"uid":m.uid(),"gid":m.gid(),"mode":m.mode(),"nlink":m.nlink(),"mtime":m.mtime(),"mtime_nsec":m.mtime_nsec(),"ctime":m.ctime(),"ctime_nsec":m.ctime_nsec()})
}
fn open_sealed(path: &Path) -> Result<(File, Value)> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical sealed file"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.gid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "unsealed file: {}",
        path.display()
    );
    let id = identity(&m);
    ensure!(
        id == identity(&fs::symlink_metadata(path)?),
        "path changed at open"
    );
    Ok((file, id))
}
fn stable(path: &Path, file: &File, id: &Value) -> Result<()> {
    ensure!(
        *id == identity(&file.metadata()?) && *id == identity(&fs::symlink_metadata(path)?),
        "input changed: {}",
        path.display()
    );
    Ok(())
}
fn small(path: &Path, expected: &str) -> Result<Vec<u8>> {
    ensure!(hex(expected), "invalid digest");
    let (mut f, id) = open_sealed(path)?;
    ensure!(
        id["bytes"].as_u64().context("file bytes")? <= 16 << 20,
        "metadata exceeds bound"
    );
    let mut bytes = Vec::new();
    (&mut f).take((16 << 20) + 1).read_to_end(&mut bytes)?;
    stable(path, &f, &id)?;
    ensure!(
        bytes.len() <= 16 << 20 && digest(&bytes) == expected,
        "metadata digest differs"
    );
    Ok(bytes)
}
fn bound(v: &Value) -> Result<(PathBuf, String)> {
    exact_keys(v, &["path", "sha256"])?;
    let p = PathBuf::from(text(v, "path")?);
    let h = text(v, "sha256")?.to_string();
    ensure!(p.is_absolute() && hex(&h), "invalid binding");
    Ok((p, h))
}
fn bound_json(v: &Value) -> Result<Value> {
    let (p, h) = bound(v)?;
    Ok(serde_json::from_slice(&small(&p, &h)?)?)
}
fn verify_file(path: &Path, expected: &str, size: u64) -> Result<Value> {
    ensure!(hex(expected), "invalid file digest");
    let (mut f, id) = open_sealed(path)?;
    ensure!(id["bytes"] == size, "file size differs");
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = vec![0; 1 << 20];
    let started = Instant::now();
    let mut last = Instant::now();
    eprintln!("{} hash start {} bytes={size}", now()?, path.display());
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        bytes = bytes.checked_add(n as u64).context("byte overflow")?;
        ensure!(bytes <= size, "input grew");
        if last.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "{} hashing {} bytes={bytes}/{size} elapsed_seconds={}",
                now()?,
                path.display(),
                started.elapsed().as_secs()
            );
            last = Instant::now();
        }
    }
    stable(path, &f, &id)?;
    ensure!(
        bytes == size && format!("{:x}", hash.finalize()) == expected,
        "whole-file digest differs"
    );
    eprintln!("{} hash complete {}", now()?, path.display());
    Ok(json!({"path":path,"sha256":expected,"identity":id}))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn no_authority() -> Value {
    json!({"native_runtime_qualified":false,"codec_tests_executed":false,"replay_launch_authorized":false,"admission_authorized":false,"publication_authorized":false,"resource_release_authorized":false,"remote_mutations":false,"r2_mutations":false})
}
fn codec_sources(sources: &Value) -> Result<()> {
    let sources = sources.as_array().context("codec sources")?;
    ensure!(sources.len() == CODEC.len(), "codec source census differs");
    let mut seen = BTreeSet::new();
    for entry in sources {
        exact_keys(entry, &["repository_path", "source_commit", "file"])?;
        let name = text(entry, "repository_path")?;
        ensure!(
            seen.insert(name) && entry["source_commit"] == SOURCE,
            "duplicate or wrong source revision"
        );
        let (_, expected) = CODEC
            .iter()
            .find(|(p, _)| *p == name)
            .context("unknown codec source")?;
        ensure!(
            bound(&entry["file"])?.1 == *expected,
            "old or changed instruction codec"
        );
    }
    Ok(())
}
fn validate_plan(plan: &Value) -> Result<()> {
    exact_keys(
        plan,
        &[
            "schema",
            "cache",
            "cache_seal",
            "codec_sources",
            "output",
            "authority",
        ],
    )?;
    ensure!(
        plan["schema"] == "horizon265-input-packet-plan-v1" && plan["authority"] == no_authority(),
        "wrong plan or authority"
    );
    let cache = Path::new(text(plan, "cache")?);
    ensure!(
        cache.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && cache
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon265-index-")
                    && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')),
        "foreign cache namespace"
    );
    let (seal, _) = bound(&plan["cache_seal"])?;
    ensure!(
        seal == cache.join("deployment-seal-receipt.json"),
        "cache seal path differs"
    );
    codec_sources(&plan["codec_sources"])?;
    let output = Path::new(text(plan, "output")?);
    let parent = output.parent().context("output parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        output.is_absolute()
            && parent.canonicalize()? == parent
            && pm.is_dir()
            && pm.uid() == 0
            && pm.gid() == 0
            && pm.mode() & 0o7777 == 0o700,
        "output parent must be root-private"
    );
    match fs::symlink_metadata(output) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        _ => anyhow::bail!("output already exists or is inaccessible"),
    }
    Ok(())
}
struct IndexMember {
    path: PathBuf,
    hash: String,
    size: u64,
    epoch: u64,
    kind: &'static str,
    cid: &'static str,
}
fn cache_members(seal: &Value, cache: &Path) -> Result<Vec<IndexMember>> {
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == cache.to_str().context("cache UTF8")?
            && seal["replay_launch_authorized"] == false
            && seal["publication_authorized"] == false
            && seal["remote_mutations"] == false
            && seal["sealer_sha256"]
                == "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a",
        "foreign cache seal"
    );
    let members = seal["members"].as_array().context("cache members")?;
    ensure!(
        members.len() == INDEXES.len(),
        "cache member census differs"
    );
    let mut seen = BTreeSet::new();
    members
        .iter()
        .map(|m| {
            let name = text(m, "name")?;
            ensure!(seen.insert(name), "duplicate cache member");
            let (epoch, cid, kind, size) = INDEXES
                .iter()
                .find(|(e, c, k, _)| name == format!("epoch-{e}-{c}-mainnet-{k}.index"))
                .context("foreign index name")?;
            let hash = text(m, "sha256")?;
            let source = format!("/home/ubuntu/.jetstreamer-private/qualification-265-singleton-46b4b4a-v1/output/compact-indexes/{epoch}/{name}");
            ensure!(
                hex(hash) && m["bytes"] == *size && m["mode"] == "0444" && m["source"] == source,
                "invalid cache member binding"
            );
            Ok(IndexMember {
                path: cache.join(name),
                hash: hash.to_string(),
                size: *size,
                epoch: *epoch,
                kind,
                cid,
            })
        })
        .collect()
}
fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 6
            && matches!(args[0].as_str(), "check-plan" | "verify")
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256",
        "usage: horizon265-input-packet check-plan|verify PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        hex(&args[5]) && digest(&fs::read("/proc/self/exe")?) == args[5],
        "running image differs"
    );
    let plan: Value = serde_json::from_slice(&small(Path::new(&args[1]), &args[3])?)?;
    validate_plan(&plan)?;
    let manifest: Value = serde_json::from_slice(&small(Path::new(MANIFEST.0), MANIFEST.1)?)?;
    validate_manifest(&manifest)?;
    let incident: Value = serde_json::from_slice(&small(Path::new(INCIDENT.0), INCIDENT.1)?)?;
    validate_incident(&incident)?;
    let build: Value = serde_json::from_slice(&small(Path::new(BUILD.0), BUILD.1)?)?;
    validate_build(&build)?;
    let worker_source: Value =
        serde_json::from_slice(&small(Path::new(WORKER_SOURCE.0), WORKER_SOURCE.1)?)?;
    validate_worker(&worker_source)?;
    for entry in plan["codec_sources"].as_array().unwrap() {
        let (path, hash) = bound(&entry["file"])?;
        small(&path, &hash)?;
    }
    let cache = Path::new(text(&plan, "cache")?);
    let cache_meta = fs::symlink_metadata(cache)?;
    ensure!(
        cache.canonicalize()? == cache
            && cache_meta.is_dir()
            && cache_meta.uid() == 0
            && cache_meta.gid() == 0
            && cache_meta.mode() & 0o022 == 0,
        "unsafe cache directory"
    );
    let seal = bound_json(&plan["cache_seal"])?;
    let members = cache_members(&seal, cache)?;
    if args[0] == "check-plan" {
        println!(
            "{}",
            json!({"static_bindings_checked":true,"file_bodies_checked":false,"authority":no_authority()})
        );
        return Ok(());
    }
    let mut files = Vec::new();
    for (path, hash, size) in ARTIFACTS {
        files.push(verify_file(Path::new(path), hash, *size)?);
    }
    let mut indexes = Vec::new();
    for m in &members {
        let binding = verify_file(&m.path, &m.hash, m.size)?;
        let structure = index::inspect(&m.path, m.size, m.epoch, m.kind, m.cid)?;
        ensure!(
            binding["identity"] == identity(&fs::symlink_metadata(&m.path)?),
            "index changed after hash"
        );
        indexes.push(json!({"binding":binding,"structure":structure}));
    }
    // Recheck every identity after the last long read, including the first bootstrap.
    for binding in files.iter().chain(indexes.iter().map(|v| &v["binding"])) {
        ensure!(
            binding["identity"] == identity(&fs::symlink_metadata(text(binding, "path")?)?),
            "packet member changed before receipt"
        );
    }
    let receipt = json!({"schema":"horizon265-input-packet-v1","epoch":265,"recorded_unix_seconds":now()?,"plan":{"path":args[1],"sha256":args[3]},"checker_sha256":args[5],"manifest":{"path":MANIFEST.0,"sha256":MANIFEST.1},"source_commit":SOURCE,"node_build":{"path":BUILD.0,"sha256":BUILD.1},"worker_source":{"path":WORKER_SOURCE.0,"sha256":WORKER_SOURCE.1},"prior_failure":{"path":INCIDENT.0,"sha256":INCIDENT.1},"codec_sources":plan["codec_sources"],"cache_seal":plan["cache_seal"],"files":files,"indexes":indexes,"sealed_file_bytes_and_index_structure_accepted":true,"output_slot_start":114480000,"output_slot_end":114911999,"canonical_root_slot":114910768,"post_root_slots":1231,"authority":no_authority(),"remaining_gates":["qualified codec-test receipt for the exact relevant source","service-effective CAR header/CID and node negative probes","exact selected worker/bootstrap runtime initialization or reviewed runtime equivalence","current account-updates source containment and reader compatibility","fresh capacity, owner, guard and native startup admission","full replay, local/plugin verification, authenticated remote playback and sidecar"]});
    let output = Path::new(text(&plan, "output")?);
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &receipt)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(output.parent().context("output parent")?)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("epoch265 input packet rejected: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codec_repair_source_rejects_old_capacity_hash_revision_and_duplicate() {
        let good = json!(CODEC.iter().map(|(path,sha)| json!({"repository_path":path,"source_commit":SOURCE,"file":{"path":format!("/var/lib/jetstreamer/fixture/{path}"),"sha256":sha}})).collect::<Vec<_>>());
        codec_sources(&good).unwrap();
        for pointer in ["/0/file/sha256", "/1/source_commit", "/2/repository_path"] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("old-inline-capacity-64");
            assert!(codec_sources(&bad).is_err());
        }
        let mut duplicate = good.clone();
        duplicate[2] = good[1].clone();
        assert!(codec_sources(&duplicate).is_err());
    }
    #[test]
    fn cache_requires_exact_three_members_and_qualified_sealer() {
        let cache = Path::new("/var/lib/jetstreamer/horizon265-index-fixture");
        let good = json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":cache,"sealer_sha256":"faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a","replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"members":INDEXES.iter().map(|(epoch,cid,kind,size)|json!({"name":format!("epoch-{epoch}-{cid}-mainnet-{kind}.index"),"source":format!("/home/ubuntu/.jetstreamer-private/qualification-265-singleton-46b4b4a-v1/output/compact-indexes/{epoch}/epoch-{epoch}-{cid}-mainnet-{kind}.index"),"bytes":size,"mode":"0444","sha256":"a".repeat(64)})).collect::<Vec<_>>()});
        assert_eq!(cache_members(&good, cache).unwrap().len(), 3);
        for pointer in [
            "/sealer_sha256",
            "/members/0/name",
            "/members/0/source",
            "/members/1/bytes",
            "/members/2/mode",
            "/members/2/sha256",
            "/publication_authorized",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = Value::Null;
            assert!(cache_members(&bad, cache).is_err(), "{pointer}");
        }
        let mut duplicate = good.clone();
        duplicate["members"][2] = good["members"][0].clone();
        assert!(cache_members(&duplicate, cache).is_err());
    }
}
