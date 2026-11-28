//! Read-only qualification of epoch 250's exact sealed compact-index cache.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

mod epoch251;

const CACHE: &str = "/var/lib/jetstreamer/horizon250-index-reboot-20261117-cache-v1";
const AUTH: &str = "/var/lib/jetstreamer/horizon250-reboot-20261117-input-auth-v1/acceptance.json";
const AUTH_SHA: &str = "8c7bcf8828827081f6005e0be006aa8bb3b25fb64a03b55dc5ebf1919943bf04";
const SEAL_SHA: &str = "f4f8e02135249ed127564bc4e49b0b44271652ed72c338e80d6f0ad80e70ae99";
const ROOT_CID_HEX: &str =
    "01711220f7c80e0ba7289e3a8e0eb9e8a146859ee76dbb8c77d6cb7268a6f2f03dd75e28";
const OUT: &str =
    "/home/ubuntu/workspace/horizon250-readiness-20261117-v1/index-capability/capability-v4.json";

const FILES: [(&str, &str, u64, u64, &str); 3] = [
    (
        "epoch-249-bafyreibqqyle7ppgb2oxvaba4vfsoromxagbnavjxvmehp66fyaneqcthe-mainnet-slot-to-cid.index",
        "49246841043972c464e53dec814e5394d1ef6da6cc96a04adcf82b7503abece6",
        15_962_110,
        249,
        "slot-to-cid",
    ),
    (
        "epoch-250-bafyreihxzahaxjzity5i4dvz5cqunbm645w3xddx23fxe2fg6lyd3v26fa-mainnet-slot-to-cid.index",
        "233dd69d874a13f9bcf025ac877fd2cca14b3c9d5668095e699b41c98927cb91",
        15_576_774,
        250,
        "slot-to-cid",
    ),
    (
        "epoch-250-bafyreihxzahaxjzity5i4dvz5cqunbm645w3xddx23fxe2fg6lyd3v26fa-mainnet-cid-to-offset-and-size.index",
        "48d53158d37ac02462da700dc319716fc144cc7b56aad6f35376a4e166c95c13",
        10_330_329_678,
        250,
        "cid-to-offset-and-size",
    ),
];

fn exact_file(path: &Path, expected: &str, expected_size: u64) -> Result<Value> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && before.is_file() && before.nlink() == 1,
        "unsafe input {}",
        path.display()
    );
    ensure!(
        before.len() == expected_size
            && before.uid() == 0
            && before.gid() == 0
            && before.mode() & 0o777 == 0o444,
        "wrong size, owner or mode: {}",
        path.display()
    );
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec(),
        "input changed: {}",
        path.display()
    );
    let actual = format!("{:x}", digest.finalize());
    ensure!(actual == expected, "digest mismatch: {}", path.display());
    Ok(
        json!({"path":path,"sha256":actual,"size":before.len(),"dev":before.dev(),"ino":before.ino(),"mtime_ns":before.mtime() as i128 * 1_000_000_000 + before.mtime_nsec() as i128,"ctime_ns":before.ctime() as i128 * 1_000_000_000 + before.ctime_nsec() as i128}),
    )
}

fn metadata(data: &[u8]) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    ensure!(!data.is_empty(), "empty metadata");
    let count = usize::from(data[0]);
    let mut at = 1;
    let mut map = BTreeMap::new();
    for _ in 0..count {
        let key_len = usize::from(*data.get(at).context("metadata key length")?);
        at += 1;
        let key = data.get(at..at + key_len).context("metadata key")?.to_vec();
        at += key_len;
        let value_len = usize::from(*data.get(at).context("metadata value length")?);
        at += 1;
        let value = data
            .get(at..at + value_len)
            .context("metadata value")?
            .to_vec();
        at += value_len;
        ensure!(map.insert(key, value).is_none(), "duplicate metadata key");
    }
    ensure!(at == data.len(), "trailing metadata bytes");
    Ok(map)
}

fn inspect_index(path: &Path, size: u64, epoch: u64, kind: &str) -> Result<Value> {
    inspect_index_root(
        path,
        size,
        epoch,
        kind,
        (epoch == 250).then_some(ROOT_CID_HEX),
    )
}

fn inspect_index_root(
    path: &Path,
    size: u64,
    epoch: u64,
    kind: &str,
    expected_root_hex: Option<&str>,
) -> Result<Value> {
    let mut file = File::open(path)?;
    let mut prefix = [0u8; 25];
    file.read_exact(&mut prefix)?;
    ensure!(
        &prefix[..8] == b"compiszd" && prefix[24] == 1,
        "invalid compact-index magic or version"
    );
    let header_len = u32::from_le_bytes(prefix[8..12].try_into()?) as usize;
    ensure!(
        (13..=4096).contains(&header_len),
        "unexpected header length"
    );
    let header_end = 12 + header_len;
    let value_size = u64::from_le_bytes(prefix[12..20].try_into()?);
    let buckets = u32::from_le_bytes(prefix[20..24].try_into()?);
    ensure!(
        (1..=1_000_000).contains(&buckets) && (1..=64).contains(&value_size),
        "invalid index dimensions"
    );
    let mut rest = vec![0; header_end - 25];
    file.read_exact(&mut rest)?;
    let meta = metadata(&rest)?;
    // Old Faithful currently emits `kind`; the deployed parser's optional
    // `index_kind` check does not cover this field, so require it here.
    ensure!(
        meta.get(b"kind".as_slice()).map(Vec::as_slice) == Some(kind.as_bytes()),
        "index kind mismatch"
    );
    let actual_epoch = meta.get(b"epoch".as_slice()).context("missing epoch")?;
    ensure!(
        actual_epoch.len() == 8 && u64::from_le_bytes(actual_epoch[..8].try_into()?) == epoch,
        "index epoch mismatch"
    );
    if let Some(expected_root_hex) = expected_root_hex {
        let root = meta
            .get(b"rootCid".as_slice())
            .context("missing root CID")?;
        ensure!(
            root.iter().map(|b| format!("{b:02x}")).collect::<String>() == expected_root_hex,
            "root CID mismatch"
        );
    }
    let table_end = (header_end as u64)
        .checked_add(u64::from(buckets) * 16)
        .context("table overflow")?;
    ensure!(table_end <= size, "bucket table beyond file");
    let mut table = vec![0u8; usize::try_from(u64::from(buckets) * 16)?];
    file.read_exact(&mut table)?;
    let mut entries = 0u64;
    let mut nonempty = 0u64;
    for header in table.as_chunks::<16>().0 {
        let count = u64::from(u32::from_le_bytes(header[4..8].try_into()?));
        if count == 0 {
            continue;
        }
        let hash_len = u64::from(header[8]);
        ensure!((1..=8).contains(&hash_len), "invalid entry hash length");
        let mut offset = [0u8; 8];
        offset[..6].copy_from_slice(&header[10..16]);
        let start = u64::from_le_bytes(offset);
        let span = count
            .checked_mul(hash_len + value_size)
            .context("bucket span overflow")?;
        ensure!(
            start >= table_end && start.checked_add(span).is_some_and(|end| end <= size),
            "bucket outside file"
        );
        entries += count;
        nonempty += 1;
    }
    ensure!(entries > 0, "empty index");
    file.seek(SeekFrom::Start(size - 1))?;
    let mut tail = [0];
    file.read_exact(&mut tail)?;
    Ok(
        json!({"epoch":epoch,"kind":kind,"header_bytes":header_end,"value_size":value_size,"bucket_count":buckets,"nonempty_buckets":nonempty,"entry_count":entries,"bucket_spans_within_file":true}),
    )
}

fn run() -> Result<()> {
    ensure!(std::env::args().len() == 1, "no arguments accepted");
    ensure!(!Path::new(OUT).exists(), "capability already exists");
    let auth_bytes = fs::read(AUTH)?;
    ensure!(
        format!("{:x}", Sha256::digest(&auth_bytes)) == AUTH_SHA,
        "input acceptance changed"
    );
    let auth: Value = serde_json::from_slice(&auth_bytes)?;
    ensure!(
        auth["schema"] == "horizon250-reboot-exact-input-custody-v1"
            && auth["accepted_input_custody"] == true
            && auth["epoch"] == 250
            && auth["replay_launch_authorized"] == false,
        "foreign input acceptance"
    );
    let seal_bytes = fs::read(format!("{CACHE}/deployment-seal-receipt.json"))?;
    ensure!(
        format!("{:x}", Sha256::digest(&seal_bytes)) == SEAL_SHA,
        "cache seal changed"
    );
    let seal: Value = serde_json::from_slice(&seal_bytes)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == CACHE
            && seal["replay_launch_authorized"] == false
            && seal["r2_mutations"] == false,
        "foreign cache seal"
    );
    let members = seal["members"]
        .as_array()
        .context("missing sealed members")?;
    ensure!(members.len() == 4, "unexpected cache member count");
    let mut indexes = Vec::new();
    for (name, sha, size, epoch, kind) in FILES {
        ensure!(
            members.iter().any(|m| m["name"] == name
                && m["sha256"] == sha
                && m["bytes"] == size
                && m["mode"] == "0444"),
            "unsealed index: {name}"
        );
        let path = PathBuf::from(CACHE).join(name);
        let binding = exact_file(&path, sha, size)?;
        let format = inspect_index(&path, size, epoch, kind)?;
        indexes.push(json!({"binding":binding,"format":format}));
    }
    let source = members
        .iter()
        .find(|m| m["name"] == "source-proof.json")
        .context("missing source proof seal")?;
    ensure!(
        source["sha256"] == "3d4ebcf04703f1942e0719542de87e4f84b47a037efbbad156075ef315e7b0d0"
            && source["bytes"] == 1496
            && source["mode"] == "0444",
        "source proof seal mismatch"
    );
    let source_binding = exact_file(
        &PathBuf::from(CACHE).join("source-proof.json"),
        source["sha256"].as_str().context("source hash")?,
        1496,
    )?;
    let source_value: Value =
        serde_json::from_slice(&fs::read(format!("{CACHE}/source-proof.json"))?)?;
    ensure!(
        source_value["schema"] == "horizon250-compact-index-source-proof-v1"
            && source_value["epoch"] == 250
            && source_value["http_code"] == 200
            && source_value["r2_mutations"] == false,
        "foreign source proof"
    );
    let result = json!({"schema":"horizon250-sealed-compact-index-capability-v1","accepted":true,"epoch":250,"input_acceptance":{"path":AUTH,"sha256":AUTH_SHA},"cache_seal":{"path":format!("{CACHE}/deployment-seal-receipt.json"),"sha256":SEAL_SHA},"source_proof":source_binding,"indexes":indexes,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"native_replay_probe_passed":false,"replay_launch_authorized":false,"admission_authorized":false,"r2_mutations":false,"remote_mutations":false});
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(OUT)?;
    serde_json::to_writer_pretty(&mut out, &result)?;
    out.write_all(b"\n")?;
    out.sync_all()?;
    File::open(Path::new(OUT).parent().context("output parent")?)?.sync_all()?;
    println!("{OUT}");
    Ok(())
}

fn main() {
    let result = if std::env::args().nth(1).as_deref() == Some("check-251") {
        epoch251::run()
    } else {
        run()
    };
    if let Err(error) = result {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_index_bucket_past_end() {
        let mut meta = vec![2, 5];
        meta.extend_from_slice(b"epoch");
        meta.push(8);
        meta.extend_from_slice(&249_u64.to_le_bytes());
        meta.push(4);
        meta.extend_from_slice(b"kind");
        meta.push(11);
        meta.extend_from_slice(b"slot-to-cid");

        let header_len = 13 + meta.len();
        let table_end = 12 + header_len + 16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"compiszd");
        bytes.extend_from_slice(&(header_len as u32).to_le_bytes());
        bytes.extend_from_slice(&8_u64.to_le_bytes());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&meta);
        let table_start = bytes.len();
        bytes.resize(table_end + 16, 0);
        bytes[table_start + 4..table_start + 8].copy_from_slice(&1_u32.to_le_bytes());
        bytes[table_start + 8] = 8;
        bytes[table_start + 10..table_start + 16]
            .copy_from_slice(&(table_end as u64).to_le_bytes()[..6]);

        let path = std::env::temp_dir().join(format!(
            "horizon250-index-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, &bytes).unwrap();
        assert!(inspect_index(&path, bytes.len() as u64, 249, "slot-to-cid").is_ok());
        assert!(inspect_index(&path, bytes.len() as u64, 250, "slot-to-cid").is_err());
        bytes[table_start + 10..table_start + 16]
            .copy_from_slice(&((table_end + 1) as u64).to_le_bytes()[..6]);
        fs::write(&path, &bytes).unwrap();
        assert!(inspect_index(&path, bytes.len() as u64, 249, "slot-to-cid").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn rejects_duplicate_or_trailing_metadata() {
        assert!(metadata(&[1, 1, b'a', 1, b'b']).is_ok());
        assert!(metadata(&[2, 1, b'a', 1, b'b', 1, b'a', 1, b'c']).is_err());
        assert!(metadata(&[1, 1, b'a', 1, b'b', 0]).is_err());
    }
}
