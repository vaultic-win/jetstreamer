//! Read-only structural check for the next epoch's sealed input cache.
use super::*;

const ROOT251: &str = "017112209310992bd217a84ad737224c38279f2da531f5b487283ca225eccebe344e936f";
const CID251: &str = "bafyreietccmsxuqxvbfnonzcjq4cphznuuy7lnehfa6kejpmz27ditutn4";
const CID250: &str = "bafyreihxzahaxjzity5i4dvz5cqunbm645w3xddx23fxe2fg6lyd3v26fa";

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sealed_json(path: &Path, sha: &str) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1,
        "evidence must be a sealed root-owned regular file"
    );
    let bytes = fs::read(path)?;
    ensure!(hash(&bytes) == sha, "evidence digest mismatch");
    Ok(serde_json::from_slice(&bytes)?)
}

fn expected(name: &str) -> Result<(u64, &'static str, &'static str, u64)> {
    for (epoch, cid, kind, size, root) in [
        (250, CID250, "slot-to-cid", 15_576_774, ROOT_CID_HEX),
        (251, CID251, "slot-to-cid", 15_666_061, ROOT251),
        (
            251,
            CID251,
            "cid-to-offset-and-size",
            10_554_622_710,
            ROOT251,
        ),
    ] {
        if name == format!("epoch-{epoch}-{cid}-mainnet-{kind}.index") {
            return Ok((epoch, kind, root, size));
        }
    }
    anyhow::bail!("unexpected epoch 251 cache member: {name}")
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 5,
        "usage: horizon250-index-capability check-251 PLAN PLAN_SHA256 SELF_SHA256"
    );
    ensure!(
        hash(&fs::read("/proc/self/exe")?) == args[4],
        "running image mismatch"
    );
    let plan = sealed_json(Path::new(&args[2]), &args[3])?;
    let keys = plan.as_object().context("plan must be an object")?;
    ensure!(
        keys.len() == 5
            && [
                "schema",
                "cache",
                "cache_seal_sha256",
                "output",
                "replay_launch_authorized"
            ]
            .iter()
            .all(|k| keys.contains_key(*k)),
        "unexpected plan fields"
    );
    ensure!(
        plan["schema"] == "horizon251-index-structure-plan-v1"
            && plan["replay_launch_authorized"] == false,
        "foreign plan or authority"
    );
    let cache = PathBuf::from(plan["cache"].as_str().context("cache")?);
    ensure!(
        cache.starts_with("/var/lib/jetstreamer") && cache.canonicalize()? == cache,
        "cache must be an immutable deployment"
    );
    let cm = fs::symlink_metadata(&cache)?;
    ensure!(
        cm.is_dir() && cm.uid() == 0 && cm.mode() & 0o022 == 0,
        "unsafe cache directory"
    );
    let seal_sha = plan["cache_seal_sha256"].as_str().context("seal hash")?;
    let seal_path = cache.join("deployment-seal-receipt.json");
    let seal = sealed_json(&seal_path, seal_sha)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == cache.to_str().context("cache UTF8")?
            && seal["replay_launch_authorized"] == false
            && seal["remote_mutations"] == false,
        "foreign seal"
    );
    let members = seal["members"].as_array().context("sealed members")?;
    ensure!(members.len() == 3, "expected exactly three sealed indexes");
    let output = PathBuf::from(plan["output"].as_str().context("output")?);
    let parent = output.parent().context("output parent")?;
    ensure!(
        output.is_absolute() && parent.canonicalize()? == parent && !output.exists(),
        "unsafe or existing output"
    );
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir() && pm.uid() == 0 && pm.mode() & 0o077 == 0,
        "output parent must be root-private"
    );
    let mut names = std::collections::BTreeSet::new();
    let mut indexes = Vec::new();
    for m in members {
        let name = m["name"].as_str().context("member name")?;
        ensure!(names.insert(name), "duplicate member");
        let (epoch, kind, root, size) = expected(name)?;
        ensure!(
            m["bytes"] == size && m["mode"] == "0444",
            "member size or mode mismatch"
        );
        let sha = m["sha256"].as_str().context("member hash")?;
        let path = cache.join(name);
        eprintln!("checking epoch {epoch} {kind}: {size} bytes");
        let binding = exact_file(&path, sha, size)?;
        let structure = inspect_index_root(&path, size, epoch, kind, Some(root))?;
        indexes.push(json!({"binding":binding,"structure":structure}));
        eprintln!("checked epoch {epoch} {kind}");
    }
    // Structural parsing is intentionally narrower than a production reader or replay probe.
    let receipt = json!({"schema":"horizon251-index-structure-receipt-v1","epoch":251,"structure_accepted":true,"plan":{"path":args[2],"sha256":args[3]},"checker_sha256":args[4],"cache_seal":{"path":seal_path,"sha256":seal_sha},"indexes":indexes,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"native_replay_probe_passed":false,"replay_launch_authorized":false,"admission_authorized":false,"publication_authorized":false,"remote_mutations":false});
    let mut out = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&output)?;
    serde_json::to_writer_pretty(&mut out, &receipt)?;
    out.write_all(b"\n")?;
    out.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_binds_root_epoch_and_kind() {
        let root: Vec<u8> = ROOT251
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
            .collect();
        let mut meta = vec![3];
        for (key, value) in [
            (b"epoch".as_slice(), 251u64.to_le_bytes().to_vec()),
            (b"kind".as_slice(), b"slot-to-cid".to_vec()),
            (b"rootCid".as_slice(), root),
        ] {
            meta.push(key.len() as u8);
            meta.extend(key);
            meta.push(value.len() as u8);
            meta.extend(value);
        }
        let header_end = 25 + meta.len();
        let table_end = header_end + 16;
        let mut bytes = b"compiszd".to_vec();
        bytes.extend(((header_end - 12) as u32).to_le_bytes());
        bytes.extend(8u64.to_le_bytes());
        bytes.extend(1u32.to_le_bytes());
        bytes.push(1);
        bytes.extend(meta);
        bytes.resize(table_end + 16, 0);
        bytes[header_end + 4..header_end + 8].copy_from_slice(&1u32.to_le_bytes());
        bytes[header_end + 8] = 8;
        bytes[header_end + 10..header_end + 16]
            .copy_from_slice(&(table_end as u64).to_le_bytes()[..6]);
        let path = std::env::temp_dir().join(format!(
            "horizon251-index-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, &bytes).unwrap();
        let size = bytes.len() as u64;
        assert!(inspect_index_root(&path, size, 251, "slot-to-cid", Some(ROOT251)).is_ok());
        assert!(inspect_index_root(&path, size, 251, "slot-to-cid", Some(ROOT_CID_HEX)).is_err());
        assert!(inspect_index_root(&path, size, 250, "slot-to-cid", Some(ROOT251)).is_err());
        assert!(
            inspect_index_root(&path, size, 251, "cid-to-offset-and-size", Some(ROOT251)).is_err()
        );
        bytes[header_end + 10..header_end + 16]
            .copy_from_slice(&((table_end + 1) as u64).to_le_bytes()[..6]);
        fs::write(&path, &bytes).unwrap();
        assert!(inspect_index_root(&path, size, 251, "slot-to-cid", Some(ROOT251)).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn exact_epoch_and_root_member_set() {
        assert!(expected(&format!("epoch-251-{CID251}-mainnet-slot-to-cid.index")).is_ok());
        assert!(expected(&format!("epoch-250-{CID250}-mainnet-slot-to-cid.index")).is_ok());
        assert!(expected(&format!("epoch-251-{CID250}-mainnet-slot-to-cid.index")).is_err());
        assert!(expected(&format!("../epoch-251-{CID251}-mainnet-slot-to-cid.index")).is_err());
        assert!(
            expected(&format!(
                "epoch-250-{CID250}-mainnet-cid-to-offset-and-size.index"
            ))
            .is_err()
        );
    }
}
