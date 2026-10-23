//! Offline conversion of exact retained207 metadata into a private singleton.
//! No Bank, worker, resource sample, GCloud or R2 access.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

const SOURCE: &str = "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/preflight-root-only-203-213.json";
const SOURCE_SHA: &str = "7389720afed30d7480f952b240f3469974e5a18ceb02e01c8e3086fd6f71eb97";
const SOURCE_FP: &str = "sha256:63e4f6b5f858ed636b2c22bc15f971d0f4a1009b50f39f66b779df782060976d";
const BINDINGS: &str = "/var/lib/jetstreamer/horizon-focused-207-complete-span-store8-ca2e38b-v2/snapshot-bindings-207.json";
const BINDINGS_SHA: &str = "804c7c90f765226164d0b8d840d9122fc2a83d1e9e5cf19ed5630b2c0789f8e2";

fn canonical(v: &Value, out: &mut Vec<u8>) -> Result<()> {
    match v {
        Value::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canonical(v, out)?;
            }
            out.push(b']');
        }
        Value::Object(m) => {
            out.push(b'{');
            let mut keys = m.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                ensure!(key.is_ascii(), "non-ASCII key");
                out.extend(serde_json::to_vec(key)?);
                out.push(b':');
                canonical(&m[key], out)?;
            }
            out.push(b'}');
        }
        Value::Number(n) => {
            ensure!(n.is_u64() || n.is_i64(), "non-integer manifest number");
            out.extend(n.to_string().as_bytes());
        }
        Value::String(s) => {
            ensure!(s.is_ascii(), "non-ASCII manifest string");
            out.extend(serde_json::to_vec(s)?);
        }
        _ => out.extend(serde_json::to_vec(v)?),
    }
    Ok(())
}
fn fingerprint(v: &Value) -> Result<String> {
    let mut bytes = Vec::new();
    canonical(v, &mut bytes)?;
    Ok(format!("sha256:{:x}", Sha256::digest(&bytes)))
}
fn read(path: &str, expected: &str) -> Result<Value> {
    let p = Path::new(path);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1
            && m.len() <= 16 * 1024 * 1024
            && p.canonicalize()? == p,
        "unsafe retained evidence"
    );
    let bytes = fs::read(p)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == expected,
        "retained evidence digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn convert(source: &Value, bindings: &Value) -> Result<Value> {
    ensure!(
        source["manifest_fingerprint"] == SOURCE_FP
            && fingerprint(&source["manifest"])? == SOURCE_FP
            && source["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v2"
            && source["manifest"]["bucket"] == "gs://mainnet-beta-ledger-us-ny5"
            && bindings["epoch"] == 207
            && bindings["preflight_manifest_fingerprint"] == SOURCE_FP,
        "wrong source manifest"
    );
    let selected = source["manifest"]["verification_cohorts"]
        .as_array()
        .context("source cohorts")?
        .iter()
        .filter(|c| c["first_epoch"] == 207 && c["last_epoch"] == 207)
        .collect::<Vec<_>>();
    ensure!(selected.len() == 1, "207 source cohort missing/duplicated");
    let mut entry = selected[0].clone();
    ensure!(
        entry["runtime"] == "solana-v1.6.16"
            && entry["bootstrap"]["slot"] == 89_423_444u64
            && entry["root_checkpoints"]
                .as_array()
                .is_some_and(|r| r.len() == 2)
            && entry["root_checkpoints"][0]["slot"] == 89_523_820u64
            && entry["root_checkpoints"][1]["slot"] == 89_855_469u64,
        "207 root census differs"
    );
    for (slot, hash) in [
        (
            89_423_444u64,
            "3NVZVHDVwXgMxuTP77gaZF4UBP1oNBQzGScBGyoLx2Px",
        ),
        (89_523_820, "7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik"),
        (89_855_469, "9i59TwLmzXvbomizFZNuXgPygtx8zJ3P4nWDQuNxrTxK"),
    ] {
        let item = if slot == 89_423_444 {
            &mut entry["bootstrap"]
        } else {
            &mut entry["root_checkpoints"][usize::from(slot == 89_855_469)]
        };
        ensure!(
            item["accounts_hash"] == hash
                && item["source"] == "root"
                && item["anchor_slot"] == slot
                && item["size"].as_u64().is_some_and(|n| n > 0)
                && item["generation"].as_u64().is_some_and(|n| n > 0),
            "root identity differs"
        );
        if slot == 89_523_820 {
            // Same v2->v4 offline representation as the existing reviewed
            // preflight converter: legacy evidence has no MD5 field. This is
            // planning only, not a claim that current remote MD5 is absent.
            item["md5_hash"] = Value::Null;
        } else {
            let b = &bindings[if slot == 89_423_444 {
                "bootstrap"
            } else {
                "terminal"
            }];
            ensure!(
                item["versioned_uri"] == b["versioned_uri"]
                    && item["size"] == b["size"]
                    && item["crc32c"] == b["crc32c_base64"]
                    && b["md5_base64"].is_string(),
                "retained MD5 binding differs"
            );
            item["md5_hash"] = b["md5_base64"].clone();
        }
    }
    let manifest = json!({"schema":"jetstreamer-gcs-snapshot-preflight-v4","bucket":"gs://mainnet-beta-ledger-us-ny5",
        "epoch_slots":432000,"first_epoch":207,"last_epoch":207,"verification_cohorts":[entry]});
    Ok(
        json!({"manifest_fingerprint":fingerprint(&manifest)?,"manifest":manifest,
        "preparation":{"schema":"jetstreamer-private-epoch207-singleton-offline-preparation-v1",
            "source":{"path":SOURCE,"sha256":SOURCE_SHA,"manifest_fingerprint":SOURCE_FP},
            "bindings":{"path":BINDINGS,"sha256":BINDINGS_SHA},
            "legacy_v2_md5_unobserved_slots":[89523820],"fresh_exact_generation_reobservation_still_required":true,
            "final_output_slot":89855999,"post_root_slot_count":530,"epoch208_input_required":false,
            "runtime_registry_promoted":false,"native_input_qualified":false,"replay_qualified":false,
            "resource_observation_taken":false,"worker_started":false,"launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}}),
    )
}
fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 4 && args[2] == "--self-sha256" && unsafe { libc::geteuid() } == 0,
        "usage: prepare OUTPUT --self-sha256 HEX (root)"
    );
    ensure!(
        format!("{:x}", Sha256::digest(fs::read("/proc/self/exe")?)) == args[3],
        "self digest differs"
    );
    let output = PathBuf::from(&args[1]);
    let dir = output.parent().context("output parent")?;
    ensure!(
        output.file_name().and_then(|s| s.to_str()) == Some("preflight207-singleton.json")
            && dir.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && dir
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-207-singleton-")),
        "wrong private output"
    );
    let metadata = fs::symlink_metadata(dir)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0
            && dir.canonicalize()? == dir,
        "unsafe preparation directory"
    );
    let result = convert(&read(SOURCE, SOURCE_SHA)?, &read(BINDINGS, BINDINGS_SHA)?)?;
    let mut bytes = serde_json::to_vec_pretty(&result)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(dir)?.sync_all()?;
    println!(
        "{} {}",
        output.display(),
        result["manifest_fingerprint"]
            .as_str()
            .context("prepared fingerprint")?
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_fingerprint_preserves_consensus_integer_and_rejects_float() {
        assert_eq!(
            fingerprint(&json!({"x":u64::MAX,"a":[1,2]})).unwrap(),
            fingerprint(
                &serde_json::from_str::<Value>(r#"{"a":[1,2],"x":18446744073709551615}"#).unwrap()
            )
            .unwrap()
        );
        assert!(fingerprint(&json!({"x":1.5})).is_err());
    }
}
