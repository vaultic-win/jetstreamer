//! Offline, exact-generation candidate builder. Never performs or claims a GCS read.
#[allow(dead_code)]
#[path = "../epoch141_ledger_common.rs"]
mod common;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::{bound_file, sha, write_receipt};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    path::{Path, PathBuf},
};

const BASE: &str =
    "/var/lib/jetstreamer/horizon-207-singleton-metadata-v1/preflight207-singleton.json";
const BASE_SHA: &str = "a921cb0be8c518950b0611d2f03cfa05576655f3160be5732b2bc3157213a580";
const BASE_FP: &str = "sha256:50896e94150b8ca275a628bf1c760d81b45a8e5ac7bb5425c7e0d0b0d2f8b1e4";
const BUCKET: &str = "mainnet-beta-ledger-us-ny5";
const NAME: &str =
    "89523820/snapshot-89523820-7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik.tar.zst";
const GENERATION: u64 = 1_633_927_404_656_451;
const SIZE: u64 = 8_419_571_372;
const CRC: &str = "qIeOcA==";
const URI: &str = "gs://mainnet-beta-ledger-us-ny5/89523820/snapshot-89523820-7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik.tar.zst#1633927404656451";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    raw_metadata: Bound,
    output: PathBuf,
}
fn number(v: &Value) -> Result<u64> {
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    let s = v
        .as_str()
        .context("metadata number must be integer or decimal string")?;
    let n = s.parse::<u64>()?;
    ensure!(s == n.to_string(), "noncanonical metadata integer");
    Ok(n)
}
fn alias<'a>(v: &'a Value, keys: &[&str]) -> Result<&'a str> {
    let mut found = None;
    for key in keys {
        if let Some(value) = v.get(*key) {
            let text = value
                .as_str()
                .context("metadata checksum is not a string")?;
            ensure!(
                found.is_none_or(|old| old == text),
                "conflicting metadata aliases"
            );
            found = Some(text);
        }
    }
    found.context("missing metadata checksum")
}
fn metadata(v: &Value) -> Result<&str> {
    ensure!(
        v["bucket"] == BUCKET
            && v["name"] == NAME
            && number(&v["generation"])? == GENERATION
            && number(&v["size"])? == SIZE,
        "wrong exact root object"
    );
    ensure!(
        alias(v, &["crc32c_hash", "crc32c"])? == CRC,
        "root CRC32C differs"
    );
    let md5 = alias(v, &["md5_hash", "md5Hash"])?;
    let decoded = STANDARD.decode(md5)?;
    ensure!(
        decoded.len() == 16 && STANDARD.encode(decoded) == md5,
        "MD5 is not canonical 16-byte base64"
    );
    let mut identity = false;
    if let Some(uri) = v.get("storage_url") {
        ensure!(uri == URI, "root versioned URI differs");
        identity = true;
    }
    if let Some(id) = v.get("id") {
        ensure!(
            id.as_str() == Some(format!("{BUCKET}/{NAME}/{GENERATION}").as_str()),
            "root object ID differs"
        );
        identity = true;
    }
    ensure!(identity, "no generation-bound object identity");
    let mut component_count = None;
    for key in ["componentCount", "component_count"] {
        if let Some(count) = v.get(key) {
            let count = number(count)?;
            ensure!(
                count <= 1 && component_count.is_none_or(|old| old == count),
                "composite or conflicting component count requires a separate reviewed checksum policy"
            );
            component_count = Some(count);
        }
    }
    Ok(md5)
}
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
                ensure!(key.is_ascii(), "non-ASCII manifest key");
                out.extend(serde_json::to_vec(key)?);
                out.push(b':');
                canonical(&m[key], out)?;
            }
            out.push(b'}');
        }
        Value::Number(n) => {
            ensure!(
                n.is_u64() || n.is_i64(),
                "manifest number must be exact integer"
            );
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
    Ok(format!("sha256:{}", sha(&bytes)))
}
fn candidate(base: &Value, raw: &Value, binding: &Bound) -> Result<Value> {
    let md5 = metadata(raw)?;
    ensure!(
        base["manifest_fingerprint"] == BASE_FP && fingerprint(&base["manifest"])? == BASE_FP,
        "prior singleton manifest differs"
    );
    let mut manifest = base["manifest"].clone();
    ensure!(
        manifest["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && manifest["first_epoch"] == 207
            && manifest["last_epoch"] == 207
            && manifest["verification_cohorts"]
                .as_array()
                .is_some_and(|v| v.len() == 1)
            && manifest["verification_cohorts"][0]["runtime"] == "solana-v1.6.16",
        "prior singleton scope differs"
    );
    let root = &mut manifest["verification_cohorts"][0]["root_checkpoints"][0];
    ensure!(
        root["slot"] == 89_523_820u64
            && root["accounts_hash"] == "7NUvFRrgkc2pc9DPmD7vrrooZkEwc6r8KqUMq5MrG3ik"
            && root["generation"] == GENERATION
            && root["size"] == SIZE
            && root["crc32c"] == CRC
            && root["versioned_uri"] == URI
            && root["md5_hash"].is_null(),
        "prior canonical root binding differs"
    );
    root["md5_hash"] = json!(md5);
    let mut only_change = manifest.clone();
    only_change["verification_cohorts"][0]["root_checkpoints"][0]["md5_hash"] = Value::Null;
    ensure!(
        only_change == base["manifest"],
        "candidate changed an unrelated manifest field"
    );
    Ok(
        json!({"manifest_fingerprint":fingerprint(&manifest)?,"manifest":manifest,
        "metadata_candidate":{"schema":"jetstreamer-private-epoch207-root-metadata-candidate-v1","epoch":207,"root_slot":89523820u64,
        "prior_preflight":{"path":BASE,"sha256":BASE_SHA,"manifest_fingerprint":BASE_FP},
        "raw_metadata":{"path":binding.path,"sha256":binding.sha256},"generation":GENERATION.to_string(),"versioned_uri":URI,
        "observed_md5_candidate":md5,"only_first_root_md5_changed":true,"raw_metadata_structurally_validated":true,
        "authenticated_generation_reobservation_proven":false,"independent_authenticated_reader_receipt_required":true,
        "cached_body_hash_substituted_for_remote_metadata":false,"native_input_proof_not_replaced":true,
        "network_performed":false,"resource_observation_taken":false,"snapshot_restored":false,"replay_launched":false,
        "metadata_admission_authorized":false,"launch_authorized":false,"snapshot_restore_authorized":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}}),
    )
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: candidate PLAN --plan-sha256 SHA --self-sha256 SHA (root)"
    );
    bound_file(
        &Path::new("/proc/self/exe").read_link()?,
        &a[5],
        64 << 20,
        true,
    )?;
    let p: Plan = serde_json::from_slice(&bound_file(Path::new(&a[1]), &a[3], 65536, true)?)?;
    ensure!(
        p.schema == "jetstreamer-private-epoch207-root-metadata-candidate-plan-v1"
            && p.output
                .file_name()
                .is_some_and(|s| s == "preflight207-singleton-candidate.json")
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-207-root-metadata-candidate-")),
        "wrong candidate output scope"
    );
    let base: Value =
        serde_json::from_slice(&bound_file(Path::new(BASE), BASE_SHA, 1 << 20, true)?)?;
    let raw: Value = serde_json::from_slice(&bound_file(
        &p.raw_metadata.path,
        &p.raw_metadata.sha256,
        65536,
        true,
    )?)?;
    let mut result = candidate(&base, &raw, &p.raw_metadata)?;
    result["metadata_candidate"]["helper_sha256"] = json!(a[5]);
    write_receipt(&p.output, &result)?;
    println!("{}", p.output.display());
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
    fn raw() -> Value {
        json!({"bucket":BUCKET,"name":NAME,"generation":GENERATION.to_string(),"size":SIZE,"crc32c_hash":CRC,"md5_hash":"AAAAAAAAAAAAAAAAAAAAAA==","storage_url":URI})
    }
    #[test]
    fn candidate_changes_only_the_missing_md5_and_cannot_claim_authenticated_admission() {
        let bytes = include_bytes!("../../tests/fixtures/epoch207-singleton-metadata-v1.json");
        assert_eq!(sha(bytes), BASE_SHA);
        let base: Value = serde_json::from_slice(bytes).unwrap();
        let binding = Bound {
            path: "/sealed/raw.json".into(),
            sha256: "a".repeat(64),
        };
        let result = candidate(&base, &raw(), &binding).unwrap();
        assert_ne!(result["manifest_fingerprint"], base["manifest_fingerprint"]);
        assert_eq!(
            result["metadata_candidate"]["authenticated_generation_reobservation_proven"],
            false
        );
        assert_eq!(
            result["metadata_candidate"]["metadata_admission_authorized"],
            false
        );
        assert_eq!(
            result["manifest"]["verification_cohorts"][0]["root_checkpoints"][1],
            base["manifest"]["verification_cohorts"][0]["root_checkpoints"][1]
        );
        let mut bad = base.clone();
        bad["manifest"]["verification_cohorts"][0]["root_checkpoints"][0]["generation"] =
            json!(GENERATION + 1);
        assert!(candidate(&bad, &raw(), &binding).is_err());
    }
    #[test]
    fn metadata_requires_the_exact_remote_identity_and_real_unambiguous_md5() {
        metadata(&raw()).unwrap();
        for (key, value) in [
            ("bucket", json!("other")),
            ("generation", json!(GENERATION + 1)),
            ("size", json!(SIZE + 1)),
            ("crc32c_hash", json!("AAAAAA==")),
            ("md5_hash", Value::Null),
            ("md5Hash", json!("AQAAAAAAAAAAAAAAAAAAAA==")),
            ("storage_url", json!(URI.replace('#', "?generation="))),
            ("componentCount", json!(2)),
        ] {
            let mut bad = raw();
            bad[key] = value;
            assert!(metadata(&bad).is_err(), "{key}");
        }
        let mut rest = raw();
        rest.as_object_mut().unwrap().remove("storage_url");
        rest["id"] = json!(format!("{BUCKET}/{NAME}/{GENERATION}"));
        metadata(&rest).unwrap();
        rest.as_object_mut().unwrap().remove("md5_hash");
        assert!(metadata(&rest).is_err());
    }
    #[test]
    fn canonical_fingerprint_keeps_consensus_integers_exact() {
        let v = json!({"z":18446744073709551614u64,"a":[1,false,null]});
        let mut bytes = Vec::new();
        canonical(&v, &mut bytes).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"a\":[1,false,null],\"z\":18446744073709551614}"
        );
        assert!(fingerprint(&json!({"fraction":1.5})).is_err());
    }
}
