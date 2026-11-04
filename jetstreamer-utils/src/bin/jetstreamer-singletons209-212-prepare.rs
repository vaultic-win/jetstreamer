//! Exact offline singleton metadata from retained generation/CRC/MD5 bindings.
#[allow(dead_code)]
#[path = "../epoch141_ledger_common.rs"]
mod common;
#[allow(dead_code)]
#[path = "../../../jetstreamer-node/src/singletons209_212_profile.rs"]
mod profile;
use anyhow::{Context, Result, ensure};
use common::{bound_file, sha, write_receipt};
use profile::{Profile, Snapshot};
use serde_json::{Value, json};
use std::{
    env,
    path::{Path, PathBuf},
};
const SOURCE_SHA: &str = "7389720afed30d7480f952b240f3469974e5a18ceb02e01c8e3086fd6f71eb97";
const SOURCE_FP: &str = "sha256:63e4f6b5f858ed636b2c22bc15f971d0f4a1009b50f39f66b779df782060976d";
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
    Ok(format!("sha256:{}", sha(&bytes)))
}
fn source_snapshot(v: &Value, s: Snapshot) -> Result<()> {
    ensure!(
        v["slot"] == s.slot
            && v["anchor_slot"] == s.slot
            && v["accounts_hash"] == s.hash
            && v["generation"] == s.generation
            && v["size"] == s.size
            && v["crc32c"] == s.crc
            && v["source"] == "root"
            && v["extension"] == ".tar.zst"
            && v["uri"] == s.uri()
            && v["versioned_uri"] == s.versioned_uri(),
        "retained canonical snapshot tuple differs"
    );
    Ok(())
}
fn snapshot_binding(v: &Value, s: Snapshot) -> Result<()> {
    ensure!(
        v["versioned_uri"] == s.versioned_uri()
            && v["size"] == s.size
            && v["crc32c_base64"] == s.crc
            && v["md5_base64"] == s.md5,
        "retained checksum binding differs"
    );
    Ok(())
}
fn derive(source: &Value, bindings: &Value, p: Profile) -> Result<Value> {
    ensure!(
        source["manifest_fingerprint"] == SOURCE_FP
            && fingerprint(&source["manifest"])? == SOURCE_FP
            && source["manifest"]["schema"] == "jetstreamer-gcs-snapshot-preflight-v2"
            && source["manifest"]["bucket"] == "gs://mainnet-beta-ledger-us-ny5"
            && bindings["epoch"] == p.epoch
            && bindings["preflight_manifest_fingerprint"] == SOURCE_FP,
        "wrong retained source or epoch binding"
    );
    let selected = source["manifest"]["verification_cohorts"]
        .as_array()
        .context("retained cohorts")?
        .iter()
        .filter(|c| c["first_epoch"] == p.epoch && c["last_epoch"] == p.epoch)
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "singleton source omitted or duplicated"
    );
    let mut entry = selected[0].clone();
    ensure!(
        entry["runtime"] == "solana-v1.6.16"
            && entry["root_checkpoints"]
                .as_array()
                .is_some_and(|r| r.len() == 1)
            && entry["publication_gate"] == "all-archives-validated-and-final-root-verified",
        "wrong runtime, publication gate or root census"
    );
    source_snapshot(&entry["bootstrap"], p.bootstrap)?;
    source_snapshot(&entry["root_checkpoints"][0], p.root)?;
    snapshot_binding(&bindings["bootstrap"], p.bootstrap)?;
    snapshot_binding(&bindings["terminal"], p.root)?;
    entry["bootstrap"]["md5_hash"] = json!(p.bootstrap.md5);
    entry["root_checkpoints"][0]["md5_hash"] = json!(p.root.md5);
    let manifest = json!({"schema":"jetstreamer-gcs-snapshot-preflight-v4","bucket":"gs://mainnet-beta-ledger-us-ny5","epoch_slots":432000,
        "first_epoch":p.epoch,"last_epoch":p.epoch,"verification_cohorts":[entry]});
    Ok(
        json!({"manifest":manifest,"manifest_fingerprint":fingerprint(&manifest)?,"preparation":{
        "schema":"jetstreamer-private-v1616-singleton-offline-preparation-v1","epoch":p.epoch,
        "retained_package":p.package,"source_preflight_sha256":SOURCE_SHA,"source_manifest_fingerprint":SOURCE_FP,
        "snapshot_bindings_sha256":p.bindings_sha,"bootstrap_slot":p.bootstrap.slot,"output_slot_start":p.start(),
        "output_slot_end_exclusive":p.end(),"output_slot_count":432000,"canonical_root_slots":[p.root.slot],"post_root_slot_count":p.end()-1-p.root.slot,
        "both_exact_generation_checksum_bindings_revalidated":true,"successor_epoch_input_required":false,"cached_body_full_reread_performed":false,
        "native_input_qualified":false,"runtime_registry_promoted":false,"snapshot_restored":false,"worker_started":false,"replay_entries":0,
        "resource_observation_taken":false,"resource_admission_passed":false,"launch_authorized":false,"full_epoch_qualified":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}}),
    )
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 5 && a[3] == "--self-sha256" && unsafe { libc::geteuid() } == 0,
        "usage: prepare EPOCH OUTPUT --self-sha256 SHA (root)"
    );
    bound_file(
        &Path::new("/proc/self/exe").read_link()?,
        &a[4],
        64 << 20,
        true,
    )?;
    let p = profile::profile(a[1].parse()?).map_err(anyhow::Error::msg)?;
    let output = PathBuf::from(&a[2]);
    ensure!(
        output.file_name().and_then(|n| n.to_str())
            == Some(format!("preflight{}-singleton.json", p.epoch).as_str())
            && output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&format!("horizon-singleton-{}-", p.epoch))),
        "wrong singleton output scope"
    );
    let source = Path::new(p.package).join("preflight-root-only-203-213.json");
    let bindings = Path::new(p.package).join(format!("snapshot-bindings-{}.json", p.epoch));
    let source: Value = serde_json::from_slice(&bound_file(&source, SOURCE_SHA, 16 << 20, true)?)?;
    let bindings: Value =
        serde_json::from_slice(&bound_file(&bindings, p.bindings_sha, 65536, true)?)?;
    let mut result = derive(&source, &bindings, p)?;
    result["preparation"]["helper_sha256"] = json!(a[4]);
    write_receipt(&output, &result)?;
    println!(
        "{} {}",
        output.display(),
        result["manifest_fingerprint"]
            .as_str()
            .context("fingerprint")?
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
    fn all_four_real_retained_profiles_derive_exact_singletons_without_authority() {
        let bytes = include_bytes!("../../tests/fixtures/singletons209-212/source.json");
        assert_eq!(sha(bytes), SOURCE_SHA);
        let source: Value = serde_json::from_slice(bytes).unwrap();
        let bindings: [&[u8]; 4] = [
            include_bytes!("../../tests/fixtures/singletons209-212/bindings209.json"),
            include_bytes!("../../tests/fixtures/singletons209-212/bindings210.json"),
            include_bytes!("../../tests/fixtures/singletons209-212/bindings211.json"),
            include_bytes!("../../tests/fixtures/singletons209-212/bindings212.json"),
        ];
        for (p, bytes) in profile::PROFILES.into_iter().zip(bindings) {
            assert_eq!(sha(bytes), p.bindings_sha);
            let bindings: Value = serde_json::from_slice(bytes).unwrap();
            let result = derive(&source, &bindings, p).unwrap();
            assert_eq!(result["manifest"]["first_epoch"], p.epoch);
            assert_eq!(result["manifest"]["last_epoch"], p.epoch);
            assert_eq!(
                result["manifest"]["verification_cohorts"][0]["root_checkpoints"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(result["preparation"]["output_slot_count"], 432000);
            assert_eq!(result["preparation"]["launch_authorized"], false);
            assert_eq!(
                result["preparation"]["cached_body_full_reread_performed"],
                false
            );
            let mut bad = bindings.clone();
            bad["epoch"] = json!(207);
            assert!(derive(&source, &bad, p).is_err());
            let mut bad = bindings;
            bad["terminal"]["md5_base64"] = Value::Null;
            assert!(derive(&source, &bad, p).is_err());
        }
    }
    #[test]
    fn canonical_snapshot_binding_rejects_generation_crc_md5_and_epoch_substitution() {
        for p in profile::PROFILES {
            let valid = json!({"versioned_uri":p.bootstrap.versioned_uri(),"size":p.bootstrap.size,"crc32c_base64":p.bootstrap.crc,"md5_base64":p.bootstrap.md5});
            snapshot_binding(&valid, p.bootstrap).unwrap();
            for (k, v) in [
                ("versioned_uri", json!(p.root.versioned_uri())),
                ("size", json!(p.bootstrap.size + 1)),
                ("crc32c_base64", json!("AAAAAA==")),
                ("md5_base64", Value::Null),
            ] {
                let mut bad = valid.clone();
                bad[k] = v;
                assert!(
                    snapshot_binding(&bad, p.bootstrap).is_err(),
                    "{}:{k}",
                    p.epoch
                );
            }
        }
    }
}
