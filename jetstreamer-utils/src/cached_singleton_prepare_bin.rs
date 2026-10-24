//! Offline planning from frozen root metadata and existing immutable inputs.
//! No worker, Bank, GCloud, network, archive, runtime admission or R2 access.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const PROFILE: &str = "epoch228-v1620-root-tail";
const SOURCE_SHA: &str = "ef1c66a65556d5b4431037014fb43b41a1fd75f515a6c644438fcc22f21ccbf6";
const SOURCE_FP: &str = "sha256:c6eb7167208bdaac92b70cb733bede6069f66807e383de7b65b8de6c2cc31066";
const SNAPSHOT_SHA: &str = "da26bd1b4b3b93be74c9dae28d1d982f821474333aa06e87f32dfa83342915f3";
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    profile: String,
    source: Bound,
    node: Bound,
    genesis: Bound,
    bootstrap_cache: Bound,
    output_directory: PathBuf,
}
fn fingerprint(v: &Value) -> Result<String> {
    fn ordered(v: &Value) -> Result<Value> {
        Ok(match v {
            Value::Object(m) => {
                let sorted = m
                    .iter()
                    .map(|(k, v)| {
                        ensure!(k.is_ascii(), "non-ASCII key");
                        Ok((k.clone(), ordered(v)?))
                    })
                    .collect::<Result<BTreeMap<_, _>>>()?;
                serde_json::to_value(sorted)?
            }
            Value::Array(a) => Value::Array(a.iter().map(ordered).collect::<Result<Vec<_>>>()?),
            Value::Number(n) => {
                ensure!(n.is_u64() || n.is_i64(), "manifest floats forbidden");
                v.clone()
            }
            Value::String(s) => {
                ensure!(s.is_ascii(), "non-ASCII manifest string");
                v.clone()
            }
            _ => v.clone(),
        })
    }
    Ok(format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&ordered(v)?)?)
    ))
}
fn same(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
}
fn read(b: &Bound, maximum: u64) -> Result<Value> {
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && b.sha256.len() == 64
            && b.sha256
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "invalid immutable binding"
    );
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= maximum,
        "unsafe immutable input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    ensure!(same(&m, &f.metadata()?), "input replaced at open");
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("input overflow")?;
        ensure!(count <= maximum, "input grew");
        hash.update(&buffer[..n]);
    }
    ensure!(
        count == m.len()
            && same(&m, &f.metadata()?)
            && same(&m, &fs::symlink_metadata(&b.path)?)
            && format!("{:x}", hash.finalize()) == b.sha256,
        "input changed or digest differs"
    );
    Ok(json!({"path":b.path,"sha256":b.sha256,"bytes":count,"device":m.dev(),"inode":m.ino()}))
}
fn read_json(b: &Bound, maximum: u64) -> Result<Value> {
    let input = read(b, maximum)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&b.path)?;
    let m = f.metadata()?;
    let mut bytes = Vec::new();
    f.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum
            && m.ino() == input["inode"].as_u64().context("bound inode")?
            && m.dev() == input["device"].as_u64().context("bound device")?
            && format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "JSON input changed after binding"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn derive(source: &Value) -> Result<Value> {
    let m = &source["manifest"];
    ensure!(
        source["manifest_fingerprint"] == SOURCE_FP
            && fingerprint(m)? == SOURCE_FP
            && m["schema"] == "jetstreamer-gcs-snapshot-preflight-v4"
            && m["bucket"] == "gs://mainnet-beta-ledger-us-ny5"
            && m["epoch_slots"] == 432000,
        "source metadata authority differs"
    );
    derive_manifest(m)
}
fn derive_manifest(m: &Value) -> Result<Value> {
    let candidates = m["verification_cohorts"]
        .as_array()
        .context("source cohorts")?
        .iter()
        .filter(|c| {
            c["first_epoch"].as_u64().is_some_and(|n| n <= 228)
                && c["last_epoch"].as_u64().is_some_and(|n| n >= 228)
        })
        .collect::<Vec<_>>();
    ensure!(candidates.len() == 1, "source 228 cohort missing/duplicate");
    let c = candidates[0];
    ensure!(
        c["runtime"] == "solana-v1.6.20"
            && c["publication_gate"] == "all-archives-validated-and-final-root-verified",
        "source runtime/gate changed"
    );
    let bootstrap = &c["bootstrap"];
    ensure!(
        bootstrap["slot"] == 98_495_291u64
            && bootstrap["source"] == "root"
            && bootstrap["generation"] == 1_633_013_483_898_142u64
            && bootstrap["accounts_hash"] == "GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq"
            && bootstrap["size"] == 10_510_540_911u64
            && bootstrap["md5_hash"] == "rl4K2g2yB+AxECfkBXMEKQ=="
            && bootstrap["crc32c"] == "U/kA/w==",
        "retained bootstrap binding changed"
    );
    let roots = c["root_checkpoints"].as_array().context("source roots")?;
    ensure!(
        !roots.iter().any(|r| r["slot"]
            .as_u64()
            .is_some_and(|s| (98_496_000..=98_927_999).contains(&s))),
        "228 in-epoch root appeared; review the shorter route"
    );
    let terminal = roots
        .iter()
        .filter(|r| r["slot"].as_u64().is_some_and(|s| s > 98_927_999))
        .min_by_key(|r| r["slot"].as_u64())
        .context("no later trusted checkpoint")?;
    ensure!(
        terminal["slot"] == 98_928_278u64
            && terminal["source"] == "root"
            && terminal["generation"] == 1_633_247_230_841_050u64
            && terminal["accounts_hash"] == "6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra"
            && terminal["size"] == 10_281_222_478u64
            && terminal["md5_hash"] == "qHaeoiHjciwFHRaK9rCCSQ=="
            && terminal["crc32c"] == "S5T4hw==",
        "first later checkpoint changed"
    );
    let cohort = json!({"accepted_extensions":c["accepted_extensions"],"bootstrap":bootstrap,"first_epoch":228,"last_epoch":229,"publish_through_epoch":228,
        "publication_gate":"all-archives-validated-and-final-root-verified","root_checkpoints":[terminal],"runtime":"solana-v1.6.20"});
    let manifest = json!({"schema":"jetstreamer-gcs-snapshot-preflight-v4","bucket":"gs://mainnet-beta-ledger-us-ny5","epoch_slots":432000,"first_epoch":228,"last_epoch":229,"publication_boundary_epoch":228,"verification_cohorts":[cohort]});
    Ok(
        json!({"manifest_fingerprint":fingerprint(&manifest)?,"manifest":manifest,"preparation":{"profile":PROFILE,"requested_epoch":228,
        "intended_publication_epochs":[228],"intended_private_verification_epochs":[229],"canonical_bootstrap_slot":98495291,"canonical_checkpoint_slot":98928278,
        "complete_epoch_output":{"first_slot":98496000,"last_slot":98927999,"slot_count":432000},"minimum_post_epoch_verification_slots":279,
        "existing_cohort_route_runs_through_slot":99359999,"ordinary_singleton_has_in_epoch_checkpoint":false,
        "focused_tail_output_slot_count":432279,"focused_tail_output_is_canonical_epoch_archive":false,
        "capped227_worker_accepts_this_bootstrap":false,"new_closed_capped_profile_and_tail_extraction_qualification_required":true,
        "fresh_cohort_manifest_alone_enforces_publication_prefix":false,
        "bank_restored":false,"worker_spawned":false,"native_input_qualified":false,"runtime_route_qualified":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}}),
    )
}
fn write(path: &Path, v: &Value) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(v)?;
    if path.try_exists()? {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file()
                && m.uid() == unsafe { libc::geteuid() }
                && m.nlink() == 1
                && m.mode() & 0o222 == 0,
            "unsafe existing preparation"
        );
        ensure!(fs::read(path)? == bytes, "existing preparation conflicts");
        return Ok(());
    }
    let parent = path.parent().context("output parent")?;
    let mut t = tempfile::NamedTempFile::new_in(parent)?;
    t.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    t.write_all(&bytes)?;
    t.as_file().sync_all()?;
    t.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("preparation publication: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn run() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "cached-singleton-prepare PLAN --plan-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[5].clone(),
    };
    let own_binding = read(&own, 100 << 20)?;
    let plan_binding = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read_json(&plan_binding, 1 << 20)?)?;
    ensure!(
        p.schema == "jetstreamer-cached-singleton-prepare-plan-v1"
            && p.profile == PROFILE
            && p.source.sha256 == SOURCE_SHA
            && p.node.sha256 == "f2c11e5b596e5a0107ddded523c310a1deb71b9206e95f3113f5ac713b920e11"
            && p.genesis.sha256
                == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945"
            && p.bootstrap_cache.sha256 == SNAPSHOT_SHA,
        "unreviewed profile or input"
    );
    let d = fs::symlink_metadata(&p.output_directory)?;
    ensure!(
        p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-cached-singleton-228-"))
            && p.output_directory.canonicalize()? == p.output_directory
            && d.is_dir()
            && d.uid() == 0
            && d.mode() & 0o077 == 0,
        "unsafe preparation destination"
    );
    let source_binding = read(&p.source, 16 << 20)?;
    let source = read_json(&p.source, 16 << 20)?;
    let report = derive(&source)?;
    let inputs = vec![
        read(&p.node, 100 << 20)?,
        read(&p.genesis, 1 << 20)?,
        read(&p.bootstrap_cache, 11u64 << 30)?,
    ];
    ensure!(
        inputs[2]["bytes"] == 10_510_540_911u64,
        "cached bootstrap size differs"
    );
    write(&p.output_directory.join("manifest.json"), &report)?;
    write(
        &p.output_directory.join("epoch-hashes.json"),
        &json!({"98495291":"GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq","98928278":"6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra"}),
    )?;
    write(
        &p.output_directory.join("capability.json"),
        &json!({"schema":"jetstreamer-private-cached-singleton-input-capability-v1","profile":PROFILE,"source":source_binding,"plan":plan_binding,"self":own_binding,"inputs":inputs,
        "manifest_fingerprint":report["manifest_fingerprint"],"preparation":report["preparation"],"all_immutable_inputs_rehashed":true,"bank_restored":false,"worker_spawned":false,"resource_samples_taken":0,
        "native_input_qualified":false,"runtime_route_qualified":false,"replay_launch_authorized":false,"publication_authorized":false,"downloads":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("{}", p.output_directory.join("capability.json").display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn metadata() -> Value {
        json!({"verification_cohorts":[{"first_epoch":228,"last_epoch":230,"runtime":"solana-v1.6.20","publication_gate":"all-archives-validated-and-final-root-verified","accepted_extensions":[".tar.bz2",".tar.zst"],
            "bootstrap":{"slot":98495291,"source":"root","generation":1633013483898142u64,"accounts_hash":"GfiRSgpC1qvH3uxVd9VAtYZ6qKM8fcdkyoyAkhF7izLq","size":10510540911u64,"md5_hash":"rl4K2g2yB+AxECfkBXMEKQ==","crc32c":"U/kA/w=="},
            "root_checkpoints":[{"slot":98928278,"source":"root","generation":1633247230841050u64,"accounts_hash":"6Ec1ZPL4kEMFLU2qAsRfrbmYnEhm8pL77Xt1PoBhyGra","size":10281222478u64,"md5_hash":"qHaeoiHjciwFHRaK9rCCSQ==","crc32c":"S5T4hw=="}]}]})
    }
    #[test]
    fn next_root_requires_279_private_tail_slots_and_cannot_qualify_a_canonical_archive() {
        let report = derive_manifest(&metadata()).unwrap();
        assert_eq!(
            report["preparation"]["minimum_post_epoch_verification_slots"],
            279
        );
        assert_eq!(
            report["preparation"]["focused_tail_output_slot_count"],
            432279
        );
        assert_eq!(
            report["preparation"]["focused_tail_output_is_canonical_epoch_archive"],
            false
        );
        assert_eq!(
            report["manifest"]["verification_cohorts"][0]["publish_through_epoch"],
            228
        );
        assert_eq!(
            report["manifest"]["verification_cohorts"][0]["last_epoch"],
            229
        );
        for (pointer, value) in [
            ("/verification_cohorts/0/runtime", json!("solana-v1.6.25")),
            ("/verification_cohorts/0/bootstrap/slot", json!(98063464)),
            (
                "/verification_cohorts/0/root_checkpoints/0/source",
                json!("hourly"),
            ),
            (
                "/verification_cohorts/0/root_checkpoints/0/slot",
                json!(98927999),
            ),
            (
                "/verification_cohorts/0/root_checkpoints/0/accounts_hash",
                json!("invented"),
            ),
        ] {
            let mut bad = metadata();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(derive_manifest(&bad).is_err(), "{pointer}");
        }
    }
    #[test]
    fn canonical_fingerprint_keeps_raw_integers_and_rejects_floats() {
        assert_eq!(
            fingerprint(&json!({"z":18446744073709551614u64,"a":1})).unwrap(),
            fingerprint(
                &serde_json::from_str::<Value>("{\"a\":1,\"z\":18446744073709551614}").unwrap()
            )
            .unwrap()
        );
        assert!(fingerprint(&json!({"a":1.5})).is_err());
    }
    #[test]
    fn output_is_idempotent_and_never_replaces_evidence() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("proof.json");
        write(&p, &json!({"x":1})).unwrap();
        write(&p, &json!({"x":1})).unwrap();
        assert!(write(&p, &json!({"x":2})).is_err());
    }
    #[test]
    fn manifest_fingerprint_and_root_authority_cannot_be_invented() {
        assert!(derive(&json!({"manifest_fingerprint":SOURCE_FP,"manifest":{}})).is_err());
    }
}
