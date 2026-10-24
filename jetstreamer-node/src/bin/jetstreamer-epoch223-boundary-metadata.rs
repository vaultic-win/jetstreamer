//! Fixed, read-only finalized RPC collection for epoch 223 canonical boundaries.
//! No archive scan, replay, runtime admission, sidecar, import or R2 operation.
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
const ROLES: [(&str, u64); 3] = [
    ("anchor", 96335999),
    ("first", 96336000),
    ("terminal", 96767999),
];
const MAX_BYTES: usize = 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    output_directory: PathBuf,
}
fn request(slot: u64) -> Value {
    json!({"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,
    {"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]})
}
fn hash(v: &Value) -> Result<&str> {
    let text = v.as_str().context("boundary blockhash must be a string")?;
    let value: text_hash::Hash = text.parse().context("invalid boundary blockhash")?;
    ensure!(
        value != text_hash::Hash::default() && value.to_string() == text,
        "noncanonical/zero boundary blockhash"
    );
    Ok(text)
}
// A small alias keeps the actual shared Hash parser/version explicit.
mod text_hash {
    pub(super) use solana_hash::Hash;
}
fn block(v: &Value, slot: u64) -> Result<&Value> {
    ensure!(
        v["jsonrpc"] == "2.0" && v["id"] == slot && v.get("error").is_none(),
        "boundary RPC response id/error differs"
    );
    let r = &v["result"];
    ensure!(
        r.is_object()
            && r["parentSlot"].as_u64().is_some_and(|p| p < slot)
            && r["blockHeight"].as_u64().is_some_and(|h| h > 0)
            && r["blockTime"].as_i64().is_some_and(|t| t > 0),
        "canonical boundary is unavailable/skipped or metadata is incomplete; preserve evidence and obtain a trusted exact boundary, never invent a hash"
    );
    hash(&r["blockhash"])?;
    hash(&r["previousBlockhash"])?;
    Ok(r)
}
fn derive(responses: &BTreeMap<String, Value>) -> Result<Value> {
    ensure!(
        responses
            .keys()
            .map(String::as_str)
            .eq(ROLES.iter().map(|(r, _)| *r)),
        "incomplete canonical boundary response census"
    );
    let a = block(&responses["anchor"], ROLES[0].1)?;
    let f = block(&responses["first"], ROLES[1].1)?;
    let t = block(&responses["terminal"], ROLES[2].1)?;
    ensure!(
        f["parentSlot"] == ROLES[0].1
            && f["previousBlockhash"] == a["blockhash"]
            && f["blockHeight"].as_u64()
                == a["blockHeight"].as_u64().and_then(|n| n.checked_add(1))
            && t["blockHeight"]
                .as_u64()
                .zip(f["blockHeight"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && t["blockTime"]
                .as_i64()
                .zip(f["blockTime"].as_i64())
                .is_some_and(|(a, b)| a >= b),
        "canonical first block does not link to slot 96335999 or terminal metadata goes backwards"
    );
    Ok(
        json!({"candidate_anchor":{"slot":96335999,"blockhash":a["blockhash"]},
        "first_rpc_child":{"slot":96336000,"blockhash":f["blockhash"],"parent_slot":f["parentSlot"],"parent_blockhash":f["previousBlockhash"]},
        "expected_terminal":{"slot":96767999,"blockhash":t["blockhash"]},"canonical_epoch_output_start":96336000,
        "canonical_epoch_output_count":432000,"parent_and_child_rpc_hash_link_matches":true}),
    )
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("metadata output parent")?;
    let mut out = tempfile::NamedTempFile::new_in(parent)?;
    out.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    out.write_all(bytes)?;
    out.as_file().sync_all()?;
    out.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("canonical metadata output occupied: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn binding(path: &Path) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o400
            && m.len() <= MAX_BYTES as u64,
        "unsafe existing canonical metadata"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        evidence::identity(&m) == evidence::identity(&file.metadata()?),
        "canonical metadata changed before opening"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_BYTES
            && bytes.len() as u64 == m.len()
            && evidence::identity(&m) == evidence::identity(&file.metadata()?)
            && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "canonical metadata changed during bounded read"
    );
    Ok(json!({"path":path,"sha256":evidence::sha(&bytes)}))
}
async fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "canonical metadata collector requires root"
    );
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &args[2], 128 << 20, true)?;
    let p: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[0]),
        &args[1],
        65536,
        true,
    )?)?;
    ensure!(
        p.schema == "jetstreamer-epoch223-canonical-boundary-collection-plan-v1"
            && p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-canonical-metadata-")),
        "canonical metadata output scope differs"
    );
    let d = &p.output_directory;
    let m = fs::symlink_metadata(d)?;
    ensure!(
        d.canonicalize()? == *d && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "canonical metadata directory must be root-private"
    );
    let client = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut requests = BTreeMap::new();
    let mut responses = BTreeMap::new();
    let mut rows = BTreeMap::new();
    let mut network_requests = 0u64;
    for (role, slot) in ROLES {
        let wanted = serde_json::to_vec(&request(slot))?;
        let rq = d.join(format!("{role}.request.json"));
        let rp = d.join(format!("{role}.response.json"));
        if rq.try_exists()? {
            let b = binding(&rq)?;
            ensure!(
                b["sha256"] == evidence::sha(&wanted),
                "existing canonical request differs"
            );
        } else {
            write(&rq, &wanted)?;
        }
        if !rp.try_exists()? {
            let mut response = client
                .post(ENDPOINT)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(wanted)
                .send()
                .await?;
            ensure!(
                response.status().is_success()
                    && response
                        .content_length()
                        .is_none_or(|n| n <= MAX_BYTES as u64),
                "canonical RPC HTTP response failed/oversized"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes
                        .len()
                        .checked_add(chunk.len())
                        .is_some_and(|n| n <= MAX_BYTES),
                    "canonical RPC response exceeds bounded metadata size"
                );
                bytes.extend_from_slice(&chunk);
            }
            // Preserve actual error/null bytes too. A rerun never overwrites them.
            write(&rp, &bytes)?;
            network_requests += 1;
        }
        let rb = binding(&rp)?;
        let raw =
            evidence::bound_file(&rp, rb["sha256"].as_str().unwrap(), MAX_BYTES as u64, true)?;
        rows.insert(role.into(), serde_json::from_slice(&raw)?);
        requests.insert(role, binding(&rq)?);
        responses.insert(role, rb);
    }
    let derived = derive(&rows)?;
    let receipt = json!({"schema":"jetstreamer-private-epoch223-boundary-metadata-v1","epoch":223,"endpoint":ENDPOINT,
        "collector_sha256":args[2],"plan":{"path":args[0],"sha256":args[1]},"requests":requests,"responses":responses,
        "derived":derived,"finalized_commitment_requested":true,"redirects_permitted":false,"raw_rpc_responses_rehashed":true,
        "network_requests_this_invocation":network_requests,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "archive_opened":false,"archive_initial_boundary_verified":false,"complete_coverage_verified":false,"independent_full_poh_verified":false,
        "runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let output = d.join("candidate.json");
    if output.try_exists()? {
        let b = binding(&output)?;
        let old: Value = serde_json::from_slice(&evidence::bound_file(
            &output,
            b["sha256"].as_str().unwrap(),
            MAX_BYTES as u64,
            true,
        )?)?;
        for key in [
            "schema",
            "epoch",
            "endpoint",
            "collector_sha256",
            "plan",
            "requests",
            "responses",
            "derived",
        ] {
            ensure!(
                old[key] == receipt[key],
                "existing canonical candidate conflicts:{key}"
            );
        }
    } else {
        let mut bytes = serde_json::to_vec_pretty(&receipt)?;
        bytes.push(b'\n');
        write(&output, &bytes)?;
    }
    println!(
        "canonical epoch 223 metadata preserved; independent V3 full/plugin/import gates remain closed"
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn response(slot: u64, parent: u64, height: u64, hash: u8, previous: u8) -> Value {
        json!({"jsonrpc":"2.0","id":slot,"result":{"parentSlot":parent,"blockHeight":height,"blockTime":1000+(slot-ROLES[0].1),
            "blockhash":text_hash::Hash::new_from_array([hash;32]).to_string(),"previousBlockhash":text_hash::Hash::new_from_array([previous;32]).to_string()}})
    }
    fn fixture() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("anchor".into(), response(96335999, 96335998, 100, 1, 9)),
            ("first".into(), response(96336000, 96335999, 101, 2, 1)),
            ("terminal".into(), response(96767999, 96767998, 200, 3, 4)),
        ])
    }
    #[test]
    fn exact_adjacent_anchor_is_separate_from_the_earlier_native_bootstrap() {
        let rows = fixture();
        let d = derive(&rows).unwrap();
        assert_eq!(d["candidate_anchor"]["slot"], 96335999);
        assert_eq!(d["expected_terminal"]["slot"], 96767999);
        assert_eq!(d["canonical_epoch_output_count"], 432000);
        for (role, pointer, value) in [
            ("anchor", "/id", json!(96335538)),
            ("first", "/result/parentSlot", json!(96335538)),
            (
                "first",
                "/result/previousBlockhash",
                json!(text_hash::Hash::new_from_array([8; 32]).to_string()),
            ),
            ("terminal", "/result", Value::Null),
            ("terminal", "/result/blockHeight", json!(99)),
        ] {
            let mut bad = rows.clone();
            *bad.get_mut(role).unwrap().pointer_mut(pointer).unwrap() = value;
            assert!(derive(&bad).is_err(), "{role}:{pointer}");
        }
    }
    #[test]
    fn finalized_exact_requests_and_response_failures_never_grant_archive_coverage() {
        for (_, slot) in ROLES {
            let r = request(slot);
            assert_eq!(r["id"], slot);
            assert_eq!(r["params"][0], slot);
            assert_eq!(r["params"][1]["commitment"], "finalized");
        }
        let mut bad = fixture();
        bad.get_mut("anchor").unwrap()["error"] = json!({"code":-32004});
        assert!(derive(&bad).is_err());
        let mut bad = fixture();
        bad.remove("first");
        assert!(derive(&bad).is_err());
        assert!(hash(&json!(text_hash::Hash::default().to_string())).is_err());
    }
}
