//! Closed offline collection of finalized203 RPC boundary metadata.
//! Never opens an archive, contacts RPC/R2, promotes a runtime or permits publication.
#[allow(dead_code)]
mod epoch141_ledger_common;
use anyhow::{Context, Result, ensure};
use epoch141_ledger_common::{bound_file, is_sha, sha, write_receipt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
const PARENT: u64 = 87_695_999;
const FIRST: u64 = 87_696_000;
const LAST: u64 = 88_127_999;
const PARENT_HASH: &str = "4c9Zfnjqk9Ur8gLU6woi1wJEZePZN37MfjVFGVuKt5su";
const FIRST_HASH: &str = "EEopsKp9p26aNzCULSmj7MNVwgb9LCvtMi5xxEEX8651";
const LAST_HASH: &str = "8eVbfSWY2UX4KW1ms9y7TJNmJEfc5DfFoXa5iF5W7XgR";
const RESPONSES: [(&str, &str); 4] = [
    (
        "first",
        "d401c4fec2571f469de244962346239dcc694fdc51cb4b2cc0531139459325da",
    ),
    (
        "first_slots",
        "0a5c1bfb8ba23a962f6abca65ef6ea9bd00c0e2d312edaa59cf1436fd0c6c06d",
    ),
    (
        "parent",
        "0307664dcb761b1532ce96de01f54c7bd62ababa820d5589bf007e3b271d6587",
    ),
    (
        "terminal",
        "07c8ea33dc1b57e19891acef812234fd5bd0e1f535a7fd2872539dd49fe1d181",
    ),
];
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
    endpoint: String,
    responses: BTreeMap<String, Bound>,
    output: PathBuf,
}
fn plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch203-boundary-metadata-plan-v1"
            && p.endpoint == ENDPOINT
            && p.responses
                .keys()
                .map(String::as_str)
                .eq(RESPONSES.iter().map(|(k, _)| *k)),
        "203 metadata scope differs"
    );
    for (k, hash) in RESPONSES {
        ensure!(
            p.responses[k].sha256 == hash,
            "203 changed raw response:{k}"
        );
    }
    let parent = p.output.parent().context("203 metadata output parent")?;
    ensure!(
        p.output.file_name().and_then(|n| n.to_str()) == Some("candidate.json")
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-203-boundary-metadata-")
                    && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "203 metadata output outside private scope"
    );
    Ok(())
}
fn hash(value: &Value) -> Result<&str> {
    let h = value.as_str().context("203 blockhash is not a string")?;
    let bytes = bs58::decode(h)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("203 invalid base58 blockhash: {e}"))?;
    ensure!(
        bytes.len() == 32
            && bytes.iter().any(|v| *v != 0)
            && bs58::encode(bytes).into_string() == h,
        "203 noncanonical or zero blockhash"
    );
    Ok(h)
}
fn block(v: &Value, slot: u64) -> Result<&Value> {
    ensure!(
        v["jsonrpc"] == "2.0" && v["id"] == slot && v.get("error").is_none(),
        "203 response ID/error differs"
    );
    let r = &v["result"];
    ensure!(
        r.is_object()
            && r["parentSlot"].as_u64().is_some_and(|p| p < slot)
            && r["blockHeight"].as_u64().is_some()
            && r["blockTime"].as_i64().is_some_and(|t| t > 0),
        "203 incomplete finalized block metadata"
    );
    hash(&r["blockhash"])?;
    hash(&r["previousBlockhash"])?;
    Ok(r)
}
fn derive(rows: &BTreeMap<String, Value>) -> Result<Value> {
    ensure!(
        rows.keys()
            .map(String::as_str)
            .eq(RESPONSES.iter().map(|(k, _)| *k)),
        "203 incomplete response census"
    );
    let p = block(&rows["parent"], PARENT)?;
    let f = block(&rows["first"], FIRST)?;
    let t = block(&rows["terminal"], LAST)?;
    ensure!(
        hash(&p["blockhash"])? == PARENT_HASH
            && hash(&f["blockhash"])? == FIRST_HASH
            && f["parentSlot"] == PARENT
            && hash(&f["previousBlockhash"])? == PARENT_HASH
            && f["blockHeight"].as_u64()
                == p["blockHeight"].as_u64().and_then(|n| n.checked_add(1))
            && hash(&t["blockhash"])? == LAST_HASH
            && t["parentSlot"] == LAST - 1,
        "203 parent/child/terminal link differs from independently captured metadata"
    );
    let list = &rows["first_slots"];
    ensure!(
        list["jsonrpc"] == "2.0" && list["id"] == 203 && list.get("error").is_none(),
        "203 invalid getBlocks response"
    );
    let slots = list["result"]
        .as_array()
        .context("203 missing finalized first-block census")?;
    let values: Vec<u64> = slots
        .iter()
        .map(|v| v.as_u64().context("203 noninteger slot"))
        .collect::<Result<_>>()?;
    ensure!(
        values.first() == Some(&FIRST)
            && values.iter().all(|s| (FIRST..=FIRST + 20).contains(s))
            && values.windows(2).all(|w| w[0] < w[1]),
        "203 first-block census has wrong start, order or duplicates"
    );
    Ok(
        json!({"candidate_anchor":{"slot":PARENT,"blockhash":PARENT_HASH,
        "first_available_rpc_child_slot":FIRST,"first_available_rpc_child_blockhash":FIRST_HASH,
        "parent_and_child_rpc_hash_link_matches":true},"expected_terminal":{"slot":LAST,"blockhash":LAST_HASH},
        "finalized_first_slots":values,"canonical_epoch_output_start":FIRST,"canonical_epoch_output_count":432000}),
    )
}
fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[4] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: jetstreamer-epoch203-boundary-metadata PLAN --plan-sha256 SHA --self-sha256 SHA (root)"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&own)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && is_sha(&args[5])
            && sha(&fs::read("/proc/self/exe")?) == args[5],
        "203 metadata collector is not sealed"
    );
    let p: Plan = serde_json::from_slice(&bound_file(
        Path::new(&args[1]),
        &args[3],
        1024 * 1024,
        true,
    )?)?;
    plan(&p)?;
    let mut rows = BTreeMap::new();
    for (key, b) in &p.responses {
        rows.insert(
            key.clone(),
            serde_json::from_slice(&bound_file(&b.path, &b.sha256, 1024 * 1024, true)?)?,
        );
    }
    let derived = derive(&rows)?;
    let r = json!({"schema":"jetstreamer-private-epoch203-boundary-metadata-v1","epoch":203,
        "collector_sha256":args[5],"plan":{"path":args[1],"sha256":args[3]},"endpoint":ENDPOINT,
        "responses":p.responses,"derived":derived,"raw_rpc_responses_rehashed":true,"network_performed":false,
        "archive_opened":false,"archive_initial_boundary_verified":false,"complete_coverage_verified":false,
        "independent_full_poh_verified":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
        "limitations":["RPC metadata supplies candidate independent anchors, not complete archive coverage or replay correctness.",
            "Strict final verification must bind the actual complete assembled archive digest and exact V4 provenance and recompute its full PoH chain.",
            "This is not the separate adjacent-boundary receipt required for local retirement."]});
    write_receipt(&p.output, &r)?;
    println!(
        "203 independent RPC boundary candidates collected; archive verification/publication remain closed"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn rows() -> BTreeMap<String, Value> {
        [
            (
                "parent",
                include_str!("../tests/fixtures/epoch203-boundary-parent.json"),
            ),
            (
                "first",
                include_str!("../tests/fixtures/epoch203-boundary-first.json"),
            ),
            (
                "terminal",
                include_str!("../tests/fixtures/epoch203-boundary-terminal.json"),
            ),
            (
                "first_slots",
                include_str!("../tests/fixtures/epoch203-boundary-first-slots.json"),
            ),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), serde_json::from_str(v).unwrap()))
        .collect()
    }
    #[test]
    fn actual_metadata_supplies_only_exact_independent_anchor_candidates() {
        let r = derive(&rows()).unwrap();
        assert_eq!(r["candidate_anchor"]["slot"], PARENT);
        assert_eq!(r["expected_terminal"]["slot"], LAST);
        assert_eq!(r["canonical_epoch_output_count"], 432000);
    }
    #[test]
    fn changed_links_skipped_endpoints_errors_and_duplicate_slots_fail_closed() {
        let r = rows();
        for (key, pointer, bad) in [
            ("first", "/result/parentSlot", json!(PARENT - 1)),
            ("first", "/result/previousBlockhash", json!(LAST_HASH)),
            ("terminal", "/result/blockhash", json!(PARENT_HASH)),
            ("parent", "/id", json!(PARENT - 1)),
            ("first_slots", "/result/1", json!(FIRST)),
        ] {
            let mut changed = r.clone();
            *changed.get_mut(key).unwrap().pointer_mut(pointer).unwrap() = bad;
            assert!(derive(&changed).is_err(), "{key}:{pointer}");
        }
        let mut changed = r;
        changed.get_mut("terminal").unwrap()["error"] = json!({"code":-32007});
        assert!(derive(&changed).is_err());
    }
    #[test]
    fn bound_responses_cannot_be_replaced_or_grant_publication() {
        let b = |k: &str, h: &str| {
            (
                k.into(),
                Bound {
                    path: Path::new("/sealed").join(k),
                    sha256: h.into(),
                },
            )
        };
        let mut p = Plan {
            schema: "jetstreamer-private-epoch203-boundary-metadata-plan-v1".into(),
            endpoint: ENDPOINT.into(),
            responses: RESPONSES.iter().map(|(k, h)| b(k, h)).collect(),
            output: "/var/lib/jetstreamer/horizon-203-boundary-metadata-test/candidate.json".into(),
        };
        plan(&p).unwrap();
        p.responses.get_mut("first").unwrap().sha256 = "f".repeat(64);
        assert!(plan(&p).is_err());
        let v = json!({"schema":"jetstreamer-private-epoch203-boundary-metadata-plan-v1","endpoint":ENDPOINT,
            "responses":p.responses,"output":p.output,"publication_authorized":true});
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }
}
