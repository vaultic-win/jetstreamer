//! Fixed first-target, read-only RPC/original-shred transaction equivalence.
#[allow(dead_code)]
mod epoch141_acquired_input;
mod epoch141_poh_clock;
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use epoch141_acquired_input::{Bound, decode, read};
use jetstreamer_utils::{
    horizon_legacy_poh::PohExpectation,
    horizon_legacy_shred::{assemble_v1_4_25_padded_batches, decode_v1_4_25_complete_slot_meta},
    horizon_legacy_source::bind_v1_4_25_source_entries,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{fs, os::unix::fs::MetadataExt, path::PathBuf, process::Command, time::Instant};

const SLOT: u64 = 60_911_776;
const PARENT: u64 = 60_911_771;
const RAW: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2/results/target-acquisitions/slot-60911776.json";
const RAW_SHA: &str = "a911135ca8d32abf75db380e0bd13d9deda7ae789d522aeaa6977516126c5600";
const POH: &str = "/var/lib/jetstreamer/horizon-epoch141-census-poh-diagnostic-20261022-v2/targets/slot-60911776.json";
const POH_SHA: &str = "329ebed023c8bff71c885d1ee7aa34771b3e9d6e65b9dd59469fe4da21a7eeff";
const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";
const MAX_RESPONSE: usize = 16 << 20;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    curl: Bound,
    output_directory: PathBuf,
}

fn request() -> Value {
    json!({"jsonrpc":"2.0","id":SLOT,"method":"getBlock","params":[SLOT,
        {"commitment":"finalized","encoding":"base64","transactionDetails":"full",
         "rewards":false,"maxSupportedTransactionVersion":0}]})
}

fn source_transactions(v: &Value, anchor: &Value) -> Result<Vec<Vec<u8>>> {
    ensure!(
        v["jsonrpc"] == "2.0" && v["id"] == SLOT && v.get("error").is_none(),
        "RPC error or wrong identity"
    );
    let block = &v["result"];
    ensure!(
        block["parentSlot"] == PARENT
            && block["blockhash"] == anchor["final_poh_hash"]
            && block["previousBlockhash"] == anchor["previous_poh_hash"],
        "RPC parent/final anchors differ"
    );
    let transactions = block["transactions"]
        .as_array()
        .context("source transactions absent")?;
    ensure!(
        transactions.len() <= 65_536,
        "source transaction count exceeds bound"
    );
    transactions
        .iter()
        .map(|tx| {
            ensure!(
                tx["version"] == "legacy",
                "source transaction is not explicitly legacy"
            );
            let encoded = tx["transaction"]
                .as_array()
                .context("source wire tuple absent")?;
            ensure!(
                encoded.len() == 2 && encoded[1] == "base64",
                "wrong source encoding"
            );
            let encoded = encoded[0].as_str().context("source wire bytes absent")?;
            ensure!(
                encoded.len() <= 1644,
                "source transaction encoded length exceeds packet bound"
            );
            let bytes = STANDARD.decode(encoded)?;
            ensure!(
                !bytes.is_empty() && bytes.len() <= 1232 && STANDARD.encode(&bytes) == encoded,
                "noncanonical or oversized source transaction"
            );
            Ok(bytes)
        })
        .collect()
}

fn hash(v: &Value) -> Result<[u8; 32]> {
    bs58::decode(v.as_str().context("hash absent")?)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid base58 hash: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("hash length differs"))
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: source-equivalence PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "requires privileged immutable evidence reader"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    evidence::bound_file(&executable, &args[5], 128 << 20, true)?;
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        &PathBuf::from(&args[1]),
        &args[3],
        65536,
        true,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch141-first-source-equivalence-plan-v1",
        "wrong plan schema"
    );
    ensure!(
        plan.output_directory.parent() == Some(std::path::Path::new("/var/lib/jetstreamer"))
            && plan
                .output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch141-source-equivalence-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-".contains(&b))),
        "wrong output scope"
    );
    let directory = fs::symlink_metadata(&plan.output_directory)?;
    ensure!(
        directory.is_dir()
            && directory.uid() == 0
            && directory.mode() & 0o077 == 0
            && plan.output_directory.canonicalize()? == plan.output_directory
            && fs::read_dir(&plan.output_directory)?.next().is_none(),
        "output directory must be empty and root-private"
    );
    evidence::bound_file(&plan.curl.path, &plan.curl.sha256, 16 << 20, true)?;
    let raw = read(
        &Bound {
            path: RAW.into(),
            sha256: RAW_SHA.into(),
        },
        false,
    )?;
    let prior = read(
        &Bound {
            path: POH.into(),
            sha256: POH_SHA.into(),
        },
        false,
    )?;
    ensure!(
        prior["diagnostic_passed"] == true
            && prior["slot"] == SLOT
            && prior["parent_slot"] == PARENT
            && prior["raw_target"]["path"] == RAW
            && prior["raw_target"]["sha256"] == RAW_SHA,
        "wrong prior original-entry diagnostic"
    );
    ensure!(
        raw["slot"] == SLOT
            && raw["parent_slot"] == PARENT
            && raw["outcome"]["status"] == "raw-acquired",
        "wrong retained acquisition"
    );
    let clock = epoch141_poh_clock::load(
        &Bound {
            path: epoch141_poh_clock::CLOCK_PATH.into(),
            sha256: epoch141_poh_clock::CLOCK_SHA.into(),
        },
        &Bound {
            path: epoch141_poh_clock::NATIVE_PATH.into(),
            sha256: epoch141_poh_clock::NATIVE_SHA.into(),
        },
    )?;
    let started = Instant::now();
    let invocation =
        std::env::var("INVOCATION_ID").context("requires persistent systemd invocation")?;
    ensure!(
        invocation.len() == 32 && evidence::is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation"
    );
    let request = request();
    evidence::write_receipt(
        &plan.output_directory.join("request.json"),
        &json!({"endpoint":ENDPOINT,"request":request,"invocation_id":invocation}),
    )?;
    let response = Command::new(&plan.curl.path)
        .env_clear()
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--max-time",
            "30",
            "--max-filesize",
            "16777216",
            "-H",
            "Content-Type: application/json",
            "--data-raw",
            &serde_json::to_string(&request)?,
            ENDPOINT,
        ])
        .output()?;
    ensure!(
        response.stdout.len() <= MAX_RESPONSE && response.stderr.len() <= 65536,
        "RPC output exceeds bound"
    );
    let response_sha = evidence::sha(&response.stdout);
    evidence::write_receipt(
        &plan.output_directory.join("response.json"),
        &json!({
        "raw_base64":STANDARD.encode(&response.stdout),"raw_sha256":response_sha,"curl_success":response.status.success(),"stderr":String::from_utf8_lossy(&response.stderr)}),
    )?;
    ensure!(response.status.success(), "bounded RPC request failed");
    let source = source_transactions(
        &serde_json::from_slice(&response.stdout)?,
        &prior["finalized_metadata"],
    )?;
    let n = raw["outcome"]["summary"]["expected_data_shreds"]
        .as_u64()
        .context("missing shred count")?;
    ensure!((1..=65_528).contains(&n), "shred count exceeds bound");
    let first = decode(&raw["outcome"]["first_metadata"], 1)?;
    let records = decode(&raw["outcome"]["records"], n as usize + 8)?;
    let meta = decode_v1_4_25_complete_slot_meta(
        first[0].borrowed().value.context("missing metadata")?,
        SLOT,
        PARENT,
    )
    .map_err(anyhow::Error::msg)?;
    let shreds = records[8..]
        .iter()
        .map(|r| r.borrowed().value.context("missing shred"))
        .collect::<Result<Vec<_>>>()?;
    let batches = assemble_v1_4_25_padded_batches(SLOT, PARENT, meta.last_index, &shreds)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        batches.iter().map(|b| b.last_index).collect::<Vec<_>>() == meta.completed_data_indexes,
        "batch endpoint mismatch"
    );
    let expected = PohExpectation {
        slot: SLOT,
        parent_slot: PARENT,
        parent_hash: hash(&prior["finalized_metadata"]["previous_poh_hash"])?,
        final_hash: hash(&prior["finalized_metadata"]["final_poh_hash"])?,
        ticks_per_slot: clock.ticks_per_slot,
        hashes_per_tick: clock.hashes_per_tick,
    };
    let matched = bind_v1_4_25_source_entries(
        &batches
            .iter()
            .map(|b| b.bytes.as_slice())
            .collect::<Vec<_>>(),
        &source.iter().map(Vec::as_slice).collect::<Vec<_>>(),
        &expected,
        4_000_000,
        || {
            if started.elapsed().as_secs() > 90 {
                Err("equivalence deadline exceeded".into())
            } else {
                Ok(())
            }
        },
    )
    .map_err(anyhow::Error::msg)?;
    // Revalidate immutable inputs and the exact executable after all external/hash work.
    read(
        &Bound {
            path: RAW.into(),
            sha256: RAW_SHA.into(),
        },
        false,
    )?;
    read(
        &Bound {
            path: POH.into(),
            sha256: POH_SHA.into(),
        },
        false,
    )?;
    evidence::bound_file(&executable, &args[5], 128 << 20, true)?;
    let mapping: Vec<_> = matched.entries.iter().map(|e| json!({"entry_index":e.entry_index,"transaction_start_index":e.transaction_start_index,"transaction_count":e.transactions.len(),"num_hashes":e.metadata.num_hashes,"hash":bs58::encode(e.metadata.hash).into_string()})).collect();
    evidence::write_receipt(
        &plan.output_directory.join("completion.json"),
        &json!({
            "schema":"jetstreamer-epoch141-first-source-equivalence-v1","slot":SLOT,"parent_slot":PARENT,
            "invocation_id":invocation,"self_sha256":args[5],"plan_sha256":args[3],"raw_target_sha256":RAW_SHA,"prior_poh_sha256":POH_SHA,
            "rpc_response_raw_sha256":response_sha,"source_transactions":source.len(),"matched_transactions":matched.matched_transactions,
            "entries":mapping,"executed_hashes":matched.poh.executed_hashes,"boundaries":matched.poh.boundaries.len(),"elapsed_millis":started.elapsed().as_millis(),
            "byte_equivalence_passed":true,"full_target_census_equivalence_proven":false,"source_completeness_proven":false,"canonical_ancestry_proven":false,
            "runtime_promotion_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("source equivalence failed closed: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn anchor() -> Value {
        json!({"final_poh_hash":"final","previous_poh_hash":"parent"})
    }
    fn response() -> Value {
        json!({"jsonrpc":"2.0","id":SLOT,"result":{"parentSlot":PARENT,"blockhash":"final","previousBlockhash":"parent","transactions":[{"version":"legacy","transaction":[STANDARD.encode([1,2,3]),"base64"]}]}})
    }
    #[test]
    fn exact_legacy_wire_response_is_required() {
        assert_eq!(
            source_transactions(&response(), &anchor()).unwrap(),
            vec![vec![1, 2, 3]]
        );
        for (key, value) in [
            ("parentSlot", json!(PARENT - 1)),
            ("blockhash", json!("wrong")),
            ("previousBlockhash", json!("wrong")),
        ] {
            let mut v = response();
            v["result"][key] = value;
            assert!(source_transactions(&v, &anchor()).is_err());
        }
        let mut v = response();
        v["error"] = json!({"code":429});
        assert!(source_transactions(&v, &anchor()).is_err());
        let mut v = response();
        v["result"]["transactions"][0]["version"] = json!(0);
        assert!(source_transactions(&v, &anchor()).is_err());
        let mut v = response();
        v["result"]["transactions"][0]["transaction"][1] = json!("json");
        assert!(source_transactions(&v, &anchor()).is_err());
        let mut v = response();
        v["result"]["transactions"][0]["transaction"][0] = json!(STANDARD.encode(vec![0; 1233]));
        assert!(source_transactions(&v, &anchor()).is_err());
    }
}
