//! One finalized getBlock, anchored to sealed original entries. No replay/R2.
#[allow(dead_code)]
#[path = "epoch141_ledger_common.rs"]
mod evidence;

use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

const SLOT: u64 = 60_912_004;
const INDEX: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch141-original-input-20261023-v1/index.json";
const INDEX_SHA: &str = "fe38bd4ce018996349c10029720dd7f738340fb0ad30ce6b8577b9651bf87df3";
const ENDPOINT: &str = "https://api.mainnet-beta.solana.com";

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
    curl: Bound,
    output_directory: PathBuf,
    retained_response: Option<Bound>,
}

fn hash32(s: &str) -> Result<[u8; 32]> {
    let bytes = bs58::decode(s)
        .into_vec()
        .map_err(|e| anyhow::anyhow!("invalid base58: {e}"))?;
    let result: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("wrong hash/pubkey length"))?;
    ensure!(
        bs58::encode(result).into_string() == s,
        "noncanonical base58"
    );
    Ok(result)
}
fn summary(response: &Value, anchor: &Value) -> Result<Value> {
    ensure!(
        response["jsonrpc"] == "2.0" && response["id"] == SLOT && response.get("error").is_none(),
        "RPC error or wrong request identity"
    );
    let block = &response["result"];
    ensure!(
        anchor["slot"] == SLOT
            && anchor["parent_slot"] == 60_911_999
            && block["parentSlot"] == anchor["parent_slot"],
        "wrong original parent"
    );
    for (rpc, original) in [
        ("blockhash", "final_hash_hex"),
        ("previousBlockhash", "parent_hash_hex"),
    ] {
        let h = hash32(block[rpc].as_str().context("RPC hash absent")?)?;
        let hex = h.iter().map(|b| format!("{b:02x}")).collect::<String>();
        ensure!(
            anchor[original] == hex,
            "finalized RPC PoH anchor differs:{rpc}"
        );
    }
    let rewards = block["rewards"].as_array().context("missing reward list")?;
    ensure!(
        rewards.len() <= 1_000_000,
        "reward count exceeds worker bound"
    );
    let names = ["Fee", "Rent", "Staking", "Voting"];
    let mut rows = Vec::with_capacity(rewards.len());
    let mut totals = BTreeMap::<String, i64>::new();
    for reward in rewards {
        let key = hash32(reward["pubkey"].as_str().context("reward pubkey")?)?;
        let kind = reward["rewardType"].as_str().context("reward type")?;
        let tag = names
            .iter()
            .position(|s| *s == kind)
            .context("unknown legacy reward type")? as u32;
        let lamports = reward["lamports"].as_i64().context("exact signed reward")?;
        let balance = reward["postBalance"]
            .as_u64()
            .context("exact reward balance")?;
        let total = totals.entry(kind.to_ascii_lowercase()).or_default();
        *total = total
            .checked_add(lamports)
            .context("reward total overflow")?;
        rows.push((key, tag, lamports, balance));
    }
    rows.sort();
    // Legacy bincode 1.3.1 fixed-int Vec<(Pubkey, RewardInfo)> wire format.
    // Enum discriminants are u32; Pubkey is exactly 32 bytes (no length).
    let mut bytes = (rows.len() as u64).to_le_bytes().to_vec();
    for (key, tag, lamports, balance) in rows {
        bytes.extend(key);
        bytes.extend(tag.to_le_bytes());
        bytes.extend(lamports.to_le_bytes());
        bytes.extend(balance.to_le_bytes());
    }
    Ok(
        json!({"slot":SLOT,"parent_slot":block["parentSlot"],"final_poh_hash":block["blockhash"],"previous_poh_hash":block["previousBlockhash"],"reward_count":rewards.len(),"reward_totals_lamports":totals,"reward_list_hash_base58":bs58::encode(Sha256::digest(&bytes)).into_string(),"legacy_reward_encoding_bytes":bytes.len(),"commission_omitted_from_legacy_encoding":true,"bank_hash_supplied_by_rpc":false}),
    )
}
fn retained_bytes(v: &Value) -> Result<Vec<u8>> {
    ensure!(v["curl_success"] == true, "retained transport failed");
    let encoded = v["raw_base64"].as_str().context("retained raw bytes")?;
    ensure!(encoded.len() <= 24 << 20, "retained encoding exceeds bound");
    let bytes = STANDARD.decode(encoded)?;
    ensure!(
        bytes.len() <= 16 << 20
            && STANDARD.encode(&bytes) == encoded
            && v["raw_sha256"] == evidence::sha(&bytes),
        "retained response digest/encoding differs"
    );
    Ok(bytes)
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: reward-reference PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "requires root immutable reader"
    );
    evidence::bound_file(
        &std::env::current_exe()?.canonicalize()?,
        &args[5],
        128 << 20,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&evidence::bound_file(
        Path::new(&args[1]),
        &args[3],
        65536,
        true,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch141-reward-reference-plan-v2",
        "wrong plan schema"
    );
    ensure!(
        plan.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && plan
                .output_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch141-reward-reference-")
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "wrong output scope"
    );
    let m = fs::symlink_metadata(&plan.output_directory)?;
    ensure!(
        m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && plan.output_directory.canonicalize()? == plan.output_directory
            && fs::read_dir(&plan.output_directory)?.next().is_none(),
        "output must be empty root-private directory"
    );
    evidence::bound_file(&plan.curl.path, &plan.curl.sha256, 16 << 20, true)?;
    ensure!(
        plan.curl.path.file_name().is_some_and(|s| s == "curl"),
        "wrong transport"
    );
    let index: Value = serde_json::from_slice(&evidence::bound_file(
        Path::new(INDEX),
        INDEX_SHA,
        32 << 20,
        true,
    )?)?;
    ensure!(
        index["schema"] == "jetstreamer-epoch141-original-entry-bundle-v1",
        "wrong original index schema"
    );
    let anchors: Vec<_> = index["slots"]
        .as_array()
        .context("original slots")?
        .iter()
        .filter(|r| r["slot"] == SLOT)
        .collect();
    ensure!(anchors.len() == 1, "requires unique original slot");
    let invocation = std::env::var("INVOCATION_ID").context("requires systemd invocation")?;
    ensure!(
        invocation.len() == 32 && evidence::is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation"
    );
    let request = json!({"jsonrpc":"2.0","id":SLOT,"method":"getBlock","params":[SLOT,{"commitment":"finalized","transactionDetails":"none","rewards":true,"maxSupportedTransactionVersion":0}]});
    evidence::write_receipt(
        &plan.output_directory.join("request.json"),
        &json!({"endpoint":ENDPOINT,"request":request,"invocation_id":invocation}),
    )?;
    let response_bytes = if let Some(retained) = &plan.retained_response {
        let value: Value = serde_json::from_slice(&evidence::bound_file(
            &retained.path,
            &retained.sha256,
            32 << 20,
            true,
        )?)?;
        let bytes = retained_bytes(&value)?;
        evidence::write_receipt(
            &plan.output_directory.join("retained-response.json"),
            &json!({"source":{"path":retained.path,"sha256":retained.sha256},"network_requests":0,"raw_sha256":evidence::sha(&bytes)}),
        )?;
        bytes
    } else {
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
            response.stdout.len() <= 16 << 20 && response.stderr.len() <= 65536,
            "transport output exceeds bound"
        );
        evidence::write_receipt(
            &plan.output_directory.join("response.json"),
            &json!({"raw_base64":STANDARD.encode(&response.stdout),"raw_sha256":evidence::sha(&response.stdout),"curl_success":response.status.success(),"stderr":String::from_utf8_lossy(&response.stderr)}),
        )?;
        ensure!(
            response.status.success(),
            "bounded RPC failed; response retained"
        );
        response.stdout
    };
    let reference = summary(&serde_json::from_slice(&response_bytes)?, anchors[0])?;
    evidence::write_receipt(
        &plan.output_directory.join("reference.json"),
        &json!({"schema":"jetstreamer-epoch141-reward-reference-v2","invocation_id":invocation,"plan_sha256":args[3],"self_sha256":args[5],"original_index":{"path":INDEX,"sha256":INDEX_SHA},"response_sha256":evidence::sha(&response_bytes),"network_requests":if plan.retained_response.is_some(){0}else{1},"reference":reference,"canonical_bank_hash_proven":false,"full_epoch_verified":false,"replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    println!("finalized reward reference retained; no canonical Bank or epoch qualification");
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("reward reference failed closed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, Value) {
        let h = bs58::encode([1u8; 32]).into_string();
        (
            json!({"jsonrpc":"2.0","id":SLOT,"result":{"parentSlot":60911999,"blockhash":h,"previousBlockhash":h,"rewards":[{"pubkey":h,"rewardType":"Rent","lamports":-1,"postBalance":9007199254740993u64,"commission":null}]}}),
            json!({"slot":SLOT,"parent_slot":60911999,"final_hash_hex":"01".repeat(32),"parent_hash_hex":"01".repeat(32)}),
        )
    }
    #[test]
    fn legacy_fixture_matches_worker_bytes_with_exact_large_balance() {
        let (v, a) = fixture();
        let s = summary(&v, &a).unwrap();
        let mut bytes = 1u64.to_le_bytes().to_vec();
        bytes.extend([1u8; 32]);
        bytes.extend(1u32.to_le_bytes());
        bytes.extend((-1i64).to_le_bytes());
        bytes.extend(9007199254740993u64.to_le_bytes());
        assert_eq!(
            s["reward_list_hash_base58"],
            bs58::encode(Sha256::digest(bytes)).into_string()
        );
        assert_eq!(s["reward_totals_lamports"]["rent"], -1);
    }
    #[test]
    fn rejects_unanchored_or_inexact_reference() {
        let (v, a) = fixture();
        for field in ["blockhash", "previousBlockhash"] {
            let mut bad = v.clone();
            bad["result"][field] = json!(bs58::encode([2u8; 32]).into_string());
            assert!(summary(&bad, &a).is_err());
        }
        let mut bad = v.clone();
        bad["result"]["rewards"][0]["postBalance"] = json!(1.5);
        assert!(summary(&bad, &a).is_err());
        let mut bad = v;
        bad["error"] = json!({"code":429});
        assert!(summary(&bad, &a).is_err());
    }
    #[test]
    fn retained_response_rejects_changed_bytes_or_failed_transport() {
        let bytes = serde_json::to_vec(&fixture().0).unwrap();
        let v = json!({"curl_success":true,"raw_base64":STANDARD.encode(&bytes),"raw_sha256":evidence::sha(&bytes)});
        assert_eq!(retained_bytes(&v).unwrap(), bytes);
        let mut bad = v.clone();
        bad["raw_sha256"] = json!("0".repeat(64));
        assert!(retained_bytes(&bad).is_err());
        let mut bad = v;
        bad["curl_success"] = json!(false);
        assert!(retained_bytes(&bad).is_err());
    }
}
