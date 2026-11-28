//! Compare an exact private full-reread first block with sealed finalized RPC metadata.
//! No network, archive writes, replay, initial-anchor promotion, or publication authority.
#[allow(dead_code)]
mod epoch141_ledger_common;

use {
    anyhow::{Context, Result, ensure},
    epoch141_ledger_common::{bound_file, identity, is_sha, write_receipt},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env, fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    },
};

const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs122-147-20260922-v1/lane-j/private/destination-dbfdd780def396afe992e723ea9c107d1ba5ee00b2bb34854c8cf4291b8f2113/work/root-cohort-140-143/run-828090-1791987085289451499/archives/epoch-140.jet";
const SOURCE_SHA: &str = "65d311f5b96b2c1f2b8ff50ecfbe5da29bcf57573b55b39c48282f6d259a6842";
const COLLECTOR_SHA: &str = "a19db3bf113ad59ef73eac9ff6f850ceb7390c90e7e37aaaba59c086f37e8f10";
const FULL_PLAN_SHA: &str = "85d2255a38aeb40d8068c800f812242a0499e5e81d04960cc40bcc52549ad4de";
const VERIFIER_SHA: &str = "f27caf676a477d77d5e423125d1cb840f53589af09f36ca9b67a8732c35fb9e8";
const VERIFIER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-reread-20261019-v4/verify_archive";
const COLLECTOR: &str = "/usr/local/lib/jetstreamer/horizon-epoch140-transient-evidence-20261021-v2/jetstreamer-horizon-full-verification-evidence";
const FULL_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-transient-evidence-20261021-v2/plan.json";
const UNIT: &str = "horizon-epoch140-source-bound-full-reread-20261020-v1.service";
const INVOCATION: &str = "6c553218f2d64309935be94785077ccd";
const RPC_REQUEST_SHA: &str = "0b65d6dbe24d56a50c8f47b30d958b232369e02629ee70cc5638e4af21db39fa";
const RPC_RESPONSE_SHA: &str = "ee2cc65876dc2761da7b1f4bc840ce715ad5029b8fecf4fc3f4efa416c7fb3bf";
const MAX_JSON: u64 = 4 * 1024 * 1024;
const MAX_LOG: u64 = 64 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    full_receipt: Bound,
    rpc_request: Bound,
    rpc_response: Bound,
    output: PathBuf,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct FirstBlock {
    slot: u64,
    parent_slot: u64,
    parent_blockhash: String,
    blockhash: String,
}

fn canonical_hash(hash: &str) -> Result<()> {
    ensure!((32..=44).contains(&hash.len()), "invalid hash length");
    let bytes = bs58::decode(hash)
        .into_vec()
        .map_err(|error| anyhow::anyhow!("invalid base58 hash: {error}"))?;
    ensure!(
        bytes.len() == 32
            && bytes.iter().any(|byte| *byte != 0)
            && bs58::encode(bytes).into_string() == hash,
        "noncanonical or zero hash"
    );
    Ok(())
}

fn rpc_boundary(request: &Value, response: &Value) -> Result<FirstBlock> {
    let requests = request.as_array().context("RPC request is not a batch")?;
    let responses = response.as_array().context("RPC response is not a batch")?;
    ensure!(
        requests.len() == 2 && responses.len() == 2,
        "RPC boundary requires exactly two blocks"
    );
    let mut expected = BTreeMap::new();
    for item in requests {
        let slot = item["id"].as_u64().context("request ID is not a slot")?;
        ensure!(
            [60479999, 60480000].contains(&slot) && expected.insert(slot, ()).is_none(),
            "duplicate/wrong request slot"
        );
        ensure!(
            item == &json!({"jsonrpc":"2.0","id":slot,"method":"getBlock",
            "params":[slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]}),
            "request is not exact finalized metadata-only getBlock"
        );
    }
    let mut blocks = BTreeMap::new();
    for item in responses {
        let slot = item["id"].as_u64().context("response ID is not a slot")?;
        ensure!(
            item["jsonrpc"] == "2.0"
                && item.get("error").is_none()
                && expected.contains_key(&slot)
                && !blocks.contains_key(&slot),
            "RPC error, duplicate or unbound response"
        );
        let result = &item["result"];
        let hash = result["blockhash"].as_str().context("missing blockhash")?;
        let previous = result["previousBlockhash"]
            .as_str()
            .context("missing previous blockhash")?;
        canonical_hash(hash)?;
        canonical_hash(previous)?;
        blocks.insert(
            slot,
            FirstBlock {
                slot,
                parent_slot: result["parentSlot"]
                    .as_u64()
                    .context("missing parent slot")?,
                parent_blockhash: previous.into(),
                blockhash: hash.into(),
            },
        );
    }
    let parent = blocks
        .get(&60479999)
        .context("missing incoming canonical block")?;
    let first = blocks
        .get(&60480000)
        .context("missing first canonical block")?;
    ensure!(
        parent.parent_slot == 60479998
            && first.parent_slot == parent.slot
            && first.parent_blockhash == parent.blockhash,
        "finalized boundary is not the exact adjacent chain"
    );
    Ok(FirstBlock {
        slot: first.slot,
        parent_slot: first.parent_slot,
        parent_blockhash: first.parent_blockhash.clone(),
        blockhash: first.blockhash.clone(),
    })
}

fn first_block(log: &[u8], receipt: &Value) -> Result<FirstBlock> {
    let log = std::str::from_utf8(log)?;
    let results: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("RESULT:"))
        .collect();
    ensure!(
        results.len() == 1
            && results[0].starts_with("RESULT: OK (internal only):")
            && receipt["result"]["line"] == results[0]
            && log.contains("=== verify summary (")
            && log.contains("=== full PoH verification ==="),
        "log is not the exact successful full internal reread"
    );
    let lines: Vec<_> = log
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("first block:"))
        .collect();
    ensure!(lines.len() == 1, "missing or ambiguous first-block summary");
    let tokens: Vec<_> = lines[0].split_whitespace().collect();
    ensure!(tokens.len() == 4, "unexpected first-block summary fields");
    let value = |index: usize, prefix: &str| -> Result<&str> {
        tokens[index]
            .strip_prefix(prefix)
            .context("wrong first-block field order")
    };
    let number = |index, prefix| -> Result<u64> {
        let text = value(index, prefix)?;
        let number: u64 = text.parse()?;
        ensure!(number.to_string() == text, "noncanonical slot integer");
        Ok(number)
    };
    let block = FirstBlock {
        slot: number(0, "slot=")?,
        parent_slot: number(1, "parent_slot=")?,
        parent_blockhash: value(2, "parent_blockhash=")?.into(),
        blockhash: value(3, "blockhash=")?.into(),
    };
    canonical_hash(&block.parent_blockhash)?;
    canonical_hash(&block.blockhash)?;
    ensure!(
        block.slot == 60480000 && block.parent_slot == 60479999,
        "wrong archive initial boundary"
    );
    Ok(block)
}

fn validate_full(receipt: &Value) -> Result<()> {
    ensure!(
        receipt["schema"] == "horizon-private-transient-full-verification-v2"
            && receipt["status"] == "passed"
            && receipt["epoch"] == 140
            && receipt["collector_sha256"] == COLLECTOR_SHA
            && receipt["plan"]["sha256"] == FULL_PLAN_SHA
            && receipt["plan"]["path"] == FULL_PLAN
            && receipt["verifier"]["sha256"] == VERIFIER_SHA
            && receipt["verifier"]["path"] == VERIFIER
            && receipt["archive"]["path"] == SOURCE
            && receipt["archive"]["sha256"] == SOURCE_SHA
            && receipt["archive"]["whole_source_rehashed_after_reread"] == true
            && receipt["unit"]["name"] == UNIT
            && receipt["unit"]["invocation_id"] == INVOCATION
            && receipt["initial_anchor_proven"] == false,
        "wrong exact private full-reread receipt"
    );
    for key in [
        "archive_mutations",
        "sidecar_created",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            receipt[key] == false,
            "full receipt lacks explicit non-authorizing {key}"
        );
    }
    let state = &receipt["unit"]["effective_properties"];
    for (key, expected) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("MainPID", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ExecMainCode", "1"),
        ("NRestarts", "0"),
        ("InvocationID", INVOCATION),
        ("Type", "oneshot"),
        ("RemainAfterExit", "yes"),
        ("Restart", "no"),
    ] {
        ensure!(state[key] == expected, "wrong terminal full-reread {key}");
    }
    let pid: u64 = state["ExecMainPID"]
        .as_str()
        .context("missing verifier PID")?
        .parse()?;
    let journal = &receipt["unit"]["journal"];
    let first = journal["first_realtime_timestamp_us"]
        .as_u64()
        .context("missing first timestamp")?;
    let last = journal["last_realtime_timestamp_us"]
        .as_u64()
        .context("missing last timestamp")?;
    let finished = journal["finished_realtime_timestamp_us"]
        .as_u64()
        .context("missing finished timestamp")?;
    ensure!(
        pid > 0
            && journal["pid"] == pid
            && first > 0
            && first <= last
            && last <= finished
            && journal["records"].as_u64().is_some_and(|n| n > 0)
            && journal["deactivation_observed"] == false
            && journal
                .get("deactivated_realtime_timestamp_us")
                .is_some_and(Value::is_null),
        "full receipt lacks honest exact terminal journal binding"
    );
    Ok(())
}

fn source_unchanged(receipt: &Value) -> Result<()> {
    ensure!(
        fs::canonicalize(SOURCE)? == Path::new(SOURCE),
        "archive path is no longer exact canonical"
    );
    let metadata = fs::symlink_metadata(SOURCE)?;
    let expected = &receipt["archive"]["identity"];
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.dev() == 64512
            && metadata.ino() == 99811416
            && metadata.len() == 103138915297
            && metadata.uid() == 1001
            && metadata.gid() == 1003
            && metadata.mode() & 0o7777 == 0o440,
        "original archive identity changed"
    );
    for (key, value) in [
        ("device", metadata.dev()),
        ("inode", metadata.ino()),
        ("bytes", metadata.len()),
        ("uid", u64::from(metadata.uid())),
        ("gid", u64::from(metadata.gid())),
        ("mode", u64::from(metadata.mode() & 0o7777)),
        ("links", metadata.nlink()),
    ] {
        ensure!(
            expected[key].as_u64() == Some(value),
            "archive identity field {key} differs"
        );
    }
    ensure!(
        expected["mtime_seconds"].as_i64() == Some(metadata.mtime())
            && expected["mtime_nanoseconds"].as_i64() == Some(metadata.mtime_nsec())
            && receipt["archive"]["ctime_seconds"].as_i64() == Some(metadata.ctime())
            && receipt["archive"]["ctime_nanoseconds"].as_i64() == Some(metadata.ctime_nsec()),
        "archive timestamps differ from post-reread source binding"
    );
    ensure!(
        fs::symlink_metadata(format!("{SOURCE}.sha256"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "original canonical sidecar must remain positively absent"
    );
    Ok(())
}

fn nested_bound(receipt: &Value, key: &str) -> Result<Bound> {
    serde_json::from_value(receipt[key].clone()).context("invalid full receipt child binding")
}

fn run() -> Result<()> {
    let arguments: Vec<_> = env::args().collect();
    ensure!(
        (arguments.len() == 6 || (arguments.len() == 7 && arguments[6] == "--check-only"))
            && arguments[2] == "--plan-sha256"
            && arguments[4] == "--self-sha256",
        "usage: jetstreamer-epoch140-initial-boundary PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "requires root");
    let executable = fs::read_link("/proc/self/exe")?;
    bound_file(&executable, &arguments[5], 64 * 1024 * 1024, true)?;
    ensure!(
        fs::metadata(&executable)?.mode() & 0o111 != 0,
        "collector not executable"
    );
    let plan_bound = Bound {
        path: arguments[1].clone().into(),
        sha256: arguments[3].clone(),
    };
    let plan: Plan = serde_json::from_slice(&bound_file(
        &plan_bound.path,
        &plan_bound.sha256,
        MAX_JSON,
        true,
    )?)?;
    ensure!(
        plan.schema == "jetstreamer-epoch140-initial-boundary-plan-v1"
            && plan.rpc_request.sha256 == RPC_REQUEST_SHA
            && plan.rpc_response.sha256 == RPC_RESPONSE_SHA,
        "wrong private boundary plan or independently sealed RPC source"
    );
    ensure!(
        plan.output.is_absolute()
            && fs::symlink_metadata(&plan.output)
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output must be positively absent"
    );
    let output_parent = plan.output.parent().context("missing output parent")?;
    let parent = fs::symlink_metadata(output_parent)?;
    ensure!(
        output_parent.canonicalize()? == output_parent
            && parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o077 == 0,
        "output requires exact root-private parent"
    );
    let full_bytes = bound_file(
        &plan.full_receipt.path,
        &plan.full_receipt.sha256,
        MAX_JSON,
        false,
    )?;
    let full: Value = serde_json::from_slice(&full_bytes)?;
    validate_full(&full)?;
    for (path, digest) in [(VERIFIER, VERIFIER_SHA), (COLLECTOR, COLLECTOR_SHA)] {
        bound_file(Path::new(path), digest, 128 * 1024 * 1024, true)?;
        ensure!(
            fs::metadata(path)?.mode() & 0o111 != 0,
            "bound verifier/collector is not executable"
        );
    }
    bound_file(Path::new(FULL_PLAN), FULL_PLAN_SHA, MAX_JSON, true)?;
    source_unchanged(&full)?;
    let source_before = identity(&fs::symlink_metadata(SOURCE)?);
    let log = nested_bound(&full, "log")?;
    let metadata = nested_bound(&full, "journal_metadata")?;
    ensure!(
        is_sha(&log.sha256) && is_sha(&metadata.sha256),
        "invalid child evidence digest"
    );
    let log_bytes = bound_file(&log.path, &log.sha256, MAX_LOG, false)?;
    bound_file(&metadata.path, &metadata.sha256, MAX_LOG, false)?;
    let request: Value = serde_json::from_slice(&bound_file(
        &plan.rpc_request.path,
        &plan.rpc_request.sha256,
        MAX_JSON,
        true,
    )?)?;
    let response: Value = serde_json::from_slice(&bound_file(
        &plan.rpc_response.path,
        &plan.rpc_response.sha256,
        MAX_JSON,
        true,
    )?)?;
    let canonical = rpc_boundary(&request, &response)?;
    let stored = first_block(&log_bytes, &full)?;
    ensure!(
        stored == canonical,
        "stored archive first block differs from finalized canonical metadata"
    );
    for evidence in [&plan_bound, &plan.rpc_request, &plan.rpc_response] {
        bound_file(&evidence.path, &evidence.sha256, MAX_JSON, true)?;
    }
    bound_file(
        &plan.full_receipt.path,
        &plan.full_receipt.sha256,
        MAX_JSON,
        false,
    )?;
    bound_file(&log.path, &log.sha256, MAX_LOG, false)?;
    bound_file(&metadata.path, &metadata.sha256, MAX_LOG, false)?;
    source_unchanged(&full)?;
    ensure!(
        identity(&fs::symlink_metadata(SOURCE)?) == source_before,
        "archive changed during comparison"
    );
    if arguments.len() == 7 {
        println!("private initial-boundary comparison check passed; no output or mutation");
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("systemd invocation required")?;
    ensure!(
        invocation.len() == 32 && is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation ID"
    );
    write_receipt(
        &plan.output,
        &json!({
            "schema":"jetstreamer-epoch140-initial-boundary-comparison-v1","epoch":140,"status":"matched",
            "invocation_id":invocation,"self_sha256":arguments[5],"plan":plan_bound,
            "full_verification":plan.full_receipt,"rpc_request":plan.rpc_request,"rpc_response":plan.rpc_response,
            "log":log,"journal_metadata":metadata,"archive":SOURCE,"archive_sha256":SOURCE_SHA,
            "stored_first_block":stored,"canonical_first_block":canonical,
            "canonical_first_block_comparison_passed":true,"whole_source_rehashed_by_this_comparison":false,
            "initial_anchor_proven":false,"ordered_chain_gate_still_required":true,
            "complete_prefix_qualification_proven":false,"hidden_poh_hashes_recovered":false,
            "archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("{}", plan.output.display());
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PARENT: &str = "HpCoYsom9ZgNNAyCG9Ct72GyQaSdeUpeQKPJ5sKNSCRG";
    const FIRST: &str = "EJtda2adMQbzSTYJugrrJmweXdAYZc8Uwea3ixne773D";
    const PREVIOUS: &str = "Dby6hN8BoBpnjwvNc3Z61rdvGzEWLUf4h8Mc8qvinZEd";

    fn rpc() -> (Value, Value) {
        let request = json!([60479999_u64,60480000_u64]).as_array().unwrap().iter().map(|slot|
            json!({"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,
                {"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]}))
            .collect::<Vec<_>>();
        (
            json!(request),
            json!([
                {"jsonrpc":"2.0","id":60479999,"result":{"parentSlot":60479998,"blockhash":PARENT,"previousBlockhash":PREVIOUS}},
                {"jsonrpc":"2.0","id":60480000,"result":{"parentSlot":60479999,"blockhash":FIRST,"previousBlockhash":PARENT}}
            ]),
        )
    }

    fn full() -> Value {
        json!({"schema":"horizon-private-transient-full-verification-v2","status":"passed","epoch":140,
            "collector_sha256":COLLECTOR_SHA,"plan":{"path":FULL_PLAN,"sha256":FULL_PLAN_SHA},"verifier":{"path":VERIFIER,"sha256":VERIFIER_SHA},
            "archive":{"path":SOURCE,"sha256":SOURCE_SHA,"whole_source_rehashed_after_reread":true},
            "unit":{"name":UNIT,"invocation_id":INVOCATION,"effective_properties":{
                "LoadState":"loaded","ActiveState":"active","SubState":"exited","MainPID":"0",
                "Result":"success","ExecMainStatus":"0","ExecMainCode":"1","NRestarts":"0",
                "InvocationID":INVOCATION,"Type":"oneshot","RemainAfterExit":"yes","Restart":"no","ExecMainPID":"42"
            },"journal":{"pid":42,"records":10,"first_realtime_timestamp_us":100,
                "last_realtime_timestamp_us":200,"finished_realtime_timestamp_us":201,
                "deactivation_observed":false,"deactivated_realtime_timestamp_us":null}},
            "result":{"line":"RESULT: OK (internal only): all stored links verify; the first block is unanchored."},
            "initial_anchor_proven":false,"archive_mutations":false,"sidecar_created":false,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }

    fn log() -> String {
        format!(
            "full PoH verify: epoch=140 slot_start=60480000 slot_count=432000 buckets=3375 threads=8\n\n=== verify summary (3100.0s, 8 threads) ===\n  first block:          slot=60480000 parent_slot=60479999 parent_blockhash={PARENT} blockhash={FIRST}\n=== full PoH verification ===\n{}\n",
            full()["result"]["line"].as_str().unwrap()
        )
    }

    #[test]
    fn binds_exact_finalized_parent_and_first_block_to_real_summary_shape() {
        let (request, response) = rpc();
        validate_full(&full()).unwrap();
        assert_eq!(
            rpc_boundary(&request, &response).unwrap(),
            first_block(log().as_bytes(), &full()).unwrap()
        );
    }

    #[test]
    fn batch_order_is_not_identity() {
        let (mut request, mut response) = rpc();
        request.as_array_mut().unwrap().reverse();
        response.as_array_mut().unwrap().reverse();
        assert_eq!(rpc_boundary(&request, &response).unwrap().blockhash, FIRST);
    }

    #[test]
    fn rejects_non_finalized_or_substituted_requests() {
        for (pointer, value) in [
            ("/0/method", json!("getConfirmedBlock")),
            ("/0/params/1/commitment", json!("confirmed")),
            ("/0/id", json!(60479998)),
            ("/0/params/0", json!(60479998)),
            ("/0/params/1/rewards", json!(true)),
            ("/0/params/1/transactionDetails", json!("full")),
        ] {
            let (mut request, response) = rpc();
            *request.pointer_mut(pointer).unwrap() = value;
            assert!(
                rpc_boundary(&request, &response).is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn rejects_incomplete_duplicate_or_errored_batches() {
        let (request, response) = rpc();
        for changed in [
            json!([response[0]]),
            json!([response[0], response[0]]),
            json!([response[0],{"jsonrpc":"2.0","id":60480000,"error":{"code":429,"message":"rate limit"}}]),
            json!([response[0],{"jsonrpc":"2.0","id":"60480000","result":response[1]["result"]}]),
        ] {
            assert!(rpc_boundary(&request, &changed).is_err());
        }
        assert!(rpc_boundary(&json!([request[0], request[0]]), &response).is_err());
    }

    #[test]
    fn rejects_hash_parent_and_slot_topology_changes() {
        for (pointer, value) in [
            ("/1/result/previousBlockhash", json!(PREVIOUS)),
            ("/1/result/parentSlot", json!(60479998)),
            ("/0/result/parentSlot", json!(60479997)),
            ("/1/result/blockhash", json!("0notbase58")),
            ("/0/result/blockhash", json!("1".repeat(32))),
        ] {
            let (request, mut response) = rpc();
            *response.pointer_mut(pointer).unwrap() = value;
            assert!(
                rpc_boundary(&request, &response).is_err(),
                "accepted {pointer}"
            );
        }
    }

    #[test]
    fn rejects_ambiguous_or_modified_archive_summary() {
        let original = log();
        let first_line = original
            .lines()
            .find(|line| line.contains("first block:"))
            .unwrap();
        for changed in [
            format!("{original}{first_line}\n"),
            original.replace(first_line, ""),
            original.replace("slot=60480000", "slot=060480000"),
            original.replace("parent_slot=60479999", "parent_slot=60479998"),
            original.replace("parent_blockhash=", "incoming="),
            original.replace(FIRST, "0bad"),
            original.replace("=== full PoH verification ===", "not a full proof"),
            format!("{original}RESULT: OK (internal only): duplicate\n"),
        ] {
            assert!(first_block(changed.as_bytes(), &full()).is_err());
        }
        let mut different = full();
        different["result"]["line"] = "RESULT: OK (internal only): another".into();
        assert!(first_block(original.as_bytes(), &different).is_err());
    }

    #[test]
    fn refuses_legacy_receipt_forged_source_and_premature_anchor_claim() {
        for (pointer, value) in [
            ("/schema", json!("horizon-private-full-verification-v1")),
            ("/status", json!("running")),
            ("/epoch", json!(141)),
            ("/collector_sha256", json!("00".repeat(32))),
            ("/plan/sha256", json!("11".repeat(32))),
            ("/verifier/sha256", json!("22".repeat(32))),
            ("/archive/path", json!("/different.jet")),
            ("/archive/sha256", json!("33".repeat(32))),
            ("/archive/whole_source_rehashed_after_reread", json!(false)),
            ("/unit/invocation_id", json!("foreign")),
            ("/initial_anchor_proven", json!(true)),
        ] {
            let mut receipt = full();
            *receipt.pointer_mut(pointer).unwrap() = value;
            assert!(validate_full(&receipt).is_err(), "accepted {pointer}");
        }
    }

    #[test]
    fn refuses_live_changed_or_failed_full_reread_identity() {
        for (key, value) in [
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("MainPID", "42"),
            ("NRestarts", "1"),
            ("InvocationID", "foreign"),
            ("Result", "exit-code"),
            ("ExecMainStatus", "1"),
            ("ExecMainPID", "0"),
            ("ExecMainCode", "2"),
            ("RemainAfterExit", "no"),
        ] {
            let mut receipt = full();
            receipt["unit"]["effective_properties"][key] = value.into();
            assert!(validate_full(&receipt).is_err(), "accepted {key}");
        }
    }

    #[test]
    fn requires_honest_terminal_journal_and_explicit_no_authority() {
        for (pointer, value) in [
            ("/unit/journal/pid", json!(43)),
            ("/unit/journal/records", json!(0)),
            ("/unit/journal/first_realtime_timestamp_us", json!(0)),
            ("/unit/journal/last_realtime_timestamp_us", json!(300)),
            ("/unit/journal/deactivation_observed", json!(true)),
            ("/unit/journal/deactivated_realtime_timestamp_us", json!(0)),
        ] {
            let mut receipt = full();
            *receipt.pointer_mut(pointer).unwrap() = value;
            assert!(validate_full(&receipt).is_err(), "accepted {pointer}");
        }
        for key in [
            "archive_mutations",
            "sidecar_created",
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut receipt = full();
            receipt[key] = true.into();
            assert!(validate_full(&receipt).is_err());
            receipt.as_object_mut().unwrap().remove(key);
            assert!(validate_full(&receipt).is_err());
        }
        let mut receipt = full();
        receipt["unit"]["journal"]
            .as_object_mut()
            .unwrap()
            .remove("deactivated_realtime_timestamp_us");
        assert!(validate_full(&receipt).is_err());
    }

    #[test]
    fn comparison_detects_valid_but_different_stored_first_block() {
        let (request, response) = rpc();
        let canonical = rpc_boundary(&request, &response).unwrap();
        let changed = log().replace(
            &format!("blockhash={FIRST}"),
            &format!("blockhash={PREVIOUS}"),
        );
        let stored = first_block(changed.as_bytes(), &full()).unwrap();
        assert_ne!(canonical, stored);
    }

    #[test]
    #[ignore = "requires the independently sealed dev-samjohnson finalized RPC source package"]
    fn real_sealed_rpc_boundary_sources() {
        let root = PathBuf::from(
            env::var("HORIZON_EPOCH140_RPC_FIXTURE_ROOT")
                .expect("explicit sealed source package required"),
        );
        let request: Value = serde_json::from_slice(
            &bound_file(
                &root.join("block-request.json"),
                RPC_REQUEST_SHA,
                MAX_JSON,
                true,
            )
            .unwrap(),
        )
        .unwrap();
        let response: Value = serde_json::from_slice(
            &bound_file(
                &root.join("block-response.json"),
                RPC_RESPONSE_SHA,
                MAX_JSON,
                true,
            )
            .unwrap(),
        )
        .unwrap();
        let boundary = rpc_boundary(&request, &response).unwrap();
        assert_eq!(boundary.slot, 60480000);
        assert_eq!(boundary.parent_slot, 60479999);
        assert_eq!(boundary.parent_blockhash, PARENT);
        assert_eq!(boundary.blockhash, FIRST);
    }
}
