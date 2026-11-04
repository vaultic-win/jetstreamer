//! Read-only finalized parent-gap census. Never supplies hidden PoH hashes.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    },
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BoundFile {
    pub(crate) path: PathBuf,
    pub(crate) sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Batch {
    request: BoundFile,
    response: BoundFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    first_slot: u64,
    last_slot: u64,
    block_list_request: BoundFile,
    block_list: BoundFile,
    rpc_batches: Vec<Batch>,
    output: PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BlockListPage {
    first_slot: u64,
    last_slot: u64,
    request: BoundFile,
    response: BoundFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PagedCensusPlan {
    schema: String,
    first_slot: u64,
    last_slot: u64,
    pages: Vec<BlockListPage>,
    output: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct Gap {
    parent_slot: u64,
    slot: u64,
    skipped_slots: u64,
    expected_tick_boundaries: u64,
    final_poh_hash: String,
    previous_poh_hash: String,
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn read_bound(bound: &BoundFile) -> Result<Vec<u8>> {
    ensure!(valid_sha(&bound.sha256), "invalid input SHA-256");
    ensure!(
        bound.path.is_absolute() && bound.path.canonicalize()? == bound.path,
        "input must be canonical and absolute"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&bound.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1 && before.uid() == 0 && before.mode() & 0o222 == 0,
        "input must be root-owned, singly linked, immutable regular file"
    );
    ensure!(before.len() <= 8 * 1024 * 1024, "input exceeds size bound");
    let mut bytes = Vec::new();
    (&mut file)
        .take(8 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == before.len(), "input length changed");
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.uid(),
            m.mode(),
            m.nlink(),
        )
    };
    ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&bound.path)?),
        "input identity changed"
    );
    ensure!(digest(&bytes) == bound.sha256, "input SHA-256 mismatch");
    Ok(bytes)
}

fn array(value: &Value) -> Result<&Vec<Value>> {
    value.as_array().context("expected JSON array")
}

type GapPairs = Vec<(u64, u64)>;

fn check_block_list_request(
    first: u64,
    last: u64,
    request: &Value,
    response: &Value,
) -> Result<()> {
    ensure!(
        request["jsonrpc"] == "2.0" && request["method"] == "getBlocks",
        "wrong block-list request method/version"
    );
    ensure!(
        request["id"].as_u64().is_some() && request["id"] == response["id"],
        "block-list request/response ID mismatch"
    );
    let params = array(&request["params"])?;
    ensure!(
        params.len() == 3
            && params[0] == first
            && params[1] == last
            && params[2]["commitment"] == "finalized",
        "block-list request must bind exact finalized interval"
    );
    Ok(())
}

fn target_pairs(first: u64, last: u64, response: &Value) -> Result<(Vec<u64>, GapPairs)> {
    ensure!(
        last >= first && last - first <= 432_000,
        "invalid or oversized slot interval"
    );
    ensure!(
        response["jsonrpc"] == "2.0" && response.get("error").is_none(),
        "invalid block-list RPC response"
    );
    let blocks = array(&response["result"])?
        .iter()
        .map(|v| v.as_u64().context("block slot is not an integer"))
        .collect::<Result<Vec<_>>>()?;
    let gaps = pairs_from_present(first, last, &blocks)?;
    Ok((blocks, gaps))
}

fn pairs_from_present(first: u64, last: u64, blocks: &[u64]) -> Result<GapPairs> {
    ensure!(
        blocks.first() == Some(&first) && blocks.last() == Some(&last),
        "block-list endpoints differ from plan"
    );
    ensure!(
        blocks.windows(2).all(|p| p[0] < p[1]),
        "block list is not strictly increasing"
    );
    Ok(blocks
        .windows(2)
        .filter(|p| p[1] - p[0] > 1)
        .map(|p| (p[0], p[1]))
        .collect())
}

fn check_hash(value: &Value) -> Result<String> {
    let hash = value.as_str().context("PoH hash missing")?;
    ensure!(
        hash.len() <= 44
            && bs58::decode(hash)
                .into_vec()
                .is_ok_and(|bytes| bytes.len() == 32),
        "invalid PoH hash"
    );
    Ok(hash.to_owned())
}

pub(crate) fn collect_batch(
    request: &Value,
    response: &Value,
    targets: &BTreeSet<u64>,
    successes: &mut BTreeMap<u64, (u64, String, String)>,
) -> Result<u64> {
    let mut expected = BTreeSet::new();
    for item in array(request)? {
        let id = item["id"]
            .as_u64()
            .context("request ID must be slot integer")?;
        ensure!(
            expected.insert(id) && targets.contains(&id),
            "duplicate or non-target request"
        );
        ensure!(
            item["jsonrpc"] == "2.0" && item["method"] == "getBlock",
            "wrong RPC method/version"
        );
        let params = array(&item["params"])?;
        ensure!(
            params.len() == 2
                && params[0] == id
                && params[1]["commitment"] == "finalized"
                && params[1]["transactionDetails"] == "none"
                && params[1]["rewards"] == false
                && params[1]["maxSupportedTransactionVersion"] == 0,
            "RPC request must bind finalized metadata-only block"
        );
    }
    let mut seen = BTreeSet::new();
    let mut errors = 0;
    for item in array(response)? {
        let id = item["id"]
            .as_u64()
            .context("response ID must be slot integer")?;
        ensure!(
            item["jsonrpc"] == "2.0" && expected.contains(&id) && seen.insert(id),
            "duplicate, unexpected or malformed RPC response"
        );
        if let Some(error) = item.get("error") {
            ensure!(
                item.get("result").is_none()
                    && error["code"].as_i64().is_some()
                    && error["message"].as_str().is_some(),
                "malformed RPC error"
            );
            errors += 1;
            continue;
        }
        let result = &item["result"];
        let value = (
            result["parentSlot"]
                .as_u64()
                .context("missing parent slot")?,
            check_hash(&result["blockhash"])?,
            check_hash(&result["previousBlockhash"])?,
        );
        if let Some(previous) = successes.get(&id) {
            ensure!(
                previous == &value,
                "conflicting finalized metadata for slot {id}"
            );
        } else {
            successes.insert(id, value);
        }
    }
    ensure!(seen == expected, "incomplete batch response");
    Ok(errors)
}

fn assemble(
    pairs: &[(u64, u64)],
    successes: &BTreeMap<u64, (u64, String, String)>,
) -> Result<Vec<Gap>> {
    ensure!(
        pairs.len() == successes.len(),
        "incomplete target metadata census"
    );
    pairs
        .iter()
        .map(|&(parent, slot)| {
            let (actual_parent, hash, previous) = successes
                .get(&slot)
                .context("missing successful finalized target response")?;
            ensure!(
                *actual_parent == parent,
                "finalized parent disagrees with block-list gap at {slot}"
            );
            Ok(Gap {
                parent_slot: parent,
                slot,
                skipped_slots: slot - parent - 1,
                expected_tick_boundaries: slot - parent,
                final_poh_hash: hash.clone(),
                previous_poh_hash: previous.clone(),
            })
        })
        .collect()
}

fn write_receipt(path: &Path, receipt: &Value) -> Result<()> {
    let parent = path.parent().context("output parent missing")?;
    ensure!(
        path.is_absolute() && parent.canonicalize()? == parent,
        "output parent must be canonical"
    );
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "output parent must be root-private"
    );
    let mut bytes = serde_json::to_vec_pretty(receipt)?;
    bytes.push(b'\n');
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_mode(plan: &Plan, census_only: bool) -> Result<()> {
    if census_only {
        ensure!(
            plan.schema == "jetstreamer-horizon-finalized-gap-census-plan-v1"
                && plan.rpc_batches.is_empty()
                && plan
                    .output
                    .file_name()
                    .is_some_and(|name| name == "gap-census.json"),
            "census-only requires its distinct schema/output and no block metadata batches"
        );
    } else {
        ensure!(
            plan.schema == "jetstreamer-horizon-finalized-gap-audit-plan-v1",
            "wrong audit plan schema"
        );
        ensure!(
            !plan.rpc_batches.is_empty() && plan.rpc_batches.len() <= 64,
            "invalid batch count"
        );
    }
    Ok(())
}

// A large execution interval can have thousands of parent-gap candidates.
// Preserve the complete list before requesting individual finalized blocks.
// This first stage deliberately cannot produce the full audit's receipt shape.
fn census_receipt(
    binding: &BoundFile,
    plan: &Plan,
    present: &[u64],
    pairs: &[(u64, u64)],
) -> Result<Value> {
    let mut receipt = census_summary(binding, plan.first_slot, plan.last_slot, present, pairs)?;
    receipt["schema"] = json!("jetstreamer-horizon-finalized-gap-census-v1");
    receipt["block_list_request"] = serde_json::to_value(&plan.block_list_request)?;
    receipt["block_list"] = serde_json::to_value(&plan.block_list)?;
    Ok(receipt)
}

fn census_summary(
    binding: &BoundFile,
    first_slot: u64,
    last_slot: u64,
    present: &[u64],
    pairs: &[(u64, u64)],
) -> Result<Value> {
    let skipped: u64 = pairs.iter().map(|(parent, slot)| slot - parent - 1).sum();
    ensure!(
        present.len() as u64 + skipped == last_slot - first_slot + 1,
        "interval count mismatch"
    );
    Ok(json!({
        "plan":binding,"first_slot":first_slot,"last_slot":last_slot,
        "present_slots":present.len(),"skipped_slots":skipped,
        "post_gap_targets":pairs.len(),
        "expected_tick_boundaries":skipped + pairs.len() as u64,
        "gap_candidates":pairs.iter().map(|(parent,slot)| json!({
            "parent_slot":parent,"slot":slot,"skipped_slots":slot-parent-1,
            "expected_tick_boundaries":slot-parent
        })).collect::<Vec<_>>(),
        "finalized_getblocks_only":true,"target_getblock_metadata_complete":false,
        "independent_target_parent_checks_passed":false,"full_gap_audit_complete":false,
        "source_obscuration_proven":false,"hidden_poh_hashes_recovered":false,
        "bulk_download_authorized":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false
    }))
}

fn validate_page_ranges(plan: &PagedCensusPlan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-horizon-finalized-paged-gap-census-plan-v1"
            && plan.last_slot >= plan.first_slot
            && plan.last_slot - plan.first_slot <= 432_000
            && !plan.pages.is_empty()
            && plan.pages.len() <= 512
            && plan
                .output
                .file_name()
                .is_some_and(|name| name == "gap-census.json"),
        "invalid paged census scope, schema or output"
    );
    let mut next = plan.first_slot;
    for page in &plan.pages {
        ensure!(
            page.first_slot == next
                && page.last_slot >= page.first_slot
                && page.last_slot <= plan.last_slot
                && page.last_slot - page.first_slot < 50_000,
            "pages must cover the complete interval contiguously without overlap"
        );
        next = page
            .last_slot
            .checked_add(1)
            .context("page bound overflow")?;
    }
    ensure!(next - 1 == plan.last_slot, "incomplete final page");
    Ok(())
}

fn page_blocks(page: &BlockListPage, request: &Value, response: &Value) -> Result<Vec<u64>> {
    check_block_list_request(page.first_slot, page.last_slot, request, response)?;
    ensure!(
        response["jsonrpc"] == "2.0" && response.get("error").is_none(),
        "invalid page RPC response"
    );
    let blocks = array(&response["result"])?
        .iter()
        .map(|slot| slot.as_u64().context("page slot is not an integer"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        blocks
            .iter()
            .all(|slot| *slot >= page.first_slot && *slot <= page.last_slot)
            && blocks.windows(2).all(|pair| pair[0] < pair[1]),
        "page contains an out-of-range or unordered slot"
    );
    // A page edge can itself be skipped; only the global endpoints are
    // required to be present. Cross-page gaps are derived after concatenation.
    Ok(blocks)
}

fn paged_census(binding: &BoundFile, plan: &PagedCensusPlan) -> Result<Value> {
    validate_page_ranges(plan)?;
    let mut blocks = Vec::new();
    for page in &plan.pages {
        blocks.extend(page_blocks(
            page,
            &serde_json::from_slice(&read_bound(&page.request)?)?,
            &serde_json::from_slice(&read_bound(&page.response)?)?,
        )?);
    }
    let pairs = pairs_from_present(plan.first_slot, plan.last_slot, &blocks)?;
    // Use the exact same count/authority semantics as single-response census,
    // but retain every actual RPC request/response rather than inventing one
    // combined RPC response or attributing it to a request never answered.
    let mut receipt = census_summary(binding, plan.first_slot, plan.last_slot, &blocks, &pairs)?;
    let object = receipt
        .as_object_mut()
        .context("census receipt is not an object")?;
    object.insert(
        "schema".into(),
        json!("jetstreamer-horizon-finalized-paged-gap-census-v1"),
    );
    object.insert(
        "block_list_pages".into(),
        serde_json::to_value(&plan.pages)?,
    );
    Ok(receipt)
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    let census_only = args.len() == 6 && args[5] == "--census-only";
    let paged_only = args.len() == 6 && args[5] == "--paged-census-only";
    ensure!(
        (args.len() == 5 || census_only || paged_only)
            && args[1] == "--plan-sha256"
            && args[3] == "--self-sha256",
        "usage: jetstreamer-horizon-gap-audit PLAN --plan-sha256 HEX --self-sha256 HEX [--census-only|--paged-census-only]"
    );
    ensure!(
        valid_sha(&args[4]) && digest(&fs::read("/proc/self/exe")?) == args[4],
        "running binary SHA-256 mismatch"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let plan_binding = BoundFile {
        path: PathBuf::from(&args[0]),
        sha256: args[2].clone(),
    };
    let bytes = read_bound(&plan_binding)?;
    if paged_only {
        let plan: PagedCensusPlan = serde_json::from_slice(&bytes)?;
        let receipt = paged_census(&plan_binding, &plan)?;
        write_receipt(&plan.output, &receipt)?;
        println!(
            "{}",
            json!({"output":plan.output,"pages":plan.pages.len(),"post_gap_targets":receipt["post_gap_targets"],"full_gap_audit_complete":false})
        );
        return Ok(());
    }
    let plan: Plan = serde_json::from_slice(&bytes)?;
    validate_mode(&plan, census_only)?;
    let blocks: Value = serde_json::from_slice(&read_bound(&plan.block_list)?)?;
    let block_request: Value = serde_json::from_slice(&read_bound(&plan.block_list_request)?)?;
    check_block_list_request(plan.first_slot, plan.last_slot, &block_request, &blocks)?;
    let (present, pairs) = target_pairs(plan.first_slot, plan.last_slot, &blocks)?;
    if census_only {
        write_receipt(
            &plan.output,
            &census_receipt(&plan_binding, &plan, &present, &pairs)?,
        )?;
        println!(
            "{}",
            json!({"output":plan.output,"post_gap_targets":pairs.len(),"full_gap_audit_complete":false})
        );
        return Ok(());
    }
    let targets = pairs.iter().map(|p| p.1).collect();
    let mut successes = BTreeMap::new();
    let mut retained_rpc_errors = 0;
    for batch in &plan.rpc_batches {
        retained_rpc_errors += collect_batch(
            &serde_json::from_slice(&read_bound(&batch.request)?)?,
            &serde_json::from_slice(&read_bound(&batch.response)?)?,
            &targets,
            &mut successes,
        )?;
    }
    let gaps = assemble(&pairs, &successes)?;
    let skipped_slots: u64 = gaps.iter().map(|g| g.skipped_slots).sum();
    ensure!(
        present.len() as u64 + skipped_slots == plan.last_slot - plan.first_slot + 1,
        "interval count mismatch"
    );
    let receipt = json!({
        "schema":"jetstreamer-horizon-finalized-gap-audit-v1", "plan":plan_binding,
        "first_slot":plan.first_slot,"last_slot":plan.last_slot,"block_list_request":plan.block_list_request,"block_list":plan.block_list,
        "rpc_batches":plan.rpc_batches,"present_slots":present.len(),"skipped_slots":skipped_slots,
        "post_gap_targets":gaps.len(),"expected_tick_boundaries":gaps.iter().map(|g|g.expected_tick_boundaries).sum::<u64>(),
        "gaps":gaps,"retained_rpc_errors":retained_rpc_errors,
        "hash_semantics":"PoH, not Bank/SlotHashes hashes",
        "source_obscuration_proven":false,"hidden_poh_hashes_recovered":false,
        "bulk_download_authorized":false,"replay_launch_authorized":false,
        "runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false
    });
    write_receipt(&plan.output, &receipt)?;
    println!(
        "{}",
        json!({"output":plan.output,"post_gap_targets":pairs.len(),"skipped_slots":skipped_slots})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(first: u64, last: u64) -> BlockListPage {
        BlockListPage {
            first_slot: first,
            last_slot: last,
            request: BoundFile {
                path: "/immutable/request".into(),
                sha256: "a".repeat(64),
            },
            response: BoundFile {
                path: "/immutable/response".into(),
                sha256: "b".repeat(64),
            },
        }
    }

    #[test]
    fn paged_census_requires_complete_nonoverlapping_exact_coverage() {
        let mut plan = PagedCensusPlan {
            schema: "jetstreamer-horizon-finalized-paged-gap-census-plan-v1".into(),
            first_slot: 100,
            last_slot: 108,
            pages: vec![page(100, 103), page(104, 108)],
            output: "/private/gap-census.json".into(),
        };
        validate_page_ranges(&plan).unwrap();
        plan.pages[1].first_slot = 105;
        assert!(validate_page_ranges(&plan).is_err());
        plan.pages[1].first_slot = 103;
        assert!(validate_page_ranges(&plan).is_err());
        plan.pages[1].first_slot = 104;
        plan.pages[1].last_slot = 107;
        assert!(validate_page_ranges(&plan).is_err());
        plan.pages[1].last_slot = 109;
        assert!(validate_page_ranges(&plan).is_err());
        plan.pages[1].last_slot = 108;
        plan.schema = "jetstreamer-horizon-finalized-gap-audit-plan-v1".into();
        assert!(validate_page_ranges(&plan).is_err());
    }

    #[test]
    fn paged_census_checks_each_actual_rpc_and_keeps_cross_page_gaps() {
        let first = page(100, 103);
        let second = page(104, 108);
        let request = |start, end| json!({"jsonrpc":"2.0","id":start,"method":"getBlocks","params":[start,end,{"commitment":"finalized"}]});
        let response = |id, slots| json!({"jsonrpc":"2.0","id":id,"result":slots});
        let mut blocks =
            page_blocks(&first, &request(100, 103), &response(100, vec![100, 101])).unwrap();
        blocks.extend(
            page_blocks(&second, &request(104, 108), &response(104, vec![105, 108])).unwrap(),
        );
        assert_eq!(
            pairs_from_present(100, 108, &blocks).unwrap(),
            [(101, 105), (105, 108)]
        );
        // Neither page edge needs to be a produced block, but all returned
        // blocks must belong to the exact page and responses must match IDs.
        assert!(page_blocks(&first, &request(100, 103), &response(100, vec![100, 104])).is_err());
        assert!(page_blocks(&first, &request(100, 103), &response(101, vec![100, 101])).is_err());
        assert!(page_blocks(&first, &request(100, 102), &response(100, vec![100, 101])).is_err());
        assert!(
            page_blocks(
                &first,
                &request(100, 103),
                &json!({"jsonrpc":"2.0","id":100,"error":{"code":429}})
            )
            .is_err()
        );
        assert!(pairs_from_present(100, 108, &[101, 105, 108]).is_err());
        assert!(pairs_from_present(100, 108, &[100, 105, 107]).is_err());
    }

    fn census_plan() -> Plan {
        let bound = || BoundFile {
            path: PathBuf::from("/immutable/input.json"),
            sha256: "a".repeat(64),
        };
        Plan {
            schema: "jetstreamer-horizon-finalized-gap-census-plan-v1".into(),
            first_slot: 100,
            last_slot: 108,
            block_list_request: bound(),
            block_list: bound(),
            rpc_batches: Vec::new(),
            output: PathBuf::from("/private/gap-census.json"),
        }
    }

    #[test]
    fn census_never_substitutes_for_complete_metadata_audit() {
        let binding = BoundFile {
            path: PathBuf::from("/immutable/census-plan.json"),
            sha256: "b".repeat(64),
        };
        let plan = census_plan();
        validate_mode(&plan, true).unwrap();
        assert!(validate_mode(&plan, false).is_err());
        let (present, pairs) = target_pairs(
            100,
            108,
            &json!({"jsonrpc":"2.0","result":[100,101,104,105,108]}),
        )
        .unwrap();
        let receipt = census_receipt(&binding, &plan, &present, &pairs).unwrap();
        assert_eq!(
            receipt["schema"],
            "jetstreamer-horizon-finalized-gap-census-v1"
        );
        assert_eq!(receipt["present_slots"], 5);
        assert_eq!(receipt["skipped_slots"], 4);
        assert_eq!(receipt["post_gap_targets"], 2);
        assert_eq!(receipt["expected_tick_boundaries"], 6);
        assert_eq!(receipt["gap_candidates"][0]["parent_slot"], 101);
        assert_eq!(receipt["gap_candidates"][1]["slot"], 108);
        assert!(receipt.get("gaps").is_none());
        assert!(receipt.get("rpc_batches").is_none());
        for key in [
            "target_getblock_metadata_complete",
            "independent_target_parent_checks_passed",
            "full_gap_audit_complete",
            "hidden_poh_hashes_recovered",
            "publication_authorized",
            "replay_launch_authorized",
            "runtime_promotion_authorized",
            "r2_mutations",
        ] {
            assert_eq!(receipt[key], false, "{key}");
        }
        assert!(census_receipt(&binding, &plan, &present[..4], &pairs).is_err());
    }

    #[test]
    fn census_requires_explicit_distinct_schema_output_and_empty_metadata() {
        let mut plan = census_plan();
        plan.output = PathBuf::from("/private/gap-audit.json");
        assert!(validate_mode(&plan, true).is_err());
        plan.output = PathBuf::from("/private/gap-census.json");
        plan.schema = "jetstreamer-horizon-finalized-gap-audit-plan-v1".into();
        assert!(validate_mode(&plan, true).is_err());
        assert!(validate_mode(&plan, false).is_err());
        plan.rpc_batches.push(Batch {
            request: BoundFile {
                path: "/request".into(),
                sha256: "a".repeat(64),
            },
            response: BoundFile {
                path: "/response".into(),
                sha256: "b".repeat(64),
            },
        });
        validate_mode(&plan, false).unwrap();
        plan.schema = "jetstreamer-horizon-finalized-gap-census-plan-v1".into();
        assert!(validate_mode(&plan, true).is_err());
    }

    #[test]
    fn census_supports_complete_wide_interval_without_invented_gap_hashes() {
        let blocks: Vec<_> = (100..=432_100).filter(|slot| slot % 10 != 9).collect();
        let (present, pairs) =
            target_pairs(100, 432_100, &json!({"jsonrpc":"2.0","result":blocks})).unwrap();
        assert_eq!(present.len() + pairs.len(), 432_001);
        assert_eq!(pairs.len(), 43_200);
        assert!(pairs.iter().all(|(parent, slot)| slot - parent == 2));
    }

    fn request(slot: u64) -> Value {
        json!([{"jsonrpc":"2.0","id":slot,"method":"getBlock","params":[slot,{"commitment":"finalized","transactionDetails":"none","rewards":false,"maxSupportedTransactionVersion":0}]}])
    }
    fn response(slot: u64, parent: u64) -> Value {
        json!([{"jsonrpc":"2.0","id":slot,"result":{"parentSlot":parent,"blockhash":"11111111111111111111111111111111","previousBlockhash":"11111111111111111111111111111111"}}])
    }

    #[test]
    fn counts_every_gap_and_binds_finalized_parent() {
        let (blocks, pairs) = target_pairs(
            100,
            108,
            &json!({"jsonrpc":"2.0","result":[100,101,104,105,108]}),
        )
        .unwrap();
        let targets = BTreeSet::from([104, 108]);
        let mut successes = BTreeMap::new();
        collect_batch(&request(104), &response(104, 101), &targets, &mut successes).unwrap();
        assert!(assemble(&pairs, &successes).is_err());
        collect_batch(&request(108), &response(108, 105), &targets, &mut successes).unwrap();
        let gaps = assemble(&pairs, &successes).unwrap();
        assert_eq!(blocks.len(), 5);
        assert_eq!(gaps.iter().map(|g| g.skipped_slots).sum::<u64>(), 4);
        assert_eq!(
            gaps.iter().map(|g| g.expected_tick_boundaries).sum::<u64>(),
            6
        );
        successes.get_mut(&108).unwrap().0 = 104;
        assert!(assemble(&pairs, &successes).is_err());
    }

    #[test]
    fn binds_finalized_block_list_request_and_response_identity() {
        let mut request = json!({"jsonrpc":"2.0","id":2,"method":"getBlocks","params":[100,108,{"commitment":"finalized"}]});
        let response = json!({"jsonrpc":"2.0","id":2,"result":[100,101,104,105,108]});
        check_block_list_request(100, 108, &request, &response).unwrap();
        assert!(check_block_list_request(100, 109, &request, &response).is_err());
        request["params"][2]["commitment"] = json!("confirmed");
        assert!(check_block_list_request(100, 108, &request, &response).is_err());
        request["params"][2]["commitment"] = json!("finalized");
        request["id"] = json!(3);
        assert!(check_block_list_request(100, 108, &request, &response).is_err());
    }

    #[test]
    fn rejects_nonfinalized_conflicting_duplicate_and_wrong_rpc_metadata() {
        let targets = BTreeSet::from([104]);
        let mut successes = BTreeMap::new();
        let mut nonfinalized = request(104);
        nonfinalized[0]["params"][1]["commitment"] = json!("confirmed");
        assert!(
            collect_batch(&nonfinalized, &response(104, 101), &targets, &mut successes).is_err()
        );
        collect_batch(&request(104), &response(104, 101), &targets, &mut successes).unwrap();
        assert!(
            collect_batch(&request(104), &response(104, 100), &targets, &mut successes).is_err()
        );
        assert!(
            collect_batch(&request(104), &response(105, 101), &targets, &mut successes).is_err()
        );
        let duplicate = json!([response(104, 101)[0], response(104, 101)[0]]);
        assert!(collect_batch(&request(104), &duplicate, &targets, &mut successes).is_err());
    }

    #[test]
    fn preserves_errors_but_never_counts_them_as_success() {
        let targets = BTreeSet::from([104]);
        let mut successes = BTreeMap::new();
        let error =
            json!([{"jsonrpc":"2.0","id":104,"error":{"code":429,"message":"rate limited"}}]);
        assert_eq!(
            collect_batch(&request(104), &error, &targets, &mut successes).unwrap(),
            1
        );
        assert!(successes.is_empty());
        assert!(assemble(&[(101, 104)], &successes).is_err());
        collect_batch(&request(104), &response(104, 101), &targets, &mut successes).unwrap();
        assemble(&[(101, 104)], &successes).unwrap();
    }

    #[test]
    fn rejects_unordered_or_incomplete_slot_lists_and_invalid_hashes() {
        for slots in [
            json!([100, 100, 108]),
            json!([100, 99, 108]),
            json!([101, 108]),
        ] {
            assert!(target_pairs(100, 108, &json!({"jsonrpc":"2.0","result":slots})).is_err());
        }
        assert!(target_pairs(0, 432001, &json!({"jsonrpc":"2.0","result":[0,432001]})).is_err());
        assert!(check_hash(&json!("not-a-hash")).is_err());
        assert!(check_hash(&json!("1".repeat(33))).is_err());
    }

    #[test]
    fn root_input_integrity_and_private_no_clobber_output() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"bounded evidence").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        let bound = BoundFile {
            path: path.clone(),
            sha256: digest(b"bounded evidence"),
        };
        assert_eq!(read_bound(&bound).unwrap(), b"bounded evidence");
        assert!(
            read_bound(&BoundFile {
                path: path.clone(),
                sha256: "0".repeat(64)
            })
            .is_err()
        );
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(
            read_bound(&BoundFile {
                path: link,
                sha256: bound.sha256.clone()
            })
            .is_err()
        );
        fs::hard_link(&path, directory.path().join("hard-link")).unwrap();
        assert!(read_bound(&bound).is_err());
        let output = directory.path().join("receipt.json");
        write_receipt(&output, &json!({"publication_authorized":false})).unwrap();
        assert!(write_receipt(&output, &json!({"overwritten":true})).is_err());
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(write_receipt(&directory.path().join("public-receipt.json"), &json!({})).is_err());
    }
}
