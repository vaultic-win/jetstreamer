//! Read-only source diagnostic. Entry hashes are PoH hashes, not Bank/SlotHashes hashes.
use jetstreamer_firehose::{epochs::fetch_epoch_stream, node_reader::NodeReader};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn require_directory(directory: &Path) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let metadata = fs::symlink_metadata(directory)?;
    if !directory.is_absolute()
        || directory.canonicalize()? != directory
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o077 != 0
    {
        return Err("evidence directory must be canonical, root-owned, and owner-only".into());
    }
    Ok(())
}

fn retain(
    directory: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    require_directory(directory)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn retain_json(
    directory: &Path,
    name: &str,
    value: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    retain(directory, name, &bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let epoch: u64 = std::env::args().nth(1).ok_or("expected epoch")?.parse()?;
    let client = jetstreamer_firehose::network::create_http_client();
    let mode = std::env::args().nth(2);
    let summary_mode = mode.as_deref() == Some("--bounded-prefix-summary");
    let summary_directory = if summary_mode {
        let path = PathBuf::from(
            std::env::args()
                .nth(3)
                .ok_or("summary requires an absolute private evidence directory")?,
        );
        require_directory(&path)?;
        Some(path)
    } else {
        None
    };
    if summary_mode || mode.as_deref() == Some("--bounded-prefix") {
        // Diagnostic only: compare one bounded range with the ordinary reader's
        // open-ended request. Reject status/framing errors before CAR decoding.
        const LIMIT: usize = 1024 * 1024;
        let mut response = client
            .get(format!(
                "https://files.old-faithful.net/{epoch}/epoch-{epoch}.car"
            ))
            .header(reqwest::header::RANGE, format!("bytes=0-{}", LIMIT - 1))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;
        if let Some(directory) = &summary_directory {
            let mut headers = BTreeMap::new();
            for name in [
                "content-type",
                "content-length",
                "content-range",
                "etag",
                "date",
                "retry-after",
                "cf-ray",
            ] {
                if let Some(value) = response.headers().get(name) {
                    headers.insert(name, value.to_str()?.to_owned());
                }
            }
            retain_json(
                directory,
                &format!("epoch-{epoch}.http-response.json"),
                &serde_json::json!({
                "schema":"jetstreamer-bounded-car-http-observation-v1","epoch":epoch,
                "url":response.url().as_str(),"http_status":response.status().as_u16(),"headers":headers,
                "requested_prefix_bytes":LIMIT,"publication_authorized":false,"r2_mutations":false}),
            )?;
        }
        response.error_for_status_ref()?;
        if response.status() != reqwest::StatusCode::PARTIAL_CONTENT
            || response.content_length() != Some(LIMIT as u64)
            || !response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value.starts_with("bytes 0-1048575/"))
        {
            return Err("unexpected bounded CAR range response".into());
        }
        let content_range = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or("missing range")?
            .to_owned();
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let car_length = content_range
            .strip_prefix("bytes 0-1048575/")
            .and_then(|total| total.parse::<u64>().ok())
            .filter(|total| *total > LIMIT as u64)
            .ok_or("invalid bounded CAR total length")?;
        let mut bytes = Vec::with_capacity(LIMIT);
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() > LIMIT - bytes.len() {
                return Err("oversized bounded CAR response".into());
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len() != LIMIT {
            return Err("incomplete bounded CAR response".into());
        }
        if let Some(directory) = &summary_directory {
            retain(
                directory,
                &format!("epoch-{epoch}.first-block-prefix.car"),
                &bytes,
            )?;
            retain_json(
                directory,
                &format!("epoch-{epoch}.response.json"),
                &serde_json::json!({
                "schema":"jetstreamer-bounded-car-prefix-v1","epoch":epoch,"bytes":LIMIT,
                "sha256":format!("{:x}",Sha256::digest(&bytes)),"content_range":content_range,
                "complete_car":false,"publication_authorized":false,"r2_mutations":false}),
            )?;
        }
        let mut reader = jetstreamer_firehose::node::NodeReader::new(std::io::Cursor::new(&bytes))?;
        reader.read_raw_header()?;
        let mut entries = BTreeMap::new();
        for node_index in 0..100_000 {
            let raw = reader.next()?;
            raw.verify_sha256_cid()?;
            let cid = raw.get_cid().to_string();
            let node = raw.parse()?;
            if let Some(entry) = node.get_entry() {
                if entry.hash.0.len() != 32 {
                    return Err("entry hash is not 32 bytes".into());
                }
                entries.insert(
                    cid.clone(),
                    serde_json::json!({"cid":cid,"num_hashes":entry.num_hashes,
                    "hash":entry.hash.to_string(),"transaction_count":entry.transactions.len()}),
                );
            }
            if let Some(block) = node.get_block() {
                if block.slot / 432_000 != epoch
                    || (block.slot != 0 && block.meta.parent_slot >= block.slot)
                    || (block.slot == 0 && block.meta.parent_slot != 0)
                {
                    return Err("first block epoch/parent mismatch".into());
                }
                if summary_mode {
                    let block_entries = block
                        .entries
                        .iter()
                        .map(|cid| {
                            entries.get(&cid.to_string()).cloned().ok_or(
                                "first block references an entry absent from the bounded prefix",
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    let distinct: BTreeSet<_> = block_entries
                        .iter()
                        .map(|entry| entry["hash"].as_str().unwrap())
                        .collect();
                    let summary = serde_json::json!({"schema":"jetstreamer-bounded-car-first-block-diagnostic-v1",
                        "epoch":epoch,"prefix_bytes":LIMIT,"prefix_sha256":format!("{:x}",Sha256::digest(&bytes)),
                        "content_range":content_range,"car_length_bytes":car_length,"etag":etag,"cid_verified_nodes":node_index+1,
                        "block_cid":cid,"block":block.to_json(),"entries":block_entries,
                        "distinct_entry_hashes":distinct.len(),"tick_entries":block_entries.iter().filter(|entry|entry["transaction_count"]==0).count(),
                        "complete_car":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
                    let directory = summary_directory
                        .as_ref()
                        .expect("validated summary directory");
                    retain_json(
                        directory,
                        &format!("epoch-{epoch}.first-block.json"),
                        &summary,
                    )?;
                    println!(
                        "{}",
                        serde_json::json!({"evidence_directory":directory.display().to_string(),"epoch":epoch,"slot":block.slot,
                        "parent_slot":block.meta.parent_slot,"entry_count":block.entries.len(),"distinct_entry_hashes":distinct.len()})
                    );
                    return Ok(());
                }
                println!(
                    "bounded_bytes={LIMIT} epoch={epoch} parent={} slot={}",
                    block.meta.parent_slot, block.slot
                );
                return Ok(());
            }
        }
        return Err("first block exceeds diagnostic node bound".into());
    }
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let stream = fetch_epoch_stream(epoch, &client).await;
        let mut reader = NodeReader::new(stream);
        let header = reader.read_raw_header().await?;
        eprintln!("epoch={epoch} header_bytes={}", header.len());
        for _ in 0..100_000 {
            let node = reader.next_parsed().await?;
            if let Some(block) = node.get_node().get_block() {
                println!(
                    "epoch={epoch} items={} parent={} slot={}",
                    reader.get_item_index(),
                    block.meta.parent_slot,
                    block.slot
                );
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
            }
        }
        Err("first block exceeds diagnostic node bound".into())
    })
    .await??;
    Ok(())
}
