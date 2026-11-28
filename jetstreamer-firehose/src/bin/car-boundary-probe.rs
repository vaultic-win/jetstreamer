//! Bounded, read-only native block check for suspect Old Faithful CAR ranges.
use jetstreamer_firehose::node::{Node, NodeReader};
use reqwest::{StatusCode, header::RANGE};
use sha2::{Digest, Sha256};
use std::{env, error::Error, fs, io::Cursor};

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() != 7 {
        return Err("usage: car-boundary-probe EPOCH SLOT OFFSET LENGTH CAR_BYTES HEADER_PATH HEADER_SHA256".into());
    }
    let epoch: u64 = args[0].parse()?;
    let slot: u64 = args[1].parse()?;
    let offset: u64 = args[2].parse()?;
    let length: u64 = args[3].parse()?;
    let car_bytes: u64 = args[4].parse()?;
    if !(253..=255).contains(&epoch)
        || slot / 432_000 != epoch
        || length == 0
        || length > 32 * 1024 * 1024
        || offset < 59
        || offset.checked_add(length).is_none_or(|end| end > car_bytes)
    {
        return Err("range exceeds the bounded epoch CAR scope".into());
    }
    let header = fs::read(&args[5])?;
    if header.len() != 4096
        || format!("{:x}", Sha256::digest(&header)) != args[6]
        || header[0] != 58
    {
        return Err("CAR header binding changed".into());
    }
    let url = format!("https://files.old-faithful.net/{epoch}/epoch-{epoch}.car");
    let end = offset + length - 1;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let body = runtime.block_on(async {
        let response = reqwest::Client::new()
            .get(&url)
            .header(RANGE, format!("bytes={offset}-{end}"))
            .send()
            .await?;
        if response.status() != StatusCode::PARTIAL_CONTENT
            || response
                .headers()
                .get(reqwest::header::CONTENT_RANGE)
                .and_then(|value| value.to_str().ok())
                != Some(format!("bytes {offset}-{end}/{car_bytes}").as_str())
            || response.content_length() != Some(length)
        {
            return Err("CAR source did not return the exact bounded range".into());
        }
        let body = response.bytes().await?;
        if body.len() as u64 != length {
            return Err("CAR range length changed".into());
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(body)
    })?;
    let body_sha = format!("{:x}", Sha256::digest(&body));
    let mut bytes = Vec::with_capacity(59 + body.len());
    bytes.extend_from_slice(&header[..59]);
    bytes.extend_from_slice(&body);
    let expected_len = bytes.len() as u64;
    let mut reader = NodeReader::new(Cursor::new(bytes))?;
    reader.read_raw_header()?;
    let mut nodes = 0_u64;
    loop {
        let raw = reader.next()?;
        let parsed = raw.parse()?;
        raw.verify_sha256_cid()?;
        nodes += 1;
        if let Node::Block(block) = parsed {
            let consumed = reader.into_inner().position();
            if block.slot != slot || consumed != expected_len {
                eprintln!(
                    "decoded_block_slot={} requested_slot={slot} consumed_bytes={consumed} expected_bytes={expected_len} body_sha256={body_sha}",
                    block.slot
                );
                return Err("decoded block slot or CAR range coverage mismatch".into());
            }
            println!(
                "epoch={epoch} slot={slot} offset={offset} length={length} nodes={nodes} body_sha256={body_sha} block_slot={}",
                block.slot
            );
            return Ok(());
        }
    }
}
