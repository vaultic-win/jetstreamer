//! Offline qualification of the corrected index and three generation-captured CAR ranges.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/horizon_legacy_entry.rs"]
mod horizon_legacy_entry;
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/horizon_legacy_poh.rs"]
mod horizon_legacy_poh;
use horizon_legacy_poh::{PohExpectation, verify_v1_4_25_poh_chain};
use jetstreamer_firehose::{
    index::{SlotOffsetIndexError, slot_to_range},
    node::{Node, NodeReader},
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, error::Error, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
const INDEX: &str = "ed2654c5fdd9a115176d6d799df636ee1ce945fca393c812a0ba2f1db8f909c8";
struct Sample {
    body: &'static str,
    sha: &'static str,
    slot: u64,
    parent: u64,
    previous: &'static str,
    last: &'static str,
}
const SAMPLES: [Sample; 3] = [
    Sample {
        body: "first-gap.body",
        sha: "e17902c8453d628ac2d6532ced2e5899d5bb113c35bf06deb8a03d7ccf848417",
        slot: 61_328_816,
        parent: 61_328_811,
        previous: "fc678b4338245332046e7cae7ef82a027175ef88b7bc2b32d9fe3efe218945f6",
        last: "0653456967c72d28cd6255a5272127555100f7acdffea992f8e9a991092b6162",
    },
    Sample {
        body: "interstice-61333087.car",
        sha: "5f13e717da19d62df79385416df065510f01841fcdcdea8a3288fd786bc6e69b",
        slot: 61_333_100,
        parent: 61_333_087,
        previous: "1f5ec8f1323226f7ea0c1316ce8f0a038e9569a51d166fd96cbc78c105a623d8",
        last: "81758e7a0b65d474ff918ac6c6b0dcb8571ecd7adcd059a25058621d0180ca62",
    },
    Sample {
        body: "interstice-61341139.car",
        sha: "31e6a55f73dfe82e326d78218adca111d3cc8afbd70304cb394c996420a22571",
        slot: 61_341_144,
        parent: 61_341_139,
        previous: "0046bee6a1f9f0cc8ef377b03543ed5932cd9e2bd161a363892e2e9f2cbf5c59",
        last: "0ceb4ba75cacf296e12e9b249b6707e82ec84d939da5de158be04405a2b63cfe",
    },
];
fn hex_hash(hex: &str) -> Result<[u8; 32]> {
    let mut hash = [0u8; 32];
    for (i, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)?;
    }
    Ok(hash)
}
fn verify_block(header: &[u8], body: &[u8], sample: &Sample) -> Result<()> {
    if format!("{:x}", Sha256::digest(body)) != sample.sha {
        return Err("CAR body SHA mismatch".into());
    }
    let car = [header, body].concat();
    let mut cursor = car.as_slice();
    let mut reader = NodeReader::new(&mut cursor)?;
    reader.read_raw_header()?;
    let mut entries = HashMap::new();
    let mut txs = HashMap::new();
    let mut sections = 0usize;
    let block = loop {
        let raw = reader.next()?;
        raw.verify_sha256_cid()?;
        let cid = *raw.get_cid();
        sections += 1;
        match raw.parse()? {
            Node::Entry(e) if entries.insert(cid, e.clone()).is_some() => {
                return Err("duplicate entry".into());
            }
            Node::Transaction(tx) if txs.insert(cid, tx.clone()).is_some() => {
                return Err("duplicate transaction".into());
            }
            Node::Block(b) => break b,
            _ => {}
        }
    };
    if !cursor.is_empty() || block.slot != sample.slot || block.meta.parent_slot != sample.parent {
        return Err("CAR extent or decoded parent differs".into());
    }
    let mut bytes = (block.entries.len() as u64).to_le_bytes().to_vec();
    let mut tx_index = 0;
    for cid in &block.entries {
        let entry = entries.remove(cid).ok_or("missing linked entry")?;
        bytes.extend(entry.num_hashes.to_le_bytes());
        bytes.extend(<[u8; 32]>::try_from(entry.hash.0.as_slice())?);
        bytes.extend((entry.transactions.len() as u64).to_le_bytes());
        for tx_cid in &entry.transactions {
            let tx = txs.remove(tx_cid).ok_or("missing linked transaction")?;
            if tx.index != Some(tx_index) || tx.slot != block.slot || !tx.is_complete_data() {
                return Err("transaction body or index differs".into());
            }
            bytes.extend(tx.data.data.as_slice());
            tx_index += 1;
        }
    }
    if !entries.is_empty() || !txs.is_empty() {
        return Err("unreferenced CAR entries or transactions".into());
    }
    let batch = horizon_legacy_entry::decode_v1_4_25_padded_entries(&bytes)?;
    let ticks = batch
        .entries
        .iter()
        .filter(|e| e.transaction_count == 0)
        .count();
    let expected = PohExpectation {
        parent_slot: sample.parent,
        slot: sample.slot,
        parent_hash: hex_hash(sample.previous)?,
        final_hash: hex_hash(sample.last)?,
        ticks_per_slot: 64,
        hashes_per_tick: 12_500,
    };
    let work = (sample.slot - sample.parent) * 64 * 12_500;
    let chain = verify_v1_4_25_poh_chain(std::slice::from_ref(&batch), &expected, work, || Ok(()))?;
    if chain.boundaries.len() as u64 != sample.slot - sample.parent {
        return Err("boundary count differs".into());
    }
    let mut bad = batch;
    bad.entries[0].hash[0] ^= 1;
    if verify_v1_4_25_poh_chain(&[bad], &expected, work, || Ok(())).is_ok() {
        return Err("corrupted original entry accepted".into());
    }
    println!(
        "slot={} parent={} sections={sections} entries={} txs={tx_index} ticks={ticks} boundaries={} chained_hashes={} final={} corrupt_hash_rejected=true",
        sample.slot,
        sample.parent,
        block.entries.len(),
        chain.boundaries.len(),
        chain.executed_hashes,
        sample.last
    );
    Ok(())
}
async fn run(folder: &Path, raw: &Path) -> Result<()> {
    let data = fs::read(raw)?;
    if data.len() != 5_184_000 || format!("{:x}", Sha256::digest(&data)) != INDEX {
        return Err("expected corrected epoch 141 data".into());
    }
    let mut present = 0;
    for (i, row) in data.chunks_exact(12).enumerate() {
        let slot = 60_912_000 + i as u64;
        let start = u64::from_le_bytes(row[..8].try_into()?);
        let len = u32::from_le_bytes(row[8..].try_into()?);
        match slot_to_range(slot).await {
            Ok(got) if len > 0 && got == (start, u64::from(len)) => present += 1,
            Err(SlotOffsetIndexError::SlotNotFound(v, url))
                if v == slot && start == 0 && len == 0 && url.scheme() == "file" => {}
            got => return Err(format!("actual replay lookup differs for {slot}: {got:?}").into()),
        }
    }
    if present != 363_668 {
        return Err("epoch block count differs".into());
    }
    println!("index={INDEX} actual_reader=slot_to_range checked=432000 present={present}");
    let header = fs::read(folder.join("of-header.car"))?;
    if format!("{:x}", Sha256::digest(&header))
        != "a6e3f7a3ec146c14476608d108d243db185d7767d727c8995b96dbe5968da6e2"
    {
        return Err("wrong CAR header".into());
    }
    for sample in &SAMPLES {
        verify_block(&header, &fs::read(folder.join(sample.body))?, sample)?;
    }
    Ok(())
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: epoch141-suffix-source CAPTURE_DIRECTORY CORRECTED_RAW".into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(Path::new(&args[0]), Path::new(&args[1])))
}
