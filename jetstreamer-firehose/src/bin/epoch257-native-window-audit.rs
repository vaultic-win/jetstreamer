//! Compare every local CAR section against the normal Firehose NodeReader under its actual crate.
use jetstreamer_firehose::node::{Node, NodeReader};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    error::Error,
    fs,
    io::{self, Read},
    path::PathBuf,
};

type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
struct Position<'a> {
    source: &'a [u8],
    position: &'a Cell<usize>,
}
impl Read for Position<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.source.read(out)?;
        self.position.set(self.position.get() + count);
        Ok(count)
    }
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: native-reader REPAIR_CANDIDATE_JSON".into());
    }
    let report = fs::read(&args[0])?;
    let candidate: Value = serde_json::from_slice(&report)?;
    let index =
        fs::read(PathBuf::from(&args[0]).with_file_name("epoch-257-slot-ranges.candidate.raw"))?;
    let actual = format!("{:x}", Sha256::digest(&index));
    if candidate["candidate_sha256"] != actual || index.len() != 5_184_000 {
        return Err("candidate file digest/length".into());
    }
    if candidate["candidate_sha256"]
        != "5810e796b7565404320544ebb5cd98055eb5cfaf60af64884c96481e5f75d126"
        || candidate["schema"] != "horizon257-direct-car-repair-candidate-v1"
    {
        return Err("wrong candidate".into());
    }
    let plan =
        fs::read("/var/lib/jetstreamer/horizon257-edge-source-20261120-v1/edge-windows.json")?;
    if format!("{:x}", Sha256::digest(&plan))
        != "b8459e69dbecdffc9086c7954f1ae2bdd8a841ac70f85e034d38cfb8ec708f3b"
    {
        return Err("edge window plan digest mismatch".into());
    }
    let plans: Vec<Value> = serde_json::from_slice(&plan)?;
    let dir = PathBuf::from("/run/horizon257-edge-source-20261120-v1/result/windows");
    let prefix =
        fs::read("/var/lib/jetstreamer/horizon257-index-source-20261120-v1/257.car.prefix")?;
    let edges = candidate["edges"].as_array().ok_or("no edges")?;
    if edges.len() != 29 || plans.len() != 29 {
        return Err("coverage".into());
    }
    if format!("{:x}", Sha256::digest(&prefix))
        != "b05ac5e7b6c0d9b595c98bec38ba37b00d9183154eb5a922d6f69a05724affea"
    {
        return Err("source CAR prefix changed".into());
    }
    let mut result = Vec::new();
    let mut total_sections = 0u64;
    let mut total_blocks = 0u64;
    for (w, edge) in plans.iter().zip(edges) {
        let id = w["edge"].as_u64().ok_or("edge")?;
        let start = w["start"].as_u64().ok_or("offset")?;
        let end = w["end"].as_u64().ok_or("end")?;
        let expected = edge["blocks"].as_array().ok_or("blocks")?;
        let body = fs::read(dir.join(format!("{id}.car")))?;
        if body.len() as u64 != end - start
            || edge["edge"] != id
            || edge["capture_sha256"] != format!("{:x}", Sha256::digest(&body))
        {
            return Err("window bound".into());
        }
        let mut data = prefix[..59].to_vec();
        data.extend(body);
        let pos = Cell::new(0);
        let mut reader = NodeReader::new(Position {
            source: &data,
            position: &pos,
        })?;
        reader.read_raw_header()?;
        let mut prior = start;
        let mut blocks = 0usize;
        let mut sections = 0u64;
        while pos.get() < data.len() {
            let raw = reader.next()?;
            raw.verify_sha256_cid()?;
            sections += 1;
            let cid: String = raw
                .get_cid()
                .to_bytes()
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect();
            if let Node::Block(b) = raw.parse()? {
                let end = start + (pos.get() - 59) as u64;
                let index_slot =
                    usize::try_from(b.slot.checked_sub(111024000).ok_or("slot outside epoch")?)?;
                let row_start = index_slot.checked_mul(12).ok_or("slot index overflow")?;
                let record = index
                    .get(row_start..row_start + 12)
                    .ok_or("slot beyond epoch257")?;
                let actual_offset = u64::from_le_bytes(record[..8].try_into()?);
                let actual_length = u32::from_le_bytes(record[8..].try_into()?);
                if (actual_offset, u64::from(actual_length)) != (prior, end - prior) {
                    return Err("native terminal range differs from candidate row".into());
                }
                let row = expected.get(blocks).ok_or("extra terminal block")?;
                if row["slot"] != b.slot
                    || row["parent"] != b.meta.parent_slot
                    || row["start"] != prior
                    || row["end"] != end
                    || row["block_cid_hex"] != cid
                {
                    return Err(format!(
                        "native decoder disagreement at edge {id} slot {}",
                        b.slot
                    )
                    .into());
                }
                prior = end;
                blocks += 1;
            }
        }
        if blocks != expected.len() || prior != end || pos.get() != data.len() {
            return Err("incomplete native window".into());
        }
        total_sections += sections;
        total_blocks += blocks as u64;
        result.push(json!({"edge":id,"sections":sections,"blocks":blocks,"bytes":end-start}));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &json!({"schema":"horizon257-native-window-comparison-v1","candidate_sha256":candidate["candidate_sha256"],"windows":result,"total_sections":total_sections,"repair_report_sha256":format!("{:x}",Sha256::digest(&report)),"total_blocks":total_blocks,"all_cids_checked":true,"all_terminal_blocks_offsets_parents_cids_match":true,"replay_authorized":false})
        )?
    );
    Ok(())
}
