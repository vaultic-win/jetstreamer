//! Decode complete CAR windows with the production Firehose reader and CID check.
use jetstreamer_firehose::node::{Node, NodeReader};
use std::{
    cell::Cell,
    error::Error,
    io::{self, Read},
};
pub(super) type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
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

pub(super) struct Block {
    pub slot: u64,
    pub parent: u64,
    pub start: u64,
    pub end: u64,
    pub cid: String,
}
pub(super) fn decode(prefix: &[u8], body: &[u8], start: u64) -> Result<(Vec<Block>, u64)> {
    let mut data = prefix.get(..59).ok_or("short CAR header")?.to_vec();
    data.extend_from_slice(body);
    let pos = Cell::new(0);
    let mut reader = NodeReader::new(Position {
        source: &data,
        position: &pos,
    })?;
    reader.read_raw_header()?;
    if pos.get() != 59 {
        return Err("unexpected native header size".into());
    }
    let mut prior = start;
    let mut blocks = Vec::new();
    let mut sections = 0;
    while pos.get() < data.len() {
        let raw = reader.next()?;
        raw.verify_sha256_cid()?;
        sections += 1;
        let cid = raw.get_cid();
        if let Node::Block(b) = raw.parse()? {
            let end = start
                .checked_add(u64::try_from(pos.get() - 59)?)
                .ok_or("window offset overflow")?;
            blocks.push(Block {
                slot: b.slot,
                parent: b.meta.parent_slot,
                start: prior,
                end,
                cid: cid.to_bytes().iter().map(|x| format!("{x:02x}")).collect(),
            });
            prior = end;
        }
    }
    if pos.get() != data.len()
        || prior
            != start
                .checked_add(u64::try_from(body.len())?)
                .ok_or("window length overflow")?
    {
        return Err("incomplete native window".into());
    }
    Ok((blocks, sections))
}
