//! Reconstruct the exact bounded epoch 173 source as historical protocol-v5
//! request frames. A controller admits and runs the diagnostic separately.
use anyhow::{Context, Result, ensure};
use jetstreamer_firehose::node::{Node, NodeReader, NodeWithCid, NodesWithCids};
use jetstreamer_historical_protocol::{
    EntryRequest, Request, RequestBody, read_frame, write_frame,
};
use jetstreamer_node::archive_checksum::{
    ArchiveFileIdentity, archive_file_identity, measure_open_archive, open_regular_nofollow,
    path_matches_archive_identity,
};
use jetstreamer_node::segment_manifest::sha256_hex_string;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use solana_transaction::versioned::VersionedTransaction;
use std::{
    collections::HashSet,
    env,
    fs::{self, File, OpenOptions, Permissions},
    io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;

const PACKET_SHA: &str = "266bb57977b9601c3e8d22c8a8c937adeafc4fe411a5443f5d49244826546d76";
const WARMUP_SHA: &str = "2abdc07dbfd932c4b855f105ae6daad91bd76793392ec328296056000db42e74";
const BOUNDARY_SHA: &str = "1eea02791f82f4e286d69328ff2265647df0552eeea1ca624cc787ad83126c67";
const WARMUP_PREFIX_SHA: &str = "0101a86451cf696c10feba6952956e15b361b1f7572928294bb748d2cdb8f038";
const BOUNDARY_PREFIX_SHA: &str =
    "5052a372813437f8a1c88eab54f0aa31a1a21c1bd14036a1acadf15aeef6317d";
const BOOTSTRAP: u64 = 74_735_808;
const BOUNDARY: u64 = 74_736_000;
const FINAL: u64 = BOUNDARY + 1;
const INDEXED_ENTRIES: usize = 68_188 + 64 + 1_013;
const VOTE_ENTRY: u64 = 209;
const VOTE_ORDINAL: usize = 295;
const VOTE_SIGNATURE: &str =
    "N5MLNYEdLwY2m5dCnTQjgCErHVQpCSmfrbpJqHiuXotCc12rM7E72mZGXXwm7sd7sRhd2reAGx4PJnXXz45kW4s";
const VOTE_RECENT: &str = "8Sa6gDMQoudVkvRY12cBD194kjVTayxLUPrZSA368smV";
const VOTE_WIRE_SHA: &str = "bc77d569270ae72bcc83423d8f7c813efe4cebd8c63b20cf6e86dfd0f4c1292f";
const EXPECTED_TRANSACTIONS: usize = 106_607 + 1_350;
const MAX_WIRE_BYTES: u64 = 160 << 20;
const BATCH_ENTRIES: usize = 64;

#[derive(Deserialize)]
struct Packet {
    schema: String,
    expected_post_bootstrap_banks: Vec<Bank>,
    scope: Scope,
}

#[derive(Deserialize)]
struct Scope {
    bootstrap_slot: u64,
    first_slot: u64,
    last_slot: u64,
    skipped_slots: Vec<u64>,
}

#[derive(Deserialize)]
struct Bank {
    slot: u64,
    parent_slot: u64,
    offset: u64,
    length: u64,
    last_blockhash: String,
}

struct Input {
    path: PathBuf,
    file: File,
    identity: ArchiveFileIdentity,
}

impl Input {
    fn open(path: &Path, sha256: &str, bytes: u64) -> Result<Self> {
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "aliased input: {}",
            path.display()
        );
        let file = open_regular_nofollow(path)?;
        let before = file.metadata()?;
        ensure!(
            before.len() == bytes && before.nlink() == 1 && before.mode() & 0o222 == 0,
            "unexpected input extent or mode: {}",
            path.display()
        );
        let measured = measure_open_archive(&file)?;
        ensure!(
            sha256_hex_string(&measured.sha256) == sha256,
            "changed input: {}",
            path.display()
        );
        let input = Self {
            path: path.to_owned(),
            file,
            identity: measured.identity,
        };
        input.recheck()?;
        Ok(input)
    }

    fn recheck(&self) -> Result<()> {
        ensure!(
            archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(&self.path, self.identity)?,
            "input changed during source framing: {}",
            self.path.display()
        );
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
struct Vote {
    slot: u64,
    entry_index: u64,
    transaction_ordinal: usize,
    signature: String,
    recent_blockhash: String,
    wire_sha256: String,
}

#[derive(Default, Debug, Eq, PartialEq, Serialize)]
struct Counts {
    frames: u64,
    blocks: usize,
    entries: usize,
    transactions: usize,
    vote: Option<Vote>,
}

fn check_vote(slot: u64, entry_index: u64, ordinal: usize, wire: &[u8]) -> Result<Vote> {
    ensure!(
        slot == FINAL && entry_index == VOTE_ENTRY && ordinal == VOTE_ORDINAL,
        "unexpected target vote location"
    );
    let tx: VersionedTransaction = bincode::deserialize(wire)?;
    ensure!(
        bincode::serialize(&tx)? == wire
            && tx
                .signatures
                .first()
                .context("unsigned source vote")?
                .to_string()
                == VOTE_SIGNATURE
            && tx.message.recent_blockhash().to_string() == VOTE_RECENT,
        "bounded source does not contain the original signed vote"
    );
    tx.verify_and_hash_message()?;
    let wire_sha256 = format!("{:x}", Sha256::digest(wire));
    ensure!(
        wire_sha256 == VOTE_WIRE_SHA,
        "original vote wire differs from the independent decoder"
    );
    Ok(Vote {
        slot,
        entry_index,
        transaction_ordinal: ordinal,
        signature: VOTE_SIGNATURE.into(),
        recent_blockhash: VOTE_RECENT.into(),
        wire_sha256,
    })
}

fn append_scope(
    mut source: &File,
    prefix: &[u8],
    banks: &[Bank],
    base: u64,
    out: &mut BufWriter<&mut File>,
    counts: &mut Counts,
) -> Result<()> {
    let mut next_offset = base;
    for bank in banks {
        ensure!(
            bank.offset == next_offset && (1..=16 << 20).contains(&bank.length),
            "invalid source range around slot {}",
            bank.slot
        );
        source.seek(SeekFrom::Start(bank.offset - base))?;
        let input = Cursor::new(&prefix[..59]).chain(Read::by_ref(&mut source).take(bank.length));
        let mut reader = NodeReader::new(input).map_err(|e| anyhow::anyhow!("{e}"))?;
        reader
            .read_raw_header()
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut nodes = NodesWithCids::new();
        let block = loop {
            let raw = reader.next().map_err(|e| anyhow::anyhow!("{e}"))?;
            raw.verify_sha256_cid()
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let cid = *raw.get_cid();
            let node = raw.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
            if let Node::Block(block) = node {
                break block;
            }
            nodes.push(NodeWithCid::new(cid, node));
        };
        drop(reader);
        ensure!(
            source.stream_position()? == bank.offset - base + bank.length
                && block.slot == bank.slot
                && block.meta.parent_slot == bank.parent_slot
                && !block.entries.is_empty(),
            "indexed CAR block or parent mismatch at {}",
            bank.slot
        );
        let mut used_entries = HashSet::new();
        let mut used_transactions = HashSet::new();
        let mut ordinal = 0;
        let mut last_hash = None;
        for (batch_index, links) in block.entries.chunks(BATCH_ENTRIES).enumerate() {
            let mut batch = Vec::with_capacity(links.len());
            for (index, entry_link) in links.iter().enumerate() {
                let entry_index = (batch_index * BATCH_ENTRIES + index) as u64;
                ensure!(used_entries.insert(*entry_link), "duplicate entry link");
                let Some(Node::Entry(entry)) =
                    nodes.get_by_cid(entry_link).map(NodeWithCid::get_node)
                else {
                    anyhow::bail!("missing entry {entry_index} in block {}", bank.slot);
                };
                ensure!(entry.hash.0.len() == 32, "invalid source entry hash");
                last_hash = Some(entry.hash.0.as_slice());
                let mut transactions = Vec::with_capacity(entry.transactions.len());
                for tx_link in &entry.transactions {
                    ensure!(
                        used_transactions.insert(*tx_link),
                        "duplicate transaction link"
                    );
                    let Some(Node::Transaction(tx)) =
                        nodes.get_by_cid(tx_link).map(NodeWithCid::get_node)
                    else {
                        anyhow::bail!("missing transaction {ordinal} in block {}", bank.slot);
                    };
                    ensure!(
                        tx.slot == bank.slot && tx.index.is_none_or(|ix| ix == ordinal as u64),
                        "source transaction order changed"
                    );
                    let wire = nodes
                        .reassemble_dataframes(&tx.data)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                    ensure!(
                        (65..=1232).contains(&wire.len()),
                        "invalid legacy transaction length"
                    );
                    if bank.slot == FINAL && ordinal == VOTE_ORDINAL {
                        counts.vote = Some(check_vote(bank.slot, entry_index, ordinal, &wire)?);
                    }
                    transactions.push(wire);
                    ordinal += 1;
                }
                batch.push(EntryRequest {
                    slot: bank.slot,
                    entry_index,
                    num_hashes: entry.num_hashes,
                    hash: entry.hash.0.clone(),
                    transactions,
                });
            }
            counts.entries += batch.len();
            counts.frames += 1;
            write_frame(
                out,
                &Request {
                    id: counts.frames,
                    body: RequestBody::ProcessEntries(batch),
                },
            )?;
            ensure!(
                out.stream_position()? <= MAX_WIRE_BYTES,
                "wire fixture exceeded its allocation"
            );
        }
        let blockhash = bank.last_blockhash.parse::<Hash>()?.to_bytes();
        ensure!(
            last_hash == Some(blockhash.as_slice()),
            "original last entry hash differs at {}",
            bank.slot
        );
        counts.blocks += 1;
        counts.transactions += ordinal;
        next_offset = next_offset
            .checked_add(bank.length)
            .context("source range overflow")?;
    }
    ensure!(
        source.metadata()?.len() == next_offset - base,
        "unexpected trailing source bytes"
    );
    Ok(())
}

fn verify_frames(file: &File, banks: &[Bank], expected: &Counts) -> Result<()> {
    let mut file = file.try_clone()?;
    file.rewind()?;
    let mut file = BufReader::new(file);
    let mut counts = Counts::default();
    let mut next_index = 0;
    let mut ordinal = 0;
    let mut must_start_slot = true;
    while let Some(frame) = read_frame::<Request, _>(&mut file)? {
        counts.frames += 1;
        ensure!(frame.id == counts.frames, "nonconsecutive wire frame ID");
        let RequestBody::ProcessEntries(entries) = frame.body else {
            anyhow::bail!("non-replay record in bounded wire fixture");
        };
        ensure!(
            (1..=BATCH_ENTRIES).contains(&entries.len()),
            "wire batch bound"
        );
        let bank = banks
            .get(counts.blocks)
            .context("path exceeds original bank range")?;
        let terminal_hash = bank.last_blockhash.parse::<Hash>()?.to_bytes();
        let mut block_complete = false;
        for (in_batch, entry) in entries.iter().enumerate() {
            ensure!(
                entry.slot == bank.slot && entry.entry_index == next_index,
                "wire entry order changed"
            );
            next_index += 1;
            counts.entries += 1;
            for wire in &entry.transactions {
                if bank.slot == FINAL && ordinal == VOTE_ORDINAL {
                    counts.vote = Some(check_vote(bank.slot, entry.entry_index, ordinal, wire)?);
                }
                ordinal += 1;
                counts.transactions += 1;
            }
            if entry.hash.as_slice() == terminal_hash {
                ensure!(
                    in_batch + 1 == entries.len(),
                    "slot ends before its last wire entry"
                );
                block_complete = true;
            }
        }
        must_start_slot = block_complete;
        if block_complete {
            next_index = 0;
            ordinal = 0;
            counts.blocks += 1;
        }
    }
    ensure!(
        must_start_slot && counts == *expected,
        "protocol reread differs from source extraction"
    );
    Ok(())
}

fn run(input_root: &Path, output_root: &Path) -> Result<()> {
    let packet = Input::open(
        &input_root.join("COMPARATOR_PACKET.json"),
        PACKET_SHA,
        86_804,
    )?;
    let warmup = Input::open(
        &input_root.join("epoch172-warmup.car"),
        WARMUP_SHA,
        75_282_718,
    )?;
    let boundary = Input::open(
        &input_root.join("epoch173-boundary.car"),
        BOUNDARY_SHA,
        1_820_937,
    )?;
    let warmup_prefix = Input::open(&input_root.join("172.prefix"), WARMUP_PREFIX_SHA, 96)?;
    let boundary_prefix = Input::open(&input_root.join("173.prefix"), BOUNDARY_PREFIX_SHA, 96)?;
    let source: Packet = serde_json::from_reader(BufReader::new(&packet.file))?;
    let banks = &source.expected_post_bootstrap_banks;
    ensure!(
        source.schema == "horizon-epoch173-bounded-comparator-source-packet-v1"
            && source.scope.bootstrap_slot == BOOTSTRAP
            && source.scope.first_slot == BOOTSTRAP + 1
            && source.scope.last_slot == FINAL
            && banks.len() == 179
            && banks[176].slot == BOUNDARY - 1
            && banks[177].slot == BOUNDARY
            && banks[178].slot == FINAL,
        "unexpected comparator packet scope"
    );
    let mut expected =
        (BOOTSTRAP + 1..=FINAL).filter(|slot| !source.scope.skipped_slots.contains(slot));
    let mut parent = BOOTSTRAP;
    for bank in banks {
        ensure!(
            expected.next() == Some(bank.slot) && bank.parent_slot == parent,
            "unexpected source lineage"
        );
        parent = bank.slot;
    }
    ensure!(
        expected.next().is_none(),
        "comparator packet omitted an original bank"
    );

    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(output_root)?;
    let metadata = dir.metadata()?;
    ensure!(
        output_root.is_absolute()
            && output_root.canonicalize()? == output_root
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o077 == 0
            && metadata.dev() == fs::metadata("/home/sol")?.dev(),
        "output must be private and HOME-backed"
    );
    let wire_path = output_root.join("epoch173-source-requests.v5");
    let receipt_path = output_root.join("WIRE_SOURCE.json");
    for path in [&wire_path, &receipt_path] {
        ensure!(
            path.symlink_metadata()
                .is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
            "output already present"
        );
    }
    let mut temporary = NamedTempFile::new_in(output_root)?;
    let mut writer = BufWriter::new(temporary.as_file_mut());
    let mut counts = Counts::default();
    let mut warmup_header = [0; 96];
    let mut boundary_header = [0; 96];
    (&warmup_prefix.file).read_exact(&mut warmup_header)?;
    (&boundary_prefix.file).read_exact(&mut boundary_header)?;
    append_scope(
        &warmup.file,
        &warmup_header,
        &banks[..177],
        153_903_244_308,
        &mut writer,
        &mut counts,
    )?;
    append_scope(
        &boundary.file,
        &boundary_header,
        &banks[177..],
        59,
        &mut writer,
        &mut counts,
    )?;
    writer.flush()?;
    drop(writer);
    ensure!(
        counts.entries == INDEXED_ENTRIES
            && counts.blocks == 179
            && counts.transactions == EXPECTED_TRANSACTIONS
            && counts.vote.is_some(),
        "incomplete original source coverage"
    );
    verify_frames(temporary.as_file(), banks, &counts)?;
    temporary
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    temporary.as_file().sync_all()?;
    for input in [
        &packet,
        &warmup,
        &boundary,
        &warmup_prefix,
        &boundary_prefix,
    ] {
        input.recheck()?;
    }
    let measured = measure_open_archive(temporary.as_file())?;
    let mut receipt = NamedTempFile::new_in(output_root)?;
    serde_json::to_writer_pretty(
        &mut receipt,
        &serde_json::json!({
            "schema": "horizon-epoch173-original-comparator-wire-v1",
            "packet_sha256": PACKET_SHA,
            "warmup_sha256": WARMUP_SHA,
            "boundary_sha256": BOUNDARY_SHA,
            "protocol_version": 5,
            "first_slot": BOOTSTRAP + 1,
            "last_slot": FINAL,
            "counts": counts,
            "wire_path": wire_path,
            "wire_sha256": sha256_hex_string(&measured.sha256),
            "wire_bytes": temporary.as_file().metadata()?.len(),
            "independent_framing_reread": true,
            "worker_executed": false,
            "publication_authorized": false,
        }),
    )?;
    receipt.write_all(b"\n")?;
    receipt
        .as_file()
        .set_permissions(Permissions::from_mode(0o400))?;
    receipt.as_file().sync_all()?;
    let current = output_root.symlink_metadata()?;
    ensure!(
        metadata.dev() == current.dev() && metadata.ino() == current.ino(),
        "output root changed"
    );
    temporary.persist_noclobber(wire_path)?;
    dir.sync_all()?;
    receipt.persist_noclobber(&receipt_path)?;
    dir.sync_all()?;
    println!("{}", receipt_path.display());
    Ok(())
}

fn main() -> Result<()> {
    let [input, output] = env::args_os()
        .skip(1)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| {
            anyhow::anyhow!("usage: jetstreamer-epoch173-source-wire INPUT_DIR OUTPUT_DIR")
        })?;
    run(Path::new(&input), Path::new(&output))
}
