use jetstreamer_horizon::{
    archive::{
        ArchiveProvenance, ArchiveProvenanceV1, ArchiveProvenanceV2, ArchiveReader, ArchiveWriter,
        ArchiveWriterConfig, BootstrapStateKind, ReencodeStats, RuntimeAdmission, SemanticDigest,
        TransactionMetadataPolicy, reencode_archive_prefix_from_retained_buckets,
    },
    block_metas::BlockMeta,
    entries::EntryRecord,
    epochs::EpochMeta,
};
use sha2::{Digest, Sha256};
use solana_hash::Hash;
use std::{
    fs::File,
    io::{self, BufReader, Cursor, Read, Seek, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

mod original_view;
mod reservation;
use reservation::{Reservation, ReservedWriter};

const FIRST: u64 = 114_912_000;
const SELECTED: u64 = 11_431;
const RETAINED: u64 = 11_520;
const BOOTSTRAP_SLOT: u64 = 114_910_768;
const VIEW_SHA: &str = "e3dc37bfefb9b8d42f2b201658170ba6d2d7cc6aff3954a4828ba0024eeaa568";
const TRAILER_SHA: &str = "7209682c763e597309eeea097c0d5f226bfe201c04e600f790c6708eb6d13bb1";
const RAW_SHA: &str = "a58ca8569cf3d10b2a063f9b731ac94ce61945a48adf216cc1c65608d2e3111a";
const SOURCE_SEMANTIC: &str = "eb045cee7a1f6280efb212acad3fa687b7f8c8b1a888505cd742ae65c5df6311";
const WORKER_SHA: &str = "763f1aff1f752f0d9886f0f2324a73c9c66a154269d28931575744316bb2f220";
const END_HASH: &str = "2AVLhEfu6PZDrYe2UC3y1G6S1QSjySS97HpdvDMB1cC6";
const FIRST_PARENT: &str = "FxGem4zq3seyLHAAgu7wUNega2s6RbMGdr48EnQZaLmU";
const BOOTSTRAP_HASH: &str = "HnePfSpTtWaPDFx9RrPeuamDZREhoUXa7xpK6fbtPGyK";
const OUTPUT_NAME: &str = "epoch-266-prefix-through-114923430.jet";
const OUTPUT_CAP: u64 = 8 << 30;
const ROOT_CAP: u64 = OUTPUT_CAP + (1 << 20);
const MEMORY_CAP: u64 = 8 << 30;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn check(test: bool, description: &'static str) -> Result<()> {
    if test {
        Ok(())
    } else {
        Err(description.into())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Bounded<W> {
    sink: W,
    bytes: u64,
    cap: u64,
}

impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() as u64 > self.cap - self.bytes {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "dense prefix output cap",
            ));
        }
        let done = self.sink.write(bytes)?;
        self.bytes += done as u64;
        Ok(done)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

fn convert<R: Read + Seek, W: Write>(
    input: R,
    output: W,
    retained: u64,
    selected: u64,
    terminal: Hash,
    cap: u64,
) -> Result<(Bounded<W>, ReencodeStats)> {
    Ok(reencode_archive_prefix_from_retained_buckets(
        input,
        Bounded {
            sink: output,
            bytes: 0,
            cap,
        },
        ArchiveWriterConfig::default(),
        retained,
        selected,
        terminal,
    )?)
}

fn reread<R: Read + Seek>(
    input: R,
    epoch: u64,
    first: u64,
    count: u64,
    stats: &ReencodeStats,
) -> Result<ArchiveProvenanceV2> {
    let mut r = ArchiveReader::open(input)?;
    check(
        r.header().epoch == epoch
            && r.header().slot_start == first
            && r.header().slot_count == count
            && r.has_complete_slot_coverage()?,
        "dense output range or coverage changed",
    )?;
    let Some(ArchiveProvenance::V2(p)) = r.provenance()? else {
        return Err("dense output has foreign provenance".into());
    };
    check(
        p.base.requested_slot_start == first && p.base.requested_slot_count == count,
        "provenance is not narrowed to the dense output",
    )?;
    r.verify_chain = true;
    let mut digest = SemanticDigest::new();
    check(
        r.read_slots(first, count, &mut digest)? == count
            && digest
                .finish()
                .map_err(|_| "output semantic digest error")?
                == stats.output_semantic_sha256,
        "independent output reread disagrees with the reencoder",
    )?;
    Ok(p)
}

fn fixture() -> Result<()> {
    let first = 432_000;
    let anchor = Hash::new_from_array([0xa5; 32]);
    let p = ArchiveProvenance::V2(ArchiveProvenanceV2 {
        base: ArchiveProvenanceV1 {
            generation_profile: "jetstreamer-node/historical-replay-v1".into(),
            runtime_profile: "solana-v1.0.24".into(),
            runtime_admission: RuntimeAdmission::Candidate,
            runtime_revision: "a93915f1bddb73480f86fc09f487315ae191897d".into(),
            runtime_toolchain: "rustc-1.43.0-x86_64-unknown-linux-gnu".into(),
            genesis_hash: Hash::new_from_array([5; 32]),
            bootstrap_state_kind: BootstrapStateKind::SnapshotArchive,
            bootstrap_slot: 416_012,
            bootstrap_state_hash: Hash::new_from_array([9; 32]),
            requested_slot_start: first,
            requested_slot_count: 13,
            transaction_metadata: TransactionMetadataPolicy::observed(),
        },
        worker_executable_sha256: [0x42; 32],
    });
    let mut writer = ArchiveWriter::new_with_provenance(
        Vec::new(),
        1,
        first,
        13,
        ArchiveWriterConfig {
            bucket_slots: 4,
            ..Default::default()
        },
        &p,
    )?;
    writer.preserve_initial_poh_anchor(first, anchor)?;
    let mut predecessor = anchor;
    for offset in 0..12 {
        let slot = first + offset;
        if offset < 2 {
            writer.write_skipped_slot(slot)?;
            continue;
        }
        writer.begin_slot(slot)?;
        if offset == 2 {
            let mut epoch = EpochMeta::new_boxed();
            epoch.epoch = 1;
            epoch.start_slot = first;
            epoch.slot_count = 13;
            epoch.first_block_slot = slot;
            writer.write_epoch_meta(&epoch)?;
        }
        let mut b = BlockMeta::new_boxed();
        b.slot = slot;
        b.parent_slot = if offset == 2 { first - 1 } else { slot - 1 };
        b.parent_blockhash = predecessor;
        b.blockhash = Hash::new_from_array([offset as u8; 32]);
        b.entry_count = 1;
        writer.end_slot(
            &b,
            &[EntryRecord {
                num_hashes: 1,
                tx_count: 0,
            }],
        )?;
        predecessor = b.blockhash;
    }
    let (index_view, _) = writer.finish()?;
    let terminal = Hash::new_from_array([4; 32]);
    let (encoded, stats) = convert(
        Cursor::new(&index_view),
        Vec::new(),
        12,
        5,
        terminal,
        1 << 20,
    )?;
    check(
        stats.slots_reencoded == 5
            && stats.source_buckets == 2
            && stats.source_semantic_sha256 != stats.output_semantic_sha256
            && encoded.bytes == encoded.sink.len() as u64,
        "fixture did not cut a complete physical bucket",
    )?;
    let p = reread(Cursor::new(&encoded.sink), 1, first, 5, &stats)?;
    check(
        p.worker_executable_sha256 == [0x42; 32],
        "fixture worker provenance changed",
    )?;
    check(
        convert(Cursor::new(&index_view), Vec::new(), 12, 5, anchor, 1 << 20).is_err()
            && convert(
                Cursor::new(&index_view),
                Vec::new(),
                11,
                5,
                terminal,
                1 << 20,
            )
            .is_err()
            && convert(Cursor::new(&index_view), Vec::new(), 12, 5, terminal, 8).is_err(),
        "fixture accepted a foreign root, extent or output-cap overflow",
    )?;
    println!(
        "{{\"fixture_selected_slots\":5,\"fixture_retained_slots\":12,\"fixture_declared_slots\":13,\"native_cut_inside_bucket\":true,\"independent_output_reread\":true,\"wrong_terminal_rejected\":true,\"wrong_extent_rejected\":true,\"output_cap_rejected\":true,\"fixture_output_bytes\":{}}}",
        encoded.bytes
    );
    Ok(())
}

fn private_output_dir(path: &Path) -> Result<File> {
    let m = path.symlink_metadata()?;
    check(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 1000
            && m.gid() == 1000
            && m.permissions().mode() & 0o777 == 0o700
            && std::fs::read_dir(path)?.next().is_none(),
        "output directory must be the empty owned private directory",
    )?;
    Ok(File::open(path)?)
}

fn preflight(file: &File, tail: &[u8]) -> Result<()> {
    check(
        tail.len() == 1410 && hex(&Sha256::digest(tail)) == TRAILER_SHA,
        "indexed trailer differs from the qualified source",
    )?;
    original_view::verify_trailer(file, tail)?;
    let mut r = ArchiveReader::open(original_view::open(file, tail)?)?;
    let header = r.header();
    check(
        header.epoch == 266
            && header.slot_start == FIRST
            && header.slot_count == 432_000
            && r.bucket_count() == 90
            && !r.has_complete_slot_coverage()?,
        "indexed source container scope changed",
    )?;
    let Some(ArchiveProvenance::V2(p)) = r.provenance()? else {
        return Err("source does not carry recognized uninterrupted V2 provenance".into());
    };
    check(
        p.base.bootstrap_slot == BOOTSTRAP_SLOT
            && p.base.bootstrap_state_hash.to_string() == BOOTSTRAP_HASH
            && p.base.runtime_profile == "solana-v1.8.11"
            && hex(&p.worker_executable_sha256) == WORKER_SHA,
        "V2 runtime or pinned input differs",
    )?;
    r.verify_chain = true;
    let got = r.read_bucket_prefix_with_header(0, 1, &mut SemanticDigest::new(), |bucket, _| {
        if bucket.poh_start_hash.to_string() != FIRST_PARENT {
            return Err(
                jetstreamer_horizon::archive::ArchiveFormatError::InvalidContainerLayout(
                    "initial anchor differs",
                ),
            );
        }
        Ok(())
    })?;
    check(got == 1, "native initial frame is missing")?;
    Ok(())
}

fn hash_file(file: &File) -> Result<String> {
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut hash = Sha256::new();
    io::copy(&mut reader, &mut hash)?;
    Ok(format!("{:x}", hash.finalize()))
}

fn full_conversion(
    source: &File,
    path: &Path,
    tail: &[u8],
    dir: &Path,
    dir_fd: File,
    admission: &Path,
    trailer: &Path,
) -> Result<()> {
    let booking = Reservation::enter(admission, path, trailer, dir, &dir_fd)?;
    preflight(source, tail)?;
    check(
        original_view::rehash(source, tail)? == VIEW_SHA,
        "qualified input view changed",
    )?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".partial-epoch266-prefix-")
        .tempfile_in(dir)?;
    let (output, stats) = convert(
        original_view::open(source, tail)?,
        ReservedWriter::new(temporary.as_file_mut(), &booking)?,
        RETAINED,
        SELECTED,
        END_HASH.parse()?,
        OUTPUT_CAP,
    )?;
    check(
        stats.slots_reencoded == SELECTED
            && stats.source_epoch == 266
            && stats.source_buckets == 90
            && hex(&stats.source_semantic_sha256) == SOURCE_SEMANTIC
            && output.bytes == stats.output.bytes_written,
        "native reencoder source semantics or output length changed",
    )?;
    let output_size = output.bytes;
    temporary.as_file().sync_all()?;
    booking.check_file(temporary.as_file())?;
    let p = reread(temporary.reopen()?, 266, FIRST, SELECTED, &stats)?;
    check(
        hex(&p.worker_executable_sha256) == WORKER_SHA,
        "output worker provenance differs",
    )?;
    let output_sha = hash_file(&temporary.reopen()?)?;
    check(
        original_view::rehash(source, tail)? == VIEW_SHA,
        "physical source changed during conversion",
    )?;
    original_view::pinned_source(source, path)?;
    booking.check_file(temporary.as_file())?;
    let destination = dir.join(OUTPUT_NAME);
    let persisted = temporary.persist_noclobber(&destination)?;
    persisted.sync_all()?;
    dir_fd.sync_all()?;
    let file = persisted.metadata()?;
    let current = destination.symlink_metadata()?;
    check(
        file.dev() == current.dev()
            && file.ino() == current.ino()
            && file.nlink() == 1
            && file.len() == output_size
            && file.permissions().mode() & 0o777 == 0o600,
        "persisted output inode or length changed",
    )?;
    println!(
        "{{\"epoch\":266,\"first_slot\":{FIRST},\"selected_slots\":{SELECTED},\"output_bytes\":{output_size},\"output_sha256\":\"{output_sha}\",\"output_semantic_sha256\":\"{}\",\"source_semantic_sha256\":\"{SOURCE_SEMANTIC}\",\"physical_source_sha256\":\"{RAW_SHA}\",\"indexed_view_sha256\":\"{VIEW_SHA}\",\"full_poh_recomputed\":false,\"native_checkpoint_tuple_qualified\":false,\"publication_authorized\":false}}",
        hex(&stats.output_semantic_sha256)
    );
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "fixture" {
        return fixture();
    }
    check(
        matches!(args.first().and_then(|mode| mode.to_str()), Some("preflight") if args.len() == 4)
            || matches!(args.first().and_then(|mode| mode.to_str()), Some("convert") if args.len() == 5),
        "usage: dense-prefix preflight RAW_ARCHIVE TRAILER OUTPUT_DIR | dense-prefix convert RAW_ARCHIVE TRAILER OUTPUT_DIR ADMISSION",
    )?;
    let path = Path::new(&args[1]);
    let dir = Path::new(&args[3]);
    let dir_fd = private_output_dir(dir)?;
    let file = File::open(path)?;
    original_view::pinned_source(&file, path)?;
    let trailer = Path::new(&args[2]);
    check(
        trailer.symlink_metadata()?.is_file() && trailer.metadata()?.len() == 1410,
        "foreign trailer size or type",
    )?;
    let tail = std::fs::read(trailer)?;
    original_view::pinned_source(&file, path)?;
    match args[0].to_str() {
        Some("preflight") => {
            preflight(&file, &tail)?;
            println!(
                "{{\"epoch\":266,\"first_slot\":{FIRST},\"last_slot\":114923430,\"retained_slots\":{RETAINED},\"selected_slots\":{SELECTED},\"trailer_sha256\":\"{TRAILER_SHA}\",\"indexed_view_sha256\":\"{VIEW_SHA}\",\"verified_source_semantic_sha256\":\"{SOURCE_SEMANTIC}\",\"output_bytes_cap\":{OUTPUT_CAP},\"working_root_bytes_cap\":{ROOT_CAP},\"proposed_memory_cap_bytes\":{MEMORY_CAP},\"full_conversion_started\":false,\"output_created\":false}}"
            );
            Ok(())
        }
        Some("convert") => full_conversion(
            &file,
            path,
            &tail,
            dir,
            dir_fd,
            Path::new(&args[4]),
            trailer,
        ),
        _ => Err("unknown mode".into()),
    }
}
