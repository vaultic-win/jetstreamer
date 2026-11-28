//! Verify or materialize Anza's private first epoch 162 segment with the stock
//! epoch-boundary reward order. The virtual reader also supplies the bytes
//! written to disk, so verification needs no archive-sized scratch.
use anyhow::{Context, Result, bail, ensure};
use jetstreamer_horizon::archive::{
    ArchiveProvenance, ArchiveReader, BucketIndexEntry, FOOTER_LEN, Footer, MAGIC,
    encode_archive_provenance, parse_file_header,
};
use jetstreamer_node::{
    archive_checksum::{
        ArchiveFileIdentity, archive_file_identity, measure_open_archive, open_regular_nofollow,
        path_matches_archive_identity,
    },
    segment_manifest::{
        HistoricalSegmentManifest, SegmentManifestError,
        read_and_validate_seekable_segment_manifest, sha256_hex_string,
    },
};
use lencode::Encode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::CString,
    fs::{self, File},
    io::{self, BufReader, Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};
use tempfile::Builder;
use xxhash_rust::xxh64::xxh64;

const PRIVATE: &str = "/home/sol/.jetstreamer-private";
const STOCK: &str = "/home/sol/.jetstreamer-private/epoch162-first-hourly-20261127-v1/ledger/epoch-162.diagnostic.jet";
const CAPPED: &str = "/home/sol/.jetstreamer-private/epoch162-first-hourly-completion-20261127-v2/ledger/epoch-162.diagnostic.jet";
const QUAL: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch162-first-hourly-completion-20261127-v2/SPLIT162_STOCK_ORDER_WRITER_QUALIFICATION.json";
const END_BANK: &str = "/home/sol/.jetstreamer-private/epoch162-v156-capped-shrink-20261127.v1/checkpoint-v1/TERMINAL_BANK_WITNESS.json";
const STOCK_HASH: &str = "d60611775200eccdc64357ee0928b0ae99321f31c665f310f42791afe9bf6f8f";
const CAPPED_HASH: &str = "889a4c3e4e54adc5c3ff54877eb9e4a3d52937f315b540ed5233e9f07de55cfc";
const MANIFEST_HASH: &str = "54d8f9373f46ecb99ca2098dee12749803d89bfeb26c9237f8dc1410d4574b03";
const QUAL_HASH: &str = "f7a441d900fbdd502e5a662b95fe38b0e218f512fb65134d74b4c9784a000a1f";
const BANK_HASH: &str = "6089633fc4f78a962c89a28fd738c076e1aa8621ec81f766c22a09b2c8a3d792";
const CAPPED_WORKER: &str = "79179ca07a537c0f63f7f5012e24b0f66092d7853852ea50d67cb3f03b7ab691";
const STOCK_WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const STOCK_EXPANDED: &str = "076d522c7eeff54b81fdfc2fe0abf674ff0fe2e714d2b4864d73d9232b36cdec";
const FIRST: u64 = 69_984_000;
const COUNT: u64 = 7077;
const NAME: &str = "epoch-162-through-69991076.jet";

fn bytes(value: impl AsRef<[u8]>) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn bound_json(path: &Path, digest: &str) -> Result<Vec<u8>> {
    let source = open_regular_nofollow(path)?;
    let mut raw = Vec::new();
    source.take((1 << 20) + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= 1 << 20 && bytes(&raw) == digest,
        "different input {}",
        path.display()
    );
    Ok(raw)
}

struct Input {
    path: PathBuf,
    file: File,
    identity: ArchiveFileIdentity,
}

impl Input {
    fn open(path: impl Into<PathBuf>, size: u64, digest: &str) -> Result<Self> {
        let path = path.into();
        let file = open_regular_nofollow(&path)?;
        ensure!(
            file.metadata()?.len() == size,
            "different length for {}",
            path.display()
        );
        let proof = measure_open_archive(&file)?;
        ensure!(
            sha256_hex_string(&proof.sha256) == digest,
            "different bytes for {}",
            path.display()
        );
        let input = Self {
            path,
            file,
            identity: proof.identity,
        };
        input.recheck()?;
        Ok(input)
    }

    fn recheck(&self) -> Result<()> {
        ensure!(
            archive_file_identity(&self.file)? == self.identity
                && path_matches_archive_identity(&self.path, self.identity)?,
            "source changed {}",
            self.path.display()
        );
        Ok(())
    }
}

// Reads are positional so independent native verifier handles can seek freely.
enum Piece<'a> {
    Memory(Vec<u8>),
    File {
        file: &'a File,
        offset: u64,
        len: u64,
    },
}

impl Piece<'_> {
    fn len(&self) -> u64 {
        match self {
            Self::Memory(data) => data.len() as u64,
            Self::File { len, .. } => *len,
        }
    }
}

struct Stream<'a> {
    pieces: &'a [Piece<'a>],
    len: u64,
    pos: u64,
}

impl<'a> Stream<'a> {
    fn new(pieces: &'a [Piece<'a>]) -> Self {
        Self {
            pieces,
            len: pieces.iter().map(Piece::len).sum(),
            pos: 0,
        }
    }
}

impl Read for Stream<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let mut offset = self.pos;
        for part in self.pieces {
            if offset >= part.len() {
                offset -= part.len();
                continue;
            }
            let n = (part.len() - offset).min(buf.len() as u64) as usize;
            let received = match part {
                Piece::Memory(data) => (&data[offset as usize..]).read(&mut buf[..n])?,
                Piece::File {
                    file, offset: base, ..
                } => file.read_at(&mut buf[..n], base + offset)?,
            };
            if received == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.pos += received as u64;
            return Ok(received);
        }
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

impl Seek for Stream<'_> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(pos) => Some(pos),
            SeekFrom::End(delta) => self.len.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.pos.checked_add_signed(delta),
        }
        .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(self.pos)
    }
}

fn layout<'a>(
    stock: &'a Input,
    capped: &'a Input,
    manifest: &mut HistoricalSegmentManifest,
) -> Result<Vec<Piece<'a>>> {
    let mut stock_prefix = [0; 4096];
    stock.file.read_exact_at(&mut stock_prefix, 0)?;
    let (stock_header, stock_start) = parse_file_header(&stock_prefix)?;
    let mut reader = ArchiveReader::open(BufReader::new(&capped.file))?;
    ensure!(
        reader.has_complete_slot_coverage()?
            && reader.bucket_count() == COUNT.div_ceil(128) as usize
    );
    let mut fh = reader.header().clone();
    ensure!(
        (
            fh.format_version,
            fh.epoch,
            fh.slot_start,
            fh.slot_count,
            fh.bucket_slots
        ) == (2, 162, FIRST, COUNT, 128)
            && (
                stock_header.format_version,
                stock_header.epoch,
                stock_header.slot_start,
                stock_header.slot_count,
                stock_header.bucket_slots
            ) == (2, 162, FIRST, COUNT, 128)
            && stock_header.flags == fh.flags
            && stock_header.prime_table_id == fh.prime_table_id
    );
    let Some(ArchiveProvenance::V2(stock_prov)) = stock_header.meta.provenance()? else {
        bail!("stock provenance missing");
    };
    let Some(ArchiveProvenance::V2(mut provenance)) = reader.provenance()? else {
        bail!("capped provenance missing");
    };
    ensure!(
        stock_prov.base == provenance.base
            && sha256_hex_string(&stock_prov.worker_executable_sha256) == STOCK_WORKER
            && sha256_hex_string(&provenance.worker_executable_sha256) == CAPPED_WORKER
            && provenance.worker_executable_sha256 == manifest.worker_executable_sha256
            && manifest.runtime.generation_profile == provenance.base.generation_profile
    );
    // The capped worker replayed the complete interval. The qualified stock
    // frame supplies the exact already-proven reward order for its first bucket.
    let profile = format!(
        "jetstreamer/epoch162-stock-reward-order-v1/stock={STOCK_HASH}/capped={CAPPED_HASH}/manifest={MANIFEST_HASH}/qualification={QUAL_HASH}/terminal={BANK_HASH}"
    );
    manifest.runtime.generation_profile = profile.clone();
    provenance.base.generation_profile = profile;
    fh.meta.reserved = encode_archive_provenance(&ArchiveProvenance::V2(provenance))?;
    fh.meta.writer_version = b"epoch162-stock-order-v1".to_vec();
    let mut encoded = Vec::new();
    fh.encode_ext(&mut encoded, None)?;
    let mut header = MAGIC.to_vec();
    (encoded.len() as u64).encode_ext(&mut header, None)?;
    header.extend(encoded);

    let index = reader.bucket_index();
    let stock_frame = stock.file.metadata()?.len() - stock_start as u64;
    ensure!(
        stock_start == 391
            && stock_frame == 32_145_540
            && index[0].offset == 391
            && index[0].len == 32_147_033
            && index[1].offset == 32_147_424
            && index[0].first_slot == FIRST
            && index[1].first_slot == FIRST + 128
    );
    let last = index.last().context("empty segment index")?;
    let capped_tail = last.offset + last.len - index[1].offset;
    let mut offset = header.len() as u64;
    let mut trailer = Vec::new();
    (index.len() as u64).encode_ext(&mut trailer, None)?;
    for (i, old) in index.iter().enumerate() {
        let len = if i == 0 { stock_frame } else { old.len };
        BucketIndexEntry {
            first_slot: old.first_slot,
            offset,
            len,
        }
        .encode_ext(&mut trailer, None)?;
        offset = offset.checked_add(len).context("derived index overflows")?;
    }
    let footer = Footer {
        index_offset: offset,
        index_len: trailer.len() as u64,
        bucket_count: index.len() as u64,
        index_xxh64: xxh64(&trailer, 0),
    };
    ensure!(footer.to_bytes().len() == FOOTER_LEN);
    trailer.extend(footer.to_bytes());
    Ok(vec![
        Piece::Memory(header),
        Piece::File {
            file: &stock.file,
            offset: stock_start as u64,
            len: stock_frame,
        },
        Piece::File {
            file: &capped.file,
            offset: index[1].offset,
            len: capped_tail,
        },
        Piece::Memory(trailer),
    ])
}

fn compare_terminal(manifest: &HistoricalSegmentManifest, witness: &Value) -> Result<()> {
    let bank = &witness["bank"];
    let observed = serde_json::to_value(&manifest.terminal)?;
    for key in [
        "slot",
        "bank_hash",
        "last_blockhash",
        "capitalization",
        "transaction_count",
        "tick_height",
        "slot_complete",
    ] {
        ensure!(
            !observed[key].is_null() && observed[key] == bank[key],
            "terminal witness mismatch in {key}"
        );
    }
    ensure!(
        observed["accounts_hash"] == witness["canonical_accounts_hash_from_snapshot_identity"]
            && observed["slot"] == FIRST + COUNT - 1
            && observed["slot_complete"] == true
            && manifest.emitted_raw_write_versions.end == manifest.terminal.next_write_version
    );
    Ok(())
}

fn copy(
    src: &mut impl Read,
    mut output: impl Write,
    mut check: impl FnMut(u64) -> Result<()>,
) -> Result<([u8; 32], u64)> {
    let mut buf = vec![0; 1 << 20];
    let mut hasher = Sha256::new();
    let mut total = 0;
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        check(n as u64)?;
        output.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hasher.finalize().into(), total))
}

fn check_floor(dir: &File, bytes: u64, floor: u64) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::fstatvfs(dir.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.f_bavail
            .saturating_mul(stat.f_frsize)
            .saturating_sub(bytes)
            >= floor,
        "admitted HOME floor"
    );
    Ok(())
}

fn synced_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = File::create_new(path)?;
    f.write_all(data)?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    Ok(())
}

fn rename_new(from: &Path, to: &Path) -> Result<()> {
    let source = CString::new(from.as_os_str().as_bytes())?;
    let destination = CString::new(to.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

struct Output {
    dir: PathBuf,
    max: u64,
    floor: u64,
}

fn derive(output: Option<Output>) -> Result<Value> {
    let qualification: Value = serde_json::from_slice(&bound_json(Path::new(QUAL), QUAL_HASH)?)?;
    let diagnostic = &qualification["first_slot_writer_qualification"]["diagnostic"];
    ensure!(
        diagnostic["candidate_with_stock_reward_positions"] == diagnostic["stock_reencoded"]
            && diagnostic["stock_reencoded"]["encoded_slot_stream_sha256"] == STOCK_EXPANDED
            && diagnostic["stock_reencoded"]["slots"] == 128
            && diagnostic["mutated_candidate_content_rejected"] == true
            && diagnostic["mutated_candidate_source_version_rejected"] == true
    );
    let witness: Value = serde_json::from_slice(&bound_json(Path::new(END_BANK), BANK_HASH)?)?;
    let stock = Input::open(STOCK, 32_145_931, STOCK_HASH)?;
    let capped = Input::open(CAPPED, 1_787_238_028, CAPPED_HASH)?;
    let manifest_path = PathBuf::from(format!("{CAPPED}.segment.json"));
    let mut manifest: HistoricalSegmentManifest =
        serde_json::from_slice(&bound_json(&manifest_path, MANIFEST_HASH)?)?;
    manifest.validate()?;
    ensure!(
        manifest.epoch == 162
            && manifest.output_slot_start == FIRST
            && manifest.output_slot_count == COUNT
            && sha256_hex_string(&manifest.archive_sha256) == CAPPED_HASH
    );
    compare_terminal(&manifest, &witness)?;
    let pieces = layout(&stock, &capped, &mut manifest)?;
    let mut reader = Stream::new(&pieces);
    let length = reader.len;
    let (hash, read) = copy(&mut reader, io::sink(), |_| Ok(()))?;
    ensure!(read == length);
    manifest.archive_sha256 = hash;
    let typed_bytes = serde_json::to_vec_pretty(&manifest)?;
    // The shared validator authenticates the bytes again, walks every bucket
    // with a single decoder, and verifies all slots, raw cursors and PoH links.
    let tmp = Builder::new().prefix("epoch162-manifest-").tempdir()?;
    let typed_path = tmp.path().join("segment.json");
    synced_file(&typed_path, &typed_bytes)?;
    let verified = read_and_validate_seekable_segment_manifest(
        Path::new(NAME),
        &typed_path,
        NonZeroUsize::MIN,
        || Ok(Stream::new(&pieces)),
        || {
            stock.recheck().and_then(|_| capped.recheck()).map_err(|e| {
                SegmentManifestError::Invalid(format!("changed derivation source: {e}"))
            })
        },
    )?;
    ensure!(verified == manifest);
    let receipt = json!({
        "schema":"horizon-private-162-stock-reward-order-verified-segment-v1",
        "derivation":"New V2 provenance, exact stock first frame, unchanged capped frames 2 through 56, regenerated index and footer",
        "source_capped_archive":{"path":CAPPED,"sha256":CAPPED_HASH,"producer_invocation":"e08ac6700a714ea0bf2d08a40516fc7e",
                                 "worker_sha256":CAPPED_WORKER,"first_retained_slot":FIRST+128,"first_retained_offset":32_147_424},
        "source_stock_frame":{"path":STOCK,"sha256":STOCK_HASH,"worker_sha256":STOCK_WORKER,"first_slot":FIRST,"slots":128,
                              "offset":391,"length":32_145_540,"expanded_sha256":STOCK_EXPANDED},
        "source_manifest":{"path":manifest_path,"sha256":MANIFEST_HASH}, "qualification":{"path":QUAL,"sha256":QUAL_HASH},
        "original_rejection":qualification["original_strict_rejection"],
        "terminal_witness":{"path":END_BANK,"sha256":BANK_HASH}, "derived_manifest":manifest,
        "derived_manifest_sha256":bytes(&typed_bytes), "derived_archive_sha256":sha256_hex_string(&hash),
        "derived_size":length, "verified_slot_count":COUNT, "native_segment_validation_workers":1,
        "materialized":output.is_some(), "canonical_publication":false
    });
    if let Some(out) = output {
        let parent = out.dir.parent().context("private output parent missing")?;
        ensure!(
            parent.canonicalize()? == parent
                && parent.starts_with(PRIVATE)
                && fs::symlink_metadata(parent)?.mode() & 0o077 == 0
                && fs::metadata(parent)?.uid() == unsafe { libc::geteuid() }
                && fs::metadata(parent)?.dev() == fs::metadata(PRIVATE)?.dev(),
            "output parent must be an owned private directory on HOME"
        );
        let parent_fd = File::open(parent)?;
        // Exclusively charge one staging copy in this admission directory,
        // also when a caller retries before learning that rename succeeded.
        parent_fd
            .try_lock()
            .context("another materialization owns this private directory")?;
        ensure!(out.dir.file_name().is_some() && out.max >= length + (64 << 10) && out.floor > 0);
        let receipt_bytes = serde_json::to_vec_pretty(&receipt)?;
        match fs::symlink_metadata(&out.dir) {
            Ok(meta) => {
                ensure!(
                    meta.file_type().is_dir()
                        && meta.uid() == unsafe { libc::geteuid() }
                        && meta.mode() & 0o077 == 0,
                    "existing destination must be an owned private directory"
                );
                let disk = Input::open(out.dir.join(NAME), length, &sha256_hex_string(&hash))?;
                bound_json(
                    &out.dir.join(format!("{NAME}.segment.json")),
                    &bytes(&typed_bytes),
                )?;
                bound_json(&out.dir.join("derivation.json"), &bytes(&receipt_bytes))?;
                disk.recheck()?;
                parent_fd.sync_all()?;
                return Ok(receipt);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        check_floor(&parent_fd, length + (64 << 10), out.floor)?;
        let txn = Builder::new()
            .prefix(".epoch162-partial-")
            .tempdir_in(parent)?;
        let archive_path = txn.path().join(NAME);
        let mut target = File::create_new(&archive_path)?;
        let (written, n) = copy(&mut Stream::new(&pieces), &mut target, |n| {
            check_floor(&parent_fd, n + (64 << 10), out.floor)
        })?;
        ensure!(written == hash && n == length);
        target.set_permissions(fs::Permissions::from_mode(0o400))?;
        target.sync_all()?;
        let disk = measure_open_archive(&open_regular_nofollow(&archive_path)?)?;
        ensure!(
            disk.sha256 == hash && path_matches_archive_identity(&archive_path, disk.identity)?
        );
        stock.recheck()?;
        capped.recheck()?;
        synced_file(
            &txn.path().join(format!("{NAME}.segment.json")),
            &typed_bytes,
        )?;
        synced_file(&txn.path().join("derivation.json"), &receipt_bytes)?;
        File::open(txn.path())?.sync_all()?;
        rename_new(txn.path(), &out.dir)?;
        parent_fd.sync_all()?;
    }
    Ok(receipt)
}

fn main() -> Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let output = match args.as_slice() {
        [mode] if mode == "verify" => None,
        [mode, path, max, floor] if mode == "materialize" => Some(Output {
            dir: path.into(),
            max: max.to_str().context("invalid byte cap")?.parse()?,
            floor: floor.to_str().context("invalid HOME floor")?.parse()?,
        }),
        _ => bail!(
            "usage: jetstreamer-epoch162-stock-order verify | materialize PRIVATE_BUNDLE MAX_BUNDLE_BYTES MIN_FREE_BYTES"
        ),
    };
    println!("{}", serde_json::to_string(&derive(output)?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn independent_reads_cross_real_and_memory_piece_boundaries() -> Result<()> {
        let mut f = tempfile::tempfile()?;
        f.write_all(b"xxpayloadyy")?;
        let parts = [
            Piece::Memory(b"H".to_vec()),
            Piece::File {
                file: &f,
                offset: 2,
                len: 7,
            },
            Piece::Memory(b"END".to_vec()),
        ];
        let wanted = b"HpayloadEND";
        for start in 0..=wanted.len() + 1 {
            for size in 0..=wanted.len() + 1 {
                let mut got = Vec::new();
                let mut read = Stream::new(&parts);
                read.seek(SeekFrom::Start(start as u64))?;
                read.take(size as u64).read_to_end(&mut got)?;
                let mut expected = Vec::new();
                let mut oracle = Cursor::new(wanted);
                oracle.seek(SeekFrom::Start(start as u64))?;
                oracle.take(size as u64).read_to_end(&mut expected)?;
                assert_eq!(got, expected);
            }
        }
        let mut read = Stream::new(&parts);
        assert!(read.seek(SeekFrom::End(-12)).is_err());
        assert_eq!(read.seek(SeekFrom::End(-3))?, 8);
        assert!(read.seek(SeekFrom::Current(-9)).is_err());
        assert_eq!(read.stream_position()?, 8);
        Ok(())
    }
}
