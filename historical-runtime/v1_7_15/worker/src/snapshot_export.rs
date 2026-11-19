//! Candidate checkpoint export. Native bank serialization, in-process sparse tar,
//! and no-clobber publication; no external packager or archive-retention cleanup.
use bzip2::{write::BzEncoder, Compression};
use jetstreamer_historical_protocol::{Checkpoint, SnapshotExport};
use sha2::{Digest, Sha256};
use solana_runtime::{
    append_vec::AppendVec,
    bank::Bank,
    snapshot_utils::{self, SnapshotVersion},
};
use solana_sdk::hash::Hash;
use std::{
    collections::HashSet,
    fs::{self, File},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};
use tar::{Builder as TarBuilder, EntryType, Header};
use tempfile::Builder;

pub fn check_bank(bank: &Bank, checkpoint: &Checkpoint) -> Result<(), String> {
    if !bank.is_frozen()
        || bank.parent().is_some()
        || !bank.is_complete()
        || !checkpoint.slot_complete
        || bank.slot() != checkpoint.slot
        || bank.hash().as_ref() != checkpoint.bank_hash.as_slice()
        || bank.get_accounts_hash().as_ref() != checkpoint.accounts_hash.as_slice()
        || bank.last_blockhash().as_ref() != checkpoint.last_blockhash.as_slice()
        || bank.capitalization() != checkpoint.capitalization
        || bank.transaction_count() != checkpoint.transaction_count
        || bank.tick_height() != checkpoint.tick_height
        || bank.accounts().accounts_db.next_write_version() != checkpoint.next_write_version
    {
        return Err("snapshot export bank differs from the complete frozen checkpoint".into());
    }
    Ok(())
}

pub fn export_archive(
    bank: &Bank,
    checkpoint: &Checkpoint,
    output_directory: &Path,
) -> Result<SnapshotExport, String> {
    check_bank(bank, checkpoint)?;
    let canonical = fs::canonicalize(output_directory).map_err(error)?;
    let metadata = fs::symlink_metadata(output_directory).map_err(error)?;
    if !output_directory.is_absolute()
        || canonical != output_directory
        || !metadata.is_dir()
        || metadata.mode() & 0o077 != 0
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err("snapshot output must be a canonical, owned private directory".into());
    }
    let final_path = output_directory.join(format!(
        "snapshot-{}-{}.tar.bz2",
        checkpoint.slot,
        Hash::new(&checkpoint.accounts_hash)
    ));
    match fs::symlink_metadata(&final_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        _ => return Err("refusing to replace existing or inaccessible snapshot archive".into()),
    }

    // Match v1.7.15 bank_to_snapshot_archive's storage housekeeping, then
    // compare against the checkpoint captured BEFORE those mutations.
    bank.force_flush_accounts_cache();
    bank.clean_accounts(true, false);
    bank.update_accounts_hash();
    bank.rehash();
    check_bank(bank, checkpoint)?;
    let storages = bank.get_snapshot_storages();
    let staging = Builder::new()
        .prefix("checkpoint-staging-")
        .tempdir_in(output_directory)
        .map_err(error)?;
    let snapshots = staging.path().join("snapshots");
    fs::create_dir(&snapshots).map_err(error)?;
    snapshot_utils::add_snapshot(&snapshots, bank, &storages, SnapshotVersion::V1_2_0)
        .map_err(error)?;
    let roots = bank.src.roots();
    if !roots.contains(&checkpoint.slot) || roots.iter().any(|slot| *slot > checkpoint.slot) {
        return Err("snapshot status-cache roots do not end at the checkpoint".into());
    }
    let deltas = bank.src.slot_deltas(&roots);
    snapshot_utils::serialize_snapshot_data_file(&snapshots.join("status_cache"), |writer| {
        bincode::serialize_into(writer, &deltas)?;
        Ok(())
    })
    .map_err(error)?;
    let version = staging.path().join("version");
    fs::write(&version, b"1.2.0").map_err(error)?;

    let archive = Builder::new()
        .prefix("checkpoint-archive-")
        .suffix(".partial")
        .tempfile_in(output_directory)
        .map_err(error)?;
    let mut tar = TarBuilder::new(BzEncoder::new(
        BufWriter::new(archive.reopen().map_err(error)?),
        Compression::Best,
    ));
    tar.append_dir("accounts", staging.path()).map_err(error)?;
    let mut names = HashSet::new();
    for storage in storages.iter().flatten() {
        storage.flush().map_err(error)?;
        let source = storage.get_path();
        let name = AppendVec::file_name(storage.slot(), storage.append_vec_id());
        if !names.insert(name.clone()) || names.len() > 524_280 {
            return Err("duplicate or excessive snapshot storage entries".into());
        }
        let (written, capacity) = storage.snapshot_file_layout();
        if capacity > 16 * 1024 * 1024 * 1024 {
            return Err("snapshot storage exceeds loader size limit".into());
        }
        append_sparse_append_vec(
            &mut tar,
            &Path::new("accounts").join(name),
            &source,
            written as u64,
            capacity,
        )
        .map_err(error)?;
    }
    tar.append_dir_all("snapshots", &snapshots).map_err(error)?;
    tar.append_path_with_name(&version, "version")
        .map_err(error)?;
    let encoder = tar.into_inner().map_err(error)?;
    let mut writer = encoder.finish().map_err(error)?;
    writer.flush().map_err(error)?;
    writer.get_ref().sync_all().map_err(error)?;
    drop(writer);

    // Hash and verify the staged bytes before the final pathname becomes visible.
    let mut file = archive.reopen().map_err(error)?;
    let archive_size = file.metadata().map_err(error)?.len();
    if archive_size == 0 {
        return Err("snapshot archive is empty".into());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    let mut hashed = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(error)?;
        if n == 0 {
            break;
        }
        hasher.input(&buffer[..n]);
        hashed = hashed
            .checked_add(n as u64)
            .ok_or("snapshot size overflow")?;
    }
    if hashed != archive_size || file.metadata().map_err(error)?.len() != archive_size {
        return Err("snapshot archive changed while hashing".into());
    }
    check_bank(bank, checkpoint)?;
    let archive_path = final_path
        .to_str()
        .ok_or("snapshot path is not UTF-8")?
        .to_owned();
    file.set_permissions(fs::Permissions::from_mode(0o400))
        .map_err(error)?;
    file.sync_all().map_err(error)?;
    archive.persist_noclobber(&final_path).map_err(error)?;
    File::open(output_directory)
        .and_then(|d| d.sync_all())
        .map_err(error)?;
    Ok(SnapshotExport {
        slot: checkpoint.slot,
        archive_path,
        accounts_hash: checkpoint.accounts_hash.clone(),
        archive_size,
        archive_sha256: hasher.result().to_vec(),
    })
}

fn error(e: impl std::fmt::Display) -> String {
    format!("snapshot export failed: {}", e)
}

/// Append an AppendVec without materializing its unwritten fixed-capacity
/// tail.  GNU sparse records describe the written prefix and a single byte at
/// the logical end of the file.  The latter preserves the original mapped file
/// length; rounding the prefix to a tar block boundary keeps multiple sparse
/// extents valid for the old tar reader used by this runtime.
fn append_sparse_append_vec<W: Write>(
    tar: &mut TarBuilder<W>,
    archive_path: &Path,
    source_path: &Path,
    written_len: u64,
    file_len: u64,
) -> io::Result<()> {
    if file_len == 0 || written_len > file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid AppendVec layout: written {}, file {}",
                written_len, file_len
            ),
        ));
    }
    let file = File::open(source_path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != file_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AppendVec file metadata does not match the captured layout",
        ));
    }

    let prefix_len = written_len
        .checked_add(511)
        .map(|length| length / 512 * 512)
        .unwrap_or(file_len)
        .min(file_len);
    if prefix_len == file_len {
        let mut header = Header::new_gnu();
        header.set_metadata(&metadata);
        header.set_size(file_len);
        header.set_cksum();
        return tar.append_data(&mut header, archive_path, file.take(file_len));
    }

    let mut extents = Vec::with_capacity(2);
    if prefix_len != 0 {
        extents.push((0, prefix_len));
    }
    // AppendVec::new writes this byte when it creates the fixed-size mmap, so
    // reading it is both cheap and an exact representation of the source.
    extents.push((file_len - 1, 1));
    let archived_size = prefix_len + 1;

    let mut header = Header::new_gnu();
    header.set_metadata(&metadata);
    header.set_entry_type(EntryType::GNUSparse);
    header.set_size(archived_size);
    let gnu = header
        .as_gnu_mut()
        .expect("Header::new_gnu must produce a GNU header");
    write_octal(&mut gnu.realsize, file_len)?;
    gnu.isextended[0] = 0;
    for (sparse, &(offset, length)) in gnu.sparse.iter_mut().zip(&extents) {
        write_octal(&mut sparse.offset, offset)?;
        write_octal(&mut sparse.numbytes, length)?;
    }
    header.set_cksum();
    tar.append_data(
        &mut header,
        archive_path,
        FileExtentsReader::new(file, extents),
    )
}

fn write_octal(field: &mut [u8], value: u64) -> io::Result<()> {
    let encoded = format!("{:o}", value);
    if encoded.len() + 1 > field.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value does not fit GNU tar numeric field",
        ));
    }
    for byte in field.iter_mut() {
        *byte = b'0';
    }
    let start = field.len() - encoded.len() - 1;
    field[start..start + encoded.len()].copy_from_slice(encoded.as_bytes());
    field[field.len() - 1] = 0;
    Ok(())
}

struct FileExtentsReader {
    file: File,
    extents: Vec<(u64, u64)>,
    next_extent: usize,
    remaining: u64,
}

impl FileExtentsReader {
    fn new(file: File, extents: Vec<(u64, u64)>) -> Self {
        Self {
            file,
            extents,
            next_extent: 0,
            remaining: 0,
        }
    }
}

impl Read for FileExtentsReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let &(offset, length) = match self.extents.get(self.next_extent) {
                Some(extent) => extent,
                None => return Ok(0),
            };
            self.next_extent += 1;
            self.file.seek(SeekFrom::Start(offset))?;
            self.remaining = length;
        }
        let maximum = std::cmp::min(self.remaining, buffer.len() as u64) as usize;
        let read = self.file.read(&mut buffer[..maximum])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "AppendVec changed while its snapshot was being archived",
            ));
        }
        self.remaining -= read as u64;
        Ok(read)
    }
}
