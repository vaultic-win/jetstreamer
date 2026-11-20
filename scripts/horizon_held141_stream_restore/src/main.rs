//! Verify or stage the epoch 141 RocksDB collection from the held compressed stream.
//! The caller supplies the authenticated R2 bytes and admits private HOME capacity.
//! A failing stage is incomplete and never becomes the live database directory.

#[path = "../../../jetstreamer-utils/src/horizon_ledger_tar.rs"]
mod horizon_ledger_tar;

use anyhow::{Context, Result, ensure};
use bzip2::read::MultiBzDecoder;
use horizon_ledger_tar::{
    CollectionLimits, DiagnosticCollection, census_rocksdb_tar, collect_rocksdb_tar,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const RECEIPT: &str =
    "/var/lib/jetstreamer-epoch141-ledger-retention-20261020-v3/results/collection.json";
const RECEIPT_SHA: &str = "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937";
const COMPRESSED_SHA: &str = "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b";
const COMPRESSED_BYTES: u64 = 189_943_475_031;

#[derive(Deserialize)]
struct Receipt {
    census: Source,
}

#[derive(Deserialize)]
struct Source {
    compressed_sha256: String,
    compressed_bytes: u64,
    collection: DiagnosticCollection,
}

struct CountedInput<R> {
    reader: R,
    digest: Sha256,
    bytes: u64,
}

impl<R: Read> Read for CountedInput<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes = self.reader.read(buf)?;
        self.digest.update(&buf[..bytes]);
        self.bytes += bytes as u64;
        Ok(bytes)
    }
}

fn process(input: impl Read, source: &Source, stage: Option<&Path>) -> Result<()> {
    let expected = &source.collection;
    ensure!(
        source.compressed_bytes > 0 && expected.files_retained,
        "invalid collection receipt"
    );
    let limits = CollectionLimits {
        maximum_files: expected.files.len(),
        maximum_total_bytes: expected.total_bytes,
        maximum_file_bytes: expected
            .files
            .iter()
            .map(|f| f.bytes)
            .max()
            .context("empty collection")?,
        maximum_trailer_bytes: 16 << 20,
    };
    let mut counted = CountedInput {
        reader: input.take(
            source
                .compressed_bytes
                .checked_add(1)
                .context("compressed bound overflow")?,
        ),
        digest: Sha256::new(),
        bytes: 0,
    };
    let decoder = MultiBzDecoder::new(&mut counted);
    let root = Path::new(&expected.archive_root);
    let mut actual = match stage {
        Some(dir) => collect_rocksdb_tar(decoder, root, dir, limits)?,
        None => census_rocksdb_tar(decoder, root, limits)?,
    };
    ensure!(
        counted.bytes == source.compressed_bytes,
        "compressed length differs"
    );
    ensure!(
        format!("{:x}", counted.digest.finalize()) == source.compressed_sha256,
        "compressed digest differs"
    );
    // The census path hashes the same members without making a staged copy.
    actual.files_retained = expected.files_retained;
    ensure!(
        serde_json::to_value(actual)? == serde_json::to_value(expected)?,
        "member census differs"
    );
    Ok(())
}

fn validate_parent(parent: &Path) -> Result<()> {
    let home = Path::new("/home/sol");
    let private = home.join(".jetstreamer-private");
    let runtime = Path::new("/var/lib/jetstreamer/horizon_runtime_data");
    let uid = unsafe { libc::geteuid() };
    ensure!(
        parent.is_absolute()
            && parent.canonicalize()? == parent
            && (parent.starts_with(&private) || uid == 0 && parent.starts_with(runtime)),
        "expected an admitted private HOME directory"
    );
    let md = fs::symlink_metadata(parent)?;
    ensure!(
        md.is_dir()
            && md.dev() == fs::metadata(home)?.dev()
            && md.mode() & 0o077 == 0
            && md.uid() == uid,
        "unexpected staging parent custody or filesystem"
    );
    Ok(())
}

// The completed name exposes the member directory and its receipt in one
// filesystem transaction. A partial attempt can only occupy the staging name.
fn stage(input: impl Read, source: &Source, parent: &Path) -> Result<serde_json::Value> {
    let staging = parent.join("held141-restore.staging");
    let complete = parent.join("held141-restore.verified");
    ensure!(
        !complete.try_exists()?,
        "a completed restore already occupies this parent"
    );
    fs::DirBuilder::new().mode(0o700).create(&staging)?;
    File::open(parent)?.sync_all()?;
    let members = staging.join("rocksdb");
    fs::DirBuilder::new().mode(0o700).create(&members)?;
    process(input, source, Some(&members))?;
    let record = report(source, Some(complete.join("rocksdb")));
    let mut receipt = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(staging.join("COMPLETE.json"))?;
    serde_json::to_writer(&mut receipt, &record)?;
    receipt.write_all(b"\n")?;
    receipt.sync_all()?;
    File::open(&staging)?.sync_all()?;
    let from = CString::new(staging.as_os_str().as_bytes())?;
    let to = CString::new(complete.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(io::Error::last_os_error().into());
    }
    File::open(parent)?.sync_all()?;
    Ok(record)
}

fn report(source: &Source, restored: Option<PathBuf>) -> serde_json::Value {
    serde_json::json!({
        "schema":"horizon-held141-compressed-collection-v1", "epoch":141,
        "source_sha256":source.compressed_sha256, "compressed_bytes":source.compressed_bytes,
        "collection_receipt_sha256":RECEIPT_SHA, "files":source.collection.files.len(),
        "verified_member_bytes":source.collection.total_bytes,
        "restored_bytes":if restored.is_some() { source.collection.total_bytes } else { 0 },
        "staged_directory":restored, "remote_mutations":false, "local_retirement_authorized":false
    })
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let parent = match args.as_slice() {
        [mode] if mode == "--verify-stream" => None,
        [mode, dir] if mode == "--stage-in" => Some(Path::new(dir)),
        _ => anyhow::bail!("expected --verify-stream or --stage-in PRIVATE_HOME_DIRECTORY"),
    };
    let bytes = fs::read(RECEIPT)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == RECEIPT_SHA,
        "retained receipt changed"
    );
    let source = serde_json::from_slice::<Receipt>(&bytes)?.census;
    ensure!(
        source.compressed_bytes == COMPRESSED_BYTES && source.compressed_sha256 == COMPRESSED_SHA,
        "wrong holding object"
    );
    let record = if let Some(parent) = parent {
        validate_parent(parent)?;
        stage(io::stdin().lock(), &source, parent)?
    } else {
        process(io::stdin().lock(), &source, None)?;
        report(&source, None)
    };
    println!("{record}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn compressed() -> Vec<u8> {
        let mut out = tar::Builder::new(Vec::new());
        for (name, data) in [
            ("rocksdb/CURRENT", b"MANIFEST-1\n".as_slice()),
            ("rocksdb/MANIFEST-1", b"manifest"),
            ("rocksdb/1.sst", b"retained rows"),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_mode(0o444);
            header.set_size(data.len() as u64);
            out.append_data(&mut header, name, data).unwrap();
        }
        let mut writer = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::best());
        writer.write_all(&out.into_inner().unwrap()).unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn exact_stream_stages_and_rejects_changed_inputs_or_members() {
        let bytes = compressed();
        let limits = CollectionLimits {
            maximum_files: 3,
            maximum_file_bytes: 100,
            maximum_total_bytes: 300,
            maximum_trailer_bytes: 4096,
        };
        let mut collection = census_rocksdb_tar(
            MultiBzDecoder::new(bytes.as_slice()),
            Path::new("rocksdb"),
            limits,
        )
        .unwrap();
        collection.files_retained = true;
        let mut source = Source {
            compressed_sha256: format!("{:x}", Sha256::digest(&bytes)),
            compressed_bytes: bytes.len() as u64,
            collection,
        };
        use std::os::unix::fs::PermissionsExt;
        let dest = tempfile::tempdir().unwrap();
        fs::set_permissions(dest.path(), fs::Permissions::from_mode(0o700)).unwrap();
        process(bytes.as_slice(), &source, None).unwrap();
        process(bytes.as_slice(), &source, Some(dest.path())).unwrap();
        assert_eq!(
            fs::read(dest.path().join("1.sst")).unwrap(),
            b"retained rows"
        );
        assert!(process(bytes.as_slice(), &source, Some(dest.path())).is_err());
        assert!(process(&bytes[..bytes.len() - 1], &source, None).is_err());
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(process(extra.as_slice(), &source, None).is_err());
        let parent = tempfile::tempdir().unwrap();
        let verified = stage(bytes.as_slice(), &source, parent.path()).unwrap();
        let final_dir = parent.path().join("held141-restore.verified");
        let durable: serde_json::Value =
            serde_json::from_slice(&fs::read(final_dir.join("COMPLETE.json")).unwrap()).unwrap();
        assert_eq!(verified, durable);
        assert_eq!(verified["restored_bytes"], source.collection.total_bytes);
        assert_eq!(report(&source, None)["restored_bytes"], 0);
        assert_eq!(
            fs::read(final_dir.join("rocksdb/1.sst")).unwrap(),
            b"retained rows"
        );
        assert!(stage(bytes.as_slice(), &source, parent.path()).is_err());
        assert!(!parent.path().join("held141-restore.staging").exists());

        let partial = tempfile::tempdir().unwrap();
        assert!(stage(&bytes[..bytes.len() - 1], &source, partial.path()).is_err());
        assert!(!partial.path().join("held141-restore.verified").exists());
        assert!(partial.path().join("held141-restore.staging").is_dir());
        assert!(stage(bytes.as_slice(), &source, partial.path()).is_err());
        source.collection.files[0].sha256 = "0".repeat(64);
        assert!(process(bytes.as_slice(), &source, None).is_err());
    }
}
