use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use md5::Md5;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::{fs::MetadataExt as _, fs::OpenOptionsExt as _},
    path::Path,
};
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

#[derive(Debug)]
pub struct LocalProof {
    pub sha256_hex: String,
    pub multipart_etag: String,
    pub composite_sha256: String,
}

fn identity(metadata: &fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

pub fn regular_identity(path: &Path) -> Result<FileIdentity> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file(),
        "not a regular file: {}",
        path.display()
    );
    ensure!(
        metadata.nlink() == 1,
        "file has multiple links: {}",
        path.display()
    );
    Ok(identity(&metadata))
}

pub fn hash_and_etag(path: &Path, expected: FileIdentity, part_size: u64) -> Result<LocalProof> {
    hash_and_etag_observed(path, expected, part_size, |_| {})
}

pub fn hash_and_etag_observed(
    path: &Path,
    expected: FileIdentity,
    part_size: u64,
    mut progress: impl FnMut(u64),
) -> Result<LocalProof> {
    ensure!(part_size > 0, "hash part size must be positive");
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))?;
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed before hashing"
    );
    let mut sha256 = Sha256::new();
    let mut combined_md5 = Md5::new();
    let mut combined_sha256 = Sha256::new();
    let mut part_count = 0u64;
    let mut remaining = expected.length;
    let mut buffer = vec![0u8; usize::try_from(part_size.min(8 * 1024 * 1024))?];
    while remaining > 0 {
        let this_part = remaining.min(part_size);
        let mut part_remaining = this_part;
        let mut md5 = Md5::new();
        let mut part_sha256 = Sha256::new();
        while part_remaining > 0 {
            let take = usize::try_from(part_remaining.min(buffer.len() as u64))?;
            file.read_exact(&mut buffer[..take])?;
            sha256.update(&buffer[..take]);
            md5.update(&buffer[..take]);
            part_sha256.update(&buffer[..take]);
            part_remaining -= take as u64;
            progress(expected.length - remaining + this_part - part_remaining);
        }
        combined_md5.update(md5.finalize());
        combined_sha256.update(part_sha256.finalize());
        part_count += 1;
        remaining -= this_part;
    }
    ensure!(
        identity(&file.metadata()?) == expected,
        "archive changed while hashing"
    );
    ensure!(
        regular_identity(path)? == expected,
        "archive namespace changed while hashing"
    );
    let sha256_hex = format!("{:x}", sha256.finalize());
    Ok(LocalProof {
        sha256_hex,
        multipart_etag: format!("{:x}-{part_count}", combined_md5.finalize()),
        composite_sha256: BASE64_STANDARD.encode(combined_sha256.finalize()),
    })
}

pub fn multipart_etag(part_digests: &[Vec<u8>]) -> String {
    let mut md5 = Md5::new();
    for digest in part_digests {
        md5.update(digest);
    }
    format!("{:x}-{}", md5.finalize(), part_digests.len())
}

pub fn composite_sha256(part_digests: &[Vec<u8>]) -> String {
    let mut sha256 = Sha256::new();
    for digest in part_digests {
        sha256.update(digest);
    }
    BASE64_STANDARD.encode(sha256.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_proof_binds_sha_and_etag() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        fs::write(&path, b"abcdefgh").unwrap();
        let proof = hash_and_etag(&path, regular_identity(&path).unwrap(), 5).unwrap();
        assert_eq!(
            proof.sha256_hex,
            format!("{:x}", Sha256::digest(b"abcdefgh"))
        );
        let expected =
            multipart_etag(&[Md5::digest(b"abcde").to_vec(), Md5::digest(b"fgh").to_vec()]);
        assert_eq!(proof.multipart_etag, expected);
        let expected_sha = composite_sha256(&[
            Sha256::digest(b"abcde").to_vec(),
            Sha256::digest(b"fgh").to_vec(),
        ]);
        assert_eq!(proof.composite_sha256, expected_sha);
    }
    #[test]
    fn zero_hash_part_size_is_rejected_before_opening_the_archive() {
        let missing = Path::new("/nonexistent/zero-part-size-archive");
        for length in [0, 1] {
            let expected = FileIdentity {
                device: 0,
                inode: 0,
                length,
                modified_seconds: 0,
                modified_nanoseconds: 0,
            };
            let error = hash_and_etag(missing, expected, 0).unwrap_err();
            assert_eq!(error.to_string(), "hash part size must be positive");
        }
    }
    #[test]
    fn streaming_part_digests_preserve_empty_single_and_many_part_proofs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("archive");
        for data in [b"".as_slice(), b"a", b"abcdefghijklmno"] {
            fs::write(&path, data).unwrap();
            for part_size in [1, 3, 64] {
                let proof =
                    hash_and_etag(&path, regular_identity(&path).unwrap(), part_size).unwrap();
                let md5_parts = data
                    .chunks(part_size as usize)
                    .map(|part| Md5::digest(part).to_vec())
                    .collect::<Vec<_>>();
                let sha_parts = data
                    .chunks(part_size as usize)
                    .map(|part| Sha256::digest(part).to_vec())
                    .collect::<Vec<_>>();
                assert_eq!(proof.sha256_hex, format!("{:x}", Sha256::digest(data)));
                assert_eq!(proof.multipart_etag, multipart_etag(&md5_parts));
                assert_eq!(proof.composite_sha256, composite_sha256(&sha_parts));
            }
        }
    }
}
