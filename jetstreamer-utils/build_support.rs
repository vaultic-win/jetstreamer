//! Pinned ClickHouse acquisition shared by the build script and its tests.

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::NamedTempFile;

pub const VERSION: &str = "26.10.2.103";
const RELEASE_URL: &str =
    "https://github.com/ClickHouse/ClickHouse/releases/download/v26.10.2.103-stable";

#[derive(Clone, Copy, Debug)]
pub struct Artifact {
    pub name: &'static str,
    pub sha256: &'static str,
    pub archive_member: Option<&'static str>,
}

/// Select by Cargo's target triple, never by the machine running the build script.
pub fn artifact_for_target(target: &str) -> io::Result<Artifact> {
    let artifact = match target {
        "x86_64-unknown-linux-gnu" => Artifact {
            name: "clickhouse-common-static-26.10.2.103-amd64.tgz",
            sha256: "ec811478449184dea496ba17c3f76fdd3aeb2013dd5041676bd00041fed98d17",
            archive_member: Some("clickhouse-common-static-26.10.2.103/usr/bin/clickhouse"),
        },
        "aarch64-unknown-linux-gnu" => Artifact {
            name: "clickhouse-common-static-26.10.2.103-arm64.tgz",
            sha256: "bd59e072630c8884037575c59dad664330fd69c4247da334c9cf1b3f79a1a4c4",
            archive_member: Some("clickhouse-common-static-26.10.2.103/usr/bin/clickhouse"),
        },
        "x86_64-apple-darwin" => Artifact {
            name: "clickhouse-macos",
            sha256: "8bdb041c299a849ebd9bbba72ffca925a24482abec690ae698be63818eece1ab",
            archive_member: None,
        },
        "aarch64-apple-darwin" => Artifact {
            name: "clickhouse-macos-aarch64",
            sha256: "7f43a3c4d5f41e42ae6ec275c1531ca44b6018caae15217394fd85181ca1df59",
            archive_member: None,
        },
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "no pinned ClickHouse {VERSION} artifact for target {target}; \
                     supported targets: x86_64-unknown-linux-gnu, aarch64-unknown-linux-gnu, \
                     x86_64-apple-darwin, aarch64-apple-darwin"
                ),
            ));
        }
    };
    Ok(artifact)
}

pub fn download(artifact: Artifact, destination: &Path) -> io::Result<()> {
    // --disable must be first: a user's .curlrc must not weaken TLS validation or
    // change the output. Neither the installer nor the downloaded binary runs here.
    let status = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--retry",
            "3",
            "--retry-all-errors",
            "--connect-timeout",
            "30",
            "--max-time",
            "600",
            "--output",
        ])
        .arg(destination)
        .arg(format!("{RELEASE_URL}/{}", artifact.name))
        .status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "download of pinned ClickHouse artifact {} failed: {status}",
            artifact.name
        )));
    }
    Ok(())
}

/// Hash and rewind the same open file that the extractor will consume.
pub fn open_verified(path: &Path, expected: &str) -> io::Result<File> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let len = file.read(&mut buffer)?;
        if len == 0 {
            break;
        }
        hash.update(&buffer[..len]);
    }
    let actual: String = hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "ClickHouse SHA-256 mismatch for {}: expected {expected}, got {actual}",
                path.display()
            ),
        ));
    }
    file.rewind()?;
    Ok(file)
}

/// Keep only verified downloads in the cache. A failed or interrupted attempt
/// leaves neither a partial cache entry nor an embedded executable.
pub fn acquire(
    directory: &Path,
    artifact: Artifact,
    supplied: Option<&Path>,
    mut fetch: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<(File, PathBuf)> {
    if let Some(path) = supplied {
        let path = path.canonicalize()?;
        return Ok((open_verified(&path, artifact.sha256)?, path));
    }
    let cache = directory.join(format!("{}-{}", artifact.sha256, artifact.name));
    match open_verified(&cache, artifact.sha256) {
        Ok(file) => return Ok((file, cache)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            // An old or damaged cache must never become executable bytes.
            fs::remove_file(&cache)?;
        }
        Err(error) => return Err(error),
    }
    let pending = NamedTempFile::new_in(directory)?;
    fetch(pending.path())?;
    let verified = open_verified(pending.path(), artifact.sha256)?;
    pending.persist(&cache).map_err(|error| error.error)?;
    Ok((verified, cache))
}

/// Extract only the named regular file to a caller-owned output. No paths or
/// links from the archive are unpacked onto the filesystem.
pub fn materialize(mut source: File, artifact: Artifact, destination: &Path) -> io::Result<()> {
    let directory = destination
        .parent()
        .ok_or_else(|| io::Error::other("ClickHouse output has no parent directory"))?;
    let mut pending = NamedTempFile::new_in(directory)?;
    source.seek(SeekFrom::Start(0))?;
    if let Some(member) = artifact.archive_member {
        let mut archive = tar::Archive::new(GzDecoder::new(source));
        let mut found = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if entry.path_bytes().as_ref() != member.as_bytes() {
                continue;
            }
            if found || !entry.header().entry_type().is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ClickHouse archive must contain exactly one regular executable member",
                ));
            }
            io::copy(&mut entry, &mut pending)?;
            found = true;
        }
        if !found {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ClickHouse archive is missing {member}"),
            ));
        }
    } else {
        io::copy(&mut source, &mut pending)?;
    }
    pending.flush()?;
    // It is data at build time; runtime code sets permissions on its own copy.
    pending.persist(destination).map_err(|error| error.error)?;
    Ok(())
}
