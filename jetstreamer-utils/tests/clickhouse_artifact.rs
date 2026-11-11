#[allow(dead_code)]
#[path = "../build_support.rs"]
mod build_support;

use build_support::{Artifact, acquire, artifact_for_target, materialize, open_verified};
use flate2::{Compression, write::GzEncoder};
use sha2::{Digest, Sha256};
use std::{fs, io, path::Path};

const FIXTURE: &[u8] = b"verified ClickHouse fixture\n";
const FIXTURE_HASH: &str = "a97f6f2424a6e0e8a454580014eb812c29b5d01e424227484912db247d7951c3";

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture_artifact() -> Artifact {
    Artifact {
        name: "fixture",
        sha256: FIXTURE_HASH,
        archive_member: None,
    }
}

#[test]
fn selects_target_artifact_and_rejects_unsupported_targets() {
    let linux = artifact_for_target("x86_64-unknown-linux-gnu").unwrap();
    assert!(linux.name.ends_with("amd64.tgz"));
    assert!(linux.archive_member.is_some());
    let arm_linux = artifact_for_target("aarch64-unknown-linux-gnu").unwrap();
    assert!(arm_linux.name.ends_with("arm64.tgz"));
    assert_ne!(linux.sha256, arm_linux.sha256);
    let mac = artifact_for_target("x86_64-apple-darwin").unwrap();
    assert_eq!(mac.name, "clickhouse-macos");
    assert!(mac.archive_member.is_none());
    let arm_mac = artifact_for_target("aarch64-apple-darwin").unwrap();
    assert_eq!(arm_mac.name, "clickhouse-macos-aarch64");
    assert_ne!(mac.sha256, arm_mac.sha256);
    for target in [
        "x86_64-unknown-linux-musl",
        "aarch64-pc-windows-msvc",
        "riscv64gc-unknown-linux-gnu",
        "aarch64-apple-ios",
    ] {
        assert_eq!(
            artifact_for_target(target).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
    }
}

#[test]
fn cache_and_extracted_binary_tampering_are_repaired_from_verified_bytes() {
    assert_eq!(sha256(FIXTURE), FIXTURE_HASH);
    let directory = tempfile::tempdir().unwrap();
    let mut downloads = 0;
    let mut fetch = |destination: &Path| {
        downloads += 1;
        fs::write(destination, FIXTURE)
    };
    let artifact = fixture_artifact();
    let (source, cache) = acquire(directory.path(), artifact, None, &mut fetch).unwrap();
    let executable = directory.path().join("clickhouse");
    materialize(source, artifact, &executable).unwrap();
    fs::write(&executable, b"tampered executable").unwrap();
    let (source, _) = acquire(directory.path(), artifact, None, &mut fetch).unwrap();
    materialize(source, artifact, &executable).unwrap();
    assert_eq!(fs::read(&executable).unwrap(), FIXTURE);
    fs::write(&cache, b"tampered cache").unwrap();
    let (source, _) = acquire(directory.path(), artifact, None, &mut fetch).unwrap();
    materialize(source, artifact, &executable).unwrap();
    assert_eq!(fs::read(&executable).unwrap(), FIXTURE);
    assert_eq!(downloads, 2);
}

#[test]
fn interrupted_and_corrupt_downloads_do_not_poison_retries() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = fixture_artifact();
    let result = acquire(directory.path(), artifact, None, |destination| {
        fs::write(destination, &FIXTURE[..5])?;
        Err(io::Error::new(io::ErrorKind::TimedOut, "connection lost"))
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    let result = acquire(directory.path(), artifact, None, |destination| {
        fs::write(destination, b"wrong content")
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    acquire(directory.path(), artifact, None, |destination| {
        fs::write(destination, FIXTURE)
    })
    .unwrap();
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn supplied_artifact_is_verified_without_network_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let supplied = directory.path().join("supplied");
    fs::write(&supplied, FIXTURE).unwrap();
    let artifact = fixture_artifact();
    acquire(directory.path(), artifact, Some(&supplied), |_| {
        panic!("supplied artifacts must not download")
    })
    .unwrap();
    fs::write(&supplied, b"wrong platform or corrupt binary").unwrap();
    let result = acquire(directory.path(), artifact, Some(&supplied), |_| {
        panic!("bad supplied artifact must fail closed")
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

fn archive(path: &Path, members: &[(&str, tar::EntryType, &[u8])]) {
    let mut writer = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for (name, kind, bytes) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o755);
        header.set_entry_type(*kind);
        header.set_cksum();
        writer.append_data(&mut header, name, *bytes).unwrap();
    }
    let compressed = writer.into_inner().unwrap().finish().unwrap();
    fs::write(path, compressed).unwrap();
}

#[test]
fn extracts_only_named_regular_member_and_never_runs_archive_scripts() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("archive.tgz");
    archive(
        &source,
        &[
            ("install.sh", tar::EntryType::Regular, b"must not execute"),
            ("payload/clickhouse", tar::EntryType::Regular, FIXTURE),
            ("unrelated", tar::EntryType::Regular, b"must not unpack"),
        ],
    );
    let digest = sha256(&fs::read(&source).unwrap());
    let artifact = Artifact {
        archive_member: Some("payload/clickhouse"),
        ..fixture_artifact()
    };
    let executable = directory.path().join("output");
    materialize(
        open_verified(&source, &digest).unwrap(),
        artifact,
        &executable,
    )
    .unwrap();
    assert_eq!(fs::read(executable).unwrap(), FIXTURE);
    assert!(!directory.path().join("install.sh").exists());
    assert!(!directory.path().join("unrelated").exists());
    assert!(!directory.path().join("payload").exists());
}

#[test]
fn rejects_missing_duplicate_and_non_regular_archive_members() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("archive.tgz");
    let destination = directory.path().join("output");
    let artifact = Artifact {
        archive_member: Some("payload/clickhouse"),
        ..fixture_artifact()
    };
    let cases = [
        vec![("wrong/path", tar::EntryType::Regular, FIXTURE)],
        vec![
            ("payload/clickhouse", tar::EntryType::Regular, FIXTURE),
            ("payload/clickhouse", tar::EntryType::Regular, FIXTURE),
        ],
        vec![(
            "payload/clickhouse",
            tar::EntryType::Symlink,
            b"".as_slice(),
        )],
    ];
    for members in cases {
        archive(&source, &members);
        let digest = sha256(&fs::read(&source).unwrap());
        assert!(
            materialize(
                open_verified(&source, &digest).unwrap(),
                artifact,
                &destination
            )
            .is_err()
        );
        assert!(!destination.exists());
    }
}
