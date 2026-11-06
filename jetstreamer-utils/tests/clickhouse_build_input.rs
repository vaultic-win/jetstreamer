// Exercise the same module that the Cargo build script uses.
#[path = "../build_support/clickhouse_input.rs"]
mod clickhouse_input;

#[test]
#[ignore = "requires the sealed binary and bounded writable native execution scope"]
fn sealed_clickhouse_runs_from_writable_extraction() {
    use sha2::{Digest, Sha256};
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

    let path = PathBuf::from(std::env::var_os("HORIZON_TEST_CLICKHOUSE_INPUT").unwrap());
    let digest = std::env::var("HORIZON_TEST_CLICKHOUSE_SHA256").unwrap();
    clickhouse_input::verify(&path, &digest).unwrap();
    let work = tempfile::tempdir().unwrap();
    let extracted = work.path().join("clickhouse");
    fs::copy(&path, &extracted).unwrap();
    fs::set_permissions(&extracted, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(fs::read(&extracted).unwrap())),
        digest
    );
    // The retained distribution self-decompresses beside the executable. This
    // writable extraction matches the embedded runtime, preserving sealed input.
    for arguments in [
        vec!["--version"],
        vec![
            "local",
            "--max_threads=2",
            "--max_memory_usage=268435456",
            "--max_execution_time=10",
            "--query",
            "SELECT version(), 1 + 1 FORMAT TSVRaw",
        ],
    ] {
        let output = Command::new("/usr/bin/timeout")
            .args(["--signal=TERM", "--kill-after=5", "30"])
            .arg(&extracted)
            .args(&arguments)
            .env("HOME", work.path())
            .current_dir(work.path())
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("ClickHouse native probe {arguments:?}: {stdout}{stderr}");
        assert!(
            output.status.success(),
            "native probe failed: {}: {stderr}",
            output.status
        );
        if arguments[0] == "--version" {
            assert!(stdout.contains("ClickHouse"));
        } else {
            let (version, result) = stdout.trim().split_once('\t').unwrap();
            assert!(!version.is_empty());
            assert_eq!(result, "2");
        }
    }
    // Self-extraction must never have modified the immutable build input.
    clickhouse_input::verify(&path, &digest).unwrap();
}
