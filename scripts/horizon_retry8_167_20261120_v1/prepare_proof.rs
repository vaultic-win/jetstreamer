//! Authenticate the v2 preparer's full native test result and the four-lane regression.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(crate) fn tested_independent_baseline(proof: &Value) -> Result<()> {
    let binding = &proof["tests"];
    let path = Path::new(
        binding["path"]
            .as_str()
            .context("preparer native test log")?,
    );
    let expected = binding["sha256"]
        .as_str()
        .context("preparer native test digest")?;
    ensure!(
        path.is_absolute() && path.canonicalize()? == path && expected.len() == 64,
        "invalid test binding"
    );
    let mut log = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = log.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 8 << 20,
        "unsafe test log"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut log)
        .take((8 << 20) + 1)
        .read_to_end(&mut raw)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == after.dev()
            && m.ino() == after.ino()
            && m.len() == after.len()
            && raw.len() as u64 == m.len()
            && format!("{:x}", Sha256::digest(&raw)) == expected,
        "test receipt digest or file changed"
    );
    let log = std::str::from_utf8(&raw)?;
    let count = proof["tests_passed"]
        .as_u64()
        .context("preparer test count")?;
    ensure!(count >= 321 && proof["tests_failed"] == 0
        && log.lines().any(|s| s.starts_with(&format!("test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;")))
        && log.lines().any(|s| s=="test current_allocation::independent166_declaration_tests::real_four_lane_declaration_charges_cold166_from_zero_and_keeps_standard_roots_positive ... ok"),
        "native receipt is missing the complete v2 test suite or the zero-baseline declaration regression");
    Ok(())
}
