use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
const ID: &str = "65f2ef2e02cb9d14";
fn fixture(crate_name: &str, metadata: bool) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let stem = format!("{crate_name}-{ID}");
    let d = root.join(format!("{stem}.d"));
    fs::write(&d, depinfo(crate_name, ID, metadata)).unwrap();
    let output = if metadata {
        root.join(format!("lib{stem}.rmeta"))
    } else {
        root.join(&stem)
    };
    if metadata {
        fs::write(&output, []).unwrap();
    } else {
        let mut bytes = vec![0u8; 256];
        bytes[..16].copy_from_slice(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
        bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[40..48].copy_from_slice(&128u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
        fs::write(&output, bytes).unwrap();
        fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).unwrap();
    }
    (directory, d, output)
}
fn accepted(root: &Path, path: &Path) -> bool {
    qualified(Path::new(RELEASE_DEPS), root, path, &node(path).unwrap()).unwrap_or(false)
}
#[test]
fn exact_observed_compiler_pairs_pass_the_existing_full_manifest_engine() {
    if unsafe { libc::geteuid() } != 1000 {
        return;
    }
    for (crate_name, metadata) in [
        (RESTORE, true),
        (JOURNAL, true),
        (RESTORE, false),
        (JOURNAL, false),
    ] {
        let (directory, d, output) = fixture(crate_name, metadata);
        assert!(forbidden(
            Path::new(RELEASE_DEPS),
            &Path::new(RELEASE_DEPS).join(d.file_name().unwrap()),
            "file"
        ));
        assert!(accepted(directory.path(), &d));
        assert!(accepted(directory.path(), &output));
        let manifest = manifest_scoped(directory.path(), Path::new(RELEASE_DEPS)).unwrap();
        assert_eq!(manifest.nodes.len(), 3);
        if metadata {
            let observed_no_deps = fs::read_to_string(&d).unwrap().replace(
                "# env-dep:CLIPPY_ARGS=-D",
                "# env-dep:CLIPPY_ARGS=--no-deps__CLIPPY_HACKERY__-D",
            );
            fs::write(&d, observed_no_deps).unwrap();
            assert!(accepted(directory.path(), &d));
            assert!(accepted(directory.path(), &output));
            assert_eq!(
                manifest_scoped(directory.path(), Path::new(RELEASE_DEPS))
                    .unwrap()
                    .nodes
                    .len(),
                3
            );
        }
        for policy in [DEBUG_INCREMENTAL, "/private/other/target/release/deps"] {
            assert!(
                !qualified(
                    Path::new(policy),
                    directory.path(),
                    &output,
                    &node(&output).unwrap()
                )
                .unwrap()
            );
            assert!(manifest_scoped(directory.path(), Path::new(policy)).is_err());
        }
    }
}
#[test]
fn names_alone_never_exempt_unknown_nested_malformed_or_protected_files() {
    for bad in [
        "libunknown_checkpoint-65f2ef2e02cb9d14.rmeta",
        "libjetstreamer_checkpoint_restore_probe-G5f2ef2e02cb9d14.rmeta",
        "libjetstreamer_checkpoint_restore_probe-65f2ef2e02cb9d1.rmeta",
        "libjetstreamer_checkpoint_restore_probe-65f2ef2e02cb9d14.rlib",
        "jetstreamer_epoch140_checkpoint_journal-65f2ef2e02cb9d14.rlib",
        "jetstreamer_checkpoint_restore_probe-65f2ef2e02cb9d14.jet",
        "jetstreamer_checkpoint_restore_probe-65f2ef2e02cb9d14.sha256",
        "snapshot-checkpoint.tar.zst",
        "native-checkpoint.json",
        "Cargo.lock",
    ] {
        assert!(name(bad).is_none(), "{bad}");
    }
    if unsafe { libc::geteuid() } != 1000 {
        return;
    }
    let (directory, d, output) = fixture(RESTORE, true);
    let nested = directory.path().join("nested");
    fs::create_dir(&nested).unwrap();
    let nested_output = nested.join(output.file_name().unwrap());
    fs::write(&nested_output, []).unwrap();
    assert!(!accepted(directory.path(), &nested_output));
    let alias = directory
        .path()
        .join("libjetstreamer_checkpoint_restore_probe-ffffffffffffffff.rmeta");
    symlink(&output, &alias).unwrap();
    assert!(!accepted(directory.path(), &alias));
    fs::remove_file(&output).unwrap();
    fs::create_dir(&output).unwrap();
    assert!(!accepted(directory.path(), &output));
    assert!(accepted(directory.path(), &d));
}
#[test]
fn paired_depinfo_requires_exact_crate_sources_target_and_complete_records() {
    if unsafe { libc::geteuid() } != 1000 {
        return;
    }
    let (directory, d, output) = fixture(RESTORE, true);
    let good = fs::read_to_string(&d).unwrap();
    for bad in [
        good.replace(
            "jetstreamer-node/src/bin/jetstreamer-checkpoint-restore-probe.rs",
            "private-checkpoint.json",
        ),
        good.replace(RELEASE_DEPS, "/other/target/release/deps"),
        good.replace(ID, "ffffffffffffffff"),
        good.clone() + "\nprivate-checkpoint.json:\n",
        good.replace("# env-dep:CLIPPY_CONF_DIR\n", ""),
        good.replace("CLIPPY_ARGS=-D", "CLIPPY_ARGS=--all-targets -D"),
        "checkpoint state".into(),
    ] {
        fs::write(&d, bad).unwrap();
        assert!(!accepted(directory.path(), &d));
        assert!(!accepted(directory.path(), &output));
    }
    fs::write(&d, good).unwrap();
    fs::remove_file(&output).unwrap();
    assert!(accepted(directory.path(), &d));
}
#[test]
fn metadata_placeholder_must_be_empty_and_executable_must_have_real_elf_tables() {
    if unsafe { libc::geteuid() } != 1000 {
        return;
    }
    let (directory, d, output) = fixture(RESTORE, true);
    fs::write(
        &output,
        b"real checkpoint state must never be retired as metadata",
    )
    .unwrap();
    assert!(accepted(directory.path(), &d));
    assert!(!accepted(directory.path(), &output));
    let (directory, d, output) = fixture(RESTORE, false);
    let good = fs::read(&output).unwrap();
    for changed in [0usize, 4, 5, 16, 18, 20, 52, 54, 58] {
        let mut bad = good.clone();
        bad[changed] = 0;
        fs::write(&output, bad).unwrap();
        assert!(accepted(directory.path(), &d));
        assert!(!accepted(directory.path(), &output));
    }
    fs::write(&output, &good[..64]).unwrap();
    assert!(!accepted(directory.path(), &output));
    fs::write(&output, &good).unwrap();
    fs::set_permissions(&output, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(accepted(directory.path(), &d));
    assert!(!accepted(directory.path(), &output));
}

#[test]
fn retirement_order_preserves_positive_compiler_witness_through_every_interrupted_subset() {
    if unsafe { libc::geteuid() } != 1000 {
        return;
    }
    for (crate_name, metadata) in [
        (RESTORE, true),
        (JOURNAL, true),
        (RESTORE, false),
        (JOURNAL, false),
    ] {
        let (directory, d, output) = fixture(crate_name, metadata);
        let original = manifest_scoped(directory.path(), Path::new(RELEASE_DEPS)).unwrap();
        let ordered = retirement_nodes(Path::new(RELEASE_DEPS), &original);
        let files = ordered
            .iter()
            .filter(|(_, n)| n.kind != "directory")
            .map(|(p, _)| (*p).clone())
            .collect::<Vec<_>>();
        assert_eq!(
            files,
            vec![
                PathBuf::from(output.file_name().unwrap()),
                PathBuf::from(d.file_name().unwrap())
            ]
        );
        for relative in files {
            fs::remove_file(directory.path().join(relative)).unwrap();
            let remaining = manifest_scoped(directory.path(), Path::new(RELEASE_DEPS)).unwrap();
            subset(&remaining, &original).unwrap();
        }
        let default = retirement_nodes(Path::new("/private/other/target/release/deps"), &original);
        assert_eq!(
            default
                .iter()
                .map(|(p, _)| (*p).clone())
                .collect::<Vec<_>>(),
            original.nodes.keys().cloned().collect::<Vec<_>>()
        );
    }
}
