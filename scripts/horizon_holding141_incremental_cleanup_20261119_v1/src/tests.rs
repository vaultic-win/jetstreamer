use super::*;
use incremental::{cache_tree_with_policy, reject_incremental_mounts};
fn fixture() -> (tempfile::TempDir, PathBuf, u32) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("incremental");
    fs::create_dir(&root).unwrap();
    let uid = fs::metadata(&root).unwrap().uid();
    (dir, root, uid)
}
#[test]
fn closed_profile_rejects_other_target_and_schema() {
    let mut p = Plan {
        schema: PROFILE.into(),
        source_commit: "a".repeat(40),
        cargo_lock_sha256: "b".repeat(64),
        output: "/var/lib/jetstreamer/holding141-incremental-check-v1/check.json".into(),
        prior_check: None,
    };
    validate_plan(&p).unwrap();
    p.schema = "other".into();
    assert!(validate_plan(&p).is_err());
    p.schema = PROFILE.into();
    p.output = "/tmp/check.json".into();
    assert!(validate_plan(&p).is_err());
    assert!(serde_json::from_value::<Plan>(json!({"schema":PROFILE,"source_commit":"a".repeat(40),"cargo_lock_sha256":"b".repeat(64),"output":"/var/lib/jetstreamer/holding141-incremental-check/check.json","target":"/arbitrary"})).is_err());
}
#[test]
fn internal_hardlinks_count_once_external_link_fails() {
    let (d, r, uid) = fixture();
    let a = r.join("a.o");
    fs::write(&a, b"compiler bytes").unwrap();
    fs::hard_link(&a, r.join("b.o")).unwrap();
    let c = cache_tree_with_policy(&r, uid, true).unwrap();
    assert_eq!(c["regular_files"], 2);
    assert_eq!(c["unique_regular_inodes"], 1);
    assert_eq!(
        c["physical_bytes"],
        (fs::metadata(&r).unwrap().blocks() + fs::metadata(&a).unwrap().blocks()) * 512
    );
    fs::hard_link(&a, d.path().join("retained.o")).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
}
#[test]
fn unknown_symlink_and_executable_members_fail() {
    let (d, r, uid) = fixture();
    for name in ["failed-executable", "epoch-141.jet", "query-cache.bin.bak"] {
        let p = r.join(name);
        fs::write(&p, b"retained").unwrap();
        assert!(cache_tree_with_policy(&r, uid, true).is_err());
        fs::remove_file(p).unwrap();
    }
    let a = r.join("a.o");
    fs::write(&a, b"object").unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
    fs::remove_file(&a).unwrap();
    std::os::unix::fs::symlink(d.path().join("outside"), a).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
}
#[test]
fn only_empty_rustc_locks_allow_execute_mode() {
    let (_d, r, uid) = fixture();
    let lock = r.join("s-build-id.lock");
    fs::write(&lock, b"").unwrap();
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o700)).unwrap();
    cache_tree_with_policy(&r, uid, true).unwrap();
    fs::write(&lock, b"evidence").unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
}
#[test]
fn member_metadata_changes_are_bound() {
    let (_d, r, uid) = fixture();
    let a = r.join("a.o");
    fs::write(&a, b"before").unwrap();
    let before = cache_tree_with_policy(&r, uid, true).unwrap();
    fs::write(&a, b"after-longer").unwrap();
    let after = cache_tree_with_policy(&r, uid, true).unwrap();
    assert_ne!(
        before["metadata_identity_sha256"],
        after["metadata_identity_sha256"]
    );
    fs::set_permissions(&a, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
}
#[test]
fn group_writable_requires_private_group_principal() {
    private_group_output(
        b"sol:x:1001:\n",
        b"root:x:0:0:root:/root:/bin/sh\nsol:x:1001:1001:sol:/home/sol:/bin/zsh\n",
    )
    .unwrap();
    assert!(
        private_group_output(
            b"sol:x:1001:guest\n",
            b"sol:x:1001:1001:sol:/home/sol:/bin/zsh\n"
        )
        .is_err()
    );
    assert!(private_group_output(b"sol:x:1001:\n",b"sol:x:1001:1001:sol:/home/sol:/bin/zsh\nguest:x:1002:1001:guest:/home/guest:/bin/sh\n").is_err());
}
#[test]
fn mount_and_bind_aliases_fail() {
    let t = Path::new(TARGET);
    reject_incremental_mounts(b"1 0 8:1 / / rw - ext4 /dev/root rw\n", t).unwrap();
    for p in [
        TARGET,
        concat!("/tmp/holding141-target/debug/incremental", "/sub"),
    ] {
        let row = format!("2 1 8:1 / {p} rw - ext4 /dev/root rw\n");
        assert!(reject_incremental_mounts(row.as_bytes(), t).is_err());
    }
    assert!(reject_incremental_mounts(b"bad row", t).is_err());
}
#[test]
fn staged_target_and_debug_binary_both_preserve_cache() {
    let t = Path::new(TARGET);
    for row in [
        format!("Environment=CARGO_TARGET_DIR={ROOT}\nExecStart=cargo test"),
        format!("ExecStart={DEBUG}/jetstreamer-r2"),
        format!("ExecStart=rustc --out-dir={ROOT}"),
    ] {
        assert!(relative_cache_reference(row.as_bytes(), t));
    }
    assert!(!relative_cache_reference(
        b"Environment=CARGO_TARGET_DIR=/another/build\nExecStart=cargo test",
        t
    ));
    assert!(!relative_cache_reference(
        b"ExecStart=/tmp/holding141-target-other/debug/tool",
        t
    ));
}

#[test]
fn raw_pre_lto_bitcode_requires_exact_name_and_magic() {
    let (_d, r, uid) = fixture();
    let p = r.join("2puf9b8c8u53gnrrsp5hrpwxi.pre-lto.bc");
    fs::write(&p, b"BC\xc0\xde\x35\x14\x00\x00").unwrap();
    cache_tree_with_policy(&r, uid, true).unwrap();
    for bytes in [
        b"".as_slice(),
        b"BC\xc0",
        b"\x7fELF",
        b"BC\xc0\xdf",
        b"\xde\xc0\x17\x0b",
    ] {
        fs::write(&p, bytes).unwrap();
        assert!(cache_tree_with_policy(&r, uid, true).is_err());
    }
    fs::remove_file(&p).unwrap();
    for name in [
        ".pre-lto.bc",
        "a-b.pre-lto.bc",
        "a.pre-lto.bc.bak",
        "a.bc",
        "a.pre-lto.bc.jet",
    ] {
        let bad = r.join(name);
        fs::write(&bad, b"BC\xc0\xde").unwrap();
        assert!(
            cache_tree_with_policy(&r, uid, true).is_err(),
            "accepted {name}"
        );
        fs::remove_file(bad).unwrap();
    }
}

#[test]
fn pre_lto_bitcode_keeps_executable_symlink_and_external_link_rejections() {
    let (d, r, uid) = fixture();
    let p = r.join("abc123.pre-lto.bc");
    fs::write(&p, b"BC\xc0\xde").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&p, d.path().join("retained.bc")).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
    fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(d.path().join("retained.bc"), &p).unwrap();
    assert!(cache_tree_with_policy(&r, uid, true).is_err());
}

#[test]
fn pre_lto_bitcode_rejects_replaced_identity() {
    let (_d, r, _uid) = fixture();
    let p = r.join("abc123.pre-lto.bc");
    fs::write(&p, b"BC\xc0\xde").unwrap();
    let before = fs::symlink_metadata(&p).unwrap();
    fs::rename(&p, r.join("preserved.pre-lto.bc")).unwrap();
    fs::write(&p, b"BC\xc0\xde").unwrap();
    assert!(incremental::pre_lto_bitcode(&p, &before).is_err());
}
