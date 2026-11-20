use super::*;
use std::os::unix::fs::symlink;
fn fixture() -> (tempfile::TempDir, File, Stamp) {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("scratch")).unwrap();
    let root = File::open(temp.path()).unwrap();
    let expected = stamp(&fs::symlink_metadata(temp.path().join("scratch")).unwrap());
    (temp, root, expected)
}
#[test]
fn empty_directory_retirement_preserves_every_sibling_and_parent() {
    let (temp, root, expected) = fixture();
    for name in ["native-result.json", "worker.stderr", "ledger", "tmp"] {
        fs::write(temp.path().join(name), name).unwrap();
    }
    remove_empty(&root, &expected).unwrap();
    assert!(!temp.path().join("scratch").exists());
    for name in ["native-result.json", "worker.stderr", "ledger", "tmp"] {
        assert_eq!(fs::read(temp.path().join(name)).unwrap(), name.as_bytes());
    }
}
#[test]
fn new_child_between_precheck_and_unlink_fails_atomically_without_deletion() {
    let (temp, root, _) = fixture();
    fs::write(temp.path().join("scratch/appendvec"), b"retain").unwrap();
    // Match current metadata so the actual AT_REMOVEDIR kernel gate is exercised.
    let current = stamp(&fs::symlink_metadata(temp.path().join("scratch")).unwrap());
    assert!(remove_empty(&root, &current).is_err());
    assert_eq!(
        fs::read(temp.path().join("scratch/appendvec")).unwrap(),
        b"retain"
    );
}
#[test]
fn changed_inode_and_symlink_are_never_retired() {
    let (temp, root, expected) = fixture();
    fs::rename(temp.path().join("scratch"), temp.path().join("old-scratch")).unwrap();
    fs::create_dir(temp.path().join("scratch")).unwrap();
    assert!(remove_empty(&root, &expected).is_err());
    fs::remove_dir(temp.path().join("scratch")).unwrap();
    symlink(temp.path().join("old-scratch"), temp.path().join("scratch")).unwrap();
    let symlink_stamp = stamp(&fs::symlink_metadata(temp.path().join("scratch")).unwrap());
    assert!(remove_empty(&root, &symlink_stamp).is_err());
    assert!(temp.path().join("old-scratch").is_dir());
}
#[test]
fn mount_gate_rejects_direct_subtree_and_bind_alias_mounts() {
    let target = Path::new("/private/native/scratch");
    for (root, mount) in [
        ("/private/native/scratch", "/alias"),
        ("/", "/private/native/scratch"),
        ("/private/native/scratch/child", "/alias"),
    ] {
        let raw = format!("1 0 259:1 {root} {mount} rw - ext4 /dev/test rw\n");
        assert!(mount_check(&raw, target).is_err());
    }
    assert!(mount_check("1 0 259:1 / / rw - ext4 /dev/test rw\n", target).is_ok());
    assert!(mount_check("invalid", target).is_err());
    assert_eq!(unescape("/space\\040name").unwrap(), "/space name");
    assert!(unescape("/bad\\09x").is_err());
    assert!(unescape("/bad\\777").is_err());
}
#[test]
fn receipt_writer_never_clobbers_existing_or_follows_symlinks() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("receipt");
    write_new(&p, &json!({"original":true})).unwrap();
    assert!(write_new(&p, &json!({"original":false})).is_err());
    let link = t.path().join("link");
    symlink(&p, &link).unwrap();
    assert!(write_new(&link, &json!({"original":false})).is_err());
}
#[test]
fn source_has_no_recursive_removal_or_service_mutation_route() {
    let source = include_str!("main.rs");
    assert!(!source.contains("remove_dir_all"));
    assert!(!source.contains("daemon-reload"));
    assert!(!source.contains("SIGKILL"));
    assert!(!source.contains("DeleteObject"));
    assert_eq!(source.matches("libc::unlinkat(").count(), 1);
    assert!(source.contains("libc::AT_REMOVEDIR"));
}

#[test]
fn terminal_properties_reject_restarted_replaced_or_live_native_owner() {
    let mut m: BTreeMap<String, String> = [
        ("Id", UNIT),
        ("InvocationID", IID),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainCode", "1"),
        ("ExecMainPID", "1307638"),
        ("ExecMainStatus", "0"),
        ("Job", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("TriggeredBy", ""),
        ("ControlGroup", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect();
    for k in [
        "ExecStart",
        "FragmentPath",
        "DropInPaths",
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "Type",
        "User",
        "Group",
    ] {
        m.insert(k.into(), format!("original-{k}"));
    }
    let proof = json!({"original_evidence":{"terminal_manager":m}});
    terminal_properties(&m, &proof).unwrap();
    for (key, bad) in [
        ("InvocationID", "different"),
        ("MainPID", "123"),
        ("ExecMainPID", "123"),
        ("ControlPID", "456"),
        ("NRestarts", "1"),
        ("Job", "23/start"),
        ("ActiveState", "active"),
        ("Restart", "always"),
        ("TriggeredBy", "some.timer"),
        ("ExecStart", "replacement image"),
        ("MemoryMax", "0"),
    ] {
        let mut changed = m.clone();
        changed.insert(key.into(), bad.into());
        assert!(terminal_properties(&changed, &proof).is_err(), "{key}");
    }
}
