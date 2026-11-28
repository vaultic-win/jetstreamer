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
    m.insert(
        "ExecStart".into(),
        format!("{NATIVE_COMMAND} ; start_time={ORIGINAL_HISTORY}"),
    );
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

#[test]
fn actual_post_reload_display_preserves_all_twenty_eight_terminal_properties() {
    let original: Value =
        serde_json::from_str(include_str!("fixtures/original-terminal.json")).unwrap();
    let old: BTreeMap<String, String> =
        serde_json::from_value(original["terminal_manager"].clone()).unwrap();
    let current: BTreeMap<String, String> =
        include_str!("fixtures/post-reload-terminal.properties")
            .lines()
            .map(|l| {
                let (k, v) = l.split_once('=').unwrap();
                (k.into(), v.into())
            })
            .collect();
    assert_eq!(current.len(), 28);
    assert_ne!(current["ExecStart"], old["ExecStart"]);
    for (k, v) in &current {
        if k != "ExecStart" {
            assert_eq!(v, &old[k], "{k}");
        }
    }
    assert_eq!(
        native_command(&current["ExecStart"]).unwrap(),
        native_command(&old["ExecStart"]).unwrap()
    );
    let proof = json!({"original_evidence":original});
    terminal_properties(&old, &proof).unwrap();
    terminal_properties(&current, &proof).unwrap();
}
#[test]
fn display_reset_never_accepts_changed_command_or_malformed_suffix_even_when_equal() {
    let original = format!("{NATIVE_COMMAND} ; start_time={ORIGINAL_HISTORY}");
    let reset = format!("{NATIVE_COMMAND} ; start_time={RESET_HISTORY}");
    for bad in [
        original.replace(
            "horizon265-native-input-daa786c0",
            "replacement-native-input",
        ),
        reset.replace("ignore_errors=no", "ignore_errors=yes"),
        reset.replace("argv[]=", "argv[]=--extra "),
        reset.replace("pid=0", "pid=1307638"),
        reset.replace("code=(null)", "code=exited"),
        reset.replace("status=0/0", "status=0"),
        reset.replace("start_time=[n/a]", "start_time=[]"),
        reset.replace("stop_time=[n/a]", "stop_time=[unknown]"),
        format!("{reset} trailing"),
        format!("{reset} ; start_time={RESET_HISTORY}"),
        "unframed".into(),
    ] {
        assert!(native_command(&bad).is_err(), "{bad}");
        let mut m: BTreeMap<String, String> = serde_json::from_value(
            serde_json::from_str::<Value>(include_str!("fixtures/original-terminal.json")).unwrap()
                ["terminal_manager"]
                .clone(),
        )
        .unwrap();
        m.insert("ExecStart".into(), bad);
        let proof = json!({"original_evidence":{"terminal_manager":m}});
        assert!(terminal_properties(&m, &proof).is_err());
    }
}
