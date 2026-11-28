//! Ignored native fixtures: disposable files and commands only. Never call
//! capture(), manager(), systemctl, a real contract path or retained RAM path.
use super::*;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

const SCRATCH: &str = "/var/lib/jetstreamer/horizon-retained-ram-native934-fixtures-v1/scratch";
const EXT4: i64 = 0xEF53;

fn fixture(label: &str) -> PathBuf {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "requires separately admitted Root fixture actor"
    );
    let parent = anchored(SCRATCH, true).expect("Main must pre-admit the exact fresh scratch root");
    let meta = parent.metadata().unwrap();
    assert_eq!(meta.uid(), 0);
    assert_eq!(meta.mode() & 0o777, 0o700);
    directory(&parent, EXT4).expect("fixture profile requires the real ext4 scratch filesystem");
    // Keep every created member as qualification evidence. No existing file,
    // mount, permissions or data outside this new private directory is changed.
    let path = tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(SCRATCH)
        .unwrap()
        .keep();
    println!("retained-RAM native fixture path: {}", path.display());
    path
}
fn path_text(path: &Path) -> &str {
    path.to_str().unwrap()
}
fn proof(root: &Path, name: &str, body: &[u8], mode: u32) -> PathBuf {
    let path = root.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.write_all(body).unwrap();
    file.set_permissions(fs::Permissions::from_mode(mode))
        .unwrap();
    file.sync_all().unwrap();
    path
}
fn fixture_command(program: &str) -> Command {
    assert!(matches!(
        program,
        "/usr/bin/printf" | "/usr/bin/false" | "/usr/bin/sleep"
    ));
    let mut command = Command::new("/usr/bin/timeout");
    command.args(["--signal=KILL", "2s", program]);
    command
}
fn printed(text: &str) -> Result<BTreeMap<String, String>> {
    manager_output(fixture_command("/usr/bin/printf").args(["%s", text]))
}
fn printed_owner(iid: &str) -> Result<BTreeMap<String, String>> {
    let mut properties = sample(10).manager;
    properties.insert("InvocationID".into(), iid.into());
    let text = properties
        .iter()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect::<String>();
    printed(&text)
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_nofollow_rejects_ancestor_and_final_symlinks() {
    let root = fixture("nofollow-");
    let dir = root.join("original");
    fs::create_dir(&dir).unwrap();
    let file = proof(&dir, "proof", b"original", 0o400);
    assert_eq!(
        bytes(anchored(path_text(&file), false).unwrap(), 8).unwrap(),
        b"original"
    );
    let alias = root.join("alias");
    symlink(&dir, &alias).unwrap();
    assert!(anchored(path_text(&alias.join("proof")), false).is_err());
    let final_alias = root.join("proof-alias");
    symlink(&file, &final_alias).unwrap();
    assert!(anchored(path_text(&final_alias), false).is_err());
    assert!(fixed(path_text(&final_alias), &sha256(b"original"), true).is_err());
    let descriptor = anchored(path_text(&root), true).unwrap();
    assert!(child(&descriptor, "alias", true).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_fixed_enforces_root_owner_mode_and_hash() {
    let root = fixture("custody-");
    let good = proof(&root, "good", b"proof", 0o400);
    assert_eq!(
        fixed(path_text(&good), &sha256(b"proof"), true).unwrap(),
        sha256(b"proof")
    );
    assert!(fixed(path_text(&good), &sha256(b"changed"), true).is_err());
    let writable = proof(&root, "root-writable", b"proof", 0o600);
    assert!(fixed(path_text(&writable), &sha256(b"proof"), true).is_err());
    fixed(path_text(&writable), &sha256(b"proof"), false).unwrap();
    let group_writable = proof(&root, "group-writable", b"proof", 0o420);
    assert!(fixed(path_text(&group_writable), &sha256(b"proof"), false).is_err());
    let foreign = proof(&root, "foreign-owner", b"proof", 0o400);
    let name = CString::new(path_text(&foreign)).unwrap();
    assert_eq!(
        unsafe { libc::chown(name.as_ptr(), 65534, 65534) },
        0,
        "fixture needs CAP_CHOWN"
    );
    assert!(fixed(path_text(&foreign), &sha256(b"proof"), true).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_fixed_enforces_regular_single_link_and_exact_bounds() {
    let root = fixture("bounds-");
    let exact = vec![0x5a; 1 << 20];
    let file = proof(&root, "exact-1MiB", &exact, 0o400);
    fixed(path_text(&file), &sha256(&exact), true).unwrap();
    let mut oversized = exact;
    oversized.push(0x5a);
    let too_large = proof(&root, "over-1MiB", &oversized, 0o400);
    let error = fixed(path_text(&too_large), &sha256(&oversized), true).unwrap_err();
    assert!(format!("{error:#}").contains("oversized"));
    let single = proof(&root, "linked", b"same", 0o400);
    fs::hard_link(&single, root.join("second-link")).unwrap();
    assert!(fixed(path_text(&single), &sha256(b"same"), true).is_err());
    assert!(bytes(anchored(path_text(&root), true).unwrap(), 32).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_file_descriptor_and_post_read_path_replacement_are_distinct() {
    let root = fixture("file-replace-");
    let path = proof(&root, "proof", b"old bytes", 0o400);
    let opened = anchored(path_text(&path), false).unwrap();
    let original = identity(&opened).unwrap();
    unchanged_path(path_text(&path), false, &original).unwrap();
    fs::rename(&path, root.join("retained-original")).unwrap();
    proof(&root, "proof", b"new bytes", 0o400);
    assert_eq!(bytes(opened, 32).unwrap(), b"old bytes");
    assert!(unchanged_path(path_text(&path), false, &original).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_directory_descriptor_is_not_retargeted_by_parent_replacement() {
    let root = fixture("directory-replace-");
    let path = root.join("parent");
    fs::create_dir(&path).unwrap();
    proof(&path, "proof", b"old", 0o400);
    let opened = anchored(path_text(&path), true).unwrap();
    let original = identity(&opened).unwrap();
    fs::rename(&path, root.join("retained-parent")).unwrap();
    fs::create_dir(&path).unwrap();
    proof(&path, "proof", b"new", 0o400);
    assert_eq!(
        bytes(child(&opened, "proof", false).unwrap(), 3).unwrap(),
        b"old"
    );
    assert!(unchanged_path(path_text(&path), true, &original).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_directory_checks_real_filesystem_type_inode_and_mode() {
    let root = fixture("filesystem-");
    let opened = anchored(path_text(&root), true).unwrap();
    let actual = directory(&opened, EXT4).unwrap();
    assert!(actual.device > 0 && actual.inode > 0);
    assert!(directory(&opened, 0x63677270).is_err());
    assert!(directory(&opened, 0x01021994).is_err());
    let file = proof(&root, "regular", b"x", 0o400);
    assert!(directory(&anchored(path_text(&file), false).unwrap(), EXT4).is_err());
    let mut wrong_inode = actual.clone();
    wrong_inode.inode += 1;
    assert!(unchanged_path(path_text(&root), true, &wrong_inode).is_err());
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(unchanged_path(path_text(&root), true, &actual).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_text_reader_enforces_bound_and_utf8() {
    let root = fixture("text-");
    let good = proof(&root, "text", b"123\n", 0o400);
    assert_eq!(text(path_text(&good), 4).unwrap(), "123\n");
    assert!(text(path_text(&good), 3).is_err());
    let invalid = proof(&root, "invalid", &[0xff], 0o400);
    assert!(text(path_text(&invalid), 1).is_err());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_manager_runner_parses_actual_output_and_detects_changed_owner() {
    fixture("manager-owner-");
    let first = printed_owner("1234567890abcdef1234567890abcdef").unwrap();
    let second = printed_owner("abcdef1234567890abcdef1234567890").unwrap();
    let mut before = sample(10);
    before.manager = first;
    let mut after = sample(20);
    after.manager = second;
    let result = report(Ok(before), Ok(after));
    assert_eq!(result["status"], "unavailable");
    no_authority(&result);
    assert!(result["before"].is_object() && result["after"].is_object());
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_manager_runner_rejects_malformed_duplicate_and_failed_commands() {
    fixture("manager-denials-");
    assert!(
        format!("{:#}", printed("malformed\n").unwrap_err())
            .contains("malformed systemctl property")
    );
    assert!(
        format!("{:#}", printed("Id=a\nId=b\n").unwrap_err())
            .contains("duplicate systemctl property")
    );
    let error = manager_output(&mut fixture_command("/usr/bin/false")).unwrap_err();
    assert!(format!("{error:#}").contains("retained parent manager read unavailable"));
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_manager_runner_enforces_exact_stdout_boundary() {
    fixture("manager-size-");
    let exact = format!("Padding={}\n", "x".repeat(65536 - "Padding=\n".len()));
    assert_eq!(exact.len(), 65536);
    assert_eq!(
        printed(&exact).unwrap()["Padding"].len(),
        65536 - "Padding=\n".len()
    );
    let oversized = format!("Padding={}\n", "x".repeat(65537 - "Padding=\n".len()));
    assert_eq!(oversized.len(), 65537);
    let error = printed(&oversized).unwrap_err();
    assert!(format!("{error:#}").contains("retained parent manager read unavailable"));
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_manager_runner_uses_actual_bounded_timeout() {
    fixture("manager-timeout-");
    let started = std::time::Instant::now();
    let error = manager_output(fixture_command("/usr/bin/sleep").arg("30")).unwrap_err();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1500) && elapsed <= Duration::from_secs(8),
        "{elapsed:?}"
    );
    assert!(format!("{error:#}").contains("retained parent manager read unavailable"));
    println!("actual disposable command timeout elapsed: {elapsed:?}");
}

#[test]
#[ignore = "Root native fixture; separate admission and exact scratch root required"]
fn native_read_failure_report_preserves_other_endpoint_and_zero_authority() {
    let root = fixture("optional-error-");
    let good = proof(&root, "proof", b"retained", 0o400);
    let alias = root.join("alias");
    symlink(&good, &alias).unwrap();
    let actual_error = fixed(path_text(&alias), &sha256(b"retained"), true).unwrap_err();
    let result = report(Ok(sample(10)), Err(actual_error));
    assert_eq!(result["status"], "unavailable");
    assert!(result["before"].is_object());
    assert!(result["after"].is_null());
    no_authority(&result);
}
