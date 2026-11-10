use super::*;
use std::os::unix::fs::symlink;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, u32, u32) {
    let t = tempfile::tempdir().unwrap();
    let source = t.path().join("source");
    let parent = t.path().join("target-parent");
    fs::create_dir(&source).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let m = fs::metadata(&source).unwrap();
    (t, source, parent, m.uid(), m.gid())
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn stage(source: &Path, parent: &Path, uid: u32, gid: u32) -> Result<copy::Snapshot> {
    copy::copy_stage(
        &copy::open_directory(source)?,
        &copy::open_directory(parent)?,
        "new.stage",
        uid,
        uid,
        gid,
        || Ok(()),
    )
}
#[test]
fn coherent_copy_preserves_real_bytes_file_modes_mtimes_and_private_directories() {
    let (_t, source, parent, uid, gid) = fixture();
    write(
        &source.join("credentials.db"),
        b"disposable-fixture-credentials",
        0o600,
    );
    write(&source.join("config_sentinel"), b"", 0o644);
    fs::create_dir(source.join("configurations")).unwrap();
    fs::set_permissions(
        source.join("configurations"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    write(
        &source.join("configurations/config_default"),
        b"fixture setting",
        0o600,
    );
    let result = stage(&source, &parent, uid, gid).unwrap();
    assert_eq!(result.count(), 5);
    let copied = copy::snapshot(
        &copy::open_directory(&parent.join("new.stage")).unwrap(),
        uid,
    )
    .unwrap();
    assert!(result.logical_equals(&copied));
    assert_eq!(
        fs::read(parent.join("new.stage/credentials.db")).unwrap(),
        b"disposable-fixture-credentials"
    );
    assert_eq!(
        fs::metadata(parent.join("new.stage/configurations"))
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(parent.join("new.stage/config_sentinel"))
            .unwrap()
            .mode()
            & 0o777,
        0o644
    );
    let a = fs::metadata(source.join("credentials.db")).unwrap();
    let b = fs::metadata(parent.join("new.stage/credentials.db")).unwrap();
    assert_eq!((a.mtime(), a.mtime_nsec()), (b.mtime(), b.mtime_nsec()));
    assert_eq!((b.uid(), b.gid()), (uid, gid));
}
#[test]
fn source_mutation_after_initial_snapshot_fails_and_preserves_attempt() {
    let (_t, source, parent, uid, gid) = fixture();
    let file = source.join("credentials.db");
    write(&file, b"before", 0o600);
    let result = copy::copy_stage(
        &copy::open_directory(&source).unwrap(),
        &copy::open_directory(&parent).unwrap(),
        "new.stage",
        uid,
        uid,
        gid,
        || {
            write(&file, b"changed", 0o600);
            Ok(())
        },
    );
    assert!(result.is_err());
    assert!(parent.join("new.stage").is_dir());
    assert_eq!(fs::read(file).unwrap(), b"changed");
}
#[test]
fn occupied_target_and_repeated_success_never_overwrite() {
    let (_t, source, parent, uid, gid) = fixture();
    write(&source.join("credentials.db"), b"one", 0o600);
    stage(&source, &parent, uid, gid).unwrap();
    let before = fs::read(parent.join("new.stage/credentials.db")).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert_eq!(
        fs::read(parent.join("new.stage/credentials.db")).unwrap(),
        before
    );
    write(&source.join("credentials.db"), b"two", 0o600);
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert_eq!(
        fs::read(parent.join("new.stage/credentials.db")).unwrap(),
        b"one"
    );
}
#[test]
fn interrupted_existing_stage_is_preserved_and_new_attempt_can_succeed() {
    let (_t, source, parent, uid, gid) = fixture();
    write(&source.join("credentials.db"), b"fixture", 0o600);
    fs::create_dir(parent.join("new.stage")).unwrap();
    write(&parent.join("new.stage/partial"), b"interrupted", 0o600);
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert_eq!(
        fs::read(parent.join("new.stage/partial")).unwrap(),
        b"interrupted"
    );
    copy::copy_stage(
        &copy::open_directory(&source).unwrap(),
        &copy::open_directory(&parent).unwrap(),
        "other.stage",
        uid,
        uid,
        gid,
        || Ok(()),
    )
    .unwrap();
    assert_eq!(
        fs::read(parent.join("other.stage/credentials.db")).unwrap(),
        b"fixture"
    );
}
#[test]
fn file_symlink_and_directory_alias_are_rejected_without_copying_target() {
    let (_t, source, parent, uid, gid) = fixture();
    write(&source.join("real"), b"fixture", 0o600);
    symlink("real", source.join("alias")).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert!(!parent.join("new.stage").exists());
    symlink(&source, parent.join("source-alias")).unwrap();
    assert!(copy::open_directory(&parent.join("source-alias")).is_err());
}
#[test]
fn hardlinked_and_peer_writable_files_are_rejected() {
    let (_t, source, parent, uid, gid) = fixture();
    let file = source.join("db");
    write(&file, b"fixture", 0o600);
    fs::hard_link(&file, source.join("alias")).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
    fs::remove_file(source.join("alias")).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
}
#[test]
fn fifo_and_oversized_source_are_rejected() {
    let (_t, source, parent, uid, gid) = fixture();
    let fifo = source.join("pipe");
    let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    assert!(stage(&source, &parent, uid, gid).is_err());
    fs::remove_file(fifo).unwrap();
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(source.join("large"))
        .unwrap();
    file.set_len((32 << 20) + 1).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert!(!parent.join("new.stage").exists());
}
#[test]
fn source_owner_mismatch_is_not_accepted() {
    let (_t, source, parent, uid, gid) = fixture();
    write(&source.join("db"), b"fixture", 0o600);
    assert!(
        copy::copy_stage(
            &copy::open_directory(&source).unwrap(),
            &copy::open_directory(&parent).unwrap(),
            "new.stage",
            uid + 1,
            uid,
            gid,
            || Ok(())
        )
        .is_err()
    );
}
#[test]
fn atomic_receipt_ignores_interrupted_staging_and_preserves_final_conflict() {
    let t = tempfile::tempdir().unwrap();
    fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = t.path().join("receipt.json");
    write(&t.path().join(".interrupted.tmp"), b"partial", 0o600);
    atomic_json(t.path(), &path, &json!({"stage_only":true})).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
    assert!(atomic_json(t.path(), &path, &json!({"stage_only":false})).is_err());
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(path).unwrap()).unwrap()["stage_only"],
        true
    );
}
fn plan() -> Plan {
    let b = Bound {
        path: "/root/evidence.json".into(),
        sha256: "a".repeat(64),
    };
    Plan {
        schema: "horizon-idle-gcloud-copy-plan-v6".into(),
        owner: "/root".into(),
        primary_thread: PRIMARY.into(),
        epoch: 166,
        source: SOURCE.into(),
        source_identity: copy::Directory {
            device: 1,
            inode: 2,
            uid: 1001,
            gid: 1001,
            mode: 0o700,
        },
        source_group_review: b.clone(),
        target_parent: "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/config"
            .into(),
        target_parent_identity: copy::Directory {
            device: 1,
            inode: 3,
            uid: 1001,
            gid: 1003,
            mode: 0o700,
        },
        stage_leaf: "gcloud.recovery-fixture1.stage".into(),
        source_uid: 1001,
        target_uid: 1001,
        target_gid: 1001,
        fleet: b.clone(),
        stop_event: Bound {
            path: EVENT.into(),
            sha256: "b".repeat(64),
        },
        absence: b,
        closed_units: vec![original_unit(166)],
        intent: Path::new(OUT).join("166-fixture.intent.json"),
        receipt: Path::new(OUT).join("166-fixture.receipt.json"),
        stage_only_authorized: true,
        install_authorized: false,
        replay_launch_authorized: false,
        remote_mutations: false,
        resource_promise_ending_authorized: false,
    }
}
#[test]
fn scope_is_exact_and_never_installs_or_launches() {
    scope(&plan()).unwrap();
    let mut p = plan();
    p.source_identity.mode = 0o775;
    scope(&p).unwrap();
    let mut p = plan();
    p.source_identity.mode = 0o777;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.source_identity.gid = 1002;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.epoch = 165;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.stage_leaf = "gcloud.recovery-../live.stage".into();
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.install_authorized = true;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.replay_launch_authorized = true;
    assert!(scope(&p).is_err());
    let mut p = plan();
    p.target_parent = PathBuf::from(SOURCE);
    assert!(scope(&p).is_err());
}
#[test]
fn current_owner_or_queued_job_blocks_copy() {
    let n = json!({"Id":original_unit(166),"MainPID":"0","ControlPID":"0","NRestarts":"0","Job":"","ActiveState":"inactive","SubState":"dead"});
    closed(&n).unwrap();
    for (k, v) in [
        ("MainPID", "3"),
        ("ControlPID", "4"),
        ("NRestarts", "1"),
        ("Job", "44"),
        ("ActiveState", "active"),
    ] {
        let mut changed = n.clone();
        changed[k] = json!(v);
        assert!(closed(&changed).is_err());
    }
}
#[test]
fn fleet_claims_include_singletons_ranges_bootstraps_and_nested_rows() {
    assert!(claims_epoch(&json!([{"epoch":166}]), 166));
    assert!(claims_epoch(&json!({"range":"166"}), 166));
    assert!(claims_epoch(&json!({"range":"165-167"}), 166));
    assert!(claims_epoch(&json!({"bootstrap":{"epoch":166}}), 166));
    assert!(!claims_epoch(
        &json!([{"epoch":167},{"range":"168-172"}]),
        166
    ));
}
fn profile(
    source: &Path,
    parent: &Path,
    uid: u32,
    gid: u32,
    sole_gid: u32,
) -> Result<copy::Snapshot> {
    copy::copy_stage_profile(
        &copy::open_directory(source)?,
        &copy::open_directory(parent)?,
        "new.stage",
        uid,
        uid,
        gid,
        Some(sole_gid),
        || Ok(()),
    )
}
#[test]
fn reviewed_0775_source_directories_are_copied_privately_without_chmod_source() {
    let (_t, source, parent, uid, gid) = fixture();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
    fs::create_dir(source.join("legacy_credentials")).unwrap();
    fs::set_permissions(
        source.join("legacy_credentials"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    write(
        &source.join("credentials.db"),
        b"disposable-layout-fixture",
        0o600,
    );
    let before = fs::metadata(&source).unwrap();
    let result = profile(&source, &parent, uid, gid, gid).unwrap();
    let after = fs::metadata(&source).unwrap();
    assert_eq!(
        (before.mode(), before.ctime(), before.ctime_nsec()),
        (after.mode(), after.ctime(), after.ctime_nsec())
    );
    assert_eq!(after.mode() & 0o7777, 0o775);
    for path in [
        parent.join("new.stage"),
        parent.join("new.stage/legacy_credentials"),
    ] {
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, 0o700);
    }
    assert_eq!(
        fs::metadata(parent.join("new.stage/credentials.db"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        result.logical_equals(
            &copy::snapshot(
                &copy::open_directory(&parent.join("new.stage")).unwrap(),
                uid
            )
            .unwrap()
        )
    );
}
#[test]
fn root_fixture_exercises_real_chown_to_sol_and_private_target_readback() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "Root fixture qualification required"
    );
    let (_t, source, parent, uid, gid) = fixture();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
    write(
        &source.join("credentials.db"),
        b"disposable-syscall-fixture",
        0o600,
    );
    copy::copy_stage_profile(
        &copy::open_directory(&source).unwrap(),
        &copy::open_directory(&parent).unwrap(),
        "new.stage",
        uid,
        1001,
        1001,
        Some(gid),
        || Ok(()),
    )
    .unwrap();
    for path in [
        parent.join("new.stage"),
        parent.join("new.stage/credentials.db"),
    ] {
        let m = fs::metadata(path).unwrap();
        assert_eq!((m.uid(), m.gid()), (1001, 1001));
    }
    assert_eq!(
        fs::read(parent.join("new.stage/credentials.db")).unwrap(),
        b"disposable-syscall-fixture"
    );
}
#[test]
fn writable_source_directory_requires_the_exact_reviewed_group() {
    let (_t, source, parent, uid, gid) = fixture();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(stage(&source, &parent, uid, gid).is_err());
    assert!(profile(&source, &parent, uid, gid, gid + 1).is_err());
    assert!(!parent.join("new.stage").exists());
}
#[test]
fn sole_source_group_never_admits_world_write_or_writable_regular_files() {
    let (_t, source, parent, uid, gid) = fixture();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(profile(&source, &parent, uid, gid, gid).is_err());
    fs::set_permissions(&source, fs::Permissions::from_mode(0o775)).unwrap();
    write(&source.join("credentials.db"), b"fixture", 0o660);
    assert!(profile(&source, &parent, uid, gid, gid).is_err());
    assert!(!parent.join("new.stage").exists());
}
#[test]
fn reviewed_sdk_0664_files_copy_as_0644_without_changing_source_or_credentials() {
    let (_t, source, parent, uid, gid) = fixture();
    write(&source.join("active_config"), b"default", 0o664);
    write(
        &source.join("credentials.db"),
        b"disposable-credentials",
        0o600,
    );
    let before = fs::metadata(source.join("active_config")).unwrap();
    let captured = profile(&source, &parent, uid, gid, gid).unwrap();
    let after = fs::metadata(source.join("active_config")).unwrap();
    assert_eq!(
        (before.mode(), before.ctime(), before.ctime_nsec()),
        (after.mode(), after.ctime(), after.ctime_nsec())
    );
    assert_eq!(after.mode() & 0o7777, 0o664);
    assert_eq!(
        fs::metadata(parent.join("new.stage/active_config"))
            .unwrap()
            .mode()
            & 0o7777,
        0o644
    );
    assert_eq!(
        fs::metadata(parent.join("new.stage/credentials.db"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    assert!(
        captured.logical_equals(
            &copy::snapshot(
                &copy::open_directory(&parent.join("new.stage")).unwrap(),
                uid
            )
            .unwrap()
        )
    );
}
#[test]
fn actual_sol_source_can_capture_only_readonly_root_sdk_logs() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    let (_t, source, parent, _, _) = fixture();
    fs::create_dir(source.join("logs")).unwrap();
    fs::set_permissions(source.join("logs"), fs::Permissions::from_mode(0o775)).unwrap();
    write(&source.join("credentials.db"), b"disposable-db", 0o600);
    write(&source.join("logs/probe.log"), b"disposable-log", 0o644);
    for path in [
        &source,
        &source.join("logs"),
        &source.join("credentials.db"),
    ] {
        let file = File::open(path).unwrap();
        assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 1001, 1001) }, 0);
    }
    let captured = profile(&source, &parent, 1001, 1001, 1001).unwrap();
    let copied = copy::snapshot(
        &copy::open_directory(&parent.join("new.stage")).unwrap(),
        1001,
    )
    .unwrap();
    assert!(captured.logical_equals(&copied));
    let log = fs::metadata(parent.join("new.stage/logs/probe.log")).unwrap();
    assert_eq!(
        (log.uid(), log.gid(), log.mode() & 0o7777),
        (1001, 1001, 0o644)
    );
    assert_eq!(
        fs::metadata(source.join("logs/probe.log")).unwrap().uid(),
        0
    );
}
#[test]
fn root_owned_non_log_and_writable_root_log_sources_remain_rejected() {
    assert_eq!(unsafe { libc::geteuid() }, 0);
    for (relative, mode) in [
        ("credentials.db", 0o644),
        ("logs/probe.log", 0o666),
        ("logs/probe.log", 0o640),
    ] {
        let (_t, source, parent, _, _) = fixture();
        fs::create_dir(source.join("logs")).unwrap();
        write(&source.join(relative), b"disposable-rejected", mode);
        for path in [&source, &source.join("logs")] {
            let file = File::open(path).unwrap();
            assert_eq!(unsafe { libc::fchown(file.as_raw_fd(), 1001, 1001) }, 0);
        }
        assert!(profile(&source, &parent, 1001, 1001, 1001).is_err());
        assert!(!parent.join("new.stage").exists());
    }
}
const PASSWD: &str = "root:x:0:0:root:/root:/bin/bash\nsol:x:1001:1001:sol:/home/sol:/bin/zsh\n";
const GROUPS: &str = "root:x:0:\nsol:x:1001:\n";
const NSS: &str = "passwd: files systemd\ngroup: files systemd\nshadow: files\n";
#[test]
fn sole_local_group_accepts_only_one_primary_owner_and_optional_same_supplementary_owner() {
    group::sole_local_group(PASSWD, GROUPS, NSS, 1001, 1001, "sol", "sol").unwrap();
    group::sole_local_group(PASSWD, "sol:x:1001:sol\n", NSS, 1001, 1001, "sol", "sol").unwrap();
    group::sole_local_group(
        PASSWD,
        GROUPS,
        "passwd: files\ngroup: files\ninitgroups: files\n",
        1001,
        1001,
        "sol",
        "sol",
    )
    .unwrap();
}
#[test]
fn source_group_identity_rejects_other_primary_supplementary_aliased_and_missing_members() {
    for passwd in [
        format!("{PASSWD}peer:x:1002:1001:peer:/home/peer:/bin/bash\n"),
        PASSWD.replace("sol:x:1001:1001", "sol:x:1002:1001"),
        format!("{PASSWD}alias:x:1001:1002:alias:/home/alias:/bin/bash\n"),
    ] {
        assert!(group::sole_local_group(&passwd, GROUPS, NSS, 1001, 1001, "sol", "sol").is_err());
    }
    for groups in [
        "sol:x:1001:peer\n",
        "sol:x:1001:sol,peer\n",
        "sol:x:1001:sol,sol\n",
        "other:x:1001:\n",
        "sol:x:1002:\n",
        "sol:x:1001:\nalias:x:1001:\n",
    ] {
        assert!(group::sole_local_group(PASSWD, groups, NSS, 1001, 1001, "sol", "sol").is_err());
    }
}
#[test]
fn source_group_identity_rejects_external_action_duplicate_and_absent_nss_policies() {
    for nss in [
        "passwd: files\ngroup: files sss\n",
        "passwd: files ldap\ngroup: files\n",
        "passwd: files\ngroup: files [SUCCESS=return]\n",
        "passwd: files\ngroup: files\ninitgroups: ldap\n",
        "passwd: files\ngroup: files\ngroup: systemd\n",
        "passwd: files\n",
    ] {
        assert!(group::sole_local_group(PASSWD, GROUPS, nss, 1001, 1001, "sol", "sol").is_err());
    }
}
fn group_review() -> SourceGroupReview {
    let b = |p: &str| Bound {
        path: p.into(),
        sha256: "a".repeat(64),
    };
    SourceGroupReview {
        schema: "horizon-idle-gcloud-sole-source-group-review-v1".into(),
        owner: "/root".into(),
        primary_thread: PRIMARY.into(),
        recorded_unix_seconds: 1000,
        source: SOURCE.into(),
        source_uid: 1001,
        source_gid: 1001,
        account_name: "sol".into(),
        group_name: "sol".into(),
        nss_effective_membership_resolved_to_local_files: true,
        no_other_primary_or_supplementary_members: true,
        passwd: b("/etc/passwd"),
        group: b("/etc/group"),
        nsswitch: b("/etc/nsswitch.conf"),
    }
}
#[test]
fn source_group_review_rejects_stale_future_foreign_and_unreviewed_bindings() {
    source_group_scope(&group_review(), 1300).unwrap();
    assert!(source_group_scope(&group_review(), 1301).is_err());
    assert!(source_group_scope(&group_review(), 999).is_err());
    let mut r = group_review();
    r.no_other_primary_or_supplementary_members = false;
    assert!(source_group_scope(&r, 1100).is_err());
    let mut r = group_review();
    r.nss_effective_membership_resolved_to_local_files = false;
    assert!(source_group_scope(&r, 1100).is_err());
    let mut r = group_review();
    r.group.path = "/tmp/group".into();
    assert!(source_group_scope(&r, 1100).is_err());
    let mut r = group_review();
    r.source_gid = 1002;
    assert!(source_group_scope(&r, 1100).is_err());
    let mut r = group_review();
    r.primary_thread = "different".into();
    assert!(source_group_scope(&r, 1100).is_err());
}
