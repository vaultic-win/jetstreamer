use super::*;
use std::os::unix::fs::symlink;
fn fixture() -> (tempfile::TempDir, PathBuf, u32) {
    let d = tempfile::tempdir().unwrap();
    let r = d.path().join("debug");
    fs::create_dir(&r).unwrap();
    let uid = fs::metadata(&r).unwrap().uid();
    (d, r, uid)
}
fn elf(path: &Path) {
    fs::write(path, b"\x7fELFcompiler fixture").unwrap();
}
fn plan() -> Plan {
    Plan {
        schema: PROFILE.into(),
        source_commit: "a".repeat(40),
        cargo_lock_sha256: "b".repeat(64),
        indirect_review: Bound {
            path: "/sealed/review.json".into(),
            sha256: "c".repeat(64),
        },
        output: CHECK.into(),
        prior_check: None,
    }
}
#[test]
fn closed_profile_rejects_foreign_paths_and_old_schemas() {
    let mut p = plan();
    validate_plan(&p).unwrap();
    p.schema = "other".into();
    assert!(validate_plan(&p).is_err());
    p.schema = PROFILE.into();
    p.output = "/tmp/check.json".into();
    assert!(validate_plan(&p).is_err());
    p.output = EXECUTE.into();
    assert!(validate_plan(&p).is_err());
    p.prior_check = Some(Bound {
        path: CHECK.into(),
        sha256: "d".repeat(64),
    });
    validate_plan(&p).unwrap();
    p.prior_check.as_mut().unwrap().path = "/other/check.json".into();
    assert!(validate_plan(&p).is_err());
    assert!(serde_json::from_value::<Plan>(json!({"schema":PROFILE,"source_commit":"a".repeat(40),"cargo_lock_sha256":"b".repeat(64),"indirect_review":{"path":"/sealed/review.json","sha256":"c".repeat(64)},"output":CHECK,"targets":["/arbitrary"]})).is_err());
}
#[test]
fn internal_hardlinks_are_retired_once_and_locks_directories_preserved() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    fs::create_dir(r.join("empty")).unwrap();
    let a = r.join("deps/node-1111111111111111");
    elf(&a);
    fs::set_permissions(&a, fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(&a, r.join("deps/node-0123456789abcdef")).unwrap();
    fs::hard_link(&a, r.join("deps/node-fedcba9876543210")).unwrap();
    fs::write(r.join(".cargo-lock"), b"").unwrap();
    fs::write(r.join(".cargo-build-lock"), b"").unwrap();
    let before = cache::select(&r, uid, false).unwrap();
    assert_eq!(before.selected.len(), 1);
    assert_eq!(before.selected[0].paths.len(), 3);
    assert_eq!(
        before.selected_allocated_bytes,
        fs::metadata(&a).unwrap().blocks() * 512
    );
    let after = cache::retire(&before, uid, false).unwrap();
    assert!(after.selected.is_empty());
    assert_eq!(after.preserved, before.preserved);
    assert!(r.join("empty").is_dir());
    assert!(r.join("deps").is_dir());
    assert!(r.join(".cargo-lock").is_file());
}
#[test]
fn external_hardlink_groups_are_preserved() {
    let (d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    fs::hard_link(r.join("deps/a.o"), r.join("deps/b.o")).unwrap();
    fs::hard_link(r.join("deps/a.o"), d.path().join("outside.o")).unwrap();
    let before = cache::select(&r, uid, false).unwrap();
    assert!(before.selected.is_empty());
    assert_eq!(before.preserved.len(), 2);
    cache::retire(&before, uid, false).unwrap();
    assert_eq!(fs::metadata(d.path().join("outside.o")).unwrap().nlink(), 3);
}
#[test]
fn unknown_alias_preserves_whole_group() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    fs::hard_link(r.join("deps/a.o"), r.join("keep-evidence")).unwrap();
    let before = cache::select(&r, uid, false).unwrap();
    assert!(before.selected.is_empty());
    assert_eq!(before.preserved.len(), 2);
}
#[test]
fn replacement_before_execute_preserves_every_file() {
    let (d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    elf(&r.join("deps/b.o"));
    let before = cache::select(&r, uid, false).unwrap();
    fs::rename(r.join("deps/a.o"), d.path().join("old.o")).unwrap();
    elf(&r.join("deps/a.o"));
    assert!(cache::retire(&before, uid, false).is_err());
    assert!(r.join("deps/a.o").is_file());
    assert!(r.join("deps/b.o").is_file());
}
#[test]
fn new_hardlink_after_census_refuses_group() {
    let (d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    let before = cache::select(&r, uid, false).unwrap();
    fs::hard_link(r.join("deps/a.o"), d.path().join("new.o")).unwrap();
    assert!(cache::unlink_group(&before, &before.selected[0]).is_err());
    assert!(r.join("deps/a.o").is_file());
}
#[test]
fn parent_replacement_cannot_redirect_unlink() {
    let (d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    let before = cache::select(&r, uid, false).unwrap();
    fs::rename(r.join("deps"), d.path().join("old-deps")).unwrap();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    assert!(cache::unlink_group(&before, &before.selected[0]).is_err());
    assert!(r.join("deps/a.o").is_file());
    assert!(d.path().join("old-deps/a.o").is_file());
}
#[test]
fn symlinks_are_preserved_without_following_and_cannot_redirect_unlink() {
    let (d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    let before = cache::select(&r, uid, false).unwrap();
    fs::rename(r.join("deps"), d.path().join("old-deps")).unwrap();
    symlink(d.path().join("old-deps"), r.join("deps")).unwrap();
    let linked_directory = cache::select(&r, uid, false).unwrap();
    assert!(linked_directory.selected.is_empty());
    assert!(linked_directory.preserved.contains_key(Path::new("deps")));
    assert!(cache::unlink_group(&before, &before.selected[0]).is_err());
    fs::remove_file(r.join("deps")).unwrap();
    fs::create_dir(r.join("deps")).unwrap();
    symlink(d.path().join("old-deps/a.o"), r.join("deps/a.o")).unwrap();
    let linked_file = cache::select(&r, uid, false).unwrap();
    assert!(linked_file.selected.is_empty());
    let original = fs::read(d.path().join("old-deps/a.o")).unwrap();
    cache::retire(&linked_file, uid, false).unwrap();
    assert!(
        fs::symlink_metadata(r.join("deps/a.o"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(d.path().join("old-deps/a.o")).unwrap(), original);
    fs::remove_file(r.join("deps/a.o")).unwrap();
    symlink("/a/different/target", r.join("deps/a.o")).unwrap();
    assert!(cache::retire(&linked_file, uid, false).is_err());
}
#[test]
fn archives_and_replay_data_are_rejected() {
    let (_d, r, uid) = fixture();
    for name in [
        "epoch-169.jet",
        "epoch-169.jet.sha256",
        "snapshot-1.tar.zst",
        "snapshot-2.tar.bz2",
    ] {
        fs::write(r.join(name), b"preserve").unwrap();
        assert!(cache::select(&r, uid, false).is_err());
        fs::remove_file(r.join(name)).unwrap();
    }
    fs::create_dir(r.join("receipts")).unwrap();
    assert!(cache::select(&r, uid, false).is_err());
}
#[test]
fn unknown_text_sources_and_noncompiler_executables_are_preserved() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    fs::write(r.join("deps/pretend.o"), b"not ELF").unwrap();
    fs::write(r.join("generated.rs"), b"fn main(){}").unwrap();
    fs::write(r.join("deps/custom-0123456789abcdef"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(
        r.join("deps/custom-0123456789abcdef"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let b = cache::select(&r, uid, false).unwrap();
    assert!(b.selected.is_empty());
    assert_eq!(b.preserved.len(), 3);
}
#[test]
fn metadata_drift_and_special_members_fail_closed() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    let before = cache::select(&r, uid, false).unwrap();
    fs::write(r.join("deps/a.o"), b"\x7fELFlonger changed content").unwrap();
    assert!(cache::retire(&before, uid, false).is_err());
    fs::set_permissions(r.join("deps/a.o"), fs::Permissions::from_mode(0o666)).unwrap();
    assert!(cache::select(&r, uid, false).is_err());
    fs::remove_file(r.join("deps/a.o")).unwrap();
    // A FIFO exercises the same special-inode rejection without AF_UNIX's
    // 108-byte pathname limit in the deliberately long isolated TMPDIR.
    let special = std::ffi::CString::new(r.join("deps/a.o").as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(special.as_ptr(), 0o600) }, 0);
    assert!(cache::select(&r, uid, false).is_err());
}
#[test]
fn postcheck_detects_new_files_and_changed_retained_files() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    elf(&r.join("deps/a.o"));
    fs::write(r.join("keep.txt"), b"retained").unwrap();
    let before = cache::select(&r, uid, false).unwrap();
    cache::retire(&before, uid, false).unwrap();
    elf(&r.join("deps/new.o"));
    assert!(cache::verify_after(&before, uid, false).is_err());
    fs::remove_file(r.join("deps/new.o")).unwrap();
    cache::verify_after(&before, uid, false).unwrap();
    fs::write(r.join("keep.txt"), b"changed").unwrap();
    assert!(cache::verify_after(&before, uid, false).is_err());
}
#[test]
fn release_build_compiler_products_are_selected_but_logs_remain() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("crate-0123456789abcdef")).unwrap();
    let b = r.join("crate-0123456789abcdef/build-script-build");
    elf(&b);
    fs::set_permissions(&b, fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(
        &b,
        r.join("crate-0123456789abcdef/build_script_build-0123456789abcdef"),
    )
    .unwrap();
    fs::write(r.join("crate-0123456789abcdef/output"), b"cargo:output").unwrap();
    let before = cache::select(&r, uid, true).unwrap();
    assert_eq!(before.selected.len(), 1);
    cache::retire(&before, uid, true).unwrap();
    assert!(r.join("crate-0123456789abcdef/output").is_file());
}
#[test]
fn prior_check_binds_selection_source_review_and_image() {
    let good = json!({"schema":SCHEMA,"profile":PROFILE,"source_commit":"a","cargo_lock_sha256":"b","self_sha256":"c","selection":[1],"source_proof":{"patch":"x"},"group":1,"mount_census_sha256":"d","indirect_review":{"sha256":"e"},"cache_unused_proven":true});
    prior_matches(&good, &good).unwrap();
    for k in [
        "selection",
        "source_proof",
        "indirect_review",
        "self_sha256",
        "cache_unused_proven",
    ] {
        let mut bad = good.clone();
        bad[k] = Value::Null;
        assert!(prior_matches(&good, &bad).is_err());
    }
}
#[test]
fn source_and_receipt_reader_bounds_reject_alias_and_oversize() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("source");
    fs::write(&p, b"12345").unwrap();
    assert!(hash_file(&p, 4).is_err());
    hash_file(&p, 5).unwrap();
    symlink(&p, d.path().join("alias")).unwrap();
    assert!(hash_file(&d.path().join("alias"), 5).is_err());
    fs::hard_link(&p, d.path().join("hardlink")).unwrap();
    assert!(hash_file(&p, 5).is_err());
    assert!(
        bound_json(&Bound {
            path: p,
            sha256: "invalid".into()
        })
        .is_err()
    );
}
#[test]
fn indirect_closure_requires_all_classes_and_actual_inputs() {
    let good = json!({"schema":REVIEW_SCHEMA,"owner":"/root","targets":TARGETS.iter().map(|t|t.0).collect::<Vec<_>>(),"no_current_or_staged_consumer":true,"no_reopen_until_completion_reconciled":true,"terminal_owners_inspected":true,"retired_units":[],"indirect_dependencies":[],"classes":CLASSES.iter().map(|c|json!({"class":c,"no_local_outputs_required":true,"reason":"actual retired input inspection","inspected_inputs":[{"path":"/sealed/input","sha256":"a".repeat(64)}]})).collect::<Vec<_>>()});
    validate_review(&good).unwrap();
    let mut bad = good.clone();
    bad["classes"].as_array_mut().unwrap().pop();
    assert!(validate_review(&bad).is_err());
    let mut bad = good;
    bad["classes"][0]["inspected_inputs"] = json!([]);
    assert!(validate_review(&bad).is_err());
}
#[test]
fn review_requires_explicit_dependency_census_separate_from_evidence() {
    let mut review = json!({"schema":REVIEW_SCHEMA,"owner":"/root","targets":TARGETS.iter().map(|t|t.0).collect::<Vec<_>>(),"no_current_or_staged_consumer":true,"no_reopen_until_completion_reconciled":true,"terminal_owners_inspected":true,"retired_units":[],"classes":CLASSES.iter().map(|c|json!({"class":c,"no_local_outputs_required":true,"reason":"current input is independent of compiler cache","inspected_inputs":[{"path":"/sealed/current-plan","sha256":"a".repeat(64)}]})).collect::<Vec<_>>()});
    assert!(validate_review(&review).is_err());
    review["indirect_dependencies"] = json!([]);
    validate_review(&review).unwrap();
    review["indirect_dependencies"] = Value::Null;
    assert!(validate_review(&review).is_err());
}
#[test]
fn nested_mount_or_bind_alias_is_rejected() {
    mounts::reject_incremental_mounts(
        b"1 0 8:1 / / rw - ext4 /dev/root rw\n",
        Path::new(TARGETS[0].0),
    )
    .unwrap();
    for path in [TARGETS[0].0.to_owned(), format!("{}/deps", TARGETS[0].0)] {
        let line = format!("2 1 8:1 / {path} rw - ext4 /dev/root rw\n");
        assert!(
            mounts::reject_incremental_mounts(line.as_bytes(), Path::new(TARGETS[0].0)).is_err()
        );
    }
}

#[test]
fn audit_profile_selects_exact_six_roots_and_all_existing_cargo_locks() {
    assert_eq!(TARGETS.len(), 6);
    assert!(
        TARGETS
            .iter()
            .all(|(_, _, mode, build)| *mode == 0o775 && !build)
    );
    assert_eq!(LOCKS.len(), 19);
    assert_eq!(LOCKS[0], (LOCK, 64512, 101135013, 1003, 0o600));
    for (root, _, _, _) in TARGETS {
        for name in [".cargo-lock", ".cargo-build-lock", ".cargo-artifact-lock"] {
            let path = format!("{root}/{name}");
            assert_eq!(LOCKS.iter().filter(|r| r.0 == path).count(), 1);
        }
    }
    assert_eq!(evidence::RETAINED_IMAGES.len(), 7);
    for (image, _) in evidence::RETAINED_IMAGES {
        assert!(
            TARGETS
                .iter()
                .any(|r| Path::new(image).parent() == Some(Path::new(r.0)))
        );
    }
    let mut p = plan();
    p.schema = "horizon-holding141-build-partial-cleanup-plan-v1".into();
    assert!(validate_plan(&p).is_err());
    p.schema = PROFILE.into();
    p.output = "/var/lib/jetstreamer/holding141-build-check-20261119-v1/check.json".into();
    assert!(validate_plan(&p).is_err());
}

#[test]
fn terminal_owner_census_must_be_explicit_and_names_closed() {
    let good = json!({"schema":REVIEW_SCHEMA,"owner":"/root","targets":TARGETS.iter().map(|t|t.0).collect::<Vec<_>>(),"no_current_or_staged_consumer":true,"no_reopen_until_completion_reconciled":true,"terminal_owners_inspected":true,"retired_units":[],"indirect_dependencies":[],"classes":CLASSES.iter().map(|c|json!({"class":c,"no_local_outputs_required":true,"reason":"sealed native owner census","inspected_inputs":[{"path":"/sealed/owners","sha256":"a".repeat(64)}]})).collect::<Vec<_>>()});
    validate_review(&good).unwrap();
    for value in [
        Value::Null,
        json!(["--all"]),
        json!(["../../other.service"]),
        json!(["a.socket"]),
        json!(["a.service", "a.service"]),
    ] {
        let mut bad = good.clone();
        bad["retired_units"] = value;
        assert!(validate_review(&bad).is_err());
    }
    let mut bad = good.clone();
    bad["terminal_owners_inspected"] = false.into();
    assert!(validate_review(&bad).is_err());
    let mut valid = good;
    valid["retired_units"] = json!([
        "historical-test.service",
        "historical-test.timer",
        "historical-test.path"
    ]);
    validate_review(&valid).unwrap();
}

#[test]
fn generated_sources_fingerprints_and_depfiles_survive_partial_retirement() {
    let (_d, r, uid) = fixture();
    for dir in [
        "deps",
        ".fingerprint/crate-0123456789abcdef",
        "build/crate-0123456789abcdef/out",
    ] {
        fs::create_dir_all(r.join(dir)).unwrap();
    }
    elf(&r.join("deps/libcrate.so"));
    elf(&r.join(".fingerprint/crate-0123456789abcdef/retained.o"));
    fs::write(r.join("deps/crate.d"), b"source.rs: include.rs\n").unwrap();
    fs::write(
        r.join("build/crate-0123456789abcdef/out/generated.rs"),
        b"const A: u32 = 1;\n",
    )
    .unwrap();
    fs::write(
        r.join("build/crate-0123456789abcdef/output"),
        b"cargo:rerun-if-changed=source.rs\n",
    )
    .unwrap();
    let before = cache::select(&r, uid, false).unwrap();
    assert_eq!(before.selected.len(), 1);
    cache::retire(&before, uid, false).unwrap();
    for path in [
        ".fingerprint/crate-0123456789abcdef/retained.o",
        "deps/crate.d",
        "build/crate-0123456789abcdef/out/generated.rs",
        "build/crate-0123456789abcdef/output",
    ] {
        assert!(r.join(path).is_file());
    }
}

#[test]
fn historical_top_level_workers_and_all_hardlink_aliases_are_preserved() {
    let (_d, r, uid) = fixture();
    fs::create_dir(r.join("deps")).unwrap();
    let worker = r.join("jetstreamer-historical-worker-v1-4-25");
    elf(&worker);
    fs::set_permissions(&worker, fs::Permissions::from_mode(0o700)).unwrap();
    let alias = r.join("deps/worker-0123456789abcdef");
    fs::hard_link(&worker, &alias).unwrap();
    elf(&r.join("deps/disposable.o"));
    let before = cache::select(&r, uid, false).unwrap();
    assert_eq!(before.selected.len(), 1);
    assert!(
        before
            .preserved
            .contains_key(Path::new("jetstreamer-historical-worker-v1-4-25"))
    );
    assert!(
        before
            .preserved
            .contains_key(Path::new("deps/worker-0123456789abcdef"))
    );
    cache::retire(&before, uid, false).unwrap();
    assert_eq!(fs::read(&worker).unwrap(), fs::read(&alias).unwrap());
    assert_eq!(fs::metadata(&worker).unwrap().nlink(), 2);
    assert!(!r.join("deps/disposable.o").exists());
}

#[test]
fn dependency_root_cleanup_preserves_external_image_and_incremental_aliases() {
    let (d, root, uid) = fixture();
    let deps = root.join("deps");
    fs::create_dir(&deps).unwrap();
    let executable = deps.join("jetstreamer_r2-0123456789abcdef");
    elf(&executable);
    fs::hard_link(&executable, root.join("jetstreamer-r2")).unwrap();
    let shared = deps.join("libcrate.rmeta");
    fs::write(&shared, b"rust\0metadata").unwrap();
    fs::hard_link(&shared, d.path().join("incremental.rmeta")).unwrap();
    elf(&deps.join("disposable.o"));
    fs::write(deps.join("crate.d"), b"source: source.rs").unwrap();
    let before = cache::select(&deps, uid, true).unwrap();
    assert_eq!(before.selected.len(), 1);
    cache::retire(&before, uid, true).unwrap();
    assert!(executable.exists() && shared.exists() && deps.join("crate.d").exists());
    assert_eq!(fs::metadata(executable).unwrap().nlink(), 2);
}

#[test]
fn cross_target_hardlinks_are_preserved_by_each_independent_selection() {
    let (d, a, uid) = fixture();
    let b = d.path().join("release");
    fs::create_dir_all(a.join("deps")).unwrap();
    fs::create_dir_all(b.join("deps")).unwrap();
    elf(&a.join("deps/shared.o"));
    fs::hard_link(a.join("deps/shared.o"), b.join("deps/shared.o")).unwrap();
    elf(&a.join("deps/disposable.o"));
    for root in [&a, &b] {
        let selected = cache::select(root, uid, false).unwrap();
        assert!(selected.preserved.contains_key(Path::new("deps/shared.o")));
        cache::retire(&selected, uid, false).unwrap();
    }
    assert_eq!(fs::metadata(a.join("deps/shared.o")).unwrap().nlink(), 2);
    assert_eq!(
        fs::read(a.join("deps/shared.o")).unwrap(),
        fs::read(b.join("deps/shared.o")).unwrap()
    );
    assert!(!a.join("deps/disposable.o").exists());
}
