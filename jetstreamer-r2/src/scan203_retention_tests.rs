//! Pure parser/policy tests plus opt-in tiny native filesystem fixtures.
//! No test reads the actual203/204 body, polls host resources or contacts R2.
use super::*;

#[test]
fn scan203_retention_missing_command_requires_the_exact_typed_empty_array() {
    assert!(typed_empty_commands(br#"{"type":"a(sasbttttuii)","data":[]}"#).is_ok());
    for bad in [
        br#"{"type":"as","data":[]}"#.as_slice(),
        br#"{"type":"a(sasbttttuii)","data":[[]]}"#,
        br#"{"type":"a(sasbttttuii)"}"#,
        br#"{"type":"a(sasbttttuii)","data":[],"unknown":true}"#,
        b"",
    ] {
        assert!(typed_empty_commands(bad).is_err());
    }
}

#[test]
#[ignore = "real typed D-Bus read needs separately admitted fixed native fixture"]
fn scan203_retention_native_actual_empty_command_property_has_typed_proof() {
    require_native_root();
    let proof = empty_manager_command(
        "horizon-qualify-scan203-native-tests938-v2.service",
        "ExecStartPost",
    )
    .unwrap();
    typed_empty_commands(proof.as_bytes()).unwrap();
}

fn bound(path: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: "0".repeat(64),
    }
}
fn stamp(inode: u64, length: u64) -> Stamp {
    Stamp {
        device: 66305,
        inode,
        length,
        uid: 0,
        gid: 0,
        mode: 0o400,
        links: 1,
        mtime_ns: 1,
        ctime_ns: 1,
    }
}
pub(super) fn plan() -> Plan {
    Plan {
        schema: "jetstreamer-scan203-retention-inspection-plan-v1".into(),
        parent_identity: Parent {
            device: 66305,
            inode: 1,
            uid: 0,
            gid: 0,
            mode: 0o700,
        },
        source_identity: stamp(10_796_937, LENGTH203),
        retained204_identity: stamp(10_796_926, LENGTH204),
        normal203_gates: bound("/gates"),
        normal203_completion: bound("/completion"),
        verification203: bound("/verification"),
        publication203: bound("/publication"),
        remote_receipt203: bound("/receipt"),
        full204_outcome: bound("/full204"),
        executor_recipe: bound(&format!("/etc/systemd/system/{UNIT}")),
        actors: ACTORS
            .iter()
            .enumerate()
            .map(|(index, n)| {
                (
                    n.to_string(),
                    Actor {
                        invocation_id: ORIGINALS[index].0.into(),
                        original_terminal: Bound {
                            path: ORIGINALS[index].1.into(),
                            sha256: ORIGINALS[index].2.into(),
                        },
                    },
                )
            })
            .collect(),
        historical_recipes: vec![],
        dependency_metadata: DEPENDENCIES
            .iter()
            .map(|(path, sha)| Bound {
                path: (*path).into(),
                sha256: (*sha).into(),
            })
            .collect(),
    }
}
fn terminal_properties(name: &str) -> BTreeMap<String, String> {
    [
        ("Id", name),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("SubState", "dead"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("InvocationID", ""),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Job", ""),
        ("ControlGroup", ""),
        ("Triggers", ""),
        ("TriggeredBy", ""),
        ("OnSuccess", ""),
        ("OnFailure", ""),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

#[test]
fn scan203_retention_fixed_profile_excludes204_canonical_or_other_inode() {
    let mut p = plan();
    assert!(scope(&p).is_ok());
    p.source_identity.inode = 10_796_926;
    assert!(scope(&p).is_err());
    p = plan();
    p.source_identity.length = LENGTH204;
    assert!(scope(&p).is_err());
    p = plan();
    p.source_identity.inode = 230_572_721;
    assert!(scope(&p).is_err());
}
#[test]
fn scan203_retention_preserves_exact204_dependency_identity() {
    let mut p = plan();
    p.retained204_identity.inode = 510_665;
    assert!(scope(&p).is_err());
    p = plan();
    p.retained204_identity.device += 1;
    assert!(scope(&p).is_err());
    p = plan();
    p.retained204_identity.links = 2;
    assert!(scope(&p).is_err());
}
#[test]
fn scan203_retention_rejects_writable_foreign_or_linked203() {
    for p in [
        Stamp {
            mode: 0o600,
            ..stamp(10_796_937, LENGTH203)
        },
        Stamp {
            uid: 1000,
            ..stamp(10_796_937, LENGTH203)
        },
        Stamp {
            links: 2,
            ..stamp(10_796_937, LENGTH203)
        },
    ] {
        assert!(p.fixed(10_796_937, LENGTH203).is_err());
    }
}
#[test]
fn scan203_retention_requires_each_original_consumer_and_separate_executor() {
    let mut p = plan();
    p.actors.remove(ACTORS[0]);
    assert!(scope(&p).is_err());
    p = plan();
    p.actors.insert(
        UNIT.into(),
        Actor {
            invocation_id: "a".repeat(32),
            original_terminal: bound("/self"),
        },
    );
    assert!(scope(&p).is_err());
}
#[test]
fn scan203_retention_exact_historical_pair_cannot_borrow_another_actor_iid() {
    let v = json!({"nested":[{"unit":ACTORS[0],"invocation_id":"a".repeat(32)}]});
    assert!(historical_pair(&v, ACTORS[0], &"a".repeat(32)));
    assert!(!historical_pair(&v, ACTORS[1], &"a".repeat(32)));
    assert!(!historical_pair(&v, ACTORS[0], &"b".repeat(32)));
}
#[test]
fn scan203_retention_cleared_iid_is_terminal_only_with_complete_properties() {
    let mut p = terminal_properties(ACTORS[0]);
    assert!(terminal(&p, ACTORS[0], &"a".repeat(32)).is_ok());
    p.remove("Restart");
    assert!(terminal(&p, ACTORS[0], &"a".repeat(32)).is_err());
    p = terminal_properties(ACTORS[0]);
    p.insert("InvocationID".into(), "b".repeat(32));
    assert!(terminal(&p, ACTORS[0], &"a".repeat(32)).is_err());
}
#[test]
fn scan203_retention_any_live_job_trigger_restart_or_cgroup_blocks() {
    for (k, v) in [
        ("MainPID", "9"),
        ("ControlPID", "9"),
        ("NRestarts", "1"),
        ("Restart", "on-failure"),
        ("Job", "99"),
        ("Triggers", "next.service"),
        ("TriggeredBy", "watch.timer"),
        ("ControlGroup", "/system.slice/live.service"),
        ("OnFailure", "retry.service"),
    ] {
        let mut p = terminal_properties(ACTORS[0]);
        p.insert(k.into(), v.into());
        assert!(
            terminal(&p, ACTORS[0], &"a".repeat(32)).is_err(),
            "accepted {k}"
        );
    }
}
#[test]
fn scan203_retention_failed_historical_actor_can_close_but_active_exited_does_not_fake_closure() {
    let mut p = terminal_properties(ACTORS[0]);
    p.insert("ActiveState".into(), "failed".into());
    p.insert("SubState".into(), "failed".into());
    assert!(terminal(&p, ACTORS[0], &"a".repeat(32)).is_ok());
    p.insert("ActiveState".into(), "active".into());
    p.insert("SubState".into(), "exited".into());
    assert!(terminal(&p, ACTORS[0], &"a".repeat(32)).is_err());
}
#[test]
fn scan203_retention_timer_interface_omissions_are_typed() {
    let name = "old.timer";
    let mut p = terminal_properties(name);
    for k in ["MainPID", "ControlPID", "NRestarts", "Restart"] {
        p.remove(k);
    }
    assert!(terminal(&p, name, &"a".repeat(32)).is_ok());
    p.insert("NRestarts".into(), "1".into());
    assert!(terminal(&p, name, &"a".repeat(32)).is_err());
}
#[test]
fn scan203_retention_manager_parser_rejects_duplicate_malformed_oversized() {
    assert!(properties(b"Id=a\nId=b\n").is_err());
    assert!(properties(b"broken\n").is_err());
    assert!(properties(&vec![b'x'; 131073]).is_err());
    assert_eq!(properties(b"Id=a\nJob=\n").unwrap()["Job"], "");
}
#[test]
fn scan203_retention_path_tokens_do_not_confuse_siblings_or_prefixes() {
    assert!(references(
        format!("'{SOURCE}'\0").as_bytes(),
        SOURCE.as_bytes()
    ));
    assert!(references(
        format!("{SOURCE} (deleted)").as_bytes(),
        SOURCE.as_bytes()
    ));
    assert!(!references(
        format!("{SOURCE}.bak").as_bytes(),
        SOURCE.as_bytes()
    ));
    assert!(!references(b"/old-scratch-store8", b"/old-scratch"));
    assert!(!references(b"prefixold.service", b"old.service"));
}

#[test]
fn scan203_retention_directory_options_are_consumers_but_retained204_filename_is_distinct() {
    assert!(directory_argument(
        format!("tool\0--directory={ROOT}\0").as_bytes(),
        Path::new(ROOT)
    ));
    assert!(directory_argument(
        format!("tool\0{ROOT}/\0").as_bytes(),
        Path::new(ROOT)
    ));
    assert!(!directory_argument(
        format!("tool\0{RETAINED}\0").as_bytes(),
        Path::new(ROOT)
    ));
}
#[test]
fn scan203_retention_indirect_stage_spec_and_actor_names_are_references() {
    let mut p = plan();
    p.dependency_metadata
        .push(bound("/var/lib/jetstreamer/bound/spec.json"));
    assert!(recipe_references(
        b"ExecStart=tool /var/lib/jetstreamer/bound/spec.json --check",
        &p
    ));
    assert!(recipe_references(
        format!("Unit={}\n", ACTORS[0]).as_bytes(),
        &p
    ));
    assert!(!recipe_references(b"ExecStart=unrelated --help", &p));
}
#[test]
fn scan203_retention_proc_stat_comm_parentheses_do_not_shift_start_ticks() {
    let tail = (3..=24)
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    assert_eq!(
        process_start(format!("9 (has ) parentheses) {tail}").as_bytes()).unwrap(),
        22
    );
    assert!(process_start(b"9 (broken").is_err());
}
#[test]
fn scan203_retention_maps_alias_is_identified_by_device_and_inode() {
    let id = stamp(99, 10);
    let row = format!(
        "1000-2000 r--p 00000000 {:x}:{:x} 99 /alias\n",
        libc::major(id.device),
        libc::minor(id.device)
    );
    assert!(maps_identity(row.as_bytes(), &id).unwrap());
    assert!(!maps_identity(row.replace(" 99 ", " 100 ").as_bytes(), &id).unwrap());
    assert!(maps_identity(b"malformed", &id).is_err());
}

#[test]
fn scan203_retention_exact_current_executor_is_separate_from_terminal_actors() {
    let args = vec![
        "/sealed/tool".into(),
        "inspect-scan203-retention".into(),
        "/sealed/plan.json".into(),
    ];
    let iid = "b".repeat(32);
    let mut p = terminal_properties(UNIT);
    for (k, v) in [
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("MainPID", "2000"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
    ] {
        p.insert(k.into(), v.into());
    }
    p.insert("InvocationID".into(), iid.clone());
    p.insert(
        "ExecStart".into(),
        format!("{{ path=/sealed/tool ; argv[]={}; }}", args.join(" ")),
    );
    for k in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecStop",
        "ExecStopPost",
        "ExecReload",
        "ReadWritePaths",
    ] {
        p.insert(k.into(), String::new());
    }
    assert!(executor_properties(&p, &args, &iid, 2000).is_ok());
    assert!(executor_properties(&p, &args, &iid, 2001).is_err());
    assert!(executor_properties(&p, &args, &"c".repeat(32), 2000).is_err());
    for (k, v) in [
        ("ReadWritePaths", "/var/lib"),
        ("PrivateNetwork", "no"),
        ("ExecStartPre", "script"),
        ("TriggeredBy", "reopen.timer"),
        ("Restart", "on-failure"),
    ] {
        let mut changed = p.clone();
        changed.insert(k.into(), v.into());
        assert!(
            executor_properties(&changed, &args, &iid, 2000).is_err(),
            "accepted {k}"
        );
    }
    assert!(terminal(&p, UNIT, &iid).is_err());
}

fn require_native_root() {
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "explicit Root fixture admission required"
    );
}
fn fake_process(root: &Path, pid: u32) -> PathBuf {
    let p = root.join(pid.to_string());
    fs::create_dir(&p).unwrap();
    fs::create_dir(p.join("fd")).unwrap();
    fs::write(
        p.join("stat"),
        format!(
            "{pid} (fixture) {}",
            (3..=24)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
    )
    .unwrap();
    fs::write(p.join("cmdline"), b"fixture\0").unwrap();
    fs::write(p.join("maps"), b"").unwrap();
    p
}

#[test]
#[ignore = "native tiny-file fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_no_follow_metadata_rejects_symlink_and_changed_hash() {
    use std::os::unix::fs::symlink;
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("data.json");
    fs::write(&p, b"{}\n").unwrap();
    let b = Bound {
        path: p.clone(),
        sha256: hex_lower(&Sha256::digest(b"{}\n")),
    };
    assert!(metadata_bytes(&b).is_ok());
    let alias = d.path().join("alias.json");
    symlink(&p, &alias).unwrap();
    assert!(
        metadata_bytes(&Bound {
            path: alias,
            sha256: b.sha256.clone()
        })
        .is_err()
    );
    fs::write(p, b"[]\n").unwrap();
    assert!(metadata_bytes(&b).is_err());
}
#[test]
#[ignore = "native tiny-file fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_recipe_cycle_and_oversize_fail_closed() {
    use std::os::unix::fs::symlink;
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let a = d.path().join("a");
    let b = d.path().join("b");
    symlink(&b, &a).unwrap();
    symlink(&a, &b).unwrap();
    assert!(recipe(&a).is_err());
    let big = d.path().join("large");
    File::create(&big)
        .unwrap()
        .set_len(MAX_METADATA + 1)
        .unwrap();
    assert!(recipe(&big).is_err());
}
#[test]
#[ignore = "native tiny-file fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_hardlink_fd_alias_blocks_and_clean_fixture_passes() {
    use std::os::unix::fs::symlink;
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let proc = d.path().join("proc");
    fs::create_dir(&proc).unwrap();
    let p = fake_process(&proc, 2001);
    let target = d.path().join("source");
    fs::write(&target, b"tiny").unwrap();
    let id = Stamp::of(&fs::metadata(&target).unwrap());
    assert!(process_references(&proc, &target, &id, 0, &[]).is_ok());
    let alias = d.path().join("alias");
    fs::hard_link(&target, &alias).unwrap();
    symlink(&alias, p.join("fd/3")).unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_err());
}
#[test]
#[ignore = "native tiny-file fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_mapped_alias_blocks_without_matching_pathname() {
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let proc = d.path().join("proc");
    fs::create_dir(&proc).unwrap();
    let p = fake_process(&proc, 2002);
    let target = d.path().join("source");
    fs::write(&target, b"tiny").unwrap();
    let id = Stamp::of(&fs::metadata(&target).unwrap());
    fs::write(
        p.join("maps"),
        format!(
            "1000-2000 r--p 00000000 {:x}:{:x} {} /other-name\n",
            libc::major(id.device),
            libc::minor(id.device),
            id.inode
        ),
    )
    .unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_err());
}
#[test]
#[ignore = "native tiny-file fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_relative_reopen_cwd_and_incomplete_maps_fail() {
    use std::os::unix::fs::symlink;
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let proc = d.path().join("proc");
    fs::create_dir(&proc).unwrap();
    let p = fake_process(&proc, 2003);
    let target = d.path().join("source");
    fs::write(&target, b"tiny").unwrap();
    let id = Stamp::of(&fs::metadata(&target).unwrap());
    symlink(d.path(), p.join("cwd")).unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_err());
    fs::remove_file(p.join("cwd")).unwrap();
    symlink(d.path(), p.join("fd/5")).unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_err());
    fs::remove_file(p.join("fd/5")).unwrap();
    fs::remove_file(p.join("maps")).unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_err());
}

#[test]
#[ignore = "anonymous metadata I/O fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_manager_capture_needs_no_writable_filesystem() {
    require_native_root();
    let mut file = manager_capture("scan203-native-fixture").unwrap();
    file.write_all(b"Id=fixture.service\nJob=\n").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = vec![];
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(properties(&bytes).unwrap()["Id"], "fixture.service");
    assert_eq!(file.metadata().unwrap().nlink(), 0);
}

#[test]
#[ignore = "tiny indirect consumer fixture requires separately admitted Root sandbox"]
fn scan203_retention_native_indirect_spec_process_blocks_without_a_body_descriptor() {
    require_native_root();
    let d = tempfile::tempdir().unwrap();
    let proc = d.path().join("proc");
    fs::create_dir(&proc).unwrap();
    let process = fake_process(&proc, 2004);
    let target = d.path().join("source");
    fs::write(&target, b"tiny").unwrap();
    let id = Stamp::of(&fs::metadata(&target).unwrap());
    let metadata = d.path().join("reader-spec.json");
    let dependencies = [Bound {
        path: metadata.clone(),
        sha256: "0".repeat(64),
    }];
    fs::write(
        process.join("cmdline"),
        format!("tool\0--spec={}\0", metadata.display()),
    )
    .unwrap();
    assert!(process_references(&proc, &target, &id, 0, &[]).is_ok());
    assert!(process_references(&proc, &target, &id, 0, &dependencies).is_err());
    fs::write(
        process.join("cmdline"),
        format!("tool\0--spec={}.backup\0", metadata.display()),
    )
    .unwrap();
    assert!(process_references(&proc, &target, &id, 0, &dependencies).is_ok());
    fs::write(
        process.join("cmdline"),
        format!("tool\0--directory={}\0", d.path().display()),
    )
    .unwrap();
    assert!(process_references(&proc, &target, &id, 0, &dependencies).is_err());
}

#[test]
fn scan203_retention_typed_reader_classification_preserves205_anchor_and_refuses_unknown() {
    let full204 = json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-spec-v1", "stage":"full", "scan_directory":ROOT, "source":{"kind":"AssemblyRecovery204"}});
    assert_eq!(
        dependency_reader(&full204).unwrap(),
        DependencyReader::ScanDirectory204
    );
    let mut full205 = json!({"schema":"jetstreamer-continuation205-delivery-stage-spec-v1", "stage":"full", "scan_directory":"/var/lib/jetstreamer/horizon-205-delivery-full-scan-v2", "source":{"kind":"Continuation205"}, "neighbors":[{"epoch":204,"archive":{"path":RETAINED,"sha256":SHA204},"bytes":LENGTH204}]});
    assert_eq!(
        dependency_reader(&full205).unwrap(),
        DependencyReader::RetainedAnchor205
    );
    full205["neighbors"][0]["archive"]["path"] = json!(SOURCE);
    assert!(dependency_reader(&full205).is_err());
    assert!(dependency_reader(&json!({"schema":"unreviewed-wrapper", "reads":SOURCE})).is_err());
    let mut changed = full204;
    changed["scan_directory"] = json!("/other");
    assert!(dependency_reader(&changed).is_err());
}
