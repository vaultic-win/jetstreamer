#[cfg(test)]
mod tests {
    use super::*;

    fn good_outcome() -> Value {
        json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-v1","producer_unit":UNIT,"producer_invocation_id":INVOCATION,"node_sha256":NODE,"plan":{"sha256":PRODUCER_PLAN},"private_output":SOURCE,"prefix_archive_sha256":PREFIX,"suffix_archive_sha256":SUFFIX,"restart_snapshot_sha256":SNAPSHOT,"assembly":{"source_archives":2,"slots_merged":432000,"provenance_version":4},"fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,"canonical_root_slot":92447542,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }

    #[test]
    fn outcome_is_exact_and_never_authorizing() {
        validate_outcome(&good_outcome()).unwrap();
        for (pointer, value) in [
            ("/producer_invocation_id", json!("wrong")),
            ("/private_output", json!("/tmp/epoch-213.jet")),
            ("/assembly/slots_merged", json!(431999)),
            ("/assembly/provenance_version", json!(2)),
            ("/canonical_root_slot", json!(92447999)),
            ("/fresh_native_checkpoint_matches", json!(false)),
            ("/publication_authorized", json!(true)),
            ("/suffix_archive_sha256", json!(PREFIX)),
        ] {
            let mut changed = good_outcome();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_outcome(&changed).is_err(), "{pointer}");
        }
    }

    #[test]
    fn terminal_identity_and_exit_are_mandatory() {
        let good = format!(
            "LoadState=loaded\nInvocationID={INVOCATION}\nMainPID=0\nNRestarts=0\nRestart=no\nResult=success\nExecMainStatus=0\nExecMainCode=1\nActiveState=inactive\nSubState=dead\n"
        );
        validate_terminal(&good).unwrap();
        let cleared = good
            .replace(INVOCATION, "")
            .replace("ExecMainCode=1", "ExecMainCode=0");
        validate_terminal(&cleared).unwrap();
        validate_terminal(&cleared.replace("LoadState=loaded", "LoadState=not-found")).unwrap();
        assert!(
            validate_terminal(&good.replace("LoadState=loaded", "LoadState=not-found")).is_err()
        );
        assert!(
            validate_terminal(&cleared.replace("LoadState=loaded", "LoadState=error")).is_err()
        );
        let original_invocation = format!("InvocationID={INVOCATION}");
        for (old, new) in [
            ("InvocationID=", original_invocation.as_str()),
            ("ActiveState=inactive", "ActiveState=active"),
            ("SubState=dead", "SubState=exited"),
            ("Result=success", "Result=exit-code"),
        ] {
            assert!(validate_terminal(&cleared.replace(old, new)).is_err());
        }
        for (old, new) in [
            (INVOCATION, "different"),
            ("MainPID=0", "MainPID=42"),
            ("NRestarts=0", "NRestarts=1"),
            ("ExecMainStatus=0", "ExecMainStatus=1"),
            ("SubState=dead", "SubState=running"),
            ("ExecMainCode=1", "ExecMainCode=2"),
        ] {
            assert!(validate_terminal(&good.replace(old, new)).is_err());
        }
        assert!(validate_terminal(&(good + "Result=success\n")).is_err());
    }

    #[test]
    fn terminal_journal_requires_exact_process_and_ordered_manager_success() {
        let completion = json!({"_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":INVOCATION,"_EXE":"/var/lib/jetstreamer/horizon-213-checkpoint-continuation-ae43646-v1/jetstreamer-node","_PID":"847475","__REALTIME_TIMESTAMP":"100","MESSAGE":"private epoch213 checkpoint continuation assembled; independent final/plugin verification and publication gates remain closed"});
        let manager = json!({"UNIT":UNIT,"_PID":"1","_EXE":"/usr/lib/systemd/systemd","__REALTIME_TIMESTAMP":"101","MESSAGE":format!("{UNIT}: Deactivated successfully.")});
        let encode =
            |records: &[Value]| records.iter().map(|v| format!("{v}\n")).collect::<String>();
        validate_terminal_journal(encode(&[completion.clone(), manager.clone()]).as_bytes())
            .unwrap();
        for (pointer, value) in [
            ("/_PID", json!("999")),
            ("/_SYSTEMD_INVOCATION_ID", json!("foreign")),
            ("/_EXE", json!("/tmp/node")),
            ("/__REALTIME_TIMESTAMP", json!("102")),
        ] {
            let mut changed = completion.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_terminal_journal(encode(&[changed, manager.clone()]).as_bytes()).is_err()
            );
        }
        for records in [
            vec![completion.clone()],
            vec![manager.clone()],
            vec![completion.clone(), completion.clone(), manager.clone()],
            vec![completion, manager.clone(), manager],
        ] {
            assert!(validate_terminal_journal(encode(&records).as_bytes()).is_err());
        }
    }

    #[test]
    fn commands_cannot_downgrade_strict_validation() {
        let args = full_args(Path::new("/private/epoch-213.jet"));
        assert_eq!(args.len(), 12);
        assert_eq!(
            &args[1..5],
            [
                "--full",
                "--anchor",
                "92015999",
                "9xdazt5sEpSUzwYi9nTRMmXJDuP4kLdcY9ZXAM5oQVi7"
            ]
        );
        assert_eq!(args[5], "--expected-terminal");
        assert_eq!(args[10], "--expected-provenance-sha256");
        assert_eq!(args[11], PROVENANCE);
        assert!(
            !args
                .iter()
                .any(|v| v == "--internal-full" || v == "--bench")
        );
        assert_eq!(
            plugin_args(Path::new("/private")),
            ["213:213", "/private", "--threads", "8", "--verify-only"]
        );
    }

    fn good_plan() -> Value {
        json!({"schema":"jetstreamer-private-epoch213-verification-plan-v1",
            "producer_outcome":{"path":"/sealed/outcome.json","sha256":"a".repeat(64)},
            "provenance_expectation":{"path":"/sealed/expectation.json","sha256":EXPECTATION},
            "full_verifier":{"path":"/sealed/verify_archive","sha256":FULL},
            "plugin":{"path":"/sealed/horizon-pipeline","sha256":PLUGIN},
            "private_directory":"/var/lib/jetstreamer/horizon-213-private-scan-test-v1",
            "protected_free_bytes":MIN_PROTECTED,"maximum_archive_bytes":128u64*1024*1024*1024,"threads":8})
    }

    #[test]
    fn plan_pins_tools_private_namespace_and_resource_bounds() {
        validate_plan(&serde_json::from_value(good_plan()).unwrap()).unwrap();
        for (pointer, value) in [
            ("/schema", json!("other")),
            ("/full_verifier/sha256", json!(PLUGIN)),
            ("/plugin/sha256", json!(FULL)),
            ("/provenance_expectation/sha256", json!(FULL)),
            ("/protected_free_bytes", json!(MIN_PROTECTED - 1)),
            ("/maximum_archive_bytes", json!(129u64 * 1024 * 1024 * 1024)),
            ("/threads", json!(16)),
            (
                "/private_directory",
                json!("/var/lib/jetstreamer/nested/horizon-213-private-scan-v1"),
            ),
            ("/private_directory", json!("/home/ubuntu/horizon")),
        ] {
            let mut changed = good_plan();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_plan(&serde_json::from_value(changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = good_plan();
        unknown["publication_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
    }

    #[test]
    fn digest_and_absence_gates_reject_ambiguous_inputs() {
        assert!(hex(&"a".repeat(64)).is_ok());
        for value in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            assert!(hex(&value).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-213.jet.sha256");
        require_absent(&path).unwrap();
        std::os::unix::fs::symlink("/does-not-exist", &path).unwrap();
        assert!(require_absent(&path).is_err());
    }

    #[test]
    fn root_scan_requires_success_and_preserves_failed_log() {
        // Repeated under sudo as part of release qualification.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for (binary, succeeds) in [("/usr/bin/true", true), ("/usr/bin/false", false)] {
            // The host's system coreutils may be hardlinked. Make a distinct
            // root-owned inode, just like a sealed deployment member.
            let path = dir
                .path()
                .join(if succeeds { "scan-true" } else { "scan-false" });
            fs::copy(binary, &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
            let evidence = Evidence {
                sha256: measure(&path, true).unwrap().0,
                path,
            };
            let log = dir.path().join(if succeeds {
                "success.log"
            } else {
                "failure.log"
            });
            assert_eq!(scan(&evidence, &[], &log).is_ok(), succeeds);
            assert!(log.exists());
            assert!(
                scan(&evidence, &[], &log).is_err(),
                "existing log must never be overwritten"
            );
        }
    }

    #[test]
    fn changed_inode_symlink_and_hardlink_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (sha, _) = measure(&path, false).unwrap();
        assert_eq!(sha, format!("{:x}", Sha256::digest(b"original")));
        let file = open_file(&path, false).unwrap();
        let before = identity(&file.metadata().unwrap());
        // Keep the old descriptor open so the replacement cannot reuse its
        // inode. Same-length in-place writes can share a filesystem timestamp
        // tick, even when nanoseconds are recorded; they are not an inode test.
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"original").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_ne!(identity(&fs::metadata(&path).unwrap()).ino, before.ino);
        assert!(unchanged(&path, &file, &before).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_file(&link, false).is_err());
        fs::remove_file(link).unwrap();
        fs::hard_link(&path, dir.path().join("hard")).unwrap();
        assert!(open_file(&path, false).is_err());
    }

    #[test]
    fn changed_length_fails_without_timestamp_resolution_assumptions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = open_file(&path, false).unwrap();
        let before = identity(&file.metadata().unwrap());
        fs::write(&path, b"modified with a different length").unwrap();
        assert_ne!(file.metadata().unwrap().len(), before.len);
        assert!(unchanged(&path, &file, &before).is_err());
    }

    #[test]
    fn independent_hash_detects_same_length_content_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (before, _) = measure(&path, false).unwrap();
        fs::write(&path, b"modified").unwrap();
        let (after, _) = measure(&path, false).unwrap();
        assert_ne!(before, after);
    }
}
