//! Private cold223 canonical-root prefix, never a full epoch or publication gate.
mod profile {
    pub const NATURAL_ROOT_FINISH: bool = true;
    pub const ARCHIVE_NAME: &str = "epoch-223.jet";
    pub const PARENT_SHA: &str = "d2cb8dd811d0abee15e71f8333037e561e2951157d667e156a1712e042fe95a8";
    pub const RAYON_THREADS: u32 = 2;
    pub const EPOCH: u64 = 223;
    pub const TARGET: u64 = 96_767_522;
    pub const TERMINAL: u64 = TARGET;
    pub const INITIAL_REPLAY: u64 = 96_335_539;
    // Rejection baseline only: floor + unchanged225 growth + full1536GiB trial.
    // Fresh full-fleet admission and an invocation-bound guard remain mandatory.
    pub const MINIMUM_FREE: u64 = 2_584_751_391_635;
    pub const MAX_SCRATCH: u64 = 1280 << 30;
    pub const MAX_RUNTIME: u64 = 259200;
    pub const SNAPSHOT_SIZE: u64 = 9_815_262_303;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch223-root-prefix-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch223-root-prefix-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch223-root-prefix-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-223-root-prefix-resource-";
    pub const ROOT_PREFIX: &str = "qualification-223-v1625-prefix-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst";
    pub const CHECKPOINT_NAMES: &[&str] = &[SNAPSHOT_NAME, TERMINAL_NAME];
    pub const WORKER: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_25";
    pub const SNAPSHOT: &str = "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665";
}
mod bounded_resource_runner {
    include!("bounded_resource_runner.rs");
    #[cfg(test)]
    mod prefix223_tests {
        use super::*;

        fn manifest() -> Value {
            json!({"schema_version":1,"epoch":223,"output_slot_start":96336000,
                "output_slot_count":431523,"worker_executable_sha256":WORKER,
                "runtime":{"runtime_profile":"solana-v1.6.25"},
                "bootstrap":{"slot":96335538,"slot_complete":true,
                    "accounts_hash":"Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE",
                    "bank_hash":"8LxWwzEvnAvZC6FwgcqFMxeswZD5skZ7zacYhf1eYW1F"},
                "terminal":{"slot":96767522,"slot_complete":true,
                    "accounts_hash":"3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7",
                    "bank_hash":"EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB"},
                "archive_sha256":"a".repeat(64)})
        }
        fn plan() -> Plan {
            Plan {
                schema: PLAN_SCHEMA.into(),
                unit: format!("{UNIT_PREFIX}test.service"),
                node: BoundFile {
                    path: "/sealed/node".into(),
                    sha256: PARENT_SHA.into(),
                },
                worker: "/sealed/worker".into(),
                snapshot: PathBuf::from(format!("/sealed/{SNAPSHOT_NAME}")),
                ledger_directory: "/sealed".into(),
                epoch_hashes: BoundFile {
                    path: "/sealed/hashes".into(),
                    sha256: "b".repeat(64),
                },
                run_root: PathBuf::from(format!(
                    "/home/ubuntu/.jetstreamer-private/{ROOT_PREFIX}test"
                )),
                target_slot: TARGET,
                terminal_slot: TERMINAL,
                minimum_free_bytes: MINIMUM_FREE,
                maximum_runtime_seconds: MAX_RUNTIME,
            }
        }
        #[test]
        fn exact_span_and_all_independent_checkpoint_fields_are_mandatory() {
            root_manifest_valid(&manifest()).unwrap();
            for key in [
                "epoch",
                "output_slot_start",
                "output_slot_count",
                "schema_version",
                "worker_executable_sha256",
                "archive_sha256",
            ] {
                let mut m = manifest();
                m[key] = Value::Null;
                assert!(root_manifest_valid(&m).is_err(), "accepted missing {key}");
            }
            for checkpoint in ["bootstrap", "terminal"] {
                for key in ["slot", "slot_complete", "accounts_hash", "bank_hash"] {
                    let mut m = manifest();
                    m[checkpoint][key] = Value::Null;
                    assert!(
                        root_manifest_valid(&m).is_err(),
                        "accepted missing {checkpoint}.{key}"
                    );
                }
            }
            for terminal in [96_767_521, 96_767_523, 96_767_999] {
                let mut m = manifest();
                m["terminal"]["slot"] = json!(terminal);
                assert!(root_manifest_valid(&m).is_err());
            }
        }
        #[test]
        fn plan_cannot_borrow_tail_full_epoch_or_another_profile() {
            validate_plan(&plan()).unwrap();
            for which in 0..8 {
                let mut p = plan();
                match which {
                    0 => {
                        p.schema =
                            "jetstreamer-private-epoch203-root-prefix-resource-plan-v1".into()
                    }
                    1 => {
                        p.run_root =
                            "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-test"
                                .into()
                    }
                    2 => p.target_slot = 96_767_999,
                    3 => p.terminal_slot = 96_767_999,
                    4 => p.minimum_free_bytes -= 1,
                    5 => p.node.sha256 = "c".repeat(64),
                    6 => p.maximum_runtime_seconds += 1,
                    _ => p.snapshot = PathBuf::from(format!("/sealed/{TERMINAL_NAME}")),
                }
                assert!(validate_plan(&p).is_err());
            }
            assert_eq!(MINIMUM_FREE, 248_289_182_611 + (640u64 + 1536) * (1 << 30));
            assert_eq!(MAX_SCRATCH, 1280 << 30);
        }
        #[test]
        fn command_and_marker_are_private_and_exact() {
            let c = command(&plan());
            let args = c
                .get_args()
                .map(|s| s.to_str().unwrap())
                .collect::<Vec<_>>();
            assert!(args.contains(&"--verify"));
            assert!(args.contains(&"--qualification-end-slot=96767522"));
            assert!(args.iter().any(|s| s.ends_with("/output/epoch-223.jet")));
            assert!(!args.iter().any(|s| s.contains("tail-comparison")
                || s.contains("cohort")
                || s.contains("publish")));
            let good = "[2026 INFO  jetstreamer_node::historical_replay] historical checkpoint slot=96767522 complete=true";
            assert!(root_checkpoint_marker(good));
            assert!(!root_checkpoint_marker(
                &good.replace("96767522", "88127580")
            ));
            assert!(!root_checkpoint_marker(
                &good.replace("complete=true", "complete=false")
            ));
            validate_checkpoint_names(&format!("{SNAPSHOT_NAME}\n{TERMINAL_NAME}\n")).unwrap();
            assert!(validate_checkpoint_names(TERMINAL_NAME).is_err());
        }
        #[test]
        fn natural_completion_needs_private_manifest_and_never_grants_publication() {
            for variant in ["valid", "missing-manifest", "canonical-sidecar"] {
                let t = tempfile::tempdir().unwrap();
                for name in ["scratch", "output", "receipts", "cgroup"] {
                    fs::create_dir(t.path().join(name)).unwrap();
                    fs::set_permissions(t.path().join(name), fs::Permissions::from_mode(0o700))
                        .unwrap();
                }
                for name in [
                    "memory.current",
                    "memory.peak",
                    "memory.events",
                    "memory.stat",
                    "cpu.stat",
                    "io.stat",
                    "memory.pressure",
                    "io.pressure",
                ] {
                    fs::write(t.path().join("cgroup").join(name), b"0\n").unwrap();
                }
                let archive = t.path().join("output").join(ARCHIVE_NAME);
                fs::write(&archive, b"fixture, not an independently verified archive").unwrap();
                fs::set_permissions(&archive, fs::Permissions::from_mode(0o600)).unwrap();
                if variant != "missing-manifest" {
                    let segment = PathBuf::from(format!("{}.segment.json", archive.display()));
                    fs::write(&segment, serde_json::to_vec(&manifest()).unwrap()).unwrap();
                    fs::set_permissions(segment, fs::Permissions::from_mode(0o600)).unwrap();
                }
                if variant == "canonical-sidecar" {
                    fs::write(format!("{}.sha256", archive.display()), b"forbidden").unwrap();
                }
                let mut p = plan();
                p.run_root = t.path().into();
                p.minimum_free_bytes = 0; // Synthetic tmpdir only; production validates baseline.
                let mut cmd = Command::new("/bin/true");
                cmd.stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .process_group(0);
                let result = measure_root(
                    &p,
                    &"a".repeat(32),
                    &t.path().join("cgroup"),
                    &mut cmd,
                    &json!({"plan_path":"/sealed/plan","plan_sha256":"b".repeat(64),
                        "self_sha256":"c".repeat(64)}),
                    &DiskStorage,
                );
                assert_eq!(result.is_ok(), variant == "valid", "{variant}");
                let name = if result.is_ok() {
                    "root-prefix.json"
                } else {
                    "failure.json"
                };
                let r: Value = serde_json::from_slice(
                    &fs::read(t.path().join("receipts").join(name)).unwrap(),
                )
                .unwrap();
                assert_eq!(r["epoch"], 223);
                assert_eq!(
                    r["producer_canonical_root_prefix_present"],
                    variant == "valid"
                );
                assert_eq!(r["capture_is_peak_proof"], false);
                assert!(
                    r["authority"]
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|v| v == false)
                );
            }
        }
    }
}
fn main() {
    bounded_resource_runner::main();
}
