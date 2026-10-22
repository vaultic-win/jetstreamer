//! Separate closed RAM-only cold/tail gates for the isolated epoch223 candidate.
use super::*;

const PLAN_SCHEMA: &str = if COLD223 {
    "jetstreamer-private-epoch223-cold-ram-snapshot-test-plan-v1"
} else {
    "jetstreamer-private-epoch223-tail-ram-snapshot-test-plan-v1"
};
const UNIT_PREFIX: &str = if COLD223 {
    "archive-223-cold-snapshot-test-"
} else {
    "archive-223-tail-snapshot-test-"
};
const RECEIPT_PREFIX: &str = if COLD223 {
    "ram-snapshot-test-223-cold-"
} else {
    "ram-snapshot-test-223-tail-"
};
const SNAPSHOT_PATH: &str = if COLD223 {
    "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst"
} else {
    "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-bd60006d-v1/snapshot-96767522-3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7.tar.zst"
};
const GENESIS_PATH: &str = if COLD223 {
    "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1/genesis.tar.bz2"
} else {
    "/var/lib/jetstreamer/horizon-focused-223-v1625-tail-bd60006d-v1/genesis.tar.bz2"
};

const CLAIMS: [(u64, &str, &str, &str); 2] = [
    (
        203,
        "203-203",
        "horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service",
        "748ffa40e0a2408da0a10fc9e160cf0a",
    ),
    (
        225,
        "225-226",
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
];
const LENGTHS: [(u64, u64); 13] = [
    (201, 102605729507),
    (202, 101842225683),
    (206, 108774749680),
    (213, 125368013231),
    (214, 128213350837),
    (215, 128820081409),
    (216, 128977079203),
    (217, 129125423643),
    (218, 125325863645),
    (219, 128896280026),
    (220, 135699623364),
    (221, 137055363091),
    (222, 133175903649),
];
fn safe_name(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix).is_some_and(|tail| {
        !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
pub(super) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PLAN_SCHEMA && matches!(p.mode.as_str(), "capability" | "snapshot-tests"),
        "wrong223 schema/mode"
    );
    ensure!(
        p.unit
            .strip_suffix(".service")
            .is_some_and(|s| safe_name(s, UNIT_PREFIX)),
        "foreign223 unit"
    );
    ensure!(
        p.test_binary.sha256 == TEST_SHA
            && p.snapshot.sha256 == SNAPSHOT_SHA
            && p.genesis.sha256 == GENESIS_SHA,
        "foreign223 inputs"
    );
    ensure!(
        p.snapshot.path == Path::new(SNAPSHOT_PATH) && p.genesis.path == Path::new(GENESIS_PATH),
        "foreign223 package"
    );
    ensure!(
        p.test_binary.path.file_name().and_then(|s| s.to_str()) == Some("historical-worker")
            && p.test_binary.path.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer/horizon-223-tail-snapshot-harness-release-bd60006d-v1"
                )),
        "foreign223 harness"
    );
    ensure!(
        p.receipt_directory.parent()
            == Some(Path::new("/var/lib/jetstreamer/horizon-ram-snapshot-tests"))
            && p.receipt_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| safe_name(s, RECEIPT_PREFIX))
            && (60..=1800).contains(&p.maximum_runtime_seconds),
        "foreign223 receipt/time scope"
    );
    validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY)
}
pub(super) fn validate_observer(v: &Value, now: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["cadence"]["observation_reason"] == "routine"
            && v["cadence"]["minimum_interval_seconds"] == 1800,
        "not routine v2 evidence"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v["mutation"][key] == false, "mutating observation");
    }
    let at = utc(v["recorded_at_utc"]
        .as_str()
        .context("missing sample time")?)?;
    ensure!(at <= now && now - at <= 1800, "stale/future observation");
    ensure!(
        v["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= START_MEMORY),
        "memory admission failed"
    );
    ensure!(
        v["replays"].as_array().is_some_and(Vec::is_empty),
        "ordinary census changed"
    );
    let diagnostics = v["diagnostic_replays"]
        .as_array()
        .context("missing diagnostics")?;
    ensure!(
        diagnostics.len() == CLAIMS.len(),
        "diagnostic census changed"
    );
    for (_, range, unit, id) in CLAIMS {
        let matches: Vec<_> = diagnostics.iter().filter(|d| d["range"] == range).collect();
        ensure!(matches.len() == 1, "missing/duplicate diagnostic");
        let d = matches[0];
        ensure!(
            d["status"] == "observed"
                && d["producer_unit"] == unit
                && d["expected_producer_invocation_id"] == id
                && d["ordinary_replay_claim"] == false
                && d["publication_authorized"] == false,
            "foreign/unavailable diagnostic"
        );
        let r = &d["observation"];
        ensure!(
            r["invocation_binding_stable"] == true,
            "unstable diagnostic"
        );
        for key in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            ensure!(
                r[key]["invocation_id"] == id
                    && r[key]["restarts"] == 0
                    && r[key]["active_state"] == "active",
                "changed diagnostic invocation"
            );
        }
    }
    Ok(())
}
fn active_units(f: &Value) -> Result<Vec<&Value>> {
    let a = f["active"].as_array().context("missing active fleet")?;
    ensure!(a.len() == CLAIMS.len(), "changed active census");
    let mut out = Vec::new();
    for (epoch, _, unit, id) in CLAIMS {
        let matches: Vec<_> = a.iter().filter(|e| e["epoch"] == epoch).collect();
        ensure!(matches.len() == 1, "missing/duplicate active claim");
        let e = matches[0];
        let u = &e["producer"];
        ensure!(
            e["phase"] == "diagnostic-qualification"
                && e["ordinary_replay_claim"] == false
                && e["current_sidecar_eta_valid"] == false
                && u["Id"] == unit
                && u["InvocationID"] == id
                && u["NRestarts"] == "0"
                && u["ActiveState"] == "active"
                && u["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|n| n > 0),
            "foreign/inactive fleet claim"
        );
        out.push(u);
    }
    Ok(out)
}
fn fleet_binding(f: &Value, o: &Value, hash: &str) -> Result<()> {
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_sha256"] == hash
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false,
        "unbound223 fleet"
    );
    let entries = f["inventory"]["entries"]
        .as_array()
        .context("missing inventory")?;
    let ready: Vec<_> = entries
        .iter()
        .filter(|e| e["state"] == "ready-pair")
        .collect();
    ensure!(ready.len() == LENGTHS.len(), "century census changed");
    let mut sum = 0u64;
    for ((epoch, length), e) in LENGTHS.iter().zip(ready) {
        ensure!(
            e["epoch"] == *epoch && e["archive_length"] == *length,
            "century sample changed"
        );
        sum = sum.checked_add(*length).context("length overflow")?;
    }
    ensure!(
        sum.checked_mul(2)
            .context("floor overflow")?
            .div_ceil(LENGTHS.len() as u64)
            == FLOOR,
        "century floor changed"
    );
    active_units(f)?;
    Ok(())
}
pub(super) fn validate_fleet(f: &Value, o: &Value, hash: &str) -> Result<()> {
    fleet_binding(f, o, hash)?;
    for u in active_units(f)? {
        let output = Command::new("/usr/bin/systemctl")
            .args([
                "show",
                u["Id"].as_str().unwrap(),
                "--no-pager",
                "--property=Id,InvocationID,NRestarts,MainPID,ActiveState,ExecStart",
            ])
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() < 16384,
            "cannot authenticate active fleet"
        );
        let text = std::str::from_utf8(&output.stdout)?;
        for key in [
            "Id",
            "InvocationID",
            "NRestarts",
            "MainPID",
            "ActiveState",
            "ExecStart",
        ] {
            let expected = format!("{key}={}", u[key].as_str().context("missing live field")?);
            ensure!(
                text.lines().filter(|s| *s == expected).count() == 1,
                "active fleet changed at {key}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_ram_sandbox_cannot_expand_host_writes_or_keep_privileges() {
        let path = Path::new(
            "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-tail-fixture",
        );
        let s = format!(
            "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectControlGroups=yes\nPrivateNetwork=yes\nOOMPolicy=kill\nOOMScoreAdjust=1000\nTemporaryFileSystem={TMPFS_OPTIONS}\nReadWritePaths={}\nCapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid\n",
            path.display()
        );
        validate_sandbox(&s, path).unwrap();
        for (from, to) in [
            ("nr_inodes=1048576,", ""),
            ("size=512G", "size=1024G"),
            ("PrivateNetwork=yes", "PrivateNetwork=no"),
            ("cap_setuid", "cap_sys_admin"),
            ("ProtectHome=read-only", "ProtectHome=no"),
            ("ReadWritePaths=/var/lib", "ReadWritePaths=/tmp"),
        ] {
            assert!(
                validate_sandbox(&s.replace(from, to), path).is_err(),
                "{from}"
            );
        }
        validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY).unwrap();
        assert!(validate_reserves(TMPFS_SIZE, TMPFS_SIZE, FLOOR, STOP_MEMORY).is_err());
    }
    #[test]
    fn terminal_counters_require_bounded_regular_complete_inputs() {
        let dir = tempfile::tempdir().unwrap();
        for name in RESOURCE_FILES {
            fs::write(dir.path().join(name), "high 0\noom 0\n").unwrap();
        }
        assert_eq!(
            resource_counters_at(dir.path())
                .unwrap()
                .as_object()
                .unwrap()
                .len(),
            RESOURCE_FILES.len()
        );
        fs::remove_file(dir.path().join("cpu.stat")).unwrap();
        assert!(resource_counters_at(dir.path()).is_err());
        std::os::unix::fs::symlink("memory.events", dir.path().join("cpu.stat")).unwrap();
        assert!(resource_counters_at(dir.path()).is_err());
    }
    fn observer() -> Value {
        let diagnostics: Vec<_> = CLAIMS.iter().map(|(_, range, unit, id)| {
            let mut r = json!({"invocation_binding_stable":true});
            for key in ["controller_before","controller_after","producer_before","producer_after"] {
                r[key] = json!({"invocation_id":id,"restarts":0,"active_state":"active"});
            }
            json!({"range":range,"producer_unit":unit,"expected_producer_invocation_id":id,
                "ordinary_replay_claim":false,"publication_authorized":false,"status":"observed","observation":r})
        }).collect();
        json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-22T20:27:24Z",
            "cadence":{"routine_minimum_interval_enforced":true,"observation_reason":"routine","minimum_interval_seconds":1800},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},
            "host_memory":{"conservative_available_kib":START_MEMORY/1024},"replays":[],"diagnostic_replays":diagnostics})
    }
    fn fleet() -> Value {
        let active: Vec<_> = CLAIMS.iter().map(|(epoch,_,unit,id)| json!({"epoch":epoch,
            "phase":"diagnostic-qualification","ordinary_replay_claim":false,"current_sidecar_eta_valid":false,
            "producer":{"Id":unit,"InvocationID":id,"NRestarts":"0","MainPID":"42","ActiveState":"active","ExecStart":"bound"}})).collect();
        let entries: Vec<_> = LENGTHS.iter().map(|(epoch,length)|json!({"epoch":epoch,"archive_length":length,"state":"ready-pair"})).collect();
        json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","observer_sha256":"a".repeat(64),
            "sampled_at_utc":"2026-10-22T20:27:24Z","first_epoch":201,"last_epoch":300,
            "producer_mutations":false,"remote_mutations":false,"active":active,"inventory":{"entries":entries}})
    }
    #[test]
    fn exact_routine_census_and_fresh_memory_are_required() {
        let v = observer();
        let now = utc("2026-10-22T20:30:00Z").unwrap();
        validate_observer(&v, now).unwrap();
        for (ptr, value) in [
            (
                "/cadence/observation_reason",
                json!("user-requested-status"),
            ),
            ("/host_memory/conservative_available_kib", json!(0)),
            ("/mutation/r2_mutations", json!(true)),
            ("/diagnostic_replays/0/status", json!("unavailable")),
            (
                "/diagnostic_replays/1/observation/producer_after/restarts",
                json!(1),
            ),
            (
                "/diagnostic_replays/1/observation/controller_after/invocation_id",
                json!("f".repeat(32)),
            ),
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(validate_observer(&bad, now).is_err(), "{ptr}");
        }
        assert!(validate_observer(&v, now + 1801).is_err());
        let mut bad = v.clone();
        bad["replays"] = json!([{}]);
        assert!(validate_observer(&bad, now).is_err());
        let mut bad = v;
        let duplicate = bad["diagnostic_replays"][0].clone();
        bad["diagnostic_replays"][1] = duplicate;
        assert!(validate_observer(&bad, now).is_err());
    }
    #[test]
    fn complete_fleet_and_century_samples_cannot_be_substituted() {
        let f = fleet();
        let o = observer();
        let hash = "a".repeat(64);
        fleet_binding(&f, &o, &hash).unwrap();
        for (ptr, value) in [
            ("/observer_sha256", json!("b".repeat(64))),
            ("/inventory/entries/0/archive_length", json!(1)),
            ("/active/0/producer/InvocationID", json!("f".repeat(32))),
            ("/active/0/producer/NRestarts", json!("1")),
            ("/active/1/current_sidecar_eta_valid", json!(true)),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(fleet_binding(&bad, &o, &hash).is_err(), "{ptr}");
        }
        let mut bad = f;
        bad["active"].as_array_mut().unwrap().pop();
        assert!(fleet_binding(&bad, &o, &hash).is_err());
    }
    #[test]
    fn exact_223_profile_plan_cannot_borrow_225_or_run_entries() {
        let p = json!({"schema":PLAN_SCHEMA,
            "mode":"capability","unit":format!("{UNIT_PREFIX}fixture.service"),
            "test_binary":{"path":"/var/lib/jetstreamer/horizon-223-tail-snapshot-harness-release-bd60006d-v1/historical-worker","sha256":TEST_SHA},
            "snapshot":{"path":SNAPSHOT_PATH,"sha256":SNAPSHOT_SHA},
            "genesis":{"path":GENESIS_PATH,"sha256":GENESIS_SHA},
            "observer":{"path":"/sample","sha256":"a".repeat(64)},"fleet":{"path":"/fleet","sha256":"b".repeat(64)},
            "receipt_directory":format!("/var/lib/jetstreamer/horizon-ram-snapshot-tests/{RECEIPT_PREFIX}fixture"),"maximum_runtime_seconds":1800});
        validate_plan(&serde_json::from_value(p.clone()).unwrap()).unwrap();
        for (ptr, value) in [
            (
                "/schema",
                json!("jetstreamer-private-v1625-ram-snapshot-test-plan-v1"),
            ),
            ("/mode", json!("replay")),
            ("/unit", json!("horizon-v1625-snapshot-test-225.service")),
            ("/test_binary/sha256", json!("a".repeat(64))),
            (
                "/test_binary/sha256",
                json!("6baab37dfe86bd957ba21c22a2769f1d32c28bee930cad2b4b17d1eb25a087a5"),
            ),
            ("/snapshot/path", json!("/foreign/snapshot")),
            ("/genesis/path", json!("/foreign/genesis.tar.bz2")),
            (
                "/snapshot/sha256",
                json!(if COLD223 {
                    "dc7f2ac03813bc609629885af82222ac5af070cc6187b7bce08e10944fd214e1"
                } else {
                    "301110cad7eb56ed68c99d31cf6769b7622e2c166f33aec084dc51592d0cd665"
                }),
            ),
            (
                "/schema",
                json!(if COLD223 {
                    "jetstreamer-private-epoch223-tail-ram-snapshot-test-plan-v1"
                } else {
                    "jetstreamer-private-epoch223-cold-ram-snapshot-test-plan-v1"
                }),
            ),
            (
                "/unit",
                json!(if COLD223 {
                    "archive-223-tail-snapshot-test-foreign.service"
                } else {
                    "archive-223-cold-snapshot-test-foreign.service"
                }),
            ),
            (
                "/receipt_directory",
                json!(if COLD223 {
                    "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-tail-foreign"
                } else {
                    "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-223-cold-foreign"
                }),
            ),
            ("/receipt_directory", json!("/tmp/receipts")),
            ("/maximum_runtime_seconds", json!(1801)),
        ] {
            let mut bad = p.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(
                validate_plan(&serde_json::from_value(bad).unwrap()).is_err(),
                "{ptr}"
            );
        }
        assert_eq!(CPU_CORES, 8);
        assert_eq!(
            SNAPSHOT_SIZE,
            if COLD223 {
                9_815_262_303
            } else {
                9_705_551_147
            }
        );
        assert_eq!(ANCHOR223, if COLD223 { "96335538" } else { "96767522" });
        assert_eq!(
            receipt_schema("result"),
            if COLD223 {
                "jetstreamer-private-epoch223-cold-v1625-ram-snapshot-result-v1"
            } else {
                "jetstreamer-private-epoch223-tail-v1625-ram-snapshot-result-v1"
            }
        );
        validate_test_list(&format!(
            "{}\n{}\n2 tests, 0 benchmarks\n",
            TEST_NAMES[0], TEST_NAMES[1]
        ))
        .unwrap();
        assert!(validate_test_list("2 tests, 0 benchmarks\n").is_err());
        validate_inode_geometry(1_048_576).unwrap();
        assert!(validate_inode_geometry(409_600).is_err());
    }
}
