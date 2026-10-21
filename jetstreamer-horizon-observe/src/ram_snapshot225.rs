//! Isolated epoch225 profile for the shared, bounded RAM-only test supervisor.
use super::*;

fn allowed_203_invocation(id: &str) -> bool {
    matches!(
        id,
        "bfdfb1a74959444e9f477451fadc3d43" | "748ffa40e0a2408da0a10fc9e160cf0a"
    )
}

pub(super) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-v1625-ram-snapshot-test-plan-v1"
            && matches!(p.mode.as_str(), "capability" | "snapshot-tests"),
        "wrong225 schema/mode"
    );
    ensure!(
        p.unit.starts_with("horizon-v1625-snapshot-test-")
            && p.unit.ends_with(".service")
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "foreign225 unit"
    );
    ensure!(
        p.test_binary.sha256 == TEST_SHA
            && p.snapshot.sha256 == SNAPSHOT_SHA
            && p.genesis.sha256 == GENESIS_SHA,
        "foreign225 fixture or test"
    );
    ensure!(
        p.snapshot.path.file_name().and_then(|s| s.to_str())
            == Some("snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst")
            && p.genesis.path.file_name().and_then(|s| s.to_str()) == Some("genesis.tar.bz2"),
        "foreign225 fixture name"
    );
    ensure!(
        p.receipt_directory.parent()
            == Some(Path::new("/var/lib/jetstreamer/horizon-ram-snapshot-tests"))
            && p.receipt_directory
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("ram-snapshot-test-225-"))
            && (60..=1800).contains(&p.maximum_runtime_seconds),
        "foreign225 receipts/time bound"
    );
    validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY)
}

pub(super) fn validate_observer(v: &Value, now: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["cadence"]["observation_reason"] == "routine"
            && v["cadence"]["minimum_interval_seconds"] == 1800,
        "not a routine v2 sample"
    );
    for k in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(v["mutation"][k] == false, "mutating sample");
    }
    let at = utc(v["recorded_at_utc"]
        .as_str()
        .context("missing sample time")?)?;
    ensure!(at <= now && now - at <= 1800, "stale/future sample");
    ensure!(
        v["host_memory"]["conservative_available_kib"]
            .as_u64()
            .and_then(|n| n.checked_mul(1024))
            .is_some_and(|n| n >= START_MEMORY),
        "insufficient sampled memory"
    );
    let ordinary = v["replays"].as_array().context("missing replays")?;
    ensure!(
        ordinary.len() == 1 && ordinary[0]["range"] == "220-223",
        "changed ordinary census"
    );
    let r = &ordinary[0];
    ensure!(
        r["invocation_binding_stable"] == true,
        "unstable ordinary binding"
    );
    for (key, id) in [
        ("controller_before", "0b69b5009dc74bbda94b94d059a3daa7"),
        ("controller_after", "0b69b5009dc74bbda94b94d059a3daa7"),
        ("producer_before", "c2adebaad0cb42b385156631156813fe"),
        ("producer_after", "c2adebaad0cb42b385156631156813fe"),
    ] {
        ensure!(
            r[key]["invocation_id"] == id
                && r[key]["restarts"] == 0
                && r[key]["active_state"] == "active",
            "changed ordinary invocation"
        );
    }
    let diagnostics = v["diagnostic_replays"]
        .as_array()
        .context("missing diagnostic census")?;
    ensure!(
        diagnostics.len() <= 1
            && diagnostics.iter().all(|d| d["range"] == "203-203"
                && d["expected_producer_invocation_id"]
                    .as_str()
                    .is_some_and(allowed_203_invocation)),
        "foreign diagnostic census"
    );
    Ok(())
}

fn validate_active(f: &Value) -> Result<Vec<&Value>> {
    let active = f["active"].as_array().context("missing active fleet")?;
    let mut units = std::collections::BTreeMap::<&str, &Value>::new();
    let mut claims = std::collections::BTreeSet::new();
    for e in active {
        let epoch = e["epoch"].as_u64().context("missing epoch")?;
        let phase = e["phase"].as_str().context("missing phase")?;
        ensure!(claims.insert((epoch, phase)), "duplicate active claim");
        let u = if e.get("unit").is_some() {
            &e["unit"]
        } else {
            &e["producer"]
        };
        let id = u["InvocationID"].as_str().context("missing invocation")?;
        let allowed = match phase {
            "replay" => (220..=223).contains(&epoch) && id == "c2adebaad0cb42b385156631156813fe",
            "diagnostic-qualification" => epoch == 203 && allowed_203_invocation(id),
            "full-verification" => {
                (216..=219).contains(&epoch) && id == "90240f6b62544d8aa35b1fc84101737c"
            }
            "plugin-verification" => {
                (216..=219).contains(&epoch) && id == "9fd365792925483eac69e7f0ad3ea6c5"
            }
            "upload-readback" => {
                (216..=219).contains(&epoch) && id == "9d4f7efc28c14d62a831c5fd4db6769f"
            }
            _ => false,
        };
        ensure!(
            allowed
                && u["NRestarts"] == "0"
                && matches!(u["ActiveState"].as_str(), Some("active" | "activating"))
                && u["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u32>().ok())
                    .is_some_and(|n| n > 0),
            "foreign or inactive fleet claim"
        );
        let name = u["Id"].as_str().context("missing unit")?;
        if let Some(previous) = units.insert(name, u) {
            ensure!(previous == u, "inconsistent shared unit");
        }
        if phase == "replay" {
            let c = &e["controller"];
            ensure!(
                c["InvocationID"] == "0b69b5009dc74bbda94b94d059a3daa7"
                    && c["ActiveState"] == "active"
                    && c["NRestarts"] == "0",
                "changed controller"
            );
            units.insert(c["Id"].as_str().context("missing controller")?, c);
        }
    }
    ensure!(
        (220..=223).all(|n| claims.contains(&(n, "replay"))),
        "missing ordinary claim"
    );
    Ok(units.into_values().collect())
}

pub(super) fn validate_fleet(f: &Value, observer: &Value, observer_hash: &str) -> Result<()> {
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["observer_sha256"] == observer_hash
            && f["sampled_at_utc"] == observer["recorded_at_utc"]
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false,
        "unbound225 fleet"
    );
    let ready = f["inventory"]["entries"]
        .as_array()
        .context("missing inventory")?;
    let ready: Vec<_> = ready
        .iter()
        .filter(|e| e["state"] == "ready-pair")
        .collect();
    ensure!(
        ready
            .iter()
            .filter_map(|e| e["epoch"].as_u64())
            .collect::<Vec<_>>()
            == [201, 202, 206, 213, 214, 215],
        "century samples changed"
    );
    let sum = ready
        .iter()
        .try_fold(0u64, |s, e| s.checked_add(e["archive_length"].as_u64()?))
        .context("size overflow")?;
    ensure!(
        sum == 695_624_150_347 && (2 * sum).div_ceil(6) == FLOOR,
        "century floor changed"
    );
    for u in validate_active(f)? {
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
            "cannot revalidate active fleet"
        );
        let text = std::str::from_utf8(&output.stdout)?;
        for k in [
            "Id",
            "InvocationID",
            "NRestarts",
            "MainPID",
            "ActiveState",
            "ExecStart",
        ] {
            let expected = format!("{k}={}", u[k].as_str().context("missing live field")?);
            ensure!(
                text.lines().filter(|l| *l == expected).count() == 1,
                "active fleet changed at {k}"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected225_requires_exact_inode_mount_and_geometry() {
        let path = Path::new(
            "/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-225-fixture",
        );
        let s = format!(
            "NoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=read-only\nProtectControlGroups=yes\nPrivateNetwork=yes\nOOMPolicy=kill\nOOMScoreAdjust=1000\nTemporaryFileSystem={TMPFS_OPTIONS}\nReadWritePaths={}\nCapabilityBoundingSet=cap_dac_override cap_kill cap_setgid cap_setuid\n",
            path.display()
        );
        validate_sandbox(&s, path).unwrap();
        for altered in [
            s.replace("nr_inodes=1048576,", ""),
            s.replace("nr_inodes=1048576", "nr_inodes=409600"),
            s.replace("size=512G", "size=1024G"),
        ] {
            assert!(validate_sandbox(&altered, path).is_err());
        }
        validate_inode_geometry(1_048_576).unwrap();
        for files in [409_600, 1_048_575, 1_048_577] {
            assert!(validate_inode_geometry(files).is_err());
        }
    }
    #[test]
    fn diagnostic_allowlist_is_exact() {
        assert!(allowed_203_invocation("bfdfb1a74959444e9f477451fadc3d43"));
        assert!(allowed_203_invocation("748ffa40e0a2408da0a10fc9e160cf0a"));
        assert!(!allowed_203_invocation("748ffa40e0a2408da0a10fc9e160cf0b"));
        assert!(!allowed_203_invocation(""));
    }
    #[test]
    fn plan_rejects_wrong_profile_fixture_and_scope() {
        let v = json!({"schema":"jetstreamer-private-v1625-ram-snapshot-test-plan-v1",
            "mode":"capability","unit":"horizon-v1625-snapshot-test-fixture.service",
            "test_binary":{"path":"/sealed/tests","sha256":TEST_SHA},
            "snapshot":{"path":"/sealed/snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst","sha256":SNAPSHOT_SHA},
            "genesis":{"path":"/sealed/genesis.tar.bz2","sha256":GENESIS_SHA},
            "observer":{"path":"/sealed/observer","sha256":"a".repeat(64)},
            "fleet":{"path":"/sealed/fleet","sha256":"b".repeat(64)},
            "receipt_directory":"/var/lib/jetstreamer/horizon-ram-snapshot-tests/ram-snapshot-test-225-fixture",
            "maximum_runtime_seconds":1800});
        validate_plan(&serde_json::from_value(v.clone()).unwrap()).unwrap();
        for (ptr, value) in [
            (
                "/schema",
                json!("jetstreamer-private-v1616-ram-snapshot-test-plan-v1"),
            ),
            ("/mode", json!("replay")),
            ("/unit", json!("foreign.service")),
            ("/test_binary/sha256", json!("c".repeat(64))),
            (
                "/snapshot/path",
                json!("/sealed/snapshot-86831488-other.tar.zst"),
            ),
            ("/snapshot/sha256", json!("d".repeat(64))),
            ("/receipt_directory", json!("/tmp/receipts")),
            ("/maximum_runtime_seconds", json!(1801)),
        ] {
            let mut bad = v.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(
                validate_plan(&serde_json::from_value(bad).unwrap()).is_err(),
                "{ptr}"
            );
        }
    }
    #[test]
    fn observation_requires_fresh_unchanged_routine_memory_admission() {
        let mut r = json!({"range":"220-223","invocation_binding_stable":true});
        for k in ["controller_before", "controller_after"] {
            r[k] = json!({"invocation_id":"0b69b5009dc74bbda94b94d059a3daa7","restarts":0,"active_state":"active"});
        }
        for k in ["producer_before", "producer_after"] {
            r[k] = json!({"invocation_id":"c2adebaad0cb42b385156631156813fe","restarts":0,"active_state":"active"});
        }
        let good = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-21T13:59:36Z",
            "cadence":{"routine_minimum_interval_enforced":true,"observation_reason":"routine","minimum_interval_seconds":1800},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},
            "host_memory":{"conservative_available_kib":START_MEMORY/1024},"replays":[r],"diagnostic_replays":[]});
        let now = utc("2026-10-21T14:00:00Z").unwrap();
        validate_observer(&good, now).unwrap();
        let mut root203 = good.clone();
        root203["diagnostic_replays"] = json!([{"range":"203-203", "expected_producer_invocation_id":"748ffa40e0a2408da0a10fc9e160cf0a"}]);
        validate_observer(&root203, now).unwrap();
        root203["diagnostic_replays"][0]["expected_producer_invocation_id"] =
            json!("748ffa40e0a2408da0a10fc9e160cf0b");
        assert!(validate_observer(&root203, now).is_err());
        for (ptr, value) in [
            ("/recorded_at_utc", json!("2026-10-21T13:00:00Z")),
            ("/host_memory/conservative_available_kib", json!(0)),
            ("/cadence/minimum_interval_seconds", json!(60)),
            ("/mutation/r2_mutations", json!(true)),
            ("/replays/0/producer_after/restarts", json!(1)),
            (
                "/replays/0/controller_after/invocation_id",
                json!("a".repeat(32)),
            ),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(ptr).unwrap() = value;
            assert!(validate_observer(&bad, now).is_err(), "{ptr}");
        }
    }
    #[test]
    fn rejects_foreign_or_duplicate_active_claims() {
        let unit = json!({"Id":"replay.service","InvocationID":"c2adebaad0cb42b385156631156813fe", "MainPID":"1","NRestarts":"0","ActiveState":"active"});
        let controller = json!({"Id":"controller.service","InvocationID":"0b69b5009dc74bbda94b94d059a3daa7","ActiveState":"active","NRestarts":"0"});
        let entries: Vec<_> = (220..=223)
            .map(|n| json!({"epoch":n,"phase":"replay","producer":unit,"controller":controller}))
            .collect();
        let good = json!({"active":entries});
        validate_active(&good).unwrap();
        let mut root203 = good.clone();
        root203["active"].as_array_mut().unwrap().push(json!({"epoch":203,"phase":"diagnostic-qualification","unit":{"Id":"horizon-qualify-203-shrink-root-prefix-resource-f9fc5a0-v1.service","InvocationID":"748ffa40e0a2408da0a10fc9e160cf0a","MainPID":"42","NRestarts":"0","ActiveState":"active"}}));
        validate_active(&root203).unwrap();
        root203["active"][4]["unit"]["InvocationID"] = json!("748ffa40e0a2408da0a10fc9e160cf0b");
        assert!(validate_active(&root203).is_err());
        for (ptr, v) in [
            ("/active/0/epoch", json!(225)),
            ("/active/0/producer/NRestarts", json!("1")),
            ("/active/0/producer/InvocationID", json!("a".repeat(32))),
            ("/active/0/producer/MainPID", json!("0")),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(ptr).unwrap() = v;
            assert!(validate_active(&bad).is_err(), "{ptr}");
        }
        let mut bad = good;
        let duplicate = bad["active"][0].clone();
        bad["active"].as_array_mut().unwrap().push(duplicate);
        assert!(validate_active(&bad).is_err());
    }
    #[test]
    fn exact_profile_and_test_census() {
        assert_eq!(CPU_CORES, 8);
        assert_eq!(SNAPSHOT_SIZE, 10_177_204_112);
        validate_test_list(&format!(
            "{}\n{}\n2 tests, 0 benchmarks\n",
            TEST_NAMES[0], TEST_NAMES[1]
        ))
        .unwrap();
        assert!(validate_test_list("2 tests, 0 benchmarks\n").is_err());
        validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY).unwrap();
    }
}
