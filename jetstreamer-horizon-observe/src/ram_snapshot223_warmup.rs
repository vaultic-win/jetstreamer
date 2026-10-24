//! Exact native input qualification of the bounded 223 worker, never entry replay.
use super::*;
const PACKAGE: &str = if cfg!(feature = "epoch223-v1620-native-input-release") {
    "/var/lib/jetstreamer/horizon-223-v1620-native-release-test-v1"
} else if V1620 {
    "/var/lib/jetstreamer/horizon-223-v1620-native-test-v1"
} else {
    "/var/lib/jetstreamer/horizon-223-warmup-e3d48954-v1"
};
const PLAN_SCHEMA: &str = if V1620 {
    "jetstreamer-private-epoch223-v1620-native-input-plan-v1"
} else {
    "jetstreamer-private-epoch223-warmup-native-input-plan-v1"
};
const UNIT_PREFIX: &str = if V1620 {
    "archive-223-v1620-native-input-"
} else {
    "archive-223-warmup-snapshot-"
};
const RECEIPT_PREFIX: &str = if V1620 {
    "ram-snapshot-test-223-v1620-"
} else {
    "ram-snapshot-test-223-warmup-"
};
const INPUT: &str = "/var/lib/jetstreamer/horizon-223-known-root-prefix-b1670f57-v1";
const OWNERS: [(u64, &str, &str, &str); 3] = [
    (
        225,
        "225-226",
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
    (
        205,
        "205-205",
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
    (
        204,
        "204-204",
        "horizon-qualify-204-shrink-root-prefix-resource-fcbf3992-v1.service",
        "448da7f2a3a34217afe7e115120b3cea",
    ),
];
const UPLOAD: &str = "horizon-upload-203-v4-20261023-v1.service";
const UPLOAD_IID: &str = "4a9d184a487540409e4edcd1ac353cf4";

pub(super) fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == PLAN_SCHEMA
            && matches!(p.mode.as_str(), "capability" | "snapshot-tests")
            && p.unit.starts_with(UNIT_PREFIX)
            && p.unit.ends_with(".service")
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "foreign warmup qualification plan"
    );
    ensure!(
        p.test_binary.path == Path::new(PACKAGE).join("snapshot-test-harness")
            && p.test_binary.sha256 == TEST_SHA
            && p.snapshot.path
                == Path::new(INPUT)
                    .join("snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst")
            && p.snapshot.sha256 == SNAPSHOT_SHA
            && p.genesis.path == Path::new(INPUT).join("genesis.tar.bz2")
            && p.genesis.sha256 == GENESIS_SHA,
        "warmup qualification input binding differs"
    );
    ensure!(
        p.receipt_directory.parent()
            == Some(Path::new("/var/lib/jetstreamer/horizon-ram-snapshot-tests"))
            && p.receipt_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.starts_with(RECEIPT_PREFIX)
                    && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
            && (60..=1800).contains(&p.maximum_runtime_seconds),
        "warmup qualification output/time differs"
    );
    validate_reserves(TMPFS_SIZE, MEMORY_MAX, FLOOR, STOP_MEMORY)
}

pub(super) fn validate_observer(o: &Value, now: u64) -> Result<()> {
    let routine = o["cadence"]["routine_minimum_interval_enforced"] == true
        && o["cadence"]["observation_reason"] == "routine";
    let requested = V1620
        && o["cadence"]["routine_minimum_interval_enforced"] == false
        && o["cadence"]["observation_reason"] == "user-requested-status";
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && (routine || requested)
            && o["cadence"]["minimum_interval_seconds"] == 1800,
        "not an authorized warmup input sample"
    );
    let sampled = utc(o["recorded_at_utc"]
        .as_str()
        .context("warmup sample clock")?)?;
    ensure!(
        sampled <= now
            && now - sampled <= 1800
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .and_then(|n| n.checked_mul(1024))
                .is_some_and(|n| n >= START_MEMORY),
        "stale/insufficient warmup input sample"
    );
    for key in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(o["mutation"][key] == false, "mutating warmup observer");
    }
    ensure!(
        o["replays"].as_array().is_some_and(Vec::is_empty),
        "unaccounted ordinary replay"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("warmup diagnostic census")?;
    ensure!(
        rows.len() == OWNERS.len(),
        "warmup diagnostic count differs"
    );
    for (_, range, name, iid) in OWNERS {
        let matching = rows
            .iter()
            .filter(|r| r["range"] == range)
            .collect::<Vec<_>>();
        ensure!(matching.len() == 1, "missing/duplicate protected replay");
        let row = matching[0];
        ensure!(
            row["status"] == "observed"
                && row["producer_unit"] == name
                && row["expected_producer_invocation_id"] == iid
                && row["observation"]["invocation_binding_stable"] == true,
            "protected observation differs"
        );
        for key in [
            "controller_before",
            "controller_after",
            "producer_before",
            "producer_after",
        ] {
            let u = &row["observation"][key];
            ensure!(
                u["invocation_id"] == iid && u["restarts"] == 0 && u["active_state"] == "active",
                "protected observation changed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_event_clock_is_canonical_and_never_wraps_unsigned_seconds() {
        assert_eq!(metadata_utc(1_792_774_959).unwrap(), "2026-10-23T17:02:39Z");
        assert_eq!(metadata_utc(0).unwrap(), "1970-01-01T00:00:00Z");
        assert!(metadata_utc(u64::MAX).is_err());
    }
    #[test]
    fn selected_native_harness_requires_its_exact_list_and_receipt_era() {
        let count = if V1620 {
            "1 test, 0 benchmarks"
        } else {
            "2 tests, 0 benchmarks"
        };
        let text = format!("{}\n\n{count}\n", TEST_NAMES.join("\n"));
        validate_test_list(&text).unwrap();
        assert!(validate_test_list(&text.replace(TEST_NAMES[0], "foreign: test")).is_err());
        assert!(validate_test_list(&text.replace(count, "0 tests, 0 benchmarks")).is_err());
        if V1620 {
            assert!(receipt_schema("intent").contains("v1620"));
            assert_eq!(TEST_NAMES.len(), 1);
            assert!(!FILTER.contains("v1_6_25"));
        }
    }
    fn observer() -> Value {
        let diagnostics = OWNERS.iter().map(|(_,range,name,iid)| {
            let role=json!({"invocation_id":iid,"restarts":0,"active_state":"active"});
            json!({"range":range,"producer_unit":name,"expected_producer_invocation_id":iid,
                "status":"observed","observation":{"invocation_binding_stable":true,
                "controller_before":role,"controller_after":role,"producer_before":role,"producer_after":role}})
        }).collect::<Vec<_>>();
        json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T11:16:43Z",
            "cadence":{"routine_minimum_interval_enforced":true,"observation_reason":"routine","minimum_interval_seconds":1800},
            "mutation":{"producer_or_controller_signals_sent":false,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false},
            "host_memory":{"conservative_available_kib":START_MEMORY/1024,"total_kib":1_200_000_000},
            "replays":[],"diagnostic_replays":diagnostics})
    }
    #[test]
    fn observation_requires_every_current_replay_and_a_fresh_stable_census() {
        let good = observer();
        let now = utc("2026-10-23T11:17:00Z").unwrap();
        validate_observer(&good, now).unwrap();
        for (pointer, value) in [
            ("/diagnostic_replays/2/status", json!("unavailable")),
            (
                "/diagnostic_replays/1/observation/producer_after/restarts",
                json!(1),
            ),
            (
                "/diagnostic_replays/0/observation/controller_before/invocation_id",
                json!("f".repeat(32)),
            ),
            ("/host_memory/conservative_available_kib", json!(0)),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(validate_observer(&bad, now).is_err(), "{pointer}");
        }
        assert!(validate_observer(&good, now + 1801).is_err());
    }
    #[test]
    fn native20_user_requested_sample_requires_the_exact_cadence_pair() {
        let mut requested = observer();
        requested["cadence"]["routine_minimum_interval_enforced"] = json!(false);
        requested["cadence"]["observation_reason"] = json!("user-requested-status");
        let now = utc("2026-10-23T11:17:00Z").unwrap();
        assert_eq!(validate_observer(&requested, now).is_ok(), V1620);
        requested["cadence"]["observation_reason"] = json!("routine");
        assert!(validate_observer(&requested, now).is_err());
    }
    #[test]
    fn active_owners_exclude_other_work_but_include_the_actual_optional_upload() {
        let active=OWNERS.iter().map(|(epoch,_,name,iid)|json!({"epoch":epoch,
            "ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"producer":{
                "Id":name,"InvocationID":iid,"NRestarts":"0","MainPID":"42","ActiveState":"active","SubState":"running"}})).collect::<Vec<_>>();
        let mut f = json!({"active":active});
        assert_eq!(owners(&f).unwrap().len(), 3);
        f["active"]
            .as_array_mut()
            .unwrap()
            .push(json!({"epoch":203,"phase":"upload-readback",
            "unit":{"Id":UPLOAD,"InvocationID":UPLOAD_IID,"NRestarts":"0","MainPID":"43"}}));
        f["active"][3]["unit"]["ActiveState"] = json!("activating");
        f["active"][3]["unit"]["SubState"] = json!("start");
        assert_eq!(owners(&f).unwrap().len(), 4);
        f["active"][3]["unit"]["InvocationID"] = json!("f".repeat(32));
        assert!(owners(&f).is_err());
        f["active"].as_array_mut().unwrap().pop();
        f["active"][1]["producer"]["MainPID"] = json!("0");
        assert!(owners(&f).is_err());
    }
    #[test]
    fn native_plan_is_bound_to_the_new_harness_cold_snapshot_and_private_scope() {
        let mut p = Plan {
            schema: PLAN_SCHEMA.into(),
            mode: "capability".into(),
            unit: format!("{UNIT_PREFIX}fixture.service"),
            test_binary: Bound {
                path: Path::new(PACKAGE).join("snapshot-test-harness"),
                sha256: TEST_SHA.into(),
            },
            snapshot: Bound {
                path: Path::new(INPUT)
                    .join("snapshot-96335538-Gavt9cmcj5BFXuZnz44JktRGbM9oxRkJqoWRF8PvMBTE.tar.zst"),
                sha256: SNAPSHOT_SHA.into(),
            },
            genesis: Bound {
                path: Path::new(INPUT).join("genesis.tar.bz2"),
                sha256: GENESIS_SHA.into(),
            },
            observer: Bound {
                path: "/fixture/observer".into(),
                sha256: "a".repeat(64),
            },
            fleet: Bound {
                path: "/fixture/fleet".into(),
                sha256: "b".repeat(64),
            },
            receipt_directory: format!(
                "/var/lib/jetstreamer/horizon-ram-snapshot-tests/{RECEIPT_PREFIX}fixture"
            )
            .into(),
            maximum_runtime_seconds: 1800,
        };
        validate_plan(&p).unwrap();
        p.test_binary.sha256 = "a".repeat(64);
        assert!(validate_plan(&p).is_err());
        p.test_binary.sha256 = TEST_SHA.into();
        p.maximum_runtime_seconds = 1801;
        assert!(validate_plan(&p).is_err());
    }
}

fn owners(f: &Value) -> Result<Vec<&Value>> {
    let active = f["active"].as_array().context("warmup active census")?;
    ensure!(
        (3..=4).contains(&active.len()),
        "unaccounted active warmup peer"
    );
    let mut result = Vec::new();
    for (epoch, _, name, iid) in OWNERS {
        let matching = active
            .iter()
            .filter(|r| r["epoch"] == epoch)
            .collect::<Vec<_>>();
        ensure!(matching.len() == 1, "protected replay missing/duplicate");
        let row = matching[0];
        let u = &row["producer"];
        ensure!(
            row["ordinary_replay_claim"] == false
                && row["current_sidecar_eta_valid"] == false
                && u["Id"] == name
                && u["InvocationID"] == iid
                && u["NRestarts"] == "0"
                && u["ActiveState"] == "active"
                && u["SubState"] == "running"
                && u["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 0),
            "protected replay owner differs"
        );
        result.push(u);
    }
    if active.len() == 4 {
        let row = active
            .iter()
            .find(|r| r["epoch"] == 203)
            .context("unaccounted fourth owner")?;
        let u = &row["unit"];
        ensure!(
            row["phase"] == "upload-readback"
                && u["Id"] == UPLOAD
                && u["InvocationID"] == UPLOAD_IID
                && u["NRestarts"] == "0"
                && ((u["ActiveState"] == "activating" && u["SubState"] == "start")
                    || (u["ActiveState"] == "active" && u["SubState"] == "running"))
                && u["MainPID"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 0),
            "foreign 203 delivery owner"
        );
        result.push(u);
    }
    Ok(result)
}

fn fleet_shape(f: &Value, o: &Value, hash: &str) -> Result<()> {
    ensure!(
        f["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && f["first_epoch"] == 201
            && f["last_epoch"] == 300
            && f["observer_sha256"] == hash
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["producer_mutations"] == false
            && f["remote_mutations"] == false
            && f["inventory"]["anomalies"] == 0,
        "warmup fleet binding differs"
    );
    // Allow the independently delivered 203 pair to join the existing sample,
    // while retaining the older, stricter floor and every old guard unchanged.
    let ready = f["inventory"]["entries"]
        .as_array()
        .context("warmup remote census")?
        .iter()
        .filter(|r| r["state"] == "ready-pair")
        .collect::<Vec<_>>();
    ensure!(
        (13..=14).contains(&ready.len()),
        "warmup century census changed"
    );
    let mut sum = 0u64;
    let mut seen = std::collections::BTreeSet::new();
    for row in ready {
        let epoch = row["epoch"].as_u64().context("warmup inventory epoch")?;
        ensure!(seen.insert(epoch), "duplicate ready sample");
        let length = row["archive_length"]
            .as_u64()
            .context("warmup archive length")?;
        let expected = match epoch {
            201 => 102605729507,
            202 => 101842225683,
            203 => 103802397352,
            206 => 108774749680,
            213 => 125368013231,
            214 => 128213350837,
            215 => 128820081409,
            216 => 128977079203,
            217 => 129125423643,
            218 => 125325863645,
            219 => 128896280026,
            220 => 135699623364,
            221 => 137055363091,
            222 => 133175903649,
            _ => anyhow::bail!("foreign century sample"),
        };
        ensure!(length == expected, "warmup canonical length changed");
        sum = sum.checked_add(length).context("warmup floor overflow")?;
    }
    ensure!(
        [
            201, 202, 206, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222
        ]
        .iter()
        .all(|n| seen.contains(n))
            && sum
                .checked_mul(2)
                .context("warmup floor overflow")?
                .div_ceil(seen.len() as u64)
                <= FLOOR,
        "warmup floor no longer protected"
    );
    owners(f)?;
    Ok(())
}

pub(super) fn validate_fleet(f: &Value, o: &Value, hash: &str) -> Result<()> {
    fleet_shape(f, o, hash)?;
    for u in owners(f)? {
        let name = u["Id"].as_str().context("warmup owner name")?;
        let output = Command::new("/usr/bin/systemctl").args(["show",name,"--no-pager",
            "--property=Id,InvocationID,NRestarts,MainPID,ActiveState,SubState,ExecStart,MemoryMax,MemorySwapMax"]).output()?;
        ensure!(
            output.status.success() && output.stdout.len() < 65536,
            "warmup owner lookup failed"
        );
        let text = std::str::from_utf8(&output.stdout)?;
        for key in [
            "Id",
            "InvocationID",
            "NRestarts",
            "MainPID",
            "ActiveState",
            "SubState",
            "ExecStart",
        ] {
            let expected = format!(
                "{key}={}",
                u[key].as_str().context("missing protected owner field")?
            );
            ensure!(
                text.lines().filter(|line| *line == expected).count() == 1,
                "protected warmup owner changed at {key}"
            );
        }
        let max = match name {
            UPLOAD => 32 * GIB,
            n if n == OWNERS[0].2 => 192 * GIB,
            _ => 224 * GIB,
        };
        ensure!(
            text.lines().any(|l| l == format!("MemoryMax={max}"))
                && text.lines().any(|l| l == "MemorySwapMax=0"),
            "protected warmup memory envelope differs"
        );
    }
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("warmup memory total")?
        .checked_mul(1024)
        .context("warmup memory overflow")?;
    ensure!(
        total >= 800 * GIB + total / 10,
        "warmup maximum peer+candidate caps and host reserve do not fit"
    );
    for name in [
        "horizon-ownroot225-protective-v1.timer",
        "horizon-prefix205-protective-v1.timer",
        "horizon-prefix204-protective-v1.timer",
    ] {
        let output = Command::new("/usr/bin/systemctl")
            .args(["show", name, "--value", "--property=ActiveState"])
            .output()?;
        ensure!(
            output.status.success() && output.stdout == b"active\n",
            "protected warmup guard inactive"
        );
    }
    Ok(())
}
