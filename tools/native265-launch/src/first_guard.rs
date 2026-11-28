use super::*;
pub(super) fn first_guard(
    p: &Value,
    t: &Value,
    gp: &Value,
    g: &Value,
    j: &Value,
    clock: u64,
) -> Result<()> {
    let iid = text(t, "invocation_id")?;
    let gid = text(t, "guard_invocation_id")?;
    let pid = num(t, "main_pid")?;
    ensure!(
        hex(iid, 32) && hex(gid, 32) && iid != gid && pid > 1,
        "token identities"
    );
    let issued = num(p, "issued_monotonic_us")?;
    let expires = num(p, "expires_monotonic_us")?;
    ensure!(
        expires > issued
            && expires - issued <= 60_000_000
            && num(t, "recorded_monotonic_us")? >= issued,
        "first guard reset or lengthened original window"
    );
    ensure!(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == UNIT
            && gp["invocation_id"] == iid
            && gp["filesystem"] == EXPECTED_FILESYSTEM
            && gp["worker_root"] == ROOT
            && gp["minimum_free_bytes"] == p["minimum_free_bytes"]
            && gp["maximum_root_physical_bytes"] == SCRATCH
            && gp["maximum_worker_vmas"] == 3500000
            && gp["native_main"]["main_pid"] == pid
            && gp["native_main"]["executable"] == HARNESS
            && gp["native_main"]["sha256"] == HARNESS_SHA
            && gp.get("bounded_measurement").is_none_or(Value::is_null)
            && gp.get("bounded_canary").is_none_or(Value::is_null),
        "first native guard plan differs"
    );
    ensure!(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["plan"] == t["guard_plan"]["path"]
            && g["plan_sha256"] == t["guard_plan"]["sha256"]
            && g["guard_sha256"] == p["guard"]["sha256"]
            && g["guard_invocation_id"] == gid
            && g["producer_invocation_id"] == iid
            && g["producer"]["invocation_id"] == iid
            && g["producer"]["pid"] == pid
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["restarts"] == 0
            && g["producer"]["cgroup"] == format!("/system.slice/{UNIT}")
            && g["producer_stop_enabled"] == true
            && g["native_main"] == gp["native_main"]
            && g["minimum_free_bytes"] == p["minimum_free_bytes"]
            && num(g, "available_bytes")? >= num(p, "minimum_free_bytes")?
            && g["maximum_worker_vmas"] == 3_500_000
            && g["maximum_root_physical_bytes"] == SCRATCH
            && g["root_physical_observation"]["maximum_physical_bytes"] == SCRATCH
            && g["root_physical_observation"]["exceeds_budget"] == false
            && num(
                &g["root_physical_observation"],
                "conservative_physical_bytes"
            )? <= SCRATCH
            && g["workers"].as_array().is_some_and(|v| v.len() == 1)
            && g["workers"][0][0] == pid
            && g["workers"][0][1]
                .as_u64()
                .is_some_and(|v| v > 0 && v < 3_500_000)
            && g["bounded_measurement"] == false
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "first guard did not protect native main"
    );
    for key in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "canary_target_error",
        "target_handoff_error",
        "bounded_canary",
        "target_handoff",
    ] {
        ensure!(
            g.get(key) == Some(&Value::Null),
            "guard error or missing null {key}"
        );
    }
    fresh(num(g, "recorded_unix_seconds")?, clock, 60)?;
    let rows = j.as_array().context("PID1 array")?;
    ensure!(!rows.is_empty() && rows.len() <= 64, "journal bound");
    let rows: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == gid
                && r["_BOOT_ID"] == text(p, "boot_id").unwrap_or("").replace('-', "")
        })
        .collect();
    let start: Vec<_> = rows
        .iter()
        .filter(|r| {
            r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with(&format!("Starting {GUARD_UNIT} -")))
        })
        .collect();
    let end: Vec<_> = rows
        .iter()
        .filter(|r| r["MESSAGE"] == format!("{GUARD_UNIT}: Deactivated successfully."))
        .collect();
    ensure!(
        start.len() == 1 && end.len() == 1,
        "genuine unique PID1 first fire missing"
    );
    let start = text(start[0], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
    let end = text(end[0], "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
    ensure!(
        start >= num(p, "issued_monotonic_us")?
            && end > start
            && end <= num(t, "recorded_monotonic_us")?
            && num(t, "recorded_monotonic_us")? < num(p, "expires_monotonic_us")?,
        "guard outside original startup window"
    );
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn first_guard_rejects_absent_evidence() {
        assert!(
            first_guard(
                &json!({}),
                &json!({}),
                &json!({}),
                &json!({}),
                &json!([]),
                0
            )
            .is_err()
        );
    }
    pub(crate) fn fixture() -> (Value, Value, Value, Value, Value) {
        let p = json!({"boot_id":"00000000-0000-0000-0000-000000000001","guard":{"sha256":GUARD_SHA},"minimum_free_bytes":100,"issued_monotonic_us":1000,"expires_monotonic_us":60_001_000});
        let t = json!({"invocation_id":"a".repeat(32),"guard_invocation_id":"b".repeat(32),"main_pid":42,"guard_plan":{"path":"/var/lib/jetstreamer/guard/plan.json","sha256":"c".repeat(64)},"recorded_monotonic_us":3000});
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":t["invocation_id"],"filesystem":EXPECTED_FILESYSTEM,"worker_root":ROOT,"minimum_free_bytes":100,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"native_main":{"main_pid":42,"executable":HARNESS,"sha256":HARNESS_SHA}});
        let g = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","plan":t["guard_plan"]["path"],"plan_sha256":t["guard_plan"]["sha256"],"guard_sha256":GUARD_SHA,"guard_invocation_id":t["guard_invocation_id"],"producer_invocation_id":t["invocation_id"],
            "producer":{"invocation_id":t["invocation_id"],"pid":42,"active":"active","sub":"running","load_state":"loaded","result":"success","restart_policy":"no","kill_mode":"control-group","delegated":false,"restarts":0,"cgroup":format!("/system.slice/{UNIT}")},"producer_stop_enabled":true,"native_main":gp["native_main"],"minimum_free_bytes":100,"available_bytes":101,"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":SCRATCH,"root_physical_observation":{"maximum_physical_bytes":SCRATCH,"exceeds_budget":false,"conservative_physical_bytes":1},"workers":[[42,10]],"bounded_measurement":false,"remote_mutations":false,"r2_mutations":false,"recorded_unix_seconds":100,
            "trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"canary_target_error":null,"target_handoff_error":null,"bounded_canary":null,"target_handoff":null});
        let row = |message: String, clock: &str| json!({"_PID":"1","_UID":"0","UNIT":GUARD_UNIT,"INVOCATION_ID":t["guard_invocation_id"],"_BOOT_ID":"00000000000000000000000000000001","MESSAGE":message,"__MONOTONIC_TIMESTAMP":clock});
        let j = json!([
            row(format!("Starting {GUARD_UNIT} - guard..."), "1001"),
            row(format!("{GUARD_UNIT}: Deactivated successfully."), "2000")
        ]);
        (p, t, gp, g, j)
    }
    #[test]
    fn first_guard_requires_real_native_sample_and_original_pid1_window() {
        let (p, t, gp, g, j) = fixture();
        first_guard(&p, &t, &gp, &g, &j, 100).unwrap();
        for (pointer, value) in [
            ("/producer_stop_enabled", json!(false)),
            ("/producer/pid", json!(43)),
            ("/producer/restarts", json!(1)),
            ("/workers", json!([[43, 10]])),
            ("/native_main/sha256", json!("0".repeat(64))),
            ("/bounded_measurement", json!(true)),
            ("/trip_reason", json!("floor")),
            ("/recorded_unix_seconds", json!(39)),
            ("/recorded_unix_seconds", json!(101)),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                first_guard(&p, &t, &gp, &bad, &j, 100).is_err(),
                "{pointer}"
            );
        }
        for (pointer, value) in [
            ("/0/_PID", json!("42")),
            ("/1/INVOCATION_ID", json!("c".repeat(32))),
            ("/0/__MONOTONIC_TIMESTAMP", json!("999")),
            ("/1/__MONOTONIC_TIMESTAMP", json!("3001")),
            ("/1/_BOOT_ID", json!("0".repeat(32))),
        ] {
            let mut bad = j.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                first_guard(&p, &t, &gp, &g, &bad, 100).is_err(),
                "{pointer}"
            );
        }
        assert!(first_guard(&p, &t, &gp, &g, &json!([j[0], j[0], j[1]]), 100).is_err());
        let mut missing = g.clone();
        missing.as_object_mut().unwrap().remove("trip_reason");
        assert!(first_guard(&p, &t, &gp, &missing, &j, 100).is_err());
        for key in gp.as_object().unwrap().keys() {
            let mut bad = gp.clone();
            bad[key] = Value::Null;
            assert!(
                first_guard(&p, &t, &bad, &g, &j, 100).is_err(),
                "plan {key}"
            );
        }
        for (key, value) in [
            ("issued_monotonic_us", json!(2001)),
            ("expires_monotonic_us", json!(60_001_001)),
            ("expires_monotonic_us", json!(3000)),
        ] {
            let mut bad = p.clone();
            bad[key] = value;
            assert!(
                first_guard(&bad, &t, &gp, &g, &j, 100).is_err(),
                "clock {key}"
            );
        }
    }
}
