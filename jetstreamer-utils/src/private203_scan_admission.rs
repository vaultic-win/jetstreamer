// Fresh admission for the exact203 private scan; no producer signals or R2 access.
const SCAN203_UNIT: &str = "horizon-full-verify-203-private-v4-af051b90-v1.service";
const PROTECTED203_PRODUCERS: [(&str, &str); 2] = [
    (
        "horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service",
        "4cd76ae1353a4411885b997f04306402",
    ),
    (
        "horizon-qualify-205-shrink-root-prefix-resource-5c01bf93-v1.service",
        "373359a11aef4993a1a949e19ff617c3",
    ),
];

fn scan203_properties(unit: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let out = Command::new("/usr/bin/systemctl").args(["show", unit, "--no-pager",
        "--property=ActiveState,SubState,InvocationID,NRestarts,Restart,MainPID,Result,MemoryMax,MemoryHigh,MemorySwapMax,ControlGroup,Type,TimeoutStartUSec,ProtectSystem,ProtectHome,ReadWritePaths,PrivateNetwork,CPUQuotaPerSecUSec,TasksMax"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 32768,
        "scan admission service query failed"
    );
    let mut fields = std::collections::BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("invalid admission service field")?;
        ensure!(
            fields.insert(key.to_owned(), value.to_owned()).is_none(),
            "duplicate admission field"
        );
    }
    Ok(fields)
}

fn scan203_live(p: &std::collections::BTreeMap<String, String>, iid: &str) -> Result<()> {
    for (key, value) in [
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", iid),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("MemorySwapMax", "0"),
    ] {
        ensure!(
            p.get(key).map(String::as_str) == Some(value),
            "scan admission protected service differs: {key}"
        );
    }
    ensure!(
        p.get("MainPID")
            .context("admission MainPID")?
            .parse::<u64>()?
            > 0,
        "admission producer missing"
    );
    let expected_cap_gib = if iid == PROTECTED203_PRODUCERS[0].1 {
        192
    } else {
        224
    };
    ensure!(
        p.get("MemoryMax")
            .context("admission memory cap")?
            .parse::<u64>()?
            == expected_cap_gib << 30,
        "protected producer cap changed"
    );
    Ok(())
}

fn scan203_campaign_service(name: &str) -> bool {
    [
        "horizon-qualify-",
        "horizon-publish-",
        "horizon-upload-",
        "horizon-full-verify-",
        "horizon-plugin-verify-",
        "horizon-independent-full-read-",
        "horizon-native-",
        "horizon-perf-epoch",
    ]
    .iter()
    .any(|prefix| {
        name.strip_prefix(prefix)
            .and_then(|tail| tail.split(['-', '@', '.']).next())
            .and_then(|n| n.parse::<u64>().ok())
            .is_some_and(|n| (201..=301).contains(&n))
    }) || name.starts_with("jetstreamer-root-sweep-horizon-")
        || name.starts_with("jetstreamer-root-import-horizon-")
}

fn scan203_census() -> Result<Vec<String>> {
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running,activating",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 4 << 20,
        "scan admission census failed"
    );
    let entries: Vec<Value> = serde_json::from_slice(&out.stdout)?;
    let mut census = Vec::new();
    for entry in entries {
        let name = entry["unit"]
            .as_str()
            .context("scan admission census name")?;
        if scan203_campaign_service(name) {
            ensure!(
                name == SCAN203_UNIT
                    || PROTECTED203_PRODUCERS.iter().any(|(unit, _)| *unit == name),
                "unaccounted campaign work: {name}"
            );
            census.push(name.to_owned());
        }
    }
    census.sort();
    ensure!(
        census.len() == 3 && census.iter().any(|n| n == SCAN203_UNIT),
        "scan admission incomplete fleet"
    );
    Ok(census)
}

fn scan203_memory(text: &str) -> Result<(u64, u64)> {
    let mut found = std::collections::BTreeMap::new();
    for line in text.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if matches!(parts.first(), Some(&"MemTotal:" | &"MemAvailable:")) {
            ensure!(parts.len() == 3 && parts[2] == "kB", "invalid memory units");
            let bytes = parts[1]
                .parse::<u64>()?
                .checked_mul(1024)
                .context("memory overflow")?;
            ensure!(
                found.insert(parts[0], bytes).is_none(),
                "duplicate memory field"
            );
        }
    }
    let total = *found.get("MemTotal:").context("missing total memory")?;
    let available = *found
        .get("MemAvailable:")
        .context("missing available memory")?;
    ensure!(available <= total && total > 0, "invalid memory bounds");
    Ok((total, available))
}

fn scan203_guard(
    directory: &str,
    timer: &str,
    unit: &str,
    iid: &str,
    binary_sha: &str,
    plan_sha: &str,
    own_root: bool,
) -> Result<Value> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    private_dir(Path::new(directory))?;
    let mut latest: Option<(u64, Evidence, Value)> = None;
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("sample-") && n.ends_with(".json"))
        {
            continue;
        }
        let evidence = Evidence {
            sha256: measure(&path, true)?.0,
            path,
        };
        let v = read_json(&evidence)?;
        let time = v["recorded_unix_seconds"]
            .as_u64()
            .context("guard sample missing time")?;
        ensure!(time <= now, "guard sample is in the future");
        if latest.as_ref().is_none_or(|(prior, _, _)| time > *prior) {
            latest = Some((time, evidence, v));
        }
    }
    let (time, evidence, v) = latest.context("scan admission has no guard receipt")?;
    ensure!(
        now - time <= 180
            && v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && v["guard_sha256"] == binary_sha
            && v["plan_sha256"] == plan_sha
            && v["producer_invocation_id"] == iid
            && v["producer"]["invocation_id"] == iid
            && v["producer"]["active"] == "active"
            && v["producer"]["sub"] == "running"
            && v["producer"]["restarts"] == 0
            && v["producer"]["cgroup"] == format!("/system.slice/{unit}")
            && v["trip_reason"].is_null()
            && v.get("trip_reason").is_some()
            && v.get("worker_observation_error")
                .is_some_and(Value::is_null)
            && v["maximum_worker_vmas"] == 3500000
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false,
        "scan admission guard is stale, tripped or foreign"
    );
    if own_root {
        ensure!(
            v["maximum_root_physical_bytes"] == 300_000_000_000u64
                && v.get("root_physical_observation_error")
                    .is_some_and(Value::is_null)
                && v["producer_stop_enabled"] == true,
            "205 own-root guard differs"
        );
    } else {
        ensure!(
            v.get("producer_stop_enabled").is_none(),
            "legacy225 guard format differs"
        );
    }
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            timer,
            "--property=ActiveState,SubState",
            "--no-pager",
        ])
        .output()?;
    ensure!(
        out.status.success()
            && std::str::from_utf8(&out.stdout)?
                .lines()
                .all(|line| matches!(line, "ActiveState=active" | "SubState=waiting"))
            && out
                .stdout
                .split(|b| *b == b'\n')
                .filter(|s| !s.is_empty())
                .count()
                == 2,
        "protective timer is not waiting"
    );
    Ok(
        json!({"receipt":evidence,"recorded_unix_seconds":time,"timer":timer,"guard_sha256":binary_sha,"plan_sha256":plan_sha}),
    )
}

fn admit_private203_scan(plan: &Plan, binding: &Evidence, runner: &str) -> Result<()> {
    if EPOCH != 203 {
        return Ok(());
    }
    let before = scan203_census()?;
    let mut producers = Vec::new();
    for (unit, iid) in PROTECTED203_PRODUCERS {
        let p = scan203_properties(unit)?;
        scan203_live(&p, iid)?;
        producers.push((unit, p));
    }
    let own = scan203_properties(SCAN203_UNIT)?;
    for (key, value) in [
        ("Type", "oneshot"),
        ("ActiveState", "activating"),
        ("SubState", "start"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("MemoryMax", "137438953472"),
        ("MemoryHigh", "103079215104"),
        ("MemorySwapMax", "0"),
        ("TimeoutStartUSec", "12h"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("TasksMax", "512"),
    ] {
        ensure!(
            own.get(key).map(String::as_str) == Some(value),
            "scan203 sandbox differs: {key}"
        );
    }
    ensure!(
        own.get("ReadWritePaths").map(String::as_str) == plan.private_directory.to_str(),
        "scan203 write scope differs"
    );
    let iid = own.get("InvocationID").context("scan203 invocation")?;
    ensure!(
        iid.len() == 32 && iid.bytes().all(|b| b.is_ascii_hexdigit()),
        "scan203 invocation missing"
    );
    let (total, available) = scan203_memory(&fs::read_to_string("/proc/meminfo")?)?;
    let charged = (192u64 + 224 + 128) << 30;
    let target = total / 10 * 9;
    ensure!(
        charged <= target && available >= (128u64 << 30) + total / 10,
        "scan203 memory admission failed"
    );
    let free = free_bytes(&plan.private_directory)?;
    ensure!(
        free.checked_sub(plan.maximum_archive_bytes)
            .is_some_and(|remaining| remaining >= plan.protected_free_bytes),
        "scan203 disk admission failed"
    );
    let guards = vec![
        scan203_guard(
            "/var/lib/jetstreamer/horizon-ownroot225-rebased-guard-receipts-v1",
            "horizon-ownroot225-protective-v1.timer",
            PROTECTED203_PRODUCERS[0].0,
            PROTECTED203_PRODUCERS[0].1,
            "cc3536dfcc268c913feccf1603a25e3cdbdf2807289c9061e04884027d1b1560",
            "831f3eae5d4326d04ae399b4046532cda5cceb32e8e3f89b87a1de0b299a3d22",
            false,
        )?,
        scan203_guard(
            "/var/lib/jetstreamer/horizon-prefix205-guard-receipts-v1",
            "horizon-prefix205-protective-v1.timer",
            PROTECTED203_PRODUCERS[1].0,
            PROTECTED203_PRODUCERS[1].1,
            "134904cf2e28ce3ede1dd85a6878e40a407443580d4e83a50cb30efc29fd28be",
            "2b639357a4754b914ad9f4af949fb7c38085a37b9cac7aa0b2c519950ee963e7",
            true,
        )?,
    ];
    let after = scan203_census()?;
    ensure!(before == after, "scan203 fleet changed during admission");
    for (unit, p) in &producers {
        let after = scan203_properties(unit)?;
        for key in [
            "InvocationID",
            "MainPID",
            "NRestarts",
            "ActiveState",
            "SubState",
            "MemoryMax",
            "MemorySwapMax",
        ] {
            ensure!(
                p.get(key) == after.get(key),
                "protected service changed during scan admission"
            );
        }
    }
    write_new(
        &plan.private_directory.join("admission.json"),
        &json!({"schema":"jetstreamer-private-epoch203-scan-admission-v1","plan":binding,"runner_sha256":runner,"unit":SCAN203_UNIT,"invocation_id":iid,"sandbox":own,"producers":producers,"guards":guards,"census_before":before,"census_after":after,"host_total_bytes":total,"host_available_bytes":available,"charged_hard_caps_bytes":charged,"target_memory_bytes":target,"available_disk_bytes":free,"maximum_copy_bytes":plan.maximum_archive_bytes,"protected_free_bytes":plan.protected_free_bytes,"recorded_unix_seconds":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),"scan_only_admitted":true,"publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}

#[cfg(test)]
mod admission203_tests {
    use super::*;
    #[test]
    fn memory_units_and_bounds_are_checked() {
        assert_eq!(
            scan203_memory("MemTotal: 1000 kB\nMemAvailable: 900 kB\n").unwrap(),
            (1024000, 921600)
        );
        for text in [
            "MemTotal: 1 MB\nMemAvailable: 1 kB",
            "MemTotal: 1 kB\nMemAvailable: 2 kB",
            "MemTotal: 1 kB\nMemTotal: 1 kB\nMemAvailable: 1 kB",
        ] {
            assert!(scan203_memory(text).is_err());
        }
    }
    #[test]
    fn census_detects_other_campaign_replay_and_delivery() {
        for name in [
            "horizon-qualify-204-new.service",
            "horizon-upload-203-new.service",
            "horizon-native-203-test.service",
            "jetstreamer-root-import-horizon-any.service",
        ] {
            assert!(scan203_campaign_service(name));
        }
        assert!(!scan203_campaign_service(
            "horizon-prefix205-protective-v1.service"
        ));
        assert!(!scan203_campaign_service(
            "horizon-qualify-144-other-host.service"
        ));
    }
}
