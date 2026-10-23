//! Pin an authenticated, actual timer-generated one-worker guard sample.
use super::*;
use std::os::unix::fs::PermissionsExt;
const GUARD_UNIT: &str = "horizon-original141-root-guard-20261023-v1.service";
const GUARD_ROOT: &str = "/var/lib/jetstreamer/horizon-original141-root-guard-20261023-v1";
const GUARD_BIN: &str = "/usr/local/lib/jetstreamer/horizon-standalone-guard-target-handoff-20261019-v2/jetstreamer-horizon-standalone-guard";
fn properties(name: &str, keys: &str) -> Result<BTreeMap<String, String>> {
    let out = ProcessCommand::new("systemctl")
        .args(["show", name, "--no-pager", &format!("--property={keys}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "guard pin properties unavailable"
    );
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("guard pin property shape")?;
        ensure!(
            result.insert(k.into(), v.into()).is_none(),
            "duplicate guard property"
        );
    }
    Ok(result)
}
fn checked(
    g: &Value,
    gp: &BoundFile,
    service: &BTreeMap<String, String>,
    timer: &BTreeMap<String, String>,
    time: u64,
) -> Result<()> {
    let id = g["guard_invocation_id"]
        .as_str()
        .context("guard invocation absent")?;
    ensure!(invocation(id), "invalid guard invocation");
    let timer_name = GUARD_UNIT.replace(".service", ".timer");
    for (k, v) in [
        ("Id", GUARD_UNIT),
        ("InvocationID", id),
        ("User", "root"),
        ("Type", "oneshot"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("MainPID", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("PrivateNetwork", "yes"),
        ("PrivateTmp", "yes"),
        ("NoNewPrivileges", "yes"),
        ("EnvironmentFiles", ""),
        ("MemoryHigh", "268435456"),
        ("MemoryMax", "536870912"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("TimeoutStartUSec", "3min"),
        ("ReadWritePaths", GUARD_ROOT),
        ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
        ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
        ("TriggeredBy", timer_name.as_str()),
    ] {
        ensure!(
            service.get(k).is_some_and(|s| s == v),
            "guard firstfire service differs:{k}"
        );
    }
    for (k, v) in [
        ("Id", timer_name.as_str()),
        ("ActiveState", "active"),
        ("SubState", "waiting"),
        ("Unit", GUARD_UNIT),
    ] {
        ensure!(
            timer.get(k).is_some_and(|s| s == v),
            "guard firstfire timer differs:{k}"
        );
    }
    let trigger = timer
        .get("LastTriggerUSecMonotonic")
        .context("timer has not fired")?
        .parse::<u64>()?;
    let started = service
        .get("ExecMainStartTimestampMonotonic")
        .context("guard start absent")?
        .parse::<u64>()?;
    ensure!(
        trigger > 0 && started.checked_sub(trigger).is_some_and(|d| d <= 5_000_000),
        "guard invocation not bound to actual timer fire"
    );
    let expected = format!(
        "{{ path={GUARD_BIN} ; argv[]={GUARD_BIN} {} --plan-sha256 {} --self-sha256 {GUARD_SHA}",
        gp.path.display(),
        gp.sha256
    );
    ensure!(
        command(&json!(service.get("ExecStart"))).is_some_and(|s| s == expected),
        "guard firstfire command differs"
    );
    ensure!(
        g["recorded_unix_seconds"]
            .as_u64()
            .is_some_and(|t| t <= time && time - t <= 180)
            && g["guard_sha256"] == GUARD_SHA
            && g["plan"].as_str() == gp.path.to_str()
            && g["plan_sha256"] == gp.sha256,
        "guard firstfire sample stale/foreign"
    );
    Ok(())
}
fn copy_new(source: &BoundFile, destination: &BoundFile) -> Result<()> {
    sealed_file(source)?;
    ensure!(
        source.sha256 == destination.sha256,
        "guard pin digest mismatch"
    );
    let parent = validate_output_destination(&destination.path)?;
    let bytes = read_stable_bounded(&source.path, 16 * 1024 * 1024, "guard pin source")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == source.sha256,
        "guard source changed before pin"
    );
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    tmp.write_all(&bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(&destination.path)
        .map_err(|e| anyhow!("guard pin occupied:{e}"))?;
    File::open(parent)?.sync_all()?;
    bound_json(destination)?;
    Ok(())
}
pub(super) fn pin(
    source: &BoundFile,
    destination: &BoundFile,
    g: &Value,
    gp: &BoundFile,
) -> Result<Value> {
    let id = g["guard_invocation_id"]
        .as_str()
        .context("guard identity absent")?;
    ensure!(
        source.path == Path::new(GUARD_ROOT).join(format!("sample-{id}.json"))
            && destination.path == Path::new(ROOT).join("receipts/first-guard.json"),
        "guard pin paths differ"
    );
    sealed_file(gp)?;
    let plan = bound_json(gp)?;
    ensure!(
        plan["receipt_directory"] == GUARD_ROOT,
        "guard receipts outside bound root"
    );
    require_absent(&Path::new(GUARD_ROOT).join("stop-intent.json"))?;
    require_absent(&Path::new(GUARD_ROOT).join("stop-completion.json"))?;
    let service = properties(
        GUARD_UNIT,
        "Id,InvocationID,User,Type,Restart,KillMode,NRestarts,Result,ExecMainStatus,MainPID,ActiveState,SubState,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,NoNewPrivileges,EnvironmentFiles,ReadWritePaths,CapabilityBoundingSet,AmbientCapabilities,TriggeredBy,ExecMainStartTimestampMonotonic,ExecStart,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,TimeoutStartUSec",
    )?;
    let timer_name = GUARD_UNIT.replace(".service", ".timer");
    let timer = properties(
        &timer_name,
        "Id,ActiveState,SubState,Unit,LastTriggerUSecMonotonic",
    )?;
    checked(g, gp, &service, &timer, now()?)?;
    copy_new(source, destination)?;
    ensure!(
        properties(GUARD_UNIT, "InvocationID")?.get("InvocationID") == service.get("InvocationID"),
        "guard owner raced pin"
    );
    require_absent(&Path::new(GUARD_ROOT).join("stop-intent.json"))?;
    require_absent(&Path::new(GUARD_ROOT).join("stop-completion.json"))?;
    Ok(
        json!({"source":private157::binding(source),"destination":private157::binding(destination),"service":service,"timer":timer,"exact_bytes_preserved":true,"no_clobber":true,"recorded_unix_seconds":now()?}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firstfire_needs_exact_timer_invocation_command_sandbox_and_clock() {
        let gp = BoundFile {
            path: "/sealed/guard.json".into(),
            sha256: "b".repeat(64),
        };
        let g = json!({"guard_invocation_id":"a".repeat(32),"guard_sha256":GUARD_SHA,"plan":gp.path,"plan_sha256":gp.sha256,"recorded_unix_seconds":1000});
        let timer_name = GUARD_UNIT.replace(".service", ".timer");
        let pairs = [
            ("Id", GUARD_UNIT),
            ("InvocationID", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("User", "root"),
            ("Type", "oneshot"),
            ("Restart", "no"),
            ("KillMode", "control-group"),
            ("NRestarts", "0"),
            ("Result", "success"),
            ("ExecMainStatus", "0"),
            ("MainPID", "0"),
            ("ActiveState", "active"),
            ("SubState", "exited"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("PrivateTmp", "yes"),
            ("NoNewPrivileges", "yes"),
            ("EnvironmentFiles", ""),
            ("MemoryHigh", "268435456"),
            ("MemoryMax", "536870912"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "1s"),
            ("TimeoutStartUSec", "3min"),
            ("ReadWritePaths", GUARD_ROOT),
            ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
            ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
            ("TriggeredBy", timer_name.as_str()),
            ("ExecMainStartTimestampMonotonic", "1000010"),
        ];
        let mut service: BTreeMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        service.insert("ExecStart".into(),format!("{{ path={GUARD_BIN} ; argv[]={GUARD_BIN} {} --plan-sha256 {} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=0 }}",gp.path.display(),gp.sha256));
        let timer: BTreeMap<String, String> = [
            ("Id", timer_name.as_str()),
            ("ActiveState", "active"),
            ("SubState", "waiting"),
            ("Unit", GUARD_UNIT),
            ("LastTriggerUSecMonotonic", "1000000"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
        checked(&g, &gp, &service, &timer, 1180).unwrap();
        for (key, value) in [
            ("InvocationID", "cccccccccccccccccccccccccccccccc"),
            ("User", "sol"),
            ("ExecMainStartTimestampMonotonic", "999999"),
            ("ExecMainStartTimestampMonotonic", "6000001"),
            ("MainPID", "12"),
            ("NRestarts", "1"),
            ("ReadWritePaths", "/"),
            ("EnvironmentFiles", "/unbound.env"),
            ("TriggeredBy", ""),
        ] {
            let mut bad = service.clone();
            bad.insert(key.into(), value.into());
            assert!(checked(&g, &gp, &bad, &timer, 1000).is_err(), "{key}");
        }
        let mut bad = timer.clone();
        bad.insert("LastTriggerUSecMonotonic".into(), "0".into());
        assert!(checked(&g, &gp, &service, &bad, 1000).is_err());
        assert!(checked(&g, &gp, &service, &timer, 1181).is_err());
        assert!(checked(&g, &gp, &service, &timer, 999).is_err());
        let mut bad = service.clone();
        bad.insert(
            "ExecStart".into(),
            service["ExecStart"]
                .replace(" ; ignore_errors=", " --capability-only ; ignore_errors="),
        );
        assert!(checked(&g, &gp, &bad, &timer, 1000).is_err());
    }
    #[test]
    #[ignore = "requires sealed root test binary and writable private test root"]
    fn guard_pin_preserves_bytes_and_never_overwrites_existing_evidence() {
        ensure_root_test();
        let d = tempfile::tempdir().unwrap();
        let source = d.path().join("sample.json");
        let destination = d.path().join("first.json");
        let bytes = b"{ \"original\": true }\n";
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o400)).unwrap();
        let b = BoundFile {
            path: source,
            sha256: hex_lower(&Sha256::digest(bytes)),
        };
        let out = BoundFile {
            path: destination,
            sha256: b.sha256.clone(),
        };
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(copy_new(&b, &out).is_err());
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        copy_new(&b, &out).unwrap();
        assert_eq!(fs::read(&out.path).unwrap(), bytes);
        assert!(copy_new(&b, &out).is_err());
        assert_eq!(fs::read(&out.path).unwrap(), bytes);
    }
    fn ensure_root_test() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
    }
}
