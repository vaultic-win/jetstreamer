//! Source-bound read-only current accounting facts for exact failed4 retirement.
//! No new allocation, retirement, replay, namespace reuse or publication authority.
use super::*;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
pub(super) const UNIT: &str = "horizon-failed4-current-accounting-reader-20261104-v1.service";
const ROOT: &str = "/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1";
const COMMAND: &str = "read-failed4-current-accounting";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    resource_accounting: Value,
    retention_plan: BoundFile,
    prior_memory: BoundFile,
    terminal_legacy_memory_closure: charge136::admission::terminal_legacy_memory::Bound,
    captured141_memory_retirement: captured141_memory_retirement::Request,
    external_booking: BoundFile,
    output_directory: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn shape(s: &Spec) -> Result<()> {
    let current = &s.captured141_memory_retirement.current;
    ensure!(
        s.schema == "failed4-current-complete-accounting-reader-spec-v1"
            && s.resource_accounting["schema"]
                == "jetstreamer-current-protected-data-accounting-spec-v1"
            && s.resource_accounting["observer"] == json!(current.observer)
            && s.resource_accounting["fleet"] == json!(current.fleet)
            && s.resource_accounting["fleet_plan"] == json!(current.fleet_plan),
        "reader current tuple/schema differs"
    );
    output_namespace_shape(&current.observer.sha256, &s.output_directory)?;
    Ok(())
}
// Syntax alone never selects the native route. run() authenticates the exact
// current registration/task and derives its output before creating a directory.
fn output_namespace_shape(observer_sha: &str, output: &Path) -> Result<()> {
    ensure!(is_lower_hex(observer_sha, 64), "reader observer digest malformed");
    let legacy = Path::new(ROOT).join(observer_sha);
    if output == legacy {
        return Ok(());
    }
    let prefix = format!("{observer_sha}-cold185-");
    let leaf = output.file_name().and_then(|n| n.to_str()).context("reader output leaf")?;
    let iid = leaf.strip_prefix(&prefix).context("reader output outside exact observer family")?;
    ensure!(output.parent() == Some(Path::new(ROOT)) && is_lower_hex(iid, 32),
        "reader output outside exact current observer and invocation namespace");
    Ok(())
}
fn booking_shape(v: &Value, spec: &Spec, clock: u64) -> Result<()> {
    let at = v["recorded_unix_seconds"]
        .as_u64()
        .context("reader booking clock")?;
    let end = v["expires_unix_seconds"]
        .as_u64()
        .context("reader booking expiry")?;
    ensure!(
        v["schema"] == "failed4-current-accounting-reader-external-booking-v1"
            && v["current"] == json!(spec.captured141_memory_retirement.current)
            && v["accounting_sources_serde_json_sha256"]
                == hex_lower(&Sha256::digest(serde_json::to_vec(
                    &spec.resource_accounting
                )?))
            && v["retention_plan"] == json!(spec.retention_plan)
            && v["prior_memory"] == json!(spec.prior_memory)
            && v["terminal_legacy_memory_closure"] == json!(spec.terminal_legacy_memory_closure)
            && v["output_directory"] == json!(spec.output_directory)
            && v["unit"] == UNIT
            && v["memory_max_bytes"] == 2147483648u64
            && v["total_external_qualification_bytes"] == 6442450944u64
            && v["replay_launch_authorized"] == false
            && v["memory_credit_bytes"] == 0
            && v["DATA_credit_bytes"] == 0
            && at <= clock
            && clock < end
            && end.checked_sub(at).is_some_and(|n| n <= 600),
        "reader finite exact external booking differs/expired"
    );
    let _: BoundFile = serde_json::from_value(v["accepted_tuple"].clone())?;
    let _: BoundFile = serde_json::from_value(v["resource_arithmetic"].clone())?;
    Ok(())
}
fn booking(v: &Value, spec: &Spec, clock: u64) -> Result<()> {
    booking_shape(v, spec, clock)?;
    let arithmetic =
        input136::protected_json(&serde_json::from_value(v["resource_arithmetic"].clone())?)?;
    let tuple = input136::protected_json(&serde_json::from_value(v["accepted_tuple"].clone())?)?;
    let selector =
        input136::protected_json(&serde_json::from_value(tuple["accepted_selector"].clone())?)?;
    let current = &spec.captured141_memory_retirement.current;
    ensure!(
        arithmetic["observer"] == json!(current.observer)
            && arithmetic["one_external_serial_bytes"] == 6442450944u64
            && arithmetic["headroom_bytes"].as_u64().is_some_and(|n| n > 0)
            && tuple["observer"] == json!(current.observer)
            && tuple["fleet"] == json!(current.fleet)
            && tuple["frame"] == json!(current.frame)
            && selector["fleet_plan"] == json!(current.fleet_plan)
            && selector["fleet"] == json!(current.fleet)
            && selector["frame"] == json!(current.frame),
        "reader actual root booking/current accepted tuple differs"
    );
    Ok(())
}
fn actor(iid: &str) -> Result<Value> {
    let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",UNIT,"--no-pager","--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,ActiveState,SubState,Type,User,Group,MemoryAccounting,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,RuntimeMaxUSec,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,PrivateMounts,PrivateTmp,ProtectHome,ProtectSystem,BindPaths,BindReadOnlyPaths,TemporaryFileSystem,RootDirectory,RootImage,Job"]).output()?;
    ensure!(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 65536,
        "reader native query unavailable"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("reader native framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "reader duplicate native field"
        );
    }
    let n = Value::Object(m);
    let pid = std::process::id().to_string();
    validate_actor(&n, iid, pid.as_str())?;
    Ok(n)
}
fn validate_actor(n: &Value, iid: &str, pid: &str) -> Result<()> {
    ensure!(
        n["Id"] == UNIT && n["InvocationID"] == iid && n["MainPID"].as_str() == Some(pid),
        "reader actor identity changed"
    );
    for (k, v) in [
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("Type", "exec"),
        ("User", "root"),
        ("Group", "root"),
        ("MemoryAccounting", "yes"),
        ("MemoryHigh", "2147483648"),
        ("MemoryMax", "2147483648"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "1s"),
        ("TasksMax", "512"),
        ("RuntimeMaxUSec", "10min"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
        ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
        ("PrivateMounts", "no"),
        ("PrivateTmp", "no"),
        ("ProtectHome", "no"),
        ("ProtectSystem", "no"),
        ("BindPaths", ""),
        ("BindReadOnlyPaths", ""),
        ("TemporaryFileSystem", ""),
        ("RootDirectory", ""),
        ("RootImage", ""),
        ("Job", ""),
    ] {
        ensure!(n[k] == v, "reader native envelope differs: {k}");
    }
    Ok(())
}

fn save(directory: &Path, name: &str, v: &Value) -> Result<BoundFile> {
    ensure!(
        [
            "raw-builder-before.json",
            "raw-builder-after.json",
            "raw-accounting-before.json",
            "raw-accounting.json",
            "captured141-selection-before.json",
            "captured141-selection.json",
            "proof.json"
        ]
        .contains(&name),
        "reader member outside contract"
    );
    let path = directory.join(name);
    let raw = serde_json::to_vec_pretty(v)?;
    ensure!(raw.len() <= 16 << 20, "reader member exceeds bound");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    std::io::Write::write_all(&mut f, &raw)?;
    f.sync_all()?;
    fs::File::open(directory)?.sync_all()?;
    Ok(BoundFile {
        path,
        sha256: hex_lower(&Sha256::digest(&raw)),
    })
}
fn memory(o: &Value, b: &Value, prior: &Value, s: &Spec, clock: u64) -> Result<(u64, Value)> {
    let raw = charge136_retry0005::admission::existing_memory_with_closure(
        o,
        b,
        prior,
        Some(&s.terminal_legacy_memory_closure),
    )?;
    let selected = captured141_memory_retirement::select(
        raw,
        &s.resource_accounting,
        b,
        Some(&s.captured141_memory_retirement),
        clock,
    )?;
    ensure!(
        selected.evidence["raw_total_memory_promises_bytes"] == raw
            && raw.checked_sub(selected.total) == Some(207232172032u64)
            && selected.evidence["raw_history_preserved"] == true
            && selected.evidence["DATA_credit_bytes"] == 0,
        "reader captured141 revalidation differs"
    );
    Ok((raw, selected.evidence))
}
pub(super) async fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7
            && args[1] == COMMAND
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "reader root exact command differs"
    );
    let sb = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let s: Spec = serde_json::from_value(input136::sealed(&sb)?)?;
    shape(&s)?;
    let image = fs::read_link("/proc/self/exe")?;
    charge136::executable(
        &charge136::contract::Bound {
            path: image.clone(),
            sha256: args[6].clone(),
        },
        256 << 20,
    )?;
    let iid = env::var("INVOCATION_ID")?;
    ensure!(
        is_lower_hex(&iid, 32)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "reader outside exact native role"
    );
    let native = actor(&iid)?;
    let booked = input136::protected_json(&s.external_booking)?;
    booking(&booked, &s, now()?)?;
    let expected_output = epoch186::accounting::cold185::reader_output_namespace(
        &s.resource_accounting, Path::new(ROOT),
        &s.captured141_memory_retirement.current.observer.sha256,
    )?;
    ensure!(s.output_directory == expected_output,
        "reader output differs from authenticated current task and observer");
    let parent = Path::new(ROOT);
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "reader root is not root private"
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&s.output_directory)?;
    fs::File::open(parent)?.sync_all()?;
    let plan: charge136_retry0005::contract::Plan =
        serde_json::from_value(input136::sealed(&s.retention_plan)?)?;
    let prior = input136::sealed(&s.prior_memory)?;
    let ob: BoundFile = serde_json::from_value(s.resource_accounting["observer"].clone())?;
    let observer = input136::protected_json(&ob)?;
    let retained_before = charge136_retry0005::retained_attempt::actual(&plan)?;
    let raw_before =
        epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    let before =
        charge136_retry0005::retained_attempt::project(&plan, &raw_before, &retained_before)?;
    let before_raw = save(&s.output_directory, "raw-builder-before.json", &raw_before)?;
    let before_binding = save(&s.output_directory, "raw-accounting-before.json", &before)?;
    let (raw_memory_before, selection_before) = memory(&observer, &before, &prior, &s, now()?)?;
    let before_selection = save(
        &s.output_directory,
        "captured141-selection-before.json",
        &selection_before,
    )?;
    let raw_after =
        epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    let retained_after = charge136_retry0005::retained_attempt::actual(&plan)?;
    ensure!(
        retained_before == retained_after,
        "reader retained custody changed"
    );
    let after = charge136_retry0005::retained_attempt::project(&plan, &raw_after, &retained_after)?;
    charge136::admission::stable(&s.resource_accounting, &before, &after)?;
    let (raw_memory_after, selection_after) = memory(&observer, &after, &prior, &s, now()?)?;
    ensure!(
        raw_memory_before == raw_memory_after,
        "reader raw memory changed"
    );
    ensure!(
        actor(&iid)? == native
            && input136::protected_json(&s.external_booking)? == booked
            && input136::sealed(&s.retention_plan)? == serde_json::to_value(&plan)?
            && input136::sealed(&s.prior_memory)? == prior
            && input136::protected_json(&ob)? == observer,
        "reader source/owner changed"
    );
    booking(&booked, &s, now()?)?;
    let after_raw = save(&s.output_directory, "raw-builder-after.json", &raw_after)?;
    let after_binding = save(&s.output_directory, "raw-accounting.json", &after)?;
    let after_selection = save(
        &s.output_directory,
        "captured141-selection.json",
        &selection_after,
    )?;
    let proof = json!({"schema":"failed4-current-complete-accounting-reader-proof-v1","recorded_unix_seconds":now()?,"unit":UNIT,"invocation_id":iid,"native":native,
        "spec":sb,"image":{"path":image,"sha256":args[6]},"external_booking":s.external_booking,"retention_plan":s.retention_plan,
        "original_raw_builder_before":before_raw,"original_raw_builder_after":after_raw,"accounting_before":before_binding,"accounting":after_binding,
        "captured141_selection_before":before_selection,"captured141_selection":after_selection,"raw_total_memory_promises_bytes":raw_memory_after,
        "raw_history_preserved":true,"all_DATA_promises_preserved":true,"terminal_legacy_minimum_already_applied_once":true,
        "captured141_existing_selection_only":true,"failed4_memory_selection_enabled":false,"memory_budget_credit_applied_bytes":0,"DATA_credit_bytes":0,"physical_credit_bytes":0,
        "admission_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"archive_mutations":false,"sidecar_mutations":false,"r2_mutations":false,"new_resource_observations":0});
    let result = save(&s.output_directory, "proof.json", &proof)?;
    fs::File::open(&s.output_directory)?.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> Spec {
        let sha = "a".repeat(64);
        let b = |p: &str| json!({"path":p,"sha256":sha});
        serde_json::from_value(json!({"schema":"failed4-current-complete-accounting-reader-spec-v1",
            "resource_accounting":{"schema":"jetstreamer-current-protected-data-accounting-spec-v1","observer":b("/observer"),"fleet":b("/fleet"),"fleet_plan":b("/fleet-plan")},
            "retention_plan":b("/retention-plan"),"prior_memory":b("/prior"),"terminal_legacy_memory_closure":b("/closure"),
            "captured141_memory_retirement":{"opt_in":{"registration":b("/registration"),"seal":b("/seal")},"current":{"observer":b("/observer"),"fleet":b("/fleet"),"fleet_plan":b("/fleet-plan"),"frame":b("/frame")}},
            "external_booking":b("/booking"),"output_directory":Path::new(ROOT).join(&sha)})).unwrap()
    }
    #[test]
    fn every_crossed_current_tuple_member_or_source_schema_rejects_before_native_reads() {
        let s = spec();
        shape(&s).unwrap();
        for k in ["observer", "fleet", "fleet_plan", "schema"] {
            let mut s = spec();
            s.resource_accounting[k] = Value::Null;
            assert!(shape(&s).is_err(), "{k}");
        }
    }
    #[test]
    fn output_is_one_exact_current_observer_namespace_with_no_parent_or_foreign_generation() {
        for p in [
            ROOT,
            "/tmp/proof",
            "/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/../other",
        ] {
            let mut s = spec();
            s.output_directory = p.into();
            assert!(shape(&s).is_err());
        }
    }
    #[test]
    fn finite_booking_rejects_expiry_crossed_spec_credit_or_wrong_hard_envelope() {
        let sb = spec();
        let v = json!({"schema":"failed4-current-accounting-reader-external-booking-v1","current":sb.captured141_memory_retirement.current,"accounting_sources_serde_json_sha256":hex_lower(&Sha256::digest(serde_json::to_vec(&sb.resource_accounting).unwrap())),"retention_plan":sb.retention_plan,"prior_memory":sb.prior_memory,"terminal_legacy_memory_closure":sb.terminal_legacy_memory_closure,"output_directory":sb.output_directory,"accepted_tuple":{"path":"/accepted-tuple","sha256":"b".repeat(64)},"resource_arithmetic":{"path":"/arithmetic","sha256":"c".repeat(64)},"unit":UNIT,"memory_max_bytes":2147483648u64,"total_external_qualification_bytes":6442450944u64,"recorded_unix_seconds":100,"expires_unix_seconds":700,"replay_launch_authorized":false,"memory_credit_bytes":0,"DATA_credit_bytes":0});
        booking_shape(&v, &sb, 100).unwrap();
        booking_shape(&v, &sb, 699).unwrap();
        assert!(booking_shape(&v, &sb, 99).is_err());
        assert!(booking_shape(&v, &sb, 700).is_err());
        for (k, value) in [
            ("current", Value::Null),
            ("memory_max_bytes", json!(1073741824u64)),
            ("memory_max_bytes", json!(536870912u64)),
            ("memory_max_bytes", json!(4294967296u64)),
            ("total_external_qualification_bytes", json!(7516192768u64)),
            ("memory_credit_bytes", json!(1)),
            ("replay_launch_authorized", json!(true)),
            ("expires_unix_seconds", json!(701)),
        ] {
            let mut bad = v.clone();
            bad[k] = value;
            assert!(booking_shape(&bad, &sb, 100).is_err(), "{k}");
        }
    }
    fn exact_native_profile() -> Value {
        json!({"Id":UNIT,"InvocationID":"a".repeat(32),"MainPID":"2","ControlPID":"0","NRestarts":"0","Restart":"no","ActiveState":"active","SubState":"running","Type":"exec","User":"root","Group":"root","MemoryAccounting":"yes","MemoryHigh":"2147483648","MemoryMax":"2147483648","MemorySwapMax":"0","CPUQuotaPerSecUSec":"1s","TasksMax":"512","RuntimeMaxUSec":"10min","NoNewPrivileges":"yes","CapabilityBoundingSet":"cap_dac_override cap_sys_ptrace","AmbientCapabilities":"cap_dac_override cap_sys_ptrace","PrivateMounts":"no","PrivateTmp":"no","ProtectHome":"no","ProtectSystem":"no","BindPaths":"","BindReadOnlyPaths":"","TemporaryFileSystem":"","RootDirectory":"","RootImage":"","Job":""})
    }
    #[test]
    fn exact_600_second_actor_rejects_old_unbounded_or_foreign_runtime() {
        let good = exact_native_profile();
        let iid = "a".repeat(32);
        validate_actor(&good, &iid, "2").unwrap();
        for value in [
            json!("5min"),
            json!("15min"),
            json!("infinity"),
            json!(600000000u64),
        ] {
            let mut bad = good.clone();
            bad["RuntimeMaxUSec"] = value;
            assert!(validate_actor(&bad, &iid, "2").is_err());
        }
    }
    #[test]
    fn exact_2gib_reader_envelope_accepts_and_old_undercharge_hard_cap_swap_or_type_changes_reject()
    {
        let good = exact_native_profile();
        let iid = "a".repeat(32);
        validate_actor(&good, &iid, "2").unwrap();
        for (key, value) in [
            ("MemoryHigh", json!("402653184")),
            ("MemoryHigh", json!("536870912")),
            ("MemoryHigh", json!("2147483649")),
            ("MemoryMax", json!("536870912")),
            ("MemoryMax", json!("4294967296")),
            ("MemoryMax", json!("1073741824")),
            ("MemorySwapMax", json!("infinity")),
            ("MemoryAccounting", json!("no")),
            ("MemoryHigh", json!(536870912u64)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_actor(&bad, &iid, "2").is_err(), "{key}");
        }
    }
    #[test]
    fn profile_change_cannot_borrow_foreign_identity_restart_mounts_or_capabilities() {
        let good = exact_native_profile();
        let iid = "a".repeat(32);
        for (key, value) in [
            ("Id", json!("foreign.service")),
            ("InvocationID", json!("b".repeat(32))),
            ("MainPID", json!("3")),
            ("NRestarts", json!("1")),
            ("Restart", json!("always")),
            ("PrivateMounts", json!("yes")),
            ("BindPaths", json!("/foreign")),
            ("CapabilityBoundingSet", json!("cap_sys_admin")),
            ("AmbientCapabilities", json!("cap_sys_admin")),
            ("Type", json!("oneshot")),
            ("Job", json!("1")),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_actor(&bad, &iid, "2").is_err(), "{key}");
        }
        assert!(validate_actor(&good, &"b".repeat(32), "2").is_err());
        assert!(validate_actor(&good, &iid, "3").is_err());
    }
}

#[cfg(test)]
mod exact_cold185_output_namespace_tests {
    use super::*;
    #[test]
    fn legacy_namespace_and_exact_new_invocation_syntax_are_accepted() {
        let observer = "a".repeat(64);
        output_namespace_shape(&observer, &Path::new(ROOT).join(&observer)).unwrap();
        output_namespace_shape(&observer,
            &Path::new(ROOT).join(format!("{observer}-cold185-{}", "b".repeat(32)))).unwrap();
    }
    #[test]
    fn unrelated_observer_alias_nested_and_malformed_invocation_are_rejected() {
        let observer = "a".repeat(64);
        for leaf in [format!("{}-cold185-{}", "c".repeat(64), "b".repeat(32)),
            format!("{observer}-cold185-{}", "b".repeat(31)),
            format!("{observer}-cold185-{}", "B".repeat(32)),
            format!("{observer}-cold185-{}-retry", "b".repeat(32)),
            format!("{observer}-unbound-{}", "b".repeat(32))] {
            assert!(output_namespace_shape(&observer, &Path::new(ROOT).join(leaf)).is_err());
        }
        let leaf = format!("{observer}-cold185-{}", "b".repeat(32));
        assert!(output_namespace_shape(&observer, &Path::new(ROOT).join("nested").join(leaf)).is_err());
        assert!(output_namespace_shape(&observer, &Path::new("/tmp").join(&observer)).is_err());
    }
}
