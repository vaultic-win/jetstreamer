//! Explicitly admitted native control; never compiled into production helpers.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeAdmission {
    schema: String,
    route: String,
    recorded_unix_seconds: u64,
    expires_unix_seconds: u64,
    test_binary: Bound,
    normal_helper_lineage: Bound,
    gcloud: Bound,
    profile: Bound,
    sources: Vec<Bound>,
    output: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NormalLineage {
    schema: String,
    helper: Bound,
    artifact_proof: Bound,
    sources: Vec<Bound>,
    cargo_features: Vec<String>,
    lto: String,
    codegen_units: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeProfile {
    schema: String,
    unit: String,
    invocation_id: String,
    control_group: String,
    expected_properties: BTreeMap<String, String>,
}

fn bound_decode<T: serde::de::DeserializeOwned>(b: &Bound) -> Result<T> {
    Ok(serde_json::from_slice(&root_bound_file(b, 1 << 20, true)?)?)
}
fn bindings(sources: &[Bound]) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for b in sources {
        root_bound_file(b, 1 << 20, true)?;
        let name = b
            .path
            .file_name()
            .context("source filename missing")?
            .to_str()
            .context("source filename is not UTF-8")?;
        ensure!(
            map.insert(name.to_owned(), b.sha256.clone()).is_none(),
            "duplicate source"
        );
    }
    Ok(map)
}
fn compiled_sources() -> BTreeMap<String, String> {
    [
        (
            "snapshot92447542_cache.rs",
            include_bytes!("snapshot92447542_cache.rs").as_slice(),
        ),
        (
            "snapshot92447542_native_sdk.rs",
            include_bytes!("snapshot92447542_native_sdk.rs").as_slice(),
        ),
        ("Cargo.toml", include_bytes!("../Cargo.toml").as_slice()),
        (
            "README.md",
            include_bytes!("../../scripts/horizon_snapshot92447542_cache_v1/README.md").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(name, bytes)| (name.to_owned(), sha(bytes)))
    .collect()
}
fn status(pid: u32) -> Result<BTreeMap<String, String>> {
    let text = fs::read_to_string(format!("/proc/{pid}/status"))?;
    text.lines()
        .map(|line| {
            let (key, value) = line.split_once(':').context("invalid process status")?;
            Ok((key.to_owned(), value.trim().to_owned()))
        })
        .collect()
}
fn ids(s: &BTreeMap<String, String>, key: &str, uid: u32) -> Result<()> {
    let values = s
        .get(key)
        .context("process status identity missing")?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values == vec![uid; 4],
        "process real/effective/saved/fs identity changed"
    );
    Ok(())
}
fn stat(pid: u32) -> Result<(u32, u64)> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (head, tail) = text.rsplit_once(") ").context("invalid process stat")?;
    ensure!(
        head.split_whitespace().next() == Some(&pid.to_string()),
        "process PID mismatch"
    );
    let fields: Vec<_> = tail.split_whitespace().collect();
    // Tail starts at field 3 (state); pgrp is field 5, starttime field 22.
    ensure!(fields.len() > 19, "short process stat");
    Ok((fields[2].parse()?, fields[19].parse()?))
}
fn capability(s: &BTreeMap<String, String>, key: &str) -> Result<u64> {
    Ok(u64::from_str_radix(
        s.get(key).context("capability field missing")?,
        16,
    )?)
}
fn cgroup(pid: u32) -> Result<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let mut lines = text.lines();
    let group = lines
        .next()
        .and_then(|x| x.strip_prefix("0::"))
        .context("unified cgroup required")?;
    ensure!(
        lines.next().is_none() && group.starts_with('/') && !group.contains(".."),
        "invalid cgroup"
    );
    Ok(group.to_owned())
}
fn duration_seconds(value: &str) -> Result<u64> {
    let mut total = 0u64;
    for word in value.split_whitespace() {
        let (number, multiplier) = if let Some(n) = word.strip_suffix("min") {
            (n, 60)
        } else {
            (
                word.strip_suffix('s')
                    .context("runtime must be finite seconds/minutes")?,
                1,
            )
        };
        total = total
            .checked_add(
                number
                    .parse::<u64>()?
                    .checked_mul(multiplier)
                    .context("runtime overflow")?,
            )
            .context("runtime overflow")?;
    }
    ensure!(
        (1..=180).contains(&total),
        "native runtime exceeds admission ceiling"
    );
    Ok(total)
}
fn native_service(
    p: &NativeProfile,
    self_start: (u32, u64),
    output_parent: &Path,
) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-snapshot92447542-native-sdk-profile-v1"
            && safe_unit(&p.unit)
            && p.invocation_id.len() == 32
            && p.invocation_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            && p.control_group == format!("/system.slice/{}", p.unit),
        "invalid native profile identity"
    );
    let required = [
        ("Id", p.unit.as_str()),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", p.invocation_id.as_str()),
        ("ControlGroup", p.control_group.as_str()),
        ("NRestarts", "0"),
        ("MemoryMax", "536870912"),
        ("MemorySwapMax", "0"),
        ("CPUQuotaPerSecUSec", "2s"),
        ("NoNewPrivileges", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("KillMode", "control-group"),
    ];
    for (key, value) in required {
        ensure!(
            p.expected_properties.get(key).map(String::as_str) == Some(value),
            "native required property mismatch: {key}"
        );
    }
    for key in [
        "ExecStart",
        "MainPID",
        "User",
        "Group",
        "TasksMax",
        "RuntimeMaxUSec",
        "ReadWritePaths",
        "CapabilityBoundingSet",
        "AmbientCapabilities",
    ] {
        ensure!(
            p.expected_properties.contains_key(key),
            "native property missing: {key}"
        );
    }
    ensure!(
        matches!(p.expected_properties["User"].as_str(), "" | "root")
            && matches!(p.expected_properties["Group"].as_str(), "" | "root")
            && !p.expected_properties["ExecStart"].is_empty()
            && p.expected_properties["MainPID"].parse::<u32>()? == std::process::id()
            && matches!(p.expected_properties["TasksMax"].as_str(), "128" | "512"),
        "native root identity/tasks mismatch"
    );
    let writable: BTreeSet<_> = p.expected_properties["ReadWritePaths"]
        .split_whitespace()
        .collect();
    let output_path = output_parent
        .to_str()
        .context("output parent must be UTF-8")?;
    ensure!(
        writable == BTreeSet::from(["/home/ubuntu/.config/gcloud", output_path]),
        "native writable mounts must be exact config and private result directory"
    );
    duration_seconds(&p.expected_properties["RuntimeMaxUSec"])?;
    let properties = evidence::properties(
        &p.unit,
        &p.expected_properties
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(","),
    )?;
    ensure!(
        properties == p.expected_properties,
        "effective native service properties changed"
    );
    ensure!(
        env::var("INVOCATION_ID")? == p.invocation_id
            && cgroup(std::process::id())? == p.control_group
            && stat(std::process::id())? == self_start,
        "native invocation/cgroup/start identity changed"
    );
    let s = status(std::process::id())?;
    ids(&s, "Uid", 0)?;
    ids(&s, "Gid", 0)?;
    // DAC_OVERRIDE, KILL, SETGID, SETUID, SYS_PTRACE only. KILL is essential
    // after dropping the owned SDK to UID 1000; ptrace permits /proc inspection.
    const CAPS: u64 = (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 19);
    for key in ["CapEff", "CapPrm", "CapBnd"] {
        ensure!(capability(&s, key)? == CAPS, "native capability mismatch");
    }
    ensure!(
        capability(&s, "CapAmb")? & !CAPS == 0
            && s.get("NoNewPrivs").map(String::as_str) == Some("1"),
        "native privilege gate failed"
    );
    let base = Path::new("/sys/fs/cgroup").join(p.control_group.trim_start_matches('/'));
    let read = |name: &str| -> Result<String> {
        Ok(fs::read_to_string(base.join(name))?.trim().to_owned())
    };
    ensure!(
        read("memory.max")? == MEMORY.to_string()
            && read("memory.swap.max")? == "0"
            && read("pids.max")? == p.expected_properties["TasksMax"],
        "native kernel resource limits differ"
    );
    let cpu = read("cpu.max")?;
    let cpu: Vec<_> = cpu.split_whitespace().collect();
    ensure!(
        cpu.len() == 2
            && cpu[0].parse::<u64>()?
                == cpu[1]
                    .parse::<u64>()?
                    .checked_mul(2)
                    .context("CPU quota overflow")?
            && cpu[1].parse::<u64>()? > 0,
        "native kernel CPU quota differs"
    );
    Ok(
        json!({"properties":properties,"parent_status":s,"parent_start_identity":self_start,"control_group":p.control_group}),
    )
}
fn child_witness(pid: u32, group: &str) -> Result<Value> {
    let before = stat(pid)?;
    let s = status(pid)?;
    ids(&s, "Uid", 1000)?;
    ids(&s, "Gid", 1000)?;
    ensure!(
        s.get("Groups").is_some_and(String::is_empty)
            && capability(&s, "CapEff")? == 0
            && capability(&s, "CapPrm")? == 0
            && capability(&s, "CapAmb")? == 0
            && s.get("NoNewPrivs").map(String::as_str) == Some("1")
            && before.0 == pid
            && before.1 > 0
            && stat(pid)? == before
            && cgroup(pid)? == group,
        "native SDK kernel witness failed"
    );
    Ok(json!({"pid":pid,"pgid":before.0,"start_ticks":before.1,"status":s,"control_group":group}))
}
fn shutdown_witness(pid: u32) -> Result<()> {
    let mut status = 0;
    ensure!(
        unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD),
        "SDK leader not reaped"
    );
    // SIGKILL delivery and an orphan's reaping are asynchronous. Observe the
    // already-signaled group for a bounded interval; never signal it again
    // after the original leader has been reaped and its PID may be reused.
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let result = unsafe { libc::kill(-(pid as i32), 0) };
        let error = std::io::Error::last_os_error().raw_os_error();
        if result == -1 && error == Some(libc::ESRCH) {
            return Ok(());
        }
        ensure!(result == 0, "cannot observe owned SDK group: {error:?}");
        ensure!(Instant::now() < deadline, "owned SDK group remains");
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn actual_uid1000_sdk_metadata_profile() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native SDK control requires Root"
    );
    let started = Instant::now();
    let self_start = stat(std::process::id())?;
    let admission = Bound {
        path: env::var_os("JETSTREAMER_SNAPSHOT92447542_NATIVE_ADMISSION")
            .context("separate native admission path required")?
            .into(),
        sha256: env::var("JETSTREAMER_SNAPSHOT92447542_NATIVE_ADMISSION_SHA256")
            .context("separate native admission hash required")?,
    };
    let a: NativeAdmission = bound_decode(&admission)?;
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-native-sdk-admission-v1"
            && a.route == "native-sdk-metadata-only"
            && a.recorded_unix_seconds <= now()?
            && now()? <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.recorded_unix_seconds
            && a.expires_unix_seconds - a.recorded_unix_seconds <= 180,
        "native admission expired or wrong route"
    );
    root_bound_file(&a.test_binary, 256 << 20, true)?;
    // /proc/self/exe is deliberately a kernel symlink; hash_file refuses
    // symlinks. Hash its actual descriptor and bind its unchanged identity
    // to the independently verified file.
    let mut running = File::open("/proc/self/exe")?;
    let running_identity = Identity::of(&running.metadata()?);
    ensure!(
        fs::canonicalize("/proc/self/exe")? == a.test_binary.path
            && running_identity == Identity::of(&fs::symlink_metadata(&a.test_binary.path)?),
        "native executable identity differs from admission"
    );
    let mut running_hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut length = 0u64;
    loop {
        let count = running.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length += count as u64;
        ensure!(length <= 256 << 20, "native executable exceeds bound");
        running_hash.update(&buffer[..count]);
    }
    ensure!(
        format!("{:x}", running_hash.finalize()) == a.test_binary.sha256
            && length == running_identity.length
            && Identity::of(&running.metadata()?) == running_identity
            && Identity::of(&fs::symlink_metadata(&a.test_binary.path)?) == running_identity,
        "native executable differs from admission"
    );
    let lineage: NormalLineage = bound_decode(&a.normal_helper_lineage)?;
    ensure!(
        lineage.schema == "jetstreamer-snapshot92447542-normal-helper-lineage-v1"
            && lineage.cargo_features.is_empty()
            && lineage.lto == "fat"
            && lineage.codegen_units == 1,
        "normal helper build lineage mismatch"
    );
    root_bound_file(&lineage.helper, 256 << 20, true)?;
    let proof: Value = bound_decode(&lineage.artifact_proof)?;
    ensure!(
        proof["schema"] == "jetstreamer-snapshot92447542-normal-artifact-proof-v1"
            && proof["helper_sha256"] == lineage.helper.sha256
            && proof["cargo_features"] == json!([])
            && proof["lto"] == "fat"
            && proof["codegen_units"] == 1
            && proof["source_hashes"] == serde_json::to_value(compiled_sources())?,
        "normal artifact proof mismatch"
    );
    ensure!(
        bindings(&a.sources)? == compiled_sources()
            && bindings(&lineage.sources)? == compiled_sources(),
        "native/normal compiled source lineage differs"
    );
    let profile: NativeProfile = bound_decode(&a.profile)?;
    let output_parent = a.output.parent().context("native output parent missing")?;
    private_dir(output_parent)?;
    ensure!(
        a.output.is_absolute()
            && output_parent.canonicalize()? == output_parent
            && absent(&a.output)?
            && a.output
                .file_name()
                .is_some_and(|n| n == "native-sdk-result.json"),
        "native output must be a new private result"
    );
    let before = native_service(&profile, self_start, output_parent)?;
    let mut witnesses = Vec::new();
    let bytes = metadata_core(&a.gcloud, |pid, point| {
        let witness = match point {
            SdkWitnessPoint::Spawned => child_witness(pid, &profile.control_group)?,
            SdkWitnessPoint::BeforeReap => {
                // An exited, WNOWAIT-held leader can already have left its
                // cgroup. Its unreaped PID and original starttime remain
                // available and must match before signaling the owned PGID.
                let identity = stat(pid)?;
                let state = status(pid)?;
                ids(&state, "Uid", 1000)?;
                ids(&state, "Gid", 1000)?;
                ensure!(
                    identity.0 == pid && stat(pid)? == identity,
                    "SDK final identity changed during witness"
                );
                json!({"pid":pid,"pgid":identity.0,"start_ticks":identity.1,"status":state})
            }
        };
        if let Some(first) = witnesses.first() {
            let first: &Value = first;
            ensure!(
                first["pid"] == witness["pid"]
                    && first["pgid"] == witness["pgid"]
                    && first["start_ticks"] == witness["start_ticks"],
                "SDK child start identity changed"
            );
        }
        witnesses.push(witness);
        Ok(())
    })?;
    ensure!(witnesses.len() == 2, "both actual SDK witnesses required");
    shutdown_witness(
        witnesses[0]["pid"]
            .as_u64()
            .context("SDK PID missing")?
            .try_into()?,
    )?;
    // Deliberately fail a real SDK spawn witness. The engine must stop its
    // owned group and reap the leader before returning the witness error.
    let mut rejected_pid = None;
    let rejected = metadata_core(&a.gcloud, |pid, _| {
        rejected_pid = Some(pid);
        child_witness(pid, &profile.control_group)?;
        bail!("intentional native witness failure control")
    });
    ensure!(
        rejected
            .is_err_and(|error| error.to_string() == "intentional native witness failure control"),
        "native witness-failure control did not propagate the intended error"
    );
    let rejected_pid = rejected_pid.context("native failure control never spawned SDK")?;
    shutdown_witness(rejected_pid)?;
    let after = native_service(&profile, self_start, output_parent)?;
    ensure!(
        started.elapsed() <= Duration::from_secs(180) && now()? <= a.expires_unix_seconds,
        "native admission elapsed"
    );
    persist(
        &a.output,
        &json!({
            "schema":"jetstreamer-snapshot92447542-native-sdk-result-v1",
            "admission":{"path":admission.path,"sha256":admission.sha256},
            "native_binary_sha256":a.test_binary.sha256,"normal_helper_sha256":lineage.helper.sha256,
            "normal_helper_lineage_sha256":a.normal_helper_lineage.sha256,"gcloud_sha256":a.gcloud.sha256,
            "profile_sha256":a.profile.sha256,"source_hashes":compiled_sources(),
            "before":before,"after":after,"sdk_witnesses":witnesses,
            "authenticated_generation_metadata":serde_json::from_slice::<Value>(&bytes)?,
            "authenticated_generation_metadata_sha256":sha(&bytes),
            "shutdown_evidence":{"leader_waitpid_errno":libc::ECHILD,"group_probe_errno":libc::ESRCH,"rejected_witness_pid":rejected_pid,"rejected_witness_leader_waitpid_errno":libc::ECHILD,"rejected_witness_group_probe_errno":libc::ESRCH},
            "completed_unix_seconds":now()?,"elapsed_milliseconds":started.elapsed().as_millis(),
            "scope":"native-sdk-metadata-only; no snapshot body, eviction, restore or lifecycle qualification"
        }),
    )?;
    Ok(())
}
