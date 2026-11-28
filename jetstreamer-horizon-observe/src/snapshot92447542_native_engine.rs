//! Separately admitted fixed-generation full-engine native control.
//! This is not operational lifecycle qualification; all results remain isolated.
use super::lifecycle_engine::{
    self as core, Bindings, Booking, Environment, ObjectSpec, Phase, RestoreRequest,
};
use super::*;
use std::cell::{Cell, RefCell};
use std::io::Write;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineProfile {
    schema: String,
    unit: String,
    invocation_id: String,
    control_group: String,
    expected_properties: BTreeMap<String, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineAdmission {
    schema: String,
    route: String,
    issued_unix_seconds: u64,
    expires_unix_seconds: u64,
    test_binary: Bound,
    engine_lineage: Bound,
    profile: Bound,
    gcloud: Bound,
    fixture_root: PathBuf,
    fixture_identity: DirectoryIdentity,
    maximum_fixture_bytes: u64,
    output: PathBuf,
    protected_floor_bytes: u64,
    fleet: Bound,
    protected_owners: Vec<Owner>,
    maximum_run_seconds: u64,
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
        (1..=7200).contains(&total),
        "native runtime exceeds admission ceiling"
    );
    Ok(total)
}
fn native_service(
    p: &EngineProfile,
    self_start: (u32, u64),
    output_parent: &Path,
    fixture_parent: &Path,
) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-snapshot92447542-native-engine-profile-v1"
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
        ("AllowedCPUs", "56-63"),
        ("CPUAffinity", "56-63"),
        ("Type", "exec"),
        ("Restart", "no"),
        ("ControlPID", "0"),
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
        writable
            == BTreeSet::from([
                "/home/ubuntu/.config/gcloud",
                output_path,
                fixture_parent.to_str().context("fixture UTF8")?
            ]),
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
    const CAPS: u64 = (1 << 0) | (1 << 1) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 19);
    for key in ["CapEff", "CapPrm", "CapBnd"] {
        ensure!(capability(&s, key)? == CAPS, "native capability mismatch");
    }
    ensure!(
        capability(&s, "CapAmb")? & !CAPS == 0
            && s.get("NoNewPrivs").map(String::as_str) == Some("1")
            && s.get("Cpus_allowed_list").map(String::as_str) == Some("56-63"),
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

fn unix_utc(s: &str) -> Result<u64> {
    ensure!(
        s.is_ascii()
            && s.len() == 20
            && &s[4..5] == "-"
            && &s[7..8] == "-"
            && &s[10..11] == "T"
            && &s[13..14] == ":"
            && &s[16..17] == ":"
            && &s[19..20] == "Z",
        "noncanonical UTC timestamp"
    );
    let year: u32 = s[..4].parse()?;
    let month: usize = s[5..7].parse()?;
    let day: u64 = s[8..10].parse()?;
    let hour: u64 = s[11..13].parse()?;
    let minute: u64 = s[14..16].parse()?;
    let second: u64 = s[17..19].parse()?;
    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1970..=2200).contains(&year)
            && (1..=12).contains(&month)
            && day > 0
            && day <= months[month - 1]
            && hour < 24
            && minute < 60
            && second < 60,
        "invalid UTC date"
    );
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..month - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}
fn validate_fleet(a: &EngineAdmission) -> Result<()> {
    let fleet = evidence::bound_json(&a.fleet)?;
    let stamp = unix_utc(
        fleet["sampled_at_utc"]
            .as_str()
            .context("fleet sample missing")?,
    )?;
    ensure!(
        stamp <= a.issued_unix_seconds && a.issued_unix_seconds - stamp < 1800,
        "native admission uses stale fleet sample"
    );
    let capacity: Bound = serde_json::from_value(fleet["capacity_decision"].clone())?;
    let c = evidence::bound_json(&capacity)?;
    ensure!(
        a.protected_floor_bytes
            >= c["current_root_future_obligations_bytes"]
                .as_u64()
                .context("fleet floor missing")?,
        "native floor omits current protected growth"
    );
    let active = fleet["active"].as_array().context("active fleet missing")?;
    ensure!(
        !active.is_empty() && active.len() == a.protected_owners.len(),
        "protected native owner enrollment differs"
    );
    let mut names = BTreeSet::new();
    for p in &a.protected_owners {
        ensure!(
            names.insert(&p.unit)
                && active.iter().any(|r| r["unit"] == p.unit
                    && r["producer_invocation_id"] == p.invocation_id
                    && r["phase"] == "replay"),
            "native protected owner differs from live fleet"
        );
        owner(&p.unit, &p.invocation_id, &p.exec_start)?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EngineLineage {
    schema: String,
    helper: Bound,
    normal_build: Bound,
    harness_compile: Bound,
    full_source_manifest: Bound,
    source_evidence: Vec<Bound>,
}
fn embedded_sources() -> BTreeMap<&'static str, String> {
    [
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_cache.rs",
            include_bytes!("snapshot92447542_cache.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_lifecycle_engine.rs",
            include_bytes!("snapshot92447542_lifecycle_engine.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_mount_probe.rs",
            include_bytes!("snapshot92447542_mount_probe.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_native_crash.rs",
            include_bytes!("snapshot92447542_native_crash.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/src/snapshot92447542_native_engine.rs",
            include_bytes!("snapshot92447542_native_engine.rs").as_slice(),
        ),
        (
            "jetstreamer-horizon-observe/Cargo.toml",
            include_bytes!("../Cargo.toml").as_slice(),
        ),
        (
            "scripts/horizon_snapshot92447542_cache_v1/README.md",
            include_bytes!("../../scripts/horizon_snapshot92447542_cache_v1/README.md").as_slice(),
        ),
    ]
    .into_iter()
    .map(|(n, b)| (n, sha(b)))
    .collect()
}
fn decode<T: serde::de::DeserializeOwned>(b: &Bound) -> Result<T> {
    Ok(serde_json::from_slice(&root_bound_file(b, 1 << 20, true)?)?)
}
fn lineage(bound: &Bound, harness_sha: &str) -> Result<EngineLineage> {
    let l: EngineLineage = decode(bound)?;
    ensure!(
        l.schema == "jetstreamer-snapshot92447542-normal-engine-lineage-v1",
        "wrong engine lineage"
    );
    let (h, m) = evidence::hash_file(&l.helper.path, 256 << 20)?;
    ensure!(
        h == l.helper.sha256 && m.uid() == 0 && m.mode() & 0o222 == 0 && m.mode() & 0o111 != 0,
        "normal helper custody changed"
    );
    let build = evidence::bound_json(&l.normal_build)?;
    ensure!(
        build["features"] == json!([])
            && build["actual_normal_binary"]["sha256"] == l.helper.sha256
            && build["actual_root_Cargo_artifact"]["profile"]["test"] == false
            && build["actual_normal_library_artifact"]["profile"]["test"] == false
            && build["actual_bin_extern_bound_to_normal_library_without_test_cfg"] == true
            && build["actual_workspace_release_profile"]["lto"] == true
            && build["actual_workspace_release_profile"]["codegen-units"] == 1,
        "normal engine artifact differs"
    );
    let harness = evidence::bound_json(&l.harness_compile)?;
    ensure!(
        harness["native_harness_compiled"] == true
            && harness["native_tests_executed"] == false
            && harness["actual_harness"]["sha256"] == harness_sha
            && harness["features"]
                == json!([
                    "snapshot92447542-native-lifecycle-tests",
                    "snapshot92447542-native-sdk-tests"
                ])
            && harness["actual_root_Cargo_artifact"]["profile"]["test"] == true
            && harness["full_source_manifest"] == build["full_source_manifest"],
        "native harness build differs"
    );
    let manifest: Value =
        serde_json::from_slice(&root_bound_file(&l.full_source_manifest, 8 << 20, true)?)?;
    ensure!(
        build["full_source_manifest"]
            == json!({"path":l.full_source_manifest.path,"sha256":l.full_source_manifest.sha256}),
        "lineage manifest differs"
    );
    let rows = manifest["tracked_source_files"]
        .as_array()
        .context("full source manifest members missing")?;
    let embedded = embedded_sources();
    ensure!(
        l.source_evidence.len() == embedded.len(),
        "incomplete engine source evidence"
    );
    for (rel, digest) in embedded {
        let row = rows
            .iter()
            .find(|r| r["path"] == rel)
            .context("missing exact source member")?;
        ensure!(
            row["sha256"] == digest,
            "native compilation source differs from normal workspace"
        );
        let b = l
            .source_evidence
            .iter()
            .find(|b| b.path.file_name() == Path::new(rel).file_name())
            .context("sealed source evidence missing")?;
        ensure!(b.sha256 == digest, "sealed source mismatch");
        root_bound_file(b, 16 << 20, true)?;
    }
    Ok(l)
}
struct NativeEnvironment<'a> {
    admission: &'a EngineAdmission,
    profile: &'a EngineProfile,
    start_identity: (u32, u64),
    start: Instant,
    cache: Directory,
    state: Directory,
    source: Identity,
    object: ObjectSpec,
    bindings: Bindings,
    request: RefCell<Option<RestoreRequest>>,
    history: Bound,
    reference_policy: Bound,
    phase_counter: Cell<u32>,
    phases: RefCell<Vec<String>>,
}
impl NativeEnvironment<'_> {
    fn native(&self) -> Result<Value> {
        ensure!(
            DirectoryIdentity::of(&fs::symlink_metadata(&self.admission.fixture_root)?)
                == self.admission.fixture_identity,
            "native fixture root replaced"
        );
        for protected in &self.admission.protected_owners {
            owner(
                &protected.unit,
                &protected.invocation_id,
                &protected.exec_start,
            )?;
        }
        ensure!(
            self.start.elapsed().as_secs() < self.admission.maximum_run_seconds,
            "native engine runtime exhausted"
        );
        native_service(
            self.profile,
            self.start_identity,
            self.admission.output.parent().context("output parent")?,
            &self.admission.fixture_root,
        )
    }
}
impl Environment for NativeEnvironment<'_> {
    fn cache(&self) -> &Directory {
        &self.cache
    }
    fn state(&self) -> &Directory {
        &self.state
    }
    fn source_identity(&self) -> &Identity {
        &self.source
    }
    fn bindings(&self) -> &Bindings {
        &self.bindings
    }
    fn object(&self) -> &ObjectSpec {
        &self.object
    }
    fn history(&self) -> Result<Value> {
        evidence::bound_json(&self.history)
    }
    fn consumers(&self) -> Result<Value> {
        self.native()?;
        evidence::bound_json(&self.reference_policy)?;
        let scan = process_references::scan(Path::new("/proc"), &self.admission.fixture_root)?;
        ensure!(
            scan.references.is_empty(),
            "isolated fixture has an external reader"
        );
        let aliases = inode_references(Path::new("/proc"), self.source.device, self.source.inode)?;
        ensure!(
            aliases.is_empty(),
            "isolated source inode has an external alias reader"
        );
        Ok(
            json!({"consumers":[],"scope":"isolated-full-generation-control-only","actual_reference_scan":scan,"inode_references":aliases,"reference_policy_sha256":self.reference_policy.sha256}),
        )
    }
    fn metadata(&self) -> Result<Vec<u8>> {
        let mut first = None;
        let bytes = metadata_core(&self.admission.gcloud, |pid, point| {
            match point {
                SdkWitnessPoint::Spawned => {
                    child_witness(pid, &self.profile.control_group)?;
                    first = Some((pid, stat(pid)?));
                }
                SdkWitnessPoint::BeforeReap => {
                    let state = status(pid)?;
                    ids(&state, "Uid", 1000)?;
                    ids(&state, "Gid", 1000)?;
                    ensure!(
                        first == Some((pid, stat(pid)?)),
                        "owned SDK identity changed"
                    );
                }
            }
            Ok(())
        })?;
        shutdown_witness(first.context("SDK witness missing")?.0)?;
        Ok(bytes)
    }
    fn restore_request(&self) -> Option<RestoreRequest> {
        self.request.borrow().clone()
    }
    fn restore_admission(&self, verified: &str) -> Result<Booking> {
        self.native()?;
        ensure!(is_sha(verified), "invalid verified digest");
        Ok(Booking {
            protected_floor_bytes: self.admission.protected_floor_bytes,
            owner: Owner {
                unit: self.profile.unit.clone(),
                invocation_id: self.profile.invocation_id.clone(),
                exec_start: self.profile.expected_properties["ExecStart"].clone(),
            },
            protected_owners: self
                .admission
                .protected_owners
                .iter()
                .map(|o| Owner {
                    unit: o.unit.clone(),
                    invocation_id: o.invocation_id.clone(),
                    exec_start: o.exec_start.clone(),
                })
                .collect(),
        })
    }
    fn guard_owners(&self, _booking: &Booking) -> Result<()> {
        self.native()?;
        Ok(())
    }
    fn spawn_download(&self, destination: &Path) -> Result<OwnedSdk> {
        ensure!(
            destination.starts_with(&self.admission.fixture_root)
                && destination.file_name() == Some(std::ffi::OsStr::new(NAME)),
            "download outside admitted fixture"
        );
        let mut cmd = sdk_command(&self.admission.gcloud)?;
        cmd.args([
            "storage",
            "cp",
            "--no-clobber",
            "--quiet",
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            URI,
        ])
        .arg(destination);
        Ok(OwnedSdk(Some(cmd.spawn()?)))
    }
    fn after_phase(&self, phase: Phase) -> Result<()> {
        self.native()?;
        let index = self.phase_counter.get();
        self.phase_counter
            .set(index.checked_add(1).context("phase overflow")?);
        let name = format!("{phase:?}");
        self.phases.borrow_mut().push(name.clone());
        persist(
            &self
                .admission
                .output
                .parent()
                .context("output parent")?
                .join(format!("phase-{index:03}.json")),
            &json!({"schema":"jetstreamer-snapshot92447542-native-engine-phase-v1","phase":name,"elapsed_millis":self.start.elapsed().as_millis(),"actual_unit":self.profile.unit,"actual_invocation_id":self.profile.invocation_id,"data_retirement_authorized":false}),
        )
    }
    fn authorize_recovery(
        &self,
        _prior: &Value,
        _stage: Option<&DirectoryIdentity>,
    ) -> Result<Value> {
        bail!("positive roundtrip admission supplies no abandoned-attempt recovery authority")
    }
}

/// Entry gate for the separately selected bounded full-engine fault models.
/// This proves the enclosing native invocation; fixture callbacks intentionally
/// model transport/owner/floor faults and do not establish real crash controls.
pub(super) fn fixture_gate() -> Result<PathBuf> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "Root native fixture admission required"
    );
    let path = env::var("JETSTREAMER_SNAPSHOT92447542_ENGINE_ADMISSION")?;
    let digest = env::var("JETSTREAMER_SNAPSHOT92447542_ENGINE_ADMISSION_SHA256")?;
    let bound = Bound {
        path: path.into(),
        sha256: digest,
    };
    let a: EngineAdmission = decode(&bound)?;
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-native-engine-admission-v1"
            && a.route == "bounded-full-engine-fixture-models"
            && a.issued_unix_seconds <= now()?
            && now()? <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 300
            && a.maximum_fixture_bytes == (16 << 20),
        "wrong/stale fixture-model admission"
    );
    let actual = fs::canonicalize("/proc/self/exe")?;
    let (hash, m) = evidence::hash_file(&actual, 256 << 20)?;
    ensure!(
        actual == a.test_binary.path
            && hash == a.test_binary.sha256
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && Identity::of(&m) == Identity::of(&fs::metadata("/proc/self/exe")?),
        "fixture harness image changed"
    );
    lineage(&a.engine_lineage, &a.test_binary.sha256)?;
    validate_fleet(&a)?;
    let p: EngineProfile = decode(&a.profile)?;
    let output = a.output.parent().context("fixture output parent")?;
    private_dir(output)?;
    let root = fs::symlink_metadata(&a.fixture_root)?;
    ensure!(
        a.fixture_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && a.fixture_root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("qualification-snapshot92447542-native-engine-"))
            && a.fixture_root.canonicalize()? == a.fixture_root
            && DirectoryIdentity::of(&root) == a.fixture_identity
            && root.is_dir()
            && root.uid() == 1000
            && root.gid() == 1000
            && root.mode() & 0o7777 == 0o700,
        "fixture root identity/custody differs"
    );
    native_service(&p, stat(std::process::id())?, output, &a.fixture_root)?;
    let hidden: BTreeSet<_> = p
        .expected_properties
        .get("InaccessiblePaths")
        .context("original quarantine missing")?
        .split_whitespace()
        .collect();
    ensure!(
        hidden == BTreeSet::from([CACHE_ROOT, STATE])
            && fs::symlink_metadata(Path::new(CACHE_ROOT).join(NAME)).is_err(),
        "original cache visible to fixture models"
    );
    let mut stack = vec![a.fixture_root.clone()];
    let mut count = 0u64;
    let mut bytes = 0u64;
    while let Some(path) = stack.pop() {
        count += 1;
        ensure!(count <= 4096, "fixture enrollment exceeds bound");
        let meta = fs::symlink_metadata(&path)?;
        ensure!(
            matches!(meta.uid(), 0 | 1000) && !meta.file_type().is_symlink(),
            "foreign fixture member"
        );
        bytes = bytes
            .checked_add(meta.blocks().checked_mul(512).context("blocks overflow")?)
            .context("fixture allocation overflow")?;
        ensure!(
            bytes <= a.maximum_fixture_bytes,
            "fixture allocation cap exceeded"
        );
        if meta.is_dir() {
            for entry in fs::read_dir(path)? {
                stack.push(entry?.path());
            }
        } else {
            ensure!(meta.is_file() && meta.nlink() == 1, "unsafe fixture file");
        }
    }
    ensure!(
        free_bytes(&a.fixture_root)? >= a.protected_floor_bytes
            && a.protected_floor_bytes >= CENTURY_MINIMUM,
        "fixture floor crossed"
    );
    Ok(a.fixture_root)
}

#[test]
fn actual_fixed_generation_full_engine_roundtrip() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "explicit native Root admission required"
    );
    let path = env::var("JETSTREAMER_SNAPSHOT92447542_ENGINE_ADMISSION")?;
    let admission_sha = env::var("JETSTREAMER_SNAPSHOT92447542_ENGINE_ADMISSION_SHA256")?;
    let bound = Bound {
        path: path.into(),
        sha256: admission_sha,
    };
    let a: EngineAdmission = decode(&bound)?;
    let started = Instant::now();
    ensure!(
        a.schema == "jetstreamer-snapshot92447542-native-engine-admission-v1"
            && a.route == "fixed-generation-isolated-full-engine-roundtrip"
            && a.issued_unix_seconds <= now()?
            && now()? <= a.expires_unix_seconds
            && a.expires_unix_seconds > a.issued_unix_seconds
            && a.expires_unix_seconds - a.issued_unix_seconds <= 300
            && (60..=7200).contains(&a.maximum_run_seconds)
            && a.protected_floor_bytes >= CENTURY_MINIMUM,
        "wrong native engine admission"
    );
    let actual_self = fs::canonicalize("/proc/self/exe")?;
    let (h, m) = evidence::hash_file(&actual_self, 256 << 20)?;
    ensure!(
        actual_self == a.test_binary.path
            && h == a.test_binary.sha256
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && Identity::of(&m) == Identity::of(&fs::metadata("/proc/self/exe")?),
        "wrong native image"
    );
    let l = lineage(&a.engine_lineage, &a.test_binary.sha256)?;
    validate_fleet(&a)?;
    let profile: EngineProfile = decode(&a.profile)?;
    let output = a.output.parent().context("output parent")?;
    private_dir(output)?;
    ensure!(
        a.output.file_name() == Some(std::ffi::OsStr::new("native-engine-result.json"))
            && absent(&a.output)?,
        "unsafe occupied native result"
    );
    ensure!(
        a.fixture_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && a.fixture_root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("qualification-snapshot92447542-native-engine-"))
            && a.fixture_root.canonicalize()? == a.fixture_root,
        "fixture root outside exact private namespace"
    );
    let fm = fs::symlink_metadata(&a.fixture_root)?;
    ensure!(
        DirectoryIdentity::of(&fm) == a.fixture_identity
            && a.maximum_fixture_bytes == 2 * SIZE + 2 * SLACK
            && fm.is_dir()
            && fm.uid() == 1000
            && fm.gid() == 1000
            && fm.mode() & 0o7777 == 0o700
            && fs::read_dir(&a.fixture_root)?.next().is_none(),
        "fixture root not fresh/private"
    );
    let self_start = stat(std::process::id())?;
    let before = native_service(&profile, self_start, output, &a.fixture_root)?;
    ensure!(
        duration_seconds(&profile.expected_properties["RuntimeMaxUSec"])? == a.maximum_run_seconds,
        "native runtime differs from booking"
    );
    let hidden: BTreeSet<_> = profile
        .expected_properties
        .get("InaccessiblePaths")
        .context("original-path quarantine missing")?
        .split_whitespace()
        .collect();
    ensure!(
        hidden == BTreeSet::from([CACHE_ROOT, STATE]),
        "original paths must be quarantined from native fixture"
    );
    ensure!(
        fs::symlink_metadata(Path::new(CACHE_ROOT).join(NAME)).is_err(),
        "original payload is visible to isolated control"
    );
    let expected_peak = SIZE
        .checked_mul(2)
        .and_then(|n| n.checked_add(2 * SLACK))
        .context("fixture reservation overflow")?;
    ensure!(
        free_bytes(&a.fixture_root)?
            >= a.protected_floor_bytes
                .checked_add(expected_peak)
                .context("fixture floor overflow")?,
        "full native fixture does not fit"
    );
    let cache_path = a.fixture_root.join("cache");
    let state_path = a.fixture_root.join("state");
    for (p, uid) in [(&cache_path, 1000), (&state_path, 0)] {
        fs::create_dir(p)?;
        fs::set_permissions(p, fs::Permissions::from_mode(0o700))?;
        let d = File::open(p)?;
        chown(&d, uid, uid)?;
        d.sync_all()?;
    }
    File::open(&a.fixture_root)?.sync_all()?;
    let cache = Directory::open(
        &cache_path,
        &DirectoryIdentity::of(&fs::symlink_metadata(&cache_path)?),
    )?;
    let state = Directory::open(
        &state_path,
        &DirectoryIdentity::of(&fs::symlink_metadata(&state_path)?),
    )?;
    // Establish a genuine isolated full-generation source. This is outside the
    // production lifecycle and carries no original-cache or operational authority.
    let mut command = sdk_command(&a.gcloud)?;
    command
        .args([
            "storage",
            "cp",
            "--no-clobber",
            "--quiet",
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            URI,
        ])
        .arg(cache_path.join(NAME));
    let mut child = OwnedSdk(Some(command.spawn()?));
    let pid = child.0.as_ref().context("SDK child")?.id();
    child_witness(pid, &profile.control_group)?;
    let mut last = Instant::now();
    while !child.exited()? {
        native_service(&profile, self_start, output, &a.fixture_root)?;
        ensure!(
            started.elapsed().as_secs() < a.maximum_run_seconds
                && free_bytes(&cache_path)? >= a.protected_floor_bytes
                && staged_bytes(&cache)? <= SIZE + SLACK,
            "bootstrap fixture guard failed"
        );
        if last.elapsed() >= Duration::from_secs(60) {
            println!(
                "slot92447542 isolated baseline download bytes={}",
                staged_bytes(&cache)?
            );
            last = Instant::now();
        }
        thread::sleep(Duration::from_millis(200));
    }
    ensure!(
        child.finish()?.success(),
        "isolated generation bootstrap failed"
    );
    shutdown_witness(pid)?;
    let file = cache.open_file(NAME)?;
    file.sync_all()?;
    cache.sync()?;
    drop(file);
    let (source, digests, _) = hash_at(&cache, NAME, None, None, || {
        ensure!(
            started.elapsed().as_secs() < a.maximum_run_seconds
                && free_bytes(&cache_path)? >= a.protected_floor_bytes,
            "isolated source hash guard failed"
        );
        Ok(())
    })?;
    ensure!(
        source.uid == 1000 && source.gid == 1000 && source.mode & 0o7777 == 0o600,
        "isolated source custody differs"
    );
    let history_path = state_path.join("isolated-source-history.json");
    persist(
        &history_path,
        &json!({"schema":"jetstreamer-snapshot92447542-isolated-source-history-v1","uri":URI,"generation":GENERATION,"identity":source,"digests":digests,"actual_native_admission_sha256":bound.sha256,"original_snapshot_body_read":false}),
    )?;
    let policy_path = state_path.join("isolated-reference-policy.json");
    persist(
        &policy_path,
        &json!({"schema":"jetstreamer-snapshot92447542-isolated-reference-policy-v1","fixture_root":a.fixture_root,"source_identity":source,"actual_unit":profile.unit,"actual_invocation_id":profile.invocation_id,"scope":"this isolated native service and its owned SDK children only; does not qualify production consumers"}),
    )?;
    let history = Bound {
        path: history_path.clone(),
        sha256: reference(&history_path)?["sha256"]
            .as_str()
            .context("history hash")?
            .into(),
    };
    let policy = Bound {
        path: policy_path.clone(),
        sha256: reference(&policy_path)?["sha256"]
            .as_str()
            .context("policy hash")?
            .into(),
    };
    let e = NativeEnvironment {
        admission: &a,
        profile: &profile,
        start_identity: self_start,
        start: started,
        cache,
        state,
        source: source.clone(),
        object: ObjectSpec::fixed_generation(),
        bindings: Bindings::isolated(
            &bound.sha256,
            &a.test_binary.sha256,
            &policy.sha256,
            &a.engine_lineage.sha256,
        )?,
        request: RefCell::new(None),
        history,
        reference_policy: policy,
        phase_counter: Cell::new(0),
        phases: RefCell::new(Vec::new()),
    };
    core::run_check(&e)?;
    let check = reference(&state_path.join(state_name("check")))?;
    let check_sha = check["sha256"].as_str().context("check hash")?;
    core::run_evict(&e, check_sha)?;
    ensure!(
        e.cache.absent(NAME)?,
        "isolated source not retired by shared engine"
    );
    *e.request.borrow_mut() = Some(RestoreRequest {
        attempt: format!("slot92447542-restore-native-{}", profile.invocation_id),
        maximum_runtime_seconds: a
            .maximum_run_seconds
            .saturating_sub(started.elapsed().as_secs()),
        admission_sha256: bound.sha256.clone(),
    });
    core::run_restore(&e, check_sha)?;
    let restored = load(&state_path.join(state_name("restored")))?;
    let identity = Identity::of(&fs::symlink_metadata(cache_path.join(NAME))?);
    ensure!(
        identity.inode != source.inode
            && identity.uid == 0
            && identity.gid == 0
            && identity.mode & 0o7777 == 0o444
            && restored["digests"] == serde_json::to_value(&digests)?,
        "full-engine restored object differs"
    );
    let after = e.native()?;
    ensure!(
        before["properties"] == after["properties"],
        "native owner changed"
    );
    persist(
        &a.output,
        &json!({"schema":"jetstreamer-snapshot92447542-native-engine-roundtrip-v1","admission":{"path":bound.path,"sha256":bound.sha256},"normal_helper_sha256":l.helper.sha256,"native_binary_sha256":a.test_binary.sha256,"engine_lineage_sha256":a.engine_lineage.sha256,"uri":URI,"generation":GENERATION,"bytes":SIZE,"actual_source_identity":source,"restored_identity":identity,"full_object_digests":digests,"before":before,"after":after,"phases":*e.phases.borrow(),"shared_engine_check_evict_restore_passed":true,"original_cache_body_read":false,"lifecycle_qualification":false,"eviction_authorized":false,"restore_authorized":false,"replay_authorized":false,"remote_mutations":false}),
    )?;
    Ok(())
}

// Actual process-exit/recovery controls have separate per-invocation admission
// and persistent isolated-session authority. No normal CLI route exposes them.
#[path = "snapshot92447542_native_crash.rs"]
mod process_crash;
