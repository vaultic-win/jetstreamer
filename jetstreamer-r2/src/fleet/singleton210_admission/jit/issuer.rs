//! Exact native role and effective sandbox of the same-process JIT issuer.
use super::*;
const FIELDS: &str = "Id,LoadState,Type,User,Group,ActiveState,SubState,MainPID,InvocationID,NRestarts,ControlGroup,ExecStart,FragmentPath,DropInPaths,NeedDaemonReload,Transient,Restart,RuntimeMaxUSec,TimeoutStopUSec,KillMode,MemoryMax,MemoryHigh,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,Nice,UMask,ProtectSystem,ProtectHome,PrivateTmp,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,EnvironmentFiles,PassEnvironment,ExecStartPre,ExecStartPost,ExecCondition,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure,LimitCORE,LimitCORESoft,LimitFSIZE,LimitFSIZESoft";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Role {
    pub unit: String,
    pub fragment: PathBuf,
    pub runner: BoundFile,
    pub deployment_seal: BoundFile,
    pub qualification: BoundFile,
}
pub(super) fn scope(name: &str) -> bool {
    name.strip_prefix("horizon-capacity210-jit-")
        .and_then(|s| s.strip_suffix(".service"))
        .is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 128
                && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn text(path: impl AsRef<Path>, maximum: u64) -> Result<String> {
    completed_archive_phase::jit210_native_text(path, maximum)
}
fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .with_context(|| format!("210 JIT issuer missing text: {k}"))
}
fn credentials(raw: &str) -> Result<Value> {
    let fields = raw
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k, v.trim()))
        .collect::<BTreeMap<_, _>>();
    for key in ["Uid", "Gid"] {
        ensure!(
            fields
                .get(key)
                .is_some_and(|v| v.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"]),
            "210 JIT issuer is not native root"
        );
    }
    ensure!(
        fields.get("NoNewPrivs") == Some(&"1"),
        "210 JIT issuer can gain privileges"
    );
    for key in ["CapEff", "CapPrm", "CapBnd", "CapAmb"] {
        ensure!(
            fields.get(key) == Some(&"0000000000080002"),
            "210 JIT issuer has wrong native capabilities: {key}"
        );
    }
    Ok(json!({"uid":0,"gid":0,"no_new_privileges":true,"capabilities":"0000000000080002"}))
}
fn command(role: &Role, spec: &BoundFile) -> Vec<String> {
    vec![
        role.runner.path.display().to_string(),
        "admit-singleton210-jit".into(),
        spec.path.display().to_string(),
        "--spec-sha256".into(),
        spec.sha256.clone(),
        "--self-sha256".into(),
        role.runner.sha256.clone(),
    ]
}
fn command_display(argv: &[String]) -> Result<String> {
    ensure!(
        !argv.is_empty()
            && argv
                .iter()
                .all(|a| !a.is_empty() && !a.chars().any(char::is_whitespace)),
        "210 JIT argv cannot be represented exactly"
    );
    Ok(format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no }}",
        argv[0],
        argv.join(" ")
    ))
}
fn fragment(role: &Role, spec: &BoundFile, output: &Path) -> Result<BoundFile> {
    ensure!(
        scope(&role.unit) && role.fragment == Path::new("/etc/systemd/system").join(&role.unit),
        "210 JIT fragment escaped exact caller scope"
    );
    let raw = String::from_utf8(read_stable_bounded(
        &role.fragment,
        1 << 20,
        "210 JIT caller fragment",
    )?)?;
    let binding = BoundFile {
        path: role.fragment.clone(),
        sha256: hex_lower(&Sha256::digest(raw.as_bytes())),
    };
    let mut keys = BTreeMap::new();
    let mut section = "";
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
    {
        if line.starts_with('[') {
            ensure!(
                matches!(line, "[Unit]" | "[Service]"),
                "210 JIT foreign unit section"
            );
            section = line;
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .context("210 JIT malformed caller directive")?;
        ensure!(
            section == "[Service]" || (section == "[Unit]" && key == "Description"),
            "210 JIT caller unit has dependencies or hooks"
        );
        ensure!(
            keys.insert(key.to_owned(), value.to_owned()).is_none(),
            "210 JIT repeated caller directive"
        );
    }
    keys.remove("Description");
    let argv = command(role, spec);
    let expected = BTreeMap::from([
        ("Type".into(), "exec".into()),
        ("User".into(), "root".into()),
        ("Group".into(), "root".into()),
        ("Restart".into(), "no".into()),
        ("RuntimeMaxSec".into(), "600".into()),
        ("TimeoutStopSec".into(), "60".into()),
        ("KillMode".into(), "control-group".into()),
        ("MemoryMax".into(), "21474836480".into()),
        ("MemorySwapMax".into(), "0".into()),
        ("TasksMax".into(), "512".into()),
        ("CPUQuota".into(), "800%".into()),
        ("Nice".into(), "10".into()),
        ("UMask".into(), "0077".into()),
        ("ProtectSystem".into(), "strict".into()),
        ("ProtectHome".into(), "read-only".into()),
        ("PrivateTmp".into(), "yes".into()),
        ("PrivateNetwork".into(), "yes".into()),
        ("NoNewPrivileges".into(), "yes".into()),
        (
            "CapabilityBoundingSet".into(),
            "CAP_DAC_OVERRIDE CAP_SYS_PTRACE".into(),
        ),
        (
            "AmbientCapabilities".into(),
            "CAP_DAC_OVERRIDE CAP_SYS_PTRACE".into(),
        ),
        ("ReadWritePaths".into(), output.display().to_string()),
        ("Environment".into(), "TOKIO_WORKER_THREADS=4".into()),
        ("LimitCORE".into(), "0".into()),
        ("LimitFSIZE".into(), "67108864".into()),
        ("ExecStart".into(), argv.join(" ")),
        ("StandardOutput".into(), "journal".into()),
        ("StandardError".into(), "journal".into()),
    ]);
    ensure!(
        keys == expected,
        "210 JIT caller fragment is not the exact bounded metadata profile"
    );
    Ok(binding)
}
fn shape(
    role: &Role,
    spec: &BoundFile,
    self_sha: &str,
    output: &Path,
    props: &BTreeMap<String, String>,
) -> Result<()> {
    ensure!(
        scope(&role.unit) && role.runner.sha256 == self_sha,
        "210 JIT caller role/self differs"
    );
    singleton227_capture::require(
        props,
        &[
            ("Id", &role.unit),
            ("LoadState", "loaded"),
            ("Type", "exec"),
            ("User", "root"),
            ("Group", "root"),
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("NRestarts", "0"),
            ("Restart", "no"),
            ("RuntimeMaxUSec", "10min"),
            ("TimeoutStopUSec", "1min"),
            ("KillMode", "control-group"),
            ("MemoryMax", "21474836480"),
            ("MemoryHigh", "infinity"),
            ("MemorySwapMax", "0"),
            ("TasksMax", "512"),
            ("CPUQuotaPerSecUSec", "8s"),
            ("Nice", "10"),
            ("UMask", "0077"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateTmp", "yes"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
            ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
            ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
            ("Environment", "TOKIO_WORKER_THREADS=4"),
            ("DropInPaths", ""),
            ("NeedDaemonReload", "no"),
            ("Transient", "no"),
            ("LimitCORE", "0"),
            ("LimitCORESoft", "0"),
            ("LimitFSIZE", "67108864"),
            ("LimitFSIZESoft", "67108864"),
        ],
    )?;
    let expected_command = command_display(&command(role, spec))?;
    ensure!(
        props
            .get("ReadWritePaths")
            .is_some_and(|p| p == output.to_string_lossy().as_ref())
            && props
                .get("FragmentPath")
                .is_some_and(|p| p == role.fragment.to_string_lossy().as_ref())
            && props.get("ExecStart").is_some_and(|actual| {
                assembly204_recovery::delivery_command_matches(actual, &expected_command)
            }),
        "210 JIT effective output/fragment/argv differs"
    );
    Ok(())
}
pub(super) fn snapshot(
    role: &Role,
    spec: &BoundFile,
    self_sha: &str,
    output: &Path,
) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && unsafe { libc::getegid() } == 0
            && fs::read_link("/proc/self/exe")? == role.runner.path,
        "210 JIT caller is not the actual root issuer"
    );
    let fm = fs::symlink_metadata(&role.fragment)?;
    ensure!(
        role.fragment.canonicalize()? == role.fragment
            && fm.is_file()
            && fm.uid() == 0
            && fm.nlink() == 1
            && fm.mode() & 0o222 == 0,
        "210 JIT effective fragment is not immutable root custody"
    );
    assembly204_recovery::deployed_delivery_member(&role.deployment_seal, &role.runner, 256 << 20)?;
    let qualification = native210::immutable_json(&role.qualification)?;
    ensure!(
        qualification["schema"] == "jetstreamer-full210-jit-issuer-role-qualification-v1"
            && qualification["role"] == "singleton210-jit-admission"
            && qualification["helper"] == private157::binding(&role.runner)
            && qualification["strict_clippy_passed"] == true
            && qualification["full_default_tests_passed"] == true
            && qualification["focused_jit_regressions_passed"] == true
            && qualification["native210_small_enabled"] == true,
        "210 JIT issuer role is not independently qualified for this ELF"
    );
    for key in ["source_commit", "source_tree"] {
        ensure!(
            qualification[key]
                .as_str()
                .is_some_and(|s| is_lower_hex(s, 40)),
            "210 JIT qualification source identity missing"
        );
    }
    for key in [
        "publication_authorized",
        "replay_launch_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            qualification[key] == false,
            "210 JIT role borrows execution/publication authority"
        );
    }
    let qa: BoundFile = serde_json::from_value(qualification["source_qa"].clone())?;
    native210::immutable_json(&qa)?;
    let fragment = fragment(role, spec, output)?;
    let props = completed_archive_phase::jit210_properties(&role.unit, FIELDS)?;
    shape(role, spec, self_sha, output, &props)?;
    let iid = env::var("INVOCATION_ID").context("210 JIT native IID missing")?;
    ensure!(
        is_lower_hex(&iid, 32)
            && iid.bytes().any(|c| c != b'0')
            && props.get("InvocationID") == Some(&iid)
            && props.get("MainPID") == Some(&std::process::id().to_string()),
        "210 JIT caller PID/IID differs"
    );
    let credentials = credentials(&text("/proc/self/status", 64 << 10)?)?;
    let ticks = completed_archive_phase::jit210_start_ticks(&text("/proc/self/stat", 64 << 10)?)?;
    let clock = completed_archive_phase::jit210_start_clock(ticks)?;
    let started = clock["started_unix_seconds"]
        .as_u64()
        .context("210 JIT native start clock")?;
    let now = super::now()?;
    ensure!(
        started <= now && now - started < 600,
        "210 JIT native issuer deadline elapsed"
    );
    let group = format!("/system.slice/{}", role.unit);
    ensure!(
        props.get("ControlGroup") == Some(&group)
            && text("/proc/self/cgroup", 64 << 10)? == format!("0::{group}\n"),
        "210 JIT native cgroup differs"
    );
    let argv = command(role, spec);
    let mut encoded = argv.join("\0");
    encoded.push('\0');
    ensure!(
        text("/proc/self/cmdline", 64 << 10)? == encoded
            && env::var("TOKIO_WORKER_THREADS").as_deref() == Ok("4"),
        "210 JIT actual argv or thread bound differs"
    );
    for key in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "LD_LIBRARY_PATH",
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "RUBYOPT",
        "PERL5OPT",
        "GCONV_PATH",
    ] {
        ensure!(
            env::var_os(key).is_none(),
            "210 JIT inherited unsafe execution environment"
        );
    }
    let root = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    ensure!(
        root.canonicalize()? == root,
        "210 JIT cgroup namespace redirected"
    );
    for (key, wanted) in [
        ("memory.max", "21474836480"),
        ("memory.high", "max"),
        ("memory.swap.max", "0"),
        ("pids.max", "512"),
        ("cpu.max", "800000 100000"),
    ] {
        ensure!(
            text(root.join(key), 1024)?.trim() == wanted,
            "210 JIT native hard limit differs: {key}"
        );
    }
    ensure!(
        text(root.join("cgroup.procs"), 64 << 10)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?
            == [std::process::id()],
        "210 JIT issuer started another process"
    );
    ensure!(
        completed_archive_phase::jit210_start_ticks(&text("/proc/self/stat", 64 << 10)?)? == ticks,
        "210 JIT native PID was reused"
    );
    let after = singleton227_capture::properties(&role.unit, FIELDS)?;
    let raw: BTreeMap<String, String> = serde_json::from_str(
        props
            .get("TypedEmptyRawShow")
            .context("210 JIT typed raw evidence absent")?,
    )?;
    ensure!(
        raw == after,
        "210 JIT effective sandbox changed during native capture"
    );
    Ok(
        json!({"pid":std::process::id(),"invocation_id":iid,"start_ticks":ticks,"native_start_clock":clock,
        "cgroup":group,"runner":role.runner,"argv":argv,"credentials":credentials,"properties":props,
        "fragment":fragment,"qualification":role.qualification,"deployment_seal":role.deployment_seal}),
    )
}
pub(super) fn same(before: &Value, after: &Value) -> Result<()> {
    for key in [
        "pid",
        "invocation_id",
        "start_ticks",
        "native_start_clock",
        "cgroup",
        "runner",
        "argv",
        "credentials",
        "fragment",
        "qualification",
        "deployment_seal",
    ] {
        ensure!(
            !before[key].is_null() && before[key] == after[key],
            "210 JIT issuer changed: {key}"
        );
    }
    let a: BTreeMap<String, String> = serde_json::from_value(before["properties"].clone())?;
    let b: BTreeMap<String, String> = serde_json::from_value(after["properties"].clone())?;
    for (key, value) in a.iter().filter(|(k, _)| {
        !matches!(
            k.as_str(),
            "TypedEmptyRawShow" | "TypedEmptyReplies" | "ExecStart"
        )
    }) {
        ensure!(
            b.get(key) == Some(value),
            "210 JIT effective caller contract changed: {key}"
        );
    }
    ensure!(
        assembly204_recovery::delivery_command_matches(
            str_field(&after["properties"], "ExecStart")?,
            str_field(&before["properties"], "ExecStart")?
        ),
        "210 JIT caller command changed"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn identity_fixture() -> Value {
        json!({"pid":7,"invocation_id":"a".repeat(32),"start_ticks":123,
            "native_start_clock":{"boot_id":"b".repeat(36),"started_unix_seconds":100},
            "cgroup":"/system.slice/horizon-capacity210-jit-test.service","runner":{"path":"/sealed/helper","sha256":"c".repeat(64)},
            "argv":["/sealed/helper","admit-singleton210-jit"],"credentials":{"uid":0},
            "fragment":{"path":"/etc/systemd/system/horizon-capacity210-jit-test.service","sha256":"d".repeat(64)},
            "qualification":{"path":"/sealed/qualification","sha256":"e".repeat(64)},
            "deployment_seal":{"path":"/sealed/seal","sha256":"f".repeat(64)},
            "properties":{"ExecStart":"{ path=/sealed/helper ; argv[]=/sealed/helper admit-singleton210-jit ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }","MemoryMax":"21474836480","TypedEmptyRawShow":"{}","TypedEmptyReplies":"{}"}})
    }
    #[test]
    fn full210_jit_same_process_proof_rejects_replaced_caller_and_effective_contract() {
        let before = identity_fixture();
        same(&before, &before).unwrap();
        for (path, value) in [
            ("/pid", json!(8)),
            ("/start_ticks", json!(124)),
            ("/invocation_id", json!("9".repeat(32))),
            ("/native_start_clock/boot_id", json!("other-boot")),
            ("/cgroup", json!("/system.slice/other.service")),
            ("/runner/sha256", json!("0".repeat(64))),
            ("/fragment/sha256", json!("0".repeat(64))),
            ("/credentials/uid", json!(1000)),
            ("/argv", json!(["/sealed/helper", "other-command"])),
            ("/properties/MemoryMax", json!("1073741824")),
        ] {
            let mut changed = before.clone();
            *changed.pointer_mut(path).unwrap() = value;
            assert!(same(&before, &changed).is_err(), "{path}");
        }
        let mut display = before.clone();
        display["properties"]["ExecStart"] = json!(
            "{ path=/sealed/helper ; argv[]=/sealed/helper admit-singleton210-jit ; ignore_errors=no }"
        );
        same(&before, &display).unwrap();
        display["properties"]["ExecStart"] = json!(
            "{ path=/sealed/helper ; argv[]=/sealed/helper other-command ; ignore_errors=no }"
        );
        assert!(same(&before, &display).is_err());
    }
    #[test]
    fn full210_jit_caller_scope_and_native_capabilities_are_closed() {
        assert!(scope("horizon-capacity210-jit-attempt1.service"));
        for unit in [
            "horizon-capacity209-jit-a.service",
            "horizon-capacity210-jit-.service",
            "horizon-capacity210-jit-a.timer",
            "horizon-capacity210-jit-a/b.service",
        ] {
            assert!(!scope(unit));
        }
        let raw = "Uid:\t0 0 0 0\nGid:\t0 0 0 0\nNoNewPrivs:\t1\nCapEff:\t0000000000080002\nCapPrm:\t0000000000080002\nCapBnd:\t0000000000080002\nCapAmb:\t0000000000080002\n";
        credentials(raw).unwrap();
        for (from, to) in [
            ("Uid:\t0 0 0 0", "Uid:\t1000 1000 1000 1000"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            ("CapEff:\t0000000000080002", "CapEff:\t0000000000000002"),
        ] {
            assert!(credentials(&raw.replace(from, to)).is_err());
        }
    }
}
