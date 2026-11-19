//! Running-origin capture. No snapshot work, resource observation or epoch launch.
use super::native211::{self as c, num, text};
use super::*;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Result,ExecStart,ControlGroup,Type,User,Group,Restart,KillMode,Delegate,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,CPUAffinity,TasksMax,RuntimeMaxUSec,ProtectHome,ProtectSystem,PrivateNetwork,NoNewPrivileges,CapabilityBoundingSet,ReadWritePaths,Environment,Transient,RemainAfterExit,DropInPaths,FragmentPath,ExecMainPID,ExecMainStartTimestampMonotonic,ExecMainCode,ExecMainStatus,ControlPID,Job,TriggeredBy";
pub(super) fn properties() -> Result<Value> {
    Ok(json!(singleton227_capture::properties(c::UNIT, FIELDS)?))
}
pub(super) fn retention_values(v: &Value) -> Result<()> {
    ensure!(
        v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "active"
            && v["After"] == c::UNIT
            && v["IgnoreOnIsolate"] == "yes"
            && v["DefaultDependencies"] == "no"
            && v["DropInPaths"] == ""
            && v["Job"] == "",
        "211 retention absent"
    );
    for k in ["Wants", "Requires", "BindsTo", "Upholds"] {
        ensure!(v[k] == "", "211 retention activates producer: {k}");
    }
    Ok(())
}
pub(super) fn retention() -> Result<Value> {
    let v = json!(singleton227_capture::properties(
        c::RETENTION,
        "Id,LoadState,ActiveState,SubState,After,IgnoreOnIsolate,DefaultDependencies,DropInPaths,Job,Wants,Requires,BindsTo,Upholds,FragmentPath"
    )?);
    retention_values(&v)?;
    Ok(v)
}
pub(super) fn sandbox_values(v: &Value, p: &Value, pb: &BoundFile) -> Result<()> {
    sandbox_values_read(v, p, pb, &c::FsEvidence)
}
pub(super) fn sandbox_values_read(
    v: &Value,
    p: &Value,
    pb: &BoundFile,
    reader: &impl c::EvidenceReader,
) -> Result<()> {
    for (k, want) in [
        ("Id", c::UNIT),
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryHigh", "120259084288"),
        ("MemoryMax", "137438953472"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "8s"),
        ("RuntimeMaxUSec", "45min"),
        ("ProtectHome", "read-only"),
        ("ProtectSystem", "strict"),
        ("PrivateNetwork", "yes"),
        ("NoNewPrivileges", "yes"),
        ("CapabilityBoundingSet", ""),
        ("ReadWritePaths", c::ROOT),
        ("Transient", "no"),
        ("RemainAfterExit", "no"),
        ("DropInPaths", ""),
        ("LoadState", "loaded"),
        ("NRestarts", "0"),
    ] {
        ensure!(v[k] == want, "211 sandbox {k} differs");
    }
    ensure!(
        text(v, "ExecStart")?.split(" ; ignore_errors=").next() == Some(c::command().as_str()),
        "211 command differs"
    );
    let expected: BTreeSet<String> = [
        "RUST_MIN_STACK=134217728".into(),
        "SOLANA_RAYON_THREADS=8".into(),
        "JETSTREAMER_HISTORICAL_POH_THREADS=2".into(),
        format!(
            "JETSTREAMER_EPOCH211_V1616_TEST_SCRATCH={}/scratch",
            c::ROOT
        ),
        format!("JETSTREAMER_EPOCH211_STARTUP_PLAN={}", pb.path.display()),
        format!("JETSTREAMER_EPOCH211_STARTUP_PLAN_SHA256={}", pb.sha256),
    ]
    .into_iter()
    .collect();
    ensure!(
        text(v, "Environment")?
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            == expected,
        "211 environment differs"
    );
    let admission = reader.json(&c::binding(&p["admission"])?, true)?;
    let review = reader.json(&c::binding(&admission["review"])?, true)?;
    let expected: BTreeSet<u64> = review["cpu_affinity"]
        .as_array()
        .context("211 CPU review")?
        .iter()
        .map(|v| v.as_u64().context("211 CPU integer"))
        .collect::<Result<_>>()?;
    let mut actual = BTreeSet::new();
    for token in text(v, "CPUAffinity")?.split_whitespace() {
        if let Some((a, b)) = token.split_once('-') {
            let a = a.parse::<u64>()?;
            let b = b.parse::<u64>()?;
            ensure!(a <= b && b - a < 4096, "211 CPU range");
            actual.extend(a..=b);
        } else {
            actual.insert(token.parse::<u64>()?);
        }
    }
    ensure!(
        actual.len() == 8 && actual == expected,
        "211 CPU set differs"
    );
    Ok(())
}
pub(super) fn check_live(h: &Value) -> Result<Value> {
    let before = properties()?;
    let pb = c::binding(&h["startup_plan"])?;
    let p = c::sealed(&pb)?;
    sandbox_values(&before, &p, &pb)?;
    ensure!(
        before["InvocationID"] == h["invocation_id"]
            && text(&before, "MainPID")? == num(h, "main_pid")?.to_string()
            && before["ActiveState"] == "active"
            && before["SubState"] == "running"
            && before["Result"] == "success"
            && before["ControlGroup"] == format!("/system.slice/{}", c::UNIT)
            && before["Job"] == "",
        "211 live owner differs"
    );
    let pid = num(h, "main_pid")?;
    let exe = PathBuf::from(format!("/proc/{pid}/exe"));
    let disk = fs::symlink_metadata(c::TEST)?;
    let mapped = fs::metadata(&exe)?;
    ensure!(
        fs::read_link(&exe)? == Path::new(c::TEST)
            && mapped.dev() == disk.dev()
            && mapped.ino() == disk.ino()
            && disk.uid() == 0
            && disk.nlink() == 1
            && disk.mode() & 0o222 == 0
            && disk.len() < 128 << 20,
        "211 mapped executable differs"
    );
    let bytes = fs::read(&exe)?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == c::TEST_SHA,
        "211 mapped executable digest"
    );
    let group = format!("/sys/fs/cgroup/system.slice/{}", c::UNIT);
    let members = fs::read_to_string(format!("{group}/cgroup.procs"))?
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    ensure!(
        members == vec![pid.to_string()]
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                == format!("0::/system.slice/{}", c::UNIT)
            && fs::read_to_string(format!("{group}/memory.max"))?.trim() == c::MEMORY.to_string()
            && fs::read_to_string(format!("{group}/memory.swap.max"))?.trim() == "0",
        "211 process/cgroup scope differs"
    );
    retention()?;
    protection(h)?;
    ensure!(
        properties()? == before,
        "211 owner changed during identity capture"
    );
    Ok(before)
}
fn protection(h: &Value) -> Result<()> {
    super::native211_protection::check(h)
}
/// Preserve every previous manager row, including auxiliary jobs not in replay active[].
pub(super) fn peers(
    previous: &Value,
    current: &BTreeMap<String, Value>,
    exclude: &str,
) -> Result<()> {
    let old = previous["unit_census"]
        .as_object()
        .context("211 prior complete census")?;
    for (name, prior) in old {
        if name == exclude {
            continue;
        }
        let next = current.get(name).context("211 prior owner omitted")?;
        for key in [
            "Id",
            "LoadState",
            "ActiveState",
            "SubState",
            "InvocationID",
            "MainPID",
            "NRestarts",
            "Result",
            "ControlGroup",
        ] {
            ensure!(prior[key] == next[key], "211 peer changed {name}:{key}");
        }
        if let Some(cmd) = prior["ExecStart"].as_str() {
            ensure!(
                pipeline_status::same_exec_start(cmd, text(next, "ExecStart")?),
                "211 peer command changed"
            );
        }
    }
    for (name, next) in current {
        ensure!(
            name == exclude || old.contains_key(name) || !diagnostic_stage_running(next),
            "211 unaccounted new owner {name}"
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    startup_handoff: BoundFile,
    output: PathBuf,
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("capture-native211-input")?;
    let s: Spec = serde_json::from_value(c::sealed(&binding)?)?;
    ensure!(
        s.schema == "jetstreamer-native211-running-capture-spec-v1",
        "211 running spec"
    );
    c::namespace(&s.output, "horizon-native211-running-", "intent.json")?;
    let (h, a) = c::startup(&s.startup_handoff)?;
    ensure!(
        a["boot_id"] == fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "211 current boot differs"
    );
    let source = c::sealed(&c::binding(&a["source_publication"])?)?;
    ensure!(
        source["artifacts"]
            .as_array()
            .context("211 artifacts")?
            .iter()
            .any(|r| r["role"] == "fleet"
                && r["artifact"]["sha256"] == self_sha
                && r["artifact"]["path"].as_str()
                    == std::env::current_exe()
                        .ok()
                        .as_ref()
                        .and_then(|p| p.to_str())),
        "211 capture helper lacks published provenance"
    );
    let f = bound_json(&c::binding(&a["fleet"])?)?;
    let o = bound_json(&c::binding(&a["observer"])?)?;
    ensure!(
        f["observer_receipt"] == a["observer"]["path"]
            && f["observer_sha256"] == a["observer"]["sha256"]
            && f["sampled_at_utc"] == o["recorded_at_utc"],
        "211 accepted observer differs"
    );
    let names = f["unit_census"]
        .as_object()
        .context("211 names")?
        .keys()
        .cloned()
        .chain(std::iter::once(c::UNIT.into()))
        .collect();
    let before = census(&names, 201, 300)?;
    peers(&f, &before, c::UNIT)?;
    let producer = check_live(&h)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        num(&h, "recorded_unix_seconds")? <= now && now - num(&h, "recorded_unix_seconds")? <= 300,
        "211 running handoff stale/future"
    );
    let mut r = json!({"schema":c::SCHEMA,"epoch":211,"unit":c::UNIT,"private_run_root":c::ROOT,"invocation_id":h["invocation_id"],"main_pid":h["main_pid"],"test_sha256":c::TEST_SHA,"snapshot_sha256":c::SNAPSHOT_SHA,"bootstrap_slot":91_151_575u64,"accounts_hash":c::ACCOUNTS_HASH,"maximum_memory_bytes":c::MEMORY,"maximum_scratch_bytes":c::SCRATCH,"expected_exec_start":producer["ExecStart"],"startup_handoff":private157::binding(&s.startup_handoff),"admission":h["admission"],"observer":a["observer"],"fleet":a["fleet"],"boot_id":a["boot_id"],"resource_samples_taken":0,"ordinary_replay_claim":false,"replay_entries":0,"native_input_qualified":false,"public_sidecar_countdown_authorized":true,"recorded_unix_seconds":now,"sampled_at_utc":publication203::utc(now)?,"capture_spec":private157::binding(&binding),"capture_helper_sha256":self_sha,"producer_start_monotonic_microseconds":text(&producer,"ExecMainStartTimestampMonotonic")?.parse::<u64>()?,"producer":producer});
    c::deny(&mut r);
    ensure!(
        census(&names, 201, 300)? == before,
        "211 peer census changed during capture"
    );
    private157::immutable_receipt(&s.output, &r)?;
    c::claim(&PipelineClaim {
        epoch: 211,
        phase: "private-cold-snapshot-verification".into(),
        unit: c::UNIT.into(),
        invocation_id: text(&r, "invocation_id")?.into(),
        expected_exec_start: text(&r, "expected_exec_start")?.into(),
        evidence: vec![c::binding(&private157::file_binding(&s.output)?)?],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peers_preserve_auxiliaries_and_dormant_history_without_old210_assumptions() {
        let owner = |unit: &str, state: &str, pid: &str| json!({"Id":unit,"LoadState":"loaded","ActiveState":state,"SubState":if state=="active"{"running"}else{"dead"},"InvocationID":"a".repeat(32),"MainPID":pid,"NRestarts":"0","Result":"success","ControlGroup":format!("/system.slice/{unit}"),"ExecStart":"{ path=/sealed/bin ; argv[]=/sealed/bin ; ignore_errors=no }"});
        let replay = owner("replay.service", "active", "42");
        let audit = owner("audit.service", "active", "43");
        let dead = owner("old.service", "inactive", "0");
        let f = json!({"unit_census":{"replay.service":replay,"audit.service":audit,"old.service":dead},"active":[{"epoch":247,"producer":replay}]});
        let current = BTreeMap::from([
            ("replay.service".into(), replay),
            ("audit.service".into(), audit),
            ("old.service".into(), dead),
        ]);
        peers(&f, &current, c::UNIT).unwrap();
        for name in current.keys() {
            let mut bad = current.clone();
            bad.remove(name);
            assert!(peers(&f, &bad, c::UNIT).is_err());
        }
        let mut unknown = current.clone();
        unknown.insert(
            "unknown.service".into(),
            owner("unknown.service", "active", "99"),
        );
        assert!(peers(&f, &unknown, c::UNIT).is_err());
        for field in [
            "InvocationID",
            "MainPID",
            "ActiveState",
            "ControlGroup",
            "ExecStart",
        ] {
            let mut bad = current.clone();
            bad.get_mut("audit.service").unwrap()[field] = json!("changed");
            assert!(peers(&f, &bad, c::UNIT).is_err(), "{field}");
        }
    }
    #[test]
    fn terminal_retention_is_nonactivating() {
        let v = json!({"LoadState":"loaded","ActiveState":"active","SubState":"active","After":c::UNIT,"IgnoreOnIsolate":"yes","DefaultDependencies":"no","DropInPaths":"","Job":"","Wants":"","Requires":"","BindsTo":"","Upholds":""});
        retention_values(&v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(retention_values(&bad).is_err(), "{key}");
        }
    }
}
