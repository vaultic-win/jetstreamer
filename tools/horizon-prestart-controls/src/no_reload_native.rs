//! Opt-in native fixture graph. Never reloads PID1 or addresses a campaign unit.
//! The unchanged qualified guard and sealer are the only campaign artifacts read.
use super::*;

const ROOT: &str = "/var/lib/jetstreamer/horizon265-no-reload-fixture-v1";
const TEST_BINARY: &str =
    "/var/lib/jetstreamer/horizon265-no-reload-fixture-package-v1/horizon-prestart-controls-tests";
const CONTROLLER: &str = "horizon265-no-reload-fixture-controller-v1.service";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const SEALER: &str =
    "/var/lib/jetstreamer/horizon251-published-sealer-20261118-v1/horizon251-sealer";
const SEALER_SHA: &str = "faf7aa8270b3472969bf394d4486cdf94445e30e4f15bc6acd38bed56880877a";
const RETAIN: &str = "horizon265-no-reload-fixture-retention-v1.target";
const VARIABLE: &str = "HORIZON265_GUARD_PLAN_SHA256";
const CASES: [&str; 5] = ["peer-a", "peer-b", "candidate", "missing", "wrong"];
const MARKER_TEST: &str = "no_reload_native::native_fixture_marker";
const DETAIL: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainStartTimestampMonotonic,NRestarts,Restart,Result,ExecMainCode,ExecMainStatus,Job,FragmentPath,DropInPaths,ExecStart,ExecStartPre,EnvironmentFiles,Environment,PassEnvironment,UnsetEnvironment,Type,User,Group,KillMode,Delegate,MemoryMax,MemorySwapMax,TasksMax,ControlGroup";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePlan {
    schema: String,
    test_binary: Bound,
    sleep: Bound,
    test: Bound,
}

fn unit(case: &str, role: &str) -> String {
    if role == "producer" {
        format!("horizon-qualify-265-no-reload-fixture-v1-{case}.service")
    } else {
        format!("horizon265-no-reload-fixture-v1-{case}-guard.{role}")
    }
}
fn leaf(case: &str) -> PathBuf {
    Path::new(ROOT).join(case)
}
fn token_path(case: &str, id: &str) -> PathBuf {
    leaf(case)
        .join("tokens")
        .join(id)
        .join("guard-admission.json")
}
fn mono() -> Result<u64> {
    let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, t.as_mut_ptr()) } == 0,
        "clock"
    );
    let t = unsafe { t.assume_init() };
    Ok(t.tv_sec as u64 * 1_000_000 + t.tv_nsec as u64 / 1_000)
}
fn mkdir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Ok(())
}
fn load_plan() -> Result<(FixturePlan, Bound)> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native fixtures require root"
    );
    let reference = Bound {
        path: env::var("HORIZON_NO_RELOAD_PLAN")?.into(),
        sha256: env::var("HORIZON_NO_RELOAD_PLAN_SHA256")?,
    };
    let p: FixturePlan = serde_json::from_slice(&bytes(&reference, true)?)?;
    ensure!(
        p.schema == "horizon265-isolated-no-reload-native-plan-v1",
        "plan schema"
    );
    ensure!(
        p.test_binary.path == Path::new(TEST_BINARY)
            && p.test_binary.path == env::current_exe()?
            && p.test_binary.sha256 == env::var("HORIZON_NO_RELOAD_SELF_SHA256")?,
        "test image binding"
    );
    // Test harnesses include libtest/debug metadata and may exceed the receipt bound.
    let executable = fs::symlink_metadata(&p.test_binary.path)?;
    ensure!(
        p.test_binary.path.canonicalize()? == p.test_binary.path
            && executable.is_file()
            && executable.uid() == 0
            && executable.nlink() == 1
            && executable.mode() & 0o222 == 0
            && executable.len() <= 64 << 20,
        "test executable custody/size"
    );
    for parent in p.test_binary.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "test executable ancestor"
        );
    }
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == p.test_binary.sha256,
        "test executable hash"
    );
    system_binary(&p.sleep)?;
    system_binary(&p.test)?;
    for (path, sha256) in [(GUARD, GUARD_SHA), (SEALER, SEALER_SHA)] {
        bytes(
            &Bound {
                path: path.into(),
                sha256: sha256.into(),
            },
            true,
        )?;
    }
    Ok((p, reference))
}
fn retention_source() -> String {
    let names: Vec<_> = CASES
        .into_iter()
        .flat_map(|case| {
            ["producer", "service", "timer"]
                .into_iter()
                .map(move |role| unit(case, role))
        })
        .collect();
    format!(
        "[Unit]\nDescription=Nonactivating fixture evidence retention\nDefaultDependencies=no\nIgnoreOnIsolate=yes\nBindsTo={CONTROLLER}\nAfter={CONTROLLER} {}\n",
        names.join(" ")
    )
}
fn source(case: &str, role: &str, binary: &Path) -> String {
    let base = leaf(case).display().to_string();
    let header = format!(
        "[Unit]\nDescription=Isolated late guard argument fixture\nBindsTo={CONTROLLER}\nAfter={CONTROLLER}\nStartLimitIntervalSec=0\n"
    );
    if role == "timer" {
        return format!(
            "{header}[Timer]\nOnActiveSec=1s\nOnUnitInactiveSec=60s\nAccuracySec=1us\nRandomizedDelaySec=0\nUnit={}\n",
            unit(case, "service")
        );
    }
    let isolation = format!(
        "Restart=no\nUser=root\nUMask=0077\nKillMode=control-group\nDelegate=no\nMemorySwapMax=0\nTasksMax=256\nCPUQuota=100%\nTimeoutStopSec=5s\nProtectSystem=strict\nProtectHome=yes\nPrivateNetwork=yes\nNoNewPrivileges=yes\nReadWritePaths={base}/receipts {base}/markers\n"
    );
    if role == "producer" {
        format!(
            "{header}[Service]\nType=exec\n{isolation}MemoryMax=67108864\nTimeoutStartSec=75s\nRuntimeMaxSec=10s\nCapabilityBoundingSet=\nAmbientCapabilities=\nExecStartPre=/usr/bin/sleep 60\nExecStartPre=/usr/bin/test -f {base}/tokens/${{INVOCATION_ID}}/guard-admission.json\nExecStartPre=/usr/bin/test ! -L {base}/tokens/${{INVOCATION_ID}}/guard-admission.json\nExecStart={} --exact {MARKER_TEST} --ignored --nocapture\n",
            binary.display()
        )
    } else {
        format!(
            "{header}[Service]\nType=oneshot\n{isolation}MemoryMax=1073741824\nTimeoutStartSec=10s\nEnvironmentFile={base}/binding/guard.env\nExecStart={GUARD} {base}/binding/guard-plan.json --plan-sha256 ${{{VARIABLE}}} --self-sha256 {GUARD_SHA}\n"
        )
    }
}

struct Native {
    receipt_root: PathBuf,
    written: usize,
    serial: u32,
    deadline: Instant,
}
impl Native {
    fn new() -> Self {
        Self {
            receipt_root: PathBuf::from(ROOT),
            written: 0,
            serial: 0,
            deadline: Instant::now() + Duration::from_secs(150),
        }
    }
    fn save(&mut self, label: &str, value: &Value) -> Result<()> {
        self.serial += 1;
        ensure!(self.serial <= 2000, "fixture receipt count");
        let raw = serde_json::to_vec_pretty(value)?;
        ensure!(raw.len() <= 1 << 20, "fixture receipt size");
        self.written += raw.len();
        ensure!(self.written <= 16 << 20, "fixture aggregate receipt bound");
        write_new(
            &self
                .receipt_root
                .join(format!("{:04}-{label}.json", self.serial)),
            &raw,
            0o600,
        )
    }
    fn command(&mut self, program: &str, args: &[&str]) -> Result<Vec<u8>> {
        ensure!(Instant::now() < self.deadline, "fixture wall deadline");
        let raw = raw_command(program, args)?;
        self.save("command", &json!({"program":program,"argv":args,"stdout":std::str::from_utf8(&raw)?,"monotonic_us":mono()?}))?;
        Ok(raw)
    }
    fn system(&mut self, args: &[&str]) -> Result<()> {
        self.command("/usr/bin/systemctl", args).map(|_| ())
    }
    fn show(&mut self, name: &str) -> Result<BTreeMap<String, String>> {
        parse_properties(&self.command(
            "/usr/bin/systemctl",
            &[
                "show",
                name,
                &format!("--property={DETAIL},Unit,NextElapseUSecMonotonic"),
            ],
        )?)
    }
    fn next(&mut self, name: &str) -> Result<u64> {
        let escaped: String = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_string()
                } else {
                    format!("_{:02x}", c as u32)
                }
            })
            .collect();
        let raw = self.command(
            "/usr/bin/busctl",
            &[
                "get-property",
                "org.freedesktop.systemd1",
                &format!("/org/freedesktop/systemd1/unit/{escaped}"),
                "org.freedesktop.systemd1.Timer",
                "NextElapseUSecMonotonic",
            ],
        )?;
        let words: Vec<_> = std::str::from_utf8(&raw)?.split_whitespace().collect();
        ensure!(words.len() == 2 && words[0] == "t", "typed timer deadline");
        Ok(words[1].parse()?)
    }
    fn journal(&mut self, name: &str, id: &str) -> Result<Vec<Value>> {
        let raw = self.command(
            "/usr/bin/journalctl",
            &[
                "--all",
                "--no-pager",
                "--output=json",
                "_PID=1",
                &format!("UNIT={name}"),
                &format!("INVOCATION_ID={id}"),
            ],
        )?;
        let events: Vec<Value> = std::str::from_utf8(&raw)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        ensure!(!events.is_empty() && events.len() < 32, "PID1 event bounds");
        for r in &events {
            ensure!(
                r["_PID"] == "1"
                    && r["_UID"] == "0"
                    && r["UNIT"] == name
                    && r["INVOCATION_ID"] == id,
                "PID1 event identity"
            );
        }
        Ok(events)
    }
}
fn assert_pre(v: &BTreeMap<String, String>, id: &str) -> Result<()> {
    ensure!(
        iid(id)
            && row(v, "InvocationID")? == id
            && row(v, "ActiveState")? == "activating"
            && row(v, "SubState")? == "start-pre"
            && row(v, "MainPID")? == "0"
            && row(v, "ExecMainPID")? == "0"
            && row(v, "ExecMainStartTimestampMonotonic")? == "0"
            && row(v, "NRestarts")? == "0"
            && row(v, "ControlPID")?.parse::<u32>()? > 1,
        "producer escaped native prestart gate"
    );
    Ok(())
}
fn guard_contract(v: &BTreeMap<String, String>, case: &str, pristine: bool) -> Result<()> {
    let command = row(v, "ExecStart")?
        .split_once(" ; start_time=")
        .context("PID1 ExecStart framing")?
        .0;
    let expected = format!(
        "{{ path={GUARD} ; argv[]={GUARD} {}/binding/guard-plan.json --plan-sha256 ${{{VARIABLE}}} --self-sha256 {GUARD_SHA} ; ignore_errors=no",
        leaf(case).display()
    );
    ensure!(
        command == expected && row(v, "ExecStart")?.matches("{ path=").count() == 1,
        "direct braced argument contract"
    );
    for (k, want) in [
        ("Environment", ""),
        ("PassEnvironment", ""),
        ("UnsetEnvironment", ""),
        ("DropInPaths", ""),
        ("Type", "oneshot"),
        ("User", "root"),
        ("Group", ""),
        ("Restart", "no"),
        ("MemoryMax", "1073741824"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "256"),
    ] {
        ensure!(row(v, k)? == want, "guard {k} differs");
    }
    ensure!(
        row(v, "EnvironmentFiles")?
            == format!(
                "{}/binding/guard.env (ignore_errors=no)",
                leaf(case).display()
            ),
        "mandatory exact env file"
    );
    if pristine {
        ensure!(
            row(v, "InvocationID")?.is_empty()
                && row(v, "ActiveState")? == "inactive"
                && row(v, "SubState")? == "dead"
                && row(v, "Job")?.is_empty(),
            "consumed guard namespace"
        );
    }
    Ok(())
}
fn start_producer(n: &mut Native, case: &str) -> Result<String> {
    n.system(&["start", "--no-block", &unit(case, "producer")])?;
    let v = wait_for(Instant::now() + Duration::from_secs(3), || {
        let v = n.show(&unit(case, "producer"))?;
        if row(&v, "SubState")? == "start-pre" {
            Ok(Some(v))
        } else {
            Ok(None)
        }
    })?;
    let id = row(&v, "InvocationID")?.to_owned();
    assert_pre(&v, &id)?;
    absent(&token_path(case, &id))?;
    Ok(id)
}
fn seal_binding(n: &mut Native, case: &str, id: &str, wrong: bool) -> Result<Bound> {
    let base = leaf(case);
    let value = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":unit(case,"producer"),"invocation_id":id,"filesystem":"/","minimum_free_bytes":1,"worker_root":base.join("worker"),"maximum_worker_vmas":3500000,"maximum_root_physical_bytes":67108864,"receipt_directory":base.join("receipts")});
    let raw = serde_json::to_vec_pretty(&value)?;
    let plan_sha = digest(&raw);
    let env = format!(
        "{VARIABLE}={}\n",
        if wrong {
            "0".repeat(64)
        } else {
            plan_sha.clone()
        }
    );
    let mut members = Vec::new();
    for (name, raw) in [("guard-plan.json", raw), ("guard.env", env.into_bytes())] {
        let src = base.join(format!("source-{name}"));
        write_new(&src, &raw, 0o444)?;
        members.push(json!({"source":src,"name":name,"sha256":digest(&raw),"mode":292}));
    }
    let plan = serde_json::to_vec_pretty(
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":base.join("binding"),"members":members}),
    )?;
    let seal_plan = base.join("seal-plan.json");
    write_new(&seal_plan, &plan, 0o444)?;
    n.command(
        SEALER,
        &[
            seal_plan.to_str().context("seal plan path")?,
            "--plan-sha256",
            &digest(&plan),
            "--self-sha256",
            SEALER_SHA,
        ],
    )?;
    let bound = Bound {
        path: base.join("binding/guard-plan.json"),
        sha256: plan_sha,
    };
    bytes(&bound, true)?;
    let env_bound = Bound {
        path: base.join("binding/guard.env"),
        sha256: digest(&fs::read(base.join("source-guard.env"))?),
    };
    bytes(&env_bound, true)?;
    Ok(bound)
}
fn first_guard(n: &mut Native, case: &str, id: &str, plan: &Bound) -> Result<Value> {
    n.system(&["start", &unit(case, "timer")])?;
    let g = wait_for(Instant::now() + Duration::from_secs(8), || {
        let v = n.show(&unit(case, "service"))?;
        if iid(row(&v, "InvocationID")?)
            && row(&v, "ActiveState")? == "inactive"
            && row(&v, "SubState")? == "dead"
        {
            Ok(Some(v))
        } else {
            ensure!(row(&v, "ActiveState")? != "failed", "fixture guard failed");
            Ok(None)
        }
    })?;
    guard_contract(&g, case, false)?;
    ensure!(
        row(&g, "Result")? == "success"
            && row(&g, "ExecMainCode")? == "1"
            && row(&g, "ExecMainStatus")? == "0"
            && row(&g, "MainPID")? == "0"
            && row(&g, "ControlPID")? == "0"
            && row(&g, "Job")?.is_empty(),
        "guard completion"
    );
    let gid = row(&g, "InvocationID")?;
    let path = leaf(case)
        .join("receipts")
        .join(format!("sample-{gid}.json"));
    let sample: Value = serde_json::from_slice(&bytes(
        &Bound {
            path,
            sha256: digest(&fs::read(
                leaf(case)
                    .join("receipts")
                    .join(format!("sample-{gid}.json")),
            )?),
        },
        false,
    )?)?;
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && sample["producer_invocation_id"] == id
            && sample["guard_invocation_id"] == gid
            && sample["plan"] == plan.path.to_string_lossy().as_ref()
            && sample["plan_sha256"] == plan.sha256
            && sample["guard_sha256"] == GUARD_SHA
            && sample["producer_stop_enabled"] == true,
        "real guard binding"
    );
    ensure!(
        sample["workers"] == json!([])
            && sample["producer"]["pid"] == 0
            && sample["producer"]["active"] == "activating"
            && sample["producer"]["sub"] == "start-pre"
            && sample["minimum_free_bytes"] == 1
            && sample["maximum_root_physical_bytes"] == 67108864
            && sample["maximum_worker_vmas"] == 3500000,
        "first sample prestart envelope"
    );
    for k in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(sample.get(k) == Some(&Value::Null), "guard error {k}");
    }
    let events = n.journal(&unit(case, "service"), gid)?;
    ensure!(
        events.iter().any(|r| r["JOB_TYPE"] == "start"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Starting ")))
            && events.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.ends_with("Deactivated successfully.")))
            && events.iter().any(|r| r["JOB_RESULT"] == "done"),
        "actual first PID1 lifecycle"
    );
    assert_pre(&n.show(&unit(case, "producer"))?, id)?;
    absent(&token_path(case, id))?;
    ensure!(
        fs::read_dir(leaf(case).join("markers"))?.next().is_none(),
        "marker preceded token"
    );
    bytes(plan, true)?;
    let expected_env = format!("{VARIABLE}={}\n", plan.sha256);
    bytes(
        &Bound {
            path: leaf(case).join("binding/guard.env"),
            sha256: digest(expected_env.as_bytes()),
        },
        true,
    )?;
    n.save(
        "first-guard",
        &json!({"case":case,"sample":sample,"PID1":events,"properties":g}),
    )?;
    Ok(sample)
}
fn peer_snapshot(n: &mut Native, case: &str) -> Result<Value> {
    let g = n.show(&unit(case, "service"))?;
    let t = n.show(&unit(case, "timer"))?;
    ensure!(
        iid(row(&g, "InvocationID")?)
            && row(&g, "ActiveState")? == "inactive"
            && row(&g, "SubState")? == "dead"
            && row(&g, "Result")? == "success"
            && row(&g, "Job")?.is_empty()
            && row(&t, "ActiveState")? == "active"
            && row(&t, "SubState")? == "waiting"
            && iid(row(&t, "InvocationID")?)
            && row(&t, "Job")?.is_empty()
            && row(&t, "Unit")? == unit(case, "service"),
        "retained fixture pair not clean"
    );
    let next = n.next(&unit(case, "timer"))?;
    Ok(json!({"guard":g,"timer":t,"next_monotonic_us":next}))
}
fn stop_all(n: &mut Native, p: &FixturePlan) -> Result<()> {
    // Validate every exact link/source before acting; never wildcard unit names.
    for role in ["timer", "service", "producer"] {
        for case in CASES {
            let name = unit(case, role);
            let link = Path::new("/run/systemd/system").join(&name);
            if !link.try_exists()? {
                continue;
            }
            ensure!(
                fs::read_link(&link)? == Path::new(ROOT).join("units").join(&name),
                "cleanup foreign link"
            );
            ensure!(
                fs::read(&link)? == source(case, role, &p.test_binary.path).as_bytes(),
                "cleanup source changed"
            );
            n.system(&["stop", &name])?;
            if role != "timer" {
                drained(&name)?;
            }
        }
    }
    let retained = Path::new("/run/systemd/system").join(RETAIN);
    if retained.try_exists()? {
        ensure!(
            fs::read_link(&retained)? == Path::new(ROOT).join("units").join(RETAIN)
                && fs::read(&retained)? == retention_source().as_bytes(),
            "cleanup foreign retention"
        );
        n.system(&["stop", RETAIN])?;
    }
    Ok(())
}

fn run_fixture(p: &FixturePlan, reference: &Bound) -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{CONTROLLER}"),
        "must run in exact bounded fixture controller"
    );
    absent(Path::new(ROOT))?;
    absent(&Path::new("/run/systemd/system").join(RETAIN))?;
    for case in CASES {
        for role in ["producer", "service", "timer"] {
            absent(&Path::new("/run/systemd/system").join(unit(case, role)))?;
        }
    }
    mkdir(Path::new(ROOT))?;
    let mut n = Native::new();
    let result = (|| -> Result<()> {
        n.save("plan", &json!({"path":reference.path,"sha256":reference.sha256,"test_binary_sha256":p.test_binary.sha256,"replay_launch_authorized":false}))?;
        mkdir(&Path::new(ROOT).join("units"))?;
        for case in CASES {
            mkdir(&leaf(case))?;
            for name in ["worker", "receipts", "tokens", "markers"] {
                mkdir(&leaf(case).join(name))?;
            }
            for role in ["producer", "service", "timer"] {
                let name = unit(case, role);
                let path = Path::new(ROOT).join("units").join(&name);
                write_new(
                    &path,
                    source(case, role, &p.test_binary.path).as_bytes(),
                    0o444,
                )?;
                symlink(&path, Path::new("/run/systemd/system").join(&name))?;
            }
        }
        let retained = Path::new(ROOT).join("units").join(RETAIN);
        write_new(&retained, retention_source().as_bytes(), 0o444)?;
        symlink(&retained, Path::new("/run/systemd/system").join(RETAIN))?;
        File::open("/run/systemd/system")?.sync_all()?;
        // New names are loaded on demand. Failure is evidence, never a reason to reload PID1.
        for case in CASES {
            for role in ["producer", "service", "timer"] {
                let name = unit(case, role);
                let v = n.show(&name)?;
                ensure!(
                    row(&v, "LoadState")? == "loaded"
                        && row(&v, "InvocationID")?.is_empty()
                        && row(&v, "DropInPaths")?.is_empty()
                        && row(&v, "ActiveState")? == "inactive"
                        && row(&v, "Job")?.is_empty(),
                    "fresh fixture did not load pristine"
                );
                ensure!(
                    Path::new(row(&v, "FragmentPath")?).canonicalize()?
                        == Path::new(ROOT).join("units").join(&name),
                    "fixture fragment path"
                );
                if role == "service" {
                    guard_contract(&v, case, true)?;
                }
            }
            absent(&leaf(case).join("binding"))?;
        }
        n.system(&["start", RETAIN])?;
        for case in CASES {
            let v = n.show(&unit(case, "producer"))?;
            ensure!(
                row(&v, "InvocationID")?.is_empty() && row(&v, "ActiveState")? == "inactive",
                "retention activated producer"
            );
        }
        let prepared = now()?;
        n.save("prepared", &json!({"recorded_unix_seconds":prepared,"all_static_units_loaded":true,"all_argument_files_absent":true,"daemon_reload_used":false}))?;
        for case in ["peer-a", "peer-b"] {
            let id = start_producer(&mut n, case)?;
            let binding = seal_binding(&mut n, case, &id, false)?;
            first_guard(&mut n, case, &id, &binding)?;
        }
        ensure!(
            now()? > prepared,
            "fresh admission must follow preparation by a whole second"
        );
        let peers = [
            peer_snapshot(&mut n, "peer-a")?,
            peer_snapshot(&mut n, "peer-b")?,
        ];
        let accepted = mono()?;
        let earliest = peers
            .iter()
            .map(|p| p["next_monotonic_us"].as_u64().context("peer deadline"))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .min()
            .context("no peers")?;
        ensure!(
            earliest >= accepted + 30_000_000,
            "original retained window shorter than 30 seconds"
        );
        n.save("original-window", &json!({"peers":peers,"accepted_monotonic_us":accepted,"original_expiry_monotonic_us":earliest-5_000_000,"prepared_unix_seconds":prepared,"admission_unix_seconds":now()?}))?;
        let id = start_producer(&mut n, "candidate")?;
        let binding = seal_binding(&mut n, "candidate", &id, false)?;
        let sample = first_guard(&mut n, "candidate", &id, &binding)?;
        for (i, case) in ["peer-a", "peer-b"].into_iter().enumerate() {
            ensure!(
                peer_snapshot(&mut n, case)? == peers[i],
                "retained fixture peer rolled over"
            );
        }
        let before_token = mono()?;
        ensure!(
            before_token < earliest - 5_000_000 && before_token < accepted + 50_000_000,
            "original lease/setup window elapsed"
        );
        assert_pre(&n.show(&unit("candidate", "producer"))?, &id)?;
        let token_dir = leaf("candidate").join("tokens").join(&id);
        mkdir(&token_dir)?;
        ensure!(
            mono()? < earliest - 5_000_000 && mono()? < accepted + 50_000_000,
            "lease expired immediately before token"
        );
        write_new(
            &token_path("candidate", &id),
            &serde_json::to_vec(
                &json!({"schema":"horizon265-isolated-real-first-guard-token-v1","actual_invocation_id":id,"first_guard_sample":sample,"original_window_monotonic_us":accepted,"replay_launch_authorized":false}),
            )?,
            0o444,
        )?;
        n.save("token-published", &json!({"producer_invocation_id":id,"peers":peers,"monotonic_us":before_token,"no_unit_mutation_after_admission":true}))?;
        // The measured peer window is complete. Retire fixture peers before their next firing.
        for case in ["peer-a", "peer-b"] {
            n.system(&["stop", &unit(case, "timer")])?;
            n.system(&["stop", &unit(case, "producer")])?;
            drained(&unit(case, "producer"))?;
        }
        n.system(&["stop", &unit("candidate", "timer")])?;
        // Native negative cases run in distinct producers with no token, concurrently.
        let mut negatives = Vec::new();
        for case in ["missing", "wrong"] {
            let bad_id = start_producer(&mut n, case)?;
            if case == "wrong" {
                seal_binding(&mut n, case, &bad_id, true)?;
            }
            n.system(&["start", "--no-block", &unit(case, "service")])?;
            let failed = wait_for(Instant::now() + Duration::from_secs(8), || {
                let v = n.show(&unit(case, "service"))?;
                if row(&v, "ActiveState")? == "failed" {
                    Ok(Some(v))
                } else {
                    Ok(None)
                }
            })?;
            ensure!(
                row(&failed, "Result")? != "success",
                "negative guard succeeded"
            );
            let gid = row(&failed, "InvocationID")?;
            ensure!(iid(gid), "negative guard lacks actual invocation");
            if case == "wrong" {
                ensure!(
                    row(&failed, "ExecMainPID")?.parse::<u32>()? > 1
                        && row(&failed, "ExecMainCode")? == "1"
                        && row(&failed, "ExecMainStatus")? != "0",
                    "wrong digest did not reach direct guard"
                );
                let raw = n.command(
                    "/usr/bin/journalctl",
                    &[
                        "--all",
                        "--no-pager",
                        "--output=json",
                        &format!("_SYSTEMD_UNIT={}", unit(case, "service")),
                        &format!("_SYSTEMD_INVOCATION_ID={gid}"),
                    ],
                )?;
                let events: Vec<Value> = std::str::from_utf8(&raw)?
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<std::result::Result<_, _>>()?;
                ensure!(
                    events.iter().any(|e| e["MESSAGE"]
                        .as_str()
                        .is_some_and(|m| m.contains("guard plan digest mismatch"))),
                    "wrong-digest failure reason not proved"
                );
            } else {
                ensure!(
                    row(&failed, "ExecMainPID")? == "0"
                        && row(&failed, "ExecMainStartTimestampMonotonic")? == "0",
                    "missing env reached guard executable"
                );
                let events = n.journal(&unit(case, "service"), gid)?;
                ensure!(
                    events.iter().any(|e| e["MESSAGE"]
                        .as_str()
                        .is_some_and(|m| m.contains("environment files"))),
                    "missing-environment failure reason not proved"
                );
            }
            assert_pre(&n.show(&unit(case, "producer"))?, &bad_id)?;
            absent(&token_path(case, &bad_id))?;
            ensure!(
                fs::read_dir(leaf(case).join("receipts"))?.next().is_none(),
                "negative guard wrote a successful sample"
            );
            n.save("negative-guard",&json!({"case":case,"guard":failed,"producer_invocation_id":bad_id,"no_token":true}))?;
            negatives.push((case, bad_id));
        }
        let complete = wait_for(n.deadline, || {
            let v = n.show(&unit("candidate", "producer"))?;
            if row(&v, "ActiveState")? == "inactive" && row(&v, "SubState")? == "dead" {
                Ok(Some(v))
            } else {
                ensure!(
                    row(&v, "ActiveState")? != "failed",
                    "candidate marker failed"
                );
                Ok(None)
            }
        })?;
        ensure!(
            row(&complete, "InvocationID")? == id
                && row(&complete, "Result")? == "success"
                && row(&complete, "ExecMainStatus")? == "0"
                && row(&complete, "ExecMainPID")?.parse::<u32>()? > 1
                && row(&complete, "NRestarts")? == "0",
            "marker terminal identity"
        );
        let marker: Value = serde_json::from_slice(&fs::read(
            leaf("candidate").join("markers").join(format!("{id}.json")),
        )?)?;
        ensure!(
            marker["invocation_id"] == id
                && marker["pid"].as_u64() == Some(row(&complete, "ExecMainPID")?.parse()?)
                && marker["monotonic_us"].as_u64().context("marker clock")? > before_token,
            "real marker identity/order"
        );
        for (case, bad_id) in negatives {
            let failed = wait_for(n.deadline, || {
                let v = n.show(&unit(case, "producer"))?;
                if row(&v, "ActiveState")? == "failed" {
                    Ok(Some(v))
                } else {
                    Ok(None)
                }
            })?;
            ensure!(
                row(&failed, "InvocationID")? == bad_id
                    && row(&failed, "ExecMainPID")? == "0"
                    && row(&failed, "ExecMainStartTimestampMonotonic")? == "0"
                    && row(&failed, "NRestarts")? == "0",
                "negative crossed useful-work gate"
            );
            ensure!(
                fs::read_dir(leaf(case).join("markers"))?.next().is_none(),
                "negative marker exists"
            );
            absent(&token_path(case, &bad_id))?;
            n.save(
                "negative-producer",
                &json!({"case":case,"terminal":failed,"marker_absent":true}),
            )?;
        }
        n.save("qualification",&json!({"schema":"horizon265-isolated-no-reload-native-qualification-v1","plan_sha256":reference.sha256,"test_binary_sha256":p.test_binary.sha256,"actual_guard_sha256":GUARD_SHA,"preloaded_static_graph_with_missing_environment":true,"actual_late_braced_digest_expansion":true,"two_retained_peer_pairs_unchanged_during_original_window":true,"real_first_guard_before_token":true,"real_token_before_useful_marker":true,"missing_environment_blocks_useful_work":true,"wrong_digest_blocks_useful_work":true,"daemon_reload_used":false,"actual_candidate_startup_qualified":false,"replay_launch_authorized":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false,"marker":marker,"terminal":complete}))?;
        Ok(())
    })();
    n.deadline = Instant::now() + Duration::from_secs(45);
    let cleanup = stop_all(&mut n, p);
    n.save("outcome",&json!({"result":result.as_ref().err().map(ToString::to_string),"stop_and_drain_error":cleanup.as_ref().err().map(ToString::to_string),"receipts_retained":true}))?;
    result?;
    cleanup
}

#[test]
#[ignore = "root native PID1 fixture graph; sealed plan and bounded exact controller required"]
fn native_late_environment_binding_retains_peer_windows() {
    let (p, reference) = load_plan().unwrap();
    run_fixture(&p, &reference).unwrap();
}
#[test]
#[ignore = "internal real PID1 useful marker; never invoke manually"]
fn native_fixture_marker() {
    let run = || -> Result<()> {
        ensure!(unsafe { libc::geteuid() } == 0, "fixture marker uid");
        let id = env::var("INVOCATION_ID")?;
        ensure!(iid(&id), "fixture marker IID");
        let group = fs::read_to_string("/proc/self/cgroup")?;
        let case = CASES
            .into_iter()
            .find(|case| group.trim() == format!("0::/system.slice/{}", unit(case, "producer")))
            .context("fixture marker cgroup")?;
        let token = token_path(case, &id);
        let raw = fs::read(&token)?;
        let m = fs::symlink_metadata(&token)?;
        ensure!(
            m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o222 == 0,
            "fixture token custody"
        );
        let value: Value = serde_json::from_slice(&raw)?;
        ensure!(
            value["actual_invocation_id"] == id && value["replay_launch_authorized"] == false,
            "fixture token binding"
        );
        write_new(
            &leaf(case).join("markers").join(format!("{id}.json")),
            &serde_json::to_vec(
                &json!({"schema":"horizon265-no-reload-real-marker-v1","invocation_id":id,"pid":std::process::id(),"monotonic_us":mono()?,"token_sha256":digest(&raw),"replay_launch_authorized":false}),
            )?,
            0o600,
        )
    };
    run().unwrap();
}
#[test]
#[ignore = "explicit fixture-only stop/drain; preserves all source and receipts, no reload"]
fn native_cleanup_fixture_units() {
    let (p, _) = load_plan().unwrap();
    let cleanup_root = Path::new(ROOT).join("cleanup-v1");
    mkdir(&cleanup_root).unwrap();
    let mut n = Native::new();
    n.receipt_root = cleanup_root;
    stop_all(&mut n, &p).unwrap();
    // Remove only the already validated fixture links. Preserve every source/receipt.
    let names = CASES
        .into_iter()
        .flat_map(|case| {
            ["producer", "service", "timer"]
                .into_iter()
                .map(move |role| unit(case, role))
        })
        .chain(std::iter::once(RETAIN.to_string()));
    for name in names {
        let link = Path::new("/run/systemd/system").join(&name);
        match fs::symlink_metadata(&link) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => panic!("fixture cleanup stat: {e}"),
            Ok(_) => {}
        }
        assert_eq!(
            fs::read_link(&link).unwrap(),
            Path::new(ROOT).join("units").join(&name)
        );
        fs::remove_file(&link).unwrap();
    }
    File::open("/run/systemd/system")
        .unwrap()
        .sync_all()
        .unwrap();
    n.save("cleanup-complete", &json!({"all_fixture_units_stopped_and_drained":true,"fixture_links_unlinked":true,"daemon_reload_used":false,"receipts_retained":true})).unwrap();
}
#[test]
fn native_fixture_graph_has_only_disjoint_bounded_units() {
    for case in CASES {
        for role in ["producer", "service", "timer"] {
            let text = source(case, role, Path::new("/sealed/test-binary"));
            assert!(text.contains(&format!("BindsTo={CONTROLLER}")));
            assert!(!text.contains("daemon-reload"));
            assert!(!text.contains("jetstreamer-node"));
            if role == "producer" {
                gate_lines(&text, &format!("{}/tokens", leaf(case).display())).unwrap();
            }
        }
    }
}
