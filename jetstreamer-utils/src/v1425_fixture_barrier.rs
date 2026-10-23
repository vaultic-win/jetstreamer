//! Closed fixture-only pre-exec release barrier. No campaign or remote authority.
use super::*;
use std::os::unix::process::CommandExt;

#[cfg(not(barrier_disposable))]
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-v1425-fixture-barrier-20261023-v1";
#[cfg(barrier_disposable)]
const PACKAGE: &str = "/usr/local/lib/jetstreamer/horizon-v1425-barrier-disposable-20261023-v2";
#[cfg(not(barrier_disposable))]
const EXE: &str = "/usr/local/lib/jetstreamer/horizon-v1425-native-portability-tests-20261023-v3/native-portability-tests";
#[cfg(not(barrier_disposable))]
const EXE_SHA: &str = "7d0678d3d1edf4f75240bc7d7a800fd1093d61ef3ae7a77fe1348ed74425c539";
#[cfg(barrier_disposable)]
const EXE: &str =
    "/usr/local/lib/jetstreamer/horizon-v1425-barrier-disposable-probe-20261023-v1/probe";
#[cfg(not(barrier_disposable))]
const STATE: &str = "/var/lib/jetstreamer-v1425-fixture-barrier-20261023-v1";
#[cfg(barrier_disposable)]
const STATE: &str = "/var/lib/jetstreamer-v1425-barrier-disposable-20261023-v1";
#[cfg(not(barrier_disposable))]
const WATCH: &str = "horizon-v1425-fixture-barrier-watch-20261023-v1.service";
#[cfg(barrier_disposable)]
const WATCH: &str = "horizon-v1425-barrier-disposable-watch-20261023-v1.service";

fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn fields(v: &Value, keys: &[&str]) -> Result<()> {
    let m = v.as_object().context("expected object")?;
    ensure!(
        m.len() == keys.len() && m.keys().all(|k| keys.contains(&k.as_str())),
        "unknown/missing field"
    );
    Ok(())
}
fn trusted_dir(p: &Path, readable: bool) -> Result<()> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == if readable { 0o755 } else { 0o700 },
        "unsafe barrier directory"
    );
    Ok(())
}
fn root_bytes(p: &Path, maximum: u64) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= maximum,
        "unsafe immutable barrier file"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(p)?;
    let before = f.metadata()?;
    ensure!(
        before.dev() == m.dev() && before.ino() == m.ino(),
        "barrier file replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut f)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(p)?;
    ensure!(
        bytes.len() as u64 <= maximum
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "barrier file changed"
    );
    Ok(bytes)
}
fn executable(p: &str, expected: &str) -> Result<()> {
    ensure!(
        digest(expected, 64) && sha(&root_bytes(Path::new(p), 64 << 20)?) == expected,
        "executable hash mismatch"
    );
    Ok(())
}
fn args() -> Vec<&'static str> {
    #[cfg(not(barrier_disposable))]
    {
        vec!["--ignored", "--exact", "runtime::checkpoint_portability_fixture::native_v12_fresh_process_raw_output_equivalence", "--nocapture", "--test-threads=1"]
    }
    #[cfg(barrier_disposable)]
    {
        vec!["--disposable-exec-proof"]
    }
}
fn launch(v: &Value, self_sha: &str) -> Result<()> {
    fields(
        v,
        &[
            "schema",
            "barrier_sha256",
            "fixture_exe",
            "fixture_sha256",
            "wait_seconds",
            "fixture_root",
            "unit",
            "state",
        ],
    )?;
    ensure!(
        v["schema"] == "jetstreamer-v1425-fixture-barrier-launch-v1"
            && v["barrier_sha256"] == self_sha
            && v["fixture_exe"] == EXE
            && v["fixture_root"] == FIXTURE_ROOT
            && v["unit"] == FIXTURE_UNIT
            && v["state"] == STATE
            && v["wait_seconds"]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= 120),
        "foreign launch scope or timeout"
    );
    #[cfg(not(barrier_disposable))]
    ensure!(
        v["fixture_sha256"] == EXE_SHA && v["wait_seconds"] == 120,
        "foreign production fixture hash/wait"
    );
    executable(EXE, s(v, "fixture_sha256")?)?;
    Ok(())
}
fn proc_start(pid: u32) -> Result<String> {
    let st = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, tail) = st.rsplit_once(") ").context("process stat")?;
    let start = tail
        .split_whitespace()
        .nth(19)
        .context("process startticks")?;
    ensure!(
        start.parse::<u64>().is_ok_and(|n| n > 0),
        "bad process startticks"
    );
    Ok(start.into())
}
fn proc_exe(pid: u32) -> Result<(String, String, Vec<String>)> {
    let path = format!("/proc/{pid}");
    let exe = fs::read_link(format!("{path}/exe"))?
        .to_str()
        .context("exe encoding")?
        .to_owned();
    let hash = sha(&fs::read(format!("{path}/exe"))?);
    let bytes = fs::read(format!("{path}/cmdline"))?;
    ensure!(
        bytes.len() <= 8192 && bytes.last() == Some(&0),
        "process command bounds"
    );
    let command = bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
        .collect::<Result<Vec<_>>>()?;
    Ok((exe, hash, command))
}
fn manager(name: &str) -> Result<Value> {
    ensure!(
        name == FIXTURE_UNIT || name == WATCH,
        "foreign barrier unit"
    );
    let output = Command::new("/usr/bin/systemctl").args(["show", name, "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,ExecMainStartTimestampMonotonic,Result,ExecMainStatus,UMask,Job,ExecStart"]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16384,
        "barrier manager probe"
    );
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&output.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("manager property")?;
        ensure!(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate property"
        );
    }
    Ok(Value::Object(map))
}
fn running(v: &Value, name: &str, iid: &str, pid: u32, monotonic: &str) -> Result<()> {
    owned(v, name, iid, monotonic)?;
    ensure!(
        v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"] == pid.to_string()
            && v["Job"] == "",
        "target absent or terminal"
    );
    Ok(())
}
fn watch_plan(v: &Value, launch_sha: &str) -> Result<()> {
    fields(
        v,
        &[
            "schema",
            "launch_sha256",
            "fixture_iid",
            "fixture_pid",
            "fixture_startticks",
            "fixture_start_monotonic",
        ],
    )?;
    ensure!(
        v["schema"] == "jetstreamer-v1425-fixture-barrier-watch-v1"
            && v["launch_sha256"] == launch_sha
            && digest(s(v, "fixture_iid")?, 32)
            && v["fixture_pid"]
                .as_u64()
                .is_some_and(|n| n > 1 && n <= u32::MAX as u64)
            && s(v, "fixture_startticks")?
                .parse::<u64>()
                .is_ok_and(|n| n > 0)
            && s(v, "fixture_start_monotonic")?
                .parse::<u64>()
                .is_ok_and(|n| n > 0),
        "invalid watch binding"
    );
    Ok(())
}
fn pid(v: &Value) -> u32 {
    v["fixture_pid"].as_u64().unwrap() as u32
}
fn command(
    mode: &str,
    launch_sha: &str,
    self_sha: &str,
    watch: Option<(&str, &str)>,
) -> Vec<String> {
    let mut a = vec![
        format!("{PACKAGE}/barrier"),
        mode.into(),
        format!("{PACKAGE}/launch.json"),
        "--launch-sha256".into(),
        launch_sha.into(),
        "--self-sha256".into(),
        self_sha.into(),
    ];
    if let Some((p, h)) = watch {
        a.extend([p.into(), h.into()]);
    }
    a
}
fn fixture_process(
    v: &Value,
    l: &Value,
    launch_sha: &str,
    self_sha: &str,
    allow_exec: bool,
) -> Result<()> {
    let p = pid(v);
    let unit = manager(FIXTURE_UNIT)?;
    configured_command(
        &unit,
        &command("barrier-launch", launch_sha, self_sha, None),
    )?;
    running(
        &unit,
        FIXTURE_UNIT,
        s(v, "fixture_iid")?,
        p,
        s(v, "fixture_start_monotonic")?,
    )?;
    ensure!(
        proc_start(p)? == s(v, "fixture_startticks")?,
        "fixture PID reused"
    );
    let (exe, hash, argv) = proc_exe(p)?;
    let launcher = exe == format!("{PACKAGE}/barrier")
        && hash == self_sha
        && argv == command("barrier-launch", launch_sha, self_sha, None);
    let mut fixture_args = vec![EXE.to_owned()];
    fixture_args.extend(args().into_iter().map(str::to_owned));
    let fixture =
        allow_exec && exe == EXE && hash == s(l, "fixture_sha256")? && argv == fixture_args;
    if fixture {
        let t: Value = serde_json::from_slice(&root_bytes(
            Path::new(&token_path(s(v, "fixture_iid")?)),
            1 << 20,
        )?)?;
        token_valid(
            &t,
            s(v, "fixture_iid")?,
            p,
            s(v, "fixture_startticks")?,
            launch_sha,
            s(l, "fixture_sha256")?,
        )?;
        ensure!(
            t["first_sample_sha256"]
                == sha(&root_bytes(
                    Path::new(&first_path(s(v, "fixture_iid")?)),
                    1 << 20
                )?),
            "unauthenticated exec transition"
        );
    }
    ensure!(
        launcher || fixture,
        "unexpected fixture process/command transition"
    );
    Ok(())
}
fn configured_command(unit: &Value, argv: &[String]) -> Result<()> {
    let configured = s(unit, "ExecStart")?;
    let expected = format!(
        "{{ path={PACKAGE}/barrier ; argv[]={} ; ignore_errors=no ;",
        argv.join(" ")
    );
    ensure!(
        configured.starts_with(&expected)
            && configured.matches("{ path=").count() == 1
            && configured.matches("argv[]=").count() == 1,
        "configured ExecStart differs from sealed command"
    );
    Ok(())
}
fn first_path(iid: &str) -> String {
    format!("{STATE}/receipts/{iid}/first-no-trip.json")
}
fn token_path(iid: &str) -> String {
    format!("{STATE}/gate/{iid}.release.json")
}
fn sample_no_trip() -> Result<Value> {
    closed_fixture_members(Path::new(FIXTURE_ROOT), 2304, 1001)?;
    let sample = sample(Profile::Fixture)?;
    ensure!(sample["trip"] == false, "fresh OS guard budget trips");
    Ok(sample)
}
fn save_token(p: &Path, v: &Value) -> Result<()> {
    trusted_dir(p.parent().context("gate parent")?, true)?;
    ensure!(
        fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "preexisting token or alias"
    );
    let prepared = p.with_extension("prepared");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&prepared)?;
    f.write_all(&serde_json::to_vec_pretty(v)?)?;
    f.sync_all()?;
    File::open(p.parent().unwrap())?.sync_all()?;
    let source = std::ffi::CString::new(prepared.as_os_str().as_bytes())?;
    let destination = std::ffi::CString::new(p.as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no-clobber token publication: {}",
        std::io::Error::last_os_error()
    );
    File::open(p.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn token_valid(
    v: &Value,
    iid: &str,
    p: u32,
    ticks: &str,
    launch_sha: &str,
    exe_sha: &str,
) -> Result<()> {
    fields(
        v,
        &[
            "schema",
            "fixture_iid",
            "fixture_pid",
            "fixture_startticks",
            "fixture_start_monotonic",
            "launch_sha256",
            "fixture_sha256",
            "watcher_iid",
            "watcher_pid",
            "watcher_startticks",
            "watcher_start_monotonic",
            "first_sample_sha256",
            "fresh_sample",
        ],
    )?;
    ensure!(
        v["schema"] == "jetstreamer-v1425-fixture-barrier-release-v1"
            && v["fixture_iid"] == iid
            && v["fixture_pid"] == p
            && v["fixture_startticks"] == ticks
            && v["launch_sha256"] == launch_sha
            && v["fixture_sha256"] == exe_sha
            && digest(s(v, "watcher_iid")?, 32)
            && v["watcher_pid"].as_u64().is_some_and(|n| n > 1)
            && s(v, "watcher_startticks")?
                .parse::<u64>()
                .is_ok_and(|n| n > 0)
            && s(v, "watcher_start_monotonic")?
                .parse::<u64>()
                .is_ok_and(|n| n > 0)
            && digest(s(v, "first_sample_sha256")?, 64)
            && v["fresh_sample"]["trip"] == false,
        "release binding mismatch"
    );
    Ok(())
}
fn waiting(started: Instant, seconds: u64) -> Result<()> {
    ensure!(
        started.elapsed() < Duration::from_secs(seconds) && seconds <= 120,
        "fixture barrier timeout"
    );
    Ok(())
}
fn launch_wait(l: &Value, launch_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1001,
        "launcher must run as fixture user"
    );
    #[cfg(not(barrier_disposable))]
    for (key, value) in [
        ("JETSTREAMER_V1425_PORTABILITY_FIXTURE_ROOT", FIXTURE_ROOT),
        ("JETSTREAMER_HISTORICAL_POH_THREADS", "2"),
        ("SOLANA_RAYON_THREADS", "2"),
        ("RAYON_NUM_THREADS", "2"),
        ("RUST_MIN_STACK", "134217728"),
        ("TMPDIR", FIXTURE_ROOT),
        ("TMP", FIXTURE_ROOT),
        ("TEMP", FIXTURE_ROOT),
    ] {
        ensure!(
            std::env::var(key).as_deref() == Ok(value),
            "fixture environment changed: {key}"
        );
    }
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(digest(&iid, 32), "invalid launcher IID");
    let p = std::process::id();
    let ticks = proc_start(p)?;
    let token = token_path(&iid);
    trusted_dir(Path::new(&format!("{STATE}/gate")), true)?;
    ensure!(
        fs::symlink_metadata(&token).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "preexisting release token"
    );
    let started = Instant::now();
    loop {
        waiting(started, l["wait_seconds"].as_u64().unwrap())?;
        match root_bytes(Path::new(&token), 1 << 20) {
            Ok(bytes) => {
                let t: Value = serde_json::from_slice(&bytes)?;
                token_valid(&t, &iid, p, &ticks, launch_sha, s(l, "fixture_sha256")?)?;
                let watcher_pid = t["watcher_pid"].as_u64().context("watcher pid")? as u32;
                running(
                    &manager(WATCH)?,
                    WATCH,
                    s(&t, "watcher_iid")?,
                    watcher_pid,
                    s(&t, "watcher_start_monotonic")?,
                )?;
                ensure!(
                    proc_start(watcher_pid)? == s(&t, "watcher_startticks")?,
                    "watcher changed before exec"
                );
                ensure!(proc_start(p)? == ticks, "launcher identity changed");
                executable(EXE, s(l, "fixture_sha256")?)?;
                let error = Command::new(EXE).args(args()).exec();
                return Err(error.into());
            }
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn watcher_identity(v: &Value, launch_sha: &str, self_sha: &str, wp: &str, wh: &str) -> Result<()> {
    let w = manager(WATCH)?;
    configured_command(
        &w,
        &command("barrier-watch", launch_sha, self_sha, Some((wp, wh))),
    )?;
    let p = v["watcher_pid"].as_u64().context("watcher pid")? as u32;
    running(
        &w,
        WATCH,
        s(v, "watcher_iid")?,
        p,
        s(v, "watcher_start_monotonic")?,
    )?;
    ensure!(
        proc_start(p)? == s(v, "watcher_startticks")?,
        "watcher PID reused"
    );
    let (exe, hash, argv) = proc_exe(p)?;
    ensure!(
        exe == format!("{PACKAGE}/barrier")
            && hash == self_sha
            && argv == command("barrier-watch", launch_sha, self_sha, Some((wp, wh))),
        "watcher process/command changed"
    );
    Ok(())
}
fn release(
    l: &Value,
    v: &Value,
    launch_sha: &str,
    self_sha: &str,
    wp: &str,
    wh: &str,
) -> Result<()> {
    let iid = s(v, "fixture_iid")?;
    let bytes = root_bytes(Path::new(&first_path(iid)), 1 << 20)?;
    let first: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        first["schema"] == "jetstreamer-v1425-fixture-barrier-first-sample-v1"
            && first["watch_plan"] == *v
            && first["sample"]["trip"] == false
            && first["launch_sha256"] == launch_sha
            && first["self_sha256"] == self_sha,
        "absent/unready/foreign first watcher sample"
    );
    watcher_identity(&first, launch_sha, self_sha, wp, wh)?;
    fixture_process(v, l, launch_sha, self_sha, false)?;
    ensure!(
        manager(FIXTURE_UNIT)?["UMask"] == "0077",
        "fixture umask changed"
    );
    let fresh = sample_no_trip()?;
    watcher_identity(&first, launch_sha, self_sha, wp, wh)?;
    fixture_process(v, l, launch_sha, self_sha, false)?;
    let token = json!({"schema":"jetstreamer-v1425-fixture-barrier-release-v1","fixture_iid":iid,"fixture_pid":pid(v),
        "fixture_startticks":v["fixture_startticks"],"fixture_start_monotonic":v["fixture_start_monotonic"],
        "launch_sha256":launch_sha,"fixture_sha256":l["fixture_sha256"],"watcher_iid":first["watcher_iid"],
        "watcher_pid":first["watcher_pid"],"watcher_startticks":first["watcher_startticks"],
        "watcher_start_monotonic":first["watcher_start_monotonic"],"first_sample_sha256":sha(&bytes),"fresh_sample":fresh});
    token_valid(
        &token,
        iid,
        pid(v),
        s(v, "fixture_startticks")?,
        launch_sha,
        s(l, "fixture_sha256")?,
    )?;
    save_token(Path::new(&token_path(iid)), &token)?;
    println!("{}", token_path(iid));
    Ok(())
}
fn watch(l: &Value, v: &Value, launch_sha: &str, self_sha: &str) -> Result<()> {
    let iid = s(v, "fixture_iid")?;
    let receipts = format!("{STATE}/receipts/{iid}");
    private(Path::new(&receipts))?;
    let own = manager(WATCH)?;
    let owniid = std::env::var("INVOCATION_ID")?;
    let ownpid = std::process::id();
    let ownticks = proc_start(ownpid)?;
    running(
        &own,
        WATCH,
        &owniid,
        ownpid,
        s(&own, "ExecMainStartTimestampMonotonic")?,
    )?;
    fixture_process(v, l, launch_sha, self_sha, false)?;
    let first = json!({"schema":"jetstreamer-v1425-fixture-barrier-first-sample-v1","watch_plan":v,"launch_sha256":launch_sha,
        "self_sha256":self_sha,"watcher_iid":owniid,"watcher_pid":ownpid,"watcher_startticks":ownticks,
        "watcher_start_monotonic":own["ExecMainStartTimestampMonotonic"],"sample":sample_no_trip()?});
    fixture_process(v, l, launch_sha, self_sha, false)?;
    persist(Path::new(&first_path(iid)), &first)?;
    let started = Instant::now();
    loop {
        ensure!(
            started.elapsed() < Duration::from_secs(1800),
            "barrier watcher deadline"
        );
        let target = manager(FIXTURE_UNIT)?;
        if terminal_shape(&target, FIXTURE_UNIT, iid, s(v, "fixture_start_monotonic")?) {
            persist(
                Path::new(&format!("{receipts}/natural-completion.json")),
                &json!({"watch_plan":v,"terminal":target,"r2_mutations":false}),
            )?;
            return Ok(());
        }
        if fixture_process(v, l, launch_sha, self_sha, true).is_err() {
            let fresh = manager(FIXTURE_UNIT)?;
            if terminal_shape(&fresh, FIXTURE_UNIT, iid, s(v, "fixture_start_monotonic")?) {
                persist(
                    Path::new(&format!("{receipts}/natural-completion.json")),
                    &json!({"watch_plan":v,"terminal":fresh,"r2_mutations":false}),
                )?;
                return Ok(());
            }
            // One immediate coherent reread covers exec's readlink/hash/cmdline transition.
            // Any changed PID/start/hash/command still fails closed; no signal is submitted.
            fixture_process(v, l, launch_sha, self_sha, true)?;
        }
        if fs::read_link(format!("/proc/{}/exe", pid(v)))
            .ok()
            .as_deref()
            == Some(Path::new(EXE))
        {
            let observed = Path::new(&receipts).join("authenticated-exec-observed.json");
            if record(&observed)?.is_none() {
                fixture_process(v, l, launch_sha, self_sha, true)?;
                persist(
                    &observed,
                    &json!({"watch_plan":v,"release_sha256":sha(&root_bytes(Path::new(&token_path(iid)),1<<20)?),"same_pid_startticks_iid":true,"fixture_sha256":l["fixture_sha256"]}),
                )?;
            }
        }
        if let Err(e) = sample_no_trip() {
            let descriptor = json!({"watch_plan":v,"reason":format!("{e:#}"),"r2_mutations":false});
            persist(
                Path::new(&format!("{receipts}/stop-intent.json")),
                &descriptor,
            )?;
            fixture_process(v, l, launch_sha, self_sha, true)?;
            let result = Command::new("/usr/bin/systemctl")
                .args(["stop", "--no-block", FIXTURE_UNIT])
                .status()?;
            ensure!(result.success(), "fixture exact stop failed");
            persist(
                Path::new(&format!("{receipts}/stop-submitted.json")),
                &descriptor,
            )?;
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}
pub(super) fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    ensure!(a.len() == 7 || a.len() == 9, "barrier arguments");
    ensure!(
        a[3] == "--launch-sha256"
            && a[5] == "--self-sha256"
            && digest(&a[4], 64)
            && digest(&a[6], 64),
        "barrier hash arguments"
    );
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == a[6],
        "barrier self hash"
    );
    ensure!(
        a[2] == format!("{PACKAGE}/launch.json"),
        "foreign launch path"
    );
    let bytes = root_bytes(Path::new(&a[2]), 1 << 20)?;
    ensure!(sha(&bytes) == a[4], "launch digest mismatch");
    let l: Value = serde_json::from_slice(&bytes)?;
    launch(&l, &a[6])?;
    if a[1] == "barrier-launch" {
        ensure!(a.len() == 7, "launch trailing options");
        return launch_wait(&l, &a[4]);
    }
    ensure!(
        unsafe { libc::geteuid() } == 0 && a.len() == 9 && digest(&a[8], 64),
        "root watch/release only"
    );
    trusted_dir(Path::new(STATE), true)?;
    trusted_dir(Path::new(&format!("{STATE}/gate")), true)?;
    private(Path::new(&format!("{STATE}/receipts")))?;
    let bytes = root_bytes(Path::new(&a[7]), 1 << 20)?;
    ensure!(sha(&bytes) == a[8], "watch plan digest mismatch");
    let v: Value = serde_json::from_slice(&bytes)?;
    watch_plan(&v, &a[4])?;
    match a[1].as_str() {
        "barrier-watch" => watch(&l, &v, &a[4], &a[6]),
        "barrier-release" => release(&l, &v, &a[4], &a[6], &a[7], &a[8]),
        _ => anyhow::bail!("unknown barrier mode"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn token() -> Value {
        json!({"schema":"jetstreamer-v1425-fixture-barrier-release-v1","fixture_iid":"a".repeat(32),"fixture_pid":22,"fixture_startticks":"42","fixture_start_monotonic":"50","launch_sha256":"b".repeat(64),"fixture_sha256":"c".repeat(64),"watcher_iid":"d".repeat(32),"watcher_pid":23,"watcher_startticks":"43","watcher_start_monotonic":"51","first_sample_sha256":"e".repeat(64),"fresh_sample":{"trip":false}})
    }
    fn valid(v: &Value) -> Result<()> {
        token_valid(
            v,
            &"a".repeat(32),
            22,
            "42",
            &"b".repeat(64),
            &"c".repeat(64),
        )
    }
    #[test]
    fn release_rejects_wrong_iid_hash_pid_start_and_trip() {
        assert!(valid(&token()).is_ok());
        for (key, value) in [
            ("fixture_iid", json!("f".repeat(32))),
            ("fixture_pid", json!(24)),
            ("fixture_startticks", json!("99")),
            ("launch_sha256", json!("f".repeat(64))),
            ("fixture_sha256", json!("f".repeat(64))),
            ("first_sample_sha256", json!("bad")),
            ("fresh_sample", json!({"trip":true})),
            ("watcher_iid", Value::Null),
        ] {
            let mut v = token();
            v[key] = value;
            assert!(valid(&v).is_err(), "accepted {key}");
        }
    }
    #[test]
    fn wait_is_bounded_and_expired_wait_denied() {
        assert!(waiting(Instant::now(), 120).is_ok());
        assert!(waiting(Instant::now(), 121).is_err());
        assert!(waiting(Instant::now() - Duration::from_secs(2), 1).is_err());
    }
    #[test]
    fn absent_unready_terminal_changed_watcher_never_releases() {
        let live = json!({"Id":WATCH,"LoadState":"loaded","InvocationID":"a".repeat(32),"ExecMainStartTimestampMonotonic":"50","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no","ActiveState":"active","SubState":"running","MainPID":"22","Job":""});
        assert!(running(&live, WATCH, &"a".repeat(32), 22, "50").is_ok());
        for (k, value) in [
            ("MainPID", json!("0")),
            ("MainPID", json!("23")),
            ("ActiveState", json!("failed")),
            ("SubState", json!("exited")),
            ("LoadState", json!("not-found")),
            ("InvocationID", json!("b".repeat(32))),
            ("NRestarts", json!("1")),
            ("Job", json!("new-job")),
        ] {
            let mut v = live.clone();
            v[k] = value;
            assert!(
                running(&v, WATCH, &"a".repeat(32), 22, "50").is_err(),
                "accepted watcher {k}"
            );
        }
    }
    #[test]
    fn root_token_requires_no_clobber_regular_file() {
        use std::os::unix::fs::symlink;
        // Root-only actual custody cases are also exercised by disposable systemd qualification.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let p = d.path().join("token");
        save_token(&p, &token()).unwrap();
        assert!(save_token(&p, &token()).is_err());
        let q = d.path().join("alias");
        symlink(&p, &q).unwrap();
        assert!(root_bytes(&q, 1 << 20).is_err());
        assert!(save_token(&q, &token()).is_err());
    }
}
