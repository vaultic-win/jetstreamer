use super::*;

fn mount_readonly(p: &Path) -> Result<bool> {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes())?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut st) } == 0,
        "input filesystem"
    );
    Ok(st.f_flag & libc::ST_RDONLY != 0)
}
pub(super) fn inputs() -> Result<Value> {
    let packet = Bound::new(INPUT, INPUT_SHA).sealed()?;
    ensure!(
        packet["epoch"] == 266
            && packet["bootstrap_slot"] == 114910768
            && packet["terminal_root_slot"] == 115343448,
        "epoch 266 source"
    );
    let files = rows(&packet, "files")?;
    ensure!(files.len() == 4, "epoch 266 file count");
    for row in files {
        let path = Path::new(text(row, "path")?);
        let i = &row["identity"];
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file()
                && path.canonicalize()? == path
                && m.uid() == 0
                && m.mode() & 0o222 == 0
                && m.nlink() == 1
                && m.dev() == num(i, "device")?
                && m.ino() == num(i, "inode")?
                && m.ctime() == num(i, "ctime")? as i64
                && m.ctime_nsec() == num(i, "ctime_nsec")? as i64
                && m.len() == num(i, "bytes")?,
            "epoch 266 input changed"
        );
    }
    Ok(packet)
}
fn mounted(p: &Profile, s: &Value) -> Result<()> {
    let m = fs::metadata(&p.root)?;
    ensure!(
        m.dev() == num(s, "root_device")? && m.ino() == num(s, "root_inode")? && m.uid() == 1000,
        "private root mount"
    );
    let loop_path = Path::new(text(s, "loop")?);
    let leaf = loop_path
        .file_name()
        .context("loop name")?
        .to_str()
        .context("loop text")?;
    ensure!(
        leaf.strip_prefix("loop")
            .is_some_and(|x| !x.is_empty() && x.bytes().all(|c| c.is_ascii_digit()))
            && loop_path.parent() == Some(Path::new("/dev"))
            && Path::new("/sys/block")
                .join(leaf)
                .join("loop/backing_file")
                .exists(),
        "private loop backing"
    );
    let backing = fs::read_to_string(Path::new("/sys/block").join(leaf).join("loop/backing_file"))?;
    ensure!(
        Path::new(backing.trim()) == p.state.join("private.ext4"),
        "foreign loop image"
    );
    for project in rows(s, "projections")? {
        let src = Path::new(text(project, "source")?);
        let dst = Path::new(text(project, "target")?);
        let a = fs::metadata(src)?;
        let b = fs::metadata(dst)?;
        ensure!(
            a.dev() == b.dev() && a.ino() == b.ino() && mount_readonly(dst)?,
            "unbound input {}",
            dst.display()
        );
    }
    Ok(())
}
pub(super) fn wait(p: &Profile, b: &Bound) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 1000 && b.path == p.state.join("spec.json"),
        "real producer wait"
    );
    let s = b.sealed()?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        hex(&iid, 32)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{}", p.unit),
        "wait cgroup"
    );
    ensure!(
        s["unit"] == p.unit && s["mode"] == p.mode && std::env::current_dir()? == p.root,
        "wrong held producer"
    );
    if p.lane == Lane::Epoch228 {
        epoch228::verify_payload(p, &s)?;
    } else {
        inputs()?;
        if p.lane.is_bounded() {
            bounded::payload(p, &s)?;
        } else if matches!(p.lane, Lane::Instructions266 | Lane::Turnover266) {
            successor::payload(p, &s)?;
        }
    }
    mounted(p, &s)?;
    let token = p.state.join(format!("token-{iid}.json"));
    let end = Instant::now() + Duration::from_secs(240);
    while !token.exists() {
        ensure!(Instant::now() < end, "real token deadline");
        std::thread::sleep(Duration::from_millis(100));
    }
    let t = bound_at(&token)?.sealed()?;
    ensure!(
        p.mode == "pilot"
            && t["unit"] == p.unit
            && t["iid"] == iid
            && t["pid"] == std::process::id()
            && t["spec"] == json!(b)
            && num(&t, "expires")? >= now()?
            && t["first_guard"].is_object()
            && t["held_fit"].is_object(),
        "wrong first-guard token"
    );
    mounted(p, &s)?;
    let argv = rows(&s, "argv")?
        .iter()
        .map(|v| v.as_str().context("argv"))
        .collect::<Result<Vec<_>>>()?;
    if p.lane == Lane::Epoch228 {
        epoch228::verify_payload(p, &s)?;
    } else if p.lane.is_bounded() {
        bounded::payload(p, &s)?;
    } else if matches!(p.lane, Lane::Instructions266 | Lane::Turnover266) {
        successor::payload(p, &s)?;
    } else {
        ensure!(
            argv.first() == Some(&format!("{SNAPROOT}/jetstreamer-node").as_str())
                && argv.get(1) == Some(&"266"),
            "foreign node"
        );
    }
    let err = Command::new(argv[0]).args(&argv[1..]).exec();
    Err(err.into())
}
pub(super) fn owner_fields(unit: &str) -> Result<BTreeMap<String, String>> {
    let out=Command::new("/usr/bin/systemctl").args(["show",unit,"-p","Id,LoadState,InvocationID,MainPID,ActiveState,SubState,ControlGroup,NRestarts,MemoryMax,MemorySwapMax,Restart,KillMode,Result,Delegate"]).output()?;
    ensure!(out.status.success(), "guard owner census");
    Ok(std::str::from_utf8(&out.stdout)?
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(a, b)| (a.to_owned(), b.to_owned()))
        .collect())
}
fn stop(p: &Profile, s: &Value, reason: &str, rec: &Value) -> Result<()> {
    let a = owner_fields(&p.unit)?;
    ensure!(
        a.get("Id") == Some(&p.unit)
            && a.get("InvocationID").map(String::as_str) == s["iid"].as_str()
            && a["NRestarts"] == "0"
            && a["Restart"] == "no"
            && a["KillMode"] == "control-group",
        "wrong pressure-stop owner"
    );
    if a["ActiveState"] != "active" {
        return Ok(());
    }
    ensure!(
        a["MainPID"].parse::<u64>()? > 1
            && a["ControlGroup"] == format!("/system.slice/{}", p.unit),
        "wrong stop cgroup"
    );
    let out = p.state.join("receipts");
    let intent = out.join("pressure-stop.json");
    if !intent.exists() {
        save_json(
            &out,
            "pressure-stop.json",
            &json!({"unit":p.unit,"iid":s["iid"],"guard_iid":std::env::var("INVOCATION_ID")?,"reason":reason,"owner":a,"pressure":rec}),
        )?;
    }
    ensure!(owner_fields(&p.unit)? == a, "owner changed before stop");
    ensure!(
        Command::new("/usr/bin/systemctl")
            .args(["stop", &p.unit])
            .status()?
            .success(),
        "pressure stop failed"
    );
    Ok(())
}
fn guard_once(p: &Profile, s: &Value) -> Result<Value> {
    let m = owner_fields(&p.unit)?;
    if p.lane.is_bounded() && p.mode == "pilot" && m["ActiveState"] == "inactive" {
        let intent = p.state.join("receipts/target-stop-intent.json");
        if intent.try_exists()? {
            return Ok(
                json!({"bounded_terminal":bounded::finish(p,text(s,"iid")?,&bound_at(&intent)?)?}),
            );
        }
    }
    ensure!(
        m["Id"] == p.unit
            && m["InvocationID"] == text(s, "iid")?
            && m["NRestarts"] == "0"
            && m["MemorySwapMax"] == "0",
        "guard invocation changed"
    );
    if m["ActiveState"] == "active" {
        let cg = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
        let cap = num(s, "memory")?;
        let pg = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
        ensure!(
            m["MemoryMax"].parse::<u64>()? == cap
                && fs::read_to_string(cg.join("memory.max"))?
                    .trim()
                    .parse::<u64>()?
                    == cap / pg * pg
                && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0"
                && fs::read_to_string(cg.join("cgroup.procs"))?
                    .lines()
                    .any(|l| l == m["MainPID"]),
            "kernel owner"
        );
        let current = fs::read_to_string(cg.join("memory.current"))?
            .trim()
            .parse::<u64>()?;
        let mut events = BTreeMap::new();
        for l in fs::read_to_string(cg.join("memory.events"))?.lines() {
            let (k, v) = l.split_once(' ').context("memory event")?;
            events.insert(k.to_owned(), v.parse::<u64>()?);
        }
        if current >= num(s, "stop_at")?
            || ["max", "oom", "oom_kill"]
                .iter()
                .any(|k| events.get(*k).copied().unwrap_or(1) > 0)
        {
            let pressure = json!({"memory":current,"cap":cap,"events":events});
            stop(p, s, "cgroup-memory-pressure", &pressure)?;
            return Ok(pressure);
        }
    }
    if p.lane == Lane::Epoch228 && p.mode == "pilot" && m["ActiveState"] == "active" {
        let available = live::resources_at(&p.root)?.2;
        if available < 8 << 30 {
            let pressure = json!({"loop_available":available});
            stop(p, s, "private-filesystem-floor", &pressure)?;
            return Ok(pressure);
        }
    }
    let (exe, sha) = p.lane.guard();
    let guard = Bound::new(exe, sha);
    guard.artifact()?;
    let plan = binding(&s["guard_plan"])?;
    plan.sealed()?;
    let result = Command::new(&guard.path)
        .arg(&plan.path)
        .args([
            "--plan-sha256",
            &plan.sha256,
            "--self-sha256",
            &guard.sha256,
        ])
        .output()?;
    if !result.status.success() {
        let failure = std::str::from_utf8(&result.stderr)?.trim();
        ensure!(
            result.status.code() == Some(1)
                && failure == "invocation, restart count, or standalone restart policy changed",
            "standalone guard {}: {}",
            result.status,
            failure
        );
        let proof = stopped::closed(p, s, &m, &plan)?;
        return Ok(json!({"qualified_native_guard":guard,"closed_manager_owner":proof}));
    }
    if p.lane.is_bounded() && p.mode == "pilot" && m["ActiveState"] == "active" {
        bounded::stop_at_target(p, s, &m)?;
    }
    Ok(json!({"qualified_native_guard":guard}))
}
pub(super) fn guard(p: &Profile, b: &Bound, failsafe: bool) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && b.path == p.state.join("supervisor.json"),
        "entry guard scope"
    );
    let s = b.sealed()?;
    ensure!(
        s["unit"] == p.unit && hex(&std::env::var("INVOCATION_ID")?, 32),
        "PID1 guard binding"
    );
    if failsafe {
        stop(p, &s, "protective-service-failure", &Value::Null)?;
        return Ok(Value::Null);
    }
    match guard_once(p, &s) {
        Ok(v) => Ok(v),
        Err(e) => {
            stop(p, &s, "native-guard-failure", &json!(format!("{e:#}")))?;
            Err(e)
        }
    }
}
