//! Apply the same outstanding output reservation to every subsequent native fleet quote.
use super::*;
use std::os::unix::fs::PermissionsExt;
const REG: &str = "epoch167_private_assembly";
const TOOLS: &str = "turnover-tools-v1";
pub(super) fn our_seal() -> Result<Value> {
    let seal = reference(&rt(TOOLS).join("deployment-seal-receipt.json"))?;
    let tool = member(&seal, "turnover")?;
    let me = fs::metadata("/proc/self/exe")?;
    let st = fs::metadata(tool)?;
    ensure!(
        (me.dev(), me.ino()) == (st.dev(), st.ino()),
        "use sealed assembly turnover operator"
    );
    Ok(seal)
}
fn funded(q: &Value) -> Result<(u64, u64)> {
    let s = &q["closed_167_suballocations"];
    ensure!(
        s["retained_producer_ram"] == 42u64 << 30
            && s["native_drain"]["sha256"]
                == "84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9"
            && s["additional_home"] == 0
            && s["additional_ram"] == 0
            && s["guard_ram_separate"] == 1u64 << 30
            && s["phases"]["source_qualification"]["invocation"] == QID
            && matches!(
                s["phases"]["source_qualification"]["phase"].as_str(),
                Some("active" | "terminal")
            ),
        "different closed 167 allocation"
    );
    let u = &s["unassigned"];
    let mem = num(u, "ram_bytes")?
        .checked_sub(MEMORY)
        .context("unassigned RAM below 8 GiB")?;
    let cpu = num(u, "cpu_micros_per_second")?
        .checked_sub(CPU)
        .context("unassigned CPU below one core")?;
    Ok((mem, cpu))
}
fn formula(base: u64, floor: u64, budget: u64, resident: u64) -> Result<(u64, u64)> {
    ensure!(resident <= budget, "output allocation exceeds its cap");
    let remaining = budget - resident;
    Ok((
        remaining,
        base.max(floor)
            .checked_add(remaining)
            .context("required HOME overflow")?,
    ))
}
fn occupied() -> Result<u64> {
    let p = Path::new(OUT);
    let mut n = 0;
    let mut paths = fs::read_dir(p)?
        .map(|row| row.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(paths.len() <= 1, "unexpected second private output tree");
    if let Some(d) = paths.pop() {
        let name = d
            .file_name()
            .and_then(|s| s.to_str())
            .context("output name")?;
        let m = fs::symlink_metadata(&d)?;
        ensure!(
            d.canonicalize()? == d
                && m.is_dir()
                && m.uid() == 0
                && m.dev() == fs::metadata(p)?.dev()
                && (name == "accepted" || name.starts_with(".pending-167-")),
            "unbound output tree"
        );
        let file = d.join("epoch-167.jet");
        if file.try_exists()? {
            let m = fs::symlink_metadata(&file)?;
            ensure!(
                m.is_file()
                    && m.uid() == 0
                    && m.nlink() == 1
                    && m.dev() == fs::metadata(p)?.dev()
                    && m.len() <= OUTPUT_CAP
                    && file.canonicalize()? == file,
                "different private archive"
            );
            n = m.len().min(m.blocks() * 512);
        }
    }
    Ok(n)
}
pub(super) fn account(mut q: Value) -> Result<Value> {
    let seal = our_seal()?;
    ensure!(
        q.get(REG).is_none() && q["resource_credit_bytes"] == 0 && q["fits"].is_boolean(),
        "invalid or already charged roster"
    );
    let mut status = json!({"phase":"unbooked","operator_seal":seal,"output_cap":BUDGET,"additional_compute_ram":0,"additional_compute_cpu":0,"additional_home":0});
    if state("BOOKED.json").try_exists()? {
        let booking = reference(&state("BOOKED.json"))?;
        let b = bound(&booking)?;
        ensure!(
            b["schema"] == "horizon-167-assembly-booking-v1"
                && b["unit"] == UNIT
                && b["operator_seal"] == seal
                && b["budget"] == BUDGET
                && b["memory"] == MEMORY
                && b["cpu"] == CPU,
            "foreign assembly booking"
        );
        let done = state("PRIVATE_TERMINAL.json");
        if done.try_exists()? {
            let proof = reference(&done)?;
            let result = bound(&proof)?;
            ensure!(
                result["booking"] == booking
                    && result["unit"] == UNIT
                    && result["success"] == true
                    && result["publication_authorized"] == false,
                "foreign assembly terminal"
            );
            status["phase"] = json!("closed");
            status["terminal"] = proof;
        } else {
            let (mem, cpu) = funded(&q)?;
            let lower = occupied()?;
            let (remaining, required) = formula(
                num(&q, "required_home")?,
                num(&b, "minimum_home_free_bytes")?,
                BUDGET,
                lower,
            )?;
            let free = num(&q, "available_home")?;
            q["required_home"] = required.into();
            q["guard_floor"] = num(&q, "guard_floor")?
                .max(num(&b, "minimum_home_free_bytes")?)
                .into();
            let margin = i64::try_from(free)? - i64::try_from(required)?;
            q["home_margin"] = margin.into();
            q["fits"] = json!(q["fits"] == true && margin >= 0);
            q["closed_167_suballocations"]["unassigned"]["ram_bytes"] = mem.into();
            q["closed_167_suballocations"]["unassigned"]["cpu_micros_per_second"] = cpu.into();
            status["phase"] = json!("booked");
            status["booking"] = booking;
            status["additional_home"] = remaining.into();
            status["occupied_archive_lower_bytes"] = lower.into();
        }
    }
    q[REG] = status;
    Ok(q)
}
fn provider(path: &str, sha: &str) -> Result<Value> {
    let p = Path::new(path);
    let base = Path::new(RT).join("epoch162-first-hourly-completion-20261127-v2");
    let dir = p.parent().context("provider directory")?;
    let version = dir
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|n| n.strip_prefix("issued-price-v"))
        .context("unexpected roster name")?
        .parse::<u16>()?;
    ensure!(
        p.file_name()
            .is_some_and(|n| n == "deployment-seal-receipt.json")
            && dir.parent() == Some(base.as_path())
            && version >= 16,
        "unexpected provider location"
    );
    let seal = fixed(p.into(), sha);
    let program = member(&seal, "capacity.py")?;
    let raw = command(
        "/usr/bin/python3",
        &[
            "-IB",
            "-c",
            "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['whole_roster']()))",
            program.to_str().context("provider path")?,
        ],
    )?;
    let q: Value = serde_json::from_str(&raw)?;
    ensure!(
        q["package"] == seal && q["resource_credit_bytes"] == 0,
        "different common price binding"
    );
    let ts = q["recorded_unix_seconds"]
        .as_f64()
        .context("quote timestamp")?;
    ensure!((now()? as f64 - ts).abs() < 120.0, "stale common price");
    bound(&q["fleet"])?;
    bound(&q["writer"])?;
    Ok(q)
}
fn fit(q: &Value) -> Result<Value> {
    let _ = funded(q)?;
    ensure!(
        q["preparation_only"] != true,
        "preparation-only price cannot admit an assembly"
    );
    let current = available()?;
    let free = current.0.min(num(q, "available_home")?);
    let avail = current.1.min(num(q, "available_ram")?);
    let floor = num(q, "required_home")?.max(num(q, "guard_floor")?);
    let (_, home) = formula(floor, 0, BUDGET, 0)?;
    let required_ram = num(q, "required_ram")?;
    ensure!(required_ram >= MEMORY, "missing paid memory");
    Ok(
        json!({"epoch":167,"unit":UNIT,"fits":q["fits"]==true&&free>=home&&avail>=required_ram,"maximum_additional_home_bytes":BUDGET,"available_home_bytes":free,"minimum_home_free_bytes":floor,"home_shortfall_bytes":home.saturating_sub(free),"home_margin_bytes":i64::try_from(free)?-i64::try_from(home)?,"cpu_quota_us":CPU,"memory_max_bytes":MEMORY,"memory_swap_max_bytes":0,"available_memory_bytes":avail,"required_memory_bytes":required_ram,"expires_unix_seconds":now()?+240,"source_qualification_phase":q["closed_167_suballocations"]["phases"]["source_qualification"]["phase"],"resource_credit_bytes":0,"publication_authorized":false}),
    )
}
fn read_paths(start: &Value) -> Result<Vec<String>> {
    let args = start["argv"].as_array().context("qualifier argv")?;
    let rows: Vec<_> = args
        .iter()
        .filter_map(Value::as_str)
        .filter_map(|s| s.strip_prefix("--property=BindReadOnlyPaths="))
        .collect();
    ensure!(rows.len() == 1, "source projections");
    let paths: Vec<_> = rows[0]
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect();
    ensure!(
        paths.len() == 4
            && paths.iter().all(|p| p
                .starts_with("/home/sol/.jetstreamer-private/epoch167-standard-lane-20261109-v1/")
                && !p.contains([':', '%'])
                && Path::new(p).canonicalize().ok().as_ref() == Some(&PathBuf::from(p))),
        "foreign input projections"
    );
    Ok(paths)
}
fn empty_projection(sources: &[String]) -> Result<PathBuf> {
    let root = state("namespace-home");
    private_dir(&root)?;
    for path in sources.iter().map(String::as_str).chain([OUT]) {
        let rel = Path::new(path).strip_prefix("/home/sol")?;
        let dst = root.join(rel);
        let dir = if path == OUT {
            dst.as_path()
        } else {
            dst.parent().context("projected parent")?
        };
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        if path != OUT && !dst.try_exists()? {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(&dst)?
                .sync_all()?;
        }
        ensure!(dst.canonicalize()? == dst, "indirect projected path");
    }
    Ok(root)
}
fn launch_args(sources: &[String], view: &Path, plan: &Value) -> Result<Vec<String>> {
    let mut args: Vec<String> = [
        "--quiet",
        "--service-type=exec",
        &format!("--unit={UNIT}"),
        "--slice=system.slice",
        "--setenv=RUST_MIN_STACK=67108864",
    ]
    .iter()
    .map(|s| (*s).into())
    .collect();
    let prop = [
        "User=root".to_string(),
        "Group=root".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=read-only".into(),
        format!("BindReadOnlyPaths={}:/home/sol", view.display()),
        format!("BindReadOnlyPaths={}", sources.join(" ")),
        format!("BindPaths={OUT}"),
        "PrivateNetwork=yes".into(),
        "PrivateDevices=yes".into(),
        "PrivateIPC=yes".into(),
        "NoNewPrivileges=yes".into(),
        "CapabilityBoundingSet=CAP_DAC_READ_SEARCH".into(),
        "RestrictAddressFamilies=AF_UNIX".into(),
        "ProtectControlGroups=yes".into(),
        "ProtectKernelTunables=yes".into(),
        "InaccessiblePaths=/tmp /var/tmp /run/jetstreamer-ready-bounds-20261121-v1".into(),
        "CPUQuota=100%".into(),
        "MemoryMax=8G".into(),
        "MemorySwapMax=0".into(),
        "TasksMax=24".into(),
        "RuntimeMaxSec=72h".into(),
        "Restart=no".into(),
        "IOWeight=10".into(),
        "Nice=12".into(),
        "LimitFSIZE=137438953472".into(),
        "LimitCORE=0".into(),
        "UMask=0077".into(),
        format!(
            "StandardOutput=append:{}",
            state("ASSEMBLY.stdout").display()
        ),
        format!(
            "StandardError=append:{}",
            state("ASSEMBLY.stderr").display()
        ),
    ];
    args.extend(prop.into_iter().map(|p| format!("--property={p}")));
    args.extend([
        "--".into(),
        rt("tools/horizon-167-assembly").display().to_string(),
        "--assemble-epoch167-private".into(),
        word(plan, "path")?.into(),
        word(plan, "sha256")?.into(),
    ]);
    Ok(args)
}
fn prepare() -> Result<(Vec<String>, PathBuf)> {
    private_dir(&state(""))?;
    private_dir(Path::new(OUT).parent().context("output parent")?)?;
    private_dir(Path::new(OUT))?;
    let (_, s, _) = original()?;
    let paths = read_paths(&s)?;
    let view = empty_projection(&paths)?;
    Ok((paths, view))
}
fn dispatch(q: &Value, mut f: Value, tip: &str) -> Result<Value> {
    ensure!(
        q[REG]["phase"] == "unbooked"
            && q[REG]["operator_seal"] == our_seal()?
            && f["fits"] == true
            && f["source_qualification_phase"] == "terminal",
        "private dispatch needs a registered unbooked operator, source terminal, and positive fresh fit"
    );
    idle(UNIT)?;
    let term = capture()?;
    let source = qualified_source(tip)?;
    let (paths, view) = prepare()?;
    ensure!(
        !state("BOOKED.json").try_exists()? && fs::read_dir(OUT)?.next().is_none(),
        "assembly already booked or output is occupied"
    );
    let stem = now()?;
    let native = receipt(&state(&format!("ROSTER-{stem}.json")), q)?;
    f["whole_roster"] = native.clone();
    let ad = receipt(&state(&format!("ADMISSION-{stem}.json")), &f)?;
    let plan_arg = member(&assembler_seal(), "assembly_plan.py")?;
    let p: Value = serde_json::from_str(&command(
        "/usr/bin/python3",
        &[
            "-IB",
            plan_arg.to_str().context("plan generator")?,
            "assemble",
            word(&ad, "path")?,
            "--qualification",
            state("QUALIFIED.json").to_str().context("source result")?,
        ],
    )?)?;
    let plan = bound(&p)?;
    ensure!(
        plan["admission"] == ad && plan["qualification"] == reference(&state("QUALIFIED.json"))?,
        "wrong generated assembly plan"
    );
    let args = launch_args(&paths, &view, &p)?;
    let seal = our_seal()?;
    let b = receipt(
        &state("BOOKED.json"),
        &json!({"schema":"horizon-167-assembly-booking-v1","unit":UNIT,"operator_seal":seal,"budget":BUDGET,"cpu":CPU,"memory":MEMORY,"minimum_home_free_bytes":f["minimum_home_free_bytes"],"whole_roster":native,"qualified":term,"source":source,"admission":ad,"plan":p,"argv":args,"publication_authorized":false}),
    )?;
    command("/usr/bin/systemd-run", &args)?;
    let row = props(
        UNIT,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NRestarts,Job",
    )?;
    ensure!(
        row["Id"] == UNIT
            && row["InvocationID"].len() == 32
            && row["MainPID"].parse::<u32>()? > 1
            && row["MemoryMax"] == MEMORY.to_string()
            && row["CPUQuotaPerSecUSec"] == "1s"
            && row["MemorySwapMax"] == "0"
            && row["NRestarts"] == "0"
            && row["ControlGroup"] == format!("/system.slice/{UNIT}"),
        "reconcile booked native dispatch before retry"
    );
    receipt(
        &state("DISPATCH_RESULT.json"),
        &json!({"booking":b,"unit":row,"boot":BOOT}),
    )
}
fn finish() -> Result<Value> {
    let dispatch = bound(&reference(&state("DISPATCH_RESULT.json"))?)?;
    let b = reference(&state("BOOKED.json"))?;
    ensure!(
        dispatch["booking"] == b && dispatch["boot"] == BOOT,
        "wrong booked assembly"
    );
    let iid = word(&dispatch["unit"], "InvocationID")?;
    let end = query_terminal(UNIT, iid)?;
    let out = Path::new(OUT).join("accepted");
    let report = reference(&out.join("assembly.json"))?;
    let v = bound(&report)?;
    let stdout: Value = serde_json::from_slice(&trusted(&state("ASSEMBLY.stdout"))?)?;
    let archive = out.join("epoch-167.jet");
    ensure!(
        v == stdout
            && v["schema"] == "horizon-167-private-mixed-worker-assembly-v1"
            && v["epoch"] == 167
            && v["invocation"] == iid
            && v["plan"] == bound(&b)?["plan"]
            && v["source_qualification"] == reference(&state("QUALIFIED.json"))?
            && v["unit"] == UNIT
            && v["private_archive"] == json!(archive)
            && v["publication_authorized"] == false
            && v["slots"] == 432000
            && v["first_slot"] == 72144000
            && v["last_slot"] == 72575999,
        "wrong native assembled archive"
    );
    let m = fs::symlink_metadata(&archive)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.permissions().mode() & 0o777 == 0o400
            && archive.canonicalize()? == archive
            && m.len() == num(&v, "archive_bytes")?
            && m.len() <= OUTPUT_CAP,
        "archive extent or custody changed"
    );
    stable(
        &state("PRIVATE_TERMINAL.json"),
        &json!({"success":true,"unit":UNIT,"booking":b,"native_terminal":end,"private_assembly":report,"archive_identity":stamp(&archive)?,"publication_authorized":false}),
    )
}
fn check_namespace() -> Result<Value> {
    let group = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        group.starts_with("0::/system.slice/horizon-167-private-assembly-namespace-"),
        "sandbox fixture unit required"
    );
    let source = original()?.1;
    let mut inputs = Vec::new();
    for path in read_paths(&source)? {
        let f = File::open(&path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file() && m.len() > 0 && Path::new(&path).canonicalize()? == Path::new(&path),
            "private input failed to open"
        );
        inputs.push(json!({"path":path,"dev":m.dev(),"ino":m.ino(),"bytes":m.len()}));
    }
    let out = Path::new(OUT);
    ensure!(
        fs::metadata("/home/sol")?.dev() == fs::metadata(out)?.dev()
            && !Path::new("/home/sol/workspace").exists()
            && out.canonicalize()? == out
            && fs::read_dir(out)?.next().is_none(),
        "HOME projection or private output differs"
    );
    let probe = out.join(".namespace-write-probe");
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&probe)?
        .sync_all()?;
    fs::remove_file(probe)?;
    File::open(out)?.sync_all()?;
    Ok(
        json!({"inputs":inputs,"visible_HOME_device":fs::metadata("/home/sol")?.dev(),"output_device":fs::metadata(out)?.dev(),"output_inode":fs::metadata(out)?.ino(),"namespace":group.trim(),"write_probe_removed":true}),
    )
}
fn namespace() -> Result<Value> {
    let _l = lock()?;
    let (sources, view) = prepare()?;
    ensure!(
        !state("BOOKED.json").try_exists()?,
        "assembler has the output"
    );
    let mut args = launch_args(
        &sources,
        &view,
        &json!({"path":"fixture","sha256":"fixture"}),
    )?;
    args.truncate(
        args.iter()
            .position(|s| s == "--")
            .context("missing native delimiter")?,
    );
    let label = format!(
        "--unit=horizon-167-private-assembly-namespace-{}-{}.service",
        now()?,
        std::process::id()
    );
    args.retain(|s| {
        !s.starts_with("--property=Standard")
            && !s.starts_with("--unit=")
            && !s.starts_with("--property=MemoryMax=")
            && !s.starts_with("--property=CPUQuota=")
    });
    args.extend([
        label,
        "--wait".into(),
        "--pipe".into(),
        "--property=MemoryMax=128M".into(),
        "--property=CPUQuota=25%".into(),
        "--".into(),
        rt(TOOLS).join("turnover").display().to_string(),
        "check-namespace".into(),
    ]);
    let r: Value = serde_json::from_str(&command("/usr/bin/systemd-run", &args)?)?;
    ensure!(
        r["output_device"] == fs::metadata(OUT)?.dev()
            && r["output_inode"] == fs::metadata(OUT)?.ino(),
        "namespace output differs from real charged filesystem"
    );
    for entry in r["inputs"].as_array().context("namespace inputs")? {
        let m = fs::metadata(word(entry, "path")?)?;
        ensure!(
            entry["dev"] == m.dev() && entry["ino"] == m.ino() && entry["bytes"] == m.len(),
            "namespace input differs from real source"
        );
    }
    receipt(&state(&format!("NAMESPACE-{}.json", now()?)), &r)
}
pub(super) fn entry(args: &[String]) -> Result<Value> {
    match args {
        [c] if c == "namespace" => namespace(),
        [c] if c == "check-namespace" => check_namespace(),
        [c, tip] if c == "inspect" => {
            let _l = lock()?;
            let source = qualified_source(tip)?;
            let (paths, view) = prepare()?;
            Ok(
                json!({"source":source,"original_streams":reference(&rt(SCOPE).join("NATIVE_STREAMS.json"))?,"views":paths,"home_projection":view,"budget":BUDGET,"publication_authorized":false}),
            )
        }
        [c] if c == "finish" => {
            let _l = lock()?;
            finish()
        }
        [c, path, sha, tip] if matches!(c.as_str(), "quote" | "dispatch") => {
            let _l = lock()?;
            let q = provider(path, sha)?;
            let mut f = fit(&q)?;
            if c == "dispatch" {
                dispatch(&q, f, tip)
            } else {
                f["provider"] = q["package"].clone();
                f["fleet"] = q["fleet"].clone();
                f["writer"] = q["writer"].clone();
                f["operator_registered"] = q[REG]["phase"].is_string().into();
                Ok(f)
            }
        }
        _ => anyhow::bail!(
            "expected inspect TIP, capture, quote|dispatch ROSTER_SEAL SHA TIP, account on stdin, or finish"
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ongoing_tree_and_floor() {
        assert_eq!(formula(500, 730, 140, 30).unwrap(), (110, 840));
        assert_eq!(formula(900, 730, 140, 0).unwrap(), (140, 1040));
        assert!(formula(500, 500, 32, 33).is_err());
        assert!(formula(u64::MAX, 0, 1, 0).is_err());
    }
    #[test]
    fn closed_resources() {
        let mut v = json!({"closed_167_suballocations":{"retained_producer_ram":42u64<<30,"native_drain":{"sha256":"84f37a4cb4886968c932b624b47a7863fde5b115eff2bbd11a4255f4c5f4bee9"},"additional_home":0,"additional_ram":0,"guard_ram_separate":1u64<<30,"phases":{"source_qualification":{"phase":"active","invocation":QID}},"unassigned":{"ram_bytes":MEMORY,"cpu_micros_per_second":CPU}}});
        assert_eq!(funded(&v).unwrap(), (0, 0));
        v["closed_167_suballocations"]["unassigned"]["cpu_micros_per_second"] = json!(CPU - 1);
        assert!(funded(&v).is_err());
    }
}
