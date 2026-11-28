//! A serial holding owner is priced once and bound to the real systemd scope for its entire lifetime.
use super::*;
pub(super) fn limits(phase: &str) -> Result<(u64, u64)> {
    Ok(match phase {
        "fixture" | "custody" => (256 << 20, 250_000),
        "census" => (512 << 20, 500_000),
        "retire" => (1 << 30, 1_000_000),
        "restore" => (2 << 30, 2_000_000),
        _ => anyhow::bail!("unknown phase"),
    })
}
fn service(phase: &str, salt: &str) -> String {
    if matches!(phase, "retire" | "restore") {
        format!("horizon-closed157-{phase}-lanej-{salt}.service")
    } else {
        format!("horizon-157-lanej-{phase}-{salt}.service")
    }
}
pub(super) fn intake(phase: &str, unit: &str) -> Result<PathBuf> {
    let prefix = service(phase, "");
    let p = prefix.strip_suffix(".service").unwrap();
    let token = unit
        .strip_prefix(p)
        .and_then(|s| s.strip_suffix(".service"))
        .context("different 157 unit")?;
    ensure!(
        !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()),
        "foreign 157 generation"
    );
    Ok(root(&format!(
        "{}_ADMISSION_{token}.json",
        phase.to_uppercase()
    )))
}
fn whole(path: &str, sha: &str) -> Result<Value> {
    let p = Path::new(path);
    let dir = p.parent().context("provider directory")?;
    ensure!(
        p.file_name()
            .is_some_and(|n| n == "deployment-seal-receipt.json")
            && dir.parent()
                == Some(
                    Path::new(ROOT)
                        .parent()
                        .unwrap()
                        .join("epoch162-first-hourly-completion-20261127-v2")
                        .as_path()
                )
            && dir
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_prefix("issued-price-v"))
                .and_then(|s| s.parse::<usize>().ok())
                .is_some_and(|v| v >= 20),
        "foreign whole-roster provider"
    );
    let seal = pinned(p, sha);
    let cmd = member(&seal, "capacity.py")?;
    let q: Value = serde_json::from_str(&command(
        "/usr/bin/python3",
        &[
            "-IB",
            "-c",
            "import json,runpy,sys; print(json.dumps(runpy.run_path(sys.argv[1])['whole_roster']()))",
            cmd.to_str().unwrap(),
        ],
    )?)?;
    ensure!(
        q["package"] == seal
            && q["resource_credit_bytes"] == 0
            && q["preparation_only"] != true
            && q["fits"].is_boolean()
            && (now()? as f64 - q["recorded_unix_seconds"].as_f64().context("recording")?).abs()
                < 120.,
        "invalid complete roster"
    );
    bound(&q["fleet"])?;
    bound(&q["writer"])?;
    Ok(q)
}
fn active_holding() -> Result<Vec<String>> {
    Ok(command(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--no-pager",
            "--plain",
            "--no-legend",
            "--type=service",
            "--state=running,activating,deactivating,reloading",
            "horizon-closed186-*",
            "horizon-*park*",
            "horizon-*holding*",
            "horizon-*retire*",
            "horizon-*restore*",
        ],
    )?
    .lines()
    .filter_map(|s| s.split_whitespace().next().map(str::to_string))
    .collect())
}
pub(super) fn holder(unit: &str) -> Result<Value> {
    let phase = if unit.starts_with("horizon-closed157-retire-lanej-") {
        "retire"
    } else {
        "restore"
    };
    let path = intake(phase, unit)?;
    let a = bound(&reference(&path)?)?;
    let seal = ours()?;
    ensure!(
        a["operator_seal"] == seal
            && a["phase"] == phase
            && a["unit"] == unit
            && a["serial_holding_slot"] == true
            && a["fits"] == true
            && a["resource_credit_bytes"] == 0
            && a["restore_bytes"] == LENGTH + META
            && a["serial_slot_bytes"] == 123350028052u64
            && active_holding()? == [unit],
        "foreign paid holding transition"
    );
    let s = props(
        unit,
        "Id,ActiveState,MainPID,ControlPID,Job,InvocationID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
    )?;
    let pid = s["MainPID"].parse::<u32>()?;
    let iid = &s["InvocationID"];
    let (mem, cpu) = limits(phase)?;
    ensure!(
        iid.len() == 32
            && pid > 1
            && s["ActiveState"] == "active"
            && s["Id"] == unit
            && s["Job"].is_empty()
            && s["ControlPID"] == "0"
            && s["ControlGroup"] == format!("/system.slice/{unit}")
            && s["MemoryMax"] == mem.to_string()
            && s["MemorySwapMax"] == "0"
            && s["CPUQuotaPerSecUSec"] == if phase == "retire" { "1s" } else { "2s" },
        "holding scope limits changed"
    );
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let image = member(&seal, "rotation")?;
    let actual = fs::metadata(proc.join("exe"))?;
    let target = fs::metadata(&image)?;
    let cmd = fs::read(proc.join("cmdline"))?;
    let desired = format!("{}\0{}\0", image.display(), phase);
    ensure!(
        (actual.dev(), actual.ino()) == (target.dev(), target.ino()) && cmd == desired.as_bytes(),
        "wrong actual holding command"
    );
    let g = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
    let kernel = fs::read_to_string(g.join("cpu.max"))?;
    let v = kernel
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        v.len() == 2
            && v[0] * 1_000_000 == cpu * v[1]
            && fs::read_to_string(g.join("memory.max"))?.trim() == mem.to_string()
            && fs::read_to_string(g.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(g.join("cgroup.procs"))?
                .split_whitespace()
                .any(|x| x == pid.to_string()),
        "kernel holding scope changed"
    );
    Ok(
        json!({"phase":phase,"admission":reference(&path)?,"native":s,"expected":reference(&root("park-package-v1/expected.json"))?,"resource_credit_bytes":0}),
    )
}
pub(super) fn dispatch(phase: &str, provider: &str, sha: &str) -> Result<Value> {
    let (mem, cpu) = limits(phase)?;
    let seal = ours()?;
    let _lock = global()?;
    let q = whole(provider, sha)?;
    let serial = matches!(phase, "retire" | "restore");
    let floor0 = num(&q, "guard_floor")?;
    let required = num(&q, "required_home")?;
    let free = available()?.0.min(num(&q, "available_home")?);
    let mut floor = required.max(floor0);
    let mut budget = META;
    if serial {
        let identity = bound(&reference(&root("PARK_CUSTODY.json"))?)?;
        ensure!(
            identity["whole_remote_readback"] == true && active_holding()?.is_empty(),
            "serial holding slot remains occupied"
        );
        ensure!(
            q["epoch157_lanej_rotation"]["operator_seal"] == seal,
            "provider has not registered this exact serial operator"
        );
        if phase == "restore" {
            budget = LENGTH + META;
            floor = floor0.max(required.saturating_sub(budget));
        } else {
            ensure!(
                root("RESTORE_QUALIFICATION.json").is_file(),
                "fixture is not accepted"
            );
        }
    } else {
        let u = &q["closed_167_suballocations"]["unassigned"];
        ensure!(
            num(u, "ram_bytes")? >= mem
                && num(u, "cpu_micros_per_second")? >= cpu
                && num(u, "home_bytes")? >= META,
            "previously paid share is occupied"
        );
    }
    ensure!(
        q["fits"] == true && free >= floor.checked_add(budget).context("capacity overflow")?,
        "fresh roster refuses {phase}: HOME margin {}, RAM margin {}, HOME above callback floor {}",
        q["home_margin"],
        q["ram_margin"],
        i128::from(free) - i128::from(floor) - i128::from(budget)
    );
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let unit = service(phase, &nonce);
    let path = intake(phase, &unit)?;
    let native = receipt(
        &root(&format!(
            "{}_FULL_ROSTER_{nonce}.json",
            phase.to_uppercase()
        )),
        &q,
    )?;
    let admission = receipt(
        &path,
        &json!({"phase":phase,"unit":unit,"fits":true,"operator_seal":seal,"issued":now()?,"floor":floor,"maximum_evidence":META,"memory_max":mem,"cpu_micros":cpu,"swap":0,"provider":q["package"],"whole_roster":native,"serial_holding_slot":serial,"restore_bytes":LENGTH+META,"serial_slot_bytes":123350028052u64,"resource_credit_bytes":0,"canonical_publication":false}),
    )?;
    let stdout = root(&format!("{}_RESULT_{nonce}.json", phase.to_uppercase()));
    let stderr = root(&format!("{}_STDERR_{nonce}", phase.to_uppercase()));
    let image = member(&seal, "rotation")?;
    let mut props = vec![
        "Type=exec".to_string(),
        "User=root".into(),
        "Group=root".into(),
        "UMask=0077".into(),
        "ProtectSystem=strict".into(),
        "ProtectHome=read-only".into(),
        format!("ReadWritePaths={ROOT}"),
        "PrivateDevices=yes".into(),
        "NoNewPrivileges=yes".into(),
        "PrivateTmp=yes".into(),
        format!("MemoryMax={mem}"),
        "MemorySwapMax=0".into(),
        format!("CPUQuota={}%", cpu / 10000),
        "TasksMax=32".into(),
        "LimitCORE=0".into(),
        "Restart=no".into(),
        "Nice=12".into(),
        "IOSchedulingClass=idle".into(),
        "EnvironmentFile=/etc/jetstreamer/horizon-r2.env".into(),
        format!("StandardOutput=file:{}", stdout.display()),
        format!("StandardError=file:{}", stderr.display()),
        format!(
            "Environment=HORIZON157_ADMISSION_SHA={}",
            word(&admission, "sha256")?
        ),
    ];
    if serial {
        props.push(format!(
            "ReadWritePaths={}",
            Path::new(SRC).parent().unwrap().display()
        ));
        props.push("RuntimeMaxSec=4h".into())
    } else {
        props.push("RuntimeMaxSec=12min".into())
    }
    let mut args = vec![
        "--quiet".to_string(),
        "--collect".to_string(),
        format!("--unit={unit}"),
        format!(
            "--slice={}",
            if serial {
                "system.slice"
            } else {
                "horizonaudit.slice"
            }
        ),
    ];
    args.extend(props.into_iter().map(|p| format!("--property={p}")));
    args.extend(["--".into(), image.display().to_string(), phase.to_string()]);
    command("/usr/bin/systemd-run", &args)?;
    let row = props_native(&unit)?;
    let invocation = if row["InvocationID"].is_empty() {
        // A short transient service can drain before systemctl's reply. Its native entry
        // records the invocation under the immutable admission generated for this dispatch.
        let prefix = format!("{}_NATIVE_ENTRY_", phase.to_uppercase());
        let mut entries = Vec::new();
        for p in fs::read_dir(ROOT)? {
            let path = p?.path();
            if path
                .file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| f.starts_with(&prefix) && f.ends_with(".json"))
            {
                let entry = bound(&reference(&path)?)?;
                if entry["unit"] == unit && entry["admission"] == admission {
                    entries.push(word(&entry, "invocation")?.to_string())
                }
            }
        }
        ensure!(
            entries.len() == 1,
            "reconcile actual native start for {unit}"
        );
        entries.pop().unwrap()
    } else {
        row["InvocationID"].clone()
    };
    ensure!(
        invocation.len() == 32 && invocation.bytes().all(|b| b.is_ascii_hexdigit()),
        "reconcile actual native start"
    );
    receipt(
        &root(&format!("{}_START_{nonce}.json", phase.to_uppercase())),
        &json!({"unit":unit,"invocation":invocation,"native":row,"admission":admission,"stdout":stdout,"stderr":stderr,"argv":args}),
    )
}
fn props_native(unit: &str) -> Result<std::collections::BTreeMap<String, String>> {
    props(
        unit,
        "Id,LoadState,InvocationID,MainPID,ControlPID,ActiveState,SubState,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,ControlGroup,Job,Result",
    )
}
