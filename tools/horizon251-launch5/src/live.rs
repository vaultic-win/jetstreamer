//! Preserve all four live owners while admitting the isolated fifth lane.
use super::*;

pub(super) struct Owner {
    pub epoch: u64,
    pub unit: &'static str,
    pub iid: &'static str,
    pub guard: &'static str,
    pub timer: &'static str,
    pub cpus: &'static str,
    pub handoff: &'static str,
    pub handoff_sha: &'static str,
    pub schema: &'static str,
}
pub(super) const OWNERS: [Owner; 4] = [
    Owner {
        epoch: 247,
        unit: LIVE247_UNIT,
        iid: LIVE247_IID,
        guard: LIVE247_GUARD,
        timer: LIVE247_TIMER,
        cpus: "80-95",
        handoff: LIVE247_HANDOFF,
        handoff_sha: LIVE247_HANDOFF_SHA,
        schema: "horizon247-reboot-guarded-startup-v1",
    },
    Owner {
        epoch: 248,
        unit: LIVE248_UNIT,
        iid: LIVE248_IID,
        guard: LIVE248_GUARD,
        timer: LIVE248_TIMER,
        cpus: "96-111",
        handoff: LIVE248_HANDOFF,
        handoff_sha: LIVE248_HANDOFF_SHA,
        schema: "horizon248-reboot-guarded-startup-v1",
    },
    Owner {
        epoch: 249,
        unit: LIVE249_UNIT,
        iid: LIVE249_IID,
        guard: LIVE249_GUARD,
        timer: LIVE249_TIMER,
        cpus: "64-79",
        handoff: LIVE249_HANDOFF,
        handoff_sha: LIVE249_HANDOFF_SHA,
        schema: "horizon249-reboot-guarded-startup-v1",
    },
    Owner {
        epoch: 250,
        unit: "horizon-qualify-250-reboot-20261117-v1.service",
        iid: "a59fe93cc1d443abbb33317600227600",
        guard: "horizon-250-reboot-20261117-protective-v1.service",
        timer: "horizon-250-reboot-20261117-protective-v1.timer",
        cpus: "64-79",
        handoff: "/var/lib/jetstreamer/horizon250-reboot-20261117-state-v2/launch-v1/guarded-startup-handoff.json",
        handoff_sha: "27ab9b1d011881944834c882e3c139c4aa1e156bbbfe36a4a58f4c3cf8b06ff4",
        schema: "horizon250-reboot-guarded-startup-v2",
    },
];
const PROPS: &str = "MemoryHigh,MemoryMax,MemorySwapMax,AllowedCPUs,CPUAffinity";

fn validate(o: &Owner, v: &BTreeMap<String, String>) -> Result<u32> {
    for (k, want) in [
        ("Id", o.unit),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", o.iid),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryMax", "251041591296"),
        ("MemoryHigh", "167361060864"),
        ("MemorySwapMax", "0"),
        ("AllowedCPUs", o.cpus),
        ("CPUAffinity", o.cpus),
    ] {
        ensure!(row(v, k)? == want, "live epoch {} {k} changed", o.epoch);
    }
    ensure!(
        row(v, "ControlGroup")? == format!("/system.slice/{}", o.unit),
        "live cgroup changed"
    );
    let pid = row(v, "MainPID")?.parse::<u32>()?;
    ensure!(pid > 0, "live producer missing");
    Ok(pid)
}
pub(super) fn handoffs(a: &Value) -> Result<()> {
    for o in &OWNERS {
        ensure!(
            a[format!("live{}_unit", o.epoch)] == o.unit
                && a[format!("live{}_invocation_id", o.epoch)] == o.iid,
            "live owner missing/changed"
        );
        let r = &a[format!("live{}_handoff", o.epoch)];
        ensure!(
            *r == json!({"path":o.handoff,"sha256":o.handoff_sha}),
            "wrong handoff binding"
        );
        live_handoff_values(&bound(r)?, o.schema, o.unit, o.iid)?;
    }
    Ok(())
}
pub(super) fn census(n: &mut Native, a: &Value, allow_candidate: bool) -> Result<()> {
    ensure!(!allow_candidate, "census only before candidate startup");
    let mut before = Vec::new();
    let mut pids = Vec::new();
    let mut mains = BTreeSet::new();
    for o in &OWNERS {
        let (v, _) = n.show(o.unit, PROPS)?;
        let main = validate(o, &v)?;
        ensure!(mains.insert(main), "duplicate producer PID");
        let (timer, _) = n.show(o.timer, "Unit,NextElapseUSecMonotonic")?;
        for (k, want) in [
            ("Id", o.timer),
            ("LoadState", "loaded"),
            ("ActiveState", "active"),
            ("SubState", "waiting"),
            ("Unit", o.guard),
        ] {
            ensure!(row(&timer, k)? == want, "live timer changed: {}", o.timer);
        }
        ensure!(
            !row(&timer, "NextElapseUSecMonotonic")?.is_empty(),
            "timer not scheduled"
        );
        let set: BTreeSet<u32> = fs::read_to_string(format!(
            "/sys/fs/cgroup/system.slice/{}/cgroup.procs",
            o.unit
        ))?
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
        ensure!(set.contains(&main), "producer outside cgroup");
        for old in &pids {
            ensure!(set.is_disjoint(old), "overlapping cgroup membership");
        }
        before.push(v);
        pids.push(set);
    }
    let bytes = n.run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--all",
            "--type=service",
            "--state=active,activating,deactivating,reloading",
            "--output=json",
            "--no-pager",
        ],
    )?;
    let list: Value = serde_json::from_slice(&bytes)?;
    for x in list.as_array().context("unit census")? {
        let name = text(x, "unit")?;
        if !["horizon", "jetstreamer", "archive"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        if name == text(a, "launcher_unit")?
            || OWNERS.iter().any(|o| name == o.unit || name == o.guard)
        {
            continue;
        }
        let entry = a["coexisting_services"]
            .as_array()
            .context("auxiliaries")?
            .iter()
            .find(|e| e["unit"] == name)
            .context(format!("unexpected busy campaign service {name}"))?;
        ensure!(
            !name.contains("qualify") && !name.contains("replay"),
            "extra replay cannot be auxiliary"
        );
        let (v, _) = n.show(name, "")?;
        ensure!(
            row(&v, "Id")? == name
                && row(&v, "InvocationID")? == text(entry, "invocation_id")?
                && iid(row(&v, "InvocationID")?)
                && row(&v, "ActiveState")? == "active"
                && row(&v, "NRestarts")? == text(entry, "restart_count")?,
            "auxiliary changed"
        );
    }
    closed(
        &n.show(
            "horizon-qualify-247-general-shrink-debt-budget506-e3f15eb2-v1.service",
            "",
        )?
        .0,
    )?;
    let mut seen_main = [false; 4];
    let mut workers = [0u32; 4];
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let cmd = match fs::read(e.path().join("cmdline")) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let name = cmd
            .split(|b| *b == 0)
            .next()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        if ![
            "/jetstreamer-node",
            "/jetstreamer-historical-worker-v1-7-15",
            "/bound-worker/historical-worker",
        ]
        .iter()
        .any(|s| name.ends_with(s))
        {
            continue;
        }
        let index = pids
            .iter()
            .position(|set| set.contains(&pid))
            .context(format!("unexpected replay PID {pid}"))?;
        if pid == row(&before[index], "MainPID")?.parse::<u32>()? {
            ensure!(
                hash(&e.path().join("exe"))?
                    == "362e928c778c171dff190c2efcf631a7fc9675b96be4f1b699e433993ac365a1",
                "node image changed"
            );
            seen_main[index] = true;
        } else {
            ensure!(
                hash(&e.path().join("exe"))?
                    == "c3b2c33420bcf6b6809d7f0b43309e7d57d2791a88e2d4074d21d4f636c521e4",
                "worker image changed"
            );
            workers[index] += 1;
        }
    }
    ensure!(
        seen_main.iter().all(|v| *v) && workers.iter().all(|n| *n > 0),
        "missing producer or worker"
    );
    for (i, o) in OWNERS.iter().enumerate() {
        let (after, _) = n.show(o.unit, PROPS)?;
        ensure!(
            validate(o, &after)? == row(&before[i], "MainPID")?.parse::<u32>()?,
            "producer changed during census"
        );
        let after_pids: BTreeSet<u32> = fs::read_to_string(format!(
            "/sys/fs/cgroup/system.slice/{}/cgroup.procs",
            o.unit
        ))?
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
        ensure!(after_pids == pids[i], "cgroup changed during census");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_live_limit_and_identity_is_retained() {
        for o in &OWNERS {
            let mut v: BTreeMap<String, String> = [
                ("Id", o.unit),
                ("LoadState", "loaded"),
                ("ActiveState", "active"),
                ("SubState", "running"),
                ("InvocationID", o.iid),
                ("NRestarts", "0"),
                ("Restart", "no"),
                ("KillMode", "control-group"),
                ("Delegate", "no"),
                ("MemoryMax", "251041591296"),
                ("MemoryHigh", "167361060864"),
                ("MemorySwapMax", "0"),
                ("AllowedCPUs", o.cpus),
                ("CPUAffinity", o.cpus),
                ("MainPID", "123"),
            ]
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
            v.insert("ControlGroup".into(), format!("/system.slice/{}", o.unit));
            validate(o, &v).unwrap();
            for (k, bad) in [
                ("InvocationID", "old"),
                ("MemoryMax", "128000000000"),
                ("NRestarts", "1"),
                ("AllowedCPUs", "0-15"),
                ("MainPID", "0"),
            ] {
                let mut changed = v.clone();
                changed.insert(k.into(), bad.into());
                assert!(validate(o, &changed).is_err(), "{} {k}", o.epoch);
            }
        }
    }
}
