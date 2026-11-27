//! Match the actual service, frozen writable leaf, projected inputs and native worker.
use super::*;
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
pub(super) fn actor(held: bool) -> Result<Value> {
    let state = props(
        UNIT,
        "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NRestarts,Job",
    )?;
    ensure!(
        state["Id"] == UNIT
            && state["ActiveState"] == "active"
            && state["SubState"] == "running"
            && state["NRestarts"] == "0"
            && state["ControlPID"] == "0"
            && state["Job"].is_empty(),
        "no stable 170 producer"
    );
    ensure!(
        state["MemoryMax"] == (48 * G).to_string()
            && state["MemorySwapMax"] == "0"
            && state["CPUQuotaPerSecUSec"] == "6s",
        "effective 170 compute differs"
    );
    let iid = &state["InvocationID"];
    ensure!(
        iid.len() == 32
            && iid.bytes().all(|b| b.is_ascii_hexdigit())
            && iid.bytes().any(|b| b != b'0'),
        "invalid invocation"
    );
    let pid: u32 = state["MainPID"].parse()?;
    let start = ticks(pid)?;
    let group = format!("/system.slice/{UNIT}");
    ensure!(
        state["ControlGroup"] == group
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim() == format!("0::{group}"),
        "wrong cgroup"
    );
    let cg = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    let ids = fs::read_to_string(cg.join("cgroup.procs"))?
        .split_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<Vec<u32>, _>>()?;
    let path = PathBuf::from(format!("/proc/{pid}"));
    let exe = path.join("exe");
    let expected = if held {
        base().join("bridge-73726716/gate")
    } else {
        PathBuf::from(NODE)
    };
    ensure!(
        inode(&exe)? == inode(&expected)? && ids.contains(&pid) && (!held || ids == [pid]),
        "unexpected executable or process extent"
    );
    let identity = fs::read_to_string(path.join("status"))?;
    for (field, id) in [("Uid:", 1001), ("Gid:", 1003)] {
        let line = identity
            .lines()
            .find_map(|l| l.strip_prefix(field))
            .context("no identity")?;
        ensure!(
            line.split_whitespace().all(|n| n.parse::<u32>() == Ok(id)),
            "wrong service identity"
        )
    }
    let cmd = fs::read(path.join("cmdline"))?;
    let args = cmd
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(std::str::from_utf8)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if held {
        ensure!(args == [format!("{ALIAS}/bridge-gate")], "wrong gate argv")
    } else {
        ensure!(
            args.contains(&"--qualification-end-slot=73726716")
                && args.contains(
                    &format!("--horizon-output={RUN}/ledger/epoch-170.bridge-73726716.jet")
                        .as_str()
                ),
            "wrong live replay route"
        )
    }
    let v = bound(&reference(&base().join("BRIDGE_LAYOUT_AND_MOUNTS.json"))?)?;
    let mounts = fs::read_to_string(path.join("mountinfo"))?;
    for (target, object) in v["observed_bindings"]
        .as_object()
        .context("no input projections")?
    {
        let mounted = path.join("root").join(target.trim_start_matches('/'));
        let meta = fs::metadata(&mounted)?;
        ensure!(
            object[0] == meta.dev()
                && object[1] == meta.ino()
                && (object[2].is_null() || object[2] == meta.len()),
            "replaced input {target}"
        );
        let matches = mounts
            .lines()
            .filter_map(|line| {
                let cols = line.split_whitespace().take(6).collect::<Vec<_>>();
                (cols.len() == 6 && cols[4] == target).then(|| cols[5])
            })
            .collect::<Vec<_>>();
        ensure!(
            matches.iter().any(|s| s.split(',').any(|x| x == "ro")),
            "input has no read-only projection {target}"
        );
    }
    let mut worker = Value::Null;
    let mut processes = Vec::new();
    for other in ids {
        let ex = PathBuf::from(format!("/proc/{other}/exe"));
        let tick = ticks(other)?;
        let (dev, ino) = inode(&ex)?;
        processes.push(json!([other, tick, dev, ino]));
        if other != pid {
            let link = fs::read_link(&ex)?;
            ensure!(
                link.starts_with(Path::new(RUN).join("scratch/bridge-73726716"))
                    && worker.is_null(),
                "foreign process in 170 cgroup: {}",
                link.display()
            );
            let bytes = fs::read(&ex)?;
            ensure!(
                digest(&bytes) == WORKER_SHA && ticks(other)? == tick,
                "worker digest or start time differs"
            );
            worker = json!({"pid":other,"start_ticks":tick,"exe_device":dev,"exe_inode":ino,"path":link,"sha256":WORKER_SHA});
        }
    }
    ensure!(
        ticks(pid)? == start
            && props(UNIT, "Id,LoadState,ActiveState,MainPID,InvocationID,Job")?["InvocationID"]
                == *iid,
        "170 actor changed"
    );
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let (dev, ino) = inode(&exe)?;
    Ok(
        json!({"unit":UNIT,"producer_unit":UNIT,"producer_invocation_id":iid,"invocation_id":iid,"producer_pid":pid,"pid":pid,"start_ticks":start,"boot_id":boot.trim(),"cgroup":group,"exe_device":dev,"exe_inode":ino,"processes":processes,"worker":worker}),
    )
}
pub(super) fn same(a: &Value, b: &Value) -> bool {
    [
        "producer_unit",
        "producer_invocation_id",
        "producer_pid",
        "start_ticks",
        "boot_id",
    ]
    .iter()
    .all(|&k| !a[k].is_null() && a[k] == b[k])
}
pub(super) fn guard_sample(a: &Value, plan: &Value, need_worker: bool) -> Result<Value> {
    let root = base();
    let gp = bound(plan)?;
    let dir = root.join("guard-receipts");
    ensure!(!dir.join("stop-intent.json").exists(), "170 guard stopped");
    let tm = props(
        TIMER,
        "Id,LoadState,ActiveState,InvocationID,Unit,Result,Job",
    )?;
    ensure!(
        tm["ActiveState"] == "active"
            && tm["Unit"] == GUARD_UNIT
            && tm["Result"] == "success"
            && tm["Job"].is_empty(),
        "170 guard timer inactive"
    );
    let mut samples = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let p = entry?.path();
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("sample-") && n.ends_with(".json"))
        {
            samples.push((p.metadata()?.modified()?, p));
        }
    }
    samples.sort_by_key(|item| std::cmp::Reverse(item.0));
    let mut chosen = None;
    for (_, p) in samples.into_iter().take(5) {
        let r = reference(&p)?;
        let s = bound(&r)?;
        if s["producer_invocation_id"] != a["producer_invocation_id"]
            || s["plan_sha256"] != plan["sha256"]
            || !s["trip_reason"].is_null()
            || s["producer_stop_enabled"] != true
        {
            continue;
        }
        if need_worker
            && !s["workers"]
                .as_array()
                .is_some_and(|w| w.iter().any(|x| x[0] == a["worker"]["pid"]))
        {
            continue;
        }
        ensure!(
            s["maximum_root_physical_bytes"] == gp["maximum_root_physical_bytes"]
                && s["minimum_free_bytes"] == gp["minimum_free_bytes"]
                && s.get("guard_sha256")
                    .or_else(|| s.get("self_sha256"))
                    .is_some_and(|v| v == GUARD_SHA)
                && s["producer"]["pid"] == a["producer_pid"]
                && s["producer"]["cgroup"] == a["cgroup"],
            "crossed guard sample"
        );
        let t = num(&s, "recorded_unix_seconds")?;
        if now()?.saturating_sub(t) > 100 || t > now()? {
            continue;
        }
        let physical = num(
            &s["root_physical_observation"],
            "conservative_physical_bytes",
        )?;
        ensure!(
            s["root_physical_observation_error"].is_null()
                && physical <= num(&gp, "maximum_root_physical_bytes")?
                && num(&s, "available_bytes")? >= num(&gp, "minimum_free_bytes")?,
            "dirty or nonfitting guard observation"
        );
        chosen = Some(
            json!({"sample":r,"guard_invocation_id":s["guard_invocation_id"],"timer_invocation_id":tm["InvocationID"],"floor":gp["minimum_free_bytes"],"cap":gp["maximum_root_physical_bytes"],"physical_bytes":physical,"available_home":s["available_bytes"],"workers":s["workers"],"recorded_unix_seconds":t}),
        );
        break;
    }
    chosen.context("no clean recent native guard sample for this actor")
}
pub(super) fn progress(a: &Value) -> Result<Value> {
    ensure!(!a["worker"].is_null(), "worker has not started");
    let log = Path::new(RUN).join("producer.log");
    let meta = fs::symlink_metadata(&log)?;
    let layout = bound(&reference(&base().join("STATIC_LAYOUT.json"))?)?;
    ensure!(
        meta.dev() == layout["producer_log"]["device"]
            && meta.ino() == layout["producer_log"]["inode"]
            && meta.uid() == 0
            && meta.nlink() == 1,
        "replaced root-owned log"
    );
    let mut f = fs::File::open(log)?;
    let len = meta.len();
    f.seek(SeekFrom::Start(len.saturating_sub(4 << 20)))?;
    let mut bytes = Vec::new();
    f.take(4 << 20).read_to_end(&mut bytes)?;
    for line in String::from_utf8_lossy(&bytes).lines().rev() {
        for label in ["] block slot ", "] progress slot "] {
            if let Some((_, tail)) = line.split_once(label) {
                let n = tail
                    .split(|c: char| !c.is_ascii_digit())
                    .next()
                    .context("missing slot")?
                    .parse::<u64>()?;
                if (73706461..=73726716).contains(&n) {
                    return Ok(json!({"slot":n,"log_line":line,"inode":meta.ino(),"bytes":len}));
                }
            }
        }
    }
    bail!("worker is still bootstrapping; no advancing slot in this invocation")
}
