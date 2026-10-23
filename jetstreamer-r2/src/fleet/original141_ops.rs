//! Exact private141 layout/admission/capture. No service is launched here.
use super::*;
use std::{
    ffi::CString,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
};
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const GENESIS: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-native-restore-inputs-20261020-v1/genesis.tar.bz2";
const GENESIS_SHA: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
const RANGES: [&str; 5] = ["152-153", "155-156", "191-194", "183-184", "185-185"];
const GUARDS: [&str; 5] = [
    "jetstreamer-adaptive-reserve-controller-rebind-152-153-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-155-156-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-191-194-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-183-184-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1.service",
];
#[path = "original141_growth.rs"]
mod growth_bridge;
#[path = "original141_guard_pin.rs"]
mod guard_pin;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Guard {
    unit: String,
    command_sha256: String,
    intent: PathBuf,
    completion: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    floor: BoundFile,
    layout: BoundFile,
    growth: BTreeMap<String, BoundFile>,
    growth_extension_observers: Vec<BoundFile>,
    guards: BTreeMap<String, Guard>,
    output: PathBuf,
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn sealed_file(b: &BoundFile) -> Result<()> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.is_absolute()
            && b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0,
        "unsealed original141 input"
    );
    Ok(())
}
fn self_ok(sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "original141 operations require root"
    );
    let own = fs::read_link("/proc/self/exe")?;
    let b = BoundFile {
        path: own,
        sha256: sha.into(),
    };
    sealed_file(&b)?;
    ensure!(
        hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == sha,
        "original141 self digest differs"
    );
    Ok(())
}
fn spec_args() -> Result<(BoundFile, String, bool)> {
    let a: Vec<_> = env::args().collect();
    let check = a.len() == 8 && a[7] == "--check-only";
    ensure!(
        (a.len() == 7 || check) && a[3] == "--spec-sha256" && a[5] == "--self-sha256",
        "usage: original141-command SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    self_ok(&a[6])?;
    let b = BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    sealed_file(&b)?;
    Ok((b, a[6].clone(), check))
}
fn require_absent(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "original141 path occupied or unreadable:{}",
        path.display()
    );
    Ok(())
}
fn dormant() -> Result<Value> {
    let u = unit(UNIT)?;
    ensure!(
        u["MainPID"] == "0"
            && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
            && u["NRestarts"] == "0",
        "original141 owner is already active/restarted"
    );
    Ok(u)
}
fn owned_directory(path: &Path, uid: u32, gid: u32) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0,
        "original141 directory ownership failed"
    );
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Ok(())
}
fn genesis_bytes() -> Result<Vec<u8>> {
    let b = BoundFile {
        path: GENESIS.into(),
        sha256: GENESIS_SHA.into(),
    };
    sealed_file(&b)?;
    let bytes = read_stable_bounded(&b.path, 8 * 1024 * 1024, "original141 genesis")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == GENESIS_SHA,
        "original141 genesis digest differs"
    );
    Ok(bytes)
}
pub(super) fn prepare() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 4 && a[2] == "--self-sha256",
        "usage: prepare-original141-layout --self-sha256 SHA"
    );
    self_ok(&a[3])?;
    let before = dormant()?;
    let root = Path::new(ROOT);
    require_absent(root)?;
    let parent = root.parent().context("private parent")?;
    ensure!(
        parent.canonicalize()? == parent && fs::metadata(parent)?.is_dir(),
        "private parent differs"
    );
    let bytes = genesis_bytes()?;
    owned_directory(root, 1001, 1003)?;
    for name in ["destination", "output", "scratch"] {
        owned_directory(&root.join(name), 1001, 1003)?;
    }
    owned_directory(&root.join("receipts"), 0, 0)?;
    let path = root.join("destination/genesis.tar.bz2");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    ensure!(
        dormant()? == before,
        "original141 owner changed during layout"
    );
    private157::immutable_receipt(
        &root.join("receipts/layout.json"),
        &json!({"schema":"jetstreamer-original141-private-layout-v2","epoch":141,"run_root":ROOT,"uid":1001,"gid":1003,"genesis_sha256":GENESIS_SHA,"genesis_bytes":bytes.len(),"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"self_sha256":a[3],"recorded_unix_seconds":now()?}),
    )?;
    println!("original141 private layout and verified genesis staged; no launch");
    Ok(())
}
fn accepted(s: &Spec, o: &Value, f: &Value, p: &Value, time: u64) -> Result<()> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("sample clock")?)?;
    ensure!(
        s.schema == "jetstreamer-original141-root-admission-spec-v2"
            && admission_path(&s.output)
            && s.floor.sha256 == FLOOR_SHA
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && t <= time
            && time - t <= 1800
            && f["schema"] == super::super::SCHEMA
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["plan"].as_str() == s.fleet_plan.path.to_str()
            && f["plan_sha256"] == s.fleet_plan.sha256
            && p["observer"] == private157::binding(&s.observer)
            && f["inventory"]["anomalies"] == 0,
        "original141 stale/foreign/unaccepted admission basis"
    );
    if s.output != Path::new(ADMISSION) {
        let stamp = o["recorded_at_utc"]
            .as_str()
            .context("admission sample clock")?
            .replace(['-', ':'], "");
        ensure!(
            s.output.file_name().and_then(|s| s.to_str())
                == Some(format!("admission-{stamp}.json").as_str()),
            "admission filename must bind exact sample"
        );
    }
    ensure!(
        o["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= FLOOR + PEAK)
            && o["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 256 * 1024 * 1024)
            && o["vm_max_map_count"].as_u64().is_some_and(|n| n >= 4194304),
        "original141 sampled envelope unavailable"
    );
    let rows = o["replays"].as_array().context("replay census")?;
    ensure!(
        rows.len() == RANGES.len()
            && rows
                .iter()
                .filter_map(|r| r["range"].as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(RANGES),
        "original141 must preserve exact five lanes"
    );
    for r in rows {
        ensure!(
            r["invocation_binding_stable"] == true
                && r["controller_after"]["restarts"] == 0
                && r["producer_after"]["restarts"] == 0
                && r["worker_after"]["matching_workers"] == 1
                && r["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 800000)
                && r["useful_work"]["sufficient_for_rates"] == true
                && r["useful_work"]["slots_per_second"]
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n > 0.),
            "original141 existing lane unstable/not advancing"
        );
        for key in [
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
            "memory_events.max",
        ] {
            ensure!(
                r["cross_sample"]["producer_cgroup_counter_delta"][key] == 0,
                "original141 existing memory event:{key}"
            );
        }
    }
    let epoch = f["epochs"]
        .as_array()
        .context("epoch census")?
        .iter()
        .filter(|e| e["epoch"] == 141)
        .collect::<Vec<_>>();
    ensure!(
        epoch.len() == 1
            && epoch[0]["state"] == "failed-needs-repair"
            && f["active"]
                .as_array()
                .context("active census")?
                .iter()
                .all(|e| e["epoch"] != 141),
        "original141 already claimed or repair incident relabeled"
    );
    ensure!(
        s.growth.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["152-153", "155-156", "191-194"])
            && s.guards.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(RANGES),
        "original141 incomplete growth/guard census"
    );
    Ok(())
}
fn growth(s: &Spec, floor: u64) -> Result<(u64, Value)> {
    ensure!(
        floor == 205211459014,
        "original141 century floor changed; review policy"
    );
    let evidence = growth_bridge::extend(s)?;
    let formula = floor
        .checked_add(3 * (512u64 << 30))
        .and_then(|n| n.checked_add(2 * (768u64 << 30)))
        .and_then(|n| n.checked_add(32u64 << 30))
        .context("protection overflow")?;
    Ok((FLOOR.max(formula), evidence))
}
fn layout(s: &Spec) -> Result<()> {
    ensure!(
        s.layout.path == Path::new(ROOT).join("receipts/layout.json"),
        "original141 foreign layout"
    );
    let l = bound_json(&s.layout)?;
    ensure!(
        l["schema"] == "jetstreamer-original141-private-layout-v2"
            && l["run_root"] == ROOT
            && l["uid"] == 1001
            && l["gid"] == 1003
            && l["genesis_sha256"] == GENESIS_SHA,
        "original141 layout proof differs"
    );
    for name in ["", "destination", "output", "scratch"] {
        let path = Path::new(ROOT).join(name);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path
                && m.is_dir()
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o777 == 0o700,
            "original141 private writable path differs"
        );
    }
    for name in ["output", "scratch"] {
        ensure!(
            fs::read_dir(Path::new(ROOT).join(name))?.next().is_none(),
            "original141 layout is no longer empty"
        );
    }
    let entries = fs::read_dir(Path::new(ROOT).join("destination"))?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        entries == [std::ffi::OsString::from("genesis.tar.bz2")],
        "original141 destination is no longer genesis-only"
    );
    let bytes = read_stable_bounded(
        &Path::new(ROOT).join("destination/genesis.tar.bz2"),
        8 * 1024 * 1024,
        "private genesis",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(bytes)) == GENESIS_SHA,
        "original141 private genesis changed"
    );
    Ok(())
}
fn latest_fleet(s: &Spec, f: &Value) -> Result<()> {
    let time = utc_seconds(f["sampled_at_utc"].as_str().context("fleet clock")?)?;
    let recorded = f["recorded_unix_seconds"]
        .as_u64()
        .context("fleet record clock")?;
    let root = s.fleet.path.parent().context("fleet root")?;
    ensure!(
        root == Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"),
        "foreign fleet directory"
    );
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().is_none_or(|e| e != "json") || path == s.fleet.path {
            continue;
        }
        let v: Value = serde_json::from_slice(&read_stable_bounded(
            &path,
            16 * 1024 * 1024,
            "fleet census",
        )?)?;
        if v["schema"] == super::super::SCHEMA && v["first_epoch"] == 101 && v["last_epoch"] == 200
        {
            let t = utc_seconds(
                v["sampled_at_utc"]
                    .as_str()
                    .context("fleet candidate clock")?,
            )?;
            ensure!(
                t < time
                    || (t == time
                        && v["recorded_unix_seconds"]
                            .as_u64()
                            .context("candidate record clock")?
                            < recorded),
                "newer/tied fleet invalidates original141 admission"
            );
        }
    }
    Ok(())
}
fn journal_guard(value: &Value, contract: &Guard, row: &Value, time: u64) -> Result<Value> {
    ensure!(
        value["_SYSTEMD_UNIT"] == contract.unit
            && value["_UID"] == "0"
            && value["_SYSTEMD_INVOCATION_ID"]
                .as_str()
                .is_some_and(invocation),
        "foreign guard journal identity"
    );
    let t = value["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("guard journal clock")?
        .parse::<u64>()?
        / 1000000;
    ensure!(t <= time && time - t <= 180, "stale/future guard journal");
    let g: Value = serde_json::from_str(value["MESSAGE"].as_str().context("guard message")?)?;
    ensure!(
        g["armed"] == true
            && g["trip"] == false
            && g["maximum_worker_vmas"] == 800000
            && g["minimum_free_bytes"].as_u64().is_some_and(|n| n > 0)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b)
            && g["producer"]["worker_count"] == 1
            && g["producer"]["worker_vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 800000),
        "existing guard is not clean and armed"
    );
    for kind in ["controller", "producer"] {
        ensure!(
            g[kind]["invocation_id"] == row[format!("{kind}_after")]["invocation_id"]
                && g[kind]["unit"] == row[format!("{kind}_after")]["unit"]
                && g[kind]["restarts"] == 0
                && g[kind]["active_state"] == "active"
                && g[kind]["sub_state"] == "running",
            "guard owner changed"
        );
    }
    Ok(
        json!({"journal_cursor":value["__CURSOR"],"realtime_timestamp":value["__REALTIME_TIMESTAMP"],"invocation_id":value["_SYSTEMD_INVOCATION_ID"],"guard":g}),
    )
}
fn guards(s: &Spec, o: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (i, range) in RANGES.iter().enumerate() {
        let c = &s.guards[*range];
        ensure!(c.unit == GUARDS[i], "original141 guard unit differs");
        require_absent(&c.intent)?;
        require_absent(&c.completion)?;
        let current = unit(&c.unit)?;
        ensure!(
            current["Result"] == "success"
                && current["ExecMainStatus"] == "0"
                && current["NRestarts"] == "0",
            "existing guard failed"
        );
        let command = super::command(&current["ExecStart"]).context("guard command")?;
        ensure!(
            command.contains(&format!("--intent-receipt={}", c.intent.display()))
                && command.contains(&format!("--completion-receipt={}", c.completion.display())),
            "guard absence paths differ from actual command"
        );
        let timer = ProcessCommand::new("systemctl")
            .args([
                "is-active",
                "--quiet",
                &c.unit.replace(".service", ".timer"),
            ])
            .output()?;
        ensure!(timer.status.success(), "existing guard timer is not armed");
        ensure!(
            hex_lower(&Sha256::digest(command.as_bytes())) == c.command_sha256,
            "guard command changed"
        );
        let out = ProcessCommand::new("journalctl")
            .args([
                "--unit",
                &c.unit,
                "--output=json",
                "--no-pager",
                "--lines=24",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() <= 1024 * 1024,
            "guard journal observation failed"
        );
        let row = o["replays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["range"] == *range)
            .context("guard replay")?;
        let mut found = None;
        for line in std::str::from_utf8(&out.stdout)?.lines().rev() {
            let v: Value = serde_json::from_str(line)?;
            if v["_SYSTEMD_UNIT"] == c.unit
                && v["MESSAGE"].as_str().is_some_and(|m| m.starts_with('{'))
            {
                found = Some(journal_guard(&v, c, row, now()?)?);
                break;
            }
        }
        result.insert(
            (*range).into(),
            found.context("fresh no-trip guard journal missing")?,
        );
        require_absent(&c.intent)?;
        require_absent(&c.completion)?;
    }
    Ok(Value::Object(result))
}
fn cpu_budget(o: &Value) -> Result<Value> {
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &mut affinity) } == 0,
        "CPU affinity unavailable"
    );
    let cpus = unsafe { libc::CPU_COUNT(&affinity) } as u64;
    let mut units = serde_json::Map::new();
    let mut total = 0u64;
    for (range, quota) in [
        ("152-153", 9u64),
        ("155-156", 9),
        ("191-194", 8),
        ("183-184", 8),
        ("185-185", 8),
    ] {
        let row = o["replays"]
            .as_array()
            .context("CPU owner census")?
            .iter()
            .find(|r| r["range"] == range)
            .context("CPU owner missing")?;
        let name = row["producer_after"]["unit"]
            .as_str()
            .context("CPU producer unit")?;
        let out = ProcessCommand::new("systemctl")
            .args([
                "show",
                name,
                "--no-pager",
                "--property=InvocationID,CPUQuotaPerSecUSec",
            ])
            .output()?;
        ensure!(
            out.status.success() && out.stdout.len() < 4096,
            "CPU quota observation failed"
        );
        let text = std::str::from_utf8(&out.stdout)?;
        let p: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
        ensure!(
            p.get("InvocationID").copied() == row["producer_after"]["invocation_id"].as_str()
                && p.get("CPUQuotaPerSecUSec")
                    .is_some_and(|v| *v == format!("{quota}s")),
            "CPU owner/quota changed"
        );
        total = total.checked_add(quota).context("CPU sum overflow")?;
        units.insert(range.into(),json!({"unit":name,"invocation_id":row["producer_after"]["invocation_id"],"quota_cores":quota}));
    }
    ensure!(
        cpus >= total + 2 + 8,
        "CPU envelope cannot fit candidate and reserve"
    );
    Ok(
        json!({"affinity_logical_cpus":cpus,"existing_producer_quota_cores":total,"candidate_quota_cores":2,"reserved_other_work_cores":8,"uncommitted_cores":cpus-total-10,"units":units}),
    )
}
pub(super) async fn admit() -> Result<()> {
    let (sb, own, check) = spec_args()?;
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.fleet_plan)?;
    let floor = bound_json(&s.floor)?;
    accepted(&s, &o, &f, &p, now()?)?;
    let (protected, growth_evidence) = growth(&s, snapshot144::floor(&floor)?)?;
    layout(&s)?;
    dormant()?;
    latest_fleet(&s, &f)?;
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "original141 admission inputs passed; no resource/remote observation, write or launch"
        );
        return Ok(());
    }
    let names = f["unit_census"]
        .as_object()
        .context("unit census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 101, 200)?;
    continuation144_protection::owners(&f, &before)?;
    let cpu = cpu_budget(&o)?;
    let guard_evidence = guards(&s, &o)?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "wrong admission bucket"
    );
    let client = s3_client(&r2);
    assembly144_admission::remote_floor(&client, &r2, &floor).await?;
    let available = snapshot144::free_bytes()?;
    let memory = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .context("available memory")?;
    let vmas = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(
        available >= protected + PEAK && memory >= 256 * 1024 * 1024 && vmas >= 4194304,
        "original141 current envelope unavailable"
    );
    let after = census(&names, 101, 200)?;
    continuation144_protection::owners(&f, &after)?;
    ensure!(
        cpu_budget(&o)? == cpu,
        "CPU budget changed during admission"
    );
    accepted(&s, &o, &f, &p, now()?)?;
    latest_fleet(&s, &f)?;
    layout(&s)?;
    dormant()?;
    let inv = env::var("INVOCATION_ID")?;
    ensure!(invocation(&inv), "admission needs persistent invocation");
    let required = protected.max(
        guard_evidence
            .as_object()
            .unwrap()
            .values()
            .filter_map(|g| g["guard"]["minimum_free_bytes"].as_u64())
            .max()
            .unwrap_or(0)
            .checked_add(64u64 << 30)
            .context("guard protection overflow")?,
    );
    ensure!(
        available >= required + PEAK,
        "original141 current guards require larger envelope"
    );
    let mut receipt = json!({"schema":"jetstreamer-original141-root-admission-v2","epoch":141,"unit":UNIT,"admitted":true,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"candidate_incremental_peak_bytes":PEAK,"required_guard_minimum_free_bytes":required,"required_initial_free_bytes":required+PEAK,"minimum_available_memory_bytes":192u64<<30,"existing_growth_claims_protected":true,"century_floor_protected":true,"century_floor_bytes":snapshot144::floor(&floor)?,"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"spec":private157::binding(&sb),"layout":private157::binding(&s.layout),"growth":s.growth,"guard_evidence":guard_evidence,"unit_census_before":before,"unit_census_after":after,"available_bytes":available,"memory_available_kib":memory,"vm_max_map_count":vmas,"new_resource_samples":0,"guard_first_fire_required":true,"actual_fleet_transition_required":true,"recorded_unix_seconds":now()?,"invocation_id":inv,"self_sha256":own});
    for key in DENIED {
        receipt[*key] = json!(false);
    }
    receipt["growth_extension"] = growth_evidence;
    receipt["cpu_budget"] = cpu;
    receipt["host_memory_reserve_bytes"] = json!(64u64 << 30);
    private157::immutable_receipt(&s.output, &receipt)?;
    println!("original141 fresh experimental admission written; no launch or publication");
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    plan: BoundFile,
    admission: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
    first_guard: BoundFile,
    first_guard_source: BoundFile,
}
pub(super) fn capture() -> Result<()> {
    let (sb, own, check) = spec_args()?;
    ensure!(!check, "original141 capture has no preflight write path");
    let s: CaptureSpec = serde_json::from_value(bound_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-original141-launch-capture-spec-v2"
            && s.plan.path == Path::new(PLAN)
            && admission_path(&s.admission.path)
            && s.first_guard.path == Path::new(ROOT).join("receipts/first-guard.json"),
        "foreign original141 capture paths"
    );
    let before = unit(UNIT)?;
    let inv = before["InvocationID"]
        .as_str()
        .context("producer invocation")?;
    let a = bound_json(&s.admission)?;
    let p = bound_json(&s.plan)?;
    ensure!(
        s.first_guard.sha256 == s.first_guard_source.sha256,
        "original141 first-guard pin must preserve exact source bytes"
    );
    let g = bound_json(&s.first_guard_source)?;
    let gp: BoundFile =
        serde_json::from_value(json!({"path":g["plan"],"sha256":g["plan_sha256"]}))?;
    let c = DiagnosticClaim {
        epoch: 141,
        unit: UNIT.into(),
        invocation_id: inv.into(),
        scratch_path: Path::new(ROOT).join("scratch"),
        launch_receipt: BoundFile {
            path: Path::new(ROOT).join("receipts/launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"epoch":141,"unit":UNIT,"invocation_id":inv,"launched":true,"private_original_entry_root_qualification":true,"node_sha256":NODE_SHA,"worker_sha256":WORKER_SHA,"original_index_sha256":INDEX_SHA,"original_data_sha256":DATA_SHA,"checkpoints_sha256":CHECKPOINTS_SHA,"snapshot_sha256":"47d5911465901975e397c570e06ccf72296db7ecd3b3b1beda710cacd3e683a1","bootstrap_slot":60911751,"replay_start_slot":60911752,"terminal_root_slot":61328765,"run_root":ROOT,"maximum_runtime_seconds":MAX_RUNTIME,"candidate_incremental_peak_bytes":PEAK,"required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],"plan":private157::binding(&s.plan),"admission":private157::binding(&s.admission),"observer":private157::binding(&s.observer),"previous_fleet":private157::binding(&s.previous_fleet),"first_guard":private157::binding(&s.first_guard),"expected_exec_start":before["ExecStart"],"recorded_unix_seconds":now()?,"capture_spec":private157::binding(&sb),"capture_self_sha256":own});
    for key in DENIED {
        r[*key] = json!(false);
    }
    shape(&r, &c)?;
    bindings(&r, &p, &a)?;
    first_guard(&c, &r, &g, &bound_json(&gp)?)?;
    live_shape(&c, &before)?;
    let properties=ProcessCommand::new("systemctl").args(["show",UNIT,"--no-pager","--property=User,Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,EnvironmentFiles"]).output()?;
    ensure!(
        properties.status.success() && properties.stdout.len() < 16384,
        "capture sandbox read failed"
    );
    let text = std::str::from_utf8(&properties.stdout)?;
    let props: BTreeMap<_, _> = text.lines().filter_map(|l| l.split_once('=')).collect();
    limits(&props)?;
    ensure!(
        props.get("EnvironmentFiles") == Some(&""),
        "original141 rejects unbound environment files"
    );
    ensure!(
        unit(UNIT)? == before,
        "original141 owner changed during capture"
    );
    let pin = guard_pin::pin(&s.first_guard_source, &s.first_guard, &g, &gp)?;
    r["first_guard_timer_pin"] = pin;
    ensure!(
        unit(UNIT)? == before,
        "original141 owner changed during guard pin"
    );
    launch(&r, &c)?;
    private157::immutable_receipt(&c.launch_receipt.path, &r)?;
    println!("actual guarded original141 launch captured; fleet handoff still required");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture() -> (Spec, Value, Value, Value, u64) {
        let b = |p: &str| BoundFile {
            path: p.into(),
            sha256: "a".repeat(64),
        };
        let s = Spec {
            schema: "jetstreamer-original141-root-admission-spec-v2".into(),
            observer: b("/sample.json"),
            fleet: b("/fleet.json"),
            fleet_plan: b("/plan.json"),
            floor: BoundFile {
                path: "/floor.json".into(),
                sha256: FLOOR_SHA.into(),
            },
            layout: b("/layout.json"),
            growth: ["152-153", "155-156", "191-194"]
                .into_iter()
                .map(|r| (r.into(), b("/growth.json")))
                .collect(),
            growth_extension_observers: vec![b("/sample.json")],
            guards: RANGES
                .into_iter()
                .zip(GUARDS)
                .map(|(r, u)| {
                    (
                        r.into(),
                        Guard {
                            unit: u.into(),
                            command_sha256: "a".repeat(64),
                            intent: "/intent".into(),
                            completion: "/completion".into(),
                        },
                    )
                })
                .collect(),
            output: ADMISSION.into(),
        };
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T06:39:58Z",
            "filesystem":{"conservative_available_bytes":FLOOR+PEAK},"host_memory":{"conservative_available_kib":256u64*1024*1024},"vm_max_map_count":4194304,
            "replays":RANGES.iter().map(|r|json!({"range":r,"invocation_binding_stable":true,"controller_after":{"restarts":0},"producer_after":{"restarts":0},
                "worker_after":{"matching_workers":1,"vmas":400000},"useful_work":{"sufficient_for_rates":true,"slots_per_second":1.},
                "cross_sample":{"producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}}})).collect::<Vec<_>>()});
        let f = json!({"schema":super::super::super::SCHEMA,"first_epoch":101,"last_epoch":200,"observer_receipt":"/sample.json","observer_sha256":s.observer.sha256,
            "sampled_at_utc":o["recorded_at_utc"],"plan":"/plan.json","plan_sha256":s.fleet_plan.sha256,"inventory":{"anomalies":0},"active":[],"epochs":[{"epoch":141,"state":"failed-needs-repair"}]});
        let p = json!({"observer":private157::binding(&s.observer)});
        let time = utc_seconds(o["recorded_at_utc"].as_str().unwrap()).unwrap();
        (s, o, f, p, time)
    }
    #[test]
    fn admission_requires_fresh_complete_progressing_five_lane_sample() {
        let (s, o, f, p, t) = fixture();
        accepted(&s, &o, &f, &p, t + 1800).unwrap();
        assert!(accepted(&s, &o, &f, &p, t + 1801).is_err());
        assert!(accepted(&s, &o, &f, &p, t - 1).is_err());
        for (pointer, value) in [
            ("/host_memory/conservative_available_kib", json!(0)),
            (
                "/filesystem/conservative_available_bytes",
                json!(FLOOR + PEAK - 1),
            ),
            ("/vm_max_map_count", json!(1000000)),
            ("/replays/0/range", json!("155-156")),
            ("/replays/0/controller_after/restarts", json!(1)),
            ("/replays/0/worker_after/vmas", json!(800000)),
            ("/replays/0/useful_work/slots_per_second", json!(0.)),
            (
                "/replays/0/cross_sample/producer_cgroup_counter_delta/memory_events.oom",
                json!(1),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(accepted(&s, &bad, &f, &p, t).is_err(), "{pointer}");
        }
        let mut claimed = f.clone();
        claimed["active"] = json!([{"epoch":141}]);
        assert!(accepted(&s, &o, &claimed, &p, t).is_err());
    }
    #[test]
    fn renewed_admission_is_a_new_sample_bound_receipt() {
        let (mut s, o, f, p, t) = fixture();
        let parent = Path::new(ADMISSION).parent().unwrap();
        s.output = parent.join("admission-20261023T063958Z.json");
        accepted(&s, &o, &f, &p, t).unwrap();
        for name in [
            "admission-20261023T070958Z.json",
            "admission-20260230T063958Z.json",
            "admission-latest.json",
            "../admission-20261023T063958Z.json",
        ] {
            s.output = parent.join(name);
            assert!(accepted(&s, &o, &f, &p, t).is_err(), "{name}");
        }
    }
    #[test]
    fn absence_gate_rejects_occupied_and_dangling_symlink_paths() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("intent.json");
        require_absent(&path).unwrap();
        fs::write(&path, b"intent").unwrap();
        assert!(require_absent(&path).is_err());
        let link = d.path().join("completion.json");
        std::os::unix::fs::symlink(d.path().join("missing"), &link).unwrap();
        assert!(require_absent(&link).is_err());
    }
}
