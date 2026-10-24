//! Fresh admission, no-clobber layout and live attestation; no launch/restart API.
use super::*;
use std::{
    ffi::CString,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
};

const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const PRIVATE141: &str = "horizon-qualify-141-original-entry-capped-root-20261023-v1.service";
const PRIVATE141_IID: &str = "e639f007d482464f8a251455659d2ede";
const PRIVATE141_LAUNCH: &str = "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1/receipts/launch.json";
const PRIVATE141_SHA: &str = "fddefbddec6d98f344f9b7c2411cfcf874fee365e1af9fa4a6b380745021e28f";
const PRIVATE141_GUARD_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-original141-capped-root-guard-plan-20261023-v1/plan.json";
const PRIVATE141_GUARD_PLAN_SHA: &str =
    "918045a8ba88d6b052962eb4115be995c077a709d85022a08d41718e7d29dfba";
const RANGES: [&str; 5] = ["152-153", "155-156", "191-194", "183-184", "185-185"];
const GUARDS: [&str; 5] = [
    "jetstreamer-adaptive-reserve-controller-rebind-152-153-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-155-156-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-191-194-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-183-184-20261023-v1.service",
    "jetstreamer-adaptive-reserve-controller-rebind-185-185-20261023-v1.service",
];
#[path = "growth.rs"]
mod growth_bridge;
#[path = "../original141_guard_pin.rs"]
#[allow(
    clippy::duplicate_mod,
    reason = "Guard firstfire provenance binds136's distinct compile-time unit and paths"
)]
mod guard_pin;
fn invocation(s: &str) -> bool {
    canonical_invocation(s)
}
fn require_absent(p: &Path) -> Result<()> {
    absent(p)
}
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
    capability: BoundFile,
    private141_launch: BoundFile,
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
            && m.mode() & 0o222 == 0
            && canonical_digest(&json!(b.sha256)),
        "unsealed 136 input"
    );
    Ok(())
}
fn self_ok(digest: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private 136 operations require root"
    );
    sealed_file(&BoundFile {
        path: fs::read_link("/proc/self/exe")?,
        sha256: digest.into(),
    })?;
    ensure!(
        hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == digest,
        "private 136 executable digest differs"
    );
    Ok(())
}
fn args() -> Result<(BoundFile, String, bool)> {
    let a: Vec<_> = env::args().collect();
    let check = a.len() == 8 && a[7] == "--check-only";
    ensure!(
        (a.len() == 7 || check) && a[3] == "--spec-sha256" && a[5] == "--self-sha256",
        "usage: epoch136-command SPEC --spec-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    self_ok(&a[6])?;
    let b = BoundFile {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    sealed_file(&b)?;
    Ok((b, a[6].clone(), check))
}
fn absent(p: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "private 136 path occupied or unreadable:{}",
        p.display()
    );
    Ok(())
}
fn dormant() -> Result<Value> {
    let u = unit(UNIT)?;
    ensure!(
        u["MainPID"] == "0"
            && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
            && u["NRestarts"] == "0",
        "private 136 candidate already active or restarting"
    );
    Ok(u)
}
fn capability(b: &BoundFile) -> Result<Value> {
    ensure!(
        b.path == Path::new(CAPABILITY) && b.sha256 == CAPABILITY_SHA,
        "foreign 136 capability binding"
    );
    let c = bound_json(b)?;
    ensure!(
        c["schema"] == "jetstreamer-private-epoch136-capped-input-capability-v2"
            && c["epoch"] == 136
            && c["invocation_id"] == CAPABILITY_IID
            && c["node_sha256"] == NODE
            && c["worker_sha256"] == WORKER
            && c["snapshot_sha256"] == SNAPSHOT_SHA
            && c["all_immutable_inputs_rehashed"] == true
            && c["checkpoint_names_verified"] == true
            && c["bootstrap_slot"] == 58751483
            && c["terminal_root_slot"] == 59183944
            && c["output_slot_count"] == 431945
            && c["excluded_epoch_suffix_slots"] == 55,
        "private 136 capability scope differs"
    );
    for k in [
        "worker_spawned",
        "bank_initialized",
        "snapshot_restored",
        "archive_created",
        "replay_launch_authorized",
        "canonical_prefix_qualified",
        "full_cold_epoch_peak_qualified",
        "complete_epoch_span_covered",
        "runtime_promotion_authorized",
        "publication_authorized",
        "local_retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            c[k] == false,
            "136 input capability claims unsupported authority:{k}"
        );
    }
    Ok(c)
}
fn immutable(name: &str, digest: &str, maximum: u64) -> Result<()> {
    let p = Path::new(PACKAGE).join(name);
    sealed_file(&BoundFile {
        path: p.clone(),
        sha256: digest.into(),
    })?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)?;
    let m = f.metadata()?;
    ensure!(m.len() <= maximum, "136 input length exceeds bound");
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut count = 0u64;
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).context("136 hash overflow")?;
        ensure!(count <= maximum, "136 input grew beyond bound");
        hash.update(&buffer[..n]);
    }
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.uid(),
            m.gid(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        count == m.len()
            && id(&m) == id(&f.metadata()?)
            && id(&m) == id(&fs::symlink_metadata(&p)?)
            && hex_lower(&hash.finalize()) == digest,
        "136 immutable input changed or digest differs"
    );
    Ok(())
}
fn inputs(b: &BoundFile) -> Result<()> {
    capability(b)?;
    for (name, sha, max) in [
        ("jetstreamer-node", NODE, 512u64 << 20),
        ("jetstreamer-historical-worker-v1-4-25", WORKER, 256 << 20),
        (SNAPSHOT, SNAPSHOT_SHA, 1930905776),
        ("epoch-hashes-136.txt", CHECKPOINTS_SHA, 1024),
        (
            "genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            8 << 20,
        ),
        (
            "source-manifest.json",
            "ec62e2ce730a28033e5626e7afdb59c2b6e73a2ce188ae1040a77a7a09e396c3",
            1 << 20,
        ),
        (
            "original-failure.json",
            "4629a2bb6806a45c21ab541d19cf6d3368cff47e6965c10304bdfb6c06c5be03",
            1 << 20,
        ),
        (
            "review.json",
            "2c7c5a0f6e670aa78287cd1117b3c49e9ac6e959e46944340906573f63b42739",
            1 << 20,
        ),
    ] {
        immutable(name, sha, max)?;
    }
    Ok(())
}
fn directory(path: &Path, uid: u32, gid: u32) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let c = CString::new(path.as_os_str().as_encoded_bytes())?;
    ensure!(
        unsafe { libc::chown(c.as_ptr(), uid, gid) } == 0,
        "136 directory ownership failed"
    );
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("directory parent")?)?.sync_all()?;
    Ok(())
}
pub(super) fn prepare() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        a.len() == 4 && a[2] == "--self-sha256",
        "prepare 136 requires self digest"
    );
    self_ok(&a[3])?;
    let before = dormant()?;
    let cap = BoundFile {
        path: CAPABILITY.into(),
        sha256: CAPABILITY_SHA.into(),
    };
    inputs(&cap)?;
    let root = Path::new(ROOT);
    absent(root)?;
    ensure!(
        root.parent().context("136 parent")?.canonicalize()? == root.parent().unwrap(),
        "noncanonical 136 parent"
    );
    directory(root, 1001, 1003)?;
    for name in ["destination", "output", "scratch", ".jetstreamer-private"] {
        directory(&root.join(name), 1001, 1003)?;
    }
    directory(&root.join("receipts"), 0, 0)?;
    let bytes = read_stable_bounded(
        &Path::new(PACKAGE).join("genesis.tar.bz2"),
        8 << 20,
        "136 genesis",
    )?;
    let p = root.join("destination/genesis.tar.bz2");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)?;
    f.write_all(&bytes)?;
    f.set_permissions(fs::Permissions::from_mode(0o444))?;
    f.sync_all()?;
    File::open(p.parent().unwrap())?.sync_all()?;
    ensure!(dormant()? == before, "136 owner changed during preparation");
    let mut r = json!({"schema":"jetstreamer-epoch136-capped-root-layout-v2","uid":1001,"gid":1003,
        "capability":private157::binding(&cap),"self_sha256":a[3],"recorded_unix_seconds":now()?});
    fields(&mut r);
    private157::immutable_receipt(&root.join("receipts/layout.json"), &r)?;
    Ok(())
}
fn layout(b: &BoundFile) -> Result<()> {
    ensure!(
        b.path == Path::new(ROOT).join("receipts/layout.json"),
        "foreign 136 layout"
    );
    let l = bound_json(b)?;
    scope(&l)?;
    ensure!(
        l["schema"] == "jetstreamer-epoch136-capped-root-layout-v2"
            && l["uid"] == 1001
            && l["gid"] == 1003,
        "136 layout owner differs"
    );
    for name in [
        "",
        "destination",
        "output",
        "scratch",
        ".jetstreamer-private",
    ] {
        let p = Path::new(ROOT).join(name);
        let m = fs::symlink_metadata(&p)?;
        ensure!(
            p.canonicalize()? == p
                && m.is_dir()
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o7777 == 0o700,
            "unsafe 136 layout directory"
        );
        if !name.is_empty() && name != "destination" {
            ensure!(
                fs::read_dir(p)?.next().is_none(),
                "136 candidate root no longer empty"
            );
        }
    }
    let names = fs::read_dir(Path::new(ROOT).join("destination"))?
        .map(|e| e.map(|v| v.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        names == [std::ffi::OsString::from("genesis.tar.bz2")],
        "136 destination is not genesis-only"
    );
    let g = read_stable_bounded(
        &Path::new(ROOT).join("destination/genesis.tar.bz2"),
        8 << 20,
        "136 private genesis",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(g))
            == "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        "136 genesis differs"
    );
    Ok(())
}
fn accepted(s: &Spec, o: &Value, f: &Value, p: &Value, time: u64) -> Result<u64> {
    let t = utc_seconds(o["recorded_at_utc"].as_str().context("136 sample clock")?)?;
    ensure!(
        s.schema == "jetstreamer-epoch136-capped-root-admission-spec-v2"
            && s.floor.sha256 == FLOOR_SHA
            && s.private141_launch.path == Path::new(PRIVATE141_LAUNCH)
            && s.private141_launch.sha256 == PRIVATE141_SHA
            && s.output.parent() == Some(Path::new(ADMISSIONS))
            && s.output
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("admission-")
                    && n.ends_with(".json")
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
            && o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && t <= time
            && time - t <= 1800
            && f["schema"] == SCHEMA_FLEET
            && f["first_epoch"] == 101
            && f["last_epoch"] == 200
            && f["observer_receipt"].as_str() == s.observer.path.to_str()
            && f["observer_sha256"] == s.observer.sha256
            && f["sampled_at_utc"] == o["recorded_at_utc"]
            && f["plan"].as_str() == s.fleet_plan.path.to_str()
            && f["plan_sha256"] == s.fleet_plan.sha256
            && p["observer"] == private157::binding(&s.observer)
            && f["inventory"]["anomalies"] == 0,
        "136 admission basis stale, foreign or incomplete"
    );
    let rows = f["epochs"].as_array().context("136 epoch census")?;
    ensure!(
        rows.len() == 100
            && (101..=200).all(|n| rows.iter().filter(|r| r["epoch"] == n).count() == 1),
        "136 complete epoch census missing"
    );
    let e = rows.iter().find(|r| r["epoch"] == 136).unwrap();
    ensure!(
        e["state"] == "failed-needs-repair"
            && f["active"]
                .as_array()
                .context("136 active census")?
                .iter()
                .all(|r| r["epoch"] != 136)
            && f["diagnostics"]
                .as_array()
                .context("136 diagnostic census")?
                .iter()
                .all(|r| r["epoch"] != 136 || r["live"] != true),
        "136 already claimed or original repair relabeled"
    );
    let rows = o["replays"].as_array().context("136 production census")?;
    ensure!(
        rows.len() == RANGES.len()
            && rows
                .iter()
                .filter_map(|r| r["range"].as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(RANGES),
        "136 five production claims differ"
    );
    for row in rows {
        ensure!(
            row["invocation_binding_stable"] == true
                && row["useful_work"]["sufficient_for_rates"] == true
                && row["useful_work"]["slots_per_second"]
                    .as_f64()
                    .is_some_and(|r| r.is_finite() && r > 0.)
                && row["worker_after"]["matching_workers"] == 1
                && row["worker_after"]["vmas"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 800000),
            "136 protected producer unstable"
        );
        for role in ["controller", "producer"] {
            let before = &row[format!("{role}_before")];
            let after = &row[format!("{role}_after")];
            ensure!(
                before["invocation_id"] == after["invocation_id"]
                    && before["main_pid"] == after["main_pid"]
                    && after["restarts"] == 0
                    && after["active_state"] == "active"
                    && after["sub_state"] == "running",
                "136 protected owner changed"
            );
        }
        for key in [
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.oom_group_kill",
            "memory_events.max",
        ] {
            ensure!(
                row["cross_sample"]["producer_cgroup_counter_delta"][key] == 0,
                "136 protected memory event:{key}"
            );
        }
    }
    ensure!(
        s.guards.keys().map(String::as_str).collect::<BTreeSet<_>>() == BTreeSet::from(RANGES)
            && s.growth.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["152-153", "155-156", "191-194"]),
        "136 incomplete growth/guard contract"
    );
    Ok(t)
}
const SCHEMA_FLEET: &str = "jetstreamer-horizon-campaign-fleet-v1";
fn private141(o: &Value, l: &Value) -> Result<(u64, Value)> {
    ensure!(
        l["schema"] == "jetstreamer-private-epoch141-original-entry-capped-root-launch-v2"
            && l["unit"] == PRIVATE141
            && l["invocation_id"] == PRIVATE141_IID
            && l["candidate_incremental_peak_bytes"] == PEAK,
        "136 private 141 remaining-growth authority differs"
    );
    let rows = o["diagnostic_replays"]
        .as_array()
        .context("136 private growth census")?;
    let live: Vec<_> = rows
        .iter()
        .filter(|r| r["status"] == "observed")
        .filter_map(|r| r.get("observation"))
        .filter(|r| {
            r["producer_after"]["active_state"] == "active"
                && r["producer_after"]["sub_state"] == "running"
        })
        .collect();
    ensure!(live.len() == 1, "136 private growth census changed");
    let r = live[0];
    ensure!(
        r["range"] == "141"
            && r["invocation_binding_stable"] == true
            && r["producer_after"]["unit"] == PRIVATE141
            && r["producer_after"]["invocation_id"] == PRIVATE141_IID
            && r["producer_before"]["invocation_id"] == PRIVATE141_IID
            && r["producer_after"]["restarts"] == 0
            && r["worker_after"]["matching_workers"] == 1
            && r["worker_after"]["vmas"]
                .as_u64()
                .is_some_and(|n| n > 0 && n < 3500000)
            && r["useful_work"]["sufficient_for_rates"] == true
            && r["useful_work"]["slots_per_second"]
                .as_f64()
                .is_some_and(|n| n.is_finite() && n > 0.),
        "136 live 141 owner changed"
    );
    for key in [
        "memory_events.oom",
        "memory_events.oom_kill",
        "memory_events.oom_group_kill",
        "memory_events.max",
    ] {
        ensure!(
            r["cross_sample"]["producer_cgroup_counter_delta"][key] == 0,
            "136 live 141 memory event prevents scaling:{key}"
        );
    }
    let consumed = r["scratch_pass_1"]["physical_bytes"]
        .as_u64()
        .context("141 first scratch")?
        .min(
            r["scratch_pass_2"]["physical_bytes"]
                .as_u64()
                .context("141 second scratch")?,
        );
    ensure!(consumed <= PEAK, "live 141 already exceeds bounded stop");
    Ok((
        PEAK - consumed,
        json!({"launch":l["plan"],"unit":PRIVATE141,"invocation_id":PRIVATE141_IID,
        "whole_root_stop_bytes":PEAK,"consumed_scratch_lower_bound_bytes":consumed,"remaining_growth_bytes":PEAK-consumed,
        "archive_and_index_bytes_not_credited":true}),
    ))
}
fn budget(floor: u64, growth: &Value, remaining141: u64) -> Result<u64> {
    let ranges = growth["ranges"]
        .as_object()
        .context("136 extended growth ranges")?;
    ensure!(
        ranges.len() == 3
            && ranges.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["152-153", "155-156", "191-194"]),
        "136 incomplete extended growth"
    );
    for value in ranges.values() {
        ensure!(
            value["requested_claim_bytes"] == 512u64 << 30
                && value["formula_minimum_bytes"]
                    .as_u64()
                    .is_some_and(|n| n <= 512u64 << 30),
            "136 production growth no longer fits"
        );
    }
    let protected = floor
        .checked_add(3 * (512u64 << 30))
        .and_then(|n| n.checked_add(2 * (768u64 << 30)))
        .and_then(|n| n.checked_add(32u64 << 30))
        .context("136 production protection overflow")?
        .max(BASE_PROTECTED);
    protected
        .checked_add(remaining141)
        .context("136 full protection overflow")
}
fn memory(o: &Value) -> Result<u64> {
    let h = &o["lane_rss_history"]["100"];
    let rss = h["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .context("136 needs valid century RSS history")?;
    let reserve = rss
        .checked_mul(3)
        .context("136 memory reservation overflow")?
        / 2;
    ensure!(
        rss > 0 && h["reservation_ceiling_bytes"] == reserve,
        "136 century RSS allowance differs"
    );
    let total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("136 total memory")?
        .checked_mul(1024)
        .context("136 total memory overflow")?;
    let available = o["host_memory"]["conservative_available_kib"]
        .as_u64()
        .context("136 available memory")?
        .checked_mul(1024)
        .context("136 memory overflow")?;
    let target = (total / 10)
        .checked_add(rss)
        .context("136 memory target overflow")?;
    ensure!(
        available >= reserve && available >= target,
        "136 lacks next lane RSS allowance or is already at memory target"
    );
    let psi = &o["host_global_pressure"]["cross_sample"];
    let elapsed = psi["elapsed_millis"]
        .as_u64()
        .context("136 comparable host-memory PSI pending: enable host_global_pressure in normally sealed successor observers and retain two enabled samples at least 1800 seconds apart")?;
    ensure!(
        psi["status"] == "observed"
            && elapsed >= 1800000
            && psi["counter_delta_usec"]["memory.full_total_usec"]
                .as_u64()
                .zip(elapsed.checked_mul(100))
                .is_some_and(|(n, bound)| n <= bound),
        "136 memory pressure window missing or severe"
    );
    Ok(reserve)
}
fn sampled_envelope(o: &Value, required: u64) -> Result<u64> {
    let available = o["filesystem"]["conservative_available_bytes"]
        .as_u64()
        .context("136 sampled disk unavailable")?;
    let memory = memory(o);
    ensure!(
        available >= required && memory.is_ok(),
        "136 sampled admission denied: required_disk_bytes={required}, available_disk_bytes={available}, disk_deficit_bytes={}, memory_gate={}",
        required.saturating_sub(available),
        memory
            .as_ref()
            .map(|_| "passed".to_string())
            .unwrap_or_else(|e| format!("{e:#}"))
    );
    memory
}
fn latest(s: &Spec, f: &Value) -> Result<()> {
    let root = s.fleet.path.parent().context("136 fleet directory")?;
    ensure!(
        root == Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1"),
        "136 foreign fleet root"
    );
    let selected = (
        utc_seconds(f["sampled_at_utc"].as_str().context("fleet time")?)?,
        f["recorded_unix_seconds"]
            .as_u64()
            .context("fleet recorded time")?,
    );
    for entry in fs::read_dir(root)? {
        let p = entry?.path();
        if p.extension().is_none_or(|s| s != "json") || p == s.fleet.path {
            continue;
        }
        let v: Value =
            serde_json::from_slice(&read_stable_bounded(&p, 16 << 20, "136 fleet freshness")?)?;
        if v["schema"] == SCHEMA_FLEET && v["first_epoch"] == 101 && v["last_epoch"] == 200 {
            let other = (
                utc_seconds(
                    v["sampled_at_utc"]
                        .as_str()
                        .context("candidate fleet time")?,
                )?,
                v["recorded_unix_seconds"]
                    .as_u64()
                    .context("candidate fleet recorded")?,
            );
            ensure!(
                other < selected,
                "newer or tied fleet invalidates 136 admission"
            );
        }
    }
    Ok(())
}
fn properties(name: &str, keys: &str) -> Result<BTreeMap<String, String>> {
    let out = ProcessCommand::new("systemctl")
        .args(["show", name, "--no-pager", &format!("--property={keys}")])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 32768,
        "136 property observation failed"
    );
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("136 property shape")?;
        ensure!(
            result.insert(k.into(), v.into()).is_none(),
            "136 duplicate property"
        );
    }
    Ok(result)
}
fn timer(name: &str) -> Result<()> {
    let t = properties(
        &name.replace(".service", ".timer"),
        "ActiveState,SubState,Unit",
    )?;
    ensure!(
        t.get("ActiveState").map(String::as_str) == Some("active")
            && t.get("Unit").map(String::as_str) == Some(name),
        "136 protected timer not armed"
    );
    Ok(())
}
fn production_guard(value: &Value, c: &Guard, row: &Value, time: u64) -> Result<Value> {
    ensure!(
        value["_SYSTEMD_UNIT"] == c.unit
            && value["_UID"] == "0"
            && value["_SYSTEMD_INVOCATION_ID"]
                .as_str()
                .is_some_and(canonical_invocation),
        "136 foreign guard journal identity"
    );
    let at = value["__REALTIME_TIMESTAMP"]
        .as_str()
        .context("136 guard journal clock")?
        .parse::<u64>()?
        / 1000000;
    ensure!(
        at <= time && time - at <= 180,
        "136 protected guard stale or future"
    );
    let g: Value = serde_json::from_str(value["MESSAGE"].as_str().context("136 guard message")?)?;
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
        "136 existing producer guard not clean and armed"
    );
    for role in ["controller", "producer"] {
        ensure!(
            g[role]["invocation_id"] == row[format!("{role}_after")]["invocation_id"]
                && g[role]["unit"] == row[format!("{role}_after")]["unit"]
                && g[role]["restarts"] == 0
                && g[role]["active_state"] == "active"
                && g[role]["sub_state"] == "running",
            "136 guard owner changed"
        );
    }
    Ok(
        json!({"journal_cursor":value["__CURSOR"],"realtime_timestamp":value["__REALTIME_TIMESTAMP"],
        "invocation_id":value["_SYSTEMD_INVOCATION_ID"],"guard":g}),
    )
}
fn private141_guard_contract(u: &Value, g: &Value, p: &Value) -> Result<()> {
    let expected = format!(
        "{{ path={GUARD_BIN} ; argv[]={GUARD_BIN} {PRIVATE141_GUARD_PLAN} --plan-sha256 {PRIVATE141_GUARD_PLAN_SHA} --self-sha256 {GUARD_SHA}"
    );
    ensure!(
        command(&u["ExecStart"]) == Some(expected.as_str())
            && g["plan"] == PRIVATE141_GUARD_PLAN
            && g["plan_sha256"] == PRIVATE141_GUARD_PLAN_SHA
            && p["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && p["unit"] == PRIVATE141
            && p["invocation_id"] == PRIVATE141_IID
            && p["filesystem"] == "/home/sol"
            && p["worker_root"]
                == "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1"
            && p["receipt_directory"]
                == "/var/lib/jetstreamer/horizon-original141-capped-root-guard-20261023-v1"
            && p["maximum_worker_vmas"] == 3500000
            && p["maximum_root_physical_bytes"] == PEAK
            && p["minimum_free_bytes"] == g["minimum_free_bytes"]
            && g["root_physical_observation"]["maximum_physical_bytes"] == PEAK
            && g["root_physical_observation"]["conservative_physical_bytes"]
                .as_u64()
                .is_some_and(|n| n <= PEAK)
            && g["producer"]["restart_policy"] == "no"
            && g["producer"]["kill_mode"] == "control-group"
            && g["producer"]["delegated"] == false
            && g["producer"]["load_state"] == "loaded"
            && g["producer"]["result"] == "success"
            && g["workers"].as_array().is_some_and(|w| w.len() == 1
                && w[0][0].as_u64().is_some_and(|p| p > 1)
                && w[0][1].as_u64().is_some_and(|v| v > 0 && v <= 3500000)),
        "136 protected 141 guard command, sealed plan, worker census or root budget changed"
    );
    Ok(())
}
fn guards(s: &Spec, o: &Value) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for (i, range) in RANGES.iter().enumerate() {
        let c = &s.guards[*range];
        ensure!(
            c.unit == GUARDS[i] && canonical_digest(&json!(c.command_sha256)),
            "136 guard contract changed"
        );
        absent(&c.intent)?;
        absent(&c.completion)?;
        timer(&c.unit)?;
        let u = unit(&c.unit)?;
        ensure!(
            u["Result"] == "success" && u["ExecMainStatus"] == "0" && u["NRestarts"] == "0",
            "136 existing guard failed"
        );
        let cmd = command(&u["ExecStart"]).context("136 protected guard command")?;
        ensure!(
            cmd.contains(&format!("--intent-receipt={}", c.intent.display()))
                && cmd.contains(&format!("--completion-receipt={}", c.completion.display()))
                && hex_lower(&Sha256::digest(cmd.as_bytes())) == c.command_sha256,
            "136 existing guard command changed"
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
            "136 guard journal unreadable"
        );
        let row = o["replays"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["range"] == *range)
            .context("136 guard replay")?;
        let mut found = None;
        for line in std::str::from_utf8(&out.stdout)?.lines().rev() {
            let v: Value = serde_json::from_str(line)?;
            if v["_SYSTEMD_UNIT"] == c.unit
                && v["MESSAGE"].as_str().is_some_and(|m| m.starts_with('{'))
            {
                found = Some(production_guard(&v, c, row, now()?)?);
                break;
            }
        }
        result.insert(
            (*range).into(),
            found.context("136 missing fresh guard fire")?,
        );
        absent(&c.intent)?;
        absent(&c.completion)?;
    }
    let guard_unit = "horizon-original141-capped-root-guard-20261023-v1.service";
    let guard_root =
        Path::new("/var/lib/jetstreamer/horizon-original141-capped-root-guard-20261023-v1");
    timer(guard_unit)?;
    absent(&guard_root.join("stop-intent.json"))?;
    absent(&guard_root.join("stop-completion.json"))?;
    let u = unit(guard_unit)?;
    let iid = u["InvocationID"]
        .as_str()
        .context("136 live 141 guard invocation")?;
    ensure!(
        canonical_invocation(iid) && u["Result"] == "success" && u["ExecMainStatus"] == "0",
        "136 live 141 guard not successful"
    );
    let path = guard_root.join(format!("sample-{iid}.json"));
    let bytes = read_stable_bounded(&path, 16 << 20, "136 protected141 guard sample")?;
    let g: Value = serde_json::from_slice(&bytes)?;
    private141_guard_contract(
        &u,
        &g,
        &bound_json(&BoundFile {
            path: PRIVATE141_GUARD_PLAN.into(),
            sha256: PRIVATE141_GUARD_PLAN_SHA.into(),
        })?,
    )?;
    let at = g["recorded_unix_seconds"]
        .as_u64()
        .context("136 live 141 guard time")?;
    let time = now()?;
    ensure!(
        at <= time
            && time - at <= 180
            && g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == GUARD_SHA
            && g["guard_invocation_id"] == iid
            && g["producer_invocation_id"] == PRIVATE141_IID
            && g["producer"]["invocation_id"] == PRIVATE141_IID
            && g["producer"]["cgroup"] == format!("/system.slice/{PRIVATE141}")
            && g["producer"]["active"] == "active"
            && g["producer"]["sub"] == "running"
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g["maximum_root_physical_bytes"] == PEAK
            && g["root_physical_observation"]["exceeds_budget"] == false
            && [
                "trip_reason",
                "worker_observation_error",
                "root_physical_observation_error"
            ]
            .iter()
            .all(|k| g.get(*k).is_some_and(Value::is_null))
            && g["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= BASE_PROTECTED)
            && g["available_bytes"]
                .as_u64()
                .zip(g["minimum_free_bytes"].as_u64())
                .is_some_and(|(a, b)| a >= b),
        "136 live 141 reserve/root guard stale, changed or tripped"
    );
    ensure!(
        unit(guard_unit)?["InvocationID"] == iid,
        "136 live 141 guard changed during read"
    );
    result.insert(
        "141".into(),
        json!({"path":path,"sha256":hex_lower(&Sha256::digest(bytes)),"guard":g}),
    );
    absent(&guard_root.join("stop-intent.json"))?;
    absent(&guard_root.join("stop-completion.json"))?;
    Ok(Value::Object(result))
}
fn cpu(o: &Value) -> Result<Value> {
    let mut affinity: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&affinity), &mut affinity) } == 0,
        "136 CPU affinity unavailable"
    );
    let available = unsafe { libc::CPU_COUNT(&affinity) } as u64;
    let mut total = 8u64;
    let private = properties(PRIVATE141, "InvocationID,CPUQuotaPerSecUSec")?;
    ensure!(
        private.get("InvocationID").map(String::as_str) == Some(PRIVATE141_IID)
            && private.get("CPUQuotaPerSecUSec").map(String::as_str) == Some("8s"),
        "136 live 141 CPU owner changed"
    );
    for (range, quota) in [
        ("152-153", 9u64),
        ("155-156", 9),
        ("191-194", 8),
        ("183-184", 8),
        ("185-185", 8),
    ] {
        let r = o["replays"]
            .as_array()
            .context("136 CPU census")?
            .iter()
            .find(|r| r["range"] == range)
            .context("136 CPU range")?;
        let u = r["producer_after"]["unit"]
            .as_str()
            .context("136 CPU unit")?;
        let p = properties(u, "InvocationID,CPUQuotaPerSecUSec")?;
        ensure!(
            p.get("InvocationID").map(String::as_str)
                == r["producer_after"]["invocation_id"].as_str()
                && p.get("CPUQuotaPerSecUSec") == Some(&format!("{quota}s")),
            "136 protected CPU contract changed"
        );
        total = total.checked_add(quota).context("136 CPU sum overflow")?;
    }
    ensure!(
        available >= total + 8 + 8,
        "136 candidate CPU and other-work reserve cannot fit"
    );
    Ok(
        json!({"affinity_logical_cpus":available,"existing_production_and_private_quota_cores":total,
        "candidate_quota_cores":8,"reserved_other_work_cores":8}),
    )
}
fn current_owners(f: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    continuation144_protection::owners(f, current)?;
    for row in f["diagnostics"]
        .as_array()
        .context("136 current diagnostic census")?
    {
        if row["live"] != true {
            continue;
        }
        let old = &row["unit"];
        let name = old["Id"].as_str().context("136 diagnostic owner name")?;
        let new = current
            .get(name)
            .context("136 live diagnostic absent from complete census")?;
        for key in [
            "Id",
            "InvocationID",
            "MainPID",
            "ActiveState",
            "SubState",
            "NRestarts",
        ] {
            ensure!(
                old[key] == new[key],
                "136 protected diagnostic owner changed:{name}:{key}"
            );
        }
        ensure!(
            command(&old["ExecStart"]).is_some()
                && command(&old["ExecStart"]) == command(&new["ExecStart"]),
            "136 diagnostic command changed"
        );
    }
    let private = current
        .get(PRIVATE141)
        .context("136 live 141 omitted from complete census")?;
    let claim = DiagnosticClaim {
        epoch: 141,
        unit: PRIVATE141.into(),
        invocation_id: PRIVATE141_IID.into(),
        scratch_path:
            "/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1/scratch"
                .into(),
        launch_receipt: BoundFile {
            path: PRIVATE141_LAUNCH.into(),
            sha256: PRIVATE141_SHA.into(),
        },
    };
    original141_capped::validate_live(&claim, private)
}
pub(super) async fn admit() -> Result<()> {
    let (sb, own, check) = args()?;
    let s: Spec = serde_json::from_value(bound_json(&sb)?)?;
    let o = bound_json(&s.observer)?;
    let f = bound_json(&s.fleet)?;
    let p = bound_json(&s.fleet_plan)?;
    let floor = bound_json(&s.floor)?;
    accepted(&s, &o, &f, &p, now()?)?;
    let floor_bytes = snapshot144::floor(&floor)?;
    let growth = growth_bridge::extend(&s)?;
    let (remain, private) = private141(&o, &bound_json(&s.private141_launch)?)?;
    let protected = budget(floor_bytes, &growth, remain)?;
    let required = protected
        .checked_add(PEAK)
        .context("136 initial budget overflow")?;
    let reserve = sampled_envelope(&o, required)?;
    inputs(&s.capability)?;
    layout(&s.layout)?;
    dormant()?;
    latest(&s, &f)?;
    validate_output_destination(&s.output)?;
    if check {
        println!(
            "136 offline admission inputs passed; no resource or remote observation, receipt or launch"
        );
        return Ok(());
    }
    let mut names: BTreeSet<_> = f["unit_census"]
        .as_object()
        .context("136 full unit census")?
        .keys()
        .cloned()
        .collect();
    names.insert(UNIT.into());
    let before = census(&names, 101, 200)?;
    current_owners(&f, &before)?;
    let cpu_budget = cpu(&o)?;
    let guard_evidence = guards(&s, &o)?;
    let guard_min = guard_evidence
        .as_object()
        .unwrap()
        .values()
        .filter_map(|g| g["guard"]["minimum_free_bytes"].as_u64())
        .max()
        .context("136 guard reserve missing")?;
    let protected = protected.max(
        guard_min
            .checked_add(64u64 << 30)
            .context("136 guard margin overflow")?,
    );
    let initial = protected
        .checked_add(PEAK)
        .context("136 final budget overflow")?;
    let r2 = r2_config_from_env()?;
    ensure!(
        r2.bucket == "solana-archive-with-accounts-data",
        "136 wrong bucket"
    );
    let client = s3_client(&r2);
    assembly144_admission::remote_floor(&client, &r2, &floor).await?;
    ensure!(
        inventory_epoch(&client, &r2, 136).await?.state == InventoryState::Missing,
        "136 canonical object already exists; reconcile rather than duplicate"
    );
    let free = snapshot144::free_bytes()?;
    let mem = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .context("136 live memory unavailable")?
        .checked_mul(1024)
        .context("136 live memory overflow")?;
    let vmas = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let host_total = o["host_memory"]["total_kib"]
        .as_u64()
        .context("136 host total")?
        .checked_mul(1024)
        .context("136 host total overflow")?;
    let max_rss = o["lane_rss_history"]["100"]["maximum_observed_lane_rss_bytes"]
        .as_u64()
        .unwrap();
    let memory_target = (host_total / 10)
        .checked_add(max_rss)
        .context("136 live memory target overflow")?;
    ensure!(
        free >= initial && mem >= reserve && mem >= memory_target && vmas >= 4194304,
        "136 fresh resource envelope cannot fit"
    );
    let after = census(&names, 101, 200)?;
    current_owners(&f, &after)?;
    ensure!(
        cpu(&o)? == cpu_budget,
        "136 CPU owners changed during admission"
    );
    guards(&s, &o)?;
    accepted(&s, &o, &f, &p, now()?)?;
    latest(&s, &f)?;
    layout(&s.layout)?;
    dormant()?;
    let inv = env::var("INVOCATION_ID")?;
    ensure!(
        canonical_invocation(&inv),
        "136 admission must run under persistent systemd invocation"
    );
    let mut r = json!({"schema":"jetstreamer-epoch136-capped-root-admission-v2","admitted":true,
        "observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),"spec":private157::binding(&sb),
        "layout":private157::binding(&s.layout),"capability":private157::binding(&s.capability),"private141_launch":private157::binding(&s.private141_launch),
        "growth_extension":growth,"private141_growth":private,"required_guard_minimum_free_bytes":protected,
        "required_initial_free_bytes":initial,"century_floor_bytes":floor_bytes,"existing_growth_claims_protected":true,
        "live141_remaining_growth_protected":true,"century_floor_protected":true,"memory_reservation_bytes":reserve,
        "hard_memory_high_bytes":128u64<<30,"hard_memory_max_bytes":192u64<<30,"available_bytes":free,"memory_available_bytes":mem,
        "vm_max_map_count":vmas,"cpu_budget":cpu_budget,"guard_evidence":guard_evidence,"unit_census_before":before,"unit_census_after":after,
        "recorded_unix_seconds":now()?,"invocation_id":inv,"self_sha256":own,"new_resource_samples":0,
        "guard_first_fire_required":true,"actual_fleet_transition_required":true});
    fields(&mut r);
    private157::immutable_receipt(&s.output, &r)?;
    println!("136 bounded fresh admission written; no producer launch or publication");
    Ok(())
}
pub(super) fn sandbox() -> Result<BTreeMap<String, String>> {
    let mut p = properties(
        UNIT,
        "User,Group,Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,Environment,EnvironmentFiles",
    )?;
    p.insert(
        "EnvironmentFiles".into(),
        guard_pin::empty_environment_files(UNIT)?,
    );
    Ok(p)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    plan: BoundFile,
    admission: BoundFile,
    observer: BoundFile,
    previous_fleet: BoundFile,
    first_guard: BoundFile,
    first_guard_source: BoundFile,
}
pub(super) fn capture() -> Result<()> {
    let (sb, own, check) = args()?;
    ensure!(!check, "136 capture does not have a write preflight mode");
    let s: Capture = serde_json::from_value(bound_json(&sb)?)?;
    ensure!(
        s.schema == "jetstreamer-epoch136-capped-root-launch-capture-spec-v2"
            && s.plan.path == Path::new(PLAN)
            && s.admission.path.parent() == Some(Path::new(ADMISSIONS))
            && s.first_guard.path == Path::new(ROOT).join("receipts/first-guard.json")
            && s.first_guard.sha256 == s.first_guard_source.sha256,
        "136 capture paths or firstfire bytes differ"
    );
    let before = unit(UNIT)?;
    let iid = before["InvocationID"]
        .as_str()
        .context("136 actual invocation")?;
    let p = bound_json(&s.plan)?;
    let a = bound_json(&s.admission)?;
    let g = bound_json(&s.first_guard_source)?;
    let gp: BoundFile =
        serde_json::from_value(json!({"path":g["plan"],"sha256":g["plan_sha256"]}))?;
    ensure!(
        gp.path == Path::new(GUARD_PLAN),
        "136 capture foreign guard plan"
    );
    let c = DiagnosticClaim {
        epoch: 136,
        unit: UNIT.into(),
        invocation_id: iid.into(),
        scratch_path: Path::new(ROOT).join("scratch"),
        launch_receipt: BoundFile {
            path: Path::new(ROOT).join("receipts/launch.json"),
            sha256: "0".repeat(64),
        },
    };
    let mut r = json!({"schema":SCHEMA,"invocation_id":iid,"launched":true,"plan":private157::binding(&s.plan),
        "admission":private157::binding(&s.admission),"observer":private157::binding(&s.observer),"previous_fleet":private157::binding(&s.previous_fleet),
        "capability":{"path":CAPABILITY,"sha256":CAPABILITY_SHA},"first_guard":private157::binding(&s.first_guard),
        "required_guard_minimum_free_bytes":a["required_guard_minimum_free_bytes"],"expected_exec_start":before["ExecStart"],
        "actual_start_unix_seconds":guard_pin::producer_start_seconds()?,"recorded_unix_seconds":now()?,
        "capture_spec":private157::binding(&sb),"capture_self_sha256":own});
    fields(&mut r);
    shape(&r, &c)?;
    bindings(&r, &p, &a)?;
    first_guard(&c, &r, &g, &bound_json(&gp)?)?;
    live_shape(&c, &before)?;
    limits(&sandbox()?)?;
    ensure!(unit(UNIT)? == before, "136 owner changed during capture");
    r["first_guard_timer_pin"] = guard_pin::pin(&s.first_guard_source, &s.first_guard, &g, &gp)?;
    ensure!(
        unit(UNIT)? == before,
        "136 owner changed during firstfire pin"
    );
    launch(&r, &c)?;
    private157::immutable_receipt(&c.launch_receipt.path, &r)?;
    println!("actual136 guarded bounded launch attested; complete fleet adoption still required");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(path: &str) -> BoundFile {
        BoundFile {
            path: path.into(),
            sha256: "a".repeat(64),
        }
    }
    fn fixture() -> (Spec, Value, Value, Value, u64) {
        let s = Spec {
            schema: "jetstreamer-epoch136-capped-root-admission-spec-v2".into(),
            observer: binding("/sample.json"),
            fleet: binding("/fleet.json"),
            fleet_plan: binding("/fleet-plan.json"),
            floor: BoundFile {
                path: "/floor.json".into(),
                sha256: FLOOR_SHA.into(),
            },
            layout: binding("/layout.json"),
            capability: BoundFile {
                path: CAPABILITY.into(),
                sha256: CAPABILITY_SHA.into(),
            },
            private141_launch: BoundFile {
                path: PRIVATE141_LAUNCH.into(),
                sha256: PRIVATE141_SHA.into(),
            },
            growth: ["152-153", "155-156", "191-194"]
                .into_iter()
                .map(|r| (r.into(), binding("/growth.json")))
                .collect(),
            growth_extension_observers: vec![],
            guards: RANGES
                .into_iter()
                .enumerate()
                .map(|(i, r)| {
                    (
                        r.into(),
                        Guard {
                            unit: GUARDS[i].into(),
                            command_sha256: "b".repeat(64),
                            intent: "/intent.json".into(),
                            completion: "/completion.json".into(),
                        },
                    )
                })
                .collect(),
            output: format!("{ADMISSIONS}/admission-20261023T180000Z.json").into(),
        };
        let owner = json!({"invocation_id":"a".repeat(32),"main_pid":10,"restarts":0,"active_state":"active","sub_state":"running"});
        let rows:Vec<_>=RANGES.iter().map(|r|json!({"range":r,"invocation_binding_stable":true,"controller_before":owner,"controller_after":owner,
            "producer_before":owner,"producer_after":owner,"useful_work":{"sufficient_for_rates":true,"slots_per_second":1.0},
            "worker_after":{"matching_workers":1,"vmas":1000},"cross_sample":{"producer_cgroup_counter_delta":{
                "memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}}})).collect();
        let o = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-10-23T18:00:00Z","replays":rows});
        let epochs: Vec<_> = (101..=200)
            .map(
                |n| json!({"epoch":n,"state":if n==136{"failed-needs-repair"}else{"remote-ready"}}),
            )
            .collect();
        let f = json!({"schema":SCHEMA_FLEET,"first_epoch":101,"last_epoch":200,"observer_receipt":s.observer.path,"observer_sha256":s.observer.sha256,
            "sampled_at_utc":o["recorded_at_utc"],"plan":s.fleet_plan.path,"plan_sha256":s.fleet_plan.sha256,"inventory":{"anomalies":0},
            "epochs":epochs,"active":[],"diagnostics":[]});
        let p = json!({"observer":private157::binding(&s.observer)});
        let t = utc_seconds("2026-10-23T18:01:00Z").unwrap();
        (s, o, f, p, t)
    }
    #[test]
    fn fresh_full_range_census_and_failed136_ownership_are_required() {
        let (s, o, f, p, t) = fixture();
        accepted(&s, &o, &f, &p, t).unwrap();
        for (pointer, value) in [
            ("/first_epoch", json!(100)),
            ("/last_epoch", json!(199)),
            ("/inventory/anomalies", json!(1)),
            ("/observer_sha256", json!("b".repeat(64))),
            ("/active", json!([{"epoch":136}])),
            ("/diagnostics", json!([{"epoch":136,"live":true}])),
        ] {
            let mut bad = f.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(accepted(&s, &o, &bad, &p, t).is_err(), "accepted{pointer}");
        }
        let mut incomplete = f.clone();
        incomplete["epochs"].as_array_mut().unwrap().pop();
        assert!(accepted(&s, &o, &incomplete, &p, t).is_err());
        let mut duplicate = f.clone();
        duplicate["epochs"][0] = duplicate["epochs"][1].clone();
        assert!(accepted(&s, &o, &duplicate, &p, t).is_err());
        assert!(accepted(&s, &o, &f, &p, t + 1800).is_err());
        assert!(accepted(&s, &o, &f, &p, t - 61).is_err());
    }
    #[test]
    fn production_restart_failure_missing_range_and_memory_events_block136() {
        let (s, o, f, p, t) = fixture();
        for (pointer, value) in [
            ("/replays/0/range", json!("152-154")),
            ("/replays/0/producer_after/restarts", json!(1)),
            (
                "/replays/0/producer_after/invocation_id",
                json!("replacement"),
            ),
            ("/replays/0/invocation_binding_stable", json!(false)),
            ("/replays/0/worker_after/vmas", json!(800000)),
            ("/replays/0/useful_work/slots_per_second", json!(0.0)),
            (
                "/replays/0/cross_sample/producer_cgroup_counter_delta/memory_events.oom_kill",
                json!(1),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(accepted(&s, &bad, &f, &p, t).is_err(), "accepted{pointer}");
        }
    }
    #[test]
    fn live141_remaining_growth_is_conservative_and_cannot_be_omitted() {
        let owner = json!({"unit":PRIVATE141,"invocation_id":PRIVATE141_IID,"active_state":"active","sub_state":"running","restarts":0});
        let o = json!({"diagnostic_replays":[{"status":"observed","observation":{"range":"141","invocation_binding_stable":true,
            "producer_before":owner,"producer_after":owner,"scratch_pass_1":{"physical_bytes":100},"scratch_pass_2":{"physical_bytes":200},
            "worker_after":{"matching_workers":1,"vmas":1000},"useful_work":{"sufficient_for_rates":true,"slots_per_second":1.0},
            "cross_sample":{"producer_cgroup_counter_delta":{"memory_events.oom":0,"memory_events.oom_kill":0,"memory_events.oom_group_kill":0,"memory_events.max":0}}}}]});
        let l = json!({"schema":"jetstreamer-private-epoch141-original-entry-capped-root-launch-v2","unit":PRIVATE141,
            "invocation_id":PRIVATE141_IID,"candidate_incremental_peak_bytes":PEAK});
        assert_eq!(private141(&o, &l).unwrap().0, PEAK - 100);
        for (pointer, value) in [
            (
                "/diagnostic_replays/0/observation/producer_after/invocation_id",
                json!("replacement"),
            ),
            ("/diagnostic_replays/0/status", json!("unavailable")),
            (
                "/diagnostic_replays/0/observation/invocation_binding_stable",
                json!(false),
            ),
            (
                "/diagnostic_replays/0/observation/scratch_pass_1/physical_bytes",
                json!(PEAK + 1),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            if pointer.contains("physical_bytes") {
                bad["diagnostic_replays"][0]["observation"]["scratch_pass_2"]["physical_bytes"] =
                    json!(PEAK + 2);
            }
            assert!(private141(&bad, &l).is_err(), "accepted{pointer}");
        }
        let mut duplicate = o.clone();
        duplicate["diagnostic_replays"]
            .as_array_mut()
            .unwrap()
            .push(o["diagnostic_replays"][0].clone());
        assert!(private141(&duplicate, &l).is_err());
    }
    #[test]
    fn six_claim_budget_reproduces1826_deficit_and_retirement_is_insufficient() {
        let growth = json!({"ranges":{
            "152-153":{"requested_claim_bytes":512u64<<30,"formula_minimum_bytes":1},
            "155-156":{"requested_claim_bytes":512u64<<30,"formula_minimum_bytes":1},
            "191-194":{"requested_claim_bytes":512u64<<30,"formula_minimum_bytes":1}}});
        let protected = budget(205211459014, &growth, 528084676608).unwrap();
        assert_eq!(protected, 4100550495686);
        let free = 3851812921344u64;
        let initial = protected + PEAK;
        assert_eq!(initial - free, 798493388230);
        assert!(
            free + 99719081984 < initial,
            "retained136artifact alone cannot admit this stop"
        );
        assert!(budget(u64::MAX, &growth, 1).is_err());
        assert!(budget(205211459014, &growth, u64::MAX).is_err());
        let mut missing = growth.clone();
        missing["ranges"].as_object_mut().unwrap().remove("191-194");
        assert!(budget(1, &missing, 1).is_err());
        let mut too_small = growth.clone();
        too_small["ranges"]["152-153"]["requested_claim_bytes"] = json!(300000000000u64);
        assert!(budget(1, &too_small, 1).is_err());
    }
    #[test]
    fn memory_uses_this_centurys_rss_reservation_once_and_requires_clean_pressure() {
        let o = json!({"lane_rss_history":{"100":{"maximum_observed_lane_rss_bytes":100000000000u64,"reservation_ceiling_bytes":150000000000u64}},
            "host_memory":{"total_kib":800000000,"conservative_available_kib":500000000},
            "host_global_pressure":{"cross_sample":{"status":"observed","elapsed_millis":1800000,"counter_delta_usec":{"memory.full_total_usec":0}}}});
        assert_eq!(memory(&o).unwrap(), 150000000000);
        for (pointer, value) in [
            (
                "/lane_rss_history/100/reservation_ceiling_bytes",
                json!(225000000000u64),
            ),
            ("/host_memory/conservative_available_kib", json!(100000000)),
            (
                "/host_global_pressure/cross_sample/elapsed_millis",
                json!(1000),
            ),
            (
                "/host_global_pressure/cross_sample/counter_delta_usec/memory.full_total_usec",
                json!(180000001),
            ),
        ] {
            let mut bad = o.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(memory(&bad).is_err(), "accepted{pointer}");
        }
        let mut other = o.clone();
        other["lane_rss_history"] = json!({"200":{"maximum_observed_lane_rss_bytes":150000000000u64,"reservation_ceiling_bytes":225000000000u64}});
        assert!(memory(&other).is_err());
    }
    #[test]
    fn offline_denial_preserves_independent_disk_and_telemetry_blockers() {
        let o = json!({"filesystem":{"conservative_available_bytes":3851812921344u64},
            "lane_rss_history":{"100":{"maximum_observed_lane_rss_bytes":126550958080u64,"reservation_ceiling_bytes":189826437120u64}},
            "host_memory":{"total_kib":791897308,"conservative_available_kib":622599920},"host_global_pressure":null});
        let error = format!(
            "{:#}",
            sampled_envelope(&o, 4100550495686 + PEAK).unwrap_err()
        );
        assert!(error.contains("disk_deficit_bytes=798493388230"));
        assert!(error.contains("comparable host-memory PSI pending"));
        assert!(error.contains("normally sealed successor observers"));
    }
    #[test]
    fn protected141_guard_requires_its_actual_sealed_command_plan_and_one_worker() {
        let expected = format!(
            "{{ path={GUARD_BIN} ; argv[]={GUARD_BIN} {PRIVATE141_GUARD_PLAN} --plan-sha256 {PRIVATE141_GUARD_PLAN_SHA} --self-sha256 {GUARD_SHA} ; ignore_errors=no ; start_time=0 }}"
        );
        let u = json!({"ExecStart":expected});
        let g = json!({"plan":PRIVATE141_GUARD_PLAN,"plan_sha256":PRIVATE141_GUARD_PLAN_SHA,"minimum_free_bytes":BASE_PROTECTED,
            "root_physical_observation":{"maximum_physical_bytes":PEAK,"conservative_physical_bytes":1},
            "producer":{"restart_policy":"no","kill_mode":"control-group","delegated":false,"load_state":"loaded","result":"success"},"workers":[[11,1000]]});
        let p = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":PRIVATE141,"invocation_id":PRIVATE141_IID,"filesystem":"/home/sol",
            "worker_root":"/home/sol/.jetstreamer-private/epoch141-original-entry-capped-root-20261023-v1",
            "receipt_directory":"/var/lib/jetstreamer/horizon-original141-capped-root-guard-20261023-v1",
            "maximum_worker_vmas":3500000,"maximum_root_physical_bytes":PEAK,"minimum_free_bytes":BASE_PROTECTED});
        private141_guard_contract(&u, &g, &p).unwrap();
        let other = json!({"ExecStart":expected.replace(GUARD_BIN,"/other/guard")});
        assert!(private141_guard_contract(&other, &g, &p).is_err());
        for (pointer, value) in [
            ("/plan_sha256", json!("a".repeat(64))),
            ("/producer/delegated", json!(true)),
            ("/workers", json!([])),
            (
                "/root_physical_observation/conservative_physical_bytes",
                json!(PEAK + 1),
            ),
        ] {
            let mut bad = g.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                private141_guard_contract(&u, &bad, &p).is_err(),
                "accepted{pointer}"
            );
        }
        let mut bad = p.clone();
        bad["maximum_root_physical_bytes"] = json!(PEAK - 1);
        assert!(private141_guard_contract(&u, &g, &bad).is_err());
    }
}
