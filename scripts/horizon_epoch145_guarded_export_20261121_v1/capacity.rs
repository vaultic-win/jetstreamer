//! Reuse the accepted native reservation collector and the armed 169/172
//! guard plans. The transfer consumes the locked holding phase of the existing
//! auxiliary envelope. It never ends a promise or charges the same CPU twice.
use crate::{custody as f, model::Bound};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Seek, SeekFrom},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::Command,
};

pub const RUNTIME: &str = "/var/lib/jetstreamer/horizon_runtime_data";
pub const UNIT: &str = "horizon-holding-export145-20261121-v1.service";
pub const BYTES: u64 = 105_610_995_833;
const G: u64 = 1 << 30;
const META: u64 = 128 << 20;
const E172: &str = "epoch172-full-half-core-20261120-v1";
const E169: &str = "epoch169-focused-admission-20261120-v4";
const HOST_MEMORY: u64 = 810_658_050_048;
const E172_ADMISSION: &str = "c1dc591288eca1a2f6e2ab37888c57f108d2d25e6639d292d612def83ff2f2df";

pub fn n(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("missing {key}"))
}
fn bound(path: impl Into<PathBuf>, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
fn checked(path: &str, sha: &str) -> Result<Value> {
    f::evidence(&bound(Path::new(RUNTIME).join(path), sha))
}
fn session172() -> Result<Value> {
    checked(
        &format!("{E172}/ACTUAL_ADMISSION_AND_PROTECTION.json"),
        E172_ADMISSION,
    )
}
fn jsonref(v: &Value) -> Result<Value> {
    f::evidence(&serde_json::from_value::<Bound>(v.clone())?)
}
#[derive(Debug)]
pub struct TopologyTimeout;
impl std::fmt::Display for TopologyTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("systemctl replay census exceeded its native deadline")
    }
}
impl std::error::Error for TopologyTimeout {}
fn census_timeout(program: &str, args: &[&str], code: Option<i32>) -> bool {
    if program != "/usr/bin/systemctl" || code != Some(124) {
        return false;
    }
    match args {
        ["show", unit, properties] => {
            let Some(fields) = properties.strip_prefix("--property=") else {
                return false;
            };
            matches!(
                (*unit, fields),
                (crate::partial::NODE, crate::partial::NODE_PROPERTIES)
                    | (crate::partial::GUARD, crate::partial::GUARD_PROPERTIES)
            )
        }
        ["list-units", .., "horizon-qualify*.service"] => true,
        _ => false,
    }
}
pub fn run(program: &str, args: &[&str], seconds: &str) -> Result<String> {
    let o = Command::new("/usr/bin/timeout")
        .args(["--kill-after=2s", seconds, program])
        .args(args)
        .env_remove("SYSTEMD_HOST")
        .output()?;
    if census_timeout(program, args, o.status.code()) {
        return Err(TopologyTimeout.into());
    }
    ensure!(
        o.status.success(),
        "{program} {args:?} failed with {}: {}",
        o.status,
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn number_file(path: &Path) -> Result<u64> {
    Ok(fs::read_to_string(path)?.trim().parse()?)
}
pub(super) fn meminfo(key: &str) -> Result<u64> {
    let s = fs::read_to_string("/proc/meminfo")?;
    let mut w = s
        .lines()
        .find_map(|l| l.strip_prefix(key))
        .context("meminfo field")?
        .split_whitespace();
    let x: u64 = w.next().context("meminfo value")?.parse()?;
    ensure!(w.next() == Some("kB"), "meminfo units");
    Ok(x * 1024)
}
pub fn home() -> Result<(u64, u64)> {
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c"/home/sol".as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs HOME"
    );
    let v = unsafe { v.assume_init() };
    ensure!(v.f_frsize == 4096, "unexpected HOME geometry");
    Ok((
        v.f_bavail
            .checked_mul(v.f_frsize)
            .context("free bytes overflow")?,
        v.f_frsize,
    ))
}
fn peer_names(fleet: &Value, ad: &Value, joint: bool) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    let mut epochs = BTreeSet::new();
    for field in [
        "actual_executing_replays",
        "actual_active_bootstraps",
        "actual_active_private_diagnostics",
    ] {
        for v in fleet[field].as_array().context("fleet census")? {
            let epoch = n(v, "epoch")?;
            let name = v["unit"]["Id"].as_str().context("native owner")?;
            if epoch == 136 && joint {
                ensure!(
                    name == crate::joint_candidate::UNIT,
                    "unrecognized 136 fleet entry"
                );
                continue;
            }
            if epoch == 172 {
                ensure!(
                    v["unit"]["InvocationID"] == ad["producer_invocation_id"],
                    "172 owner changed"
                );
            }
            ensure!(
                epochs.insert(epoch) && names.insert(name.to_string()),
                "duplicate fleet owner"
            );
        }
    }
    ensure!(
        if cfg!(continuity145_only) {
            crate::continuity::roster(&epochs)
        } else {
            epochs
                == if cfg!(partial145_only) {
                    BTreeSet::from([166, 167, 169, 170, 172])
                } else if cfg!(materialized145_only) {
                    BTreeSet::from([167, 168, 169, 170, 172])
                } else {
                    BTreeSet::from([166, 167, 168, 169, 170, 172])
                }
        },
        "authoritative fleet differs from the admitted roster"
    );
    Ok(names)
}
pub(super) fn active(patterns: &[&str]) -> Result<BTreeSet<String>> {
    let mut args = vec![
        "list-units",
        "--state=running,activating,reloading,deactivating",
        "--no-pager",
        "--no-legend",
        "--output=json",
    ];
    args.extend(patterns);
    let rows: Vec<Value> = serde_json::from_str(&run("/usr/bin/systemctl", &args, "10")?)?;
    rows.into_iter()
        .map(|v| Ok(v["unit"].as_str().context("unit census row")?.to_string()))
        .collect()
}
pub(super) fn native_values(unit: &str) -> Result<Value> {
    ensure!(
        unit.starts_with("horizon-")
            && unit.ends_with(".service")
            && unit
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(&c)),
        "unit name"
    );
    let s = run(
        "/usr/bin/systemctl",
        &[
            "show",
            unit,
            "--property=Id,InvocationID,ActiveState,SubState,MainPID,ControlGroup,Job,NRestarts,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec",
        ],
        "8",
    )?;
    let mut v = json!({});
    for l in s.lines() {
        let (k, w) = l.split_once('=').context("native state")?;
        ensure!(v[k].is_null(), "duplicate native state");
        v[k] = json!(w);
    }
    ensure!(
        v["Id"] == unit
            && v["Job"] == ""
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["MemorySwapMax"] == "0",
        "native {unit} changed"
    );
    Ok(v)
}
fn resident(entry: &Value, epoch: u64) -> Result<u64> {
    let name = entry["unit"].as_str().context("owner unit")?;
    let s = native_values(name)?;
    let cpu = match epoch {
        169 => "3s",
        172 => "500ms",
        _ => "9s",
    };
    ensure!(
        s["InvocationID"] == entry["iid"]
            && s["CPUQuotaPerSecUSec"] == cpu
            && s["MemoryMax"] == (68 * G).to_string(),
        "owner {epoch} limits or generation changed"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(name);
    let own = format!("/system.slice/{name}");
    ensure!(s["ControlGroup"] == own, "foreign cgroup");
    let contents = fs::read_to_string(group.join("cgroup.procs"))?;
    let members: BTreeSet<u32> = contents
        .lines()
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    let pids = entry["processes"].as_array().context("owner processes")?;
    let mut recorded = BTreeSet::new();
    let mut pss = 0u64;
    for row in pids {
        let pid = u32::try_from(row[0].as_u64().context("pid")?)?;
        ensure!(
            members.contains(&pid)
                && recorded.insert(pid)
                && crate::native::ticks(pid)? == row[1].as_u64().context("ticks")?,
            "peer process changed"
        );
        let meta = fs::metadata(format!("/proc/{pid}/exe"))?;
        ensure!(
            row[2] == meta.dev() && row[3] == meta.ino(),
            "peer executable changed"
        );
        let m = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;
        let k: u64 = m
            .lines()
            .find_map(|x| x.strip_prefix("Pss:"))
            .context("peer PSS")?
            .split_whitespace()
            .next()
            .context("PSS value")?
            .parse()?;
        pss = pss.checked_add(k * 1024).context("PSS sum")?;
    }
    ensure!(recorded == members, "unexpected peer process");
    let stat = fs::read_to_string(group.join("memory.stat"))?;
    let get = |k: &str| -> Result<u64> {
        Ok(stat
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .context("cgroup memory field")?
            .parse()?)
    };
    Ok(pss.min(get("anon ")? + get("file_mapped ")?).min(68 * G))
}
#[derive(Debug)]
pub struct GuardInFlight;
impl std::fmt::Display for GuardInFlight {
    fn fmt(&self, o: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        o.write_str("waiting for next freshly measured native guard sample")
    }
}
impl std::error::Error for GuardInFlight {}

/// A verified sample whose measured inputs require a complete reprice before playback.
#[derive(Debug)]
pub struct Reprice(pub String);
impl std::fmt::Display for Reprice {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}
impl std::error::Error for Reprice {}

/// The producer records its timestamp at the start of the two-pass scan.
/// An already-published healthy result can cease to qualify its physical
/// credit while its successor is still scanning. Require the same original
/// freshness on resumed work and place the private worker in an actual stop
/// during the short gap. No stale sample can authorize a read or write.
fn temporal(start: u64, completed: u64, now: u64) -> Result<()> {
    ensure!(
        start <= completed && completed <= now && now - completed <= 45,
        "native guard completion expired"
    );
    if now - start > 45 {
        return Err(GuardInFlight.into());
    }
    Ok(())
}
fn newest_sample(plan_ref: &Value) -> Result<(u64, u64, Option<Value>)> {
    let plan = jsonref(plan_ref)?;
    let dir = Path::new(
        plan["receipt_directory"]
            .as_str()
            .context("guard directory")?,
    );
    let mut log = fs::File::open(dir.parent().context("guard root")?.join("guard.stdout"))?;
    let end = log.metadata()?.len();
    log.seek(SeekFrom::Start(end.saturating_sub(64 << 10)))?;
    let mut tail = String::new();
    log.take(64 << 10).read_to_string(&mut tail)?;
    let observed = tail
        .lines()
        .rev()
        .find_map(|line| serde_json::from_str::<Value>(line).ok())
        .context("complete guard sample")?;
    let iid = observed["guard_invocation_id"]
        .as_str()
        .context("native guard invocation")?;
    ensure!(f::hex(iid, 32), "guard invocation syntax");
    let p = dir.join(format!("sample-{iid}.json"));
    let s = f::evidence(&f::binding(&p)?)?;
    ensure!(s == observed, "guard receipt differs from native stdout");
    let o = &s["root_physical_observation"];
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["plan_sha256"] == plan_ref["sha256"]
            && s["producer_invocation_id"] == plan["invocation_id"]
            && s["trip_reason"].is_null()
            && s["root_physical_observation_error"].is_null()
            && o["exceeds_budget"] == false
            && s["producer"]["active"] == "active"
            && s["producer_stop_enabled"] == true
            && s["worker_observation_error"].is_null()
            && s["producer"]["invocation_id"] == plan["invocation_id"]
            && s["producer"]["restarts"] == 0
            && s["guard_sha256"]
                == "b2271db6f25696612c388297db3a10852f7911560887f67dcb404392d91f7016",
        "stale or invalid native guard sample {}",
        p.display()
    );
    let m = fs::symlink_metadata(&p)?;
    temporal(
        n(&s, "recorded_unix_seconds")?,
        m.mtime().try_into()?,
        f::now()?,
    )?;
    let cap = n(&plan, "maximum_root_physical_bytes")?;
    let min = n(&o["first"], "physical_bytes")?.min(n(&o["second"], "physical_bytes")?);
    let (realized, subset) =
        if o["first"]["vanished_entries"] == 0 && o["second"]["vanished_entries"] == 0 {
            (min, None)
        } else {
            let root = Path::new(plan["worker_root"].as_str().context("worker root")?);
            let (observed, proof) = crate::stable::measure(root)?;
            // No whole-walk credit from either unstable sample. Each subset
            // file is independently pinned and refetched from the admitted root.
            (observed.min(min), Some(proof))
        };
    Ok((
        n(&plan, "minimum_free_bytes")?,
        cap.checked_sub(realized).context("root exceeds cap")?,
        subset,
    ))
}

pub struct Fit {
    successor_fleet: Option<Value>,
    pub evidence: Value,
    pub names: BTreeSet<String>,
    pub joint: bool,
    owners: Vec<(u32, u64, String)>,
    pub base: u64,
    pub memfloor: u64,
    pub g169: Value,
    pub g172: Value,
    metered168: std::cell::RefCell<Option<Value>>,
    transitions: crate::peer_terminal::Transitions,
    peer_rss: std::collections::BTreeMap<u64, u64>,
}
impl Fit {
    pub fn current(&self, needed: u64) -> Result<Value> {
        let mut sample = self.existing(needed)?;
        if self.joint {
            let candidate = crate::joint_candidate::observe()?;
            if candidate.occupied || candidate.armed {
                let required = n(&sample, "protected_bytes")?
                    .max(candidate.floor)
                    .checked_add(needed)
                    .and_then(|s| s.checked_add(candidate.remaining()))
                    .context("joint HOME overflow")?;
                ensure!(
                    n(&sample, "free_bytes")? >= required,
                    "charged concurrent 136 growth exceeds free HOME"
                );
                sample["joint136"] = candidate.json(n(&sample, "protected_bytes")?)?;
            }
        }
        Ok(sample)
    }
    pub fn existing(&self, needed: u64) -> Result<Value> {
        match self.existing_measurement(needed) {
            Err(e) if cfg!(continuity145_only) => {
                self.transitions.rapid_check()?;
                Err(e)
            }
            result => result,
        }
    }
    fn existing_measurement(&self, needed: u64) -> Result<Value> {
        if cfg!(continuity145_only) {
            self.transitions.rapid_check()?;
            if self.metered168.borrow().is_none()
                && Path::new("/sys/fs/cgroup/system.slice")
                    .join(crate::continuity::REPLACEMENT)
                    .try_exists()?
            {
                return Err(crate::peer_terminal::Pending(168).into());
            }
        }
        let (a, ra, sa) = if cfg!(continuity145_only) && self.transitions.closed(169) {
            let plan = jsonref(&self.g169)?;
            let (realized, evidence) = crate::stable::measure_closed(Path::new(
                plan["worker_root"].as_str().context("169 retained root")?,
            ))?;
            (
                n(&plan, "minimum_free_bytes")?,
                n(&plan, "maximum_root_physical_bytes")?
                    .checked_sub(realized)
                    .context("closed 169 root cap")?,
                Some(evidence),
            )
        } else {
            newest_sample(&self.g169)?
        };
        let (b, rb, sb) = newest_sample(&self.g172)?;
        let mut protected = (self.base.max(a) + ra + 16 * G).max(b) + rb + META;
        if let Some(replacement) = self.metered168.borrow().as_ref() {
            // The standard root cap is already charged in base. The guard's
            // own absolute minimum may be higher at its actual admission.
            let (floor, _, _) = newest_sample(&replacement["guard"])?;
            protected = protected.max(floor);
        }
        let free = home()?.0;
        let available = meminfo("MemAvailable:")?;
        let required_memory = self
            .peer_rss
            .iter()
            .filter(|(epoch, _)| self.transitions.closed(**epoch))
            .try_fold(self.memfloor, |n, (_, bytes)| {
                n.checked_add(*bytes).context("retired peer memory")
            })?;
        ensure!(
            available >= required_memory,
            "RAM {available} needs {required_memory}"
        );
        let required = protected.checked_add(needed).context("disk sum")?;
        if free < required && (sa.is_some() || sb.is_some()) {
            return Err(anyhow::Error::new(GuardInFlight).context(format!(
                "changing-root subset HOME {free} needs {required}; 169={sa:?}, 172={sb:?}"
            )));
        }
        ensure!(
            free >= required,
            "HOME {free} needs {required} (protected {protected}, new bytes {needed})"
        );
        let mut sample = json!({"free_bytes":free,"protected_bytes":protected,"needed":needed,"available_memory":available,"required_memory":required_memory,"169_unspent":ra,"172_unspent":rb,"169_subset":sa,"172_subset":sb});
        if cfg!(continuity145_only) {
            sample["retained_peer_terminal_evidence"] = self.transitions.receipts();
        }
        Ok(sample)
    }
    /// Used only before the source barrier or while the worker is stopped.
    /// Other current guard failures remain terminal immediately.
    pub fn await_topology(&self) -> Result<()> {
        let start = std::time::Instant::now();
        loop {
            match self.topology() {
                Err(e) if cfg!(continuity145_only) && e.is::<crate::peer_terminal::Pending>() => {
                    std::thread::sleep(std::time::Duration::from_secs(10));
                }
                Err(e)
                    if self.joint
                        && (e.is::<GuardInFlight>() || e.is::<TopologyTimeout>())
                        && start.elapsed() < std::time::Duration::from_secs(75) =>
                {
                    std::thread::sleep(std::time::Duration::from_secs(1))
                }
                r => return r,
            }
        }
    }
    pub fn await_existing(&self) -> Result<Value> {
        let start = std::time::Instant::now();
        loop {
            match self.existing(0) {
                Err(e) if cfg!(continuity145_only) && e.is::<crate::peer_terminal::Pending>() => {
                    self.await_topology()?;
                }
                Err(e)
                    if e.is::<GuardInFlight>()
                        && start.elapsed() < std::time::Duration::from_secs(90) =>
                {
                    std::thread::sleep(std::time::Duration::from_secs(1))
                }
                r => return r,
            }
        }
    }
    pub fn await_current(&self, needed: u64) -> Result<Value> {
        let start = std::time::Instant::now();
        loop {
            match self.current(needed) {
                Err(e) if cfg!(continuity145_only) && e.is::<crate::peer_terminal::Pending>() => {
                    self.await_topology()?;
                }
                Err(e)
                    if e.is::<GuardInFlight>()
                        && start.elapsed() < std::time::Duration::from_secs(90) =>
                {
                    std::thread::sleep(std::time::Duration::from_secs(1))
                }
                result => return result,
            }
        }
    }
    pub fn topology(&self) -> Result<()> {
        if cfg!(continuity145_only) {
            self.transitions.reconcile()?;
        } else {
            validate_roster(&self.names, self.joint)?;
        }
        let result = self.live_topology();
        if cfg!(continuity145_only) && result.is_err() {
            self.transitions.check_crossing()?;
        }
        result
    }

    fn live_topology(&self) -> Result<()> {
        if cfg!(materialized145_only) {
            if cfg!(partial145_only) {
                crate::partial::drained()?;
            } else {
                crate::closed166::drained()?;
            }
            if cfg!(continuity145_only) && (!cfg!(early145_only) || self.transitions.closed(166)) {
                crate::closed166::drained()?;
            }
            let initial = self
                .successor_fleet
                .as_ref()
                .context("missing bound fleet")?;
            if cfg!(continuity145_only) {
                let mut fleet = self.transitions.projected(initial)?;
                let mut names = self.transitions.names(&self.names);
                let row = crate::continuity::replacement_row()?;
                let had = initial["actual_executing_replays"]
                    .as_array()
                    .context("roster")?
                    .iter()
                    .chain(
                        initial["actual_active_bootstraps"]
                            .as_array()
                            .context("bootstrap roster")?,
                    )
                    .chain(
                        initial["actual_active_private_diagnostics"]
                            .as_array()
                            .context("private roster")?,
                    )
                    .any(|r| r["epoch"] == 168);
                ensure!(!had || row.is_some(), "registered metered 168 disappeared");
                if let Some(row) = row {
                    names.insert(crate::continuity::REPLACEMENT.into());
                    if !had {
                        fleet["actual_active_bootstraps"]
                            .as_array_mut()
                            .context("mutable bootstrap roster")?
                            .push(row);
                    }
                }
                validate_roster(&names, self.joint)?;
                let now = crate::joint::incumbents(&fleet)?;
                for (e, actor) in self.evidence["remaining_native_owners"]
                    .as_object()
                    .context("bound original owners")?
                {
                    if !self.transitions.closed(e.parse()?) {
                        ensure!(
                            now.get(e) == Some(actor),
                            "remaining {e} changed generation"
                        );
                    }
                }
                let metered = crate::continuity::metered(&json!(now))?;
                let mut previous = self.metered168.borrow_mut();
                ensure!(
                    previous.is_none() || *previous == metered,
                    "registered metered 168 changed"
                );
                *previous = metered;
            } else {
                let fresh = crate::joint::incumbents(initial)?;
                ensure!(
                    self.evidence["remaining_native_owners"] == json!(fresh),
                    "remaining producer or guard changed"
                );
            }
        }
        for (pid, ticks, unit) in &self.owners {
            if cfg!(continuity145_only) && self.transitions.unit_closed(unit) {
                continue;
            }
            ensure!(
                crate::native::ticks(*pid)? == *ticks
                    && fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
                        == format!("0::/system.slice/{unit}"),
                "replay owner generation changed"
            );
        }
        Ok(())
    }
}

fn validate_roster(names: &BTreeSet<String>, joint: bool) -> Result<()> {
    let actual = active(&["horizon-qualify*.service"])?;
    if joint {
        let mut expected = names.clone();
        if crate::joint_candidate::observe()?.occupied {
            expected.insert(crate::joint_candidate::UNIT.into());
        }
        if expected != actual {
            if expected
                .symmetric_difference(&actual)
                .all(|u| u == crate::joint_candidate::UNIT)
            {
                return Err(GuardInFlight.into());
            }
            if cfg!(continuity145_only) {
                let missing = expected.difference(&actual).collect::<Vec<_>>();
                if !missing.is_empty() && actual.difference(&expected).next().is_none() {
                    for unit in missing {
                        let Some(peer) =
                            crate::peer_terminal::PEERS.iter().find(|p| p.unit == unit)
                        else {
                            anyhow::bail!("unknown removed producer");
                        };
                        let m =
                            crate::joint_candidate::show(unit, "Id,InvocationID,ActiveState,Job")?;
                        ensure!(
                            m["Id"] == unit.as_str()
                                && (m["InvocationID"] == peer.iid || m["InvocationID"] == ""),
                            "unrelated native transition"
                        );
                        if matches!(
                            m["ActiveState"].as_str(),
                            Some("deactivating" | "inactive" | "failed")
                        ) {
                            return Err(crate::peer_terminal::Pending(peer.epoch).into());
                        }
                    }
                }
            }
            anyhow::bail!("unexpected simultaneous replay topology");
        }
    } else {
        ensure!(&actual == names, "replay topology changed");
    }
    Ok(())
}

fn skip_original(epoch: &str) -> bool {
    (cfg!(partial145_only) && epoch == "168")
        || (cfg!(materialized145_only)
            && (!cfg!(partial145_only) || cfg!(continuity145_only))
            && epoch == "166")
}

pub fn holding_owners() -> Result<BTreeSet<String>> {
    active(&[
        "horizon-*holding*.service",
        "horizon-*park*.service",
        "horizon-*census*.service",
        "horizon-held141-custody*.service",
        "horizon-extract145-prefix*.service",
    ])
}
pub fn holding_budget(names: &BTreeSet<String>) -> Result<()> {
    ensure!(names.len() <= 1, "concurrent serial holding owners");
    for unit in names {
        let cg = Path::new("/sys/fs/cgroup/system.slice").join(unit);
        let cpu = fs::read_to_string(cg.join("cpu.max"))?;
        let limits = cpu
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            limits.len() == 2
                && limits[1] > 0
                && limits[0] > 0
                && limits[0] <= limits[1].checked_mul(2).context("holding CPU")?
                && number_file(&cg.join("memory.max"))? <= 2 * G
                && number_file(&cg.join("memory.swap.max"))? == 0,
            "holding exceeds retained allowance"
        );
    }
    Ok(())
}
pub fn capture(b: &Bound) -> Result<Fit> {
    capture_phase(b, false)
}
pub fn capture_phase(b: &Bound, joint: bool) -> Result<Fit> {
    capture_host(b, joint, false, false)
}
#[cfg(any(publication166_only, test))]
pub fn capture_publication(b: &Bound) -> Result<Fit> {
    capture_host(b, true, true, false)
}
#[cfg(test)]
pub fn project_publication(b: &Bound) -> Result<Fit> {
    capture_host(b, true, true, true)
}
fn capture_host(b: &Bound, joint: bool, publication: bool, live_fixture: bool) -> Result<Fit> {
    ensure!(
        b.path
            .file_name()
            .is_some_and(|x| x == "ROOT_COMPLETE_OPERATIONAL_FLEET.json")
            && b.path.parent().and_then(Path::parent) == Some(Path::new(RUNTIME)),
        "fleet source namespace"
    );
    let mut fleet: Value = serde_json::from_slice(&f::bytes(b, 32 << 20, false)?)?;
    let after166 = if cfg!(continuity145_only) && !cfg!(early145_only) && !live_fixture {
        Some(crate::closed166::evidence()?)
    } else {
        None
    };
    if publication {
        if !live_fixture {
            ensure!(
                after166.as_ref().context("166 terminal")?["terminal"]
                    == fleet["terminal166_local_commit"],
                "fleet carries another 166 terminal"
            );
        }
        for key in [
            "actual_executing_replays",
            "actual_active_bootstraps",
            "actual_active_private_diagnostics",
        ] {
            let records = fleet[key].as_array_mut().context("fleet rows")?;
            for row in records.iter().filter(|r| r["epoch"] == 166) {
                ensure!(
                    row["unit"]["Id"] == crate::closed166::NODE
                        && row["unit"]["InvocationID"] == "fa16ee2f14fe44ecbc37c59e197553ac",
                    "foreign 166 in observation"
                );
            }
            records.retain(|r| r["epoch"] != 166);
        }
    }
    let now = f::now()?;
    ensure!(
        now.checked_sub(n(&fleet, "recorded_unix_seconds")?)
            .is_some_and(|s| s <= 40 * 60)
            && fleet["owner"] == "/root"
            && fleet["all_reservation_ending_bytes"] == 0
            && fleet["all_existing_memory_DATA_OS_native_transport_promises_retained"] == true,
        "stale or incomplete fleet"
    );
    let ad = session172()?;
    let post = jsonref(&ad["post_guard_capacity"])?;
    let transitions = crate::peer_terminal::Transitions::new(publication || cfg!(test));
    if cfg!(continuity145_only) {
        transitions.reconcile()?;
        #[cfg(early145_only)]
        crate::early166::bind_initial(&fleet, transitions.receipts().get("166"))?;
    }
    if cfg!(continuity145_only) {
        fleet = transitions.projected(&fleet)?;
        let had = crate::peer_terminal::rows(&fleet)?.any(|r| r["epoch"] == 168);
        let row = crate::continuity::replacement_row()?;
        ensure!(
            !had || row.is_some(),
            "registered metered 168 disappeared at capture"
        );
        if let Some(row) = row
            && !had
        {
            fleet["actual_active_bootstraps"]
                .as_array_mut()
                .context("bootstrap census")?
                .push(row);
        }
    }
    let names = peer_names(&fleet, &ad, joint)?;
    let retired = if cfg!(partial145_only) {
        Some(crate::partial::closed168()?)
    } else if cfg!(materialized145_only) {
        Some(crate::closed166::evidence()?)
    } else {
        None
    };
    let mut at_capture = names.clone();
    if live_fixture {
        at_capture.insert(crate::closed166::NODE.to_owned());
    }
    let start = std::time::Instant::now();
    loop {
        match validate_roster(&at_capture, joint) {
            Err(e) if joint && e.is::<GuardInFlight>() && start.elapsed().as_secs() < 60 => {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            r => {
                r?;
                break;
            }
        }
    }
    let holding = holding_owners()?;
    if publication {
        // The entire serial holding allowance is retained independently of 166.
        // Its current occupant can stay in place on either side of this check.
        holding_budget(&holding)?;
    } else {
        ensure!(
            holding.iter().all(|u| u == UNIT),
            "conflicting holding or exporter owner {holding:?}"
        );
        ensure!(
            fleet["actual_active_holding_transfers"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "holding transfer in fleet"
        );
    }
    let allowance = &fleet["retry9_auxiliary_commitments"];
    ensure!(
        allowance["holding_serial"] == true
            && allowance["holding_cpu_quota_micros"] == 2_000_000
            && allowance["holding_memory_bytes"] == 2 * G,
        "holding phase funding changed"
    );
    let p = Path::new(RUNTIME)
        .join(E172)
        .join("controller/reservations");
    let sha = "316998786367d07ad76fec0c29841d52d84bfa489dd4d8ac0c91f4fa3351a3b7";
    f::bytes(&bound(p.clone(), sha), 8 << 20, true)?;
    let inputs: Value = serde_json::from_str(&run(
        p.to_str().context("reservations path")?,
        &[
            "--measure-replay-reservations",
            b.path.to_str().context("fleet name")?,
            &b.sha256,
        ],
        "145",
    )?)?;
    let aux = &inputs["auxiliary"];
    let roots = &inputs["roots"];
    let audit = &fleet["continuing_audit_obligation"];
    ensure!(
        inputs["temporary_cpu_micros"] == 0
            && inputs["temporary_memory"] == 0
            && aux["cpu_quota_micros"] == 3_250_000
            && aux["memory_bytes"] == 6_576_668_672u64
            && post["complete_cpu_quota_micros"] == 64_000_000
            && post["complete_memory_plus_reserve_bytes"] == HOST_MEMORY
            && audit["additional_cpu_quota_micros"] == 4_000_000
            && audit["additional_memory_bytes"] == 24 * G
            && audit["current_storage"]["remaining_archive_growth_bytes"] == 0
            && audit["current_storage"]["remaining_DATA_growth_bytes"] == 18 * G
            && n(&fleet, "complete_projected_memory_bytes")?
                + 16 * G
                + n(aux, "memory_bytes")?
                + 24 * G
                == HOST_MEMORY,
        "full-fleet CPU, memory or audit changed"
    );
    let slice = Path::new("/sys/fs/cgroup/horizonaudit.slice");
    ensure!(
        fs::read_to_string(slice.join("cpu.max"))?
            .split_whitespace()
            .map(str::parse)
            .collect::<std::result::Result<Vec<u64>, _>>()?
            .as_slice()
            == [400000, 100000]
            && number_file(&slice.join("memory.max"))? == 24 * G
            && number_file(&slice.join("memory.swap.max"))? == 0,
        "audit envelope"
    );
    let prior = checked(
        &format!("{E169}/POST_GUARD_CAPACITY.json"),
        "803bb540a6601238e8754c733a8cf900a9b6d103116ad6dac50bdcc2a081defc",
    )?;
    let g169 = json!(bound(
        Path::new(RUNTIME).join(E169).join("ACTUAL_GUARD_PLAN.json"),
        "3ddbafe25e1b5df2498d86b629ce6411e47c116b4377035f3a6690a504e1aa58"
    ));
    let fixed = n(&inputs, "historical_floor_bytes")?.max(n(audit, "configured_free_floor_bytes")?);
    let extra = n(roots, "peer_remaining_growth_bytes")?
        + n(roots, "remaining_standard_root_bytes")?
        + 10 * G
        + n(aux, "remaining_growth_bytes")?
        + (64 << 20)
        + n(&inputs, "independent166_whole_cap_bytes")?;
    let base = (fixed + extra + 18 * G)
        .max(n(&prior, "protected_raw_floor_bytes")?)
        .max(8_297_502_499_408 + n(roots, "remaining_standard_root_bytes")?);
    let before = meminfo("MemAvailable:")?;
    let mut rss = 0;
    let mut peer_rss = std::collections::BTreeMap::new();
    for (k, row) in post["owners"].as_object().context("172 native owners")? {
        let epoch = k.parse()?;
        if !skip_original(k) && !transitions.closed(epoch) {
            let credit = resident(row, epoch)?.min(resident(row, epoch)?);
            rss += credit;
            if crate::peer_terminal::PEERS.iter().any(|p| p.epoch == epoch) {
                peer_rss.insert(epoch, credit);
            }
        }
    }
    if cfg!(continuity145_only) {
        let first = checked(
            &format!("{E172}/FIRST_PROTECTED_HISTORICAL_WORKER_20261121.json"),
            "165d1600fb91aebef3903532ed997db46658f8901d765c49e3550fb548c39148",
        )?;
        let row = json!({"unit":ad["producer_unit"],"iid":ad["producer_invocation_id"],
            "processes":[[ad["producer_pid"],ad["start_ticks"],64512,101134947],
                         [first["worker_pid"],first["worker_start_ticks"],64512,115672187]]});
        rss += resident(&row, 172)?.min(resident(&row, 172)?);
    }
    let live172 = native_values(ad["producer_unit"].as_str().context("172 native unit")?)?;
    ensure!(
        live172["InvocationID"] == ad["producer_invocation_id"]
            && live172["MainPID"] == n(&ad, "producer_pid")?.to_string()
            && live172["CPUQuotaPerSecUSec"] == "500ms"
            && live172["MemoryMax"] == (68 * G).to_string(),
        "172 native bounds"
    );
    ensure!(
        meminfo("MemTotal:")? >= HOST_MEMORY && before >= HOST_MEMORY - rss,
        "full memory does not fit"
    );
    let mut subset_samples = Vec::new();
    for plan in [&g169, &ad["actual_guard_plan"]] {
        let cfg = jsonref(plan)?;
        let root = Path::new(cfg["worker_root"].as_str().context("guard root")?);
        let (bytes, sample) = crate::stable::measure(root)?;
        ensure!(
            bytes <= n(&cfg, "maximum_root_physical_bytes")?,
            "stable subset exceeds native cap"
        );
        subset_samples.push(sample);
    }
    let mut owners = Vec::new();
    for row in post["owners"]
        .as_object()
        .context("native peer owners")?
        .values()
    {
        let unit = row["unit"].as_str().context("owner name")?;
        if (cfg!(partial145_only) && unit == crate::partial::NODE)
            || (cfg!(materialized145_only)
                && (!cfg!(partial145_only) || cfg!(continuity145_only))
                && unit == crate::closed166::NODE)
        {
            continue;
        }
        for process in row["processes"].as_array().context("owner processes")? {
            owners.push((
                u32::try_from(process[0].as_u64().context("owner PID")?)?,
                process[1].as_u64().context("owner start ticks")?,
                unit.to_owned(),
            ));
        }
    }
    let pid = u32::try_from(n(&ad, "producer_pid")?)?;
    owners.push((
        pid,
        crate::native::ticks(pid)?,
        ad["producer_unit"].as_str().context("172 unit")?.to_owned(),
    ));
    let guarded = if cfg!(materialized145_only) {
        Some(crate::joint::incumbents(&fleet)?)
    } else {
        None
    };
    let metered168 = if cfg!(continuity145_only) {
        crate::continuity::metered(&json!(guarded))?
    } else {
        None
    };
    let evidence = json!({"joint_closed166":after166,"metered168":metered168,"remaining_native_owners":guarded,"completed166":if cfg!(partial145_only){None}else{retired.as_ref()},"terminal168":if cfg!(partial145_only){retired.as_ref()}else{None},"joint136_enabled":joint,"fleet":b,"capture":now,"existing_total_memory":HOST_MEMORY,"charged_cpu_micros":64_000_000,"auxiliary":aux,"temporary":inputs["temporary_workers"],"five_peer_resident_lower_bound":rss,"independent_root_subsets":subset_samples,"reservation_baseline":base,"172_admission_sha256":E172_ADMISSION,"holding_transfer_cpu_micros":1_000_000,"holding_transfer_memory":2*G});
    Ok(Fit {
        successor_fleet: cfg!(materialized145_only).then_some(fleet),
        metered168: std::cell::RefCell::new(metered168),
        transitions,
        peer_rss,
        evidence,
        joint,
        names,
        owners,
        base,
        memfloor: HOST_MEMORY - rss,
        g169,
        g172: ad["actual_guard_plan"].clone(),
    })
}

pub fn output_allocation() -> u64 {
    BYTES.div_ceil(4096) * 4096
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    #[test]
    fn positive_credit_requires_fresh_scan_start() {
        assert!(temporal(100, 120, 145).is_ok());
        assert!(temporal(100, 120, 146).unwrap_err().is::<GuardInFlight>());
        assert!(!temporal(100, 120, 170).unwrap_err().is::<GuardInFlight>());
        assert!(temporal(100, 90, 110).is_err());
        assert!(temporal(100, 120, 110).is_err());
    }
}

#[cfg(test)]
mod census_tests {
    use super::*;
    #[test]
    fn failed_original_trace_read_can_retry_only_its_native_observation() {
        use crate::partial::{GUARD, GUARD_PROPERTIES, NODE, NODE_PROPERTIES};
        for (unit, fields) in [(NODE, NODE_PROPERTIES), (GUARD, GUARD_PROPERTIES)] {
            let property = format!("--property={fields}");
            let args = ["show", unit, property.as_str()];
            assert!(census_timeout("/usr/bin/systemctl", &args, Some(124)));
            assert!(!census_timeout("/usr/bin/systemctl", &args, Some(1)));
            assert!(!census_timeout("/usr/bin/journalctl", &args, Some(124)));
            assert!(!census_timeout(
                "/usr/bin/systemctl",
                &["stop", unit, property.as_str()],
                Some(124)
            ));
            assert!(!census_timeout(
                "/usr/bin/systemctl",
                &["show", "unrelated.service", property.as_str()],
                Some(124)
            ));
            assert!(!census_timeout(
                "/usr/bin/systemctl",
                &["show", unit, "--property=MainPID"],
                Some(124)
            ));
        }
    }
    #[test]
    fn retry_only_the_specific_native_census_timeout() {
        let args = &["list-units", "--output=json", "horizon-qualify*.service"];
        assert!(census_timeout("/usr/bin/systemctl", args, Some(124)));
        for code in [None, Some(0), Some(1), Some(125), Some(137)] {
            assert!(!census_timeout("/usr/bin/systemctl", args, code));
        }
        assert!(!census_timeout(
            "/usr/bin/systemctl",
            &["show", "worker"],
            Some(124)
        ));
        assert!(!census_timeout("/usr/bin/journalctl", args, Some(124)));
    }
}
