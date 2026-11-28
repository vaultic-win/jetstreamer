//! Bind live work to the actual producer, PID/start tick, timer and first guard.
use super::{n, peer, sum};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs, io,
    path::Path,
};
const NEXT: &str = "horizon-qualify-170-replacement-local3retry9-20261110-v1.service";
const TIMER: &str = "horizon-guard-replacement-170-local3retry9-20261110-v1.timer";
const BASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch170-retry9-recovery-20261120-v1/launch-state/epoch170";

fn ticks(pid: u64) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("proc start")?
        .parse()?)
}
fn closed(v: &Value) -> bool {
    matches!(v["ActiveState"].as_str(), Some("inactive" | "failed"))
        && v["Job"] == ""
        && ["MainPID", "ControlPID"]
            .iter()
            .all(|k| v[*k].is_null() || v[*k] == "0")
}
fn binding170(file: &str, sha: &str) -> Value {
    peer::pair(&format!("{BASE}/{file}.json"), sha)
}
fn retry170(e: &Value, fleet: &Value) -> Result<Option<Value>> {
    let terminal = &fleet["latest_terminal_retry8_170"];
    ensure!(
        terminal["sha256"] == "8caf45b9f9e6aa5c15333aa93b0fb69731a1cff0483c9acc00d25fb03092335e",
        "missing retry8 closure"
    );
    let stop = peer::bound(terminal)?;
    ensure!(
        stop["epoch"] == 170
            && stop["state"]["MainPID"] == "0"
            && stop["resource_credit_bytes"] == 0,
        "retry8 closure"
    );
    let old = stop["unit"].as_str().context("retry8 unit")?;
    ensure!(closed(&crate::show(old)?), "retry8 producer still present");
    let live = crate::show(NEXT)?;
    let timer = crate::show(TIMER)?;
    let a = binding170(
        "ACTUAL_REPLACEMENT_ADMISSION",
        "1dd1394c641e5dd0869dc780cc42e46a0cfbe9b84a781b4d38e9f8db5d6b273c",
    );
    let g = binding170(
        "ACTUAL_GUARD_PROTECTION",
        "241d1a0fba4907b2372cd61493e23e9bdc85ef30db1748b8c33c095e72d5c14e",
    );
    if closed(&live) && closed(&timer) {
        let ap = Path::new(a["path"].as_str().unwrap());
        let gp = Path::new(g["path"].as_str().unwrap());
        if ap.try_exists()? || gp.try_exists()? {
            let t = peer::bound(&fleet["latest_terminal_retry9_170"])?;
            ensure!(
                t["unit"] == NEXT
                    && t["invocation"] == "8d120ed88adc4afb9485fb3f61dfa29c"
                    && closed(&t["state"])
                    && t["resource_credit_bytes"] == 0,
                "unreconciled closed retry9 owner"
            );
        }
        return Ok(None);
    }
    let ad = peer::bound(&a)?;
    let gd = peer::bound(&g)?;
    let native = peer::bound(&ad["actual_producer_native"])?;
    let plan = peer::bound(&gd["plan"])?;
    let scope = peer::bound(&ad["prelaunch_static_guard_scope"])?;
    let proof = peer::bound(&ad["first_guard"])?;
    let sample = peer::bound(&gd["first_guard_sample"])?;
    let id = "8d120ed88adc4afb9485fb3f61dfa29c";
    ensure!(
        ad["producer_invocation_id"] == id
            && native["MainStartTicks"] == 350635451
            && ad["producer_pid"] == 2619210
            && ad["producer_unit"] == NEXT
            && ad["protected166_admission"] == e["active166"]["admission"]
            && ad["protected167_admission"] == e["active167"]["admission"]
            && ad["protected166_guard"] == e["active166"]["guard_protection"]
            && ad["protected167_guard"] == e["active167"]["guard_protection"]
            && ad["fresh_admission_passed"] == true
            && ad["all_prior_promises_retained"] == true
            && ad["candidate_root_cap_bytes"] == peer::CAP
            && ad["memory_or_DATA_promise_ending_bytes"] == 0
            && ad["resource_credit_bytes"] == 0
            && ad["guard_sha256"] == guard168::GUARD_SHA
            && scope["static_validation"]["self_sha256"] == guard168::GUARD_SHA
            && scope["static_validation"]["unit"] == NEXT
            && scope["static_validation"]["validated"] == true
            && gd["admission"] == a
            && gd["timer_unit"] == TIMER
            && gd["producer_invocation_id"] == id
            && plan["invocation_id"] == id
            && plan["unit"] == NEXT
            && plan["maximum_root_physical_bytes"] == peer::CAP
            && plan["minimum_free_bytes"] == peer::FLOOR
            && proof["genuine_first_timer_driven_success"] == true
            && proof["receipt"] == gd["first_guard_sample"]
            && sample["producer_invocation_id"] == id
            && sample["trip_reason"].is_null(),
        "170 admission/guard mismatch"
    );
    Ok(Some(
        json!({"epoch":170,"unit":NEXT,"invocation_id":id,"main_pid":2619210,"main_start_ticks":350635451,"admission":a,"guard_protection":g,"recorded_unix_seconds":ad["recorded_unix_seconds"]}),
    ))
}
fn time(v: &Value) -> Result<u64> {
    let s = v.as_str().context("UTC time")?;
    ensure!(
        s.len() == 20 && s.ends_with('Z'),
        "expected whole UTC seconds"
    );
    let r = std::process::Command::new("/usr/bin/date")
        .args(["-u", "-d", s, "+%s"])
        .output()?;
    ensure!(r.status.success(), "invalid UTC time");
    Ok(std::str::from_utf8(&r.stdout)?.trim().parse()?)
}
pub(super) fn owners(fleet: &Value, e: &Value) -> Result<Vec<Value>> {
    peer::live(e)?;
    let observe = peer::bound(&fleet["observer"])?;
    let sampled = time(&observe["recorded_at_utc"])?;
    let next = time(&observe["cadence"]["next_routine_observation_not_before_utc"])?;
    let now = crate::now()?;
    ensure!(
        next == sum(sampled, 1800)? && now >= sampled && now < next,
        "fresh native fleet observation required"
    );
    let mut owners = peer::owners(e);
    ensure!(
        owners.len() == 2
            && owners[1]["invocation_id"] == "93e60160c9164d3781a5b544fc2a48b4"
            && owners[1]["main_pid"] == 2472615
            && owners[1]["main_start_ticks"] == 349632179,
        "167 actual admission required"
    );
    owners.extend(retry170(e, fleet)?);
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("replays")?
        .iter()
        .chain(
            fleet["actual_active_bootstraps"]
                .as_array()
                .context("bootstraps")?,
        )
        .collect::<Vec<_>>();
    let mut covered = BTreeSet::new();
    for r in rows {
        let o = owners
            .iter()
            .find(|o| o["epoch"] == r["epoch"])
            .context("unknown fleet owner")?;
        ensure!(
            covered.insert(n(o, "epoch")?)
                && r["unit"]["Id"] == o["unit"]
                && r["unit"]["InvocationID"] == o["invocation_id"]
                && r["admission"] == o["admission"]
                && r["guard_protection"] == o["guard_protection"],
            "stale fleet owner binding"
        );
    }
    for o in &mut owners {
        let epoch = n(o, "epoch")?;
        ensure!(
            covered.contains(&epoch) || (epoch == 170 && n(o, "recorded_unix_seconds")? > sampled),
            "missing live owner in fleet"
        );
        let g = peer::bound(&o["guard_protection"])?;
        o["guard_unit"] = g["guard_unit"].clone();
        o["timer_unit"] = g["timer_unit"].clone();
        o["timer_invocation_id"] = g["timer_invocation_id"].clone();
        o["first_guard_sample"] = g["first_guard_sample"].clone();
        let s = peer::bound(&o["first_guard_sample"])?;
        ensure!(
            s["producer_invocation_id"] == o["invocation_id"] && s["trip_reason"].is_null(),
            "wrong first guard"
        );
        o["first_guard_invocation_id"] = s["guard_invocation_id"].clone();
    }
    Ok(owners)
}
fn member(pid: u64, unit: &str) -> Result<()> {
    ensure!(
        fs::read_to_string(format!("/proc/{pid}/cgroup"))?.trim()
            == format!("0::/system.slice/{unit}"),
        "peer cgroup changed"
    );
    Ok(())
}
fn kib(text: &str, field: &str) -> Result<u64> {
    let mut words = text
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .context("missing resident metric")?
        .split_whitespace();
    let x = words.next().context("resident value")?.parse::<u64>()?;
    ensure!(
        words.next() == Some("kB") && words.next().is_none(),
        "resident unit"
    );
    x.checked_mul(1024).context("PSS overflow")
}
fn census(owners: &[Value], own_iid: Option<&str>) -> Result<BTreeMap<String, BTreeSet<u64>>> {
    let mut out = BTreeMap::<String, BTreeSet<u64>>::new();
    for entry in fs::read_dir("/proc")? {
        let e = entry?;
        let Some(pid) = e.file_name().to_str().and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        let exe = match fs::read_link(e.path().join("exe")) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        let name = exe
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .trim_end_matches(" (deleted)");
        if name != "jetstreamer-node"
            && name != "historical-worker"
            && !name.starts_with("jetstreamer-historical-worker-")
        {
            continue;
        }
        let c = fs::read_to_string(e.path().join("cgroup"))?;
        let u = c
            .trim()
            .strip_prefix("0::/system.slice/")
            .context("unowned replay cgroup")?;
        let o = owners
            .iter()
            .find(|o| o["unit"] == u)
            .context("unaccounted replay unit")?;
        ensure!(
            name != "jetstreamer-node" || n(o, "main_pid")? == pid,
            "unbound producer PID"
        );
        out.entry(u.to_owned()).or_default().insert(pid);
    }
    let cand = crate::show(guard168::UNIT)?;
    if let Some(id) = own_iid {
        ensure!(
            guard168::iid(id)
                && cand["InvocationID"] == id
                && cand["ActiveState"] == "active"
                && cand["SubState"] == "running"
                && cand["NRestarts"] == "0"
                && cand["Job"] == "",
            "168 held producer changed"
        );
        let p = cand["MainPID"]
            .as_str()
            .context("candidate pid")?
            .parse::<u64>()?;
        member(p, guard168::UNIT)?;
        let exe = fs::metadata(format!("/proc/{p}/exe"))?;
        let image = fs::metadata(format!("{}/gate168", crate::PACKAGE))?;
        use std::os::unix::fs::MetadataExt;
        ensure!(
            exe.dev() == image.dev() && exe.ino() == image.ino(),
            "168 payload started before fit release"
        );
    } else {
        ensure!(closed(&cand), "duplicate 168 candidate");
    }
    Ok(out)
}
pub(super) fn resident(owners: &[Value], own_iid: Option<&str>) -> Result<BTreeMap<u64, u64>> {
    let actors = census(owners, own_iid)?;
    let mut result = BTreeMap::new();
    for o in owners {
        let unit = o["unit"].as_str().context("producer unit")?;
        let epoch = n(o, "epoch")?;
        let live = crate::show(unit)?;
        let t = crate::show(o["timer_unit"].as_str().context("guard timer")?)?;
        let main = n(o, "main_pid")?;
        ensure!(
            live["ActiveState"] == "active"
                && live["SubState"] == "running"
                && live["Job"] == ""
                && live["NRestarts"] == "0"
                && live["InvocationID"] == o["invocation_id"]
                && live["MainPID"].as_str().and_then(|v| v.parse::<u64>().ok()) == Some(main)
                && ticks(main)? == n(o, "main_start_ticks")?
                && t["ActiveState"] == "active"
                && t["Job"] == ""
                && t["InvocationID"] == o["timer_invocation_id"],
            "peer invocation changed {epoch}"
        );
        let c = Path::new("/sys/fs/cgroup/system.slice").join(unit);
        let pids = fs::read_to_string(c.join("cgroup.procs"))?
            .lines()
            .map(str::parse::<u64>)
            .collect::<Result<BTreeSet<_>, _>>()?;
        ensure!(
            pids.contains(&main) && actors.get(unit) == Some(&pids),
            "unknown process in {unit}"
        );
        let mut resident = 0;
        for pid in pids {
            member(pid, unit)?;
            let start = ticks(pid)?;
            let smaps = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;
            resident = sum(resident, kib(&smaps, "Pss:")?)?;
            member(pid, unit)?;
            ensure!(ticks(pid)? == start, "PID reuse");
        }
        let stat = fs::read_to_string(c.join("memory.stat"))?;
        let metric = |k: &str| -> Result<u64> {
            Ok(stat
                .lines()
                .filter_map(|l| l.split_once(' '))
                .find(|(n, _)| *n == k)
                .context("cgroup stat")?
                .1
                .parse()?)
        };
        let cap = fs::read_to_string(c.join("memory.max"))?
            .trim()
            .parse::<u64>()?;
        ensure!(cap == (68u64 << 30), "peer memory limit changed");
        result.insert(
            epoch,
            resident
                .min(sum(metric("anon")?, metric("file_mapped")?)?)
                .min(cap),
        );
    }
    Ok(result)
}
