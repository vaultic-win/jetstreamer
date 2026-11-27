use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const GIB: u64 = 1 << 30;
const MIB: u64 = 1 << 20;
const UNIT: &str = "horizon-143-full-local-qualification-20261126-v1.service";
const SELECTOR: &str = "horizon-167-retained-prefix-selection-20261127-v1.service";
const AUTHORITY: &str = "/var/lib/jetstreamer/horizon_runtime_data";
const LEASE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch143-bounded-entry-20261126-v1/BOUNDED_ENTRY_LEASE.json";

fn number(value: &Value) -> Result<u64> {
    value.as_u64().context("missing numeric evidence")
}

fn string(value: &Value) -> Result<&str> {
    value.as_str().context("missing string evidence")
}

fn read(reference: &Value) -> Result<Value> {
    let path = Path::new(string(&reference["path"])?);
    let meta = path.symlink_metadata()?;
    ensure!(
        path.starts_with(AUTHORITY)
            && path.canonicalize()? == path
            && meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o022 == 0
            && meta.len() <= 32 * MIB,
        "unsafe evidence path {}",
        path.display()
    );
    let raw = fs::read(path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&raw)) == string(&reference["sha256"])?,
        "changed evidence {}",
        path.display()
    );
    Ok(serde_json::from_slice(&raw)?)
}

fn command(args: &[&str]) -> Result<String> {
    let output = Command::new("/usr/bin/systemctl").args(args).output()?;
    ensure!(output.status.success(), "systemctl failed for {args:?}");
    Ok(String::from_utf8(output.stdout)?)
}

fn state(unit: &str) -> Result<BTreeMap<String, String>> {
    Ok(command(&["show", "--all", "-p", "Id,InvocationID,ActiveState,MainPID,ControlPID,Job,ControlGroup,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec", "--", unit])?
        .lines().filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.into(), v.into())).collect())
}

fn property<'a>(state: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str> {
    state
        .get(name)
        .map(String::as_str)
        .with_context(|| format!("missing PID1 property {name}"))
}

fn usage() -> Result<(u64, u64)> {
    let output = Command::new("/usr/bin/stat")
        .args(["-f", "-c", "%a %S", "/home/sol"])
        .output()?;
    ensure!(output.status.success(), "cannot read HOME statvfs");
    let blocks = String::from_utf8(output.stdout)?;
    let (available, size) = blocks
        .trim()
        .split_once(' ')
        .context("HOME statvfs fields")?;
    let disk = available
        .parse::<u64>()?
        .checked_mul(size.parse()?)
        .context("HOME byte overflow")?;
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let ram = kib_field(&meminfo, "MemAvailable:")?;
    Ok((disk, ram))
}

fn kib_field(text: &str, name: &str) -> Result<u64> {
    Ok(text
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .and_then(|line| line.split_ascii_whitespace().next())
        .with_context(|| format!("missing {name}"))?
        .parse::<u64>()?
        * 1024)
}

fn ticks(pid: u64) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(") ")
        .context("invalid proc stat")?
        .1
        .split_ascii_whitespace()
        .nth(19)
        .context("missing start ticks")?
        .parse()?)
}

fn protected(
    anchor_ref: &Value,
    roster: &Value,
    timer_iid: &Value,
    now: u64,
) -> Result<(Value, u64, u64)> {
    let anchor = read(anchor_ref)?;
    let old = &anchor["producer"];
    let cgroup = string(&old["cgroup"])?;
    let unit = cgroup.rsplit('/').next().context("producer unit")?;
    let iid = string(&old["invocation_id"])?;
    let leader = number(&old["pid"])?;
    let props = state(unit)?;
    ensure!(
        property(&props, "InvocationID")? == iid
            && property(&props, "ActiveState")? == "active"
            && property(&props, "ControlGroup")? == cgroup
            && property(&props, "MainPID")? == leader.to_string()
            && property(&props, "Job")?.is_empty()
            && property(&props, "MemorySwapMax")? == "0",
        "incumbent changed {unit}"
    );
    let timer = unit
        .replace("-qualify-", "-guard-")
        .replace(".service", ".timer");
    let timer_props = state(&timer)?;
    ensure!(
        property(&timer_props, "InvocationID")? == string(timer_iid)?
            && property(&timer_props, "ActiveState")? == "active"
            && property(&timer_props, "Job")?.is_empty(),
        "guard timer changed {timer}"
    );
    let group = format!("/sys/fs/cgroup{cgroup}");
    let native_pids = fs::read_to_string(format!("{group}/cgroup.procs"))?
        .split_ascii_whitespace()
        .map(str::parse)
        .collect::<std::result::Result<BTreeSet<u64>, _>>()?;
    let processes = roster.as_array().context("missing tracked processes")?;
    let mut pids = BTreeSet::new();
    let mut pss = 0;
    for process in processes {
        let pid = number(&process[0])?;
        let exe = fs::metadata(format!("/proc/{pid}/exe"))?;
        ensure!(
            ticks(pid)? == number(&process[1])?
                && exe.dev() == number(&process[2])?
                && exe.ino() == number(&process[3])?,
            "tracked process changed {pid}"
        );
        pids.insert(pid);
        if unit.contains("-146-") || unit.contains("-172-") {
            let smaps = fs::read_to_string(format!("/proc/{pid}/smaps_rollup"))?;
            pss += kib_field(&smaps, "Pss:")?;
        }
    }
    ensure!(
        native_pids == pids && pids.contains(&leader) && pids.len() == 2,
        "different cgroup membership {unit}"
    );
    let memory_limit = property(&props, "MemoryMax")?.parse::<u64>()?;
    ensure!(
        fs::read_to_string(format!("{group}/memory.max"))?
            .trim()
            .parse::<u64>()?
            == memory_limit,
        "different incumbent memory limit {unit}"
    );
    let memory = fs::read_to_string(format!("{group}/memory.stat"))?;
    let mem: BTreeMap<_, _> = memory
        .lines()
        .filter_map(|line| line.split_once(' '))
        .collect();
    let resident = pss
        .min(mem["anon"].parse::<u64>()? + mem["file_mapped"].parse::<u64>()?)
        .min(memory_limit);
    let directory = Path::new(string(&anchor_ref["path"])?)
        .parent()
        .context("guard directory")?;
    ensure!(
        !directory.join("stop-intent.json").exists(),
        "guard stop intent for {unit}"
    );
    let latest = fs::read_dir(directory)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("sample-"))
        .map(|entry| {
            Ok((
                entry.metadata()?.mtime(),
                entry.metadata()?.mtime_nsec(),
                entry.path(),
            ))
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .max()
        .context("missing live guard sample")?
        .2;
    let sample_ref =
        json!({"path":latest,"sha256":format!("{:x}",Sha256::digest(fs::read(&latest)?))});
    let sample = read(&sample_ref)?;
    let walk = &sample["root_physical_observation"];
    ensure!(
        now.abs_diff(number(&sample["recorded_unix_seconds"])?) <= 120
            && sample["plan_sha256"] == anchor["plan_sha256"]
            && sample["producer"] == anchor["producer"]
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["worker_observation_error"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["minimum_free_bytes"] == anchor["minimum_free_bytes"]
            && number(&sample["available_bytes"])? >= number(&sample["minimum_free_bytes"])?
            && walk["exceeds_budget"] == false
            && sample["workers"]
                .as_array()
                .is_some_and(|workers| workers.len() == 1
                    && workers[0][0]
                        .as_u64()
                        .is_some_and(|pid| pid != leader && pids.contains(&pid))),
        "invalid fresh guard sample for {unit}"
    );
    let physical =
        number(&walk["first"]["physical_bytes"])?.min(number(&walk["second"]["physical_bytes"])?);
    ensure!(
        state(unit)? == props && state(&timer)? == timer_props,
        "guard or unit changed while pricing {unit}"
    );
    Ok((sample_ref, physical, resident))
}

fn follows_observation(mut current: Value, anchor: &Value) -> Result<bool> {
    for _ in 0..2 {
        let cadence = &current["cadence"];
        ensure!(
            cadence["minimum_interval_seconds"] == 1800
                && cadence["routine_minimum_interval_enforced"] == true,
            "observation changed its routine cadence"
        );
        let predecessor = json!({
            "path": cadence["previous_sample"],
            "sha256": cadence["previous_sample_sha256"]
        });
        if &predecessor == anchor {
            return Ok(true);
        }
        current = read(&predecessor)?;
    }
    Ok(false)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 6 && matches!(args[0].as_str(), "prestart" | "held"),
        "usage: price_entry143 prestart|held FLEET FLEET_SHA 170_POST_GUARD 170_SHA 170_FIRST_WORKER_SHA"
    );
    let held = args[0] == "held";
    let fleet_ref = json!({"path":args[1],"sha256":args[2]});
    let quote_ref = json!({"path":args[3],"sha256":args[4]});
    let bridge_first = PathBuf::from(&args[3]).with_file_name("FIRST_PROTECTED_WORKER.json");
    let fleet = read(&fleet_ref)?;
    let quote = read(&quote_ref)?;
    let native = &quote["native"];
    let accepted = read(&native["fleet"])?;
    let first = read(&json!({"path":bridge_first,"sha256":args[5]}))?;
    let release = &native["released_167"];
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let first_usage = usage()?;
    let sample = read(&fleet["observer"])?;
    let same_fleet = fleet_ref == native["fleet"];
    ensure!(
        quote["phase"] == "post-guard"
            && quote["resource_credit_bytes"] == 0
            && fleet["all_reservation_ending_bytes"] == 0
            && fleet["resource_credit_bytes"] == 0
            && fleet["actual_active_bootstraps"] == json!([])
            && fleet["actual_active_holding_transfers"] == json!([])
            && fleet["actual_active_retirements"] == json!([])
            && fleet["actual_active_retirement_checks"] == json!([])
            && (same_fleet && !held || follows_observation(sample, &accepted["observer"])?),
        "future fleet or changed reservations"
    );
    let stable = |f: &Value| -> Result<Vec<Value>> {
        f["actual_executing_replays"]
            .as_array()
            .context("missing replay roster")?
            .iter()
            .map(|r| {
                Ok(json!([
                    r["epoch"],
                    r["unit"]["Id"],
                    r["unit"]["InvocationID"],
                    r["start_ticks"],
                    r["admission"]
                ]))
            })
            .collect()
    };
    ensure!(
        stable(&fleet)? == stable(&accepted)? && stable(&fleet)?.len() == 2,
        "full replay roster changed"
    );
    let mut rosters = release["tracked_processes"]
        .as_object()
        .context("missing price roster")?
        .clone();
    let bridge_unit = string(&first["actor"]["unit"])?;
    ensure!(
        first["actor"]["producer_invocation_id"] == quote["actor"]["producer_invocation_id"]
            && first["actor"]["start_ticks"] == quote["actor"]["start_ticks"],
        "different 170 bridge"
    );
    rosters.insert(bridge_unit.into(), first["actor"]["processes"].clone());
    if !same_fleet {
        let diagnostics = fleet["actual_active_private_diagnostics"]
            .as_array()
            .context("missing accepted private replay roster")?;
        ensure!(
            diagnostics.len() == 2
                && diagnostics.iter().all(|row| {
                    matches!(row["epoch"].as_u64(), Some(167 | 170))
                        && row["phase"] == "worker"
                        && row["unit"]["Id"]
                            .as_str()
                            .and_then(|unit| rosters.get(unit))
                            == Some(&row["processes"])
                })
                && diagnostics[0]["epoch"] != diagnostics[1]["epoch"],
            "accepted private replay roster changed"
        );
    }
    let listing = command(&[
        "list-units",
        "--type=service",
        "--state=running,activating,deactivating",
        "--plain",
        "--no-legend",
        "horizon-qualify-*",
    ])?;
    ensure!(
        listing
            .lines()
            .filter_map(|line| line.split_ascii_whitespace().next())
            .collect::<BTreeSet<_>>()
            == rosters.keys().map(String::as_str).collect(),
        "foreign replay unit"
    );
    let holding = read(&fleet["epoch185_lanel_holding"])?;
    let original_holding = read(&accepted["epoch185_lanel_holding"])?;
    ensure!(
        holding["result"] == original_holding["result"],
        "185 holding obligations changed"
    );
    for key in [
        "additional_cpu_quota_micros",
        "additional_memory_bytes",
        "maximum_output_allocation_bytes",
    ] {
        ensure!(
            fleet["active_ready_range_audit_obligation"][key]
                == accepted["active_ready_range_audit_obligation"][key],
            "ready audit changed {key}"
        );
    }
    let mut additional = 0;
    let mut resident = 0;
    let mut guards = BTreeMap::new();
    for peer in fleet["actual_executing_replays"]
        .as_array()
        .context("missing replays")?
    {
        let unit = string(&peer["unit"]["Id"])?;
        let anchor = &release["checked_samples"][unit];
        let (reference, physical, credit) = protected(
            &anchor["sample"],
            &rosters[unit],
            &peer["guard_timer"]["InvocationID"],
            now,
        )?;
        additional += number(&anchor["lower"])?.saturating_sub(physical);
        resident += credit;
        guards.insert(unit, reference);
    }
    let guard167 = &release["incumbent_guard"];
    let anchor167 = read(&guard167["sample"])?;
    let unit167 = string(&anchor167["producer"]["cgroup"])?
        .rsplit('/')
        .next()
        .context("167 unit")?;
    let (reference, physical, _) = protected(
        &guard167["sample"],
        &rosters[unit167],
        &guard167["timer_invocation_id"],
        now,
    )?;
    let growth167 = number(&guard167["run_guard_cap_bytes"])?
        .checked_sub(physical)
        .context("167 over cap")?;
    guards.insert(unit167, reference);
    let guard170 = &quote["first_guard"];
    let (reference, physical, _) = protected(
        &guard170["sample"],
        &rosters[bridge_unit],
        &guard170["timer_invocation_id"],
        now,
    )?;
    let growth170 = number(&guard170["cap"])?
        .checked_sub(physical)
        .context("170 over cap")?;
    guards.insert(bridge_unit, reference);
    let selector = state(SELECTOR)?;
    ensure!(
        property(&selector, "ActiveState")? != "active"
            || (property(&selector, "MemoryMax")? == (4 * GIB).to_string()
                && property(&selector, "MemorySwapMax")? == "0"),
        "167 retained prefix selector changed"
    );
    let fit_actor = if held {
        let lease_ref = &fleet["epoch143_bounded_entry_lease"];
        ensure!(
            lease_ref["path"] == LEASE,
            "143 hold lacks accepted fleet lease"
        );
        let lease = read(lease_ref)?;
        let actor = state(UNIT)?;
        let pid = number(&lease["pid"])?;
        ensure!(
            lease["unit"] == UNIT
                && property(&actor, "MainPID")? == pid.to_string()
                && property(&actor, "InvocationID")? == string(&lease["invocation_id"])?
                && property(&actor, "ActiveState")? == "active"
                && property(&actor, "MemoryMax")? == (192 * MIB).to_string()
                && property(&actor, "CPUQuotaPerSecUSec")? == "250ms"
                && property(&actor, "MemorySwapMax")? == "0"
                && ticks(pid)? == number(&lease["start_ticks"])?,
            "different 143 hold"
        );
        json!({"unit":UNIT,"invocation_id":lease["invocation_id"],"pid":pid,"start_ticks":lease["start_ticks"],
            "memory_bytes":192*MIB,"scratch_bytes":8*MIB,"additional_cpu_quota_micros":0,"registration":lease_ref})
    } else {
        ensure!(
            fleet["epoch143_bounded_entry_lease"].is_null()
                && fleet["epoch146_bounded_entry_lease"].is_null(),
            "bounded audit slot already held"
        );
        Value::Null
    };
    let second_usage = usage()?;
    let available_home = first_usage.0.min(second_usage.0);
    let available_memory = first_usage.1.min(second_usage.1);
    // The released 167 projection kept 782,740,762,624 bytes plus 6 GiB before
    // deducting current 146/172 residency; the bridge borrowed the existing 170 booking.
    let memory_before_residency = 782_740_762_624 + 6 * GIB;
    let required_ram = memory_before_residency - resident + 4 * GIB + 192 * MIB + 8 * MIB;
    // No earlier disk commitments or recovered allocations become spendable here.
    let required_home =
        number(&native["armed_floor"])? + additional + growth167 + growth170 + 16 * MIB + 2 * MIB;
    println!(
        "{}",
        json!({"schema":"horizon-incident-replay-fit-v1","phase":args[0],"fleet":fleet_ref,
        "fits":available_home >= required_home && available_memory >= required_ram,
        "bounded_qualification":fit_actor,"resource_credit_bytes":0,"recorded_unix_seconds":now,
        "available_HOME_bytes":available_home,"complete_required_HOME_bytes":required_home,
        "available_memory_bytes":available_memory,"required_available_memory_bytes":required_ram,
        "prior_fit":quote_ref,"live_guards":guards,"resident_lower_bound_bytes":resident,
        "incumbent_disk_growth_bytes":additional,"remaining_167_bytes":growth167,"remaining_170_bytes":growth170,
        "reserved_new_selector_HOME_bytes":16*MIB,"reserved_new_selector_RAM_bytes":4*GIB,
        "archive_publication_authorized":false,"full_replay_authorized":false})
    );
    Ok(())
}
