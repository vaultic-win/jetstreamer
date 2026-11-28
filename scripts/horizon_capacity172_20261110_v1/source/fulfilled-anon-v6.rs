//! Finite six-owner epoch172 remaining-growth qualification after distinct genuine prior endings.
//! Existing hard promises stay intact; no RSS/file-cache credit or pool allocation authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-fulfilled-anon-memory-tools-20261110-v6/check";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const GIB: u64 = 1 << 30;
const BASE_MEMORY: u64 = 685_701_345_280;
const BASE_DATA: u64 = 5_783_162_011_442;
const CAP: u64 = 68 * GIB;
const MARGIN: u64 = GIB;
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing integer {k}"))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn bytes(p: &Path, max: u64, virtual_file: bool) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical input path required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && (virtual_file || m.len() <= max),
        "Root input custody/size differs"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= max
            && (virtual_file || raw.len() as u64 == m.len())
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "input identity or bound changed"
    );
    Ok(raw)
}
fn bound(b: &Value) -> Result<Value> {
    let raw = bytes(Path::new(s(b, "path")?), 32 << 20, false)?;
    ensure!(sha(&raw) == s(b, "sha256")?, "bound metadata hash differs");
    Ok(serde_json::from_slice(&raw)?)
}
fn native(name: &str) -> Result<Value> {
    ensure!(
        name.ends_with(".service")
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unsafe unit name"
    );
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",name,"--no-pager","-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Restart,Job,MemoryAccounting,MemoryMax,MemorySwapMax,Delegate"]).output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= 65536,
        "native capture failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    Ok(Value::Object(m))
}
fn owner(actual: &Value, expected: &Value) -> Result<()> {
    ensure!(
        actual["LoadState"] == "loaded"
            && actual["ActiveState"] == "active"
            && actual["SubState"] == "running"
            && actual["ControlPID"] == "0"
            && actual["NRestarts"] == "0"
            && actual["Job"] == ""
            && s(actual, "MainPID")?.parse::<u64>()? > 0,
        "owner not stable running"
    );
    for k in ["Id", "InvocationID", "MainPID"] {
        ensure!(actual[k] == expected[k], "owner identity changed: {k}");
    }
    Ok(())
}
fn counter(text: &str, key: &str) -> Result<u64> {
    let mut keys = BTreeSet::new();
    let mut found = None;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2 && keys.insert(fields[0]),
            "invalid/duplicate cgroup counter"
        );
        let value = fields[1].parse::<u64>()?;
        if fields[0] == key {
            found = Some(value);
        }
    }
    found.context("required cgroup counter absent")
}
fn meminfo(raw: &str) -> Result<(u64, u64)> {
    let mut total = None;
    let mut available = None;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            anyhow::bail!("meminfo delimiter")
        };
        if ["MemTotal", "MemAvailable"].contains(&key) {
            let fields = value.split_whitespace().collect::<Vec<_>>();
            ensure!(
                fields.len() == 2 && fields[1] == "kB",
                "meminfo unit differs"
            );
            let value = fields[0]
                .parse::<u64>()?
                .checked_mul(1024)
                .context("meminfo overflow")?;
            let slot = if key == "MemTotal" {
                &mut total
            } else {
                &mut available
            };
            ensure!(slot.replace(value).is_none(), "duplicate meminfo field");
        }
    }
    let total = total.context("MemTotal absent")?;
    let available = available.context("MemAvailable absent")?;
    ensure!(
        total > 0 && available > 0 && available <= total,
        "invalid host available memory"
    );
    Ok((total, available))
}
fn host() -> Result<Value> {
    let raw = bytes(Path::new("/proc/meminfo"), 65536, true)?;
    let (total, available) = meminfo(std::str::from_utf8(&raw)?)?;
    Ok(json!({"total_bytes":total,"available_bytes":available,"raw_meminfo_sha256":sha(&raw)}))
}
fn gauges(expected: &Value) -> Result<Value> {
    let name = s(expected, "Id")?;
    let unit = native(name)?;
    owner(&unit, expected)?;
    ensure!(
        unit["MemoryAccounting"] == "yes"
            && unit["MemoryMax"] == "73014444032"
            && unit["MemorySwapMax"] == "0"
            && unit["Delegate"] == "no"
            && unit["ControlGroup"] == format!("/system.slice/{name}"),
        "exact68GiB zero-swap producer envelope required"
    );
    let path = Path::new("/sys/fs/cgroup").join(s(&unit, "ControlGroup")?.trim_start_matches('/'));
    ensure!(path.is_dir(), "original producer cgroup missing");
    let stat = bytes(&path.join("memory.stat"), 32768, true)?;
    let anon = counter(std::str::from_utf8(&stat)?, "anon")?;
    let current = std::str::from_utf8(&bytes(&path.join("memory.current"), 64, true)?)?
        .trim()
        .parse::<u64>()?;
    let swap = std::str::from_utf8(&bytes(&path.join("memory.swap.current"), 64, true)?)?
        .trim()
        .parse::<u64>()?;
    let events = bytes(&path.join("memory.events"), 16384, true)?;
    ensure!(
        counter(std::str::from_utf8(&events)?, "oom")? == 0
            && counter(std::str::from_utf8(&events)?, "oom_kill")? == 0,
        "producer has an OOM event"
    );
    ensure!(
        anon <= current && current <= CAP && swap == 0,
        "anonymous/current/cap/swap counters conflict"
    );
    Ok(
        json!({"unit":unit,"anonymous_bytes":anon,"memory_current_bytes":current,"memory_swap_current_bytes":swap,"memory_stat_sha256":sha(&stat),"memory_events_sha256":sha(&events),"anonymous_is_a_component_of_the_existing_hard_cap":true,"file_cache_RSS_and_other_cgroups_counted_bytes":0}),
    )
}
fn fulfilled(a: u64, b: u64, cap: u64) -> Result<u64> {
    ensure!(
        cap == CAP && a <= cap && b <= cap,
        "fulfilled amount exceeds original hard cap"
    );
    Ok(a.min(b).saturating_sub(MARGIN))
}
fn required(base: u64, candidate: u64, headroom: u64, already_resident: u64) -> Result<u64> {
    base.checked_add(candidate)
        .and_then(|v| v.checked_add(headroom))
        .and_then(|v| v.checked_sub(already_resident))
        .context("remaining-growth arithmetic overflow/underflow")
}
fn candidate_memory(plan: &Value) -> Result<u64> {
    ensure!(plan["candidate_epoch"]==172 && plan["candidate_actor_memory_bytes"]==68*GIB && plan["candidate_guard_memory_bytes"]==GIB && plan["additional_host_headroom_bytes"]==16*GIB,"exact172 actor68+guard1 and host16 required");Ok(69*GIB)
}
fn ended_projection(memory: u64, data: u64, actor: u64, future_data: u64) -> Result<()> {
    ensure!(actor==48*GIB && future_data==480_969_228_288 && memory.checked_sub(actor)==Some(BASE_MEMORY) && data.checked_sub(future_data)==Some(BASE_DATA),"current prior endings crossed or reapplied");Ok(())
}
fn selected_prior_endings(parent: &Value, fleet: &Value, plan: &Value) -> Result<()> {
    ensure!(parent["schema"]=="horizon-Root-once-only-old722-future-DATA-selection-authority-v1" && parent["current_complete_fleet"]==plan["current_fleet"] && parent["additional_once_only_ended_unused_future_DATA_bytes"]==480_969_228_288u64 && parent["actor48_memory_ending_reapplied_bytes"]==0 && parent["physical_retirement_bytes"]==0 && parent["holding_credit_bytes"]==0,"actual distinct DATA-only selection required");
    let memory=bound(&parent["prior_once_only_actor48_memory_selection"])?;let me=bound(&memory["genuine_memory_only_ending"])?;let de=bound(&parent["genuine_distinct_DATA_only_ending"])?;
    ensure!(memory["schema"]=="horizon-Root-once-only-old722-actor48-memory-ending-selection-authority-v1" && memory["current_complete_fleet"]==plan["current_fleet"] && memory["additional_once_only_ended_actor_memory_bytes"]==48*GIB && memory["complete_projected_memory_bytes"]==BASE_MEMORY && memory["complete_DATA_bytes"]==fleet["complete_DATA_bytes"] && me["ended_actor_memory_bytes"]==48*GIB && me["ended_future_DATA_bytes"]==0 && me["base_projected_memory_bytes_after"]==BASE_MEMORY && de["ended_actor_memory_bytes"]==0 && de["prior_actor48_memory_ending_reapplied_bytes"]==0 && de["ended_future_DATA_bytes"]==480_969_228_288u64 && de["base_projected_memory_bytes_after"]==BASE_MEMORY && de["complete_DATA_bytes"]==BASE_DATA,"both genuine independent ending receipts must remain selected once");
    ended_projection(n(fleet,"complete_projected_memory_bytes")?,n(fleet,"complete_DATA_bytes")?,48*GIB,480_969_228_288)
}
fn own_unit(plan: &Value) -> Result<&'static str> {
    match s(plan, "purpose")? {
        "qualification" => Ok("horizon-fulfilled-anon-memory-qualification-20261110-v6.service"),
        "epoch172-admission-check" => {
            Ok("horizon-fulfilled-anon-memory-epoch172-admission-check-20261110-v6.service")
        }
        _ => anyhow::bail!("unqualified purpose"),
    }
}
fn run(plan: &Value) -> Result<Value> {
    ensure!(
        plan["schema"] == "horizon-fulfilled-anon-memory-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == PRIMARY,
        "exclusive Root plan required"
    );
    let parent = bound(&plan["current_complete_authority"])?;
    ensure!(
        parent["owner"] == "/root"
            && parent["primary_thread"] == PRIMARY
            && parent["complete_projected_memory_bytes"] == BASE_MEMORY
            && n(&parent, "complete_DATA_bytes")? >= BASE_DATA,
        "complete unreduced hard-promise authority differs"
    );
    let fleet = bound(&plan["current_fleet"])?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["live_replay_count"] == 6
            && fleet["complete_projected_memory_bytes"] == BASE_MEMORY + 48*GIB
            && n(&fleet, "complete_DATA_bytes")? >= 6_263_929_913_138
            && fleet["sampled_at_utc"] == "2026-11-10T03:30:22Z"
            && now()?
                .checked_sub(1794281422)
                .is_some_and(|age| age <= 1800),
        "exact fresh complete six-owner context required"
    );
    selected_prior_endings(&parent,&fleet,plan)?;
    let candidate = candidate_memory(plan)?;
    let own = own_unit(plan)?;
    let mine = native(own)?;
    ensure!(
        mine["InvocationID"] == std::env::var("INVOCATION_ID")?
            && s(&mine, "MainPID")?.parse::<u32>()? == std::process::id()
            && mine["MemoryMax"] == "536870912"
            && mine["MemorySwapMax"] == "0"
            && mine["NRestarts"] == "0"
            && mine["Restart"] == "no"
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{own}"),
        "own funded512MiB identity differs"
    );
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("complete six replays")?;
    ensure!(rows.len() == 6, "six rows required");
    let mut epochs = BTreeSet::new();
    let mut iids = BTreeSet::new();
    for row in rows {
        ensure!(
            epochs.insert(n(row, "epoch")?) && iids.insert(s(&row["unit"], "InvocationID")?),
            "duplicate replay epoch/IID"
        );
    }
    ensure!(
        epochs == BTreeSet::from([166, 167, 168, 169, 170, 171]),
        "exact live epoch set required"
    );
    let stable = fleet["stable_non_replay_owners"]
        .as_object()
        .context("stable background census")?;
    ensure!(
        stable.len() == 2,
        "two persistent background owners required"
    );
    let mut background_before = serde_json::Map::new();
    for (name, expected) in stable {
        let actual = native(name)?;
        owner(&actual, expected)?;
        background_before.insert(name.clone(), actual);
    }
    let started = now()?;
    let host_before = host()?;
    let mut before = Vec::new();
    for row in rows {
        before.push(gauges(&row["unit"])?);
    }
    let mut after = Vec::new();
    for row in rows {
        after.push(gauges(&row["unit"])?);
    }
    let host_after = host()?;
    let mut total = 0u64;
    let mut credits = Vec::new();
    for (a, b) in before.iter().zip(&after) {
        ensure!(
            a["unit"] == b["unit"],
            "producer native identity/envelope changed during sample"
        );
        let amount = fulfilled(n(a, "anonymous_bytes")?, n(b, "anonymous_bytes")?, CAP)?;
        total = total
            .checked_add(amount)
            .context("fulfilled sum overflow")?;
        credits.push(json!({"unit":a["unit"]["Id"],"invocation_id":a["unit"]["InvocationID"],"conservative_nonreclaimable_fulfilled_bytes":amount,"per_lane_additional_margin_bytes":MARGIN}));
    }
    let mut background_after = serde_json::Map::new();
    for (name, expected) in stable {
        let actual = native(name)?;
        owner(&actual, expected)?;
        background_after.insert(name.clone(), actual);
    }
    ensure!(
        background_before == background_after
            && bound(&plan["current_complete_authority"])? == parent
            && host_before["total_bytes"] == host_after["total_bytes"]
            && now()?
                .checked_sub(started)
                .is_some_and(|elapsed| elapsed <= 30),
        "background/authority/host changed or finite sample expired"
    );
    let available = n(&host_before, "available_bytes")?.min(n(&host_after, "available_bytes")?);
    let full = required(BASE_MEMORY, candidate, 16 * GIB, 0)?;
    let remaining = required(BASE_MEMORY, candidate, 16 * GIB, total)?;
    Ok(
        json!({"schema":"horizon-fulfilled-anon-memory-native-check-v1","owner":"/root","primary_thread":PRIMARY,"recorded_unix_seconds":now()?,"planning_sample_expires_unix_seconds":now()?.checked_add(300).context("expiry overflow")?,"plan":plan,"native_self":mine,"host_before":host_before,"host_after":host_after,"producer_before":before,"producer_after":after,"persistent_background_before":background_before,"persistent_background_after":background_after,"per_producer_fulfilled":credits,"complete_hard_memory_promises_preserved_bytes":BASE_MEMORY,"candidate_additive_hard_memory_bytes":candidate,"additional_host_headroom_bytes":16*GIB,"already_resident_nonreclaimable_anonymous_bytes_counted_in_those_caps":total,"full_caps_plus_candidate_and_headroom_bytes":full,"required_available_memory_for_remaining_growth_bytes":remaining,"conservative_available_memory_bytes":available,"candidate_fits_this_native_sample":available>=remaining,"kernel_zero_swap_anon_semantics_only":true,"RSS_file_cache_shared_pages_and_other_cgroups_credited_bytes":0,"new_memory_or_DATA_promise_bytes":0,"resource_credit_bytes":0,"hard_promises_released_bytes":0,"physical_credit_bytes":0,"native_Frame_or_full_Reader_authority":false,"replay_launch_authorized":false,"producer_mutations":false,"remote_mutations":false,"new_resource_observations":true,"observation_reason":"admission-qualification","routine_observation_cadence_reset":false}),
    )
}
fn main() -> Result<()> {
    let a = std::env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 6 && a[2] == "--plan-sha256" && a[4] == "--self-sha256",
        "exact argv required"
    );
    let image = fs::read_link("/proc/self/exe")?;
    ensure!(
        image == Path::new(IMAGE) && sha(&bytes(&image, 32 << 20, false)?) == a[5],
        "normally sealed self image required"
    );
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let report = run(&plan)?;
    let output = Path::new(s(&plan, "output")?);
    let parent = output.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private output parent required"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &report)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"output":output,"candidate_fits_this_native_sample":report["candidate_fits_this_native_sample"],"resource_credit_bytes":0,"replay_launch_authorized":false})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cgroup_parser_rejects_duplicate_missing_and_fractional_anon() {
        assert_eq!(counter("anon 42\nfile 999999\n", "anon").unwrap(), 42);
        assert!(counter("anon 1\nanon 2\n", "anon").is_err());
        assert!(counter("file 1\n", "anon").is_err());
        assert!(counter("anon 1.5\n", "anon").is_err());
    }
    #[test]
    fn host_parser_requires_exact_units_no_overflow_and_valid_available() {
        assert_eq!(
            meminfo("MemTotal: 100 kB\nMemAvailable: 60 kB\n").unwrap(),
            (102400, 61440)
        );
        for raw in [
            "MemTotal: 100 MB\nMemAvailable: 60 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 200 kB\n",
            "MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 2 kB\nMemAvailable: 3 kB\n",
        ] {
            assert!(meminfo(raw).is_err());
        }
    }
    #[test]
    fn fulfilled_is_the_smaller_anon_endpoint_minus_an_extra_margin() {
        assert_eq!(fulfilled(9 * GIB, 8 * GIB, CAP).unwrap(), 7 * GIB);
        assert_eq!(fulfilled(GIB / 2, GIB, CAP).unwrap(), 0);
        assert!(fulfilled(CAP + 1, CAP, CAP).is_err());
        assert!(fulfilled(GIB, GIB, CAP + 1).is_err());
    }
    #[test]
    fn hard_promises_stay_intact_while_remaining_growth_counts_consumed_bytes_once() {
        assert_eq!(required(200, 30, 10, 20).unwrap(), 220);
        assert_eq!(required(200, 30, 10, 0).unwrap(), 240);
        assert!(required(u64::MAX, 1, 0, 0).is_err());
        assert!(required(1, 1, 1, 4).is_err());
    }
    #[test]
    fn file_cache_alone_never_counts_as_fulfilled() {
        let anon = counter("anon 0\nfile 18446744073709551615\n", "anon").unwrap();
        assert_eq!(fulfilled(anon, anon, CAP).unwrap(), 0);
    }
    #[test]
    fn only_the_qualified_purposes_can_run() {
        assert!(own_unit(&json!({"purpose":"qualification"})).is_ok());
        assert!(own_unit(&json!({"purpose":"epoch172-admission-check"})).is_ok());
        assert!(own_unit(&json!({"purpose":"replay"})).is_err());
    }
    #[test]
    fn candidate172_keeps_actor_guard_and_host_headroom_exact() {
        let p=json!({"candidate_epoch":172,"candidate_actor_memory_bytes":68*GIB,"candidate_guard_memory_bytes":GIB,"additional_host_headroom_bytes":16*GIB});assert_eq!(candidate_memory(&p).unwrap(),69*GIB);
        for (key,value) in [("candidate_epoch",171),("candidate_actor_memory_bytes",67*GIB),("candidate_guard_memory_bytes",0),("additional_host_headroom_bytes",15*GIB)] {let mut bad=p.clone();bad[key]=json!(value);assert!(candidate_memory(&bad).is_err());}
    }
    #[test]
    fn distinct_prior_endings_preserve_raw_fleet_and_cannot_be_applied_twice() {
        let m=BASE_MEMORY+48*GIB;let d=BASE_DATA+480_969_228_288;
        assert!(ended_projection(m,d,48*GIB,480_969_228_288).is_ok());assert!(ended_projection(BASE_MEMORY,d,48*GIB,480_969_228_288).is_err());assert!(ended_projection(m,BASE_DATA,48*GIB,480_969_228_288).is_err());assert!(ended_projection(m,d,0,480_969_228_288).is_err());assert!(ended_projection(m,d,48*GIB,0).is_err());
    }
}
