#![recursion_limit = "512"]
//! Metadata-only Root review; never native Frame, full Reader, admission or release authority.
use anyhow::ensure;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-native16-serial8-reuse-tools-20261110-v2/check";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Type,Job,MemoryMax,MemorySwapMax,MemoryAccounting,Restart";
fn need(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str()
        .ok_or_else(|| format!("missing string {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing integer {k}").into())
}
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn now() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn ident(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.mode(),
        m.uid(),
        m.gid(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn raw(path: &Path) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical metadata path required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20,
        "unsafe Root metadata",
    )?;
    let mut b = Vec::new();
    Read::by_ref(&mut f)
        .take((32 << 20) + 1)
        .read_to_end(&mut b)?;
    need(
        b.len() as u64 == m.len()
            && ident(&m) == ident(&f.metadata()?)
            && ident(&m) == ident(&fs::symlink_metadata(path)?),
        "metadata changed",
    )?;
    Ok(b)
}
fn bound(b: &Value) -> R<Value> {
    let bytes = raw(Path::new(s(b, "path")?))?;
    need(
        sha(&bytes) == s(b, "sha256")?,
        "bound metadata digest mismatch",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn durable(path: &Path, value: &Value) -> R<()> {
    let parent = path.parent().ok_or("output parent")?;
    need(
        parent.is_absolute() && parent.canonicalize()? == parent,
        "canonical output parent required",
    )?;
    let m = fs::symlink_metadata(parent)?;
    need(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private Root output parent required",
    )?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn command(args: &[&str], cap: usize) -> R<String> {
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args(args)
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= cap,
        "systemd metadata capture failed",
    )?;
    Ok(String::from_utf8(out.stdout)?)
}
fn unit_name(name: &str) -> R<()> {
    need(
        !name.starts_with('-')
            && (name.ends_with(".service") || name.ends_with(".timer"))
            && name.bytes().all(|b| (33..127).contains(&b)),
        "invalid unit name",
    )
}
fn native(name: &str) -> R<Value> {
    unit_name(name)?;
    let text = command(&["show", name, "--no-pager", "-p", FIELDS], 65536)?;
    let mut v = serde_json::Map::new();
    for line in text.lines() {
        let (k, x) = line.split_once('=').ok_or("native delimiter")?;
        need(
            v.insert(k.into(), json!(x)).is_none(),
            "duplicate native property",
        )?;
    }
    for key in ["Id", "LoadState", "ActiveState", "SubState", "InvocationID"] {
        need(
            v.get(key).is_some_and(Value::is_string),
            "incomplete native metadata",
        )?;
    }
    Ok(Value::Object(v))
}
fn discover() -> R<BTreeSet<String>> {
    let text = command(
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--type=service",
            "--type=timer",
        ],
        16 << 20,
    )?;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let name = line
            .split_whitespace()
            .next()
            .ok_or("empty loaded unit row")?;
        if name.contains("horizon") || name.contains("epoch") || name.contains("root-sweep") {
            unit_name(name)?;
            need(out.insert(name.into()), "duplicate loaded unit")?;
        }
    }
    Ok(out)
}
fn live(v: &Value) -> bool {
    v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["MainPID"]
            .as_str()
            .is_some_and(|x| x.parse::<u64>().is_ok_and(|p| p > 0))
}
fn owner_matches(actual: &Value, expected: &Value) -> R<()> {
    need(
        live(actual) && actual["NRestarts"] == "0" && actual["ControlPID"] == "0",
        "owner not stable running",
    )?;
    for (native_key, plan_key) in [
        ("Id", "unit"),
        ("InvocationID", "invocation_id"),
        ("MainPID", "main_pid"),
    ] {
        need(
            actual[native_key] == expected[plan_key],
            "owner identity mismatch",
        )?;
    }
    Ok(())
}
const POOL: u64 = 16 << 30;
fn old_pool(v: &Value) -> R<u64> {
    need(
        v["native_pool_bytes"] == POOL && v["new_allocation_authorized"] == false,
        "qualified retained native16 pool required",
    )?;
    let rows = v["native_pool_suballocations"]
        .as_array()
        .ok_or("old pool census")?;
    need(
        rows.len() == 6,
        "exact historical six-owner pool census required",
    )?;
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut sum = 0u64;
    for row in rows {
        unit_name(s(row, "unit")?)?;
        need(
            names.insert(s(row, "unit")?)
                && ids.insert(s(row, "invocation_id")?)
                && s(row, "invocation_id")?.len() == 32,
            "duplicate pool ownership",
        )?;
        let cap = n(row, "memory_max_bytes")?;
        if s(row, "unit")? == "horizon-failed4-current-accounting-reader-20261104-v1.service" {
            need(
                cap == 2 << 30 && row["nonoverlapping_successor_slot"] == true,
                "historical reader slot differs",
            )?;
        } else {
            need(
                s(row, "unit")?.starts_with("horizon-epoch161-snapshot-download-")
                    && cap == 512 << 20
                    && row["state"] == "failed-retained-input"
                    && row["native_pool_release_pending_status_cleanup"] == true,
                "failed downloader reservation must be retained",
            )?;
        }
        sum = sum.checked_add(cap).ok_or("pool sum overflow")?;
    }
    need(
        sum == n(v, "native_pool_committed_bytes")? && sum == 4_831_838_208,
        "original pool sum differs",
    )?;
    Ok(sum)
}
fn fit(retained: u64, extra: u64) -> R<u64> {
    need(
        extra > 0 && extra <= 8 << 30,
        "only a bounded compiler suballocation is supported",
    )?;
    let total = retained
        .checked_add(extra)
        .ok_or("suballocation overflow")?;
    need(
        total <= POOL,
        "retained native16 pool would be overcommitted",
    )?;
    Ok(total)
}
fn executing(v: &Value) -> bool {
    v["MainPID"]
        .as_str()
        .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
        || v["ControlPID"]
            .as_str()
            .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
}
fn classify(
    unit: &str,
    value: &Value,
    owners: &BTreeMap<String, Value>,
    guards: &BTreeMap<String, Value>,
    own: &str,
) -> R<()> {
    let job = value["Job"].as_str().ok_or("native job property missing")?;
    if let Some(expected) = owners.get(unit) {
        owner_matches(value, expected)?;
        return Ok(());
    }
    if let Some(expected) = guards.get(unit) {
        need(
            value["MemoryMax"] == expected["MemoryMax"]
                && value["MemorySwapMax"] == "0"
                && value["Restart"] == "no",
            "separate guard hard envelope changed",
        )?;
        return Ok(());
    }
    if unit == own {
        need(
            live(value)
                && s(value, "MainPID")?.parse::<u32>()? == std::process::id()
                && value["InvocationID"] == std::env::var("INVOCATION_ID")?
                && value["MemoryMax"] == "536870912"
                && value["MemorySwapMax"] == "0"
                && value["NRestarts"] == "0",
            "exact own Root callback512 required",
        )?;
        return Ok(());
    }
    need(
        !executing(value) && job.is_empty(),
        "unclassified executing or queued Horizon unit; no native-pool reuse authority",
    )
}
fn take(
    owners: &BTreeMap<String, Value>,
    guards: &BTreeMap<String, Value>,
    own: &str,
    historical: &[Value],
) -> R<BTreeMap<String, Value>> {
    let mut names = discover()?;
    names.extend(owners.keys().cloned());
    names.extend(guards.keys().cloned());
    names.insert(own.into());
    for row in historical {
        names.insert(s(row, "unit")?.into());
    }
    let mut result = BTreeMap::new();
    for name in names {
        let value = native(&name)?;
        classify(&name, &value, owners, guards, own)?;
        result.insert(name, value);
    }
    for row in historical {
        let value = &result[s(row, "unit")?];
        need(
            !executing(value) && value["Job"] == "" && !live(value),
            "historical native-pool slot restarted; retain and deny reuse",
        )?;
    }
    Ok(result)
}

fn reuse_projection(retained: u64, serial: u64) -> R<u64> {
    need(
        retained == 4_831_838_208 && serial == 8u64 << 30,
        "only exact existing serial8 can be reused",
    )?;
    let base = fit(retained, serial)?;
    let committed = base
        .checked_add(256u64 << 20)
        .and_then(|n| n.checked_add(64u64 << 20))
        .ok_or("native8 backing overflow")?;
    need(
        committed == 13_757_317_120 && committed + (512u64 << 20) <= POOL,
        "all existing native8/guard/OS and current512 callback must fit",
    )?;
    Ok(committed)
}
fn backing(plan: &Value, parent: &Value) -> R<()> {
    need(
        plan["current_complete_resource_authority"]
            == json!({"path":"/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json","sha256":"2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa"})
            && parent["complete_DATA_bytes"] == 6_229_838_610_226u64
            && parent["complete_projected_memory_bytes"] == 759_789_531_136u64
            && parent["retained_native16_pool_bytes"] == POOL
            && parent["effective_verification_pool_bytes"] == 96u64 << 30
            && parent["retained_shared_pool_bytes"] == 64u64 << 30
            && parent["normal_pool_bytes"] == 10u64 << 30,
        "genuine current selected154 head and all retained pools required",
    )?;
    need(
        plan["serial8_existing_backing"]
            == json!({"path":"/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ROOT_VERIFICATION144_NATIVE16_PROFILE48_CURRENT_AUTHORITY.json","sha256":"9def5e3b680a13f9a414bf100c0ef70f2f2abcecc10937eb7599d188d04ec060"}),
        "exact existing8 funding point required",
    )?;
    let b = bound(&plan["serial8_existing_backing"])?;
    need(
        b["retained_native16_pool_bytes"] == POOL
            && b["staged_full_helper_control_bytes"] == 8u64 << 30
            && b["staged_profile_guard_bytes"] == 256u64 << 20
            && b["all_original_native_pool_rows_retained_bytes"] == 4_831_838_208u64,
        "existing8 backing/guard/historical rows differ",
    )?;
    need(
        plan["profile48_already_cancelled"]
            == json!({"path":"/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/ROOT_ONCE_ONLY_UNUSED_VERIFICATION32_FUTURE_ENDED_CURRENT_AUTHORITY.json","sha256":"d4f1b74c3fd21e67df1839e12270aca4e53ee8756877b69b64af14662e25ff08"}),
        "exact consumed profile cancellation source required",
    )?;
    let cancelled = bound(&plan["profile48_already_cancelled"])?;
    need(
        cancelled["cancelled_unused_future_profile48_bytes"] == 48u64 << 30
            && cancelled["retained_native16_pool_bytes"] == POOL
            && cancelled["native_pool_committed_bytes"] == 13_757_317_120u64
            && cancelled["all_six_retained_verifier_roles_bytes"] == 96u64 << 30,
        "oldprofile cancellation must retain8, not supply second credit",
    )?;
    need(
        plan["reuse_purpose"] == "immutable-original-uploader-image-reproduction"
            && plan["temporary_exclusive_reuse_only"] == true,
        "only exact bounded reproduction purpose may request existing8 reuse",
    )?;
    Ok(())
}
fn utc_seconds(raw: &str) -> anyhow::Result<u64> {
    let b = raw.as_bytes();
    ensure!(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z'
            && b.iter()
                .enumerate()
                .all(|(i, c)| [4, 7, 10, 13, 16, 19].contains(&i) || c.is_ascii_digit()),
        "strict UTC sample clock required"
    );
    let y = raw[0..4].parse::<u64>()?;
    let m = raw[5..7].parse::<usize>()?;
    let d = raw[8..10].parse::<u64>()?;
    let h = raw[11..13].parse::<u64>()?;
    let min = raw[14..16].parse::<u64>()?;
    let sec = raw[17..19].parse::<u64>()?;
    ensure!(
        (1970..=9999).contains(&y) && (1..=12).contains(&m) && h < 24 && min < 60 && sec < 60,
        "sample clock components out of range"
    );
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        d > 0 && d <= months[m - 1],
        "sample calendar date out of range"
    );
    let days = (1970..y)
        .map(|year| if leap(year) { 366u64 } else { 365 })
        .sum::<u64>()
        + months[..m - 1].iter().sum::<u64>()
        + d
        - 1;
    Ok(days * 86400 + h * 3600 + min * 60 + sec)
}
fn run(plan: &Value) -> R<Value> {
    need(
        plan["schema"] == "horizon-native16-existing-pool-compiler-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "exclusive Root campaign plan required",
    )?;
    let old = bound(&plan["historical_raw_accounting"])?;
    let retained = old_pool(&old)?;
    let parent = bound(&plan["current_complete_resource_authority"])?;
    backing(plan, &parent)?;
    need(
        parent["complete_DATA_bytes"] == plan["complete_DATA_bytes"]
            && parent["complete_projected_memory_bytes"] == plan["complete_projected_memory_bytes"],
        "current complete authority mismatch",
    )?;
    let original = bound(&plan["original_memory_pool_facts"])?;
    need(
        original["existing_pools_bytes"]["compiler_and_native16GiB"] == POOL
            && original["existing_pools_bytes"]["plugin128GiB"] == 128u64 << 30
            && original["existing_pools_bytes"]["shared64GiB"] == 64u64 << 30,
        "original separate pools must remain unchanged",
    )?;
    let selected = bound(&plan["selected_parent_memory"])?;
    need(
        selected["selection"]["effective_total_memory_promises_bytes"]
            == plan["selected_parent_memory_total_bytes"]
            && selected["selection"]["raw_accounting_serde_json_sha256"]
                == sha(&serde_json::to_vec(&old)?),
        "selected memory authority changed",
    )?;
    let fleet = bound(&plan["current_fleet"])?;
    let observer = bound(&fleet["observer"])?;
    need(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["live_replay_count"] == 7
            && fleet["complete_DATA_authority"] == plan["current_complete_resource_authority"]
            && fleet["complete_projected_memory_bytes"] == plan["complete_projected_memory_bytes"],
        "current complete seven-owner fleet differs",
    )?;
    let stamp = utc_seconds(s(&observer, "recorded_at_utc")?)?;
    need(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && n(&plan["freshness"], "sample_unix_seconds")? == stamp
            && observer["recorded_at_utc"] == plan["freshness"]["sampled_at_utc"]
            && utc_seconds(s(&observer, "completed_at_utc")?)? <= now()?
            && now()?.checked_sub(stamp).is_some_and(|age| age <= 1800),
        "exact genuine fleet observer clock must be fresh, complete and not future",
    )?;
    let drained = bound(&plan["current_Root_callback_drain"])?;
    need(
        drained["active_extra_QA_bytes"] == 0 && drained["normal_pool_bytes"] == 10u64 << 30,
        "current extra QA must be drained",
    )?;
    let mut owners = BTreeMap::new();
    for replay in plan["live_replays"].as_array().ok_or("seven live owners")? {
        need(
            owners
                .insert(s(replay, "unit")?.into(), replay.clone())
                .is_none(),
            "duplicate live replay",
        )?;
    }
    need(owners.len() == 7, "seven current replays required")?;
    for row in fleet["actual_executing_replays"]
        .as_array()
        .ok_or("fleet live rows")?
    {
        let value = &row["unit"];
        let expected = owners.get(s(value, "Id")?).ok_or("fleet owner omitted")?;
        for (a, b) in [
            ("Id", "unit"),
            ("InvocationID", "invocation_id"),
            ("MainPID", "main_pid"),
        ] {
            need(value[a] == expected[b], "fleet owner differs")?;
        }
    }
    for owner in plan["separately_protected_background_owners"]
        .as_array()
        .ok_or("background census")?
    {
        let original = fleet["currently_running_background_control_services"]
            .as_array()
            .ok_or("background fleet")?
            .iter()
            .find(|x| x["unit"]["Id"] == owner["unit"])
            .ok_or("background owner not in accepted census")?;
        for (a, b) in [
            ("Id", "unit"),
            ("InvocationID", "invocation_id"),
            ("MainPID", "main_pid"),
        ] {
            need(original["unit"][a] == owner[b], "background owner changed")?;
        }
        need(
            owners
                .insert(s(owner, "unit")?.into(), owner.clone())
                .is_none(),
            "overlapping background owner",
        )?;
    }
    let mut guards = BTreeMap::new();
    for row in plan["normal10_guard_roles"]
        .as_array()
        .ok_or("normal guard census")?
    {
        let name = s(row, "unit")?;
        unit_name(name)?;
        need(
            name.starts_with("horizon-guard-")
                && row["MemoryMax"] == "1073741824"
                && guards.insert(name.into(), row.clone()).is_none(),
            "exact separately booked seven guard roles required",
        )?;
    }
    need(
        guards.len() == 7 && n(plan, "normal_pool_bytes")? == 10 << 30,
        "normal pool must retain seven guards+observer2+Root1",
    )?;
    let own = s(plan, "native_check_unit")?;
    unit_name(own)?;
    let before = take(
        &owners,
        &guards,
        own,
        old["native_pool_suballocations"].as_array().unwrap(),
    )?;
    let proposed = n(plan, "one_serial_compiler_cap_bytes")?;
    let committed = reuse_projection(retained, proposed)?;
    let after = take(
        &owners,
        &guards,
        own,
        old["native_pool_suballocations"].as_array().unwrap(),
    )?;
    need(
        bound(&plan["current_complete_resource_authority"])? == parent
            && bound(&plan["current_fleet"])? == fleet
            && now()?.checked_sub(stamp).is_some_and(|age| age <= 1800),
        "authority/fleet changed or complete metadata qualification expired",
    )?;
    need(
        before.keys().eq(after.keys()),
        "Horizon unit set changed during suballocation check",
    )?;
    for name in owners.keys() {
        need(
            before[name] == after[name],
            "protected owner changed during check",
        )?;
    }
    Ok(
        json!({"schema":"horizon-native16-existing-serial8-reuse-check-v1","owner":"/root","recorded_unix_seconds":now()?,"planning_sample_expires_unix_seconds":now()?.checked_add(300).ok_or("expiry overflow")?.min(stamp.checked_add(1800).ok_or("observer expiry overflow")?),"plan":plan,"current_fleet":plan["current_fleet"],"retained_native_pool_bytes":POOL,"all_original_raw_suballocations_retained":true,"historical_committed_bytes_retained":retained,"one_serial_compiler_cap_bytes":proposed,"serial8_existing_backing":plan["serial8_existing_backing"],"profile48_already_cancelled":plan["profile48_already_cancelled"],"this_is_existing_charged8_reuse_not_new8_promise":true,"all_helper_guard_OS_old_rows_retained":true,"temporary_native512_including_check_bytes":committed+(512u64<<20),"total_committed_if_Root_books_compiler_bytes":committed,"remaining_uncommitted_native_pool_bytes":POOL-committed,"native_before_sha256":sha(&serde_json::to_vec(&before)?),"native_after_sha256":sha(&serde_json::to_vec(&after)?),"native_before_count":before.len(),"native_after_count":after.len(),"protected_native_before":before.iter().filter(|(k,_)|owners.contains_key(*k)||guards.contains_key(*k)||k.as_str()==own).map(|(k,v)|(k.clone(),v.clone())).collect::<BTreeMap<_,_>>(),"protected_native_after":after.iter().filter(|(k,_)|owners.contains_key(*k)||guards.contains_key(*k)||k.as_str()==own).map(|(k,v)|(k.clone(),v.clone())).collect::<BTreeMap<_,_>>(),"no_unclassified_live_or_queued_Horizon_unit":true,"normal_pool_bytes":10u64<<30,"complete_projected_memory_bytes_unchanged":plan["complete_projected_memory_bytes"],"plugin128GiB_and_shared64GiB_untouched":true,"resource_credit_bytes":0,"physical_retirement_bytes":0,"new_memory_promise_bytes":0,"replay_admission_authorized":false,"allocation_booked":false,"remote_mutations":false,"producer_mutations":false,"new_resource_observations":false,"next_action":"Root may lease exactly the already charged serial8 role exclusively while holding the same native16 pool lock; old full-helper8 may not overlap. The256MiB guard,64MiB metadata and original4.5 stay retained. Exact immutable source/output/sandbox and genuine prestart guard remain required before compiler launch; this checker grants no new8, ending, release, Frame or replay authority."}),
    )
}
fn main() -> R<()> {
    let a = std::env::args().collect::<Vec<_>>();
    need(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && a[6] == "--check-existing-pool",
        "exact check argv required",
    )?;
    let image = fs::read_link("/proc/self/exe")?;
    need(
        image == Path::new(IMAGE) && sha(&fs::read(&image)?) == a[5],
        "exact normally sealed check image required",
    )?;
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let report = run(&plan)?;
    durable(Path::new(s(&plan, "output")?), &report)?;
    println!(
        "{}",
        json!({"output":plan["output"],"existing_pool_check_passed":true,"allocation_booked":false,"new_memory_promise_bytes":0})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> Value {
        json!({"MainPID":"0","ControlPID":"0","Job":"","ActiveState":"inactive","SubState":"dead"})
    }
    #[test]
    fn strict_clock_matches_real_observer_and_rejects_units_or_calendar_errors() {
        assert_eq!(utc_seconds("2026-11-10T11:00:22Z").unwrap(), 1794308422);
        assert!(utc_seconds("2026-02-29T11:00:22Z").is_err());
        assert!(utc_seconds("2026-11-10T11:00:22+00:00").is_err());
    }
    #[test]
    fn strict_clock_keeps_real_leap_dates() {
        assert!(utc_seconds("2024-02-29T00:00:00Z").is_ok());
        assert!(utc_seconds("2024-02-30T00:00:00Z").is_err());
    }
    #[test]
    fn exact8_reuse_keeps_guard_os_and_all_history() {
        assert_eq!(
            reuse_projection(4_831_838_208, 8u64 << 30).unwrap(),
            13_757_317_120
        );
    }
    #[test]
    fn extra8_cannot_be_added_on_top_of_charged8() {
        assert!(reuse_projection(13_757_317_120, 8u64 << 30).is_err());
    }
    #[test]
    fn lower_original_history_cannot_create_new_room() {
        assert!(reuse_projection(4_831_838_208 - 1, 8u64 << 30).is_err());
    }
    #[test]
    fn changed_reproduction_slot_is_rejected() {
        assert!(reuse_projection(4_831_838_208, 7u64 << 30).is_err());
        assert!(reuse_projection(4_831_838_208, 9u64 << 30).is_err());
    }
    #[test]
    fn conservative_fit_keeps_every_old_byte() {
        assert_eq!(fit(4_831_838_208, 8 << 30).unwrap(), 13_421_772_800);
    }
    #[test]
    fn fit_denies_overcommit_and_zero() {
        assert!(fit(POOL, 1).is_err());
        assert!(fit(0, 0).is_err());
        assert!(fit(0, 9 << 30).is_err());
        assert!(fit(u64::MAX, 1).is_err());
    }
    #[test]
    fn unclassified_running_unit_denies_reuse() {
        let mut v = empty();
        v["MainPID"] = json!("12");
        assert!(
            classify(
                "new.service",
                &v,
                &BTreeMap::new(),
                &BTreeMap::new(),
                "own.service"
            )
            .is_err()
        );
    }
    #[test]
    fn unclassified_queued_unit_denies_reuse() {
        let mut v = empty();
        v["Job"] = json!("12/start");
        assert!(
            classify(
                "new.service",
                &v,
                &BTreeMap::new(),
                &BTreeMap::new(),
                "own.service"
            )
            .is_err()
        );
    }
    #[test]
    fn drained_unknown_unit_does_not_gain_credit() {
        assert!(
            classify(
                "old.service",
                &empty(),
                &BTreeMap::new(),
                &BTreeMap::new(),
                "own.service"
            )
            .is_ok()
        );
    }
    #[test]
    fn missing_pool_and_replay_alias_fail() {
        assert!(old_pool(&json!({})).is_err());
        let p = json!({"unit":"x.service","invocation_id":"a","main_pid":"12"});
        assert!(owner_matches(&empty(), &p).is_err());
    }
    #[test]
    fn separate_guard_cannot_borrow_more_memory() {
        let mut guards = BTreeMap::new();
        guards.insert("g.service".into(), json!({"MemoryMax":"1073741824"}));
        let mut v = empty();
        v["MemoryMax"] = json!("2147483648");
        v["MemorySwapMax"] = json!("0");
        v["Restart"] = json!("no");
        assert!(classify("g.service", &v, &BTreeMap::new(), &guards, "own.service").is_err());
    }
    #[test]
    fn unsafe_unit_names_fail() {
        assert!(unit_name("--oops.service").is_err());
        assert!(unit_name("x.target").is_err());
    }
}
