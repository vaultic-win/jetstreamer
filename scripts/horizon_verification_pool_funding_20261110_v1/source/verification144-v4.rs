#![recursion_limit = "512"]
//! Metadata-only Root review; never native Frame, full Reader, admission or release authority.
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
    "/usr/local/lib/jetstreamer/horizon-verification144-suballocation-tools-20261110-v4/check";
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Type,Job,MemoryMax,MemorySwapMax,MemoryAccounting,Restart,Delegate,KillMode";
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
const VERIFICATION_POOL: u64 = 144 << 30;
fn fixed_verification_cap(unit: &str) -> R<u64> {
    if unit == "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service" {
        return Ok(32 << 30);
    }
    if unit == "jetstreamer-horizon-audit-epochs101-181-v4.service" {
        return Ok(32 << 30);
    }
    if unit == "jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service"
        || ["a", "b", "c", "d"].iter().any(|part| {
            unit == format!(
                "jetstreamer-horizon-plugin-receipt-watcher-shard-{part}-v4-fsync.service"
            )
        })
    {
        return Ok(8 << 30);
    }
    Err("unknown verification pool role".into())
}
fn verification_fit(rows: &[Value], candidate: u64) -> R<u64> {
    need(
        rows.len() == 6 && candidate > 0 && candidate <= 48 << 30,
        "exact six retained verification roles and bounded48 profile required",
    )?;
    let mut names = BTreeSet::new();
    let mut total = 0u64;
    for row in rows {
        let name = s(row, "unit")?;
        need(names.insert(name), "duplicate verification owner")?;
        let cap = fixed_verification_cap(name)?;
        need(
            n(row, "retained_cap_bytes")? == cap,
            "retained verification hard cap cannot be lowered",
        )?;
        total = total.checked_add(cap).ok_or("verification sum overflow")?;
    }
    need(
        total == 96 << 30,
        "complete retained verification envelope differs",
    )?;
    total = total
        .checked_add(candidate)
        .ok_or("verification candidate overflow")?;
    need(
        total <= VERIFICATION_POOL,
        "proposed verification144 pool overcommitted",
    )?;
    Ok(total)
}
fn verification_native(rows: &[Value]) -> R<Value> {
    let mut result = Vec::new();
    for row in rows {
        let name = s(row, "unit")?;
        let cap = fixed_verification_cap(name)?;
        let value = native(name)?;
        if value["LoadState"] == "not-found" {
            need(
                name == "jetstreamer-horizon-plugin-receipt-watcher-shard-a-v4-fsync.service"
                    && value["ActiveState"] == "inactive"
                    && value["SubState"] == "dead"
                    && value["MainPID"] == "0"
                    && value["ControlPID"] == "0"
                    && value["Job"] == "",
                "only exact collected shardA may retain its conservative8GiB future slot",
            )?;
        } else {
            need(
                value["MemoryMax"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    == Some(cap)
                    && value["MemorySwapMax"] == "0"
                    && value["Delegate"] == "no"
                    && value["KillMode"] == "control-group",
                "actual bounded descendant verification envelope differs",
            )?;
        }
        let binding = &row["immutable_script"];
        let bytes = raw(Path::new(s(binding, "path")?))?;
        need(
            sha(&bytes) == s(binding, "sha256")?,
            "verification script bytes changed",
        )?;
        let script = String::from_utf8(bytes)?;
        need(
            !script.contains("systemd-run")
                && !script.contains("systemctl")
                && !script.contains("setsid")
                && !script.contains("nohup"),
            "unqualified verifier cgroup escape route",
        )?;
        result.push(json!({"unit":name,"retained_cap_bytes":cap,"native":value,"immutable_script":binding,"slot_retained_even_when_collected":true}));
    }
    Ok(json!(result))
}
fn executing(v: &Value) -> bool {
    v["MainPID"]
        .as_str()
        .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
        || v["ControlPID"]
            .as_str()
            .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
}
const PROTECTED_BACKGROUND_UNITS: [&str; 7] = [
    "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service",
    "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service",
    "jetstreamer-horizon-audit-epochs101-181-v4.service",
    "jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-b-v4-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-d-v4-fsync.service",
];
fn complete_background_census(rows: &[Value]) -> R<()> {
    // The two stable controllers are only a subset of the protected fleet.
    // Retain the five running verifier owners too; shard A's future slot stays
    // charged separately by verification_fit and verification_native.
    let expected = PROTECTED_BACKGROUND_UNITS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for row in rows {
        let unit = s(row, "unit")?;
        unit_name(unit)?;
        need(actual.insert(unit), "duplicate protected background owner")?;
    }
    let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
    let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
    need(
        missing.is_empty() && extra.is_empty(),
        &format!("protected background census differs; missing={missing:?}; extra={extra:?}"),
    )
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
                && value["MemoryMax"] == "536870912"
                && value["MemorySwapMax"] == "0"
                && value["NRestarts"] == "0",
            "native check must use existing Root callback512",
        )?;
        return Ok(());
    }
    need(
        !executing(value) && job.is_empty(),
        &format!(
            "unclassified executing or queued Horizon unit {unit}; no native-pool reuse authority; native={value}"
        ),
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
fn funding_point(point: &Value, plan: &Value, t: u64) -> R<()> {
    need(
        point["schema"] == "horizon-fulfilled-anon-memory-native-check-v1"
            && point["owner"] == "/root"
            && point["candidate_fits_this_native_sample"] == true
            && point["complete_hard_memory_promises_preserved_bytes"]
                == plan["complete_projected_memory_bytes"]
            && point["candidate_additive_hard_memory_bytes"] == 16u64 << 30
            && point["additional_host_headroom_bytes"] == 16u64 << 30
            && point["resource_credit_bytes"] == 0
            && point["hard_promises_released_bytes"] == 0
            && point["replay_launch_authorized"] == false,
        "qualified unchanged-promises additive16 funding proof required",
    )?;
    need(
        point["plan"]["current_complete_authority"] == plan["current_complete_resource_authority"]
            && point["plan"]["current_fleet"] == plan["current_fleet"]
            && point["plan"]["candidate_pool"] == "verification128-to144",
        "funding point context crossed",
    )?;
    need(
        t >= n(point, "recorded_unix_seconds")?
            && t <= n(point, "planning_sample_expires_unix_seconds")?,
        "funding point expired or future",
    )?;
    Ok(())
}
fn run(plan: &Value) -> R<Value> {
    need(
        plan["schema"] == "horizon-existing-verification144-native16-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "exclusive Root campaign plan required",
    )?;
    let old = bound(&plan["historical_raw_accounting"])?;
    let retained = old_pool(&old)?;
    let parent = bound(&plan["current_complete_resource_authority"])?;
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
            && fleet["live_replay_count"] == 6
            && fleet["proven_replay_count"] == 6
            && fleet["complete_DATA_authority"] == plan["current_complete_resource_authority"]
            && fleet["complete_projected_memory_bytes"] == plan["complete_projected_memory_bytes"],
        "current complete six-owner fleet differs",
    )?;
    let stamp = n(&observer["cadence"], "sample_unix_seconds")
        .or_else(|_| n(&plan["freshness"], "sample_unix_seconds"))?;
    need(
        now()?.checked_sub(stamp).is_some_and(|age| age <= 1800),
        "current sample too old for prospective suballocation",
    )?;
    need(
        n(&plan["freshness"], "sample_unix_seconds")? == 1_794_279_622
            && observer["recorded_at_utc"] == "2026-11-10T03:00:22Z",
        "actual sample timestamp required",
    )?;
    let drained = bound(&plan["current_Root_callback_drain"])?;
    need(
        drained["active_extra_QA_bytes"] == 0
            && drained["normal_pool_bytes"] == 9u64 << 30
            && drained["accepted_fleet"] == plan["current_fleet"]
            && drained["original_native"]["MainPID"] == "0"
            && drained["original_native"]["ControlPID"] == "0"
            && drained["original_native"]["NRestarts"] == "0"
            && drained["original_native"]["Result"] == "success"
            && drained["original_native"]["ExecMainStatus"] == "0"
            && drained["original_native"]["ActiveState"] == "inactive"
            && drained["original_native"]["SubState"] == "dead",
        "current extra QA must be drained",
    )?;
    let mut owners = BTreeMap::new();
    for replay in plan["live_replays"].as_array().ok_or("six live owners")? {
        need(
            owners
                .insert(s(replay, "unit")?.into(), replay.clone())
                .is_none(),
            "duplicate live replay",
        )?;
    }
    need(owners.len() == 6, "six current replays required")?;
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
    let background_owners = plan["separately_protected_background_owners"]
        .as_array()
        .ok_or("background census")?;
    complete_background_census(background_owners)?;
    for owner in background_owners {
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
    for row in plan["normal9_guard_roles"]
        .as_array()
        .ok_or("normal guard census")?
    {
        let name = s(row, "unit")?;
        unit_name(name)?;
        need(
            name.starts_with("horizon-guard-")
                && row["MemoryMax"] == "1073741824"
                && guards.insert(name.into(), row.clone()).is_none(),
            "exact separately booked six guard roles required",
        )?;
    }
    need(
        guards.len() == 6 && n(plan, "normal_pool_bytes")? == 9 << 30,
        "normal pool must retain six guards+observer2+Root1",
    )?;
    let funding = bound(&plan["additive16_funding_point"])?;
    funding_point(&funding, plan, now()?)?;
    let own = s(plan, "native_check_unit")?;
    unit_name(own)?;
    eprintln!("{} verification/native pool census-before start", now()?);
    let before = take(
        &owners,
        &guards,
        own,
        old["native_pool_suballocations"].as_array().unwrap(),
    )?;
    eprintln!(
        "{} census-before complete,{}unit identities; retained obligations unchanged",
        now()?,
        before.len()
    );
    let ended = bound(&plan["helper40_previous_slot_drained"])?;
    need(
        ended["active_existing_native16_compiler_bytes"] == 0
            && ended["native_pool_committed_bytes_after"] == retained
            && ended["DATA_released_bytes"] == 0,
        "full helper40 compiler/test slot must be genuinely drained; all DATA remains",
    )?;
    let verification_rows = plan["retained_verification_roles"]
        .as_array()
        .ok_or("six retained verification roles")?;
    let candidate = n(plan, "one_bounded_verification_profile_bytes")?;
    need(
        candidate == 48 << 30,
        "exact proposed48GiB native profile required",
    )?;
    let verification_committed = verification_fit(verification_rows, candidate)?;
    let verification_before = verification_native(verification_rows)?;
    let proposed = n(plan, "one_serial_native_control_bytes")?;
    let extra_guard = n(plan, "one_profile_native_guard_bytes")?;
    need(
        proposed == 8u64 << 30 && extra_guard == 256u64 << 20,
        "exact helper8GiB and separate guard256MiB proposal required",
    )?;
    let committed = fit(
        retained
            .checked_add(extra_guard)
            .ok_or("native guard sum overflow")?,
        proposed,
    )?;
    eprintln!("{} verification/native pool census-after start", now()?);
    let after = take(
        &owners,
        &guards,
        own,
        old["native_pool_suballocations"].as_array().unwrap(),
    )?;
    eprintln!(
        "{} census-after complete,{}unit identities",
        now()?,
        after.len()
    );
    let verification_after = verification_native(verification_rows)?;
    need(
        verification_before == verification_after,
        "verification owners or caps changed during check",
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
    funding_point(&funding, plan, now()?)?;
    Ok(
        json!({"schema":"horizon-existing-verification144-native16-check-v1","owner":"/root","recorded_unix_seconds":now()?,"plan":plan,"current_fleet":plan["current_fleet"],"original_retained_verification_pool_bytes":128u64<<30,"proposed_verification_pool_bytes":VERIFICATION_POOL,"additional_verification_pool_bytes_if_Root_books":16u64<<30,"additive16_funding_point":plan["additive16_funding_point"],"all_six_verification_slots_retained_bytes":96u64<<30,"one_bounded_verification_profile_bytes":candidate,"verification_committed_if_Root_books_profile_bytes":verification_committed,"verification_uncommitted_bytes":VERIFICATION_POOL-verification_committed,"verification_before":verification_before,"verification_after":verification_after,"retained_native_pool_bytes":POOL,"all_original_raw_suballocations_retained":true,"historical_committed_bytes_retained":retained,"one_serial_native_control_bytes":proposed,"one_profile_native_guard_bytes":extra_guard,"total_committed_if_Root_books_compiler_bytes":committed,"remaining_uncommitted_native_pool_bytes":POOL-committed,"native_before":before,"native_after":after,"no_unclassified_live_or_queued_Horizon_unit":true,"normal_pool_bytes":9u64<<30,"complete_projected_memory_bytes_unchanged":plan["complete_projected_memory_bytes"],"raw_verification128_promise_and_shared64GiB_retained":true,"proposed_complete_projected_memory_bytes":n(plan,"complete_projected_memory_bytes")?.checked_add(16u64<<30).ok_or("memory extension overflow")?,"resource_credit_bytes":0,"physical_retirement_bytes":0,"new_memory_promise_bytes":0,"replay_admission_authorized":false,"allocation_booked":false,"remote_mutations":false,"producer_mutations":false,"new_resource_observations":false,"next_action":"Root may explicitly book an additional16GiB verification envelope after a fresh final funding point, retaining raw128 and all96GiB old verifier caps, then subdivide144 into96 retained+48 proposed native profile. A separate8GiB helper plus256MiB guard fits native16 alongside every old4.5GiB slot. Keep both pool locks; qualify the exact harmless body and DATA before any control. No replay is authorized."}),
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
        json!({"output":plan["output"],"existing_verification_and_native_pool_checks_passed":true,"allocation_booked":false,"new_memory_promise_bytes":0})
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
    fn verifier_rows() -> Vec<Value> {
        let mut names = vec![
            "jetstreamer-horizon-audit-epochs101-181-v4.service".to_string(),
            "jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service".to_string(),
        ];
        names.extend(["a", "b", "c", "d"].iter().map(|p| {
            format!("jetstreamer-horizon-plugin-receipt-watcher-shard-{p}-v4-fsync.service")
        }));
        names
            .into_iter()
            .map(|n| json!({"retained_cap_bytes":fixed_verification_cap(&n).unwrap(),"unit":n}))
            .collect()
    }
    #[test]
    fn verification_profile_retains_all96_in_proposed144() {
        assert_eq!(
            verification_fit(&verifier_rows(), 48 << 30).unwrap(),
            144 << 30
        );
    }
    #[test]
    fn verification_caps_duplicates_and_larger_profile_reject() {
        let rows = verifier_rows();
        assert!(verification_fit(&rows, 49 << 30).is_err());
        let mut bad = rows.clone();
        bad[0]["retained_cap_bytes"] = json!(1);
        assert!(verification_fit(&bad, 48 << 30).is_err());
        let mut bad = rows;
        bad[1] = bad[0].clone();
        assert!(verification_fit(&bad, 48 << 30).is_err());
    }
    #[test]
    fn unknown_verification_role_is_not_uncommitted_capacity() {
        let mut bad = verifier_rows();
        bad[5]["unit"] = json!("another.service");
        assert!(verification_fit(&bad, 48 << 30).is_err());
        assert!(verification_fit(&bad[..5], 48 << 30).is_err());
    }

    #[test]
    fn fresh_additive16_funding_is_not_pool_allocation_or_a_lower_cap() {
        let plan = json!({"complete_projected_memory_bytes":720061083648u64,"current_complete_resource_authority":{"path":"current"},"current_fleet":{"path":"fleet"}});
        let p = json!({"schema":"horizon-fulfilled-anon-memory-native-check-v1","owner":"/root","candidate_fits_this_native_sample":true,"complete_hard_memory_promises_preserved_bytes":plan["complete_projected_memory_bytes"],"candidate_additive_hard_memory_bytes":16u64<<30,"additional_host_headroom_bytes":16u64<<30,"resource_credit_bytes":0,"hard_promises_released_bytes":0,"replay_launch_authorized":false,"plan":{"current_complete_authority":plan["current_complete_resource_authority"],"current_fleet":plan["current_fleet"],"candidate_pool":"verification128-to144"},"recorded_unix_seconds":100,"planning_sample_expires_unix_seconds":400});
        assert!(funding_point(&p, &plan, 400).is_ok());
        assert!(funding_point(&p, &plan, 401).is_err());
        assert!(funding_point(&p, &plan, 99).is_err());
        for k in [
            "candidate_fits_this_native_sample",
            "complete_hard_memory_promises_preserved_bytes",
            "candidate_additive_hard_memory_bytes",
            "resource_credit_bytes",
            "hard_promises_released_bytes",
            "replay_launch_authorized",
        ] {
            let mut b = p.clone();
            b[k] = json!("changed");
            assert!(funding_point(&b, &plan, 200).is_err());
        }
        let mut b = plan;
        b["current_fleet"] = json!({"path":"foreign"});
        assert!(funding_point(&p, &b, 200).is_err());
    }
    #[test]
    fn actual_shard_c32_is_retained_and_cannot_be_relabelled8() {
        let rows = verifier_rows();
        let mut bad = rows.clone();
        let c = bad
            .iter_mut()
            .find(|x| {
                x["unit"] == "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service"
            })
            .unwrap();
        c["retained_cap_bytes"] = json!(8u64 << 30);
        assert!(verification_fit(&bad, 48 << 30).is_err());
        assert_eq!(verification_fit(&rows, 48 << 30).unwrap(), 144u64 << 30);
        assert_eq!((144u64 << 30) - (128u64 << 30), 16u64 << 30);
    }
    #[test]
    fn native_helper8_and_guard256_are_counted_separately() {
        assert_eq!(
            fit(4_831_838_208 + (256 << 20), 8 << 30).unwrap(),
            13_690_208_256
        );
        assert!(fit(POOL - (8 << 30) + 1, 8 << 30).is_err());
    }
    #[test]
    fn complete_background_census_keeps_both_controllers_and_all_five_live_verifiers() {
        let rows = PROTECTED_BACKGROUND_UNITS
            .iter()
            .map(|unit| json!({"unit":unit}))
            .collect::<Vec<_>>();
        assert!(complete_background_census(&rows).is_ok());
        let err = complete_background_census(&rows[..2])
            .unwrap_err()
            .to_string();
        for unit in &PROTECTED_BACKGROUND_UNITS[2..] {
            assert!(err.contains(unit));
        }
    }
    #[test]
    fn complete_background_census_rejects_duplicate_and_unknown_owners() {
        let mut rows = PROTECTED_BACKGROUND_UNITS
            .iter()
            .map(|unit| json!({"unit":unit}))
            .collect::<Vec<_>>();
        rows.push(rows[0].clone());
        assert!(complete_background_census(&rows).is_err());
        rows.pop();
        rows[6]["unit"] = json!("unregistered-horizon-watcher.service");
        let err = complete_background_census(&rows).unwrap_err().to_string();
        assert!(err.contains(PROTECTED_BACKGROUND_UNITS[6]));
        assert!(err.contains("unregistered-horizon-watcher.service"));
    }
    #[test]
    fn unclassified_failure_identifies_exact_unit_and_native_state() {
        let mut value = empty();
        value["MainPID"] = json!("200268");
        value["InvocationID"] = json!("89b072dea9cd4167881d060c571be6cf");
        let unit = "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service";
        let err = classify(
            unit,
            &value,
            &BTreeMap::new(),
            &BTreeMap::new(),
            "own.service",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains(unit));
        assert!(err.contains("200268"));
        assert!(err.contains("89b072dea9cd4167881d060c571be6cf"));
    }
}
