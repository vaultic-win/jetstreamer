//! End the original failed74 actor's future promises, retaining all files and guards.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const PINS: &str = include_str!("bindings.json");
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-failed74-actor-future-tools-20261109-v1/end-actor";
const IID: &str = "f37b155136614e0183ba2e9adb8714ef";
const ACTOR: &str = "horizon-extract145-prefix-shared72h-20261107-v8g1.service";
const GUARD: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.service";
const TIMER: &str = "horizon-guard145-prefix-shared72h-20261107-v8g1.timer";
const TIMER_IID: &str = "f6f2308db2dc47be8f470030fb587b90";
const PROGRAM: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-20261107-v8/epoch145-prefix-extract";
const PROGRAM_SHA: &str = "b416b7c932ef781c8d0f863b63b803379dd58cb1affe99dced6a61830a95ad76";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-shared72h-20261107-v8g1/plan.json";
const PLAN_SHA: &str = "c1a7b5fcad8aa850be48a811fdfa7f703aa162d615070689fbba68f8f025dcf3";
const OUTPUT: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-shared72h-20261107-v8g1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon-failed74-actor-future-20261109-v1/f37b155136614e0183ba2e9adb8714ef";
const BASE_DATA: u64 = 6_568_000_175_922;
const BASE_MEMORY: u64 = 708_249_923_584;
const ACTOR_MEMORY: u64 = 80 << 30;
const GUARD_MEMORY: u64 = 256 << 20;
const OLD_OUTPUT: u64 = 160 << 30;
const RETAINED_OUTPUT: u64 = 64 << 30;
const ENDED_OUTPUT: u64 = OLD_OUTPUT - RETAINED_OUTPUT;
const CLOSED_BYTES: u64 = 55_954_296_252;
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;

fn require(ok: bool, why: &str) -> R<()> {
    if ok { Ok(()) } else { Err(why.into()) }
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn clock() -> R<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn number(v: &Value, key: &str) -> R<u64> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("missing integer {key}").into())
}
fn string<'a>(v: &'a Value, key: &str) -> R<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("missing string {key}").into())
}
fn identity(m: &fs::Metadata) -> Value {
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
        m.ctime_nsec(),
        m.blocks()
    ])
}
fn bytes(path: &Path, cap: u64) -> R<Vec<u8>> {
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical no-symlink path required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let before = f.metadata()?;
    require(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= cap,
        "unsafe Root metadata",
    )?;
    let mut out = Vec::new();
    Read::by_ref(&mut f).take(cap + 1).read_to_end(&mut out)?;
    require(
        out.len() as u64 == before.len()
            && identity(&before) == identity(&f.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "metadata changed",
    )?;
    Ok(out)
}
fn bound(b: &Value) -> R<Value> {
    let raw = bytes(Path::new(string(b, "path")?), 32 << 20)?;
    require(
        sha(&raw) == string(b, "sha256")?,
        "bound evidence SHA mismatch",
    )?;
    Ok(serde_json::from_slice(&raw)?)
}
fn durable(path: &Path, value: &Value) -> R<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    f.write_all(&serde_json::to_vec(value)?)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(path.parent().ok_or("receipt parent")?)?.sync_all()?;
    Ok(())
}
fn native(unit: &str) -> R<Value> {
    let fields = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Restart,Result,ExecMainCode,ExecMainStatus,ControlGroup,Job,TriggeredBy,Triggers,WantedBy,RequiredBy,Upholds,UpheldBy,DropInPaths,FragmentPath,ExecStart,Type,User,Group,KillMode,Delegate,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ExecMainPID,ExecMainStartTimestamp,ExecMainExitTimestamp,RuntimeMaxUSec";
    let out = Command::new("/usr/bin/systemctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .args(["show", unit, "--no-pager", "-p", fields])
        .output()?;
    require(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "native property capture failed",
    )?;
    let mut map = serde_json::Map::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line.split_once('=').ok_or("native delimiter")?;
        require(
            map.insert(k.into(), json!(v)).is_none(),
            "duplicate native property",
        )?;
    }
    Ok(Value::Object(map))
}
fn unit_object(unit: &str) -> String {
    let mut s = String::from("/org/freedesktop/systemd1/unit/");
    for b in unit.bytes() {
        if b.is_ascii_alphanumeric() {
            s.push(char::from(b));
        } else {
            s.push_str(&format!("_{b:02x}"));
        }
    }
    s
}
fn empty_native_hook(unit: &str, property: &str) -> R<()> {
    let out = Command::new("/usr/bin/busctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &unit_object(unit),
            "org.freedesktop.systemd1.Service",
            property,
        ])
        .output()?;
    require(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "typed native hook capture failed",
    )?;
    let v: Value = serde_json::from_slice(&out.stdout)?;
    require(
        v["type"] == "a(sasbttttuii)" && v["data"] == json!([]),
        "nonempty or untyped native execution hook",
    )
}
fn command(v: &Value, mode: &str) -> R<()> {
    let expected = format!(
        "argv[]={PROGRAM} {mode} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ; ignore_errors=no"
    );
    let actual = string(v, "ExecStart")?;
    require(
        actual.contains(&expected) && actual.matches("argv[]=").count() == 1,
        "original command changed",
    )
}
fn own_policy(v: &Value, operation: &str) -> R<()> {
    let unit = format!("horizon-failed74-actor-future-{operation}-20261109-v1.service");
    let pid = std::process::id().to_string();
    require(
        v["Id"].as_str() == Some(unit.as_str())
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"].as_str() == Some(pid.as_str())
            && v["ControlPID"] == "0"
            && v["Job"] == ""
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "exec"
            && v["User"] == "root"
            && v["Group"] == "root"
            && v["MemoryAccounting"] == "yes"
            && v["MemoryMax"] == "536870912"
            && v["MemorySwapMax"] == "0"
            && v["RuntimeMaxUSec"] == "3min"
            && v["CPUQuotaPerSecUSec"] == "2s",
        "exact original finite512MiB helper required",
    )
}
fn actor_policy(a: &Value) -> R<()> {
    require(
        a["Id"] == ACTOR
            && a["LoadState"] == "loaded"
            && a["InvocationID"] == IID
            && a["ActiveState"] == "failed"
            && a["SubState"] == "failed"
            && a["MainPID"] == "0"
            && a["ControlPID"] == "0"
            && a["ControlGroup"] == ""
            && a["NRestarts"] == "0"
            && a["Result"] == "exit-code"
            && a["ExecMainCode"] == "1"
            && a["ExecMainStatus"] == "74"
            && a["ExecMainPID"] == "2463122"
            && a["ExecMainStartTimestamp"] == "Sat 2026-11-07 07:44:22 UTC"
            && a["ExecMainExitTimestamp"] == "Sat 2026-11-07 17:33:02 UTC",
        "original failed74 actor not drained",
    )?;
    for k in [
        "Job",
        "TriggeredBy",
        "Triggers",
        "WantedBy",
        "RequiredBy",
        "Upholds",
        "UpheldBy",
        "DropInPaths",
    ] {
        require(a[k] == "", "actor has activation/dependency or overlay")?;
    }
    require(
        a["Restart"] == "no"
            && a["Type"] == "exec"
            && a["User"] == "root"
            && a["Group"] == "root"
            && a["KillMode"] == "control-group"
            && a["Delegate"] == "no"
            && a["MemoryMax"] == "85899345920"
            && a["MemorySwapMax"] == "0"
            && a["CPUQuotaPerSecUSec"] == "8s"
            && a["TasksMax"] == "512",
        "original actor hard envelope changed",
    )?;
    command(a, "extract")
}
fn retained_guard(g: &Value, t: &Value) -> R<()> {
    require(
        t["Id"] == TIMER
            && t["LoadState"] == "loaded"
            && t["InvocationID"] == TIMER_IID
            && t["ActiveState"] == "active"
            && ["waiting", "running"].contains(&string(t, "SubState")?)
            && t["Triggers"] == GUARD
            && t["Job"] == ""
            && t["DropInPaths"] == "",
        "original guard timer changed",
    )?;
    require(
        g["Id"] == GUARD
            && g["LoadState"] == "loaded"
            && g["Restart"] == "no"
            && g["Type"] == "exec"
            && g["User"] == "root"
            && g["Group"] == "root"
            && g["MemoryMax"] == "268435456"
            && g["MemorySwapMax"] == "0"
            && g["CPUQuotaPerSecUSec"] == "1s"
            && g["TasksMax"] == "512"
            && g["TriggeredBy"] == TIMER
            && g["DropInPaths"] == "",
        "retained guard hard promise changed",
    )?;
    require(
        ["active", "inactive", "failed"].contains(&string(g, "ActiveState")?)
            && g["NRestarts"] == "0",
        "unknown guard state",
    )?;
    command(g, "guard")
}
fn source_identity(p: &Value) -> R<Value> {
    let path = Path::new(string(&p["source"], "path")?);
    let m = fs::symlink_metadata(path)?;
    let id = &p["source_identity"];
    require(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.len() == number(id, "bytes")?
            && m.dev() == number(id, "device")?
            && m.ino() == number(id, "inode")?
            && u64::try_from(m.mtime())? * 1_000_000_000 + u64::try_from(m.mtime_nsec())?
                == number(id, "mtime_ns")?
            && u64::try_from(m.ctime())? * 1_000_000_000 + u64::try_from(m.ctime_nsec())?
                == number(id, "ctime_ns")?,
        "retained source identity changed",
    )?;
    Ok(identity(&m))
}
fn retained_tree(root: &Path) -> R<Value> {
    require(
        root == Path::new(OUTPUT) && root.canonicalize()? == root,
        "exact original output root required",
    )?;
    let m = fs::symlink_metadata(root)?;
    require(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "output root custody changed",
    )?;
    let entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    require(
        entries.len() == 1 && entries[0].file_name() == ".tmplqcLua",
        "unexpected retained output member",
    )?;
    let path = entries[0].path();
    let file = fs::symlink_metadata(&path)?;
    require(
        file.is_file()
            && file.nlink() == 1
            && file.uid() == 0
            && file.mode() & 0o777 == 0o600
            && file.dev() == m.dev()
            && file.len() == CLOSED_BYTES
            && file
                .blocks()
                .checked_mul(512)
                .is_some_and(|n| n <= RETAINED_OUTPUT),
        "retained partial changed or exceeds64GiB",
    )?;
    Ok(
        json!({"root":identity(&m),"file":identity(&file),"path":path,"apparent_bytes":file.len(),"physical_bytes":file.blocks()*512}),
    )
}
fn selection(data: u64, memory: u64, output: u64, raw: &Value) -> R<(u64, u64)> {
    require(
        raw["invocation_id"] == IID
            && raw["unit"] == ACTOR
            && raw["memory_max_bytes"] == ACTOR_MEMORY + GUARD_MEMORY
            && raw["actual_actor_memory_hard_limit_bytes"] == ACTOR_MEMORY
            && raw["reserved_guard_memory_bytes"] == GUARD_MEMORY
            && raw["output_DATA_bytes"] == OLD_OUTPUT
            && raw["data_reservation_bytes"] == 176_227_876_864u64
            && raw["metadata_DATA_bytes"] == 128u64 << 20
            && raw["retained185_source_DATA_bytes"] == 4u64 << 30,
        "wrong raw actor/guard/DATA promise",
    )?;
    require(
        output == CLOSED_BYTES
            && output <= RETAINED_OUTPUT
            && memory == BASE_MEMORY
            && data == BASE_DATA + (128 << 20),
        "crossed baseline or retained output cap",
    )?;
    Ok((
        data.checked_sub(ENDED_OUTPUT).ok_or("DATA underflow")?,
        memory.checked_sub(ACTOR_MEMORY).ok_or("memory underflow")?,
    ))
}
fn current_chain(request: &Value, pins: &Value) -> R<Value> {
    let mut next = request["current_DATA_authority"].clone();
    let mut seen = BTreeSet::new();
    let mut newer = None;
    for _ in 0..8 {
        require(seen.insert(next.to_string()), "cyclic DATA chain")?;
        let v = bound(&next)?;
        let data = number(&v, "complete_DATA_bytes")?;
        if let Some(total) = newer {
            require(
                total == data || total == data.checked_add(128 << 20).ok_or("DATA overflow")?,
                "unexpected promise drop/increment",
            )?;
        }
        require(
            v["ended_failed74_actor_future"].is_null(),
            "actor promise already ended",
        )?;
        if next == pins["anchor"] {
            require(
                data == BASE_DATA && newer.is_some(),
                "wrong original anchor",
            )?;
            return bound(&request["current_DATA_authority"]);
        }
        require(
            [
                "horizon-failed74-actor-future-QA-booking-v1",
                "horizon-failed74-actor-future-QA-closed-v1",
                "horizon-failed74-actor-future-native512-booking-v1",
            ]
            .contains(&string(&v, "schema")?),
            "unknown post-anchor allocation",
        )?;
        require(
            v["old_failed74_and_all_other_claims_retained"] == true
                && v["resource_credit_bytes"] == 0,
            "post-anchor claim drop",
        )?;
        newer = Some(data);
        next = v["previous"].clone();
    }
    Err("DATA authority did not reach exact anchor".into())
}
fn proofs(pins: &Value) -> R<(Value, Value)> {
    let plan = bound(&pins["plan"])?;
    let watchdog = bound(&pins["watchdog"])?;
    let terminal = bound(&pins["terminal"])?;
    let raw = bound(&pins["raw"])?;
    require(
        plan["actor_unit"] == ACTOR
            && plan["guard_unit"] == GUARD
            && plan["timer_unit"] == TIMER
            && plan["output_root"] == OUTPUT
            && plan["output_maximum_bytes"] == OLD_OUTPUT
            && plan["actor_memory_bytes"] == ACTOR_MEMORY
            && plan["guard_memory_bytes"] == GUARD_MEMORY
            && plan["program"]["path"] == PROGRAM
            && plan["program"]["sha256"] == PROGRAM_SHA,
        "original plan changed",
    )?;
    require(
        watchdog["actor_iid"] == IID
            && watchdog["at_unix_seconds"] == 1_794_072_782u64
            && watchdog["charged_output_bytes"] == CLOSED_BYTES
            && watchdog["error"] == "missing/stale/crossed native guard proof"
            && watchdog["phase"] == 2,
        "original watchdog failure changed",
    )?;
    require(
        terminal["memory_credit_bytes"] == 0
            && terminal["DATA_credit_bytes"] == 0
            && terminal["all_sources_and_partial_output_preserved"] == true
            && terminal["native"]["InvocationID"] == IID
            && terminal["native"]["ExecMainStatus"] == "74",
        "original terminal evidence changed",
    )?;
    require(
        terminal["original_PID1_journal"]
            .as_array()
            .ok_or("original PID1 history")?
            .iter()
            .any(|r| {
                r["_PID"] == "1"
                    && r["_UID"] == "0"
                    && r["UNIT"] == ACTOR
                    && r["INVOCATION_ID"] == IID
                    && r["UNIT_RESULT"] == "exit-code"
            }),
        "original failed PID1 completion missing",
    )?;
    let peers = raw["active_peer_allocations"]
        .as_array()
        .ok_or("raw peer census")?;
    let matches: Vec<_> = peers
        .iter()
        .filter(|r| r["unit"] == ACTOR || r["invocation_id"] == IID)
        .collect();
    require(matches.len() == 1, "duplicate/crossed failed74 peer")?;
    Ok((plan, matches[0].clone()))
}
fn run() -> R<()> {
    let a: Vec<_> = std::env::args().collect();
    require(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && ["check", "end"].contains(&a[6].as_str()),
        "TOOL PLAN --plan-sha256 SHA --self-sha256 SHA check|end",
    )?;
    require(
        fs::metadata("/proc/self")?.uid() == 0
            && !std::env::vars_os()
                .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "Root without loader overrides required",
    )?;
    require(
        fs::read_link("/proc/self/exe")? == Path::new(IMAGE)
            && sha(&fs::read("/proc/self/exe")?) == a[5],
        "exact normal image/self SHA mismatch",
    )?;
    let own_unit = format!("horizon-failed74-actor-future-{}-20261109-v1.service", a[6]);
    let own_before = native(&own_unit)?;
    own_policy(&own_before, &a[6])?;
    let pins: Value = serde_json::from_str(PINS)?;
    let request = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    require(
        request["schema"] == "horizon-failed74-actor-future-plan-v1"
            && request["authority"]["original_actor_will_never_be_restarted"] == true
            && request["authority"]["end_only_actor80GiB_and_future_output96GiB"] == true
            && request["authority"]["all_original_files_sources_guard_CPU_and_metadata_retained"]
                == true
            && request["authority"]["all_other_ended_claims_preserved_without_double_credit"]
                == true,
        "exact Root actor-future-only authority required",
    )?;
    let observed = number(&request, "recorded_unix_seconds")?;
    require(
        clock()?.checked_sub(observed).is_some_and(|age| age <= 900),
        "stale/future request",
    )?;
    let current = current_chain(&request, &pins)?;
    require(
        current["schema"] == "horizon-failed74-actor-future-native512-booking-v1"
            && current["temporary_native_memory_bytes"] == 512u64 << 20
            && current["base_projected_memory_bytes_without_temporary_role"] == BASE_MEMORY,
        "native allowance/base memory missing",
    )?;
    let out = Path::new(RECEIPTS);
    let om = fs::symlink_metadata(out)?;
    require(
        out.canonicalize()? == out && om.is_dir() && om.uid() == 0 && om.mode() & 0o777 == 0o700,
        "Root0700 receipt directory required",
    )?;
    require(
        !out.join("ended.json").try_exists()?,
        "existing ended receipt: inspect, never repeat",
    )?;
    for key in ["actor_fragment", "guard_fragment", "timer_fragment"] {
        bound_text(&pins[key])?;
    }
    require(
        sha(&bytes(Path::new(PROGRAM), 64 << 20)?) == PROGRAM_SHA,
        "original program changed",
    )?;
    let (plan, peer) = proofs(&pins)?;
    let source = source_identity(&plan)?;
    let tree = retained_tree(Path::new(OUTPUT))?;
    let actor = native(ACTOR)?;
    actor_policy(&actor)?;
    empty_native_hook(ACTOR, "ExecStartPre")?;
    empty_native_hook(ACTOR, "ExecStartPost")?;
    empty_native_hook(GUARD, "ExecStartPre")?;
    empty_native_hook(GUARD, "ExecStartPost")?;
    let guard = native(GUARD)?;
    let timer = native(TIMER)?;
    retained_guard(&guard, &timer)?;
    eprintln!(
        "failed74 {}: original failed actor, retained output/source and active guard family validated; process reference scan",
        a[6]
    );
    let references = proc_scan(&[PathBuf::from(OUTPUT)])?;
    let (data, memory) = selection(
        number(&current, "complete_DATA_bytes")?,
        number(
            &current,
            "base_projected_memory_bytes_without_temporary_role",
        )?,
        number(&tree, "apparent_bytes")?,
        &peer,
    )?;
    require(
        actor == native(ACTOR)?
            && source == source_identity(&plan)?
            && tree == retained_tree(Path::new(OUTPUT))?,
        "actor or retained files changed",
    )?;
    retained_guard(&native(GUARD)?, &native(TIMER)?)?;
    for key in ["actor_fragment", "guard_fragment", "timer_fragment"] {
        bound_text(&pins[key])?;
    }
    let (after_plan, after_peer) = proofs(&pins)?;
    require(
        plan == after_plan && peer == after_peer,
        "original evidence changed",
    )?;
    require(
        own_before == native(&own_unit)?,
        "helper native identity changed",
    )?;
    require(
        clock()?.checked_sub(observed).is_some_and(|age| age <= 900),
        "request expired during inspection",
    )?;
    let result = json!({"schema":"horizon-failed74-actor-future-inspection-v1","original_actor":actor,"guard_before":guard,"timer_before":timer,"retained_source_identity":source,"retained_tree":tree,"reference_scan":references,"raw_peer_unchanged":peer,"historical_pins":pins,"current_DATA_authority":request["current_DATA_authority"],"previous_complete_DATA_bytes":number(&current,"complete_DATA_bytes")?,"complete_DATA_bytes":data,"base_projected_memory_bytes_before":BASE_MEMORY,"base_projected_memory_bytes_after":memory,"ended_actor_memory_bytes":ACTOR_MEMORY,"ended_future_output_bytes":ENDED_OUTPUT,"retained_output_allowance_bytes":RETAINED_OUTPUT,"retained_guard_memory_bytes":GUARD_MEMORY,"all_physical_files_retained":true,"physical_credit_bytes":0,"all_CPU_and_guard_metadata_source_promises_retained":true,"raw_rows_mutated":false,"replay_admission_authorized":false,"remote_mutations":false});
    if a[6] == "check" {
        durable(&out.join("check.json"), &result)?;
        println!("checked exact failed74 actor-future transition; no promise ended");
        return Ok(());
    }
    let prior = bound(
        &json!({"path":out.join("check.json"),"sha256":string(&request,"prior_check_sha256")?}),
    )?;
    for key in [
        "original_actor",
        "retained_source_identity",
        "retained_tree",
        "raw_peer_unchanged",
        "historical_pins",
        "current_DATA_authority",
        "complete_DATA_bytes",
        "base_projected_memory_bytes_after",
        "ended_actor_memory_bytes",
        "ended_future_output_bytes",
    ] {
        require(prior[key] == result[key], "prior check does not reproduce")?;
    }
    let mut receipt = result;
    receipt["schema"] = json!("horizon-failed74-actor-future-ended-v1");
    receipt["recorded_unix_seconds"] = json!(clock()?);
    receipt["request"] = json!({"path":a[1],"sha256":a[3]});
    receipt["prior_check_sha256"] = request["prior_check_sha256"].clone();
    receipt["ended_failed74_actor_future"] = json!(IID);
    receipt["native_extra512_memory_remains_reserved_until_actual_drain"] = json!(true);
    durable(&out.join("ended.json"), &receipt)?;
    println!(
        "ended original failed74 actor80GiB and future output96GiB only; all physical files and guard promises retained"
    );
    Ok(())
}
fn bound_text(b: &Value) -> R<()> {
    require(
        sha(&bytes(Path::new(string(b, "path")?), 16 << 20)?) == string(b, "sha256")?,
        "original native fragment changed",
    )
}
fn main() {
    if let Err(e) = run() {
        eprintln!("failed74 actor-future refused: {e}");
        std::process::exit(1);
    }
}

fn path_ref(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).enumerate().any(|(i, s)| {
        s == needle
            && (i + needle.len() == bytes.len()
                || b"/\0\n\r\t '\";|&()<>[]{}:=,".contains(&bytes[i + needle.len()]))
    })
}
fn check_blob(bytes: &[u8], targets: &[PathBuf], label: &str) -> R<()> {
    for p in targets {
        require(
            !path_ref(bytes, p.as_os_str().as_encoded_bytes()),
            &format!("consumer reference: {label}"),
        )?;
    }
    Ok(())
}
fn transient(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound || e.raw_os_error() == Some(3)
}
fn proc_scan(targets: &[PathBuf]) -> R<Value> {
    let me = std::process::id().to_string();
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        let p = entry?.path();
        let name = p.file_name().ok_or("pid name")?.to_string_lossy();
        if name == me || !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let before = match fs::read(p.join("stat")) {
            Ok(x) => x,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(e.into()),
        };
        for n in ["cmdline", "maps", "environ"] {
            match fs::read(p.join(n)) {
                Ok(b) => check_blob(&b, targets, &format!("{name}/{n}"))?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        for n in ["cwd", "root", "exe"] {
            match fs::read_link(p.join(n)) {
                Ok(q) => check_blob(
                    q.as_os_str().as_encoded_bytes(),
                    targets,
                    &format!("{name}/{n}"),
                )?,
                Err(e) if transient(&e) => {}
                Err(e) => return Err(e.into()),
            }
        }
        match fs::read_dir(p.join("fd")) {
            Ok(fds) => {
                for fd in fds {
                    let fd = fd?;
                    match fs::read_link(fd.path()) {
                        Ok(q) => check_blob(
                            q.as_os_str().as_encoded_bytes(),
                            targets,
                            &format!("{name}/fd"),
                        )?,
                        Err(e) if transient(&e) => {}
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            Err(e) if transient(&e) => {}
            Err(e) => return Err(e.into()),
        }
        if let Ok(after) = fs::read(p.join("stat")) {
            require(
                start_ticks(&before)? == start_ticks(&after)?,
                "PID reused during census",
            )?;
        }
        count += 1;
    }
    Ok(json!({"processes":count,"permission_errors":0}))
}
fn start_ticks(b: &[u8]) -> R<&str> {
    let s = std::str::from_utf8(b)?;
    s.rsplit_once(')')
        .ok_or("bad proc stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| "missing proc start ticks".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> Value {
        json!({"unit":ACTOR,"invocation_id":IID,"memory_max_bytes":ACTOR_MEMORY+GUARD_MEMORY,"actual_actor_memory_hard_limit_bytes":ACTOR_MEMORY,"reserved_guard_memory_bytes":GUARD_MEMORY,"output_DATA_bytes":OLD_OUTPUT,"data_reservation_bytes":176_227_876_864u64,"metadata_DATA_bytes":128u64<<20,"retained185_source_DATA_bytes":4u64<<30})
    }
    fn actor() -> Value {
        let mut v = json!({"Id":ACTOR,"LoadState":"loaded","InvocationID":IID,"ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","ControlGroup":"","NRestarts":"0","Result":"exit-code","ExecMainCode":"1","ExecMainStatus":"74","ExecMainPID":"2463122","ExecMainStartTimestamp":"Sat 2026-11-07 07:44:22 UTC","ExecMainExitTimestamp":"Sat 2026-11-07 17:33:02 UTC","Restart":"no","Type":"exec","User":"root","Group":"root","KillMode":"control-group","Delegate":"no","MemoryMax":"85899345920","MemorySwapMax":"0","CPUQuotaPerSecUSec":"8s","TasksMax":"512","ExecStart":format!("{{ path={PROGRAM} ; argv[]={PROGRAM} extract {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ; ignore_errors=no ; pid=0 }}")});
        for k in [
            "Job",
            "TriggeredBy",
            "Triggers",
            "WantedBy",
            "RequiredBy",
            "Upholds",
            "UpheldBy",
            "DropInPaths",
        ] {
            v[k] = json!("");
        }
        v
    }
    #[test]
    fn exact_future_difference_keeps_guard_source_metadata_and_output() {
        let (data, memory) =
            selection(BASE_DATA + (128 << 20), BASE_MEMORY, CLOSED_BYTES, &peer()).unwrap();
        assert_eq!(data, 6_465_055_178_546);
        assert_eq!(memory, 622_350_577_664);
        assert_eq!(OLD_OUTPUT - ENDED_OUTPUT, RETAINED_OUTPUT);
        assert_eq!(ACTOR_MEMORY + GUARD_MEMORY - ACTOR_MEMORY, GUARD_MEMORY);
    }
    #[test]
    fn no_old_baseline_new_claim_or_double_credit() {
        for data in [
            BASE_DATA,
            BASE_DATA + (256 << 20),
            BASE_DATA + (128 << 20) - ENDED_OUTPUT,
        ] {
            assert!(selection(data, BASE_MEMORY, CLOSED_BYTES, &peer()).is_err());
        }
        assert!(
            selection(
                BASE_DATA + (128 << 20),
                BASE_MEMORY - ACTOR_MEMORY,
                CLOSED_BYTES,
                &peer()
            )
            .is_err()
        );
    }
    #[test]
    fn guard_and_raw_identity_cannot_be_borrowed_or_refunded() {
        for (key, value) in [
            ("invocation_id", json!(TIMER_IID)),
            ("unit", json!(GUARD)),
            ("reserved_guard_memory_bytes", json!(0)),
            ("memory_max_bytes", json!(ACTOR_MEMORY)),
            ("output_DATA_bytes", json!(RETAINED_OUTPUT)),
            ("metadata_DATA_bytes", json!(0)),
            ("retained185_source_DATA_bytes", json!(0)),
        ] {
            let mut p = peer();
            p[key] = value;
            assert!(selection(BASE_DATA + (128 << 20), BASE_MEMORY, CLOSED_BYTES, &p).is_err());
        }
    }
    #[test]
    fn current_output_is_not_historical_partial_or_a_retirement() {
        for n in [0, 41_966_206_710, RETAINED_OUTPUT, RETAINED_OUTPUT + 1] {
            assert!(selection(BASE_DATA + (128 << 20), BASE_MEMORY, n, &peer()).is_err());
        }
    }
    #[test]
    fn genuine_failed74_shape_accepts_and_replacement_or_live_actor_rejects() {
        assert!(actor_policy(&actor()).is_ok());
        for (k, v) in [
            ("InvocationID", json!(TIMER_IID)),
            ("MainPID", json!("2463122")),
            ("ControlPID", json!("7")),
            ("NRestarts", json!("1")),
            ("ExecMainStatus", json!("0")),
            ("ActiveState", json!("active")),
            ("TriggeredBy", json!(TIMER)),
            ("WantedBy", json!("some.target")),
            ("DropInPaths", json!("/tmp/override.conf")),
        ] {
            let mut a = actor();
            a[k] = v;
            assert!(actor_policy(&a).is_err());
        }
    }
    #[test]
    fn command_mode_and_a_second_execution_cannot_cross_roles() {
        let mut a = actor();
        a["ExecStart"] = json!(
            string(&a, "ExecStart")
                .unwrap()
                .replace(" extract ", " guard ")
        );
        assert!(actor_policy(&a).is_err());
        let mut a = actor();
        a["ExecStart"] = json!(format!(
            "{} ; argv[]=other",
            string(&a, "ExecStart").unwrap()
        ));
        assert!(actor_policy(&a).is_err());
    }
    #[test]
    fn proc_path_boundary_does_not_match_sibling() {
        assert!(path_ref(b"/home/sol/output/file", b"/home/sol/output"));
        assert!(!path_ref(
            b"/home/sol/output-other/file",
            b"/home/sol/output"
        ));
    }
    #[test]
    fn manager_object_path_is_typed_exact_unit_encoding() {
        assert_eq!(
            unit_object("a-b.service"),
            "/org/freedesktop/systemd1/unit/a_2db_2eservice"
        );
    }
}
