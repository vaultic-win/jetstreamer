//! Source proposal only. End exact old722 future promises; retain every physical file.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const PINS: &str = include_str!("bindings.json");
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-old722-actor-future-tools-20261109-v3/end-actor";
const IID: &str = "722adc397ae24bb4b96d452783599f57";
const ACTOR: &str = "horizon-qualify-185-capped-cold-positive-positive-0500-20261109-next.service";
const GUARD: &str = "horizon-guard-185-capped-cold-positive-positive-0500-20261109-next.service";
const TIMER: &str = "horizon-guard-185-capped-cold-positive-positive-0500-20261109-next.timer";
const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v12/epoch185-guarded-cold";
const PROGRAM_SHA: &str = "b437ada8808ceae8d80a699fa2114446c735d7e72ae4d616fdead4646bb3082e";
const PLAN: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-positive-envelope-positive-0500-20261109-next/envelope.json";
const PLAN_SHA: &str = "ff8bd6e279fad04843692652ed2ed014455974bb1f8db3a7b00e6bacdb8605bd";
const RUN_ROOT: &str =
    "/home/sol/.jetstreamer-private/capped-root-prefix-185-positive-positive-0500-20261109-next";
const RECEIPTS: &str =
    "/var/lib/jetstreamer/horizon-old722-actor-future-20261109-v1/722adc397ae24bb4b96d452783599f57";
const BASE_DATA: u64 = 6_782_882_758_450;
const BASE_MEMORY: u64 = 696_438_763_520;
const ACTOR_MEMORY: u64 = 48 << 30;
const GUARD_MEMORY: u64 = 256 << 20;
const OLD_SCRATCH: u64 = 384 << 30;
const OLD_OUTPUT: u64 = 128 << 30;
const RETAINED_SCRATCH: u64 = 64 << 30;
const RETAINED_OUTPUT: u64 = 64 << 20;
const METADATA: u64 = 64 << 20;
const LOG: u64 = 64 << 20;
const OLD_DATA: u64 = OLD_SCRATCH + OLD_OUTPUT + METADATA + LOG;
const RETAINED_DATA: u64 = RETAINED_SCRATCH + RETAINED_OUTPUT + METADATA + LOG;
const ENDED_DATA: u64 = OLD_DATA - RETAINED_DATA;
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
include!("common.rs");

fn command(v: &Value, property: &str, mode: Option<&str>) -> R<()> {
    let middle = mode.map_or(String::new(), |m| format!("{m} "));
    let expected = format!(
        "argv[]={PROGRAM} {middle}{PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ; ignore_errors=no"
    );
    let actual = string(v, property)?;
    require(
        actual.contains(&expected) && actual.matches("argv[]=").count() == 1,
        "original execution command changed",
    )
}
fn own_policy(v: &Value, operation: &str) -> R<()> {
    let unit = format!("horizon-old722-actor-future-{operation}-20261109-v3.service");
    let pid = std::process::id().to_string();
    require(
        v["Id"] == unit
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["MainPID"] == pid
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
        "exact finite512MiB helper required",
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
            && a["ExecMainStatus"] == "1"
            && a["ExecMainPID"] == "3961564"
            && a["ExecMainStartTimestamp"] == "Mon 2026-11-09 05:15:23 UTC"
            && !string(a, "ExecMainExitTimestamp")?.is_empty(),
        "exact genuinely started failed722 actor required",
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
            && a["User"] == "sol"
            && a["Group"] == "horizon"
            && a["KillMode"] == "control-group"
            && a["Delegate"] == "no"
            && a["MemoryMax"] == "51539607552"
            && a["MemorySwapMax"] == "0"
            && a["CPUQuotaPerSecUSec"] == "4s"
            && a["TasksMax"] == "1024"
            && a["RuntimeMaxUSec"] == "4h",
        "old722 actor hard envelope changed",
    )?;
    command(a, "ExecStart", None)
}
fn guard_policy(g: &Value, t: &Value) -> R<()> {
    require(
        t["Id"] == TIMER
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "inactive"
            && t["SubState"] == "dead"
            && t["Triggers"] == GUARD
            && t["Job"] == ""
            && t["DropInPaths"] == "",
        "retained722 timer must remain inactive",
    )?;
    require(
        g["Id"] == GUARD
            && g["LoadState"] == "loaded"
            && g["ActiveState"] == "failed"
            && g["SubState"] == "failed"
            && g["MainPID"] == "0"
            && g["ControlPID"] == "0"
            && g["ControlGroup"] == ""
            && g["NRestarts"] == "0"
            && g["Job"] == ""
            && g["Result"] == "exit-code"
            && g["ExecMainStatus"] == "1"
            && g["Restart"] == "no"
            && g["Type"] == "oneshot"
            && g["User"] == "root"
            && g["Group"] == "root"
            && g["MemoryMax"] == "268435456"
            && g["MemorySwapMax"] == "0"
            && g["CPUQuotaPerSecUSec"] == "1s"
            && g["TasksMax"] == "256"
            && g["TriggeredBy"] == ""
            && g["DropInPaths"] == "",
        "old722 guard changed or is not drained",
    )?;
    command(g, "ExecStart", Some("guard"))
}
fn hook_pre() -> R<()> {
    let out = Command::new("/usr/bin/busctl")
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            &unit_object(ACTOR),
            "org.freedesktop.systemd1.Service",
            "ExecStartPre",
        ])
        .output()?;
    require(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() < 65536,
        "typed prestart query",
    )?;
    let v: Value = serde_json::from_slice(&out.stdout)?;
    let rows = v["data"].as_array().ok_or("typed prestart array")?;
    require(
        v["type"] == "a(sasbttttuii)" && rows.len() == 1,
        "exact one original prestart required",
    )?;
    let r = rows[0].as_array().ok_or("prestart tuple")?;
    require(
        r.len() == 10
            && r[0] == PROGRAM
            && r[1]
                == json!([
                    PROGRAM,
                    "prestart",
                    PLAN,
                    "--plan-sha256",
                    PLAN_SHA,
                    "--self-sha256",
                    PROGRAM_SHA
                ])
            && r[2] == false,
        "changed prestart executable/argv/ignore-errors",
    )
}
fn bound_sol(b: &Value) -> R<Value> {
    let path = Path::new(string(b, "path")?);
    require(
        path.is_absolute() && path.canonicalize()? == path,
        "sol canonical metadata",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    require(
        m.is_file()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o400
            && m.len() <= 1 << 20,
        "closed sol metadata custody",
    )?;
    let mut raw = Vec::new();
    Read::by_ref(&mut f)
        .take((1 << 20) + 1)
        .read_to_end(&mut raw)?;
    require(
        raw.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?)
            && sha(&raw) == string(b, "sha256")?,
        "closed sol metadata changed",
    )?;
    Ok(serde_json::from_slice(&raw)?)
}
fn proofs(pins: &Value) -> R<Value> {
    let task = bound(&pins["task"])?;
    let terminal = bound(&pins["terminal"])?;
    let lifecycle = bound(&pins["lifecycle"])?;
    let env = bound(&pins["envelope"])?;
    let failure = bound_sol(&pins["failure"])?;
    require(
        task["schema"] == "horizon-epoch185-genuine-native-startpre-task-v1"
            && task["actor_invocation_id"] == IID
            && task["run_root"] == RUN_ROOT
            && task["release"].is_null()
            && task["limits"] == env["limits"]
            && task["candidate_DATA_bytes"] == OLD_DATA
            && task["limits"]["scratch"] == OLD_SCRATCH
            && task["limits"]["output"] == OLD_OUTPUT
            && task["limits"]["memory"] == ACTOR_MEMORY
            && task["limits"]["metadata"] == METADATA
            && task["limits"]["log"] == LOG
            && env["plan"]["run_root"] == RUN_ROOT
            && env["self_program"] == PROGRAM
            && env["self_sha256"] == PROGRAM_SHA,
        "original task/envelope promise changed",
    )?;
    let tc = &terminal["terminal_context"];
    require(
        terminal["schema"] == "horizon-epoch185-native-terminal-retention-v2"
            && terminal["actor_invocation_id"] == IID
            && terminal["resource_credit_bytes"] == 0
            && terminal["memory_and_DATA_retained"] == true
            && tc["schema"] == "horizon-epoch185-genuine-drained-terminal-context-v2"
            && tc["actor_unit"] == ACTOR
            && tc["actor_invocation_id"] == IID
            && tc["actor_cgroup_drained"] == true
            && tc["guard_cgroup_drained"] == true
            && tc["timer_cgroup_drained"] == true
            && tc["timer_inactive"] == true
            && tc["terminal_actor_exit_status"] == "1"
            && tc["terminal_guard_exit_status"] == "1"
            && tc["terminal_at"] == 1_794_201_806u64,
        "genuine started terminal context required",
    )?;
    let start = &tc["original_start_event"];
    let end = &tc["original_terminal_event"];
    require(
        start["_PID"] == "1"
            && start["_UID"] == "0"
            && start["UNIT"] == ACTOR
            && start["INVOCATION_ID"] == IID
            && start["JOB_TYPE"] == "start"
            && start["JOB_RESULT"] == "done"
            && start["__REALTIME_TIMESTAMP"] == "1794201323260859"
            && end["_PID"] == "1"
            && end["_UID"] == "0"
            && end["UNIT"] == ACTOR
            && end["INVOCATION_ID"] == IID
            && end["UNIT_RESULT"] == "exit-code"
            && end["__REALTIME_TIMESTAMP"] == "1794201806932317",
        "original PID1 start/terminal history required",
    )?;
    require(
        lifecycle["schema"] == "horizon-epoch185-native-retained-lifecycle-v2"
            && lifecycle["actor_invocation_id"] == IID
            && lifecycle["task"] == pins["task"]
            && lifecycle["candidate_DATA_bytes"] == OLD_DATA
            && lifecycle["limits"] == task["limits"]
            && lifecycle["released_actor"]["pid"] == 3_961_564u64
            && lifecycle["released_actor"]["start_ticks"] == 254_798_434u64
            && lifecycle["release"]["original_start_event"] == *start
            && lifecycle["release"]["token"] == tc["release_token"]
            && lifecycle["release"]["seal"] == tc["release_seal"],
        "genuine released722 history required",
    )?;
    for k in ["token", "seal", "first_guard"] {
        let actual = bound(&lifecycle["release"][k])?;
        let value_key = match k {
            "token" => "token_value",
            "seal" => "seal_value",
            _ => "first_guard_value",
        };
        require(
            actual == lifecycle["release"][value_key],
            "released native evidence changed",
        )?;
    }
    require(
        failure["schema"] == "horizon-private-epoch185-capped-root-prefix-resource-v4"
            && failure["unit"] == ACTOR
            && failure["invocation_id"] == IID
            && failure["success"] == false
            && failure["archive_length"] == 0
            && failure["first_progress"].is_null()
            && failure["last_progress"].is_null()
            && failure["producer_canonical_root_prefix_present"] == false
            && failure["producer_segment_manifest"].is_null()
            && failure["error"].as_str().is_some_and(|e| {
                e.starts_with("allocation census retry limit; no usage accepted:")
            }),
        "closed original initialization failure required; no archive completion inferred",
    )?;
    let raw = bound(&pins["raw"])?;
    let peers = raw["active_peer_allocations"]
        .as_array()
        .ok_or("original raw peers")?;
    let selected: Vec<_> = peers
        .iter()
        .filter(|r| r["invocation_id"] == IID || r["unit"] == ACTOR)
        .collect();
    require(selected.len() == 1, "crossed/duplicate722 raw peer")?;
    let peer = selected[0].clone();
    require(
        peer["unit"] == ACTOR
            && peer["invocation_id"] == IID
            && peer["data_reservation_bytes"] == OLD_DATA
            && peer["memory_max_bytes"] == ACTOR_MEMORY + GUARD_MEMORY
            && peer["actual_actor_memory_hard_limit_bytes"] == ACTOR_MEMORY
            && peer["reserved_guard_memory_bytes"] == GUARD_MEMORY
            && peer["epoch185_task"] == pins["task"]
            && peer["cold185_terminal_retention"] == pins["terminal"]
            && peer["cold185_lifecycle"] == pins["lifecycle"],
        "raw722 promises changed",
    )?;
    Ok(peer)
}

#[derive(Default)]
struct Scan {
    apparent: u64,
    physical: u64,
    entries: u64,
    digest: Sha256,
}
fn walk(
    path: &Path,
    root: &Path,
    device: u64,
    depth: usize,
    scan: &mut Scan,
    start: Instant,
) -> R<()> {
    require(
        depth <= 64 && start.elapsed().as_secs() < 30 && scan.entries < 4_000_000,
        "retained census bound exceeded",
    )?;
    let m = fs::symlink_metadata(path)?;
    require(
        m.dev() == device
            && !m.file_type().is_symlink()
            && ((m.uid() == 1001 && m.gid() == 1003) || (m.uid() == 0 && m.gid() == 0))
            && m.mode() & 0o022 == 0
            && (m.is_dir() || (m.is_file() && m.nlink() == 1)),
        "retained entry mount/type/owner/link/mode changed",
    )?;
    require(
        path.canonicalize()? == path,
        "retained namespace path changed",
    )?;
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(path)?;
    require(
        identity(&m) == identity(&held.metadata()?),
        "retained entry changed on open",
    )?;
    scan.entries = scan.entries.checked_add(1).ok_or("entry overflow")?;
    scan.apparent = scan
        .apparent
        .checked_add(m.len())
        .ok_or("apparent overflow")?;
    scan.physical = scan
        .physical
        .checked_add(m.blocks().checked_mul(512).ok_or("blocks overflow")?)
        .ok_or("physical overflow")?;
    scan.digest.update(serde_json::to_vec(&json!([
        path.strip_prefix(root)?.as_os_str().as_encoded_bytes(),
        identity(&m)
    ]))?);
    if m.is_dir() {
        let mut entries = Vec::new();
        for e in fs::read_dir(path)? {
            require(
                entries.len() < 1_000_000,
                "one directory exceeds bounded census",
            )?;
            entries.push(e?.path());
        }
        entries.sort();
        for child in entries {
            walk(&child, root, device, depth + 1, scan, start)?;
        }
    }
    require(
        identity(&m) == identity(&held.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "retained entry changed during census",
    )?;
    require(
        start.elapsed().as_secs() < 30,
        "retained census deadline exceeded",
    )
}
fn finish(s: Scan) -> Value {
    json!({"apparent_bytes":s.apparent,"physical_bytes":s.physical,"entries":s.entries,"metadata_digest":format!("{:x}",s.digest.finalize())})
}
fn retained_tree() -> R<Value> {
    let root = Path::new(RUN_ROOT);
    let m = fs::symlink_metadata(root)?;
    require(
        root.canonicalize()? == root
            && m.is_dir()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() & 0o777 == 0o700,
        "original722 root custody",
    )?;
    let expected = BTreeSet::from([
        ".jetstreamer-private".to_owned(),
        "ledger".to_owned(),
        "output".to_owned(),
        "receipts".to_owned(),
        "scratch".to_owned(),
    ]);
    let actual = fs::read_dir(root)?
        .map(|x| x.map(|v| v.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    require(actual == expected, "original722 root members changed")?;
    let start = Instant::now();
    let mut scratch = Scan::default();
    let mut output = Scan::default();
    let mut metadata = Scan {
        apparent: m.len(),
        physical: m.blocks().checked_mul(512).ok_or("root blocks overflow")?,
        ..Scan::default()
    };
    metadata.digest.update(serde_json::to_vec(&identity(&m))?);
    for name in [".jetstreamer-private", "ledger", "scratch"] {
        walk(&root.join(name), root, m.dev(), 1, &mut scratch, start)?;
    }
    walk(&root.join("output"), root, m.dev(), 1, &mut output, start)?;
    walk(
        &root.join("receipts"),
        root,
        m.dev(),
        1,
        &mut metadata,
        start,
    )?;
    let v = json!({"root":identity(&m),"scratch":finish(scratch),"output":finish(output),"metadata":finish(metadata)});
    retained_caps(&v)?;
    require(
        identity(&m) == identity(&fs::symlink_metadata(root)?),
        "root changed during retained census",
    )?;
    Ok(v)
}
fn retained_caps(v: &Value) -> R<()> {
    for (key, cap) in [
        ("scratch", RETAINED_SCRATCH),
        ("output", RETAINED_OUTPUT),
        ("metadata", METADATA),
    ] {
        require(
            number(&v[key], "apparent_bytes")? <= cap && number(&v[key], "physical_bytes")? <= cap,
            "retained722 bytes exceed conservative retained allowance",
        )?;
    }
    Ok(())
}
fn selection(data: u64, memory: u64, peer: &Value) -> R<(u64, u64)> {
    require(
        data == BASE_DATA
            && memory == BASE_MEMORY
            && peer["unit"] == ACTOR
            && peer["invocation_id"] == IID
            && peer["data_reservation_bytes"] == OLD_DATA
            && peer["memory_max_bytes"] == ACTOR_MEMORY + GUARD_MEMORY
            && peer["actual_actor_memory_hard_limit_bytes"] == ACTOR_MEMORY
            && peer["reserved_guard_memory_bytes"] == GUARD_MEMORY,
        "crossed baseline or raw722 promise",
    )?;
    Ok((
        data.checked_sub(ENDED_DATA).ok_or("DATA underflow")?,
        memory.checked_sub(ACTOR_MEMORY).ok_or("memory underflow")?,
    ))
}
fn current_chain(request: &Value, pins: &Value) -> R<Value> {
    let mut next = request["current_DATA_authority"].clone();
    let mut seen = BTreeSet::new();
    for _ in 0..16 {
        require(
            seen.insert(next.to_string()),
            "cyclic current DATA ancestry",
        )?;
        let v = bound(&next)?;
        require(
            v["ended_old722_actor_future"].is_null(),
            "old722 future already ended",
        )?;
        if next == pins["anchor"] {
            require(
                v["complete_DATA_bytes"] == BASE_DATA
                    && v["complete_projected_memory_bytes"] == BASE_MEMORY
                    && v["all_raw_history_and_physical_files_retained"] == true
                    && v["no_duplicate_failed1530_failed136_cached145_original199_or_captured141_credit"]
                        == true,
                "actual169 anchor changed",
            )?;
            return bound(&request["current_DATA_authority"]);
        }
        require(
            [
                "horizon-old722-actor-future-QA-booking-v1",
                "horizon-old722-actor-future-QA-closed-v1",
                "horizon-old722-actor-future-native512-booking-v1",
            ]
            .contains(&string(&v, "schema")?)
                && v["complete_DATA_bytes"] == BASE_DATA
                && v["new_retained_DATA_bytes"] == 0
                && v["tooling_on_separate_OS_filesystem"] == true
                && v["separate_OS_allowance_bytes"] == 268_435_456u64
                && v["base_projected_memory_bytes_without_temporary_role"] == BASE_MEMORY
                && v["old722_and_all_other_claims_retained"] == true
                && v["resource_credit_bytes"] == 0,
            "unknown intervening722 allocation/claim change",
        )?;
        next = v["previous"].clone();
    }
    Err("current722 authority did not reach exact169 anchor".into())
}
fn bound_text(b: &Value) -> R<()> {
    require(
        sha(&bytes(Path::new(string(b, "path")?), 32 << 20)?) == string(b, "sha256")?,
        "original native source changed",
    )
}
fn inspect_native() -> R<(Value, Value, Value)> {
    let a = native(ACTOR)?;
    actor_policy(&a)?;
    hook_pre()?;
    empty_native_hook(ACTOR, "ExecStartPost")?;
    empty_native_hook(GUARD, "ExecStartPre")?;
    empty_native_hook(GUARD, "ExecStartPost")?;
    let g = native(GUARD)?;
    let t = native(TIMER)?;
    guard_policy(&g, &t)?;
    Ok((a, g, t))
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
        "exact normal image/selfSHA required",
    )?;
    let own_unit = format!("horizon-old722-actor-future-{}-20261109-v3.service", a[6]);
    let own = native(&own_unit)?;
    own_policy(&own, &a[6])?;
    let request = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let pins: Value = serde_json::from_str(PINS)?;
    require(
        request["schema"] == "horizon-old722-actor-future-plan-v1"
            && request["authority"]["original_actor_will_never_be_restarted"] == true
            && request["authority"]["end_only_actor48GiB_and_unused_future_scratch_output"] == true
            && request["authority"]["all_physical_files_paths_inputs_guard_CPU_metadata_and_logs_retained"]
                == true
            && request["authority"]["all_prior_endings_preserved_without_double_credit"] == true,
        "exact722 future-only Root authority required",
    )?;
    let observed = number(&request, "recorded_unix_seconds")?;
    require(
        clock()?.checked_sub(observed).is_some_and(|n| n <= 900),
        "stale/future722 request",
    )?;
    let current = current_chain(&request, &pins)?;
    require(
        current["schema"] == "horizon-old722-actor-future-native512-booking-v1"
            && current["temporary_native_memory_bytes"] == 512u64 << 20,
        "fresh512MiB722 booking required",
    )?;
    let out = Path::new(RECEIPTS);
    let om = fs::symlink_metadata(out)?;
    require(
        out.canonicalize()? == out && om.is_dir() && om.uid() == 0 && om.mode() & 0o777 == 0o700,
        "Root0700 output required",
    )?;
    require(
        !out.join("ended.json").try_exists()? && !out.join("end-intent.json").try_exists()?,
        "existing/interrupted722 ending: inspect, never repeat",
    )?;
    for (key, unit) in [
        ("actor_fragment", ACTOR),
        ("guard_fragment", GUARD),
        ("timer_fragment", TIMER),
    ] {
        bound_text(&pins[key])?;
        require(
            fs::read_link(format!("/etc/systemd/system/{unit}"))?
                == Path::new(string(&pins[key], "path")?),
            "original native unit link changed",
        )?;
    }
    require(
        sha(&bytes(Path::new(PROGRAM), 64 << 20)?) == PROGRAM_SHA,
        "original immutable driver image changed",
    )?;
    let peer = proofs(&pins)?;
    let native_before = inspect_native()?;
    eprintln!(
        "old722 {}: genuine started terminal provenance verified; bounded retained metadata census starts",
        a[6]
    );
    let tree = retained_tree()?;
    let references = proc_scan(&[PathBuf::from(RUN_ROOT)])?;
    let tree_after = retained_tree()?;
    require(
        tree == tree_after,
        "retained722 metadata census changed across process scan",
    )?;
    require(
        native_before == inspect_native()? && own == native(&own_unit)? && peer == proofs(&pins)?,
        "722 native/owner/provenance changed",
    )?;
    for (key, unit) in [
        ("actor_fragment", ACTOR),
        ("guard_fragment", GUARD),
        ("timer_fragment", TIMER),
    ] {
        bound_text(&pins[key])?;
        require(
            fs::read_link(format!("/etc/systemd/system/{unit}"))?
                == Path::new(string(&pins[key], "path")?),
            "original native unit link changed",
        )?;
    }
    require(
        clock()?.checked_sub(observed).is_some_and(|n| n <= 900),
        "722 request expired during inspection",
    )?;
    let (data, memory) = selection(
        number(&current, "complete_DATA_bytes")?,
        number(
            &current,
            "base_projected_memory_bytes_without_temporary_role",
        )?,
        &peer,
    )?;
    let result = json!({"schema":"horizon-old722-actor-future-inspection-v1","original_actor":native_before.0,"guard":native_before.1,"timer":native_before.2,"retained_tree":tree,"reference_scan":references,"raw_peer_unchanged":peer,"historical_pins":pins,"current_DATA_authority":request["current_DATA_authority"],"previous_complete_DATA_bytes":number(&current,"complete_DATA_bytes")?,"complete_DATA_bytes":data,"base_projected_memory_bytes_before":BASE_MEMORY,"base_projected_memory_bytes_after":memory,"ended_actor_memory_bytes":ACTOR_MEMORY,"ended_future_DATA_bytes":ENDED_DATA,"retained_scratch_allowance_bytes":RETAINED_SCRATCH,"retained_output_allowance_bytes":RETAINED_OUTPUT,"retained_metadata_allowance_bytes":METADATA,"retained_log_allowance_bytes":LOG,"retained_guard_memory_bytes":GUARD_MEMORY,"all_physical_files_paths_and_inputs_retained":true,"all_CPU_guard_metadata_and_log_promises_retained":true,"physical_credit_bytes":0,"raw_rows_mutated":false,"replay_admission_authorized":false,"remote_mutations":false});
    if a[6] == "check" {
        durable(&out.join("check.json"), &result)?;
        println!("checked722 future-only transition; no promise ended");
        return Ok(());
    }
    let prior = bound(
        &json!({"path":out.join("check.json"),"sha256":string(&request,"prior_check_sha256")?}),
    )?;
    for key in [
        "schema",
        "original_actor",
        "guard",
        "timer",
        "retained_tree",
        "raw_peer_unchanged",
        "historical_pins",
        "current_DATA_authority",
        "previous_complete_DATA_bytes",
        "complete_DATA_bytes",
        "base_projected_memory_bytes_before",
        "base_projected_memory_bytes_after",
        "ended_actor_memory_bytes",
        "ended_future_DATA_bytes",
        "retained_scratch_allowance_bytes",
        "retained_output_allowance_bytes",
        "retained_guard_memory_bytes",
    ] {
        require(
            prior[key] == result[key],
            "722 native check must reproduce exact substantive state",
        )?;
    }
    durable(
        &out.join("end-intent.json"),
        &json!({"request":{"path":a[1],"sha256":a[3]},"inspection":result,"recorded_unix_seconds":clock()?}),
    )?;
    let mut receipt = result;
    receipt["schema"] = json!("horizon-old722-actor-future-ended-v1");
    receipt["recorded_unix_seconds"] = json!(clock()?);
    receipt["request"] = json!({"path":a[1],"sha256":a[3]});
    receipt["prior_check_sha256"] = request["prior_check_sha256"].clone();
    receipt["ended_old722_actor_future"] = json!(IID);
    receipt["temporary512_memory_stays_reserved_until_actual_drain"] = json!(true);
    durable(&out.join("ended.json"), &receipt)?;
    println!(
        "ended722 actor48GiB and unused future scratch/output only; every physical byte retained"
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("old722 future ending refused: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> Value {
        json!({"unit":ACTOR,"invocation_id":IID,"data_reservation_bytes":OLD_DATA,"memory_max_bytes":ACTOR_MEMORY+GUARD_MEMORY,"actual_actor_memory_hard_limit_bytes":ACTOR_MEMORY,"reserved_guard_memory_bytes":GUARD_MEMORY})
    }
    fn actor() -> Value {
        let mut v = json!({"Id":ACTOR,"LoadState":"loaded","InvocationID":IID,"ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","ControlGroup":"","NRestarts":"0","Result":"exit-code","ExecMainCode":"1","ExecMainStatus":"1","ExecMainPID":"3961564","ExecMainStartTimestamp":"Mon 2026-11-09 05:15:23 UTC","ExecMainExitTimestamp":"Mon 2026-11-09 05:23:23 UTC","Restart":"no","Type":"exec","User":"sol","Group":"horizon","KillMode":"control-group","Delegate":"no","MemoryMax":"51539607552","MemorySwapMax":"0","CPUQuotaPerSecUSec":"4s","TasksMax":"1024","RuntimeMaxUSec":"4h","ExecStart":format!("{{ path={PROGRAM} ; argv[]={PROGRAM} {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ; ignore_errors=no ; pid=3961564 }}")});
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
    fn tree() -> Value {
        json!({"scratch":{"apparent_bytes":RETAINED_SCRATCH,"physical_bytes":RETAINED_SCRATCH},"output":{"apparent_bytes":RETAINED_OUTPUT,"physical_bytes":RETAINED_OUTPUT},"metadata":{"apparent_bytes":METADATA,"physical_bytes":METADATA}})
    }
    #[test]
    fn future_difference_keeps_existing_bytes_and_guard() {
        let (d, m) = selection(BASE_DATA, BASE_MEMORY, &peer()).unwrap();
        assert_eq!(OLD_DATA, 549_890_031_616);
        assert_eq!(RETAINED_DATA, 68_920_803_328);
        assert_eq!(ENDED_DATA, 480_969_228_288);
        assert_eq!(d, 6_301_913_530_162);
        assert_eq!(m, 644_899_155_968);
        assert_eq!(ACTOR_MEMORY + GUARD_MEMORY - ACTOR_MEMORY, GUARD_MEMORY);
    }
    #[test]
    fn no_repeated_or_stale_selection() {
        for d in [
            BASE_DATA + 1,
            BASE_DATA + (256 << 20),
            BASE_DATA - ENDED_DATA,
        ] {
            assert!(selection(d, BASE_MEMORY, &peer()).is_err());
        }
        assert!(selection(BASE_DATA, BASE_MEMORY - ACTOR_MEMORY, &peer()).is_err());
    }
    #[test]
    fn raw_actor_guard_and_data_cannot_cross() {
        for (k, v) in [
            ("invocation_id", json!("5f4b7cb4621a4a2080fd9b083c14f5a0")),
            ("unit", json!(GUARD)),
            ("data_reservation_bytes", json!(RETAINED_DATA)),
            ("reserved_guard_memory_bytes", json!(0)),
            ("memory_max_bytes", json!(ACTOR_MEMORY)),
        ] {
            let mut p = peer();
            p[k] = v;
            assert!(selection(BASE_DATA, BASE_MEMORY, &p).is_err());
        }
    }
    #[test]
    fn started722_accepts_empty1530_or_failed74_do_not() {
        assert!(actor_policy(&actor()).is_ok());
        for (k, v) in [
            ("InvocationID", json!("5f4b7cb4621a4a2080fd9b083c14f5a0")),
            ("ExecMainPID", json!("0")),
            ("ExecMainStartTimestamp", json!("")),
            ("ExecMainStatus", json!("74")),
        ] {
            let mut a = actor();
            a[k] = v;
            assert!(actor_policy(&a).is_err());
        }
    }
    #[test]
    fn live_restarted_or_queued_actor_rejects() {
        for (k, v) in [
            ("MainPID", json!("3961564")),
            ("ControlPID", json!("7")),
            ("NRestarts", json!("1")),
            ("ActiveState", json!("active")),
            ("TriggeredBy", json!(TIMER)),
            ("WantedBy", json!("multi-user.target")),
            ("Job", json!("something")),
            ("DropInPaths", json!("/test/override.conf")),
        ] {
            let mut a = actor();
            a[k] = v;
            assert!(actor_policy(&a).is_err());
        }
    }
    #[test]
    fn genuine_stopped_timer_has_no_reverse_trigger_and_cannot_rearm() {
        let mut g=json!({"Id":GUARD,"LoadState":"loaded","ActiveState":"failed","SubState":"failed","MainPID":"0","ControlPID":"0","ControlGroup":"","NRestarts":"0","Job":"","Result":"exit-code","ExecMainStatus":"1","Restart":"no","Type":"oneshot","User":"root","Group":"root","MemoryMax":"268435456","MemorySwapMax":"0","CPUQuotaPerSecUSec":"1s","TasksMax":"256","TriggeredBy":"","DropInPaths":"","ExecStart":format!("argv[]={PROGRAM} guard {PLAN} --plan-sha256 {PLAN_SHA} --self-sha256 {PROGRAM_SHA} ; ignore_errors=no")});
        let mut t=json!({"Id":TIMER,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Triggers":GUARD,"Job":"","DropInPaths":""});
        assert!(guard_policy(&g,&t).is_ok());
        g["TriggeredBy"]=json!(TIMER);assert!(guard_policy(&g,&t).is_err());
        g["TriggeredBy"]=json!("");t["ActiveState"]=json!("active");assert!(guard_policy(&g,&t).is_err());
    }
    #[test]
    fn changed_runtime_or_second_command_rejects() {
        let mut a = actor();
        a["ExecStart"] = json!(
            string(&a, "ExecStart")
                .unwrap()
                .replace(PROGRAM_SHA, "wrong")
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
    fn physical_and_apparent_caps_both_required() {
        assert!(retained_caps(&tree()).is_ok());
        for (k, c) in [
            ("scratch", RETAINED_SCRATCH),
            ("output", RETAINED_OUTPUT),
            ("metadata", METADATA),
        ] {
            for field in ["apparent_bytes", "physical_bytes"] {
                let mut t = tree();
                t[k][field] = json!(c + 1);
                assert!(retained_caps(&t).is_err());
            }
        }
    }
    #[test]
    fn missing_or_negative_retained_size_rejects() {
        let mut t = tree();
        t["scratch"]["physical_bytes"] = json!(null);
        assert!(retained_caps(&t).is_err());
        t["scratch"]["physical_bytes"] = json!(-1);
        assert!(retained_caps(&t).is_err());
    }
    #[test]
    fn path_ref_requires_component_boundary() {
        assert!(path_ref(b"/test/original722/file", b"/test/original722"));
        assert!(!path_ref(
            b"/test/original722-other/file",
            b"/test/original722"
        ));
    }
    #[test]
    fn typed_unit_object_has_exact_escaped_name() {
        assert_eq!(
            unit_object("a-b.service"),
            "/org/freedesktop/systemd1/unit/a_2db_2eservice"
        );
    }
}

#[cfg(test)]
mod native_scanner_controls {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    struct Temp(PathBuf);
    impl Temp {
        fn new(label: &str) -> Self {
            assert_eq!(
                fs::metadata("/proc/self").unwrap().uid(),
                0,
                "separately booked Root native control"
            );
            let p = PathBuf::from(format!(
                "/tmp/old722-scanner-control-{label}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            fs::create_dir(&p).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
            Self(p)
        }
        fn scan(&self) -> R<Value> {
            let mut s = Scan::default();
            walk(
                &self.0,
                &self.0,
                fs::metadata(&self.0)?.dev(),
                0,
                &mut s,
                Instant::now(),
            )?;
            Ok(finish(s))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    #[ignore = "requires explicit Root native-control booking; real metadata syscalls and disjoint /tmp writes"]
    fn real_closed_tree_is_counted_and_symlink_or_shared_inode_rejects() {
        let t = Temp::new("links");
        let p = t.0.join("payload");
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        f.write_all(&[3; 8192]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let one = t.scan().unwrap();
        assert!(number(&one, "apparent_bytes").unwrap() >= 8192);
        assert!(number(&one, "physical_bytes").unwrap() >= 8192);
        symlink(&p, t.0.join("link")).unwrap();
        assert!(t.scan().is_err());
        fs::remove_file(t.0.join("link")).unwrap();
        fs::hard_link(&p, t.0.join("shared")).unwrap();
        assert!(t.scan().is_err());
    }
    #[test]
    #[ignore = "requires explicit Root native-control booking; verifies stable two-pass metadata contract"]
    fn real_growth_changes_digest_and_world_writable_entry_rejects() {
        let t = Temp::new("growth");
        let p = t.0.join("payload");
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&p)
            .unwrap();
        f.write_all(&[3; 8192]).unwrap();
        f.sync_all().unwrap();
        let first = t.scan().unwrap();
        f.write_all(&[4; 8192]).unwrap();
        f.sync_all().unwrap();
        let second = t.scan().unwrap();
        assert_ne!(first, second);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(t.scan().is_err());
    }
}
