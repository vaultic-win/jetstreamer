//! Fresh replacement metadata adapter. These receipts are inputs, never permissions.
use super::*;
const NODE: &str = "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65";
const WORKER: &str = "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819";
const GUARD_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-original141-trace-guard-20261023-v1/jetstreamer-horizon-standalone-guard";
const GUARD_DIGEST: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const FLOOR: u64 = 6_264_131_239_730;
const LOCAL_RECIPE_IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-standard-replacement-recipes-20261110-v9/prepare";
const LOCAL_RECIPE_SHA: &str = "af7b5156db7637dd16ed8c100254434e9a3248e145e413d8f9ac411f2f80649c";
fn local_input_route(launch: &Value) -> R<bool> {
    let network = launch["fresh_effective_GCS_generation_probes_passed"] == true;
    let local = launch["input_acquisition"] == "sealed-local";
    need(
        network != local,
        "exactly one qualified input acquisition route",
    )?;
    if local {
        need(
            launch["fresh_effective_GCS_generation_probes_passed"] == false
                && launch["authentication_qualified"] == false
                && launch["qualified_local_input_validation_passed"] == true
                && hex(s(&launch["qualified_local_input_evidence"], "sha256")?, 64)
                && Path::new(s(&launch["qualified_local_input_evidence"], "path")?).is_absolute(),
            "local validation must not impersonate fresh GCS authentication",
        )?;
    }
    Ok(local)
}
fn local_preparation(launch: &Value, d: &Value, argv: &[String]) -> R<()> {
    let evidence = bound(&launch["qualified_local_input_evidence"])?;
    need(
        evidence["schema"] == "horizon-standard-local-input-native-preparation-acceptance-v1"
            && evidence["owner"] == "/root"
            && evidence["epoch"] == d["epoch"]
            && evidence["qualified_runtime"]["path"] == LOCAL_RECIPE_IMAGE
            && evidence["qualified_runtime"]["sha256"] == LOCAL_RECIPE_SHA
            && evidence["authentication_qualified"] == false,
        "exact qualified local recipe acceptance required",
    )?;
    need(
        sha(&raw(Path::new(LOCAL_RECIPE_IMAGE))?) == LOCAL_RECIPE_SHA,
        "local recipe image changed",
    )?;
    let prepared = bound(&evidence["preparation"])?;
    need(
        prepared["schema"] == "horizon-standard-replacement-recipe-preparation-v1"
            && prepared["owner"] == "/root"
            && prepared["epoch"] == d["epoch"]
            && prepared["replay_launched"] == false
            && prepared["resource_credit_bytes"] == 0
            && prepared["resource_promise_ending_bytes"] == 0
            && prepared["local_inputs"].is_object()
            && prepared["actual_full_lane_ledger"]["physical_bytes"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && prepared["genesis_stage"]["no_clobber"] == true
            && prepared["genesis_stage"]["gcloud_invoked"] == false,
        "genuine local CRC/MD5/SHA/ledger/genesis preparation required",
    )?;
    let execution = bound(&evidence["native_execution"])?;
    need(
        execution["code"] == 0
            && serde_json::from_str::<Value>(s(&execution, "stdout")?)? == evidence["preparation"],
        "successful original local preparation execution required",
    )?;
    let native_argv = bound(&evidence["native_argv"])?;
    let native = native_argv.as_array().ok_or("local execution argv")?;
    let expected = json!([
        LOCAL_RECIPE_IMAGE,
        prepared["plan"]["path"],
        "--plan-sha256",
        prepared["plan"]["sha256"],
        "--self-sha256",
        LOCAL_RECIPE_SHA,
        "--prepare"
    ]);
    need(
        native.len() >= 7
            && &native[native.len() - 7..] == expected.as_array().ok_or("local suffix")?.as_slice(),
        "actual normally sealed local recipe ABI differs",
    )?;
    let produced = prepared["producer_argv"]
        .as_array()
        .ok_or("prepared producer argv")?;
    let node = s(&launch["producer_command"], "path")?;
    let start = produced
        .iter()
        .position(|v| v == node)
        .ok_or("prepared exact node")?;
    let bootstrap_arg = format!(
        "--snapshot-archive={}",
        s(&prepared["local_inputs"]["bootstrap"], "path")?
    );
    need(
        &produced[start..]
            == launch["producer_command"]["argv"]
                .as_array()
                .ok_or("actual producer argv")?
                .as_slice()
            && argv.iter().any(|arg| arg == &bootstrap_arg),
        "actual producer differs from qualified local input recipe",
    )?;
    Ok(())
}
pub(super) fn utc(v: &str) -> R<u64> {
    let bytes = v.as_bytes();
    need(
        bytes.len() == 20
            && bytes[4] == b'-'
            && bytes[7] == b'-'
            && bytes[10] == b'T'
            && bytes[13] == b':'
            && bytes[16] == b':'
            && bytes[19] == b'Z',
        "exact UTC timestamp",
    )?;
    let digit = |a: usize, b: usize| -> R<u64> {
        need(bytes[a..b].iter().all(u8::is_ascii_digit), "UTC digits")?;
        Ok(std::str::from_utf8(&bytes[a..b])?.parse()?)
    };
    let year = digit(0, 4)?;
    let month = digit(5, 7)?;
    let day = digit(8, 10)?;
    let hour = digit(11, 13)?;
    let minute = digit(14, 16)?;
    let second = digit(17, 19)?;
    need(
        (2020..=2099).contains(&year)
            && (1..=12).contains(&month)
            && hour < 24
            && minute < 60
            && second < 60,
        "UTC bounds",
    )?;
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
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
    need(
        day > 0 && day <= lengths[month as usize - 1],
        "UTC calendar date",
    )?;
    let mut days = 0;
    for y in 1970..year {
        days += if leap(y) { 366 } else { 365 };
    }
    days += lengths[..month as usize - 1].iter().sum::<u64>() + day - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}
fn hex(v: &str, count: usize) -> bool {
    v.len() == count
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn named(v: &str, suffix: &str) -> bool {
    v.len() <= 255
        && v.ends_with(suffix)
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
}
pub(super) fn declarations(plan: &Value) -> R<Vec<Value>> {
    let entries = plan["replacement_owners"]
        .as_array()
        .ok_or("explicit replacements required")?;
    need(
        !entries.is_empty() && entries.len() <= 3,
        "one to three exact replacements",
    )?;
    let mut epochs = BTreeSet::new();
    let mut units = BTreeSet::new();
    let mut invocations = BTreeSet::new();
    for d in entries {
        let e = n(d, "epoch")?;
        need(
            (166..=168).contains(&e)
                && epochs.insert(e)
                && units.insert(s(d, "unit")?)
                && invocations.insert(s(d, "invocation_id")?),
            "duplicate or unsupported replacement",
        )?;
        need(
            named(s(d, "unit")?, ".service")
                && hex(s(d, "invocation_id")?, 32)
                && s(d, "main_pid")?.parse::<u64>().is_ok_and(|p| p > 0)
                && matches!(s(d, "phase")?, "bootstrap" | "replay"),
            "exact replacement identity/phase",
        )?;
        for key in [
            "admission",
            "guard_protection",
            "launch_proof",
            "phase_event",
            "first_guard_pid1_timer",
            "current_guard_pid1_timer",
        ] {
            let b = &d[key];
            need(
                Path::new(s(b, "path")?).is_absolute() && hex(s(b, "sha256")?, 64),
                "separately bound replacement evidence",
            )?;
        }
    }
    Ok(entries.clone())
}
fn command_identity(actual: &str, path: &str, argv: &[String]) -> R<()> {
    let inner = actual
        .strip_prefix("{ ")
        .and_then(|v| v.strip_suffix(" }"))
        .ok_or("single native command")?;
    let mut fields = BTreeMap::new();
    for member in inner.split(" ; ") {
        let (k, v) = member.split_once('=').ok_or("native command field")?;
        need(
            fields.insert(k, v).is_none(),
            "duplicate native command field",
        )?;
    }
    let expected = BTreeSet::from([
        "path",
        "argv[]",
        "ignore_errors",
        "start_time",
        "stop_time",
        "pid",
        "code",
        "status",
    ]);
    need(
        fields.keys().copied().collect::<BTreeSet<_>>() == expected
            && fields["path"] == path
            && fields["ignore_errors"] == "no"
            && fields["argv[]"]
                .split_whitespace()
                .eq(argv.iter().map(String::as_str)),
        "exact native executable/argv required",
    )
}
fn properties(unit: &str, fields: &str) -> R<Value> {
    unit_name(unit)?;
    let text = command(&["show", unit, "--no-pager", "-p", fields], 65536)?;
    let mut out = serde_json::Map::new();
    for row in text.lines() {
        let (k, v) = row.split_once('=').ok_or("native replacement delimiter")?;
        need(
            out.insert(k.into(), json!(v)).is_none(),
            "duplicate native replacement property",
        )?;
    }
    Ok(Value::Object(out))
}
fn native_producer(d: &Value) -> R<Value> {
    properties(
        s(d, "unit")?,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,ControlGroup,Job,Restart,MemoryHigh,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,ExecStart,ExecMainStartTimestamp,User,Group,WorkingDirectory,UMask,LimitNOFILE",
    )
}
fn timer(t: &Value, p: &Value) -> R<()> {
    need(
        t["Id"] == p["timer_unit"]
            && t["InvocationID"] == p["timer_invocation_id"]
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && matches!(
                t["SubState"].as_str(),
                Some("waiting" | "running" | "elapsed")
            )
            && t["Triggers"] == p["guard_unit"]
            && t["Job"] == "",
        "exact protective timer not armed",
    )
}
fn sample(g: &Value, p: &Value, d: &Value, guard_plan: &Value, at: u64, current: bool) -> R<()> {
    let when = n(g, "recorded_unix_seconds")?;
    need(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == GUARD_DIGEST
            && g["plan_sha256"] == p["plan"]["sha256"]
            && g["producer_invocation_id"] == d["invocation_id"]
            && g["producer"]["invocation_id"] == d["invocation_id"]
            && g["producer"]["pid"].as_u64() == s(d, "main_pid")?.parse::<u64>().ok()
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g.get("trip_reason") == Some(&Value::Null)
            && g.get("worker_observation_error") == Some(&Value::Null)
            && g.get("root_physical_observation_error") == Some(&Value::Null)
            && g["scratch_deleted"] == false
            && g["minimum_free_bytes"] == guard_plan["minimum_free_bytes"]
            && g["maximum_root_physical_bytes"] == 309_237_645_312u64
            && g["maximum_worker_vmas"] == 3_500_000
            && n(g, "available_bytes")? >= n(g, "minimum_free_bytes")?
            && when >= n(d, "original_start_unix_seconds")?
            && when <= at,
        "genuine exact replacement no-trip guard sample",
    )?;
    if current {
        need(at - when <= 45, "current replacement guard is stale")?;
    }
    Ok(())
}
fn proof(v: &Value, g: &Value, p: &Value, d: &Value, current: bool) -> R<()> {
    let id = s(g, "guard_invocation_id")?;
    let service = &v["guard_service"];
    need(
        hex(id, 32)
            && service["Id"] == p["guard_unit"]
            && service["InvocationID"] == id
            && service["LoadState"] == "loaded"
            && service["ActiveState"] == "inactive"
            && service["SubState"] == "dead"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["NRestarts"] == "0"
            && service["Result"] == "success"
            && service["ExecMainStatus"] == "0"
            && service["Job"] == "",
        "genuine completed guard service required",
    )?;
    let rows = v["journal"]
        .as_array()
        .ok_or("original guard PID1 journal")?;
    let exact =
        |r: &&Value| r["_PID"] == "1" && r["UNIT"] == p["guard_unit"] && r["INVOCATION_ID"] == id;
    need(
        rows.iter()
            .filter(exact)
            .any(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            && rows.iter().filter(exact).any(|r| {
                r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" && r["JOB_RESULT"] == "done"
            }),
        "original PID1 successful guard lifecycle",
    )?;
    timer(&v["timer"], p)?;
    owner_matches(&v["actual_producer"], d)?;
    if !current {
        need(
            v["genuine_first_timer_driven_success"] == true
                && v["continuous_Root_supervision"] == true,
            "genuine first timer-driven guard proof required",
        )?;
    }
    Ok(())
}
fn process(pid: u64, expected: &Value, unit: &str) -> R<Value> {
    need(pid > 0, "positive replacement process")?;
    let base = format!("/proc/{pid}");
    let text = fs::read_to_string(format!("{base}/stat"))?;
    let tail = text
        .rsplit_once(") ")
        .ok_or("proc stat delimiter")?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    need(tail.len() >= 20, "complete proc stat")?;
    let ticks: u64 = tail[19].parse()?;
    let executable = fs::read_link(format!("{base}/exe"))?;
    let m = fs::metadata(format!("{base}/exe"))?;
    let cgroup = fs::read_to_string(format!("{base}/cgroup"))?;
    let cmdline = fs::read(format!("{base}/cmdline"))?;
    let actual = json!({"pid":pid,"start_ticks":ticks,"executable":executable,"executable_dev":m.dev(),"executable_ino":m.ino(),"executable_len":m.len(),"executable_mtime":m.mtime(),"executable_mtime_nsec":m.mtime_nsec(),"executable_ctime":m.ctime(),"executable_ctime_nsec":m.ctime_nsec(),"cmdline_sha256":sha(&cmdline),"cgroup_sha256":sha(cgroup.as_bytes())});
    need(
        actual == *expected
            && cgroup.lines().any(|line| {
                line.strip_prefix("0::")
                    .is_some_and(|v| v == format!("/system.slice/{unit}"))
            }),
        "live replacement PID/start/executable/argv/cgroup changed",
    )?;
    Ok(actual)
}
/// Pure envelope checks. Native readers separately bind these claims to the host.
pub(super) struct Envelope<'a> {
    pub d: &'a Value,
    pub a: &'a Value,
    pub p: &'a Value,
    pub launch: &'a Value,
    pub event: &'a Value,
    pub old: &'a Value,
    pub plan: &'a Value,
}
pub(super) fn envelope(input: &Envelope<'_>, clock: u64) -> R<()> {
    let Envelope {
        d,
        a,
        p,
        launch,
        event,
        old,
        plan,
    } = *input;
    need(
        d["unit"] != old["unit"] && d["invocation_id"] != old["original_invocation_id"],
        "original native identity may never be reused",
    )?;
    need(
        a["schema"] == "horizon-standard-replacement-admission-v1"
            && a["owner"] == "/root"
            && a["primary_thread"] == plan["primary_thread"]
            && a["epoch"] == d["epoch"]
            && a["producer_unit"] == d["unit"]
            && a["producer_invocation_id"] == d["invocation_id"]
            && a["producer_pid"].as_u64() == s(d, "main_pid")?.parse::<u64>().ok()
            && a["original_stop_event"] == plan["terminal_producer_event"]
            && a["fresh_admission_passed"] == true
            && a["all_existing_growth_and_floor_protected"] == true
            && a["all_prior_promises_retained"] == true
            && a["old_partial_and_inputs_preserved"] == true
            && a["resource_credit_bytes"] == 0
            && a["memory_or_DATA_promise_ending_bytes"] == 0
            && a["node_sha256"] == NODE
            && a["worker_sha256"] == WORKER
            && a["candidate_hard_memory_bytes"] == 73_014_444_032u64
            && a["remote_mutations"] == false
            && a["r2_mutations"] == false
            && n(a, "guard_minimum_free_bytes")? >= FLOOR
            && n(a, "recorded_unix_seconds")? <= clock,
        "fresh exact Root admission with retained promises required",
    )?;
    need(
        p["schema"] == "horizon-standard-live-peer-protection-v1"
            && p["owner"] == "/root"
            && p["epoch"] == d["epoch"]
            && p["producer_unit"] == d["unit"]
            && p["producer_invocation_id"] == d["invocation_id"]
            && p["admission"] == d["admission"]
            && named(s(p, "guard_unit")?, ".service")
            && named(s(p, "timer_unit")?, ".timer")
            && hex(s(p, "timer_invocation_id")?, 32),
        "exact registered protection contract",
    )?;
    let start = n(d, "original_start_unix_seconds")?;
    need(
        n(a, "recorded_unix_seconds")? <= n(launch, "recorded_unix_seconds")?
            && launch["schema"] == "horizon-standard-replacement-native-launch-proof-v1"
            && launch["owner"] == "/root"
            && launch["primary_thread"] == plan["primary_thread"]
            && launch["admission"] == d["admission"]
            && launch["guard_protection"] == d["guard_protection"]
            && launch["original_stop_event"] == plan["terminal_producer_event"]
            && launch["source_start_unix_seconds"] == start
            && launch["source_start_native"] == d["original_start_native"]
            && launch["exact_input_and_capability_gates_passed"] == true
            && local_input_route(launch).is_ok()
            && launch["old_partial_path"] == old["original_archive"]
            && launch["old_scratch_path"] == old["scratch"]
            && launch["old_output_rename_performed"] == false
            && launch["node_sha256"] == NODE
            && launch["worker_sha256"] == WORKER
            && n(launch, "recorded_unix_seconds")? <= clock
            && start <= n(launch, "recorded_unix_seconds")?,
        "genuine fresh input/native launch proof required",
    )?;
    for role in ["producer_before", "producer_after"] {
        owner_matches(&launch[role], d)?;
    }
    let root = Path::new(s(a, "lane_root")?);
    let run = Path::new(s(launch, "run_directory")?);
    let archive = Path::new(s(launch, "archive_path")?);
    need(
        root.is_absolute()
            && run.is_absolute()
            && run.starts_with(root)
            && run != root
            && archive.starts_with(run)
            && archive != Path::new(s(old, "original_archive")?)
            && s(launch, "scratch_path")? != s(old, "scratch")?,
        "fresh isolated paths must preserve every old output path",
    )?;
    need(
        event["schema"] == "horizon-standard-replacement-phase-event-v1"
            && event["owner"] == "/root"
            && event["primary_thread"] == plan["primary_thread"]
            && event["epoch"] == d["epoch"]
            && event["phase"] == d["phase"]
            && event["admission"] == d["admission"]
            && event["launch_proof"] == d["launch_proof"]
            && event["guard_protection"] == d["guard_protection"]
            && event["source_start_unix_seconds"] == start
            && event["source_log"]["stdout_append_binding_verified"] == true
            && event["source_log"]["producer_invocation_id"] == d["invocation_id"]
            && event["no_new_resource_sample"] == true
            && event["replay_launch_authorized"] == false
            && n(event, "recorded_unix_seconds")? >= n(launch, "recorded_unix_seconds")?
            && n(event, "recorded_unix_seconds")? <= clock,
        "source-bound actual phase handoff required",
    )?;
    for role in ["producer_before", "producer_after"] {
        owner_matches(&event[role], d)?;
    }
    if d["phase"] == "bootstrap" {
        let lifetime = n(d, "maximum_bootstrap_seconds")?;
        need(
            lifetime > 0
                && lifetime <= 3600
                && n(d, "bootstrap_deadline_unix_seconds")?
                    == start
                        .checked_add(lifetime)
                        .ok_or("bootstrap deadline overflow")?
                && clock >= start
                && clock <= n(d, "bootstrap_deadline_unix_seconds")?
                && event["transaction_replay_claimed"] == false
                && event["latest_target_progress"].is_null(),
            "bootstrap deadline may never reset or imply replay",
        )?;
    } else {
        need(
            event["transaction_replay_claimed"] == true
                && n(&event["latest_target_progress"], "transactions")? > 0
                && n(&event["latest_target_progress"], "epoch")? == n(d, "epoch")?
                && n(&event["latest_target_progress"], "recorded_unix_seconds")? >= start
                && n(&event["latest_target_progress"], "recorded_unix_seconds")?
                    <= n(event, "recorded_unix_seconds")?
                && launch["worker_identity"].is_object(),
            "actual target transactions and worker identity required",
        )?;
    }
    Ok(())
}
fn guard_native(p: &Value, d: &Value, gp: &Value) -> R<Value> {
    need(
        sha(&raw(Path::new(GUARD_IMAGE))?) == GUARD_DIGEST,
        "qualified guard image digest changed",
    )?;
    let unit = s(p, "guard_unit")?;
    let service = properties(
        unit,
        "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,Job,Restart,MemoryMax,MemorySwapMax,ExecStart",
    )?;
    need(
        service["Restart"] == "no"
            && service["MemoryMax"] == "1073741824"
            && service["MemorySwapMax"] == "0",
        "guard reserved profile changed",
    )?;
    let argv = vec![
        GUARD_IMAGE.into(),
        s(&p["plan"], "path")?.into(),
        "--plan-sha256".into(),
        s(&p["plan"], "sha256")?.into(),
        "--self-sha256".into(),
        GUARD_DIGEST.into(),
    ];
    command_identity(s(&service, "ExecStart")?, GUARD_IMAGE, &argv)?;
    let iid = s(&service, "InvocationID")?;
    need(hex(iid, 32), "actual completed guard invocation")?;
    let directory = Path::new(s(gp, "receipt_directory")?);
    need(
        directory.is_absolute()
            && directory.canonicalize()? == directory
            && !directory.join("stop-intent.json").try_exists()?
            && !directory.join("stop-completion.json").try_exists()?,
        "guard stop lifecycle has begun",
    )?;
    let path = directory.join(format!("sample-{iid}.json"));
    let bytes = raw(&path)?;
    let g: Value = serde_json::from_slice(&bytes)?;
    sample(&g, p, d, gp, now()?, true)?;
    let out = Command::new("/usr/bin/journalctl")
        .args([
            "--all",
            "--no-pager",
            "-ojson",
            "-u",
            unit,
            "_PID=1",
            &format!("INVOCATION_ID={iid}"),
        ])
        .output()?;
    need(
        out.status.success() && out.stderr.is_empty() && out.stdout.len() <= 1 << 20,
        "guard PID1 capture",
    )?;
    let journal = std::str::from_utf8(&out.stdout)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    let timer_now = properties(
        s(p, "timer_unit")?,
        "Id,LoadState,ActiveState,SubState,InvocationID,Triggers,Job",
    )?;
    let actual_producer = native(s(d, "unit")?)?;
    let observed = json!({"guard_service":service,"timer":timer_now,"actual_producer":actual_producer,"journal":journal});
    proof(&observed, &g, p, d, true)?;
    need(
        properties(
            unit,
            "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainStatus,Job,Restart,MemoryMax,MemorySwapMax,ExecStart",
        )? == service,
        "guard rolled during bounded capture; preserve failed attempt and retry in genuine quiet window",
    )?;
    Ok(
        json!({"native":observed,"receipt":{"path":path,"sha256":sha(&bytes)},"recorded_unix_seconds":n(&g,"recorded_unix_seconds")?}),
    )
}
pub(super) fn load(
    d: &Value,
    old: &Value,
    plan: &Value,
    obs: &Value,
    pr: &Value,
    clock: u64,
) -> R<Value> {
    let a = bound(&d["admission"])?;
    let p = bound(&d["guard_protection"])?;
    let launch = bound(&d["launch_proof"])?;
    let event = bound(&d["phase_event"])?;
    envelope(
        &Envelope {
            d,
            a: &a,
            p: &p,
            launch: &launch,
            event: &event,
            old,
            plan,
        },
        clock,
    )?;
    let gp = bound(&p["plan"])?;
    need(
        gp["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && gp["unit"] == d["unit"]
            && gp["invocation_id"] == d["invocation_id"]
            && gp["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && gp["worker_root"] == a["lane_root"]
            && gp["maximum_root_physical_bytes"] == 309_237_645_312u64
            && gp["maximum_worker_vmas"] == 3_500_000,
        "fresh replacement guard plan binding",
    )?;
    let first = bound(&p["first_guard_sample"])?;
    let fp = bound(&d["first_guard_pid1_timer"])?;
    let cp = bound(&d["current_guard_pid1_timer"])?;
    let current = bound(&cp["receipt"])?;
    need(
        fp["receipt"] == p["first_guard_sample"],
        "first sample/proof binding",
    )?;
    sample(&first, &p, d, &gp, clock, false)?;
    sample(&current, &p, d, &gp, clock, true)?;
    proof(&fp, &first, &p, d, false)?;
    proof(&cp, &current, &p, d, true)?;
    need(
        n(&first, "recorded_unix_seconds")? <= n(&launch, "recorded_unix_seconds")?
            && n(&first, "recorded_unix_seconds")?
                <= n(d, "original_start_unix_seconds")?
                    .checked_add(25)
                    .ok_or("first guard setup deadline overflow")?
            && n(&current, "recorded_unix_seconds")? >= n(&first, "recorded_unix_seconds")?,
        "first genuine guard must precede accepted launch completion",
    )?;
    let producer = native_producer(d)?;
    owner_matches(&producer, d)?;
    need(
        producer["Restart"] == "no"
            && producer["User"] == "sol"
            && producer["Group"] == "horizon"
            && producer["UMask"] == "0077"
            && producer["LimitNOFILE"] == "1048576"
            && producer["WorkingDirectory"] == launch["producer_working_directory"]
            && producer["MemoryHigh"] == "68719476736"
            && producer["MemoryMax"] == "73014444032"
            && producer["MemorySwapMax"] == "0"
            && producer["CPUQuotaPerSecUSec"] == "9s"
            && producer["TasksMax"] == "1024"
            && producer["ExecMainStartTimestamp"] == d["original_start_native"]
            && producer["Job"] == "",
        "exact unchanged qualified producer profile",
    )?;
    let argv = launch["producer_command"]["argv"]
        .as_array()
        .ok_or("exact launch argv")?
        .iter()
        .map(|v| v.as_str().map(String::from).ok_or("argv string"))
        .collect::<Result<Vec<_>, _>>()?;
    command_identity(
        s(&producer, "ExecStart")?,
        s(&launch["producer_command"], "path")?,
        &argv,
    )?;
    process(
        s(d, "main_pid")?.parse()?,
        &launch["producer_identity"],
        s(d, "unit")?,
    )?;
    if !launch["worker_identity"].is_null() {
        process(
            n(&launch["worker_identity"], "pid")?,
            &launch["worker_identity"],
            s(d, "unit")?,
        )?;
    }
    for key in [
        "exact_input_and_capability_evidence",
        "effective_GCS_generation_evidence",
        "manifest_evidence",
        "node_image_hash_evidence",
        "worker_image_hash_evidence",
    ] {
        if key != "effective_GCS_generation_evidence" || !local_input_route(&launch)? {
            bound(&launch[key])?;
        }
    }
    if local_input_route(&launch)? {
        local_preparation(&launch, d, &argv)?;
    }
    let manifest = bound(&launch["manifest_evidence"])?;
    let cohorts = manifest["manifest"]["verification_cohorts"]
        .as_array()
        .ok_or("exact accepted singleton manifest")?;
    need(
        cohorts.len() == 1
            && cohorts[0]["first_epoch"] == d["epoch"]
            && cohorts[0]["last_epoch"] == d["epoch"]
            && cohorts[0]["publish_through_epoch"] == d["epoch"]
            && cohorts[0]["runtime"] == "solana-v1.5.6"
            && manifest["manifest_fingerprint"] == launch["manifest_fingerprint"],
        "replacement must retain its exact singleton runtime/manifest lineage",
    )?;
    for (key, expected, identity) in [
        (
            "node_image_hash_evidence",
            NODE,
            &launch["producer_identity"],
        ),
        (
            "worker_image_hash_evidence",
            WORKER,
            &launch["worker_identity"],
        ),
    ] {
        let image = bound(&launch[key])?;
        need(
            image["schema"] == "horizon-standard-replacement-image-hash-proof-v1"
                && image["sha256"] == expected
                && image["stable_full_hash_passed"] == true,
            "stable actual node/worker image hash proof required",
        )?;
        if !identity.is_null() {
            need(
                image["path"] == identity["executable"]
                    && image["dev"] == identity["executable_dev"]
                    && image["ino"] == identity["executable_ino"]
                    && image["len"] == identity["executable_len"]
                    && image["mtime"] == identity["executable_mtime"]
                    && image["mtime_nsec"] == identity["executable_mtime_nsec"]
                    && image["ctime"] == identity["executable_ctime"]
                    && image["ctime_nsec"] == identity["executable_ctime_nsec"],
                "running executable metadata differs from accepted full image hash",
            )?;
        }
    }
    need(
        utc(s(&pr["after_status"], "sampled_at_utc")?)? >= n(&event, "recorded_unix_seconds")?,
        "replacement status may not predate its actual phase event",
    )?;
    let owner = &pr["owner_evidence"];
    need(
        owner["current_operator"] == "/root"
            && owner["actual_producer"]["InvocationID"] == d["invocation_id"]
            && owner["replacement_admission"] == d["admission"]
            && owner["replacement_launch_proof"] == d["launch_proof"]
            && owner["replacement_phase_event"] == d["phase_event"]
            && owner["guard_protection"] == d["guard_protection"]
            && pr["after_status"]["phase"]
                == if d["phase"] == "bootstrap" {
                    "verification"
                } else {
                    "replay"
                },
        "authenticated current replacement status owner",
    )?;
    let rows = obs["replays"]
        .as_array()
        .ok_or("observed replacement set")?;
    let matches = rows
        .iter()
        .filter(|row| {
            row["range"].as_str().and_then(|v| v.parse::<u64>().ok()) == d["epoch"].as_u64()
        })
        .collect::<Vec<_>>();
    need(matches.len() <= 1, "duplicate replacement observer claim")?;
    let in_sample = if let Some(row) = matches.first() {
        owner_identity_observation(row, d)?;
        need(
            n(d, "original_start_unix_seconds")? <= utc(s(obs, "recorded_at_utc")?)?,
            "owner cannot predate its start in the observation",
        )?;
        if d["phase"] == "replay" {
            owner_observation(row, d)?;
        } else {
            need(
                row["useful_work"]["matching_markers"] == 0 && row["useful_work"]["last"].is_null(),
                "bootstrap observation contains transaction replay",
            )?;
        }
        true
    } else {
        need(
            n(d, "original_start_unix_seconds")? > utc(s(obs, "recorded_at_utc")?)?
                && n(&event, "recorded_unix_seconds")? > utc(s(obs, "recorded_at_utc")?)?,
            "an owner absent from the sample needs a strictly later genuine launch/event",
        )?;
        false
    };
    let guard = guard_native(&p, d, &gp)?;
    Ok(
        json!({"epoch":d["epoch"],"phase":d["phase"],"declaration":d,"unit":native(s(d,"unit")?)?,"native_producer_profile":producer,"admission":d["admission"],"guard_protection":d["guard_protection"],"launch_proof":d["launch_proof"],"source_phase_event":d["phase_event"],"source_start_unix_seconds":d["original_start_unix_seconds"],"source_start_native":d["original_start_native"],"bootstrap_deadline_unix_seconds":if d["phase"] == "bootstrap"{d["bootstrap_deadline_unix_seconds"].clone()}else{Value::Null},"latest_target_progress":event["latest_target_progress"],"current_guard_capture":guard,"in_current_observer":in_sample,"measured_rate_claimed":false,"useful_transaction_replay":d["phase"] == "replay","scratch_path":launch["scratch_path"],"archive_path":launch["archive_path"],"run_directory":launch["run_directory"],"resource_credit_bytes":0,"replay_launch_authorized":false}),
    )
}
pub(super) fn finish(d: &Value, accepted: &Value) -> R<Value> {
    need(
        native_producer(d)? == accepted["native_producer_profile"],
        "replacement producer/profile changed during fleet review",
    )?;
    let p = bound(&d["guard_protection"])?;
    let gp = bound(&p["plan"])?;
    let launch = bound(&d["launch_proof"])?;
    let at = now()?;
    if d["phase"] == "bootstrap" {
        need(
            at <= n(d, "bootstrap_deadline_unix_seconds")?,
            "bootstrap lifetime expired during review",
        )?;
    }
    process(
        s(d, "main_pid")?.parse()?,
        &launch["producer_identity"],
        s(d, "unit")?,
    )?;
    if !launch["worker_identity"].is_null() {
        process(
            n(&launch["worker_identity"], "pid")?,
            &launch["worker_identity"],
            s(d, "unit")?,
        )?;
    }
    for key in [
        "admission",
        "guard_protection",
        "launch_proof",
        "phase_event",
        "first_guard_pid1_timer",
        "current_guard_pid1_timer",
    ] {
        bound(&d[key])?;
    }
    guard_native(&p, d, &gp)
}

#[cfg(test)]
#[path = "replacement_tests.rs"]
mod tests;
