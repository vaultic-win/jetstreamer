//! Black-box native controls for the unchanged, normally sealed capture168.
//! This is a local synthetic fixture runner, never a source-acquisition tool.
mod fixture;
mod isolation;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
        process::ExitStatusExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Error = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, Error>;

fn ensure(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    file.set_permissions(Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(path.parent().ok_or("output parent")?)?.sync_all()?;
    Ok(())
}

fn json_new(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_new(path, &bytes)
}

fn directory(path: &Path) -> Result<()> {
    ensure(path.is_absolute(), "absolute fixture path required")?;
    let parent = path.parent().ok_or("fixture parent")?;
    ensure(parent.canonicalize()? == parent, "fixture parent alias")?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure(
        metadata.is_dir() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o700,
        "fixture directory must be root0700",
    )?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn immutable(path: &Path, expected: &str, maximum: u64) -> Result<Vec<u8>> {
    ensure(
        expected.len() == 64
            && expected
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "bound digest format",
    )?;
    ensure(
        path.is_absolute() && path.canonicalize()? == path,
        "bound path alias",
    )?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    ensure(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() > 0
            && before.len() <= maximum,
        "unsafe bound input",
    )?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.uid(),
            m.gid(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure(
        identity(&before) == identity(&after)
            && identity(&after) == identity(&named)
            && bytes.len() as u64 == before.len()
            && hash(&bytes) == expected,
        "bound input changed",
    )?;
    Ok(bytes)
}

struct Args {
    capture: PathBuf,
    capture_sha: String,
    funding: PathBuf,
    funding_sha: String,
    shim: PathBuf,
    shim_sha: String,
    output: PathBuf,
}

// Child::drop does not terminate or reap a process. Keep this guard alive until
// every fallible case observation has finished, including trace collection.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn arguments() -> Result<Args> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure(
        args.len() == 14,
        "usage: native-qualification --capture PATH --capture-sha256 HEX --funding PATH --funding-sha256 HEX --fault-image PATH --fault-sha256 HEX --output NEW_ABS_DIR",
    )?;
    let mut pairs = BTreeMap::new();
    for pair in args.as_chunks::<2>().0 {
        ensure(
            pairs.insert(pair[0].as_str(), pair[1].clone()).is_none(),
            "duplicate CLI key",
        )?;
    }
    let mut take = |name| {
        pairs
            .remove(name)
            .ok_or_else(|| -> Error { format!("missing CLI key {name}").into() })
    };
    let value = Args {
        capture: take("--capture")?.into(),
        capture_sha: take("--capture-sha256")?,
        funding: take("--funding")?.into(),
        funding_sha: take("--funding-sha256")?,
        shim: take("--fault-image")?.into(),
        shim_sha: take("--fault-sha256")?,
        output: take("--output")?.into(),
    };
    ensure(pairs.is_empty(), "unknown CLI key")?;
    ensure(
        !value
            .shim
            .to_string_lossy()
            .chars()
            .any(|c| c == ':' || c.is_whitespace()),
        "LD_PRELOAD fixture path has separators",
    )?;
    Ok(value)
}

// Deliberately serial, with a good baseline before any negative result can be
// counted. The actual socket timeout precedes the shortened deadline cases.
const CASES: &[&str] = &[
    "baseline",
    "wrong-self-digest",
    "wrong-plan-digest",
    "wrong-funding-digest",
    "foreign-url-field",
    "funding-not-accepted",
    "funding-expired",
    "funding-future",
    "funding-overlong",
    "symlink-plan",
    "occupied-output",
    "tls-untrusted",
    "tls-wrong-name",
    "head-weak-etag",
    "head-missing-etag",
    "head-duplicate-etag",
    "head-missing-length",
    "head-zero-length",
    "head-redirect",
    "range-http200",
    "range-http412",
    "range-redirect",
    "range-changed-etag",
    "range-duplicate-etag",
    "range-wrong-offset",
    "range-wrong-total",
    "range-wrong-length",
    "range-gzip",
    "range-chunked-overflow",
    "range-truncated",
    "range-version-disappears",
    "range-version-changes",
    "range-version-appears",
    "range-version-duplicates",
    "index-zero",
    "index-outside",
    "index-overflow",
    "index-header-overlap",
    "index-oversized",
    "header-nonminimal",
    "header-oversized",
    "header-varint-overflow",
    "header-zero",
    "header-truncated",
    "header-changes",
    "posthead-changed",
    "posthead-version-disappears",
    "proxy-ignored",
    "socket-timeout",
    "slot-write-enospc",
    "slot-fsync-eio",
    "marker-fsync-eio",
    "marker-kill",
    "marker-deadline",
    "marker-clock-regression",
];

fn expected_requests(case: &str) -> usize {
    match case {
        "baseline" | "proxy-ignored" | "posthead-version-disappears" => 8,
        "posthead-changed" => 7,
        "socket-timeout" | "slot-write-enospc" | "slot-fsync-eio" => 6,
        "header-changes" => 5,
        name if name.starts_with("marker-") => 8,
        name if name.starts_with("head-") => 1,
        name if name.starts_with("range-") => 3,
        name if name.starts_with("index-") => 5,
        name if name.starts_with("header-") => 4,
        _ => 0,
    }
}

fn positive(case: &str) -> bool {
    case == "baseline" || case == "proxy-ignored"
}
fn fault_mode(case: &str) -> bool {
    case.starts_with("marker-") || case == "slot-write-enospc" || case == "slot-fsync-eio"
}

fn expected_rejection(case: &str) -> Option<&'static str> {
    match case {
        "wrong-self-digest" | "wrong-plan-digest" | "wrong-funding-digest" => {
            Some("bound bytes changed")
        }
        "foreign-url-field" => Some("unknown or missing plan field"),
        "funding-not-accepted" => Some("capture funding/guard contract missing"),
        "funding-expired" | "funding-future" | "funding-overlong" => {
            Some("original capture funding clock expired")
        }
        "symlink-plan" => Some("noncanonical bound path"),
        "occupied-output" => Some("occupied output"),
        "head-weak-etag" => Some("strong representation ETag required"),
        "head-missing-etag"
        | "head-duplicate-etag"
        | "head-missing-length"
        | "range-duplicate-etag"
        | "range-version-duplicates" => Some("missing or duplicated response identity/header"),
        "head-zero-length" => Some("empty provider object"),
        "head-redirect" => Some("HEAD status/redirect differs"),
        "range-http200" | "range-http412" | "range-redirect" => {
            Some("exact range requires206 without redirects")
        }
        "range-changed-etag" | "range-wrong-offset" | "range-wrong-total"
        | "range-wrong-length" => Some("conditional response range/identity differs"),
        "range-gzip" => Some("encoded representation rejected"),
        "range-chunked-overflow" => Some("transfer encoded response rejected"),
        "range-version-disappears" | "range-version-changes" | "range-version-appears" => {
            Some("provider version headers changed/appeared/disappeared")
        }
        name if name.starts_with("index-") => Some("invalid/missing/oversized exact slot range"),
        "header-nonminimal" => Some("nonminimal CAR header varint"),
        "header-oversized" | "header-zero" => Some("CAR header size bound"),
        "header-varint-overflow" => Some("CAR header varint overflow"),
        "header-changes" => Some("header bytes changed between conditional requests"),
        "posthead-changed" | "posthead-version-disappears" => {
            Some("provider identity changed after capture")
        }
        "slot-write-enospc" => Some("os error 28"),
        "slot-fsync-eio" | "marker-fsync-eio" => Some("os error 5"),
        _ => None,
    }
}

fn verify_fixture_completion(output: &Path) -> Result<()> {
    let completion_bytes = fs::read(output.join("completion.json"))?;
    ensure(
        fs::read_to_string(output.join("COMPLETION.sha256"))?
            == format!("{}  completion.json\n", hash(&completion_bytes)),
        "actual fixture completion digest differs",
    )?;
    let completion: Value = serde_json::from_slice(&completion_bytes)?;
    ensure(
        completion["schema"] == "horizon168-capture-transport-completion-v1",
        "actual completion schema differs",
    )?;
    let members = completion["members"]
        .as_object()
        .ok_or("actual completion members absent")?;
    ensure(
        fs::read_dir(output)?.count() == members.len() + 2,
        "actual completion has missing or extra members",
    )?;
    for name in members
        .keys()
        .map(String::as_str)
        .chain(["completion.json", "COMPLETION.sha256"])
    {
        ensure(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "unsafe actual member name",
        )?;
        let metadata = fs::symlink_metadata(output.join(name))?;
        ensure(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o400,
            "completed fixture member custody differs",
        )?;
    }
    for (name, expected) in members {
        ensure(
            !name.is_empty() && !name.contains('/') && name != "." && name != "..",
            "unsafe actual member name",
        )?;
        let member = output.join(name);
        let metadata = fs::symlink_metadata(&member)?;
        ensure(
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.nlink() == 1
                && metadata.mode() & 0o7777 == 0o400,
            "completed fixture member custody differs",
        )?;
        let bytes = fs::read(member)?;
        ensure(
            expected["bytes"].as_u64() == Some(bytes.len() as u64)
                && expected["sha256"].as_str() == Some(hash(&bytes).as_str()),
            "completed fixture member readback differs",
        )?;
    }
    let input: Vec<u8> = [1u8, 0xa0].into_iter().chain(32u8..40).collect();
    ensure(
        fs::read(output.join("input.car"))? == input,
        "fixture capture changed original header/segment bytes",
    )?;
    ensure(
        !output.join("failure.json").exists(),
        "fixture positive case has failure.json",
    )?;
    let directory = fs::symlink_metadata(output)?;
    ensure(
        directory.is_dir() && directory.uid() == 0 && directory.mode() & 0o7777 == 0o700,
        "actual output directory custody differs",
    )?;
    Ok(())
}

fn run_case(
    args: &Args,
    certificates: &fixture::Certificates,
    root_funding: &Value,
    index: usize,
    case: &str,
) -> Result<Value> {
    let parent = args.output.join(format!("{index:02}-{case}"));
    directory(&parent)?;
    let output = parent.join("capture-output");
    let mut funding = root_funding.clone();
    let actual_deadline = root_funding["deadline_unix_millis"]
        .as_u64()
        .ok_or("original deadline absent")?;
    ensure(
        now()?
            .checked_add(45_000)
            .is_some_and(|n| n < actual_deadline),
        "insufficient original Root clock for next native control",
    )?;
    match case {
        "funding-not-accepted" => {
            funding["actual_capture_guard_and_allocation_accepted"] = json!(false)
        }
        "funding-expired" => {
            funding["not_before_unix_millis"] = json!(0);
            funding["deadline_unix_millis"] = json!(30_000);
        }
        "funding-future" => {
            let time = now()?;
            funding["not_before_unix_millis"] = json!(time + 100_000);
            funding["deadline_unix_millis"] = json!(time + 130_000);
        }
        "funding-overlong" => {
            let start = funding["not_before_unix_millis"]
                .as_u64()
                .ok_or("start absent")?;
            funding["deadline_unix_millis"] = json!(start + 900_001);
        }
        "marker-deadline" | "marker-clock-regression" => {
            // Only shorten Root's real interval; keep its original start and
            // every genuine ownership/capacity binding. Never renew a clock.
            let shortened = now()?.checked_add(4000).ok_or("clock overflow")?;
            let start = funding["not_before_unix_millis"]
                .as_u64()
                .ok_or("start absent")?;
            ensure(
                shortened < actual_deadline && shortened.saturating_sub(start) >= 30_000,
                "deadline fault requires 30 seconds of actual original interval elapsed",
            )?;
            funding["deadline_unix_millis"] = json!(shortened);
        }
        _ => (),
    }
    let funding_bytes = serde_json::to_vec_pretty(&funding)?;
    let funding_path = parent.join("funding.json");
    write_new(&funding_path, &funding_bytes)?;
    let funding_sha = if case == "wrong-funding-digest" {
        "0".repeat(64)
    } else {
        hash(&funding_bytes)
    };
    let mut plan = json!({"schema":"horizon168-exact-capture-plan-v1","output_directory":output,"current_funding":{"path":funding_path,"sha256":funding_sha}});
    if case == "foreign-url-field" {
        plan["url"] = json!("https://files.old-faithful.net/172/epoch-172.car");
    }
    let plan_bytes = serde_json::to_vec_pretty(&plan)?;
    let plan_path = parent.join("plan.json");
    write_new(&plan_path, &plan_bytes)?;
    let invoked_plan = if case == "symlink-plan" {
        let link = parent.join("symlink-plan.json");
        symlink(&plan_path, &link)?;
        link
    } else {
        plan_path.clone()
    };
    if case == "occupied-output" {
        directory(&output)?;
        write_new(
            &output.join("preserve-sentinel"),
            b"pre-existing output must survive",
        )?;
    }
    let plan_sha = if case == "wrong-plan-digest" {
        "0".repeat(64)
    } else {
        hash(&plan_bytes)
    };
    let self_sha = if case == "wrong-self-digest" {
        "0".repeat(64)
    } else {
        args.capture_sha.clone()
    };
    let server = fixture::Server::start(certificates, case)?;
    let stdout_path = parent.join("capture.stdout");
    let stderr_path = parent.join("capture.stderr");
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stdout_path)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stderr_path)?;
    let mut command = Command::new(&args.capture);
    command
        .env_clear()
        .env("LANG", "C")
        .arg(&invoked_plan)
        .arg("--plan-sha256")
        .arg(&plan_sha)
        .arg("--self-sha256")
        .arg(&self_sha)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    if case == "proxy-ignored" {
        command
            .env("HTTPS_PROXY", "http://127.0.0.1:444")
            .env("https_proxy", "http://127.0.0.1:444")
            .env("ALL_PROXY", "http://127.0.0.1:444");
    }
    if fault_mode(case) {
        command
            .env("LD_PRELOAD", &args.shim)
            .env("HORIZON168_NATIVE_FAULT", case)
            .env(
                "HORIZON168_NATIVE_DEADLINE_MS",
                funding["deadline_unix_millis"]
                    .as_u64()
                    .ok_or("fixture deadline")?
                    .to_string(),
            );
    }
    let started = now()?;
    let timer = Instant::now();
    let mut child = ChildGuard(command.spawn()?);
    let pid = child.0.id();
    let mut supervisor_killed = false;
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        if timer.elapsed() > Duration::from_secs(45) || now()? >= actual_deadline {
            supervisor_killed = true;
            child.0.kill()?;
            break child.0.wait()?;
        }
        thread::sleep(Duration::from_millis(10));
    };
    let elapsed_millis = timer.elapsed().as_millis();
    let ended = now()?;
    let trace = server.finish()?;
    File::open(&stdout_path)?.sync_all()?;
    File::open(&stderr_path)?.sync_all()?;
    let stderr_bytes = fs::read(&stderr_path)?;
    let stderr_text = String::from_utf8_lossy(&stderr_bytes);
    let marker = output.join("COMPLETION.sha256").exists();
    let failure_json = output.join("failure.json").exists();
    let mut failures = Vec::<String>::new();
    if supervisor_killed {
        failures.push(
            "supervisor had to kill the child; intended capture failure was not established".into(),
        );
    }
    if trace.requests.len() != expected_requests(case) {
        failures.push(format!(
            "expected {} requests; saw {}",
            expected_requests(case),
            trace.requests.len()
        ));
    }
    if !trace.fixture_errors.is_empty() {
        failures.push("fixture encountered unexpected requests or I/O failure".into());
    }
    if trace.proxy_connections != 0 {
        failures.push("capture used the forbidden proxy endpoint".into());
    }
    if !case.starts_with("tls-")
        && (trace.connections != trace.requests.len() || !trace.tls_errors.is_empty())
    {
        failures.push("unexpected extra connection or TLS failure; single-attempt transport was not established".into());
    }
    if positive(case) {
        if !status.success() {
            failures.push("positive transport control did not exit successfully".into());
        }
        if trace.requests.iter().any(|request| {
            request.write_error.is_some()
                || request.response_body_bytes_written != request.response_body_bytes
        }) {
            failures.push("positive fixture response was not fully written".into());
        }
        if ended >= funding["deadline_unix_millis"].as_u64().ok_or("deadline")? {
            failures.push("positive child exited after original deadline".into());
        }
        if let Err(error) = verify_fixture_completion(&output) {
            failures.push(error.to_string());
        }
    } else {
        if status.success() {
            failures.push("adversarial control was accepted by capture".into());
        }
        if case != "marker-kill"
            && (status.code() != Some(1) || !stderr_text.contains("exact168 capture rejected:"))
        {
            failures
                .push("negative control did not return the capture's normal rejection exit".into());
        }
        if expected_rejection(case).is_some_and(|message| !stderr_text.contains(message)) {
            failures
                .push("capture rejected for a different reason than the intended control".into());
        }
        if !case.starts_with("marker-") && marker {
            failures.push("ordinary rejection unexpectedly created a completion marker".into());
        }
        if (expected_requests(case) > 0 || case.starts_with("tls-"))
            && case != "marker-kill"
            && !failure_json
        {
            failures.push(
                "capture did not retain its failure.json after entering the transport path".into(),
            );
        }
        if case.starts_with("tls-") {
            if trace.connections != 1 || trace.tls_errors.is_empty() {
                failures.push("intended single-attempt TLS rejection was not exercised".into());
            }
        } else if fault_mode(case) {
            if !stderr_text.contains(&format!("epoch168-native-fault: {case}")) {
                failures.push("fault shim was not exercised at the intended member".into());
            }
            if stderr_text.contains("deadline-injection-not-exercised") {
                failures.push("deadline fault injection did not reach its intended timing".into());
            }
            if case.starts_with("marker-") && !marker {
                failures.push("marker control never reached actual marker creation".into());
            }
            if case == "marker-kill" && (status.signal() != Some(libc::SIGKILL) || failure_json) {
                failures.push("marker-kill did not preserve marker with actual SIGKILL and absent failure.json".into());
            }
            if case == "marker-clock-regression"
                && !stderr_text.contains("epoch168-native-fault: realtime-regressed")
            {
                failures.push("child realtime clock interception was not observed".into());
            }
            if matches!(case, "marker-deadline" | "marker-clock-regression")
                && (ended < funding["deadline_unix_millis"].as_u64().ok_or("deadline")?
                    || !stderr_text.contains("capture original deadline expired"))
            {
                failures.push(
                    "marker delay did not reach the intended original-deadline rejection".into(),
                );
            }
        } else if expected_requests(case) > 0 && !trace.fault_applied {
            failures.push("planned wire mutation was not sent".into());
        }
    }
    if case == "socket-timeout" && elapsed_millis < 29_000 {
        failures.push(
            "socket control failed before exercising the actual 30-second read timeout".into(),
        );
    }
    if case == "occupied-output"
        && fs::read(output.join("preserve-sentinel"))? != b"pre-existing output must survive"
    {
        failures.push("occupied output was changed".into());
    }
    let result = json!({
        "schema":"horizon168-native-fixture-control-v1","case":case,"passed":failures.is_empty(),"failures":failures,
        "fixture_only":true,"provider_source_bytes":false,"native_admission_receipt":false,"archive_publication_authorized":false,
        "capture_image":{"path":args.capture,"sha256":args.capture_sha},"root_funding":{"path":args.funding,"sha256":args.funding_sha},
        "invoked_plan":{"path":invoked_plan,"sha256_argument":plan_sha,"actual_sha256":hash(&plan_bytes)},
        "pid":pid,"started_unix_millis":started,"ended_unix_millis":ended,"monotonic_elapsed_millis":elapsed_millis,"exit_code":status.code(),"signal":status.signal(),
        "supervisor_killed":supervisor_killed,"marker_exists":marker,"failure_json_exists":failure_json,
        "stderr_sha256":hash(&stderr_bytes),"trace":trace,"resource_credit_bytes":0,"remote_operations":false,
    });
    json_new(&parent.join("control-result.json"), &result)?;
    Ok(result)
}

fn run() -> Result<()> {
    let args = arguments()?;
    ensure(
        unsafe { libc::geteuid() } == 0,
        "Root must invoke the qualified harness inside its actual admitted scope",
    )?;
    unsafe {
        libc::umask(0o077);
    }
    immutable(&args.capture, &args.capture_sha, 256 << 20)?;
    immutable(&args.shim, &args.shim_sha, 64 << 20)?;
    let funding_bytes = immutable(&args.funding, &args.funding_sha, 1 << 20)?;
    let funding: Value = serde_json::from_slice(&funding_bytes)?;
    ensure(
        funding["schema"] == "horizon168-exact-capture-funding-v1"
            && funding["owner"] == "/root"
            && funding["actual_capture_guard_and_allocation_accepted"] == true,
        "Root's actual funding contract required; harness never synthesizes acceptance",
    )?;
    let start = funding["not_before_unix_millis"]
        .as_u64()
        .ok_or("Root start")?;
    let deadline = funding["deadline_unix_millis"]
        .as_u64()
        .ok_or("Root deadline")?;
    let timestamp = now()?;
    ensure(
        start <= timestamp
            && deadline > timestamp.saturating_add(120_000)
            && deadline.saturating_sub(start) <= 900_000,
        "Root must provide an original finite interval with at least 120 seconds remaining",
    )?;
    directory(&args.output)?;
    write_new(&args.output.join("FIXTURE_ONLY_DO_NOT_ADMIT"), b"All bytes under this directory are local synthetic native controls, never provider source or admission receipts.\n")?;
    let trust = args.output.join("fixture-ca-store");
    directory(&trust)?;
    let certificates = fixture::Certificates::prepare(&trust)?;
    let hosts = args.output.join("fixture-hosts");
    write_new(
        &hosts,
        b"127.0.0.1 localhost files.old-faithful.net\n::1 localhost\n",
    )?;
    let namespaces_before =
        json!({"net":isolation::namespace_id("net")?,"mnt":isolation::namespace_id("mnt")?});
    isolation::enter(&hosts, &trust)?;
    let namespaces_after =
        json!({"net":isolation::namespace_id("net")?,"mnt":isolation::namespace_id("mnt")?});
    ensure(
        namespaces_before["net"] != namespaces_after["net"]
            && namespaces_before["mnt"] != namespaces_after["mnt"],
        "fresh fixture namespaces were not established",
    )?;
    json_new(
        &args.output.join("namespace-evidence.json"),
        &json!({"before":namespaces_before,"after":namespaces_after,"fixture_only":true,"production_image_unchanged":true,"private_hosts_sha256":hash(&fs::read(&hosts)?),"private_ca_sha256":hash(&fs::read(trust.join("ca-certificates.crt"))?)}),
    )?;
    let mut results = Vec::new();
    for (index, case) in CASES.iter().enumerate() {
        let result = match run_case(&args, &certificates, &funding, index, case) {
            Ok(result) => result,
            Err(error) => {
                results.push(json!({"case":case,"passed":false,"fixture_setup_or_observation_error":error.to_string(),"fixture_only":true,"native_admission_receipt":false}));
                // A fixture infrastructure failure is never a passing negative
                // control. Child/server RAII has drained actual work here.
                break;
            }
        };
        let passed = result["passed"] == true;
        results.push(result);
        // A bad baseline must never turn generic child failures into passing
        // negative controls. Preserve its actual evidence and stop immediately.
        if index == 0 && !passed {
            break;
        }
    }
    let passed = results.len() == CASES.len() && results.iter().all(|v| v["passed"] == true);
    json_new(
        &args.output.join("native-controls.json"),
        &json!({"schema":"horizon168-native-fixture-suite-v1","passed":passed,"expected_cases":CASES.len(),"actual_cases":results.len(),"cases":results,"fixture_only":true,"production_source_capture_accepted":false,"native_admission_receipt":false,"resource_credit_bytes":0,"replay_launch_authorized":false,"remote_mutations":false}),
    )?;
    ensure(
        passed,
        "native fixture controls failed; inspect retained actual child and wire evidence",
    )
}

fn main() {
    if let Err(error) = run() {
        eprintln!("epoch168 native qualification failed: {error}");
        std::process::exit(1);
    }
}
