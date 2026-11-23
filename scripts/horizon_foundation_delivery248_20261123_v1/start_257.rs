use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[path = "issue_257.rs"]
mod issuer;

const UNIT: &str = "horizon-qualify-257-singleton-v1.service";
const GUARD_UNIT: &str = "horizon-257-singleton-protective-v1.service";
const TIMER: &str = "horizon-257-singleton-protective-v1.timer";
const RETAIN: &str = "horizon257-singleton-terminal-retention-v1.target";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/qualification-257-singleton-v1";
const BOUND: &str = "/var/lib/jetstreamer/horizon257-full-guard-v1";
const TOKENS: &str = "/var/lib/jetstreamer/horizon257-full-tokens-v1";
const RECEIPTS: &str = "/var/lib/jetstreamer/horizon257-full-guard-receipts-v1";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20257118-v1/horizon251-standalone-guard";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const CAP: u64 = 516130089652;
const PERMIT: &str = "/var/lib/jetstreamer/horizon257-full-admission-after248-v1/admission.json";
const PROFILE: &str = "/var/lib/jetstreamer/horizon257-full-profile-v230-a1/profile.json";
const PROFILE_SHA: &str = "0f94cde65866edcf0ff777e557da2b8d61aea907673b5f82a9a6cd3486129bdc";
const MAIN: &str = "01a1f8f4-293b-7a91-a36e-2e7658bba721";
const LOCK: &str = "/run/horizon292-300-finite-v205-a1/issuer.lock";
const PEER_UNIT: &str = "horizon-qualify-261-singleton-v1.service";
const PEER_RECEIPTS: &str = "/var/lib/jetstreamer/horizon261-full-guard-receipts-v1";
const PEER_PLAN_SHA: &str = "4ea8544bf4c90d62918f085370d582faecdd147ab03553edb5be5682a185e498";
const PEER_CAP: u64 = 516_546_263_816;
const SHARED_DISK_FLOOR: u64 = 3_770_104_987_645;
const SHARED_MEMORY_OBLIGATION: u64 = 1_145_657_529_856;
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing number {k}"))
}
fn hash(p: &Path) -> Result<String> {
    let mut f = File::open(p)?;
    let mut h = Sha256::new();
    let mut b = [0; 65536];
    loop {
        let n = f.read(&mut b)?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
    }
    Ok(format!("{:x}", h.finalize()))
}
fn row<'a>(v: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str> {
    v.get(k)
        .map(String::as_str)
        .with_context(|| format!("missing native property {k}"))
}
fn closed(v: &BTreeMap<String, String>) -> Result<()> {
    let absent_service_properties =
        row(v, "LoadState")? == "not-found" || row(v, "Id")?.ends_with(".timer");
    for (key, zero) in [
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("ControlGroup", ""),
    ] {
        ensure!(
            v.get(key).map(String::as_str) == Some(zero)
                || (absent_service_properties && !v.contains_key(key)),
            "unit has live or unknown {key}"
        );
    }
    ensure!(
        matches!(row(v, "ActiveState")?, "inactive" | "failed") && row(v, "Job")?.is_empty(),
        "unit not drained"
    );
    Ok(())
}
fn iid(v: &str) -> bool {
    v.len() == 32
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn pre(v: &BTreeMap<String, String>, expected: &str) -> Result<u32> {
    ensure!(
        iid(expected)
            && row(v, "InvocationID")? == expected
            && row(v, "ActiveState")? == "activating"
            && row(v, "SubState")? == "start-pre"
            && row(v, "MainPID")? == "0"
            && row(v, "NRestarts")? == "0"
            && row(v, "Restart")? == "no"
            && row(v, "KillMode")? == "control-group"
            && row(v, "Delegate")? == "no",
        "producer left admitted start-pre"
    );
    Ok(row(v, "ControlPID")?.parse()?)
}
fn mount_options(mountinfo: &str, path: &str) -> Result<BTreeSet<String>> {
    let mut selected = None;
    for row in mountinfo.lines() {
        let f: Vec<_> = row.split_whitespace().collect();
        ensure!(f.len() >= 7, "bad mountinfo");
        let m = f[4];
        if (path == m || path.starts_with(&format!("{}/", m.trim_end_matches('/'))))
            && selected.as_ref().is_none_or(|(len, _)| *len < m.len())
        {
            selected = Some((m.len(), f[5].split(',').map(str::to_string).collect()));
        }
    }
    Ok(selected.context("no applicable mount")?.1)
}
fn validate_first_sample(
    s: &Value,
    a: &Value,
    id: &str,
    gid: &str,
    plan_sha: &str,
    started: u64,
) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && s["producer_invocation_id"] == id
            && s["guard_invocation_id"] == gid
            && s["producer_stop_enabled"] == true,
        "guard owner/stop policy mismatch"
    );
    ensure!(
        s["plan"] == format!("{BOUND}/guard-plan.json")
            && s["plan_sha256"] == plan_sha
            && s["guard_sha256"] == GUARD_SHA,
        "guard provenance differs"
    );
    ensure!(
        s["minimum_free_bytes"] == a["guard_minimum_free_bytes"]
            && s["maximum_root_physical_bytes"] == CAP
            && s["maximum_worker_vmas"] == 3500000,
        "guard envelope differs"
    );
    for k in [
        "trip_reason",
        "worker_observation_error",
        "root_physical_observation_error",
        "target_handoff_error",
        "canary_target_error",
    ] {
        ensure!(s.get(k) == Some(&Value::Null), "guard reported {k}");
    }
    ensure!(
        s["workers"] == json!([])
            && s["root_physical_observation"].is_null()
            && s["producer"]["pid"] == 0
            && s["producer"]["active"] == "activating"
            && s["producer"]["sub"] == "start-pre",
        "guard sampled useful work before token"
    );
    ensure!(
        number(s, "available_bytes")? >= number(a, "required_initial_free_bytes")?
            && number(s, "recorded_unix_seconds")? >= started,
        "guard free space/freshness failed"
    );
    Ok(())
}
fn guard_journal(raw: &[u8], id: &str) -> Result<Vec<Value>> {
    let rows: Vec<Value> = std::str::from_utf8(raw)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(
        !rows.is_empty() && rows.len() < 16,
        "guard PID1 journal count"
    );
    for r in &rows {
        ensure!(
            r["_PID"] == "1"
                && r["_UID"] == "0"
                && r["UNIT"] == GUARD_UNIT
                && r["INVOCATION_ID"] == id,
            "foreign guard journal identity"
        );
    }
    ensure!(
        rows.iter().any(|r| r["JOB_TYPE"] == "start"
            && r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.starts_with("Starting ")))
            && rows.iter().any(|r| r["MESSAGE"]
                .as_str()
                .is_some_and(|s| s.ends_with("Deactivated successfully.")))
            && rows.iter().any(|r| r["JOB_RESULT"] == "done"),
        "missing genuine PID1 guard lifecycle"
    );
    Ok(rows)
}
fn monotonic_us() -> Result<u64> {
    let mut v = std::mem::MaybeUninit::<libc::timespec>::uninit();
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, v.as_mut_ptr()) } == 0,
        "monotonic clock"
    );
    let v = unsafe { v.assume_init() };
    Ok(v.tv_sec as u64 * 1000000 + v.tv_nsec as u64 / 1000)
}
fn timer_deadline(bytes: &[u8], clock: u64) -> Result<u64> {
    let s = std::str::from_utf8(bytes)?;
    let words: Vec<_> = s.split_whitespace().collect();
    ensure!(
        words.len() == 2 && words[0] == "t",
        "wrong typed timer deadline"
    );
    let next = words[1].parse::<u64>()?;
    ensure!(
        next > clock + 5000000,
        "timer next fire lacks required budget"
    );
    Ok(next)
}
fn run(exe: &str, args: &[&str]) -> Result<String> {
    let o = Command::new("/usr/bin/timeout")
        .arg("--kill-after=1s")
        .arg("8s")
        .arg(exe)
        .args(args)
        .output()?;
    ensure!(
        o.status.success(),
        "{exe} failed: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(String::from_utf8(o.stdout)?)
}
fn show(u: &str) -> Result<BTreeMap<String, String>> {
    let fields = "Id,InvocationID,ActiveState,SubState,MainPID,ControlPID,ControlGroup,Result,NRestarts,Restart,Delegate,KillMode,Job,ExecMainStatus,Unit,LoadState,FragmentPath,DropInPaths,MemoryMax,MemorySwapMax,AllowedCPUs,Triggers";
    Ok(run("/usr/bin/systemctl", &["show", u, "-p", fields])?
        .lines()
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect())
}
fn read_json(p: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(p)?)?)
}
fn record(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(data)?;
    f.sync_all()?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn verify_parent(a: &Value) -> Result<()> {
    let pid = unsafe { libc::getppid() };
    let lock = fs::metadata(LOCK)?;
    let key = format!(
        "{:02x}:{:02x}:{}",
        libc::major(lock.dev()),
        libc::minor(lock.dev()),
        lock.ino()
    );
    let locked = fs::read_to_string("/proc/locks")?.lines().any(|row| {
        let cols: Vec<_> = row.split_whitespace().collect();
        cols.len() > 5
            && cols[1] == "FLOCK"
            && cols[3] == "WRITE"
            && cols[4] == pid.to_string()
            && cols[5] == key
    });
    ensure!(
        locked
            && a["issuer_pid"] == pid
            && a["controller"] == MAIN
            && std::env::var("CODEX_THREAD_ID")? == MAIN,
        "wrong issuer or controller"
    );
    ensure!(
        now()? < number(a, "expires_unix_seconds")? && now()? >= number(a, "issued_unix_seconds")?,
        "admission expired"
    );
    Ok(())
}
fn peer_disk_required(sample: &Value, iid: &str, now: u64, booked_physical: u64) -> Result<u64> {
    let recorded = number(sample, "recorded_unix_seconds")?;
    let root = &sample["root_physical_observation"];
    ensure!(
        sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && iid.len() == 32
            && sample["producer_invocation_id"] == iid
            && sample["producer"]["active"] == "active"
            && sample["producer"]["sub"] == "running"
            && sample["guard_sha256"] == GUARD_SHA
            && sample["plan_sha256"] == PEER_PLAN_SHA
            && sample["producer_stop_enabled"] == true
            && sample["trip_reason"].is_null()
            && sample["root_physical_observation_error"].is_null()
            && sample["minimum_free_bytes"] == SHARED_DISK_FLOOR
            && sample["maximum_root_physical_bytes"] == PEER_CAP
            && number(root, "maximum_physical_bytes")? == PEER_CAP
            && root["exceeds_budget"] == false
            && recorded <= now
            && now - recorded <= 150,
        "epoch 261 guard identity, storage envelope or freshness changed"
    );
    let pass = |key: &str| -> Result<u64> {
        let v = &root[key];
        ensure!(
            number(v, "vanished_entries")? == 0,
            "unstable epoch 261 root walk"
        );
        number(v, "physical_bytes")
    };
    let observed = pass("first")?.min(pass("second")?);
    ensure!(
        booked_physical > 0 && booked_physical <= PEER_CAP && observed <= PEER_CAP,
        "invalid epoch 261 allocated bytes"
    );
    Ok(SHARED_DISK_FLOOR + CAP + (PEER_CAP - booked_physical.min(observed)))
}

fn latest_peer_guard() -> Result<Value> {
    let mut latest = None;
    for entry in fs::read_dir(PEER_RECEIPTS)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|name| !name.starts_with("sample-") || !name.ends_with(".json"))
        {
            continue;
        }
        let metadata = entry.path().symlink_metadata()?;
        ensure!(
            metadata.is_file() && metadata.uid() == 0 && metadata.nlink() == 1,
            "unexpected peer receipt custody"
        );
        let timestamp = metadata.modified()?;
        if latest
            .as_ref()
            .is_none_or(|(clock, _, _)| timestamp > *clock)
        {
            latest = Some((timestamp, entry.path(), metadata));
        }
    }
    let (_, path, before) = latest.context("missing epoch 261 guard receipt")?;
    ensure!(before.len() <= 1 << 20, "oversized peer guard receipt");
    let value = read_json(&path)?;
    let after = path.symlink_metadata()?;
    ensure!(
        (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec()
        ) == (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec()
        ),
        "peer guard receipt changed"
    );
    Ok(value)
}

fn check_space(a: &Value) -> Result<()> {
    let available: u64 = run("/usr/bin/stat", &["-f", "-c", "%a %S", ROOT])?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<u64>, _>>()?
        .into_iter()
        .product();
    let booked = number(a, "peer261_allocated_bytes_lower_bound")?;
    let iid = text(&a["live_owners"], PEER_UNIT)?;
    let peer_required = peer_disk_required(&latest_peer_guard()?, iid, now()?, booked)?;
    ensure!(
        available >= number(a, "required_initial_free_bytes")?.max(peer_required),
        "insufficient free space after preserving epoch 261 growth"
    );
    let mem = fs::read_to_string("/proc/meminfo")?;
    let kb = mem
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .context("meminfo")?
        .split_whitespace()
        .nth(1)
        .context("memory")?
        .parse::<u64>()?;
    // The accepted donor exchange keeps the host's hard obligation unchanged.
    // Credit only actual anonymous pages of the surviving publishers and epoch 261.
    let mut resident = 0;
    for (u, i) in a["live_owners"].as_object().context("live owner roster")? {
        let prop = show(u)?;
        ensure!(
            prop["InvocationID"] == i.as_str().context("IID")?
                && prop["ActiveState"] == "active"
                && prop["SubState"] == "running"
                && prop["NRestarts"] == "0"
                && prop["MemorySwapMax"] == "0"
                && prop["Job"].is_empty(),
            "live owner {u} changed"
        );
        let cg = Path::new("/sys/fs/cgroup").join(prop["ControlGroup"].trim_start_matches('/'));
        let stat = fs::read_to_string(cg.join("memory.stat"))?;
        let anon = stat
            .lines()
            .find_map(|v| v.strip_prefix("anon "))
            .context("anon")?
            .parse::<u64>()?;
        resident += anon.min(prop["MemoryMax"].parse()?).min(
            fs::read_to_string(cg.join("memory.current"))?
                .trim()
                .parse()?,
        );
    }
    ensure!(
        kb * 1024 + resident >= SHARED_MEMORY_OBLIGATION,
        "hard growth no longer fits"
    );
    Ok(())
}
fn namespace(pid: u32, prof: &Value) -> Result<()> {
    let process = PathBuf::from(format!("/proc/{pid}"));
    let expected = fs::metadata("/usr/bin/sleep")?;
    let mut confirmed = false;
    for _ in 0..40 {
        let actual = fs::metadata(process.join("exe"))?;
        if (actual.dev(), actual.ino()) == (expected.dev(), expected.ino())
            && fs::read(process.join("cmdline"))? == b"/usr/bin/sleep\x0060\x00".as_slice()
        {
            confirmed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    ensure!(confirmed, "wrong sleep executable inode or arguments");
    let info = fs::read_to_string(process.join("mountinfo"))?;
    let inputs = read_json(Path::new(text(&prof["inputs"], "path")?))?;
    for key in [
        "node",
        "worker",
        "bootstrap",
        "slot_override",
        "range_table",
    ] {
        let path = text(&inputs[key], "path")?;
        let host = fs::metadata(path)?;
        let view = fs::metadata(process.join("root").join(path.trim_start_matches('/')))?;
        ensure!(
            (host.dev(), host.ino(), host.len()) == (view.dev(), view.ino(), view.len()),
            "different {key} in service namespace"
        );
    }
    for mount in inputs["cache_mounts"]
        .as_array()
        .context("index mounts")?
        .iter()
        .chain(std::iter::once(&inputs["genesis_mount"]))
    {
        let dest = format!("{ROOT}/output/{}", text(mount, "output_relative")?);
        let source = fs::metadata(text(mount, "source")?)?;
        let actual = fs::metadata(process.join("root").join(dest.trim_start_matches('/')))?;
        ensure!(
            (source.dev(), source.ino()) == (actual.dev(), actual.ino())
                && mount_options(&info, &dest)?.contains("ro"),
            "read-only input bind failed"
        );
    }
    ensure!(
        mount_options(&info, TOKENS)?.contains("ro") && mount_options(&info, ROOT)?.contains("rw"),
        "wrong token or scratch mount"
    );
    Ok(())
}
fn stable_static(a: &Value) -> Result<Value> {
    ensure!(
        hash(Path::new(PROFILE))? == PROFILE_SHA
            && a["profile_sha256"] == PROFILE_SHA
            && hash(Path::new(GUARD))? == GUARD_SHA,
        "changed image or profile"
    );
    let prof = read_json(Path::new(PROFILE))?;
    let seal = read_json(
        Path::new(PROFILE)
            .with_file_name("deployment-seal-receipt.json")
            .as_path(),
    )?;
    for unit in [UNIT, GUARD_UNIT, TIMER, RETAIN] {
        let member = seal["members"]
            .as_array()
            .context("members")?
            .iter()
            .find(|m| m["name"] == unit)
            .context("unit seal")?;
        let p = Path::new(PROFILE).with_file_name(unit);
        let m = show(unit)?;
        ensure!(
            hash(&p)? == text(member, "sha256")?
                && Path::new(&m["FragmentPath"]).canonicalize()? == p
                && m["DropInPaths"].is_empty(),
            "wrong {unit} definition"
        );
    }
    let peer = number(a, "peer261_allocated_bytes_lower_bound")?;
    ensure!(
        a["schema"] == "horizon257-full-admission-v1"
            && a["epoch"] == 257
            && a["root_cap_bytes"] == CAP
            && a["guard_minimum_free_bytes"] == SHARED_DISK_FLOOR
            && peer > 0
            && peer <= PEER_CAP
            && number(a, "required_initial_free_bytes")?
                == SHARED_DISK_FLOOR + CAP + (PEER_CAP - peer)
            && a["requested_memory_bytes"] == 173_207_977_984u64
            && a["hard_growth_before_live_residency"] == SHARED_MEMORY_OBLIGATION,
        "wrong funding envelope"
    );
    Ok(prof)
}
fn prepared_start(a: &Value) -> Result<Value> {
    let profile = stable_static(a)?;
    for dir in [BOUND, TOKENS, RECEIPTS] {
        ensure!(
            fs::read_dir(dir)?.next().is_none(),
            "consumed start destination {dir}"
        );
    }
    for u in [UNIT, GUARD_UNIT, TIMER] {
        closed(&show(u)?)?;
    }
    let mem = show(UNIT)?;
    ensure!(
        mem["AllowedCPUs"] == "32-39"
            && mem["MemoryMax"] == "171798691840"
            && mem["Restart"] == "no"
            && mem["MemorySwapMax"] == "0",
        "producer envelope"
    );
    let retained = show(RETAIN)?;
    ensure!(
        retained["ActiveState"] == "inactive" && retained["Job"].is_empty(),
        "retention changed"
    );
    Ok(profile)
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    if args.len() == 5 && matches!(args[1].as_str(), "inspect" | "issue") {
        return issuer::run(&args[1], Path::new(&args[2]), &args[3], &args[4]);
    }
    ensure!(
        args.len() == 3 && args[1] == "start",
        "expected start ADMISSION_SHA256 or inspect|issue CHECK_JSON CHECK_SHA256 SELF_SHA256"
    );
    let file = Path::new(PERMIT);
    let md = fs::symlink_metadata(file)?;
    ensure!(
        md.uid() == 0
            && md.mode() & 0o222 == 0
            && file.canonicalize()? == file
            && hash(file)? == args[2],
        "admission identity"
    );
    let a = read_json(file)?;
    verify_parent(&a)?;
    let prof = prepared_start(&a)?;
    check_space(&a)?;
    ensure!(
        hash(&std::env::current_exe()?)? == text(&a, "launcher_sha256")?,
        "wrong launcher"
    );
    let started = now()?;
    let clock = Instant::now();
    verify_parent(&a)?;
    run("/usr/bin/systemctl", &["start", "--no-block", UNIT])?;
    let p = show(UNIT)?;
    let id = &p["InvocationID"];
    let pid = pre(&p, id)?;
    ensure!(pid > 0, "no setup process");
    namespace(pid, &prof)?;
    let mut plan = read_json(Path::new(text(&prof["validation_plan"], "path")?))?;
    plan["minimum_free_bytes"] = a["guard_minimum_free_bytes"].clone();
    plan["invocation_id"] = json!(id);
    let gp = Path::new(BOUND).join("guard-plan.json");
    record(&gp, &serde_json::to_vec_pretty(&plan)?, 0o400)?;
    let gs = hash(&gp)?;
    record(
        &Path::new(BOUND).join("guard.env"),
        format!("HORIZON257_GUARD_PLAN_SHA256={gs}\n").as_bytes(),
        0o400,
    )?;
    let validation: Value = serde_json::from_str(&run(
        GUARD,
        &[
            gp.to_str().unwrap(),
            "--plan-sha256",
            &gs,
            "--self-sha256",
            GUARD_SHA,
            "--validate-plan-only",
        ],
    )?)?;
    ensure!(
        validation["validated"] == true && validation["producer_signaled"] == false,
        "guard rejected real plan"
    );
    pre(&show(UNIT)?, id)?;
    run("/usr/bin/systemctl", &["start", TIMER])?;
    let (g, gid, sample) = loop {
        let g = show(GUARD_UNIT)?;
        if let Some(gid) = g.get("InvocationID").filter(|s| iid(s)) {
            let path = Path::new(RECEIPTS).join(format!("sample-{gid}.json"));
            if g["ActiveState"] == "inactive" && path.is_file() {
                break (g.clone(), gid.clone(), path);
            }
        }
        ensure!(
            clock.elapsed() < Duration::from_secs(18),
            "missing successful first guard"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    ensure!(
        g["Result"] == "success"
            && g["ExecMainStatus"] == "0"
            && g["MainPID"] == "0"
            && g["ControlPID"] == "0"
            && g["Job"].is_empty(),
        "guard did not finish cleanly"
    );
    let t = show(TIMER)?;
    ensure!(
        t["ActiveState"] == "active"
            && t["SubState"] == "waiting"
            && t["Unit"] == GUARD_UNIT
            && iid(&t["InvocationID"]),
        "guard timer unarmed"
    );
    let sample_meta = fs::symlink_metadata(&sample)?;
    ensure!(
        sample_meta.is_file() && sample_meta.uid() == 0 && sample_meta.len() < 1 << 20,
        "invalid guard receipt"
    );
    let sample_value = read_json(&sample)?;
    validate_first_sample(&sample_value, &a, id, &gid, &gs, started)?;
    for e in fs::read_dir(RECEIPTS)? {
        ensure!(
            !e?.file_name().to_string_lossy().contains("stop"),
            "guard stop"
        );
    }
    let native = run(
        "/usr/bin/journalctl",
        &[
            "-b",
            "--no-pager",
            "-o",
            "json",
            "_PID=1",
            &format!("UNIT={GUARD_UNIT}"),
            &format!("INVOCATION_ID={gid}"),
        ],
    )?;
    guard_journal(native.as_bytes(), &gid)?;
    let obj = format!(
        "/org/freedesktop/systemd1/unit/{}",
        TIMER
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_string()
            } else {
                format!("_{:02x}", c as u32)
            })
            .collect::<String>()
    );
    let dead = run(
        "/usr/bin/busctl",
        &[
            "get-property",
            "org.freedesktop.systemd1",
            &obj,
            "org.freedesktop.systemd1.Timer",
            "NextElapseUSecMonotonic",
        ],
    )?;
    let next = timer_deadline(dead.as_bytes(), monotonic_us()?)?;
    check_space(&a)?;
    verify_parent(&a)?;
    ensure!(
        pre(&show(UNIT)?, id)? == pid && clock.elapsed() < Duration::from_secs(48),
        "prestart changed"
    );
    let evidence = file.parent().unwrap();
    record(
        &evidence.join("first-guard-journal.jsonl"),
        native.as_bytes(),
        0o400,
    )?;
    let token = json!({"schema":"horizon257-full-first-guard-v1","epoch":257,"unit":UNIT,"invocation_id":id,"guard_invocation_id":gid,"timer_invocation_id":t["InvocationID"],"sample":sample,"sample_sha256":hash(&sample)?,"guard_plan_sha256":gs,"guard_binary_sha256":GUARD_SHA,"admission":PERMIT,"admission_sha256":args[2],"next_guard_monotonic_us":next,"publication_authorized":false,"recorded_unix_seconds":now()?});
    let td = Path::new(TOKENS).join(id);
    fs::create_dir(&td)?;
    fs::set_permissions(&td, fs::Permissions::from_mode(0o755))?;
    let staged = td.join("first-fire.tmp");
    record(&staged, &serde_json::to_vec_pretty(&token)?, 0o444)?;
    verify_parent(&a)?;
    pre(&show(UNIT)?, id)?;
    ensure!(
        clock.elapsed() < Duration::from_secs(49),
        "setup deadline expired"
    );
    let dest = td.join("guard-admission.json");
    fs::hard_link(&staged, &dest)?;
    fs::remove_file(staged)?;
    File::open(&td)?.sync_all()?;
    record(
        &evidence.join("handoff.json"),
        &serde_json::to_vec_pretty(
            &json!({"token":dest,"token_sha256":hash(&dest)?,"producer":UNIT,"invocation_id":id,"guard_invocation_id":gid,"started_unix_seconds":started,"actual_first_guard":sample,"actual_first_guard_sha256":hash(&sample)?,"ready":false}),
        )?,
        0o400,
    )?;
    println!("accepted startup for epoch 257 invocation {id}, guard {gid}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    fn admission() -> Value {
        json!({"guard_minimum_free_bytes":3000000000000u64,"required_initial_free_bytes":3516130089652u64})
    }
    fn sample() -> Value {
        json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","producer_invocation_id":"a".repeat(32),"guard_invocation_id":"b".repeat(32),"producer_stop_enabled":true,"plan":format!("{BOUND}/guard-plan.json"),"plan_sha256":"c".repeat(64),"guard_sha256":GUARD_SHA,"minimum_free_bytes":3000000000000u64,"maximum_root_physical_bytes":CAP,"maximum_worker_vmas":3500000,"trip_reason":null,"worker_observation_error":null,"root_physical_observation_error":null,"target_handoff_error":null,"canary_target_error":null,"workers":[],"root_physical_observation":null,"producer":{"pid":0,"active":"activating","sub":"start-pre"},"available_bytes":4000000000000u64,"recorded_unix_seconds":1100})
    }
    #[test]
    fn genuine_first_sample() {
        validate_first_sample(
            &sample(),
            &admission(),
            &"a".repeat(32),
            &"b".repeat(32),
            &"c".repeat(64),
            1100,
        )
        .unwrap();
    }
    #[test]
    fn reject_old_owner_trip_early_worker_and_missing_checks() {
        for k in [
            "producer_invocation_id",
            "guard_invocation_id",
            "trip_reason",
            "root_physical_observation",
            "worker_observation_error",
        ] {
            let mut s = sample();
            s[k] = json!("wrong");
            assert!(
                validate_first_sample(
                    &s,
                    &admission(),
                    &"a".repeat(32),
                    &"b".repeat(32),
                    &"c".repeat(64),
                    1100
                )
                .is_err(),
                "{k}"
            );
        }
        let mut s = sample();
        s["producer"]["pid"] = json!(123);
        assert!(
            validate_first_sample(
                &s,
                &admission(),
                &"a".repeat(32),
                &"b".repeat(32),
                &"c".repeat(64),
                1100
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "reads the pinned Foundation epoch 261 guard evidence"]
    fn preserve_epoch_261_headroom_with_the_actual_guard_receipt() {
        let source = env::var("HORIZON_261_REFERENCE_GUARD").unwrap();
        let file = Path::new(&source);
        assert_eq!(
            hash(file).unwrap(),
            env::var("HORIZON_261_REFERENCE_GUARD_SHA256").unwrap()
        );
        let actual = read_json(file).unwrap();
        let clock = number(&actual, "recorded_unix_seconds").unwrap();
        let iid = text(&actual, "producer_invocation_id").unwrap();
        let physical = number(
            &actual["root_physical_observation"]["first"],
            "physical_bytes",
        )
        .unwrap()
        .min(
            number(
                &actual["root_physical_observation"]["second"],
                "physical_bytes",
            )
            .unwrap(),
        );
        let accepted = peer_disk_required(&actual, iid, clock, physical).unwrap();
        assert_eq!(accepted, SHARED_DISK_FLOOR + CAP + PEER_CAP - physical);
        assert_eq!(
            peer_disk_required(&actual, iid, clock, physical - 1).unwrap(),
            accepted + 1
        );
        assert!(peer_disk_required(&actual, iid, clock + 151, physical).is_err());
        let mut changed = actual.clone();
        changed["root_physical_observation"]["first"]["physical_bytes"] = json!(physical - 32);
        assert_eq!(
            peer_disk_required(&changed, iid, clock, physical).unwrap(),
            accepted + 32
        );
        changed["trip_reason"] = json!("anything is a failed guard");
        assert!(peer_disk_required(&changed, iid, clock, physical).is_err());
        assert!(peer_disk_required(&actual, &"0".repeat(32), clock, physical).is_err());
    }
}
