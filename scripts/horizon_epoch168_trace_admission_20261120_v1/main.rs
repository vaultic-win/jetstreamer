//! One owner, one generation. The producer remains inside gate168 until actual guard
//! completion and an independent second complete host fit permit the trace payload.
mod fit;
mod launch;
mod staged;
use anyhow::{Context, Result, bail, ensure};
use guard168::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-trace-admission-20261120-v2/admission-v1";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const RETIRED: &str =
    "/var/lib/jetstreamer/local2-mismatch168-retirement-20261114-v1/epoch168/completion.json";
const RETIRED_SHA: &str = "02fa4339d22d77b7c1cfa97dcc1519a1f31ac190275e85cddc4dcd5568aff0a9";
const CAPTURE: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-trace-worker-build-20261120-v1/SOURCE_EXTRACTION_COMPLETE.json";
const CAPTURE_SHA: &str = "5eaa13bf58e7eca4df72ba29481973deec634aaecf04d83b9bdb30fd9aa0d3e9";
fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn read_root(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 64 << 20,
        "unsafe root member {}",
        path.display()
    );
    let mut data = Vec::new();
    f.take((64 << 20) + 1).read_to_end(&mut data)?;
    ensure!(data.len() as u64 == m.len(), "changed root member");
    Ok(data)
}
fn pinned(p: &Path, sha: &str) -> Result<Vec<u8>> {
    let b = read_root(p)?;
    ensure!(digest(&b) == sha, "digest {}", p.display());
    Ok(b)
}
fn json_pin(p: &Path, sha: &str) -> Result<Value> {
    Ok(serde_json::from_slice(&pinned(p, sha)?)?)
}
fn at<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn binding(p: &Path, sha: &str) -> Value {
    json!({"path":p,"sha256":sha})
}
fn record(dir: &Path, name: &str, v: &Value) -> Result<Value> {
    let mut data = serde_json::to_vec_pretty(v)?;
    data.push(b'\n');
    exclusive(&dir.join(name), &data, 0o400)?;
    Ok(binding(&dir.join(name), &digest(&data)))
}
fn exclusive(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p)?;
    f.write_all(data)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.sync_all()?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn run(prog: &str, args: &[String], deadline: Instant) -> Result<String> {
    // Only public status fields and bounded helper diagnostics enter this process.
    // stdout is read after completion; this route's commands have small, fixed outputs.
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "{} failed ({status})",
                Path::new(prog)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            );
            let mut text = String::new();
            child
                .stdout
                .take()
                .context("stdout")?
                .take(1 << 20)
                .read_to_string(&mut text)?;
            return Ok(text);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("bounded {} timed out", prog);
        }
        thread::sleep(Duration::from_millis(50));
    }
}
fn bounded() -> Instant {
    Instant::now() + Duration::from_secs(12)
}
fn show(unit: &str) -> Result<Value> {
    let fields = "Id,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,LoadState,Result,ExecMainStatus,Triggers,TriggeredBy";
    let args = vec!["show".into(), unit.into(), format!("--property={fields}")];
    let mut v = json!({});
    for l in run("/usr/bin/systemctl", &args, bounded())?.lines() {
        let (k, val) = l.split_once('=').context("native field")?;
        v[k] = json!(val);
    }
    ensure!(v["Id"] == unit, "unexpected native identity");
    Ok(v)
}
fn unused(unit: &str) -> Result<()> {
    let n = show(unit)?;
    ensure!(
        n["LoadState"] == "not-found"
            && n["ActiveState"] == "inactive"
            && n["Job"] == ""
            && n["InvocationID"] == "",
        "unit in use {unit}"
    );
    Ok(())
}
fn custody(path: &Path, uid: u32, gid: u32, ino: Option<u64>, mode: u32) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir()
            && path.canonicalize()? == path
            && m.uid() == uid
            && m.gid() == gid
            && m.mode() & 0o7777 == mode
            && m.dev() == fs::metadata("/home/sol")?.dev()
            && ino.is_none_or(|i| i == m.ino()),
        "directory custody {}",
        path.display()
    );
    Ok(())
}
fn child_stage() -> Result<()> {
    let dest = Path::new(DEST);
    let parent = dest.parent().context("nested parent")?;
    custody(Path::new(LANE), 1001, 1003, Some(103878482), 0o700)?;
    custody(parent, 1001, 1003, Some(103874598), 0o700)?;
    let pid = unsafe { libc::fork() };
    ensure!(pid >= 0, "fork staging");
    if pid == 0 {
        let ok = unsafe {
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setgid(1003) == 0
                && libc::setuid(1001) == 0
        };
        let created = ok
            && (|| -> Result<()> {
                custody(parent, 1001, 1003, Some(103874598), 0o700)?;
                fs::DirBuilder::new().mode(0o700).create(dest)?;
                exclusive(&dest.join("producer.log"), &[], 0o600)?;
                File::open(parent)?.sync_all()?;
                Ok(())
            })()
            .is_ok();
        unsafe {
            libc::_exit(if created { 0 } else { 1 });
        }
    }
    let mut status = 0;
    ensure!(
        unsafe { libc::waitpid(pid, &mut status, 0) } == pid
            && libc::WIFEXITED(status)
            && libc::WEXITSTATUS(status) == 0,
        "subtree or log already exists or failed staging"
    );
    custody(dest, 1001, 1003, None, 0o700)?;
    let log = fs::symlink_metadata(dest.join("producer.log"))?;
    ensure!(
        log.is_file()
            && log.len() == 0
            && log.uid() == 1001
            && log.gid() == 1003
            && log.mode() & 0o7777 == 0o600
            && log.nlink() == 1,
        "wrong log"
    );
    Ok(())
}
fn verify_inputs(seal_sha: &str, source: &str) -> Result<Value> {
    let pkg = Path::new(PACKAGE);
    ensure!(
        std::env::current_exe()? == pkg.join("admit168"),
        "unsealed launcher path"
    );
    let seal = json_pin(&pkg.join("deployment-seal-receipt.json"), seal_sha)?;
    ensure!(
        seal["destination"] == PACKAGE && seal["remote_mutations"] == false,
        "package seal"
    );
    let entries = seal["members"].as_array().context("members")?;
    let mut binaries = json!({});
    for name in ["admit168", "gate168", "artifact-proof.json"] {
        let matches: Vec<_> = entries.iter().filter(|e| e["name"] == name).collect();
        ensure!(matches.len() == 1, "missing or duplicate sealed {name}");
        let e = matches[0];
        let hash = at(e, "sha256")?;
        ensure!(
            e["mode"]
                == if name.ends_with(".json") {
                    "0444"
                } else {
                    "0555"
                },
            "wrong package mode"
        );
        let bytes = pinned(&pkg.join(name), hash)?;
        if name.ends_with(".json") {
            let proof: Value = serde_json::from_slice(&bytes)?;
            ensure!(
                proof["source_commit"] == source
                    && proof["source_contained_in_origin_account_updates"] == true
                    && proof["tests_passed"].as_u64().is_some_and(|n| n > 0)
                    && proof["tests_failed"] == 0,
                "source provenance"
            );
        }
        binaries[name] = json!(hash);
    }
    let payload = Path::new(PAYLOAD);
    let payload_dir = payload.parent().context("payload dir")?;
    let proof = json_pin(
        &payload_dir.join("artifact-proof.json"),
        "a56337c517ac9af0b9c9a517ffdcda5b68b1bb11f9ea50e27cfb49fbb0ba2835",
    )?;
    let ps = json_pin(
        &payload_dir.join("deployment-seal-receipt.json"),
        "bafaa75953bd07990283978551f7689ad6df7447266e51df7d175ad8c111365f",
    )?;
    ensure!(
        ps["destination"] == payload_dir.to_string_lossy().as_ref()
            && proof["source_commit"] == "62748cfc29f30e399607b1b7867a22b11595e27f"
            && proof["production"]["sha256"] == PAYLOAD_SHA,
        "payload lineage"
    );
    pinned(payload, PAYLOAD_SHA)?;
    pinned(Path::new(GUARD), GUARD_SHA)?;
    pinned(Path::new(SEALER), SEALER_SHA)?;
    let retired = json_pin(Path::new(RETIRED), RETIRED_SHA)?;
    let custody = &retired["scope"]["holding_original_completion"];
    json_pin(Path::new(at(custody, "path")?), at(custody, "sha256")?)?;
    ensure!(
        retired["source_name_absent"] == true
            && retired["scope"]["epoch"] == 168
            && retired["hard_promises_released_bytes"] == 0
            && retired["resource_credit_bytes"] == 0,
        "retired local2 lineage"
    );
    ensure!(
        matches!(fs::symlink_metadata(Path::new(at(&retired["scope"],"source")?)), Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "retired original reappeared"
    );
    let capture = json_pin(Path::new(CAPTURE), CAPTURE_SHA)?;
    for key in ["output", "bootstrap"] {
        let b = &capture[key];
        let p = Path::new(at(b, "path")?); // bootstrap census is owned by sol; authenticate its pinned bytes.
        let bytes = fs::read(p)?;
        ensure!(digest(&bytes) == at(b, "sha256")?, "capture output binding");
    }
    Ok(
        json!({"controller_seal":seal_sha,"controller_commit":source,"members":binaries,"payload_sha256":PAYLOAD_SHA,"guard_sha256":GUARD_SHA,"retired_local2":binding(Path::new(RETIRED),RETIRED_SHA),"source_capture":binding(Path::new(CAPTURE),CAPTURE_SHA)}),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 6
            && matches!(&*args[1], "--preflight" | "--launch"),
        "usage: admit168 --preflight|--launch FLEET FLEET_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT"
    );
    ensure!(
        args[3].len() == 64
            && args[4].len() == 64
            && args[5].len() == 40
            && args[3..6].iter().all(|v| v
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "invalid SHA"
    );
    unsafe { libc::umask(0o077) };
    let evidence = verify_inputs(&args[4], &args[5])?;
    let fleet = Path::new(&args[2]);
    let pre = fit::inspect(fleet, &args[3], None)?;
    if args[1] == "--preflight" {
        println!(
            "{}",
            json!({"fit":pre,"provenance":evidence,"launch_authorized":false})
        );
        return Ok(());
    }
    launch::launch(fleet, &args[3], evidence, pre)
}
