//! One owner, one generation. The producer remains inside gate169 until actual guard
//! completion and an independent second complete host fit permit the trace payload.
#![recursion_limit = "384"]
mod fit;
#[path = "../horizon_guard_floor_margin_20261120_v1/floor.rs"]
mod guard_floor;
mod launch;
mod peers;
#[path = "retry2.rs"]
mod retry;
mod staged;
use anyhow::{Context, Result, bail, ensure};
use guard169::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PACKAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch169-focused-admission-20261120-v4/admission-v1";
const SEALER: &str = "/usr/local/lib/jetstreamer/horizon-deployment-sealer-umask-20261021-v1/jetstreamer-seal-deployment";
const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
mod inputs;
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
fn verify_inputs(seal_sha: &str, source: &str) -> Result<Value> {
    let pkg = Path::new(PACKAGE);
    ensure!(
        std::env::current_exe()? == pkg.join("admit169"),
        "unsealed launcher path"
    );
    let seal = json_pin(&pkg.join("deployment-seal-receipt.json"), seal_sha)?;
    ensure!(
        seal["destination"] == PACKAGE && seal["remote_mutations"] == false,
        "package seal"
    );
    let entries = seal["members"].as_array().context("members")?;
    let mut binaries = json!({});
    for name in ["admit169", "gate169", "focused169", "artifact-proof.json"] {
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
    let proof = json_pin(
        &pkg.join("artifact-proof.json"),
        at(&binaries, "artifact-proof.json")?,
    )?;
    for key in ["admit169", "gate169", "focused169"] {
        ensure!(
            proof["artifacts"][key] == binaries[key],
            "controller build/seal differs for {key}"
        );
    }
    let repo = "/home/sol/workspace/jetstreamer";
    let git = |argv: &[&str]| -> Result<String> {
        let mut args = vec![
            "--no-replace-objects".to_owned(),
            "-c".into(),
            format!("safe.directory={repo}"),
            "-C".into(),
            repo.into(),
        ];
        args.extend(argv.iter().map(|s| s.to_string()));
        run("/usr/bin/git", &args, bounded())
    };
    let tracked = git(&["rev-parse", "refs/remotes/origin/account-updates^{commit}"])?;
    let tip = tracked.trim();
    let observed = at(&proof, "observed_origin")?;
    ensure!(
        observed.len() == 40 && observed.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid observed origin"
    );
    ensure!(
        source != retry::OLD_SOURCE,
        "original controller cannot execute recovery"
    );
    git(&["merge-base", "--is-ancestor", retry::OLD_SOURCE, source])?;
    for commit in [
        source,
        "dead395c32e6c46d3f600eaffda9554b16123ec4",
        "061b47a6447c733771a12160ea52ee5f044e20a8",
    ] {
        git(&["merge-base", "--is-ancestor", commit, observed])?;
    }
    git(&["merge-base", "--is-ancestor", observed, tip])?;
    ensure!(
        git(&["rev-parse", &format!("{source}^{{tree}}")])?.trim() == at(&proof, "source_tree")?,
        "controller source tree differs"
    );
    inputs::failed_g1()?;
    inputs::existing_destination(Path::new(DEST))?;
    retry::cold()?;
    let extra = inputs::verify(&proof)?;
    pinned(Path::new(GUARD), GUARD_SHA)?;
    pinned(Path::new(SEALER), SEALER_SHA)?;
    Ok(
        json!({"controller_seal":seal_sha,"controller_commit":source,"members":binaries,"guard_sha256":GUARD_SHA,"signed_inputs":extra}),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--measure-replay-reservations" {
        ensure!(unsafe { libc::geteuid() } == 0, "privileged measurement required");
        let fleet = json_pin(Path::new(&args[2]), &args[3])?;
        println!("{}", fit::measure_replay_reservations(&fleet)?);
        return Ok(());
    }
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 6
            && matches!(&*args[1], "--preflight" | "--launch"),
        "usage: admit169 --preflight|--launch FLEET FLEET_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT"
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
    let _owner_lock = peers::admission_interlock()?;
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
