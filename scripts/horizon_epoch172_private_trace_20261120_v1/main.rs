//! One owner, one generation. The producer remains inside gate172 until actual guard
//! completion and an independent second complete host fit permit the trace payload.
#![recursion_limit = "384"]
mod closure;
mod fit;
#[path = "../horizon_guard_floor_margin_20261120_v1/floor.rs"]
mod guard_floor;
mod launch;
mod peers;
mod staged;
#[path = "../horizon_standard169_cpu_lease.rs"]
pub mod standard169_cpu_lease;
#[cfg(feature = "epoch171")]
#[path = "../horizon_standard169_lineage.rs"]
mod standard169_lineage;
#[cfg(feature = "epoch171")]
mod standard169_native;
#[cfg(feature = "epoch171")]
#[path = "../horizon_systemd_owned_mask.rs"]
pub mod systemd_owned_mask;
use anyhow::{Context, Result, bail, ensure};
use guard172::*;
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
    let (status, output) = run_status(prog, args, deadline)?;
    ensure!(status.success(), "{prog} failed ({status})");
    Ok(String::from_utf8(output)?)
}
fn run_status(
    prog: &str,
    args: &[String],
    deadline: Instant,
) -> Result<(std::process::ExitStatus, Vec<u8>)> {
    use std::os::{fd::OwnedFd, unix::net::UnixStream};
    const LIMIT: usize = 1 << 20;
    let (mut reader, writer) = UnixStream::pair()?;
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .spawn()?;
    let result = (|| {
        let mut output = Vec::new();
        let mut chunk = [0; 16 * 1024];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            ensure!(!remaining.is_zero(), "bounded {prog} timed out");
            reader.set_read_timeout(Some(remaining))?;
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    ensure!(
                        output.len() + n <= LIMIT,
                        "{prog} output exceeded {LIMIT} bytes"
                    );
                    output.extend_from_slice(&chunk[..n]);
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    return Err(err).with_context(|| format!("reading bounded {prog} output"));
                }
            }
        }
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok((status, output));
            }
            ensure!(Instant::now() < deadline, "bounded {prog} timed out");
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
        child.wait()?;
    }
    result
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
    custody(Path::new(LANE), 1001, 1003, Some(LANE_INO), 0o700)?;
    custody(parent, 1001, 1003, Some(PARENT_INO), 0o700)?;
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
                custody(parent, 1001, 1003, Some(PARENT_INO), 0o700)?;
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
        std::env::current_exe()? == pkg.join(ADMIT),
        "unsealed launcher path"
    );
    let seal = json_pin(&pkg.join("deployment-seal-receipt.json"), seal_sha)?;
    ensure!(
        seal["destination"] == PACKAGE && seal["remote_mutations"] == false,
        "package seal"
    );
    let entries = seal["members"].as_array().context("members")?;
    let mut binaries = json!({});
    for name in [ADMIT, GATE, TRACE, "artifact-proof.json"] {
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
    if EPOCH == 171 {
        ensure!(
            proof["controller_cargo_features"] == json!(["epoch171"]),
            "controller not built for 171"
        );
    }
    for key in [ADMIT, GATE, TRACE] {
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
    for commit in [source, WORKER_SOURCE] {
        git(&["merge-base", "--is-ancestor", commit, observed])?;
    }
    git(&["merge-base", "--is-ancestor", observed, tip])?;
    ensure!(
        git(&["rev-parse", &format!("{source}^{{tree}}")])?.trim() == at(&proof, "source_tree")?,
        "controller source tree differs"
    );
    ensure!(
        git(&["rev-parse", &format!("{WORKER_SOURCE}^{{tree}}")])?.trim() == WORKER_TREE,
        "worker source tree differs"
    );
    let extra = inputs::verify(&proof)?;
    pinned(Path::new(GUARD), GUARD_SHA)?;
    pinned(Path::new(SEALER), SEALER_SHA)?;
    let retired = json_pin(Path::new(RETIRED), RETIRED_SHA)?;
    let custody = &retired["scope"]["holding_original_completion"];
    json_pin(Path::new(at(custody, "path")?), at(custody, "sha256")?)?;
    ensure!(
        retired["source_name_absent"] == true
            && retired["scope"]["epoch"] == EPOCH
            && retired["hard_promises_released_bytes"] == 0
            && retired["resource_credit_bytes"] == 0,
        "retired local2 lineage"
    );
    ensure!(
        matches!(fs::symlink_metadata(Path::new(at(&retired["scope"],"source")?)), Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "retired original reappeared"
    );
    Ok(
        json!({"controller_seal":seal_sha,"controller_commit":source,"members":binaries,"guard_sha256":GUARD_SHA,"retired_local2":binding(Path::new(RETIRED),RETIRED_SHA),"signed_inputs":extra}),
    )
}
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    #[cfg(feature = "epoch171")]
    if args
        .get(1)
        .is_some_and(|a| a == "--inspect-standard169-closure")
    {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 2,
            "usage: admit171 --inspect-standard169-closure"
        );
        let lock = standard169_native::OperationLock::acquire()?;
        println!("{}", standard169_native::inspect(&lock)?);
        return Ok(());
    }
    if args.get(1).is_some_and(|a| a == "--close") {
        ensure!(
            unsafe { libc::geteuid() } == 0 && args.len() == 5,
            "usage: admit --close ADMISSION_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT"
        );
        let provenance = verify_inputs(&args[3], &args[4])?;
        println!("{}", closure::collect(&args[2], provenance)?);
        return Ok(());
    }
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 6
            && matches!(&*args[1], "--preflight" | "--launch"),
        "usage: admit --preflight|--launch FLEET FLEET_SHA CONTROLLER_SEAL_SHA SOURCE_COMMIT"
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

#[cfg(test)]
mod output_tests {
    use super::*;
    #[test]
    fn drains_output_before_waiting_for_exit() {
        let args = ["-c", "262144", "/dev/zero"].map(String::from);
        let output = run("/usr/bin/head", &args, bounded()).unwrap();
        assert_eq!(output.len(), 262144);
    }

    #[test]
    fn rejects_incomplete_or_excessive_output() {
        let args = ["-c", "1048577", "/dev/zero"].map(String::from);
        assert!(run("/usr/bin/head", &args, bounded()).is_err());
        assert!(run("/usr/bin/false", &[], bounded()).is_err());
        assert!(
            run(
                "/usr/bin/sleep",
                &["2".into()],
                Instant::now() + Duration::from_millis(100)
            )
            .is_err()
        );
    }
}
