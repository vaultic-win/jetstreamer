//! Native per-epoch full/plugin receipt producer. Never publishes archives or R2.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    sha2::{Digest, Sha256},
    std::{
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::{Child, Command},
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum Stage {
    Full,
    Plugin,
}

fn milestone(p: &Plan, event: &str) -> Result<()> {
    eprintln!(
        "{}",
        serde_json::json!({"schema":"horizon-pair-verification-milestone-v1","epoch":p.epoch,"stage":p.stage.suffix(),"event":event,"unix_millis":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()})
    );
    Ok(())
}
impl Stage {
    fn suffix(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
        }
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    epoch: u64,
    stage: Stage,
    archive_directory: PathBuf,
    expected_archive_sha256: String,
    verifier: Bound,
    threads_per_command: usize,
    state_directory: PathBuf,
    #[serde(default)]
    admission_observer: Option<Bound>,
}

fn local191(p: &Plan) -> bool {
    p.schema == "horizon-verify-canonical-pair-dev-samjohnson191-v1"
}
fn local(p: &Plan) -> bool {
    local191(p) || p.schema == "horizon-verify-canonical-pair-dev-samjohnson198-v1"
}
fn validate_plan(p: &Plan) -> Result<()> {
    let local198 = p.schema == "horizon-verify-canonical-pair-dev-samjohnson198-v1";
    ensure!(
        local(p) || p.schema == "horizon-verify-canonical-pair-plan-v1",
        "wrong schema"
    );
    ensure!(
        if local198 {
            p.epoch == 198
        } else if local191(p) {
            (191..=194).contains(&p.epoch)
        } else {
            (201..=300).contains(&p.epoch)
        },
        "epoch outside assigned campaign"
    );
    ensure!(
        (1..=32).contains(&p.threads_per_command),
        "unbounded threads"
    );
    ensure!(
        evidence::is_sha(&p.expected_archive_sha256),
        "invalid archive digest"
    );
    ensure!(
        p.archive_directory
            == Path::new(if local(p) {
                "/home/sol/horizon"
            } else {
                "/home/ubuntu/horizon"
            }),
        "foreign archive directory"
    );
    if local(p) {
        ensure!(
            p.admission_observer.is_some(),
            "epoch 198 requires fresh coordinated admission evidence"
        );
        let state = if local198 {
            PathBuf::from(
                "/var/lib/jetstreamer/horizon-epoch198-canonical-verification-20261021-v1",
            )
        } else {
            Path::new("/var/lib/jetstreamer/horizon-cohort191-canonical-verification-20261023-v1")
                .join(format!("epoch-{}", p.epoch))
        };
        ensure!(
            (!local198
                || p.expected_archive_sha256
                    == "4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb")
                && p.threads_per_command <= 16
                && p.state_directory == state.join(p.stage.suffix()),
            "foreign local archive or verifier state"
        );
        let (name, digest) = match p.stage {
            Stage::Full => (
                "verify_archive",
                "5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574",
            ),
            Stage::Plugin => (
                "horizon_pipeline",
                "e20892a111f8e26c8e25561a939eaf171771789753059100510c936d92092137",
            ),
        };
        ensure!(
            p.verifier.path
                == Path::new(
                    "/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1"
                )
                .join(name)
                && p.verifier.sha256 == digest,
            "epoch 198 requires the qualified exact verifier"
        );
    }
    ensure!(
        p.state_directory.is_absolute()
            && !p.state_directory.starts_with(&p.archive_directory)
            && p.verifier.path.is_absolute(),
        "unsafe verification paths"
    );
    ensure!(
        p.verifier.path.file_name().and_then(|s| s.to_str())
            == Some(match p.stage {
                Stage::Full => "verify_archive",
                Stage::Plugin => "horizon_pipeline",
            }),
        "wrong verifier executable for stage"
    );
    Ok(())
}

fn verifier_size_limit(stage: Stage) -> u64 {
    match stage {
        Stage::Full => 128 * 1024 * 1024,
        Stage::Plugin => 512 * 1024 * 1024,
    }
}

fn utc_seconds(value: &str) -> Result<u64> {
    let input = std::ffi::CString::new(value)?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(input.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(
        !end.is_null() && unsafe { *end } == 0,
        "invalid observer clock"
    );
    let seconds = unsafe { libc::timegm(&mut tm) };
    let canonical = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );
    ensure!(
        seconds >= 0 && canonical == value,
        "noncanonical observer clock"
    );
    Ok(seconds as u64)
}

fn admission_value(v: &serde_json::Value, now: u64) -> Result<()> {
    let time = utc_seconds(v["recorded_at_utc"].as_str().context("observer time")?)?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && time <= now
            && now - time <= 900
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= 4_740_696_923_590 + (32 << 20))
            && v["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 192 * 1024 * 1024),
        "fresh observer does not admit the combined two 64 GiB verifier services plus 64 GiB reserve or protected disk claims"
    );
    let replays = v["replays"].as_array().context("admission replay census")?;
    let expected = [
        "1a7e8cde872b45f786979150d5639ab4",
        "518ff0bf0bbb4413a155a63f95907163",
        "f3ec98a134d544e78cb2083f502ed292",
        "ea93199ed2fa470d99de248c2a10b246",
    ];
    ensure!(
        replays.len() == expected.len()
            && expected.iter().all(|iid| replays
                .iter()
                .filter(|r| r["producer_after"]["invocation_id"] == *iid)
                .count()
                == 1)
            && replays
                .iter()
                .all(|r| r["invocation_binding_stable"] == true),
        "protected replay claims differ from admitted fleet"
    );
    Ok(())
}

// A191 verifier makes two independent scans with the already qualified large-
// frame reader. This is a fresh verifier envelope, never replay admission or
// evidence that any 191 archive has passed either check.
// The 1 TiB scalar below is only the read-only service floor. It does not
// prove live growth reservations fit, reduce a replay guard/century floor, or
// replace the dispatcher's independently bound capacity and compiler claims.
fn admission191_value(v: &serde_json::Value, now: u64) -> Result<()> {
    let time = utc_seconds(
        v["recorded_at_utc"]
            .as_str()
            .context("191 admission time")?,
    )?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && time <= now
            && now - time <= 900
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 128 * 1024 * 1024)
            && v["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= (1024u64 << 30) + (32 << 20)),
        "191 verifier admission is stale or lacks one 64 GiB verifier plus 64 GiB reserve or read-only service disk floor"
    );
    let replays = v["replays"]
        .as_array()
        .context("191 protected replay census")?;
    ensure!(
        !replays.is_empty()
            && replays
                .iter()
                .all(|r| r["invocation_binding_stable"] == true),
        "191 protected replay owner changed"
    );
    for flag in [
        "producer_or_controller_signals_sent",
        "service_state_changed",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v["mutation"][flag] == false,
            "191 admission is not observational"
        );
    }
    Ok(())
}
fn gate_name(name: &str) -> bool {
    [191, 192, 193, 194, 198].iter().any(|epoch| {
        ["full", "plugin"]
            .iter()
            .any(|stage| name == format!("epoch-{epoch}.{stage}.ok"))
    })
}
fn check_admission(p: &Plan) -> Result<()> {
    let Some(bound) = &p.admission_observer else {
        return Ok(());
    };
    ensure!(
        local(p)
            && bound.path.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1"
                )),
        "foreign admission observer"
    );
    let bytes = evidence::bound_file(&bound.path, &bound.sha256, 16 << 20, false)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    if local191(p) {
        admission191_value(&value, now)?;
    } else {
        admission_value(&value, now)?;
    }
    for replay in value["replays"].as_array().context("admission replays")? {
        for owner in ["controller_after", "producer_after"] {
            let owner = &replay[owner];
            let name = owner["unit"].as_str().context("admission unit")?;
            let result = Command::new("/usr/bin/systemctl")
                .args([
                    "show",
                    name,
                    "--property=InvocationID,ActiveState,SubState,NRestarts",
                ])
                .output()?;
            ensure!(result.status.success(), "cannot recheck admitted owner");
            let output = std::str::from_utf8(&result.stdout)?;
            for expected in [
                format!(
                    "InvocationID={}",
                    owner["invocation_id"]
                        .as_str()
                        .context("owner invocation")?
                ),
                "ActiveState=active".into(),
                "SubState=running".into(),
                "NRestarts=0".into(),
            ] {
                ensure!(
                    output.lines().any(|line| line == expected),
                    "admitted owner changed before launch"
                );
            }
        }
    }
    Ok(())
}

// Executables are not JSON. Stream large plugin binaries without weakening the
// independent, small plan/receipt limits or allocating their entire contents.
fn verify_executable(p: &Plan) -> Result<()> {
    let maximum = if local(p) {
        512 * 1024 * 1024
    } else {
        verifier_size_limit(p.stage)
    };
    let mut f = open_stable(&p.verifier.path)?;
    let before = f.metadata()?;
    ensure!(
        before.uid() == 0 && before.len() <= maximum && before.mode() & 0o111 != 0,
        "unsafe verifier identity or size"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = f.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("verifier length overflow")?;
        ensure!(total <= before.len(), "verifier grew");
        hash.update(&buffer[..count]);
    }
    recheck(&p.verifier.path, &f, &before)?;
    ensure!(
        total == before.len() && format!("{:x}", hash.finalize()) == p.verifier.sha256,
        "verifier digest mismatch"
    );
    Ok(())
}

fn batch_absent(directory: &Path) -> Result<()> {
    for name in [
        ".jetstreamer-archive-batch",
        ".jetstreamer-archive-batch-outcome",
    ] {
        match fs::symlink_metadata(directory.join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!("archive batch publication is not acknowledged"),
        }
    }
    Ok(())
}

fn open_stable(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o222 == 0,
        "input must be an immutable singly linked regular file"
    );
    ensure!(
        evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "input raced open"
    );
    Ok(f)
}

fn recheck(path: &Path, f: &File, before: &fs::Metadata) -> Result<()> {
    ensure!(
        evidence::identity(before) == evidence::identity(&f.metadata()?)
            && evidence::identity(before) == evidence::identity(&fs::symlink_metadata(path)?),
        "input path or descriptor changed"
    );
    Ok(())
}

fn hash_archive(path: &Path) -> Result<(String, fs::Metadata)> {
    let mut f = open_stable(path)?;
    let m = f.metadata()?;
    ensure!(m.len() > 0, "empty archive");
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 8 * 1024 * 1024];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    recheck(path, &f, &m)?;
    Ok((format!("{:x}", digest.finalize()), m))
}

fn sidecar(path: &Path, epoch: u64, digest: &str) -> Result<Vec<u8>> {
    let mut f = open_stable(path)?;
    let m = f.metadata()?;
    ensure!(m.len() <= 512, "oversized sidecar");
    let mut bytes = Vec::new();
    (&mut f).take(513).read_to_end(&mut bytes)?;
    ensure!(
        bytes == format!("{digest}  epoch-{epoch}.jet\n").as_bytes(),
        "noncanonical or mismatching sidecar"
    );
    recheck(path, &f, &m)?;
    Ok(bytes)
}

fn commands(p: &Plan) -> Vec<Vec<String>> {
    let archive = p.archive_directory.join(format!("epoch-{}.jet", p.epoch));
    let threads = p.threads_per_command.to_string();
    match p.stage {
        Stage::Full => vec![
            vec![
                archive.display().to_string(),
                "--threads".into(),
                threads.clone(),
            ],
            vec![
                archive.display().to_string(),
                "--full".into(),
                "--internal-full".into(),
                "--threads".into(),
                threads,
            ],
        ],
        Stage::Plugin => vec![vec![
            format!("{}:{}", p.epoch, p.epoch),
            p.archive_directory.display().to_string(),
            "--threads".into(),
            threads,
            "--verify-only".into(),
        ]],
    }
}

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn run_commands(executable: &Path, args: &[Vec<String>]) -> Result<()> {
    let mut children = Children(Vec::new());
    for command in args {
        children
            .0
            .push(Command::new(executable).args(command).spawn()?);
    }
    for child in &mut children.0 {
        ensure!(
            child.wait()?.success(),
            "independent verifier command failed"
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0,
        "verification state must be root-owned and owner-only: {} uid={} mode={:o}",
        path.display(),
        m.uid(),
        m.mode() & 0o7777
    );
    Ok(())
}
fn commit_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("receipt parent missing")?;
    private_directory(parent)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        ensure!(
            m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.mode() & 0o077 == 0,
            "unsafe existing receipt"
        );
        let mut old = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let mut found = Vec::new();
        (&mut old).take(4097).read_to_end(&mut found)?;
        ensure!(
            found == bytes
                && evidence::identity(&m) == evidence::identity(&old.metadata()?)
                && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
            "existing receipt differs"
        );
        old.sync_all()?;
        File::open(parent)?.sync_all()?;
        return Ok(());
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".verify-pair-")
        .tempfile_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn mirror_gate_receipt(directory: &Path, name: &str, bytes: &[u8], owner: u32) -> Result<()> {
    ensure!(
        directory.is_absolute() && directory.canonicalize()? == directory,
        "noncanonical gate directory"
    );
    let m = fs::symlink_metadata(directory)?;
    ensure!(
        m.is_dir() && m.uid() == owner && m.mode() & 0o022 == 0,
        "unsafe gate directory"
    );
    ensure!(gate_name(name), "foreign gate receipt");
    let path = directory.join(name);
    if let Ok(existing) = fs::symlink_metadata(&path) {
        let mut f = open_stable(&path)?;
        ensure!(
            existing.uid() == unsafe { libc::geteuid() } && existing.len() <= 4096,
            "foreign existing gate receipt"
        );
        let mut old = Vec::new();
        f.read_to_end(&mut old)?;
        ensure!(old == bytes, "existing gate receipt differs");
        f.sync_all()?;
        File::open(directory)?.sync_all()?;
        return Ok(());
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".native198-gate-")
        .tempfile_in(directory)?;
    temp.write_all(bytes)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o444))?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path).map_err(|e| e.error)?;
    File::open(directory)?.sync_all()?;
    Ok(())
}

fn record_local198_launch(p: &Plan, args: &[String], executable: &Path) -> Result<()> {
    if !local(p) {
        return Ok(());
    }
    let phase = match p.stage {
        Stage::Full => "full-verification",
        Stage::Plugin => "plugin-verification",
    };
    let unit = if local191(p) {
        format!(
            "horizon-{}-verify-{}-native191-20261023-v1.service",
            p.stage.suffix(),
            p.epoch
        )
    } else {
        format!(
            "horizon-{}-verify-198-native-20261021-v1.service",
            p.stage.suffix()
        )
    };
    let result = Command::new("/usr/bin/systemctl").args(["show", &unit,
        "--property=Id,LoadState,ActiveState,SubState,MainPID,NRestarts,InvocationID,ExecStart,Type,Result,ControlGroup"])
        .output()?;
    ensure!(
        result.status.success(),
        "cannot capture verification service"
    );
    let mut state = serde_json::Map::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line.split_once('=').context("malformed unit property")?;
        ensure!(
            state.insert(key.into(), value.into()).is_none(),
            "duplicate unit property"
        );
    }
    let state = serde_json::Value::Object(state);
    let invocation = env::var("INVOCATION_ID")?;
    let expected = format!(
        "{{ path={} ; argv[]={} {} {} {} ; ignore_errors=",
        executable.display(),
        executable.display(),
        args[0],
        args[1],
        args[2]
    );
    ensure!(
        state["Id"] == unit
            && state["LoadState"] == "loaded"
            && state["ActiveState"] == "active"
            && state["SubState"] == "running"
            && state["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u32>().ok())
                == Some(std::process::id())
            && state["NRestarts"] == "0"
            && state["Type"] == "exec"
            && state["InvocationID"] == invocation
            && invocation.len() == 32
            && invocation.bytes().all(|b| b.is_ascii_hexdigit())
            && state["ExecStart"]
                .as_str()
                .is_some_and(|s| s.starts_with(&expected))
            && state["ControlGroup"] == format!("/system.slice/{unit}"),
        "verification service identity differs"
    );
    evidence::write_receipt(
        &p.state_directory.join("launch.json"),
        &serde_json::json!({
            "schema":if local191(p) {"horizon-cohort191-native-verification-launch-v1"} else {"horizon-epoch198-native-verification-launch-v1"}, "epoch":p.epoch,
            "plan":{"path":args[0],"sha256":args[1]}, "runner_sha256":args[2],
        "admission_observer":p.admission_observer,
            "unit":state, "claim":{"epoch":p.epoch,"phase":phase,"unit":unit,
            "invocation_id":invocation,"expected_exec_start":state["ExecStart"],
            "evidence":[{"path":args[0],"sha256":args[1]}]},
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "archive_hashing_started":false,"verification_complete":false,
            "publication_authorized":false,"local_retirement_authorized":false,"r2_mutations":false
        }),
    )
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(
        args.len() == 3 || (args.len() == 4 && args[3] == "--check-only"),
        "usage: PLAN PLAN_SHA256 SELF_SHA256 [--check-only]"
    );
    let self_path = fs::read_link("/proc/self/exe")?;
    evidence::bound_file(&self_path, &args[2], 64 * 1024 * 1024, true)?;
    let raw = evidence::bound_file(Path::new(&args[0]), &args[1], 65536, true)?;
    let p: Plan = serde_json::from_slice(&raw)?;
    validate_plan(&p)?;
    private_directory(&p.state_directory)?;
    let receipts = p.state_directory.join("receipts");
    private_directory(&receipts)?;
    batch_absent(&p.archive_directory)?;
    verify_executable(&p)?;
    let archive = p.archive_directory.join(format!("epoch-{}.jet", p.epoch));
    let checksum = p
        .archive_directory
        .join(format!("epoch-{}.jet.sha256", p.epoch));
    let before_sidecar = sidecar(&checksum, p.epoch, &p.expected_archive_sha256)?;
    if args.len() == 4 {
        let f = open_stable(&archive)?;
        let m = f.metadata()?;
        if p.epoch == 198 {
            ensure!(
                m.len() == 99_381_250_591,
                "epoch 198 archive length differs"
            );
        }
        recheck(&archive, &f, &m)?;
        println!(
            "{}",
            serde_json::json!({"schema":"horizon-verify-pair-preflight-v1","epoch":p.epoch,"stage":p.stage.suffix(),"plan_sha256":args[1],"self_sha256":args[2],"verifier_sha256":p.verifier.sha256,"verifier_size_limit":verifier_size_limit(p.stage),"binary_binding_checked":true,"canonical_sidecar_checked":true,"archive_identity_checked":true,"full_archive_hash_proven":false,"verifier_commands_ran":false,"receipt_created":false,"archive_mutations":false,"remote_mutations":false,"r2_mutations":false})
        );
        return Ok(());
    }
    check_admission(&p)?;
    record_local198_launch(&p, &args, &self_path)?;
    milestone(&p, "pre_verification_hash_started")?;
    let (before_hash, before_meta) = hash_archive(&archive)?;
    ensure!(
        before_hash == p.expected_archive_sha256,
        "archive digest differs before verification"
    );
    milestone(&p, "pre_verification_hash_passed")?;
    eprintln!(
        "epoch {} {} verification started",
        p.epoch,
        p.stage.suffix()
    );
    run_commands(&p.verifier.path, &commands(&p))?;
    milestone(&p, "independent_verifier_commands_passed")?;
    milestone(&p, "post_verification_hash_started")?;
    let (after_hash, after_meta) = hash_archive(&archive)?;
    ensure!(
        before_hash == after_hash
            && evidence::identity(&before_meta) == evidence::identity(&after_meta),
        "archive changed across independent verification"
    );
    milestone(&p, "post_verification_hash_passed")?;
    ensure!(
        sidecar(&checksum, p.epoch, &p.expected_archive_sha256)? == before_sidecar,
        "sidecar changed"
    );
    verify_executable(&p)?;
    evidence::bound_file(Path::new(&args[0]), &args[1], 65536, true)?;
    evidence::bound_file(&self_path, &args[2], 64 * 1024 * 1024, true)?;
    batch_absent(&p.archive_directory)?;
    let output = receipts.join(format!("epoch-{}.{}.ok", p.epoch, p.stage.suffix()));
    milestone(&p, "receipt_fsync_started")?;
    commit_receipt(
        &output,
        format!("{} {} {}\n", after_hash, p.verifier.sha256, args[2]).as_bytes(),
    )?;
    if local(&p) {
        let directory = match p.stage {
            Stage::Full => {
                "/home/sol/.jetstreamer-private/final-audits/epochs-101-200-parallel-v1/receipts"
            }
            Stage::Plugin => {
                "/home/sol/.jetstreamer-private/horizon-plugin-current-101-200-v2/receipts"
            }
        };
        mirror_gate_receipt(
            Path::new(directory),
            &format!("epoch-{}.{}.ok", p.epoch, p.stage.suffix()),
            format!("{} {} {}\n", after_hash, p.verifier.sha256, args[2]).as_bytes(),
            1001,
        )?;
    }
    milestone(&p, "receipt_durable")?;
    println!("{}", output.display());
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn plan(stage: Stage) -> Plan {
        Plan {
            schema: "horizon-verify-canonical-pair-plan-v1".into(),
            epoch: 220,
            stage,
            archive_directory: "/home/ubuntu/horizon".into(),
            expected_archive_sha256: "a".repeat(64),
            verifier: Bound {
                path: match stage {
                    Stage::Full => "/immutable/verify_archive",
                    Stage::Plugin => "/immutable/horizon_pipeline",
                }
                .into(),
                sha256: "b".repeat(64),
            },
            threads_per_command: 8,
            state_directory: "/private/state".into(),
            admission_observer: None,
        }
    }
    #[test]
    fn full_requires_both_ordered_and_internal_full_scans() {
        let p = plan(Stage::Full);
        let c = commands(&p);
        assert_eq!(c.len(), 2);
        assert_eq!(
            c[0],
            vec!["/home/ubuntu/horizon/epoch-220.jet", "--threads", "8"]
        );
        assert_eq!(
            c[1],
            vec![
                "/home/ubuntu/horizon/epoch-220.jet",
                "--full",
                "--internal-full",
                "--threads",
                "8"
            ]
        );
    }
    #[test]
    fn local198_admission_requires_fresh_bound_complete_fleet_and_combined_headroom() {
        let mut value = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2",
            "recorded_at_utc":"2026-10-21T21:28:00Z",
            "cadence":{"routine_minimum_interval_enforced":true},
            "filesystem":{"conservative_available_bytes":4_740_696_923_590u64 + (32u64 << 20)},
            "host_memory":{"conservative_available_kib":192u64 * 1024 * 1024},
            "replays":(["1a7e8cde872b45f786979150d5639ab4","518ff0bf0bbb4413a155a63f95907163","f3ec98a134d544e78cb2083f502ed292","ea93199ed2fa470d99de248c2a10b246"].map(|iid| json!({"producer_after":{"invocation_id":iid},"invocation_binding_stable":true})))});
        let time = utc_seconds("2026-10-21T21:28:00Z").unwrap();
        admission_value(&value, time).unwrap();
        admission_value(&value, time + 900).unwrap();
        assert!(admission_value(&value, time - 1).is_err());
        assert!(admission_value(&value, time + 901).is_err());
        for (pointer, bad) in [
            (
                "/filesystem/conservative_available_bytes",
                json!(4_740_696_923_590u64 + (32u64 << 20) - 1),
            ),
            (
                "/host_memory/conservative_available_kib",
                json!(192u64 * 1024 * 1024 - 1),
            ),
            ("/cadence/routine_minimum_interval_enforced", json!(false)),
            ("/replays/0/invocation_binding_stable", json!(false)),
            ("/replays/0/producer_after/invocation_id", json!("changed")),
        ] {
            let mut bad_value = value.clone();
            *bad_value.pointer_mut(pointer).unwrap() = bad;
            assert!(admission_value(&bad_value, time).is_err(), "{pointer}");
        }
        value["replays"].as_array_mut().unwrap().pop();
        assert!(admission_value(&value, time).is_err());
        for clock in [
            "2026-02-30T00:00:00Z",
            "2026-10-21T24:00:00Z",
            "2026-10-21T21:28:00Zextra",
            "2026-1-21T21:28:00Z",
        ] {
            assert!(utc_seconds(clock).is_err(), "{clock}");
        }
    }
    #[test]
    fn local191_is_closed_and_retains_independent_full_and_plugin_checks() {
        for epoch in 191..=194 {
            for stage in [Stage::Full, Stage::Plugin] {
                let mut p = plan(stage);
                p.schema = "horizon-verify-canonical-pair-dev-samjohnson191-v1".into();
                p.epoch = epoch;
                p.archive_directory = "/home/sol/horizon".into();
                p.admission_observer = Some(Bound {
                    path: "/observer".into(),
                    sha256: "c".repeat(64),
                });
                p.state_directory = Path::new(
                    "/var/lib/jetstreamer/horizon-cohort191-canonical-verification-20261023-v1",
                )
                .join(format!("epoch-{epoch}"))
                .join(stage.suffix());
                p.verifier = Bound {
                    path:Path::new("/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1")
                        .join(if stage == Stage::Full {"verify_archive"} else {"horizon_pipeline"}),
                    sha256:if stage == Stage::Full {"5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574"}
                        else {"e20892a111f8e26c8e25561a939eaf171771789753059100510c936d92092137"}.into()};
                validate_plan(&p).unwrap();
                let commands = commands(&p);
                assert_eq!(commands.len(), if stage == Stage::Full { 2 } else { 1 });
                if stage == Stage::Full {
                    assert!(commands[1].contains(&"--internal-full".into()));
                } else {
                    assert!(commands[0].contains(&"--verify-only".into()));
                }
                p.epoch = 190;
                assert!(validate_plan(&p).is_err());
                p.epoch = epoch;
                p.verifier.sha256 = "0".repeat(64);
                assert!(validate_plan(&p).is_err());
            }
        }
    }
    #[test]
    fn gate_receipts_cannot_escape_the_qualified191_or198_epoch_set() {
        for epoch in [190, 195, 197, 199, 201] {
            for stage in ["full", "plugin"] {
                assert!(!gate_name(&format!("epoch-{epoch}.{stage}.ok")));
            }
        }
        for name in [
            "epoch-191.full.ok/other",
            "epoch-0191.full.ok",
            "epoch-191.boundary.ok",
            "../epoch-191.full.ok",
        ] {
            assert!(!gate_name(name));
        }
    }
    #[test]
    fn plugin_is_one_epoch_current_verify_only() {
        assert_eq!(
            commands(&plan(Stage::Plugin)),
            vec![vec![
                "220:220",
                "/home/ubuntu/horizon",
                "--threads",
                "8",
                "--verify-only"
            ]]
        );
    }
    #[test]
    fn campaign_bounds_and_threads_never_expand() {
        let mut p = plan(Stage::Full);
        validate_plan(&p).unwrap();
        for n in [0, 200, 301, 1000] {
            p.epoch = n;
            assert!(validate_plan(&p).is_err());
        }
        p.epoch = 220;
        for n in [0, 33, usize::MAX] {
            p.threads_per_command = n;
            assert!(validate_plan(&p).is_err());
        }
    }
    #[test]
    fn local198_is_explicit_exact_and_keeps_both_full_scans() {
        let mut p = plan(Stage::Full);
        p.schema = "horizon-verify-canonical-pair-dev-samjohnson198-v1".into();
        p.epoch = 198;
        p.admission_observer = Some(Bound {
            path: "/observer".into(),
            sha256: "c".repeat(64),
        });
        p.archive_directory = "/home/sol/horizon".into();
        p.expected_archive_sha256 =
            "4a1252a650f7b50f45326a07c0a58090b8c0174cf547099a16eeca45869f7ffb".into();
        p.state_directory =
            "/var/lib/jetstreamer/horizon-epoch198-canonical-verification-20261021-v1/full".into();
        p.verifier = Bound {
            path: "/usr/local/lib/jetstreamer/horizon-epoch198-compatible-verifiers-20261021-v1/verify_archive".into(),
            sha256: "5fc5640254f6a065e96bf73ad951c9dacd57aa963b87a4379e1f27c6ebeb3574".into(),
        };
        validate_plan(&p).unwrap();
        let c = commands(&p);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], ["/home/sol/horizon/epoch-198.jet", "--threads", "8"]);
        assert_eq!(
            c[1],
            [
                "/home/sol/horizon/epoch-198.jet",
                "--full",
                "--internal-full",
                "--threads",
                "8"
            ]
        );
        for epoch in [197, 199, 200, 201, 300] {
            p.epoch = epoch;
            assert!(validate_plan(&p).is_err());
        }
        p.epoch = 198;
        p.schema = "horizon-verify-canonical-pair-plan-v1".into();
        assert!(validate_plan(&p).is_err());
        p.schema = "horizon-verify-canonical-pair-dev-samjohnson198-v1".into();
        p.verifier.sha256 = "a".repeat(64);
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn strict_plan_rejects_skip_overwrite_and_retirement() {
        let p = json!({"schema":"horizon-verify-canonical-pair-plan-v1","epoch":220,"stage":"full","archive_directory":"/home/ubuntu/horizon","expected_archive_sha256":"a".repeat(64),"verifier":{"path":"/bin/verifier","sha256":"b".repeat(64)},"threads_per_command":8,"state_directory":"/private/state"});
        assert!(serde_json::from_value::<Plan>(p.clone()).is_ok());
        for key in ["skip_full", "delete_local", "overwrite", "allow_partial"] {
            let mut bad = p.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Plan>(bad).is_err());
        }
    }
    fn immutable_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o440)).unwrap();
    }
    #[test]
    fn sidecar_is_exact_and_hardlinks_writable_files_reject() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        let digest = "a".repeat(64);
        immutable_file(&p, format!("{digest}  epoch-220.jet\n").as_bytes());
        sidecar(&p, 220, &digest).unwrap();
        assert!(sidecar(&p, 221, &digest).is_err());
        assert!(sidecar(&p, 220, &"b".repeat(64)).is_err());
        let link = d.path().join("b");
        fs::hard_link(&p, &link).unwrap();
        assert!(sidecar(&p, 220, &digest).is_err());
        fs::remove_file(link).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(sidecar(&p, 220, &digest).is_err());
    }
    #[test]
    fn path_replacement_is_not_stable_evidence() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a");
        immutable_file(&p, b"first");
        let f = open_stable(&p).unwrap();
        let m = f.metadata().unwrap();
        fs::rename(&p, d.path().join("old")).unwrap();
        immutable_file(&p, b"first");
        assert!(recheck(&p, &f, &m).is_err());
    }
    #[test]
    fn command_failure_does_not_succeed() {
        assert!(run_commands(Path::new("/bin/false"), &[vec![], vec![]]).is_err());
    }
    #[test]
    fn dangling_batch_marker_is_not_absence() {
        let d = tempfile::tempdir().unwrap();
        batch_absent(d.path()).unwrap();
        std::os::unix::fs::symlink("missing", d.path().join(".jetstreamer-archive-batch")).unwrap();
        assert!(batch_absent(d.path()).is_err());
    }
    #[test]
    fn receipt_is_no_clobber_private_and_idempotently_durable() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = d.path().join("epoch-220.full.ok");
        let bytes = b"digest verifier runner\n";
        if unsafe { libc::geteuid() } != 0 {
            assert!(commit_receipt(&p, bytes).is_err());
            return;
        }
        commit_receipt(&p, bytes).unwrap();
        commit_receipt(&p, bytes).unwrap();
        assert_eq!(fs::read(&p).unwrap(), bytes);
        assert_eq!(fs::symlink_metadata(&p).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::symlink_metadata(&p).unwrap().nlink(), 1);
        assert!(commit_receipt(&p, b"changed").is_err());
        assert_eq!(fs::read(&p).unwrap(), bytes);
    }
    #[test]
    fn gate_mirror_preserves_existing_receipts_and_refuses_foreign_names() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let owner = unsafe { libc::geteuid() };
        let bytes = b"archive verifier runner\n";
        mirror_gate_receipt(d.path(), "epoch-198.full.ok", bytes, owner).unwrap();
        mirror_gate_receipt(d.path(), "epoch-198.full.ok", bytes, owner).unwrap();
        assert_eq!(
            fs::symlink_metadata(d.path().join("epoch-198.full.ok"))
                .unwrap()
                .mode()
                & 0o777,
            0o444
        );
        assert!(mirror_gate_receipt(d.path(), "epoch-198.full.ok", b"changed", owner).is_err());
        assert!(mirror_gate_receipt(d.path(), "epoch-199.full.ok", bytes, owner).is_err());
        assert!(
            mirror_gate_receipt(
                d.path(),
                "epoch-198.plugin.ok",
                bytes,
                owner.wrapping_add(1)
            )
            .is_err()
        );
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(mirror_gate_receipt(d.path(), "epoch-198.plugin.ok", bytes, owner).is_err());
    }
    #[test]
    fn stages_cannot_use_a_different_executable_name() {
        let mut p = plan(Stage::Full);
        p.verifier.path = "/bin/true".into();
        assert!(validate_plan(&p).is_err());
        p.verifier.path = "/immutable/horizon_pipeline".into();
        assert!(validate_plan(&p).is_err());
        p.stage = Stage::Plugin;
        validate_plan(&p).unwrap();
    }
    #[test]
    fn plugin_bound_covers_actual_large_pipeline_but_stays_finite() {
        assert_eq!(verifier_size_limit(Stage::Full), 128 * 1024 * 1024);
        assert_eq!(verifier_size_limit(Stage::Plugin), 512 * 1024 * 1024);
        assert!(238472424 > verifier_size_limit(Stage::Full));
        assert!(238472424 < verifier_size_limit(Stage::Plugin));
    }
}
