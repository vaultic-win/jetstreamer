//! Keep a checked disk copy of the stopped epoch 229 AccountsDb before RAM retirement.
use super::*;
use serde::Deserialize;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/epoch229-demotion-tmpfs-v1/run";
const SOURCE_RELATIVE: &str = "output/.historical-runtime/jetstreamer-historical-parent-O7Clmc/jetstreamer-historical-v1.6.20-iXcpFP/accounts-state";
const PARTIAL: &str = "output/epoch-229-program-demotion-diagnostic.jet";
const PARTIAL_SHA: &str = "b8fac8f4d574226c520b9b6111fbbe937499d0291a5326e34ab8ec7f742b7d03";
const TERMINAL: &str = "/var/lib/jetstreamer/horizon229-called-program-demotion-v1/terminal.json";
const TERMINAL_SHA: &str = "cd8eb4a2ae2da0210ac54f954858be2b59f09304193d9383466c50f45f66c2b6";
const SUCCESSOR: &str = "/var/lib/jetstreamer/horizon229-called-program-demotion-v2/terminal.json";
const SUCCESSOR_SHA: &str = "7589e1bb05fac416d7694b5029e41115382afe18336e9edec8a1a4f9294a552b";
const PRODUCER: &str = "horizon-qualify-229-called-program-demotion-v1.service";
const TIMER: &str = "horizon-229-called-program-demotion-protective-v1.timer";
const UNIT: &str = "foundation-229-closed-accounts-stage-v1.service";
const STATE: &str = "/var/lib/jetstreamer/horizon229-v1-accounts-custody-v1";
const FILE: &str = "epoch-229-closed-accounts.pax.zst";
const CAP: u64 = 96 << 30;
const MEMBERS: usize = 372_299;
const ALLOCATED: u64 = 153_204_084_736;
const CENSUS_SHA: &str = "1ba93110f4fc2228ff4d5112f3e6b6b4a3c9748569473c6bebceaa2fc00b6306";

#[derive(Deserialize)]
struct Admission {
    schema: String,
    recorded_unix_seconds: u64,
    unit: String,
    source_census_sha256: String,
    maximum_bundle_bytes: u64,
    protected_free_bytes: u64,
    admitted: bool,
}

fn sealed_document(path: &Path) -> Result<Vec<u8>> {
    ensure!(path.canonicalize()? == path, "aliased staging evidence");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o222 == 0
            && metadata.len() <= 1 << 20,
        "unsealed staging evidence"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == metadata.len(),
        "evidence length changed"
    );
    Ok(bytes)
}

fn verify_file(path: &Path, expected: &str) -> Result<()> {
    ensure!(
        hash_file(path)? == expected,
        "artifact changed: {}",
        path.display()
    );
    Ok(())
}

fn availability(path: &Path) -> Result<libc::statvfs> {
    let name = CString::new(path.as_os_str().as_bytes())?;
    let mut value = std::mem::MaybeUninit::uninit();
    if unsafe { libc::statvfs(name.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { value.assume_init() })
}

fn guarded_invocation(source: &Path) -> Result<String> {
    let group = format!("/system.slice/{UNIT}");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{group}")
            && availability(source)?.f_flag & libc::ST_RDONLY != 0,
        "need the admitted service and a read-only source view"
    );
    let cgroup = Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/'));
    for (file, expected) in [
        ("memory.max", "2147483648"),
        ("memory.swap.max", "0"),
        ("cpuset.cpus.effective", "78-79"),
    ] {
        ensure!(
            fs::read_to_string(cgroup.join(file))?.trim() == expected,
            "staging cgroup setting differs: {file}"
        );
    }
    let mut file_size_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut file_size_limit) } == 0
            && file_size_limit.rlim_cur == CAP
            && file_size_limit.rlim_max == CAP,
        "staging file size limit differs"
    );
    let invocation = std::env::var("INVOCATION_ID")?;
    ensure!(
        invocation.len() == 32 && invocation.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "missing systemd invocation identity"
    );
    Ok(invocation)
}

fn compare(source: &Path, bundle: &Path) -> Result<()> {
    let mut decoder = Command::new(ZSTD)
        .args(["-qdc", "--"])
        .arg(bundle)
        .stdout(Stdio::piped())
        .spawn()?;
    let mut tar = match Command::new(TAR)
        .current_dir(source)
        .args([
            "--compare",
            "--sparse",
            "--numeric-owner",
            "--atime-preserve=system",
            "--file=-",
        ])
        .stdin(decoder.stdout.take().context("missing decoder output")?)
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let _ = decoder.kill();
            let _ = decoder.wait();
            return Err(error.into());
        }
    };
    let tar_exit = tar.wait()?;
    let decoder_exit = decoder.wait()?;
    ensure!(
        tar_exit.success() && decoder_exit.success(),
        "full staged payload differs"
    );
    Ok(())
}

fn admission(state: &Path, invocation: &str) -> Result<(Admission, String)> {
    let path = state.join("admission.json");
    let bytes = sealed_document(&path)?;
    let admission: Admission = serde_json::from_slice(&bytes)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let start_path = state.join("start.json");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !start_path.try_exists()? {
        ensure!(
            Instant::now() < deadline,
            "staging activation was not recorded"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let start: serde_json::Value = serde_json::from_slice(&sealed_document(&start_path)?)?;
    let age = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .checked_sub(admission.recorded_unix_seconds);
    let free = availability(state)?;
    ensure!(
        start["schema"] == "foundation-epoch229-local-accounts-stage-start-v1"
            && start["owner"]["InvocationID"] == invocation
            && start["owner"]["MainPID"] == std::process::id().to_string()
            && start["admission"]["path"] == path.to_str().context("non-UTF-8 admission path")?
            && start["admission"]["sha256"] == digest
            && start["retirement_authorized"] == false
            && start["remote_mutations"] == false
            && admission.schema == "foundation-epoch229-local-accounts-stage-admission-v1"
            && admission.admitted
            && admission.unit == UNIT
            && age.is_some_and(|seconds| seconds <= 900)
            && admission.source_census_sha256 == CENSUS_SHA
            && admission.maximum_bundle_bytes == CAP
            && admission.protected_free_bytes > 0
            && free.f_bavail * free.f_frsize
                >= admission
                    .protected_free_bytes
                    .checked_add(CAP)
                    .context("invalid disk budget")?,
        "staging admission, activation, or local disk budget differs"
    );
    Ok((admission, digest))
}

pub(super) fn run(stage: bool) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "staging requires root");
    let root = Path::new(ROOT);
    let source = root.join(SOURCE_RELATIVE);
    let partial = root.join(PARTIAL);
    let state = Path::new(STATE);
    let activation = if stage {
        let metadata = state.symlink_metadata()?;
        ensure!(
            state.canonicalize()? == state
                && metadata.is_dir()
                && metadata.uid() == 0
                && metadata.mode() & 0o777 == 0o700
                && metadata.dev() == Path::new("/").metadata()?.dev(),
            "need a private same-device staging directory"
        );
        let invocation = guarded_invocation(&source)?;
        let (admission, digest) = admission(state, &invocation)?;
        Some((invocation, admission, digest))
    } else {
        None
    };
    let source_metadata = source.symlink_metadata()?;
    let partial_metadata = partial.symlink_metadata()?;
    ensure!(
        source_metadata.is_dir()
            && source_metadata.dev() == 160
            && source_metadata.ino() == 406824
            && partial_metadata.is_file()
            && partial_metadata.dev() == 160
            && partial_metadata.ino() == 746044
            && partial_metadata.len() == 2_510_240_156,
        "closed epoch 229 inode changed"
    );
    for (path, sha) in [
        (TAR, TAR_SHA),
        (ZSTD, ZSTD_SHA),
        (TERMINAL, TERMINAL_SHA),
        (SUCCESSOR, SUCCESSOR_SHA),
    ] {
        verify_file(Path::new(path), sha)?;
    }
    verify_file(&partial, PARTIAL_SHA)?;
    let before = closed(root, PRODUCER, TIMER)?;
    let mut members = if stage {
        tempfile::NamedTempFile::new_in(state)?
    } else {
        tempfile::NamedTempFile::new()?
    };
    let source_census = census(&source, &mut members, MEMBERS)?;
    ensure!(
        source_census == CENSUS_SHA,
        "closed epoch 229 census changed: {source_census}"
    );
    let Some((invocation, admission, admission_sha256)) = activation else {
        println!(
            "{}",
            json!({
                "epoch":229, "source":source, "census_sha256":source_census, "members":MEMBERS,
                "estimated_reclaimable_bytes":ALLOCATED, "partial":partial, "partial_sha256":PARTIAL_SHA,
                "process_scan":before, "retirement_authorized":false,
            })
        );
        return Ok(());
    };
    let bundle = state.join(FILE);
    let receipt = state.join("staged.json");
    ensure!(
        !bundle.try_exists()? && !receipt.try_exists()?,
        "stage already exists"
    );
    let part = state.join(format!("{FILE}.part"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&part)?;
    let (length, digest) = compress(&source, members.path(), &mut file, CAP)?;
    file.sync_all()?;
    ensure!(file.metadata()?.len() == length, "staging length changed");
    verify_file(&part, &digest)?;
    compare(&source, &part)?;
    ensure!(
        census(&source, &mut std::io::sink(), MEMBERS)? == source_census,
        "source census changed during staging"
    );
    verify_file(&partial, PARTIAL_SHA)?;
    let after = closed(root, PRODUCER, TIMER)?;
    let free = availability(state)?;
    ensure!(
        free.f_bavail * free.f_frsize >= admission.protected_free_bytes,
        "protected disk changed"
    );
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    fs::hard_link(&part, &bundle)?;
    fs::remove_file(&part)?;
    let mut report = tempfile::NamedTempFile::new_in(state)?;
    report
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(
        &mut report,
        &json!({
            "schema":"foundation-epoch229-locally-checked-accounts-stage-v1", "epoch":229,
            "unit":UNIT, "invocation_id":invocation, "pid":std::process::id(), "source":source,
            "source_census_sha256":source_census, "members":MEMBERS,
            "terminal_sha256":TERMINAL_SHA, "successor_terminal_sha256":SUCCESSOR_SHA,
        "admission_sha256":admission_sha256,
            "bundle":bundle, "length":length, "sha256":digest, "full_sparse_comparison_matches":true,
            "partial":partial, "partial_sha256":PARTIAL_SHA, "readers_before":before, "readers_after":after,
            "remote_mutations":false, "retirement_authorized":false,
        }),
    )?;
    writeln!(report)?;
    report.as_file().sync_all()?;
    report.persist_noclobber(&receipt)?;
    File::open(state)?.sync_all()?;
    println!("{}", receipt.display());
    Ok(())
}
