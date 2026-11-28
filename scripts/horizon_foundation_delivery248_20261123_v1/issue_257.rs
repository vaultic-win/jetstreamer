//! Issue the existing guard launcher’s permit from a coordinated funding check.
//! Epoch 257’s sealed systemd definitions are linked before this runs.

use super::*;
use std::os::{fd::AsRawFd, unix::fs::DirBuilderExt};

const DIAGNOSTICS: &str = "/home/ubuntu/.codex/diagnostics";
const CHECKS: &str = "/home/ubuntu/.codex/diagnostics/horizon257-activation-v235-a1";
const CYCLE_LOCK: &str =
    "/var/lib/jetstreamer/horizon-seven-publication-controller-v222/cycle.lock";
const CYCLE: &str = "foundation-publication-cadence-v222.service";
const PEER_GUARD: &str = "horizon-261-singleton-protective-v1.service";
const MAX_DOCUMENT: u64 = 16 << 20;

fn lock(path: &str) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == 0 && meta.nlink() == 1,
        "unsafe lock {path}"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "campaign lock is held: {path}"
    );
    Ok(file)
}

fn document(path: &Path, expected: &str) -> Result<Value> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "aliased evidence path"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == 0
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= MAX_DOCUMENT,
        "unsafe evidence: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    (&file).take(MAX_DOCUMENT + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == meta.len() && format!("{:x}", Sha256::digest(&bytes)) == expected,
        "evidence SHA-256 differs: {}",
        path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn bound(value: &Value) -> Result<Value> {
    document(Path::new(text(value, "path")?), text(value, "sha256")?)
}

fn latest_cycle() -> Result<PathBuf> {
    let mut latest = None;
    for entry in fs::read_dir(DIAGNOSTICS)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(version) = name
            .to_str()
            .and_then(|s| s.strip_prefix("horizon-foundation-seven-lane-v"))
            .and_then(|s| s.parse::<u64>().ok())
        else {
            continue;
        };
        let path = entry.path().join("completion.json");
        if path.is_file()
            && latest
                .as_ref()
                .is_none_or(|(current, _)| version > *current)
        {
            latest = Some((version, path));
        }
    }
    Ok(latest.context("no completed Foundation cadence")?.1)
}

fn check_basis(path: &Path, sha256: &str) -> Result<Value> {
    ensure!(
        path.parent() == Some(Path::new(CHECKS))
            && path.file_name().and_then(|s| s.to_str()).is_some_and(|s| s
                .strip_prefix("check-")
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(|s| s.parse::<u128>().is_ok())),
        "expected a native admission check input"
    );
    let basis = document(path, sha256)?;
    ensure!(
        basis["controller"] == MAIN
            && basis["admitted"] == false
            && basis["publication_authorized"] == false
            && basis["automatic_release"] == false,
        "foreign admission check"
    );
    let selected = &basis["cadence"];
    ensure!(
        Path::new(text(selected, "path")?) == latest_cycle()?,
        "capacity check predates the latest cycle"
    );
    let cycle = bound(selected)?;
    ensure!(
        basis["fleet"] == cycle["fleet"],
        "check is not bound to the accepted fleet"
    );
    let obs = bound(&cycle["observer"])?;
    let stamp = text(&obs, "recorded_at_utc")?;
    ensure!(
        basis["observation_recorded_at"] == stamp,
        "observation time differs"
    );
    let sampled = super::run("/usr/bin/date", &["-u", "-d", stamp, "+%s"])?
        .trim()
        .parse::<u64>()?;
    ensure!(
        now()?.checked_sub(sampled).is_some_and(|age| age < 1800),
        "cadence sample expired"
    );
    let fleet = bound(&basis["fleet"])?;
    let mut active = BTreeMap::new();
    for row in fleet["active"].as_array().context("missing active fleet")? {
        ensure!(
            row["epoch"].as_u64().is_some_and(|epoch| epoch != 257),
            "epoch 257 already claimed"
        );
        let manager = if row["phase"] == "replay" {
            &row["producer"]
        } else {
            &row["unit"]
        };
        let unit = text(manager, "Id")?;
        let invocation = text(manager, "InvocationID")?;
        ensure!(
            iid(invocation) && active.insert(unit, invocation).is_none(),
            "duplicate or invalid fleet owner"
        );
    }
    ensure!(
        basis["live_owners"] == json!(active) && active.contains_key(PEER_UNIT),
        "live owners differ from fleet"
    );
    Ok(basis)
}

fn check_roster(basis: &Value) -> Result<()> {
    let active = basis["live_owners"]
        .as_object()
        .context("missing active owner roster")?;
    let current = super::run(
        "/usr/bin/systemctl",
        &[
            "list-units",
            "--type=service",
            "--state=active,activating,deactivating,reloading",
            "--plain",
            "--no-legend",
            "--no-pager",
        ],
    )?;
    let current: BTreeSet<_> = current
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|unit| {
            *unit != PEER_GUARD
                && ["horizon", "foundation-", "archive-", "jetstreamer"]
                    .iter()
                    .any(|prefix| unit.starts_with(prefix))
        })
        .collect();
    let expected = active.keys().map(String::as_str).collect::<BTreeSet<_>>();
    ensure!(current == expected, "live service roster changed");
    Ok(())
}

pub(super) fn run(mode: &str, source: &Path, basis_sha: &str, self_sha: &str) -> Result<()> {
    ensure!(
        std::env::var("CODEX_THREAD_ID")? == MAIN,
        "wrong campaign controller"
    );
    let executable = std::env::current_exe()?;
    let meta = executable.symlink_metadata()?;
    ensure!(
        executable.starts_with("/var/lib/jetstreamer")
            && executable.canonicalize()? == executable
            && meta.is_file()
            && meta.uid() == 0
            && meta.mode() & 0o222 == 0
            && hash(&executable)? == self_sha,
        "issuer executable is not the bound sealed image"
    );
    let _issuer = lock(LOCK)?;
    let _cycle = lock(CYCLE_LOCK)?;
    let cycle = show(CYCLE)?;
    ensure!(
        cycle["ActiveState"] == "inactive" && cycle["Job"].is_empty(),
        "cadence is running"
    );
    let file = Path::new(PERMIT);
    let directory = file.parent().context("missing permit directory")?;
    ensure!(!directory.try_exists()?, "admission directory already used");
    let mut basis = check_basis(source, basis_sha)?;
    prepared_start(&basis)?;
    check_roster(&basis)?;
    if mode == "inspect" {
        let funding = check_space(&basis);
        println!(
            "{}",
            json!({"prepared_units_verified":true,"manager_reload":false,
            "funded_now":funding.is_ok(),"funding_error":funding.err().map(|e|e.to_string()),
            "observed_disk_shortfall":basis["disk_shortfall"],"observed_memory_shortfall":basis["memory_shortfall"],
            "admission_issued":false,"producer_started":false})
        );
        return Ok(());
    }
    ensure!(
        basis["disk_shortfall"] == 0 && basis["memory_shortfall"] == 0,
        "accepted capacity check does not fund epoch 257"
    );
    check_space(&basis)?;
    check_roster(&basis)?;
    let issued = now()?;
    basis["capacity_check"] = json!({"path":source,"sha256":basis_sha});
    basis["launcher_sha256"] = json!(self_sha);
    basis["issuer_pid"] = json!(std::process::id());
    basis["issued_unix_seconds"] = json!(issued);
    basis["expires_unix_seconds"] = json!(issued + 110);
    basis["boot"] = json!(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim());
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    File::open(directory.parent().context("missing permit parent")?)?.sync_all()?;
    record(file, &serde_json::to_vec_pretty(&basis)?, 0o400)?;
    let permit_sha = hash(file)?;
    let result = Command::new(&executable)
        .args(["start", &permit_sha])
        .output()?;
    record(
        &directory.join("result.json"),
        &serde_json::to_vec_pretty(&json!({
            "returncode":result.status.code(),"stdout":String::from_utf8_lossy(&result.stdout),
            "stderr":String::from_utf8_lossy(&result.stderr),"admission":{"path":file,"sha256":permit_sha}
        }))?,
        0o400,
    )?;
    ensure!(
        result.status.success(),
        "guarded startup failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let handoff = directory.join("handoff.json");
    let result = read_json(&handoff)?;
    ensure!(result["producer"] == UNIT, "wrong guarded startup handoff");
    let token = document(
        Path::new(text(&result, "token")?),
        text(&result, "token_sha256")?,
    )?;
    ensure!(
        token["admission_sha256"] == permit_sha,
        "startup token does not bind the issued permit"
    );
    super::run("/usr/bin/systemctl", &["start", "--no-block", RETAIN])?;
    println!(
        "{}",
        json!({"admitted":true,"handoff":handoff,"invocation_id":result["invocation_id"]})
    );
    Ok(())
}
