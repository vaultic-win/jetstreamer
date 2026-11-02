//! One durable sampler rollover. A systemd timer owns cadence; there is no loop.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const LIMIT: u64 = 4 << 20;
const INTERVAL: u64 = 1800;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    root: PathBuf,
    sampler: Bound,
    template: Bound,
    seed: Bound,
    minimum_interval_seconds: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    schema: String,
    sequence: u64,
    started_unix_seconds: u64,
    predecessor: Bound,
    config: Bound,
    plan: Bound,
    sampler: Bound,
    output: PathBuf,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Commit {
    schema: String,
    intent: Bound,
    predecessor: Bound,
    sample: Bound,
}
fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn stable(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let a = f.metadata()?;
    ensure!(
        a.is_file()
            && a.nlink() == 1
            && a.uid() == unsafe { libc::geteuid() }
            && a.mode() & 0o022 == 0
            && a.len() <= limit,
        "unsafe input metadata"
    );
    let mut bytes = Vec::new();
    f.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    let b = f.metadata()?;
    let named = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == a.len()
            && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
            && named.dev() == a.dev()
            && named.ino() == a.ino()
            && !named.file_type().is_symlink(),
        "input changed"
    );
    Ok(bytes)
}
fn bound(path: &Path) -> Result<Bound> {
    Ok(Bound {
        path: path.into(),
        sha256: hex(&stable(path, LIMIT)?),
    })
}
fn read(b: &Bound) -> Result<Value> {
    ensure!(digest(&b.sha256), "invalid binding digest");
    let bytes = stable(&b.path, LIMIT)?;
    ensure!(hex(&bytes) == b.sha256, "binding digest mismatch");
    Ok(serde_json::from_slice(&bytes)?)
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "nonprivate control directory"
    );
    Ok(())
}
fn write_new(path: &Path, value: &impl Serialize) -> Result<Bound> {
    let parent = path.parent().context("output parent")?;
    private(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), value)?;
    use std::io::Write;
    tmp.as_file_mut().write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    // Atomic publication keeps nlink == 1 even if the owner crashes here;
    // link/unlink publication could strand a second temporary hard link.
    use std::os::unix::ffi::OsStrExt;
    let from = std::ffi::CString::new(tmp.path().as_os_str().as_bytes())?;
    let to = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "no-clobber publication failed: {}",
        std::io::Error::last_os_error()
    );
    File::open(parent)?.sync_all()?;
    bound(path)
}
fn clock() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn utc(seconds: u64) -> Result<String> {
    let t: libc::time_t = seconds.try_into()?;
    let mut tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&t, &mut tm) }.is_null(),
        "UTC conversion"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}
fn seconds(v: &Value, key: &str) -> Result<u64> {
    let s = v[key].as_str().context("missing UTC timestamp")?;
    ensure!(
        s.len() == 20 && s.as_bytes()[19] == b'Z',
        "noncanonical UTC"
    );
    let s = std::ffi::CString::new(s)?;
    let mut tm = unsafe { std::mem::zeroed() };
    let end = unsafe { libc::strptime(s.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(!end.is_null() && unsafe { *end } == 0, "invalid UTC");
    let t = unsafe { libc::timegm(&mut tm) };
    ensure!(
        t >= 0 && utc(t as u64)? == s.to_str()?,
        "UTC normalization or overflow"
    );
    Ok(t as u64)
}
struct Lease(File);
impl Lease {
    fn acquire(root: &Path) -> Result<Self> {
        private(root)?;
        let path = root.join("lease");
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.nlink() == 1
                && m.uid() == unsafe { libc::geteuid() }
                && m.mode() & 0o077 == 0,
            "unsafe lease"
        );
        ensure!(
            unsafe {
                libc::flock(
                    std::os::fd::AsRawFd::as_raw_fd(&f),
                    libc::LOCK_EX | libc::LOCK_NB,
                )
            } == 0,
            "another observation owner holds lease"
        );
        File::open(root)?.sync_all()?;
        Ok(Self(f))
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&self.0), libc::LOCK_UN) };
    }
}
fn template(p: &Plan) -> Result<Value> {
    ensure!(
        p.schema == "jetstreamer-observer-rollover-plan-v1"
            && p.minimum_interval_seconds >= INTERVAL,
        "unsupported rollover plan/cadence"
    );
    let t = read(&p.template)?;
    ensure!(
        t["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && t["minimum_interval_seconds"] == p.minimum_interval_seconds
            && t.get("observation_reason").is_none_or(|v| v == "routine")
            && t.get("epoch203_ram_auxiliary").is_none_or(Value::is_null)
            && t.get("native_input_diagnostics")
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
        "unsupported template"
    );
    ensure!(
        t["previous_sample"].as_str() == p.seed.path.to_str()
            && t["replays"].as_array().is_some_and(|r| !r.is_empty()),
        "template seed or ordinary roster missing"
    );
    Ok(t)
}
fn config(t: &Value, prior: &Bound, output: &Path, due: u64) -> Result<Value> {
    let mut c = t.clone();
    c["previous_sample"] = json!(prior.path);
    c["output"] = json!(output);
    c["not_before_utc"] = json!(utc(due)?);
    Ok(c)
}
fn owner(observation: &Value, expected: &Value) -> Result<()> {
    ensure!(
        observation["invocation_binding_stable"] == true
            && observation["range"] == expected["range"],
        "unstable or changed observation owner"
    );
    for role in ["producer", "controller"] {
        for stage in ["before", "after"] {
            let v = &observation[format!("{role}_{stage}")];
            ensure!(
                v["unit"] == expected[format!("{role}_unit")]
                    && v["invocation_id"] == expected[format!("expected_{role}_invocation_id")]
                    && v["restarts"] == 0
                    && v["active_state"] == "active"
                    && v["sub_state"] == "running",
                "changed owner identity/state"
            );
        }
    }
    Ok(())
}
fn sample(
    v: &Value,
    c: &Value,
    prior: &Bound,
    prior_value: &Value,
    attempt: u64,
    now: u64,
) -> Result<()> {
    let start = seconds(v, "recorded_at_utc")?;
    let end = seconds(v, "completed_at_utc")?;
    let interval = c["minimum_interval_seconds"]
        .as_u64()
        .context("sample interval")?;
    let previous = seconds(prior_value, "recorded_at_utc")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && v["cadence"]["observation_reason"] == "routine"
            && v["cadence"]["routine_minimum_interval_enforced"] == true
            && v["cadence"]["previous_sample"].as_str() == prior.path.to_str()
            && v["cadence"]["previous_sample_sha256"] == prior.sha256
            && v["cadence"]["minimum_interval_seconds"] == interval
            && start
                >= previous
                    .checked_add(interval)
                    .context("sample due overflow")?
            && start >= seconds(c, "not_before_utc")?
            && start >= attempt
            && end >= start
            && end <= now,
        "sample predecessor/cadence mismatch"
    );
    let observed = v["replays"].as_array().context("sample replay list")?;
    let expected = c["replays"].as_array().context("config replay list")?;
    ensure!(
        observed.len() == expected.len(),
        "sample owner count changed"
    );
    for (o, e) in observed.iter().zip(expected) {
        owner(o, e)?;
    }
    let ds = c
        .get("diagnostic_replays")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let observed = v["diagnostic_replays"]
        .as_array()
        .context("sample diagnostic list")?;
    ensure!(observed.len() == ds.len(), "diagnostic count changed");
    for (o, e) in observed.iter().zip(ds.iter()) {
        ensure!(
            o["producer_unit"] == e["producer_unit"]
                && o["expected_producer_invocation_id"] == e["expected_producer_invocation_id"],
            "diagnostic binding changed"
        );
        match o["status"].as_str() {
            Some("observed") => {
                ensure!(o["error"].is_null(), "diagnostic error");
                owner(&o["observation"], e)?;
            }
            Some("unavailable") => {
                ensure!(
                    o["observation"].is_null() && o["error"].is_string(),
                    "invalid unavailable diagnostic"
                );
            }
            _ => anyhow::bail!("unknown diagnostic status"),
        }
    }
    ensure!(
        v["mutation"]["producer_or_controller_signals_sent"] == false
            && v["mutation"]["service_state_changed"] == false
            && v["mutation"]["r2_mutations"] == false
            && v["mutation"]["remote_mutations"] == false,
        "sampler mutation flags"
    );
    Ok(())
}
fn commit(
    dir: &Path,
    i: &Intent,
    ib: &Bound,
    c: &Value,
    prior_value: &Value,
    now: u64,
) -> Result<Bound> {
    let sb = bound(&i.output)?;
    let v = read(&sb)?;
    sample(
        &v,
        c,
        &i.predecessor,
        prior_value,
        i.started_unix_seconds,
        now,
    )?;
    // Sync a fully validated sample before making its immutable selector commit.
    File::open(&i.output)?.sync_all()?;
    File::open(dir)?.sync_all()?;
    write_new(
        &dir.join("commit.json"),
        &Commit {
            schema: "jetstreamer-observer-rollover-commit-v1".into(),
            intent: ib.clone(),
            predecessor: i.predecessor.clone(),
            sample: sb.clone(),
        },
    )?;
    Ok(sb)
}
fn run(
    p: &Plan,
    pb: &Bound,
    now: u64,
    invoke: impl FnOnce(&Bound, &Path) -> Result<bool>,
) -> Result<Value> {
    let _lease = Lease::acquire(&p.root)?;
    let t = template(p)?;
    let root = p.root.join("attempts");
    private(&root)?;
    let mut dirs = Vec::new();
    for e in fs::read_dir(&root)? {
        let e = e?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 attempt"))?;
        let n: u64 = name.parse()?;
        ensure!(
            n > 0 && format!("{n:020}") == name,
            "noncanonical attempt sequence"
        );
        private(&e.path())?;
        dirs.push((n, e.path()));
    }
    ensure!(dirs.len() <= 100000, "attempt journal bound exceeded");
    dirs.sort_by_key(|x| x.0);
    let mut prior = p.seed.clone();
    let mut pv = read(&prior)?;
    ensure!(
        pv["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "seed schema"
    );
    let mut last_attempt = 0;
    let mut next = 1;
    let mut recovered = false;
    for (n, dir) in dirs {
        next = n.checked_add(1).context("sequence overflow")?;
        let ip = dir.join("intent.json");
        if !ip.exists() {
            ensure!(
                !dir.join("sample.json").exists() && !dir.join("commit.json").exists(),
                "sample without intent"
            );
            continue;
        }
        let ib = bound(&ip)?;
        let i: Intent = serde_json::from_value(read(&ib)?)?;
        ensure!(
            i.schema == "jetstreamer-observer-rollover-intent-v1"
                && i.sequence == n
                && i.predecessor == prior
                && i.plan == *pb
                && i.sampler == p.sampler
                && i.output == dir.join("sample.json")
                && i.config.path == dir.join("config.json")
                && i.started_unix_seconds >= last_attempt
                && i.started_unix_seconds <= now,
            "intent journal mismatch"
        );
        let c = read(&i.config)?;
        let due = seconds(&pv, "recorded_at_utc")?
            .checked_add(p.minimum_interval_seconds)
            .context("due overflow")?
            .max(seconds(&t, "not_before_utc")?)
            .max(
                last_attempt
                    .checked_add(p.minimum_interval_seconds)
                    .context("attempt cadence overflow")?,
            );
        ensure!(
            c == config(&t, &prior, &i.output, due)? && i.started_unix_seconds >= due,
            "derived config changed"
        );
        last_attempt = i.started_unix_seconds;
        let cp = dir.join("commit.json");
        if cp.exists() {
            let cb = bound(&cp)?;
            let cm: Commit = serde_json::from_value(read(&cb)?)?;
            ensure!(
                cm.schema == "jetstreamer-observer-rollover-commit-v1"
                    && cm.intent == ib
                    && cm.predecessor == prior
                    && cm.sample.path == i.output,
                "selector commit mismatch"
            );
            let v = read(&cm.sample)?;
            sample(&v, &c, &prior, &pv, last_attempt, now)?;
            File::open(&cm.sample.path)?.sync_all()?;
            File::open(&cp)?.sync_all()?;
            File::open(&dir)?.sync_all()?;
            prior = cm.sample;
            pv = v;
        } else if i.output.exists()
            && serde_json::from_slice::<Value>(&stable(&i.output, LIMIT)?).is_ok()
        {
            prior = commit(&dir, &i, &ib, &c, &pv, now)?;
            pv = read(&prior)?;
            recovered = true;
        }
        // Partial/missing samples remain untouched. The intent clock prevents
        // retrying resource reads early after an owner crash or sampler failure.
    }
    if recovered {
        return Ok(json!({"outcome":"recovered-selector","sample":prior,"new_resource_samples":0}));
    }
    let due = seconds(&pv, "recorded_at_utc")?
        .checked_add(p.minimum_interval_seconds)
        .context("due overflow")?
        .max(seconds(&t, "not_before_utc")?)
        .max(
            last_attempt
                .checked_add(p.minimum_interval_seconds)
                .context("attempt cadence overflow")?,
        );
    if now < due {
        return Ok(
            json!({"outcome":"not-due","not_before_unix_seconds":due,"new_resource_samples":0}),
        );
    }
    let dir = root.join(format!("{next:020}"));
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    File::open(&root)?.sync_all()?;
    let output = dir.join("sample.json");
    let c = config(&t, &prior, &output, due)?;
    let cb = write_new(&dir.join("config.json"), &c)?;
    let i = Intent {
        schema: "jetstreamer-observer-rollover-intent-v1".into(),
        sequence: next,
        started_unix_seconds: now,
        predecessor: prior.clone(),
        config: cb.clone(),
        plan: pb.clone(),
        sampler: p.sampler.clone(),
        output,
    };
    let ib = write_new(&dir.join("intent.json"), &i)?;
    eprintln!(
        "observer rollover attempt {next}: sampling from predecessor {}",
        prior.path.display()
    );
    let success = invoke(&p.sampler, &cb.path)?;
    write_new(
        &dir.join("child-result.json"),
        &json!({"success":success,"new_resource_samples_attempted":1}),
    )?;
    ensure!(
        success,
        "sampler failed; preserve attempt and wait normal cadence"
    );
    let sb = commit(&dir, &i, &ib, &c, &pv, clock()?.max(now))?;
    Ok(json!({"outcome":"sample-committed","sample":sb,"new_resource_samples":1}))
}
fn invoke(sampler: &Bound, config: &Path) -> Result<bool> {
    // Validate the sealed executable without loading or replacing it.
    let bytes = stable(&sampler.path, 512 << 20)?;
    let m = fs::metadata(&sampler.path)?;
    ensure!(
        hex(&bytes) == sampler.sha256 && m.mode() & 0o222 == 0 && m.mode() & 0o111 != 0,
        "sampler is not the pinned immutable executable"
    );
    let parent = unsafe { libc::getpid() };
    let mut command = Command::new(&sampler.path);
    command
        .arg(config)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    // The child cannot outlive a crashed lease owner and overlap a recovery.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(std::io::Error::other("rollover parent exited"));
            }
            Ok(())
        });
    }
    Ok(command.status()?.success())
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "rollover requires root");
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6
            && args[2] == "--plan-sha256"
            && args[3].len() == 64
            && args[4] == "--self-sha256",
        "usage: PLAN --plan-sha256 SHA --self-sha256 SHA"
    );
    let self_sha = &args[5];
    let exe = fs::read_link("/proc/self/exe")?;
    ensure!(
        digest(self_sha)
            && hex(&stable(&exe, 512 << 20)?) == self_sha
            && fs::metadata(&exe)?.mode() & 0o222 == 0,
        "self executable mismatch"
    );
    let pb = Bound {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    };
    let plan: Plan = serde_json::from_value(read(&pb)?)?;
    ensure!(
        fs::metadata(&pb.path)?.mode() & 0o222 == 0
            && fs::metadata(&plan.template.path)?.mode() & 0o222 == 0,
        "plan/template must be sealed immutable members"
    );
    println!("{}", run(&plan, &pb, clock()?, invoke)?);
    Ok(())
}
#[cfg(test)]
mod tests;
