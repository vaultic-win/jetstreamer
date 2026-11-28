//! Gate the metered replay behind the exact native service invocation.
use super::*;
use std::{
    collections::BTreeMap,
    io,
    mem::MaybeUninit,
    os::{fd::AsRawFd, unix::process::CommandExt},
    thread,
    time::{Duration, Instant},
};

const PROFILE: &str = "/run/horizon-epoch170-full-metered/payload.json";
const PERMIT: &str = "/run/horizon-epoch170-full-metered/barrier/allow";
const HOLD: Duration = Duration::from_secs(360);
const HEARTBEAT: Duration = Duration::from_secs(60);

fn valid_iid(iid: &str) -> bool {
    iid.len() == 32
        && iid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && iid.bytes().any(|b| b != b'0')
}

fn readonly(file: &File) -> Result<()> {
    let mut view = MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::fstatvfs(file.as_raw_fd(), view.as_mut_ptr()) } == 0,
        "read mount flags: {}",
        io::Error::last_os_error()
    );
    ensure!(
        unsafe { view.assume_init() }.f_flag & libc::ST_RDONLY != 0,
        "held input mount is writable"
    );
    Ok(())
}

fn permit(path: &Path, iid: &str) -> Result<bool> {
    let mut handle = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let before = handle.metadata()?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.gid() == 0
            && before.nlink() == 1
            && before.mode() & 0o7777 == 0o444
            && before.len() == 32,
        "invalid epoch 170 invocation permit custody"
    );
    readonly(&handle)?;
    let mut bytes = [0; 32];
    handle.read_exact(&mut bytes)?;
    stable(path, &handle, &before)?;
    ensure!(
        bytes.as_slice() == iid.as_bytes(),
        "epoch 170 permit names a different invocation"
    );
    Ok(true)
}

fn limits() -> Result<()> {
    let cgroup = format!("/system.slice/{UNIT}");
    ensure!(
        unsafe { libc::getuid() } == 1001
            && unsafe { libc::geteuid() } == 1001
            && unsafe { libc::getgid() } == 1003
            && unsafe { libc::getegid() } == 1003
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::{cgroup}"),
        "outside the epoch 170 held service identity"
    );
    let group = Path::new("/sys/fs/cgroup/system.slice").join(UNIT);
    let cpu = fs::read_to_string(group.join("cpu.max"))?;
    let values = cpu
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        values.len() == 2
            && values[1] > 0
            && values[1].checked_mul(9) == Some(values[0])
            && fs::read_to_string(group.join("memory.max"))?.trim() == (68_u64 << 30).to_string()
            && fs::read_to_string(group.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(group.join("pids.max"))?.trim() == "1024",
        "epoch 170 held service limits differ from the native route"
    );
    Ok(())
}

fn verify_image(value: &Value, path: &Path, expected: &str) -> Result<()> {
    let expected_image = reference(path, expected);
    ensure!(
        value["reference"]["sha256"] == expected,
        "unexpected held build digest"
    );
    let actual = image(&expected_image)?;
    let handle = file(path, 0)?;
    readonly(&handle)?;
    let meta = handle.metadata()?;
    ensure!(
        actual["device"] == value["device"]
            && actual["inode"] == value["inode"]
            && actual["bytes"] == value["bytes"]
            && meta.dev() == number(&actual, "device")?
            && meta.ino() == number(&actual, "inode")?
            && meta.len() == number(&actual, "bytes")?,
        "epoch 170 held executable identity changed"
    );
    Ok(())
}

fn verify_archive_inputs(source: &Value) -> Result<()> {
    let snapshot = &source["bootstrap_identity"];
    let name = Path::new(string(&source["bootstrap"], "source_path")?)
        .file_name()
        .context("missing held bootstrap filename")?;
    let target =
        Path::new("/usr/local/lib/jetstreamer/horizon-standard-local-input170-20261110-v1")
            .join(name);
    let handle = file(&target, 1001)?;
    readonly(&handle)?;
    let m = handle.metadata()?;
    ensure!(
        snapshot["path"] == source["bootstrap"]["source_path"]
            && snapshot["sha256"] == BOOT_SHA
            && json!([m.ctime(), m.ctime_nsec()]) == snapshot["ctime"]
            && m.dev() == number(snapshot, "device")?
            && m.ino() == number(snapshot, "inode")?
            && m.len() == number(snapshot, "length")?,
        "held bootstrap projection changed"
    );

    let indexes = source["indexes"]
        .as_array()
        .context("missing held compact indexes")?;
    ensure!(
        indexes.len() == 3,
        "different held compact index population"
    );
    for index in indexes {
        let path = Path::new(string(index, "target")?);
        ensure!(
            path.starts_with(run(NEW_RUN).join("output/compact-indexes")),
            "foreign held compact index"
        );
        let handle = file(path, 1001)?;
        readonly(&handle)?;
        let m = handle.metadata()?;
        let identity = &index["identity"];
        let nanos = |sec: i64, ns: i64| i128::from(sec) * 1_000_000_000 + i128::from(ns);
        ensure!(
            identity[0].as_u64() == Some(m.dev())
                && identity[1].as_u64() == Some(m.ino())
                && identity[2].as_u64() == Some(m.len())
                && identity[3].as_i64().map(i128::from) == Some(nanos(m.mtime(), m.mtime_nsec()))
                && identity[4].as_i64().map(i128::from) == Some(nanos(m.ctime(), m.ctime_nsec())),
            "held compact index projection changed: {}",
            path.display()
        );
    }
    let manifest = Path::new(PACKAGE).join("preflight-170-v4.json");
    ensure!(
        source["manifest"] == reference(&manifest, MANIFEST_SHA),
        "foreign held manifest"
    );
    readonly(&file(&manifest, 0)?)?;
    doc(&manifest, MANIFEST_SHA, 0)?;
    Ok(())
}

fn command(profile: &Value) -> Result<Command> {
    ensure!(
        profile["schema"] == "horizon-epoch170-full-metered-source-preflight-v1"
            && profile["epoch"] == 170
            && profile["actor"]["unit"] == UNIT
            && profile["actor"]["run"] == json!(run(NEW_RUN))
            && profile["actor"]["requires_held_before_useful_work"] == true
            && profile["replay_launch_authorized"] == false
            && profile["archive_publication_authorized"] == false,
        "foreign epoch 170 held profile"
    );
    let source = &profile["source"];
    let node = Path::new(PACKAGE).join("jetstreamer-node");
    ensure!(
        source["worker_target"] == WORKER_TARGET
            && source["worker"]["reference"]["path"] == WORKER
            && source["node"]["reference"]["path"] == json!(node),
        "different held runtime projections"
    );
    verify_image(&source["node"], &node, NODE_SHA)?;
    verify_image(&source["worker"], Path::new(WORKER_TARGET), WORKER_SHA)?;
    verify_archive_inputs(source)?;

    let args: Vec<String> =
        serde_json::from_value(profile["actor"]["producer_argv_after_protection"].clone())?;
    let node_text = node.to_str().context("node path")?;
    let (manager, payload) = args.split_at(
        args.iter()
            .position(|a| a == node_text)
            .context("missing held producer argv")?,
    );
    ensure!(
        manager.first().is_some_and(|a| a == "/usr/bin/systemd-run")
            && manager.iter().any(|a| a == &format!("--unit={UNIT}"))
            && payload
                .iter()
                .skip(1)
                .any(|a| a == "--root-checkpoint-cohort")
            && payload
                .iter()
                .skip(1)
                .any(|a| a == &format!("--cohort-manifest-fingerprint={FINGERPRINT}")),
        "different held whole-epoch command"
    );
    let mut envs = BTreeMap::new();
    for entry in manager.iter().filter_map(|a| a.strip_prefix("--setenv=")) {
        let (name, val) = entry
            .split_once('=')
            .context("invalid held environment entry")?;
        ensure!(
            !name.is_empty() && name != "INVOCATION_ID" && envs.insert(name, val).is_none(),
            "duplicate or foreign held environment name"
        );
    }
    ensure!(
        envs.get("JETSTREAMER_HISTORICAL_WORKER_V1_5_6") == Some(&WORKER_TARGET),
        "unbound held historical worker environment"
    );
    let mut command = Command::new(node);
    command.args(&payload[1..]).env_clear().envs(envs);
    Ok(command)
}

pub(super) fn hold(digest: &str) -> Result<Value> {
    let started = Instant::now();
    limits()?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(valid_iid(&iid), "missing epoch 170 native invocation ID");
    let path = Path::new(PROFILE);
    let handle = file(path, 0)?;
    let before = handle.metadata()?;
    ensure!(
        before.gid() == 0 && before.mode() & 0o7777 == 0o444,
        "unsealed epoch 170 payload"
    );
    readonly(&handle)?;
    let mut command = command(&doc(path, digest, 0)?)?;
    stable(path, &handle, &before)?;
    let mut heartbeat = started + HEARTBEAT;
    println!(
        "{}",
        json!({"phase":"held","epoch":170,"invocation_id":iid,"pid":std::process::id(),"payload_sha256":digest})
    );
    while started.elapsed() < HOLD {
        if permit(Path::new(PERMIT), &iid)? {
            limits()?;
            stable(path, &handle, &before)?;
            ensure!(started.elapsed() < HOLD, "epoch 170 guard release expired");
            println!(
                "{}",
                json!({"phase":"released","epoch":170,"invocation_id":iid,"elapsed_seconds":started.elapsed().as_secs()})
            );
            return Err(command.env("INVOCATION_ID", &iid).exec().into());
        }
        if Instant::now() >= heartbeat {
            println!(
                "{}",
                json!({"phase":"waiting_for_guard_release","epoch":170,"invocation_id":iid,"elapsed_seconds":started.elapsed().as_secs()})
            );
            heartbeat += HEARTBEAT;
        }
        thread::sleep(Duration::from_millis(200));
    }
    bail!("epoch 170 native guard did not release the held replay before its deadline")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invocation_requires_nonzero_lowercase_hex() {
        assert!(valid_iid("0123456789abcdef0123456789abcdef"));
        assert!(!valid_iid("00000000000000000000000000000000"));
        assert!(!valid_iid("0123456789abcdeF0123456789abcdef"));
        assert!(!valid_iid("0123456789abcdef"));
    }

    #[test]
    fn absent_permit_keeps_the_payload_held() {
        assert!(
            !permit(
                Path::new("/proc/self/horizon-170-no-permit"),
                "0123456789abcdef0123456789abcdef"
            )
            .unwrap()
        );
    }
}
