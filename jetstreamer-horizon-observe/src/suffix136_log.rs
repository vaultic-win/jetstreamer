//! Closed current diagnostic child-log source. The generic O_APPEND policy is unchanged.
use super::*;
use std::io::{Seek, SeekFrom};
const UNIT: &str = "horizon-qualify-136-hourly-suffix-reproduction-20261027-v8.service";
const IID: &str = "c0c214c5b7c440449298bdb90d3f3bd3";
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch136-hourly-suffix-run-parent-20261027-v8/reproduction";
const ENTRY_SHA: &str = "fa182109cc6a6308ac7129fffb0628007f0a1df0444778b5a69d8d15f038d237";
const NODE: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch136-hourly-suffix-tools-20261027-v8/jetstreamer-node";
const NODE_SHA: &str = "c60addae46e06ee83b6e3cec0d027a2786386bd7ed06b865d092b634bf70eda4";
const DEVICE: u64 = 64512;
const INODE: u64 = 96617392;
const MAX_TAIL: u64 = 64 << 20;

#[derive(Debug, Serialize)]
pub(super) struct Evidence {
    source_kind: &'static str,
    path: PathBuf,
    device: u64,
    inode: u64,
    entry_sha256: &'static str,
    node_sha256: &'static str,
    helper_invocation_id: &'static str,
    node_pid: u64,
    node_start_ticks: u64,
    snapshot_length_bytes: u64,
    read_offset_bytes: u64,
    read_bytes: u64,
    read_sha256: String,
    supervised_child_stdout_binding_verified: bool,
    stdout_append_flag_present: bool,
}
pub(super) fn matches(r: &ReplayConfig) -> bool {
    r.range == "136"
        && r.controller_unit == UNIT
        && r.producer_unit == UNIT
        && r.expected_controller_invocation_id == IID
        && r.expected_producer_invocation_id == IID
        && r.scratch_path == Path::new(ROOT)
        && r.worker_executable_basename == "historical-worker"
        && r.append_log.is_none()
}
fn log_path() -> PathBuf {
    Path::new(ROOT).join("output/reproduction.log")
}
fn custody(m: &fs::Metadata) -> Result<()> {
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.nlink() == 1
            && m.dev() == DEVICE
            && m.ino() == INODE,
        "suffix 136 log custody/identity differs"
    );
    Ok(())
}
fn start_ticks(raw: &str) -> Result<u64> {
    raw.rsplit_once(") ")
        .context("node stat malformed")?
        .1
        .split_whitespace()
        .nth(19)
        .context("node start ticks absent")?
        .parse()
        .context("node start ticks malformed")
}
fn entry() -> Result<Value> {
    let path = Path::new(ROOT).join("receipts/entry.json");
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 1 << 20,
        "suffix 136 entry custody differs"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    (&mut f).take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == m.len()
            && f.metadata()?.ino() == m.ino()
            && sha256(&bytes) == ENTRY_SHA,
        "suffix 136 entry digest differs"
    );
    let value: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        value["schema"] == "jetstreamer-epoch136-hourly-suffix-entry-v1"
            && value["invocation_id"] == IID
            && value["bootstrap"] == 59_176_548u64
            && value["first"] == 59_176_549u64
            && value["end"] == 59_183_944u64
            && value["publication_authorized"] == false,
        "suffix 136 entry scope differs"
    );
    Ok(value)
}
fn owner(unit: &str, iid: &str, pid: u64, cgroup: &str) -> Result<()> {
    ensure!(
        unit == UNIT && iid == IID && pid > 0 && cgroup.starts_with('/'),
        "suffix 136 owner scope differs"
    );
    let output = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            UNIT,
            "--no-pager",
            "--property=Id,InvocationID,MainPID,ControlGroup,ActiveState,SubState,NRestarts",
        ])
        .output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 16384,
        "suffix 136 owner unreadable"
    );
    let text = std::str::from_utf8(&output.stdout)?;
    let fields = text
        .lines()
        .filter_map(|s| s.split_once('='))
        .collect::<BTreeMap<_, _>>();
    ensure!(
        fields.get("Id") == Some(&UNIT)
            && fields.get("InvocationID") == Some(&IID)
            && fields.get("MainPID").and_then(|s| s.parse::<u64>().ok()) == Some(pid)
            && fields.get("ControlGroup") == Some(&cgroup)
            && fields.get("ActiveState") == Some(&"active")
            && fields.get("SubState") == Some(&"running")
            && fields.get("NRestarts") == Some(&"0"),
        "suffix 136 helper changed"
    );
    Ok(())
}
fn executable(pid: u64) -> Result<()> {
    let path = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure!(
        fs::read_link(&path)? == Path::new(NODE),
        "suffix 136 child executable path differs"
    );
    let mut f = File::open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && m.len() <= 128 << 20,
        "suffix 136 child executable custody differs"
    );
    let mut hash = Sha256::new();
    let mut buffer = [0; 128 << 10];
    loop {
        let n = f.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    ensure!(
        format!("{:x}", hash.finalize()) == NODE_SHA && f.metadata()?.ino() == m.ino(),
        "suffix 136 child executable digest differs"
    );
    Ok(())
}
fn binding(helper_pid: u64, cgroup: &str) -> Result<(u64, u64)> {
    let entry = entry()?;
    let pid = entry["node_pid"]
        .as_u64()
        .filter(|p| *p > 1)
        .context("suffix 136 child PID missing")?;
    let ticks = entry["node_start_ticks"]
        .as_u64()
        .filter(|p| *p > 0)
        .context("suffix 136 child start missing")?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let field = |prefix: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(prefix))
            .map(str::trim)
    };
    ensure!(
        field("PPid:").and_then(|s| s.parse::<u64>().ok()) == Some(helper_pid)
            && field("Uid:") == Some("1001\t1001\t1001\t1001")
            && field("Gid:") == Some("1003\t1003\t1003\t1003")
            && field("NoNewPrivs:") == Some("1")
            && field("CapEff:") == Some("0000000000000000"),
        "suffix 136 child parent/credentials differ"
    );
    ensure!(
        start_ticks(&fs::read_to_string(format!("/proc/{pid}/stat"))?)? == ticks
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?
                .lines()
                .any(|l| l.strip_prefix("0::") == Some(cgroup)),
        "suffix 136 child incarnation/cgroup differs"
    );
    executable(pid)?;
    let path = log_path();
    for number in [1, 2] {
        let fd = PathBuf::from(format!("/proc/{pid}/fd/{number}"));
        ensure!(
            fs::read_link(&fd)? == path,
            "suffix 136 child output path differs"
        );
        custody(&fs::metadata(&fd)?)?;
        let info = fs::read_to_string(format!("/proc/{pid}/fdinfo/{number}"))?;
        let flags = info
            .lines()
            .find_map(|l| l.strip_prefix("flags:\t"))
            .context("child output flags missing")?;
        let flags = u32::from_str_radix(flags.trim(), 8)?;
        ensure!(
            flags & libc::O_ACCMODE as u32 == libc::O_WRONLY as u32
                && flags & libc::O_APPEND as u32 == 0,
            "suffix 136 child output flags differ from sealed writer"
        );
    }
    Ok((pid, ticks))
}
pub(super) fn observe(
    producer: &UnitObservation,
    since: u64,
    until: u64,
) -> Result<ProgressWindow> {
    let cgroup = producer
        .control_group
        .to_str()
        .context("suffix 136 cgroup is not UTF-8")?;
    owner(
        &producer.unit,
        &producer.invocation_id,
        producer.main_pid,
        cgroup,
    )?;
    let node = binding(producer.main_pid, cgroup)?;
    let path = log_path();
    ensure!(path.canonicalize()? == path, "suffix 136 log alias");
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let before = f.metadata()?;
    custody(&before)?;
    let offset = before.len().saturating_sub(MAX_TAIL);
    f.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::new();
    (&mut f)
        .take(before.len() - offset)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() - offset && f.metadata()?.len() >= before.len(),
        "suffix 136 log truncated"
    );
    custody(&f.metadata()?)?;
    custody(&fs::symlink_metadata(&path)?)?;
    owner(
        &producer.unit,
        &producer.invocation_id,
        producer.main_pid,
        cgroup,
    )?;
    ensure!(
        node == binding(producer.main_pid, cgroup)?,
        "suffix 136 child changed during log read"
    );
    let mut result = progress_window_from_points(
        IID,
        since,
        until,
        append_log::points(&bytes, offset, since, until)?,
    )?;
    result.suffix136_log_evidence = Some(Evidence {
        source_kind: "exact-supervised-136-child-stdout",
        path,
        device: DEVICE,
        inode: INODE,
        entry_sha256: ENTRY_SHA,
        node_sha256: NODE_SHA,
        helper_invocation_id: IID,
        node_pid: node.0,
        node_start_ticks: node.1,
        snapshot_length_bytes: before.len(),
        read_offset_bytes: offset,
        read_bytes: bytes.len() as u64,
        read_sha256: sha256(&bytes),
        supervised_child_stdout_binding_verified: true,
        stdout_append_flag_present: false,
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_cannot_select_other_generations_owners_or_ordinary_logs() {
        let value = serde_json::json!({"range":"136","controller_unit":UNIT,"producer_unit":UNIT,"expected_controller_invocation_id":IID,"expected_producer_invocation_id":IID,"scratch_path":ROOT,"worker_executable_basename":"historical-worker"});
        let r: ReplayConfig = serde_json::from_value(value.clone()).unwrap();
        assert!(matches(&r));
        for key in [
            "range",
            "controller_unit",
            "producer_unit",
            "expected_controller_invocation_id",
            "expected_producer_invocation_id",
            "scratch_path",
            "worker_executable_basename",
        ] {
            let mut changed = value.clone();
            changed[key] = serde_json::json!("other");
            let r: ReplayConfig = serde_json::from_value(changed).unwrap();
            assert!(!matches(&r), "{key}");
        }
    }
    #[test]
    fn stat_parser_handles_parentheses_in_process_names() {
        let raw = format!(
            "123 (name ) with spaces) S {}",
            (1..=21)
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );
        assert_eq!(start_ticks(&raw).unwrap(), 19);
        assert!(start_ticks("bad").is_err());
    }
    #[test]
    #[ignore = "root exact live child identity/FD capability only; no progress read or resource observation"]
    fn actual_live_child_binding_is_readonly_and_separate_from_generic_append_stdout() {
        let result = Command::new("/usr/bin/systemctl")
            .args(["show", UNIT, "--property=MainPID,ControlGroup"])
            .output()
            .unwrap();
        let text = std::str::from_utf8(&result.stdout).unwrap();
        let fields = text
            .lines()
            .filter_map(|s| s.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let pid = fields["MainPID"].parse().unwrap();
        let cg = fields["ControlGroup"];
        owner(UNIT, IID, pid, cg).unwrap();
        binding(pid, cg).unwrap();
    }
}
