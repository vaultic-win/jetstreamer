//! Classifies one separately admitted, exact noncanonical 185 park transport.
//! This policy grants no upload, replay, overwrite, deletion or retirement authority.
use super::*;

const PROGRAM: &str =
    "/usr/local/lib/jetstreamer/horizon-node02-holding-epoch185-tools-20261024-v2/jetstreamer-r2";
const PROGRAM_SHA: &str = "0f0f7c9475b69b3371098dfb0b7702a772de989189d0974359c2569020caab1f";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch185-singleton-20261020-v1/lane-a/private/destination-9d993937f539bf7591c81fd831c0b525eead17dd3e52088d2fc90cec7f9e6fa9/work/root-cohort-185-185/run-333127-1792725435594713064/archives/epoch-185.jet";
const LENGTH: u64 = 56_206_322_555;
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Admission {
    schema: String,
    host: String,
    pub(super) unit: String,
    program: Bound,
    park_spec: Bound,
    mapping: Bound,
    eligibility: Bound,
    source: PathBuf,
    length: u64,
    sha256: String,
    holding_prefix: String,
    classification_only: bool,
    noncanonical_transport_only: bool,
    replay_launch_authorized: bool,
    canonical_publication_authorized: bool,
    local_retirement_authorized: bool,
    remote_overwrite_authorized: bool,
    remote_delete_authorized: bool,
    growth_claim_release_authorized: bool,
    r2_mutation_authority_granted: bool,
    #[serde(skip)]
    validated_program: Option<ProgramIdentity>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProgramIdentity {
    device: u64,
    inode: u64,
    length: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn program_identity(m: &fs::Metadata) -> ProgramIdentity {
    ProgramIdentity {
        device: m.dev(),
        inode: m.ino(),
        length: m.len(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParkSpec {
    schema: String,
    mapping: Bound,
    eligibility: Bound,
    source: PathBuf,
    length: u64,
    sha256: String,
}
fn same(a: &Bound, b: &Bound) -> bool {
    a.path == b.path && a.sha256 == b.sha256
}
fn policy(a: &Admission, p: &ParkSpec, m: &Value, e: &Value) -> Result<()> {
    ensure!(
        a.schema == "jetstreamer-horizon-holding185-park-cadence-admission-v2"
            && a.host == "dev-samjohnson"
            && a.classification_only
            && a.noncanonical_transport_only
            && a.program.path == Path::new(PROGRAM)
            && a.program.sha256 == PROGRAM_SHA
            && a.mapping.path == Path::new(MAPPING)
            && a.mapping.sha256 == MAPPING_SHA
            && a.holding_prefix == "node_02/"
            && a.source == Path::new(SOURCE)
            && a.length == LENGTH
            && is_sha(&a.sha256)
            && is_sha(&a.park_spec.sha256)
            && is_sha(&a.eligibility.sha256)
            && a.unit.len() <= 255
            && a.unit.starts_with("jetstreamer-")
            && a.unit.ends_with(".service")
            && a.unit.contains("185")
            && a.unit != CONTROLLER
            && a.unit != PRODUCER
            && a.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "185 holding classification policy has foreign scope"
    );
    ensure!(
        !a.replay_launch_authorized
            && !a.canonical_publication_authorized
            && !a.local_retirement_authorized
            && !a.remote_overwrite_authorized
            && !a.remote_delete_authorized
            && !a.growth_claim_release_authorized
            && !a.r2_mutation_authority_granted,
        "185 holding classification cannot grant mutation or replay authority"
    );
    ensure!(
        p.schema == "jetstreamer-horizon-holding-park-plan-v2"
            && same(&p.mapping, &a.mapping)
            && same(&p.eligibility, &a.eligibility)
            && p.source == a.source
            && p.length == LENGTH
            && p.sha256 == a.sha256,
        "185 holding classification requires the exact sealed park spec"
    );
    ensure!(
        m["schema"] == "jetstreamer-horizon-host-holding-prefix-v2"
            && m["host"] == a.host
            && m["prefix"] == "node_02/"
            && m["user_provided_prefix"] == true
            && m["authorization_reference"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "185 holding mapping is not the authenticated node_02 mapping"
    );
    ensure!(
        e["schema"] == "jetstreamer-horizon-holding-eligibility-v2"
            && e["host"] == a.host
            && e["epoch"] == 185
            && e["source"] == SOURCE
            && e["length"] == LENGTH
            && e["sha256"] == a.sha256
            && e["mapping"] == serde_json::to_value(&a.mapping)?
            && e["closed"] == true
            && e["content_class"] == "public-chain-artifact"
            && e["credentials_config_and_logs_excluded"] == true
            && e["artifact_kind"] == "retained-failed-partial-archive"
            && e["interrupted_container_unvalidated"] == true
            && e["valid_prefix_established"] == false
            && e["canonical_archive"] == false
            && e["local_retirement_authorized"] == false
            && e["failure_repaired"] == false
            && e["runtime_checkpoint_qualified"] == false
            && e["job_resume_authorized"] == false
            && e["replay_launch_authorized"] == false
            && e["publication_authorized"] == false
            && e["source_identity"]["device"] == 64512
            && e["source_identity"]["inode"] == 100270097
            && e["source_identity"]["length"] == LENGTH,
        "185 park eligibility is not the exact closed failed partial inspection"
    );
    Ok(())
}
pub(super) fn load(b: &Bound) -> Result<Admission> {
    let mut a: Admission = serde_json::from_value(bound_json(b, true)?)?;
    let p: ParkSpec = serde_json::from_value(bound_json(&a.park_spec, true)?)?;
    policy(
        &a,
        &p,
        &bound_json(&a.mapping, true)?,
        &bound_json(&a.eligibility, true)?,
    )?;
    let before = program_identity(&fs::symlink_metadata(&a.program.path)?);
    tool_ok(&a.program)?;
    ensure!(
        program_identity(&fs::symlink_metadata(&a.program.path)?) == before,
        "185 qualified program changed across hash proof"
    );
    a.validated_program = Some(before);
    Ok(a)
}
fn unit_object(name: &str) -> String {
    let mut out = String::from("/org/freedesktop/systemd1/unit/");
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("_{b:02x}"));
        }
    }
    out
}
fn dbus_property(path: &str, interface: &str, name: &str) -> Result<Value> {
    let out = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--json=short",
            "get-property",
            "org.freedesktop.systemd1",
            path,
            interface,
            name,
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "185 holding native job property unavailable"
    );
    Ok(serde_json::from_slice(&out.stdout)?)
}
fn start_job(name: &str) -> Result<Value> {
    let unit = unit_object(name);
    let slot = dbus_property(&unit, "org.freedesktop.systemd1.Unit", "Job")?;
    ensure!(
        slot["type"] == "(uo)",
        "185 holding start job signature differs"
    );
    let parts = slot["data"]
        .as_array()
        .context("185 holding start job tuple")?;
    ensure!(parts.len() == 2, "185 holding start job tuple length");
    let id = parts[0].as_u64().context("185 holding start job id")?;
    let path = parts[1].as_str().context("185 holding start job path")?;
    ensure!(
        id > 0 && path == format!("/org/freedesktop/systemd1/job/{id}"),
        "185 holding start job path differs"
    );
    let native_id = dbus_property(path, "org.freedesktop.systemd1.Job", "Id")?;
    let kind = dbus_property(path, "org.freedesktop.systemd1.Job", "JobType")?;
    let state = dbus_property(path, "org.freedesktop.systemd1.Job", "State")?;
    let owner = dbus_property(path, "org.freedesktop.systemd1.Job", "Unit")?;
    ensure!(
        native_id["type"] == "u"
            && native_id["data"] == id
            && kind["type"] == "s"
            && kind["data"] == "start"
            && state["type"] == "s"
            && state["data"] == "running"
            && owner["type"] == "(so)"
            && owner["data"] == json!([name, unit]),
        "185 holding job is not this unit's running start job"
    );
    Ok(json!({"id":id,"path":path,"type":"start","state":"running","unit":name}))
}
fn live_manager(name: &str) -> Result<Value> {
    let out=Command::new("/usr/bin/systemctl").args(["show",name,"--all","--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,Restart,ControlGroup,Type"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() < 16384,
        "185 holding owner metadata unavailable"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = l
            .split_once('=')
            .context("185 holding owner metadata shape")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate 185 holding owner field"
        );
    }
    let mut v = Value::Object(m);
    if v["Type"] == "oneshot" && v["ActiveState"] == "activating" && v["SubState"] == "start" {
        v["holding_start_job"] = start_job(name)?;
    }
    Ok(v)
}

fn live_shape(a: &Admission, v: &Value) -> Result<u32> {
    let text = v["MainPID"]
        .as_str()
        .context("185 holding MainPID missing")?;
    let pid = text.parse::<u32>()?;
    let iid = v["InvocationID"]
        .as_str()
        .context("185 holding invocation missing")?;
    let ordinary = v["Type"] == "exec"
        && v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["Job"] == ""
        && v["ControlPID"] == "0";
    let job = &v["holding_start_job"];
    let oneshot = v["Type"] == "oneshot"
        && v["ActiveState"] == "activating"
        && v["SubState"] == "start"
        && v["Job"].as_str().is_some_and(|s| !s.is_empty())
        && job["id"].as_u64().is_some_and(|n| n > 0)
        && job["type"] == "start"
        && job["state"] == "running"
        && job["unit"] == a.unit
        && (v["ControlPID"] == "0" || v["ControlPID"] == text);
    ensure!(
        pid > 1
            && pid.to_string() == text
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && v["Id"] == a.unit
            && v["LoadState"] == "loaded"
            && (ordinary || oneshot)
            && v["NRestarts"] == "0"
            && v["Restart"] == "no",
        "185 holding owner is not a stable executing zero-restart park invocation"
    );
    Ok(pid)
}
fn proc_bytes(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let mut bytes = Vec::new();
    (&mut f).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "185 holding process metadata exceeds bound"
    );
    Ok(bytes)
}
fn argv(a: &Admission, bytes: &[u8]) -> Result<()> {
    ensure!(bytes.last() == Some(&0), "185 holding argv framing missing");
    let args = bytes[..bytes.len() - 1]
        .split(|b| *b == 0)
        .collect::<Vec<_>>();
    let path = a
        .park_spec
        .path
        .to_str()
        .context("185 holding spec path encoding")?;
    let expected = [
        PROGRAM,
        "holding-park",
        path,
        "--spec-sha256",
        a.park_spec.sha256.as_str(),
        "--self-sha256",
        PROGRAM_SHA,
    ];
    ensure!(
        args.len() == expected.len() && args.iter().zip(expected).all(|(a, b)| *a == b.as_bytes()),
        "185 live process argv is not the exact qualified holding-park command"
    );
    Ok(())
}
fn start_time(bytes: &[u8], pid: u32) -> Result<u64> {
    let text = std::str::from_utf8(bytes)?;
    ensure!(
        text.starts_with(&format!("{pid} (")),
        "185 holding process stat PID differs"
    );
    let close = text
        .rfind(") ")
        .context("185 holding process stat framing")?;
    let fields = text[close + 2..].split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() >= 20 && !matches!(fields[0], "Z" | "X" | "x"),
        "185 holding process not live"
    );
    let at = fields[19].parse::<u64>()?;
    ensure!(at > 0, "185 holding process start missing");
    Ok(at)
}
#[derive(Debug, PartialEq, Eq)]
struct Process {
    pid: u32,
    start: u64,
    exe_device: u64,
    exe_inode: u64,
    cmdline: Vec<u8>,
    cgroup: Vec<u8>,
}
fn sole_process(bytes: &[u8], pid: u32) -> Result<()> {
    let ids = std::str::from_utf8(bytes)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !ids.is_empty() && ids.iter().all(|n| *n == pid),
        "185 holding unit has an additional or missing process"
    );
    Ok(())
}
fn process(a: &Admission, v: &Value, pid: u32) -> Result<Process> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let stat = proc_bytes(&root.join("stat"), 8192)?;
    let start = start_time(&stat, pid)?;
    let cmdline = proc_bytes(&root.join("cmdline"), 65536)?;
    argv(a, &cmdline)?;
    ensure!(
        fs::read_link(root.join("exe"))? == a.program.path,
        "185 holding MainPID executable path differs"
    );
    let exe = fs::metadata(root.join("exe"))?;
    let named = fs::symlink_metadata(&a.program.path)?;
    ensure!(
        exe.is_file()
            && a.validated_program == Some(program_identity(&exe))
            && !named.file_type().is_symlink()
            && exe.dev() == named.dev()
            && exe.ino() == named.ino(),
        "185 holding MainPID is not executing the pinned program inode"
    );
    let status = proc_bytes(&root.join("status"), 65536)?;
    let uid = std::str::from_utf8(&status)?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .context("185 holding process UID missing")?;
    ensure!(
        uid.split_whitespace().collect::<Vec<_>>() == ["0", "0", "0", "0"],
        "185 holding process is not the root holding owner"
    );
    let group = v["ControlGroup"]
        .as_str()
        .context("185 holding cgroup missing")?;
    ensure!(
        group.starts_with('/') && group != "/" && !group.split('/').any(|s| s == ".." || s == "."),
        "185 holding cgroup invalid"
    );
    let cgroup = proc_bytes(&root.join("cgroup"), 65536)?;
    ensure!(
        std::str::from_utf8(&cgroup)?
            .lines()
            .any(|l| l == format!("0::{group}")),
        "185 holding PID is outside the exact unit cgroup"
    );
    let members = Path::new("/sys/fs/cgroup")
        .join(group.trim_start_matches('/'))
        .join("cgroup.procs");
    sole_process(&proc_bytes(&members, 65536)?, pid)?;
    Ok(Process {
        pid,
        start,
        exe_device: exe.dev(),
        exe_inode: exe.ino(),
        cmdline,
        cgroup,
    })
}
fn same_owner(a: &Value, b: &Value) -> Result<()> {
    for key in [
        "Id",
        "LoadState",
        "ActiveState",
        "SubState",
        "MainPID",
        "InvocationID",
        "NRestarts",
        "Job",
        "Restart",
    ] {
        ensure!(
            a[key] == b[key],
            "185 holding owner changed during classification"
        );
    }
    Ok(())
}
pub(super) fn verify_live(a: &Admission, observed: &Value) -> Result<()> {
    let before = live_manager(&a.unit)?;
    let pid = live_shape(a, &before)?;
    same_owner(observed, &before)?;
    let first = process(a, &before, pid)?;
    let after = live_manager(&a.unit)?;
    let again = live_shape(a, &after)?;
    ensure!(
        before == after,
        "185 holding native owner/start job changed"
    );
    let second = process(a, &after, again)?;
    ensure!(
        first == second,
        "185 holding process identity/exe/argv changed during classification"
    );
    let spec: ParkSpec = serde_json::from_value(bound_json(&a.park_spec, true)?)?;
    ensure!(
        spec.source == Path::new(SOURCE) && spec.length == LENGTH && spec.sha256 == a.sha256,
        "185 holding spec changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Value, ParkSpec, Value, Value) {
        let map = json!({"path":MAPPING,"sha256":MAPPING_SHA});
        let elig = json!({"path":"/sealed/actual185-eligibility.json","sha256":"a".repeat(64)});
        let a = json!({"schema":"jetstreamer-horizon-holding185-park-cadence-admission-v2","host":"dev-samjohnson",
            "unit":"jetstreamer-holding-park185-fixture.service","program":{"path":PROGRAM,"sha256":PROGRAM_SHA},
            "park_spec":{"path":"/sealed/park185.json","sha256":"c".repeat(64)},"mapping":map,"eligibility":elig,
            "source":SOURCE,"length":LENGTH,"sha256":"b".repeat(64),"holding_prefix":"node_02/",
            "classification_only":true,"noncanonical_transport_only":true,"replay_launch_authorized":false,
            "canonical_publication_authorized":false,"local_retirement_authorized":false,"remote_overwrite_authorized":false,
            "remote_delete_authorized":false,"growth_claim_release_authorized":false,"r2_mutation_authority_granted":false});
        let p:ParkSpec=serde_json::from_value(json!({"schema":"jetstreamer-horizon-holding-park-plan-v2",
            "mapping":map,"eligibility":elig,"source":SOURCE,"length":LENGTH,"sha256":"b".repeat(64)})).unwrap();
        let m = json!({"schema":"jetstreamer-horizon-host-holding-prefix-v2","host":"dev-samjohnson","prefix":"node_02/",
            "user_provided_prefix":true,"authorization_reference":"fixture"});
        let e = json!({"schema":"jetstreamer-horizon-holding-eligibility-v2","host":"dev-samjohnson","epoch":185,
            "source":SOURCE,"length":LENGTH,"sha256":"b".repeat(64),"mapping":map,"closed":true,
            "content_class":"public-chain-artifact","credentials_config_and_logs_excluded":true,
            "artifact_kind":"retained-failed-partial-archive","interrupted_container_unvalidated":true,"valid_prefix_established":false,
            "canonical_archive":false,"local_retirement_authorized":false,"failure_repaired":false,"runtime_checkpoint_qualified":false,
            "job_resume_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,
            "source_identity":{"device":64512,"inode":100270097,"length":LENGTH}});
        (a, p, m, e)
    }
    #[test]
    fn policy_is_exact_noncanonical_park_and_grants_no_authority() {
        let (v, p, m, e) = fixture();
        let a: Admission = serde_json::from_value(v.clone()).unwrap();
        policy(&a, &p, &m, &e).unwrap();
        for key in [
            "replay_launch_authorized",
            "canonical_publication_authorized",
            "local_retirement_authorized",
            "remote_overwrite_authorized",
            "remote_delete_authorized",
            "growth_claim_release_authorized",
            "r2_mutation_authority_granted",
        ] {
            let mut bad = v.clone();
            bad[key] = json!(true);
            let bad: Admission = serde_json::from_value(bad).unwrap();
            assert!(policy(&bad, &p, &m, &e).is_err(), "{key}");
        }
        for (key, value) in [
            ("source", json!("/other/epoch-185.jet")),
            ("holding_prefix", json!("node_01/")),
            ("unit", json!(PRODUCER)),
            ("classification_only", json!(false)),
        ] {
            let mut bad = v.clone();
            bad[key] = value;
            assert!(
                policy(&serde_json::from_value(bad).unwrap(), &p, &m, &e).is_err(),
                "{key}"
            );
        }
        let mut wrong = e.clone();
        wrong["valid_prefix_established"] = json!(true);
        assert!(policy(&a, &p, &m, &wrong).is_err());
        let mut wrong = m;
        wrong["prefix"] = json!("foundation_node_01/");
        assert!(policy(&a, &p, &wrong, &e).is_err());
        let mut unknown = v;
        unknown["whitelist"] = json!([PRODUCER]);
        assert!(serde_json::from_value::<Admission>(unknown).is_err());
    }
    fn args(a: &Admission, verb: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        for s in [
            PROGRAM,
            verb,
            a.park_spec.path.to_str().unwrap(),
            "--spec-sha256",
            &a.park_spec.sha256,
            "--self-sha256",
            PROGRAM_SHA,
        ] {
            bytes.extend_from_slice(s.as_bytes());
            bytes.push(0);
        }
        bytes
    }
    #[test]
    fn argv_rejects_every_other_r2_verb_and_additional_flags() {
        let (v, _, _, _) = fixture();
        let a: Admission = serde_json::from_value(v).unwrap();
        argv(&a, &args(&a, "holding-park")).unwrap();
        for verb in [
            "sync",
            "holding-restore",
            "holding-retire185",
            "status-publish",
            "restore",
            "holding-check-retire185",
        ] {
            assert!(argv(&a, &args(&a, verb)).is_err(), "{verb}");
        }
        let mut extra = args(&a, "holding-park");
        extra.extend_from_slice(b"--overwrite-existing\0");
        assert!(argv(&a, &extra).is_err());
        let mut bad = args(&a, "holding-park");
        bad[0] = b'X';
        assert!(argv(&a, &bad).is_err());
        let mut bad = args(&a, "holding-park");
        bad.pop();
        assert!(argv(&a, &bad).is_err());
    }
    #[test]
    fn executing_oneshot_requires_positive_pid_iid_and_own_running_start_job() {
        let (v, _, _, _) = fixture();
        let a: Admission = serde_json::from_value(v).unwrap();
        let owner = json!({"Id":a.unit,"Type":"oneshot","LoadState":"loaded","ActiveState":"activating","SubState":"start",
            "MainPID":"1234","ControlPID":"0","InvocationID":"d".repeat(32),"NRestarts":"0","Restart":"no","Job":"42",
            "holding_start_job":{"id":42,"type":"start","state":"running","unit":a.unit}});
        live_shape(&a, &owner).unwrap();
        for (key, value) in [
            ("MainPID", json!("0")),
            ("InvocationID", json!("")),
            ("NRestarts", json!("1")),
            ("ControlPID", json!("999")),
            ("Job", json!("")),
            ("SubState", json!("start-pre")),
            ("Restart", json!("on-failure")),
        ] {
            let mut bad = owner.clone();
            bad[key] = value;
            assert!(live_shape(&a, &bad).is_err(), "{key}");
        }
        for (key, value) in [
            ("type", json!("stop")),
            ("state", json!("waiting")),
            ("unit", json!(PRODUCER)),
        ] {
            let mut bad = owner.clone();
            bad["holding_start_job"][key] = value;
            assert!(live_shape(&a, &bad).is_err(), "{key}");
        }
        let mut changed = owner.clone();
        changed["InvocationID"] = json!("e".repeat(32));
        assert!(same_owner(&owner, &changed).is_err());
        let mut changed = owner.clone();
        changed["MainPID"] = json!("1235");
        assert!(same_owner(&owner, &changed).is_err());
    }
    #[test]
    fn admitted_unit_cannot_hide_a_second_replay_or_transport_process() {
        sole_process(b"1234\n", 1234).unwrap();
        for bytes in [
            b"".as_slice(),
            b"1234\n4321\n".as_slice(),
            b"4321\n".as_slice(),
            b"unknown\n".as_slice(),
        ] {
            assert!(sole_process(bytes, 1234).is_err());
        }
    }
    #[test]
    fn process_stat_binds_start_identity_and_rejects_zombies() {
        let mut fields = vec!["0"; 20];
        fields[0] = "S";
        fields[19] = "98765";
        let text = format!("1234 (park ) odd) {}", fields.join(" "));
        assert_eq!(start_time(text.as_bytes(), 1234).unwrap(), 98765);
        assert!(start_time(text.as_bytes(), 1235).is_err());
        fields[0] = "Z";
        assert!(start_time(format!("1234 (park) {}", fields.join(" ")).as_bytes(), 1234).is_err());
    }
}
