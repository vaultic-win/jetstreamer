//! Closed post-assembly chain. Service success and operation evidence are
//! independently captured; every read is against the same immutable tuple.
use super::*;
pub(super) mod stage_success;
mod tool_qa;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    Assembly,
    Full,
    Plugin,
    Boundary,
    Import,
    Upload,
}
impl Stage {
    pub(super) fn all() -> [Self; 6] {
        [
            Self::Assembly,
            Self::Full,
            Self::Plugin,
            Self::Boundary,
            Self::Import,
            Self::Upload,
        ]
    }
    pub(super) fn unit(self) -> &'static str {
        match self {
            Self::Assembly => UNIT,
            Self::Full => "horizon-full-verify-204-assembly-recovery-v2.service",
            Self::Plugin => "horizon-plugin-verify-204-assembly-recovery-v2.service",
            Self::Boundary => "horizon-boundary-verify-204-assembly-recovery-v2.service",
            Self::Import => "horizon-import-204-assembly-recovery-v2.service",
            Self::Upload => "horizon-upload-204-assembly-recovery-v2.service",
        }
    }
    pub(super) fn memory(self) -> u64 {
        match self {
            Self::Assembly | Self::Full | Self::Plugin => MEMORY,
            _ => 16 << 30,
        }
    }
    pub(super) fn public_phase(self) -> &'static str {
        if self == Self::Upload {
            "upload"
        } else {
            "verification"
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Gate {
    pub stage: Stage,
    pub terminal: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Neighbor {
    epoch: u64,
    archive: BoundFile,
    ready_evidence: BoundFile,
    bytes: u64,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageSpec {
    schema: String,
    context: AcceptedContext,
    pub stage: Stage,
    pub source: lineage::DownstreamSource,
    gates: Vec<Gate>,
    tool: Option<BoundFile>,
    tool_qualification: Option<BoundFile>,
    anchor_tool: Option<BoundFile>,
    anchor_tool_qualification: Option<BoundFile>,
    pub admission: PathBuf,
    pub output_directory: PathBuf,
    scan_directory: PathBuf,
    upload_receipt: Option<PathBuf>,
    neighbors: Vec<Neighbor>,
}
fn stage_spec(v: &Value) -> Result<StageSpec> {
    let x: StageSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-stage-spec-v1"
            && x.stage != Stage::Assembly,
        "204 downstream stage spec scope"
    );
    private(&x.output_directory)?;
    private(&x.scan_directory)?;
    let device = fs::metadata(CANONICAL)?.dev();
    ensure!(
        fs::metadata(&x.output_directory)?.dev() == device
            && fs::metadata(&x.scan_directory)?.dev() == device,
        "204 staging is outside the admitted filesystem"
    );
    ensure!(
        x.admission.parent() == Some(x.output_directory.as_path())
            && x.admission.file_name() == Some(std::ffi::OsStr::new("admission.json")),
        "204 stage admission location"
    );
    Ok(x)
}
pub(super) fn stage_gate(g: &Gate, source: &lineage::DownstreamSource) -> Result<Value> {
    let t = read(&g.terminal)?;
    ownership::validate_success_terminal(&t, g.stage.unit(), s(&t, "invocation_id")?)?;
    let o = read(&serde_json::from_value(t["outcome"].clone())?)?;
    ensure!(
        o["schema"] == "jetstreamer-epoch204-assembly-recovery-stage-outcome-v1"
            && o["stage"] == serde_json::to_value(g.stage)?
            && o["source"] == serde_json::to_value(source)?
            && o["unit"] == g.stage.unit()
            && o["invocation_id"] == t["invocation_id"]
            && o["passed"] == true,
        "204 stage terminal and actual outcome differ"
    );
    deny(&o["authority"])?;
    Ok(o)
}
fn neighbor_ready(n: &Neighbor) -> Result<()> {
    let ready = read(&n.ready_evidence)?;
    ensure!(
        ready["schema"] == RECEIPT_SCHEMA
            && ready["epoch"] == n.epoch
            && ready["archive_sha256"] == n.archive.sha256
            && ready["archive_length"] == n.bytes
            && ready["archive_key"] == format!("epoch-{}.jet", n.epoch)
            && ready["checksum_key"] == format!("epoch-{}.jet.sha256", n.epoch)
            && (ready["remote_sha256_readback"] == true
                || ready["r2_composite_sha256"]
                    .as_str()
                    .is_some_and(|s| !s.is_empty())),
        "204 neighbor lacks actual ready-pair receipt"
    );
    Ok(())
}
const ANCHOR203: &str = "/home/ubuntu/horizon/epoch-203.jet";
fn full_anchor(x: &StageSpec) -> Result<&Neighbor> {
    ensure!(
        x.stage == Stage::Full && x.neighbors.len() == 1,
        "204 Full needs one exact203 anchor"
    );
    let n = &x.neighbors[0];
    ensure!(
        n.epoch == 203
            && n.archive.path == Path::new(ANCHOR203)
            && n.bytes > 0
            && n.bytes <= OUTPUT_MAX,
        "204 Full anchor scope/length differs"
    );
    neighbor_ready(n)?;
    let input = custody::open_source(&n.archive.path)?;
    anchor_stamp(
        &n.archive.path,
        &custody::FileStamp::of(&input.metadata()?),
        n.bytes,
    )?;
    Ok(n)
}
fn anchor_reserve(x: &StageSpec) -> Result<u64> {
    if x.stage == Stage::Full {
        Ok(full_anchor(x)?.bytes)
    } else {
        Ok(0)
    }
}
fn anchor_stamp(path: &Path, stamp: &custody::FileStamp, bytes: u64) -> Result<()> {
    ensure!(
        path == Path::new(ANCHOR203)
            && stamp.bytes == bytes
            && matches!(stamp.uid, 0 | 1000)
            && stamp.links == 1
            && stamp.mode & libc::S_IFMT == libc::S_IFREG
            && stamp.mode & 0o222 == 0,
        "204 canonical203 anchor is not exact readonly regular single-link root/ubuntu data"
    );
    Ok(())
}
pub(super) fn validate_stage_owner(v: &Value, spec: &BoundFile, stage: Stage) -> Result<()> {
    let x = stage_spec(v)?;
    ensure!(x.stage == stage, "204 stage owner phase differs");
    let (c, _) = lineage::load_source(&x.source)?;
    gates(&x)?;
    issued_admission(&x, spec, n(&c, "archive_bytes")?)?;
    if stage != Stage::Import {
        tool(&x)?;
    }
    Ok(())
}
pub(super) fn required_gates(stage: Stage) -> Result<&'static [Stage]> {
    // Strict Full proves the initial 203→204 anchor and expected V4 provenance.
    // Both adjacent boundary receipts additionally authorize local retirement;
    // they do not hold publication behind a missing full epoch205.
    Ok(match stage {
        Stage::Full => &[],
        Stage::Plugin => &[Stage::Full],
        Stage::Boundary => &[Stage::Full, Stage::Plugin],
        Stage::Import => &[Stage::Full, Stage::Plugin],
        Stage::Upload => &[Stage::Full, Stage::Plugin, Stage::Import],
        Stage::Assembly => bail!("204 standalone assembly has its own runner"),
    })
}
pub(super) fn retirement_neighbor_epochs() -> [u64; 2] {
    [203, 205]
}
fn gates(x: &StageSpec) -> Result<Vec<Value>> {
    let wanted = required_gates(x.stage)?;
    ensure!(
        x.gates.len() == wanted.len(),
        "204 stage predecessor gate arity"
    );
    wanted
        .iter()
        .map(|stage| {
            let found = x
                .gates
                .iter()
                .filter(|g| g.stage == *stage)
                .collect::<Vec<_>>();
            ensure!(found.len() == 1, "204 missing/duplicate predecessor gate");
            stage_gate(found[0], &x.source)
        })
        .collect()
}
fn tool(x: &StageSpec) -> Result<BoundFile> {
    validate_tool_qualification(
        x.stage,
        x.tool.as_ref().context("204 stage tool missing")?,
        x.tool_qualification
            .as_ref()
            .context("204 stage tool qualification missing")?,
    )
}
pub(in crate::fleet) fn qualified_tool(
    role: &str,
    tool: &BoundFile,
    qualification: &BoundFile,
) -> Result<BoundFile> {
    let stage: Stage = serde_json::from_value(json!(role))?;
    ensure!(
        matches!(
            stage,
            Stage::Full | Stage::Plugin | Stage::Boundary | Stage::Upload
        ),
        "unsupported completed archive tool role"
    );
    validate_tool_qualification(stage, tool, qualification)
}
fn validate_tool_qualification(
    stage: Stage,
    artifact: &BoundFile,
    qualification: &BoundFile,
) -> Result<BoundFile> {
    let tool = artifact.clone();
    sealed(&tool, 256 << 20)?;
    let proof = read(qualification)?;
    ensure!(
        proof["schema"] == "jetstreamer-epoch204-assembly-recovery-tool-qualification-v1"
            && proof["stage"] == serde_json::to_value(stage)?
            && proof["artifact"] == private157::binding(&tool)
            && is_lower_hex(s(&proof, "source_revision")?, 40),
        "204 tool qualification scope differs"
    );
    let seal: BoundFile = serde_json::from_value(proof["deployment_seal"].clone())?;
    artifact::validate_member_binding(&seal, &tool, 256 << 20)?;
    let capture: BoundFile = serde_json::from_value(proof["source_capture"].clone())?;
    let report: BoundFile = serde_json::from_value(proof["qa_report"].clone())?;
    artifact::validate_member_binding(&seal, &capture, 16 << 20)?;
    artifact::validate_member_binding(&seal, &report, 16 << 20)?;
    let source = read(&capture)?;
    let qa = read(&report)?;
    for (v, key) in [
        (&source, "source_revision_pointer"),
        (&qa, "qa_revision_pointer"),
    ] {
        let pointer = s(&proof, key)?;
        ensure!(
            matches!(
                pointer,
                "/source/commit"
                    | "/source_commit"
                    | "/source_revision"
                    | "/commit"
                    | "/final_frozen_commit"
            ) && v.pointer(pointer) == Some(&proof["source_revision"]),
            "204 actual tool capture/QA source revision differs"
        );
    }
    let (component, qa_target) = match stage {
        Stage::Full => (
            "jetstreamer-horizon",
            tool_qa::Target::Example("verify_archive"),
        ),
        Stage::Boundary => (
            "jetstreamer-horizon",
            tool_qa::Target::Example("archive_boundaries"),
        ),
        Stage::Plugin => ("jetstreamer", tool_qa::Target::Binary("horizon_pipeline")),
        Stage::Upload => ("jetstreamer-r2", tool_qa::Target::Package),
        _ => bail!("204 stage has no child tool"),
    };
    let logs: Vec<BoundFile> = serde_json::from_value(proof["qa_logs"].clone())?;
    for log in &logs {
        artifact::validate_member_binding(&seal, log, 32 << 20)?;
    }
    let qa_files: Vec<tool_qa::EvidenceFile> =
        serde_json::from_value(proof.get("qa_files").cloned().unwrap_or_else(|| json!([])))?;
    for file in &qa_files {
        artifact::validate_member_binding(&seal, &file.copy, 32 << 20)?;
    }
    tool_qa::validate(
        &qa,
        s(&proof, "source_revision")?,
        (component, qa_target),
        &logs,
        &qa_files,
        read,
        |b| sealed(b, 32 << 20),
    )?;
    Ok(tool)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StageAdmission {
    schema: String,
    stage_spec: BoundFile,
    resource_basis: Value,
    runner: BoundFile,
    unit_file: BoundFile,
    capacity_output: PathBuf,
}
fn installed_stage(
    x: &StageSpec,
    spec: &BoundFile,
    runner: &BoundFile,
    fragment: &BoundFile,
    self_sha: &str,
) -> Result<()> {
    ensure!(
        runner.sha256 == self_sha && fs::read_link("/proc/self/exe")? == runner.path,
        "204 stage runner is not the actual qualified issuer"
    );
    sealed(runner, 256 << 20)?;
    ensure!(
        fragment.path == Path::new("/etc/systemd/system").join(x.stage.unit()),
        "204 stage fragment scope"
    );
    let raw = String::from_utf8(sealed(fragment, 1 << 20)?)?;
    let mut keys = BTreeMap::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#') && !s.starts_with('['))
    {
        let (k, v) = line
            .split_once('=')
            .context("204 malformed stage fragment")?;
        ensure!(keys.insert(k, v).is_none(), "204 duplicate stage directive");
    }
    let argv = format!(
        "{} run-assembly204-recovery-stage {} --spec-sha256 {} --self-sha256 {}",
        runner.path.display(),
        spec.path.display(),
        spec.sha256,
        self_sha
    );
    let memory = x.stage.memory().to_string();
    let high = (x.stage.memory() / 4 * 3).to_string();
    for (k, v) in [
        ("Type", "exec"),
        ("User", "root"),
        ("Restart", "no"),
        ("RuntimeMaxSec", "8h"),
        ("MemoryMax", memory.as_str()),
        ("MemoryHigh", high.as_str()),
        ("MemorySwapMax", "0"),
        ("CPUQuota", "800%"),
        ("TasksMax", "512"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "read-only"),
        ("NoNewPrivileges", "yes"),
        ("Environment", "TOKIO_WORKER_THREADS=4"),
        (
            "PrivateNetwork",
            if x.stage == Stage::Upload {
                "no"
            } else {
                "yes"
            },
        ),
        ("ExecStart", argv.as_str()),
    ] {
        ensure!(
            keys.get(k) == Some(&v),
            "204 installed stage directive differs: {k}"
        );
    }
    let mut writes = BTreeSet::from([
        x.output_directory.display().to_string(),
        x.scan_directory.display().to_string(),
    ]);
    if x.stage == Stage::Import {
        writes.insert(CANONICAL.into());
    }
    if matches!(x.stage, Stage::Import | Stage::Upload) {
        writes.insert("/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock".into());
    }
    ensure!(
        keys.get("ReadWritePaths")
            .context("204 stage writable paths")?
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            == writes.iter().map(String::as_str).collect(),
        "204 stage writable namespace differs"
    );
    let actual = singleton227_capture::properties(
        x.stage.unit(),
        "FragmentPath,DropInPaths,NeedDaemonReload,Transient,ExecStart,MemoryMax,MemoryHigh,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,TasksMax,Type,User,Restart,ProtectSystem,ProtectHome,NoNewPrivileges,PrivateNetwork,Environment",
    )?;
    ensure!(
        actual
            .get("FragmentPath")
            .is_some_and(|p| p == &fragment.path.to_string_lossy())
            && actual.get("DropInPaths").is_some_and(String::is_empty)
            && actual.get("NeedDaemonReload").map(String::as_str) == Some("no")
            && actual.get("Transient").map(String::as_str) == Some("no"),
        "204 installed stage effective fragment differs"
    );
    for k in [
        "MemoryMax",
        "MemoryHigh",
        "MemorySwapMax",
        "TasksMax",
        "Type",
        "User",
        "Restart",
        "ProtectSystem",
        "ProtectHome",
        "NoNewPrivileges",
        "PrivateNetwork",
        "Environment",
    ] {
        ensure!(
            actual.get(k).map(String::as_str) == keys.get(k).copied(),
            "204 effective stage directive differs: {k}"
        );
    }
    ensure!(
        actual.get("RuntimeMaxUSec").map(String::as_str) == Some("8h")
            && actual.get("CPUQuotaPerSecUSec").map(String::as_str) == Some("8s")
            && ownership::command_matches(
                actual
                    .get("ExecStart")
                    .context("204 actual stage command")?,
                &format!(
                    "{{ path={} ; argv[]={argv} ; ignore_errors=no }}",
                    runner.path.display()
                )
            ),
        "204 actual stage lifecycle/command differs"
    );
    Ok(())
}
pub(super) fn admit_stage(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let a: StageAdmission = serde_json::from_value(v.clone())?;
    ensure!(
        a.schema == "jetstreamer-epoch204-assembly-recovery-stage-admission-spec-v1",
        "204 stage admission spec"
    );
    let x = stage_spec(&read(&a.stage_spec)?)?;
    x.context.matches_basis(&a.resource_basis)?;
    let (source, _) = lineage::load_source(&x.source)?;
    gates(&x)?;
    if x.stage != Stage::Import {
        tool(&x)?;
    }
    if x.stage == Stage::Full {
        let mut anchor = x.clone();
        anchor.stage = Stage::Boundary;
        anchor.tool = x.anchor_tool.clone();
        anchor.tool_qualification = x.anchor_tool_qualification.clone();
        tool(&anchor)?;
    }
    installed_stage(&x, &a.stage_spec, &a.runner, &a.unit_file, self_sha)?;
    ownership::no_overlap(&x.context, None)?;
    let before = unit(x.stage.unit())?;
    ensure!(is_idle(&before), "204 stage is already running");
    inactive_status::no_pending_owner_trigger(x.stage.unit(), false)?;
    let capacity = capacity::stage_capacity(
        &a.resource_basis,
        x.stage,
        n(&source, "archive_bytes")?,
        anchor_reserve(&x)?,
    )?;
    let cap = write(&a.capacity_output, &capacity)?;
    ownership::no_overlap(&x.context, None)?;
    ensure!(
        unit(x.stage.unit())? == before,
        "204 stage changed during admission"
    );
    write(
        &x.admission,
        &json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-admission-v1",
        "stage_spec":private157::binding(&a.stage_spec),"stage":x.stage,"capacity":cap,
        "source":x.source,"runner":a.runner,"unit_file":a.unit_file,"recorded_unix_seconds":n(&capacity,"recorded_unix_seconds")?,
        "issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
fn issued_admission(x: &StageSpec, spec: &BoundFile, bytes: u64) -> Result<BoundFile> {
    let b = binding(&x.admission)?;
    let a = read(&b)?;
    deny(&a["authority"])?;
    ensure!(
        a["schema"] == "jetstreamer-epoch204-assembly-recovery-stage-admission-v1"
            && a["stage_spec"] == private157::binding(spec)
            && a["source"] == serde_json::to_value(&x.source)?
            && a["stage"] == serde_json::to_value(x.stage)?,
        "204 wrong stage admission"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let at = n(&a, "recorded_unix_seconds")?;
    ensure!(
        at <= now && now - at <= 900,
        "204 stage admission expired before launch"
    );
    let cap = read(&serde_json::from_value(a["capacity"].clone())?)?;
    let candidate = capacity::candidate_with_anchor(x.stage, bytes, anchor_reserve(x)?)?;
    capacity::validate_capacity(&cap, candidate.memory_max_bytes, candidate.additional_bytes)?;
    capacity::validate_provenance(&cap)?;
    Ok(b)
}
fn tuple(c: &Value, path: &Path) -> Result<custody::FileStamp> {
    let f = custody::open_source(path)?;
    let stamp = custody::FileStamp::of(&f.metadata()?);
    stamp.frozen(n(c, "archive_bytes")?)?;
    Ok(stamp)
}
fn copy_verified(
    source: &Path,
    target: &Path,
    bytes: u64,
    sha: &str,
) -> Result<custody::FileStamp> {
    copy_verified_with_policy(source, target, bytes, sha, false)
}
fn copy_verified_with_policy(
    source: &Path,
    target: &Path,
    bytes: u64,
    sha: &str,
    canonical_anchor: bool,
) -> Result<custody::FileStamp> {
    let mut input = custody::open_source(source)?;
    let before = custody::FileStamp::of(&input.metadata()?);
    if canonical_anchor {
        anchor_stamp(source, &before, bytes)?;
    } else {
        before.frozen(bytes)?;
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(target)?;
    let mut digest = Sha256::new();
    let mut copied = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let count = input.read(&mut buf)?;
        if count == 0 {
            break;
        }
        copied = copied
            .checked_add(count as u64)
            .context("204 copy overflow")?;
        ensure!(copied <= bytes, "204 copy source grew");
        digest.update(&buf[..count]);
        output.write_all(&buf[..count])?;
    }
    ensure!(
        copied == bytes
            && hex_lower(&digest.finalize()) == sha
            && custody::FileStamp::of(&input.metadata()?) == before
            && custody::FileStamp::of(&fs::symlink_metadata(source)?) == before,
        "204 copy source tuple changed"
    );
    output.sync_all()?;
    File::open(target.parent().context("204 copy parent")?)?.sync_all()?;
    let result = custody::FileStamp::of(&output.metadata()?);
    result.frozen(bytes)?;
    ensure!(
        result.mode & 0o7777 == 0o400,
        "204 copied input is not root readonly0400"
    );
    Ok(result)
}
fn hash_tuple(b: &BoundFile, bytes: u64) -> Result<()> {
    let mut f = custody::open_source(&b.path)?;
    let before = custody::FileStamp::of(&f.metadata()?);
    before.frozen(bytes)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 65536];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).context("204 hash overflow")?;
        ensure!(total <= bytes, "204 input grew");
        digest.update(&buf[..n]);
    }
    ensure!(
        total == bytes
            && hex_lower(&digest.finalize()) == b.sha256
            && custody::FileStamp::of(&f.metadata()?) == before
            && custody::FileStamp::of(&fs::symlink_metadata(&b.path)?) == before,
        "204 input tuple changed"
    );
    Ok(())
}
// Pipe readers retain at most 8 MiB each; the owning process group is stopped
// on a log/time violation. No detached verifier or unbounded output buffer.
fn child(tool: &BoundFile, args: &[String], directory: &Path, label: &str) -> Result<Value> {
    let overflow = Arc::new(AtomicBool::new(false));
    let mut command = ProcessCommand::new(&tool.path);
    command
        .args(args)
        .env("TOKIO_WORKER_THREADS", "4")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut process = command.spawn()?;
    let pid: i32 = process.id().try_into()?;
    let pump = |mut stream: Box<dyn Read + Send>,
                path: PathBuf,
                overflow: Arc<AtomicBool>,
                journal: bool| {
        std::thread::spawn(move || -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .open(path)?;
            let mut total = 0;
            let mut buf = [0u8; 8192];
            loop {
                let n = stream.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                total += n;
                if total > 8 << 20 {
                    overflow.store(true, Ordering::SeqCst);
                    bail!("204 child log limit");
                }
                file.write_all(&buf[..n])?;
                if journal {
                    std::io::stderr().write_all(&buf[..n])?;
                }
            }
            file.sync_all()?;
            Ok(())
        })
    };
    let stdout = directory.join(format!("{label}-stdout.log"));
    let stderr = directory.join(format!("{label}-stderr.log"));
    let out = pump(
        Box::new(process.stdout.take().context("204 stdout pipe")?),
        stdout.clone(),
        overflow.clone(),
        false,
    );
    let err = pump(
        Box::new(process.stderr.take().context("204 stderr pipe")?),
        stderr.clone(),
        overflow.clone(),
        true,
    );
    let started = Instant::now();
    let status = loop {
        if overflow.load(Ordering::SeqCst) || started.elapsed() > Duration::from_millis(DURATION) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = process.wait();
            let _ = out.join();
            let _ = err.join();
            bail!("204 child exceeded bound");
        }
        if let Some(status) = process.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    out.join()
        .map_err(|_| anyhow!("204 stdout reader panicked"))??;
    err.join()
        .map_err(|_| anyhow!("204 stderr reader panicked"))??;
    ensure!(status.success(), "204 actual child failed: {status}");
    Ok(
        json!({"tool":tool,"arguments":args,"exit_code":status.code(),"stdout":binding(&stdout)?,"stderr":binding(&stderr)?}),
    )
}
fn mutation_lock() -> Result<File> {
    let path = Path::new("/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && matches!(m.uid(), 0 | 1000)
            && m.nlink() == 1
            && m.mode() & 0o077 == 0
            && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "204 normal shared local-mutation/upload lease unsafe or occupied"
    );
    let named = fs::symlink_metadata(path)?;
    ensure!(
        m.dev() == named.dev() && m.ino() == named.ino(),
        "204 shared mutation lease namespace changed"
    );
    Ok(file)
}
/// Shared by the actual strict204 runner and its metadata-only preparation.
/// The anchor values come from the real203 decoder, never from the204 target.
pub(super) fn full_arguments(
    scan: &Path,
    anchor_slot: String,
    anchor_hash: String,
    expected: &lineage::Expected,
) -> Result<Vec<String>> {
    Ok(vec![
        scan.display().to_string(),
        "--full".into(),
        "--anchor".into(),
        anchor_slot,
        anchor_hash,
        "--expected-terminal".into(),
        "88559999".into(),
        s(&expected.document, "terminal_blockhash")?.into(),
        "--expected-provenance-sha256".into(),
        expected.digest.clone(),
        "--threads".into(),
        "8".into(),
    ])
}
pub(super) async fn run_stage(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x = stage_spec(v)?;
    let (c, l) = lineage::load_source(&x.source)?;
    let predecessors = gates(&x)?;
    let _mutation_lease = if matches!(x.stage, Stage::Import | Stage::Upload) {
        Some(mutation_lock()?)
    } else {
        None
    };
    if x.stage != Stage::Import {
        tool(&x)?;
    }
    let admission = issued_admission(&x, spec, n(&c, "archive_bytes")?)?;
    let current = ownership::current_actor(x.stage, spec, self_sha)?;
    ownership::no_overlap(&x.context, Some(x.stage))?;
    let scan = x.scan_directory.join("epoch-204.jet");
    let sha = s(&c, "archive_sha256")?;
    let bytes = n(&c, "archive_bytes")?;
    ensure!(
        tuple(&c, Path::new(OUTPUT))? == serde_json::from_value(c["output_identity"].clone())?,
        "204 completed source identity changed"
    );
    let mut commands = Vec::new();
    let mut imported = Value::Null;
    match x.stage {
        Stage::Full => {
            no_file(&scan)?;
            copy_verified(Path::new(OUTPUT), &scan, bytes, sha)?;
            let t = tool(&x)?;
            let neighbor = full_anchor(&x)?;
            let anchor_copy = x.scan_directory.join("epoch-203.jet");
            no_file(&anchor_copy)?;
            copy_verified_with_policy(
                &neighbor.archive.path,
                &anchor_copy,
                neighbor.bytes,
                &neighbor.archive.sha256,
                true,
            )?;
            // Keep the original root-only frozen-input hash and decoder gates.
            hash_tuple(
                &BoundFile {
                    path: anchor_copy.clone(),
                    sha256: neighbor.archive.sha256.clone(),
                },
                neighbor.bytes,
            )?;
            let mut anchor_spec = x.clone();
            anchor_spec.stage = Stage::Boundary;
            anchor_spec.tool = x.anchor_tool.clone();
            anchor_spec.tool_qualification = x.anchor_tool_qualification.clone();
            let anchor_result = child(
                &tool(&anchor_spec)?,
                &[anchor_copy.display().to_string()],
                &x.output_directory,
                "anchor203",
            )?;
            let stdout = sealed(
                &serde_json::from_value(anchor_result["stdout"].clone())?,
                8 << 20,
            )?;
            let text = std::str::from_utf8(&stdout)?;
            let lines = text.lines().collect::<Vec<_>>();
            ensure!(lines.len() == 1, "204 anchor tool output arity");
            let fields = lines[0].split('\t').collect::<Vec<_>>();
            ensure!(
                fields.len() == 12
                    && fields[0] == anchor_copy.to_string_lossy()
                    && fields[1] == "203"
                    && fields[2] == "87696000"
                    && fields[3] == "432000"
                    && fields[8].parse::<u64>()? < 88128000,
                "204 real epoch203 boundary metadata scope"
            );
            let anchor_slot = fields[8].to_string();
            let anchor_hash = fields[9].to_string();
            commands.push(anchor_result);
            commands.push(child(
                &t,
                &full_arguments(&scan, anchor_slot, anchor_hash, &l.expected)?,
                &x.output_directory,
                "full",
            )?);
        }
        Stage::Plugin => {
            hash_tuple(
                &BoundFile {
                    path: scan.clone(),
                    sha256: sha.into(),
                },
                bytes,
            )?;
            commands.push(child(
                &tool(&x)?,
                &[
                    "204:204".into(),
                    x.scan_directory.display().to_string(),
                    "--threads".into(),
                    "8".into(),
                    "--verify-only".into(),
                ],
                &x.output_directory,
                "plugin",
            )?);
        }
        Stage::Boundary => {
            ensure!(x.neighbors.len() == 2, "204 needs both boundary neighbors");
            let t = tool(&x)?;
            for epoch in retirement_neighbor_epochs() {
                let neighbors = x
                    .neighbors
                    .iter()
                    .filter(|n| n.epoch == epoch)
                    .collect::<Vec<_>>();
                ensure!(neighbors.len() == 1, "204 boundary neighbor scope");
                let n = neighbors[0];
                neighbor_ready(n)?;
                hash_tuple(&n.archive, n.bytes)?;
                let (left, right) = if epoch == 203 {
                    (&n.archive.path, &scan)
                } else {
                    (&scan, &n.archive.path)
                };
                commands.push(child(
                    &t,
                    &[
                        "--verify-pair".into(),
                        left.display().to_string(),
                        right.display().to_string(),
                    ],
                    &x.output_directory,
                    &format!("boundary-{epoch}"),
                )?);
            }
        }
        Stage::Import => {
            hash_tuple(
                &BoundFile {
                    path: scan.clone(),
                    sha256: sha.into(),
                },
                bytes,
            )?;
            let canonical = Path::new(CANONICAL).join("epoch-204.jet");
            no_file(&canonical)?;
            no_sidecar(&canonical)?;
            let staging = x.output_directory.join("epoch-204.jet");
            copy_verified(&scan, &staging, bytes, sha)?;
            ensure!(
                fs::metadata(&x.output_directory)?.dev() == fs::metadata(CANONICAL)?.dev(),
                "204 import must be atomic on one filesystem"
            );
            let from = std::ffi::CString::new(staging.as_os_str().as_encoded_bytes())?;
            let to = std::ffi::CString::new(canonical.as_os_str().as_encoded_bytes())?;
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
                "204 no-clobber canonical import failed"
            );
            let sidecar = PathBuf::from(format!("{}.sha256", canonical.display()));
            let mut checksum = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&sidecar)?;
            checksum.write_all(format!("{sha}  epoch-204.jet\n").as_bytes())?;
            checksum.sync_all()?;
            File::open(CANONICAL)?.sync_all()?;
            imported = json!({"path":canonical,"sha256":sha,"bytes":bytes,"identity":tuple(&c,&canonical)?});
        }
        Stage::Upload => {
            hash_tuple(
                &BoundFile {
                    path: Path::new(CANONICAL).join("epoch-204.jet"),
                    sha256: sha.into(),
                },
                bytes,
            )?;
            let receipt = x
                .upload_receipt
                .as_ref()
                .context("204 upload durable receipt destination missing")?;
            no_file(receipt)?;
            let directory = receipt.parent().context("204 uploader receipts")?;
            ensure!(
                directory == x.output_directory,
                "204 uploader receipt namespace"
            );
            commands.push(child(
                &tool(&x)?,
                &[
                    "sync".into(),
                    CANONICAL.into(),
                    "--epochs".into(),
                    "204-204".into(),
                    "--expected-archive-sha256".into(),
                    sha.into(),
                    "--expected-archive-bytes".into(),
                    bytes.to_string(),
                    "--receipt-directory".into(),
                    directory.display().to_string(),
                ],
                &x.output_directory,
                "upload",
            )?);
            ensure!(
                receipt == &directory.join("epoch-204.r2.json"),
                "204 uploader receipt canonical name"
            );
            let file = custody::open_source(receipt)?;
            ensure!(
                file.metadata()?.uid() == 0 && file.metadata()?.nlink() == 1,
                "204 uploader receipt custody"
            );
            file.set_permissions(fs::Permissions::from_mode(0o400))?;
            file.sync_all()?;
            let actual = read(&binding(receipt)?)?;
            ensure!(
                actual["schema"] == RECEIPT_SCHEMA
                    && actual["epoch"] == 204
                    && actual["archive_sha256"] == sha
                    && actual["archive_length"] == bytes
                    && actual["archive_key"] == "epoch-204.jet"
                    && actual["checksum_key"] == "epoch-204.jet.sha256"
                    && (actual["remote_sha256_readback"] == true
                        || actual["r2_composite_sha256"]
                            .as_str()
                            .is_some_and(|s| !s.is_empty())),
                "204 normal uploader readback/sidecar receipt differs"
            );
        }
        Stage::Assembly => bail!("204 assembly uses pinned standalone helper"),
    }
    ensure!(
        unit(x.stage.unit())? == current,
        "204 stage owner changed while running"
    );
    hash_tuple(
        &BoundFile {
            path: scan,
            sha256: sha.into(),
        },
        bytes,
    )?;
    write(
        &x.output_directory.join("outcome.json"),
        &json!({"schema":"jetstreamer-epoch204-assembly-recovery-stage-outcome-v1",
        "stage":x.stage,"source":x.source,"unit":x.stage.unit(),"invocation_id":current["InvocationID"],
        "spec":spec,"admission":admission,"archive_sha256":sha,"archive_bytes":bytes,"commands":commands,
        "retirement_boundary_only":x.stage==Stage::Boundary,"local_retirement_authorized":false,"predecessor_gates":x.gates,"predecessor_outcomes":predecessors,"imported":imported,"passed":true,
        "issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Capture {
    schema: String,
    pub(super) context: AcceptedContext,
    #[serde(default)]
    pub(super) observer_history: Vec<BoundFile>,
    #[serde(default)]
    pub(super) full209_terminal_peer: Option<full209_terminal_peer::Proof>,
    stage: Stage,
    pub(super) launch: BoundFile,
    pub(super) outcome: Option<PathBuf>,
    pub(super) output_directory: PathBuf,
}
pub(super) fn capture_stage(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let c: Capture = serde_json::from_value(v.clone())?;
    ensure!(
        c.schema == "jetstreamer-epoch204-assembly-recovery-stage-terminal-spec-v1",
        "204 stage terminal spec"
    );
    let launch = read(&c.launch)?;
    let iid = s(&launch, "invocation_id")?;
    ensure!(
        launch["unit"] == c.stage.unit(),
        "204 stage terminal launch scope"
    );
    let current = unit(c.stage.unit())?;
    let success = current["Result"] == "success" && current["ExecMainStatus"] == "0";
    terminal_success_context(success, &c.observer_history)?;
    ensure!(
        c.full209_terminal_peer.is_none() || (success && c.stage == Stage::Assembly),
        "204 terminal Full209 peer belongs only to assembly natural success"
    );
    if c.stage == Stage::Assembly && success {
        return ownership::assembly_success::capture(&c, spec, self_sha);
    }
    if success {
        stage_success::capture(&c, spec, self_sha)
    } else {
        ownership::capture_failure_terminal(
            &c.context,
            c.stage.unit(),
            iid,
            &c.output_directory,
            spec,
            self_sha,
        )
    }
}
fn terminal_success_context(success: bool, history: &[BoundFile]) -> Result<()> {
    ensure!(
        success || history.is_empty(),
        "204 observer refresh belongs only to natural success capture"
    );
    Ok(())
}

#[cfg(test)]
mod terminal_capture_context_tests {
    use super::*;
    #[test]
    fn refreshed_terminal_context_is_exclusive_to_natural_success() {
        let history = [BoundFile {
            path: "/fixture/middle-observer.json".into(),
            sha256: "a".repeat(64),
        }];
        assert!(terminal_success_context(true, &history).is_ok());
        assert!(terminal_success_context(false, &history).is_err());
        assert!(terminal_success_context(true, &[]).is_ok());
        assert!(terminal_success_context(false, &[]).is_ok());
    }
}

#[cfg(test)]
mod full_anchor_tests {
    use super::*;
    fn stamp() -> custody::FileStamp {
        custody::FileStamp {
            device: 1,
            inode: 2,
            bytes: 103_802_397_352,
            uid: 1000,
            gid: 1000,
            mode: libc::S_IFREG | 0o440,
            links: 1,
            mtime: 3,
            mtime_nanos: 4,
            ctime: 5,
            ctime_nanos: 6,
        }
    }
    #[test]
    fn exact_readonly_canonical203_custody_accepts_only_root_or_ubuntu_single_link() {
        let path = Path::new(ANCHOR203);
        let original = stamp();
        anchor_stamp(path, &original, original.bytes).unwrap();
        let mut root = original.clone();
        root.uid = 0;
        anchor_stamp(path, &root, root.bytes).unwrap();
        assert!(
            anchor_stamp(
                Path::new("/private/epoch-203.jet"),
                &original,
                original.bytes
            )
            .is_err()
        );
        assert!(anchor_stamp(path, &original, original.bytes + 1).is_err());
        let mut foreign = original;
        foreign.uid = 1001;
        assert!(anchor_stamp(path, &foreign, foreign.bytes).is_err());
        let mut bad = stamp();
        bad.links = 2;
        assert!(anchor_stamp(path, &bad, bad.bytes).is_err());
        bad = stamp();
        bad.mode |= 0o200;
        assert!(anchor_stamp(path, &bad, bad.bytes).is_err());
        bad = stamp();
        bad.mode = libc::S_IFLNK | 0o440;
        assert!(anchor_stamp(path, &bad, bad.bytes).is_err());
    }
}
