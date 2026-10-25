//! Metadata admission for a qualified, guarded completed-archive delivery phase.
//! The downstream core has no epoch/tool pins. Origin variants retain their own
//! native provenance gates. This command never launches a verifier or uploader.
use super::*;

const SCHEMA: &str = "jetstreamer-completed-archive-phase-spec-v1";
const RECEIPT: &str = "jetstreamer-completed-archive-phase-admission-v1";
const METADATA: u64 = 1 << 30;

#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Phase {
    Full,
    Plugin,
    Upload,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Plugin => "plugin",
            Self::Upload => "upload",
        }
    }
    fn profile(self) -> (u64, u64, u64) {
        match self {
            Self::Full => (16 << 30, 32 << 30, 86400),
            Self::Plugin => (32 << 30, 64 << 30, 86400),
            Self::Upload => (8 << 30, 16 << 30, 172800),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Origin {
    Singleton209 {
        launch: BoundFile,
        native_input: BoundFile,
        cohort_publication: BoundFile,
    },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    artifact: BoundFile,
    qualification: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Program {
    artifact: BoundFile,
    deployment_seal: BoundFile,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Prior {
    phase: Phase,
    admission: BoundFile,
    invocation_id: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    epoch: u64,
    phase: Phase,
    origin: Origin,
    tools: BTreeMap<String, Tool>,
    programs: BTreeMap<String, Program>,
    units: BTreeMap<String, String>,
    state_root: PathBuf,
    r2_receipt_directory: PathBuf,
    upload_lock: PathBuf,
    environment_file: Option<BoundFile>,
    unit_file: BoundFile,
    resource_basis: Value,
    prior: Vec<Prior>,
    output: PathBuf,
}
fn token(path: &Path) -> Result<&str> {
    let p = path.to_str().context("completed phase path is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
        "completed phase path is unsafe"
    );
    Ok(p)
}
fn read(b: &BoundFile) -> Result<Value> {
    native209::immutable_json(b)
}
fn program(p: &Program) -> Result<()> {
    assembly204_recovery::deployed_delivery_member(&p.deployment_seal, &p.artifact, 256 << 20)
}
fn bound_bytes(b: &BoundFile, max: u64, uid: u32) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == uid
            && m.mode() & 0o022 == 0,
        "completed phase evidence custody differs"
    );
    let raw = read_stable_bounded(&b.path, max, "completed phase evidence")?;
    ensure!(
        is_lower_hex(&b.sha256, 64)
            && hex_lower(&Sha256::digest(&raw)) == b.sha256
            && identity(&m) == identity(&fs::symlink_metadata(&b.path)?),
        "completed phase evidence changed"
    );
    Ok(raw)
}
fn shape(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == SCHEMA && (201..=300).contains(&s.epoch),
        "completed phase scope differs"
    );
    ensure!(
        s.tools.keys().map(String::as_str).collect::<BTreeSet<_>>()
            == BTreeSet::from(["full", "plugin", "boundary", "upload"])
            && s.programs
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["full", "plugin", "boundary", "progressive", "guard"])
            && s.units.keys().map(String::as_str).collect::<BTreeSet<_>>()
                == BTreeSet::from(["full", "plugin", "upload"]),
        "completed phase tool/program/unit census differs"
    );
    let mut names = BTreeSet::new();
    for (phase, name) in &s.units {
        ensure!(
            name.starts_with(&format!("horizon-qualify-{}-", s.epoch))
                && name.ends_with(".service")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && names.insert(name),
            "completed phase unit namespace differs"
        );
        ensure!(
            matches!(phase.as_str(), "full" | "plugin" | "upload"),
            "completed phase unit role differs"
        );
    }
    for path in [
        &s.state_root,
        &s.r2_receipt_directory,
        &s.upload_lock,
        &s.output,
    ] {
        token(path)?;
    }
    ensure!(
        s.state_root
            .starts_with("/home/ubuntu/.jetstreamer-private")
            && s.state_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && s.r2_receipt_directory == Path::new("/home/ubuntu/.jetstreamer-private/r2-receipts")
            && s.upload_lock == s.r2_receipt_directory.join("local-mutation.lock")
            && s.output.file_name().is_some_and(|p| p == "admission.json")
            && s.output.starts_with("/var/lib/jetstreamer")
            && !s.output.starts_with(&s.state_root),
        "completed phase directory scope differs"
    );
    ensure!(
        (s.phase == Phase::Upload) == s.environment_file.is_some(),
        "completed phase credentials differ"
    );
    let expected = match s.phase {
        Phase::Full => vec![],
        Phase::Plugin => vec![Phase::Full],
        Phase::Upload => vec![Phase::Full, Phase::Plugin],
    };
    ensure!(
        s.prior.iter().map(|p| p.phase).collect::<Vec<_>>() == expected,
        "completed phase predecessor order differs"
    );
    Ok(())
}
fn origin(s: &Spec) -> Result<(LocalArchive, Value)> {
    match &s.origin {
        Origin::Singleton209 {
            launch,
            native_input,
            cohort_publication,
        } => {
            ensure!(s.epoch == 209, "origin variant does not qualify this epoch");
            let (_, l) = full209_status::claim(launch)?;
            ensure!(
                l["native_input"] == private157::binding(native_input),
                "completed phase changed native origin"
            );
            let native = read(native_input)?;
            ensure!(
                native["epoch"] == s.epoch && native["native_input_qualified"] == true,
                "completed phase native origin unqualified"
            );
            let terminal = singleton209_delivery::source_terminal(&l)?;
            let cgroup = capped204205_work::empty_terminal_cgroup(singleton209::UNIT)?;
            inactive_status::no_pending_owner_trigger(singleton209::UNIT, false)?;
            let root = Path::new(singleton209::ROOT);
            let references =
                jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), root)?;
            ensure!(
                references.references.is_empty(),
                "completed archive still has process references"
            );
            let dir = root.join("output");
            ensure!(
                dir.canonicalize()? == dir && !s.state_root.starts_with(root),
                "completed phase source redirected or writable"
            );
            let a = read_local_archive(&dir, s.epoch)?;
            ensure!(
                fs::metadata(&s.state_root)?.dev() == a.identity.device
                    && fs::metadata("/")?.dev() == a.identity.device,
                "completed phase source/state filesystem differs"
            );
            singleton209_delivery::cohort(&read(cohort_publication)?, &a)?;
            Ok((
                a,
                json!({"origin":s.origin,"terminal":terminal,"process_reference_census":references,"cgroup":cgroup}),
            ))
        }
    }
}
fn command(s: &Spec, archive: &Path) -> Result<Vec<String>> {
    let state = |p: &str| s.state_root.join(p).display().to_string();
    let tool = |p: &str| s.tools[p].artifact.path.display().to_string();
    let script = |p: &str| s.programs[p].artifact.path.display().to_string();
    let e = s.epoch.to_string();
    let dir = token(archive)?.to_owned();
    let argv = match s.phase {
        Phase::Full => vec![
            script("full"),
            tool("full"),
            dir,
            state("full"),
            e.clone(),
            e,
            "1".into(),
            "8".into(),
            "8".into(),
        ],
        Phase::Plugin => vec![
            script("plugin"),
            tool("plugin"),
            dir,
            state("plugin"),
            e.clone(),
            e,
            "8".into(),
            "1800".into(),
        ],
        Phase::Upload => vec![
            script("progressive"),
            tool("upload"),
            dir,
            s.r2_receipt_directory.display().to_string(),
            e.clone(),
            e,
            "--poll-seconds".into(),
            "1800".into(),
            "--concurrency".into(),
            "1".into(),
            "--local-mutation-lock".into(),
            s.upload_lock.display().to_string(),
            "--full-receipt-directory".into(),
            state("full/receipts"),
            "--full-verifier-sha256".into(),
            s.tools["full"].artifact.sha256.clone(),
            "--full-verifier-script-sha256".into(),
            s.programs["full"].artifact.sha256.clone(),
            "--plugin-receipt-directory".into(),
            state("plugin/receipts"),
            "--plugin-pipeline-sha256".into(),
            s.tools["plugin"].artifact.sha256.clone(),
            "--plugin-verifier-script-sha256".into(),
            s.programs["plugin"].artifact.sha256.clone(),
            "--boundary-receipt-directory".into(),
            state("boundary/receipts"),
            "--boundary-verifier-sha256".into(),
            s.tools["boundary"].artifact.sha256.clone(),
            "--boundary-verifier-script-sha256".into(),
            s.programs["boundary"].artifact.sha256.clone(),
            "--defer-epochs".into(),
            format!("{}-{}", s.epoch, s.epoch),
        ],
    };
    for arg in &argv {
        ensure!(
            !arg.is_empty() && !arg.bytes().any(|b| b.is_ascii_whitespace() || b == b'%'),
            "unsafe completed phase argument"
        );
    }
    Ok(argv)
}
fn idle(row: &Value) -> Result<()> {
    ensure!(
        row["MainPID"] == "0"
            && row["NRestarts"] == "0"
            && matches!(row["ActiveState"].as_str(), Some("inactive" | "failed"))
            && matches!(row["SubState"].as_str(), Some("dead" | "failed")),
        "completed phase owner is running/restarted"
    );
    Ok(())
}
fn check_unit(s: &Spec, argv: &[String]) -> Result<Value> {
    let name = &s.units[s.phase.name()];
    ensure!(
        s.unit_file.path == Path::new("/etc/systemd/system").join(name),
        "completed phase unit fragment differs"
    );
    let raw = bound_bytes(&s.unit_file, 64 << 10, 0)?;
    let text = std::str::from_utf8(&raw)?;
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("ExecStart="))
            .collect::<Vec<_>>()
            == vec![format!("ExecStart={}", argv.join(" "))],
        "completed phase command differs"
    );
    let fields = "Id,LoadState,Type,User,Group,Restart,KillMode,Delegate,FragmentPath,DropInPaths,NeedDaemonReload,Transient,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,RuntimeMaxUSec,LimitFSIZE,LimitFSIZESoft,LimitCORE,LimitCORESoft,NoNewPrivileges,ProtectSystem,ProtectHome,PrivateTmp,PrivateDevices,PrivateNetwork,CapabilityBoundingSet,AmbientCapabilities,Environment,ReadWritePaths,OnSuccess,OnFailure,ExecStart,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost";
    let p = singleton227_capture::properties(name, fields)?;
    let (high, max, runtime) = s.phase.profile();
    for (k, v) in [
        ("Id", name.clone()),
        ("LoadState", "loaded".into()),
        ("Type", "exec".into()),
        ("User", "ubuntu".into()),
        ("Group", "ubuntu".into()),
        ("Restart", "no".into()),
        ("KillMode", "control-group".into()),
        ("Delegate", "no".into()),
        ("FragmentPath", s.unit_file.path.display().to_string()),
        ("DropInPaths", String::new()),
        ("NeedDaemonReload", "no".into()),
        ("Transient", "no".into()),
        ("MemoryHigh", high.to_string()),
        ("MemoryMax", max.to_string()),
        ("MemorySwapMax", "0".into()),
        ("TasksMax", "512".into()),
        ("CPUQuotaPerSecUSec", "8s".into()),
        (
            "RuntimeMaxUSec",
            if runtime == 86400 { "1d" } else { "2d" }.into(),
        ),
        ("LimitFSIZE", "67108864".into()),
        ("LimitFSIZESoft", "67108864".into()),
        ("LimitCORE", "0".into()),
        ("LimitCORESoft", "0".into()),
        ("NoNewPrivileges", "yes".into()),
        ("ProtectSystem", "strict".into()),
        ("ProtectHome", "read-only".into()),
        ("PrivateTmp", "yes".into()),
        ("PrivateDevices", "yes".into()),
    ] {
        ensure!(
            p.get(k) == Some(&v),
            "completed phase effective property differs: {k}"
        );
    }
    for k in ["CapabilityBoundingSet", "AmbientCapabilities"] {
        ensure!(
            p.get(k).is_some_and(String::is_empty),
            "completed phase has extra capabilities"
        );
    }
    let environments = BTreeSet::from([
        "PATH=/usr/bin:/bin",
        "LC_ALL=C",
        "TOKIO_WORKER_THREADS=8",
        "RAYON_NUM_THREADS=8",
        "SOLANA_RAYON_THREADS=8",
    ]);
    ensure!(
        p.get("Environment")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(environments),
        "completed phase environment differs"
    );
    let environment_lines = text
        .lines()
        .filter(|l| l.starts_with("EnvironmentFile="))
        .collect::<Vec<_>>();
    let expected_environment = s
        .environment_file
        .as_ref()
        .map(|b| format!("EnvironmentFile={}", b.path.display()))
        .into_iter()
        .collect::<Vec<_>>();
    ensure!(
        environment_lines == expected_environment,
        "completed phase environment file differs"
    );
    for k in [
        "OnSuccess",
        "OnFailure",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ] {
        ensure!(
            p.get(k).is_some_and(String::is_empty),
            "completed phase has an extra command: {k}"
        );
    }
    if s.phase != Phase::Upload {
        ensure!(
            p.get("PrivateNetwork").map(String::as_str) == Some("yes"),
            "verification has network access"
        );
    }
    let mut writable = BTreeSet::from([s.state_root.join(s.phase.name()).display().to_string()]);
    if s.phase == Phase::Upload {
        writable.insert(s.r2_receipt_directory.display().to_string());
    }
    ensure!(
        p.get("ReadWritePaths").map(|s| s
            .split_whitespace()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>())
            == Some(writable),
        "completed phase writable namespace differs"
    );
    let log = format!(
        "StandardOutput=append:{}/{}/coordinator.log",
        s.state_root.display(),
        s.phase.name()
    );
    ensure!(
        text.lines()
            .filter(|l| l.starts_with("StandardOutput="))
            .collect::<Vec<_>>()
            == vec![log],
        "completed phase log destination differs"
    );
    let expected = format!(
        "{{ path={} ; argv[]={} ; ignore_errors=no }}",
        argv[0],
        argv.join(" ")
    );
    ensure!(
        assembly204_recovery::delivery_command_matches(
            p.get("ExecStart")
                .context("completed phase command missing")?,
            &expected
        ),
        "completed phase actual argv differs"
    );
    Ok(serde_json::to_value(p)?)
}
fn receipt_words(raw: &[u8], wanted: &[&str]) -> Result<()> {
    let text = std::str::from_utf8(raw)?;
    ensure!(
        text == format!("{}\n", wanted.join(" ")),
        "completed phase verification receipt differs"
    );
    Ok(())
}
fn predecessor(s: &Spec, p: &Prior, archive: &LocalArchive, self_sha: &str) -> Result<Value> {
    ensure!(
        is_lower_hex(&p.invocation_id, 32),
        "completed phase predecessor IID invalid"
    );
    let v = read(&p.admission)?;
    ensure!(
        v["schema"] == RECEIPT
            && v["admitted"] == true
            && v["epoch"] == s.epoch
            && v["phase"] == p.phase.name()
            && v["issuer_sha256"] == self_sha
            && v["origin"] == serde_json::to_value(&s.origin)?
            && v["tools"] == serde_json::to_value(&s.tools)?
            && v["programs"] == serde_json::to_value(&s.programs)?
            && v["state_root"] == serde_json::to_value(&s.state_root)?
            && v["units"] == serde_json::to_value(&s.units)?
            && v["archive"] == singleton209_delivery::pair_identity(archive),
        "completed phase predecessor admission differs"
    );
    let old_spec: BoundFile = serde_json::from_value(v["spec"].clone())?;
    let prior: Spec = serde_json::from_value(read(&old_spec)?)?;
    shape(&prior)?;
    ensure!(
        prior.phase == p.phase,
        "completed phase predecessor spec differs"
    );
    check_unit(
        &prior,
        &command(
            &prior,
            archive.archive_path.parent().context("archive parent")?,
        )?,
    )?;
    let name = &s.units[p.phase.name()];
    let current = unit(name)?;
    idle(&current)?;
    ensure!(
        current["LoadState"] == "loaded"
            && current["ActiveState"] == "inactive"
            && current["SubState"] == "dead"
            && current["Result"] == "success"
            && current["ExecMainStatus"] == "0"
            && (current["InvocationID"] == p.invocation_id || current["InvocationID"] == ""),
        "completed phase predecessor is not natural success"
    );
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--unit",
            name,
            "_PID=1",
            "--output=json",
            "--no-pager",
            "--lines=256",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 2 << 20,
        "completed phase predecessor journal unavailable"
    );
    let rows = serde_json::Deserializer::from_slice(&out.stdout)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let events = singleton209_delivery::terminal_history_for(&rows, name, &p.invocation_id)?;
    let state = s.state_root.join(p.phase.name());
    let path = state
        .join("receipts")
        .join(format!("epoch-{}.{}.ok", s.epoch, p.phase.name()));
    let raw = read_stable_bounded(&path, 4096, "completed phase verification receipt")?;
    let m = fs::symlink_metadata(&path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 1000
            && m.mode() & 0o077 == 0,
        "completed phase receipt custody differs"
    );
    receipt_words(
        &raw,
        &[
            &archive.sha256_hex,
            &s.tools[p.phase.name()].artifact.sha256,
            &s.programs[p.phase.name()].artifact.sha256,
        ],
    )?;
    if p.phase == Phase::Full {
        let manifest = format!("{}  epoch-{}.jet\n", archive.sha256_hex, s.epoch);
        ensure!(
            read_stable_bounded(
                &state.join("archive-manifest.sha256"),
                4096,
                "completed full manifest"
            )? == manifest.as_bytes(),
            "completed full manifest differs"
        );
        let chain = read_stable_bounded(
            &state.join("receipts/ordered-chain.ok"),
            4096,
            "completed ordered receipt",
        )?;
        receipt_words(
            &chain,
            &[
                &hex_lower(&Sha256::digest(manifest.as_bytes())),
                &s.tools["full"].artifact.sha256,
                &s.programs["full"].artifact.sha256,
            ],
        )?;
    }
    Ok(
        json!({"admission":private157::binding(&p.admission),"invocation_id":p.invocation_id,"unit":current,"manager_events":events,"manager_journal_sha256":hex_lower(&Sha256::digest(&out.stdout)),"receipt_path":path,"receipt_sha256":hex_lower(&Sha256::digest(&raw))}),
    )
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-completed-archive-phase")?;
    let s: Spec = serde_json::from_value(read(&binding)?)?;
    shape(&s)?;
    validate_output_destination(&s.output)?;
    let state = fs::symlink_metadata(&s.state_root)?;
    ensure!(
        s.state_root.canonicalize()? == s.state_root
            && state.is_dir()
            && state.uid() == 1000
            && state.mode() & 0o077 == 0,
        "completed phase state root unsafe"
    );
    for phase in ["full", "plugin", "boundary", "upload"] {
        let path = s.state_root.join(phase);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            path.canonicalize()? == path && m.is_dir() && m.uid() == 1000 && m.mode() & 0o077 == 0,
            "completed phase child state namespace unsafe"
        );
        if phase == s.phase.name() {
            ensure!(
                fs::read_dir(&path)?.next().is_none(),
                "completed phase attempt must be empty"
            );
        }
    }
    for (role, t) in &s.tools {
        assembly204_recovery::qualified_delivery_tool(role, &t.artifact, &t.qualification)?;
    }
    for p in s.programs.values() {
        program(p)?;
    }
    if let Some(e) = &s.environment_file {
        bound_bytes(e, 64 << 10, 0)?;
        ensure!(
            fs::symlink_metadata(&e.path)?.mode() & 0o077 == 0,
            "completed phase credentials are not private"
        );
    }
    let (archive, original) = origin(&s)?;
    let argv = command(&s, archive.archive_path.parent().context("archive parent")?)?;
    let effective = check_unit(&s, &argv)?;
    let mut names =
        bound_json(&serde_json::from_value(s.resource_basis["fleet"].clone())?)?["unit_census"]
            .as_object()
            .context("completed phase complete census missing")?
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
    names.extend(s.units.values().cloned());
    let before = census(&names, 201, 300)?;
    for name in s.units.values() {
        idle(before.get(name).context("completed phase owner missing")?)?;
        inactive_status::no_pending_owner_trigger(name, false)?;
    }
    let prior = s
        .prior
        .iter()
        .map(|p| predecessor(&s, p, &archive, &self_sha))
        .collect::<Result<Vec<_>>>()?;
    let _upload_lock = if s.phase == Phase::Upload {
        Some(singleton209_delivery::lock()?)
    } else {
        None
    };
    let capacity = maintenance_capacity::check_completed_archive_phase(
        &s.resource_basis,
        maintenance_capacity::Candidate {
            additional_bytes: METADATA,
            memory_max_bytes: s.phase.profile().1,
            minimum_protected_disk_bytes: 1,
        },
    )?;
    let after = census(&names, 201, 300)?;
    let (archive_after, origin_after) = origin(&s)?;
    ensure!(
        before == after
            && effective == check_unit(&s, &argv)?
            && origin_after["origin"] == original["origin"]
            && origin_after["terminal"] == original["terminal"]
            && origin_after["cgroup"] == original["cgroup"]
            && singleton209_delivery::pair_identity(&archive_after)
                == singleton209_delivery::pair_identity(&archive),
        "completed phase origin/owners/unit changed during admission"
    );
    for name in s.units.values() {
        inactive_status::no_pending_owner_trigger(name, false)?;
    }
    ensure!(
        prior
            == s.prior
                .iter()
                .map(|p| predecessor(&s, p, &archive, &self_sha))
                .collect::<Result<Vec<_>>>()?,
        "completed phase predecessor changed during admission"
    );
    for (role, t) in &s.tools {
        assembly204_recovery::qualified_delivery_tool(role, &t.artifact, &t.qualification)?;
    }
    for p in s.programs.values() {
        program(p)?;
    }
    if let Some(e) = &s.environment_file {
        bound_bytes(e, 64 << 10, 0)?;
    }
    private157::immutable_receipt(
        &s.output,
        &json!({"schema":RECEIPT,"epoch":s.epoch,"phase":s.phase,"admitted":true,"spec":private157::binding(&binding),"issuer_sha256":self_sha,"origin":s.origin,"origin_evidence":original,"archive":singleton209_delivery::pair_identity(&archive),"tools":s.tools,"programs":s.programs,"units":s.units,"state_root":s.state_root,"unit_file":s.unit_file,"effective_unit":effective,"argv":argv,"prior":prior,"capacity":capacity,"unit_census_before":before,"unit_census_after":after,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"maximum_age_seconds":900,"new_stage_IID_and_first_guard_fire_pending":true,"replay_launch_authorized":false,"publication_authorized":false,"local_retirement_authorized":false,"archive_body_reads":0,"remote_mutations":false,"r2_mutations":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn b(name: &str) -> BoundFile {
        BoundFile {
            path: Path::new("/sealed").join(name),
            sha256: "a".repeat(64),
        }
    }
    fn fixture(phase: Phase) -> Spec {
        Spec {
            schema: SCHEMA.into(),
            epoch: 209,
            phase,
            origin: Origin::Singleton209 {
                launch: b("launch"),
                native_input: b("native"),
                cohort_publication: b("cohort"),
            },
            tools: ["full", "plugin", "boundary", "upload"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        Tool {
                            artifact: b(r),
                            qualification: b(&format!("{r}-qualification")),
                        },
                    )
                })
                .collect(),
            programs: ["full", "plugin", "boundary", "progressive", "guard"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        Program {
                            artifact: b(&format!("{r}-program")),
                            deployment_seal: b("seal"),
                        },
                    )
                })
                .collect(),
            units: ["full", "plugin", "upload"]
                .into_iter()
                .map(|r| {
                    (
                        r.into(),
                        format!("horizon-qualify-209-generic-{r}-v1.service"),
                    )
                })
                .collect(),
            state_root: "/home/ubuntu/.jetstreamer-private/generic-delivery209".into(),
            r2_receipt_directory: "/home/ubuntu/.jetstreamer-private/r2-receipts".into(),
            upload_lock: "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock".into(),
            environment_file: (phase == Phase::Upload).then(|| b("credentials")),
            unit_file: b("unit"),
            resource_basis: json!({}),
            prior: match phase {
                Phase::Full => vec![],
                Phase::Plugin => vec![Phase::Full],
                Phase::Upload => vec![Phase::Full, Phase::Plugin],
            }
            .into_iter()
            .map(|p| Prior {
                phase: p,
                admission: b("prior"),
                invocation_id: "b".repeat(32),
            })
            .collect(),
            output: "/var/lib/jetstreamer/completed-phase-test/admission.json".into(),
        }
    }
    #[test]
    fn completed_phase_core_binds_actual_tools_and_preserves_serial_no_retirement_upload() {
        for phase in [Phase::Full, Phase::Plugin, Phase::Upload] {
            let mut s = fixture(phase);
            shape(&s).unwrap();
            let original = command(&s, Path::new("/private/output")).unwrap();
            let selected = if phase == Phase::Upload {
                "upload"
            } else {
                phase.name()
            };
            s.tools.get_mut(selected).unwrap().artifact.path = "/sealed/new-qualified-tool".into();
            let changed = command(&s, Path::new("/private/output")).unwrap();
            assert_ne!(original, changed);
            assert!(changed.contains(&"/sealed/new-qualified-tool".into()));
            assert!(!changed.iter().any(|a| matches!(
                a.as_str(),
                "--delete-local" | "--overwrite-existing" | "--repair-orphaned-archive"
            )));
            if phase == Phase::Upload {
                assert!(changed.windows(2).any(|a| a == ["--concurrency", "1"]));
                assert!(
                    changed
                        .windows(2)
                        .any(|a| a == ["--defer-epochs", "209-209"])
                );
                assert!(changed.iter().any(|a| a.ends_with("/full/receipts")));
                s.tools.get_mut("full").unwrap().artifact.sha256 = "c".repeat(64);
                assert!(
                    command(&s, Path::new("/private/output"))
                        .unwrap()
                        .contains(&"c".repeat(64))
                );
            }
        }
    }
    #[test]
    fn completed_phase_scope_rejects_missing_tools_shared_units_and_borrowed_future_receipts() {
        let good = fixture(Phase::Full);
        let mut bad = good.clone();
        bad.tools.remove("full");
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.units.insert("plugin".into(), bad.units["full"].clone());
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.units.insert(
            "full".into(),
            "horizon-qualify-210-generic-full-v1.service".into(),
        );
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.state_root = "/home/ubuntu/.jetstreamer-private".into();
        assert!(shape(&bad).is_err());
        let mut bad = good.clone();
        bad.prior = fixture(Phase::Plugin).prior;
        assert!(shape(&bad).is_err());
        let mut bad = fixture(Phase::Upload);
        bad.prior.reverse();
        assert!(shape(&bad).is_err());
        let mut bad = good;
        bad.environment_file = Some(b("credentials"));
        assert!(shape(&bad).is_err());
    }
    #[test]
    fn completed_phase_receipts_reject_changed_archive_tool_script_and_partial_ordered_gate() {
        let words = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let wanted = words.iter().map(String::as_str).collect::<Vec<_>>();
        let good = format!("{}\n", wanted.join(" "));
        receipt_words(good.as_bytes(), &wanted).unwrap();
        for i in 0..3 {
            let mut changed = words.clone();
            changed[i] = "d".repeat(64);
            assert!(receipt_words(format!("{}\n", changed.join(" ")).as_bytes(), &wanted).is_err());
        }
        for bad in [
            wanted[..2].join(" "),
            format!("{} extra\n", wanted.join(" ")),
            format!("{}\n\n", wanted.join(" ")),
        ] {
            assert!(receipt_words(bad.as_bytes(), &wanted).is_err());
        }
    }
    #[test]
    fn completed_phase_terminal_history_rejects_foreign_restart_and_partial_success() {
        let name = "horizon-qualify-209-generic-full-v1.service";
        let iid = "a".repeat(32);
        let rows = vec![
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"1000","MESSAGE":format!("Started {name} - Full verification.")}),
            json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":iid,"__REALTIME_TIMESTAMP":"2000","MESSAGE":format!("{name}: Deactivated successfully.")}),
        ];
        singleton209_delivery::terminal_history_for(&rows, name, &iid).unwrap();
        assert!(singleton209_delivery::terminal_history_for(&rows[..1], name, &iid).is_err());
        assert!(singleton209_delivery::terminal_history_for(&rows, "other.service", &iid).is_err());
        let mut changed = rows.clone();
        changed[1]["INVOCATION_ID"] = json!("b".repeat(32));
        assert!(singleton209_delivery::terminal_history_for(&changed, name, &iid).is_err());
        let mut changed = rows.clone();
        changed.push(json!({"_PID":"1","_UID":"0","UNIT":name,"INVOCATION_ID":"b".repeat(32),"__REALTIME_TIMESTAMP":"3000"}));
        assert!(singleton209_delivery::terminal_history_for(&changed, name, &iid).is_err());
    }
    #[test]
    fn completed_phase_spec_rejects_unknown_authority_and_unimplemented_origin() {
        let s = serde_json::to_value(fixture(Phase::Full)).unwrap();
        for key in [
            "publication_authorized",
            "ignore_peer",
            "memory_max_bytes",
            "skip_native",
        ] {
            let mut bad = s.clone();
            bad[key] = json!(true);
            assert!(serde_json::from_value::<Spec>(bad).is_err());
        }
        let mut bad = s;
        bad["origin"]["kind"] = json!("unqualified_epoch");
        assert!(serde_json::from_value::<Spec>(bad).is_err());
        let artifact = b("tool");
        assert!(
            assembly204_recovery::qualified_delivery_tool("assembly", &artifact, &b("proof"))
                .is_err()
        );
    }
}
