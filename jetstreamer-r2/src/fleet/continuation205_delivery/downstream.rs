//! Strict epoch205 post-continuation stages. First Full measures the previously
//! unknown source digest; subsequent stages consume that genuine Full outcome.
use super::*;
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
    pub fn all() -> [Self; 5] {
        [
            Self::Full,
            Self::Plugin,
            Self::Boundary,
            Self::Import,
            Self::Upload,
        ]
    }
    pub fn unit(self) -> &'static str {
        match self {
            Self::Full => "horizon-full-verify-205-continuation-delivery-v1.service",
            Self::Plugin => "horizon-plugin-verify-205-continuation-delivery-v1.service",
            Self::Boundary => "horizon-boundary-verify-205-continuation-delivery-v1.service",
            Self::Import => "horizon-import-205-continuation-delivery-v1.service",
            Self::Upload => "horizon-upload-205-continuation-delivery-v1.service",
            Self::Assembly => UNIT,
        }
    }
    pub fn memory(self) -> u64 {
        match self {
            Self::Assembly | Self::Full | Self::Plugin => 64 << 30,
            _ => 16 << 30,
        }
    }
    pub fn public_phase(self) -> &'static str {
        if self == Self::Upload {
            "upload"
        } else {
            "verification"
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    pub fleet: BoundFile,
    pub observer: BoundFile,
}
impl Context {
    pub fn historical(&self) -> Result<Value> {
        assembly204_recovery::accepted_context(&self.fleet, &self.observer)
    }
    pub fn matches_basis(&self, basis: &Value) -> Result<()> {
        ensure!(
            basis["fleet"] == private157::binding(&self.fleet)
                && basis["observer"] == private157::binding(&self.observer),
            "205 resource basis changed its accepted context"
        );
        self.historical()?;
        Ok(())
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
pub(super) struct Neighbor {
    pub epoch: u64,
    pub archive: BoundFile,
    pub bytes: u64,
    pub full204_terminal: Option<BoundFile>,
    pub ready_evidence: Option<BoundFile>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StageSpec {
    pub schema: String,
    pub context: Context,
    pub stage: Stage,
    pub source: lineage::DownstreamSource,
    pub startup: Option<BoundFile>,
    pub environment_file: Option<BoundFile>,
    pub gates: Vec<Gate>,
    pub tool: Option<BoundFile>,
    pub tool_qualification: Option<BoundFile>,
    pub anchor_tool: Option<BoundFile>,
    pub anchor_tool_qualification: Option<BoundFile>,
    pub admission: PathBuf,
    pub output_directory: PathBuf,
    pub scan_directory: PathBuf,
    pub upload_receipt: Option<PathBuf>,
    pub neighbors: Vec<Neighbor>,
}
pub(super) fn stage_spec(v: &Value) -> Result<StageSpec> {
    let x: StageSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-continuation205-delivery-stage-spec-v1"
            && x.stage != Stage::Assembly
            && x.environment_file.is_some() == (x.stage == Stage::Upload),
        "205 stage scope or credentials differ"
    );
    private(&x.output_directory)?;
    private(&x.scan_directory)?;
    ensure!(
        x.admission == x.output_directory.join("admission.json")
            && fs::metadata(&x.scan_directory)?.dev() == fs::metadata(CANONICAL)?.dev()
            && fs::metadata(&x.output_directory)?.dev() == fs::metadata(CANONICAL)?.dev(),
        "205 stage filesystem/admission path differs"
    );
    Ok(x)
}
pub(super) fn anchor_reserve(x: &StageSpec) -> Result<u64> {
    if x.stage != Stage::Full {
        return Ok(0);
    }
    Ok(full_anchor(x)?.bytes)
}
fn full_anchor(x: &StageSpec) -> Result<&Neighbor> {
    ensure!(
        x.stage == Stage::Full && x.neighbors.len() == 1,
        "205 Full requires one genuine204 anchor"
    );
    let n = &x.neighbors[0];
    ensure!(
        n.epoch == 204 && n.ready_evidence.is_none(),
        "205 private anchor scope differs"
    );
    let proof = assembly204_recovery::private_full204_anchor(
        n.full204_terminal
            .as_ref()
            .context("205 private204 Full terminal missing")?,
    )?;
    ensure!(
        proof["archive"] == private157::binding(&n.archive) && proof["bytes"] == n.bytes,
        "205 anchor differs from genuine strict-Full204 digest/length"
    );
    let stamp = custody::tuple(&n.archive.path)?;
    ensure!(
        stamp.bytes == n.bytes,
        "205 private204 anchor length changed"
    );
    Ok(n)
}
fn required_gates(stage: Stage) -> Result<&'static [Stage]> {
    Ok(match stage {
        Stage::Full => &[],
        Stage::Plugin => &[Stage::Full],
        Stage::Boundary | Stage::Import => &[Stage::Full, Stage::Plugin],
        Stage::Upload => &[Stage::Full, Stage::Plugin, Stage::Import],
        Stage::Assembly => bail!("205 assembler cannot be a delivery stage"),
    })
}
pub(super) fn gates(x: &StageSpec) -> Result<Vec<Value>> {
    let expected = required_gates(x.stage)?;
    ensure!(
        x.gates.len() == expected.len(),
        "205 predecessor gate arity differs"
    );
    expected
        .iter()
        .map(|stage| {
            let gates = x
                .gates
                .iter()
                .filter(|g| g.stage == *stage)
                .collect::<Vec<_>>();
            ensure!(gates.len() == 1, "205 missing/duplicate predecessor");
            terminal::stage_gate(gates[0], &x.source)
        })
        .collect()
}
fn tool(x: &StageSpec) -> Result<BoundFile> {
    let role = match x.stage {
        Stage::Full => "full",
        Stage::Plugin => "plugin",
        Stage::Boundary => "boundary",
        Stage::Upload => "upload",
        _ => bail!("205 stage has no external tool"),
    };
    assembly204_recovery::qualified_delivery_tool(
        role,
        x.tool.as_ref().context("205 tool missing")?,
        x.tool_qualification
            .as_ref()
            .context("205 tool qualification missing")?,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema: String,
    stage_spec: BoundFile,
    resource_basis: Value,
    runner: BoundFile,
    unit_file: BoundFile,
    capacity_output: PathBuf,
}
pub(super) fn admit(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let a: AdmissionSpec = serde_json::from_value(v.clone())?;
    ensure!(
        a.schema == "jetstreamer-continuation205-delivery-admission-spec-v1",
        "205 admission schema differs"
    );
    let x = stage_spec(&read(&a.stage_spec)?)?;
    x.context.matches_basis(&a.resource_basis)?;
    startup::before_admission(&x)?;
    let (source, _) = lineage::load_source(&x.source)?;
    gates(&x)?;
    if x.stage != Stage::Import {
        tool(&x)?;
    }
    installed_stage(&x, &a.stage_spec, &a.runner, &a.unit_file, self_sha)?;
    peer::no_file(&x.admission)?;
    let before = unit(x.stage.unit())?;
    ensure!(
        before["MainPID"] == "0" && before["NRestarts"] == "0",
        "205 actor already active/restarted"
    );
    inactive_status::no_pending_owner_trigger(x.stage.unit(), false)?;
    let cap = capacity::stage_capacity(
        &a.resource_basis,
        x.stage,
        n(&source, "archive_bytes")?,
        anchor_reserve(&x)?,
    )?;
    let capacity = peer::write_bound(&a.capacity_output, &cap)?;
    ensure!(
        unit(x.stage.unit())? == before,
        "205 actor changed during admission"
    );
    write(
        &x.admission,
        &json!({"schema":"jetstreamer-continuation205-delivery-admission-v1","stage":x.stage,
        "stage_spec":a.stage_spec,"source":x.source,"runner":a.runner,"unit_file":a.unit_file,"capacity":capacity,
        "recorded_unix_seconds":cap["recorded_unix_seconds"],"issuer":peer::issuer(spec,self_sha),"authority":denied()}),
    )
}
pub(super) fn saved_admission(x: &StageSpec, spec: &BoundFile, bytes: u64) -> Result<BoundFile> {
    let b = peer::binding(&x.admission)?;
    let a = read(&b)?;
    deny(&a["authority"])?;
    ensure!(
        a["schema"] == "jetstreamer-continuation205-delivery-admission-v1"
            && a["stage_spec"] == private157::binding(spec)
            && a["source"] == serde_json::to_value(&x.source)?
            && a["stage"] == serde_json::to_value(x.stage)?,
        "205 saved admission belongs to another stage/source"
    );
    let cap = read(&serde_json::from_value(a["capacity"].clone())?)?;
    let c = capacity::candidate_with_anchor(x.stage, bytes, anchor_reserve(x)?)?;
    capacity::validate_capacity(&cap, c.memory_max_bytes, c.additional_bytes)?;
    capacity::validate_provenance(&cap)?;
    Ok(b)
}
pub(super) fn issued_admission(x: &StageSpec, spec: &BoundFile, bytes: u64) -> Result<BoundFile> {
    let b = saved_admission(x, spec, bytes)?;
    let a = read(&b)?;
    let at = n(&a, "recorded_unix_seconds")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(at <= now && now - at <= 900, "205 launch admission expired");
    Ok(b)
}
fn child(t: &BoundFile, args: &[String], x: &StageSpec, label: &str) -> Result<Value> {
    assembly204_recovery::delivery_child(t, args, &x.output_directory, label)
}
fn full_arguments(
    scan: &Path,
    slot: &str,
    hash: &str,
    expected: &lineage::Expected,
) -> Vec<String> {
    vec![
        scan.display().to_string(),
        "--full".into(),
        "--anchor".into(),
        slot.into(),
        hash.into(),
        "--expected-terminal".into(),
        "88991999".into(),
        "HuZtkhXnzaJ9BvDazHHSUgQWTFg3u2Uvf12AHBWqYuji".into(),
        "--expected-provenance-sha256".into(),
        expected.digest.clone(),
        "--threads".into(),
        "8".into(),
    ]
}
fn mutation_lock() -> Result<File> {
    use std::os::fd::AsRawFd;
    let path = Path::new("/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && matches!(m.uid(), 0 | 1000)
            && m.mode() & 0o077 == 0
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "205 shared mutation lease is unsafe/occupied"
    );
    ensure!(
        m.dev() == fs::symlink_metadata(path)?.dev()
            && m.ino() == fs::symlink_metadata(path)?.ino(),
        "205 mutation lease replaced"
    );
    Ok(f)
}
pub(super) async fn run_stage(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    use std::io::Write;
    let started = std::time::Instant::now();
    let x = stage_spec(v)?;
    let (source, loaded) = lineage::load_source(&x.source)?;
    let predecessors = gates(&x)?;
    let admission = issued_admission(&x, spec, BYTES)?;
    if x.stage != Stage::Import {
        tool(&x)?;
    }
    let owner = peer::current_actor(x.stage, spec, self_sha)?;
    let consumed = startup::wait(&x, spec, self_sha, started)?;
    let _lease = if matches!(x.stage, Stage::Import | Stage::Upload) {
        Some(mutation_lock()?)
    } else {
        None
    };
    let scan = x.scan_directory.join("epoch-205.jet");
    let original: custody::Stamp = serde_json::from_value(source["output_identity"].clone())?;
    ensure!(
        custody::tuple(Path::new(OUTPUT))? == original,
        "205 original frozen source changed before payload"
    );
    let mut commands = Vec::new();
    let mut measurement = Value::Null;
    let mut anchor_proof = Value::Null;
    let mut imported = Value::Null;
    let mut sha = predecessors
        .first()
        .and_then(|o| o["archive_sha256"].as_str())
        .unwrap_or("")
        .to_owned();
    let mut scan_stamp = if x.stage != Stage::Full {
        Some(serde_json::from_value::<custody::Stamp>(
            predecessors[0]["measurement"]["copy_identity"].clone(),
        )?)
    } else {
        None
    };
    if x.stage != Stage::Full {
        let full = predecessors
            .first()
            .context("205 downstream lost first Full gate")?;
        ensure!(
            is_lower_hex(&sha, 64),
            "205 downstream lacks measured Full digest"
        );
        ensure!(
            full["measurement"]["copy"] == serde_json::to_value(&scan)?,
            "205 stage changed verified copy path"
        );
        let stamp: custody::Stamp =
            serde_json::from_value(full["measurement"]["copy_identity"].clone())?;
        custody::hash_exact(&scan, &stamp, &sha)?;
    }
    match x.stage {
        Stage::Full => {
            let before = custody::no_writers(Path::new("/proc"), &original)?;
            let measured = custody::copy_and_measure(Path::new(OUTPUT), &scan, &original)?;
            custody::no_writers(Path::new("/proc"), &original)?;
            sha = measured.sha256.clone();
            scan_stamp = Some(measured.copy_identity.clone());
            measurement = serde_json::to_value(&measured)?;
            let n = full_anchor(&x)?;
            let proof = assembly204_recovery::private_full204_anchor(
                n.full204_terminal.as_ref().context("205204 terminal")?,
            )?;
            let anchor_stamp = custody::tuple(&n.archive.path)?;
            let anchor_writers = custody::no_writers(Path::new("/proc"), &anchor_stamp)?;
            let anchor_copy = x.scan_directory.join("epoch-204.jet");
            let copied = custody::copy_and_measure(&n.archive.path, &anchor_copy, &anchor_stamp)?;
            ensure!(
                copied.sha256 == n.archive.sha256 && copied.bytes == n.bytes,
                "205 private204 anchor copy no longer matches genuine Full digest"
            );
            custody::no_writers(Path::new("/proc"), &anchor_stamp)?;
            custody::hash_exact(&anchor_copy, &copied.copy_identity, &n.archive.sha256)?;
            let decoder = assembly204_recovery::qualified_delivery_tool(
                "boundary",
                x.anchor_tool.as_ref().context("205 anchor decoder")?,
                x.anchor_tool_qualification
                    .as_ref()
                    .context("205 anchor qualification")?,
            )?;
            let decoded = child(
                &decoder,
                &[anchor_copy.display().to_string()],
                &x,
                "anchor204",
            )?;
            let raw = sealed(&serde_json::from_value(decoded["stdout"].clone())?, 8 << 20)?;
            let text = std::str::from_utf8(&raw)?;
            let lines = text.lines().collect::<Vec<_>>();
            ensure!(lines.len() == 1, "205 real204 decoder arity");
            let fields = lines[0].split('\t').collect::<Vec<_>>();
            ensure!(
                fields.len() == 12
                    && fields[0] == anchor_copy.to_string_lossy()
                    && fields[1] == "204"
                    && fields[2] == "88128000"
                    && fields[3] == "432000",
                "205 real204 decoder scope differs"
            );
            let expected_slot = proof["strict_full_command"]["arguments"][6]
                .as_str()
                .context("204 Full terminal slot absent")?;
            let expected_hash = proof["strict_full_command"]["arguments"][7]
                .as_str()
                .context("204 Full terminal hash absent")?;
            ensure!(
                fields[8] == expected_slot && fields[9] == expected_hash,
                "205 qualified204 terminal differs from strict Full203 ancestry"
            );
            commands.push(decoded);
            commands.push(child(
                &tool(&x)?,
                &full_arguments(&scan, fields[8], fields[9], &loaded.expected),
                &x,
                "full",
            )?);
            anchor_proof = json!({"genuine_full204":proof,"copied":copied,"writer_census":anchor_writers,"source_writer_census":before});
        }
        Stage::Plugin => commands.push(child(
            &tool(&x)?,
            &[
                "205:205".into(),
                x.scan_directory.display().to_string(),
                "--threads".into(),
                "8".into(),
                "--verify-only".into(),
            ],
            &x,
            "plugin",
        )?),
        Stage::Boundary => {
            ensure!(
                x.neighbors.len() == 2,
                "205 retirement needs both204 and206 neighbors"
            );
            for epoch in [204, 206] {
                let rows = x
                    .neighbors
                    .iter()
                    .filter(|n| n.epoch == epoch)
                    .collect::<Vec<_>>();
                ensure!(rows.len() == 1, "205 boundary neighbor arity");
                let n = rows[0];
                if epoch == 204 {
                    let proof = assembly204_recovery::private_full204_anchor(
                        n.full204_terminal
                            .as_ref()
                            .context("205204 Full terminal")?,
                    )?;
                    ensure!(
                        proof["archive"] == private157::binding(&n.archive)
                            && proof["bytes"] == n.bytes,
                        "205204 boundary source changed"
                    );
                } else {
                    let r = read(n.ready_evidence.as_ref().context("205206 ready receipt")?)?;
                    ensure!(
                        r["schema"] == RECEIPT_SCHEMA
                            && r["epoch"] == 206
                            && r["archive_sha256"] == n.archive.sha256
                            && r["archive_length"] == n.bytes
                            && (r["remote_sha256_readback"] == true
                                || r["r2_composite_sha256"]
                                    .as_str()
                                    .is_some_and(|s| !s.is_empty())),
                        "205206 neighbor is not authenticated ready data"
                    );
                }
                let stamp = custody::tuple(&n.archive.path)?;
                custody::hash_exact(&n.archive.path, &stamp, &n.archive.sha256)?;
                let (left, right) = if epoch == 204 {
                    (&n.archive.path, &scan)
                } else {
                    (&scan, &n.archive.path)
                };
                commands.push(child(
                    &tool(&x)?,
                    &[
                        "--verify-pair".into(),
                        left.display().to_string(),
                        right.display().to_string(),
                    ],
                    &x,
                    &format!("boundary-{epoch}"),
                )?);
            }
        }
        Stage::Import => {
            let canonical = Path::new(CANONICAL).join("epoch-205.jet");
            peer::no_file(&canonical)?;
            let sidecar = PathBuf::from(format!("{}.sha256", canonical.display()));
            peer::no_file(&sidecar)?;
            let staging = x.output_directory.join("epoch-205.jet");
            let copied = custody::copy_and_measure(
                &scan,
                &staging,
                scan_stamp.as_ref().context("205 verified copy identity")?,
            )?;
            ensure!(
                copied.sha256 == sha,
                "205 import differs from actual verified Full digest"
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
                "205 canonical no-clobber import failed"
            );
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o400)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&sidecar)?;
            file.write_all(format!("{sha}  epoch-205.jet\n").as_bytes())?;
            file.sync_all()?;
            File::open(CANONICAL)?.sync_all()?;
            imported = json!({"archive":canonical,"identity":custody::tuple(&canonical)?,"sha256":sha,"checksum":sidecar});
        }
        Stage::Upload => {
            let canonical = Path::new(CANONICAL).join("epoch-205.jet");
            let stamp = custody::tuple(&canonical)?;
            custody::hash_exact(&canonical, &stamp, &sha)?;
            let receipt = x
                .upload_receipt
                .as_ref()
                .context("205 upload receipt missing")?;
            ensure!(
                receipt == &x.output_directory.join("epoch-205.r2.json"),
                "205 upload receipt namespace differs"
            );
            peer::no_file(receipt)?;
            commands.push(child(
                &tool(&x)?,
                &[
                    "sync".into(),
                    CANONICAL.into(),
                    "--epochs".into(),
                    "205-205".into(),
                    "--expected-archive-sha256".into(),
                    sha.clone(),
                    "--expected-archive-bytes".into(),
                    BYTES.to_string(),
                    "--receipt-directory".into(),
                    x.output_directory.display().to_string(),
                ],
                &x,
                "upload",
            )?);
            let file = custody::open(receipt)?;
            file.set_permissions(fs::Permissions::from_mode(0o400))?;
            file.sync_all()?;
            let r = read(&peer::binding(receipt)?)?;
            ensure!(
                r["schema"] == RECEIPT_SCHEMA
                    && r["epoch"] == 205
                    && r["archive_sha256"] == sha
                    && r["archive_length"] == BYTES
                    && r["archive_key"] == "epoch-205.jet"
                    && r["checksum_key"] == "epoch-205.jet.sha256"
                    && (r["remote_sha256_readback"] == true
                        || r["r2_composite_sha256"]
                            .as_str()
                            .is_some_and(|s| !s.is_empty())),
                "205 upload lacked whole-object readback and sidecar proof"
            );
        }
        Stage::Assembly => {
            bail!("205 existing continuation assembler cannot be relaunched through delivery")
        }
    }
    let stamp = scan_stamp.context("205 no measured copy after Full")?;
    custody::hash_exact(&scan, &stamp, &sha)?;
    custody::hash_exact(Path::new(OUTPUT), &original, &sha)?;
    ensure!(
        unit(x.stage.unit())? == owner,
        "205 actor changed during actual operation"
    );
    write(
        &x.output_directory.join("outcome.json"),
        &json!({"schema":"jetstreamer-continuation205-delivery-stage-outcome-v1","epoch":205,"stage":x.stage,"spec":spec,
        "source":x.source,"admission":admission,"startup_release":consumed,"invocation_id":owner["InvocationID"],"archive_sha256":sha,"archive_bytes":BYTES,
        "measurement":measurement,"source_digest_initial_state":if x.stage==Stage::Full{"unmeasured"}else{"measured_by_genuine_full"},
        "predecessor_outcomes":predecessors,"commands":commands,"anchor_proof":anchor_proof,"imported":imported,
        "retirement_boundary_only":x.stage==Stage::Boundary,"local_retirement_authorized":false,"passed":true,"issuer":peer::issuer(spec,self_sha),"authority":denied()}),
    )
}

pub(super) fn installed_stage(
    x: &StageSpec,
    spec: &BoundFile,
    runner: &BoundFile,
    fragment: &BoundFile,
    self_sha: &str,
) -> Result<()> {
    ensure!(
        runner.sha256 == self_sha && fs::read_link("/proc/self/exe")? == runner.path,
        "205 stage runner is not the actual qualified issuer"
    );
    sealed(runner, 256 << 20)?;
    ensure!(
        fragment.path == Path::new("/etc/systemd/system").join(x.stage.unit()),
        "205 stage fragment scope"
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
            .context("205 malformed stage fragment")?;
        ensure!(keys.insert(k, v).is_none(), "205 duplicate stage directive");
    }
    let argv = format!(
        "{} run-continuation205-delivery-stage {} --spec-sha256 {} --self-sha256 {}",
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
            "205 installed stage directive differs: {k}"
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
            .context("205 stage writable paths")?
            .split_whitespace()
            .collect::<BTreeSet<_>>()
            == writes.iter().map(String::as_str).collect(),
        "205 stage writable namespace differs"
    );
    let actual = completed_archive_phase::root205_properties(
        x.stage.unit(),
        "FragmentPath,DropInPaths,NeedDaemonReload,Transient,ExecStart,MemoryMax,MemoryHigh,MemorySwapMax,RuntimeMaxUSec,CPUQuotaPerSecUSec,TasksMax,Type,User,Restart,KillMode,Delegate,ProtectSystem,ProtectHome,NoNewPrivileges,PrivateNetwork,PrivateTmp,PrivateDevices,InaccessiblePaths,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,CapabilityBoundingSet,AmbientCapabilities,ExecCondition,ExecStartPre,ExecStartPost,ExecReload,ExecStop,ExecStopPost,OnSuccess,OnFailure,ReadWritePaths,LimitCORE,LimitCORESoft,LimitFSIZE,LimitFSIZESoft",
    )?;
    completed_archive_phase::root205_environment(&actual, x.environment_file.as_ref())?;
    for key in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
        "OnSuccess",
        "OnFailure",
    ] {
        ensure!(
            actual.get(key).is_some_and(String::is_empty),
            "205 stage has unqualified hook: {key}"
        );
    }
    singleton227_capture::require(
        &actual,
        &[
            ("KillMode", "control-group"),
            ("Delegate", "no"),
            ("PrivateTmp", "yes"),
            ("PrivateDevices", "yes"),
            ("CapabilityBoundingSet", "cap_dac_override cap_sys_ptrace"),
            ("AmbientCapabilities", "cap_dac_override cap_sys_ptrace"),
            ("LimitCORE", "0"),
            ("LimitCORESoft", "0"),
            ("LimitFSIZE", "171798691840"),
            ("LimitFSIZESoft", "171798691840"),
        ],
    )?;
    ensure!(
        actual
            .get("InaccessiblePaths")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(BTreeSet::from(["/tmp", "/var/tmp"])),
        "205 stage has writable temporary paths outside admitted root"
    );
    ensure!(
        actual
            .get("ReadWritePaths")
            .map(|v| v.split_whitespace().collect::<BTreeSet<_>>())
            == Some(writes.iter().map(String::as_str).collect()),
        "205 effective writable namespace differs"
    );
    ensure!(
        actual
            .get("FragmentPath")
            .is_some_and(|p| p == &fragment.path.to_string_lossy())
            && actual.get("DropInPaths").is_some_and(String::is_empty)
            && actual.get("NeedDaemonReload").map(String::as_str) == Some("no")
            && actual.get("Transient").map(String::as_str) == Some("no"),
        "205 installed stage effective fragment differs"
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
            "205 effective stage directive differs: {k}"
        );
    }
    ensure!(
        actual.get("RuntimeMaxUSec").map(String::as_str) == Some("8h")
            && actual.get("CPUQuotaPerSecUSec").map(String::as_str) == Some("8s")
            && peer::command_matches(
                actual
                    .get("ExecStart")
                    .context("205 actual stage command")?,
                &format!(
                    "{{ path={} ; argv[]={argv} ; ignore_errors=no }}",
                    runner.path.display()
                )
            ),
        "205 actual stage lifecycle/command differs"
    );
    Ok(())
}
