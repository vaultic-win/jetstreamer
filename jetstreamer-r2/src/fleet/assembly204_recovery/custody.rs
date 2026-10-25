use super::*;
use std::os::fd::AsRawFd;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(super) struct FileStamp {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub links: u64,
    pub mtime: i64,
    pub mtime_nanos: i64,
    pub ctime: i64,
    pub ctime_nanos: i64,
}
impl FileStamp {
    pub(super) fn of(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            bytes: m.len(),
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            links: m.nlink(),
            mtime: m.mtime(),
            mtime_nanos: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_nanos: m.ctime_nsec(),
        }
    }
    pub(super) fn frozen(&self, bytes: u64) -> Result<()> {
        ensure!(
            self.bytes == bytes
                && self.uid == 0
                && self.links == 1
                && self.mode & libc::S_IFMT == libc::S_IFREG
                && self.mode & 0o222 == 0,
            "204 source custody is not exact frozen single-link root data"
        );
        Ok(())
    }
}
pub(super) fn open_source(path: &Path) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "204 source alias"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "204 source is not a regular file"
    );
    Ok(file)
}
fn journal(name: &str) -> Result<Vec<u8>> {
    let o = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "_PID=1",
            &format!("UNIT={name}"),
        ])
        .output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 8 << 20,
        "204 complete PID 1 history unavailable"
    );
    Ok(o.stdout)
}
pub(super) fn terminal_shape(current: &Value, raw: &[u8]) -> Result<u64> {
    ensure!(
        current["Id"] == OLD_UNIT
            && is_idle(current)
            && (current["InvocationID"] == OLD_IID || current["InvocationID"] == ""),
        "204 original live/replaced/restarted"
    );
    let mut finished = None;
    let mut natural = false;
    let mut failure = false;
    let mut stop = false;
    let mut started = None;
    let mut previous = 0;
    let mut count = 0;
    for row in serde_json::Deserializer::from_slice(raw).into_iter::<Value>() {
        count += 1;
        ensure!(count <= 16384, "204 manager history row bound");
        let row = row?;
        let at = s(&row, "__REALTIME_TIMESTAMP")?.parse::<u64>()?;
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["UNIT"] == OLD_UNIT
                && row["INVOCATION_ID"] == OLD_IID
                && at >= previous,
            "204 manager identity/order differs"
        );
        previous = at;
        if row["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" {
            ensure!(
                at > 0 && started.replace(at).is_none(),
                "204 manager duplicate start"
            );
        }
        let msg = s(&row, "MESSAGE")?;
        let failed_id = matches!(
            row["MESSAGE_ID"].as_str(),
            Some("be02cf6855d2428ba40df7e9d022f03d" | "d9b373ed55a64feb8242e02dbe79a49c")
        );
        let failed = failed_id
            && msg
                .strip_prefix(&format!("{OLD_UNIT}: Failed with result '"))
                .and_then(|s| s.strip_suffix("'."))
                .is_some_and(|s| {
                    matches!(
                        s,
                        "resources"
                            | "protocol"
                            | "timeout"
                            | "exit-code"
                            | "signal"
                            | "core-dump"
                            | "watchdog"
                            | "start-limit-hit"
                            | "oom-kill"
                    )
                })
            && row["JOB_RESULT"] != "done";
        ensure!(!failed_id || failed, "204 contradictory failure event");
        let stopped = row["MESSAGE_ID"] == "9d1aaa27d60140bd96365438aad20286"
            && row["JOB_TYPE"] == "stop"
            && row["JOB_RESULT"] == "done";
        natural |= row["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448";
        failure |= failed;
        stop |= stopped;
        if failed || stopped {
            ensure!(
                started.is_some_and(|s| at > s),
                "204 terminal precedes start"
            );
            finished = Some(at / 1000);
        }
    }
    ensure!(
        !natural || (stop && !failure),
        "204 original naturally succeeded or has contradictory terminal facts"
    );
    finished.context("204 has no actual failed/stopped terminal")
}
pub(super) fn old_idle() -> Result<Value> {
    let names = BTreeSet::from([OLD_UNIT.into(), OLD_GUARD.into(), UNIT.into(), GUARD.into()]);
    let before = census(&names, 201, 300)?;
    let original = before.get(OLD_UNIT).context("204 old owner omitted")?;
    ensure!(
        is_idle(original)
            && (original["InvocationID"] == OLD_IID || original["InvocationID"] == ""),
        "204 old assembler is live, unknown or replaced"
    );
    ensure!(
        is_idle(before.get(OLD_GUARD).context("204 old guard omitted")?),
        "204 old guard still owns work"
    );
    for (name, row) in &before {
        if name == UNIT
            || name == GUARD
            || downstream::Stage::all()
                .iter()
                .any(|stage| stage.unit() == name)
        {
            continue;
        }
        if name != OLD_UNIT
            && name != OLD_GUARD
            && name
                .split(|c: char| !c.is_ascii_digit())
                .any(|s| s == "204")
        {
            ensure!(
                !is_live(row) && row["ActiveState"] != "activating",
                "another 204 owner exists"
            );
        }
    }
    inactive_status::no_pending_owner_trigger(OLD_UNIT, false)?;
    inactive_status::no_pending_owner_trigger(OLD_GUARD, false)?;
    let group = capped204205_work::empty_terminal_cgroup(OLD_UNIT)?;
    let old_guard_group = capped204205_work::empty_terminal_cgroup(OLD_GUARD)?;
    let prefix_root = Path::new(PREFIX_PATH)
        .parent()
        .and_then(Path::parent)
        .context("204 prefix root")?;
    let first =
        jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), prefix_root)?;
    let second = jetstreamer_horizon_observe::process_references::scan(
        Path::new("/proc"),
        Path::new(OLD_ROOT),
    )?;
    ensure!(
        first.references.is_empty() && second.references.is_empty(),
        "204 original sources retain process references"
    );
    let after = census(&names, 201, 300)?;
    ensure!(
        before == after,
        "204 source ownership changed during custody census"
    );
    Ok(
        json!({"unit_census_before":before,"unit_census_after":after,"old_cgroup":group,"old_guard_cgroup":old_guard_group,
        "prefix_references":first,"suffix_references":second,"old_owner_idle":true}),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalSpec {
    schema: String,
    original_plan: BoundFile,
    suffix_proof: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn capture_terminal(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let t: TerminalSpec = serde_json::from_value(v.clone())?;
    ensure!(
        t.schema == "jetstreamer-epoch204-assembly-recovery-terminal-spec-v1",
        "204 terminal spec"
    );
    private(&t.output_directory)?;
    // Presence is a conflict, not a reason to relabel an actual natural result.
    no_file(&Path::new(OLD_ROOT).join("receipts/continuation.json"))?;
    let idle = old_idle()?;
    let current = unit(OLD_UNIT)?;
    let raw = journal(OLD_UNIT)?;
    let finished = terminal_shape(&current, &raw)?;
    let proof_bytes = raw_proof(&t.suffix_proof)?;
    let proof_path = t.output_directory.join("suffix.json");
    write_bytes(&proof_path, &proof_bytes)?;
    let proof = binding(&proof_path)?;
    lineage::sources(&t.original_plan, &proof)?;
    let journal_path = t.output_directory.join("manager.jsonl");
    write_bytes(&journal_path, &raw)?;
    let manager = binding(&journal_path)?;
    let idle_after = old_idle()?;
    ensure!(current == unit(OLD_UNIT)?, "204 original terminal changed");
    no_file(&Path::new(OLD_ROOT).join("receipts/continuation.json"))?;
    write(
        &t.output_directory.join("terminal.json"),
        &json!({
        "schema":"jetstreamer-epoch204-assembly-recovery-original-terminal-v1","epoch":204,"unit":OLD_UNIT,
        "invocation_id":OLD_IID,"original_plan_sha256":OLD_PLAN,"original_plan":t.original_plan,
        "suffix_proof":proof,"outcome":"failed_or_stopped","epoch_started_unix_millis":ORIGIN,
        "manager_journal":private157::binding(&manager),"manager_journal_complete":true,
        "finished_unix_millis":finished,"current_unit":current,"old_cgroup_empty":true,
        "source_reference_census_empty":true,"custody_before":idle,"custody_after":idle_after,
        "original_complete_outcome_absent":true,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
pub(super) fn validate_terminal_saved(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-epoch204-assembly-recovery-original-terminal-v1"
            && v["epoch"] == 204
            && v["unit"] == OLD_UNIT
            && v["invocation_id"] == OLD_IID
            && v["original_plan_sha256"] == OLD_PLAN
            && v["outcome"] == "failed_or_stopped"
            && v["epoch_started_unix_millis"] == ORIGIN
            && v["old_cgroup_empty"] == true
            && v["source_reference_census_empty"] == true
            && v["original_complete_outcome_absent"] == true
            && v["manager_journal_complete"] == true
            && is_lower_hex(s(&v["issuer"], "executable_sha256")?, 64),
        "204 original terminal is not issued exact failure/custody evidence"
    );
    let raw = sealed(
        &serde_json::from_value(v["manager_journal"].clone())?,
        8 << 20,
    )?;
    ensure!(
        n(v, "finished_unix_millis")? == terminal_shape(&v["current_unit"], &raw)?,
        "204 terminal clock differs"
    );
    deny(&v["authority"])
}
pub(super) fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    private(path.parent().context("204 byte receipt parent")?)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(())
}
fn raw_proof(b: &BoundFile) -> Result<Vec<u8>> {
    ensure!(b.sha256 == SUFFIX_PROOF, "204 suffix proof primary digest");
    let f = open_source(&b.path)?;
    let before = FileStamp::of(&f.metadata()?);
    ensure!(
        before.links == 1 && matches!(before.uid, 0 | 1000) && before.mode & 0o022 == 0,
        "unsafe suffix proof"
    );
    let bytes = read_stable_bounded(&b.path, 1 << 20, "204 genuine suffix proof")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == SUFFIX_PROOF
            && before == FileStamp::of(&fs::symlink_metadata(&b.path)?),
        "204 suffix proof changed"
    );
    Ok(bytes)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureSpec {
    schema: String,
    original_plan: BoundFile,
    original_terminal: BoundFile,
    suffix_proof: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn capture_sources(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let c: CaptureSpec = serde_json::from_value(v.clone())?;
    ensure!(
        c.schema == "jetstreamer-epoch204-assembly-recovery-source-spec-v1",
        "204 source spec"
    );
    private(&c.output_directory)?;
    let terminal = read(&c.original_terminal)?;
    validate_terminal_saved(&terminal)?;
    ensure!(
        c.original_plan.sha256 == OLD_PLAN,
        "204 source plan differs"
    );
    let proof_bytes = raw_proof(&c.suffix_proof)?;
    let idle_before = old_idle()?;
    let proof_path = c.output_directory.join("suffix.json");
    write_bytes(&proof_path, &proof_bytes)?;
    let proof = binding(&proof_path)?;
    lineage::sources(&c.original_plan, &proof)?;
    let mut sources = Vec::new();
    for (path, sha, bytes) in [
        (PREFIX_PATH, PREFIX_SHA, 103_318_151_802),
        (SUFFIX_PATH, SUFFIX_SHA, 155_545_863),
    ] {
        let file = open_source(Path::new(path))?;
        let before = FileStamp::of(&file.metadata()?);
        ensure!(
            before.links == 1 && before.bytes == bytes && matches!(before.uid, 0 | 1000),
            "204 source before freeze differs"
        );
        no_sidecar(Path::new(path))?;
        if before.uid != 0 || before.mode & 0o222 != 0 {
            ensure!(
                unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } == 0,
                "204 source custody transfer failed"
            );
            file.set_permissions(fs::Permissions::from_mode(0o400))?;
            file.sync_all()?;
        }
        let frozen = FileStamp::of(&file.metadata()?);
        frozen.frozen(bytes)?;
        ensure!(
            frozen == FileStamp::of(&fs::symlink_metadata(path)?),
            "204 source name changed during freeze"
        );
        sources.push(json!({"path":path,"sha256":sha,"identity":frozen,"identity_before_custody":before,
            "source_digest_basis":"preserved genuine source proof; merger rehashes exact handle","body_reads":0}));
    }
    let idle_after = old_idle()?;
    write(
        &c.output_directory.join("source-capture.json"),
        &json!({
        "schema":"jetstreamer-epoch204-assembly-recovery-source-capture-v1","epoch":204,
        "original_invocation_id":OLD_IID,"original_plan":c.original_plan,"original_terminal":c.original_terminal,
        "suffix_proof":private157::binding(&proof),"captured_unix_millis":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
        "original_owner_idle":true,"no_source_references":true,"sources":sources,"idle_before":idle_before,
        "idle_after":idle_after,"archive_body_reads":0,"issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
pub(super) fn validate_source_capture(
    c: &Value,
    old: &BoundFile,
    terminal: &BoundFile,
    proof: &BoundFile,
    finished: u64,
) -> Result<()> {
    ensure!(
        c["schema"] == "jetstreamer-epoch204-assembly-recovery-source-capture-v1"
            && c["epoch"] == 204
            && c["original_invocation_id"] == OLD_IID
            && c["original_plan"] == private157::binding(old)
            && c["original_terminal"] == private157::binding(terminal)
            && c["suffix_proof"] == private157::binding(proof)
            && n(c, "captured_unix_millis")? >= finished
            && c["original_owner_idle"] == true
            && c["no_source_references"] == true
            && c["archive_body_reads"] == 0
            && is_lower_hex(s(&c["issuer"], "executable_sha256")?, 64),
        "204 source capture join/custody differs"
    );
    let rows = c["sources"].as_array().context("204 capture sources")?;
    ensure!(rows.len() == 2, "204 capture source arity");
    for (row, path, sha, bytes) in [
        (&rows[0], PREFIX_PATH, PREFIX_SHA, 103_318_151_802),
        (&rows[1], SUFFIX_PATH, SUFFIX_SHA, 155_545_863),
    ] {
        ensure!(
            row["path"] == path && row["sha256"] == sha && row["body_reads"] == 0,
            "204 source tuple differs"
        );
        let stamp: FileStamp = serde_json::from_value(row["identity"].clone())?;
        stamp.frozen(bytes)?;
    }
    deny(&c["authority"])
}
pub(super) fn check_source_names(c: &Value) -> Result<()> {
    for source in c["sources"].as_array().context("204 captured sources")? {
        let path = Path::new(s(source, "path")?);
        let file = open_source(path)?;
        let stamp: FileStamp = serde_json::from_value(source["identity"].clone())?;
        ensure!(
            FileStamp::of(&file.metadata()?) == stamp,
            "204 frozen source changed"
        );
        no_sidecar(path)?;
    }
    Ok(())
}
pub(super) fn plan_scope(p: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-epoch204-assembly-only-recovery-plan-v1"
            && p["epoch"] == 204
            && p["original_plan"]["sha256"] == OLD_PLAN
            && p["suffix_proof"]["sha256"] == SUFFIX_PROOF
            && p["output_root"] == ROOT
            && p["admission_receipt"] == format!("{ROOT}/admission.json")
            && p["epoch_started_unix_millis"] == ORIGIN
            && p["maximum_millis"] == DURATION
            && p["maximum_output_bytes"] == OUTPUT_MAX
            && matches!(p["zstd_level"].as_i64(), Some(3 | 9))
            && is_lower_hex(s(p, "executable_sha256")?, 64),
        "204 exact helper plan scope differs"
    );
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanSpec {
    schema: String,
    original_plan: BoundFile,
    original_terminal: BoundFile,
    source_capture: BoundFile,
    assembler: BoundFile,
    guard_spec: BoundFile,
    assembler_capture: BoundFile,
    zstd_level: i32,
    output: PathBuf,
}
pub(super) fn issue_plan(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let x: PlanSpec = serde_json::from_value(v.clone())?;
    ensure!(
        x.schema == "jetstreamer-epoch204-assembly-recovery-plan-issuer-spec-v1"
            && matches!(x.zstd_level, 3 | 9),
        "204 plan issuer spec"
    );
    let terminal = read(&x.original_terminal)?;
    validate_terminal_saved(&terminal)?;
    let capture = read(&x.source_capture)?;
    let proof: BoundFile = serde_json::from_value(capture["suffix_proof"].clone())?;
    validate_source_capture(
        &capture,
        &x.original_plan,
        &x.original_terminal,
        &proof,
        n(&terminal, "finished_unix_millis")?,
    )?;
    lineage::sources(&x.original_plan, &proof)?;
    old_idle()?;
    check_source_names(&capture)?;
    sealed(&x.assembler, 128 << 20)?;
    let approved = read(&x.assembler_capture)?;
    ensure!(
        approved["schema"] == "jetstreamer-epoch204-assembly-recovery-production-binding-v1"
            && approved["source_revision"] == "94705c5d546341f4fdfc6cc50c819c4031f9ab1d"
            && approved["artifact"] == private157::binding(&x.assembler)
            && approved["production_capture_verified"] == true
            && approved["qa_verified"] == true,
        "204 standalone 94705 production capture/seal is still required"
    );
    let guard = read(&x.guard_spec)?;
    ensure!(
        guard["executable_sha256"] == x.assembler.sha256
            && guard["producer_unit"] == UNIT
            && guard["guard_unit"] == GUARD,
        "204 guard artifact differs"
    );
    let plan = json!({"schema":"jetstreamer-epoch204-assembly-only-recovery-plan-v1","epoch":204,
        "executable_sha256":x.assembler.sha256,"original_plan":x.original_plan,"suffix_proof":proof,
        "original_terminal":x.original_terminal,"source_capture":x.source_capture,"guard_spec":x.guard_spec,
        "admission_receipt":format!("{ROOT}/admission.json"),"output_root":ROOT,"zstd_level":x.zstd_level,
        "maximum_millis":DURATION,"maximum_output_bytes":OUTPUT_MAX,"epoch_started_unix_millis":ORIGIN});
    plan_scope(&plan)?;
    let result = write(&x.output, &plan)?;
    write(
        &x.output.with_extension("issuer.json"),
        &json!({"schema":"jetstreamer-epoch204-assembly-recovery-plan-issuance-v1",
        "plan":private157::binding(&result),"assembler":x.assembler,"assembler_capture":x.assembler_capture,
        "issuer":issuer(spec,self_sha),"authority":denied()}),
    )?;
    Ok(())
}
