//! Finite original 199 authority census. Reuses accepted complete-accounting discovery,
//! the qualified retained-v2 native validator, and the existing bounded proc-reference scanner.
//! No whole-campaign source rediscovery, signals, resource samples or R2 writes.
use crate::{
    context_inputs::ContextInputs, directory_anchor, fsutil as f, model::*, process_references,
    validate,
};
use anyhow::{Context, Result, ensure};
use horizon_recovered_resource_frame_retained199_v2::{ordinary199, terminal199_context};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};
#[path = "native_properties.rs"]
mod native_properties;
const SCRATCH: &str =
    "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private";
const DEPLOY: &str = "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1";
const FIELDS: &str = "ActiveState,After,AmbientCapabilities,CPUQuotaPerSecUSec,CapabilityBoundingSet,Conflicts,ControlGroup,ControlPID,Delegate,DropInPaths,ExecMainCode,ExecMainExitTimestamp,ExecMainPID,ExecMainStartTimestamp,ExecMainStatus,ExecStart,ExecStartPost,ExecStartPre,ExecStop,ExecStopPost,FragmentPath,Group,Id,InvocationID,Job,KillMode,LoadState,MainPID,MemoryAccounting,MemoryHigh,MemoryMax,MemorySwapMax,NRestarts,NoNewPrivileges,OnFailure,OnSuccess,PrivateNetwork,PrivateTmp,ProtectHome,ProtectSystem,ReadWritePaths,RemainAfterExit,Restart,Result,RuntimeMaxUSec,SubState,TasksMax,TimersMonotonic,TriggeredBy,Triggers,Type,Unit,User";
fn command(args: &[String], max: usize) -> Result<Vec<u8>> {
    let o = Command::new("/usr/bin/systemctl")
        .arg("--system")
        .args(args)
        .env_remove("DBUS_SYSTEM_BUS_ADDRESS")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("SYSTEMD_BUS_ADDRESS")
        .env_remove("SYSTEMD_HOST")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() <= max,
        "bounded native census command failed"
    );
    Ok(o.stdout)
}
fn native(name: &str) -> Result<Value> {
    ensure!(
        !name.is_empty()
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unsafe native unit name"
    );
    let raw = command(
        &[
            "show".into(),
            name.into(),
            "--no-pager".into(),
            format!("--property={FIELDS}"),
        ],
        65536,
    )?;
    native_properties::parse(name, std::str::from_utf8(&raw)?, FIELDS)
}
fn read(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut b = Vec::new();
    Read::by_ref(&mut File::open(path)?)
        .take(max + 1)
        .read_to_end(&mut b)?;
    ensure!(b.len() as u64 <= max, "proc source exceeds bound");
    Ok(b)
}
fn start(stat: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(stat)?;
    let (_, tail) = text.rsplit_once(')').context("proc stat framing")?;
    Ok(tail
        .split_whitespace()
        .nth(19)
        .context("proc start_ticks")?
        .parse()?)
}
fn argv(pid: u64) -> Result<Vec<String>> {
    let raw = read(&PathBuf::from(format!("/proc/{pid}/cmdline")), 1 << 20)?;
    if raw.is_empty() {
        let stat = read(&PathBuf::from(format!("/proc/{pid}/stat")), 65536)?;
        let text = std::str::from_utf8(&stat)?;
        let tail = text.rsplit_once(')').context("empty argv stat")?.1;
        let parts = tail.split_whitespace().collect::<Vec<_>>();
        let kernel = parts
            .get(6)
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|f| f & 0x20_0000 != 0);
        ensure!(
            kernel || parts.first() == Some(&"Z"),
            "live user process has unreadable/empty argv"
        );
        return Ok(vec![]);
    }
    ensure!(raw.last() == Some(&0), "nonterminated actual process argv");
    raw[..raw.len() - 1]
        .split(|b| *b == 0)
        .map(|b| Ok(std::str::from_utf8(b)?.to_owned()))
        .collect()
}
fn cgroup(pid: u64) -> Result<String> {
    let raw = read(&PathBuf::from(format!("/proc/{pid}/cgroup")), 1 << 20)?;
    let text = std::str::from_utf8(&raw)?;
    let mut rows = text.lines().filter_map(|l| l.strip_prefix("0::"));
    let s = rows.next().context("unified process cgroup absent")?;
    ensure!(
        rows.next().is_none() && s.starts_with('/'),
        "ambiguous process cgroup"
    );
    Ok(s.into())
}
fn image(path: PathBuf) -> Result<Bound> {
    let m = fs::metadata(&path)?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.len() <= 128 << 20,
        "process executable custody"
    );
    let raw = read(&path, 128 << 20)?;
    Ok(Bound {
        path,
        sha256: f::sha(&raw),
    })
}
fn proc_record(pid: u64, unit: &str, iid: &str, role: &str, source: &Bound) -> Result<Process> {
    let root = PathBuf::from(format!("/proc/{pid}"));
    let before = start(&read(&root.join("stat"), 65536)?)?;
    let args = argv(pid)?;
    let exe = fs::read_link(root.join("exe"))?;
    let executable = image(exe)?;
    let group = cgroup(pid)?;
    let cwd = fs::read_link(root.join("cwd"))?;
    ensure!(
        start(&read(&root.join("stat"), 65536)?)? == before,
        "process PID reused during exact census"
    );
    Ok(Process {
        pid,
        start_ticks: before,
        unit: unit.into(),
        invocation_id: iid.into(),
        executable,
        argv: args,
        command_source: source.clone(),
        cwd,
        cgroup: group,
        descriptor_refs: vec![],
        mmap_refs: vec![],
        role: role.into(),
    })
}
fn parent_command(text: &str) -> bool {
    let producer = text.contains("jetstreamer-node")
        || text.contains("historical-worker")
        || text.contains("adaptive-root-cohort-sweep.py");
    producer
        && (text.contains("--first-epoch=199")
            || text.contains("--first-epoch 199")
            || text.contains("199-200")
            || text.contains("root-cohort-199-")
            || text.contains(DEPLOY))
}
fn known_units(a: &Value) -> Result<BTreeSet<String>> {
    let mut s = BTreeSet::new();
    for r in a["active_peer_allocations"]
        .as_array()
        .context("complete peer inventory")?
    {
        if let Some(u) = r["unit"].as_str() {
            s.insert(u.to_owned());
        }
    }
    for u in a["current_owner_hard_limits"]
        .as_object()
        .context("complete hard-limit inventory")?
        .keys()
    {
        s.insert(u.clone());
    }
    Ok(s)
}
fn existing_discovery(a: &Value, p: &Policy) -> Result<Value> {
    let before = a["workload_discovery_before"]
        .as_object()
        .context("qualified complete existing workload discovery absent")?;
    let after = a["workload_discovery_after"]
        .as_object()
        .context("qualified complete existing workload discovery after absent")?;
    ensure!(
        before == after,
        "accepted complete workload discovery changed"
    );
    for (unit, n) in after {
        if parent_command(n["ExecStart"].as_str().unwrap_or("")) {
            ensure!(
                unit == CONTROLLER,
                "another current/staged parent199 authority is already present"
            );
            validate::controller(n)?;
        }
    }
    let fleet_units = p.native_units.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        [PRODUCER, CONTROLLER, GUARD, TIMER]
            .iter()
            .all(|u| fleet_units.contains(*u)),
        "original launch family scope missing"
    );
    Ok(
        json!({"source":"existing-qualified-complete-accounting-workload-discovery",
        "before_after_serde_sha256":f::sha(&serde_json::to_vec(after)?),"known_owner_units":known_units(a)?}),
    )
}
fn queued() -> Result<Value> {
    let raw = command(
        &[
            "list-jobs".into(),
            "--no-legend".into(),
            "--plain".into(),
            "--no-pager".into(),
        ],
        1 << 20,
    )?;
    let mut rows = Vec::new();
    for line in std::str::from_utf8(&raw)?.lines() {
        if line.trim() == "No jobs running." {
            continue;
        }
        let c = line.split_whitespace().collect::<Vec<_>>();
        ensure!(c.len() >= 2, "queued job framing");
        let name = c[1];
        ensure!(
            ![PRODUCER, CONTROLLER, GUARD, TIMER].contains(&name),
            "original199 family has a real queued job"
        );
        if name.ends_with(".service") {
            let n = native(name)?;
            ensure!(
                !parent_command(n["ExecStart"].as_str().unwrap_or("")),
                "queued competing original199 parent authority"
            );
            rows.push(n);
        } else {
            rows.push(json!({"unit":name,"nonservice_native_job":true}));
        }
    }
    Ok(json!({"queued_jobs_sha256":f::sha(&raw),"actual_queued_commands":rows}))
}
fn process_claims(a: &Value) -> Result<u64> {
    known_units(a)?;
    let mut inspected = 0;
    for e in fs::read_dir("/proc")? {
        let e = e?;
        let Some(pid) = e.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        if pid == u64::from(std::process::id()) {
            continue;
        }
        let args = match argv(pid) {
            Ok(a) => a,
            Err(err) if !e.path().exists() => {
                let _ = err;
                continue;
            }
            Err(err) => return Err(err).context("incomplete relevant process claim census"),
        };
        let text = args.join(" ");
        inspected += 1;
        if parent_command(&text) {
            ensure!(
                pid == CONTROLLER_PID,
                "another parent199/worker/retry process is live"
            );
        }
        let worker = args.first().is_some_and(|s| {
            Path::new(s)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.contains("historical-worker") || n == "jetstreamer-node")
        });
        if worker {
            let group = cgroup(pid)?;
            ensure!(
                ![PRODUCER, CONTROLLER, GUARD]
                    .iter()
                    .any(|u| group == format!("/system.slice/{u}")
                        || group.starts_with(&format!("/system.slice/{u}/"))),
                "original199 family regained a replay process"
            );
        }
    }
    ensure!(inspected > 0, "empty process command census");
    Ok(inspected)
}
fn group_members() -> Result<Vec<u64>> {
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{PRODUCER}"));
    ensure!(
        Path::new("/sys/fs/cgroup/system.slice").is_dir(),
        "native cgroup parent unavailable"
    );
    if !root.try_exists()? {
        return Ok(vec![]);
    }
    let mut stack = vec![root];
    let mut members = BTreeSet::new();
    let mut count = 0;
    while let Some(dir) = stack.pop() {
        count += 1;
        ensure!(count <= 1024, "original cgroup subtree exceeds bound");
        for line in std::str::from_utf8(&read(&dir.join("cgroup.procs"), 1 << 20)?)?.lines() {
            members.insert(line.parse()?);
        }
        for e in fs::read_dir(&dir)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                stack.push(e.path());
            }
        }
    }
    Ok(members.into_iter().collect())
}
fn save(dir: &Path, name: &str, v: &Value) -> Result<Bound> {
    let m = fs::symlink_metadata(dir)?;
    ensure!(
        dir.is_absolute()
            && dir.canonicalize()? == dir
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700
            && !name.contains('/'),
        "private no-clobber census output custody"
    );
    let mut raw = serde_json::to_vec_pretty(v)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 32 << 20, "census output exceeds bound");
    let path = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    file.write_all(&raw)?;
    file.set_permissions(fs::Permissions::from_mode(0o400))?;
    file.sync_all()?;
    File::open(dir)?.sync_all()?;
    Ok(Bound {
        path,
        sha256: f::sha(&raw),
    })
}
fn endpoint(
    p: &Policy,
    a: &Value,
    dir: &Path,
    end: &str,
    inputs: &ContextInputs,
) -> Result<(Endpoint, Value)> {
    let mut rows = BTreeMap::new();
    for u in &p.native_units {
        rows.insert(u.clone(), native(u)?);
    }
    let c = &inputs.retained;
    let proof = ordinary199::load_for_context(&json!(c.original_enrollment()), c)?
        .context("original enrollment absent")?;
    let native_value = json!(rows);
    c.validate_current_membership(&native_value)?;
    proof.validate_native_retained(&native_value, c)?;
    validate::failed_state(&inputs.state(&p.quarantined_state)?)?;
    f::bytes(&p.controller_source, 1 << 20, true)?;
    f::bytes(&p.guard_source, 1 << 20, true)?;
    let mut processes = vec![proc_record(
        CONTROLLER_PID,
        CONTROLLER,
        CONTROLLER_IID,
        "quarantined-original-controller",
        &p.controller_source,
    )?];
    if let Some(pid) = rows[GUARD]["MainPID"]
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|p| *p > 1)
    {
        processes.push(proc_record(
            pid,
            GUARD,
            rows[GUARD]["InvocationID"].as_str().context("guard IID")?,
            "original-stop-only-guard",
            &p.guard_source,
        )?);
    }
    let allowed = processes.iter().map(|p| p.pid).collect::<BTreeSet<_>>();
    let mut scanned = process_claims(a)?;
    let anchor = directory_anchor::observe(p, &rows[CONTROLLER])?;
    let mut scratch_references = Vec::new();
    for target in [SCRATCH, DEPLOY, STATE] {
        let scan = process_references::scan(Path::new("/proc"), Path::new(target))?;
        scanned = scanned.max(scan.inspected_processes);
        for reference in scan.references {
            if target == SCRATCH {
                scratch_references.push(reference.clone());
            }
            let parts = reference.split_whitespace().collect::<Vec<_>>();
            let pid = parts.get(1).context("proc reference PID")?.parse::<u64>()?;
            ensure!(
                allowed.contains(&pid),
                "unreserved exact original199 tree/process reference: {reference}"
            );
            if target == SCRATCH
                && !directory_anchor::permits(&reference, anchor.as_ref())
                && (reference.contains(" fd ")
                    || reference.ends_with(" maps")
                    || reference.ends_with(" cwd")
                    || reference.ends_with(" root"))
            {
                anyhow::bail!(
                    "original199 worker scratch still has descriptor/mmap/working-root holder: {reference}"
                );
            }
        }
    }
    ensure!(
        anchor == directory_anchor::observe(p, &rows[CONTROLLER])?,
        "directory anchor changed during process scan"
    );
    if anchor.is_some() {
        ensure!(
            scratch_references
                .iter()
                .filter(|r| directory_anchor::permits(r, anchor.as_ref()))
                .count()
                == 1,
            "exact anchor missing or duplicated in complete process scan"
        );
    }
    let mut findings = Vec::new();
    for u in &p.native_units {
        let (disposition, source, iid) = if u == CONTROLLER {
            (
                "quarantined-original-controller",
                p.controller_source.clone(),
                Some(CONTROLLER_IID.to_owned()),
            )
        } else if u == PRODUCER {
            (
                "original-collected-worker",
                p.controller_source.clone(),
                None,
            )
        } else if u == GUARD || u == TIMER {
            (
                "original-stop-only-guard",
                p.guard_source.clone(),
                rows[u]["InvocationID"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned),
            )
        } else {
            ensure!(
                rows[u]["LoadState"] == "masked"
                    && rows[u]["MainPID"] == "0"
                    && rows[u]["ControlPID"] == "0"
                    && rows[u]["Job"] == "",
                "registered extra future launcher is not fenced"
            );
            (
                "persistently-fenced-future-source",
                p.controller_source.clone(),
                None,
            )
        };
        let q = save(
            dir,
            &format!("launcher-{}-{end}.json", f::sha(u.as_bytes())),
            &json!({"schema":"terminal199-parent-memory-launcher-no-retry-custody-v1","unit":u,"source":source,
            "disposition":disposition,"may_start_original_parent":false,"census_program":p.census.program,"actual_native":rows[u]}),
        )?;
        findings.push(LauncherFinding {
            unit: u.clone(),
            disposition: disposition.into(),
            source,
            qualification: q,
            current_invocation_id: iid,
            may_start_original_parent: false,
        });
    }
    let stable_sources=rows.iter().map(|(unit,n)| {
        let keys=["ExecStart","ExecStartPre","ExecStartPost","ExecStop","ExecStopPost","FragmentPath","DropInPaths","Triggers","TriggeredBy","OnFailure","OnSuccess"];
        let mut v=serde_json::Map::new();for key in keys{
            let value=if unit==GUARD && key=="ExecStart" {
                json!({"qualified_original_enrollment_command_checked":true,"immutable_stop_only_source":p.guard_source})
            }else{n[key].clone()};v.insert(key.into(),value);
        }
        (unit.clone(),Value::Object(v))
    }).collect::<BTreeMap<_,_>>();
    let mut source_listing = json!({"schema":"terminal199-actual-original-launch-authority-source-list-v1","controller_source":p.controller_source,"guard_source":p.guard_source,
        "actual_current_source_hooks":stable_sources,"existing_complete_workload_discovery":existing_discovery(a,p)?,"actual_queued_jobs":queued()?});
    if let Some(anchor) = anchor {
        source_listing["controller_directory_anchor"] =
            json!({"actual_evidence":anchor,"actual_scratch_references":scratch_references});
    }
    let e = Endpoint {
        native: rows,
        matching_processes: processes,
        scanned_process_count: scanned,
        scanned_dimensions: vec![
            "argv".into(),
            "cwd".into(),
            "descriptors".into(),
            "executable".into(),
            "mappings".into(),
            "source".into(),
        ],
        unresolved_processes: vec![],
        unreadable_processes: vec![],
        original_worker_cgroup: format!("/system.slice/{PRODUCER}"),
        original_worker_cgroup_members: group_members()?,
        original_worker_descriptor_holders: vec![],
        original_worker_mmap_holders: vec![],
        controller_state: p.quarantined_state.clone(),
        launcher_findings: findings,
        unresolved_launchers: vec![],
    };
    validate::endpoint(p, &e)?;
    Ok((e, source_listing))
}
/// Bootstrap collection reads only actual scoped authority; artifact qualification may
/// be absent here. It cannot construct a memory selection or enable registration.
pub fn capture(s: &CaptureSpec, program: &Bound, now: u64) -> Result<Bound> {
    ensure!(
        s.schema == "terminal199-parent-memory-capture-spec-v1"
            && s.policy.census.program == *program,
        "capture spec/program scope differs"
    );
    validate::policy(&s.policy)?;
    let scope = Path::new("/var/lib/jetstreamer/horizon-original199-parent-memory-census-v1")
        .join(&s.current.observer.sha256);
    ensure!(
        s.output_directory.parent() == Some(scope.as_path())
            && s.output_directory
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("capture-")),
        "new no-clobber capture output is outside exact current observer namespace"
    );
    let (_, _, before_accounting, after_accounting) = super::reader(
        &s.current,
        &s.current_reader,
        &s.reader_program,
        &s.current_reader_acceptance,
        now,
    )?;
    let inputs = ContextInputs::for_current(&s.policy, &s.current)?;
    super::terminal(
        &s.policy,
        &s.current,
        &before_accounting,
        &after_accounting,
        &inputs,
    )?;
    let (before, bsource) = endpoint(
        &s.policy,
        &before_accounting,
        &s.output_directory,
        "before",
        &inputs,
    )?;
    let (after, asource) = endpoint(
        &s.policy,
        &after_accounting,
        &s.output_directory,
        "after",
        &inputs,
    )?;
    ensure!(
        source_listing_stable(&bsource, &asource)?,
        "actual original199 source/jobs changed across census"
    );
    ensure!(
        normalize_native_pair(&json!(before.native), &json!(after.native), &inputs)?
            == json!(before.native),
        "nonperiodic native authority changed across census"
    );
    let sb = save(&s.output_directory, "source-list-before.json", &bsource)?;
    let sa = save(&s.output_directory, "source-list-after.json", &asource)?;
    let c = Census {
        schema: "terminal199-parent-memory-complete-current-census-v1".into(),
        current: s.current.clone(),
        program: program.clone(),
        scope_review: s.policy.census_scope_review.clone(),
        recorded_unix_seconds: now,
        before,
        after,
        complete_native_unit_universe: s.policy.native_units.clone(),
        complete_source_roots: vec![PathBuf::from(
            "/usr/local/lib/jetstreamer/horizon-epoch199-backfill-controller-guard-20261102-v1",
        )],
        source_listing_before: sb,
        source_listing_after: sa,
        controller_source: s.policy.controller_source.clone(),
        guard_source: s.policy.guard_source.clone(),
        source_custody_unchanged: true,
        mutation_count: 0,
    };
    save(
        &s.output_directory,
        "census.json",
        &serde_json::to_value(c)?,
    )
}
/// Guard/admission recheck: no new observer, accounting build, R2 access or writes.
/// Changed actual jobs, source, state, process claim or native membership invalidates selection.
pub(crate) fn recheck(p: &Policy, a: &Value, inputs: &ContextInputs) -> Result<()> {
    validate::failed_state(&inputs.state(&p.quarantined_state)?)?;
    f::bytes(&p.controller_source, 1 << 20, true)?;
    f::bytes(&p.guard_source, 1 << 20, true)?;
    let mut rows = BTreeMap::new();
    for u in &p.native_units {
        rows.insert(u.clone(), native(u)?);
    }
    let c = &inputs.retained;
    let proof = ordinary199::load_for_context(&json!(c.original_enrollment()), c)?
        .context("original199 enrollment absent")?;
    c.validate_current_membership(&json!(rows))?;
    proof.validate_native_retained(&json!(rows), c)?;
    validate::controller(&rows[CONTROLLER])?;
    let actual = proc_record(
        CONTROLLER_PID,
        CONTROLLER,
        CONTROLLER_IID,
        "quarantined-original-controller",
        &p.controller_source,
    )?;
    ensure!(
        actual.start_ticks == p.controller_start_ticks
            && actual.argv == p.controller_argv
            && actual.executable == p.controller_executable,
        "controller changed since scoped census"
    );
    existing_discovery(a, p)?;
    queued()?;
    process_claims(a)?;
    ensure!(
        group_members()?.is_empty(),
        "original worker cgroup regained work"
    );
    let anchor = directory_anchor::observe(p, &rows[CONTROLLER])?;
    let mut anchors_seen = 0;
    for target in [SCRATCH, DEPLOY, STATE] {
        let scan = process_references::scan(Path::new("/proc"), Path::new(target))?;
        for reference in scan.references {
            let pid = reference
                .split_whitespace()
                .nth(1)
                .context("reference PID")?
                .parse::<u64>()?;
            let guard = rows[GUARD]["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok());
            ensure!(
                pid == CONTROLLER_PID || guard == Some(pid),
                "new original199 process/tree holder invalidates parent closure"
            );
            if target == SCRATCH {
                if directory_anchor::permits(&reference, anchor.as_ref()) {
                    anchors_seen += 1;
                    continue;
                }
                ensure!(
                    !reference.contains(" fd ")
                        && !reference.ends_with(" maps")
                        && !reference.ends_with(" cwd")
                        && !reference.ends_with(" root"),
                    "worker scratch reference reappeared"
                );
            }
        }
    }
    ensure!(
        anchor == directory_anchor::observe(p, &rows[CONTROLLER])?
            && (anchor.is_none() || anchors_seen == 1),
        "directory anchor changed or missing at point of use"
    );
    c.revalidate_inputs()
}

/// Small bootstrap metadata proof for a later immutable capture plan. No current
/// accounting proof, reduction, qualification or admission is manufactured.
pub fn controller_probe() -> Result<Value> {
    let source = Bound {
        path: SCRIPT.into(),
        sha256: SCRIPT_SHA.into(),
    };
    f::bytes(&source, 1 << 20, true)?;
    let state = Bound {
        path: STATE.into(),
        sha256: STATE_SHA.into(),
    };
    validate::failed_state(&f::json(&state)?)?;
    let mut rows = BTreeMap::new();
    for u in [PRODUCER, CONTROLLER, GUARD, TIMER] {
        rows.insert(u.to_owned(), native(u)?);
    }
    validate::controller(&rows[CONTROLLER])?;
    let c = terminal199_context::Retained::load(&terminal199_context::Bound {
        path: REGISTRY.into(),
        sha256: REGISTRY_SHA.into(),
    })?;
    let proof = ordinary199::load(&json!(c.original_enrollment()))?
        .context("original enrollment missing")?;
    c.validate_current_membership(&json!(rows))?;
    proof.validate_native_retained(&json!(rows), &c)?;
    let process = proc_record(
        CONTROLLER_PID,
        CONTROLLER,
        CONTROLLER_IID,
        "quarantined-original-controller",
        &source,
    )?;
    ensure!(
        f::sha(&serde_json::to_vec(&process.argv)?) == CONTROLLER_ARGV_SHA
            && group_members()?.is_empty(),
        "controller argv or original worker drain changed"
    );
    validate::failed_state(&f::json(&state)?)?;
    Ok(
        json!({"schema":"terminal199-controller-no-retry-binding-probe-v1","controller":process,"native":rows,
        "quarantined_state":state,"controller_source":source,"controller_argv_serde_sha256":CONTROLLER_ARGV_SHA,
        "raw_original199_memory_bytes":RAW_MEMORY,"retained_controller_guard_bytes":RESIDUAL,"retained_DATA_bytes":DATA,
        "original_worker_cgroup_empty":true,"memory_credit_bytes":0,"DATA_credit_bytes":0,"parent_retirement_authorized":false,
        "replay_launch_authorized":false,"admission_authorized":false}),
    )
}

/// Reuse the existing qualified periodic guard normalization, preserving raw endpoints.
pub(crate) fn normalize_native_pair(
    before: &Value,
    after: &Value,
    inputs: &ContextInputs,
) -> Result<Value> {
    let c = &inputs.retained;
    let proof = ordinary199::load_for_context(&json!(c.original_enrollment()), c)?
        .context("original199 enrollment absent")?;
    proof.normalize_guard_retained(before, after, c)
}

/// Queue histories remain complete in both source receipts; unrelated queued
/// jobs do not invalidate unchanged original 199 authority. Re-evaluate the
/// actual competing-claim predicate before normalizing that provenance field.
pub(crate) fn source_listing_stable(before: &Value, after: &Value) -> Result<bool> {
    for source in [before, after] {
        let q = &source["actual_queued_jobs"];
        ensure!(
            f::hex(
                q["queued_jobs_sha256"]
                    .as_str()
                    .context("queued native digest")?,
                64
            ),
            "queued digest absent"
        );
        for row in q["actual_queued_commands"]
            .as_array()
            .context("actual queued command census")?
        {
            let name = row["Id"]
                .as_str()
                .or_else(|| row["unit"].as_str())
                .context("queued native identity")?;
            ensure!(
                ![PRODUCER, CONTROLLER, GUARD, TIMER].contains(&name)
                    && !parent_command(row["ExecStart"].as_str().unwrap_or("")),
                "actual queued original199 authority"
            );
        }
    }
    let mut normalized = after.clone();
    normalized["actual_queued_jobs"] = before["actual_queued_jobs"].clone();
    Ok(normalized == *before)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_parent_claims_are_distinct_from_metadata_repair_names() {
        assert!(parent_command(
            "jetstreamer-node --first-epoch=199 --last-epoch=200"
        ));
        assert!(parent_command("historical-worker root-cohort-199-200"));
        assert!(!parent_command(
            "parent-memory-select /source/epoch199.json"
        ));
        assert!(!parent_command(
            "jetstreamer-node --first-epoch=145 --last-epoch=145"
        ));
    }
    #[test]
    fn process_start_tick_parser_uses_the_last_parenthesis() {
        let mut fields = vec!["0"; 20];
        fields[19] = "12345";
        let line = format!("12 (worker (name)) {}", fields.join(" "));
        assert_eq!(start(line.as_bytes()).unwrap(), 12345);
        assert!(start(b"bad stat").is_err());
    }
}
