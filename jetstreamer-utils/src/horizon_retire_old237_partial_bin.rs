//! Retirement of one superseded, incomplete, non-append-resumable epoch 237 file.
//! No remote client, directory deletion, publication, or producer control exists.
//! Historical size is not free-space credit. Runtime admission belongs to Main.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        ffi::CString,
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::{fd::AsRawFd, unix::{ffi::OsStrExt, fs::{MetadataExt, OpenOptionsExt}}},
        path::{Path, PathBuf},
        process::Command,
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

const OLD: &str = "/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-v1";
const RUN: &str = concat!("/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-v1/state/",
    "destination-b101133264beb5653bf62c0288153254f04c04e1c5d6370a8b4d4b07441b8f54/",
    "work/root-cohort-237-237/run-1213927-1793421489530010065");
const UNIT: &str = "horizon-qualify-237-general-target1-v1.service";
const IID: &str = "f77854054df74e468e717668051429c9";
const GUARD: &str = "horizon-237-general-target1-protective-v1.service";
const TIMER: &str = "horizon-237-general-target1-protective-v1.timer";
const SUCCESSOR: &str = "horizon-qualify-237-general-target1-budget620-v2.service";
const SUCCESSOR_IID: &str = "3949b88a4ca34fc892a19f219cebd476";
const STATE: &str = "/var/lib/jetstreamer/horizon-old237-partial-retirement-v1";
const LIMIT: u64 = 4 * 1024 * 1024;

// Exact already sealed small records. No adjacent digest supplies its own authority.
const RECORDS: &[(&str, &str)] = &[
    ("/var/lib/jetstreamer/horizon-237-guard-stop-discovered-cycle717-v1/terminal-evidence.json", "626cf18776763ad9ba2edaf6fd32b206aa7d6c95eb6e345a5f0546712d49f93a"),
    ("/var/lib/jetstreamer/horizon-237-guard-stop-discovered-cycle717-v1/guard-stop-binding.json", "9a19047b426a38d94f7eebcbade6760e46104d7d9f14a1e3ef70cf330a17a204"),
    ("/var/lib/jetstreamer/horizon-237-general-target1-guard-receipts-v1/stop-intent.json", "df19a2355cc49577600a0d449ebc5e0e9ca980056f86b986c2b9efefd81246e4"),
    ("/var/lib/jetstreamer/horizon-237-failed-scratch-retirement-cycle717-v1/precheck.json", "9d8b00eff47f73f50373d70ea8bb37a512db68030e79b924cba141f0b05b2394"),
    ("/var/lib/jetstreamer/horizon-237-failed-scratch-retirement-cycle717-v1/preserved-cohort-state.json", "f6a3bbe06ad8c1d349d38b95d8045e3d0637e6e524db0c8631fedc6d39f6f76d"),
    ("/var/lib/jetstreamer/horizon-237-failed-scratch-retirement-cycle717-v1/completion.json", "59cd6cdf3def31c619df31c06fac286388b12e4a3ad5b9d2cc54e2953b87ff5d"),
    ("/var/lib/jetstreamer/horizon-237-guard-stop-discovered-cycle717-v1/guard-retry-stop-completion.json", "164e0d99305f8231b629eb2684d3a1bdc3a9f758b62b619d1b5a91a1f4ff1165"),
    ("/var/lib/jetstreamer/horizon-237-budget620-preparation-v2/actual-launch.json", "9647e8c4e7989c6ca3909b83cf11f77a0a2eb5e1e69dce87067ba01526645bb6"),
    ("/var/lib/jetstreamer/horizon-237-budget620-preparation-v2/producer-unit-source.json", "58fdfe8338f818d75d1472694443400de0a90973e34007f6adf597c4a2b4ccce"),
    ("/var/lib/jetstreamer/horizon-237-failed-scratch-retirement-cycle717-v1/retirement-intent.json", "a2db265343c3456cbb38a20e82cc47e4d026e41f13cf5fa5d340a3c82ded5d8c"),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    archive_sha256: String,
    local_failed_output_retirement_authorized: bool,
    archive_publication_authorized: bool,
    remote_mutations: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64, inode: u64, size: u64, blocks: u64, uid: u32, gid: u32,
    mode: u32, nlink: u64, mtime: i64, mtime_nsec: i64,
}
fn identity(m: &Metadata) -> Identity {
    Identity { device: m.dev(), inode: m.ino(), size: m.len(), blocks: m.blocks(),
        uid: m.uid(), gid: m.gid(), mode: m.mode(), nlink: m.nlink(),
        mtime: m.mtime(), mtime_nsec: m.mtime_nsec() }
}
fn expected() -> Identity {
    Identity { device: 66305, inode: 11311387, size: 149096347639, blocks: 291204144,
        uid: 1000, gid: 1000, mode: 33152, nlink: 1,
        mtime: 1793563520, mtime_nsec: 971972622 }
}
fn source() -> PathBuf { Path::new(RUN).join("archives/epoch-237.jet") }
fn quarantine() -> PathBuf { Path::new(STATE).join("epoch-237.partial.quarantine") }
fn now() -> Result<u128> { Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()) }
fn digest(mut f: impl Read) -> Result<String> {
    let mut sha = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop { let n = f.read(&mut buf)?; if n == 0 { break; } sha.update(&buf[..n]); }
    Ok(format!("{:x}", sha.finalize()))
}
fn valid_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn open_read(p: &Path) -> Result<File> {
    Ok(OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(p)?)
}
fn absent(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(false), Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn small_owned(p: &Path, uid: u32) -> Result<Vec<u8>> {
    ensure!(p.is_absolute() && p.canonicalize()? == p, "aliased evidence path");
    let mut f = open_read(p)?;
    let a = f.metadata()?;
    ensure!(a.is_file() && a.uid() == uid && a.nlink() == 1 && a.mode() & 0o022 == 0 && a.len() <= LIMIT,
        "unsafe small evidence file");
    let mut data = Vec::new();
    (&mut f).take(LIMIT + 1).read_to_end(&mut data)?;
    let b = f.metadata()?;
    ensure!(data.len() as u64 == a.len() && identity(&a) == identity(&b)
        && a.ctime() == b.ctime() && a.ctime_nsec() == b.ctime_nsec(), "evidence changed");
    Ok(data)
}
fn small(p: &Path) -> Result<Vec<u8>> { small_owned(p, 0) }
fn read_json(p: &Path) -> Result<Value> { Ok(serde_json::from_slice(&small(p)?)?) }
fn state_directory() -> Result<File> {
    let p = Path::new(STATE);
    let f = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(p)?;
    let m = f.metadata()?;
    ensure!(p.canonicalize()? == p && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "state directory must already exist, canonical, root:root mode 0700");
    ensure!(m.dev() == expected().device, "quarantine must be on the source filesystem");
    Ok(f)
}
fn write_once(name: &str, value: &Value) -> Result<()> {
    let dir = state_directory()?;
    // A crash during writing leaves only an uncommitted temporary member. The
    // canonical receipt appears atomically, after its entire body is durable.
    let temporary = format!(".{name}.{}-{}.tmp", std::process::id(), now()?);
    let p = Path::new(STATE).join(&temporary);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW).open(&p)?;
    let mut bytes = serde_json::to_vec_pretty(value)?; bytes.push(b'\n');
    f.write_all(&bytes)?; f.sync_all()?;
    let a = CString::new(temporary)?; let b = CString::new(name)?;
    let rc = unsafe { libc::renameat2(dir.as_raw_fd(), a.as_ptr(), dir.as_raw_fd(), b.as_ptr(), libc::RENAME_NOREPLACE) };
    ensure!(rc == 0, "receipt no-clobber commit failed: {}", std::io::Error::last_os_error());
    dir.sync_all()?;
    Ok(())
}
fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(p.schema == "jetstreamer-old237-partial-retirement-plan-v1" && valid_sha(&p.archive_sha256), "invalid exact plan");
    ensure!(p.local_failed_output_retirement_authorized && !p.archive_publication_authorized && !p.remote_mutations,
        "plan must authorize only exact failed local output retirement");
    Ok(())
}
fn validate_records(records: &[Value]) -> Result<()> {
    ensure!(records.len() == RECORDS.len(), "incomplete historical records");
    let t = &records[0];
    ensure!(t["schema"] == "horizon-237-authenticated-stop-event-v1" && t["epoch"] == 237
        && t["invocation_id"] == IID && t["stopped_before_terminal_slot"] == true
        && t["not_a_verified_completion"] == true && t["last_observed_slot"] == 102753469
        && t["required_terminal_slot"] == 102815999, "wrong terminal or complete output");
    for (fragment, message_id) in [("Stopping ", "de5b426a63be47a7b6ac3eaac82e2f6f"), ("Stopped ", "9d1aaa27d60140bd96365438aad20286")] {
        ensure!(t["stop_journal"].as_array().context("stop journal")?.iter().any(|r|
            r["_PID"] == "1" && r["_UID"] == "0" && r["_EXE"] == "/usr/lib/systemd/systemd"
            && r["UNIT"] == UNIT && r["INVOCATION_ID"] == IID && r["MESSAGE_ID"] == message_id
            && r["MESSAGE"].as_str().is_some_and(|s| s.starts_with(fragment))), "missing original trusted stop record");
    }
    ensure!(records[1]["partial_jet_path"].as_str() == source().to_str()
        && records[1]["stop_reason"] == "root-physical-budget", "wrong stopped partial");
    ensure!(records[3]["qualified_in_place_resume_cursor_present"] == false
        && records[3]["archive_preserved"].as_str() == source().to_str(), "resume cursor or wrong archive");
    ensure!(records[5]["partial_archive_identity_unchanged"] == true
        && records[5]["cohort_state_unchanged"] == true && records[5]["scratch_root_preserved_empty"] == true,
        "scratch was not retired while preserving the diagnostic");
    ensure!(records[6]["actual_after"]["Id"] == TIMER && records[6]["actual_after"]["ActiveState"] == "inactive", "retry timer not retired");
    ensure!(records[7]["manager"]["Id"] == SUCCESSOR && records[7]["manager"]["InvocationID"] == SUCCESSOR_IID
        && records[7]["launched"] == true, "independent successor not launched");
    let unit = records[8]["new_unit_text"].as_str().context("successor unit source")?;
    let unset = unit.lines().find(|l| l.starts_with("UnsetEnvironment=")).context("unset environment")?;
    ensure!(unset.split_whitespace().any(|s| s == "JETSTREAMER_ROOT_COHORT_RESUME_RUN")
        && !unit.contains(&format!("JETSTREAMER_ROOT_COHORT_RESUME_RUN={RUN}"))
        && unit.contains("JETSTREAMER_PRIVATE_RUN_ROOT=/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-budget620-v2/state")
        && !records[7]["manager"]["ExecStart"].as_str().context("successor exec")?.contains(OLD), "successor borrowed old mutable state");
    ensure!(records[9]["preserved_manifests"] == json!([]), "unpreserved segment manifests need independent review");
    Ok(())
}
fn records() -> Result<Value> {
    let mut values = Vec::new(); let mut bindings = Vec::new();
    for (path, sha) in RECORDS {
        let bytes = small(Path::new(path))?;
        ensure!(digest(bytes.as_slice())? == *sha, "historical evidence hash mismatch: {path}");
        values.push(serde_json::from_slice(&bytes)?);
        bindings.push(json!({"path":path,"sha256":sha}));
    }
    validate_records(&values)?;
    // Re-read the retained cohort metadata, never any snapshot/archive input body.
    let current = small_owned(&Path::new(RUN).join("cohort-state.json"), 1000)?;
    ensure!(current.len() as u64 <= LIMIT && digest(current.as_slice())? == RECORDS[4].1,
        "original cohort state changed");
    for suffix in [".sha256", ".full-verification.json", ".plugin-verification.json"] {
        let p = PathBuf::from(format!("{}{suffix}", source().display()));
        ensure!(absent(&p)?, "archive now has completion/verification evidence; review instead");
    }
    Ok(json!(bindings))
}

fn systemctl(args: &[&str]) -> Result<String> {
    let o = Command::new("/usr/bin/systemctl").args(args).output()?;
    ensure!(o.status.success(), "systemctl inspection failed");
    Ok(String::from_utf8(o.stdout)?)
}
fn properties(unit: &str) -> Result<BTreeMap<String, String>> {
    let text = systemctl(&["show", unit, "--property=Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Restart,Job,Result,ExecMainCode,ExecMainStatus"])?;
    text.lines().map(|l| { let (k,v) = l.split_once('=').context("bad manager output")?;
        Ok((k.to_string(),v.to_string())) }).collect()
}
fn terminal() -> Result<Value> {
    let mut states = Vec::new();
    for unit in [UNIT, GUARD, TIMER] {
        let s = properties(unit)?;
        ensure!(s.get("ActiveState").map(String::as_str) == Some("inactive")
            && s.get("SubState").map(String::as_str) == Some("dead"), "old producer or retry is active");
        for key in ["MainPID", "ControlPID", "NRestarts"] {
            ensure!(s.get(key).is_none_or(|v| v == "0"), "old actor has process/restart");
        }
        ensure!(s.get("Job").is_none_or(String::is_empty), "old actor has queued job");
        if unit == UNIT && s.get("LoadState").map(String::as_str) != Some("not-found") {
            ensure!(s.get("InvocationID").map(String::as_str) == Some(IID)
                && s.get("Restart").map(String::as_str) == Some("no"), "old original invocation changed or may restart");
        }
        states.push(json!({"unit":unit,"state":s}));
    }
    let jobs = systemctl(&["list-jobs", "--no-legend", "--plain"])?;
    ensure!(!jobs.lines().any(|l| l.split_whitespace().any(|s| [UNIT,GUARD,TIMER].contains(&s))), "queued old relaunch");
    // A staged unit referencing the old generation must be one of the exact inert
    // originals above. Do not permit a new/replacement recipe to borrow old bytes.
    for root in ["/run/systemd/system", "/etc/systemd/system", "/run/systemd/transient", "/run/systemd/generator", "/run/systemd/generator.early", "/run/systemd/generator.late"] {
        let root = Path::new(root);
        if !absent(root)? { scan_staged(root, &jobs)?; }
    }
    Ok(json!(states))
}
fn scan_staged(root: &Path, jobs: &str) -> Result<()> {
    for e in fs::read_dir(root)? {
        let e = e?; let p = e.path(); let m = fs::symlink_metadata(&p)?;
        if m.is_dir() { scan_staged(&p, jobs)?; continue; }
        // Enabled unit symlinks can stage an automatic relaunch even when inert.
        if m.file_type().is_symlink() {
            let link = fs::read_link(&p)?;
            let name = link.file_name().and_then(|s| s.to_str()).unwrap_or("");
            ensure!(![UNIT,GUARD,TIMER].contains(&name), "old actor remains enabled/linked");
            continue;
        }
        if !m.is_file() || m.len() > LIMIT { continue; }
        let bytes = fs::read(&p)?;
        if !bytes.windows(OLD.len()).any(|w| w == OLD.as_bytes()) { continue; }
        let name = p.file_name().and_then(|s| s.to_str()).context("unit name")?;
        ensure!(root == Path::new("/run/systemd/system") && [UNIT, GUARD, TIMER].contains(&name),
            "foreign staged unit references old generation: {}", p.display());
        ensure!(!jobs.split_whitespace().any(|s| s == name), "referencing actor has queued job");
    }
    Ok(())
}
fn references() -> Result<()> {
    let mut found = Vec::new();
    for e in fs::read_dir("/proc")? {
        let e = e?; let name = e.file_name();
        let Some(pid) = name.to_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())) else { continue; };
        if pid.parse::<u32>()? == std::process::id() { continue; }
        let proc = e.path();
        for name in ["cmdline", "maps"] {
            match fs::read(proc.join(name)) {
                Ok(bytes) => if [OLD.as_bytes(), quarantine().as_os_str().as_bytes()].iter().any(|p| bytes.windows(p.len()).any(|w| w == *p)) {
                    found.push(format!("pid {pid} {name}"));
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(e).context("incomplete process scan"),
            }
        }
        let mut paths = vec![proc.join("cwd"),proc.join("root"),proc.join("exe")];
        match fs::read_dir(proc.join("fd")) {
            Ok(fds) => for fd in fds { paths.push(fd?.path()); },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e).context("incomplete descriptor scan"),
        }
        for p in paths {
            match fs::read_link(&p) {
                Ok(link) => {
                    let text = link.to_string_lossy();
                    let link = Path::new(text.strip_suffix(" (deleted)").unwrap_or(&text));
                    let inode_ref = match fs::metadata(&p) {
                        Ok(m) => m.dev() == expected().device && m.ino() == expected().inode,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                        Err(e) => return Err(e).context("incomplete inode reference scan"),
                    };
                    if link.starts_with(OLD) || link == quarantine() || inode_ref { found.push(format!("pid {pid} {}", p.display())); }
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(e).context("incomplete process-link scan"),
            }
        }
    }
    ensure!(found.is_empty(), "old output still referenced: {found:?}");
    Ok(())
}
fn file_identity(path: &Path, original: bool) -> Result<Identity> {
    ensure!(path.canonicalize()? == path, "aliased target");
    let m = fs::symlink_metadata(path)?;
    ensure!(m.is_file() && identity(&m) == expected(), "foreign target identity");
    if original { ensure!(m.ctime() == 1793563520 && m.ctime_nsec() == 971972622, "original ctime changed"); }
    Ok(identity(&m))
}
fn hash_target(path: &Path, original: bool, sha: &str) -> Result<Identity> {
    let before = file_identity(path, original)?;
    let f = open_read(path)?; let m = f.metadata()?;
    ensure!(identity(&m) == before, "target replaced before hashing");
    eprintln!("Checking old epoch 237 diagnostic SHA-256: {} bytes at {}", before.size, path.display());
    let mut reader = &f; let mut hasher = Sha256::new(); let mut bytes = [0u8; 1024 * 1024];
    let mut total = 0u64; let mut next = 10_000_000_000u64; let started = Instant::now();
    loop {
        let n = reader.read(&mut bytes)?; if n == 0 { break; }
        hasher.update(&bytes[..n]); total += n as u64;
        if total >= next {
            eprintln!("Old epoch 237 diagnostic hash progress: {total}/{} bytes in {} seconds", before.size, started.elapsed().as_secs());
            next = next.saturating_add(10_000_000_000);
        }
    }
    ensure!(total == before.size && format!("{:x}", hasher.finalize()) == sha, "payload digest mismatch");
    let after = f.metadata()?;
    ensure!(identity(&after) == before && after.ctime() == m.ctime() && after.ctime_nsec() == m.ctime_nsec()
        && file_identity(path, original)? == before, "target changed during hashing");
    Ok(before)
}
fn operation(plan_sha: &str, body_sha: &str) -> Value {
    json!({"schema":"jetstreamer-old237-partial-retirement-operation-v1", "plan_sha256":plan_sha,
        "source":source(),"quarantine":quarantine(),"identity":expected(),"archive_sha256":body_sha,
        "source_ctime_unix_nanos":1793563520971972622_u64,
        "original_unit":UNIT,"original_invocation_id":IID,"superseded_by":SUCCESSOR_IID,
        "last_observed_slot":102753469_u64,"required_terminal_slot":102815999_u64,
        "stop_reason":"root-physical-budget","not_a_verified_epoch_completion":true,
        "source_commit":"46b4b4ad551b9f7866a8aa6fb8569dc9e9917908",
        "nonresumability":"resumed root cohort preserves existing output then replays; mutable scratch retired",
        "archive_publication_authorized":false,"remote_mutations":false})
}
fn require_record(name: &str, op: &Value) -> Result<Value> {
    let v = read_json(&Path::new(STATE).join(name))?;
    ensure!(v["operation"] == *op, "interrupted operation identity differs"); Ok(v)
}
fn require_unlinked_chain(op: &Value) -> Result<()> {
    let custody = require_record("custody.json", op)?;
    let unlink = require_record("unlink-intent.json", op)?;
    ensure!(custody["identity"] == json!(expected()) && unlink["identity"] == json!(expected())
        && custody["complete_local_sha256_verified"] == true && custody["root_private_quarantine"] == true,
        "missing fully hashed quarantine custody before unlink");
    Ok(())
}
fn rename_exact() -> Result<()> {
    let src = source(); let dst = quarantine();
    let parent = src.parent().context("source parent")?;
    ensure!(parent.canonicalize()? == parent, "source parent alias");
    let a = OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(parent)?;
    let b = state_directory()?;
    file_identity(&src, true)?;
    let source_name = CString::new("epoch-237.jet")?;
    let dest_name = CString::new("epoch-237.partial.quarantine")?;
    let rc = unsafe { libc::renameat2(a.as_raw_fd(), source_name.as_ptr(), b.as_raw_fd(), dest_name.as_ptr(), libc::RENAME_NOREPLACE) };
    ensure!(rc == 0, "exact no-clobber quarantine rename failed: {}", std::io::Error::last_os_error());
    a.sync_all()?; b.sync_all()?;
    file_identity(&dst, false)?;
    ensure!(absent(&src)?, "source reappeared after quarantine");
    Ok(())
}
fn validate_lifecycle(source: bool, quarantine: bool, intent: bool, custody: bool, unlink: bool, complete: bool) -> Result<()> {
    ensure!(!(source && quarantine), "both namespaces occupied");
    ensure!(!unlink || custody, "unlink intent lacks fully verified custody");
    ensure!(!custody || intent, "quarantine custody lacks original retirement intent");
    if complete {
        ensure!(!source && !quarantine && intent && custody && unlink, "invalid completed namespace");
    } else if !intent {
        ensure!(source && !quarantine && !custody && !unlink, "fresh operation requires original file only");
    } else if source {
        ensure!(!custody && !unlink, "original namespace reappeared after custody");
    } else if !quarantine {
        ensure!(custody && unlink, "missing file without a durable authorized unlink chain");
    }
    Ok(())
}
fn run(plan: &Plan, plan_sha: &str, self_sha: &str, check: bool) -> Result<Value> {
    validate_plan(plan)?; let dir = state_directory()?;
    ensure!(unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another exact retirement operation holds the state directory lock");
    let evidence = records()?; let actors = terminal()?; references()?;
    let op = operation(plan_sha, &plan.archive_sha256);
    let completion_path = Path::new(STATE).join("completion.json");
    let has_source = !absent(&source())?; let has_quarantine = !absent(&quarantine())?;
    let intent_path = Path::new(STATE).join("intent.json");
    validate_lifecycle(has_source, has_quarantine, !absent(&intent_path)?,
        !absent(&Path::new(STATE).join("custody.json"))?,
        !absent(&Path::new(STATE).join("unlink-intent.json"))?, !absent(&completion_path)?)?;
    if !absent(&completion_path)? {
        let done = require_record("completion.json", &op)?;
        ensure!(absent(&source())? && absent(&quarantine())?, "completed target reappeared");
        ensure!(done["status"] == "complete" && done["source_and_quarantine_absent"] == true,
            "invalid completion receipt");
        require_record("intent.json", &op)?; require_unlinked_chain(&op)?;
        return Ok(done);
    }
    if absent(&intent_path)? {
        ensure!(has_source && !has_quarantine, "fresh operation requires original file");
        let id = hash_target(&source(), true, &plan.archive_sha256)?;
        let report = json!({"operation":op,"recorded_unix_millis":now()?,"tool_sha256":self_sha,
            "historical_evidence":evidence,"terminal_actors":actors,"identity":id,
            "reference_scan":["command","maps","cwd","root","exe","file-descriptors","inode","staged-units","queued-jobs"],
            "historical_blocks_are_not_capacity_credit":true,"logs_manifests_inputs_and_cohort_state_preserved":true});
        if check { return Ok(json!({"status":"check-passed","report":report})); }
        write_once("intent.json", &report)?;
    } else {
        require_record("intent.json", &op)?;
        if has_source { hash_target(&source(), true, &plan.archive_sha256)?; }
        else if has_quarantine { hash_target(&quarantine(), false, &plan.archive_sha256)?; }
        else { require_unlinked_chain(&op)?; }
    }
    if check { return Ok(json!({"status":"interrupted-operation-check-passed","operation":op})); }
    // Fresh actor/reference proof after the (potentially lengthy) payload hash.
    records()?; terminal()?; references()?;
    if has_source { rename_exact()?; }
    if !absent(&quarantine())? {
        let id = hash_target(&quarantine(), false, &plan.archive_sha256)?;
        let custody = Path::new(STATE).join("custody.json");
        if absent(&custody)? {
            write_once("custody.json", &json!({"operation":op,"recorded_unix_millis":now()?,"identity":id,
                "complete_local_sha256_verified":true,"root_private_quarantine":true}))?;
        } else { ensure!(require_record("custody.json", &op)?["identity"] == json!(id), "custody identity changed"); }
        let unlink = Path::new(STATE).join("unlink-intent.json");
        if absent(&unlink)? {
            write_once("unlink-intent.json", &json!({"operation":op,"recorded_unix_millis":now()?,"identity":id}))?;
        } else { ensure!(require_record("unlink-intent.json", &op)?["identity"] == json!(id), "unlink identity changed"); }
        records()?; terminal()?; references()?;
        ensure!(absent(&source())?, "original namespace reappeared");
        file_identity(&quarantine(), false)?;
        // Only the fixed child of a root-private pinned directory can be unlinked.
        let name = CString::new("epoch-237.partial.quarantine")?;
        let rc = unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) };
        ensure!(rc == 0, "quarantine unlink failed: {}", std::io::Error::last_os_error());
        dir.sync_all()?;
    } else {
        ensure!(!has_source, "source disappeared before qualified quarantine");
        require_unlinked_chain(&op)?;
    }
    ensure!(absent(&source())? && absent(&quarantine())?, "target remains/reappeared");
    let result = json!({"operation":op,"status":"complete","recorded_unix_millis":now()?,
        "source_and_quarantine_absent":true,"all_other_output_and_inputs_preserved":true,
        "free_space_credit_requires_independent_fresh_observation":true});
    write_once("completion.json", &result)?;
    Ok(result)
}
fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let args: Vec<String> = std::env::args().skip(1).collect();
    ensure!((args.len() == 6 || args.len() == 7) && args[0] == "--plan" && args[2] == "--plan-sha256"
        && args[4] == "--self-sha256" && (args.len() == 6 || args[6] == "--check-only"),
        "usage: jetstreamer-horizon-retire-old237-partial --plan PATH --plan-sha256 HEX --self-sha256 HEX [--check-only]");
    ensure!(valid_sha(&args[3]) && valid_sha(&args[5]), "invalid independent hash");
    ensure!(digest(File::open("/proc/self/exe")?)? == args[5], "self hash mismatch");
    let bytes = small(Path::new(&args[1]))?;
    ensure!(digest(bytes.as_slice())? == args[3], "plan hash mismatch");
    let plan = serde_json::from_slice(&bytes)?;
    println!("{}", run(&plan, &args[3], &args[5], args.len() == 7)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan { Plan { schema:"jetstreamer-old237-partial-retirement-plan-v1".into(),
        archive_sha256:"a".repeat(64),local_failed_output_retirement_authorized:true,
        archive_publication_authorized:false,remote_mutations:false } }
    #[test]
    fn cannot_borrow_other_retirement_authority() {
        let mut p = plan(); validate_plan(&p).unwrap();
        p.schema = "jetstreamer-horizon-failed-diagnostic-retirement-plan-v1".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan(); p.remote_mutations = true; assert!(validate_plan(&p).is_err());
        let mut p = plan(); p.archive_publication_authorized = true; assert!(validate_plan(&p).is_err());
        let mut p = plan(); p.local_failed_output_retirement_authorized = false; assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn archive_digest_must_be_independent_full_lowercase_sha256() {
        for hash in ["", "unknown", &"A".repeat(64), &"a".repeat(63)] {
            let mut p = plan(); p.archive_sha256 = hash.into(); assert!(validate_plan(&p).is_err());
        }
    }
    #[test]
    fn operation_cannot_rebind_plan_digest_or_payload_digest() {
        let a = operation(&"a".repeat(64), &"b".repeat(64));
        assert_ne!(a, operation(&"c".repeat(64), &"b".repeat(64)));
        assert_ne!(a, operation(&"a".repeat(64), &"d".repeat(64)));
        assert_eq!(a["identity"]["inode"], 11311387);
        assert_eq!(a["remote_mutations"], false);
        assert_eq!(a["archive_publication_authorized"], false);
    }
    #[test]
    fn unknown_scope_and_target_fields_are_rejected() {
        assert!(serde_json::from_value::<Plan>(json!({"schema":"jetstreamer-old237-partial-retirement-plan-v1",
            "archive_sha256":"a".repeat(64),"local_failed_output_retirement_authorized":true,
            "archive_publication_authorized":false,"remote_mutations":false,"target":"/tmp/other"})).is_err());
        assert!(validate_records(&[]).is_err());
    }
    fn stopped_records() -> Vec<Value> {
        // Minimal form of the separately hash-pinned historical records. No
        // systemd, payload I/O, process observations, or runtime writes in tests.
        let mut records = vec![json!({}); RECORDS.len()];
        let journal: Vec<Value> = [("Stopping ", "de5b426a63be47a7b6ac3eaac82e2f6f"),
            ("Stopped ", "9d1aaa27d60140bd96365438aad20286")].into_iter().map(|(prefix,id)|
            json!({"_PID":"1","_UID":"0","_EXE":"/usr/lib/systemd/systemd","UNIT":UNIT,
                "INVOCATION_ID":IID,"MESSAGE_ID":id,"MESSAGE":format!("{prefix}{UNIT}")})).collect();
        records[0] = json!({"schema":"horizon-237-authenticated-stop-event-v1","epoch":237,
            "invocation_id":IID,"stopped_before_terminal_slot":true,"not_a_verified_completion":true,
            "last_observed_slot":102753469,"required_terminal_slot":102815999,"stop_journal":journal});
        records[1] = json!({"partial_jet_path":source(),"stop_reason":"root-physical-budget"});
        records[3] = json!({"qualified_in_place_resume_cursor_present":false,"archive_preserved":source()});
        records[5] = json!({"partial_archive_identity_unchanged":true,"cohort_state_unchanged":true,"scratch_root_preserved_empty":true});
        records[6] = json!({"actual_after":{"Id":TIMER,"ActiveState":"inactive"}});
        records[7] = json!({"launched":true,"manager":{"Id":SUCCESSOR,"InvocationID":SUCCESSOR_IID,
            "ExecStart":"/immutable/jetstreamer-node 237 /home/ubuntu/.jetstreamer-private/qualification-237-general-target1-budget620-v2/output"}});
        records[8] = json!({"new_unit_text":"UnsetEnvironment=HORIZON_S3_ENDPOINT JETSTREAMER_ROOT_COHORT_RESUME_RUN\nEnvironment=\"JETSTREAMER_PRIVATE_RUN_ROOT=/home/ubuntu/.jetstreamer-private/qualification-237-general-target1-budget620-v2/state\"\n"});
        records[9] = json!({"preserved_manifests":[]});
        records
    }
    #[test]
    fn deactivated_successfully_alone_does_not_prove_terminal_full_epoch() {
        let mut records = stopped_records(); validate_records(&records).unwrap();
        records[0]["stop_journal"] = json!([{"MESSAGE":"Deactivated successfully."}]);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records();
        records[0]["not_a_verified_completion"] = json!(false);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records();
        records[0]["stop_journal"][0]["INVOCATION_ID"] = json!(SUCCESSOR_IID);
        assert!(validate_records(&records).is_err());
    }
    #[test]
    fn resumable_stop_or_borrowed_successor_cannot_be_retired() {
        let mut records = stopped_records();
        records[3]["qualified_in_place_resume_cursor_present"] = json!(true);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records();
        records[7]["manager"]["ExecStart"] = json!(format!("jetstreamer-node 237 {OLD}/output"));
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records();
        records[7]["manager"]["InvocationID"] = json!(IID);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records();
        records[8]["new_unit_text"] = json!("Environment=JETSTREAMER_ROOT_COHORT_RESUME_RUN=old");
        assert!(validate_records(&records).is_err());
    }
    #[test]
    fn lost_manifest_custody_or_changed_original_evidence_blocks_retirement() {
        let mut records = stopped_records(); records[9]["preserved_manifests"] = json!(["unreviewed-segment"]);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records(); records[5]["partial_archive_identity_unchanged"] = json!(false);
        assert!(validate_records(&records).is_err());
        let mut records = stopped_records(); records[6]["actual_after"]["ActiveState"] = json!("active");
        assert!(validate_records(&records).is_err());
    }
    #[test]
    fn every_durable_crash_boundary_can_resume_without_redeleting_or_replacing() {
        for state in [
            (true,false,false,false,false,false), // original untouched
            (true,false,true,false,false,false), // intent sealed before rename
            (false,true,true,false,false,false), // rename durable, custody not yet sealed
            (false,true,true,true,false,false), // rehashed quarantine custody
            (false,true,true,true,true,false), // unlink intent sealed, file still present
            (false,false,true,true,true,false), // unlink durable, completion not yet sealed
            (false,false,true,true,true,true), // repeat completed operation
        ] {
            validate_lifecycle(state.0,state.1,state.2,state.3,state.4,state.5).unwrap();
        }
    }
    #[test]
    fn namespace_reappearance_and_missing_custody_never_authorize_unlink() {
        for state in [
            (true,true,true,true,true,false),
            (true,false,true,true,true,false),
            (false,true,false,false,false,false),
            (false,false,true,false,true,false),
            (false,false,true,true,false,false),
            (false,false,false,false,false,true),
        ] {
            assert!(validate_lifecycle(state.0,state.1,state.2,state.3,state.4,state.5).is_err());
        }
    }
}
