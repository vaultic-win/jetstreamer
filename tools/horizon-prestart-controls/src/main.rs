//! Isolated native ExecStartPre controls. No node, worker, archive or R2 access.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const UNIT: &str = "horizon265-prestart-control-v4.service";
const OVERRIDE: &str = "horizon265-prestart-override-v4.service";
const RETENTION: &str = "horizon265-prestart-control-retention-v4.target";
const PACKAGE: &str = "/var/lib/jetstreamer/horizon265-prestart-control-package-v5";
const BINARY: &str =
    "/var/lib/jetstreamer/horizon265-prestart-control-package-v5/horizon-prestart-controls";
const STATE: &str = "/var/lib/jetstreamer/horizon265-prestart-control-state-v4";
const TOKENS: &str = "/var/lib/jetstreamer/horizon265-prestart-control-state-v4/tokens";
const MARKERS: &str = "/var/lib/jetstreamer/horizon265-prestart-control-state-v4/markers";
const PROD_TOKENS: &str = "/var/lib/jetstreamer/horizon265-replacement-20261119-tokens-v3";
const PROD_UNIT: &str = "horizon-qualify-265-replacement-20261119-v3.service";
const FIELDS: &str = "Id,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,NRestarts,Result,ExecMainCode,ExecMainStatus,ExecMainPID,ExecStartPre,ExecStart,Job,FragmentPath,DropInPaths,Restart,KillMode,Delegate,ControlGroup,Environment,EnvironmentFiles,PassEnvironment,UnsetEnvironment,MemoryMax,MemorySwapMax,TasksMax,TimeoutStartUSec,NoNewPrivileges,PrivateNetwork,ProtectSystem,ProtectHome,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,ReadOnlyPaths,Type,User,Group,RemainAfterExit";
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    production_template: Bound,
    production_retention: Bound,
    source_publication: Bound,
    sleep: Bound,
    test: Bound,
    maximum_wall_seconds: u64,
    maximum_metadata_bytes: u64,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn iid(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn bytes(b: &Bound, immutable: bool) -> Result<Vec<u8>> {
    let m = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && m.len() <= 8 << 20,
        "untrusted input"
    );
    for p in b.path.ancestors().skip(1) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "untrusted input ancestor"
        );
    }
    let raw = fs::read(&b.path)?;
    ensure!(digest(&raw) == b.sha256, "input digest differs");
    Ok(raw)
}
// Ubuntu's installed coreutils use two root-owned symlinks to a shared,
// hard-linked executable. This exception is only for the two system commands;
// immutable campaign evidence continues through the strict reader above.
fn system_binary(b: &Bound) -> Result<()> {
    let name = match b.path.to_str() {
        Some("/usr/bin/sleep") => "sleep",
        Some("/usr/bin/test") => "test",
        _ => bail!("unregistered system gate executable"),
    };
    let link = fs::symlink_metadata(&b.path)?;
    ensure!(
        link.is_symlink() && link.uid() == 0,
        "system executable link custody"
    );
    let expected = PathBuf::from(format!("../lib/cargo/bin/coreutils/{name}"));
    ensure!(
        fs::read_link(&b.path)? == expected,
        "system executable link changed"
    );
    let target = PathBuf::from(format!("/usr/lib/cargo/bin/coreutils/{name}"));
    ensure!(
        b.path.canonicalize()? == target,
        "system executable resolution changed"
    );
    for p in b.path.ancestors().skip(1).chain(target.ancestors().skip(1)) {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "system executable ancestor custody"
        );
    }
    let before = fs::symlink_metadata(&target)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.mode() & 0o022 == 0
            && before.nlink() == 116
            && before.len() <= 16 << 20,
        "system executable target custody"
    );
    let raw = fs::read(&target)?;
    let after = fs::symlink_metadata(&target)?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mode() == after.mode()
            && before.uid() == after.uid()
            && before.gid() == after.gid()
            && before.nlink() == after.nlink()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && fs::read_link(&b.path)? == expected
            && b.path.canonicalize()? == target
            && digest(&raw) == b.sha256,
        "system executable changed during read"
    );
    Ok(())
}
fn absent(p: &Path) -> Result<()> {
    match fs::symlink_metadata(p) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => bail!("path already exists: {}", p.display()),
    }
}
fn write_new(p: &Path, raw: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(p)?;
    f.write_all(raw)?;
    f.sync_all()?;
    File::open(p.parent().context("parent")?)?.sync_all()?;
    Ok(())
}
fn save(name: &str, v: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(v)?.len() <= 1 << 20,
        "metadata receipt bound"
    );
    ensure!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "evidence name"
    );
    write_new(
        &Path::new(STATE).join(name),
        &serde_json::to_vec_pretty(v)?,
        0o600,
    )
}
fn raw_command(program: &str, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new(program).args(args).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "command failed: {program} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    Ok(out.stdout)
}
fn system(args: &[&str]) -> Result<()> {
    raw_command("/usr/bin/systemctl", args)?;
    Ok(())
}
fn properties(unit: &str, fields: &str) -> Result<(BTreeMap<String, String>, Vec<u8>)> {
    let raw = raw_command(
        "/usr/bin/systemctl",
        &["show", unit, &format!("--property={fields}")],
    )?;
    Ok((parse_properties(&raw)?, raw))
}
fn parse_properties(raw: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in std::str::from_utf8(raw)?.lines() {
        let (k, v) = line.split_once('=').context("property framing")?;
        if let Some(previous) = map.get_mut(k) {
            ensure!(k == "ExecStartPre", "duplicate scalar property");
            previous.push('\n');
            previous.push_str(v);
        } else {
            map.insert(k.into(), v.into());
        }
    }
    Ok(map)
}
fn row<'a>(v: &'a BTreeMap<String, String>, k: &str) -> Result<&'a str> {
    v.get(k)
        .map(String::as_str)
        .with_context(|| format!("missing {k}"))
}
fn gate_lines(source: &str, tokens: &str) -> Result<()> {
    let lines = source
        .lines()
        .filter(|l| l.starts_with("ExecStartPre="))
        .collect::<Vec<_>>();
    ensure!(
        lines
            == vec![
                "ExecStartPre=/usr/bin/sleep 60".to_owned(),
                format!(
                    "ExecStartPre=/usr/bin/test -f {tokens}/${{INVOCATION_ID}}/guard-admission.json"
                ),
                format!(
                    "ExecStartPre=/usr/bin/test ! -L {tokens}/${{INVOCATION_ID}}/guard-admission.json"
                )
            ],
        "native gate source differs"
    );
    Ok(())
}
fn environment(v: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        row(v, "Environment")? == "CONTROL_MODE=metadata-only"
            && v.get("EnvironmentFiles").is_none_or(|s| s.is_empty())
            && row(v, "PassEnvironment")?.is_empty()
            && !row(v, "UnsetEnvironment")?
                .split_whitespace()
                .any(|s| s == "INVOCATION_ID"),
        "native environment differs"
    );
    Ok(())
}
fn template(override_env: bool) -> String {
    format!(
        "[Unit]\nDescription=Isolated epoch265 native prestart metadata control\nStartLimitIntervalSec=0\n[Service]\nType=exec\nUser=ubuntu\nGroup=ubuntu\nUMask=0077\nRestart=no\nRemainAfterExit=no\nKillMode=control-group\nDelegate=no\nMemoryMax=67108864\nMemorySwapMax=0\nTasksMax=16\nCPUQuota=100%\nTimeoutStartSec=90\nTimeoutStopSec=10\nRuntimeMaxSec=10\nProtectSystem=strict\nProtectHome=yes\nPrivateNetwork=yes\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nReadOnlyPaths={TOKENS}\nReadWritePaths={MARKERS}\nEnvironment=CONTROL_MODE=metadata-only\n{}ExecStartPre=/usr/bin/sleep 60\nExecStartPre=/usr/bin/test -f {TOKENS}/${{INVOCATION_ID}}/guard-admission.json\nExecStartPre=/usr/bin/test ! -L {TOKENS}/${{INVOCATION_ID}}/guard-admission.json\nExecStart={BINARY} marker\n",
        if override_env {
            "Environment=INVOCATION_ID=11111111111111111111111111111111\n"
        } else {
            ""
        }
    )
}
fn retention() -> String {
    format!(
        "[Unit]\nDescription=Nonactivating metadata control retention\nDefaultDependencies=no\nAfter={UNIT}\nIgnoreOnIsolate=yes\n"
    )
}
fn loaded(v: &BTreeMap<String, String>, unit: &str, source: &str) -> Result<()> {
    for (k, want) in [
        ("Id", unit),
        ("LoadState", "loaded"),
        ("ActiveState", "inactive"),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("NRestarts", "0"),
        ("DropInPaths", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
        ("MemoryMax", "67108864"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "16"),
        ("TimeoutStartUSec", "1min 30s"),
        ("NoNewPrivileges", "yes"),
        ("PrivateNetwork", "yes"),
        ("ProtectSystem", "strict"),
        ("ProtectHome", "yes"),
        ("CapabilityBoundingSet", ""),
        ("AmbientCapabilities", ""),
        ("ReadWritePaths", MARKERS),
        ("ReadOnlyPaths", TOKENS),
        ("Type", "exec"),
        ("User", "ubuntu"),
        ("Group", "ubuntu"),
        ("RemainAfterExit", "no"),
    ] {
        ensure!(row(v, k)? == want, "loaded {k} differs");
    }
    ensure!(
        fs::canonicalize(row(v, "FragmentPath")?)? == Path::new(PACKAGE).join(unit),
        "loaded fragment differs"
    );
    ensure!(
        source == template(unit == OVERRIDE),
        "sealed control template differs"
    );
    gate_lines(source, TOKENS)?;
    let pre = row(v, "ExecStartPre")?;
    let mut commands = Vec::new();
    for part in pre.split("{ path=").skip(1) {
        let (path, tail) = part.split_once(" ; argv[]=").context("prestart path")?;
        let (argv, tail) = tail
            .split_once(" ; ignore_errors=")
            .context("prestart argv")?;
        ensure!(tail.starts_with("no ;"), "ignored prestart failure");
        commands.push((path.to_owned(), argv.to_owned()));
    }
    ensure!(
        commands
            == vec![
                ("/usr/bin/sleep".into(), "/usr/bin/sleep 60".into()),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test -f {TOKENS}/${{INVOCATION_ID}}/guard-admission.json")
                ),
                (
                    "/usr/bin/test".into(),
                    format!("/usr/bin/test ! -L {TOKENS}/${{INVOCATION_ID}}/guard-admission.json")
                )
            ],
        "actual prestart sequence differs"
    );
    ensure!(
        row(v, "ExecStart")?.starts_with(&format!(
            "{{ path={BINARY} ; argv[]={BINARY} marker ; ignore_errors=no ;"
        )),
        "control marker command differs"
    );
    Ok(())
}
fn drained(unit: &str) -> Result<()> {
    let group = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    match fs::symlink_metadata(&group) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(m) => ensure!(
            m.is_dir() && group.canonicalize()? == group,
            "foreign cgroup"
        ),
    }
    for item in fs::read_dir(&group)? {
        ensure!(!item?.file_type()?.is_dir(), "nested control cgroup");
    }
    for file in ["cgroup.procs", "cgroup.threads"] {
        ensure!(
            fs::read_to_string(group.join(file))?.trim().is_empty(),
            "control still populated"
        );
    }
    Ok(())
}
fn marker() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 1000 && env::current_exe()? == Path::new(BINARY),
        "marker identity"
    );
    ensure!(env::var("CONTROL_MODE")? == "metadata-only", "marker mode");
    let id = env::var("INVOCATION_ID")?;
    ensure!(iid(&id), "marker IID");
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{UNIT}"),
        "marker native unit"
    );
    let value = json!({"schema":"horizon265-native-prestart-useful-marker-v1","invocation_id":id,"pid":std::process::id(),"boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),"recorded_unix_seconds":now()?,"metadata_only":true,"replay_launch_authorized":false});
    write_new(
        &Path::new(MARKERS).join(format!("{id}.json")),
        &serde_json::to_vec(&value)?,
        0o600,
    )?;
    println!("horizon265-native-prestart-useful-marker invocation={id}");
    Ok(())
}
fn wait_for<T>(deadline: Instant, mut observe: impl FnMut() -> Result<Option<T>>) -> Result<T> {
    loop {
        ensure!(
            Instant::now() < deadline,
            "bounded control deadline expired"
        );
        if let Some(v) = observe()? {
            return Ok(v);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn token(id: &str) -> PathBuf {
    Path::new(TOKENS).join(id).join("guard-admission.json")
}
fn case(kind: &str, old: Option<&str>, global: Instant) -> Result<String> {
    system(&["reset-failed", UNIT])?;
    let (before, _) = properties(UNIT, FIELDS)?;
    environment(&before)?;
    loaded(&before, UNIT, &template(false))?;
    system(&["start", "--no-block", UNIT])?;
    let start_deadline = (Instant::now() + Duration::from_secs(5)).min(global);
    let pre = wait_for(start_deadline, || {
        let (v, _) = properties(UNIT, FIELDS)?;
        if row(&v, "ActiveState")? == "activating" && row(&v, "SubState")? == "start-pre" {
            Ok(Some(v))
        } else {
            ensure!(
                matches!(row(&v, "ActiveState")?, "inactive" | "activating"),
                "control failed before waiting gate"
            );
            Ok(None)
        }
    })?;
    let id = row(&pre, "InvocationID")?.to_owned();
    ensure!(iid(&id) && old != Some(id.as_str()), "reused control IID");
    ensure!(
        row(&pre, "MainPID")? == "0" && row(&pre, "ControlPID")?.parse::<u32>()? > 1,
        "useful work before native gate"
    );
    absent(&Path::new(MARKERS).join(format!("{id}.json")))?;
    absent(&token(&id))?;
    save(
        &format!("{kind}-waiting.json"),
        &json!({"producer":pre,"token_absent":true,"marker_absent":true,"recorded_unix_seconds":now()?}),
    )?;
    if kind == "matching" || kind == "symlink" {
        fs::create_dir(Path::new(TOKENS).join(&id))?;
        fs::set_permissions(
            Path::new(TOKENS).join(&id),
            fs::Permissions::from_mode(0o755),
        )?;
        if kind == "matching" {
            write_new(
                &token(&id),
                &serde_json::to_vec(
                    &json!({"schema":"horizon265-isolated-control-token-v1","invocation_id":id,"metadata_only":true,"production_authority":false}),
                )?,
                0o444,
            )?;
        } else {
            let previous = old.context("symlink needs old token")?;
            ensure!(token(previous).is_file(), "old regular token lost");
            symlink(token(previous), token(&id))?;
            File::open(token(&id).parent().unwrap())?.sync_all()?;
        }
    } else if kind == "stale" {
        ensure!(
            token(old.context("stale old IID")?).is_file(),
            "stale control missing old token"
        );
    }
    let terminal = wait_for(
        (Instant::now() + Duration::from_secs(95)).min(global),
        || {
            let (v, _) = properties(UNIT, FIELDS)?;
            ensure!(row(&v, "InvocationID")? == id, "control IID replaced");
            if matches!(row(&v, "ActiveState")?, "inactive" | "failed")
                && row(&v, "ControlPID")? == "0"
                && row(&v, "MainPID")? == "0"
            {
                Ok(Some(v))
            } else {
                Ok(None)
            }
        },
    )?;
    ensure!(
        row(&terminal, "NRestarts")? == "0" && row(&terminal, "Job")?.is_empty(),
        "control restarted/job remains"
    );
    drained(UNIT)?;
    let marker_path = Path::new(MARKERS).join(format!("{id}.json"));
    if kind == "matching" {
        ensure!(
            row(&terminal, "Result")? == "success"
                && row(&terminal, "ExecMainCode")? == "1"
                && row(&terminal, "ExecMainStatus")? == "0",
            "matching token failed"
        );
        let m = fs::symlink_metadata(&marker_path)?;
        ensure!(
            m.is_file()
                && m.uid() == 1000
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && m.len() <= 4096,
            "marker custody"
        );
        let marker: Value = serde_json::from_slice(&fs::read(&marker_path)?)?;
        ensure!(
            marker["invocation_id"] == id
                && marker["pid"].as_u64().is_some_and(
                    |n| n > 1 && n.to_string() == row(&terminal, "ExecMainPID").unwrap_or("")
                ),
            "marker owner differs"
        );
    } else {
        ensure!(
            row(&terminal, "Result")? == "exit-code"
                && row(&terminal, "ExecMainPID")? == row(&pre, "ExecMainPID")?,
            "negative control reached marker executable or wrong failure"
        );
        absent(&marker_path)?;
        let expected = if kind == "symlink" {
            "/usr/bin/test ! -L"
        } else {
            "/usr/bin/test -f"
        };
        ensure!(
            row(&terminal, "ExecStartPre")?
                .split("{ path=")
                .any(|r| r.contains(&format!(
                    "argv[]={expected} {TOKENS}/${{INVOCATION_ID}}/guard-admission.json"
                )) && r.contains("code=exited")
                    && r.contains("status=1")),
            "negative did not fail exact native test"
        );
    }
    let journal = raw_command(
        "/usr/bin/journalctl",
        &[
            "--all",
            "--no-pager",
            "--output=json",
            "--boot=0",
            "_PID=1",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={id}"),
        ],
    )?;
    ensure!(
        !journal.is_empty() && journal.len() <= 1 << 20,
        "missing or oversized PID1 journal"
    );
    write_new(
        &Path::new(STATE).join(format!("{kind}-PID1.jsonl")),
        &journal,
        0o600,
    )?;
    save(
        &format!("{kind}-terminal.json"),
        &json!({"producer":terminal,"case":kind,"invocation_id":id,"actual_pid1_journal_sha256":digest(&journal),"marker_present":kind=="matching","kernel_drained":true,"metadata_only":true,"production_authority":false}),
    )?;
    Ok(id)
}
fn publication(b: &Bound) -> Result<()> {
    let v: Value = serde_json::from_slice(&bytes(b, true)?)?;
    ensure!(
        v["schema"] == "horizon265-native-prestart-source-publication-v1"
            && v["Main_accepted"] == true
            && v["remote_ref"] == "refs/heads/account-updates"
            && v["source_manifest_reviewed"] == true,
        "unqualified source publication"
    );
    let commit = v["source_commit"].as_str().context("source commit")?;
    let head = v["remote_head"].as_str().context("remote head")?;
    ensure!(
        [commit, head]
            .iter()
            .all(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
            && v["helper_sha256"] == digest(&fs::read("/proc/self/exe")?),
        "source artifact differs"
    );
    let base = [
        "-c",
        "safe.directory=/home/ubuntu/workspace/jetstreamer",
        "-C",
        "/home/ubuntu/workspace/jetstreamer",
    ];
    let mut args = base.to_vec();
    args.extend(["rev-parse", "refs/remotes/origin/account-updates"]);
    ensure!(
        std::str::from_utf8(&raw_command("/usr/bin/git", &args)?)?.trim() == head,
        "remote ref differs"
    );
    args = base.to_vec();
    args.extend(["merge-base", "--is-ancestor", commit, head]);
    raw_command("/usr/bin/git", &args)?;
    let fetched = v["fetched_unix_seconds"].as_u64().context("fetch clock")?;
    ensure!(
        fetched <= now()? && now()? - fetched <= 1800,
        "stale source fetch"
    );
    let sources = v["source_files"]
        .as_array()
        .context("published source manifest")?;
    ensure!(
        !sources.is_empty() && sources.len() <= 64,
        "source manifest bounds"
    );
    let mut seen = std::collections::BTreeSet::new();
    for source in sources {
        let path = source["repository_path"].as_str().context("source path")?;
        ensure!(
            !path.starts_with('/')
                && path
                    .split('/')
                    .all(|c| !c.is_empty() && c != ".." && c != ".")
                && seen.insert(path),
            "unsafe/duplicate source path"
        );
        args = base.to_vec();
        let object = format!("{commit}:{path}");
        args.extend(["show", &object]);
        ensure!(
            digest(&raw_command("/usr/bin/git", &args)?) == source["sha256"],
            "published source digest differs"
        );
    }
    for path in [
        "tools/horizon-prestart-controls/src/main.rs",
        "tools/horizon-prestart-controls/Cargo.toml",
        "tools/horizon-prestart-controls/Cargo.lock",
    ] {
        ensure!(seen.contains(path), "required source omitted");
    }
    let provenance: Bound = serde_json::from_value(v["build_provenance"].clone())?;
    let proof: Value = serde_json::from_slice(&bytes(&provenance, true)?)?;
    ensure!(
        proof["schema"] == "horizon265-native-prestart-build-provenance-v1"
            && proof["artifact_sha256"] == v["helper_sha256"]
            && proof["source_commit"] == commit
            && proof["source_files"] == v["source_files"]
            && proof["unresolved_dependencies"] == json!([])
            && proof["actual_build_command_verified"] == true,
        "source/build provenance missing"
    );
    Ok(())
}
fn run(plan: Bound, self_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && env::current_exe()? == Path::new(BINARY)
            && digest(&fs::read("/proc/self/exe")?) == self_sha,
        "controller identity"
    );
    let p: Plan = serde_json::from_slice(&bytes(&plan, true)?)?;
    ensure!(
        p.schema == "horizon265-native-prestart-controls-v1"
            && p.maximum_wall_seconds == 360
            && p.maximum_metadata_bytes == 16 << 20,
        "control bounds"
    );
    ensure!(
        p.sleep.path == Path::new("/usr/bin/sleep") && p.test.path == Path::new("/usr/bin/test"),
        "native gate executables"
    );
    system_binary(&p.sleep)?;
    system_binary(&p.test)?;
    publication(&p.source_publication)?;
    let production = String::from_utf8(bytes(&p.production_template, true)?)?;
    gate_lines(&production, PROD_TOKENS)?;
    ensure!(
        production
            .lines()
            .filter_map(|l| l.strip_prefix("Environment="))
            .all(|l| !l.trim_matches('"').starts_with("INVOCATION_ID="))
            && !production
                .lines()
                .any(|l| l.starts_with("EnvironmentFile=") || l.starts_with("PassEnvironment=")),
        "production native environment override"
    );
    let retained = String::from_utf8(bytes(&p.production_retention, true)?)?;
    ensure!(
        retained.lines().any(|l| l == format!("After={PROD_UNIT}"))
            && retained.lines().any(|l| l == "DefaultDependencies=no")
            && retained.lines().any(|l| l == "IgnoreOnIsolate=yes")
            && !retained
                .lines()
                .any(|l| ["Wants=", "Requires=", "BindsTo=", "Upholds="]
                    .iter()
                    .any(|p| l.starts_with(p))),
        "production retention activates work"
    );
    for unit in [UNIT, OVERRIDE, RETENTION] {
        ensure!(
            properties(unit, "LoadState")?
                .0
                .get("LoadState")
                .is_some_and(|s| s == "not-found"),
            "control unit exists"
        );
        absent(&Path::new("/run/systemd/system").join(unit))?;
    }
    absent(Path::new(STATE))?;
    fs::create_dir(STATE)?;
    fs::set_permissions(STATE, fs::Permissions::from_mode(0o755))?;
    for dir in [TOKENS, MARKERS] {
        fs::create_dir(dir)?;
        fs::set_permissions(
            dir,
            fs::Permissions::from_mode(if dir == TOKENS { 0o755 } else { 0o700 }),
        )?;
    }
    ensure!(
        unsafe { libc::chown(std::ffi::CString::new(MARKERS)?.as_ptr(), 1000, 1000) } == 0,
        "marker ownership"
    );
    let deadline = Instant::now() + Duration::from_secs(p.maximum_wall_seconds);
    for (unit, expected) in [
        (UNIT, template(false)),
        (OVERRIDE, template(true)),
        (RETENTION, retention()),
    ] {
        let file = Path::new(PACKAGE).join(unit);
        let m = fs::symlink_metadata(&file)?;
        ensure!(
            m.uid() == 0
                && m.nlink() == 1
                && m.is_file()
                && m.mode() & 0o222 == 0
                && file.canonicalize()? == file
                && fs::read_to_string(&file)? == expected,
            "sealed control template differs"
        );
        symlink(file, Path::new("/run/systemd/system").join(unit))?;
    }
    system(&["daemon-reload"])?;
    let (before, _) = properties(UNIT, FIELDS)?;
    loaded(&before, UNIT, &template(false))?;
    environment(&before)?;
    ensure!(
        row(&before, "InvocationID")?.is_empty(),
        "producer previously invoked"
    );
    system(&["start", RETENTION])?;
    let (after, _) = properties(UNIT, FIELDS)?;
    ensure!(after == before, "retention activated or changed producer");
    let (r, _) = properties(
        RETENTION,
        "LoadState,ActiveState,SubState,After,Wants,Requires,BindsTo,Upholds,DefaultDependencies,IgnoreOnIsolate,DropInPaths,Job",
    )?;
    for (k, want) in [
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "active"),
        ("After", UNIT),
        ("Wants", ""),
        ("Requires", ""),
        ("BindsTo", ""),
        ("Upholds", ""),
        ("DefaultDependencies", "no"),
        ("IgnoreOnIsolate", "yes"),
        ("DropInPaths", ""),
        ("Job", ""),
    ] {
        ensure!(row(&r, k)? == want, "retention {k} differs");
    }
    save(
        "retention.json",
        &json!({"before":before,"after":after,"retention":r,"producer_activated":false}),
    )?;
    let (override_values, raw) = properties(OVERRIDE, FIELDS)?;
    loaded(&override_values, OVERRIDE, &template(true))?;
    let rejection = environment(&override_values)
        .err()
        .context("adversarial INVOCATION_ID was not rejected")?;
    ensure!(
        row(&override_values, "InvocationID")?.is_empty(),
        "override control was invoked"
    );
    save(
        "environment-rejection.json",
        &json!({"loaded":override_values,"native_raw_sha256":digest(&raw),"error":rejection.to_string(),"unit_never_started":true}),
    )?;
    let missing = case("missing", None, deadline)?;
    let matching = case("matching", Some(&missing), deadline)?;
    let stale = case("stale", Some(&matching), deadline)?;
    let link = case("symlink", Some(&matching), deadline)?;
    ensure!(
        missing != matching && stale != matching && link != matching && link != stale,
        "control invocation collision"
    );
    ensure!(
        fs::read_dir(MARKERS)?.count() == 1,
        "unexpected useful marker"
    );
    drained(UNIT)?;
    drained(OVERRIDE)?;
    system_binary(&p.sleep)?;
    system_binary(&p.test)?;
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == self_sha,
        "controller changed during controls"
    );
    // Keep all units, tokens and native evidence; cleanup is a separate reviewed
    // lifecycle. A failed control is never automatically relaunched or erased.
    save(
        "qualification.json",
        &json!({"schema":"horizon265-native-prestart-control-qualification-v1","plan":{"path":plan.path,"sha256":plan.sha256},"helper_sha256":self_sha,"recorded_unix_seconds":now()?,"missing_token_blocks_marker":true,"exact_actual_invocation_token_allows_marker":true,"next_invocation_rejects_old_token":true,"symlink_token_rejected":true,"environment_override_rejected_before_activation":true,"terminal_retention_cannot_activate_producer":true,"actual_candidate_startup_qualified":false,"actual_first_guard_required_before_useful_work":true,"native265_initialization_repeated":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false,"archive_mutations":false,"metadata_only":true}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("marker") if args.len() == 2 => marker(),
        Some("emit-source") if args.len() == 3 => {
            let dir = Path::new(&args[2]);
            fs::create_dir(dir)?;
            for (name, raw) in [
                (UNIT, template(false)),
                (OVERRIDE, template(true)),
                (RETENTION, retention()),
            ] {
                write_new(&dir.join(name), raw.as_bytes(), 0o644)?;
            }
            Ok(())
        }
        Some("run") if args.len() == 5 => run(
            Bound {
                path: args[2].clone().into(),
                sha256: args[3].clone(),
            },
            &args[4],
        ),
        _ => bail!(
            "usage: horizon-prestart-controls emit-source NEW_DIRECTORY | run PLAN PLAN_SHA SELF_SHA | marker"
        ),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_prestart_array_preserves_order_and_rejects_duplicate_scalars() {
        let p = parse_properties(b"ExecStartPre={ path=/usr/bin/sleep ; argv[]=/usr/bin/sleep 60 }\nExecStartPre={ path=/usr/bin/test ; argv[]=/usr/bin/test -f TOKEN }\nExecStartPre={ path=/usr/bin/test ; argv[]=/usr/bin/test ! -L TOKEN }\n").unwrap();
        let commands = p["ExecStartPre"].lines().collect::<Vec<_>>();
        assert_eq!(commands.len(), 3);
        assert!(commands[0].contains("sleep 60"));
        assert!(commands[1].contains("test -f"));
        assert!(commands[2].contains("test ! -L"));
        assert!(parse_properties(b"MainPID=0\nMainPID=1\n").is_err());
    }
    #[test]
    fn system_link_exception_cannot_read_campaign_evidence() {
        assert!(
            system_binary(&Bound {
                path: "/var/lib/jetstreamer/proof.json".into(),
                sha256: "0".repeat(64)
            })
            .is_err()
        );
    }
    #[test]
    fn exact_native_gate_preserves_three_ordered_fail_closed_commands() {
        let t = template(false);
        gate_lines(&t, TOKENS).unwrap();
        assert!(gate_lines(&t.replace("sleep 60", "sleep 1"), TOKENS).is_err());
        assert!(gate_lines(&t.replace("test ! -L", "test -f"), TOKENS).is_err());
        assert!(gate_lines(&t, PROD_TOKENS).is_err());
    }
    #[test]
    fn environment_cannot_select_or_remove_invocation() {
        let v = BTreeMap::from([
            ("Environment".into(), "CONTROL_MODE=metadata-only".into()),
            ("PassEnvironment".into(), "".into()),
            ("UnsetEnvironment".into(), "".into()),
        ]);
        environment(&v).unwrap();
        for (k, value) in [
            (
                "Environment",
                "CONTROL_MODE=metadata-only INVOCATION_ID=11111111111111111111111111111111",
            ),
            ("PassEnvironment", "INVOCATION_ID"),
            ("UnsetEnvironment", "INVOCATION_ID"),
            ("EnvironmentFiles", "/override"),
        ] {
            let mut bad = v.clone();
            bad.insert(k.into(), value.into());
            assert!(environment(&bad).is_err(), "{k}");
        }
    }
    #[test]
    fn templates_never_reference_production_working_set_or_node() {
        for t in [template(false), template(true), retention()] {
            assert!(!t.contains(PROD_TOKENS));
            assert!(!t.contains("jetstreamer-node"));
            assert!(!t.contains("snapshot-"));
            assert!(!t.contains("Wants="));
            assert!(!t.contains("Requires="));
        }
    }
    #[test]
    fn control_evidence_is_noclobber_and_does_not_follow_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt");
        write_new(&path, b"original", 0o600).unwrap();
        assert!(write_new(&path, b"replacement", 0o600).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"original");
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(write_new(&link, b"replacement", 0o600).is_err());
    }
}

#[cfg(test)]
mod no_reload_native;
