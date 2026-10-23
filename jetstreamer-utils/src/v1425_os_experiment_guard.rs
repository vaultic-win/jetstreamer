//! Closed OS-volume compiler guard. Standalone build; no replay selectors.
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
#[path = "horizon_standalone_guard_root.rs"]
mod root_budget;

const BUDGET: &str =
    "/usr/local/lib/jetstreamer/horizon-v1425-portability-os-budget-20261023-v2/budget.json";
const BUDGET_SHA: &str = "2e95927a3c49972630c9de458e32359a859b90de7b0fa9b195d6dbb1083ed620";
const BUILD_UNIT: &str = "horizon-v1425-portability-native-build-20261023-v1.service";
const CANARY_UNIT: &str = "horizon-v1425-os-budget-canary-20261023-v1.service";
const LEGACY_ROOT: &str =
    "/var/lib/jetstreamer-builds/readback-progress-20261022-v1/legacy-v1-4-25";
const MIN_FREE: u64 = 220_243_844_550;
const MAX_LEGACY: u64 = 11_232_206_848;
const BUILD_ALIASES: [&str; 2] = [
    "release/build/jemalloc-sys-8e59224338bed73f/out/build/lib/libjemalloc.so",
    "debug/build/jemalloc-sys-d7a0337ead603603/out/build/lib/libjemalloc.so",
];

#[derive(Clone, Copy)]
enum Profile {
    Build,
    Canary,
}
impl Profile {
    fn unit(self) -> &'static str {
        match self {
            Self::Build => BUILD_UNIT,
            Self::Canary => CANARY_UNIT,
        }
    }
    fn root(self) -> &'static str {
        match self {
            Self::Build => LEGACY_ROOT,
            Self::Canary => "/var/lib/jetstreamer-v1425-os-guard-canary-20261023-v1/tree",
        }
    }
    fn receipts(self) -> &'static str {
        match self {
            Self::Build => "/var/lib/jetstreamer-v1425-os-guard-build-20261023-v1/receipts",
            Self::Canary => "/var/lib/jetstreamer-v1425-os-guard-canary-20261023-v1/receipts",
        }
    }
    fn maximum(self) -> u64 {
        match self {
            Self::Build => MAX_LEGACY,
            Self::Canary => 16 << 10,
        }
    }
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o777 == 0o700,
        "unsafe guard receipt directory"
    );
    Ok(())
}
fn read_regular(path: &Path, immutable: bool) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && before.is_file()
            && before.nlink() == 1
            && before.len() <= 1 << 20
            && before.uid() == unsafe { libc::geteuid() }
            && (!immutable || before.mode() & 0o222 == 0),
        "unsafe guard evidence"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let opened = f.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "guard evidence replaced"
    );
    let mut b = Vec::new();
    Read::by_ref(&mut f)
        .take((1 << 20) + 1)
        .read_to_end(&mut b)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        b.len() <= 1 << 20
            && before.len() == after.len()
            && before.ino() == after.ino()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "guard evidence changed"
    );
    Ok(b)
}
fn persist(path: &Path, value: &Value) -> Result<()> {
    private(path.parent().context("receipt parent")?)?;
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    f.set_permissions(fs::Permissions::from_mode(0o400))?;
    f.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}
fn record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(Some(serde_json::from_slice(&read_regular(path, true)?)?)),
    }
}
fn parse_plan(v: &Value, canary: bool) -> Result<(Profile, String, String)> {
    let fields = v.as_object().context("guard plan object")?;
    ensure!(
        fields.len() == 5
            && fields.keys().all(|k| [
                "schema",
                "profile",
                "budget",
                "invocation_id",
                "start_monotonic"
            ]
            .contains(&k.as_str())),
        "unknown guard plan field"
    );
    let profile = match (v["profile"].as_str(), canary) {
        (Some("build"), false) => Profile::Build,
        (Some("disposable-canary"), true) => Profile::Canary,
        _ => anyhow::bail!("foreign guard profile"),
    };
    let iid = v["invocation_id"].as_str().context("target invocation")?;
    let start = v["start_monotonic"].as_str().context("target start")?;
    ensure!(
        v["schema"] == "jetstreamer-v1425-os-experiment-guard-plan-v2"
            && v["budget"] == json!({"path":BUDGET,"sha256":BUDGET_SHA})
            && digest(iid, 32)
            && start.parse::<u64>().is_ok_and(|n| n > 0),
        "invalid guard identity/budget"
    );
    Ok((profile, iid.into(), start.into()))
}
fn unit(name: &str) -> Result<Value> {
    ensure!(
        matches!(name, BUILD_UNIT | CANARY_UNIT),
        "foreign target unit"
    );
    let o = Command::new("/usr/bin/systemctl").args(["show", name, "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,KillMode,Delegate,ExecMainStartTimestampMonotonic,ExecMainCode,ExecMainStatus,Result,ControlGroup,Job"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() <= 16384,
        "target manager read failed"
    );
    let mut fields = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("target property shape")?;
        ensure!(
            fields.insert(k.into(), json!(v)).is_none(),
            "duplicate target property"
        );
    }
    Ok(Value::Object(fields))
}
fn owned(v: &Value, name: &str, iid: &str, start: &str) -> Result<()> {
    ensure!(
        v["Id"] == name
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == iid
            && v["ExecMainStartTimestampMonotonic"] == start
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["KillMode"] == "control-group"
            && v["Delegate"] == "no",
        "target identity changed; no stop authorized"
    );
    Ok(())
}
fn terminal_shape(v: &Value, name: &str, iid: &str, start: &str) -> bool {
    v["Id"] == name
        && v["LoadState"] == "loaded"
        && v["MainPID"] == "0"
        && v["ExecMainStartTimestampMonotonic"] == start
        && v["NRestarts"] == "0"
        && v["Restart"] == "no"
        && v["KillMode"] == "control-group"
        && v["Delegate"] == "no"
        && (v["InvocationID"] == iid || v["InvocationID"] == "")
        && ((v["ActiveState"] == "inactive" && v["SubState"] == "dead")
            || (v["ActiveState"] == "failed" && v["SubState"] == "failed")
            || (v["ActiveState"] == "active" && v["SubState"] == "exited"))
}
fn cleared_terminal_shape(v: &Value, name: &str) -> bool {
    v["Id"] == name
        && v["LoadState"] == "loaded"
        && v["MainPID"] == "0"
        && v["ExecMainStartTimestampMonotonic"] == "0"
        && v["InvocationID"] == ""
        && v["NRestarts"] == "0"
        && v["Restart"] == "no"
        && v["KillMode"] == "control-group"
        && v["Delegate"] == "no"
        && v["Job"] == ""
        && v["ControlGroup"] == ""
        && v["ActiveState"] == "inactive"
        && v["SubState"] == "dead"
}
fn validate_terminal_history(
    rows: &[Value],
    name: &str,
    iid: &str,
    start: &str,
    boot: &str,
) -> Result<Value> {
    ensure!(
        !rows.is_empty() && rows.len() <= 64 && digest(boot, 32),
        "terminal PID1 history absent/bounded"
    );
    let mut previous = 0u64;
    let mut last_bound = None;
    let mut last_lifecycle = None;
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["_UID"] == "0"
                && row["_COMM"] == "systemd"
                && row["_EXE"] == "/usr/lib/systemd/systemd"
                && row["_SYSTEMD_UNIT"] == "init.scope"
                && row["_TRANSPORT"] == "journal"
                && row["UNIT"] == name
                && row["_BOOT_ID"] == boot,
            "untrusted PID1 terminal history"
        );
        let at = row["__MONOTONIC_TIMESTAMP"]
            .as_str()
            .context("journal monotonic timestamp")?
            .parse::<u64>()?;
        ensure!(at >= previous, "PID1 terminal history reordered");
        previous = at;
        if row["INVOCATION_ID"].as_str().is_some_and(|s| !s.is_empty()) {
            last_bound = Some(row);
        }
        if matches!(
            row["MESSAGE_ID"].as_str(),
            Some(
                "7d4958e842da4a758f6c1cdc7b36dcc5"
                    | "39f53479d3a045ac8e11786248231fbf"
                    | "de5b426a63be47a7b6ac3eaac82e2f6f"
                    | "7ad2d189f7e94e70a38c781354912448"
                    | "9d1aaa27d60140bd96365438aad20286"
            )
        ) {
            ensure!(
                row["INVOCATION_ID"].as_str().is_some_and(|s| digest(s, 32)),
                "PID1 lifecycle lacks invocation"
            );
            last_lifecycle = Some(row);
        }
    }
    ensure!(
        last_bound.context("PID1 history lacks bound invocation")?["INVOCATION_ID"] == iid,
        "latest PID1 invocation replaced original owner"
    );
    let last = last_lifecycle.context("PID1 terminal lifecycle absent")?;
    ensure!(
        last["INVOCATION_ID"] == iid
            && matches!(
                last["MESSAGE_ID"].as_str(),
                Some("7ad2d189f7e94e70a38c781354912448" | "9d1aaa27d60140bd96365438aad20286")
            )
            && (last["MESSAGE_ID"] != "9d1aaa27d60140bd96365438aad20286"
                || last["JOB_RESULT"] == "done")
            && last["__MONOTONIC_TIMESTAMP"]
                .as_str()
                .unwrap()
                .parse::<u64>()?
                >= start.parse::<u64>()?,
        "latest PID1 lifecycle is not original invocation terminal proof"
    );
    Ok(last.clone())
}
fn observe_target(profile: Profile, iid: &str, start: &str, stop_lineage: bool) -> Result<Value> {
    let mut target = unit(profile.unit())?;
    if stop_lineage && cleared_terminal_shape(&target, profile.unit()) {
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "");
        let o = Command::new("/usr/bin/journalctl")
            .args([
                "--no-pager",
                "-o",
                "json",
                "-n",
                "64",
                "_PID=1",
                "_UID=0",
                &format!("UNIT={}", profile.unit()),
                &format!("_BOOT_ID={boot}"),
            ])
            .output()?;
        ensure!(
            o.status.success() && o.stdout.len() <= 1 << 20,
            "PID1 terminal journal unavailable/bounded"
        );
        let rows: Vec<Value> = std::str::from_utf8(&o.stdout)?
            .lines()
            .map(serde_json::from_str)
            .collect::<std::result::Result<_, _>>()?;
        let last = validate_terminal_history(&rows, profile.unit(), iid, start, &boot)?;
        target["trusted_terminal_history"] = json!({"records":rows,"latest_terminal":last,"boot_id":boot,"journal_raw_sha256":sha(&o.stdout)});
        // No intervening manager replacement may be hidden by the journal read.
        ensure!(
            cleared_terminal_shape(&unit(profile.unit())?, profile.unit()),
            "target changed during terminal journal proof"
        );
    }
    Ok(target)
}
fn terminal(v: &Value, name: &str, iid: &str, start: &str, stop_lineage: bool) -> Result<bool> {
    if !terminal_shape(v, name, iid, start) && !(stop_lineage && cleared_terminal_shape(v, name)) {
        return Ok(false);
    }
    if cleared_terminal_shape(v, name) {
        let h = &v["trusted_terminal_history"];
        let rows = h["records"]
            .as_array()
            .context("cleared owner lacks latest trusted PID1 history")?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .replace('-', "");
        ensure!(
            h["boot_id"] == boot
                && validate_terminal_history(rows, name, iid, start, &boot)?
                    == h["latest_terminal"],
            "cleared owner terminal lineage differs"
        );
    }
    let cgroup = Path::new("/sys/fs/cgroup/system.slice")
        .join(name)
        .join("cgroup.events");
    match fs::read_to_string(cgroup) {
        Ok(s) => ensure!(
            s.lines().any(|s| s == "populated 0"),
            "target cgroup remains populated"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ensure!(
            v["ControlGroup"] == "",
            "target cgroup evidence unavailable"
        ),
        Err(e) => return Err(e.into()),
    }
    Ok(true)
}
fn available(path: &Path) -> Result<u64> {
    ensure!(
        fs::metadata(path)?.dev() == 2304 && path.canonicalize()? == path,
        "wrong OS filesystem"
    );
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut v: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), &mut v) } == 0,
        "OS statvfs failed"
    );
    v.f_bavail
        .checked_mul(v.f_frsize)
        .context("OS free-space overflow")
}
fn exceeds(free: u64, minimum: u64, physical: u64, maximum: u64) -> bool {
    free < minimum || physical > maximum
}
fn alias_catalog(root: &Path, aliases: &[&str], device: u64, uid: u32) -> Result<Vec<Value>> {
    let mut catalog = Vec::new();
    for relative in aliases {
        ensure!(
            Path::new(relative)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "unsafe compiled alias"
        );
        let path = root.join(relative);
        let before = fs::symlink_metadata(&path)?;
        let parent = path.parent().context("compiled alias parent")?;
        ensure!(
            before.file_type().is_symlink()
                && before.dev() == device
                && before.uid() == uid
                && before.nlink() == 1
                && fs::read_link(&path)? == Path::new("libjemalloc.so.2")
                && parent.canonicalize()? == parent,
            "compiled internal alias differs"
        );
        let target = parent.join("libjemalloc.so.2");
        let m = fs::symlink_metadata(&target)?;
        ensure!(
            target.canonicalize()? == target
                && m.is_file()
                && m.dev() == device
                && m.uid() == uid
                && m.nlink() == 1
                && m.mode() & 0o002 == 0,
            "compiled alias does not name a canonical owned sibling"
        );
        let after = fs::symlink_metadata(&path)?;
        ensure!(
            before.ino() == after.ino()
                && before.dev() == after.dev()
                && fs::read_link(&path)? == Path::new("libjemalloc.so.2"),
            "compiled alias changed"
        );
        catalog.push(json!({"relative_path":relative,"literal_target":"libjemalloc.so.2","symlink_device":before.dev(),
            "symlink_inode":before.ino(),"uid":before.uid(),"target":target,"target_device":m.dev(),
            "target_inode":m.ino(),"target_uid":m.uid(),"target_gid":m.gid(),"target_mode":m.mode()&0o7777,
            "target_length":m.len(),"target_physical_bytes":m.blocks()*512,"target_mtime":m.mtime(),"target_mtime_nsec":m.mtime_nsec(),
            "traversal_followed_alias":false,"target_inside_censused_tree":true}));
    }
    Ok(catalog)
}
fn tree_with_aliases(
    root: &Path,
    maximum: u64,
    device: u64,
    aliases: &[&str],
    uid: u32,
) -> Result<Value> {
    ensure!(
        fs::metadata(root)?.dev() == device,
        "experiment tree on wrong device"
    );
    let before = alias_catalog(root, aliases, device, uid)?;
    let mut tree = serde_json::to_value(root_budget::observe(root, maximum)?)?;
    let after = alias_catalog(root, aliases, device, uid)?;
    ensure!(
        before == after
            && tree["first"]["symlinks"] == aliases.len()
            && tree["second"]["symlinks"] == aliases.len(),
        "experiment tree contains unapproved or changing aliases"
    );
    tree["verified_internal_aliases"] = json!(after);
    Ok(tree)
}
fn tree_sample(root: &Path, maximum: u64, device: u64) -> Result<Value> {
    tree_with_aliases(
        root,
        maximum,
        device,
        if root == Path::new(LEGACY_ROOT) {
            &BUILD_ALIASES
        } else {
            &[]
        },
        1001,
    )
}
fn sample(profile: Profile) -> Result<Value> {
    let free = available(Path::new("/var/lib"))?;
    let tree = tree_sample(Path::new(profile.root()), profile.maximum(), 2304)?;
    let physical = tree["conservative_physical_bytes"]
        .as_u64()
        .context("physical total")?;
    Ok(
        json!({"available_bytes":free,"minimum_free_bytes":MIN_FREE,"tree":tree,
        "trip":exceeds(free,MIN_FREE,physical,profile.maximum()),"device":2304}),
    )
}
fn intent_descriptor(profile: Profile, plan_sha: &str, iid: &str, start: &str) -> Value {
    json!({"schema":"jetstreamer-v1425-os-guard-stop-intent-v2","unit":profile.unit(),
        "invocation_id":iid,"start_monotonic":start,"plan_sha256":plan_sha,"budget_sha256":BUDGET_SHA,
        "tree":profile.root(),"minimum_free_bytes":MIN_FREE,"maximum_physical_bytes":profile.maximum(),
        "replay_signal_authorized":false,"r2_mutations":false})
}
fn transition(
    receipts: &Path,
    descriptor: &Value,
    reason: &Value,
    mut observe: impl FnMut() -> Result<Value>,
    mut is_terminal: impl FnMut(&Value) -> Result<bool>,
    mut check_owner: impl FnMut(&Value) -> Result<()>,
    mut stop: impl FnMut() -> Result<()>,
) -> Result<bool> {
    let intent = receipts.join("stop-intent.json");
    let submitted = receipts.join("stop-submitted.json");
    let completion = receipts.join("stop-completion.json");
    let authorized = receipts.join("stop-authorized.json");
    let old_intent = record(&intent)?;
    let old_completion = record(&completion)?;
    let old_submitted = record(&submitted)?;
    let request = json!({"descriptor":descriptor,"systemctl_stop_submitted":true});
    let old_authorized = record(&authorized)?;
    if let Some(old) = &old_authorized {
        ensure!(
            old["descriptor"] == *descriptor && old["systemctl_stop_authorized"] == true,
            "foreign stop authorization"
        );
    }
    if let Some(old) = &old_submitted {
        ensure!(*old == request, "foreign stop submission");
    }
    ensure!(
        old_intent.is_some()
            || (old_submitted.is_none() && old_authorized.is_none() && old_completion.is_none()),
        "orphan guard frontier"
    );
    if let Some(old) = &old_intent {
        ensure!(old["descriptor"] == *descriptor, "foreign stop intent");
    }
    let before = observe()?;
    if let Some(done) = old_completion {
        ensure!(
            done["descriptor"] == *descriptor && done["terminal"] == true && is_terminal(&before)?,
            "completed target reappeared or changed"
        );
        return Ok(true);
    }
    if is_terminal(&before)? {
        if old_intent.is_some() {
            persist(
                &completion,
                &json!({"schema":"jetstreamer-v1425-os-guard-stop-completion-v2",
                "descriptor":descriptor,"terminal":true,"target":before,"remote_mutations":false,"r2_mutations":false}),
            )?;
        }
        return Ok(true);
    }
    check_owner(&before)?;
    if old_intent.is_none() {
        persist(
            &intent,
            &json!({"descriptor":descriptor,"reason":reason,"target":before}),
        )?;
    }
    let fresh = observe()?;
    if is_terminal(&fresh)? {
        return Ok(false);
    }
    check_owner(&fresh)?; // No stop after any invocation/start/restart change.
    if old_authorized.is_none() {
        persist(
            &authorized,
            &json!({"descriptor":descriptor,"systemctl_stop_authorized":true,"target":fresh}),
        )?;
    }
    check_owner(&observe()?)?; // Recheck after durable authorization, before manager command.
    stop()?;
    match record(&submitted)? {
        Some(old) => ensure!(old == request, "foreign stop submission"),
        None => persist(&submitted, &request)?,
    }
    Ok(false)
}
fn has_stop_lineage(
    receipts: &Path,
    descriptor: &Value,
    profile: Profile,
    iid: &str,
    start: &str,
) -> Result<bool> {
    let Some(intent) = record(&receipts.join("stop-intent.json"))? else {
        return Ok(false);
    };
    ensure!(
        intent["descriptor"] == *descriptor,
        "foreign stop lineage intent"
    );
    owned(&intent["target"], profile.unit(), iid, start)?;
    if let Some(a) = record(&receipts.join("stop-authorized.json"))? {
        ensure!(
            a["descriptor"] == *descriptor && a["systemctl_stop_authorized"] == true,
            "foreign stop authorization lineage"
        );
        owned(&a["target"], profile.unit(), iid, start)?;
        return Ok(true);
    }
    if let Some(s) = record(&receipts.join("stop-submitted.json"))? {
        ensure!(
            s == json!({"descriptor":descriptor,"systemctl_stop_submitted":true}),
            "foreign submitted stop lineage"
        );
        return Ok(true);
    }
    Ok(false)
}
fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "guard requires root");
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() >= 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && digest(&a[3], 64)
            && digest(&a[5], 64),
        "usage: guard PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only] [--canary]"
    );
    ensure!(
        a[6..]
            .iter()
            .all(|s| matches!(s.as_str(), "--check-only" | "--canary"))
            && a.len() <= 8,
        "unknown guard option"
    );
    let check = a[6..].contains(&"--check-only".into());
    let canary = a[6..].contains(&"--canary".into());
    ensure!(
        sha(&fs::read("/proc/self/exe")?) == a[5],
        "guard executable hash mismatch"
    );
    let bytes = read_regular(Path::new(&a[1]), true)?;
    ensure!(sha(&bytes) == a[3], "guard plan hash mismatch");
    let (profile, iid, start) = parse_plan(&serde_json::from_slice(&bytes)?, canary)?;
    let budget = read_regular(Path::new(BUDGET), true)?;
    ensure!(sha(&budget) == BUDGET_SHA, "immutable OS budget mismatch");
    let b: Value = serde_json::from_slice(&budget)?;
    ensure!(
        b["device"] == 2304
            && b["legacy_target"] == LEGACY_ROOT
            && b["legacy_target_maximum_physical_bytes"] == MAX_LEGACY
            && b["minimum_retained_free_bytes"]
                .as_u64()
                .and_then(|n| n.checked_add(14 << 30))
                == Some(MIN_FREE),
        "OS guard budget scope mismatch"
    );
    let receipt_root = Path::new(profile.receipts());
    private(receipt_root)?;
    let receipt_path = receipt_root.join(&iid);
    let receipts = receipt_path.as_path();
    private(receipts)?;
    let descriptor = intent_descriptor(profile, &a[3], &iid, &start);
    let started = Instant::now();
    loop {
        ensure!(
            started.elapsed() <= Duration::from_secs(1800),
            "OS guard deadline exceeded"
        );
        let stop_lineage = has_stop_lineage(receipts, &descriptor, profile, &iid, &start)?;
        let target = observe_target(profile, &iid, &start, stop_lineage)?;
        let is_terminal = terminal(&target, profile.unit(), &iid, &start, stop_lineage)?;
        if !check && is_terminal && record(&receipts.join("stop-intent.json"))?.is_none() {
            let path = receipts.join("natural-completion.json");
            match record(&path)? {
                Some(old) => ensure!(
                    old["descriptor"] == descriptor && old["terminal"] == true,
                    "foreign natural completion"
                ),
                None => persist(
                    &path,
                    &json!({"descriptor":descriptor,"terminal":true,"target":target,"stop_submitted":false}),
                )?,
            }
            return Ok(());
        }
        if !is_terminal {
            owned(&target, profile.unit(), &iid, &start)?;
        }
        let observed = match sample(profile) {
            Ok(s) => s,
            Err(e) => json!({"trip":true,"observation_error":format!("{e:#}")}),
        };
        if check {
            let after = unit(profile.unit())?;
            owned(&after, profile.unit(), &iid, &start)?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            let path = receipts.join(format!("check-{now}.json"));
            persist(
                &path,
                &json!({"schema":"jetstreamer-v1425-os-guard-check-v2","descriptor":descriptor,
                "target":target,"target_after":after,"sample":observed,"check_only":true,"stop_submitted":false,"r2_mutations":false}),
            )?;
            println!("{}", path.display());
            return Ok(());
        }
        if observed["trip"] == true || record(&receipts.join("stop-intent.json"))?.is_some() {
            if transition(
                receipts,
                &descriptor,
                &observed,
                || observe_target(profile, &iid, &start, stop_lineage),
                |v| terminal(v, profile.unit(), &iid, &start, stop_lineage),
                |v| owned(v, profile.unit(), &iid, &start),
                || {
                    let o = Command::new("/usr/bin/systemctl")
                        .args(["stop", "--no-block", profile.unit()])
                        .output()?;
                    ensure!(o.status.success(), "exact experimental stop failed");
                    Ok(())
                },
            )? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(1));
        } else {
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore]
    fn actual_legacy_storage_capability() {
        let observed = sample(Profile::Build).unwrap();
        assert_eq!(observed["trip"], false);
        persist(Path::new("/var/lib/jetstreamer-v1425-os-guard-bootstrap-20261023-v1/actual-legacy-storage-capability.json"),
            &json!({"schema":"jetstreamer-v1425-os-guard-legacy-storage-capability-v2",
            "budget_sha256":BUDGET_SHA,"source_and_legacy_tree_readonly":true,"sample":observed,
            "unit_stop_authorized":false,"compiler_started":false,"replay_signal_authorized":false,"r2_mutations":false})).unwrap();
    }
    fn owned_fixture() -> Value {
        json!({"Id":BUILD_UNIT,"LoadState":"loaded","InvocationID":"a".repeat(32),
        "ExecMainStartTimestampMonotonic":"123","NRestarts":"0","Restart":"no","KillMode":"control-group","Delegate":"no",
        "ActiveState":"active","SubState":"running","MainPID":"1234"})
    }
    #[test]
    fn changed_reused_or_restarted_target_is_never_owned() {
        let good = owned_fixture();
        assert!(owned(&good, BUILD_UNIT, &"a".repeat(32), "123").is_ok());
        for (k, v) in [
            ("InvocationID", json!("b".repeat(32))),
            ("ExecMainStartTimestampMonotonic", json!("124")),
            ("NRestarts", json!("1")),
            ("Id", json!(CANARY_UNIT)),
        ] {
            let mut bad = good.clone();
            bad[k] = v;
            assert!(owned(&bad, BUILD_UNIT, &"a".repeat(32), "123").is_err());
        }
    }
    #[test]
    fn exact_floor_and_tree_limits_include_equality() {
        assert!(!exceeds(MIN_FREE, MIN_FREE, MAX_LEGACY, MAX_LEGACY));
        assert!(exceeds(MIN_FREE - 1, MIN_FREE, 0, MAX_LEGACY));
        assert!(exceeds(MIN_FREE, MIN_FREE, MAX_LEGACY + 1, MAX_LEGACY));
    }
    #[test]
    fn tree_aliases_missing_roots_and_foreign_devices_fail_closed() {
        let d = tempfile::tempdir().unwrap();
        let dev = fs::metadata(d.path()).unwrap().dev();
        assert!(tree_sample(d.path(), 1 << 20, dev).is_ok());
        assert!(tree_sample(d.path(), 1 << 20, dev + 1).is_err());
        assert!(tree_sample(&d.path().join("missing"), 1 << 20, dev).is_err());
        std::os::unix::fs::symlink("/", d.path().join("alias")).unwrap();
        assert!(tree_sample(d.path(), 1 << 20, dev).is_err());
    }
    #[test]
    fn only_closed_canonical_sibling_aliases_are_counted_without_following() {
        let d = tempfile::tempdir().unwrap();
        let dev = fs::metadata(d.path()).unwrap().dev();
        let uid = unsafe { libc::geteuid() };
        fs::write(d.path().join("libjemalloc.so.2"), vec![7u8; 8192]).unwrap();
        std::os::unix::fs::symlink("libjemalloc.so.2", d.path().join("libjemalloc.so")).unwrap();
        let a = tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid).unwrap();
        assert_eq!(
            a["verified_internal_aliases"][0]["traversal_followed_alias"],
            false
        );
        assert!(a["conservative_physical_bytes"].as_u64().unwrap() >= 8192);
        let outside = tempfile::tempdir().unwrap();
        fs::hard_link(
            d.path().join("libjemalloc.so.2"),
            outside.path().join("external-link"),
        )
        .unwrap();
        assert!(tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid).is_err());
        fs::remove_file(outside.path().join("external-link")).unwrap();
        assert!(tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid + 1).is_err());
        std::os::unix::fs::symlink("libjemalloc.so.2", d.path().join("unapproved")).unwrap();
        assert!(tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid).is_err());
        fs::remove_file(d.path().join("unapproved")).unwrap();
        fs::remove_file(d.path().join("libjemalloc.so")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("libjemalloc.so")).unwrap();
        assert!(tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid).is_err());
        fs::remove_file(d.path().join("libjemalloc.so")).unwrap();
        std::os::unix::fs::symlink("libjemalloc.so.2", d.path().join("libjemalloc.so")).unwrap();
        fs::remove_file(d.path().join("libjemalloc.so.2")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", d.path().join("libjemalloc.so.2")).unwrap();
        assert!(tree_with_aliases(d.path(), 1 << 20, dev, &["libjemalloc.so"], uid).is_err());
    }
    #[test]
    fn cleared_manager_identity_needs_durable_exact_stop_lineage() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let iid = "a".repeat(32);
        let desc = intent_descriptor(Profile::Build, &"c".repeat(64), &iid, "123");
        persist(
            &d.path().join("stop-intent.json"),
            &json!({"descriptor":desc,"target":owned_fixture()}),
        )
        .unwrap();
        assert!(!has_stop_lineage(d.path(), &desc, Profile::Build, &iid, "123").unwrap());
        persist(
            &d.path().join("stop-authorized.json"),
            &json!({"descriptor":desc,"target":owned_fixture(),"systemctl_stop_authorized":true}),
        )
        .unwrap();
        assert!(has_stop_lineage(d.path(), &desc, Profile::Build, &iid, "123").unwrap());
        let mut cleared = owned_fixture();
        for (k, v) in [
            ("InvocationID", ""),
            ("ExecMainStartTimestampMonotonic", "0"),
            ("MainPID", "0"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
            ("ControlGroup", ""),
            ("Job", ""),
        ] {
            cleared[k] = json!(v);
        }
        assert!(cleared_terminal_shape(&cleared, BUILD_UNIT));
        assert!(!terminal_shape(&cleared, BUILD_UNIT, &iid, "123"));
        cleared["InvocationID"] = json!("b".repeat(32));
        assert!(!cleared_terminal_shape(&cleared, BUILD_UNIT));
        assert!(!terminal_shape(&cleared, BUILD_UNIT, &iid, "123"));
    }
    #[test]
    fn latest_pid1_terminal_history_rejects_a_replaced_and_finished_owner() {
        let iid = "a".repeat(32);
        let boot = "d".repeat(32);
        let row = |id: &str, message: &str, at: &str| {
            json!({"_PID":"1","_UID":"0","_COMM":"systemd",
            "_EXE":"/usr/lib/systemd/systemd","_SYSTEMD_UNIT":"init.scope","_TRANSPORT":"journal",
            "UNIT":BUILD_UNIT,"_BOOT_ID":boot,"INVOCATION_ID":id,"MESSAGE_ID":message,
            "JOB_RESULT":"done","__MONOTONIC_TIMESTAMP":at})
        };
        let terminal = row(&iid, "9d1aaa27d60140bd96365438aad20286", "200");
        assert!(
            validate_terminal_history(&[terminal.clone()], BUILD_UNIT, &iid, "123", &boot).is_ok()
        );
        let replacement = row(&"b".repeat(32), "9d1aaa27d60140bd96365438aad20286", "300");
        assert!(validate_terminal_history(
            &[terminal.clone(), replacement],
            BUILD_UNIT,
            &iid,
            "123",
            &boot
        )
        .is_err());
        let later_start = row(&iid, "7d4958e842da4a758f6c1cdc7b36dcc5", "300");
        assert!(validate_terminal_history(
            &[terminal.clone(), later_start],
            BUILD_UNIT,
            &iid,
            "123",
            &boot
        )
        .is_err());
        let mut untrusted = terminal.clone();
        untrusted["_PID"] = json!("1234");
        assert!(validate_terminal_history(&[untrusted], BUILD_UNIT, &iid, "123", &boot).is_err());
        let mut incomplete = terminal;
        incomplete["JOB_RESULT"] = json!("failed");
        assert!(validate_terminal_history(&[incomplete], BUILD_UNIT, &iid, "123", &boot).is_err());
    }
    #[test]
    fn closed_profiles_cannot_select_arbitrary_tree_or_unit() {
        let mut p = json!({"schema":"jetstreamer-v1425-os-experiment-guard-plan-v2","profile":"build",
            "budget":{"path":BUDGET,"sha256":BUDGET_SHA},"invocation_id":"a".repeat(32),"start_monotonic":"123"});
        assert!(parse_plan(&p, false).is_ok());
        assert!(parse_plan(&p, true).is_err());
        p["unit"] = json!("other.service");
        assert!(parse_plan(&p, false).is_err());
    }
    #[test]
    fn stop_frontiers_retry_and_reused_owner_never_receives_stop() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let desc = json!({"fixture":"exact"});
        let calls = std::cell::Cell::new(0);
        let state = std::cell::Cell::new(0);
        for _ in 0..2 {
            assert!(!transition(
                d.path(),
                &desc,
                &json!({"trip":true}),
                || Ok(json!(state.get())),
                |v| Ok(v == 2),
                |v| {
                    ensure!(v == 0, "changed owner");
                    Ok(())
                },
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                }
            )
            .unwrap());
        }
        assert_eq!(calls.get(), 2);
        state.set(1);
        assert!(transition(
            d.path(),
            &desc,
            &json!({}),
            || Ok(json!(state.get())),
            |v| Ok(v == 2),
            |v| {
                ensure!(v == 0, "changed owner");
                Ok(())
            },
            || {
                calls.set(calls.get() + 1);
                Ok(())
            }
        )
        .is_err());
        assert_eq!(calls.get(), 2);
        state.set(2);
        for _ in 0..2 {
            assert!(transition(
                d.path(),
                &desc,
                &json!({}),
                || Ok(json!(2)),
                |v| Ok(v == 2),
                |_| Ok(()),
                || panic!("terminal target")
            )
            .unwrap());
        }
        state.set(0);
        assert!(transition(
            d.path(),
            &desc,
            &json!({}),
            || Ok(json!(0)),
            |v| Ok(v == 2),
            |_| Ok(()),
            || panic!("reappeared target")
        )
        .is_err());
    }
    #[test]
    fn changed_owner_between_intent_and_stop_gets_no_stop() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let seen = std::cell::Cell::new(0);
        assert!(transition(
            d.path(),
            &json!({"fixture":1}),
            &json!({}),
            || {
                let n = seen.get();
                seen.set(n + 1);
                Ok(json!(n))
            },
            |_| Ok(false),
            |v| {
                ensure!(v == 0, "owner replaced");
                Ok(())
            },
            || panic!("changed owner must not stop")
        )
        .is_err());
        assert!(record(&d.path().join("stop-intent.json"))
            .unwrap()
            .is_some());
        assert!(record(&d.path().join("stop-submitted.json"))
            .unwrap()
            .is_none());
    }
    #[test]
    fn intent_only_interruption_and_orphan_submission_recover_without_false_stop() {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let desc = json!({"fixture":"intent-only"});
        assert!(transition(
            d.path(),
            &desc,
            &json!({}),
            || Ok(json!(0)),
            |_| Ok(false),
            |_| Ok(()),
            || anyhow::bail!("fixture stop submission interrupted")
        )
        .is_err());
        assert!(record(&d.path().join("stop-intent.json"))
            .unwrap()
            .is_some());
        assert!(record(&d.path().join("stop-submitted.json"))
            .unwrap()
            .is_none());
        assert!(transition(
            d.path(),
            &desc,
            &json!({}),
            || Ok(json!(2)),
            |v| Ok(v == 2),
            |_| Ok(()),
            || panic!("terminal recovery must not stop")
        )
        .unwrap());
        let other = tempfile::tempdir().unwrap();
        fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700)).unwrap();
        persist(
            &other.path().join("stop-submitted.json"),
            &json!({"foreign":true}),
        )
        .unwrap();
        assert!(transition(
            other.path(),
            &desc,
            &json!({}),
            || Ok(json!(0)),
            |_| Ok(false),
            |_| Ok(()),
            || panic!("orphan must never stop")
        )
        .is_err());
    }
}
