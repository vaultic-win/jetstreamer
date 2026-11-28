//! Retire only the old epoch 170 CID caches selected in an independently hashed inventory.
use super::*;
use evidence::{bound, command, digest, num, props, reference, word};
use std::{
    collections::{BTreeMap, VecDeque},
    io,
    sync::OnceLock,
};
const BASE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/closed170-retry-index-retirement-20261128-v1";
const SCOPE: &str = "02858350f95f8ec875e4cbb3621447adad31a75dcd9dec399a81ad61cb532f32";
const DATA: &str = "a11d1eae36a0db51a384b9e7d629305084ccb9d0f4f93038d075819357f10202";
const LENGTH: u64 = 4_334_770_962;
const FILENAME: &str = "epoch-170-bafyreia7an3ku7nhc6mwpqygmsldmq25yli5urrrtf4j75u7k4zwx2psc4-mainnet-cid-to-offset-and-size.index";
const RETRY_ROOT: &str = "/home/sol/.jetstreamer-private/epoch170-standard-lane-20261109-v1";
const ROOTS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/home/sol/.config/systemd/user",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/etc/crontab",
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
static BINDINGS: OnceLock<Vec<(PathBuf, &'static str)>> = OnceLock::new();
fn initialize(entries: &Value, ids: &[&'static str]) -> Result<()> {
    let mut binds = Vec::new();
    for &id in ids {
        let row = &entries[id]["file"];
        let root = Path::new(word(row, "owner")?);
        let dst = Path::new(word(row, "path")?);
        ensure!(
            root.starts_with(RETRY_ROOT)
                && dst == root.join("output/compact-indexes/170").join(FILENAME),
            "different retry owner"
        );
        for p in [
            root.to_path_buf(),
            root.join("output"),
            root.join("output/compact-indexes"),
            root.join("output/compact-indexes/170"),
            dst.to_path_buf(),
        ] {
            binds.push((p, id));
        }
    }
    BINDINGS
        .set(binds)
        .map_err(|_| anyhow::anyhow!("already initialized"))
}
fn raw_terms(text: &str) -> Vec<&'static str> {
    if !text.contains(RETRY_ROOT) && !text.contains(FILENAME) {
        return Vec::new();
    }
    let mut result = BTreeSet::new();
    if text.contains(FILENAME)
        && text
            .split(|c: char| c.is_ascii_whitespace() || "\\\"'(){}[]=,;|:".contains(c))
            .any(|v| !v.starts_with('/') && v.ends_with(FILENAME))
    {
        result.insert("unbound relative CID index");
    }
    let bindings = BINDINGS.get().expect("scope initialized before census");
    for p in tokens(text).map(Path::new) {
        for (known, id) in bindings {
            if p == known {
                result.insert(id);
            }
        }
    }
    result.into_iter().collect()
}
fn json_terms(value: &Value, historical: bool, found: &mut BTreeSet<&'static str>) {
    match value {
        Value::Object(v) => {
            // These exact native argv snapshots belong to the stopped retry6 producer. The same
            // path in a placement, restore, or current launcher is a real dependency.
            let retired_argv = historical
                && value["Id"]
                    == "horizon-qualify-170-replacement-local3retry6-20261110-v1.service"
                && value["InvocationID"] == "ebd212d2045145259449d1d5c3d65353"
                && value["MainPID"] == "2295526";
            for (k, v) in v {
                found.extend(raw_terms(k));
                if k == "ExecStart" && retired_argv {
                    continue;
                }
                json_terms(
                    v,
                    historical
                        || matches!(
                            k.as_str(),
                            "historical_retry6_replay"
                                | "historical_live_owner"
                                | "historical_epoch170_join_identity"
                        ),
                    found,
                );
            }
        }
        Value::Array(v) => {
            for child in v {
                json_terms(child, historical, found);
            }
        }
        Value::String(s) => found.extend(raw_terms(s)),
        _ => (),
    }
}
fn terms(text: &str) -> Vec<&'static str> {
    let initial = raw_terms(text);
    if initial.is_empty() || !text.trim_start().starts_with(['{', '[']) {
        return initial;
    }
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        let mut found = BTreeSet::new();
        json_terms(&v, false, &mut found);
        return found.into_iter().collect();
    }
    initial
}
include!("consumer_plans.rs");
include!("index_activations.rs");
fn absent(p: &Path) -> Result<bool> {
    match fs::symlink_metadata(p) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn same_identity(p: &Path, array: &Value) -> Result<()> {
    let s = fs::symlink_metadata(p)?;
    let mtime = (s.mtime() as i128 * 1_000_000_000 + s.mtime_nsec() as i128) as i64;
    let ctime = (s.ctime() as i128 * 1_000_000_000 + s.ctime_nsec() as i128) as i64;
    ensure!(
        p.canonicalize()? == p
            && s.is_file()
            && json!([
                s.dev(),
                s.ino(),
                s.nlink(),
                s.len(),
                s.blocks(),
                mtime,
                ctime,
                s.uid(),
                s.gid(),
                s.mode()
            ]) == *array,
        "changed surveyed path {}",
        p.display()
    );
    Ok(())
}
fn survey_file(row: &Value, read_content: bool) -> Result<Value> {
    let path = Path::new(word(row, "path")?);
    let id = &row["identity"];
    ensure!(
        row["sha256"] == DATA
            && id[0] == 64512
            && id[2] == 1
            && id[3] == LENGTH
            && path.file_name().and_then(|n| n.to_str()) == Some(FILENAME),
        "wrong content scope"
    );
    same_identity(path, id)?;
    if read_content {
        file_hash(path, id[1].as_u64().context("inode")?, 1, LENGTH, DATA)
    } else {
        file_stamp(path, id[1].as_u64().context("inode")?, 1, LENGTH)
    }
}
fn original_actor(row: &Value) -> Result<Value> {
    let end = bound(&row["completion"])?;
    let intent = bound(&row["intent"])?;
    let plan = bound(&row["plan"])?;
    let unit = word(row, "unit")?;
    let iid = word(row, "invocation")?;
    let native = &row["terminal"];
    ensure!(
        end["producer_invocation_id"] == iid
            && end["intent"] == row["intent"]["path"]
            && end["plan_sha256"] == row["plan"]["sha256"]
            && intent["plan_sha256"] == row["plan"]["sha256"]
            && intent["producer_invocation_id"] == iid
            && plan["unit"] == unit
            && plan["invocation_id"] == iid,
        "original guard lineage differs"
    );
    ensure!(
        end["terminal"]["invocation_id"] == iid
            && end["terminal"]["active"] == "inactive"
            && end["terminal"]["sub"] == "dead"
            && end["terminal"]["pid"] == 0
            && native["INVOCATION_ID"] == iid
            && native["UNIT"] == unit
            && native["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448",
        "incorrect terminal legacy producer"
    );
    let args: Vec<_> = [
        "_PID=1".into(),
        "_UID=0".into(),
        format!("_BOOT_ID={}", word(native, "_BOOT_ID")?),
        format!("INVOCATION_ID={iid}"),
        format!("UNIT={unit}"),
        format!("MESSAGE_ID={}", word(native, "MESSAGE_ID")?),
    ]
    .into_iter()
    .collect();
    let mut argv = vec!["-q", "--no-pager", "-o", "json"];
    argv.extend(args.iter().map(String::as_str));
    let out = command("/usr/bin/journalctl", &argv)?;
    let events = out.lines().collect::<Vec<_>>();
    ensure!(
        events.len() == 1,
        "unresolved original native terminal {unit}"
    );
    let event: Value = serde_json::from_str(events[0])?;
    ensure!(
        native
            .as_object()
            .context("terminal row")?
            .iter()
            .all(|(k, v)| event[k] == *v),
        "original terminal journal changed"
    );
    let u = props(
        unit,
        "Id,LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID,ControlGroup,Job,TriggeredBy,Triggers,Restart,NRestarts",
    )?;
    ensure!(
        u["Id"] == unit
            && u["ActiveState"] == "inactive"
            && u["SubState"] == "dead"
            && u["MainPID"] == "0"
            && u["ControlPID"] == "0"
            && u["Restart"] == "no"
            && u["NRestarts"] == "0"
            && u["ControlGroup"].is_empty()
            && u["Job"].is_empty()
            && u["TriggeredBy"].is_empty()
            && u["Triggers"].is_empty()
            && (u["InvocationID"] == iid
                || u["LoadState"] == "not-found" && u["InvocationID"].is_empty()),
        "original producer reopened {unit}"
    );
    ensure!(
        absent(&Path::new("/sys/fs/cgroup/system.slice").join(unit))?,
        "original cgroup remains {unit}"
    );
    Ok(
        json!({"completion":row["completion"],"intent":row["intent"],"plan":row["plan"],"terminal":native,"current":u}),
    )
}
fn search(paths: &[PathBuf], patterns: &[String], source_only: bool) -> Result<Vec<PathBuf>> {
    let mut rg = Command::new("/usr/bin/rg");
    rg.args([
        "--no-config",
        "--files-with-matches",
        "--null",
        "--fixed-strings",
        "--hidden",
        "--no-ignore",
    ]);
    if source_only {
        for mask in ["*.json", "*.rs", "*.sh", "*.py", "*.toml", "*.conf"] {
            rg.args(["-g", mask]);
        }
        rg.args([
            "-g",
            "!**/guard-receipts/**",
            "-g",
            "!**/receipts/sample-*.json",
        ]);
    } else {
        rg.arg("--text");
    }
    for v in patterns {
        rg.args(["-e", v]);
    }
    for p in paths {
        rg.arg(p);
    }
    let out = rg.output()?;
    ensure!(
        matches!(out.status.code(), Some(0 | 1)),
        "staged search failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|n| Ok(Path::new(std::str::from_utf8(n)?).to_path_buf()))
        .collect()
}
fn static_closure(entries: &Value, ids: &[&'static str]) -> Result<Vec<Value>> {
    let mut wanted = BTreeMap::new();
    let mut patterns = vec![FILENAME.to_owned()];
    for id in ids {
        patterns.push(word(&entries[id]["file"], "owner")?.to_owned());
        for r in entries[id]["direct_definitions"]
            .as_array()
            .context("expected recipes")?
        {
            wanted.insert(PathBuf::from(word(r, "fragment_path")?), r);
        }
    }
    let dirs: Vec<_> = ROOTS
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    let mut observed = Vec::new();
    for path in search(&dirs, &patterns, false)? {
        let raw = fs::read(&path)?;
        if terms(std::str::from_utf8(&raw)?).is_empty() {
            continue;
        }
        let known = wanted
            .remove(&path)
            .with_context(|| format!("new original-root recipe {}", path.display()))?;
        ensure!(
            reference(&path.canonicalize()?)? == known["real"],
            "changed staged definition"
        );
        let unit = path.file_name().and_then(|v| v.to_str()).context("unit")?;
        let s = props(
            unit,
            "Id,LoadState,ActiveState,SubState,Job,MainPID,ControlPID,ControlGroup,TriggeredBy,Triggers,OnFailure,OnSuccess,Restart,NRestarts,UnitFileState,DropInPaths",
        )?;
        ensure!(
            s["Id"] == unit
                && matches!(s["ActiveState"].as_str(), "failed" | "inactive")
                && s["Job"].is_empty()
                && s["MainPID"] == "0"
                && s["ControlPID"] == "0"
                && s["ControlGroup"].is_empty()
                && s["Restart"] == "no"
                && s["NRestarts"] == "0"
                && s["UnitFileState"] == "transient"
                && [
                    "TriggeredBy",
                    "Triggers",
                    "OnSuccess",
                    "OnFailure",
                    "DropInPaths"
                ]
                .into_iter()
                .all(|k| s[k].is_empty()),
            "runnable original recipe {unit}"
        );
        observed.push(json!({"recipe":known,"native":s}));
    }
    ensure!(wanted.is_empty(), "missing pinned original recipe");
    Ok(observed)
}
fn latest_fleet() -> Result<Value> {
    let mut latest = None;
    for e in fs::read_dir(RUNTIME)? {
        let e = e?;
        if !e.file_name().as_encoded_bytes().starts_with(b"root") {
            continue;
        }
        let p = e.path().join("ROOT_COMPLETE_OPERATIONAL_FLEET.json");
        if !p.try_exists()? {
            continue;
        }
        let t = p.metadata()?.modified()?;
        if latest.as_ref().is_none_or(|(old, _)| t > *old) {
            latest = Some((t, p));
        }
    }
    let p = latest.context("no fleet")?.1;
    let raw = evidence::trusted(&p)?;
    let d: Value = serde_json::from_slice(&raw)?;
    ensure!(
        d["owner"] == "/root"
            && d["epochs"]
                .as_array()
                .is_some_and(|s| s.iter().any(|i| i["epoch"] == 170))
            && terms(std::str::from_utf8(&raw)?).is_empty(),
        "current fleet binds this retry output"
    );
    Ok(json!({"path":p,"sha256":digest(&raw)}))
}
fn route_closure(entries: &Value, ids: &[&'static str], scope: &Value) -> Result<Value> {
    let binding = &scope["retained_retry9_active_binding"];
    let prepared = bound(binding)?;
    let row = &entries["9"]["file"];
    let path = word(row, "path")?;
    let expected = prepared["inputs_already_resident"]
        .as_object()
        .context("registered sources")?
        .iter()
        .find(|(k, v)| k.ends_with(FILENAME) && v["source"] == path)
        .context("missing original retry9 route")?
        .1;
    ensure!(
        expected["identity"]
            == json!([
                64512,
                row["identity"][1],
                LENGTH,
                row["identity"][5],
                row["identity"][6]
            ]),
        "different staged retry9 inode"
    );
    let mut routes = Vec::new();
    for ent in fs::read_dir(RUNTIME)? {
        let e = ent?;
        let name = e.file_name();
        let s = name.to_str().unwrap_or("");
        if e.file_type()?.is_dir()
            && [
                "epoch170-from-",
                "epoch170-full-metered-",
                "epoch170-raised-",
                "epoch169-from-",
                "epoch169-first-",
                "epoch169-second-",
                "epoch169-adjacent-",
            ]
            .iter()
            .any(|prefix| s.starts_with(prefix))
        {
            routes.push(e.path());
        }
    }
    let prices = Path::new(RUNTIME).join("epoch162-first-hourly-completion-20261127-v2");
    let mut newest = None;
    for ent in fs::read_dir(prices)? {
        let e = ent?;
        let name = e.file_name();
        if let Some(n) = name
            .to_str()
            .and_then(|s| s.strip_prefix("issued-price-v"))
            .and_then(|s| s.parse::<u32>().ok())
        {
            let p = e.path();
            if p.join("deployment-seal-receipt.json").try_exists()?
                && newest.as_ref().is_none_or(|(i, _)| n > *i)
            {
                newest = Some((n, p));
            }
        }
    }
    let provider = newest.context("current capacity package")?.1;
    let seal = reference(&provider.join("deployment-seal-receipt.json"))?;
    routes.push(provider);
    routes.sort();
    let patterns = ids
        .iter()
        .map(|id| word(&entries[id]["file"], "owner").map(|s| format!("{s}/output")))
        .collect::<Result<Vec<_>>>()?;
    let mut inspected = 0;
    for file in search(&routes, &patterns, true)? {
        let m = fs::metadata(&file)?;
        ensure!(
            m.len() < 32 << 20,
            "oversized staged recipe {}",
            file.display()
        );
        let text = fs::read_to_string(&file)?;
        ensure!(
            terms(&text).is_empty(),
            "prepared 169/170 receiver or capacity recipe needs selected retry {}",
            file.display()
        );
        inspected += 1;
    }
    Ok(
        json!({"retained_retry9":binding,"capacity_provider":seal,"route_roots":routes,"matching_plan_files":inspected}),
    )
}

fn stable_reference(base: &Path, name: &str, value: &Value) -> Result<Value> {
    let p = base.join(name);
    if p.try_exists()? {
        let r = reference(&p)?;
        ensure!(bound(&r)? == *value, "different immutable {name}");
        Ok(r)
    } else {
        evidence::receipt(&p, value)
    }
}
fn verify_kept(entries: &Value, hash_source: bool) -> Result<Value> {
    // Retry 9 is a required source for the prepared successor. The original lane is an
    // independent fallback whose inode is recorded in the full producer's allocation witness.
    let mut kept = BTreeMap::new();
    for id in ["0", "9"] {
        let row = &entries[id]["file"];
        let stamp = survey_file(row, hash_source && id == "0")?;
        kept.insert(
            id,
            json!({"path":row["path"],"identity":stamp,"sha256":DATA}),
        );
    }
    Ok(json!(kept))
}
fn copy_restore(
    src: &Path,
    dst: &Path,
    expected: u64,
    sha: &str,
    uid: u32,
    gid: u32,
) -> Result<()> {
    use std::ffi::CString;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    let parent = dst.parent().context("restore directory")?;
    ensure!(
        parent.canonicalize()? == parent && src.canonicalize()? == src && absent(dst)?,
        "restore paths changed or already occupied"
    );
    let raw = CString::new(parent.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            raw.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "unnamed private restore file: {}",
        std::io::Error::last_os_error()
    );
    let mut dest = unsafe { File::from_raw_fd(fd) };
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(src)?
        .take(expected + 1);
    let opened = source.get_ref().metadata()?;
    ensure!(
        opened.is_file() && opened.len() == expected,
        "different restore input"
    );
    let mut buffer = vec![0; 1 << 20];
    let mut sent = 0;
    let mut h = Sha256::new();
    loop {
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sent += n as u64;
        ensure!(sent <= expected, "oversized source");
        dest.write_all(&buffer[..n])?;
        h.update(&buffer[..n]);
        if sent % (32 << 20) == 0 {
            unsafe {
                libc::posix_fadvise(
                    source.get_ref().as_raw_fd(),
                    (sent - (32 << 20)) as i64,
                    32 << 20,
                    libc::POSIX_FADV_DONTNEED,
                );
            }
        }
    }
    ensure!(
        sent == expected && format!("{:x}", h.finalize()) == sha,
        "restore source checksum"
    );
    ensure!(
        unsafe { libc::fchown(fd, uid, gid) } == 0 && unsafe { libc::fchmod(fd, 0o600) } == 0,
        "restore owner or mode"
    );
    dest.sync_all()?;
    dest.seek(SeekFrom::Start(0))?;
    let mut h = Sha256::new();
    let mut readback = 0;
    loop {
        let n = dest.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        readback += n as u64;
        h.update(&buffer[..n]);
    }
    ensure!(
        readback == expected && format!("{:x}", h.finalize()) == sha,
        "private readback failed"
    );
    let dir = File::open(parent)?;
    let name = CString::new(dst.file_name().context("restore name")?.as_bytes())?;
    // The procfd form links unnamed inodes for unprivileged operators as well.
    let procfd = CString::new(format!("/proc/self/fd/{fd}"))?;
    ensure!(
        unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                procfd.as_ptr(),
                dir.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } == 0,
        "no-clobber restore: {}",
        std::io::Error::last_os_error()
    );
    dir.sync_all()?;
    let end = fs::symlink_metadata(dst)?;
    let made = dest.metadata()?;
    ensure!(
        (
            end.dev(),
            end.ino(),
            end.len(),
            end.nlink(),
            end.uid(),
            end.gid(),
            end.mode() & 0o777
        ) == (made.dev(), made.ino(), expected, 1, uid, gid, 0o600),
        "restored file changed"
    );
    Ok(())
}
fn fixture(runtime: &Path) -> Result<Value> {
    let mut data = Vec::from(b"Old Faithful original compressed index fixture\n".as_slice());
    data.extend(0..=255);
    let sha = digest(&data);
    let src = runtime.join("FIXTURE_SOURCE.bin");
    if !src.try_exists()? {
        evidence::publish(&src, &data, 0o400)?;
    }
    ensure!(evidence::trusted(&src)? == data, "fixture source changed");
    let dst = runtime.join("FIXTURE_RESTORED.bin");
    let missing = runtime.join("FIXTURE_BAD.bin");
    ensure!(
        copy_restore(&src, &missing, data.len() as u64, &"0".repeat(64), 0, 0).is_err()
            && absent(&missing)?,
        "wrong hash published"
    );
    if !dst.try_exists()? {
        copy_restore(&src, &dst, data.len() as u64, &sha, 0, 0)?;
    }
    let identity = evidence::stamp(&dst)?;
    ensure!(
        copy_restore(&src, &dst, data.len() as u64, &sha, 0, 0).is_err()
            && evidence::trusted(&dst)? == data
            && evidence::stamp(&dst)? == identity,
        "restore clobbered existing name"
    );
    stable_reference(
        runtime,
        "RESTORE_FIXTURE.json",
        &json!({"source":reference(&src)?,"restored":reference(&dst)?,"single_inode":true,"fsync_and_full_readback":true,"no_clobber":true,"wrong_checksum_refused":true,"original_path_restore_requires_one_full_payload":LENGTH,"live_source":DATA}),
    )
}
fn scope_locks(rows: &Value, ids: &[&str]) -> Result<Vec<File>> {
    let mut result = vec![
        lock(
            Path::new("/run/horizon-epoch171-to136-g1.operation.lock"),
            26,
            3453440,
        )?,
        lock(
            &Path::new(PRIVATE).join("r2-receipts/local-mutation.lock"),
            64512,
            101135013,
        )?,
    ];
    // Original owners and the independent restoration source. The live staged retry9 source is read-only.
    for id in std::iter::once("0").chain(ids.iter().copied()) {
        let r = &rows[id]["file"];
        let p = Path::new(word(r, "epoch_lock")?);
        let identity = &r["lock_identity"];
        same_identity(p, identity)?;
        result.push(lock(p, 64512, identity[1].as_u64().context("epoch lock")?)?);
    }
    Ok(result)
}
fn plan_price(provider: &Value) -> Result<Value> {
    let seal = bound(provider)?;
    let dir = Path::new(word(&seal, "destination")?);
    for m in seal["members"].as_array().context("provider members")? {
        ensure!(
            reference(&dir.join(word(m, "name")?))?["sha256"] == m["sha256"],
            "changed capacity calculator"
        );
    }
    let code = "import sys,runpy,json;sys.path.insert(0,sys.argv[1]);f=runpy.run_path(sys.argv[1]+'/capacity.py')['whole_roster'];q=f();print(json.dumps({k:q[k] for k in ('home_margin','ram_margin','recorded_unix_seconds','package','preparation_only')}))";
    let q: Value = serde_json::from_str(&command(
        "/usr/bin/python3",
        &["-IB", "-c", code, dir.to_str().unwrap()],
    )?)?;
    ensure!(
        q["package"] == *provider
            && q["preparation_only"] == false
            && evidence::now()?.abs_diff(num(&q, "recorded_unix_seconds")?) < 90
            && num(&q, "home_margin")? >= LENGTH + (16 << 20)
            && num(&q, "ram_margin")? >= 1 << 30,
        "insufficient fresh capacity for original-path restore"
    );
    Ok(q)
}
pub(super) fn run(mode: &str) -> Result<Value> {
    let ids: &[&'static str] = match mode {
        "check-170" | "retire-170" => &["3", "4", "6"],
        "check-170-seven" | "retire-170-seven" => &["7"],
        "restore-170-3" => &["3"],
        "restore-170-4" => &["4"],
        "restore-170-6" => &["6"],
        "restore-170-7" => &["7"],
        _ => anyhow::bail!("unregistered compact-index operation"),
    };
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "run through the sealed root operator"
    );
    let base = Path::new(BASE);
    let exe = fs::read_link("/proc/self/exe")?;
    let pkg = exe.parent().context("package")?;
    ensure!(
        pkg.parent() == Some(base)
            && pkg
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|s| s.strip_prefix("tools-v"))
                .and_then(|s| s.parse::<u32>().ok())
                .is_some_and(|v| v > 0),
        "unsealed operator"
    );
    let operator = reference(&pkg.join("deployment-seal-receipt.json"))?;
    ensure!(
        evidence::member(&operator, "retire")? == exe,
        "different retirement image"
    );
    let scope_ref = reference(&base.join("SCOPE.json"))?;
    ensure!(
        scope_ref["sha256"] == SCOPE,
        "unrecognized lane index scope"
    );
    let scope = bound(&scope_ref)?;
    let survey = bound(&scope["survey"])?;
    ensure!(
        scope["length"] == LENGTH
            && scope["hash"] == DATA
            && survey["files"].as_array().is_some_and(|r| r.len() == 6),
        "wrong content survey"
    );
    let entries = &scope["entries"];
    initialize(entries, ids)?;
    let _locks = scope_locks(entries, ids)?;
    let root = base.join(if ids == ["7"] { "retry7" } else { "retry346" });
    let proof = fixture(&root)?;
    let kept = verify_kept(entries, true)?;
    let mut originals = Vec::new();
    let mut dirs = Vec::new();
    let mut inodes = Vec::new();
    for id in ids {
        let item = &entries[id];
        let row = &item["file"];
        let path = Path::new(word(row, "path")?);
        let slot = Path::new(word(row, "slot_index")?);
        same_identity(slot, &row["slot_identity"])?;
        dirs.push(path.parent().context("index directory")?.to_path_buf());
        inodes.push(row["identity"][1].as_u64().context("inode")?);
        originals.push(original_actor(&item["actor"])?);
    }
    let fleet = latest_fleet()?;
    let static_units = static_closure(entries, ids)?;
    let route = route_closure(entries, ids, &scope)?;
    let executable = active_plans(&fleet, &root)?;
    let kernel = kernel_references(&dirs, &inodes)?;
    let census = json!({"fleet":fleet,"static_units":static_units,"executable":executable,"routes":route,"kernel":kernel});
    let check = root.join("CHECKED.json");
    let flag = root.join("INTENT.json");
    let completion = root.join("COMPLETE.json");
    if mode.starts_with("check-") {
        let stamps = ids
            .iter()
            .map(|id| survey_file(&entries[id]["file"], true))
            .collect::<Result<Vec<_>>>()?;
        let r = json!({"scope":scope_ref,"operator":operator,"targets":ids,"stamps":stamps,"kept":kept,"restore_fixture":proof,"originals":originals,"census":census});
        if check.try_exists()? {
            let old = bound(&reference(&check)?)?;
            ensure!(
                old["stamps"] == r["stamps"] && old["operator"] == operator,
                "different checked inputs"
            );
            return reference(&check);
        }
        return evidence::receipt(&check, &r);
    }
    let checked_ref = reference(&check)?;
    let checked = bound(&checked_ref)?;
    ensure!(
        checked["operator"] == operator
            && checked["scope"] == scope_ref
            && checked["restore_fixture"] == proof
            && checked["kept"] == kept,
        "different qualification"
    );
    if mode.starts_with("restore-") {
        let id = ids[0];
        let row = &entries[id]["file"];
        let dst = Path::new(word(row, "path")?);
        let src = Path::new(word(&entries["0"]["file"], "path")?);
        let done = bound(&reference(&completion)?)?;
        ensure!(
            done["targets"]
                .as_array()
                .is_some_and(|r| r.contains(&json!(id)))
                && done["sha256"] == DATA,
            "missing matching retirement"
        );
        let receipt = root.join(format!("RESTORED_{id}.json"));
        if receipt.try_exists()? {
            let r = reference(&receipt)?;
            let d = bound(&r)?;
            let stat = fs::symlink_metadata(dst)?;
            ensure!(
                d["identity"] == file_hash(dst, stat.ino(), 1, LENGTH, DATA)?,
                "different restored file"
            );
            return Ok(r);
        }
        let capacity = plan_price(&route["capacity_provider"])?;
        let intent = root.join(format!("RESTORE_INTENT_{id}.json"));
        if !intent.try_exists()? {
            ensure!(absent(dst)?, "restore path occupied");
            evidence::receipt(
                &intent,
                &json!({"operator":operator,"completion":reference(&completion)?,"source":src,"target":dst,"capacity":capacity}),
            )?;
        }
        let ir = reference(&intent)?;
        let i = bound(&ir)?;
        ensure!(
            i["operator"] == operator && i["target"] == json!(dst) && i["source"] == json!(src),
            "restore intent mismatch"
        );
        if absent(dst)? {
            copy_restore(src, dst, LENGTH, DATA, 1001, 1003)?;
        }
        let m = fs::symlink_metadata(dst)?;
        let stamp = file_hash(dst, m.ino(), 1, LENGTH, DATA)?;
        return evidence::receipt(
            &receipt,
            &json!({"intent":ir,"capacity":capacity,"identity":stamp,"sha256":DATA}),
        );
    }
    ensure!(
        checked["targets"] == json!(ids) && checked["originals"] == json!(originals),
        "different closed producers"
    );
    if completion.try_exists()? {
        for id in ids {
            ensure!(
                absent(Path::new(word(&entries[id]["file"], "path")?))?,
                "retired target reappeared"
            );
        }
        return reference(&completion);
    }
    if !flag.try_exists()? {
        for (i, id) in ids.iter().enumerate() {
            ensure!(
                survey_file(&entries[id]["file"], false)? == checked["stamps"][i],
                "changed target before intent"
            );
        }
        evidence::receipt(
            &flag,
            &json!({"checked":checked_ref,"census":census,"before":free()?}),
        )?;
    }
    let ir = reference(&flag)?;
    let intent = bound(&ir)?;
    ensure!(
        intent["checked"] == checked_ref,
        "different retirement intent"
    );
    let mut removed = Vec::new();
    let mut allocation = 0;
    for (i, id) in ids.iter().enumerate() {
        let r = &entries[id]["file"];
        let p = Path::new(word(r, "path")?);
        let result = remove_checked(p, inodes[i], &root, &ir, || {
            let stamp = survey_file(r, false)?;
            ensure!(
                stamp == checked["stamps"][i] && verify_kept(entries, false)? == kept,
                "changed selected or retained index"
            );
            Ok(stamp[4].as_u64().context("allocated blocks")? * 512)
        })?;
        allocation += num(&bound(&result)?, "unlinked_allocation")?;
        removed.push(result);
    }
    let after = free()?;
    let before = num(&intent, "before")?;
    ensure!(
        verify_kept(entries, false)? == kept,
        "retained bytes changed"
    );
    for id in ids {
        let r = &entries[id]["file"];
        same_identity(Path::new(word(r, "slot_index")?), &r["slot_identity"])?;
    }
    evidence::receipt(
        &completion,
        &json!({"intent":ir,"operator":operator,"targets":ids,"removed":removed,"kept":kept,"restore_fixture":proof,"sha256":DATA,"allocated_bytes_removed":allocation,"available_before":before,"available_after":after,"conservative_credit":allocation.min(after.saturating_sub(before))}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_retired_argv_is_ignored_in_the_historical_fleet_row() {
        let root = Path::new(RETRY_ROOT).join("replacement-local3retry6-20261110-v1");
        let output = root.join("output");
        let target = output.join("compact-indexes/170").join(FILENAME);
        let entries = json!({"6":{"file":{"owner":root,"path":target}}});
        initialize(&entries, &["6"]).unwrap();
        let row = json!({"Id":"horizon-qualify-170-replacement-local3retry6-20261110-v1.service","InvocationID":"ebd212d2045145259449d1d5c3d65353","MainPID":"2295526","ExecStart":format!("node 170 {} --verify",output.display())});
        assert!(terms(&json!({"historical_live_owner":{"unit":row}}).to_string()).is_empty());
        assert_eq!(
            terms(&json!({"current":{"unit":row}}).to_string()),
            vec!["6"]
        );
        assert_eq!(
            terms(&json!({"historical_live_owner":{"unit":row,"check":target}}).to_string()),
            vec!["6"]
        );
        assert!(
            terms(
                Path::new(RETRY_ROOT)
                    .join("replacement-local3retry7-20261110-v1/output/compact-indexes/170")
                    .join(FILENAME)
                    .to_str()
                    .unwrap()
            )
            .is_empty()
        );
    }
    #[test]
    fn content_replication_is_single_copy_and_never_replaces_an_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let p = temp.path();
        let input = p.join("source");
        let target = p.join("result");
        fs::write(&input, b"fixture").unwrap();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        assert!(copy_restore(&input, &target, 7, &"0".repeat(64), uid, gid).is_err());
        assert!(!target.exists());
        copy_restore(&input, &target, 7, &digest(b"fixture"), uid, gid).unwrap();
        let ino = target.metadata().unwrap().ino();
        assert!(copy_restore(&input, &target, 7, &digest(b"fixture"), uid, gid).is_err());
        assert_eq!(ino, target.metadata().unwrap().ino());
        assert_eq!(fs::read(target).unwrap(), b"fixture");
    }
}
