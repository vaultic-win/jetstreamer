use super::*;
use std::{
    ffi::CString,
    time::{SystemTime, UNIX_EPOCH},
};

const MAIN: &str = "01a1f8f4-293b-7a91-a36e-2e7658bba721";
const IMAGE: &str = "epoch251-duplicate-index-retire";
const READERS: &str = "readers.py";
const DIAG: &str = "/home/ubuntu/.codex/diagnostics";

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn field(v: &Value, k: &str) -> Result<Bound> {
    Ok(serde_json::from_value(v[k].clone())?)
}
fn paths() -> Result<Vec<Profile>> {
    Ok(serde_json::from_str(include_str!("profiles.json"))?)
}
fn get_profile(name: &str) -> Result<Profile> {
    paths()?
        .into_iter()
        .find(|p| p.selection == name)
        .context("unregistered epoch 251 target")
}
fn doc(b: &Bound) -> Result<Value> {
    let meta = fs::symlink_metadata(&b.path)?;
    ensure!(
        b.path.canonicalize()? == b.path
            && meta.is_file()
            && [0, 1000].contains(&meta.uid())
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && meta.len() <= LIMIT,
        "unsafe evidence {}",
        b.path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&b.path)?;
    ensure!(stamp(&f.metadata()?) == stamp(&meta), "receipt open race");
    let mut data = Vec::new();
    (&f).take(LIMIT + 1).read_to_end(&mut data)?;
    ensure!(
        sha(&data) == b.sha256
            && data.len() as u64 == meta.len()
            && stamp(&f.metadata()?) == stamp(&meta)
            && stamp(&fs::symlink_metadata(&b.path)?) == stamp(&meta),
        "changed receipt {}",
        b.path.display()
    );
    Ok(serde_json::from_slice(&data)?)
}
fn root_dir(p: &Path) -> Result<()> {
    ensure!(p.canonicalize()? == p, "aliased root-owned directory");
    for parent in p.ancestors() {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
            "unsafe ancestor {}",
            parent.display()
        );
    }
    Ok(())
}
fn exact_bound(v: &Bound) -> Result<Value> {
    root_dir(v.path.parent().context("file parent")?)?;
    let data = file_bytes(&v.path, &v.sha256, 0, None, true)?;
    Ok(serde_json::from_slice(&data)?)
}
fn original(p: &Profile) -> Result<()> {
    let retirement_source = p
        .target
        .parent()
        .context("original acquisition directory")?;
    ensure!(
        p.selection == "cid"
            && p.unit == "horizon251-index-transfer-20261118-v1.service"
            && p.iid == "8fd0271eb06b4307aba4e116c12f00d8"
            && retirement_source == p.root
            && p.target.file_name().and_then(|n| n.to_str()) == Some("cid251.partial")
            && p.target_identity.dev == DEV
            && p.retained.stamp.dev == DEV
            && p.target_identity.ino == 31109756
            && p.retained.stamp.ino == 30861107
            && p.target_identity.nlink == 1
            && p.retained.stamp.nlink == 1
            && p.target_identity.len == 10_554_622_710
            && p.retained.stamp.len == p.target_identity.len
            && p.sha256 == "1f946a290b09cf28610958876d91090c212740e9b0dd86a3e5ae5519e89a2d5c"
            && p.custody.len() == 6,
        "different epoch 251 acquisition or retained body"
    );
    let records: Vec<_> = p.custody.iter().map(doc).collect::<Result<_>>()?;
    validate_records(p, &records)?;
    file_bytes(&p.sums.path, &p.sums.sha256, 0, None, true)?;
    file_bytes(&p.response.path, &p.response.sha256, 1000, None, false)?;
    for other in &p.protected {
        exact(&other.path, &other.stamp)?;
    }
    Ok(())
}
fn validate_records(p: &Profile, records: &[Value]) -> Result<()> {
    let package = p.retained.path.parent().context("sealed package")?;
    let retained_name = p
        .retained
        .path
        .file_name()
        .and_then(|n| n.to_str())
        .context("member name")?;
    let [plan, seal, structure, production, handoff, drain] = records else {
        bail!("incomplete original 251 custody");
    };
    let member = |v: &Value| -> Result<Value> {
        let matched: Vec<_> = v["members"]
            .as_array()
            .context("members")?
            .iter()
            .filter(|m| {
                m["source"] == json!(p.target)
                    && m["name"] == retained_name
                    && m["sha256"] == p.sha256
            })
            .collect();
        ensure!(matched.len() == 1, "source-to-member binding");
        Ok(matched[0].clone())
    };
    ensure!(
        plan["schema"] == "jetstreamer-sealed-deployment-plan-v1"
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && plan["destination"] == json!(package)
            && member(plan)?["mode"] == 0o444
            && seal["plan_sha256"] == p.custody[0].sha256
            && seal["destination"] == json!(package)
            && member(seal)?["bytes"] == p.target_identity.len
            && member(seal)?["mode"] == "0444"
            && structure["cache_seal"] == json!(p.custody[1])
            && structure["structure_accepted"] == true
            && structure["indexes"]
                .as_array()
                .context("structure indexes")?
                .iter()
                .any(|row| row["binding"]["ino"] == p.retained.stamp.ino
                    && row["binding"]["dev"] == DEV
                    && row["binding"]["path"] == json!(p.retained.path)
                    && row["binding"]["sha256"] == p.sha256
                    && row["structure"]["epoch"] == 251
                    && row["structure"]["kind"] == "cid-to-offset-and-size")
            && production["index_cache"] == json!(package)
            && production["index_structure"] == json!(p.custody[2])
            && handoff["epoch"] == 251
            && handoff["producer"]["unit"]["InvocationID"] == "cd2477bfec7f4e498545762c633e7bb0"
            && handoff["source"]["archive"]["identity"]["inode"] == 31112947
            && p.protected
                .iter()
                .any(|a| json!(a.path) == handoff["source"]["archive"]["path"]
                    && a.stamp.ino == 31112947)
            && drain["terminal_handoff"] == json!(p.custody[4])
            && drain["producer_cgroup_drained"] == true,
        "invalid original seal, retained consumer or terminal custody"
    );
    Ok(())
}
fn free(p: &Path) -> Result<u64> {
    let c = CString::new(p.as_os_str().as_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c.as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs"
    );
    let v = unsafe { v.assume_init() };
    v.f_bavail.checked_mul(v.f_frsize).context("free overflow")
}
fn gate(b: &Value, p: &Profile) -> Result<()> {
    ensure!(
        now()? <= number(b, "expires_unix_seconds")?
            && free(&p.retained.path)? >= number(b, "minimum_free_bytes")?,
        "expired or shared floor crossed"
    );
    for other in &p.protected {
        exact(&other.path, &other.stamp)?;
    }
    for unit in [
        &p.unit[..],
        "horizon251-index-cache-seal-20261118-v1.service",
    ] {
        let fields = manager(
            unit,
            "Id,LoadState,ActiveState,SubState,ControlGroup,MainPID,ControlPID,Job,InvocationID,ExecStart,FragmentPath,DropInPaths",
        )?;
        ensure!(
            fields.get("Id").map(String::as_str) == Some(unit)
                && fields.get("LoadState").map(String::as_str) == Some("not-found")
                && fields.get("ActiveState").map(String::as_str) == Some("inactive")
                && fields.get("SubState").map(String::as_str) == Some("dead")
                && ["MainPID", "ControlPID"]
                    .iter()
                    .all(|k| fields.get(*k).map(String::as_str) == Some("0"))
                && [
                    "Job",
                    "ControlGroup",
                    "InvocationID",
                    "FragmentPath",
                    "DropInPaths"
                ]
                .iter()
                .all(|k| fields.get(*k).is_some_and(String::is_empty))
                && fields.get("ExecStart").is_none_or(String::is_empty)
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(unit)
                    .try_exists()?,
            "acquisition or sealing unit is scheduled or live: {unit}"
        );
    }
    Ok(())
}
fn manager(unit: &str, keys: &str) -> Result<BTreeMap<String, String>> {
    let r = Command::new("/usr/bin/systemctl")
        .args(["show", "--all", unit, "--property", keys])
        .output()?;
    ensure!(
        r.status.success() || r.status.code() == Some(4),
        "manager query failed"
    );
    let s = String::from_utf8(r.stdout)?;
    Ok(s.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect())
}
fn protected_fleet(book: &Value) -> Result<()> {
    let fleet = doc(&field(book, "fleet")?)?;
    let census = fleet["unit_census"]
        .as_object()
        .context("original unit census")?;
    for (unit, prior) in census.iter().filter(|(_, v)| v["ActiveState"] == "active") {
        ensure!(
            unit.ends_with(".service")
                && prior["Id"] == unit.as_str()
                && text(prior, "InvocationID")?.len() == 32
                && text(prior, "MainPID")?.parse::<u64>()? > 0,
            "invalid live owner in booked fleet"
        );
        let current = manager(
            unit,
            "Id,InvocationID,MainPID,ControlGroup,ActiveState,NRestarts",
        )?;
        for k in [
            "Id",
            "InvocationID",
            "MainPID",
            "ControlGroup",
            "ActiveState",
            "NRestarts",
        ] {
            ensure!(
                current.get(k).map(String::as_str) == Some(text(prior, k)?),
                "booked owner changed: {unit} {k}"
            );
        }
    }
    Ok(())
}
fn hash_body(
    path: &Path,
    expected: &Stamp,
    header: &str,
    b: &Value,
    p: &Profile,
) -> Result<String> {
    exact(path, expected)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    ensure!(stamp(&f.metadata()?) == *expected, "index open race");
    let mut f = BufReader::with_capacity(1 << 20, f);
    let head_len = header.len() / 2;
    let mut head = vec![0; head_len];
    f.read_exact(&mut head)?;
    ensure!(
        head.iter().map(|x| format!("{x:02x}")).collect::<String>() == header,
        "epoch 251 CID header"
    );
    let mut h = Sha256::new();
    h.update(&head);
    let mut n = head_len as u64;
    let mut next = 1 << 30;
    let mut buf = vec![0; 1 << 20];
    loop {
        let count = f.read(&mut buf)?;
        if count == 0 {
            break;
        }
        n += count as u64;
        ensure!(n <= expected.len, "index grew");
        h.update(&buf[..count]);
        if n >= next {
            gate(b, p)?;
            next += 1 << 30;
        }
    }
    ensure!(
        n == expected.len && stamp(&f.get_ref().metadata()?) == *expected,
        "changed body"
    );
    exact(path, expected)?;
    Ok(format!("{:x}", h.finalize()))
}
fn binding(p: &Path) -> Result<Bound> {
    Ok(Bound {
        path: p.to_path_buf(),
        sha256: sha(&read_bounded(p, LIMIT)?),
    })
}
fn run_readers(p: &Profile, book: &Value) -> Result<Value> {
    let source = field(book, "readers")?;
    ensure!(
        source.path == Path::new(DEPLOY).join(READERS)
            && source.sha256 == sha(include_bytes!("readers.py")),
        "reader census source mismatch"
    );
    file_bytes(&source.path, &source.sha256, 0, None, true)?;
    let own = format!("/run/systemd/transient/{}", text(book, "unit")?);
    let action = Command::new("/usr/bin/python3")
        .args(["-I", "-B"])
        .arg(source.path)
        .args([&p.selection, "--own", &own])
        .output()?;
    ensure!(
        action.status.success() && action.stdout.len() <= LIMIT as usize,
        "scheduled graph incomplete: {}",
        String::from_utf8_lossy(&action.stderr)
    );
    let x: Value = serde_json::from_slice(&action.stdout)?;
    ensure!(
        x["selection"] == p.selection
            && x["remaining"] == json!([])
            && x["unresolved"] == json!([])
            && number(&x, "files")? > 0,
        "staged/scheduled reader remains: {}",
        x
    );
    Ok(x)
}
fn current_context(p: &Profile, b: &Value) -> Result<Value> {
    gate(b, p)?;
    protected_fleet(b)?;
    let staged = run_readers(p, b)?;
    let live = process_closure(p)?;
    // This acquisition directory is the target parent already covered by process_closure.
    ensure!(p.target.parent() == Some(&p.root), "foreign cache root");
    protected_fleet(b)?;
    gate(b, p)?;
    Ok(json!({"live":live,"scheduled":staged}))
}
fn controller(b: &Value, mode: &str, p: &Profile, booking: &Bound, self_sha: &str) -> Result<()> {
    let attempt = number(b, "attempt")?;
    ensure!((1..=999).contains(&attempt), "attempt range");
    let unit = format!("horizon251-index-{}-{mode}-a{attempt}.service", p.selection);
    let want = Path::new(DIAG)
        .join(unit.trim_end_matches(".service"))
        .join("booking.json");
    let meta = fs::symlink_metadata(&want)?;
    ensure!(
        booking.path == want
            && meta.mode() & 0o777 == 0o400
            && meta.uid() == 0
            && want.parent().unwrap().metadata()?.uid() == 0
            && want.parent().unwrap().metadata()?.mode() & 0o077 == 0
            && b["schema"] == "horizon251-duplicate-index-booking-v1"
            && b["controller"] == MAIN
            && b["unit"] == unit
            && b["mode"] == mode
            && b["selection"] == p.selection
            && b["replay_authorized"] == false
            && b["physical_credit_taken_bytes"] == 0
            && number(b, "maximum_memory_bytes")? == 512 << 20
            && number(b, "maximum_metadata_bytes")? == 32 << 20
            && number(b, "minimum_free_bytes")? > 0,
        "incorrect original Main booking"
    );
    let start = number(b, "recorded_unix_seconds")?;
    let expiry = number(b, "expires_unix_seconds")?;
    ensure!(
        start <= now()? && start < expiry && expiry <= start + 1800,
        "invalid booking lifetime"
    );
    let fleet = doc(&field(b, "fleet")?)?;
    let funding = doc(&field(b, "complete_funding")?)?;
    ensure!(
        fleet["schema"]
            .as_str()
            .is_some_and(|s| s.contains("fleet"))
            && funding["controller"] == MAIN
            && funding["fleet"] == b["fleet"]
            && funding["mode"] == mode
            && funding["cpu"] == b["cpu"]
            && funding["requested_memory"] == (576u64 << 20)
            && funding["disk_reserve"] == (32u64 << 20)
            && funding["minimum_free_bytes"] == b["minimum_free_bytes"]
            && funding["replay_authorized"] == false
            && funding["physical_credit_taken_bytes"] == 0
            && funding["finite_memory"]["hard_margin"]
                .as_i64()
                .is_some_and(|x| x >= 0)
            && funding["finite_memory"]["growth_margin"]
                .as_i64()
                .is_some_and(|x| x >= 0)
            && funding["disk_margin"].as_i64().is_some_and(|x| x >= 0)
            && number(&funding, "recorded_unix_seconds")? <= start
            && start - number(&funding, "recorded_unix_seconds")? <= 120,
        "different or unfunded phase"
    );
    let image = field(b, "image")?;
    ensure!(
        image.path == Path::new(DEPLOY).join(IMAGE)
            && image.sha256 == self_sha
            && fs::read_link("/proc/self/exe")? == image.path
            && stamp(&fs::metadata("/proc/self/exe")?) == stamp(&fs::metadata(&image.path)?),
        "wrong mapped binary"
    );
    root_dir(Path::new(DEPLOY))?;
    let bin = file_bytes(&image.path, self_sha, 0, None, true)?;
    ensure!(!bin.is_empty(), "empty image");
    let seal_path = Path::new(DEPLOY).join("deployment-seal-receipt.json");
    let seal = exact_bound(&binding(&seal_path)?)?;
    let members = seal["members"].as_array().context("deployment members")?;
    ensure!(seal["destination"]==DEPLOY &&
        members.iter().filter(|m|m["name"]==IMAGE && m["sha256"]==self_sha).count()==1 &&
        members.iter().filter(|m|m["name"]==READERS && m["sha256"]==sha(include_bytes!("readers.py"))).count()==1,
        "unsealed or substituted deployment");
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(&unit);
    let iid = env::var("INVOCATION_ID")?;
    let props=Command::new("/usr/bin/systemctl").args(["show",&unit,"--property=Id,InvocationID,MainPID,ActiveState,NRestarts,MemoryMax,MemorySwapMax,AllowedCPUs,Restart,Type,PrivateNetwork"]).output()?;
    ensure!(props.status.success(), "issuer manager");
    let raw = String::from_utf8(props.stdout)?;
    let m: BTreeMap<_, _> = raw.lines().filter_map(|x| x.split_once('=')).collect();
    let cpu = number(b, "cpu")?.to_string();
    let pid = std::process::id().to_string();
    ensure!(
        m.get("Id") == Some(&unit.as_str())
            && m.get("InvocationID") == Some(&iid.as_str())
            && m.get("ActiveState") == Some(&"active")
            && m.get("Type") == Some(&"exec")
            && m.get("MainPID") == Some(&pid.as_str())
            && m.get("NRestarts") == Some(&"0")
            && m.get("Restart") == Some(&"no")
            && m.get("PrivateNetwork") == Some(&"yes")
            && m.get("MemoryMax") == Some(&"536870912")
            && m.get("MemorySwapMax") == Some(&"0")
            && fs::read_to_string(cg.join("memory.max"))?.trim() == "536870912"
            && fs::read_to_string(cg.join("memory.swap.max"))?.trim() == "0"
            && fs::read_to_string(cg.join("cpuset.cpus.effective"))?.trim() == cpu
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{unit}"),
        "wrong service envelope"
    );
    Ok(())
}
fn durable(p: &Path, v: Value) -> Result<Bound> {
    write_new(p, &v)
}
fn same_after_rename(actual: &Stamp, prior: &Stamp) -> bool {
    let mut x = actual.clone();
    x.ctime = prior.ctime;
    x.ctime_ns = prior.ctime_ns;
    x == *prior
}
fn name(p: &Path) -> Result<CString> {
    Ok(CString::new(p.file_name().context("filename")?.as_bytes())?)
}
fn mount_id(f: &File) -> Result<u64> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", f.as_raw_fd()))?;
    Ok(info
        .lines()
        .find_map(|l| l.strip_prefix("mnt_id:"))
        .context("kernel mount id")?
        .trim()
        .parse()?)
}
fn isolation_dir(p: &Profile, b: &Value) -> Result<(PathBuf, File)> {
    let parent = parent_fd(p)?;
    let dir = p
        .target
        .parent()
        .context("target parent")?
        .join(".horizon251-index-quarantine-v1");
    let enrolled = &b["quarantine_directory"];
    ensure!(enrolled["path"] == json!(dir), "unregistered quarantine");
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name(&dir)?.as_ptr(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    ensure!(raw >= 0, "cannot open original quarantine");
    use std::os::fd::FromRawFd;
    let f = unsafe { File::from_raw_fd(raw) };
    let m = f.metadata()?;
    ensure!(
        dir.canonicalize()? == dir
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && m.dev() == DEV
            && enrolled["dev"] == m.dev()
            && enrolled["ino"] == m.ino()
            && stamp(&m) == stamp(&fs::symlink_metadata(&dir)?)
            && mount_id(&f)? == mount_id(&parent)?,
        "quarantine changed or cross mount"
    );
    Ok((dir, f))
}
fn quarantine(p: &Profile, dir: &File, dest: &Path) -> Result<Stamp> {
    let parent = parent_fd(p)?;
    exact(&p.target, &p.target_identity)?;
    let old = name(&p.target)?;
    let new = name(dest)?;
    let rc = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            old.as_ptr(),
            dir.as_raw_fd(),
            new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    ensure!(rc == 0, "quarantine: {}", std::io::Error::last_os_error());
    parent.sync_all()?;
    dir.sync_all()?;
    absent(&p.target)?;
    let after = stamp(&fs::symlink_metadata(dest)?);
    ensure!(
        same_after_rename(&after, &p.target_identity),
        "quarantined entry changed; retain for adjudication"
    );
    Ok(after)
}
pub(super) fn run() -> Result<()> {
    let a: Vec<_> = env::args().collect();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && a.len() == 6
            && matches!(a[1].as_str(), "check" | "retire")
            && digest(&a[4])
            && digest(&a[5]),
        "usage: IMAGE check|retire SELECTION BOOKING BOOKING_SHA IMAGE_SHA"
    );
    let mode = &a[1];
    let p = get_profile(&a[2])?;
    let book = Bound {
        path: a[3].clone().into(),
        sha256: a[4].clone(),
    };
    let b = doc(&book)?;
    controller(&b, mode, &p, &book, &a[5])?;
    original(&p)?;
    let state = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon251-index-{}-state-v1",
        p.selection
    ));
    root_dir(&state)?;
    ensure!(
        state.metadata()?.mode() & 0o777 == 0o700 && state.metadata()?.dev() == DEV,
        "state directory"
    );
    let _lock = lock()?;
    let attempt = number(&b, "attempt")?;
    let result = state.join(format!("{mode}-a{attempt}.json"));
    absent(&result)?;
    let begin = current_context(&p, &b)?;
    let keep = hash_body(&p.retained.path, &p.retained.stamp, &p.header_hex, &b, &p)?;
    ensure!(
        keep == p.sha256,
        "retained bytes differ from original sealed digest"
    );
    if mode == "check" {
        let observed = hash_body(&p.target, &p.target_identity, &p.header_hex, &b, &p)?;
        ensure!(
            observed == keep,
            "target differs from retained sealed index"
        );
        let end = current_context(&p, &b)?;
        exact(&p.target, &p.target_identity)?;
        durable(
            &result,
            json!({"schema":"horizon251-duplicate-index-check-v1","selection":p.selection,"image":a[5],
            "booking":book,"profile":p,"sha256":keep,"initial":begin,"final":end,"recorded":now()?,"credit":0}),
        )?;
        return Ok(());
    }
    let check = field(&b, "prior_check")?;
    ensure!(
        check.path.parent() == Some(&state)
            && check
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("check-a") && s.ends_with(".json")),
        "prior check namespace"
    );
    let c = exact_bound(&check)?;
    let intent = state.join("intent.json");
    ensure!(
        c["schema"] == "horizon251-duplicate-index-check-v1"
            && c["selection"] == p.selection
            && c["profile"] == json!(p)
            && c["image"] == a[5]
            && c["sha256"] == keep
            && c["credit"] == 0
            && number(&c, "recorded")? <= now()?
            && (intent.try_exists()? || now()? - number(&c, "recorded")? <= 1800),
        "prior full check changed/expired"
    );
    let (isolation, dir) = isolation_dir(&p, &b)?;
    let isolated = isolation.join("quarantined.index");
    let checked = state.join("quarantine-verified.json");
    let unlink = state.join("unlink-intent.json");
    let complete = state.join("completion.json");
    absent(&complete)?;
    let scope = json!({"schema":"horizon251-duplicate-index-intent-v1","selection":p.selection,"profile":p,"image":a[5],"sha256":keep,"check":check,"quarantine_directory":b["quarantine_directory"]});
    if !intent.try_exists()? {
        absent(&isolated)?;
        absent(&checked)?;
        absent(&unlink)?;
        exact(&p.target, &p.target_identity)?;
        current_context(&p, &b)?;
        durable(&intent, scope.clone())?;
    }
    ensure!(
        exact_bound(&binding(&intent)?)? == scope,
        "existing intent belongs to different check/profile"
    );
    if p.target.try_exists()? {
        absent(&isolated)?;
        absent(&checked)?;
        absent(&unlink)?;
        ensure!(
            hash_body(&p.target, &p.target_identity, &p.header_hex, &b, &p)? == keep,
            "pre-quarantine content"
        );
        current_context(&p, &b)?;
        isolation_dir(&p, &b)?;
        quarantine(&p, &dir, &isolated)?;
    }
    absent(&p.target)?;
    if isolated.try_exists()? {
        let q = stamp(&fs::symlink_metadata(&isolated)?);
        ensure!(
            same_after_rename(&q, &p.target_identity)
                && hash_body(&isolated, &q, &p.header_hex, &b, &p)? == keep,
            "isolated body changed"
        );
        let witness = json!({"intent":binding(&intent)?,"identity":q,"sha256":keep});
        if !checked.try_exists()? {
            durable(&checked, witness.clone())?;
        }
        ensure!(
            exact_bound(&binding(&checked)?)? == witness,
            "invalid quarantine readback"
        );
        current_context(&p, &b)?;
        absent(&p.target)?;
        exact(&isolated, &q)?;
        let u = json!({"intent":binding(&intent)?,"verified":binding(&checked)?,"expected":q});
        if !unlink.try_exists()? {
            durable(&unlink, u.clone())?;
        }
        ensure!(
            exact_bound(&binding(&unlink)?)? == u,
            "unlink intent differs"
        );
        // Reopen the original parent and root-only directory just before the fd-relative unlink.
        let (_, fresh) = isolation_dir(&p, &b)?;
        ensure!(
            stamp(&dir.metadata()?) == stamp(&fresh.metadata()?),
            "quarantine moved"
        );
        let pinned = PathBuf::from(format!(
            "/proc/self/fd/{}/quarantined.index",
            dir.as_raw_fd()
        ));
        ensure!(
            stamp(&fs::symlink_metadata(pinned)?) == q,
            "quarantine entry changed"
        );
        ensure!(
            unsafe { libc::unlinkat(dir.as_raw_fd(), name(&isolated)?.as_ptr(), 0) } == 0,
            "quarantine unlink"
        );
        dir.sync_all()?;
    }
    let verified = exact_bound(&binding(&checked)?)?;
    let s: Stamp = serde_json::from_value(verified["identity"].clone())?;
    ensure!(
        same_after_rename(&s, &p.target_identity)
            && verified == json!({"intent":binding(&intent)?,"identity":s,"sha256":keep})
            && exact_bound(&binding(&unlink)?)?
                == json!({"intent":binding(&intent)?,"verified":binding(&checked)?,"expected":s}),
        "missing original unlink proof"
    );
    absent(&p.target)?;
    absent(&isolated)?;
    original(&p)?;
    protected_fleet(&b)?;
    gate(&b, &p)?;
    let end = json!({"schema":"horizon251-duplicate-index-retirement-completion-v1","intent":binding(&intent)?,"check":check,
        "verified":binding(&checked)?,"unlink":binding(&unlink)?,"selection":p.selection,"booking":book,
        "retained":p.retained,"sha256":keep,"removed_inode":p.target_identity.ino,
        "physically_removed_bytes":p.target_identity.blocks*512,"credit":0,"fresh_admission_required":true});
    let completion = durable(&complete, end)?;
    durable(&result, json!({"completion":completion}))?;
    Ok(())
}

#[cfg(test)]
mod checks {
    use super::*;
    #[test]
    fn only_registered_acquisition_and_structural_donor() {
        let rows = paths().unwrap();
        assert_eq!(rows.len(), 1);
        let p = get_profile("cid").unwrap();
        assert_eq!(p.target_identity.ino, 31109756);
        assert_eq!(p.target_identity.blocks * 512, 10_554_638_336);
        assert_eq!(p.retained.stamp.ino, 30861107);
        assert_eq!(p.header_hex.len(), 260);
        assert!(p.protected.iter().any(|a| a.stamp.ino == 31112947));
        assert_eq!(p.unit, "horizon251-index-transfer-20261118-v1.service");
        assert_eq!(p.iid, "8fd0271eb06b4307aba4e116c12f00d8");
        for bad in [
            "singleton",
            "249",
            "251",
            "../cid",
            "slot251.partial",
            "all",
        ] {
            assert!(get_profile(bad).is_err());
        }
    }
    #[test]
    fn substituted_source_donor_consumer_or_drain_fails_custody() {
        let p = get_profile("cid").unwrap();
        let package = p.retained.path.parent().unwrap();
        let raw = json!({"source":p.target,"name":p.retained.path.file_name().unwrap().to_str(),"sha256":p.sha256,"mode":292});
        let mut sealed = raw.clone();
        sealed["mode"] = json!("0444");
        sealed["bytes"] = json!(p.target_identity.len);
        let archive = p
            .protected
            .iter()
            .find(|a| a.stamp.ino == 31112947)
            .unwrap();
        let docs = vec![
            json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":package,"members":[raw]}),
            json!({"schema":"jetstreamer-sealed-deployment-receipt-v1","destination":package,"members":[sealed],"plan_sha256":p.custody[0].sha256}),
            json!({"cache_seal":p.custody[1],"structure_accepted":true,"indexes":[{"binding":{"ino":p.retained.stamp.ino,"dev":DEV,"path":p.retained.path,"sha256":p.sha256},"structure":{"epoch":251,"kind":"cid-to-offset-and-size"}}]}),
            json!({"index_cache":package,"index_structure":p.custody[2]}),
            json!({"epoch":251,"producer":{"unit":{"InvocationID":"cd2477bfec7f4e498545762c633e7bb0"}},"source":{"archive":{"identity":{"inode":31112947},"path":archive.path}}}),
            json!({"terminal_handoff":p.custody[4],"producer_cgroup_drained":true}),
        ];
        validate_records(&p, &docs).unwrap();
        for (row, pointer) in [
            (0, "/members/0/source"),
            (1, "/members/0/sha256"),
            (2, "/indexes/0/binding/ino"),
            (3, "/index_cache"),
            (4, "/source/archive/path"),
            (5, "/producer_cgroup_drained"),
        ] {
            let mut altered = docs.clone();
            *altered[row].pointer_mut(pointer).unwrap() = Value::Null;
            assert!(
                validate_records(&p, &altered).is_err(),
                "field accepted {pointer}"
            );
        }
    }
    #[test]
    fn quarantine_allows_only_the_original_rename_ctime_change() {
        let base = get_profile("cid").unwrap().target_identity;
        let mut other = base.clone();
        other.ctime_ns += 1;
        assert!(same_after_rename(&other, &base));
        other.ino += 1;
        assert!(!same_after_rename(&other, &base));
        other = base.clone();
        other.mtime_ns += 1;
        assert!(!same_after_rename(&other, &base));
        other = base.clone();
        other.nlink = 2;
        assert!(!same_after_rename(&other, &base));
        other = base.clone();
        other.len += 1;
        assert!(!same_after_rename(&other, &base));
        other = base.clone();
        other.blocks += 1;
        assert!(!same_after_rename(&other, &base));
    }
}
