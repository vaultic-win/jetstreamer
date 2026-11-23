use super::*;
use crate::{closure::Volume, journal::Journal, retirement::Tree};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::MetadataExt,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
const LOCK: &str = "/home/ubuntu/.jetstreamer-private/r2-receipts/local-mutation.lock";
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn geteuid() -> u32;
}
pub fn command(cmd: &str, args: &[&str]) -> io::Result<String> {
    let o = Command::new(cmd).args(args).env("LC_ALL", "C").output()?;
    need(
        o.status.success() && o.stdout.len() < 4 << 20,
        "command failed or output exceeded bound",
    )?;
    String::from_utf8(o.stdout).map_err(io::Error::other)
}
fn systemd(u: &str, keys: &str) -> io::Result<BTreeMap<String, String>> {
    let raw = command("/usr/bin/systemctl", &["show", u, "-p", keys])?;
    let mut out = BTreeMap::new();
    for l in raw.lines() {
        let (k, v) = l
            .split_once('=')
            .ok_or_else(|| io::Error::other("unit property"))?;
        need(
            out.insert(k.to_string(), v.to_string()).is_none(),
            "duplicate unit property",
        )?
    }
    Ok(out)
}
fn manager() -> io::Result<()> {
    for u in [UNIT, GUARD, TIMER, FAILSAFE] {
        let is_timer = u == TIMER;
        let keys = if is_timer {
            "Id,LoadState,ActiveState,Job,WantedBy,RequiredBy,Triggers,TriggeredBy,Unit,DropInPaths,FragmentPath"
        } else {
            "Id,LoadState,ActiveState,Job,WantedBy,RequiredBy,Triggers,TriggeredBy,ControlGroup,MainPID,ControlPID,Restart,NRestarts,InvocationID,SubState,DropInPaths,FragmentPath"
        };
        let m = systemd(u, keys)?;
        let prop = |k: &str| m.get(k).map(String::as_str);
        need(
            prop("Id") == Some(u)
                && prop("LoadState") == Some("loaded")
                && matches!(prop("ActiveState"), Some("inactive" | "failed"))
                && ["Job", "WantedBy", "RequiredBy", "DropInPaths"]
                    .iter()
                    .all(|k| prop(k) == Some("")),
            "stopped owner reactivated",
        )?;
        let fp = Path::new(prop("FragmentPath").unwrap_or("")).canonicalize()?;
        need(fp == Path::new(CONTROL_DIR).join(u), "changed stopped unit")?;
        need(
            prop("Triggers") == Some(if is_timer { GUARD } else { "" })
                && prop("TriggeredBy") == Some(if u == GUARD { TIMER } else { "" }),
            "extra or missing trigger",
        )?;
        if is_timer {
            need(prop("Unit") == Some(GUARD), "timer peer")?
        } else {
            need(
                ["MainPID", "ControlPID", "NRestarts"]
                    .iter()
                    .all(|k| prop(k) == Some("0"))
                    && prop("Restart") == Some("no")
                    && prop("ControlGroup") == Some("")
                    && !Path::new("/sys/fs/cgroup/system.slice")
                        .join(u)
                        .try_exists()?,
                "peer cgroup or job",
            )?;
        }
        if u == UNIT {
            need(
                prop("ActiveState") == Some("inactive")
                    && prop("SubState") == Some("dead")
                    && prop("InvocationID") == Some(""),
                "original terminal PID1",
            )?
        }
    }
    Ok(())
}
fn sha(p: &Path) -> io::Result<String> {
    preservation::digest(&File::open(p)?)
}
fn under_root(path: &Path) -> io::Result<()> {
    need(path.canonicalize()? == path, "noncanonical control path")?;
    for a in path.ancestors() {
        let m = fs::symlink_metadata(a)?;
        need(
            m.uid() == 0 && m.mode() & 0o022 == 0,
            "mutable root control ancestor",
        )?
    }
    Ok(())
}
fn pinned(p: &Path, s: &str) -> io::Result<()> {
    let m = fs::symlink_metadata(p)?;
    need(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() < 1 << 20,
        "original receipt custody",
    )?;
    let f = open(p, 0)?;
    let old = preservation::Stamp::from(&m);
    need(
        old == preservation::Stamp::from(&f.metadata()?)
            && preservation::digest(&f)? == s
            && old == preservation::Stamp::from(&p.symlink_metadata()?),
        "original receipt digest or identity",
    )?;
    Ok(())
}
fn originals() -> io::Result<()> {
    for l in profile::ORIGINALS.lines() {
        let (h, p) = l.split_once('\t').unwrap();
        pinned(Path::new(p), h)?
    }
    let j = command(
        "/usr/bin/journalctl",
        &[
            "--boot=3b17d0055c3a4a0e8841da097e0957b5",
            "--quiet",
            "--no-pager",
            "-n",
            "20",
            "-o",
            "export",
            "--output-fields=MESSAGE_ID",
            "_PID=1",
            "_UID=0",
            &format!("UNIT={UNIT}"),
            &format!("INVOCATION_ID={PRODUCER_IID}"),
        ],
    )?;
    let events = profile::EVENTS;
    let mut matched = vec![];
    for rec in j.split("\n\n") {
        let id = rec.lines().find_map(|s| s.strip_prefix("MESSAGE_ID="));
        let cur = rec.lines().find_map(|s| s.strip_prefix("__CURSOR="));
        if let (Some(i), Some(c)) = (id, cur) {
            if events.iter().any(|(x, _)| *x == i) {
                matched.push((i, c));
            }
        }
    }
    need(matched == events, "original journal boundaries")
}
fn lock() -> io::Result<File> {
    let p = Path::new(LOCK);
    need(p.canonicalize()? == p, "unexpected lock path")?;
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(NOFOLLOW)
        .open(p)?;
    let m = f.metadata()?;
    need(
        (m.dev(), m.ino(), m.uid(), m.mode() & 0o7777, m.nlink())
            == (66305, 550574, 1000, 0o600, 1)
            && m.is_file(),
        "shared lock identity",
    )?;
    need(
        unsafe { flock(f.as_raw_fd(), 6) } == 0,
        "shared mutation lock busy",
    )?;
    lock_current(&f)?;
    Ok(f)
}
fn lock_current(f: &File) -> io::Result<()> {
    let m = fs::symlink_metadata(LOCK)?;
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", f.as_raw_fd()))?;
    need(
        (m.dev(), m.ino()) == (66305, 550574)
            && info
                .lines()
                .any(|s| s.starts_with("lock:") && s.contains(" FLOCK ") && s.contains(" WRITE ")),
        "lock replaced or lost",
    )
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn grant_text(p: &Path) -> io::Result<String> {
    under_root(p)?;
    let f = open(p, 0)?;
    let m = f.metadata()?;
    need(
        m.is_file() && m.nlink() == 1 && m.len() < 4096 && m.mode() & 0o7777 == 0o400,
        "first-guard token custody",
    )?;
    use std::io::Read;
    let mut text = String::new();
    f.take(4096).read_to_string(&mut text)?;
    Ok(text)
}
struct Grant {
    path: PathBuf,
    text: String,
    unit: String,
    iid: String,
    booking: String,
    image: String,
}
impl Grant {
    fn read(close: bool) -> io::Result<Self> {
        let iid = std::env::var("INVOCATION_ID").map_err(io::Error::other)?;
        need(hex(&iid, 32), "actual service invocation")?;
        let group = fs::read_to_string("/proc/self/cgroup")?;
        let unit = group
            .trim()
            .strip_prefix("0::/system.slice/")
            .ok_or_else(|| io::Error::other("unexpected service cgroup"))?
            .to_string();
        let phase = if close { "close" } else { "retire" };
        let n = unit
            .strip_prefix(&format!(
                "horizon266-stopped-{phase}-{SERVICE_GENERATION}-a"
            ))
            .and_then(|s| s.strip_suffix(".service"))
            .unwrap_or("");
        need(
            !n.is_empty()
                && n.len() <= 4
                && n.bytes().all(|c| c.is_ascii_digit())
                && !n.starts_with('0'),
            "unbooked unit name",
        )?;
        let dir = Path::new(GRANTS);
        under_root(dir)?;
        let path = dir.join(&iid);
        for _ in 0..70 {
            if path.try_exists()? {
                break;
            }
            std::thread::sleep(Duration::from_secs(1))
        }
        let text = grant_text(&path)?;
        let entry: Vec<_> = text.lines().collect();
        need(
            entry.len() == 8
                && entry[0] == "horizon266-stopped-first-guard-v1"
                && entry[1] == unit
                && entry[2] == iid
                && entry[3] == phase
                && entry[7] == CHECK
                && hex(entry[5], 64)
                && hex(entry[6], 64),
            "guard authority",
        )?;
        let exp = entry[4].parse::<u64>().map_err(io::Error::other)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_secs();
        need(
            exp >= now && exp - now <= 120,
            "expired or overlong initial first-guard grant",
        )?;
        let image = entry[5].to_string();
        let booking = entry[6].to_string();
        need(
            sha(Path::new("/proc/self/exe"))? == image,
            "self image hash",
        )?;
        let executable = std::env::current_exe()?;
        under_root(&executable)?;
        need(
            executable.symlink_metadata()?.mode() & 0o222 == 0,
            "mutable executable",
        )?;
        let g = Self {
            path,
            text,
            unit,
            iid,
            booking,
            image,
        };
        g.live()?;
        Ok(g)
    }
    fn live(&self) -> io::Result<()> {
        need(
            grant_text(&self.path)? == self.text,
            "first guard revoked or replaced",
        )?;
        let p = Path::new(STATE)
            .join("bookings")
            .join(format!("{}.json", self.iid));
        under_root(&p)?;
        pinned(&p, &self.booking)?;
        let m = systemd(
            &self.unit,
            "Id,ActiveState,SubState,InvocationID,MainPID,NRestarts,Restart,MemoryMax,MemorySwapMax,TasksMax,KillMode,ControlGroup,User,CPUQuotaPerSecUSec",
        )?;
        let v = |k: &str| m.get(k).map(String::as_str);
        need(
            v("Id") == Some(&self.unit)
                && v("InvocationID") == Some(&self.iid)
                && v("ActiveState") == Some("active")
                && v("SubState") == Some("running")
                && v("MainPID") == Some(std::process::id().to_string().as_str())
                && v("NRestarts") == Some("0")
                && v("Restart") == Some("no")
                && v("KillMode") == Some("control-group")
                && v("MemorySwapMax") == Some("0")
                && v("User") == Some("root")
                && v("MemoryMax")
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|n| n > 0 && n <= 256 << 20)
                && v("TasksMax")
                    .and_then(|s| s.parse::<usize>().ok())
                    .is_some_and(|n| n > 0 && n <= 32)
                && v("CPUQuotaPerSecUSec") == Some("1s"),
            "effective first-guard service boundary",
        )
    }
}
fn census(allowed: &[i32], ro: bool) -> io::Result<()> {
    // Execute the exact previously used, compiled-in source. Its Python argv contains
    // no target path, so the census can reject any such independent process command.
    let script = "import os,sys; m={'__name__':'locked_census','STOPPED_PROFILE':sys.argv[2]}; exec(compile(sys.stdin.buffer.read(),'<sealed-census>','exec'),m); r=m['census'](); allowed={(str(os.getppid()),'fd/'+i) for i in sys.argv[3:]}; refs={tuple(x) for x in r['references']}; assert refs==allowed, refs; assert sys.argv[1]!='ro' or all('ro' in row.split(' - ')[1].split()[2].split(',') for rows in r['namespaces'].values() for row in rows); print('verified')";
    let mut p = Command::new("/usr/bin/python3")
        .args([
            "-I",
            "-B",
            "-c",
            script,
            if ro { "ro" } else { "normal" },
            SERVICE_GENERATION,
        ])
        .args(allowed.iter().map(ToString::to_string))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    p.stdin
        .take()
        .unwrap()
        .write_all(include_bytes!("census.py"))?;
    let o = p.wait_with_output()?;
    need(
        o.status.success() && o.stdout == b"verified\n",
        "fresh locked namespace/consumer census failed",
    )
}
/// Check the stopped producer and all preservation evidence on the actual host before issuing a grant.
pub fn check_terminal() -> io::Result<()> {
    need(
        unsafe { geteuid() } == 0
            && fs::read_link("/proc/1/ns/mnt")? == fs::read_link("/proc/self/ns/mnt")?
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "original host/boot/root",
    )?;
    let held = lock()?;
    manager()?;
    originals()?;
    retained::manifest()?;
    census(&[], false)?;
    let volume = closure::Original;
    need(
        volume.state()? == (false, false),
        "unexpected stopped volume state",
    )?;
    volume.allocated()?;
    lock_current(&held)
}

pub fn run(close: bool) -> io::Result<()> {
    need(
        unsafe { geteuid() } == 0
            && fs::read_link("/proc/1/ns/mnt")? == fs::read_link("/proc/self/ns/mnt")?
            && fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "original host/boot/root",
    )?;
    let now = Grant::read(close)?;
    let held = lock()?;
    under_root(Path::new(STATE))?;
    let j = Journal::new(Path::new(STATE), 0)?;
    manager()?;
    originals()?;
    census(&[], false)?;
    retained::manifest()?;
    preservation::originals()?;
    let vol = closure::Original;
    vol.allocated()?;
    j.put(&format!("grant-{}", now.iid), &now.text)?;
    let prior = if let Some(old) = j.get("first-grant")? {
        old
    } else {
        need(!close, "cannot begin at trim")?;
        j.put("first-grant", &now.text)?;
        now.text.clone()
    };
    let v: Vec<_> = prior.lines().collect();
    need(
        v.len() == 8
            && v[0] == "horizon266-stopped-first-guard-v1"
            && v[3] == "retire"
            && hex(v[2], 32)
            && v[5] == now.image
            && hex(v[6], 64)
            && v[7] == CHECK,
        "original intent grant",
    )?;
    let p = Path::new(STATE)
        .join("bookings")
        .join(format!("{}.json", v[2]));
    under_root(&p)?;
    pinned(&p, v[6])?;
    let binding = format!(
        "horizon266-stopped-retirement-v1\nstop={STOP}\ncheck={CHECK}\nfirst_invocation={}\nfirst_booking={}\nimage={}\nboot={BOOT}\noriginal={DEVICE}:{CHILD_INODE}\narchive={ARCHIVE_SHA}\nstate=2c9c246126a8878f8e11928858512f8ef881a6a794118c04d1a1572b18427c87\n",
        v[2], v[6], v[5]
    );
    let check = || -> io::Result<()> {
        lock_current(&held)?;
        now.live()?;
        manager()?;
        retained::manifest()?;
        vol.allocated()?;
        Ok(())
    };
    if close {
        need(
            retirement::Original::open()?.names()? == (None, None),
            "scratch still present",
        )?;
        closure::close(&vol, &j, &binding, &mut |ro| {
            check()?;
            census(&[], ro)
        })?;
    } else {
        let t = retirement::Original::open()?;
        let fds = [t.src.as_raw_fd(), t.vault.as_raw_fd()];
        if j.get("retired")?.is_none() {
            need(
                vol.state()? == (false, false),
                "unexpected readonly guest before retirement",
            )?;
        }
        retirement::retire(&t, &j, &binding, vol.allocated()?, &mut || {
            check()?;
            census(&fds, false)
        })?;
        drop(t);
        check()?;
        census(&[], false)?;
        preservation::originals()?;
        println!("retirement_complete=true\ncapacity_credit=0");
    }
    check()?;
    originals()?;
    let phase = if close { "close" } else { "retire" };
    let record = j
        .get(if close { "closed" } else { "retired" })?
        .ok_or_else(|| io::Error::other("missing phase evidence"))?;
    j.put(
        &format!("{phase}-confirmed-{}", now.iid),
        &format!(
            "{record}confirming_invocation={}\nconfirming_booking={}\ncapacity_credit=0\n",
            now.iid, now.booking
        ),
    )?;
    Ok(())
}
