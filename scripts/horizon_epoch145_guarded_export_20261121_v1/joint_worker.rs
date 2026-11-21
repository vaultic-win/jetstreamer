//! Authenticate the private copy made by the admitted 136 node.
use super::*;
use model::Identity;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    sync::{Mutex, OnceLock},
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub(super) struct Process {
    pub pid: u32,
    parent: u32,
    pub start_ticks: u64,
    image: PathBuf,
    file: Identity,
}

fn replay_process(pid: u32, group: &str) -> Result<Process> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let ticks = native::ticks(pid)?;
    let status = fs::read_to_string(proc.join("status"))?;
    let field = |k: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(k))
            .map(str::trim)
    };
    ensure!(
        fs::read_to_string(proc.join("cgroup"))?.trim() == group
            && field("Uid:") == Some("1001\t1001\t1001\t1001")
            && field("Gid:") == Some("1003\t1003\t1003\t1003")
            && field("Groups:") == Some("")
            && field("NoNewPrivs:") == Some("1")
            && ["CapEff:", "CapPrm:", "CapAmb:"]
                .iter()
                .all(|k| field(k) == Some("0000000000000000")),
        "136 replay PID {pid} outside admitted cgroup or credentials"
    );
    let p = Process {
        pid,
        parent: field("PPid:").context("replay parent")?.parse()?,
        start_ticks: ticks,
        image: fs::read_link(proc.join("exe"))?,
        file: custody::identity(&fs::metadata(proc.join("exe"))?),
    };
    ensure!(ticks == native::ticks(pid)?, "136 replay PID reused");
    Ok(p)
}

fn relative_image(root: &Path, image: &Path) -> Result<PathBuf> {
    let fixed = root.join("scratch/.historical-runtime");
    let relative = image.strip_prefix(&fixed)?;
    let mut parts = relative.iter();
    let dir = parts
        .next()
        .and_then(|v| v.to_str())
        .context("worker directory")?;
    let suffix = dir
        .strip_prefix("jetstreamer-historical-parent-")
        .context("private worker directory")?;
    ensure!(
        suffix.len() == 6
            && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
            && parts.next() == Some("bound-worker".as_ref())
            && parts.next() == Some("historical-worker".as_ref())
            && parts.next().is_none()
            && image == fixed.join(dir).join("bound-worker/historical-worker"),
        "unexpected 136 private worker layout"
    );
    Ok(image.strip_prefix(root)?.to_path_buf())
}

// Retaining the executable fd also pins the inode while its cached digest is
// reused. Every sample still reopens the scoped name and the live executable.
struct Verified {
    process: Process,
    digest: String,
    fd: File,
}
static VERIFIED: OnceLock<Mutex<Option<Verified>>> = OnceLock::new();

fn verify_worker(root: &Path, p: &Process, source: &Identity, digest: &str) -> Result<()> {
    let relative = relative_image(root, &p.image)?;
    ensure!(root.canonicalize()? == root, "136 root is aliased");
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let named = stable::beneath(&dir, &relative, libc::O_RDONLY)?;
    let m = named.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.dev() == dir.metadata()?.dev()
            && m.dev() == source.device
            && m.ino() != source.inode
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() == source.mode
            && m.mode() & 0o7777 == 0o555
            && m.len() == source.bytes
            && m.len() > 0
            && m.len() <= 256 << 20
            && custody::identity(&m) == p.file,
        "136 staged worker custody, mode, length or named inode changed"
    );
    let live = format!("/proc/{}/exe", p.pid);
    let mut exe = File::open(&live)?;
    ensure!(
        custody::identity(&exe.metadata()?) == p.file,
        "136 running inode changed"
    );
    let mut cached = VERIFIED
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| anyhow::anyhow!("worker digest cache unavailable"))?;
    let hit = if let Some(c) = cached.as_ref() {
        c.process == *p && c.digest == digest && custody::identity(&c.fd.metadata()?) == p.file
    } else {
        false
    };
    if !hit {
        let mut hash = Sha256::new();
        let mut buf = [0; 64 << 10];
        let mut remaining = p.file.bytes;
        while remaining > 0 {
            let n = buf.len().min(remaining as usize);
            exe.read_exact(&mut buf[..n])?;
            hash.update(&buf[..n]);
            remaining -= n as u64;
        }
        ensure!(
            exe.read(&mut buf[..1])? == 0 && format!("{:x}", hash.finalize()) == digest,
            "136 staged worker digest differs"
        );
    }
    let after = stable::beneath(&dir, &relative, libc::O_RDONLY)?.metadata()?;
    ensure!(
        after.nlink() == 1
            && custody::identity(&after) == p.file
            && custody::identity(&exe.metadata()?) == p.file
            && fs::read_link(&live)? == p.image
            && custody::identity(&fs::metadata(&live)?) == p.file
            && native::ticks(p.pid)? == p.start_ticks,
        "136 matched executable changed"
    );
    if !hit {
        *cached = Some(Verified {
            process: p.clone(),
            digest: digest.into(),
            fd: exe,
        });
    }
    Ok(())
}

#[derive(Debug, Default, Eq, PartialEq, serde::Serialize)]
pub(super) struct Tree {
    pub node: Option<Process>,
    pub worker: Option<Process>,
}

pub(super) fn census(
    members: &BTreeSet<u32>,
    helper: u32,
    group: &str,
    root: &Path,
    node_image: &Path,
    source: &Path,
    digest: &str,
) -> Result<Tree> {
    let original_node = custody::frozen_identity(node_image)?;
    let mut tree = Tree::default();
    for &pid in members.iter().filter(|&&p| p != helper) {
        let image = fs::read_link(format!("/proc/{pid}/exe"))?;
        let m = fs::metadata(format!("/proc/{pid}/exe"))?;
        if m.dev() == original_node.device && m.ino() == original_node.inode {
            let p = replay_process(pid, group)?;
            ensure!(
                tree.node.is_none()
                    && p.parent == helper
                    && p.image == image
                    && p.file == original_node,
                "duplicate, inherited or replaced 136 node"
            );
            tree.node = Some(p);
        } else if image.starts_with(root)
            || image.file_name().is_some_and(|name| {
                let name = name.as_encoded_bytes();
                name.starts_with(b"historical-worker")
                    || name.starts_with(b"jetstreamer-historical-worker")
            })
        {
            let p = replay_process(pid, group)?;
            ensure!(
                tree.worker.is_none() && p.image == image,
                "duplicate or replaced 136 worker"
            );
            verify_worker(root, &p, &custody::frozen_identity(source)?, digest)?;
            tree.worker = Some(p);
        } else {
            // A short-lived helper subprocess is never positive admission.
            return Err(capacity::GuardInFlight.into());
        }
    }
    if let Some(w) = &tree.worker {
        ensure!(
            tree.node
                .as_ref()
                .is_some_and(|n| n.pid == w.parent && n.start_ticks <= w.start_ticks),
            "136 worker not directly descended from admitted node"
        );
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::{PermissionsExt, chown};
    use std::process::Child;

    struct Children(Child);
    impl Drop for Children {
        fn drop(&mut self) {
            // Only the fixture's own process group.
            unsafe { libc::kill(-(self.0.id() as i32), libc::SIGKILL) };
            let _ = self.0.wait();
        }
    }

    #[test]
    fn exact_private_worker_path() {
        let root = Path::new("/test");
        let path = root.join("scratch/.historical-runtime/jetstreamer-historical-parent-ABC123/bound-worker/historical-worker");
        assert!(relative_image(root, &path).is_ok());
        for invalid in [
            "scratch/historical-worker",
            "scratch/private-run/jetstreamer-historical-parent-ABC123/bound-worker/historical-worker",
            "scratch/.historical-runtime/jetstreamer-historical-parent-ABC123/historical-worker",
            "scratch/.historical-runtime/jetstreamer-historical-parent-ABC123/extra/bound-worker/historical-worker",
            "scratch/.historical-runtime/jetstreamer-historical-parent-*/bound-worker/historical-worker",
        ] {
            assert!(relative_image(root, &root.join(invalid)).is_err());
        }
        assert!(relative_image(Path::new("/test-other"), &path).is_err());
    }

    #[test]
    #[ignore = "requires the native replay credentials and normally sealed worker"]
    fn copied_worker_native_tree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("reproduction");
        let bound = root
            .join("scratch/.historical-runtime/jetstreamer-historical-parent-ABC123/bound-worker");
        fs::create_dir_all(&bound).unwrap();
        let node = bound.join("fixture-node");
        fs::copy("/usr/bin/dash", &node).unwrap();
        fs::set_permissions(&node, fs::Permissions::from_mode(0o555)).unwrap();
        let source = temp.path().join("sealed-worker");
        let original =
            Path::new(joint_candidate::BASE136).join("tools/jetstreamer-historical-worker-v1-4-25");
        fs::copy(original, &source).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o555)).unwrap();
        let exe = bound.join("historical-worker");
        fs::copy(&source, &exe).unwrap();
        chown(&exe, Some(1001), Some(1003)).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        // The child works from the opened fixture directory. Its ancestors
        // remain private to this root-owned build.
        let cwd = File::open(&bound).unwrap();
        fs::set_permissions(&bound, fs::Permissions::from_mode(0o711)).unwrap();
        let (worker_input, _keep_input_open) = std::io::pipe().unwrap();
        let mut cmd = Command::new("./fixture-node");
        cmd.args(["-c", "./historical-worker <&7 >/dev/null & echo $!; read -r go; ./historical-worker <&7 >/dev/null & echo $!; wait"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).process_group(0);
        unsafe {
            cmd.pre_exec(move || {
                if libc::fchdir(cwd.as_raw_fd()) != 0
                    || libc::dup2(worker_input.as_raw_fd(), 7) < 0
                    || libc::fcntl(7, libc::F_SETFD, 0) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(1003) != 0
                    || libc::setuid(1001) != 0
                    || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut children = Children(cmd.spawn().unwrap());
        let node_pid = children.0.id();
        let mut pids = BufReader::new(children.0.stdout.take().unwrap()).lines();
        let mut next_worker = || {
            let pid = pids.next().unwrap().unwrap().parse::<u32>().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while fs::read_link(format!("/proc/{pid}/exe")).ok().as_ref() != Some(&exe) {
                assert!(
                    Instant::now() < deadline,
                    "native staged worker failed to exec"
                );
                thread::sleep(Duration::from_millis(10));
            }
            pid
        };
        let worker = next_worker();
        let group = fs::read_to_string("/proc/self/cgroup").unwrap();
        let helper = std::process::id();
        let one = BTreeSet::from([helper, node_pid, worker]);
        let observe = |members: &BTreeSet<u32>, parent: u32, root: &Path, digest: &str| {
            census(members, parent, group.trim(), root, &node, &source, digest)
        };
        let digest = joint_candidate::WORKER;
        let first = observe(&one, helper, &root, digest).unwrap();
        assert_eq!(first.worker.as_ref().unwrap().file.bytes, 12_554_416);
        assert_eq!(observe(&one, helper, &root, digest).unwrap(), first);
        assert!(observe(&one, helper, &root, &"0".repeat(64)).is_err());
        assert!(observe(&one, helper, temp.path(), digest).is_err());
        assert!(observe(&BTreeSet::from([worker]), helper, &root, digest).is_err());
        assert!(
            observe(
                &BTreeSet::from([node_pid, worker]),
                helper + 1,
                &root,
                digest
            )
            .is_err()
        );
        assert!(census(&one, helper, "0::/foreign", &root, &node, &source, digest).is_err());
        writeln!(children.0.stdin.as_mut().unwrap(), "next").unwrap();
        let both = BTreeSet::from([helper, node_pid, worker, next_worker()]);
        assert!(observe(&both, helper, &root, digest).is_err());
        // Even a same-content replacement cannot inherit the running inode.
        fs::rename(&exe, bound.join("replaced")).unwrap();
        fs::copy(&source, &exe).unwrap();
        chown(&exe, Some(1001), Some(1003)).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        assert!(observe(&one, helper, &root, digest).is_err());
        assert!(
            verify_worker(
                &root,
                first.worker.as_ref().unwrap(),
                &custody::frozen_identity(&source).unwrap(),
                digest
            )
            .is_err()
        );
    }
}
