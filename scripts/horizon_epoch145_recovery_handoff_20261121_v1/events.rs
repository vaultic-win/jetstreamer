//! Wait on the original service generation and its files without sampling the fleet.
use super::*;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::Stdio;
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const FAILURE: &str = "d9b373ed55a64feb8242e02dbe79a49c";
fn generation_event(row: &Value, unit: &str, iid: &str) -> Result<bool> {
    ensure!(
        row["_PID"] == "1" && row["UNIT"] == unit && row["INVOCATION_ID"] == iid,
        "foreign manager event"
    );
    if row["MESSAGE_ID"] == SUCCESS {
        return Ok(true);
    }
    ensure!(
        row["MESSAGE_ID"] != FAILURE,
        "original {unit} failed: {}",
        row["MESSAGE"]
    );
    Ok(false)
}
pub fn manager(unit: &str, iid: &str) -> Result<Value> {
    ensure!(valid_iid(iid), "invalid invocation");
    let mut cmd = Command::new("/usr/bin/journalctl");
    cmd.args([
        "--no-pager",
        "-b",
        "--follow",
        "-n",
        "all",
        "-o",
        "json",
        "--output-fields=_PID,UNIT,INVOCATION_ID,MESSAGE_ID,MESSAGE",
        "_PID=1",
        &format!("UNIT={unit}"),
        &format!("INVOCATION_ID={iid}"),
        &format!("MESSAGE_ID={SUCCESS}"),
        &format!("MESSAGE_ID={FAILURE}"),
    ]);
    let mut child = cmd.stdout(Stdio::piped()).spawn()?;
    let result = (|| {
        for line in BufReader::new(child.stdout.take().context("manager event stream")?).lines() {
            let row: Value = serde_json::from_str(&line?)?;
            if generation_event(&row, unit, iid)? {
                return Ok(row);
            }
        }
        bail!("manager event stream ended");
    })();
    let _ = child.kill();
    child.wait()?;
    result
}
fn owned(n: i32) -> Result<OwnedFd> {
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}
fn watch(fd: &OwnedFd, path: &Path) -> Result<()> {
    let p = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    ensure!(
        unsafe {
            libc::inotify_add_watch(
                fd.as_raw_fd(),
                p.as_ptr(),
                libc::IN_CREATE | libc::IN_CLOSE_WRITE | libc::IN_MOVED_TO | libc::IN_DELETE_SELF,
            )
        } >= 0,
        "watch {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}
pub fn started(dir: &Path, pid: i32, iid: &str) -> Result<PathBuf> {
    let parent = dir.parent().context("post directory")?;
    let proc = owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32)?;
    let files = owned(unsafe { libc::inotify_init1(libc::IN_CLOEXEC) })?;
    watch(&files, parent)?;
    let path = dir.join("started.json");
    let mut watching = false;
    loop {
        if !watching && dir.try_exists()? {
            watch(&files, dir)?;
            watching = true;
        }
        if path.try_exists()? {
            // The producer atomically publishes via create_new/write/fsync. Its final
            // CLOSE_WRITE event can follow the first directory entry notification.
            if let Ok(v) =
                platform::read(&path).and_then(|b| Ok(serde_json::from_slice::<Value>(&b)?))
            {
                ensure!(v["invocation"] == iid, "crossed post start");
                return Ok(path);
            }
        }
        let mut fds = [
            libc::pollfd {
                fd: files.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: proc.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if rc < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            rc > 0 && fds[1].revents == 0,
            "post owner exited before an eligible start"
        );
        let mut buf = [0u8; 8192];
        ensure!(
            unsafe { libc::read(files.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) } > 0,
            "post event read"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_original_successful_manager_event_can_advance() {
        let mut e = json!({"_PID":"1","UNIT":"original.service","INVOCATION_ID":"a".repeat(32),"MESSAGE_ID":SUCCESS});
        let iid = "a".repeat(32);
        assert!(generation_event(&e, "original.service", &iid).unwrap());
        assert!(generation_event(&e, "foreign.service", &iid).is_err());
        e["MESSAGE_ID"] = FAILURE.into();
        assert!(generation_event(&e, "original.service", &iid).is_err());
        e["MESSAGE_ID"] = "unrelated".into();
        assert!(!generation_event(&e, "original.service", &iid).unwrap());
    }
    #[test]
    #[ignore = "requires PID 1 evidence and a root-owned HOME fixture"]
    fn native_events_watch_an_original_manager_and_published_file() {
        let event = manager(W, "f5691c8b17a746d99935282a88509a43").unwrap();
        assert!(generation_event(&event, W, "f5691c8b17a746d99935282a88509a43").unwrap());
        let dir = PathBuf::from(std::env::var("HANDOFF_PRIVATE_FIXTURE").unwrap()).join("post");
        let writer = dir.clone();
        let iid = "a".repeat(32);
        let id = iid.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(70));
            fs::create_dir(&writer).unwrap();
            platform::save(&writer.join("started.json"), &json!({"invocation":id})).unwrap();
        });
        let p = started(&dir, std::process::id() as i32, &iid).unwrap();
        thread.join().unwrap();
        assert_eq!(p, dir.join("started.json"));
        assert!(started(&dir, std::process::id() as i32, &"b".repeat(32)).is_err());
    }
}
