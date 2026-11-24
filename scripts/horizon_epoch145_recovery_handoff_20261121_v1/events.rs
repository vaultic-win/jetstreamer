//! Wait on the original service generation and its files without sampling the fleet.
use super::*;
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::process::Stdio;
const SUCCESS: &str = "7ad2d189f7e94e70a38c781354912448";
const FAILURE: &str = "d9b373ed55a64feb8242e02dbe79a49c";
const STARTING: &str = "7d4958e842da4a758f6c1cdc7b36dcc5";
const STARTED: &str = "39f53479d3a045ac8e11786248231fbf";
const STOPPING: &str = "de5b426a63be47a7b6ac3eaac82e2f6f";
const STOPPED: &str = "9d1aaa27d60140bd96365438aad20286";

fn generation_event(row: &Value, unit: &str, iid: &str) -> Result<bool> {
    ensure!(
        row["_PID"] == "1" && row["UNIT"] == unit && row["INVOCATION_ID"] == iid,
        "foreign manager event"
    );
    if row["MESSAGE_ID"] == SUCCESS {
        return Ok(true);
    }
    ensure!(
        row["MESSAGE_ID"] != STOPPING,
        "original {unit} is stopping through a manager job"
    );
    ensure!(
        row["MESSAGE_ID"] != FAILURE,
        "original {unit} failed: {}",
        row["MESSAGE"]
    );
    Ok(false)
}
pub fn manager(unit: &str, iid: &str) -> Result<Value> {
    manager_exit(unit, iid, true)
}
pub fn manager_exit(unit: &str, iid: &str, success: bool) -> Result<Value> {
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
    if success {
        cmd.arg(format!("MESSAGE_ID={STOPPING}"));
    }
    let mut child = cmd.stdout(Stdio::piped()).spawn()?;
    let result = (|| {
        for line in BufReader::new(child.stdout.take().context("manager event stream")?).lines() {
            let row: Value = serde_json::from_str(&line?)?;
            if !success
                && row["_PID"] == "1"
                && row["UNIT"] == unit
                && row["INVOCATION_ID"] == iid
                && row["MESSAGE_ID"] == FAILURE
            {
                return Ok(row);
            }
            if generation_event(&row, unit, iid)? {
                ensure!(success, "unexpected original success");
                return Ok(row);
            }
        }
        bail!("manager event stream ended");
    })();
    let _ = child.kill();
    child.wait()?;
    result
}

fn explicit_stop(rows: &[Value], unit: &str, iid: &str, boot: &str, after: u64) -> Result<Value> {
    for row in rows {
        ensure!(
            row["_PID"] == "1"
                && row["UNIT"] == unit
                && row["_BOOT_ID"] == boot
                && row["INVOCATION_ID"].as_str().is_some_and(valid_iid)
                && row["__CURSOR"].as_str().is_some_and(|s| !s.is_empty()),
            "foreign manager stop event"
        );
    }
    let terminal = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| {
            row["INVOCATION_ID"] == iid
                && matches!(
                    row["MESSAGE_ID"].as_str(),
                    Some(STOPPING | SUCCESS | FAILURE | STOPPED)
                )
        })
        .collect::<Vec<_>>();
    let [(stop_index, start), (_, deactivated), (_, finish)] = terminal.as_slice() else {
        bail!("expected exactly one manager stop job and a clean deactivation");
    };
    let time = |row: &Value| -> Result<u64> {
        Ok(text(&row["__MONOTONIC_TIMESTAMP"])?.parse()?)
    };
    ensure!(
        start["MESSAGE_ID"] == STOPPING
            && start["JOB_TYPE"] == "stop"
            && deactivated["MESSAGE_ID"] == SUCCESS
            && finish["MESSAGE_ID"] == STOPPED
            && finish["JOB_TYPE"] == "stop"
            && finish["JOB_RESULT"] == "done"
            && time(start)? >= after
            && time(start)? <= time(deactivated)?
            && time(deactivated)? <= time(finish)?
            && start["__CURSOR"] != deactivated["__CURSOR"]
            && deactivated["__CURSOR"] != finish["__CURSOR"]
            && start["__CURSOR"] != finish["__CURSOR"],
        "missing, failed, or stale manager stop"
    );
    ensure!(
        rows[stop_index + 1..]
            .iter()
            .all(|row| !matches!(row["MESSAGE_ID"].as_str(), Some(STARTING | STARTED))),
        "service was started again after the requested stop"
    );
    Ok(json!({"stop_started":start,"deactivated":deactivated,"stop_finished":finish}))
}

pub fn inspect_native_stop(unit: &str, iid: &str, after: u64) -> Result<Value> {
    ensure!(valid_iid(iid) && after > 0, "invalid stop scope");
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .replace('-', "");
    let check_drained = || -> Result<Value> {
        let manager = native(unit)?;
        drained(&manager, unit)?;
        ensure!(
            manager["InvocationID"] == "" || manager["InvocationID"] == iid,
            "a different manager generation owns the stopped name"
        );
        Ok(manager)
    };
    let manager = check_drained()?;
    let query = command(
        Path::new("/usr/bin/journalctl"),
        &[
            "--no-pager",
            "-o",
            "json",
            "--output-fields=_PID,UNIT,INVOCATION_ID,_BOOT_ID,MESSAGE_ID,JOB_TYPE,JOB_RESULT",
            "_PID=1",
            &format!("_BOOT_ID={boot}"),
            &format!("UNIT={unit}"),
            &format!("MESSAGE_ID={STARTING}"),
            &format!("MESSAGE_ID={STARTED}"),
            &format!("MESSAGE_ID={STOPPING}"),
            &format!("MESSAGE_ID={SUCCESS}"),
            &format!("MESSAGE_ID={FAILURE}"),
            &format!("MESSAGE_ID={STOPPED}"),
        ],
    )?;
    let rows = std::str::from_utf8(&query)?
        .lines()
        .map(serde_json::from_str)
        .collect::<serde_json::Result<Vec<Value>>>()?;
    let records = explicit_stop(&rows, unit, iid, &boot, after)?;
    ensure!(
        manager == check_drained()?,
        "service owner changed during stop inspection"
    );
    Ok(json!({
        "schema":"horizon-manager-explicit-stop-witness-v1",
        "unit":unit,"invocation_id":iid,"boot_id":boot,"not_before_monotonic_usec":after,
        "manager":manager,"records":records,"worker_launch_authorized":false
    }))
}
pub(super) fn owned(n: i32) -> Result<OwnedFd> {
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}
pub(super) fn watch(fd: &OwnedFd, path: &Path) -> Result<()> {
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
    started_record(dir, pid, iid, "started.json", "invocation")
}
pub fn started_record(dir: &Path, pid: i32, iid: &str, name: &str, field: &str) -> Result<PathBuf> {
    let parent = dir.parent().context("post directory")?;
    let proc = owned(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32)?;
    let files = owned(unsafe { libc::inotify_init1(libc::IN_CLOEXEC) })?;
    watch(&files, parent)?;
    let path = dir.join(name);
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
                ensure!(v[field] == iid, "crossed owner start");
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
        e["MESSAGE_ID"] = STOPPING.into();
        assert!(generation_event(&e, "original.service", &iid).is_err());
        e["MESSAGE_ID"] = "unrelated".into();
        assert!(!generation_event(&e, "original.service", &iid).unwrap());
    }

    #[test]
    fn explicit_stop_requires_the_exact_ordered_generation() {
        let iid = "a".repeat(32);
        let boot = "b".repeat(32);
        let unit = "original.service";
        let entry = |time: u64, message_id: &str| {
            json!({"_PID":"1","UNIT":unit,"INVOCATION_ID":iid,"_BOOT_ID":boot,
                "MESSAGE_ID":message_id,"__MONOTONIC_TIMESTAMP":time.to_string(),
                "__CURSOR":format!("cursor-{time}")})
        };
        let mut rows = [entry(10, STOPPING), entry(11, SUCCESS), entry(12, STOPPED)];
        rows[0]["JOB_TYPE"] = "stop".into();
        rows[2]["JOB_TYPE"] = "stop".into();
        rows[2]["JOB_RESULT"] = "done".into();
        assert!(explicit_stop(&rows, unit, &iid, &boot, 10).is_ok());
        assert!(explicit_stop(&rows[1..2], unit, &iid, &boot, 10).is_err());
        assert!(explicit_stop(&rows, unit, &iid, &boot, 11).is_err());
        assert!(explicit_stop(&rows, unit, &iid, &"c".repeat(32), 10).is_err());
        let mut superseded = rows.to_vec();
        let mut later = entry(13, STARTING);
        later["INVOCATION_ID"] = "d".repeat(32).into();
        superseded.push(later);
        assert!(explicit_stop(&superseded, unit, &iid, &boot, 10).is_err());
        rows.swap(1, 2);
        assert!(explicit_stop(&rows, unit, &iid, &boot, 10).is_err());
        rows.swap(1, 2);
        rows[2]["JOB_RESULT"] = "failed".into();
        assert!(explicit_stop(&rows, unit, &iid, &boot, 10).is_err());
    }

    #[test]
    #[ignore = "requires an isolated PID 1 stop fixture from this boot"]
    fn native_explicit_stop_is_distinct_from_recovery_success() {
        let unit = std::env::var("HANDOFF_STOP_UNIT").unwrap();
        let iid = std::env::var("HANDOFF_STOP_IID").unwrap();
        let after = std::env::var("HANDOFF_STOP_AFTER").unwrap().parse().unwrap();
        let witness = inspect_native_stop(&unit, &iid, after).unwrap();
        assert_eq!(witness["records"]["stop_finished"]["JOB_RESULT"], "done");
        assert_eq!(
            manager(&unit, &iid).unwrap_err().to_string(),
            format!("original {unit} is stopping through a manager job")
        );
        let natural_unit = std::env::var("HANDOFF_NATURAL_UNIT").unwrap();
        let natural_iid = std::env::var("HANDOFF_NATURAL_IID").unwrap();
        let natural_after = std::env::var("HANDOFF_NATURAL_AFTER").unwrap().parse().unwrap();
        assert_eq!(
            manager(&natural_unit, &natural_iid).unwrap()["MESSAGE_ID"],
            SUCCESS
        );
        assert!(inspect_native_stop(&natural_unit, &natural_iid, natural_after).is_err());
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
