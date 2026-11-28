//! Switch the one serialized audit owner only at the observed clean epoch boundary.
mod common;
use anyhow::{Context, Result, ensure};
use common::*;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
const INCUMBENT: &str = "7204441a3de34846a079875d564838dc";
const PID: i32 = 2464769;
const OLD: &str = "408703e0c58c738a55d30742e01e348e3720a1ec62357f555dbc887926de7435";
const CFG: &str = "5d7d09bfb1ffdb08ac5aa04b228e9cd3827a6ef3bbb700723d7b777d2261e177";
const FAILURE: &str = "d05c0f397a4b4c96a16454869bb0834135735a931136ee9a0ce3ba88393daa9c";
const INVENTORY: &str = "d38d5146d50b7788cf5866fa0f7f5aeefade92fbf0496398fee334b480b7084e";
const PREVIOUS_DROPIN: &str = "ca2ceb37eb130d1a8daabab5af275f498a2962b671e865ad25612412ead616e1";
fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unchanged_owner(n: &BTreeMap<String, String>) -> Result<()> {
    for (k, v) in [
        ("InvocationID", INCUMBENT),
        ("MainPID", "2464769"),
        (
            "ControlGroup",
            "/system.slice/horizon-r2-chronological-plugin-audit-20261118-v1.service",
        ),
        ("SubState", "running"),
        ("NRestarts", "0"),
        ("Job", ""),
        ("MemoryMax", "25769803776"),
        ("MemorySwapMax", "0"),
        ("TasksMax", "512"),
        ("CPUQuotaPerSecUSec", "4s"),
    ] {
        ensure!(n.get(k).is_some_and(|s| s == v), "incumbent {k} differs");
    }
    ensure!(
        sha(Path::new("/proc/2464769/exe"))? == OLD,
        "incumbent executable differs"
    );
    Ok(())
}
fn verify_result(result: &Value, cleanup: &Value, epoch: u64, attempt: &Path) -> Result<()> {
    let play = &result["playback"];
    let dl = &result["download"];
    ensure!(
        result["epoch"] == epoch
            && result["attempt"] == attempt.to_string_lossy().as_ref()
            && result["status"] == "passed"
            && result["remote_mutations"] == false
            && dl["object"] == result["object"]
            && dl["bytes"].as_u64().is_some_and(|n| n > 0)
            && dl["bytes"] == result["object"]["bytes"]
            && dl["sha256"].as_str().is_some_and(|s| hex(s, 64))
            && play["epoch"] == epoch
            && play["first_slot"] == epoch * 432000
            && play["last_slot"] == (epoch + 1) * 432000 - 1
            && play["counters"]["slots"] == 432000
            && play["clean_process_exit"] == true
            && result["invocation"]
                .as_array()
                .is_some_and(|r| !r.is_empty())
            && cleanup["epoch"] == epoch
            && cleanup["removed_only_owned_audit_copy"] == true,
        "epoch {epoch} full verification/cleanup incomplete"
    );
    Ok(())
}
fn check_clean(
    state: &Path,
    n: &BTreeMap<String, String>,
    epoch: u64,
    attempt: &Path,
) -> Result<Value> {
    let result = state.join(format!("results/epoch-{epoch}.json"));
    let cleanup = attempt.join("cleanup.json");
    let got = read(&result)?;
    verify_result(&got, &read(&cleanup)?, epoch, attempt)?;
    let proof = Path::new(
        got["playback"]["native_report_path"]
            .as_str()
            .context("native report")?,
    );
    ensure!(
        proof.parent() == Some(attempt) && got["playback"]["native_report_sha256"] == sha(proof)?,
        "native report binding"
    );
    let cg = Path::new("/sys/fs/cgroup").join(n["ControlGroup"].trim_start_matches('/'));
    ensure!(
        fs::read_to_string(cg.join("cgroup.events"))?
            .lines()
            .any(|s| s == "frozen 1")
            && fs::read_to_string(cg.join("cgroup.procs"))?.trim() == PID.to_string(),
        "old owner not frozen alone"
    );
    for name in [
        "scratch-owner.json",
        "results/epoch-90.retry-1.intent.json",
        "results/epoch-90.retry-1.json",
    ] {
        ensure!(
            !state.join(name).try_exists()?,
            "next audit transfer/repair already started"
        );
    }
    ensure!(
        fs::read_dir(state.join("scratch"))?.next().is_none(),
        "next audit transfer owns scratch"
    );
    let progress = read(&state.join("progress.json"))?;
    ensure!(
        progress["pid"] == PID && progress["epoch"] == epoch,
        "missed selected epoch handoff"
    );
    Ok(
        json!({"result":result,"result_sha256":sha(&result)?,"cleanup":cleanup,"cleanup_sha256":sha(&cleanup)?,"native_report":proof,"native_report_sha256":sha(proof)?,"old_owner":n,"clean_epoch":epoch}),
    )
}
fn deployment(image: &str, seal_sha: &str, source: &str) -> Result<PathBuf> {
    ensure!(
        hex(image, 64) && hex(seal_sha, 64) && hex(source, 40) && image != OLD,
        "supply exact new image, seal and merged commit"
    );
    let rt = Path::new(ROOT).join("runtime-v11");
    let seal = rt.join("deployment-seal-receipt.json");
    ensure!(
        sha(&seal)? == seal_sha
            && sha(&rt.join("audit"))? == image
            && sha(&rt.join("config.json"))? == CFG,
        "successor hashes"
    );
    let s = read(&seal)?;
    ensure!(
        s["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && s["destination"] == rt.to_string_lossy().as_ref()
            && s["remote_mutations"] == false
            && s["sealer_sha256"]
                == "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3",
        "successor seal"
    );
    let proof = rt.join("artifact-proof.json");
    for (name, hash, mode) in [
        ("audit", image.to_owned(), "0555"),
        ("config.json", CFG.to_owned(), "0444"),
        ("artifact-proof.json", sha(&proof)?, "0444"),
    ] {
        let r: Vec<_> = s["members"]
            .as_array()
            .context("members")?
            .iter()
            .filter(|row| row["name"] == name)
            .collect();
        ensure!(
            r.len() == 1 && r[0]["sha256"] == hash && r[0]["mode"] == mode,
            "sealed {name}"
        );
    }
    let b = read(&proof)?;
    ensure!(
        b["git"] == source
            && b["artifact_sha256"] == image
            && b["predecessor_terminal"] == FAILURE
            && b["full_playback_required"] == true,
        "new source or proof differs"
    );
    run(
        "/usr/bin/git",
        &[
            "--no-replace-objects",
            "-c",
            "safe.directory=/home/sol/workspace/jetstreamer",
            "-C",
            "/home/sol/workspace/jetstreamer",
            "merge-base",
            "--is-ancestor",
            source,
            "refs/remotes/origin/account-updates",
        ],
    )?;
    let state = Path::new(STATE);
    ensure!(
        sha(&state.join("results/epoch-90.json"))? == FAILURE
            && sha(&state.join("inventory.json"))? == INVENTORY,
        "frozen original differs"
    );
    let status: Value = serde_json::from_str(&run(
        rt.join("audit").to_str().unwrap(),
        &["status", rt.join("config.json").to_str().unwrap()],
    )?)?;
    ensure!(
        status["summary"]["archives"] == 225 && status["summary"]["transfer_retries_pending"] == 1,
        "new selector did not find one repair"
    );
    Ok(rt)
}
// Arm the watch before checking existence. An old, already-passed boundary is
// harmless: check_clean rechecks scratch, native tasks and epoch while frozen.
fn await_cleanup(attempt: &Path, limit: Duration) -> Result<()> {
    use std::ffi::CString;
    use std::io::Read;
    use std::os::{fd::FromRawFd, unix::ffi::OsStrExt};
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut events = unsafe { fs::File::from_raw_fd(fd) };
    let path = CString::new(attempt.as_os_str().as_bytes())?;
    let wd = unsafe {
        libc::inotify_add_watch(
            fd,
            path.as_ptr(),
            libc::IN_CREATE
                | libc::IN_CLOSE_WRITE
                | libc::IN_MOVED_TO
                | libc::IN_DELETE_SELF
                | libc::IN_MOVE_SELF,
        )
    };
    if wd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let until = Instant::now() + limit;
    let file = attempt.join("cleanup.json");
    let mut buf = [0u8; 8192];
    loop {
        if file.try_exists()? {
            return Ok(());
        }
        ensure!(attempt.is_dir(), "selected attempt disappeared");
        let ms = until
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut p = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut p, 1, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e.into());
        }
        ensure!(
            rc > 0,
            "selected cleanup did not arrive within the bounded handoff watch"
        );
        ensure!(
            p.revents == libc::POLLIN && events.read(&mut buf)? > 0,
            "invalid cleanup notification"
        );
    }
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        a.len() == 6 && matches!(a[0].as_str(), "check" | "switch" | "watch"),
        "handoff90 check|switch|watch IMAGE_SHA SEAL_SHA SOURCE_COMMIT AFTER_EPOCH ATTEMPT_BASENAME"
    );
    let e: u64 = a[4].parse()?;
    ensure!(
        e >= 91
            && read(&Path::new(STATE).join("inventory.json"))?["objects"]
                .as_array()
                .context("inventory objects")?
                .iter()
                .any(|obj| obj["epoch"] == e)
            && a[5]
                .strip_prefix(&format!("epoch-{e}-"))
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())),
        "invalid clean boundary"
    );
    let rt = deployment(&a[1], &a[2], &a[3])?;
    unchanged_owner(&native()?)?;
    let state = Path::new(STATE);
    let attempt = state.join("attempts").join(&a[5]);
    ensure!(
        attempt.canonicalize()? == attempt && read(&attempt.join("started.json"))?["epoch"] == e,
        "wrong incumbent attempt"
    );
    let previous = Path::new(CFG_DIR).join("96-epoch79-range-recovery.conf");
    ensure!(
        sha(&previous)? == PREVIOUS_DROPIN,
        "previous drop-in differs"
    );
    let text = fs::read_to_string(previous)?;
    ensure!(
        text.matches("runtime-v10").count() == 5,
        "drop-in references changed"
    );
    let next = text.replace("runtime-v10", "runtime-v11");
    if a[0] == "check" {
        println!("Validated incumbent, sealed successor and one eligible repair");
        return Ok(());
    }
    let switch = Path::new(ROOT).join("range-v11-transition");
    let lock = fs::File::open(&switch)?;
    ensure!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent handoff"
    );
    let dropin = Path::new(CFG_DIR).join("97-epoch90-range-recovery.conf");
    ensure!(
        !dropin.try_exists()? && !switch.join("STOP_INTENT.json").try_exists()?,
        "handoff already attempted"
    );
    if a[0] == "watch" {
        await_cleanup(&attempt, Duration::from_secs(48 * 3600))?;
    }
    // A missed inotify/.path delivery must never interrupt an active download.
    ensure!(
        attempt.join("cleanup.json").try_exists()?
            && !state.join("scratch-owner.json").try_exists()?,
        "selected cleanup boundary not idle"
    );
    let before = native()?;
    unchanged_owner(&before)?;
    ensure!(
        before["FreezerState"] == "running",
        "incumbent freeze belongs to another owner"
    );
    let thaw = Frozen;
    run("systemctl", &["freeze", UNIT])?;
    let n = native()?;
    unchanged_owner(&n)?;
    let clean = check_clean(state, &n, e, &attempt)?;
    let intent = json!({"verified_clean_boundary":clean,"old_image":OLD,"next_image":a[1],"next_seal":a[2],"required_source":a[3],"frozen_inventory":INVENTORY,"epoch90_original":FAILURE});
    durable(
        &switch.join("STOP_INTENT.json"),
        &serde_json::to_vec_pretty(&intent)?,
    )?;
    durable(&dropin, next.as_bytes())?;
    run("systemctl", &["daemon-reload"])?;
    ensure!(
        unsafe { libc::kill(PID, libc::SIGTERM) } == 0,
        "signal validated frozen incumbent"
    );
    drop(thaw);
    run("systemctl", &["stop", UNIT])?;
    let stopped = native()?;
    ensure!(stopped["MainPID"] == "0", "old owner remains");
    durable(
        &switch.join("STOPPED.json"),
        &serde_json::to_vec_pretty(&stopped)?,
    )?;
    run("systemctl", &["start", UNIT])?;
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let s = native()?;
        if s["InvocationID"] != INCUMBENT
            && hex(&s["InvocationID"], 32)
            && s["SubState"] == "running"
            && s["NRestarts"] == "0"
            && s["MainPID"].parse::<u32>().is_ok_and(|p| p > 1)
        {
            let exe = PathBuf::from(format!("/proc/{}/exe", s["MainPID"]));
            if fs::read_link(&exe).is_ok_and(|p| p == rt.join("audit")) && sha(&exe)? == a[1] {
                // The previous handoff left a stale manager freezer flag on the successor.
                run("systemctl", &["thaw", UNIT])?;
                let end = native()?;
                ensure!(
                    end["InvocationID"] == s["InvocationID"]
                        && end["MainPID"] == s["MainPID"]
                        && end["FreezerState"] == "running"
                        && [
                            "ControlGroup",
                            "MemoryMax",
                            "MemorySwapMax",
                            "CPUQuotaPerSecUSec",
                            "TasksMax",
                            "NRestarts"
                        ]
                        .iter()
                        .all(|k| end[*k] == before[*k])
                        && fs::read_to_string(
                            Path::new("/sys/fs/cgroup")
                                .join(end["ControlGroup"].trim_start_matches('/'))
                                .join("cgroup.events")
                        )?
                        .lines()
                        .any(|line| line == "frozen 0"),
                    "successor native freezer/identity"
                );
                durable(
                    &switch.join("STARTED.json"),
                    &serde_json::to_vec_pretty(&end)?,
                )?;
                return Ok(());
            }
        }
        ensure!(
            Instant::now() < until,
            "capture actual successor separately; inspect existing owner before recovery"
        );
        thread::sleep(Duration::from_millis(150));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prearmed_and_preexisting_cleanup_are_both_detected() {
        let parent = std::env::temp_dir().join(format!("audit90-notify-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let q = parent.clone();
        let task = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            fs::write(q.join(".tmp"), b"{}").unwrap();
            fs::rename(q.join(".tmp"), q.join("cleanup.json")).unwrap();
        });
        await_cleanup(&parent, Duration::from_secs(2)).unwrap();
        task.join().unwrap();
        await_cleanup(&parent, Duration::from_millis(1)).unwrap();
        fs::remove_file(parent.join("cleanup.json")).unwrap();
        assert!(await_cleanup(&parent, Duration::from_millis(10)).is_err());
        fs::remove_dir(parent).unwrap();
    }
    #[test]
    #[ignore = "read-only host evidence from completed epoch 89"]
    fn genuine_full_plugin_receipt_and_cleanup() {
        let state = Path::new(STATE);
        let r = read(&state.join("results/epoch-89.json")).unwrap();
        let a = Path::new(r["attempt"].as_str().unwrap());
        verify_result(&r, &read(&a.join("cleanup.json")).unwrap(), 89, a).unwrap();
    }
    #[test]
    fn boundary_rejects_truncation_wrong_attempt_or_missing_cleanup() {
        let p = Path::new("/local/attempt");
        let e = 91;
        let obj = json!({"epoch":e,"bytes":17});
        let r = json!({"epoch":e,"attempt":p,"status":"passed","object":obj,"remote_mutations":false,"download":{"object":obj,"bytes":17,"sha256":"a".repeat(64)},"playback":{"epoch":e,"first_slot":39312000,"last_slot":39743999,"counters":{"slots":432000},"clean_process_exit":true},"invocation":["plugin"]});
        let c = json!({"epoch":91,"removed_only_owned_audit_copy":true});
        verify_result(&r, &c, e, p).unwrap();
        for (path, bad) in [
            ("/playback/last_slot", json!(39743998)),
            ("/download/bytes", json!(16)),
            ("/attempt", json!("/foreign")),
            ("/playback/clean_process_exit", json!(false)),
            ("/invocation", json!([])),
        ] {
            let mut rr = r.clone();
            *rr.pointer_mut(path).unwrap() = bad;
            assert!(verify_result(&rr, &c, e, p).is_err());
        }
        assert!(verify_result(&r, &Value::Null, e, p).is_err());
    }
}
