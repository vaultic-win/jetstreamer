//! A path-activated handoff for the original paid 145 inode. Its two possible
//! terminal markers are emitted before the original worker's service exits.
use super::*;
use std::os::fd::AsRawFd;
const BOOT: &str = "763ea84c-a81f-4ddd-ad36-4b1ea2ba36dd";
const REG: &str = "epoch166-post168-cadence-20261121-v1";
const PARENT_SEAL: &str = "fa2629cdaa5e9ed89bebc905108bc07366b4b3b95e4ea4bb2afc2c53aa8c515a";
const CONT: &str = "epoch145-semantic-continuity-20261121-v1/tools-v3";
const CONT_SEAL: &str = "e048a2694aebe57fd9018fd9cc22fd3047c397102efa394c1fa7f589be29ac53";
const JOINT: &str = "epoch145-recovery-handoff-20261121-v1/tools";
const JOINT_SEAL: &str = "fea45afb2023968c089bda02f4da811a410fab0ddca51f4bbd0b0519eb295b1a";
const AUDIT: &str = "7879aafbf64134e61971aca3c0e51aed4ee39f7c59170f8e3e4f1a3d713c83ac";
const FLEET: &str = "ROOT_COMPLETE_OPERATIONAL_FLEET.json";
const T166: &str = "epoch166-terminal-20261121-v1/TERMINAL_SUCCESS.json";
fn original(iid: &str) -> PathBuf {
    rt("epoch145-guarded-export-20261121-v1/state").join(iid)
}
fn boot() -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "different boot; original native owners must be requalified"
    );
    Ok(())
}
pub(super) fn next(f: &Value) -> Result<PathBuf> {
    let name = f["sole_next_timer"]
        .as_str()
        .or_else(|| f["sole_next_timer"]["unit"].as_str())
        .context("missing successor timer")?
        .strip_prefix("horizon-observer-")
        .and_then(|n| n.strip_suffix(".timer"))
        .context("foreign cadence timer")?;
    ensure!(
        name.starts_with("root") && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
        "foreign cycle directory"
    );
    Ok(rt(name).join(FLEET))
}
fn accepted(f: &Value) -> Result<()> {
    let r = from_ref(&f["authenticated_status_audit"])?;
    ensure!(
        f["owner"] == "/root"
            && f["all_reservation_ending_bytes"] == 0
            && f["all_active_status_reports_authenticated_readback"] == true
            && r["schema"] == "horizon-status-full-range-audit-v1"
            && r["owner"] == "/root"
            && r["authenticated_readback"] == true
            && r["all_nineteen_existing_statuses_authenticated"] == true
            && r["authenticated_status_count"] == 19
            && r["receipts"] == f["effective_status_receipts"]
            && r["fleet_predecessor"] == f["previous_Root_operational_review"]
            && r["sampled_at_utc"] == f["sampled_at_utc"]
            && r["observer"] == f["observer"],
        "unaccepted status fleet"
    );
    let entries = r["receipts"].as_object().context("status receipts")?;
    ensure!(entries.len() == 19, "incomplete status table");
    for (epoch, reference) in entries {
        let s = from_ref(reference)?;
        ensure!(
            s["authenticated_readback"] == true
                && s["epoch"] == json!(epoch.parse::<u64>()?)
                && s["sampled_at_utc"] == r["sampled_at_utc"],
            "invalid status readback"
        );
    }
    Ok(())
}
fn seed() -> Value {
    json!({"path":rt("root101959-live166167170-20261121-v1").join(FLEET),"sha256":AUDIT})
}
/// Walk only committed, hash-linked scheduled successors, then ask the actual
/// sole publisher's sealed parent to independently validate the selected head.
fn head(mut at: Value, parent: &Path) -> Result<(Value, Value)> {
    loop {
        let f = from_ref(&at)?;
        let p = next(&f)?;
        if p.try_exists()? {
            let n = bound(&p)?;
            ensure!(
                from_ref(&n)?["previous_Root_operational_review"] == at,
                "divergent cadence"
            );
            at = n;
        } else {
            let proof: Value = serde_json::from_slice(&command(
                parent,
                &["inspect-status", text(&at["path"])?, text(&at["sha256"])?],
            )?)?;
            if proof["fleet"] != at {
                continue;
            }
            accepted(&f)?;
            return Ok((at, f));
        }
    }
}
pub(super) fn wait_file(path: &Path) -> Result<()> {
    // The next cycle's directory may still be absent. Watch its existing
    // parent first and recheck after watch installation to close both races.
    while !path.try_exists()? {
        let parent = path.parent().context("event parent")?;
        let fd = events::owned(unsafe { libc::inotify_init1(libc::IN_CLOEXEC) })?;
        let exists = parent.try_exists()?;
        events::watch(
            &fd,
            if exists {
                parent
            } else {
                parent.parent().context("event grandparent")?
            },
        )?;
        if path.try_exists()? || (!exists && parent.try_exists()?) {
            continue;
        }
        let mut buf = [0u8; 8192];
        let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(n > 0, "lost file notification for {}", path.display());
    }
    Ok(())
}
fn exit_one(unit: &str, iid: &str) -> Result<Value> {
    let rows = platform::output(
        "/usr/bin/journalctl",
        &[
            "-b",
            "--no-pager",
            "-ojson",
            "--output-fields=_PID,_BOOT_ID,UNIT,INVOCATION_ID,MESSAGE_ID,EXIT_CODE,EXIT_STATUS",
            "_PID=1",
            &format!("UNIT={unit}"),
            &format!("INVOCATION_ID={iid}"),
            "MESSAGE_ID=98e322203f7a4ed290d09fe03c09fe15",
        ],
    )?;
    let mut rows = rows
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == 1, "expected one exit-status event");
    let v = rows.pop().unwrap();
    ensure!(
        v["_PID"] == "1"
            && v["_BOOT_ID"] == BOOT.replace('-', "")
            && v["UNIT"] == unit
            && v["INVOCATION_ID"] == iid
            && v["EXIT_CODE"] == "exited"
            && v["EXIT_STATUS"] == "1",
        "foreign native failure"
    );
    Ok(v)
}
fn failure(dir: &Path, iid: &str) -> Result<Value> {
    let r = bound(&dir.join("failed.json"))?;
    let v = from_ref(&r)?;
    ensure!(
        v["iid"] == iid
            && v["error"].as_str().is_some_and(|s| !s.is_empty())
            && !dir.join("complete.json").try_exists()?,
        "invalid recovery failure"
    );
    Ok(r)
}
fn clear_original_failure(v: &Value) -> Result<()> {
    if v["ActiveState"] == "failed" {
        ensure!(
            v["InvocationID"] == REC
                && v["MainPID"] == "0"
                && v["SubState"] == "failed"
                && v["Job"] == ""
                && platform::group_members(&format!("/system.slice/{E}"))?.is_empty(),
            "fixed-name failure still owns tasks or changed generation"
        );
        ensure!(
            platform::ticks(3738161).ok() != Some(359708608)
                && platform::ticks(3751536).ok() != Some(359803826),
            "original verifier still owns the frozen inode"
        );
        // Failed transient units stay loaded. Clear this exact completed
        // generation after preserving its evidence so PID 1 can reuse the name.
        platform::ctl(&["reset-failed", E])?;
    }
    drained(&native(E)?, E)
}
fn arguments(pid: i32) -> Result<Vec<String>> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
    bytes
        .strip_suffix(&[0])
        .context("unterminated argv")?
        .split(|b| *b == 0)
        .map(|a| Ok(std::str::from_utf8(a)?.to_owned()))
        .collect()
}
fn continuation(
    state: &Path,
    start: &Value,
    evidence: &Value,
    parent: &Path,
    failed: bool,
) -> Result<()> {
    let mode = if failed {
        "recover-full-output"
    } else {
        "post-full"
    };
    let launch = check_member(&rt(CONT), CONT_SEAL, "run-recovery")?;
    let image = check_member(&rt(CONT), CONT_SEAL, "export145")?;
    let terminal = rt(T166);
    wait_file(&terminal)?;
    let marker = bound(&terminal)?;
    let mut cursor = start.clone();
    let (fleet, f) = loop {
        let (current, f) = head(cursor, parent)?;
        if !f["terminal166_local_commit"].is_null() {
            ensure!(
                f["terminal166_local_commit"] == marker,
                "foreign terminal166 reference"
            );
            break (current, f);
        }
        wait_file(&next(&f)?)?;
        cursor = current;
    };
    let intent_path = state.join("continuity-submission.json");
    let now = native(E)?;
    if !intent_path.try_exists()? {
        clear_original_failure(&now)?;
        platform::save(
            &intent_path,
            &json!({"original":REC,"source_event":evidence,"mode":mode,"terminal166":marker,"fleet":fleet,"status_report":f["authenticated_status_audit"],"launcher":bound(&launch)?,"image":bound(&image)?}),
        )?;
        command(&launch, &[mode, text(&fleet["path"])?])?;
    }
    let intent = from_ref(&bound(&intent_path)?)?;
    ensure!(
        intent["original"] == REC
            && intent["source_event"] == *evidence
            && intent["terminal166"] == marker
            && intent["mode"] == mode
            && intent["image"] == bound(&image)?
            && intent["launcher"] == bound(&launch)?,
        "different prior submission intent"
    );
    let prior = &intent["fleet"];
    let of = from_ref(prior)?;
    accepted(&of)?;
    ensure!(
        of["terminal166_local_commit"] == marker
            && of["authenticated_status_audit"] == intent["status_report"],
        "unbound submitted fleet"
    );
    let (pid, iid) = stable(&native(E)?, E)?;
    let image_sha = text(&intent["image"]["sha256"])?;
    ensure!(
        iid != REC
            && platform::proc_exe(pid)? == image
            && arguments(pid)?
                == [
                    platform::string_path(&image)?,
                    mode,
                    text(&prior["path"])?,
                    text(&prior["sha256"])?,
                    image_sha
                ],
        "ambiguous submission; reconcile original intent"
    );
    let args = if failed {
        (original(&iid), "recovery-started.json", "iid")
    } else {
        (
            rt("epoch145-publication-20261121-v1").join(format!("full-{iid}")),
            "started.json",
            "invocation",
        )
    };
    let path = events::started_record(&args.0, pid, &iid, args.1, args.2)?;
    let reference = bound(&path)?;
    let started = from_ref(&reference)?;
    if failed {
        ensure!(
            started["prior_frozen_recovery"]["verified_predecessor_failure"]["failure"]
                == evidence["marker"]
                && started["image"] == image_sha
                && started["r2_mutations"] == false
                && started["fresh_fit"].is_object()
                && started["initial"].is_object(),
            "missing native protected recovery"
        );
    } else {
        ensure!(
            started["completion"] == evidence["marker"]
                && started["fleet"] == *prior
                && started["initial"].is_object(),
            "unbound post-full"
        );
    }
    platform::save(
        &state.join("continuity-started.json"),
        &json!({"invocation":iid,"pid":pid,"ticks":platform::ticks(pid)?,"started":reference,"intent":bound(&intent_path)?}),
    )?;
    Ok(())
}
pub fn run(mode: &str) -> Result<()> {
    ensure!(
        matches!(mode, "inspect-outcome" | "route-outcome"),
        "unknown outcome action"
    );
    boot()?;
    let dir = original(REC);
    let success = dir.join("complete.json").try_exists()?;
    let failed = dir.join("failed.json").try_exists()?;
    ensure!(!(success && failed), "conflicting original outcomes");
    let pkg = rt(REG).join("parent-package");
    let parent = check_member(&pkg, PARENT_SEAL, "parent136")?;
    let handoff = check_member(&rt(JOINT), JOINT_SEAL, "follow145")?;
    check_member(&rt(CONT), CONT_SEAL, "run-recovery")?;
    if mode == "inspect-outcome" {
        let (f, _) = head(seed(), &parent)?;
        println!(
            "{}",
            json!({"complete":success,"failed":failed,"fleet":f,"native":native(E)?,"launch":false})
        );
        return Ok(());
    }
    ensure!(success || failed, "no original outcome");
    let state = rt("epoch145-recovery-handoff-20261121-v1/outcome-state");
    let _lock = guard_instance(&state)?;
    if state.join("continuity-started.json").try_exists()?
        || rt(STATE).join("136-dispatched.json").try_exists()?
    {
        return Ok(());
    }
    let manager = events::manager_exit(E, REC, success)?;
    let source = if failed {
        json!({"marker":failure(&dir,REC)?,"manager":manager,"exit":exit_one(E,REC)?})
    } else {
        json!({"marker":completed()?,"manager":manager})
    };
    let (f, doc) = head(seed(), &parent)?;
    if success && !rt(T166).try_exists()? && original_peers(&doc).is_ok() {
        command(
            &handoff,
            &[
                "follow",
                text(&f["path"])?,
                text(&f["sha256"])?,
                platform::string_path(&pkg)?,
                PARENT_SEAL,
            ],
        )?;
        Ok(())
    } else {
        continuation(&state, &f, &source, &parent, failed)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cadence_names_cannot_escape() {
        for t in [
            "x",
            "horizon-observer-root/escape.timer",
            "horizon-observer-../root.timer",
        ] {
            assert!(next(&json!({"sole_next_timer":t})).is_err());
        }
    }
    #[test]
    #[ignore = "requires original PID 1 and protected disjoint HOME fixture"]
    fn original_failed_native_and_scheduled_status() {
        boot().unwrap();
        let m = events::manager_exit(E, ORIGINAL, false).unwrap();
        assert_eq!(m["INVOCATION_ID"], ORIGINAL);
        exit_one(E, ORIGINAL).unwrap();
        assert!(exit_one(E, REC).is_err());
        failure(&original(ORIGINAL), ORIGINAL).unwrap();
        assert!(failure(&original(ORIGINAL), REC).is_err());
        let dir = PathBuf::from(std::env::var("HANDOFF_PRIVATE_FIXTURE").unwrap());
        let path = dir.join("cadence").join("committed");
        let expected = path.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(30));
            fs::create_dir(expected.parent().unwrap()).unwrap();
            platform::save(&expected, &json!(true)).unwrap();
        });
        wait_file(&path).unwrap();
        t.join().unwrap();
        let f = from_ref(&seed()).unwrap();
        accepted(&f).unwrap();
        let mut bad = f.clone();
        bad["all_reservation_ending_bytes"] = 1.into();
        assert!(accepted(&bad).is_err());
    }
}
