use super::identity::*;
use super::platform::*;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};
const CHILD_BUILD: &str = "public-reader-refresh-20261121-v1/build-2be87499054e4f3690ecabfb6faa7152/CURRENT_BRANCH_BUILD.json";
const BUILD_SHA: &str = "97c769f5f32522c9974f79536dfe565674fe37da4c57a16c84b067b647b90d1e";

pub fn manifest() -> Result<Value> {
    let mut files = BTreeMap::new();
    for e in fs::read_dir(public().join("results"))? {
        let p = e?.path();
        let s = p
            .file_name()
            .and_then(|s| s.to_str())
            .context("result name")?;
        let epoch: u64 = s
            .strip_prefix("epoch-")
            .and_then(|s| s.strip_suffix(".json"))
            .context("foreign result file")?
            .parse()?;
        ensure!(s == format!("epoch-{epoch}.json"), "noncanonical result");
        let bytes = read(&p)?;
        let v: Value = serde_json::from_slice(&bytes)?;
        ensure!(
            v["epoch"] == epoch
                && v["status"] == "passed"
                && v["epoch_plugin_completed"] == true
                && v["inventory_sha256"] == INV_SHA
                && v["remote_mutations"] == false,
            "invalid old accepted result {epoch}"
        );
        files.insert(epoch, sha(&bytes));
    }
    let inventory = pinned(&public().join("inventory.json"), INV_SHA)?;
    let epochs = inventory["objects"]
        .as_array()
        .context("inventory objects")?;
    ensure!(
        files.len() >= 73
            && files.len() <= epochs.len()
            && files
                .keys()
                .zip(epochs)
                .all(|(epoch, obj)| obj["epoch"] == *epoch),
        "accepted results differ from the inventory prefix"
    );
    let first: BTreeMap<String, &String> = (0..73)
        .map(|epoch| {
            Ok((
                epoch.to_string(),
                files
                    .get(&epoch)
                    .context("original accepted epoch missing")?,
            ))
        })
        .collect::<Result<_>>()?;
    ensure!(
        sha(&serde_json::to_vec(&first)?)
            == "2e787eea29b2b0cf749dd4c9a809d02352bd4e516ba8d67df4ffee58e6c9afd4",
        "original accepted epoch changed"
    );
    Ok(json!(files))
}
pub fn confirm_preserved(m: &Value) -> Result<()> {
    for (id, hash) in m.as_object().context("manifest")? {
        ensure!(
            bound(&public().join(format!("results/epoch-{id}.json")))?["sha256"] == *hash,
            "accepted {id} changed"
        )
    }
    Ok(())
}
pub fn validate_report(report: &Value, reference: &Value, event: &Value) -> Result<()> {
    let s = &report["report"];
    ensure!(
        event["completed"].as_u64() == Some(3)
            && event["reader_commit"] == "5bb2637754782ad3f03f5b780a5024fa89602adc"
            && event["at"].as_u64().is_some(),
        "wrong legacy event"
    );
    ensure!(
        report["schema"] == reference["schema"]
            && report["schema"] == "jetstreamer-horizon-plugin-playback-v1"
            && report["invocation"] == reference["invocation"]
            && report["source"] == reference["source"]
            && report["source"] == "https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev"
            && report["full_epoch_verified"] == true
            && s["epoch"] == 73
            && s["first_slot"] == 31536000
            && report["expected_first_slot"] == 31536000
            && s["last_slot"] == 31967999
            && report["expected_last_slot"] == 31967999
            && s["slots"] == 432000
            && s["worker_count"] == 4,
        "incorrect original epoch 73 report"
    );
    ensure!(
        s["blocks"]
            .as_u64()
            .and_then(|b| b.checked_add(s["skipped"].as_u64()?))
            == Some(432000)
            && ["transactions", "entries", "account_data_bytes"]
                .iter()
                .all(|k| s[k].as_u64().is_some_and(|v| v > 0))
            && s["stream_digest"].as_array().is_some_and(
                |a| a.len() == 32 && a.iter().all(|v| v.as_u64().is_some_and(|n| n <= 255))
            ),
        "missing complete counters or digest"
    );
    Ok(())
}
fn scoped_tree(repo: &str, commit: &str, build: &Value) -> Result<BTreeMap<String, String>> {
    ensure!(
        commit.len() == 40 && commit.bytes().all(|v| v.is_ascii_hexdigit()),
        "invalid commit"
    );
    let mut git = vec![
        "--no-replace-objects",
        "-c",
        "safe.directory=/home/sol/workspace/jetstreamer",
        "-C",
        repo,
        "ls-tree",
        "-rz",
        "--full-tree",
        commit,
        "--",
    ];
    for p in build["resolved_local_packages"]
        .as_array()
        .context("packages")?
    {
        git.push(text(p)?)
    }
    for p in build["current_source_files"]
        .as_object()
        .context("files")?
        .keys()
    {
        git.push(p);
    }
    git.push(".cargo");
    let listing = output("/usr/bin/git", &git)?;
    listing
        .split_terminator('\0')
        .map(|entry| {
            let (descriptor, path) = entry.split_once('\t').context("invalid Git tree")?;
            Ok((path.to_owned(), descriptor.to_owned()))
        })
        .collect()
}
pub fn branch_equivalent() -> Result<Value> {
    compare_branch("/var/lib/jetstreamer/r2-chronological-plugin-audit-20261118-v1/source")
}
pub fn compare_branch(src: &str) -> Result<Value> {
    let build = pinned(&base(CHILD_BUILD), BUILD_SHA)?;
    let tip = output(
        "/usr/bin/git",
        &[
            "--no-replace-objects",
            "-c",
            "safe.directory=/home/sol/workspace/jetstreamer",
            "-C",
            src,
            "rev-parse",
            "--verify",
            "refs/remotes/origin/account-updates",
        ],
    )?;
    let recorded = text(&build["branch_commit"])?;
    let original = scoped_tree("/home/sol/workspace/jetstreamer", recorded, &build)?;
    let latest = scoped_tree(src, &tip, &build)?;
    ensure!(
        build["byte_identical_to_sealed_reader"] == true
            && original == latest
            && original.len()
                >= build["current_source_files"]
                    .as_object()
                    .context("source list")?
                    .len(),
        "reader inputs differ from the byte-identical qualified build"
    );
    let qa = pinned(&base(E2E), E2E_SHA)?;
    ensure!(
        qa["current_build"] == recorded
            && qa["artifact_sha256"] == build["current_reader_sha256"]
            && qa["controller_seal_sha256"] == NEW_SEAL
            && qa["old_and_new_links_verified"] == true
            && qa["same_epoch_counters_and_digest"] == true,
        "controller QA differs"
    );
    Ok(
        json!({"fetched_branch_commit":tip,"current_build":bound(&base(CHILD_BUILD))?,"identical_scoped_paths":latest.len(),"scope_sha256":sha(&serde_json::to_vec(&latest)?),"isolated_controller_qualification":bound(&base(E2E))?}),
    )
}
pub fn no_new_playback() -> Result<()> {
    for e in fs::read_dir(public().join("attempts"))? {
        let item = e?;
        let n = item.file_name();
        if let Some(rest) = n.to_str().and_then(|n| n.strip_prefix("range-73-135-")) {
            ensure!(
                rest.parse::<u64>().is_ok()
                    && !item.path().join("playback.log").try_exists()?
                    && fs::read_dir(item.path().join("reports"))?.next().is_none(),
                "replacement range has started"
            );
        }
    }
    Ok(())
}
fn proc_tree_safe() -> Result<()> {
    ensure!(
        ticks(OLD_CHILD).ok() != Some(OLD_CHILD_TICKS),
        "original native reader is still active"
    );
    let pids = group_members(CG)?;
    ensure!(pids.contains(&OLD_PID), "old parent left its group");
    for p in pids.into_iter().filter(|p| *p != OLD_PID) {
        // Only transient source qualification may race the marker. No decoder,
        // build, second controller or unrecognised descendant may be fenced.
        let image = proc_exe(p)?;
        ensure!(
            [
                "/usr/bin/git",
                "/usr/bin/ssh",
                "/usr/bin/ssh-keygen",
                "/usr/bin/ssh-add",
                "/usr/bin/dash",
                "/usr/lib/git-core/git"
            ]
            .iter()
            .any(|s| Path::new(s) == image),
            "new/unknown worker {p} in audit group"
        );
    }
    no_new_playback()
}
pub struct ParentFence(OwnedFd);
impl ParentFence {
    fn stop_verified(
        pid: i32,
        start: u64,
        image: &Path,
        persist: impl FnOnce() -> Result<()>,
    ) -> Result<Self> {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        ensure!(
            ticks(pid)? == start && proc_exe(pid)? == image,
            "old process identity changed before pidfd"
        );
        ensure!(
            !fs::read_to_string(proc_path(pid, "status"))?
                .lines()
                .any(|l| l.starts_with("State:\tT") || l.starts_with("State:\tt")),
            "incumbent already suspended"
        );
        persist()?;
        // Signal only this process identity; never its process group or any decoder.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGSTOP,
                0,
                0,
            )
        } < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self(fd))
    }
    pub fn acquire() -> Result<Self> {
        old_live()?;
        proc_tree_safe()?;
        let guard = Self::stop_verified(OLD_PID, OLD_TICKS, &package(false).join("audit"), || {
            save(
                &work().join("FENCE_INTENT.json"),
                &json!({"at":now(),"owner":bound(&old_owner())?,"pid":OLD_PID,"ticks":OLD_TICKS,"event":bound(&attempt().join("branch-change.json"))?}),
            )
        })?;
        let until = Instant::now() + Duration::from_secs(5);
        loop {
            proc_tree_safe()?;
            let all_stopped = fs::read_dir(proc_path(OLD_PID, "task"))?
                .collect::<std::io::Result<Vec<_>>>()?
                .iter()
                .all(|t| {
                    fs::read_to_string(t.path().join("status"))
                        .is_ok_and(|s| s.lines().any(|l| l.starts_with("State:\tT")))
                });
            if all_stopped && group_members(CG)? == [OLD_PID] {
                break;
            }
            ensure!(
                Instant::now() < until,
                "could not isolate the quiescent old parent"
            );
            sleep(Duration::from_millis(15));
        }
        proc_tree_safe()?;
        Ok(guard)
    }
}
impl Drop for ParentFence {
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGCONT,
                0,
                0,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> (Value, Value, Value) {
        let native = json!({"schema":"jetstreamer-horizon-plugin-playback-v1","source":"https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev",
            "expected_first_slot":31536000,"expected_last_slot":31967999,"invocation":["sealed","70:135"],"full_epoch_verified":true,
            "report":{"epoch":73,"slots":432000,"worker_count":4,"first_slot":31536000,"last_slot":31967999,"blocks":420000,
                "skipped":12000,"transactions":45,"entries":60,"account_data_bytes":10,"stream_digest":vec![11;32]}});
        let prior = json!({"source":native["source"],"schema":native["schema"],"invocation":native["invocation"]});
        (
            native,
            prior,
            json!({"at":1795229000,"completed":3,"reader_commit":"5bb2637754782ad3f03f5b780a5024fa89602adc"}),
        )
    }
    #[test]
    fn pidfd_targets_only_the_verified_process_and_unwinds() {
        use std::process::{Command, Stdio};
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30 & echo $!; wait"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut line,
        )
        .unwrap();
        let descendant = line.trim().parse::<i32>().unwrap();
        let pid = child.id() as i32;
        let start = ticks(pid).unwrap();
        let image = proc_exe(pid).unwrap();
        let rejected = ParentFence::stop_verified(pid, start + 1, &image, || {
            panic!("unverified fence intent persisted")
        });
        assert!(rejected.is_err());
        let rejected =
            ParentFence::stop_verified(pid, start, &image, || anyhow::bail!("intent write failed"));
        assert!(rejected.is_err());
        let stopped = |p| {
            fs::read_to_string(proc_path(p, "status"))
                .unwrap()
                .lines()
                .any(|l| l.starts_with("State:\tT"))
        };
        assert!(!stopped(pid));
        let guard = ParentFence::stop_verified(pid, start, &image, || Ok(())).unwrap();
        let limit = Instant::now() + Duration::from_secs(1);
        while !stopped(pid) {
            assert!(Instant::now() < limit);
            sleep(Duration::from_millis(1));
        }
        assert!(!stopped(descendant));
        drop(guard);
        let limit = Instant::now() + Duration::from_secs(1);
        while stopped(pid) {
            assert!(Instant::now() < limit);
            sleep(Duration::from_millis(1));
        }
        unsafe {
            libc::kill(descendant, libc::SIGTERM);
        }
        child.wait().unwrap();
    }
    #[test]
    fn original_native_evidence_and_exact_range() {
        let (r, p, e) = valid();
        validate_report(&r, &p, &e).unwrap();
    }
    #[test]
    fn decline_wrong_native_range() {
        let (n, p, e) = valid();
        for (ptr, bad) in [
            ("/full_epoch_verified", json!(false)),
            ("/report/epoch", json!(74)),
            ("/report/worker_count", json!(256)),
            ("/report/slots", json!(431999)),
            ("/report/blocks", json!(419999)),
            ("/report/stream_digest", json!([])),
            ("/report/transactions", json!(0)),
            ("/report/account_data_bytes", json!(null)),
            ("/invocation", json!(["new"])),
            ("/expected_first_slot", json!(31535999)),
        ] {
            let mut test = n.clone();
            *test.pointer_mut(ptr).unwrap() = bad;
            assert!(validate_report(&test, &p, &e).is_err(), "{ptr}");
        }
    }
    #[test]
    fn reject_wrong_legacy_event() {
        let (n, p, e) = valid();
        for (key, bad) in [
            ("at", json!(null)),
            ("completed", json!(true)),
            ("completed", json!(4)),
            ("reader_commit", json!("other")),
        ] {
            let mut test = e.clone();
            test[key] = bad;
            assert!(validate_report(&n, &p, &test).is_err(), "{key}");
        }
    }
}
