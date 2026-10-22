//! Observational ownership capture. Never acquires the mutation lock or invokes R2.
use super::*;
use std::os::unix::fs::PermissionsExt;
fn receipt(path: &Path) -> Result<(Bound, Value)> {
    let (bytes, _) = stable(path, 0)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let mut canonical = serde_json::to_vec_pretty(&value)?;
    canonical.push(b'\n');
    ensure!(
        bytes == canonical,
        "ownership receipt is partial/noncanonical"
    );
    let b = Bound {
        path: path.into(),
        sha256: evidence::sha(&bytes),
    };
    Ok((b, value))
}
struct CaptureMutex(File);
impl CaptureMutex {
    fn acquire(root: &Path) -> Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(root.join(".ownership-capture.lock"))?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.len() == 0
                && m.mode() & 0o777 == 0o600,
            "unsafe private capture mutex"
        );
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0,
            "capture mutex unavailable"
        );
        f.sync_all()?;
        File::open(root)?.sync_all()?;
        Ok(Self(f))
    }
}
impl Drop for CaptureMutex {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn finish(path: &Path) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.nlink() == 1 && matches!(m.mode() & 0o777, 0o400 | 0o600),
        "unsafe capture finalization"
    );
    f.sync_all()?;
    if m.mode() & 0o777 != 0o400 {
        f.set_permissions(fs::Permissions::from_mode(0o400))?;
        f.sync_all()?;
    }
    File::open(path.parent().context("capture parent")?)?.sync_all()?;
    Ok(())
}
fn durable(path: &Path, v: &Value) -> Result<()> {
    evidence::write_receipt(path, v)?;
    finish(path)
}
fn hex_id(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
fn command(pb: &Bound, sha: &str, exe: &Path) -> String {
    format!(
        "{{ path={} ; argv[]={} {} --plan-sha256 {} --self-sha256 {sha} --run",
        exe.display(),
        exe.display(),
        pb.path.display(),
        pb.sha256
    )
}
fn owner(v: &Value, iid: &Value, pb: &Bound, sha: &str, exe: &Path) -> Result<()> {
    ensure!(
        hex_id(iid)
            && v["Id"] == UNIT
            && v["LoadState"] == "loaded"
            && v["InvocationID"] == *iid
            && v["NRestarts"] == "0"
            && v["Restart"] == "no"
            && v["Type"] == "oneshot"
            && v["RemainAfterExit"] == "yes"
            && v["ExecStart"]
                .as_str()
                .and_then(|s| s.split_once(" ; ignore_errors="))
                .is_some_and(|(s, t)| s == command(pb, sha, exe) && t.starts_with("no ;")),
        "delivery owner/command changed"
    );
    Ok(())
}
fn live(v: &Value) -> bool {
    v["ActiveState"] == "activating"
        && v["SubState"] == "start"
        && v["MainPID"]
            .as_str()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|n| n > 0)
}
fn terminal(v: &Value) -> Result<bool> {
    ensure!(
        v["MainPID"] == "0"
            && ((v["ActiveState"] == "active" && v["SubState"] == "exited")
                || (v["ActiveState"] == "failed" && v["SubState"] == "failed")
                || (v["ActiveState"] == "inactive" && v["SubState"] == "dead")),
        "delivery owner not positively terminal"
    );
    Ok(v["ActiveState"] == "active"
        && v["SubState"] == "exited"
        && v["Result"] == "success"
        && v["ExecMainStatus"] == "0")
}
fn intent(v: &Value, pb: &Bound, sha: &str, exe: &Path) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-exact144-delivery-intent-v1"
            && v["plan"] == serde_json::to_value(pb)?
            && v["self_sha256"] == sha
            && v["shared_mutation_lock"] == LOCK
            && v["lock_acquisition_mode"] == "nonblocking-no-queue"
            && v["lock_wait_started_millis"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && v["another_progressive_coordinator"] == false
            && v["local_retirement_authorized"] == false
            && v["publisher"]["publisher"]["Id"] == PUB
            && hex_id(&v["publisher"]["publisher"]["InvocationID"]),
        "foreign delivery intent"
    );
    owner(&v["owner"], &v["owner"]["InvocationID"], pb, sha, exe)?;
    ensure!(
        live(&v["owner"]),
        "delivery intent did not record genuine live owner"
    );
    Ok(())
}
fn lock(v: &Value, i: &Value, pb: &Bound) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-exact144-delivery-lock-v1"
            && v["owner"] == i["owner"]
            && v["plan"] == serde_json::to_value(pb)?
            && v["shared_mutation_lock"] == LOCK
            && gate_identity::same_gate(&i["publisher"], &v["gates"])
            && v["acquired_millis"]
                .as_u64()
                .zip(i["lock_wait_started_millis"].as_u64())
                .is_some_and(|(a, b)| a >= b),
        "foreign or out-of-order144lock handoff"
    );
    Ok(())
}
fn launch(v: &Value, b: &Bound, i: &Value, pb: &Bound, sha: &str, exe: &Path) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-exact144-delivery-launch-v1"
            && v["epoch"] == 144
            && v["plan"] == serde_json::to_value(pb)?
            && v["self_sha256"] == sha
            && v["worker_intent"] == serde_json::to_value(b)?
            && v["owner"]["InvocationID"] == i["owner"]["InvocationID"]
            && v["claim"]["unit"] == UNIT
            && v["claim"]["invocation_id"] == i["owner"]["InvocationID"]
            && v["claim"]["expected_exec_start"] == v["owner"]["ExecStart"]
            && v["claim"]["phase"] == "upload-readback"
            && v["claim"]["origin_unit"] == PUB
            && v["claim"]["origin_invocation_id"] == i["publisher"]["publisher"]["InvocationID"],
        "delivery launch binding changed"
    );
    ensure!(
        v["captured_at_millis"]
            .as_u64()
            .zip(i["lock_wait_started_millis"].as_u64())
            .is_some_and(|(a, b)| a >= b),
        "capture precedes worker lock wait"
    );
    ensure!(
        v["initial_delivery_phase"] == "upload-readback"
            && v["lock_acquisition"]["path"].as_str()
                == b.path
                    .parent()
                    .map(|p| p.join("lock-acquired.json"))
                    .as_ref()
                    .and_then(|p| p.to_str())
            && v["lock_acquisition"]["sha256"]
                .as_str()
                .is_some_and(evidence::is_sha),
        "delivery capture phase/lock evidence changed"
    );
    owner(&v["owner"], &i["owner"]["InvocationID"], pb, sha, exe)?;
    ensure!(live(&v["owner"]), "captured owner was not live");
    for flag in [
        "ordinary_replay_claim",
        "current_sidecar_eta_valid",
        "publication_authorized",
        "retirement_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v[flag] == false,
            "delivery capture acquired authority:{flag}"
        );
    }
    Ok(())
}
fn declined(v: &Value, i: &Value, pb: &Bound, sha: &str, device: u64, inode: u64) -> Result<()> {
    ensure!(
        v["schema"] == "horizon-exact144-delivery-lock-declined-v1"
            && v["owner"] == i["owner"]
            && v["plan"] == serde_json::to_value(pb)?
            && v["self_sha256"] == sha
            && v["shared_mutation_lock"] == LOCK
            && v["lock_device"] == device
            && v["lock_inode"] == inode
            && v["declined_at_millis"]
                .as_u64()
                .zip(i["lock_wait_started_millis"].as_u64())
                .is_some_and(|(a, b)| a >= b),
        "foreign busy-lock decline receipt"
    );
    for flag in [
        "delivery_launched",
        "client_started",
        "queued",
        "archive_or_status_mutations",
        "automatic_retry_authorized",
    ] {
        ensure!(
            v[flag] == false,
            "busy-lock decline acquired authority:{flag}"
        );
    }
    Ok(())
}
pub(super) fn run(p: &Plan, pb: &Bound, self_sha: &str, is_terminal: bool) -> Result<()> {
    configuration(p)?;
    let exe = fs::read_link("/proc/self/exe")?;
    let (ib, i) = receipt(&p.output_directory.join("intent.json"))?;
    intent(&i, pb, self_sha, &exe)?;
    let before = fields(UNIT)?;
    owner(&before, &i["owner"]["InvocationID"], pb, self_sha, &exe)?;
    if is_terminal {
        terminal(&before)?;
    } else {
        ensure!(
            live(&before),
            "delivery capture requires actual live worker"
        );
    }
    // This tiny private metadata mutex is distinct from the global archive
    // mutation lock. Acquire only after a genuine owner is authenticated.
    let _capture_mutex = CaptureMutex::acquire(&p.output_directory)?;
    if is_terminal
        && matches!(fs::symlink_metadata(p.output_directory.join("launch.json")),Err(e) if e.kind()==std::io::ErrorKind::NotFound)
    {
        let (db, d) = receipt(&p.output_directory.join("lock-declined.json"))?;
        declined(
            &d,
            &i,
            pb,
            self_sha,
            p.shared_lock_device,
            p.shared_lock_inode,
        )?;
        ensure!(
            !terminal(&before)?,
            "declined busy-lock attempt cannot claim successful delivery"
        );
        for name in [
            "lock-acquired.json",
            "upload-child-launch.json",
            "upload-child.json",
            "archive-complete.json",
            "completion.json",
        ] {
            ensure!(
                matches!(fs::symlink_metadata(p.output_directory.join(name)),Err(e) if e.kind()==std::io::ErrorKind::NotFound),
                "declined attempt has downstream evidence:{name}"
            );
        }
        ensure!(
            fields(UNIT)? == before,
            "declined owner changed during terminal capture"
        );
        durable(
            &p.output_directory.join("terminal.json"),
            &json!({"schema":"jetstreamer-exact144-delivery-terminal-v1",
            "epoch":144,"plan":pb,"self_sha256":self_sha,"worker_intent":ib,"decline":db,"owner":before,
            "service_success":false,"delivery_not_launched":true,"queued":false,"automatic_retry_authorized":false,
            "archive_verification_or_ready_pair_proven":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
        println!(
            "exact144 declined attempt captured; no delivery, client,queue or remote mutation"
        );
        return Ok(());
    }
    if !is_terminal {
        ensure!(
            live(&before),
            "delivery capture requires actual live worker"
        );
        // Canonical/full/plugin identities must still agree with the exact
        // publisher gate established by this worker before its lock wait.
        let v = read(&p.publisher_plan, true)?;
        ensure!(
            gates(p, &v)? == i["publisher"],
            "delivery publisher/canonical gate changed"
        );
        let launch_path = p.output_directory.join("launch.json");
        match fs::symlink_metadata(&launch_path) {
            Ok(_) => {
                let (_, existing) = receipt(&launch_path)?;
                launch(&existing, &ib, &i, pb, self_sha, &exe)?;
                finish(&launch_path)?;
                ensure!(
                    fields(UNIT)? == before,
                    "delivery changed during capture recovery"
                );
                println!("exact existing144 ownership capture verified; no write or remote access");
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let lock_path = p.output_directory.join("lock-acquired.json");
        let (phase, lb) = match fs::symlink_metadata(&lock_path) {
            Ok(_) => {
                let (b, v) = receipt(&lock_path)?;
                lock(&v, &i, pb)?;
                ("upload-readback", Some(b))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => anyhow::bail!(
                "nonblocking delivery cannot capture a queued claim before lock ownership"
            ),
            Err(e) => return Err(e.into()),
        };
        let after = fields(UNIT)?;
        ensure!(after == before, "delivery changed during capture");
        let value = json!({"schema":"jetstreamer-exact144-delivery-launch-v1","epoch":144,"plan":pb,"self_sha256":self_sha,"worker_intent":ib,"owner":before,"initial_delivery_phase":phase,"lock_acquisition":lb,"captured_at_millis":now()?,"claim":{"unit":UNIT,"invocation_id":before["InvocationID"],"expected_exec_start":before["ExecStart"],"phase":"upload-readback","origin_unit":PUB,"origin_invocation_id":i["publisher"]["publisher"]["InvocationID"]},"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        launch(&value, &ib, &i, pb, self_sha, &exe)?;
        if let Err(error) = durable(&launch_path, &value) {
            // Another legitimate capture may have won the no-clobber race.
            // Accept only its complete exact-owner receipt; partial or foreign
            // files remain fatal and are never replaced.
            let (_, existing) =
                receipt(&launch_path).with_context(|| format!("capture write failed:{error:#}"))?;
            launch(&existing, &ib, &i, pb, self_sha, &exe)?;
            finish(&launch_path)?;
        }
    } else {
        let (lb, l) = receipt(&p.output_directory.join("launch.json"))?;
        launch(&l, &ib, &i, pb, self_sha, &exe)?;
        if !l["lock_acquisition"].is_null() {
            let b: Bound = serde_json::from_value(l["lock_acquisition"].clone())?;
            lock(&read(&b, false)?, &i, pb)?;
        }
        let success = terminal(&before)?;
        ensure!(
            fields(UNIT)? == before,
            "terminal delivery changed during capture"
        );
        durable(
            &p.output_directory.join("terminal.json"),
            &json!({"schema":"jetstreamer-exact144-delivery-terminal-v1","epoch":144,"plan":pb,"self_sha256":self_sha,"launch":lb,"worker_intent":ib,"owner":before,"service_success":success,"archive_verification_or_ready_pair_proven":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false}),
        )?;
    }
    println!(
        "exact144 delivery ownership captured; no lock acquisition,archive hash or remote access"
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root disposable durable ownership receipt proof only; no real publisher,worker,archive or R2 access"]
    fn root_capture_receipts_are_private_durable_and_no_clobber() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let d = tempfile::tempdir().unwrap();
        let _mutex = CaptureMutex::acquire(d.path()).unwrap();
        let p = d.path().join("launch.json");
        let v = json!({"fixture":true,"publication_authorized":false,"r2_mutations":false});
        durable(&p, &v).unwrap();
        let (b, read) = receipt(&p).unwrap();
        assert_eq!(read, v);
        assert_eq!(b.sha256, evidence::sha(&fs::read(&p).unwrap()));
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o777, 0o400);
        assert!(durable(&p, &json!({"foreign":true})).is_err());
        assert_eq!(receipt(&p).unwrap().1, v);
        let alias = d.path().join("alias");
        std::os::unix::fs::symlink(&p, &alias).unwrap();
        assert!(durable(&alias, &v).is_err());
        assert!(receipt(&alias).is_err());
    }
    fn fixture() -> (Bound, PathBuf, Value) {
        let pb = Bound {
            path: "/sealed/plan.json".into(),
            sha256: "a".repeat(64),
        };
        let exe = PathBuf::from("/sealed/deliver");
        let owner = json!({"Id":UNIT,"LoadState":"loaded","InvocationID":"b".repeat(32),"NRestarts":"0","Restart":"no","Type":"oneshot","RemainAfterExit":"yes","ActiveState":"activating","SubState":"start","MainPID":"123","ExecStart":format!("{} ; ignore_errors=no ; start_time=[now] }}",command(&pb,&"c".repeat(64),&exe))});
        let v = json!({"schema":"horizon-exact144-delivery-intent-v1","plan":pb,"self_sha256":"c".repeat(64),"owner":owner,"publisher":{"publisher":{"Id":PUB,"InvocationID":"d".repeat(32)},"publication":{"committed":true}},"shared_mutation_lock":LOCK,"lock_wait_started_millis":10,"lock_acquisition_mode":"nonblocking-no-queue","another_progressive_coordinator":false,"local_retirement_authorized":false});
        (pb, exe, v)
    }
    #[test]
    fn nonblocking_intent_retains_exact_live_worker_and_original_publisher() {
        let (p, e, v) = fixture();
        intent(&v, &p, &"c".repeat(64), &e).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(intent(&bad, &p, &"c".repeat(64), &e).is_err(), "{key}");
        }
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("MainPID", "0"),
            ("NRestarts", "1"),
            ("Restart", "always"),
            ("Type", "exec"),
            ("RemainAfterExit", "no"),
            ("SubState", "exited"),
            ("ExecStart", "--capture"),
        ] {
            let mut bad = v.clone();
            bad["owner"][key] = json!(value);
            assert!(intent(&bad, &p, &"c".repeat(64), &e).is_err(), "{key}");
        }
    }
    #[test]
    fn lock_phase_cannot_borrow_another_intent_or_precede_queue_start() {
        let (p, _, i) = fixture();
        let l = json!({"schema":"horizon-exact144-delivery-lock-v1","owner":i["owner"],"plan":p,"shared_mutation_lock":LOCK,"gates":i["publisher"],"acquired_millis":11});
        lock(&l, &i, &p).unwrap();
        for key in l.as_object().unwrap().keys() {
            let mut bad = l.clone();
            bad[key] = Value::Null;
            assert!(lock(&bad, &i, &p).is_err(), "{key}");
        }
        let mut bad = l;
        bad["acquired_millis"] = json!(9);
        assert!(lock(&bad, &i, &p).is_err());
    }
    #[test]
    fn positive_terminal_is_separate_from_ready_pair_evidence() {
        let mut u = json!({"MainPID":"0","ActiveState":"active","SubState":"exited","Result":"success","ExecMainStatus":"0"});
        assert!(terminal(&u).unwrap());
        u["Result"] = json!("exit-code");
        assert!(!terminal(&u).unwrap());
        u["ActiveState"] = json!("failed");
        u["SubState"] = json!("failed");
        assert!(!terminal(&u).unwrap());
        u["MainPID"] = json!("123");
        assert!(terminal(&u).is_err());
    }
    #[test]
    fn busy_decline_is_bound_and_never_a_queued_upload_or_retry_permission() {
        let (p, _, i) = fixture();
        let d = json!({"schema":"horizon-exact144-delivery-lock-declined-v1","owner":i["owner"],"plan":p,"self_sha256":"c".repeat(64),
            "shared_mutation_lock":LOCK,"lock_device":1,"lock_inode":2,"declined_at_millis":11,
            "delivery_launched":false,"client_started":false,"queued":false,"archive_or_status_mutations":false,"automatic_retry_authorized":false});
        declined(&d, &i, &p, &"c".repeat(64), 1, 2).unwrap();
        for key in d.as_object().unwrap().keys() {
            let mut bad = d.clone();
            bad[key] = Value::Null;
            assert!(
                declined(&bad, &i, &p, &"c".repeat(64), 1, 2).is_err(),
                "{key}"
            );
        }
        assert!(declined(&d, &i, &p, &"c".repeat(64), 1, 3).is_err());
    }
    #[test]
    fn captured_claim_cannot_change_origin_command_phase_or_authority() {
        let (p, e, i) = fixture();
        let b = Bound {
            path: "/private/intent.json".into(),
            sha256: "e".repeat(64),
        };
        let v = json!({"schema":"jetstreamer-exact144-delivery-launch-v1","epoch":144,"plan":p,"self_sha256":"c".repeat(64),"worker_intent":b,"owner":i["owner"],"captured_at_millis":11,"initial_delivery_phase":"upload-readback","lock_acquisition":{"path":"/private/lock-acquired.json","sha256":"f".repeat(64)},"claim":{"unit":UNIT,"invocation_id":i["owner"]["InvocationID"],"expected_exec_start":i["owner"]["ExecStart"],"phase":"upload-readback","origin_unit":PUB,"origin_invocation_id":i["publisher"]["publisher"]["InvocationID"]},"ordinary_replay_claim":false,"current_sidecar_eta_valid":false,"publication_authorized":false,"retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        launch(&v, &b, &i, &p, &"c".repeat(64), &e).unwrap();
        for key in [
            "worker_intent",
            "plan",
            "epoch",
            "owner",
            "initial_delivery_phase",
            "claim",
            "publication_authorized",
            "current_sidecar_eta_valid",
        ] {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(
                launch(&bad, &b, &i, &p, &"c".repeat(64), &e).is_err(),
                "{key}"
            );
        }
        let mut bad = v.clone();
        bad["claim"]["expected_exec_start"] = json!("foreign");
        assert!(launch(&bad, &b, &i, &p, &"c".repeat(64), &e).is_err());
        let mut bad = v;
        bad["initial_delivery_phase"] = json!("queued-upload");
        assert!(launch(&bad, &b, &i, &p, &"c".repeat(64), &e).is_err());
    }
}
