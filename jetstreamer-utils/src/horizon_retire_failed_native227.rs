//! One exact unregistered bootstrap attempt; never a replay/commitment profile.
use super::*;
pub(super) const OUTCOME_SCHEMA: &str = "jetstreamer-private-native227-small-capture-failure-v1";
const ROOT: &str = "/home/ubuntu/.jetstreamer-private/native-input227-v1625-full-small-v2";
const UNIT: &str = "horizon-native-input-227-v1625-small-v2.service";
const IID: &str = "9fe28fc981da4147a6fff8de3990323a";
const GUARD: &str = "horizon-native227-v1625-small-protective-v2.service";
const GUARD_IID: &str = "d16bcd65e330405ebeea5c57e73eb8e8";
const FAILURE: &str = "/var/lib/jetstreamer/horizon-native227-small-capture-failure-9fe28fc9-v1";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-227-v1625-native-capture-small-v2/intent.json";
const TERMINAL: &str =
    "/var/lib/jetstreamer/horizon-native227-v1625-terminal-proof-small-v2/proof.json";
const REQUIRED: &[(&str, &str)] = &[
    (
        "/var/lib/jetstreamer/horizon-native227-small-capture-failure-9fe28fc9-v1/native-original-journal.jsonl",
        "8a020677ba65708ca6b063a9da6b809c1d7214209c567a7fdd7beb22fe248b76",
    ),
    (
        "/var/lib/jetstreamer/horizon-native227-small-capture-failure-9fe28fc9-v1/guard-original-journal.jsonl",
        "7207ff571b505cacf3ae1e178719480a06aaf0cfeee28e52b7b44a26d47abab1",
    ),
    (
        "/var/lib/jetstreamer/horizon-native227-small-capture-failure-9fe28fc9-v1/native-terminal-manager.txt",
        "db4c48d572ef50f740cca76f35460555793dc3aee9c0163026c09f0a359143a0",
    ),
    (
        "/var/lib/jetstreamer/horizon-227-v1625-native-admission-small343-v1/admission.json",
        "da07a98b03a99cbb46a27ec3514a5139f98e315efeb4de2507c4051e32d821a0",
    ),
    (
        "/var/lib/jetstreamer/horizon-native227-v1625-small-guard-actual-v2/guard-plan.json",
        "49421344208c4a51fff6209ce75e1ef94469be4efc81acba576bb69018e18495",
    ),
    (
        "/var/lib/jetstreamer/horizon-native227-v1625-small-guard-receipts-v2/sample-d16bcd65e330405ebeea5c57e73eb8e8.json",
        "07954a5ccfea5f6b1d032b9b6d48498ea58a9d3860fc467d286f6dfdd197810f",
    ),
];
const INPUTS: &[(&str, &str)] = &[
    (
        "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/snapshot-98063464-4TaJaC5esCEWtHp5Fay2aMS9XjA1o9bwQthcvBeSyYbR.tar.zst",
        "77e5b3bbb733d9ab3b2383c1ad9f1d7ef4062aedacbe9e2326927512c4b95e07",
    ),
    (
        "/var/lib/jetstreamer/horizon-stage227-bootstrap-dcaafc6-v1/genesis.tar.bz2",
        "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
    ),
    (
        "/var/lib/jetstreamer/horizon-227-v1625-qualification-tests-df338451-v1/test-runner",
        "df3384519a64629e99aafadee46833ad2889a9c60c3255ac939bd444965578ef",
    ),
];
pub(super) fn profile(p: &Plan) -> Result<()> {
    ensure!(
        !p.restore_only_probe
            && !p.warmup223_v3
            && p.native227_small_unregistered
            && p.run_root == Path::new(ROOT)
            && p.producer.unit == UNIT
            && p.producer.invocation_id == IID
            && p.producer.active_state == "inactive"
            && p.producer.sub_state == "dead"
            && p.producer.result == "success"
            && p.producer.exec_main_status == 0
            && p.guard.unit == GUARD
            && p.guard.invocation_id == GUARD_IID
            && p.guard.active_state == "inactive"
            && p.guard.sub_state == "dead"
            && p.guard.result == "success"
            && p.guard.exec_main_status == 0
            && p.inactive_units == ["horizon-native227-v1625-small-protective-v2.timer"]
            && p.outcome.path == Path::new(FAILURE).join("failed-capture.json")
            && p.outcome.sha256
                == "e1cd6713270cd966611b5829e0d61a4df3968c500ca791c97f97001dc81e3a40"
            && p.evidence.len() == REQUIRED.len(),
        "native227 retirement scope differs"
    );
    for (path, sha) in REQUIRED {
        ensure!(
            p.evidence
                .iter()
                .filter(|e| e.path == Path::new(path) && e.sha256 == *sha)
                .count()
                == 1,
            "native227 original evidence missing:{path}"
        );
    }
    Ok(())
}
fn failure(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == OUTCOME_SCHEMA
            && v["epoch"] == 227
            && v["unit"] == UNIT
            && v["invocation_id"] == IID
            && v["main_pid"] == 447704
            && v["capture_failure"] == "ENOENT: output parent was not prepared before launch"
            && v["guard_proven"] == true
            && v["new_job_stopped_under_parent_fail_stop_instruction"] == true
            && v["original_scratch_preserved"] == true
            && v["native_input_qualified"] == false
            && v["replay_launch_authorized"] == false
            && v["publication_authorized"] == false
            && v["r2_mutations"] == false,
        "native227 failure is not the exact unqualified stopped bootstrap"
    );
    Ok(())
}
fn original_journal(bytes: &[u8]) -> Result<()> {
    let rows = std::str::from_utf8(bytes)?
        .lines()
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut start = None;
    let mut stop = None;
    for (i, r) in rows.iter().enumerate() {
        let msg = r["MESSAGE"].as_str().context("native227 journal message")?;
        ensure!(
            !msg.starts_with("epoch227-v1625-native-input ")
                && !msg.contains("native_input_matches_canonical_accounts_commitment=")
                && !msg.starts_with("test result: ok.")
                && !msg.contains("canonical_accounts_commitment={"),
            "native227 successful commitment/test cannot be retired as failed input"
        );
        if r["_PID"] == "1" && r["UNIT"] == UNIT {
            ensure!(
                r["INVOCATION_ID"] == IID,
                "native227 manager journal owner differs"
            );
            if msg.starts_with(&format!("Started {UNIT}")) {
                ensure!(start.replace(i).is_none(), "native227 multiple starts");
            }
            if msg.starts_with(&format!("Stopped {UNIT}")) {
                ensure!(stop.replace(i).is_none(), "native227 multiple stops");
            }
        } else {
            ensure!(
                r["_PID"] == "447704" && r["_SYSTEMD_INVOCATION_ID"] == IID,
                "native227 worker journal owner differs"
            );
        }
    }
    ensure!(
        start.zip(stop).is_some_and(|(a, b)| a < b),
        "native227 original manager start/stop absent"
    );
    Ok(())
}
fn guard_journal(bytes: &[u8]) -> Result<()> {
    let allowed = BTreeSet::from([
        "28aa88a5095a4ae086f69fc1a07a2ecb",
        "51909e7b8b5245fdbbe2f52e8377ab98",
        GUARD_IID,
    ]);
    let mut samples = BTreeMap::new();
    let mut completions = BTreeMap::new();
    for (i, line) in std::str::from_utf8(bytes)?.lines().enumerate() {
        let r: Value = serde_json::from_str(line)?;
        let msg = r["MESSAGE"].as_str().context("native227 guard message")?;
        if r["_PID"] == "1" && r["UNIT"] == GUARD {
            let iid = r["INVOCATION_ID"]
                .as_str()
                .context("native227 guard manager IID")?;
            ensure!(
                allowed.contains(iid),
                "native227 newer guard invocation exists"
            );
            if msg == format!("{GUARD}: Deactivated successfully.") {
                ensure!(
                    completions.insert(iid.to_owned(), i).is_none(),
                    "native227 duplicate guard completion"
                );
            }
        } else {
            let iid = r["_SYSTEMD_INVOCATION_ID"]
                .as_str()
                .context("native227 guard worker IID")?;
            ensure!(allowed.contains(iid), "native227 guard writer changed");
            let v: Value = serde_json::from_str(msg)?;
            ensure!(
                v["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
                    && v["guard_invocation_id"] == iid
                    && v["producer_invocation_id"] == IID
                    && v["native_main"]["main_pid"] == 447704
                    && v["maximum_root_physical_bytes"] == 96_000_000_000u64
                    && v["trip_reason"].is_null()
                    && v["producer_stop_enabled"] == true,
                "native227 original guard proof differs"
            );
            ensure!(
                samples.insert(iid.to_owned(), i).is_none(),
                "native227 duplicate guard sample"
            );
        }
    }
    ensure!(
        samples.len() == allowed.len()
            && completions.len() == allowed.len()
            && allowed.iter().all(|id| samples
                .get(*id)
                .zip(completions.get(*id))
                .is_some_and(|(a, b)| a < b)),
        "native227 original guard completion chain absent"
    );
    Ok(())
}
fn current_original_journal() -> Result<()> {
    for (unit, guard) in [(UNIT, false), (GUARD, true)] {
        let output = Command::new("journalctl")
            .args(["-u", unit, "--output=json", "--no-pager"])
            .output()?;
        ensure!(
            output.status.success() && output.stdout.len() <= MAX_JSON_BYTES as usize,
            "native227 current journal unavailable or oversized"
        );
        if guard {
            guard_journal(&output.stdout)?;
        } else {
            original_journal(&output.stdout)?;
        }
    }
    Ok(())
}
pub(super) fn outcome(p: &Plan, v: &Value) -> Result<()> {
    profile(p)?;
    failure(v)?;
    original_journal(&read_secure(
        &Path::new(FAILURE).join("native-original-journal.jsonl"),
        MAX_JSON_BYTES,
        0,
    )?)?;
    for path in [ORIGIN, TERMINAL] {
        ensure!(
            matches!(fs::symlink_metadata(path),Err(e) if e.kind() == std::io::ErrorKind::NotFound),
            "native227 origin or successful terminal exists; cannot retire failed preparation"
        );
    }
    current_original_journal()?;
    let admission = read_bound_json(
        p.evidence
            .iter()
            .find(|e| e.path == Path::new(REQUIRED[3].0))
            .context("native227 admission binding")?,
    )?;
    ensure!(
        admission["admitted"] == true
            && admission["unit"] == UNIT
            && admission["maximum_scratch_bytes"] == 96_000_000_000u64,
        "native227 original admission differs"
    );
    for (path, sha) in INPUTS {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.mode() & 0o222 == 0
                && file_sha256(Path::new(path))? == *sha,
            "native227 retained reproducible input differs:{path}"
        );
    }
    Ok(())
}

fn directory(path: &Path, uid: u32, empty: bool) -> Result<Value> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == uid && m.mode() & 0o777 == 0o700 && path.canonicalize()? == path,
        "native227 destination not canonical owned0700:{}",
        path.display()
    );
    let is_empty = fs::read_dir(path)?.next().is_none();
    ensure!(
        !empty || is_empty,
        "native227 destination not empty:{}",
        path.display()
    );
    Ok(
        json!({"path":path,"device":m.dev(),"inode":m.ino(),"uid":uid,"mode":"0700","empty":is_empty}),
    )
}
pub(super) fn prelaunch() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        (args.len() == 6 || (args.len() == 7 && args[6] == "--destinations-only"))
            && args[2] == "--output"
            && args[4] == "--self-sha256",
        "usage: retire --native227-small-prelaunch --output ABS --self-sha256 SHA [--destinations-only]"
    );
    verify_self(&args[5])?;
    let destinations_only = args.len() == 7;
    let output = Path::new(&args[3]);
    ensure!(
        output
            == Path::new(
                "/var/lib/jetstreamer/horizon-native227-small-prelaunch-v1/destinations.json"
            )
            || output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-native227-small-prelaunch-v1/prelaunch.json"
                ),
        "native227 preflight output differs"
    );
    ensure!(
        destinations_only == (output.file_name() == Some(OsStr::new("destinations.json"))),
        "native227 proof mode/path differs"
    );
    directory(output.parent().unwrap(), 0, false)?;
    let mut dirs = Vec::new();
    for path in [
        Path::new(ORIGIN).parent().unwrap(),
        Path::new(TERMINAL).parent().unwrap(),
        Path::new("/var/lib/jetstreamer/horizon-native227-v1625-terminal-journal-small-v2"),
    ] {
        dirs.push(directory(path, 0, true)?);
    }
    dirs.push(directory(
        Path::new("/var/lib/jetstreamer/horizon-native227-v1625-small-guard-receipts-v2"),
        0,
        false,
    )?);
    dirs.push(directory(Path::new(ROOT), 1000, false)?);
    dirs.push(directory(
        &Path::new(ROOT).join("scratch"),
        1000,
        !destinations_only,
    )?);
    ensure!(
        file_sha256(Path::new(
            "/etc/systemd/system/horizon-native-input-227-v1625-small-v2.service"
        ))? == "135a4b4dee78f6779cf06e87cc83e37418f8dd1150f8a5530d9cb2fdda357b53",
        "native227 installed unit differs"
    );
    let expected = UnitExpectation {
        unit: UNIT.into(),
        invocation_id: IID.into(),
        active_state: "inactive".into(),
        sub_state: "dead".into(),
        result: "success".into(),
        exec_main_status: 0,
    };
    current_original_journal()?;
    let before = sample_unit(&expected, false, true)?;
    require_no_jobs(&BTreeSet::from([UNIT.into()]))?;
    let after = sample_unit(&expected, false, true)?;
    current_original_journal()?;
    ensure!(before == after, "native227 prelaunch owner changed");
    let proof = json!({"schema":"jetstreamer-native227-small-prelaunch-destinations-v1","recorded_unix_millis":now_millis()?,"unit":UNIT,
        "directories":dirs,"unit_terminal":before,"destinations_only":destinations_only,"empty_scratch_required":!destinations_only,
        "installed_unit_sha256":"135a4b4dee78f6779cf06e87cc83e37418f8dd1150f8a5530d9cb2fdda357b53",
        "fresh_complete_fleet_admission_still_required":true,"native_input_qualified":false,"replay_launch_authorized":false,
        "native_execution_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    write_noclobber(output, &proof)?;
    println!("{}", serde_json::to_string(&proof)?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_value(json!({"schema":PLAN_SCHEMA,"native227_small_unregistered":true,
            "private_root":"/home/ubuntu/.jetstreamer-private","run_root":ROOT,"targets":[format!("{ROOT}/scratch")],
            "producer":{"unit":UNIT,"invocation_id":IID,"active_state":"inactive","sub_state":"dead","result":"success","exec_main_status":0},
            "guard":{"unit":GUARD,"invocation_id":GUARD_IID,"active_state":"inactive","sub_state":"dead","result":"success","exec_main_status":0},
            "inactive_units":["horizon-native227-v1625-small-protective-v2.timer"],
            "outcome":{"path":format!("{FAILURE}/failed-capture.json"),"sha256":"e1cd6713270cd966611b5829e0d61a4df3968c500ca791c97f97001dc81e3a40"},
            "evidence":REQUIRED.iter().map(|(p,s)|json!({"path":p,"sha256":s})).collect::<Vec<_>>(),
            "intent_receipt":"/home/ubuntu/.jetstreamer-private/native227-small-retirement-9fe28fc9-v1/intent.json",
            "completion_receipt":"/home/ubuntu/.jetstreamer-private/native227-small-retirement-9fe28fc9-v1/complete.json",
            "authority":{"local_failed_diagnostic_retirement_authorized":true,"preserve_run_root":true,
                "archive_publication_authorized":false,"remote_mutations":false,"r2_mutations":false}})).unwrap()
    }
    #[test]
    fn cleared_guard_requires_only_the_original_three_completed_fires() {
        let mut rows = Vec::new();
        for id in [
            "28aa88a5095a4ae086f69fc1a07a2ecb",
            "51909e7b8b5245fdbbe2f52e8377ab98",
            GUARD_IID,
        ] {
            let sample = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1","guard_invocation_id":id,
                "producer_invocation_id":IID,"native_main":{"main_pid":447704},"maximum_root_physical_bytes":96_000_000_000u64,
                "trip_reason":null,"producer_stop_enabled":true});
            rows.push(
                json!({"_PID":"22","_SYSTEMD_INVOCATION_ID":id,"MESSAGE":sample.to_string()}),
            );
            rows.push(json!({"_PID":"1","UNIT":GUARD,"INVOCATION_ID":id,"MESSAGE":format!("{GUARD}: Deactivated successfully.")}));
        }
        let encode = |r: &[Value]| {
            r.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        guard_journal(encode(&rows).as_bytes()).unwrap();
        let mut bad = rows.clone();
        bad[0]["_SYSTEMD_INVOCATION_ID"] = json!("a".repeat(32));
        assert!(guard_journal(encode(&bad).as_bytes()).is_err());
        let mut bad = rows.clone();
        bad.push(
            json!({"_PID":"1","UNIT":GUARD,"INVOCATION_ID":"a".repeat(32),"MESSAGE":"Starting"}),
        );
        assert!(guard_journal(encode(&bad).as_bytes()).is_err());
        assert!(guard_journal(encode(&rows[..4]).as_bytes()).is_err());
    }
    #[test]
    fn retirement_profile_never_borrows_a_registered_replay_or_expands_target_scope() {
        validate_plan(&plan()).unwrap();
        let mut p = plan();
        p.targets.push(Path::new(ROOT).join("output"));
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.run_root = PathBuf::from("/home/ubuntu/.jetstreamer-private/other");
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.producer.invocation_id = "a".repeat(32);
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.producer.active_state = "active".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.evidence.pop();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.evidence[0].sha256 = "a".repeat(64);
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.restore_only_probe = true;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.authority.r2_mutations = true;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.authority.local_failed_diagnostic_retirement_authorized = false;
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn directory_preflight_rejects_missing_writable_symlink_and_nonempty_destination() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("private");
        assert!(directory(&p, unsafe { libc::geteuid() }, true).is_err());
        fs::create_dir(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).unwrap();
        directory(&p, unsafe { libc::geteuid() }, true).unwrap();
        fs::write(p.join("old"), b"x").unwrap();
        assert!(directory(&p, unsafe { libc::geteuid() }, true).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(directory(&p, unsafe { libc::geteuid() }, false).is_err());
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(directory(&link, unsafe { libc::geteuid() }, false).is_err());
    }
    #[test]
    fn journal_requires_exact_stopped_attempt_without_success() {
        let rows = [
            json!({"_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE":format!("Started {UNIT}")}),
            json!({"_PID":"1","UNIT":UNIT,"INVOCATION_ID":IID,"MESSAGE":format!("Stopped {UNIT}")}),
        ];
        let encode = |rows: &[Value]| {
            rows.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        };
        original_journal(encode(&rows).as_bytes()).unwrap();
        let mut bad = rows.clone();
        bad[1]["INVOCATION_ID"] = json!("a".repeat(32));
        assert!(original_journal(encode(&bad).as_bytes()).is_err());
        let mut bad = rows.to_vec();
        bad.push(json!({"_PID":"447704","_SYSTEMD_INVOCATION_ID":IID,"MESSAGE":"test result: ok. 1 passed"}));
        assert!(original_journal(encode(&bad).as_bytes()).is_err());
        assert!(original_journal(encode(&rows[..1]).as_bytes()).is_err());
        let mut bad = rows.to_vec();
        bad.push(json!({"_PID":"447704","_SYSTEMD_INVOCATION_ID":IID,"MESSAGE":"epoch227-v1625-native-input slot=98063464"}));
        assert!(original_journal(encode(&bad).as_bytes()).is_err());
    }
}
