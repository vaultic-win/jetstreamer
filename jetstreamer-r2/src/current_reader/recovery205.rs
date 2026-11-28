//! Resume only the final metadata gates of the exact completed epoch205 playback.
//! The original native invocation remains failed; this never runs a reader.
use super::*;
use std::collections::BTreeSet;
pub const EPOCH: u64 = 205;
pub const LENGTH: u64 = 104_772_252_720;
pub const SHA: &str = "8a8205ade01bc4a39b5c59b5597841869bf7bd2bbda9f982744e14ac1dd250d7";
pub const UNIT: &str = "horizon-current-reader-205-audit-20261119-v4.service";
pub const IID: &str = "b1c2b133e40c42b6940081d73d2863c0";
pub const ORIGINAL_PID: u64 = 1_125_719;
const PLUGIN_PID: u64 = 1_265_781;
const RUN: &str = "/home/ubuntu/.jetstreamer-private/current-reader-r2-audit-205-20261119-v4/playback/epoch-205-1125719-1795092478054787059";
pub const LOCAL: &str =
    "/home/ubuntu/.jetstreamer-private/current-reader-r2-audit-205-20261118-v1/restored";
const ORIGINAL_UPLOADER: &str =
    "/var/lib/jetstreamer/horizon-skipped-tail-qualified-db1c31fe-20261119-v1/jetstreamer-r2";
const ORIGINAL_UPLOADER_SHA: &str =
    "02ae4dd1eafbb614b8ddf984817b3d544cbf68180e62613818fd49ff972c4ba4";
const JOURNAL_SHA: &str = "48b642e9fcb911ad712c053490ae44cab28c4e4572d7ffb6664c64d310ec8380";
fn original_plan() -> Bound {
    Bound {
        path: "/var/lib/jetstreamer/horizon-205-current-reader-plan-db1c31fe-20261119-v4/plan.json"
            .into(),
        sha256: "1541285cae9cc6981a0d0332815fe790345a3348c70c0c95c1539d22c3e7dc85".into(),
    }
}
fn retained(name: &str, sha: &str) -> Bound {
    Bound {
        path: Path::new(RUN).join(name),
        sha256: sha.into(),
    }
}
fn local_acceptance() -> Bound {
    retained(
        "local-acceptance.json",
        "23713a6be6f8105b9d8707bc1e0fc0d8426a70a336f250d1ee7168b78cb642e7",
    )
}
fn local_report() -> Bound {
    retained(
        "local-plugin.json",
        "a423d5d524086a9cf280a1d4e5be638e2a94555896c339508c40abf7154e731f",
    )
}
fn remote_report() -> Bound {
    retained(
        "remote-plugin.json",
        "e51fd25298c1e68ca484bdca4e3caf26ed91ea2743577bad4037275b2ed5d998",
    )
}
pub fn readback() -> PathBuf {
    Path::new(RUN).join("readback/epoch-205.jet")
}
fn uploader_args() -> Vec<String> {
    vec![
        ORIGINAL_UPLOADER.into(),
        "verify".into(),
        LOCAL.into(),
        "--epochs".into(),
        "205-205".into(),
        "--receipt-directory".into(),
        "/home/ubuntu/.jetstreamer-private/current-reader-r2-audit-205-20261119-v4/receipts".into(),
        "--concurrency".into(),
        "2".into(),
        "--current-reader-plan".into(),
        original_plan().path.to_string_lossy().into(),
        "--current-reader-plan-sha256".into(),
        original_plan().sha256,
    ]
}
fn plugin_args(p: &Plan, remote: bool) -> Vec<String> {
    vec![
        p.pipeline.path.to_string_lossy().into(),
        "205".into(),
        if remote {
            Path::new(RUN).join("readback").to_string_lossy().into()
        } else {
            LOCAL.into()
        },
        "--verify-only".into(),
        "--threads".into(),
        "2".into(),
        "--verification-report".into(),
        if remote {
            remote_report().path
        } else {
            local_report().path
        }
        .to_string_lossy()
        .into(),
    ]
}
fn str_field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing {k}"))
}
fn failed_native(v: &Value) -> Result<()> {
    for (k, w) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("InvocationID", IID),
        ("MainPID", "0"),
        ("ControlPID", "0"),
        ("ExecMainPID", "1125719"),
        ("ExecMainCode", "1"),
        ("ExecMainStatus", "1"),
        ("NRestarts", "0"),
        ("ActiveState", "failed"),
        ("SubState", "failed"),
        ("Result", "exit-code"),
        ("Job", ""),
        ("Restart", "no"),
        ("KillMode", "control-group"),
        ("Delegate", "no"),
    ] {
        ensure!(v[k] == w, "original failed owner changed {k}");
    }
    let prefix = format!(
        "{{ path={ORIGINAL_UPLOADER} ; argv[]={} ; ignore_errors=no ; start_time=[",
        uploader_args().join(" ")
    );
    let s = str_field(v, "ExecStart")?;
    ensure!(
        s.starts_with(&prefix) && s.ends_with(" }") && s.matches("{ path=").count() == 1,
        "original uploader command changed"
    );
    Ok(())
}
fn manager() -> Result<Value> {
    let props = "Id,LoadState,InvocationID,MainPID,ControlPID,ExecMainPID,ExecMainCode,ExecMainStatus,NRestarts,ActiveState,SubState,Result,Job,Restart,KillMode,Delegate,ControlGroup,ExecStart";
    let o = Command::new("/usr/bin/systemctl")
        .args(["show", UNIT, "--property", props])
        .output()?;
    ensure!(
        o.status.success() && o.stderr.is_empty() && o.stdout.len() < 65536,
        "original manager capture"
    );
    let mut m = serde_json::Map::new();
    for l in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = l.split_once('=').context("manager framing")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate manager key"
        );
    }
    let v = Value::Object(m);
    failed_native(&v)?;
    Ok(v)
}
fn drained() -> Result<()> {
    for pid in [ORIGINAL_PID, PLUGIN_PID] {
        match fs::symlink_metadata(format!("/proc/{pid}")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
            Ok(_) => anyhow::bail!("original process PID remains/reused"),
        }
    }
    fn walk(p: &Path, budget: &mut usize) -> Result<()> {
        ensure!(
            *budget > 0 && p.canonicalize()? == p,
            "unsafe/unbounded cgroup"
        );
        *budget -= 1;
        for f in ["cgroup.procs", "cgroup.threads"] {
            ensure!(
                fs::read_to_string(p.join(f))?.trim().is_empty(),
                "original cgroup populated"
            );
        }
        ensure!(
            fs::read_to_string(p.join("cgroup.events"))?
                .lines()
                .any(|l| l == "populated 0"),
            "original descendants populated"
        );
        for e in fs::read_dir(p)? {
            let e = e?;
            if e.file_type()?.is_dir() {
                walk(&e.path(), budget)?;
            }
        }
        Ok(())
    }
    let root = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{UNIT}"));
    match fs::symlink_metadata(&root) {
        Ok(_) => walk(&root, &mut 128)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    let group = format!("0::/system.slice/{UNIT}");
    for e in fs::read_dir("/proc")? {
        let e = e?;
        if !e
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        match fs::read_to_string(e.path().join("cgroup")) {
            Ok(v) => ensure!(
                !v.lines()
                    .any(|l| l == group || l.starts_with(&format!("{group}/"))),
                "original process remains in group"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn journal_rows(rows: &[Value], boot: &str, remote_argv: &[String]) -> Result<Value> {
    ensure!(!rows.is_empty() && rows.len() <= 20000, "journal row bound");
    let mut seen = BTreeMap::new();
    let mut mono = 0;
    for r in rows {
        ensure!(
            r["_BOOT_ID"] == boot.replace('-', ""),
            "journal boot changed"
        );
        let t = str_field(r, "__MONOTONIC_TIMESTAMP")?.parse::<u64>()?;
        ensure!(t >= mono, "journal rollback");
        mono = t;
        let msg = str_field(r, "MESSAGE")?;
        let pid = str_field(r, "_PID")?;
        let event = if pid == ORIGINAL_PID.to_string() {
            ensure!(
                r["_UID"] == "0"
                    && r["_SYSTEMD_UNIT"] == UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == IID
                    && r["_EXE"] == ORIGINAL_UPLOADER
                    && r["_CMDLINE"] == uploader_args().join(" "),
                "foreign original uploader journal"
            );
            if msg.starts_with('{') {
                let v: Value = serde_json::from_str(msg)?;
                if v["event"] == "r2-readback-verified" {
                    ensure!(
                        v["key"] == "epoch-205.jet"
                            && v["hashed_bytes"] == LENGTH
                            && v["total_bytes"] == LENGTH
                            && v["whole_file_sha256_verified"] == true,
                        "incomplete original authenticated readback"
                    );
                    Some("readback")
                } else {
                    None
                }
            } else if msg
                == "epoch 205: local source revalidation started after remote integrity proof"
            {
                Some("post_playback")
            } else if msg == "epoch 205: local source revalidation complete elapsed_millis=0" {
                Some("local_revalidated")
            } else if msg == "Error: epoch 205 R2 delivery failed" {
                Some("outer_error")
            } else if msg
                == "    0: current account-updates reader changed; qualify new artifacts and repeat full playback"
            {
                Some("source_error")
            } else if msg
                == "    1: reader Git command [\"diff\", \"--exit-code\", \"db1c31fe4e6d462a8e45c18c61f6b331a9c1a1c6\", \"3a3063194d25199bc22d65ccc385c9856729605c\", \"--\", \"Cargo.toml\", \"Cargo.lock\", \".cargo\", \"src\", \"jetstreamer-firehose\", \"jetstreamer-horizon\", \"jetstreamer-plugin\", \"jetstreamer-utils\", \"vendor\", \"build.rs\", \"rust-toolchain\", \"rust-toolchain.toml\"] failed:"
            {
                Some("exact_diff_error")
            } else {
                ensure!(
                    !msg.starts_with("Error:")
                        && !msg.contains("reader ")
                        && !msg.contains("panicked"),
                    "unexpected original uploader error"
                );
                None
            }
        } else if pid == PLUGIN_PID.to_string() {
            ensure!(
                r["_UID"] == "0"
                    && r["_SYSTEMD_UNIT"] == UNIT
                    && r["_SYSTEMD_INVOCATION_ID"] == IID
                    && r["_EXE"] == remote_argv[0]
                    && r["_CMDLINE"] == remote_argv.join(" "),
                "foreign remote plugin journal"
            );
            ensure!(
                !msg.contains(" ERROR ") && !msg.contains("panicked"),
                "original plugin failed"
            );
            if msg.ends_with("horizon pipeline: epoch 205 complete") {
                Some("plugin_complete")
            } else {
                None
            }
        } else if pid == "1" {
            ensure!(
                r["_UID"] == "0" && r["UNIT"] == UNIT && r["INVOCATION_ID"] == IID,
                "foreign manager journal"
            );
            if msg == format!("{UNIT}: Main process exited, code=exited, status=1/FAILURE") {
                Some("manager_exit")
            } else if msg == format!("{UNIT}: Failed with result 'exit-code'.") {
                Some("manager_failed")
            } else {
                ensure!(
                    !msg.contains("timed out") && !msg.contains("Deactivated successfully"),
                    "original terminal outcome changed"
                );
                None
            }
        } else {
            None
        };
        if let Some(e) = event {
            ensure!(
                seen.insert(e, (t, r.clone())).is_none(),
                "duplicate original journal event {e}"
            );
        }
    }
    let order = [
        "readback",
        "plugin_complete",
        "post_playback",
        "local_revalidated",
        "outer_error",
        "source_error",
        "exact_diff_error",
        "manager_exit",
        "manager_failed",
    ];
    let mut previous = 0;
    for e in order {
        let (t, _) = seen
            .get(e)
            .with_context(|| format!("missing original event {e}"))?;
        ensure!(*t >= previous && *t > 0, "original event ordering");
        previous = *t;
    }
    ensure!(
        seen["plugin_complete"].0 > seen["readback"].0
            && seen["post_playback"].0 > seen["plugin_complete"].0,
        "original pipeline progression not proven"
    );
    Ok(
        json!({"events":seen,"original_run_successful":false,"original_exit_status":1,"remote_plugin_clean_exit_proven_by_original_uploader_control_flow":true}),
    )
}
fn load_journal(b: &Bound, plan: &Plan) -> Result<Value> {
    ensure!(b.sha256 == JOURNAL_SHA, "unreviewed original journal bytes");
    ensure!(fs::metadata(&b.path)?.len() <= 64 << 20, "journal size");
    bound_file(b)?;
    let bytes = fs::read(&b.path)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == b.sha256,
        "journal changed"
    );
    let rows = serde_json::Deserializer::from_slice(&bytes)
        .into_iter::<Value>()
        .collect::<std::result::Result<Vec<_>, _>>()?;
    journal_rows(
        &rows,
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        &plugin_args(plan, true),
    )
}
fn reports(plan: &Plan, local: &Value, remote: &Value) -> Result<()> {
    let expected: EpochExpectation = serde_json::from_value(bound_json(
        plan.epoch_expectations
            .get(&EPOCH)
            .context("epoch205 expectation")?,
    )?)?;
    let args = full_arguments(&Path::new(LOCAL).join("epoch-205.jet"), EPOCH, 2, &expected)?;
    for b in &expected.independent_evidence {
        bound_file(b)?;
    }
    let raw = bound_json(&local_report())?;
    report_shapes(plan, local, remote, &raw, &args)
}
fn report_shapes(
    plan: &Plan,
    local: &Value,
    remote: &Value,
    raw: &Value,
    args: &[String],
) -> Result<()> {
    ensure!(
        local["schema"] == "horizon-current-reader-local-acceptance-v1"
            && local["reader_plan"] == json!(original_plan())
            && local["full_verifier"] == json!(plan.full_verifier)
            && local["full_invocation"] == json!(args)
            && local["full_exit_code"] == 0
            && local["minimum_thread_stack_bytes"] == 67_108_864u64,
        "original full verification acceptance differs"
    );
    let lp = &local["local_playback"];
    ensure!(
        lp["pipeline"] == json!(plan.pipeline)
            && lp["process_exit_code"] == 0
            && lp["report_binding"] == json!(local_report())
            && &lp["report"] == raw
            && lp["invocation"] == json!(plugin_args(plan, false)),
        "original local plugin acceptance differs"
    );
    validate_report(raw, EPOCH, LOCAL, &plugin_args(plan, false))?;
    validate_report(
        remote,
        EPOCH,
        Path::new(RUN)
            .join("readback")
            .to_str()
            .context("non-UTF8 readback")?,
        &plugin_args(plan, true),
    )?;
    ensure!(
        raw["report"] == remote["report"],
        "original local/remote plugin streams or counts differ"
    );
    Ok(())
}
pub fn load_bound(b: &Bound) -> Result<Value> {
    bound_json(b)
}
pub fn check_bound(b: &Bound) -> Result<()> {
    bound_file(b)
}
pub fn write_bound(p: &Path, v: &Value) -> Result<Bound> {
    write_json(p, v)
}
#[derive(Debug)]
pub struct Evidence {
    plan: Plan,
    journal: Bound,
    journal_proof: Value,
    local: Value,
    remote: Value,
    terminal: Value,
    readback_identity: (u64, u64, u64, i64, i64, i64, i64),
}
fn readback_custody() -> Result<(u64, u64, u64, i64, i64, i64, i64)> {
    let p = readback();
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        p.canonicalize()? == p
            && m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o400
            && m.len() == LENGTH,
        "original readback custody differs"
    );
    private_directory(p.parent().unwrap())?;
    private_directory(Path::new(RUN))?;
    Ok(identity(&m))
}
pub fn prepare(journal: Bound) -> Result<Evidence> {
    let plan: Plan = serde_json::from_value(bound_json(&original_plan())?)?;
    ensure!(
        plan.reader_commit == "db1c31fe4e6d462a8e45c18c61f6b331a9c1a1c6"
            && plan.threads == 2
            && plan.scratch_directory == Path::new(RUN).parent().unwrap(),
        "original reader plan differs"
    );
    let q: Qualification = serde_json::from_value(bound_json(&plan.qualification)?)?;
    validate_qualification(&plan, &q)?;
    ensure!(
        q.minimum_thread_stack_bytes == Some(67_108_864),
        "original stack qualification differs"
    );
    for b in &q.source_build_evidence {
        bound_file(b)?;
    }
    bound_file(&plan.pipeline)?;
    bound_file(&plan.full_verifier)?;
    bound_file(&Bound {
        path: ORIGINAL_UPLOADER.into(),
        sha256: ORIGINAL_UPLOADER_SHA.into(),
    })?;
    let terminal = manager()?;
    drained()?;
    let local = bound_json(&local_acceptance())?;
    let remote = bound_json(&remote_report())?;
    reports(&plan, &local, &remote)?;
    let journal_proof = load_journal(&journal, &plan)?;
    let readback_identity = readback_custody()?;
    current_branch(&plan)?;
    Ok(Evidence {
        plan,
        journal,
        journal_proof,
        local,
        remote,
        terminal,
        readback_identity,
    })
}
impl Evidence {
    pub fn recheck(&self) -> Result<()> {
        ensure!(
            manager()? == self.terminal,
            "original native owner changed during recovery"
        );
        drained()?;
        ensure!(
            readback_custody()? == self.readback_identity,
            "original readback changed during recovery"
        );
        ensure!(
            bound_json(&local_acceptance())? == self.local
                && bound_json(&remote_report())? == self.remote,
            "original reports changed"
        );
        bound_file(&local_report())?;
        bound_file(&self.journal)?;
        bound_file(&self.plan.pipeline)?;
        bound_file(&self.plan.full_verifier)?;
        Ok(())
    }
    pub fn final_source(&self, publication: &Bound, helper: &Bound) -> Result<Value> {
        self.recheck()?;
        let (head, equivalence) = current_branch(&self.plan)?;
        let p = bound_json(publication)?;
        ensure!(
            p["schema"] == "horizon205-reader-recovery-source-publication-v1"
                && p["Main_accepted"] == true
                && p["source_artifact_correspondence_accepted"] == true
                && p["helper"] == json!(helper)
                && p["original_reader_plan"] == json!(original_plan()),
            "missing qualified recovery helper provenance"
        );
        let commit = str_field(&p, "source_commit")?;
        ensure!(hex(commit, 40), "helper source commit");
        git(&self.plan, &["merge-base", "--is-ancestor", commit, &head])?;
        let required = BTreeSet::from([
            "jetstreamer-r2/src/main.rs",
            "jetstreamer-r2/src/recover_reader205.rs",
            "jetstreamer-r2/src/current_reader.rs",
            "jetstreamer-r2/src/current_reader/operator_equivalence205.rs",
            "jetstreamer-r2/src/current_reader/recovery205.rs",
        ]);
        let mut seen = BTreeSet::new();
        for f in p["source_files"]
            .as_array()
            .context("helper source closure")?
        {
            let path = str_field(f, "path")?;
            ensure!(
                required.contains(path) && seen.insert(path),
                "helper source scope/duplicate"
            );
            let entry = git(&self.plan, &["ls-tree", commit, "--", path])?;
            ensure!(
                entry.starts_with("100644 blob ") && entry == str_field(f, "git_tree_entry")?,
                "helper exact source tree entry differs"
            );
        }
        ensure!(seen == required, "incomplete helper source closure");
        let evidence = p["source_build_evidence"]
            .as_array()
            .context("helper build evidence")?;
        ensure!(!evidence.is_empty(), "missing helper build evidence");
        for b in evidence {
            bound_file(&serde_json::from_value(b.clone())?)?;
        }
        bound_file(helper)?;
        for k in [
            "replay_launch_authorized",
            "publication_authorized",
            "remote_mutations",
            "r2_mutations",
            "local_retirement_authorized",
        ] {
            ensure!(p[k] == false, "helper provenance overclaims {k}");
        }
        Ok(
            json!({"fetched_branch_commit":head,"source_equivalence":equivalence,"recovery_helper_publication":publication,"recovery_helper":helper}),
        )
    }
    pub fn acceptance(
        &self,
        source: Value,
        remote: RemoteObject,
        proof: Value,
        recovery_plan: &Bound,
    ) -> Result<Value> {
        self.recheck()?;
        ensure!(
            remote.key == "epoch-205.jet"
                && remote.length == LENGTH
                && remote.sha256 == SHA
                && !remote.bucket.is_empty()
                && !remote.etag.is_empty(),
            "recovered remote identity"
        );
        Ok(
            json!({"schema":"horizon-r2-current-reader-recovered-audit-acceptance-v1","epoch":EPOCH,"reader_commit":self.plan.reader_commit,"reader_plan":original_plan(),"qualification":self.plan.qualification,
    "source_revalidation":source,"local_acceptance":local_acceptance(),"local_playback":self.local["local_playback"],"remote_playback":{"object":remote,"readback_path":readback(),"readback_identity":self.readback_identity,"playback":{"report":self.remote,"report_binding":remote_report(),"pipeline":self.plan.pipeline,"invocation":plugin_args(&self.plan,true),"process_exit_code":0,"exit_evidence":"original qualified uploader reached post-playback local revalidation"}},
    "original_run":{"unit":UNIT,"invocation_id":IID,"main_pid":ORIGINAL_PID,"remote_plugin_pid":PLUGIN_PID,"uploader":{"path":ORIGINAL_UPLOADER,"sha256":ORIGINAL_UPLOADER_SHA},"terminal":self.terminal,"journal":self.journal,"validated_progression":self.journal_proof},
    "original_run_successful":false,"original_exit_status":1,"full_readback_rehashed_during_recovery":true,"fresh_remote_pair_proof":proof,"recovery_plan":recovery_plan,"verified_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"readiness_sidecar_committed":false,"remote_mutations":false,"r2_mutations":false,"local_retirement_authorized":false,"publication_authorized":false}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Value, Value, Value, Vec<Value>, EpochExpectation) {
        (
            serde_json::from_str(include_str!("fixtures/epoch205-original-plan.json")).unwrap(),
            serde_json::from_str(include_str!("fixtures/epoch205-local-acceptance.json")).unwrap(),
            serde_json::from_str(include_str!("fixtures/epoch205-local-plugin.json")).unwrap(),
            serde_json::from_str(include_str!("fixtures/epoch205-remote-plugin.json")).unwrap(),
            serde_json::from_str(include_str!(
                "fixtures/epoch205-original-terminal-events.json"
            ))
            .unwrap(),
            serde_json::from_str(include_str!("fixtures/epoch205-expectation.json")).unwrap(),
        )
    }
    #[test]
    fn genuine_completed_playback_keeps_original_failure_and_requires_full_event_chain() {
        let (p, _, _, _, rows, _) = fixture();
        let boot = rows[0]["_BOOT_ID"].as_str().unwrap();
        let accepted = journal_rows(&rows, boot, &plugin_args(&p, true)).unwrap();
        assert_eq!(accepted["original_run_successful"], false);
        assert_eq!(accepted["original_exit_status"], 1);
        for index in 0..rows.len() {
            let mut missing = rows.clone();
            missing.remove(index);
            assert!(
                journal_rows(&missing, boot, &plugin_args(&p, true)).is_err(),
                "accepted missing original event {index}"
            );
        }
        let mut duplicate = rows.clone();
        duplicate.push(rows.last().unwrap().clone());
        assert!(journal_rows(&duplicate, boot, &plugin_args(&p, true)).is_err());
        for key in [
            "_PID",
            "_UID",
            "_EXE",
            "_CMDLINE",
            "_SYSTEMD_INVOCATION_ID",
            "_BOOT_ID",
        ] {
            let mut changed = rows.clone();
            changed[1][key] = json!("wrong");
            assert!(
                journal_rows(&changed, boot, &plugin_args(&p, true)).is_err(),
                "accepted substituted {key}"
            );
        }
    }
    #[test]
    fn different_final_failure_or_incomplete_authenticated_readback_is_not_recoverable() {
        let (p, _, _, _, rows, _) = fixture();
        let boot = rows[0]["_BOOT_ID"].as_str().unwrap();
        let mut changed = rows.clone();
        let mut event: Value =
            serde_json::from_str(changed[0]["MESSAGE"].as_str().unwrap()).unwrap();
        event["whole_file_sha256_verified"] = json!(false);
        changed[0]["MESSAGE"] = json!(event.to_string());
        assert!(journal_rows(&changed, boot, &plugin_args(&p, true)).is_err());
        for index in [4, 5, 6, 7, 8] {
            let mut changed = rows.clone();
            changed[index]["MESSAGE"] = json!("reader failed for another reason");
            assert!(journal_rows(&changed, boot, &plugin_args(&p, true)).is_err());
        }
        let mut reverse = rows.clone();
        reverse.swap(1, 2);
        assert!(journal_rows(&reverse, boot, &plugin_args(&p, true)).is_err());
    }
    #[test]
    fn actual_report_pair_requires_exact_source_invocations_boundary_and_stream() {
        let (p, local, raw, remote, _, expected) = fixture();
        let args =
            full_arguments(&Path::new(LOCAL).join("epoch-205.jet"), EPOCH, 2, &expected).unwrap();
        report_shapes(&p, &local, &remote, &raw, &args).unwrap();
        for pointer in [
            "/source",
            "/invocation/2",
            "/report/first_slot",
            "/report/last_slot",
            "/report/slots",
            "/report/stream_digest/0",
            "/report/blocks",
        ] {
            let mut changed = remote.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(
                report_shapes(&p, &local, &changed, &raw, &args).is_err(),
                "accepted changed {pointer}"
            );
        }
        for pointer in [
            "/full_exit_code",
            "/full_invocation/5",
            "/local_playback/process_exit_code",
            "/local_playback/report_binding/sha256",
        ] {
            let mut changed = local.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("wrong");
            assert!(
                report_shapes(&p, &changed, &remote, &raw, &args).is_err(),
                "accepted changed {pointer}"
            );
        }
        assert!(report_shapes(&p, &local, &raw, &raw, &args).is_err()); // Local playback cannot replace remote playback.
    }
    #[test]
    fn original_failed_native_cannot_be_relabelled_success_or_replacement() {
        let mut v = json!({"Id":UNIT,"LoadState":"loaded","InvocationID":IID,"MainPID":"0","ControlPID":"0","ExecMainPID":"1125719","ExecMainCode":"1","ExecMainStatus":"1","NRestarts":"0","ActiveState":"failed","SubState":"failed","Result":"exit-code","Job":"","Restart":"no","KillMode":"control-group","Delegate":"no","ExecStart":format!("{{ path={ORIGINAL_UPLOADER} ; argv[]={} ; ignore_errors=no ; start_time=[x] ; stop_time=[y] ; pid=1125719 ; code=exited ; status=1 }}",uploader_args().join(" "))});
        failed_native(&v).unwrap();
        for key in [
            "ExecMainStatus",
            "Result",
            "InvocationID",
            "ExecMainPID",
            "MainPID",
            "NRestarts",
        ] {
            let mut changed = v.clone();
            changed[key] = json!("changed");
            assert!(failed_native(&changed).is_err());
        }
        v["ExecStart"] = json!(
            v["ExecStart"]
                .as_str()
                .unwrap()
                .replace("ignore_errors=no", "ignore_errors=yes")
        );
        assert!(failed_native(&v).is_err());
    }
}
