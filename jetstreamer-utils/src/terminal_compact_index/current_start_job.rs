// The historical no-job rule remains unchanged. Only authenticate_current,
// after validating its fixed operation and actual payload identity, uses this
// finite original-running-start-job proof. This helper alone grants no PID or
// staged-recipe exemption and is never a Plan-controlled mode.
fn native_job_id(text: &str) -> Result<u32> {
    ensure!(
        !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) && !text.starts_with('0'),
        "missing/noncanonical original start job ID"
    );
    let id: u32 = text.parse().context("original start job ID overflow")?;
    ensure!(id > 0, "zero original start job ID");
    Ok(id)
}
fn current_start_job(
    native: &BTreeMap<&str, &str>,
    jobs: &str,
    unit: &str,
    iid: &str,
    own: u32,
) -> Result<u32> {
    let group = format!("/system.slice/{unit}");
    let own_pid = own.to_string();
    ensure!(
        own > 0
            && iid.len() == 32
            && iid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && native.get("Id") == Some(&unit)
            && native.get("LoadState") == Some(&"loaded")
            && native.get("InvocationID") == Some(&iid)
            && native.get("Type") == Some(&"oneshot")
            && native.get("ActiveState") == Some(&"activating")
            && native.get("SubState") == Some(&"start")
            && native.get("NRestarts") == Some(&"0")
            && native.get("ControlGroup") == Some(&group.as_str())
            && [native.get("MainPID"), native.get("ControlPID")]
                .into_iter()
                .any(|p| p == Some(&own_pid.as_str())),
        "original start job does not belong to this current payload"
    );
    ensure!(
        [
            "Triggers",
            "TriggeredBy",
            "OnSuccess",
            "OnFailure",
            "DropInPaths"
        ]
        .iter()
        .all(|key| native.get(key) == Some(&"")),
        "current original start job has trigger/dropin"
    );
    let expected = native_job_id(native.get("Job").context("missing current Job")?)?;
    let mut ids = BTreeSet::new();
    let mut units = BTreeSet::new();
    let mut matched = false;
    // --plain --no-legend emits ID UNIT TYPE STATE. Any unexpected transport
    // shape, duplicate, mismatch or absent row fails closed. Unrelated rows
    // receive no allowance and remain subject to ordinary campaign closure.
    for line in jobs.lines().filter(|line| !line.trim().is_empty()) {
        let row: Vec<_> = line.split_whitespace().collect();
        ensure!(row.len() == 4, "malformed native list-jobs row");
        let id = native_job_id(row[0])?;
        ensure!(
            ids.insert(id) && units.insert(row[1]),
            "duplicate native job ID/unit"
        );
        if id == expected || row[1] == unit {
            ensure!(
                id == expected && row[1] == unit && row[2] == "start" && row[3] == "running",
                "current job is not exactly its original running start"
            );
            matched = true;
        }
    }
    ensure!(matched, "current original start job absent from manager");
    Ok(expected)
}
fn unchanged_start_owner(
    before: &BTreeMap<&str, &str>,
    after: &BTreeMap<&str, &str>,
) -> Result<()> {
    for key in [
        "Id",
        "LoadState",
        "InvocationID",
        "MainPID",
        "ControlPID",
        "ActiveState",
        "SubState",
        "NRestarts",
        "ControlGroup",
        "Type",
        "Job",
        "Triggers",
        "TriggeredBy",
        "OnSuccess",
        "OnFailure",
        "DropInPaths",
    ] {
        ensure!(
            before.contains_key(key) && after.get(key) == before.get(key),
            "current native owner/job changed during authentication: {key}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod current_start_job_tests {
    use super::*;
    const UNIT: &str = "horizon-235237-index939-check-only-v1.service";
    const IID: &str = "0123456789abcdef0123456789abcdef";
    fn owner() -> String {
        format!("Id={UNIT}\nLoadState=loaded\nInvocationID={IID}\nType=oneshot\nActiveState=activating\nSubState=start\nNRestarts=0\nMainPID=42\nControlPID=0\nControlGroup=/system.slice/{UNIT}\nJob=731\nTriggers=\nTriggeredBy=\nOnSuccess=\nOnFailure=\nDropInPaths=\n")
    }
    fn jobs() -> String {
        format!("731 {UNIT} start running\n")
    }
    #[test]
    fn original_running_start_job_requires_exact_current_owner_and_manager_row() {
        let text = owner();
        let native = props(&text).unwrap();
        assert_eq!(
            current_start_job(&native, &jobs(), UNIT, IID, 42).unwrap(),
            731
        );
        let unrelated = format!("99 unrelated.service stop waiting\n{}", jobs());
        assert_eq!(
            current_start_job(&native, &unrelated, UNIT, IID, 42).unwrap(),
            731
        );
        let control = text.replace("MainPID=42\nControlPID=0", "MainPID=0\nControlPID=42");
        assert_eq!(
            current_start_job(&props(&control).unwrap(), &jobs(), UNIT, IID, 42).unwrap(),
            731
        );
        let retire_unit = "horizon-235237-index939-retire-v1.service";
        let retire = text.replace(UNIT, retire_unit);
        let retire_jobs = jobs().replace(UNIT, retire_unit);
        assert_eq!(
            current_start_job(&props(&retire).unwrap(), &retire_jobs, retire_unit, IID, 42)
                .unwrap(),
            731
        );
        // Historical recipes retain their stricter complete absence rule.
        assert!(no_triggers(&native).is_err());
    }
    #[test]
    fn empty_malformed_foreign_future_and_duplicate_start_jobs_reject() {
        for value in [
            "",
            "0",
            "0731",
            "+731",
            "731 ",
            " 731",
            "731x",
            "4294967296",
        ] {
            let text = owner().replace("Job=731", &format!("Job={value}"));
            assert!(
                current_start_job(&props(&text).unwrap(), &jobs(), UNIT, IID, 42).is_err(),
                "{value:?}"
            );
        }
        let text = owner();
        let native = props(&text).unwrap();
        for row in [
            String::new(),
            "No jobs running.\n".into(),
            format!("732 {UNIT} start running\n"),
            "731 foreign.service start running\n".into(),
            format!("731 {UNIT} stop running\n"),
            format!("731 {UNIT} start waiting\n"),
            format!("731 {UNIT} start done\n"),
            format!("731 {UNIT} start running extra\n"),
            format!("● 731 {UNIT} start running\n"),
            format!("{}{}", jobs(), jobs()),
            format!("{}731 foreign.service start running\n", jobs()),
            format!("{}732 {UNIT} start waiting\n", jobs()),
        ] {
            assert!(
                current_start_job(&native, &row, UNIT, IID, 42).is_err(),
                "{row:?}"
            );
        }
        let missing = text.replace("Job=731\n", "");
        assert!(current_start_job(&props(&missing).unwrap(), &jobs(), UNIT, IID, 42).is_err());
        assert!(props(&format!("{text}Job=731\n")).is_err());
    }
    #[test]
    fn job_ownership_never_substitutes_for_original_pid_iid_cgroup_or_trigger_checks() {
        for (old, new) in [
            (format!("Id={UNIT}"), "Id=foreign.service".into()),
            (
                format!("InvocationID={IID}"),
                format!("InvocationID={}", "a".repeat(32)),
            ),
            ("MainPID=42".into(), "MainPID=43".into()),
            ("Type=oneshot".into(), "Type=exec".into()),
            ("LoadState=loaded".into(), "LoadState=not-found".into()),
            ("ActiveState=activating".into(), "ActiveState=active".into()),
            ("SubState=start".into(), "SubState=running".into()),
            ("NRestarts=0".into(), "NRestarts=1".into()),
            (
                format!("ControlGroup=/system.slice/{UNIT}"),
                "ControlGroup=/system.slice/foreign.service".into(),
            ),
            ("Triggers=\n".into(), "Triggers=foreign.service\n".into()),
            (
                "TriggeredBy=\n".into(),
                "TriggeredBy=foreign.timer\n".into(),
            ),
            ("OnSuccess=\n".into(), "OnSuccess=foreign.service\n".into()),
            ("OnFailure=\n".into(), "OnFailure=foreign.service\n".into()),
            (
                "DropInPaths=\n".into(),
                "DropInPaths=/etc/override.conf\n".into(),
            ),
        ] {
            let text = owner().replace(&old, &new);
            assert!(
                current_start_job(&props(&text).unwrap(), &jobs(), UNIT, IID, 42).is_err(),
                "{new}"
            );
        }
        let text = owner();
        let native = props(&text).unwrap();
        assert!(current_start_job(&native, &jobs(), UNIT, IID, 0).is_err());
        assert!(current_start_job(&native, &jobs(), UNIT, "", 42).is_err());
    }
    #[test]
    fn original_start_job_and_owner_must_remain_stable_across_native_samples() {
        let first = owner();
        let before = props(&first).unwrap();
        unchanged_start_owner(&before, &before).unwrap();
        for (key, value) in &before {
            let changed = first.replace(&format!("{key}={value}\n"), &format!("{key}=changed\n"));
            assert!(
                unchanged_start_owner(&before, &props(&changed).unwrap()).is_err(),
                "{key}"
            );
            let missing = first.replace(&format!("{key}={value}\n"), "");
            assert!(
                unchanged_start_owner(&before, &props(&missing).unwrap()).is_err(),
                "{key}"
            );
        }
        let changed = first.replace("Job=731", "Job=732");
        let after = props(&changed).unwrap();
        assert_eq!(
            current_start_job(&after, &jobs().replace("731", "732"), UNIT, IID, 42).unwrap(),
            732
        );
        assert!(unchanged_start_owner(&before, &after).is_err());
    }
    #[test]
    #[ignore = "Root separately admitted fixed QA current oneshot, equivalent 2GiB/CPU2/Swap0/Tasks512/180s profile"]
    fn native_current_oneshot_proves_only_its_original_running_start_job() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let unit = "horizon-index944-fixed-current-job-native-v1.service";
        let iid = std::env::var("INVOCATION_ID").unwrap();
        let own = std::process::id();
        let ticks = start_ticks(&fs::read_to_string("/proc/self/stat").unwrap()).unwrap();
        let query = || {
            systemctl(&["show",unit,"--all","--property=Id,LoadState,InvocationID,MainPID,ControlPID,ActiveState,SubState,NRestarts,ControlGroup,Type,Job,Triggers,TriggeredBy,OnSuccess,OnFailure,DropInPaths,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,TimeoutStartUSec,ProtectSystem,ProtectHome,PrivateNetwork,NoNewPrivileges"]).unwrap()
        };
        let before = query();
        let m = props(&before).unwrap();
        for (key, value) in [
            ("MemoryMax", "2147483648"),
            ("MemorySwapMax", "0"),
            ("CPUQuotaPerSecUSec", "2s"),
            ("TasksMax", "512"),
            ("TimeoutStartUSec", "3min"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "read-only"),
            ("PrivateNetwork", "yes"),
            ("NoNewPrivileges", "yes"),
        ] {
            assert_eq!(m.get(key), Some(&value), "{key}");
        }
        let group = format!("0::/system.slice/{unit}\n");
        assert_eq!(fs::read_to_string("/proc/self/cgroup").unwrap(), group);
        let status = fs::read_to_string("/proc/self/status").unwrap();
        assert!(status.lines().any(|l| l == "CapEff:\t0000000000080002"));
        assert!(status.lines().any(|l| l == "NoNewPrivs:\t1"));
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) },
            0
        );
        assert!(limit.rlim_cur >= LIMIT + 1 && limit.rlim_max >= LIMIT + 1);
        let cgroup = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{unit}"));
        for (file, expected) in [
            ("memory.max", "2147483648"),
            ("memory.swap.max", "0"),
            ("pids.max", "512"),
        ] {
            assert_eq!(
                fs::read_to_string(cgroup.join(file)).unwrap().trim(),
                expected
            );
        }
        let cpu = fs::read_to_string(cgroup.join("cpu.max")).unwrap();
        let parts: Vec<_> = cpu.split_whitespace().collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(
            parts[0].parse::<u64>().unwrap(),
            parts[1].parse::<u64>().unwrap().checked_mul(2).unwrap()
        );
        let jobs = systemctl(&["list-jobs", "--no-legend", "--no-pager", "--plain"]).unwrap();
        let original = current_start_job(&m, &jobs, unit, &iid, own).unwrap();
        assert!(no_triggers(&m).is_err());
        let after = query();
        let last = props(&after).unwrap();
        let final_jobs = systemctl(&["list-jobs", "--no-legend", "--no-pager", "--plain"]).unwrap();
        assert_eq!(
            current_start_job(&last, &final_jobs, unit, &iid, own).unwrap(),
            original
        );
        unchanged_start_owner(&m, &last).unwrap();
        assert_eq!(
            start_ticks(&fs::read_to_string("/proc/self/stat").unwrap()).unwrap(),
            ticks
        );
        assert_eq!(fs::read_to_string("/proc/self/cgroup").unwrap(), group);
        println!(
            "{}",
            json!({"schema":"horizon-index944-actual-current-start-job-native-v1","unit":unit,"invocation_id":iid,"pid":own,"start_ticks":ticks,"job_id":original,"before":m,"after":last,"list_jobs_before":jobs,"list_jobs_after":final_jobs,"actual_profile_verified":true,"historical_no_job_rule_still_rejects_current":true,"production_current_operation_authenticated":false,"fixture_only":true})
        );
    }
}
