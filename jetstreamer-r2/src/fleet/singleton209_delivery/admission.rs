//! Metadata admission for one bounded full 209 delivery attempt.
//! Existing independent archive and authenticated delivery gates remain separate.
use super::*;

const HELPER: &str = "/var/lib/jetstreamer/horizon-full210-memory-c09acf84-v1/jetstreamer-r2";
const HELPER_SHA: &str = "77cdcbacc33e375ce38d198b3b3e92822d97e97e1103f68c233e88523126a6e9";
const FILE_LIMIT: u64 = 64 << 20;
const METADATA: u64 = 1 << 30;
const ADMISSION: &str = "jetstreamer-private-epoch209-singleton-delivery-admission-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionSpec {
    schema: String,
    delivery_spec: BoundFile,
    resource_basis: Value,
    unit_file: BoundFile,
    environment_file: Option<BoundFile>,
    output: PathBuf,
}

fn profile(stage: Stage) -> (u64, u64, u64) {
    match stage {
        Stage::Full => (16 << 30, 32 << 30, 86400),
        Stage::Plugin => (32 << 30, 64 << 30, 86400),
        Stage::Upload => (8 << 30, 16 << 30, 172800),
    }
}

fn token(path: &Path) -> Result<&str> {
    let value = path.to_str().context("209 delivery path is not UTF-8")?;
    ensure!(
        path.is_absolute()
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b)),
        "209 delivery path contains a systemd expansion or unsupported character"
    );
    Ok(value)
}

fn bound_file(binding: &BoundFile, maximum: u64, private: bool) -> Result<Vec<u8>> {
    let p = &binding.path;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.is_absolute()
            && p.canonicalize()? == *p
            && m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && (!private || m.mode() & 0o077 == 0),
        "209 delivery bound file has unsafe identity or permissions"
    );
    let bytes = read_stable_bounded(p, maximum, "209 delivery bound file")?;
    ensure!(
        is_lower_hex(&binding.sha256, 64)
            && hex_lower(&Sha256::digest(&bytes)) == binding.sha256
            && identity(&fs::symlink_metadata(p)?) == identity(&m),
        "209 delivery bound file changed or has the wrong digest"
    );
    Ok(bytes)
}

fn helper() -> Result<()> {
    let m = fs::symlink_metadata(HELPER)?;
    ensure!(
        m.mode() & 0o222 == 0 && m.mode() & 0o111 != 0,
        "209 delivery helper is writable or not executable"
    );
    bound_file(
        &BoundFile {
            path: HELPER.into(),
            sha256: HELPER_SHA.into(),
        },
        32 << 20,
        false,
    )?;
    Ok(())
}

fn empty_attempt(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-singleton-delivery-"))
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && fs::read_dir(path)?.next().is_none(),
        "209 delivery attempt must be fresh, empty, root-owned and private"
    );
    Ok(())
}

fn unit_text(s: &Spec, spec: &BoundFile, environment: Option<&BoundFile>) -> Result<String> {
    let (high, maximum, runtime) = profile(s.stage);
    let spec_path = token(&spec.path)?;
    let output = token(&s.output_directory)?;
    ensure!(
        is_lower_hex(&spec.sha256, 64),
        "209 delivery spec digest is invalid"
    );
    let upload = s.stage == Stage::Upload;
    ensure!(
        upload == environment.is_some(),
        "209 delivery credential scope differs"
    );
    let environment = if let Some(e) = environment {
        ensure!(
            e.path.starts_with("/home/ubuntu/.jetstreamer-private"),
            "209 delivery environment is outside the authorized private root"
        );
        format!(
            "Environment=TOKIO_WORKER_THREADS=8\nEnvironmentFile={}\n",
            token(&e.path)?
        )
    } else {
        String::new()
    };
    let write_receipts = if upload {
        format!("ReadWritePaths={R2_RECEIPTS}\n")
    } else {
        String::new()
    };
    let families = if upload {
        "AF_UNIX AF_INET AF_INET6"
    } else {
        "AF_UNIX"
    };
    Ok(format!(
        "[Unit]\nDescription=Full 209 {} delivery stage\nConditionPathExists={spec_path}\n\n[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\nExecStart={HELPER} deliver-singleton209-output {spec_path} --spec-sha256 {} --self-sha256 {HELPER_SHA}\nRestart=no\nRuntimeMaxSec={runtime}\nTimeoutStopSec=120\nKillMode=control-group\nOOMPolicy=stop\nMemoryAccounting=yes\nMemoryHigh={high}\nMemoryMax={maximum}\nMemorySwapMax=0\nTasksAccounting=yes\nTasksMax=512\nLimitFSIZE={FILE_LIMIT}:{FILE_LIMIT}\nLimitCORE=0\nCPUAccounting=yes\nCPUQuota=800%\nEnvironment=PATH=/usr/bin:/bin\nEnvironment=LC_ALL=C\n{environment}NoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE\nAmbientCapabilities=CAP_DAC_OVERRIDE\nProtectSystem=strict\nProtectHome=read-only\nPrivateTmp=yes\nInaccessiblePaths=/tmp /var/tmp\nPrivateDevices=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nRestrictSUIDSGID=yes\nRestrictAddressFamilies={families}\nReadWritePaths={output}\n{write_receipts}StandardOutput=append:{output}/coordinator.log\nStandardError=inherit\n",
        s.stage.name(),
        spec.sha256
    ))
}

fn effective(s: &Spec, file: &BoundFile) -> Result<BTreeMap<String, String>> {
    ensure!(
        file.path == Path::new("/etc/systemd/system").join(s.stage.unit()),
        "209 delivery fragment is not its exact unit"
    );
    let out = ProcessCommand::new("/usr/bin/systemctl").args([
        "show", s.stage.unit(), "--no-pager",
        "--property=Id,LoadState,Type,User,Group,Restart,FragmentPath,DropInPaths,NeedDaemonReload,Transient,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,LimitFSIZE,LimitFSIZESoft,LimitCORE,LimitCORESoft,NoNewPrivileges",
    ]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "209 delivery effective unit lookup failed"
    );
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("209 delivery unit property is malformed")?;
        ensure!(
            result.insert(k.to_owned(), v.to_owned()).is_none(),
            "209 delivery effective property is duplicated"
        );
    }
    let (high, maximum, _) = profile(s.stage);
    for (key, expected) in [
        ("Id", s.stage.unit().to_owned()),
        ("LoadState", "loaded".into()),
        ("Type", "exec".into()),
        ("User", "root".into()),
        ("Group", "root".into()),
        ("Restart", "no".into()),
        ("FragmentPath", token(&file.path)?.into()),
        ("DropInPaths", String::new()),
        ("NeedDaemonReload", "no".into()),
        ("Transient", "no".into()),
        ("MemoryHigh", high.to_string()),
        ("MemoryMax", maximum.to_string()),
        ("MemorySwapMax", "0".into()),
        ("TasksMax", "512".into()),
        ("LimitFSIZE", FILE_LIMIT.to_string()),
        ("LimitFSIZESoft", FILE_LIMIT.to_string()),
        ("LimitCORE", "0".into()),
        ("LimitCORESoft", "0".into()),
        ("NoNewPrivileges", "yes".into()),
    ] {
        ensure!(
            result.get(key) == Some(&expected),
            "209 delivery effective property differs: {key}"
        );
    }
    Ok(result)
}

fn no_downstream_owner(current: &BTreeMap<String, Value>) -> Result<()> {
    for stage in [Stage::Full, Stage::Plugin, Stage::Upload] {
        let u = &current[stage.unit()];
        ensure!(
            u["MainPID"] == "0"
                && u["NRestarts"] == "0"
                && matches!(u["ActiveState"].as_str(), Some("inactive" | "failed"))
                && matches!(u["SubState"].as_str(), Some("dead" | "failed")),
            "209 delivery overlaps an active or restarted downstream owner"
        );
    }
    Ok(())
}

fn pending() -> Result<()> {
    let out = ProcessCommand::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--plain", "--no-pager"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "209 delivery pending job lookup failed"
    );
    ensure!(
        !std::str::from_utf8(&out.stdout)?
            .split_whitespace()
            .any(|word| [Stage::Full, Stage::Plugin, Stage::Upload]
                .iter()
                .any(|s| word == s.unit())),
        "209 delivery has a pending downstream job"
    );
    Ok(())
}

pub(in crate::fleet) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-singleton209-delivery")?;
    let a: AdmissionSpec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    ensure!(
        a.schema == "jetstreamer-private-epoch209-singleton-delivery-admission-spec-v1"
            && a.output.file_name().is_some_and(|n| n == "admission.json")
            && a.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && a.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-209-singleton-delivery-admission-")),
        "209 delivery admission scope differs"
    );
    validate_output_destination(&a.output)?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&a.delivery_spec)?)?;
    ensure!(
        s.schema == "jetstreamer-private-epoch209-singleton-delivery-spec-v1"
            && s.r2_mutations == (s.stage == Stage::Upload)
            && s.r2_receipt_directory == Path::new(R2_RECEIPTS)
            && s.upload_lock == Path::new(LOCK),
        "209 delivery stage spec scope differs"
    );
    ensure!(
        a.output.parent() != Some(s.output_directory.as_path()),
        "209 delivery admission receipt must remain outside the writable attempt"
    );
    empty_attempt(&s.output_directory)?;
    helper()?;
    let expected = unit_text(&s, &a.delivery_spec, a.environment_file.as_ref())?;
    ensure!(
        bound_file(&a.unit_file, 64 << 10, false)? == expected.as_bytes(),
        "209 delivery fragment differs from the closed bounded profile"
    );
    if let Some(e) = &a.environment_file {
        bound_file(e, 64 << 10, true)?;
    }
    let (_, launch) = full209_status::claim(&s.launch)?;
    let terminal = source_terminal(&launch)?;
    let output = Path::new(c::ROOT).join("output");
    ensure!(
        output.canonicalize()? == output,
        "209 delivery archive directory was redirected"
    );
    let archive = read_local_archive(&output, 209)?;
    cohort(&native209::immutable_json(&s.cohort_publication)?, &archive)?;
    match s.stage {
        Stage::Full => ensure!(
            s.full_verification.is_none() && s.plugin_verification.is_none(),
            "209 full admission borrowed future verification receipts"
        ),
        Stage::Plugin => {
            ensure!(
                s.plugin_verification.is_none(),
                "209 plugin admission borrowed its own receipt"
            );
            prior(
                s.full_verification.as_ref(),
                Stage::Full,
                &s,
                &archive,
                HELPER_SHA,
            )?;
        }
        Stage::Upload => {
            prior(
                s.full_verification.as_ref(),
                Stage::Full,
                &s,
                &archive,
                HELPER_SHA,
            )?;
            prior(
                s.plugin_verification.as_ref(),
                Stage::Plugin,
                &s,
                &archive,
                HELPER_SHA,
            )?;
        }
    }
    // This is only a local serialization preflight. The delivery helper must
    // independently acquire the same lock for its actual authenticated upload.
    let _upload_lock = if s.stage == Stage::Upload {
        Some(lock()?)
    } else {
        None
    };
    let fleet_binding: BoundFile = serde_json::from_value(a.resource_basis["fleet"].clone())?;
    let f = bound_json(&fleet_binding)?;
    ensure!(
        !f["active"]
            .as_array()
            .context("209 delivery complete active census missing")?
            .iter()
            .any(|r| r["epoch"] == 209),
        "209 delivery still has active work"
    );
    let mut names = f["unit_census"]
        .as_object()
        .context("209 delivery unit census missing")?
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    names.insert(c::UNIT.into());
    for stage in [Stage::Full, Stage::Plugin, Stage::Upload] {
        names.insert(stage.unit().into());
    }
    let before = census(&names, 201, 300)?;
    no_downstream_owner(&before)?;
    pending()?;
    let properties = effective(&s, &a.unit_file)?;
    let capacity = maintenance_capacity::check_singleton209_delivery(
        &a.resource_basis,
        maintenance_capacity::Candidate {
            additional_bytes: METADATA,
            memory_max_bytes: profile(s.stage).1,
            minimum_protected_disk_bytes: singleton227_admission::century_floor_for_maintenance(
                &f,
            )?,
        },
    )?;
    let after = census(&names, 201, 300)?;
    no_downstream_owner(&after)?;
    pending()?;
    ensure!(
        before == after
            && properties == effective(&s, &a.unit_file)?
            && terminal == source_terminal(&launch)?
            && pair_identity(&read_local_archive(&output, 209)?) == pair_identity(&archive),
        "209 delivery owner, unit, terminal or pair changed during admission"
    );
    ensure!(
        bound_file(&a.unit_file, 64 << 10, false)? == expected.as_bytes(),
        "209 delivery unit file changed during admission"
    );
    if let Some(e) = &a.environment_file {
        bound_file(e, 64 << 10, true)?;
    }
    helper()?;
    empty_attempt(&s.output_directory)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    private157::immutable_receipt(
        &a.output,
        &json!({
            "schema":ADMISSION,"epoch":209,"stage":s.stage.name(),"admitted":true,
            "unit":s.stage.unit(),"maximum_age_seconds":900,"recorded_unix_seconds":now,
            "delivery_spec":private157::binding(&a.delivery_spec),"spec":private157::binding(&binding),
            "control_helper_sha256":self_sha,"delivery_helper_path":HELPER,"delivery_helper_sha256":HELPER_SHA,
            "launch":private157::binding(&s.launch),"cohort_publication":private157::binding(&s.cohort_publication),
            "origin_unit":c::UNIT,"origin_invocation_id":launch["evidence"]["units"][0]["invocation_id"],
            "producer_terminal":terminal,"archive_metadata_only":pair_identity(&archive),
            "capacity":capacity,"unit_file":private157::binding(&a.unit_file),"effective_unit":properties,
            "unit_census_before":before,"unit_census_after":after,"resource_basis":a.resource_basis,
            "environment_file":a.environment_file.as_ref().map(private157::binding),
            "log_file_limit_bytes":FILE_LIMIT,"new_metadata_allowance_bytes":METADATA,
            "fresh_empty_attempt_directory":s.output_directory,"actual_stage_invocation_captured":false,
            "new_resource_samples":0,"archive_body_reads":0,"replay_launch_authorized":false,
            "runtime_promotion_authorized":false,"full_epoch_qualified":false,"canonical_sidecar_authorized":false,
            "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_caps_and_file_census_are_closed() {
        assert_eq!(profile(Stage::Full), (16 << 30, 32 << 30, 86400));
        assert_eq!(profile(Stage::Plugin), (32 << 30, 64 << 30, 86400));
        assert_eq!(profile(Stage::Upload), (8 << 30, 16 << 30, 172800));
        assert!(4 * FILE_LIMIT < METADATA);
        for p in [
            "/tmp/bad%209",
            "/tmp/bad path",
            "/tmp/bad\npath",
            "relative",
        ] {
            assert!(token(Path::new(p)).is_err());
        }
        assert!(token(Path::new("/var/lib/jetstreamer/epoch-209.json")).is_ok());
    }

    #[test]
    fn admission_spec_rejects_borrowed_authority_and_unknown_fields() {
        let b = json!({"path":"/sealed/a.json","sha256":"a".repeat(64)});
        let mut v = json!({"schema":"future","delivery_spec":b,"resource_basis":{},
            "unit_file":b,"environment_file":null,"output":"/private/admission.json"});
        assert!(serde_json::from_value::<AdmissionSpec>(v.clone()).is_ok());
        for key in [
            "ignore_peer",
            "publication_authorized",
            "r2_mutations",
            "memory_max_bytes",
        ] {
            v[key] = json!(true);
            assert!(serde_json::from_value::<AdmissionSpec>(v.clone()).is_err());
            v.as_object_mut().unwrap().remove(key);
        }
    }

    fn specimen(stage: Stage) -> Spec {
        let b = || BoundFile {
            path: "/sealed/evidence.json".into(),
            sha256: "a".repeat(64),
        };
        Spec {
            schema: "jetstreamer-private-epoch209-singleton-delivery-spec-v1".into(),
            stage,
            launch: b(),
            cohort_publication: b(),
            full_verification: None,
            plugin_verification: None,
            output_directory: "/var/lib/jetstreamer/horizon-209-singleton-delivery-test".into(),
            r2_receipt_directory: R2_RECEIPTS.into(),
            upload_lock: LOCK.into(),
            r2_mutations: stage == Stage::Upload,
        }
    }

    #[test]
    fn closed_unit_keeps_regular_logs_limits_and_credential_scope() {
        let b = BoundFile {
            path: "/sealed/spec.json".into(),
            sha256: "a".repeat(64),
        };
        let full = unit_text(&specimen(Stage::Full), &b, None).unwrap();
        for line in [
            "Type=exec",
            "Restart=no",
            "LimitFSIZE=67108864:67108864",
            "LimitCORE=0",
            "MemoryMax=34359738368",
            "TasksMax=512",
            "InaccessiblePaths=/tmp /var/tmp",
            "StandardError=inherit",
        ] {
            assert!(full.lines().any(|l| l == line));
        }
        assert!(full.contains("StandardOutput=append:/var/lib/jetstreamer/horizon-209-singleton-delivery-test/coordinator.log\n"));
        assert!(!full.contains("EnvironmentFile="));
        assert!(unit_text(&specimen(Stage::Upload), &b, None).is_err());
        let e = BoundFile {
            path: "/home/ubuntu/.jetstreamer-private/r2.env".into(),
            sha256: "b".repeat(64),
        };
        assert!(unit_text(&specimen(Stage::Full), &b, Some(&e)).is_err());
        let upload = unit_text(&specimen(Stage::Upload), &b, Some(&e)).unwrap();
        assert!(upload.contains("EnvironmentFile=/home/ubuntu/.jetstreamer-private/r2.env\n"));
        assert!(upload.contains("MemoryMax=17179869184\n"));
        assert!(upload.contains("ReadWritePaths=/home/ubuntu/.jetstreamer-private/r2-receipts\n"));
    }

    #[test]
    fn downstream_overlap_and_restart_history_refuse_admission() {
        let mut current = BTreeMap::new();
        for stage in [Stage::Full, Stage::Plugin, Stage::Upload] {
            current.insert(
                stage.unit().into(),
                json!({"MainPID":"0", "NRestarts":"0",
                "ActiveState":"inactive", "SubState":"dead"}),
            );
        }
        assert!(no_downstream_owner(&current).is_ok());
        for (key, value) in [
            ("MainPID", "123"),
            ("NRestarts", "1"),
            ("ActiveState", "activating"),
            ("SubState", "running"),
        ] {
            let mut bad = current.clone();
            bad.get_mut(Stage::Plugin.unit()).unwrap()[key] = json!(value);
            assert!(no_downstream_owner(&bad).is_err());
        }
    }

    #[test]
    fn regular_file_limit_is_inherited_and_preserves_failed_log_bytes() {
        use std::os::unix::process::CommandExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("limited.log");
        let mut command = ProcessCommand::new(env::current_exe().unwrap());
        command
            .args([
                "fleet::singleton209_delivery::admission::tests::limited_child",
                "--exact",
                "--ignored",
            ])
            .env("JETSTREAMER_209_LIMIT_TEST_PATH", &path);
        // Only the child inherits this hard limit. Ignoring SIGXFSZ lets its
        // assertion observe EFBIG while preserving every byte already written.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: FILE_LIMIT,
                    rlim_max: FILE_LIMIT,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        assert!(command.status().unwrap().success());
        assert_eq!(fs::metadata(&path).unwrap().len(), FILE_LIMIT);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    #[ignore = "bounded subprocess fixture; invoked only by the inheritance test"]
    fn limited_child() {
        let path = env::var_os("JETSTREAMER_209_LIMIT_TEST_PATH").expect("explicit test path");
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, limit.as_mut_ptr()) },
            0
        );
        let limit = unsafe { limit.assume_init() };
        assert_eq!(limit.rlim_cur, FILE_LIMIT);
        assert_eq!(limit.rlim_max, FILE_LIMIT);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        let block = vec![7u8; 1 << 20];
        for _ in 0..64 {
            file.write_all(&block).unwrap();
        }
        assert_eq!(
            file.write_all(&[8]).unwrap_err().raw_os_error(),
            Some(libc::EFBIG)
        );
        file.sync_all().unwrap();
    }
}
