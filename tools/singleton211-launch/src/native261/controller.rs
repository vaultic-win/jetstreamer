fn pristine(disk: u64) -> Result<Value> {
    let mount = tmpfs::observe(true)?;
    ensure!(
        mount.device != disk
            && mount.bytes == 0
            && mount.free_inodes >= tmpfs::INODES - 1
            && fs::read_dir(ROOT)?.next().is_none(),
        "{EPOCH} scratch must be an independent empty tmpfs"
    );
    Ok(
        json!({"root":ROOT,"device":mount.device,"inode":mount.inode,"bytes":tmpfs::BYTES,
        "inodes":tmpfs::INODES,"free_inodes":mount.free_inodes,"used_bytes":mount.bytes,
        "maximum_root_physical_bytes":ROOT_CAP,"minimum_free_bytes":tmpfs::BYTES-ROOT_CAP,
        "minimum_free_inodes":4096,"charged_within_memory_max":true}),
    )
}

fn review_scope(n: &mut Native, r: &Value, self_sha: &str, prepare_only: bool) -> Result<()> {
    use native257::publication::SourceScope;
    no_authority(r)?;
    ensure!(
        r["schema"] == format!("horizon-native{EPOCH}-launch-review-v1")
            && r["epoch"] == EPOCH
            && r["Main_accepted"] == true
            && r["single_campaign_controller_confirmed"] == true
            && matches!(
                r["operation"].as_str(),
                Some("native-cold" | "qualify-guard")
            )
            && launch::safe_attempt(text(r, "attempt")?)
            && r["guard"] == json!(Bound::new(GUARD, GUARD_SHA)),
        "unaccepted {EPOCH} review"
    );
    native257::controller_scope(r)?;
    units::affinity(r)?;
    let source = binding(&r["source_publication"])?.sealed()?;
    let source_scope = if prepare_only {
        SourceScope::Preparation
    } else if EPOCH == 262 && qualify(r)? {
        SourceScope::ProtectiveStop
    } else {
        SourceScope::Runtime
    };
    native257::publication::validate_native(
        n,
        &source,
        &Bound::new(GUARD, GUARD_SHA),
        self_sha,
        source_scope,
        &native257::publication::SourceProfile {
            epoch: EPOCH,
            harness: Bound::new(INPUT, INPUT_SHA),
            worker: Bound::new(WORKER, WORKER_SHA),
        },
    )?;
    let verified: Value = serde_json::from_slice(&n.run(INPUT, &["--validate-inputs"])?)?;
    ensure!(
        verified["schema"] == format!("horizon{EPOCH}-sealed-input-validation-v1")
            && verified["input_packet_sha256"] == PACKET_SHA
            && verified["bootstrap_slot"] == SLOT
            && verified["measured_identities_accepted"] == true
            && verified["worker_started"] == false
            && verified["replay_launch_authorized"] == false,
        "{EPOCH} measured input validation differs"
    );
    Ok(())
}

fn evaluate(
    n: &mut Native,
    r: &Value,
    source: &Bound,
    timed_stop: bool,
) -> Result<(Value, peer_window::Window)> {
    let initial = funding::current(n, r, false)?;
    let mut context = json!({"epoch":EPOCH,"boot_id":initial["boot_id"],"review":source,
        "actual_current_memory":initial["actual_current_memory"]});
    if EPOCH == 262 {
        context["foundation_roster"] = initial["foundation_roster"].clone();
    }
    let limit = n.deadline.context("admission clock")?;
    let (current, mut peers) = if timed_stop {
        // Finish both full funding views before binding a guard firing. Startup
        // takes another complete census immediately before starting the producer.
        let before = mono()?;
        let current = funding::current(n, r, false)?;
        let minimum = crate::native261::stop_window(
            mono()?
                .checked_sub(before)
                .context("funding clock decreased")?,
        )?;
        let mut latest = context;
        latest["actual_current_memory"] = current["actual_current_memory"].clone();
        let peers = peer_window::select_minimum(n, r, &latest, minimum)?;
        ensure!(
            peers.limit.min(limit).saturating_sub(mono()?) >= minimum - 5_000_000,
            "261 operator or peer window too short after selection"
        );
        (current, peers)
    } else {
        let peers = peer_window::capture(n, r, &context)?;
        n.deadline = Some(limit.min(peers.limit));
        (funding::current(n, r, false)?, peers)
    };
    n.deadline = Some(limit.min(peers.limit));
    ensure!(
        current["tmpfs"] == initial["tmpfs"]
            && current["disk_device"] == initial["disk_device"]
            && current["boot_id"] == initial["boot_id"],
        "capacity devices or boot changed"
    );
    peers.verify(n)?;
    let issued = now()?;
    let clock = mono()?;
    let end = if timed_stop {
        peers.limit.min(limit)
    } else {
        peers.limit
    };
    let remaining = end.checked_sub(clock).context("original guards expired")? / 1_000_000;
    let valid = remaining.min(60);
    ensure!(valid > 0, "no current owner guard window remains");
    n.check()?;
    let mut value = json!({"schema":ADMISSION_SCHEMA,"epoch":EPOCH,"mode":"native-cold",
        "operation":r["operation"],"unit":UNIT,"guard_unit":GUARD_UNIT,"timer":TIMER,"admitted":true,
        "harness":Bound::new(INPUT,INPUT_SHA),"guard":Bound::new(GUARD,GUARD_SHA),
        "worker":Bound::new(WORKER,WORKER_SHA),"input_packet":Bound::new(PACKET,PACKET_SHA),
        "maximum_memory_bytes":MEMORY,"maximum_root_physical_bytes":ROOT_CAP,"candidate_incremental_peak_bytes":DISK_RECEIPTS,
        "protected_existing_floor_bytes":current["capacity"]["protected_existing_floor_bytes"],
        "disk_filesystem":FILESYSTEM,"disk_device":current["disk_device"],"tmpfs":current["tmpfs"],
        "boot_id":current["boot_id"],"source_publication":r["source_publication"],"review":source,"fleet":r["fleet"],
        "observer":r["observer"],"reservation_ledger":r["reservation_ledger"],"century":r["century"],
        "actual_current_memory":current["actual_current_memory"],"capacity":current,"cpu_affinity":r["cpu_affinity"],
        "peer_window":peers.receipt,"original_peer_deadline_monotonic_us":peers.limit,
        "issued_unix_seconds":issued,"expires_unix_seconds":issued.checked_add(valid).context("admission expiry")?,
        "guard_token_issued":false,"scratch_release_authorized":false});
    deny_authority(&mut value);
    Ok((value, peers))
}
fn check_sandbox(v: &Value) -> Result<()> {
    ensure!(
        v["PrivateDevices"] == "yes"
            && v["WorkingDirectory"] == ROOT
            && v["ProtectControlGroups"] == "yes"
            && v["RestrictAddressFamilies"] == "AF_UNIX"
            && v["OOMPolicy"] == "kill"
            && v["OOMScoreAdjust"] == "1000"
            && v["AmbientCapabilities"] == ""
            && text(v, "InaccessiblePaths")?
                .split_whitespace()
                .collect::<BTreeSet<_>>()
                == BTreeSet::from(["/tmp", "/var/tmp", "/dev/shm"]),
        "{EPOCH} producer sandbox changed"
    );
    Ok(())
}
fn prepared_transition(
    reference: &Bound,
    gate: &Bound,
    current: &Bound,
    old: &Value,
    new: &Value,
) -> Result<()> {
    let mut prepared = publication::prepared_artifacts(old)?;
    let mut successor = publication::prepared_artifacts(new)?;
    ensure!(
        prepared["launcher"]["artifact"] == json!(gate)
            && successor["launcher"]["artifact"] == json!(current),
        "unbound prepared or running launcher"
    );
    if gate != current {
        ensure!(
            permits_predecessor(reference, gate, &prepared["launcher"]["source_commit"])
                && current.path == Path::new(LAUNCHER),
            "unknown inert {EPOCH} launcher succession"
        );
        prepared.remove("launcher");
        successor.remove("launcher");
    }
    ensure!(
        prepared == successor,
        "prepared {EPOCH} images or source changed"
    );
    Ok(())
}
fn refreshed_capacity(n: &mut Native, r: &Value, held: bool) -> Result<Value> {
    let mut latest = funding::current(n, r, held)?;
    latest["protected_existing_floor_bytes"] =
        latest["capacity"]["protected_existing_floor_bytes"].clone();
    Ok(latest)
}
fn package(attempt: &str, kind: &str) -> PathBuf {
    PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native{EPOCH}-{kind}-{attempt}"
    ))
}
fn qualify(r: &Value) -> Result<bool> {
    match r["operation"].as_str() {
        Some("qualify-guard") => Ok(true),
        Some("native-cold") => Ok(false),
        _ => bail!("unknown native{EPOCH} operation"),
    }
}
fn prestart(r: &Value) -> Result<()> {
    let qual = qualify(r)?;
    if EPOCH == 262 && qual {
        return crate::native262::protective_stop_prestart(r);
    }
    let lifecycle = binding(&r["prestart_qualification"])?.sealed()?;
    ensure!(
        lifecycle["schema"] == format!("horizon-native{EPOCH}-prestart-qualification-v1")
            && lifecycle["Main_accepted"] == true
            && lifecycle["harness"] == json!(Bound::new(HARNESS, HARNESS_SHA))
            && lifecycle["guard"] == r["guard"]
            && lifecycle["source_publication"] == r["source_publication"]
            && lifecycle["complete_live_terminal_and_inactive_consumers_accepted"] == true
            && lifecycle["first_guard_required_before_snapshot"] == true
            && lifecycle["native_runtime_qualified"] == false,
        "native prestart lifecycle missing"
    );
    no_authority(&lifecycle)?;
    for k in [
        "fleet",
        "observer",
        "inactive_status",
        "terminal_retention",
        "startup_gate",
    ] {
        binding(&lifecycle["evidence"][k])?.sealed()?;
    }
    if !qual {
        let qualification = binding(&r["protective_stop_qualification"])?.sealed()?;
        stop::accepted(&qualification)?;
        retire::validate_capture(&binding(&qualification["capture"])?.sealed()?)?;
        let retirement = binding(&qualification["retirement"])?.sealed()?;
        ensure!(
            retirement["capture"] == qualification["capture"]
                && retirement["all_four_links_removed"] == true
                && retirement["kernel_drained"] == true
                && retirement["token_absent"] == true
                && retirement["after"]
                    .as_object()
                    .is_some_and(|v| v.len() == 4),
            "incomplete qualification retirement"
        );
    }
    Ok(())
}
/// Authenticate the original on-host startup graph without taking another resource sample.
pub fn validate_saved_handoff(path: &Path, sha: &str) -> Result<Value> {
    ensure!(
        path.starts_with("/var/lib/jetstreamer"),
        "handoff namespace"
    );
    trusted_parents(path)?;
    let h = Bound::new(path, sha).json()?;
    handoff::reopen(&h)?;
    Ok(h)
}
pub fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "validate-handoff" {
        let h = validate_saved_handoff(Path::new(&args[2]), &args[3])?;
        println!(
            "{}",
            json!({"epoch":EPOCH,"invocation_id":h["invocation_id"],"historical_startup_accepted":true,"entry_replay":false,"admission_authorized":false})
        );
        return Ok(());
    }
    ensure!(
        args.len() == 6
            && matches!(
                args[1].as_str(),
                "prepare" | "admit" | "launch" | "qualify-guard" | "retire-qualification"
            ),
        "usage: horizon-native{EPOCH}-launch prepare|admit|launch|qualify-guard|retire-qualification REVIEW_OR_CAPTURE SHA256 SELF_SHA256 NEW_EVIDENCE_DIRECTORY"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && fs::canonicalize("/proc/self/exe")? == Path::new(LAUNCHER)
            && hex(&args[4], 64)
            && hash(Path::new("/proc/self/exe"))? == args[4],
        "sealed launcher identity"
    );
    let rf = Bound::new(&args[2], &args[3]);
    let r = rf.sealed()?;
    let _campaign_lock = if EPOCH == 262 {
        Some(crate::native262::foundation_roster::cadence_lock()?)
    } else {
        None
    };
    let root = PathBuf::from(&args[5]);
    ensure!(
        root.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && root
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(&format!("horizon-native{EPOCH}-execution-"))),
        "execution namespace"
    );
    absent(&root)?;
    trusted_parents(&root)?;
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let mut n = Native {
        root,
        counter: 0,
        deadline: Some(
            mono()?
                .checked_add(180_000_000)
                .context("controller deadline")?,
        ),
    };
    let result = (|| {
        if args[1] == "retire-qualification" {
            return retire::run(&mut n, &rf, &r);
        }
        review_scope(&mut n, &r, &args[4], args[1] == "prepare")?;
        if args[1] == "prepare" {
            return units::prepare(&mut n, &r, &rf, &args[4]);
        }
        ensure!(
            args[1] == "admit" || (args[1] == "qualify-guard") == qualify(&r)?,
            "operation mismatch"
        );
        ensure!(EPOCH != 262 || args[1] != "admit" || r["synchronize_peer_guards"] != true,
            "read-only epoch 262 admission cannot advance guard firings");
        if args[1] != "admit" {
            prestart(&r)?;
        }
        let (a, peers) = evaluate(
            &mut n,
            &r,
            &rf,
            matches!(EPOCH, 261 | 266) && args[1] == "qualify-guard",
        )?;
        if args[1] == "admit" {
            println!(
                "{}",
                serde_json::to_string(&save_json(&n.root, "admission.json", &a)?)?
            );
            Ok(())
        } else {
            startup::run(&mut n, &r, &args[4], &a, Some(peers))
        }
    })();
    if let Err(ref e) = result {
        let _ = save_json(
            &n.root,
            "failure.json",
            &json!({"error":format!("{e:#}"),"automatic_retry":false,"remote_mutations":false}),
        );
    }
    result
}
