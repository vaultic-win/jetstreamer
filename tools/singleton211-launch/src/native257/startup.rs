// The first fire and token publish within the original owner and peer deadlines.
use super::first_guard::first_guard;
use super::*;
use std::os::unix::fs::DirBuilderExt;
pub(super) struct FirstGuardProof {
    pub plan: Bound,
    pub sample: Bound,
    pub journal: Bound,
}

pub(super) fn cold_input_token(
    startup: &Value,
    startup_sha: &str,
    guard_plan: &Value,
    guard_iid: &str,
    proof: FirstGuardProof,
    recorded_us: u64,
) -> Value {
    let mut token = json!({
        "schema": TOKEN_SCHEMA,
        "startup_plan_sha256": startup_sha,
        "unit": UNIT,
        "invocation_id": guard_plan["invocation_id"],
        "main_pid": guard_plan["native_main"]["main_pid"],
        "harness": startup["harness"],
        "guard": startup["guard"],
        "boot_id": startup["boot_id"],
        "admission": startup["admission"],
        "guard_invocation_id": guard_iid,
        "guard_plan": proof.plan,
        "guard_sample": proof.sample,
        "guard_pid1_journal": proof.journal,
        "recorded_monotonic_us": recorded_us,
    });
    deny_authority(&mut token);
    token
}
fn verify_mount(alias: &Path, actual: &Path) -> Result<()> {
    let m = fs::symlink_metadata(alias)?;
    ensure!(
        m.file_type().is_symlink()
            && m.uid() == 0
            && m.gid() == 0
            && fs::read_link(alias)? == actual
            && alias.canonicalize()? == actual
            && actual.canonicalize()? == actual,
        "guard receipt alias changed"
    );
    let m = fs::symlink_metadata(actual)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == 0o700,
        "guard receipt directory changed"
    );
    Ok(())
}
fn create_receipt_mount(alias: &Path, iid: &str) -> Result<PathBuf> {
    ensure!(hex(iid, 32), "invalid held owner");
    let actual = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native{EPOCH}-guard-receipts-{iid}"
    ));
    trusted_parents(alias)?;
    trusted_parents(&actual)?;
    absent(alias)?;
    absent(&actual)?;
    fs::DirBuilder::new().mode(0o700).create(&actual)?;
    symlink(&actual, alias)?;
    File::open(alias.parent().context("receipt parent")?)?.sync_all()?;
    verify_mount(alias, &actual)?;
    Ok(actual)
}
fn preserves_admitted_space(latest: &Value, a: &Value, guard_floor: u64) -> Result<()> {
    let original = num(a, "protected_existing_floor_bytes")?;
    let refreshed = num(latest, "protected_existing_floor_bytes")?;
    let available = num(&latest["capacity"], "observed_available_bytes")?;
    let required = capacity::add(original.max(refreshed), RESERVATION)?;
    ensure!(
        guard_floor >= original.max(refreshed),
        "guard floor {guard_floor} does not cover admitted {original} and refreshed {refreshed} bytes"
    );
    ensure!(
        available >= required,
        "available {available} bytes below {required} required (admitted {original}, refreshed {refreshed}, reservation {RESERVATION})"
    );
    Ok(())
}

pub(super) fn run(
    n: &mut Native,
    review: &Value,
    self_sha: &str,
    a: &Value,
    selected: Option<peer_window::Window>,
) -> Result<()> {
    let qualification = qualify(review)?;
    let attempt = text(review, "attempt")?;
    ensure!(crate::launch::safe_attempt(attempt), "attempt namespace");
    let affinity = units::affinity(review)?;
    units::pristine()?;
    Bound::new(HARNESS, HARNESS_SHA).artifact()?;
    let guard = binding(&review["guard"])?;
    guard.artifact()?;
    let prepared = units::accepted(n, review, self_sha, a)?;
    let admitted = package(attempt, "admission");
    let startup = package(attempt, "startup-plan");
    let producer_package = package(attempt, "producer");
    let guard_binding = package(attempt, "guard-binding");
    let proof_package = package(attempt, "first-fire");
    let receipt_mount = package(attempt, "receipt-mount");
    for path in [
        &admitted,
        &startup,
        &guard_binding,
        &proof_package,
        &receipt_mount,
    ] {
        absent(path)?;
    }
    let mut peers = match selected {
        Some(window) => window,
        None => peer_window::capture(n, review, a)?,
    };
    let ar = save_json(&n.root, "admission.json", a)?;
    n.seal(
        &admitted,
        &[
            ("admission.json", ar.clone()),
            ("peer-window.json", peers.receipt.clone()),
        ],
    )?;
    let wr = Bound::new(admitted.join("peer-window.json"), &peers.receipt.sha256);
    let ar = Bound::new(admitted.join("admission.json"), ar.sha256);

    let token_root = Path::new(TOKENS);
    let m = fs::symlink_metadata(token_root)?;
    ensure!(
        token_root.canonicalize()? == token_root
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o022 == 0,
        "unsafe startup token root"
    );
    trusted_parents(&token_root.join("future"))?;
    // One original 60s gate window includes plan sealing and all manager work.
    let issued = mono()?;
    let wall_us = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_micros()
        .try_into()?;
    let (expires, deadline) =
        crate::launch::startup_window(issued, wall_us, num(a, "expires_unix_seconds")?)?;
    let expires = expires.min(peers.limit);
    n.deadline = Some(deadline.min(peers.limit));
    n.check()?;
    let p = json!({"schema":PLAN_SCHEMA,"operation":review["operation"],"preparation":prepared,"peer_window":wr,"epoch":EPOCH,"unit":UNIT,"guard_unit":GUARD_UNIT,"worker_root":ROOT,"bootstrap_slot":SLOT,
        "snapshot_sha256":SNAPSHOT_SHA,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"token_root":TOKENS,"boot_id":a["boot_id"],
        "harness":Bound::new(HARNESS,HARNESS_SHA),"worker":Bound::new(WORKER,WORKER_SHA),"input_packet":Bound::new(PACKET,PACKET_SHA),"genesis_sha256":GENESIS_SHA,"guard":guard,"admission":ar,"minimum_free_bytes":a["protected_existing_floor_bytes"],"issued_monotonic_us":issued,"expires_monotonic_us":expires});
    let pr = save_json(&n.root, "plan.json", &p)?;
    let pr = units::bind_plan(n, &startup, &pr, units::STARTUP)?;
    units::producer(n, None, &pr, &affinity)?;
    n.run("/usr/bin/systemctl", &["start", RETENTION])?;
    units::retention(n, &producer_package)?;
    units::producer(n, None, &pr, &affinity)?;
    // Recheck fresh capacity immediately before the first activation, without
    // rerunning Git/source hashing within the short first-fire clock.
    // The stop qualification deliberately trips at its first firing. Its
    // installed guard covers either complete census and cannot issue a token.
    let guard_floor = if qualification {
        u64::MAX
    } else {
        num(a, "protected_existing_floor_bytes")?
    };
    let latest = refreshed_capacity(n, review, false)?;
    preserves_admitted_space(&latest, a, guard_floor)?;
    check_devices(&latest, a)?;
    units::producer(n, None, &pr, &affinity)?;
    peers.verify(n)?;
    n.run("/usr/bin/systemctl", &["start", "--no-block", UNIT])?;
    let first = loop {
        n.check()?;
        let v = n.show(UNIT)?;
        if v["ActiveState"] == "active" && v["SubState"] == "running" {
            break v;
        }
        ensure!(
            v["ActiveState"] == "activating" || v["Job"] != "",
            "native failed before first guard"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    let iid = text(&first, "InvocationID")?.to_owned();
    ensure!(hex(&iid, 32), "native invocation missing");
    // No retry: failure retains all sealed evidence and only this exact attempt is stopped.
    let result = (|| -> Result<()> {
        let v = units::producer(n, Some(&iid), &pr, &affinity)?;
        let pid = text(&v, "MainPID")?.parse::<u64>()?;
        let token_dest = token_root.join(&iid);
        absent(&token_dest)?;
        let receipts = create_receipt_mount(&receipt_mount, &iid)?;
        let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"filesystem":EXPECTED_FILESYSTEM,"boot_id":a["boot_id"],"main_start_ticks":process_ticks(pid)?,"native_main":{"main_pid":pid,"executable":HARNESS,"sha256":HARNESS_SHA},"minimum_free_bytes":guard_floor,"worker_root":ROOT,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"receipt_directory":receipts});
        let gr = save_json(&n.root, "guard-plan.json", &gp)?;
        let deployed_gr = units::bind_plan(n, &guard_binding, &gr, units::GUARD_ARG)?;
        units::guard_properties(
            &n.show(GUARD_UNIT)?,
            &guard,
            &deployed_gr.path,
            &receipt_mount,
        )?;
        n.run(
            guard.path.to_str().context("guard path")?,
            &[
                deployed_gr.path.to_str().context("guard plan path")?,
                "--plan-sha256",
                &deployed_gr.sha256,
                "--self-sha256",
                &guard.sha256,
                "--validate-plan-only",
            ],
        )?;
        units::producer(n, Some(&iid), &pr, &affinity)?;
        peers.verify(n)?;
        verify_mount(&receipt_mount, &receipts)?;
        n.run("/usr/bin/systemctl", &["start", TIMER])?;
        if qualification {
            stop::capture_stop(
                n,
                &iid,
                pid,
                &receipts,
                &deployed_gr,
                &pr,
                &producer_package,
                &package(attempt, "guard-units"),
                &p,
            )?;
            let capture_path = n.root.join("protective-stop-capture.json");
            let capture = Bound::new(&capture_path, hash(&capture_path)?).json()?;
            retire::validate_capture(&capture)?;
            peers.verify(n)?;
            return Ok(());
        }
        let g = loop {
            n.check()?;
            let g = n.show(GUARD_UNIT)?;
            if g["ActiveState"] == "inactive"
                && g["SubState"] == "dead"
                && g["Result"] == "success"
                && g["ExecMainStatus"] == "0"
                && g["MainPID"] == "0"
                && g["ControlPID"] == "0"
                && g["Job"] == ""
                && g["InvocationID"].as_str().is_some_and(|s| hex(s, 32))
            {
                break g;
            }
            ensure!(g["ActiveState"] != "failed", "first guard failed");
            std::thread::sleep(Duration::from_millis(100));
        };
        ensure!(
            g["StartLimitIntervalUSec"] == "0" && g["DropInPaths"] == "",
            "guard rate limit/drop-ins differ"
        );
        let gid = text(&g, "InvocationID")?;
        let timer = n.show(TIMER)?;
        ensure!(
            timer["LoadState"] == "loaded"
                && timer["ActiveState"] == "active"
                && timer["SubState"] == "waiting"
                && timer["Unit"] == GUARD_UNIT
                && timer["Job"] == ""
                && timer["DropInPaths"] == "",
            "timer not armed"
        );
        let next = peer_window::deadline(n, TIMER)?;
        let clock = mono()?;
        ensure!(
            next > clock && next - clock <= 35_000_000,
            "candidate first timer deadline missing/late"
        );
        let candidate_limit = next
            .checked_sub(5_000_000)
            .context("candidate timer margin")?;
        n.deadline = Some(
            n.deadline
                .context("original operator clock")?
                .min(candidate_limit),
        );
        n.check()?;
        let sample_path = receipts.join(format!("sample-{gid}.json"));
        let sample = Bound::new(&sample_path, hash(&sample_path)?).json()?;
        for stop in ["stop-intent.json", "stop-completion.json"] {
            absent(&receipts.join(stop))?;
        }
        let raw = n.run(
            "/usr/bin/journalctl",
            &[
                "--all",
                "--no-pager",
                "--output=json",
                "--boot=0",
                "_PID=1",
                &format!("UNIT={GUARD_UNIT}"),
                &format!("INVOCATION_ID={gid}"),
            ],
        )?;
        let rows = serde_json::Deserializer::from_slice(&raw)
            .into_iter::<Value>()
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let journal = json!(rows);
        let sr = save_json(&n.root, "actual-first-guard-sample.json", &sample)?;
        let jr = save_json(&n.root, "actual-first-guard-PID1.json", &journal)?;
        n.seal(
            &proof_package,
            &[
                ("guard-sample.json", sr.clone()),
                ("guard-PID1.json", jr.clone()),
            ],
        )?;
        let token = cold_input_token(
            &p,
            &pr.sha256,
            &gp,
            gid,
            FirstGuardProof {
                plan: deployed_gr.clone(),
                sample: Bound::new(proof_package.join("guard-sample.json"), sr.sha256),
                journal: Bound::new(proof_package.join("guard-PID1.json"), jr.sha256),
            },
            mono()?,
        );
        handoff::limited_sample(&p, &gp, &sample)?;
        check_mount_sample(a, &sample)?;
        first_guard(&p, &token, &gp, &sample, &journal, now()?)?;
        let latest = refreshed_capacity(n, review, true)?;
        preserves_admitted_space(&latest, a, guard_floor)?;
        check_devices(&latest, a)?;
        units::producer(n, Some(&iid), &pr, &affinity)?;
        gate::held_image(pid, &iid, UNIT, HARNESS)?;
        verify_mount(&receipt_mount, &receipts)?;
        peers.verify(n)?;
        ensure!(
            n.show(GUARD_UNIT)? == g
                && n.show(TIMER)? == timer
                && peer_window::deadline(n, TIMER)? == next,
            "candidate first guard rolled over before token"
        );
        for stop in ["stop-intent.json", "stop-completion.json"] {
            absent(&receipts.join(stop))?;
        }
        n.check()?;
        let tr = save_json(&n.root, "guard-admission.json", &token)?;
        let ts = save(
            &n.root,
            "guard-admission.sha256",
            format!("{}\n", tr.sha256).as_bytes(),
        )?;
        n.seal(
            &token_dest,
            &[
                ("guard-admission.json", tr.clone()),
                ("guard-admission.sha256", ts),
            ],
        )?;
        n.check()?;
        let producer = units::producer(n, Some(&iid), &pr, &affinity)?;
        let retain = units::retention(n, &producer_package)?;
        let unit_file = Bound::new(
            producer_package.join(UNIT),
            hash(&producer_package.join(UNIT))?,
        );
        let mut handoff = json!({"schema":HANDOFF_SCHEMA,"unit":UNIT,"invocation_id":iid,"main_pid":pid,"producer":producer,"unit_file":unit_file,"retention":retain,"startup_plan":pr,"admission":ar,"guard_plan":deployed_gr,"first_guard_sample":token["guard_sample"],"first_guard_pid1_journal":token["guard_pid1_journal"],"first_guard_token":Bound::new(token_dest.join("guard-admission.json"),tr.sha256),"recorded_monotonic_us":mono()?,"recorded_unix_seconds":now()?,"native_input_qualified":false,"epoch":EPOCH,"harness":p["harness"],"worker":p["worker"],"input_packet":p["input_packet"],"launcher_sha256":self_sha,"peer_window":wr,"receipt_mount":receipt_mount,"cpu_affinity":review["cpu_affinity"]});
        ensure!(
            num(&handoff, "recorded_unix_seconds")? <= num(a, "expires_unix_seconds")?
                && num(&handoff, "recorded_monotonic_us")? < expires,
            "original admission expired before handoff"
        );
        if EPOCH == 257 {
            handoff["guard"] = p["guard"].clone();
        }
        deny_authority(&mut handoff);
        handoff::reopen(&handoff)?;
        let h = save_json(&n.root, "guarded-startup-handoff.json", &handoff)?;
        println!("{}", serde_json::to_string(&h)?);
        Ok(())
    })();
    if result.is_err() {
        n.deadline = None;
        if let Ok(v) = n.show(UNIT)
            && v["InvocationID"] == iid
            && matches!(v["ActiveState"].as_str(), Some("active" | "activating"))
        {
            let _ = n.run("/usr/bin/systemctl", &["stop", "--no-block", UNIT]);
        }
    }
    result
}

#[cfg(test)]
mod disk_tests {
    use super::*;

    #[test]
    fn rising_floor_requires_both_free_bytes_and_guard_coverage() {
        let original = 4_174_855_092_600_u64;
        let refreshed = original + (163_732_389_888 - 162_524_471_296_u64);
        let admission = json!({"protected_existing_floor_bytes":original});
        let latest = |floor: u64, free: u64| {
            json!({
                "protected_existing_floor_bytes": floor, "capacity":{"observed_available_bytes":free}
            })
        };
        let required = refreshed + RESERVATION;
        assert!(
            preserves_admitted_space(&latest(refreshed, required), &admission, u64::MAX).is_ok()
        );
        assert!(
            preserves_admitted_space(&latest(refreshed, required - 1), &admission, u64::MAX)
                .is_err()
        );
        assert!(
            preserves_admitted_space(&latest(refreshed, u64::MAX), &admission, original).is_err()
        );
        assert!(
            preserves_admitted_space(
                &latest(original - 1, original + RESERVATION - 1),
                &admission,
                original
            )
            .is_err()
        );
        assert!(
            preserves_admitted_space(&latest(u64::MAX, u64::MAX), &admission, u64::MAX).is_err()
        );
    }
}
