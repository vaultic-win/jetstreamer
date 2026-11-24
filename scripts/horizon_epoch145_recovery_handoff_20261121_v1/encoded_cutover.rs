//! Replace the live frozen verifier on its existing reservation.
use super::*;
use std::os::unix::fs::DirBuilderExt;

const INCUMBENT: &str = "cbacb5a17e6347509640846eccb95cb0";
const INCUMBENT_IMAGE: &str = "epoch145-semantic-continuity-20261121-v1/tools-v5q/export145";
const INCUMBENT_PROVIDER: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-145-audit-turnover-rejoin-v1";
const SUBMISSION: &str =
    "epoch145-semantic-continuity-20261121-v1/v5q-name-handoff/submission-result.json";
const SELECTOR: &str = "horizon-145-v5q-136-dispatch-20261124-v1.service";
const SELECTOR_DIR: &str = "epoch145-v5q-136-dispatch-20261124-v1";
const STAGE_DIR: &str = "epoch145-encoded-prefix-stage-20261124-v1";
const HANDOFF_DIR: &str = "epoch145-semantic-continuity-20261121-v1/v5r-name-handoff";
const WRITER_LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const FROZEN: &str =
    "/home/sol/.jetstreamer-private/epoch145-prefix-extract-funded-20261121-v1/.tmp36MvkN";

fn frozen() -> Result<Value> {
    let f = Path::new(FROZEN);
    let m = fs::symlink_metadata(f)?;
    ensure!(
        f.canonicalize()? == f
            && m.is_file()
            && (
                m.dev(),
                m.ino(),
                m.len(),
                m.uid(),
                m.nlink(),
                m.mode() & 0o7777
            ) == (64512, 103237059, 105610995833, 0, 1, 0o400),
        "different frozen 145 candidate"
    );
    Ok(
        json!({"path":f,"device":m.dev(),"inode":m.ino(),"bytes":m.len(),
              "mtime_ns":m.mtime() * 1_000_000_000 + m.mtime_nsec(),
              "ctime_ns":m.ctime() * 1_000_000_000 + m.ctime_nsec()}),
    )
}

fn current_owners() -> Result<(Value, Value)> {
    let manager = native(E)?;
    let (pid, iid) = stable(&manager, E)?;
    ensure!(
        iid == INCUMBENT && platform::proc_exe(pid)? == rt(INCUMBENT_IMAGE),
        "a different 145 verifier owns the reservation"
    );
    let selector = native(SELECTOR)?;
    let (selector_pid, _) = stable(&selector, SELECTOR)?;
    let dir = rt(SELECTOR_DIR);
    ensure!(
        platform::proc_exe(selector_pid)? == dir.join("tools/follow145")
            && !dir.join("READY.json").try_exists()?,
        "old 136 selector already made a decision or changed owner"
    );
    drained(&native(W)?, W)?;
    let payload = "horizon-qualify-136-actual-20261120-g1.service";
    drained(&native(payload)?, payload)?;
    Ok((manager, selector))
}

fn successor_command(
    mut argv: Vec<String>,
    actual_command: &[u8],
    image: &str,
    fleet: &str,
    fleet_sha: &str,
    image_sha: &str,
) -> Result<Vec<String>> {
    let end = argv
        .len()
        .checked_sub(5)
        .context("missing prior verifier argv")?;
    let (prefix, old) = argv.split_at_mut(end);
    ensure!(
        prefix.first().is_some_and(|arg| arg == "systemd-run")
            && prefix.last().is_some_and(|arg| arg == "--")
            && old[0] == rt(INCUMBENT_IMAGE).to_string_lossy()
            && old[1] == "recover-full-output"
            && old
                .iter()
                .map(|arg| arg.as_bytes())
                .chain([&b""[..]])
                .collect::<Vec<_>>()
                .join(&0)
                == actual_command,
        "sealed submission differs from the live verifier command"
    );
    old[0] = image.to_owned();
    old[2] = fleet.to_owned();
    old[3] = fleet_sha.to_owned();
    old[4] = image_sha.to_owned();
    Ok(argv)
}

pub(super) fn inspect(stage_sha: &str, fleet: &str, fleet_sha: &str) -> Result<Value> {
    let stage_path = rt(STAGE_DIR).join("STAGED.json");
    let stage = pinned(&stage_path, stage_sha)?;
    ensure!(
        stage["schema"] == "horizon-epoch145-encoded-prefix-stage-v1"
            && stage["incumbent"]["InvocationID"] == INCUMBENT
            && stage["successor_launched"] == false
            && stage["publication_authorized"] == false,
        "foreign encoded-prefix staging receipt"
    );
    let pair = [
        (
            "worker",
            "epoch145-semantic-continuity-20261121-v1/tools-v5r",
            "export145",
        ),
        (
            "provider",
            "incident-replay-fit-20261121-v1/tools-homefloor-145-encoded-prefix-rejoin-v1",
            "post-stop-fit",
        ),
        (
            "inspector",
            "epoch145-explicit-stop-inspector-20261124-v2/tools",
            "follow145",
        ),
    ];
    let mut images = json!({});
    for (key, dir, leaf) in pair {
        let dir = rt(dir);
        let reference = &stage[key];
        ensure!(
            aspath(reference)? == dir.join("deployment-seal-receipt.json"),
            "foreign encoded-prefix {key} deployment"
        );
        images[key] = bound(&check_member(&dir, text(&reference["sha256"])?, leaf)?)?;
    }
    let (owner, selector) = current_owners()?;
    let immutable = frozen()?;
    let argv_path = format!("/proc/{}/cmdline", text(&owner["MainPID"])?);
    let submission = pinned(
        &rt(SUBMISSION),
        "398f1a2d5d5a50ab4d35c0f27de035d7c07023b6c8d632ef326b9fcd169cb5e9",
    )?;
    let doc = pinned(Path::new(fleet), fleet_sha)?;
    ensure!(
        submission["invocation_id"] == INCUMBENT
            && doc["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && doc["owner"] == "/root"
            && doc["all_active_status_reports_authenticated_readback"] == true,
        "unaccepted verifier submission or current fleet"
    );
    let args = successor_command(
        serde_json::from_value(submission["argv"].clone())?,
        &fs::read(&argv_path)?,
        text(&images["worker"]["path"])?,
        fleet,
        fleet_sha,
        text(&images["worker"]["sha256"])?,
    )?;
    let incumbent_provider = check_member(
        &rt(INCUMBENT_PROVIDER),
        "f553f7a4f7d4b061f637b0a83e936e6dd6a9a33d4dcae56b15e492f74339b679",
        "post-stop-fit",
    )?;
    let quote: Value = serde_json::from_str(&platform::output(
        incumbent_provider.to_str().context("provider path")?,
        &["145", fleet, fleet_sha],
    )?)?;
    ensure!(
        quote["schema"] == "horizon-incident-replay-fit-v1"
            && quote["fits"] == true
            && quote["phase145"]["invocation_id"] == INCUMBENT
            && quote["phase145"]["stage"] == "leased-worker"
            && quote["complete_cpu_quota_micros"] == 64_000_000
            && quote["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && quote["resource_credit_bytes"] == 0
            && quote["replay_launch_authorized"] == false
            && quote["candidate136"]["occupied"] == false,
        "live fit does not cover the unchanged 145 reservation and idle 136 writer"
    );
    ensure!(
        current_owners()? == (owner.clone(), selector.clone())
            && frozen()? == immutable
            && bound(Path::new(fleet))? == quote["fleet"],
        "cutover inputs changed during live repricing"
    );
    Ok(json!({
        "schema":"horizon-145-encoded-prefix-cutover-inspection-v1",
        "staging":bound(&stage_path)?,"images":images,"incumbent":owner,
        "old_136_selector":selector,"frozen_candidate":immutable,
        "successor_argv":args,"current_reservation":quote,
        "successor_launch_authorized":false,"r2_mutations":false
    }))
}

fn writer_lock() -> Result<fs::File> {
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(WRITER_LOCK)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.gid() == 0
            && m.nlink() == 1
            && m.len() == 0
            && m.mode() & 0o7777 == 0o600
            && unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "136 operation lock is occupied or untrusted"
    );
    let named = fs::symlink_metadata(WRITER_LOCK)?;
    ensure!(
        (m.dev(), m.ino()) == (named.dev(), named.ino()),
        "136 operation lock was replaced"
    );
    Ok(f)
}

fn monotonic_usec() -> Result<u64> {
    let mut clock = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut clock) } == 0,
        "cannot read the native monotonic clock"
    );
    Ok(u64::try_from(clock.tv_sec)? * 1_000_000 + u64::try_from(clock.tv_nsec)? / 1_000)
}

fn stop_once(dir: &Path, leaf: &str, unit: &str, expected: &Value) -> Result<Value> {
    let receipt = dir.join(format!("{leaf}.json"));
    if receipt.try_exists()? {
        return from_ref(&bound(&receipt)?);
    }
    let intent_path = dir.join(format!("{leaf}_REQUEST.json"));
    if !intent_path.try_exists()? {
        ensure!(native(unit)? == *expected, "{unit} changed before stopping");
        platform::save(
            &intent_path,
            &json!({"manager":expected,"not_before_monotonic_usec":monotonic_usec()?}),
        )?;
    }
    let intent = from_ref(&bound(&intent_path)?)?;
    ensure!(
        intent["manager"] == *expected,
        "different saved stop request"
    );
    let manager = native(unit)?;
    if manager == *expected {
        platform::ctl(&["stop", unit])?;
    } else {
        drained(&manager, unit)?;
    }
    let witness = events::inspect_native_stop(
        unit,
        text(&expected["InvocationID"])?,
        intent["not_before_monotonic_usec"]
            .as_u64()
            .context("stop clock")?,
        None,
    )?;
    platform::save(&receipt, &witness)?;
    Ok(witness)
}

fn submit_successor(
    dir: &Path,
    unit: &str,
    previous: &str,
    stopped_after: u64,
    argv: &[String],
    service_argv: &[String],
) -> Result<Value> {
    let request = dir.join("SUCCESSOR_START_REQUEST.json");
    let image = service_argv
        .first()
        .context("missing successor executable")?;
    ensure!(
        argv.first().is_some_and(|arg| arg == "systemd-run")
            && argv.ends_with(service_argv)
            && argv
                .iter()
                .any(|arg| arg.strip_prefix("--unit=") == unit.strip_suffix(".service"))
            && unit.ends_with(".service"),
        "different saved systemd submission"
    );
    let submission = if request.try_exists()? {
        Ok(Vec::new())
    } else {
        events::inspect_native_stop(unit, previous, stopped_after, None)?;
        platform::save(
            &request,
            &json!({"unit":unit,"previous":previous,"argv":argv,
                    "not_before_monotonic_usec":monotonic_usec()?}),
        )?;
        command(
            Path::new("/usr/bin/systemd-run"),
            &argv[1..].iter().map(String::as_str).collect::<Vec<_>>(),
        )
    };
    let saved = from_ref(&bound(&request)?)?;
    ensure!(
        saved["unit"] == unit && saved["previous"] == previous && saved["argv"] == json!(argv),
        "different saved successor start request"
    );
    let active = native(unit)?;
    let (pid, iid) = stable(&active, unit).with_context(|| match submission {
        Ok(_) => format!(
            "no stable successor for saved start request {}",
            request.display()
        ),
        Err(ref error) => format!(
            "successor submission failed for {}: {error:#}",
            request.display()
        ),
    })?;
    let ticks = platform::ticks(pid)?;
    ensure!(
        platform::proc_exe(pid)? == Path::new(image)
            && fs::read(format!("/proc/{pid}/cmdline"))?
                == service_argv
                    .iter()
                    .map(String::as_bytes)
                    .chain([&b""[..]])
                    .collect::<Vec<_>>()
                    .join(&0),
        "submitted verifier has different native arguments or executable"
    );
    let witness = events::inspect_native_stop(unit, previous, stopped_after, Some(&iid))?;
    let started: u64 =
        text(&witness["records"]["successor_starting"]["__MONOTONIC_TIMESTAMP"])?.parse()?;
    ensure!(
        started
            >= saved["not_before_monotonic_usec"]
                .as_u64()
                .context("successor start clock")?
            && witness["manager"] == active
            && platform::ticks(pid)? == ticks,
        "successor predates the request or changed during reconciliation"
    );
    Ok(witness)
}

pub(super) fn activate(stage_sha: &str, fleet: &str, fleet_sha: &str) -> Result<Value> {
    let _operator = guard_instance(&rt(STAGE_DIR))?;
    let dir = rt(HANDOFF_DIR);
    let result = dir.join("submission-result.json");
    if result.try_exists()? {
        return from_ref(&bound(&result)?);
    }
    let intent = dir.join("submission-intent.json");
    let writer = writer_lock()?;
    if !intent.try_exists()? {
        let quote = inspect(stage_sha, fleet, fleet_sha)?;
        ensure!(
            current_owners()?
                == (
                    quote["incumbent"].clone(),
                    quote["old_136_selector"].clone()
                )
                && frozen()? == quote["frozen_candidate"],
            "verifier or 136 selector changed after repricing"
        );
        if !dir.try_exists()? {
            fs::DirBuilder::new().mode(0o700).create(&dir)?;
        }
        platform::save(&intent, &quote)?;
    }
    let quote = from_ref(&bound(&intent)?)?;
    ensure!(
        quote["schema"] == "horizon-145-encoded-prefix-cutover-inspection-v1"
            && quote["staging"]["sha256"] == stage_sha
            && quote["current_reservation"]["fleet"] == bound(Path::new(fleet))?
            && quote["current_reservation"]["fleet"]["sha256"] == fleet_sha
            && quote["incumbent"]["InvocationID"] == INCUMBENT,
        "cutover inputs differ from the saved intent"
    );
    let incumbent = &quote["incumbent"];
    let selector = &quote["old_136_selector"];
    let frozen_candidate = &quote["frozen_candidate"];
    let was_stopped = dir.join("PREDECESSOR_STOP.json").try_exists()?;
    ensure!(
        was_stopped || &frozen()? == frozen_candidate,
        "frozen candidate changed before cutover"
    );
    let selector_stop = dir.join("SELECTOR_STOP.json");
    stop_once(&dir, "SELECTOR_STOP", SELECTOR, selector)?;
    ensure!(
        !rt(SELECTOR_DIR).join("READY.json").try_exists()?,
        "old 136 selector made a decision during the cutover"
    );
    drained(&native(W)?, W)?;
    let payload = "horizon-qualify-136-actual-20261120-g1.service";
    drained(&native(payload)?, payload)?;
    let prior_stop = dir.join("PREDECESSOR_STOP.json");
    let predecessor = stop_once(&dir, "PREDECESSOR_STOP", E, incumbent)?;
    let after = predecessor["not_before_monotonic_usec"]
        .as_u64()
        .context("stop clock")?;
    let argv: Vec<String> = serde_json::from_value(quote["successor_argv"].clone())?;
    let tail = argv
        .len()
        .checked_sub(5)
        .context("missing successor verifier arguments")?;
    ensure!(
        Path::new(&argv[tail]) == aspath(&quote["images"]["worker"])?,
        "saved command does not name the sealed verifier"
    );
    drained(&native(SELECTOR)?, SELECTOR)?;
    if !dir.join("SUCCESSOR_START_REQUEST.json").try_exists()? {
        ensure!(
            &frozen()? == frozen_candidate,
            "frozen candidate changed while the incumbent stopped"
        );
    }
    let witness = submit_successor(&dir, E, INCUMBENT, after, &argv, &argv[tail..])?;
    let receipt = json!({
        "schema":"horizon-145-encoded-prefix-submission-v1",
        "invocation_id":witness["successor_invocation_id"],"argv":argv,"manager":witness["manager"],
        "intent":bound(&intent)?,"predecessor_stop":bound(&prior_stop)?,
        "previous_136_selector_stop":bound(&selector_stop)?,"native_successor":witness,
        "publication_authorized":false,"r2_mutations":false
    });
    platform::save(&result, &receipt)?;
    drop(writer);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires a private root-owned HOME fixture and systemd"]
    fn activates_once_and_reconciles_the_same_successor() -> Result<()> {
        let dir = PathBuf::from(std::env::var("HANDOFF_CUTOVER_FIXTURE")?);
        let _lock = guard_instance(&dir)?;
        let name = format!("horizon-fixture-cutover-{}", std::process::id());
        let unit = format!("{name}.service");
        let selector_name = format!("{name}-selector");
        let selector = format!("{selector_name}.service");
        let make_argv = |name: &str, secs: &str| -> Vec<String> {
            [
                "systemd-run",
                "--quiet",
                &format!("--unit={name}"),
                "-p",
                "Type=exec",
                "-p",
                "CPUQuota=25%",
                "-p",
                "MemoryMax=33554432",
                "--",
                "/usr/bin/sleep",
                secs,
            ]
            .into_iter()
            .map(str::to_owned)
            .collect()
        };
        let start = |argv: &[String]| {
            command(
                Path::new("/usr/bin/systemd-run"),
                &argv[1..].iter().map(String::as_str).collect::<Vec<_>>(),
            )
        };
        let tested = (|| -> Result<()> {
            start(&make_argv(&name, "601"))?;
            start(&make_argv(&selector_name, "602"))?;
            let prior = native(&unit)?;
            let old_selector = native(&selector)?;
            stop_once(&dir, "SELECTOR_STOP", &selector, &old_selector)?;
            let stopped = stop_once(&dir, "PREDECESSOR_STOP", &unit, &prior)?;
            assert_eq!(stop_once(&dir, "PREDECESSOR_STOP", &unit, &prior)?, stopped);
            let iid = text(&prior["InvocationID"])?;
            let after = stopped["not_before_monotonic_usec"]
                .as_u64()
                .context("fixture stop clock")?;
            let argv = make_argv(&name, "603");
            let run = || submit_successor(&dir, &unit, iid, after, &argv, &argv[argv.len() - 2..]);
            let reported = run()?;
            assert_eq!(run()?, reported);
            assert_eq!(reported["manager"], native(&unit)?);
            platform::ctl(&["stop", &unit])?;
            assert!(run().is_err());
            drained(&native(&unit)?, &unit)
        })();
        let _ = platform::ctl(&["stop", &unit, &selector]);
        tested
    }

    #[test]
    fn replaces_only_the_sealed_verifier_and_current_fleet() {
        let mut argv: Vec<String> = ["systemd-run", "--quiet", "-p", "CPUQuota=100%", "--"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let prefix = argv.clone();
        argv.push(rt(INCUMBENT_IMAGE).to_string_lossy().into_owned());
        argv.extend(
            [
                "recover-full-output",
                "/old/fleet",
                "old-fleet-sha",
                "old-image-sha",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let actual = argv[prefix.len()..]
            .iter()
            .map(|arg| arg.as_bytes())
            .chain([&b""[..]])
            .collect::<Vec<_>>()
            .join(&0);
        let next = successor_command(
            argv.clone(),
            &actual,
            "/new/verifier",
            "/new/fleet",
            "fleet-sha",
            "image-sha",
        )
        .unwrap();
        assert_eq!(next[..prefix.len()], prefix);
        assert_eq!(
            next[prefix.len()..],
            [
                "/new/verifier",
                "recover-full-output",
                "/new/fleet",
                "fleet-sha",
                "image-sha"
            ]
        );
        assert!(successor_command(argv, b"another actor", "/x", "/y", "a", "b").is_err());
    }
}
