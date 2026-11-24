//! Price the replacement of the live frozen verifier on its existing reservation.
use super::*;

const INCUMBENT: &str = "cbacb5a17e6347509640846eccb95cb0";
const INCUMBENT_IMAGE: &str = "epoch145-semantic-continuity-20261121-v1/tools-v5q/export145";
const INCUMBENT_PROVIDER: &str =
    "incident-replay-fit-20261121-v1/tools-homefloor-145-audit-turnover-rejoin-v1";
const SUBMISSION: &str =
    "epoch145-semantic-continuity-20261121-v1/v5q-name-handoff/submission-result.json";
const SELECTOR: &str = "horizon-145-v5q-136-dispatch-20261124-v1.service";
const SELECTOR_DIR: &str = "epoch145-v5q-136-dispatch-20261124-v1";
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
    let stage_path = rt("epoch145-encoded-prefix-stage-20261124-v1/STAGED.json");
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

#[cfg(test)]
mod tests {
    use super::*;

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
