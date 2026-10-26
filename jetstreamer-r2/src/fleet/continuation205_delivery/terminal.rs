//! Natural stage success requires its genuine start/success PID1 history and
//! operation outcome. A service disappearing is never a verification result.
use super::*;
use std::process::Stdio;
use std::time::{Duration, Instant};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Capture {
    schema: String,
    stage_spec: BoundFile,
    actor_launch: BoundFile,
    output: PathBuf,
}
fn idle(owner: &Value, launch: &Value, stage: downstream::Stage) -> Result<()> {
    ensure!(
        owner["Id"] == stage.unit()
            && owner["MainPID"] == "0"
            && owner["NRestarts"] == "0"
            && owner["ActiveState"] == "inactive"
            && owner["SubState"] == "dead"
            && owner["Result"] == "success"
            && owner["ExecMainStatus"] == "0"
            && (owner["InvocationID"] == launch["invocation_id"] || owner["InvocationID"] == "")
            && peer::command_matches(s(owner, "ExecStart")?, s(launch, "expected_exec_start")?),
        "205 stage is active/replaced/restarted or not naturally successful"
    );
    Ok(())
}
fn journal(stage: downstream::Stage, launch: &Value) -> Result<Vec<u8>> {
    let start = n(launch, "started_unix_millis")? / 1000;
    let mut child = ProcessCommand::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--all",
            "-o",
            "json",
            "_PID=1",
            &format!("UNIT={}", stage.unit()),
            &format!("--since=@{}", start.saturating_sub(1)),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let begin = Instant::now();
    while child.try_wait()?.is_none() {
        if begin.elapsed() >= Duration::from_secs(2) {
            child.kill()?;
            child.wait()?;
            bail!("205 PID1 metadata query timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 65536 && output.stderr.len() <= 65536,
        "205 PID1 metadata query failed/exceeded bound"
    );
    Ok(output.stdout)
}
fn outcome(x: &downstream::StageSpec, spec: &BoundFile, launch: &Value, o: &Value) -> Result<()> {
    ensure!(
        o["schema"] == "jetstreamer-continuation205-delivery-stage-outcome-v1"
            && o["epoch"] == 205
            && o["stage"] == serde_json::to_value(x.stage)?
            && o["spec"] == private157::binding(spec)
            && o["source"] == serde_json::to_value(&x.source)?
            && o["invocation_id"] == launch["invocation_id"]
            && o["archive_bytes"] == BYTES
            && is_lower_hex(s(o, "archive_sha256")?, 64)
            && o["passed"] == true
            && o["issuer"]["executable_sha256"]
                == read(&serde_json::from_value(launch["stage_admission"].clone())?)?["runner"]["sha256"],
        "205 completed operation differs from actual admitted stage"
    );
    deny(&o["authority"])?;
    startup::validate_outcome(x, spec, o)?;
    let prior = downstream::gates(x)?;
    ensure!(
        o["predecessor_outcomes"] == serde_json::to_value(prior)?,
        "205 stage lost genuine predecessor outcomes"
    );
    if x.stage == downstream::Stage::Full {
        ensure!(
            o["measurement"]["sha256"] == o["archive_sha256"]
                && o["measurement"]["bytes"] == BYTES
                && o["measurement"]["source"] == OUTPUT
                && o["source_digest_initial_state"] == "unmeasured",
            "205 Full did not establish its first actual source digest"
        );
    }
    Ok(())
}
pub(super) fn capture(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let c: Capture = serde_json::from_value(v.clone())?;
    ensure!(
        c.schema == "jetstreamer-continuation205-stage-terminal-spec-v1",
        "205 stage terminal scope differs"
    );
    let x = downstream::stage_spec(&read(&c.stage_spec)?)?;
    let launch = read(&c.actor_launch)?;
    ensure!(
        launch["schema"] == "jetstreamer-continuation205-delivery-launch-v1"
            && launch["stage_spec"] == private157::binding(&c.stage_spec)
            && c.output == x.output_directory.join("terminal.json"),
        "205 terminal changed actual launch/output"
    );
    let o_binding = peer::binding(&x.output_directory.join("outcome.json"))?;
    let o = read(&o_binding)?;
    outcome(&x, &c.stage_spec, &launch, &o)?;
    let before = unit(x.stage.unit())?;
    idle(&before, &launch, x.stage)?;
    inactive_status::no_pending_owner_trigger(x.stage.unit(), false)?;
    let cgroup = capped204205_work::empty_terminal_cgroup(x.stage.unit())?;
    let raw = journal(x.stage, &launch)?;
    ensure!(
        capped204205_work::delivery_natural_manager(
            &raw,
            x.stage.unit(),
            s(&launch, "invocation_id")?
        )? == n(&launch, "started_unix_millis")?,
        "205 actual PID1 start differs from captured launch"
    );
    let path = x.output_directory.join("terminal-manager.jsonl");
    peer::no_file(&path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    std::io::Write::write_all(&mut file, &raw)?;
    file.sync_all()?;
    File::open(&x.output_directory)?.sync_all()?;
    ensure!(
        unit(x.stage.unit())? == before,
        "205 terminal owner changed during capture"
    );
    write(
        &c.output,
        &json!({"schema":"jetstreamer-continuation205-stage-terminal-v1","epoch":205,"stage":x.stage,"stage_spec":c.stage_spec,
        "actor_launch":c.actor_launch,"invocation_id":launch["invocation_id"],"outcome":o_binding,"current_owner":before,
        "manager_journal":peer::binding(&path)?,"cgroup":cgroup,"result":"natural_success","issuer":peer::issuer(spec,self_sha),"authority":denied()}),
    )
}
pub(super) fn stage_gate(
    g: &downstream::Gate,
    source: &lineage::DownstreamSource,
) -> Result<Value> {
    let t = read(&g.terminal)?;
    deny(&t["authority"])?;
    let spec: BoundFile = serde_json::from_value(t["stage_spec"].clone())?;
    let x = downstream::stage_spec(&read(&spec)?)?;
    let launch = read(&serde_json::from_value(t["actor_launch"].clone())?)?;
    ensure!(
        t["schema"] == "jetstreamer-continuation205-stage-terminal-v1"
            && t["epoch"] == 205
            && t["stage"] == serde_json::to_value(g.stage)?
            && x.stage == g.stage
            && t["result"] == "natural_success"
            && t["invocation_id"] == launch["invocation_id"]
            && serde_json::to_value(&x.source)? == serde_json::to_value(source)?,
        "205 predecessor is not this source's actual successful stage"
    );
    idle(&t["current_owner"], &launch, g.stage)?;
    let raw = sealed(
        &serde_json::from_value(t["manager_journal"].clone())?,
        65536,
    )?;
    ensure!(
        capped204205_work::delivery_natural_manager(
            &raw,
            g.stage.unit(),
            s(&launch, "invocation_id")?
        )? == n(&launch, "started_unix_millis")?,
        "205 predecessor PID1 start differs"
    );
    let o = read(&serde_json::from_value(t["outcome"].clone())?)?;
    outcome(&x, &spec, &launch, &o)?;
    Ok(o)
}
