//! Executes one independently admitted private epoch 225 extraction.
use anyhow::{Context, Result, ensure};
use jetstreamer_horizon_observe::epoch225_extraction as c;
use jetstreamer_node::epoch225_extract::{PINNED_WORKER_SHA256, PinnedSource};
use serde_json::{Value, json};
use std::{
    env, fs,
    path::Path,
    time::{Duration, Instant},
};
fn arguments(a: &[String]) -> Result<(c::Bound, String)> {
    ensure!(
        a.len() == 6
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && c::hex(&a[3], 64)
            && c::hex(&a[5], 64),
        "usage: jetstreamer-epoch225-prefix-extract PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    Ok((
        c::Bound {
            path: a[1].clone().into(),
            sha256: a[3].clone(),
        },
        a[5].clone(),
    ))
}
fn release(
    p: &c::Plan,
    b: &c::Bound,
    admission: &c::Bound,
    actor: &Value,
    floor: u64,
) -> Result<(c::Bound, Value)> {
    let deadline = Instant::now();
    while !p.release.try_exists()? {
        ensure!(
            deadline.elapsed() < Duration::from_secs(300),
            "epoch 225 release timed out without source reads"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let bound = c::binding(&p.release)?;
    let v = c::read(&bound)?;
    ensure!(
        v["schema"] == c::RELEASE
            && v["plan"] == json!(b)
            && v["admission"] == json!(admission)
            && v["actor"] == *actor
            && v["issuer_sha256"] == p.admitter.sha256
            && v["authority"] == c::denied()
            && v["source_reads_authorized"] == true
            && v["maximum_output_bytes"] == c::OUTPUT,
        "epoch 225 release does not authorize this exact admitted owner"
    );
    let guard: c::Bound = serde_json::from_value(v["guard_plan"].clone())?;
    let iid = actor["manager"]["InvocationID"]
        .as_str()
        .context("epoch 225 task IID missing")?;
    c::latest_guard(p, &guard, iid, floor)?;
    Ok((bound, v))
}
fn phase(
    p: &c::Plan,
    launch: &c::Bound,
    iid: &str,
    name: &str,
    bytes: u64,
    complete: bool,
) -> Result<()> {
    println!("epoch 225 phase {name}: output_bytes={bytes}");
    let millis = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    c::persist(
        &p.root.join(format!("progress-{name}.json")),
        &json!({"schema":"jetstreamer-epoch225-extraction-phase-v1",
        "launch":launch,"unit":p.unit,"invocation_id":iid,"phase":name,"output_bytes":bytes,"source_validation_complete":complete,
        "recorded_unix_seconds":millis/1000,"recorded_unix_millis":millis,"authority":c::denied()}),
    )
}
fn run() -> Result<()> {
    for key in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "LD_AUDIT",
        "BASH_ENV",
        "ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "RUBYOPT",
        "PERL5OPT",
        "GCONV_PATH",
    ] {
        ensure!(
            env::var_os(key).is_none(),
            "epoch 225 executor inherited unsafe environment: {key}"
        );
    }
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "epoch 225 extractor requires root"
    );
    let (binding, self_sha) = arguments(&env::args().collect::<Vec<_>>())?;
    let p = c::load(&binding)?;
    c::qualified(&p)?;
    ensure!(
        self_sha == p.executable.sha256 && fs::read_link("/proc/self/exe")? == p.executable.path,
        "epoch 225 running executable differs"
    );
    c::private(&p.root)?;
    ensure!(
        fs::read_dir(&p.root)?.next().is_none(),
        "epoch 225 extraction attempt is not empty"
    );
    let admitted = c::binding(&p.admission)?;
    let a = c::read(&admitted)?;
    let floor = c::admission(&p, &binding, &a, c::now()?)?;
    let iid = env::var("INVOCATION_ID").context("epoch 225 extractor requires PID1 ownership")?;
    let pid = std::process::id();
    let actor = c::actor(&p, &binding, &iid, pid)?;
    ensure!(
        actor["unit_file"] == a["unit_file"],
        "epoch 225 installed unit changed after admission"
    );
    c::persist(
        &p.root.join("waiting.json"),
        &json!({"schema":"jetstreamer-epoch225-extraction-waiting-v1",
        "plan":binding,"admission":admitted,"actor":actor,"recorded_unix_seconds":c::now()?,"archive_body_reads":0,"authority":c::denied()}),
    )?;
    let (release_bound, released) = release(&p, &binding, &admitted, &actor, floor)?;
    ensure!(
        c::actor(&p, &binding, &iid, pid)? == actor,
        "epoch 225 owner changed before release"
    );
    c::admission(&p, &binding, &a, c::now()?)?;
    let old = c::manager(c::OLD_UNIT)?;
    ensure!(
        old["MainPID"] == "0"
            && old["NRestarts"] == "0"
            && old["ActiveState"] == "inactive"
            && old["SubState"] == "dead"
            && old["Result"] == "success"
            && old["ExecMainStatus"] == "0",
        "epoch 225 original producer is no longer terminal"
    );
    let guard: c::Bound = serde_json::from_value(released["guard_plan"].clone())?;
    let guard_plan = c::read(&guard)?;
    let captured = c::now()?;
    c::persist(
        &p.root.join("launch.json"),
        &json!({"schema":c::LAUNCH,"epoch":225,"plan":binding,"admission":admitted,"release":release_bound,
        "unit":p.unit,"invocation_id":iid,"actor":actor,"guard_plan":guard,"terminal_handoff":p.terminal_handoff,
        "guard_unit":p.guard_unit,"guard_receipt_directory":guard_plan["receipt_directory"],"guard_sha256":p.guard_executable.sha256,
        "captured_unix_seconds":captured,"phase":"verification","epochs":[225,226],"missing226_suffix_slots":535,
        "maximum_output_bytes":c::OUTPUT,"memory_max_bytes":c::MEMORY,"authority":c::denied()}),
    )?;
    // Independent timer guard protects the whole deep source read. Its first
    // completed firing and native hard caps were authenticated before this point.
    println!(
        "epoch 225 phase source-validation start: validating all 265610094371 source bytes and all 863465 slots; this pass is mandatory even after an independent reader receipt"
    );
    let source_started = Instant::now();
    let launch_bound = c::binding(&p.root.join("launch.json"))?;
    phase(&p, &launch_bound, &iid, "source-validation-start", 0, false)?;
    let manifest_sha: [u8; 32] =
        sha2::Sha256::digest(include_bytes!("../epoch225_extract/source-manifest.json")).into();
    let source = Path::new(c::ORIGINAL);
    let mut pinned = PinnedSource::open(
        source,
        &p.source_manifest.path,
        manifest_sha,
        PINNED_WORKER_SHA256,
    )?;
    println!(
        "epoch 225 phase source-validation complete: elapsed_millis={}",
        source_started.elapsed().as_millis()
    );
    phase(
        &p,
        &launch_bound,
        &iid,
        "source-validation-complete",
        0,
        true,
    )?;
    let mut last_guard = Instant::now() - Duration::from_secs(5);
    let mut last_log = Instant::now();
    let result = pinned.extract_private_with_progress(
        &p.root,
        c::OUTPUT,
        |bytes, write_bytes| {
            let checked = (|| -> Result<()> {
                let required = c::write_floor(floor, bytes, write_bytes)?;
                ensure!(
                    bytes <= c::OUTPUT && c::free(&p.root)? >= required,
                    "epoch 225 protected disk floor crossed"
                );
                if last_guard.elapsed() >= Duration::from_secs(5) {
                    c::latest_guard(&p, &guard, &iid, floor)?;
                    c::actor(&p, &binding, &iid, pid)?;
                    last_guard = Instant::now();
                }
                if last_log.elapsed() >= Duration::from_secs(30) {
                    println!("epoch 225 prefix reencode output_bytes={bytes}");
                    last_log = Instant::now();
                }
                Ok(())
            })();
            checked.map_err(|e| {
                std::io::Error::other(format!("epoch 225 guard rejected write: {e:#}"))
            })
        },
        |name, bytes| phase(&p, &launch_bound, &iid, name, bytes, true),
    )?;
    c::latest_guard(&p, &guard, &iid, floor)?;
    ensure!(
        c::actor(&p, &binding, &iid, pid)? == actor,
        "epoch 225 extraction owner changed"
    );
    c::persist(
        &p.root.join("extraction.json"),
        &json!({"schema":"jetstreamer-epoch225-prefix-extraction-result-v1",
        "plan":binding,"admission":admitted,"launch":c::binding(&p.root.join("launch.json"))?,"result":result,
        "candidate_identity":c::identity(&fs::symlink_metadata(p.root.join("epoch-225.jet"))?),
        "completed_unix_seconds":c::now()?,"epochs226_complete":false,"missing226_suffix_slots":535,"authority":c::denied()}),
    )?;
    println!(
        "epoch 225 private prefix extraction complete; candidate runtime and epoch 226 debt remain explicit"
    );
    Ok(())
}
use sha2::Digest;
fn main() {
    env_logger::Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format_timestamp_nanos()
        .init();
    if let Err(e) = run() {
        eprintln!("epoch 225 extraction refused: {e:#}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn e225_runner_cli_requires_exact_bound_plan_and_self_digest() {
        let a = vec![
            "extractor".into(),
            "/sealed/plan.json".into(),
            "--plan-sha256".into(),
            "a".repeat(64),
            "--self-sha256".into(),
            "b".repeat(64),
        ];
        assert!(arguments(&a).is_ok());
        for (i, v) in [
            (2, "--ignore-admission"),
            (3, "unknown"),
            (4, "--skip-guard"),
        ] {
            let mut bad = a.clone();
            bad[i] = v.into();
            assert!(arguments(&bad).is_err());
        }
        let mut bad = a;
        bad.push("--force".into());
        assert!(arguments(&bad).is_err());
    }
}
