//! Guard-first independent private full/plugin scans of the exact completed145 export.
//! Qualification and original producer completion are required before archive access.
mod admission;
mod custody;
mod model;
mod native;
#[cfg(test)]
mod tests;

use anyhow::{Context, Result, ensure};
use custody as f;
use model::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

fn admitted_path(p: &Plan) -> std::path::PathBuf {
    p.state_root.join("admission.json")
}
fn token_path(p: &Plan) -> std::path::PathBuf {
    p.state_root.join("guard-latest.json")
}
fn load_admission(p: &Plan) -> Result<(Admission, Bound)> {
    f::private_directory(&p.state_root)?;
    let b = f::binding(&admitted_path(p))?;
    Ok((serde_json::from_slice(&f::bytes(&b, 8 << 20, false)?)?, b))
}
fn token_valid(
    t: &Token,
    p: &Plan,
    pb: &Bound,
    ab: &Bound,
    a: &Admission,
    now: u64,
    boot: u64,
) -> Result<()> {
    ensure!(
        t.schema == "horizon-epoch145-private-verifier-native-guard-token-v1"
            && t.plan == *pb
            && t.admission == *ab
            && t.actor_iid == a.actor_iid
            && t.actor_pid == a.actor_pid
            && t.actor_start_ticks == a.actor_start_ticks
            && f::hex(&t.guard_iid, 32)
            && t.guard_pid > 1
            && t.guard_start_ticks > 0
            && t.at_unix_seconds >= a.accepted_at
            && t.at_unix_seconds <= now
            && t.at_boottime_millis >= a.accepted_boottime_millis
            && t.at_boottime_millis <= boot
            && boot
                .checked_sub(t.at_boottime_millis)
                .is_some_and(|age| age <= GUARD_MAX_AGE_MILLIS)
            && t.protected_free_bytes == a.required_initial_data_bytes.max(p.minimum_free_bytes)
            && t.protected_available_memory_bytes
                == a.required_initial_memory_bytes
                    .max(p.minimum_available_memory_bytes)
            && t.actual_free_bytes >= t.protected_free_bytes
            && t.actual_available_memory_bytes >= t.protected_available_memory_bytes,
        "missing/stale/crossed native guard proof"
    );
    Ok(())
}
fn read_token(p: &Plan, pb: &Bound, ab: &Bound, a: &Admission) -> Result<Token> {
    let token: Token = serde_json::from_slice(&f::token_snapshot(&token_path(p))?)?;
    token_valid(&token, p, pb, ab, a, f::now()?, f::boottime()?)?;
    Ok(token)
}
fn own_identity() -> Result<(u32, String, u64)> {
    let pid = std::process::id();
    let iid = std::env::var("INVOCATION_ID").context("native invocation environment")?;
    ensure!(f::hex(&iid, 32), "native invocation syntax");
    Ok((pid, iid, native::ticks(pid)?))
}
fn source_unchanged(p: &Plan) -> Result<()> {
    ensure!(
        f::frozen_identity(&p.source.path)? == p.source_identity
            && f::frozen_identity(&p.manifest.path)? == p.manifest_identity,
        "source custody changed during export"
    );
    Ok(())
}
fn completion(p: &Plan, pb: &Bound, a: &Admission, ab: &Bound) -> Result<bool> {
    let path = p.state_root.join("verification-complete.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let b = f::binding(&path)?;
            let c = f::json(&b, false)?;
            ensure!(
                c["schema"] == "horizon-epoch145-guarded-private-verification-completion-v1"
                    && c["plan"] == json!(pb)
                    && c["admission"] == json!(ab)
                    && c["actor_iid"] == a.actor_iid
                    && c["authority"] == admission::false_authority(),
                "completion receipt crossed"
            );
            Ok(true)
        }
    }
}

fn guard(p: &Plan, pb: &Bound) -> Result<()> {
    // Check immutable shape at its original issuance; continuity below enforces
    // the real current execution deadline without renewing the entry window.
    admission::plan_shape(p, p.issued_at)?;
    let (pid, iid, start) = own_identity()?;
    native::owner(p, pb, true, pid, &iid, start)?;
    let (a, ab) = load_admission(p)?;
    if completion(p, pb, &a, &ab)? {
        // A private result is not remote readiness. Do no token renewal after it.
        println!(
            "{} epoch145 guard completion present; no further token issued",
            f::now()?
        );
        return Ok(());
    }
    native::owner(p, pb, false, a.actor_pid, &a.actor_iid, a.actor_start_ticks)?;
    native::timer(p)?;
    admission::continuity(p, pb, &a)?;
    source_unchanged(p)?;
    native::original()?;
    let (free, available) = native::resources(p, &a)?;
    native::owner(p, pb, false, a.actor_pid, &a.actor_iid, a.actor_start_ticks)?;
    native::owner(p, pb, true, pid, &iid, start)?;
    let token = Token {
        schema: "horizon-epoch145-private-verifier-native-guard-token-v1".into(),
        plan: pb.clone(),
        admission: ab,
        actor_iid: a.actor_iid,
        actor_pid: a.actor_pid,
        actor_start_ticks: a.actor_start_ticks,
        guard_iid: iid,
        guard_pid: pid,
        guard_start_ticks: start,
        at_unix_seconds: f::now()?,
        at_boottime_millis: f::boottime()?,
        protected_free_bytes: a.required_initial_data_bytes.max(p.minimum_free_bytes),
        protected_available_memory_bytes: a
            .required_initial_memory_bytes
            .max(p.minimum_available_memory_bytes),
        actual_free_bytes: free,
        actual_available_memory_bytes: available,
    };
    f::replace_token(&token_path(p), &token)?;
    println!(
        "{} epoch145 genuine native guard completed actor={}",
        f::now()?,
        token.actor_iid
    );
    Ok(())
}

fn watch(
    p: Plan,
    pb: Bound,
    a: Admission,
    ab: Bound,
    done: Arc<AtomicBool>,
    written: Arc<AtomicU64>,
    phase: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut last_native = Instant::now();
        let mut last_heartbeat = Instant::now();
        let started = Instant::now();
        let mut last_progress = started;
        let mut previous = (
            phase.load(Ordering::Acquire),
            written.load(Ordering::Acquire),
        );
        while !done.load(Ordering::Acquire) {
            let checked = (|| -> Result<()> {
                read_token(&p, &pb, &ab, &a)?;
                native::resources(&p, &a)?;
                source_unchanged(&p)?;
                if last_native.elapsed() >= Duration::from_secs(5) {
                    native::owner(
                        &p,
                        &pb,
                        false,
                        a.actor_pid,
                        &a.actor_iid,
                        a.actor_start_ticks,
                    )?;
                    native::timer(&p)?;
                    native::original()?;
                    last_native = Instant::now();
                }
                Ok(())
            })();
            if let Err(e) = checked {
                let event = json!({"schema":"horizon-epoch145-private-verifier-watchdog-failure-v1",
                    "at_unix_seconds":f::now().ok(),"actor_iid":a.actor_iid,"error":format!("{e:#}"),
                    "phase":phase.load(Ordering::Acquire),"charged_output_bytes":written.load(Ordering::Acquire),
                    "authority":admission::false_authority()});
                let _ = f::write_new(&p.state_root.join("watchdog-failure.json"), &event);
                eprintln!("epoch145 watchdog failed: {e:#}; preserving attempt");
                // Exit the entire cgroup's useful-work process, including a
                // source decode that has no per-write callback yet. No retry.
                std::process::exit(74);
            }
            let current = (
                phase.load(Ordering::Acquire),
                written.load(Ordering::Acquire),
            );
            if current != previous {
                last_progress = Instant::now();
                previous = current;
            }
            if last_heartbeat.elapsed() >= Duration::from_secs(60) {
                eprintln!(
                    "epoch145 heartbeat elapsed_seconds={} last_substantive_progress_age_seconds={} phase={} charged_output_bytes={} guard active; heartbeat is not archive progress",
                    started.elapsed().as_secs(),
                    last_progress.elapsed().as_secs(),
                    current.0,
                    current.1
                );
                last_heartbeat = Instant::now();
            }
            thread::sleep(Duration::from_secs(1));
        }
    })
}

fn commands(p: &Plan, expected: &Value) -> Vec<String> {
    match p.stage {
        Stage::Full => vec![
            SOURCE.into(),
            "--full".into(),
            "--anchor".into(),
            "62639999".into(),
            "Fnoa95TKZ1U419CubZrxYDtFnqadRmvM554FFi2xSizB".into(),
            "--expected-terminal".into(),
            "63071999".into(),
            "4zqmYpqcustpx2BQ2gB6y7v1HsvZpPGeyaRKFEsbThum".into(),
            "--threads".into(),
            "8".into(),
            "--expected-provenance-sha256".into(),
            expected["extraction"]["expected_output_provenance_sha256"]
                .as_str()
                .unwrap()
                .into(),
        ],
        Stage::Plugin => vec![
            "145:145".into(),
            p.output_root.to_string_lossy().into_owned(),
            "--threads".into(),
            "8".into(),
            "--verify-only".into(),
        ],
    }
}
fn sidecar_absent(p: &Plan) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(p.source.path.with_extension("jet.sha256")),
        Err(e) if e.kind()==std::io::ErrorKind::NotFound),
        "private scan must remain sidecar-free"
    );
    Ok(())
}
fn measured(p: &Plan) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    source_unchanged(p)?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p.source.path)?;
    ensure!(
        f::identity(&file.metadata()?) == p.source_identity,
        "canonical source changed at open"
    );
    let mut h = Sha256::new();
    let mut bytes = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        h.update(&bytes[..n]);
    }
    ensure!(
        f::identity(&file.metadata()?) == p.source_identity,
        "canonical source changed during hash"
    );
    source_unchanged(p)?;
    Ok(format!("{:x}", h.finalize()))
}
fn verify(p: &Plan, pb: &Bound) -> Result<()> {
    let (pid, iid, start) = own_identity()?;
    native::owner(p, pb, false, pid, &iid, start)?;
    let original = native::original()?;
    source_unchanged(p)?;
    sidecar_absent(p)?;
    let a = admission::fresh(p, pb, &iid, start, original)?;
    native::resources(p, &a)?;
    let ab = f::write_new(&admitted_path(p), &a)?;
    f::write_new(
        &p.state_root.join("ready.json"),
        &json!({"schema":"horizon-epoch145-private-verifier-ready-v1",
        "actor_iid":iid,"actor_pid":pid,"actor_start_ticks":start,"plan":pb,"admission":ab,
        "at_unix_seconds":f::now()?,"archive_body_reads_started":false}),
    )?;
    eprintln!(
        "{} epoch145 {} admission accepted; waiting for genuine guard before archive hash or child",
        f::now()?,
        p.stage.name()
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let token = loop {
        ensure!(
            Instant::now() < deadline && f::now()? <= p.entry_deadline,
            "original first guard deadline; preserve and re-admit distinct attempt"
        );
        match fs::symlink_metadata(token_path(p)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(_) => {
                native::timer(p)?;
                break read_token(p, pb, &ab, &a)?;
            }
        }
        thread::sleep(Duration::from_secs(1));
    };
    f::write_new(
        &p.state_root.join("guard-before-archive-read.json"),
        &json!({"schema":"horizon-epoch145-private-verifier-pre-read-guard-v1",
        "plan":pb,"admission":ab,"token":token,"at_unix_seconds":f::now()?}),
    )?;
    let done = Arc::new(AtomicBool::new(false));
    let written = Arc::new(AtomicU64::new(0));
    let phase = Arc::new(AtomicU64::new(1));
    let watcher = watch(
        p.clone(),
        pb.clone(),
        a.clone(),
        ab.clone(),
        done.clone(),
        written,
        phase.clone(),
    );
    let outcome = (|| -> Result<Value> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::process::{Command, Stdio};
        let hash = measured(p)?;
        ensure!(
            hash == p.source.sha256,
            "independent prefix SHA differs from genuine exporter completion"
        );
        let expected = f::evidence(&p.manifest)?;
        let argv = commands(p, &expected);
        let log_path = p.state_root.join("scan.log");
        let mut log = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&log_path)?;
        phase.store(2, Ordering::Release);
        eprintln!(
            "{} independent145 {} child start; exact source/provenance/boundaries bound",
            f::now()?,
            p.stage.name()
        );
        let status = Command::new(&p.verifier.path)
            .args(&argv)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log.try_clone()?)
            .status()?;
        log.flush()?;
        log.sync_all()?;
        fs::File::open(&p.state_root)?.sync_all()?;
        ensure!(
            status.success(),
            "independent {} child failed:{status}; preserve exact log",
            p.stage.name()
        );
        phase.store(3, Ordering::Release);
        ensure!(
            measured(p)? == hash,
            "prefix changed during independent scan"
        );
        admission::source_metadata(p)?;
        admission::authenticate_program(p, &p.program.sha256)?;
        sidecar_absent(p)?;
        read_token(p, pb, &ab, &a)?;
        native::original()?;
        native::owner(p, pb, false, pid, &iid, start)?;
        native::resources(p, &a)?;
        Ok(
            json!({"schema":"horizon-epoch145-guarded-private-verification-completion-v1","epoch":145,"stage":p.stage,
            "at_unix_seconds":f::now()?,"plan":pb,"admission":ab,"actor_iid":iid,"actor_pid":pid,"actor_start_ticks":start,
            "export_completion":p.manifest,"original_export_completion":p.export_original_completion,
            "archive":p.source,"archive_identity":p.source_identity,"source_body_copied":false,
            "verifier":p.verifier,"verifier_seal":p.verifier_seal,"arguments":argv,"exit_code":0,
            "independent_pre_post_hashes_match":true,"incoming":p.incoming,"terminal":p.terminal_boundary,
            "expected_provenance_sha256":expected["extraction"]["expected_output_provenance_sha256"],
            "last_guard_token":read_token(p,pb,&ab,&a)?,"authority":admission::false_authority()}),
        )
    })();
    let persisted=match &outcome {
        Ok(v)=>f::write_new(&p.state_root.join("verification-complete.json"),v).map(|_|()),
        Err(e)=>f::write_new(&p.state_root.join("verification-failure.json"),&json!({"schema":"horizon-epoch145-private-verifier-failure-v1",
            "plan":pb,"admission":ab,"actor_iid":iid,"at_unix_seconds":f::now().ok(),"error":format!("{e:#}"),"authority":admission::false_authority()})).map(|_|()),
    };
    done.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| anyhow::anyhow!("verifier watchdog panicked"))?;
    persisted?;
    outcome?;
    println!(
        "{} independent145 {} complete; other stage, publication and R2 remain separately gated",
        f::now()?,
        p.stage.name()
    );
    Ok(())
}
fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7
            && matches!(args[1].as_str(), "capability" | "verify" | "guard")
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "exact Root CLI"
    );
    let pb = Bound {
        path: Path::new(&args[2]).into(),
        sha256: args[4].clone(),
    };
    ensure!(
        pb.path.parent().and_then(Path::parent) == Some(Path::new("/usr/local/lib/jetstreamer"))
            && pb.path.file_name().is_some_and(|n| n == "plan.json")
            && pb
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-epoch145-private-verify-plan-")),
        "normal sealed plan namespace"
    );
    let p: Plan = serde_json::from_slice(&f::bytes(&pb, 1 << 20, true)?)?;
    admission::authenticate_program(&p, &args[6])?;
    native::directories(&p)?;
    admission::source_metadata(&p)?;
    if args[1] == "guard" {
        guard(&p, &pb)
    } else {
        admission::plan_shape(&p, f::now()?)?;
        if args[1] == "capability" {
            let (_, iid, start) = own_identity()?;
            let a = admission::fresh(&p, &pb, &iid, start, native::original()?)?;
            native::resources(&p, &a)?;
            println!(
                "{}",
                json!({"schema":"horizon-epoch145-private-verifier-read-only-capability-v1",
                "required_initial_memory_bytes":a.required_initial_memory_bytes,"required_initial_data_bytes":a.required_initial_data_bytes,
                "plan":pb,"archive_body_reads":false,"writes":false,"authority":admission::false_authority()})
            );
            Ok(())
        } else {
            verify(&p, &pb)
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch145 private verifier failed: {e:#}");
        std::process::exit(1);
    }
}
