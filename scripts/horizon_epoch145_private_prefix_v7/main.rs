//! Private canonical-width export only. This executable never creates a
//! canonical sidecar, publishes/imports an archive, retires inputs or uses R2.
//! SOURCE-ONLY: qualification, normal sealing and actual admission are pending.
mod admission;
#[allow(dead_code)]
mod archive_checksum;
mod custody;
mod epoch145_extract;
#[allow(dead_code)]
mod epoch145_stage_policy;
mod model;
mod native;
#[allow(dead_code)]
mod segment_manifest;

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
        t.schema == "horizon-epoch145-private-extractor-native-guard-token-v1"
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
    let path = p.state_root.join("extraction-complete.json");
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
        Ok(_) => {
            let b = f::binding(&path)?;
            let c = f::json(&b, false)?;
            ensure!(
                c["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
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
        schema: "horizon-epoch145-private-extractor-native-guard-token-v1".into(),
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
                let event = json!({"schema":"horizon-epoch145-private-extractor-watchdog-failure-v1",
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

fn extract(p: &Plan, pb: &Bound) -> Result<()> {
    let (pid, iid, start) = own_identity()?;
    native::owner(p, pb, false, pid, &iid, start)?;
    let original = native::original()?;
    source_unchanged(p)?;
    let a = admission::fresh(p, pb, &iid, start, original)?;
    native::resources(p, &a)?;
    let ab = f::write_new(&admitted_path(p), &a)?;
    f::write_new(
        &p.state_root.join("ready.json"),
        &json!({"schema":"horizon-epoch145-private-extractor-ready-v1",
        "actor_iid":iid,"actor_pid":pid,"actor_start_ticks":start,"plan":pb,"admission":ab,
        "at_unix_seconds":f::now()?,"archive_body_reads_started":false}),
    )?;
    eprintln!(
        "{} epoch145 metadata admission accepted; awaiting native guard before source read; deadline={}",
        f::now()?,
        p.entry_deadline
    );
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut last_wait_heartbeat = Instant::now();
    let token = loop {
        ensure!(
            Instant::now() < deadline && f::now()? <= p.entry_deadline,
            "original pre-read guard deadline expired; preserve and re-admit distinct attempt"
        );
        match fs::symlink_metadata(token_path(p)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            Ok(_) => {
                native::timer(p)?;
                break read_token(p, pb, &ab, &a)?;
            }
        }
        if last_wait_heartbeat.elapsed() >= Duration::from_secs(60) {
            eprintln!(
                "{} epoch145 waiting for first genuine native guard; remaining_seconds={}; no source body read",
                f::now()?,
                deadline.saturating_duration_since(Instant::now()).as_secs()
            );
            last_wait_heartbeat = Instant::now();
        }
        thread::sleep(Duration::from_millis(100));
    };
    native::owner(p, pb, false, pid, &iid, start)?;
    native::resources(p, &a)?;
    native::original()?;
    source_unchanged(p)?;
    f::write_new(
        &p.state_root.join("guard-before-source-read.json"),
        &json!({"schema":"horizon-epoch145-actual-pre-read-guard-v1",
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
        written.clone(),
        phase.clone(),
    );
    let outcome = (|| -> Result<Value> {
        eprintln!(
            "{} epoch145 source SHA/deep validation start bytes={SOURCE_BYTES}",
            f::now()?
        );
        let mut source = epoch145_extract::PinnedSource::open(
            &p.source.path,
            &p.manifest.path,
            decode_sha(&p.manifest.sha256)?,
            epoch145_extract::PINNED_WORKER_SHA256,
        )?;
        phase.store(2, Ordering::Release);
        eprintln!(
            "{} epoch145 source validation completed; canonical432000-slot export and independent reread start",
            f::now()?
        );
        let result = source.extract_private(&p.output_root, p.output_maximum_bytes, |next| {
            let guard = (|| -> Result<()> {
                ensure!(next <= p.output_maximum_bytes, "output ceiling");
                native::resources(p, &a)?;
                written.store(next, Ordering::Release);
                Ok(())
            })();
            guard.map_err(|e| std::io::Error::other(format!("per-write145 guard: {e:#}")))
        })?;
        phase.store(3, Ordering::Release);
        read_token(p, pb, &ab, &a)?;
        native::resources(p, &a)?;
        native::original()?;
        source_unchanged(p)?;
        native::owner(p, pb, false, pid, &iid, start)?;
        ensure!(
            result.expected_output_provenance_sha256.len() == 64
                && result.archive == p.output_root.join("epoch-145.jet")
                && result.source_must_be_retained
                && result.independent_output_reread_passed
                && !result.current_plugin_verification_passed
                && !result.canonical_sidecar_authorized
                && !result.publication_authorized
                && !result.retirement_authorized
                && !result.r2_mutations,
            "private extraction authority changed"
        );
        Ok(
            json!({"schema":"horizon-epoch145-guarded-private-prefix-completion-v1","at_unix_seconds":f::now()?,
            "plan":pb,"admission":ab,"actor_iid":iid,"actor_pid":pid,"actor_start_ticks":start,
            "extraction":result,"last_guard_token":read_token(p,pb,&ab,&a)?,"authority":admission::false_authority()}),
        )
    })();
    let persisted = match &outcome {
        Ok(result) => {
            f::write_new(&p.state_root.join("extraction-complete.json"), result).map(|_| ())
        }
        Err(error) => {
            let saved = f::write_new(
                &p.state_root.join("extraction-failure.json"),
                &json!({
            "plan":pb,"admission":ab,"actor_iid":iid,"at_unix_seconds":f::now().ok(),"error":format!("{error:#}"),
            "authority":admission::false_authority()}),
            );
            saved.map(|_| ())
        }
    };
    done.store(true, Ordering::Release);
    watcher
        .join()
        .map_err(|_| anyhow::anyhow!("watchdog panicked"))?;
    persisted?;
    outcome?;
    println!(
        "{} epoch145 private canonical prefix complete; independent full/plugin/publication still required",
        f::now()?
    );
    Ok(())
}
fn decode_sha(s: &str) -> Result<[u8; 32]> {
    ensure!(f::hex(s, 64), "digest syntax");
    let mut b = [0; 32];
    for (i, byte) in b.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(b)
}

fn run() -> Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        args.len() == 7
            && matches!(args[1].as_str(), "capability" | "extract" | "guard")
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
                .is_some_and(|n| n.starts_with("horizon-epoch145-prefix-extractor-plan-")),
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
                json!({"schema":"horizon-epoch145-private-extractor-read-only-capability-v1",
                "required_initial_memory_bytes":a.required_initial_memory_bytes,"required_initial_data_bytes":a.required_initial_data_bytes,
                "plan":pb,"archive_body_reads":false,"writes":false,"authority":admission::false_authority()})
            );
            Ok(())
        } else {
            extract(&p, &pb)
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("epoch145 private extractor failed: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_decode_never_accepts_truncated_uppercase_or_nonhex() {
        assert_eq!(decode_sha(&"00".repeat(32)).unwrap(), [0; 32]);
        for s in ["a".repeat(63), "A".repeat(64), "q".repeat(64)] {
            assert!(decode_sha(&s).is_err());
        }
    }
    fn fixture() -> (Plan, Bound, Admission, Bound, Token) {
        let bound = |path: &str| Bound {
            path: path.into(),
            sha256: "a".repeat(64),
        };
        let identity = Identity {
            device: 1,
            inode: 2,
            bytes: 3,
            mtime_ns: 4,
            ctime_ns: 5,
            mode: 0o100444,
            uid: 0,
            gid: 0,
        };
        let p = Plan {
            schema: "horizon-epoch145-private-prefix-extractor-plan-v1".into(),
            generation: "test-v1".into(),
            program: bound(
                "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-test/epoch145-prefix-extract",
            ),
            program_seal: bound(
                "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-tools-test/deployment-seal-receipt.json",
            ),
            admission_bridge: bound(
                "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-admission-bridge-tools-test/epoch145-admission-bridge",
            ),
            admission_bridge_seal: bound(
                "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-admission-bridge-tools-test/deployment-seal-receipt.json",
            ),
            terminal: Bound {
                path: WITNESS.into(),
                sha256: WITNESS_SHA.into(),
            },
            source: Bound {
                path: SOURCE.into(),
                sha256: SOURCE_SHA.into(),
            },
            source_identity: identity.clone(),
            manifest: Bound {
                path: MANIFEST.into(),
                sha256: MANIFEST_SHA.into(),
            },
            manifest_identity: identity,
            memory_request: bound("/sealed/request.json"),
            data_policy: bound("/sealed/policy.json"),
            data_policy_seal: bound("/sealed/seal.json"),
            actor_unit: "horizon-extract145-prefix-test-v1.service".into(),
            guard_unit: "horizon-guard145-prefix-test-v1.service".into(),
            timer_unit: "horizon-guard145-prefix-test-v1.timer".into(),
            output_root: "/home/sol/.jetstreamer-private/epoch145-prefix-extract-test-v1".into(),
            output_directory_identity: DirectoryIdentity {
                device: 1,
                inode: 2,
            },
            state_root: "/var/lib/jetstreamer/horizon-epoch145-prefix-extract-test-v1".into(),
            state_directory_identity: DirectoryIdentity {
                device: 1,
                inode: 3,
            },
            output_maximum_bytes: 160 * GIB,
            actor_memory_bytes: 80 * GIB,
            guard_memory_bytes: 256 << 20,
            external_pool_bytes: 6 * GIB,
            actor_cpu_quota_micros: 8_000_000,
            guard_cpu_quota_micros: 1_000_000,
            tasks_max: 512,
            minimum_available_memory_bytes: 1000,
            minimum_free_bytes: 2000,
            issued_at: 100,
            entry_deadline: 340,
            execution_deadline: 43_540,
        };
        let pb = bound("/sealed/plan.json");
        let ab = bound("/private/admission.json");
        let a = Admission {
            schema: "horizon-epoch145-private-extraction-typed-admission-v1".into(),
            plan: pb.clone(),
            actor_unit: p.actor_unit.clone(),
            actor_iid: "b".repeat(32),
            actor_pid: 42,
            actor_start_ticks: 43,
            accepted_at: 110,
            accepted_boottime_millis: 1000,
            memory_evidence: Value::Null,
            data_evidence: Value::Null,
            existing_memory_bytes: 200,
            protected_existing_data_bytes: 300,
            required_initial_memory_bytes: 900,
            required_initial_data_bytes: 1900,
            original_native: Value::Null,
        };
        let t = Token {
            schema: "horizon-epoch145-private-extractor-native-guard-token-v1".into(),
            plan: pb.clone(),
            admission: ab.clone(),
            actor_iid: a.actor_iid.clone(),
            actor_pid: a.actor_pid,
            actor_start_ticks: a.actor_start_ticks,
            guard_iid: "c".repeat(32),
            guard_pid: 44,
            guard_start_ticks: 45,
            at_unix_seconds: 120,
            at_boottime_millis: 2000,
            protected_free_bytes: 2000,
            protected_available_memory_bytes: 1000,
            actual_free_bytes: 3000,
            actual_available_memory_bytes: 2000,
        };
        (p, pb, a, ab, t)
    }
    #[test]
    fn original_entry_clock_cannot_be_extended_by_capability_or_guard() {
        let (p, _, _, _, _) = fixture();
        assert!(admission::plan_shape(&p, 100).is_ok());
        assert!(admission::plan_shape(&p, 99).is_err());
        assert!(admission::plan_shape(&p, 341).is_err());
        let mut q = p.clone();
        q.entry_deadline += 1;
        assert!(admission::plan_shape(&q, 100).is_err());
    }
    #[test]
    fn caller_approval_boolean_is_not_an_admission_interface() {
        let (p, _, _, _, _) = fixture();
        let mut v = serde_json::to_value(p).unwrap();
        v["admission_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(v).is_err());
    }
    #[test]
    fn exact_plan_rejects_source_tail_relabel_and_inadequate_decoder_budget() {
        let (p, _, _, _, _) = fixture();
        let mut q = p.clone();
        q.source.path = "/private/shortened145.jet".into();
        assert!(admission::plan_shape(&q, 100).is_err());
        let mut q = p.clone();
        q.actor_memory_bytes = 6 * GIB;
        assert!(admission::plan_shape(&q, 100).is_err());
        let mut q = p.clone();
        q.output_maximum_bytes = 160 * GIB + 1;
        assert!(admission::plan_shape(&q, 100).is_err());
    }
    #[test]
    fn native_token_crossed_plan_admission_iid_pid_or_ticks_fail_closed() {
        let (p, pb, a, ab, t) = fixture();
        assert!(token_valid(&t, &p, &pb, &ab, &a, 130, 3000).is_ok());
        let mut bad = t.clone();
        bad.actor_iid = "d".repeat(32);
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
        let mut bad = t.clone();
        bad.actor_pid += 1;
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
        let mut bad = t.clone();
        bad.actor_start_ticks += 1;
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
        let mut bad = t.clone();
        bad.plan.sha256 = "d".repeat(64);
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
        let mut bad = t.clone();
        bad.admission.sha256 = "d".repeat(64);
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
    }
    #[test]
    fn native_token_uses_monotonic_age_and_rejects_future_or_pre_admission_time() {
        let (p, pb, a, ab, t) = fixture();
        assert!(token_valid(&t, &p, &pb, &ab, &a, 130, 92_001).is_err());
        assert!(token_valid(&t, &p, &pb, &ab, &a, 130, 1999).is_err());
        assert!(token_valid(&t, &p, &pb, &ab, &a, 119, 3000).is_err());
        let mut bad = t;
        bad.at_boottime_millis = 999;
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
    }
    #[test]
    fn token_cannot_lower_existing_data_or_memory_floors() {
        let (p, pb, a, ab, t) = fixture();
        let mut bad = t.clone();
        bad.protected_free_bytes = 1900;
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
        let mut bad = t;
        bad.actual_available_memory_bytes = 999;
        assert!(token_valid(&bad, &p, &pb, &ab, &a, 130, 3000).is_err());
    }
}
