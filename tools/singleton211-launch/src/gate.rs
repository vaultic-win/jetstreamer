//! The same service MainPID waits here before exec; no node, worker or input body is opened.
use super::*;
use std::os::unix::process::CommandExt;

pub(super) fn held(pid: u64, iid: &str) -> Result<()> {
    held_image(pid, iid, UNIT, GATE)
}
pub(super) fn held_image(pid: u64, iid: &str, unit: &str, exe: &str) -> Result<()> {
    ensure!(pid > 1 && hex(iid, 32), "held identity");
    let proc = PathBuf::from(format!("/proc/{pid}"));
    ensure!(
        fs::read_link(proc.join("exe"))? == Path::new(exe)
            && metadata_identity(&fs::metadata(proc.join("exe"))?) == identity(Path::new(exe))?,
        "held gate mapped image differs"
    );
    ensure!(
        fs::read_to_string(proc.join("cgroup"))?.trim() == format!("0::/system.slice/{unit}"),
        "held gate moved cgroup"
    );
    ensure!(
        fs::read_to_string(proc.join(format!("task/{pid}/children")))?
            .trim()
            .is_empty(),
        "gate has children before release"
    );
    let members = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{unit}/cgroup.procs"))?;
    for child in fs::read_dir(format!("/sys/fs/cgroup/system.slice/{unit}"))? {
        ensure!(
            !child?.file_type()?.is_dir(),
            "held service has a descendant cgroup"
        );
    }
    ensure!(
        members
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>()
            == vec![pid.to_string()],
        "held service has another process"
    );
    Ok(())
}
fn clock(p: &Value, current: u64) -> Result<()> {
    let issued = num(p, "issued_monotonic_us")?;
    let expires = num(p, "expires_monotonic_us")?;
    ensure!(
        expires > issued
            && expires - issued <= 60_000_000
            && current >= issued
            && current < expires,
        "original first-guard deadline expired"
    );
    Ok(())
}
pub(super) fn plan(p: &Value, self_sha: &str, boot: &str, current: u64) -> Result<()> {
    ensure!(
        p["schema"] == "horizon-singleton211-startup-plan-v1"
            && p["epoch"] == 211
            && p["unit"] == UNIT
            && p["guard_unit"] == GUARD_UNIT
            && p["worker_root"] == ROOT
            && p["token_root"] == TOKENS
            && p["bootstrap_slot"] == 91151575u64
            && p["snapshot_sha256"] == SNAPSHOT_SHA
            && p["maximum_root_physical_bytes"] == SCRATCH
            && p["maximum_memory_bytes"] == MEMORY
            && p["gate"] == json!(Bound::new(GATE, self_sha))
            && p["node"] == json!(Bound::new(NODE, NODE_SHA))
            && p["worker"] == json!(Bound::new(WORKER, WORKER_SHA))
            && p["native_input"] == json!(Bound::new(NATIVE_PROOF, NATIVE_PROOF_SHA))
            && p["boot_id"] == boot
            && num(p, "minimum_free_bytes")? > 0
            && binding(&p["guard"])?.path == Path::new(GUARD)
            && hex(text(&p["guard"], "sha256")?, 64),
        "startup plan differs"
    );
    qualification::operation(p)?;
    clock(p, current)
}
fn token_clock(p: &Value, t: &Value, current: u64) -> Result<()> {
    clock(p, current)?;
    let captured = num(t, "recorded_monotonic_us")?;
    let next = num(t, "candidate_next_elapse_monotonic_us")?;
    ensure!(
        next.checked_sub(captured).is_some_and(|d| d <= 35_000_000)
            && current.checked_add(5_000_000).is_some_and(|v| v < next),
        "first candidate guard window expired"
    );
    Ok(())
}
pub(super) fn token(
    p: &Value,
    pr: &Bound,
    t: &Value,
    iid: &str,
    pid: u64,
    current: u64,
    wall: u64,
) -> Result<()> {
    ensure!(
        !qualification::operation(p)?,
        "protective-stop experiment cannot accept a release token"
    );
    token_clock(p, t, current)?;
    ensure!(
        t["schema"] == "horizon-singleton211-first-guard-token-v1"
            && t["startup_plan_sha256"] == pr.sha256
            && t["unit"] == UNIT
            && t["invocation_id"] == iid
            && t["main_pid"] == pid
            && t["gate"] == p["gate"]
            && t["node"] == p["node"]
            && t["worker"] == p["worker"]
            && t["guard"] == p["guard"]
            && t["boot_id"] == p["boot_id"]
            && t["admission"] == p["admission"]
            && num(t, "recorded_monotonic_us")? <= current,
        "release token changed owner or plan"
    );
    lifecycle::replay_only(t)?;
    let gp = binding(&t["guard_plan"])?.sealed()?;
    let g = binding(&t["guard_sample"])?.sealed()?;
    let j = binding(&t["guard_pid1_journal"])?.sealed()?;
    launch::first_guard(p, t, &gp, &g, &j, wall)
}
pub(super) fn run(args: &[String]) -> Result<()> {
    ensure!(
        args.len() == 5 && unsafe { libc::geteuid() } == 1000 && unsafe { libc::getegid() } == 1000,
        "usage: launcher gate PLAN SHA256 SELF_SHA256 under epoch211 service uid1000"
    );
    ensure!(
        hex(&args[4], 64)
            && hash(Path::new("/proc/self/exe"))? == args[4]
            && fs::canonicalize("/proc/self/exe")? == Path::new(GATE),
        "mapped startup image differs"
    );
    let pr = Bound::new(&args[2], &args[3]);
    ensure!(
        pr.path.file_name().and_then(|s| s.to_str()) == Some("plan.json")
            && pr.path.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && pr
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-singleton211-startup-plan-")),
        "startup plan namespace"
    );
    let original = identity(&pr.path)?;
    let p = pr.sealed()?;
    let iid = std::env::var("INVOCATION_ID")?;
    let pid = std::process::id() as u64;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    plan(&p, &args[4], boot.trim(), mono()?)?;
    held(pid, &iid)?;
    let a = binding(&p["admission"])?.sealed()?;
    lifecycle::admission(&a, &p)?;
    let capability = binding(&p["input_capability"])?.sealed()?;
    inputs::validate_identities(&capability)?;
    let dest = Path::new(TOKENS).join(&iid);
    let tp = dest.join("guard-admission.json");
    println!("epoch211-full-startup held invocation={iid} pid={pid} snapshot_opened=false");
    loop {
        clock(&p, mono()?)?;
        ensure!(
            identity(&pr.path)? == original,
            "startup plan inode changed"
        );
        held(pid, &iid)?;
        if qualification::operation(&p)? {
            absent(&dest)?;
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        match fs::symlink_metadata(&tp) {
            Ok(_) => {
                let dp = dest.join("guard-admission.sha256");
                trusted_parents(&dp)?;
                let id = identity(&dp)?;
                ensure!(
                    id.3 == 0 && id.4 & 0o222 == 0 && id.2 == 65,
                    "release digest custody"
                );
                let bytes = fs::read(&dp)?;
                ensure!(
                    identity(&dp)? == id && bytes.last() == Some(&b'\n'),
                    "release digest changed"
                );
                let sha = std::str::from_utf8(&bytes)?.trim();
                let t = Bound::new(&tp, sha).sealed()?;
                token(&p, &pr, &t, &iid, pid, mono()?, now()?)?;
                inputs::validate_identities(&capability)?;
                ensure!(
                    identity(&pr.path)? == original,
                    "startup plan changed during proof"
                );
                held(pid, &iid)?;
                // Node and worker cannot have run before this point. Keep the same PID/IID.
                clock(&p, mono()?)?;
                println!(
                    "epoch211-full-startup released invocation={iid} pid={pid} plan_sha256={} guard_invocation={}",
                    pr.sha256,
                    text(&t, "guard_invocation_id")?
                );
                return before_exec(
                    || token_clock(&p, &t, mono()?),
                    || {
                        let error = Command::new(NODE)
                            .args(launch::node_args())
                            .env_clear()
                            .envs(launch::environment())
                            .env("HOME", "/home/ubuntu")
                            .env("USER", "ubuntu")
                            .env("LOGNAME", "ubuntu")
                            .env(
                                "PATH",
                                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                            )
                            .env("INVOCATION_ID", &iid)
                            .exec();
                        Err(error.into())
                    },
                );
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    }
}
fn before_exec(
    check: impl FnOnce() -> Result<()>,
    exec: impl FnOnce() -> Result<()>,
) -> Result<()> {
    check()?;
    exec()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_candidate_first_timer_limits_token_through_same_pid_exec() {
        let p = json!({"issued_monotonic_us":100,"expires_monotonic_us":60_000_100});
        let t = json!({"recorded_monotonic_us":10_000_000,"candidate_next_elapse_monotonic_us":30_000_000});
        token_clock(&p, &t, 24_999_999).unwrap();
        assert!(token_clock(&p, &t, 25_000_000).is_err());
        assert!(token_clock(&p, &json!({"recorded_monotonic_us":10_000_000}), 15_000_000).is_err());
    }
    #[test]
    fn denied_start_never_executes_node_or_snapshot_work() {
        let called = std::cell::Cell::new(false);
        assert!(
            before_exec(
                || bail!("missing first fire"),
                || {
                    called.set(true);
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(!called.get());
        before_exec(
            || Ok(()),
            || {
                called.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(called.get());
    }
    #[test]
    fn held_gate_deadline_is_original_and_bounded() {
        let p = json!({"issued_monotonic_us":100,"expires_monotonic_us":200});
        assert!(clock(&p, 100).is_ok());
        assert!(clock(&p, 199).is_ok());
        assert!(clock(&p, 99).is_err());
        assert!(clock(&p, 200).is_err());
        assert!(
            clock(
                &json!({"issued_monotonic_us":100,"expires_monotonic_us":60_000_101}),
                100
            )
            .is_err()
        );
    }
    #[test]
    fn command_is_full_epoch_and_preserves_the_canonical_tail() {
        let a = launch::node_args();
        assert_eq!(a[0], "211");
        assert_eq!(a[1], format!("{ROOT}/output"));
        assert!(a.contains(&"--verify".into()));
        assert!(a.contains(&"--root-checkpoint-cohort".into()));
        assert!(
            !a.iter()
                .any(|s| s.starts_with("--focused") || s.contains("end-slot"))
        );
        assert_eq!(91_583_999 - 91_583_512, 487);
        assert_eq!(91_584_000 - 91_152_000, 432000);
    }
}
