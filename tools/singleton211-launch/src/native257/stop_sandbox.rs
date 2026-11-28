//! This ignored test runs only under a separate PID1, mount, cgroup and network
//! namespace. Production snapshots, workers, tokens and manager sockets are absent.
use super::retire::{incident_evidence, order, stop_intent};
use super::*;
use std::os::unix::fs::PermissionsExt;

const ATTEMPT: &str = "takeover-guard-v1";
fn fixture(path: &Path, v: &Value) -> Result<Bound> {
    let bytes = serde_json::to_vec_pretty(v)?;
    fs::create_dir_all(path.parent().context("parent")?)?;
    fs::write(path, &bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    Ok(Bound::new(path, digest(&bytes)))
}
fn env_file(dir: &Path, name: &str, key: &str, sha: &str) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, format!("{key}={sha}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    Ok(())
}
fn isolation() -> Result<()> {
    let host: Value = serde_json::from_slice(&fs::read("/fixture/host-namespaces.json")?)?;
    ensure!(
        fs::read_to_string("/run/systemd/container")?.trim() == "horizon257-stop-fixture",
        "foreign manager"
    );
    for name in ["pid", "mnt", "cgroup", "net"] {
        let current = fs::read_link(format!("/proc/self/ns/{name}"))?;
        let init = fs::read_link(format!("/proc/1/ns/{name}"))?;
        ensure!(
            current == init && current.to_str() != host[name].as_str(),
            "sandbox namespace {name}"
        );
    }
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim()
            == "0::/system.slice/horizon257-sandbox-driver.service",
        "wrong driver cgroup"
    );
    absent(Path::new(WORKER))?;
    absent(Path::new(PACKET))?;
    ensure!(
        fs::read_dir(TOKENS)?.next().is_none() && fs::read_dir(ROOT)?.next().is_none(),
        "sandbox already used"
    );
    Ok(())
}
#[test]
#[ignore = "requires a private nested PID1 fixture with the exact sealed harness and guard"]
fn exact_guard_terminates_a_held_owner_without_a_release_token() -> Result<()> {
    isolation()?;
    Bound::new(HARNESS, HARNESS_SHA).artifact()?;
    Bound::new(GUARD, GUARD_SHA).artifact()?;
    let mut n = Native {
        root: PathBuf::from("/evidence"),
        counter: 0,
        deadline: None,
    };
    n.run("/usr/bin/systemctl", &["start", RETENTION])?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let started = mono()?;
    let wall = now()?;
    n.deadline = Some(started + 58_000_000);
    let h = Bound::new(HARNESS, HARNESS_SHA);
    let g = Bound::new(GUARD, GUARD_SHA);
    let w = Bound::new(WORKER, WORKER_SHA);
    let inputs = Bound::new(PACKET, PACKET_SHA);
    let marker = json!({"isolated_pid1_fixture":true,"host_admission":false});
    let mut a = json!({"schema":"horizon-native257-current-fleet-admission-v1","epoch":257,"mode":"native-cold","operation":"qualify-guard","unit":UNIT,"admitted":true,"harness":h,"guard":g,"worker":w,"input_packet":inputs,"maximum_memory_bytes":MEMORY,"candidate_incremental_peak_bytes":RESERVATION,"protected_existing_floor_bytes":1,"boot_id":boot,"source_publication":marker,"observer":marker,"fleet":marker,"issued_unix_seconds":wall,"expires_unix_seconds":wall+60});
    deny_authority(&mut a);
    let ar = fixture(
        Path::new("/var/lib/jetstreamer/sandbox-fixture-admission/admission.json"),
        &a,
    )?;
    let sp = package(ATTEMPT, "startup-plan");
    let p = json!({"schema":"horizon-native257-startup-plan-v1","operation":"qualify-guard","epoch":257,"unit":UNIT,"guard_unit":GUARD_UNIT,"worker_root":ROOT,"bootstrap_slot":SLOT,
        "snapshot_sha256":SNAPSHOT_SHA,"maximum_root_physical_bytes":SCRATCH,"maximum_memory_bytes":MEMORY,"token_root":TOKENS,"boot_id":boot,"harness":h,"worker":w,"input_packet":inputs,"genesis_sha256":GENESIS_SHA,"guard":g,"admission":ar,"minimum_free_bytes":1,"issued_monotonic_us":started,"expires_monotonic_us":started+60_000_000u64});
    let pr = fixture(&sp.join("plan.json"), &p)?;
    env_file(
        &sp,
        "startup.env",
        "JETSTREAMER_EPOCH257_STARTUP_PLAN_SHA256",
        &pr.sha256,
    )?;
    n.run("/usr/bin/systemctl", &["start", UNIT])?;
    let owner = n.show(UNIT)?;
    let iid = text(&owner, "InvocationID")?;
    let pid = text(&owner, "MainPID")?.parse::<u64>()?;
    ensure!(
        hex(iid, 32)
            && pid > 1
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running",
        "held owner"
    );
    let receipts = PathBuf::from(format!(
        "/var/lib/jetstreamer/horizon-native257-guard-receipts-{iid}"
    ));
    fs::create_dir(&receipts)?;
    fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700))?;
    std::os::unix::fs::symlink(&receipts, package(ATTEMPT, "receipt-mount"))?;
    let gp = json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":UNIT,"invocation_id":iid,"filesystem":ROOT,"boot_id":boot,"main_start_ticks":process_ticks(pid)?,"native_main":{"main_pid":pid,"executable":HARNESS,"sha256":HARNESS_SHA},"minimum_free_bytes":u64::MAX,"worker_root":ROOT,"maximum_root_physical_bytes":SCRATCH,"maximum_worker_vmas":3500000,"receipt_directory":receipts});
    let gd = package(ATTEMPT, "guard-binding");
    let gr = fixture(&gd.join("guard-plan.json"), &gp)?;
    env_file(&gd, "guard.env", "HORIZON257_GUARD_PLAN_SHA256", &gr.sha256)?;
    n.run("/usr/bin/systemctl", &["start", TIMER])?;
    stop::capture_stop(
        &mut n,
        iid,
        pid,
        &receipts,
        &gr,
        &pr,
        &package(ATTEMPT, "producer"),
        &package(ATTEMPT, "guard-units"),
        &p,
    )?;
    let capture: Value =
        serde_json::from_slice(&fs::read(n.root.join("protective-stop-capture.json"))?)?;
    let gid = text(&capture, "guard_invocation_id")?;
    let sample = binding(&capture["sample"])?.json()?;
    handoff::limited_sample(&p, &gp, &sample)?;
    let request = binding(&capture["stop_request"])?.json()?;
    let intent = stop_intent(&capture)?;
    incident_evidence(&sample, &request, &intent.json()?, iid, gid, &gr)?;
    let pj = binding(&capture["producer_pid1"])?.bytes(false)?;
    let gj = binding(&capture["guard_pid1"])?.bytes(false)?;
    order(&capture, &p, &pj, &gj)?;
    for (dst, v) in [
        ("stop-intent.json", intent.json()?),
        ("stop-request.json", request),
        ("triggering-sample.json", sample),
        ("guard-plan.json", gp),
        ("startup-plan.json", p),
    ] {
        save_json(&n.root, dst, &v)?;
    }
    save_json(
        &n.root,
        "sandbox-comparison.json",
        &json!({"schema":"horizon257-independent-pid1-stop-sandbox-v1","fixture_only":true,"host_namespaces":serde_json::from_slice::<Value>(&fs::read("/fixture/host-namespaces.json")?)?,"producer_invocation_id":iid,"guard_invocation_id":gid,"main_pid":pid,"harness":h,"guard":g,"intent":intent,"genuine_pid1_stop":true,"host_protective_stop_qualification":false,"entry_replay":false,"remote_mutations":false}),
    )?;
    Ok(())
}
