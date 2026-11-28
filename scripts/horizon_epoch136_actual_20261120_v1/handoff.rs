//! Parent-owned current-capacity/status handoff, after this payload's real guard prefire.
//! Replaces the obsolete retry0005 Frame/foreman chain with a separate new contract;
//! the historical chain and its already-consumed retirement credit remain untouched.
use super::*;
fn binding(path: &Path) -> Result<Bound> {
    let mut f = immutable(path, 16 << 20)?;
    let before = identity(&f.metadata()?);
    let (sha256, _) = hash_file(&mut f, 16 << 20)?;
    ensure!(
        identity(&f.metadata()?) == before && identity(&fs::symlink_metadata(path)?) == before,
        "handoff changed"
    );
    Ok(Bound {
        path: path.into(),
        sha256,
    })
}
pub(super) fn wait(
    p: &Plan,
    a: &Admission,
    iid: &str,
    guard_sha: &str,
    initial: &root_budget::Observation,
) -> Result<()> {
    let root = Path::new(ROOT);
    let launch = binding(&root.join("receipts/launch.json"))?;
    let before = actual_guard(iid, guard_sha, None, a.protected_existing_free_bytes, 0)?;
    ensure!(
        before["sample"]["workers"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "prefire already has a worker"
    );
    persist(
        &root.join("receipts/ready.json"),
        &json!({"schema":"horizon-epoch136-actual-ready-v1",
        "unit":UNIT,"invocation_id":iid,"helper":p.helper,"node":p.node,"worker":p.worker,
        "pid":std::process::id(),"start_ticks":start(std::process::id())?,"launch":launch,
        "guard_plan_sha256":guard_sha,"guard_prefire":before,"root_meter":initial,
        "recorded_unix_seconds":now()?,"node_spawned":false,"worker_spawned":false,
        "publication_authorized":false}),
    )?;
    let ready = binding(&root.join("receipts/ready.json"))?;
    let path = root.join("receipts/parent-release.json");
    let started = Instant::now();
    loop {
        ensure!(
            SIGNAL.load(Ordering::SeqCst) == 0
                && started.elapsed() < Duration::from_secs(180)
                && now()? < a.launch_expires_unix_seconds,
            "parent handoff deadline/signal"
        );
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            Err(e) => return Err(e.into()),
            Ok(_) => (),
        }
        let release = value(&binding(&path)?)?;
        ensure!(
            release["schema"] == "horizon-epoch136-actual-parent-release-v1"
                && release["unit"] == UNIT
                && release["invocation_id"] == iid
                && release["ready"] == json!(ready)
                && release["launch"] == json!(launch)
                && release["writer"] == json!(a.writer)
                && release["writer_invocation_id"] == a.writer_invocation_id
                && release["helper"] == json!(p.helper)
                && release["node"] == json!(p.node)
                && release["worker"] == json!(p.worker)
                && release["node_spawn_authorized"] == true
                && release["publication_authorized"] == false
                && release["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|t| t <= now().unwrap_or(0)
                        && t >= a.recorded_unix_seconds
                        && now().unwrap_or(u64::MAX).saturating_sub(t) <= 120),
            "foreign or stale current-parent release"
        );
        let capacity_binding: Bound =
            serde_json::from_value(release["post_prefire_capacity"].clone())?;
        let capacity = value(&capacity_binding)?;
        contract::capacity(a, &capacity)?;
        let status: Bound = serde_json::from_value(release["status_registration"].clone())?;
        let status = value(&status)?;
        ensure!(
            status["schema"] == "horizon-epoch136-current-owner-registration-v1"
                && status["epoch"] == 136
                && status["unit"] == UNIT
                && status["invocation_id"] == iid
                && status["helper"] == json!(p.helper)
                && status["repair_open"] == true
                && status["ordinary_replay_claim"] == false
                && status["authenticated_readback"] == true
                && status["recorded_unix_seconds"] == release["recorded_unix_seconds"],
            "current status owner missing"
        );
        for key in ["status_receipt", "fleet_receipt"] {
            let bound: Bound = serde_json::from_value(status[key].clone())?;
            value(&bound)?;
        }
        let current = actual_guard(iid, guard_sha, None, a.protected_existing_free_bytes, 0)?;
        ensure!(
            current["sample"]["workers"]
                .as_array()
                .is_some_and(Vec::is_empty),
            "unexpected worker before spawn"
        );
        native_owner(&native(UNIT)?, iid)?;
        return Ok(());
    }
}
