//! One writer invocation from donor acquisition to parent node-spawn release.
//! The parent launches the waiting payload and owns authenticated status changes.
//! This controller neither launches actors nor sends the worker's Initialize token.
use super::*;
use std::{
    thread,
    time::{Duration, Instant},
};
#[path = "session_contract.rs"]
mod contract;
#[path = "../horizon_epoch136_actual_20261120_v1/scope.rs"]
mod scope;
const PASS: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch136-preinit-image-custody-20261120-v1/probe/PASS.json";
const PASS_SHA: &str = "235ef6e5deaf79576a56a8bfbab6fe4b9fece3dda7bb0148f7fe1c791e6f044b";

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .with_context(|| format!("missing string {key}"))
}
fn digest(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && s.bytes().any(|b| b != b'0')
}
pub(super) fn immutable(path: &Path) -> Result<(Value, Value)> {
    let m = fs::symlink_metadata(path)?;
    ensure!(m.mode() & 0o222 == 0, "handoff receipt must be immutable");
    let bytes = root_file(path, 16 << 20)?;
    let end = fs::symlink_metadata(path)?;
    ensure!(
        end.mode() & 0o222 == 0
            && end.dev() == m.dev()
            && end.ino() == m.ino()
            && end.ctime() == m.ctime()
            && end.ctime_nsec() == m.ctime_nsec(),
        "handoff receipt changed around immutable read"
    );
    Ok((
        serde_json::from_slice(&bytes)?,
        binding(path, &format!("{:x}", Sha256::digest(bytes))),
    ))
}
fn load(bound: &Value) -> Result<Value> {
    ensure!(
        bound.as_object().is_some_and(|m| m.len() == 2) && digest(text(bound, "sha256")?, 64),
        "bad evidence binding"
    );
    let (v, b) = immutable(Path::new(text(bound, "path")?))?;
    ensure!(b == *bound, "changed immutable handoff evidence");
    Ok(v)
}
pub(super) fn load_admission_for_post(plan: &Value, donor: &Value, iid: &str) -> Result<Value> {
    let base = Path::new(BASE);
    let (admission, _) = immutable(&base.join("admission.json"))?;
    let (capacity, capacity_ref) = immutable(&base.join("capacity.json"))?;
    ensure!(
        admission["resource_accounting"] == capacity_ref
            && capacity["writer_plan"] == *plan
            && capacity["exclusive_handoff_receipt"] == *donor
            && capacity["writer_invocation_id"] == iid
            && admission["writer_invocation_id"] == iid
            && capacity["payload_plan"] == admission["plan"],
        "admission or initial capacity belongs to another writer session"
    );
    Ok(admission)
}

pub(super) fn native_denial_provenance(plan: &Value) -> Result<()> {
    contract::denial(plan, &json_pin(Path::new(PASS), PASS_SHA)?)
}
pub(super) fn register_status(args: &[String]) -> Result<()> {
    let plan = json_pin(Path::new(&args[0]), &args[1])?;
    generation(&plan)?;
    let exe = Path::new(BASE).join("controller/admit136");
    let installed = fs::symlink_metadata(&exe)?;
    let running = fs::metadata("/proc/self/exe")?;
    ensure!(
        installed.dev() == running.dev()
            && installed.ino() == running.ino()
            && plan["controller"]
                == binding(
                    &exe,
                    &format!("{:x}", Sha256::digest(root_file(&exe, 64 << 20)?))
                ),
        "registration requires the exact installed controller"
    );
    let receipts = Path::new(scope::ROOT).join("receipts");
    let (request, request_ref) = immutable(&receipts.join("parent-status-request.json"))?;
    let (ready, ready_ref) = immutable(&receipts.join("ready.json"))?;
    let admission = load(&request["admission"])?;
    let writer_plan = binding(Path::new(&args[0]), &args[1]);
    check_plan_bindings(
        &plan,
        &writer_plan,
        &admission["plan"],
        &load(&admission["resource_accounting"])?,
    )?;
    ensure!(
        request["schema"] == "horizon-epoch136-parent-status-request-v1"
            && request["ready"] == ready_ref
            && request["helper"] == plan["helper"]
            && request["invocation_id"] == ready["invocation_id"]
            && request["writer_plan"] == writer_plan
            && request["payload_plan"] == admission["plan"]
            && request["writer"] == admission["writer"]
            && request["writer_invocation_id"] == admission["writer_invocation_id"]
            && now()? < n(&request, "handoff_deadline_unix_seconds")?,
        "foreign/expired registration request"
    );
    let writer = show(WRITER_UNIT)?;
    ensure!(
        writer["ActiveState"] == "active"
            && writer["SubState"] == "running"
            && writer["InvocationID"] == admission["writer_invocation_id"]
            && writer["Job"] == "",
        "original session writer is absent"
    );
    let launch = load(&ready["launch"])?;
    ensure!(
        launch["admission"] == request["admission"],
        "wrong registration launch"
    );
    contract::ready(&plan, &admission, &ready, &launch, now()?)?;
    current_prefire(&ready, &admission)?;
    let status_ref = binding(Path::new(&args[2]), &args[3]);
    let fleet_ref = binding(Path::new(&args[4]), &args[5]);
    let status = load(&status_ref)?;
    let fleet = load(&fleet_ref)?;
    let initial_fleet = load(&request["complete_fleet"])?;
    let owner = contract::pending_owner(&plan, &ready, &ready_ref, &request_ref);
    let registration = json!({"schema":"horizon-epoch136-current-owner-registration-v1",
        "epoch":136,"unit":UNIT,"invocation_id":ready["invocation_id"],"helper":plan["helper"],
        "request":request_ref,"writer_plan":writer_plan,"payload_plan":admission["plan"],"repair_open":true,"ordinary_replay_claim":false,
        "authenticated_readback":true,"recorded_unix_seconds":status["epoch136_registration_unix_seconds"],
        "status_receipt":status_ref,"fleet_receipt":fleet_ref,
        "node_spawn_authorized":false,"initialize_authorized":false,"r2_mutations":false});
    contract::registration(
        &registration,
        &owner,
        &status,
        &fleet,
        &initial_fleet,
        now()?,
    )?;
    current_owner(&ready)?;
    ensure!(
        now()? < n(&request, "handoff_deadline_unix_seconds")?,
        "registration expired"
    );
    let result = file_write(
        &receipts.join("parent-status-registration.json"),
        &registration,
    )?;
    println!("{result}");
    Ok(())
}
fn current_owner(ready: &Value) -> Result<()> {
    let iid = text(ready, "invocation_id")?;
    candidate_state(Some(iid))?;
    let live = show(UNIT)?;
    let pid = n(ready, "pid")?;
    ensure!(
        live["MainPID"].as_str().and_then(|p| p.parse::<u64>().ok()) == Some(pid)
            && ticks(pid)? == n(ready, "start_ticks")?,
        "waiting owner PID reused"
    );
    Ok(())
}
fn timer_trigger() -> Result<u64> {
    let mut path = String::from("/org/freedesktop/systemd1/unit/");
    for byte in scope::GUARD_TIMER.bytes() {
        if byte.is_ascii_alphanumeric() {
            path.push(char::from(byte));
        } else {
            path.push_str(&format!("_{byte:02x}"));
        }
    }
    let out = Command::new("/usr/bin/busctl")
        .args([
            "--system",
            "--timeout=5s",
            "get-property",
            "org.freedesktop.systemd1",
            &path,
            "org.freedesktop.systemd1.Timer",
            "LastTriggerUSecMonotonic",
        ])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 64,
        "timer property query"
    );
    let raw = std::str::from_utf8(&out.stdout)?;
    let value = raw
        .strip_prefix("t ")
        .and_then(|s| s.strip_suffix('\n'))
        .context("typed monotonic timer trigger")?
        .parse::<u64>()?;
    ensure!(
        value > 0 && raw == format!("t {value}\n"),
        "timer has not fired"
    );
    Ok(value)
}
fn current_prefire(ready: &Value, admission: &Value) -> Result<Value> {
    current_owner(ready)?;
    let timer = show(scope::GUARD_TIMER)?;
    ensure!(
        timer["ActiveState"] == "active"
            && timer["Unit"] == scope::GUARD_UNIT
            && timer["Job"] == "",
        "payload timer not armed"
    );
    let trigger = timer_trigger()?;
    let guard = show(scope::GUARD_UNIT)?;
    let iid = text(&guard, "InvocationID")?;
    let command = format!(
        "{{ path={} ; argv[]={0} {}/receipts/guard-plan.json --plan-sha256 {} --self-sha256 {} ; ignore_errors=no ; start_time=",
        scope::GUARD_PATH,
        scope::ROOT,
        text(ready, "guard_plan_sha256")?,
        scope::GUARD_SHA
    );
    ensure!(
        guard168::iid(iid)
            && guard["Type"] == "oneshot"
            && guard["MainPID"] == "0"
            && guard["ControlPID"] == "0"
            && guard["NRestarts"] == "0"
            && guard["Result"] == "success"
            && guard["ExecMainStatus"] == "0"
            && guard["TimeoutStartUSec"] == "1min 30s"
            && text(&guard, "ExecMainStartTimestampMonotonic")?.parse::<u64>()? >= trigger
            && text(&guard, "ExecStart")?.starts_with(&command)
            && text(&guard, "ExecStart")?.matches(" ; argv[]=").count() == 1,
        "missing genuine completed timer-driven prefire"
    );
    let path = Path::new(scope::ROOT).join(format!("receipts/guard/sample-{iid}.json"));
    let bytes = root_file(&path, 1 << 20)?;
    let sample: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        sample["guard_invocation_id"] == iid,
        "crossed guard invocation"
    );
    contract::prefire(&sample, ready, admission, now()?)?;
    current_owner(ready)?;
    ensure!(
        show(scope::GUARD_UNIT)?["InvocationID"] == iid
            && show(scope::GUARD_TIMER)?["InvocationID"] == timer["InvocationID"],
        "guard changed during consumption"
    );
    Ok(
        json!({"sample":binding(&path,&format!("{:x}",Sha256::digest(bytes))),
        "guard":guard,"timer":timer,"timer_trigger_usec_monotonic":trigger}),
    )
}
fn wait_file(path: &Path, deadline: u64, budget: Duration) -> Result<(Value, Value)> {
    let start = Instant::now();
    loop {
        ensure!(
            now()? < deadline && start.elapsed() < budget,
            "parent session deadline: {}",
            path.display()
        );
        match fs::symlink_metadata(path) {
            Ok(_) => return immutable(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                thread::sleep(Duration::from_millis(200))
            }
            Err(e) => return Err(e.into()),
        }
    }
}
pub(super) fn release_incident(path: &Path, allow_release: bool) -> Result<Value> {
    let (intent, original) = immutable(path)?;
    let iid = text(&intent, "writer_invocation_id")?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let (plan, source) = immutable(Path::new(text(&intent["writer_plan"], "path")?))?;
    #[cfg(feature = "fixture-semantic")]
    super::fixture_plan::validate(&plan)?;
    ensure!(
        intent["schema"] == "horizon-136-incident-donor-intent-v1"
            && intent["boot_id"] == boot.trim()
            && guard168::iid(iid)
            && source == intent["writer_plan"]
            && plan["controller"] == intent["writer"]
            && plan["holding145_prestart_ready"] == intent["selector"],
        "foreign donor intent"
    );
    let image = fs::read("/proc/self/exe")?;
    ensure!(
        format!("{:x}", Sha256::digest(image)) == text(&intent["writer"], "sha256")?,
        "release requires the original verified controller"
    );
    let admission = Path::new(BASE).join("admission.json");
    let admitted = if admission.try_exists()? {
        let (a, binding) = immutable(&admission)?;
        ensure!(
            a["writer_invocation_id"] == iid
                && a["writer"] == intent["writer"]
                && now()? >= n(&a, "launch_expires_unix_seconds")?,
            "different or unexpired admission"
        );
        Some(binding)
    } else {
        None
    };
    let registered = intent["standard_routes"]
        .as_object()
        .context("original standard CPU routes")?;
    let routes = registered.keys().cloned().collect::<BTreeSet<_>>();
    ensure!(
        !routes.is_empty() && routes.iter().all(|u| standard169::valid_name(u)),
        "foreign donor routes"
    );
    let result_path = Path::new(BASE).join("prestart-released.json");
    if result_path.try_exists()? {
        let (receipt, binding) = immutable(&result_path)?;
        ensure!(
            receipt["schema"] == "horizon-136-incident-donor-released-v1"
                && receipt["epoch"] == 136
                && receipt["writer_invocation_id"] == iid
                && receipt["boot_id"] == boot.trim()
                && receipt["intent"] == original
                && receipt["admission"] == json!(admitted)
                && receipt["donor_restored"] == true
                && receipt["candidate_physically_drained"] == true
                && receipt["resource_credit_bytes"] == 0
                && receipt["original_routes"] == json!(routes),
            "released another 136 generation"
        );
        fence::confirm_released(&routes)?;
        return Ok(binding);
    }
    ensure!(allow_release, "no completed donor release receipt");
    fence::finish_release(&routes)?;
    file_write(
        &result_path,
        &json!({
            "schema":"horizon-136-incident-donor-released-v1","epoch":136,"intent":original,
            "writer_invocation_id":iid,"admission":admitted,"boot_id":boot.trim(),
            "recorded_unix_seconds":now()?,"original_routes":routes,"donor_restored":true,
            "candidate_physically_drained":true,"all_physical_outputs_retained":true,"resource_credit_bytes":0
        }),
    )
}

fn phase_args(name: &str, args: &[String], iid: Option<&str>) -> Vec<String> {
    let mut out = vec![name.to_owned()];
    out.extend_from_slice(args);
    if let Some(id) = iid {
        out.push(id.to_owned());
    }
    out
}
pub(super) fn run(args: &[String]) -> Result<()> {
    // run() in main.rs owns the flock for the entire lifetime of this call.
    // All immutable outputs are no-clobber. Restart cannot mint another lease.
    let base = Path::new(BASE);
    for name in [
        "prestart-intent.json",
        "prestart-released.json",
        "donor171.json",
        "capacity.json",
        "admission.json",
        "capacity-post-prefire.json",
    ] {
        ensure!(
            fs::symlink_metadata(base.join(name))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "session requires an unused generation: {name}"
        );
    }
    ensure!(
        fs::symlink_metadata(scope::ROOT).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "payload reproduction root already exists"
    );
    let plan = json_pin(Path::new(&args[0]), &args[1])?;
    let initial_fleet = json_pin(Path::new(&args[2]), &args[3])?;
    let donor = phase(&phase_args("establish", args, None))?;
    let admission_ref = phase(&phase_args("prepare", args, None))?;
    let admission = load(&admission_ref)?;
    let writer_plan = binding(Path::new(&args[0]), &args[1]);
    check_plan_bindings(
        &plan,
        &writer_plan,
        &admission["plan"],
        &load(&admission["resource_accounting"])?,
    )?;
    let deadline = n(&admission, "launch_expires_unix_seconds")?;
    // A durable notification to the already-authorized parent, not an actor launch.
    file_write(
        &base.join("parent-launch-request.json"),
        &json!({
            "schema":"horizon-epoch136-parent-launch-request-v1","admission":admission_ref,
            "donor":donor,"writer":admission["writer"],"writer_invocation_id":admission["writer_invocation_id"],
            "unit":UNIT,"plan":admission["plan"],"writer_plan":writer_plan,"helper":plan["helper"],
            "launch_expires_unix_seconds":deadline,"native_denial":binding(Path::new(PASS),PASS_SHA),
            "actor_launch_performed":false,"r2_mutations":false,"initialize_authorized":false
        }),
    )?;
    let receipts = Path::new(scope::ROOT).join("receipts");
    let (ready, ready_ref) = wait_file(
        &receipts.join("ready.json"),
        deadline,
        Duration::from_secs(900),
    )?;
    let launch = load(&ready["launch"])?;
    ensure!(
        ready["launch"]["path"] == receipts.join("launch.json").to_str().unwrap()
            && launch["admission"] == admission_ref,
        "foreign launch evidence"
    );
    contract::ready(&plan, &admission, &ready, &launch, now()?)?;
    let prefire = current_prefire(&ready, &admission)?;
    let handoff_deadline = deadline.min(
        n(&ready, "recorded_unix_seconds")?
            .checked_add(175)
            .context("handoff deadline overflow")?,
    );
    let request = file_write(
        &receipts.join("parent-status-request.json"),
        &json!({
            "schema":"horizon-epoch136-parent-status-request-v1","epoch":136,"unit":UNIT,
            "invocation_id":ready["invocation_id"],"helper":plan["helper"],"ready":ready_ref,
            "launch":ready["launch"],"admission":admission_ref,"guard_prefire":prefire,
            "complete_fleet":binding(Path::new(&args[2]),&args[3]),"writer_plan":writer_plan,"payload_plan":admission["plan"],
            "writer":admission["writer"],"writer_invocation_id":admission["writer_invocation_id"],
            "recorded_unix_seconds":now()?,"handoff_deadline_unix_seconds":handoff_deadline,
            "status_registration_path":receipts.join("parent-status-registration.json"),
            "parent_owns_authenticated_status_publication":true,"repair_open":true,
            "ordinary_replay_claim":false,"node_spawned":false,"worker_spawned":false,
            "positive_worker_release_still_required":true,"initialize_authorized":false,"r2_mutations":false
        }),
    )?;
    let owner = contract::pending_owner(&plan, &ready, &ready_ref, &request);
    let (registration, registration_ref) = wait_file(
        &receipts.join("parent-status-registration.json"),
        handoff_deadline,
        Duration::from_secs(90),
    )?;
    let status = load(&registration["status_receipt"])?;
    ensure!(
        registration["writer_plan"] == writer_plan
            && registration["payload_plan"] == admission["plan"],
        "registration plan bindings changed"
    );
    let registered_fleet = load(&registration["fleet_receipt"])?;
    contract::registration(
        &registration,
        &owner,
        &status,
        &registered_fleet,
        &initial_fleet,
        now()?,
    )?;
    // Rebuild current capacity only after the parent's potentially slow status operation.
    // This is the original full fit, donor lease and fresh native ownership path.
    let capacity = phase(&phase_args(
        "post",
        args,
        Some(text(&ready, "invocation_id")?),
    ))?;
    let capacity_value = load(&capacity)?;
    ensure!(
        now()?.saturating_sub(n(&capacity_value, "recorded_unix_seconds")?) <= 120,
        "post-prefire fit already stale"
    );
    ensure!(
        now()? < handoff_deadline,
        "payload handoff expired during capacity fit"
    );
    contract::registration(
        &registration,
        &owner,
        &status,
        &registered_fleet,
        &initial_fleet,
        now()?,
    )?;
    let final_prefire = current_prefire(&ready, &admission)?;
    ensure!(
        load(&ready_ref)? == ready && load(&registration_ref)? == registration,
        "parent handoff changed before release"
    );
    ensure!(
        now()? < handoff_deadline
            && load(&registration["status_receipt"])? == status
            && load(&registration["fleet_receipt"])? == registered_fleet,
        "parent evidence changed or handoff expired"
    );
    let (author, writer_iid) = writer(&plan)?;
    ensure!(
        author == admission["writer"] && writer_iid == text(&admission, "writer_invocation_id")?,
        "writer invocation changed"
    );
    let release = file_write(
        &receipts.join("parent-release.json"),
        &json!({
            "schema":"horizon-epoch136-actual-parent-release-v1","unit":UNIT,
            "invocation_id":ready["invocation_id"],"ready":ready_ref,"launch":ready["launch"],
            "writer":author,"writer_invocation_id":writer_iid,"helper":plan["helper"],
            "node":plan["node"],"worker":plan["worker"],"post_prefire_capacity":capacity,
            "status_registration":registration_ref,"guard_prefire":final_prefire,
            "recorded_unix_seconds":registration["recorded_unix_seconds"],
            "node_spawn_authorized":true,"initialize_authorized":false,
            "positive_worker_release_still_required":true,"publication_authorized":false,"r2_mutations":false
        }),
    )?;
    println!("{release}");
    Ok(())
}
#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
