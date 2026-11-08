//! The actual original ready/task/enrollment/current-reader and c71 handoff.
//! Every dynamic digest comes from completed originals, never a predicted receipt.
use crate::*;
use std::io::Read;
use std::os::unix::process::CommandExt;
fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn open_generated_json(path: &Path, uid: u32, mode: u32) -> Result<(Bound, Value)> {
    let mut f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o777 == mode
            && m.len() <= 4 << 20,
        "exact original generated JSON custody"
    );
    let mut raw = Vec::new();
    std::io::Read::by_ref(&mut f)
        .take((4 << 20) + 1)
        .read_to_end(&mut raw)?;
    let a = f.metadata()?;
    let b = fs::symlink_metadata(path)?;
    ensure!(
        identity(&m) == identity(&a) && identity(&m) == identity(&b) && raw.len() as u64 == m.len(),
        "original generated JSON changed"
    );
    let value: Value = serde_json::from_slice(&raw)?;
    Ok((
        Bound {
            path: path.into(),
            sha256: storage::sha(&raw),
        },
        value,
    ))
}
// This wait observes only original ready-file events, never resource polling.
fn wait_ready(
    control: &Path,
    actor: &str,
    r: &mut process::Runner<'_>,
) -> Result<(Bound, Value, Value)> {
    let metadata = fs::symlink_metadata(control)?;
    ensure!(
        control.canonicalize()? == control
            && metadata.is_dir()
            && metadata.uid() == 1001
            && metadata.mode() & 0o7777 == 0o700,
        "actual original ready directory custody"
    );
    struct Watch(i32);
    impl Drop for Watch {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let name = std::ffi::CString::new(control.as_os_str().as_encoded_bytes())?;
    let watch = Watch(unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) });
    ensure!(
        watch.0 >= 0
            && unsafe {
                libc::inotify_add_watch(
                    watch.0,
                    name.as_ptr(),
                    libc::IN_CLOSE_WRITE
                        | libc::IN_MOVED_TO
                        | libc::IN_DELETE_SELF
                        | libc::IN_MOVE_SELF,
                )
            } >= 0,
        "original ready event watch"
    );
    for _ in 0..256 {
        let mut found = Vec::new();
        for entry in fs::read_dir(control)? {
            let entry = entry?;
            let leaf = entry.file_name();
            let leaf = leaf.to_str().context("ready leaf UTF8")?;
            if leaf
                .strip_prefix("ready-")
                .and_then(|x| x.strip_suffix(".json"))
                .is_some_and(|x| storage::hex(x, 32))
            {
                found.push(entry.path());
            }
        }
        ensure!(found.len() <= 1, "ambiguous original ready writer");
        if let Some(path) = found.pop() {
            let (binding, ready) = open_generated_json(&path, 1001, 0o600)?;
            let iid = text(&ready, "actor_invocation_id")?;
            let native = r.native(actor)?;
            ensure!(
                storage::hex(iid, 32)
                    && path == control.join(format!("ready-{iid}.json"))
                    && ready["schema"] == "horizon-epoch185-worker-ready-v4"
                    && ready["epoch"] == 185
                    && ready["actor_unit"] == actor
                    && ready["driver_sha256"] == DRIVER_SHA
                    && ready["metadata_and_prerequisites_validated"] == true
                    && native["InvocationID"] == iid
                    && native["NRestarts"] == "0"
                    && native["MainPID"] == "0"
                    && native["ActiveState"] == "activating"
                    && native["SubState"] == "start-pre"
                    && text(&native, "ControlPID")?.parse::<u64>()? > 1,
                "actual original185 ready/start-pre identity"
            );
            let start = n(&ready, "started_at")?;
            let clock = now()?;
            ensure!(
                start <= clock && clock - start < 600,
                "original ready setup clock"
            );
            return Ok((binding, ready, native));
        }
        let left = r
            .deadline
            .min(r.pool_deadline)
            .checked_duration_since(Instant::now())
            .context("original ready event deadline")?;
        let mut poll = libc::pollfd {
            fd: watch.0,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut poll,
                1,
                left.as_millis().clamp(1, i32::MAX as u128) as i32,
            )
        };
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        ensure!(
            result > 0 && poll.revents & libc::POLLIN != 0,
            "original ready event expired"
        );
        let mut bytes = [0u8; 65536];
        let count = unsafe { libc::read(watch.0, bytes.as_mut_ptr().cast(), bytes.len()) };
        ensure!(count > 0, "original ready event stream closed");
        let mut offset = 0;
        while offset < count as usize {
            ensure!(
                offset + std::mem::size_of::<libc::inotify_event>() <= count as usize,
                "truncated ready event"
            );
            let event = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(offset).cast::<libc::inotify_event>())
            };
            ensure!(
                event.mask
                    & (libc::IN_Q_OVERFLOW
                        | libc::IN_DELETE_SELF
                        | libc::IN_MOVE_SELF
                        | libc::IN_IGNORED)
                    == 0,
                "original ready watch overflow/movement"
            );
            offset = offset
                .checked_add(std::mem::size_of::<libc::inotify_event>() + event.len as usize)
                .context("ready event overflow")?;
            ensure!(offset <= count as usize, "truncated ready event name");
        }
    }
    anyhow::bail!("original ready event bound exceeded")
}

fn rebind(v: &Value, old: &Value, new: &Value) -> Value {
    for k in ["observer", "fleet", "fleet_plan", "frame"] {
        if v == &old[k] {
            return new[k].clone();
        }
    }
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| (k.clone(), rebind(v, old, new)))
                .collect(),
        ),
        Value::Array(a) => json!(a.iter().map(|v| rebind(v, old, new)).collect::<Vec<_>>()),
        _ => v.clone(),
    }
}
fn sealed_spec(r: &mut process::Runner<'_>, label: &str, iid: &str, v: &Value) -> Result<Bound> {
    let sb = storage::save(r.root, &format!("{label}-source.json"), v)?;
    let d = Path::new("/usr/local/lib/jetstreamer")
        .join(format!("horizon-epoch185-positive-{label}-{iid}"));
    let result = seal(r, label, &d, &[("spec.json", sb)])?;
    binding(&result["members"]["spec.json"])
}
pub fn continue_original(v: &Value, r: &mut process::Runner<'_>) -> Result<()> {
    require_qualified_fleet_helper()?;
    let control = binding(&v["reader_lifecycle_control"])?;
    crate::persistent_reader::validate_control(r, &control)?;
    let b = binding(&v["activation"])?;
    let activation = storage::json(&b)?;
    let route = storage::json(&binding(&activation["qualified_route"])?)?;
    let capability = storage::json(&binding(&route["capability_acceptance"])?)?;
    ensure!(
        capability["actual_persistent_reader_lifecycle_control"] == json!(control),
        "original continuation route lacks this actual reader lifecycle control"
    );
    continue_from_activation(&b, r)
}
pub fn continue_from_activation(activation: &Bound, r: &mut process::Runner<'_>) -> Result<()> {
    let ctx = storage::json(activation)?;
    ensure!(
        ctx["schema"] == "horizon-positive185-original-upstream-activation-v1"
            && ctx["no_retry_or_clock_reset"] == true,
        "original activation source"
    );
    let a: Assemble = serde_json::from_value(storage::json(&binding(&ctx["assembly"])?)?)?;
    let actor = text(&ctx, "actor")?;
    let control = PathBuf::from(text(&ctx, "control_root")?);
    r.deadline = Instant::now() + Duration::from_secs(30);
    let (ready_bound, ready, native) = wait_ready(&control, actor, r)?;
    let iid = text(&ready, "actor_invocation_id")?;
    let started = n(&ready, "started_at")?;
    let deadline = started + 600;
    ensure!(
        now()? < deadline
            && ready["admission_sha256"] == ctx["admission"]["sha256"]
            && ready["driver_sha256"] == DRIVER_SHA,
        "original600s ready bound"
    );
    r.deadline = Instant::now() + Duration::from_secs(deadline - now()?);
    r.pool_deadline = r.deadline;
    let registry = Path::new(REGISTRY).join(iid);
    if registry.try_exists()? {
        ensure!(
            env::args().nth(1).as_deref() == Some("continue-positive185-original"),
            "existing registry only for explicit original continuation"
        );
        private(&registry, true)?;
        let failure = binding(&ctx["original_failed_task_capture"])?;
        let original = storage::json(&failure)?;
        ensure!(
            original["exit_code"] == 1 && original["no_retry_or_clock_reset"] == true,
            "original failed task capture proof required"
        );
        let stderr: Vec<u8> = serde_json::from_value(original["stderr_bytes"].clone())?;
        ensure!(
            std::str::from_utf8(&stderr)?
                .contains("epoch 185 task status crossed the original Root admission"),
            "only exact original status alias failure may continue"
        );
    } else {
        make_private(&registry)?;
    }
    storage::save(
        r.root,
        "original-ready-native.json",
        &json!({"ready":ready_bound,"original_native":native,"original_setup_deadline":deadline,"no_retry_or_renewal":true}),
    )?;
    let units = storage::json(&binding(&ctx["unit_seal"]["normal_seal"])?)?;
    let dir = PathBuf::from(text(&units, "destination")?);
    let envelope = binding(&ctx["envelope"])?;
    let admission = binding(&ctx["admission"])?;
    let admitted = storage::json(&admission)?;
    let admitted_status = binding(&admitted["status_readback"])?;
    ensure!(
        storage::bytes(&admitted_status, 32 << 20, true)?
            == storage::bytes(&a.status_readback, 32 << 20, false)?,
        "original status alias bytes differ"
    );
    let task_spec = json!({"schema":"horizon-epoch185-native-startpre-task-capture-v1","native_spec":{"schema":"horizon-epoch185-native-startpre-spec-v1","actor_unit":actor,"expected_actor_invocation_id":iid,"envelope":envelope,"admission":admission,
  "actor_source":process::bind_file(&dir.join(actor),1<<20)?,"guard_source":process::bind_file(&dir.join(text(&ctx,"guard")?),1<<20)?,"timer_source":process::bind_file(&dir.join(text(&ctx,"timer")?),1<<20)?,"ready":ready_bound,"current_task_status":admitted_status,"mode":"task-start-pre"},"output":registry.join("task.json")});
    let tb = sealed_spec(r, "task-capture-status-bound-v12", iid, &task_spec)?;
    child(
        r,
        "capture-original-task",
        &fixed(NATIVE, NATIVE_SHA),
        "capture-cold185-startpre-task",
        &tb,
        20,
    )?;
    let task = process::bind_file(&registry.join("task.json"), 4 << 20)?;
    let t = storage::json(&task)?;
    ensure!(
        t["self_sha256"] == NATIVE_SHA
            && t["actor_invocation_id"] == iid
            && t["stage"] == "start-pre",
        "genuine distinct native task original"
    );
    let status = storage::json(&a.status_readback)?;
    let eta = n(&status["after_status"], "estimated_remaining_millis")?;
    let old = &ctx["prelaunch_current"];
    let previous = binding(&old["fleet"])?;
    let registration_spec = sealed_spec(
        r,
        "registration",
        iid,
        &json!({"schema":"horizon-epoch185-startpre-fleet-registration-spec-v1","task":task,"previous_fleet":previous,"numeric_delivery_eta_millis":eta,"output":registry.join("registration.json")}),
    )?;
    child(
        r,
        "enroll-original-task",
        &fixed(HELPER, HELPER_SHA),
        "enroll-cold185-startpre",
        &registration_spec,
        20,
    )?;
    let registration = process::bind_file(&registry.join("registration.json"), 4 << 20)?;
    let event = storage::json(&registration)?;
    let prior_plan = storage::json(&binding(&old["fleet_plan"])?)?;
    ensure!(
        prior_plan["epoch185_cold_startpre_registration"].is_null(),
        "new independent185 original enrollment"
    );
    let mut plan = prior_plan;
    plan["previous_fleet"] = json!(previous);
    plan["metadata_event"] = json!(registration);
    plan["epoch185_cold_startpre_registration"] = json!(registration);
    let fleet_output = Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1")
        .join(format!("fleet-positive185-original-{iid}.json"));
    ensure!(!fleet_output.try_exists()?, "new fleet output");
    plan["output"] = json!(fleet_output);
    for key in ["actor_unit", "guard_unit", "timer_unit"] {
        plan["tracked_units"]
            .as_array_mut()
            .context("tracked units")?
            .push(event[key].clone());
    }
    plan["diagnostics"].as_array_mut().context("diagnostic claims")?.push(json!({"epoch":185,"unit":event["actor_unit"],"invocation_id":event["actor_invocation_id"],"scratch_path":event["run_root"],"launch_receipt":registration}));
    plan["gates"]["185"]["next_action"] = json!(
        "Original guarded48GiB bounded185 replay qualification; preserve failed185 repair and all full-boundary/runtime/publication gates"
    );
    plan["gates"]["185"]["evidence"]
        .as_array_mut()
        .context("existing gate evidence")?
        .push(json!(registration));
    let plan_bound = sealed_spec(r, "enrolled-fleet", iid, &plan)?;
    let mut command = Command::new("/usr/bin/systemd-run");
    command.args([
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit",
        &format!("horizon-positive185-upstream-{}-fleet", r.iid),
    ]);
    for p in [
        "User=root",
        "Group=root",
        "Restart=no",
        "MemoryMax=2G",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=512",
        "RuntimeMaxSec=60",
        "NoNewPrivileges=yes",
        "PrivateNetwork=no",
        "EnvironmentFile=/etc/jetstreamer/horizon-r2.env",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
        "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
    ] {
        command.arg(format!("--property={p}"));
    }
    role(FLEET_HELPER, FLEET_HELPER_SHA)?;
    storage::bytes(&fixed(FLEET_HELPER, FLEET_HELPER_SHA), 128 << 20, true)?;
    command
        .arg(FLEET_HELPER)
        .arg("fleet-reconcile")
        .arg(&plan_bound.path)
        .args(["--plan-sha256", &plan_bound.sha256]);
    r.run("actual-enrolled-fleet", command, Duration::from_secs(65))?;
    let fleet_bound = process::bind_file(&fleet_output, 16 << 20)?;
    let fleet = storage::json(&fleet_bound)?;
    ensure!(
        fleet["observer_receipt"] == old["observer"]["path"]
            && fleet["observer_sha256"] == old["observer"]["sha256"]
            && fleet["previous_fleet"] == json!(previous),
        "genuine same-sample Root fleet completion"
    );
    let mut current = old.clone();
    current["fleet"] = json!(fleet_bound);
    current["fleet_plan"] = json!(plan_bound);
    let source = storage::json(&a.reader_source_spec)?;
    let mut spec = rebind(&source, old, &current);
    spec["output_directory"] = json!(format!(
        "/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/{}-cold185-{iid}",
        text(&old["observer"], "sha256")?
    ));
    let accepted_selector = storage::save(r.root, "enrolled-current-selector.json", &current)?;
    let accepted = storage::save(
        r.root,
        "enrolled-current-accepted-tuple.json",
        &json!({"observer":current["observer"],"fleet":current["fleet"],"frame":current["frame"],"accepted_selector":accepted_selector,"original_same_sample_registration":registration,"resource_observation_clock_unchanged":true}),
    )?;
    let original_booking = storage::json(&a.reader_external_booking)?;
    let mut booking = original_booking;
    booking["current"] = current.clone();
    booking["output_directory"] = spec["output_directory"].clone();
    booking["accounting_sources_serde_json_sha256"] = json!(storage::sha(&serde_json::to_vec(
        &spec["resource_accounting"]
    )?));
    booking["accepted_tuple"] = json!(accepted);
    let arithmetic = storage::json(&binding(&booking["resource_arithmetic"])?)?;
    ensure!(
        arithmetic["observer"] == old["observer"]
            && n(&arithmetic, "headroom_bytes")? > 0
            && arithmetic["one_external_serial_bytes"] == 6u64 << 30,
        "same-end current reader booking arithmetic"
    );
    booking["recorded_unix_seconds"] = json!(now()?);
    booking["expires_unix_seconds"] = json!(deadline);
    let bb = storage::save(r.root, "enrolled-reader-external-booking.json", &booking)?;
    spec["external_booking"] = json!(bb);
    let reader_spec = sealed_spec(r, "enrolled-reader", iid, &spec)?;
    ensure!(
        now()? + 240 < deadline,
        "original setup cannot fund100s reader and120s final transaction"
    );
    let unit = crate::persistent_reader::READER_UNIT;
    let reader_generation = format!("positive-{iid}");
    let execution = crate::persistent_reader::read(r, &reader_spec, &reader_generation)?;
    let reader_bound = binding(&execution["reader_proof"])?;
    let reader = storage::json(&reader_bound)?;
    ensure!(
        reader["image"] == json!(fixed(HELPER, HELPER_SHA))
            && reader["raw_history_preserved"] == true
            && reader["all_DATA_promises_preserved"] == true,
        "same helper actual original complete reader"
    );
    let riid = text(&reader, "invocation_id")?;
    let original_pid = text(&reader["native"], "MainPID")?.parse::<u64>()?;
    ensure!(
        original_pid > 1 && !Path::new(&format!("/proc/{original_pid}")).try_exists()?,
        "actual original full-reader PID absent"
    );
    let mut completion = execution["lifecycle"].clone();
    completion["actual_original_native_execution_record"] =
        execution["original_native_execution_record"].clone();
    completion["schema"] = json!("terminal199-parent-memory-original-reader-completion-v1");
    completion["reader_proof"] = json!(reader_bound);
    completion["program"] = reader["image"].clone();
    let journal = storage::save(
        r.root,
        "original-enrolled-reader-PID1.json",
        &json!({"unit":unit,"invocation_id":riid,"original_rows":[completion["original_PID1_success_event"].clone()]}),
    )?;
    completion["original_PID1_journal"] = json!(journal);
    let cb = storage::save(
        r.root,
        "original-enrolled-reader-completion.json",
        &completion,
    )?;
    let final_root = Path::new("/home/sol/.jetstreamer-private")
        .join(format!("epoch185-positive-final-control-{iid}"));
    make_private(&final_root)?;
    let actual_pool = verify_closed_pool(r, &binding(&ctx["normal_pool_closure"])?)?;
    let booking = storage::save(
        r.root,
        "final-normal-pool-booking.json",
        &json!({"schema":"horizon-positive185-finite-final-booking-v1","qualified_route":ctx["qualified_route"],"task":task,"original_reader_completion":cb,"normal_external_pool_bytes":6u64<<30,"root_control_memory_bytes":512u64<<20,"serial_child_memory_bytes":2u64<<30,"additional_QA_memory_bytes":0,"all_other_normal_pool_actors_drained":true,"actual_closed_QA_pool_revalidation":actual_pool,"all_own_prior_serial_children_completed_and_reaped_by_pidfd":true,"resource_credit_bytes":0,"expires_at":deadline}),
    )?;
    // Root admission coordinator must serially reserve this same pool across the
    // complete invocation; source has no authority to stop unrelated pool actors.
    let context = storage::save(
        r.root,
        "actual-postreader-context.json",
        &json!({"schema":"horizon-positive185-postreader-final-context-v1","qualified_route":ctx["qualified_route"],"task":task,"registration":registration,"actual_fleet":fleet_bound,"actual_fleet_plan":plan_bound,"original_reader":reader_bound,"original_reader_completion":cb,"normal_pool_booking":booking,"work_root":final_root}),
    )?;
    ensure!(
        now()? + 120 <= deadline,
        "original setup final120s allowance exhausted"
    );
    let mut c = Command::new(FINAL);
    c.arg("execute-positive185-final").arg(&context.path).args([
        "--context-sha256",
        &context.sha256,
        "--self-sha256",
        FINAL_SHA,
    ]);
    unsafe {
        c.pre_exec(|| {
            libc::umask(0o022);
            Ok(())
        });
    }
    let outcome = r.run("actual-c71-one-original-final", c, Duration::from_secs(120))?;
    storage::save(r.root, "original-c71-final-outer.json", &outcome)?;
    println!(
        "{}",
        json!({"original_final_control_root":final_root,"original_actor":actor,"original_actor_iid":iid,"no_epoch_completion_or_publication_claim":true})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rebinding_is_simultaneous_and_retains_original_hash_literals() {
        let b = |n: &str| json!({"path":format!("/fixture/{n}"),"sha256":n.repeat(64)});
        let old = json!({"observer":b("a"),"fleet":b("b"),"fleet_plan":b("c"),"frame":b("d")});
        let mut new = old.clone();
        new["fleet"] = old["fleet_plan"].clone();
        new["fleet_plan"] = b("e");
        let v = json!({"current":old,"history_hash":"b".repeat(64)});
        let changed = rebind(&v, &old, &new);
        assert_eq!(changed["current"], new);
        assert_eq!(changed["history_hash"], "b".repeat(64));
    }
}
