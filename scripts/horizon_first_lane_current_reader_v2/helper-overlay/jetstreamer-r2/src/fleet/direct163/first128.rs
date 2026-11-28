//! Child of fleet::direct163: new source-only bounded admission, not its192GiB
//! route. Reuses qualified raw builders and original selection/drain validators.
use super::*;
mod enrollment128;
mod native_capability;
mod current_phase;
mod candidate_memory128;
mod release128;
mod integration;
pub(in crate::fleet) use integration::{
    REGISTER128, comparison_census, guard_floor, launch_matches, native_namespace, normalize_peers,
    owned_owner, raw_profile, validate_transition,
};
mod qualified_profile;
use qualified_profile::{BOUNDED_GUARD_IMAGE, BOUNDED_GUARD_SHA, NODE_IMAGE, NODE_SHA};
pub(in crate::fleet) const PARENT128: &str = "horizon-epoch163-first-output128-20261106-v1.service";
pub(in crate::fleet) const GUARD128: &str =
    "horizon-guard-epoch163-first-output128-20261106-v1.service";
pub(in crate::fleet) const STOP128: &str =
    "horizon-stop-epoch163-first-output128-20261106-v1.service";
pub(in crate::fleet) const TIMER128: &str =
    "horizon-guard-epoch163-first-output128-20261106-v1.timer";
pub(in crate::fleet) const ADMIT128: &str =
    "horizon-admit-epoch163-first-output128-20261106-v1.service";
pub(in crate::fleet) const ENROLL128: &str =
    "horizon-enroll-epoch163-first-output128-20261106-v1.service";
pub(in crate::fleet) const RELEASE128: &str = "horizon-release-epoch163-first-output128-20261107-v1.service";
const HARD128: u64 = 128 << 30;
const AUX128: u64 = (2 << 30) + (512 << 20);
const EXPORT128: u64 = 642177138688;
const MARGIN128: u64 = 8 << 30;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedSpec {
    schema: String,
    input_policy: Bound,
    current_phase_ledger: Bound,
    input_metadata: Bound,
    isolated_active_config: Bound,
    isolated_configuration: Bound,
    native_finalizer_completion: Bound,
    memory_request: memory::model::Request,
    memory_receipt: Bound,
    memory_completion: Bound,
    data_receipt: Bound,
    data_completion: Bound,
    data_policy: Bound,
    data_policy_seal: Bound,
    resource_accounting: Value,
    source_qualification: Bound,
    output: PathBuf,
}
fn actor128(command: &str, actor_unit: &str) -> Result<(Bound, Bound)> {
    let args = std::env::args().collect::<Vec<_>>();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 7
            && args[1] == command
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256",
        "exact bounded admission CLI/root"
    );
    ensure!(
        !std::env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "bounded loader override"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: args[6].clone(),
    };
    let raw = storage::bytes(&image, 256 << 20, true)?;
    let mapped = fs::metadata("/proc/self/exe")?;
    let canonical = fs::metadata(&image.path)?;
    ensure!(
        raw.starts_with(b"\x7fELF")
            && fs::read("/proc/self/exe")? == raw
            && (mapped.dev(), mapped.ino()) == (canonical.dev(), canonical.ino())
            && image.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer")),
        "actual bounded helper image"
    );
    let n = unit(actor_unit)?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        n["Id"] == actor_unit
            && n["InvocationID"] == iid
            && n["MainPID"].as_str() == Some(std::process::id().to_string().as_str())
            && n["NRestarts"] == "0"
            && n["Restart"] == "no"
            && n["ControlPID"] == "0"
            && n["MemoryAccounting"] == "yes"
            && n["CPUQuotaPerSecUSec"] == "1s"
            && n["TasksMax"] == "512"
            && n["User"] == "root"
            && n["MemoryMax"] == "2147483648"
            && n["MemorySwapMax"] == "0"
            && n["ActiveState"] == "active"
            && n["SubState"] == "running"
            && n["Job"] == "",
        "bounded actual2GiB nonrestarting admission actor"
    );
    Ok((
        Bound {
            path: args[2].clone().into(),
            sha256: args[4].clone(),
        },
        image,
    ))
}
fn scope128(v: &Value) -> Result<()> {
    ensure!(
        v["schema"] == "epoch163-first-output128-input-policy-v1"
            && v["node"] == json!({"path":NODE_IMAGE,"sha256":NODE_SHA})
            && v["guard"] == json!({"path":BOUNDED_GUARD_IMAGE,"sha256":BOUNDED_GUARD_SHA})
            && v["maximum_runtime_seconds"] == 3600
            && v["maximum_replayed_slots"] == 259
            && v["maximum_output_bytes"] == 1u64 << 30
            && v["exporter_floor_bytes"] == EXPORT128
            && v.get("admission").is_none()
            && v.get("input_policy").is_none(),
        "bounded immutable pre-admission scope or digest cycle"
    );
    Ok(())
}
fn absent128() -> Result<()> {
    for name in [PARENT128, GUARD128, STOP128, TIMER128] {
        let n = unit(name)?;
        ensure!(
            !matches!(
                n["ActiveState"].as_str(),
                Some("active" | "activating" | "deactivating" | "reloading")
            ) && n["MainPID"].as_str().is_none_or(|s| s == "0")
                && n["ControlPID"].as_str().is_none_or(|s| s == "0")
                && n["Job"].as_str().is_none_or(|s| s.is_empty() || s == "0"),
            "bounded owner already live/queued"
        );
    }
    let root =
        Path::new("/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work");
    for rel in ["scratch", "output"] {
        let path = root.join(rel);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.is_dir()
                && m.uid() == 1001
                && m.mode() & 0o777 == 0o700
                && path.canonicalize()? == path
                && fs::read_dir(path)?.next().is_none(),
            "bounded private output/scratch occupied or foreign"
        );
    }
    Ok(())
}
fn fit128(
    view: &memory::VerifiedParentMemory,
    data: &data::VerifiedData,
    budget: &candidate_memory128::Budget,
    a: &Value,
    b: &Value,
    raw: &Value,
) -> Result<u64> {
    ensure!(
        view.selected_parent_retirement_bytes() == 192u64 << 30
            && view.selected_cached145_parent_retirement_bytes() == 192u64 << 30,
        "bounded profile requires both separate qualified parent views"
    );
    let current = &view.evidence()["request"]["current"];
    ensure!(
        data.evidence()["current"] == *current,
        "bounded DATA/current memory crossed"
    );
    let host = n(view.evidence(), "raw_total_memory_promises_bytes")?;
    // Host capacity is read from the bound original observer, not an invented total.
    let observer = storage::json(&to_bound(&current["observer"])?)?;
    let host_total = observer["host_memory"]["total_kib"]
        .as_u64()
        .context("bound host total")?
        .checked_mul(1024)
        .context("host overflow")?;
    ensure!(host >= view.effective_total_bytes(), "bounded original typed baseline exceeds its raw total");
    // Capacity must include the separately proven retained native128 charge.
    budget.host_fit(host_total)?;
    let disk = budget.required_free_bytes();
    let needed = EXPORT128
        .checked_add(HARD128)
        .and_then(|x| x.checked_add(AUX128))
        .and_then(|x| x.checked_add(MARGIN128))
        .context("bounded memory overflow")?;
    for p in [a, b] {
        ensure!(
            n(p, "available_memory_bytes")? >= needed
                && n(p, "free_bytes")? >= disk
                && n(p, "free_inodes")? >= 131072
                && n(p, "vm_max_map_count")? >= 4194304,
            "bounded physical hard growth/exporter floor/DATA/inode/VMA admission"
        );
    }
    let cpu = n(raw, "current_replay_cpu_quota_micros")?
        .checked_add(8_000_000 + 3_000_000)
        .context("bounded CPU overflow")?;
    ensure!(
        n(a, "available_logical_cpus")? == n(b, "available_logical_cpus")?
            && cpu
                <= n(b, "available_logical_cpus")?
                    .checked_mul(1_000_000)
                    .context("CPU overflow")?,
        "bounded CPU affinity/quotas"
    );
    let owners = raw["current_unique_owner_census"]
        .as_array()
        .context("bounded complete owners")?;
    ensure!(
        owners
            .iter()
            .filter(|o| matches!(
                o["role"].as_str(),
                Some("replay-producer" | "diagnostic-replay")
            ))
            .count()
            < 2
            && !owners
                .iter()
                .any(|o| o["first_epoch"].as_u64().is_some_and(|e| e <= 163)
                    && o["last_epoch"].as_u64().is_some_and(|e| e >= 163)),
        "bounded operating point or overlapping source-owned claim"
    );
    Ok(disk)
}
pub(in crate::fleet) async fn run() -> Result<()> {
    let (sb, image) = actor128("admit-first163128", ADMIT128)?;
    let s: BoundedSpec = serde_json::from_value(immutable(&sb)?)?;
    ensure!(
        s.schema == "epoch163-first-output128-full-admission-spec-v1"
            && s.output
                == Path::new(
                    "/var/lib/jetstreamer/horizon-epoch163-first-output128-admission-20261106-v1/admission.json"
                ),
        "bounded exact spec/output"
    );
    let phase = current_phase::validate(&s.current_phase_ledger)?;
    let metadata = protected(&s.input_metadata)?;
    ensure!(s.input_metadata.path == Path::new(current_metadata::CURRENT_PATH), "first128 current post-custody metadata required");
    current_metadata::validate_selected(&s.input_metadata, &s.isolated_active_config, &s.isolated_configuration, &metadata)?;
    let policy = immutable(&s.input_policy)?;
    scope128(&policy)?;
    ensure!(
        policy["admission_program"] == json!(image),
        "bounded cohesive admission/enrollment issuer"
    );
    artifact(NODE_IMAGE, NODE_SHA)?;
    artifact(BOUNDED_GUARD_IMAGE, BOUNDED_GUARD_SHA)?;
    let qualified = immutable(&s.source_qualification)?;
    let inputs = immutable(&to_bound(&policy["input_acceptance"])?)?;
    let native_retained = native_capability::validate(&to_bound(&policy["input_acceptance"])?, &inputs, &s.native_finalizer_completion)?;
    let target = immutable(&to_bound(&policy["first_slot_source"])?)?;
    ensure!(
        inputs["schema"] == "epoch163-first-output128-input-capability-v1"
            && inputs["bootstrap_generation"] == 1634787272998262u64
            && inputs["bootstrap_slot"] == 70415741
            && inputs["snapshot_integrity_verified"] == true
            && inputs["mapped_worker_sha256"]
                == "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819"
            && inputs["original_capability_actor_drained"] == true
            && target["schema"] == "jetstreamer-successor-boundary-source-probe-v1"
            && target["epoch"] == 163
            && target["requested_slot"] == 70416000
            && target["first_block_slot"] == 70416000
            && target["parent_slot"]
                .as_u64()
                .is_some_and(|p| (70415741..70416000).contains(&p))
            && target["production_boundary_reader"] == true
            && target["replay_launch_authorized"] == false
            && target["publication_authorized"] == false,
        "bounded actual snapshot integrity/native worker and present first-slot proof missing"
    );
    ensure!(
        qualified["schema"] == "epoch163-first-output128-actual-source-capabilities-v1"
            && qualified["node"] == policy["node"]
            && qualified["guard"] == policy["guard"]
            && qualified["input_acceptance"] == policy["input_acceptance"]
            && qualified["first_slot_source"] == policy["first_slot_source"]
            && qualified["exclusive_node_profile_QA_passed"] == true
            && qualified["bounded_guard_QA_passed"] == true
            && qualified["actual_native_capability_passed"] == true
            && qualified["original_capability_actors_drained"] == true
            && qualified["ordinary_qualification_gates_preserved"] == true
            && qualified["publication_authorized"] == false,
        "actual bounded source/native qualification missing"
    );
    let m = immutable(&s.memory_receipt)?;
    let d = immutable(&s.data_receipt)?;
    original_selection(
        &m,
        &immutable(&s.memory_completion)?,
        &s.memory_receipt,
        "memory",
    )?;
    original_selection(&d, &immutable(&s.data_completion)?, &s.data_receipt, "DATA")?;
    ensure!(
        m["selection"]["request"] == json!(s.memory_request)
            && d["memory_selection"] == json!(s.memory_receipt)
            && policy["memory"] == json!(s.memory_receipt)
            && policy["memory_completion"] == json!(s.memory_completion)
            && policy["data"] == json!(s.data_receipt)
            && policy["data_completion"] == json!(s.data_completion),
        "bounded selected original memory/DATA crossing"
    );
    absent128()?;
    let start = now()?;
    let view = memory::admission_bridge::from_current_reader(&s.memory_request, start)?;
    let selected = data::select(&view, &s.data_policy, &s.data_policy_seal, start)?;
    ensure!(
        selected.evidence()["current"] == m["selection"]["request"]["current"]
            && selected.evidence()["projection"] == d["data_selection"]["projection"],
        "bounded DATA selection differs from genuine original selector"
    );
    let current = &view.evidence()["request"]["current"];
    ensure!(
        s.resource_accounting["observer"] == current["observer"]
            && s.resource_accounting["fleet"] == current["fleet"]
            && s.resource_accounting["fleet_plan"] == current["fleet_plan"]
            && s.resource_accounting["phase_events"][1]["source"] == current["frame"],
        "bounded complete raw source tuple crossing"
    );
    pressures(&storage::json(&to_bound(&current["observer"])?)?)?;
    let before = epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    let p0 = physical()?;
    let after = epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    let p1 = physical()?;
    epoch186::accounting::stable_guard_basis(&s.resource_accounting, &before, &after)?;
    unchanged_claims(&before, &after)?;
    let original = immutable(&s.memory_request.current_reader)?;
    let original_raw = immutable(&to_bound(&original["accounting"])?)?;
    unchanged_claims(&original_raw, &after)?;
    let budget = candidate_memory128::compose(&view, &selected, &phase, &native_retained,
        &before, &after, candidate_memory128::Stage::Admission)?;
    let observer = storage::json(&to_bound(&current["observer"])?)?;
    let host_total = observer["host_memory"]["total_kib"]
        .as_u64()
        .context("bounded host total")?
        .checked_mul(1024)
        .context("host bytes overflow")?;
    // Keep the original physically adjacent PSI and full filesystem checks.
    fits(
        budget.evidence(),
        budget.existing_data_bytes(),
        host_total,
        &p0,
        &p1,
    )?;
    let disk = fit128(&view, &selected, &budget, &p0, &p1, &after)?;
    for physical in [&p0,&p1] { ensure!(n(physical,"free_bytes")? >= disk,"first128 current whole DATA/guard floor"); }
    absent128()?;
    artifact(NODE_IMAGE, NODE_SHA)?;
    artifact(BOUNDED_GUARD_IMAGE, BOUNDED_GUARD_SHA)?;
    let end = now()?;
    ensure!(
        end.checked_sub(start).is_some_and(|v| v <= 300),
        "bounded admission transaction expired"
    );
    let end_view = memory::admission_bridge::from_current_reader(&s.memory_request, end)?;
    let end_data = data::select(&end_view, &s.data_policy, &s.data_policy_seal, end)?;
    ensure!(
        end_view.effective_total_bytes() == view.effective_total_bytes()
            && end_data.evidence()["projection"] == selected.evidence()["projection"],
        "bounded final typed custody changed"
    );
    ensure!(current_phase::validate(&s.current_phase_ledger)? == phase,"first128 current phase changed");
    let end_native = native_capability::validate(&to_bound(&policy["input_acceptance"])?, &inputs, &s.native_finalizer_completion)?;
    ensure!(end_native.evidence() == native_retained.evidence(), "retained native identity changed before first128 admission");
    let end_budget = candidate_memory128::compose(&end_view, &end_data, &phase, &end_native,
        &before, &after, candidate_memory128::Stage::Admission)?;
    ensure!(end_budget.evidence() == budget.evidence(), "composed native memory/DATA changed before admission");
    end_budget.host_fit(host_total)?;
    save(
        &s.output,
        &json!({"schema":"epoch163-first-output128-full-admission-v1","spec":sb,"self":image,
        "input_policy":s.input_policy,"admitted":true,"parent_unit":PARENT128,"parent_program":policy["node"],
        "parent_hard_bytes":HARD128,"guard_bytes":2u64<<30,"fallback_bytes":512u64<<20,"exporter_floor_bytes":EXPORT128,
        "complete_current_owner_accounting":true,"input_capability":policy["input_acceptance"],
        "memory_receipt":s.memory_receipt,"data_receipt":s.data_receipt,"original_inputs_and_resource_actors_drained":true,
        "minimum_free_bytes":disk-(768u64<<30),"required_initial_free_bytes":disk,"candidate_DATA_bytes":768u64<<30,
        "current_phase_ledger":s.current_phase_ledger,"current_input_metadata":s.input_metadata,"native_finalizer_completion":s.native_finalizer_completion,"candidate_memory":budget.evidence(),"raw_before":before,"raw_after":after,"physical_before":p0,"physical_after":p1,"memory":view.evidence(),"DATA":selected.evidence(),
        "recorded_unix_seconds":end,"expires_unix_seconds":end+180,"maximum_runtime_seconds":3600,"maximum_replayed_slots":259,
        "attended_held_launch_only":true,"enrollment_and_actual_first_guard_before_release_required":true,
        "publication_authorized":false,"r2_mutations":false,"physical_credit_bytes":0}),
    )?;
    let original_admission = Bound {
        path: s.output.clone(),
        sha256: storage::sha(&fs::read(&s.output)?),
    };
    let original = immutable(&original_admission)?;
    let m_done = immutable(&s.memory_completion)?;
    let d_done = immutable(&s.data_completion)?;
    capsule(
        "admission-capsule.json",
        &json!({"schema":"epoch163-first-output128-admission-capsule-v1","issuer":image,
        "original_admission":original_admission,"input_policy":s.input_policy,"admitted":true,"parent_unit":PARENT128,"parent_program":policy["node"],
        "parent_hard_bytes":HARD128,"guard_bytes":2u64<<30,"fallback_bytes":512u64<<20,"exporter_floor_bytes":EXPORT128,
        "complete_current_owner_accounting":true,"input_capability":policy["input_acceptance"],"first_slot_source":policy["first_slot_source"],
        "memory_receipt":s.memory_receipt,"data_receipt":s.data_receipt,"original_inputs_and_resource_actors_drained":true,
        "recorded_unix_seconds":original["recorded_unix_seconds"],"expires_unix_seconds":original["expires_unix_seconds"],
        "memory_summary":{"schema":m["schema"],"invocation_id":m["invocation_id"],"capability_only":false,
            "selection":{"original199_parent_retirement_bytes":192u64<<30,"completed_cached145_parent_retirement_bytes":192u64<<30}},
        "DATA_summary":{"schema":d["schema"],"invocation_id":d["invocation_id"],"memory_selection":s.memory_receipt,"program":d["program"]},
        "memory_completion_summary":completion_summary(&m_done),"DATA_completion_summary":completion_summary(&d_done),
        "input_capability_summary":{"schema":inputs["schema"],"bootstrap_generation":inputs["bootstrap_generation"],"bootstrap_slot":inputs["bootstrap_slot"],
            "snapshot_integrity_verified":true,"mapped_worker_sha256":inputs["mapped_worker_sha256"],"original_capability_actor_drained":true},
        "first_slot_source_summary":target,"publication_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}
pub(in crate::fleet) fn enroll() -> Result<()> {
    enrollment128::run()
}
pub(in crate::fleet) fn allocation(plan: &Value) -> Result<Vec<Value>> {
    enrollment128::allocation(plan)
}

/// Only compact derived operational statements are made readable to the
/// unprivileged producer. Full original receipts and ancestors remain root0700.
fn capsule(name: &str, value: &Value) -> Result<Bound> {
    use std::os::fd::{AsRawFd, FromRawFd};
    ensure!(
        matches!(name, "admission-capsule.json" | "enrollment-capsule.json" | "first-guard-capsule.json")
            || name
                .strip_prefix("release-")
                .and_then(|s| s.strip_suffix(".json"))
                .is_some_and(|s| storage::hex(s, 32)),
        "bounded capsule leaf namespace"
    );
    let root =
        Path::new("/home/sol/.jetstreamer-private/epoch163-first-output128-20261106-v1/work");
    ensure!(
        root.canonicalize()? == root,
        "bounded work canonical identity"
    );
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root)?;
    let before = directory.metadata()?;
    ensure!(
        before.is_dir() && before.uid() == 1001 && before.mode() & 0o777 == 0o700,
        "bounded owner-only capsule parent"
    );
    let leaf = std::ffi::CString::new(name)?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    ensure!(
        fd >= 0,
        "bounded capsule create-new failed: {}",
        std::io::Error::last_os_error()
    );
    let mut file = unsafe { fs::File::from_raw_fd(fd) };
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 2 << 20, "bounded compact statement bound");
    std::io::Write::write_all(&mut file, &bytes)?;
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o444))?;
    file.sync_all()?;
    directory.sync_all()?;
    let after = fs::symlink_metadata(root)?;
    ensure!(
        (before.dev(), before.ino()) == (after.dev(), after.ino()),
        "bounded capsule parent replaced"
    );
    Ok(Bound {
        path: root.join(name),
        sha256: storage::sha(&bytes),
    })
}
fn completion_summary(v: &Value) -> Value {
    json!({"schema":v["schema"],"receipt":v["receipt"],"invocation_id":v["invocation_id"],
    "result":v["result"],"exec_main_status":v["exec_main_status"],"original_outer_reaped":v["original_outer_reaped"],
    "original_cgroup_empty":v["original_cgroup_empty"],"original_descriptors_drained":v["original_descriptors_drained"]})
}

pub(in crate::fleet) fn completion_namespace(name: &str) -> bool {
    [native_capability::FINALIZER, super::native_restore::ACTOR].contains(&name)
}

pub(in crate::fleet) async fn release() -> Result<()> { release128::run().await }

/// Producer8CPU is already in the live owner census; retain it after termination.
pub(in crate::fleet) fn retained_cpu(rows: &[Value]) -> u64 {
    rows.iter().find(|row| row["unit"] == PARENT128).map_or(0, |row| {
        if row["state"] == "terminal-retained-private-first-output128" { 10_000_000 } else { 2_000_000 }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> Value {
        json!({"schema":"epoch163-first-output128-input-policy-v1","node":{"path":NODE_IMAGE,"sha256":NODE_SHA},
        "guard":{"path":BOUNDED_GUARD_IMAGE,"sha256":BOUNDED_GUARD_SHA},"maximum_runtime_seconds":3600,"maximum_replayed_slots":259,
        "maximum_output_bytes":1u64<<30,"exporter_floor_bytes":EXPORT128})
    }
    #[test]
    fn exact_scope_is_bounded_and_has_no_admission_digest_dependency() {
        let p = policy();
        scope128(&p).unwrap();
        for key in ["admission", "input_policy"] {
            let mut x = p.clone();
            x[key] = json!({"path":"/cyclic","sha256":"a".repeat(64)});
            assert!(scope128(&x).is_err());
        }
    }
    #[test]
    fn different_node_duration_work_or_exporter_floor_is_not_this_profile() {
        let p = policy();
        for key in [
            "maximum_runtime_seconds",
            "maximum_replayed_slots",
            "maximum_output_bytes",
            "exporter_floor_bytes",
        ] {
            let mut x = p.clone();
            x[key] = json!(0);
            assert!(scope128(&x).is_err());
        }
        let mut x = p;
        x["node"]["sha256"] = json!("0".repeat(64));
        assert!(scope128(&x).is_err());
    }
}
