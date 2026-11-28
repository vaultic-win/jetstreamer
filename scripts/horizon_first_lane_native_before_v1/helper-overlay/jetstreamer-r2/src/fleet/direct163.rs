//! Exact direct epoch 163 admission and enrollment. No start/stop or remote writes.
use super::*;
use horizon_original199_parent_memory as memory;
use horizon_terminal183_ended_data as data;
use memory::model::Bound;
use std::os::unix::fs::OpenOptionsExt;
pub(in crate::fleet) mod native_restore;
pub(in crate::fleet) mod first128;
mod candidate_memory;
mod completed145_guard_bindings;
use completed145_guard_bindings::{GUARD_IMAGE, GUARD_SHA};
mod current_metadata;
mod enrollment;
#[cfg(test)]
mod tests;
pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e163-singleton-20261104-v1-e163-163-lane-a-1.service";
pub(super) const GUARD: &str =
    "jetstreamer-adaptive-reserve-epoch163-singleton-20261104-v1.service";
pub(super) const STOP: &str = "jetstreamer-epoch163-parent-memory-failure-stop-20261104-v1.service";
pub(super) const TIMER: &str = "jetstreamer-adaptive-reserve-epoch163-singleton-20261104-v1.timer";
pub(super) const ADMIT: &str = "horizon-direct163-admission-20261105-v1.service";
pub(super) const ENROLL: &str = "horizon-direct163-enrollment-20261105-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch163-direct-parent-20261104-v1";
const PACKAGE: &str = "/usr/local/lib/jetstreamer/deploy-epoch163-singleton-20261104-v1";
const NODE_SHA: &str = "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887";
const DATA_BYTES: u64 = 768 << 30;
const REGISTER: &str =
    "/var/lib/jetstreamer/horizon-direct163-enrollment-20261105-v1/enrollment.json";
mod storage {
    use super::*;
    pub(super) fn json(b: &Bound) -> Result<Value> {
        input136::protected_json(&BoundFile {
            path: b.path.clone(),
            sha256: b.sha256.clone(),
        })
    }
    pub(super) fn n(v: &Value, k: &str) -> Result<u64> {
        v[k].as_u64()
            .with_context(|| format!("direct163 integer {k}"))
    }
    pub(super) fn hex(s: &str, n: usize) -> bool {
        is_lower_hex(s, n)
    }
    pub(super) fn sha(v: &[u8]) -> String {
        hex_lower(&Sha256::digest(v))
    }
    pub(super) fn bytes(b: &Bound, cap: u64, immutable: bool) -> Result<Vec<u8>> {
        let m = fs::symlink_metadata(&b.path)?;
        ensure!(
            m.is_file()
                && m.uid() == 0
                && m.nlink() == 1
                && m.mode() & 0o022 == 0
                && (!immutable || m.mode() & 0o222 == 0)
                && m.len() <= cap
                && b.path.canonicalize()? == b.path,
            "direct163 immutable source custody: {}", b.path.display()
        );
        let raw = read_stable_bounded(&b.path, cap, "direct163 bound source")?;
        ensure!(sha(&raw) == b.sha256, "direct163 source digest changed");
        Ok(raw)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    memory_request: memory::model::Request,
    memory_receipt: Bound,
    memory_completion: Bound,
    data_receipt: Bound,
    data_completion: Bound,
    data_policy: Bound,
    data_policy_seal: Bound,
    resource_accounting: Value,
    package_acceptance: Bound,
    input_metadata: Bound,
    isolated_configuration: Bound,
    isolated_active_config: Bound,
    parent_service: Bound,
    output: PathBuf,
}
fn n(v: &Value, k: &str) -> Result<u64> {
    storage::n(v, k)
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn to_bound(v: &Value) -> Result<Bound> {
    Ok(serde_json::from_value(v.clone())?)
}
fn immutable(b: &Bound) -> Result<Value> {
    storage::bytes(b, 32 << 20, true)?;
    storage::json(b)
}
fn protected(b: &Bound) -> Result<Value> {
    storage::bytes(b, 32 << 20, false)?;
    storage::json(b)
}
fn artifact(path: &str, sha: &str) -> Result<()> {
    storage::bytes(
        &Bound {
            path: path.into(),
            sha256: sha.into(),
        },
        256 << 20,
        true,
    )?;
    Ok(())
}
fn save(path: &Path, value: &Value) -> Result<()> {
    ensure!(
        path.parent()
            .is_some_and(|p| p.parent() == Some(Path::new("/var/lib/jetstreamer")))
            && path
                .file_name()
                .is_some_and(|n| n == "admission.json" || n == "enrollment.json"),
        "direct163 output namespace"
    );
    let parent = path.parent().context("direct163 output parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        pm.is_dir() && pm.uid() == 0 && pm.mode() & 0o777 == 0o700,
        "direct163 output parent custody"
    );
    let mut raw = serde_json::to_vec_pretty(value)?;
    raw.push(b'\n');
    ensure!(raw.len() <= 32 << 20, "direct163 receipt bound");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn parsed(command: &str) -> Result<(Bound, String)> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7
            && a[1] == command
            && a[3] == "--spec-sha256"
            && a[5] == "--self-sha256"
            && is_lower_hex(&a[4], 64)
            && is_lower_hex(&a[6], 64),
        "direct163 exact arguments"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0
            && !env::vars_os()
                .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "direct163 root actor/loader policy"
    );
    let expected_unit = if command == "admit-direct163" {
        ADMIT
    } else {
        ENROLL
    };
    ensure!(
        fs::read_to_string("/proc/self/cgroup")?.trim()
            == format!("0::/system.slice/{expected_unit}"),
        "direct163 actor cgroup"
    );
    let out=ProcessCommand::new("/usr/bin/systemctl").args(["show",expected_unit,"--no-pager","--property=Id,InvocationID,MainPID,ControlPID,NRestarts,Restart,Type,User,MemoryAccounting,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,NoNewPrivileges,ActiveState,SubState"]).output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 65536,
        "direct163 actor native query"
    );
    let mut actor = json!({});
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, v) = line
            .split_once('=')
            .context("direct163 actor native framing")?;
        actor[k] = json!(v);
    }
    let expected_pid = std::process::id().to_string();
    ensure!(
        actor["Id"] == expected_unit
            && actor["InvocationID"] == env::var("INVOCATION_ID")?
            && actor["MainPID"].as_str() == Some(expected_pid.as_str())
            && actor["ControlPID"] == "0"
            && actor["NRestarts"] == "0"
            && actor["Restart"] == "no"
            && actor["Type"] == "exec"
            && actor["User"] == "root"
            && actor["MemoryAccounting"] == "yes"
            && actor["MemoryMax"] == "2147483648"
            && actor["MemorySwapMax"] == "0"
            && actor["CPUQuotaPerSecUSec"] == "1s"
            && actor["NoNewPrivileges"] == "yes"
            && actor["ActiveState"] == "active"
            && actor["SubState"] == "running",
        "direct163 actor identity/cap"
    );
    let path = fs::read_link("/proc/self/exe")?;
    artifact(path.to_str().context("direct163 image path")?, &a[6])?;
    Ok((
        Bound {
            path: a[2].clone().into(),
            sha256: a[4].clone(),
        },
        a[6].clone(),
    ))
}
fn original_selection(receipt: &Value, completion: &Value, b: &Bound, kind: &str) -> Result<()> {
    ensure!(
        completion["receipt"] == json!(b)
            && completion["invocation_id"] == receipt["invocation_id"]
            && completion["result"] == "success"
            && completion["exec_main_status"] == 0
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true,
        "direct163 selection lacks original completed invocation/drain"
    );
    ensure!(
        (kind == "memory"
            && receipt["schema"] == "terminal199-parent-memory-selector-original-execution-v1"
            && receipt["capability_only"] == false
            && completion["schema"] == "epoch163-parent-memory-selector-original-completion-v1")
            || (kind == "DATA"
                && receipt["schema"]
                    == "epoch183-native-ended-DATA-selector-original-execution-v1"
                && completion["schema"]
                    == "epoch163-ended183-DATA-selector-original-completion-v1"
                && receipt["admission_authorized"] == false),
        "direct163 selector schema or scope"
    );
    Ok(())
}
fn package_inputs(s: &Spec) -> Result<()> {
    ensure!(
        s.package_acceptance.path
            == Path::new(
                "/home/sol/.jetstreamer-private/epoch163-shortest-second-lane-admission-source-20261104-v1/ROOT_163_PACKAGE_AND_BOTH_NEGATIVE_CAPABILITIES_ACCEPTED.json"
            )
            && current_metadata::input_path_allowed(&s.input_metadata.path),
        "direct163 capability/input scope"
    );
    let accepted = protected(&s.package_acceptance)?;
    ensure!(
        accepted["negative_errors_matched"] == true
            && accepted["no_replay_archive_or_sidecar_created"] == true
            && accepted["all_original_native_and_cgroups_drained"] == true,
        "direct163 package capability evidence"
    );
    let seal = immutable(&to_bound(&accepted["normal_deployment_seal"])?)?;
    ensure!(
        seal["destination"] == PACKAGE,
        "direct163 package seal namespace"
    );
    for (member, sha) in [
        ("jetstreamer-node", NODE_SHA),
        (
            "jetstreamer-historical-worker-v1-5-6",
            "cf5fa883df75b23de82af52dc0e90c013f8e83397b445027e510a1137decc819",
        ),
        (
            "genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
        ),
        (
            "preflight-163-singleton-v4.json",
            "69564972d4c83ed2129d0bca1e9cbf6e9f57cef5c7a924d83c91c5c7a32ed45f",
        ),
    ] {
        ensure!(
            seal["members"]
                .as_array()
                .context("direct163 package members")?
                .iter()
                .filter(|m| m["name"] == member && m["sha256"] == sha)
                .count()
                == 1,
            "direct163 package member binding"
        );
        artifact(&format!("{PACKAGE}/{member}"), sha)?;
    }
    let inputs = protected(&s.input_metadata)?;
    current_metadata::validate_if_current(s, &inputs)?;
    ensure!(
        inputs["bootstrap_generation"] == 1634787272998262u64
            && inputs["terminal_generation"] == 1634787310547338u64
            && inputs["read_only_remote_metadata"] == true
            && inputs["no_replay_or_full_admission_authority"] == true
            && inputs["config"] == format!("{ROOT}/gcloud"),
        "direct163 isolated generations"
    );
    isolated_config(s, &inputs)?;
    for result in inputs["actual_executions"]
        .as_array()
        .context("direct163 input executions")?
    {
        protected(&to_bound(result)?)?;
    }
    let service = storage::bytes(&s.parent_service, 1 << 20, true)?;
    ensure!(s.parent_service.path==Path::new("/usr/local/lib/jetstreamer/horizon-epoch163-direct-parent-service-sources-20261105-v1").join(UNIT)
        && storage::sha(&service)=="0fd4c395a078015c836ea2cf8940640d8dad0e92ba20938f4da74ffe5f41495d", "direct163 parent service source");
    artifact(GUARD_IMAGE, GUARD_SHA)
}
fn absent() -> Result<()> {
    for name in [UNIT, GUARD, STOP, TIMER] {
        let row = unit(name)?;
        ensure!(
            !matches!(
                row["ActiveState"].as_str(),
                Some("active" | "activating" | "deactivating" | "reloading")
            ) && row["MainPID"].as_str().is_none_or(|v| v == "0")
                && row["ControlPID"].as_str().is_none_or(|v| v == "0")
                && row["Job"].as_str().is_none_or(|v| v.is_empty() || v == "0"),
            "direct163 existing native claim"
        );
    }
    for rel in ["archives", "private"] {
        let path = Path::new(ROOT).join(rel);
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.is_dir()
                && m.uid() == 1001
                && m.mode() & 0o077 == 0
                && path.canonicalize()? == path
                && fs::read_dir(path)?.next().is_none(),
            "direct163 execution tree occupied or foreign"
        );
    }
    Ok(())
}
fn unchanged_claims(a: &Value, b: &Value) -> Result<()> {
    for key in [
        "current_unique_owner_census",
        "current_owner_hard_limits",
        "active_peer_allocations",
        "projected_obligations",
        "current_replay_cpu_quota_micros",
        "protected_existing_DATA_bytes",
        "standing_frontier_bytes",
        "confirmed_DATA_floor_bytes",
        "active_trial_memory_promises_bytes",
    ] {
        ensure!(
            a.get(key).is_some() && a[key] == b[key],
            "direct163 current resource claim changed: {key}"
        );
    }
    Ok(())
}
fn pressures(o: &Value) -> Result<()> {
    let p = &o["host_global_pressure"]["cross_sample"];
    ensure!(
        p["status"] == "observed" && n(p, "elapsed_millis")? > 0,
        "direct163 pressure observation missing"
    );
    for (k, m) in [
        ("memory.full_total_usec", 100u64),
        ("cpu.some_total_usec", 500),
        ("io.full_total_usec", 100),
    ] {
        ensure!(
            p["counter_delta_usec"][k]
                .as_u64()
                .is_some_and(|v| v <= n(p, "elapsed_millis").unwrap_or(0).saturating_mul(m)),
            "direct163 pressure {k}"
        );
    }
    Ok(())
}
fn physical() -> Result<Value> {
    let o = ProcessCommand::new("/usr/bin/stat")
        .args(["-f", "--format=%a %S %d", "/home/sol"])
        .output()?;
    ensure!(o.status.success(), "direct163 filesystem observation");
    let v = std::str::from_utf8(&o.stdout)?
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(v.len() == 3, "direct163 filesystem fields");
    let memory = fs::read_to_string("/proc/meminfo")?;
    let available = memory
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))
        .context("direct163 MemAvailable")?
        .split_whitespace()
        .next()
        .context("direct163 available memory")?
        .parse::<u64>()?
        .checked_mul(1024)
        .context("direct163 physical overflow")?;
    let mut affinity = unsafe { std::mem::zeroed::<libc::cpu_set_t>() };
    ensure!(
        unsafe {
            libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut affinity)
        } == 0,
        "direct163 current CPU affinity unavailable"
    );
    let logical_cpus = u64::try_from(unsafe { libc::CPU_COUNT(&affinity) })
        .context("direct163 CPU affinity count is negative")?;
    ensure!(logical_cpus > 0, "direct163 empty CPU affinity");
    let maps = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    let mut pressure = json!({});
    for (resource, kind) in [("cpu", "some"), ("memory", "full"), ("io", "full")] {
        let raw = fs::read_to_string(format!("/proc/pressure/{resource}"))?;
        let line = raw
            .lines()
            .find(|line| line.starts_with(&format!("{kind} ")))
            .context("direct163 PSI dimension")?;
        let total = line
            .split_whitespace()
            .find_map(|v| v.strip_prefix("total="))
            .context("direct163 PSI total")?
            .parse::<u64>()?;
        pressure[resource] = json!(total);
    }
    Ok(
        json!({"free_bytes":v[0].checked_mul(v[1]).context("direct163 free overflow")?,"free_inodes":v[2],"available_memory_bytes":available,"vm_max_map_count":maps,"available_logical_cpus":logical_cpus,
        "sampled_unix_micros":u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros()).context("direct163 physical clock overflow")?,"pressure_total_usec":pressure}),
    )
}
fn fits(budget: &Value, protected: u64, host: u64, a: &Value, b: &Value) -> Result<u64> {
    let elapsed = n(b, "sampled_unix_micros")?
        .checked_sub(n(a, "sampled_unix_micros")?)
        .context("direct163 pressure clock regressed")?;
    ensure!(
        (1_000..=900_000_000).contains(&elapsed),
        "direct163 pressure window outside finite transaction"
    );
    for (resource, fraction) in [("cpu", 500u64), ("memory", 100), ("io", 100)] {
        let delta = b["pressure_total_usec"][resource]
            .as_u64()
            .and_then(|v| v.checked_sub(a["pressure_total_usec"][resource].as_u64()?))
            .context("direct163 PSI counter regressed")?;
        ensure!(
            u128::from(delta) * 1000 <= u128::from(elapsed) * u128::from(fraction),
            "direct163 current pressure: {resource}"
        );
    }
    let required = protected
        .checked_add(DATA_BYTES)
        .context("direct163 DATA overflow")?;
    let need = n(budget, "candidate_scheduling_total_bytes")?
        .checked_add(host / 10)
        .context("direct163 reserve overflow")?;
    for physical in [a, b] {
        ensure!(
            n(physical, "free_bytes")? >= required
                && n(physical, "available_memory_bytes")? >= need
                && n(physical, "free_inodes")? >= 131072
                && n(physical, "vm_max_map_count")? >= 4194304,
            "direct163 physical memory/DATA/inode/VMA gate"
        );
    }
    Ok(required)
}
fn capacity(budget: &Value, accounting: &Value, host: u64, a: &Value, b: &Value) -> Result<()> {
    // The 1.5 times RSS reservation is a scheduling allowance. The 90 percent
    // utilization target applies to measured resident usage, not this promise.
    ensure!(
        n(budget, "total_scheduling_reserved_bytes")? <= host,
        "direct163 total scheduling promises exceed physical host memory"
    );
    let before_cpus = n(a, "available_logical_cpus")?;
    ensure!(
        before_cpus > 0 && before_cpus == n(b, "available_logical_cpus")?,
        "direct163 CPU affinity changed"
    );
    // Reserve the exact admission actor, guard and fallback CPU caps once.
    let required = n(accounting, "current_replay_cpu_quota_micros")?
        .checked_add(8_000_000)
        .and_then(|v| v.checked_add(3_000_000))
        .context("direct163 CPU promise overflow")?;
    ensure!(
        required
            <= before_cpus
                .checked_mul(1_000_000)
                .context("direct163 CPU affinity overflow")?,
        "direct163 replay and auxiliary CPU promises exceed affinity"
    );
    let owners = accounting["current_unique_owner_census"]
        .as_array()
        .context("direct163 complete owner census")?;
    let replays = owners
        .iter()
        .filter(|o| {
            matches!(
                o["role"].as_str(),
                Some("replay-producer" | "diagnostic-replay")
            )
        })
        .count();
    ensure!(
        replays < 2,
        "direct163 exceeds the proven two replay lane operating point"
    );
    Ok(())
}
pub(super) async fn admit() -> Result<()> {
    let (binding, self_sha) = parsed("admit-direct163")?;
    let s: Spec = serde_json::from_value(immutable(&binding)?)?;
    ensure!(
        s.schema == "horizon-direct163-full-admission-spec-v1"
            && s.output.parent()
                == Some(Path::new(
                    "/var/lib/jetstreamer/horizon-direct163-admission-20261105-v1"
                )),
        "direct163 admission scope"
    );
    package_inputs(&s)?;
    absent()?;
    let m = immutable(&s.memory_receipt)?;
    let md = immutable(&s.memory_completion)?;
    original_selection(&m, &md, &s.memory_receipt, "memory")?;
    let d = immutable(&s.data_receipt)?;
    let dd = immutable(&s.data_completion)?;
    original_selection(&d, &dd, &s.data_receipt, "DATA")?;
    ensure!(
        m["selection"]["request"] == json!(s.memory_request)
            && d["memory_selection"] == json!(s.memory_receipt),
        "direct163 selected memory/DATA sources crossed"
    );
    let t = now()?;
    let view = memory::admission_bridge::from_current_reader(&s.memory_request, t)?;
    let selected = data::select(&view, &s.data_policy, &s.data_policy_seal, t)?;
    // The constructor above, not a JSON arithmetic result, owns both projections.
    ensure!(
        selected.evidence()["current"] == m["selection"]["request"]["current"]
            && selected.evidence()["projection"] == d["data_selection"]["projection"],
        "direct163 DATA projection changed"
    );
    let budget = candidate_memory::compose(&view)?;
    let current = &view.evidence()["request"]["current"];
    ensure!(
        s.resource_accounting["observer"] == current["observer"]
            && s.resource_accounting["fleet"] == current["fleet"]
            && s.resource_accounting["fleet_plan"] == current["fleet_plan"]
            && s.resource_accounting["phase_events"][1]["source"] == current["frame"],
        "direct163 accounting tuple crossed"
    );
    let observer = storage::json(&to_bound(&current["observer"])?)?;
    pressures(&observer)?;
    let before = epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    let p0 = physical()?;
    let after = epoch186::accounting::protected_data_basis(&s.resource_accounting, now()?).await?;
    epoch186::accounting::stable_guard_basis(&s.resource_accounting, &before, &after)?;
    unchanged_claims(&before, &after)?;
    for owner in after["current_unique_owner_census"]
        .as_array()
        .context("direct163 complete owners")?
    {
        ensure!(
            !(n(owner, "first_epoch")? <= 163 && n(owner, "last_epoch")? >= 163),
            "direct163 epoch already has an active source-owned claim"
        );
    }

    let reader = immutable(&s.memory_request.current_reader)?;
    let old = immutable(&to_bound(&reader["accounting"])?)?;
    unchanged_claims(&old, &after)?;
    absent()?;
    package_inputs(&s)?;
    let p1 = physical()?;
    let host = n(budget.evidence(), "host_total_bytes")?;
    capacity(budget.evidence(), &after, host, &p0, &p1)?;
    let required = fits(
        budget.evidence(),
        selected.effective_protected_bytes(),
        host,
        &p0,
        &p1,
    )?;
    let end = now()?;
    let fresh = memory::admission_bridge::from_current_reader(&s.memory_request, end)?;
    let fresh_data = data::select(&fresh, &s.data_policy, &s.data_policy_seal, end)?;
    ensure!(
        fresh_data.effective_protected_bytes() == selected.effective_protected_bytes()
            && fresh_data.evidence()["projection"] == selected.evidence()["projection"],
        "direct163 DATA custody changed before commit"
    );
    ensure!(
        end.checked_sub(t).is_some_and(|v| v <= 300),
        "direct163 full transaction expired"
    );
    save(
        &s.output,
        &json!({"schema":"horizon-direct163-full-admission-v1","spec":binding,"self_sha256":self_sha,
        "recorded_unix_seconds":end,"expires_unix_seconds":end+180,"current":current,
        "memory":view.evidence(),"DATA":selected.evidence(),"candidate_memory":budget.evidence(),
        "memory_receipt":s.memory_receipt,"memory_completion":s.memory_completion,
        "data_receipt":s.data_receipt,"data_completion":s.data_completion,"parent_service":s.parent_service,
        "raw_before":before,"raw_after":after,"physical_before":p0,"physical_after":p1,
        "minimum_free_bytes":selected.effective_protected_bytes(),"required_initial_free_bytes":required,
        "parent_memory_hard_bytes":192u64<<30,"candidate_DATA_bytes":DATA_BYTES,
        "guard_bytes":2u64<<30,"fallback_bytes":512u64<<20,"cpu_quota_micros":8000000,
        "maximum_worker_vmas":3000000,"reserved_auxiliary_cpu_quota_micros":3000000,"proven_operating_point_lanes":2,"admitted":true,"attended_launch_only":true,
        "unattended_authorized":false,"publication_authorized":false,"r2_mutations":false,"physical_credit_bytes":0}),
    )
}
pub(super) async fn enroll() -> Result<()> {
    enrollment::run().await
}
pub(super) use enrollment::{
    allocation, comparison_census, guard_floor, launch_matches, normalize_peers, owned_owner,
    raw_profile, validate_transition,
};

fn isolated_config(s: &Spec, metadata: &Value) -> Result<()> {
    let root = Path::new(ROOT).join("gcloud");
    ensure!(
        s.isolated_active_config.path == root.join("active_config")
            && s.isolated_configuration.path.parent()
                == Some(root.join("configurations").as_path()),
        "direct163 isolated config scope"
    );
    let read = |binding: &Bound| -> Result<String> {
        let m = fs::symlink_metadata(&binding.path)?;
        ensure!(
            m.is_file()
                && m.uid() == 1001
                && m.nlink() == 1
                && m.mode() & 0o077 == 0
                && binding.path.canonicalize()? == binding.path,
            "direct163 isolated config custody"
        );
        let raw = read_stable_bounded(&binding.path, 65536, "direct163 isolated config")?;
        ensure!(
            hex_lower(&Sha256::digest(&raw)) == binding.sha256,
            "direct163 isolated config changed"
        );
        Ok(std::str::from_utf8(&raw)?.to_owned())
    };
    let active = read(&s.isolated_active_config)?;
    ensure!(
        !active.trim().is_empty()
            && !active.trim().contains('/')
            && s.isolated_configuration
                .path
                .file_name()
                .and_then(|v| v.to_str())
                == Some(format!("config_{}", active.trim()).as_str()),
        "direct163 isolated active configuration crossed"
    );
    let text = read(&s.isolated_configuration)?;
    let mut section = "";
    let mut account = None;
    let mut project = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = &line[1..line.len() - 1];
            continue;
        }
        if section == "core"
            && !line.is_empty()
            && !line.starts_with('#')
            && !line.starts_with(';')
            && let Some((key, value)) = line.split_once('=')
        {
            match key.trim() {
                "account" => ensure!(
                    account.replace(value.trim()).is_none(),
                    "direct163 duplicate account setting"
                ),
                "project" => ensure!(
                    project.replace(value.trim()).is_none(),
                    "direct163 duplicate project setting"
                ),
                _ => {}
            }
        }
    }
    ensure!(
        account == metadata["current_account"].as_str()
            && project == metadata["current_project"].as_str(),
        "direct163 isolated authenticated configuration differs"
    );
    Ok(())
}
