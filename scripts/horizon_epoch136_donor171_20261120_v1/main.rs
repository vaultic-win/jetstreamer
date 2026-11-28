//! Epoch 171 -> 136 exclusive borrowing. The parent schedules the guarded actor.
#![recursion_limit = "384"]
mod fence;
mod fit;
#[cfg(feature = "fixture-semantic")]
mod fixture_plan;
mod joint_fit;
mod session;
mod standard169;
#[path = "../horizon_standard169_cpu_lease.rs"]
pub mod standard169_cpu_lease;
#[path = "../horizon_standard169_lineage.rs"]
mod standard169_lineage;
#[path = "../horizon_systemd_owned_mask.rs"]
mod systemd_owned_mask;
mod topology;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const BASE: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
const UNIT: &str = "horizon-qualify-136-actual-20261120-g1.service";
const GUARD: &str = "horizon-guard-136-actual-20261120-g1";
const DONOR_ROOT: &str = "/home/sol/.jetstreamer-private/epoch171-standard-lane-20261110-v1";
const CANDIDATE_DISK: u64 = 72 << 30;
const CANDIDATE_MEMORY: u64 = 68 << 30;
const PREDECESSOR: &str = "/var/lib/jetstreamer/horizon_runtime_data/epoch168-trace-admission-20261120-v2/POST_GUARD_CAPACITY.json";
const PREDECESSOR_HASH: &str = "414f2886185fbbcdf19cb5e0332d4a1301b08c09ef506a6c7873a2aaaa65503a";
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn binding(path: &Path, hash: &str) -> Value {
    json!({"path":path,"sha256":hash})
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64().with_context(|| format!("missing {k}"))
}
fn root_file(p: &Path, max: u64) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "noncanonical {}",
        p.display()
    );
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.nlink() == 1 && m.len() <= max,
        "root file {}",
        p.display()
    );
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    let end = fs::symlink_metadata(p)?;
    ensure!(
        end.dev() == m.dev()
            && end.ino() == m.ino()
            && end.ctime() == m.ctime()
            && end.ctime_nsec() == m.ctime_nsec()
            && bytes.len() as u64 == m.len(),
        "changed {}",
        p.display()
    );
    Ok(bytes)
}
fn json_pin(p: &Path, h: &str) -> Result<Value> {
    let bytes = root_file(p, 64 << 20)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == h,
        "digest {}",
        p.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn show(u: &str) -> Result<Value> {
    let fields = "Id,ActiveState,SubState,MainPID,ControlPID,InvocationID,NRestarts,Job,LoadState,FragmentPath,ControlGroup,Triggers,TriggeredBy,Result,ExecMainStatus,Type,Unit,ExecStart,ExecMainStartTimestampMonotonic,TimeoutStartUSec";
    let out = Command::new("/usr/bin/systemctl")
        .args(["show", "--no-pager", "--property", fields, "--", u])
        .output()?;
    // systemctl signals not-found via exit 4. Validate the explicit returned identity and state.
    let mut v = json!({});
    for line in std::str::from_utf8(&out.stdout)?.lines() {
        let (k, s) = line.split_once('=').context("unit property")?;
        v[k] = json!(s);
    }
    ensure!(
        v["Id"] == u
            && (out.status.success()
                || (out.status.code() == Some(4) && v["LoadState"] == "not-found")),
        "systemctl show {u}"
    );
    Ok(v)
}
fn closed(s: &Value) -> bool {
    matches!(s["ActiveState"].as_str(), Some("failed" | "inactive"))
        && s["Job"] == ""
        && ["MainPID", "ControlPID"]
            .iter()
            .all(|k| s[*k].is_null() || s[*k] == "0")
}
fn cgroup_empty(unit: &str) -> Result<()> {
    let dir = Path::new("/sys/fs/cgroup/system.slice").join(unit);
    match fs::read_to_string(dir.join("cgroup.events")) {
        Ok(s) => ensure!(
            s.lines().any(|s| s == "populated 0"),
            "populated donor cgroup {unit}"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            ensure!(!dir.try_exists()?, "unreadable cgroup {unit}")
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn ticks(pid: u64) -> Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(s.rsplit_once(')')
        .context("stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("start ticks")?
        .parse()?)
}
fn candidate_state(id: Option<&str>) -> Result<()> {
    let v = show(UNIT)?;
    match id {
        None => {
            ensure!(closed(&v), "136 unit open");
            cgroup_empty(UNIT)?;
        }
        Some(id) => {
            ensure!(
                guard168::iid(id)
                    && v["InvocationID"] == id
                    && v["ActiveState"] == "active"
                    && v["SubState"] == "running"
                    && v["Job"] == ""
                    && v["NRestarts"] == "0",
                "136 candidate identity"
            );
            let p = v["MainPID"].as_str().context("main")?.parse::<u64>()?;
            let group =
                fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{UNIT}/cgroup.procs"))?;
            ensure!(
                group.trim() == p.to_string()
                    && fs::read_to_string(format!("/proc/{p}/cgroup"))?.trim()
                        == format!("0::/system.slice/{UNIT}"),
                "136 worker already running"
            );
            let image = Path::new(BASE).join("tools/epoch136-actual-payload");
            let a = fs::metadata(image)?;
            let b = fs::metadata(format!("/proc/{p}/exe"))?;
            ensure!(
                a.dev() == b.dev() && a.ino() == b.ino(),
                "foreign 136 waiting payload"
            );
        }
    }
    Ok(())
}
fn active168(f: &Value) -> Result<Value> {
    let rows = f["actual_active_private_diagnostics"]
        .as_array()
        .context("168 observer")?;
    ensure!(
        rows.len() == 1 && rows[0]["epoch"] == 168,
        "unrecognized private diagnostic fleet"
    );
    let r = &rows[0];
    let u = guard168::UNIT;
    let s = show(u)?;
    let t = show("horizon-guard-168-trace-local3-20261120-v1.timer")?;
    ensure!(
        s["InvocationID"] == "c081016844dd40c5a78b594bf7ede73a"
            && s["InvocationID"] == r["unit"]["InvocationID"]
            && s["MainPID"] == r["unit"]["MainPID"]
            && s["ActiveState"] == "active"
            && s["SubState"] == "running"
            && s["Job"] == ""
            && s["NRestarts"] == "0"
            && t["InvocationID"] == r["guard_timer"]["InvocationID"]
            && t["ActiveState"] == "active"
            && t["Job"] == "",
        "168 observer/native ownership changed"
    );
    ensure!(
        r["post_guard_capacity"] == binding(Path::new(PREDECESSOR), PREDECESSOR_HASH),
        "168 post-guard authority"
    );
    let worker = &r["native_worker_at_consumption"];
    let p = s["MainPID"].as_str().context("168 pid")?.parse::<u64>()?;
    let w = n(worker, "pid")?;
    let main = Path::new(
        "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1/jetstreamer-node",
    );
    ensure!(
        fs::read_link(format!("/proc/{p}/exe"))? == main
            && ticks(p)? == n(r, "native_start_ticks")?
            && ticks(w)? == n(worker, "start_ticks")?
            && worker["basename"] == "historical-worker",
        "168 pid/image changed"
    );
    let image = fs::metadata(format!("/proc/{w}/exe"))?;
    ensure!(
        image.dev() == n(worker, "device")?
            && image.ino() == n(worker, "inode")?
            && fs::read_link(format!("/proc/{w}/exe"))?
                == Path::new(worker["executable"].as_str().context("168 worker")?),
        "168 worker changed"
    );
    let members = fs::read_to_string(format!("/sys/fs/cgroup/system.slice/{u}/cgroup.procs"))?
        .lines()
        .map(str::parse::<u64>)
        .collect::<Result<BTreeSet<_>, _>>()?;
    ensure!(
        members == BTreeSet::from([p, w]),
        "unbound 168 cgroup member"
    );
    Ok(
        json!({"unit":u,"invocation_id":s["InvocationID"],"accepted_processes":[{"pid":p,"basename":"jetstreamer-node"},{"pid":w,"basename":"historical-worker"}],"resident_credit_bytes":0}),
    )
}
fn file_write(path: &Path, data: &Value) -> Result<Value> {
    use std::io::Write;
    let mut bytes = serde_json::to_vec_pretty(data)?;
    bytes.push(b'\n');
    let parent = path.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.uid() == 0 && m.mode() & 0o022 == 0 && m.is_dir(),
        "unsafe output parent"
    );
    let next = parent.join(format!(".donor171-{}-{}", std::process::id(), now()?));
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o400)
        .open(&next)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    // RENAME_NOREPLACE keeps a complete record invisible until every byte is durable.
    let cv = |p: &Path| -> Result<std::ffi::CString> {
        use std::os::unix::ffi::OsStrExt;
        Ok(std::ffi::CString::new(p.as_os_str().as_bytes())?)
    };
    let a = cv(&next)?;
    let b = cv(path)?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        let e = std::io::Error::last_os_error();
        fs::remove_file(next)?;
        if e.kind() != std::io::ErrorKind::AlreadyExists || root_file(path, 64 << 20)? != bytes {
            return Err(e.into());
        }
    }
    fs::File::open(parent)?.sync_all()?;
    Ok(binding(path, &format!("{:x}", Sha256::digest(bytes))))
}
const WRITER_UNIT: &str = "horizon-admit-136-actual-20261120-g1.service";
fn generation(plan: &Value) -> Result<()> {
    #[cfg(feature = "fixture-semantic")]
    fixture_plan::validate(plan)?;
    ensure!(
        plan["schema"] == "horizon-epoch136-actual-plan-v1"
            && plan["barrier_version"] == "epoch136-actual-20261120-before-initialize-v1",
        "wrong generation"
    );
    let tools = Path::new(BASE).join("tools");
    let expect = [
        ("helper", "epoch136-actual-payload"),
        ("node", "jetstreamer-node"),
        ("worker", "jetstreamer-historical-worker-v1-4-25"),
        ("tools_seal", "deployment-seal-receipt.json"),
        ("source_proof", "artifact-proof.json"),
        ("qualification", "qualification.json"),
        ("history", "historical-accounting-review.json"),
    ];
    for (k, name) in expect {
        ensure!(
            plan[k]["path"] == tools.join(name).to_str().unwrap(),
            "foreign plan member {k}"
        );
    }
    let proof = json_pin(
        &tools.join("artifact-proof.json"),
        plan["source_proof"]["sha256"]
            .as_str()
            .context("source sha")?,
    )?;
    ensure!(
        proof["source_commit"] == plan["source_commit"]
            && proof["schema"] == "horizon-epoch136-actual-artifact-proof-v1"
            && proof["source_contained_in_origin_account_updates"] == true
            && proof["node"] == plan["node"]
            && proof["payload"] == plan["helper"]
            && proof["worker"] == plan["worker"]
            && plan["worker"]["sha256"]
                == "3ea95997d956de6a8c7fa431e679d496a5d3c31e15f8a104a8ddb0086646ea3d"
            && plan["qualification"]["sha256"]
                == "a84600699abc7ca36230fa6bb994e6d5c3cf099a9481ecad02a6c2e6178e9f81"
            && proof["exact_node_cli_and_snapshot_route_qualified"] == true
            && proof["actual_worker_pre_initialize_gate_qualified"] == true
            && proof["tests_failed"] == 0
            && proof["tests_passed"].as_u64().is_some_and(|v| v > 0),
        "unqualified worker/node/helper"
    );
    let seal = json_pin(
        &tools.join("deployment-seal-receipt.json"),
        plan["tools_seal"]["sha256"].as_str().context("seal sha")?,
    )?;
    ensure!(seal.is_object(), "tools seal");
    session::native_denial_provenance(plan)?;
    Ok(())
}
// The installed payload has a closed Plan schema. Operational metadata stays
// under the writer's full plan digest, independently of the payload's argv.
fn payload_plan(plan: &Value) -> Result<Value> {
    let fields = [
        "schema",
        "node",
        "helper",
        "worker",
        "tools_seal",
        "qualification",
        "source_proof",
        "source_commit",
        "history",
        "controller",
        "barrier_version",
    ];
    let mut payload = serde_json::Map::new();
    for key in fields {
        let member = plan
            .get(key)
            .with_context(|| format!("missing payload plan member {key}"))?;
        payload.insert(key.to_owned(), member.clone());
    }
    Ok(Value::Object(payload))
}

fn check_plan_bindings(
    plan: &Value,
    writer_plan: &Value,
    admitted: &Value,
    capacity: &Value,
) -> Result<()> {
    let payload = payload_plan(plan)?;
    ensure!(
        capacity["writer_plan"] == *writer_plan && capacity["payload_plan"] == *admitted,
        "capacity bound to another writer or payload plan"
    );
    if payload == *plan {
        ensure!(
            admitted == writer_plan,
            "original payload plan binding changed"
        );
    } else {
        let path = Path::new(BASE).join("payload-plan.json");
        ensure!(
            admitted["path"] == path.to_str().unwrap()
                && json_pin(
                    &path,
                    admitted["sha256"].as_str().context("payload plan digest")?
                )? == payload,
            "wrong payload plan projection"
        );
    }
    Ok(())
}

fn installed_controller(plan: &Value) -> Result<Value> {
    let exe = Path::new(BASE).join("controller/admit136");
    let own = fs::metadata("/proc/self/exe")?;
    let installed = fs::symlink_metadata(&exe)?;
    ensure!(
        own.dev() == installed.dev() && own.ino() == installed.ino(),
        "wrong installed admission image"
    );
    let image = root_file(&exe, 64 << 20)?;
    let hash = format!("{:x}", Sha256::digest(image));
    let bound = binding(&exe, &hash);
    ensure!(plan["controller"] == bound, "controller plan binding");
    Ok(bound)
}
fn writer(plan: &Value) -> Result<(Value, String)> {
    let bound = installed_controller(plan)?;
    let v = show(WRITER_UNIT)?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        v["InvocationID"] == iid
            && guard168::iid(&iid)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{WRITER_UNIT}"),
        "writer cgroup/plan binding"
    );
    let cg = Path::new("/sys/fs/cgroup/system.slice").join(WRITER_UNIT);
    let val = |field: &str| -> Result<String> {
        Ok(fs::read_to_string(cg.join(field))?.trim().to_owned())
    };
    let quota = val("cpu.max")?;
    let q = quota
        .split_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()?;
    ensure!(
        val("memory.max")? == "536870912"
            && val("memory.swap.max")? == "0"
            && val("pids.max")? == "64"
            && q.len() == 2
            && q[0] > 0
            && q[0].checked_mul(4) == Some(q[1]),
        "controller must fit its 512MiB/quarter-CPU share"
    );
    Ok((bound, iid))
}
fn donor_disk() -> Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let p = Path::new(DONOR_ROOT);
    let m = fs::symlink_metadata(p)?;
    ensure!(
        p.canonicalize()? == p
            && m.dev() == fs::metadata("/home/sol")?.dev()
            && m.ino() == 106233867
            && m.uid() == 1001
            && m.gid() == 1003
            && m.mode() == 0o40700,
        "donor root identity"
    );
    ensure!(
        !fs::read_to_string("/proc/self/mountinfo")?
            .lines()
            .filter_map(|l| l.split_whitespace().nth(4))
            .any(|s| Path::new(s).starts_with(p)),
        "mount inside donor root"
    );
    let get = || -> Result<u64> {
        let o = Command::new("/usr/bin/du")
            .args([
                "--summarize",
                "--one-file-system",
                "--block-size=1",
                "--",
                DONOR_ROOT,
            ])
            .output()?;
        ensure!(o.status.success(), "donor root accounting");
        let (v, path) = std::str::from_utf8(&o.stdout)?
            .trim_end()
            .split_once('\t')
            .context("du")?;
        ensure!(path == DONOR_ROOT, "donor root");
        Ok(v.parse()?)
    };
    let a = get()?;
    let b = get()?;
    ensure!(
        a == b && a <= 288 << 30 && fs::symlink_metadata(p)?.ino() == m.ino(),
        "unstable donated lane"
    );
    Ok(
        json!({"path":p,"device":m.dev(),"inode":m.ino(),"allocated_bytes":a,"retained_remaining_growth_bytes":(288u64<<30)-a,"donor_guard_metadata_bytes":8u64<<30,"donor_DATA_credit_bytes":0,"candidate_dedicated_HOME_bytes":CANDIDATE_DISK}),
    )
}
fn capacity(
    fit: &Value,
    protected: u64,
    donor: &Value,
    fleet: &Value,
    author: &Value,
    iid: &str,
) -> Result<Value> {
    let total = n(fit, "complete_memory_plus_reserve_bytes")?;
    let cpu = n(fit, "simultaneous_cpu_upper_bound_micros")?;
    let actual = n(fit, "available_HOME_bytes")?;
    if fit["schema"] == "horizon-136-writer-joint-fit-v1" {
        ensure!(
            cpu == 64_000_000
                && fit["exclusive_standard169_cpu_lease"]["cpu_quota_micros"] == 4_250_000
                && fit["activation_compatible"] == true
                && fit["disk_fits"] == true
                && actual >= n(fit, "complete_required_HOME_bytes")?,
            "missing qualified joint capacity or CPU fence"
        );
    } else {
        ensure!(
            cpu == 63_500_000,
            "exclusive-window CPU reservation differs"
        );
    }
    // The sealed payload checks the original physical start floor again before
    // spawning its node. Report observed free bytes on both visits.
    ensure!(
        total == 810658050048
            && n(fit, "total_memory_bytes")? >= total
            && n(fit, "protected_raw_floor_bytes")? <= protected
            && actual
                >= protected
                    .checked_add(CANDIDATE_DISK)
                    .context("disk overflow")?,
        "fresh capacity exceeds frozen envelope"
    );
    Ok(
        json!({"schema":"horizon-epoch136-exclusive-capacity-v1","writer":author,"writer_invocation_id":iid,"recorded_unix_seconds":now()?,"candidate_unit":UNIT,"candidate_run_root":Path::new(BASE).join("reproduction"),"candidate_memory_max_bytes":CANDIDATE_MEMORY,"candidate_data_bytes":CANDIDATE_DISK,"candidate_cpu_quota_micros":3000000,"complete_host_ledger_checked":true,"current_native_ownership_checked":true,"no_overlapping_epoch136_controller":true,"guard_512MiB_hard_limit_charged_in_complete_ledger":true,"guard_memory_bytes_borrowed_from_reserved_1GiB":512u64<<20,"writer_memory_bytes_borrowed_from_same_guard_reservation":512u64<<20,"writer_cpu_quota_micros":250000,"os_and_peer_floors_preserved":true,"all_historical_attempts_and_retained_data_preserved":true,"old_failed4_memory_retirement_reused_as_new_credit":false,"old_failed4_new_memory_credit_bytes":0,"exclusive_handoff_accepted":true,"exclusive_handoff_memory_bytes":CANDIDATE_MEMORY,"handoff_source_no_longer_launchable":true,"handoff_source_physically_drained":true,"existing_memory_promises_after_exclusive_handoff_bytes":total-CANDIDATE_MEMORY,"total_memory_promises_including_floor_and_candidate_bytes":total,"host_memory_bytes":fit["total_memory_bytes"],"protected_existing_home_free_bytes":protected,"available_home_bytes":actual,"actual_home_backing_device_verified":true,"candidate_reserved_once":true,"predecessor_capacity":binding(Path::new(PREDECESSOR),PREDECESSOR_HASH),"exclusive_handoff_receipt":donor,"complete_fleet":fleet,"complete_fresh_fit":fit}),
    )
}
fn verify_fleet(f: &Value) -> Result<()> {
    let rows = f["epochs"].as_array().context("complete fleet epochs")?;
    for e in [171, 136] {
        let r = rows
            .iter()
            .find(|r| r["epoch"] == e)
            .context("missing donor/candidate row")?;
        ensure!(
            r["repair_open"] == true && r["no_live_producer_claimed"] == true,
            "donor/candidate not idle in accepted fleet"
        );
    }
    Ok(())
}
fn passive_observer(u: &str) -> Result<bool> {
    let t = [
        (
            "204700",
            "9acfedc65a88501100a8a8068b4d6ce449b4f0c861104dd57bbd0389363ecfd3",
            "43e99533a4821f0133f464adce6b79247858c1f45b3d2f3d7b117940e0f79c25",
        ),
        (
            "212000",
            "fbad3f9ae5d34af0a6efc42dab06febbce96385302635d466a5316038546928d",
            "c3d842d2e98b78813d3d261512da43f37b8315ab1a321293d3bc26c8a00fb710",
        ),
        (
            "215000",
            "1bb1f04bcdb848bfc664eb4a7418915e6493b3e0b3273ffb4021cb8c89a161a4",
            "c09a815fc3ca0ad13bbca1a99d470ebb933682b39d21f2d8dabed22de747486b",
        ),
    ];
    for (stamp, tsha, ssha) in t {
        let base = format!("jetstreamer-horizon-observe-public191-{stamp}-20261028-trace136-v1");
        if u != format!("{base}.timer") {
            continue;
        }
        let service = format!("{base}.service");
        let time = show(u)?;
        let svc = show(&service)?;
        ensure!(
            time["Triggers"] == service
                && time["Job"] == ""
                && svc["MainPID"] == "0"
                && svc["ControlPID"] == "0"
                && svc["Job"] == ""
                && svc["SubState"] == "exited",
            "historical observer live or changed"
        );
        for (name, hash, state) in [(u, tsha, &time), (service.as_str(), ssha, &svc)] {
            let path = Path::new("/run/systemd/transient").join(name);
            ensure!(
                state["FragmentPath"] == path.to_str().unwrap()
                    && format!("{:x}", Sha256::digest(root_file(&path, 1 << 20)?)) == hash,
                "historical observer definitions changed"
            );
        }
        cgroup_empty(&service)?;
        return Ok(true);
    }
    Ok(false)
}
fn no_older_136() -> Result<()> {
    let jobs = Command::new("/usr/bin/systemctl")
        .args(["list-jobs", "--no-legend", "--no-pager", "--plain"])
        .output()?;
    ensure!(
        jobs.status.success()
            && !std::str::from_utf8(&jobs.stdout)?.lines().any(|l| l
                .split_whitespace()
                .nth(1)
                .is_some_and(|u| u.contains("136")
                    && u != WRITER_UNIT
                    && u != UNIT
                    && !u.starts_with(GUARD))),
        "queued epoch136 job"
    );
    let out = Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--full",
            "--no-legend",
            "--plain",
            "--no-pager",
            "--state=activating,active,reloading,deactivating",
            "*136*.service",
            "*136*.timer",
        ])
        .output()?;
    ensure!(out.status.success(), "historical 136 controller census");
    for l in std::str::from_utf8(&out.stdout)?.lines() {
        let mut fields = l.split_whitespace();
        let u = fields.next().context("136 unit row")?;
        let load = fields.next();
        let active = fields.next();
        let sub = fields.next();
        if load == Some("loaded") && active == Some("active") && sub == Some("exited") {
            cgroup_empty(u)?;
            continue;
        }
        if passive_observer(u)? {
            continue;
        }
        if u == WRITER_UNIT
            || u == UNIT
            || u == format!("{GUARD}.service")
            || u == format!("{GUARD}.timer")
        {
            continue;
        }
        // Static mount **units** carry other suffixes. Earlier live 136 helpers/controllers
        // must be resolved by the operator; do not derive an exception from an epoch substring.
        anyhow::bail!("other active epoch136 unit {u}");
    }
    Ok(())
}
fn joint_mode(plan: &Value) -> Result<bool> {
    let joint = standard169::requested(plan)?;
    ensure!(
        joint == plan.get("joint_fit_145").is_some(),
        "joint fit requires both the capacity provider and the exclusive CPU loan"
    );
    Ok(joint)
}

fn inspect_fit(
    plan: &Value,
    fleet_path: &Path,
    fleet_sha: &str,
    waiting: Option<&str>,
    for_activation: bool,
) -> Result<Value> {
    let fleet = json_pin(fleet_path, fleet_sha)?;
    verify_fleet(&fleet)?;
    no_older_136()?;
    if joint_mode(plan)? {
        let cpu = standard169::inspect(fleet_path, fleet_sha)?;
        let mut fit = joint_fit::inspect(plan, fleet_path, fleet_sha, waiting, for_activation)?;
        ensure!(
            cpu["fleet"] == fit["fleet"],
            "CPU and joint fit use different fleets"
        );
        fit["standard169_preflight"] = cpu;
        Ok(fit)
    } else {
        topology::exclusive_post172(&fleet)?;
        fit::inspect(fleet_path, fleet_sha, waiting)
    }
}

fn apply_cpu_lease(fit: &mut Value, native: &Value) -> Result<()> {
    let cpu = &fit["standard169_preflight"];
    let accounting = &cpu["accounting"];
    let lease = &native["standard169_cpu_lease"];
    let borrowed = n(lease, "cpu_quota_micros")?;
    let before = n(fit, "unfenced_with_candidate_cpu_micros")?;
    let actual = before
        .checked_sub(borrowed)
        .context("CPU loan exceeds booked total")?;
    let retained: BTreeSet<String> =
        serde_json::from_value(lease["masked_standard_routes"].clone())?;
    let routes = cpu["current_standard_routes"]
        .as_object()
        .context("current standard 169 routes")?;
    ensure!(
        fit["schema"] == "horizon-136-writer-joint-fit-v1"
            && fit["activation_compatible"] == true
            && fit["disk_fits"] == true
            && borrowed == 4_250_000
            && actual == 64_000_000
            && n(accounting, "candidate_cpu_micros")? == borrowed
            && n(accounting, "unfenced_simultaneous_micros")? == before
            && n(accounting, "online_and_allowed_cpu_micros")? == actual
            && n(
                accounting,
                "prospective_host_total_with_exclusive_loan_micros"
            )? == actual
            && lease["unassigned_standard169_cpu_micros"] == 4_750_000
            && lease["additional_host_cpu_micros"] == 0
            && !routes.is_empty()
            && routes
                .iter()
                .all(|(name, row)| retained.contains(name) && row["load"] == "masked")
            && lease["registry"].is_object(),
        "CPU loan is incomplete or does not fit the host"
    );
    fit["simultaneous_cpu_upper_bound_micros"] = json!(actual);
    fit["exclusive_standard169_cpu_lease"] = lease.clone();
    Ok(())
}

fn run() -> Result<()> {
    use std::os::fd::AsRawFd;
    let a: Vec<_> = std::env::args().skip(1).collect();
    ensure!(unsafe { libc::geteuid() } == 0, "root controller required");
    ensure!(
        !a.is_empty(),
        "expected inventory|preflight|establish|prepare|post|session|register-status|release"
    );
    if a[0] == "payload-plan" {
        ensure!(a.len() == 3, "payload-plan PLAN SHA");
        let plan = json_pin(Path::new(&a[1]), &a[2])?;
        println!("{}", serde_json::to_string_pretty(&payload_plan(&plan)?)?);
        return Ok(());
    }
    if a[0] == "cpu-preflight" {
        ensure!(a.len() == 3, "cpu-preflight FLEET SHA");
        println!("{}", standard169::inspect(Path::new(&a[1]), &a[2])?);
        return Ok(());
    }
    if a.first().is_some_and(|mode| mode == "audit-owner") {
        ensure!(a.len() == 3, "audit-owner FLEET SHA");
        let fleet = json_pin(Path::new(&a[1]), &a[2])?;
        println!(
            "{}",
            fit::observe_audit(&fleet["continuing_audit_obligation"])?
        );
        return Ok(());
    }
    if a[0] == "preflight" {
        ensure!(a.len() == 5, "preflight PLAN SHA FLEET SHA");
        let plan = json_pin(Path::new(&a[1]), &a[2])?;
        let fleet_path = Path::new(&a[3]);
        let controller = installed_controller(&plan)?;
        generation(&plan)?;
        let ancestry = fence::ancestry()?;
        let disk = donor_disk()?;
        let fit = inspect_fit(&plan, fleet_path, &a[4], None, false)?;
        println!(
            "{}",
            json!({"controller":controller,"plan":binding(Path::new(&a[1]),&a[2]),"donor_ancestry":ancestry,"donor_disk":disk,"fit":fit,"donor_fenced":false,"admission_granted":false})
        );
        return Ok(());
    }
    if a == ["inventory"] {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &json!({"ancestry":fence::ancestry()?,"HOME":donor_disk()?})
            )?
        );
        return Ok(());
    }
    // The session holds the admission lock while waiting for this metadata-only
    // response. Registration creates no booking and never opens the node gate.
    if a[0] == "register-status" {
        ensure!(
            a.len() == 7,
            "register-status PLAN SHA STATUS SHA FLEET SHA"
        );
        return session::register_status(&a[1..]);
    }
    if a[0] == "verify-release" {
        ensure!(a.len() == 3, "verify-release PLAN SHA");
        let path = Path::new(BASE).join("prestart-intent.json");
        let (intent, _) = session::immutable(&path)?;
        ensure!(
            intent["writer_plan"] == binding(Path::new(&a[1]), &a[2]),
            "foreign release plan"
        );
        println!("{}", session::release_incident(&path, false)?);
        return Ok(());
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(standard169_cpu_lease::OPERATION_LOCK)?;
    let md = lock.metadata()?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.mode() & 0o077 == 0
            && md.nlink() == 1
            && unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "concurrent or unsafe donor transaction"
    );
    standard169_cpu_lease::require_unclaimed(Path::new(standard169_cpu_lease::REGISTRY_171))?;
    let base = Path::new(BASE);
    if a == ["qualify-pid1"] {
        return fence::qualify_pid1();
    }
    if a == ["release"] {
        let p = base.join("admission.json");
        if p.try_exists()? {
            let v: Value = serde_json::from_slice(&root_file(&p, 1 << 20)?)?;
            ensure!(
                now()? >= n(&v, "launch_expires_unix_seconds")?,
                "unexpired candidate admission"
            );
        }
        ensure!(closed(&show(WRITER_UNIT)?), "writer still active");
        let intent = base.join("prestart-intent.json");
        if intent.try_exists()? {
            println!("{}", session::release_incident(&intent, true)?);
        } else {
            fence::release()?;
        }
        return Ok(());
    }
    if a[0] == "session" {
        ensure!(a.len() == 5, "session PLAN SHA FLEET SHA");
        return session::run(&a[1..]);
    }
    println!("{}", phase(&a)?);
    Ok(())
}
// Called in-process by session so every phase retains the same writer IID and flock.
fn phase(a: &[String]) -> Result<Value> {
    let base = Path::new(BASE);
    ensure!(
        (matches!(a[0].as_str(), "establish" | "prepare") && a.len() == 5)
            || (a[0] == "post" && a.len() == 6),
        "phase PLAN SHA FLEET SHA [candidate IID]"
    );
    let plan_path = Path::new(&a[1]);
    let plan = json_pin(plan_path, &a[2])?;
    let plan_ref = binding(plan_path, &a[2]);
    generation(&plan)?;
    let (author, iid) = writer(&plan)?;
    let fpath = Path::new(&a[3]);
    let fleet = binding(fpath, &a[4]);
    let anc = fence::ancestry()?;
    if a[0] == "establish" {
        let cpu = joint_mode(&plan)?;
        let initial = inspect_fit(&plan, fpath, &a[4], None, true)?;
        if let Some(selector) = plan.get("holding145_prestart_ready") {
            let stage = &initial["authoritative_joint_fit"]["candidate136"];
            ensure!(
                initial["activation_compatible"] == true
                    && stage["selector"] == *selector
                    && stage["writer"]["invocation_id"] == iid
                    && !stage["semantic_complete"].is_null(),
                "missing original registered 145/136 handoff"
            );
            file_write(
                &base.join("prestart-intent.json"),
                &json!({
                    "schema":"horizon-136-incident-donor-intent-v1", "epoch":136, "writer":author,
                    "writer_invocation_id":iid, "writer_plan":plan_ref, "fleet":fleet,
                    "selector":selector, "semantic_complete":stage["semantic_complete"],
                    "standard_routes":initial["standard169_preflight"]["current_standard_routes"],
                    "recorded_unix_seconds":now()?, "boot_id":fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
                    "admission_granted":false
                }),
            )?;
        }
        let native = fence::establish(cpu)?;
        let mut fenced_fit = inspect_fit(&plan, fpath, &a[4], None, true)?;
        if cpu {
            apply_cpu_lease(&mut fenced_fit, &native)?;
        }
        ensure!(
            fence::check(cpu)? == native,
            "donor changed during post-fence fit"
        );
        let loan = json!({"schema":"horizon-exclusive-171-to136-v1","complete_fleet":fleet,"writer":author,"writer_invocation_id":iid,"recorded_unix_seconds":now()?,"ancestry":anc,"HOME":donor_disk()?,"native":native,"writer_plan":plan_ref,"post_fence_host_cpu_micros":fenced_fit["simultaneous_cpu_upper_bound_micros"],"new_memory_credit_bytes":0,"replay_launched":false});
        let receipt = file_write(&base.join("donor171.json"), &loan)?;
        return Ok(receipt);
    }
    no_older_136()?;
    let donor_path = base.join("donor171.json");
    let bytes = root_file(&donor_path, 1 << 20)?;
    let cpu = joint_mode(&plan)?;
    let native = fence::check(cpu)?;
    let loan: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        loan["writer"] == author
            && loan["writer_invocation_id"] == iid
            && loan["writer_plan"] == plan_ref
            && loan["native"] == native
            && loan["ancestry"] == anc
            && loan["HOME"] == donor_disk()?,
        "foreign donor lease"
    );
    let dref = binding(&donor_path, &format!("{:x}", Sha256::digest(bytes)));
    let own = a.get(5).map(String::as_str);
    let mut fit = inspect_fit(&plan, fpath, &a[4], own, true)?;
    if cpu {
        apply_cpu_lease(&mut fit, &native)?;
    }
    ensure!(fence::check(cpu)? == native, "fence changed during fit");
    no_older_136()?;
    let cap_path = base.join("capacity.json");
    let protected = if own.is_some() {
        let old: Value = serde_json::from_slice(&root_file(&cap_path, 64 << 20)?)?;
        ensure!(
            old["writer_invocation_id"] == iid && old["exclusive_handoff_receipt"] == dref,
            "capacity predecessor"
        );
        n(&old, "protected_existing_home_free_bytes")?
    } else {
        n(&fit, "protected_raw_floor_bytes")?
    };
    let projected = payload_plan(&plan)?;
    let payload_ref = if plan == projected {
        plan_ref.clone()
    } else if own.is_none() {
        file_write(&base.join("payload-plan.json"), &projected)?
    } else {
        session::load_admission_for_post(&plan_ref, &dref, &iid)?["plan"].clone()
    };
    let mut full = capacity(&fit, protected, &dref, &fleet, &author, &iid)?;
    if cpu {
        full["complete_cpu_quota_micros"] = fit["simultaneous_cpu_upper_bound_micros"].clone();
        full["exclusive_standard169_cpu_lease"] = fit["exclusive_standard169_cpu_lease"].clone();
    }
    full["writer_plan"] = plan_ref.clone();
    full["payload_plan"] = payload_ref.clone();
    check_plan_bindings(&plan, &plan_ref, &payload_ref, &full)?;
    let result = if own.is_some() {
        file_write(&base.join("capacity-post-prefire.json"), &full)?
    } else {
        let cap = file_write(&cap_path, &full)?;
        let sec = now()?;
        let receipt = json!({"schema":"horizon-epoch136-actual-admission-v1","plan":payload_ref,"helper":plan["helper"],"node":plan["node"],"worker":plan["worker"],"tools_seal":plan["tools_seal"],"writer":author,"writer_invocation_id":iid,"recorded_unix_seconds":sec,"launch_expires_unix_seconds":sec+900,"protected_existing_free_bytes":protected,"required_initial_free_bytes":protected+CANDIDATE_DISK,"data_reservation_bytes":CANDIDATE_DISK,"memory_max_bytes":CANDIDATE_MEMORY,"cpu_quota_micros":3000000,"resource_accounting":cap,"bounded_reproduction_authorized":true,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"full_epoch_span_proven":false});
        file_write(&base.join("admission.json"), &receipt)?
    };
    Ok(result)
}
fn main() -> Result<()> {
    run()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fit() -> Value {
        json!({"complete_memory_plus_reserve_bytes":810658050048u64,"simultaneous_cpu_upper_bound_micros":63500000,"available_HOME_bytes":CANDIDATE_DISK+100,"total_memory_bytes":810902843392u64,"protected_raw_floor_bytes":100})
    }
    #[test]
    fn joint_capacity_needs_the_paid_and_masked_cpu_lease() {
        let mut fit = fit();
        fit["schema"] = json!("horizon-136-writer-joint-fit-v1");
        fit["disk_fits"] = json!(true);
        fit["activation_compatible"] = json!(true);
        fit["complete_required_HOME_bytes"] = json!(CANDIDATE_DISK + 100);
        fit["unfenced_with_candidate_cpu_micros"] = json!(68_250_000);
        fit["standard169_preflight"] = json!({
            "current_standard_routes":{"route.service":{"load":"masked"}},
            "accounting":{"candidate_cpu_micros":4_250_000,"unfenced_simultaneous_micros":68_250_000,
                "online_and_allowed_cpu_micros":64_000_000,"prospective_host_total_with_exclusive_loan_micros":64_000_000}
        });
        let native = json!({"standard169_cpu_lease":{"masked_standard_routes":["route.service"],"cpu_quota_micros":4_250_000,
            "unassigned_standard169_cpu_micros":4_750_000,"additional_host_cpu_micros":0,"registry":{"path":"fixture"}}});
        let receipt =
            |f: &Value| capacity(f, 100, &Value::Null, &Value::Null, &Value::Null, "writer");
        assert!(receipt(&fit).is_err());
        let mut bad = fit.clone();
        bad["standard169_preflight"]["current_standard_routes"]["route.service"]["load"] =
            json!("loaded");
        assert!(apply_cpu_lease(&mut bad, &native).is_err());
        assert!(apply_cpu_lease(&mut fit.clone(), &Value::Null).is_err());
        apply_cpu_lease(&mut fit, &native).unwrap();
        assert!(receipt(&fit).is_ok());
        fit["available_HOME_bytes"] = json!(CANDIDATE_DISK + 99);
        assert!(receipt(&fit).is_err());
    }

    #[test]
    fn exactly_one_donor_and_private_root() {
        let v = capacity(&fit(), 100, &Value::Null, &Value::Null, &Value::Null, "x").unwrap();
        assert_eq!(
            v["existing_memory_promises_after_exclusive_handoff_bytes"]
                .as_u64()
                .unwrap()
                + CANDIDATE_MEMORY,
            810658050048
        );
    }
    #[test]
    fn rejects_new_peer_growth_floor_and_host_overage() {
        for (k, val) in [
            ("available_HOME_bytes", CANDIDATE_DISK + 99),
            ("protected_raw_floor_bytes", 101),
            ("total_memory_bytes", 810658050047),
            ("simultaneous_cpu_upper_bound_micros", 65000000),
        ] {
            let mut f = fit();
            f[k] = json!(val);
            assert!(capacity(&f, 100, &Value::Null, &Value::Null, &Value::Null, "x").is_err());
        }
    }
}
