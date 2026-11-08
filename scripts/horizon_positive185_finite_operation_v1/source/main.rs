//! Finite Root185 upstream operation. Source proposal, never an admission by presence.
//! No shell, arbitrary command vectors, deadline retries, original199 body access,
//! snapshot hashing or archive publication. Existing qualified Rust owns all seals,
//! native task/enrollment, complete reader and final original release transaction.
mod activation;
mod follow_on;
mod persistent_reader;
mod process;
mod reader_phase;
mod storage;
mod timers;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    env, fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use storage::Bound;
pub const PLANNER: &str = "/usr/local/lib/jetstreamer/horizon-positive185-current-witness-planner-tools-20261108-v2/planner";
pub const PLANNER_SHA: &str = "2c0d6af4189b56bbee54aa91a0f7307f2e9892b54c0e9b8efde8cce12314a355";
pub const HELPER: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261107-v13/jetstreamer-r2";
pub const HELPER_SHA: &str = "d00ee6ad4076c32b90a416efc9236208cd7ee8b64e572d5ad830c9a709eac470";
pub const FLEET_HELPER: &str = "/usr/local/lib/jetstreamer/horizon-first-lane-combined-witness-terminal145-helper-tools-20261108-v27/jetstreamer-r2";
pub const FLEET_HELPER_SHA: &str =
    "cd316bb78fe122735ebf6144b3b057d03851fa528ce89fd967da0eb7f5b929cd";
pub const NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-native-hooks-complete-supported-route-tools-20261105-v11/jetstreamer-r2";
pub const NATIVE_SHA: &str = "0f1d171bc9fee7a1d06186e62b03e601d575bdcacfa30545cf0c084850f0934c";
pub const DRIVER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch185-guarded-adapter-v10/epoch185-guarded-cold";
pub const DRIVER_SHA: &str = "0a7dddaaa5ae049a6a9f6ca103fd8463987d6aff52397a4ece09a43387107e1a";
pub const FINAL: &str = "/usr/local/lib/jetstreamer/horizon-positive185-final-transaction-tools-20261107-v1/horizon-positive185-final";
pub const FINAL_SHA: &str = "c71aaab50391ac6fde77e45a47e60b39e3ccf51e806ddb59544115f03d7cd21d";
pub const REGISTRY: &str =
    "/var/lib/jetstreamer/horizon-epoch185-native-startpre-registrations-20261105-v1";
pub fn deny_original199(path: &Path) -> Result<()> {
    for root in [
        "/usr/local/lib/jetstreamer/deploy-epoch199-singleton-20261017-v1",
        "/var/lib/jetstreamer-root-sweep-epoch199-backfill-20261102-v1",
        "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1",
        "/proc/2467123/fd",
    ] {
        ensure!(
            !path.starts_with(root),
            "protected original199 body/directory-FD is outside185 operation scope"
        );
    }
    Ok(())
}
pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
pub fn n(v: &Value, k: &str) -> Result<u64> {
    storage::n(v, k)
}
pub fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
pub fn unit_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() < 180
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub fn binding(v: &Value) -> Result<Bound> {
    storage::bound(v)
}
pub fn fixed(path: &str, sha: &str) -> Bound {
    Bound {
        path: path.into(),
        sha256: sha.into(),
    }
}
pub fn utc(raw: &str) -> Result<u64> {
    let i = std::ffi::CString::new(raw)?;
    let mut tm = unsafe { std::mem::zeroed::<libc::tm>() };
    let e = unsafe { libc::strptime(i.as_ptr(), c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) };
    ensure!(!e.is_null() && unsafe { *e } == 0, "strict original UTC");
    let s = unsafe { libc::timegm(&mut tm) };
    ensure!(s >= 0, "UTC before epoch");
    Ok(s as u64)
}
pub fn private(path: &Path, empty: bool) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "Root0700 directory"
    );
    ensure!(
        !empty || fs::read_dir(path)?.next().is_none(),
        "fresh empty Root root"
    );
    Ok(())
}
pub fn make_private(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    private(path, true)
}
pub fn write_bytes(root: &Path, name: &str, raw: &[u8]) -> Result<Bound> {
    ensure!(!name.contains('/') && !name.is_empty(), "exact leaf");
    let p = root.join(name);
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)?;
    f.write_all(raw)?;
    f.sync_all()?;
    fs::File::open(root)?.sync_all()?;
    Ok(Bound {
        path: p,
        sha256: storage::sha(raw),
    })
}
pub fn role(path: &str, sha: &str) -> Result<Value> {
    let image = fixed(path, sha);
    let dir = image.path.parent().context("role parent")?;
    let artifact = process::bind_file(&dir.join("artifact-proof.json"), 16 << 20)?;
    let seal = process::bind_file(&dir.join("deployment-seal-receipt.json"), 16 << 20)?;
    let v = storage::json(&seal)?;
    ensure!(
        v["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && v["destination"] == dir.to_string_lossy().as_ref(),
        "actual role normal seal"
    );
    for (b, name) in [
        (
            &image,
            image
                .path
                .file_name()
                .context("image leaf")?
                .to_str()
                .context("image UTF8")?,
        ),
        (&artifact, "artifact-proof.json"),
    ] {
        ensure!(
            v["members"]
                .as_array()
                .context("seal members")?
                .iter()
                .filter(|x| x["name"] == name && x["sha256"] == b.sha256)
                .count()
                == 1,
            "actual role sealed member"
        );
    }
    Ok(json!({"image":image,"artifact":artifact,"normal_seal":seal}))
}
pub fn seal(
    r: &mut process::Runner<'_>,
    label: &str,
    dest: &Path,
    members: &[(&str, Bound)],
) -> Result<Value> {
    ensure!(
        dest.parent() == Some(Path::new("/usr/local/lib/jetstreamer")) && !dest.try_exists()?,
        "fresh normal deployment"
    );
    let plan = storage::save(
        r.root,
        &format!("{label}-seal-plan.json"),
        &json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":dest,"members":members.iter().map(|(k,b)|json!({"name":k,"source":b.path,"sha256":b.sha256,"mode":0o444})).collect::<Vec<_>>()}),
    )?;
    r.seal(label, &plan)?;
    let receipt = process::bind_file(&dest.join("deployment-seal-receipt.json"), 16 << 20)?;
    let v = storage::json(&receipt)?;
    ensure!(
        v["destination"] == dest.to_string_lossy().as_ref(),
        "normal destination"
    );
    let mut m = json!({});
    for (name, b) in members {
        let published = Bound {
            path: dest.join(name),
            sha256: b.sha256.clone(),
        };
        ensure!(
            storage::bytes(&published, 32 << 20, true)? == storage::bytes(b, 32 << 20, false)?,
            "normal exact original copy"
        );
        m[*name] = json!(published);
    }
    Ok(json!({"members":m,"normal_seal":receipt}))
}
pub fn child(
    r: &mut process::Runner<'_>,
    label: &str,
    image: &Bound,
    route: &str,
    spec: &Bound,
    seconds: u64,
) -> Result<Value> {
    let mut c = Command::new("/usr/bin/systemd-run");
    c.args([
        "--wait",
        "--pipe",
        "--service-type=exec",
        "--unit",
        &format!("horizon-positive185-upstream-{}-{label}", r.iid),
    ]);
    for p in [
        "User=root",
        "Group=root",
        "Restart=no",
        "UMask=0077",
        "MemoryAccounting=yes",
        "MemoryHigh=2G",
        "MemoryMax=2G",
        "MemorySwapMax=0",
        "CPUQuota=100%",
        "TasksMax=512",
        "TimeoutStopSec=2",
        "KillMode=control-group",
        "LimitNOFILE=1048576:1048576",
        "NoNewPrivileges=yes",
        "PrivateNetwork=yes",
        "AppArmorProfile=horizon-witness-test-deny199-20261107-v1",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
        "AmbientCapabilities=CAP_DAC_OVERRIDE CAP_SYS_PTRACE",
    ] {
        c.arg(format!("--property={p}"));
    }
    c.arg(format!("--property=RuntimeMaxSec={seconds}"));
    c.arg(format!("--property=ReadWritePaths={REGISTRY}"));
    c.arg(&image.path).arg(route).arg(&spec.path).args([
        "--spec-sha256",
        &spec.sha256,
        "--self-sha256",
        &image.sha256,
    ]);
    let v = r.run(label, c, Duration::from_secs(seconds + 3))?;
    process::stdout_json(&v)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Assemble {
    schema: String,
    pub complete_tuple: Bound,
    pub phase_ledger: Bound,
    pub reviewed_phase_ledger: Bound,
    pub protected_exporter_plan: Bound,
    pub accepted_local_integrity_basis: Bound,
    pub original_restore_receipt: Bound,
    pub status_readback: Bound,
    pub generation: String,
    pub useful_runtime_seconds: u64,
    pub reader_source_spec: Bound,
    pub reader_external_booking: Bound,
}
pub fn generation(s: &str) -> Result<()> {
    ensure!(
        s.starts_with("positive-")
            && s.len() < 64
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
        "distinct positive namespace"
    );
    Ok(())
}
pub fn assemble(spec: &Bound, root: &Path) -> Result<Bound> {
    let s: Assemble = serde_json::from_value(storage::json(spec)?)?;
    ensure!(
        s.schema == "horizon-positive185-upstream-assembly-request-v1",
        "assembly scope"
    );
    generation(&s.generation)?;
    ensure!(
        (600..=14400).contains(&s.useful_runtime_seconds),
        "finite bounded probe only"
    );
    let status = storage::json(&s.status_readback)?;
    ensure!(
        status["epoch"] == 185
            && status["authenticated_readback"] == true
            && status["owner_evidence"]["current_operator"] == "/root"
            && status["after_status"]["phase"] == "verification",
        "actual Root status"
    );
    let estimate = n(
        &status["estimate_parts_millis"],
        "full_epoch_replay_using_same_century_peer_rate_with25percent_contingency_millis",
    )?;
    let package =
        Path::new("/usr/local/lib/jetstreamer/horizon-epoch185-cohesive-capped-inputs-20261105-v3");
    let request = json!({"schema":"epoch185-positive-metadata-plan-request-v1","complete_tuple":s.complete_tuple,"phase_ledger":s.phase_ledger,"reviewed_phase_ledger":s.reviewed_phase_ledger,"protected_exporter_plan":s.protected_exporter_plan,
 "accounting_role":role("/usr/local/lib/jetstreamer/horizon-epoch163-first-output128-shared-helper-tools-20261106-v3/jetstreamer-r2","d54025dd48a0748deeb4fcc3845e48564aa7619e95485061d85e30e31dbc8a43")?,"native185_capture_role":role(NATIVE,NATIVE_SHA)?,"full_reader_role":role(HELPER,HELPER_SHA)?,
 "input_package_seal":process::bind_file(&package.join("deployment-seal-receipt.json"),16<<20)?,"accepted_local_integrity_basis":s.accepted_local_integrity_basis,"original_restore_receipt":s.original_restore_receipt,"status_readback":s.status_readback,"generation":s.generation,
 "profile":{"purpose":"bounded_native_probe","actor_memory_bytes":48u64<<30,"setup_deadline_seconds":600,"useful_runtime_seconds":s.useful_runtime_seconds,"estimated_useful_work_millis":estimate}});
    storage::save(root, "positive-planner-request.json", &request)
}

pub fn verify_closed_pool(r: &mut process::Runner<'_>, b: &Bound) -> Result<Value> {
    let closure = storage::json(b)?;
    ensure!(
        closure["all_original_QA_actors_terminal_and_drained"] == true
            && closure["normal_pool_released_bytes"] == 0,
        "actual current QA drain closure retaining normal6GiB"
    );
    let rows = closure["actual_terminal_unit_census"]
        .as_array()
        .context("actual original QA census required")?;
    ensure!(
        !rows.is_empty() && rows.len() < 1024,
        "bounded original QA unit census"
    );
    let mut observed = Vec::new();
    for row in rows {
        let unit = text(row, "Id")?;
        ensure!(unit_name(unit), "QA original native unit");
        let n = r.native(unit)?;
        ensure!(
            n["MainPID"] == "0" && n["ControlPID"] == "0" && n["Job"] == "",
            "required prior QA actor still occupies normal pool"
        );
        observed.push(n);
    }
    Ok(
        json!({"original_QA_closure":b,"actual_revalidated_original_QA_unit_states":observed,"all_required_original_QA_actors_terminal_and_drained":true,"normal_pool_bytes_retained":6u64<<30,"Root_must_coordinate_no_new_competing_pool_actor_during_this_one_finite_workflow":true}),
    )
}

fn root_caps() -> Result<Value> {
    ensure!(unsafe { libc::geteuid() } == 0, "Root only");
    let raw = fs::read_to_string("/proc/self/status")?;
    let caps = u64::from_str_radix(
        raw.lines()
            .find(|x| x.starts_with("CapEff:"))
            .context("effective caps")?
            .split_whitespace()
            .nth(1)
            .context("cap mask")?,
        16,
    )?;
    ensure!(
        caps & ((1 << 0) | (1 << 1) | (1 << 19)) == ((1 << 0) | (1 << 1) | (1 << 19)),
        "Root CHOWN,DAC_OVERRIDE,SYS_PTRACE"
    );
    let mut limit = unsafe { std::mem::zeroed::<libc::rlimit>() };
    ensure!(
        unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0
            && limit.rlim_cur >= 1000000,
        "Root million FD capability"
    );
    Ok(
        json!({"actual_root_uid":0,"effective_CHOWN_DAC_OVERRIDE_SYS_PTRACE":true,"actual_fd_soft_limit":limit.rlim_cur,"original_process_id":std::process::id(),"original_cgroup":fs::read_to_string("/proc/self/cgroup")?,"original_invocation_id":env::var("INVOCATION_ID")?}),
    )
}
fn kernel_check(mode: &str, spec: &Bound) -> Result<()> {
    let v = storage::json(spec)?;
    let root = PathBuf::from(text(&v, "sol_run_root")?);
    let control = PathBuf::from(text(&v, "sol_control_root")?);
    if mode == "kernel-root-check" {
        println!("{}", root_caps()?);
        return Ok(());
    }
    ensure!(
        mode == "kernel-sol-check"
            && unsafe { libc::geteuid() } == 1001
            && unsafe { libc::getegid() } == 1003,
        "actual sol/horizon actor identity"
    );
    for p in [&root, &control] {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            p.canonicalize()? == *p
                && m.is_dir()
                && m.uid() == 1001
                && m.gid() == 1003
                && m.mode() & 0o777 == 0o700,
            "actual private sol work/control"
        );
        ensure!(
            fs::read_dir(p)?.next().is_none(),
            "metadata control must not contain real producer data"
        );
        let q = p.join("kernel-control-only.json");
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&q)?;
        f.write_all(b"{\"metadata_control_only\":true}\n")?;
        f.sync_all()?;
        drop(f);
        fs::remove_file(&q)?;
    }
    let raw = fs::read_to_string("/proc/self/status")?;
    let bits = u64::from_str_radix(
        raw.lines()
            .find(|x| x.starts_with("CapEff:"))
            .context("sol caps")?
            .split_whitespace()
            .nth(1)
            .context("sol cap value")?,
        16,
    )?;
    ensure!(
        bits == 0 && raw.lines().any(|x| x == "NoNewPrivs:\t1"),
        "unprivileged no-new-privileges actor"
    );
    println!(
        "{}",
        json!({"actual_sol_uid":1001,"actual_horizon_gid":1003,"effective_capabilities":0,"NoNewPrivileges":true,"actual_private_work_control_writes_and_retirement_passed":true,"no_inputs_or_replay":true,"original_cgroup":fs::read_to_string("/proc/self/cgroup")?,"original_invocation_id":env::var("INVOCATION_ID")?})
    );
    Ok(())
}
fn run() -> Result<()> {
    let a = env::args().collect::<Vec<_>>();
    ensure!(
        a.len() == 7 && a[3] == "--request-sha256" && a[5] == "--self-sha256",
        "exact finite operation CLI"
    );
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader overrides"
    );
    let own = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: a[6].clone(),
    };
    ensure!(
        own.path.parent().and_then(Path::parent) == Some(Path::new("/usr/local/lib/jetstreamer")),
        "normally sealed upstream image namespace"
    );
    role(
        own.path.to_str().context("upstream image path UTF8")?,
        &own.sha256,
    )?;
    storage::bytes(&own, 128 << 20, true)?;
    let request = Bound {
        path: a[2].clone().into(),
        sha256: a[4].clone(),
    };
    if a[1] == "reader-lifecycle-harmless-fail" {
        return persistent_reader::failed_retirement::harmless_fail(&request, &own);
    }
    if a[1] == "reader-lifecycle-harmless-exec" {
        return persistent_reader::harmless_exec(&request, &own);
    }
    if ["kernel-root-check", "kernel-sol-check"].contains(&a[1].as_str()) {
        return kernel_check(&a[1], &request);
    }
    root_caps()?;
    let v = storage::json(&request)?;
    let root = PathBuf::from(text(&v, "operation_root")?);
    ensure!(
        root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && root
                .file_name()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.starts_with("epoch185-positive-upstream-")),
        "exact operation root namespace"
    );
    private(&root, true)?;
    let iid = text(&v, "generation")?;
    generation(iid)?;
    let mut r = process::Runner {
        root: &root,
        self_image: &own,
        iid,
        deadline: Instant::now() + Duration::from_secs(900),
        pool_deadline: Instant::now() + Duration::from_secs(900),
        sequence: 0,
    };
    match a[1].as_str() {
        "qualify-current-reader-start-phase" => reader_phase::qualify(&mut r),
        "read-current-original-between-guard-fires" => reader_phase::execute(&v, &mut r),
        "assemble-positive185" => {
            let sb = binding(&v["assembly"])?;
            let b = assemble(&sb, &root)?;
            let mut c = Command::new(PLANNER);
            c.arg("plan-positive185").arg(&b.path).args([
                "--request-sha256",
                &b.sha256,
                "--self-sha256",
                PLANNER_SHA,
            ]);
            let original = r.run("actual-qualified-planner", c, Duration::from_secs(30))?;
            let result = process::stdout_json(&original)?;
            storage::save(&root, "qualified-planner-actual-output.json", &result)?;
            println!(
                "{}",
                json!({"planner_request":b,"actual_planner_result":result,"no_admission":true})
            );
            Ok(())
        }
        "qualify-positive185-reader-lifecycle" => persistent_reader::qualify(&mut r),
        "qualify-positive185-failed-reader-retirement" => {
            persistent_reader::failed_retirement::qualify(&mut r)
        }
        "retire-positive185-failed-reader" => {
            persistent_reader::failed_retirement::execute(&v, &mut r)
        }
        "qualify-positive185-profile" => activation::qualify(&v, &mut r),
        "start-positive185-original" => activation::start(&v, &mut r),
        "continue-positive185-original" => follow_on::continue_original(&v, &mut r),
        _ => anyhow::bail!("unsupported finite operation"),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("positive185 upstream original: {e:#}");
        std::process::exit(1)
    }
}

pub fn require_qualified_fleet_helper() -> Result<()> {
    let r = role(FLEET_HELPER, FLEET_HELPER_SHA)?;
    let proof = storage::json(&binding(&r["artifact"])?)?;
    ensure!(
        proof["all_required_tests_passed"] == true
            && proof["genuine_current_complete_outer_adapter_passed"] == true
            && proof["production_artifact"]["sha256"] == FLEET_HELPER_SHA
            && proof["replay_launch_authorized"] == false,
        "exact fleet helper27 genuine final qualification required before original admission"
    );
    storage::bytes(&fixed(FLEET_HELPER, FLEET_HELPER_SHA), 128 << 20, true)?;
    Ok(())
}
