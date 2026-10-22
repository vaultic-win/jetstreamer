//! One exact144 delivery, serialized with the unchanged global uploader. This
//! is not another progressive coordinator and never retires local archives.
#[allow(dead_code)]
#[path = "../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
#[path = "publication144_gate_identity.rs"]
mod gate_identity;
#[path = "publication144_delivery_track.rs"]
mod tracking;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const PUB: &str = "horizon-publish-144-v4-20261022-v1.service";
const UNIT: &str = "horizon-upload-144-v4-20261022-v1.service";
const ORIGIN: &str = "/var/lib/jetstreamer/horizon-publication144-owner-20261022-v1/launch.json";
const PUBLIC: &str = "/home/sol/horizon";
const R2: &str = "/home/sol/.jetstreamer-private/r2-receipts";
const STATUS: &str = "/home/sol/.jetstreamer-private/r2-status-receipts";
const LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const CLIENT: &str =
    "/usr/local/lib/jetstreamer/horizon-publication144-progress-client-20261022-v1/jetstreamer-r2";
const CLIENT_SHA: &str = "c91b5ab379e876c6426be82adb381644927e7b5a199e3709dc9ce59dc2a6d96a";
const PUBLISHER_SHA: &str = "4274f83c6d84a2bc2014b30122a38406b6498045f543ba170598baa8369a7efa";
const TRACKER_SHA: &str = "b85dc978377f20036ecd40cb4495729f27c2e8dc906c3cb2576463d9adf1dc75";
const DIGEST: &str = "153d3e5e5b7cbdc31bb4229315786000b84442a75b3b83cf4a50184b20b84a33";
const LENGTH: u64 = 109177480876;
const FULL: &str = "41c03e493daa309ab7cffd9760b4e6cfe2195b3af0bb13a17f19508eb929d6e7";
const PLUGIN: &str = "73e7535b9cedc7e565a92735ca6e07c7efb8e66755a6d5272ed16649b4d8cee9";
const RUNNER: &str = "7dfe0fdabbee8e5f79b131c2b7cece49dbebe489168fe195a9086ab25f0b8810";
const BUCKET: &str = "solana-archive-with-accounts-data";
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    publisher_plan: Bound,
    tracker_plan: Bound,
    client: Bound,
    endpoint_sha256: String,
    shared_lock_device: u64,
    shared_lock_inode: u64,
    output_directory: PathBuf,
    r2_create_missing_pair_authorized: bool,
    r2_overwrite_authorized: bool,
    local_retirement_authorized: bool,
}
fn read(b: &Bound, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        4 << 20,
        immutable,
    )?)?)
}
fn stable(path: &Path, uid: u32) -> Result<(Vec<u8>, Value)> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 4 << 20,
        "unsafe delivery input:{}",
        path.display()
    );
    let mut b = Vec::new();
    (&mut f).take((4 << 20) + 1).read_to_end(&mut b)?;
    ensure!(
        b.len() as u64 == m.len()
            && evidence::identity(&m) == evidence::identity(&f.metadata()?)
            && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
        "delivery input changed"
    );
    Ok((b, json!({"path":path,"identity":evidence::identity(&m)})))
}
fn shape(p: &Plan, v: &Value, t: &Value) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-exact144-single-delivery-plan-v1"
            && p.r2_create_missing_pair_authorized
            && !p.r2_overwrite_authorized
            && !p.local_retirement_authorized
            && p.client.path == Path::new(CLIENT)
            && p.client.sha256 == CLIENT_SHA
            && evidence::is_sha(&p.endpoint_sha256)
            && p.shared_lock_device > 0
            && p.shared_lock_inode > 0
            && p.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && p.output_directory.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-epoch144-delivery-")),
        "foreign144 delivery scope or authority"
    );
    ensure!(
        v["schema"] == "jetstreamer-exact144-v4-publication-plan-v2"
            && v["artifact_publication_authorized"] == true
            && v["runtime_registry_promotion_authorized"] == false
            && v["remote_mutations"] == false
            && v["r2_mutations"] == false
            && v["refreshed_capacity"]["schema"]
                == "jetstreamer-exact144-delivery-capacity-refresh-v3"
            && v["evidence"]["sha256"]
                == "5196699c86959e9704269ae7dbfc1c9432ebc82eb40f305dca6dd56ded891f64"
            && t["schema"] == "jetstreamer-exact144-publication-owner-plan-v1"
            && t["publisher_plan"] == serde_json::to_value(&p.publisher_plan)?,
        "delivery cannot borrow another publisher or tracker plan"
    );
    let receipts = Path::new(
        v["receipt_directory"]
            .as_str()
            .context("publication receipt root")?,
    );
    ensure!(
        receipts.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && receipts.file_name().is_some_and(|n| n
                .to_string_lossy()
                .starts_with("horizon-epoch144-publication-")),
        "foreign private gate directory"
    );
    Ok(())
}
fn configuration(p: &Plan) -> Result<Value> {
    let v = read(&p.publisher_plan, true)?;
    let t = read(&p.tracker_plan, true)?;
    shape(p, &v, &t)?;
    evidence::bound_file(&p.client.path, &p.client.sha256, 128 << 20, true)?;
    let cap: Bound = serde_json::from_value(t["capability"].clone())?;
    let c = read(&cap, false)?;
    ensure!(
        c["schema"] == "jetstreamer-exact144-publication-capability-v1"
            && c["publisher_sha256"] == PUBLISHER_SHA
            && c["filesystem_transaction_passed"] == true
            && c["outside_write_denied"] == true
            && c["effective_uid"] == 1001
            && c["effective_gid"] == 1003
            && c["artifact_publication_authorized"] == false
            && c["r2_mutations"] == false,
        "144 capability differs"
    );
    let e: Bound = serde_json::from_value(v["evidence"].clone())?;
    let e = read(&e, false)?;
    ensure!(
        e["archive_sha256"] == DIGEST
            && e["archive_bytes"] == LENGTH
            && e["independent_full_and_plugin_receipts_validated"] == true,
        "144 independent private scan evidence differs"
    );
    let endpoint = std::env::var("HORIZON_S3_ENDPOINT")?;
    ensure!(
        evidence::sha(endpoint.as_bytes()) == p.endpoint_sha256
            && endpoint
                .trim_end_matches('/')
                .ends_with(&format!("/{BUCKET}")),
        "144 endpoint differs"
    );
    for key in ["HORIZON_ACCESS_KEY_ID", "HORIZON_SECRET_ACCESS_KEY"] {
        ensure!(
            std::env::var(key).is_ok_and(|v| !v.is_empty()),
            "144 credential missing"
        );
    }
    let m = fs::symlink_metadata(&p.output_directory)?;
    ensure!(
        p.output_directory.canonicalize()? == p.output_directory
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o700,
        "144 delivery receipt directory is not root-private"
    );
    let lock = fs::symlink_metadata(LOCK)?;
    ensure!(
        lock.is_file()
            && lock.uid() == 1001
            && lock.nlink() == 1
            && lock.mode() & 0o777 == 0o600
            && lock.dev() == p.shared_lock_device
            && lock.ino() == p.shared_lock_inode,
        "144 shared lock no longer matches the global uploader binding"
    );
    Ok(v)
}
fn fields(unit: &str) -> Result<Value> {
    let o=Command::new("/usr/bin/systemctl").args(["show",unit,"--property=Id,LoadState,InvocationID,MainPID,NRestarts,Result,ExecMainStatus,ActiveState,SubState,ExecStart,Restart,Type,RemainAfterExit"]).output()?;
    ensure!(
        o.status.success() && o.stdout.len() < 32768,
        "144 service identity unreadable"
    );
    let text = std::str::from_utf8(&o.stdout)?;
    Ok(serde_json::to_value(
        text.lines()
            .map(|s| s.split_once('=').context("144 service property"))
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?,
    )?)
}
fn publication(p: &Plan, r: &Value, full: &[u8], plugin: &[u8]) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-exact144-v4-publication-receipt-v1"
            && r["epoch"] == 144
            && r["context"]["plan"] == serde_json::to_value(&p.publisher_plan)?
            && r["context"]["publisher_sha256"] == PUBLISHER_SHA
            && r["committed"] == true
            && r["archive_sha256"] == DIGEST
            && r["archive_bytes"] == LENGTH
            && r["archive_path"] == format!("{PUBLIC}/epoch-144.jet")
            && r["checksum_path"] == format!("{PUBLIC}/epoch-144.jet.sha256")
            && r["original_assembly_preserved"] == true
            && r["copy_rehashed_independently"] == true
            && r["full_verifier_sha256"] == FULL
            && r["plugin_pipeline_sha256"] == PLUGIN
            && r["private_runner_sha256"] == RUNNER
            && r["retirement_authorized"] == false
            && r["runtime_registry_promoted"] == false
            && r["remote_mutations"] == false
            && r["r2_mutations"] == false,
        "144 canonical publication is not independently qualified"
    );
    ensure!(
        full == format!("{DIGEST} {FULL} {RUNNER}\n").as_bytes()
            && plugin == format!("{DIGEST} {PLUGIN} {RUNNER}\n").as_bytes(),
        "144 full/plugin gates differ"
    );
    Ok(())
}
fn gates(p: &Plan, v: &Value) -> Result<Value> {
    let (b, _) = stable(Path::new(ORIGIN), 0)?;
    let launch: Value = serde_json::from_slice(&b)?;
    ensure!(
        launch["schema"] == "jetstreamer-exact144-publication-launch-v1"
            && launch["epoch"] == 144
            && launch["launched"] == true
            && launch["publisher_plan"] == serde_json::to_value(&p.publisher_plan)?
            && launch["tracker_plan"] == serde_json::to_value(&p.tracker_plan)?
            && launch["publisher_sha256"] == PUBLISHER_SHA
            && launch["tracker_sha256"] == TRACKER_SHA
            && launch["claim"]["unit"] == PUB,
        "144 captured publisher lineage differs"
    );
    let owner = fields(PUB)?;
    ensure!(
        owner["Id"] == PUB
            && owner["InvocationID"] == launch["claim"]["invocation_id"]
            && owner["NRestarts"] == "0"
            && owner["MainPID"] == "0"
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "exited"
            && owner["Result"] == "success"
            && owner["ExecMainStatus"] == "0"
            && owner["Restart"] == "no",
        "144 publisher is not exact clean terminal owner"
    );
    let root = Path::new(v["receipt_directory"].as_str().unwrap());
    let (result, _) = stable(&root.join("publication.json"), 0)?;
    let (full, _) = stable(&root.join("full/epoch-144.full.ok"), 0)?;
    let (plugin, _) = stable(&root.join("plugin/epoch-144.plugin.ok"), 0)?;
    let result: Value = serde_json::from_slice(&result)?;
    publication(p, &result, &full, &plugin)?;
    let archive = fs::symlink_metadata(format!("{PUBLIC}/epoch-144.jet"))?;
    ensure!(
        archive.is_file()
            && archive.uid() == 1001
            && archive.gid() == 1003
            && archive.nlink() == 1
            && archive.mode() & 0o7777 == 0o440
            && archive.len() == LENGTH,
        "144 canonical archive identity differs"
    );
    let (sidecar, _) = stable(&Path::new(PUBLIC).join("epoch-144.jet.sha256"), 1001)?;
    ensure!(
        sidecar == format!("{DIGEST}  epoch-144.jet\n").as_bytes(),
        "144 canonical sidecar differs"
    );
    Ok(
        json!({"publisher":owner,"origin_sha256":evidence::sha(&b),"publication":result,"archive_identity":evidence::identity(&archive),
        "full_gate_sha256":evidence::sha(&full),"plugin_gate_sha256":evidence::sha(&plugin)}),
    )
}
struct MutationLock(File);
impl MutationLock {
    fn try_acquire(path: &Path, device: u64, inode: u64) -> Result<Option<Self>> {
        Self::try_owned(path, 1001, Some((device, inode)))
    }
    fn try_owned(path: &Path, uid: u32, expected: Option<(u64, u64)>) -> Result<Option<Self>> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let m = f.metadata()?;
        ensure!(
            m.is_file()
                && m.uid() == uid
                && m.nlink() == 1
                && m.mode() & 0o777 == 0o600
                && expected.is_none_or(|(d, i)| m.dev() == d && m.ino() == i),
            "shared144 mutation lock identity differs"
        );
        let locked = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        if !locked {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.kind() == std::io::ErrorKind::WouldBlock,
                "shared144 lock acquisition failed:{error}"
            );
        }
        ensure!(
            evidence::identity(&m) == evidence::identity(&f.metadata()?)
                && evidence::identity(&m) == evidence::identity(&fs::symlink_metadata(path)?),
            "shared mutation lock replaced"
        );
        Ok(locked.then_some(Self(f)))
    }
}
impl Drop for MutationLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
fn sync_args() -> Vec<String> {
    [
        "sync",
        PUBLIC,
        "--epochs",
        "144-144",
        "--receipt-directory",
        R2,
        "--legacy-part-size-mib",
        "5",
        "--concurrency",
        "4",
    ]
    .map(str::to_owned)
    .into()
}
fn child_identity() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Caps {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let gid = 1003;
    let header = Header {
        version: 0x20080522,
        pid: 0,
    };
    let empty = [Caps::default(); 2];
    let mut actual = [Caps::default(); 2];
    unsafe {
        if libc::setgroups(1, &gid) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(1001, 1001, 1001) != 0
            || libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            ) != 0
            || libc::syscall(libc::SYS_capset, &header, empty.as_ptr()) != 0
            || libc::syscall(libc::SYS_capget, &header, actual.as_mut_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if libc::geteuid() != 1001
            || libc::getuid() != 1001
            || libc::getegid() != gid
            || libc::getgid() != gid
            || actual
                .iter()
                .any(|c| c.effective != 0 || c.permitted != 0 || c.inheritable != 0)
        {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
    }
    Ok(())
}
fn status_args() -> Vec<String> {
    [
        "status-delete",
        PUBLIC,
        "--epochs",
        "144-144",
        "--receipt-directory",
        STATUS,
        "--archive-receipt-directory",
        R2,
        "--latest-status-publication-receipt",
    ]
    .map(str::to_owned)
    .into()
}
fn archive_child(args: &[String]) -> Result<bool> {
    if args == sync_args() {
        return Ok(true);
    }
    ensure!(
        args == status_args(),
        "144 client child may execute only exact archive sync or owned-status cleanup"
    );
    Ok(false)
}
fn child(
    p: &Plan,
    args: &[String],
    owner: &Value,
    plan: &Bound,
) -> Result<std::process::ExitStatus> {
    let mut c = Command::new(&p.client.path);
    c.args(args);
    let archive = archive_child(args)?;
    if archive {
        unsafe {
            c.pre_exec(child_identity);
        }
    }
    // Metadata publications are root-owned0600, even beneath the UID1001
    //directory. Only the fixed completion-only status command keeps root;
    //the payload upload always permanently drops IDs and capabilities.
    let spawned_millis = now()?;
    let child = c.spawn()?;
    // Record the actual spawned PID, not the worker's PID or a guessed future
    // process. Consumers must still prove current command, cgroup, executable
    // and start identity: this historical receipt alone is never liveness.
    // Always wait/reap even if receipt persistence fails after spawn.
    let recorded = evidence::write_receipt(
        &p.output_directory.join(if archive {
            "upload-child-launch.json"
        } else {
            "status-cleanup-child-launch.json"
        }),
        &json!({"schema":"horizon-exact144-delivery-child-launch-v1",
            "owner":owner,"plan":plan,"client":p.client,"arguments":args,
            "child_pid":child.id(),"spawned_millis":spawned_millis,
            "archive_sync":archive,"current_liveness_proven":false,
            "archive_ready":false,"local_retirement_authorized":false}),
    );
    reap_child(child, recorded)
}
fn reap_child(
    mut child: std::process::Child,
    recorded: Result<()>,
) -> Result<std::process::ExitStatus> {
    let status = child.wait();
    recorded?;
    Ok(status?)
}
fn ready(r: &Value) -> Result<()> {
    ensure!(
        r["schema"] == "jetstreamer-horizon-r2-receipt-v1"
            && r["bucket"] == BUCKET
            && r["epoch"] == 144
            && r["archive_key"] == "epoch-144.jet"
            && r["checksum_key"] == "epoch-144.jet.sha256"
            && r["archive_length"] == LENGTH
            && r["archive_sha256"] == DIGEST
            && r["remote_sha256_readback"] == true
            && r["archive_etag"].as_str().is_some_and(|s| !s.is_empty())
            && r["verified_unix_seconds"].as_u64().is_some_and(|n| n > 0),
        "144 uploader did not commit matching authenticated readback evidence"
    );
    Ok(())
}
fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_millis()
        .try_into()?)
}
fn run(p: &Plan, pb: &Bound, self_sha: &str, mode: &str) -> Result<()> {
    if matches!(mode, "--capture" | "--terminal") {
        return tracking::run(p, pb, self_sha, mode == "--terminal");
    }
    let v = configuration(p)?;
    if mode == "--check-staged" {
        ensure!(
            fs::read_dir(&p.output_directory)?.next().is_none(),
            "144 delivery output already occupied"
        );
        println!(
            "exact144 delivery configuration qualified; no owner query, lock wait, archive hash or remote access"
        );
        return Ok(());
    }
    let before = gates(p, &v)?;
    if mode == "--check-only" {
        println!(
            "exact144 terminal/full/plugin/canonical gates pass; no lock wait or remote access"
        );
        return Ok(());
    }
    let owner = fields(UNIT)?;
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        owner["Id"] == UNIT
            && owner["InvocationID"] == iid
            && owner["MainPID"]
                .as_str()
                .and_then(|v| v.parse::<u32>().ok())
                == Some(std::process::id())
            && owner["NRestarts"] == "0"
            && owner["Restart"] == "no"
            && owner["Type"] == "oneshot"
            && owner["RemainAfterExit"] == "yes"
            && owner["ActiveState"] == "activating"
            && owner["SubState"] == "start",
        "144 delivery requires exact nonrestarting oneshot"
    );
    evidence::write_receipt(
        &p.output_directory.join("intent.json"),
        &json!({"schema":"horizon-exact144-delivery-intent-v1","plan":pb,"self_sha256":self_sha,"owner":owner,"publisher":before,
        "shared_mutation_lock":LOCK,"lock_wait_started_millis":now()?,"lock_acquisition_mode":"nonblocking-no-queue","another_progressive_coordinator":false,"local_retirement_authorized":false}),
    )?;
    // Refuse contention instead of creating an unmodeled queue countdown.
    // The existing owner remains untouched and no client has been spawned.
    let Some(_lock) =
        MutationLock::try_acquire(Path::new(LOCK), p.shared_lock_device, p.shared_lock_inode)?
    else {
        evidence::write_receipt(
            &p.output_directory.join("lock-declined.json"),
            &json!({"schema":"horizon-exact144-delivery-lock-declined-v1","owner":owner,"plan":pb,"self_sha256":self_sha,
                "shared_mutation_lock":LOCK,"lock_device":p.shared_lock_device,"lock_inode":p.shared_lock_inode,
                "declined_at_millis":now()?,"delivery_launched":false,"client_started":false,"queued":false,
                "archive_or_status_mutations":false,"automatic_retry_authorized":false}),
        )?;
        anyhow::bail!(
            "144 delivery not launched: exact shared upload lock busy; preserve evidence and admit a fresh attempt after authenticated release"
        );
    };
    let lock_meta = _lock.0.metadata()?;
    ensure!(
        lock_meta.dev() == p.shared_lock_device && lock_meta.ino() == p.shared_lock_inode,
        "144 acquired a different shared-lock inode"
    );
    let locked = gates(p, &v)?;
    ensure!(
        gate_identity::same_gate(&before, &locked),
        "144 gate or canonical identity changed while queued"
    );
    evidence::write_receipt(
        &p.output_directory.join("lock-acquired.json"),
        &json!({"schema":"horizon-exact144-delivery-lock-v1","owner":owner,"plan":pb,"acquired_millis":now()?,"shared_mutation_lock":LOCK,"gates":locked}),
    )?;
    // Capture only after exclusive ownership is durable, before any client.
    tracking::run(p, pb, self_sha, false)?;
    let status = child(p, &sync_args(), &owner, pb)?;
    evidence::write_receipt(
        &p.output_directory.join("upload-child.json"),
        &json!({"client":p.client,"arguments":sync_args(),"exit_code":status.code(),"success":status.success()}),
    )?;
    ensure!(
        status.success(),
        "144 exact uploader failed; preserve its resumable receipt/state"
    );
    let (b, _) = stable(&Path::new(R2).join("epoch-144.r2.json"), 1001)?;
    let receipt: Value = serde_json::from_slice(&b)?;
    ready(&receipt)?;
    ensure!(
        gate_identity::same_gate(&before, &gates(p, &v)?),
        "144 source publication changed during upload"
    );
    evidence::write_receipt(
        &p.output_directory.join("archive-complete.json"),
        &json!({"schema":"horizon-exact144-delivery-archive-complete-v1","owner":owner,"plan":pb,"r2_receipt_sha256":evidence::sha(&b),"r2_receipt":receipt,"local_retirement_performed":false}),
    )?;
    let mut known = false;
    for (index, entry) in fs::read_dir(STATUS)?.enumerate() {
        ensure!(index < 100000, "status receipt census exceeds bound");
        let entry = entry?;
        let n = entry.file_name();
        let n = n.to_string_lossy();
        if n.starts_with("epoch-144.status-") && n.ends_with(".json") {
            known = true;
            break;
        }
    }
    if known {
        let args = status_args();
        let status = child(p, &args, &owner, pb)?;
        evidence::write_receipt(
            &p.output_directory.join("status-cleanup-child.json"),
            &json!({"client":p.client,"exit_code":status.code(),"success":status.success()}),
        )?;
        ensure!(
            status.success(),
            "144 archive is ready but exact owned-status cleanup needs recovery"
        );
    }
    evidence::write_receipt(
        &p.output_directory.join("completion.json"),
        &json!({"schema":"horizon-exact144-single-delivery-completion-v1","owner":owner,"plan":pb,"archive_ready":true,"owned_status_cleanup_attempted":known,"local_retirement_performed":false,"r2_overwrite_performed":false}),
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        a.len() == 7
            && a[2] == "--plan-sha256"
            && a[4] == "--self-sha256"
            && matches!(
                a[6].as_str(),
                "--check-staged" | "--check-only" | "--run" | "--capture" | "--terminal"
            )
            && unsafe { libc::geteuid() } == 0,
        "usage: exact144-deliver PLAN --plan-sha256 SHA --self-sha256 SHA --check-staged|--check-only|--run|--capture|--terminal"
    );
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &a[5], 128 << 20, true)?;
    let pb = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read(&pb, true)?)?;
    run(&p, &pb, &a[5], &a[6])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn child_is_reaped_even_when_launch_receipt_fails() {
        let child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        assert!(reap_child(child, Err(anyhow::anyhow!("receipt failed"))).is_err());
        assert_eq!(
            unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        let child = Command::new("/usr/bin/false").spawn().unwrap();
        assert!(!reap_child(child, Ok(())).unwrap().success());
    }
    #[test]
    #[ignore = "root exact sandbox UID/GID/capability-drop proof; invokes only /usr/bin/id in disposable children"]
    fn child_identity_is_permanently_unprivileged_before_exec() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        for (arg, expected) in [("-u", "1001\n"), ("-g", "1003\n")] {
            let mut c = Command::new("/usr/bin/id");
            c.arg(arg);
            unsafe {
                c.pre_exec(child_identity);
            }
            let o = c.output().unwrap();
            assert!(o.status.success());
            assert_eq!(std::str::from_utf8(&o.stdout).unwrap(), expected);
        }
    }
    fn fixture() -> (Plan, Value, Value) {
        let b = Bound {
            path: "/sealed/publisher-plan.json".into(),
            sha256: "a".repeat(64),
        };
        let p = Plan {
            schema: "jetstreamer-exact144-single-delivery-plan-v1".into(),
            publisher_plan: b.clone(),
            tracker_plan: b,
            client: Bound {
                path: CLIENT.into(),
                sha256: CLIENT_SHA.into(),
            },
            endpoint_sha256: "b".repeat(64),
            shared_lock_device: 1,
            shared_lock_inode: 2,
            output_directory: "/var/lib/jetstreamer/horizon-epoch144-delivery-test".into(),
            r2_create_missing_pair_authorized: true,
            r2_overwrite_authorized: false,
            local_retirement_authorized: false,
        };
        let v = json!({"schema":"jetstreamer-exact144-v4-publication-plan-v2","artifact_publication_authorized":true,
            "runtime_registry_promotion_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "refreshed_capacity":{"schema":"jetstreamer-exact144-delivery-capacity-refresh-v3"},
            "evidence":{"sha256":"5196699c86959e9704269ae7dbfc1c9432ebc82eb40f305dca6dd56ded891f64"},
            "receipt_directory":"/var/lib/jetstreamer/horizon-epoch144-publication-test"});
        let t = json!({"schema":"jetstreamer-exact144-publication-owner-plan-v1","publisher_plan":p.publisher_plan});
        (p, v, t)
    }
    #[test]
    fn root_metadata_identity_cannot_be_used_for_archive_or_arbitrary_commands() {
        assert!(archive_child(&sync_args()).unwrap());
        assert!(!archive_child(&status_args()).unwrap());
        for args in [
            vec!["sync".into(), "/other".into()],
            vec![
                "status-delete".into(),
                PUBLIC.into(),
                "--epochs".into(),
                "160-160".into(),
            ],
        ] {
            assert!(archive_child(&args).is_err());
        }
    }
    #[test]
    fn single_delivery_cannot_expand_epoch_client_or_mutation_scope() {
        let (mut p, v, t) = fixture();
        shape(&p, &v, &t).unwrap();
        p.r2_overwrite_authorized = true;
        assert!(shape(&p, &v, &t).is_err());
        p.r2_overwrite_authorized = false;
        p.local_retirement_authorized = true;
        assert!(shape(&p, &v, &t).is_err());
        p.local_retirement_authorized = false;
        p.client.sha256 = "f".repeat(64);
        assert!(shape(&p, &v, &t).is_err());
        let (p, mut v, t) = fixture();
        v["r2_mutations"] = json!(true);
        assert!(shape(&p, &v, &t).is_err());
        let args = sync_args();
        assert_eq!(
            args,
            vec![
                "sync",
                PUBLIC,
                "--epochs",
                "144-144",
                "--receipt-directory",
                R2,
                "--legacy-part-size-mib",
                "5",
                "--concurrency",
                "4"
            ]
        );
        assert!(
            !args.iter().any(|a| a.contains("overwrite")
                || a.contains("delete")
                || a.contains("legacy-etag"))
        );
    }
    #[test]
    fn committed_copy_requires_both_exact_private_scan_gates() {
        let (p, _, _) = fixture();
        let r = json!({"schema":"jetstreamer-exact144-v4-publication-receipt-v1","epoch":144,
            "context":{"plan":p.publisher_plan,"publisher_sha256":PUBLISHER_SHA},"committed":true,
            "archive_sha256":DIGEST,"archive_bytes":LENGTH,"archive_path":format!("{PUBLIC}/epoch-144.jet"),"checksum_path":format!("{PUBLIC}/epoch-144.jet.sha256"),
            "original_assembly_preserved":true,"copy_rehashed_independently":true,"full_verifier_sha256":FULL,"plugin_pipeline_sha256":PLUGIN,"private_runner_sha256":RUNNER,
            "retirement_authorized":false,"runtime_registry_promoted":false,"remote_mutations":false,"r2_mutations":false});
        let full = format!("{DIGEST} {FULL} {RUNNER}\n");
        let plugin = format!("{DIGEST} {PLUGIN} {RUNNER}\n");
        publication(&p, &r, full.as_bytes(), plugin.as_bytes()).unwrap();
        assert!(publication(&p, &r, plugin.as_bytes(), full.as_bytes()).is_err());
        assert!(publication(&p, &r, b"", plugin.as_bytes()).is_err());
        for key in [
            "committed",
            "archive_sha256",
            "archive_bytes",
            "epoch",
            "original_assembly_preserved",
            "copy_rehashed_independently",
            "retirement_authorized",
            "r2_mutations",
        ] {
            let mut bad = r.clone();
            bad[key] = json!("foreign");
            assert!(
                publication(&p, &bad, full.as_bytes(), plugin.as_bytes()).is_err(),
                "{key}"
            );
        }
    }
    #[test]
    fn ready_requires_authenticated_whole_object_readback_and_matching_sidecar_keys() {
        let r = json!({"schema":"jetstreamer-horizon-r2-receipt-v1","bucket":BUCKET,"epoch":144,"archive_key":"epoch-144.jet","checksum_key":"epoch-144.jet.sha256",
            "archive_length":LENGTH,"archive_sha256":DIGEST,"remote_sha256_readback":true,"archive_etag":"exact","verified_unix_seconds":1});
        ready(&r).unwrap();
        for key in [
            "bucket",
            "epoch",
            "archive_key",
            "checksum_key",
            "archive_length",
            "archive_sha256",
            "remote_sha256_readback",
            "verified_unix_seconds",
        ] {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(ready(&bad).is_err(), "{key}");
        }
    }
    #[test]
    fn shared_lock_excludes_another_uploader_and_releases_on_drop() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let lock = MutationLock::try_owned(&path, unsafe { libc::geteuid() }, None)
            .unwrap()
            .unwrap();
        let began = std::time::Instant::now();
        assert!(
            MutationLock::try_owned(&path, unsafe { libc::geteuid() }, None)
                .unwrap()
                .is_none()
        );
        assert!(began.elapsed() < std::time::Duration::from_secs(1));
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            -1
        );
        drop(lock);
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        unsafe {
            libc::flock(other.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
