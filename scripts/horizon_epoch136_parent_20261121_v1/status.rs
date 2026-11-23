use super::*;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

#[cfg(any(not(feature = "v5n-semantic"), test))]
const BRIDGE_PKG: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch168-terminal-status-20261121-v1/publisher-v1";
#[cfg(any(not(feature = "v5n-semantic"), test))]
const BRIDGE_SEAL: &str = "76283826f8700557ffa359aa274ba991f7f644302476dde78e436c1011d4ed53";
#[cfg(any(not(feature = "v5n-semantic"), test))]
const NEXT_PKG: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/epoch166-post168-cadence-20261121-v1/publisher-v1";
#[cfg(any(not(feature = "v5n-semantic"), test))]
const NEXT_SEAL: &str = "923519c0d6f031594b9b5b34195af8b37772c25553c5cb7d195f8ec66e7c276c";
const PREFIX_PKG: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/prefix140-status-cadence-20261122-v1/cadence-tools";
const PREFIX_SEAL: &str = "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e";
static SELECTED: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();
#[cfg(any(not(feature = "v5n-semantic"), test))]
fn bridge_package(consumer: &Path) -> Result<(&'static str, &'static str)> {
    for (pkg, seal) in [
        (BRIDGE_PKG, BRIDGE_SEAL),
        (NEXT_PKG, NEXT_SEAL),
        (PREFIX_PKG, PREFIX_SEAL),
    ] {
        if Path::new(pkg).join("consume") == consumer {
            return Ok((pkg, seal));
        }
    }
    anyhow::bail!("unregistered status consumer {}", consumer.display())
}
pub fn take_lock(path: &Path, create: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o077 == 0
            && path.canonicalize()? == path,
        "unexpected lock"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "another owner holds {}",
        path.display()
    );
    Ok(file)
}
#[cfg(feature = "v5n-semantic")]
fn verify_bridge() -> Result<()> {
    let package = Path::new(PREFIX_PKG);
    let seal = pinned(&package.join("deployment-seal-receipt.json"), PREFIX_SEAL)?;
    ensure!(
        seal["destination"] == json!(package),
        "foreign original status transport"
    );
    for m in seal["members"]
        .as_array()
        .context("sealed transport members")?
    {
        let name = text(&m["name"])?;
        ensure!(
            Path::new(name).file_name().and_then(|n| n.to_str()) == Some(name)
                && bound(&package.join(name))?["sha256"] == m["sha256"],
            "changed status transport member"
        );
    }
    ensure!(
        SELECTED.get_or_init(|| PREFIX_PKG) == &PREFIX_PKG,
        "changed 136 transport package"
    );
    let owner = bridge("v5n-owner", &Value::Null)?;
    let ready = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch145-v5n-136-dispatch-20261123-v1/READY.json",
    );
    if ready.try_exists()? {
        let registered = immutable(&bound(ready)?)?;
        ensure!(
            registered["status_consumer_seal"] == owner["consumer_seal"],
            "status owner changed after V5n READY"
        );
    }
    Ok(())
}
#[cfg(not(feature = "v5n-semantic"))]
fn verify_bridge() -> Result<()> {
    let publisher = "horizon-archive-status-cadence-after172-20261120-v1.service";
    let unit = native(publisher)?;
    let pid: i32 = text(&unit["MainPID"])?.parse()?;
    let consumer = fs::read_link(proc_path(pid, "fd/255"))?;
    let (folder, seal) = bridge_package(&consumer)?;
    if folder == BRIDGE_PKG {
        let intent = Path::new(
            "/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-20261121-v1/START_INTENT.json",
        );
        ensure!(
            !intent.try_exists()?,
            "previous publisher cannot register an arriving normal 168"
        );
    }
    let lock = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/stable-cadence-controller-20261120-v1/consumer.lock",
    );
    ensure!(
        pid > 0
            && unit["ActiveState"] == "active"
            && unit["SubState"] == "running"
            && unit["NRestarts"] == "0"
            && unit["Job"] == ""
            && fs::read_to_string(proc_path(pid, "cgroup"))?.trim()
                == format!("0::/system.slice/{publisher}"),
        "active status publisher changed"
    );
    verify_consumer(folder, seal, pid, lock)?;
    ensure!(
        SELECTED.get_or_init(|| folder) == &folder,
        "publisher changed during registration"
    );
    Ok(())
}
#[cfg(any(not(feature = "v5n-semantic"), test))]
fn verify_consumer(folder: &str, seal: &str, pid: i32, lock: &Path) -> Result<()> {
    let pkg = Path::new(folder);
    let s = pinned(&pkg.join("deployment-seal-receipt.json"), seal)?;
    ensure!(
        s["destination"] == folder
            && s["sealer_sha256"] == SEALER
            && s["remote_mutations"] == false,
        "status adapter seal"
    );
    ensure!(
        fs::read_link(proc_path(pid, "fd/255"))? == pkg.join("consume")
            && same_inode(&proc_path(pid, "fd/255"), &pkg.join("consume"))?
            && same_inode(&proc_path(pid, "fd/9"), lock)?
            && fs::read_to_string(proc_path(pid, "fdinfo/9"))?
                .lines()
                .any(|line| line.starts_with("lock:")
                    && line.contains("FLOCK")
                    && line.contains("WRITE")),
        "consumer does not own the admitted image and kernel lock"
    );
    for m in s["members"].as_array().context("sealed modules")? {
        let name = text(&m["name"])?;
        if name.ends_with(".py") || name == "consume" {
            ensure!(
                name.bytes()
                    .all(|v| v.is_ascii_alphanumeric() || b"-._".contains(&v))
                    && bound(&pkg.join(name))?["sha256"] == m["sha256"],
                "changed status reader"
            );
        }
    }
    Ok(())
}
pub fn check_registration_environment() -> Result<()> {
    verify_bridge()?;
    ensure!(
        bridge("client", &Value::Null)? == true,
        "cannot load authenticated status client"
    );
    Ok(())
}
pub fn inspect_head(path: &str, digest: &str) -> Result<Value> {
    verify_bridge()?;
    bridge("head", &json!({"fleet": {"path": path, "sha256": digest}}))
}
fn bridge(op: &str, body: &Value) -> Result<Value> {
    bridge_timeout(op, body, 14)
}
fn bridge_timeout(op: &str, body: &Value, seconds: u64) -> Result<Value> {
    let mut c = Command::new("/usr/bin/timeout");
    c.args([
        "--kill-after=1",
        &seconds.to_string(),
        "/usr/bin/python3",
        "-I",
        "-B",
        "-c",
        include_str!("transport.py"),
        op,
        SELECTED
            .get()
            .context("status publisher has not been verified")?,
    ]);
    #[cfg(feature = "v5n-semantic")]
    c.arg(env!("HORIZON_136_PROVIDER_SEAL_SHA256"));
    let mut c = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    c.stdin
        .take()
        .context("status bridge stdin")?
        .write_all(&serde_json::to_vec(body)?)?;
    let out = c.wait_with_output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 1 << 20,
        "existing status operation failed: {op}"
    );
    Ok(serde_json::from_slice(&out.stdout)?)
}
fn utc(stamp: u64) -> Result<String> {
    output(
        "/usr/bin/date",
        &["-u", "-d", &format!("@{stamp}"), "+%Y-%m-%dT%H:%M:%SZ"],
    )
}
fn quiet(head: &Value) -> Result<u64> {
    let due = output("/usr/bin/date", &["-u", "-d", text(&head["due"])?, "+%s"])?.parse::<u64>()?;
    ensure!(
        due > now()
            && !Path::new(text(&head["sample"])?).try_exists()?
            && show(text(&head["timer"])?, "ActiveState")?["ActiveState"] == "active",
        "scheduled status cycle is due or active"
    );
    Ok(due)
}
struct Waiting {
    request: Value,
    request_ref: Value,
    ready: Value,
    owner: Value,
}
impl Waiting {
    fn response_deadline(&self) -> Result<u64> {
        let emitted = self.request["recorded_unix_seconds"]
            .as_u64()
            .context("status request time")?;
        let upper = self.request["handoff_deadline_unix_seconds"]
            .as_u64()
            .context("handoff deadline")?;
        Ok(upper.min(emitted.saturating_add(90)))
    }
    fn load(x: &Input) -> Result<Self> {
        let request_ref = bound(&receipts().join("parent-status-request.json"))?;
        let request = immutable(&request_ref)?;
        let rr = bound(&receipts().join("ready.json"))?;
        let ready = immutable(&rr)?;
        let launch = immutable(&request["launch"])?;
        let iid = require_iid(&request["invocation_id"])?;
        ensure!(
            request["schema"] == "horizon-epoch136-parent-status-request-v1"
                && request["epoch"] == 136
                && request["unit"] == ACTOR
                && request["ready"] == rr
                && request["helper"] == x.full["helper"]
                && request["writer_plan"] == x.writer_plan
                && request["complete_fleet"] == x.fleet
                && request["payload_plan"] == x.request["plan"]
                && request["admission"] == x.admission
                && request["writer"] == x.request["writer"]
                && request["writer_invocation_id"] == x.request["writer_invocation_id"]
                && request["repair_open"] == true
                && request["ordinary_replay_claim"] == false
                && [
                    "node_spawned",
                    "worker_spawned",
                    "initialize_authorized",
                    "r2_mutations"
                ]
                .iter()
                .all(|k| request[k] == false)
                && request["positive_worker_release_still_required"] == true
                && request["parent_owns_authenticated_status_publication"] == true
                && ready["invocation_id"] == iid
                && ready["schema"] == "horizon-epoch136-actual-ready-v1"
                && ready["unit"] == ACTOR
                && ready["helper"] == x.full["helper"]
                && ready["node_spawned"] == false
                && ready["worker_spawned"] == false
                && ready["launch"] == request["launch"]
                && request["launch"]["path"] == json!(receipts().join("launch.json"))
                && launch["plan"] == x.request["plan"]
                && launch["admission"] == x.admission
                && launch["pid"] == ready["pid"]
                && launch["start_ticks"] == ready["start_ticks"]
                && launch["invocation_id"] == iid,
            "wrong waiting request"
        );
        let owner = json!({"unit":ACTOR,"invocation_id":iid,"helper":x.full["helper"],"ready_recorded_unix_seconds":ready["recorded_unix_seconds"],"ready":rr,"parent_request":request_ref,"node_spawned":false,"worker_spawned":false,"repair_open":true,"ordinary_replay_claim":false});
        Ok(Self {
            request,
            request_ref,
            ready,
            owner,
        })
    }
    fn current(&self, x: &Input) -> Result<()> {
        x.live_admission()?;
        let iid = text(&self.owner["invocation_id"])?;
        let pid: i32 = self.ready["pid"]
            .as_u64()
            .context("ready pid")?
            .try_into()?;
        let r = native(ACTOR)?;
        ensure!(
            self.response_deadline()? > now()
                && immutable(&self.request_ref)? == self.request
                && r["ActiveState"] == "active"
                && r["SubState"] == "running"
                && r["Job"] == ""
                && r["NRestarts"] == "0"
                && r["InvocationID"] == iid
                && text(&r["MainPID"])?.parse::<i32>()? == pid
                && ticks(pid)?
                    == self.ready["start_ticks"]
                        .as_u64()
                        .context("payload ticks")?
                && group_members(&format!("/system.slice/{ACTOR}"))? == [pid]
                && same_inode(&proc_path(pid, "exe"), &at("tools/epoch136-actual-payload"))?
                && !receipts().join("parent-release.json").try_exists()?,
            "waiting process changed, expired or already released"
        );
        let timer = show(&format!("{GUARD}.timer"), "ActiveState,Job,InvocationID")?;
        let pre = &self.request["guard_prefire"];
        let s = from_ref(&pre["sample"])?;
        ensure!(
            timer["ActiveState"] == "active"
                && timer["Job"] == ""
                && timer["InvocationID"] == pre["timer"]["InvocationID"]
                && s["producer_invocation_id"] == iid
                && s["workers"].as_array().is_some_and(Vec::is_empty)
                && s["producer_stop_enabled"] == true
                && s["trip_reason"].is_null()
                && s["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|t| t <= now() && now() - t <= 120),
            "protective prefire no longer valid"
        );
        Ok(())
    }
}
fn projection(
    initial: &Value,
    latest: &Value,
    accepted: &Value,
    owner: &Value,
    stamp: u64,
    proof: &Value,
) -> Result<Value> {
    let mut f = initial.clone();
    ensure!(
        initial["all_active_status_reports_authenticated_readback"] == true
            && latest["all_active_status_reports_authenticated_readback"] == true
            && latest["effective_status_receipts"]
                .as_object()
                .is_some_and(|m| m.len() == 19 && m.contains_key("136")),
        "cohort lacks authenticated receipts"
    );
    // Native/disk/CPU arrays remain exactly the initial session projection. The newer
    // authenticated status head (if any) is independently bound and supplied to cadence.
    f["effective_status_receipts"] = latest["effective_status_receipts"].clone();
    f["effective_status_receipts"]["136"] = proof.clone();
    f["epoch136_pending_owner"] = owner.clone();
    f["epoch136_registration_unix_seconds"] = json!(stamp);
    f["epoch136_corresponding_status_fleet"] = accepted.clone();
    Ok(f)
}
fn status_dir(name: &str) -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let root = Path::new(STATUS_ROOT);
    let m = fs::symlink_metadata(root)?;
    ensure!(
        root.canonicalize()? == root
            && m.uid() == 1001
            && m.mode() & 0o777 == 0o700
            && m.is_dir()
            && m.dev() == fs::metadata(HOME)?.dev(),
        "unexpected campaign status root"
    );
    let path = root.join(name);
    match fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => File::open(root)?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    open_dir(&path)?;
    Ok(path)
}
fn same_remote(r: &Value, tag: &Value, hash: &Value) -> Result<bool> {
    Ok(r["etag"] == *tag && sha(text(&r["body"])?.as_bytes()) == *hash)
}
fn expected_body(i: &Value) -> Result<String> {
    let mut b = serde_json::to_string(&i["after_status"])?;
    b.push('\n');
    ensure!(
        sha(b.as_bytes()) == i["after_sha256"],
        "intent body encoding differs from cadence"
    );
    Ok(b)
}
fn head_for(waiting: &Waiting) -> Result<(Value, Value)> {
    let head = bridge("head", &json!({"fleet":waiting.request["complete_fleet"]}))?;
    let latest = from_ref(&head["fleet"])?;
    quiet(&head)?;
    Ok((head, latest))
}
fn next_cycle_lock(head: &Value) -> Result<File> {
    let p = Path::new(text(&head["next_lock"])?);
    let dir = p.parent().context("next cycle directory")?;
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("next cycle name")?;
    ensure!(
        dir.parent() == Some(Path::new(STATUS_ROOT))
            && p.file_name().is_some_and(|n| n == "cycle.lock")
            && name.starts_with("cycle")
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unexpected upcoming status lock"
    );
    status_dir(name)?;
    take_lock(p, true)
}
pub fn register(x: &Input) -> Result<()> {
    verify_bridge()?;
    let w = Waiting::load(x)?;
    let dir = status_dir(&format!(
        "event-136-waiting-{}",
        require_iid(&w.owner["invocation_id"])?
    ))?;
    let _event = take_lock(&dir.join("writer.lock"), true)?;
    let intent_file = dir.join("INTENT.json");
    let receipt_file = dir.join("RECEIPT.json");
    let mut remote = bridge("get", &json!(null))?;
    // Recover an already-applied conditional write first, even if the waiting
    // payload has just expired. Its new status still belongs in cadence's chain.
    if intent_file.try_exists()? && !receipt_file.try_exists()? {
        let i = immutable(&bound(&intent_file)?)?;
        ensure!(
            i["epoch136_pending_owner"] == w.owner && i["request"] == w.request_ref,
            "foreign partial event"
        );
        if text(&remote["body"])? == expected_body(&i)? {
            finish_receipt(&dir, &i, &remote)?;
        }
    }
    w.current(x)?;
    let (head, latest) = head_for(&w)?;
    let cycle = next_cycle_lock(&head)?;
    quiet(&head)?;
    let oldref = &latest["effective_status_receipts"]["136"];
    if !receipt_file.try_exists()? {
        if !intent_file.try_exists()? {
            let prior_ref = bridge(
                "follow",
                &json!({"previous":oldref,"etag":remote["etag"],"body":remote["body"]}),
            )?;
            let prior = from_ref(&prior_ref)?;
            ensure!(
                same_remote(&remote, &prior["after_etag"], &prior["after_sha256"])?
                    && prior["key"] == "epoch-136.epoch-status.json"
                    && prior["epoch"] == 136
                    && prior["current_repair_owner"] == "/root"
                    && prior["authenticated_readback"] == true
                    && prior["after_status"]["phase"] == "verification",
                "prior authenticated status differs"
            );
            let stamp = now();
            let next = bridge(
                "project",
                &json!({"stamp":utc(stamp)?,"old":prior["after_status"]}),
            )?;
            ensure!(
                next["status"] != prior["after_status"],
                "same dashboard timestamp; retry before the waiting deadline"
            );
            // The unchanged writer accepts at most 16 MiB of JSON per input.
            let initial = from_ref(&w.request["complete_fleet"])?;
            let trial = projection(
                &initial,
                &latest,
                &head["fleet"],
                &w.owner,
                stamp,
                &json!({"path":receipt_file,"sha256":"0".repeat(64)}),
            )?;
            ensure!(
                serde_json::to_vec_pretty(&trial)?.len() < (16 << 20),
                "waiting fleet exceeds the writer's input bound"
            );
            let i = json!({"schema":"horizon-epoch136-waiting-status-event-v1","epoch":136,"key":"epoch-136.epoch-status.json","owner":"/root","current_repair_owner":"/root",
                "producer_invocation_id":w.owner["invocation_id"],"epoch136_pending_owner":w.owner,"epoch136_registration_unix_seconds":stamp,
                "request":w.request_ref,"writer_plan":x.writer_plan,"payload_plan":x.request["plan"],"actual_status_fleet":head["fleet"],"initial_fleet":w.request["complete_fleet"],
                "previous_receipt":prior_ref,"before_status":prior["after_status"],"before_sha256":prior["after_sha256"],"before_etag":remote["etag"],
                "after_status":next["status"],"after_sha256":sha(text(&next["body"])?.as_bytes()),"conditional_header":"If-Match","ordinary_replay_claim":false,"archive_or_sidecar_mutations":false});
            protect_json(&intent_file, &i)?;
        }
        let i = immutable(&bound(&intent_file)?)?;
        let after = expected_body(&i)?;
        ensure!(
            i["epoch136_pending_owner"] == w.owner
                && i["request"] == w.request_ref
                && i["actual_status_fleet"] == head["fleet"],
            "intent belongs to another waiting owner or fleet"
        );
        if same_remote(&remote, &i["before_etag"], &i["before_sha256"])? {
            w.current(x)?;
            let due = quiet(&head)?;
            let expiry = w.response_deadline()?;
            // Bound PUT and GET to the actual remaining session/cadence interval.
            let seconds = due.min(expiry).saturating_sub(now()) / 3;
            ensure!(
                seconds > 0,
                "no time for conditional write and authenticated readback"
            );
            let budget = seconds.min(14);
            let submitted = bridge_timeout(
                "put",
                &json!({"etag":i["before_etag"],"body":after}),
                budget,
            );
            // A disconnection may follow a successful conditional PUT. The next
            // action in either case is an authenticated read of this same key.
            remote = bridge_timeout("get", &json!(null), budget)?;
            match submitted {
                Ok(sent) => ensure!(
                    remote["etag"] == sent,
                    "conditional ETag changed before authenticated readback"
                ),
                Err(error) if text(&remote["body"])? != after => {
                    return Err(error.context("conditional write has no matching readback"));
                }
                Err(_) => (),
            }
        }
        finish_receipt(&dir, &i, &remote)?;
    }
    drop(cycle);
    let proof = bound(&receipt_file)?;
    let evt = immutable(&proof)?;
    remote = bridge("get", &json!(null))?;
    ensure!(
        same_remote(&remote, &evt["after_etag"], &evt["after_sha256"])?
            && evt["epoch136_pending_owner"] == w.owner
            && bridge(
                "follow",
                &json!({"previous":oldref,"etag":remote["etag"],"body":remote["body"]})
            )? == proof,
        "cadence cannot adopt genuine waiting event"
    );
    let initial = from_ref(&w.request["complete_fleet"])?;
    let stamp = evt["epoch136_registration_unix_seconds"]
        .as_u64()
        .context("registration stamp")?;
    let f = projection(&initial, &latest, &head["fleet"], &w.owner, stamp, &proof)?;
    let use_fleet = protect_json(&dir.join("WAITING_FLEET.json"), &f)?;
    w.current(x)?;
    let mount = File::open(proc_path(x.writer_pid, "ns/mnt"))?;
    let process_root = File::open(proc_path(x.writer_pid, "root"))?;
    let root_arg = format!(
        "--root=/proc/{}/fd/{}",
        std::process::id(),
        process_root.as_raw_fd()
    );
    x.current_writer()?;
    let ns = format!(
        "--mount=/proc/{}/fd/{}",
        std::process::id(),
        mount.as_raw_fd()
    );
    // register-status must see the exact same projected BASE/controller as the waiting writer.
    let result = output(
        "/usr/bin/nsenter",
        &[
            &ns,
            &root_arg,
            "--wdns=/",
            string_path(&at("controller/admit136"))?,
            "register-status",
            text(&x.writer_plan["path"])?,
            text(&x.writer_plan["sha256"])?,
            text(&proof["path"])?,
            text(&proof["sha256"])?,
            text(&use_fleet["path"])?,
            text(&use_fleet["sha256"])?,
        ],
    )?;
    let registered: Value = serde_json::from_str(&result)?;
    let record = immutable(&registered)?;
    ensure!(
        record["request"] == w.request_ref
            && record["status_receipt"] == proof
            && record["fleet_receipt"] == use_fleet
            && record["ordinary_replay_claim"] == false,
        "registration acknowledgment differs"
    );
    println!("{}", registered);
    Ok(())
}
fn finish_receipt(dir: &Path, i: &Value, remote: &Value) -> Result<()> {
    let after = expected_body(i)?;
    ensure!(
        text(&remote["body"])? == after && remote["etag"].as_str().is_some_and(|v| !v.is_empty()),
        "remote body differs from the durable conditional intent"
    );
    let mut proof = i.clone();
    proof["after_etag"] = remote["etag"].clone();
    proof["authenticated_readback"] = json!(true);
    proof["verified_at_utc"] = json!(utc(now())?);
    protect_json(&dir.join("RECEIPT.json"), &proof)?;
    Ok(())
}

/// One-key GET and local evidence reconciliation after an interrupted or expired
/// handoff. Never submits another PUT, starts a process or authorizes a node.
pub fn reconcile() -> Result<()> {
    verify_bridge()?;
    let req = bound(&receipts().join("parent-status-request.json"))?;
    let waiting = immutable(&req)?;
    let iid = require_iid(&waiting["invocation_id"])?;
    let dir = Path::new(STATUS_ROOT).join(format!("event-136-waiting-{iid}"));
    open_dir(&dir)?;
    let _lock = take_lock(&dir.join("writer.lock"), false)?;
    let intent = immutable(&bound(&dir.join("INTENT.json"))?)?;
    ensure!(
        intent["schema"] == "horizon-epoch136-waiting-status-event-v1"
            && intent["current_repair_owner"] == "/root"
            && intent["key"] == "epoch-136.epoch-status.json"
            && intent["epoch"] == 136
            && intent["conditional_header"] == "If-Match"
            && intent["request"] == req
            && intent["producer_invocation_id"] == iid
            && intent["epoch136_pending_owner"]["parent_request"] == req
            && intent["writer_plan"] == waiting["writer_plan"]
            && intent["payload_plan"] == waiting["payload_plan"],
        "unbound recovery intent"
    );
    let r = bridge("get", &json!(null))?;
    if dir.join("RECEIPT.json").try_exists()? {
        let proof = bound(&dir.join("RECEIPT.json"))?;
        let received = immutable(&proof)?;
        ensure!(
            received["request"] == req && received["authenticated_readback"] == true,
            "incorrect saved readback"
        );
        println!("{proof}");
        return Ok(());
    }
    if same_remote(&r, &intent["before_etag"], &intent["before_sha256"])? {
        println!(
            "{}",
            json!({"old_status_unchanged":true,"new_receipt":null})
        );
        return Ok(());
    }
    finish_receipt(&dir, &intent, &r)?;
    println!("{}", bound(&dir.join("RECEIPT.json"))?);
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires a private kernel lock and both sealed normal status packages"]
    fn combined_consumer_owns_exact_fds_and_lock() -> Result<()> {
        let lock = PathBuf::from(std::env::var("NORMAL168_BRIDGE_FIXTURE_LOCK")?);
        let pid = std::env::var("NORMAL168_BRIDGE_FIXTURE_PID")?.parse()?;
        let candidate = Path::new(NEXT_PKG).join("consume");
        let (folder, seal) = bridge_package(&candidate)?;
        verify_consumer(folder, seal, pid, &lock)?;
        ensure!(
            verify_consumer(BRIDGE_PKG, BRIDGE_SEAL, pid, &lock).is_err(),
            "crossed publisher"
        );
        ensure!(
            verify_consumer(folder, BRIDGE_SEAL, pid, &lock).is_err(),
            "crossed seal"
        );
        ensure!(
            verify_consumer(folder, seal, pid, &lock.with_extension("other")).is_err(),
            "crossed lock"
        );
        ensure!(bridge_package(&lock).is_err(), "unknown package");
        Ok(())
    }
    #[test]
    fn waiting_owner_never_changes_active_arrays_or_resource_claims() {
        let mut initial = json!({"actual_executing_replays":[{"epoch":167}],"actual_active_bootstraps":[],"actual_active_private_diagnostics":[{"epoch":169}],
            "complete_projected_memory_bytes":610,"complete_DATA_bytes":250,"all_reservation_ending_bytes":0,"terminal172_closure":{"sha":"bound"},
            "all_active_status_reports_authenticated_readback":true});
        let refs: serde_json::Map<String, Value> = (136..155)
            .map(|e| (e.to_string(), json!({"original":e})))
            .collect();
        initial["effective_status_receipts"] = Value::Object(refs);
        let mut latest = initial.clone();
        latest["effective_status_receipts"]["148"] = json!({"fresh":148});
        let wait = json!({"worker_spawned":false,"ordinary_replay_claim":false});
        let proof = json!({"sha256":"a".repeat(64)});
        let fleet = projection(
            &initial,
            &latest,
            &json!({"head":"actual"}),
            &wait,
            10,
            &proof,
        )
        .unwrap();
        assert_eq!(fleet["epoch136_pending_owner"], wait);
        assert_eq!(fleet["effective_status_receipts"]["136"], proof);
        assert_eq!(
            fleet["effective_status_receipts"]["148"],
            latest["effective_status_receipts"]["148"]
        );
        for k in [
            "actual_executing_replays",
            "actual_active_bootstraps",
            "actual_active_private_diagnostics",
            "complete_projected_memory_bytes",
            "complete_DATA_bytes",
            "all_reservation_ending_bytes",
            "terminal172_closure",
        ] {
            assert_eq!(fleet[k], initial[k], "{k}");
        }
        latest["all_active_status_reports_authenticated_readback"] = json!(false);
        assert!(projection(&initial, &latest, &Value::Null, &wait, 10, &proof).is_err());
    }
    #[test]
    fn conditional_recovery_requires_canonical_new_body() {
        let data = json!({"epoch":136,"phase":"verification"});
        let bytes = b"{\"epoch\":136,\"phase\":\"verification\"}\n";
        let mut i = json!({"after_status":data,"after_sha256":sha(bytes)});
        assert_eq!(expected_body(&i).unwrap().as_bytes(), bytes);
        i["after_status"]["phase"] = json!("replay");
        assert!(expected_body(&i).is_err());
    }
}
