//! Serialize epoch 145's first post-verification submission with the original
//! 136 writer. Both use the same kernel flock. Its inode survives owner exit.
use super::*;
use std::fs::{File, OpenOptions};

#[cfg(not(feature = "fixture-post"))]
pub(super) mod profile {
    pub(crate) const DIR: &str = "epoch145-phase-dispatch-20261122-v1";
    pub(crate) const DEPLOY: &str = "tools-v2";
    pub(crate) const DISPATCH: &str = "horizon-145-phase-dispatch-20261122-v1.service";
    pub(crate) const OLD: &str = "horizon-145-v5e-delivery-follow-20261121-v1.service";
    pub(crate) const STATE: &str = "epoch145-v5e-delivery-handoff-20261121-v1/state";
    pub(crate) const SEMANTIC: &str = "a99ed8b51e8a482b805b8a36a11b2700";
    pub(crate) const FOLLOW: &str = "follow-v5e";
    pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261122-v6";
    pub(crate) const WRITER_SEAL: &str =
        "62ced18aed9e45e564bc01aebfc2c18639c7cf2125626bdda405b6ac0af976ba";
    pub(crate) const MIRROR_SEAL: &str =
        "404c245db5060e54e24295cb54de1d60d5549f657fc288c2185c4c72612a8ee8";
    pub(crate) const PARENT_SEAL: &str =
        "a95b11e40ac911f3916494d8c932b3c61a16de857e8d2f49af7c9198438cfa6b";
    pub(crate) const LAUNCHER: &str =
        "b73e0c3220a1dcefb67ccda8981b4441dcb995238d1da377d91ad2ee0c35f804";
}
#[cfg(feature = "fixture-post")]
pub(super) mod profile {
    pub(crate) use crate::incident::generation::{FOLLOW, SOURCE as SEMANTIC, STATE_PATH as STATE};
    #[cfg(not(feature = "retry-post"))]
    mod selected {
        pub(crate) const DIR: &str = "epoch145-fixture-phase-dispatch-20261122-v1";
        pub(crate) const DISPATCH: &str = "horizon-145-fixture-phase-dispatch-20261122-v1.service";
        pub(crate) const OLD: &str = "horizon-145-phase-dispatch-20261122-v1.service";
        pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261122-v7b";
        pub(crate) const CLOSED: &str =
            "d267b6e774e26fc5c9d5b95f5845b547afbfde74f58e434b835acd63785a7f07";
    }
    #[cfg(all(
        feature = "retry-post",
        not(any(
            feature = "v5n-136-post",
            feature = "v5o-136-post",
            feature = "v5q-136-post"
        ))
    ))]
    mod selected {
        pub(crate) const DIR: &str = "epoch145-fixture-retry1-dispatch-20261122-v1";
        pub(crate) const DISPATCH: &str = "horizon-145-fixture-retry1-dispatch-20261122-v1.service";
        pub(crate) const OLD: &str = "horizon-145-fixture-phase-dispatch-20261122-v1.service";
        pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261122-v7c";
        pub(crate) const CLOSED: &str =
            "e292ddb3e46ff8e5fb0d0dd39bacc6bb5376ac238c4868b622ccfdb42df47b5a";
    }
    #[cfg(all(
        feature = "v5n-136-post",
        not(any(feature = "v5o-136-post", feature = "v5q-136-post"))
    ))]
    mod selected {
        pub(crate) const DIR: &str = "epoch145-v5n-136-dispatch-20261123-v1";
        pub(crate) const DISPATCH: &str = "horizon-145-v5n-136-dispatch-20261123-v1.service";
        pub(crate) const OLD: &str = "horizon-145-fixture-retry1-dispatch-20261122-v1.service";
        pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261123-v8";
        pub(crate) const CLOSED: &str = env!("HORIZON_145_PREDECESSOR_DRAINED_SHA256");
    }
    #[cfg(all(feature = "v5o-136-post", not(feature = "v5q-136-post")))]
    mod selected {
        pub(crate) const DIR: &str = "epoch145-v5o-136-dispatch-20261123-v1";
        pub(crate) const DISPATCH: &str = "horizon-145-v5o-136-dispatch-20261123-v1.service";
        pub(crate) const OLD: &str = "horizon-145-fixture-retry1-dispatch-20261122-v1.service";
        pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261123-v9";
        pub(crate) const CLOSED: &str = env!("HORIZON_145_PREDECESSOR_DRAINED_SHA256");
    }
    #[cfg(feature = "v5q-136-post")]
    mod selected {
        pub(crate) const DIR: &str = "epoch145-v5q-136-dispatch-20261124-v1";
        pub(crate) const DISPATCH: &str = "horizon-145-v5q-136-dispatch-20261124-v1.service";
        pub(crate) const OLD: &str = "horizon-145-fixture-retry1-dispatch-20261122-v1.service";
        pub(crate) const WRITER_DIR: &str = "epoch136-joint-writer-20261124-v10";
        pub(crate) const CLOSED: &str = env!("HORIZON_145_PREDECESSOR_DRAINED_SHA256");
    }
    pub(crate) use selected::*;
    pub(crate) const DEPLOY: &str = "tools";
    pub(crate) const WRITER_SEAL: &str = env!("HORIZON_136_WRITER_SEAL_SHA256");
    pub(crate) const MIRROR_SEAL: &str = env!("HORIZON_136_MIRROR_SEAL_SHA256");
    pub(crate) const PARENT_SEAL: &str = env!("HORIZON_136_PARENT_SEAL_SHA256");
    pub(crate) const LAUNCHER: &str = env!("HORIZON_136_LAUNCHER_SHA256");
}
use profile::{
    DEPLOY, DIR, DISPATCH, FOLLOW, LAUNCHER, MIRROR_SEAL, OLD, PARENT_SEAL, SEMANTIC, STATE,
    WRITER_DIR, WRITER_SEAL,
};

const LOCK: &str = "/run/horizon-epoch171-to136-g1.operation.lock";
const BASE: &str = "/home/sol/.jetstreamer-private/epoch136-actual-20261120-g1";
const PAYLOAD: &str = "horizon-qualify-136-actual-20261120-g1.service";
const SELECTED: &str = "writer-selected.json";

pub(super) fn ready_path() -> PathBuf {
    rt(DIR).join("READY.json")
}

fn boot() -> Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

fn owner(pid: i32, iid: &str) -> Result<Value> {
    Ok(json!({"pid":pid,"start_ticks":platform::ticks(pid)?,"invocation_id":iid}))
}

fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    (a.dev(), a.ino()) == (b.dev(), b.ino())
}

fn compare_lock_identity(m: &fs::Metadata, spec: &Value) -> Result<()> {
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o600
            && m.len() == 0
            && spec
                == &json!({
                    "path":LOCK, "device":m.dev(), "inode":m.ino()
                }),
        "different original operation lock"
    );
    Ok(())
}

fn exclusive_row(line: &str, pid: i32, m: &fs::Metadata) -> bool {
    let dev = format!(
        "{:02x}:{:02x}:{}",
        libc::major(m.dev()),
        libc::minor(m.dev()),
        m.ino()
    );
    let fields: Vec<_> = line.split_whitespace().collect();
    fields.len() == 9
        && fields[0] == "lock:"
        && fields[2..5] == ["FLOCK", "ADVISORY", "WRITE"]
        && fields[5] == pid.to_string()
        && fields[6] == dev
        && fields[7..] == ["0", "EOF"]
}

fn owned_lock(pid: i32, path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    let proc = PathBuf::from(format!("/proc/{pid}"));
    for entry in fs::read_dir(proc.join("fd"))? {
        let fd = entry?;
        let info = proc.join("fdinfo").join(fd.file_name());
        let Ok(meta) = fs::metadata(fd.path()) else {
            continue;
        };
        if same_inode(&meta, &m)
            && fs::read_to_string(info)?
                .lines()
                .any(|s| exclusive_row(s, pid, &m))
        {
            ensure!(
                same_inode(&fs::symlink_metadata(path)?, &m),
                "lock replaced"
            );
            return Ok(());
        }
    }
    bail!("PID {pid} does not own the original exclusive lock")
}

fn open_operation(ready: &Value) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(LOCK)?;
    let m = f.metadata()?;
    compare_lock_identity(&m, &ready["operation_lock"])?;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    ensure!(
        rc == 0,
        "136 operation still occupied: {}",
        std::io::Error::last_os_error()
    );
    ensure!(
        same_inode(&m, &fs::symlink_metadata(LOCK)?),
        "operation inode replaced"
    );
    Ok(f)
}

fn registration() -> Result<(Value, Value)> {
    let pin = bound(&ready_path())?;
    let ready = from_ref(&pin)?;
    ensure!(
        ready["schema"] == "horizon-145-136-prestart-selector-ready-v1"
            && ready["boot_id"] == boot()?
            && ready["original_semantic_invocation"] == SEMANTIC,
        "foreign selector registration"
    );
    #[cfg(feature = "fixture-post")]
    {
        use crate::incident::generation::{FIT_PKG, FIT_SEAL};
        let provider = rt(FIT_PKG);
        let image = check_member(&provider, FIT_SEAL, "post-stop-fit")?;
        ensure!(
            ready["registered_provider"]
                == json!({"image":bound(&image)?,
            "seal": bound(&provider.join("deployment-seal-receipt.json"))?}),
            "different registered V21 provider"
        );
        let (status, status_sha) = if cfg!(any(
            feature = "v5n-136-post",
            feature = "v5o-136-post",
            feature = "v5q-136-post"
        )) {
            (
                rt(
                    "survivor172-cadence-20261122-v1/tools-cold168-retry4-136-v1/deployment-seal-receipt.json",
                ),
                option_env!("HORIZON_136_STATUS_SEAL_SHA256").context("missing 136 status seal")?,
            )
        } else {
            (
                rt(
                    "prefix140-status-cadence-20261122-v1/cadence-tools/deployment-seal-receipt.json",
                ),
                "7afadecf5d474dfb5b4dddf8dc61f816c8bcbe837fb2bd6bb2ed713d0262722e",
            )
        };
        ensure!(
            ready["status_consumer_seal"] == bound(&status)?
                && ready["status_consumer_seal"]["sha256"] == status_sha,
            "different prefix status consumer"
        );
    }
    compare_lock_identity(&fs::symlink_metadata(LOCK)?, &ready["operation_lock"])?;
    let pkg = rt(DIR).join(DEPLOY);
    let seal = bound(&pkg.join("deployment-seal-receipt.json"))?;
    ensure!(ready["deployment"] == seal, "different selector deployment");
    let image = check_member(&pkg, text(&seal["sha256"])?, "follow145")?;
    let checker = check_member(&pkg, text(&seal["sha256"])?, "boundary-inspector")?;
    ensure!(
        ready["boundary_inspector"] == bound(&checker)?
            && bound(&image)?["sha256"] == ready["boundary_inspector"]["sha256"],
        "different inspector"
    );
    let (pid, iid) = stable(&native(DISPATCH)?, DISPATCH)?;
    ensure!(
        ready["dispatcher"] == owner(pid, &iid)?
            && platform::proc_exe(pid)? == image
            && same_inode(
                &fs::metadata(format!("/proc/{pid}/exe"))?,
                &fs::metadata(&image)?
            )
            && fs::read(format!("/proc/{pid}/cmdline"))?
                == [image.as_os_str().as_encoded_bytes(), FOLLOW.as_bytes(), b""].join(&0),
        "selector invocation changed"
    );
    owned_lock(pid, &rt(STATE).join("controller.lock"))?;
    #[cfg(not(feature = "fixture-post"))]
    drained(&native(OLD)?, OLD)?;
    #[cfg(feature = "fixture-post")]
    for path in previous_locks()? {
        owned_lock(pid, &path)?;
    }
    Ok((pin, ready))
}

#[cfg(feature = "fixture-post")]
fn previous_locks() -> Result<Vec<PathBuf>> {
    let receipt = pinned(&rt(DIR).join("PREDECESSOR_DRAINED.json"), profile::CLOSED)?;
    let original = rt("epoch145-v5e-delivery-handoff-20261121-v1/state/controller.lock");
    let earlier = "horizon-145-v5e-delivery-follow-20261121-v1.service";
    #[cfg(not(feature = "retry-post"))]
    let (locks, units) = (
        vec![(original, "controller_lock")],
        vec![(OLD, "previous"), (earlier, "earlier")],
    );
    #[cfg(all(
        feature = "retry-post",
        not(any(
            feature = "v5n-136-post",
            feature = "v5o-136-post",
            feature = "v5q-136-post"
        ))
    ))]
    let (locks, units) = (
        vec![
            (original, "controller_lock"),
            (
                rt("epoch145-fixture-phase-dispatch-20261122-v1/state/controller.lock"),
                "recent_controller_lock",
            ),
        ],
        vec![
            (OLD, "previous"),
            ("horizon-145-phase-dispatch-20261122-v1.service", "earlier"),
            (earlier, "earliest"),
        ],
    );
    #[cfg(any(
        feature = "v5n-136-post",
        feature = "v5o-136-post",
        feature = "v5q-136-post"
    ))]
    let (locks, units) = (
        vec![
            (original, "controller_lock"),
            (
                rt("epoch145-fixture-phase-dispatch-20261122-v1/state/controller.lock"),
                "recent_controller_lock",
            ),
            (
                rt("epoch145-fixture-retry1-dispatch-20261122-v1/state/controller.lock"),
                "retry_controller_lock",
            ),
        ],
        vec![
            (OLD, "retry"),
            (
                "horizon-145-fixture-phase-dispatch-20261122-v1.service",
                "previous",
            ),
            ("horizon-145-phase-dispatch-20261122-v1.service", "earlier"),
            (earlier, "earliest"),
        ],
    );
    #[cfg(any(feature = "v5o-136-post", feature = "v5q-136-post"))]
    {
        let retired = [(
            "epoch145-v5n-136-dispatch-20261123-v1",
            "horizon-145-v5n-136-dispatch-20261123-v1.service",
        )];
        #[cfg(feature = "v5q-136-post")]
        let retired = retired.into_iter().chain([(
            "epoch145-v5o-136-dispatch-20261123-v1",
            "horizon-145-v5o-136-dispatch-20261123-v1.service",
        )]);
        for (directory, unit) in retired {
            let owner = native(unit)?;
            drained(&owner, unit)?;
            ensure!(
                owner["LoadState"] == "not-found"
                    && !rt(directory).join("READY.json").try_exists()?
                    && !rt(directory).join("OFFER.json").try_exists()?
                    && !Path::new("/sys/fs/cgroup/system.slice")
                        .join(unit)
                        .try_exists()?,
                "retired selector still owns a handoff"
            );
        }
    }
    let mut paths = Vec::new();
    for (path, field) in locks {
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            receipt[field] == json!({"path":path,"device":m.dev(),"inode":m.ino()})
                && m.is_file()
                && m.nlink() == 1
                && m.len() == 0
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600,
            "predecessor controller lock changed"
        );
        paths.push(path);
    }
    for (unit, field) in units {
        let recorded = &receipt[field];
        let live = terminal136::unit_state(unit)?;
        ensure!(
            live["Id"] == recorded["Id"]
                && live["MainPID"] == "0"
                && live["ControlPID"] == "0"
                && live["Job"] == ""
                && (live["ActiveState"] == "inactive"
                    || (live["ActiveState"] == "failed"
                        && live["InvocationID"] == recorded["InvocationID"]
                        && live["SubState"] == "failed"
                        && recorded["ActiveState"] == "failed"))
                && !Path::new("/sys/fs/cgroup/system.slice")
                    .join(unit)
                    .try_exists()?,
            "previous dispatcher still owns work or has changed"
        );
    }
    Ok(paths)
}

#[cfg(feature = "fixture-post")]
pub(super) fn guard_predecessor() -> Result<Vec<File>> {
    let paths = previous_locks()?;
    let mut retained = Vec::new();
    for path in &paths {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(
            same_inode(&file.metadata()?, &fs::symlink_metadata(path)?)
                && unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "previous dispatcher owns its controller lock"
        );
        retained.push(file);
    }
    ensure!(paths == previous_locks()?, "predecessor set changed");
    for (path, file) in paths.iter().zip(&retained) {
        ensure!(
            same_inode(&file.metadata()?, &fs::symlink_metadata(path)?),
            "previous lock replaced"
        );
    }
    Ok(retained)
}

fn before_submission() -> Result<()> {
    for name in [
        "post-full-submission.json",
        "post-full-actor.json",
        "publish-submission.json",
        "publish-actor.json",
        "completed.json",
    ] {
        ensure!(
            !rt(STATE).join(name).try_exists()?,
            "145 already crossed its post boundary"
        );
    }
    #[cfg(any(
        feature = "v5n-136-post",
        feature = "v5o-136-post",
        feature = "v5q-136-post"
    ))]
    for entry in fs::read_dir(rt("epoch145-publication-20261121-v1"))? {
        let name = entry?.file_name();
        let name = name.to_str().context("non-UTF8 145 publication entry")?;
        ensure!(
            !["full-", "network-"]
                .iter()
                .any(|prefix| { name.strip_prefix(prefix).is_some_and(valid_iid) }),
            "epoch 145 has already started an ordinary post phase"
        );
    }
    Ok(())
}

#[cfg(feature = "fixture-post")]
fn fixture_plan(plan: &Value) -> Result<()> {
    use crate::incident::generation::{ADVANCING, PKG, SEAL, START};
    let post = rt(PKG);
    let seal_path = post.join("deployment-seal-receipt.json");
    let seal = pinned(&seal_path, SEAL)?;
    let binding = |name: &str| -> Result<Value> {
        let path = post.join(name);
        let reference = bound(&path)?;
        ensure!(
            seal["members"]
                .as_array()
                .context("V13b members")?
                .iter()
                .any(|m| m["name"] == name
                    && m["sha256"] == reference["sha256"]
                    && m["mode"] == "0444"),
            "unsealed V13b member"
        );
        Ok(reference)
    };
    let worker = json!({"path":rt(START),"sha256":ADVANCING});
    let build = binding("build-proof.json")?;
    #[cfg(not(any(
        feature = "v5n-136-post",
        feature = "v5o-136-post",
        feature = "v5q-136-post"
    )))]
    ensure!(
        from_ref(&build)?["prior_phase"] == worker,
        "different V5f retained worker"
    );
    #[cfg(all(
        feature = "v5n-136-post",
        not(any(feature = "v5o-136-post", feature = "v5q-136-post"))
    ))]
    ensure!(
        from_ref(&worker)?["invocation_id"] == SEMANTIC
            && build["sha256"]
                == "acd58b6927de438b036275c50d2edbc08f2f33626dec64e6a43d2235b80e541c",
        "different original V5n or V13h build"
    );
    #[cfg(any(feature = "v5o-136-post", feature = "v5q-136-post"))]
    {
        let receipt = from_ref(&build)?;
        let family = rt("epoch145-semantic-continuity-20261121-v1");
        let (key, name, hash) = if cfg!(feature = "v5q-136-post") {
            (
                "audit_turnover_binding",
                "V5Q_RUNTIME_BINDINGS.json",
                "a5dc1d9973d950d36f7302b800f0b10421066e135e0912750fd92b98521cadc4",
            )
        } else {
            (
                "donor_pressure_binding",
                "V5O_RUNTIME_BINDINGS.json",
                "d571da98684079bc937a2ddeed52dbcd457eb0a74010519171b851e3e5297137",
            )
        };
        ensure!(
            from_ref(&worker)?["invocation_id"] == SEMANTIC
                && receipt["schema"] == "horizon-145-v5j-post-build-v1"
                && receipt["semantic_submission"] == worker
                && receipt[key] == json!({"path":family.join(name), "sha256":hash}),
            "different original semantic invocation or post build"
        );
    }
    ensure!(
        seal["destination"] == json!(post)
            && plan["holding145_semantic_worker"] == worker
            && plan["holding145_completion"]
                == json!({"build":build,"adapter":binding("incident-post-phase.py")?,"seal":{"path":seal_path,"sha256":SEAL}}),
        "different V5f/V13b completion"
    );
    Ok(())
}

fn offered_plan(offer: &Value, selector: &Value) -> Result<(Value, PathBuf)> {
    ensure!(
        offer["selector"] == *selector,
        "session offer selects a different dispatcher"
    );
    #[cfg(feature = "fixture-post")]
    ensure!(
        aspath(&offer["writer_plan"])? == rt(WRITER_DIR).join("registered-production-plan.json"),
        "different registered V7 plan"
    );
    let plan = from_ref(&offer["writer_plan"])?;
    #[cfg(feature = "fixture-post")]
    fixture_plan(&plan)?;
    ensure!(
        plan["holding145_prestart_ready"] == *selector
            && plan["controller"]["path"] == json!(Path::new(BASE).join("controller/admit136")),
        "different writer binding"
    );
    let seal = &plan["controller_deployment"];
    let pkg = aspath(seal)?.parent().context("writer package")?;
    ensure!(
        pkg.file_name().is_some_and(|x| x == "controller")
            && pkg.parent().and_then(Path::parent) == Some(Path::new(RT))
            && aspath(seal)? == pkg.join("deployment-seal-receipt.json"),
        "foreign writer package"
    );
    ensure!(
        pkg == rt(WRITER_DIR).join("controller") && seal["sha256"] == WRITER_SEAL,
        "different qualified writer"
    );
    let image = check_member(pkg, WRITER_SEAL, "admit136")?;
    ensure!(
        bound(&image)?["sha256"] == plan["controller"]["sha256"],
        "writer image changed"
    );
    Ok((plan, image))
}

pub(super) fn inspect(args: &[String]) -> Result<()> {
    let (selector, ready) = registration()?;
    ensure!(
        args[1] == text(&selector["sha256"])?
            && platform::proc_exe(std::process::id() as i32)?
                == aspath(&ready["boundary_inspector"])?,
        "unregistered inspector invocation"
    );
    before_submission()?;
    let selected = from_ref(&bound(&rt(DIR).join("state").join(SELECTED))?)?;
    let offer = from_ref(&selected["offer"])?;
    let (plan, image) = offered_plan(&offer, &selector)?;
    let (pid, iid) = stable(&native(W)?, W)?;
    let writer = owner(pid, &iid)?;
    ensure!(
        args[2] == pid.to_string()
            && args[3].parse::<u64>()? == writer["start_ticks"]
            && args[4] == iid,
        "wrong writer"
    );
    let fleet = json!({"path":args[5],"sha256":args[6]});
    ensure!(
        selected["fleet"] == fleet
            && selected["semantic_complete"] == incident::completed_semantics()?,
        "different selected inputs"
    );
    let expected = [
        text(&plan["controller"]["path"])?,
        "session",
        text(&offer["writer_plan"]["path"])?,
        text(&offer["writer_plan"]["sha256"])?,
        &args[5],
        &args[6],
        "",
    ]
    .join("\0");
    ensure!(
        same_inode(
            &fs::metadata(format!("/proc/{pid}/exe"))?,
            &fs::metadata(image)?
        ) && fs::read(format!("/proc/{pid}/cmdline"))? == expected.as_bytes(),
        "foreign operation owner"
    );
    owned_lock(pid, Path::new(LOCK))?;
    drained(&native(E)?, E)?;
    before_submission()?;
    ensure!(
        stable(&native(W)?, W)? == (pid, iid) && platform::ticks(pid)? == writer["start_ticks"],
        "writer changed"
    );
    println!(
        "{}",
        json!({"schema":"horizon-145-136-writer-boundary-v1","writer":writer,"fleet":fleet,
        "selector":selector,"post_submission_held":true,"semantic_complete":selected["semantic_complete"]})
    );
    Ok(())
}

fn empty_candidate() -> Result<()> {
    drained(&native(PAYLOAD)?, PAYLOAD)?;
    for p in [
        Path::new(BASE).join("prestart-intent.json"),
        Path::new(BASE).join("admission.json"),
        Path::new(BASE).join("reproduction"),
        PathBuf::from("/run/horizon-epoch171-exclusive-to136-g1"),
    ] {
        ensure!(
            fs::symlink_metadata(&p).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "136 retains ownership at {}",
            p.display()
        );
    }
    Ok(())
}

// V19 checks the native release and the accepted roster on each price. Retain
// the post submission until both agree that the selected donation ended.
fn settled(offer: &Value, selector: &Value, ready: &Value) -> Result<File> {
    let operation = open_operation(ready)?;
    let (_, image) = offered_plan(offer, selector)?;
    let intent_path = Path::new(BASE).join("prestart-intent.json");
    if !intent_path.try_exists()? {
        drained(&native(W)?, W)?;
        empty_candidate()?;
        return Ok(operation);
    }
    let intent = from_ref(&bound(&intent_path)?)?;
    drop(operation);
    terminal136::release_before_post(&offer["writer_plan"], &image, &intent)?;
    let operation = open_operation(ready)?;
    ensure!(
        from_ref(&bound(&intent_path)?)? == intent,
        "donor intent changed after release"
    );
    let verified: Value = serde_json::from_slice(&command(
        &image,
        &[
            "verify-release",
            text(&offer["writer_plan"]["path"])?,
            text(&offer["writer_plan"]["sha256"])?,
        ],
    )?)?;
    ensure!(
        verified == bound(&Path::new(BASE).join("prestart-released.json"))?,
        "donor release changed"
    );
    Ok(operation)
}

pub(super) fn selected_boundary() -> Result<Value> {
    let state = rt(DIR).join("state");
    let writer = state.join(SELECTED);
    let post = state.join("post-selected.json");
    let selector = bound(&ready_path())?;
    let done = incident::completed_semantics()?;
    let (record, registered) = match (writer.try_exists()?, post.try_exists()?) {
        (true, false) => {
            let record = bound(&writer)?;
            let offer = from_ref(&from_ref(&record)?["offer"])?;
            (record, offer["selector"].clone())
        }
        (false, true) => {
            let record = bound(&post)?;
            let registered = from_ref(&record)?["selector"].clone();
            (record, registered)
        }
        _ => bail!("expected one registered 145 boundary decision"),
    };
    ensure!(
        registered == selector && from_ref(&record)?["semantic_complete"] == done,
        "foreign selector decision"
    );
    Ok(json!({"selector":selector,"decision":record}))
}

fn prepare_mirrors(offer: &Value, fleet: &Value, parent: &Path) -> Result<bool> {
    let pkg = rt(WRITER_DIR).join("preflight-tools");
    let price = check_member(&pkg, MIRROR_SEAL, "price-mirrors")?;
    ensure!(
        offer["mirror_price"] == bound(&price)?,
        "foreign mirror price"
    );
    let args = [text(&fleet["path"])?, text(&fleet["sha256"])?];
    let priced = || -> Result<Value> {
        let value: Value = serde_json::from_slice(&command(&price, &args)?)?;
        ensure!(
            value["schema"] == "horizon-136-parent-mirror-price-v1"
                && value["fleet"] == *fleet
                && value["admission_granted"] == false
                && value["resource_credit_bytes"] == 0
                && value["r2_mutations"] == false,
            "invalid mirror price"
        );
        Ok(value)
    };
    let fits = |v: &Value| -> Result<bool> {
        // The parent can create one waiting-fleet document of up to 16 MiB.
        // Price that document and the event receipts separately from the inputs.
        let reserve = (16 << 20) + (1 << 20);
        Ok(v["memory_fits"] == true
            && v["mirrors_fit"] == true
            && v["remaining_after_mirrors_bytes"]
                .as_i64()
                .context("missing mirror residual")?
                >= reserve)
    };
    let before = priced()?;
    if !fits(&before)? {
        return Ok(false);
    }
    command(parent, &["prepare-inputs", args[0], args[1]])?;
    let after = priced()?;
    ensure!(
        after["missing_mirror_bytes"] == 0,
        "parent omitted a priced mirror"
    );
    fits(&after)
}

// systemd-run --wait retains very short writer exits. The parent must serve the
// actual writer's launch/status requests while that process is still waiting.
fn run_session(
    launcher: &Path,
    parent: &Path,
    offer: &Value,
    plan: &Value,
    fleet: &Value,
    image: &Path,
) -> Result<Value> {
    let plan_args = [
        text(&offer["writer_plan"]["path"])?,
        text(&offer["writer_plan"]["sha256"])?,
    ];
    let fleet_args = [text(&fleet["path"])?, text(&fleet["sha256"])?];
    let mut launch = Command::new(launcher)
        .env("HORIZON_WAIT_FOR_136_WRITER", "1")
        .args([
            "session",
            plan_args[0],
            plan_args[1],
            fleet_args[0],
            fleet_args[1],
        ])
        .spawn()?;
    let dispatcher = (|| -> Result<Option<(String, std::process::ExitStatus)>> {
        loop {
            if launch.try_wait()?.is_some() {
                return Ok(None);
            }
            let n = native(W)?;
            if n["ActiveState"] == "active" && n["SubState"] == "running" && n["Job"] == "" {
                let (pid, iid) = stable(&n, W)?;
                let expected = [
                    text(&plan["controller"]["path"])?,
                    "session",
                    plan_args[0],
                    plan_args[1],
                    fleet_args[0],
                    fleet_args[1],
                    "",
                ]
                .join("\0");
                ensure!(
                    same_inode(
                        &fs::metadata(format!("/proc/{pid}/exe"))?,
                        &fs::metadata(image)?
                    ) && fs::read(format!("/proc/{pid}/cmdline"))? == expected.as_bytes(),
                    "different selected writer PID"
                );
                let status = Command::new(parent)
                    .args([
                        "dispatch",
                        &iid,
                        plan_args[0],
                        plan_args[1],
                        text(&plan["controller_deployment"]["path"])?,
                        text(&plan["controller_deployment"]["sha256"])?,
                    ])
                    .status()?;
                return Ok(Some((iid, status)));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    })();
    // The writer has its own finite RuntimeMaxSec and activation expiry.
    // Leave native ownership and all failure evidence intact if dispatch fails.
    let status = launch.wait()?;
    let parent = match dispatcher {
        Ok(value) => {
            value.map(|(iid, exit)| json!({"writer_invocation_id":iid,"exit_code":exit.code()}))
        }
        Err(error) => {
            Some(json!({"error":format!("{error:#}").chars().take(1800).collect::<String>()}))
        }
    };
    Ok(json!({"exit_code":status.code(),"parent":parent}))
}

struct WriterOffer {
    reference: Value,
    offer: Value,
    plan: Value,
    image: PathBuf,
    parent: PathBuf,
    fleet: Value,
}

fn prepare_offer(offer_path: &Path, selector: &Value) -> Result<WriterOffer> {
    let offer_ref = bound(offer_path)?;
    let offer = from_ref(&offer_ref)?;
    let (plan, image) = offered_plan(&offer, selector)?;
    let launcher = aspath(&offer["launcher"])?;
    let lp = launcher.parent().context("launcher directory")?;
    #[cfg(feature = "fixture-post")]
    ensure!(
        lp == rt(WRITER_DIR).join("controller"),
        "foreign V7 synchronous launcher"
    );
    ensure!(
        lp.starts_with(RT)
            && launcher.file_name().is_some_and(|n| n == "run-writer")
            && offer["launcher"]["sha256"] == LAUNCHER
            && bound(launcher)? == offer["launcher"],
        "unqualified synchronous launcher"
    );
    let seal = bound(&lp.join("deployment-seal-receipt.json"))?;
    check_member(lp, text(&seal["sha256"])?, "run-writer")?;
    let fleet = incident::fleet()?;
    let parent_pkg = rt(WRITER_DIR).join("parent-package");
    let parent = check_member(&parent_pkg, PARENT_SEAL, "parent136")?;
    ensure!(offer["parent"] == bound(&parent)?, "foreign parent offer");
    ensure!(
        prepare_mirrors(&offer, &fleet, &parent)?,
        "writer, status and mirror reservations do not fit"
    );
    ensure!(
        incident::fleet()? == fleet,
        "fleet advanced before writer selection"
    );
    Ok(WriterOffer {
        reference: offer_ref,
        offer,
        plan,
        image,
        parent,
        fleet,
    })
}

pub(super) fn before_post(done: &Value) -> Result<File> {
    outcome::wait_file(&ready_path())?;
    let (selector, ready) = registration()?;
    let lock = open_operation(&ready)?;
    let state = rt(DIR).join("state");
    let selection = state.join(SELECTED);
    let offer_path = rt(DIR).join("OFFER.json");
    if selection.try_exists()? {
        let selection = from_ref(&bound(&selection)?)?;
        ensure!(
            selection["semantic_complete"] == *done,
            "different prior semantic completion"
        );
        let offer = from_ref(&selection["offer"])?;
        ensure!(
            state.join("writer-exit.json").try_exists()?
                || Path::new(BASE).join("prestart-intent.json").try_exists()?,
            "unanswered writer submission requires reconciliation"
        );
        drop(lock);
        return settled(&offer, &selector, &ready);
    }
    before_submission()?;
    drained(&native(E)?, E)?;
    drained(&native(W)?, W)?;
    empty_candidate()?;
    let decision = state.join("post-selected.json");
    if decision.try_exists()? {
        let prior = from_ref(&bound(&decision)?)?;
        ensure!(
            prior["selector"] == selector && prior["semantic_complete"] == *done,
            "different post selection"
        );
        return Ok(lock);
    }
    let prepared = if offer_path.try_exists()? {
        prepare_offer(&offer_path, &selector)
    } else {
        Err(anyhow::anyhow!(
            "no qualified epoch 136 offer at this boundary"
        ))
    };
    let WriterOffer {
        reference: offer_ref,
        offer,
        plan,
        image,
        parent,
        fleet,
    } = match prepared {
        Ok(v) => v,
        Err(e) => {
            // No writer can start in this window. Preserve the reason and let
            // the already qualified 145 verifier run its own complete price.
            drained(&native(W)?, W)?;
            empty_candidate()?;
            platform::save(
                &decision,
                &json!({"selector":selector,"semantic_complete":done,"reason":format!("{e:#}").chars().take(1800).collect::<String>()}),
            )?;
            return Ok(lock);
        }
    };
    let launcher = aspath(&offer["launcher"])?;
    platform::save(
        &selection,
        &json!({"offer":offer_ref,"fleet":fleet,"semantic_complete":done}),
    )?;
    drop(lock);
    let result = run_session(launcher, &parent, &offer, &plan, &fleet, &image)?;
    platform::save(
        &state.join("writer-exit.json"),
        &json!({"selection":bound(&selection)?,"result":result}),
    )?;
    settled(&offer, &selector, &ready)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(
        feature = "fixture-post",
        not(any(
            feature = "v5n-136-post",
            feature = "v5o-136-post",
            feature = "v5q-136-post"
        ))
    ))]
    #[test]
    fn only_the_selected_v7b_and_v13b_can_follow_the_fixture_worker() {
        let actual =
            from_ref(&bound(&rt(WRITER_DIR).join("production-plan.json")).unwrap()).unwrap();
        fixture_plan(&actual).unwrap();
        let mut earlier = actual.clone();
        earlier["holding145_semantic_worker"]["path"] = json!(rt(
            "epoch145-semantic-continuity-20261121-v1/V5E_ACTUAL_ADVANCING_WORKER.json"
        ));
        assert!(fixture_plan(&earlier).is_err());
        let mut earlier = actual.clone();
        earlier["holding145_completion"]["seal"]["path"] = json!(rt(
            "epoch145-semantic-continuity-20261121-v1/tools-v13/deployment-seal-receipt.json"
        ));
        assert!(fixture_plan(&earlier).is_err());
        let selector = json!({"path":ready_path(),"sha256":"f".repeat(64)});
        let old_plan = json!({"selector":selector,"writer_plan":{"path":rt("epoch136-joint-writer-20261122-v7/registered-production-plan.json"),"sha256":"a".repeat(64)}});
        assert!(offered_plan(&old_plan, &selector).is_err());
        assert!(!crate::incident::handles("follow-v5e"));
        assert!(crate::incident::handles("inspect-v5f"));
        assert!(crate::incident::handles("follow-v5f"));
        // Read-only inspection of the recorded closure leaves the original controller lock free.
        assert!(
            previous_locks().unwrap()[0]
                .ends_with("epoch145-v5e-delivery-handoff-20261121-v1/state/controller.lock")
        );
    }
    #[test]
    fn writer_custody_requires_the_original_exclusive_kernel_flock() {
        let dir = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let fixture = dir.join(format!("145-writer-flock-test-{}", std::process::id()));
        let fd = OpenOptions::new()
            .create_new(true)
            .mode(0o600)
            .read(true)
            .write(true)
            .open(&fixture)
            .unwrap();
        let pid = std::process::id() as i32;
        assert!(owned_lock(pid, &fixture).is_err());
        assert_eq!(
            unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
            0
        );
        assert!(owned_lock(pid, &fixture).is_err());
        assert_eq!(
            unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        owned_lock(pid, &fixture).unwrap();
        assert!(owned_lock(1, &fixture).is_err());
        let meta = fd.metadata().unwrap();
        let spec = json!({"path":LOCK,"device":meta.dev(),"inode":meta.ino()});
        if meta.uid() == 0 && meta.gid() == 0 {
            compare_lock_identity(&meta, &spec).unwrap();
        }
        let mut other = spec;
        other["inode"] = json!(meta.ino() + 1);
        assert!(compare_lock_identity(&meta, &other).is_err());
        fs::remove_file(&fixture).unwrap();
    }
}
