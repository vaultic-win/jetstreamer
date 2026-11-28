//! First finite epoch 266 entry replay, using the original v165 delivery booking.
use super::*;
use std::os::unix::process::CommandExt;
mod bounded;
pub(crate) mod capped_cold;
pub(crate) mod closed266_for257;
mod entries;
mod epoch228;
mod epoch228_peer;
mod epoch228_storage;
mod funding;
mod gate;
pub(crate) mod peer228_extents;
pub(crate) mod peer261;
mod start;
mod stopped;
mod successor;
mod turnover;
pub(crate) mod turnover_window;

const V: &str = "/var/lib/jetstreamer";
const STATE: &str = "/var/lib/jetstreamer/horizon266-native-full-v165-a2";
const CTRL: &str = "horizon266-native-full-v165-a2.service";
const SNAPROOT: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1";
const INPUT: &str =
    "/var/lib/jetstreamer/horizon266-bootstrap-measure-067e29e0-v155-v1/inputs.json";
const INPUT_SHA: &str = "383502fd0018bfc694e6a3fd2328ddb4e26afa4315551eb42037a513a522c169";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
const RECEIPTS: u64 = 1024 << 20; // Three retained 256 MiB QA images and 256 MiB controls.
const GUARD_MEM: u64 = 1 << 30;
const CONTROL_MEM: u64 = 256 << 20;
const MAIN: &str = "01a1f8f4-293b-7a91-a36e-2e7658bba721";
const MODES: [&str; 3] = ["qa-disk", "qa-memory", "pilot"];

#[derive(Copy, Clone, PartialEq, Eq)]
enum Lane {
    Epoch266,
    Instructions266,
    Turnover266,
    Bounded266,
    BoundedRetry266,
    Epoch228,
}
impl Lane {
    fn is_bounded(self) -> bool {
        matches!(self, Self::Bounded266 | Self::BoundedRetry266)
    }
    fn epoch(self) -> u64 {
        match self {
            Self::Epoch266
            | Self::Instructions266
            | Self::Turnover266
            | Self::Bounded266
            | Self::BoundedRetry266 => 266,
            Self::Epoch228 => 228,
        }
    }
    fn state(self) -> &'static str {
        match self {
            Self::Epoch266 => STATE,
            Self::Instructions266 => successor::STATE,
            Self::Turnover266 => turnover::STATE,
            Self::Bounded266 => bounded::STATE,
            Self::BoundedRetry266 => bounded::RETRY_STATE,
            Self::Epoch228 => epoch228::STATE,
        }
    }
    fn controller(self) -> &'static str {
        match self {
            Self::Epoch266 => CTRL,
            Self::Instructions266 => successor::CONTROLLER,
            Self::Turnover266 => turnover::CONTROLLER,
            Self::Bounded266 => bounded::CONTROLLER,
            Self::BoundedRetry266 => bounded::RETRY_CONTROLLER,
            Self::Epoch228 => epoch228::CTRL,
        }
    }
    fn command(self) -> &'static str {
        match self {
            Self::Epoch266 => "epoch266-full",
            Self::Instructions266 => "epoch266-instructions",
            Self::Turnover266 => "epoch266-turnover",
            Self::Bounded266 => "epoch266-bounded",
            Self::BoundedRetry266 => "epoch266-bounded-retry",
            Self::Epoch228 => "epoch228-full",
        }
    }
    fn guard(self) -> (&'static str, &'static str) {
        match self {
            Self::Epoch266
            | Self::Instructions266
            | Self::Turnover266
            | Self::Bounded266
            | Self::BoundedRetry266 => (GUARD, GUARD_SHA),
            Self::Epoch228 => (epoch228::GUARD, epoch228::GUARD_SHA),
        }
    }
}
#[derive(Clone)]
struct Profile {
    lane: Lane,
    mode: String,
    unit: String,
    guard: String,
    timer: String,
    root: PathBuf,
    state: PathBuf,
}
impl Profile {
    fn new(lane: Lane, mode: &str) -> Result<Self> {
        ensure!(MODES.contains(&mode), "unknown epoch 266 operation");
        let suffix = if mode == "pilot" {
            String::new()
        } else {
            format!("-{mode}{}", if mode == "qa-disk" { "-a2" } else { "" })
        };
        if matches!(
            lane,
            Lane::Instructions266 | Lane::Turnover266 | Lane::Bounded266 | Lane::BoundedRetry266
        ) {
            let generation = if lane == Lane::Turnover266 {
                "v194"
            } else {
                "v169"
            };
            let tag = if lane == Lane::BoundedRetry266 {
                format!("266-capped-bounded{suffix}-v210")
            } else if lane == Lane::Bounded266 {
                format!("266-capped-bounded{suffix}-v207")
            } else {
                format!("266-instructions-2789f821{suffix}-{generation}")
            };
            let guard = format!("horizon-{tag}-protective");
            return Ok(Self {
                lane,
                mode: mode.into(),
                unit: format!("horizon-qualify-{tag}.service"),
                guard: format!("{guard}.service"),
                timer: format!("{guard}.timer"),
                root: Path::new("/home/ubuntu/.jetstreamer-private")
                    .join(format!("qualification-{tag}")),
                state: Path::new(lane.state()).join(mode),
            });
        }
        let g = format!("horizon-266-general-protective{suffix}-v1");
        if lane == Lane::Epoch228 {
            let g = format!("horizon-228-root-tail-protective{suffix}-v1");
            let (unit, root) = if mode == "pilot" {
                (
                    "horizon-qualify-228-demotion-root-tail-16d4b158-v1.service".into(),
                    "qualification-228-demotion-root-tail-v1".into(),
                )
            } else {
                (
                    format!("horizon-qualify-228-general{suffix}-v1.service"),
                    format!("qualification-228-general{suffix}-v1"),
                )
            };
            return Ok(Self {
                lane,
                mode: mode.into(),
                unit,
                guard: format!("{g}.service"),
                timer: format!("{g}.timer"),
                root: Path::new("/home/ubuntu/.jetstreamer-private").join(root),
                state: Path::new(lane.state()).join(mode),
            });
        }
        Ok(Self {
            lane,
            mode: mode.into(),
            unit: format!("horizon-qualify-266-general{suffix}-v1.service"),
            guard: format!("{g}.service"),
            timer: format!("{g}.timer"),
            root: PathBuf::from(format!(
                "/home/ubuntu/.jetstreamer-private/qualification-266-general{suffix}-v1"
            )),
            state: Path::new(STATE).join(mode),
        })
    }
}
fn bound_at(p: &Path) -> Result<Bound> {
    Ok(Bound::new(p, hash(p)?))
}
fn own_image(r: &Value) -> Result<Bound> {
    let b = binding(&r["controller_image"])?;
    b.artifact()?;
    ensure!(
        b.path.file_name().is_some_and(|s| s == "native-fit")
            && fs::read_link("/proc/self/exe")? == b.path
            && metadata_identity(&fs::metadata("/proc/self/exe")?) == identity(&b.path)?,
        "wrong mapped epoch 266 control image"
    );
    let parent = b.path.parent().context("image directory")?;
    let seal = bound_at(&parent.join("deployment-seal-receipt.json"))?.sealed()?;
    ensure!(
        rows(&seal, "members")?
            .iter()
            .any(|m| m["name"] == "native-fit" && m["sha256"] == b.sha256),
        "image outside immutable source qualification"
    );
    Ok(b)
}
fn original_boot() -> Result<()> {
    ensure!(
        fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() == BOOT,
        "original boot differs"
    );
    Ok(())
}
fn system(n: &mut Native, exe: &str, args: &[String]) -> Result<Vec<u8>> {
    n.run(exe, &args.iter().map(String::as_str).collect::<Vec<_>>())
}
fn dir(p: &Path, mode: u32) -> Result<()> {
    fs::create_dir(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn public(root: &Path, leaf: &str, v: &Value) -> Result<Bound> {
    let b = save_json(root, &format!(".{leaf}.part"), v)?;
    fs::set_permissions(&b.path, fs::Permissions::from_mode(0o444))?;
    let path = root.join(leaf);
    let from = std::ffi::CString::new(b.path.as_os_str().as_encoded_bytes())?;
    let to = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    File::open(root)?.sync_all()?;
    Ok(Bound::new(path, b.sha256))
}
fn command_field(n: &mut Native, u: &str, field: &str) -> Result<String> {
    Ok(std::str::from_utf8(&n.run(
        "/usr/bin/systemctl",
        &["show", u, "--value", "--property", field],
    )?)?
    .trim()
    .to_owned())
}
fn digest_file(p: &str, sha: &str) -> Result<Value> {
    Bound::new(p, sha).json()
}

pub fn dispatch(args: &[String]) -> Result<Value> {
    controller(Lane::Epoch266, args)
}
pub fn dispatch_instructions(args: &[String]) -> Result<Value> {
    controller(Lane::Instructions266, args)
}
pub fn measure_turnover_allocation(path: &Path) -> Result<Value> {
    observed_turnover(path, "allocation-", "allocation.json", turnover::allocation)
}

/// Read-only candidate census under the finite qualification booking.
pub fn measure_261_turnover(path: &Path, fleet: &Path, sha: &str) -> Result<Value> {
    measure_cold_fit(
        path,
        fleet,
        sha,
        "horizon261-turnover-fit-check-",
        "fit-261-",
        peer261::assess,
    )
}

pub fn measure_capped_266(path: &Path, fleet: &Path, sha: &str) -> Result<Value> {
    measure_cold_fit(
        path,
        fleet,
        sha,
        "horizon266-capped-fit-check-",
        "fit-capped-266-",
        capped_cold::assess,
    )
}

pub fn measure_closed266_for257(path: &Path, fleet: &Path, sha: &str) -> Result<Value> {
    measure_cold_fit(
        path,
        fleet,
        sha,
        "horizon257-closed266-fit-",
        "fit-closed266-for257-",
        closed266_for257::assess,
    )
}

fn measure_cold_fit(
    path: &Path,
    fleet: &Path,
    sha: &str,
    controller_prefix: &str,
    directory_prefix: &str,
    assess: impl FnOnce(&mut Native, &Bound, &str, bool) -> Result<Value>,
) -> Result<Value> {
    let controller = fs::read_to_string("/proc/self/cgroup")?;
    let unit = controller
        .trim()
        .strip_prefix("0::/system.slice/")
        .context("funded qualification controller")?;
    ensure!(
        unit.starts_with(controller_prefix) && unit.ends_with(".service"),
        "unexpected qualification controller"
    );
    observed_turnover(path, directory_prefix, "assessment.json", |n| {
        let owner = n.show(unit)?;
        let iid = std::env::var("INVOCATION_ID")?;
        ensure!(
            text(&owner, "MainPID")?.parse::<u32>()? == std::process::id(),
            "not the controller process"
        );
        live::finite_owner(&owner, unit, &iid, 256 << 20)?;
        let f = Bound::new(fleet, sha);
        let result = assess(n, &f, unit, false)?;
        live::same_owner(&owner, &n.show(unit)?)?;
        Ok(json!({"assessment":result,"admission_authorized":false,"producer_started":false}))
    })
}

pub fn qualify_turnover_window(path: &Path) -> Result<Value> {
    observed_turnover(
        path,
        "peer-window-",
        "qualification.json",
        turnover_window::qualify,
    )
}

fn observed_turnover(
    path: &Path,
    prefix: &str,
    file: &str,
    observe: impl FnOnce(&mut Native) -> Result<Value>,
) -> Result<Value> {
    ensure!(
        unsafe { libc::geteuid() } == 0
            && std::env::var("CODEX_THREAD_ID")? == MAIN
            && path.parent() == Some(Path::new(turnover::STATE))
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(prefix)),
        "turnover allocation evidence namespace or owner"
    );
    trusted_parents(path)?;
    dir(path, 0o700)?;
    let mut n = Native {
        root: path.to_owned(),
        counter: 0,
        deadline: Some(mono()? + 90_000_000),
    };
    let report = observe(&mut n)?;
    Ok(json!(save_json(path, file, &report)?))
}

pub fn dispatch_bounded_retry(args: &[String]) -> Result<Value> {
    controller(Lane::BoundedRetry266, args)
}
pub fn dispatch_bounded(args: &[String]) -> Result<Value> {
    controller(Lane::Bounded266, args)
}
pub fn dispatch_turnover(args: &[String]) -> Result<Value> {
    controller(Lane::Turnover266, args)
}
pub fn dispatch228(args: &[String]) -> Result<Value> {
    if args.first().is_some_and(|op| op == "entries-sealed") {
        ensure!(
            unsafe { libc::geteuid() } == 0
                && std::env::var("CODEX_THREAD_ID")? == MAIN
                && args.len() == 3,
            "Main requires entries-sealed SELF_SHA256 NEW_EVIDENCE_DIR"
        );
        original_boot()?;
        let image = fs::read_link("/proc/self/exe")?;
        let base = image.parent().context("entry witness package")?;
        let package = base
            .file_name()
            .and_then(|v| v.to_str())
            .context("entry package name")?;
        let attempt = package
            .strip_prefix("horizon228-private-entry-consumers-a")
            .and_then(|s| s.strip_suffix("-qualified"))
            .context("entry witness deployment")?;
        ensure!(
            base.parent() == Some(Path::new(V))
                && attempt
                    .parse::<u8>()
                    .is_ok_and(|n| n != 0 && n.to_string() == attempt)
                && image
                    .file_name()
                    .is_some_and(|name| name == "horizon-native257-fit"),
            "incorrect witness package"
        );
        let member = Bound::new(&image, &args[1]);
        member.artifact()?;
        ensure!(
            metadata_identity(&fs::metadata("/proc/self/exe")?) == identity(&image)?
                && hash(Path::new("/proc/self/exe"))? == member.sha256,
            "another mapped witness image"
        );
        let seal = bound_at(&base.join("deployment-seal-receipt.json"))?.sealed()?;
        ensure!(
            rows(&seal, "members")?
                .iter()
                .filter(|v| v["name"] == "horizon-native257-fit" && v["sha256"] == member.sha256)
                .count()
                == 1,
            "entry witness outside qualified deployment"
        );
        let out = PathBuf::from(&args[2]);
        let attempt = out
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix("first-entries-"))
            .context("entry capture attempt")?;
        ensure!(
            out.parent() == Some(Path::new(epoch228::STATE))
                && attempt
                    .parse::<u32>()
                    .is_ok_and(|n| n > 0 && n.to_string() == attempt),
            "entry evidence namespace"
        );
        trusted_parents(&out)?;
        dir(&out, 0o700)?;
        return entries::witness(
            &mut Native {
                root: out,
                counter: 0,
                deadline: Some(mono()? + 90_000_000),
            },
            Lane::Epoch228,
        );
    }
    controller(Lane::Epoch228, args)
}
fn controller(lane: Lane, args: &[String]) -> Result<Value> {
    original_boot()?;
    if matches!(
        args.first().map(String::as_str),
        Some("wait" | "guard" | "failsafe")
    ) {
        ensure!(args.len() == 4, "expected mode, bound path and digest");
        let prof = Profile::new(lane, &args[1])?;
        let b = Bound::new(&*args[2], &args[3]);
        if args[0] == "wait" {
            gate::wait(&prof, &b)
        } else {
            gate::guard(&prof, &b, args[0] == "failsafe")
        }
    } else {
        ensure!(
            unsafe { libc::geteuid() } == 0
                && std::env::var("CODEX_THREAD_ID")? == MAIN
                && args.len() == 4,
            "Main requires elect|run, sealed review, digest, and evidence directory"
        );
        let review = Bound::new(&*args[1], &args[2]);
        let r = review.sealed()?;
        let image = own_image(&r)?;
        ensure!(
            r["schema"] == format!("horizon{}-first-entry-native-review-v1", lane.epoch())
                && r["Main_accepted"] == true,
            "epoch 266 review"
        );
        ensure!(
            r["root"] == lane.state()
                && r["producer_epoch"] == lane.epoch()
                && r["publication_authorized"] == false,
            "entry qualification scope"
        );
        let out = PathBuf::from(&args[3]);
        ensure!(
            out.parent() == Some(Path::new(lane.state())),
            "evidence namespace"
        );
        trusted_parents(&out)?;
        dir(&out, 0o700)?;
        let mut n = Native {
            root: out.clone(),
            counter: 0,
            deadline: Some(mono()? + 900_000_000),
        };
        if args[0] == "entries" {
            ensure!(
                lane != Lane::Epoch228,
                "use the archive parent receipts for epoch 228"
            );
            return entries::witness(&mut n, lane);
        }
        let first = funding::elect(lane, &mut n, &r, None)?;
        save_json(&out, "initial-election.json", &first)?;
        if args[0] == "elect" {
            return Ok(first);
        }
        ensure!(args[0] == "run", "unknown epoch 266 controller operation");
        let manager = n.show(lane.controller())?;
        ensure!(
            text(&manager, "MainPID")?.parse::<u32>()? == std::process::id()
                && text(&manager, "MemoryMax")?.parse::<u64>()? == CONTROL_MEM
                && manager["InvocationID"] == std::env::var("INVOCATION_ID")?
                && manager["NRestarts"] == "0"
                && manager["MemorySwapMax"] == "0",
            "control must run in booked PID1 envelope"
        );
        let runtime = if lane == Lane::Bounded266 {
            bounded::runtime_image(&r)?
        } else {
            image
        };
        start::run(lane, &mut n, &r, &review, &runtime)
    }
}
fn rows<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array()
        .with_context(|| format!("missing array {k}"))
}
