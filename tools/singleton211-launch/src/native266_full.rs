//! First finite epoch 266 entry replay, using the original v165 delivery booking.
use super::*;
use std::os::unix::process::CommandExt;
mod entries;
mod funding;
mod gate;
mod start;

const V: &str = "/var/lib/jetstreamer";
const STATE: &str = "/var/lib/jetstreamer/horizon266-native-full-v165-a1";
const CTRL: &str = "horizon266-native-full-v165-a1.service";
const SNAPROOT: &str = "/var/lib/jetstreamer/horizon-contiguous-266-266-current-46b4b4a-v1";
const INPUT: &str =
    "/var/lib/jetstreamer/horizon266-bootstrap-measure-067e29e0-v155-v1/inputs.json";
const INPUT_SHA: &str = "383502fd0018bfc694e6a3fd2328ddb4e26afa4315551eb42037a513a522c169";
const GUARD: &str =
    "/var/lib/jetstreamer/horizon251-published-guard-20261118-v1/horizon251-standalone-guard";
const GUARD_SHA: &str = "938889f9dcca0b4bf271cf8c2cbad985edc3d841f944d132f1e96c8fad81386d";
const BOOT: &str = "3b17d005-5c3a-4a0e-8841-da097e0957b5";
const RECEIPTS: u64 = 768 << 20; // Two retained 256 MiB QA images and 256 MiB controls.
const GUARD_MEM: u64 = 1 << 30;
const CONTROL_MEM: u64 = 256 << 20;
const MAIN: &str = "01a1f8f4-293b-7a91-a36e-2e7658bba721";
const MODES: [&str; 3] = ["qa-disk", "qa-memory", "pilot"];

#[derive(Clone)]
struct Profile {
    mode: String,
    unit: String,
    guard: String,
    timer: String,
    root: PathBuf,
    state: PathBuf,
}
impl Profile {
    fn new(mode: &str) -> Result<Self> {
        ensure!(MODES.contains(&mode), "unknown epoch 266 operation");
        let suffix = if mode == "pilot" {
            String::new()
        } else {
            format!("-{mode}")
        };
        let g = format!("horizon-266-general-protective{suffix}-v1");
        Ok(Self {
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
    original_boot()?;
    if matches!(
        args.first().map(String::as_str),
        Some("wait" | "guard" | "failsafe")
    ) {
        ensure!(args.len() == 4, "expected mode, bound path and digest");
        let prof = Profile::new(&args[1])?;
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
            r["schema"] == "horizon266-first-entry-native-review-v1" && r["Main_accepted"] == true,
            "epoch 266 review"
        );
        ensure!(
            r["root"] == STATE
                && r["producer_epoch"] == 266
                && r["publication_authorized"] == false,
            "entry qualification scope"
        );
        let out = PathBuf::from(&args[3]);
        ensure!(
            out.starts_with(STATE) && out.parent() == Some(Path::new(STATE)),
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
            return entries::witness(&mut n);
        }
        let first = funding::elect(&mut n, &r, None)?;
        save_json(&out, "initial-election.json", &first)?;
        if args[0] == "elect" {
            return Ok(first);
        }
        ensure!(args[0] == "run", "unknown epoch 266 controller operation");
        let manager = n.show(CTRL)?;
        ensure!(
            text(&manager, "MainPID")?.parse::<u32>()? == std::process::id()
                && text(&manager, "MemoryMax")?.parse::<u64>()? == CONTROL_MEM
                && manager["InvocationID"] == std::env::var("INVOCATION_ID")?
                && manager["NRestarts"] == "0"
                && manager["MemorySwapMax"] == "0",
            "control must run in booked PID1 envelope"
        );
        start::run(&mut n, &r, &review, &image)
    }
}
fn rows<'a>(v: &'a Value, k: &str) -> Result<&'a Vec<Value>> {
    v[k].as_array()
        .with_context(|| format!("missing array {k}"))
}
