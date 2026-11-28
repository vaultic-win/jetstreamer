//! Admit one synchronous publication from the committed singleton.
//! The fleet capacity provider and receiver are deployed, digest-bound programs.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions, Permissions},
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const RT: &str = "/var/lib/jetstreamer/horizon_runtime_data";
#[cfg(all(feature = "cold167", not(feature = "source167")))]
compile_error!("cold167 requires the source167 singleton profile");
#[cfg(all(feature = "cold170", not(feature = "retry170")))]
compile_error!("cold170 requires the retry170 singleton profile");
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
#[cfg_attr(feature = "cold167", path = "cold167_profile.rs")]
#[cfg_attr(feature = "cold168", path = "cold168_profile.rs")]
#[cfg_attr(feature = "cold170", path = "cold170_profile.rs")]
mod peer_profile;

#[cfg(not(any(
    feature = "retry10",
    feature = "metered168",
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
mod deployment {
    pub(super) const DELIVERY: &str = "epoch166-committed-delivery-20261121-v1";
    pub(super) const WITNESS: &str = "epoch166-terminal-20261121-v1";
    pub(super) const UNIT: &str = "horizon-publish-166-committed.service";
    pub(super) const ORIGIN: &str = "horizon-qualify-independent-cold166-20261120-v1.service";
    pub(super) const GENERATION: &str = "fa16ee2f14fe44ecbc37c59e197553ac";
    pub(super) const LIVE: &str =
        "23817cd4c05aee995728b4413ff36c26ef72df5a9795df9691a2d699039d30fe";
    pub(super) const RECEIVER: &str =
        "55fdf7dd39661229fce3559428217d295e7644af5624039a592b14191c8d6f86";
    pub(super) const PUBLISHER: &str =
        "b734b3cc25696ea6329cf3c9fad9730f1ee789d402602826d5e206298c2c4422";
    pub(super) const FLEET_FIELD: &str = "terminal166_local_commit";
    pub(super) const FIT_PATH: &str =
        "epoch166-publication-capacity-20261121-v1/tools/publication-fit";
    pub(super) const RECEIVER_PATH: &str = "epoch166-receiver-20261121-v1/receiver-v1/receiver.py";
    pub(super) const PUBLISHER_PATH: &str = "publisher-v1/publisher";
}

// Both generations remain reachable from their own sealed event packages.
#[cfg(all(
    any(feature = "retry10", feature = "metered168"),
    feature = "transition_reader"
))]
macro_rules! reader_package {
    ($original:literal, $successor:literal) => {
        $successor
    };
}
#[cfg(all(
    any(feature = "retry10", feature = "metered168"),
    not(feature = "transition_reader")
))]
macro_rules! reader_package {
    ($original:literal, $successor:literal) => {
        $original
    };
}

#[cfg(feature = "retry10")]
#[path = "../horizon_epoch166_retry10_delivery_20261121_v1/generation.rs"]
mod generation;
#[cfg(feature = "retry10")]
mod deployment {
    pub(super) const DELIVERY: &str = "epoch166-retry10-delivery-20261121-v1";
    pub(super) const WITNESS: &str = super::generation::TERMINAL_ROOT;
    pub(super) const UNIT: &str = "horizon-publish-166-retry10-committed.service";
    pub(super) const ORIGIN: &str = super::generation::PRODUCER_UNIT;
    pub(super) const GENERATION: &str = super::generation::PRODUCER_IID;
    pub(super) const LIVE: &str = super::generation::LIVE_SHA;
    pub(super) const RECEIVER: &str = env!("HORIZON_HELD_RECEIVER_SHA256");
    pub(super) const PUBLISHER: &str = env!("HORIZON_HELD_PUBLISHER_SHA256");
    pub(super) const FLEET_FIELD: &str = "recovered166_local_commit";
    pub(super) const FIT_PATH: &str = reader_package!(
        "epoch166-retry10-delivery-20261121-v1/capacity-tools/publication-fit",
        "epoch166-retry10-delivery-20261121-v1/capacity-tools-v3/publication-fit"
    );
    pub(super) const RECEIVER_PATH: &str = reader_package!(
        "epoch166-retry10-delivery-20261121-v1/publisher-tools/receive.py",
        "epoch166-retry10-delivery-20261121-v1/publisher-tools-v2/receive.py"
    );
    pub(super) const PUBLISHER_PATH: &str =
        reader_package!("publisher-tools/publisher", "publisher-tools-v2/publisher");
}
#[cfg(feature = "metered168")]
mod deployment {
    pub(super) const DELIVERY: &str = "epoch168-current-delivery-20261121-v1";
    pub(super) const WITNESS: &str = DELIVERY;
    pub(super) const UNIT: &str = "horizon-publish-168-metered-committed.service";
    pub(super) const ORIGIN: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
    pub(super) const GENERATION: &str = "9cebb1d022124fb08588e93e055d5446";
    pub(super) const LIVE: &str =
        "11c7cbb269258849d637259fad7a005f3e1255fbeaac99e3239f089495164ac7";
    pub(super) const RECEIVER: &str = env!("HORIZON_HELD_RECEIVER_SHA256");
    pub(super) const PUBLISHER: &str = env!("HORIZON_HELD_PUBLISHER_SHA256");
    pub(super) const FLEET_FIELD: &str = "metered168_local_commit";
    pub(super) const FIT_PATH: &str = reader_package!(
        "epoch168-current-delivery-20261121-v1/capacity-tools/publication-fit",
        "epoch168-current-delivery-20261121-v1/capacity-tools-v2/publication-fit"
    );
    pub(super) const RECEIVER_PATH: &str = reader_package!(
        "epoch168-current-delivery-20261121-v1/publisher-tools/receiver.py",
        "epoch168-current-delivery-20261121-v1/publisher-tools-v2/receiver.py"
    );
    pub(super) const PUBLISHER_PATH: &str =
        reader_package!("publisher-tools/publisher", "publisher-tools-v2/publisher");
}

#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
mod deployment {
    pub(super) use super::peer_profile::{DELIVERY, GENERATION, LIVE, ORIGIN, UNIT};
    pub(super) const WITNESS: &str = DELIVERY;
    pub(super) const FLEET_FIELD: &str = super::peer_profile::controller::FIELD;
    pub(super) const FIT_PATH: &str = super::peer_profile::controller::FIT;
    pub(super) const RECEIVER_PATH: &str = super::peer_profile::controller::RECEIVER;
    pub(super) const RECEIVER: &str = env!("HORIZON_HELD_RECEIVER_SHA256");
    pub(super) const PUBLISHER: &str = env!("HORIZON_HELD_PUBLISHER_SHA256");
    pub(super) const PUBLISHER_PATH: &str = "publisher-tools/publisher";
}
#[cfg(any(
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
))]
use peer_profile::EPOCH;
#[cfg(feature = "metered168")]
const EPOCH: u64 = 168;
#[cfg(not(any(
    feature = "metered168",
    feature = "cold168",
    feature = "source167",
    feature = "retry170",
    feature = "full172"
)))]
const EPOCH: u64 = 166;
use deployment::*;
const NATIVE: &str = "dea7acbfa01d0beae046549823ebce48e7086a7276349b4530ed35c04a2d4efb";
const MEMORY: u64 = 2 << 30;
const WITNESS_MODE: u32 = if cfg!(any(
    feature = "cold167",
    feature = "cold168",
    feature = "cold170"
)) {
    0o400
} else {
    0o600
};
const PUBLICATION_CPU_MICROS: u64 = if EPOCH == 172 { 500_000 } else { 1_000_000 };

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn field<'a>(doc: &'a Value, key: &str) -> Result<&'a str> {
    doc[key].as_str().with_context(|| format!("missing {key}"))
}
fn number(doc: &Value, key: &str) -> Result<u64> {
    doc[key].as_u64().with_context(|| format!("missing {key}"))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn binding(path: &Path, digest: &str) -> Value {
    json!({"path":path,"sha256":digest})
}
fn root_file(path: &Path, mode: u32) -> Result<File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical {}",
        path.display()
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == 0 && m.gid() == 0 && m.mode() & 0o7777 == mode,
        "wrong file owner, type or mode {}",
        path.display()
    );
    Ok(f)
}
fn read_json(path: &Path, mode: u32, max: u64) -> Result<(Value, Value)> {
    let f = root_file(path, mode)?;
    let mut buf = Vec::new();
    f.take(max + 1).read_to_end(&mut buf)?;
    ensure!(
        !buf.is_empty() && buf.len() as u64 <= max,
        "invalid receipt size at {}",
        path.display()
    );
    Ok((serde_json::from_slice(&buf)?, binding(path, &sha(&buf))))
}
fn program(path: &Path, digest: &str) -> Result<()> {
    ensure!(hex(digest, 64), "invalid program SHA-256");
    let f = root_file(path, 0o555)?;
    ensure!(f.metadata()?.len() <= 128 << 20, "oversize program");
    let mut hash = Sha256::new();
    std::io::copy(&mut f.take((128 << 20) + 1), &mut hash)?;
    ensure!(
        format!("{:x}", hash.finalize()) == digest,
        "program digest changed {}",
        path.display()
    );
    Ok(())
}
fn dir(path: &Path, create: bool) -> Result<()> {
    if create {
        DirBuilder::new().mode(0o700).create(path)?;
    }
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700
            && m.dev() == fs::metadata("/home/sol")?.dev(),
        "publication directory ownership or HOME device changed {}",
        path.display()
    );
    Ok(())
}
fn put(path: &Path, doc: &Value) -> Result<Value> {
    let parent = path.parent().context("receipt parent")?;
    let mut f = tempfile::NamedTempFile::new_in(parent)?;
    let mut bytes = serde_json::to_vec_pretty(doc)?;
    bytes.push(b'\n');
    f.write_all(&bytes)?;
    f.as_file().set_permissions(Permissions::from_mode(0o400))?;
    f.as_file().sync_all()?;
    f.persist_noclobber(path)?;
    File::open(parent)?.sync_all()?;
    Ok(binding(path, &sha(&bytes)))
}
fn validate_terminal(live: &Value, live_ref: &Value, t: &Value, boot: &str) -> Result<()> {
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    ensure!(
        live["schema"] == peer_profile::LIVE_SCHEMA,
        "wrong singleton live schema"
    );
    let event = &t["manager_terminal"];
    ensure!(
        live["epoch"] == EPOCH
            && live["boot_id"] == boot
            && live["native"]["manager"]["Id"] == ORIGIN
            && live["native"]["manager"]["InvocationID"] == GENERATION
            && t["schema"] == format!("terminal{EPOCH}-success-v1")
            && t["epoch"] == EPOCH
            && t["live"] == *live_ref
            && t["source_admission"] == live["admission"]
            && t["producer_unit"] == ORIGIN
            && t["producer_invocation_id"] == GENERATION
            && t[format!("terminal_{EPOCH}_disposition")] == "node-published-local-cohort"
            && t["resource_credit_bytes"] == 0
            && t["reservation_ending_bytes"] == 0
            && t["canonical_r2_verified"] == false
            && event["_PID"] == "1"
            && event["_BOOT_ID"] == boot.replace('-', "")
            && event["UNIT"] == ORIGIN
            && event["INVOCATION_ID"] == GENERATION
            && event["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && hex(field(t, "transaction_id")?, 64),
        "original producer terminal differs"
    );
    Ok(())
}
fn source(live: &Value, t: &Value) -> Result<PathBuf> {
    let output = PathBuf::from(field(&live["output"], "path")?);
    let archive = output.join(format!("epoch-{EPOCH}.jet"));
    let d = fs::symlink_metadata(&output)?;
    let m = fs::symlink_metadata(&archive)?;
    let a = &t["local_archive"];
    ensure!(
        output.canonicalize()? == output
            && d.is_dir()
            && d.uid() == 1001
            && d.gid() == 1003
            && live["output"]["device"] == d.dev()
            && live["output"]["inode"] == d.ino()
            && archive.canonicalize()? == archive
            && m.is_file()
            && m.uid() == 1001
            && m.gid() == 1003
            && m.nlink() == 1
            && a["path"] == json!(archive)
            && m.dev() == d.dev()
            && a["device"] == m.dev()
            && a["inode"] == m.ino()
            && a["size"] == m.len()
            && m.len() > 0
            && hex(field(a, "sha256")?, 64),
        "committed archive or directory changed"
    );
    Ok(output)
}
fn capacity(
    f: &Value,
    fleet: &Value,
    terminal: &Value,
    boot: &str,
    iid: &str,
    t: u64,
) -> Result<Value> {
    let measured = number(f, "observed_unix_seconds")?;
    let avail = number(f, "available_bytes")?;
    let floor = number(f, "protected_bytes")?;
    ensure!(
        f["schema"] == format!("horizon-{EPOCH}-publication-fit-v1")
            && f["boot_id"] == boot
            && f["fleet"] == *fleet
            && f["terminal"] == *terminal
            && t.checked_sub(measured).is_some_and(|age| age <= 180)
            && f["publication_cpu_quota_micros"] == PUBLICATION_CPU_MICROS
            && f["publication_memory_bytes"] == MEMORY
            && f["complete_cpu_quota_micros"] == 64_000_000
            && f["complete_memory_plus_reserve_bytes"] == 810_658_050_048u64
            && f["resource_credit_bytes"] == 0
            && f["all_existing_commitments_retained"] == true
            && floor > 0
            && avail >= floor
            && number(f, "required_available_memory_bytes")? > 0
            && number(f, "available_memory_bytes")?
                >= number(f, "required_available_memory_bytes")?,
        "incomplete, stale or non-fitting terminal capacity"
    );
    let mut result = f.clone();
    result["invocation_id"] = json!(iid);
    Ok(result)
}
fn service() -> Result<String> {
    let iid = std::env::var("INVOCATION_ID")?;
    ensure!(
        unsafe { libc::geteuid() } == 0
            && hex(&iid, 32)
            && fs::read_to_string("/proc/self/cgroup")?.trim()
                == format!("0::/system.slice/{UNIT}"),
        "wrong controller owner"
    );
    let out=Command::new("/usr/bin/systemctl").env_remove("SYSTEMD_HOST").args(["show",UNIT,
        "--property=InvocationID,MainPID,CPUQuotaPerSecUSec,MemoryMax,MemorySwapMax,KillMode,Restart"]).output()?;
    ensure!(out.status.success(), "publication manager lookup failed");
    let raw = String::from_utf8(out.stdout)?;
    let props: std::collections::BTreeMap<_, _> =
        raw.lines().filter_map(|l| l.split_once('=')).collect();
    for (key, val) in [
        ("InvocationID", iid.clone()),
        ("MainPID", std::process::id().to_string()),
        (
            "CPUQuotaPerSecUSec",
            if EPOCH == 172 { "500ms" } else { "1s" }.into(),
        ),
        ("MemoryMax", MEMORY.to_string()),
        ("MemorySwapMax", "0".into()),
        ("KillMode", "control-group".into()),
        ("Restart", "no".into()),
    ] {
        ensure!(
            props.get(key) == Some(&val.as_str()),
            "wrong publication service property {key}"
        );
    }
    Ok(iid)
}
fn write_admission(
    base: &Path,
    mode: &str,
    output: &Path,
    terminal: &Value,
    cap: &Value,
) -> Result<Value> {
    let iid = field(cap, "invocation_id")?;
    let boot = field(cap, "boot_id")?;
    let term_ref = &cap["terminal"];
    let run = base.join(format!("run-{iid}"));
    dir(&run, true)?;
    dir(&run.join("scratch"), true)?;
    dir(&run.join("receipts"), true)?;
    File::open(base)?.sync_all()?;
    let c = put(&run.join("capacity.json"), cap)?;
    let observed = number(cap, "observed_unix_seconds")?;
    let a = &terminal["local_archive"];
    let admission = json!({"schema":format!("horizon-epoch{EPOCH}-committed-publication-admission-v1"),
        "operation":"current-reader-sync-retain-local","publication_authorized":mode=="sync","boot_id":boot,"unit":UNIT,
        "invocation_id":iid,"epoch":EPOCH,"source_directory":output,"transaction_id":terminal["transaction_id"],
        "terminal_sha256":term_ref["sha256"],"archive_bytes":a["size"],"archive_sha256":a["sha256"],
        "archive_device":a["device"],"archive_inode":a["inode"],"recorded_unix_seconds":observed,
        "valid_until_unix_seconds":observed.checked_add(180).context("fit expiration overflow")?,
        "minimum_free_bytes":cap["protected_bytes"],"capacity":c});
    put(&run.join("admission.json"), &admission)
}

fn provider_path(runtime: &Path) -> PathBuf {
    if cfg!(feature = "bounded_reader") && cfg!(feature = "paid145_fit") {
        return runtime
            .join(DELIVERY)
            .join("capacity-tools-bounded/publication-fit");
    }
    if cfg!(feature = "paid145_fit") {
        return runtime
            .join(DELIVERY)
            .join("capacity-tools-paid145/publication-fit");
    }
    if cfg!(feature = "focused169_fit") {
        let package = match EPOCH {
            166 => "capacity-tools-v5",
            167 | 170 => "capacity-tools-v3",
            168 => "capacity-tools-v4",
            172 => "capacity-tools-v2",
            _ => unreachable!("no publication capacity profile for this epoch"),
        };
        return runtime.join(DELIVERY).join(package).join("publication-fit");
    }
    if cfg!(feature = "five_source_fit") {
        let package = match EPOCH {
            166 => "capacity-tools-v4",
            167 | 170 => "capacity-tools-v2",
            168 => "capacity-tools-v3",
            172 => "capacity-tools",
            _ => unreachable!("no publication capacity profile for this epoch"),
        };
        return runtime.join(DELIVERY).join(package).join("publication-fit");
    }
    runtime.join(FIT_PATH)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [mode, fleet_path, fleet_sha, fit_sha] = args.as_slice() else {
        anyhow::bail!("usage: controller prepare|sync FLEET FLEET_SHA FIT_SHA")
    };
    ensure!(
        matches!(mode.as_str(), "prepare" | "sync") && hex(fleet_sha, 64),
        "invalid mode or fleet digest"
    );
    let iid = service()?;
    let rt = Path::new(RT);
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let boot = boot.trim();
    let (live, live_ref) = read_json(&rt.join(WITNESS).join("LIVE.json"), WITNESS_MODE, 1 << 20)?;
    ensure!(live_ref["sha256"] == LIVE, "wrong live witness");
    let (terminal, term_ref) = read_json(
        &rt.join(WITNESS).join("TERMINAL_SUCCESS.json"),
        0o400,
        1 << 20,
    )?;
    validate_terminal(&live, &live_ref, &terminal, boot)?;
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    {
        let tool = rt
            .join(WITNESS)
            .join("terminal-tools")
            .join(peer_profile::controller::TERMINAL);
        program(&tool, peer_profile::controller::TERMINAL_SHA)?;
        let inspected = Command::new(&tool).arg("inspect").output()?;
        ensure!(
            inspected.status.success()
                && inspected.stdout.len() <= 1 << 20
                && serde_json::from_slice::<Value>(&inspected.stdout)? == terminal,
            "original terminal inspector differs"
        );
    }
    let output = source(&live, &terminal)?;
    let fleet_path = Path::new(fleet_path);
    ensure!(
        fleet_path.parent().and_then(Path::parent) == Some(rt)
            && fleet_path
                .file_name()
                .is_some_and(|s| s == "ROOT_COMPLETE_OPERATIONAL_FLEET.json"),
        "wrong operational fleet path"
    );
    let (fleet, fleet_ref) = read_json(fleet_path, 0o600, 32 << 20)?;
    ensure!(
        fleet_ref["sha256"] == *fleet_sha
            && fleet["owner"] == "/root"
            && fleet[FLEET_FIELD] == term_ref,
        "fleet has not adopted the original terminal"
    );
    let provider = provider_path(rt);
    program(&provider, fit_sha)?;
    let receiver_dir = rt.join("epoch166-receiver-20261121-v1/receiver-v1");
    let receiver = rt.join(RECEIVER_PATH);
    let native = receiver_dir.join("native");
    let base = rt.join(DELIVERY);
    let publisher = if cfg!(feature = "bounded_reader") {
        base.join("publisher-tools-bounded/publisher")
    } else {
        base.join(PUBLISHER_PATH)
    };
    program(&receiver, RECEIVER)?;
    program(&native, NATIVE)?;
    program(&publisher, PUBLISHER)?;
    dir(&base, false)?;
    let fit = Command::new(&provider)
        .arg(fleet_path)
        .arg(fleet_sha)
        .output()?;
    ensure!(
        fit.status.success(),
        "fresh publication fit failed: {}",
        String::from_utf8_lossy(&fit.stderr)
    );
    ensure!(fit.stdout.len() <= 3 << 20, "oversize capacity evidence");
    let mut cap = capacity(
        &serde_json::from_slice(&fit.stdout)?,
        &fleet_ref,
        &term_ref,
        boot,
        &iid,
        now()?,
    )?;
    cap["provider"] = binding(&provider, fit_sha);
    let receipt = write_admission(&base, mode, &output, &terminal, &cap)?;
    let mut dispatch = Command::new("/usr/bin/python3");
    dispatch.arg("-IB").arg(receiver);
    #[cfg(feature = "metered168")]
    dispatch.arg("--metered168");
    #[cfg(any(
        feature = "cold168",
        feature = "source167",
        feature = "retry170",
        feature = "full172"
    ))]
    dispatch.arg(peer_profile::controller::FLAG);
    Err(dispatch
        .arg(native)
        .arg(NATIVE)
        .arg(publisher)
        .arg(PUBLISHER)
        .arg(mode)
        .arg(field(&receipt, "sha256")?)
        .exec()
        .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "bounded_reader", feature = "paid145_fit"))]
    #[test]
    fn bounded_reader_selects_its_epochs_capacity_provider() {
        let root = Path::new("/fleet");
        assert_eq!(
            provider_path(root),
            root.join(DELIVERY)
                .join("capacity-tools-bounded/publication-fit")
        );
    }

    #[cfg(any(
        feature = "five_source_fit",
        feature = "focused169_fit",
        feature = "paid145_fit"
    ))]
    #[test]
    #[ignore = "requires the sealed five-source capacity package"]
    fn selects_the_installed_five_source_fit() -> Result<()> {
        let path = provider_path(Path::new(RT));
        let reported = std::env::var("HORIZON_FIVE_FIT_QUALIFIED_PATH")?;
        let digest = std::env::var("HORIZON_FIVE_FIT_QUALIFIED_SHA256")?;
        ensure!(path == Path::new(&reported), "crossed publication fit");
        program(&path, &digest)
    }

    #[test]
    #[ignore = "requires the root-owned, private-network native receiver fixture"]
    fn committed_source_prepares_under_the_original_receiver() -> Result<()> {
        let fixture = PathBuf::from(std::env::var_os("HORIZON_166_QA_BASE").context("QA dir")?);
        let auth = fixture.join("authority");
        let (live, live_ref) = read_json(&auth.join("LIVE.json"), WITNESS_MODE, 1 << 20)?;
        let (terminal, term_ref) = read_json(&auth.join("TERMINAL_SUCCESS.json"), 0o400, 1 << 20)?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        validate_terminal(&live, &live_ref, &terminal, boot.trim())?;
        #[cfg(any(
            feature = "cold168",
            feature = "source167",
            feature = "retry170",
            feature = "full172"
        ))]
        {
            let mut changed = live.clone();
            changed["schema"] = json!(format!("horizon-{EPOCH}-live-to-terminal-witness-v1"));
            assert!(validate_terminal(&changed, &live_ref, &terminal, boot.trim()).is_err());
        }
        let out = source(&live, &terminal)?;
        for (k, v) in [
            ("transaction_id", json!("")),
            ("producer_invocation_id", json!("foreign")),
            ("reservation_ending_bytes", json!(1)),
            ("live", Value::Null),
        ] {
            let mut bad = terminal.clone();
            bad[k] = v;
            assert!(validate_terminal(&live, &live_ref, &bad, boot.trim()).is_err());
        }
        let mut bad = terminal.clone();
        bad["local_archive"]["inode"] = json!(0);
        assert!(source(&live, &bad).is_err());
        let base =
            PathBuf::from(std::env::var_os("HORIZON_166_QA_RUN").context("qualification run")?);
        let (measured, _) = read_json(&base.join("fit.json"), 0o600, 1 << 20)?;
        let iid = std::env::var("INVOCATION_ID")?;
        let cap = json!({"protected_bytes":measured["protected_home"],"available_bytes":measured["home_free"],
            "invocation_id":iid, "boot_id":boot.trim(),"observed_unix_seconds":now()?,
            "terminal":term_ref,"all_existing_commitments_retained":true});
        let r = write_admission(&base, "prepare", &out, &terminal, &cap)?;
        let run = base.join(format!("run-{iid}"));
        let (a, ar) = read_json(&run.join("admission.json"), 0o400, 1 << 20)?;
        assert_eq!(r, ar);
        assert_eq!(a["archive_inode"], terminal["local_archive"]["inode"]);
        assert_eq!(a["publication_authorized"], false);
        assert!(write_admission(&base, "sync", &out, &terminal, &cap).is_err());
        let result = Command::new("/usr/bin/python3")
            .arg("-IB")
            .arg(base.join("qualify_controller.py"))
            .arg(&fixture)
            .arg(&run)
            .arg(field(&ar, "sha256")?)
            .status()?;
        ensure!(
            result.success(),
            "native receiver refused controller-generated admission"
        );
        let (again, _) = read_json(&run.join("admission.json"), 0o400, 1 << 20)?;
        assert_eq!(a, again);
        Ok(())
    }

    #[test]
    fn only_a_current_fitting_original_terminal_can_dispatch() {
        let fleet = binding(Path::new("/fleet"), &"a".repeat(64));
        let terminal = binding(Path::new("/terminal"), &"b".repeat(64));
        let good = json!({"schema":format!("horizon-{EPOCH}-publication-fit-v1"),"boot_id":"boot","observed_unix_seconds":100,
            "fleet":fleet,"terminal":terminal,"available_bytes":1000,"protected_bytes":1000,
            "complete_cpu_quota_micros":64000000,"complete_memory_plus_reserve_bytes":810658050048u64,
            "publication_cpu_quota_micros":PUBLICATION_CPU_MICROS,"publication_memory_bytes":MEMORY,"available_memory_bytes":800,
            "required_available_memory_bytes":800,"all_existing_commitments_retained":true,"resource_credit_bytes":0});
        let check = |v: &Value, t| capacity(v, &fleet, &terminal, "boot", "iid", t);
        assert_eq!(check(&good, 280).unwrap()["invocation_id"], "iid");
        assert!(check(&good, 281).is_err());
        assert!(check(&good, 99).is_err());
        for (k, v) in [
            ("boot_id", json!("prior")),
            ("terminal", fleet.clone()),
            ("fleet", terminal.clone()),
            ("available_bytes", json!(999)),
            ("protected_bytes", json!(0)),
            ("available_memory_bytes", json!(799)),
            ("required_available_memory_bytes", Value::Null),
            ("resource_credit_bytes", json!(1)),
            ("publication_memory_bytes", json!(MEMORY + 1)),
            ("all_existing_commitments_retained", json!(false)),
        ] {
            let mut bad = good.clone();
            bad[k] = v;
            assert!(check(&bad, 100).is_err(), "accepted {k}");
        }
    }
}
