//! Retire one compile-time-bound closed lane-M artifact after authenticated whole readback.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    env,
    ffi::CString,
    fs::{self, File, Metadata, OpenOptions},
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::Path,
    process::Command,
};

#[cfg(not(main_partial185))]
mod profile {
    pub(super) const STATE: &str =
        "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-holding-20261127-v1";
    pub(super) const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs175-200-20260922-v1/lane-m/private/destination-1046bb4e16672cd81d120ecccbaaa9e559f9fcdaffc50e978ee4ce228c77732e/work/root-cohort-185-185/run-722680-1790806113840176891/archives/epoch-185.jet.replaced-1279977-1790873552-0";
    pub(super) const SHA: &str = "cc0795d82d0b438c5e2d8a63248280333789a96bc4c08fc06d2acfeb16770996";
    pub(super) const LENGTH: u64 = 30_725_885_495;
    pub(super) const ALLOCATED: u64 = 30_725_935_104;

    pub(super) const INODE: u64 = 104_006_868;
    pub(super) const UNIT: &str = "horizon-closed185-lanem-retire-20261127-v2.service";
    pub(super) const MTIME: (i64, i64) = (1_790_871_363, 450_943_659);
    pub(super) const CTIME: (i64, i64) = (1_790_873_552, 23_963_737);
    pub(super) const PLAN_SCHEMA: &str = "horizon-lanem185-retirement-plan-v1";
    pub(super) const RESULT_SCHEMA: &str = "horizon-lanem185-local-retirement-complete-v1";
}
#[cfg(main_partial185)]
mod profile {
    pub(super) const STATE: &str =
        "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-main-holding-20261127-v1";
    pub(super) const SOURCE: &str = "/home/sol/.jetstreamer-private/epochs175-200-20260922-v1/lane-m/private/destination-1046bb4e16672cd81d120ecccbaaa9e559f9fcdaffc50e978ee4ce228c77732e/work/root-cohort-185-185/run-722680-1790806113840176891/archives/epoch-185.jet";
    pub(super) const SHA: &str = "40dd56a324dc5e3abb3766a95c8189a02c7b7ace61cf2c9bc0f665c4dbc2415d";
    pub(super) const LENGTH: u64 = 54_996_291_524;
    pub(super) const ALLOCATED: u64 = 54_996_418_560;

    pub(super) const INODE: u64 = 104_005_633;
    pub(super) const UNIT: &str = "horizon-closed185-lanem-main-retire-20261127-v1.service";
    pub(super) const MTIME: (i64, i64) = (1_790_979_327, 119_986_061);
    pub(super) const CTIME: (i64, i64) = (1_790_979_327, 119_986_061);
    pub(super) const PLAN_SCHEMA: &str = "horizon-lanem185-main-retirement-plan-v1";
    pub(super) const RESULT_SCHEMA: &str = "horizon-lanem185-main-local-retirement-complete-v1";
}
use profile::*;
#[cfg(any(test, main_partial185))]
use std::io::{Seek, SeekFrom};
const DEVICE: u64 = 64_512;
const STOPPED: [&str; 2] = [
    "jetstreamer-root-sweep-historical-182-200-v111-e185-185-lane-m-3.service",
    "jetstreamer-root-sweep-historical-182-200-v112-e185-185-lane-m-2.service",
];

fn sha(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn bound(path: &Path, hex: &str) -> Result<Value> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical receipt path"
    );
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let md = f.metadata()?;
    ensure!(
        md.is_file()
            && md.uid() == 0
            && md.nlink() == 1
            && md.mode() & 0o222 == 0
            && md.len() <= 1 << 20,
        "unsafe receipt"
    );
    let mut bytes = Vec::new();
    f.take((1 << 20) + 1).read_to_end(&mut bytes)?;
    ensure!(sha(&bytes) == hex, "receipt digest mismatch");
    Ok(serde_json::from_slice(&bytes)?)
}

fn bound_ref(value: &Value, path: &Path) -> Result<Value> {
    ensure!(
        value["path"].as_str() == path.to_str(),
        "unexpected receipt path"
    );
    bound(
        path,
        value["sha256"].as_str().context("missing bound digest")?,
    )
}

fn record(path: &Path, document: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(document)?;
    let temporary = path.with_extension(format!("stage-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    rename_noreplace(&temporary, path)?;
    File::open(path.parent().context("receipt parent")?)?.sync_all()?;
    Ok(())
}

fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    let src = CString::new(from.as_os_str().as_bytes())?;
    let dst = CString::new(to.as_os_str().as_bytes())?;
    if unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            src.as_ptr(),
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn source_id(md: &Metadata, original: bool) -> bool {
    md.is_file()
        && md.dev() == DEVICE
        && md.ino() == INODE
        && md.len() == LENGTH
        && md.nlink() == 1
        && md.uid() == 1001
        && md.gid() == 1003
        && md.mode() & 0o7777 == 0o600
        && md.blocks().checked_mul(512) == Some(ALLOCATED)
        && (md.mtime(), md.mtime_nsec()) == MTIME
        && (!original || (md.ctime(), md.ctime_nsec()) == CTIME)
}

fn assert_identity(path: &Path, original: bool) -> Result<()> {
    ensure!(
        path.canonicalize()? == path && source_id(&fs::symlink_metadata(path)?, original),
        "selected inode changed"
    );
    Ok(())
}

fn rehash(path: &Path, original: bool) -> Result<()> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(source_id(&f.metadata()?, original), "opened inode changed");
    let digest = Command::new("/usr/bin/sha256sum")
        .arg("-")
        .stdin(f)
        .output()?;
    ensure!(
        digest.status.success() && digest.stdout == format!("{SHA}  -\n").as_bytes(),
        "local archive digest changed"
    );
    assert_identity(path, original)
}

fn read_unit(unit: &str) -> Result<String> {
    let result = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            unit,
            "-p",
            "LoadState,ActiveState,MainPID,ControlPID,Job,TriggeredBy,FragmentPath",
        ])
        .output()?;
    ensure!(
        result.status.success() || result.status.code() == Some(4),
        "native query failed"
    );
    Ok(String::from_utf8(result.stdout)?)
}

fn check_consumers(run: &Path, current: &Path, native_unit: &str) -> Result<()> {
    for unit in STOPPED {
        let props = read_unit(unit)?;
        for required in [
            "LoadState=not-found",
            "ActiveState=inactive",
            "MainPID=0",
            "ControlPID=0",
            "Job=",
            "TriggeredBy=",
        ] {
            ensure!(
                props.lines().any(|line| line == required),
                "old lane-M unit can execute: {unit}"
            );
        }
    }
    let own = read_unit(native_unit)?;
    ensure!(
        own.lines()
            .any(|line| line == format!("MainPID={}", std::process::id())),
        "retirement requires its native unit"
    );
    let fragment = own
        .lines()
        .find_map(|line| line.strip_prefix("FragmentPath="))
        .context("missing own unit fragment")?;
    ensure!(
        fragment == format!("/run/systemd/transient/{native_unit}"),
        "unexpected own unit fragment"
    );
    for target in [run, current] {
        let scan =
            jetstreamer_horizon_observe::process_references::scan(Path::new("/proc"), target)?;
        ensure!(
            scan.references.is_empty(),
            "live path references: {:?}",
            scan.references
        );
        if target.try_exists()? {
            let staged =
                jetstreamer_horizon_observe::dev_cache_check::sol_staged_path_references(target)?;
            ensure!(
                staged["references"]
                    .as_array()
                    .context("staged references")?
                    .iter()
                    .all(|p| p == fragment),
                "foreign staged owner: {staged}"
            );
        }
    }
    let lock_id = format!("fc:00:{INODE}");
    ensure!(
        !fs::read_to_string("/proc/locks")?
            .split_ascii_whitespace()
            .any(|s| s == lock_id),
        "inode is locked"
    );
    let mut namespaces = BTreeSet::new();
    let source_mount = Path::new(SOURCE).strip_prefix("/home/sol")?;
    let mount_root = format!("/{}", source_mount.display());
    for entry in fs::read_dir("/proc")? {
        let proc = entry?.path();
        if !proc
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.parse::<u32>().is_ok())
        {
            continue;
        }
        let mut check = || -> Result<()> {
            match fs::metadata(proc.join("ns/mnt")) {
                Ok(ns) if !namespaces.contains(&(ns.dev(), ns.ino())) => {
                    for mount in fs::read_to_string(proc.join("mountinfo"))?.lines() {
                        let mut fields = mount.split_ascii_whitespace().skip(2);
                        let device = fields.next().context("mountinfo device")?;
                        let root = fields.next().context("mountinfo root")?;
                        ensure!(
                            device != "252:0" || root != mount_root,
                            "selected archive has a file bind in {proc:?}"
                        );
                    }
                    namespaces.insert((ns.dev(), ns.ino()));
                }
                Ok(_) => (),
                Err(e) if e.kind() == ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
            for fd in fs::read_dir(proc.join("fd"))? {
                match fs::metadata(fd?.path()) {
                    Ok(md) => ensure!(
                        (md.dev(), md.ino()) != (DEVICE, INODE),
                        "open archive descriptor in {proc:?}"
                    ),
                    Err(e) if e.kind() == ErrorKind::NotFound => (),
                    Err(e) => return Err(e.into()),
                }
            }
            for line in BufReader::new(File::open(proc.join("maps"))?).lines() {
                let line = line?;
                let mut fields = line.split_ascii_whitespace().skip(3);
                if fields.next() == Some("fc:00") {
                    ensure!(
                        fields.next().and_then(|v| v.parse::<u64>().ok()) != Some(INODE),
                        "mapped archive inode in {proc:?}"
                    );
                }
            }
            Ok(())
        };
        let result = check();
        if result
            .as_ref()
            .err()
            .and_then(|e| e.downcast_ref::<std::io::Error>())
            .is_some_and(|e| e.kind() == ErrorKind::NotFound)
            && !proc.try_exists()?
        {
            continue;
        }
        result?;
    }
    Ok(())
}

fn lock(path: &Path, inode: u64, uid: u32, write: bool) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let m = f.metadata()?;
    ensure!(
        path.canonicalize()? == path
            && m.is_file()
            && m.dev() == DEVICE
            && m.ino() == inode
            && m.uid() == uid
            && m.nlink() == 1
            && m.mode() & 0o7777 == 0o600,
        "foreign operation lock"
    );
    ensure!(
        unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "operation lock occupied"
    );
    Ok(f)
}

fn available(dir: &Path) -> Result<u64> {
    let path = CString::new(dir.as_os_str().as_bytes())?;
    let mut result = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), result.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let result = unsafe { result.assume_init() };
    result
        .f_bavail
        .checked_mul(result.f_frsize)
        .context("available byte overflow")
}

fn verify_custody(custody: &Value, remote: &Value, expected: &Value) -> Result<()> {
    let etag = custody["object_etag"]
        .as_str()
        .context("custody ETag")?
        .trim_matches('"');
    ensure!(
        custody["remote_sha256_readback"] == true
            && custody["local_source_revalidated"] == true
            && custody["source"] == SOURCE
            && custody["length"] == LENGTH
            && custody["sha256"] == SHA
            && remote["authenticated"] == true
            && remote["remote_mutations"] == false
            && remote["phase"] == "accepted"
            && remote["blob"]["key"] == expected["object_key"]
            && remote["manifest"]["key"] == expected["manifest_key"]
            && remote["blob"]["status"] == 200
            && remote["manifest"]["status"] == 200
            && remote["blob"]["length"] == LENGTH
            && remote["blob"]["metadata"]["sha256"] == SHA
            && remote["blob"]["etag"]
                .as_str()
                .is_some_and(|value| value.trim_matches('"') == etag),
        "conditional identity differs from whole-readback custody"
    );
    #[cfg(main_partial185)]
    {
        ensure!(
            expected["object_key"] == format!("node_02/objects/{SHA}.blob")
                && expected["manifest_key"]
                    == format!(
                        "node_02/manifests/{}.json",
                        expected["manifest_sha256"]
                            .as_str()
                            .context("missing manifest hash")?
                    )
                && expected["manifest_sha256"]
                    .as_str()
                    .is_some_and(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
                && remote["owner"]["key"] == "node_02/owner.json"
                && remote["owner"]["status"] == 200
                && !etag.is_empty()
                && expected["manifest"]["canonical_archive"] == false
                && expected["manifest"]["canonical_publication_authorized"] == false
                && custody["local_retirement_authorized"] == false
                && custody["canonical_publication_authorized"] == false
                && ["manifest", "object_key", "manifest_sha256", "manifest_key"]
                    .iter()
                    .all(|k| custody[*k] == expected[*k]),
            "holding mapping or recovery obligation changed"
        );
    }
    Ok(())
}

fn validate_transition(source: bool, quarantine: bool, intent: bool, unlink: bool) -> Result<()> {
    ensure!(
        !(source && quarantine)
            && (!quarantine || intent)
            && (!unlink || intent && !source)
            && (source || quarantine || unlink),
        "unrecognized retirement transition"
    );
    Ok(())
}

#[cfg(not(main_partial185))]
fn neighbor_evidence(dir: &Path) -> Result<Value> {
    let neighbor = fs::symlink_metadata(dir.join("epoch-185.jet"))?;
    ensure!(
        neighbor.is_file() && neighbor.len() == 54_996_291_524 && neighbor.ino() != INODE,
        "neighboring archive changed"
    );
    Ok(json!([
        neighbor.dev(),
        neighbor.ino(),
        neighbor.len(),
        neighbor.mtime(),
        neighbor.mtime_nsec()
    ]))
}

#[cfg(main_partial185)]
fn neighbor_evidence(dir: &Path) -> Result<Value> {
    let old = Path::new(
        "/var/lib/jetstreamer/horizon_runtime_data/epoch185-lanem-holding-20261127-v1/MEASURED_LOCAL_RECLAMATION.json",
    );
    let digest = "798ee9c4446496d3ef965d3c01ce9912cd65b48a380fc6258b5403ea6bd304ea";
    let receipt = bound(old, digest)?;
    ensure!(
        receipt["source_inode"] == 104006868
            && receipt["host_source_absent"] == true
            && receipt["host_quarantine_absent"] == true
            && receipt["neighbor_preserved"] == true,
        "unproven displaced sibling retirement"
    );
    for name in [
        "epoch-185.jet.replaced-1279977-1790873552-0",
        ".epoch185-lanem-retiring-cc0795d82d0b438c5e2d8a63248280333789a96bc4c08fc06d2acfeb16770996.jet",
    ] {
        ensure!(
            fs::symlink_metadata(dir.join(name))
                .is_err_and(|err| err.kind() == ErrorKind::NotFound),
            "displaced sibling reappeared"
        );
    }
    let cohort = dir
        .parent()
        .context("missing run")?
        .join("cohort-state.json");
    ensure!(
        cohort.canonicalize()? == cohort
            && sha(&fs::read(&cohort)?)
                == "bda4c4d53c3e32b89cd41848975383255261be4156594ae1cda022f62dcda791",
        "cohort assignment changed"
    );
    Ok(
        json!({"displaced_sibling_absent":true,"previous_retirement_sha256":digest,"cohort_state":cohort}),
    )
}

#[cfg(main_partial185)]
fn lane_lock(dir: &Path) -> Result<File> {
    let destination = dir.ancestors().nth(4).context("missing lane destination")?;
    ensure!(
        destination.file_name().and_then(|name| name.to_str())
            == Some("destination-1046bb4e16672cd81d120ecccbaaa9e559f9fcdaffc50e978ee4ce228c77732e"),
        "foreign lane destination"
    );
    lock(
        &destination.join("locks/epoch-185.lock"),
        101_717_370,
        1001,
        false,
    )
}

#[cfg(any(test, main_partial185))]
fn partial_framing<R: Read + Seek>(file: &mut R) -> Result<()> {
    let mut opening = [0u8; 8];
    file.read_exact(&mut opening)?;
    file.seek(SeekFrom::End(-8))?;
    let mut ending = [0u8; 8];
    file.read_exact(&mut ending)?;
    ensure!(
        &opening == b"JSHZN1\0\0" && &ending != b"\0\0NZHSJ1",
        "not an unfinished Horizon archive"
    );
    Ok(())
}

#[cfg(main_partial185)]
fn review(self_sha: &str) -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0 && sha(&fs::read("/proc/self/exe")?) == self_sha,
        "foreign review image"
    );
    let src = Path::new(SOURCE);
    let dir = src.parent().context("missing archives")?;
    let _lock = lane_lock(dir)?;
    let neighbor = neighbor_evidence(dir)?;
    assert_identity(src, true)?;
    partial_framing(&mut File::open(src)?)?;
    let unit = "horizon-closed185-lanem-main-review-20261127-v1.service";
    check_consumers(dir.parent().context("missing run")?, src, unit)?;
    assert_identity(src, true)?;
    println!(
        "{}",
        json!({"source":SOURCE,"inode":INODE,"length":LENGTH,"sha256_expected":SHA,"unfinished":true,"previous_sibling":neighbor,"live_and_staged_check":true,"epoch_lock":101717370,"invocation":env::var("INVOCATION_ID")?,"local_mutations":false})
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(1).collect();
    #[cfg(main_partial185)]
    if let [mode, self_sha] = args.as_slice()
        && mode == "--check-source"
    {
        return review(self_sha);
    }
    let [plan_sha, self_sha] = args.as_slice() else {
        anyhow::bail!("expected sealed plan and image digests")
    };
    ensure!(
        unsafe { libc::geteuid() } == 0 && sha(&fs::read("/proc/self/exe")?) == *self_sha,
        "untrusted retirement image"
    );
    let state = Path::new(STATE);
    let plan = bound(&state.join("retirement-plan-v1/plan.json"), plan_sha)?;
    ensure!(
        plan["schema"] == PLAN_SCHEMA && plan["source"] == SOURCE,
        "foreign retirement plan"
    );
    let expected = bound_ref(&plan["expected"], &state.join("package/EXPECTED.json"))?;
    ensure!(
        expected["source"] == SOURCE
            && expected["length"] == LENGTH
            && expected["sha256"] == SHA
            && expected["existing_serial_restore_reservation_bytes"] == 123_350_028_052_u64,
        "wrong expected archive identity"
    );
    let remote = bound_ref(
        &plan["remote"],
        &state.join("RETIREMENT_REMOTE_IDENTITY.json"),
    )?;
    let parked = bound_ref(&plan["park"], &state.join("PARK_CUSTODY.json"))?;
    let custody = bound_ref(
        &parked["native_custody"],
        Path::new(
            expected["custody_path"]
                .as_str()
                .context("no custody path")?,
        ),
    )?;
    verify_custody(&custody, &remote, &expected)?;
    let _holding = lock(
        Path::new(
            "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock",
        ),
        95_818_311,
        0,
        true,
    )?;
    let _mutation = lock(
        Path::new("/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock"),
        101_135_013,
        1001,
        true,
    )?;
    let source = Path::new(SOURCE);
    let dir = source.parent().context("missing archive directory")?;
    #[cfg(main_partial185)]
    let _epoch_lock = lane_lock(dir)?;
    let neighbor = neighbor_evidence(dir)?;
    let quarantine = dir.join(format!(".epoch185-lanem-retiring-{SHA}.jet"));
    let intent = state.join("LOCAL_RETIREMENT_INTENT.json");
    let pre_unlink = state.join("LOCAL_UNLINK_INTENT.json");
    let done = state.join("LOCAL_RETIREMENT_COMPLETE.json");
    if done.try_exists()? {
        let old: Value = serde_json::from_reader(File::open(&done)?)?;
        ensure!(
            !source.try_exists()? && !quarantine.try_exists()? && old["plan_sha256"] == *plan_sha,
            "foreign completed retirement"
        );
        println!("{}", done.display());
        return Ok(());
    }
    let source_present = source.try_exists()?;
    let quarantine_present = quarantine.try_exists()?;
    let intent_present = intent.try_exists()?;
    let pre_unlink_present = pre_unlink.try_exists()?;
    validate_transition(
        source_present,
        quarantine_present,
        intent_present,
        pre_unlink_present,
    )?;
    let operation = json!({"source": SOURCE, "quarantine":quarantine, "plan_sha256":plan_sha, "device":DEVICE, "inode":INODE, "sha256":SHA});
    let invocation = env::var("INVOCATION_ID")?;
    if intent_present {
        let old: Value = serde_json::from_reader(File::open(&intent)?)?;
        ensure!(old["operation"] == operation, "foreign retirement intent");
    }
    let previous_baseline = if pre_unlink_present {
        let old: Value = serde_json::from_reader(File::open(&pre_unlink)?)?;
        ensure!(old["operation"] == operation, "foreign unlink intent");
        Some(
            old["available_before"]
                .as_u64()
                .context("missing unlink baseline")?,
        )
    } else {
        None
    };
    let run_dir = dir.parent().context("missing run directory")?;
    if source_present {
        assert_identity(source, true)?;
        #[cfg(main_partial185)]
        partial_framing(&mut File::open(source)?)?;
        rehash(source, true)?;
        check_consumers(run_dir, source, UNIT)?;
        if !intent_present {
            record(
                &intent,
                &json!({"operation":operation,"invocation":invocation}),
            )?;
        }
        assert_identity(source, true)?;
        rename_noreplace(source, &quarantine)?;
        File::open(dir)?.sync_all()?;
    } else if quarantine_present {
        assert_identity(&quarantine, false)?;
        rehash(&quarantine, false)?;
    }
    let before;
    if quarantine.try_exists()? {
        check_consumers(run_dir, &quarantine, UNIT)?;
        assert_identity(&quarantine, false)?;
        before = if let Some(baseline) = previous_baseline {
            baseline
        } else {
            let baseline = available(dir)?;
            record(
                &pre_unlink,
                &json!({"operation":operation,"available_before":baseline,"invocation":invocation}),
            )?;
            baseline
        };
        ensure!(!source.try_exists()?, "original path reappeared");
        assert_identity(&quarantine, false)?;
        fs::remove_file(&quarantine)?;
        File::open(dir)?.sync_all()?;
    } else {
        before = previous_baseline.context("no durable unlink baseline")?;
        check_consumers(run_dir, &quarantine, UNIT)?;
        File::open(dir)?.sync_all()?;
    }
    let after = available(dir)?;
    ensure!(
        !source.try_exists()? && !quarantine.try_exists()? && neighbor_evidence(dir)? == neighbor,
        "retirement scope changed"
    );
    record(
        &done,
        &json!({"schema":RESULT_SCHEMA,"plan_sha256":plan_sha,"operation":operation,"invocation":invocation,"source_absent":true,"quarantine_absent":true,"neighbor_preserved":!cfg!(main_partial185),"retained_neighbor_evidence":neighbor,"measured_freed_bytes":i128::from(after)-i128::from(before),"allocated_bytes_removed":ALLOCATED,"available_before":before,"available_after":after,"authenticated_custody_revalidated":true,"whole_readback_before_retirement":true,"resource_credit_bytes":0,"remote_mutations":false}),
    )?;
    println!("{}", done.display());
    Ok(())
}

fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interruption_requires_durable_move_and_unlink_intents() {
        for (source, quarantine, intent, unlink) in [
            (true, false, false, false),
            (true, false, true, false),
            (false, true, true, false),
            (false, true, true, true),
            (false, false, true, true),
        ] {
            assert!(validate_transition(source, quarantine, intent, unlink).is_ok());
        }
        for (source, quarantine, intent, unlink) in [
            (true, true, true, false),
            (false, false, false, false),
            (false, true, false, false),
            (true, false, true, true),
            (false, false, true, false),
        ] {
            assert!(validate_transition(source, quarantine, intent, unlink).is_err());
        }
    }

    #[test]
    fn distinguish_unfinished_from_complete_archive_framing() {
        assert!(partial_framing(&mut std::io::Cursor::new(b"JSHZN1\0\0payloadbad-tail")).is_ok());
        assert!(
            partial_framing(&mut std::io::Cursor::new(b"JSHZN1\0\0payload\0\0NZHSJ1")).is_err()
        );
        assert!(partial_framing(&mut std::io::Cursor::new(b"foreign payloadbad-tail")).is_err());
    }

    #[cfg(main_partial185)]
    #[test]
    fn only_primary_inode_accepts_its_exact_holding_readback() {
        assert!(SOURCE.ends_with("/archives/epoch-185.jet") && INODE == 104005633);
        let key = format!("node_02/objects/{SHA}.blob");
        let mh = "6".repeat(64);
        let mk = format!("node_02/manifests/{mh}.json");
        let manifest = json!({"canonical_archive":false,"canonical_publication_authorized":false});
        let expected =
            json!({"object_key":key,"manifest_key":mk,"manifest_sha256":mh,"manifest":manifest});
        let custody = json!({"source":SOURCE,"sha256":SHA,"length":LENGTH,"object_etag":"E","remote_sha256_readback":true,"local_source_revalidated":true,"local_retirement_authorized":false,"canonical_publication_authorized":false,"object_key":key,"manifest_key":mk,"manifest_sha256":mh,"manifest":manifest});
        let remote = json!({"phase":"accepted","authenticated":true,"remote_mutations":false,"owner":{"key":"node_02/owner.json","status":200},"blob":{"key":key,"etag":"E","length":LENGTH,"status":200,"metadata":{"sha256":SHA}},"manifest":{"key":mk,"status":200}});
        assert!(verify_custody(&custody, &remote, &expected).is_ok());
        for (path, replacement) in [
            ("/source", json!("sibling")),
            ("/remote_sha256_readback", json!(false)),
            ("/object_etag", json!("changed")),
            ("/length", json!(0)),
            ("/manifest_key", json!("wrong")),
        ] {
            let mut changed = custody.clone();
            *changed.pointer_mut(path).unwrap() = replacement;
            assert!(verify_custody(&changed, &remote, &expected).is_err());
        }
    }

    #[test]
    fn quarantine_is_noclobber_and_keeps_neighbor() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("quarantine");
        fs::write(&source, b"archive").unwrap();
        fs::write(&target, b"different").unwrap();
        assert!(rename_noreplace(&source, &target).is_err());
        assert_eq!(fs::read(&source).unwrap(), b"archive");
        assert_eq!(fs::read(&target).unwrap(), b"different");
        fs::remove_file(&target).unwrap();
        rename_noreplace(&source, &target).unwrap();
        assert!(!source.exists());
        assert_eq!(fs::read(&target).unwrap(), b"archive");
        assert!(!source_id(&target.metadata().unwrap(), false));
    }
}
