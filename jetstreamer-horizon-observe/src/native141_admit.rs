//! Admission for the already-qualified, read-only full-census native candidate.
//! No database open, snapshot restore, service launch, replay or remote access.
use {
    crate::ram_artifact_retention::{Bound, hash_file, properties},
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    },
};
const NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-full-census-native-candidate-20261021-v1/jetstreamer-epoch141-ledger-native";
const NATIVE_SHA: &str = "f1592d185a51f5d7503a8b3763e0f18899bc0aa0b62b61cd00dc5659bf985e02";
const REJECTION_NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-rejection-candidate-20261022-v1/jetstreamer-epoch141-ledger-native";
const REJECTION_NATIVE_SHA: &str =
    "573ce13e04f25972962c671b88c5afea8e5dd445e0e425c93816ca73b72fba42";
const ACQUISITION_NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-acquisition-candidate-20261022-v1/jetstreamer-epoch141-ledger-native";
const ACQUISITION_NATIVE_SHA: &str =
    "0e7f847b520a91ba033f97181023ea20f9c833653744715c9e3448fbd4de088b";
const ALL_ACQUISITION_NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-all-acquisition-candidate-20261022-v1/jetstreamer-epoch141-ledger-native";
const ALL_ACQUISITION_NATIVE_SHA: &str =
    "ccf620b21f3c75cde3e9c22df058b0f3e4cefac9f7ae52c533f44bde38d757ec";
const ALL_RETRY_UNIT: &str =
    "horizon-epoch141-native-full-census-acquisition-all-20261022-v2.service";
const ALL_RETRY_NATIVE: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-all-acquisition-candidate-20261022-v2/jetstreamer-epoch141-ledger-native";
const ALL_RETRY_NATIVE_SHA: &str =
    "153a0d1302369f7ff1272d8b62ca9e777d4d1e3bd5a172e5edec5fe3ad28c295";
const FLOOR: u64 = 4_740_696_923_590;
const RESERVATION: u64 = 32 << 30;
// First-target output is capped at192MiB; native logging rolls at4MiB/two logs.
// One GiB includes slack, without reducing the protected reserve or old profiles.
const ACQUISITION_RESERVATION: u64 = 1 << 30;
const MEMORY: u64 = 144 << 30;
const COLLECTOR: &str = "horizon-epoch140-gap-metadata-fetch-20261021-v1.service";
const COLLECTOR_IID: &str = "dfc713bbd0c64597bdb00570b89dab4c";
const COMPLETE: &str = "/var/lib/jetstreamer-epoch140-gap-metadata-20261021-v1/complete.json";
const POLICY: &str = "87d7d4e9b0bbdf47c9da8bfad54361b8681b2d380d071cb085ea85f2dbeccf2b";
const RETENTION: &str = "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileSpec {
    path: PathBuf,
    sha256: String,
    uid: u32,
    gid: u32,
    mode: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    native_profile: String,
    filesystem: PathBuf,
    minimum_free_bytes: u64,
    minimum_memory_available_bytes: u64,
    files: Vec<FileSpec>,
    observer: Bound,
    fleet: Bound,
    finalized_collection: Bound,
    family_policy: Bound,
    retained_collection: Bound,
    native_unit: String,
    output: PathBuf,
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn unix_utc(s: &str) -> Result<u64> {
    ensure!(
        s.is_ascii()
            && s.len() == 20
            && &s[4..5] == "-"
            && &s[7..8] == "-"
            && &s[10..11] == "T"
            && &s[13..14] == ":"
            && &s[16..17] == ":"
            && &s[19..20] == "Z",
        "noncanonical UTC timestamp"
    );
    let year: u32 = s[..4].parse()?;
    let month: usize = s[5..7].parse()?;
    let day: u64 = s[8..10].parse()?;
    let hour: u64 = s[11..13].parse()?;
    let minute: u64 = s[14..16].parse()?;
    let second: u64 = s[17..19].parse()?;
    let leap = |y: u32| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let months = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        (1970..=2200).contains(&year)
            && (1..=12).contains(&month)
            && day > 0
            && day <= months[month - 1]
            && hour < 24
            && minute < 60
            && second < 60,
        "invalid UTC date"
    );
    let days: u64 = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + months[..month - 1].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}
fn read_json(binding: &Bound, owner_only: bool) -> Result<Value> {
    ensure!(
        hex(&binding.sha256, 64)
            && binding.path.is_absolute()
            && binding.path.canonicalize()? == binding.path,
        "noncanonical input binding"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&binding.path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file()
            && m.nlink() == 1
            && m.uid() == 0
            && m.mode() & 0o022 == 0
            && (!owner_only || m.mode() & 0o077 == 0)
            && m.len() <= 32 << 20,
        "unsafe JSON input"
    );
    let mut bytes = Vec::new();
    (&mut f).take((32 << 20) + 1).read_to_end(&mut bytes)?;
    let id = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mode(),
            m.nlink(),
            m.mtime(),
            m.mtime_nsec(),
            m.ctime(),
            m.ctime_nsec(),
        )
    };
    ensure!(
        bytes.len() as u64 == m.len()
            && format!("{:x}", Sha256::digest(&bytes)) == binding.sha256
            && id(&m) == id(&f.metadata()?)
            && id(&m) == id(&fs::symlink_metadata(&binding.path)?),
        "JSON input changed or digest differs"
    );
    Ok(serde_json::from_slice(&bytes)?)
}
fn validate_plan(p: &Plan) -> Result<()> {
    let (native, native_sha) = match p.native_profile.as_str() {
        "epoch141-read-only-full-census-v2" => (NATIVE, NATIVE_SHA),
        "epoch141-read-only-full-census-rejection-v3" => (REJECTION_NATIVE, REJECTION_NATIVE_SHA),
        "epoch141-read-only-first-target-acquisition-v4" => {
            (ACQUISITION_NATIVE, ACQUISITION_NATIVE_SHA)
        }
        "epoch141-read-only-all-target-acquisition-v5" if p.native_unit == ALL_RETRY_UNIT => {
            (ALL_RETRY_NATIVE, ALL_RETRY_NATIVE_SHA)
        }
        "epoch141-read-only-all-target-acquisition-v5" => {
            (ALL_ACQUISITION_NATIVE, ALL_ACQUISITION_NATIVE_SHA)
        }
        _ => anyhow::bail!("unknown fixed native admission profile"),
    };
    ensure!(
        p.schema == "jetstreamer-historical-performance-admission-v1"
            && p.filesystem == Path::new("/home/sol")
            && p.minimum_free_bytes
                >= FLOOR
                    + if p.native_profile == "epoch141-read-only-first-target-acquisition-v4" {
                        ACQUISITION_RESERVATION
                    } else {
                        RESERVATION
                    }
            && p.minimum_memory_available_bytes >= MEMORY,
        "wrong native admission envelope"
    );
    if p.native_profile == "epoch141-read-only-first-target-acquisition-v4" {
        ensure!(
            p.native_unit
                == "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service",
            "acquisition admission needs its exact distinct unit"
        );
    }
    if p.native_profile == "epoch141-read-only-all-target-acquisition-v5" {
        ensure!(
            p.native_unit
                == "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service"
                || p.native_unit == ALL_RETRY_UNIT,
            "all-target acquisition admission needs its exact separate unit"
        );
    }
    ensure!(
        p.files.len() == 1
            && p.files[0].path == Path::new(native)
            && p.files[0].sha256 == native_sha
            && p.files[0].uid == 0
            && p.files[0].gid == 0
            && p.files[0].mode == "0555",
        "wrong fixed native executable"
    );
    ensure!(
        p.finalized_collection.path == Path::new(COMPLETE)
            && p.family_policy.sha256 == POLICY
            && p.retained_collection.sha256 == RETENTION,
        "substituted collection or independent family policy"
    );
    ensure!(
        p.native_unit
            .starts_with("horizon-epoch141-native-full-census-")
            && p.native_unit.ends_with(".service")
            && p.native_unit.len() < 200
            && p.native_unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "foreign native unit"
    );
    let parent = p.output.parent().context("missing output parent")?;
    ensure!(
        p.output.file_name().is_some_and(|s| s == "admission.json")
            && parent.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && parent
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("horizon-native141-admission-")
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))),
        "foreign output namespace"
    );
    Ok(())
}
fn validate_evidence(
    p: &Plan,
    fleet: &Value,
    observer: &Value,
    complete: &Value,
    policy: &Value,
    retention: &Value,
    now: u64,
) -> Result<()> {
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet timestamp")?;
    let sampled = unix_utc(
        observer["recorded_at_utc"]
            .as_str()
            .context("observer timestamp")?,
    )?;
    ensure!(
        now.checked_sub(recorded).is_some_and(|age| age <= 1800)
            && now.checked_sub(sampled).is_some_and(|age| age <= 1800)
            && recorded >= sampled
            && fleet["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
            && fleet["first_epoch"] == 101
            && fleet["last_epoch"] == 200
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && fleet["observer_receipt"].as_str() == p.observer.path.to_str()
            && fleet["observer_sha256"] == p.observer.sha256,
        "stale or mismatching coordinated fleet/observer"
    );
    ensure!(
        observer["filesystem"]["path"] == "/home/sol"
            && observer["filesystem"]["conservative_available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= p.minimum_free_bytes)
            && observer["host_memory"]["conservative_available_kib"]
                .as_u64()
                .and_then(|v| v.checked_mul(1024))
                .is_some_and(|v| v >= p.minimum_memory_available_bytes),
        "coordinated resource envelope does not fit"
    );
    ensure!(
        complete["schema"] == "jetstreamer-epoch140-finalized-gap-metadata-collection-v1"
            && complete["unit"] == COLLECTOR
            && complete["invocation_id"] == COLLECTOR_IID
            && complete["plan"]["sha256"]
                == "fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc"
            && complete["census"]["sha256"]
                == "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"
            && complete["first_slot"] == 60911751
            && complete["last_slot"] == 61328765
            && complete["verified_targets"] == 18283
            && complete["target_receipts"]
                .as_array()
                .is_some_and(|a| a.len() == 18283)
            && complete["finalized_parent_and_hash_metadata_complete"] == true,
        "collection is not the exact completed full census"
    );
    for flag in [
        "hidden_poh_hashes_recovered",
        "source_obscuration_proven",
        "canonical_root_qualified",
        "replay_launch_authorized",
        "publication_authorized",
        "r2_mutations",
    ] {
        ensure!(
            complete[flag] == false,
            "collector acquired authority: {flag}"
        );
    }
    ensure!(
        policy["schema"] == "jetstreamer-epoch141-native-independent-family-policy-v1"
            && policy["family_count"] == 16
            && policy["retention_receipt"]["sha256"] == RETENTION
            && retention["schema"] == "jetstreamer-epoch141-ledger-collection-receipt-v1"
            && retention["files_retained"] == true
            && retention["minimum_free_bytes"] == FLOOR,
        "retained source/protection/family evidence differs"
    );
    Ok(())
}
fn owner_bindings(fleet: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for row in fleet["active"]
        .as_array()
        .context("missing complete active census")?
    {
        ensure!(row["epoch"] != 141, "epoch141 already has an active owner");
        let mut found = false;
        for key in ["controller", "producer", "unit"] {
            if row[key].is_null() {
                continue;
            }
            found = true;
            let unit = row[key]["Id"].as_str().context("owner unit")?;
            let iid = row[key]["InvocationID"]
                .as_str()
                .context("owner invocation")?;
            ensure!(
                unit.ends_with(".service")
                    && unit
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
                    && hex(iid, 32)
                    && row[key]["NRestarts"] == "0"
                    && row[key]["ActiveState"] == "active",
                "unbound fleet owner"
            );
            if let Some(old) = result.insert(unit.into(), iid.into()) {
                ensure!(old == iid, "conflicting owner");
            }
        }
        ensure!(found, "active row has no authenticated owner");
    }
    ensure!(!result.is_empty(), "empty fleet owner census");
    Ok(result)
}
fn owner_states(bindings: &BTreeMap<String, String>) -> Result<Value> {
    let mut states = serde_json::Map::new();
    for (unit, iid) in bindings {
        let state = properties(
            unit,
            "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,ExecStart",
        )?;
        ensure!(
            state.get("InvocationID") == Some(iid)
                && state.get("ActiveState").map(String::as_str) == Some("active")
                && state.get("SubState").map(String::as_str) == Some("running")
                && state.get("NRestarts").map(String::as_str) == Some("0")
                && state
                    .get("MainPID")
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|p| p > 0),
            "fleet owner changed"
        );
        states.insert(unit.clone(), serde_json::to_value(state)?);
    }
    Ok(Value::Object(states))
}
fn collector_terminal() -> Result<BTreeMap<String, String>> {
    let s = properties(
        COLLECTOR,
        "Id,LoadState,ActiveState,SubState,MainPID,InvocationID,NRestarts,Result,ExecMainStatus",
    )?;
    for (key, want) in [
        ("InvocationID", COLLECTOR_IID),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ActiveState", "active"),
        ("SubState", "exited"),
    ] {
        ensure!(
            s.get(key).map(String::as_str) == Some(want),
            "collector not genuine terminal success: {key}"
        );
    }
    Ok(s)
}
fn no_newer_fleet(binding: &Bound, recorded: u64) -> Result<()> {
    let root = Path::new("/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1");
    no_newer_fleet_in(root, binding, recorded)
}
fn no_newer_fleet_in(root: &Path, binding: &Bound, recorded: u64) -> Result<()> {
    ensure!(
        binding.path.parent() == Some(root),
        "fleet outside assigned durable census"
    );
    let name = binding
        .path
        .file_name()
        .and_then(|s| s.to_str())
        .context("fleet filename")?;
    ensure!(
        name.starts_with("fleet-") && name.ends_with(".json"),
        "noncanonical fleet name"
    );
    let mut entries = 0;
    for entry in fs::read_dir(root)? {
        entries += 1;
        ensure!(entries <= 65536, "fleet census exceeds bound");
        let entry = entry?;
        let path = entry.path();
        if path == binding.path {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(".json") {
            continue;
        }
        let Some(_) = name.strip_prefix("fleet-") else {
            continue;
        };
        let sha = hash_file(&path, 32 << 20)?.0;
        let value = read_json(&Bound { path, sha256: sha }, false)?;
        ensure!(
            value["schema"] == "jetstreamer-horizon-campaign-fleet-v1"
                && value["recorded_unix_seconds"]
                    .as_u64()
                    .is_some_and(|t| t < recorded),
            "newer or conflicting fleet requires refreshed admission manifest"
        );
    }
    Ok(())
}
fn native_idle(unit: &str) -> Result<()> {
    let listed = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "list-units",
            "--all",
            "--no-legend",
            "--plain",
            "--state=active,activating",
            "horizon-epoch141-native-full-census-*.service",
        ])
        .output()?;
    ensure!(
        listed.status.success() && listed.stdout.len() <= 65536,
        "native owner census unavailable"
    );
    for line in std::str::from_utf8(&listed.stdout)?.lines() {
        let name = line
            .split_whitespace()
            .next()
            .context("native unit census line")?;
        let state = properties(name, "MainPID,ActiveState")?;
        ensure!(
            state.get("MainPID").map(String::as_str) == Some("0"),
            "another native audit is active"
        );
    }
    for name in [
        unit.to_owned(),
        format!(
            "{}-check.service",
            unit.strip_suffix(".service").context("unit suffix")?
        ),
    ] {
        let s = properties(&name, "ActiveState,MainPID,Triggers,TriggeredBy")?;
        ensure!(
            s.get("ActiveState").map(String::as_str) == Some("inactive")
                && s.get("MainPID").map(String::as_str) == Some("0")
                && ["Triggers", "TriggeredBy"]
                    .iter()
                    .all(|k| s.get(*k).is_some_and(String::is_empty)),
            "native launch/check is active or triggered"
        );
    }
    Ok(())
}
fn resources(p: &Plan) -> Result<(u64, u64)> {
    let path = std::ffi::CString::new("/home/sol")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs unavailable"
    );
    let stat = unsafe { stat.assume_init() };
    let free = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("free byte overflow")?;
    let mem = fs::read_to_string("/proc/meminfo")?
        .lines()
        .find_map(|l| {
            l.strip_prefix("MemAvailable:")
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .and_then(|v| v.checked_mul(1024))
        .context("missing available memory")?;
    ensure!(
        free >= p.minimum_free_bytes && mem >= p.minimum_memory_available_bytes,
        "current resources do not fit"
    );
    Ok((free, mem))
}
fn persist(path: &Path, receipt: &Value) -> Result<()> {
    let parent = path.parent().context("output parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == 0
            && meta.mode() & 0o7777 == 0o700,
        "unsafe private output parent"
    );
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(tmp.as_file_mut(), receipt)?;
    tmp.write_all(b"\n")?;
    tmp.as_file().sync_all()?;
    tmp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("occupied admission output: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn run() -> Result<()> {
    let a: Vec<_> = std::env::args().collect();
    ensure!(
        (a.len() == 6 || (a.len() == 7 && a[6] == "--check-only"))
            && a[2] == "--manifest-sha256"
            && a[4] == "--self-sha256",
        "usage: native141-admit MANIFEST --manifest-sha256 SHA --self-sha256 SHA [--check-only]"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "admission requires root");
    let mut exe = File::open("/proc/self/exe")?;
    let m = exe.metadata()?;
    let mut digest = Sha256::new();
    let bytes = std::io::copy(&mut exe, &mut digest)?;
    ensure!(
        format!("{:x}", digest.finalize()) == a[5]
            && hex(&a[5], 64)
            && m.uid() == 0
            && m.mode() & 0o222 == 0
            && m.nlink() == 1
            && bytes == m.len()
            && exe.metadata()?.ino() == m.ino(),
        "running executable differs"
    );
    let binding = Bound {
        path: a[1].clone().into(),
        sha256: a[3].clone(),
    };
    let p: Plan = serde_json::from_value(read_json(&binding, true)?)?;
    validate_plan(&p)?;
    let fleet = read_json(&p.fleet, false)?;
    let observer = read_json(&p.observer, false)?;
    let complete = read_json(&p.finalized_collection, false)?;
    let policy = read_json(&p.family_policy, false)?;
    let retention = read_json(&p.retained_collection, false)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    validate_evidence(&p, &fleet, &observer, &complete, &policy, &retention, now)?;
    let recorded = fleet["recorded_unix_seconds"]
        .as_u64()
        .context("fleet time")?;
    no_newer_fleet(&p.fleet, recorded)?;
    let owners = owner_bindings(&fleet)?;
    let before = owner_states(&owners)?;
    let collector = collector_terminal()?;
    native_idle(&p.native_unit)?;
    // validate_plan has already selected one fixed profile/path/hash tuple;
    // accepting the rejection-capable generation never admits arbitrary tools.
    let (native_sha, native_meta) = hash_file(&p.files[0].path, 128 << 20)?;
    ensure!(
        native_sha == p.files[0].sha256
            && native_meta.uid() == 0
            && native_meta.gid() == 0
            && native_meta.mode() & 0o7777 == 0o555,
        "native executable identity differs"
    );
    let (free, memory) = resources(&p)?;
    ensure!(
        before == owner_states(&owners)? && collector == collector_terminal()?,
        "owner changed during admission"
    );
    native_idle(&p.native_unit)?;
    // Recheck bound metadata after resource and identity checks. The native
    // runner independently rereads every target and retained SST before use.
    for b in [
        &p.fleet,
        &p.observer,
        &p.finalized_collection,
        &p.family_policy,
        &p.retained_collection,
    ] {
        read_json(b, false)?;
    }
    no_newer_fleet(&p.fleet, recorded)?;
    if a.len() == 7 {
        println!("native admission check passed; no receipt, database open or launch");
        return Ok(());
    }
    let receipt = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1",
        "manifest":binding.path,"manifest_sha256":binding.sha256,"admitted":true,
        "native_profile":p.native_profile,"native_unit":p.native_unit,"recorded_unix_seconds":now,
        "evidence":{"filesystem":p.filesystem,"minimum_free_bytes":p.minimum_free_bytes,"available_bytes":free,
            "minimum_memory_available_bytes":p.minimum_memory_available_bytes,"memory_available_bytes":memory,
            "files":p.files,"fleet_sha256":p.fleet.sha256,"observer_sha256":p.observer.sha256,
            "finalized_collection_sha256":p.finalized_collection.sha256,"live_owners":before,"collector":collector},
        "services_started":false,"services_installed":false,"native_database_opened":false,
        "full_target_reread_claimed":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    persist(&p.output, &receipt)?;
    println!("{}", p.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        let bound = |path: &str, sha: &str| json!({"path":path,"sha256":sha});
        serde_json::from_value(json!({
            "schema":"jetstreamer-historical-performance-admission-v1",
            "native_profile":"epoch141-read-only-full-census-v2","filesystem":"/home/sol",
            "minimum_free_bytes":FLOOR+RESERVATION,"minimum_memory_available_bytes":MEMORY,
            "files":[{"path":NATIVE,"sha256":NATIVE_SHA,"uid":0,"gid":0,"mode":"0555"}],
            "observer":bound("/private/observer.json", &"a".repeat(64)),
            "fleet":bound("/private/fleet.json", &"b".repeat(64)),
            "finalized_collection":bound(COMPLETE, &"c".repeat(64)),
            "family_policy":bound("/private/policy.json",POLICY),
            "retained_collection":bound("/private/retention.json",RETENTION),
            "native_unit":"horizon-epoch141-native-full-census-test.service",
            "output":"/var/lib/jetstreamer/horizon-native141-admission-test/admission.json"
        }))
        .unwrap()
    }
    fn evidence(p: &Plan) -> (Value, Value, Value, Value, Value) {
        let fleet = json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","first_epoch":101,"last_epoch":200,
            "recorded_unix_seconds":1000,"sampled_at_utc":"1970-01-01T00:16:40Z",
            "observer_receipt":p.observer.path,"observer_sha256":p.observer.sha256});
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"1970-01-01T00:16:40Z",
            "filesystem":{"path":"/home/sol","conservative_available_bytes":FLOOR+RESERVATION},
            "host_memory":{"conservative_available_kib":MEMORY/1024}});
        let complete = json!({"schema":"jetstreamer-epoch140-finalized-gap-metadata-collection-v1",
            "unit":COLLECTOR,"invocation_id":COLLECTOR_IID,
            "plan":{"sha256":"fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc"},
            "census":{"sha256":"11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"},
            "first_slot":60911751,"last_slot":61328765,"verified_targets":18283,
            "target_receipts":vec![json!({});18283],"finalized_parent_and_hash_metadata_complete":true,
            "hidden_poh_hashes_recovered":false,"source_obscuration_proven":false,"canonical_root_qualified":false,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let policy = json!({"schema":"jetstreamer-epoch141-native-independent-family-policy-v1",
            "family_count":16,"retention_receipt":{"sha256":RETENTION}});
        let retention = json!({"schema":"jetstreamer-epoch141-ledger-collection-receipt-v1",
            "files_retained":true,"minimum_free_bytes":FLOOR});
        (fleet, observer, complete, policy, retention)
    }
    #[test]
    fn only_fixed_native_audit_and_unchanged_protection_are_admissible() {
        validate_plan(&plan()).unwrap();
        let mut p = plan();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.minimum_memory_available_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.files[0].sha256 = "d".repeat(64);
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.native_unit = "horizon-epoch159-native.service".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.output = "/home/sol/horizon/admission.json".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.native_profile = "ordinary-replay".into();
        assert!(validate_plan(&p).is_err());
        let mut p = plan();
        p.finalized_collection.path = "/tmp/partial.json".into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn rejection_profile_requires_its_exact_qualified_tuple_and_same_envelope() {
        let mut p = plan();
        p.native_profile = "epoch141-read-only-full-census-rejection-v3".into();
        // Neither old tool under new profile nor a mixed path/hash is allowed.
        assert!(validate_plan(&p).is_err());
        p.files[0].path = REJECTION_NATIVE.into();
        assert!(validate_plan(&p).is_err());
        p.files[0].sha256 = REJECTION_NATIVE_SHA.into();
        validate_plan(&p).unwrap();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        p.minimum_free_bytes += 1;
        p.minimum_memory_available_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        p.minimum_memory_available_bytes += 1;
        p.native_profile = "epoch141-read-only-full-census-v2".into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn acquisition_admission_requires_exact_candidate_unit_and_unchanged_envelope() {
        let mut p = plan();
        p.native_profile = "epoch141-read-only-first-target-acquisition-v4".into();
        assert!(validate_plan(&p).is_err());
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service".into();
        p.files[0].path = ACQUISITION_NATIVE.into();
        assert!(validate_plan(&p).is_err());
        p.files[0].sha256 = ACQUISITION_NATIVE_SHA.into();
        p.minimum_free_bytes = FLOOR + ACQUISITION_RESERVATION;
        validate_plan(&p).unwrap();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        p.minimum_free_bytes += 1;
        p.minimum_memory_available_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        p.minimum_memory_available_bytes += 1;
        p.native_unit = "horizon-epoch141-native-full-census-rejection-20261022-v1.service".into();
        assert!(validate_plan(&p).is_err());
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service".into();
        p.native_profile = "epoch141-read-only-full-census-rejection-v3".into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn all_target_acquisition_cannot_borrow_first_target_budget_or_identity() {
        let mut p = plan();
        p.native_profile = "epoch141-read-only-all-target-acquisition-v5".into();
        assert!(validate_plan(&p).is_err());
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service".into();
        p.files[0].path = ALL_ACQUISITION_NATIVE.into();
        p.files[0].sha256 = ALL_ACQUISITION_NATIVE_SHA.into();
        validate_plan(&p).unwrap();
        p.minimum_free_bytes = FLOOR + ACQUISITION_RESERVATION;
        assert!(validate_plan(&p).is_err());
        p.minimum_free_bytes = FLOOR + RESERVATION;
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service".into();
        assert!(validate_plan(&p).is_err());
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service".into();
        p.files[0].sha256 = ACQUISITION_NATIVE_SHA.into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn corrected_all_target_retry_needs_its_own_exact_unit_binary_and_full_budget() {
        let mut p = plan();
        p.native_profile = "epoch141-read-only-all-target-acquisition-v5".into();
        p.native_unit = ALL_RETRY_UNIT.into();
        p.files[0].path = ALL_RETRY_NATIVE.into();
        p.files[0].sha256 = ALL_RETRY_NATIVE_SHA.into();
        p.minimum_free_bytes = FLOOR + RESERVATION;
        validate_plan(&p).unwrap();
        p.native_unit =
            "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service".into();
        assert!(validate_plan(&p).is_err());
        p.native_unit = ALL_RETRY_UNIT.into();
        p.files[0].sha256 = ALL_ACQUISITION_NATIVE_SHA.into();
        assert!(validate_plan(&p).is_err());
        p.files[0].sha256 = ALL_RETRY_NATIVE_SHA.into();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn authenticated_pipeline_units_are_part_of_admission_owner_census() {
        let unit = json!({"Id":"private-plugin.service","InvocationID":"a".repeat(32),"NRestarts":"0","ActiveState":"active"});
        let mut fleet =
            json!({"active":[{"epoch":144,"phase":"private-plugin-verification","unit":unit}]});
        assert_eq!(
            owner_bindings(&fleet)
                .unwrap()
                .get("private-plugin.service"),
            Some(&"a".repeat(32))
        );
        fleet["active"][0]["unit"]["NRestarts"] = json!("1");
        assert!(owner_bindings(&fleet).is_err());
        fleet["active"][0]["unit"]["NRestarts"] = json!("0");
        fleet["active"][0]["epoch"] = json!(141);
        assert!(owner_bindings(&fleet).is_err());
    }
    #[test]
    fn timestamp_is_canonical_and_late_fleet_cannot_extend_sample_freshness() {
        assert_eq!(unix_utc("1970-01-01T00:16:40Z").unwrap(), 1000);
        assert_eq!(unix_utc("2000-03-01T00:00:00Z").unwrap(), 951868800);
        for s in [
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00+00:00",
        ] {
            assert!(unix_utc(s).is_err(), "{s}");
        }
        let p = plan();
        let (mut f, o, c, policy, r) = evidence(&p);
        f["recorded_unix_seconds"] = json!(2500);
        assert!(validate_evidence(&p, &f, &o, &c, &policy, &r, 2801).is_err());
    }
    #[test]
    fn partial_stale_future_legacy_or_authorizing_metadata_is_rejected() {
        let p = plan();
        let (f, o, c, policy, r) = evidence(&p);
        validate_evidence(&p, &f, &o, &c, &policy, &r, 1000).unwrap();
        for now in [999, 2801] {
            assert!(validate_evidence(&p, &f, &o, &c, &policy, &r, now).is_err());
        }
        for key in [
            "schema",
            "invocation_id",
            "verified_targets",
            "target_receipts",
            "finalized_parent_and_hash_metadata_complete",
        ] {
            let mut bad = c.clone();
            bad[key] = Value::Null;
            assert!(
                validate_evidence(&p, &f, &o, &bad, &policy, &r, 1000).is_err(),
                "{key}"
            );
        }
        let mut bad = c.clone();
        bad["replay_launch_authorized"] = json!(true);
        assert!(validate_evidence(&p, &f, &o, &bad, &policy, &r, 1000).is_err());
        let mut bad = o.clone();
        bad["schema"] = json!("jetstreamer-horizon-live-resource-sample-v1");
        assert!(validate_evidence(&p, &f, &bad, &c, &policy, &r, 1000).is_err());
        let mut bad = r.clone();
        bad["minimum_free_bytes"] = json!(FLOOR - 1);
        assert!(validate_evidence(&p, &f, &o, &c, &policy, &bad, 1000).is_err());
        let mut bad = f.clone();
        bad["observer_sha256"] = json!("d".repeat(64));
        assert!(validate_evidence(&p, &bad, &o, &c, &policy, &r, 1000).is_err());
    }
    #[test]
    fn owner_census_rejects_duplicate_conflicts_missing_owner_and_existing_141() {
        let owner = |iid: &str| json!({"Id":"exact-owner.service","InvocationID":iid,"NRestarts":"0","ActiveState":"active"});
        let a = owner(&"a".repeat(32));
        let mut f = json!({"active":[{"epoch":144,"producer":a},{"epoch":152,"controller":a}]});
        assert_eq!(owner_bindings(&f).unwrap().len(), 1);
        f["active"][1]["controller"] = owner(&"b".repeat(32));
        assert!(owner_bindings(&f).is_err());
        f = json!({"active":[{"epoch":141,"producer":a}]});
        assert!(owner_bindings(&f).is_err());
        assert!(owner_bindings(&json!({"active":[{"epoch":144}]})).is_err());
        assert!(owner_bindings(&json!({"active":[]})).is_err());
    }

    #[test]
    #[ignore = "root-owned disposable metadata fixture only; no native database or real inputs"]
    fn root_json_and_receipt_are_bound_private_nofollow_and_noclobber() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let output = dir.path().join("admission.json");
        let value = json!({"fixture_only":true,"native_database_opened":false});
        persist(&output, &value).unwrap();
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o400);
        assert!(persist(&output, &json!({"replacement":true})).is_err());
        let binding = Bound {
            path: output.clone(),
            sha256: hash_file(&output, 1 << 20).unwrap().0,
        };
        assert_eq!(read_json(&binding, true).unwrap(), value);
        fs::set_permissions(&output, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(read_json(&binding, true).is_err());
        assert_eq!(read_json(&binding, false).unwrap(), value);
        let link = dir.path().join("alias.json");
        std::os::unix::fs::symlink(&output, &link).unwrap();
        assert!(
            read_json(
                &Bound {
                    path: link,
                    sha256: binding.sha256.clone()
                },
                false
            )
            .is_err()
        );
        fs::write(&output, b"changed").unwrap();
        assert!(read_json(&binding, false).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(persist(&dir.path().join("another.json"), &value).is_err());
    }

    #[test]
    #[ignore = "root-owned disposable fleet metadata only; no actual campaign files"]
    fn root_fleet_fence_rejects_newer_events_even_with_an_older_sample_name() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let current = d.path().join("fleet-20261022T075800Z.json");
        let value =
            |t| json!({"schema":"jetstreamer-horizon-campaign-fleet-v1","recorded_unix_seconds":t});
        persist(&current, &value(1000)).unwrap();
        let binding = Bound {
            path: current,
            sha256: "a".repeat(64),
        };
        no_newer_fleet_in(d.path(), &binding, 1000).unwrap();
        let event = d.path().join("fleet-20261022T072800Z-new-admission.json");
        persist(&event, &value(1001)).unwrap();
        assert!(no_newer_fleet_in(d.path(), &binding, 1000).is_err());
        fs::remove_file(&event).unwrap();
        persist(&event, &value(999)).unwrap();
        no_newer_fleet_in(d.path(), &binding, 1000).unwrap();
    }
}
