//! Compressed-source-only admission. No replay, restore, cloud or service mutation.
use super::*;
use std::ffi::CString;

const PROTECTED: u64 = 4_740_696_923_590;
const SIZE: u64 = 2_569_233_422;
const SLACK: u64 = 64 << 20;
const UNIT: &str = "horizon-epoch144-snapshot-download-20261021-v1.service";
const OUTPUT: &str =
    "/var/lib/jetstreamer-horizon-epoch144-snapshot-download-20261021-v1/admission.json";
const FLOOR_SHA: &str = "39673f485b44ffb5c2053e2a553819da0bd0be30dcfc3cb8990553dd4de0f682";
const PROTECTION_SHA: &str = "c35203bb5236cc70b9eace23743ace8464ae17cbe70f447656eac35a7369c0b5";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    observer: BoundFile,
    fleet: BoundFile,
    fleet_plan: BoundFile,
    protection: BoundFile,
    floor: BoundFile,
    metadata: BoundFile,
    downloader: BoundFile,
    output: PathBuf,
}

fn floor(value: &Value) -> Result<u64> {
    ensure!(
        value["schema"] == "jetstreamer-horizon-century-jet-floor-v1"
            && value["century"]["first_epoch"] == 200
            && value["century"]["last_epoch"] == 300,
        "wrong century floor"
    );
    let mut epochs = BTreeSet::new();
    let mut sum = 0u64;
    let samples = value["samples"].as_array().context("floor samples")?;
    for sample in samples {
        let epoch = sample["epoch"].as_u64().context("floor epoch")?;
        let size = sample["jet_size_bytes"].as_u64().context("floor size")?;
        ensure!(
            (200..=300).contains(&epoch) && epochs.insert(epoch) && size > 0,
            "invalid or duplicate century sample"
        );
        sum = sum.checked_add(size).context("floor sum overflow")?;
    }
    let count = samples.len() as u64;
    ensure!(count > 0, "no audited floor samples");
    let result = sum
        .checked_mul(2)
        .context("floor overflow")?
        .div_ceil(count);
    ensure!(
        value["arithmetic"]["floor_bytes"] == result
            && value["arithmetic"]["sum_jet_size_bytes"] == sum
            && value["arithmetic"]["sample_count"] == count,
        "floor arithmetic differs"
    );
    Ok(result)
}

fn check_owners(previous: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let old = previous["unit_census"]
        .as_object()
        .context("prior census")?;
    for row in previous["active"].as_array().context("active census")? {
        for role in ["controller", "producer"] {
            let owner = &row[role];
            let name = owner["Id"].as_str().context("active owner name")?;
            let live = current.get(name).context("missing active owner")?;
            ensure!(
                old.get(name) == Some(owner),
                "active owner differs from prior census"
            );
            for field in [
                "Id",
                "InvocationID",
                "MainPID",
                "ActiveState",
                "SubState",
                "NRestarts",
                "ExecStart",
            ] {
                ensure!(
                    live[field] == owner[field],
                    "protected owner changed:{name}:{field}"
                );
            }
            ensure!(
                live["NRestarts"] == "0"
                    && live["ActiveState"] == "active"
                    && live["MainPID"].as_str().is_some_and(|s| s != "0"),
                "owner not stable/live"
            );
        }
    }
    Ok(())
}

fn free_bytes() -> Result<u64> {
    let path = CString::new("/home/sol")?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid NUL-terminated input and output buffer; read only on success.
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-byte overflow")
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 7
            && args[3] == "--spec-sha256"
            && args[5] == "--self-sha256"
            && unsafe { libc::geteuid() } == 0,
        "usage: admit-snapshot144 SPEC --spec-sha256 HEX --self-sha256 HEX (root)"
    );
    let exe = fs::read_link("/proc/self/exe")?;
    let m = fs::symlink_metadata(&exe)?;
    ensure!(
        m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read("/proc/self/exe")?)) == args[6],
        "unsealed admission tool"
    );
    let spec_bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let spec_meta = fs::symlink_metadata(&spec_bound.path)?;
    ensure!(
        spec_bound.path.canonicalize()? == spec_bound.path
            && spec_meta.is_file()
            && spec_meta.uid() == 0
            && spec_meta.nlink() == 1
            && spec_meta.mode() & 0o222 == 0,
        "admission spec is not immutable root-owned regular input"
    );
    let s: Spec = serde_json::from_value(bound_json(&spec_bound)?)?;
    ensure!(
        s.schema == "jetstreamer-epoch144-snapshot-admission-spec-v1"
            && s.output == Path::new(OUTPUT)
            && s.floor.sha256 == FLOOR_SHA
            && s.protection.sha256 == PROTECTION_SHA,
        "snapshot admission scope/protection differs"
    );
    let invocation = env::var("INVOCATION_ID").context("persistent invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation"
    );
    let observer = bound_json(&s.observer)?;
    let previous = bound_json(&s.fleet)?;
    let plan = bound_json(&s.fleet_plan)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let sample = utc_seconds(
        observer["recorded_at_utc"]
            .as_str()
            .context("sample time")?,
    )?;
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && previous["schema"] == SCHEMA
            && previous["first_epoch"] == 101
            && previous["last_epoch"] == 200
            && previous["observer_sha256"] == s.observer.sha256
            && previous["sampled_at_utc"] == observer["recorded_at_utc"]
            && previous["plan"].as_str() == s.fleet_plan.path.to_str()
            && previous["plan_sha256"] == s.fleet_plan.sha256
            && plan["observer"] == private157::binding(&s.observer)
            && previous["inventory"]["anomalies"] == 0
            && sample <= now
            && now - sample <= 1800,
        "stale or unaccepted source sample"
    );
    let protection = bound_json(&s.protection)?;
    ensure!(
        protection["accepted1838"]["retained_protection_bytes"] == PROTECTED,
        "older protection changed"
    );
    let floor_value = bound_json(&s.floor)?;
    let floor_bytes = floor(&floor_value)?;
    // The exact sealed census remains the only audited local century sample;
    // independently bind its existing full/plugin and authenticated ready-pair proofs.
    for sample in floor_value["samples"].as_array().unwrap() {
        let proof = |path: &str, digest: &str| -> Result<Value> {
            bound_json(&BoundFile {
                path: sample[path].as_str().context("floor proof path")?.into(),
                sha256: sample[digest]
                    .as_str()
                    .context("floor proof digest")?
                    .into(),
            })
        };
        let verification = proof(
            "private_resource_verification",
            "private_resource_verification_sha256",
        )?;
        let remote = proof("r2_receipt", "r2_receipt_sha256")?;
        ensure!(
            verification["status"] == "passed"
                && verification["full_verifier"]["exit_code"] == 0
                && verification["current_plugin"]["exit_code"] == 0
                && verification["archive_sha256_before_after_verified"] == true
                && remote["authenticated_ready_pair_revalidated"] == true
                && remote["remote_sha256_readback"] == true,
            "floor sample lacks full/plugin/ready-pair proof"
        );
        for proof in [&verification, &remote] {
            ensure!(
                proof["epoch"] == sample["epoch"]
                    && proof["archive_length"] == sample["jet_size_bytes"]
                    && proof["archive_sha256"] == sample["archive_sha256"],
                "floor sample identity differs"
            );
        }
    }
    let metadata = bound_json(&s.metadata)?;
    ensure!(
        metadata["schema"] == "jetstreamer-epoch144-snapshot-metadata-receipt-v1"
            && metadata["epoch"] == 144
            && metadata["download_performed"] == false
            && metadata["metadata"]["generation"] == "1634786788446253"
            && metadata["metadata"]["size"] == SIZE,
        "wrong source metadata"
    );
    ensure!(
        s.downloader.path.file_name().and_then(|n| n.to_str())
            == Some("jetstreamer-epoch144-snapshot-download"),
        "wrong downloader"
    );
    let dm = fs::symlink_metadata(&s.downloader.path)?;
    ensure!(
        s.downloader.path.is_absolute()
            && s.downloader.path.canonicalize()? == s.downloader.path
            && dm.is_file()
            && dm.uid() == 0
            && dm.nlink() == 1
            && dm.mode() & 0o222 == 0
            && hex_lower(&Sha256::digest(fs::read(&s.downloader.path)?)) == s.downloader.sha256,
        "unsafe downloader identity"
    );
    let future = unit(UNIT)?;
    ensure!(
        future["ActiveState"] == "inactive" && future["MainPID"] == "0",
        "download already live or failed"
    );
    let names = previous["unit_census"]
        .as_object()
        .context("unit census")?
        .keys()
        .cloned()
        .collect();
    let before = census(&names, 101, 200)?;
    check_owners(&previous, &before)?;
    let minimum = PROTECTED
        .checked_add(SIZE + SLACK)
        .context("budget overflow")?;
    ensure!(
        observer["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= minimum)
            && observer["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= 129 * 1024 * 1024),
        "snapshot does not fit sampled disk/memory envelope"
    );
    let available = free_bytes()?;
    ensure!(
        available >= minimum,
        "snapshot no longer fits protected disk envelope"
    );
    let meminfo = fs::read_to_string("/proc/meminfo")?;
    let memory_available_kib = meminfo
        .lines()
        .find_map(|line| line.strip_prefix("MemAvailable:"))
        .and_then(|line| line.split_whitespace().next())
        .context("MemAvailable missing")?
        .parse::<u64>()?;
    let vmas = fs::read_to_string("/proc/sys/vm/max_map_count")?
        .trim()
        .parse::<u64>()?;
    ensure!(
        memory_available_kib >= 129 * 1024 * 1024 && vmas >= 4_194_304,
        "snapshot memory reserve or host VMA gate failed"
    );
    let after = census(&names, 101, 200)?;
    check_owners(&previous, &after)?;
    private157::immutable_receipt(
        &s.output,
        &json!({
            "schema":"jetstreamer-epoch144-snapshot-admission-receipt-v1","epoch":144,"admitted":true,
            "recorded_unix_seconds":now,"invocation_id":invocation,"self_sha256":args[6],
            "spec":private157::binding(&spec_bound),"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
            "century_floor_bytes":floor_bytes,"protected_existing_floor_bytes":PROTECTED,"candidate_incremental_peak_bytes":SIZE+SLACK,
            "evidence":{"filesystem":"/home/sol","minimum_free_bytes":minimum,"available_bytes":available,
              "files":[private157::binding(&s.downloader),private157::binding(&s.metadata)],"unit_census":after,
              "memory_available_kib":memory_available_kib,"vm_max_map_count":vmas},
            "new_resource_samples":0,"download_only":true,"replay_launch_authorized":false,"native_restore_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("snapshot-only admission passed; older claims and century floor unchanged");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn floor_fixture() -> Value {
        json!({"schema":"jetstreamer-horizon-century-jet-floor-v1","century":{"first_epoch":200,"last_epoch":300},
            "samples":[{"epoch":201,"jet_size_bytes":11},{"epoch":202,"jet_size_bytes":10}],
            "arithmetic":{"floor_bytes":21,"sum_jet_size_bytes":21,"sample_count":2}})
    }
    #[test]
    fn floor_rejects_duplicate_partial_scope_and_transcription() {
        assert_eq!(floor(&floor_fixture()).unwrap(), 21);
        for (pointer, value) in [
            ("/samples/1/epoch", json!(201)),
            ("/samples/0/epoch", json!(199)),
            ("/samples/0/jet_size_bytes", json!(0)),
            ("/arithmetic/floor_bytes", json!(20)),
        ] {
            let mut bad = floor_fixture();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(floor(&bad).is_err());
        }
        let mut odd = floor_fixture();
        odd["samples"]
            .as_array_mut()
            .unwrap()
            .push(json!({"epoch":203,"jet_size_bytes":1}));
        odd["arithmetic"] = json!({"floor_bytes":15,"sum_jet_size_bytes":22,"sample_count":3});
        assert_eq!(floor(&odd).unwrap(), 15);
    }
    #[test]
    fn changed_or_disappeared_owner_fails_closed() {
        let owner = json!({"Id":"producer.service","InvocationID":"a".repeat(32),"MainPID":"123","ActiveState":"active","SubState":"running","NRestarts":"0","ExecStart":"sealed command"});
        let prior = json!({"unit_census":{"producer.service":owner},"active":[{"controller":owner,"producer":owner}]});
        let mut current = BTreeMap::from([("producer.service".into(), owner)]);
        check_owners(&prior, &current).unwrap();
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("MainPID", "0"),
            ("ActiveState", "inactive"),
            ("NRestarts", "1"),
            ("ExecStart", "other"),
        ] {
            let mut bad = current.clone();
            bad.get_mut("producer.service").unwrap()[key] = json!(value);
            assert!(check_owners(&prior, &bad).is_err());
        }
        current.clear();
        assert!(check_owners(&prior, &current).is_err());
    }
}
