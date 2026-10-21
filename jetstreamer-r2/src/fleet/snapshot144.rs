//! Exact source/native-only resource admission. No worker or service is launched.
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
    #[serde(default)]
    native: Option<Native>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Native {
    inputs: BoundFile,
    capability: BoundFile,
    resource_proposal: BoundFile,
}
fn native_output(path: &Path) -> bool {
    if path.parent()
        != Some(Path::new(
            "/var/lib/jetstreamer/horizon-epoch144-native-restore-20261021-v1",
        ))
    {
        return false;
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if name == "admission.json" {
        return true;
    }
    let Some(stamp) = name
        .strip_prefix("admission-")
        .and_then(|s| s.strip_suffix(".json"))
    else {
        return false;
    };
    stamp.len() == 16
        && stamp.is_ascii()
        && stamp.as_bytes()[8] == b'T'
        && stamp.as_bytes()[15] == b'Z'
        && stamp[..8]
            .bytes()
            .chain(stamp[9..15].bytes())
            .all(|b| b.is_ascii_digit())
        && utc_seconds(&format!(
            "{}-{}-{}T{}:{}:{}Z",
            &stamp[..4],
            &stamp[4..6],
            &stamp[6..8],
            &stamp[9..11],
            &stamp[11..13],
            &stamp[13..15]
        ))
        .is_ok()
}
fn native_inputs(n: &Native, probe: &BoundFile) -> Result<()> {
    ensure!(
        n.inputs.sha256 == "908cb628fc955f0ac66692d2742b34c1422b3ad06130b8fc8b28a94efaee682f"
            && n.capability.sha256
                == "a9a8fb188816640ceef322697c4e8c7a421606e7a4fe9a95a9847d79ab89305e"
            && n.resource_proposal.sha256
                == "ae18d37b9ed5a2eb38461e500ae75c0b6ea8e831a735afb764682e1566c64cda",
        "foreign native144 input evidence"
    );
    let inputs = bound_json(&n.inputs)?;
    let capability = bound_json(&n.capability)?;
    let proposal = bound_json(&n.resource_proposal)?;
    ensure!(
        inputs["schema"] == "jetstreamer-epoch144-native-input-policy-v1"
            && inputs["probe_sha256"] == probe.sha256
            && inputs["minimum_free_bytes"] == PROTECTED + (40u64 << 30)
            && capability["schema"] == "jetstreamer-epoch144-native-input-capability-v1"
            && capability["input_policy_sha256"] == n.inputs.sha256
            && capability["probe_sha256"] == probe.sha256
            && capability["snapshot_sha256"]
                == "f170976b2bc3f2d55dd0fbb5a415bfeae8d0903a0ad69334d8aa993b5cab35ae"
            && capability["snapshot_bytes"] == SIZE
            && capability["snapshot_device"] == 64512
            && capability["snapshot_inode"] == 105578509
            && capability["worker_spawned"] == false
            && capability["native_bank_restored"] == false
            && capability["snapshot_copied"] == false
            && capability["private_source_permissions_changed"] == false
            && capability["replay_launch_authorized"] == false
            && proposal["conservative_proposal"]["native_incremental_peak_bytes"] == 40u64 << 30
            && proposal["conservative_proposal"]["protected_existing_floor_bytes"] == PROTECTED
            && proposal["native_restore_authorized"] == false,
        "native144 capability/policy/resource mismatch"
    );
    let cap = unit("horizon-epoch144-native-input-capability-20261021-v1.service")?;
    ensure!(
        cap["InvocationID"] == capability["invocation_id"]
            && cap["ActiveState"] == "active"
            && cap["SubState"] == "exited"
            && cap["MainPID"] == "0"
            && cap["ExecMainStatus"] == "0"
            && cap["Result"] == "success",
        "native144 input capability not exact terminal success"
    );
    let snapshot = fs::symlink_metadata(
        "/home/sol/.jetstreamer-private/epoch144-snapshot-source-20261021-v1/download/snapshot-62639490-59bAQjc2c1VqNWqGoCacp3tnyNyie3EYx4bjttvJhgeT.tar.zst",
    )?;
    ensure!(
        snapshot.is_file()
            && snapshot.uid() == 0
            && snapshot.mode() & 0o222 == 0
            && snapshot.nlink() == 1
            && snapshot.dev() == 64512
            && snapshot.ino() == 105578509
            && snapshot.len() == SIZE,
        "native144 retained source identity changed"
    );
    Ok(())
}

pub(super) fn floor(value: &Value) -> Result<u64> {
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

pub(super) fn check_owners(previous: &Value, current: &BTreeMap<String, Value>) -> Result<()> {
    let old = previous["unit_census"]
        .as_object()
        .context("prior census")?;
    for row in previous["active"].as_array().context("active census")? {
        let owners = match (row.get("controller"), row.get("producer"), row.get("unit")) {
            (Some(controller), Some(producer), None) => vec![controller, producer],
            (None, Some(producer), None) => vec![producer],
            (None, None, Some(owner)) => vec![owner],
            _ => anyhow::bail!("unknown or ambiguous active owner shape"),
        };
        for owner in owners {
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
                    && ((live["ActiveState"] == "active" && live["SubState"] == "running")
                        || (live["ActiveState"] == "activating" && live["SubState"] == "start"))
                    && live["MainPID"]
                        .as_str()
                        .and_then(|s| s.parse::<u32>().ok())
                        .is_some_and(|pid| pid > 0),
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
    let clock_only = args.get(1).is_some_and(|s| s == "admit-clock144");
    let native_only = args.get(1).is_some_and(|s| s == "admit-native144");
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
        s.schema
            == if native_only {
                "jetstreamer-epoch144-native-admission-spec-v2"
            } else if clock_only {
                "jetstreamer-epoch144-clock-admission-spec-v1"
            } else {
                "jetstreamer-epoch144-snapshot-admission-spec-v1"
            }
            && if native_only {
                native_output(&s.output)
            } else {
                s.output
                    == if clock_only {
                        Path::new(
                            "/var/lib/jetstreamer-horizon-epoch144-snapshot-clock-20261021-v1/admission.json",
                        )
                    } else {
                        Path::new(OUTPUT)
                    }
            }
            && s.floor.sha256 == FLOOR_SHA
            && s.protection.sha256 == PROTECTION_SHA,
        "snapshot admission scope/protection differs"
    );
    ensure!(
        native_only == s.native.is_some(),
        "native-only evidence in wrong144 admission mode"
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
            == Some(if native_only {
                "jetstreamer-epoch144-native-restore-probe"
            } else if clock_only {
                "jetstreamer-epoch144-snapshot-clock"
            } else {
                "jetstreamer-epoch144-snapshot-download"
            }),
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
    if let Some(n) = &s.native {
        native_inputs(n, &s.downloader)?;
    }
    let future = unit(if native_only {
        "horizon-qualify-144-native-restore-20261021-v1.service"
    } else if clock_only {
        "horizon-epoch144-snapshot-clock-20261021-v1.service"
    } else {
        UNIT
    })?;
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
    let peak = if native_only {
        40u64 << 30
    } else {
        SIZE + SLACK
    };
    let memory_gib = if native_only { 192 } else { 129 };
    let minimum = PROTECTED.checked_add(peak).context("budget overflow")?;
    ensure!(
        observer["filesystem"]["conservative_available_bytes"]
            .as_u64()
            .is_some_and(|n| n >= minimum)
            && observer["host_memory"]["conservative_available_kib"]
                .as_u64()
                .is_some_and(|n| n >= memory_gib * 1024 * 1024),
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
        memory_available_kib >= memory_gib * 1024 * 1024 && vmas >= 4_194_304,
        "snapshot memory reserve or host VMA gate failed"
    );
    let after = census(&names, 101, 200)?;
    check_owners(&previous, &after)?;
    private157::immutable_receipt(
        &s.output,
        &json!({
            "schema":if native_only { "jetstreamer-epoch144-native-admission-receipt-v2" } else if clock_only { "jetstreamer-epoch144-clock-admission-receipt-v1" } else { "jetstreamer-epoch144-snapshot-admission-receipt-v1" },"epoch":144,"admitted":true,
            "recorded_unix_seconds":now,"invocation_id":invocation,"self_sha256":args[6],
            "spec":private157::binding(&spec_bound),"observer":private157::binding(&s.observer),"fleet":private157::binding(&s.fleet),
            "century_floor_bytes":floor_bytes,"protected_existing_floor_bytes":PROTECTED,"candidate_incremental_peak_bytes":peak,
            "input_policy_sha256":s.native.as_ref().map(|n|n.inputs.sha256.as_str()),"probe_sha256":if native_only {Some(s.downloader.sha256.as_str())} else {None},
            "worker_sha256":if native_only {Some("2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8")} else {None},
            "evidence":{"filesystem":"/home/sol","minimum_free_bytes":minimum,"available_bytes":available,
              "files":[private157::binding(&s.downloader),private157::binding(&s.metadata)],"unit_census":after,
              "memory_available_kib":memory_available_kib,"vm_max_map_count":vmas},
            "new_resource_samples":0,"download_only":!clock_only&&!native_only,"clock_only":clock_only,"restore_only":native_only,
            "guard_and_fleet_launch_gates_required":native_only,"replay_launch_authorized":false,"native_restore_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("snapshot-only admission passed; older claims and century floor unchanged");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "root read-only exact native144 capability/input/resource bindings; no admission or launch"]
    fn root_native144_input_policy_gate_passes_without_a_worker() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        native_inputs(&Native {
            inputs:BoundFile {path:"/usr/local/lib/jetstreamer/horizon-epoch144-native-probe-tools-20261021-v2/inputs.json".into(),sha256:"908cb628fc955f0ac66692d2742b34c1422b3ad06130b8fc8b28a94efaee682f".into()},
            capability:BoundFile {path:"/home/sol/.jetstreamer-private/epoch144-native-input-capability-20261021-v1/inputs.json".into(),sha256:"a9a8fb188816640ceef322697c4e8c7a421606e7a4fe9a95a9847d79ab89305e".into()},
            resource_proposal:BoundFile {path:"/usr/local/lib/jetstreamer/horizon-epoch144-native-probe-tools-20261021-v1/resource-proposal.json".into(),sha256:"ae18d37b9ed5a2eb38461e500ae75c0b6ea8e831a735afb764682e1566c64cda".into()},
        },&BoundFile {path:"/usr/local/lib/jetstreamer/horizon-epoch144-native-probe-tools-20261021-v2/jetstreamer-epoch144-native-restore-probe".into(),sha256:"a5f8dea7cf4beed6385c1b13719fd72bee3573162c3b303282f65bd2693e7237".into()}).unwrap();
    }
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
    #[test]
    fn pipeline_and_standalone_owners_remain_fully_bound() {
        for (state, substate) in [("active", "running"), ("activating", "start")] {
            let owner = json!({"Id":"pipeline.service","InvocationID":"b".repeat(32),"MainPID":"456","ActiveState":state,"SubState":substate,"NRestarts":"0","ExecStart":"sealed pipeline"});
            for row in [json!({"unit":owner}), json!({"producer":owner})] {
                let prior = json!({"unit_census":{"pipeline.service":owner},"active":[row]});
                let current = BTreeMap::from([("pipeline.service".into(), owner.clone())]);
                check_owners(&prior, &current).unwrap();
                for key in [
                    "InvocationID",
                    "MainPID",
                    "ActiveState",
                    "SubState",
                    "NRestarts",
                    "ExecStart",
                ] {
                    let mut changed = current.clone();
                    changed.get_mut("pipeline.service").unwrap()[key] = json!("changed");
                    assert!(check_owners(&prior, &changed).is_err(), "{key}");
                }
                assert!(check_owners(&prior, &BTreeMap::new()).is_err());
                let mut unbound = prior.clone();
                unbound["unit_census"] = json!({});
                assert!(check_owners(&unbound, &current).is_err());
            }
        }
    }
    #[test]
    fn unknown_or_ambiguous_owner_rows_fail_closed() {
        for row in [
            json!({}),
            json!({"controller":{}}),
            json!({"unit":{},"producer":{}}),
            json!({"controller":{},"producer":{},"unit":{}}),
        ] {
            assert!(
                check_owners(&json!({"unit_census":{},"active":[row]}), &BTreeMap::new()).is_err()
            );
        }
    }
}
#[test]
fn renewed_native_admission_is_unique_and_stays_in_exact_receipt_namespace() {
    let root = "/var/lib/jetstreamer/horizon-epoch144-native-restore-20261021-v1";
    assert!(native_output(&PathBuf::from(format!(
        "{root}/admission.json"
    ))));
    assert!(native_output(&PathBuf::from(format!(
        "{root}/admission-20261021T200800Z.json"
    ))));
    for p in [
        format!("{root}/admission-20260230T200800Z.json"),
        format!("{root}/other.json"),
        format!("{root}/../admission-20261021T200800Z.json"),
        "/tmp/admission.json".into(),
    ] {
        assert!(!native_output(Path::new(&p)), "{p}");
    }
}
