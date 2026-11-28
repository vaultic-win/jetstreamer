//! Explicit remote-preservation mode after the separate partial retirement.
//! This reads immutable local proof only; it cannot grant retirement, restore,
//! resource credit, or perform any remote operation.
use super::*;
use std::{ffi::CString, mem::MaybeUninit};

pub(super) const COMPLETION: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry6-completion.json";
const RECEIPTS: &str =
    "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements";
pub(super) const CUSTODY: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/receipts/custody-1b3cfb30c50e1072e002c10bb8a2f036b808c76a0458db6a316f575aae671369.json";
pub(super) const CUSTODY_SHA: &str =
    "a61bad61fba797de68da201fb7ededbf5de7ed3a05c2b9eee9368b414a85ef81";
const SOURCE: &str = "/home/sol/.jetstreamer-private/epoch166-standard-lane-20261109-v1/replacement-local3retry6-20261110-v1/private/destination-d53ec84bc26887772d067cda9258daa995dc2541cb1e81e71b72376b619ffe51/work/root-cohort-166-166/run-689067-1794918104133897328/archives/epoch-166.jet";
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry6-c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85.jet";
const ARCHIVE_SHA: &str = "c6edc4b47bb905fe8825f09155edcbc217d9ea44246a3a3b4d8deb4387384e85";
const ALLOCATED: u64 = 56_174_063_616;
const ETAG: &str = "d98ea9e64f6adc65a51c5ae843e44656-838";
const MANIFEST_SHA: &str = "1b3cfb30c50e1072e002c10bb8a2f036b808c76a0458db6a316f575aae671369";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const ELIGIBILITY: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/eligibility.json";
const ELIGIBILITY_SHA: &str = "6d7243eb5912b92d96367f57c94633be768937158d16a07923669ea972e79a97";
const INSPECTION_SHA: &str = "c2eb4c497d23b0be00468eedc6eb8445659beb188c5bbe58bb8ec1845b6b7c7f";
const PARK_PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-closed166-retry6-holding-plan-20261119-v1/plan.json";
const PARK_PLAN_SHA: &str = "a835a7adf66726ffbdc07eb13def1b917a9de799ff3dc9062ad7441cd182c640";
const PARK_UNIT: &str = "horizon-closed166-retry6-park-20261119-v1.service";
const PARK_IID: &str = "afc04ba6096f4826836919c2020dcdc6";
const PARK_HELPER: &str =
    "/usr/local/lib/jetstreamer/horizon-holding-candidate-20261023-v1/jetstreamer-r2";
const PARK_HELPER_SHA: &str = "909248d8e4c1db4c3cd89e1a4f15205b4a59d442494f35b7635038152025bb7e";
const EVIDENCE_ROOT: &str = "/var/lib/jetstreamer/holding166-retry6-retirement-evidence";
const MAX_PROOF: u64 = 1 << 20;

pub(super) fn schema_matches(schema: &str, stem: &str, held: &Option<Bound>) -> bool {
    schema == format!("{stem}-v{}", if held.is_some() { 2 } else { 1 })
}

pub(super) fn validate_binding(b: &Bound) -> Result<()> {
    ensure!(
        b.path == Path::new(COMPLETION) && lower_sha(&b.sha256),
        "held mode requires the exact completed retry6 partial-retirement receipt"
    );
    Ok(())
}

fn immutable_json(path: &Path, expected: Option<&str>) -> Result<(Value, Bound)> {
    immutable_json_owned(path, expected, 0)
}
fn immutable_json_owned(path: &Path, expected: Option<&str>, uid: u32) -> Result<(Value, Bound)> {
    let mut file = custody::open_regular(path, uid)?;
    let md = file.metadata()?;
    let before = custody::identity(&md);
    ensure!(
        md.mode() & 0o222 == 0 && md.len() <= MAX_PROOF,
        "mutable or oversized held-partial evidence"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_PROOF + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == md.len()
            && custody::identity(&file.metadata()?) == before
            && custody::identity(&fs::symlink_metadata(path)?) == before,
        "held-partial evidence changed while reading"
    );
    let digest = sha(&bytes);
    ensure!(
        expected.is_none_or(|want| want == digest),
        "held-partial evidence digest changed"
    );
    Ok((
        serde_json::from_slice(&bytes)?,
        Bound {
            path: path.to_owned(),
            sha256: digest,
        },
    ))
}

fn evidence_binding(value: &Value) -> Result<Bound> {
    let b: Bound = serde_json::from_value(value.clone())?;
    let parent = b.path.parent().context("retirement evidence parent")?;
    ensure!(
        lower_sha(&b.sha256)
            && parent.parent() == Some(Path::new(EVIDENCE_ROOT))
            && b.path.extension().is_some_and(|s| s == "json")
            && parent
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| !n.is_empty()
                    && n.len() <= 128
                    && n.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))),
        "held-partial evidence must be in an immutable versioned retirement bundle"
    );
    Ok(b)
}

fn validate_custody(c: &Value) -> Result<()> {
    let key = format!("node_02/objects/{ARCHIVE_SHA}.blob");
    ensure!(
        c["schema"] == "jetstreamer-horizon-holding-custody-v2"
            && c["source"] == SOURCE
            && c["sha256"] == ARCHIVE_SHA
            && c["length"] == ARCHIVE_BYTES
            && c["host"] == "dev-samjohnson"
            && c["bucket"] == "solana-archive-with-accounts-data"
            && c["prefix"] == "node_02/"
            && c["object_key"] == key
            && c["object_etag"] == ETAG
            && c["remote_sha256_readback"] == true
            && c["local_source_revalidated"] == true
            && c["local_retirement_authorized"] == false
            && c["canonical_publication_authorized"] == false
            && c["runtime_checkpoint_qualified"] == false
            && c["job_resume_authorized"] == false
            && c["replay_launch_authorized"] == false
            && c["mapping"] == json!(Bound::fixed(MAPPING, MAPPING_SHA))
            && c["eligibility"] == json!(Bound::fixed(ELIGIBILITY, ELIGIBILITY_SHA))
            && c["manifest_sha256"] == MANIFEST_SHA
            && c["manifest_key"] == format!("node_02/manifests/{MANIFEST_SHA}.json")
            && sha(&serde_json::to_vec(&c["manifest"])?) == MANIFEST_SHA
            && c["manifest"]["sha256"] == ARCHIVE_SHA
            && c["manifest"]["length"] == ARCHIVE_BYTES
            && c["manifest"]["uid"] == UID
            && c["manifest"]["gid"] == GID
            && c["manifest"]["mode"] == 0o600
            && c["manifest"]["canonical_archive"] == false,
        "exact authenticated old166 retry6 holding custody required"
    );
    Ok(())
}

fn validate_chain(complete: &Value, intent: &Value, moved: &Value, unlink: &Value) -> Result<()> {
    let inspection = evidence_binding(&intent["inspection"])?;
    evidence_binding(&intent["park_terminal"])?;
    ensure!(
        inspection.sha256 == INSPECTION_SHA,
        "historical inspection changed"
    );
    let retained = &intent["preserved"];
    ensure!(
        retained.is_object() && retained["state_sha256"] == STATE_SHA,
        "retirement does not retain the exact cohort state"
    );
    let expected_intent = json!({"schema":"jetstreamer-holding-retire166-retry6-intent-v1",
        "source":SOURCE,"quarantine":QUARANTINE,"sha256":ARCHIVE_SHA,"length":ARCHIVE_BYTES,"inode":ARCHIVE_INODE,
        "eligibility":Bound::fixed(ELIGIBILITY,ELIGIBILITY_SHA),"inspection":inspection,
        "custody":Bound::fixed(CUSTODY,CUSTODY_SHA),"mapping":Bound::fixed(MAPPING,MAPPING_SHA),
        "park_terminal":intent["park_terminal"],"preserved":retained,
        "canonical_archive":false,"scratch_retirement_authorized":false,"resource_credit_bytes":0,
        "resource_promise_ending_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
    let expected_moved = json!({"schema":"jetstreamer-holding-retire166-retry6-moved-v1",
        "intent":expected_intent,"local_sha256":ARCHIVE_SHA,"local_multipart_etag":ETAG});
    let expected_unlink = json!({"schema":"jetstreamer-holding-retire166-retry6-unlink-intent-v1",
        "moved":expected_moved,"authenticated_custody_revalidated":true});
    let expected_complete = json!({"schema":"jetstreamer-holding-retire166-retry6-completion-v1",
        "intent":expected_intent,"source_absent":true,"quarantine_absent":true,"preserved":retained,
        "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
        "authenticated_custody_revalidated":true,"scratch_retirement_authorized":false,
        "resource_credit_bytes":0,"resource_promise_ending_authorized":false,"replay_launch_authorized":false,
        "remote_mutations":false,"r2_mutations":false});
    ensure!(
        intent == &expected_intent
            && moved == &expected_moved
            && unlink == &expected_unlink
            && complete == &expected_complete,
        "incomplete, foreign, or rewritten held-partial retirement transition chain"
    );
    Ok(())
}

fn validate_park(p: &Value) -> Result<()> {
    let n = &p["native"];
    let argv = format!(
        "argv[]={PARK_HELPER} holding-park {PARK_PLAN} --spec-sha256 {PARK_PLAN_SHA} --self-sha256 {PARK_HELPER_SHA} ;"
    );
    ensure!(
        p["schema"] == "horizon-closed166-retry6-park-terminal-v1"
            && p["unit"] == PARK_UNIT
            && p["invocation_id"] == PARK_IID
            && p["helper"] == json!(Bound::fixed(PARK_HELPER, PARK_HELPER_SHA))
            && p["park_plan"] == json!(Bound::fixed(PARK_PLAN, PARK_PLAN_SHA))
            && n["Id"] == PARK_UNIT
            && n["InvocationID"] == PARK_IID
            && ((n["ActiveState"] == "active" && n["SubState"] == "exited")
                || (n["ActiveState"] == "inactive" && n["SubState"] == "dead"))
            && n["Result"] == "success"
            && n["ExecMainStatus"] == "0"
            && n["MainPID"] == "0"
            && n["ControlPID"] == "0"
            && n["Job"] == ""
            && n["Restart"] == "no"
            && n["TriggeredBy"] == ""
            && n["ExecStart"]
                .as_str()
                .is_some_and(|s| s.contains(&argv) && s.matches("argv[]=").count() == 1),
        "genuine successful original park terminal proof required"
    );
    Ok(())
}

// ENOENT for the final component, through a positively opened no-follow parent.
// Missing ancestors, dangling symlinks, EACCES and any present object fail.
fn absent(path: &Path) -> Result<()> {
    let parent_path = path.parent().context("absence parent")?;
    let parent = custody::open_directory(parent_path)?;
    let before = custody::identity(&parent.metadata()?);
    let name = CString::new(path.file_name().context("absence basename")?.as_bytes())?;
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    let error = std::io::Error::last_os_error();
    ensure!(
        rc == -1 && error.raw_os_error() == Some(libc::ENOENT),
        "held partial is present or absence cannot be established: {}",
        path.display()
    );
    ensure!(
        custody::identity(&parent.metadata()?) == before
            && custody::identity(&custody::open_directory(parent_path)?.metadata()?) == before,
        "absence parent changed"
    );
    Ok(())
}

fn absent_and_empty(source: &Path, quarantine: &Path) -> Result<()> {
    absent(source)?;
    absent(quarantine)?;
    let archives = source.parent().context("archives parent")?;
    let held = custody::open_directory(archives)?;
    let before = custody::identity(&held.metadata()?);
    ensure!(
        fs::read_dir(archives)?.next().transpose()?.is_none(),
        "held-mode archives directory is not empty"
    );
    ensure!(
        custody::identity(&held.metadata()?) == before
            && custody::identity(&custody::open_directory(archives)?.metadata()?) == before,
        "archives directory changed during absence check"
    );
    absent(source)?;
    absent(quarantine)?;
    Ok(())
}

pub(super) fn require_absent() -> Result<()> {
    absent_and_empty(Path::new(SOURCE), Path::new(QUARANTINE))
}

fn first_five(v: &Value, expected_len: usize) -> Result<Value> {
    let values = v.as_array().context("preserved identity array")?;
    ensure!(
        values.len() == expected_len && expected_len >= 5,
        "incomplete preserved identity"
    );
    Ok(json!(&values[..5]))
}

fn preserved_matches(
    retained: &Value,
    current: &BTreeMap<String, Value>,
    ancestors: &Value,
) -> Result<()> {
    let inputs: BTreeMap<_, _> = current
        .iter()
        .filter(|(name, _)| *name == "inputs" || name.starts_with("inputs/"))
        .map(|(name, value)| {
            (
                Path::new(RUN).join(name).to_string_lossy().into_owned(),
                value,
            )
        })
        .collect();
    ensure!(
        current.get("") == Some(&retained["run"])
            && current.get("cohort-state.json") == Some(&retained["state"])
            && retained["state_sha256"] == STATE_SHA
            && current.get("scratch") == Some(&first_five(&retained["scratch"], 12)?)
            && current
                .get("archives")
                .map(|v| first_five(v, 12))
                .transpose()?
                == Some(retained["archives_directory"].clone())
            && json!(inputs) == retained["inputs"]
            && !inputs.is_empty()
            && ancestors == &retained["ancestors"],
        "held retirement and current retained inputs/state/ancestors disagree"
    );
    Ok(())
}

pub(super) fn verify(b: &Bound, current: &BTreeMap<String, Value>) -> Result<Value> {
    validate_binding(b)?;
    let (complete, _) = immutable_json(&b.path, Some(&b.sha256))?;
    let (custody, custody_binding) = immutable_json(Path::new(CUSTODY), Some(CUSTODY_SHA))?;
    validate_custody(&custody)?;
    let mut chain = Vec::new();
    let mut bindings = Vec::new();
    for name in [
        "epoch166-retry6-intent.json",
        "epoch166-retry6-moved.json",
        "epoch166-retry6-unlink-intent.json",
    ] {
        let (value, binding) = immutable_json(&Path::new(RECEIPTS).join(name), None)?;
        chain.push(value);
        bindings.push(binding);
    }
    validate_chain(&complete, &chain[0], &chain[1], &chain[2])?;
    for field in ["inspection", "park_terminal"] {
        let binding = evidence_binding(&chain[0][field])?;
        let (value, _) = immutable_json(&binding.path, Some(&binding.sha256))?;
        if field == "park_terminal" {
            validate_park(&value)?;
        }
        bindings.push(binding);
    }
    let ancestors: BTreeMap<_, _> = Path::new(RUN)
        .ancestors()
        .map(|path| {
            Ok((
                path.to_string_lossy().into_owned(),
                custody::directory_identity(&custody::open_directory(path)?.metadata()?),
            ))
        })
        .collect::<Result<_>>()?;
    preserved_matches(&complete["preserved"], current, &json!(ancestors))?;
    require_absent()?;
    Ok(
        json!({"schema":"horizon-retry6-166-held-partial-preservation-v1",
        "completion":b,"custody":custody_binding,"transition_and_terminal_evidence":bindings,
        "source":SOURCE,"quarantine":QUARANTINE,"source_absent":true,"quarantine_absent":true,
        "archives_empty":true,"sha256":ARCHIVE_SHA,"length":ARCHIVE_BYTES,"original_inode":ARCHIVE_INODE,
        "remote_mutations":false,"resource_credit_bytes":0,"resource_promise_ending_authorized":false}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn custody_fixture() -> Value {
        serde_json::from_str(include_str!("../fixtures/holding-custody.json")).unwrap()
    }
    fn chain() -> [Value; 4] {
        // Synthetic lifecycle fixture, never operational evidence.
        let retained = json!({"state_sha256":STATE_SHA});
        let intent = json!({"schema":"jetstreamer-holding-retire166-retry6-intent-v1",
            "source":SOURCE,"quarantine":QUARANTINE,"sha256":ARCHIVE_SHA,"length":ARCHIVE_BYTES,"inode":ARCHIVE_INODE,
            "eligibility":Bound::fixed(ELIGIBILITY,ELIGIBILITY_SHA),
            "inspection":Bound::fixed(&format!("{EVIDENCE_ROOT}/fixture/inspection.json"),INSPECTION_SHA),
            "custody":Bound::fixed(CUSTODY,CUSTODY_SHA),"mapping":Bound::fixed(MAPPING,MAPPING_SHA),
            "park_terminal":Bound::fixed(&format!("{EVIDENCE_ROOT}/fixture/park-terminal.json"),&"a".repeat(64)),
            "preserved":retained,"canonical_archive":false,"scratch_retirement_authorized":false,
            "resource_credit_bytes":0,"resource_promise_ending_authorized":false,
            "replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let moved = json!({"schema":"jetstreamer-holding-retire166-retry6-moved-v1",
            "intent":intent,"local_sha256":ARCHIVE_SHA,"local_multipart_etag":ETAG});
        let unlink = json!({"schema":"jetstreamer-holding-retire166-retry6-unlink-intent-v1",
            "moved":moved,"authenticated_custody_revalidated":true});
        let completion = json!({"schema":"jetstreamer-holding-retire166-retry6-completion-v1",
            "intent":intent,"source_absent":true,"quarantine_absent":true,"preserved":retained,
            "retired_censused_physical_bytes":ALLOCATED,"actual_free_delta_claimed":false,
            "authenticated_custody_revalidated":true,"scratch_retirement_authorized":false,
            "resource_credit_bytes":0,"resource_promise_ending_authorized":false,
            "replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        [completion, intent, moved, unlink]
    }
    fn accepted(values: &[Value; 4]) -> bool {
        validate_chain(&values[0], &values[1], &values[2], &values[3]).is_ok()
    }
    #[test]
    fn modes_are_explicit_and_local_mode_remains_v1() {
        let held = Some(Bound::fixed(COMPLETION, &"a".repeat(64)));
        assert!(schema_matches("plan-v1", "plan", &None));
        assert!(schema_matches("plan-v2", "plan", &held));
        assert!(!schema_matches("plan-v2", "plan", &None));
        assert!(!schema_matches("plan-v1", "plan", &held));
        validate_binding(held.as_ref().unwrap()).unwrap();
        assert!(
            validate_binding(&Bound::fixed("/foreign/completion.json", &"a".repeat(64))).is_err()
        );
        assert!(validate_binding(&Bound::fixed(COMPLETION, "")).is_err());
        let p = super::super::tests::plan();
        assert!(p.held_partial_completion.is_none());
        validate_plan(&p).unwrap();
        let mut v = serde_json::to_value(&p).unwrap();
        v["held_partial_completion"] = json!(held);
        assert!(validate_plan(&serde_json::from_value(v.clone()).unwrap()).is_err());
        v["schema"] = json!("horizon-retry6-166-scratch-retirement-plan-v2");
        validate_plan(&serde_json::from_value(v.clone()).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("held_partial_completion");
        assert!(validate_plan(&serde_json::from_value(v).unwrap()).is_err());
    }
    #[test]
    fn actual_custody_and_terminal_records_are_supported() {
        let raw = include_bytes!("../fixtures/holding-custody.json");
        assert_eq!(sha(raw), CUSTODY_SHA);
        validate_custody(&custody_fixture()).unwrap();
        let terminal: Value =
            serde_json::from_str(include_str!("../fixtures/park-terminal.json")).unwrap();
        validate_park(&terminal).unwrap();
        for (key, value) in [
            ("InvocationID", json!("foreign")),
            ("MainPID", json!("1")),
            ("Job", json!("queued")),
            ("Result", json!("failed")),
            ("ExecMainStatus", json!("1")),
            ("Restart", json!("always")),
            ("ExecStart", json!("unrelated command")),
        ] {
            let mut bad = terminal.clone();
            bad["native"][key] = value;
            assert!(validate_park(&bad).is_err(), "accepted native {key}");
        }
    }
    #[test]
    fn altered_or_unverified_custody_is_rejected() {
        let c = custody_fixture();
        for (key, value) in [
            ("source", json!("/foreign")),
            ("sha256", json!("b".repeat(64))),
            ("length", json!(ARCHIVE_BYTES - 1)),
            ("object_etag", json!("foreign")),
            ("remote_sha256_readback", json!(false)),
            ("local_source_revalidated", json!(false)),
            ("replay_launch_authorized", json!(true)),
            ("mapping", Value::Null),
            ("manifest", Value::Null),
        ] {
            let mut bad = c.clone();
            bad[key] = value;
            assert!(validate_custody(&bad).is_err(), "accepted custody {key}");
        }
    }
    #[test]
    fn retirement_requires_immutable_complete_chain() {
        let valid = chain();
        assert!(accepted(&valid));
        for index in 0..4 {
            for replacement in [Value::Null, json!({}), json!({"foreign":true})] {
                let mut bad = valid.clone();
                bad[index] = replacement;
                assert!(!accepted(&bad));
            }
        }
        for (index, key, value) in [
            (0, "source_absent", json!(false)),
            (0, "quarantine_absent", json!(false)),
            (0, "authenticated_custody_revalidated", json!(false)),
            (0, "resource_credit_bytes", json!(1)),
            (1, "inode", json!(ARCHIVE_INODE + 1)),
            (1, "source", json!("/foreign")),
            (1, "custody", json!(Bound::fixed(CUSTODY, &"b".repeat(64)))),
            (2, "local_sha256", json!("b".repeat(64))),
            (3, "authenticated_custody_revalidated", json!(false)),
        ] {
            let mut bad = valid.clone();
            bad[index][key] = value;
            assert!(!accepted(&bad), "accepted {index}:{key}");
        }
    }
    #[test]
    fn missing_changed_writable_or_aliased_records_fail() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("proof.json");
        let uid = unsafe { libc::geteuid() };
        assert!(immutable_json_owned(&p, None, uid).is_err());
        fs::write(&p, b"{}").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        let digest = sha(b"{}");
        immutable_json_owned(&p, Some(&digest), uid).unwrap();
        assert!(immutable_json_owned(&p, Some(&"f".repeat(64)), uid).is_err());
        assert!(immutable_json_owned(&p, None, uid + 1).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(immutable_json_owned(&p, None, uid).is_err());
        fs::write(&p, b"[]").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(immutable_json_owned(&p, Some(&digest), uid).is_err());
        fs::hard_link(&p, d.path().join("hardlink.json")).unwrap();
        assert!(immutable_json_owned(&p, None, uid).is_err());
        fs::remove_file(&p).unwrap();
        symlink("/definitely-missing-horizon-proof", &p).unwrap();
        assert!(immutable_json_owned(&p, None, uid).is_err());
    }
    #[test]
    fn held_source_and_quarantine_absence_require_empty_directory_and_real_parents() {
        let d = tempfile::tempdir().unwrap();
        let archives = d.path().join("archives");
        fs::create_dir(&archives).unwrap();
        let source = archives.join("epoch-166.jet");
        let quarantine = d.path().join("quarantine.jet");
        absent_and_empty(&source, &quarantine).unwrap();
        for path in [&source, &quarantine] {
            fs::write(path, b"reappeared").unwrap();
            assert!(absent_and_empty(&source, &quarantine).is_err());
            fs::remove_file(path).unwrap();
            symlink("/definitely-missing-horizon-source", path).unwrap();
            assert!(absent_and_empty(&source, &quarantine).is_err());
            fs::remove_file(path).unwrap();
        }
        fs::write(archives.join("foreign.jet"), b"extra").unwrap();
        assert!(absent_and_empty(&source, &quarantine).is_err());
        fs::remove_file(archives.join("foreign.jet")).unwrap();
        symlink(&archives, d.path().join("alias")).unwrap();
        assert!(absent(&d.path().join("alias/epoch-166.jet")).is_err());
        assert!(absent(&d.path().join("missing-parent/missing")).is_err());
    }
    #[test]
    fn retained_inputs_state_and_ancestors_must_match_completed_retirement() {
        let identity = json!([DEVICE, 10, UID, GID, 0o40700, 2, 4096, 8, 100, 0, 100, 0]);
        let mut current = BTreeMap::new();
        for key in [
            "",
            "cohort-state.json",
            "archives",
            "inputs",
            "inputs/snapshot.bin",
        ] {
            current.insert(key.into(), identity.clone());
        }
        current.insert("scratch".into(), first_five(&identity, 12).unwrap());
        let ancestors = json!({RUN:first_five(&identity,12).unwrap()});
        let retained = json!({"run":identity,"state":identity,"state_sha256":STATE_SHA,
            "scratch":identity,"archives_directory":first_five(&identity,12).unwrap(),
            "ancestors":ancestors,"inputs":{
                format!("{RUN}/inputs"):identity,format!("{RUN}/inputs/snapshot.bin"):identity}});
        preserved_matches(&retained, &current, &ancestors).unwrap();
        for key in [
            "",
            "cohort-state.json",
            "archives",
            "inputs",
            "inputs/snapshot.bin",
            "scratch",
        ] {
            let mut bad = current.clone();
            bad.get_mut(key).unwrap()[1] = json!(11);
            assert!(
                preserved_matches(&retained, &bad, &ancestors).is_err(),
                "accepted changed {key}"
            );
        }
        let mut bad = current.clone();
        bad.remove("inputs/snapshot.bin");
        assert!(preserved_matches(&retained, &bad, &ancestors).is_err());
        assert!(preserved_matches(&retained, &current, &json!({})).is_err());
    }
}
