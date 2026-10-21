//! Observational finalization for the exact already-running epoch198 singleton.
//! These logs are not independent verification, publication or ready-pair proof.
use super::*;
use std::{collections::BTreeMap, process::Command};

pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-e198-readerfix-20261019-v1-r2-e198-198-lane-a-1.service";
const INVOCATION: &str = "e5612ef00a5b4fcab04df2c13a6b35b0";
const PID: &str = "1165606";
const NODE: &str =
    "/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/jetstreamer-node";
const NODE_SHA: &str = "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/preflight-198-singleton-v4.json";
const MANIFEST_SHA: &str = "f1d0ff0521379a4c1dcd5461dca144d5d2484b3fc2d09f1f613c5ddd0a6c4d7e";
const FINGERPRINT: &str = "2ac1c3bbb1d030f1bd1e8d7d19770e97d82153e9355d0bc18ca65ad9291b3d3b";
const DESTINATION: &str =
    "/home/sol/.jetstreamer-private/epoch198-readerfix-singleton-20261019-v1/lane-a/output";
const ROOT_HASH: &str = "BQvC7FcQTSguJkWHeLnpkVSFv32ZKRqUbgHKxVF97o3x";
const SNAPSHOT: &str = "/usr/local/lib/jetstreamer/deploy-epoch198-readerfix-singleton-20261019-v1/snapshot-85535493-G6CxfFLUbddvo4Ew56wjEF6kasB1CVPB4rFqkFkTDwVW.tar.zst";
const OBSERVATION_ROOT: &str = "/var/lib/jetstreamer/horizon-epoch198-delivery-observations-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationPlan {
    schema: String,
    output: PathBuf,
    not_before_unix_seconds: u64,
    expires_unix_seconds: u64,
    expected_unit: String,
    expected_invocation_id: String,
    expected_exec_start_sha256: String,
    replay_launch_authorized: bool,
    publication_authorized: bool,
    r2_mutations: bool,
}

fn validate_observation_plan(p: &ObservationPlan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-epoch198-delivery-observation-plan-v1"
            && p.expected_unit == UNIT
            && p.expected_invocation_id == INVOCATION
            && is_lower_hex(&p.expected_exec_start_sha256, 64)
            && !p.replay_launch_authorized
            && !p.publication_authorized
            && !p.r2_mutations,
        "unqualified198 observation plan"
    );
    ensure!(
        p.not_before_unix_seconds > 0
            && p.expires_unix_seconds
                .checked_sub(p.not_before_unix_seconds)
                .is_some_and(|seconds| seconds > 0 && seconds <= 1800),
        "198 observation window exceeds one control interval"
    );
    let name = p
        .output
        .file_name()
        .and_then(|s| s.to_str())
        .context("198 proof filename missing")?;
    ensure!(
        p.output.parent() == Some(Path::new(OBSERVATION_ROOT))
            && name.starts_with("proof-")
            && name.ends_with(".json")
            && name.len() <= 96
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "198 observation output outside exact private namespace"
    );
    Ok(())
}

fn write_observation(path: &Path, value: &Value) -> Result<()> {
    resource_audit::private_directory(path.parent().context("198 proof parent missing")?)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

/// Event-driven evidence only. No resource scans, cadence consumption, R2,
/// production status update or service mutation. Check-only claims no terminal.
pub(super) fn run_observation() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        (args.len() == 7 || (args.len() == 8 && args[7] == "--check-only"))
            && args[3] == "--plan-sha256"
            && args[5] == "--self-sha256",
        "usage: jetstreamer-r2 observe-delivery-198 PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "198 delivery observation requires root"
    );
    ensure!(
        is_lower_hex(&args[4], 64) && is_lower_hex(&args[6], 64),
        "invalid198 observation digest"
    );
    let executable = fs::read_link("/proc/self/exe")?;
    let mut running = File::open("/proc/self/exe")?;
    let running_meta = running.metadata()?;
    ensure!(
        running_meta.is_file()
            && running_meta.uid() == 0
            && running_meta.nlink() == 1
            && running_meta.mode() & 0o222 == 0
            && running_meta.len() <= 128 << 20
            && regular_identity(&executable)? == identity(&running_meta),
        "198 observer is not an immutable running executable"
    );
    let mut bytes = Vec::new();
    (&mut running)
        .take((128 << 20) + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == running_meta.len()
            && identity(&running.metadata()?) == identity(&running_meta)
            && regular_identity(&executable)? == identity(&running_meta)
            && hex_lower(&Sha256::digest(&bytes)) == args[6],
        "198 running executable digest/identity differs"
    );
    let path = Path::new(&args[2]);
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && meta.uid() == 0
            && meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o222 == 0,
        "unsafe198 observation plan"
    );
    let bytes = read_stable_bounded(path, 1 << 20, "198 observation plan")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == args[4],
        "198 observation plan digest differs"
    );
    let plan: ObservationPlan = serde_json::from_slice(&bytes)?;
    validate_observation_plan(&plan)?;
    resource_audit::private_directory(Path::new(OBSERVATION_ROOT))?;
    ensure!(
        !plan.output.try_exists()?,
        "198 proof output already exists"
    );
    let before = fleet::unit(UNIT)?;
    validate_owner(&before)?;
    ensure!(
        before["ExecStart"].as_str().is_some_and(
            |s| hex_lower(&Sha256::digest(s.as_bytes())) == plan.expected_exec_start_sha256
        ),
        "198 planned exact command differs"
    );
    immutable_inputs()?;
    if args.len() == 8 {
        ensure!(
            fleet::unit(UNIT)? == before,
            "198 owner changed during preflight"
        );
        println!(
            "198 delivery preflight passed; no terminal events, resource sample, proof write, R2 access or mutation"
        );
        return Ok(());
    }
    let sampled = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        (plan.not_before_unix_seconds..=plan.expires_unix_seconds).contains(&sampled),
        "198 observation outside bound event window"
    );
    let proof = observe(&before, sampled)?;
    let after = fleet::unit(UNIT)?;
    ensure!(
        after == before,
        "198 finalization owner changed during evidence capture"
    );
    let completed = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        completed <= plan.expires_unix_seconds,
        "198 observation exceeded event window"
    );
    write_observation(
        &plan.output,
        &serde_json::json!({
        "schema":"jetstreamer-epoch198-delivery-observation-v1","plan":{"path":path,"sha256":args[4]},
        "observer_sha256":args[6],"observed_unix_seconds":sampled,"completed_unix_seconds":completed,
        "epoch":198,"phase":"producer-finalization","before":before,"after":after,"terminal_evidence":proof,
        "resource_sample_taken":false,"cadence_consumed":false,"status_publication_authorized":false,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )?;
    println!("{}", plan.output.display());
    Ok(())
}

fn validate_owner(current: &Value) -> Result<()> {
    for (key, value) in [
        ("Id", UNIT),
        ("LoadState", "loaded"),
        ("ActiveState", "active"),
        ("SubState", "running"),
        ("InvocationID", INVOCATION),
        ("MainPID", PID),
        ("NRestarts", "0"),
    ] {
        ensure!(
            current[key] == value,
            "198 finalization owner differs: {key}"
        );
    }
    let command = current["ExecStart"]
        .as_str()
        .context("198 command missing")?;
    ensure!(command.starts_with(&format!("{{ path={NODE} ; argv[]={NODE} 198 {DESTINATION} --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint=sha256:{FINGERPRINT} --snapshot-archive={SNAPSHOT} ;"))
        && command.matches("{ path=").count()==1,
        "198 finalization is not the exact sealed singleton command");
    Ok(())
}

fn immutable_inputs() -> Result<()> {
    for (path, expected, limit) in [
        (NODE, NODE_SHA, 128 << 20),
        (MANIFEST, MANIFEST_SHA, 1 << 20),
    ] {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file()
                && meta.uid() == 0
                && meta.nlink() == 1
                && meta.mode() & 0o222 == 0
                && Path::new(path).canonicalize()? == Path::new(path),
            "unsafe198 immutable input"
        );
        let bytes = read_stable_bounded(Path::new(path), limit, "198 finalization input")?;
        ensure!(
            hex_lower(&Sha256::digest(&bytes)) == expected,
            "198 immutable input digest differs"
        );
    }
    Ok(())
}

fn fields<'a>(message: &'a str, marker: &str) -> Result<BTreeMap<&'a str, &'a str>> {
    let (_, body) = message
        .split_once(marker)
        .context("198 event marker missing")?;
    let body = body.split(" (payload ").next().unwrap();
    let mut fields = BTreeMap::new();
    for token in body.split_whitespace() {
        let (key, value) = token.split_once('=').context("198 malformed event field")?;
        ensure!(
            !value.is_empty() && fields.insert(key, value).is_none(),
            "198 duplicate/empty event field"
        );
    }
    Ok(fields)
}

fn integer(fields: &BTreeMap<&str, &str>, name: &str) -> Result<u64> {
    let text = fields.get(name).context("198 integer field missing")?;
    ensure!(
        text.bytes().all(|b| b.is_ascii_digit()),
        "198 non-integer event field"
    );
    Ok(text.parse()?)
}

fn checkpoint(message: &str, slot: u64) -> Result<()> {
    let f = fields(message, "historical checkpoint ")?;
    ensure!(
        f.len() == 10 && integer(&f, "slot")? == slot && f.get("complete") == Some(&"true"),
        "198 incomplete/wrong checkpoint"
    );
    for name in ["bank_hash", "accounts_hash", "last_blockhash"] {
        let value = f.get(name).context("198 hash field missing")?;
        ensure!(
            (32..=44).contains(&value.len())
                && value.bytes().all(|b| {
                    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b)
                }),
            "198 malformed checkpoint hash"
        );
    }
    for name in [
        "capitalization",
        "transactions",
        "tick_height",
        "writes",
        "next_write_version",
    ] {
        integer(&f, name)?;
    }
    ensure!(
        integer(&f, "tick_height")? == (slot + 1) * 64,
        "198 tick height differs"
    );
    if slot == 85_967_282 {
        ensure!(
            f["accounts_hash"] == ROOT_HASH,
            "198 trusted root hash differs"
        );
    }
    Ok(())
}

fn terminal_events(records: &[Value], sampled_seconds: u64) -> Result<Value> {
    let mut selected = Vec::new();
    for marker in [
        "historical checkpoint slot=85967282 ",
        "historical checkpoint slot=85967999 ",
        "snapshot verification complete",
        "horizon archive complete:",
    ] {
        let matching: Vec<_> = records
            .iter()
            .filter(|r| r["MESSAGE"].as_str().is_some_and(|s| s.contains(marker)))
            .collect();
        ensure!(
            matching.len() == 1,
            "198 finalization event missing or duplicated"
        );
        let r = matching[0];
        ensure!(
            r["_SYSTEMD_INVOCATION_ID"] == INVOCATION
                && r["_SYSTEMD_UNIT"] == UNIT
                && r["_PID"] == PID
                && r["_UID"] == "1001",
            "unbound198 finalization event"
        );
        let timestamp = r["__REALTIME_TIMESTAMP"]
            .as_str()
            .context("198 event time missing")?
            .parse::<u64>()?;
        ensure!(
            timestamp > 0
                && timestamp
                    <= sampled_seconds
                        .checked_mul(1_000_000)
                        .context("198 sample timestamp overflow")?,
            "198 event is after coordinated sample"
        );
        selected.push((timestamp, r));
    }
    ensure!(
        selected.windows(2).all(|w| w[0].0 < w[1].0),
        "198 finalization events out of order"
    );
    checkpoint(selected[0].1["MESSAGE"].as_str().unwrap(), 85_967_282)?;
    checkpoint(selected[1].1["MESSAGE"].as_str().unwrap(), 85_967_999)?;
    let archive = fields(
        selected[3].1["MESSAGE"].as_str().unwrap(),
        "horizon archive complete: ",
    )?;
    ensure!(
        archive.len() == 8
            && integer(&archive, "slots")? == 432_000
            && integer(&archive, "epochs")? == 1
            && integer(&archive, "buckets")? == 3375
            && integer(&archive, "bytes")? > 0
            && integer(&archive, "blocks")? <= 432_000,
        "198 archive close is not a complete singleton span"
    );
    for key in ["txs", "tx_updates", "orphan_updates"] {
        integer(&archive, key)?;
    }
    Ok(
        serde_json::json!({"schema":"jetstreamer-epoch198-finalization-events-v1",
        "unit":UNIT,"invocation_id":INVOCATION,"node_sha256":NODE_SHA,
        "manifest_sha256":MANIFEST_SHA,"terminal_slot":85967999,"trusted_root_slot":85967282,
        "events":selected.iter().map(|(_,r)|*r).collect::<Vec<_>>(),
        "archive_close_bytes":integer(&archive,"bytes")?,"replay_terminal_observed":true,
        "independent_full_verification_passed":false,"publication_authorized":false,
        "replay_launch_authorized":false,"r2_mutations":false}),
    )
}

pub(super) fn observe(current: &Value, sampled_seconds: u64) -> Result<Value> {
    validate_owner(current)?;
    immutable_inputs()?;
    let output = Command::new("/usr/bin/journalctl").args([
        &format!("_SYSTEMD_INVOCATION_ID={INVOCATION}"),&format!("_SYSTEMD_UNIT={UNIT}"),
        "-g","historical checkpoint slot=85967282 |historical checkpoint slot=85967999 |snapshot verification complete|horizon archive complete:",
        "-n","32","--no-pager","-o","json",
    ]).output()?;
    ensure!(
        output.status.success() && output.stdout.len() <= 1 << 20,
        "198 journal unavailable/oversized"
    );
    let records: Vec<Value> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(serde_json::from_str)
        .collect::<std::result::Result<_, _>>()?;
    terminal_events(&records, sampled_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn plan() -> ObservationPlan {
        ObservationPlan {
            schema: "jetstreamer-epoch198-delivery-observation-plan-v1".into(),
            output: Path::new(OBSERVATION_ROOT).join("proof-fixture.json"),
            not_before_unix_seconds: 100,
            expires_unix_seconds: 1900,
            expected_unit: UNIT.into(),
            expected_invocation_id: INVOCATION.into(),
            expected_exec_start_sha256: "a".repeat(64),
            replay_launch_authorized: false,
            publication_authorized: false,
            r2_mutations: false,
        }
    }
    #[test]
    fn observation_plan_is_bounded_exact_private_and_non_authorizing() {
        validate_observation_plan(&plan()).unwrap();
        for (start, end) in [(0, 100), (100, 100), (101, 100), (100, 1901), (u64::MAX, 0)] {
            let mut p = plan();
            p.not_before_unix_seconds = start;
            p.expires_unix_seconds = end;
            assert!(validate_observation_plan(&p).is_err());
        }
        for output in [
            "/tmp/proof-fixture.json",
            "/var/lib/jetstreamer/horizon-epoch198-delivery-observations-v1/sub/proof-fixture.json",
            "/var/lib/jetstreamer/horizon-epoch198-delivery-observations-v1/epoch-198.jet",
        ] {
            let mut p = plan();
            p.output = output.into();
            assert!(validate_observation_plan(&p).is_err());
        }
        let mut p = plan();
        p.publication_authorized = true;
        assert!(validate_observation_plan(&p).is_err());
        let mut p = plan();
        p.r2_mutations = true;
        assert!(validate_observation_plan(&p).is_err());
        let mut p = plan();
        p.replay_launch_authorized = true;
        assert!(validate_observation_plan(&p).is_err());
        let mut p = plan();
        p.expected_invocation_id = "b".repeat(32);
        assert!(validate_observation_plan(&p).is_err());
    }

    #[test]
    fn observation_plan_rejects_unknown_or_missing_authority_fields() {
        let value = json!({"schema":"jetstreamer-epoch198-delivery-observation-plan-v1",
            "output":Path::new(OBSERVATION_ROOT).join("proof-fixture.json"),
            "not_before_unix_seconds":100,"expires_unix_seconds":1900,
            "expected_unit":UNIT,"expected_invocation_id":INVOCATION,"expected_exec_start_sha256":"a".repeat(64),
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
        let _: ObservationPlan = serde_json::from_value(value.clone()).unwrap();
        for key in [
            "publication_authorized",
            "replay_launch_authorized",
            "r2_mutations",
        ] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(key);
            assert!(serde_json::from_value::<ObservationPlan>(bad).is_err());
        }
        let mut bad = value;
        bad["archive_upload_authorized"] = json!(true);
        assert!(serde_json::from_value::<ObservationPlan>(bad).is_err());
    }

    #[test]
    #[ignore = "requires sealed root fixture test; writes only private disposable /tmp fixture"]
    fn proof_writer_is_private_durable_and_never_clobbers() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("fixture.json");
        let value = json!({"fixture_only":true,"u64":u64::MAX,"publication_authorized":false});
        write_observation(&path, &value).unwrap();
        let before = fs::read(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(
            serde_json::from_slice::<Value>(&before).unwrap()["u64"],
            u64::MAX
        );
        assert!(write_observation(&path, &json!({"replacement":true})).is_err());
        assert_eq!(fs::read(path).unwrap(), before);
    }
    fn owner() -> Value {
        json!({"Id":UNIT,"LoadState":"loaded","ActiveState":"active","SubState":"running",
            "InvocationID":INVOCATION,"MainPID":PID,"NRestarts":"0",
            "ExecStart":format!("{{ path={NODE} ; argv[]={NODE} 198 {DESTINATION} --verify --root-checkpoint-cohort --cohort-manifest={MANIFEST} --cohort-manifest-fingerprint=sha256:{FINGERPRINT} --snapshot-archive={SNAPSHOT} ; }}")})
    }
    fn records() -> Vec<Value> {
        let message = |slot: u64, hash| {
            format!(
                "historical checkpoint slot={slot} bank_hash={ROOT_HASH} accounts_hash={hash} last_blockhash={ROOT_HASH} capitalization=498711268750098471 transactions=20629888884 tick_height={} complete=true writes=0 next_write_version=77987646769",
                (slot + 1) * 64
            )
        };
        [message(85_967_282,ROOT_HASH),message(85_967_999,ROOT_HASH),
            "snapshot verification complete".into(),
            "horizon archive complete: slots=432000 blocks=400000 txs=9 tx_updates=9 orphan_updates=9 epochs=1 buckets=3375 bytes=100000000000 (payload 200000000000 uncompressed)".into()]
            .into_iter().enumerate().map(|(i,m)|json!({"MESSAGE":m,"_PID":PID,"_UID":"1001",
                "_SYSTEMD_UNIT":UNIT,"_SYSTEMD_INVOCATION_ID":INVOCATION,
                "__REALTIME_TIMESTAMP":((i as u64+10)*1_000_000).to_string()})).collect()
    }
    #[test]
    fn exact_singleton_events_are_only_observational() {
        validate_owner(&owner()).unwrap();
        let proof = terminal_events(&records(), 13).unwrap();
        assert_eq!(proof["terminal_slot"], 85967999);
        for key in [
            "publication_authorized",
            "independent_full_verification_passed",
            "replay_launch_authorized",
            "r2_mutations",
        ] {
            assert_eq!(proof[key], false);
        }
        assert!(
            super::super::cohort_finalization::scope(UNIT)
                .unwrap()
                .contains(&198)
        );
        assert!(
            !super::super::cohort_finalization::scope(UNIT)
                .unwrap()
                .contains(&199)
        );
        assert!(super::super::cohort_finalization::handoff_scope(UNIT).is_err());
    }
    #[test]
    fn replacement_restart_wrong_command_and_terminal_owner_fail() {
        for (key, value) in [
            ("NRestarts", "1"),
            ("InvocationID", "replacement"),
            ("MainPID", "0"),
            ("ActiveState", "inactive"),
            ("Id", super::super::cohort_finalization::UNIT),
        ] {
            let mut bad = owner();
            bad[key] = json!(value);
            assert!(validate_owner(&bad).is_err(), "{key}");
        }
        let mut bad = owner();
        bad["ExecStart"] = json!(
            owner()["ExecStart"]
                .as_str()
                .unwrap()
                .replace(" 198 ", " 199 ")
        );
        assert!(validate_owner(&bad).is_err());
    }
    #[test]
    fn missing_duplicate_foreign_late_or_out_of_order_events_fail() {
        let r = records();
        assert!(terminal_events(&r[..3], 13).is_err());
        let mut bad = r.clone();
        bad.push(r[3].clone());
        assert!(terminal_events(&bad, 13).is_err());
        for (key, value) in [
            ("_PID", "other"),
            ("_UID", "0"),
            ("_SYSTEMD_UNIT", "other.service"),
            ("_SYSTEMD_INVOCATION_ID", "replacement"),
            ("__REALTIME_TIMESTAMP", "14000000"),
            ("__REALTIME_TIMESTAMP", "13000001"),
        ] {
            let mut bad = r.clone();
            bad[3][key] = json!(value);
            assert!(terminal_events(&bad, 13).is_err(), "{key}");
        }
        let mut bad = r.clone();
        bad[1]["__REALTIME_TIMESTAMP"] = json!("9000000");
        assert!(terminal_events(&bad, 13).is_err());
    }
    #[test]
    fn partial_span_root_mismatch_and_malformed_consensus_integers_fail() {
        let r = records();
        for (index, old, new) in [
            (0, ROOT_HASH, "11111111111111111111111111111111"),
            (1, "complete=true", "complete=false"),
            (
                1,
                "transactions=20629888884",
                "transactions=18446744073709551616",
            ),
            (1, "writes=0", "writes=0 writes=0"),
            (3, "slots=432000", "slots=431999"),
            (3, "epochs=1", "epochs=2"),
            (3, "bytes=100000000000", "bytes=0"),
        ] {
            let mut bad = r.clone();
            bad[index]["MESSAGE"] = json!(r[index]["MESSAGE"].as_str().unwrap().replace(old, new));
            assert!(terminal_events(&bad, 13).is_err(), "accepted {old}->{new}");
        }
    }
    #[test]
    #[ignore = "requires exact immutable epoch198 host deployment and active original producer"]
    fn actual_owner_and_immutable_inputs_preflight() {
        let current = super::super::fleet::unit(UNIT).unwrap();
        validate_owner(&current).unwrap();
        immutable_inputs().unwrap();
        assert_eq!(super::super::fleet::unit(UNIT).unwrap(), current);
    }
}
