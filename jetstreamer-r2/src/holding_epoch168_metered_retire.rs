//! Custody and local retirement of the stopped epoch 168 full-metered archive prefix.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};

macro_rules! holding_dir {
    () => {
        "/var/lib/jetstreamer/horizon_runtime_data/epoch168-full-metered-holding-20261122-v1"
    };
}
macro_rules! destination {
    () => { "/home/sol/.jetstreamer-private/epoch168-standard-lane-20261109-v1/full-metered-20261121-v1/private/destination-5bd040760baa4f45854ef3420d18f981d3e80d5acaf485ab90d59cd3b1620fe9" };
}
macro_rules! selected_run {
    () => {
        concat!(
            destination!(),
            "/work/root-cohort-168-168/run-3879578-1795261941214288823"
        )
    };
}
macro_rules! profile {
    (epoch $prefix:literal, $suffix:literal) => {
        concat!($prefix, "168-full-metered", $suffix)
    };
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "168-full-metered", $suffix)
    };
}
const DESTINATION: &str = destination!();
const RUN: &str = selected_run!();
const SOURCE: &str = concat!(selected_run!(), "/archives/epoch-168.jet");
const SHA: &str = "ff657fe081adca0f8f1152ac6ced4b9f4493aff64566ddb8aa1c294f1004a031";
const LENGTH: u64 = 51_889_766_680;
const ALLOCATED: u64 = 51_889_844_224;
const INODE: u64 = 109_314_444;
const RUN_INODE: u64 = 109_323_515;
const SCRATCH_INODE: u64 = 109_323_519;
const STATE_INODE: u64 = 109_323_517;
const STATE_SHA: &str = "99dd7c12d3e65698cd4aa7496f873b16fbb828ed7fd62fbaba46a2da027a5ef8";
const MTIME_SEC: i64 = 1_795_367_762;
const MTIME_NSEC: i64 = 776_267_487;
const EPOCH_LOCK_INODE: u64 = 109_323_419;
const EPOCH_LOCK: &str = concat!(destination!(), "/locks/epoch-168.lock");
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
// The original stopped admission names these two leases; the holding transition has its own lock.
const SIBLING_LOCK: Option<(&str, u64)> = None;
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch168-full-metered-ff657fe081adca0f8f1152ac6ced4b9f4493aff64566ddb8aa1c294f1004a031.jet";
const LIFECYCLE: &str = concat!(holding_dir!(), "/retirement-tools");
const EVIDENCE_ROOT: &str = concat!(holding_dir!(), "/retirement-evidence");
const RUNTIME_PACKAGE_ROOT: Option<&str> = Some("/var/lib/jetstreamer/horizon_runtime_data");
const INSPECTION: &str = concat!(holding_dir!(), "/PREPARED.json");
const INSPECTION_SHA: &str = "2fa44417d9b239b8e35820c1bed5b6e47d184517e9850cbc7992c7f8b5663c58";
const ELIGIBILITY: &str = concat!(holding_dir!(), "/package/eligibility.json");
const ELIGIBILITY_SHA: &str = "f506ff7d54b55493ccb5977a6078676171d756731eb9e730e8c317a8b000d15d";
const PARK_PLAN: &str = concat!(holding_dir!(), "/package/plan.json");
const PARK_PLAN_SHA: &str = "a8c1611f228a216d68b56f249e6b8c34c346b963f4675e6d7015ae22ae8c06c6";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
pub(super) const PARK: &str = "horizon-closed168-full-metered-park-20261122-v1.service";
const PARK_START: &str = concat!(holding_dir!(), "/PARK_START.json");
const ORIGINAL_START_SHA: &str = "fd018eb97b53be8f2dda0718efa8d938355b042d4287ed9ad5dd3c2c1d043f5e";
const PARK_IID: &str = "04a7eb03f34345d88ec47da9bda309b4";
const PARK_PID: &str = "1157909";
const PARK_TIME: &str = "Mon 2026-11-23 07:11:28 UTC";
const PARK_FRAGMENT: &str =
    "/run/systemd/transient/horizon-closed168-full-metered-park-20261122-v1.service";
const PARK_FRAGMENT_SHA: &str = "f715fdb711adb06296a91dcfe88790fa6e511bd890097d7ba168ae97ffb86a5a";
const ADMISSION: &str = concat!(holding_dir!(), "/PARK_ADMISSION.json");
const FIT: &str = concat!(holding_dir!(), "/PARK_FIT.json");
const PRODUCER: &str = "horizon-qualify-168-full-metered-20261121-v1.service";
const GUARD: &str = "horizon-guard-168-full-metered-20261121-v1";
const PRODUCER_IID: &str = "9cebb1d022124fb08588e93e055d5446";
const ORIGINAL_NODE: (&str, &str) = (
    "/usr/local/lib/jetstreamer/horizon-independent168-singleton-package-20261109-v1/jetstreamer-node",
    "a09b8e5aa9426beaf42e6b5f2a469a5a147436bab8b7bf79f268758b60aa2e65",
);
const WORKER_SHA: &str = "b0219574172b54b251b4f2feda6285ca3b6bee5f2830a0d46e69ee8ea2275541";
const ADDITIONAL_COMPILED: &[(&str, &str, &str)] = &[
    (
        "/var/lib/jetstreamer/horizon_runtime_data/epoch172-full-replay-20261120-v1/inputs-v1/jetstreamer-historical-worker-v1-5-6",
        WORKER_SHA,
        PRODUCER,
    ),
    (
        "/var/lib/jetstreamer/horizon_runtime_data/four-prefix-recovery-20261122-v1/package/bucket-check",
        "bc8d033231572f888c75df6d372c72de2bc23b0829374d721c9fb89077e0dddf",
        "horizon-stopped-bucket-inspection-20261122-v1.service",
    ),
];
const PROFILES: &str =
    include_str!("../../scripts/horizon_epoch167_ancestor_accounts_20261122_v1/profiles168.json");
const DIGEST_RECEIPT: &str =
    "/home/sol/.jetstreamer-private/four-prefix-recovery-20261122/receipts/epoch-168.json";
const DIGEST_SHA: &str = "c1a93d6a62271731f85e684867d97606bb699b6a9cb8655abeecb0934fdb9825";
const MANIFEST_SHA: &str = "9d723f18a4017cbcb66af1e03803fb7f1deafb343f413dd9369493fb363daf39";
const BOOKING: &str = INSPECTION;
const BOOKING_SHA: &str = INSPECTION_SHA;
const HOLDING_IMAGE_FIELD: &str = "holding_image";
const ATTEMPT: &str = "full-metered";

fn checked_receipt(row: &Value, path: &str, maximum: u64) -> Result<Value> {
    let b: Bound = serde_json::from_value(row.clone())?;
    ensure!(
        b.path == Path::new(path),
        "unexpected receipt path: {}",
        b.path.display()
    );
    evidence_with_limit(&b, true, maximum)
}

fn validate_inspection(i: &Value, e: &Value) -> Result<()> {
    let profiles: Value = serde_json::from_str(PROFILES)?;
    let source = &profiles["profiles"][ATTEMPT]["preserved"][0];
    let object = format!("node_02/objects/{SHA}.blob");
    ensure!(
        i["epoch"] == 168
            && i["source_path"] == SOURCE
            && source["path"] == SOURCE
            && i["source_identity"] == source["identity"]
            && i["source_sha256"] == SHA
            && i["expected_keys"]
                == json!([object, format!("node_02/manifests/{MANIFEST_SHA}.json")])
            && i["expected_manifest"]["object_key"] == object
            && i["expected_manifest"]["sha256"] == SHA
            && i["expected_manifest"]["length"] == LENGTH
            && i["expected_manifest"]["canonical_archive"] == false
            && i["plan"] == serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?
            && i["digest_receipt"] == serde_json::to_value(binding(DIGEST_RECEIPT, DIGEST_SHA))?
            && i["digest_receipt"] == e["full_source_digest"]
            && e["closed_owner"] == profiles["stop"]
            && e["digest_native_iid"] == "f3b74aa33a734cb38debea76fb883395"
            && e["runtime_checkpoint_qualified"] == false
            && e["local_retirement_authorized"] == false
            && e["source"] == SOURCE
            && e["sha256"] == SHA
            && e["length"] == LENGTH,
        "stopped prefix inspection, original digest or private custody differs"
    );
    let raw = read_stable_bounded(Path::new(DIGEST_RECEIPT), 1 << 20, "native archive scan")?;
    let digest = evidence_payload(&raw, DIGEST_SHA, 1 << 20, Path::new(DIGEST_RECEIPT))?;
    ensure!(
        digest["epoch"] == 168
            && digest["buckets"] == 1457
            && digest["source"] == SOURCE
            && digest["source_bytes"] == LENGTH
            && digest["source_sha256"] == SHA
            && digest["identity"]["inode"] == INODE
            && digest["first_slot"] == 72_576_000
            && digest["last_complete_bucket_slot"] == 72_762_495,
        "native whole-prefix scan differs"
    );
    Ok(())
}

fn positive_decimal(value: &Value) -> bool {
    value
        .as_str()
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > 0)
}

fn validate_paid_rows(
    proof: &Value,
    iid: &str,
    start: &Value,
    prepared: &Value,
    admission: &Value,
    fit: &Value,
) -> Result<()> {
    let image = &prepared[HOLDING_IMAGE_FIELD];
    let plan = serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?;
    let argv = json!([
        image["path"],
        "holding-park",
        PARK_PLAN,
        "--spec-sha256",
        PARK_PLAN_SHA,
        "--self-sha256",
        image["sha256"]
    ]);
    let native = &start["native"];
    let terminal = &proof["native"];
    let command = format!(
        "argv[]={0} holding-park {PARK_PLAN} --spec-sha256 {PARK_PLAN_SHA} --self-sha256 {1} ;",
        image["path"].as_str().context("holding helper")?,
        image["sha256"].as_str().context("holding hash")?
    );
    let exec = terminal["ExecStart"]
        .as_str()
        .context("native holding command")?;
    ensure!(
        proof["schema"] == profile!(epoch "horizon-closed", "-park-terminal-v1")
            && proof["unit"] == PARK
            && proof["helper"] == *image
            && proof["park_plan"] == plan
            && prepared["plan"] == plan
            && prepared["argv"] == argv
            && native["Id"] == PARK
            && native["InvocationID"] == iid
            && native["ActiveState"] == "activating"
            && native["SubState"] == "start"
            && native["ControlGroup"] == format!("/system.slice/{PARK}")
            && positive_decimal(&start["start_ticks"])
            && positive_decimal(&native["MainPID"])
            && terminal["ExecMainPID"] == native["MainPID"]
            && terminal["ExecMainStartTimestamp"]
                .as_str()
                .is_some_and(|t| !t.is_empty())
            && native["NRestarts"] == "0"
            && native["MemorySwapMax"] == "0"
            && native["CPUQuotaPerSecUSec"] == "2s"
            && native["MemoryMax"] == "2147483648"
            && native["TasksMax"] == "256"
            && exec.contains(&command)
            && exec.matches("argv[]=").count() == 1
            && start["resource_credit_bytes"] == 0,
        "actual copy start, sealed executable, limits or terminal identity differ"
    );
    ensure!(
        admission["owner"] == "primary"
            && admission["unit"] == PARK
            && admission["inputs"] == serde_json::to_value(binding(INSPECTION, INSPECTION_SHA))?
            && admission["plan"] == plan
            && admission["cpu"] == 2_000_000
            && admission["memory"] == 2_147_483_648u64
            && admission["tasks"] == 256
            && admission["archive_staging_bytes"] == 0
            && admission["resource_credit_bytes"] == 0
            && admission["restore_overlap_bytes"] == LENGTH
            && fit["fits"] == true
            && fit["fleet"] == admission["fleet"]
            && fit["resource_credit_bytes"] == 0
            && fit["schema"] == "horizon-incident-replay-fit-v1"
            && fit["replay_launch_authorized"] == false
            && ["166", "167", "168", "169", "170"].iter().all(|epoch| {
                fit["bookings"][*epoch]["cap_bytes"]
                    .as_u64()
                    .is_some_and(|n| n > 0)
            })
            && adequate_budget(fit, "available_HOME_bytes", "complete_required_HOME_bytes")
            && adequate_budget(
                fit,
                "available_memory_bytes",
                "required_available_memory_bytes"
            ),
        "original funded admission and its complete host price differ"
    );
    Ok(())
}

fn adequate_budget(fit: &Value, available: &str, required: &str) -> bool {
    fit[available]
        .as_u64()
        .zip(fit[required].as_u64())
        .is_some_and(|(have, need)| need > 0 && have >= need)
}
fn validate_profile_rows(proof: &Value, iid: &str, start: &Value, prepared: &Value) -> Result<()> {
    ensure!(
        proof["start"] == json!(binding(PARK_START, ORIGINAL_START_SHA))
            && checked_receipt(&proof["start"], PARK_START, 1 << 20)? == *start
            && iid == PARK_IID
            && start["native"]["MainPID"] == PARK_PID
            && start["native"]["ExecMainStartTimestamp"] == PARK_TIME,
        "native start changed"
    );
    let admission = checked_receipt(&start["admission"], ADMISSION, 1 << 20)?;
    let fit = checked_receipt(&admission["fit"], FIT, 2 << 20)?;
    validate_paid_rows(proof, iid, start, prepared, &admission, &fit)
}

// PID1 clears the per-command accounting tuple on reload. Its independent
// main-process exit information survives, as does the original transient fragment.
fn same_terminal_dispatch(terminal: &Value, row: &Value, image: &Path, argv: &str) -> Result<()> {
    let exit = terminal["ExecMainExitTimestamp"]
        .as_str()
        .context("missing 168 park exit time")?;
    let micros = |key: &str| -> Result<u64> {
        Ok(terminal[key]
            .as_str()
            .context("missing 168 monotonic time")?
            .parse()?)
    };
    let start_us = micros("ExecMainStartTimestampMonotonic")?;
    ensure!(
        start_us > 0
            && micros("ExecMainExitTimestampMonotonic")? > start_us
            && !exit.is_empty()
            && exit != "n/a",
        "incomplete original 168 park accounting"
    );
    for state in [terminal, row] {
        park_shape(state, PARK_IID)?;
        ensure!(
            state["Id"] == PARK
                && state["Names"] == PARK
                && state["Transient"] == "yes"
                && state["NeedDaemonReload"] == "no"
                && state["LoadState"] == "loaded"
                && state["ActiveState"] == "active"
                && state["SubState"] == "exited"
                && state["ExecMainCode"] == "1"
                && state["ExecMainPID"] == PARK_PID
                && state["ExecMainStartTimestamp"] == PARK_TIME
                && state["FragmentPath"] == PARK_FRAGMENT
                && state["DropInPaths"] == ""
                && state["NRestarts"] == "0",
            "foreign 168 park generation or fragment"
        );
    }
    for key in [
        "ExecMainExitTimestamp",
        "ExecMainStartTimestampMonotonic",
        "ExecMainExitTimestampMonotonic",
    ] {
        ensure!(
            row[key] == terminal[key],
            "168 park main-process accounting changed: {key}"
        );
    }
    let command = format!(
        "{{ path={} ; argv[]={argv} ; ignore_errors=no ; ",
        image.display()
    );
    let recorded = format!(
        "{command}start_time=[{PARK_TIME}] ; stop_time=[{exit}] ; pid={PARK_PID} ; code=exited ; status=0 }}"
    );
    let reset = format!(
        "{command}start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
    );
    ensure!(
        terminal["ExecStart"] == recorded && row["ExecStart"] == reset,
        "168 park command differs from the original exit or exact systemd reload form"
    );
    Ok(())
}

pub(super) fn validate_reloaded_park(
    terminal: &Value,
    row: &Value,
    helper: &Bound,
    argv: &str,
) -> Result<()> {
    same_terminal_dispatch(terminal, row, &helper.path, argv)?;
    let fragment = Path::new(PARK_FRAGMENT);
    let md = fs::symlink_metadata(fragment)?;
    ensure!(
        fragment.canonicalize()? == fragment
            && md.is_file()
            && md.nlink() == 1
            && md.uid() == 0
            && md.gid() == 0
            && md.mode() & 0o022 == 0
            && hex_lower(&Sha256::digest(read_stable_bounded(
                fragment,
                1 << 20,
                "168 park fragment"
            )?)) == PARK_FRAGMENT_SHA,
        "168 original park fragment custody or contents changed"
    );
    Ok(())
}

fn checked_retained(row: &Value) -> Result<Value> {
    let path = Path::new(row["path"].as_str().context("retained path")?);
    directory(path.parent().context("retained parent")?)?;
    let md = fs::symlink_metadata(path)?;
    let actual = json!([
        md.dev(),
        md.ino(),
        md.len(),
        md.mtime() * 1_000_000_000 + md.mtime_nsec(),
        md.ctime() * 1_000_000_000 + md.ctime_nsec()
    ]);
    ensure!(
        md.is_file()
            && md.nlink() == 1
            && md.mode() & 0o022 == 0
            && row["identity"] == actual
            && (row["links"].is_null() || row["links"] == md.nlink()),
        "original protected file identity differs: {}",
        path.display()
    );
    Ok(
        json!({"path":path, "identity":actual, "mode":md.mode(),"uid":md.uid(),"gid":md.gid(),"allocated":md.blocks()*512}),
    )
}
fn retain_profile_inputs(retained: &mut Value) -> Result<()> {
    let profiles: Value = serde_json::from_str(PROFILES)?;
    let profile = &profiles["profiles"][ATTEMPT];
    let read = |key: &str| -> Result<Value> {
        evidence_with_limit(
            &serde_json::from_value(profiles[key].clone())?,
            false,
            1 << 20,
        )
    };
    let admission = read("admission")?;
    let stop = read("stop")?;
    let worker = read("worker")?;
    let payload = read("payload")?;
    let cleanup = evidence_with_limit(
        &serde_json::from_value(
            bound(&binding(INSPECTION, INSPECTION_SHA))?["source_cleanup"].clone(),
        )?,
        false,
        1 << 20,
    )?;
    ensure!(
        profile["iid"] == PRODUCER_IID
            && admission["producer_invocation_id"] == PRODUCER_IID
            && worker["producer_invocation_id"] == PRODUCER_IID
            && worker["producer_unit"] == PRODUCER
            && worker["worker_sha256"] == WORKER_SHA
            && stop["producer_invocation_id"] == PRODUCER_IID
            && stop["terminal"]["active"] == "inactive"
            && stop["terminal"]["sub"] == "dead"
            && stop["terminal"]["pid"] == 0
            && payload["producer_unit"] == PRODUCER
            && payload["members"]["jetstreamer-node"] == json!([ORIGINAL_NODE.0, ORIGINAL_NODE.1])
            && payload["members"]["jetstreamer-historical-worker-v1-5-6"][1] == WORKER_SHA
            && cleanup["original_iid"] == PRODUCER_IID
            && cleanup["scope_empty"] == true
            && cleanup["archive_or_snapshot_removed"] == false,
        "epoch 168 original producer, worker or earlier scratch retirement differs"
    );
    let mut marks = Vec::new();
    for row in profile["preserved"]
        .as_array()
        .context("fixed protected files")?
    {
        if row["path"] != SOURCE {
            marks.push(checked_retained(row)?);
        }
    }
    for row in payload["indexes"]
        .as_array()
        .context("original bootstrap indexes")?
    {
        for key in ["source", "independent_trace_copy"] {
            marks.push(checked_retained(&row[key])?);
        }
        let target = Path::new(row["target"].as_str().context("index target")?);
        directory(target.parent().context("index parent")?)?;
        marks.push(json!({"target":target,"identity":preserved_entry(target)?}));
    }
    retained["protected_inputs"] = json!(marks);
    let transition_path = Path::new(STATE).join("transition.lock");
    directory(transition_path.parent().context("transition parent")?)?;
    let lock = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&transition_path)?;
    check_primary_transition_lock(&lock)?;
    retained["holding_lock_identity"] = json!(identity(&lock.metadata()?));
    Ok(())
}
include!("holding_epoch166_partial_terminal.rs");
include!("holding_epoch166_partial_retire.rs");

#[cfg(test)]
mod metered_tests {
    use super::*;

    #[test]
    fn park_reload_requires_original_generation_and_unchanged_exit_accounting() {
        let image = Path::new("/fixture/jetstreamer-r2");
        let argv = "/fixture/jetstreamer-r2 holding-park /fixture/plan";
        let prefix = format!(
            "{{ path={} ; argv[]={argv} ; ignore_errors=no ; ",
            image.display()
        );
        let exit = "fixture park completion";
        let mut terminal = json!({"Id":PARK,"Names":PARK,"InvocationID":PARK_IID,
            "LoadState":"loaded","ActiveState":"active","SubState":"exited","MainPID":"0",
            "ControlPID":"0","Job":"","Restart":"no","Result":"success","ExecMainStatus":"0",
            "ExecMainCode":"1","ExecMainPID":PARK_PID,"ExecMainStartTimestamp":PARK_TIME,
            "ExecMainExitTimestamp":exit,"ExecMainStartTimestampMonotonic":"1000",
            "ExecMainExitTimestampMonotonic":"1001","NRestarts":"0","DropInPaths":"",
            "FragmentPath":PARK_FRAGMENT,"TriggeredBy":"","NeedDaemonReload":"no","Transient":"yes"});
        terminal["ExecStart"] = json!(format!(
            "{prefix}start_time=[{PARK_TIME}] ; stop_time=[{exit}] ; pid={PARK_PID} ; code=exited ; status=0 }}"
        ));
        let mut reset = terminal.clone();
        reset["ExecStart"] = json!(format!(
            "{prefix}start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}"
        ));
        same_terminal_dispatch(&terminal, &reset, image, argv).unwrap();
        for (key, value) in [
            ("Id", "other.service"),
            ("Names", "alias.service"),
            ("InvocationID", "new"),
            ("ExecMainPID", "1"),
            ("ExecMainStatus", "1"),
            ("ExecMainCode", "2"),
            ("ExecMainStartTimestamp", "new"),
            ("ExecMainExitTimestamp", "new"),
            ("ExecMainStartTimestampMonotonic", "900"),
            ("ExecMainExitTimestampMonotonic", "1002"),
            ("ActiveState", "active-with-job"),
            ("SubState", "running"),
            ("MainPID", "1"),
            ("ControlPID", "1"),
            ("Job", "2"),
            ("Restart", "always"),
            ("NRestarts", "1"),
            ("LoadState", "not-found"),
            ("NeedDaemonReload", "yes"),
            ("Transient", "no"),
            ("FragmentPath", "/other"),
            ("DropInPaths", "/other"),
            ("TriggeredBy", "timer"),
            ("ExecStart", "other command"),
        ] {
            let mut bad = reset.clone();
            bad[key] = json!(value);
            assert!(
                same_terminal_dispatch(&terminal, &bad, image, argv).is_err(),
                "{key}"
            );
        }
        assert!(same_terminal_dispatch(&reset, &reset, image, argv).is_err());
        assert!(same_terminal_dispatch(&terminal, &reset, image, "other argv").is_err());
        terminal["ExecMainExitTimestampMonotonic"] = json!("999");
        assert!(same_terminal_dispatch(&terminal, &reset, image, argv).is_err());
    }

    #[test]
    #[ignore = "read-only original 168 dispatch on dev-samjohnson"]
    fn recorded_active_copy_binds_this_park_start_and_fragment() {
        let s = bound(&binding(PARK_START, ORIGINAL_START_SHA)).unwrap();
        assert_eq!(s["native"]["InvocationID"], PARK_IID);
        assert_eq!(s["native"]["MainPID"], PARK_PID);
        assert_eq!(s["native"]["ExecMainStartTimestamp"], PARK_TIME);
        assert_eq!(s["start_ticks"], "376454927");
        let frag =
            read_stable_bounded(Path::new(PARK_FRAGMENT), 1 << 20, "original fragment").unwrap();
        assert_eq!(hex_lower(&Sha256::digest(&frag)), PARK_FRAGMENT_SHA);
    }

    #[test]
    fn funded_invocation_joins_price_pid_and_command() {
        let image = json!({"path":"/fixture/jetstreamer-r2","sha256":"a".repeat(64)});
        let iid = "b".repeat(32);
        let argv = json!([
            image["path"],
            "holding-park",
            PARK_PLAN,
            "--spec-sha256",
            PARK_PLAN_SHA,
            "--self-sha256",
            image["sha256"]
        ]);
        let cmd = argv
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>()
            .join(" ");
        let plan = json!(binding(PARK_PLAN, PARK_PLAN_SHA));
        let prepared = json!({"holding_image":image,"argv":argv,"plan":plan});
        let start = json!({"native":{"Id":PARK,"InvocationID":iid,"ActiveState":"activating","SubState":"start","ControlGroup":format!("/system.slice/{PARK}"),
            "NRestarts":"0","MemorySwapMax":"0","MemoryMax":"2147483648","CPUQuotaPerSecUSec":"2s","TasksMax":"256","MainPID":"1001"},
            "start_ticks":"1234567","resource_credit_bytes":0});
        let proof = json!({"schema":"horizon-closed168-full-metered-park-terminal-v1","unit":PARK,"helper":image,"park_plan":plan,
            "native":{"ExecMainPID":"1001","ExecMainStartTimestamp":"fixture timestamp","ExecStart":format!("{{ argv[]={cmd} ; }}")}});
        let fleet = json!({"path":"/fixture/fleet.json","sha256":"f".repeat(64)});
        let admission = json!({"owner":"primary","unit":PARK,"inputs":binding(INSPECTION,INSPECTION_SHA),"plan":plan,"cpu":2000000,
            "memory":2147483648u64,"tasks":256,"archive_staging_bytes":0,"resource_credit_bytes":0,"restore_overlap_bytes":LENGTH,"fleet":fleet});
        let mut fit = json!({"schema":"horizon-incident-replay-fit-v1","fits":true,"fleet":fleet,"resource_credit_bytes":0,
            "replay_launch_authorized":false,"available_HOME_bytes":9,"complete_required_HOME_bytes":9,"available_memory_bytes":7,"required_available_memory_bytes":7});
        for epoch in ["166", "167", "168", "169", "170"] {
            fit["bookings"][epoch] = json!({"cap_bytes":1});
        }
        validate_paid_rows(&proof, &iid, &start, &prepared, &admission, &fit).unwrap();
        for (key, value) in [
            ("owner", json!("other")),
            ("unit", json!("other")),
            ("fleet", json!(null)),
            ("tasks", json!(1)),
            ("restore_overlap_bytes", json!(LENGTH - 1)),
            ("archive_staging_bytes", json!(1)),
            ("resource_credit_bytes", json!(1)),
        ] {
            let mut bad = admission.clone();
            bad[key] = value;
            assert!(
                validate_paid_rows(&proof, &iid, &start, &prepared, &bad, &fit).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("fits", json!(false)),
            ("available_HOME_bytes", json!(8)),
            ("available_memory_bytes", json!(6)),
            ("bookings", json!({})),
            ("replay_launch_authorized", json!(true)),
        ] {
            let mut bad = fit.clone();
            bad[key] = value;
            assert!(
                validate_paid_rows(&proof, &iid, &start, &prepared, &admission, &bad).is_err(),
                "{key}"
            );
        }
        for (key, value) in [
            ("InvocationID", json!("wrong")),
            ("MainPID", json!("0")),
            ("TasksMax", json!("511")),
            ("SubState", json!("dead")),
        ] {
            let mut bad = start.clone();
            bad["native"][key] = value;
            assert!(
                validate_paid_rows(&proof, &iid, &bad, &prepared, &admission, &fit).is_err(),
                "{key}"
            );
        }
        let mut bad = proof.clone();
        bad["native"]["ExecStart"] = json!("unbound helper");
        assert!(validate_paid_rows(&bad, &iid, &start, &prepared, &admission, &fit).is_err());
        bad = proof;
        bad["native"]["ExecMainPID"] = json!("1002");
        assert!(validate_paid_rows(&bad, &iid, &start, &prepared, &admission, &fit).is_err());
    }

    #[test]
    #[ignore = "requires the native reviewed files and source allocation on the producer host"]
    fn stopped_source_and_fixed_protected_siblings() {
        let prepared = bound(&binding(INSPECTION, INSPECTION_SHA)).unwrap();
        let eligible = bound(&binding(ELIGIBILITY, ELIGIBILITY_SHA)).unwrap();
        validate_inspection(&prepared, &eligible).unwrap();
        assert_eq!(source_identity(Path::new(SOURCE)).unwrap().length, LENGTH);
        for key in [
            "epoch",
            "source_identity",
            "digest_receipt",
            "source_sha256",
            "expected_keys",
            "plan",
        ] {
            let mut bad = prepared.clone();
            bad[key] = Value::Null;
            assert!(validate_inspection(&bad, &eligible).is_err(), "{key}");
        }
        for key in [
            "closed_owner",
            "digest_native_iid",
            "runtime_checkpoint_qualified",
            "full_source_digest",
        ] {
            let mut bad = eligible.clone();
            bad[key] = Value::Null;
            assert!(validate_inspection(&prepared, &bad).is_err(), "{key}");
        }
        let retained = preserved().unwrap();
        assert_eq!(retained, preserved().unwrap());
        let marks = retained["protected_inputs"].as_array().unwrap();
        assert_eq!(marks.len(), 16);
        assert!(
            marks
                .iter()
                .any(|r| r["identity"][1] == 104804528 && r["identity"][2] == 42215375916u64)
        );
        assert!(
            !marks
                .iter()
                .any(|r| r["path"] == SOURCE || r["target"] == SOURCE)
        );
    }
}
