//! Retire only the independently staged, fully hash-bound retry10 archive prefix.
use super::*;
use std::{
    collections::BTreeMap,
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
};
macro_rules! directory_root {
    () => {
        "/var/lib/jetstreamer/horizon_runtime_data/epoch166-retry10-holding-20261122-v1"
    };
}
macro_rules! independent {
    () => {
        "/home/sol/.jetstreamer-private/epoch166-independent-cold-20261120-v1"
    };
}
macro_rules! selected_destination {
    () => { concat!(independent!(), "/replacement-local3retry10-20261121-v1/private/destination-7a798c2c541f09bf18d3c3b33df9faa66e8609f5d416fb227745547144979d81") };
}
macro_rules! sibling_destination {
    () => { concat!(independent!(), "/replacement-local3retry9-20261110-v1/private/destination-a016b4284060be2297b683ac3b88b986ff008872d936fd6e13eb4a9564ac54ae") };
}
macro_rules! selected_run {
    () => {
        concat!(
            selected_destination!(),
            "/work/root-cohort-166-166/run-3866816-1795260845522831443"
        )
    };
}
const DESTINATION: &str = selected_destination!();
const RUN: &str = selected_run!();
const SOURCE: &str = concat!(selected_run!(), "/archives/epoch-166.jet");
const SHA: &str = "dfddb43b910008e87d319638dcd6dce950b8d5fc298ff412e3a3ac82afad6128";
const LENGTH: u64 = 64_922_604_512;
const ALLOCATED: u64 = 64_922_697_728;
const INODE: u64 = 93_782_070;
const INSPECTION: &str = concat!(directory_root!(), "/PREPARED.json");
const INSPECTION_SHA: &str = "dd02c73abfee1065873cf370e9a72d566717bd1b4efab4ae206032ce4424778e";
const ELIGIBILITY: &str = concat!(directory_root!(), "/package/eligibility.json");
const ELIGIBILITY_SHA: &str = "8a562db940f376847374d006e1d9fe5b2f5c4b802b4c318953636d45388788bd";
const PARK_PLAN: &str = concat!(directory_root!(), "/package/plan.json");
const PARK_PLAN_SHA: &str = "cee159c094d1d77778a24d7b563a6a6bdd295786652ff73745258bb086f33b04";
const MAPPING: &str = "/usr/local/lib/jetstreamer/horizon-node02-holding-20261023-v1/mapping.json";
const MAPPING_SHA: &str = "61f7601f78a7aa1f71394a020cbbb28aa9dbd85de858f139def1c989f2b2a89e";
const PARK: &str = "horizon-closed166-retry10-park-20261122-v1.service";
const PRODUCER: &str = "horizon-qualify-166-independent-recovery-20261121-v1.service";
const GUARD: &str = "horizon-guard-166-independent-recovery-20261121-v1";
const MUTATION_LOCK: &str = "/home/sol/.jetstreamer-private/r2-receipts/local-mutation.lock";
const EPOCH_LOCK: &str = concat!(selected_destination!(), "/locks/epoch-166.lock");
const SIBLING_LOCK: Option<(&str, u64)> = Some((
    concat!(sibling_destination!(), "/locks/epoch-166.lock"),
    93_717_107,
));
const QUARANTINE: &str = "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/retirements/epoch166-retry10-dfddb43b910008e87d319638dcd6dce950b8d5fc298ff412e3a3ac82afad6128.jet";
const STATE_SHA: &str = "ef63e2a2e443375f84b1c851c8d0ffc51454d3ef0f5bea03124f8ce3cd73e47a";
const LIFECYCLE: &str = concat!(directory_root!(), "/retirement-tools");
const EVIDENCE_ROOT: &str = concat!(directory_root!(), "/retirement-evidence");
const RUN_INODE: u64 = 93_782_047;
const SCRATCH_INODE: u64 = 93_782_050;
const STATE_INODE: u64 = 93_782_048;
const EPOCH_LOCK_INODE: u64 = 93_782_040;
const ATTEMPT: &str = "10";
const PARK_START: &str = concat!(directory_root!(), "/PARK_START.json");
const MTIME_SEC: i64 = 1_795_367_799;
const MTIME_NSEC: i64 = 466_466_537;
const RUNTIME_PACKAGE_ROOT: Option<&str> = Some("/var/lib/jetstreamer/horizon_runtime_data");
const BOOKING: &str = concat!(directory_root!(), "/HOLDING_PRICE_BASIS.json");
const BOOKING_SHA: &str = "d5071abe6d840e4cb0dd402ce75ee69e720543fb83005cc944dd939061aca7e5";
const ACTUAL_BOOKING: &str = concat!(directory_root!(), "/PARK_ADMISSION.json");
const RETRY10_IID: &str = "3c220efd0d0740f59572a96447e83762";
const ORIGINAL_SCANNER_IID: &str = "f3b74aa33a734cb38debea76fb883395";
const INDEXES_AND_PROTECTED: &str =
    include_str!("../../scripts/horizon_epoch167_ancestor_accounts_20261122_v1/profiles166.json");
macro_rules! profile {
    ($prefix:literal, $suffix:literal) => {
        concat!($prefix, "retry10", $suffix)
    };
}

fn validate_inspection(i: &Value, e: &Value) -> Result<()> {
    let s = &i["closed_sources"]["local3retry10"];
    let identity = &s["source"];
    ensure!(
        i["selected"] == "local3retry10"
            && i["verified_digest"] == SHA
            && i["signed_bytes"] == LENGTH
            && i["checksum_count"] == 1_893
            && i["native_digest_iid"] == ORIGINAL_SCANNER_IID
            && i["native_digest_unit"] == "horizon-stopped-bucket-inspection-20261122-v1.service"
            && i["whole_file_receipt"] == e["full_source_digest"]
            && i["whole_file_receipt"]["sha256"]
                == "46b9414dbcac6994a7f99e8fb2ff268adfaeb138e0f5fcd5791533da244df380"
            && s["owner_iid"] == RETRY10_IID
            && s["allocated"] == ALLOCATED
            && identity["path"] == SOURCE
            && identity["device"] == 64512
            && identity["inode"] == INODE
            && identity["size"] == LENGTH
            && identity["ctime_ns"] == 1_795_367_799_466_466_537_i64
            && identity["mtime_ns"] == identity["ctime_ns"]
            && i["park_spec"] == serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?
            && !e["runtime_checkpoint_qualified"].as_bool().unwrap_or(true)
            && e["closed_owner"] == s["original_stop"]
            && e["drained_guard"] == s["guard_drained"]
            && e["bootstrap_recovery"] == i["original_bootstrap"]
            && e["input_index_proof"] == i["exact_input_proof"],
        "retry10 requires the receipt covering every stored byte of its closed prefix"
    );
    Ok(())
}
const ACTUAL_BOOKING_SHA: &str = "e9fd206ceb587186f439c8afa4b6e6d2eb4f3b64a024a09f7a286b9c4fef2d08";
const ACTUAL_START_SHA: &str = "8439ad40268f89f9bcc94b511d21c6c7daf39139f284477bdd1a67099271dff9";
const FIT_SHA: &str = "a1dd96d765c64876b211c1f8d729c39b9d1bc4c83fbf7e8c70bc0c54d550ec7e";
const PARK_IID: &str = "57146d4b5c9940449cd129433a5acd2b";

fn validate_paid_rows(
    proof: &Value,
    iid: &str,
    start: &Value,
    basis: &Value,
    admission: &Value,
    fit: &Value,
) -> Result<()> {
    let plan = serde_json::to_value(binding(PARK_PLAN, PARK_PLAN_SHA))?;
    let raw = serde_json::to_value(binding(INSPECTION, INSPECTION_SHA))?;
    let h = &basis["qualified_image"];
    let native = &start["native"];
    let cmd = json!([
        h["path"],
        "holding-park",
        PARK_PLAN,
        "--spec-sha256",
        PARK_PLAN_SHA,
        "--self-sha256",
        h["sha256"]
    ]);
    let argv = cmd
        .as_array()
        .context("park arguments")?
        .iter()
        .map(|v| v.as_str().context("park argument"))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let terminal = &proof["native"];
    let exec = terminal["ExecStart"]
        .as_str()
        .context("terminal manager command")?;
    ensure!(
        iid == PARK_IID
            && proof["schema"] == profile!("horizon-closed166-", "-park-terminal-v1")
            && proof["unit"] == PARK
            && proof["helper"] == *h
            && proof["park_plan"] == plan
            && proof["start"] == serde_json::to_value(binding(PARK_START, ACTUAL_START_SHA))?
            && start["admission"]
                == serde_json::to_value(binding(ACTUAL_BOOKING, ACTUAL_BOOKING_SHA))?
            && start["start_ticks"] == "372809203"
            && native["MainPID"] == "685781"
            && native["Id"] == PARK
            && native["InvocationID"] == iid
            && native["SubState"] == "start"
            && native["ActiveState"] == "activating"
            && native["NRestarts"] == "0"
            && native["ControlGroup"] == format!("/system.slice/{PARK}")
            && native["MemorySwapMax"] == "0"
            && native["CPUQuotaPerSecUSec"] == "2s"
            && native["MemoryMax"] == "2147483648"
            && native["TasksMax"] == "256"
            && terminal["ExecMainPID"] == native["MainPID"]
            && terminal["ExecMainStartTimestamp"] == "Sun 2026-11-22 21:03:50 UTC"
            && exec.contains(&format!("argv[]={argv} ;"))
            && exec.matches("argv[]=").count() == 1,
        "park start and terminal must bind the actual invocation and sealed command"
    );
    ensure!(
        admission["owner"] == "primary"
            && admission["unit"] == PARK
            && admission["inputs"] == raw
            && basis["source_and_custody_plan"] == raw
            && basis["park_argv"] == cmd
            && basis["plans"][ATTEMPT]["plan"] == plan
            && admission["plan"] == plan
            && admission["fit"]
                == serde_json::to_value(binding(
                    concat!(directory_root!(), "/PARK_FIT.json"),
                    FIT_SHA
                ))?
            && admission["cpu"] == 2_000_000
            && admission["memory"] == 2_147_483_648_u64
            && admission["tasks"] == 256
            && admission["archive_staging_bytes"] == 0
            && admission["resource_credit_bytes"] == 0
            && admission["restore_overlap_bytes"] == LENGTH
            && fit["fits"] == true
            && fit["fleet"] == admission["fleet"]
            && fit["resource_credit_bytes"] == 0,
        "actual holding admission and complete fleet fit differ"
    );
    Ok(())
}
fn validate_profile_rows(proof: &Value, iid: &str, start: &Value, basis: &Value) -> Result<()> {
    let admission =
        evidence_with_limit(&binding(ACTUAL_BOOKING, ACTUAL_BOOKING_SHA), false, 1 << 20)?;
    let fit = evidence_with_limit(
        &binding(concat!(directory_root!(), "/PARK_FIT.json"), FIT_SHA),
        false,
        2 << 20,
    )?;
    validate_paid_rows(proof, iid, start, basis, &admission, &fit)
}
pub(super) fn check_transition_lock(file: &File) -> Result<()> {
    let md = file.metadata()?;
    ensure!(
        md.dev() == 64512
            && md.ino() == 95_818_311
            && identity(&md) == regular_identity(&Path::new(STATE).join("transition.lock"))?,
        "unexpected holding transition lock descriptor"
    );
    Ok(())
}
fn checked_protected(row: &Value) -> Result<Value> {
    let p = Path::new(row["path"].as_str().context("retained path")?);
    directory(p.parent().context("retained parent")?)?;
    let md = fs::symlink_metadata(p)?;
    ensure!(
        md.is_file()
            && md.nlink() == 1
            && row["device"] == md.dev()
            && row["inode"] == md.ino()
            && row["size"] == md.len()
            && row["mode"] == md.mode()
            && row["uid"] == md.uid()
            && row["gid"] == md.gid()
            && row["mtime_ns"] == md.mtime() * 1_000_000_000 + md.mtime_nsec()
            && row["ctime_ns"] == md.ctime() * 1_000_000_000 + md.ctime_nsec(),
        "retained input changed: {}",
        p.display()
    );
    Ok(json!({"path":p, "identity":identity(&md), "allocated":md.blocks()*512}))
}
fn retain_profile_inputs(retained: &mut Value) -> Result<()> {
    let profiles: Value = serde_json::from_str(INDEXES_AND_PROTECTED)?;
    let mut marks = Vec::new();
    for attempt in ["local3retry9", "local3retry10"] {
        let row = &profiles["profiles"][attempt];
        let stopped: Bound = serde_json::from_value(row["stop"].clone())?;
        let term = evidence_with_limit(&stopped, false, 1 << 20)?;
        ensure!(
            term["producer_invocation_id"] == row["iid"]
                && term["terminal"]["active"] == "inactive"
                && term["terminal"]["pid"] == 0,
            "original producer closure differs"
        );
        for k in ["unit", "guard", "timer"] {
            let unit = row[k].as_str().context("original producer/guard unit")?;
            closed(&native(unit)?, unit)?;
        }
        for file in row["preserved"]
            .as_array()
            .context("fixed retained siblings")?
        {
            if file["path"] != SOURCE {
                marks.push(checked_protected(file)?);
            }
        }
        marks.push(checked_protected(&row["bound_worker"])?);
    }
    for file in profiles["indexes"]
        .as_array()
        .context("bootstrap indexes")?
    {
        marks.push(checked_protected(file)?);
    }
    let lock = Path::new(STATE).join("transition.lock");
    directory(lock.parent().context("holding lock parent")?)?;
    let metadata = fs::symlink_metadata(&lock)?;
    ensure!(
        metadata.is_file()
            && metadata.dev() == 64512
            && metadata.ino() == 95_818_311
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "holding transition lock was replaced"
    );
    retained["holding_lock_identity"] = json!(identity(&metadata));
    retained["preserved_cold_bootstrap_and_sibling"] = json!(marks);
    Ok(())
}
include!("holding_epoch166_partial_terminal.rs");
include!("holding_epoch166_partial_retire.rs");

#[cfg(test)]
mod independent_tests {
    use super::*;
    #[test]
    #[ignore = "requires the original primary admission and manager receipt"]
    fn genuine_prepaid_park_rejects_crossed_fit_start_and_command() {
        let basis = evidence_with_limit(&binding(BOOKING, BOOKING_SHA), false, 1 << 20).unwrap();
        let admission =
            evidence_with_limit(&binding(ACTUAL_BOOKING, ACTUAL_BOOKING_SHA), false, 1 << 20)
                .unwrap();
        let fit = evidence_with_limit(
            &binding(concat!(directory_root!(), "/PARK_FIT.json"), FIT_SHA),
            false,
            2 << 20,
        )
        .unwrap();
        let start =
            evidence_with_limit(&binding(PARK_START, ACTUAL_START_SHA), false, 1 << 20).unwrap();
        // The live invocation's PID, timestamp and command persist through its successful terminal state.
        let proof = json!({"schema":"horizon-closed166-retry10-park-terminal-v1","unit":PARK,
            "helper":basis["qualified_image"],"park_plan":admission["plan"],"start":binding(PARK_START,ACTUAL_START_SHA),
            "native":native(PARK).unwrap()});
        validate_paid_rows(&proof, PARK_IID, &start, &basis, &admission, &fit).unwrap();
        for (k, v) in [
            ("owner", json!("other")),
            ("unit", json!("other")),
            ("fleet", json!(null)),
            ("fit", json!(null)),
            ("tasks", json!(1)),
            ("resource_credit_bytes", json!(1)),
            ("inputs", json!(null)),
        ] {
            let mut bad = admission.clone();
            bad[k] = v;
            assert!(
                validate_paid_rows(&proof, PARK_IID, &start, &basis, &bad, &fit).is_err(),
                "{k}"
            );
        }
        for k in ["start_ticks", "native", "admission"] {
            let mut bad = start.clone();
            bad[k] = Value::Null;
            assert!(
                validate_paid_rows(&proof, PARK_IID, &bad, &basis, &admission, &fit).is_err(),
                "{k}"
            );
        }
        let mut wrong = proof;
        wrong["native"]["ExecStart"] = json!("other");
        assert!(validate_paid_rows(&wrong, PARK_IID, &start, &basis, &admission, &fit).is_err());
    }
    #[test]
    #[ignore = "reads native stopped-owner metadata on the original host"]
    fn original_prefix_and_untouched_retry9_bind_their_own_generations() {
        let source = bound(&binding(INSPECTION, INSPECTION_SHA)).unwrap();
        let eligibility = bound(&binding(ELIGIBILITY, ELIGIBILITY_SHA)).unwrap();
        validate_inspection(&source, &eligibility).unwrap();
        for (k, v) in [
            ("native_digest_iid", json!(RETRY10_IID)),
            ("checksum_count", json!(1892)),
            ("signed_bytes", json!(LENGTH - 1)),
            ("verified_digest", json!("b".repeat(64))),
            ("closed_sources", json!({})),
            ("exact_input_proof", json!(null)),
        ] {
            let mut bad = source.clone();
            bad[k] = v;
            assert!(validate_inspection(&bad, &eligibility).is_err(), "{k}");
        }
        let mut left = Value::Object(Default::default());
        retain_profile_inputs(&mut left).unwrap();
        let mut right = Value::Object(Default::default());
        retain_profile_inputs(&mut right).unwrap();
        assert_eq!(left, right);
        let rows = left["preserved_cold_bootstrap_and_sibling"]
            .as_array()
            .unwrap();
        assert!(
            rows.iter()
                .any(|r| r["identity"]["inode"] == 93_717_159
                    && r["allocated"] == 69_065_297_920_u64)
        );
        assert!(!rows.iter().any(|r| r["path"] == SOURCE));
        let mut sibling = source["closed_sources"]["local3retry9"]["source"].clone();
        checked_protected(&sibling).unwrap();
        sibling["inode"] = json!(INODE);
        assert!(checked_protected(&sibling).is_err());
    }
}
