//! One historical ownership alternative for cold130. The three original sweep
//! file locks stay held throughout both the body transaction and every census.
use crate::{CANONICAL_SHA, LENGTH, SHA, SOURCE, bound, raw, s, sha};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};
pub(super) const IMAGE: &str =
    "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/tools/retire";
pub(super) fn is_image(path: &Path) -> bool {
    path == Path::new(IMAGE)
        || path
            == Path::new(
                "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retire-v7/retire",
            )
        || path
            == Path::new(
                "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retire-v8/retire",
            )
        || path
            == Path::new(
                "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retire-v9/retire",
            )
        || path
            == Path::new(
                "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/retire-v10/retire",
            )
}
pub(super) fn holding_transition() -> Result<File> {
    acquire(
        Path::new(
            "/home/sol/.jetstreamer-private/r2-holding-state-dev-samjohnson-v1/transition.lock",
        ),
        64512,
        95818311,
    )
}
const RECEIPT: &str = "/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1/BOUND_NATIVE_PRIOR_BOOT_EVIDENCE.json";
const RECEIPT_SHA: &str = "a4f25ab7cc4e4905b38cfe7a92913ab4a9377a20fa96eab85dae121b59b4f5ef";
pub(super) const UNIT: &str =
    "jetstreamer-root-sweep-historical-130-v1417-v4-e130-130-lane-a-1.service";
const FINGERPRINT: &str = "sha256:39a742a31a701d425a4cd94451838000be273c1be8a35ddfbebf06a22c6c3883";
const ROOTS: [(&str, u64); 3] = [
    (
        "/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20260930-v4",
        3801199,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20261002-v5-r2",
        3801144,
    ),
    (
        "/var/lib/jetstreamer-root-sweep-epoch130-v1417-production-20261004-v6-r2",
        3802700,
    ),
];
pub(super) fn owners() -> Value {
    json!([{"role":"source-producer","unit":UNIT,"historical_pid":382916,"start_ticks":349911858,"prior_boot_evidence":{"path":RECEIPT,"sha256":RECEIPT_SHA}},
           {"role":"source-controller","state_dir":ROOTS[0].0,"controller_lock_inode":ROOTS[0].1,"prior_boot_evidence":{"path":RECEIPT,"sha256":RECEIPT_SHA}}])
}
pub(super) fn alternative(review: &Value) -> Result<bool> {
    match review.get("original_owner_method") {
        None => Ok(false),
        Some(method) => {
            ensure!(
                method == "cold130-prior-boot-v1" && review["closed_source_owners"] == owners(),
                "unknown or altered historical owner set"
            );
            Ok(true)
        }
    }
}
fn acquire(path: &Path, dev: u64, ino: u64) -> Result<File> {
    ensure!(path.canonicalize()? == path, "controller lock path alias");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.mode() & 0o777 == 0o600
            && m.nlink() == 1
            && (m.dev(), m.ino()) == (dev, ino),
        "controller lock identity changed"
    );
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "controller still owns {}",
        path.display()
    );
    let again = fs::symlink_metadata(path)?;
    ensure!(
        (again.dev(), again.ino()) == (dev, ino),
        "controller lock path changed"
    );
    Ok(file)
}
pub(super) struct Fence(Vec<File>);
impl Fence {
    pub(super) fn take() -> Result<Self> {
        let mut files = Vec::new();
        for (root, ino) in ROOTS {
            let dir = fs::symlink_metadata(root)?;
            ensure!(
                dir.is_dir() && dir.uid() == 0 && dir.mode() & 0o077 == 0,
                "controller state directory custody"
            );
            files.push(acquire(
                &Path::new(root).join("controller.lock"),
                2304,
                ino,
            )?);
        }
        Ok(Self(files))
    }
    pub(super) fn evidence(&self) -> Result<Value> {
        ensure!(self.0.len() == ROOTS.len(), "all sweep fences required");
        for ((root, ino), file) in ROOTS.iter().zip(&self.0) {
            let p = fs::symlink_metadata(Path::new(root).join("controller.lock"))?;
            ensure!(
                (p.dev(), p.ino()) == (2304, *ino) && file.metadata()?.ino() == *ino,
                "sweep lock replaced"
            );
        }
        let packet = bound(&json!({"path":RECEIPT,"sha256":RECEIPT_SHA}))?;
        let mut docs = serde_json::Map::new();
        for (name, entry) in packet["original_controller_and_run_link"]
            .as_object()
            .context("pinned historical files")?
        {
            let path = Path::new(s(entry, "path")?);
            let m = fs::symlink_metadata(path)?;
            ensure!(
                json!(m.dev()) == entry["dev"]
                    && json!(m.ino()) == entry["ino"]
                    && json!(m.uid()) == entry["uid"],
                "historical document identity: {name}"
            );
            let b = raw(path, 2 << 20, false)?;
            ensure!(
                sha(&b) == s(entry, "sha256")?,
                "historical document content: {name}"
            );
            docs.insert(name.clone(), serde_json::from_slice(&b)?);
        }
        let middle = bound(
            &json!({"path":format!("{}/state.json",ROOTS[1].0),"sha256":"219e8061435c5202af6bd0e6537870501e95cdbc8e7a5b840e2560400f72baf3"}),
        )?;
        ensure!(
            middle["assignments"] == json!({})
                && middle["attempts"] == json!({})
                && middle["completed"] == json!({})
                && middle["import_owner"].is_null()
                && middle["manifest_fingerprint"] == FINGERPRINT,
            "intervening controller still has an assignment"
        );
        let kernel = fs::read_to_string("/proc/stat")?;
        let boot = kernel
            .lines()
            .find_map(|l| l.strip_prefix("btime "))
            .context("kernel boot time")?
            .parse::<u64>()?;
        let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        for namespace in ["pid", "user"] {
            ensure!(
                fs::read_link(format!("/proc/self/ns/{namespace}"))?
                    == fs::read_link(format!("/proc/1/ns/{namespace}"))?,
                "host PID/user namespace required"
            );
        }
        let docs = Value::Object(docs);
        let publication_time=packet["original_controller_and_run_link"]["canonical_controller_completion"]["mtime_ns"].as_u64().context("completion time")?;
        verify_lifetime(&docs, &packet, boot, publication_time)?;
        let current = crate::closure::native(UNIT)?;
        crate::closure::terminal(UNIT, &current)?;
        ensure!(
            current["InvocationID"] == "" && current["LoadState"] == "not-found",
            "historical unit now has a definition or invocation"
        );
        Ok(
            json!({"historical_receipt":{"path":RECEIPT,"sha256":RECEIPT_SHA},"producer":current,
            "current_boot_id":boot_id.trim(),"current_boot_unix":boot,"sweep_state_directories_and_lock_inodes":ROOTS,
            "original_controller_invocation_id":null,"original_journal_recovered":false,"body_retirement_authorized":false}),
        )
    }
}
fn verify_lifetime(d: &Value, packet: &Value, btime: u64, completion_ns: u64) -> Result<()> {
    let assigned = &d["producer_controller_state"]["assignments"]["lane-a"];
    let complete = &d["canonical_controller_completion"];
    let earliest = 1_790_762_712_552_279_895u64;
    ensure!(
        assigned == &packet["original_assignment"]
            && assigned["unit"] == UNIT
            && assigned["pid"] == 382916
            && assigned["pid_start_time"] == 349911858
            && assigned["attempt"] == 1
            && assigned["first_epoch"] == 130
            && assigned["last_epoch"] == 130
            && assigned["phase"] == "failed"
            && assigned["unit_result"] == "exit-code"
            && assigned["unit_status"] == 1
            && assigned["failure"] == "producer ended without one live v2 receipt"
            && d["producer_controller_state"]["import_owner"].is_null()
            && d["producer_controller_state"]["completed"] == json!({}),
        "original assignment or terminal result differs"
    );
    let run = Path::new(s(packet, "run_directory")?);
    ensure!(
        Path::new(SOURCE).parent().and_then(Path::parent) == Some(run)
            && run.file_name().and_then(|n| n.to_str())
                == Some(format!("run-382916-{earliest}").as_str()),
        "run path differs from the original terminal assignment"
    );
    let failed_ns =
        packet["original_controller_and_run_link"]["producer_controller_state"]["mtime_ns"]
            .as_u64()
            .context("terminal state mtime")?;
    ensure!(
        packet["run_tag_unix_ns"] == earliest
            && earliest < failed_ns
            && failed_ns < completion_ns
            && completion_ns / 1_000_000_000 < btime,
        "boot must follow the failed original and completed replacement"
    );
    ensure!(
        packet["source_path"] == SOURCE
            && packet["source_sha256_on_historical_read"] == SHA
            && d["hash_only_identity"]["identity"] == packet["source_identity"]
            && d["hash_only_identity"]["sha256"] == SHA
            && d["hash_only_identity"]["length"] == LENGTH
            && d["hash_only_identity"]["source"] == SOURCE
            && d["native_run_state"]["schema"] == "jetstreamer-root-cohort-run-v1"
            && d["native_run_state"]["status"] == "running-private"
            && d["native_run_state"]["start_epoch"] == 130
            && d["native_run_state"]["end_epoch"] == 130
            && d["native_run_state"]["manifest_fingerprint"] == FINGERPRINT
            && d["deployed_preflight"]["manifest_fingerprint"] == FINGERPRINT
            && d["producer_controller_state"]["manifest_fingerprint"] == FINGERPRINT
            && complete["manifest_fingerprint"] == FINGERPRINT
            && complete["assignments"] == json!({})
            && complete["import_owner"].is_null(),
        "original body, run, deploy or controller scope differs"
    );
    for name in ["original_publication", "public_import_receipt"] {
        let r = &d[name];
        ensure!(
            r["manifest_fingerprint"] == FINGERPRINT
                && r["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
                && r["epochs"] == json!([130])
                && r["outcome"]["kind"] == "committed"
                && r["outcome"]["members"]
                    .as_array()
                    .is_some_and(|a| a.len() == 1)
                && r["outcome"]["members"][0]["archive_sha256"] == CANONICAL_SHA
                && r["outcome"]["members"][0]["epoch"] == 130,
            "canonical/import receipt differs"
        );
    }
    let row = &complete["completed"]["130"];
    let reference = &packet["original_controller_and_run_link"]["public_import_receipt"];
    ensure!(
        row["epochs"] == json!([130])
            && row["members"] == json!([{"epoch":130,"archive_sha256":CANONICAL_SHA}])
            && row["receipt"] == reference["path"]
            && row["receipt_sha256"] == reference["sha256"]
            && d["public_import_receipt"]["destination"]["inode"]
                == row["destination_identity"]["inode"]
            && d["public_import_receipt"]["destination"]["device"]
                == row["destination_identity"]["device"],
        "replacement import binding differs"
    );
    Ok(())
}

pub(super) fn remote_state(remote_binding: &Value, custody: &Value) -> Result<()> {
    let remote_read = crate::bound_with_limit(remote_binding, 64 << 10, true)?;
    let remote_rows = &remote_read["rows"];
    let parked = &remote_rows[s(&custody, "object_key")?];
    let manifest = &remote_rows[s(&custody, "manifest_key")?];
    let canonical = &remote_rows["epoch-130.jet"];
    ensure!(
        remote_read["bucket"] == custody["bucket"]
            && remote_read["mutations"] == false
            && parked["http_status"] == 200
            && parked["length"] == LENGTH
            && parked["etag"] == custody["object_etag"]
            && manifest["http_status"] == 200
            && manifest["body_sha256"] == custody["manifest_sha256"]
            && canonical["http_status"] == 200
            && canonical["length"] == 83_405_061_082u64
            && canonical["etag"] == "73d501e604900b1c9a079d9453459a52-1243"
            && remote_rows["epoch-130.jet.sha256"]["archive_sha256"] == CANONICAL_SHA,
        "independent holding or canonical conditional readback differs"
    );
    println!(
        "{}",
        json!({"stage":"authenticated-remote-metadata","observation":remote_binding,"utc":remote_read["utc"],"parked":parked,"canonical":canonical})
    );

    Ok(())
}
fn chronological_reader(audit: &Value) -> Result<Value> {
    let inventory = bound(&audit["inventory"])?;
    let remote = inventory["objects"]
        .as_array()
        .context("audit inventory")?
        .iter()
        .find(|r| r["epoch"] == 130)
        .context("audit does not cover epoch130")?;
    ensure!(
        remote["key"] == "epoch-130.jet"
            && remote["bytes"] == 83_405_061_082u64
            && remote["etag"] == "\"73d501e604900b1c9a079d9453459a52-1243\"",
        "audit's canonical source differs"
    );
    let audit_pid = audit["child"]["pid"]
        .as_u64()
        .context("bound audit child")?;
    let audit_cmd = fs::read(format!("/proc/{audit_pid}/cmdline"))?;
    let args: Vec<&[u8]> = audit_cmd.split(|b| *b == 0).collect();
    ensure!(
        args.get(2) == Some(&b"https://pub-e7795f13d2d04a5f829e49e8f3ef3011.r2.dev".as_slice())
            && args.contains(&b"--verify-only".as_slice()),
        "audit child uses another source"
    );
    let pair = args
        .windows(2)
        .find(|p| p[0] == b"--archive-inventory")
        .context("actual reader inventory argument")?;
    let audit_input = Path::new(std::str::from_utf8(pair[1])?);
    let observed = fs::metadata(s(&audit["inventory"], "path")?)?;
    let actual = fs::metadata(audit_input)?;
    ensure!(
        (actual.dev(), actual.ino()) == (observed.dev(), observed.ino()),
        "audit child inventory differs"
    );
    Ok(remote.clone())
}

fn ready_readers(fleet_binding: &Value, fleet: &Value, audit: &Value) -> Result<Value> {
    let output = std::process::Command::new("/usr/bin/python3")
        .env_clear()
        .args([
            "-IB",
            "-c",
            include_str!("../ready_audit_preflight.py"),
            s(fleet_binding, "path")?,
            s(fleet_binding, "sha256")?,
        ])
        .output()
        .context("verify current public ready readers")?;
    ensure!(
        output.status.success(),
        "current ready audit proof failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let proof: Value = serde_json::from_slice(&output.stdout)?;
    let expected = json!({"epoch":130,"key":"epoch-130.jet","bytes":83_405_061_082u64,
                          "etag":"\"73d501e604900b1c9a079d9453459a52-1243\""});
    ensure!(
        proof["schema"] == "cold130-ready-audit-reader-proof-v1"
            && proof["fleet"] == *fleet_binding
            && proof["audit"] == fleet["current_audit_child"]["observation"]
            && proof["scope"] == audit["inventory"]
            && proof["retirement"] == audit["chronological_retirement"]
            && proof["canonical_object"] == expected
            && proof["source_body_bytes_read"] == 0
            && proof["resource_credit_bytes"] == 0
            && proof["retirement_authorized"] == false,
        "ready reader proof belongs to another source or scope"
    );
    println!(
        "{}",
        json!({"stage":"current-ready-public-readers","proof":proof})
    );
    Ok(expected)
}

pub(super) fn fleet_readers(fleet_binding: &Value) -> Result<()> {
    let fleet = crate::closure::fleet(fleet_binding)?;
    let row = fleet["epochs"]
        .as_array()
        .context("complete epoch rows")?
        .iter()
        .find(|r| r["epoch"] == 130)
        .context("missing epoch130")?;
    ensure!(
        fleet["owner"] == "/root"
            && fleet["primary_thread"] == crate::PRIMARY
            && row["state"] == "remote-ready"
            && row["inventory_state"] == "ready-pair",
        "current epoch disposition"
    );
    let audit = bound(&fleet["current_audit_child"]["observation"])?;
    let remote = if audit.get("child").is_some_and(Value::is_null) {
        ready_readers(fleet_binding, &fleet, &audit)?
    } else {
        chronological_reader(&audit)?
    };
    let mut replay = Vec::new();
    for key in [
        "actual_executing_replays",
        "actual_active_private_diagnostics",
        "actual_active_bootstraps",
    ] {
        for row in fleet[key].as_array().context("native fleet class")? {
            let u = &row["unit"];
            let live = crate::closure::native(s(u, "Id")?)?;
            ensure!(
                live["ActiveState"] == "active"
                    && live["MainPID"] == u["MainPID"]
                    && live["InvocationID"] == u["InvocationID"],
                "changed replay owner {}",
                u["Id"]
            );
            ensure!(row["epoch"] != 130, "live epoch130");
            let pid = s(u, "MainPID")?.parse::<u32>()?;
            let bytes = fs::read(format!("/proc/{pid}/cmdline"))?;
            let argv: Vec<&[u8]> = bytes.split(|b| *b == 0).collect();
            let epoch = row["epoch"].as_u64().context("replay epoch")?.to_string();
            ensure!(
                argv.get(1) == Some(&epoch.as_bytes()) && argv.contains(&b"--verify".as_slice()),
                "replay argv names a different epoch"
            );
            let admission = bound(&row["admission"])?;
            ensure!(
                admission["producer_invocation_id"] == u["InvocationID"]
                    && admission["producer_unit"] == u["Id"],
                "admission belongs to another unit"
            );
            replay.push(json!({"epoch":row["epoch"],"unit":u["Id"],"iid":u["InvocationID"],"argv_sha256":sha(&bytes),"admission":row["admission"]}));
        }
    }
    println!(
        "{}",
        json!({"stage":"current-readers","fleet":fleet_binding,"row":row,"replay":replay,"audit_future_canonical_object":remote,"other_active_holding":fleet["actual_active_holding_transfers"],"staged_scope_complete":false})
    );
    Ok(())
}
pub(super) fn assess(fleet_binding: &Value, remote_binding: &Value) -> Result<()> {
    use crate::closure;
    let _fence = Fence::take()?;
    let lifetime = _fence.evidence()?;
    crate::current_readers::controller()?;
    let disjoint = crate::current_readers::canonical_classes()?;
    println!(
        "{}",
        json!({"stage":"live-local-canonical-watchers","classes":disjoint,"archive_root":"/home/sol/horizon","canonical_body_currently_present":Path::new("/home/sol/horizon/epoch-130.jet").exists()})
    );
    println!(
        "{}",
        json!({"stage":"historical-ownership","result":lifetime})
    );
    let packet = bound(&json!({"path":RECEIPT,"sha256":RECEIPT_SHA}))?;
    let eligibility = bound(&packet["original_controller_and_run_link"]["eligibility"])?;
    let held = json!({"path":"/var/lib/jetstreamer/cold130-holding-20261110-v1/receipts/custody-7b0b0c27f95af14975f3ba5c40db87bb81812467dd3311ac471b2577100935ad.json","sha256":"29b6bb4e4a8ba713d28fb072f9498cfd5f6eb824a994c8622969ac34a3e0a6b7"});
    let plan = json!({"custody":held,"park_spec":{"path":"/usr/local/lib/jetstreamer/horizon-cold130-holding-plan-20261110-v1/plan.json","sha256":"51521593b641d165c60fa3d0190d1b3ca0677110bdb0b2194230b338dedb0651"},
       "holding_transport_qualification":{"path":"/usr/local/lib/jetstreamer/horizon-node02-holding-qualification-20261023-v1/qualification.json","sha256":"15692445c39b47b011851b9db68798730077be2cb665dbb7e527049c5e9c5f70"},
       "holding_original_completion":{"path":"/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/cold130-candidate-20261110-v1/ROOT_COLD130_CUSTODY_COMPLETE_NO_RETIREMENT.json","sha256":"50423005a35d87c6a674120069752d5bbc0e9a7d5c3a9abc7e3ab8ae33bacf7e"},
       "canonical_R2_receipt":eligibility["canonical_R2_receipt"],"canonical_full":eligibility["canonical_current_full"],"canonical_plugin":eligibility["canonical_current_plugin"],
       "canonical_left_boundary":eligibility["canonical_left_boundary"],"canonical_right_boundary":eligibility["canonical_right_boundary"]});
    let custody = bound(&held)?;
    crate::custody(&custody)?;
    closure::holding_lineage(&plan, &custody)?;
    crate::canonical::validate(&plan)?;
    remote_state(remote_binding, &custody)?;
    let m = fs::symlink_metadata(SOURCE)?;
    let nanos = |secs: i64, ns: i64| secs as i128 * 1_000_000_000 + ns as i128;
    let local = json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        nanos(m.mtime(), m.mtime_nsec()) as i64,
        nanos(m.ctime(), m.ctime_nsec()) as i64
    ]);
    ensure!(
        local == packet["source_identity"]
            && m.blocks() * 512
                == packet["original_body_allocated_bytes"]
                    .as_u64()
                    .context("historical physical size")?,
        "original body metadata changed"
    );
    println!(
        "{}",
        json!({"stage":"custody-canonical-identity","canonical_sha256":CANONICAL_SHA,"holding":held,"source_identity":local,"allocated_bytes":m.blocks()*512,"hash_from_historical_read":SHA,"source_bytes_hashed_this_run":0})
    );
    fleet_readers(fleet_binding)?;
    let old185 = bound(
        &json!({"path":"/var/lib/jetstreamer/horizon-old185-scratch-runtime-20261024-v1/control-execute-0946-v2/execute-plan.json","sha256":"06416146cc34819c5dafcebd20305472c3627a48ba9933f4b311607d3302ba66"}),
    )?;
    let old185_unit = "jetstreamer-holding-scratch185-execute-0946-20261024-v2.service";
    let dormant = crate::closure::native(old185_unit)?;
    crate::closure::terminal(old185_unit, &dormant)?;
    ensure!(
        old185["retained_work"]["epoch"] == 185
            && s(&old185["retained_work"], "run_directory")?
                .starts_with("/home/sol/.jetstreamer-private/epoch185-singleton-"),
        "broader read-only mount has an unrelated or changed actual operation"
    );
    println!(
        "{}",
        json!({"stage":"prior-scratch-sandbox","unit":dormant,"retained_work":old185["retained_work"]["scratch"]})
    );
    let target = Path::new(SOURCE);
    let targets = vec![
        target.to_owned(),
        target.parent().context("body directory")?.to_owned(),
    ];
    let staged = closure::staged_census(&targets)?;
    println!(
        "{}",
        json!({"stage":"scheduler-inputs","inspected_files":staged})
    );
    let live =
        crate::process_references::scan(Path::new("/proc"), target, Path::new(closure::LANE), &[])?;
    ensure!(
        live.references.is_empty(),
        "live source references: {:?}",
        live.references
    );
    _fence.evidence()?;
    println!(
        "{}",
        json!({"stage":"read-only-assessment","live_direct_reference_scan":live,
        "requires_independent_indirect_reader_review_and_controller_handoff":true,"full_pre_removal_hash_observed":false,
        "retirement_check_receipt":false,"local_removal_performed":false,"remote_mutations":false,"resource_credit_bytes":0})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_deployed_v9_path_selects_the_new_prior_boot_image() {
        let base =
            Path::new("/var/lib/jetstreamer/horizon_runtime_data/cold130-boot-lineage-20261121-v1");
        assert!(is_image(&base.join("retire-v9/retire")));
        assert!(is_image(&base.join("retire-v10/retire")));
        assert!(!is_image(&base.join("retire-v10/other")));
        for path in [
            base.join("retire-v9/copy"),
            base.join("retire-v90/retire"),
            base.join("qualification/retire"),
            Path::new("/tmp/retire-v9/retire").to_owned(),
        ] {
            assert!(!is_image(&path));
        }
    }

    #[test]
    fn historical_mode_rejects_substituted_owner_or_invocation() {
        let mut v = json!({"original_owner_method":"cold130-prior-boot-v1","closed_source_owners":owners()});
        assert!(alternative(&v).unwrap());
        v["closed_source_owners"][1]["invocation_id"] = json!("invented");
        assert!(alternative(&v).is_err());
        v["closed_source_owners"] = owners();
        v["closed_source_owners"][0]["start_ticks"] = json!(349911859);
        assert!(alternative(&v).is_err());
        assert!(!alternative(&json!({"closed_source_owners":[]})).unwrap());
    }
    #[test]
    fn no_ownership_inference_from_boot_or_completed_epoch_alone() {
        for packet in [
            json!({}),
            json!({"run_tag_unix_ns":1790762712552279895u64,"original_assignment":{"phase":"failed","pid":382916}}),
        ] {
            assert!(
                verify_lifetime(
                    &json!({"canonical_controller_completion":{"completed":{"130":{}}}}),
                    &packet,
                    1791653338,
                    1791474066717471071
                )
                .is_err()
            );
        }
    }
    #[test]
    fn prior_boot_requires_original_pid_clock_run_and_distinct_committed_import() {
        let terminal = json!({"unit":UNIT,"pid":382916,"pid_start_time":349911858,"attempt":1,"first_epoch":130,"last_epoch":130,"phase":"failed","unit_result":"exit-code","unit_status":1,"failure":"producer ended without one live v2 receipt"});
        let id = json!([
            64512,
            100794422,
            1001,
            1003,
            33152,
            1,
            LENGTH,
            1790973017227277588i64,
            1790973017227277588i64
        ]);
        let run = Path::new(SOURCE).parent().unwrap().parent().unwrap();
        let packet = json!({"original_assignment":terminal,"run_directory":run,
            "run_tag_unix_ns":1790762712552279895u64,"source_path":SOURCE,"source_sha256_on_historical_read":SHA,"source_identity":id,
            "original_controller_and_run_link":{"producer_controller_state":{"mtime_ns":1790973044591429867u64},"public_import_receipt":{"path":"/import.json","sha256":"abc"}}});
        let receipt = json!({"manifest_fingerprint":FINGERPRINT,"schema":"jetstreamer-root-cohort-publication-receipt-v2","epochs":[130],"outcome":{"kind":"committed","members":[{"archive_sha256":CANONICAL_SHA,"epoch":130}]},"destination":{"inode":11,"device":22}});
        let docs = json!({"producer_controller_state":{"assignments":{"lane-a":terminal},"completed":{},"import_owner":null,"manifest_fingerprint":FINGERPRINT},
            "hash_only_identity":{"identity":id,"sha256":SHA,"source":SOURCE,"length":LENGTH},
            "native_run_state":{"schema":"jetstreamer-root-cohort-run-v1","status":"running-private","start_epoch":130,"end_epoch":130,"manifest_fingerprint":FINGERPRINT},
            "deployed_preflight":{"manifest_fingerprint":FINGERPRINT},"original_publication":receipt,"public_import_receipt":receipt,
            "canonical_controller_completion":{"manifest_fingerprint":FINGERPRINT,"assignments":{},"import_owner":null,"completed":{"130":{"epochs":[130],"members":[{"epoch":130,"archive_sha256":CANONICAL_SHA}],
              "receipt":"/import.json","receipt_sha256":"abc","destination_identity":{"inode":11,"device":22}}}}});
        let end = 1791474066717471071;
        verify_lifetime(&docs, &packet, 1791653338, end).unwrap();
        assert!(verify_lifetime(&docs, &packet, 1791474066, end).is_err());
        for (path, v) in [
            (
                "/producer_controller_state/assignments/lane-a/pid_start_time",
                json!(1),
            ),
            (
                "/canonical_controller_completion/completed/130/members/0/archive_sha256",
                json!(SHA),
            ),
            (
                "/canonical_controller_completion/assignments",
                json!({"lane-b":{}}),
            ),
            ("/public_import_receipt/destination/inode", json!(12)),
            ("/native_run_state/manifest_fingerprint", json!("foreign")),
        ] {
            let mut altered = docs.clone();
            *altered.pointer_mut(path).unwrap() = v;
            assert!(
                verify_lifetime(&altered, &packet, 1791653338, end).is_err(),
                "{path}"
            );
        }
        let mut wrong = packet.clone();
        wrong["run_directory"] = json!("/a/run-382916-1790762712552279895");
        assert!(verify_lifetime(&docs, &wrong, 1791653338, end).is_err());
    }
    #[test]
    fn exclusive_lock_rejects_busy_or_substituted_inode() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("controller.lock");
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let m = f.metadata().unwrap();
        if m.uid() == 0 {
            let held = acquire(&path, m.dev(), m.ino()).unwrap();
            assert!(acquire(&path, m.dev(), m.ino()).is_err());
            drop(held);
            assert!(acquire(&path, m.dev(), m.ino() + 1).is_err());
            assert!(acquire(&path, m.dev(), m.ino()).is_ok());
        }
    }
}
