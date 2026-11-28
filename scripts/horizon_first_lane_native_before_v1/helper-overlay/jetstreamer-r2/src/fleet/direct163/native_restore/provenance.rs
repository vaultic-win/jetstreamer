//! Pinned original phase graph and actual downloader custody, not caller totals.
use super::*;
mod retained_exec;
const DOWNLOAD_IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-epoch163-snapshot-input-tools-20261106-v1/snapshot-download";
const DOWNLOAD_SHA: &str = "742e4f2d4c2ca43369671f2fbae9d0a45ac2caed797e6c0b226f391c0086a11d";
pub(super) const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
pub(super) const CURRENT_DOWNLOAD_UNIT: &str = "horizon-visible-bootstrap163-download-20261107-v1.service";
const CURRENT_DOWNLOAD_IID: &str = "7e01ca99b80f4f629ff315a19f10b4a1";
const CURRENT_DOWNLOAD_PLAN: &str = "/usr/local/lib/jetstreamer/horizon-visible-bootstrap163-download-plan-20261107-v1/plan.json";
const CURRENT_DOWNLOAD_RECEIPT: &str = "/var/lib/jetstreamer/horizon-visible-bootstrap163-20261107-v1/download.json";
const SNAPSHOT_SHA: &str = "fd1a2409e2ba63ef3256727f0c91b2c674132c6cd2d8fab1cb51fa81cbc6bfaf";
const LEGACY_DATA_FLOOR: u64 = 4720000000000;
const SIZE: u64 = 1901405026;
pub(super) fn takeover_binding() -> Bound {
    fixed("/home/sol/.jetstreamer-private/epoch163-first-output128-admission-source-20261106-v1/ROOT_USER_ORDERED_VISIBLE_THREAD_TAKEOVER_20261107.json",
        "9b895fd8e137c30ba7a6d94432639c2e7e114140bb2cde5700f32e08987ab61f")
}
fn takeover_scope(v: &Value) -> Result<()> {
    ensure!(v["schema"] == "horizon-user-ordered-visible-thread-takeover-v1"
        && v["current_sole_primary_thread"] == PRIMARY
        && v["former_primary_thread"] == "01a1af2b-bc56-7311-a916-55aa5e102974"
        && v["supersedes_prior_owner_ACK_for_future_control"] == true
        && v["former_thread_archive_tool_returned_archived_true"] == true
        && v["preserve_launched_jobs_guards_evidence_and_single_observer"] == true,
        "native sole visible controller explicit takeover evidence");
    Ok(())
}
fn current_phase_scope(v: &Value) -> Result<()> {
    ensure!(v["schema"] == "horizon-native163-current-fixed128-phase-v1"
        && v["exclusive_operational_owner"] == PRIMARY
        && v["visible_thread_takeover"] == json!(takeover_binding())
        && v["normal_external_pool_bytes"] == NORMAL_POOL
        && v["extra_full_reader_QA_memory_bytes"] == 0
        && v["additional_QA_memory_bytes_retained_until_authoritative_closure"] == 0
        && n(v,"protected_existing_DATA_bytes")? >= DATA_FLOOR
        && n(v,"complete_conservative_raw_DATA_booking_bytes")? >= DATA_FLOOR
        && n(v,"protected_existing_DATA_bytes")? >= n(v,"complete_conservative_raw_DATA_booking_bytes")?
        && n(v,"minimum_available_memory_bytes")? >= MEM_FLOOR
        && n(v,"minimum_existing_memory_bytes")? >= (80u64 << 30) + (256u64 << 20)
        && v["all_original_memory_DATA_and_raw_producer_promises_retained"] == true
        && v["no_release_or_idle_credit"] == true
        && v["retained145"] == json!({"exporter_memory_bytes":80u64<<30,
            "guard_memory_bytes":256u64<<20,"exporter_DATA_bytes":(160u64<<30)+(128u64<<20),"source_DATA_bytes":4u64<<30,
            "exporter_cpu_quota_micros":8000000,"guard_cpu_quota_micros":1000000,
            "failed_exporter_does_not_release_promises":true,"memory_in_existing_total":true}),
        "native current whole phase retains failed145 and all later DATA/memory charges");
    Ok(())
}
const URI: &str = "gs://mainnet-beta-ledger-us-ny5/70415741/snapshot-70415741-2aSbRXHXZJgT4bdrY34gWizngFB527wavw6Ar9KadzUY.tar.zst#1634787272998262";
fn phase_chain(b: &Bound, visited: &mut BTreeSet<PathBuf>, depth: usize) -> Result<()> {
    ensure!(
        depth <= 128 && visited.insert(b.path.clone()),
        "native original phase history cycle/depth"
    );
    ensure!(!b.path.extension().is_some_and(|x| ["jet", "zst", "bz2", "tar"].iter().any(|v| x == *v)),
        "phase provenance must never open archive/input bodies");
    let v = protected(b)?;
    // Preserve every original phase byte and the original closure/booking files.
    // A bound reference is verified as original bytes, never rewritten/normalized.
    for (k, value) in v.as_object().context("native phase object")? {
        if k == "previous_phase_ledger" {
            phase_chain(&to_bound(value)?, visited, depth + 1)?;
        } else if value.get("path").is_some() && value.get("sha256").is_some() {
            let reference = to_bound(value)?;
            ensure!(!reference.path.extension().is_some_and(|x| ["jet", "zst", "bz2", "tar"].iter().any(|v| x == *v)),
                "phase provenance reference cannot open archive/input bodies");
            storage::bytes(&reference, 32 << 20, false)?;
        }
    }
    Ok(())
}
fn legacy_phases() -> Result<Value> {
    let b = fixed(R24, R24_SHA);
    let v = protected(&b)?;
    ensure!(
        v["schema"] == "horizon-resource-phases-new-native163-source-QA-DATA-v24"
            && v["exclusive_operational_owner"] == "01a1af2b-bc56-7311-a916-55aa5e102974"
            && v["normal_external_pool_bytes"] == NORMAL_POOL
            && v["temporary_QA_memory_additional_bytes"] == 0
            && v["additional_QA_memory_bytes_retained_until_authoritative_closure"] == 0
            && v["raw_DATA_bytes"] == 4641344777168u64
            && v["complete_conservative_raw_DATA_booking_bytes"] == 4703577050930u64
            && v["input163_protected_transfer_floor_after_new_helper_DATA_bytes"] == LEGACY_DATA_FLOOR
            && v["all_old_memory_DATA_and_raw_producer_promises_retained"] == true
            && v["no_idle_based_release_or_capacity_credit"] == true,
        "native exact original R24 pool/phases/raw obligations"
    );
    ensure!(
        n(&v, "raw_DATA_bytes")?.checked_add(n(&v, "complete_retained_additional_DATA_bytes")?)
            == Some(n(&v, "complete_conservative_raw_DATA_booking_bytes")?)
            && LEGACY_DATA_FLOOR >= n(&v, "complete_conservative_raw_DATA_booking_bytes")?,
        "native pinned DATA whole-phase arithmetic"
    );
    phase_chain(&b, &mut BTreeSet::new(), 0)?;
    Ok(v)
}
pub(super) fn phases(s: &NativeSpec) -> Result<Value> {
    // Historical R24 remains byte-exact with its historical owner. Takeover is additive.
    legacy_phases()?;
    takeover_scope(&protected(&takeover_binding())?)?;
    let v = immutable(&s.current_phase_ledger)?;
    current_phase_scope(&v)?;
    let mut visited = BTreeSet::new();
    phase_chain(&s.current_phase_ledger, &mut visited, 0)?;
    ensure!(visited.contains(Path::new(R24)), "current phase must retain original R24 chain");
    let closure = immutable(&to_bound(&v["extra_QA6_closure"])?)?;
    ensure!(closure["schema"] == "native163-full-reader-extra-QA6-closure-v1"
        && closure["extra_QA_memory_bytes"] == 6u64 << 30
        && closure["released_bytes"] == 6u64 << 30
        && closure["normal_pool_released_bytes"] == 0
        && closure["all_original_QA_actors_terminal_and_drained"] == true
        && closure["all_required_qualification_actors_terminal_successful_and_drained"] == true
        && closure["source_and_DATA_promises_retained"] == true,
        "full reader extra6GiB QA must close authoritatively before native launch");
    Ok(v)
}
fn receipt_scope(d: &Value, snapshot: &Path, download_plan: &Bound) -> Result<()> {
    ensure!(
        d["schema"] == "jetstreamer-epoch163-snapshot-download-receipt-v1"
            && d["epoch"] == 163
            && d["generation"] == "1634787272998262"
            && d["uri"] == URI
            && d["path"] == json!(snapshot)
            && d["bytes"] == SIZE
            && d["crc32c_base64"] == "bpbuVg=="
            && d["md5_base64"] == "GIvvcL0yXKjY2dumxRsJrg=="
            && d["sha256"] == SNAPSHOT_SHA
            && d["self_sha256"] == DOWNLOAD_SHA
            && d["plan_sha256"] == download_plan.sha256
            && d["compressed_input_verified"] == true
            && d["source_completeness_proven"] == false
            && d["live_state_proven"] == false
            && d["replay_launch_authorized"] == false
            && d["publication_authorized"] == false
            && d["remote_mutations"] == false
            && d["r2_mutations"] == false,
        "native genuine generation-pinned canonical downloader receipt scope"
    );
    Ok(())
}
fn receipt(d: &Value, p: &NativePlan, download_plan: &Bound) -> Result<()> {
    receipt_scope(d, &p.snapshot, download_plan)?;
    let t = now()?;
    ensure!(
        d["recorded_unix_seconds"].as_u64().is_some_and(|x| x <= t),
        "downloader receipt future/missing time"
    );
    let m = fs::symlink_metadata(&p.snapshot)?;
    ensure!(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o777 == 0o444
            && m.len() == SIZE
            && d["device"] == m.dev()
            && d["inode"] == m.ino()
            && d["uid"] == m.uid()
            && d["links"] == m.nlink()
            && d["mode"] == "0444",
        "original verified compressed file inode/size/Root ownership changed"
    );
    Ok(())
}
fn history(unit: &str, iid: &str, recorded: u64) -> Result<Value> {
    let out = ProcessCommand::new("/usr/bin/journalctl")
        .args(["--all", "--no-pager", "--output=json", "-u", unit, "_PID=1"])
        .output()?;
    ensure!(
        out.status.success() && out.stdout.len() <= 8 << 20,
        "native original downloader PID1 journal"
    );
    let mut start = None;
    let mut complete = None;
    for row in out.stdout.split(|b| *b == b'\n').filter(|r| !r.is_empty()) {
        let v: Value = serde_json::from_slice(row)?;
        if v["_PID"] != "1" || v["UNIT"] != unit || v["INVOCATION_ID"] != iid {
            continue;
        }
        if v["JOB_TYPE"] == "start" && v["JOB_RESULT"] == "done" {
            ensure!(
                start.replace(v.clone()).is_none(),
                "duplicate original downloader start"
            );
        }
        if v["UNIT_RESULT"] == "success" {
            let time = v["__REALTIME_TIMESTAMP"]
                .as_str()
                .context("downloader completion journal time")?
                .parse::<u64>()?
                / 1000000;
            ensure!(
                time >= recorded,
                "downloader original completion predates receipt"
            );
            ensure!(
                complete.replace(v).is_none(),
                "duplicate original downloader completion"
            );
        }
    }
    let start=start.context("original downloader PID1 start absent")?;
    let completion=match complete {
        Some(value)=>value,
        None=>retained_exec::retained_completion(unit,iid,recorded,&start)?,
    };
    Ok(json!({"start":start,"completion":completion}))
}
pub(super) fn download(s: &NativeSpec, p: &NativePlan) -> Result<Value> {
    let d = immutable(&p.download)?;
    if s.download_unit == CURRENT_DOWNLOAD_UNIT {
        ensure!(s.download_plan.path == Path::new(CURRENT_DOWNLOAD_PLAN)
            && p.download.path == Path::new(CURRENT_DOWNLOAD_RECEIPT)
            && d["invocation_id"] == CURRENT_DOWNLOAD_IID,
            "current downloaded original unit/plan/receipt/IID binding");
    }
    receipt(&d, p, &s.download_plan)?;
    storage::bytes(&fixed(DOWNLOAD_IMAGE, DOWNLOAD_SHA), 64 << 20, true)?;
    let plan = immutable(&s.download_plan)?;
    ensure!(
        plan["schema"] == "jetstreamer-epoch163-snapshot-download-plan-v1"
            && plan["output_receipt"] == json!(p.download.path)
            && plan["staging_directory"].as_str().map(Path::new) == p.snapshot.parent()
            && plan["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|x| x >= 4700000000000u64)
            && d["admission_receipt_sha256"] == plan["admission_receipt"]["sha256"],
        "native original downloader plan binding"
    );
    // Bind original metadata and downloader admission bytes; these do not grant native/replay authority.
    for key in ["metadata_receipt", "admission_receipt"] {
        immutable(&to_bound(&plan[key])?)?;
    }
    let iid = d["invocation_id"]
        .as_str()
        .context("original downloader invocation")?;
    ensure!(storage::hex(iid, 32), "original downloader IID shape");
    let native = held::native(&s.download_unit)?;
    ensure!(
        native["Id"] == s.download_unit
            && native["LoadState"] == "loaded"
            && native["InvocationID"] == iid
            && native["MainPID"] == "0"
            && native["ControlPID"] == "0"
            && native["NRestarts"] == "0"
            && native["Restart"] == "no"
            && native["User"] == "root"
            && native["Type"] == "exec"
            && native["MemoryAccounting"] == "yes"
            && native["MemoryMax"].as_str() == Some((512u64 << 20).to_string().as_str())
            && native["MemorySwapMax"] == "0"
            && native["NoNewPrivileges"] == "yes"
            && native["Result"] == "success"
            && native["ExecMainStatus"] == "0"
            && native["RemainAfterExit"] == "yes"
            && native["ActiveState"] == "active"
            && native["SubState"] == "exited"
            && native["ControlGroup"] == ""
            && native["Job"] == "",
        "actual original compressed downloader not terminal successful/drained/retained"
    );
    let args = vec![
        DOWNLOAD_IMAGE.into(),
        "--plan".into(),
        s.download_plan.path.to_string_lossy().into_owned(),
        "--plan-sha256".into(),
        s.download_plan.sha256.clone(),
        "--self-sha256".into(),
        DOWNLOAD_SHA.into(),
    ];
    held::command(&native, Path::new(DOWNLOAD_IMAGE), &args)?;
    let cg = PathBuf::from(format!("/sys/fs/cgroup/system.slice/{}", s.download_unit));
    ensure!(
        !cg.try_exists()?
            || fs::read_to_string(cg.join("cgroup.procs"))?
                .trim()
                .is_empty(),
        "downloader child cgroup remains"
    );
    let hist = history(&s.download_unit, iid, n(&d, "recorded_unix_seconds")?)?;
    ensure!(
        held::native(&s.download_unit)? == native,
        "downloader native changed"
    );
    Ok(
        json!({"download_receipt":p.download,"download_plan":s.download_plan,"native":native,"original_PID1":hist,"snapshot_sha256":d["sha256"],"snapshot_body_not_opened":true}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn good() -> Value {
        json!({"schema":"jetstreamer-epoch163-snapshot-download-receipt-v1","epoch":163,
        "generation":"1634787272998262","uri":URI,"path":"/snapshot","bytes":SIZE,"crc32c_base64":"bpbuVg==",
        "md5_base64":"GIvvcL0yXKjY2dumxRsJrg==","sha256":SNAPSHOT_SHA,"self_sha256":DOWNLOAD_SHA,
        "plan_sha256":"b".repeat(64),"compressed_input_verified":true,"source_completeness_proven":false,
        "live_state_proven":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false})
    }
    fn phase() -> Value {
        json!({"schema":"horizon-native163-current-fixed128-phase-v1",
            "exclusive_operational_owner":PRIMARY,"visible_thread_takeover":takeover_binding(),
            "normal_external_pool_bytes":NORMAL_POOL,"extra_full_reader_QA_memory_bytes":0,
            "additional_QA_memory_bytes_retained_until_authoritative_closure":0,
            "protected_existing_DATA_bytes":DATA_FLOOR,
            "complete_conservative_raw_DATA_booking_bytes":DATA_FLOOR,
            "minimum_available_memory_bytes":MEM_FLOOR,
            "minimum_existing_memory_bytes":(80u64<<30)+(256u64<<20),
            "all_original_memory_DATA_and_raw_producer_promises_retained":true,
            "no_release_or_idle_credit":true,
            "retained145":{"exporter_memory_bytes":80u64<<30,"guard_memory_bytes":256u64<<20,
                "exporter_DATA_bytes":(160u64<<30)+(128u64<<20),"source_DATA_bytes":4u64<<30,"exporter_cpu_quota_micros":8000000,
                "guard_cpu_quota_micros":1000000,"failed_exporter_does_not_release_promises":true,
                "memory_in_existing_total":true}})
    }
    #[test]
    fn current_phase_retains_failed145_and_all_later_charges() {
        let good = phase();
        current_phase_scope(&good).unwrap();
        for (field, bad) in [("protected_existing_DATA_bytes",json!(DATA_FLOOR-1)),
            ("minimum_available_memory_bytes",json!(MEM_FLOOR-1)),
            ("minimum_existing_memory_bytes",json!(80u64<<30)),
            ("exclusive_operational_owner",json!("01a1af2b-bc56-7311-a916-55aa5e102974")),
            ("extra_full_reader_QA_memory_bytes",json!(6u64<<30)),
            ("additional_QA_memory_bytes_retained_until_authoritative_closure",json!(6u64<<30)),
            ("normal_external_pool_bytes",json!(8u64<<30)),
            ("no_release_or_idle_credit",json!(false))] {
            let mut v=good.clone(); v[field]=bad; assert!(current_phase_scope(&v).is_err(), "{field}");
        }
        let mut higher=good.clone();
        higher["protected_existing_DATA_bytes"]=json!(DATA_FLOOR+100);
        higher["complete_conservative_raw_DATA_booking_bytes"]=json!(DATA_FLOOR+100);
        current_phase_scope(&higher).unwrap();
        higher["complete_conservative_raw_DATA_booking_bytes"]=json!(DATA_FLOOR+101);
        assert!(current_phase_scope(&higher).is_err());
        for field in ["exporter_memory_bytes","guard_memory_bytes","exporter_DATA_bytes","source_DATA_bytes",
            "exporter_cpu_quota_micros","guard_cpu_quota_micros"] {
            let mut v=good.clone();v["retained145"][field]=json!(0);
            assert!(current_phase_scope(&v).is_err(),"{field}");
        }
    }
    #[test]
    fn explicit_archival_and_new_sole_controller_are_required() {
        let good=json!({"schema":"horizon-user-ordered-visible-thread-takeover-v1",
            "current_sole_primary_thread":PRIMARY,
            "former_primary_thread":"01a1af2b-bc56-7311-a916-55aa5e102974",
            "supersedes_prior_owner_ACK_for_future_control":true,
            "former_thread_archive_tool_returned_archived_true":true,
            "preserve_launched_jobs_guards_evidence_and_single_observer":true});
        takeover_scope(&good).unwrap();
        for field in ["supersedes_prior_owner_ACK_for_future_control",
            "former_thread_archive_tool_returned_archived_true",
            "preserve_launched_jobs_guards_evidence_and_single_observer"] {
            let mut v=good.clone();v[field]=json!(false);assert!(takeover_scope(&v).is_err());
        }
    }
    #[test]
    fn canonical_download_scope_rejects_other_generation_image_path_or_authority() {
        let plan = fixed("/download-plan", &"b".repeat(64));
        let snapshot = Path::new("/snapshot");
        let ok = good();
        receipt_scope(&ok, snapshot, &plan).unwrap();
        for (key, bad) in [
            ("generation", json!(1634787272998262u64)),
            ("generation", json!("1634787310547338")),
            ("bytes", json!(SIZE + 1)),
            ("sha256", json!("a".repeat(64))),
            ("self_sha256", json!("0".repeat(64))),
            ("crc32c_base64", json!("yrN75Q==")),
            ("md5_base64", json!("wrong")),
            ("plan_sha256", json!("c".repeat(64))),
            ("path", json!("/other")),
            ("schema", json!("epoch163-bootstrap-download-receipt-v1")),
            ("replay_launch_authorized", json!(true)),
            ("compressed_input_verified", json!(false)),
            ("r2_mutations", json!(true)),
        ] {
            let mut d = ok.clone();
            d[key] = bad;
            assert!(receipt_scope(&d, snapshot, &plan).is_err(), "{key}");
        }
    }
    #[test]
    fn missing_source_integrity_or_no_authority_fields_fail_closed() {
        let plan = fixed("/download-plan", &"b".repeat(64));
        for key in [
            "sha256",
            "self_sha256",
            "plan_sha256",
            "source_completeness_proven",
            "live_state_proven",
            "remote_mutations",
            "publication_authorized",
        ] {
            let mut d = good();
            d.as_object_mut().unwrap().remove(key);
            assert!(
                receipt_scope(&d, Path::new("/snapshot"), &plan).is_err(),
                "{key}"
            );
        }
    }
}
