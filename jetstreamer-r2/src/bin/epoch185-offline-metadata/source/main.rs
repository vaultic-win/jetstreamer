//! Metadata-only original source-plan materializer. No native/service/resource
//! endpoints, credential/network/body work, admission, clock issuance or launch.
mod lineage;
mod resources;
mod storage;
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File},
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::{Path, PathBuf},
};
use storage::Bound;
const ROOT: &str =
    "/home/sol/.jetstreamer-private/epoch185-offline-retained-input-contract-source-20261106-v1/r5";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Role {
    image: Bound,
    artifact: Bound,
    normal_seal: Bound,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    complete_tuple: Bound,
    phase_ledger: Bound,
    protected_exporter_plan: Bound,
    #[serde(rename = "native163_QA_drain")]
    native163_qa_drain: Bound,
    accounting_role: Role,
    native185_capture_role: Role,
    original_controller_correction: Bound,
    input_package_seal: Bound,
    accepted_local_integrity_basis: Bound,
    original_restore_receipt: Bound,
    predecessor_v13_failure: Bound,
    output_directory: PathBuf,
}
fn revised(raw: &str) -> String {
    raw.replace("20261106-v14", "20261107-v15")
}
fn template(raw: &str, floor: u64, envelope: bool) -> Result<Value> {
    let mut v: Value = serde_json::from_str(&revised(raw))?;
    if envelope {
        v["plan"]["minimum_free_bytes"] = json!(floor);
    } else {
        v["minimum_free_bytes"] = json!(floor);
    }
    Ok(v)
}
fn output_path(tuple_sha: &str) -> Result<PathBuf> {
    ensure!(storage::hex(tuple_sha, 64), "exact tuple digest namespace");
    Ok(Path::new(ROOT).join(format!("generated-v15-plan-{tuple_sha}")))
}
fn materialize(request_binding: &Bound, self_image: &Bound) -> Result<Value> {
    let s: Request = serde_json::from_value(storage::json(request_binding)?)?;
    ensure!(
        s.schema == "epoch185-R25-retained-metadata-plan-request-v3",
        "exact metadata plan request"
    );
    ensure!(
        s.output_directory == output_path(&s.complete_tuple.sha256)?
            && !s.output_directory.try_exists()?,
        "exact fresh output directory"
    );
    let parent = s.output_directory.parent().context("output parent")?;
    let pm = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && pm.is_dir()
            && pm.uid() == 0
            && pm.mode() & 0o777 == 0o700,
        "private source-plan output custody"
    );
    let ledger = storage::json(&s.phase_ledger)?;
    let tuple = storage::json(&s.complete_tuple)?;
    ensure!(
        tuple["schema"] == "horizon-existing-completed-tuple-metadata-binding-v1"
            && tuple["metadata_only_no_admission_or_new_resource_credit"] == true,
        "complete retained tuple scope"
    );
    let (_, components) = storage::member(&tuple, "components")?;
    let (memory_binding, memory) = storage::member(&components, "actual_memory_selection")?;
    let (data_binding, data) = storage::member(&components, "actual_DATA_selection")?;
    ensure!(
        data["memory_selection"] == json!(memory_binding),
        "original typed DATA/memory selection crossing"
    );
    let current = lineage::tuple(&memory, &data, &tuple)?;
    let (reader_binding, reader) =
        storage::member(&memory["selection"]["request"], "current_reader")?;
    let (completion_binding, completion) =
        storage::member(&memory["selection"]["request"], "current_reader_acceptance")?;
    let cn = &completion["original_native"];
    ensure!(
        completion["reader_proof"] == json!(reader_binding)
            && completion["original_outer_reaped"] == true
            && completion["original_cgroup_empty"] == true
            && completion["original_descriptors_drained"] == true
            && cn["InvocationID"] == reader["invocation_id"]
            && cn["Result"] == "success"
            && cn["ExecMainStatus"] == "0"
            && cn["MainPID"] == "0"
            && cn["ControlPID"] == "0"
            && cn["Job"] == ""
            && cn["NRestarts"] == "0"
            && reader["raw_history_preserved"] == true
            && reader["all_DATA_promises_preserved"] == true,
        "original full-reader completion/history"
    );
    let (raw_binding, raw) = storage::member(&reader, "accounting")?;
    let mut projection = resources::project(&ledger, &tuple, &raw, &memory, &data)?;
    projection["sources"] =
        resources::projection_sources(&s.complete_tuple, &s.phase_ledger, &raw_binding);
    let exporter = storage::json(&s.protected_exporter_plan)?;
    ensure!(
        exporter["schema"] == "horizon-epoch145-private-prefix-extractor-plan-v1"
            && exporter["actor_unit"] == "horizon-extract145-prefix-real1328-20261106-v1.service"
            && exporter["minimum_available_memory_bytes"] == 642177138688u64
            && exporter["minimum_free_bytes"] == 4855589825488u64,
        "exact existing exporter reserve plan"
    );
    let inherited_floor = storage::n(&projection, "minimum_free_bytes_for_future_template")?;
    let exporter_floor = storage::n(&exporter, "minimum_free_bytes")?;
    projection["minimum_free_bytes_for_future_template"] =
        json!(inherited_floor.max(exporter_floor));
    projection["protected_exporter_plan"] = json!(s.protected_exporter_plan);
    projection["inherited_exporter_available_memory_floor_bytes"] =
        exporter["minimum_available_memory_bytes"].clone();
    projection["fresh_admission_must_preserve_actual_exporter_reserves"] = json!(true);

    let anchor = lineage::directory_anchor(&memory, &current)?;
    let correction = storage::json(&s.original_controller_correction)?;
    ensure!(
        correction["controller_still_running"] == true
            && correction["summary_claim_controller_ended_disproved"] == true
            && correction["native"]["InvocationID"] == lineage::IID
            && correction["native"]["MainPID"] == "2467123"
            && correction["original_fd9"]
                == "/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private",
        "preserve live-controller correction; no terminal closure requirement"
    );
    let qa = storage::json(&s.native163_qa_drain)?;
    ensure!(
        qa["all_original_actors_succeeded_and_drained"] == true
            && qa["original_actor_count"] == 15
            && qa["additional_QA_memory_reservation_bytes"] == 0
            && qa["normal_pool_retained_bytes"] == 6u64 << 30,
        "native163 normal-pool actor phase not drained"
    );
    for b in qa["original_actor_drain_receipts"]
        .as_array()
        .context("original native163 drains")?
    {
        let b = Bound {
            path: b["path"].as_str().context("drain path")?.into(),
            sha256: b["sha256"].as_str().context("drain digest")?.into(),
        };
        let drain = storage::json(&b)?;
        let n = &drain["actual_stopped_and_drained_native"];
        ensure!(
            drain["original_process_absent"] == true
                && n["MainPID"] == "0"
                && n["ControlPID"] == "0"
                && n["Job"] == ""
                && n["NRestarts"] == "0",
            "retained original native163 actor not drained"
        );
    }
    let roles = json!({"accounting":lineage::role(&s.accounting_role.image,&s.accounting_role.artifact,&s.accounting_role.normal_seal,lineage::ACCOUNTING_PATH,lineage::ACCOUNTING_SHA)?,
  "native185_capture":lineage::role(&s.native185_capture_role.image,&s.native185_capture_role.artifact,&s.native185_capture_role.normal_seal,lineage::NATIVE_PATH,lineage::NATIVE_SHA)?,
  "native185_capture_consumers_current_schema_compatibility_not_claimed":true});
    let seal = storage::json(&s.input_package_seal)?;
    ensure!(
        seal["destination"]
            == "/usr/local/lib/jetstreamer/horizon-epoch185-cohesive-capped-inputs-20261105-v3",
        "cohesive capped input package scope"
    );
    ensure!(
        seal["members"]
            .as_array()
            .context("input seal members")?
            .iter()
            .any(|m| m["name"] == "jetstreamer-historical-worker-v1-6-15"
                && m["sha256"]
                    == "6eef40863851927d0611fd90dd7c68528c8e1491a0fc18a28de492afa67316bd"),
        "capped worker image crossed"
    );
    storage::json(&s.accepted_local_integrity_basis)?;
    let restore = storage::json(&s.original_restore_receipt)?;
    lineage::retained_inputs(&seal, &restore)?;
    // The generation/body lineage is retained as its original receipt. This planner
    // never opens the snapshot or claims new integrity/native initialization.
    let prior = storage::json(&s.predecessor_v13_failure)?;
    ensure!(
        prior["never_started_v13_actor"] == true
            && prior["original_deadline_not_reset"] == true
            && prior["no_token_guard_timer_replay_or_publication"] == true,
        "original failure/clock preservation"
    );
    let floor = storage::n(&projection, "minimum_free_bytes_for_future_template")?;
    let admission = template(include_str!("templates/admission.json"), floor, false)?;
    let mut envelope = template(include_str!("templates/envelope.json"), floor, true)?;
    let timer_sha = storage::sha(revised(include_str!("templates/guard.timer")).as_bytes());
    envelope["timer_service"]["sha256"] = json!(timer_sha);
    let mut task_spec: Value =
        serde_json::from_str(&revised(include_str!("templates/task-spec.json")))?;
    task_spec["native_spec"]["timer_source"]["sha256"] = json!(timer_sha);
    let future = json!({"schema":"epoch185-distinct-v15-missing-token-required-gates-v1",
  "original_deployment_and_GCS_contract_unchanged":true,"offline_restore_requires_separate_qualified_source_profile":true,
  "required_before_original_admission":["Root source/artifact QA and normal seal of this planner","Fresh complete typed tuple and authenticated exact six-field status with positive remaining time","R24 or explicitly reviewed successor ledger and no unbooked/overlapping actor phase","Image hashes/source graphs and exact native185/current-reader consumer compatibility","Fresh supported live directory-anchor census/selection preserving controller IID,start ticks and retained directory","Point-of-use CPU affinity,memory/PSI/DATA/inode/VMA,all guards and complete owners","Full300second original admission within both unchanged freshness windows","Original v13 failures,all raw promises and no duplicate selection/retirement credit"],
  "required_after_original_admission":["Normal create-new evidence/envelope/unit seals and exact unprivileged metadata readability","Distinct v15 native unit namespace,one reload with full R4 timer deadline audit","Actual original ready-file event,IID,ControlPID,start ticks,60second immutable setup deadline","Capture task using native1850f1d helper only","No token,guard/timer activation,main hashing,worker,replay,publication","Original deadline failure,PID1 ExecStartPre exit1,same-IID terminal,cgroup drain,stable original logs,empty artifacts"],
  "publication_authorized":false,"admission_authorized":false});
    // Only after all bound retained inputs are validated do we create metadata.
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&s.output_directory)?;
    let outputs = vec![
        storage::save(
            &s.output_directory,
            "RESOURCE_PLAN_NOT_ADMISSION.json",
            &projection,
        )?,
        storage::save(&s.output_directory, "HELPER_ROLES.json", &roles)?,
        storage::save(
            &s.output_directory,
            "LIVE_CONTROLLER_DIRECTORY_ANCHOR_PLAN.json",
            &anchor,
        )?,
        storage::save(
            &s.output_directory,
            "ADMISSION_TEMPLATE_UNISSUED.json",
            &admission,
        )?,
        storage::save(
            &s.output_directory,
            "ENVELOPE_TEMPLATE_UNISSUED.json",
            &envelope,
        )?,
        storage::save(&s.output_directory, "REQUIRED_GATES.json", &future)?,
        storage::save(
            &s.output_directory,
            "ORIGINAL_SOURCE_TEMPLATES.json",
            &json!({"actor":revised(include_str!("templates/actor.service")),
   "guard":revised(include_str!("templates/guard.service")),"timer":revised(include_str!("templates/guard.timer")),
   "task_capture_spec":task_spec}),
        )?,
    ];
    let manifest = json!({"schema":"epoch185-R25-original-metadata-plan-materialized-v3","request":request_binding,"program":self_image,
  "complete_tuple":s.complete_tuple,"phase_ledger":s.phase_ledger,"current":current,"reader":reader_binding,"original_reader_completion":completion_binding,
  "memory_selection":memory_binding,"DATA_selection":data_binding,"controller_correction":s.original_controller_correction,
  "native163_QA_drain":s.native163_qa_drain,"input_package_seal":s.input_package_seal,
  "accepted_local_integrity_basis":s.accepted_local_integrity_basis,"original_restore_receipt":s.original_restore_receipt,
  "original_restore_schema":restore["schema"],"prior_v13_failure":s.predecessor_v13_failure,"outputs":outputs,
  "metadata_only":true,"new_resource_samples":0,"new_snapshot_body_hash":false,"native_calls":0,"fresh_current_capacity_claimed":false,
  "admission_issued":false,"replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false});
    let result = storage::save(
        &s.output_directory,
        "PLAN_MANIFEST_NOT_ADMISSION.json",
        &manifest,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(json!({"metadata_plan":result,"admission_issued":false}))
}
fn run() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    ensure!(
        unsafe { libc::geteuid() } == 0
            && args.len() == 7
            && args[1] == "plan-retained185"
            && args[3] == "--request-sha256"
            && args[5] == "--self-sha256",
        "exact metadata planner root/CLI"
    );
    ensure!(
        !env::vars_os()
            .any(|(k, _)| k.to_string_lossy().starts_with("LD_") || k == "GLIBC_TUNABLES"),
        "loader override"
    );
    let image = Bound {
        path: fs::read_link("/proc/self/exe")?,
        sha256: args[6].clone(),
    };
    ensure!(
        image.path.parent().and_then(Path::parent) == Some(Path::new("/usr/local/lib/jetstreamer")),
        "qualified normal image namespace"
    );
    let own = storage::bytes(&image, 128 << 20, true)?;
    ensure!(fs::read("/proc/self/exe")? == own, "mapped image differs");
    let request = Bound {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    println!("{}", materialize(&request, &image)?);
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("metadata185 plan: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod output_tests {
    use super::*;
    #[test]
    fn different_full_tuples_get_disjoint_retry_stable_private_output_paths() {
        let a = output_path(&"a".repeat(64)).unwrap();
        let b = output_path(&"b".repeat(64)).unwrap();
        assert_eq!(a, output_path(&"a".repeat(64)).unwrap());
        assert_ne!(a, b);
        assert_eq!(a.parent(), Some(Path::new(ROOT)));
        for invalid in ["../escape".into(), "A".repeat(64), "a".repeat(63)] {
            assert!(output_path(&invalid).is_err());
        }
    }
    #[test]
    fn real_packet_members_cannot_overwrite_or_escape() {
        let root =
            std::env::temp_dir().join(format!("offline185-packet-control-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let original = json!({"authority":false,"original":true});
        let bound = storage::save(&root, "original.json", &original).unwrap();
        let before = std::fs::read(&bound.path).unwrap();
        assert!(storage::save(&root, "original.json", &json!({"authority":true})).is_err());
        assert_eq!(std::fs::read(&bound.path).unwrap(), before);
        assert!(storage::save(&root, "../escape.json", &original).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
