//! Explicit byte-identical normal-sealed views for sol's existing release reader.
//! Original receipts, paths, clocks and authority remain immutable. This route
//! neither seals files itself nor launches work; Root supplies the real seal.
use super::*;
use std::os::unix::fs::MetadataExt;

const SEALER_SHA: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const READABLE_PARENT: &str = "/usr/local/lib/jetstreamer";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    task: BoundFile,
    original_bridge: BoundFile,
    readable_underlying: BoundFile,
    normal_copy_seal: BoundFile,
    output: PathBuf,
}
fn integer(v: &Value, key: &str) -> Result<u64> {
    v[key].as_u64().with_context(|| format!("readable evidence integer {key}"))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key].as_str().with_context(|| format!("readable evidence string {key}"))
}
fn names(kind: &str) -> Result<(&'static str, &'static str)> {
    Ok(match kind {
        "task_acknowledgment" => ("task-acknowledgment.json", "readable-task-acknowledgment.json"),
        "status_readback" => ("status-readback.json", "readable-status-readback.json"),
        "fleet_enrollment" => ("fleet-acceptance.json", "readable-fleet-acceptance.json"),
        "current_reader_native_acceptance" => ("reader-acceptance.json", "readable-reader-acceptance.json"),
        _ => bail!("readable evidence cannot promote an unknown receipt kind"),
    })
}

fn bridge_policy(spec: &Spec, bridge: &Value, task: &Value, self_sha: &str, now: u64) -> Result<BoundFile> {
    ensure!(spec.schema == "horizon-epoch185-readable-original-proof-spec-v1",
        "readable evidence spec schema changed");
    let iid = text(task, "actor_invocation_id")?;
    ensure!(is_lower_hex(iid, 32), "readable evidence malformed original IID");
    let kind = text(bridge, "kind")?;
    let (original_name, output_name) = names(kind)?;
    let directory = Path::new(ROOT).join(iid);
    ensure!(spec.original_bridge.path == directory.join(original_name)
        && spec.output == directory.join(output_name),
        "readable evidence changed original/output path, IID or kind");
    let ready = &task["ready"];
    let at = integer(bridge, "sampled_at")?;
    let started = integer(ready, "started_at")?;
    ensure!(task["schema"] == TASK_SCHEMA && task["stage"] == "start-pre"
        && task["guard_pending"] == true && task["task"] == json!(spec.task)
        && bridge["schema"] == "horizon-epoch185-native-owner-enrollment-v4"
        && bridge["epoch"] == 185 && bridge["actor_unit"] == task["actor_unit"]
        && bridge["actor_invocation_id"] == iid && bridge["ready_pid"] == ready["pid"]
        && bridge["ready_start_ticks"] == ready["start_ticks"]
        && bridge["admission_sha256"] == task["admission"]["sha256"]
        && bridge["restarts"] == 0 && bridge["phase"] == "verification"
        && bridge["root_operator_owner"] == true
        && bridge["actual_start_pre_evidence_accepted"] == true
        && bridge["resource_credit_bytes"] == 0
        && bridge["self_sha256"] == self_sha
        && bridge["publication_authorized"] == false && bridge["r2_mutations"] == false
        && bridge["ordinary_full_replay_authorized"] != true && bridge["replay_launch_authorized"] != true
        && started <= at && at <= now && now - at <= 30
        && now < integer(task, "original_setup_deadline_unix_seconds")?,
        "readable evidence original receipt is stale, foreign, released or unauthorized");
    let original: BoundFile = serde_json::from_value(bridge["underlying_accepted_proof"].clone())?;
    match kind {
        "task_acknowledgment" => ensure!(json!(original) == json!(spec.task), "task bridge underlying source crossed"),
        "status_readback" => ensure!(json!(original) == task["current_task"], "status bridge underlying source crossed"),
        "fleet_enrollment" => ensure!(json!(original) == bridge["actual_fleet"], "fleet bridge underlying source crossed"),
        "current_reader_native_acceptance" => {
            ensure!(bridge["exact_original_families"] == json!([4,5,6,7])
                && bridge["all_four_original_family_rows_rehashed_and_equal"] == true,
                "reader bridge lost its original complete four families");
        }
        _ => unreachable!(),
    }
    Ok(original)
}

/// Pure seal-member provenance policy. Both original and copy are independently
/// rehashed under their original custody rules by the runtime caller.
fn copy_policy(original: &BoundFile, copy: &BoundFile, seal: &Value, iid: &str, bytes: u64) -> Result<()> {
    ensure!(is_lower_hex(&original.sha256, 64) && original.sha256 == copy.sha256
        && original.path != copy.path && bytes <= 4 << 20,
        "readable copy is not a distinct byte-identical bounded original");
    let parent = copy.path.parent().context("readable copy parent")?;
    let leaf = parent.file_name().and_then(|p| p.to_str()).context("readable copy directory leaf")?;
    ensure!(parent.parent() == Some(Path::new(READABLE_PARENT))
        && leaf.starts_with("horizon-epoch185-readable-originals-")
        && leaf.ends_with(&format!("-{iid}")),
        "readable copy escaped exact positive original IID package");
    ensure!(seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
        && seal["destination"] == parent.to_string_lossy().as_ref()
        && seal["sealer_sha256"] == SEALER_SHA
        && is_lower_hex(text(seal, "plan_sha256")?, 64),
        "readable copy has no exact normal sealer provenance");
    let name = copy.path.file_name().and_then(|p| p.to_str()).context("readable copy filename")?;
    let members = seal["members"].as_array().context("readable normal-seal members")?;
    let matching = members.iter().filter(|m| m["name"] == name).collect::<Vec<_>>();
    ensure!(matching.len() == 1 && matching[0]["source"] == original.path.to_string_lossy().as_ref()
        && matching[0]["sha256"] == original.sha256
        && matching[0]["bytes"] == bytes && matching[0]["mode"] == "0444",
        "readable copy seal lost exact original source, bytes, digest or mode");
    Ok(())
}
fn readable_metadata(path: &Path) -> Result<()> {
    ensure!(path.is_absolute() && path.canonicalize()? == path, "readable copy path alias");
    let m = fs::symlink_metadata(path)?;
    ensure!(m.is_file() && m.uid() == 0 && m.nlink() == 1 && m.mode() & 0o7777 == 0o444,
        "readable copy must be Root regular single-link0444");
    for parent in path.ancestors().skip(1) {
        let m = fs::symlink_metadata(parent)?;
        ensure!(m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o005 == 0o005,
            "readable copy ancestor is not immutable Root custody with sol traversal");
    }
    Ok(())
}

pub(in crate::fleet) fn run() -> Result<()> {
    let (spec_binding, self_sha) = super::parsed("prove-cold185-readable-evidence")?;
    let spec: Spec = serde_json::from_value(super::native::read_json(&spec_binding, 4 << 20)?)?;
    let before = super::load(&spec.task, super::now()?)?;
    let original_bridge = super::native::read_json(&spec.original_bridge, 4 << 20)?;
    let original = bridge_policy(&spec, &original_bridge, &before, &self_sha, super::now()?)?;
    let producer_spec: BoundFile = serde_json::from_value(original_bridge["spec"].clone())?;
    let producer = super::native::read_json(&producer_spec, 4 << 20)?;
    ensure!(producer["output"] == spec.original_bridge.path.to_string_lossy().as_ref(),
        "readable receipt does not bind its original producer output");
    let expected_schema = match text(&original_bridge,"kind")? {
        "task_acknowledgment" | "status_readback" => "horizon-epoch185-task-status-bridge-spec-v1",
        "fleet_enrollment" => "horizon-epoch185-genuine-fleet-acceptance-spec-v1",
        "current_reader_native_acceptance" => "horizon-epoch185-complete-current-reader-acceptance-spec-v1",
        _ => bail!("readable producer kind changed"),
    };
    ensure!(producer["schema"] == expected_schema, "readable original producer schema changed");
    match text(&original_bridge,"kind")? {
        "task_acknowledgment" | "status_readback" => {
            ensure!(producer["kind"] == original_bridge["kind"]
                && producer["task"] == json!(spec.task)
                && original_bridge["task"] == json!(spec.task),
                "readable task/status producer selected another original task or kind");
        }
        "fleet_enrollment" | "current_reader_native_acceptance" => {
            ensure!(producer["registration"] == original_bridge["registration"],
                "readable fleet/reader producer crossed registration");
            let registration:BoundFile=serde_json::from_value(producer["registration"].clone())?;
            let event=super::native::read_json(&registration,4<<20)?;
            ensure!(event["task"] == json!(spec.task)
                && event["actor_invocation_id"] == before["actor_invocation_id"],
                "readable fleet/reader event crossed actual task/IID");
            if original_bridge["kind"] == "fleet_enrollment" {
                ensure!(producer["actual_fleet"] == json!(original)
                    && producer["actual_fleet_plan"] == original_bridge["actual_fleet_plan"],
                    "readable fleet producer crossed original fleet/plan");
            } else {
                ensure!(producer["original_reader"] == json!(original)
                    && producer["original_reader_completion"] == original_bridge["original_reader_completion"],
                    "readable reader producer crossed original reader/completion");
            }
        }
        _ => unreachable!(),
    }
    // Raw current-reader/fleet JSON can be Root0600. Use the same stable,
    // no-follow, digest-bound generated-evidence reader as original accounting.
    let protected = crate::fleet::epoch186::accounting::protected_generated;
    ensure!(fs::symlink_metadata(&original.path)?.len() <= 4 << 20,
        "original proof exceeds release consumer bound");
    let original_value = protected(&original)?;
    if original_bridge["kind"] == "current_reader_native_acceptance" {
        ensure!(original_value["schema"] == "failed4-current-complete-accounting-reader-proof-v1"
            && original_value["image"] == json!({"path":fs::read_link("/proc/self/exe")?,"sha256":self_sha}),
            "readable reader underlying proof crossed original qualified image");
    }
    let copy_value = super::native::read_json(&spec.readable_underlying, 4 << 20)?;
    ensure!(copy_value == original_value, "readable copy semantic drift");
    readable_metadata(&spec.readable_underlying.path)?;
    readable_metadata(&spec.normal_copy_seal.path)?;
    let copy_parent = spec.readable_underlying.path.parent().context("readable copy parent")?;
    ensure!(spec.normal_copy_seal.path == copy_parent.join("deployment-seal-receipt.json"),
        "readable copy seal path differs from exact copy package");
    let seal = super::native::read_json(&spec.normal_copy_seal, 4 << 20)?;
    copy_policy(&original, &spec.readable_underlying, &seal, text(&before,"actor_invocation_id")?,
        fs::symlink_metadata(&spec.readable_underlying.path)?.len())?;
    let status_source: BoundFile = serde_json::from_value(before["current_task"].clone())?;
    let status = super::native::read_json(&status_source, 4 << 20)?;
    ensure!(status["owner_evidence"]["current_operator"] == "/root"
        && status["authenticated_readback"] == true
        && status["after_status"]["estimated_remaining_millis"] == original_bridge["numeric_delivery_eta_millis"]
        && integer(&original_bridge,"numeric_delivery_eta_millis")? > 0,
        "readable original bridge ETA differs from exact authenticated Root status");
    let after = super::load(&spec.task, super::now()?)?;
    super::task_status_bridge::stable(&before, &after)?;
    bridge_policy(&spec, &original_bridge, &after, &self_sha, super::now()?)?;
    // Repeat original and immutable copy reads immediately before publication.
    ensure!(protected(&original)? == original_value
        && super::native::read_json(&spec.readable_underlying, 4 << 20)? == original_value
        && super::native::read_json(&spec.original_bridge, 4 << 20)? == original_bridge
        && super::native::read_json(&spec.normal_copy_seal, 4 << 20)? == seal,
        "readable evidence drifted before create-new publication");
    readable_metadata(&spec.readable_underlying.path)?;
    let mut view = original_bridge;
    // Preserve sample clock: relocation never renews a receipt's30-second
    // validity or the actor's original setup/admission.
    view["underlying_accepted_proof"] = json!(spec.readable_underlying);
    view["original_bridge"] = json!(spec.original_bridge);
    view["original_underlying_accepted_proof"] = json!(original);
    view["normal_copy_seal"] = json!(spec.normal_copy_seal);
    view["readable_evidence_spec"] = json!(spec_binding);
    view["readable_evidence_validator_sha256"] = json!(self_sha);
    view["original_clocks_unchanged"] = json!(true);
    super::persist(&spec.output, &view)?;
    println!("{}",json!({"readable_view":spec.output,"original_clocks_unchanged":true,
        "replay_launch_authorized":false,"publication_authorized":false}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn copy_fixture() -> (BoundFile, BoundFile, Value, String) {
        let iid="a".repeat(32);
        let original=BoundFile{path:"/fixture/original-reader-proof.json".into(),sha256:"b".repeat(64)};
        let parent=Path::new(READABLE_PARENT).join(format!("horizon-epoch185-readable-originals-fixture-{iid}"));
        let copy=BoundFile{path:parent.join("reader.json"),sha256:original.sha256.clone()};
        let seal=json!({"schema":"jetstreamer-sealed-deployment-receipt-v1",
            "sealer_sha256":SEALER_SHA,"plan_sha256":"c".repeat(64),"destination":parent,
            "members":[{"source":original.path,"name":"reader.json","sha256":original.sha256,
                "bytes":100,"mode":"0444"}]});
        (original,copy,seal,iid)
    }

    fn bridge_fixture() -> (Spec, Value, Value, String, u64) {
        let iid="a".repeat(32);let sha="d".repeat(64);let now=1000;
        let task_binding=json!({"path":"/fixture/task.json","sha256":"b".repeat(64)});
        let spec:Spec=serde_json::from_value(json!({
            "schema":"horizon-epoch185-readable-original-proof-spec-v1",
            "task":task_binding,
            "original_bridge":{"path":Path::new(ROOT).join(&iid).join("task-acknowledgment.json"),"sha256":"c".repeat(64)},
            "readable_underlying":{"path":"/fixture/copy.json","sha256":"b".repeat(64)},
            "normal_copy_seal":{"path":"/fixture/deployment-seal-receipt.json","sha256":"c".repeat(64)},
            "output":Path::new(ROOT).join(&iid).join("readable-task-acknowledgment.json")
        })).unwrap();
        let task=json!({"schema":TASK_SCHEMA,"stage":"start-pre","guard_pending":true,
            "task":task_binding,"actor_unit":"actor.service","actor_invocation_id":iid,
            "ready":{"started_at":900,"pid":123,"start_ticks":456},
            "admission":{"sha256":"c".repeat(64)},"original_setup_deadline_unix_seconds":1500});
        let bridge=json!({"schema":"horizon-epoch185-native-owner-enrollment-v4",
            "kind":"task_acknowledgment","epoch":185,"actor_unit":"actor.service","actor_invocation_id":iid,
            "ready_pid":123,"ready_start_ticks":456,"admission_sha256":"c".repeat(64),
            "restarts":0,"phase":"verification","root_operator_owner":true,
            "actual_start_pre_evidence_accepted":true,"resource_credit_bytes":0,"self_sha256":sha,
            "publication_authorized":false,"r2_mutations":false,"sampled_at":990,
            "underlying_accepted_proof":task_binding});
        (spec,bridge,task,sha,now)
    }
    #[test]
    fn relocation_cannot_renew_an_expired_bridge_or_original_setup() {
        let (spec,bridge,task,sha,now)=bridge_fixture();
        bridge_policy(&spec,&bridge,&task,&sha,now).unwrap();
        assert!(bridge_policy(&spec,&bridge,&task,&sha,1021).is_err());
        assert!(bridge_policy(&spec,&bridge,&task,&sha,1500).is_err());
        assert_eq!(bridge["sampled_at"],990);
    }
    #[test]
    fn relocation_rejects_foreign_iid_ready_image_and_output_kind() {
        let (mut spec,bridge,task,sha,now)=bridge_fixture();
        for (pointer,value) in [("/actor_invocation_id",json!("e".repeat(32))),
            ("/ready_start_ticks",json!(457)),("/self_sha256",json!("e".repeat(64))),
            ("/sampled_at",json!(1001))] {
            let mut bad=bridge.clone();*bad.pointer_mut(pointer).unwrap()=value;
            assert!(bridge_policy(&spec,&bad,&task,&sha,now).is_err(),"{pointer}");
        }
        spec.output=Path::new(ROOT).join("a".repeat(32)).join("readable-status-readback.json");
        assert!(bridge_policy(&spec,&bridge,&task,&sha,now).is_err());
    }
    #[test]
    fn normal_copy_requires_exact_original_path_digest_bytes_and_mode() {
        let (original,copy,seal,iid)=copy_fixture();
        copy_policy(&original,&copy,&seal,&iid,100).unwrap();
        for (pointer,value) in [("/members/0/source",json!("/wrong-original")),
            ("/members/0/sha256",json!("d".repeat(64))),("/members/0/bytes",json!(101)),
            ("/members/0/mode",json!("0600")),("/sealer_sha256",json!("d".repeat(64)))] {
            let mut bad=seal.clone();*bad.pointer_mut(pointer).unwrap()=value;
            assert!(copy_policy(&original,&copy,&bad,&iid,100).is_err(),"{pointer}");
        }
    }
    #[test]
    fn copy_cannot_cross_iid_or_duplicate_seal_member() {
        let (original,copy,mut seal,iid)=copy_fixture();
        assert!(copy_policy(&original,&copy,&seal,&"d".repeat(32),100).is_err());
        let member=seal["members"][0].clone();seal["members"].as_array_mut().unwrap().push(member);
        assert!(copy_policy(&original,&copy,&seal,&iid,100).is_err());
    }
    #[test]
    fn digest_identity_and_release_bound_are_required() {
        let (original,mut copy,seal,iid)=copy_fixture();
        assert!(copy_policy(&original,&copy,&seal,&iid,(4<<20)+1).is_err());
        copy.sha256="d".repeat(64);
        assert!(copy_policy(&original,&copy,&seal,&iid,100).is_err());
    }
    #[test]
    fn supported_receipt_kind_cannot_be_reinterpreted_as_another_output() {
        assert_eq!(names("fleet_enrollment").unwrap(),("fleet-acceptance.json","readable-fleet-acceptance.json"));
        assert!(names("arbitrary_success").is_err());
    }
}
