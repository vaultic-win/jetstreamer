use crate::storage::{self, Bound};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
pub const CONTROLLER: &str = "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service";
pub const IID: &str = "dbf49bb1b72c42c584f2d3ac94259cb8";
pub const ACCOUNTING_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch163-first-output128-shared-helper-tools-20261106-v3/jetstreamer-r2";
pub const ACCOUNTING_SHA: &str = "d54025dd48a0748deeb4fcc3845e48564aa7619e95485061d85e30e31dbc8a43";
pub const NATIVE_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-native-hooks-complete-supported-route-tools-20261105-v11/jetstreamer-r2";
pub const NATIVE_SHA: &str = "0f1d171bc9fee7a1d06186e62b03e601d575bdcacfa30545cf0c084850f0934c";
pub const DRIVER11_NATIVE_PATH: &str = "/usr/local/lib/jetstreamer/horizon-epoch185-enrollment-composition-postreader-tools-20261108-v33/jetstreamer-r2";
pub const DRIVER11_NATIVE_SHA: &str = "b445a1fb3717da5b68984d6598d7d75efcf5131f0bc82091af506d586b8f49fd";
pub fn tuple(memory: &Value, data: &Value, tuple: &Value) -> Result<Value> {
    let current = &memory["selection"]["request"]["current"];
    ensure!(
        current.is_object() && *current == data["data_selection"]["current"],
        "memory/DATA current tuple crossed"
    );
    for k in ["observer", "fleet", "frame"] {
        ensure!(
            current[k] == tuple[k],
            "complete metadata tuple source crossed: {k}"
        );
        storage::member(current, k)?;
    }
    storage::member(current, "fleet_plan")?;
    ensure!(
        data["memory_selection"] == tuple["memory_selection"]
            || tuple.get("memory_selection").is_none(),
        "DATA parent memory binding"
    );
    Ok(current.clone())
}
pub fn directory_anchor(memory: &Value, current: &Value) -> Result<Value> {
    let request = &memory["selection"]["request"];
    let (census_bound, census) = storage::member(request, "census")?;
    let (reg_bound, reg) = storage::member(request, "registration")?;
    ensure!(
        census["current"] == *current
            && census["mutation_count"] == 0
            && census["source_custody_unchanged"] == true,
        "directory-anchor census is crossed or mutated"
    );
    ensure!(
        reg["census"]["program"] == census["program"],
        "directory-anchor qualified program crossed"
    );
    storage::member(&reg["census"], "qualification")?;
    storage::member(&reg, "census_scope_review")?;
    storage::member(&reg, "terminal_context")?;
    let rows = census["after"]["matching_processes"]
        .as_array()
        .context("retained process census")?;
    let controllers = rows
        .iter()
        .filter(|v| v["unit"] == CONTROLLER)
        .collect::<Vec<_>>();
    ensure!(
        controllers.len() == 1,
        "no unique original retained controller"
    );
    let controller = controllers[0];
    ensure!(
        controller["invocation_id"] == IID
            && controller["pid"] == 2467123
            && controller["start_ticks"] == 200799001
            && controller["role"] == "quarantined-original-controller",
        "original retained controller PID/start/IID replaced"
    );
    let findings = census["after"]["launcher_findings"]
        .as_array()
        .context("launcher census")?;
    let matches = findings
        .iter()
        .filter(|v| v["unit"] == CONTROLLER)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1
            && matches[0]["disposition"] == "quarantined-original-controller"
            && matches[0]["may_start_original_parent"] == false
            && matches[0]["current_invocation_id"] == IID,
        "original no-retry controller custody"
    );
    let (_, qualification) = storage::member(matches[0], "qualification")?;
    let native = &qualification["actual_native"];
    ensure!(
        native["Id"] == CONTROLLER
            && native["InvocationID"] == IID
            && native["MainPID"] == "2467123"
            && native["ActiveState"] == "active"
            && native["SubState"] == "running"
            && native["NRestarts"] == "0",
        "retained supported native directory-anchor lineage changed"
    );
    Ok(
        json!({"schema":"epoch185-retained-live-controller-directory-anchor-plan-v1","registration":reg_bound,
  "census":census_bound,"current":current,"controller_unit":CONTROLLER,"original_invocation_id":IID,
  "original_pid":2467123,"original_start_ticks":200799001,"controller_still_live_in_retained_lineage":true,
  "retained_directory_anchor":"/home/sol/.jetstreamer-private/epoch199-private-tail-20261017-v1/lane-a/private",
  "false_terminal_controller_requirement_removed":true,"future_gate":"Revalidate through supported qualified current directory-anchor census/selection at fresh admission; no need to stop controller, dropfd9, or create terminal closure.",
  "current_native_observation_performed":false,"resource_credit_bytes":0}),
    )
}
fn role_identity(image: &Bound, path: &str, sha: &str) -> Result<()> {
    ensure!(
        image.path.to_str() == Some(path) && image.sha256 == sha,
        "accounting/native185 role crossed"
    );
    Ok(())
}
pub fn role(image: &Bound, proof: &Bound, seal: &Bound, path: &str, sha: &str) -> Result<Value> {
    role_identity(image, path, sha)?;
    let artifact = storage::json(proof)?;
    let sealed = storage::json(seal)?;
    let directory = image.path.parent().context("image parent")?;
    ensure!(
        sealed["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && sealed["destination"].as_str() == directory.to_str(),
        "helper normal seal crossed"
    );
    let members = sealed["members"]
        .as_array()
        .context("normal seal members")?;
    ensure!(
        members
            .iter()
            .filter(|m| m["name"] == "jetstreamer-r2" && m["sha256"] == sha && m["mode"] == "0555")
            .count()
            == 1
            && members
                .iter()
                .filter(|m| m["name"] == "artifact-proof.json"
                    && m["sha256"] == proof.sha256
                    && m["mode"] == "0444")
                .count()
                == 1,
        "helper role/image/artifact mismatch"
    );
    Ok(
        json!({"image":image,"artifact_qualification":proof,"normal_seal":seal,"artifact_schema":artifact["schema"],
  "capture_cold185_startpre_task":path==NATIVE_PATH||path==DRIVER11_NATIVE_PATH,"image_body_rehash_pending_future_readiness":true}),
    )
}
pub fn retained_inputs(seal: &Value, restore: &Value) -> Result<()> {
    ensure!(
        restore["schema"] == "jetstreamer-bound-gcs-snapshot-restore-v1"
            && restore["snapshot_slot"] == 79919283
            && restore["generation"] == 1634788419305851u64
            && restore["remote_object"]["generation"] == restore["generation"]
            && restore["file"]["size"] == 7250303600u64
            && restore["file"]["sha256"]
                == "218173053f960ab1917adaae99b1680fdd75968d95f22aae6ffd41aef37f9ef2",
        "original local snapshot restore lineage crossed"
    );
    let members = seal["members"]
        .as_array()
        .context("cohesive input members")?;
    for (name, sha, mode) in [
        (
            "jetstreamer-node",
            "e987401354f0cddbd838b71439768d6ed84baddfe8c0c2b484addec553db1887",
            "0555",
        ),
        (
            "jetstreamer-historical-worker-v1-6-15",
            "6eef40863851927d0611fd90dd7c68528c8e1491a0fc18a28de492afa67316bd",
            "0555",
        ),
        (
            "genesis.tar.bz2",
            "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945",
            "0444",
        ),
        (
            "epoch-hashes-185.txt",
            "9ef0d882bf9b530abcd77f8aae199a0c2057c06b32a1d738c7443e3e431606fa",
            "0444",
        ),
        (
            "preflight-185-singleton-v4.json",
            "01f3be9f86ccf2a39284b0faf11b7910532c2348e2a0801ef1e50a77548d3dc3",
            "0444",
        ),
        (
            "snapshot-79919283-Hozk66F2tKQuhouHceuwU9xZzWaXksnBeU1JBysRBmmf.tar.zst",
            "218173053f960ab1917adaae99b1680fdd75968d95f22aae6ffd41aef37f9ef2",
            "0444",
        ),
    ] {
        ensure!(
            members
                .iter()
                .filter(|m| m["name"] == name && m["sha256"] == sha && m["mode"] == mode)
                .count()
                == 1,
            "retained cohesive input missing/crossed: {name}"
        );
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accounting_image_never_substitutes_for_native185_capture() {
        let accounting = Bound {
            path: ACCOUNTING_PATH.into(),
            sha256: ACCOUNTING_SHA.into(),
        };
        let native = Bound {
            path: NATIVE_PATH.into(),
            sha256: NATIVE_SHA.into(),
        };
        role_identity(&accounting, ACCOUNTING_PATH, ACCOUNTING_SHA).unwrap();
        role_identity(&native, NATIVE_PATH, NATIVE_SHA).unwrap();
        assert!(role_identity(&accounting, NATIVE_PATH, NATIVE_SHA).is_err());
        assert!(role_identity(&native, ACCOUNTING_PATH, ACCOUNTING_SHA).is_err());
        let crossed = Bound {
            path: NATIVE_PATH.into(),
            sha256: ACCOUNTING_SHA.into(),
        };
        assert!(role_identity(&crossed, NATIVE_PATH, NATIVE_SHA).is_err());
    }
}

#[cfg(test)] mod driver11_native_role_regression {
use super::*;
#[test] fn original_native11_and_current_helper32_roles_cannot_be_crossed() {
 let current=Bound{path:DRIVER11_NATIVE_PATH.into(),sha256:DRIVER11_NATIVE_SHA.into()};
 role_identity(&current,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).unwrap();
 let historical=Bound{path:NATIVE_PATH.into(),sha256:NATIVE_SHA.into()};
 role_identity(&historical,NATIVE_PATH,NATIVE_SHA).unwrap();
 assert!(role_identity(&historical,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).is_err());
 assert!(role_identity(&current,NATIVE_PATH,NATIVE_SHA).is_err());
 let crossed=Bound{path:DRIVER11_NATIVE_PATH.into(),sha256:NATIVE_SHA.into()};
 assert!(role_identity(&crossed,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).is_err());
}
}

#[cfg(test)] mod helper33_exact_native_role_regression {
 use super::*;
 #[test] fn helper33_native_role_rejects_old32_and_crossed_pairs() {
  let current=Bound{path:DRIVER11_NATIVE_PATH.into(),sha256:DRIVER11_NATIVE_SHA.into()};
  role_identity(&current,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).unwrap();
  let old=Bound{path:"/usr/local/lib/jetstreamer/horizon-epoch185-driver11-postreader-tools-20261108-v32/jetstreamer-r2".into(),sha256:"7d93abb0ff24e187f648d3ba06a1be544d39528b28f46776f818dc409df21925".into()};
  assert!(role_identity(&old,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).is_err());
  for crossed in [Bound{path:current.path.clone(),sha256:old.sha256.clone()},Bound{path:old.path,sha256:current.sha256}] {assert!(role_identity(&crossed,DRIVER11_NATIVE_PATH,DRIVER11_NATIVE_SHA).is_err());}
 }
}
