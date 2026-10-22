//! One separately qualified rejection-evidence attempt; old failure stays history.
use super::*;
const UNIT: &str = "horizon-epoch141-native-full-census-rejection-20261022-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-rejection-20261022-v1";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-rejection-candidate-20261022-v1/jetstreamer-epoch141-ledger-native";
const TOOL_SHA: &str = "573ce13e04f25972962c671b88c5afea8e5dd445e0e425c93816ca73b72fba42";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-rejection-plan-20261022-v1/plan.json";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-native141-rejection-admission-plan-20261022-v1/manifest.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-native141-admission-rejection-20261022-v1/admission.json";
const FAMILIES: [&str; 16] = [
    "address_signatures",
    "blocktime",
    "code_shred",
    "data_shred",
    "dead_slots",
    "default",
    "duplicate_slots",
    "erasure_meta",
    "index",
    "meta",
    "orphans",
    "perf_samples",
    "rewards",
    "root",
    "transaction_status",
    "transaction_status_index",
];
pub(super) fn namespace(c: &DiagnosticClaim) -> bool {
    c.epoch == 141 && c.unit == UNIT
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(ROOT)
            && c.launch_receipt.path == Path::new(ROOT).join("results/initial-guard.json")
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && r["schema"] == SCHEMA
            && r["epoch"] == 141
            && r["invocation_id"] == c.invocation_id
            && r["self_sha256"] == TOOL_SHA
            && r["minimum_free_bytes"] == FLOOR
            && r["available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= FLOOR + (32u64 << 30))
            && r["trip"] == false,
        "foreign native141 rejection attempt"
    );
    for key in ["plan_sha256", "admission_sha256"] {
        let s = r[key].as_str().context("missing rejection binding")?;
        ensure!(
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "noncanonical rejection binding"
        );
    }
    for flag in ["publication_authorized", "remote_mutations", "r2_mutations"] {
        ensure!(r[flag] == false, "rejection guard grants authority:{flag}");
    }
    Ok(())
}
fn bindings(p: &Value, a: &Value, m: &Value) -> Result<()> {
    ensure!(
        p["schema"] == "jetstreamer-epoch141-ledger-native-full-census-plan-v2"
            && p["unit"] == UNIT
            && p["minimum_free_bytes"] == FLOOR
            && p["maximum_runtime_seconds"] == 43200
            && p["database_directory"]
                == "/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1/retained"
            && p["expected_families"] == json!(FAMILIES)
            && p["collection_receipt"]["sha256"]
                == "569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937"
            && p["complete_census"]["sha256"]
                == "7dba362278d8cdd7689f053a6a5ef4d79623d9029b12320bed5bdfbc5b79668e"
            && p["source_verification"]["sha256"]
                == "93228cf8caaae18d07c501c9a0430773239af05da0047f1129c670bbe4fe0e2a"
            && p["gap_audit"]["sha256"]
                == "11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"
            && p["finalized_collection_receipt"]["sha256"]
                == "21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4"
            && p["finalized_collection_plan"]["sha256"]
                == "fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc"
            && p["admission_manifest"]["path"] == MANIFEST
            && p["admission_receipt"] == ADMISSION
            && p["log_directory"] == format!("{ROOT}/logs")
            && p["initial_guard_receipt"] == format!("{ROOT}/results/initial-guard.json")
            && p["metadata_receipt"] == format!("{ROOT}/results/intent.json")
            && p["output_receipt"] == format!("{ROOT}/results/candidates.json"),
        "native141 rejection plan differs"
    );
    ensure!(
        m["schema"] == "jetstreamer-historical-performance-admission-v1"
            && m["native_profile"] == "epoch141-read-only-full-census-rejection-v3"
            && m["filesystem"] == "/home/sol"
            && m["native_unit"] == UNIT
            && m["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= FLOOR + (32u64 << 30))
            && m["minimum_memory_available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 144u64 << 30)
            && m["files"] == json!([{"path":TOOL,"sha256":TOOL_SHA,"uid":0,"gid":0,"mode":"0555"}]),
        "native141 rejection manifest differs"
    );
    ensure!(
        a["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && a["native_profile"] == m["native_profile"]
            && a["native_unit"] == UNIT
            && a["manifest"] == MANIFEST
            && a["manifest_sha256"] == p["admission_manifest"]["sha256"]
            && a["admitted"] == true
            && a["evidence"]["filesystem"] == "/home/sol"
            && a["evidence"]["files"] == m["files"]
            && a["evidence"]["minimum_free_bytes"] == m["minimum_free_bytes"],
        "native141 rejection admission differs"
    );
    for flag in [
        "services_started",
        "services_installed",
        "native_database_opened",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            a[flag] == false,
            "rejection admission grants authority:{flag}"
        );
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let p = bound_json(&BoundFile {
        path: PLAN.into(),
        sha256: r["plan_sha256"].as_str().unwrap().into(),
    })?;
    let a = bound_json(&BoundFile {
        path: ADMISSION.into(),
        sha256: r["admission_sha256"].as_str().unwrap().into(),
    })?;
    let m = bound_json(&BoundFile {
        path: MANIFEST.into(),
        sha256: p["admission_manifest"]["sha256"]
            .as_str()
            .context("manifest digest")?
            .into(),
    })?;
    bindings(&p, &a, &m)
}
fn expected_command(r: &Value) -> String {
    format!(
        "{{ path={TOOL} ; argv[]={TOOL} --plan {PLAN} --plan-sha256 {} --self-sha256 {TOOL_SHA} --admission-sha256 {}",
        r["plan_sha256"].as_str().unwrap(),
        r["admission_sha256"].as_str().unwrap()
    )
}
fn live(c: &DiagnosticClaim, r: &Value, v: &Value) -> Result<()> {
    shape(r, c)?;
    ensure!(
        v["Id"] == UNIT
            && v["InvocationID"] == c.invocation_id
            && v["LoadState"] == "loaded"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["NRestarts"] == "0"
            && v["Type"] == "exec"
            && v["MainPID"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|p| p > 0)
            && command(&v["ExecStart"]) == Some(expected_command(r).as_str()),
        "native141 rejection live identity differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    let r = bound_json(&c.launch_receipt)?;
    launch(&r, c)?;
    live(c, &r, v)?;
    let output=ProcessCommand::new("systemctl").args(["show",UNIT,"--no-pager","--property=Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,User,Group"]).output()?;
    ensure!(output.status.success(), "rejection sandbox read failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let properties: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    ensure!(
        properties.get("ReadWritePaths") == Some(&format!("{ROOT}/logs {ROOT}/results").as_str()),
        "rejection writable paths differ"
    );
    common_limits(&properties)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (DiagnosticClaim, Value, Value, Value, Value) {
        let claim = DiagnosticClaim {
            epoch: 141,
            unit: UNIT.into(),
            invocation_id: "a".repeat(32),
            scratch_path: ROOT.into(),
            launch_receipt: BoundFile {
                path: Path::new(ROOT).join("results/initial-guard.json"),
                sha256: "b".repeat(64),
            },
        };
        let r = json!({"schema":SCHEMA,"epoch":141,"invocation_id":claim.invocation_id,
            "self_sha256":TOOL_SHA,"plan_sha256":"c".repeat(64),"admission_sha256":"d".repeat(64),
            "minimum_free_bytes":FLOOR,"available_bytes":FLOOR+(32u64<<30),"trip":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        let p = json!({"schema":"jetstreamer-epoch141-ledger-native-full-census-plan-v2",
            "unit":UNIT,"minimum_free_bytes":FLOOR,"maximum_runtime_seconds":43200,
            "database_directory":"/home/sol/.jetstreamer-private/epoch141-ledger-retention-20261020-v1/retained",
            "expected_families":FAMILIES,
            "collection_receipt":{"sha256":"569df15e8ce87beca8df0a800c85e616aaf252baeb365a7c92f35b8b39b4e937"},
            "complete_census":{"sha256":"7dba362278d8cdd7689f053a6a5ef4d79623d9029b12320bed5bdfbc5b79668e"},
            "source_verification":{"sha256":"93228cf8caaae18d07c501c9a0430773239af05da0047f1129c670bbe4fe0e2a"},
            "gap_audit":{"sha256":"11a6049bc9378b4e3e063e765ce2b908b621f5d7845a49d372aca509d6d37a9f"},
            "finalized_collection_receipt":{"sha256":"21427d5debbc22ab44c337fb32679620ec663f44c52c5ceeb7100fcb450f8fe4"},
            "finalized_collection_plan":{"sha256":"fc320b12c2a53c95f6781ed9130a57e179078ce09b654f96b79c675a96fdf5cc"},
            "admission_manifest":{"path":MANIFEST,"sha256":"e".repeat(64)},"admission_receipt":ADMISSION,
            "log_directory":format!("{ROOT}/logs"),"initial_guard_receipt":format!("{ROOT}/results/initial-guard.json"),
            "metadata_receipt":format!("{ROOT}/results/intent.json"),"output_receipt":format!("{ROOT}/results/candidates.json")});
        let m = json!({"schema":"jetstreamer-historical-performance-admission-v1",
            "native_profile":"epoch141-read-only-full-census-rejection-v3","filesystem":"/home/sol",
            "native_unit":UNIT,"minimum_free_bytes":FLOOR+(32u64<<30),"minimum_memory_available_bytes":144u64<<30,
            "files":[{"path":TOOL,"sha256":TOOL_SHA,"uid":0,"gid":0,"mode":"0555"}]});
        let a = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1",
            "native_profile":m["native_profile"],"native_unit":UNIT,"manifest":MANIFEST,
            "manifest_sha256":p["admission_manifest"]["sha256"],"admitted":true,
            "evidence":{"filesystem":"/home/sol","files":m["files"],"minimum_free_bytes":m["minimum_free_bytes"]},
            "services_started":false,"services_installed":false,"native_database_opened":false,
            "replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
        (claim, r, p, a, m)
    }
    #[test]
    fn guarded_new_attempt_cannot_alias_original_or_another_invocation() {
        let (c, r, ..) = fixture();
        shape(&r, &c).unwrap();
        for key in r.as_object().unwrap().keys() {
            let mut bad = r.clone();
            bad[key] = Value::Null;
            assert!(shape(&bad, &c).is_err(), "accepted missing {key}");
        }
        for which in 0..5 {
            let (mut c, r, ..) = fixture();
            match which {
                0 => c.epoch = 144,
                1 => c.unit = super::super::UNIT.into(),
                2 => c.invocation_id = "f".repeat(32),
                3 => c.scratch_path = "/private/other".into(),
                _ => c.launch_receipt.path = "/private/other.json".into(),
            }
            assert!(shape(&r, &c).is_err());
        }
    }
    #[test]
    fn source_census_profile_files_resources_and_no_authority_remain_exact() {
        let (_, _, p, a, m) = fixture();
        bindings(&p, &a, &m).unwrap();
        for (which, good) in [&p, &a, &m].into_iter().enumerate() {
            for key in good.as_object().unwrap().keys() {
                let mut bad = good.clone();
                bad[key] = Value::Null;
                let result = match which {
                    0 => bindings(&bad, &a, &m),
                    1 => bindings(&p, &bad, &m),
                    _ => bindings(&p, &a, &bad),
                };
                assert!(result.is_err(), "accepted missing binding {which}/{key}");
            }
        }
        let mut bad = p.clone();
        bad["expected_families"][0] = "other".into();
        assert!(bindings(&bad, &a, &m).is_err());
        let mut bad = m.clone();
        bad["minimum_memory_available_bytes"] = ((144u64 << 30) - 1).into();
        assert!(bindings(&p, &a, &bad).is_err());
    }
    #[test]
    fn new_attempt_live_command_cannot_expand_scope_or_change_identity() {
        let (c, r, ..) = fixture();
        let v = json!({"Id":UNIT,"InvocationID":c.invocation_id,"LoadState":"loaded",
            "ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","MainPID":"123",
            "ExecStart":format!("{} ; ignore_errors=no ; start_time=[now] }}",expected_command(&r))});
        live(&c, &r, &v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(live(&c, &r, &bad).is_err(), "accepted missing {key}");
        }
        let mut bad = v.clone();
        bad["ExecStart"] = format!("{} --extra ; ignore_errors=no", expected_command(&r)).into();
        assert!(live(&c, &r, &bad).is_err());
    }
}
