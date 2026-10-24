//! Exact bounded raw acquisition profiles; earlier attempts remain history.
use super::*;
const UNIT: &str = "horizon-epoch141-native-full-census-acquisition-first-20261022-v1.service";
const ROOT: &str = "/home/sol/.jetstreamer-private/epoch141-native-acquisition-first-20261022-v1";
const TOOL: &str = "/usr/local/lib/jetstreamer/horizon-epoch141-native-acquisition-candidate-20261022-v1/jetstreamer-epoch141-ledger-native";
const TOOL_SHA: &str = "0e7f847b520a91ba033f97181023ea20f9c833653744715c9e3448fbd4de088b";
const PLAN: &str =
    "/usr/local/lib/jetstreamer/horizon-native141-acquisition-plan-20261022-v2/plan.json";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-native141-acquisition-admission-plan-20261022-v2/manifest.json";
const ADMISSION: &str =
    "/var/lib/jetstreamer/horizon-native141-admission-acquisition-20261022-v1/admission.json";
struct Profile {
    unit: &'static str,
    root: &'static str,
    tool: &'static str,
    tool_sha: &'static str,
    plan: &'static str,
    manifest: &'static str,
    admission: &'static str,
    schema: &'static str,
    admission_profile: &'static str,
    output_name: &'static str,
    guard_reservation: u64,
    admission_reservation: u64,
}
const FIRST: Profile = Profile {
    unit: UNIT,
    root: ROOT,
    tool: TOOL,
    tool_sha: TOOL_SHA,
    plan: PLAN,
    manifest: MANIFEST,
    admission: ADMISSION,
    schema: "jetstreamer-epoch141-ledger-native-first-target-acquisition-plan-v1",
    admission_profile: "epoch141-read-only-first-target-acquisition-v4",
    output_name: "first-target-acquisition.json",
    guard_reservation: 256u64 << 20,
    admission_reservation: 1u64 << 30,
};
const ALL: Profile = Profile {
    unit: "horizon-epoch141-native-full-census-acquisition-all-20261022-v1.service",
    root: "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v1",
    tool: "/usr/local/lib/jetstreamer/horizon-epoch141-native-all-acquisition-candidate-20261022-v1/jetstreamer-epoch141-ledger-native",
    tool_sha: "ccf620b21f3c75cde3e9c22df058b0f3e4cefac9f7ae52c533f44bde38d757ec",
    plan: "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-plan-20261022-v1/plan.json",
    manifest: "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-admission-plan-20261022-v1/manifest.json",
    admission: "/var/lib/jetstreamer/horizon-native141-admission-all-acquisition-20261022-v1/admission.json",
    schema: "jetstreamer-epoch141-ledger-native-all-target-acquisition-plan-v2",
    admission_profile: "epoch141-read-only-all-target-acquisition-v5",
    output_name: "all-target-acquisition.json",
    guard_reservation: 32u64 << 30,
    admission_reservation: 32u64 << 30,
};
const ALL_RETRY: Profile = Profile {
    unit: "horizon-epoch141-native-full-census-acquisition-all-20261022-v2.service",
    root: "/home/sol/.jetstreamer-private/epoch141-native-acquisition-all-20261022-v2",
    tool: "/usr/local/lib/jetstreamer/horizon-epoch141-native-all-acquisition-candidate-20261022-v2/jetstreamer-epoch141-ledger-native",
    tool_sha: "153a0d1302369f7ff1272d8b62ca9e777d4d1e3bd5a172e5edec5fe3ad28c295",
    plan: "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-plan-20261022-v2/plan.json",
    manifest: "/usr/local/lib/jetstreamer/horizon-native141-all-acquisition-admission-plan-20261022-v2/manifest.json",
    admission: "/var/lib/jetstreamer/horizon-native141-admission-all-acquisition-20261022-v2/admission.json",
    ..ALL
};
fn profile(unit: &str) -> Result<&'static Profile> {
    match unit {
        UNIT => Ok(&FIRST),
        u if u == ALL.unit => Ok(&ALL),
        u if u == ALL_RETRY.unit => Ok(&ALL_RETRY),
        _ => anyhow::bail!("unknown native 141 acquisition owner"),
    }
}
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
    c.epoch == 141 && profile(&c.unit).is_ok()
}
fn shape(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    let profile = profile(&c.unit)?;
    let root = profile.root;
    ensure!(
        namespace(c)
            && c.scratch_path == Path::new(root)
            && c.launch_receipt.path == Path::new(root).join("results/initial-guard.json")
            && c.invocation_id.len() == 32
            && c.invocation_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && r["schema"] == SCHEMA
            && r["epoch"] == 141
            && r["invocation_id"] == c.invocation_id
            && r["self_sha256"] == profile.tool_sha
            && r["minimum_free_bytes"] == FLOOR
            && r["available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= FLOOR + profile.guard_reservation)
            && r["trip"] == false,
        "foreign native 141 acquisition attempt"
    );
    for key in ["plan_sha256", "admission_sha256"] {
        let s = r[key].as_str().context("missing acquisition binding")?;
        ensure!(
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "noncanonical acquisition binding"
        );
    }
    for flag in ["publication_authorized", "remote_mutations", "r2_mutations"] {
        ensure!(
            r[flag] == false,
            "acquisition guard grants authority:{flag}"
        );
    }
    Ok(())
}
fn bindings(p: &Value, a: &Value, m: &Value) -> Result<()> {
    let profile = profile(p["unit"].as_str().context("missing acquisition unit")?)?;
    let root = profile.root;
    ensure!(
        p["schema"] == profile.schema
            && p["unit"] == profile.unit
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
            && p["admission_manifest"]["path"] == profile.manifest
            && p["admission_receipt"] == profile.admission
            && p["log_directory"] == format!("{root}/logs")
            && p["initial_guard_receipt"] == format!("{root}/results/initial-guard.json")
            && p["metadata_receipt"] == format!("{root}/results/intent.json")
            && p["output_receipt"] == format!("{root}/results/{}", profile.output_name),
        "native 141 acquisition plan differs"
    );
    ensure!(
        m["schema"] == "jetstreamer-historical-performance-admission-v1"
            && m["native_profile"] == profile.admission_profile
            && m["filesystem"] == "/home/sol"
            && m["native_unit"] == profile.unit
            && m["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|v| v >= FLOOR + profile.admission_reservation)
            && m["minimum_memory_available_bytes"]
                .as_u64()
                .is_some_and(|v| v >= 144u64 << 30)
            && m["files"]
                == json!([{"path":profile.tool,"sha256":profile.tool_sha,"uid":0,"gid":0,"mode":"0555"}]),
        "native 141 acquisition manifest differs"
    );
    ensure!(
        a["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && a["native_profile"] == m["native_profile"]
            && a["native_unit"] == profile.unit
            && a["manifest"] == profile.manifest
            && a["manifest_sha256"] == p["admission_manifest"]["sha256"]
            && a["admitted"] == true
            && a["evidence"]["filesystem"] == "/home/sol"
            && a["evidence"]["files"] == m["files"]
            && a["evidence"]["minimum_free_bytes"] == m["minimum_free_bytes"],
        "native 141 acquisition admission differs"
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
            "acquisition admission grants authority:{flag}"
        );
    }
    Ok(())
}
pub(super) fn launch(r: &Value, c: &DiagnosticClaim) -> Result<()> {
    shape(r, c)?;
    let profile = profile(&c.unit)?;
    let p = bound_json(&BoundFile {
        path: profile.plan.into(),
        sha256: r["plan_sha256"].as_str().unwrap().into(),
    })?;
    let a = bound_json(&BoundFile {
        path: profile.admission.into(),
        sha256: r["admission_sha256"].as_str().unwrap().into(),
    })?;
    let m = bound_json(&BoundFile {
        path: profile.manifest.into(),
        sha256: p["admission_manifest"]["sha256"]
            .as_str()
            .context("manifest digest")?
            .into(),
    })?;
    ensure!(
        p["unit"] == c.unit,
        "acquisition plan belongs to another owner"
    );
    bindings(&p, &a, &m)
}
fn expected_command(r: &Value, profile: &Profile) -> String {
    let (tool, plan, tool_sha) = (profile.tool, profile.plan, profile.tool_sha);
    format!(
        "{{ path={tool} ; argv[]={tool} --plan {plan} --plan-sha256 {} --self-sha256 {tool_sha} --admission-sha256 {}",
        r["plan_sha256"].as_str().unwrap(),
        r["admission_sha256"].as_str().unwrap()
    )
}
fn live(c: &DiagnosticClaim, r: &Value, v: &Value) -> Result<()> {
    shape(r, c)?;
    let profile = profile(&c.unit)?;
    ensure!(
        v["Id"] == profile.unit
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
            && command(&v["ExecStart"]) == Some(expected_command(r, profile).as_str()),
        "native 141 acquisition live identity differs"
    );
    Ok(())
}
pub(super) fn validate_live(c: &DiagnosticClaim, v: &Value) -> Result<()> {
    let profile = profile(&c.unit)?;
    let root = profile.root;
    let r = bound_json(&c.launch_receipt)?;
    launch(&r, c)?;
    live(c, &r, v)?;
    let output=ProcessCommand::new("systemctl").args(["show",profile.unit,"--no-pager","--property=Type,Restart,KillMode,Delegate,RuntimeMaxUSec,CPUQuotaPerSecUSec,MemoryHigh,MemoryMax,MemorySwapMax,TasksMax,UMask,ProtectSystem,ProtectHome,PrivateNetwork,PrivateTmp,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,ReadWritePaths,User,Group,DynamicUser"]).output()?;
    ensure!(output.status.success(), "acquisition sandbox read failed");
    let text = std::str::from_utf8(&output.stdout)?;
    let properties: BTreeMap<_, _> = text.lines().filter_map(|s| s.split_once('=')).collect();
    ensure!(
        properties.get("DynamicUser") == Some(&"no"),
        "acquisition requires non-dynamic root"
    );
    ensure!(
        properties.get("ReadWritePaths") == Some(&format!("{root}/logs {root}/results").as_str()),
        "acquisition writable paths differ"
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
        let p = json!({"schema":"jetstreamer-epoch141-ledger-native-first-target-acquisition-plan-v1",
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
            "metadata_receipt":format!("{ROOT}/results/intent.json"),"output_receipt":format!("{ROOT}/results/first-target-acquisition.json")});
        let m = json!({"schema":"jetstreamer-historical-performance-admission-v1",
            "native_profile":"epoch141-read-only-first-target-acquisition-v4","filesystem":"/home/sol",
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
        let mut old = p.clone();
        old["schema"] = json!("jetstreamer-epoch141-ledger-native-full-census-plan-v2");
        assert!(bindings(&old, &a, &m).is_err());
        let mut old = m.clone();
        old["native_profile"] = json!("epoch141-read-only-full-census-rejection-v3");
        assert!(bindings(&p, &a, &old).is_err());
    }
    #[test]
    fn new_attempt_live_command_cannot_expand_scope_or_change_identity() {
        let (c, r, ..) = fixture();
        let v = json!({"Id":UNIT,"InvocationID":c.invocation_id,"LoadState":"loaded",
            "ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","MainPID":"123",
            "ExecStart":format!("{} ; ignore_errors=no ; start_time=[now] }}",expected_command(&r, &FIRST))});
        live(&c, &r, &v).unwrap();
        for key in v.as_object().unwrap().keys() {
            let mut bad = v.clone();
            bad[key] = Value::Null;
            assert!(live(&c, &r, &bad).is_err(), "accepted missing {key}");
        }
        let mut bad = v.clone();
        bad["ExecStart"] = format!(
            "{} --extra ; ignore_errors=no",
            expected_command(&r, &FIRST)
        )
        .into();
        assert!(live(&c, &r, &bad).is_err());
    }
    #[test]
    fn first_target_guard_and_admission_have_distinct_bounded_output_reservations() {
        let (c, mut r, p, mut a, mut m) = fixture();
        r["available_bytes"] = json!(FLOOR + (256u64 << 20));
        shape(&r, &c).unwrap();
        r["available_bytes"] = json!(FLOOR + (256u64 << 20) - 1);
        assert!(shape(&r, &c).is_err());
        m["minimum_free_bytes"] = json!(FLOOR + (1u64 << 30));
        a["evidence"]["minimum_free_bytes"] = m["minimum_free_bytes"].clone();
        bindings(&p, &a, &m).unwrap();
        m["minimum_free_bytes"] = json!(FLOOR + (1u64 << 30) - 1);
        a["evidence"]["minimum_free_bytes"] = m["minimum_free_bytes"].clone();
        assert!(bindings(&p, &a, &m).is_err());
    }
    fn all_fixture() -> (DiagnosticClaim, Value, Value, Value, Value) {
        let (mut c, mut r, mut p, mut a, mut m) = fixture();
        c.unit = ALL.unit.into();
        c.scratch_path = ALL.root.into();
        c.launch_receipt.path = Path::new(ALL.root).join("results/initial-guard.json");
        r["self_sha256"] = json!(ALL.tool_sha);
        p["schema"] = json!(ALL.schema);
        p["unit"] = json!(ALL.unit);
        p["admission_manifest"]["path"] = json!(ALL.manifest);
        p["admission_receipt"] = json!(ALL.admission);
        p["log_directory"] = json!(format!("{}/logs", ALL.root));
        p["initial_guard_receipt"] = json!(c.launch_receipt.path);
        p["metadata_receipt"] = json!(format!("{}/results/intent.json", ALL.root));
        p["output_receipt"] = json!(format!("{}/results/{}", ALL.root, ALL.output_name));
        m["native_profile"] = json!(ALL.admission_profile);
        m["native_unit"] = json!(ALL.unit);
        m["files"] = json!([{"path":ALL.tool,"sha256":ALL.tool_sha,"uid":0,"gid":0,"mode":"0555"}]);
        a["native_profile"] = m["native_profile"].clone();
        a["native_unit"] = m["native_unit"].clone();
        a["manifest"] = json!(ALL.manifest);
        a["evidence"]["files"] = m["files"].clone();
        (c, r, p, a, m)
    }
    #[test]
    fn all_target_profile_requires_its_exact_sources_owner_and_full_reservation() {
        let (c, mut r, p, mut a, mut m) = all_fixture();
        assert!(namespace(&c));
        shape(&r, &c).unwrap();
        bindings(&p, &a, &m).unwrap();
        r["available_bytes"] = json!(FLOOR + ALL.guard_reservation - 1);
        assert!(shape(&r, &c).is_err());
        m["minimum_free_bytes"] = json!(FLOOR + FIRST.admission_reservation);
        a["evidence"]["minimum_free_bytes"] = m["minimum_free_bytes"].clone();
        assert!(bindings(&p, &a, &m).is_err());
        let (_, _, first_p, first_a, first_m) = fixture();
        assert!(bindings(&p, &first_a, &first_m).is_err());
        assert!(bindings(&first_p, &a, &m).is_err());
        let (_, r, ..) = all_fixture();
        let (first_c, first_r, ..) = fixture();
        assert!(shape(&r, &first_c).is_err());
        assert!(shape(&first_r, &c).is_err());
        for key in p.as_object().unwrap().keys() {
            let mut bad = p.clone();
            bad[key] = Value::Null;
            let (_, _, _, a, m) = all_fixture();
            assert!(bindings(&bad, &a, &m).is_err(), "missing all-target {key}");
        }
    }
    #[test]
    fn all_target_live_command_cannot_alias_first_target_or_expand_scope() {
        let (c, r, ..) = all_fixture();
        let v = json!({"Id":ALL.unit,"InvocationID":c.invocation_id,"LoadState":"loaded",
            "ActiveState":"active","SubState":"running","NRestarts":"0","Type":"exec","MainPID":"123",
            "ExecStart":format!("{} ; ignore_errors=no }}", expected_command(&r, &ALL))});
        live(&c, &r, &v).unwrap();
        for command in [
            expected_command(&r, &FIRST),
            format!("{} --extra", expected_command(&r, &ALL)),
        ] {
            let mut bad = v.clone();
            bad["ExecStart"] = json!(format!("{command} ; ignore_errors=no }}"));
            assert!(live(&c, &r, &bad).is_err());
        }
        let mut unknown = c;
        unknown.unit = "horizon-epoch141-native-full-census-acquisition-all-foreign.service".into();
        assert!(!namespace(&unknown));
        assert!(shape(&r, &unknown).is_err());
    }
    #[test]
    fn corrected_retry_cannot_alias_failed_all_target_owner_or_its_evidence() {
        let (mut c, mut r, mut p, mut a, mut m) = all_fixture();
        c.unit = ALL_RETRY.unit.into();
        c.scratch_path = ALL_RETRY.root.into();
        c.launch_receipt.path = Path::new(ALL_RETRY.root).join("results/initial-guard.json");
        r["self_sha256"] = json!(ALL_RETRY.tool_sha);
        p["unit"] = json!(ALL_RETRY.unit);
        p["admission_manifest"]["path"] = json!(ALL_RETRY.manifest);
        p["admission_receipt"] = json!(ALL_RETRY.admission);
        p["log_directory"] = json!(format!("{}/logs", ALL_RETRY.root));
        p["initial_guard_receipt"] = json!(c.launch_receipt.path);
        p["metadata_receipt"] = json!(format!("{}/results/intent.json", ALL_RETRY.root));
        p["output_receipt"] = json!(format!(
            "{}/results/{}",
            ALL_RETRY.root, ALL_RETRY.output_name
        ));
        m["native_unit"] = json!(ALL_RETRY.unit);
        m["files"] = json!([{"path":ALL_RETRY.tool,"sha256":ALL_RETRY.tool_sha,"uid":0,"gid":0,"mode":"0555"}]);
        a["native_unit"] = m["native_unit"].clone();
        a["manifest"] = json!(ALL_RETRY.manifest);
        a["evidence"]["files"] = m["files"].clone();
        shape(&r, &c).unwrap();
        bindings(&p, &a, &m).unwrap();
        let (old, old_r, old_p, old_a, old_m) = all_fixture();
        assert!(shape(&old_r, &c).is_err());
        assert!(shape(&r, &old).is_err());
        assert!(bindings(&p, &old_a, &old_m).is_err());
        assert!(bindings(&old_p, &a, &m).is_err());
        assert_ne!(expected_command(&r, &ALL_RETRY), expected_command(&r, &ALL));
        assert_eq!(ALL_RETRY.guard_reservation, 32u64 << 30);
        assert_eq!(ALL_RETRY.admission_reservation, 32u64 << 30);
    }
}
