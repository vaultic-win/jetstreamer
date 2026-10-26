//! Metadata-only adapter for the genuine two-segment epoch204 assembly.
//! This is preparation, never admission or an alternate payload executor.
use super::*;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    artifact: BoundFile,
    qualification: BoundFile,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preparation {
    schema: String,
    recipe: lineage::Recipe,
    full: Tool,
    plugin: Tool,
    anchor: Tool,
    upload: Tool,
    full_capacity: BoundFile,
    plugin_capacity: BoundFile,
    output: PathBuf,
}

// The generic verifier probe has four producer fields. For this distinct typed
// origin their meaning is explicit: actual assembler ELF, genuine runtime worker,
// recovery plan, and independently derived V4 provenance, respectively. No209
// preflight or synthetic normal-producer manifest can stand in for these inputs.
fn producer(recipe: &lineage::Recipe, plan: &Value, digest: &str) -> Result<Value> {
    ensure!(
        is_lower_hex(s(plan, "executable_sha256")?, 64)
            && is_lower_hex(&recipe.recovery_plan.sha256, 64)
            && is_lower_hex(digest, 64),
        "204 delivery producer identity is incomplete"
    );
    Ok(
        json!({"node_sha256":plan["executable_sha256"],"worker_sha256":WORKER,
        "manifest_sha256":recipe.recovery_plan.sha256,
        "manifest_fingerprint":format!("sha256:{digest}")}),
    )
}
fn full_capacity(v: &Value, tool: &Tool, expected: &Value, qa: &Value) -> Result<u64> {
    let decoded = n(&v["probe"], "decoded_records")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-verifier-capacity-probe-v1"
            && v["verifier_path"] == serde_json::to_value(&tool.artifact.path)?
            && v["verifier_sha256"] == tool.artifact.sha256
            && v["source_commit"] == qa["source_revision"]
            && v["producer"] == *expected
            && v["probe"]["phase"] == "pre-account-updates"
            && v["probe"]["result"] == "pass"
            && n(&v["probe"], "old_inline_limit")? > 0
            && decoded > n(&v["probe"], "old_inline_limit")?,
        "204 delivery full capacity has foreign producer/tool/source or insufficient decode"
    );
    for key in [
        "production_archive_reread_authorized",
        "replay_launch_authorized",
        "publication_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        ensure!(
            v["authority"][key] == false,
            "204 capacity borrowed authority: {key}"
        );
    }
    Ok(decoded)
}
fn plugin_capacity(v: &Value, required: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-plugin-capacity-probe-v1"
            && n(v, "maximum_pre_updates")? >= required
            && n(v, "account_data_bytes")? > 0
            && n(v, "maximum_pre_update_data_bytes")? >= n(v, "account_data_bytes")?,
        "204 delivery plugin capacity does not cover full probe"
    );
    Ok(())
}
fn plugin_probe(binding: &BoundFile, tool: &Tool, required: u64) -> Result<Value> {
    let child = read(binding)?;
    resource_verify::validate_bound_child(
        &child,
        &tool.artifact.path,
        &tool.artifact.sha256,
        &["--archive-capacity-probe".into()],
    )?;
    let log = BoundFile {
        path: s(&child, "log")?.into(),
        sha256: s(&child, "log_sha256")?.into(),
    };
    let raw = sealed(&log, 32 << 20)?;
    let text = std::str::from_utf8(&raw)?;
    let rows = text
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == 1, "204 plugin capacity output is ambiguous");
    plugin_capacity(&rows[0], required)?;
    Ok(json!({"bound_child":binding,"log":log,"result":rows[0]}))
}
fn contracts(expected: &lineage::Expected) -> Result<Value> {
    let full = downstream::full_arguments(
        Path::new("ADMITTED_PRIVATE_SCAN_DIRECTORY/epoch-204.jet"),
        "ACTUAL_203_TERMINAL_SLOT".into(),
        "ACTUAL_203_TERMINAL_HASH".into(),
        expected,
    )?;
    Ok(json!({
        "full":{
            "unit":downstream::Stage::Full.unit(),
            "source":OUTPUT,"source_root_uid":0,"source_mode":"0400",
            "anchor_epoch":203,"anchor_archive":"/home/ubuntu/horizon/epoch-203.jet",
            "anchor_requires_authenticated_ready_receipt":true,
            "anchor_terminal_must_be_derived_by_qualified_decoder":true,
            "non_executable_argv_template":full,
            "expected_provenance_is_independent_of_target":true
        },
        "plugin":{"unit":downstream::Stage::Plugin.unit(),"requires":["genuine_full_outcome","genuine_full_pid1_terminal"],
            "non_executable_argv_template":["204:204","ADMITTED_PRIVATE_SCAN_DIRECTORY","--threads","8","--verify-only"]},
        "import":{"unit":downstream::Stage::Import.unit(),"requires":["full","current_plugin","shared_local_mutation_lease","no_clobber_canonical_pair"]},
        "upload":{"unit":downstream::Stage::Upload.unit(),"requires":["full","current_plugin","import","shared_local_mutation_lease"],
            "sidecar_after_whole_object_readback_and_source_revalidation":true},
        "retirement":{"requires_adjacent_boundaries":[203,205],"authorized":false},
        "startup":{"implemented_by_this_preparation":false,"execution_authorized":false,
            "requires":["fresh_complete_fleet_and_resource_admission","exact_root204_waiting_pid_ticks_iid_cgroup_native_caps",
                "bound_root204_startup_plan","first_genuine_independent_guard_fire","exact_recurring_guard_timer",
                "immutable_fresh_no_clobber_release","final_freshness_check_after_last_manager_call",
                "no_archive_payload_access_before_release","same_process_identity_after_release"]}
    }))
}
pub(super) fn prepare(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let p: Preparation = serde_json::from_value(v.clone())?;
    ensure!(
        p.schema == "jetstreamer-epoch204-delivery-preparation-spec-v1",
        "204 delivery preparation schema differs"
    );
    // This loader reads authenticated metadata only. In particular it never
    // opens the assembled target or treats its contents as its expectation.
    let loaded = lineage::load_recipe(p.recipe.clone())?;
    let plan = read(&p.recipe.recovery_plan)?;
    let identity = producer(&p.recipe, &plan, &loaded.expected.digest)?;
    for (role, tool) in [
        ("full", &p.full),
        ("plugin", &p.plugin),
        ("boundary", &p.anchor),
        ("upload", &p.upload),
    ] {
        downstream::qualified_tool(role, &tool.artifact, &tool.qualification)?;
    }
    let probe = read(&p.full_capacity)?;
    let decoded = full_capacity(&probe, &p.full, &identity, &read(&p.full.qualification)?)?;
    let plugin = plugin_probe(&p.plugin_capacity, &p.plugin, decoded)?;
    write(
        &p.output,
        &json!({
            "schema":"jetstreamer-epoch204-delivery-preparation-v1","epoch":204,"kind":"AssemblyRecovery204",
            "recipe":p.recipe,"producer_capacity_identity":identity,
            "producer_identity_semantics":{"node_sha256":"actual_assembly_helper","worker_sha256":"both_native_runtime_segments",
                "manifest_sha256":"genuine_recovery_plan","manifest_fingerprint":"independently_derived_v4_provenance"},
            "expected_lineage":loaded.expected.document,"archive_sha256_from_outcome":loaded.outcome["archive_sha256"],
            "archive_bytes_from_outcome":loaded.outcome["archive_bytes"],
            "tools":{"full":p.full,"plugin":p.plugin,"anchor":p.anchor,"upload":p.upload},
            "full_capacity":p.full_capacity,"plugin_capacity":plugin,"contracts":contracts(&loaded.expected)?,
            "source_archive_body_reads":0,"output_body_reads":0,"issuer":issuer(spec,self_sha),
            "runtime_admission":false,"startup_release_issued":false,"authority":denied()
        }),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed204_capacity_rejects_singleton209_and_changed_dual_lineage_identity() {
        let tool = Tool {
            artifact: BoundFile {
                path: "/sealed/full".into(),
                sha256: "a".repeat(64),
            },
            qualification: BoundFile {
                path: "/sealed/qa".into(),
                sha256: "b".repeat(64),
            },
        };
        let qa = json!({"source_revision":"c".repeat(40)});
        let expected = json!({"node_sha256":"d".repeat(64),"worker_sha256":WORKER,
            "manifest_sha256":OLD_PLAN,"manifest_fingerprint":format!("sha256:{}","e".repeat(64))});
        let good = json!({"schema":"jetstreamer-horizon-verifier-capacity-probe-v1","verifier_path":tool.artifact.path,
            "verifier_sha256":tool.artifact.sha256,"source_commit":qa["source_revision"],"producer":expected,
            "probe":{"decoded_records":131073,"old_inline_limit":131072,"phase":"pre-account-updates","result":"pass"},
            "authority":{"production_archive_reread_authorized":false,"replay_launch_authorized":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}});
        assert_eq!(full_capacity(&good, &tool, &expected, &qa).unwrap(), 131073);
        for pointer in [
            "/producer/node_sha256",
            "/producer/worker_sha256",
            "/producer/manifest_sha256",
            "/producer/manifest_fingerprint",
            "/verifier_sha256",
            "/source_commit",
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = json!("foreign209");
            assert!(
                full_capacity(&bad, &tool, &expected, &qa).is_err(),
                "{pointer}"
            );
        }
        let mut bad = good.clone();
        bad["authority"]["publication_authorized"] = json!(true);
        assert!(full_capacity(&bad, &tool, &expected, &qa).is_err());
    }
    #[test]
    fn typed204_plugin_probe_must_cover_full_decode_and_account_bytes() {
        let good = json!({"schema":"jetstreamer-horizon-plugin-capacity-probe-v1","maximum_pre_updates":131073,
            "account_data_bytes":1024,"maximum_pre_update_data_bytes":1024});
        plugin_capacity(&good, 131073).unwrap();
        for (key, value) in [
            ("maximum_pre_updates", 131072),
            ("account_data_bytes", 0),
            ("maximum_pre_update_data_bytes", 1023),
        ] {
            let mut bad = good.clone();
            bad[key] = json!(value);
            assert!(plugin_capacity(&bad, 131073).is_err(), "{key}");
        }
    }
    #[test]
    fn typed204_contract_keeps_strict_anchor_v4_and_startup_denial() {
        let proof: Value = serde_json::from_str(include_str!("fixtures/suffix.json")).unwrap();
        let prefix: lineage::Manifest =
            serde_json::from_str(include_str!("fixtures/prefix_manifest.json")).unwrap();
        let suffix = serde_json::from_value(proof["suffix_manifest"].clone()).unwrap();
        let expected = lineage::derive(&prefix, &suffix, &proof).unwrap();
        let c = contracts(&expected).unwrap();
        assert_eq!(c["full"]["non_executable_argv_template"][1], "--full");
        assert_eq!(c["full"]["non_executable_argv_template"][2], "--anchor");
        assert_eq!(
            c["full"]["non_executable_argv_template"][8],
            "--expected-provenance-sha256"
        );
        assert_eq!(
            c["full"]["non_executable_argv_template"][9],
            expected.digest
        );
        assert_eq!(c["startup"]["execution_authorized"], false);
        assert_eq!(
            c["retirement"]["requires_adjacent_boundaries"],
            json!([203, 205])
        );
        assert_eq!(expected.document["logical_write_versions"], 642344887);
    }
}
