//! A fixed in-memory plugin decoder probe, never an archive verification run.
use super::*;

const SPEC: &str = "jetstreamer-completed-archive-plugin-capacity-spec-v1";
const REPORT: &str = "jetstreamer-completed-archive-plugin-capacity-report-v1";
const ARGUMENT: &str = "--archive-capacity-probe";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CapacitySpec {
    schema: String,
    epoch: u64,
    origin: Origin,
    full: Tool,
    plugin: Tool,
    full_capacity: BoundFile,
    launcher: Program,
    output_directory: PathBuf,
}

struct Inputs {
    producer: Value,
    full_required_records: u64,
    full_source_revision: String,
    plugin_source_revision: String,
}

fn manifest_binding() -> BoundFile {
    BoundFile {
        path: singleton209::PREFLIGHT.into(),
        sha256: singleton209::PREFLIGHT_SHA.into(),
    }
}

fn metadata_binding(binding: &BoundFile) -> Result<()> {
    token(&binding.path)?;
    ensure!(
        binding.path.starts_with("/var/lib/jetstreamer")
            && binding.path.extension().is_some_and(|e| e == "json")
            && is_lower_hex(&binding.sha256, 64),
        "plugin capacity input is not bound JSON metadata"
    );
    Ok(())
}

fn shape(s: &CapacitySpec) -> Result<()> {
    ensure!(
        s.schema == SPEC && s.epoch == 209,
        "plugin capacity scope differs"
    );
    let Origin::Singleton209 {
        launch,
        native_input,
        cohort_publication,
    } = &s.origin;
    for b in [
        launch,
        native_input,
        cohort_publication,
        &s.full.qualification,
        &s.plugin.qualification,
        &s.full_capacity,
        &s.launcher.deployment_seal,
    ] {
        metadata_binding(b)?;
    }
    for artifact in [&s.full.artifact, &s.plugin.artifact, &s.launcher.artifact] {
        token(&artifact.path)?;
        ensure!(
            is_lower_hex(&artifact.sha256, 64),
            "plugin capacity artifact digest differs"
        );
    }
    token(&s.output_directory)?;
    ensure!(
        s.output_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && s.output_directory
                .file_name()
                .and_then(|v| v.to_str())
                .is_some_and(|v| {
                    v.strip_prefix("horizon-generic209-plugin-capacity-")
                        .is_some_and(|suffix| !suffix.is_empty())
                }),
        "plugin capacity output directory is outside its dedicated namespace"
    );
    Ok(())
}

fn producer_shape(
    s: &CapacitySpec,
    launch: &Value,
    native: &Value,
    cohort: &Value,
    manifest: &Value,
) -> Result<Value> {
    let Origin::Singleton209 { native_input, .. } = &s.origin;
    ensure!(
        s.epoch == 209
            && launch["schema"] == singleton209::SCHEMA
            && launch["epoch"] == 209
            && launch["node_sha256"] == singleton209::NODE_SHA
            && launch["worker_sha256"] == singleton209::WORKER_SHA
            && launch["manifest_fingerprint"] == singleton209::FINGERPRINT
            && launch["native_input"] == private157::binding(native_input)
            && native["schema"] == "jetstreamer-private-epoch209-native-terminal-proof-v1"
            && native["epoch"] == 209
            && native["native_input_qualified"] == true
            && manifest["manifest_fingerprint"] == singleton209::FINGERPRINT
            && cohort["schema"] == "jetstreamer-root-cohort-publication-receipt-v2"
            && cohort["epochs"] == json!([209])
            && cohort["manifest_fingerprint"] == singleton209::FINGERPRINT
            && cohort["root_checkpoint_gate"]["kind"] == "sealed-root-checkpoint-cohort"
            && cohort["root_checkpoint_gate"]["version"] == 1
            && cohort["outcome"]["kind"] == "committed",
        "plugin capacity producer metadata differs from the exact singleton 209 origin"
    );
    Ok(json!({
        "node_sha256": launch["node_sha256"],
        "worker_sha256": launch["worker_sha256"],
        "manifest_sha256": singleton209::PREFLIGHT_SHA,
        "manifest_fingerprint": launch["manifest_fingerprint"]
    }))
}

fn inputs(s: &CapacitySpec) -> Result<Inputs> {
    let Origin::Singleton209 {
        launch,
        native_input,
        cohort_publication,
    } = &s.origin;
    let original = read(launch)?;
    // This authenticates saved launch/first-guard metadata only. In particular,
    // do not call origin(), which checks the current archive and live custody.
    ensure!(
        full209_status::claim(launch)?.1 == original,
        "plugin capacity launch changed"
    );
    let producer = producer_shape(
        s,
        &original,
        &read(native_input)?,
        &read(cohort_publication)?,
        &read(&manifest_binding())?,
    )?;
    let full_source = read(&s.full.qualification)?;
    let plugin_source = read(&s.plugin.qualification)?;
    let full_required_records = decoder_capacity::full_requirement(
        &s.full_capacity,
        &s.full.artifact,
        &s.full.qualification,
        &producer,
    )?;
    Ok(Inputs {
        producer,
        full_required_records,
        full_source_revision: full_source["source_revision"]
            .as_str()
            .context("Full source absent")?
            .into(),
        plugin_source_revision: plugin_source["source_revision"]
            .as_str()
            .context("plugin source absent")?
            .into(),
    })
}

fn report(
    s: &CapacitySpec,
    binding: &BoundFile,
    self_sha: &str,
    inputs: &Inputs,
    mut child: Value,
) -> Result<Value> {
    ensure!(
        child["path"] == serde_json::to_value(&s.plugin.artifact.path)?
            && child["sha256"] == s.plugin.artifact.sha256
            && child["arguments"] == json!([ARGUMENT])
            && child["status"] == "passed"
            && child["exit_code"] == 0
            && child["log"]
                == serde_json::to_value(s.output_directory.join("plugin-capacity.log"))?
            && child["log_sha256"]
                .as_str()
                .is_some_and(|v| is_lower_hex(v, 64))
            && child["started_unix_seconds"]
                .as_u64()
                .is_some_and(|start| start > 0
                    && child["completed_unix_seconds"]
                        .as_u64()
                        .is_some_and(|end| end >= start))
            && is_lower_hex(&inputs.full_source_revision, 40)
            && is_lower_hex(&inputs.plugin_source_revision, 40)
            && inputs.full_required_records > 0
            && is_lower_hex(self_sha, 64)
            && self_sha == s.launcher.artifact.sha256,
        "plugin capacity child result or source/self binding differs"
    );
    let object = child
        .as_object_mut()
        .context("plugin capacity child report is not an object")?;
    object.extend(
        json!({
            "schema": REPORT, "epoch": s.epoch, "spec": private157::binding(binding),
            "issuer_sha256": self_sha, "launcher": s.launcher, "origin": s.origin,
            "producer_manifest": manifest_binding(), "producer": inputs.producer,
            "full": s.full, "plugin": s.plugin, "full_capacity": s.full_capacity,
            "full_source_revision": inputs.full_source_revision,
            "plugin_source_revision": inputs.plugin_source_revision,
            "full_required_records": inputs.full_required_records,
            "archive_body_reads": 0, "capability_only": true, "probe_executed": true,
            "admitted": false, "child_execution_authorized": false,
            "production_completion_authorized": false, "publication_authorized": false,
            "local_retirement_authorized": false, "remote_mutations": false, "r2_mutations": false
        })
        .as_object()
        .context("plugin capacity metadata is not an object")?
        .clone(),
    );
    Ok(child)
}

pub(super) fn run() -> Result<()> {
    let (binding, self_sha) =
        publication203::parsed_args("capture-completed-archive-plugin-capacity")?;
    metadata_binding(&binding)?;
    let s: CapacitySpec = serde_json::from_value(read(&binding)?)?;
    shape(&s)?;
    program(&s.launcher)?;
    ensure!(
        s.launcher.artifact.sha256 == self_sha
            && fs::read_link("/proc/self/exe")? == s.launcher.artifact.path,
        "plugin capacity issuer differs from its sealed launcher"
    );
    assembly204_recovery::qualified_delivery_tool("full", &s.full.artifact, &s.full.qualification)?;
    assembly204_recovery::qualified_delivery_tool(
        "plugin",
        &s.plugin.artifact,
        &s.plugin.qualification,
    )?;
    let inputs = inputs(&s)?;
    resource_audit::private_directory(&s.output_directory)?;
    ensure!(
        fs::read_dir(&s.output_directory)?.next().is_none(),
        "plugin capacity attempt is not empty"
    );
    let output = s.output_directory.join("plugin-capacity-child.json");
    let log = s.output_directory.join("plugin-capacity.log");
    validate_output_destination(&output)?;
    validate_output_destination(&log)?;
    let child = resource_verify::run_bound_child(
        &s.plugin.artifact.path,
        &s.plugin.artifact.sha256,
        &[ARGUMENT.into()],
        &log,
    )?;
    decoder_capacity::validate_plugin_child(
        &child,
        &s.plugin.artifact,
        inputs.full_required_records,
    )?;
    let result = report(&s, &binding, &self_sha, &inputs, child)?;
    private157::immutable_receipt(&output, &result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> CapacitySpec {
        let phase = super::super::tests::fixture(Phase::Full);
        let mut spec = CapacitySpec {
            schema: SPEC.into(),
            epoch: 209,
            origin: phase.origin,
            full: phase.tools["full"].clone(),
            plugin: phase.tools["plugin"].clone(),
            full_capacity: phase.decoder_capacity.full,
            launcher: phase.programs["launcher"].clone(),
            output_directory: "/var/lib/jetstreamer/horizon-generic209-plugin-capacity-test".into(),
        };
        let Origin::Singleton209 {
            launch,
            native_input,
            cohort_publication,
        } = &mut spec.origin;
        launch.path = "/var/lib/jetstreamer/launch.json".into();
        native_input.path = "/var/lib/jetstreamer/native.json".into();
        cohort_publication.path = "/var/lib/jetstreamer/cohort.json".into();
        spec.full.qualification.path = "/var/lib/jetstreamer/full-qualification.json".into();
        spec.plugin.qualification.path = "/var/lib/jetstreamer/plugin-qualification.json".into();
        spec.full_capacity.path = "/var/lib/jetstreamer/full-capacity.json".into();
        spec.launcher.deployment_seal.path = "/var/lib/jetstreamer/deployment-seal.json".into();
        spec
    }

    #[test]
    fn plugin_capacity_spec_is_closed_to_exact_epoch_json_inputs_and_dedicated_outputs() {
        let s = fixture();
        shape(&s).unwrap();
        let mut bad = s.clone();
        bad.epoch = 204;
        assert!(shape(&bad).is_err());
        bad = s.clone();
        bad.full_capacity.path = "/var/lib/jetstreamer/epoch-209.jet".into();
        assert!(shape(&bad).is_err());
        bad = s.clone();
        bad.output_directory = "/var/lib/jetstreamer/foreign".into();
        assert!(shape(&bad).is_err());
        for key in [
            "arguments",
            "publication_authorized",
            "resource_basis",
            "archive",
        ] {
            let mut value = serde_json::to_value(&s).unwrap();
            value[key] = json!(true);
            assert!(
                serde_json::from_value::<CapacitySpec>(value).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn plugin_capacity_producer_binding_rejects_foreign_native_manifest_and_cohort() {
        let s = fixture();
        let Origin::Singleton209 { native_input, .. } = &s.origin;
        let launch = json!({"schema":singleton209::SCHEMA,"epoch":209,"node_sha256":singleton209::NODE_SHA,"worker_sha256":singleton209::WORKER_SHA,"manifest_fingerprint":singleton209::FINGERPRINT,"native_input":private157::binding(native_input)});
        let native = json!({"schema":"jetstreamer-private-epoch209-native-terminal-proof-v1","epoch":209,"native_input_qualified":true});
        let cohort = json!({"schema":"jetstreamer-root-cohort-publication-receipt-v2","epochs":[209],"manifest_fingerprint":singleton209::FINGERPRINT,"root_checkpoint_gate":{"kind":"sealed-root-checkpoint-cohort","version":1},"outcome":{"kind":"committed"}});
        let manifest = json!({"manifest_fingerprint":singleton209::FINGERPRINT});
        let producer = producer_shape(&s, &launch, &native, &cohort, &manifest).unwrap();
        assert_eq!(producer["manifest_sha256"], singleton209::PREFLIGHT_SHA);
        for key in [
            "node_sha256",
            "worker_sha256",
            "manifest_fingerprint",
            "native_input",
        ] {
            let mut bad = launch.clone();
            bad[key] = json!("foreign");
            assert!(
                producer_shape(&s, &bad, &native, &cohort, &manifest).is_err(),
                "{key}"
            );
        }
        let mut bad = native.clone();
        bad["native_input_qualified"] = json!(false);
        assert!(producer_shape(&s, &launch, &bad, &cohort, &manifest).is_err());
        let mut bad = cohort.clone();
        bad["epochs"] = json!([204]);
        assert!(producer_shape(&s, &launch, &native, &bad, &manifest).is_err());
        assert!(
            producer_shape(
                &s,
                &launch,
                &native,
                &cohort,
                &json!({"manifest_fingerprint":"foreign"})
            )
            .is_err()
        );
    }

    #[test]
    fn plugin_capacity_report_preserves_real_child_fields_and_denies_runtime_authority() {
        let s = fixture();
        let inputs = Inputs {
            producer: json!({"node_sha256":singleton209::NODE_SHA}),
            full_required_records: 131073,
            full_source_revision: "b".repeat(40),
            plugin_source_revision: "c".repeat(40),
        };
        let binding = BoundFile {
            path: "/var/lib/jetstreamer/capacity-spec.json".into(),
            sha256: "d".repeat(64),
        };
        let child = json!({"path":s.plugin.artifact.path,"sha256":s.plugin.artifact.sha256,"arguments":[ARGUMENT],"status":"passed","exit_code":0,"log":s.output_directory.join("plugin-capacity.log"),"log_sha256":"e".repeat(64),"started_unix_seconds":10,"completed_unix_seconds":11});
        let result = report(
            &s,
            &binding,
            &s.launcher.artifact.sha256,
            &inputs,
            child.clone(),
        )
        .unwrap();
        for (key, value) in child.as_object().unwrap() {
            assert_eq!(result[key], *value, "{key}");
        }
        for key in [
            "admitted",
            "child_execution_authorized",
            "production_completion_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            assert_eq!(result[key], false, "{key}");
        }
        for (key, value) in [
            ("arguments", json!(["--verify-only"])),
            ("exit_code", json!(1)),
            ("sha256", json!("f".repeat(64))),
            ("log", json!("/foreign.log")),
            ("completed_unix_seconds", json!(9)),
        ] {
            let mut bad = child.clone();
            bad[key] = value;
            assert!(
                report(&s, &binding, &s.launcher.artifact.sha256, &inputs, bad).is_err(),
                "{key}"
            );
        }
        assert!(report(&s, &binding, &"f".repeat(64), &inputs, child).is_err());
    }
}
