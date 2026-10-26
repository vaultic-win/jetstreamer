//! Exact component capabilities for the separate205 producer identity.
use super::*;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tool {
    pub artifact: BoundFile,
    pub qualification: BoundFile,
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
fn producer(r: &lineage::Recipe, loaded: &lineage::Loaded) -> Value {
    json!({"node_sha256":"8e82375e588b46413118ad198fefba618c8db3cbe5f070bbac50fa5d94fc97c3",
        "worker_sha256":WORKER,"manifest_sha256":r.producer_plan.sha256,"manifest_fingerprint":format!("sha256:{}",loaded.expected.digest)})
}
fn validate(p: &Preparation) -> Result<lineage::Loaded> {
    ensure!(
        p.schema == "jetstreamer-continuation205-delivery-preparation-spec-v1",
        "205 capability preparation scope differs"
    );
    let loaded = lineage::load_recipe(&p.recipe)?;
    for (role, tool) in [
        ("full", &p.full),
        ("plugin", &p.plugin),
        ("boundary", &p.anchor),
        ("upload", &p.upload),
    ] {
        assembly204_recovery::qualified_delivery_tool(role, &tool.artifact, &tool.qualification)?;
    }
    let count = assembly204_recovery::component_full_requirement(
        &p.full.artifact,
        &p.full.qualification,
        &p.full_capacity,
        &producer(&p.recipe, &loaded),
    )?;
    assembly204_recovery::component_plugin_coverage(
        &p.plugin.artifact,
        &p.plugin.qualification,
        &p.plugin_capacity,
        count,
    )?;
    Ok(loaded)
}
pub(super) fn prepare(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let p: Preparation = serde_json::from_value(v.clone())?;
    let loaded = validate(&p)?;
    write(
        &p.output,
        &json!({"schema":"jetstreamer-continuation205-delivery-preparation-v1","epoch":205,"kind":"Continuation205",
        "recipe":p.recipe,"producer_capacity_identity":producer(&p.recipe,&loaded),"expected_lineage":loaded.expected.document,
        "tools":{"full":p.full,"plugin":p.plugin,"anchor":p.anchor,"upload":p.upload},"full_capacity":p.full_capacity,"plugin_capacity":p.plugin_capacity,
        "final_archive_digest":{"state":"unmeasured"},"output_body_reads":0,"source_archive_body_reads":0,
        "runtime_admission":false,"startup_release_issued":false,"issuer":{"spec":spec,"executable_sha256":self_sha},"authority":denied()}),
    )
}
pub(super) fn validate_stage(binding: &BoundFile, x: &downstream::StageSpec) -> Result<()> {
    let saved = read(binding)?;
    ensure!(
        saved["schema"] == "jetstreamer-continuation205-delivery-preparation-v1"
            && saved["epoch"] == 205
            && saved["kind"] == "Continuation205"
            && saved["runtime_admission"] == false
            && saved["startup_release_issued"] == false,
        "205 startup requires separate typed capability preparation"
    );
    deny(&saved["authority"])?;
    let p: Preparation = serde_json::from_value(
        json!({"schema":"jetstreamer-continuation205-delivery-preparation-spec-v1",
        "recipe":saved["recipe"],"full":saved["tools"]["full"],"plugin":saved["tools"]["plugin"],"anchor":saved["tools"]["anchor"],"upload":saved["tools"]["upload"],
        "full_capacity":saved["full_capacity"],"plugin_capacity":saved["plugin_capacity"],"output":binding.path}),
    )?;
    let loaded = validate(&p)?;
    let (completion, _) = lineage::load_source(&x.source)?;
    ensure!(
        completion["recipe"] == saved["recipe"]
            && saved["expected_lineage"] == loaded.expected.document
            && saved["producer_capacity_identity"] == producer(&p.recipe, &loaded),
        "205 source changed prepared origin"
    );
    use downstream::Stage;
    let tool = match x.stage {
        Stage::Full => Some(&p.full),
        Stage::Plugin => Some(&p.plugin),
        Stage::Boundary => Some(&p.anchor),
        Stage::Upload => Some(&p.upload),
        Stage::Import => None,
        Stage::Assembly => bail!("205 assembly is not downstream"),
    };
    if let Some(t) = tool {
        ensure!(
            x.tool.as_ref() == Some(&t.artifact)
                && x.tool_qualification.as_ref() == Some(&t.qualification),
            "205 actual tool differs from its capability proof"
        );
    } else {
        ensure!(
            x.tool.is_none() && x.tool_qualification.is_none(),
            "205 import has unexpected child"
        );
    }
    if x.stage == Stage::Full {
        ensure!(
            x.anchor_tool.as_ref() == Some(&p.anchor.artifact)
                && x.anchor_tool_qualification.as_ref() == Some(&p.anchor.qualification),
            "205 real204 decoder changed"
        );
    } else {
        ensure!(
            x.anchor_tool.is_none() && x.anchor_tool_qualification.is_none(),
            "205 unexpected anchor tool"
        );
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeSpec {
    schema: String,
    recipe: lineage::Recipe,
    full: Tool,
    plugin: Tool,
    full_capacity: BoundFile,
    launcher: BoundFile,
    launcher_seal: BoundFile,
    output_directory: PathBuf,
}
pub(super) fn capture_plugin(v: &Value, spec: &BoundFile, self_sha: &str) -> Result<()> {
    let p: ProbeSpec = serde_json::from_value(v.clone())?;
    ensure!(
        p.schema == "jetstreamer-continuation205-plugin-capacity-spec-v1"
            && p.launcher.sha256 == self_sha
            && fs::read_link("/proc/self/exe")? == p.launcher.path,
        "205 capacity issuer scope/self differs"
    );
    assembly204_recovery::deployed_delivery_member(&p.launcher_seal, &p.launcher, 256 << 20)?;
    private(&p.output_directory)?;
    ensure!(
        p.output_directory
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("horizon-205-delivery-plugin-capacity-"))
            && fs::read_dir(&p.output_directory)?.next().is_none(),
        "205 probe attempt is not empty and dedicated"
    );
    let loaded = lineage::load_recipe(&p.recipe)?;
    let identity = producer(&p.recipe, &loaded);
    let required = assembly204_recovery::component_full_requirement(
        &p.full.artifact,
        &p.full.qualification,
        &p.full_capacity,
        &identity,
    )?;
    assembly204_recovery::qualified_delivery_tool(
        "plugin",
        &p.plugin.artifact,
        &p.plugin.qualification,
    )?;
    let log = p.output_directory.join("plugin-capacity.log");
    let mut child = resource_verify::run_bound_child(
        &p.plugin.artifact.path,
        &p.plugin.artifact.sha256,
        &["--archive-capacity-probe".into()],
        &log,
    )?;
    resource_verify::validate_bound_child(
        &child,
        &p.plugin.artifact.path,
        &p.plugin.artifact.sha256,
        &["--archive-capacity-probe".into()],
    )?;
    let raw = completed_archive_phase::root205_bound_log(&BoundFile {
        path: log,
        sha256: s(&child, "log_sha256")?.into(),
    })?;
    let rows = std::str::from_utf8(&raw)?
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        rows.len() == 1
            && rows[0]["schema"] == "jetstreamer-horizon-plugin-capacity-probe-v1"
            && n(&rows[0], "maximum_pre_updates")? >= required
            && n(&rows[0], "account_data_bytes")? > 0
            && n(&rows[0], "maximum_pre_update_data_bytes")? >= n(&rows[0], "account_data_bytes")?,
        "205 plugin cannot cover producer-bound Full probe"
    );
    child.as_object_mut().context("205 plugin report absent")?.extend(json!({"schema":"jetstreamer-continuation205-plugin-capacity-report-v1",
        "epoch":205,"kind":"Continuation205","recipe":p.recipe,"producer":identity,"full_capacity":p.full_capacity,
        "full":p.full,"plugin":p.plugin,"full_required_records":required,"capability_only":true,"archive_body_reads":0,
        "runtime_admission":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false,"issuer":peer::issuer(spec,self_sha)})
        .as_object().context("205 plugin report shape")?.clone());
    write(
        &p.output_directory.join("plugin-capacity-child.json"),
        &child,
    )
}
