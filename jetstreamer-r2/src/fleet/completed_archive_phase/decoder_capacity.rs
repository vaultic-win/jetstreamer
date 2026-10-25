//! Bind genuine decoder probes to the qualified binaries and native producer.
use super::*;
fn full_shape(v: &Value, tool: &BoundFile, source: &Value, producer: &Value) -> Result<u64> {
    let decoded = v["probe"]["decoded_records"]
        .as_u64()
        .context("full capacity decoded count absent")?;
    ensure!(
        v["schema"] == "jetstreamer-horizon-verifier-capacity-probe-v1"
            && v["verifier_path"] == serde_json::to_value(&tool.path)?
            && v["verifier_sha256"] == tool.sha256
            && v["source_commit"] == source["source_revision"]
            && v["producer"] == *producer
            && v["probe"]["result"] == "pass"
            && v["probe"]["phase"] == "pre-account-updates"
            && v["probe"]["old_inline_limit"]
                .as_u64()
                .is_some_and(|old| old > 0 && decoded > old)
            && [
                "production_archive_reread_authorized",
                "replay_launch_authorized",
                "publication_authorized",
                "remote_mutations",
                "r2_mutations"
            ]
            .iter()
            .all(|k| v["authority"][*k] == false),
        "completed phase full capacity provenance differs"
    );
    Ok(decoded)
}
fn plugin_shape(v: &Value, required: u64) -> Result<()> {
    ensure!(
        v["schema"] == "jetstreamer-horizon-plugin-capacity-probe-v1"
            && v["maximum_pre_updates"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && v["account_data_bytes"].as_u64().is_some_and(|n| n > 0
                && v["maximum_pre_update_data_bytes"]
                    .as_u64()
                    .is_some_and(|max| max >= n)),
        "completed phase plugin capacity is below its producer-bound full probe"
    );
    Ok(())
}
pub(super) fn validate(s: &Spec, producer: &Value) -> Result<()> {
    let full = read(&s.decoder_capacity.full)?;
    let source = read(&s.tools["full"].qualification)?;
    let required = full_shape(&full, &s.tools["full"].artifact, &source, producer)?;
    let child = read(&s.decoder_capacity.plugin)?;
    let tool = &s.tools["plugin"].artifact;
    resource_verify::validate_bound_child(
        &child,
        &tool.path,
        &tool.sha256,
        &["--archive-capacity-probe".into()],
    )?;
    let log = Path::new(
        child["log"]
            .as_str()
            .context("plugin capacity log missing")?,
    );
    let raw = bound_bytes(
        &BoundFile {
            path: log.to_owned(),
            sha256: child["log_sha256"]
                .as_str()
                .context("plugin capacity log digest missing")?
                .to_owned(),
        },
        64 << 20,
        0,
    )?;
    let text = std::str::from_utf8(&raw)?;
    let rows = text
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(serde_json::from_str::<Value>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(rows.len() == 1, "plugin capacity result is ambiguous");
    plugin_shape(&rows[0], required)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_decoder_capacity_rejects_foreign_binary_source_and_native_producer() {
        let tool = BoundFile {
            path: "/sealed/new-full".into(),
            sha256: "a".repeat(64),
        };
        let source = json!({"source_revision":"b".repeat(40)});
        let producer = json!({"node_sha256":"c".repeat(64),"worker_sha256":"d".repeat(64),"manifest_sha256":"e".repeat(64),"manifest_fingerprint":format!("sha256:{}","f".repeat(64))});
        let good = json!({"schema":"jetstreamer-horizon-verifier-capacity-probe-v1","verifier_path":tool.path,"verifier_sha256":tool.sha256,"source_commit":source["source_revision"],"producer":producer,"probe":{"decoded_records":131073,"old_inline_limit":131072,"phase":"pre-account-updates","result":"pass"},"authority":{"production_archive_reread_authorized":false,"replay_launch_authorized":false,"publication_authorized":false,"remote_mutations":false,"r2_mutations":false}});
        assert_eq!(
            full_shape(&good, &tool, &source, &producer).unwrap(),
            131073
        );
        for field in [
            "verifier_path",
            "verifier_sha256",
            "source_commit",
            "producer",
        ] {
            let mut bad = good.clone();
            bad[field] = json!("foreign");
            assert!(full_shape(&bad, &tool, &source, &producer).is_err());
        }
        let mut bad = good;
        bad["probe"]["decoded_records"] = json!(131072);
        assert!(full_shape(&bad, &tool, &source, &producer).is_err());
    }
    #[test]
    fn completed_plugin_capacity_must_cover_the_producer_bound_decoder_requirement() {
        let mut v = json!({"schema":"jetstreamer-horizon-plugin-capacity-probe-v1","maximum_pre_updates":1048576,"account_data_bytes":1144384,"maximum_pre_update_data_bytes":8388608});
        plugin_shape(&v, 131073).unwrap();
        v["maximum_pre_updates"] = json!(131072);
        assert!(plugin_shape(&v, 131073).is_err());
        v["maximum_pre_updates"] = json!(1048576);
        v["maximum_pre_update_data_bytes"] = json!(1144383);
        assert!(plugin_shape(&v, 131073).is_err());
    }
}
