// The previous three generations use the original stopped-prefix inspector.
const SIBLING_LOCK: Option<(&str, u64)> = None;
fn retain_profile_inputs(_: &mut Value) -> Result<()> {
    Ok(())
}
fn validate_inspection(inspected: &Value, eligibility: &Value) -> Result<()> {
    ensure!(
        eligibility["inspection"] == serde_json::to_value(binding(INSPECTION, INSPECTION_SHA))?,
        "historical inspection differs from the park eligibility"
    );
    ensure!(
        inspected["schema"] == INSPECTION_SCHEMA
            && inspected["source"] == SOURCE
            && inspected["sha256"] == SHA
            && inspected["length"] == LENGTH
            && inspected["source_stable"] == true
            && inspected["native_consumers_clear"] == true
            && inspected["source_identity"]
                == json!([
                    64512,
                    INODE,
                    LENGTH,
                    ALLOCATED / 512,
                    1001,
                    1003,
                    33152,
                    1,
                    MTIME_SEC,
                    MTIME_NSEC,
                    MTIME_SEC,
                    MTIME_NSEC
                ])
            && inspected["complete_transitive_consumer_graph_qualified"] == false,
        "exact historical inspection differs"
    );
    Ok(())
}
