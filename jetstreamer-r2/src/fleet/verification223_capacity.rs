//! Independent fresh complete-owner capacity for private 223 final verification.
//! Does not authenticate future prefix completion; the node admission does that.
use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    schema: String,
    resource_basis: Value,
    output: PathBuf,
}
fn scope(s: &Spec) -> Result<()> {
    ensure!(
        s.schema == "jetstreamer-private223-verification-capacity-spec-v1"
            && s.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && s.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-verification-capacity-"))
            && s.output.file_name().is_some_and(|n| n == "capacity.json"),
        "private 223 capacity scope differs"
    );
    Ok(())
}
pub(super) fn run() -> Result<()> {
    let (binding, self_sha) = publication203::parsed_args("admit-verification223-capacity")?;
    let s: Spec = serde_json::from_value(native209::immutable_json(&binding)?)?;
    scope(&s)?;
    validate_output_destination(&s.output)?;
    let mut capacity = maintenance_capacity::check_candidate(
        &s.resource_basis,
        maintenance_capacity::Candidate {
            additional_bytes: (160 << 30) + (256 << 20),
            memory_max_bytes: 64 << 30,
            minimum_protected_disk_bytes: 2_000_000_000_000,
        },
    )?;
    let fleet: BoundFile = serde_json::from_value(capacity["fleet"].clone())?;
    let f = bound_json(&fleet)?;
    ensure!(
        !f["active"]
            .as_array()
            .context("private 223 complete active census")?
            .iter()
            .any(|row| row["epoch"] == 223),
        "private 223 source still has active work"
    );
    capacity["schema"] = json!("jetstreamer-private223-verification-capacity-v1");
    capacity["spec"] = private157::binding(&binding);
    capacity["self_sha256"] = json!(self_sha);
    capacity["verification_only_no_replay"] = json!(true);
    capacity["source_completion_authenticated"] = json!(false);
    capacity["verification_launch_authorized"] = json!(false);
    ensure!(
        serde_json::to_vec_pretty(&capacity)?.len() < 8 << 20,
        "private 223 capacity exceeds the independently readable 8 MiB metadata envelope"
    );
    private157::immutable_receipt(&s.output, &capacity)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_capacity_scope_cannot_be_repurposed_as_launch_or_other_output() {
        let good = json!({"schema":"jetstreamer-private223-verification-capacity-spec-v1","resource_basis":{},
            "output":"/var/lib/jetstreamer/horizon-223-verification-capacity-test/capacity.json"});
        scope(&serde_json::from_value(good.clone()).unwrap()).unwrap();
        let mut bad = good.clone();
        bad["output"] = json!("/var/lib/jetstreamer/other/capacity.json");
        assert!(scope(&serde_json::from_value(bad).unwrap()).is_err());
        let mut bad = good;
        bad["launch"] = json!(true);
        assert!(serde_json::from_value::<Spec>(bad).is_err());
    }
}
