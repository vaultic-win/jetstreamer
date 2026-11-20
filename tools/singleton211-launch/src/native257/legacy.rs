use super::*;
// The inert v1 package invokes only the pinned harness and guard. The new
// launcher revalidates its four original definitions and the complete v2 publication.
const PREPARED_V1: &str =
    "/var/lib/jetstreamer/horizon-native257-prepared-takeover-guard-v1/prepared.json";
const PREPARED_V1_SHA: &str = "4f1ed487e65e6f93e442672ee47df25c9dbc64e2b58a7593e35de88d199525d3";
const LAUNCHER_V1: &str =
    "/var/lib/jetstreamer/horizon257-native-launch-20261120-v1/horizon-native257-launch";
const LAUNCHER_V1_SHA: &str = "34ba46673bd5898e0f9a728a6f0f6aa8d05b4a393165bd4b9a98435ca57e5b6c";
pub(super) fn prepared_transition(
    reference: &Bound,
    gate: &Bound,
    current_gate: &Bound,
    old_source: &Value,
    current_source: &Value,
) -> Result<()> {
    let mut old = publication::prepared_artifacts(old_source)?;
    let mut current = publication::prepared_artifacts(current_source)?;
    ensure!(
        old["launcher"]["artifact"] == json!(gate)
            && current["launcher"]["artifact"] == json!(current_gate),
        "launcher publication differs from prepared or running image"
    );
    if reference == &Bound::new(PREPARED_V1, PREPARED_V1_SHA) {
        ensure!(
            gate == &Bound::new(LAUNCHER_V1, LAUNCHER_V1_SHA)
                && old["launcher"]["source_commit"] == "3a9d4e749c78893880c51f0ddd9aa28965fe16f9"
                && current_gate.path == Path::new(LAUNCHER),
            "unknown prepared launcher transition"
        );
        old.remove("launcher");
        current.remove("launcher");
    }
    ensure!(old == current, "prepared executable or source changed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_registered_inert_preparation_can_transfer_to_the_successor() {
        let reference = Bound::new(PREPARED_V1, PREPARED_V1_SHA);
        let old_gate = Bound::new(LAUNCHER_V1, LAUNCHER_V1_SHA);
        let new_gate = Bound::new(LAUNCHER, "d".repeat(64));
        let source = |gate: &Bound, commit: &str| {
            json!({"artifacts":[
            {"role":"launcher","artifact":gate,"source_commit":commit},
            {"role":"guard","artifact":Bound::new(GUARD,GUARD_SHA),"source_commit":"b".repeat(40)},
            {"role":"harness","artifact":Bound::new(HARNESS,HARNESS_SHA),"source_commit":"b".repeat(40)}]})
        };
        let old = source(&old_gate, "3a9d4e749c78893880c51f0ddd9aa28965fe16f9");
        let new = source(&new_gate, &"e".repeat(40));
        prepared_transition(&reference, &old_gate, &new_gate, &old, &new).unwrap();
        let other = Bound::new(PREPARED_V1, "a".repeat(64));
        assert!(prepared_transition(&other, &old_gate, &new_gate, &old, &new).is_err());
        prepared_transition(&other, &new_gate, &new_gate, &new, &new).unwrap();
        for role in 0..3 {
            let mut changed = old.clone();
            changed["artifacts"][role]["source_commit"] = json!("f".repeat(40));
            assert!(prepared_transition(&reference, &old_gate, &new_gate, &changed, &new).is_err());
        }
    }
}
